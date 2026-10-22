use anyhow::bail;
use colored::*;
use coordinator::{Coordinator, CoordinatorConfig, Hooks, Sockets};
use db::DatabasePeer;
use dialoguer::Confirm;
use innernet_client_core::rest_client::{RestClient, RestError};
use innernet_node::{
    addresses,
    events::{EventSource, TunnelEvent, TunnelEvents},
    realize::{DnsService, TunnelBackend as _, WireGuard},
    runtime::{self, Node, StoreChanged, Triggers},
    Store,
};
use innernet_shared::{
    interface_config::{DnsInfo, InterfaceConfig, InterfaceInfo, ServerInfo, FEATURE_TLS},
    prompts, wg, Error, HostsOpts, Interface, IoErrorContext, NatOpts, NetworkOpts,
};
use ipnet::IpNet;
use node::LocalLink;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    env,
    fs::{File, OpenOptions},
    io::prelude::*,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use wireguard_control::{InterfaceName, Key};

mod api;
mod coordinator;
mod db;
mod error;
pub mod initialize;
mod node;
#[cfg(test)]
mod test;
mod util;

pub use error::ServerError;

#[cfg(test)]
pub(crate) use coordinator::{hyper_service, Context, Db};
pub(crate) use coordinator::{Endpoints, Session};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct ConfigFile {
    /// The server's WireGuard key
    pub private_key: String,

    /// The listen port of the server
    pub listen_port: u16,

    /// The internal WireGuard IP address assigned to the server
    pub address: IpAddr,

    /// The CIDR prefix of the WireGuard network
    pub network_cidr_prefix: u8,

    /// The UDP port of the TLS API, which runs over QUIC at the server's internal address. The
    /// kernel's WireGuard holds `listen_port` on every address, so the API needs a port of its
    /// own. The server refuses to start without it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic_port: Option<u16>,

    /// The DNS server that the server runs, as every node runs it, at the address of the
    /// table, or `None` if the server runs none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsInfo>,
}

impl ConfigFile {
    /// The prefix of the whole network.
    pub fn network(&self) -> IpNet {
        IpNet::new(self.address, self.network_cidr_prefix)
            .map(|net| net.trunc())
            .unwrap_or_else(|_| IpNet::from(self.address))
    }

    pub fn write_to_path<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let mut invitation_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .with_path(&path)?;
        innernet_shared::chmod(&invitation_file, 0o600)?;
        invitation_file
            .write_all(toml::to_string(self).unwrap().as_bytes())
            .with_path(path)?;
        Ok(())
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let path = path.as_ref();
        let mut file = File::open(path).with_path(path)?;
        if innernet_shared::chmod(&file, 0o600)? {
            println!(
                "{} updated permissions for {} to 0600.",
                "[!]".yellow(),
                path.display()
            );
        }
        let mut toml = String::new();
        file.read_to_string(&mut toml).with_path(path)?;
        Ok(toml::from_str(&toml)?)
    }
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
}

impl ServerConfig {
    pub fn new(config_dir: PathBuf, data_dir: PathBuf) -> Self {
        Self {
            config_dir,
            data_dir,
        }
    }

    pub fn database_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn database_path(&self, interface: &InterfaceName) -> PathBuf {
        PathBuf::new()
            .join(self.database_dir())
            .join(interface.to_string())
            .with_extension("db")
    }

    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    pub fn config_path(&self, interface: &InterfaceName) -> PathBuf {
        PathBuf::new()
            .join(self.config_dir())
            .join(interface.to_string())
            .with_extension("conf")
    }
}

/// Opens the database of `interface`, for the network of its config, migrating a database of
/// 2.0.0, whose coordinator is the peer with the public key of the config's private key.
fn open_database_connection(
    interface: &InterfaceName,
    conf: &ServerConfig,
) -> Result<Store, Error> {
    let database_path = conf.database_path(interface);
    if !Path::new(&database_path).exists() {
        bail!(
            "no database file found at {}",
            database_path.to_string_lossy()
        );
    }
    let config = ConfigFile::from_file(conf.config_path(interface))?;
    let server_key = Key::from_base64(&config.private_key)?.get_public();

    let file = File::open(&database_path).with_path(&database_path)?;
    innernet_shared::warn_on_dangerous_mode(&file, &database_path).with_path(&database_path)?;
    drop(file);
    db::open(&database_path, config.network(), &server_key)
}

/// The admin client of the coordinator of a network, which the running server serves: the
/// server's own peer, an admin, over TLS, at the primary IP and the API port of its config. Every
/// change of the network goes through the coordinator, so a command fails if the server isn't
/// running.
pub struct AdminClient {
    interface: InterfaceName,
    config: InterfaceConfig,
}

impl AdminClient {
    pub fn new(interface: &InterfaceName, conf: &ServerConfig) -> Result<Self, Error> {
        let config = ConfigFile::from_file(conf.config_path(interface))?;
        let internal_endpoint = SocketAddr::new(config.address, config.listen_port);
        let server = ServerInfo {
            public_key: Key::from_base64(&config.private_key)?
                .get_public()
                .to_base64(),
            // Invitations name the coordinator at the endpoint of the server's own peer, which
            // `new` records and the coordinator lists, in place of this one.
            external_endpoint: internal_endpoint.into(),
            internal_endpoint,
            features: vec![FEATURE_TLS.to_string()],
            quic_port: config.quic_port,
        };
        let own = InterfaceInfo {
            network_name: interface.to_string(),
            address: IpNet::new(config.address, config.network_cidr_prefix)?,
            private_key: config.private_key,
            listen_port: Some(config.listen_port),
        };
        Ok(Self {
            interface: *interface,
            config: InterfaceConfig::new(own, server),
        })
    }

    /// The coordinator, as invitations name it.
    pub fn server(&self) -> &ServerInfo {
        &self.config.server
    }

    pub fn rest_client(&self) -> Result<RestClient<'_>, Error> {
        Ok(RestClient::new(&self.config, true)?)
    }

    /// `error`, which a command met, explained if the coordinator didn't answer.
    pub fn explain(&self, error: Error) -> Error {
        match error.downcast_ref::<RestError>() {
            Some(rest) if rest.is_transport_error() => {
                let interface = self.interface.as_str_lossy();
                error.context(format!(
                    "the coordinator of {interface} doesn't answer; `innernet-server serve \
                     {interface}` must be running"
                ))
            },
            _ => error,
        }
    }
}

pub fn uninstall(
    interface: &InterfaceName,
    conf: &ServerConfig,
    network: NetworkOpts,
    yes: bool,
) -> Result<(), Error> {
    if yes
        || Confirm::with_theme(&*prompts::THEME)
            .with_prompt(format!(
                "Permanently delete network \"{}\"?",
                interface.as_str_lossy().yellow()
            ))
            .default(false)
            .interact()?
    {
        println!("{} bringing down interface (if up).", "[*]".dimmed());
        wg::down(interface, network.backend).ok();
        let config = conf.config_path(interface);
        let data = conf.database_path(interface);
        std::fs::remove_file(&config)
            .with_path(&config)
            .map_err(|e| println!("[!] {}", e.to_string().yellow()))
            .ok();
        std::fs::remove_file(&data)
            .with_path(&data)
            .map_err(|e| println!("[!] {}", e.to_string().yellow()))
            .ok();
        println!(
            "{} network {} is uninstalled.",
            "[*]".dimmed(),
            interface.as_str_lossy().yellow()
        );
    }
    Ok(())
}

/// Runs the server's node and, beside it, the coordinator of the network of `interface`.
pub async fn serve(
    interface: InterfaceName,
    conf: &ServerConfig,
    network: NetworkOpts,
    hosts_opts: HostsOpts,
) -> Result<(), Error> {
    hosts_opts.warn_of_hosts_file_options();
    let config_path = conf.config_path(&interface);
    let config = ConfigFile::from_file(&config_path)?;
    let quic_port = quic_port(&config, &config_path)?;
    log::debug!("opening database connection...");
    let store = open_database_connection(&interface, conf)?;
    let public_key = check_database_matches_config(&store, &config)?;
    check_internal_address(&DatabasePeer::own(&store, &public_key)?, config.address)?;

    log::info!("bringing up interface.");
    wg::up(
        &interface,
        &config.private_key,
        IpNet::new(config.address, config.network_cidr_prefix)?,
        Some(config.listen_port),
        None,
        &network,
    )?;

    let tunnel = WireGuard {
        interface,
        backend: network.backend,
        endpoint_overrides: BTreeMap::new(),
        events: EventSource::default(),
    };
    let endpoints = follow_endpoints(tunnel.events());
    let db = Arc::new(Mutex::new(store));
    let changed = StoreChanged::default();
    let mut node = Node {
        interface,
        listen_port: config.listen_port,
        nat: NatOpts {
            no_nat_traversal: false,
            exclude_nat_candidates: vec![],
            no_nat_candidates: false,
        },
        tunnel: Box::new(tunnel),
    };
    let mut dns = DnsService::new(interface, hosts_opts.host_suffix.clone());
    let mut link = LocalLink {
        db: db.clone(),
        key: public_key,
    };
    let triggers = Triggers {
        changed: Some(changed.clone()),
        interval: None,
        addresses: addresses::Watcher::new(ADDRESS_SETTLE)
            .inspect_err(|e| log::warn!("can't watch the host's addresses: {e}"))
            .ok(),
    };
    let node_loop = runtime::run(triggers, async || {
        let round = node.round(&mut link).await?;
        dns.update(config.dns.as_ref(), &round.snapshot).await;
        Ok(round)
    });

    log::info!("the TLS API's QUIC port is {quic_port}.");
    log::info!("innernet-server {} starting.", VERSION);
    let coordinator = Coordinator::spawn(
        CoordinatorConfig {
            address: config.address,
            quic_port,
        },
        &config.private_key,
        db,
        Sockets {
            api: get_listener((config.address, config.listen_port).into(), &interface)?,
        },
        Hooks { changed, endpoints },
    )?;
    tokio::select! {
        () = node_loop => unreachable!("the node's loop runs forever"),
        result = coordinator.join() => result,
    }
}

/// How long the watcher of the host's addresses waits for a burst of changes to settle.
const ADDRESS_SETTLE: Duration = Duration::from_millis(200);

/// The endpoints at which the tunnel observes the peers, as `events` report them.
fn follow_endpoints(mut events: TunnelEvents) -> Endpoints {
    let endpoints: Endpoints = Arc::default();
    tokio::spawn({
        let endpoints = endpoints.clone();
        async move {
            while let Some(event) = events.next().await {
                if let TunnelEvent::EndpointChanged {
                    public_key,
                    endpoint,
                } = event
                {
                    endpoints.write().insert(public_key, endpoint);
                }
            }
        }
    });
    endpoints
}

/// The QUIC port of `config`, the config at `path`. Nothing writes the config, so a config that
/// states none, such as one of v2.0.0, is refused with a free UDP port for the operator to add.
fn quic_port(config: &ConfigFile, path: &Path) -> Result<u16, Error> {
    if let Some(port) = config.quic_port {
        return Ok(port);
    }
    let unspecified = match config.address {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    bail!(
        "{} states no quic-port; nothing writes the config, so the operator must add one, such \
         as this free UDP port:\n\nquic-port = {}\n",
        path.display(),
        free_udp_port(unspecified, config.listen_port)?
    )
}

/// A UDP port that is free at `address`, other than `listen_port`, the port of WireGuard, which
/// the kernel holds on every address.
pub(crate) fn free_udp_port(address: IpAddr, listen_port: u16) -> Result<u16, Error> {
    loop {
        let port = std::net::UdpSocket::bind((address, 0))?
            .local_addr()?
            .port();
        if port != listen_port {
            return Ok(port);
        }
    }
}

/// Checks, before the server starts anything, that the database holds the server's own peer, the
/// one with the public key of the config's private key, and returns that key. Without it, the
/// database and the config belong to different networks, or one of them was edited by hand.
fn check_database_matches_config(
    conn: &rusqlite::Connection,
    config: &ConfigFile,
) -> Result<Key, Error> {
    let public_key = Key::from_base64(&config.private_key)?.get_public();
    if DatabasePeer::own(conn, &public_key).is_err() {
        bail!(
            "the database and the config don't match: the database holds no peer with the key \
             {} of the config's private key",
            public_key.to_base64()
        );
    }
    Ok(public_key)
}

/// Checks that the server's own peer `myself` holds `address`, the internal address that the
/// server serves its API on. Clients route the address to the server's key through the server's
/// delegations, so an address outside them is unreachable.
fn check_internal_address(myself: &DatabasePeer, address: IpAddr) -> Result<(), Error> {
    if !myself.holds(address) {
        bail!(
            "the server's internal address {address}, from its config, lies outside the \
             delegations of its own peer ({}); the config or the database is inconsistent",
            myself.display_delegations()
        );
    }
    Ok(())
}

/// This function differs per OS, because different operating systems have
/// opposing characteristics when binding to a specific IP address.
/// On Linux, binding to a specific local IP address does *not* bind it to
/// that IP's interface, allowing for spoofing attacks.
///
/// See https://github.com/tonarino/innernet/issues/26 for more details.
#[cfg(target_os = "linux")]
fn get_listener(addr: SocketAddr, interface: &InterfaceName) -> Result<TcpListener, Error> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let sock = socket2::Socket::from(listener);
    sock.bind_device(Some(interface.as_str_lossy().as_bytes()))?;
    Ok(sock.into())
}

/// BSD-likes do seem to bind to an interface when binding to an IP,
/// according to the internet, but we may want to explicitly use
/// IP_BOUND_IF in the future regardless. This isn't currently in
/// the socket2 crate however, so we aren't currently using it.
///
/// See https://github.com/tonarino/innernet/issues/26 for more details.
#[cfg(not(target_os = "linux"))]
fn get_listener(addr: SocketAddr, _interface: &InterfaceName) -> Result<TcpListener, Error> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{coordinator::serve_api, test};
    use anyhow::Result;
    use hyper::{Body, Request, StatusCode};
    use innernet_shared::{tls, INNERNET_PUBKEY_HEADER};
    use std::path::Path;
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
        net::TcpStream,
    };
    use tokio_rustls::rustls;
    use wireguard_control::KeyPair;

    #[test]
    fn test_init_wizard() -> Result<(), Error> {
        // This runs init_wizard().
        let server = test::Server::new()?;

        assert!(Path::new(&server.wg_conf_path()).exists());
        let config = ConfigFile::from_file(server.wg_conf_path())?;
        assert_eq!(config.quic_port, Some(54322));

        // The server's own peer has the key of the config.
        let key = Key::from_base64(&config.private_key)?.get_public();
        let own = DatabasePeer::own(&server.db().lock(), &key)?;
        assert_eq!(own.name.as_deref(), Some("innernet-server"));

        // A config whose key no peer has doesn't match the database.
        assert_eq!(
            check_database_matches_config(&server.db().lock(), &config)?,
            key
        );
        let other = ConfigFile {
            private_key: Key::generate_private().to_base64(),
            ..config
        };
        assert!(check_database_matches_config(&server.db().lock(), &other).is_err());

        Ok(())
    }

    #[test]
    fn test_config_without_quic_port_is_refused() -> Result<(), Error> {
        // A config without the QUIC port gets a free one suggested, and nothing writes it.
        let server = test::Server::new()?;
        let path = server.wg_conf_path();
        let mut config = ConfigFile::from_file(&path)?;
        assert_eq!(quic_port(&config, &path)?, 54322);
        config.quic_port = None;
        let error = quic_port(&config, &path).unwrap_err().to_string();
        assert!(error.contains("states no quic-port"), "{error}");
        let suggested: u16 = error
            .rsplit("quic-port = ")
            .next()
            .and_then(|port| port.trim().parse().ok())
            .expect("a suggested port");
        assert_ne!(suggested, config.listen_port);
        assert_eq!(ConfigFile::from_file(&path)?.quic_port, Some(54322));
        Ok(())
    }

    async fn requires_tls(server: &test::Server, id: i64) -> bool {
        test::peer(&server.db.lock(), id).requires_tls
    }

    #[tokio::test]
    async fn test_tls_latch() -> Result<(), Error> {
        let server = test::Server::new()?;
        server.predate_tls(test::DEVELOPER1_PEER_ID);
        server.predate_tls(test::DEVELOPER2_PEER_ID);
        let ip = test::DEVELOPER1_PEER_IP;

        // A peer from before TLS that has never connected over TLS is identified by its IP...
        assert!(!requires_tls(&server, test::DEVELOPER1_PEER_ID).await);
        let res = server.plain_request(ip, "GET", "/v1/user/state").await;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(!requires_tls(&server, test::DEVELOPER1_PEER_ID).await);

        // ...until it does, after which it must always.
        let res = server.request(ip, "GET", "/user/state").await;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(requires_tls(&server, test::DEVELOPER1_PEER_ID).await);

        let res = server.plain_request(ip, "GET", "/v1/user/state").await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let body = hyper::body::to_bytes(res.into_body()).await?;
        assert!(String::from_utf8_lossy(&body).contains("TLS"));

        // Other peers are unaffected.
        let res = server
            .plain_request(test::DEVELOPER2_PEER_IP, "GET", "/v1/user/state")
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn test_errors_by_transport() -> Result<(), Error> {
        let server = test::Server::new()?;

        // A TLS session is told of errors in problem details, in deterministic CBOR. An error
        // without a meaning of innernet's own is of the type about:blank.
        let res = server
            .request(test::ADMIN_PEER_IP, "GET", "/admin/nothing")
            .await;
        assert_eq!(
            res.headers()[hyper::header::CONTENT_TYPE],
            "application/problem+cbor"
        );
        let body = hyper::body::to_bytes(res.into_body()).await?;
        let problem: innernet_shared::problem::Problem = innernet_shared::cbor::from_slice(&body)?;
        assert_eq!(innernet_shared::cbor::to_vec(&problem)?, body);
        assert_eq!(
            problem,
            innernet_shared::problem::Problem::about_blank(404, Some("Not Found"))
        );
        for (ip, path, status) in [
            (test::ADMIN_PEER_IP, "/v1/user/state", StatusCode::NOT_FOUND),
            (
                test::USER1_PEER_IP,
                "/admin/peers",
                StatusCode::UNAUTHORIZED,
            ),
        ] {
            let res = server.request(ip, "GET", path).await;
            test::blank_problem(res, status).await?;
        }

        // A request that chooses the debug view is told of errors in the debug view too, even a
        // change, which the debug view doesn't answer.
        for (method, path, status) in [
            ("GET", "/admin/nothing", StatusCode::NOT_FOUND),
            ("PUT", "/user/candidates", StatusCode::NOT_ACCEPTABLE),
        ] {
            let mut req = server.body_request(method, path, &test::content_type(), vec![0x80]);
            req.headers_mut()
                .insert(hyper::header::ACCEPT, "*/*".parse().unwrap());
            let res = server.raw_request(test::ADMIN_PEER_IP, req).await;
            assert_eq!(res.status(), status);
            assert_eq!(
                res.headers()[hyper::header::CONTENT_TYPE],
                "application/problem+cbor-diagnostic"
            );
            let body = hyper::body::to_bytes(res.into_body()).await?;
            let text = String::from_utf8(body.to_vec())?;
            assert!(
                text.starts_with(
                    "# unstable debug view; use Accept: application/vnd.innernet+cbor; \
                     version=1\n{"
                ),
                "{text}"
            );
            assert!(text.contains("\"type\": \"about:blank\""), "{text}");
        }

        // A request that accepts no version is told so in CBOR.
        let mut req = server.body_request("GET", "/user/state", "", vec![]);
        req.headers_mut().remove(hyper::header::CONTENT_TYPE);
        req.headers_mut().insert(
            hyper::header::ACCEPT,
            "application/vnd.innernet+cbor; version=2".parse().unwrap(),
        );
        let res = server.raw_request(test::ADMIN_PEER_IP, req).await;
        test::blank_problem(res, StatusCode::NOT_ACCEPTABLE).await?;

        // A plain-HTTP session is told of errors as before: with an explanation in plain text
        // for those that clients that predate TLS can't make sense of, and an empty body
        // otherwise, without a content type.
        server.predate_tls(test::USER1_PEER_ID);
        let res = server
            .plain_request(test::USER1_PEER_IP, "GET", "/v1/admin/peers")
            .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert!(res.headers().get(hyper::header::CONTENT_TYPE).is_none());
        assert!(hyper::body::to_bytes(res.into_body()).await?.is_empty());
        let res = server
            .plain_request(test::USER2_PEER_IP, "GET", "/v1/user/state")
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert!(res.headers().get(hyper::header::CONTENT_TYPE).is_none());
        let body = hyper::body::to_bytes(res.into_body()).await?;
        assert_eq!(body, ServerError::TlsRequired.to_string());
        Ok(())
    }

    #[tokio::test]
    async fn test_peers_require_tls_from_creation() -> Result<(), Error> {
        let server = test::Server::new()?;
        for (id, ip) in [
            (test::ADMIN_PEER_ID, test::ADMIN_PEER_IP),
            (test::DEVELOPER1_PEER_ID, test::DEVELOPER1_PEER_IP),
        ] {
            assert!(requires_tls(&server, id).await);
            let res = server.plain_request(ip, "GET", "/v1/user/state").await;
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
            let res = server.request(ip, "GET", "/user/state").await;
            assert_eq!(res.status(), StatusCode::OK);
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_authentication_by_delegated_address() -> Result<(), Error> {
        let server = test::Server::new()?;
        let (prefix, within) = if cfg!(feature = "v6-test") {
            ("fd00:1337::2:0:1:0/112", "fd00:1337::2:0:1:5")
        } else {
            ("10.80.64.16/28", "10.80.64.20")
        };
        server.delegate(test::DEVELOPER1_PEER_ID, prefix);
        let developer1 = test::peer(&server.db.lock(), test::DEVELOPER1_PEER_ID);
        let key = Key::from_base64(&developer1.public_key)?;
        let request = || {
            Request::builder()
                .uri("/user/state")
                .header(INNERNET_PUBKEY_HEADER, server_key(&server))
                .body(Body::empty())
                .unwrap()
        };

        // Over TLS, the peer's key is accepted from any address of its delegations.
        let res = server
            .raw_request_as(within, Some(key.clone()), request())
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        let res = server
            .raw_request_as(test::DEVELOPER2_PEER_IP, Some(key), request())
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // In plain HTTP, any address of its delegations identifies the peer.
        server.predate_tls(test::DEVELOPER1_PEER_ID);
        let res = server.plain_request(within, "GET", "/v1/user/state").await;
        assert_eq!(res.status(), StatusCode::OK);
        Ok(())
    }

    #[test]
    fn test_internal_address_lies_in_the_server_delegation() -> Result<(), Error> {
        let server = test::Server::new()?;
        let config = ConfigFile::from_file(server.wg_conf_path())?;
        let store = server.db.lock();
        let key = Key::from_base64(&config.private_key)?.get_public();
        let myself = DatabasePeer::own(&store, &key)?;
        check_internal_address(&myself, config.address)?;
        let error = check_internal_address(&myself, test::ADMIN_PEER_IP.parse()?).unwrap_err();
        assert!(error.to_string().contains("outside"), "{error}");
        Ok(())
    }

    #[tokio::test]
    async fn test_tls_key_must_match_peer_and_ip() -> Result<(), Error> {
        let server = test::Server::new()?;
        let admin_key = {
            let admin = test::peer(&server.db.lock(), test::ADMIN_PEER_ID);
            Key::from_base64(&admin.public_key)?
        };
        let request = || {
            let path = if cfg!(feature = "v6-test") {
                format!("http://[{}]/admin/peers", test::WG_MANAGE_PEER_IP)
            } else {
                format!("http://{}/admin/peers", test::WG_MANAGE_PEER_IP)
            };
            Request::builder()
                .uri(path)
                .header(INNERNET_PUBKEY_HEADER, server_key(&server))
                .body(Body::empty())
                .unwrap()
        };

        // The admin's key from another peer's IP.
        let res = server
            .raw_request_as(test::USER1_PEER_IP, Some(admin_key.clone()), request())
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // An unknown key from the admin's IP.
        let unknown = KeyPair::generate().public;
        let res = server
            .raw_request_as(test::ADMIN_PEER_IP, Some(unknown), request())
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        let res = server
            .raw_request_as(test::ADMIN_PEER_IP, Some(admin_key), request())
            .await;
        assert_eq!(res.status(), StatusCode::OK);

        // A user peer connecting over TLS gains nothing beyond its own rights.
        let res = server
            .request(test::USER1_PEER_IP, "GET", "/admin/peers")
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    /// Sends a request for `path` on a raw stream and returns the response's status line.
    async fn status_line<S: AsyncRead + AsyncWrite + Unpin>(
        mut stream: S,
        server_key: &str,
        path: &str,
    ) -> String {
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: innernet\r\n{INNERNET_PUBKEY_HEADER}: \
             {server_key}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8_lossy(&response)
            .lines()
            .next()
            .unwrap_or_default()
            .to_string()
    }

    #[tokio::test]
    async fn test_serves_tls_and_plain_http_on_one_port() -> Result<(), Error> {
        let server = test::Server::new()?;
        let server_tls_key = KeyPair::generate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(serve_api(
            listener,
            server.context(),
            tls::server_config(&server_tls_key.private.to_base64())?,
        ));

        // A peer whose private key is known, at an IP other than the loopback's.
        let peer_key = KeyPair::generate();
        let ip = if cfg!(feature = "v6-test") {
            "fd00:1337::2:0:0:9"
        } else {
            "10.80.64.9"
        };
        let mut contents = test::developer_peer_contents("developer3", ip)?;
        contents.public_key = peer_key.public.to_base64();
        let peer = DatabasePeer::create(&server.db.lock(), contents)?;
        server.predate_tls_key(&peer.public_key);

        let header_key = server_key(&server);
        let connect_tls = |client: &KeyPair, pinned: &Key| {
            let config = tls::client_config(&client.private.to_base64(), &pinned.to_base64());
            let connector = tokio_rustls::TlsConnector::from(config.unwrap());
            async move {
                let stream = TcpStream::connect(addr).await.unwrap();
                let name = rustls::pki_types::ServerName::IpAddress(addr.ip().into());
                connector.connect(name, stream).await
            }
        };

        // Plain HTTP is still served; nothing is at the loopback's IP.
        let plain = TcpStream::connect(addr).await?;
        assert_eq!(
            status_line(plain, &header_key, "/v1/user/state").await,
            "HTTP/1.1 401 Unauthorized"
        );

        // TLS is served on the same port. The peer's key is accepted by the handshake, but not
        // from an IP other than its own, and that doesn't latch it.
        let tls = connect_tls(&peer_key, &server_tls_key.public).await?;
        assert_eq!(
            status_line(tls, &header_key, "/user/state").await,
            "HTTP/1.1 401 Unauthorized"
        );
        assert!(!peer.reload(&server.db.lock())?.requires_tls);

        // A client pinning another server key refuses the handshake.
        let wrong = KeyPair::generate().public;
        assert!(connect_tls(&peer_key, &wrong).await.is_err());
        Ok(())
    }

    fn server_key(server: &test::Server) -> String {
        server.context().public_key.to_base64()
    }

    #[tokio::test]
    async fn test_with_session_disguised_with_headers() -> Result<(), Error> {
        let server = test::Server::new()?;

        let path = if cfg!(feature = "v6-test") {
            format!("http://[{}]/v1/user/state", test::WG_MANAGE_PEER_IP)
        } else {
            format!("http://{}/v1/user/state", test::WG_MANAGE_PEER_IP)
        };
        let req = Request::builder()
            .uri(path)
            .header("Forwarded", format!("for={}", test::ADMIN_PEER_IP))
            .header("X-Forwarded-For", test::ADMIN_PEER_IP)
            .header("X-Real-IP", test::ADMIN_PEER_IP)
            .body(Body::empty())
            .unwrap();

        // Request from an unknown IP, trying to disguise as an admin using HTTP headers.
        let res = if cfg!(feature = "v6-test") {
            server.raw_request("fd00:1337::1337", req).await
        } else {
            server.raw_request("10.80.80.80", req).await
        };

        // addr::remote() filter only look at remote_addr from TCP socket.
        // HTTP headers are not considered. This also means that innernet
        // server would not function behind an HTTP proxy.
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[tokio::test]
    async fn test_incorrect_public_key() -> Result<(), Error> {
        let server = test::Server::new()?;

        let key = Key::generate_private().get_public();

        let path = if cfg!(feature = "v6-test") {
            format!("http://[{}]/v1/user/state", test::WG_MANAGE_PEER_IP)
        } else {
            format!("http://{}/v1/user/state", test::WG_MANAGE_PEER_IP)
        };
        // Request from an unknown IP, trying to disguise as an admin using HTTP headers.
        let req = Request::builder()
            .uri(path)
            .header(innernet_shared::INNERNET_PUBKEY_HEADER, key.to_base64())
            .body(Body::empty())
            .unwrap();
        let res = if cfg!(feature = "v6-test") {
            server.raw_request("fd00:1337::1337", req).await
        } else {
            server.raw_request("10.80.80.80", req).await
        };

        // addr::remote() filter only look at remote_addr from TCP socket.
        // HTTP headers are not considered. This also means that innernet
        // server would not function behind an HTTP proxy.
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[tokio::test]
    async fn test_unparseable_public_key() -> Result<(), Error> {
        let server = test::Server::new()?;

        let path = if cfg!(feature = "v6-test") {
            format!("http://[{}]/v1/user/state", test::WG_MANAGE_PEER_IP)
        } else {
            format!("http://{}/v1/user/state", test::WG_MANAGE_PEER_IP)
        };
        let req = Request::builder()
            .uri(path)
            .header(innernet_shared::INNERNET_PUBKEY_HEADER, "!!!")
            .body(Body::empty())
            .unwrap();
        let res = if cfg!(feature = "v6-test") {
            server.raw_request("fd00:1337::1337", req).await
        } else {
            server.raw_request("10.80.80.80", req).await
        };

        // addr::remote() filter only look at remote_addr from TCP socket.
        // HTTP headers are not considered. This also means that innernet
        // server would not function behind an HTTP proxy.
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }
}
