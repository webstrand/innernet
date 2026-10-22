use anyhow::{anyhow, bail};
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
    snapshot::SnapshotConfig,
    Store,
};
use innernet_shared::{
    interface_config::{InterfaceConfig, ServerInfo, FEATURE_TLS},
    prompts, wg, Error, HostsOpts, Interface, IoErrorContext, NatOpts, NetworkOpts,
};
use node::LocalLink;
use parking_lot::Mutex;
use std::{
    collections::BTreeMap,
    env,
    fs::File,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use wireguard_control::{InterfaceName, Key};

mod api;
pub mod config;
mod coordinator;
mod db;
mod error;
pub mod initialize;
mod node;
mod quic;
#[cfg(test)]
mod test;
mod util;

pub use config::{ConfigFile, V2Layout};
pub(crate) use coordinator::{hyper_service, ConnectionMode, Db, Endpoints};
pub use coordinator::{Context, Session};
pub use error::ServerError;

const VERSION: &str = env!("CARGO_PKG_VERSION");

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

/// Opens the database of `interface`, for the network of `config`, migrating a database of
/// v2.0.0, whose coordinator is the peer with the public key of the config's private key.
fn open_database_connection(
    interface: &InterfaceName,
    conf: &ServerConfig,
    config: &ConfigFile,
) -> Result<Store, Error> {
    let database_path = conf.database_path(interface);
    if !Path::new(&database_path).exists() {
        bail!(
            "no database file found at {}",
            database_path.to_string_lossy()
        );
    }
    let server_key = Key::from_base64(&config.interface.private_key)?.get_public();

    let file = File::open(&database_path).with_path(&database_path)?;
    innernet_shared::warn_on_dangerous_mode(&file, &database_path).with_path(&database_path)?;
    drop(file);
    let store = db::open(&database_path, &server_key, config.network())?;
    // The server's node core takes the peers that have never announced as the server makes them,
    // as clients do.
    DatabasePeer::admit_synthesized(&store)?;
    Ok(store)
}

/// The admin client of the coordinator of a network, which the running server serves: the
/// server's own peer, an admin, over TLS, at the primary IP and the QUIC port of its config, with
/// the coordinator named as invitations name it, at the bootstrap endpoint. Every change of the
/// network goes through the coordinator, so a command fails if the server isn't running.
pub struct AdminClient {
    interface: InterfaceName,
    config: InterfaceConfig,
}

impl AdminClient {
    pub fn new(interface: &InterfaceName, conf: &ServerConfig) -> Result<Self, Error> {
        let config = ConfigFile::from_file(conf.config_path(interface))?;
        let incomplete = || {
            anyhow!(
                "the config is incomplete; `innernet-server serve {}` names what it lacks",
                interface.as_str_lossy()
            )
        };
        let server = ServerInfo {
            public_key: Key::from_base64(&config.interface.private_key)?
                .get_public()
                .to_base64(),
            external_endpoint: config
                .coordinator
                .bootstrap_endpoint
                .clone()
                .ok_or_else(incomplete)?,
            internal_endpoint: SocketAddr::new(config.address(), config.listen_port()),
            features: vec![FEATURE_TLS.to_string()],
            quic_port: Some(config.coordinator.quic_port.ok_or_else(incomplete)?),
        };
        Ok(Self {
            interface: *interface,
            config: InterfaceConfig::new(config.interface, server),
        })
    }

    /// The coordinator, as invitations name it.
    pub fn server(&self) -> &ServerInfo {
        &self.config.server
    }

    pub fn rest_client(&self) -> Result<RestClient<'_>, Error> {
        Ok(RestClient::new(&self.config, true)?.on_interface(&self.interface))
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
    let (config, v2) = match ConfigFile::from_file(&config_path) {
        Ok(config) => (config, false),
        Err(e) => match e.downcast::<V2Layout>() {
            Ok(V2Layout(config)) => (config, true),
            Err(e) => return Err(e),
        },
    };
    config.check_primary_ip()?;
    log::debug!("opening database connection...");
    let store = open_database_connection(&interface, conf, &config)?;
    let public_key = check_database_matches_config(&store, &config)?;
    let myself = DatabasePeer::get_from_public_key(&store, &public_key)?;
    check_internal_address(&myself, config.address())?;
    // Nothing writes the config, so a config that lacks what the server needs, or one in the
    // layout of v2.0.0, is refused with the config that the operator must write in its place.
    let (completed, missing) = complete(&config, &myself)?;
    if v2 || !missing.is_empty() {
        let refusal = if v2 {
            format!(
                "{} is in the layout of innernet-server 2.0.0, which this version doesn't read",
                config_path.display()
            )
        } else {
            format!(
                "{} states no {} in [coordinator]",
                config_path.display(),
                missing.join(" nor ")
            )
        };
        bail!(
            "{refusal}; nothing writes the config, so the operator must replace it with:\n\n{}",
            completed.to_toml()?
        );
    }
    let quic_port = config
        .coordinator
        .quic_port
        .expect("a complete config states the QUIC port");

    log::info!("bringing up interface.");
    wg::up(
        &interface,
        &config.interface.private_key,
        config.interface.address,
        Some(config.listen_port()),
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
    // QUIC never completes a handshake over an interface whose MTU can't carry its datagrams.
    tunnel
        .capabilities()
        .check_quic_mtu(&interface, config.address())?;
    log::info!("the TLS API's QUIC port is {quic_port}.");
    let db = Arc::new(Mutex::new(store));
    let changed = StoreChanged::default();
    let mut node = Node {
        interface,
        info: config.interface.clone(),
        listen_port: config.listen_port(),
        nat: NatOpts {
            no_nat_traversal: false,
            exclude_nat_candidates: vec![],
            no_nat_candidates: false,
        },
        snapshot_config: SnapshotConfig {
            route_primary_ip: true,
        },
        tunnel: Box::new(tunnel),
    };
    let mut dns = DnsService::new(interface, hosts_opts.host_suffix.clone());
    let mut link = LocalLink {
        db: db.clone(),
        server_key: public_key,
        bootstrap: config.coordinator.bootstrap_endpoint.clone(),
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

    log::info!("innernet-server {} starting.", VERSION);
    // The TLS API runs over QUIC, at the primary IP, on a port of its own.
    let sockets = Sockets {
        quic: get_udp_socket((config.address(), quic_port).into(), &interface)?,
        legacy: config
            .coordinator
            .legacy_api
            .then(|| get_listener((config.address(), config.listen_port()).into(), &interface))
            .transpose()?,
    };
    let coordinator = Coordinator::spawn(
        CoordinatorConfig {
            network_name: interface,
            address: config.address(),
            quic_port,
            network: config.network(),
        },
        &config.interface.private_key,
        db,
        sockets,
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

/// `config` with the keys of `[coordinator]` that the server needs to start, and the keys that it
/// lacks, each with a value to add: a free UDP port as the QUIC port, and as the bootstrap
/// endpoint the endpoint that `myself`, the server's own peer, last announced first, or, before
/// its first announcement, the endpoint that the server was initialized with.
fn complete(
    config: &ConfigFile,
    myself: &DatabasePeer,
) -> Result<(ConfigFile, Vec<&'static str>), Error> {
    let mut completed = config.clone();
    let mut missing = vec![];
    if completed.coordinator.quic_port.is_none() {
        let unspecified = match config.address() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        completed.coordinator.quic_port = Some(free_udp_port(unspecified, config.listen_port())?);
        missing.push("quic-port");
    }
    if completed.coordinator.bootstrap_endpoint.is_none() {
        let endpoint = match myself.signed_announcement() {
            Some(announced) => announced.endpoints.first().cloned(),
            None => myself.endpoint.clone(),
        };
        completed.coordinator.bootstrap_endpoint = Some(endpoint.ok_or_else(|| {
            anyhow!(
                "the config states no bootstrap-endpoint in [coordinator], and the server knows \
                 none to suggest; the operator must add the endpoint at which invitees reach the \
                 server"
            )
        })?);
        missing.push("bootstrap-endpoint");
    }
    Ok((completed, missing))
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
fn check_database_matches_config(store: &Store, config: &ConfigFile) -> Result<Key, Error> {
    let public_key = Key::from_base64(&config.interface.private_key)?.get_public();
    if DatabasePeer::get_from_public_key(store, &public_key).is_err() {
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

/// A UDP socket bound to `addr`, and on Linux to `interface` too, as [`get_listener`] binds a
/// TCP listener, so that only the tunnel's traffic reaches it.
#[cfg(target_os = "linux")]
fn get_udp_socket(addr: SocketAddr, interface: &InterfaceName) -> Result<UdpSocket, Error> {
    let socket = socket2::Socket::from(UdpSocket::bind(addr)?);
    socket.bind_device(Some(interface.as_str_lossy().as_bytes()))?;
    Ok(socket.into())
}

/// A UDP socket bound to `addr`, as [`get_listener`] binds a TCP listener.
#[cfg(not(target_os = "linux"))]
fn get_udp_socket(addr: SocketAddr, _interface: &InterfaceName) -> Result<UdpSocket, Error> {
    Ok(UdpSocket::bind(addr)?)
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
    use crate::{coordinator::serve_legacy_api, test};
    use anyhow::Result;
    use hyper::{Body, Request, StatusCode};
    use innernet_shared::{Prefix, INNERNET_PUBKEY_HEADER};
    use std::path::Path;
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
        net::TcpStream,
    };
    use wireguard_control::KeyPair;

    #[test]
    fn test_init_wizard() -> Result<(), Error> {
        // This runs init_wizard().
        let server = test::Server::new()?;

        assert!(Path::new(&server.wg_conf_path()).exists());
        let config = ConfigFile::from_file(server.wg_conf_path())?;
        assert_eq!(config.coordinator.quic_port, Some(54322));

        // The server's own peer has the key of the config.
        let key = Key::from_base64(&config.interface.private_key)?.get_public();
        let own = DatabasePeer::get_from_public_key(&server.db().lock(), &key)?;
        assert_eq!(own.name.as_deref(), Some("innernet-server"));

        // A config whose key no peer has doesn't match the database.
        assert_eq!(
            check_database_matches_config(&server.db().lock(), &config)?,
            key
        );
        let mut other = config;
        other.interface.private_key = Key::generate_private().to_base64();
        assert!(check_database_matches_config(&server.db().lock(), &other).is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_server_announces_itself() -> Result<(), Error> {
        // The server signs the announcement of its own peer, as every peer signs its own: its
        // primary IP is the internal address, and its preferred endpoint the one that it was
        // initialized with, which it keeps, before its local candidates.
        let server = test::Server::new()?;
        let config = ConfigFile::from_file(server.wg_conf_path())?;
        let public_key = Key::from_base64(&config.interface.private_key)?.get_public();
        let db = server.db();
        let initialized_endpoint = DatabasePeer::get_from_public_key(&db.lock(), &public_key)?
            .endpoint
            .clone()
            .expect("the endpoint that the server was initialized with");

        let interface: InterfaceName = "test".parse()?;
        let node = Node {
            interface,
            info: config.interface.clone(),
            listen_port: config.listen_port(),
            nat: NatOpts::all_disabled(),
            snapshot_config: SnapshotConfig::default(),
            tunnel: Box::new(WireGuard {
                interface,
                backend: wireguard_control::Backend::Userspace,
                endpoint_overrides: BTreeMap::new(),
                events: EventSource::default(),
            }),
        };
        let mut link = LocalLink {
            db: db.clone(),
            server_key: public_key.clone(),
            bootstrap: None,
        };
        node.announce(&mut link).await?;
        let announced = DatabasePeer::get_from_public_key(&db.lock(), &public_key)?;
        assert!(announced.announcement.as_ref().unwrap().is_signed());
        let announcement = announced.announced.clone().unwrap();
        assert_eq!(announcement.primary_ip, Some(config.address()));
        assert_eq!(
            announcement.endpoints,
            std::slice::from_ref(&initialized_endpoint)
        );
        assert_eq!(announcement.claims.delegation, announced.delegations);
        assert_eq!(
            announced.effective().endpoint,
            Some(initialized_endpoint.clone())
        );

        // Announcing again changes nothing, so no announcement is made, and the endpoint stays
        // the one that it last announced.
        node.announce(&mut link).await?;
        let again = DatabasePeer::get_from_public_key(&db.lock(), &public_key)?
            .announced
            .unwrap();
        assert_eq!(again, announcement);
        Ok(())
    }

    #[test]
    fn test_incomplete_config_is_completed() -> Result<(), Error> {
        // A config without the QUIC port or the bootstrap endpoint gets both suggested, and
        // nothing writes them.
        let server = test::Server::new()?;
        let mut config = ConfigFile::from_file(server.wg_conf_path())?;
        let myself = DatabasePeer::get_from_public_key(&server.db.lock(), server.public_key())?;
        assert!(complete(&config, &myself)?.1.is_empty());
        config.coordinator.quic_port = None;
        config.coordinator.bootstrap_endpoint = None;
        let (completed, missing) = complete(&config, &myself)?;
        assert_eq!(missing, ["quic-port", "bootstrap-endpoint"]);
        assert_ne!(completed.coordinator.quic_port, Some(config.listen_port()));
        assert_eq!(completed.coordinator.bootstrap_endpoint, myself.endpoint);
        assert_eq!(
            ConfigFile::from_file(server.wg_conf_path())?
                .coordinator
                .quic_port,
            Some(54322)
        );
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
        let myself = DatabasePeer::get_from_public_key(&store, server.public_key())?;
        check_internal_address(&myself, config.address())?;
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
    async fn test_serves_only_plain_http_over_tcp() -> Result<(), Error> {
        let server = test::Server::new()?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(serve_legacy_api(listener, server.context()));

        // Plain HTTP is served; nothing is at the loopback's IP.
        let plain = TcpStream::connect(addr).await?;
        assert_eq!(
            status_line(plain, &server_key(&server), "/v1/user/state").await,
            "HTTP/1.1 401 Unauthorized"
        );

        // TLS isn't: the start of a TLS handshake is a malformed request.
        let mut tls = TcpStream::connect(addr).await?;
        tls.write_all(&[0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00])
            .await?;
        let mut response = Vec::new();
        tls.read_to_end(&mut response).await?;
        assert!(response.starts_with(b"HTTP/1.1 400 "), "{response:?}");
        Ok(())
    }

    #[tokio::test]
    async fn test_serves_the_tls_api_over_quic() -> Result<(), Error> {
        let server = test::Server::new()?;
        let server_tls_key = KeyPair::generate();
        let addr = test::serve_quic(&server, &server_tls_key)?;

        // A peer whose private key is known, at an IP other than the loopback's.
        let peer_key = KeyPair::generate();
        let ip = if cfg!(feature = "v6-test") {
            "fd00:1337::2:0:0:9"
        } else {
            "10.80.64.9"
        };
        let mut contents = test::developer_peer_contents("developer3", ip)?;
        contents.public_key = peer_key.public.to_base64();
        DatabasePeer::create(&server.db.lock(), contents)?;
        server.predate_tls_key(&peer_key.public.to_base64());
        let header_key = server_key(&server);
        let pinned = &server_tls_key.public;
        let client = Some(&peer_key);

        // The peer's key is accepted by the handshake, but not from an IP other than its own,
        // and that doesn't latch it.
        let (status, _) = test::quic_get(addr, client, pinned, &header_key, "/user/state").await?;
        assert_eq!(status, 401);
        assert!(!DatabasePeer::get_by_address(&server.db.lock(), ip.parse()?)?.requires_tls);

        // From an address of its delegations, it is served, and latched.
        {
            let store = server.db.lock();
            crate::db::peer::insert_delegation(
                &store,
                &peer_key.public.0,
                &Prefix::host(addr.ip()),
            )?;
            DatabasePeer::admit_synthesized(&store)?;
        }
        let (status, body) =
            test::quic_get(addr, client, pinned, &header_key, "/user/state").await?;
        assert_eq!(status, 200);
        let _: innernet_shared::State = innernet_shared::cbor::from_slice(&body)?;
        assert!(DatabasePeer::get_by_address(&server.db.lock(), ip.parse()?)?.requires_tls);

        // A client without a key connects, as an anonymous client, which the route refuses for
        // the lack of a key, though its address is that of the peer.
        let (status, body) = test::quic_get(addr, None, pinned, &header_key, "/user/state").await?;
        assert_eq!(status, 403);
        let problem: innernet_shared::problem::Problem = innernet_shared::cbor::from_slice(&body)?;
        assert!(problem.is(&innernet_shared::problem::CLIENT_KEY_REQUIRED));
        // It may use the public routes.
        let (status, body) = test::quic_get(addr, None, pinned, &header_key, "/server").await?;
        assert_eq!(status, 200);
        let description: innernet_shared::ServerDescription =
            innernet_shared::cbor::from_slice(&body)?;
        assert_eq!(description.public_key, header_key);

        // A client pinning another server key refuses the handshake, with a key or without.
        let wrong = KeyPair::generate().public;
        let refused = test::quic_get(addr, client, &wrong, &header_key, "/user/state").await;
        assert!(refused.is_err());
        let refused = test::quic_get(addr, None, &wrong, &header_key, "/user/state").await;
        assert!(refused.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_order_of_checks() -> Result<(), Error> {
        let server = test::Server::new()?;
        let ip = test::DEVELOPER1_PEER_IP;
        let unacceptable = |req: &mut Request<Body>| {
            req.headers_mut().insert(
                hyper::header::ACCEPT,
                "application/vnd.innernet+cbor; version=2".parse().unwrap(),
            );
        };

        // An anonymous connection is refused every route that requires a client key, and every
        // path that the server has no route for, alike, before the content type and Accept are
        // checked, so that it can't probe for routes.
        for (method, path) in [
            ("GET", "/user/state"),
            ("GET", "/admin/peers"),
            ("GET", "/nothing"),
            ("GET", "/v1/user/state"),
            ("PUT", "/user/candidates"),
        ] {
            for unacceptable_accept in [false, true] {
                let mut req = server.body_request(method, path, "text/plain", vec![0]);
                if unacceptable_accept {
                    unacceptable(&mut req);
                }
                let res = server.anonymous_request(ip, req).await;
                test::problem(res, &innernet_shared::problem::CLIENT_KEY_REQUIRED).await?;
            }
        }

        // An authenticated connection is told that a path has no route before the content type
        // and Accept are checked, and those before the handler checks the session.
        let mut req = server.empty_request("GET", "/nothing");
        unacceptable(&mut req);
        let res = server.raw_request(ip, req).await;
        test::blank_problem(res, StatusCode::NOT_FOUND).await?;
        let mut req = server.empty_request("GET", "/user/state");
        unacceptable(&mut req);
        let res = server
            .raw_request_as(ip, Some(KeyPair::generate().public), req)
            .await;
        test::blank_problem(res, StatusCode::NOT_ACCEPTABLE).await?;
        let res = server
            .raw_request_as(
                ip,
                Some(KeyPair::generate().public),
                server.empty_request("GET", "/user/state"),
            )
            .await;
        test::blank_problem(res, StatusCode::UNAUTHORIZED).await?;
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
