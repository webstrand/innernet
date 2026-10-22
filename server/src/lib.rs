use anyhow::bail;
use colored::*;
use coordinator::{Coordinator, Hooks, Sockets};
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
    net::{IpAddr, SocketAddr, TcpListener},
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
    let config = ConfigFile::from_file(conf.config_path(&interface))?;
    log::debug!("opening database connection...");
    let store = open_database_connection(&interface, conf)?;
    let public_key = check_database_matches_config(&store, &config)?;

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

    log::info!("innernet-server {} starting.", VERSION);
    let coordinator = Coordinator::spawn(
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
    use crate::test;
    use anyhow::Result;
    use hyper::{Body, Request, StatusCode};
    use std::path::Path;

    #[test]
    fn test_init_wizard() -> Result<(), Error> {
        // This runs init_wizard().
        let server = test::Server::new()?;

        assert!(Path::new(&server.wg_conf_path()).exists());

        // The server's own peer has the key of the config.
        let config = ConfigFile::from_file(server.wg_conf_path())?;
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
