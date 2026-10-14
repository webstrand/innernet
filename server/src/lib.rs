use anyhow::{anyhow, bail};
use colored::*;
use db::{DatabaseCidr, DatabasePeer};
use dialoguer::Confirm;
use hyper::{http, service::service_fn, Body, Request, Response};
use indoc::printdoc;
use innernet_shared::{
    get_local_addrs,
    interface_config::{InterfaceInfo, PeerInvitation, ServerInfo},
    prompts, tls, update_hosts_file, wg, AddCidrOpts, AddPeerOpts, CidrTree, DeleteCidrOpts,
    DeleteForgetPeerOpts, EnableDisablePeerOpts, Endpoint, Error, HostsOpts, Interface,
    IoErrorContext, NetworkOpts, Peer, PeerContents, RenameCidrOpts, RenamePeerOpts,
    INNERNET_PUBKEY_HEADER,
};
use ipnet::IpNet;
use parking_lot::{Mutex, RwLock};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    convert::TryInto,
    env,
    fs::{File, OpenOptions},
    io::prelude::*,
    net::{IpAddr, SocketAddr, TcpListener},
    ops::Deref,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::{rustls, TlsAcceptor};
use wireguard_control::{
    Backend, Device, DeviceUpdate, InterfaceName, Key, KeyPair, PeerConfigBuilder,
};

mod api;
mod db;
mod error;
pub mod initialize;
#[cfg(test)]
mod test;
mod util;

pub use error::ServerError;

const VERSION: &str = env!("CARGO_PKG_VERSION");

type Db = Arc<Mutex<Connection>>;
type Endpoints = Arc<RwLock<HashMap<String, SocketAddr>>>;

#[derive(Clone)]
pub struct Context {
    pub db: Db,
    pub endpoints: Endpoints,
    pub interface: InterfaceName,
    pub backend: Backend,
    pub public_key: Key,
    /// How far ahead of the server's clock an announcement may be dated.
    pub max_clock_ahead: Duration,
}

pub struct Session {
    pub context: Context,
    pub peer: DatabasePeer,
}

impl Session {
    pub fn admin_capable(&self) -> bool {
        self.peer.is_admin && self.user_capable()
    }

    pub fn user_capable(&self) -> bool {
        !self.peer.is_disabled && self.peer.is_redeemed
    }

    pub fn redeemable(&self) -> bool {
        !self.peer.is_disabled && !self.peer.is_redeemed
    }
}

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
}

impl ConfigFile {
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

fn open_database_connection(
    interface: &InterfaceName,
    conf: &ServerConfig,
) -> Result<rusqlite::Connection, Error> {
    let database_path = conf.database_path(interface);
    if !Path::new(&database_path).exists() {
        bail!(
            "no database file found at {}",
            database_path.to_string_lossy()
        );
    }

    // TODO(strohel): warn about too open permissions on the db file?
    let conn = Connection::open(&database_path)?;
    // Foreign key constraints aren't on in SQLite by default. Enable.
    conn.pragma_update(None, "foreign_keys", 1)?;
    db::auto_migrate(&conn)?;
    Ok(conn)
}

/// Replaces a peer's allowed IPs on the interface after its delegations changed. Disabled peers
/// aren't on the interface, and are left off it.
pub(crate) fn update_allowed_ips(
    peer: &Peer,
    interface: &InterfaceName,
    backend: Backend,
) -> Result<(), ServerError> {
    if peer.is_disabled {
        return Ok(());
    }
    let public_key = Key::from_base64(&peer.public_key).map_err(|_| ServerError::WireGuard)?;
    DeviceUpdate::new()
        .add_peer(
            PeerConfigBuilder::new(&public_key)
                .replace_allowed_ips()
                .add_allowed_ips(&peer.allowed_ips()),
        )
        .apply(interface, backend)
        .map_err(|_| ServerError::WireGuard)
}

pub fn add_peer(
    interface: &InterfaceName,
    conf: &ServerConfig,
    opts: AddPeerOpts,
    network: NetworkOpts,
) -> Result<(), Error> {
    let config = ConfigFile::from_file(conf.config_path(interface))?;
    let conn = open_database_connection(interface, conf)?;
    let peers = DatabasePeer::list(&conn)?
        .into_iter()
        .map(|dp| dp.inner)
        .collect::<Vec<_>>();
    let cidrs = DatabaseCidr::list(&conn)?;
    let cidr_tree = CidrTree::new(&cidrs[..]);

    if let Some((new_peer_info, target_path)) =
        innernet_shared::prompts::gather_new_peer_info(&peers, &cidr_tree, &opts)?
    {
        let keypair = KeyPair::generate();
        let peer_contents = new_peer_info.into_peer_contents(&keypair);
        let peer = DatabasePeer::create(&conn, peer_contents)?;
        if cfg!(not(test)) && Device::get(interface, network.backend).is_ok() {
            // Update the current WireGuard interface with the new peers.
            DeviceUpdate::new()
                .add_peer(PeerConfigBuilder::from(&*peer))
                .apply(interface, network.backend)
                .map_err(|_| ServerError::WireGuard)?;

            println!("adding to WireGuard interface: {}", *peer);
        }

        let address = cidr_tree
            .ip_net_for(peer.ip)
            .expect("Peer's IpNet address to be valid because the peer was created successfully.");
        let interface_info = InterfaceInfo::new(interface, &keypair, address);

        let internal_endpoint = SocketAddr::new(config.address, config.listen_port);
        let server_peer = DatabasePeer::get(&conn, 1)?;
        let server_info = ServerInfo::new(&server_peer, internal_endpoint);

        let invitation = PeerInvitation::new(interface_info, server_info);
        invitation.save_new(target_path)?;
    } else {
        println!("exited without creating peer.");
    }

    Ok(())
}

pub fn rename_peer(
    interface: &InterfaceName,
    conf: &ServerConfig,
    opts: RenamePeerOpts,
) -> Result<(), Error> {
    let conn = open_database_connection(interface, conf)?;
    let peers = DatabasePeer::list(&conn)?
        .into_iter()
        .map(|dp| dp.inner)
        .collect::<Vec<_>>();

    if let Some((peer_request, id)) = innernet_shared::prompts::rename_peer(&peers, &opts)? {
        let mut db_peer = DatabasePeer::get(&conn, id)?;
        db_peer.update(&conn, peer_request)?;
    } else {
        println!("exited without creating peer.");
    }

    Ok(())
}

pub fn enable_or_disable_peer(
    interface: &InterfaceName,
    conf: &ServerConfig,
    enable: bool,
    network: NetworkOpts,
    opts: EnableDisablePeerOpts,
) -> Result<(), Error> {
    let conn = open_database_connection(interface, conf)?;
    let peers = DatabasePeer::list(&conn)?
        .into_iter()
        .map(|dp| dp.inner)
        .collect::<Vec<_>>();

    if let Some(peer) = prompts::enable_or_disable_peer(&peers[..], &opts, enable)? {
        let mut db_peer = DatabasePeer::get(&conn, peer.id)?;
        db_peer.update(
            &conn,
            PeerContents {
                is_disabled: !enable,
                ..peer.contents.clone()
            },
        )?;

        if enable {
            DeviceUpdate::new()
                .add_peer(db_peer.deref().into())
                .apply(interface, network.backend)
                .map_err(|_| ServerError::WireGuard)?;
        } else {
            let public_key =
                Key::from_base64(&peer.public_key).map_err(|_| ServerError::WireGuard)?;

            DeviceUpdate::new()
                .remove_peer_by_key(&public_key)
                .apply(interface, network.backend)
                .map_err(|_| ServerError::WireGuard)?;
        }
    } else {
        log::info!("exiting without enabling or disabling peer.");
    }

    Ok(())
}

pub fn delete_peer(
    interface: &InterfaceName,
    conf: &ServerConfig,
    network: NetworkOpts,
    opts: DeleteForgetPeerOpts,
) -> Result<(), Error> {
    let conn = open_database_connection(interface, conf)?;
    // Only disabled peers can be deleted, so that they have been removed from every
    // up-to-date client's interface before their IP can be handed out again.
    let disabled_peers = DatabasePeer::list(&conn)?
        .into_iter()
        .map(|dp| dp.inner)
        .filter(|peer| peer.is_disabled)
        .collect::<Vec<_>>();

    if let Some(peer) = prompts::delete_or_forget_peer(&disabled_peers[..], &opts, "delete")? {
        DatabasePeer::delete(&conn, peer.id)?;

        // Disabled peers should already be absent from the interface; the removal is
        // repeated as a safeguard.
        let public_key = Key::from_base64(&peer.public_key).map_err(|_| ServerError::WireGuard)?;
        if let Err(e) = DeviceUpdate::new()
            .remove_peer_by_key(&public_key)
            .apply(interface, network.backend)
        {
            log::warn!("failed to remove peer from WireGuard interface: {e}");
        }

        printdoc!(
            "
            Peer {name} ({ip}) deleted. Its name and IP can now be reused.

            Clients that have seen this peer pin its public key to {ip}, and refuse a
            new peer at that IP until the following command has been run on each of them:

                innernet forget-peer {interface} --name {name}
            ",
            name = peer.display_name().yellow(),
            ip = peer.ip,
        );
    } else {
        log::info!("exiting without deleting peer.");
    }

    Ok(())
}

pub fn add_cidr(
    interface: &InterfaceName,
    conf: &ServerConfig,
    opts: AddCidrOpts,
) -> Result<(), Error> {
    let conn = open_database_connection(interface, conf)?;
    let cidrs = DatabaseCidr::list(&conn)?;
    if let Some(cidr_request) = innernet_shared::prompts::add_cidr(&cidrs, &opts)? {
        let cidr = DatabaseCidr::create(&conn, cidr_request)?;
        printdoc!(
            "
            CIDR \"{cidr_name}\" added.

            Right now, peers within {cidr_name} can only see peers in the same CIDR, and in
            the special \"innernet-server\" CIDR that includes the innernet server peer.

            You'll need to add more associations for peers in diffent CIDRs to communicate.
            ",
            cidr_name = cidr.name.bold()
        );
    } else {
        println!("exited without creating CIDR.");
    }

    Ok(())
}

pub fn rename_cidr(
    interface: &InterfaceName,
    conf: &ServerConfig,
    opts: RenameCidrOpts,
) -> Result<(), Error> {
    let conn = open_database_connection(interface, conf)?;
    let cidrs = DatabaseCidr::list(&conn)?;

    if let Some((cidr_request, old_name)) = innernet_shared::prompts::rename_cidr(&cidrs, &opts)? {
        let db_cidr = DatabaseCidr::list(&conn)?
            .into_iter()
            .find(|c| c.name == old_name)
            .ok_or_else(|| anyhow!("CIDR not found."))?;
        db::DatabaseCidr::from(db_cidr).update(&conn, cidr_request)?;
    } else {
        println!("exited without renaming CIDR.");
    }

    Ok(())
}

pub fn delete_cidr(
    interface: &InterfaceName,
    conf: &ServerConfig,
    args: DeleteCidrOpts,
) -> Result<(), Error> {
    println!("Fetching eligible CIDRs");
    let conn = open_database_connection(interface, conf)?;
    let cidrs = DatabaseCidr::list(&conn)?;
    let peers = DatabasePeer::list(&conn)?
        .into_iter()
        .map(|dp| dp.inner)
        .collect::<Vec<_>>();

    let cidr_id = prompts::delete_cidr(&cidrs, &peers, &args)?;

    println!("Deleting CIDR...");
    DatabaseCidr::delete(&conn, cidr_id)?;

    println!("CIDR deleted.");

    Ok(())
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

fn spawn_endpoint_refresher(interface: InterfaceName, network: NetworkOpts) -> Endpoints {
    let endpoints = Arc::new(RwLock::new(HashMap::new()));
    tokio::task::spawn({
        let endpoints = endpoints.clone();
        async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                if let Ok(info) = Device::get(&interface, network.backend) {
                    for peer in info.peers {
                        if let Some(endpoint) = peer.config.endpoint {
                            endpoints
                                .write()
                                .insert(peer.config.public_key.to_base64(), endpoint);
                        }
                    }
                }
            }
        }
    });
    endpoints
}

fn spawn_expired_invite_sweeper(db: Db) {
    tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            match DatabasePeer::delete_expired_invites(&db.lock()) {
                Ok(deleted) if deleted > 0 => {
                    log::info!("Deleted {} expired peer invitations.", deleted)
                },
                Err(e) => log::error!("Failed to delete expired peer invitations: {}", e),
                _ => {},
            }
        }
    });
}

fn spawn_hostfile_writer(db: Db, interface: InterfaceName, hosts_opts: HostsOpts) {
    tokio::task::spawn({
        async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;

                match DatabasePeer::list_enabled(&db.lock()) {
                    Ok(peers) => {
                        if let Err(e) = update_hosts_file(
                            &interface,
                            &hosts_opts,
                            peers.into_iter().map(|peer| peer.inner),
                        ) {
                            log::error!("Failed to write hostfile: {}", e);
                        }
                    },
                    Err(e) => {
                        log::error!("Failed to list enabled peers for hostfile writing: {}", e)
                    },
                }
            }
        }
    });
}

pub async fn serve(
    interface: InterfaceName,
    conf: &ServerConfig,
    network: NetworkOpts,
    hosts_opts: HostsOpts,
    max_clock_ahead: Duration,
) -> Result<(), Error> {
    let config = ConfigFile::from_file(conf.config_path(&interface))?;
    log::debug!("opening database connection...");
    let conn = open_database_connection(&interface, conf)?;

    let mut peers = DatabasePeer::list(&conn)?;
    log::debug!("peers listed...");
    let peer_configs = peers
        .iter()
        .map(|peer| peer.deref().into())
        .collect::<Vec<PeerConfigBuilder>>();

    log::info!("bringing up interface.");
    wg::up(
        &interface,
        &config.private_key,
        IpNet::new(config.address, config.network_cidr_prefix)?,
        Some(config.listen_port),
        None,
        &network,
    )?;

    DeviceUpdate::new()
        .add_peers(&peer_configs)
        .apply(&interface, network.backend)?;

    log::info!("{} peers added to wireguard interface.", peers.len());

    let candidates: Vec<Endpoint> = get_local_addrs()?
        .map(|addr| SocketAddr::from((addr, config.listen_port)).into())
        .collect();
    let num_candidates = candidates.len();
    let public_key = wireguard_control::Key::from_base64(&config.private_key)?.get_public();
    let myself = peers
        .iter_mut()
        .find(|peer| peer.public_key == public_key.to_base64())
        .expect("Couldn't find server peer in peer list.");
    myself.update(
        &conn,
        PeerContents {
            candidates,
            ..myself.contents.clone()
        },
    )?;

    log::info!(
        "{} local candidates added to server peer config.",
        num_candidates
    );

    let db = Arc::new(Mutex::new(conn));
    let endpoints = spawn_endpoint_refresher(interface, network);
    spawn_expired_invite_sweeper(db.clone());

    if !hosts_opts.no_write_hosts {
        spawn_hostfile_writer(db.clone(), interface, hosts_opts);
    }

    let context = Context {
        db,
        endpoints,
        interface,
        public_key,
        backend: network.backend,
        max_clock_ahead,
    };

    log::info!("innernet-server {} starting.", VERSION);

    let tls_config = tls::server_config(&config.private_key)?;
    let listener = get_listener((config.address, config.listen_port).into(), &interface)?;
    serve_api(
        tokio::net::TcpListener::from_std(listener)?,
        context,
        tls_config,
    )
    .await
}

/// How long a client may take to send its first byte, and then to complete a TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Serves the API in TLS and, for clients that predate it, in plain HTTP on the same port.
async fn serve_api(
    listener: tokio::net::TcpListener,
    context: Context,
    tls_config: Arc<rustls::ServerConfig>,
) -> Result<(), Error> {
    let acceptor = TlsAcceptor::from(tls_config);
    loop {
        let (stream, remote_addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                // Such as running out of file descriptors, which may pass.
                log::warn!("failed to accept a connection: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            },
        };
        let (context, acceptor) = (context.clone(), acceptor.clone());
        tokio::spawn(async move {
            if let Err(e) = serve_connection(stream, remote_addr, context, acceptor).await {
                log::debug!("{remote_addr} - connection failed: {e}");
            }
        });
    }
}

/// Serves one connection, in TLS if it starts with a TLS handshake record, which no HTTP
/// request does, and in plain HTTP otherwise.
async fn serve_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    context: Context,
    acceptor: TlsAcceptor,
) -> Result<(), Error> {
    let mut first_byte = [0u8; 1];
    if timeout(HANDSHAKE_TIMEOUT, stream.peek(&mut first_byte)).await?? == 0 {
        return Ok(());
    }
    let mut http = hyper::server::conn::Http::new();
    http.http1_only(true);

    if first_byte[0] == tls::TLS_HANDSHAKE_RECORD {
        let stream = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await??;
        let client_key = tls::peer_public_key(stream.get_ref().1.peer_certificates())
            .ok_or_else(|| anyhow!("the client presented no usable key"))?;
        let service = service_fn(move |req: Request<Body>| {
            log::debug!("{} (TLS) - {} {}", remote_addr, req.method(), req.uri());
            hyper_service(req, context.clone(), remote_addr, Some(client_key.clone()))
        });
        http.serve_connection(stream, service).await?;
    } else {
        let service = service_fn(move |req: Request<Body>| {
            log::debug!("{} - {} {}", remote_addr, req.method(), req.uri());
            hyper_service(req, context.clone(), remote_addr, None)
        });
        http.serve_connection(stream, service).await?;
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

/// Serves a request from `remote_addr`. `client_key` is the key the client authenticated with
/// over TLS, if it connected that way.
pub(crate) async fn hyper_service(
    req: Request<Body>,
    context: Context,
    remote_addr: SocketAddr,
    client_key: Option<Key>,
) -> Result<Response<Body>, http::Error> {
    // Break the path into components.
    let components: VecDeque<_> = req
        .uri()
        .path()
        .trim_start_matches('/')
        .split('/')
        .map(String::from)
        .collect();

    routes(req, context, remote_addr, client_key, components)
        .await
        .or_else(TryInto::try_into)
}

async fn routes(
    req: Request<Body>,
    context: Context,
    remote_addr: SocketAddr,
    client_key: Option<Key>,
    mut components: VecDeque<String>,
) -> Result<Response<Body>, ServerError> {
    // Must be "/v1/[something]"
    if components.pop_front().as_deref() != Some("v1") {
        Err(ServerError::NotFound)
    } else {
        let session = get_session(&req, context, remote_addr.ip(), client_key.as_ref())?;
        let component = components.pop_front();
        match component.as_deref() {
            Some("user") => api::user::routes(req, components, session).await,
            Some("admin") => api::admin::routes(req, components, session).await,
            _ => Err(ServerError::NotFound),
        }
    }
}

/// Identifies the peer making a request: by the key it authenticated with over TLS if it did,
/// otherwise by its source IP, which anything on the peer's machine can send from. Peers that
/// have once connected over TLS are refused the latter from then on.
fn get_session(
    req: &Request<Body>,
    context: Context,
    addr: IpAddr,
    client_key: Option<&Key>,
) -> Result<Session, ServerError> {
    let pubkey = req
        .headers()
        .get(INNERNET_PUBKEY_HEADER)
        .ok_or(ServerError::Unauthorized)?;
    let pubkey = pubkey.to_str().map_err(|_| ServerError::Unauthorized)?;
    let pubkey = Key::from_base64(pubkey).map_err(|_| ServerError::Unauthorized)?;
    if !bool::from(pubkey.as_bytes().ct_eq(context.public_key.as_bytes())) {
        return Err(ServerError::Unauthorized);
    }

    let not_found_is_unauthorized = |e| match e {
        rusqlite::Error::QueryReturnedNoRows => ServerError::Unauthorized,
        e => ServerError::Database(e),
    };
    let peer = {
        let conn = context.db.lock();
        let mut peer = match client_key {
            Some(key) => DatabasePeer::get_from_public_key(&conn, key),
            None => DatabasePeer::get_from_ip(&conn, addr),
        }
        .map_err(not_found_is_unauthorized)?;

        // WireGuard only delivers the peer's traffic from its own IP and its delegations, so
        // anything else means the connection didn't come through the tunnel. Its delegations
        // are routed to whatever is behind the peer, so only its own IP is the peer itself.
        if peer.ip != addr {
            log::warn!("refusing {} connecting from {addr}.", *peer);
            return Err(ServerError::Unauthorized);
        }
        if client_key.is_none() && peer.requires_tls {
            log::warn!("refusing {} connecting without TLS.", *peer);
            return Err(ServerError::TlsRequired);
        }

        if peer.is_disabled {
            return Err(ServerError::Unauthorized);
        }
        if client_key.is_some() && !peer.requires_tls {
            log::info!("{} connected over TLS, and is now required to.", *peer);
            peer.set_requires_tls(&conn)?;
        }
        peer
    };

    Ok(Session { context, peer })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test;
    use anyhow::Result;
    use hyper::StatusCode;
    use std::path::Path;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    #[test]
    fn test_init_wizard() -> Result<(), Error> {
        // This runs init_wizard().
        let server = test::Server::new()?;

        assert!(Path::new(&server.wg_conf_path()).exists());

        Ok(())
    }

    async fn requires_tls(server: &test::Server, id: i64) -> bool {
        DatabasePeer::get(&server.db.lock(), id)
            .unwrap()
            .requires_tls
    }

    #[tokio::test]
    async fn test_tls_latch() -> Result<(), Error> {
        let server = test::Server::new()?;
        let ip = test::DEVELOPER1_PEER_IP;

        // A peer that has never connected over TLS is identified by its IP...
        assert!(!requires_tls(&server, test::DEVELOPER1_PEER_ID).await);
        let res = server.plain_request(ip, "GET", "/v1/user/state").await;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(!requires_tls(&server, test::DEVELOPER1_PEER_ID).await);

        // ...until it does, after which it must always.
        let res = server.request(ip, "GET", "/v1/user/state").await;
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
    async fn test_admins_require_tls_from_creation() -> Result<(), Error> {
        let server = test::Server::new()?;
        assert!(requires_tls(&server, test::ADMIN_PEER_ID).await);
        let res = server
            .plain_request(test::ADMIN_PEER_IP, "GET", "/v1/admin/peers")
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let res = server
            .request(test::ADMIN_PEER_IP, "GET", "/v1/admin/peers")
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn test_tls_key_must_match_peer_and_ip() -> Result<(), Error> {
        let server = test::Server::new()?;
        let admin_key = {
            let admin = DatabasePeer::get(&server.db.lock(), test::ADMIN_PEER_ID)?;
            Key::from_base64(&admin.public_key)?
        };
        let request = || {
            let path = if cfg!(feature = "v6-test") {
                format!("http://[{}]/v1/admin/peers", test::WG_MANAGE_PEER_IP)
            } else {
                format!("http://{}/v1/admin/peers", test::WG_MANAGE_PEER_IP)
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
            .request(test::USER1_PEER_IP, "GET", "/v1/admin/peers")
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn test_delegated_ips_are_not_the_peer() -> Result<(), Error> {
        let server = test::Server::new()?;
        let developer1_key = {
            let conn = server.db.lock();
            let mut peer = DatabasePeer::get(&conn, test::DEVELOPER1_PEER_ID)?;
            peer.add_delegation(&conn, test::DELEGATION.parse()?)?;
            Key::from_base64(&peer.public_key)?
        };
        let request = || {
            server
                .base_request_builder("GET", "/v1/user/state")
                .body(Body::empty())
                .unwrap()
        };

        // Anything behind the peer sends from its delegations, so the peer's key over TLS
        // doesn't make a request from there the peer's...
        let res = server
            .raw_request_as(test::DELEGATED_IP, Some(developer1_key.clone()), request())
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert!(!requires_tls(&server, test::DEVELOPER1_PEER_ID).await);

        // ...nor does the address alone, in plain HTTP.
        let res = server
            .plain_request(test::DELEGATED_IP, "GET", "/v1/user/state")
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // The peer itself is still recognized at its own IP, both ways.
        let res = server
            .plain_request(test::DEVELOPER1_PEER_IP, "GET", "/v1/user/state")
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        let res = server
            .raw_request_as(test::DEVELOPER1_PEER_IP, Some(developer1_key), request())
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        Ok(())
    }

    /// Sends a request on a raw stream and returns the response's status line.
    async fn status_line<S: AsyncRead + AsyncWrite + Unpin>(
        mut stream: S,
        server_key: &str,
    ) -> String {
        let request = format!(
            "GET /v1/user/state HTTP/1.1\r\nHost: innernet\r\n{INNERNET_PUBKEY_HEADER}: \
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
        let id = DatabasePeer::create(&server.db.lock(), contents)?.id;

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
            status_line(plain, &header_key).await,
            "HTTP/1.1 401 Unauthorized"
        );

        // TLS is served on the same port. The peer's key is accepted by the handshake, but
        // not from an IP other than its own, and that doesn't latch it.
        let tls = connect_tls(&peer_key, &server_tls_key.public).await?;
        assert_eq!(
            status_line(tls, &header_key).await,
            "HTTP/1.1 401 Unauthorized"
        );
        assert!(!requires_tls(&server, id).await);

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
            format!("http://[{}]/v1/admin/peers", test::WG_MANAGE_PEER_IP)
        } else {
            format!("http://{}/v1/admin/peers", test::WG_MANAGE_PEER_IP)
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
            format!("http://[{}]/v1/admin/peers", test::WG_MANAGE_PEER_IP)
        } else {
            format!("http://{}/v1/admin/peers", test::WG_MANAGE_PEER_IP)
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
            format!("http://[{}]/v1/admin/peers", test::WG_MANAGE_PEER_IP)
        } else {
            format!("http://{}/v1/admin/peers", test::WG_MANAGE_PEER_IP)
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
