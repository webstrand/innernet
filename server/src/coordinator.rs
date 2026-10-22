//! The coordinator of a network, as a service of the node that it runs beside: it serves the API,
//! in TLS over QUIC and, for clients that predate TLS, in plain HTTP, and keeps what it assigns the
//! peers in its annex to the node's database. It runs on what it is handed: its key, the database
//! that it shares with its node, its config, sockets that the host has bound, and the hooks through
//! which it tells the node of a change and learns where the node's tunnel observes the peers.

use crate::{api, db::DatabasePeer, quic, util, ServerError};
use anyhow::Error;
use hyper::{http, service::service_fn, Body, Request, Response};
use innernet_node::{runtime::StoreChanged, Store};
use innernet_shared::{media_type::Representation, tls, INNERNET_PUBKEY_HEADER};
use parking_lot::{Mutex, RwLock};
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr, TcpListener, UdpSocket},
    sync::Arc,
    time::{Duration, SystemTime},
};
use subtle::ConstantTimeEq;
use tokio::{net::TcpStream, sync::Notify, task::JoinHandle};
use wireguard_control::Key;

/// What the coordinator serves, as its host configures it.
#[derive(Clone, Debug)]
pub struct CoordinatorConfig {
    /// The address at which the coordinator serves its API: the primary IP of its node.
    pub address: IpAddr,
    /// The UDP port of the TLS API, at `address`.
    pub quic_port: u16,
}

/// The sockets at which the coordinator serves its API, which the host binds.
pub struct Sockets {
    /// The UDP socket of the TLS API, over QUIC.
    pub quic: UdpSocket,
    /// The TCP listener of the legacy API, in plain HTTP, if the coordinator serves it.
    pub legacy: Option<TcpListener>,
}

/// What the coordinator shares with its node.
#[derive(Clone)]
pub struct Hooks {
    /// The signal by which the coordinator tells its node that it changed the store.
    pub changed: StoreChanged,
    /// Where the tunnel of the node observes the peers.
    pub endpoints: Endpoints,
}

pub struct Coordinator {
    task: JoinHandle<Result<(), Error>>,
}

impl Coordinator {
    /// Starts the coordinator with the private key `private_key`, in base64, on `db`, the
    /// database that it shares with its node, in the current Tokio runtime.
    pub fn spawn(
        config: CoordinatorConfig,
        private_key: &str,
        db: Db,
        sockets: Sockets,
        hooks: Hooks,
    ) -> Result<Self, Error> {
        let public_key = Key::from_base64(private_key)?.get_public();
        let context = Context {
            db: db.clone(),
            endpoints: hooks.endpoints,
            public_key,
            internal_address: config.address,
            quic_port: config.quic_port,
            changed: hooks.changed.clone(),
            invitations: Arc::default(),
        };
        spawn_invitation_sweeper(db, hooks.changed, context.invitations.clone());
        let tls_config = tls::server_config(private_key)?;
        let tls_api = quic::serve(quic::endpoint(sockets.quic, tls_config)?, context.clone());
        let legacy = sockets
            .legacy
            .map(|listener| {
                listener.set_nonblocking(true)?;
                Ok::<_, Error>(tokio::net::TcpListener::from_std(listener)?)
            })
            .transpose()?;
        let task = tokio::spawn(async move {
            match legacy {
                Some(listener) => {
                    tokio::try_join!(tls_api, serve_legacy_api(listener, context))?;
                    Ok(())
                },
                None => {
                    log::info!("the legacy API is off, so the server serves no plain HTTP.");
                    tls_api.await
                },
            }
        });
        Ok(Self { task })
    }

    /// Waits until the coordinator stops, which it does only on an error.
    pub async fn join(self) -> Result<(), Error> {
        self.task.await?
    }
}

/// Deletes each invitation once it expires, and tells the node when it did. The sweeper sleeps
/// until the next expiry that the database holds, and looks again when `invitations` signals that
/// an invitation was created or redeemed.
fn spawn_invitation_sweeper(db: Db, changed: StoreChanged, invitations: Arc<Notify>) {
    tokio::task::spawn(async move {
        loop {
            let next = match DatabasePeer::next_invite_expiry(&db.lock()) {
                Ok(next) => next,
                Err(e) => {
                    log::error!("Failed to read when the next invitation expires: {}", e);
                    None
                },
            };
            let expiry = async {
                match next {
                    Some(next) => {
                        let left = next
                            .duration_since(SystemTime::now())
                            .unwrap_or(Duration::ZERO);
                        // An invitation expires once its second has passed.
                        tokio::time::sleep(left + Duration::from_secs(1)).await;
                    },
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                () = expiry => {},
                () = invitations.notified() => continue,
            }
            match DatabasePeer::delete_expired_invites(&db.lock()) {
                Ok(deleted) if deleted > 0 => {
                    log::info!("Deleted {} expired peer invitations.", deleted);
                    changed.notify();
                },
                Err(e) => log::error!("Failed to delete expired peer invitations: {}", e),
                _ => {},
            }
        }
    });
}

/// The database that the coordinator shares with its node.
pub type Db = Arc<Mutex<Store>>;

/// The endpoints at which the tunnel of the coordinator's node observes the peers, by public key.
pub type Endpoints = Arc<RwLock<HashMap<String, SocketAddr>>>;

#[derive(Clone)]
pub struct Context {
    pub db: Db,
    /// The endpoints at which the tunnel of the coordinator's node observes the peers.
    pub endpoints: Endpoints,
    pub public_key: Key,
    /// The address that the server serves its API on, within the delegations of its own peer.
    pub internal_address: IpAddr,
    /// The UDP port of the TLS API, at `internal_address`.
    pub quic_port: u16,
    /// Tells the coordinator's node that the coordinator changed what the node holds.
    pub changed: StoreChanged,
    /// Tells the sweeper of invitations that one was created or redeemed, so that it sleeps until
    /// the next expiry.
    pub invitations: Arc<Notify>,
}

pub struct Session {
    pub context: Context,
    pub peer: DatabasePeer,
    /// Whether the peer authenticated with its key over TLS. Plain-HTTP sessions are those of
    /// clients that predate TLS, and are served the API as those clients know it.
    pub over_tls: bool,
    /// The representation of the responses of a TLS session, as its `Accept` chose it, or `None`
    /// in plain HTTP, which answers in JSON.
    pub representation: Option<Representation>,
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

/// How long a client of the legacy API may take to send the head of a request.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// Serves the legacy API, in plain HTTP, to clients that predate TLS, and to clients upgraded from
/// v2.0.0, which ask it for the QUIC port of the TLS API.
pub(crate) async fn serve_legacy_api(
    listener: tokio::net::TcpListener,
    context: Context,
) -> Result<(), Error> {
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
        let context = context.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_legacy_connection(stream, remote_addr, context).await {
                log::debug!("{remote_addr} - connection failed: {e}");
            }
        });
    }
}

/// Serves one connection of the legacy API, in plain HTTP.
async fn serve_legacy_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    context: Context,
) -> Result<(), Error> {
    let mut http = hyper::server::conn::Http::new();
    http.http1_only(true);
    http.http1_header_read_timeout(HEADER_TIMEOUT);
    let service = service_fn(move |req: Request<Body>| {
        log::debug!("{} - {} {}", remote_addr, req.method(), req.uri());
        hyper_service(req, context.clone(), remote_addr, ConnectionMode::Legacy)
    });
    http.serve_connection(stream, service).await?;
    Ok(())
}

/// Serves a request from `remote_addr`. `client_key` is the key the client authenticated with
/// over TLS, if it connected that way.
pub(crate) async fn hyper_service(
    req: Request<Body>,
    context: Context,
    remote_addr: SocketAddr,
    mode: ConnectionMode,
) -> Result<Response<Body>, http::Error> {
    // Break the path into components.
    let components: VecDeque<_> = req
        .uri()
        .path()
        .trim_start_matches('/')
        .split('/')
        .map(String::from)
        .collect();

    // A client of the TLS API is told of errors in problem details, in the debug view if it chose
    // it, and one in plain HTTP as clients that predate TLS expect.
    let debug_view = util::debug_view(&req);
    match mode {
        ConnectionMode::Legacy => legacy_routes(req, context, remote_addr, components)
            .await
            .or_else(|e| e.try_into()),
        mode => tls_routes(req, context, remote_addr, mode, components)
            .await
            .or_else(|e| e.problem_response(debug_view)),
    }
}

/// How the client of a connection authenticated, which the server decides once per connection,
/// and which the router follows for each of its requests.
#[derive(Clone, Debug)]
pub(crate) enum ConnectionMode {
    /// Plain HTTP, the legacy API of clients that predate TLS, which identifies a peer by its
    /// source address.
    Legacy,
    /// The TLS API, with the key that the client authenticated with.
    Authenticated(Key),
    /// The TLS API, without a client key, which may use only the routes that allow anonymous
    /// connections.
    Anonymous,
}

/// The routes of the TLS API, each of which allows anonymous connections or requires a client
/// key. A route names a resource, such as `/user`, under which the handler finds the rest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    /// `/user/...`, what every peer may do.
    User,
    /// `/admin/...`, what only admins may do.
    Admin,
}

impl Route {
    /// The route of a request for the path `components`, if the server has one.
    fn of(components: &VecDeque<String>) -> Option<Self> {
        match components.front().map(String::as_str) {
            Some("user") => Some(Route::User),
            Some("admin") => Some(Route::Admin),
            _ => None,
        }
    }

    /// Whether a connection without a client key may use the route.
    fn allows_anonymous(self) -> bool {
        match self {
            Route::User | Route::Admin => false,
        }
    }
}

/// Serves a request of the TLS API, of a connection in `mode`. The checks follow one order: the
/// route; then the gate, which refuses a route that requires a client key to a connection without
/// one, and refuses an unknown path to such a connection the same way, so that it can't probe for
/// routes; then the content type and `Accept`, which [`util::negotiate`] checks; then the handler.
/// The API of TLS sessions is versioned by its media type, not by its paths.
async fn tls_routes(
    req: Request<Body>,
    context: Context,
    remote_addr: SocketAddr,
    mode: ConnectionMode,
    mut components: VecDeque<String>,
) -> Result<Response<Body>, ServerError> {
    let route = Route::of(&components);
    let client_key = match mode {
        ConnectionMode::Authenticated(key) => Some(key),
        _ => None,
    };
    if client_key.is_none() && !route.is_some_and(Route::allows_anonymous) {
        return Err(ServerError::ClientKeyRequired);
    }
    let route = route.ok_or(ServerError::NotFound)?;
    let representation = util::negotiate(&req)?;
    components.pop_front();
    let client_key = client_key.ok_or(ServerError::ClientKeyRequired)?;
    let mut session = get_session(&req, context, remote_addr.ip(), Some(&client_key), false)?;
    session.representation = Some(representation);
    match route {
        Route::User => api::user::routes(req, components, session).await,
        Route::Admin => api::admin::routes(req, components, session).await,
    }
}

/// Serves a request of the legacy API, in plain HTTP, under the "/v1/" of v2.0.0. The legacy API
/// has only the user routes: the admin API is served only over TLS, and an admin that predates TLS
/// is an ordinary peer in plain HTTP until its client is upgraded.
async fn legacy_routes(
    req: Request<Body>,
    context: Context,
    remote_addr: SocketAddr,
    mut components: VecDeque<String>,
) -> Result<Response<Body>, ServerError> {
    if components.pop_front().as_deref() != Some("v1")
        || components.front().map(String::as_str) != Some("user")
    {
        return Err(ServerError::NotFound);
    }
    // The capabilities are only information, which a peer that has connected over TLS asks for in
    // plain HTTP to learn the QUIC port of the TLS API. WireGuard authenticates the server's
    // internal address, so the answer can be trusted.
    let capabilities =
        req.method() == hyper::Method::GET && components.iter().eq(["user", "capabilities"].iter());
    let session = get_session(&req, context, remote_addr.ip(), None, capabilities)?;
    components.pop_front();
    api::user::routes(req, components, session).await
}

/// Identifies the peer making a request: by the key it authenticated with over TLS if it did,
/// otherwise by its source IP, which must lie within one of the peer's delegations, and which
/// anything on the peer's machine can send from. Peers that have once connected over TLS are
/// refused the latter from then on, unless `information_only`, for a request that only reads
/// information that the peer may have without TLS.
pub(crate) fn get_session(
    req: &Request<Body>,
    context: Context,
    addr: IpAddr,
    client_key: Option<&Key>,
    information_only: bool,
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
        let store = context.db.lock();
        let mut peer = match client_key {
            Some(key) => DatabasePeer::get_from_public_key(&store, key),
            None => DatabasePeer::get_by_address(&store, addr),
        }
        .map_err(not_found_is_unauthorized)?;

        // WireGuard only delivers the peer's traffic from the addresses of its delegations, so
        // anything else means the connection didn't come through the tunnel.
        if !peer.holds(addr) {
            log::warn!("refusing {} connecting from {addr}.", *peer);
            return Err(ServerError::Unauthorized);
        }
        if client_key.is_none() && peer.requires_tls && !information_only {
            log::warn!("refusing {} connecting without TLS.", *peer);
            return Err(ServerError::TlsRequired);
        }

        if peer.is_disabled {
            return Err(ServerError::Unauthorized);
        }
        if client_key.is_some() && !peer.requires_tls {
            log::info!("{} connected over TLS, and is now required to.", *peer);
            peer.set_requires_tls(&store)?;
        }
        peer
    };

    Ok(Session {
        context,
        peer,
        over_tls: client_key.is_some(),
        representation: None,
    })
}
