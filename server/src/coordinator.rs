//! The coordinator of a network, as a service of the node that it runs beside: it serves the API,
//! in TLS and, for clients that predate TLS, in plain HTTP, and keeps what it assigns the peers in
//! its annex to the node's database. It runs on what it is handed: its key, the database that it
//! shares with its node, a listener that the host has bound, and the hooks through which it tells
//! the node of a change and learns where the node's tunnel observes the peers.

use crate::{api, db::DatabasePeer, util, ServerError};
use anyhow::{anyhow, Error};
use hyper::{http, service::service_fn, Body, Request, Response};
use innernet_node::{runtime::StoreChanged, Store};
use innernet_shared::{media_type::Representation, tls, INNERNET_PUBKEY_HEADER};
use parking_lot::{Mutex, RwLock};
use std::{
    collections::{HashMap, VecDeque},
    convert::TryInto,
    net::{IpAddr, SocketAddr, TcpListener},
    sync::Arc,
    time::{Duration, SystemTime},
};
use subtle::ConstantTimeEq;
use tokio::{net::TcpStream, sync::Notify, task::JoinHandle, time::timeout};
use tokio_rustls::{rustls, TlsAcceptor};
use wireguard_control::Key;

/// What the coordinator serves, as its host configures it.
#[derive(Clone, Debug)]
pub struct CoordinatorConfig {
    /// The address at which the coordinator serves its API: the primary IP of its node.
    pub address: IpAddr,
}

/// The sockets at which the coordinator serves its API, which the host binds.
pub struct Sockets {
    /// The TCP listener of the API, in TLS and in plain HTTP.
    pub api: TcpListener,
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
            changed: hooks.changed.clone(),
            invitations: Arc::default(),
        };
        spawn_invitation_sweeper(db, hooks.changed, context.invitations.clone());
        let tls_config = tls::server_config(private_key)?;
        sockets.api.set_nonblocking(true)?;
        let listener = tokio::net::TcpListener::from_std(sockets.api)?;
        let task = tokio::spawn(serve_api(listener, context, tls_config));
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

/// How long a client may take to send its first byte, and then to complete a TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Serves the API in TLS and, for clients that predate it, in plain HTTP on the same port.
pub(crate) async fn serve_api(
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

/// Serves one connection, in TLS if it starts with a TLS handshake record, which no HTTP request
/// does, and in plain HTTP otherwise.
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
        let component = components.pop_front();
        // The admin API exists only over TLS: in plain HTTP its paths are not found, before the
        // peer is identified. An admin that predates TLS is an ordinary peer in plain HTTP until
        // its client is upgraded.
        if component.as_deref() == Some("admin") && client_key.is_none() {
            return Err(ServerError::NotFound);
        }
        let mut session = get_session(&req, context, remote_addr.ip(), client_key.as_ref())?;
        if session.over_tls {
            session.representation = Some(util::negotiate(&req)?);
        }
        match component.as_deref() {
            Some("user") => api::user::routes(req, components, session).await,
            Some("admin") => api::admin::routes(req, components, session).await,
            _ => Err(ServerError::NotFound),
        }
    }
}

/// Identifies the peer making a request: by the key it authenticated with over TLS if it did,
/// otherwise by its source IP, which must lie within one of the peer's delegations, and which
/// anything on the peer's machine can send from. Peers that have once connected over TLS are
/// refused the latter from then on.
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
        if client_key.is_none() && peer.requires_tls {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test;
    use hyper::StatusCode;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use wireguard_control::KeyPair;

    fn requires_tls(server: &test::Server, id: i64) -> bool {
        test::peer(&server.db.lock(), id).requires_tls
    }

    fn server_key(server: &test::Server) -> String {
        server.context().public_key.to_base64()
    }

    #[tokio::test]
    async fn test_tls_latch() -> Result<(), Error> {
        let server = test::Server::new()?;
        server.predate_tls(test::DEVELOPER1_PEER_ID);
        server.predate_tls(test::DEVELOPER2_PEER_ID);
        let ip = test::DEVELOPER1_PEER_IP;

        // A peer from before TLS that has never connected over TLS is identified by its IP...
        assert!(!requires_tls(&server, test::DEVELOPER1_PEER_ID));
        let res = server.plain_request(ip, "GET", "/v1/user/state").await;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(!requires_tls(&server, test::DEVELOPER1_PEER_ID));

        // ...until it does, after which it must always.
        let res = server.request(ip, "GET", "/v1/user/state").await;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(requires_tls(&server, test::DEVELOPER1_PEER_ID));

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
    async fn test_peers_require_tls_from_creation() -> Result<(), Error> {
        let server = test::Server::new()?;
        for (id, ip) in [
            (test::ADMIN_PEER_ID, test::ADMIN_PEER_IP),
            (test::DEVELOPER1_PEER_ID, test::DEVELOPER1_PEER_IP),
        ] {
            assert!(requires_tls(&server, id));
            let res = server.plain_request(ip, "GET", "/v1/user/state").await;
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
            let res = server.request(ip, "GET", "/v1/user/state").await;
            assert_eq!(res.status(), StatusCode::OK);
        }
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
        let path = if cfg!(feature = "v6-test") {
            format!("http://[{}]/v1/user/state", test::WG_MANAGE_PEER_IP)
        } else {
            format!("http://{}/v1/user/state", test::WG_MANAGE_PEER_IP)
        };
        let request = || {
            Request::builder()
                .uri(&path)
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
            status_line(plain, &header_key).await,
            "HTTP/1.1 401 Unauthorized"
        );

        // TLS is served on the same port. The peer's key is accepted by the handshake, but not
        // from an IP other than its own, and that doesn't latch it.
        let tls = connect_tls(&peer_key, &server_tls_key.public).await?;
        assert_eq!(
            status_line(tls, &header_key).await,
            "HTTP/1.1 401 Unauthorized"
        );
        assert!(!peer.reload(&server.db.lock())?.requires_tls);

        // A client pinning another server key refuses the handshake.
        let wrong = KeyPair::generate().public;
        assert!(connect_tls(&peer_key, &wrong).await.is_err());
        Ok(())
    }
}
