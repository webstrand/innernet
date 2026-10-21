//! The coordinator of a network, as a service of the node that it runs beside: it serves the API
//! and keeps what it assigns the peers in its annex to the node's database. It runs on what it is
//! handed: its key, the database that it shares with its node, a listener that the host has
//! bound, and the hooks through which it tells the node of a change and learns where the node's
//! tunnel observes the peers.

use crate::{api, db::DatabasePeer, ServerError};
use anyhow::Error;
use hyper::{http, server::conn::AddrStream, Body, Request, Response};
use innernet_node::{runtime::StoreChanged, Store};
use innernet_shared::INNERNET_PUBKEY_HEADER;
use parking_lot::{Mutex, RwLock};
use std::{
    collections::{HashMap, VecDeque},
    convert::TryInto,
    net::{IpAddr, SocketAddr, TcpListener},
    sync::Arc,
    time::{Duration, SystemTime},
};
use subtle::ConstantTimeEq;
use tokio::{sync::Notify, task::JoinHandle};
use wireguard_control::Key;

/// The sockets at which the coordinator serves its API, which the host binds.
pub struct Sockets {
    /// The TCP listener of the API, in plain HTTP.
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
    /// Starts the coordinator, whose peer has the public key `public_key`, on `db`, the database
    /// that it shares with its node, in the current Tokio runtime.
    pub fn spawn(public_key: Key, db: Db, sockets: Sockets, hooks: Hooks) -> Result<Self, Error> {
        let context = Context {
            db: db.clone(),
            endpoints: hooks.endpoints,
            public_key,
            changed: hooks.changed.clone(),
            invitations: Arc::default(),
        };
        spawn_invitation_sweeper(db, hooks.changed, context.invitations.clone());
        sockets.api.set_nonblocking(true)?;
        let make_svc = hyper::service::make_service_fn(move |socket: &AddrStream| {
            let remote_addr = socket.remote_addr();
            let context = context.clone();
            async move {
                Ok::<_, http::Error>(hyper::service::service_fn(move |req: Request<Body>| {
                    log::debug!("{} - {} {}", remote_addr, req.method(), req.uri());
                    hyper_service(req, context.clone(), remote_addr)
                }))
            }
        });
        let server = hyper::Server::from_tcp(sockets.api)?.serve(make_svc);
        let task = tokio::spawn(async move { Ok(server.await?) });
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
    /// Tells the coordinator's node that the coordinator changed what the node holds.
    pub changed: StoreChanged,
    /// Tells the sweeper of invitations that one was created or redeemed, so that it sleeps until
    /// the next expiry.
    pub invitations: Arc<Notify>,
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

pub(crate) async fn hyper_service(
    req: Request<Body>,
    context: Context,
    remote_addr: SocketAddr,
) -> Result<Response<Body>, http::Error> {
    // Break the path into components.
    let components: VecDeque<_> = req
        .uri()
        .path()
        .trim_start_matches('/')
        .split('/')
        .map(String::from)
        .collect();

    routes(req, context, remote_addr, components)
        .await
        .or_else(TryInto::try_into)
}

async fn routes(
    req: Request<Body>,
    context: Context,
    remote_addr: SocketAddr,
    mut components: VecDeque<String>,
) -> Result<Response<Body>, ServerError> {
    // Must be "/v1/[something]"
    if components.pop_front().as_deref() != Some("v1") {
        Err(ServerError::NotFound)
    } else {
        let session = get_session(&req, context, remote_addr.ip())?;
        let component = components.pop_front();
        match component.as_deref() {
            Some("user") => api::user::routes(req, components, session).await,
            Some("admin") => api::admin::routes(req, components, session).await,
            _ => Err(ServerError::NotFound),
        }
    }
}

fn get_session(
    req: &Request<Body>,
    context: Context,
    addr: IpAddr,
) -> Result<Session, ServerError> {
    let pubkey = req
        .headers()
        .get(INNERNET_PUBKEY_HEADER)
        .ok_or(ServerError::Unauthorized)?;
    let pubkey = pubkey.to_str().map_err(|_| ServerError::Unauthorized)?;
    let pubkey = Key::from_base64(pubkey).map_err(|_| ServerError::Unauthorized)?;
    if pubkey
        .as_bytes()
        .ct_eq(context.public_key.as_bytes())
        .into()
    {
        let peer = DatabasePeer::get_from_ip(&context.db.lock(), addr).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => ServerError::Unauthorized,
            e => ServerError::Database(e),
        })?;

        if !peer.is_disabled {
            return Ok(Session { context, peer });
        }
    }

    Err(ServerError::Unauthorized)
}
