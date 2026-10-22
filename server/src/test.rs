#![allow(dead_code)]
use crate::{
    db::{DatabaseCidr, DatabasePeer},
    initialize::{init_wizard, InitializeOpts},
    Context, Db, Endpoints, ServerConfig,
};
use anyhow::anyhow;
use hyper::{header::HeaderValue, http, Body, Request, Response};
use innernet_node::Store;
use innernet_shared::{
    cbor,
    problem::{self, Problem, ProblemType},
    Error, LegacyPeerContents, PeerContents, Prefix,
};
use parking_lot::{Mutex, RwLock};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};
use tempfile::TempDir;
use wireguard_control::{InterfaceName, Key, KeyPair};

#[cfg(not(feature = "v6-test"))]
mod v4 {
    pub const ROOT_CIDR: &str = "10.80.0.0/15";
    pub const SERVER_CIDR: &str = "10.80.0.1/32";
    pub const ADMIN_CIDR: &str = "10.80.1.0/24";
    pub const DEVELOPER_CIDR: &str = "10.80.64.0/24";
    pub const USER_CIDR: &str = "10.80.128.0/17";
    pub const EXPERIMENTAL_CIDR: &str = "10.81.0.0/16";
    pub const EXPERIMENTAL_SUBCIDR: &str = "10.81.0.0/17";

    pub const ADMIN_PEER_IP: &str = "10.80.1.1";
    pub const WG_MANAGE_PEER_IP: &str = ADMIN_PEER_IP;
    pub const DEVELOPER1_PEER_IP: &str = "10.80.64.2";
    pub const DEVELOPER1_PEER_ENDPOINT: &str = "169.10.26.8:14720";
    pub const DEVELOPER2_PEER_IP: &str = "10.80.64.3";
    pub const DEVELOPER2_PEER_ENDPOINT: &str = "169.55.140.9:5833";
    pub const USER1_PEER_IP: &str = "10.80.128.2";
    pub const USER2_PEER_IP: &str = "10.80.129.2";
    pub const EXPERIMENT_SUBCIDR_PEER_IP: &str = "10.81.0.1";
}
#[cfg(not(feature = "v6-test"))]
pub use v4::*;

#[cfg(feature = "v6-test")]
mod v6 {
    pub const ROOT_CIDR: &str = "fd00:1337::/64";
    pub const SERVER_CIDR: &str = "fd00:1337::1/128";
    pub const ADMIN_CIDR: &str = "fd00:1337::1:0:0:0/80";
    pub const DEVELOPER_CIDR: &str = "fd00:1337::2:0:0:0/80";
    pub const USER_CIDR: &str = "fd00:1337::3:0:0:0/80";
    pub const EXPERIMENTAL_CIDR: &str = "fd00:1337::4:0:0:0/80";
    pub const EXPERIMENTAL_SUBCIDR: &str = "fd00:1337::4:0:0:0/81";

    pub const ADMIN_PEER_IP: &str = "fd00:1337::1:0:0:1";
    pub const WG_MANAGE_PEER_IP: &str = ADMIN_PEER_IP;
    pub const DEVELOPER1_PEER_IP: &str = "fd00:1337::2:0:0:1";
    pub const DEVELOPER1_PEER_ENDPOINT: &str = "[1001:db8::1]:14720";
    pub const DEVELOPER2_PEER_IP: &str = "fd00:1337::2:0:0:2";
    pub const DEVELOPER2_PEER_ENDPOINT: &str = "[2001:db8::1]:5833";
    pub const USER1_PEER_IP: &str = "fd00:1337::3:0:0:1";
    pub const USER2_PEER_IP: &str = "fd00:1337::3:0:0:2";
    pub const EXPERIMENT_SUBCIDR_PEER_IP: &str = "fd00:1337::4:0:0:1";
}
#[cfg(feature = "v6-test")]
pub use v6::*;

// The IDs by which the API of plain-HTTP sessions names the CIDRs, their positions in the order
// of their prefixes, as [`DatabaseCidr::id_of`] numbers them. The database stores no such ID.
pub const ROOT_CIDR_ID: i64 = 1;
pub const INFRA_CIDR_ID: i64 = 2;
pub const ADMIN_CIDR_ID: i64 = 3;
pub const DEVELOPER_CIDR_ID: i64 = 4;
pub const USER_CIDR_ID: i64 = 5;

/// The CIDRs of the test database, by ID.
const CIDR_IDS: [(i64, &str); 5] = [
    (ROOT_CIDR_ID, ROOT_CIDR),
    (INFRA_CIDR_ID, SERVER_CIDR),
    (ADMIN_CIDR_ID, ADMIN_CIDR),
    (DEVELOPER_CIDR_ID, DEVELOPER_CIDR),
    (USER_CIDR_ID, USER_CIDR),
];

// The IDs by which the API of plain-HTTP sessions names the peers, their positions in the order of
// their IPs, as [`DatabasePeer::plain_http_ids`] numbers them. The database stores no such ID:
// [`peer`] finds a peer by the IP of its ID.
pub const SERVER_PEER_ID: i64 = 1;
pub const ADMIN_PEER_ID: i64 = 2;
pub const DEVELOPER1_PEER_ID: i64 = 3;
pub const DEVELOPER2_PEER_ID: i64 = 4;
pub const USER1_PEER_ID: i64 = 5;
pub const USER2_PEER_ID: i64 = 6;

/// The IDs of the peers of the test database.
const PEER_IDS: [i64; 6] = [
    SERVER_PEER_ID,
    ADMIN_PEER_ID,
    DEVELOPER1_PEER_ID,
    DEVELOPER2_PEER_ID,
    USER1_PEER_ID,
    USER2_PEER_ID,
];

/// The peer of the test database with the ID `id`, one of the `*_PEER_ID`s, found by its IP.
pub fn peer(conn: &rusqlite::Connection, id: i64) -> DatabasePeer {
    let ip = match id {
        SERVER_PEER_ID => SERVER_CIDR.split_once('/').unwrap().0,
        ADMIN_PEER_ID => ADMIN_PEER_IP,
        DEVELOPER1_PEER_ID => DEVELOPER1_PEER_IP,
        DEVELOPER2_PEER_ID => DEVELOPER2_PEER_IP,
        USER1_PEER_ID => USER1_PEER_IP,
        USER2_PEER_ID => USER2_PEER_IP,
        _ => panic!("the test database has no peer with the ID {id}"),
    };
    DatabasePeer::get_by_address(conn, ip.parse().unwrap()).unwrap()
}

pub struct Server {
    pub db: Db,
    endpoints: Endpoints,
    interface: InterfaceName,
    conf: ServerConfig,
    public_key: Key,
    internal_address: IpAddr,
    // The directory will be removed during destruction.
    _test_dir: TempDir,
}

impl Server {
    pub fn new() -> Result<Self, Error> {
        let test_dir = tempfile::tempdir()?;
        let test_dir_path = test_dir.path();

        // Run the init wizard to initialize the database and create basic
        // cidrs and peers.
        let interface = "test".to_string();
        let conf = ServerConfig {
            config_dir: test_dir_path.to_path_buf(),
            data_dir: test_dir_path.to_path_buf(),
        };

        let opts = InitializeOpts {
            network_name: Some(interface.parse()?),
            network_cidr: Some(ROOT_CIDR.parse()?),
            external_endpoint: Some("155.155.155.155:54321".parse().unwrap()),
            listen_port: Some(54321),
            auto_external_endpoint: false,
        };
        init_wizard(&conf, opts).map_err(|_| anyhow!("init_wizard failed"))?;

        let interface = interface.parse().unwrap();
        // Add developer CIDR and user CIDR and some peers for testing.
        let config = crate::ConfigFile::from_file(conf.config_path(&interface))?;
        let public_key = Key::from_base64(&config.private_key)?.get_public();
        let db = crate::db::open(
            &conf.database_path(&interface),
            config.network(),
            &public_key,
        )?;
        create_cidr(&db, "admin", ADMIN_CIDR)?;
        DatabasePeer::create(&db, admin_peer_contents("admin", ADMIN_PEER_IP)?)?;
        create_cidr(&db, "developer", DEVELOPER_CIDR)?;

        let developer_1 = developer_peer_contents("developer1", DEVELOPER1_PEER_IP)?;
        let developer_1_public_key = developer_1.public_key.clone();
        DatabasePeer::create(&db, developer_1)?;

        let developer_2 = developer_peer_contents("developer2", DEVELOPER2_PEER_IP)?;
        let developer_2_public_key = developer_2.public_key.clone();
        DatabasePeer::create(&db, developer_2)?;
        create_cidr(&db, "user", USER_CIDR)?;
        DatabasePeer::create(&db, user_peer_contents("user1", USER1_PEER_IP)?)?;
        DatabasePeer::create(&db, user_peer_contents("user2", USER2_PEER_IP)?)?;
        let ids = DatabasePeer::plain_http_ids(&db)?;
        for id in PEER_IDS {
            assert_eq!(ids[&peer(&db, id).public_key], id);
        }
        let cidrs = DatabaseCidr::list(&db)?;
        for (id, prefix) in CIDR_IDS {
            let cidr = DatabaseCidr::get(&db, &prefix.parse()?)?;
            assert_eq!(cidr.legacy(&cidrs).id, id);
        }

        let db = Arc::new(Mutex::new(db));

        let endpoints = [
            (
                developer_1_public_key,
                DEVELOPER1_PEER_ENDPOINT.parse().unwrap(),
            ),
            (
                developer_2_public_key,
                DEVELOPER2_PEER_ENDPOINT.parse().unwrap(),
            ),
        ];
        let endpoints = Arc::new(RwLock::new(endpoints.into()));

        Ok(Self {
            conf,
            db,
            endpoints,
            interface,
            public_key,
            internal_address: config.address,
            _test_dir: test_dir,
        })
    }

    /// Makes the peer with the ID `id` one that the server created before it spoke TLS, which
    /// may still use plain HTTP until it first connects over TLS.
    pub fn predate_tls(&self, id: i64) {
        let key = peer(&self.db.lock(), id).inner.public_key;
        self.predate_tls_key(&key);
    }

    /// Makes the peer with the public key `key` one that the server created before it spoke TLS.
    pub fn predate_tls_key(&self, key: &str) {
        let key = Key::from_base64(key).unwrap();
        self.db
            .lock()
            .execute("UPDATE peers SET tls = 0 WHERE public_key = ?1", [key.0])
            .unwrap();
    }

    /// Delegates `prefix` to the peer with the ID `id`, beside its delegations.
    pub fn delegate(&self, id: i64, prefix: &str) {
        let store = self.db.lock();
        let mut peer = peer(&store, id);
        let mut delegations = peer.delegations.clone();
        delegations.push(prefix.parse().unwrap());
        peer.set_delegations(&store, delegations, &self.public_key, self.internal_address)
            .unwrap();
    }

    pub fn db(&self) -> Db {
        self.db.clone()
    }

    pub fn context(&self) -> Context {
        Context {
            db: self.db.clone(),
            endpoints: self.endpoints.clone(),
            public_key: self.public_key.clone(),
            internal_address: self.internal_address,
            changed: Default::default(),
            invitations: Default::default(),
        }
    }

    pub fn wg_conf_path(&self) -> PathBuf {
        self.conf.config_path(&self.interface)
    }

    /// Sends a request as a client connecting over TLS would, authenticated by the key of the
    /// peer at `ip_str`, or as `plain_request` does if there is no peer there.
    pub async fn raw_request(&self, ip_str: &str, req: Request<Body>) -> Response<Body> {
        let ip = ip_str.parse().unwrap();
        let client_key = DatabasePeer::get_by_address(&self.db.lock(), ip)
            .ok()
            .map(|peer| Key::from_base64(&peer.public_key).unwrap());
        self.raw_request_as(ip_str, client_key, req).await
    }

    /// Sends a request as a client connecting in plain HTTP would, identified by its IP.
    pub async fn plain_request(&self, ip_str: &str, verb: &str, path: &str) -> Response<Body> {
        let req = self
            .base_request_builder(verb, path)
            .body(Body::empty())
            .unwrap();
        self.raw_request_as(ip_str, None, req).await
    }

    /// Sends a request from `ip_str`, over TLS authenticated by `client_key` if there is one, and
    /// in plain HTTP otherwise.
    pub async fn raw_request_as(
        &self,
        ip_str: &str,
        client_key: Option<Key>,
        req: Request<Body>,
    ) -> Response<Body> {
        let port = 54321u16;
        crate::hyper_service(
            req,
            self.context(),
            SocketAddr::new(ip_str.parse().unwrap(), port),
            client_key,
        )
        .await
        .unwrap()
    }

    fn base_request_builder(&self, verb: &str, path: &str) -> http::request::Builder {
        let path = if cfg!(feature = "v6-test") {
            format!("http://[{WG_MANAGE_PEER_IP}]{path}")
        } else {
            format!("http://{WG_MANAGE_PEER_IP}{path}")
        };
        Request::builder()
            .uri(path)
            .method(verb)
            .header(
                innernet_shared::INNERNET_PUBKEY_HEADER,
                HeaderValue::from_str(&self.public_key.to_base64()).unwrap(),
            )
            .header(hyper::header::ACCEPT, innernet_shared::media_type::accept())
    }

    /// Sends a request without a body and without a content type, as [`Self::raw_request`] does.
    /// A change names the newest version of the API in `Accept`, as every request does.
    pub async fn request(&self, ip_str: &str, verb: &str, path: &str) -> Response<Body> {
        let req = self
            .base_request_builder(verb, path)
            .body(Body::empty())
            .unwrap();
        self.raw_request(ip_str, req).await
    }

    /// A request with the body `body`, of the content type `content_type`.
    pub fn body_request(
        &self,
        verb: &str,
        path: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> Request<Body> {
        self.base_request_builder(verb, path)
            .header("Content-Type", content_type)
            .header("Content-Length", body.len().to_string())
            .body(Body::from(body))
            .unwrap()
    }

    /// Sends `form` in CBOR, in the newest version of the API, as a client connecting over TLS
    /// does, as [`Self::raw_request`] does.
    pub async fn form_request<F: Serialize>(
        &self,
        ip_str: &str,
        verb: &str,
        path: &str,
        form: F,
    ) -> Response<Body> {
        let body = cbor::to_vec(&form).unwrap();
        let req = self.body_request(verb, path, &content_type(), body);
        self.raw_request(ip_str, req).await
    }

    /// Sends `form` in JSON, as a client connecting in plain HTTP does, identified by its IP.
    pub async fn plain_form_request<F: Serialize>(
        &self,
        ip_str: &str,
        verb: &str,
        path: &str,
        form: F,
    ) -> Response<Body> {
        let body = serde_json::to_vec(&form).unwrap();
        let req = self.body_request(verb, path, "application/json", body);
        self.raw_request_as(ip_str, None, req).await
    }
}

/// The media type of the newest version of the API, which the bodies of requests and responses of
/// TLS sessions state in tests.
pub fn content_type() -> String {
    innernet_shared::media_type::content_type(innernet_shared::media_type::VERSION)
}

/// The body of `res`, a response to a TLS session, decoded from CBOR, which its content type must
/// state, in the newest version of the API.
pub async fn cbor_body<T: DeserializeOwned>(res: Response<Body>) -> Result<T, Error> {
    assert_eq!(res.headers().get("Content-Type").unwrap(), &content_type());
    let body = hyper::body::to_bytes(res.into_body()).await?;
    Ok(cbor::from_slice(&body)?)
}

/// The problem detail of `res`, the refusal of a request of a TLS session, which must be of the
/// type `problem_type`, with its status.
pub async fn problem(res: Response<Body>, problem_type: &ProblemType) -> Result<Problem, Error> {
    assert_eq!(
        res.headers().get("Content-Type").unwrap(),
        problem::CONTENT_TYPE
    );
    assert_eq!(res.status().as_u16(), problem_type.status);
    let body = hyper::body::to_bytes(res.into_body()).await?;
    let problem: Problem = cbor::from_slice(&body)?;
    assert!(problem.is(problem_type), "{problem:?}");
    assert_eq!(problem.status, Some(problem_type.status));
    Ok(problem)
}

/// Checks that `res`, the refusal of a request of a TLS session, is a problem of the type
/// `about:blank` with the status `status`, and nothing else.
pub async fn blank_problem(res: Response<Body>, status: http::StatusCode) -> Result<(), Error> {
    assert_eq!(res.status(), status);
    assert_eq!(
        res.headers().get("Content-Type").unwrap(),
        problem::CONTENT_TYPE
    );
    let body = hyper::body::to_bytes(res.into_body()).await?;
    assert_eq!(
        cbor::from_slice::<Problem>(&body)?,
        Problem::about_blank(status.as_u16(), status.canonical_reason())
    );
    Ok(())
}

/// The detail of the problem of `res`, as [`problem`] reads it.
pub async fn problem_detail(
    res: Response<Body>,
    problem_type: &ProblemType,
) -> Result<String, Error> {
    Ok(problem(res, problem_type).await?.detail.unwrap())
}

/// The body of `res`, a response to a plain-HTTP session, decoded from JSON, which its content type
/// must state.
pub async fn json_body<T: DeserializeOwned>(res: Response<Body>) -> Result<T, Error> {
    assert_eq!(
        res.headers().get("Content-Type").unwrap(),
        "application/json"
    );
    let body = hyper::body::to_bytes(res.into_body()).await?;
    Ok(serde_json::from_slice(&body)?)
}

/// The ID by which the API of plain-HTTP sessions names the CIDR `cidr`.
pub fn cidr_id(store: &Store, cidr: &DatabaseCidr) -> i64 {
    cidr.legacy(&DatabaseCidr::list(store).unwrap()).id
}

/// Creates the CIDR `cidr_str` named `name`, which is to be a child of the root CIDR.
pub fn create_cidr(db: &Store, name: &str, cidr_str: &str) -> Result<DatabaseCidr, Error> {
    let cidr = DatabaseCidr::create(db, name.to_string(), cidr_str.parse()?)?;
    let cidrs = DatabaseCidr::list(db)?;
    assert_eq!(cidr.legacy(&cidrs).parent, Some(ROOT_CIDR_ID));
    Ok(cidr)
}

//
// Below are helper functions for writing tests.
//

/// A peer at `ip_str`, whose CIDR is the one that holds it.
pub fn peer_contents(name: &str, ip_str: &str, is_admin: bool) -> Result<PeerContents, Error> {
    let public_key = KeyPair::generate().public;

    Ok(PeerContents {
        name: Some(name.parse().map_err(|e: &str| anyhow!(e))?),
        delegations: vec![Prefix::host(ip_str.parse()?)],
        public_key: public_key.to_base64(),
        is_admin,
        endpoint: None,
        persistent_keepalive_interval: None,
        is_disabled: false,
        is_redeemed: true,
        invite_expires: None,
        candidates: vec![],
    })
}

/// `contents` as a client that predates TLS sends it in plain HTTP, with the ID of the CIDR of the
/// test server that holds its address, or 0 if none does.
pub fn legacy(contents: &PeerContents) -> LegacyPeerContents {
    // The CIDRs of the test server, children before their parent.
    let cidrs = [
        (SERVER_CIDR, INFRA_CIDR_ID),
        (ADMIN_CIDR, ADMIN_CIDR_ID),
        (DEVELOPER_CIDR, DEVELOPER_CIDR_ID),
        (USER_CIDR, USER_CIDR_ID),
        (ROOT_CIDR, ROOT_CIDR_ID),
    ];
    let ip = contents.hosts_fallback().unwrap();
    let cidr_id = cidrs
        .iter()
        .find(|(cidr, _)| cidr.parse::<Prefix>().unwrap().contains_addr(&ip))
        .map_or(0, |(_, id)| *id);
    LegacyPeerContents::from_peer(contents, cidr_id).unwrap()
}

pub fn admin_peer_contents(name: &str, ip_str: &str) -> Result<PeerContents, Error> {
    peer_contents(name, ip_str, true)
}

pub fn infra_peer_contents(name: &str, ip_str: &str) -> Result<PeerContents, Error> {
    peer_contents(name, ip_str, false)
}

pub fn developer_peer_contents(name: &str, ip_str: &str) -> Result<PeerContents, Error> {
    peer_contents(name, ip_str, false)
}

pub fn user_peer_contents(name: &str, ip_str: &str) -> Result<PeerContents, Error> {
    peer_contents(name, ip_str, false)
}
