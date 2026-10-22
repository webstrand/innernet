use crate::data_store::DataStore;
use hyper::{client::HttpConnector, header, Body, Client, Method, Request, Response, StatusCode};
use innernet_shared::{
    interface_config::{InterfaceConfig, ServerInfo},
    tls, Cidr, CidrContents, LegacyPeer, LegacyPeerContents, LegacyState, PeerContents, PeerUpdate,
    State, TaggedPeer, INNERNET_PUBKEY_HEADER,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{cell::Cell, io, path::Path, time::Duration};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_rustls::{rustls, TlsConnector};
use wireguard_control::InterfaceName;

/// How long a request may take. Some platforms, such as OpenBSD, can take longer to complete the
/// first WireGuard handshake, so a lower timeout could fail a request that would succeed.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Records something that the client learned about the server in the data store.
type Recorder<'a> = Box<dyn Fn() -> Result<(), anyhow::Error> + 'a>;

/// A REST client that can be used to communicate with an innernet REST server.
///
/// Requests are made over TLS, authenticated with the interface's WireGuard key. A server that
/// answers the TLS handshake in plain HTTP, as servers that predate TLS do, is sent the request in
/// plain HTTP instead, unless the server is known to speak TLS. The server becomes known to speak
/// TLS when it first answers over TLS, and from then on the client refuses plain HTTP.
///
/// We recommend to use the high level API (like [`Self::create_peer()`]) when possible and fall
/// back on the low level [`Self::http()`] and [`Self::http_form()`] otherwise.
pub struct RestClient<'a> {
    plain_client: Client<HttpConnector>,
    tls_connector: TlsConnector,
    server: &'a ServerInfo,
    /// Whether the server is known to speak TLS, in which case the client never falls back to
    /// plain HTTP.
    speaks_tls: Cell<bool>,
    /// Whether the server answered a TLS handshake in plain HTTP, after which the client makes its
    /// requests in plain HTTP.
    predates_tls: Cell<bool>,
    /// Records for good that the server speaks TLS, when it first answers over TLS.
    latch: Option<Recorder<'a>>,
}

impl<'a> RestClient<'a> {
    /// Create a [`Self`] to communicate with the innernet server of an interface, as the
    /// interface's peer. `speaks_tls` is whether the server is known to speak TLS. Nothing
    /// records it if the server answers over TLS; [`Self::speaks_tls`] tells whether it did.
    pub fn new(config: &'a InterfaceConfig, speaks_tls: bool) -> Result<Self, RestError> {
        let tls_config =
            tls::client_config(&config.interface.private_key, &config.server.public_key)
                .map_err(RestError::TlsConfig)?;
        Ok(Self {
            plain_client: Client::new(),
            tls_connector: TlsConnector::from(tls_config),
            server: &config.server,
            speaks_tls: Cell::new(speaks_tls),
            predates_tls: Cell::new(false),
            latch: None,
        })
    }

    /// Create a [`Self`] to communicate with the innernet server of `interface`, whose data store
    /// records whether the server is known to speak TLS, and records it when the server first
    /// answers over TLS.
    pub fn for_interface(
        config: &'a InterfaceConfig,
        data_dir: &'a Path,
        interface: &'a InterfaceName,
    ) -> Result<Self, RestError> {
        let speaks_tls = DataStore::open(data_dir, interface, config)
            .and_then(|store| store.speaks_tls(&config.server.public_key))
            .map_err(RestError::DataStore)?;
        Ok(Self {
            latch: Some(Box::new(move || {
                DataStore::open(data_dir, interface, config)?.latch_tls(&config.server.public_key)
            })),
            ..Self::new(config, speaks_tls)?
        })
    }

    /// Whether the server is known to speak TLS, either from the start or because it has
    /// answered this client over TLS.
    pub fn speaks_tls(&self) -> bool {
        self.speaks_tls.get()
    }

    pub async fn create_cidr(&self, cidr_contents: &CidrContents) -> Result<Cidr, RestError> {
        self.http_form("POST", "/admin/cidrs", cidr_contents).await
    }

    pub async fn get_cidrs(&self) -> Result<Vec<Cidr>, RestError> {
        self.http("GET", "/admin/cidrs").await
    }

    /// Creates a peer, and returns it as the server created it. A server in plain HTTP is sent the
    /// peer as clients that predate TLS know it, and returns the peer with its ID, which is left
    /// out. A peer without a name, which such clients can't represent, is refused as
    /// [`RestError::NamelessUnsupported`] without a request.
    pub async fn create_peer(
        &self,
        peer_contents: &PeerContents,
    ) -> Result<PeerContents, RestError> {
        match self.admin_api().await? {
            AdminApi::ByKey => self.http_form("POST", "/admin/peers", peer_contents).await,
            AdminApi::Legacy => {
                let legacy = LegacyPeerContents::from_peer(peer_contents)
                    .ok_or(RestError::NamelessUnsupported)?;
                let peer: LegacyPeer = self.http_form("POST", "/admin/peers", legacy).await?;
                Ok(peer.contents.into())
            },
        }
    }

    /// The state of the network as this peer sees it. A server in plain HTTP sends the peers with
    /// their IDs, which are left out.
    pub async fn get_state(&self) -> Result<State, RestError> {
        let (transport, body) = self.request_raw::<()>("GET", "/user/state", None).await?;
        match transport {
            Transport::Tls => decode(&body),
            Transport::Plain => decode::<LegacyState>(&body).map(State::from),
        }
    }

    /// Lists every peer of the network. A server in plain HTTP lists the peers with their IDs,
    /// which are left out.
    pub async fn get_peers(&self) -> Result<Vec<PeerContents>, RestError> {
        let (transport, body) = self.request_raw::<()>("GET", "/admin/peers", None).await?;
        match transport {
            Transport::Tls => decode(&body),
            Transport::Plain => decode::<Vec<LegacyPeer>>(&body)
                .map(|peers| peers.into_iter().map(|peer| peer.contents.into()).collect()),
        }
    }

    /// Lists every peer of the network as a server in plain HTTP lists them, with their IDs.
    pub async fn get_legacy_peers(&self) -> Result<Vec<LegacyPeer>, RestError> {
        self.http("GET", "/admin/peers").await
    }

    /// The admin API that the server offers this client. Unless an earlier request has settled
    /// whether the client speaks TLS or plain HTTP to the server, a request to
    /// `/user/capabilities` settles it.
    pub async fn admin_api(&self) -> Result<AdminApi, RestError> {
        if !self.speaks_tls.get() && !self.predates_tls.get() {
            match self
                .http::<serde::de::IgnoredAny>("GET", "/user/capabilities")
                .await
            {
                Ok(_) | Err(RestError::Status(_) | RestError::Refused { .. }) => {},
                Err(e) => return Err(e),
            }
        }
        Ok(if self.predates_tls.get() {
            AdminApi::Legacy
        } else {
            AdminApi::ByKey
        })
    }

    /// Reads the peer `listed` and its tag in the API of TLS sessions, as long as the peer is
    /// still as it was listed, but for its endpoint and candidates, which the peer reports on its
    /// own. A peer that has changed since it was listed is refused as
    /// [`RestError::PeerChanged`]. A peer that the server does not find by its key, since it has
    /// been deleted or its key has changed, as a redeemed invitation's does, is refused as
    /// [`RestError::NoSuchPeer`].
    pub async fn get_tagged_peer(&self, listed: &PeerContents) -> Result<TaggedPeer, RestError> {
        let path = format!("/admin/peers/{}", listed.api_path_segment());
        let tagged: TaggedPeer = self
            .http("GET", &path)
            .await
            .map_err(RestError::peer_refusal)?;
        if !same_but_endpoints(&tagged.peer, listed) {
            return Err(RestError::PeerChanged);
        }
        Ok(tagged)
    }

    /// The peer `listed` as a server in plain HTTP lists it, with the ID by which it names the
    /// peer, as long as the peer is still as it was listed, but for its endpoint and candidates.
    /// The client keeps no IDs, so it lists the peers again, and takes the peer with the public
    /// key of `listed`. A peer that has changed since it was listed, or is gone, is refused as
    /// [`RestError::PeerChanged`].
    async fn get_legacy_peer(&self, listed: &PeerContents) -> Result<LegacyPeer, RestError> {
        self.get_legacy_peers()
            .await?
            .into_iter()
            .find(|peer| peer.public_key == listed.public_key)
            .filter(|peer| same_but_endpoints(&peer.contents.clone().into(), listed))
            .ok_or(RestError::PeerChanged)
    }

    /// Applies an admin's changes to the peer `listed`, as it was listed: its name, its admin
    /// role and whether it is disabled are set to those of `contents`. A peer that has changed
    /// since it was listed is refused as [`RestError::PeerChanged`]: in the API of TLS sessions,
    /// the server refuses it, and with a server in plain HTTP, which can't, the client refuses
    /// it before the change, as far as it can tell. In the API of TLS sessions, a peer that the
    /// server does not find by its key is refused as [`RestError::NoSuchPeer`]. A server in plain
    /// HTTP can't hold a peer without a name, so a change that removes the name is refused as
    /// [`RestError::NamelessUnsupported`] without a request.
    pub async fn update_peer(
        &self,
        listed: &PeerContents,
        contents: &PeerContents,
    ) -> Result<(), RestError> {
        match self.admin_api().await? {
            AdminApi::ByKey => {
                let TaggedPeer { tag, .. } = self.get_tagged_peer(listed).await?;
                let path = format!("/admin/peers/{}", listed.api_path_segment());
                self.http_form("PUT", &path, PeerUpdate::new(tag, contents))
                    .await
                    .map_err(RestError::peer_refusal)
            },
            AdminApi::Legacy => {
                if contents.name.is_none() {
                    return Err(RestError::NamelessUnsupported);
                }
                // The peer is sent as the server lists it, with the changes an admin may make.
                let LegacyPeer { id, contents: peer } = self.get_legacy_peer(listed).await?;
                let legacy = LegacyPeerContents {
                    name: contents.name.clone(),
                    is_admin: contents.is_admin,
                    is_disabled: contents.is_disabled,
                    ..peer
                };
                self.http_form("PUT", &format!("/admin/peers/{id}"), legacy)
                    .await
            },
        }
    }

    /// Perform a `verb` HTTP request at the given `endpoint`.
    ///
    /// Example: `rest_client.http("GET", "/admin/peers").await?;`.
    pub async fn http<T: DeserializeOwned>(
        &self,
        verb: &str,
        endpoint: &str,
    ) -> Result<T, RestError> {
        self.request::<(), _>(verb, endpoint, None).await
    }

    /// Send serializable data using a `verb` HTTP request at the given `endpoint`
    ///
    /// Example: `rest_client.http_form("POST", "/admin/peers", PeerContents { .. }).await?;`.
    pub async fn http_form<S: Serialize, T: DeserializeOwned>(
        &self,
        verb: &str,
        endpoint: &str,
        form: S,
    ) -> Result<T, RestError> {
        self.request(verb, endpoint, Some(form)).await
    }

    async fn request<S: Serialize, T: DeserializeOwned>(
        &self,
        verb: &str,
        endpoint: &str,
        form: Option<S>,
    ) -> Result<T, RestError> {
        let (_, body) = self.request_raw(verb, endpoint, form).await?;
        decode(&body)
    }

    /// Performs a `verb` HTTP request at `endpoint`, with `form` as its body, and returns the
    /// transport that the server answered in, with the body of the answer. The form of the
    /// answer can depend on the transport, since a server in plain HTTP serves the API as clients
    /// that predate TLS know it.
    async fn request_raw<S: Serialize>(
        &self,
        verb: &str,
        endpoint: &str,
        form: Option<S>,
    ) -> Result<(Transport, Vec<u8>), RestError> {
        let method = Method::from_bytes(verb.as_bytes()).map_err(|_| RestError::Method)?;
        let payload = form
            .map(|form| serde_json::to_vec(&form))
            .transpose()
            .map_err(RestError::RequestSerialize)?;
        let request = |uri: String| {
            let request = Request::builder()
                .method(method.clone())
                .uri(uri)
                .header(header::HOST, self.server.internal_endpoint.to_string())
                .header(INNERNET_PUBKEY_HEADER, &self.server.public_key);
            match &payload {
                Some(payload) => request
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(payload.clone())),
                None => request.body(Body::empty()),
            }
            .map_err(|_| RestError::Method)
        };

        let (transport, (status, body)) = loop {
            if self.predates_tls.get() {
                let uri = format!("http://{}/v1{endpoint}", self.server.internal_endpoint);
                let answer = timed(self.plain_exchange(request(uri)?)).await?;
                break (Transport::Plain, answer);
            }
            match timed(self.tls_exchange(request(format!("/v1{endpoint}"))?)).await {
                // The server authenticated with its key and answered over TLS.
                Ok(answer) => {
                    self.record_tls();
                    break (Transport::Tls, answer);
                },
                // The server answered the handshake without reading the request, so the request
                // is sent again in plain HTTP, unless the server is known to speak TLS.
                Err(RestError::Handshake(e)) if is_plain_http_server(&e) => {
                    if self.speaks_tls.get() {
                        return Err(RestError::ServerDowngraded);
                    }
                    log::warn!(
                        "the innernet server predates TLS, so requests to it are made in plain \
                         HTTP, in which anything on this machine that sends from its innernet IP \
                         can act as this peer, until the server is upgraded."
                    );
                    self.predates_tls.set(true);
                },
                Err(e) => return Err(e),
            }
        };
        if !status.is_success() {
            // The server explains refusals that a client can't make sense of on its own.
            let message = explanation(&body);
            return Err(if message.is_empty() {
                RestError::Status(status)
            } else {
                RestError::Refused { status, message }
            });
        }

        Ok((transport, body))
    }

    /// Exchanges `request` for an answer in plain HTTP.
    async fn plain_exchange(
        &self,
        request: Request<Body>,
    ) -> Result<(StatusCode, Vec<u8>), RestError> {
        let response = self
            .plain_client
            .request(request)
            .await
            .map_err(|e| RestError::RequestSend(Box::new(e)))?;
        read_answer(response).await
    }

    /// Exchanges `request` for an answer over TLS, on a connection of its own to the server.
    async fn tls_exchange(
        &self,
        request: Request<Body>,
    ) -> Result<(StatusCode, Vec<u8>), RestError> {
        let address = self.server.internal_endpoint;
        let stream = TcpStream::connect(address)
            .await
            .map_err(|e| RestError::RequestSend(Box::new(e)))?;
        // The name is the server's address, which the client doesn't check: it pins the key.
        let name = rustls::pki_types::ServerName::IpAddress(address.ip().into());
        let stream = self
            .tls_connector
            .connect(name, stream)
            .await
            .map_err(RestError::Handshake)?;
        let (mut sender, connection) = hyper::client::conn::handshake(stream)
            .await
            .map_err(|e| RestError::RequestSend(Box::new(e)))?;
        let connection = tokio::spawn(connection);
        let answer = async {
            let response = sender
                .send_request(request)
                .await
                .map_err(|e| RestError::RequestSend(Box::new(e)))?;
            read_answer(response).await
        }
        .await;
        connection.abort();
        answer
    }

    /// Records that the server speaks TLS, if it isn't known yet.
    fn record_tls(&self) {
        if self.speaks_tls.replace(true) {
            return;
        }
        if let Some(latch) = &self.latch {
            if let Err(e) = latch() {
                log::warn!("failed to record that the innernet server speaks TLS: {e:#}");
            }
        }
    }
}

/// Whether the peers `a` and `b` are the same, but for their endpoints and candidates, which the
/// peer reports on its own.
fn same_but_endpoints(a: &PeerContents, b: &PeerContents) -> bool {
    let without_endpoints = |peer: &PeerContents| PeerContents {
        endpoint: None,
        candidates: vec![],
        ..peer.clone()
    };
    without_endpoints(a) == without_endpoints(b)
}

/// Decodes the body of an answer as JSON. An empty body decodes as `null`, so that it decodes as
/// `()`.
fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, RestError> {
    let body: &[u8] = if body.is_empty() { b"null" } else { body };
    serde_json::from_slice(body).map_err(RestError::ResponseDeserialize)
}

/// The transport that a server answered a request in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// TLS, authenticated with the server's key.
    Tls,
    /// Plain HTTP, as servers that predate TLS speak it.
    Plain,
}

/// The admin API that a server offers a client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminApi {
    /// The API of TLS sessions, which addresses peers by public key only.
    ByKey,
    /// The API of plain-HTTP sessions with a server that predates TLS, which addresses peers by
    /// ID.
    Legacy,
}

/// Runs `exchange` for at most [`TIMEOUT`].
async fn timed<T>(
    exchange: impl std::future::Future<Output = Result<T, RestError>>,
) -> Result<T, RestError> {
    tokio::time::timeout(TIMEOUT, exchange)
        .await
        .map_err(|_| RestError::Timeout)?
}

/// The status and the body of `response`, of which only the explanation, the first
/// [`MAX_EXPLANATION_LEN`] bytes, is read for a refusal.
async fn read_answer(response: Response<Body>) -> Result<(StatusCode, Vec<u8>), RestError> {
    use hyper::body::HttpBody as _;
    let status = response.status();
    let mut body = response.into_body();
    if status.is_success() {
        let body = hyper::body::to_bytes(body)
            .await
            .map_err(|e| RestError::RequestSend(Box::new(e)))?;
        return Ok((status, body.to_vec()));
    }
    let mut explanation = vec![];
    while explanation.len() < MAX_EXPLANATION_LEN {
        match body.data().await {
            Some(Ok(chunk)) => explanation.extend_from_slice(&chunk),
            _ => break,
        }
    }
    explanation.truncate(MAX_EXPLANATION_LEN);
    Ok((status, explanation))
}

/// How many bytes of the server's explanation of a refusal the client reads.
const MAX_EXPLANATION_LEN: usize = 1024;

/// The server's explanation of a refusal, of which `body` holds at most [`MAX_EXPLANATION_LEN`]
/// bytes, trimmed and escaped as [`str::escape_debug`] escapes it, so that printing it can't
/// affect the terminal.
fn explanation(body: &[u8]) -> String {
    String::from_utf8_lossy(body)
        .trim()
        .escape_debug()
        .to_string()
}

/// Whether the TLS handshake failed because the server answered in plain HTTP, as servers that
/// predate TLS do.
fn is_plain_http_server(error: &io::Error) -> bool {
    matches!(
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>()),
        Some(rustls::Error::InvalidMessage(
            rustls::InvalidMessage::InvalidContentType
        ))
    )
}

#[derive(Debug, Error)]
pub enum RestError {
    #[error("Error setting up TLS: {0}")]
    TlsConfig(anyhow::Error),
    #[error(
        "The innernet server answered in plain HTTP, but it is known to speak TLS, so the client \
         refuses to fall back to plain HTTP."
    )]
    ServerDowngraded,
    #[error("Error reading the data store: {0:#}")]
    DataStore(anyhow::Error),
    #[error(
        "The peer has changed since it was listed, so the change was not made. Running the \
         command again lists the peers anew."
    )]
    PeerChanged,
    #[error(
        "No peer has this public key (the invitation may have been redeemed under a new key, or \
         have expired), so the change was not made. Running the command again lists the peers \
         anew."
    )]
    NoSuchPeer,
    #[error(
        "The innernet server predates TLS, and can't hold a peer without a name. The operator \
         must upgrade the server first."
    )]
    NamelessUnsupported,
    /// The request failed to reach the server, or the server failed to answer it.
    #[error("Error sending request: {0}")]
    RequestSend(Box<dyn std::error::Error + Send + Sync>),
    /// The TLS handshake failed, such as when the server presents another key than the pinned
    /// one.
    #[error("The TLS handshake with the server failed: {0}")]
    Handshake(io::Error),
    #[error("The request timed out after {}s", TIMEOUT.as_secs())]
    Timeout,
    #[error("The server answered with {0}")]
    Status(StatusCode),
    #[error("The server refused the request ({status}): {message}")]
    Refused { status: StatusCode, message: String },
    #[error("Invalid request method")]
    Method,
    #[error("Error serializing request: {0}")]
    RequestSerialize(serde_json::Error),
    #[error("Error deserializing response: {0}")]
    ResponseDeserialize(serde_json::Error),
}

impl RestError {
    pub fn has_status_of(&self, status: u16) -> bool {
        match self {
            RestError::Status(s) | RestError::Refused { status: s, .. } => s.as_u16() == status,
            _ => false,
        }
    }

    /// Turns the statuses with which the server refuses a request about a peer named by its key
    /// into errors that say why: [`Self::PeerChanged`] for a peer that has changed since it was
    /// read, and [`Self::NoSuchPeer`] for a key that no peer has.
    fn peer_refusal(self) -> Self {
        if self.has_status_of(409) {
            RestError::PeerChanged
        } else if self.has_status_of(404) {
            RestError::NoSuchPeer
        } else {
            self
        }
    }

    /// Whether the request failed to reach the server, as when the server is down or
    /// unreachable. A failed TLS handshake, such as one in which the server presents another key
    /// than the pinned one, is not: something answered at the server's address.
    pub fn is_transport_error(&self) -> bool {
        matches!(self, RestError::RequestSend(_) | RestError::Timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::{SocketAddr, TcpListener},
        sync::{
            atomic::{AtomicUsize, Ordering},
            mpsc, Arc,
        },
        thread,
    };
    use wireguard_control::KeyPair;

    fn config(internal_endpoint: SocketAddr, server: &KeyPair) -> InterfaceConfig {
        let client = KeyPair::generate();
        toml::from_str(&format!(
            r#"
            [interface]
            network-name = "test"
            address = "10.0.0.2/24"
            private-key = "{}"
            listen-port = 51820

            [server]
            public-key = "{}"
            external-endpoint = "203.0.113.1:51820"
            internal-endpoint = "{internal_endpoint}"
            "#,
            client.private.to_base64(),
            server.public.to_base64(),
        ))
        .unwrap()
    }

    /// Answers each connection in plain HTTP, like a server that predates TLS, and returns the
    /// number of connections that opened with a TLS handshake.
    fn plain_http_server(connections: usize) -> (SocketAddr, thread::JoinHandle<usize>) {
        let (addr, server) = plain_http_server_recording(
            connections,
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        let handle = thread::spawn(move || {
            let requests = server.join().unwrap();
            requests.iter().filter(|r| *r == TLS_HANDSHAKE).count()
        });
        (addr, handle)
    }

    /// What [`plain_http_server_recording`] records of a connection that opens with a TLS
    /// handshake.
    const TLS_HANDSHAKE: &str = "TLS handshake";

    /// Answers each connection in plain HTTP with `response`, like a server that predates TLS,
    /// and returns the request line of each request, or [`TLS_HANDSHAKE`].
    fn plain_http_server_recording(
        connections: usize,
        response: &'static str,
    ) -> (SocketAddr, thread::JoinHandle<Vec<String>>) {
        plain_http_server_answering(vec![response.to_string(); connections])
    }

    /// Answers each connection in plain HTTP with the next of `responses`, like a server that
    /// predates TLS, and returns the request line of each request, or [`TLS_HANDSHAKE`].
    fn plain_http_server_answering(
        responses: Vec<String>,
    ) -> (SocketAddr, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut requests = vec![];
            for (response, stream) in responses.into_iter().zip(listener.incoming()) {
                let mut stream = stream.unwrap();
                let mut buffer = [0u8; 4096];
                let read = stream.read(&mut buffer).unwrap();
                requests.push(
                    if buffer[..read].first() == Some(&tls::TLS_HANDSHAKE_RECORD) {
                        TLS_HANDSHAKE.to_string()
                    } else {
                        let request = String::from_utf8_lossy(&buffer[..read]);
                        request.lines().next().unwrap_or_default().to_string()
                    },
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
            requests
        });
        (addr, handle)
    }

    /// Answers each connection over TLS, authenticated with `server`'s key, with an empty
    /// response.
    fn tls_server(server: &KeyPair, connections: usize) -> SocketAddr {
        tls_server_answering(
            server,
            connections,
            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
        )
    }

    /// Answers each connection over TLS, authenticated with `server`'s key, with `response`.
    fn tls_server_answering(server: &KeyPair, connections: usize, response: String) -> SocketAddr {
        tls_server_recording(server, vec![response; connections]).0
    }

    /// Answers each connection over TLS, authenticated with `server`'s key, with the next of
    /// `responses`, and sends each request, its head and its body, to the receiver.
    fn tls_server_recording(
        server: &KeyPair,
        responses: Vec<String>,
    ) -> (SocketAddr, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let config = tls::server_config(&server.private.to_base64()).unwrap();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            for (response, stream) in responses.into_iter().zip(listener.incoming()) {
                let connection = rustls::ServerConnection::new(config.clone()).unwrap();
                let mut stream = rustls::StreamOwned::new(connection, stream.unwrap());
                let mut reader = BufReader::new(&mut stream);
                let mut request = String::new();
                // A client that refuses the handshake ends the connection.
                while matches!(reader.read_line(&mut request), Ok(read) if read > 0)
                    && !request.ends_with("\r\n\r\n")
                {}
                let content_length = request
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().ok())?
                    })
                    .unwrap_or(0);
                let mut body = vec![0; content_length];
                if reader.read_exact(&mut body).is_ok() {
                    request.push_str(&String::from_utf8_lossy(&body));
                }
                let _ = sender.send(request);
                let _ = stream.write_all(response.as_bytes());
                stream.conn.send_close_notify();
                let _ = stream.flush();
            }
        });
        (addr, receiver)
    }

    /// A response with the status `status` and the JSON body `body`.
    fn json_response(status: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        )
    }

    const NO_CONTENT: &str = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";

    /// [`NO_CONTENT`], for a server that closes each connection after its answer.
    const NO_CONTENT_CLOSE: &str =
        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

    /// A peer whose key, in standard base64, holds both '+' and '/'.
    fn listed_peer() -> PeerContents {
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_mut(3) {
            chunk.copy_from_slice(&[0xfb, 0xff, 0xbf][..chunk.len()]);
        }
        PeerContents {
            name: Some("peer".parse().unwrap()),
            ip: "10.0.0.7".parse().unwrap(),
            cidr_id: 1,
            public_key: wireguard_control::Key(bytes).to_base64(),
            endpoint: None,
            persistent_keepalive_interval: None,
            is_admin: false,
            is_disabled: false,
            is_redeemed: true,
            invite_expires: None,
            candidates: vec![],
        }
    }

    /// The answer of a server in plain HTTP to a listing of `peers`, each with the ID 7.
    fn legacy_list_response(peers: &[PeerContents]) -> String {
        let peers: Vec<_> = peers
            .iter()
            .map(|contents| LegacyPeer {
                id: 7,
                contents: LegacyPeerContents::from_peer(contents).unwrap(),
            })
            .collect();
        json_response("200 OK", &serde_json::to_string(&peers).unwrap())
    }

    /// The server's answer to a read of `peer` with the tag `tag`.
    fn tagged_response(peer: &PeerContents, tag: &str) -> String {
        let tagged = TaggedPeer {
            peer: peer.clone(),
            tag: tag.into(),
        };
        json_response("200 OK", &serde_json::to_string(&tagged).unwrap())
    }

    #[tokio::test]
    async fn test_updates_peers_by_key_over_tls() {
        let server_key = KeyPair::generate();
        let peer = listed_peer();
        // The server reports the endpoint that it observes, which the tag leaves out.
        let observed = PeerContents {
            endpoint: Some("198.51.100.1:51820".parse().unwrap()),
            ..peer.clone()
        };
        let (addr, requests) = tls_server_recording(
            &server_key,
            vec![
                json_response("200 OK", "{}"),
                tagged_response(&observed, "ab"),
                NO_CONTENT.into(),
            ],
        );
        let config = config(addr, &server_key);
        let client = RestClient::new(&config, false).unwrap();

        // Unless a request has settled it, the client asks the server which API it offers.
        assert_eq!(client.admin_api().await.unwrap(), AdminApi::ByKey);
        let renamed = PeerContents {
            name: Some("renamed".parse().unwrap()),
            ..peer.clone()
        };
        client.update_peer(&peer, &renamed).await.unwrap();
        assert!(requests
            .recv()
            .unwrap()
            .starts_with("GET /v1/user/capabilities "));

        // The client reads the peer by key, and changes it with the tag it read.
        let segment = peer.api_path_segment();
        assert!(!segment.contains(['+', '/']));
        let get = requests.recv().unwrap();
        assert!(
            get.starts_with(&format!("GET /v1/admin/peers/{segment} ")),
            "{get}"
        );
        let put = requests.recv().unwrap();
        assert!(
            put.starts_with(&format!("PUT /v1/admin/peers/{segment} ")),
            "{put}"
        );
        let body: PeerUpdate = serde_json::from_str(put.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(body, PeerUpdate::new("ab".into(), &renamed));
    }

    #[tokio::test]
    async fn test_refuses_peers_changed_since_listed() {
        let server_key = KeyPair::generate();
        let peer = listed_peer();
        let promoted = PeerContents {
            is_admin: true,
            ..peer.clone()
        };
        let not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string();
        let conflict = "HTTP/1.1 409 Conflict\r\nContent-Length: 0\r\n\r\n".to_string();
        let (addr, requests) = tls_server_recording(
            &server_key,
            vec![
                // The peer changed between the listing and the read.
                tagged_response(&promoted, "ab"),
                // The peer changed between the read and the change.
                tagged_response(&peer, "ab"),
                conflict,
                // No peer has the key any more, as when an invitation is redeemed under a new
                // key, before the read.
                not_found.clone(),
                // No peer has the key any more, between the read and the change.
                tagged_response(&peer, "ab"),
                not_found,
            ],
        );
        let config = config(addr, &server_key);
        let client = RestClient::new(&config, true).unwrap();
        for _ in 0..2 {
            let error = client.update_peer(&peer, &peer).await.unwrap_err();
            assert!(matches!(error, RestError::PeerChanged), "{error:?}");
        }
        for _ in 0..2 {
            let error = client.update_peer(&peer, &peer).await.unwrap_err();
            assert!(matches!(error, RestError::NoSuchPeer), "{error:?}");
        }
        let methods: Vec<_> = requests
            .iter()
            .map(|request| request.split(' ').next().unwrap().to_string())
            .collect();
        assert_eq!(methods, ["GET", "GET", "PUT", "GET", "GET", "PUT"]);
    }

    #[tokio::test]
    async fn test_updates_peers_by_id_in_plain_http() {
        // The server observes an endpoint for the peer, which it didn't when the peer was listed.
        let peer = listed_peer();
        let observed = PeerContents {
            endpoint: Some("198.51.100.1:51820".parse().unwrap()),
            ..peer.clone()
        };
        let server_key = KeyPair::generate();
        let (addr, server) = plain_http_server_answering(vec![
            NO_CONTENT_CLOSE.into(),
            NO_CONTENT_CLOSE.into(),
            legacy_list_response(&[observed]),
            NO_CONTENT_CLOSE.into(),
        ]);
        let config = config(addr, &server_key);
        let client = RestClient::new(&config, false).unwrap();

        // The client lists the peers again for the ID of the peer, and changes it by its ID.
        assert_eq!(client.admin_api().await.unwrap(), AdminApi::Legacy);
        client.update_peer(&peer, &peer).await.unwrap();
        assert_eq!(
            server.join().unwrap(),
            [
                TLS_HANDSHAKE,
                "GET /v1/user/capabilities HTTP/1.1",
                "GET /v1/admin/peers HTTP/1.1",
                "PUT /v1/admin/peers/7 HTTP/1.1",
            ]
        );
    }

    #[tokio::test]
    async fn test_refuses_peers_changed_since_listed_in_plain_http() {
        // A peer that has changed since it was listed, or that is gone, is refused, and nothing
        // is changed.
        let peer = listed_peer();
        let promoted = PeerContents {
            is_admin: true,
            ..peer.clone()
        };
        let server_key = KeyPair::generate();
        let (addr, server) = plain_http_server_answering(vec![
            NO_CONTENT_CLOSE.into(),
            NO_CONTENT_CLOSE.into(),
            legacy_list_response(&[promoted]),
            legacy_list_response(&[]),
        ]);
        let config = config(addr, &server_key);
        let client = RestClient::new(&config, false).unwrap();
        for _ in 0..2 {
            let error = client.update_peer(&peer, &peer).await.unwrap_err();
            assert!(matches!(error, RestError::PeerChanged), "{error:?}");
        }
        assert_eq!(
            server.join().unwrap(),
            [
                TLS_HANDSHAKE,
                "GET /v1/user/capabilities HTTP/1.1",
                "GET /v1/admin/peers HTTP/1.1",
                "GET /v1/admin/peers HTTP/1.1",
            ]
        );
    }

    #[tokio::test]
    async fn test_decodes_by_transport() {
        // A server in plain HTTP sends peers with their IDs, which are left out, and is never
        // sent a peer that it can't hold.
        let peer = listed_peer();
        let state = format!(
            r#"{{"peers": {}, "cidrs": []}}"#,
            serde_json::to_string(&[LegacyPeer {
                id: 7,
                contents: LegacyPeerContents::from_peer(&peer).unwrap(),
            }])
            .unwrap()
        );
        let server_key = KeyPair::generate();
        let (addr, server) = plain_http_server_answering(vec![
            NO_CONTENT_CLOSE.into(),
            json_response("200 OK", &state),
            legacy_list_response(std::slice::from_ref(&peer)),
        ]);
        let config = config(addr, &server_key);
        let client = RestClient::new(&config, false).unwrap();
        assert_eq!(
            client.get_state().await.unwrap().peers,
            std::slice::from_ref(&peer)
        );
        assert_eq!(
            client.get_peers().await.unwrap(),
            std::slice::from_ref(&peer)
        );
        let nameless = PeerContents { name: None, ..peer };
        let error = client.create_peer(&nameless).await.unwrap_err();
        assert!(matches!(error, RestError::NamelessUnsupported), "{error:?}");
        let error = client.update_peer(&nameless, &nameless).await.unwrap_err();
        assert!(matches!(error, RestError::NamelessUnsupported), "{error:?}");
        assert_eq!(
            server.join().unwrap(),
            [
                TLS_HANDSHAKE,
                "GET /v1/user/state HTTP/1.1",
                "GET /v1/admin/peers HTTP/1.1",
            ]
        );
    }

    #[tokio::test]
    async fn test_falls_back_for_servers_that_predate_tls() {
        let server_key = KeyPair::generate();
        let (addr, server) = plain_http_server(3);
        let config = config(addr, &server_key);
        let client = RestClient::new(&config, false).unwrap();

        // The first request tries TLS and is sent again in plain HTTP, and later requests are
        // only sent in plain HTTP.
        for _ in 0..2 {
            let error = client
                .http::<String>("GET", "/user/state")
                .await
                .unwrap_err();
            assert!(error.has_status_of(400), "{error:?}");
        }
        assert!(!client.speaks_tls());
        assert_eq!(server.join().unwrap(), 1);
    }

    #[tokio::test]
    async fn test_refuses_plain_http_from_servers_known_to_speak_tls() {
        let server_key = KeyPair::generate();
        let (addr, server) = plain_http_server(2);
        let config = config(addr, &server_key);
        let client = RestClient::new(&config, true).unwrap();

        // Every request is refused, and none is sent in plain HTTP.
        for _ in 0..2 {
            let error = client
                .http::<String>("GET", "/user/state")
                .await
                .unwrap_err();
            assert!(matches!(error, RestError::ServerDowngraded), "{error:?}");
            assert!(!error.is_transport_error());
        }
        assert_eq!(server.join().unwrap(), 2);
    }

    #[tokio::test]
    async fn test_latches_when_answered_over_tls() {
        let server_key = KeyPair::generate();
        let addr = tls_server(&server_key, 2);
        let config = config(addr, &server_key);
        let latched = Arc::new(AtomicUsize::new(0));
        let client = RestClient {
            latch: Some(Box::new({
                let latched = latched.clone();
                move || {
                    latched.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            })),
            ..RestClient::new(&config, false).unwrap()
        };

        // The server is recorded as speaking TLS once, on its first answer.
        for _ in 0..2 {
            client.http::<()>("GET", "/user/state").await.unwrap();
        }
        assert!(client.speaks_tls());
        assert_eq!(latched.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_wrong_server_key_is_not_a_transport_error() {
        // A server that authenticates with another key than the pinned one isn't merely
        // unreachable.
        let addr = tls_server(&KeyPair::generate(), 1);
        let config = config(addr, &KeyPair::generate());
        let client = RestClient::new(&config, false).unwrap();
        let error = client.http::<()>("GET", "/user/state").await.unwrap_err();
        assert!(!error.is_transport_error(), "{error:?}");
        assert!(!client.speaks_tls());
    }

    #[tokio::test]
    async fn test_explanations_are_sanitized() {
        // The server's explanation of a refusal is cut short, and its control characters are
        // escaped.
        let server_key = KeyPair::generate();
        let text = "\x1b[31mrefused\nby the server\x07";
        let body = format!("{text}{}", "x".repeat(10_000));
        let response = format!(
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let addr = tls_server_answering(&server_key, 1, response);
        let config = config(addr, &server_key);
        let client = RestClient::new(&config, false).unwrap();
        match client.http::<()>("GET", "/user/state").await.unwrap_err() {
            RestError::Refused { status, message } => {
                assert_eq!(status, StatusCode::UNAUTHORIZED);
                let shown = "x".repeat(MAX_EXPLANATION_LEN - text.len());
                assert_eq!(
                    message,
                    format!(r"\u{{1b}}[31mrefused\nby the server\u{{7}}{shown}")
                );
            },
            error => panic!("{error:?}"),
        }
    }

    #[tokio::test]
    async fn test_transport_errors() {
        // Nothing is listening.
        let addr = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let config = config(addr, &KeyPair::generate());
        let client = RestClient::new(&config, false).unwrap();
        let error = client
            .http::<String>("GET", "/user/state")
            .await
            .unwrap_err();
        assert!(error.is_transport_error());
    }
}
