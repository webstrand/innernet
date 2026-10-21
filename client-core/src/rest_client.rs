use crate::data_store::DataStore;
use hyper::{client::HttpConnector, header, Body, Client, Method, Request, Response, StatusCode};
use innernet_shared::{
    interface_config::{InterfaceConfig, ServerInfo},
    tls, Cidr, CidrContents, Peer, PeerContents, INNERNET_PUBKEY_HEADER,
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

    pub async fn create_peer(&self, peer_contents: &PeerContents) -> Result<Peer, RestError> {
        self.http_form("POST", "/admin/peers", peer_contents).await
    }

    pub async fn get_peers(&self) -> Result<Vec<Peer>, RestError> {
        self.http("GET", "/admin/peers").await
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

        let (status, body) = loop {
            if self.predates_tls.get() {
                let uri = format!("http://{}/v1{endpoint}", self.server.internal_endpoint);
                break timed(self.plain_exchange(request(uri)?)).await?;
            }
            match timed(self.tls_exchange(request(format!("/v1{endpoint}"))?)).await {
                // The server authenticated with its key and answered over TLS.
                Ok(answer) => {
                    self.record_tls();
                    break answer;
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

        // A little trick for serde to parse an empty response as `()`.
        let body: &[u8] = if body.is_empty() { b"null" } else { &body };
        serde_json::from_slice(body).map_err(RestError::ResponseDeserialize)
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
            Arc,
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
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut handshakes = 0;
            for stream in listener.incoming().take(connections) {
                let mut stream = stream.unwrap();
                let mut buffer = [0u8; 4096];
                let read = stream.read(&mut buffer).unwrap();
                if buffer[..read].first() == Some(&tls::TLS_HANDSHAKE_RECORD) {
                    handshakes += 1;
                }
                let response =
                    "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                stream.write_all(response.as_bytes()).unwrap();
            }
            handshakes
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
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let config = tls::server_config(&server.private.to_base64()).unwrap();
        thread::spawn(move || {
            for stream in listener.incoming().take(connections) {
                let connection = rustls::ServerConnection::new(config.clone()).unwrap();
                let mut stream = rustls::StreamOwned::new(connection, stream.unwrap());
                let mut reader = BufReader::new(&mut stream);
                let mut line = String::new();
                // A client that refuses the handshake ends the connection.
                while matches!(reader.read_line(&mut line), Ok(read) if read > 0)
                    && !line.ends_with("\r\n\r\n")
                {}
                let _ = stream.write_all(response.as_bytes());
                stream.conn.send_close_notify();
                let _ = stream.flush();
            }
        });
        addr
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
