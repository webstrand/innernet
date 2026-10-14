use innernet_shared::{
    interface_config::{InterfaceConfig, ServerInfo},
    tls, Cidr, CidrContents, Peer, PeerContents, INNERNET_PUBKEY_HEADER,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{io, time::Duration};
use thiserror::Error;
use ureq::{Agent, AgentBuilder};

/// A REST client that can be used to communicate with an innernet REST server.
///
/// Requests are made over TLS, authenticated with the interface's WireGuard key. A server that
/// predates TLS is refused.
///
/// We recommend to use the high level API (like [`Self::create_peer()`]) when possible and fall
/// back on the low level [`Self::http()`] and [`Self::http_form()`] otherwise.
pub struct RestClient<'a> {
    agent: Agent,
    server: &'a ServerInfo,
}

impl<'a> RestClient<'a> {
    /// Create a [`Self`] to communicate with the innernet server of an interface, as the
    /// interface's peer.
    pub fn new(config: &'a InterfaceConfig) -> Result<Self, RestError> {
        let tls_config =
            tls::client_config(&config.interface.private_key, &config.server.public_key)
                .map_err(RestError::TlsConfig)?;
        let agent = AgentBuilder::new()
            // Some platforms (e.g. OpenBSD) can take longer to complete the first WireGuard
            // handshake, hence a lower timeout value could result in an unwarranted failure
            .timeout(Duration::from_secs(10))
            .redirects(0)
            .tls_config(tls_config)
            .build();
        Ok(Self {
            agent,
            server: &config.server,
        })
    }

    pub fn create_cidr(&self, cidr_contents: &CidrContents) -> Result<Cidr, RestError> {
        let cidr = self.http_form("POST", "/admin/cidrs", cidr_contents)?;
        Ok(cidr)
    }

    pub fn get_cidrs(&self) -> Result<Vec<Cidr>, RestError> {
        let cidrs = self.http("GET", "/admin/cidrs")?;
        Ok(cidrs)
    }

    pub fn create_peer(&self, peer_contents: &PeerContents) -> Result<Peer, RestError> {
        let peer = self.http_form("POST", "/admin/peers", peer_contents)?;
        Ok(peer)
    }

    pub fn get_peers(&self) -> Result<Vec<Peer>, RestError> {
        let peers = self.http("GET", "/admin/peers")?;
        Ok(peers)
    }

    #[allow(clippy::result_large_err)]
    /// Perform a `verb` HTTP request at the given `endpoint`.
    ///
    /// Example: `rest_client.http("GET", "/admin/peers")?;`.
    pub fn http<T: DeserializeOwned>(&self, verb: &str, endpoint: &str) -> Result<T, RestError> {
        self.request::<(), _>(verb, endpoint, None)
    }

    /// Send serializable data using a `verb` HTTP request at the given `endpoint`
    ///
    /// Example: `rest_client.http_form("POST", "/admin/peers", PeerContents { .. })?;`.
    #[allow(clippy::result_large_err)]
    pub fn http_form<S: Serialize, T: DeserializeOwned>(
        &self,
        verb: &str,
        endpoint: &str,
        form: S,
    ) -> Result<T, RestError> {
        self.request(verb, endpoint, Some(form))
    }

    #[allow(clippy::result_large_err)]
    fn request<S: Serialize, T: DeserializeOwned>(
        &self,
        verb: &str,
        endpoint: &str,
        form: Option<S>,
    ) -> Result<T, RestError> {
        let payload = form
            .map(serde_json::to_value)
            .transpose()
            .map_err(RestError::RequestSerialize)?;

        let request = self
            .agent
            .request(
                verb,
                &format!("https://{}/v1{}", self.server.internal_endpoint, endpoint),
            )
            .set(INNERNET_PUBKEY_HEADER, &self.server.public_key);

        let result = match payload {
            Some(payload) => request.send_json(payload),
            None => request.call(),
        };
        let response = match result {
            Ok(response) => response,
            Err(ureq::Error::Status(status, response)) => {
                // The server explains refusals that an outdated client can't make sense of.
                let message = response.into_string().unwrap_or_default();
                return Err(if message.is_empty() {
                    RestError::Status(status)
                } else {
                    RestError::Refused { status, message }
                });
            },
            Err(e) if is_plain_http_server(&e) => return Err(RestError::ServerPredatesTls),
            Err(e) => return Err(RestError::RequestSend(Box::new(e))),
        };

        let mut response = response.into_string().map_err(RestError::ResponseRead)?;
        // A little trick for serde to parse an empty response as `()`.
        if response.is_empty() {
            response = "null".into();
        }
        serde_json::from_str(&response).map_err(RestError::ResponseDeserialize)
    }
}

/// Whether the TLS handshake failed because the server answered in plain HTTP, as servers that
/// predate TLS do.
fn is_plain_http_server(error: &ureq::Error) -> bool {
    let mut source = std::error::Error::source(error);
    while let Some(error) = source {
        let rustls_error = error
            .downcast_ref::<io::Error>()
            .and_then(|io| io.get_ref())
            .and_then(|inner| inner.downcast_ref::<rustls::Error>());
        if let Some(rustls::Error::InvalidMessage(rustls::InvalidMessage::InvalidContentType)) =
            rustls_error
        {
            return true;
        }
        source = error.source();
    }
    false
}

#[derive(Debug, Error)]
pub enum RestError {
    #[error("Error setting up TLS: {0}")]
    TlsConfig(anyhow::Error),
    #[error(
        "The innernet server predates TLS, which this client requires. The server must be \
         upgraded before its clients."
    )]
    ServerPredatesTls,
    /// A transport error; error statuses are [`Self::Status`] and [`Self::Refused`].
    #[error("Error sending request: {0}")]
    RequestSend(Box<ureq::Error>),
    #[error("The server responded with status {0}")]
    Status(u16),
    #[error("The server refused the request ({status}): {message}")]
    Refused { status: u16, message: String },
    #[error("Error serializing request: {0}")]
    RequestSerialize(serde_json::Error),
    #[error("Error deserializing response: {0}")]
    ResponseDeserialize(serde_json::Error),
    #[error("Error reading response: {0}")]
    ResponseRead(io::Error),
}

impl RestError {
    pub fn has_status_of(&self, status: u16) -> bool {
        match self {
            RestError::Status(s) | RestError::Refused { status: s, .. } => *s == status,
            _ => false,
        }
    }

    pub fn is_transport_error(&self) -> bool {
        if let RestError::RequestSend(error) = self {
            matches!(**error, ureq::Error::Transport(_))
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };
    use wireguard_control::KeyPair;

    fn config(internal_endpoint: std::net::SocketAddr) -> InterfaceConfig {
        let (client, server) = (KeyPair::generate(), KeyPair::generate());
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
    fn plain_http_server(connections: usize) -> (std::net::SocketAddr, thread::JoinHandle<usize>) {
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

    #[test]
    fn test_refuses_servers_that_predate_tls() {
        let (addr, server) = plain_http_server(2);
        let config = config(addr);
        let client = RestClient::new(&config).unwrap();

        // Every request is refused, and none is sent in plain HTTP.
        for _ in 0..2 {
            let error = client.http::<String>("GET", "/user/state").unwrap_err();
            assert!(matches!(error, RestError::ServerPredatesTls), "{error:?}");
            assert!(!error.is_transport_error());
        }
        assert_eq!(server.join().unwrap(), 2);
    }

    #[test]
    fn test_transport_errors() {
        // Nothing is listening.
        let addr = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let config = config(addr);
        let client = RestClient::new(&config).unwrap();
        let error = client.http::<String>("GET", "/user/state").unwrap_err();
        assert!(error.is_transport_error());
    }
}
