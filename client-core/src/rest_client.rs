use hyper::{client::HttpConnector, header, Body, Client, Method, Request, StatusCode};
use innernet_shared::{
    interface_config::ServerInfo, Cidr, CidrContents, Peer, PeerContents, INNERNET_PUBKEY_HEADER,
};
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;
use thiserror::Error;

/// How long a request may take. Some platforms, such as OpenBSD, can take longer to complete the
/// first WireGuard handshake, so a lower timeout could fail a request that would succeed.
const TIMEOUT: Duration = Duration::from_secs(10);

/// A REST client that can be used to communicate with an innernet REST server.
///
/// We recommend to use the high level API (like [`Self::create_peer()`]) when possible and fall
/// back on the low level [`Self::http()`] and [`Self::http_form()`] otherwise.
pub struct RestClient<'a> {
    client: Client<HttpConnector>,
    server: &'a ServerInfo,
}

impl<'a> RestClient<'a> {
    /// Create a [`Self`] to communicate with an innernet server described by [`ServerInfo`].
    pub fn new(server: &'a ServerInfo) -> Self {
        Self {
            client: Client::new(),
            server,
        }
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
        let request = Request::builder()
            .method(method)
            .uri(format!(
                "http://{}/v1{}",
                self.server.internal_endpoint, endpoint
            ))
            .header(INNERNET_PUBKEY_HEADER, &self.server.public_key);
        let request = match form {
            Some(form) => {
                let payload = serde_json::to_vec(&form).map_err(RestError::RequestSerialize)?;
                request
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(payload))
            },
            None => request.body(Body::empty()),
        }
        .map_err(|_| RestError::Method)?;

        let response = tokio::time::timeout(TIMEOUT, async {
            let response = self.client.request(request).await?;
            let status = response.status();
            let body = hyper::body::to_bytes(response.into_body()).await?;
            Ok::<_, hyper::Error>((status, body))
        })
        .await
        .map_err(|_| RestError::Timeout)?;
        let (status, body) = response.map_err(RestError::Transport)?;
        if !status.is_success() {
            return Err(RestError::Status(status));
        }

        // A little trick for serde to parse an empty response as `()`.
        let body: &[u8] = if body.is_empty() { b"null" } else { &body };
        serde_json::from_slice(body).map_err(RestError::ResponseDeserialize)
    }
}

#[derive(Debug, Error)]
pub enum RestError {
    #[error("Error sending request: {0}")]
    Transport(hyper::Error),
    #[error("The request timed out after {}s", TIMEOUT.as_secs())]
    Timeout,
    #[error("The server answered with {0}")]
    Status(StatusCode),
    #[error("Invalid request method")]
    Method,
    #[error("Error serializing request: {0}")]
    RequestSerialize(serde_json::Error),
    #[error("Error deserializing response: {0}")]
    ResponseDeserialize(serde_json::Error),
}

impl RestError {
    pub fn has_status_of(&self, status: u16) -> bool {
        matches!(self, RestError::Status(s) if s.as_u16() == status)
    }

    pub fn is_transport_error(&self) -> bool {
        matches!(self, RestError::Transport(_) | RestError::Timeout)
    }
}
