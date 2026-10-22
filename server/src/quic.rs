//! The TLS API, served in HTTP/3 over QUIC at the server's internal address.
//!
//! Each request is handed to the same router as the legacy API, [`crate::hyper_service`], which
//! speaks hyper's types; the request and the response are translated at the edge, with their
//! bodies read in full, since both are small.

use crate::{util::MAX_BODY_LEN as MAX_REQUEST_BODY_LEN, Context};
use anyhow::{anyhow, bail, Error};
use bytes::{Buf, Bytes};
use hyper::Body;
use innernet_shared::tls;
use quinn::{
    crypto::rustls::QuicServerConfig,
    rustls::{self, pki_types::CertificateDer},
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use wireguard_control::Key;

/// How long a connection may stay silent before the server drops it, the handshake included.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a client may take to send a request, its body included.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// A QUIC endpoint on `socket` that serves HTTP/3 in TLS as `tls_config` describes it. A
/// connection stays at the address it started from, so that the address that the router checks is
/// the one that WireGuard authenticated.
pub fn endpoint(
    socket: std::net::UdpSocket,
    tls_config: Arc<rustls::ServerConfig>,
) -> Result<quinn::Endpoint, Error> {
    let crypto = QuicServerConfig::try_from(tls_config)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(IDLE_TIMEOUT.try_into()?));
    server_config.transport_config(Arc::new(transport));
    server_config.migration(false);
    Ok(quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?)
}

/// Serves the TLS API on `endpoint`, each connection in a task of its own.
pub async fn serve(endpoint: quinn::Endpoint, context: Context) -> Result<(), Error> {
    while let Some(incoming) = endpoint.accept().await {
        let context = context.clone();
        tokio::spawn(async move {
            let remote_addr = incoming.remote_address();
            if let Err(e) = serve_connection(incoming, context).await {
                log::debug!("{remote_addr} (QUIC) - connection failed: {e}");
            }
        });
    }
    bail!("the QUIC endpoint of the TLS API closed")
}

/// The X25519 key that the client of `connection` authenticated with.
fn client_key(connection: &quinn::Connection) -> Option<Key> {
    let certificates = connection
        .peer_identity()?
        .downcast::<Vec<CertificateDer<'static>>>()
        .ok()?;
    tls::peer_public_key(Some(&certificates))
}

/// Serves the requests of one connection, each in a task of its own.
async fn serve_connection(incoming: quinn::Incoming, context: Context) -> Result<(), Error> {
    let connection = incoming.await?;
    let remote_addr = connection.remote_address();
    let client_key =
        client_key(&connection).ok_or_else(|| anyhow!("the client presented no usable key"))?;
    let mut h3 =
        h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection)).await?;
    loop {
        match h3.accept().await {
            Ok(Some(resolver)) => {
                let (context, client_key) = (context.clone(), client_key.clone());
                tokio::spawn(async move {
                    let served = async {
                        let (request, stream) = resolver.resolve_request().await?;
                        serve_request(request, stream, context, remote_addr, client_key).await
                    };
                    if let Err(e) = served.await {
                        log::debug!("{remote_addr} (QUIC) - request failed: {e}");
                    }
                });
            },
            Ok(None) => return Ok(()),
            Err(e) if e.is_h3_no_error() => return Ok(()),
            Err(e) => return Err(e.into()),
        }
    }
}

/// Serves one request, whose head is `request`, and whose body and response travel on `stream`.
async fn serve_request<S>(
    request: http1::Request<()>,
    mut stream: h3::server::RequestStream<S, Bytes>,
    context: Context,
    remote_addr: SocketAddr,
    client_key: Key,
) -> Result<(), Error>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let body = tokio::time::timeout(REQUEST_TIMEOUT, read_body(&mut stream)).await??;
    let request = hyper_request(request, body)?;
    log::debug!(
        "{remote_addr} (QUIC) - {} {}",
        request.method(),
        request.uri().path()
    );
    let response = crate::hyper_service(request, context, remote_addr, Some(client_key)).await?;

    let (parts, body) = response.into_parts();
    let body = hyper::body::to_bytes(body).await?;
    let mut response = http1::Response::builder().status(parts.status.as_u16());
    for (name, value) in &parts.headers {
        response = response.header(name.as_str(), value.as_bytes());
    }
    stream.send_response(response.body(())?).await?;
    if !body.is_empty() {
        stream.send_data(body).await?;
    }
    stream.finish().await?;
    Ok(())
}

/// Reads the body of a request from `stream`, up to one byte more than the server reads, so that
/// the router refuses a longer body for its length.
async fn read_body<S>(stream: &mut h3::server::RequestStream<S, Bytes>) -> Result<Vec<u8>, Error>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        while chunk.has_remaining() && body.len() <= MAX_REQUEST_BODY_LEN {
            let bytes = chunk.chunk();
            let take = bytes.len().min(MAX_REQUEST_BODY_LEN + 1 - body.len());
            body.extend_from_slice(&bytes[..take]);
            chunk.advance(take);
        }
        if body.len() > MAX_REQUEST_BODY_LEN {
            break;
        }
    }
    Ok(body)
}

/// The request with the head `request` and the body `body`, in hyper's types. A body states the
/// length that was read, whatever the head states, since HTTP/3 frames the body itself.
fn hyper_request(
    request: http1::Request<()>,
    body: Vec<u8>,
) -> Result<hyper::Request<Body>, Error> {
    let (parts, ()) = request.into_parts();
    let mut builder = hyper::Request::builder()
        .method(parts.method.as_str())
        .uri(parts.uri.to_string());
    for (name, value) in &parts.headers {
        if name != http1::header::CONTENT_LENGTH {
            builder = builder.header(name.as_str(), value.as_bytes());
        }
    }
    if !body.is_empty() {
        builder = builder.header(hyper::header::CONTENT_LENGTH, body.len());
    } else if parts.headers.contains_key(http1::header::CONTENT_LENGTH) {
        builder = builder.header(hyper::header::CONTENT_LENGTH, 0);
    }
    Ok(builder.body(Body::from(Bytes::from(body)))?)
}
