use bytes::Buf;
use hyper::{header, Body, Request, Response, StatusCode};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha512};

use crate::ServerError;

pub async fn form_body<F: DeserializeOwned>(req: Request<Body>) -> Result<F, ServerError> {
    let content_len: usize = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.parse().ok())
        .ok_or(ServerError::InvalidQuery)?;

    if content_len > 16 * 1024 {
        return Err(ServerError::InvalidQuery);
    }

    let whole_body = hyper::body::aggregate(req).await?;

    serde_json::from_reader(whole_body.reader()).map_err(Into::into)
}

pub fn json_response<F: Serialize>(form: F) -> Result<Response<Body>, ServerError> {
    let json = serde_json::to_string(&form)?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json))?)
}

pub fn json_status_response<F: Serialize>(
    form: F,
    status: StatusCode,
) -> Result<Response<Body>, ServerError> {
    let json = serde_json::to_string(&form)?;
    Ok(Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json))?)
}

pub fn status_response(status: StatusCode) -> Result<Response<Body>, ServerError> {
    Ok(Response::builder().status(status).body(Body::empty())?)
}

/// The entity tag of `value`: SHA-512 of its JSON serialization, truncated to 256 bits, in hex
/// and quoted.
pub fn etag<T: Serialize>(value: &T) -> Result<String, ServerError> {
    let hash = Sha512::digest(serde_json::to_vec(value)?);
    let hex: String = hash[..32]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(format!("\"{hex}\""))
}

/// The `If-Match` header of `req`, if any.
pub fn if_match(req: &Request<Body>) -> Result<Option<String>, ServerError> {
    req.headers()
        .get(header::IF_MATCH)
        .map(|value| {
            value
                .to_str()
                .map(str::to_string)
                .map_err(|_| ServerError::InvalidQuery)
        })
        .transpose()
}

/// Checks the `If-Match` header `if_match` against the entity tag `current` of the resource as it
/// stands. A request without the header is always accepted. Entity tags are compared strongly, so
/// weak ones never match.
pub fn check_if_match(if_match: Option<&str>, current: &str) -> Result<(), ServerError> {
    match if_match {
        None => Ok(()),
        Some(if_match)
            if if_match.trim() == "*" || if_match.split(',').any(|tag| tag.trim() == current) =>
        {
            Ok(())
        },
        Some(_) => Err(ServerError::PreconditionFailed),
    }
}

/// A JSON response with the entity tag `etag`.
pub fn json_etag_response<F: Serialize>(
    form: F,
    etag: &str,
) -> Result<Response<Body>, ServerError> {
    let json = serde_json::to_string(&form)?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ETAG, etag)
        .body(Body::from(json))?)
}
