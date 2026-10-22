use bytes::Bytes;
use hyper::{body::HttpBody, header, Body, Method, Request, Response, StatusCode};
use innernet_shared::cbor;
use serde::{
    de::{DeserializeOwned, IgnoredAny},
    Deserialize, Serialize,
};

use crate::{ServerError, Session};
use innernet_shared::media_type::{self, Representation};

/// The longest body of a request that the server reads.
pub const MAX_BODY_LEN: usize = 16 * 1024;

/// Reads the body of `req`, a request of `session`, and decodes it as [`decode`] does.
pub async fn form_body<F: DeserializeOwned>(
    req: Request<Body>,
    session: &Session,
) -> Result<F, ServerError> {
    let body = read_body(req, session).await?;
    decode(session, &body)
}

/// Reads the body of `req`, a change of a tagged resource in `session`, as [`form_body`] does. A
/// change without a body, or whose body has no tag, is refused as [`ServerError::TagMissing`].
pub async fn tagged_form_body<F: DeserializeOwned>(
    req: Request<Body>,
    session: &Session,
) -> Result<F, ServerError> {
    #[derive(Deserialize)]
    struct Tagged {
        #[serde(default)]
        tag: Option<IgnoredAny>,
    }

    let has_body = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .is_some_and(|length| length != "0");
    if !has_body {
        return Err(ServerError::TagMissing);
    }
    let body = read_body(req, session).await?;
    if decode::<Tagged>(session, &body)?.tag.is_none() {
        return Err(ServerError::TagMissing);
    }
    decode(session, &body)
}

/// Reads the body of `req`, a request of `session`, which must state its length. A TLS session
/// must send the body in CBOR, and state its version in `Content-Type`, as [`body_version`] reads
/// it; any other content type is refused as [`ServerError::UnsupportedMediaType`]. A plain-HTTP
/// session sends JSON, as clients that predate TLS do, whatever content type it states.
pub async fn read_body(req: Request<Body>, session: &Session) -> Result<Bytes, ServerError> {
    let content_len: usize = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.parse().ok())
        .ok_or(ServerError::InvalidQuery)?;

    if content_len > MAX_BODY_LEN {
        return Err(ServerError::InvalidQuery);
    }
    if session.over_tls {
        body_version(&req)?.ok_or(ServerError::UnsupportedMediaType)?;
    }

    Ok(hyper::body::to_bytes(req).await?)
}

/// The version of the API that `req`, a request of a TLS session, states in `Content-Type`, or
/// `None` if it states no content type. Any content type but the media type of the API with a
/// version that the server reads is refused as [`ServerError::UnsupportedMediaType`].
pub fn body_version(req: &Request<Body>) -> Result<Option<u32>, ServerError> {
    let Some(header) = req.headers().get(header::CONTENT_TYPE) else {
        return Ok(None);
    };
    header
        .to_str()
        .ok()
        .and_then(|header| media_type::body_version(header, media_type::VERSIONS))
        .map(Some)
        .ok_or(ServerError::UnsupportedMediaType)
}

/// Chooses the representation of the responses to `req`, a request of a TLS session, by its
/// `Accept`, as [`media_type::negotiate`] does. A TLS session speaks a version of the API that
/// the server reads in every request: a content type of any other version, even without a body,
/// is refused as [`ServerError::UnsupportedMediaType`]. A content type announces a body, so a
/// request that states one without a body is refused as [`ServerError::EmptyBody`], since an
/// empty body is no CBOR; a change that has nothing to send states no content type. A request
/// that accepts no version that the server writes is refused as [`ServerError::NotAcceptable`],
/// and so is a request that changes state without naming a version in `Accept`, so that the
/// debug view never answers a change, which a client that knows no version could not read. A
/// change thus names its version in `Accept` whether it carries a body or not, and is never
/// taken for a change of another version.
pub fn negotiate(req: &Request<Body>) -> Result<Representation, ServerError> {
    let changes_state = !matches!(*req.method(), Method::GET | Method::HEAD);
    if body_version(req)?.is_some() && req.body().is_end_stream() {
        return Err(ServerError::EmptyBody);
    }
    match media_type::negotiate(accept(req).as_deref(), media_type::VERSIONS) {
        Some(Representation::Diagnostic(_)) if changes_state => Err(ServerError::NotAcceptable),
        Some(representation) => Ok(representation),
        None => Err(ServerError::NotAcceptable),
    }
}

/// The version of the debug view that `req`, a request of a TLS session, chooses with its
/// `Accept`, as [`media_type::negotiate`] chooses it, or `None` if it chooses no debug view. The
/// problems of such a request are answered in the debug view too, even for a change, which the
/// debug view never answers otherwise.
pub fn debug_view(req: &Request<Body>) -> Option<u32> {
    match media_type::negotiate(accept(req).as_deref(), media_type::VERSIONS) {
        Some(Representation::Diagnostic(version)) => Some(version),
        _ => None,
    }
}

/// The value of `Accept` in `req`, its fields joined as one, or `None` if `req` has none. A field
/// that isn't text accepts nothing.
fn accept(req: &Request<Body>) -> Option<String> {
    let fields: Vec<&str> = req
        .headers()
        .get_all(header::ACCEPT)
        .iter()
        .map(|field| field.to_str().unwrap_or_default())
        .collect();
    (!fields.is_empty()).then(|| fields.join(", "))
}

/// Decodes `body`, the body of a request of `session`: in the deterministic encoding of CBOR in a
/// TLS session, and in JSON in a plain-HTTP session.
pub fn decode<F: DeserializeOwned>(session: &Session, body: &[u8]) -> Result<F, ServerError> {
    if session.over_tls {
        Ok(cbor::from_slice(body)?)
    } else {
        Ok(serde_json::from_slice(body)?)
    }
}

/// A response with the body `form`, encoded for `session` as [`form_status_response`] encodes it.
pub fn form_response<F: Serialize>(
    session: &Session,
    form: F,
) -> Result<Response<Body>, ServerError> {
    form_status_response(session, form, StatusCode::OK)
}

/// A response with the status `status` and the body `form`, encoded for `session`: in a TLS
/// session, in the representation that its `Accept` chose, the deterministic encoding of CBOR of
/// a version of the API or the debug view, and in a plain-HTTP session in JSON, as clients that
/// predate TLS read it.
pub fn form_status_response<F: Serialize>(
    session: &Session,
    form: F,
    status: StatusCode,
) -> Result<Response<Body>, ServerError> {
    let (content_type, body) = match session.representation {
        Some(representation) => (representation.content_type(), representation.encode(&form)?),
        None => ("application/json".to_string(), serde_json::to_vec(&form)?),
    };
    Ok(Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(body))?)
}

/// A response of a public route of the TLS API, which needs no session, with the body `form`, in
/// `representation`, as [`util::negotiate`](negotiate) chose it.
pub fn represented_response<F: Serialize>(
    representation: Representation,
    form: F,
) -> Result<Response<Body>, ServerError> {
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, representation.content_type())
        .body(Body::from(representation.encode(&form)?))?)
}

pub fn status_response(status: StatusCode) -> Result<Response<Body>, ServerError> {
    Ok(Response::builder().status(status).body(Body::empty())?)
}
