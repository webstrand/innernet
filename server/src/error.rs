use std::convert::TryFrom;

use hyper::{http, Body, Response, StatusCode};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("unauthorized access")]
    Unauthorized,

    #[error("object not found")]
    NotFound,

    #[error("invalid query")]
    InvalidQuery,

    #[error("endpoint gone")]
    Gone,

    #[error(
        "this peer has connected over TLS before, so it must always do so; upgrade innernet \
         to connect"
    )]
    TlsRequired,

    #[error(
        "only peers that have connected over TLS can be made admins; upgrade innernet on the \
         peer and run 'innernet fetch' first"
    )]
    PromotionRequiresTls,

    #[error("the peer has changed since it was read; read it again before changing it")]
    PreconditionFailed,

    #[error("internal database error")]
    Database(#[from] rusqlite::Error),

    #[error("internal WireGuard error")]
    WireGuard,

    #[error("internal I/O error")]
    Io(#[from] std::io::Error),

    #[error("JSON parsing/serialization error")]
    Json(#[from] serde_json::Error),

    #[error("Generic HTTP error")]
    Http(#[from] http::Error),

    #[error("Generic Hyper error")]
    Hyper(#[from] hyper::Error),
}

impl From<&ServerError> for StatusCode {
    fn from(error: &ServerError) -> StatusCode {
        use ServerError::*;
        match error {
            Unauthorized | TlsRequired => StatusCode::UNAUTHORIZED,
            PromotionRequiresTls => StatusCode::UNPROCESSABLE_ENTITY,
            NotFound => StatusCode::NOT_FOUND,
            Gone => StatusCode::GONE,
            PreconditionFailed => StatusCode::PRECONDITION_FAILED,
            InvalidQuery | Json(_) => StatusCode::BAD_REQUEST,
            // Special-case the constraint violation situation.
            Database(rusqlite::Error::SqliteFailure(libsqlite3_sys::Error { code, .. }, ..))
                if *code == libsqlite3_sys::ErrorCode::ConstraintViolation =>
            {
                StatusCode::BAD_REQUEST
            },
            Database(rusqlite::Error::QueryReturnedNoRows) => StatusCode::NOT_FOUND,
            WireGuard | Io(_) | Database(_) | Http(_) | Hyper(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            },
        }
    }
}

impl TryFrom<ServerError> for Response<Body> {
    type Error = http::Error;

    fn try_from(e: ServerError) -> Result<Self, Self::Error> {
        // Explain the errors that an outdated client can't make sense of on its own.
        let body = match e {
            ServerError::TlsRequired
            | ServerError::PromotionRequiresTls
            | ServerError::PreconditionFailed => e.to_string().into(),
            _ => Body::empty(),
        };
        Response::builder().status(StatusCode::from(&e)).body(body)
    }
}
