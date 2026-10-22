use std::convert::TryFrom;

use hyper::{header, http, Body, Response, StatusCode};
use innernet_shared::{
    cbor, media_type,
    problem::{self, Problem, ProblemType},
    Prefix,
};
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
        "this peer must connect over TLS, which requires a version of innernet that speaks \
         TLS"
    )]
    TlsRequired,

    #[error(
        "only peers that have connected over TLS can be made admins; the peer must first run \
         'innernet fetch' with a version of innernet that speaks TLS"
    )]
    PromotionRequiresTls,

    #[error(
        "the peer has changed since it was read, so the change was not made; the admin client \
         must read the peer again before it changes the peer"
    )]
    PeerChanged,

    #[error(
        "the CIDR has changed since it was read, so the change was not made; the admin client \
         must read the CIDR again before it changes the CIDR"
    )]
    CidrChanged,

    /// A change of a tagged resource, in a TLS session, without a tag.
    #[error("the change carries no tag; the admin client must read the resource for its tag")]
    TagMissing,

    /// No peer has the public key that the path of a TLS session names.
    #[error("no peer has this public key")]
    NoSuchPeer,

    /// No CIDR has the prefix that the path of a TLS session names.
    #[error("no CIDR has this prefix")]
    NoSuchCidr,

    /// No association joins the CIDRs that the path of a TLS session names.
    #[error("no association joins these CIDRs")]
    NoSuchAssociation,

    /// Delegations that break the rules of delegations, with the explanation.
    #[error("{0}")]
    Delegation(String),

    /// A delegation, `prefix`, that overlaps `held`, which the peer with the public key `holder`,
    /// in base64, holds, with the explanation.
    #[error("{reason}")]
    DelegationTaken {
        reason: String,
        prefix: Prefix,
        held: Prefix,
        holder: String,
    },

    #[error("internal database error")]
    Database(#[from] rusqlite::Error),

    #[error("internal WireGuard error")]
    WireGuard,

    #[error("internal I/O error")]
    Io(#[from] std::io::Error),

    #[error("JSON parsing/serialization error")]
    Json(#[from] serde_json::Error),

    #[error("CBOR parsing/serialization error")]
    Cbor(#[from] innernet_shared::cbor::Error),

    /// A request of a TLS session whose content type is not that of a version of the API that the
    /// server reads, or that reads a body without a content type.
    #[error("unsupported media type")]
    UnsupportedMediaType,

    /// A request of a TLS session that accepts no version of the API that the server writes, or a
    /// change that names no version in `Accept`.
    #[error("not acceptable")]
    NotAcceptable,

    /// A request of a TLS session that states a content type but carries no body, which is no
    /// CBOR.
    #[error("the request states a content type but carries no body")]
    EmptyBody,

    #[error("Generic HTTP error")]
    Http(#[from] http::Error),

    #[error("Generic Hyper error")]
    Hyper(#[from] hyper::Error),
}

impl ServerError {
    /// The error `self`, but `error` if `self` is that of something not found, as a database
    /// lookup reports it, so that a TLS session is told what wasn't found.
    pub fn not_found_as(self, error: ServerError) -> ServerError {
        match self {
            ServerError::NotFound | ServerError::Database(rusqlite::Error::QueryReturnedNoRows) => {
                error
            },
            e => e,
        }
    }

    /// The type of problem of innernet's own that the error is, or `None` for an error without
    /// a meaning of innernet's own, which is of the type `about:blank`.
    fn problem_type(&self) -> Option<&'static ProblemType> {
        use ServerError::*;
        Some(match self {
            TlsRequired => &problem::TLS_REQUIRED,
            PromotionRequiresTls => &problem::PROMOTION_REQUIRES_TLS,
            PeerChanged => &problem::PEER_CHANGED,
            CidrChanged => &problem::CIDR_CHANGED,
            TagMissing => &problem::TAG_MISSING,
            NoSuchPeer => &problem::NO_SUCH_PEER,
            NoSuchCidr => &problem::NO_SUCH_CIDR,
            NoSuchAssociation => &problem::NO_SUCH_ASSOCIATION,
            Delegation(_) | DelegationTaken { .. } => &problem::DELEGATION_REFUSED,
            Unauthorized | NotFound | InvalidQuery | Gone | Database(_) | WireGuard | Io(_)
            | Json(_) | Cbor(_) | UnsupportedMediaType | NotAcceptable | EmptyBody | Http(_)
            | Hyper(_) => return None,
        })
    }

    /// The error as a problem detail, as the API of TLS sessions answers it. An error of
    /// innernet's own is explained in `detail`; any other is of the type `about:blank`, with the
    /// reason phrase of its status as its title, and nothing else, so that nothing internal leaks.
    pub fn problem(&self) -> Problem {
        let status = StatusCode::from(self);
        let Some(problem_type) = self.problem_type() else {
            return Problem::about_blank(status.as_u16(), status.canonical_reason());
        };
        let mut problem = problem_type.problem(self.to_string());
        if let ServerError::DelegationTaken {
            prefix,
            held,
            holder,
            ..
        } = self
        {
            problem.prefix = Some(*prefix);
            problem.held = Some(*held);
            problem.holder = Some(holder.clone());
        }
        problem
    }

    /// The response to the error in a TLS session: its problem detail, in CBOR, or in the debug
    /// view of the version `debug_view`, for a request that chose the debug view.
    pub fn problem_response(self, debug_view: Option<u32>) -> Result<Response<Body>, http::Error> {
        let problem = self.problem();
        let (content_type, body) = match debug_view {
            Some(version) => (
                problem::DIAGNOSTIC_CONTENT_TYPE,
                media_type::to_diagnostic(version, &problem).map(String::into_bytes),
            ),
            None => (problem::CONTENT_TYPE, cbor::to_vec(&problem)),
        };
        Response::builder()
            .status(StatusCode::from(&self))
            .header(header::CONTENT_TYPE, content_type)
            .body(body.expect("a problem detail is encodable").into())
    }
}

impl From<&ServerError> for StatusCode {
    fn from(error: &ServerError) -> StatusCode {
        use ServerError::*;
        match error {
            Unauthorized | TlsRequired => StatusCode::UNAUTHORIZED,
            PromotionRequiresTls | Delegation(_) | DelegationTaken { .. } => {
                StatusCode::UNPROCESSABLE_ENTITY
            },
            NotFound | NoSuchPeer | NoSuchCidr | NoSuchAssociation => StatusCode::NOT_FOUND,
            Gone => StatusCode::GONE,
            PeerChanged | CidrChanged => StatusCode::CONFLICT,
            InvalidQuery | TagMissing | Json(_) | Cbor(_) => StatusCode::BAD_REQUEST,
            UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            NotAcceptable => StatusCode::NOT_ACCEPTABLE,
            EmptyBody => StatusCode::BAD_REQUEST,
            // Special-case the constraint violation situation.
            Database(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error { code, .. }, ..))
                if *code == rusqlite::ErrorCode::ConstraintViolation =>
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

    /// The response to the error in a plain-HTTP session, as clients that predate TLS read it.
    fn try_from(e: ServerError) -> Result<Self, Self::Error> {
        // The server explains the errors that an outdated client can't make sense of on its own.
        let body = match e {
            ServerError::TlsRequired
            | ServerError::PromotionRequiresTls
            | ServerError::PeerChanged
            | ServerError::CidrChanged
            | ServerError::Delegation(_)
            | ServerError::DelegationTaken { .. } => e.to_string().into(),
            _ => Body::empty(),
        };
        Response::builder().status(StatusCode::from(&e)).body(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_problems_have_the_status_of_their_type() {
        let key = wireguard_control::Key([7; 32]).to_base64();
        let prefix: Prefix = "10.0.0.0/30".parse().unwrap();
        for error in [
            ServerError::TlsRequired,
            ServerError::PromotionRequiresTls,
            ServerError::PeerChanged,
            ServerError::CidrChanged,
            ServerError::TagMissing,
            ServerError::NoSuchPeer,
            ServerError::NoSuchCidr,
            ServerError::NoSuchAssociation,
            ServerError::Delegation("no".into()),
            ServerError::DelegationTaken {
                reason: "taken".into(),
                prefix,
                held: prefix,
                holder: key.clone(),
            },
        ] {
            let problem_type = error.problem_type().unwrap();
            let problem = error.problem();
            assert!(problem.is(problem_type), "{error:?}");
            assert_eq!(problem.title.as_deref(), Some(problem_type.title));
            assert_eq!(problem.detail, Some(error.to_string()));
            assert_eq!(problem.status, Some(problem_type.status));
            assert_eq!(StatusCode::from(&error).as_u16(), problem_type.status);
        }

        // Other errors are of the type about:blank, and say nothing but their status.
        for error in [
            ServerError::Unauthorized,
            ServerError::NotFound,
            ServerError::InvalidQuery,
            ServerError::UnsupportedMediaType,
            ServerError::WireGuard,
            ServerError::Database(rusqlite::Error::InvalidQuery),
        ] {
            let status = StatusCode::from(&error);
            assert_eq!(
                error.problem(),
                Problem::about_blank(status.as_u16(), status.canonical_reason()),
                "{error:?}"
            );
        }
    }
}
