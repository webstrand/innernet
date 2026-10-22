//! A table to describe which CIDRs another CIDR is allowed to peer with.
//!
//! A peer belongs to one parent CIDR, and can by default see all peers within that parent.

use std::collections::VecDeque;

use crate::{
    db::DatabaseAssociation,
    util::{form_body, form_response, status_response},
    ServerError, Session,
};
use hyper::{Body, Method, Request, Response, StatusCode};
use innernet_shared::{Association, Prefix};

/// Serves `/admin/associations`, in which a path names an association by the prefixes of its two
/// CIDRs, in either order, each as [`Prefix::api_path_segment`] writes it:
/// `/admin/associations/{cidr}/{cidr}`.
pub async fn routes(
    req: Request<Body>,
    components: VecDeque<String>,
    session: Session,
) -> Result<Response<Body>, ServerError> {
    let prefixes = components
        .iter()
        .map(|segment| Prefix::from_api_path_segment(segment).ok_or(ServerError::NotFound))
        .collect::<Result<Vec<_>, _>>()?;
    match (req.method(), &prefixes[..]) {
        (&Method::GET, []) => handlers::list(session).await,
        (&Method::POST, []) => {
            let form = form_body(req, &session).await?;
            handlers::create(form, session).await
        },
        // A pair of prefixes that no association joins is refused as such, apart from a path
        // that the server has no route for.
        (&Method::DELETE, [a, b]) => handlers::delete(a, b, session)
            .await
            .map_err(|e| e.not_found_as(ServerError::NoSuchAssociation)),
        _ => Err(ServerError::NotFound),
    }
}

mod handlers {
    use super::*;

    pub async fn create(
        contents: Association,
        session: Session,
    ) -> Result<Response<Body>, ServerError> {
        let store = session.context.db.lock();

        DatabaseAssociation::create(&store, contents.cidr_1, contents.cidr_2)?;

        status_response(StatusCode::CREATED)
    }

    pub async fn list(session: Session) -> Result<Response<Body>, ServerError> {
        let store = session.context.db.lock();
        let auths: Vec<_> = DatabaseAssociation::list(&store)?
            .iter()
            .map(DatabaseAssociation::contents)
            .collect();

        form_response(&session, auths)
    }

    pub async fn delete(
        a: &Prefix,
        b: &Prefix,
        session: Session,
    ) -> Result<Response<Body>, ServerError> {
        let store = session.context.db.lock();
        DatabaseAssociation::delete(&store, a, b)?;

        status_response(StatusCode::NO_CONTENT)
    }
}
