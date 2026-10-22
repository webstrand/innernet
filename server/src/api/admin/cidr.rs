use std::collections::VecDeque;

use crate::{
    db::DatabaseCidr,
    util::{form_body, json_response, status_response},
    ServerError, Session,
};
use hyper::{Body, Method, Request, Response, StatusCode};
use innernet_shared::{Cidr, CidrDeletion, Prefix, TaggedCidr};
use rusqlite::Connection;

/// Serves `/admin/cidrs`, in which a path names a CIDR by its prefix, as
/// [`Prefix::api_path_segment`] writes it.
pub async fn routes(
    req: Request<Body>,
    mut components: VecDeque<String>,
    session: Session,
) -> Result<Response<Body>, ServerError> {
    let prefix = components
        .pop_front()
        .map(|segment| Prefix::from_api_path_segment(&segment).ok_or(ServerError::NotFound))
        .transpose()?;
    if !components.is_empty() {
        return Err(ServerError::NotFound);
    }
    match (req.method(), prefix) {
        (&Method::GET, None) => handlers::list(session).await,
        (&Method::POST, None) => {
            let form = form_body(req).await?;
            handlers::create(form, session).await
        },
        (&Method::GET, Some(prefix)) => handlers::get(prefix, session).await,
        (&Method::PUT, Some(prefix)) => {
            let form = form_body(req).await?;
            handlers::update(prefix, form, session).await
        },
        (&Method::DELETE, Some(prefix)) => {
            let form = form_body(req).await?;
            handlers::delete(prefix, form, session).await
        },
        _ => Err(ServerError::NotFound),
    }
}

/// The tag of a CIDR: that of its name and prefix, computed as the tags of peers are.
fn cidr_tag(cidr: &Cidr) -> Result<String, ServerError> {
    super::peer::tag("cidr", cidr)
}

/// The CIDR `prefix`, if its tag is still `tag`. A CIDR that has changed since it was tagged is
/// refused as [`ServerError::CidrChanged`], and one that doesn't exist is not found.
fn get_unchanged(
    conn: &Connection,
    prefix: &Prefix,
    tag: &str,
) -> Result<DatabaseCidr, ServerError> {
    let cidr = DatabaseCidr::get(conn, prefix)?;
    if cidr_tag(&cidr.contents())? != tag {
        return Err(ServerError::CidrChanged);
    }
    Ok(cidr)
}

mod handlers {
    use crate::util::json_status_response;

    use super::*;

    /// Creates the CIDR `contents`, under the parent that its prefix gives it.
    pub async fn create(contents: Cidr, session: Session) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();

        let cidr = DatabaseCidr::create(&conn, contents.name, contents.cidr)?;

        json_status_response(cidr.contents(), StatusCode::CREATED)
    }

    /// The CIDR `prefix`, with its tag.
    pub async fn get(prefix: Prefix, session: Session) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        let cidr = DatabaseCidr::get(&conn, &prefix)?.contents();
        let tag = cidr_tag(&cidr)?;
        json_response(TaggedCidr { cidr, tag })
    }

    /// Renames the CIDR `prefix` to the name of `form`, which names the CIDR by its prefix too,
    /// if the CIDR hasn't changed since the admin read it with the tag that `form` carries.
    /// Nothing else of a CIDR changes, so a `form` with another prefix is refused.
    pub async fn update(
        prefix: Prefix,
        form: TaggedCidr,
        session: Session,
    ) -> Result<Response<Body>, ServerError> {
        if form.cidr.cidr != prefix {
            log::warn!("tried to move the CIDR {prefix} to {}.", form.cidr.cidr);
            return Err(ServerError::InvalidQuery);
        }
        let conn = session.context.db.lock();
        let mut cidr = get_unchanged(&conn, &prefix, &form.tag)?;
        cidr.rename(&conn, form.cidr.name)?;

        status_response(StatusCode::NO_CONTENT)
    }

    pub async fn list(session: Session) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        let cidrs: Vec<_> = DatabaseCidr::list(&conn)?
            .iter()
            .map(DatabaseCidr::contents)
            .collect();

        json_response(cidrs)
    }

    /// Deletes the CIDR `prefix`, if the CIDR hasn't changed since the admin read it with the tag
    /// that the request carries. Only a CIDR without peers and without children is deleted.
    pub async fn delete(
        prefix: Prefix,
        form: CidrDeletion,
        session: Session,
    ) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        get_unchanged(&conn, &prefix, &form.tag)?;
        DatabaseCidr::delete(&conn, &prefix)?;

        status_response(StatusCode::NO_CONTENT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test, DatabasePeer};
    use anyhow::Result;
    use innernet_shared::{Error, LegacyCidr};
    use serde::de::{DeserializeOwned, IgnoredAny};
    use std::collections::BTreeMap;

    /// The CIDR named `name` at `cidr`.
    fn cidr(name: &str, cidr: &str) -> Result<Cidr, Error> {
        Ok(Cidr {
            name: name.to_string(),
            cidr: cidr.parse()?,
        })
    }

    /// The path of the CIDR `cidr` in the API of TLS sessions.
    fn path(cidr: &str) -> Result<String, Error> {
        Ok(format!(
            "/v1/admin/cidrs/{}",
            cidr.parse::<Prefix>()?.api_path_segment()
        ))
    }

    /// The body of `res`, decoded from JSON.
    async fn json_body<T: DeserializeOwned>(res: Response<Body>) -> Result<T, Error> {
        let body = hyper::body::to_bytes(res.into_body()).await?;
        Ok(serde_json::from_slice(&body)?)
    }

    /// Reads the CIDR `cidr` with its tag, as the admin.
    async fn get_tagged(server: &test::Server, cidr: &str) -> Result<TaggedCidr, Error> {
        let res = server
            .request(test::ADMIN_PEER_IP, "GET", &path(cidr)?)
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        json_body(res).await
    }

    /// Sends `body` to rename the CIDR at `path`, as the admin.
    async fn put(server: &test::Server, path: &str, body: impl serde::Serialize) -> Response<Body> {
        server
            .form_request(test::ADMIN_PEER_IP, "PUT", path, body)
            .await
    }

    /// Deletes the CIDR `cidr` as the admin, with the tag `tag`.
    async fn delete_tagged(server: &test::Server, cidr: &str, tag: &str) -> Result<StatusCode> {
        let deletion = CidrDeletion { tag: tag.into() };
        let res = server
            .form_request(test::ADMIN_PEER_IP, "DELETE", &path(cidr)?, &deletion)
            .await;
        Ok(res.status())
    }

    /// Deletes the CIDR `cidr` as the admin, with its current tag.
    async fn delete_current(server: &test::Server, cidr: &str) -> Result<StatusCode> {
        let tag = get_tagged(server, cidr).await?.tag;
        delete_tagged(server, cidr, &tag).await
    }

    #[tokio::test]
    async fn test_cidr_add() -> Result<(), Error> {
        let server = test::Server::new()?;

        let old_cidrs = DatabaseCidr::list(&server.db().lock())?;

        let contents = cidr("experimental", test::EXPERIMENTAL_CIDR)?;

        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/cidrs", &contents)
            .await;

        assert_eq!(res.status(), 201);

        let cidr_res: Cidr = json_body(res).await?;
        assert_eq!(contents, cidr_res);

        let new_cidrs = DatabaseCidr::list(&server.db().lock())?;
        assert_eq!(old_cidrs.len() + 1, new_cidrs.len());

        // The CIDR is listed without an ID or a parent, and is found by its prefix.
        let res = server
            .request(test::ADMIN_PEER_IP, "GET", "/v1/admin/cidrs")
            .await;
        let body = hyper::body::to_bytes(res.into_body()).await?;
        let listed: Vec<Cidr> = serde_json::from_slice(&body)?;
        assert!(listed.contains(&contents));
        let fields: Vec<BTreeMap<String, IgnoredAny>> = serde_json::from_slice(&body)?;
        assert!(fields
            .iter()
            .all(|cidr| cidr.keys().eq(["cidr", "name"].iter())));

        // A misaligned prefix is refused.
        let misaligned = serde_json::json!({ "name": "loose", "cidr": "10.80.2.5/24" });
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/cidrs", misaligned)
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        Ok(())
    }

    #[tokio::test]
    async fn test_cidr_name_uniqueness() -> Result<(), Error> {
        let server = test::Server::new()?;

        let contents = cidr("experimental", test::EXPERIMENTAL_CIDR)?;
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/cidrs", &contents)
            .await;
        assert!(res.status().is_success());

        let contents = cidr("experimental", test::EXPERIMENTAL_SUBCIDR)?;
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/cidrs", &contents)
            .await;
        assert!(!res.status().is_success());

        Ok(())
    }

    #[tokio::test]
    async fn test_cidr_create_auth() -> Result<(), Error> {
        let server = test::Server::new()?;

        let contents = cidr("experimental", test::EXPERIMENTAL_CIDR)?;

        let res = server
            .form_request(test::USER1_PEER_IP, "POST", "/v1/admin/cidrs", &contents)
            .await;
        assert!(!res.status().is_success());

        Ok(())
    }

    #[tokio::test]
    async fn test_cidr_legacy_view() -> Result<(), Error> {
        // The view of plain-HTTP sessions, as a client that predates TLS reads it in its state,
        // names each CIDR and its parent by ID.
        let server = test::Server::new()?;
        let res = server
            .form_request(
                test::ADMIN_PEER_IP,
                "POST",
                "/v1/admin/cidrs",
                cidr("experimental", test::EXPERIMENTAL_CIDR)?,
            )
            .await;
        assert_eq!(res.status(), StatusCode::CREATED);

        let cidrs = DatabaseCidr::list(&server.db().lock())?;
        let listed: Vec<LegacyCidr> = cidrs.iter().map(|cidr| cidr.legacy(&cidrs)).collect();
        assert_eq!(
            listed
                .iter()
                .find(|cidr| cidr.name == "experimental")
                .map(|cidr| cidr.parent),
            Some(Some(test::ROOT_CIDR_ID))
        );
        assert_eq!(
            listed
                .iter()
                .find(|cidr| cidr.name == "developer")
                .map(|cidr| (cidr.id, cidr.parent)),
            Some((test::DEVELOPER_CIDR_ID, Some(test::ROOT_CIDR_ID)))
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_cidr_overlap() -> Result<(), Error> {
        let server = test::Server::new()?;

        // A new CIDR that would hold the admin CIDR is refused.
        let holding = if cfg!(feature = "v6-test") {
            "fd00:1337::/78"
        } else {
            "10.80.0.0/21"
        };
        let contents = cidr("experimental", holding)?;
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/cidrs", &contents)
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        Ok(())
    }

    #[tokio::test]
    async fn test_cidr_rename_by_prefix() -> Result<(), Error> {
        let server = test::Server::new()?;
        let developer_path = path(test::DEVELOPER_CIDR)?;
        let seen = get_tagged(&server, test::DEVELOPER_CIDR).await?;
        assert_eq!(seen.cidr, cidr("developer", test::DEVELOPER_CIDR)?);
        assert_eq!(
            get_tagged(&server, test::DEVELOPER_CIDR).await?.tag,
            seen.tag
        );
        let rename = |name: &str, prefix: &str, tag: &str| -> Result<TaggedCidr, Error> {
            Ok(TaggedCidr {
                cidr: cidr(name, prefix)?,
                tag: tag.into(),
            })
        };
        let renamed = rename("devs", test::DEVELOPER_CIDR, &seen.tag)?;
        let res = put(&server, &developer_path, &renamed).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        let stored = DatabaseCidr::get(&server.db.lock(), &renamed.cidr.cidr)?;
        assert_eq!(stored.name, "devs");
        assert_eq!(
            test::cidr_id(&server.db.lock(), &stored),
            test::DEVELOPER_CIDR_ID
        );
        let current = get_tagged(&server, test::DEVELOPER_CIDR).await?;
        assert_eq!(current.cidr, renamed.cidr);
        assert_ne!(current.tag, seen.tag);

        // A rename based on what was read before another is refused, with an explanation, and a
        // rename must carry a tag.
        let stale = rename("devs2", test::DEVELOPER_CIDR, &seen.tag)?;
        let res = put(&server, &developer_path, &stale).await;
        assert_eq!(res.status(), StatusCode::CONFLICT);
        let body = hyper::body::to_bytes(res.into_body()).await?;
        assert!(String::from_utf8_lossy(&body).contains("changed"));
        for untagged in [
            serde_json::to_value(&stale.cidr)?,
            serde_json::json!({ "cidr": stale.cidr }),
        ] {
            let res = put(&server, &developer_path, untagged).await;
            assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        }
        assert_eq!(get_tagged(&server, test::DEVELOPER_CIDR).await?, current);

        // A non-admin can't.
        let res = server
            .form_request(
                test::DEVELOPER1_PEER_IP,
                "PUT",
                &developer_path,
                rename("devs2", test::DEVELOPER_CIDR, &current.tag)?,
            )
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // A CIDR is never moved, and one that doesn't exist is not found, as is a path that names
        // no prefix in the canonical form.
        let moved = rename("devs", test::EXPERIMENTAL_CIDR, &current.tag)?;
        let res = put(&server, &developer_path, &moved).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let res = put(&server, &path(test::EXPERIMENTAL_CIDR)?, &moved).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        for path in [
            format!("/v1/admin/cidrs/{}", test::DEVELOPER_CIDR_ID),
            format!("/v1/admin/cidrs/{}", test::DEVELOPER_CIDR),
            format!("/v1/admin/cidrs/{}", test::DEVELOPER_CIDR.replace('/', "-")),
        ] {
            let res = put(&server, &path, &current).await;
            assert_eq!(res.status(), StatusCode::NOT_FOUND, "{path}");
            let res = server.request(test::ADMIN_PEER_IP, "GET", &path).await;
            assert_eq!(res.status(), StatusCode::NOT_FOUND, "{path}");
        }
        Ok(())
    }

    #[test]
    fn test_cidr_tags_depend_only_on_state() -> Result<(), Error> {
        // A tag is a hash of the CIDR's name and prefix, and of nothing else.
        let developer = cidr("developer", test::DEVELOPER_CIDR)?;
        let tag = cidr_tag(&developer)?;
        assert_eq!(cidr_tag(&developer.clone())?, tag);
        assert_ne!(cidr_tag(&cidr("devs", test::DEVELOPER_CIDR)?)?, tag);
        assert_ne!(cidr_tag(&cidr("developer", test::EXPERIMENTAL_CIDR)?)?, tag);
        Ok(())
    }

    #[tokio::test]
    async fn test_cidr_delete_by_tag() -> Result<(), Error> {
        let server = test::Server::new()?;
        DatabaseCidr::create(
            &server.db().lock(),
            "experimental".to_string(),
            test::EXPERIMENTAL_CIDR.parse()?,
        )?;
        let seen = get_tagged(&server, test::EXPERIMENTAL_CIDR).await?;

        // Once the CIDR is renamed, a deletion based on what was read before is refused.
        let prefix: Prefix = test::EXPERIMENTAL_CIDR.parse()?;
        {
            let store = server.db.lock();
            DatabaseCidr::get(&store, &prefix)?.rename(&store, "lab".into())?;
        }
        assert_eq!(
            delete_tagged(&server, test::EXPERIMENTAL_CIDR, &seen.tag).await?,
            StatusCode::CONFLICT
        );

        // A deletion must carry a tag, and a non-admin can't.
        let current = get_tagged(&server, test::EXPERIMENTAL_CIDR).await?;
        let experimental_path = path(test::EXPERIMENTAL_CIDR)?;
        let res = server
            .request(test::ADMIN_PEER_IP, "DELETE", &experimental_path)
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let res = server
            .form_request(
                test::ADMIN_PEER_IP,
                "DELETE",
                &experimental_path,
                serde_json::json!({}),
            )
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let res = server
            .form_request(
                test::DEVELOPER1_PEER_IP,
                "DELETE",
                &experimental_path,
                CidrDeletion {
                    tag: current.tag.clone(),
                },
            )
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert!(DatabaseCidr::get(&server.db.lock(), &prefix).is_ok());

        // With the current tag, the CIDR is deleted, and is then not found.
        assert_eq!(
            delete_tagged(&server, test::EXPERIMENTAL_CIDR, &current.tag).await?,
            StatusCode::NO_CONTENT
        );
        assert!(DatabaseCidr::get(&server.db.lock(), &prefix).is_err());
        assert_eq!(
            delete_tagged(&server, test::EXPERIMENTAL_CIDR, &current.tag).await?,
            StatusCode::NOT_FOUND
        );
        Ok(())
    }

    #[test]
    fn test_cidrs_with_peers_get_no_children() -> Result<(), Error> {
        // Peers belong only to CIDRs without children, so a CIDR that holds the delegations of
        // a peer gets no child CIDR, and a new CIDR holds no other.
        let server = test::Server::new()?;
        let store = server.db.lock();
        let (child, holding) = if cfg!(feature = "v6-test") {
            ("fd00:1337::2:0:0:0/96", "fd00:1337::2:0:0:0/79")
        } else {
            ("10.80.64.128/25", "10.80.64.0/23")
        };
        let before = DatabaseCidr::list(&store)?;
        for prefix in [child, holding, test::DEVELOPER_CIDR] {
            let created = DatabaseCidr::create(&store, "new".into(), prefix.parse()?);
            assert!(
                matches!(created, Err(ServerError::InvalidQuery)),
                "{prefix}: {created:?}"
            );
        }
        assert_eq!(DatabaseCidr::list(&store)?, before);

        // Once the CIDR has no peer, it may get a child.
        let developer: Prefix = test::DEVELOPER_CIDR.parse()?;
        store.execute(
            "DELETE FROM delegations WHERE length(address) = length(?1)
               AND address >= ?1 AND last <= ?2",
            rusqlite::params![
                innernet_node::store::ip_to_bytes(developer.first()),
                innernet_node::store::ip_to_bytes(developer.last()),
            ],
        )?;
        let created = DatabaseCidr::create(&store, "new".into(), child.parse()?)?;
        let cidrs = DatabaseCidr::list(&store)?;
        assert_eq!(created.legacy(&cidrs).parent, Some(test::DEVELOPER_CIDR_ID));
        Ok(())
    }

    #[tokio::test]
    async fn test_cidr_delete_fail_with_child_cidr() -> Result<(), Error> {
        let server = test::Server::new()?;

        DatabaseCidr::create(
            &server.db().lock(),
            "experimental".to_string(),
            test::EXPERIMENTAL_CIDR.parse()?,
        )?;
        DatabaseCidr::create(
            &server.db().lock(),
            "experimental subcidr".to_string(),
            test::EXPERIMENTAL_SUBCIDR.parse()?,
        )?;

        let tag = get_tagged(&server, test::EXPERIMENTAL_CIDR).await?.tag;
        let status = delete_tagged(&server, test::EXPERIMENTAL_CIDR, &tag).await?;
        // Should fail because child CIDR exists.
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let status = delete_current(&server, test::EXPERIMENTAL_SUBCIDR).await?;
        // Deleting the child "leaf" CIDR works, since no peer is inside it.
        assert_eq!(status, StatusCode::NO_CONTENT);

        let status = delete_tagged(&server, test::EXPERIMENTAL_CIDR, &tag).await?;
        // Now deleting parent CIDR should work because child is gone.
        assert_eq!(status, StatusCode::NO_CONTENT);

        // A CIDR that doesn't exist is not found.
        let status = delete_tagged(&server, test::EXPERIMENTAL_CIDR, &tag).await?;
        assert_eq!(status, StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn test_cidr_delete_fail_with_peer_inside() -> Result<(), Error> {
        let server = test::Server::new()?;

        DatabaseCidr::create(
            &server.db().lock(),
            "experimental".to_string(),
            test::EXPERIMENTAL_CIDR.parse()?,
        )?;

        let _experiment_peer = DatabasePeer::create(
            &server.db().lock(),
            test::peer_contents("experiment-peer", test::EXPERIMENT_SUBCIDR_PEER_IP, false)?,
        )?;

        // Deleting CIDR should fail because peer exists inside it.
        assert_eq!(
            delete_current(&server, test::EXPERIMENTAL_CIDR).await?,
            StatusCode::BAD_REQUEST
        );

        Ok(())
    }
}
