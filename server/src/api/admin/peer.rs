use std::collections::VecDeque;

use crate::{
    api::inject_endpoints,
    db::DatabasePeer,
    util::{form_body, json_response, json_status_response, status_response},
    ServerError, Session,
};
use hyper::{Body, Method, Request, Response, StatusCode};
use innernet_shared::{PeerContents, PeerEndpoints, PeerUpdate, TaggedPeer, TaggedPeerEndpoints};
use rusqlite::Connection;
use serde::Serialize;
use sha2::{Digest, Sha512};
use wireguard_control::Key;

/// Serves `/admin/peers`, in which a path names a peer by its public key only, as
/// [`PeerContents::api_path_segment`] encodes it. Any other path under a peer is not found.
pub async fn routes(
    req: Request<Body>,
    mut components: VecDeque<String>,
    session: Session,
) -> Result<Response<Body>, ServerError> {
    let peer = components.pop_front();
    let resource = components.pop_front();
    if !components.is_empty() {
        return Err(ServerError::NotFound);
    }
    let key = peer.as_deref().map(parse_path_key).transpose()?;
    match (req.method(), key, resource.as_deref()) {
        (&Method::GET, None, None) => handlers::list(session).await,
        (&Method::POST, None, None) => {
            let form = form_body(req).await?;
            handlers::create(form, session).await
        },
        (&Method::GET, Some(key), None) => handlers::get_by_key(key, session).await,
        (&Method::PUT, Some(key), None) => {
            let form = form_body(req).await?;
            handlers::update_by_key(key, form, session).await
        },
        (&Method::GET, Some(key), Some("endpoints")) => handlers::endpoints(key, session).await,
        (&Method::PUT, Some(key), Some("endpoints")) => {
            let form = form_body(req).await?;
            handlers::set_endpoints(key, form, session).await
        },
        _ => Err(ServerError::NotFound),
    }
}

/// Parses a path segment that names a peer by its public key in the URL-safe base64 alphabet,
/// padding included. Any other encoding of a key is not found.
fn parse_path_key(segment: &str) -> Result<Key, ServerError> {
    if segment.contains(['+', '/']) {
        return Err(ServerError::NotFound);
    }
    let base64 = segment.replace('-', "+").replace('_', "/");
    match Key::from_base64(&base64) {
        Ok(key) if key.to_base64() == base64 => Ok(key),
        _ => Err(ServerError::NotFound),
    }
}

/// The tag of `value`, a resource of a peer of the kind `kind`: a hash of the kind and the value,
/// and of nothing else, so that a tag depends only on the state that it was computed for. Clients
/// treat tags as opaque. The hash is SHA-512, which XEdDSA uses already, cut to 128 bits: a tag
/// only tells states apart, and needs no more resistance to collisions.
fn tag<T: Serialize>(kind: &str, value: &T) -> Result<String, ServerError> {
    let mut hasher = Sha512::new();
    hasher.update(kind.as_bytes());
    hasher.update([0]);
    hasher.update(serde_json::to_vec(value)?);
    let hash = hasher.finalize();
    Ok(hash[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// The tag of a peer: that of everything an admin reads of the peer, its public key included, but
/// its endpoint and candidates, which the peer reports on its own.
fn peer_tag(peer: &PeerContents) -> Result<String, ServerError> {
    let peer = PeerContents {
        endpoint: None,
        candidates: vec![],
        ..peer.clone()
    };
    tag("peer", &peer)
}

/// The endpoint and candidates stored for a peer.
fn peer_endpoints(peer: &PeerContents) -> PeerEndpoints {
    PeerEndpoints {
        endpoint: peer.endpoint.clone(),
        candidates: peer.candidates.clone(),
    }
}

/// The tag of a peer's endpoints: that of its public key, endpoint and candidates.
fn endpoints_tag(peer: &PeerContents) -> Result<String, ServerError> {
    tag("endpoints", &(&peer.public_key, peer_endpoints(peer)))
}

/// The peer with the public key `key`, if `tag_of` the peer is still `tag`. A peer that has
/// changed since it was tagged is refused as [`ServerError::PeerChanged`]. A peer whose key has
/// changed since, as a redeemed invitation's does, is not found, like a peer that never existed:
/// a tag doesn't identify the peer it was computed for.
fn get_unchanged(
    conn: &Connection,
    key: &Key,
    tag: &str,
    tag_of: impl Fn(&PeerContents) -> Result<String, ServerError>,
) -> Result<DatabasePeer, ServerError> {
    match DatabasePeer::get_from_public_key(conn, key) {
        Ok(peer) if tag_of(&peer)? == tag => Ok(peer),
        Ok(_) => Err(ServerError::PeerChanged),
        Err(rusqlite::Error::QueryReturnedNoRows) => Err(ServerError::NotFound),
        Err(e) => Err(e.into()),
    }
}

mod handlers {

    use super::*;

    pub async fn create(
        form: PeerContents,
        session: Session,
    ) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();

        let peer = DatabasePeer::create(&conn, form)?;
        log::info!("adding peer {}", *peer);
        session.context.changed.notify();
        if !peer.is_redeemed {
            session.context.invitations.notify_one();
        }

        json_status_response(&peer.inner, StatusCode::CREATED)
    }

    /// The peer with the public key `key` as the listing reports it, with its tag.
    pub async fn get_by_key(key: Key, session: Session) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        let mut peer = DatabasePeer::get_from_public_key(&conn, &key)?.inner;
        let tag = peer_tag(&peer)?;
        inject_endpoints(&session, [&mut peer]);
        json_response(TaggedPeer { peer, tag })
    }

    /// Applies an admin's changes to the peer with the public key `key`, if the peer hasn't
    /// changed since the admin read it with the tag that the changes carry.
    pub async fn update_by_key(
        key: Key,
        form: PeerUpdate,
        session: Session,
    ) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        let mut peer = get_unchanged(&conn, &key, &form.tag, peer_tag)?;
        let contents = PeerContents {
            name: form.name,
            is_admin: form.is_admin,
            is_disabled: form.is_disabled,
            ..peer.inner.clone()
        };
        peer.update(&conn, contents)?;
        // The update may have enabled or disabled the peer.
        session.context.changed.notify();

        status_response(StatusCode::NO_CONTENT)
    }

    /// The endpoint and candidates stored for the peer with the public key `key`, without the
    /// endpoint that the server observes, so that they can be written back as they are read, and
    /// their tag.
    pub async fn endpoints(key: Key, session: Session) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        let peer = DatabasePeer::get_from_public_key(&conn, &key)?;
        json_response(TaggedPeerEndpoints {
            endpoints: peer_endpoints(&peer),
            tag: endpoints_tag(&peer)?,
        })
    }

    /// Sets the endpoint and candidates of the peer with the public key `key` on its behalf, if
    /// they haven't changed since the admin read them with the tag that the request carries.
    pub async fn set_endpoints(
        key: Key,
        form: TaggedPeerEndpoints,
        session: Session,
    ) -> Result<Response<Body>, ServerError> {
        let PeerEndpoints {
            endpoint,
            candidates,
        } = form.endpoints;
        if candidates.len() > 10 {
            return status_response(StatusCode::PAYLOAD_TOO_LARGE);
        }
        let conn = session.context.db.lock();
        let mut peer = get_unchanged(&conn, &key, &form.tag, endpoints_tag)?;
        peer.set_endpoints(&conn, endpoint, candidates)?;
        log::info!("set the endpoints of peer {}", *peer);
        session.context.changed.notify();

        status_response(StatusCode::NO_CONTENT)
    }

    /// List all peers, including disabled ones, without IDs. This is an admin-only endpoint.
    pub async fn list(session: Session) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        let mut peers = DatabasePeer::list(&conn)?
            .into_iter()
            .map(|peer| peer.inner)
            .collect::<Vec<_>>();
        inject_endpoints(&session, &mut peers);
        json_response(&peers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test;
    use bytes::Buf;
    use innernet_shared::{Endpoint, Error};
    use wireguard_control::KeyPair;

    #[tokio::test]
    async fn test_add_peer() -> Result<(), Error> {
        let server = test::Server::new()?;

        let old_peers = DatabasePeer::list(&server.db().lock())?;

        let peer = if cfg!(feature = "v6-test") {
            test::developer_peer_contents("developer3", "fd00:1337::2:0:0:3")?
        } else {
            test::developer_peer_contents("developer3", "10.80.64.4")?
        };

        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/peers", &peer)
            .await;

        assert_eq!(res.status(), StatusCode::CREATED);
        // The response contains the new peer information.
        let whole_body = hyper::body::aggregate(res).await?;
        let peer_res: PeerContents = serde_json::from_reader(whole_body.reader())?;

        assert_eq!(peer, peer_res);

        // The number of peer entries in the database increased by 1.
        let new_peers = DatabasePeer::list(&server.db().lock())?;
        assert_eq!(old_peers.len() + 1, new_peers.len());

        Ok(())
    }

    #[tokio::test]
    async fn test_add_peer_with_invalid_name() -> Result<(), Error> {
        assert!(test::developer_peer_contents("devel oper", "10.80.64.4").is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_add_peer_with_duplicate_name() -> Result<(), Error> {
        let server = test::Server::new()?;

        let old_peers = DatabasePeer::list(&server.db().lock())?;

        // Try to add a peer with a name that is already taken.
        let peer = test::developer_peer_contents("developer2", "10.80.64.4")?;

        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/peers", &peer)
            .await;

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // The number of peer entries in the database should not change.
        let new_peers = DatabasePeer::list(&server.db().lock())?;
        assert_eq!(old_peers.len(), new_peers.len());

        Ok(())
    }

    #[tokio::test]
    async fn test_add_peer_with_duplicate_ip() -> Result<(), Error> {
        let server = test::Server::new()?;

        let old_peers = DatabasePeer::list(&server.db().lock())?;

        // Try to add a peer with an IP that is already taken.
        let peer = test::developer_peer_contents("developer3", "10.80.64.3")?;

        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/peers", &peer)
            .await;

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // The number of peer entries in the database should not change.
        let new_peers = DatabasePeer::list(&server.db().lock())?;
        assert_eq!(old_peers.len(), new_peers.len());

        Ok(())
    }

    #[tokio::test]
    async fn test_add_peer_with_outside_cidr_range_ip() -> Result<(), Error> {
        let server = test::Server::new()?;

        let old_peers = DatabasePeer::list(&server.db().lock())?;

        // Try to add IP outside of the CIDR network.
        let peer = test::developer_peer_contents("developer3", "10.80.65.4")?;
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/peers", &peer)
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // Try to use the network address as peer IP.
        let peer = test::developer_peer_contents("developer3", "10.80.64.0")?;
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/peers", &peer)
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // Try to use the broadcast address as peer IP.
        let peer = test::developer_peer_contents("developer3", "10.80.64.255")?;
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/peers", &peer)
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // The number of peer entries in the database should not change.
        let new_peers = DatabasePeer::list(&server.db().lock())?;
        assert_eq!(old_peers.len(), new_peers.len());

        Ok(())
    }

    #[tokio::test]
    async fn test_add_peer_to_cidr_with_children() -> Result<(), Error> {
        let server = test::Server::new()?;

        let old_peers = DatabasePeer::list(&server.db().lock())?;

        // The admin adds a peer to the root CIDR, at an IP that no child CIDR covers.
        let ip = if cfg!(feature = "v6-test") {
            "fd00:1337::5:0:0:1"
        } else {
            "10.80.2.1"
        };
        let peer = test::peer_contents("developer3", ip, test::ROOT_CIDR_ID, false)?;
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/peers", &peer)
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // The number of peer entries in the database should not change.
        let new_peers = DatabasePeer::list(&server.db().lock())?;
        assert_eq!(old_peers.len(), new_peers.len());

        Ok(())
    }

    #[tokio::test]
    async fn test_add_peer_from_non_admin() -> Result<(), Error> {
        let server = test::Server::new()?;

        let peer = test::developer_peer_contents("developer3", "10.80.64.4")?;

        // Try to create a new developer peer from a user peer.
        let res = server
            .form_request(test::USER1_PEER_IP, "POST", "/v1/admin/peers", &peer)
            .await;

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }

    fn peer(server: &test::Server, id: i64) -> DatabasePeer {
        test::peer(&server.db.lock(), id)
    }

    /// The path of the peer `id` in the API of TLS sessions.
    fn key_path(server: &test::Server, id: i64) -> String {
        format!("/v1/admin/peers/{}", peer(server, id).api_path_segment())
    }

    #[test]
    fn test_parse_path_key() {
        // A key whose standard base64 holds both '+' and '/'.
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_mut(3) {
            chunk.copy_from_slice(&[0xfb, 0xff, 0xbf][..chunk.len()]);
        }
        let key = Key(bytes);
        let contents = PeerContents {
            public_key: key.to_base64(),
            ..test::developer_peer_contents("peer", "10.80.64.9").unwrap()
        };
        let segment = contents.api_path_segment();
        assert!(contents.public_key.contains('+') && contents.public_key.contains('/'));
        assert!(!segment.contains(['+', '/']));
        assert_eq!(parse_path_key(&segment).unwrap(), key);

        // IDs, the standard alphabet, a missing padding and other text are not keys.
        for segment in [
            "12",
            &contents.public_key.replace('/', "_"),
            segment.trim_end_matches('='),
            "nonsense",
            "",
        ] {
            assert!(parse_path_key(segment).is_err(), "{segment}");
        }
    }

    /// Reads the peer at `path` with its tag, as the admin.
    async fn get_tagged(server: &test::Server, path: &str) -> TaggedPeer {
        let res = server.request(test::ADMIN_PEER_IP, "GET", path).await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = hyper::body::aggregate(res).await.unwrap();
        serde_json::from_reader(body.reader()).unwrap()
    }

    /// The changes that leave the peer at `path` as it is, with its current tag.
    async fn unchanged(server: &test::Server, path: &str) -> PeerUpdate {
        let TaggedPeer { peer, tag } = get_tagged(server, path).await;
        PeerUpdate::new(tag, &peer)
    }

    #[tokio::test]
    async fn test_update_peer_by_key() -> Result<(), Error> {
        let server = test::Server::new()?;
        let path = key_path(&server, test::DEVELOPER1_PEER_ID);
        let mut change = unchanged(&server, &path).await;
        change.name = "new-peer-name".parse().unwrap();
        change.is_disabled = true;

        let res = server
            .form_request(test::ADMIN_PEER_IP, "PUT", &path, &change)
            .await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let new_peer = peer(&server, test::DEVELOPER1_PEER_ID);
        assert_eq!(&*new_peer.name, "new-peer-name");
        assert!(new_peer.is_disabled);

        // A non-admin can't, and no other path under a peer is routed to it.
        let res = server
            .form_request(test::DEVELOPER2_PEER_IP, "PUT", &path, &change)
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let res = server
            .form_request(
                test::ADMIN_PEER_IP,
                "PUT",
                &format!("{path}/other"),
                &change,
            )
            .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        // An unknown key is not found, even with the tag of a peer that exists.
        let unknown = PeerContents {
            public_key: KeyPair::generate().public.to_base64(),
            ..new_peer.inner.clone()
        };
        let path = format!("/v1/admin/peers/{}", unknown.api_path_segment());
        let res = server.request(test::ADMIN_PEER_IP, "GET", &path).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let res = server
            .form_request(test::ADMIN_PEER_IP, "PUT", &path, &change)
            .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[test]
    fn test_tags_depend_only_on_state() -> Result<(), Error> {
        // A tag is a hash of the peer's state, and that state includes the key.
        let peer = test::developer_peer_contents("peer", "10.80.64.9")?;
        let tag = peer_tag(&peer)?;
        assert_eq!(tag.len(), 32);
        assert_eq!(peer_tag(&peer.clone())?, tag);
        let other_key = PeerContents {
            public_key: KeyPair::generate().public.to_base64(),
            ..peer.clone()
        };
        assert_ne!(peer_tag(&other_key)?, tag);
        let renamed = PeerContents {
            name: "renamed".parse().unwrap(),
            ..peer.clone()
        };
        assert_ne!(peer_tag(&renamed)?, tag);
        Ok(())
    }

    #[tokio::test]
    async fn test_tags() -> Result<(), Error> {
        let server = test::Server::new()?;
        let path = key_path(&server, test::DEVELOPER1_PEER_ID);
        let seen = get_tagged(&server, &path).await;
        assert_eq!(get_tagged(&server, &path).await.tag, seen.tag);
        assert_eq!(
            seen.peer.public_key,
            peer(&server, test::DEVELOPER1_PEER_ID).public_key
        );

        // The endpoint and candidates that the peer reports leave its tag unchanged.
        {
            let store = server.db.lock();
            let mut peer = test::peer(&store, test::DEVELOPER1_PEER_ID);
            peer.set_endpoint(&store, Some("198.51.100.1:51820".parse().unwrap()))?;
            peer.set_candidates(&store, vec!["198.51.100.2:51820".parse().unwrap()])?;
        }
        assert_eq!(get_tagged(&server, &path).await.tag, seen.tag);

        // A change by another admin turns away a change based on what was read before it.
        let rename = |name: &str| PeerUpdate {
            name: name.parse().unwrap(),
            ..PeerUpdate::new(seen.tag.clone(), &seen.peer)
        };
        let res = server
            .form_request(test::ADMIN_PEER_IP, "PUT", &path, rename("first"))
            .await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        let res = server
            .form_request(test::ADMIN_PEER_IP, "PUT", &path, rename("second"))
            .await;
        assert_eq!(res.status(), StatusCode::CONFLICT);
        let body = hyper::body::to_bytes(res.into_body()).await?;
        assert!(String::from_utf8_lossy(&body).contains("changed"));
        assert_eq!(&*peer(&server, test::DEVELOPER1_PEER_ID).name, "first");
        assert_ne!(get_tagged(&server, &path).await.tag, seen.tag);

        // A change must carry a tag.
        let untagged = serde_json::json!({
            "name": "third",
            "is_admin": false,
            "is_disabled": false,
        });
        let res = server
            .form_request(test::ADMIN_PEER_IP, "PUT", &path, untagged)
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(&*peer(&server, test::DEVELOPER1_PEER_ID).name, "first");
        Ok(())
    }

    #[tokio::test]
    async fn test_update_peer_keeps_endpoint() -> Result<(), Error> {
        let server = test::Server::new()?;
        let endpoint: Endpoint = "1.1.1.1:51820".parse().unwrap();
        let candidate: Endpoint = "192.168.0.2:51820".parse().unwrap();
        {
            let store = server.db.lock();
            let mut peer = test::peer(&store, test::DEVELOPER1_PEER_ID);
            peer.set_endpoint(&store, Some(endpoint.clone()))?;
            peer.set_candidates(&store, vec![candidate.clone()])?;
        }

        let path = key_path(&server, test::DEVELOPER1_PEER_ID);
        let mut change = unchanged(&server, &path).await;
        change.name = "new-peer-name".parse().unwrap();
        let res = server
            .form_request(test::ADMIN_PEER_IP, "PUT", &path, &change)
            .await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let new_peer = peer(&server, test::DEVELOPER1_PEER_ID);
        assert_eq!(&*new_peer.name, "new-peer-name");
        assert_eq!(new_peer.endpoint, Some(endpoint));
        assert_eq!(new_peer.candidates, vec![candidate]);
        Ok(())
    }

    #[tokio::test]
    async fn test_endpoints() -> Result<(), Error> {
        let server = test::Server::new()?;
        let peer_path = key_path(&server, test::DEVELOPER1_PEER_ID);
        let path = format!("{peer_path}/endpoints");
        let get = || async {
            let res = server.request(test::ADMIN_PEER_IP, "GET", &path).await;
            assert_eq!(res.status(), StatusCode::OK);
            let body = hyper::body::aggregate(res).await.unwrap();
            serde_json::from_reader::<_, TaggedPeerEndpoints>(body.reader()).unwrap()
        };
        let put = |endpoints: &TaggedPeerEndpoints| {
            server.form_request(test::ADMIN_PEER_IP, "PUT", &path, endpoints.clone())
        };

        // The server observes an endpoint for the peer, which isn't stored.
        let seen = get().await;
        assert_eq!(seen.endpoints, PeerEndpoints::default());
        let peer_tag = get_tagged(&server, &peer_path).await.tag;

        let endpoints = PeerEndpoints {
            endpoint: Some("198.51.100.1:51820".parse().unwrap()),
            candidates: vec!["198.51.100.2:51820".parse().unwrap()],
        };
        let change = TaggedPeerEndpoints {
            endpoints: endpoints.clone(),
            tag: seen.tag.clone(),
        };
        assert_eq!(put(&change).await.status(), StatusCode::NO_CONTENT);
        let stored = peer(&server, test::DEVELOPER1_PEER_ID);
        assert_eq!(stored.endpoint, endpoints.endpoint);
        assert_eq!(stored.candidates, endpoints.candidates);
        let current = get().await;
        assert_eq!(current.endpoints, endpoints);
        assert_ne!(current.tag, seen.tag);

        // The endpoints are tagged apart from the rest of the peer.
        assert_eq!(get_tagged(&server, &peer_path).await.tag, peer_tag);
        let mut rename = unchanged(&server, &peer_path).await;
        rename.name = "renamed".parse().unwrap();
        let res = server
            .form_request(test::ADMIN_PEER_IP, "PUT", &peer_path, &rename)
            .await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert_eq!(get().await.tag, current.tag);

        // A change based on endpoints read before the peer reported others is refused.
        let report = TaggedPeerEndpoints {
            endpoints: PeerEndpoints::default(),
            tag: current.tag.clone(),
        };
        {
            let store = server.db.lock();
            let mut peer = test::peer(&store, test::DEVELOPER1_PEER_ID);
            peer.set_candidates(&store, vec![])?;
        }
        assert_eq!(put(&report).await.status(), StatusCode::CONFLICT);

        // Non-admins can't, too many candidates are refused, and a tag is required.
        let current = get().await;
        let res = server
            .form_request(test::DEVELOPER1_PEER_IP, "PUT", &path, &current)
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let too_many = TaggedPeerEndpoints {
            endpoints: PeerEndpoints {
                endpoint: None,
                candidates: vec!["198.51.100.2:51820".parse().unwrap(); 11],
            },
            tag: current.tag.clone(),
        };
        assert_eq!(put(&too_many).await.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let untagged = serde_json::json!({ "endpoints": { "endpoint": null, "candidates": [] } });
        let res = server
            .form_request(test::ADMIN_PEER_IP, "PUT", &path, untagged)
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(get().await, current);

        // Any other path under a peer is not found, rather than routed to the peer itself, and
        // the endpoints are not reached by ID.
        let id_path = format!("/v1/admin/peers/{}/endpoints", test::DEVELOPER1_PEER_ID);
        for path in [
            format!("{peer_path}/other"),
            format!("{path}/other"),
            id_path.clone(),
        ] {
            for method in ["GET", "PUT", "DELETE"] {
                let res = server
                    .form_request(test::ADMIN_PEER_IP, method, &path, &current)
                    .await;
                assert_eq!(res.status(), StatusCode::NOT_FOUND, "{method} {path}");
            }
        }
        server.predate_tls(test::ADMIN_PEER_ID);
        let res = server
            .plain_request(test::ADMIN_PEER_IP, "GET", &path)
            .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            peer(&server, test::DEVELOPER1_PEER_ID).endpoint,
            current.endpoints.endpoint
        );
        assert!(!peer(&server, test::DEVELOPER1_PEER_ID).is_disabled);

        Ok(())
    }

    #[tokio::test]
    async fn test_redeemed_peer_changed() -> Result<(), Error> {
        let server = test::Server::new()?;
        let ip = if cfg!(feature = "v6-test") {
            "fd00:1337::2:0:0:9"
        } else {
            "10.80.64.9"
        };
        let contents = PeerContents {
            is_redeemed: false,
            ..test::developer_peer_contents("invitee", ip)?
        };
        let invitee = DatabasePeer::create(&server.db.lock(), contents)?;
        let path = format!("/v1/admin/peers/{}", invitee.api_path_segment());
        let mut change = unchanged(&server, &path).await;
        change.name = "renamed".parse().unwrap();

        // The invitation is redeemed, which changes the peer's key, after the admin read it. The
        // change, which names the peer by its old key, finds no peer.
        {
            let store = server.db.lock();
            let mut invitee = DatabasePeer::get_from_ip(&store, ip.parse()?)?;
            invitee.redeem(&store, &KeyPair::generate().public.to_base64())?;
        }
        let res = server
            .form_request(test::ADMIN_PEER_IP, "PUT", &path, &change)
            .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let invitee = DatabasePeer::get_from_ip(&server.db.lock(), ip.parse()?)?;
        assert_eq!(&*invitee.name, "invitee");
        Ok(())
    }

    #[tokio::test]
    async fn test_tls_sessions_refuse_ids() -> Result<(), Error> {
        let server = test::Server::new()?;
        let old_peer = peer(&server, test::DEVELOPER1_PEER_ID);
        let id_path = format!("/v1/admin/peers/{}", test::DEVELOPER1_PEER_ID);

        let change = PeerContents {
            name: "new-peer-name".parse().unwrap(),
            ..old_peer.inner.clone()
        };
        let res = server
            .form_request(test::ADMIN_PEER_IP, "PUT", &id_path, &change)
            .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let mut update = unchanged(&server, &key_path(&server, test::DEVELOPER1_PEER_ID)).await;
        update.name = change.name.clone();
        let res = server
            .form_request(test::ADMIN_PEER_IP, "PUT", &id_path, &update)
            .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        for method in ["GET", "DELETE"] {
            let res = server.request(test::ADMIN_PEER_IP, method, &id_path).await;
            assert_eq!(res.status(), StatusCode::NOT_FOUND);
        }

        assert_eq!(
            peer(&server, test::DEVELOPER1_PEER_ID).inner,
            old_peer.inner
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_promotion_requires_tls() -> Result<(), Error> {
        let server = test::Server::new()?;
        server.predate_tls(test::DEVELOPER1_PEER_ID);
        let path = key_path(&server, test::DEVELOPER1_PEER_ID);
        let promote = || async {
            let mut change = unchanged(&server, &path).await;
            change.is_admin = true;
            server
                .form_request(test::ADMIN_PEER_IP, "PUT", &path, &change)
                .await
        };

        // The peer predates TLS, and has only been seen in plain HTTP.
        assert_eq!(promote().await.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(!peer(&server, test::DEVELOPER1_PEER_ID).is_admin);

        // Once it has connected over TLS, it can be.
        let res = server
            .request(test::DEVELOPER1_PEER_IP, "GET", "/v1/user/state")
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(promote().await.status(), StatusCode::NO_CONTENT);
        assert!(peer(&server, test::DEVELOPER1_PEER_ID).is_admin);
        Ok(())
    }

    #[tokio::test]
    async fn test_add_peer_with_invalid_key() -> Result<(), Error> {
        let server = test::Server::new()?;
        let ip = if cfg!(feature = "v6-test") {
            "fd00:1337::2:0:0:3"
        } else {
            "10.80.64.4"
        };
        let mut peer = test::developer_peer_contents("developer3", ip)?;
        // A low-order point.
        peer.public_key = Key([0; 32]).to_base64();
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/peers", &peer)
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn test_list_all_peers_from_admin() -> Result<(), Error> {
        let server = test::Server::new()?;
        let res = server
            .request(test::ADMIN_PEER_IP, "GET", "/v1/admin/peers")
            .await;

        assert_eq!(res.status(), StatusCode::OK);

        let whole_body = hyper::body::aggregate(res).await?;
        let peers: Vec<PeerContents> = serde_json::from_reader(whole_body.reader())?;
        let peer_names = peers.iter().map(|p| &*p.name).collect::<Vec<_>>();
        // An admin peer should see all the peers.
        assert_eq!(
            &[
                "innernet-server",
                "admin",
                "developer1",
                "developer2",
                "user1",
                "user2"
            ],
            &peer_names[..]
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_peers_without_ids() -> Result<(), Error> {
        let server = test::Server::new()?;
        let ip = if cfg!(feature = "v6-test") {
            "fd00:1337::2:0:0:3"
        } else {
            "10.80.64.4"
        };
        let json = |res: Response<Body>| async {
            let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()
        };

        // The admin API lists and creates peers without IDs.
        let res = server
            .request(test::ADMIN_PEER_IP, "GET", "/v1/admin/peers")
            .await;
        let peers = json(res).await;
        assert_eq!(peers.as_array().unwrap().len(), 6);
        assert!(peers
            .as_array()
            .unwrap()
            .iter()
            .all(|peer| peer.get("id").is_none()));
        let contents = test::developer_peer_contents("developer3", ip)?;
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/peers", &contents)
            .await;
        assert_eq!(res.status(), StatusCode::CREATED);
        assert!(json(res).await.get("id").is_none());
        Ok(())
    }

    #[tokio::test]
    async fn test_list_all_peers_from_non_admin() -> Result<(), Error> {
        let server = test::Server::new()?;
        let res = server
            .request(test::DEVELOPER1_PEER_IP, "GET", "/v1/admin/peers")
            .await;

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[tokio::test]
    async fn test_admin_routes_not_in_plain_http() -> Result<(), Error> {
        // An admin that predates TLS is an ordinary peer in plain HTTP until it upgrades: the
        // admin API exists only over TLS.
        let server = test::Server::new()?;
        server.predate_tls(test::ADMIN_PEER_ID);
        let old_peers = DatabasePeer::list(&server.db().lock())?;
        let peer_path = format!("/v1/admin/peers/{}", test::USER1_PEER_ID);
        for (method, path) in [
            ("GET", "/v1/admin/peers"),
            ("POST", "/v1/admin/peers"),
            ("PUT", &peer_path),
            ("DELETE", &peer_path),
            ("GET", "/v1/admin/cidrs"),
            ("GET", "/v1/admin/associations"),
        ] {
            let res = server
                .plain_request(test::ADMIN_PEER_IP, method, path)
                .await;
            assert_eq!(res.status(), StatusCode::NOT_FOUND, "{method} {path}");
        }
        let res = server
            .plain_request(test::ADMIN_PEER_IP, "GET", "/v1/user/state")
            .await;
        assert_eq!(res.status(), StatusCode::OK);

        let peers = |peers: Vec<DatabasePeer>| -> Vec<PeerContents> {
            peers.into_iter().map(|peer| peer.inner).collect()
        };
        assert_eq!(
            peers(DatabasePeer::list(&server.db().lock())?),
            peers(old_peers)
        );
        Ok(())
    }
}
