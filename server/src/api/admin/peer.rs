use std::collections::VecDeque;

use crate::{
    api::inject_endpoints,
    db::DatabasePeer,
    util::{form_body, json_response, json_status_response, status_response},
    ServerError, Session,
};
use hyper::{Body, Method, Request, Response, StatusCode};
use innernet_shared::{
    Hostname, PeerContents, PeerEndpoints, PeerUpdate, TaggedPeer, TaggedPeerDelegations,
    TaggedPeerEndpoints,
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
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
            let form = peer_form_body(req).await?;
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
        (&Method::GET, Some(key), Some("delegations")) => handlers::delegations(key, session).await,
        (&Method::PUT, Some(key), Some("delegations")) => {
            let form = form_body(req).await?;
            handlers::set_delegations(key, form, session).await
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

/// Reads a peer from the body of `req`. A [`PeerContents`] reads an invalid name as no name, so
/// that clients can read peers from servers that allow other names, but the server refuses a peer
/// whose name is not a valid [`Hostname`], with 400.
async fn peer_form_body(req: Request<Body>) -> Result<PeerContents, ServerError> {
    #[derive(Deserialize)]
    struct Name {
        #[serde(default, rename = "name")]
        _name: Option<Hostname>,
    }

    let form: serde_json::Value = form_body(req).await?;
    Name::deserialize(&form)?;
    Ok(PeerContents::deserialize(form)?)
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
/// its endpoint and candidates, which the peer reports on its own, and its delegations, which an
/// admin changes apart from the rest of the peer.
fn peer_tag(peer: &PeerContents) -> Result<String, ServerError> {
    let peer = PeerContents {
        delegations: vec![],
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

/// The tag of a peer's delegations: that of its public key and delegations.
fn delegations_tag(peer: &PeerContents) -> Result<String, ServerError> {
    tag("delegations", &(&peer.public_key, &peer.delegations))
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

    /// The delegations of the peer with the public key `key`, and their tag.
    pub async fn delegations(key: Key, session: Session) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        let peer = DatabasePeer::get_from_public_key(&conn, &key)?;
        json_response(TaggedPeerDelegations {
            delegations: peer.delegations.clone(),
            tag: delegations_tag(&peer)?,
        })
    }

    /// Replaces the delegations of the peer with the public key `key` as a whole, if they
    /// haven't changed since the admin read them with the tag that the request carries.
    pub async fn set_delegations(
        key: Key,
        form: TaggedPeerDelegations,
        session: Session,
    ) -> Result<Response<Body>, ServerError> {
        let store = session.context.db.lock();
        let mut peer = get_unchanged(&store, &key, &form.tag, delegations_tag)?;
        peer.set_delegations(
            &store,
            form.delegations,
            &session.context.public_key,
            session.context.internal_address,
        )?;
        log::info!(
            "set the delegations of peer {} to {}",
            *peer,
            peer.display_delegations()
        );
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
    use innernet_shared::{Endpoint, Error, LegacyPeer, Prefix, State};
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

        // The server refuses an invalid name with 400, whichever route carries it, although a
        // client reads an invalid name as no name.
        let server = test::Server::new()?;
        let old_peers = DatabasePeer::list(&server.db().lock())?;
        let ip = if cfg!(feature = "v6-test") {
            "fd00:1337::2:0:0:3"
        } else {
            "10.80.64.4"
        };
        let mut invalid = serde_json::to_value(test::developer_peer_contents("developer3", ip)?)?;
        invalid["name"] = "devel oper".into();
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/peers", &invalid)
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        let path = key_path(&server, test::DEVELOPER1_PEER_ID);
        let mut rename = serde_json::to_value(unchanged(&server, &path).await)?;
        rename["name"] = "devel oper".into();
        let res = server
            .form_request(test::ADMIN_PEER_IP, "PUT", &path, &rename)
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        let peers = |peers: Vec<DatabasePeer>| -> Vec<PeerContents> {
            peers.into_iter().map(|peer| peer.inner).collect()
        };
        assert_eq!(
            peers(DatabasePeer::list(&server.db().lock())?),
            peers(old_peers)
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_add_peer_with_duplicate_name() -> Result<(), Error> {
        let server = test::Server::new()?;

        let old_peers = DatabasePeer::list(&server.db().lock())?;

        // Try to add a peer with a name that is already taken.
        let ip = if cfg!(feature = "v6-test") {
            "fd00:1337::2:0:0:3"
        } else {
            "10.80.64.4"
        };
        let peer = test::developer_peer_contents("developer2", ip)?;

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

        // Try to add a peer with an IP that is already taken, which the server explains.
        let peer = test::developer_peer_contents("developer3", test::DEVELOPER2_PEER_IP)?;

        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/peers", &peer)
            .await;

        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = hyper::body::to_bytes(res.into_body()).await?;
        assert!(String::from_utf8_lossy(&body).contains("delegated to peer developer2"));

        // The number of peer entries in the database should not change.
        let new_peers = DatabasePeer::list(&server.db().lock())?;
        assert_eq!(old_peers.len(), new_peers.len());

        Ok(())
    }

    #[tokio::test]
    async fn test_add_peer_with_outside_cidr_range_ip() -> Result<(), Error> {
        let server = test::Server::new()?;

        let old_peers = DatabasePeer::list(&server.db().lock())?;

        // An IP outside of the CIDR network, in the root CIDR, which has children, or outside
        // every CIDR, its network address and its broadcast address are refused, with an
        // explanation. In IPv6, only the network address is reserved.
        let refused: &[(&str, &str)] = if cfg!(feature = "v6-test") {
            &[
                ("fd00:1337::5:0:0:4", "child CIDR"),
                ("fd00:1338::4", "outside every CIDR"),
                ("fd00:1337::2:0:0:0", "network or broadcast"),
            ]
        } else {
            &[
                ("10.80.65.4", "child CIDR"),
                ("10.90.0.4", "outside every CIDR"),
                ("10.80.64.0", "network or broadcast"),
                ("10.80.64.255", "network or broadcast"),
            ]
        };
        for (ip, reason) in refused {
            let peer = test::developer_peer_contents("developer3", ip)?;
            let res = server
                .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/peers", &peer)
                .await;
            assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
            let body = hyper::body::to_bytes(res.into_body()).await?;
            assert!(String::from_utf8_lossy(&body).contains(reason), "{ip}");
        }

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
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = hyper::body::to_bytes(res.into_body()).await?;
        assert!(String::from_utf8_lossy(&body).contains("child CIDR"));

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
        change.name = Some("new-peer-name".parse().unwrap());
        change.is_disabled = true;

        let res = server
            .form_request(test::ADMIN_PEER_IP, "PUT", &path, &change)
            .await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let new_peer = peer(&server, test::DEVELOPER1_PEER_ID);
        assert_eq!(new_peer.name.as_deref(), Some("new-peer-name"));
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
            name: Some("renamed".parse().unwrap()),
            ..peer.clone()
        };
        assert_ne!(peer_tag(&renamed)?, tag);

        // The delegations, which an admin changes apart from the rest of the peer, leave the
        // tag unchanged.
        let delegated = PeerContents {
            delegations: vec!["10.80.64.16/28".parse()?],
            ..peer.clone()
        };
        assert_eq!(peer_tag(&delegated)?, tag);
        Ok(())
    }

    #[tokio::test]
    async fn test_add_peer_with_delegations() -> Result<(), Error> {
        let server = test::Server::new()?;
        let (wider, ip, host_len) = if cfg!(feature = "v6-test") {
            ("fd00:1337::2:0:1:0/112", "fd00:1337::2:0:0:9", 128)
        } else {
            ("10.80.64.16/28", "10.80.64.9", 32)
        };
        let with = |delegations: &[&str]| -> Result<PeerContents, Error> {
            Ok(PeerContents {
                delegations: delegations
                    .iter()
                    .map(|d| d.parse())
                    .collect::<Result<_, _>>()?,
                ..test::developer_peer_contents("developer3", ip)?
            })
        };

        // A peer without a delegation, or with one that another peer holds, is refused.
        let host = format!("{ip}/{host_len}");
        let taken = format!("{}/{host_len}", test::DEVELOPER2_PEER_IP);
        for (delegations, reason) in [
            (vec![], "at least one"),
            (vec![wider, taken.as_str()], "delegated to peer developer2"),
        ] {
            let res = server
                .form_request(
                    test::ADMIN_PEER_IP,
                    "POST",
                    "/v1/admin/peers",
                    with(&delegations)?,
                )
                .await;
            assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
            let body = hyper::body::to_bytes(res.into_body()).await?;
            assert!(String::from_utf8_lossy(&body).contains(reason), "{reason}");
        }

        // A peer is created with every delegation it is offered.
        let peer = with(&[wider, &host])?;
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/peers", &peer)
            .await;
        assert_eq!(res.status(), StatusCode::CREATED);
        let body = hyper::body::to_bytes(res.into_body()).await?;
        let created: PeerContents = serde_json::from_slice(&body)?;
        let mut sorted = peer.delegations.clone();
        sorted.sort();
        assert_eq!(created.delegations, sorted);
        let key = Key::from_base64(&peer.public_key)?;
        let stored = DatabasePeer::get_from_public_key(&server.db.lock(), &key)?;
        assert_eq!(stored.delegations, sorted);

        // Clients that predate TLS see the lowest address of its delegations as its IP.
        let id = DatabasePeer::plain_http_ids(&server.db.lock())?[&peer.public_key];
        let legacy = stored.legacy(id).unwrap();
        assert_eq!(Some(legacy.ip), stored.hosts_fallback());
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
            name: Some(name.parse().unwrap()),
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
        assert_eq!(
            peer(&server, test::DEVELOPER1_PEER_ID).name.as_deref(),
            Some("first")
        );
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
        assert_eq!(
            peer(&server, test::DEVELOPER1_PEER_ID).name.as_deref(),
            Some("first")
        );
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
        change.name = Some("new-peer-name".parse().unwrap());
        let res = server
            .form_request(test::ADMIN_PEER_IP, "PUT", &path, &change)
            .await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let new_peer = peer(&server, test::DEVELOPER1_PEER_ID);
        assert_eq!(new_peer.name.as_deref(), Some("new-peer-name"));
        assert_eq!(new_peer.endpoint, Some(endpoint));
        assert_eq!(new_peer.candidates, vec![candidate]);
        Ok(())
    }

    /// Prefixes of the developer CIDR: a wider prefix, one misaligned, one outside the CIDR, and
    /// the IP of developer2 as a host prefix.
    fn developer_prefixes() -> [String; 4] {
        let host = if cfg!(feature = "v6-test") { 128 } else { 32 };
        let [wider, misaligned, outside] = if cfg!(feature = "v6-test") {
            [
                "fd00:1337::2:0:1:0/112",
                "fd00:1337::2:0:1:1/112",
                "fd00:1337::5:0:0:0/112",
            ]
        } else {
            ["10.80.64.16/28", "10.80.64.17/28", "10.80.65.0/28"]
        };
        [
            wider.into(),
            misaligned.into(),
            outside.into(),
            format!("{}/{host}", test::DEVELOPER2_PEER_IP),
        ]
    }

    #[tokio::test]
    async fn test_delegations() -> Result<(), Error> {
        let server = test::Server::new()?;
        let peer_path = key_path(&server, test::DEVELOPER1_PEER_ID);
        let path = format!("{peer_path}/delegations");
        let [wider, misaligned, outside, taken] = developer_prefixes();
        let get = |path: String| {
            let server = &server;
            async move {
                let res = server.request(test::ADMIN_PEER_IP, "GET", &path).await;
                assert_eq!(res.status(), StatusCode::OK);
                let body = hyper::body::aggregate(res).await.unwrap();
                serde_json::from_reader::<_, TaggedPeerDelegations>(body.reader()).unwrap()
            }
        };
        let put = |path: &str, delegations: &[&str], tag: &str| {
            let body = serde_json::json!({ "delegations": delegations, "tag": tag });
            let path = path.to_string();
            let server = &server;
            async move {
                server
                    .form_request(test::ADMIN_PEER_IP, "PUT", &path, body)
                    .await
            }
        };

        let seen = get(path.clone()).await;
        let own = seen.delegations[0].to_string();
        assert_eq!(seen.delegations.len(), 1);
        let peer_tag = get_tagged(&server, &peer_path).await.tag;

        // The delegations are replaced as a whole, and routed from then on.
        let res = put(&path, &[&wider, &own], &seen.tag).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        let current = get(path.clone()).await;
        let mut expected: Vec<Prefix> = vec![own.parse()?, wider.parse()?];
        expected.sort();
        assert_eq!(current.delegations, expected);
        assert_ne!(current.tag, seen.tag);
        let wider_prefix: Prefix = wider.parse()?;
        let within = DatabasePeer::get_by_address(&server.db.lock(), wider_prefix.last())?;
        assert_eq!(
            within.public_key,
            peer(&server, test::DEVELOPER1_PEER_ID).public_key
        );

        // The delegations are tagged apart from the rest of the peer.
        assert_eq!(get_tagged(&server, &peer_path).await.tag, peer_tag);

        // A change based on delegations read before is refused, as is one without a tag or with
        // a misaligned prefix, and delegations that break the rules are refused with an
        // explanation.
        assert_eq!(
            put(&path, &[&own], &seen.tag).await.status(),
            StatusCode::CONFLICT
        );
        let untagged = serde_json::json!({ "delegations": [own] });
        let res = server
            .form_request(test::ADMIN_PEER_IP, "PUT", &path, untagged)
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            put(&path, &[&misaligned], &current.tag).await.status(),
            StatusCode::BAD_REQUEST
        );
        // A prefix of the user CIDR, another than the peer's.
        let other_cidr = if cfg!(feature = "v6-test") {
            "fd00:1337::3:0:1:0/112"
        } else {
            "10.80.130.0/24"
        };
        for (delegations, reason) in [
            (vec![outside.as_str()], "child CIDR"),
            (vec![other_cidr], "in its CIDR"),
            (vec![taken.as_str()], "delegated to peer developer2"),
            (
                vec![wider.as_str(), wider.as_str()],
                "another of the delegations",
            ),
        ] {
            let res = put(&path, &delegations, &current.tag).await;
            assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
            let body = hyper::body::to_bytes(res.into_body()).await?;
            assert!(String::from_utf8_lossy(&body).contains(reason), "{reason}");
        }
        assert_eq!(get(path.clone()).await, current);

        // A withdrawn delegation stays pinned to the peer's key, so the server's node refuses it
        // to another peer, with an explanation.
        let res = put(&path, &[&own], &current.tag).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        let other_path = format!(
            "{}/delegations",
            key_path(&server, test::DEVELOPER2_PEER_ID)
        );
        let other = get(other_path.clone()).await;
        let other_own = other.delegations[0].to_string();
        let res = put(&other_path, &[&other_own, &wider], &other.tag).await;
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = hyper::body::to_bytes(res.into_body()).await?;
        assert!(String::from_utf8_lossy(&body).contains("pinned"));
        assert_eq!(get(other_path).await, other);

        // A peer may be left without a delegation, which leaves it out of the legacy view.
        let current = get(path.clone()).await;
        let key = Key::from_base64(&peer(&server, test::DEVELOPER1_PEER_ID).public_key)?;
        assert_eq!(
            put(&path, &[], &current.tag).await.status(),
            StatusCode::NO_CONTENT
        );
        let without = DatabasePeer::get_from_public_key(&server.db.lock(), &key)?;
        assert!(without.delegations.is_empty());
        assert!(without.legacy(test::DEVELOPER1_PEER_ID).is_none());

        // A non-admin can't, and an unknown key is not found.
        let tag = get(path.clone()).await.tag;
        let res = server
            .form_request(
                test::DEVELOPER2_PEER_IP,
                "PUT",
                &path,
                TaggedPeerDelegations {
                    delegations: vec![],
                    tag,
                },
            )
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let unknown = PeerContents {
            public_key: KeyPair::generate().public.to_base64(),
            ..without.inner.clone()
        };
        let unknown_path = format!("/v1/admin/peers/{}/delegations", unknown.api_path_segment());
        let res = server
            .request(test::ADMIN_PEER_IP, "GET", &unknown_path)
            .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn test_server_keeps_its_internal_address() -> Result<(), Error> {
        // The server's own peer can't lose the delegation that holds its internal address.
        let server = test::Server::new()?;
        let path = format!("{}/delegations", key_path(&server, test::SERVER_PEER_ID));
        let res = server.request(test::ADMIN_PEER_IP, "GET", &path).await;
        let body = hyper::body::to_bytes(res.into_body()).await?;
        let seen: TaggedPeerDelegations = serde_json::from_slice(&body)?;
        let res = server
            .form_request(
                test::ADMIN_PEER_IP,
                "PUT",
                &path,
                TaggedPeerDelegations {
                    delegations: vec![],
                    tag: seen.tag,
                },
            )
            .await;
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = hyper::body::to_bytes(res.into_body()).await?;
        assert!(String::from_utf8_lossy(&body).contains("internal address"));
        assert_eq!(
            peer(&server, test::SERVER_PEER_ID).delegations,
            seen.delegations
        );
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
        rename.name = Some("renamed".parse().unwrap());
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
        change.name = Some("renamed".parse().unwrap());

        // The invitation is redeemed, which changes the peer's key, after the admin read it. The
        // change, which names the peer by its old key, finds no peer.
        {
            let store = server.db.lock();
            let mut invitee = DatabasePeer::get_by_address(&store, ip.parse()?)?;
            invitee.redeem(&store, &KeyPair::generate().public.to_base64())?;
        }
        let res = server
            .form_request(test::ADMIN_PEER_IP, "PUT", &path, &change)
            .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let invitee = DatabasePeer::get_by_address(&server.db.lock(), ip.parse()?)?;
        assert_eq!(invitee.name.as_deref(), Some("invitee"));
        Ok(())
    }

    #[tokio::test]
    async fn test_tls_sessions_refuse_ids() -> Result<(), Error> {
        let server = test::Server::new()?;
        let old_peer = peer(&server, test::DEVELOPER1_PEER_ID);
        let id_path = format!("/v1/admin/peers/{}", test::DEVELOPER1_PEER_ID);

        let change = PeerContents {
            name: Some("new-peer-name".parse().unwrap()),
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
        let peer_names = peers
            .iter()
            .map(|p| p.name.as_deref().unwrap())
            .collect::<Vec<_>>();
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

    #[tokio::test]
    async fn test_nameless_peers() -> Result<(), Error> {
        let server = test::Server::new()?;
        let json = |res: Response<Body>| async {
            assert_eq!(res.status(), StatusCode::OK);
            let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()
        };
        let names = |peers: &serde_json::Value| -> Vec<serde_json::Value> {
            peers
                .as_array()
                .unwrap()
                .iter()
                .map(|peer| peer["name"].clone())
                .collect()
        };

        // An admin removes the names of both user peers over TLS: any number of peers can be
        // without a name.
        for id in [test::USER1_PEER_ID, test::USER2_PEER_ID] {
            let path = key_path(&server, id);
            let mut change = unchanged(&server, &path).await;
            change.name = None;
            let res = server
                .form_request(test::ADMIN_PEER_IP, "PUT", &path, &change)
                .await;
            assert_eq!(res.status(), StatusCode::NO_CONTENT);
            assert_eq!(peer(&server, id).name, None);
            assert_eq!(get_tagged(&server, &path).await.peer.name, None);
        }

        // Over TLS, a peer without a name has a null name.
        let res = server
            .request(test::ADMIN_PEER_IP, "GET", "/v1/admin/peers")
            .await;
        let listed = json(res).await;
        assert_eq!(names(&listed).len(), 6);
        assert_eq!(
            names(&listed).iter().filter(|name| name.is_null()).count(),
            2
        );
        let res = server
            .request(test::USER1_PEER_IP, "GET", "/v1/user/state")
            .await;
        let state: State = serde_json::from_value(json(res).await)?;
        assert_eq!(state.peers.iter().filter(|p| p.name.is_none()).count(), 2);

        // The view of plain-HTTP sessions leaves out the peers without a name, which clients that
        // predate TLS can't read.
        server.predate_tls(test::USER1_PEER_ID);
        let res = server
            .plain_request(test::USER1_PEER_IP, "GET", "/v1/user/state")
            .await;
        let state = json(res).await;
        let peers: Vec<LegacyPeer> = serde_json::from_value(state["peers"].clone())?;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name.as_deref(), Some("innernet-server"));

        Ok(())
    }
}
