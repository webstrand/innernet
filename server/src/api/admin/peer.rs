use innernet_node::Store;
use std::collections::VecDeque;

use crate::{
    api::inject_endpoints,
    db::DatabasePeer,
    util::{
        decode, form_response, form_status_response, read_body, status_response, tagged_form_body,
    },
    ServerError, Session,
};
use hyper::{Body, Method, Request, Response, StatusCode};
use innernet_shared::{
    announcement, Hostname, PeerContents, PeerEndpoints, PeerUpdate, Tag, TaggedPeer,
    TaggedPeerDelegations,
};
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
    // A key that no peer has is refused as such, apart from a path that the server has no route
    // for.
    let no_such_peer = |e: ServerError| e.not_found_as(ServerError::NoSuchPeer);
    match (req.method(), key, resource.as_deref()) {
        (&Method::GET, None, None) => handlers::list(session).await,
        (&Method::POST, None, None) => {
            let form = peer_form_body(req, &session).await?;
            handlers::create(form, session).await
        },
        (&Method::GET, Some(key), None) => handlers::get_by_key(key, session)
            .await
            .map_err(no_such_peer),
        (&Method::PUT, Some(key), None) => {
            let form = tagged_form_body(req, &session).await?;
            handlers::update_by_key(key, form, session)
                .await
                .map_err(no_such_peer)
        },
        (&Method::GET, Some(key), Some("endpoints")) => handlers::endpoints(key, session)
            .await
            .map_err(no_such_peer),
        (&Method::GET, Some(key), Some("delegations")) => handlers::delegations(key, session)
            .await
            .map_err(no_such_peer),
        (&Method::PUT, Some(key), Some("delegations")) => {
            let form = tagged_form_body(req, &session).await?;
            handlers::set_delegations(key, form, session)
                .await
                .map_err(no_such_peer)
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

/// Reads a peer from the body of `req`, a request of `session`. A [`PeerContents`] reads an
/// invalid name as no name, so that clients can read peers from servers that allow other names,
/// but the server refuses a peer whose name is not a valid [`Hostname`], with 400.
async fn peer_form_body(
    req: Request<Body>,
    session: &Session,
) -> Result<PeerContents, ServerError> {
    #[derive(Deserialize)]
    struct Name {
        #[serde(default, rename = "name")]
        _name: Option<Hostname>,
    }

    let body = read_body(req, session).await?;
    decode::<Name>(session, &body)?;
    decode(session, &body)
}

/// The tag of `value`, a resource of the kind `kind`, such as a peer or a CIDR: a hash of the kind
/// and the value, and of nothing else, so that a tag depends only on the state that it was
/// computed for. Clients treat tags as opaque. The hash is SHA-512, which XEdDSA uses already,
/// cut to 128 bits: a tag only tells states apart, and needs no more resistance to collisions.
pub(super) fn tag<T: Serialize>(kind: &str, value: &T) -> Result<Tag, ServerError> {
    let mut hasher = Sha512::new();
    hasher.update(kind.as_bytes());
    hasher.update([0]);
    hasher.update(serde_json::to_vec(value)?);
    let hash = hasher.finalize();
    Ok(Tag::new(hash[..16].to_vec()))
}

/// The tag of a peer: that of everything an admin reads of the peer, its public key included, but
/// its endpoint and candidates and its announcement, which the peer reports on its own, and its
/// delegations, which an admin changes apart from the rest of the peer.
fn peer_tag(peer: &PeerContents) -> Result<Tag, ServerError> {
    let peer = PeerContents {
        delegations: vec![],
        endpoint: None,
        candidates: vec![],
        announcement: None,
        allowed_ips: None,
        primary_ip: None,
        nameserver: None,
        ..peer.clone()
    };
    tag("peer", &peer)
}

/// The tag of a peer's delegations: that of its public key, its delegations, and those of them
/// that are marked to be reclaimed.
fn delegations_tag(peer: &DatabasePeer) -> Result<Tag, ServerError> {
    tag(
        "delegations",
        &(&peer.public_key, &peer.delegations, &peer.reclaim),
    )
}

/// The peer with the public key `key`, if `tag_of` the peer is still `tag`. A peer that has
/// changed since it was tagged is refused as [`ServerError::PeerChanged`]. A peer whose key has
/// changed since, as a redeemed invitation's does, is not found, like a peer that never existed:
/// a tag doesn't identify the peer it was computed for.
fn get_unchanged(
    store: &Store,
    key: &Key,
    tag: &Tag,
    tag_of: impl Fn(&DatabasePeer) -> Result<Tag, ServerError>,
) -> Result<DatabasePeer, ServerError> {
    match DatabasePeer::get_from_public_key(store, key) {
        Ok(peer) if tag_of(&peer)? == *tag => Ok(peer),
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
        let store = session.context.db.lock();

        let peer = DatabasePeer::create(&store, form)?;
        log::info!("adding peer {}", *peer);
        session.context.changed.notify();
        if !peer.is_redeemed {
            session.context.invitations.notify_one();
        }

        form_status_response(&session, &peer.inner, StatusCode::CREATED)
    }

    /// The peer with the public key `key` as the listing reports it, with its tag.
    pub async fn get_by_key(key: Key, session: Session) -> Result<Response<Body>, ServerError> {
        let store = session.context.db.lock();
        let mut peer = DatabasePeer::get_from_public_key(&store, &key)?.inner;
        let tag = peer_tag(&peer)?;
        inject_endpoints(&session, [&mut peer]);
        form_response(&session, TaggedPeer { peer, tag })
    }

    /// Applies an admin's changes to the peer with the public key `key`, if the peer hasn't
    /// changed since the admin read it with the tag that the changes carry.
    pub async fn update_by_key(
        key: Key,
        form: PeerUpdate,
        session: Session,
    ) -> Result<Response<Body>, ServerError> {
        let store = session.context.db.lock();
        let mut peer = get_unchanged(&store, &key, &form.tag, |peer| peer_tag(peer))?;
        let contents = PeerContents {
            name: form.name,
            is_admin: form.is_admin,
            is_disabled: form.is_disabled,
            ..peer.inner.clone()
        };
        peer.update(&store, contents)?;
        // The update may have enabled or disabled the peer.
        session.context.changed.notify();

        status_response(StatusCode::NO_CONTENT)
    }

    /// The endpoints at which other peers reach the peer with the public key `key`, as the server
    /// relays them, in the order in which peers try them: those that its announcement states, or,
    /// for a peer that has never announced, the endpoint that it set and then its candidates, with
    /// the endpoint at which the server observes it, as the unsigned announcement that the server
    /// relays of it orders them. Only the peer sets them, so they carry no tag.
    pub async fn endpoints(key: Key, session: Session) -> Result<Response<Body>, ServerError> {
        let store = session.context.db.lock();
        let mut peer = DatabasePeer::get_from_public_key(&store, &key)?;
        inject_endpoints(&session, [&mut peer.inner]);
        let PeerContents {
            endpoint,
            candidates,
            ..
        } = if peer.has_announced() {
            peer.effective()
        } else {
            peer.inner.effective_with(None)
        };
        let endpoints = announcement::legacy_endpoints(endpoint.as_ref(), &candidates);
        form_response(&session, PeerEndpoints { endpoints })
    }

    /// The delegations of the peer with the public key `key`, and their tag.
    pub async fn delegations(key: Key, session: Session) -> Result<Response<Body>, ServerError> {
        let store = session.context.db.lock();
        let peer = DatabasePeer::get_from_public_key(&store, &key)?;
        form_response(
            &session,
            TaggedPeerDelegations {
                delegations: peer.delegations.clone(),
                reclaim: peer.reclaim.clone(),
                tag: delegations_tag(&peer)?,
            },
        )
    }

    /// Replaces the delegations of the peer with the public key `key` as a whole, and those of
    /// them marked to be reclaimed, if they haven't changed since the admin read them with the tag
    /// that the request carries.
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
            form.reclaim,
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
        let store = session.context.db.lock();
        let mut peers = DatabasePeer::list(&store)?
            .into_iter()
            .map(|peer| peer.inner)
            .collect::<Vec<_>>();
        inject_endpoints(&session, &mut peers);
        form_response(&session, &peers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{db::DatabaseCidr, test};
    use innernet_shared::{problem, Endpoint, Error, LegacyPeer, Prefix, State};
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
            .form_request(test::ADMIN_PEER_IP, "POST", "/admin/peers", &peer)
            .await;

        assert_eq!(res.status(), StatusCode::CREATED);
        // The response contains the new peer information.
        let peer_res: PeerContents = test::cbor_body(res).await?;

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
        let mut invalid =
            cbor_core::Value::serialized(&test::developer_peer_contents("developer3", ip)?)?;
        invalid["name"] = "devel oper".into();
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/admin/peers", &invalid)
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        let path = key_path(&server, test::DEVELOPER1_PEER_ID);
        let mut rename = cbor_core::Value::serialized(&unchanged(&server, &path).await)?;
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
            .form_request(test::ADMIN_PEER_IP, "POST", "/admin/peers", &peer)
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

        // Try to add a peer with an IP that is already taken, which the server explains, and
        // names the delegation that it overlaps, and its holder.
        let peer = test::developer_peer_contents("developer3", test::DEVELOPER2_PEER_IP)?;

        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/admin/peers", &peer)
            .await;

        let problem = test::problem(res, &problem::DELEGATION_REFUSED).await?;
        assert!(problem
            .detail
            .unwrap()
            .contains("delegated to peer developer2"));
        let developer2 = test::peer(&server.db.lock(), test::DEVELOPER2_PEER_ID);
        assert_eq!(problem.prefix, Some(peer.delegations[0]));
        assert_eq!(problem.held, Some(developer2.delegations[0]));
        assert_eq!(problem.holder, Some(developer2.public_key.clone()));

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
                .form_request(test::ADMIN_PEER_IP, "POST", "/admin/peers", &peer)
                .await;
            let problem = test::problem(res, &problem::DELEGATION_REFUSED).await?;
            assert!(problem.detail.unwrap().contains(reason), "{ip}");
            assert_eq!((problem.prefix, problem.holder), (None, None));
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
        let peer = test::peer_contents("developer3", ip, false)?;
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/admin/peers", &peer)
            .await;
        let detail = test::problem_detail(res, &problem::DELEGATION_REFUSED).await?;
        assert!(detail.contains("child CIDR"), "{detail}");

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
            .form_request(test::USER1_PEER_IP, "POST", "/admin/peers", &peer)
            .await;

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }

    fn peer(server: &test::Server, id: i64) -> DatabasePeer {
        test::peer(&server.db.lock(), id)
    }

    /// The path of the peer `id` in the API of TLS sessions.
    fn key_path(server: &test::Server, id: i64) -> String {
        format!("/admin/peers/{}", peer(server, id).api_path_segment())
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
        test::cbor_body(res).await.unwrap()
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
        test::blank_problem(res, StatusCode::NOT_FOUND).await?;

        // An unknown key is not found, even with the tag of a peer that exists, and the problem
        // says so, unlike that of a path that the server has no route for.
        let unknown = PeerContents {
            public_key: KeyPair::generate().public.to_base64(),
            ..new_peer.inner.clone()
        };
        let path = format!("/admin/peers/{}", unknown.api_path_segment());
        let res = server.request(test::ADMIN_PEER_IP, "GET", &path).await;
        test::problem(res, &problem::NO_SUCH_PEER).await?;
        let res = server
            .form_request(test::ADMIN_PEER_IP, "PUT", &path, &change)
            .await;
        test::problem(res, &problem::NO_SUCH_PEER).await?;
        Ok(())
    }

    #[test]
    fn test_tags_depend_only_on_state() -> Result<(), Error> {
        // A tag is a hash of the peer's state, and that state includes the key.
        let peer = test::developer_peer_contents("peer", "10.80.64.9")?;
        let tag = peer_tag(&peer)?;
        // In CBOR, a tag is a byte string of 16 bytes.
        let encoded = innernet_shared::cbor::to_vec(&tag)?;
        assert_eq!((encoded[0], encoded.len()), (0x50, 17));
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

        // What the peer reports on its own leaves the tag unchanged.
        let reported = PeerContents {
            endpoint: Some("198.51.100.1:51820".parse().unwrap()),
            announcement: Some(innernet_shared::announcement::SignedAnnouncement {
                payload: vec![0xa0],
                signature: Some(vec![0; 64]),
            }),
            ..peer.clone()
        };
        assert_eq!(peer_tag(&reported)?, tag);

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
                    "/admin/peers",
                    with(&delegations)?,
                )
                .await;
            let detail = test::problem_detail(res, &problem::DELEGATION_REFUSED).await?;
            assert!(detail.contains(reason), "{reason}");
        }

        // A peer is created with every delegation it is offered.
        let peer = with(&[wider, &host])?;
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/admin/peers", &peer)
            .await;
        assert_eq!(res.status(), StatusCode::CREATED);
        let created: PeerContents = test::cbor_body(res).await?;
        let mut sorted = peer.delegations.clone();
        sorted.sort();
        assert_eq!(created.delegations, sorted);
        let key = Key::from_base64(&peer.public_key)?;
        let stored = DatabasePeer::get_from_public_key(&server.db.lock(), &key)?;
        assert_eq!(stored.delegations, sorted);

        // Clients that predate TLS see the lowest address of its delegations as its IP.
        let id = DatabasePeer::plain_http_ids(&server.db.lock())?[&peer.public_key];
        let cidrs = DatabaseCidr::list(&server.db.lock())?;
        let legacy = stored.legacy(id, &cidrs).unwrap();
        assert_eq!(Some(legacy.ip), stored.hosts_fallback());
        assert_eq!(legacy.cidr_id, test::DEVELOPER_CIDR_ID);
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
        let detail = test::problem_detail(res, &problem::PEER_CHANGED).await?;
        assert!(detail.contains("changed"), "{detail}");
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
        test::problem(res, &problem::TAG_MISSING).await?;
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
        // A prefix of the user CIDR, another than the peer's.
        let other_cidr = if cfg!(feature = "v6-test") {
            "fd00:1337::3:0:1:0/112"
        } else {
            "10.80.130.0/24"
        };
        let get = || async {
            let res = server.request(test::ADMIN_PEER_IP, "GET", &path).await;
            assert_eq!(res.status(), StatusCode::OK);
            test::cbor_body::<TaggedPeerDelegations>(res).await.unwrap()
        };
        // The delegations are sent as text, which a prefix also deserializes from, so that a
        // misaligned prefix can be sent.
        #[derive(Serialize)]
        struct Delegations {
            delegations: Vec<String>,
            tag: Tag,
        }
        let put = |delegations: &[&str], tag: &Tag| {
            let body = Delegations {
                delegations: delegations.iter().map(|d| d.to_string()).collect(),
                tag: tag.clone(),
            };
            server.form_request(test::ADMIN_PEER_IP, "PUT", &path, body)
        };

        let seen = get().await;
        let own = seen.delegations[0].to_string();
        assert_eq!(seen.delegations.len(), 1);
        let peer_tag = get_tagged(&server, &peer_path).await.tag;

        // The delegations are replaced as a whole, and routed from then on.
        let res = put(&[&wider, &own], &seen.tag).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        let current = get().await;
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
        assert_eq!(put(&[&own], &seen.tag).await.status(), StatusCode::CONFLICT);
        let untagged = serde_json::json!({ "delegations": [own] });
        let res = server
            .form_request(test::ADMIN_PEER_IP, "PUT", &path, untagged)
            .await;
        test::problem(res, &problem::TAG_MISSING).await?;
        let res = put(&[&misaligned], &current.tag).await;
        test::blank_problem(res, StatusCode::BAD_REQUEST).await?;
        for (delegations, reason) in [
            (vec![outside.as_str()], "child CIDR"),
            (vec![other_cidr], "can't move it to the CIDR"),
            (vec![taken.as_str()], "delegated to peer developer2"),
            (
                vec![wider.as_str(), wider.as_str()],
                "another of the delegations",
            ),
        ] {
            let res = put(&delegations, &current.tag).await;
            let detail = test::problem_detail(res, &problem::DELEGATION_REFUSED).await?;
            assert!(detail.contains(reason), "{reason}");
        }
        assert_eq!(get().await, current);

        // A peer may be left without a delegation, which leaves it out of the legacy view.
        let key = Key::from_base64(&peer(&server, test::DEVELOPER1_PEER_ID).public_key)?;
        assert_eq!(
            put(&[], &current.tag).await.status(),
            StatusCode::NO_CONTENT
        );
        let without = DatabasePeer::get_from_public_key(&server.db.lock(), &key)?;
        assert!(without.delegations.is_empty());
        let cidrs = DatabaseCidr::list(&server.db.lock())?;
        assert!(without.legacy(test::DEVELOPER1_PEER_ID, &cidrs).is_none());

        // A peer without a delegation has no CIDR, so a new delegation may give it any CIDR.
        let tag = get().await.tag;
        assert_eq!(
            put(&[other_cidr], &tag).await.status(),
            StatusCode::NO_CONTENT
        );
        let moved = DatabasePeer::get_from_public_key(&server.db.lock(), &key)?;
        assert_eq!(
            moved
                .legacy(test::DEVELOPER1_PEER_ID, &cidrs)
                .map(|legacy| legacy.cidr_id),
            Some(test::USER_CIDR_ID)
        );
        let tag = get().await.tag;
        assert_eq!(put(&[], &tag).await.status(), StatusCode::NO_CONTENT);

        // A non-admin can't, an unknown key is not found, and plain-HTTP sessions don't reach
        // the delegations.
        let tag = get().await.tag;
        let res = server
            .form_request(
                test::DEVELOPER2_PEER_IP,
                "PUT",
                &path,
                TaggedPeerDelegations {
                    delegations: vec![],
                    reclaim: vec![],
                    tag: tag.clone(),
                },
            )
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let unknown = PeerContents {
            public_key: KeyPair::generate().public.to_base64(),
            ..without.inner.clone()
        };
        let unknown_path = format!("/admin/peers/{}/delegations", unknown.api_path_segment());
        let res = server
            .request(test::ADMIN_PEER_IP, "GET", &unknown_path)
            .await;
        test::problem(res, &problem::NO_SUCH_PEER).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_server_keeps_its_internal_address() -> Result<(), Error> {
        // The server's own peer can't lose the delegation that holds its internal address.
        let server = test::Server::new()?;
        let path = format!("{}/delegations", key_path(&server, test::SERVER_PEER_ID));
        let res = server.request(test::ADMIN_PEER_IP, "GET", &path).await;
        let seen: TaggedPeerDelegations = test::cbor_body(res).await?;
        let res = server
            .form_request(
                test::ADMIN_PEER_IP,
                "PUT",
                &path,
                TaggedPeerDelegations {
                    delegations: vec![],
                    reclaim: vec![],
                    tag: seen.tag,
                },
            )
            .await;
        let detail = test::problem_detail(res, &problem::DELEGATION_REFUSED).await?;
        assert!(detail.contains("internal address"), "{detail}");
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
            test::cbor_body::<PeerEndpoints>(res).await.unwrap()
        };

        // A peer that has never announced is reached at the endpoint that the server observes.
        let observed: innernet_shared::Endpoint = test::DEVELOPER1_PEER_ENDPOINT.parse().unwrap();
        assert_eq!(
            get().await,
            PeerEndpoints {
                endpoints: vec![observed.clone()]
            }
        );

        // One that has announced is reached where it announces, which only it states.
        let keypair = server.keypair(test::DEVELOPER1_PEER_ID);
        let path = format!("{}/endpoints", key_path(&server, test::DEVELOPER1_PEER_ID));
        let ip: std::net::IpAddr = test::DEVELOPER1_PEER_IP.parse()?;
        let announcement = innernet_shared::announcement::Announcement {
            timestamp: innernet_shared::announcement::timestamp_now(),
            claims: innernet_shared::announcement::Claims {
                delegation: vec![Prefix::host(ip)],
                ..Default::default()
            },
            primary_ip: Some(ip),
            endpoints: vec![
                "198.51.100.2:51820".parse().unwrap(),
                "198.51.100.1:51820".parse().unwrap(),
            ],
            ..Default::default()
        };
        let res = server
            .form_request(
                test::DEVELOPER1_PEER_IP,
                "PUT",
                "/user/announcement",
                server.sign(&keypair, &announcement),
            )
            .await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        let res = server.request(test::ADMIN_PEER_IP, "GET", &path).await;
        let endpoints: PeerEndpoints = test::cbor_body(res).await?;
        assert_eq!(endpoints.endpoints, announcement.endpoints);

        // An admin can't set them, nor can a non-admin read them.
        for method in ["PUT", "DELETE"] {
            let res = server
                .form_request(test::ADMIN_PEER_IP, method, &path, &endpoints)
                .await;
            test::blank_problem(res, StatusCode::NOT_FOUND).await?;
        }
        let res = server.request(test::DEVELOPER2_PEER_IP, "GET", &path).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // Any other path under a peer is not found, rather than routed to the peer itself, and
        // the endpoints are not reached by ID.
        let peer_path = key_path(&server, test::DEVELOPER1_PEER_ID);
        let id_path = format!("/admin/peers/{}/endpoints", test::DEVELOPER1_PEER_ID);
        for path in [
            format!("{peer_path}/other"),
            format!("{path}/other"),
            id_path.clone(),
        ] {
            for method in ["GET", "PUT", "DELETE"] {
                let res = server
                    .form_request(test::ADMIN_PEER_IP, method, &path, &endpoints)
                    .await;
                test::blank_problem(res, StatusCode::NOT_FOUND).await?;
            }
        }
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
        let path = format!("/admin/peers/{}", invitee.api_path_segment());
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
        test::problem(res, &problem::NO_SUCH_PEER).await?;
        let invitee = DatabasePeer::get_by_address(&server.db.lock(), ip.parse()?)?;
        assert_eq!(invitee.name.as_deref(), Some("invitee"));
        Ok(())
    }

    #[tokio::test]
    async fn test_tls_sessions_refuse_ids() -> Result<(), Error> {
        let server = test::Server::new()?;
        let old_peer = peer(&server, test::DEVELOPER1_PEER_ID);
        let id_path = format!("/admin/peers/{}", test::DEVELOPER1_PEER_ID);

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
            .request(test::DEVELOPER1_PEER_IP, "GET", "/user/state")
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
            .form_request(test::ADMIN_PEER_IP, "POST", "/admin/peers", &peer)
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn test_list_all_peers_from_admin() -> Result<(), Error> {
        let server = test::Server::new()?;
        let res = server
            .request(test::ADMIN_PEER_IP, "GET", "/admin/peers")
            .await;

        assert_eq!(res.status(), StatusCode::OK);

        let peers: Vec<PeerContents> = test::cbor_body(res).await?;
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
        let cbor = |res: Response<Body>| async {
            let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
            cbor_core::Value::decode_owned(&body).unwrap()
        };

        // The admin API lists and creates peers without IDs.
        let res = server
            .request(test::ADMIN_PEER_IP, "GET", "/admin/peers")
            .await;
        let peers = cbor(res).await;
        assert_eq!(peers.as_array().unwrap().len(), 6);
        assert!(peers
            .as_array()
            .unwrap()
            .iter()
            .all(|peer| peer.get("id").is_none()));
        let contents = test::developer_peer_contents("developer3", ip)?;
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/admin/peers", &contents)
            .await;
        assert_eq!(res.status(), StatusCode::CREATED);
        assert!(cbor(res).await.get("id").is_none());
        Ok(())
    }

    #[tokio::test]
    async fn test_list_all_peers_from_non_admin() -> Result<(), Error> {
        let server = test::Server::new()?;
        let res = server
            .request(test::DEVELOPER1_PEER_IP, "GET", "/admin/peers")
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
        let peer_path = format!("/admin/peers/{}", test::USER1_PEER_ID);
        for (method, path) in [
            ("GET", "/admin/peers"),
            ("POST", "/admin/peers"),
            ("PUT", &peer_path),
            ("DELETE", &peer_path),
            ("GET", "/admin/cidrs"),
            ("GET", "/admin/associations"),
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
            test::json_body::<serde_json::Value>(res).await.unwrap()
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
            .request(test::ADMIN_PEER_IP, "GET", "/admin/peers")
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = hyper::body::to_bytes(res.into_body()).await?;
        let listed = cbor_core::Value::decode_owned(&body).unwrap();
        let names: Vec<_> = listed
            .as_array()
            .unwrap()
            .iter()
            .map(|peer| &peer["name"])
            .collect();
        assert_eq!(names.len(), 6);
        assert_eq!(
            names
                .iter()
                .filter(|name| name.data_type().is_null())
                .count(),
            2
        );
        let res = server
            .request(test::USER1_PEER_IP, "GET", "/user/state")
            .await;
        let state: State = test::cbor_body(res).await?;
        assert_eq!(state.peers.iter().filter(|p| p.name.is_none()).count(), 2);

        // The view of plain-HTTP sessions is what the server's node core accepted. The user peers
        // have never announced, and the unsigned announcement that the server makes of a peer
        // releases no name, so they keep the names pinned to their keys. The view leaves out the
        // peers without a name, which clients that predate TLS can't read, such as a new peer
        // that is offered none.
        let nameless_ip = if cfg!(feature = "v6-test") {
            "fd00:1337::3:0:0:9"
        } else {
            "10.80.128.9"
        };
        DatabasePeer::create(
            &server.db().lock(),
            PeerContents {
                name: None,
                ..test::user_peer_contents("nameless", nameless_ip)?
            },
        )?;
        server.predate_tls(test::USER1_PEER_ID);
        let res = server
            .plain_request(test::USER1_PEER_IP, "GET", "/v1/user/state")
            .await;
        let state = json(res).await;
        let peers: Vec<LegacyPeer> = serde_json::from_value(state["peers"].clone())?;
        let names: Vec<_> = peers.iter().map(|peer| peer.name.as_deref()).collect();
        assert_eq!(
            names,
            [Some("innernet-server"), Some("user1"), Some("user2")]
        );

        Ok(())
    }
}
