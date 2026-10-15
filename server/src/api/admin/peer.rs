use std::collections::VecDeque;

use crate::{
    api::inject_endpoints,
    db::DatabasePeer,
    update_allowed_ips,
    util::{form_body, json_response, json_status_response, status_response},
    ServerError, Session,
};
use hyper::{Body, Method, Request, Response, StatusCode};
use innernet_shared::{DelegationContents, PeerContents};
use ipnet::IpNet;
use wireguard_control::{DeviceUpdate, Key, PeerConfigBuilder};

/// A peer as a path segment of the admin API names it: by its ID, or by its public key in the
/// URL-safe base64 alphabet. Servers that predate public keys in paths answer 404 to them.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PeerRef {
    Id(i64),
    PublicKey(Key),
}

impl PeerRef {
    fn parse(segment: &str) -> Result<Self, ServerError> {
        if let Ok(id) = segment.parse() {
            return Ok(Self::Id(id));
        }
        let key = segment.replace('-', "+").replace('_', "/");
        Key::from_base64(&key)
            .map(Self::PublicKey)
            .map_err(|_| ServerError::NotFound)
    }

    fn get(&self, conn: &rusqlite::Connection) -> Result<DatabasePeer, ServerError> {
        Ok(match self {
            Self::Id(id) => DatabasePeer::get(conn, *id)?,
            Self::PublicKey(key) => DatabasePeer::get_from_public_key(conn, key)?,
        })
    }
}

/// Parses the next path segment as a [`PeerRef`].
fn next_peer(components: &mut VecDeque<String>) -> Result<PeerRef, ServerError> {
    PeerRef::parse(&components.pop_front().ok_or(ServerError::NotFound)?)
}

pub async fn routes(
    req: Request<Body>,
    mut components: VecDeque<String>,
    session: Session,
) -> Result<Response<Body>, ServerError> {
    match (req.method(), components.pop_front().as_deref()) {
        (&Method::GET, None) => handlers::list(session).await,
        (&Method::POST, None) => {
            let form = form_body(req).await?;
            handlers::create(form, session).await
        },
        (&Method::PUT, Some(peer)) => {
            let peer = PeerRef::parse(peer)?;
            let form = form_body(req).await?;
            handlers::update(peer, form, session).await
        },
        // Deliberately not `/peers/{id}/permanent`: servers without this endpoint would
        // route that to `delete` (disable) and report success.
        (&Method::DELETE, Some("permanent")) => {
            let peer = next_peer(&mut components)?;
            handlers::delete_permanently(peer, session).await
        },
        // Likewise not under `/peers/{id}/`, so that older servers answer 404.
        (&Method::POST, Some("delegations")) => {
            let peer = next_peer(&mut components)?;
            let form = form_body(req).await?;
            handlers::add_delegation(peer, form, session).await
        },
        // The prefix ends the path, as in `/peers/delegations/{id}/10.42.1.32/28`.
        (&Method::DELETE, Some("delegations")) => {
            let peer = next_peer(&mut components)?;
            let prefix: IpNet = Vec::from(components)
                .join("/")
                .parse()
                .map_err(|_| ServerError::InvalidQuery)?;
            handlers::remove_delegation(peer, prefix, session).await
        },
        (&Method::DELETE, Some(peer)) => {
            let peer = PeerRef::parse(peer)?;
            handlers::delete(peer, session).await
        },
        _ => Err(ServerError::NotFound),
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

        if cfg!(not(test)) {
            // Update the current WireGuard interface with the new peers.
            DeviceUpdate::new()
                .add_peer(PeerConfigBuilder::from(&*peer))
                .apply(&session.context.interface, session.context.backend)
                .map_err(|_| ServerError::WireGuard)?;
            log::info!("updated WireGuard interface, adding {}", *peer);
        }

        json_status_response(&*peer, StatusCode::CREATED)
    }

    pub async fn update(
        peer: PeerRef,
        form: PeerContents,
        session: Session,
    ) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        let mut peer = peer.get(&conn)?;
        peer.update(&conn, form)?;

        status_response(StatusCode::NO_CONTENT)
    }

    /// List all peers, including disabled ones. This is an admin-only endpoint.
    pub async fn list(session: Session) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        let mut peers = DatabasePeer::list(&conn)?
            .into_iter()
            .map(|peer| peer.inner)
            .collect::<Vec<_>>();
        inject_endpoints(&session, &mut peers);
        json_response(&peers)
    }

    pub async fn delete(peer: PeerRef, session: Session) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        DatabasePeer::disable(&conn, peer.get(&conn)?.id)?;

        status_response(StatusCode::NO_CONTENT)
    }

    /// Permanently deletes a disabled peer, freeing its name and IP for reuse.
    pub async fn delete_permanently(
        peer: PeerRef,
        session: Session,
    ) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        let peer = peer.get(&conn)?;
        DatabasePeer::delete(&conn, peer.id)?;
        log::info!("permanently deleted peer {}", *peer);

        if cfg!(not(test)) {
            // Disabled peers should already be absent from the interface; the removal is
            // repeated as a safeguard.
            let public_key =
                Key::from_base64(&peer.public_key).map_err(|_| ServerError::WireGuard)?;
            DeviceUpdate::new()
                .remove_peer_by_key(&public_key)
                .apply(&session.context.interface, session.context.backend)
                .map_err(|_| ServerError::WireGuard)?;
        }

        status_response(StatusCode::NO_CONTENT)
    }

    /// Delegates a prefix of its CIDR to a peer, as if it were that many more peers.
    pub async fn add_delegation(
        peer: PeerRef,
        form: DelegationContents,
        session: Session,
    ) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        let mut peer = peer.get(&conn)?;
        peer.add_delegation(&conn, form.prefix)?;
        log::info!("delegated {} to peer {}", form.prefix, *peer);

        if cfg!(not(test)) {
            update_allowed_ips(&peer, &session.context.interface, session.context.backend)?;
        }

        json_status_response(&*peer, StatusCode::CREATED)
    }

    /// Withdraws a prefix delegated to a peer.
    pub async fn remove_delegation(
        peer: PeerRef,
        prefix: IpNet,
        session: Session,
    ) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        let mut peer = peer.get(&conn)?;
        peer.remove_delegation(&conn, prefix)?;
        log::info!("withdrew {} from peer {}", prefix, *peer);

        if cfg!(not(test)) {
            update_allowed_ips(&peer, &session.context.interface, session.context.backend)?;
        }

        status_response(StatusCode::NO_CONTENT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test;
    use bytes::Buf;
    use innernet_shared::{Error, Peer};

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
        let peer_res: Peer = serde_json::from_reader(whole_body.reader())?;

        assert_eq!(peer, peer_res.contents);

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

        // Try to add a peer to the root CIDR, at an IP that no child CIDR covers.
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

    #[tokio::test]
    async fn test_update_peer_from_admin() -> Result<(), Error> {
        let server = test::Server::new()?;
        let old_peer = DatabasePeer::get(&server.db.lock(), test::DEVELOPER1_PEER_ID)?;

        let change = PeerContents {
            name: Some("new-peer-name".parse().unwrap()),
            ..old_peer.contents.clone()
        };

        // Try to create a new developer peer from a user peer.
        let res = server
            .form_request(
                test::ADMIN_PEER_IP,
                "PUT",
                &format!("/v1/admin/peers/{}", test::DEVELOPER1_PEER_ID),
                &change,
            )
            .await;

        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let new_peer = DatabasePeer::get(&server.db.lock(), test::DEVELOPER1_PEER_ID)?;
        assert_eq!(new_peer.name.as_deref(), Some("new-peer-name"));
        Ok(())
    }

    #[tokio::test]
    async fn test_update_leaves_peer_owned_fields() -> Result<(), Error> {
        let server = test::Server::new()?;
        let old_peer = DatabasePeer::get(&server.db.lock(), test::DEVELOPER1_PEER_ID)?;

        // An admin's update that also carries an endpoint and candidates, as a listing of the
        // peer with its observed endpoint injected does.
        let change = PeerContents {
            name: Some("new-peer-name".parse().unwrap()),
            endpoint: Some("198.51.100.1:51820".parse().unwrap()),
            candidates: vec!["198.51.100.2:51820".parse().unwrap()],
            ..old_peer.contents.clone()
        };
        let path = format!("/v1/admin/peers/{}", test::DEVELOPER1_PEER_ID);
        let res = server
            .form_request(test::ADMIN_PEER_IP, "PUT", &path, &change)
            .await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let new_peer = DatabasePeer::get(&server.db.lock(), test::DEVELOPER1_PEER_ID)?;
        assert_eq!(new_peer.name.as_deref(), Some("new-peer-name"));
        assert_eq!(new_peer.endpoint, old_peer.endpoint);
        assert_eq!(new_peer.candidates, old_peer.candidates);
        Ok(())
    }

    #[tokio::test]
    async fn test_promotion_requires_tls() -> Result<(), Error> {
        let server = test::Server::new()?;
        let promote = || async {
            let peer = DatabasePeer::get(&server.db.lock(), test::DEVELOPER1_PEER_ID).unwrap();
            let change = PeerContents {
                is_admin: true,
                ..peer.contents.clone()
            };
            server
                .form_request(
                    test::ADMIN_PEER_IP,
                    "PUT",
                    &format!("/v1/admin/peers/{}", test::DEVELOPER1_PEER_ID),
                    &change,
                )
                .await
        };

        // The peer has only been seen in plain HTTP.
        assert_eq!(promote().await.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(!DatabasePeer::get(&server.db.lock(), test::DEVELOPER1_PEER_ID)?.is_admin);

        // Once it has connected over TLS, it can be.
        let res = server
            .request(test::DEVELOPER1_PEER_IP, "GET", "/v1/user/state")
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(promote().await.status(), StatusCode::NO_CONTENT);
        assert!(DatabasePeer::get(&server.db.lock(), test::DEVELOPER1_PEER_ID)?.is_admin);
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
    async fn test_update_peer_from_non_admin() -> Result<(), Error> {
        let server = test::Server::new()?;

        let peer = test::developer_peer_contents("developer3", "10.80.64.4")?;

        // Try to create a new developer peer from a user peer.
        let res = server
            .form_request(
                test::USER1_PEER_IP,
                "PUT",
                &format!("/v1/admin/peers/{}", test::DEVELOPER1_PEER_ID),
                &peer,
            )
            .await;

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

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
        let peers: Vec<Peer> = serde_json::from_reader(whole_body.reader())?;
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
    async fn test_list_all_peers_from_non_admin() -> Result<(), Error> {
        let server = test::Server::new()?;
        let res = server
            .request(test::DEVELOPER1_PEER_IP, "GET", "/v1/admin/peers")
            .await;

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[tokio::test]
    async fn test_delete() -> Result<(), Error> {
        let server = test::Server::new()?;
        let old_peers = DatabasePeer::list(&server.db().lock())?;

        let res = server
            .request(
                test::ADMIN_PEER_IP,
                "DELETE",
                &format!("/v1/admin/peers/{}", test::USER1_PEER_ID),
            )
            .await;

        assert!(res.status().is_success());

        // The number of peer entries in the database decreased by 1.
        let all_peers = DatabasePeer::list(&server.db().lock())?;
        let new_peers = all_peers.iter().filter(|p| !p.is_disabled).count();
        assert_eq!(old_peers.len() - 1, new_peers);

        Ok(())
    }

    #[tokio::test]
    async fn test_delete_from_non_admin() -> Result<(), Error> {
        let server = test::Server::new()?;

        let old_peers = DatabasePeer::list(&server.db().lock())?;

        let res = server
            .request(
                test::DEVELOPER1_PEER_IP,
                "DELETE",
                &format!("/v1/admin/peers/{}", test::USER1_PEER_ID),
            )
            .await;

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // The number of peer entries in the database hasn't changed.
        let new_peers = DatabasePeer::list(&server.db().lock())?;
        assert_eq!(old_peers.len(), new_peers.len());

        Ok(())
    }

    #[tokio::test]
    async fn test_delete_unknown_id() -> Result<(), Error> {
        let server = test::Server::new()?;

        let res = server
            .request(
                test::ADMIN_PEER_IP,
                "DELETE",
                &format!("/v1/admin/peers/{}", test::USER1_PEER_ID + 100),
            )
            .await;

        // Trying to delete a peer of non-existing ID will result in error.
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        Ok(())
    }

    #[tokio::test]
    async fn test_permanent_delete_api() -> Result<(), Error> {
        let server = test::Server::new()?;
        let path = format!("/v1/admin/peers/permanent/{}", test::USER1_PEER_ID);

        // Enabled peers can't be permanently deleted.
        let res = server.request(test::ADMIN_PEER_IP, "DELETE", &path).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        DatabasePeer::disable(&server.db().lock(), test::USER1_PEER_ID)?;

        // Non-admins can't permanently delete peers.
        let res = server
            .request(test::DEVELOPER1_PEER_IP, "DELETE", &path)
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        let res = server.request(test::ADMIN_PEER_IP, "DELETE", &path).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert!(DatabasePeer::get(&server.db().lock(), test::USER1_PEER_ID).is_err());

        // Already deleted.
        let res = server.request(test::ADMIN_PEER_IP, "DELETE", &path).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        // The IP can be reused.
        let peer = test::user_peer_contents("user1", test::USER1_PEER_IP)?;
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/peers", &peer)
            .await;
        assert_eq!(res.status(), StatusCode::CREATED);

        Ok(())
    }

    #[tokio::test]
    async fn test_permanent_delete_frees_ip() -> Result<(), Error> {
        let server = test::Server::new()?;
        let db = server.db();
        let conn = db.lock();

        // Enabled peers can't be permanently deleted.
        assert!(DatabasePeer::delete(&conn, test::USER1_PEER_ID).is_err());

        // While disabled, the peer still reserves its name and IP.
        DatabasePeer::disable(&conn, test::USER1_PEER_ID)?;
        assert!(DatabasePeer::create(
            &conn,
            test::user_peer_contents("user1", test::USER1_PEER_IP)?
        )
        .is_err());

        DatabasePeer::delete(&conn, test::USER1_PEER_ID)?;
        assert!(DatabasePeer::get(&conn, test::USER1_PEER_ID).is_err());

        let new_peer = DatabasePeer::create(
            &conn,
            test::user_peer_contents("user1", test::USER1_PEER_IP)?,
        )?;
        assert_eq!(new_peer.ip.to_string(), test::USER1_PEER_IP);

        Ok(())
    }

    #[tokio::test]
    async fn test_nameless_peers() -> Result<(), Error> {
        let server = test::Server::new()?;
        let db = server.db();
        let conn = db.lock();

        // Any number of peers can be without a name.
        for id in [test::USER1_PEER_ID, test::USER2_PEER_ID] {
            let mut peer = DatabasePeer::get(&conn, id)?;
            let contents = PeerContents {
                name: None,
                ..peer.contents.clone()
            };
            peer.update(&conn, contents)?;
            assert_eq!(DatabasePeer::get(&conn, id)?.name, None);
        }

        Ok(())
    }

    #[test]
    fn test_peer_ref_parse() {
        assert_eq!(PeerRef::parse("12").unwrap(), PeerRef::Id(12));

        // A key whose standard base64 holds both '+' and '/'.
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_mut(3) {
            chunk.copy_from_slice(&[0xfb, 0xff, 0xbf][..chunk.len()]);
        }
        let key = Key(bytes);
        let contents = PeerContents {
            public_key: key.to_base64(),
            ..test::peer_contents("peer", "10.80.64.9", test::DEVELOPER_CIDR_ID, false).unwrap()
        };
        let segment = contents.api_path_segment();
        assert!(contents.public_key.contains('+') && contents.public_key.contains('/'));
        assert!(!segment.contains('/'));
        assert_eq!(PeerRef::parse(&segment).unwrap(), PeerRef::PublicKey(key));

        assert!(PeerRef::parse("nonsense").is_err());
        assert!(PeerRef::parse("").is_err());
    }

    #[tokio::test]
    async fn test_routes_by_public_key() -> Result<(), Error> {
        let server = test::Server::new()?;
        let peer = |id| DatabasePeer::get(&server.db().lock(), id).unwrap();
        let developer1 = peer(test::DEVELOPER1_PEER_ID).api_path_segment();
        let user1 = peer(test::USER1_PEER_ID).api_path_segment();

        let change = PeerContents {
            name: Some("new-peer-name".parse().unwrap()),
            ..peer(test::DEVELOPER1_PEER_ID).contents.clone()
        };
        let path = format!("/v1/admin/peers/{developer1}");
        let res = server
            .form_request(test::ADMIN_PEER_IP, "PUT", &path, &change)
            .await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            peer(test::DEVELOPER1_PEER_ID).name.as_deref(),
            Some("new-peer-name")
        );

        let form = DelegationContents {
            prefix: test::DELEGATION.parse()?,
        };
        let path = format!("/v1/admin/peers/delegations/{developer1}");
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", &path, &form)
            .await;
        assert_eq!(res.status(), StatusCode::CREATED);
        assert_eq!(
            delegations(&server, test::DEVELOPER1_PEER_ID),
            [test::DELEGATION]
        );
        let path = format!(
            "/v1/admin/peers/delegations/{developer1}/{}",
            test::DELEGATION
        );
        let res = server.request(test::ADMIN_PEER_IP, "DELETE", &path).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert!(delegations(&server, test::DEVELOPER1_PEER_ID).is_empty());

        let path = format!("/v1/admin/peers/{user1}");
        let res = server.request(test::ADMIN_PEER_IP, "DELETE", &path).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert!(peer(test::USER1_PEER_ID).is_disabled);
        let path = format!("/v1/admin/peers/permanent/{user1}");
        let res = server.request(test::ADMIN_PEER_IP, "DELETE", &path).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert!(DatabasePeer::get(&server.db().lock(), test::USER1_PEER_ID).is_err());

        // A key that no peer has, and a segment that is neither an ID nor a key.
        for segment in [user1.as_str(), "nonsense"] {
            let path = format!("/v1/admin/peers/{segment}");
            let res = server
                .form_request(test::ADMIN_PEER_IP, "PUT", &path, &change)
                .await;
            assert_eq!(res.status(), StatusCode::NOT_FOUND);
        }

        Ok(())
    }

    async fn add_delegation(
        server: &test::Server,
        from: &str,
        id: i64,
        prefix: &str,
    ) -> StatusCode {
        let form = DelegationContents {
            prefix: prefix.parse().unwrap(),
        };
        let path = format!("/v1/admin/peers/delegations/{id}");
        server
            .form_request(from, "POST", &path, &form)
            .await
            .status()
    }

    async fn remove_delegation(
        server: &test::Server,
        from: &str,
        id: i64,
        prefix: &str,
    ) -> StatusCode {
        let path = format!("/v1/admin/peers/delegations/{id}/{prefix}");
        server.request(from, "DELETE", &path).await.status()
    }

    fn delegations(server: &test::Server, id: i64) -> Vec<String> {
        let peer = DatabasePeer::get(&server.db().lock(), id).unwrap();
        peer.delegations.iter().map(|d| d.to_string()).collect()
    }

    #[tokio::test]
    async fn test_add_delegation() -> Result<(), Error> {
        let server = test::Server::new()?;
        let form = DelegationContents {
            prefix: test::DELEGATION.parse()?,
        };
        let path = format!("/v1/admin/peers/delegations/{}", test::DEVELOPER1_PEER_ID);
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", &path, &form)
            .await;
        assert_eq!(res.status(), StatusCode::CREATED);
        let whole_body = hyper::body::aggregate(res).await?;
        let peer: Peer = serde_json::from_reader(whole_body.reader())?;
        assert_eq!(peer.delegations, vec![form.prefix]);
        assert_eq!(peer.ip.to_string(), test::DEVELOPER1_PEER_IP);
        assert_eq!(
            delegations(&server, test::DEVELOPER1_PEER_ID),
            [test::DELEGATION]
        );

        // A single address is a delegation too.
        let single = if cfg!(feature = "v6-test") {
            "fd00:1337::2:0:0:7/128"
        } else {
            "10.80.64.7/32"
        };
        assert_eq!(
            add_delegation(
                &server,
                test::ADMIN_PEER_IP,
                test::DEVELOPER1_PEER_ID,
                single
            )
            .await,
            StatusCode::CREATED
        );
        assert_eq!(delegations(&server, test::DEVELOPER1_PEER_ID).len(), 2);

        // Admins see the delegations of every peer.
        let res = server
            .request(test::ADMIN_PEER_IP, "GET", "/v1/admin/peers")
            .await;
        let whole_body = hyper::body::aggregate(res).await?;
        let peers: Vec<Peer> = serde_json::from_reader(whole_body.reader())?;
        let developer1 = peers.iter().find(|p| p.id == test::DEVELOPER1_PEER_ID);
        assert_eq!(developer1.unwrap().delegations.len(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn test_add_invalid_delegations() -> Result<(), Error> {
        let server = test::Server::new()?;
        let v6 = cfg!(feature = "v6-test");
        let pick = |v4, v6_prefix| if v6 { v6_prefix } else { v4 };

        // Peers that still hold their addresses although they don't show up to others.
        let disabled_ip = pick("10.80.64.9", "fd00:1337::2:0:0:9");
        let unredeemed_ip = pick("10.80.64.13", "fd00:1337::2:0:0:d");
        {
            let conn = server.db.lock();
            let mut contents = test::developer_peer_contents("disabled", disabled_ip)?;
            contents.is_disabled = true;
            DatabasePeer::create(&conn, contents)?;
            let mut contents = test::developer_peer_contents("unredeemed", unredeemed_ip)?;
            contents.is_redeemed = false;
            DatabasePeer::create(&conn, contents)?;
        }
        assert_eq!(
            add_delegation(
                &server,
                test::ADMIN_PEER_IP,
                test::DEVELOPER1_PEER_ID,
                test::DELEGATION
            )
            .await,
            StatusCode::CREATED
        );

        for (description, prefix) in [
            (
                "unaligned",
                pick("10.80.64.33/28", "fd00:1337::2:0:3:1/112"),
            ),
            (
                "outside the CIDR",
                pick("10.80.65.0/28", "fd00:1337::3:0:3:0/112"),
            ),
            ("of the other family", pick("fd00::/120", "10.80.64.32/28")),
            (
                "the network address",
                pick("10.80.64.0/32", "fd00:1337::2:0:0:0/128"),
            ),
            (
                "including the network address",
                pick("10.80.64.0/30", "fd00:1337::2:0:0:0/126"),
            ),
            // IPv6 has no broadcast address; the whole CIDR includes its network address.
            (
                "the broadcast address",
                pick("10.80.64.255/32", "fd00:1337::2:0:0:0/80"),
            ),
            (
                "including the broadcast address",
                pick("10.80.64.240/28", "fd00:1337::2:0:0:0/80"),
            ),
            (
                "its own IP",
                pick("10.80.64.2/32", "fd00:1337::2:0:0:1/128"),
            ),
            (
                "another peer's IP",
                pick("10.80.64.3/32", "fd00:1337::2:0:0:2/128"),
            ),
            (
                "a disabled peer's IP",
                pick("10.80.64.8/30", "fd00:1337::2:0:0:8/126"),
            ),
            (
                "an unredeemed peer's IP",
                pick("10.80.64.12/30", "fd00:1337::2:0:0:c/126"),
            ),
            ("an existing delegation", test::DELEGATION),
            (
                "inside a delegation",
                pick("10.80.64.40/29", "fd00:1337::2:0:3:80/121"),
            ),
            (
                "around a delegation",
                pick("10.80.64.32/27", "fd00:1337::2:0:2:0/111"),
            ),
        ] {
            for id in [test::DEVELOPER1_PEER_ID, test::DEVELOPER2_PEER_ID] {
                assert_eq!(
                    add_delegation(&server, test::ADMIN_PEER_IP, id, prefix).await,
                    StatusCode::BAD_REQUEST,
                    "delegating {description} ({prefix}) to peer {id}"
                );
            }
        }
        assert_eq!(
            delegations(&server, test::DEVELOPER1_PEER_ID),
            [test::DELEGATION]
        );
        assert!(delegations(&server, test::DEVELOPER2_PEER_ID).is_empty());

        // The server's own CIDR has no room for delegations.
        let server_prefix = pick("10.80.0.1/32", "fd00:1337::1/128");
        assert_eq!(
            add_delegation(&server, test::ADMIN_PEER_IP, 1, server_prefix).await,
            StatusCode::BAD_REQUEST
        );

        assert_eq!(
            add_delegation(&server, test::ADMIN_PEER_IP, 100, test::DELEGATION).await,
            StatusCode::NOT_FOUND
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_add_peer_inside_delegation() -> Result<(), Error> {
        let server = test::Server::new()?;
        assert_eq!(
            add_delegation(
                &server,
                test::ADMIN_PEER_IP,
                test::DEVELOPER1_PEER_ID,
                test::DELEGATION
            )
            .await,
            StatusCode::CREATED
        );

        let peer = test::developer_peer_contents("developer3", test::DELEGATED_IP)?;
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/peers", &peer)
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // Once the delegation is withdrawn, the address is free.
        assert_eq!(
            remove_delegation(
                &server,
                test::ADMIN_PEER_IP,
                test::DEVELOPER1_PEER_ID,
                test::DELEGATION
            )
            .await,
            StatusCode::NO_CONTENT
        );
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/peers", &peer)
            .await;
        assert_eq!(res.status(), StatusCode::CREATED);
        Ok(())
    }

    #[tokio::test]
    async fn test_delegations_from_non_admin() -> Result<(), Error> {
        let server = test::Server::new()?;
        let (id, prefix) = (test::DEVELOPER1_PEER_ID, test::DELEGATION);
        assert_eq!(
            add_delegation(&server, test::DEVELOPER1_PEER_IP, id, prefix).await,
            StatusCode::UNAUTHORIZED
        );
        assert!(delegations(&server, id).is_empty());

        assert_eq!(
            add_delegation(&server, test::ADMIN_PEER_IP, id, prefix).await,
            StatusCode::CREATED
        );
        assert_eq!(
            remove_delegation(&server, test::DEVELOPER1_PEER_IP, id, prefix).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(delegations(&server, id), [prefix]);
        Ok(())
    }

    #[tokio::test]
    async fn test_withdraw_and_reassign_delegation() -> Result<(), Error> {
        let server = test::Server::new()?;
        let prefix = test::DELEGATION;
        let (developer1, developer2) = (test::DEVELOPER1_PEER_ID, test::DEVELOPER2_PEER_ID);
        assert_eq!(
            add_delegation(&server, test::ADMIN_PEER_IP, developer1, prefix).await,
            StatusCode::CREATED
        );

        // Only the peer it is delegated to can have it withdrawn.
        assert_eq!(
            remove_delegation(&server, test::ADMIN_PEER_IP, developer2, prefix).await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            remove_delegation(&server, test::ADMIN_PEER_IP, developer1, prefix).await,
            StatusCode::NO_CONTENT
        );
        assert!(delegations(&server, developer1).is_empty());
        assert_eq!(
            remove_delegation(&server, test::ADMIN_PEER_IP, developer1, prefix).await,
            StatusCode::NOT_FOUND
        );

        // A malformed prefix.
        let path = format!("/v1/admin/peers/delegations/{developer1}/nonsense");
        let res = server.request(test::ADMIN_PEER_IP, "DELETE", &path).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // A withdrawn prefix can be delegated again, to another peer as well.
        assert_eq!(
            add_delegation(&server, test::ADMIN_PEER_IP, developer2, prefix).await,
            StatusCode::CREATED
        );
        assert_eq!(delegations(&server, developer2), [prefix]);
        Ok(())
    }

    #[tokio::test]
    async fn test_permanent_delete_frees_delegations() -> Result<(), Error> {
        let server = test::Server::new()?;
        let prefix = test::DELEGATION;
        assert_eq!(
            add_delegation(
                &server,
                test::ADMIN_PEER_IP,
                test::DEVELOPER1_PEER_ID,
                prefix
            )
            .await,
            StatusCode::CREATED
        );
        {
            let conn = server.db.lock();
            DatabasePeer::disable(&conn, test::DEVELOPER1_PEER_ID)?;
            // While disabled, the peer still holds its delegations.
            let peer = DatabasePeer::get(&conn, test::DEVELOPER1_PEER_ID)?;
            assert_eq!(peer.delegations, [prefix.parse()?]);
            DatabasePeer::delete(&conn, test::DEVELOPER1_PEER_ID)?;
            let count: u32 =
                conn.query_row("SELECT COUNT(*) FROM delegations", [], |row| row.get(0))?;
            assert_eq!(count, 0);
        }
        assert_eq!(
            add_delegation(
                &server,
                test::ADMIN_PEER_IP,
                test::DEVELOPER2_PEER_ID,
                prefix
            )
            .await,
            StatusCode::CREATED
        );
        Ok(())
    }
}
