use std::collections::VecDeque;

use crate::{
    api::{inject_endpoints, observed_endpoint},
    db::{DatabaseCidr, DatabasePeer},
    util::{form_body, form_response, status_response},
    ServerError, Session,
};
use hyper::{Body, Method, Request, Response, StatusCode};
use innernet_shared::{
    announcement::{self, Announcement, SignedAnnouncement},
    Endpoint, EndpointContents, LegacyCapabilities, LegacyState, RedeemContents,
    ServerCapabilities, State, REDEEM_TRANSITION_WAIT,
};

pub async fn routes(
    req: Request<Body>,
    mut components: VecDeque<String>,
    session: Session,
) -> Result<Response<Body>, ServerError> {
    match (req.method(), components.pop_front().as_deref()) {
        (&Method::GET, Some("state")) => {
            if !session.user_capable() {
                return Err(ServerError::Unauthorized);
            }
            handlers::state(session).await
        },
        (&Method::GET, Some("capabilities")) => handlers::capabilities(session).await,
        (&Method::POST, Some("redeem")) => {
            if !session.redeemable() {
                return Err(ServerError::Unauthorized);
            }
            let form = form_body(req, &session).await?;
            handlers::redeem(form, session).await
        },
        // A peer that speaks TLS states its endpoints in its announcements, so only a peer whose
        // client predates TLS sets an endpoint and candidates on their own, which its unsigned
        // announcement lists in that order.
        (&Method::PUT, Some("endpoint")) if !session.over_tls => {
            if !session.user_capable() {
                return Err(ServerError::Unauthorized);
            }
            let form = form_body(req, &session).await?;
            handlers::endpoint(form, session).await
        },
        (&Method::PUT, Some("candidates")) if !session.over_tls => {
            if !session.user_capable() {
                return Err(ServerError::Unauthorized);
            }
            let form = form_body(req, &session).await?;
            handlers::candidates(form, session).await
        },
        (&Method::PUT, Some("announcement")) if session.over_tls => {
            if !session.user_capable() {
                return Err(ServerError::Unauthorized);
            }
            let form = form_body(req, &session).await?;
            handlers::announcement(form, session).await
        },
        _ => Err(ServerError::NotFound),
    }
}

mod handlers {

    use super::*;

    /// Get the current state of the network, in the eyes of the current peer.
    ///
    /// This endpoint returns the visible CIDRs and Peers, providing all the necessary
    /// information for the peer to create connections to all of them.
    ///
    /// A TLS session gets the peers and the CIDRs without IDs, each peer with its announcement,
    /// which the client checks and makes the peer of itself, and the endpoint at which the server
    /// observes the peer of the session, which that peer may state in its announcements. For a peer
    /// that has never announced, the server makes an unsigned announcement of what it records of
    /// the peer, as [`Announcement::synthetic`] makes it, so that every peer comes with one. The
    /// ranges that the server assigns a peer are its own business: the peer of the session gets its
    /// own, so that its client can choose its claims among them, and no other peer's. A plain-HTTP
    /// session gets them with the IDs that [`DatabasePeer::plain_http_ids`] and
    /// [`DatabaseCidr::id_of`] number them by, as clients that predate TLS use them, each peer with
    /// the ID of its CIDR and each CIDR with that of its parent, each peer as its announcement
    /// makes it, since such clients can't check announcements, and without the peers that have no
    /// name, which such clients can't read. Such a client takes a peer that it no longer sees for
    /// disabled.
    pub async fn state(session: Session) -> Result<Response<Body>, ServerError> {
        let store = session.context.db.lock();
        let selected_peer = session.peer.reload(&store)?;

        let cidrs = DatabaseCidr::list(&store)?;

        let mut peers = selected_peer.get_all_allowed_peers(&store, &session.context.public_key)?;
        inject_endpoints(&session, peers.iter_mut().map(|peer| &mut peer.inner));
        if session.over_tls {
            form_response(
                &session,
                State {
                    peers: peers
                        .into_iter()
                        .map(|peer| {
                            let mut peer = peer.inner;
                            if peer.announcement.is_none() {
                                let synthetic = Announcement::synthetic(&peer);
                                match SignedAnnouncement::unsigned(&synthetic) {
                                    Ok(unsigned) => peer.announcement = Some(unsigned),
                                    Err(e) => log::warn!(
                                        "relaying peer {} without an announcement: {e}",
                                        peer.public_key
                                    ),
                                }
                            }
                            if peer.public_key != selected_peer.public_key {
                                peer.delegations = vec![];
                            }
                            peer
                        })
                        .collect(),
                    cidrs: cidrs.iter().map(DatabaseCidr::contents).collect(),
                    observed_endpoint: observed_endpoint(&session, &selected_peer.public_key),
                    invalid_peer_keys: vec![],
                },
            )
        } else {
            let ids = DatabasePeer::plain_http_ids(&store)?;
            form_response(
                &session,
                LegacyState {
                    peers: peers
                        .iter()
                        .filter_map(|peer| peer.legacy(ids[&peer.public_key], &cidrs))
                        .collect(),
                    cidrs: cidrs.iter().map(|cidr| cidr.legacy(&cidrs)).collect(),
                    invalid_peer_keys: vec![],
                },
            )
        }
    }

    /// What the server supports, and the QUIC port of its TLS API, which a client upgraded from
    /// v2.0.0 asks for in plain HTTP, even once the server requires TLS of it, and which clients
    /// that predate TLS ignore. A plain-HTTP session is told, as such clients read it, that the
    /// server fills in an unspecified host at `PUT /v1/user/endpoint`; a TLS session is told the
    /// types of claims that the server checks in announcements instead.
    pub async fn capabilities(session: Session) -> Result<Response<Body>, ServerError> {
        let quic_port = Some(session.context.quic_port);
        if !session.over_tls {
            let capabilities = LegacyCapabilities {
                unspecified_ip_in_override_endpoint: true,
                quic_port,
            };
            return form_response(&session, capabilities);
        }
        let capabilities = ServerCapabilities {
            quic_port,
            announcement_claims: announcement::CLAIM_TYPES.map(String::from).to_vec(),
        };

        form_response(&session, capabilities)
    }

    /// Redeems an invitation. An invitation includes a WireGuard keypair generated by either the
    /// server or a peer with admin rights.
    ///
    /// Redemption is the process of an invitee generating their own keypair and exchanging their
    /// temporary key with their permanent one.
    ///
    /// Until this API endpoint is called, the invited peer will not show up to other peers, and
    /// once it is called and succeeds, it cannot be called again.
    pub async fn redeem(
        form: RedeemContents,
        session: Session,
    ) -> Result<Response<Body>, ServerError> {
        let store = session.context.db.lock();
        let mut selected_peer = session.peer.reload(&store)?;

        selected_peer.redeem(&store, &form.public_key)?;

        session.context.invitations.notify_one();
        // If the node were to change the WireGuard interface at once, the HTTP response wouldn't
        // get through. Instead, the node is told after a wait long enough for the response to
        // flush, which the client also waits after a success of /redeem.
        //
        // Related: https://github.com/hyperium/hyper/issues/2181
        let changed = session.context.changed.clone();
        tokio::task::spawn(async move {
            tokio::time::sleep(REDEEM_TRANSITION_WAIT).await;
            log::info!(
                "WireGuard: replacing the invitation's key with {}'s",
                *selected_peer
            );
            changed.notify();
        });
        status_response(StatusCode::NO_CONTENT)
    }

    /// Accepts an announcement of the peer, which states its endpoints, and claims what it
    /// accepts of the resources that the server assigns it, as [`DatabasePeer::announce`]
    /// checks it. The node is told, since the delegations routed to the peer may have changed.
    pub async fn announcement(
        signed: SignedAnnouncement,
        session: Session,
    ) -> Result<Response<Body>, ServerError> {
        let store = session.context.db.lock();
        let mut selected_peer = session.peer.reload(&store)?;
        selected_peer.announce(&store, signed, announcement::timestamp_now())?;
        log::info!("{} announced.", *selected_peer);
        session.context.changed.notify();

        status_response(StatusCode::NO_CONTENT)
    }

    /// Report any other endpoint candidates that can be tried by peers to connect.
    /// Currently limited to 10 candidates max.
    pub async fn candidates(
        contents: Vec<Endpoint>,
        session: Session,
    ) -> Result<Response<Body>, ServerError> {
        if contents.len() > 10 {
            return status_response(StatusCode::PAYLOAD_TOO_LARGE);
        }
        let store = session.context.db.lock();
        let mut selected_peer = session.peer.reload(&store)?;
        selected_peer.set_candidates(&store, contents)?;

        status_response(StatusCode::NO_CONTENT)
    }

    /// Force a specific endpoint to be reported by the server.
    pub async fn endpoint(
        contents: EndpointContents,
        session: Session,
    ) -> Result<Response<Body>, ServerError> {
        let store = session.context.db.lock();
        let mut selected_peer = session.peer.reload(&store)?;
        selected_peer.set_endpoint(&store, contents.into())?;

        status_response(StatusCode::NO_CONTENT)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::{db::DatabaseAssociation, test};
    use innernet_shared::{
        announcement::{Announcement, Claims},
        media_type, Association, Endpoint, EndpointContents, Error, LegacyPeer, LegacyState,
        PeerContents, Prefix,
    };

    #[tokio::test]
    async fn test_get_state_from_developer1() -> Result<(), Error> {
        let server = test::Server::new()?;
        let res = server
            .request(test::DEVELOPER1_PEER_IP, "GET", "/user/state")
            .await;

        assert_eq!(res.status(), StatusCode::OK);

        let State { peers, .. } = test::cbor_body(res).await?;
        let mut peer_names = peers
            .iter()
            .map(|p| p.name.as_deref().unwrap())
            .collect::<Vec<_>>();
        peer_names.sort_unstable();
        // Developers should see only peers in infra CIDR and developer CIDR.
        assert_eq!(
            &["developer1", "developer2", "innernet-server"],
            &peer_names[..]
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_tls_sessions_speak_cbor() -> Result<(), Error> {
        let server = test::Server::new()?;
        let ip = test::DEVELOPER1_PEER_IP;

        // The state is sent in the deterministic encoding of CBOR, so that it encodes again to
        // the same bytes, in the version that the request accepts.
        let res = server.request(ip, "GET", "/user/state").await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers()["Content-Type"],
            "application/vnd.innernet+cbor; version=1"
        );
        let body = hyper::body::to_bytes(res.into_body()).await?;
        let state: State = innernet_shared::cbor::from_slice(&body)?;
        assert_eq!(innernet_shared::cbor::to_vec(&state)?, body);

        // A body in any other content type, without a version or with one that the server
        // doesn't read, or without a content type, is refused, as is any other content type on a
        // request without a body.
        let keypair = server.keypair(test::DEVELOPER1_PEER_ID);
        let announce = || server.sign(&keypair, &developer1_announcement());
        let json = serde_json::to_vec(&announce())?;
        let cbor = innernet_shared::cbor::to_vec(&announce())?;
        for (content_type, body) in [
            ("application/json", json.clone()),
            ("application/x-www-form-urlencoded", json.clone()),
            ("application/cbor", cbor.clone()),
            ("application/vnd.innernet+cbor", cbor.clone()),
            ("application/vnd.innernet+cbor; version=2", cbor.clone()),
            ("application/vnd.innernet+cbor; version=01", cbor.clone()),
        ] {
            let req = server.body_request("PUT", "/user/announcement", content_type, body);
            let res = server.raw_request(ip, req).await;
            assert_eq!(
                res.status(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "{content_type}"
            );
        }
        let mut req = server.body_request("PUT", "/user/announcement", "", cbor.clone());
        req.headers_mut().remove("Content-Type");
        let res = server.raw_request(ip, req).await;
        assert_eq!(res.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let req = server.body_request("GET", "/user/state", "application/json", vec![]);
        let res = server.raw_request(ip, req).await;
        assert_eq!(res.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        // CBOR in another encoding than the deterministic one is refused: here, the length of
        // the map in two bytes rather than one.
        let mut longer = vec![0xb8, 0x02];
        longer.extend_from_slice(&cbor[1..]);
        let req = server.body_request("PUT", "/user/announcement", &test::content_type(), longer);
        let res = server.raw_request(ip, req).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        let content_type = "Application/VND.innernet+CBOR; Version=\"1\"";
        let req = server.body_request("PUT", "/user/announcement", content_type, cbor);
        let res = server.raw_request(ip, req).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        // A plain-HTTP session still speaks JSON, whatever content type it states.
        server.predate_tls(test::DEVELOPER2_PEER_ID);
        let ip = test::DEVELOPER2_PEER_IP;
        let candidates = vec!["1.1.1.1:51820".parse::<Endpoint>().unwrap()];
        let json = serde_json::to_vec(&candidates)?;
        let req = server.body_request("PUT", "/v1/user/candidates", "text/plain", json);
        let res = server.raw_request_as(ip, None, req).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        let res = server.plain_request(ip, "GET", "/v1/user/state").await;
        assert_eq!(res.headers()["Content-Type"], "application/json");
        Ok(())
    }

    #[tokio::test]
    async fn test_tls_sessions_negotiate_the_version() -> Result<(), Error> {
        let server = test::Server::new()?;
        let ip = test::DEVELOPER1_PEER_IP;
        let get = |accept: Option<&str>| {
            let mut req = server.body_request("GET", "/user/state", "", vec![]);
            req.headers_mut().remove("Content-Type");
            req.headers_mut().remove("Accept");
            if let Some(accept) = accept {
                req.headers_mut().insert("Accept", accept.parse().unwrap());
            }
            server.raw_request(ip, req)
        };

        // A version that the server writes is answered in CBOR, whatever else the request
        // accepts.
        let ours = "application/vnd.innernet+cbor";
        for accept in [
            format!("{ours}; version=1"),
            format!("{ours}; version=2, {ours}; version=1; q=0.5, */*"),
            format!("application/problem+cbor, {ours};version=\"1\""),
        ] {
            let res = get(Some(&accept)).await;
            assert_eq!(res.status(), StatusCode::OK, "{accept}");
            let _: State = test::cbor_body(res).await?;
        }

        // A request that accepts none is refused, an entry without a version being malformed.
        for accept in [
            format!("{ours}; version=2"),
            ours.to_string(),
            format!("{ours}; version=1; q=0"),
            "application/cbor".to_string(),
            "text/*".to_string(),
        ] {
            let res = get(Some(&accept)).await;
            assert_eq!(res.status(), StatusCode::NOT_ACCEPTABLE, "{accept}");
        }

        // A request without Accept, or with a wildcard, gets the debug view of the newest version.
        for accept in [
            None,
            Some("*/*"),
            Some("application/*"),
            Some("text/plain, */*"),
        ] {
            let res = get(accept).await;
            assert_eq!(res.status(), StatusCode::OK, "{accept:?}");
            assert_eq!(
                res.headers()["Content-Type"],
                "application/vnd.innernet+cbor-diagnostic; version=1"
            );
            let body = hyper::body::to_bytes(res.into_body()).await?;
            let text = String::from_utf8(body.to_vec())?;
            let (comment, notation) = text.split_once('\n').unwrap();
            assert_eq!(
                comment,
                "# unstable debug view; use Accept: application/vnd.innernet+cbor; version=1"
            );
            assert!(notation.contains("\"peers\": ["), "{notation}");
        }

        // The debug view never answers a change: a change must name a version in Accept.
        let keypair = server.keypair(test::DEVELOPER1_PEER_ID);
        let cbor =
            innernet_shared::cbor::to_vec(&server.sign(&keypair, &developer1_announcement()))?;
        for accept in [None, Some("*/*"), Some(ours)] {
            let mut req = server.body_request(
                "PUT",
                "/user/announcement",
                &test::content_type(),
                cbor.clone(),
            );
            req.headers_mut().remove("Accept");
            if let Some(accept) = accept {
                req.headers_mut().insert("Accept", accept.parse().unwrap());
            }
            let res = server.raw_request(ip, req).await;
            assert_eq!(res.status(), StatusCode::NOT_ACCEPTABLE, "{accept:?}");
        }
        let req = server.body_request("PUT", "/user/announcement", &test::content_type(), cbor);
        let res = server.raw_request(ip, req).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        // A change that has nothing to send, such as the deletion of an association, carries
        // neither a body nor a content type, and names its version in Accept as every change
        // does. A content type announces a body, so a request that states one without a body is
        // refused, since an empty body is no CBOR.
        let admin = test::ADMIN_PEER_IP;
        let association = Association {
            cidr_1: test::USER_CIDR.parse()?,
            cidr_2: test::DEVELOPER_CIDR.parse()?,
        };
        let res = server
            .form_request(admin, "POST", "/admin/associations", association)
            .await;
        assert_eq!(res.status(), StatusCode::CREATED);
        let path = format!("/admin/associations/{}", association.api_path());
        let delete = |accept: &str, content_type: Option<String>| {
            let mut req = server.body_request("DELETE", &path, "", vec![]);
            req.headers_mut().remove("Content-Length");
            req.headers_mut().remove("Content-Type");
            if let Some(content_type) = content_type {
                req.headers_mut()
                    .insert("Content-Type", content_type.parse().unwrap());
            }
            req.headers_mut().insert("Accept", accept.parse().unwrap());
            server.raw_request(admin, req)
        };
        let res = delete("*/*", None).await;
        assert_eq!(res.status(), StatusCode::NOT_ACCEPTABLE);
        let res = delete(&media_type::accept(), Some(test::content_type())).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let res = delete(&media_type::accept(), None).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert!(DatabaseAssociation::list(&server.db.lock())?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_capabilities_state_the_quic_port() -> Result<(), Error> {
        let server = test::Server::new()?;

        // A peer that is required to connect over TLS may still ask for the capabilities in plain
        // HTTP, which state the QUIC port of the TLS API, but nothing else.
        let ip = test::DEVELOPER1_PEER_IP;
        let res = server
            .plain_request(ip, "GET", "/v1/user/capabilities")
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        let capabilities: serde_json::Value = test::json_body(res).await?;
        assert_eq!(capabilities["quic_port"], 54322);
        assert_eq!(capabilities["unspecified_ip_in_override_endpoint"], true);
        let res = server.plain_request(ip, "GET", "/v1/user/state").await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let res = server
            .plain_request(ip, "PUT", "/v1/user/capabilities")
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // An unknown address learns nothing.
        let res = server
            .plain_request(
                test::EXPERIMENT_SUBCIDR_PEER_IP,
                "GET",
                "/v1/user/capabilities",
            )
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // Over TLS, the capabilities state it too, but not that the server fills in an
        // unspecified host, which only a peer that sets its own endpoint needs.
        let res = server.request(ip, "GET", "/user/capabilities").await;
        let capabilities: ServerCapabilities = test::cbor_body(res).await?;
        assert_eq!(capabilities.quic_port, Some(54322));
        let res = server.request(ip, "GET", "/user/capabilities").await;
        let members: std::collections::BTreeMap<String, serde::de::IgnoredAny> =
            test::cbor_body(res).await?;
        assert!(!members.contains_key("unspecified_ip_in_override_endpoint"));
        Ok(())
    }

    #[tokio::test]
    async fn test_paths_by_transport() -> Result<(), Error> {
        let server = test::Server::new()?;
        server.predate_tls(test::DEVELOPER2_PEER_ID);

        // The API of TLS sessions has no version in its paths, and that of plain-HTTP sessions
        // stays under /v1, as clients that predate TLS know it.
        let ip = test::DEVELOPER1_PEER_IP;
        let res = server.request(ip, "GET", "/user/state").await;
        assert_eq!(res.status(), StatusCode::OK);
        let res = server.request(ip, "GET", "/v1/user/state").await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let res = server
            .plain_request(test::DEVELOPER2_PEER_IP, "GET", "/v1/user/state")
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        let res = server
            .plain_request(test::DEVELOPER2_PEER_IP, "GET", "/user/state")
            .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn test_state_has_ids_only_in_plain_http() -> Result<(), Error> {
        let server = test::Server::new()?;
        server.predate_tls(test::DEVELOPER2_PEER_ID);

        // A TLS session gets the peers without IDs, in CBOR.
        #[derive(serde::Deserialize)]
        struct Fields {
            peers: Vec<std::collections::BTreeMap<String, serde::de::IgnoredAny>>,
        }
        let res = server
            .request(test::DEVELOPER1_PEER_IP, "GET", "/user/state")
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        let Fields { peers } = test::cbor_body(res).await?;
        assert_eq!(peers.len(), 3);
        assert!(peers.iter().all(|peer| !peer.contains_key("id")));
        assert!(peers.iter().all(|peer| !peer.contains_key("cidr_id")));

        // A plain-HTTP session gets them with the IDs that the server names them by, in JSON.
        let res = server
            .plain_request(test::DEVELOPER2_PEER_IP, "GET", "/v1/user/state")
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        let state: serde_json::Value = test::json_body(res).await?;
        let peers: Vec<LegacyPeer> = serde_json::from_value(state["peers"].clone())?;
        assert_eq!(peers.len(), 3);
        let ids = DatabasePeer::plain_http_ids(&server.db().lock())?;
        for peer in peers {
            assert_eq!(peer.id, ids[&peer.public_key]);
        }

        // So do the CIDRs, each with the ID of its parent, and each peer with the ID of its CIDR.
        let res = server
            .plain_request(test::DEVELOPER2_PEER_IP, "GET", "/v1/user/state")
            .await;
        let state: LegacyState = test::json_body(res).await?;
        let developer = state
            .cidrs
            .iter()
            .find(|cidr| cidr.name == "developer")
            .unwrap();
        assert_eq!(developer.id, test::DEVELOPER_CIDR_ID);
        assert_eq!(developer.parent, Some(test::ROOT_CIDR_ID));
        let server_peer = test::peer(&server.db().lock(), test::SERVER_PEER_ID);
        for peer in &state.peers {
            let cidr_id = if peer.public_key == server_peer.public_key {
                test::INFRA_CIDR_ID
            } else {
                test::DEVELOPER_CIDR_ID
            };
            assert_eq!(peer.cidr_id, cidr_id, "{}", peer.public_key);
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_peers_without_a_delegation() -> Result<(), Error> {
        // A peer without a delegation has no CIDR, so no other peer sees it. It stays in the
        // admin listing of TLS sessions, with no delegations, and clients that predate TLS can't
        // represent it.
        let server = test::Server::new()?;
        let developer2 = test::peer(&server.db().lock(), test::DEVELOPER2_PEER_ID);
        server.db().lock().execute(
            "DELETE FROM delegations WHERE public_key = ?1",
            [wireguard_control::Key::from_base64(&developer2.public_key)?.0],
        )?;
        let res = server
            .request(test::DEVELOPER1_PEER_IP, "GET", "/user/state")
            .await;
        let State { peers, .. } = test::cbor_body(res).await?;
        assert!(!peers.is_empty());
        assert!(peers
            .iter()
            .all(|peer| peer.public_key != developer2.public_key));

        let res = server
            .request(test::ADMIN_PEER_IP, "GET", "/admin/peers")
            .await;
        let peers: Vec<PeerContents> = test::cbor_body(res).await?;
        let listed = peers
            .iter()
            .find(|peer| peer.public_key == developer2.public_key)
            .unwrap();
        assert!(listed.delegations.is_empty());
        let cidrs = DatabaseCidr::list(&server.db().lock())?;
        assert!(test::peer(&server.db().lock(), test::DEVELOPER1_PEER_ID)
            .legacy(1, &cidrs)
            .is_some());
        let without = DatabasePeer::get_from_public_key(
            &server.db().lock(),
            &wireguard_control::Key::from_base64(&developer2.public_key)?,
        )?;
        assert!(without.legacy(1, &cidrs).is_none());
        Ok(())
    }

    #[tokio::test]
    async fn test_override_endpoint() -> Result<(), Error> {
        // A peer whose client predates TLS sets its endpoint in plain HTTP.
        let server = test::Server::new()?;
        server.predate_tls(test::DEVELOPER1_PEER_ID);
        let ip = test::DEVELOPER1_PEER_IP;
        let set = EndpointContents::Set("1.1.1.1:51820".parse().unwrap());
        for (form, status) in [
            (serde_json::to_value(&set)?, StatusCode::NO_CONTENT),
            (
                serde_json::to_value(EndpointContents::Unset)?,
                StatusCode::NO_CONTENT,
            ),
            (serde_json::json!("endpoint=blah"), StatusCode::BAD_REQUEST),
        ] {
            let res = server
                .plain_form_request(ip, "PUT", "/v1/user/endpoint", form)
                .await;
            assert_eq!(res.status(), status);
        }

        // A peer that speaks TLS states its endpoint in its announcements instead.
        let ip = test::DEVELOPER2_PEER_IP;
        for (path, form) in [
            ("/user/endpoint", serde_json::to_value(&set)?),
            ("/user/candidates", serde_json::json!(["1.1.1.1:51820"])),
        ] {
            let res = server.form_request(ip, "PUT", path, form).await;
            test::blank_problem(res, StatusCode::NOT_FOUND).await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_list_peers_from_unknown_ip() -> Result<(), Error> {
        let server = test::Server::new()?;

        // Request comes from an unknown IP.
        let res = server.request("10.80.80.80", "GET", "/v1/user/state").await;

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[tokio::test]
    async fn test_list_peers_for_developer_subcidr() -> Result<(), Error> {
        let server = test::Server::new()?;
        {
            let db = server.db.lock();
            let cidr = DatabaseCidr::create(
                &db,
                "experiment cidr".to_string(),
                test::EXPERIMENTAL_CIDR.parse()?,
            )?;
            DatabaseCidr::create(
                &db,
                "experiment subcidr".to_string(),
                test::EXPERIMENTAL_SUBCIDR.parse()?,
            )?;
            // The peer's CIDR is the subcidr, which holds its IP.
            DatabasePeer::create(
                &db,
                test::peer_contents("experiment-peer", test::EXPERIMENT_SUBCIDR_PEER_IP, false)?,
            )?;

            // Add a peering between the developer's CIDR and the experimental *parent* cidr.
            DatabaseAssociation::create(&db, test::DEVELOPER_CIDR.parse()?, cidr.prefix)?;
            DatabaseAssociation::create(&db, test::SERVER_CIDR.parse()?, cidr.prefix)?;
        }

        for ip in &[test::DEVELOPER1_PEER_IP, test::EXPERIMENT_SUBCIDR_PEER_IP] {
            let res = server.request(ip, "GET", "/user/state").await;
            assert_eq!(res.status(), StatusCode::OK);
            let State { peers, .. } = test::cbor_body(res).await?;
            let mut peer_names = peers
                .iter()
                .map(|p| p.name.as_deref().unwrap())
                .collect::<Vec<_>>();
            peer_names.sort_unstable();
            // Developers should see only peers in infra CIDR and developer CIDR.
            assert_eq!(
                &[
                    "developer1",
                    "developer2",
                    "experiment-peer",
                    "innernet-server"
                ],
                &peer_names[..]
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_redeem() -> Result<(), Error> {
        let server = test::Server::new()?;

        DatabaseCidr::create(
            &server.db().lock(),
            "experimental".to_string(),
            test::EXPERIMENTAL_CIDR.parse()?,
        )?;

        let mut peer_contents =
            test::peer_contents("experiment-peer", test::EXPERIMENT_SUBCIDR_PEER_IP, false)?;
        peer_contents.is_redeemed = false;
        peer_contents.invite_expires = Some(SystemTime::now() + Duration::from_secs(100));
        let _experiment_peer = DatabasePeer::create(&server.db().lock(), peer_contents)?;

        // Step 1: Ensure that before redeeming, other endpoints aren't yet accessible.
        let res = server
            .request(test::EXPERIMENT_SUBCIDR_PEER_IP, "GET", "/user/state")
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // Step 2: Ensure that redemption works.
        let body = RedeemContents {
            public_key: wireguard_control::KeyPair::generate().public.to_base64(),
        };
        let res = server
            .form_request(
                test::EXPERIMENT_SUBCIDR_PEER_IP,
                "POST",
                "/user/redeem",
                &body,
            )
            .await;
        assert!(res.status().is_success());

        // Step 3: Ensure that a second attempt at redemption DOESN'T work.
        let res = server
            .form_request(
                test::EXPERIMENT_SUBCIDR_PEER_IP,
                "POST",
                "/user/redeem",
                &body,
            )
            .await;
        assert!(res.status().is_client_error());

        // Step 3: Ensure that after redemption, fetching state works.
        let res = server
            .request(test::EXPERIMENT_SUBCIDR_PEER_IP, "GET", "/user/state")
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn test_redeem_expired() -> Result<(), Error> {
        let server = test::Server::new()?;

        DatabaseCidr::create(
            &server.db().lock(),
            "experimental".to_string(),
            test::EXPERIMENTAL_CIDR.parse()?,
        )?;

        let mut peer_contents =
            test::peer_contents("experiment-peer", test::EXPERIMENT_SUBCIDR_PEER_IP, false)?;
        peer_contents.is_redeemed = false;
        peer_contents.invite_expires = Some(SystemTime::now() - Duration::from_secs(1));
        let _experiment_peer = DatabasePeer::create(&server.db().lock(), peer_contents)?;

        // Step 1: Ensure that before redeeming, other endpoints aren't yet accessible.
        let res = server
            .request(test::EXPERIMENT_SUBCIDR_PEER_IP, "GET", "/user/state")
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // Step 2: Ensure that redemption works.
        let body = RedeemContents {
            public_key: wireguard_control::KeyPair::generate().public.to_base64(),
        };
        let res = server
            .form_request(
                test::EXPERIMENT_SUBCIDR_PEER_IP,
                "POST",
                "/user/redeem",
                &body,
            )
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    /// Unused IPs in the user and admin CIDRs.
    fn new_user_and_admin_ips() -> (&'static str, &'static str) {
        if cfg!(feature = "v6-test") {
            ("fd00:1337::3:0:0:3", "fd00:1337::1:0:0:2")
        } else {
            ("10.80.128.3", "10.80.1.2")
        }
    }

    #[tokio::test]
    async fn test_redeem_requires_tls() -> Result<(), Error> {
        let server = test::Server::new()?;
        let (user_ip, admin_ip) = new_user_and_admin_ips();
        for (name, ip, is_admin) in [("new-user", user_ip, false), ("new-admin", admin_ip, true)] {
            let mut contents = test::peer_contents(name, ip, is_admin)?;
            contents.is_redeemed = false;
            DatabasePeer::create(&server.db().lock(), contents)?;

            // An invitation can only be redeemed by a client that uses TLS.
            let body = RedeemContents {
                public_key: wireguard_control::KeyPair::generate().public.to_base64(),
            };
            let res = server
                .plain_form_request(ip, "POST", "/v1/user/redeem", &body)
                .await;
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
            let res = server.form_request(ip, "POST", "/user/redeem", &body).await;
            assert_eq!(res.status(), StatusCode::NO_CONTENT);

            // The redeemed peer keeps the invitation's latch.
            let ip = ip.parse()?;
            assert!(DatabasePeer::get_by_address(&server.db().lock(), ip)?.requires_tls);
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_redeem_predating_tls() -> Result<(), Error> {
        // An invitation whose latch the operator cleared can be redeemed in plain HTTP, and the
        // peer stays unlatched until it connects over TLS.
        let server = test::Server::new()?;
        let (ip, _) = new_user_and_admin_ips();
        let mut contents = test::user_peer_contents("new-user", ip)?;
        contents.is_redeemed = false;
        let invitation = DatabasePeer::create(&server.db().lock(), contents)?;
        server.predate_tls_key(&invitation.public_key);

        let body = RedeemContents {
            public_key: wireguard_control::KeyPair::generate().public.to_base64(),
        };
        let res = server
            .plain_form_request(ip, "POST", "/v1/user/redeem", &body)
            .await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        let ip = ip.parse()?;
        assert!(!DatabasePeer::get_by_address(&server.db().lock(), ip)?.requires_tls);
        Ok(())
    }

    #[tokio::test]
    async fn test_redeem_with_invalid_key() -> Result<(), Error> {
        let server = test::Server::new()?;
        let (ip, _) = new_user_and_admin_ips();
        let mut contents = test::user_peer_contents("new-user", ip)?;
        contents.is_redeemed = false;
        DatabasePeer::create(&server.db().lock(), contents)?;

        // A low-order point.
        let mut low_order = [0u8; 32];
        low_order[0] = 1;
        let body = RedeemContents {
            public_key: wireguard_control::Key(low_order).to_base64(),
        };
        let res = server.form_request(ip, "POST", "/user/redeem", &body).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn test_candidates() -> Result<(), Error> {
        let server = test::Server::new()?;
        server.predate_tls(test::DEVELOPER1_PEER_ID);

        let peer = test::peer(&server.db().lock(), test::DEVELOPER1_PEER_ID);
        assert_eq!(peer.candidates, vec![]);

        let candidates = vec!["1.1.1.1:51820".parse::<Endpoint>().unwrap()];
        let res = server
            .plain_form_request(
                test::DEVELOPER1_PEER_IP,
                "PUT",
                "/v1/user/candidates",
                &candidates,
            )
            .await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let peer = test::peer(&server.db().lock(), test::DEVELOPER1_PEER_ID);
        assert_eq!(peer.candidates, candidates);
        Ok(())
    }

    /// The peer with the public key `public_key` in the state that developer2 gets over TLS.
    async fn seen_by_developer2(server: &test::Server, public_key: &str) -> PeerContents {
        let res = server
            .request(test::DEVELOPER2_PEER_IP, "GET", "/user/state")
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        let State { peers, .. } = test::cbor_body(res).await.unwrap();
        peers
            .into_iter()
            .find(|peer| peer.public_key == public_key)
            .unwrap()
    }

    #[tokio::test]
    async fn test_endpoint_in_candidates() -> Result<(), Error> {
        // We want to verify that the current wireguard endpoint always shows up
        // either in the peer.endpoint field, or the peer.candidates field (in the
        // case that the peer has specified an endpoint override), for a peer that has never
        // announced.
        let server = test::Server::new()?;
        server.predate_tls(test::DEVELOPER1_PEER_ID);

        let peer = test::peer(&server.db().lock(), test::DEVELOPER1_PEER_ID);
        assert_eq!(peer.candidates, vec![]);

        // Specify one NAT candidate. At this point, we have an unspecified
        // endpoint and one NAT candidate specified.
        let candidates = vec!["1.1.1.1:51820".parse::<Endpoint>().unwrap()];
        let res = server
            .plain_form_request(
                test::DEVELOPER1_PEER_IP,
                "PUT",
                "/v1/user/candidates",
                &candidates,
            )
            .await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let developer_1 = seen_by_developer2(&server, &peer.public_key).await;
        assert_eq!(
            developer_1.endpoint,
            Some(test::DEVELOPER1_PEER_ENDPOINT.parse().unwrap())
        );
        assert_eq!(developer_1.candidates, candidates);

        // Now, explicitly set an endpoint with the override-endpoint API
        // and check that the original wireguard endpoint still shows up
        // in the list of NAT candidates.
        let res = server
            .plain_form_request(
                test::DEVELOPER1_PEER_IP,
                "PUT",
                "/v1/user/endpoint",
                &EndpointContents::Set("1.2.3.4:51820".parse().unwrap()),
            )
            .await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let developer_1 = seen_by_developer2(&server, &peer.public_key).await;

        // The peer endpoint should be the one we just specified in the override-endpoint request.
        assert_eq!(developer_1.endpoint, Some("1.2.3.4:51820".parse().unwrap()));

        // The list of candidates should now contain the one we specified at the beginning of the
        // test, and the wireguard-reported endpoint of the peer.
        let nat_candidate_1 = "1.1.1.1:51820".parse().unwrap();
        let nat_candidate_2 = test::DEVELOPER1_PEER_ENDPOINT.parse().unwrap();
        assert_eq!(developer_1.candidates.len(), 2);
        assert!(developer_1.candidates.contains(&nat_candidate_1));
        assert!(developer_1.candidates.contains(&nat_candidate_2));

        Ok(())
    }

    #[tokio::test]
    async fn test_peers_that_never_announced_are_relayed_unsigned() -> Result<(), Error> {
        // The server makes an unsigned announcement of what it records of a peer that has never
        // announced, so that every peer comes with an announcement, and other peers get nothing
        // of its ranges but what the announcement claims.
        let server = test::Server::new()?;
        let mut peer = test::peer(&server.db().lock(), test::DEVELOPER1_PEER_ID);
        let candidate: Endpoint = "192.0.2.1:51820".parse().unwrap();
        peer.set_candidates(&server.db().lock(), vec![candidate.clone()])?;
        let seen = seen_by_developer2(&server, &peer.public_key).await;
        let relayed = seen.announcement.clone().unwrap();
        assert!(!relayed.is_signed());
        assert!(seen.delegations.is_empty());
        let announcement = relayed.decode()?;
        assert_eq!(announcement.timestamp, 0);
        assert_eq!(
            announcement.claims.delegation,
            [Prefix::host(developer1_ip())]
        );
        assert_eq!(announcement.claims.name, peer.name);
        assert_eq!(announcement.allowed_ips, [Prefix::host(developer1_ip())]);
        assert_eq!(announcement.primary_ip, Some(developer1_ip()));
        // It lists the endpoint, here the one at which the server observes the peer, before the
        // candidates that the peer set.
        assert_eq!(
            announcement.endpoints,
            [test::DEVELOPER1_PEER_ENDPOINT.parse().unwrap(), candidate]
        );

        // The peer itself gets its own the same way, with its ranges.
        let res = server
            .request(test::DEVELOPER1_PEER_IP, "GET", "/user/state")
            .await;
        let State { peers, .. } = test::cbor_body(res).await?;
        let own = peers
            .iter()
            .find(|own| own.public_key == peer.public_key)
            .unwrap();
        assert_eq!(own.delegations, [Prefix::host(developer1_ip())]);
        assert!(!own.announcement.as_ref().unwrap().is_signed());
        Ok(())
    }

    /// The address of developer1, which the server assigns it as a range of its own.
    fn developer1_ip() -> std::net::IpAddr {
        test::DEVELOPER1_PEER_IP.parse().unwrap()
    }

    /// An announcement of developer1, dated now, that claims the name and the range that the
    /// server assigns it, accepts traffic for all of it, and states its address as its primary
    /// IP.
    fn developer1_announcement() -> Announcement {
        let delegation = vec![Prefix::host(developer1_ip())];
        Announcement {
            timestamp: announcement::timestamp_now(),
            claims: Claims {
                delegation: delegation.clone(),
                name: Some("developer1".parse().unwrap()),
            },
            allowed_ips: delegation,
            primary_ip: Some(developer1_ip()),
            endpoints: vec![
                "198.51.100.1:51820".parse().unwrap(),
                "192.0.2.1:51820".parse().unwrap(),
            ],
        }
    }

    #[tokio::test]
    async fn test_announcement_is_relayed_as_signed() -> Result<(), Error> {
        let server = test::Server::new()?;
        let ip = test::DEVELOPER1_PEER_IP;
        let keypair = server.keypair(test::DEVELOPER1_PEER_ID);
        let public_key = keypair.public.to_base64();
        {
            // When the server accepts the first announcement of a peer whose client was upgraded
            // from plain HTTP, it deletes the endpoint that the peer had set over plain HTTP.
            let store = server.db.lock();
            let mut peer = DatabasePeer::get_from_public_key(&store, &keypair.public)?;
            peer.set_endpoint(&store, Some("1.2.3.4:51820".parse().unwrap()))?;
        }

        let signed = server.sign(&keypair, &developer1_announcement());
        let res = server
            .form_request(ip, "PUT", "/user/announcement", &signed)
            .await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        let stored = DatabasePeer::get_from_public_key(&server.db().lock(), &keypair.public)?;
        assert_eq!(stored.announcement.as_ref(), Some(&signed));
        assert_eq!(stored.endpoint, None);

        // Other peers get the announcement as it was signed, nothing of the endpoint that the
        // server observes, which only the peer itself can state, and nothing of the ranges that
        // the server assigns it.
        let seen = seen_by_developer2(&server, &public_key).await;
        assert_eq!(seen.announcement.as_ref(), Some(&signed));
        assert_eq!(
            (seen.endpoint.clone(), seen.candidates.clone()),
            (None, vec![])
        );
        assert!(seen.delegations.is_empty());
        let effective = seen.effective();
        assert_eq!(
            effective.endpoint.as_ref(),
            developer1_announcement().endpoints.first()
        );
        assert_eq!(
            effective.candidates,
            developer1_announcement().endpoints[1..]
        );
        assert_eq!(effective.delegations, [Prefix::host(developer1_ip())]);
        assert_eq!(effective.hosts_fallback(), Some(developer1_ip()));

        // The peer itself is told the ranges that the server assigns it, and the endpoint at
        // which the server observes it, and other peers only their own.
        let res = server.request(ip, "GET", "/user/state").await;
        let state: State = test::cbor_body(res).await?;
        let own = state
            .peers
            .iter()
            .find(|peer| peer.public_key == public_key)
            .unwrap();
        assert_eq!(own.delegations, [Prefix::host(developer1_ip())]);
        assert_eq!(
            state.observed_endpoint,
            Some(test::DEVELOPER1_PEER_ENDPOINT.parse().unwrap())
        );
        let res = server
            .request(test::DEVELOPER2_PEER_IP, "GET", "/user/state")
            .await;
        let state: State = test::cbor_body(res).await?;
        assert_ne!(
            state.observed_endpoint,
            Some(test::DEVELOPER1_PEER_ENDPOINT.parse().unwrap())
        );

        // A client that predates TLS can't check the announcement, so it gets the peer as the
        // announcement makes it, at its primary IP.
        server.predate_tls(test::USER1_PEER_ID);
        DatabaseAssociation::create(
            &server.db().lock(),
            test::USER_CIDR.parse()?,
            test::DEVELOPER_CIDR.parse()?,
        )?;
        let res = server
            .plain_request(test::USER1_PEER_IP, "GET", "/v1/user/state")
            .await;
        let state: serde_json::Value = test::json_body(res).await?;
        let peers: Vec<LegacyPeer> = serde_json::from_value(state["peers"].clone())?;
        let legacy = peers
            .iter()
            .find(|peer| peer.public_key == public_key)
            .unwrap();
        assert_eq!(legacy.ip, developer1_ip());
        assert_eq!(legacy.endpoint, effective.endpoint);
        assert_eq!(legacy.candidates, effective.candidates);
        Ok(())
    }

    #[tokio::test]
    async fn test_announcement_refusals() -> Result<(), Error> {
        let server = test::Server::new()?;
        let ip = test::DEVELOPER1_PEER_IP;
        let keypair = server.keypair(test::DEVELOPER1_PEER_ID);
        let announce = |signed: SignedAnnouncement| {
            server.form_request(ip, "PUT", "/user/announcement", signed)
        };
        let accepted = developer1_announcement();
        let res = announce(server.sign(&keypair, &accepted)).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        // An announcement that is not newer than the last one is refused, even the same again.
        let res = announce(server.sign(&keypair, &accepted)).await;
        test::problem(res, &innernet_shared::problem::ANNOUNCEMENT_STALE).await?;
        let older = Announcement {
            timestamp: accepted.timestamp - 1,
            ..developer1_announcement()
        };
        let res = announce(server.sign(&keypair, &older)).await;
        test::problem(res, &innernet_shared::problem::ANNOUNCEMENT_STALE).await?;

        // So is one that another key signed.
        let other = wireguard_control::KeyPair::generate();
        let res = announce(server.sign(&other, &developer1_announcement())).await;
        test::problem(res, &innernet_shared::problem::ANNOUNCEMENT_INVALID).await?;

        // And one dated too far ahead.
        let ahead = Announcement {
            timestamp: announcement::timestamp_now() + 3_600_000_000_000,
            ..developer1_announcement()
        };
        let res = announce(server.sign(&keypair, &ahead)).await;
        test::problem(res, &innernet_shared::problem::ANNOUNCEMENT_TOO_FAR_AHEAD).await?;

        // And one without a signature: only the server makes unsigned announcements.
        let res = announce(SignedAnnouncement::unsigned(&developer1_announcement())?).await;
        test::problem(res, &innernet_shared::problem::ANNOUNCEMENT_INVALID).await?;

        // And one that claims what the server doesn't assign the peer, another name or a
        // delegation beyond its ranges, or that states no primary IP, or one outside the
        // delegation that it claims. The server can't narrow what the peer signed.
        let user_ip = test::USER1_PEER_IP.parse().unwrap();
        for unassigned in [
            Announcement {
                claims: Claims {
                    name: Some("developer2".parse().unwrap()),
                    ..developer1_announcement().claims
                },
                ..developer1_announcement()
            },
            Announcement {
                claims: Claims {
                    delegation: vec![test::DEVELOPER_CIDR.parse().unwrap()],
                    ..developer1_announcement().claims
                },
                ..developer1_announcement()
            },
            Announcement {
                primary_ip: None,
                ..developer1_announcement()
            },
            Announcement {
                primary_ip: Some(user_ip),
                ..developer1_announcement()
            },
        ] {
            let res = announce(server.sign(&keypair, &unassigned)).await;
            test::problem(res, &innernet_shared::problem::ANNOUNCEMENT_UNASSIGNED).await?;
        }
        // The coordinator judges what an announcement claims before its node applies the rules of
        // the store, so one that is both stale and unassigned is refused as unassigned.
        let stale_unassigned = Announcement {
            timestamp: accepted.timestamp - 1,
            claims: Claims {
                name: Some("developer2".parse().unwrap()),
                ..developer1_announcement().claims
            },
            ..developer1_announcement()
        };
        let res = announce(server.sign(&keypair, &stale_unassigned)).await;
        test::problem(res, &innernet_shared::problem::ANNOUNCEMENT_UNASSIGNED).await?;

        // Allowed IPs beyond the delegation are no reason to refuse it: every peer shrinks them.
        let wider = Announcement {
            allowed_ips: vec![test::DEVELOPER_CIDR.parse().unwrap()],
            ..developer1_announcement()
        };
        let res = announce(server.sign(&keypair, &wider)).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        let accepted = wider;

        // And one that makes a claim of a type that the server doesn't check, while a statement,
        // which isn't a claim, is ignored.
        #[derive(serde::Serialize)]
        struct LaterClaims {
            #[serde(flatten)]
            claims: Claims,
            relay: bool,
        }
        #[derive(serde::Serialize)]
        struct Later<C> {
            timestamp: u64,
            claims: C,
            #[serde(rename = "primaryIp")]
            primary_ip: String,
            note: &'static str,
        }
        let private_key =
            innernet_shared::xeddsa::PrivateKey::from_base64(&keypair.private.to_base64())?;
        let sign = |payload| SignedAnnouncement::sign(payload, &private_key).unwrap();
        let later = Later {
            timestamp: announcement::timestamp_now(),
            claims: LaterClaims {
                claims: developer1_announcement().claims,
                relay: true,
            },
            primary_ip: test::DEVELOPER1_PEER_IP.into(),
            note: "not a claim",
        };
        let res = announce(sign(innernet_shared::cbor::to_vec(&later)?)).await;
        test::problem(res, &innernet_shared::problem::ANNOUNCEMENT_CLAIM_UNKNOWN).await?;

        // And one longer than the server reads.
        let signed = server.sign(&keypair, &developer1_announcement());
        let too_long = SignedAnnouncement {
            payload: vec![0; announcement::MAX_PAYLOAD_LEN + 1],
            ..signed
        };
        let res = announce(too_long).await;
        let problem = test::problem(res, &innernet_shared::problem::ANNOUNCEMENT_TOO_LARGE).await?;
        assert_eq!(problem.limit, Some(announcement::MAX_PAYLOAD_LEN as u64));

        // The last accepted announcement stays, as the server relays it and as its node core
        // stored it: nothing of a refused one is stored.
        let stored = DatabasePeer::get_from_public_key(&server.db().lock(), &keypair.public)?;
        assert_eq!(
            stored.announcement.as_ref().unwrap().decode().unwrap(),
            accepted
        );
        assert_eq!(stored.announced, Some(accepted));

        // A peer whose client predates TLS has no announcements to send.
        server.predate_tls(test::DEVELOPER2_PEER_ID);
        let res = server
            .plain_form_request(
                test::DEVELOPER2_PEER_IP,
                "PUT",
                "/v1/user/announcement",
                &developer1_announcement(),
            )
            .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn test_announcement_claimed_by_another() -> Result<(), Error> {
        // A name that another peer's last announcement claims stays that peer's, even once the
        // server gives it to another: the other peer can't claim it until the first stops.
        let server = test::Server::new()?;
        let developer1 = server.keypair(test::DEVELOPER1_PEER_ID);
        let developer2 = server.keypair(test::DEVELOPER2_PEER_ID);
        let developer2_ip: std::net::IpAddr = test::DEVELOPER2_PEER_IP.parse()?;
        let developer2_announcement = |name: &str| Announcement {
            timestamp: announcement::timestamp_now(),
            claims: Claims {
                delegation: vec![Prefix::host(developer2_ip)],
                name: Some(name.parse().unwrap()),
            },
            primary_ip: Some(developer2_ip),
            ..Default::default()
        };
        let announce = |ip, keypair, announcement: &Announcement| {
            server.form_request(
                ip,
                "PUT",
                "/user/announcement",
                server.sign(keypair, announcement),
            )
        };
        let res = announce(
            test::DEVELOPER2_PEER_IP,
            &developer2,
            &developer2_announcement("developer2"),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let rename = |key: &wireguard_control::Key, name: &str| -> Result<(), Error> {
            let db = server.db();
            let store = db.lock();
            let mut peer = DatabasePeer::get_from_public_key(&store, key)?;
            let contents = PeerContents {
                name: Some(name.parse().unwrap()),
                ..peer.inner.clone()
            };
            peer.update(&store, contents)?;
            Ok(())
        };
        rename(&developer2.public, "developer3")?;
        rename(&developer1.public, "developer2")?;
        let claiming = Announcement {
            claims: Claims {
                name: Some("developer2".parse().unwrap()),
                ..developer1_announcement().claims
            },
            ..developer1_announcement()
        };
        let res = announce(test::DEVELOPER1_PEER_IP, &developer1, &claiming).await;
        test::problem(res, &innernet_shared::problem::ANNOUNCEMENT_CLAIMED).await?;

        // Once developer2 claims its new name, the old one is free.
        let res = announce(
            test::DEVELOPER2_PEER_IP,
            &developer2,
            &developer2_announcement("developer3"),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        let claiming = Announcement {
            timestamp: announcement::timestamp_now(),
            ..claiming
        };
        let res = announce(test::DEVELOPER1_PEER_IP, &developer1, &claiming).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        Ok(())
    }

    #[tokio::test]
    async fn test_offering_a_claimed_name() -> Result<(), Error> {
        // The server's node core takes a peer that has never announced as the unsigned
        // announcement that the server makes of it, which pins its name to its key, as on every
        // client. Offering that name to another peer is harmless: the announcements of the other
        // peer that claim it, unsigned or signed, are refused, and the other peer keeps its last
        // accepted announcement, so it neither takes the name nor vanishes.
        let server = test::Server::new()?;
        let db = server.db();
        let user1 = server.keypair(test::USER1_PEER_ID);
        let user2 = server.keypair(test::USER2_PEER_ID);
        let effective = |keypair: &wireguard_control::KeyPair| -> Result<PeerContents, Error> {
            Ok(DatabasePeer::get_from_public_key(&db.lock(), &keypair.public)?.effective())
        };
        let name =
            |name: &str| -> Option<innernet_shared::Hostname> { Some(name.parse().unwrap()) };
        {
            let store = db.lock();
            for (id, offered) in [
                (test::USER1_PEER_ID, "renamed"),
                (test::USER2_PEER_ID, "user1"),
            ] {
                let mut peer = test::peer(&store, id);
                let contents = PeerContents {
                    name: name(offered),
                    ..peer.inner.clone()
                };
                peer.update(&store, contents)?;
            }
        }
        assert_eq!(effective(&user1)?.name, name("user1"));
        let user2_before = effective(&user2)?;
        assert_eq!(user2_before.name, name("user2"));
        assert!(user2_before.is_routed());

        // Even signed, user2 can't claim the name while user1 holds it.
        let user2_ip: std::net::IpAddr = test::USER2_PEER_IP.parse()?;
        let user2_claims = |name: &str| Announcement {
            timestamp: announcement::timestamp_now(),
            claims: Claims {
                delegation: vec![Prefix::host(user2_ip)],
                name: Some(name.parse().unwrap()),
            },
            allowed_ips: vec![Prefix::host(user2_ip)],
            primary_ip: Some(user2_ip),
            ..Default::default()
        };
        let res = server
            .form_request(
                test::USER2_PEER_IP,
                "PUT",
                "/user/announcement",
                server.sign(&user2, &user2_claims("user1")),
            )
            .await;
        test::problem(res, &innernet_shared::problem::ANNOUNCEMENT_CLAIMED).await?;
        assert_eq!(effective(&user2)?, user2_before);

        // Once user1 signs the name that it is now offered, the name is released. The unsigned
        // announcement of user2 releases no name, so user2 keeps its own until it signs one that
        // claims the name that it is offered, which it then can.
        let user1_ip: std::net::IpAddr = test::USER1_PEER_IP.parse()?;
        let renamed = Announcement {
            timestamp: announcement::timestamp_now(),
            claims: Claims {
                delegation: vec![Prefix::host(user1_ip)],
                name: name("renamed"),
            },
            allowed_ips: vec![Prefix::host(user1_ip)],
            primary_ip: Some(user1_ip),
            ..Default::default()
        };
        let res = server
            .form_request(
                test::USER1_PEER_IP,
                "PUT",
                "/user/announcement",
                server.sign(&user1, &renamed),
            )
            .await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert_eq!(effective(&user1)?.name, name("renamed"));
        assert_eq!(effective(&user2)?.name, name("user2"));
        let res = server
            .form_request(
                test::USER2_PEER_IP,
                "PUT",
                "/user/announcement",
                server.sign(&user2, &user2_claims("user1")),
            )
            .await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert_eq!(effective(&user2)?.name, name("user1"));
        Ok(())
    }

    #[tokio::test]
    async fn test_announcement_claims_part_of_the_ranges() -> Result<(), Error> {
        // A peer that claims part of its ranges, and accepts traffic for part of that, is routed
        // that part, and the server routes it its primary IP besides. The server never withdraws
        // a range that holds part of the claimed delegation.
        let server = test::Server::new()?;
        let wider = if cfg!(feature = "v6-test") {
            "fd00:1337::2:0:1:0/112"
        } else {
            "10.80.64.16/28"
        };
        server.delegate(test::DEVELOPER1_PEER_ID, wider);
        let wider: Prefix = wider.parse()?;
        let part = Prefix::new(ipnet::IpNet::new(wider.first(), wider.prefix_len() + 1)?)?;
        let keypair = server.keypair(test::DEVELOPER1_PEER_ID);
        let stored = || DatabasePeer::get_from_public_key(&server.db().lock(), &keypair.public);
        assert_eq!(stored()?.effective().delegations.len(), 2);

        let host = Prefix::host(developer1_ip());
        let narrowed = Announcement {
            claims: Claims {
                delegation: vec![host, part],
                ..developer1_announcement().claims
            },
            allowed_ips: vec![part],
            ..developer1_announcement()
        };
        let res = server
            .form_request(
                test::DEVELOPER1_PEER_IP,
                "PUT",
                "/user/announcement",
                server.sign(&keypair, &narrowed),
            )
            .await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        let effective = stored()?.effective();
        assert_eq!(effective.delegations, [host, part]);
        assert_eq!(effective.allowed_ips(), [part.allowed_ip()]);
        assert_eq!(
            innernet_node::snapshot::with_primary_ip(&effective).allowed_ips(),
            [host.allowed_ip(), part.allowed_ip()]
        );

        // The ranges must hold the claimed delegation, so the range of `part` stays, but the
        // rest of the ranges may change.
        let internal_address = test::SERVER_CIDR.parse::<Prefix>()?.first();
        let set = |delegations: Vec<Prefix>, reclaim: Vec<Prefix>| {
            let db = server.db();
            let store = db.lock();
            let mut peer = DatabasePeer::get_from_public_key(&store, &keypair.public)?;
            peer.set_delegations(
                &store,
                delegations,
                reclaim,
                server.public_key(),
                internal_address,
            )
        };
        assert!(matches!(
            set(vec![host], vec![]),
            Err(ServerError::DelegationClaimed(_))
        ));
        assert!(matches!(
            set(vec![wider], vec![]),
            Err(ServerError::DelegationClaimed(_))
        ));
        assert!(set(vec![host, wider], vec![part]).is_err());
        set(vec![host, wider], vec![wider])?;
        assert_eq!(stored()?.reclaim, [wider]);
        Ok(())
    }

    #[tokio::test]
    async fn test_reclaimed_ranges() -> Result<(), Error> {
        // A range marked to be reclaimed stops being assigned once the peer, having claimed some
        // of it, announces without claiming any of it; an unmarked one stays, and so does a
        // marked one that the peer never claimed.
        let server = test::Server::new()?;
        let [marked, unmarked, unclaimed] = if cfg!(feature = "v6-test") {
            [
                "fd00:1337::2:0:1:0/112",
                "fd00:1337::2:0:2:0/112",
                "fd00:1337::2:0:3:0/112",
            ]
        } else {
            ["10.80.64.16/28", "10.80.64.32/28", "10.80.64.48/28"]
        };
        for range in [marked, unmarked, unclaimed] {
            server.delegate(test::DEVELOPER1_PEER_ID, range);
        }
        let [marked, unmarked, unclaimed]: [Prefix; 3] =
            [marked.parse()?, unmarked.parse()?, unclaimed.parse()?];
        let keypair = server.keypair(test::DEVELOPER1_PEER_ID);
        let host = Prefix::host(developer1_ip());
        {
            let db = server.db();
            let store = db.lock();
            let mut peer = DatabasePeer::get_from_public_key(&store, &keypair.public)?;
            let ranges = peer.delegations.clone();
            peer.set_delegations(
                &store,
                ranges,
                vec![marked, unclaimed],
                server.public_key(),
                test::SERVER_CIDR.parse::<Prefix>()?.first(),
            )?;
        }
        let announce = |delegation: Vec<Prefix>| {
            let announcement = Announcement {
                timestamp: announcement::timestamp_now(),
                claims: Claims {
                    delegation,
                    ..developer1_announcement().claims
                },
                ..developer1_announcement()
            };
            server.form_request(
                test::DEVELOPER1_PEER_IP,
                "PUT",
                "/user/announcement",
                server.sign(&keypair, &announcement),
            )
        };
        let ranges = || {
            DatabasePeer::get_from_public_key(&server.db().lock(), &keypair.public)
                .unwrap()
                .delegations
                .clone()
        };
        let res = announce(vec![host, marked, unmarked]).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert_eq!(ranges(), [host, marked, unmarked, unclaimed]);
        let res = announce(vec![host]).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert_eq!(ranges(), [host, unmarked, unclaimed]);
        Ok(())
    }

    #[tokio::test]
    async fn test_relayed_bytes_affect_only_relaying() -> Result<(), Error> {
        // The server takes what a peer announces from the announcement as it stored it decoded, and
        // keeps the bytes only to relay them, so bytes that are damaged change nothing of what the
        // peer is: the peer stays routed, and a newer announcement replaces them.
        let server = test::Server::new()?;
        let keypair = server.keypair(test::DEVELOPER1_PEER_ID);
        let announce = |announcement: &Announcement| {
            server.form_request(
                test::DEVELOPER1_PEER_IP,
                "PUT",
                "/user/announcement",
                server.sign(&keypair, announcement),
            )
        };
        let first = developer1_announcement();
        assert_eq!(announce(&first).await.status(), StatusCode::NO_CONTENT);
        let key = keypair.public.as_bytes().to_vec();
        let stored = || DatabasePeer::get_from_public_key(&server.db().lock(), &keypair.public);
        let effective = stored()?.effective();
        server.db().lock().execute(
            "UPDATE relayed_announcements SET payload = x'ff' WHERE public_key = ?1",
            [&key],
        )?;
        assert_eq!(stored()?.effective().allowed_ips, effective.allowed_ips);
        assert_eq!(stored()?.effective().endpoint, effective.endpoint);
        assert!(stored()?.effective().is_routed());

        let res = announce(&first).await;
        test::problem(res, &innernet_shared::problem::ANNOUNCEMENT_STALE).await?;
        let newer = Announcement {
            timestamp: first.timestamp + 1,
            ..developer1_announcement()
        };
        let signed = server.sign(&keypair, &newer);
        let res = server
            .form_request(
                test::DEVELOPER1_PEER_IP,
                "PUT",
                "/user/announcement",
                &signed,
            )
            .await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert_eq!(stored()?.announced.unwrap().timestamp, newer.timestamp);
        assert_eq!(stored()?.announcement, Some(signed));
        Ok(())
    }

    #[tokio::test]
    async fn test_capabilities_state_announcements() -> Result<(), Error> {
        let server = test::Server::new()?;
        let res = server
            .request(test::DEVELOPER1_PEER_IP, "GET", "/user/capabilities")
            .await;
        let capabilities: ServerCapabilities = test::cbor_body(res).await?;
        assert_eq!(capabilities.announcement_claims, announcement::CLAIM_TYPES);
        for claim in announcement::CLAIM_TYPES {
            assert!(capabilities.checks_claim(claim));
        }
        assert!(!capabilities.checks_claim("relay"));
        assert!(capabilities.accepts_announcements());
        Ok(())
    }
}
