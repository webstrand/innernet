//! The public routes of the TLS API, which anonymous connections may use too, so that curl and
//! scripts can learn about the server without a client key. They have no path prefix, and need no
//! session.

use std::net::IpAddr;

use crate::{
    db::{DatabaseCidr, DatabasePeer},
    util::represented_response,
    Context, ServerError, VERSION,
};
use hyper::{Body, Response};
use innernet_shared::{media_type::Representation, PublicCapabilities, ServerDescription, Whoami};
use wireguard_control::Key;

/// `GET /server`: the server's public key, the name of the network and its CIDR, the root CIDR.
pub fn server(
    context: &Context,
    representation: Representation,
) -> Result<Response<Body>, ServerError> {
    let root = {
        let store = context.db.lock();
        DatabaseCidr::list(&store)?
            .iter()
            .map(DatabaseCidr::contents)
            .min_by_key(|cidr| cidr.cidr.prefix_len())
            .ok_or(ServerError::NotFound)?
    };
    let description = ServerDescription {
        public_key: context.public_key.to_base64(),
        network_name: context.interface.to_string(),
        network_cidr: root.cidr,
    };
    represented_response(representation, description)
}

/// `GET /whoami`: for a connection authenticated with `client_key`, that key, and the name of the
/// peer that has it; for an anonymous connection, the peer whose delegations hold `address`, the
/// source address of the request, only as information.
pub fn whoami(
    context: &Context,
    address: IpAddr,
    client_key: Option<&Key>,
    representation: Representation,
) -> Result<Response<Body>, ServerError> {
    let peer = {
        let store = context.db.lock();
        match client_key {
            Some(key) => DatabasePeer::get_from_public_key(&store, key),
            None => DatabasePeer::get_by_address(&store, address),
        }
    };
    let peer = match peer {
        Ok(peer) => Some(peer),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => return Err(e.into()),
    };
    let whoami = Whoami {
        address,
        authenticated: client_key.is_some(),
        public_key: client_key
            .map(Key::to_base64)
            .or_else(|| peer.as_ref().map(|peer| peer.public_key.clone())),
        name: peer.and_then(|peer| peer.inner.name),
    };
    represented_response(representation, whoami)
}

/// `GET /capabilities`: the capabilities of the server that concern any client, and the server's
/// version.
pub fn capabilities(
    context: &Context,
    representation: Representation,
) -> Result<Response<Body>, ServerError> {
    let capabilities = PublicCapabilities {
        quic_port: Some(context.quic_port),
        version: VERSION.to_string(),
    };
    represented_response(representation, capabilities)
}

#[cfg(test)]
mod tests {
    use crate::test;
    use hyper::{header, StatusCode};
    use innernet_shared::{problem, Error, Prefix, PublicCapabilities, ServerDescription, Whoami};
    use serde::de::IgnoredAny;
    use std::collections::BTreeMap;
    use wireguard_control::KeyPair;

    #[tokio::test]
    async fn test_public_routes() -> Result<(), Error> {
        let server = test::Server::new()?;
        let ip = test::DEVELOPER1_PEER_IP;
        let get = |path: &str| server.anonymous_request(ip, server.empty_request("GET", path));

        // The server describes itself to anyone.
        let description: ServerDescription = test::cbor_body(get("/server").await).await?;
        assert_eq!(
            description,
            ServerDescription {
                public_key: server.public_key().to_base64(),
                network_name: "test".into(),
                network_cidr: test::ROOT_CIDR.parse::<Prefix>()?,
            }
        );
        let capabilities: PublicCapabilities = test::cbor_body(get("/capabilities").await).await?;
        assert_eq!(capabilities.quic_port, Some(54322));
        assert_eq!(capabilities.version, crate::VERSION);
        let members: BTreeMap<String, IgnoredAny> =
            test::cbor_body(get("/capabilities").await).await?;
        assert!(!members.contains_key("unspecified_ip_in_override_endpoint"));

        // An anonymous connection is told which peer holds its address, only as information.
        let developer1 = test::peer(&server.db.lock(), test::DEVELOPER1_PEER_ID);
        let whoami: Whoami = test::cbor_body(get("/whoami").await).await?;
        assert_eq!(
            whoami,
            Whoami {
                address: ip.parse()?,
                authenticated: false,
                public_key: Some(developer1.public_key.clone()),
                name: developer1.inner.name.clone(),
            }
        );
        let unknown = "10.80.80.80";
        let unknown = if cfg!(feature = "v6-test") {
            "fd00:1337::1337"
        } else {
            unknown
        };
        let res = server
            .anonymous_request(unknown, server.empty_request("GET", "/whoami"))
            .await;
        let whoami: Whoami = test::cbor_body(res).await?;
        assert_eq!((whoami.public_key, whoami.name), (None, None));

        // An authenticated connection is told its own identity, wherever it connects from.
        let key = KeyPair::generate().public;
        let res = server
            .raw_request_as(
                unknown,
                Some(key.clone()),
                server.empty_request("GET", "/whoami"),
            )
            .await;
        let whoami: Whoami = test::cbor_body(res).await?;
        assert!(whoami.authenticated);
        assert_eq!(whoami.public_key, Some(key.to_base64()));
        let res = server.request(ip, "GET", "/whoami").await;
        let whoami: Whoami = test::cbor_body(res).await?;
        assert_eq!(whoami.name, developer1.inner.name);

        // The public routes negotiate the version as every route does, and answer in the debug
        // view a request that chooses it.
        let mut req = server.empty_request("GET", "/server");
        req.headers_mut()
            .insert(header::ACCEPT, "*/*".parse().unwrap());
        let res = server.anonymous_request(ip, req).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers()[header::CONTENT_TYPE],
            "application/vnd.innernet+cbor-diagnostic; version=1"
        );
        let body = hyper::body::to_bytes(res.into_body()).await?;
        let text = String::from_utf8(body.to_vec())?;
        assert!(text.contains("\"network_name\": \"test\""), "{text}");
        let mut req = server.empty_request("GET", "/capabilities");
        req.headers_mut().insert(
            header::ACCEPT,
            "application/vnd.innernet+cbor; version=2".parse().unwrap(),
        );
        let res = server.anonymous_request(ip, req).await;
        test::blank_problem(res, StatusCode::NOT_ACCEPTABLE).await?;

        // Only GET, and only these paths, are public.
        for (method, path) in [("PUT", "/server"), ("GET", "/server/key"), ("GET", "/")] {
            let res = server
                .anonymous_request(ip, server.empty_request(method, path))
                .await;
            test::problem(res, &problem::CLIENT_KEY_REQUIRED).await?;
            let res = server.request(ip, method, path).await;
            test::blank_problem(res, StatusCode::NOT_FOUND).await?;
        }
        Ok(())
    }
}
