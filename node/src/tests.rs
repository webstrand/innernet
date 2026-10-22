use crate::{
    accept::Refusal,
    store::{self, key_to_bytes, EndpointKind, PinKind},
    Store,
};
use innernet_shared::PeerContents;
use wireguard_control::KeyPair;

fn network() -> ipnet::IpNet {
    "10.0.0.0/16".parse().unwrap()
}

fn peer(name: &str, ip: &str) -> PeerContents {
    PeerContents {
        name: Some(name.parse().unwrap()),
        ip: ip.parse().unwrap(),
        cidr_id: 0,
        public_key: KeyPair::generate().public.to_base64(),
        endpoint: None,
        persistent_keepalive_interval: None,
        is_admin: false,
        is_disabled: false,
        is_redeemed: true,
        invite_expires: None,
        candidates: vec![],
    }
}

fn accept(store: &Store, peers: &[&PeerContents]) -> Vec<Result<(), Refusal>> {
    store.accept(peers).unwrap()
}

#[test]
fn test_pins() {
    let store = Store::in_memory(network()).unwrap();
    let a = peer("a", "10.0.0.2");
    assert_eq!(accept(&store, &[&a]), [Ok(())]);

    // The key can't move to another address, nor another key take the address.
    let moved = PeerContents {
        ip: "10.0.0.3".parse().unwrap(),
        ..a.clone()
    };
    assert_eq!(
        accept(&store, &[&moved]),
        [Err(Refusal::KeyPinned { pinned: a.ip })]
    );
    let impostor = PeerContents {
        name: Some("b".parse().unwrap()),
        ..peer("b", "10.0.0.2")
    };
    assert_eq!(
        accept(&store, &[&impostor]),
        [Err(Refusal::AddressPinned { ip: a.ip })]
    );

    // Anything else of a pinned peer changes in place.
    let renamed = PeerContents {
        name: Some("renamed".parse().unwrap()),
        is_admin: true,
        ..a.clone()
    };
    assert_eq!(accept(&store, &[&renamed]), [Ok(())]);
    assert_eq!(store::load_peers(&store).unwrap(), [renamed]);
}

#[test]
fn test_network() {
    let store = Store::in_memory(network()).unwrap();
    let outside = peer("outside", "10.1.0.2");
    assert_eq!(
        accept(&store, &[&outside]),
        [Err(Refusal::OutsideNetwork {
            ip: outside.ip,
            network: network()
        })]
    );
    assert!(store::load_peers(&store).unwrap().is_empty());
}

#[test]
fn test_duplicates_and_names_moving() {
    let store = Store::in_memory(network()).unwrap();
    let a = peer("a", "10.0.0.2");
    let b = peer("b", "10.0.0.3");
    let same_ip = PeerContents {
        name: Some("c".parse().unwrap()),
        ..peer("c", "10.0.0.2")
    };
    assert_eq!(
        accept(&store, &[&a, &b, &same_ip]),
        [Ok(()), Ok(()), Err(Refusal::Duplicate)]
    );

    // Two peers swap names within one batch.
    let a_as_b = PeerContents {
        name: Some("b".parse().unwrap()),
        ..a.clone()
    };
    let b_as_a = PeerContents {
        name: Some("a".parse().unwrap()),
        ..b.clone()
    };
    assert_eq!(accept(&store, &[&a_as_b, &b_as_a]), [Ok(()), Ok(())]);

    // A name that its holder keeps can't be taken.
    let c = PeerContents {
        name: Some("a".parse().unwrap()),
        ..peer("c", "10.0.0.4")
    };
    assert_eq!(accept(&store, &[&c]), [Err(Refusal::NameTaken)]);
    let names: Vec<String> = store::load_peers(&store)
        .unwrap()
        .iter()
        .map(|peer| peer.display_name().to_string())
        .collect();
    assert_eq!(names, ["b", "a"]);
}

#[test]
fn test_forget_releases_the_pins() {
    let store = Store::in_memory(network()).unwrap();
    let invitation = PeerContents {
        is_redeemed: false,
        endpoint: Some("198.51.100.1:51820".parse().unwrap()),
        ..peer("invited", "10.0.0.2")
    };
    accept(&store, &[&invitation]);
    store::forget_peer(&store, &key_to_bytes(&invitation.public_key).unwrap()).unwrap();
    let redeemed = PeerContents {
        is_redeemed: true,
        public_key: KeyPair::generate().public.to_base64(),
        ..invitation
    };
    assert_eq!(accept(&store, &[&redeemed]), [Ok(())]);
    assert_eq!(store::load_peers(&store).unwrap(), [redeemed]);
}

#[test]
fn test_schema_holds_no_policy() {
    // The schema enforces consistency alone: an operator may delete a pin and its peer by hand.
    let store = Store::in_memory(network()).unwrap();
    let a = peer("a", "10.0.0.2");
    accept(&store, &[&a]);
    let triggers: i64 = store
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type = 'trigger'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(triggers, 0);
    let key = key_to_bytes(&a.public_key).unwrap();
    assert!(store
        .execute("DELETE FROM peers WHERE public_key = ?1", [&key])
        .is_err());
    store
        .execute("DELETE FROM prefix_pins WHERE public_key = ?1", [&key])
        .unwrap();
    store
        .execute("DELETE FROM peers WHERE public_key = ?1", [&key])
        .unwrap();
}

#[test]
fn test_kinds_match_tables() {
    let store = Store::in_memory(network()).unwrap();
    let kinds = |table: &str| -> Vec<(i64, String)> {
        let mut stmt = store
            .prepare(&format!("SELECT kind, name FROM {table} ORDER BY kind"))
            .unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    let pins: Vec<(i64, String)> = PinKind::ALL
        .iter()
        .map(|(k, n)| (*k as i64, n.to_string()))
        .collect();
    let endpoints: Vec<(i64, String)> = EndpointKind::ALL
        .iter()
        .map(|(k, n)| (*k as i64, n.to_string()))
        .collect();
    assert_eq!(kinds("pin_kinds"), pins);
    assert_eq!(kinds("endpoint_kinds"), endpoints);
}

#[test]
fn test_peers_without_a_name() {
    // Any number of peers can be without a name, and a peer can lose its name and get one again.
    let store = Store::in_memory(network()).unwrap();
    let nameless: Vec<PeerContents> = ["10.0.0.2", "10.0.0.3"]
        .into_iter()
        .map(|ip| PeerContents {
            name: None,
            ..peer("x", ip)
        })
        .collect();
    let refs: Vec<&PeerContents> = nameless.iter().collect();
    assert_eq!(accept(&store, &refs), [Ok(()), Ok(())]);
    let nulls: i64 = store
        .query_row("SELECT count(*) FROM peers WHERE name IS NULL", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(nulls, 2);
    assert_eq!(store::load_peers(&store).unwrap(), nameless);

    let named = PeerContents {
        name: Some("named".parse().unwrap()),
        ..nameless[0].clone()
    };
    assert_eq!(accept(&store, &[&named]), [Ok(())]);
    assert_eq!(store::load_peers(&store).unwrap()[0], named);
}

#[test]
fn test_invalid_stored_names_are_no_names() {
    // A stored name that isn't a valid hostname, as an operator may write by hand, reads as none.
    let store = Store::in_memory(network()).unwrap();
    let a = peer("a", "10.0.0.2");
    accept(&store, &[&a]);
    store
        .execute("UPDATE peers SET name = 'Not Valid'", [])
        .unwrap();
    assert_eq!(store::load_peers(&store).unwrap()[0].name, None);
}
