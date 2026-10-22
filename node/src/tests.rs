//! Tests of the node's database and of the input port.

use crate::{
    accept::{self, Conflict, Received, Refusal},
    claims::Claim,
    db::Store,
    store::{self, key_to_bytes, EndpointKind, PinKind, StoreError},
};
use innernet_shared::{
    announcement::{self, Announcement, AnnouncementError, Claims, SignedAnnouncement},
    xeddsa, Prefix,
};
use rusqlite::Connection;
use wireguard_control::KeyPair;

/// A new database of the current schema, for the network 10.0.0.0/16.
fn database() -> Store {
    Store::in_memory("10.0.0.0/16".parse().unwrap()).unwrap()
}

/// Records a peer with the key `keypair`.
fn record(conn: &Connection, keypair: &KeyPair) {
    conn.execute(
        "INSERT INTO peers (public_key) VALUES (?1)",
        [keypair.public.0],
    )
    .unwrap();
}

fn prefixes(prefixes: &[&str]) -> Vec<Prefix> {
    prefixes.iter().map(|p| p.parse().unwrap()).collect()
}

/// An announcement that claims `delegation` and `name`, with the first address of the delegation
/// as its primary IP.
fn announcement(timestamp: u64, delegation: &[&str], name: Option<&str>) -> Announcement {
    Announcement {
        timestamp,
        claims: Claims {
            delegation: prefixes(delegation),
            name: name.map(|name| name.parse().unwrap()),
        },
        allowed_ips: prefixes(delegation),
        primary_ip: prefixes(delegation).first().map(Prefix::first),
        ..Default::default()
    }
}

fn sign(keypair: &KeyPair, announcement: &Announcement) -> SignedAnnouncement {
    let private_key = xeddsa::PrivateKey::from_base64(&keypair.private.to_base64()).unwrap();
    announcement.sign(&private_key).unwrap()
}

#[test]
fn test_kinds_match_tables() {
    let conn = database();
    let kinds = |table: &str| -> Vec<(i64, String)> {
        let mut stmt = conn
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
fn test_schema_keeps_consistency() {
    // The schema refuses what would make the database inconsistent: a name pinned to two keys, a
    // pin whose last address lies before its first, and a peer deleted before what refers to it.
    // It lets an operator move a pin by hand.
    let conn = database();
    let [key, other] = [(); 2].map(|_| KeyPair::generate());
    record(&conn, &key);
    record(&conn, &other);
    let hex = |keypair: &KeyPair| -> String {
        keypair
            .public
            .0
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    };
    let (key, other) = (hex(&key), hex(&other));
    conn.execute_batch(&format!(
        "INSERT INTO prefix_pins VALUES (x'0a000100', 24, x'0a0001ff', x'{other}', 1, 1);
         UPDATE peers SET name = 'other' WHERE public_key = x'{other}';"
    ))
    .unwrap();
    for refused in [
        format!("INSERT INTO prefix_pins VALUES (x'0a000209', 32, x'0a000200', x'{key}', 1, 1)"),
        format!("UPDATE peers SET name = 'other' WHERE public_key = x'{key}'"),
        format!("DELETE FROM peers WHERE public_key = x'{other}'"),
    ] {
        assert!(
            conn.execute_batch(&refused).is_err(),
            "{refused} was accepted"
        );
    }
    conn.execute_batch(&format!(
        "UPDATE prefix_pins SET public_key = x'{key}';
         DELETE FROM prefix_pins;
         DELETE FROM peers WHERE public_key = x'{other}';"
    ))
    .unwrap();
}

#[test]
fn test_store_refuses_what_accept_never_asks() {
    let conn = database();
    let [peer, other] = [(); 2].map(|_| KeyPair::generate());
    record(&conn, &peer);
    record(&conn, &other);
    let (key, other_key) = (peer.public.0, other.public.0);
    let pinned = |error: rusqlite::Error| store::store_error(&error).cloned();

    // A prefix that overlaps one pinned to another key is refused, while the pins of one key
    // nest.
    let claim = |delegation: &[&str]| Claim {
        delegation: prefixes(delegation),
        name: None,
    };
    store::pin_claims(&conn, &key, &claim(&["10.0.1.0/24"]), &[]).unwrap();
    store::pin_claims(&conn, &key, &claim(&["10.0.1.0/25"]), &[]).unwrap();
    for refused in [&["10.0.1.0/24"][..], &["10.0.1.128/25"], &["10.0.0.0/23"]] {
        let error = store::pin_claims(&conn, &other_key, &claim(refused), &[]).unwrap_err();
        assert!(matches!(pinned(error), Some(StoreError::Pinned(_))));
    }

    // An announcement older than the stored one is refused; a signed one latches the peer, after
    // which an unsigned one is refused; an unknown peer has none.
    let at = |timestamp| announcement(timestamp, &["10.0.1.0/24"], None);
    store::write_announcement(&conn, &key, &at(5), false).unwrap();
    let error = store::write_announcement(&conn, &key, &at(4), false).unwrap_err();
    assert_eq!(pinned(error), Some(StoreError::Older));
    store::write_announcement(&conn, &key, &at(6), true).unwrap();
    assert_eq!(store::announces(&conn, &key).unwrap(), Some(true));
    let error = store::write_announcement(&conn, &key, &at(7), false).unwrap_err();
    assert_eq!(pinned(error), Some(StoreError::Unsigned));
    let unknown = KeyPair::generate().public.0;
    let error = store::write_announcement(&conn, &unknown, &at(7), true).unwrap_err();
    assert_eq!(pinned(error), Some(StoreError::UnknownPeer));

    // Forgetting a peer deletes it with its announcement and its pins, which another key may then
    // take.
    store::forget_peer(&conn, &key).unwrap();
    assert_eq!(store::announces(&conn, &key).unwrap(), None);
    store::pin_claims(&conn, &other_key, &claim(&["10.0.1.0/24"]), &[]).unwrap();
}

#[test]
fn test_accept() {
    let conn = database();
    let [peer, other] = [(); 2].map(|_| KeyPair::generate());
    record(&conn, &peer);
    record(&conn, &other);
    let key = peer.public.to_base64();
    let all_types = accept::all_claim_types();
    let relayed: &[String] = &all_types;
    let now = announcement::timestamp_now();
    let accept = |key: &str, signed: &SignedAnnouncement, checked_types: &[String], repeats| {
        let received = Received {
            public_key: key,
            announcement: signed,
            checked_types,
            repeats,
        };
        conn.accept_one(&received, now).unwrap()
    };
    let stored = |key: &str| {
        store::load_announcements(&conn, Some(&key_to_bytes(key).unwrap()))
            .unwrap()
            .remove(key)
    };
    let claims = |key: &str| {
        store::load_claims(&conn, Some(&key_to_bytes(key).unwrap()))
            .unwrap()
            .remove(key)
            .unwrap_or_default()
    };

    // An unsigned announcement, on the coordinator's word, pins what it claims.
    let synthetic = announcement(0, &["10.0.1.0/24"], Some("peer"));
    let unsigned = SignedAnnouncement::unsigned(&synthetic).unwrap();
    let accepted = accept(&key, &unsigned, relayed, true).unwrap();
    assert!(!accepted.signed);
    assert_eq!(stored(&key).unwrap().announcement, synthetic);
    // The same again is read again.
    assert!(accept(&key, &unsigned, relayed, true).is_ok());

    // Another unsigned one releases nothing: neither the prefix that it leaves out, nor the name.
    let moved = announcement(0, &["10.0.2.0/24"], Some("moved"));
    let accepted = accept(
        &key,
        &SignedAnnouncement::unsigned(&moved).unwrap(),
        relayed,
        true,
    )
    .unwrap();
    assert_eq!(accepted.announcement.claims.name, synthetic.claims.name);
    assert_eq!(
        claims(&key).delegation,
        prefixes(&["10.0.1.0/24", "10.0.2.0/24"])
    );
    assert_eq!(
        stored(&key).unwrap().announcement.claims.delegation,
        prefixes(&["10.0.2.0/24"])
    );

    // Another key can't claim what is pinned to the peer, whatever it signs.
    let grabbing = sign(
        &other,
        &announcement(now, &["10.0.1.128/25"], Some("other")),
    );
    assert_eq!(
        accept(&other.public.to_base64(), &grabbing, relayed, true),
        Err(Refusal::Pinned(Conflict::Prefix {
            claimed: "10.0.1.128/25".parse().unwrap(),
            held: "10.0.1.0/24".parse().unwrap(),
            holder: key.clone(),
        }))
    );
    let naming = sign(&other, &announcement(now, &[], Some("peer")));
    assert_eq!(
        accept(&other.public.to_base64(), &naming, relayed, true),
        Err(Refusal::Pinned(Conflict::Name {
            name: "peer".parse().unwrap(),
            holder: key.clone(),
        }))
    );
    assert_eq!(stored(&other.public.to_base64()), None);

    // The first signed announcement latches the peer, and releases what it no longer claims.
    let first = announcement(now, &["10.0.1.0/25"], Some("signed"));
    assert!(
        accept(&key, &sign(&peer, &first), relayed, true)
            .unwrap()
            .signed
    );
    assert_eq!(claims(&key).delegation, first.claims.delegation);
    assert_eq!(claims(&key).name, first.claims.name);
    assert_eq!(store::announces(&conn, &peer.public.0).unwrap(), Some(true));

    // From then on, an unsigned one is refused, as is a stale one, one from too far ahead, and
    // one that isn't the peer's, and the last accepted one stays.
    let later = announcement(now + 1, &["10.0.1.0/26"], None);
    for (received, refusal) in [
        (
            SignedAnnouncement::unsigned(&later).unwrap(),
            Refusal::Unsigned,
        ),
        (
            sign(
                &peer,
                &Announcement {
                    timestamp: now - 1,
                    ..first.clone()
                },
            ),
            Refusal::Stale {
                timestamp: now - 1,
                last: now,
            },
        ),
        (
            sign(
                &peer,
                &Announcement {
                    timestamp: now + 3_600_000_000_000,
                    ..first.clone()
                },
            ),
            Refusal::TooFarAhead,
        ),
        (
            sign(&other, &later),
            Refusal::Unreadable(AnnouncementError::BadSignature),
        ),
        (
            sign(&peer, &announcement(now + 1, &["10.1.0.0/24"], None)),
            Refusal::OutsideNetwork {
                prefix: "10.1.0.0/24".parse().unwrap(),
                network: "10.0.0.0/16".parse().unwrap(),
            },
        ),
    ] {
        assert_eq!(accept(&key, &received, relayed, true), Err(refusal));
        assert_eq!(stored(&key).unwrap().announcement, first);
    }
    // The same signed announcement again is refused from a source that doesn't repeat.
    let again = sign(&peer, &first);
    assert!(accept(&key, &again, relayed, true).is_ok());
    assert!(matches!(
        accept(&key, &again, relayed, false),
        Err(Refusal::Stale { .. })
    ));

    // Only the claims of the types that the coordinator checks are taken.
    let types = ["delegation".to_string()];
    let renamed = announcement(now + 2, &["10.0.1.0/25"], Some("renamed"));
    let accepted = accept(&key, &sign(&peer, &renamed), &types, true).unwrap();
    assert_eq!(accepted.announcement.claims.name, None);
    assert_eq!(claims(&key).name, None);
}
