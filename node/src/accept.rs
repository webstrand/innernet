//! The input port of the node: what it accepts of the records of peers that it receives.
//!
//! Every source of records, whether a client's fetch from the coordinator or the coordinator's
//! own changes, hands them to [`Store::accept`](crate::Store::accept). The node accepts a record
//! whole or refuses it whole, with a [`Refusal`] that tells why.
//!
//! Every delegation of a peer is pinned to its key once the node accepts a record of the peer, and
//! the pins of a key accumulate: a delegation that the coordinator withdraws stays pinned. A record
//! with a delegation that overlaps a prefix pinned to another key is refused whole, so that a
//! coordinator can't hand an address that the node has seen a peer hold to another key. A pin goes
//! only with its peer, when the coordinator deletes an invitation that was never redeemed.
//!
//! Pinning keeps a compromised coordinator from impersonating a peer that the node has seen, but
//! not from adding a new peer under its control.

use crate::store::{self, key_to_bytes};
use innernet_shared::{PeerContents, Prefix};
use ipnet::IpNet;
use rusqlite::Connection;
use std::{
    collections::HashSet,
    fmt::{self, Display, Formatter},
};

/// Why the node refuses the record of a peer. The node keeps what it recorded of the peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The public key of the peer isn't one.
    InvalidKey,
    /// A delegation of the peer lies outside the network.
    OutsideNetwork { prefix: Prefix, network: IpNet },
    /// A delegation of the peer overlaps a prefix pinned to another key.
    Pinned { prefix: Prefix },
    /// Two delegations of the peer overlap.
    Overlapping,
    /// Another peer has the name of the peer.
    NameTaken,
    /// An earlier record of the same batch has the key of the peer, or a delegation that overlaps
    /// one of the peer's.
    Duplicate,
}

impl Display for Refusal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey => f.write_str("the public key of the peer is not valid"),
            Self::OutsideNetwork { prefix, network } => {
                write!(f, "{prefix} is outside of the network {network}")
            },
            Self::Pinned { prefix } => write!(
                f,
                "PINNING ERROR: {prefix} overlaps a prefix pinned to another public key"
            ),
            Self::Overlapping => f.write_str("two delegations of the peer overlap"),
            Self::NameTaken => f.write_str("another peer has the name"),
            Self::Duplicate => f.write_str(
                "the public key or a delegation is shared with an earlier peer of the update",
            ),
        }
    }
}

impl std::error::Error for Refusal {}

/// The delegations of `peer`, sorted.
fn delegations(peer: &PeerContents) -> Vec<Prefix> {
    vec![Prefix::host(peer.ip)]
}

/// Decides what the node accepts of `peers`, within the network `network`, without writing
/// anything. A record is refused if its key is invalid, a delegation lies outside the network or
/// overlaps a prefix pinned to another key, two of its delegations overlap, it shares its key or a
/// delegation with an earlier record of `peers`, or its name belongs to a peer that keeps it. Any
/// number of peers can be without a name.
pub(crate) fn decide(
    conn: &Connection,
    network: IpNet,
    peers: &[&PeerContents],
) -> Result<Vec<Result<(), Refusal>>, rusqlite::Error> {
    let mut decided = vec![];
    let mut seen_keys = HashSet::new();
    let mut seen: Vec<Prefix> = vec![];
    for peer in peers {
        let decision = check(conn, network, peer)?.and_then(|()| {
            let delegations = delegations(peer);
            let shared = delegations
                .iter()
                .any(|delegation| seen.iter().any(|other| other.overlaps(delegation)));
            if !seen_keys.insert(peer.public_key.clone()) || shared {
                return Err(Refusal::Duplicate);
            }
            seen.extend(delegations);
            Ok(())
        });
        decided.push(decision);
    }

    // A name may move between peers within one batch, but not to a peer whose holder keeps it:
    // one whose record isn't accepted, or is accepted with the same name, or another accepted
    // record with the name. Refusing a record can make a name kept, so this runs until nothing
    // changes.
    loop {
        let mut changed = false;
        for i in 0..peers.len() {
            if decided[i].is_err() {
                continue;
            }
            let peer = peers[i];
            let Some(name) = &peer.name else {
                continue;
            };
            let taken_in_batch = peers[..i]
                .iter()
                .zip(&decided)
                .any(|(other, decided)| decided.is_ok() && other.name.as_ref() == Some(name));
            let kept_by_holder = match store::name_holder(conn, name)? {
                Some(holder) if holder != key_to_bytes(&peer.public_key).expect("checked") => {
                    !peers.iter().zip(&decided).any(|(other, decided)| {
                        decided.is_ok()
                            && key_to_bytes(&other.public_key).ok() == Some(holder)
                            && other.name.as_ref() != Some(name)
                    })
                },
                _ => false,
            };
            if taken_in_batch || kept_by_holder {
                decided[i] = Err(Refusal::NameTaken);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    Ok(decided)
}

/// Checks `peer` alone, against the network `network` and the pins of the node, which the index of
/// the last addresses of the pins finds.
fn check(
    conn: &Connection,
    network: IpNet,
    peer: &PeerContents,
) -> Result<Result<(), Refusal>, rusqlite::Error> {
    let Ok(key) = key_to_bytes(&peer.public_key) else {
        return Ok(Err(Refusal::InvalidKey));
    };
    let delegations = delegations(peer);
    if delegations
        .windows(2)
        .any(|pair| pair[0].overlaps(&pair[1]))
    {
        return Ok(Err(Refusal::Overlapping));
    }
    for prefix in delegations {
        if !network.contains(&prefix.net()) {
            return Ok(Err(Refusal::OutsideNetwork { prefix, network }));
        }
        if store::pinned_overlapping(conn, &prefix)?
            .iter()
            .any(|(holder, _)| *holder != key)
        {
            return Ok(Err(Refusal::Pinned { prefix }));
        }
    }
    Ok(Ok(()))
}

/// Records `peers`, which [`decide`] accepted: each record in place of the stored one, its
/// delegations, each pinned to its key, and its endpoints. The names of the peers are cleared
/// first, so that a name moving between them is never held twice.
pub(crate) fn apply(conn: &Connection, peers: &[&PeerContents]) -> Result<(), rusqlite::Error> {
    let keys: Vec<[u8; 32]> = peers
        .iter()
        .map(|peer| key_to_bytes(&peer.public_key).expect("accepted"))
        .collect();
    for key in &keys {
        conn.execute(
            "UPDATE peers SET name = NULL WHERE public_key = ?1",
            rusqlite::params![key],
        )?;
    }
    for (peer, key) in peers.iter().zip(&keys) {
        store::write_peer(conn, key, peer)?;
    }
    Ok(())
}
