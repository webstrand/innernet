//! The input port of the node: what it accepts of the records of peers that it receives.
//!
//! Every source of records, whether a client's fetch from the coordinator or the coordinator's
//! own changes, hands them to [`Store::accept`](crate::Store::accept). The node accepts a record
//! whole or refuses it whole, with a [`Refusal`] that tells why.
//!
//! The address of a peer is pinned to its key once the node accepts a record of the peer: a later
//! record of the key at another address is refused, as is one of another key at the address, so
//! that a coordinator can neither move a peer that the node has seen nor hand its address to
//! another key. A pin goes only with its peer, when the coordinator deletes an invitation that
//! was never redeemed.

use crate::store::{self, key_to_bytes};
use innernet_shared::{Hostname, PeerContents};
use ipnet::IpNet;
use rusqlite::Connection;
use std::{
    collections::HashSet,
    fmt::{self, Display, Formatter},
    net::IpAddr,
};

/// Why the node refuses the record of a peer. The node keeps what it recorded of the peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The public key of the peer isn't one.
    InvalidKey,
    /// The name of the peer isn't a valid hostname.
    InvalidName,
    /// The address of the peer lies outside the network.
    OutsideNetwork { ip: IpAddr, network: IpNet },
    /// The address of the peer is pinned to another key.
    AddressPinned { ip: IpAddr },
    /// The key of the peer is pinned to another address.
    KeyPinned { pinned: IpAddr },
    /// Another peer has the name of the peer.
    NameTaken,
    /// An earlier record of the same batch has the address or the key of the peer.
    Duplicate,
}

impl Display for Refusal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey => f.write_str("the public key of the peer is not valid"),
            Self::InvalidName => f.write_str("the name is not a valid hostname"),
            Self::OutsideNetwork { ip, network } => {
                write!(f, "IP {ip} is outside of the network {network}")
            },
            Self::AddressPinned { ip } => {
                write!(f, "PINNING ERROR: {ip} is pinned to another public key")
            },
            Self::KeyPinned { pinned } => write!(
                f,
                "PINNING ERROR: the public key is pinned to another IP, {pinned}"
            ),
            Self::NameTaken => f.write_str("another peer has the name"),
            Self::Duplicate => {
                f.write_str("IP or public key is shared with an earlier peer of the update")
            },
        }
    }
}

impl std::error::Error for Refusal {}

/// Decides what the node accepts of `peers`, within the network `network`, without writing
/// anything. A record is refused if its key or name is invalid, its address lies outside the
/// network, it conflicts with a pin, it shares its address or key with an earlier record of
/// `peers`, or its name belongs to a peer that keeps it.
pub(crate) fn decide(
    conn: &Connection,
    network: IpNet,
    peers: &[&PeerContents],
) -> Result<Vec<Result<(), Refusal>>, rusqlite::Error> {
    let mut decided = vec![];
    let mut seen_ips = HashSet::new();
    let mut seen_keys = HashSet::new();
    for peer in peers {
        let decision = check(conn, network, peer)?.and_then(|()| {
            let fresh_ip = seen_ips.insert(peer.ip);
            let fresh_key = seen_keys.insert(peer.public_key.clone());
            if fresh_ip && fresh_key {
                Ok(())
            } else {
                Err(Refusal::Duplicate)
            }
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
            let taken_in_batch = peers[..i]
                .iter()
                .zip(&decided)
                .any(|(other, decided)| decided.is_ok() && other.name == peer.name);
            let kept_by_holder = match store::name_holder(conn, &peer.name)? {
                Some(holder) if holder != key_to_bytes(&peer.public_key).expect("checked") => {
                    !peers.iter().zip(&decided).any(|(other, decided)| {
                        decided.is_ok()
                            && key_to_bytes(&other.public_key).ok() == Some(holder)
                            && other.name != peer.name
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

/// Checks `peer` alone, against the network `network` and the pins of the node.
fn check(
    conn: &Connection,
    network: IpNet,
    peer: &PeerContents,
) -> Result<Result<(), Refusal>, rusqlite::Error> {
    let Ok(key) = key_to_bytes(&peer.public_key) else {
        return Ok(Err(Refusal::InvalidKey));
    };
    if !Hostname::is_valid(&peer.name) {
        return Ok(Err(Refusal::InvalidName));
    }
    if !network.contains(&peer.ip) {
        return Ok(Err(Refusal::OutsideNetwork {
            ip: peer.ip,
            network,
        }));
    }
    if store::holders_of(conn, peer.ip)?
        .iter()
        .any(|holder| *holder != key)
    {
        return Ok(Err(Refusal::AddressPinned { ip: peer.ip }));
    }
    match store::pinned_address(conn, &key)? {
        Some(pinned) if pinned != peer.ip => Ok(Err(Refusal::KeyPinned { pinned })),
        _ => Ok(Ok(())),
    }
}

/// Records `peers`, which [`decide`] accepted: each record in place of the stored one, its
/// endpoints, and its address pinned to its key. The names of the peers are cleared first, so
/// that a name moving between them is never held twice.
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
