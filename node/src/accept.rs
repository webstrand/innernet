//! The input port of the node: what it accepts of the announcements that it receives.
//!
//! Every source of announcements, whether a client's fetch from the coordinator, the coordinator
//! itself once it has checked an announcement of a peer against what it assigns the peer, or the
//! announcements that the coordinator synthesizes for peers that have never announced, hands them
//! to [`Store::accept`](crate::db::Store::accept) as [`Received`]. The node accepts an
//! announcement whole or refuses it whole, with a [`Refusal`] that tells why: it never narrows
//! what a peer signed, so that every node that receives the same announcement makes the same of
//! it.
//!
//! The node applies the same rules whatever the source: the signature, the network, staleness and
//! the pins. What a peer may claim is the coordinator's to judge, before it hands the announcement
//! on; the node takes only the claims of the types that the coordinator checked.

pub use crate::claims::Conflict;
use crate::{
    claims::{Claim, Contender},
    store::{self, StoredAnnouncement},
};
use innernet_shared::{
    announcement::{self, Announcement, AnnouncementError, SignedAnnouncement},
    Prefix,
};
use ipnet::IpNet;
use rusqlite::Connection;
use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
};
use wireguard_control::Key;

/// An announcement that the node receives, of the peer with `public_key`, from the coordinator,
/// which checked its claims of `checked_types`: a signed announcement stands on its own, but its
/// claims of other types are left out, and an unsigned one, which the coordinator makes for a peer
/// that has never announced, is taken on the coordinator's word, until the peer first signs one.
#[derive(Clone, Copy, Debug)]
pub struct Received<'a> {
    pub public_key: &'a str,
    pub announcement: &'a SignedAnnouncement,
    pub checked_types: &'a [String],
    /// Whether the source hands the last accepted announcement over again, as a coordinator
    /// relays it on every fetch, so that one with the timestamp of the last is read again, in
    /// case the node now understands more of it, rather than refused as stale. A peer signs each
    /// timestamp once, so such an announcement is the same announcement.
    pub repeats: bool,
}

/// Why the node refuses an announcement. The node keeps the last announcement that it accepted
/// from the peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The public key of the peer isn't one.
    InvalidKey,
    /// The announcement can't be read: it is too large, its signature isn't the peer's, it is
    /// malformed, or it makes a claim of a type that isn't checked.
    Unreadable(AnnouncementError),
    /// The announcement claims `prefix`, outside the network `network`.
    OutsideNetwork { prefix: Prefix, network: IpNet },
    /// The announcement is unsigned, but the peer has signed one that the node accepted.
    Unsigned,
    /// The announcement isn't newer than the last one accepted from the peer.
    Stale { timestamp: u64, last: u64 },
    /// The timestamp of the announcement is too far ahead of the node's clock.
    TooFarAhead,
    /// The announcement claims what is pinned to another key.
    Pinned(Conflict),
}

impl Display for Refusal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey => f.write_str("the public key of the peer is not valid"),
            Self::Unreadable(e) => e.fmt(f),
            Self::OutsideNetwork { prefix, network } => {
                write!(f, "{prefix} is outside of the network {network}")
            },
            Self::Unsigned => {
                f.write_str("the announcement is unsigned, but the peer signs its announcements")
            },
            Self::Stale { timestamp, last } => AnnouncementError::Stale {
                timestamp: *timestamp,
                last: *last,
            }
            .fmt(f),
            Self::TooFarAhead => AnnouncementError::TooFarAhead.fmt(f),
            Self::Pinned(conflict) => {
                write!(f, "it claims what is pinned to another key: {conflict}")
            },
        }
    }
}

impl std::error::Error for Refusal {}

impl From<AnnouncementError> for Refusal {
    fn from(error: AnnouncementError) -> Self {
        match error {
            AnnouncementError::Stale { timestamp, last } => Self::Stale { timestamp, last },
            AnnouncementError::TooFarAhead => Self::TooFarAhead,
            error => Self::Unreadable(error),
        }
    }
}

/// An announcement that passed [`check`]: decoded, with only the claims that are trusted, and
/// whether it is signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checked {
    pub announcement: Announcement,
    pub signed: bool,
}

/// Checks `received` against `last`, the last announcement accepted from its peer, if any, at the
/// time `now`, as [`announcement::timestamp_now`] reads it, and decodes it, in this order:
///
/// 1. A signed one is read only once its signature, that of the peer, is checked, and with only
///    the claims of the types that the coordinator checked.
/// 2. Every prefix that it claims lies within `network`.
/// 3. It is signed if the peer has signed one that the node accepted.
/// 4. It is newer than `last`, or, if `received` repeats, of the same timestamp at least, and not
///    too far ahead of `now`.
///
/// What it claims is then pinned, as [`Scope::decide`](crate::db::Scope::decide) decides.
pub fn check(
    network: IpNet,
    received: &Received,
    last: Option<&StoredAnnouncement>,
    now: u64,
) -> Result<Checked, Refusal> {
    let signer = Key::from_base64(received.public_key).map_err(|_| Refusal::InvalidKey)?;
    let signed = received.announcement.is_signed();
    let mut announcement = if signed {
        received.announcement.open(&signer)?
    } else {
        received.announcement.decode()?
    };
    announcement.claims.retain_types(received.checked_types);
    if let Some(prefix) = announcement
        .claims
        .delegation
        .iter()
        .find(|prefix| !network.contains(&prefix.net()))
    {
        return Err(Refusal::OutsideNetwork {
            prefix: *prefix,
            network,
        });
    }
    if !signed && last.is_some_and(|last| last.signed) {
        return Err(Refusal::Unsigned);
    }
    let last = last.map(|last| last.announcement.timestamp);
    if received.repeats && last == Some(announcement.timestamp) {
        announcement::check_not_ahead(announcement.timestamp, now)?;
    } else {
        announcement::check_timestamp(announcement.timestamp, last, now)?;
    }
    // A timestamp beyond what SQLite stores lies far beyond any clock.
    i64::try_from(announcement.timestamp).map_err(|_| Refusal::TooFarAhead)?;
    // The claims are sorted, as the store reads them back.
    announcement.claims.delegation.sort();
    Ok(Checked {
        announcement,
        signed,
    })
}

/// An announcement that the node accepted, as [`Scope::apply`](crate::db::Scope::apply) records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    pub public_key: String,
    /// The announcement as the node records it. An unsigned announcement releases no name, so
    /// it is recorded with the name pinned to the key, which it claims in effect.
    pub announcement: Announcement,
    pub signed: bool,
    /// What is pinned to the key once the announcement is accepted.
    pub pinned: Claim,
    /// The announcement that it replaces, if any.
    pub previous: Option<StoredAnnouncement>,
}

/// Decides what the node accepts of `received`, at the time `now`, against what the store of
/// `conn` holds, without writing anything: each announcement is checked as [`check`] checks it,
/// and what each accepted one claims is pinned to its key, as [`crate::claims::resolve`] decides
/// it. A signed announcement pins what it claims and releases what it no longer claims; an
/// unsigned one pins what it claims beside what is pinned already, as [`Claim::unsigned`] adds
/// it, and releases nothing, so that the coordinator alone can't move what a peer that has never
/// announced holds to another key. An announcement that claims what is pinned to another key is
/// refused whole. Each of `received` must be of another peer.
///
/// Only what the announcements can conflict with is read: the last announcement and the claims of
/// each peer of `received`, and the claims of the keys to which a prefix that overlaps a claimed
/// prefix, or a claimed name, is pinned, as the indexes of the store find them.
pub(crate) fn decide(
    conn: &Connection,
    network: IpNet,
    received: &[Received],
    now: u64,
) -> Result<Vec<Result<Accepted, Refusal>>, rusqlite::Error> {
    let mut stored: HashMap<String, StoredAnnouncement> = HashMap::new();
    let mut claims: HashMap<String, Claim> = HashMap::new();
    for received in received {
        if let Ok(key) = store::key_to_bytes(received.public_key) {
            stored.extend(store::load_announcements(conn, Some(&key))?);
            claims.extend(store::load_claims(conn, Some(&key))?);
        }
    }

    let mut decided: Vec<Result<(Checked, Contender), Refusal>> = vec![];
    for received in received {
        let last = stored.get(received.public_key);
        decided.push(check(network, received, last, now).map(|checked| {
            let old = claims.get(received.public_key).cloned().unwrap_or_default();
            let new = if checked.signed {
                Claim::announced(&checked.announcement)
            } else {
                Claim::unsigned(&checked.announcement, &old)
            };
            let contender = Contender {
                public_key: received.public_key.to_string(),
                old,
                new,
            };
            (checked, contender)
        }));
    }

    // The other keys that hold what a contender newly claims, and what each holds.
    let mut holders: HashMap<String, Claim> = HashMap::new();
    for (_, contender) in decided.iter().filter_map(|decided| decided.as_ref().ok()) {
        let mut keys = vec![];
        for prefix in &contender.new.delegation {
            for (key, _) in store::pinned_overlapping(conn, prefix)? {
                keys.push(Key(key).to_base64());
            }
        }
        if let Some(name) = &contender.new.name {
            keys.extend(store::name_holder(conn, name)?);
        }
        for key in keys {
            if claims.contains_key(&key) || holders.contains_key(&key) {
                continue;
            }
            if let Ok(bytes) = store::key_to_bytes(&key) {
                holders.extend(store::load_claims(conn, Some(&bytes))?);
            }
        }
    }
    let claims: HashMap<String, Claim> = claims.into_iter().chain(holders).collect();

    let contenders: Vec<Contender> = decided
        .iter()
        .filter_map(|decided| decided.as_ref().ok())
        .map(|(_, contender)| contender.clone())
        .collect();
    let fixed: Vec<(&str, &Claim)> = claims
        .iter()
        .filter(|(key, _)| !contenders.iter().any(|c| &c.public_key == *key))
        .map(|(key, claim)| (key.as_str(), claim))
        .collect();
    let refusals = crate::claims::resolve(&fixed, &contenders);
    // What every key ends up with, against which a refused claim is explained.
    let pinned: Vec<(&str, Claim)> = contenders
        .iter()
        .zip(&refusals)
        .map(|(contender, refusal)| (contender.public_key.as_str(), contender.pinned(refusal)))
        .collect();
    let others = fixed
        .iter()
        .map(|(key, claim)| (*key, *claim))
        .chain(pinned.iter().map(|(key, claim)| (*key, claim)));

    let mut refusals = refusals.into_iter();
    Ok(decided
        .into_iter()
        .map(|decided| {
            let (checked, contender) = decided?;
            let refusal = refusals.next().unwrap_or_default();
            if refusal.is_refused() {
                return Err(Refusal::Pinned(
                    contender
                        .conflict(others.clone())
                        .unwrap_or(Conflict::Contested),
                ));
            }
            let pinned = contender.pinned(&refusal);
            let mut announcement = checked.announcement;
            if !checked.signed {
                announcement.claims.name = pinned.name.clone();
            }
            Ok(Accepted {
                previous: stored.remove(&contender.public_key),
                public_key: contender.public_key,
                announcement,
                signed: checked.signed,
                pinned,
            })
        })
        .collect())
}

/// Records `accepted`, as [`Scope::decide`](crate::db::Scope::decide) decided it, in the store of
/// `conn`: each announcement, and what is pinned to each key. Every key's pins are released before
/// any is made, so that what moves from one key to another is never pinned twice. The peers must be
/// recorded.
pub(crate) fn apply(conn: &Connection, accepted: &[Accepted]) -> Result<(), rusqlite::Error> {
    let keys = accepted
        .iter()
        .map(|accepted| {
            store::key_to_bytes(&accepted.public_key)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
        })
        .collect::<Result<Vec<_>, _>>()?;
    for (key, accepted) in keys.iter().zip(accepted) {
        store::write_announcement(conn, key, &accepted.announcement, accepted.signed)?;
    }
    for key in &keys {
        store::release_claims(conn, key)?;
    }
    for (key, accepted) in keys.iter().zip(accepted) {
        store::pin_claims(
            conn,
            key,
            &accepted.pinned,
            &accepted.announcement.claims.delegation,
        )?;
    }
    Ok(())
}

/// The types of claims that this version of the node understands, as a coordinator relays them
/// when it checks all of them.
pub fn all_claim_types() -> Vec<String> {
    announcement::CLAIM_TYPES.map(String::from).to_vec()
}
