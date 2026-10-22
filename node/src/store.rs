//! Access to the node tables of [`SCHEMA`](crate::SCHEMA), through a [`Connection`], which a
//! [`rusqlite::Transaction`] dereferences to. Each function reads or writes what it names and
//! nothing else, and leaves transactions to the host: the host decides what applies together.
//!
//! Public keys are passed to the writers as the 32 bytes that the database holds, which
//! [`key_to_bytes`] makes of their base64 text, and the readers key their results by the canonical
//! base64 text, as a state's public keys are deserialized.

use crate::claims::Claim;
use innernet_shared::{announcement::Announcement, Cidr, Endpoint, Hostname, PeerContents, Prefix};
use ipnet::IpNet;
use rusqlite::{params, types::Type, Connection, OptionalExtension as _, Row};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, UNIX_EPOCH},
};
use wireguard_control::{InvalidKey, Key};

/// The kinds of the endpoints of `endpoints`, as the `endpoint_kinds` table names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    /// The endpoint that the node records of a peer apart from its announcements.
    Endpoint = 0,
    /// The candidates that the node records of a peer apart from its announcements.
    Candidate = 1,
    /// The endpoints that the last announcement accepted from a peer states, in their order.
    Announced = 2,
}

impl EndpointKind {
    /// Every kind, with its name in `endpoint_kinds`.
    pub const ALL: &'static [(Self, &'static str)] = &[
        (Self::Endpoint, "endpoint"),
        (Self::Candidate, "candidate"),
        (Self::Announced, "announced"),
    ];

    fn from_i64(kind: i64) -> Option<Self> {
        Self::ALL
            .iter()
            .map(|(kind, _)| *kind)
            .find(|known| *known as i64 == kind)
    }
}

/// The kinds of the pins of `prefix_pins`, as the `pin_kinds` table names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinKind {
    /// A prefix of the delegation that a peer claims.
    Delegation = 1,
}

impl PinKind {
    /// Every kind, with its name in `pin_kinds`.
    pub const ALL: &'static [(Self, &'static str)] = &[(Self::Delegation, "delegation")];
}

/// The 32 bytes of the WireGuard public key `public_key` in base64.
pub fn key_to_bytes(public_key: &str) -> Result<[u8; 32], InvalidKey> {
    Ok(Key::from_base64(public_key)?.0)
}

/// The canonical base64 encoding of the WireGuard public key of `bytes`.
pub fn key_from_bytes(bytes: &[u8]) -> Result<String, InvalidKey> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| InvalidKey)?;
    Ok(Key(bytes).to_base64())
}

/// The bytes of `ip`, as the database holds an address: 4 for IPv4, 16 for IPv6.
pub fn ip_to_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

/// The address of `bytes`, or `None` if they are neither 4 nor 16.
pub fn ip_from_bytes(bytes: &[u8]) -> Option<IpAddr> {
    if let Ok(octets) = <[u8; 4]>::try_from(bytes) {
        Some(Ipv4Addr::from(octets).into())
    } else if let Ok(octets) = <[u8; 16]>::try_from(bytes) {
        Some(Ipv6Addr::from(octets).into())
    } else {
        None
    }
}

/// The prefix whose first address has the bytes `address`, of the length `prefix_len`, as the
/// tables of prefixes hold it.
pub fn prefix_from_row(address: Vec<u8>, prefix_len: u8) -> Result<Prefix, rusqlite::Error> {
    let invalid = || rusqlite::Error::InvalidColumnType(0, "prefix".into(), Type::Blob);
    let ip = ip_from_bytes(&address).ok_or_else(invalid)?;
    let net = IpNet::new(ip, prefix_len).map_err(|_| invalid())?;
    Prefix::new(net).map_err(|_| invalid())
}

/// The public key of a row, in the column `column`, in its canonical base64 encoding.
pub fn row_key(row: &Row, column: usize) -> Result<String, rusqlite::Error> {
    key_from_bytes(&row.get::<_, Vec<u8>>(column)?)
        .map_err(|_| rusqlite::Error::InvalidColumnType(column, "public key".into(), Type::Blob))
}

/// The address of a row, in the column `column`.
fn row_ip(row: &Row, column: usize) -> Result<Option<IpAddr>, rusqlite::Error> {
    row.get::<_, Option<Vec<u8>>>(column)?
        .map(|bytes| {
            ip_from_bytes(&bytes).ok_or_else(|| {
                rusqlite::Error::InvalidColumnType(column, "address".into(), Type::Blob)
            })
        })
        .transpose()
}

/// Replaces the endpoints of the kind `kind` of the peer with the public key `key` with
/// `endpoints`, in their order.
pub fn write_endpoints<'a>(
    conn: &Connection,
    key: &[u8; 32],
    kind: EndpointKind,
    endpoints: impl IntoIterator<Item = &'a Endpoint>,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "DELETE FROM endpoints WHERE public_key = ?1 AND kind = ?2",
        params![key, kind as i64],
    )?;
    for (position, endpoint) in endpoints.into_iter().enumerate() {
        conn.execute(
            "INSERT INTO endpoints (public_key, kind, position, address, domain, port)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                key,
                kind as i64,
                position,
                endpoint.ip().map(ip_to_bytes),
                endpoint.domain(),
                endpoint.port(),
            ],
        )?;
    }
    Ok(())
}

/// The endpoints of a peer, as `endpoints` holds them: those that the node records apart from the
/// peer's announcements, and those that its last accepted announcement states, in their order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoredEndpoints {
    pub endpoint: Option<Endpoint>,
    pub candidates: Vec<Endpoint>,
    pub announced: Vec<Endpoint>,
}

/// The endpoints of every peer, or only of the peer with the public key `only`, by public key.
pub fn load_endpoints(
    conn: &Connection,
    only: Option<&[u8; 32]>,
) -> Result<HashMap<String, StoredEndpoints>, rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "SELECT public_key, kind, address, domain, port FROM endpoints
         WHERE ?1 IS NULL OR public_key = ?1
         ORDER BY public_key, kind, position",
    )?;
    let mut rows = stmt.query(params![only])?;
    let mut endpoints: HashMap<String, StoredEndpoints> = HashMap::new();
    while let Some(row) = rows.next()? {
        let port: u16 = row.get(4)?;
        let endpoint = match (row_ip(row, 2)?, row.get::<_, Option<String>>(3)?) {
            (Some(ip), None) => Endpoint::from(SocketAddr::new(ip, port)),
            (None, Some(domain)) => Endpoint::from_domain(&domain, port)
                .map_err(|_| rusqlite::Error::InvalidColumnType(3, "domain".into(), Type::Text))?,
            _ => {
                return Err(rusqlite::Error::InvalidColumnType(
                    2,
                    "endpoint".into(),
                    Type::Null,
                ))
            },
        };
        let kind = EndpointKind::from_i64(row.get(1)?).ok_or_else(|| {
            rusqlite::Error::InvalidColumnType(1, "endpoint kind".into(), Type::Integer)
        })?;
        let entry = endpoints.entry(row_key(row, 0)?).or_default();
        match kind {
            EndpointKind::Endpoint => entry.endpoint = Some(endpoint),
            EndpointKind::Candidate => entry.candidates.push(endpoint),
            EndpointKind::Announced => entry.announced.push(endpoint),
        }
    }
    Ok(endpoints)
}

/// Writes `announcement`, the last one accepted from the peer with the public key `key`, and
/// whether it is `signed`, decoded, in place of the stored one: its timestamp and its statements,
/// its announced endpoints among them, in their order. Its claims are pinned apart, with
/// [`release_claims`] and [`pin_claims`]. An older announcement is refused, as is an unsigned
/// one of a peer that has signed one, as [`StoreError`] tells; a signed one latches the peer, so
/// that only its signed announcements are written from then on.
pub fn write_announcement(
    conn: &Connection,
    key: &[u8; 32],
    announcement: &Announcement,
    signed: bool,
) -> Result<(), rusqlite::Error> {
    let stored: Option<(Option<u64>, bool)> = conn
        .query_row(
            "SELECT a.timestamp, p.announces FROM peers p
             LEFT JOIN announcements a ON a.public_key = p.public_key
             WHERE p.public_key = ?1",
            params![key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    match stored {
        None => return Err(StoreError::UnknownPeer.into()),
        Some((Some(last), _)) if announcement.timestamp < last => {
            return Err(StoreError::Older.into());
        },
        Some((_, true)) if !signed => return Err(StoreError::Unsigned.into()),
        _ => {},
    }
    let Announcement {
        timestamp,
        claims: _,
        allowed_ips,
        primary_ip,
        endpoints,
        nameserver: _,
    } = announcement;
    let timestamp = i64::try_from(*timestamp)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    conn.execute(
        "INSERT INTO announcements (public_key, timestamp, signed, primary_ip)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (public_key) DO UPDATE SET timestamp = excluded.timestamp,
           signed = excluded.signed, primary_ip = excluded.primary_ip",
        params![key, timestamp, signed, primary_ip.map(ip_to_bytes)],
    )?;
    conn.execute(
        "DELETE FROM announced_allowed_ips WHERE public_key = ?1",
        params![key],
    )?;
    for prefix in allowed_ips {
        conn.execute(
            "INSERT INTO announced_allowed_ips (public_key, address, prefix_len)
             VALUES (?1, ?2, ?3)
             ON CONFLICT DO NOTHING",
            params![key, ip_to_bytes(prefix.first()), prefix.prefix_len()],
        )?;
    }
    if signed {
        conn.execute(
            "UPDATE peers SET announces = 1 WHERE public_key = ?1",
            params![key],
        )?;
    }
    write_endpoints(conn, key, EndpointKind::Announced, endpoints)
}

/// Releases what is pinned to the key `key`: its prefixes and its name. A host that pins the
/// claims of several keys at once releases them all before it pins any, so that what moves from
/// one key to another in one update is never pinned twice; the store refuses that.
pub fn release_claims(conn: &Connection, key: &[u8; 32]) -> Result<(), rusqlite::Error> {
    conn.execute(
        "DELETE FROM prefix_pins WHERE public_key = ?1",
        params![key],
    )?;
    conn.execute(
        "UPDATE peers SET name = NULL WHERE public_key = ?1 AND name IS NOT NULL",
        params![key],
    )?;
    Ok(())
}

/// Pins `claim` to the key `key`, each of its prefixes marked claimed if `claimed`, the
/// delegation that the last announcement accepted from the peer claims, holds it, and its name as
/// the name of the peer. A prefix that overlaps one pinned to another key is refused, as
/// [`StoreError::Pinned`], and the database refuses a name pinned to another key.
pub fn pin_claims(
    conn: &Connection,
    key: &[u8; 32],
    claim: &Claim,
    claimed: &[Prefix],
) -> Result<(), rusqlite::Error> {
    for prefix in &claim.delegation {
        if pinned_overlapping(conn, prefix)?
            .iter()
            .any(|(holder, _)| holder != key)
        {
            return Err(StoreError::Pinned(*prefix).into());
        }
        conn.execute(
            "INSERT INTO prefix_pins (address, prefix_len, last, public_key, kind, claimed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (address, prefix_len) DO NOTHING",
            params![
                ip_to_bytes(prefix.first()),
                prefix.prefix_len(),
                ip_to_bytes(prefix.last()),
                key,
                PinKind::Delegation as i64,
                claimed.contains(prefix),
            ],
        )?;
    }
    conn.execute(
        "UPDATE peers SET name = ?2 WHERE public_key = ?1",
        params![key, claim.name.as_deref()],
    )?;
    Ok(())
}

/// What is pinned to the key of every peer, or only to the key `only`, by public key: its prefixes,
/// sorted, and its name. A peer with nothing pinned to it is left out. A stored name that isn't a
/// valid [`Hostname`] is no name.
pub fn load_claims(
    conn: &Connection,
    only: Option<&[u8; 32]>,
) -> Result<HashMap<String, Claim>, rusqlite::Error> {
    let mut claims: HashMap<String, Claim> = HashMap::new();
    let mut stmt = conn.prepare_cached(
        "SELECT public_key, name FROM peers
         WHERE name IS NOT NULL AND (?1 IS NULL OR public_key = ?1)",
    )?;
    let mut rows = stmt.query(params![only])?;
    while let Some(row) = rows.next()? {
        let name = Hostname::try_from(row.get::<_, String>(1)?).ok();
        if name.is_some() {
            claims.entry(row_key(row, 0)?).or_default().name = name;
        }
    }
    let mut stmt = conn.prepare_cached(
        "SELECT public_key, address, prefix_len FROM prefix_pins
         WHERE ?1 IS NULL OR public_key = ?1
         ORDER BY length(address), address, prefix_len",
    )?;
    let mut rows = stmt.query(params![only])?;
    while let Some(row) = rows.next()? {
        let prefix = prefix_from_row(row.get(1)?, row.get(2)?)?;
        claims
            .entry(row_key(row, 0)?)
            .or_default()
            .delegation
            .push(prefix);
    }
    Ok(claims)
}

/// The last announcement accepted from a peer, as the node stores it decoded, and whether it was
/// signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredAnnouncement {
    pub announcement: Announcement,
    pub signed: bool,
}

/// The last announcement accepted from every peer, or only from the peer with the public key
/// `only`, by public key, as the node stores it decoded: its timestamp and its statements, with
/// the announced endpoints in their order, and its claims, the claimed prefixes pinned to the
/// peer's key and the name of the peer. A stored name that isn't valid is none.
pub fn load_announcements(
    conn: &Connection,
    only: Option<&[u8; 32]>,
) -> Result<HashMap<String, StoredAnnouncement>, rusqlite::Error> {
    let mut announcements: HashMap<String, StoredAnnouncement> = HashMap::new();
    let mut stmt = conn.prepare_cached(
        "SELECT a.public_key, a.timestamp, a.signed, a.primary_ip, p.name
         FROM announcements a JOIN peers p ON p.public_key = a.public_key
         WHERE ?1 IS NULL OR a.public_key = ?1",
    )?;
    let mut rows = stmt.query(params![only])?;
    while let Some(row) = rows.next()? {
        let mut announcement = Announcement {
            timestamp: row.get(1)?,
            primary_ip: row_ip(row, 3)?,
            ..Default::default()
        };
        announcement.claims.name = row
            .get::<_, Option<String>>(4)?
            .and_then(|name| Hostname::try_from(name).ok());
        announcements.insert(
            row_key(row, 0)?,
            StoredAnnouncement {
                announcement,
                signed: row.get(2)?,
            },
        );
    }
    let mut stmt = conn.prepare_cached(
        "SELECT public_key, address, prefix_len FROM prefix_pins
         WHERE claimed = 1 AND (?1 IS NULL OR public_key = ?1)
         ORDER BY length(address), address, prefix_len",
    )?;
    let mut rows = stmt.query(params![only])?;
    while let Some(row) = rows.next()? {
        if let Some(stored) = announcements.get_mut(&row_key(row, 0)?) {
            let prefix = prefix_from_row(row.get(1)?, row.get(2)?)?;
            stored.announcement.claims.delegation.push(prefix);
        }
    }
    let mut stmt = conn.prepare_cached(
        "SELECT public_key, address, prefix_len FROM announced_allowed_ips
         WHERE ?1 IS NULL OR public_key = ?1
         ORDER BY length(address), address, prefix_len",
    )?;
    let mut rows = stmt.query(params![only])?;
    while let Some(row) = rows.next()? {
        if let Some(stored) = announcements.get_mut(&row_key(row, 0)?) {
            let prefix = prefix_from_row(row.get(1)?, row.get(2)?)?;
            stored.announcement.allowed_ips.push(prefix);
        }
    }
    for (public_key, endpoints) in load_endpoints(conn, only)? {
        if let Some(stored) = announcements.get_mut(&public_key) {
            stored.announcement.endpoints = endpoints.announced;
        }
    }
    Ok(announcements)
}

/// Whether the peer with the public key `key` has signed an announcement that the node accepted,
/// after which only its signed announcements are accepted, or `None` if the node doesn't record
/// the peer.
pub fn announces(conn: &Connection, key: &[u8; 32]) -> Result<Option<bool>, rusqlite::Error> {
    conn.query_row(
        "SELECT announces FROM peers WHERE public_key = ?1",
        params![key],
        |row| row.get(0),
    )
    .optional()
}

/// Why the store refuses a write. The store keeps what a node accepted consistent with the rules
/// of [`crate::accept`], whatever writes it: it refuses what the code that decides what to accept
/// never asks of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// The peer isn't recorded.
    UnknownPeer,
    /// The announcement is older than the one stored.
    Older,
    /// The announcement is unsigned, but the peer has signed one.
    Unsigned,
    /// The prefix overlaps one pinned to another key.
    Pinned(Prefix),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownPeer => f.write_str("the peer is not recorded"),
            Self::Older => f.write_str("the announcement is older than the one stored"),
            Self::Unsigned => {
                f.write_str("the peer signs its announcements, so an unsigned one is refused")
            },
            Self::Pinned(prefix) => write!(f, "{prefix} overlaps a prefix pinned to another key"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<StoreError> for rusqlite::Error {
    fn from(error: StoreError) -> Self {
        rusqlite::Error::ToSqlConversionFailure(Box::new(error))
    }
}

/// The pins that overlap `prefix`, each as the key that it is pinned to, in bytes, and its prefix,
/// found through the index of the last addresses of the pins.
pub fn pinned_overlapping(
    conn: &Connection,
    prefix: &Prefix,
) -> Result<Vec<([u8; 32], Prefix)>, rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "SELECT public_key, address, prefix_len FROM prefix_pins
         WHERE last >= ?1 AND address <= ?2 AND length(address) = length(?1)",
    )?;
    let mut rows = stmt.query(params![
        ip_to_bytes(prefix.first()),
        ip_to_bytes(prefix.last())
    ])?;
    let mut overlapping = vec![];
    while let Some(row) = rows.next()? {
        let key: Vec<u8> = row.get(0)?;
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidColumnType(0, "public key".into(), Type::Blob))?;
        overlapping.push((key, prefix_from_row(row.get(1)?, row.get(2)?)?));
    }
    Ok(overlapping)
}

/// The public key of the peer to whose key `name` is pinned, if any.
pub fn name_holder(conn: &Connection, name: &str) -> Result<Option<String>, rusqlite::Error> {
    conn.query_row(
        "SELECT public_key FROM peers WHERE name = ?1",
        params![name],
        |row| row_key(row, 0),
    )
    .optional()
}

/// Deletes the peer with the public key `key` and everything that the node holds of it: its
/// announcement, what is pinned to its key, its endpoints and its delegations, and the rows of a
/// host's tables that refer to it with `ON DELETE CASCADE`. A coordinator deletes an invitation
/// so, or a peer that it removes; what other nodes pinned to the key stays pinned there.
pub fn forget_peer(conn: &Connection, key: &[u8; 32]) -> Result<(), rusqlite::Error> {
    conn.execute(
        "DELETE FROM announcements WHERE public_key = ?1",
        params![key],
    )?;
    conn.execute(
        "DELETE FROM prefix_pins WHERE public_key = ?1",
        params![key],
    )?;
    conn.execute("DELETE FROM peers WHERE public_key = ?1", params![key])?;
    Ok(())
}

/// The error of the store that `error` carries, if it carries one.
pub fn store_error(error: &rusqlite::Error) -> Option<&StoreError> {
    match error {
        rusqlite::Error::ToSqlConversionFailure(error) => error.downcast_ref(),
        _ => None,
    }
}

/// The peers that the node records, invitations included, each without its announcement, with
/// the name pinned to its key, its delegations, and the endpoint and candidates recorded apart
/// from its announcements, ordered by their hosts fallback addresses, those without one last, then
/// by public key. A stored name that isn't a valid [`Hostname`] is no name.
pub fn load_peers(conn: &Connection) -> Result<Vec<PeerContents>, rusqlite::Error> {
    load_peers_where(conn, None)
}

/// The peer with the public key `key`, as [`load_peers`] reads it, if it is recorded.
pub fn load_peer(
    conn: &Connection,
    key: &[u8; 32],
) -> Result<Option<PeerContents>, rusqlite::Error> {
    Ok(load_peers_where(conn, Some(key))?.pop())
}

fn load_peers_where(
    conn: &Connection,
    only: Option<&[u8; 32]>,
) -> Result<Vec<PeerContents>, rusqlite::Error> {
    let mut delegations: HashMap<String, Vec<Prefix>> = HashMap::new();
    let mut stmt = conn.prepare_cached(
        "SELECT public_key, address, prefix_len FROM delegations
         WHERE ?1 IS NULL OR public_key = ?1
         ORDER BY length(address), address, prefix_len",
    )?;
    let mut rows = stmt.query(params![only])?;
    while let Some(row) = rows.next()? {
        let delegation = prefix_from_row(row.get(1)?, row.get(2)?)?;
        delegations
            .entry(row_key(row, 0)?)
            .or_default()
            .push(delegation);
    }

    let mut endpoints = load_endpoints(conn, only)?;
    let mut peers = vec![];
    let mut stmt = conn.prepare_cached(
        "SELECT public_key, name, is_admin, is_disabled, is_redeemed,
                persistent_keepalive_interval, invite_expires
         FROM peers WHERE ?1 IS NULL OR public_key = ?1",
    )?;
    let mut rows = stmt.query(params![only])?;
    while let Some(row) = rows.next()? {
        let public_key = row_key(row, 0)?;
        let invite_expires = row
            .get::<_, Option<u64>>(6)?
            .map(|secs| UNIX_EPOCH + Duration::from_secs(secs));
        let endpoints = endpoints.remove(&public_key).unwrap_or_default();
        peers.push(PeerContents {
            name: row
                .get::<_, Option<String>>(1)?
                .and_then(|name| Hostname::try_from(name).ok()),
            delegations: delegations.remove(&public_key).unwrap_or_default(),
            public_key,
            endpoint: endpoints.endpoint,
            persistent_keepalive_interval: row.get(5)?,
            is_admin: row.get(2)?,
            is_disabled: row.get(3)?,
            is_redeemed: row.get(4)?,
            invite_expires,
            candidates: endpoints.candidates,
            announcement: None,
            allowed_ips: None,
            primary_ip: None,
            nameserver: None,
        });
    }
    peers.sort_by(|a, b| {
        let order = |peer: &PeerContents| {
            let fallback = peer.hosts_fallback();
            (fallback.is_none(), fallback)
        };
        order(a)
            .cmp(&order(b))
            .then_with(|| a.public_key.cmp(&b.public_key))
    });
    Ok(peers)
}

/// The CIDRs that the node records, ordered by prefix.
pub fn load_cidrs(conn: &Connection) -> Result<Vec<Cidr>, rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "SELECT address, prefix_len, name FROM cidrs ORDER BY length(address), address, prefix_len",
    )?;
    let mut rows = stmt.query([])?;
    let mut cidrs = vec![];
    while let Some(row) = rows.next()? {
        cidrs.push(Cidr {
            name: row.get(2)?,
            cidr: prefix_from_row(row.get(0)?, row.get(1)?)?,
        });
    }
    Ok(cidrs)
}
