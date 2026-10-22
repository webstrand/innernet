//! Access to the tables of [`SCHEMA`](crate::SCHEMA), through a [`Connection`], which a
//! [`rusqlite::Transaction`] dereferences to. Each function reads or writes what it names and
//! nothing else, and leaves transactions to the host: the host decides what applies together.
//!
//! Public keys are passed to the writers as the 32 bytes that the database holds, which
//! [`key_to_bytes`] makes of their base64 text, and the readers key their results by the canonical
//! base64 text, as a state's public keys are deserialized.

use innernet_shared::{Cidr, Endpoint, Hostname, PeerContents, Prefix};
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
    Endpoint = 0,
    Candidate = 1,
}

impl EndpointKind {
    /// Every kind, with its name in `endpoint_kinds`.
    pub const ALL: &'static [(Self, &'static str)] =
        &[(Self::Endpoint, "endpoint"), (Self::Candidate, "candidate")];

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
    /// A delegation of a peer.
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

/// The endpoints of a peer, as `endpoints` holds them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoredEndpoints {
    pub endpoint: Option<Endpoint>,
    pub candidates: Vec<Endpoint>,
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
        }
    }
    Ok(endpoints)
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

/// Pins `delegations` to the key `key`, each unless it is pinned to the key already. The pins of a
/// key accumulate: none is released when a delegation is withdrawn. The caller must have checked
/// that no prefix overlaps one pinned to another key.
pub fn pin_delegations(
    conn: &Connection,
    key: &[u8; 32],
    delegations: &[Prefix],
) -> Result<(), rusqlite::Error> {
    for delegation in delegations {
        conn.execute(
            "INSERT INTO prefix_pins (address, prefix_len, last, public_key, kind)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (address, prefix_len) DO NOTHING",
            params![
                ip_to_bytes(delegation.first()),
                delegation.prefix_len(),
                ip_to_bytes(delegation.last()),
                key,
                PinKind::Delegation as i64
            ],
        )?;
    }
    Ok(())
}

/// The public key of the peer that has the name `name`, if any.
pub fn name_holder(conn: &Connection, name: &str) -> Result<Option<[u8; 32]>, rusqlite::Error> {
    conn.query_row(
        "SELECT public_key FROM peers WHERE name = ?1",
        params![name],
        |row| row.get::<_, Vec<u8>>(0),
    )
    .optional()?
    .map(|key| {
        key.try_into()
            .map_err(|_| rusqlite::Error::InvalidColumnType(0, "public key".into(), Type::Blob))
    })
    .transpose()
}

/// Writes `peer`, keyed by `key`, the bytes of its public key: its record, in place of the stored
/// one, its delegations, pinned to its key as [`pin_delegations`] pins them, and its endpoint and
/// candidates. A peer without a name is stored with a NULL name.
pub fn write_peer(
    conn: &Connection,
    key: &[u8; 32],
    peer: &PeerContents,
) -> Result<(), rusqlite::Error> {
    let invite_expires = peer
        .invite_expires
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs());
    conn.execute(
        "INSERT INTO peers (public_key, name, is_admin, is_disabled, is_redeemed,
                            persistent_keepalive_interval, invite_expires)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT (public_key) DO UPDATE SET
           name = excluded.name,
           is_admin = excluded.is_admin,
           is_disabled = excluded.is_disabled,
           is_redeemed = excluded.is_redeemed,
           persistent_keepalive_interval = excluded.persistent_keepalive_interval,
           invite_expires = excluded.invite_expires",
        params![
            key,
            peer.name.as_deref(),
            peer.is_admin,
            peer.is_disabled,
            peer.is_redeemed,
            peer.persistent_keepalive_interval,
            invite_expires,
        ],
    )?;
    pin_delegations(conn, key, &peer.delegations)?;
    write_delegations(conn, key, &peer.delegations)?;
    write_endpoints(conn, key, EndpointKind::Endpoint, &peer.endpoint)?;
    write_endpoints(conn, key, EndpointKind::Candidate, &peer.candidates)
}

/// Replaces the delegations of the peer with the public key `key` with `delegations`.
pub fn write_delegations(
    conn: &Connection,
    key: &[u8; 32],
    delegations: &[Prefix],
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "DELETE FROM delegations WHERE public_key = ?1",
        params![key],
    )?;
    for delegation in delegations {
        conn.execute(
            "INSERT INTO delegations (address, prefix_len, last, public_key)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                ip_to_bytes(delegation.first()),
                delegation.prefix_len(),
                ip_to_bytes(delegation.last()),
                key
            ],
        )?;
    }
    Ok(())
}

/// Deletes the peer with the public key `key` and everything that the node holds of it: what is
/// pinned to its key, its endpoints, and the rows of a host's tables that refer to it with
/// `ON DELETE CASCADE`. A coordinator deletes an invitation so; what other nodes pinned to the key
/// stays pinned there.
pub fn forget_peer(conn: &Connection, key: &[u8; 32]) -> Result<(), rusqlite::Error> {
    conn.execute(
        "DELETE FROM prefix_pins WHERE public_key = ?1",
        params![key],
    )?;
    conn.execute("DELETE FROM peers WHERE public_key = ?1", params![key])?;
    Ok(())
}

/// The delegations of every peer, or only of the peer with the public key `only`, by public key,
/// each sorted.
pub fn load_delegations(
    conn: &Connection,
    only: Option<&[u8; 32]>,
) -> Result<HashMap<String, Vec<Prefix>>, rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "SELECT public_key, address, prefix_len FROM delegations
         WHERE ?1 IS NULL OR public_key = ?1
         ORDER BY length(address), address, prefix_len",
    )?;
    let mut rows = stmt.query(params![only])?;
    let mut delegations: HashMap<String, Vec<Prefix>> = HashMap::new();
    while let Some(row) = rows.next()? {
        let delegation = prefix_from_row(row.get(1)?, row.get(2)?)?;
        delegations
            .entry(row_key(row, 0)?)
            .or_default()
            .push(delegation);
    }
    Ok(delegations)
}

/// The peers that the node records, invitations included, each with its delegations, ordered by
/// their hosts fallback addresses, those without one last, then by public key. Server IDs aren't
/// stored, so every peer's CIDR ID is 0: a host that needs IDs assigns them. A stored name that
/// isn't a valid [`Hostname`] reads as no name.
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
    let mut delegations = load_delegations(conn, only)?;
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
