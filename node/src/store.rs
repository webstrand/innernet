//! Access to the tables of [`SCHEMA`](crate::SCHEMA), through a [`Connection`], which a
//! [`rusqlite::Transaction`] dereferences to. Each function reads or writes what it names and
//! nothing else, and leaves transactions to the host: the host decides what applies together.
//!
//! Public keys are passed to the writers as the 32 bytes that the database holds, which
//! [`key_to_bytes`] makes of their base64 text, and the readers key their results by the canonical
//! base64 text, as a state's public keys are deserialized.

use innernet_shared::{Endpoint, Hostname, PeerContents, Prefix};
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
    /// The address of a peer.
    Address = 0,
}

impl PinKind {
    /// Every kind, with its name in `pin_kinds`.
    pub const ALL: &'static [(Self, &'static str)] = &[(Self::Address, "address")];
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

/// The address pinned to the key `key`, if any.
pub fn pinned_address(
    conn: &Connection,
    key: &[u8; 32],
) -> Result<Option<IpAddr>, rusqlite::Error> {
    conn.query_row(
        "SELECT address FROM prefix_pins WHERE public_key = ?1 AND kind = ?2",
        params![key, PinKind::Address as i64],
        |row| row_ip(row, 0),
    )
    .optional()
    .map(Option::flatten)
}

/// The keys to which a prefix that holds `ip` is pinned, found through the index of the last
/// addresses of the pins.
pub fn holders_of(conn: &Connection, ip: IpAddr) -> Result<Vec<[u8; 32]>, rusqlite::Error> {
    let address = ip_to_bytes(ip);
    let mut stmt = conn.prepare_cached(
        "SELECT public_key FROM prefix_pins
         WHERE last >= ?1 AND address <= ?1 AND length(address) = length(?1)",
    )?;
    let mut rows = stmt.query(params![address])?;
    let mut holders = vec![];
    while let Some(row) = rows.next()? {
        let key: Vec<u8> = row.get(0)?;
        holders.push(
            key.try_into().map_err(|_| {
                rusqlite::Error::InvalidColumnType(0, "public key".into(), Type::Blob)
            })?,
        );
    }
    Ok(holders)
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
/// one, its endpoint and candidates, and its address, pinned to its key if no address is. A name
/// that isn't a valid [`Hostname`], such as the placeholder of an introduced peer, is stored as
/// no name.
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
            Hostname::is_valid(&peer.name).then_some(&*peer.name),
            peer.is_admin,
            peer.is_disabled,
            peer.is_redeemed,
            peer.persistent_keepalive_interval,
            invite_expires,
        ],
    )?;
    if pinned_address(conn, key)?.is_none() {
        let address = ip_to_bytes(peer.ip);
        conn.execute(
            "INSERT INTO prefix_pins (address, prefix_len, last, public_key, kind)
             VALUES (?1, ?2, ?1, ?3, ?4)",
            params![address, address.len() * 8, key, PinKind::Address as i64],
        )?;
    }
    write_endpoints(conn, key, EndpointKind::Endpoint, &peer.endpoint)?;
    write_endpoints(conn, key, EndpointKind::Candidate, &peer.candidates)
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

/// The peers that the node records, invitations included, each at the address pinned to its key,
/// ordered by address. Server IDs aren't stored, so every peer's CIDR ID is 0: a host that needs
/// IDs assigns them. A peer without a valid name, such as an introduced peer, is named by the
/// placeholder of its public key, which no other name equals.
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
    let mut endpoints = load_endpoints(conn, only)?;
    let mut peers = vec![];
    let mut stmt = conn.prepare_cached(
        "SELECT p.public_key, p.name, p.is_admin, p.is_disabled, p.is_redeemed,
                p.persistent_keepalive_interval, p.invite_expires, a.address
         FROM peers p
         JOIN prefix_pins a ON a.public_key = p.public_key AND a.kind = ?2
         WHERE ?1 IS NULL OR p.public_key = ?1
         ORDER BY length(a.address), a.address",
    )?;
    let mut rows = stmt.query(params![only, PinKind::Address as i64])?;
    while let Some(row) = rows.next()? {
        let public_key = row_key(row, 0)?;
        let invite_expires = row
            .get::<_, Option<u64>>(6)?
            .map(|secs| UNIX_EPOCH + Duration::from_secs(secs));
        let name: Option<String> = row.get(1)?;
        let ip = row_ip(row, 7)?
            .ok_or_else(|| rusqlite::Error::InvalidColumnType(7, "address".into(), Type::Null))?;
        let endpoints = endpoints.remove(&public_key).unwrap_or_default();
        peers.push(PeerContents {
            name: name
                .filter(|name| Hostname::is_valid(name))
                .map(Hostname::unchecked)
                .unwrap_or_else(|| Hostname::placeholder(&public_key)),
            ip,
            cidr_id: 0,
            public_key,
            endpoint: endpoints.endpoint,
            persistent_keepalive_interval: row.get(5)?,
            is_admin: row.get(2)?,
            is_disabled: row.get(3)?,
            is_redeemed: row.get(4)?,
            invite_expires,
            candidates: endpoints.candidates,
        });
    }
    Ok(peers)
}

/// A CIDR as the node records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredCidr {
    pub prefix: Prefix,
    pub name: String,
    /// Whether every peer sees the peers of the CIDR.
    pub infra: bool,
}

/// The CIDRs that the node records, ordered by prefix.
pub fn load_cidrs(conn: &Connection) -> Result<Vec<StoredCidr>, rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "SELECT address, prefix_len, name, infra FROM cidrs
         ORDER BY length(address), address, prefix_len",
    )?;
    let mut rows = stmt.query([])?;
    let mut cidrs = vec![];
    while let Some(row) = rows.next()? {
        cidrs.push(StoredCidr {
            prefix: prefix_from_row(row.get(0)?, row.get(1)?)?,
            name: row.get(2)?,
            infra: row.get(3)?,
        });
    }
    Ok(cidrs)
}

/// Replaces the CIDRs that the node records with `cidrs`. Of two CIDRs with the same prefix or
/// the same name, the first is kept.
pub fn replace_cidrs(conn: &Connection, cidrs: &[StoredCidr]) -> Result<(), rusqlite::Error> {
    conn.execute("DELETE FROM cidrs", [])?;
    for cidr in cidrs {
        conn.execute(
            "INSERT INTO cidrs (address, prefix_len, name, infra) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT DO NOTHING",
            params![
                ip_to_bytes(cidr.prefix.first()),
                cidr.prefix.prefix_len(),
                cidr.name,
                cidr.infra
            ],
        )?;
    }
    Ok(())
}

/// Records `cidr`. The database refuses a prefix or a name that another CIDR has.
pub fn insert_cidr(conn: &Connection, cidr: &StoredCidr) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO cidrs (address, prefix_len, name, infra) VALUES (?1, ?2, ?3, ?4)",
        params![
            ip_to_bytes(cidr.prefix.first()),
            cidr.prefix.prefix_len(),
            cidr.name,
            cidr.infra
        ],
    )?;
    Ok(())
}
