use crate::ServerError;
use anyhow::{anyhow, bail, ensure, Context as _};
use innernet_node::{
    db as node_db,
    store::{write_endpoints, EndpointKind},
    Store,
};
use innernet_shared::{
    parent_cidr, smallest_cidr_holding, Endpoint, Error, IoErrorContext, Prefix,
};
use ipnet::IpNet;
use rusqlite::{params, Connection, MAIN_DB};
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{self, Write},
    net::IpAddr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};
use wireguard_control::Key;

pub mod association;
pub mod cidr;
pub mod peer;

pub use association::DatabaseAssociation;
pub use cidr::DatabaseCidr;
pub use peer::DatabasePeer;

const INVITE_EXPIRATION_VERSION: usize = 1;
const ENDPOINT_CANDIDATES_VERSION: usize = 2;

/// The coordinator's annex: what only the coordinator holds, beside the node's tables.
pub static ANNEX_SQL: &str = concat!(
    "INSERT INTO meta VALUES ('coordinator_version', 1);\n",
    include_str!("annex.sql")
);

/// Opens the coordinator's store at `path`, which must exist, for the network `network` of the
/// config, configured as every node's is, and migrated to the node's schema with the
/// coordinator's annex. `server_key` is the public key of the server's own peer, which a database
/// of earlier versions marks by no flag.
pub fn open(path: &Path, server_key: &Key, network: IpNet) -> Result<Store, Error> {
    let conn = Connection::open(path)?;
    node_db::configure(&conn)?;
    let mut store = Store::new(conn, network);
    auto_migrate(&mut store, server_key)?;
    Ok(store)
}

/// A new store in memory, of the node's schema with the coordinator's annex.
#[cfg(test)]
pub fn in_memory(network: IpNet) -> Result<Store, Error> {
    let store = Store::in_memory(network)?;
    store.execute_batch(ANNEX_SQL)?;
    Ok(store)
}

/// The hook that creates the coordinator's annex in a new database.
pub fn create_annex() -> node_db::CreateHook {
    Arc::new(|tx| Ok(tx.execute_batch(ANNEX_SQL)?))
}

/// Migrates the database to the node's schema with the coordinator's annex. A database of a
/// server of earlier versions, whose peers table names peers by an `id`, is first rebuilt, as
/// [`back_up_and_migrate`] does, in one exclusive transaction.
///
/// `server_key` is the public key of the server's own peer, whose CIDR the rebuild checks.
pub fn auto_migrate(store: &mut Store, server_key: &Key) -> Result<(), Error> {
    let old_version: usize = store.pragma_query_value(None, "user_version", |r| r.get(0))?;
    log::debug!("user_version: {}", old_version);

    if node_db::has_column(store, "peers", "id")? {
        store.execute_batch("BEGIN EXCLUSIVE")?;
        if let Err(e) = back_up_and_migrate(store, old_version, server_key) {
            store.execute_batch("ROLLBACK")?;
            return Err(e);
        }
        store.execute_batch("COMMIT")?;
        log::info!("migrated the database from version {old_version} to the node's schema");
    }
    store.migrate(Some(create_annex()))
}

/// Runs the migrations from `old_version` up to the rebuild of the peers table, in the transaction
/// of the caller, which holds an exclusive lock on the whole database. Does nothing if another
/// process has rebuilt the table since the caller checked.
///
/// The rebuild keys the peers table by public key, with the IP of each peer as its delegation in a
/// table of delegations, and the endpoint and the candidates of each peer in a table of their own.
/// It keys the CIDRs by their prefixes and the associations by the prefixes of their CIDRs. Server
/// binaries of earlier versions can't open the rebuilt database, so the database is first copied,
/// as it is before any migration, to a backup next to it, which such a binary can open. The
/// migration fails if the backup does, and a peer that the new schema can't hold, such as one with
/// an invalid public key, fails it too, as does a database whose tree of CIDRs, or the CIDRs of
/// whose peers, the prefixes would not give as they are (see [`rebuild`]); the caller then rolls
/// the transaction back.
fn back_up_and_migrate(store: &Store, old_version: usize, server_key: &Key) -> Result<(), Error> {
    if !has_column(store, "peers", "id")? {
        return Ok(());
    }
    if let Some(backup) = back_up(store)? {
        log::info!(
            "copied the database to {} before rebuilding its peers table; earlier versions of \
             innernet-server can't open the rebuilt database, but can open the copy.",
            backup.display()
        );
    }

    if old_version < INVITE_EXPIRATION_VERSION && !has_column(store, "peers", "invite_expires")? {
        store.execute(
            "ALTER TABLE peers ADD COLUMN invite_expires INTEGER",
            params![],
        )?;
    }

    if old_version < ENDPOINT_CANDIDATES_VERSION && !has_column(store, "peers", "candidates")? {
        store.execute("ALTER TABLE peers ADD COLUMN candidates TEXT", params![])?;
    }

    rebuild(store, server_key).context("failed to rebuild the database")
}

/// A peer as the peers table before the rebuild holds it.
struct UnkeyedPeer {
    id: i64,
    name: String,
    ip: String,
    public_key: String,
    endpoint: Option<String>,
    cidr_id: i64,
    is_admin: bool,
    is_disabled: bool,
    is_redeemed: bool,
    invite_expires: Option<i64>,
    candidates: Option<String>,
}

/// A CIDR as the cidrs table before the rebuild holds it.
struct UnkeyedCidr {
    id: i64,
    name: String,
    ip: String,
    prefix: u8,
    parent: Option<i64>,
}

/// The ID of the CIDR that every peer of a database before the rebuild sees, which holds the
/// server's own peer.
const ORIGIN_INFRA_CIDR_ID: i64 = 2;

/// Rebuilds the database in the node's schema with the coordinator's annex, in the transaction of
/// the caller.
///
/// The parent of a CIDR and the CIDR of a peer are not stored, but follow from prefixes: the
/// parent of a CIDR is the smallest other CIDR that holds it, and the CIDR of a peer is that of its
/// delegations. The CIDR with the ID 2, which every peer of the database sees, is marked infra.
/// The server's own peer is the one with the public key `server_key`. The
/// rebuild keeps what each peer sees, so it fails if the database stores anything else than what
/// the prefixes give: a CIDR under another parent, a peer in another CIDR, or the server's own peer
/// outside the CIDR with the ID 2. A CIDR whose address has host bits set
/// becomes the prefix of its network, as the server read it. An association of a CIDR with
/// itself, which changes nothing, and a second association of the same two CIDRs are dropped with
/// a warning.
fn rebuild(store: &Store, server_key: &Key) -> Result<(), Error> {
    let cidrs = store
        .prepare("SELECT id, name, ip, prefix, parent FROM cidrs ORDER BY id")?
        .query_map([], |row| {
            Ok(UnkeyedCidr {
                id: row.get(0)?,
                name: row.get(1)?,
                ip: row.get(2)?,
                prefix: row.get(3)?,
                parent: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let associations = store
        .prepare("SELECT id, cidr_id_1, cidr_id_2 FROM associations ORDER BY id")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<Vec<(i64, i64, i64)>, _>>()?;
    let peers = store
        .prepare(
            "SELECT id, name, ip, public_key, endpoint, cidr_id, is_admin, is_disabled,
                    is_redeemed, invite_expires, candidates
             FROM peers ORDER BY id",
        )?
        .query_map([], |row| {
            Ok(UnkeyedPeer {
                id: row.get(0)?,
                name: row.get(1)?,
                ip: row.get(2)?,
                public_key: row.get(3)?,
                endpoint: row.get(4)?,
                cidr_id: row.get(5)?,
                is_admin: row.get(6)?,
                is_disabled: row.get(7)?,
                is_redeemed: row.get(8)?,
                invite_expires: row.get(9)?,
                candidates: row.get(10)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    // Renaming a table makes the references to it follow it.
    store.execute_batch(
        "ALTER TABLE peers RENAME TO peers_unkeyed;
         ALTER TABLE associations RENAME TO associations_unkeyed;
         ALTER TABLE cidrs RENAME TO cidrs_unkeyed;",
    )?;
    store.execute_batch(innernet_node::SCHEMA)?;
    store.execute_batch(ANNEX_SQL)?;
    store.pragma_update(None, "user_version", node_db::SCHEMA_VERSION)?;

    let mut prefixes = HashMap::new();
    for cidr in &cidrs {
        let prefix = copy_cidr(store, cidr).with_context(|| {
            format!(
                "failed to copy the CIDR with ID {} ({})",
                cidr.id, cidr.name
            )
        })?;
        prefixes.insert(cidr.id, prefix);
    }
    let all: Vec<Prefix> = prefixes.values().copied().collect();
    for cidr in &cidrs {
        let stored = cidr
            .parent
            .map(|parent| {
                prefixes.get(&parent).copied().ok_or_else(|| {
                    anyhow!(
                        "the CIDR with ID {} has the unknown parent with ID {parent}",
                        cidr.id
                    )
                })
            })
            .transpose()?;
        let given = parent_cidr(&prefixes[&cidr.id], &all);
        ensure!(
            stored == given,
            "the CIDR with ID {} ({}) has the parent {}, but the smallest CIDR that holds it is {}",
            cidr.id,
            cidr.name,
            describe_cidr(stored),
            describe_cidr(given),
        );
    }

    for peer in &peers {
        copy_peer(store, peer, &prefixes).with_context(|| {
            format!(
                "failed to copy the peer with ID {} ({}, {})",
                peer.id, peer.name, peer.public_key
            )
        })?;
    }
    let server_peer = peers
        .iter()
        .find(|peer| Key::from_base64(&peer.public_key).is_ok_and(|key| &key == server_key))
        .ok_or_else(|| {
            anyhow!(
                "the server's own peer, with key {}, is missing",
                server_key.to_base64()
            )
        })?;
    ensure!(
        server_peer.cidr_id == ORIGIN_INFRA_CIDR_ID
            || !prefixes.contains_key(&ORIGIN_INFRA_CIDR_ID),
        "the server's own peer lies in the CIDR with ID {}, not in the CIDR with ID \
         {ORIGIN_INFRA_CIDR_ID}, which every peer sees; every peer is to see the CIDR of the \
         server's own peer",
        server_peer.cidr_id
    );
    if let Some(infra) = prefixes.get(&ORIGIN_INFRA_CIDR_ID) {
        store.execute(
            "UPDATE cidrs SET infra = 1 WHERE address = ?1 AND prefix_len = ?2",
            params![ip_to_bytes(infra.first()), infra.prefix_len()],
        )?;
    }

    let mut copied: Vec<(Prefix, Prefix)> = vec![];
    for (id, cidr_id_1, cidr_id_2) in associations {
        let prefix = |cidr_id| {
            prefixes.get(&cidr_id).copied().ok_or_else(|| {
                anyhow!("the association with ID {id} names the unknown CIDR with ID {cidr_id}")
            })
        };
        let (a, b) = (prefix(cidr_id_1)?, prefix(cidr_id_2)?);
        let pair = (a.min(b), a.max(b));
        if a == b || copied.contains(&pair) {
            log::warn!(
                "dropping the association with ID {id} of the CIDRs {a} and {b}, which changes \
                 nothing."
            );
            continue;
        }
        store.execute(
            "INSERT INTO associations (address_1, prefix_len_1, address_2, prefix_len_2)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                ip_to_bytes(pair.0.first()),
                pair.0.prefix_len(),
                ip_to_bytes(pair.1.first()),
                pair.1.prefix_len(),
            ],
        )?;
        copied.push(pair);
    }
    // A CIDR whose parent RESTRICTs its deletion can't be dropped with it, so the parents go
    // first.
    store.execute_batch(
        "DROP TABLE associations_unkeyed;
         DROP TABLE peers_unkeyed;
         UPDATE cidrs_unkeyed SET parent = NULL;
         DROP TABLE cidrs_unkeyed;",
    )?;

    // The server's node core takes each peer as the unsigned announcement that the server makes
    // of it, as clients that predate announcements take it, so that what each claims is pinned to
    // its key from the start.
    DatabasePeer::admit_synthesized(store)?;

    log::info!(
        "rebuilt the database keyed by public keys and prefixes, with the {} peers, {} CIDRs and \
         {} associations it held.",
        peers.len(),
        cidrs.len(),
        copied.len()
    );
    Ok(())
}

/// A CIDR, or the lack of one, for an error.
fn describe_cidr(cidr: Option<Prefix>) -> String {
    cidr.map_or("none".into(), |cidr| cidr.to_string())
}

/// Copies `cidr` into the rebuilt cidrs table, keyed by its prefix, and returns its prefix.
fn copy_cidr(store: &Store, cidr: &UnkeyedCidr) -> Result<Prefix, Error> {
    let ip: IpAddr = cidr.ip.parse().context("the IP is not valid")?;
    let prefix = Prefix::new(ipnet::IpNet::new(ip, cidr.prefix)?.trunc())?;
    store.execute(
        "INSERT INTO cidrs (address, prefix_len, name) VALUES (?1, ?2, ?3)",
        params![ip_to_bytes(prefix.first()), prefix.prefix_len(), cidr.name],
    )?;
    Ok(prefix)
}

/// Copies `peer` into the rebuilt peers table, with its IP as its only delegation, a host prefix,
/// which must lie in the peer's CIDR, of the prefix that
/// `prefixes` gives its ID: its CIDR is that of its delegation from then on. An endpoint or
/// candidates that the server could not read are dropped with a warning, since the server ignored
/// them anyway.
fn copy_peer(
    store: &Store,
    peer: &UnkeyedPeer,
    prefixes: &HashMap<i64, Prefix>,
) -> Result<(), Error> {
    let key = Key::from_base64(&peer.public_key)
        .map_err(|_| anyhow!("the public key is not valid base64"))?
        .0;
    let ip: IpAddr = peer.ip.parse().context("the IP is not valid")?;
    let delegation = Prefix::host(ip);
    let all: Vec<Prefix> = prefixes.values().copied().collect();
    let stored = prefixes.get(&peer.cidr_id).copied();
    let given = smallest_cidr_holding(&delegation, &all);
    ensure!(
        stored == given,
        "the peer lies in the CIDR {}, but the smallest CIDR that holds its IP {ip} is {}",
        describe_cidr(stored),
        describe_cidr(given),
    );
    // A redeemed peer that predates TLS keeps using plain HTTP until it first connects over TLS. An
    // invitation not yet redeemed is latched, as one that the server issues now is.
    store.execute(
        "INSERT INTO peers (public_key, is_admin, is_disabled, is_redeemed, invite_expires, tls)
         VALUES (?1, ?2, ?3, ?4, ?5, NOT ?4)",
        params![
            key,
            peer.is_admin,
            peer.is_disabled,
            peer.is_redeemed,
            peer.invite_expires,
        ],
    )?;
    store.execute(
        "INSERT INTO offered_names (public_key, name) VALUES (?1, ?2)",
        params![key, peer.name],
    )?;
    peer::insert_delegation(store, &key, &delegation)?;

    let endpoint = peer.endpoint.as_deref().and_then(|endpoint| {
        endpoint
            .parse::<Endpoint>()
            .inspect_err(|e| {
                log::warn!(
                    "dropping the invalid endpoint {endpoint:?} of peer {}: {e}",
                    peer.public_key
                )
            })
            .ok()
    });
    let candidates: Vec<Endpoint> = match peer.candidates.as_deref() {
        None => vec![],
        Some(candidates) => serde_json::from_str(candidates).unwrap_or_else(|e| {
            log::warn!(
                "dropping the invalid candidates {candidates:?} of peer {}: {e}",
                peer.public_key
            );
            vec![]
        }),
    };
    write_endpoints(store, &key, EndpointKind::Endpoint, &endpoint)?;
    write_endpoints(store, &key, EndpointKind::Candidate, &candidates)?;
    Ok(())
}

/// Copies the database of `store`, as the transaction of the caller reads it, to a new file next to
/// it, named after the database file with the suffix `.v2.0.0`, or `.v2.0.0.N` with the first `N`
/// for which no file exists, so that an earlier backup is never overwritten. Returns the path of
/// the copy, or `None` if the database has no file, as one in memory doesn't.
///
/// The database is read through `store`, with `sqlite3_serialize`, since SQLite's backup API can't
/// read from a connection that holds a write transaction.
fn back_up(store: &Store) -> Result<Option<PathBuf>, Error> {
    let Some(path) = store.path().filter(|path| !path.is_empty()) else {
        return Ok(None);
    };
    let image = store
        .serialize(MAIN_DB)
        .context("failed to read the database to copy it, so it is left as it is")?;
    for n in 0.. {
        let backup = match n {
            0 => PathBuf::from(format!("{path}.v2.0.0")),
            n => PathBuf::from(format!("{path}.v2.0.0.{n}")),
        };
        // The name is taken by creating the file, with the mode of a file that only the server
        // reads.
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&backup)
        {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).with_path(&backup)?,
        };
        if let Err(e) = file.write_all(&image).and_then(|()| file.sync_all()) {
            fs::remove_file(&backup).ok();
            bail!(
                "failed to copy the database to {}, so it is left as it is: {e}",
                backup.display()
            );
        }
        return Ok(Some(backup));
    }
    unreachable!("every name of a backup is taken")
}

/// Runs `f` in a savepoint of `store`, so that the writes it makes apply together or not at all,
/// whether or not a transaction is open.
pub(crate) fn atomically<T>(
    store: &Store,
    f: impl FnOnce() -> Result<T, ServerError>,
) -> Result<T, ServerError> {
    store.execute_batch("SAVEPOINT atomically")?;
    match f() {
        Ok(value) => {
            store.execute_batch("RELEASE atomically")?;
            Ok(value)
        },
        Err(e) => {
            if let Err(rollback) = store.execute_batch("ROLLBACK TO atomically; RELEASE atomically")
            {
                log::error!("failed to roll back a failed write: {rollback}");
            }
            Err(e)
        },
    }
}

pub(crate) use innernet_node::store::{ip_to_bytes, prefix_from_row};

/// The 32 bytes of the WireGuard public key `public_key` in base64.
pub(crate) fn key_to_bytes(public_key: &str) -> Result<[u8; 32], ServerError> {
    innernet_node::store::key_to_bytes(public_key).map_err(|_| ServerError::InvalidQuery)
}

use node_db::has_column;

#[cfg(test)]
mod tests {
    use super::*;
    use innernet_shared::PeerContents;
    use std::{os::unix::fs::PermissionsExt, path::Path};
    use wireguard_control::KeyPair;

    /// The peers table of innernet v2.0.0, which version 2 of the schema left as it is.
    const UPSTREAM_PEERS_SQL: &str = "CREATE TABLE peers (
      id              INTEGER PRIMARY KEY,
      name            TEXT NOT NULL UNIQUE,
      ip              TEXT NOT NULL UNIQUE,
      public_key      TEXT NOT NULL UNIQUE,
      endpoint        TEXT,
      cidr_id         INTEGER NOT NULL,
      is_admin        INTEGER DEFAULT 0 NOT NULL,
      is_disabled     INTEGER DEFAULT 0 NOT NULL,
      is_redeemed     INTEGER DEFAULT 0 NOT NULL,
      invite_expires  INTEGER,
      candidates      TEXT,
      FOREIGN KEY (cidr_id)
         REFERENCES cidrs (id)
            ON UPDATE RESTRICT
            ON DELETE RESTRICT
    )";

    /// The network of the servers of the fixture.
    fn network() -> IpNet {
        "10.0.0.0/8".parse().unwrap()
    }

    /// Opens the database at `path` as the server does, but for the migration.
    fn open(path: &Path) -> Store {
        let conn = Connection::open(path).unwrap();
        node_db::configure(&conn).unwrap();
        Store::new(conn, network())
    }

    /// A database of the schema of innernet v2.0.0, at `path`, with CIDRs and peers as
    /// [`insert_peers`] inserts them.
    fn create_upstream(path: &Path) -> Vec<(i64, PeerContents)> {
        let store = open(path);
        store.execute(cidr::ORIGIN_TABLE_SQL, []).unwrap();
        store.execute(association::ORIGIN_TABLE_SQL, []).unwrap();
        store.execute(UPSTREAM_PEERS_SQL, []).unwrap();
        store
            .pragma_update(None, "user_version", ENDPOINT_CANDIDATES_VERSION)
            .unwrap();
        insert_peers(&store)
    }

    /// Inserts CIDRs, associations and peers as a server of innernet v2.0.0 holds them:
    /// a CIDR whose address has host bits set, an association of a CIDR with itself and two of
    /// the same CIDRs, peers with IDs that a deleted peer left a gap in, IPv4 and IPv6 addresses,
    /// endpoints and candidates of every shape, an invalid endpoint and invalid candidates.
    /// Returns each peer with its ID; the first is the server's own.
    fn insert_peers(store: &Store) -> Vec<(i64, PeerContents)> {
        store
            .execute_batch(
                "INSERT INTO cidrs (id, name, ip, prefix, parent) VALUES
               (1, 'root', '10.0.0.0', 8, NULL),
               (2, 'innernet-server', '10.0.0.1', 32, 1),
               (3, 'users', '10.0.1.0', 24, 1),
               (4, 'v6', 'fd00::', 64, NULL),
               (6, 'loose', '10.0.2.5', 24, 1);
             INSERT INTO associations (id, cidr_id_1, cidr_id_2) VALUES
               (1, 4, 3), (2, 3, 4), (3, 6, 6), (5, 3, 6);",
            )
            .unwrap();
        let peer =
            |name: &str, ip: &str, endpoint: Option<&str>, candidates: &[&str]| PeerContents {
                name: Some(name.parse().unwrap()),
                delegations: vec![Prefix::host(ip.parse().unwrap())],
                public_key: KeyPair::generate().public.to_base64(),
                endpoint: endpoint.map(|endpoint| endpoint.parse().unwrap()),
                persistent_keepalive_interval: Some(
                    innernet_shared::PERSISTENT_KEEPALIVE_INTERVAL_SECS,
                ),
                is_admin: false,
                is_disabled: false,
                is_redeemed: true,
                invite_expires: None,
                candidates: candidates.iter().map(|c| c.parse().unwrap()).collect(),
                announcement: None,
                allowed_ips: None,
                primary_ip: None,
                nameserver: None,
            };
        let mut peers = vec![
            (
                1,
                PeerContents {
                    is_admin: true,
                    ..peer(
                        "innernet-server",
                        "10.0.0.1",
                        Some("203.0.113.1:51820"),
                        &[],
                    )
                },
            ),
            (
                2,
                peer(
                    "peer-v4",
                    "10.0.1.2",
                    Some("vpn.example.com:51820"),
                    &[
                        "192.168.1.2:51820",
                        "[2001:db8::1]:4000",
                        "peer.example.com:1",
                    ],
                ),
            ),
            (
                4,
                PeerContents {
                    is_disabled: true,
                    ..peer("peer-v6", "fd00::4", None, &[])
                },
            ),
            (
                7,
                PeerContents {
                    is_redeemed: false,
                    invite_expires: Some(
                        std::time::UNIX_EPOCH + std::time::Duration::from_secs(4_000_000_000),
                    ),
                    ..peer("invitee", "10.0.1.7", Some("0.0.0.0:51820"), &[])
                },
            ),
        ];
        for (id, peer) in &peers {
            store
                .execute(
                    "INSERT INTO peers (id, name, ip, public_key, endpoint, cidr_id, is_admin,
                                    is_disabled, is_redeemed, invite_expires, candidates)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                    params![
                        id,
                        peer.name.as_deref(),
                        origin_ip(peer),
                        peer.public_key,
                        peer.endpoint.as_ref().map(|e| e.to_string()),
                        origin_cidr_id(peer),
                        peer.is_admin,
                        peer.is_disabled,
                        peer.is_redeemed,
                        peer.invite_expires
                            .map(|t| t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()),
                        serde_json::to_string(&peer.candidates).unwrap(),
                    ],
                )
                .unwrap();
        }
        // An endpoint and candidates that the server could not read are dropped.
        let mut garbled = peer("garbled", "10.0.1.8", None, &[]);
        store
            .execute(
                "INSERT INTO peers (id, name, ip, public_key, endpoint, cidr_id, candidates)
             VALUES (8, ?1, ?2, ?3, 'not an endpoint', 3, 'not json')",
                params![
                    garbled.name.as_deref(),
                    origin_ip(&garbled),
                    garbled.public_key
                ],
            )
            .unwrap();
        garbled.is_redeemed = false;
        peers.push((8, garbled));
        peers
    }

    /// The public key of the server's own peer among `peers`, as [`insert_peers`] inserts them.
    fn server_key(peers: &[(i64, PeerContents)]) -> Key {
        Key::from_base64(&peers[0].1.public_key).unwrap()
    }

    /// The ID of the CIDR of `peer` among those that [`insert_peers`] inserts: the smallest that
    /// holds its IP.
    fn origin_cidr_id(peer: &PeerContents) -> i64 {
        match origin_ip(peer).as_str() {
            "10.0.0.1" => 2,
            ip if ip.starts_with("10.0.1.") => 3,
            ip if ip.starts_with("fd00::") => 4,
            ip => panic!("no CIDR of the fixture holds {ip}"),
        }
    }

    /// The IP of `peer` as the peers table of innernet v2.0.0 holds it: its only address.
    fn origin_ip(peer: &PeerContents) -> String {
        peer.hosts_fallback().unwrap().to_string()
    }

    /// The user version, the schema and the rows of every table of the database of `store`.
    fn dump(conn: &Connection) -> Result<Vec<String>, Error> {
        let user_version: usize = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let mut dump = vec![format!("user_version {user_version}")];
        let schema = conn
            .prepare("SELECT type, name, sql FROM sqlite_schema ORDER BY name")?
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (kind, name, sql) in schema {
            dump.push(format!("{kind} {name}: {sql:?}"));
            if kind != "table" {
                continue;
            }
            let mut statement = conn.prepare(&format!("SELECT * FROM \"{name}\""))?;
            let columns = statement.column_count();
            let mut rows = statement
                .query_map([], |r| {
                    let row = (0..columns)
                        .map(|i| r.get::<_, rusqlite::types::Value>(i))
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(format!("{name}: {row:?}"))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            rows.sort();
            dump.extend(rows);
        }
        Ok(dump)
    }

    #[test]
    fn test_migrate_to_keyed_peers() -> Result<(), Error> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("wg0.db");
        let peers = create_upstream(&path);
        let server_key = server_key(&peers);
        let mut store = open(&path);
        let before_migration = dump(&store)?;
        auto_migrate(&mut store, &server_key)?;
        assert_ne!(dump(&store)?, before_migration);

        let user_version: i64 = store.pragma_query_value(None, "user_version", |r| r.get(0))?;
        assert_eq!(user_version, node_db::SCHEMA_VERSION);
        assert_eq!(
            DatabasePeer::get_from_public_key(&store, &server_key)?.public_key,
            server_key.to_base64()
        );
        assert_eq!(DatabaseCidr::infra(&store)?, ["10.0.0.1/32".parse()?]);

        // Every peer keeps its data, and its IP as its only delegation. The plain-HTTP view
        // numbers the CIDRs in the order of their prefixes, which renumbers those of v2.0.0: loose,
        // 10.0.2.0/24, comes before v6, fd00::/64.
        let migrated = DatabasePeer::list(&store)?;
        assert_eq!(migrated.len(), peers.len());
        let cidrs = DatabaseCidr::list(&store)?;
        let ids = DatabasePeer::plain_http_ids(&store)?;
        let cidr_id = |origin| match origin {
            6 => 4,
            4 => 5,
            id => id,
        };
        for (id, expected) in &peers {
            let ip = origin_ip(expected).parse()?;
            let peer = DatabasePeer::get_by_address(&store, ip)?;
            assert_eq!(&peer.inner, expected, "peer {id}");
            assert_eq!(peer.delegations, [Prefix::host(ip)], "peer {id}");
            // The node takes no claim outside the network, so a peer outside it takes no effect.
            if !network().contains(&ip) {
                assert_eq!(peer.announced, None, "peer {id}");
                continue;
            }
            // The peer's CIDR, which its delegation gives it, is the one it was in.
            let legacy = peer.legacy(ids[&expected.public_key], &cidrs).unwrap();
            assert_eq!(legacy.ip, ip);
            assert_eq!(
                legacy.cidr_id,
                cidr_id(origin_cidr_id(expected)),
                "peer {id}"
            );
            let key = Key::from_base64(&expected.public_key)?;
            assert_eq!(
                DatabasePeer::get_from_public_key(&store, &key)?.inner,
                peer.inner
            );
            // Redeemed peers keep using plain HTTP until they connect over TLS, and invitations
            // are latched.
            assert_eq!(peer.requires_tls, !expected.is_redeemed, "peer {id}");
        }

        // A new peer is created in a migrated CIDR.
        DatabasePeer::create(
            &store,
            PeerContents {
                name: Some("new-peer".parse().unwrap()),
                delegations: vec!["10.0.1.9/32".parse()?],
                public_key: KeyPair::generate().public.to_base64(),
                endpoint: None,
                candidates: vec![],
                ..peers[1].1.clone()
            },
        )?;

        // Every CIDR keeps its name and its parent, and is keyed by its prefix, that of its
        // network if its address has host bits set. The plain-HTTP view numbers the CIDRs in the
        // order of their prefixes.
        let legacy: Vec<_> = cidrs
            .iter()
            .map(|cidr| {
                let legacy = cidr.legacy(&cidrs);
                (
                    legacy.id,
                    legacy.name.clone(),
                    legacy.cidr.to_string(),
                    legacy.parent,
                )
            })
            .collect();
        let cidr = |id, name: &str, cidr: &str, parent| (id, name.into(), cidr.into(), parent);
        assert_eq!(
            legacy,
            [
                cidr(1, "root", "10.0.0.0/8", None),
                cidr(2, "innernet-server", "10.0.0.1/32", Some(1)),
                cidr(3, "users", "10.0.1.0/24", Some(1)),
                cidr(4, "loose", "10.0.2.0/24", Some(1)),
                cidr(5, "v6", "fd00::/64", None),
            ]
        );

        // Every association is kept, but one of a CIDR with itself, and a second one of the
        // same CIDRs, which change nothing.
        let prefix = |text: &str| text.parse::<Prefix>().unwrap();
        let associations: Vec<_> = DatabaseAssociation::list(&store)?
            .iter()
            .map(|association| (association.cidr_1, association.cidr_2))
            .collect();
        assert_eq!(
            associations,
            [
                (prefix("10.0.1.0/24"), prefix("10.0.2.0/24")),
                (prefix("10.0.1.0/24"), prefix("fd00::/64")),
            ]
        );

        // Every peer sees the CIDR of the server's own peer, the one that every peer saw, and
        // the CIDRs associated with its own.
        let server_peer = DatabasePeer::get_from_public_key(&store, &server_key)?;
        assert_eq!(
            server_peer
                .legacy(ids[&server_peer.public_key], &cidrs)
                .unwrap()
                .cidr_id,
            ORIGIN_INFRA_CIDR_ID
        );
        let v6_key = Key::from_base64(&peers[2].1.public_key)?;
        let v6 = DatabasePeer::get_from_public_key(&store, &v6_key)?;
        DatabasePeer::get_from_public_key(&store, &v6_key)?.update(
            &store,
            PeerContents {
                is_disabled: false,
                ..v6.inner.clone()
            },
        )?;
        let seen: Vec<_> = v6
            .get_all_allowed_peers(&store, &server_key)?
            .iter()
            .map(|peer| peer.name.as_ref().map(ToString::to_string))
            .collect();
        let names = ["innernet-server", "peer-v4", "new-peer", "peer-v6"];
        assert_eq!(seen, names.map(|name| Some(name.to_string())));

        // The backup holds the database as it was, which the earlier schema can read.
        let backup = Connection::open(dir.path().join("wg0.db.v2.0.0"))?;
        assert_eq!(dump(&backup)?, before_migration);
        assert_eq!(
            backup.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))?,
            "ok"
        );
        let backup_version: usize =
            backup.pragma_query_value(None, "user_version", |r| r.get(0))?;
        assert_eq!(backup_version, ENDPOINT_CANDIDATES_VERSION);
        let ids = backup
            .prepare("SELECT id FROM peers ORDER BY id")?
            .query_map([], |r| r.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(ids, [1, 2, 4, 7, 8]);
        let mode = fs::metadata(dir.path().join("wg0.db.v2.0.0"))?
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        // Running the migration again changes nothing, and makes no other backup.
        let before = DatabasePeer::list(&store)?
            .into_iter()
            .map(|peer| peer.inner)
            .collect::<Vec<_>>();
        auto_migrate(&mut store, &server_key)?;
        let after = DatabasePeer::list(&store)?
            .into_iter()
            .map(|peer| peer.inner)
            .collect::<Vec<_>>();
        assert_eq!(after, before);
        assert!(!has_column(&store, "peers", "candidates")?);
        assert!(!dir.path().join("wg0.db.v2.0.0.1").exists());
        Ok(())
    }

    #[test]
    fn test_migration_keeps_earlier_backups() -> Result<(), Error> {
        // A backup that an earlier migration left is kept, and the new one is put next to it.
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("wg0.db");
        let peers = create_upstream(&path);
        fs::write(dir.path().join("wg0.db.v2.0.0"), "earlier")?;
        auto_migrate(&mut open(&path), &server_key(&peers))?;
        assert_eq!(fs::read(dir.path().join("wg0.db.v2.0.0"))?, b"earlier");
        let backup = Connection::open(dir.path().join("wg0.db.v2.0.0.1"))?;
        let peers: i64 = backup.query_row("SELECT count(*) FROM peers", [], |r| r.get(0))?;
        assert_eq!(peers, 5);
        Ok(())
    }

    #[test]
    fn test_migration_fails_without_backup() -> Result<(), Error> {
        // If the backup can't be made, as when the server can't create files next to the
        // database, the migration fails, and leaves the database as it is, unlocked.
        if unsafe { libc::geteuid() } == 0 {
            // Root creates files in a directory without write permission.
            return Ok(());
        }
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("wg0.db");
        let peers = create_upstream(&path);
        let mut store = open(&path);
        let before_migration = dump(&store)?;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500))?;
        let result = auto_migrate(&mut store, &server_key(&peers));
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
        assert!(result.is_err());
        assert_eq!(dump(&open(&path))?, before_migration);
        assert!(has_column(&store, "peers", "id")?);
        let user_version: usize = store.pragma_query_value(None, "user_version", |r| r.get(0))?;
        assert_eq!(user_version, ENDPOINT_CANDIDATES_VERSION);
        assert!(!dir.path().join("wg0.db.v2.0.0").exists());
        Ok(())
    }

    #[test]
    fn test_migration_rolls_back() -> Result<(), Error> {
        // A peer that the rebuilt table can't hold fails the migration, which leaves the database
        // as it was.
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("wg0.db");
        let peers = create_upstream(&path);
        let mut store = open(&path);
        store.execute(
            "INSERT INTO peers (id, name, ip, public_key, cidr_id)
             VALUES (9, 'bad-key', '10.0.1.9', 'not a key', 3)",
            [],
        )?;
        assert!(auto_migrate(&mut store, &server_key(&peers)).is_err());
        assert!(has_column(&store, "peers", "id")?);
        let peers: i64 = store.query_row("SELECT count(*) FROM peers", [], |r| r.get(0))?;
        assert_eq!(peers, 6);
        Ok(())
    }

    #[test]
    fn test_migration_keeps_what_peers_see() -> Result<(), Error> {
        // A database that stores a parent, a CIDR of a peer, or a CIDR that every peer sees,
        // other than what the prefixes give, fails the migration, which leaves it as it was.
        for (change, reason) in [
            (
                "UPDATE cidrs SET parent = NULL WHERE id = 3",
                "smallest CIDR that holds it is 10.0.0.0/8",
            ),
            (
                "UPDATE peers SET cidr_id = 1 WHERE id = 2",
                "smallest CIDR that holds its IP 10.0.1.2 is 10.0.1.0/24",
            ),
            (
                "UPDATE cidrs SET ip = '10.0.1.0', prefix = 25 WHERE id = 6",
                "smallest CIDR that holds it is 10.0.1.0/24",
            ),
            (
                "UPDATE peers SET cidr_id = 3, ip = '10.0.1.1' WHERE id = 1",
                "which every peer sees",
            ),
            ("UPDATE cidrs SET ip = '10.0.1.7' WHERE id = 6", "UNIQUE"),
        ] {
            let dir = tempfile::tempdir()?;
            let path = dir.path().join("wg0.db");
            let peers = create_upstream(&path);
            let mut store = open(&path);
            store.execute_batch(&format!("PRAGMA foreign_keys = 0; {change}"))?;
            let before_migration = dump(&store)?;
            let error = format!(
                "{:#}",
                auto_migrate(&mut store, &server_key(&peers)).unwrap_err()
            );
            assert!(error.contains(reason), "{change}: {error}");
            assert_eq!(dump(&store)?, before_migration);
        }

        // So does a database without the server's own peer.
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("wg0.db");
        create_upstream(&path);
        let error = auto_migrate(&mut open(&path), &KeyPair::generate().public).unwrap_err();
        assert!(format!("{error:#}").contains("own peer"), "{error:#}");
        Ok(())
    }

    #[test]
    fn test_migrate_again() -> Result<(), Error> {
        // A database of the current schema migrates again without change, and a newer one that
        // this version can read keeps its version.
        let mut store = in_memory(network())?;
        let server_key = KeyPair::generate().public;
        auto_migrate(&mut store, &server_key)?;
        store.pragma_update(None, "user_version", node_db::SCHEMA_VERSION + 1)?;
        auto_migrate(&mut store, &server_key)?;
        let version: i64 = store.pragma_query_value(None, "user_version", |r| r.get(0))?;
        assert_eq!(version, node_db::SCHEMA_VERSION + 1);
        Ok(())
    }
}
