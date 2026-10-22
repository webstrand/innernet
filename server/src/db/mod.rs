//! The coordinator's database: the tables of every node, which the server's node and the
//! coordinator share, and the coordinator's annex beside them.

use anyhow::{anyhow, bail, ensure, Context as _, Error};
use innernet_node::{
    db::{self as node_db, CreateHook, APPLICATION_ID, SCHEMA_VERSION},
    store::{self, key_to_bytes},
    Store,
};
use innernet_shared::{
    parent_cidr, smallest_cidr_holding, Endpoint, Prefix, PERSISTENT_KEEPALIVE_INTERVAL_SECS,
};
use ipnet::IpNet;
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use std::{
    net::IpAddr,
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

/// The coordinator's own tables.
pub const ANNEX_SQL: &str = include_str!("annex.sql");

/// The ID of the infra CIDR of a database of 2.0.0, which every peer saw.
const ORIGIN_INFRA_CIDR_ID: i64 = 2;

/// The version of the schema of the databases of 2.0.0.
const ORIGIN_VERSION: i64 = 2;

/// Opens the database at `path`, which must exist, for the network `network`, rebuilding a
/// database of 2.0.0, whose coordinator is the peer with the public key `server_key`, as
/// [`rebuild`] does, and creating the coordinator's annex beside the schema of a new database.
pub fn open(path: &Path, network: IpNet, server_key: &Key) -> Result<Store, Error> {
    let mut conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    node_db::configure(&conn)?;
    if is_origin(&conn)? {
        rebuild(&mut conn, path, network, server_key)
            .with_context(|| format!("failed to migrate the database {}", path.display()))?;
    }
    let mut store = Store::new(conn, network);
    let annex: CreateHook = Arc::new(|scope| Ok(scope.execute_batch(ANNEX_SQL)?));
    store.migrate(Some(annex))?;
    Ok(store)
}

/// Whether `conn` holds a database of 2.0.0, or of a version before it: one whose peers are keyed
/// by an integer ID.
fn is_origin(conn: &Connection) -> Result<bool, Error> {
    let application_id: i32 = conn.pragma_query_value(None, "application_id", |r| r.get(0))?;
    Ok(application_id != APPLICATION_ID && node_db::has_column(conn, "peers", "id")?)
}

/// Rebuilds the database of 2.0.0 of `conn`, at `path`, into the tables of every node and the
/// coordinator's annex, for the network `network`, in one transaction. The database must hold
/// the server's own peer, the one with the public key `server_key`; the CIDR with the ID 2 is
/// marked infra.
///
/// Earlier versions can't read the rebuilt database, so it is first copied, as it is, to
/// `<path>.v2.0.0`, or `.v2.0.0.N` with the first free `N`, so that an earlier copy is kept. If
/// the copy fails, nothing is migrated. Each peer is delegated its IP, as a host prefix. The IDs
/// of the peers, the CIDRs and the associations aren't kept: the API of plain HTTP numbers them by
/// position. The invitations not yet redeemed are latched to TLS.
///
/// The parent of a CIDR and the CIDR of a peer aren't stored, but follow from prefixes: the parent
/// of a CIDR is the smallest other CIDR that holds it, and the CIDR of a peer is that of its
/// delegation. The rebuild keeps what each peer sees, so these roll the transaction back:
/// - a CIDR whose stored parent isn't the one that the prefixes give;
/// - a peer whose stored CIDR isn't the smallest that holds its IP;
/// - the server's own peer outside the CIDR with the ID 2, which every peer sees;
/// - a record that the new tables can't hold, such as a public key that isn't base64.
///
/// A CIDR whose address has host bits set becomes the prefix of its network. An association of a
/// CIDR with itself and a second association of the same two CIDRs change nothing, and are dropped
/// with a warning, as are an endpoint or candidates that the server couldn't read.
fn rebuild(
    conn: &mut Connection,
    path: &Path,
    network: IpNet,
    server_key: &Key,
) -> Result<(), Error> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    ensure!(
        version <= ORIGIN_VERSION,
        "the database is of version {version}, which this innernet-server doesn't know"
    );
    let backup = back_up(conn, path)?;
    log::info!(
        "migrating the database; its copy is at {}.",
        backup.display()
    );

    let tx = conn.transaction_with_behavior(TransactionBehavior::Exclusive)?;
    // Databases from before 2.0.0 lack the columns that it added.
    if !node_db::has_column(&tx, "peers", "invite_expires")? {
        tx.execute("ALTER TABLE peers ADD COLUMN invite_expires INTEGER", [])?;
    }
    if !node_db::has_column(&tx, "peers", "candidates")? {
        tx.execute("ALTER TABLE peers ADD COLUMN candidates TEXT", [])?;
    }
    tx.execute_batch(
        "ALTER TABLE peers RENAME TO origin_peers;
         ALTER TABLE cidrs RENAME TO origin_cidrs;
         ALTER TABLE associations RENAME TO origin_associations;",
    )?;
    tx.execute_batch(innernet_node::SCHEMA)?;
    tx.execute_batch(ANNEX_SQL)?;

    let mut cidrs: Vec<(i64, Prefix, Option<i64>)> = vec![];
    {
        let mut stmt =
            tx.prepare("SELECT id, name, ip, prefix, parent FROM origin_cidrs ORDER BY id")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let name: String = row.get(1)?;
            let ip: String = row.get(2)?;
            let prefix_len: u8 = row.get(3)?;
            let ip: IpAddr = ip
                .parse()
                .map_err(|_| anyhow!("CIDR {id} has an invalid IP {ip}"))?;
            // A CIDR whose address has host bits set is the prefix of its network, as the server
            // read it.
            let prefix = Prefix::new(IpNet::new(ip, prefix_len)?.trunc())
                .map_err(|e| anyhow!("CIDR {id}: {e}"))?;
            cidrs.push((id, prefix, row.get(4)?));
            tx.execute(
                "INSERT INTO cidrs (address, prefix_len, name, infra) VALUES (?1, ?2, ?3, ?4)",
                params![
                    store::ip_to_bytes(prefix.first()),
                    prefix.prefix_len(),
                    name,
                    id == ORIGIN_INFRA_CIDR_ID
                ],
            )?;
        }
    }
    let prefix_of = |id: i64| {
        cidrs
            .iter()
            .find(|(cidr_id, ..)| *cidr_id == id)
            .map(|(_, prefix, _)| *prefix)
    };
    let prefixes: Vec<Prefix> = cidrs.iter().map(|(_, prefix, _)| *prefix).collect();
    for (id, prefix, parent) in &cidrs {
        let stored = parent
            .map(|parent| {
                prefix_of(parent)
                    .ok_or_else(|| anyhow!("CIDR {id} has the unknown parent {parent}"))
            })
            .transpose()?;
        let given = parent_cidr(prefix, &prefixes);
        ensure!(
            stored == given,
            "CIDR {id} ({prefix}) has the parent {}, but the smallest CIDR that holds it is {}; \
             the rebuilt database finds a CIDR's parent by its prefix",
            describe_cidr(stored),
            describe_cidr(given),
        );
    }
    {
        let mut stmt =
            tx.prepare("SELECT id, cidr_id_1, cidr_id_2 FROM origin_associations ORDER BY id")?;
        let mut rows = stmt.query([])?;
        let mut copied: Vec<(Prefix, Prefix)> = vec![];
        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let prefix = |cidr_id: i64| {
                prefix_of(cidr_id).ok_or_else(|| {
                    anyhow!("association {id} names CIDR {cidr_id}, which doesn't exist")
                })
            };
            let (a, b) = (prefix(row.get(1)?)?, prefix(row.get(2)?)?);
            let pair = (a.min(b), a.max(b));
            if a == b || copied.contains(&pair) {
                log::warn!(
                    "dropping association {id} of the CIDRs {a} and {b}, which changes nothing."
                );
                continue;
            }
            tx.execute(
                "INSERT INTO associations (address_1, prefix_len_1, address_2, prefix_len_2)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    store::ip_to_bytes(pair.0.first()),
                    pair.0.prefix_len(),
                    store::ip_to_bytes(pair.1.first()),
                    pair.1.prefix_len()
                ],
            )?;
            copied.push(pair);
        }
    }

    let scope = innernet_node::db::Scope::new(&tx, network);
    let server_key = server_key.to_base64();
    let mut stmt = tx.prepare(
        "SELECT id, name, ip, cidr_id, public_key, endpoint, is_admin, is_disabled, is_redeemed,
                invite_expires, candidates
         FROM origin_peers ORDER BY id",
    )?;
    let mut rows = stmt.query([])?;
    let mut server_cidr = None;
    while let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        let public_key: String = row.get(4)?;
        let key = key_to_bytes(&public_key)
            .map_err(|_| anyhow!("peer {id} has an invalid public key {public_key:?}"))?;
        let public_key = Key(key).to_base64();
        let ip: String = row.get(2)?;
        let ip: IpAddr = ip
            .parse()
            .map_err(|_| anyhow!("peer {id} has an invalid IP {ip}"))?;
        let cidr_id: i64 = row.get(3)?;
        let stored = prefix_of(cidr_id);
        let given = smallest_cidr_holding(&Prefix::host(ip), &prefixes);
        ensure!(
            stored == given,
            "peer {id} at {ip} lies in the CIDR {}, but the smallest CIDR that holds its IP is {}; \
             the rebuilt database finds a peer's CIDR by its IP, so the peer would see other peers",
            describe_cidr(stored),
            describe_cidr(given),
        );
        let endpoint =
            row.get::<_, Option<String>>(5)?
                .and_then(|text| match text.parse::<Endpoint>() {
                    Ok(endpoint) => Some(endpoint),
                    Err(_) => {
                        log::warn!("dropping the unreadable endpoint {text:?} of peer {id}");
                        None
                    },
                });
        let candidates = row
            .get::<_, Option<String>>(10)?
            .and_then(|text| match serde_json::from_str::<Vec<Endpoint>>(&text) {
                Ok(candidates) => Some(candidates),
                Err(_) => {
                    log::warn!("dropping the unreadable candidates {text:?} of peer {id}");
                    None
                },
            })
            .unwrap_or_default();
        let contents = innernet_shared::PeerContents {
            name: Some(
                row.get::<_, String>(1)?
                    .parse()
                    .map_err(|_| anyhow!("peer {id} has an invalid name"))?,
            ),
            delegations: vec![Prefix::host(ip)],
            public_key: public_key.clone(),
            endpoint,
            persistent_keepalive_interval: Some(PERSISTENT_KEEPALIVE_INTERVAL_SECS),
            is_admin: row.get(6)?,
            is_disabled: row.get(7)?,
            is_redeemed: row.get(8)?,
            invite_expires: row
                .get::<_, Option<u64>>(9)?
                .map(|secs| std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)),
            candidates,
            announcement: None,
            allowed_ips: None,
            primary_ip: None,
        };
        if let Err(refusal) = scope.accept(&[&contents])?.remove(0) {
            bail!("peer {id} at {ip}: {refusal}");
        }
        if public_key == server_key {
            server_cidr = Some(cidr_id);
        }
    }
    drop(rows);
    drop(stmt);
    let server_cidr = server_cidr
        .ok_or_else(|| anyhow!("no peer has the public key {server_key} of the server's config"))?;
    ensure!(
        server_cidr == ORIGIN_INFRA_CIDR_ID || prefix_of(ORIGIN_INFRA_CIDR_ID).is_none(),
        "the server's own peer lies in CIDR {server_cidr}, not in CIDR {ORIGIN_INFRA_CIDR_ID}, \
         which every peer sees; the rebuilt database marks the CIDR that every peer sees as \
         infra, and every peer is to see the server's own peer"
    );
    // A redeemed peer keeps using plain HTTP until it first connects over TLS. An invitation not
    // yet redeemed is latched, as one that the server issues is, so that only a client that speaks
    // TLS may redeem it.
    tx.execute("UPDATE peers SET tls = 1 WHERE is_redeemed = 0", [])?;

    tx.execute_batch(
        "DROP TABLE origin_associations;
         DROP TABLE origin_peers;
         DROP TABLE origin_cidrs;",
    )?;
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    tx.commit()?;
    Ok(())
}

/// A CIDR, or the lack of one, for an error.
fn describe_cidr(cidr: Option<Prefix>) -> String {
    cidr.map_or("none".into(), |cidr| cidr.to_string())
}

/// Copies the database of `conn`, at `path`, to `<path>.v2.0.0`, or `.v2.0.0.N` with the first
/// free `N`, with mode 0600, and returns the path of the copy.
fn back_up(conn: &Connection, path: &Path) -> Result<PathBuf, Error> {
    let base = format!("{}.v2.0.0", path.display());
    let backup = std::iter::once(PathBuf::from(&base))
        .chain((1..).map(|n| PathBuf::from(format!("{base}.{n}"))))
        .find(|candidate| !candidate.exists())
        .expect("some suffix is free");
    conn.execute("VACUUM INTO ?1", params![backup.to_string_lossy()])
        .with_context(|| format!("failed to copy the database to {}", backup.display()))?;
    let file = std::fs::File::open(&backup)?;
    innernet_shared::chmod(&file, 0o600)?;
    Ok(backup)
}

#[cfg(test)]
mod tests {
    use super::*;
    use innernet_node::store::load_peers;

    const ORIGIN_SQL: &str = "
        CREATE TABLE cidrs (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, ip TEXT NOT NULL,
          prefix INTEGER NOT NULL, parent INTEGER REFERENCES cidrs, UNIQUE(ip, prefix));
        CREATE TABLE peers (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, ip TEXT NOT NULL UNIQUE,
          public_key TEXT NOT NULL UNIQUE, endpoint TEXT, cidr_id INTEGER NOT NULL,
          is_admin INTEGER DEFAULT 0 NOT NULL, is_disabled INTEGER DEFAULT 0 NOT NULL,
          is_redeemed INTEGER DEFAULT 0 NOT NULL, invite_expires INTEGER, candidates TEXT,
          FOREIGN KEY (cidr_id) REFERENCES cidrs (id));
        CREATE TABLE associations (
          id INTEGER PRIMARY KEY, cidr_id_1 INTEGER NOT NULL, cidr_id_2 INTEGER NOT NULL,
          UNIQUE(cidr_id_1, cidr_id_2));
        PRAGMA user_version = 2;";

    fn origin(path: &Path, server: &Key, peers: &[(i64, &str, &str, i64, &str)]) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(ORIGIN_SQL).unwrap();
        conn.execute_batch(
            "INSERT INTO cidrs VALUES (1, 'net', '10.0.0.0', 16, NULL);
             INSERT INTO cidrs VALUES (2, 'innernet-server', '10.0.0.1', 32, 1);
             INSERT INTO cidrs VALUES (3, 'humans', '10.0.1.0', 24, 1);
             INSERT INTO cidrs VALUES (4, 'loose', '10.0.2.5', 24, 1);
             INSERT INTO associations VALUES (1, 3, 2), (2, 3, 3), (3, 2, 3);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO peers (id, name, ip, public_key, endpoint, cidr_id, is_admin, is_redeemed)
             VALUES (1, 'innernet-server', '10.0.0.1', ?1, '203.0.113.1:51820', 2, 1, 1)",
            [server.to_base64()],
        )
        .unwrap();
        for (id, name, ip, cidr_id, candidates) in peers {
            conn.execute(
                "INSERT INTO peers (id, name, ip, public_key, cidr_id, is_redeemed, candidates)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)",
                params![
                    id,
                    name,
                    ip,
                    Key::generate_private().get_public().to_base64(),
                    cidr_id,
                    candidates
                ],
            )
            .unwrap();
        }
    }

    fn network() -> IpNet {
        "10.0.0.0/16".parse().unwrap()
    }

    #[test]
    fn test_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wg0.db");
        let server = Key::generate_private().get_public();
        origin(
            &path,
            &server,
            &[(7, "alice", "10.0.1.2", 3, r#"["198.51.100.1:51820"]"#)],
        );
        Connection::open(&path)
            .unwrap()
            .execute(
                "INSERT INTO peers (id, name, ip, public_key, cidr_id, is_redeemed)
                 VALUES (8, 'invited', '10.0.1.3', ?1, 3, 0)",
                [Key::generate_private().get_public().to_base64()],
            )
            .unwrap();

        let store = open(&path, network(), &server).unwrap();
        let peers = load_peers(&store).unwrap();
        assert_eq!(peers.len(), 3);
        assert_eq!(peers[0].public_key, server.to_base64());
        assert_eq!(peers[1].display_name(), "alice");
        assert_eq!(peers[1].candidates, ["198.51.100.1:51820".parse().unwrap()]);

        // Each peer's IP is its delegation, a host prefix.
        let alice = DatabasePeer::get_by_address(&store, "10.0.1.2".parse().unwrap()).unwrap();
        assert_eq!(alice.display_name(), "alice");

        // Only the invitation is latched to TLS.
        let latched: Vec<bool> = DatabasePeer::list(&store)
            .unwrap()
            .iter()
            .map(|peer| peer.requires_tls)
            .collect();
        assert_eq!(latched, [false, false, true]);

        // The infra CIDR is marked, and a CIDR whose address has host bits set is the prefix of
        // its network.
        assert_eq!(
            DatabaseCidr::infra(&store).unwrap(),
            ["10.0.0.1/32".parse().unwrap()]
        );
        let cidrs = DatabaseCidr::list(&store).unwrap();
        assert_eq!(cidrs[3].name, "loose");
        assert_eq!(cidrs[3].prefix, "10.0.2.0/24".parse().unwrap());

        // The association joins the CIDRs that it joined, the lower first, and the association of
        // a CIDR with itself and the second one of the same CIDRs are dropped.
        let associations: Vec<(Prefix, Prefix)> = DatabaseAssociation::list(&store)
            .unwrap()
            .iter()
            .map(|association| (association.cidr_1, association.cidr_2))
            .collect();
        assert_eq!(
            associations,
            [(
                "10.0.0.1/32".parse().unwrap(),
                "10.0.1.0/24".parse().unwrap()
            )]
        );

        // The copy is the database of 2.0.0, and opening again changes nothing.
        let copy = Connection::open(dir.path().join("wg0.db.v2.0.0")).unwrap();
        assert!(node_db::has_column(&copy, "peers", "id").unwrap());
        drop(store);
        let store = open(&path, network(), &server).unwrap();
        assert_eq!(load_peers(&store).unwrap().len(), 3);
        assert!(!dir.path().join("wg0.db.v2.0.0.1").exists());
    }

    #[test]
    fn test_rebuild_keeps_what_peers_see() {
        // A database that stores a parent, a CIDR of a peer, or a CIDR that every peer sees,
        // other than what the prefixes give, is left as it was.
        for (change, reason) in [
            (
                "UPDATE cidrs SET parent = NULL WHERE id = 3",
                "smallest CIDR that holds it is 10.0.0.0/16",
            ),
            (
                "UPDATE peers SET cidr_id = 1 WHERE id = 7",
                "smallest CIDR that holds its IP is 10.0.1.0/24",
            ),
            (
                "UPDATE peers SET cidr_id = 3, ip = '10.0.1.1' WHERE id = 1",
                "which every peer sees",
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("wg0.db");
            let server = Key::generate_private().get_public();
            origin(&path, &server, &[(7, "alice", "10.0.1.2", 3, "[]")]);
            Connection::open(&path)
                .unwrap()
                .execute(change, [])
                .unwrap();
            let error = format!("{:#}", open(&path, network(), &server).unwrap_err());
            assert!(error.contains(reason), "{change}: {error}");
            let conn = Connection::open(&path).unwrap();
            assert!(node_db::has_column(&conn, "peers", "id").unwrap());
        }
    }
}
