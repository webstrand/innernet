//! The coordinator's database: the tables of every node, which the server's node and the
//! coordinator share, and the coordinator's annex beside them.

use anyhow::{anyhow, bail, ensure, Context as _, Error};
use innernet_node::{
    db::{self as node_db, CreateHook, APPLICATION_ID, SCHEMA_VERSION},
    store::{self, key_to_bytes, StoredCidr},
    Store,
};
use innernet_shared::{Endpoint, Prefix, PERSISTENT_KEEPALIVE_INTERVAL_SECS};
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
/// the copy fails, nothing is migrated. A record that the new tables can't hold, such as a public
/// key that isn't base64 or a peer whose CIDR isn't the smallest that holds its IP, rolls the
/// transaction back; an endpoint or candidates that the server couldn't read are dropped with a
/// warning, as the server ignored them. The IDs of the peers, the CIDRs and the associations
/// aren't kept: the API of plain HTTP numbers them by position.
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

    let mut cidrs = vec![];
    {
        let mut stmt = tx.prepare("SELECT id, name, ip, prefix FROM origin_cidrs ORDER BY id")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let name: String = row.get(1)?;
            let ip: String = row.get(2)?;
            let prefix_len: u8 = row.get(3)?;
            let ip: IpAddr = ip
                .parse()
                .map_err(|_| anyhow!("CIDR {id} has an invalid IP {ip}"))?;
            let prefix =
                Prefix::new(IpNet::new(ip, prefix_len)?).map_err(|e| anyhow!("CIDR {id}: {e}"))?;
            cidrs.push((id, prefix));
            store::insert_cidr(
                &tx,
                &StoredCidr {
                    prefix,
                    name,
                    infra: id == ORIGIN_INFRA_CIDR_ID,
                },
            )?;
        }
    }
    {
        let prefix_of = |id: i64| {
            cidrs
                .iter()
                .find(|(cidr_id, _)| *cidr_id == id)
                .map(|(_, prefix)| *prefix)
                .ok_or_else(|| anyhow!("an association names CIDR {id}, which doesn't exist"))
        };
        let mut stmt = tx.prepare("SELECT cidr_id_1, cidr_id_2 FROM origin_associations")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let (prefix_1, prefix_2) = (prefix_of(row.get(0)?)?, prefix_of(row.get(1)?)?);
            tx.execute(
                "INSERT INTO associations (address_1, prefix_len_1, address_2, prefix_len_2)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    store::ip_to_bytes(prefix_1.first()),
                    prefix_1.prefix_len(),
                    store::ip_to_bytes(prefix_2.first()),
                    prefix_2.prefix_len()
                ],
            )?;
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
    let mut has_server = false;
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
        let smallest = cidrs
            .iter()
            .filter(|(_, prefix)| prefix.contains_addr(&ip))
            .max_by_key(|(_, prefix)| prefix.prefix_len());
        if smallest.map(|(id, _)| *id) != Some(cidr_id) {
            bail!(
                "peer {id} at {ip} belongs to CIDR {cidr_id}, which isn't the smallest CIDR that \
                 holds its IP; the rebuilt database finds a peer's CIDR by its IP, so the peer \
                 would see other peers"
            );
        }
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
            name: row
                .get::<_, String>(1)?
                .parse()
                .map_err(|_| anyhow!("peer {id} has an invalid name"))?,
            ip,
            cidr_id,
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
        };
        if let Err(refusal) = scope.accept(&[&contents])?.remove(0) {
            bail!("peer {id} at {ip}: {refusal}");
        }
        has_server |= public_key == server_key;
    }
    drop(rows);
    drop(stmt);
    ensure!(
        has_server,
        "no peer has the public key {server_key} of the server's config"
    );

    tx.execute_batch(
        "DROP TABLE origin_associations;
         DROP TABLE origin_peers;
         DROP TABLE origin_cidrs;",
    )?;
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    tx.commit()?;
    Ok(())
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
             INSERT INTO associations VALUES (1, 3, 2);",
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

        let store = open(&path, network(), &server).unwrap();
        let peers = load_peers(&store).unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].public_key, server.to_base64());
        assert_eq!(peers[1].name.to_string(), "alice");
        assert_eq!(peers[1].candidates, ["198.51.100.1:51820".parse().unwrap()]);

        // The infra CIDR is marked, and the association joins the CIDRs that it joined.
        let infra: Vec<String> = store::load_cidrs(&store)
            .unwrap()
            .into_iter()
            .filter(|cidr| cidr.infra)
            .map(|cidr| cidr.name)
            .collect();
        assert_eq!(infra, ["innernet-server"]);
        let associations: i64 = store
            .query_row("SELECT count(*) FROM associations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(associations, 1);

        // The copy is the database of 2.0.0, and opening again changes nothing.
        let copy = Connection::open(dir.path().join("wg0.db.v2.0.0")).unwrap();
        assert!(node_db::has_column(&copy, "peers", "id").unwrap());
        drop(store);
        let store = open(&path, network(), &server).unwrap();
        assert_eq!(load_peers(&store).unwrap().len(), 2);
        assert!(!dir.path().join("wg0.db.v2.0.0.1").exists());
    }

    #[test]
    fn test_rebuild_rolls_back() {
        // A peer whose CIDR isn't the smallest that holds its IP leaves the database as it was.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wg0.db");
        let server = Key::generate_private().get_public();
        origin(&path, &server, &[(2, "alice", "10.0.1.2", 1, "[]")]);
        assert!(open(&path, network(), &server).is_err());
        let conn = Connection::open(&path).unwrap();
        assert!(node_db::has_column(&conn, "peers", "id").unwrap());
    }
}
