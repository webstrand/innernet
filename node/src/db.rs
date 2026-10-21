//! The database of a node: the [`Store`], which holds the connection to it with the network of
//! the node, and through which alone the node accepts the records of peers, and how the
//! connection is opened, configured and migrated to the version of [`SCHEMA`](crate::SCHEMA) that
//! this binary writes.

use crate::accept::{self, Refusal};
use anyhow::{ensure, Error};
use innernet_shared::PeerContents;
use ipnet::IpNet;
use rusqlite::{config::DbConfig, Connection, OpenFlags, Transaction, TransactionBehavior};
use rusqlite_migration::{HookError, Migrations, M};
use std::{ops::Deref, path::Path, sync::Arc, time::Duration};

/// Identifies the database file as an innernet database: "innr".
pub const APPLICATION_ID: i32 = 0x696e_6e72;

/// The version of the schema that this binary writes.
pub const SCHEMA_VERSION: i64 = 1;

/// How long to wait for another connection to finish writing the database.
pub const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// What a host runs in the transaction that creates the schema of a new database, such as the
/// import of a store of earlier versions.
pub type CreateHook = Arc<dyn Fn(&Scope) -> Result<(), Error> + Send + Sync>;

/// A node's database, with the network of the node, the whole-network prefix of its config,
/// outside which it accepts no peer. It dereferences to its connection, through which a host
/// reads and writes its own tables.
#[derive(Debug)]
pub struct Store {
    conn: Connection,
    network: IpNet,
}

impl Store {
    /// Opens the database at `path`, which must exist, for the network `network`, configures the
    /// connection as [`configure`] does, and migrates it to [`SCHEMA_VERSION`], running
    /// `on_create` in the transaction that creates the schema of a new database.
    pub fn open(path: &Path, network: IpNet, on_create: Option<CreateHook>) -> Result<Self, Error> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure(&conn)?;
        let mut store = Self::new(conn, network);
        store.migrate(on_create)?;
        Ok(store)
    }

    /// The store of `conn`, a connection that the host opened and configured, for the network
    /// `network`.
    pub fn new(conn: Connection, network: IpNet) -> Self {
        Self {
            conn,
            network: network.trunc(),
        }
    }

    /// A new database in memory, of the current schema, for the network `network`.
    pub fn in_memory(network: IpNet) -> Result<Self, Error> {
        let conn = Connection::open_in_memory()?;
        configure(&conn)?;
        let mut store = Self::new(conn, network);
        store.migrate(None)?;
        Ok(store)
    }

    pub fn network(&self) -> IpNet {
        self.network
    }

    /// The store as its connection sees it.
    pub fn scope(&self) -> Scope<'_> {
        Scope {
            conn: &self.conn,
            network: self.network,
        }
    }

    /// The connection, for what only a migration of the host's tables does with it.
    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    /// Begins a transaction, which takes the write lock up front.
    pub fn transaction(&mut self) -> Result<StoreTransaction<'_>, rusqlite::Error> {
        Ok(StoreTransaction {
            tx: self.conn.transaction()?,
            network: self.network,
        })
    }

    /// Migrates the database to [`SCHEMA_VERSION`], running `on_create` in the transaction that
    /// creates the schema of a new database. A database of a newer version is used as it is,
    /// unless a later migration added an invariant that this binary would break.
    pub fn migrate(&mut self, on_create: Option<CreateHook>) -> Result<(), Error> {
        migrate(&mut self.conn, self.network, on_create)
    }

    /// Accepts what the node accepts of `peers`, as [`Scope::accept`] does.
    pub fn accept(
        &self,
        peers: &[&PeerContents],
    ) -> Result<Vec<Result<(), Refusal>>, rusqlite::Error> {
        self.scope().accept(peers)
    }
}

impl Deref for Store {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        &self.conn
    }
}

/// A store as a connection or a transaction of it sees it, through which the node accepts the
/// records of peers within the network of the store.
#[derive(Clone, Copy)]
pub struct Scope<'a> {
    conn: &'a Connection,
    network: IpNet,
}

impl<'a> Scope<'a> {
    /// The store as `conn`, a connection to a node's database or a transaction of it, sees it, for
    /// the network `network`.
    pub fn new(conn: &'a Connection, network: IpNet) -> Self {
        Self {
            conn,
            network: network.trunc(),
        }
    }

    pub fn network(&self) -> IpNet {
        self.network
    }

    /// Accepts what the node accepts of `peers`, the records of peers as the coordinator makes
    /// them, as [`accept::decide`] decides it, and records it. Returns, for each of `peers`,
    /// whether it was accepted or why it was refused.
    pub fn accept(
        &self,
        peers: &[&PeerContents],
    ) -> Result<Vec<Result<(), Refusal>>, rusqlite::Error> {
        let decided = accept::decide(self.conn, self.network, peers)?;
        let accepted: Vec<&PeerContents> = peers
            .iter()
            .zip(&decided)
            .filter(|(_, decided)| decided.is_ok())
            .map(|(peer, _)| *peer)
            .collect();
        accept::apply(self.conn, &accepted)?;
        Ok(decided)
    }
}

impl Deref for Scope<'_> {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        self.conn
    }
}

/// A transaction of a [`Store`].
pub struct StoreTransaction<'a> {
    tx: Transaction<'a>,
    network: IpNet,
}

impl StoreTransaction<'_> {
    pub fn scope(&self) -> Scope<'_> {
        Scope {
            conn: &self.tx,
            network: self.network,
        }
    }

    pub fn commit(self) -> Result<(), rusqlite::Error> {
        self.tx.commit()
    }
}

impl Deref for StoreTransaction<'_> {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        &self.tx
    }
}

/// Configures `conn` as every connection to a node's database is: foreign keys on, a busy timeout,
/// and off what the database doesn't need: SQL that deliberately corrupts it, functions with side
/// effects called from the schema, and double-quoted strings, which otherwise fall back to
/// literals when no column has the name and so hide typos.
pub fn configure(conn: &Connection) -> Result<(), Error> {
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DML, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DDL, false)?;
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    Ok(())
}

fn migrate(
    conn: &mut Connection,
    network: IpNet,
    on_create: Option<CreateHook>,
) -> Result<(), Error> {
    // A deferred transaction that upgrades from reading to writing can fail with SQLITE_BUSY
    // despite the busy timeout, so every transaction takes the write lock up front.
    conn.set_transaction_behavior(TransactionBehavior::Immediate);

    let application_id: i32 = conn.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    ensure!(
        application_id == APPLICATION_ID || (application_id == 0 && version == 0),
        "the file is not an innernet database"
    );

    if version > SCHEMA_VERSION {
        let min_reader_version: i64 = conn.query_row(
            "SELECT value FROM meta WHERE key = 'min_reader_version'",
            [],
            |r| r.get(0),
        )?;
        ensure!(
            min_reader_version <= SCHEMA_VERSION,
            "the database is of version {version}, which needs a newer innernet"
        );
        return Ok(());
    }

    let first = match on_create {
        Some(hook) => M::up_with_hook(crate::SCHEMA, move |tx: &Transaction| {
            let scope = Scope { conn: tx, network };
            hook(&scope).map_err(|e| HookError::Hook(format!("{e:#}")))
        }),
        None => M::up(crate::SCHEMA),
    };
    if let Err(e) = Migrations::new(vec![first]).to_latest(conn) {
        // Another process may have migrated the database between this one reading its version and
        // taking the write lock, in which case this migration failed and was rolled back.
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version < SCHEMA_VERSION {
            return Err(e.into());
        }
    }
    Ok(())
}

/// Whether `table` has a column named `column`.
pub fn has_column(conn: &Connection, table: &str, column: &str) -> Result<bool, rusqlite::Error> {
    conn.query_row(
        "SELECT count(*) FROM pragma_table_info(?1) WHERE name = ?2",
        rusqlite::params![table, column],
        |row| row.get::<_, i64>(0),
    )
    .map(|count| count > 0)
}
