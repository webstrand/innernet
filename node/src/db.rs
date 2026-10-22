//! The database of a node: the [`Store`], which holds the connection to it with the network of
//! the node, and through which alone the node accepts announcements, and how the connection is
//! opened, configured and migrated to the version of [`SCHEMA`](crate::SCHEMA) that this binary
//! writes.

use crate::accept::{self, Accepted, Received, Refusal};
use anyhow::{ensure, Error};
use ipnet::IpNet;
use rusqlite::{config::DbConfig, Connection, OpenFlags, Transaction, TransactionBehavior};
use rusqlite_migration::{HookError, Migrations, M};
use std::{ops::Deref, path::Path, sync::Arc, time::Duration};

/// Identifies the database file as an innernet database: "innr".
pub const APPLICATION_ID: i32 = 0x696e_6e72;

/// The version of the schema that this binary writes.
pub const SCHEMA_VERSION: i64 = 1;

/// How long to wait for another connection to finish writing the database.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// What a host runs in the transaction that creates the schema of a new database, such as the
/// import of a store of earlier versions.
pub type CreateHook = Arc<dyn Fn(&Scope) -> Result<(), Error> + Send + Sync>;

/// A node's database, with the network of the node, the whole-network prefix of its config,
/// outside which it accepts no claim. It dereferences to its connection, through which a host
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

    /// Accepts what the node accepts of `received`, as [`Scope::accept`] does.
    pub fn accept(
        &self,
        received: &[Received],
        now: u64,
    ) -> Result<Vec<Result<Accepted, Refusal>>, rusqlite::Error> {
        self.scope().accept(received, now)
    }

    /// Accepts `received` alone, as [`Scope::accept`] does.
    pub fn accept_one(
        &self,
        received: &Received,
        now: u64,
    ) -> Result<Result<Accepted, Refusal>, rusqlite::Error> {
        self.scope().accept_one(received, now)
    }
}

impl Deref for Store {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        &self.conn
    }
}

/// A store as a connection or a transaction of it sees it, through which the node accepts
/// announcements within the network of the store.
#[derive(Clone, Copy)]
pub struct Scope<'a> {
    conn: &'a Connection,
    network: IpNet,
}

impl Scope<'_> {
    pub fn network(&self) -> IpNet {
        self.network
    }

    /// Decides what the node accepts of `received`, at the time `now`, without writing anything:
    /// each announcement is checked as [`accept::check`] checks it within the network of the store,
    /// and what each accepted one claims is pinned to its key, as [`crate::claims::resolve`]
    /// decides it.
    pub fn decide(
        &self,
        received: &[Received],
        now: u64,
    ) -> Result<Vec<Result<Accepted, Refusal>>, rusqlite::Error> {
        accept::decide(self.conn, self.network, received, now)
    }

    /// Records `accepted`, as [`Self::decide`] decided it: each announcement, and what is pinned to
    /// each key.
    pub fn apply(&self, accepted: &[Accepted]) -> Result<(), rusqlite::Error> {
        accept::apply(self.conn, accepted)
    }

    /// Accepts what the node accepts of `received`, as [`Self::decide`] decides it, and records
    /// it. Returns, for each of `received`, what was accepted or why it was refused.
    pub fn accept(
        &self,
        received: &[Received],
        now: u64,
    ) -> Result<Vec<Result<Accepted, Refusal>>, rusqlite::Error> {
        let decided = self.decide(received, now)?;
        let accepted: Vec<Accepted> = decided
            .iter()
            .filter_map(|decided| decided.as_ref().ok().cloned())
            .collect();
        self.apply(&accepted)?;
        Ok(decided)
    }

    /// Accepts `received` alone, as [`Self::accept`] does.
    pub fn accept_one(
        &self,
        received: &Received,
        now: u64,
    ) -> Result<Result<Accepted, Refusal>, rusqlite::Error> {
        let mut decided = self.accept(std::slice::from_ref(received), now)?;
        Ok(decided.remove(0))
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
/// transactions that take the write lock up front, and off what the database doesn't need: SQL
/// that deliberately corrupts it, functions with side effects called from the schema, and
/// double-quoted strings, which otherwise fall back to literals when no column has the name and so
/// hide typos.
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
