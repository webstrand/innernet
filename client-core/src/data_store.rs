use anyhow::{anyhow, bail, ensure, Context as _, Error};
use innernet_shared::{
    ensure_dirs_exist, interface_config::InterfaceConfig, Cidr, CidrContents, Endpoint, Hostname,
    IoErrorContext, Peer, PeerContents, State,
};
use ipnet::IpNet;
use rusqlite::{
    config::DbConfig, params, Connection, OpenFlags, OptionalExtension as _, Transaction,
    TransactionBehavior,
};
use rusqlite_migration::{HookError, Migrations, M};
use serde::Deserialize;
use std::{
    collections::HashMap,
    fs::OpenOptions,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{Duration, UNIX_EPOCH},
};
use wireguard_control::{InterfaceName, Key};

/// SQLite-backed storage of [`Peer`]s and [`Cidr`]s, and of the (IP, PublicKey) pins of the peers.
///
/// The database is stored at [`Self::get_path()`]. A data store from before SQLite, at
/// [`Self::get_legacy_path()`], is imported when the database is created, and left untouched.
#[derive(Debug)]
pub struct DataStore {
    conn: Connection,
    /// The records of the data store, as last loaded from the database.
    records: Records,
}

/// The peers and CIDRs of a data store, as loaded from its database.
#[derive(Debug)]
struct Records {
    /// The peers, indexed.
    peers: PeersIndex,
    cidrs: Vec<Cidr>,
    /// The network of the interface, from its config. It is not persisted.
    network: IpNet,
}

/// Identifies the database file as an innernet data store: "innr".
const APPLICATION_ID: i32 = 0x696e_6e72;

/// How long to wait for another process to finish writing the data store.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Server IDs aren't stored, so every peer loaded from the data store has this ID, and so does the
/// CIDR of a peer outside every CIDR. The CIDRs are numbered from 1 when they are loaded.
const UNKNOWN_ID: i64 = 0;

/// The versions of the schema, each of which the binary knows how to migrate to. A migration runs
/// in one transaction with the bump of `user_version`.
fn migrations(legacy_path: PathBuf, network: IpNet) -> Migrations<'static> {
    Migrations::new(vec![M::up_with_hook(
        include_str!("data_store/v1.sql"),
        move |tx: &Transaction| {
            import_legacy(tx, &legacy_path, network).map_err(|e| HookError::Hook(format!("{e:#}")))
        },
    )])
}

/// The version of the schema that this binary writes.
const SCHEMA_VERSION: i64 = 1;

/// The kinds of the pins of `prefix_pins`, as the `pin_kinds` table names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinKind {
    Address = 0,
}

impl PinKind {
    #[cfg(test)]
    const ALL: &'static [(Self, &'static str)] = &[(Self::Address, "address")];
}

/// The kinds of the endpoints of `endpoints`, as the `endpoint_kinds` table names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointKind {
    Endpoint = 0,
    Candidate = 1,
}

impl EndpointKind {
    #[cfg(test)]
    const ALL: &'static [(Self, &'static str)] =
        &[(Self::Endpoint, "endpoint"), (Self::Candidate, "candidate")];

    fn from_i64(kind: i64) -> Result<Self, Error> {
        match kind {
            0 => Ok(Self::Endpoint),
            1 => Ok(Self::Candidate),
            _ => bail!("unknown endpoint kind {kind}"),
        }
    }
}

/// The data store of the JSON file of earlier versions.
#[derive(Debug, Deserialize)]
#[serde(tag = "version")]
enum LegacyContents {
    #[serde(rename = "1")]
    V1 { peers: Vec<Peer>, cidrs: Vec<Cidr> },
}

impl DataStore {
    fn open_with_paths(
        path: &Path,
        legacy_path: &Path,
        network: IpNet,
        create: bool,
    ) -> Result<Self, Error> {
        // A legacy data store is imported into a new database, so the database is created for it.
        let create = create || legacy_path.try_exists().with_path(legacy_path)?;

        // The mode applies only if the file is created, in the same call that creates it. SQLite
        // gives its journal the mode of the database.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(create)
            .mode(0o600)
            .open(path)
            .with_path(path)?;
        innernet_shared::warn_on_dangerous_mode(&file, path).with_path(path)?;
        drop(file);

        let conn = connect(path, legacy_path.to_owned(), network)
            .with_context(|| format!("failed to open the data store {}", path.display()))?;
        let records = load(&conn, network.trunc())
            .with_context(|| format!("failed to load the data store {}", path.display()))?;

        Ok(Self { conn, records })
    }

    /// Produce the path "`data_dir`/`interface`.db".
    pub fn get_path(data_dir: &Path, interface: &InterfaceName) -> PathBuf {
        data_dir.join(interface.to_string()).with_extension("db")
    }

    /// Produce the path "`data_dir`/`interface`.json" of the data store of earlier versions.
    pub fn get_legacy_path(data_dir: &Path, interface: &InterfaceName) -> PathBuf {
        data_dir.join(interface.to_string()).with_extension("json")
    }

    /// The files of the data store of `interface`: the database, its journal and the data store of
    /// earlier versions.
    pub fn get_paths(data_dir: &Path, interface: &InterfaceName) -> [PathBuf; 3] {
        [
            Self::get_path(data_dir, interface),
            data_dir.join(format!("{interface}.db-journal")),
            Self::get_legacy_path(data_dir, interface),
        ]
    }

    /// Whether a data store exists for `interface`, either the database or one of earlier versions.
    pub fn exists(data_dir: &Path, interface: &InterfaceName) -> Result<bool, Error> {
        for path in [
            Self::get_path(data_dir, interface),
            Self::get_legacy_path(data_dir, interface),
        ] {
            if path.try_exists().with_path(&path)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn _open(
        data_dir: &Path,
        interface: &InterfaceName,
        config: &InterfaceConfig,
        create: bool,
    ) -> Result<Self, Error> {
        ensure_dirs_exist(&[data_dir])?;
        Self::open_with_paths(
            &Self::get_path(data_dir, interface),
            &Self::get_legacy_path(data_dir, interface),
            config.interface.address,
            create,
        )
    }

    /// Open the data store residing at "`data_dir`/`interface`.db", whose peers must lie within
    /// the network of `config`, importing the one of earlier versions if there is one.
    pub fn open(
        data_dir: &Path,
        interface: &InterfaceName,
        config: &InterfaceConfig,
    ) -> Result<Self, Error> {
        Self::_open(data_dir, interface, config, false)
    }

    /// Open or create the data store residing at "`data_dir`/`interface`.db", whose peers must
    /// lie within the network of `config`, importing the one of earlier versions if there is one.
    pub fn open_or_create(
        data_dir: &Path,
        interface: &InterfaceName,
        config: &InterfaceConfig,
    ) -> Result<Self, Error> {
        Self::_open(data_dir, interface, config, true)
    }

    /// Records the coordinator and this client as the interface config introduces them, and
    /// writes the data store. This is the introduction, when an invitation is redeemed, so the
    /// data store must be new.
    ///
    /// The interface config, which the invitation produced, is the authority on both, so their
    /// (IP, PublicKey) tuples are pinned before the coordination server reports anything. Each
    /// record is named by its public key until a fetch replaces it with the server's record.
    pub fn introduce(&mut self, config: &InterfaceConfig) -> Result<(), Error> {
        let introduced = introduced_peers(config)?;
        self.transact(|records| {
            if !records.peers.peers.is_empty() {
                bail!("the data store to introduce peers into is not new.");
            }
            for introduced in introduced {
                records.peers.insert(introduced);
            }
            Ok(())
        })
    }

    /// Merges the peers of `state` into the data store, replaces its CIDRs with those of `state`,
    /// and writes it to disk. Returns the peers of `state` that were dropped, each with the reason
    /// that it was dropped.
    ///
    /// A peer that the data store already holds is updated, a new peer is added, and a peer that
    /// is absent from `state` is disabled rather than deleted, so that its (IP, PublicKey) tuple
    /// remains pinned. A peer of `state` is dropped if it lies outside the network of the
    /// interface, conflicts with a pin, or shares its IP or public key with an earlier peer of
    /// `state`. A dropped peer is absent from the update, so a pinned peer that it conflicts with
    /// is disabled.
    ///
    /// Pinning prevents a compromised server from impersonating an existing peer, but not from
    /// adding a new peer under its control.
    pub fn update<'a>(&mut self, state: &'a State) -> Result<Vec<(&'a Peer, Error)>, Error> {
        self.transact(|records| {
            let dropped = records.update_reported_peers(&state.peers, &state.invalid_peer_keys);
            records.cidrs = state.cidrs.clone();
            Ok(dropped)
        })
    }

    #[cfg(test)]
    fn update_peers<'a>(&mut self, new_peers: &'a [Peer]) -> Vec<(&'a Peer, Error)> {
        self.transact(|records| Ok(records.update_reported_peers(new_peers, &[])))
            .unwrap()
    }

    pub fn peers(&self) -> &[Peer] {
        &self.records.peers.peers
    }

    pub fn cidrs(&self) -> &[Cidr] {
        &self.records.cidrs
    }

    /// Applies `change` to the records of the database and writes them back, in one transaction
    /// that holds the write lock from the start, so that a change made meanwhile by another
    /// process is neither missed nor overwritten. The records are then loaded again.
    fn transact<T>(
        &mut self,
        change: impl FnOnce(&mut Records) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let network = self.records.network;
        let tx = self.conn.transaction()?;
        let mut records = load(&tx, network)?;
        let result = change(&mut records)?;
        for peer in records.peers.peers.iter() {
            write_peer(&tx, peer)
                .with_context(|| format!("failed to store peer {}", peer.public_key))?;
        }
        write_cidrs(&tx, &records.cidrs)?;
        tx.commit()?;

        self.records = load(&self.conn, network)?;
        Ok(result)
    }
}

impl Records {
    /// Validates that `candidate` lies within the network of the interface.
    fn check_network_closure(&self, candidate: &Peer) -> Result<(), Error> {
        if !self.network.contains(&candidate.ip) {
            bail!(
                "IP {} is outside of the network {}.",
                candidate.ip,
                self.network
            );
        }

        Ok(())
    }

    /// Validates that the name of `candidate` is a valid hostname, that it lies within the network
    /// of the interface, matches the pins of the data store, and shares neither its IP nor its
    /// public key with a peer of `accepted`.
    fn check(&self, candidate: &Peer, accepted: &PeersIndex) -> Result<(), Error> {
        if !Hostname::is_valid(&candidate.name) {
            bail!("name is not a valid hostname.");
        }
        self.check_network_closure(candidate)?;
        match self.peers.check(candidate) {
            PinStatus::New | PinStatus::Unchanged => {},
            PinStatus::ConflictingKey => {
                bail!("PINNING ERROR: New peer has same IP but different public key.")
            },
            PinStatus::ConflictingIp => {
                bail!("PINNING ERROR: New peer has same public key but different IP.")
            },
        }
        if accepted.check(candidate) != PinStatus::New {
            bail!("IP or public key is shared with an earlier peer.");
        }

        Ok(())
    }

    /// Merges `new_peers` into the data store, dropping each that is invalid. `invalid_peer_keys`
    /// are the public keys of the peers that the server reported but that failed to deserialize.
    fn update_reported_peers<'a>(
        &mut self,
        new_peers: &'a [Peer],
        invalid_peer_keys: &[String],
    ) -> Vec<(&'a Peer, Error)> {
        let mut accepted = PeersIndex::default();
        let mut dropped = vec![];
        for new_peer in new_peers.iter() {
            match self.check(new_peer, &accepted) {
                Ok(()) => {
                    accepted.insert(new_peer.clone());
                },
                Err(e) => dropped.push((new_peer, e)),
            }
        }

        // The server leaves disabled peers out of the state, so a stored peer that the state
        // doesn't report is disabled. A dropped peer was reported, so the stored peer with its
        // public key keeps its record unchanged.
        for existing_peer in self.peers.peers.iter_mut() {
            let public_key = &existing_peer.public_key;
            if !new_peers.iter().any(|p| &p.public_key == public_key)
                && !invalid_peer_keys.contains(public_key)
            {
                existing_peer.contents.is_disabled = true;
            }
        }
        for new_peer in accepted.peers {
            self.peers.insert(new_peer);
        }

        dropped
    }
}

/// Opens the database at `path`, configures the connection, and migrates the schema to
/// [`SCHEMA_VERSION`], importing the legacy data store at `legacy_path` into a new database.
fn connect(path: &Path, legacy_path: PathBuf, network: IpNet) -> Result<Connection, Error> {
    let mut conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;

    // The connection turns off what the data store doesn't need: SQL that deliberately corrupts
    // the database, functions with side effects called from the schema, and double-quoted
    // strings, which otherwise fall back to literals when no column has the name and so hide
    // typos.
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DML, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DDL, false)?;
    conn.pragma_update(None, "foreign_keys", true)?;
    // Recursive triggers make the deletion with which REPLACE resolves a conflict fire the
    // triggers that refuse to delete pins.
    conn.pragma_update(None, "recursive_triggers", true)?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    // A deferred transaction that upgrades from reading to writing can fail with SQLITE_BUSY
    // despite the busy timeout, so every transaction takes the write lock up front.
    conn.set_transaction_behavior(TransactionBehavior::Immediate);

    let application_id: i32 = conn.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    ensure!(
        application_id == APPLICATION_ID || (application_id == 0 && version == 0),
        "the file is not an innernet data store"
    );

    if version > SCHEMA_VERSION {
        // A newer binary wrote the database. It can be used as it is, unless a later migration
        // added an invariant that this binary would break.
        let min_reader_version: i64 = conn.query_row(
            "SELECT value FROM meta WHERE key = 'min_reader_version'",
            [],
            |r| r.get(0),
        )?;
        ensure!(
            min_reader_version <= SCHEMA_VERSION,
            "the data store is of version {version}, which needs a newer innernet"
        );
        return Ok(conn);
    }

    if let Err(e) = migrations(legacy_path, network).to_latest(&mut conn) {
        // Another process may have migrated the database between this one reading its version and
        // taking the write lock, in which case this migration failed and was rolled back.
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version < SCHEMA_VERSION {
            return Err(e.into());
        }
    }

    Ok(conn)
}

/// Loads the peers and CIDRs of the database. Server IDs aren't stored: every peer has
/// [`UNKNOWN_ID`], and the CIDRs are numbered from 1, each with the smallest CIDR that contains it
/// as its parent, and each peer with the smallest CIDR that contains its IP as its CIDR.
fn load(conn: &Connection, network: IpNet) -> Result<Records, Error> {
    let mut cidrs = vec![];
    let mut stmt = conn.prepare(
        "SELECT address, prefix_len, name FROM cidrs ORDER BY length(address), address, prefix_len",
    )?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let cidr = prefix_from_row(row.get(0)?, row.get(1)?)?;
        cidrs.push(Cidr {
            id: cidrs.len() as i64 + 1,
            contents: CidrContents {
                name: row.get(2)?,
                cidr,
                parent: None,
            },
        });
    }
    let parents: Vec<Option<i64>> = cidrs
        .iter()
        .map(|child| {
            smallest_containing(&cidrs, |cidr| {
                *cidr != child.cidr && cidr.contains(&child.cidr)
            })
        })
        .collect();
    for (cidr, parent) in cidrs.iter_mut().zip(parents) {
        cidr.contents.parent = parent;
    }

    let mut endpoints: HashMap<Vec<u8>, (Option<Endpoint>, Vec<Endpoint>)> = HashMap::new();
    let mut stmt = conn.prepare(
        "SELECT public_key, kind, address, domain, port FROM endpoints
         ORDER BY public_key, kind, position",
    )?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let port: u16 = row.get(4)?;
        let endpoint = match (
            row.get::<_, Option<Vec<u8>>>(2)?,
            row.get::<_, Option<String>>(3)?,
        ) {
            (Some(address), None) => {
                Endpoint::from(std::net::SocketAddr::new(ip_from_bytes(&address)?, port))
            },
            (None, Some(domain)) => {
                Endpoint::from_domain(&domain, port).map_err(|e| anyhow!("{domain}: {e}"))?
            },
            _ => bail!("an endpoint is neither an address nor a domain"),
        };
        let entry = endpoints.entry(row.get(0)?).or_default();
        match EndpointKind::from_i64(row.get(1)?)? {
            EndpointKind::Endpoint => entry.0 = Some(endpoint),
            EndpointKind::Candidate => entry.1.push(endpoint),
        }
    }

    let mut peers = PeersIndex::default();
    let mut stmt = conn.prepare(
        "SELECT p.public_key, p.name, p.is_admin, p.is_disabled, p.is_redeemed,
                p.persistent_keepalive_interval, p.invite_expires, a.address
         FROM peers p
         LEFT JOIN prefix_pins a ON a.public_key = p.public_key AND a.kind = ?1
         ORDER BY length(a.address), a.address",
    )?;
    let mut rows = stmt.query([PinKind::Address as i64])?;
    while let Some(row) = rows.next()? {
        let key_bytes: Vec<u8> = row.get(0)?;
        let public_key = key_from_bytes(&key_bytes)?;
        let address: Option<Vec<u8>> = row.get(7)?;
        let ip = ip_from_bytes(
            &address.ok_or_else(|| anyhow!("peer {public_key} has no address pinned"))?,
        )?;
        ensure!(
            network.contains(&ip),
            "peer {public_key} at {ip} is outside of the network {network}"
        );
        let invite_expires = row
            .get::<_, Option<u64>>(6)?
            .map(|secs| UNIX_EPOCH + Duration::from_secs(secs));
        let (endpoint, candidates) = endpoints.remove(&key_bytes).unwrap_or_default();
        let peer = Peer {
            id: UNKNOWN_ID,
            contents: PeerContents {
                name: Hostname::unchecked(row.get(1)?),
                ip,
                cidr_id: smallest_containing(&cidrs, |cidr| cidr.contains(&ip))
                    .unwrap_or(UNKNOWN_ID),
                public_key,
                endpoint,
                persistent_keepalive_interval: row.get(5)?,
                is_admin: row.get(2)?,
                is_disabled: row.get(3)?,
                is_redeemed: row.get(4)?,
                invite_expires,
                candidates,
            },
        };
        let status = peers.insert(peer);
        ensure!(
            status == PinStatus::New,
            "the pins of the data store conflict ({status:?})"
        );
    }

    Ok(Records {
        peers,
        cidrs,
        network,
    })
}

/// Writes `peer` and its endpoints, and pins its IP to its public key, or checks that it is
/// already pinned to it.
fn write_peer(tx: &Transaction, peer: &Peer) -> Result<(), Error> {
    let public_key = key_to_bytes(&peer.public_key)?;
    let invite_expires = peer
        .invite_expires
        .map(|time| time.duration_since(UNIX_EPOCH).map(|d| d.as_secs()))
        .transpose()?;
    tx.execute(
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
            public_key,
            &*peer.name,
            peer.is_admin,
            peer.is_disabled,
            peer.is_redeemed,
            peer.persistent_keepalive_interval,
            invite_expires,
        ],
    )?;

    let address = ip_to_bytes(peer.ip);
    let pinned: Option<Vec<u8>> = tx
        .query_row(
            "SELECT address FROM prefix_pins WHERE public_key = ?1 AND kind = ?2",
            params![public_key, PinKind::Address as i64],
            |r| r.get(0),
        )
        .optional()?;
    match pinned {
        None => {
            tx.execute(
                "INSERT INTO prefix_pins (address, prefix_len, public_key, kind)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    address,
                    address.len() * 8,
                    public_key,
                    PinKind::Address as i64
                ],
            )?;
        },
        Some(pinned) => ensure!(pinned == address, "its address is pinned to another IP"),
    }

    tx.execute(
        "DELETE FROM endpoints WHERE public_key = ?1",
        params![public_key],
    )?;
    let endpoints = peer
        .endpoint
        .iter()
        .map(|endpoint| (EndpointKind::Endpoint, 0, endpoint))
        .chain(
            peer.candidates
                .iter()
                .enumerate()
                .map(|(position, endpoint)| (EndpointKind::Candidate, position, endpoint)),
        );
    for (kind, position, endpoint) in endpoints {
        tx.execute(
            "INSERT INTO endpoints (public_key, kind, position, address, domain, port)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                public_key,
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

/// Replaces the CIDRs of the database with `cidrs`. They are only displayed, so of two CIDRs with
/// the same prefix, the first is kept.
fn write_cidrs(tx: &Transaction, cidrs: &[Cidr]) -> Result<(), Error> {
    tx.execute("DELETE FROM cidrs", [])?;
    for cidr in cidrs {
        let prefix = cidr.cidr.trunc();
        tx.execute(
            "INSERT INTO cidrs (address, prefix_len, name) VALUES (?1, ?2, ?3)
             ON CONFLICT DO NOTHING",
            params![ip_to_bytes(prefix.addr()), prefix.prefix_len(), cidr.name],
        )?;
    }
    Ok(())
}

/// Imports the legacy data store at `path` into the new database, if there is one. The import
/// refuses, rather than repairs, a data store that holds an invalid public key, a peer outside the
/// network or two records in conflict. The file itself is left untouched, so that earlier
/// versions still find their pins in it.
fn import_legacy(tx: &Transaction, path: &Path, network: IpNet) -> Result<(), Error> {
    let json = match std::fs::read_to_string(path) {
        Ok(json) => json,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => Err::<String, _>(e).with_path(path)?,
    };
    // An empty file was a new data store.
    if json.is_empty() {
        return Ok(());
    }
    let LegacyContents::V1 { peers, cidrs } = serde_json::from_str(&json)
        .with_context(|| format!("{} is not a valid data store", path.display()))?;
    for peer in &peers {
        ensure!(
            network.contains(&peer.ip),
            "{}: peer {} at {} is outside of the network {}",
            path.display(),
            peer.public_key,
            peer.ip,
            network,
        );
        write_peer(tx, peer).with_context(|| {
            format!(
                "{}: failed to import peer {} at {}",
                path.display(),
                peer.public_key,
                peer.ip
            )
        })?;
    }
    write_cidrs(tx, &cidrs)?;
    log::info!(
        "imported {} peers from {} into the new data store.",
        peers.len(),
        path.display()
    );

    Ok(())
}

/// The ID of the smallest of `cidrs` for which `contains` holds.
fn smallest_containing(cidrs: &[Cidr], contains: impl Fn(&IpNet) -> bool) -> Option<i64> {
    cidrs
        .iter()
        .filter(|cidr| contains(&cidr.cidr))
        .max_by_key(|cidr| cidr.cidr.prefix_len())
        .map(|cidr| cidr.id)
}

fn key_to_bytes(public_key: &str) -> Result<[u8; 32], Error> {
    Ok(Key::from_base64(public_key)?.0)
}

fn key_from_bytes(bytes: &[u8]) -> Result<String, Error> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("a public key is not 32 bytes"))?;
    Ok(Key(bytes).to_base64())
}

fn ip_to_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

fn ip_from_bytes(bytes: &[u8]) -> Result<IpAddr, Error> {
    if let Ok(octets) = <[u8; 4]>::try_from(bytes) {
        Ok(Ipv4Addr::from(octets).into())
    } else if let Ok(octets) = <[u8; 16]>::try_from(bytes) {
        Ok(Ipv6Addr::from(octets).into())
    } else {
        bail!("an address is neither 4 nor 16 bytes")
    }
}

fn prefix_from_row(address: Vec<u8>, prefix_len: u8) -> Result<IpNet, Error> {
    Ok(IpNet::new(ip_from_bytes(&address)?, prefix_len)?)
}

/// The coordinator and this client, as the interface config introduces them. Each record is named
/// by its public key, and has no CIDR.
fn introduced_peers(config: &InterfaceConfig) -> Result<[Peer; 2], Error> {
    let introduced = |ip, public_key: String, endpoint| Peer {
        id: UNKNOWN_ID,
        contents: PeerContents {
            name: Hostname::placeholder(&public_key),
            ip,
            cidr_id: UNKNOWN_ID,
            public_key,
            endpoint,
            persistent_keepalive_interval: None,
            is_admin: false,
            is_disabled: false,
            is_redeemed: true,
            invite_expires: None,
            candidates: vec![],
        },
    };
    // Public keys are compared in their canonical encoding, as a state's are deserialized.
    let server_key = Key::from_base64(&config.server.public_key)?.to_base64();
    let own_key = Key::from_base64(&config.interface.private_key)?
        .get_public()
        .to_base64();
    Ok([
        introduced(
            config.server.internal_endpoint.ip(),
            server_key,
            Some(config.server.external_endpoint.clone()),
        ),
        introduced(config.interface.address.addr(), own_key, None),
    ])
}

/// How a peer relates to the (IP, PublicKey) pins of the peers of a [`PeersIndex`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinStatus {
    /// Neither its IP nor its public key belongs to a peer.
    New,
    /// Its IP and its public key belong to the same peer.
    Unchanged,
    /// Its IP belongs to a peer with a different public key.
    ConflictingKey,
    /// Its public key belongs to a peer at a different IP.
    ConflictingIp,
}

/// Peers indexed by IP and by public key, in which each IP and each public key belongs to at
/// most one peer. The index exists only at runtime.
#[derive(Debug, Default)]
struct PeersIndex {
    peers: Vec<Peer>,
    by_ip: HashMap<IpAddr, usize>,
    by_public_key: HashMap<String, usize>,
}

impl PeersIndex {
    /// How `peer` relates to the pins of the peers of the index.
    fn check(&self, peer: &Peer) -> PinStatus {
        match (
            self.by_ip.get(&peer.ip),
            self.by_public_key.get(&peer.public_key),
        ) {
            (None, None) => PinStatus::New,
            (Some(by_ip), Some(by_public_key)) if by_ip == by_public_key => PinStatus::Unchanged,
            (Some(_), _) => PinStatus::ConflictingKey,
            (None, Some(_)) => PinStatus::ConflictingIp,
        }
    }

    /// Adds `peer` if it is new, or replaces the peer with its IP and public key if it is
    /// unchanged. A conflicting peer is not inserted. Returns how `peer` related to the pins.
    fn insert(&mut self, peer: Peer) -> PinStatus {
        let status = self.check(&peer);
        match status {
            PinStatus::New => {
                let index = self.peers.len();
                self.by_ip.insert(peer.ip, index);
                self.by_public_key.insert(peer.public_key.clone(), index);
                self.peers.push(peer);
            },
            PinStatus::Unchanged => {
                let index = self.by_ip[&peer.ip];
                self.peers[index] = peer;
            },
            PinStatus::ConflictingKey | PinStatus::ConflictingIp => {},
        }

        status
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innernet_shared::{Cidr, CidrContents, Peer, PeerContents};
    use once_cell::sync::Lazy;
    static BASE_PEERS: Lazy<Vec<Peer>> = Lazy::new(|| {
        vec![Peer {
            id: 0,
            contents: PeerContents {
                name: "blah".parse().unwrap(),
                ip: "10.0.0.1".parse().unwrap(),
                cidr_id: 1,
                public_key: "dz0/Fjmj7oRBSGxgWXSkE3n9R3k19kJOj127FzJZ81g=".to_string(),
                endpoint: None,
                is_admin: false,
                is_disabled: false,
                is_redeemed: true,
                persistent_keepalive_interval: None,
                invite_expires: None,
                candidates: vec![],
            },
        }]
    });
    static BASE_CIDRS: Lazy<Vec<Cidr>> = Lazy::new(|| {
        vec![Cidr {
            id: 1,
            contents: CidrContents {
                name: "cidr".to_string(),
                cidr: "10.0.0.0/24".parse().unwrap(),
                parent: None,
            },
        }]
    });

    static NETWORK: Lazy<IpNet> = Lazy::new(|| "10.0.0.0/16".parse().unwrap());

    fn db_path(dir: &Path) -> PathBuf {
        dir.join("wg0.db")
    }

    fn legacy_path(dir: &Path) -> PathBuf {
        dir.join("wg0.json")
    }

    fn open(dir: &Path, create: bool) -> Result<DataStore, Error> {
        DataStore::open_with_paths(&db_path(dir), &legacy_path(dir), *NETWORK, create)
    }

    /// Writes a legacy data store of `peers` and `cidrs`, as earlier versions wrote it.
    fn write_legacy(dir: &Path, peers: &[Peer], cidrs: &[Cidr]) {
        let contents = serde_json::json!({ "version": "1", "peers": peers, "cidrs": cidrs });
        std::fs::write(
            legacy_path(dir),
            serde_json::to_string_pretty(&contents).unwrap(),
        )
        .unwrap();
    }

    fn setup_basic_store(dir: &Path) {
        let mut store = open(dir, true).unwrap();

        println!("{store:?}");
        assert_eq!(0, store.peers().len());
        assert_eq!(0, store.cidrs().len());

        store
            .update(&State {
                peers: BASE_PEERS.to_owned(),
                cidrs: BASE_CIDRS.to_owned(),
                invalid_peer_keys: vec![],
            })
            .unwrap();
    }

    fn disabled(peers: &[Peer]) -> Vec<Peer> {
        peers
            .iter()
            .cloned()
            .map(|mut p| {
                p.contents.is_disabled = true;
                p
            })
            .collect()
    }

    #[test]
    fn test_sanity() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let store = open(dir.path(), false).unwrap();
        assert_eq!(store.peers(), &*BASE_PEERS);
        assert_eq!(store.cidrs(), &*BASE_CIDRS);
    }

    #[test]
    fn test_pinning() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store = open(dir.path(), false).unwrap();

        // Should work, since peer is unmodified.
        assert!(store.update_peers(&BASE_PEERS).is_empty());
        assert_eq!(store.peers(), &*BASE_PEERS);

        let mut modified = BASE_PEERS.clone();
        modified[0].contents.public_key =
            "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes=".to_string();

        // Should NOT work, since the IP is pinned to another public key. The pinned peer is
        // disabled, since it is absent from the update.
        assert_eq!(
            store.records.peers.check(&modified[0]),
            PinStatus::ConflictingKey
        );
        assert_eq!(store.update_peers(&modified).len(), 1);
        assert_eq!(store.peers(), &disabled(&BASE_PEERS)[..]);
    }

    #[test]
    fn test_pinning_public_key_to_ip() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store = open(dir.path(), false).unwrap();

        // The same public key reported at another IP is dropped from the update, and the pinned
        // peer, which was reported, keeps its record unchanged.
        let mut moved = BASE_PEERS.clone();
        moved[0].contents.ip = "10.0.0.2".parse().unwrap();
        assert_eq!(
            store.records.peers.check(&moved[0]),
            PinStatus::ConflictingIp
        );
        assert_eq!(store.update_peers(&moved).len(), 1);
        assert_eq!(store.peers(), &*BASE_PEERS);

        // Other changes to a pinned peer are applied in place, and new peers are added.
        let mut updated = BASE_PEERS.clone();
        updated[0].contents.name = "renamed".parse().unwrap();
        let mut new_peer = BASE_PEERS[0].clone();
        new_peer.contents.ip = "10.0.0.2".parse().unwrap();
        new_peer.contents.public_key = "HX6Se15qwliiWM7l3iCVAtK+FXNfHRFeEq8UFRK8BBk=".to_string();
        updated.push(new_peer);
        assert!(store.update_peers(&updated).is_empty());
        assert_eq!(store.peers(), &updated[..]);
    }

    #[test]
    fn test_created_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        open(dir.path(), true).unwrap();
        let mode = std::fs::metadata(db_path(dir.path()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode & 0o077, 0);
    }

    #[test]
    fn test_missing_store() {
        // Without a database or a legacy data store, only creating opens one.
        let dir = tempfile::tempdir().unwrap();
        assert!(open(dir.path(), false).is_err());
        assert!(!db_path(dir.path()).exists());
        assert!(open(dir.path(), true).unwrap().peers().is_empty());
    }

    #[test]
    fn test_invalid_legacy_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = legacy_path(dir.path());

        // An empty file is a new data store.
        std::fs::write(&path, "").unwrap();
        assert!(open(dir.path(), false).unwrap().peers().is_empty());

        // A file that fails to parse is refused, even if it is only whitespace, and the database
        // is left without a schema, so that the import is tried again on the next open.
        for invalid in [r#"{"version": "1", "peers": [{"#, "\n"] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(legacy_path(dir.path()), invalid).unwrap();
            assert!(open(dir.path(), false).is_err());
            let conn = Connection::open(db_path(dir.path())).unwrap();
            let version: i64 = conn
                .pragma_query_value(None, "user_version", |r| r.get(0))
                .unwrap();
            assert_eq!(version, 0);
            let tables: i64 = conn
                .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
                .unwrap();
            assert_eq!(tables, 0);

            write_legacy(dir.path(), &BASE_PEERS, &BASE_CIDRS);
            assert_eq!(open(dir.path(), false).unwrap().peers(), &*BASE_PEERS);
        }
    }

    #[test]
    fn test_invalid_name() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store = open(dir.path(), false).unwrap();

        // A peer whose name isn't a valid hostname is dropped, and the other peers are kept.
        let mut invalid = BASE_PEERS.clone();
        let mut new_peer = BASE_PEERS[0].clone();
        new_peer.contents.ip = "10.0.0.2".parse().unwrap();
        new_peer.contents.public_key = "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes=".to_string();
        new_peer.contents.name = Hostname::unchecked("peer\n10.0.0.1 example.com".into());
        invalid.push(new_peer);
        let dropped = store.update_peers(&invalid);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].0, &invalid[1]);
        assert_eq!(store.peers(), &*BASE_PEERS);

        // A stored peer renamed to an invalid name keeps its record, and stays enabled.
        let mut renamed = BASE_PEERS.clone();
        renamed[0].contents.name = Hostname::unchecked("Blah".into());
        assert_eq!(store.update_peers(&renamed).len(), 1);
        assert_eq!(store.peers(), &*BASE_PEERS);
    }

    #[test]
    fn test_network() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store = open(dir.path(), false).unwrap();

        // A new peer outside the network is dropped, and the other peers are kept.
        let mut outside = BASE_PEERS.clone();
        let mut new_peer = BASE_PEERS[0].clone();
        new_peer.contents.ip = "1.1.1.1".parse().unwrap();
        new_peer.contents.public_key = "HX6Se15qwliiWM7l3iCVAtK+FXNfHRFeEq8UFRK8BBk=".to_string();
        outside.push(new_peer);
        let dropped = store.update_peers(&outside);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].0, &outside[1]);
        assert_eq!(store.peers(), &*BASE_PEERS);

        // A legacy data store with a peer outside the network is refused.
        let dir = tempfile::tempdir().unwrap();
        write_legacy(dir.path(), &outside, &[]);
        assert!(open(dir.path(), false).is_err());
    }

    #[test]
    fn test_invalid_peers() {
        let dir = tempfile::tempdir().unwrap();

        // A legacy data store with an invalid public key is refused, while a state drops the peer
        // and keeps the others.
        let mut invalid = BASE_PEERS[0].clone();
        invalid.contents.ip = "10.0.0.2".parse().unwrap();
        invalid.contents.public_key = "abc".to_string();
        let peers = [BASE_PEERS[0].clone(), invalid];
        write_legacy(dir.path(), &peers, &[]);
        assert!(open(dir.path(), false).is_err());

        let state = State {
            peers: peers.to_vec(),
            cidrs: vec![],
            invalid_peer_keys: vec![],
        };
        let state: State = serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
        assert_eq!(state.peers, *BASE_PEERS);
        assert!(state.invalid_peer_keys.is_empty());
    }

    #[test]
    fn test_invalid_reported_peer() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store = open(dir.path(), false).unwrap();

        // A reported peer that fails to deserialize, but whose public key is valid, was still
        // reported, so the stored peer with that key keeps its record rather than being disabled.
        let mut entry = serde_json::to_value(&BASE_PEERS[0]).unwrap();
        entry["ip"] = "not an IP".into();
        let state: State =
            serde_json::from_value(serde_json::json!({ "peers": [entry], "cidrs": *BASE_CIDRS }))
                .unwrap();
        assert!(state.peers.is_empty());
        assert_eq!(state.invalid_peer_keys, [BASE_PEERS[0].public_key.clone()]);
        assert!(store.update(&state).unwrap().is_empty());
        assert_eq!(store.peers(), &*BASE_PEERS);

        // A peer that isn't reported at all is disabled.
        let state: State =
            serde_json::from_value(serde_json::json!({ "peers": [], "cidrs": *BASE_CIDRS }))
                .unwrap();
        store.update(&state).unwrap();
        assert_eq!(store.peers(), &disabled(&BASE_PEERS)[..]);
    }

    #[test]
    fn test_first_wins() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store = open(dir.path(), false).unwrap();

        // Of two new peers at the same IP, the first is kept and the second dropped.
        let mut same_ip = BASE_PEERS.clone();
        let mut new_peer = BASE_PEERS[0].clone();
        new_peer.contents.ip = "10.0.0.2".parse().unwrap();
        new_peer.contents.public_key = "HX6Se15qwliiWM7l3iCVAtK+FXNfHRFeEq8UFRK8BBk=".to_string();
        same_ip.push(new_peer.clone());
        new_peer.contents.public_key = "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes=".to_string();
        same_ip.push(new_peer);
        let dropped = store.update_peers(&same_ip);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].0, &same_ip[2]);
        assert_eq!(store.peers(), &same_ip[..2]);

        // Of two new peers with the same public key, the first is kept and the second dropped.
        let mut same_public_key = same_ip[..2].to_vec();
        let mut new_peer = BASE_PEERS[0].clone();
        new_peer.contents.ip = "10.0.0.3".parse().unwrap();
        new_peer.contents.public_key = "9fNiSxgLIPEqRALrIpaK2a77aiPz/CZCpQVQtF7o4v0=".to_string();
        same_public_key.push(new_peer.clone());
        new_peer.contents.ip = "10.0.0.4".parse().unwrap();
        same_public_key.push(new_peer);
        let dropped = store.update_peers(&same_public_key);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].0, &same_public_key[3]);
        assert_eq!(store.peers(), &same_public_key[..3]);
    }

    #[test]
    fn test_conflicting_legacy_peers() {
        // A legacy data store holding two records of a peer at different IPs, or two peers at one
        // IP, is refused.
        let mut moved = BASE_PEERS[0].clone();
        moved.contents.ip = "10.0.0.2".parse().unwrap();
        let mut replaced = BASE_PEERS[0].clone();
        replaced.contents.public_key = "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes=".to_string();
        for conflicting in [moved, replaced] {
            let dir = tempfile::tempdir().unwrap();
            write_legacy(dir.path(), &[BASE_PEERS[0].clone(), conflicting], &[]);
            assert!(open(dir.path(), false).is_err());
        }
    }

    #[test]
    fn test_peer_persistence() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store = open(dir.path(), false).unwrap();

        // Should work, since peer is unmodified.
        assert!(store.update_peers(&[]).is_empty());
        assert_eq!(store.peers(), &disabled(&BASE_PEERS)[..]);
    }

    /// The coordinator of [`introducing_config`], as the server reports it.
    static COORDINATOR: Lazy<Peer> = Lazy::new(|| {
        let mut coordinator = BASE_PEERS[0].clone();
        coordinator.contents.public_key =
            "dz0/Fjmj7oRBSGxgWXSkE3n9R3k19kJOj127FzJZ81g=".to_string();
        coordinator
    });

    fn introducing_config(own_key: &wireguard_control::KeyPair) -> InterfaceConfig {
        serde_json::from_value(serde_json::json!({
            "interface": {
                "network-name": "wg0",
                "address": "10.0.0.2/16",
                "private-key": own_key.private.to_base64(),
            },
            "server": {
                "public-key": COORDINATOR.public_key,
                "external-endpoint": "203.0.113.1:51820",
                "internal-endpoint": "10.0.0.1:51820",
            },
        }))
        .unwrap()
    }

    #[test]
    fn test_introduce() {
        let dir = tempfile::tempdir().unwrap();
        let own_key = wireguard_control::KeyPair::generate();
        let config = introducing_config(&own_key);

        // A new data store pins the coordinator and this client, named by their public keys.
        let mut store = open(dir.path(), true).unwrap();
        store.introduce(&config).unwrap();
        let peers = store.peers();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].ip, COORDINATOR.ip);
        assert_eq!(peers[0].public_key, COORDINATOR.public_key);
        assert_eq!(*peers[0].name, COORDINATOR.public_key);
        assert_eq!(peers[1].ip, "10.0.0.2".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(peers[1].public_key, own_key.public.to_base64());
        assert!(!Hostname::is_valid(&peers[0].name));

        // The coordinator can't be reported at another IP, nor another key at its IP.
        let mut moved = [COORDINATOR.clone()];
        moved[0].contents.ip = "10.0.0.3".parse().unwrap();
        assert_eq!(store.update_peers(&moved).len(), 1);
        let mut replaced = [COORDINATOR.clone()];
        replaced[0].contents.public_key =
            "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes=".to_string();
        assert_eq!(store.update_peers(&replaced).len(), 1);

        // The server's record of the coordinator replaces the introduced one. The data store
        // holds no CIDRs, so the coordinator has none.
        assert!(store
            .update_peers(std::slice::from_ref(&*COORDINATOR))
            .is_empty());
        let mut expected = COORDINATOR.clone();
        expected.contents.cidr_id = UNKNOWN_ID;
        assert_eq!(store.peers()[0], expected);
        assert_eq!(store.peers().len(), 2);

        // Only a new data store is introduced.
        assert!(store.introduce(&config).is_err());
        assert_eq!(store.peers().len(), 2);
    }

    /// Peers with endpoints of every shape, in a network of each family.
    fn varied_peers() -> Vec<Peer> {
        let mut v4 = BASE_PEERS[0].clone();
        v4.contents.endpoint = Some("203.0.113.1:51820".parse().unwrap());
        v4.contents.candidates = vec![
            "192.168.1.2:51820".parse().unwrap(),
            "[2001:db8::1]:4000".parse().unwrap(),
            "peer.example.com:1".parse().unwrap(),
        ];
        v4.contents.persistent_keepalive_interval = Some(25);
        v4.contents.invite_expires = Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000));
        v4.contents.is_admin = true;
        let mut domain = BASE_PEERS[0].clone();
        domain.contents.ip = "10.0.1.1".parse().unwrap();
        domain.contents.public_key = "HX6Se15qwliiWM7l3iCVAtK+FXNfHRFeEq8UFRK8BBk=".to_string();
        domain.contents.endpoint = Some("vpn.example.com:51820".parse().unwrap());
        domain.contents.cidr_id = 2;
        vec![v4, domain]
    }

    fn varied_cidrs() -> Vec<Cidr> {
        let cidr = |id, name: &str, cidr: &str, parent| Cidr {
            id,
            contents: CidrContents {
                name: name.to_string(),
                cidr: cidr.parse().unwrap(),
                parent,
            },
        };
        vec![
            cidr(1, "cidr", "10.0.0.0/24", Some(3)),
            cidr(2, "other", "10.0.1.0/24", Some(3)),
            cidr(3, "root", "10.0.0.0/16", None),
        ]
    }

    #[test]
    fn test_round_trip() {
        // Every field survives the database, the CIDRs are numbered by prefix, each with the
        // smallest CIDR containing it as its parent, and each peer with the smallest CIDR
        // containing its IP.
        let dir = tempfile::tempdir().unwrap();
        let mut store = open(dir.path(), true).unwrap();
        let mut cidrs = varied_cidrs();
        cidrs.reverse();
        store
            .update(&State {
                peers: varied_peers(),
                cidrs,
                invalid_peer_keys: vec![],
            })
            .unwrap();
        let expected_cidrs = {
            let mut cidrs = varied_cidrs();
            // The CIDRs are ordered by address, then prefix length.
            cidrs.sort_by_key(|c| (c.cidr.addr(), c.cidr.prefix_len()));
            for (i, cidr) in cidrs.iter_mut().enumerate() {
                cidr.id = i as i64 + 1;
            }
            cidrs[1].contents.parent = Some(1);
            cidrs[2].contents.parent = Some(1);
            cidrs
        };
        let mut expected_peers = varied_peers();
        expected_peers[0].contents.cidr_id = 2;
        expected_peers[1].contents.cidr_id = 3;
        assert_eq!(store.cidrs(), &expected_cidrs[..]);
        assert_eq!(store.peers(), &expected_peers[..]);

        let store = open(dir.path(), false).unwrap();
        assert_eq!(store.cidrs(), &expected_cidrs[..]);
        assert_eq!(store.peers(), &expected_peers[..]);
    }

    #[test]
    fn test_ipv6_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let network: IpNet = "fd00::/64".parse().unwrap();
        let mut peer = BASE_PEERS[0].clone();
        peer.contents.ip = "fd00::1".parse().unwrap();
        peer.contents.cidr_id = UNKNOWN_ID;
        peer.contents.endpoint = Some("[::ffff:203.0.113.1]:51820".parse().unwrap());
        let mut store = DataStore::open_with_paths(
            &db_path(dir.path()),
            &legacy_path(dir.path()),
            network,
            true,
        )
        .unwrap();
        assert!(store.update_peers(std::slice::from_ref(&peer)).is_empty());
        assert_eq!(store.peers(), std::slice::from_ref(&peer));
    }

    #[test]
    fn test_import_legacy() {
        // A legacy data store is imported into the new database, without its server IDs, and the
        // file is left untouched.
        let dir = tempfile::tempdir().unwrap();
        let mut legacy_peers = varied_peers();
        legacy_peers[0].id = 7;
        write_legacy(dir.path(), &legacy_peers, &varied_cidrs());
        let legacy = std::fs::read(legacy_path(dir.path())).unwrap();
        let mut store = open(dir.path(), false).unwrap();
        let mut expected_peers = varied_peers();
        expected_peers[0].contents.cidr_id = 2;
        expected_peers[1].contents.cidr_id = 3;
        assert_eq!(store.peers(), &expected_peers[..]);
        assert_eq!(store.cidrs().len(), 3);

        // From then on the database is the data store, and the legacy one is never read again.
        store.update_peers(&[]);
        write_legacy(dir.path(), &[], &[]);
        let store = open(dir.path(), false).unwrap();
        assert_eq!(store.peers(), &disabled(&expected_peers)[..]);
        write_legacy(dir.path(), &legacy_peers, &varied_cidrs());
        assert_eq!(std::fs::read(legacy_path(dir.path())).unwrap(), legacy);
    }

    #[test]
    fn test_connection_settings() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(dir.path(), true).unwrap();
        let conn = &store.conn;
        let pragma = |name| -> i64 { conn.pragma_query_value(None, name, |r| r.get(0)).unwrap() };
        assert_eq!(pragma("foreign_keys"), 1);
        assert_eq!(pragma("recursive_triggers"), 1);
        assert_eq!(pragma("trusted_schema"), 0);
        assert_eq!(pragma("busy_timeout"), BUSY_TIMEOUT.as_millis() as i64);
        assert_eq!(pragma("application_id"), APPLICATION_ID as i64);
        assert_eq!(pragma("user_version"), SCHEMA_VERSION);
        assert!(conn.db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE).unwrap());
        assert!(!conn.db_config(DbConfig::SQLITE_DBCONFIG_DQS_DML).unwrap());
        assert!(!conn.db_config(DbConfig::SQLITE_DBCONFIG_DQS_DDL).unwrap());

        // Every table is strict.
        let lax: i64 = conn
            .query_row(
                "SELECT count(*) FROM pragma_table_list WHERE schema = 'main'
                 AND name NOT LIKE 'sqlite_%' AND strict = 0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(lax, 0);
    }

    #[test]
    fn test_kinds_match_tables() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(dir.path(), true).unwrap();
        let kinds = |table: &str| -> Vec<(i64, String)> {
            let mut stmt = store
                .conn
                .prepare(&format!("SELECT kind, name FROM {table} ORDER BY kind"))
                .unwrap();
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        let expected = |all: &[(i64, &str)]| -> Vec<(i64, String)> {
            all.iter().map(|(k, n)| (*k, n.to_string())).collect()
        };
        assert_eq!(
            kinds("pin_kinds"),
            expected(
                &PinKind::ALL
                    .iter()
                    .map(|(k, n)| (*k as i64, *n))
                    .collect::<Vec<_>>()
            )
        );
        assert_eq!(
            kinds("endpoint_kinds"),
            expected(
                &EndpointKind::ALL
                    .iter()
                    .map(|(k, n)| (*k as i64, *n))
                    .collect::<Vec<_>>()
            )
        );
    }

    #[test]
    fn test_newer_schema() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let set = |version: i64, min_reader_version: i64| {
            let conn = Connection::open(db_path(dir.path())).unwrap();
            conn.pragma_update(None, "user_version", version).unwrap();
            conn.execute(
                "UPDATE meta SET value = ?1 WHERE key = 'min_reader_version'",
                [min_reader_version],
            )
            .unwrap();
        };

        // A newer database that this version can still read is opened, without migrating it.
        set(SCHEMA_VERSION + 1, SCHEMA_VERSION);
        assert_eq!(open(dir.path(), false).unwrap().peers(), &*BASE_PEERS);
        let conn = Connection::open(db_path(dir.path())).unwrap();
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION + 1);

        // One that needs a newer reader is refused.
        set(SCHEMA_VERSION + 1, SCHEMA_VERSION + 1);
        assert!(open(dir.path(), false).is_err());
    }

    #[test]
    fn test_foreign_file() {
        // A database of something else is refused.
        let dir = tempfile::tempdir().unwrap();
        let conn = Connection::open(db_path(dir.path())).unwrap();
        conn.execute_batch("CREATE TABLE other (x); PRAGMA user_version = 1;")
            .unwrap();
        assert!(open(dir.path(), false).is_err());
    }

    #[test]
    fn test_update_sees_other_writers() {
        // Two handles on one data store, as a CLI command and a running daemon have. Each update
        // works on what the database holds when it starts, not on what its handle last loaded.
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut daemon = open(dir.path(), false).unwrap();
        let mut cli = open(dir.path(), false).unwrap();

        let mut pinned = BASE_PEERS[0].clone();
        pinned.contents.ip = "10.0.0.2".parse().unwrap();
        pinned.contents.public_key = "HX6Se15qwliiWM7l3iCVAtK+FXNfHRFeEq8UFRK8BBk=".to_string();
        let mut with_pinned = BASE_PEERS.clone();
        with_pinned.push(pinned.clone());
        assert!(cli.update_peers(&with_pinned).is_empty());

        // The daemon's handle predates the pin, but its update still keeps another key from the
        // pinned IP, and disables the pinned peer, which its state leaves out.
        let mut impostor = pinned.clone();
        impostor.contents.public_key = "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes=".to_string();
        let mut with_impostor = BASE_PEERS.clone();
        with_impostor.push(impostor);
        assert_eq!(daemon.update_peers(&with_impostor).len(), 1);
        let mut expected = BASE_PEERS.clone();
        expected.extend(disabled(&[pinned]));
        assert_eq!(daemon.peers(), &expected[..]);
        assert_eq!(open(dir.path(), false).unwrap().peers(), &expected[..]);
    }

    #[test]
    fn test_concurrent_writers() {
        // Concurrent updates wait for each other rather than failing as busy.
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    let mut store = open(dir.path(), false).unwrap();
                    for i in 0..25 {
                        let mut peers = BASE_PEERS.clone();
                        peers[0].contents.is_admin = i % 2 == 0;
                        let state = State {
                            peers,
                            cidrs: BASE_CIDRS.clone(),
                            invalid_peer_keys: vec![],
                        };
                        assert!(store.update(&state).unwrap().is_empty());
                    }
                });
            }
        });
        assert_eq!(open(dir.path(), false).unwrap().peers().len(), 1);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn test_pins_enforced_by_database() {
        // The database refuses to move, change or delete a pin, or to delete a peer, including by
        // REPLACE.
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let store = open(dir.path(), false).unwrap();
        let key = key_to_bytes(&BASE_PEERS[0].public_key).unwrap();
        let other = key_to_bytes("HX6Se15qwliiWM7l3iCVAtK+FXNfHRFeEq8UFRK8BBk=").unwrap();
        let conn = &store.conn;
        conn.execute_batch(&format!(
            "INSERT INTO peers VALUES (x'{other}', 'other', 0, 0, 1, NULL, NULL);
             INSERT INTO prefix_pins VALUES (x'0a000002', 32, x'{other}', 0);",
            other = hex(&other),
        ))
        .unwrap();
        for refused in [
            "UPDATE prefix_pins SET kind = kind",
            "UPDATE prefix_pins SET address = x'0a000003' WHERE public_key = x'{key}'",
            "UPDATE prefix_pins SET public_key = x'{other}' WHERE public_key = x'{key}'",
            "INSERT OR REPLACE INTO prefix_pins VALUES (x'0a000001', 32, x'{other}', 0)",
            "INSERT INTO prefix_pins VALUES (x'0a000001', 32, x'{other}', 0)
             ON CONFLICT DO UPDATE SET public_key = excluded.public_key",
            "INSERT INTO prefix_pins VALUES (x'0a000003', 32, x'{key}', 0)",
            "INSERT INTO prefix_pins VALUES (x'0a000003', 24, x'{other}', 0)",
            "DELETE FROM prefix_pins WHERE public_key = x'{key}'",
            "DELETE FROM peers WHERE public_key = x'{key}'",
            "INSERT OR REPLACE INTO peers VALUES (x'{key}', 'blah', 0, 0, 1, NULL, NULL)",
        ] {
            let refused = refused
                .replace("{key}", &hex(&key))
                .replace("{other}", &hex(&other));
            assert!(
                conn.execute_batch(&refused).is_err(),
                "{refused} was accepted"
            );
        }
        drop(store);
        assert_eq!(open(dir.path(), false).unwrap().peers()[0], BASE_PEERS[0]);
    }
}
