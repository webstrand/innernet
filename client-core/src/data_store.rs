use anyhow::{bail, ensure, Context as _, Error};
use innernet_node::{db::CreateHook, store, Store};
use innernet_shared::{
    ensure_dirs_exist, interface_config::InterfaceConfig, Cidr, IoErrorContext, LegacyCidr,
    LegacyPeer, PeerContents, Prefix, State,
};
use ipnet::IpNet;
use rusqlite::{params, Connection, OptionalExtension as _};
use serde::Deserialize;
use std::{
    fs::OpenOptions,
    io,
    net::IpAddr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};
use wireguard_control::{InterfaceName, Key};

/// The peers and CIDRs that the coordinator reported, kept in the node's database, with the
/// delegations of each peer pinned to its public key.
///
/// The database is stored at [`Self::get_path()`]. A data store from before SQLite, at
/// [`Self::get_legacy_path()`], is imported when the database is created, and left untouched.
#[derive(Debug)]
pub struct DataStore {
    store: Store,
    /// The network of the interface, from its config. It is not persisted.
    network: Network,
}

/// The network of a data store, as the interface config describes it, against which the data
/// store checks the peers that the coordinator reports.
#[derive(Clone, Debug)]
struct Network {
    /// The prefix of the network, outside which no peer lies.
    prefix: IpNet,
    /// The public key of this client, and the source address of its interface, which its
    /// delegations should hold.
    own: Option<(String, IpAddr)>,
}

impl Network {
    /// The network that `config` describes. Public keys are in their canonical encoding, as a
    /// state's are deserialized.
    fn from_config(config: &InterfaceConfig) -> Result<Self, Error> {
        let own_key = Key::from_base64(&config.interface.private_key)?
            .get_public()
            .to_base64();
        Ok(Self {
            prefix: config.interface.address.trunc(),
            own: Some((own_key, config.interface.address.addr())),
        })
    }
}

/// The data store of the JSON file of earlier versions, whose peers and CIDRs have the IDs that
/// the server gave them.
#[derive(Debug, Deserialize)]
#[serde(tag = "version")]
enum LegacyContents {
    #[serde(rename = "1")]
    V1 {
        peers: Vec<LegacyPeer>,
        cidrs: Vec<LegacyCidr>,
    },
}

impl DataStore {
    fn open_with_paths(
        path: &Path,
        legacy_path: &Path,
        network: Network,
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

        let legacy_path = legacy_path.to_owned();
        let import: CreateHook = Arc::new(move |scope| import_legacy(scope, &legacy_path));
        let store = Store::open(path, network.prefix, Some(import))
            .with_context(|| format!("failed to open the data store {}", path.display()))?;
        Ok(Self { store, network })
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
            Network::from_config(config)?,
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

    /// Create the data store residing at "`data_dir`/`interface`.db", whose peers must lie within
    /// the network of `config`, failing if `interface` has a data store already, of this version
    /// or an earlier one. A data store that fails to open once created is removed.
    pub fn create_new(
        data_dir: &Path,
        interface: &InterfaceName,
        config: &InterfaceConfig,
    ) -> Result<Self, Error> {
        let network = Network::from_config(config)?;
        ensure_dirs_exist(&[data_dir])?;
        let [path, _, legacy_path] = Self::get_paths(data_dir, interface);
        if legacy_path.try_exists().with_path(&legacy_path)? {
            bail!("the data store {} exists already", legacy_path.display());
        }
        // The file is created with its mode in the same call that fails if it exists.
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .with_path(&path)?;
        Self::open_with_paths(&path, &legacy_path, network, false).inspect_err(|_| {
            if let Err(e) = Self::remove_files(data_dir, interface) {
                log::warn!("failed to remove the data store {}: {e:#}", path.display());
            }
        })
    }

    /// Removes the data store of `interface`, which [`DataStore::create_new`] created, with its
    /// journal.
    pub fn discard(self, data_dir: &Path, interface: &InterfaceName) -> Result<(), Error> {
        drop(self);
        Self::remove_files(data_dir, interface)
    }

    /// Removes the database of `interface` and its journal, whichever exist.
    fn remove_files(data_dir: &Path, interface: &InterfaceName) -> Result<(), Error> {
        let [path, journal, _] = Self::get_paths(data_dir, interface);
        for path in [path, journal] {
            match std::fs::remove_file(&path) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e).with_path(&path)?,
                _ => {},
            }
        }
        Ok(())
    }

    /// The node's store of the data store.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Records the coordinator and this client as the interface config introduces them, when an
    /// invitation is redeemed, so the data store must be new.
    ///
    /// The invitation, which produced the interface config, is the authority on both, so their
    /// delegations are pinned to their keys before the coordinator reports anything: the
    /// coordinator's internal address, and `delegations`, those that the invitation offers this
    /// client. Each record has no name until a fetch replaces it with the coordinator's record.
    pub fn introduce(
        &mut self,
        config: &InterfaceConfig,
        delegations: &[Prefix],
    ) -> Result<(), Error> {
        let [coordinator, own] = introduced_peers(config, delegations)?;
        let tx = self.store.transaction()?;
        if !store::load_peers(&tx)?.is_empty() {
            bail!("the data store to introduce peers into is not new.");
        }
        for peer in [&coordinator, &own] {
            store::write_peer(&tx, &store::key_to_bytes(&peer.public_key)?, peer)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Merges the peers of `state` into the data store and replaces its CIDRs with those of
    /// `state`, in one transaction. Returns the peers of `state` that were dropped, each with the
    /// reason that the node refused it, and warns if the record of this client no longer holds the
    /// source address of its interface.
    ///
    /// A peer that is absent from `state` is disabled rather than deleted, so that its delegations
    /// stay pinned: the coordinator leaves disabled peers out of the state. A dropped peer was
    /// reported, so the stored peer with its key keeps its record unchanged, as does one whose
    /// record failed to deserialize.
    pub fn update<'a>(
        &mut self,
        state: &'a State,
    ) -> Result<Vec<(&'a PeerContents, Error)>, Error> {
        let tx = self.store.transaction()?;
        let reported: Vec<&PeerContents> = state.peers.iter().collect();
        let decided = tx.scope().accept(&reported)?;
        let dropped = state
            .peers
            .iter()
            .zip(decided)
            .filter_map(|(peer, decided)| decided.err().map(|refusal| (peer, refusal.into())))
            .collect();
        for stored in store::load_peers(&tx)? {
            let reported = state
                .peers
                .iter()
                .any(|peer| peer.public_key == stored.public_key)
                || state.invalid_peer_keys.contains(&stored.public_key);
            if !reported && !stored.is_disabled {
                tx.execute(
                    "UPDATE peers SET is_disabled = 1 WHERE public_key = ?1",
                    [store::key_to_bytes(&stored.public_key)?],
                )?;
            }
        }
        write_cidrs(&tx, &state.cidrs)?;
        tx.commit()?;
        self.warn_if_own_address_lost()?;
        Ok(dropped)
    }

    /// Warns if the record of this client no longer holds the source address of its interface,
    /// which the coordinator has then withdrawn.
    fn warn_if_own_address_lost(&self) -> Result<(), Error> {
        let Some((own_key, address)) = &self.network.own else {
            return Ok(());
        };
        let own = store::load_peer(&self.store, &store::key_to_bytes(own_key)?)?;
        if own.is_some_and(|own| !own.holds(*address)) {
            log::warn!(
                "the coordinator no longer delegates this client's address {address} to it, so \
                 other peers no longer route traffic for that address here."
            );
        }
        Ok(())
    }

    #[cfg(test)]
    fn update_peers<'a>(
        &mut self,
        new_peers: &'a [PeerContents],
    ) -> Vec<(&'a PeerContents, Error)> {
        let state = State {
            peers: new_peers.to_vec(),
            cidrs: self.cidrs().unwrap(),
            observed_endpoint: None,
            invalid_peer_keys: vec![],
        };
        let dropped: Vec<usize> = self
            .update(&state)
            .unwrap()
            .into_iter()
            .map(|(peer, _)| state.peers.iter().position(|p| p == peer).unwrap())
            .collect();
        dropped
            .into_iter()
            .map(|i| (&new_peers[i], anyhow::anyhow!("dropped")))
            .collect()
    }

    /// The peers, ordered by their hosts fallback addresses, those without one last.
    pub fn peers(&self) -> Result<Vec<PeerContents>, Error> {
        Ok(store::load_peers(&self.store)?)
    }

    /// Whether the peer with `public_key` is known to speak TLS.
    pub fn speaks_tls(&self, public_key: &str) -> Result<bool, Error> {
        let speaks_tls = self
            .store
            .query_row(
                "SELECT tls FROM peers WHERE public_key = ?1",
                [store::key_to_bytes(public_key)?],
                |r| r.get(0),
            )
            .optional()?;
        Ok(speaks_tls.unwrap_or(false))
    }

    /// Records for good that the peer with `public_key` speaks TLS. The peer must be recorded.
    pub fn latch_tls(&mut self, public_key: &str) -> Result<(), Error> {
        let updated = self.store.execute(
            "UPDATE peers SET tls = 1 WHERE public_key = ?1",
            [store::key_to_bytes(public_key)?],
        )?;
        ensure!(
            updated == 1,
            "no peer with the public key {public_key} is recorded"
        );
        Ok(())
    }

    /// Whether the data store records the peer with `public_key`.
    pub fn records_peer(&self, public_key: &str) -> Result<bool, Error> {
        let recorded = self
            .store
            .query_row(
                "SELECT 1 FROM peers WHERE public_key = ?1",
                [store::key_to_bytes(public_key)?],
                |_| Ok(()),
            )
            .optional()?;
        Ok(recorded.is_some())
    }

    /// The UDP port of the TLS API of the peer with `public_key`, the coordinator, which runs over
    /// QUIC at its internal address, or `None` if it is unknown.
    pub fn quic_port(&self, public_key: &str) -> Result<Option<u16>, Error> {
        let port = self
            .store
            .query_row(
                "SELECT quic_port FROM peers WHERE public_key = ?1",
                [store::key_to_bytes(public_key)?],
                |r| r.get(0),
            )
            .optional()?;
        Ok(port.flatten())
    }

    /// Records `port` as the UDP port of the TLS API of the peer with `public_key`, in place of
    /// any it had. The peer must be recorded.
    pub fn set_quic_port(&mut self, public_key: &str, port: u16) -> Result<(), Error> {
        let updated = self.store.execute(
            "UPDATE peers SET quic_port = ?2 WHERE public_key = ?1",
            params![store::key_to_bytes(public_key)?, port],
        )?;
        ensure!(
            updated == 1,
            "no peer with the public key {public_key} is recorded"
        );
        Ok(())
    }

    /// The CIDRs, ordered by prefix.
    pub fn cidrs(&self) -> Result<Vec<Cidr>, Error> {
        Ok(store::load_cidrs(&self.store)?)
    }
}

/// Replaces the CIDRs of the database with `cidrs`. They are only displayed, so of two CIDRs with
/// the same prefix or the same name, the first is kept.
fn write_cidrs(conn: &Connection, cidrs: &[Cidr]) -> Result<(), Error> {
    conn.execute("DELETE FROM cidrs", [])?;
    for cidr in cidrs {
        conn.execute(
            "INSERT INTO cidrs (address, prefix_len, name) VALUES (?1, ?2, ?3)
             ON CONFLICT DO NOTHING",
            params![
                store::ip_to_bytes(cidr.cidr.first()),
                cidr.cidr.prefix_len(),
                cidr.name
            ],
        )?;
    }
    Ok(())
}

/// Imports the legacy data store at `path` into the new database, if there is one. The import
/// refuses, rather than repairs, a data store that the node would refuse a peer of: one with an
/// invalid public key, a peer outside the network, or two records in conflict. A name that isn't
/// valid is read as no name. The file itself is left untouched, so that earlier versions still
/// find their pins in it.
fn import_legacy(scope: &innernet_node::db::Scope, path: &Path) -> Result<(), Error> {
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
    let peers: Vec<PeerContents> = peers.into_iter().map(|peer| peer.contents.into()).collect();
    let contents: Vec<&PeerContents> = peers.iter().collect();
    for (peer, decided) in peers.iter().zip(scope.accept(&contents)?) {
        if let Err(refusal) = decided {
            bail!(
                "{}: failed to import peer {} at {}: {refusal}",
                path.display(),
                peer.public_key,
                peer.display_address()
            );
        }
    }
    // A CIDR whose address has host bits set is the prefix of its network, as the server read it.
    let cidrs: Vec<Cidr> = cidrs.into_iter().map(Cidr::from).collect();
    write_cidrs(scope, &cidrs)?;
    log::info!(
        "imported {} peers from {} into the new data store.",
        peers.len(),
        path.display()
    );

    Ok(())
}

/// The coordinator, at its internal address, and this client, with the delegations
/// `delegations`, as the interface config and the invitation introduce them. Each record has no
/// name.
fn introduced_peers(
    config: &InterfaceConfig,
    delegations: &[Prefix],
) -> Result<[PeerContents; 2], Error> {
    let introduced = |delegations: Vec<Prefix>, public_key: String, endpoint| PeerContents {
        name: None,
        delegations,
        public_key,
        endpoint,
        persistent_keepalive_interval: None,
        is_admin: false,
        is_disabled: false,
        is_redeemed: true,
        invite_expires: None,
        candidates: vec![],
        announcement: None,
        allowed_ips: None,
        primary_ip: None,
    };
    // Public keys are compared in their canonical encoding, as a state's are deserialized.
    let server_key = Key::from_base64(&config.server.public_key)?.to_base64();
    let own_key = Key::from_base64(&config.interface.private_key)?
        .get_public()
        .to_base64();
    let mut delegations = delegations.to_vec();
    delegations.sort();
    Ok([
        introduced(
            vec![Prefix::host(config.server.internal_endpoint.ip())],
            server_key,
            Some(config.server.external_endpoint.clone()),
        ),
        introduced(delegations, own_key, None),
    ])
}
#[cfg(test)]
mod tests {
    use super::*;
    use innernet_node::db::{APPLICATION_ID, BUSY_TIMEOUT, SCHEMA_VERSION};
    use innernet_shared::{LegacyCidrContents, LegacyPeerContents, PeerContents};
    use once_cell::sync::Lazy;
    use rusqlite::{config::DbConfig, Connection};
    use std::time::{Duration, UNIX_EPOCH};
    static BASE_PEERS: Lazy<Vec<PeerContents>> = Lazy::new(|| {
        vec![PeerContents {
            name: Some("blah".parse().unwrap()),
            delegations: host("10.0.0.1"),
            public_key: "dz0/Fjmj7oRBSGxgWXSkE3n9R3k19kJOj127FzJZ81g=".to_string(),
            endpoint: None,
            is_admin: false,
            is_disabled: false,
            is_redeemed: true,
            persistent_keepalive_interval: None,
            invite_expires: None,
            candidates: vec![],
            announcement: None,
            allowed_ips: None,
            primary_ip: None,
        }]
    });
    static BASE_CIDRS: Lazy<Vec<Cidr>> = Lazy::new(|| {
        vec![Cidr {
            name: "cidr".to_string(),
            cidr: "10.0.0.0/24".parse().unwrap(),
        }]
    });

    static NETWORK: Lazy<IpNet> = Lazy::new(|| "10.0.0.0/16".parse().unwrap());

    /// The delegations of a peer whose only address is `ip`.
    fn host(ip: &str) -> Vec<Prefix> {
        vec![Prefix::host(ip.parse().unwrap())]
    }

    fn db_path(dir: &Path) -> PathBuf {
        dir.join("wg0.db")
    }

    fn legacy_path(dir: &Path) -> PathBuf {
        dir.join("wg0.json")
    }

    fn network(prefix: IpNet) -> Network {
        Network { prefix, own: None }
    }

    fn open(dir: &Path, create: bool) -> Result<DataStore, Error> {
        DataStore::open_with_paths(&db_path(dir), &legacy_path(dir), network(*NETWORK), create)
    }

    /// Writes a legacy data store of `peers` and `cidrs`, as earlier versions wrote it, with the
    /// server IDs of the peers and of the CIDRs, numbered from 1, each peer in the first CIDR.
    fn write_legacy(dir: &Path, peers: &[PeerContents], cidrs: &[Cidr]) {
        let peers: Vec<LegacyPeer> = peers
            .iter()
            .zip(1..)
            .map(|(contents, id)| LegacyPeer {
                id,
                contents: LegacyPeerContents::from_peer(contents, 1).unwrap(),
            })
            .collect();
        let cidrs: Vec<LegacyCidr> = cidrs
            .iter()
            .zip(1..)
            .map(|(cidr, id)| LegacyCidr {
                id,
                contents: LegacyCidrContents {
                    name: cidr.name.clone(),
                    cidr: cidr.cidr.net(),
                    parent: None,
                },
            })
            .collect();
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
        assert_eq!(0, store.peers().unwrap().len());
        assert_eq!(0, store.cidrs().unwrap().len());

        store
            .update(&State {
                peers: BASE_PEERS.to_owned(),
                cidrs: BASE_CIDRS.to_owned(),
                observed_endpoint: None,
                invalid_peer_keys: vec![],
            })
            .unwrap();
    }

    fn disabled(peers: &[PeerContents]) -> Vec<PeerContents> {
        peers
            .iter()
            .cloned()
            .map(|mut p| {
                p.is_disabled = true;
                p
            })
            .collect()
    }

    #[test]
    fn test_sanity() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let store = open(dir.path(), false).unwrap();
        assert_eq!(store.peers().unwrap(), *BASE_PEERS);
        assert_eq!(store.cidrs().unwrap(), *BASE_CIDRS);
    }

    #[test]
    fn test_pinning() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store = open(dir.path(), false).unwrap();

        // Should work, since peer is unmodified.
        assert!(store.update_peers(&BASE_PEERS).is_empty());
        assert_eq!(store.peers().unwrap(), *BASE_PEERS);

        let mut modified = BASE_PEERS.clone();
        modified[0].public_key = "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes=".to_string();

        // Should NOT work, since the IP is pinned to another public key. The pinned peer is
        // disabled, since it is absent from the update.
        assert_eq!(store.update_peers(&modified).len(), 1);
        assert_eq!(store.peers().unwrap(), disabled(&BASE_PEERS));
    }

    /// The number of rows of `table` of the peer with the public key `key`.
    fn rows_of(store: &DataStore, table: &str, key: &str) -> i64 {
        store
            .store
            .query_row(
                &format!("SELECT count(*) FROM {table} WHERE public_key = ?1"),
                [store::key_to_bytes(key).unwrap()],
                |r| r.get(0),
            )
            .unwrap()
    }

    #[test]
    fn test_reported_delegations() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store = open(dir.path(), false).unwrap();
        let other_key = "HX6Se15qwliiWM7l3iCVAtK+FXNfHRFeEq8UFRK8BBk=";
        let delegations = |prefixes: &[&str]| -> Vec<Prefix> {
            prefixes
                .iter()
                .map(|prefix| prefix.parse().unwrap())
                .collect()
        };

        // A peer's delegations are routed to it, and each is pinned to its key.
        let mut wider = BASE_PEERS.clone();
        wider[0].delegations = delegations(&["10.0.0.1/32", "10.0.0.32/28"]);
        assert!(store.update_peers(&wider).is_empty());
        assert_eq!(store.peers().unwrap(), wider);
        assert_eq!(rows_of(&store, "delegations", &BASE_PEERS[0].public_key), 2);
        assert_eq!(rows_of(&store, "prefix_pins", &BASE_PEERS[0].public_key), 2);

        // A withdrawn delegation is no longer routed, but stays pinned: another key is refused
        // within it, which drops that peer whole.
        assert!(store.update_peers(&BASE_PEERS).is_empty());
        assert_eq!(store.peers().unwrap(), *BASE_PEERS);
        assert_eq!(rows_of(&store, "prefix_pins", &BASE_PEERS[0].public_key), 2);
        let mut other = BASE_PEERS[0].clone();
        other.name = Some("other".parse().unwrap());
        other.public_key = other_key.to_string();
        other.delegations = delegations(&["10.0.0.2/32", "10.0.0.40/29"]);
        let reported = [BASE_PEERS[0].clone(), other.clone()];
        let dropped = store.update_peers(&reported);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].0, &other);
        assert_eq!(store.peers().unwrap(), *BASE_PEERS);

        // A delegation that covers a prefix pinned to another key is refused, and the stored
        // record of the peer is kept as it was.
        other.delegations = delegations(&["10.0.0.2/32"]);
        assert!(store
            .update_peers(&[BASE_PEERS[0].clone(), other.clone()])
            .is_empty());
        let mut covering = other.clone();
        covering.delegations = delegations(&["10.0.0.2/32", "10.0.0.0/30"]);
        covering.name = Some("renamed".parse().unwrap());
        let reported = [BASE_PEERS[0].clone(), covering];
        assert_eq!(store.update_peers(&reported).len(), 1);
        assert_eq!(
            store.peers().unwrap(),
            [BASE_PEERS[0].clone(), other.clone()]
        );

        // A peer may have no delegation, and is then listed last, without a CIDR.
        let mut without = other.clone();
        without.delegations = vec![];
        assert!(store
            .update_peers(&[without.clone(), BASE_PEERS[0].clone()])
            .is_empty());
        assert_eq!(
            store.peers().unwrap(),
            [BASE_PEERS[0].clone(), without.clone()]
        );
        assert_eq!(without.cidr(&store.cidrs().unwrap()), None);
        assert_eq!(
            BASE_PEERS[0].cidr(&store.cidrs().unwrap()),
            Some(&BASE_CIDRS[0])
        );
        assert_eq!(
            open(dir.path(), false).unwrap().peers().unwrap(),
            [BASE_PEERS[0].clone(), without]
        );
    }

    #[test]
    fn test_pins_accumulate() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store = open(dir.path(), false).unwrap();

        // The same public key reported at another IP moves there, and its old IP stays pinned to
        // it.
        let mut moved = BASE_PEERS.clone();
        moved[0].delegations = host("10.0.0.2");
        assert!(store.update_peers(&moved).is_empty());
        assert_eq!(store.peers().unwrap(), moved);
        let mut impostor = BASE_PEERS.clone();
        impostor[0].public_key = "HX6Se15qwliiWM7l3iCVAtK+FXNfHRFeEq8UFRK8BBk=".to_string();
        assert_eq!(store.update_peers(&impostor).len(), 1);

        // Other changes to a pinned peer are applied in place, and new peers are added.
        let mut updated = BASE_PEERS.clone();
        updated[0].name = Some("renamed".parse().unwrap());
        let mut new_peer = BASE_PEERS[0].clone();
        new_peer.name = Some("new".parse().unwrap());
        new_peer.delegations = host("10.0.0.3");
        new_peer.public_key = "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes=".to_string();
        updated.push(new_peer);
        assert!(store.update_peers(&updated).is_empty());
        assert_eq!(store.peers().unwrap(), updated);
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
    fn test_create_new() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let interface: InterfaceName = "wg0".parse().unwrap();
        let config = introducing_config(&wireguard_control::KeyPair::generate());

        // A data store is created with its mode only where none exists, and a discarded one is
        // removed.
        let store = DataStore::create_new(dir.path(), &interface, &config).unwrap();
        let mode = std::fs::metadata(db_path(dir.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
        assert!(DataStore::create_new(dir.path(), &interface, &config).is_err());
        store.discard(dir.path(), &interface).unwrap();
        assert!(!DataStore::exists(dir.path(), &interface).unwrap());

        // A data store of an earlier version counts as one.
        write_legacy(dir.path(), &BASE_PEERS, &BASE_CIDRS);
        assert!(DataStore::create_new(dir.path(), &interface, &config).is_err());
        assert!(!db_path(dir.path()).exists());
    }

    #[test]
    fn test_missing_store() {
        // Without a database or a legacy data store, only creating opens one.
        let dir = tempfile::tempdir().unwrap();
        assert!(open(dir.path(), false).is_err());
        assert!(!db_path(dir.path()).exists());
        assert!(open(dir.path(), true).unwrap().peers().unwrap().is_empty());
    }

    #[test]
    fn test_invalid_legacy_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = legacy_path(dir.path());

        // An empty file is a new data store.
        std::fs::write(&path, "").unwrap();
        assert!(open(dir.path(), false).unwrap().peers().unwrap().is_empty());

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
            assert_eq!(
                open(dir.path(), false).unwrap().peers().unwrap(),
                *BASE_PEERS
            );
        }
    }

    #[test]
    fn test_invalid_name() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store = open(dir.path(), false).unwrap();
        let state = |peers: &[serde_json::Value]| -> State {
            serde_json::from_value(serde_json::json!({ "peers": peers, "cidrs": *BASE_CIDRS }))
                .unwrap()
        };

        // A peer whose name isn't a valid hostname is recorded as a peer without a name.
        let mut new_peer = BASE_PEERS[0].clone();
        new_peer.delegations = host("10.0.0.2");
        new_peer.public_key = "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes=".to_string();
        let mut invalid = serde_json::to_value(&new_peer).unwrap();
        invalid["name"] = "peer\n10.0.0.1 example.com".into();
        let base = serde_json::to_value(&BASE_PEERS[0]).unwrap();
        assert!(store
            .update(&state(&[base.clone(), invalid]))
            .unwrap()
            .is_empty());
        new_peer.name = None;
        assert_eq!(
            store.peers().unwrap(),
            [BASE_PEERS[0].clone(), new_peer.clone()]
        );

        // A stored peer renamed to an invalid name loses its name, and stays enabled.
        let mut renamed = base;
        renamed["name"] = "Blah".into();
        let renamed_new = serde_json::to_value(&new_peer).unwrap();
        assert!(store
            .update(&state(&[renamed, renamed_new]))
            .unwrap()
            .is_empty());
        let unnamed = PeerContents {
            name: None,
            ..BASE_PEERS[0].clone()
        };
        assert_eq!(store.peers().unwrap(), [unnamed, new_peer]);
    }

    #[test]
    fn test_peers_without_a_name() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store = open(dir.path(), false).unwrap();

        // Any number of peers can be without a name, and a peer can lose its name.
        let mut nameless = BASE_PEERS.clone();
        nameless[0].name = None;
        let mut other = nameless[0].clone();
        other.delegations = host("10.0.0.2");
        other.public_key = "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes=".to_string();
        nameless.push(other);
        assert!(store.update_peers(&nameless).is_empty());
        assert_eq!(store.peers().unwrap(), nameless);
        assert_eq!(open(dir.path(), false).unwrap().peers().unwrap(), nameless);

        // And get a name again.
        assert!(store.update_peers(&BASE_PEERS).is_empty());
        assert_eq!(store.peers().unwrap()[0], BASE_PEERS[0]);
    }

    #[test]
    fn test_network() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store = open(dir.path(), false).unwrap();

        // A new peer outside the network is dropped, and the other peers are kept.
        let mut outside = BASE_PEERS.clone();
        let mut new_peer = BASE_PEERS[0].clone();
        new_peer.delegations = host("1.1.1.1");
        new_peer.public_key = "HX6Se15qwliiWM7l3iCVAtK+FXNfHRFeEq8UFRK8BBk=".to_string();
        outside.push(new_peer);
        let dropped = store.update_peers(&outside);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].0, &outside[1]);
        assert_eq!(store.peers().unwrap(), *BASE_PEERS);

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
        invalid.delegations = host("10.0.0.2");
        invalid.public_key = "abc".to_string();
        let peers = [BASE_PEERS[0].clone(), invalid];
        write_legacy(dir.path(), &peers, &[]);
        assert!(open(dir.path(), false).is_err());

        let state = State {
            peers: peers.to_vec(),
            cidrs: vec![],
            observed_endpoint: None,
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
        entry["delegations"] = serde_json::json!(["not a prefix"]);
        let state: State =
            serde_json::from_value(serde_json::json!({ "peers": [entry], "cidrs": *BASE_CIDRS }))
                .unwrap();
        assert!(state.peers.is_empty());
        assert_eq!(state.invalid_peer_keys, [BASE_PEERS[0].public_key.clone()]);
        assert!(store.update(&state).unwrap().is_empty());
        assert_eq!(store.peers().unwrap(), *BASE_PEERS);

        // A peer that isn't reported at all is disabled.
        let state: State =
            serde_json::from_value(serde_json::json!({ "peers": [], "cidrs": *BASE_CIDRS }))
                .unwrap();
        store.update(&state).unwrap();
        assert_eq!(store.peers().unwrap(), disabled(&BASE_PEERS));
    }

    #[test]
    fn test_first_wins() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store = open(dir.path(), false).unwrap();

        // Of two new peers at the same IP, the first is kept and the second dropped.
        let mut same_ip = BASE_PEERS.clone();
        let mut new_peer = BASE_PEERS[0].clone();
        new_peer.name = Some("second".parse().unwrap());
        new_peer.delegations = host("10.0.0.2");
        new_peer.public_key = "HX6Se15qwliiWM7l3iCVAtK+FXNfHRFeEq8UFRK8BBk=".to_string();
        same_ip.push(new_peer.clone());
        new_peer.name = Some("third".parse().unwrap());
        new_peer.public_key = "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes=".to_string();
        same_ip.push(new_peer);
        let dropped = store.update_peers(&same_ip);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].0, &same_ip[2]);
        assert_eq!(store.peers().unwrap(), same_ip[..2]);

        // Of two new peers with the same public key, the first is kept and the second dropped.
        let mut same_public_key = same_ip[..2].to_vec();
        let mut new_peer = BASE_PEERS[0].clone();
        new_peer.name = Some("fourth".parse().unwrap());
        new_peer.delegations = host("10.0.0.3");
        new_peer.public_key = "9fNiSxgLIPEqRALrIpaK2a77aiPz/CZCpQVQtF7o4v0=".to_string();
        same_public_key.push(new_peer.clone());
        new_peer.name = Some("fifth".parse().unwrap());
        new_peer.delegations = host("10.0.0.4");
        same_public_key.push(new_peer);
        let dropped = store.update_peers(&same_public_key);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].0, &same_public_key[3]);
        assert_eq!(store.peers().unwrap(), same_public_key[..3]);
    }

    #[test]
    fn test_conflicting_legacy_peers() {
        // A legacy data store holding two records of a peer at different IPs, or two peers at one
        // IP, is refused.
        let mut moved = BASE_PEERS[0].clone();
        moved.delegations = host("10.0.0.2");
        let mut replaced = BASE_PEERS[0].clone();
        replaced.public_key = "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes=".to_string();
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
        assert_eq!(store.peers().unwrap(), disabled(&BASE_PEERS));
    }

    /// The coordinator of [`introducing_config`], as the server reports it.
    static COORDINATOR: Lazy<PeerContents> = Lazy::new(|| {
        let mut coordinator = BASE_PEERS[0].clone();
        coordinator.public_key = "dz0/Fjmj7oRBSGxgWXSkE3n9R3k19kJOj127FzJZ81g=".to_string();
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
    fn test_tls_latch() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store = open(dir.path(), false).unwrap();
        let key = &BASE_PEERS[0].public_key;
        let unknown = "HX6Se15qwliiWM7l3iCVAtK+FXNfHRFeEq8UFRK8BBk=";

        // A peer isn't known to speak TLS until it is latched, which only a recorded peer can be.
        assert!(!store.speaks_tls(key).unwrap());
        assert!(!store.speaks_tls(unknown).unwrap());
        assert!(store.latch_tls(unknown).is_err());
        store.latch_tls(key).unwrap();
        assert!(store.speaks_tls(key).unwrap());

        // The latch survives updates of the peer and reopening the data store.
        assert!(store.update_peers(&BASE_PEERS).is_empty());
        let store = open(dir.path(), false).unwrap();
        assert!(store.speaks_tls(key).unwrap());
    }

    #[test]
    fn test_quic_port() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store = open(dir.path(), false).unwrap();
        let key = &BASE_PEERS[0].public_key;
        let unknown = "HX6Se15qwliiWM7l3iCVAtK+FXNfHRFeEq8UFRK8BBk=";

        // The port is unknown until it is recorded, which only a recorded peer can be, and a
        // port recorded later replaces it.
        assert_eq!(store.quic_port(key).unwrap(), None);
        assert_eq!(store.quic_port(unknown).unwrap(), None);
        assert!(store.set_quic_port(unknown, 4433).is_err());
        store.set_quic_port(key, 4433).unwrap();
        assert_eq!(store.quic_port(key).unwrap(), Some(4433));
        store.set_quic_port(key, 4434).unwrap();

        // The port survives updates of the peer and reopening the data store, and the database
        // refuses a port that isn't one.
        assert!(store.update_peers(&BASE_PEERS).is_empty());
        let store = open(dir.path(), false).unwrap();
        assert_eq!(store.quic_port(key).unwrap(), Some(4434));
        assert!(store
            .store
            .execute("UPDATE peers SET quic_port = 0", [])
            .is_err());
    }

    #[test]
    fn test_introduce() {
        let dir = tempfile::tempdir().unwrap();
        let own_key = wireguard_control::KeyPair::generate();
        let config = introducing_config(&own_key);

        // A new data store pins the coordinator at its internal address, and this client to the
        // delegations that the invitation offers it, without a name.
        let mut store = open(dir.path(), true).unwrap();
        let offered: Vec<Prefix> = vec![
            "10.0.0.16/28".parse().unwrap(),
            "10.0.0.2/32".parse().unwrap(),
        ];
        store.introduce(&config, &offered).unwrap();
        let peers = store.peers().unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].delegations, COORDINATOR.delegations);
        assert_eq!(peers[0].public_key, COORDINATOR.public_key);
        assert_eq!(peers[0].name, None);
        assert_eq!(peers[1].delegations, [offered[1], offered[0]]);
        assert_eq!(peers[1].public_key, own_key.public.to_base64());
        assert_eq!(peers[1].name, None);

        // No other key can be reported at the coordinator's internal address.
        let mut replaced = [COORDINATOR.clone()];
        replaced[0].public_key = "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes=".to_string();
        assert_eq!(store.update_peers(&replaced).len(), 1);

        // The server's record of the coordinator replaces the introduced one.
        assert!(store
            .update_peers(std::slice::from_ref(&*COORDINATOR))
            .is_empty());
        assert_eq!(store.peers().unwrap()[0], *COORDINATOR);
        assert_eq!(store.peers().unwrap().len(), 2);

        // Only a new data store is introduced.
        assert!(store.introduce(&config, &offered).is_err());
        assert_eq!(store.peers().unwrap().len(), 2);
    }

    /// Peers with endpoints of every shape, in a network of each family.
    fn varied_peers() -> Vec<PeerContents> {
        let mut v4 = BASE_PEERS[0].clone();
        v4.endpoint = Some("203.0.113.1:51820".parse().unwrap());
        v4.candidates = vec![
            "192.168.1.2:51820".parse().unwrap(),
            "[2001:db8::1]:4000".parse().unwrap(),
            "peer.example.com:1".parse().unwrap(),
        ];
        v4.persistent_keepalive_interval = Some(25);
        v4.invite_expires = Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000));
        v4.is_admin = true;
        let mut domain = BASE_PEERS[0].clone();
        domain.name = Some("domain".parse().unwrap());
        domain.delegations = host("10.0.1.1");
        domain.public_key = "HX6Se15qwliiWM7l3iCVAtK+FXNfHRFeEq8UFRK8BBk=".to_string();
        domain.endpoint = Some("vpn.example.com:51820".parse().unwrap());
        vec![v4, domain]
    }

    fn varied_cidrs() -> Vec<Cidr> {
        let cidr = |name: &str, cidr: &str| Cidr {
            name: name.to_string(),
            cidr: cidr.parse().unwrap(),
        };
        vec![
            cidr("cidr", "10.0.0.0/24"),
            cidr("other", "10.0.1.0/24"),
            cidr("root", "10.0.0.0/16"),
        ]
    }

    #[test]
    fn test_round_trip() {
        // Every field survives the database, the CIDRs are ordered by prefix, the parent of each
        // is the smallest CIDR containing it, and the CIDR of each peer is the smallest CIDR
        // containing its IP.
        let dir = tempfile::tempdir().unwrap();
        let mut store = open(dir.path(), true).unwrap();
        let mut cidrs = varied_cidrs();
        cidrs.reverse();
        store
            .update(&State {
                peers: varied_peers(),
                cidrs,
                observed_endpoint: None,
                invalid_peer_keys: vec![],
            })
            .unwrap();
        let expected_cidrs = {
            let mut cidrs = varied_cidrs();
            // The CIDRs are ordered by address, then prefix length.
            cidrs.sort_by_key(|c| c.cidr);
            cidrs
        };
        let expected_peers = varied_peers();
        for store in [store, open(dir.path(), false).unwrap()] {
            let cidrs = store.cidrs().unwrap();
            assert_eq!(cidrs, expected_cidrs);
            assert_eq!(store.peers().unwrap(), expected_peers);
            assert_eq!(cidrs[0].parent(&cidrs), None);
            assert_eq!(cidrs[1].parent(&cidrs), Some(&cidrs[0]));
            assert_eq!(cidrs[2].parent(&cidrs), Some(&cidrs[0]));
            assert_eq!(store.peers().unwrap()[0].cidr(&cidrs), Some(&cidrs[1]));
            assert_eq!(store.peers().unwrap()[1].cidr(&cidrs), Some(&cidrs[2]));
        }
    }

    #[test]
    fn test_ipv6_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let network: IpNet = "fd00::/64".parse().unwrap();
        let mut peer = BASE_PEERS[0].clone();
        peer.delegations = host("fd00::1");
        peer.endpoint = Some("[::ffff:203.0.113.1]:51820".parse().unwrap());
        let mut store = DataStore::open_with_paths(
            &db_path(dir.path()),
            &legacy_path(dir.path()),
            self::network(network),
            true,
        )
        .unwrap();
        assert!(store.update_peers(std::slice::from_ref(&peer)).is_empty());
        assert_eq!(store.peers().unwrap(), [peer]);
    }

    #[test]
    fn test_import_legacy() {
        // A legacy data store is imported into the new database, without its server IDs, and the
        // file is left untouched.
        let dir = tempfile::tempdir().unwrap();
        let legacy_peers = varied_peers();
        write_legacy(dir.path(), &legacy_peers, &varied_cidrs());
        let legacy = std::fs::read(legacy_path(dir.path())).unwrap();
        let mut store = open(dir.path(), false).unwrap();
        let expected_peers = varied_peers();
        assert_eq!(store.peers().unwrap(), expected_peers);
        let mut expected_cidrs = varied_cidrs();
        expected_cidrs.sort_by_key(|c| c.cidr);
        assert_eq!(store.cidrs().unwrap(), expected_cidrs);

        // From then on the database is the data store, and the legacy one is never read again.
        store.update_peers(&[]);
        write_legacy(dir.path(), &[], &[]);
        let store = open(dir.path(), false).unwrap();
        assert_eq!(store.peers().unwrap(), disabled(&expected_peers));
        write_legacy(dir.path(), &legacy_peers, &varied_cidrs());
        assert_eq!(std::fs::read(legacy_path(dir.path())).unwrap(), legacy);
    }

    #[test]
    fn test_connection_settings() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(dir.path(), true).unwrap();
        let conn: &Connection = &store.store;
        let pragma = |name| -> i64 { conn.pragma_query_value(None, name, |r| r.get(0)).unwrap() };
        assert_eq!(pragma("foreign_keys"), 1);
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
        assert_eq!(
            open(dir.path(), false).unwrap().peers().unwrap(),
            *BASE_PEERS
        );
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
        pinned.name = Some("pinned".parse().unwrap());
        pinned.delegations = host("10.0.0.2");
        pinned.public_key = "HX6Se15qwliiWM7l3iCVAtK+FXNfHRFeEq8UFRK8BBk=".to_string();
        let mut with_pinned = BASE_PEERS.clone();
        with_pinned.push(pinned.clone());
        assert!(cli.update_peers(&with_pinned).is_empty());

        // The daemon's handle predates the pin, but its update still keeps another key from the
        // pinned IP, and disables the pinned peer, which its state leaves out.
        let mut impostor = pinned.clone();
        impostor.name = Some("impostor".parse().unwrap());
        impostor.public_key = "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes=".to_string();
        let mut with_impostor = BASE_PEERS.clone();
        with_impostor.push(impostor);
        assert_eq!(daemon.update_peers(&with_impostor).len(), 1);
        let mut expected = BASE_PEERS.clone();
        expected.extend(disabled(&[pinned]));
        assert_eq!(daemon.peers().unwrap(), expected);
        assert_eq!(open(dir.path(), false).unwrap().peers().unwrap(), expected);
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
                        peers[0].is_admin = i % 2 == 0;
                        let state = State {
                            peers,
                            cidrs: BASE_CIDRS.clone(),
                            observed_endpoint: None,
                            invalid_peer_keys: vec![],
                        };
                        assert!(store.update(&state).unwrap().is_empty());
                    }
                });
            }
        });
        assert_eq!(open(dir.path(), false).unwrap().peers().unwrap().len(), 1);
    }
}
