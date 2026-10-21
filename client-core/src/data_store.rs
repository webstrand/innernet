use anyhow::{bail, ensure, Context as _, Error};
use innernet_node::{
    db::CreateHook,
    store::{self, StoredCidr},
    Store,
};
use innernet_shared::{
    ensure_dirs_exist, interface_config::InterfaceConfig, Cidr, CidrContents, Hostname,
    IoErrorContext, Peer, PeerContents, Prefix, State,
};
use ipnet::IpNet;
use rusqlite::OptionalExtension as _;
use serde::Deserialize;
use std::{
    fs::OpenOptions,
    io,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};
use wireguard_control::{InterfaceName, Key};

/// The peers and CIDRs that the coordinator reported, kept in the node's database, with the
/// address of each peer pinned to its public key.
///
/// The database is stored at [`Self::get_path()`]. A data store from before SQLite, at
/// [`Self::get_legacy_path()`], is imported when the database is created, and left untouched.
#[derive(Debug)]
pub struct DataStore {
    store: Store,
}

/// Server IDs aren't stored, so every peer read from the data store has this ID, and so does the
/// CIDR of a peer outside every CIDR. The CIDRs are numbered from 1 as they are read.
const UNKNOWN_ID: i64 = 0;

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

        let legacy_path = legacy_path.to_owned();
        let import: CreateHook = Arc::new(move |scope| import_legacy(scope, &legacy_path));
        let store = Store::open(path, network, Some(import))
            .with_context(|| format!("failed to open the data store {}", path.display()))?;
        Ok(Self { store })
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

    /// The node's store of the data store.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Records the coordinator and this client as the interface config introduces them, when an
    /// invitation is redeemed, so the data store must be new.
    ///
    /// The interface config, which the invitation produced, is the authority on both, so their
    /// addresses are pinned to their keys before the coordinator reports anything. Each record is
    /// named by its public key until a fetch replaces it with the coordinator's record.
    pub fn introduce(&mut self, config: &InterfaceConfig) -> Result<(), Error> {
        let [coordinator, own] = introduced_peers(config)?;
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
    /// reason that the node refused it.
    ///
    /// A peer that is absent from `state` is disabled rather than deleted, so that its address
    /// stays pinned: the coordinator leaves disabled peers out of the state. A dropped peer was
    /// reported, so the stored peer with its key keeps its record unchanged, as does one whose
    /// record failed to deserialize.
    pub fn update<'a>(&mut self, state: &'a State) -> Result<Vec<(&'a Peer, Error)>, Error> {
        let tx = self.store.transaction()?;
        let reported: Vec<&PeerContents> = state.peers.iter().map(|peer| &peer.contents).collect();
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
        let cidrs: Vec<StoredCidr> = state
            .cidrs
            .iter()
            .filter_map(|cidr| {
                Some(StoredCidr {
                    prefix: Prefix::new(cidr.cidr.trunc()).ok()?,
                    name: cidr.name.clone(),
                    infra: false,
                })
            })
            .collect();
        store::replace_cidrs(&tx, &cidrs)?;
        tx.commit()?;
        Ok(dropped)
    }

    #[cfg(test)]
    fn update_peers<'a>(&mut self, new_peers: &'a [Peer]) -> Vec<(&'a Peer, Error)> {
        let state = State {
            peers: new_peers.to_vec(),
            cidrs: self.cidrs().unwrap(),
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

    /// The peers, ordered by IP, each with the smallest CIDR that holds its IP as its CIDR.
    pub fn peers(&self) -> Result<Vec<Peer>, Error> {
        let cidrs = self.cidrs()?;
        Ok(store::load_peers(&self.store)?
            .into_iter()
            .map(|mut contents| {
                contents.cidr_id = smallest_containing(&cidrs, |cidr| cidr.contains(&contents.ip))
                    .unwrap_or(UNKNOWN_ID);
                Peer {
                    id: UNKNOWN_ID,
                    contents,
                }
            })
            .collect())
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

    /// The CIDRs, ordered by prefix and numbered from 1, each with the smallest CIDR that holds it
    /// as its parent.
    pub fn cidrs(&self) -> Result<Vec<Cidr>, Error> {
        let mut cidrs: Vec<Cidr> = store::load_cidrs(&self.store)?
            .into_iter()
            .zip(1..)
            .map(|(cidr, id)| Cidr {
                id,
                contents: CidrContents {
                    name: cidr.name,
                    cidr: cidr.prefix.net(),
                    parent: None,
                },
            })
            .collect();
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
        Ok(cidrs)
    }
}

/// Imports the legacy data store at `path` into the new database, if there is one. The import
/// refuses, rather than repairs, a data store that the node would refuse a peer of: one with an
/// invalid public key or name, a peer outside the network, or two records in conflict. The file
/// itself is left untouched, so that earlier versions still find their pins in it.
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
    let contents: Vec<&PeerContents> = peers.iter().map(|peer| &peer.contents).collect();
    for (peer, decided) in peers.iter().zip(scope.accept(&contents)?) {
        if let Err(refusal) = decided {
            bail!(
                "{}: failed to import peer {} at {}: {refusal}",
                path.display(),
                peer.public_key,
                peer.ip
            );
        }
    }
    let cidrs: Vec<StoredCidr> = cidrs
        .iter()
        .filter_map(|cidr| {
            Some(StoredCidr {
                prefix: Prefix::new(cidr.cidr.trunc()).ok()?,
                name: cidr.name.clone(),
                infra: false,
            })
        })
        .collect();
    store::replace_cidrs(scope, &cidrs)?;
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

/// The coordinator and this client, as the interface config introduces them. Each record is named
/// by its public key, and has no CIDR.
fn introduced_peers(config: &InterfaceConfig) -> Result<[PeerContents; 2], Error> {
    let introduced = |ip, public_key: String, endpoint| PeerContents {
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
#[cfg(test)]
mod tests {
    use super::*;
    use innernet_node::db::{APPLICATION_ID, BUSY_TIMEOUT, SCHEMA_VERSION};
    use innernet_shared::{Cidr, CidrContents, Peer, PeerContents};
    use once_cell::sync::Lazy;
    use rusqlite::{config::DbConfig, Connection};
    use std::time::{Duration, UNIX_EPOCH};
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
        assert_eq!(0, store.peers().unwrap().len());
        assert_eq!(0, store.cidrs().unwrap().len());

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
        modified[0].contents.public_key =
            "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes=".to_string();

        // Should NOT work, since the IP is pinned to another public key. The pinned peer is
        // disabled, since it is absent from the update.
        assert_eq!(store.update_peers(&modified).len(), 1);
        assert_eq!(store.peers().unwrap(), disabled(&BASE_PEERS));
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
        assert_eq!(store.update_peers(&moved).len(), 1);
        assert_eq!(store.peers().unwrap(), *BASE_PEERS);

        // Other changes to a pinned peer are applied in place, and new peers are added.
        let mut updated = BASE_PEERS.clone();
        updated[0].contents.name = "renamed".parse().unwrap();
        let mut new_peer = BASE_PEERS[0].clone();
        new_peer.contents.name = "new".parse().unwrap();
        new_peer.contents.ip = "10.0.0.2".parse().unwrap();
        new_peer.contents.public_key = "HX6Se15qwliiWM7l3iCVAtK+FXNfHRFeEq8UFRK8BBk=".to_string();
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
        assert_eq!(store.peers().unwrap(), *BASE_PEERS);

        // A stored peer renamed to an invalid name keeps its record, and stays enabled.
        let mut renamed = BASE_PEERS.clone();
        renamed[0].contents.name = Hostname::unchecked("Blah".into());
        assert_eq!(store.update_peers(&renamed).len(), 1);
        assert_eq!(store.peers().unwrap(), *BASE_PEERS);
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
        new_peer.contents.name = "second".parse().unwrap();
        new_peer.contents.ip = "10.0.0.2".parse().unwrap();
        new_peer.contents.public_key = "HX6Se15qwliiWM7l3iCVAtK+FXNfHRFeEq8UFRK8BBk=".to_string();
        same_ip.push(new_peer.clone());
        new_peer.contents.name = "third".parse().unwrap();
        new_peer.contents.public_key = "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes=".to_string();
        same_ip.push(new_peer);
        let dropped = store.update_peers(&same_ip);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].0, &same_ip[2]);
        assert_eq!(store.peers().unwrap(), same_ip[..2]);

        // Of two new peers with the same public key, the first is kept and the second dropped.
        let mut same_public_key = same_ip[..2].to_vec();
        let mut new_peer = BASE_PEERS[0].clone();
        new_peer.contents.name = "fourth".parse().unwrap();
        new_peer.contents.ip = "10.0.0.3".parse().unwrap();
        new_peer.contents.public_key = "9fNiSxgLIPEqRALrIpaK2a77aiPz/CZCpQVQtF7o4v0=".to_string();
        same_public_key.push(new_peer.clone());
        new_peer.contents.name = "fifth".parse().unwrap();
        new_peer.contents.ip = "10.0.0.4".parse().unwrap();
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
        assert_eq!(store.peers().unwrap(), disabled(&BASE_PEERS));
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
    fn test_introduce() {
        let dir = tempfile::tempdir().unwrap();
        let own_key = wireguard_control::KeyPair::generate();
        let config = introducing_config(&own_key);

        // A new data store pins the coordinator and this client, named by their public keys.
        let mut store = open(dir.path(), true).unwrap();
        store.introduce(&config).unwrap();
        let peers = store.peers().unwrap();
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
        assert_eq!(store.peers().unwrap()[0], expected);
        assert_eq!(store.peers().unwrap().len(), 2);

        // Only a new data store is introduced.
        assert!(store.introduce(&config).is_err());
        assert_eq!(store.peers().unwrap().len(), 2);
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
        domain.contents.name = "domain".parse().unwrap();
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
        assert_eq!(store.cidrs().unwrap(), expected_cidrs);
        assert_eq!(store.peers().unwrap(), expected_peers);

        let store = open(dir.path(), false).unwrap();
        assert_eq!(store.cidrs().unwrap(), expected_cidrs);
        assert_eq!(store.peers().unwrap(), expected_peers);
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
        assert_eq!(store.peers().unwrap(), [peer]);
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
        assert_eq!(store.peers().unwrap(), expected_peers);
        assert_eq!(store.cidrs().unwrap().len(), 3);

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
        pinned.contents.name = "pinned".parse().unwrap();
        pinned.contents.ip = "10.0.0.2".parse().unwrap();
        pinned.contents.public_key = "HX6Se15qwliiWM7l3iCVAtK+FXNfHRFeEq8UFRK8BBk=".to_string();
        let mut with_pinned = BASE_PEERS.clone();
        with_pinned.push(pinned.clone());
        assert!(cli.update_peers(&with_pinned).is_empty());

        // The daemon's handle predates the pin, but its update still keeps another key from the
        // pinned IP, and disables the pinned peer, which its state leaves out.
        let mut impostor = pinned.clone();
        impostor.contents.name = "impostor".parse().unwrap();
        impostor.contents.public_key = "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes=".to_string();
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
        assert_eq!(open(dir.path(), false).unwrap().peers().unwrap().len(), 1);
    }
}
