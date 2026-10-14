use anyhow::{bail, Error};
use innernet_shared::{
    ensure_dirs_exist, interface_config::InterfaceConfig, Cidr, IoErrorContext, Peer, PeerContents,
    State, WrappedIoError,
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{self, Read, Seek, Write},
    net::IpAddr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
use wireguard_control::{InterfaceName, InvalidKey, Key};

/// File-backed storage of [`Peer`]s and [`Cidr`]s.
///
/// The file is stored at [`Self::get_path()`].
#[derive(Debug)]
pub struct DataStore {
    file: File,
    /// The peers of the data store, indexed at runtime. The index is not persisted.
    peers: PeersIndex,
    cidrs: Vec<Cidr>,
    /// The network of the interface, from its config. It is not persisted.
    network: IpNet,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "version")]
enum Contents {
    #[serde(rename = "1")]
    V1 { peers: Vec<Peer>, cidrs: Vec<Cidr> },
}

impl DataStore {
    fn open_with_path<P: AsRef<Path>>(
        path: P,
        network: IpNet,
        create: bool,
    ) -> Result<Self, WrappedIoError> {
        let path = path.as_ref();

        // The mode applies only if the file is created, in the same call that creates it.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(create)
            .mode(0o600)
            .open(path)
            .with_path(path)?;
        innernet_shared::warn_on_dangerous_mode(&file, path).with_path(path)?;

        let mut json = String::new();
        file.read_to_string(&mut json).with_path(path)?;
        let Contents::V1 { peers, cidrs } = match serde_json::from_str(&json) {
            Ok(contents) => contents,
            // Only an empty file, which fails at its very start, is a new data store.
            Err(e) if e.is_eof() && e.line() == 1 && e.column() == 0 => Contents::V1 {
                peers: vec![],
                cidrs: vec![],
            },
            // Any other file that fails to parse is an error, since starting over would discard
            // its pins.
            Err(e) => return Err(io::Error::from(e)).with_path(path),
        };

        // A data store written before public keys were pinned to their IP can hold a later record
        // of a peer at another IP. The earliest record of each peer is kept.
        let mut index = PeersIndex::default();
        for peer in peers {
            let status = index.check(&peer);
            if let PinStatus::ConflictingKey | PinStatus::ConflictingIp = status {
                log::warn!(
                    "{}: ignoring stored peer {} at {} ({:?}).",
                    path.display(),
                    peer.display_name(),
                    peer.ip,
                    status
                );
            } else {
                index.insert(peer);
            }
        }

        Ok(Self {
            file,
            peers: index,
            cidrs,
            network: network.trunc(),
        })
    }

    /// Produce the path "`data_dir`/`interface`.json".
    pub fn get_path(data_dir: &Path, interface: &InterfaceName) -> PathBuf {
        data_dir.join(interface.to_string()).with_extension("json")
    }

    fn _open(
        data_dir: &Path,
        interface: &InterfaceName,
        config: &InterfaceConfig,
        create: bool,
    ) -> Result<Self, WrappedIoError> {
        ensure_dirs_exist(&[data_dir])?;
        let path = Self::get_path(data_dir, interface);
        let introduced = introduced_peers(config)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key in config"))
            .with_path(&path)?;
        let mut store = Self::open_with_path(&path, config.interface.address, create)?;
        store.introduce(introduced);
        Ok(store)
    }

    /// Adds each peer of `introduced` that the data store does not hold yet, so that its
    /// (IP, PublicKey) tuple is pinned before the first fetch. A peer that the data store already
    /// holds keeps its record, and a peer that conflicts with a pin is not added.
    fn introduce(&mut self, introduced: Vec<Peer>) {
        for peer in introduced {
            match self.peers.check(&peer) {
                PinStatus::New => {
                    self.peers.insert(peer);
                },
                PinStatus::Unchanged => {},
                status @ (PinStatus::ConflictingKey | PinStatus::ConflictingIp) => log::warn!(
                    "the data store conflicts with the interface config at {} ({:?}).",
                    peer.ip,
                    status
                ),
            }
        }
    }

    /// Open the data store residing at "`data_dir`/`interface`.json", whose peers must lie within
    /// the network of `config`.
    pub fn open(
        data_dir: &Path,
        interface: &InterfaceName,
        config: &InterfaceConfig,
    ) -> Result<Self, WrappedIoError> {
        Self::_open(data_dir, interface, config, false)
    }

    /// Open or create the data store residing at "`data_dir`/`interface`.json", whose peers must
    /// lie within the network of `config`.
    pub fn open_or_create(
        data_dir: &Path,
        interface: &InterfaceName,
        config: &InterfaceConfig,
    ) -> Result<Self, WrappedIoError> {
        Self::_open(data_dir, interface, config, true)
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
        let dropped = self.update_peers(&state.peers);
        self.set_cidrs(state.cidrs.clone());
        self.write()?;

        Ok(dropped)
    }

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

    /// Validates that `candidate` lies within the network of the interface, matches the pins of
    /// the data store, and shares neither its IP nor its public key with a peer of `accepted`.
    fn check(&self, candidate: &Peer, accepted: &PeersIndex) -> Result<(), Error> {
        self.check_network_closure(candidate)?;
        match self.peers.check(candidate) {
            PinStatus::New | PinStatus::Unchanged => {},
            PinStatus::ConflictingKey => {
                let existing_peer = self.peers.get_by_ip(&candidate.ip).unwrap();
                bail!(
                    "PINNING ERROR: New peer has same IP ({}) but different public key than \
                     previously seen peer {}.",
                    candidate.ip,
                    existing_peer.display_name(),
                )
            },
            PinStatus::ConflictingIp => {
                let existing_peer = self.peers.get_by_public_key(&candidate.public_key).unwrap();
                bail!(
                    "PINNING ERROR: New peer has same public key but different IP ({}) than \
                     previously seen peer {} ({}).",
                    candidate.ip,
                    existing_peer.display_name(),
                    existing_peer.ip,
                )
            },
        }
        if accepted.check(candidate) != PinStatus::New {
            bail!("IP or public key is shared with an earlier peer.");
        }

        Ok(())
    }

    fn update_peers<'a>(&mut self, new_peers: &'a [Peer]) -> Vec<(&'a Peer, Error)> {
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

        for existing_peer in self.peers.peers.iter_mut() {
            if !accepted.contains_public_key(&existing_peer.public_key) {
                existing_peer.contents.is_disabled = true;
            }
        }
        for new_peer in accepted.peers {
            self.peers.insert(new_peer);
        }

        dropped
    }

    /// Removes a peer from the store and persists the store to disk, un-pinning the peer's
    /// (IP, PublicKey) tuple so that a new peer may be accepted at the same IP.
    ///
    /// If the peer still exists on the server, it is simply pinned again on the next fetch.
    pub fn forget_peer(&mut self, public_key: &str) -> Result<(), Error> {
        self.peers
            .remove(public_key)
            .ok_or_else(|| anyhow::anyhow!("peer not found in data store"))?;
        self.write()?;

        Ok(())
    }

    pub fn peers(&self) -> &[Peer] {
        &self.peers.peers
    }

    pub fn cidrs(&self) -> &[Cidr] {
        &self.cidrs
    }

    fn set_cidrs(&mut self, new_cidrs: Vec<Cidr>) {
        self.cidrs = new_cidrs;
    }

    fn write(&mut self) -> Result<(), io::Error> {
        let contents = Contents::V1 {
            peers: self.peers.peers.clone(),
            cidrs: self.cidrs.clone(),
        };
        self.file.rewind()?;
        self.file.set_len(0)?;
        self.file
            .write_all(serde_json::to_string_pretty(&contents)?.as_bytes())?;
        Ok(())
    }
}

/// The ID of the record of the coordinator from the interface config. Server IDs are positive, so
/// the ID never collides with the ID of a fetched peer.
const INTRODUCED_COORDINATOR_ID: i64 = -1;
/// The ID of the record of this client from the interface config.
const INTRODUCED_SELF_ID: i64 = -2;

/// The coordinator and this client, as the interface config that the invitation produced
/// introduces them. Each record is without a name and a CIDR, and the first fetch replaces it with
/// the record of the server.
fn introduced_peers(config: &InterfaceConfig) -> Result<Vec<Peer>, InvalidKey> {
    let introduced = |id, ip, public_key, endpoint| Peer {
        id,
        contents: PeerContents {
            name: None,
            ip,
            cidr_id: -1,
            public_key,
            endpoint,
            persistent_keepalive_interval: None,
            is_admin: false,
            is_disabled: false,
            is_redeemed: true,
            invite_expires: None,
            candidates: vec![],
            announcement: None,
            observed_endpoint: None,
            delegations: vec![],
        },
    };
    let private_key = Key::from_base64(&config.interface.private_key)?;
    Ok(vec![
        introduced(
            INTRODUCED_COORDINATOR_ID,
            config.server.internal_endpoint.ip(),
            Key::from_base64(&config.server.public_key)?.to_base64(),
            Some(config.server.external_endpoint.clone()),
        ),
        introduced(
            INTRODUCED_SELF_ID,
            config.interface.address.addr(),
            private_key.get_public().to_base64(),
            None,
        ),
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

    /// Removes the peer with `public_key` and returns it, or returns `None` if no peer has it.
    /// The remaining peers keep their order.
    fn remove(&mut self, public_key: &str) -> Option<Peer> {
        let index = self.by_public_key.remove(public_key)?;
        let peer = self.peers.remove(index);
        self.by_ip.remove(&peer.ip);
        for i in self
            .by_ip
            .values_mut()
            .chain(self.by_public_key.values_mut())
        {
            if *i > index {
                *i -= 1;
            }
        }

        Some(peer)
    }

    fn get_by_ip(&self, ip: &IpAddr) -> Option<&Peer> {
        self.by_ip.get(ip).map(|&index| &self.peers[index])
    }

    fn get_by_public_key(&self, public_key: &str) -> Option<&Peer> {
        self.by_public_key
            .get(public_key)
            .map(|&index| &self.peers[index])
    }

    fn contains_public_key(&self, public_key: &str) -> bool {
        self.by_public_key.contains_key(public_key)
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
                name: Some("blah".parse().unwrap()),
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
                announcement: None,
                observed_endpoint: None,
                delegations: vec![],
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

    fn setup_basic_store(dir: &Path) {
        let mut store =
            DataStore::open_with_path(dir.join("peer_store.json"), *NETWORK, true).unwrap();

        println!("{store:?}");
        assert_eq!(0, store.peers().len());
        assert_eq!(0, store.cidrs().len());

        store
            .update(&State {
                peers: BASE_PEERS.to_owned(),
                cidrs: BASE_CIDRS.to_owned(),
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
        let store =
            DataStore::open_with_path(dir.path().join("peer_store.json"), *NETWORK, false).unwrap();
        assert_eq!(store.peers(), &*BASE_PEERS);
        assert_eq!(store.cidrs(), &*BASE_CIDRS);
    }

    #[test]
    fn test_pinning() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store =
            DataStore::open_with_path(dir.path().join("peer_store.json"), *NETWORK, false).unwrap();

        // Should work, since peer is unmodified.
        assert!(store.update_peers(&BASE_PEERS).is_empty());
        assert_eq!(store.peers(), &*BASE_PEERS);

        let mut modified = BASE_PEERS.clone();
        modified[0].contents.public_key =
            "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes=".to_string();

        // Should NOT work, since the IP is pinned to another public key. The pinned peer is
        // disabled, since it is absent from the update.
        assert_eq!(store.peers.check(&modified[0]), PinStatus::ConflictingKey);
        assert_eq!(store.update_peers(&modified).len(), 1);
        assert_eq!(store.peers(), &disabled(&BASE_PEERS)[..]);
    }

    #[test]
    fn test_pinning_public_key_to_ip() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store =
            DataStore::open_with_path(dir.path().join("peer_store.json"), *NETWORK, false).unwrap();

        // The same public key reported at another IP is dropped.
        let mut moved = BASE_PEERS.clone();
        moved[0].contents.ip = "10.0.0.2".parse().unwrap();
        assert_eq!(store.peers.check(&moved[0]), PinStatus::ConflictingIp);
        assert_eq!(store.update_peers(&moved).len(), 1);
        assert_eq!(store.peers(), &disabled(&BASE_PEERS)[..]);

        // Other changes to a pinned peer are applied in place, and new peers are added.
        let mut updated = BASE_PEERS.clone();
        updated[0].contents.name = Some("renamed".parse().unwrap());
        let mut new_peer = BASE_PEERS[0].clone();
        new_peer.contents.ip = "10.0.0.2".parse().unwrap();
        new_peer.contents.public_key = "HX6Se15qwliiWM7l3iCVAtK+FXNfHRFeEq8UFRK8BBk=".to_string();
        updated.push(new_peer);
        assert!(store.update_peers(&updated).is_empty());
        assert_eq!(store.peers(), &updated[..]);
    }

    #[test]
    fn test_network() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store =
            DataStore::open_with_path(dir.path().join("peer_store.json"), *NETWORK, false).unwrap();

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
    }

    #[test]
    fn test_first_wins() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store =
            DataStore::open_with_path(dir.path().join("peer_store.json"), *NETWORK, false).unwrap();

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
    fn test_conflicting_stored_peers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peer_store.json");

        // A data store holding a later record of a peer at another IP keeps the earliest record.
        let mut moved = BASE_PEERS[0].clone();
        moved.contents.ip = "10.0.0.2".parse().unwrap();
        let contents = Contents::V1 {
            peers: vec![BASE_PEERS[0].clone(), moved],
            cidrs: vec![],
        };
        std::fs::write(&path, serde_json::to_string(&contents).unwrap()).unwrap();
        let store = DataStore::open_with_path(&path, *NETWORK, false).unwrap();
        assert_eq!(store.peers(), &*BASE_PEERS);
    }

    #[test]
    fn test_created_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peer_store.json");
        DataStore::open_with_path(&path, *NETWORK, true).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o077, 0);
    }

    #[test]
    fn test_invalid_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peer_store.json");

        // An empty file is a new data store.
        File::create(&path).unwrap();
        let store = DataStore::open_with_path(&path, *NETWORK, false).unwrap();
        assert!(store.peers().is_empty());

        // A file that fails to parse is refused rather than replaced, even if it is only whitespace.
        std::fs::write(&path, r#"{"version": "1", "peers": [{"#).unwrap();
        assert!(DataStore::open_with_path(&path, *NETWORK, false).is_err());
        std::fs::write(&path, "\n").unwrap();
        assert!(DataStore::open_with_path(&path, *NETWORK, false).is_err());
    }

    #[test]
    fn test_forget_peer_allows_ip_reuse() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store =
            DataStore::open_with_path(dir.path().join("peer_store.json"), *NETWORK, false).unwrap();

        // A second peer follows the forgotten one, so that its index is shifted.
        let mut second = BASE_PEERS[0].clone();
        second.contents.ip = "10.0.0.2".parse().unwrap();
        second.contents.public_key = "HX6Se15qwliiWM7l3iCVAtK+FXNfHRFeEq8UFRK8BBk=".to_string();
        let mut peers = BASE_PEERS.clone();
        peers.push(second.clone());
        assert!(store.update_peers(&peers).is_empty());

        let mut replacement = peers.clone();
        replacement[0].contents.public_key =
            "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes=".to_string();
        assert_eq!(store.update_peers(&replacement).len(), 1);

        store.forget_peer(&BASE_PEERS[0].public_key).unwrap();
        assert!(store.forget_peer(&BASE_PEERS[0].public_key).is_err());
        assert_eq!(store.peers.check(&second), PinStatus::Unchanged);

        // The forgotten state is persisted.
        let mut store =
            DataStore::open_with_path(dir.path().join("peer_store.json"), *NETWORK, false).unwrap();
        assert_eq!(store.peers(), &[second.clone()]);
        assert!(store.update_peers(&replacement).is_empty());
        assert_eq!(store.peers(), &[second, replacement[0].clone()]);
    }

    #[test]
    fn test_peer_persistence() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store =
            DataStore::open_with_path(dir.path().join("peer_store.json"), *NETWORK, false).unwrap();

        // Should work, since peer is unmodified.
        assert!(store.update_peers(&[]).is_empty());
        assert_eq!(store.peers(), &disabled(&BASE_PEERS)[..]);
    }

    #[test]
    fn test_introduce() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peer_store.json");
        let mut introduced = BASE_PEERS[0].clone();
        introduced.id = INTRODUCED_COORDINATOR_ID;
        introduced.contents.name = None;

        // A fresh data store pins the introduced peer before the first fetch.
        let mut store = DataStore::open_with_path(&path, *NETWORK, true).unwrap();
        store.introduce(vec![introduced.clone()]);
        assert_eq!(store.peers(), &[introduced.clone()]);

        let mut conflicting = BASE_PEERS.clone();
        conflicting[0].contents.public_key =
            "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes=".to_string();
        assert_eq!(store.update_peers(&conflicting).len(), 1);

        // The fetched record of the introduced peer replaces the introduced record, which a later
        // introduction leaves in place.
        let mut store = DataStore::open_with_path(&path, *NETWORK, true).unwrap();
        store.introduce(vec![introduced.clone()]);
        assert!(store.update_peers(&BASE_PEERS).is_empty());
        store.introduce(vec![introduced]);
        assert_eq!(store.peers(), &*BASE_PEERS);
    }
}
