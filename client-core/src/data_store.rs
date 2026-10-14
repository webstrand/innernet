use anyhow::{bail, Error};
use innernet_shared::{
    ensure_dirs_exist, interface_config::InterfaceConfig, Cidr, IoErrorContext, Peer, State,
    WrappedIoError,
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
use wireguard_control::InterfaceName;

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
        innernet_shared::warn_on_dangerous_mode(path).with_path(path)?;

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
                    peer.name,
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
        Self::open_with_path(
            Self::get_path(data_dir, interface),
            config.interface.address,
            create,
        )
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
                name: "blah".parse().unwrap(),
                ip: "10.0.0.1".parse().unwrap(),
                cidr_id: 1,
                public_key: "abc".to_string(),
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
        modified[0].contents.public_key = "foo".to_string();

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
        updated[0].contents.name = "renamed".parse().unwrap();
        let mut new_peer = BASE_PEERS[0].clone();
        new_peer.contents.ip = "10.0.0.2".parse().unwrap();
        new_peer.contents.public_key = "def".to_string();
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
        new_peer.contents.public_key = "def".to_string();
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
        new_peer.contents.public_key = "def".to_string();
        same_ip.push(new_peer.clone());
        new_peer.contents.public_key = "ghi".to_string();
        same_ip.push(new_peer);
        let dropped = store.update_peers(&same_ip);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].0, &same_ip[2]);
        assert_eq!(store.peers(), &same_ip[..2]);

        // Of two new peers with the same public key, the first is kept and the second dropped.
        let mut same_public_key = same_ip[..2].to_vec();
        let mut new_peer = BASE_PEERS[0].clone();
        new_peer.contents.ip = "10.0.0.3".parse().unwrap();
        new_peer.contents.public_key = "jkl".to_string();
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
    fn test_peer_persistence() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store =
            DataStore::open_with_path(dir.path().join("peer_store.json"), *NETWORK, false).unwrap();

        // Should work, since peer is unmodified.
        assert!(store.update_peers(&[]).is_empty());
        assert_eq!(store.peers(), &disabled(&BASE_PEERS)[..]);
    }
}
