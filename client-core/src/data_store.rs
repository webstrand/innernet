use anyhow::{bail, Error};
use innernet_shared::{
    ensure_dirs_exist, interface_config::InterfaceConfig, Cidr, Hostname, IoErrorContext, Peer,
    PeerContents, State, WrappedIoError,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
use wireguard_control::{InterfaceName, Key};

/// File-backed storage of [`Peer`]s and [`Cidr`]s.
///
/// The file is stored at [`Self::get_path()`].
#[derive(Debug)]
pub struct DataStore {
    file: File,
    contents: Contents,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "version")]
enum Contents {
    #[serde(rename = "1")]
    V1 { peers: Vec<Peer>, cidrs: Vec<Cidr> },
}

impl DataStore {
    fn open_with_path<P: AsRef<Path>>(path: P, create: bool) -> Result<Self, WrappedIoError> {
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
        let contents = match serde_json::from_str(&json) {
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

        Ok(Self { file, contents })
    }

    /// Produce the path "`data_dir`/`interface`.json".
    pub fn get_path(data_dir: &Path, interface: &InterfaceName) -> PathBuf {
        data_dir.join(interface.to_string()).with_extension("json")
    }

    fn _open(
        data_dir: &Path,
        interface: &InterfaceName,
        create: bool,
    ) -> Result<Self, WrappedIoError> {
        ensure_dirs_exist(&[data_dir])?;
        Self::open_with_path(Self::get_path(data_dir, interface), create)
    }

    /// Open the data store residing at "`data_dir`/`interface`.json".
    pub fn open(data_dir: &Path, interface: &InterfaceName) -> Result<Self, WrappedIoError> {
        Self::_open(data_dir, interface, false)
    }

    /// Open or create the data store residing at "`data_dir`/`interface`.json".
    pub fn open_or_create(
        data_dir: &Path,
        interface: &InterfaceName,
    ) -> Result<Self, WrappedIoError> {
        Self::_open(data_dir, interface, true)
    }

    /// Records the coordinator and this client as the interface config introduces them, and
    /// writes the data store. This is the introduction, when an invitation is redeemed, so the
    /// data store must be new.
    ///
    /// The interface config, which the invitation produced, is the authority on both, so their
    /// (IP, PublicKey) tuples are pinned before the coordination server reports anything. Each
    /// record is named by its public key until a fetch replaces it with the server's record.
    pub fn introduce(&mut self, config: &InterfaceConfig) -> Result<(), Error> {
        let peers = match &mut self.contents {
            Contents::V1 { ref mut peers, .. } => peers,
        };
        if !peers.is_empty() {
            bail!("the data store to introduce peers into is not new.");
        }
        peers.extend(introduced_peers(config)?);
        self.write()?;

        Ok(())
    }

    /// Merges the peers of `state` into the data store, replaces its CIDRs with those of `state`,
    /// and writes it to disk.
    ///
    /// A peer that the data store already holds is updated, a new peer is added, and a peer that
    /// is absent from `state` is disabled rather than deleted, so that its (IP, PublicKey) tuple
    /// remains pinned. The update is refused if any peer of `state` has a pinned IP with a
    /// different public key, or a pinned public key at a different IP.
    ///
    /// Pinning prevents a compromised server from impersonating an existing peer, but not from
    /// adding a new peer under its control.
    pub fn update(&mut self, state: &State) -> Result<(), Error> {
        self.update_peers(&state.peers)?;
        self.set_cidrs(state.cidrs.clone());
        self.write()?;

        Ok(())
    }

    fn update_peers(&mut self, new_peers: &[Peer]) -> Result<(), Error> {
        let peers = match &mut self.contents {
            Contents::V1 { ref mut peers, .. } => peers,
        };

        for new_peer in new_peers.iter() {
            for existing_peer in peers.iter() {
                if existing_peer.ip == new_peer.ip
                    && existing_peer.public_key != new_peer.public_key
                {
                    bail!("PINNING ERROR: New peer has same IP but different public key.");
                }
                if existing_peer.public_key == new_peer.public_key
                    && existing_peer.ip != new_peer.ip
                {
                    bail!("PINNING ERROR: New peer has same public key but different IP.");
                }
            }
        }

        for new_peer in new_peers.iter() {
            if let Some(existing_peer) = peers
                .iter_mut()
                .find(|p| p.public_key == new_peer.public_key)
            {
                *existing_peer = new_peer.clone();
            } else {
                peers.push(new_peer.clone());
            }
        }

        for existing_peer in peers.iter_mut() {
            if !new_peers
                .iter()
                .any(|p| p.public_key == existing_peer.public_key)
            {
                existing_peer.contents.is_disabled = true;
            }
        }

        Ok(())
    }

    pub fn peers(&self) -> &[Peer] {
        match &self.contents {
            Contents::V1 { peers, .. } => peers,
        }
    }

    pub fn cidrs(&self) -> &[Cidr] {
        match &self.contents {
            Contents::V1 { cidrs, .. } => cidrs,
        }
    }

    fn set_cidrs(&mut self, new_cidrs: Vec<Cidr>) {
        match &mut self.contents {
            Contents::V1 { ref mut cidrs, .. } => *cidrs = new_cidrs,
        }
    }

    fn write(&mut self) -> Result<(), io::Error> {
        self.file.rewind()?;
        self.file.set_len(0)?;
        self.file
            .write_all(serde_json::to_string_pretty(&self.contents)?.as_bytes())?;
        Ok(())
    }
}

/// The ID of the record of the coordinator from the interface config. Server IDs are positive, so
/// it never collides with the ID of a fetched peer.
const INTRODUCED_COORDINATOR_ID: i64 = -1;
/// The ID of the record of this client from the interface config.
const INTRODUCED_SELF_ID: i64 = -2;

/// The coordinator and this client, as the interface config introduces them. Each record is named
/// by its public key, and has no CIDR.
fn introduced_peers(config: &InterfaceConfig) -> Result<[Peer; 2], Error> {
    let introduced = |id, ip, public_key: String, endpoint| Peer {
        id,
        contents: PeerContents {
            name: Hostname::placeholder(&public_key),
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
        },
    };
    // The server's key is compared as the string that the server reports, as the config holds it.
    let server_key = config.server.public_key.clone();
    let own_key = Key::from_base64(&config.interface.private_key)?
        .get_public()
        .to_base64();
    Ok([
        introduced(
            INTRODUCED_COORDINATOR_ID,
            config.server.internal_endpoint.ip(),
            server_key,
            Some(config.server.external_endpoint.clone()),
        ),
        introduced(
            INTRODUCED_SELF_ID,
            config.interface.address.addr(),
            own_key,
            None,
        ),
    ])
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

    fn setup_basic_store(dir: &Path) {
        let mut store = DataStore::open_with_path(dir.join("peer_store.json"), true).unwrap();

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

    #[test]
    fn test_sanity() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let store = DataStore::open_with_path(dir.path().join("peer_store.json"), false).unwrap();
        assert_eq!(store.peers(), &*BASE_PEERS);
        assert_eq!(store.cidrs(), &*BASE_CIDRS);
    }

    #[test]
    fn test_pinning() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store =
            DataStore::open_with_path(dir.path().join("peer_store.json"), false).unwrap();

        // Should work, since peer is unmodified.
        store.update_peers(&BASE_PEERS).unwrap();

        let mut modified = BASE_PEERS.clone();
        modified[0].contents.public_key = "foo".to_string();

        // Should NOT work, since peer is unmodified.
        assert!(store.update_peers(&modified).is_err());
    }

    #[test]
    fn test_pinning_public_key_to_ip() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store =
            DataStore::open_with_path(dir.path().join("peer_store.json"), false).unwrap();

        // The same public key reported at another IP is refused.
        let mut moved = BASE_PEERS.clone();
        moved[0].contents.ip = "10.0.0.2".parse().unwrap();
        assert!(store.update_peers(&moved).is_err());
        assert_eq!(store.peers(), &*BASE_PEERS);

        // Other changes to a pinned peer are applied in place, and new peers are added.
        let mut updated = BASE_PEERS.clone();
        updated[0].contents.name = "renamed".parse().unwrap();
        let mut new_peer = BASE_PEERS[0].clone();
        new_peer.contents.ip = "10.0.0.2".parse().unwrap();
        new_peer.contents.public_key = "def".to_string();
        updated.push(new_peer);
        store.update_peers(&updated).unwrap();
        assert_eq!(store.peers(), &updated[..]);
    }

    #[test]
    fn test_created_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peer_store.json");
        DataStore::open_with_path(&path, true).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o077, 0);
    }

    #[test]
    fn test_invalid_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peer_store.json");

        // An empty file is a new data store.
        File::create(&path).unwrap();
        let store = DataStore::open_with_path(&path, false).unwrap();
        assert!(store.peers().is_empty());

        // A file that fails to parse is refused rather than replaced, even if it is only whitespace.
        std::fs::write(&path, r#"{"version": "1", "peers": [{"#).unwrap();
        assert!(DataStore::open_with_path(&path, false).is_err());
        std::fs::write(&path, "\n").unwrap();
        assert!(DataStore::open_with_path(&path, false).is_err());
    }

    #[test]
    fn test_peer_persistence() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store =
            DataStore::open_with_path(dir.path().join("peer_store.json"), false).unwrap();

        // Should work, since peer is unmodified.
        store.update_peers(&[]).unwrap();
        let new_peers = BASE_PEERS
            .iter()
            .cloned()
            .map(|mut p| {
                p.contents.is_disabled = true;
                p
            })
            .collect::<Vec<_>>();
        assert_eq!(store.peers(), &new_peers);
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
        let path = dir.path().join("peer_store.json");

        // A new data store pins the coordinator and this client, named by their public keys.
        let mut store = DataStore::open_with_path(&path, true).unwrap();
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
        assert!(store.update_peers(&moved).is_err());
        let mut replaced = [COORDINATOR.clone()];
        replaced[0].contents.public_key =
            "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes=".to_string();
        assert!(store.update_peers(&replaced).is_err());

        // The server's record of the coordinator replaces the introduced one.
        store
            .update_peers(std::slice::from_ref(&*COORDINATOR))
            .unwrap();
        assert_eq!(store.peers()[0], *COORDINATOR);
        assert_eq!(store.peers().len(), 2);

        // Only a new data store is introduced.
        assert!(store.introduce(&config).is_err());
        assert_eq!(store.peers().len(), 2);
    }
}
