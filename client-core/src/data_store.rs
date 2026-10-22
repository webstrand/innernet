use anyhow::{anyhow, bail, ensure, Context as _, Error};
use innernet_node::{
    accept::{self, Accepted, Received, Refusal},
    db::{self, Scope},
    snapshot::{self, Own, Snapshot, SnapshotConfig},
    store::{self as node_store, key_to_bytes, EndpointKind},
    Store,
};
use innernet_shared::{
    announcement::{self, Announcement, SignedAnnouncement},
    ensure_dirs_exist,
    interface_config::InterfaceConfig,
    Cidr, IoErrorContext, LegacyCidr, LegacyPeer, PeerContents, Prefix, State,
};
use ipnet::IpNet;
use rusqlite::{params, Connection, OptionalExtension as _};
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    fs::OpenOptions,
    io,
    net::IpAddr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::UNIX_EPOCH,
};
use wireguard_control::{InterfaceName, Key};

/// The node's database of a client, which holds the peers and [`Cidr`]s that the coordination
/// server reported, the announcements of the peers, and what each peer claims, pinned to its
/// public key, in the schema of [`innernet_node::SCHEMA`]. Every read goes to the database.
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
/// store checks the peers that the coordination server reports.
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

/// How the coordination server relays the announcements of the peers, which tells
/// [`DataStore::update`] where the announcement of each peer comes from.
#[derive(Clone, Copy, Debug)]
pub enum Relay<'a> {
    /// The server relays an announcement with each peer, signed by the peer, or, for a peer that
    /// has never announced, unsigned, as the server makes it, and checks the claims of the types
    /// that it lists.
    Announcements(&'a [String]),
    /// The server predates announcements, so it relays none: each peer is taken to make the
    /// unsigned announcement that [`Announcement::synthetic`] makes of what the server reports of
    /// it, as a server that relays announcements would make it.
    Synthesized,
    /// The server may relay announcements, but this client can't tell which types of claims it
    /// checks, so it accepts none of them.
    Unknown,
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

        let legacy = legacy_path.to_owned();
        let import: db::CreateHook = Arc::new(move |scope| import_legacy(scope, &legacy));
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

    /// Records the coordinator and this client as the interface config introduces them, and
    /// writes the data store. This is the introduction, when an invitation is redeemed, so the
    /// data store must be new.
    ///
    /// The invitation, which produced the interface config, is the authority on both, so each is
    /// taken to make the unsigned announcement that [`Announcement::synthetic`] makes of its
    /// record, whose addresses are pinned to its public key before the coordination server
    /// reports anything: the coordinator's internal address, and `delegations`, those that the
    /// invitation offers this client. Neither has a name until an announcement claims one.
    pub fn introduce(
        &mut self,
        config: &InterfaceConfig,
        delegations: &[Prefix],
    ) -> Result<(), Error> {
        let introduced = introduced_peers(config, delegations)?;
        self.transact(|tx| {
            let recorded: i64 = tx.query_row("SELECT count(*) FROM peers", [], |r| r.get(0))?;
            if recorded > 0 {
                bail!("the data store to introduce peers into is not new.");
            }
            let all_types = accept::all_claim_types();
            let mut synthetic = vec![];
            for introduced in &introduced {
                write_peer(tx, introduced)?;
                synthetic.push(SignedAnnouncement::unsigned(&Announcement::synthetic(
                    introduced,
                ))?);
            }
            let received: Vec<Received> = introduced
                .iter()
                .zip(&synthetic)
                .map(|(peer, announcement)| Received {
                    public_key: &peer.public_key,
                    announcement,
                    checked_types: &all_types,
                    repeats: true,
                })
                .collect();
            let now = announcement::timestamp_now();
            for accepted in tx.accept(&received, now)? {
                accepted.map_err(|refusal| anyhow!("{refusal}"))?;
            }
            Ok(())
        })
    }

    /// Merges the peers of `state` into the data store, replaces its CIDRs with those of `state`,
    /// and writes it to disk. Returns the peers of `state` that were dropped, each with the reason
    /// that it was dropped.
    ///
    /// A peer that the data store already holds is updated, a new peer is added, and a peer that
    /// is absent from `state` is disabled rather than deleted, so that what it claims remains
    /// pinned to its public key. A peer of `state` is dropped whole if one of its delegations lies
    /// outside the network of the interface, if it shares its public key or one of its delegations
    /// with an earlier peer of `state`. The coordinator is checked as every other peer is. A
    /// dropped peer is absent from the update, so a pinned peer that it conflicts with is
    /// disabled, while the stored record of a dropped peer with a pinned key is kept as it was.
    ///
    /// The announcement of each peer comes as `relay` tells, and the node core accepts or refuses
    /// it, as [`innernet_node::db::Scope::decide`] decides. A refused announcement is ignored with
    /// a warning, so that it never fails an update, and the last one accepted from the peer stays:
    /// the server can neither forge, alter nor take back what a peer announces.
    ///
    /// What each peer claims is then pinned to its key. A signed announcement pins what it claims
    /// and releases what it no longer claims; an unsigned one, which the server makes for a peer
    /// that has never announced, pins what it claims beside what is pinned already, as
    /// [`innernet_node::claims::Claim::unsigned`] adds it, and releases nothing, so that the server
    /// alone can't move what such a peer holds to another key. An announcement that claims what is
    /// pinned to another key is refused whole; a peer whose first announcement is refused is
    /// dropped. Pinning prevents a compromised server from handing what a peer claims to another
    /// key, but not from adding a new peer under its control, nor from deciding what a peer claims
    /// before a client first sees it.
    pub fn update<'a>(
        &mut self,
        state: &'a State,
        relay: Relay,
    ) -> Result<Vec<(&'a PeerContents, Error)>, Error> {
        let network = self.network.clone();
        let dropped = self.transact(|tx| {
            let dropped =
                update_reported_peers(tx, &network, &state.peers, &state.invalid_peer_keys, relay)?;
            write_cidrs(tx, &state.cidrs)?;
            Ok(dropped)
        })?;
        self.warn_if_own_address_lost()?;
        Ok(dropped)
    }

    /// Merges `new_peers`, as a server that relays announcements reports them, and checks every
    /// type of claim.
    #[cfg(test)]
    fn relay_peers<'a>(&mut self, new_peers: &'a [PeerContents]) -> Vec<(&'a PeerContents, Error)> {
        let claim_types = accept::all_claim_types();
        let network = self.network.clone();
        self.transact(|tx| {
            update_reported_peers(
                tx,
                &network,
                new_peers,
                &[],
                Relay::Announcements(&claim_types),
            )
        })
        .unwrap()
    }

    /// Merges `new_peers`, as a server that predates announcements reports them, so that each
    /// is taken to make the unsigned announcement of its record.
    #[cfg(test)]
    fn update_peers<'a>(
        &mut self,
        new_peers: &'a [PeerContents],
    ) -> Vec<(&'a PeerContents, Error)> {
        let network = self.network.clone();
        self.transact(|tx| update_reported_peers(tx, &network, new_peers, &[], Relay::Synthesized))
            .unwrap()
    }

    /// The peers, as the coordination server last reported them, but named as they claim,
    /// without their announcements, as [`node_store::load_peers`] reads them.
    pub fn peers(&self) -> Result<Vec<PeerContents>, Error> {
        Ok(node_store::load_peers(&self.store)?)
    }

    /// The last announcement accepted from the peer with `public_key`, if any.
    pub fn announcement(&self, public_key: &str) -> Result<Option<Announcement>, Error> {
        let key = key_to_bytes(public_key)?;
        Ok(node_store::load_announcements(&self.store, Some(&key))?
            .remove(public_key)
            .map(|stored| stored.announcement))
    }

    /// Whether the peer with `public_key` has signed an announcement that this client accepted,
    /// after which only its signed announcements are accepted.
    pub fn announces(&self, public_key: &str) -> Result<bool, Error> {
        Ok(node_store::announces(&self.store, &key_to_bytes(public_key)?)?.unwrap_or(false))
    }

    /// The peers as they take effect, as [`snapshot::effective`] makes each of the last
    /// announcement accepted from it, in the order of [`Self::peers`]. A peer without an accepted
    /// announcement is routed nothing.
    pub fn effective_peers(&self) -> Result<Vec<PeerContents>, Error> {
        let announcements = node_store::load_announcements(&self.store, None)?;
        Ok(self
            .peers()?
            .iter()
            .map(|peer| {
                let announcement = announcements.get(&peer.public_key);
                snapshot::effective(peer, announcement.map(|stored| &stored.announcement))
            })
            .collect())
    }

    /// The peer with `public_key` as it takes effect, as [`Self::effective_peers`] makes it, or
    /// `None` if the data store doesn't record it.
    pub fn effective_peer(&self, public_key: &str) -> Result<Option<PeerContents>, Error> {
        let Some(peer) = node_store::load_peer(&self.store, &key_to_bytes(public_key)?)? else {
            return Ok(None);
        };
        let announcement = self.announcement(public_key)?;
        Ok(Some(snapshot::effective(&peer, announcement.as_ref())))
    }

    /// What this client configures, as the node core makes it of the data store, for `own`, this
    /// client as its config describes it: the peers as they take effect, in the order of
    /// [`Self::peers`], and what this client publishes of them.
    pub fn snapshot(&self, own: Option<Own>) -> Result<Snapshot, Error> {
        self.snapshot_as(&SnapshotConfig::default(), own)
    }

    /// The snapshot of the data store, as `config` configures it, for `own`.
    pub fn snapshot_as(
        &self,
        config: &SnapshotConfig,
        own: Option<Own>,
    ) -> Result<Snapshot, Error> {
        Ok(snapshot::of_store(&self.store, config, own)?)
    }

    /// The prefixes pinned to the keys of the peers, each with its peer.
    pub fn pins(&self) -> Result<Vec<(PeerContents, Prefix)>, Error> {
        let mut claims = node_store::load_claims(&self.store, None)?;
        Ok(self
            .peers()?
            .into_iter()
            .flat_map(|peer| {
                let claim = claims.remove(&peer.public_key).unwrap_or_default();
                claim
                    .delegation
                    .into_iter()
                    .map(move |prefix| (peer.clone(), prefix))
            })
            .collect())
    }

    /// Accepts `signed`, an announcement of the peer with `public_key` that the coordination
    /// server has accepted, with only the claims of `claim_types`, the types that the server
    /// checks, pins what it claims, and writes the data store. It must be newer than the last one
    /// accepted from the peer, which must be recorded, and claim nothing pinned to another key.
    /// This client records its own announcements so.
    pub fn accept_announcement(
        &mut self,
        public_key: &str,
        signed: &SignedAnnouncement,
        claim_types: &[String],
    ) -> Result<(), Error> {
        ensure!(signed.is_signed(), "the announcement is not signed");
        self.transact(|tx| {
            ensure!(
                node_store::announces(tx, &key_to_bytes(public_key)?)?.is_some(),
                "no peer with the public key {public_key} is recorded"
            );
            let received = Received {
                public_key,
                announcement: signed,
                checked_types: claim_types,
                repeats: false,
            };
            let now = announcement::timestamp_now();
            tx.accept_one(&received, now)?
                .map_err(|refusal| anyhow!("{refusal}"))?;
            Ok(())
        })
    }

    pub fn cidrs(&self) -> Result<Vec<Cidr>, Error> {
        Ok(node_store::load_cidrs(&self.store)?)
    }

    /// Whether the peer with `public_key` is known to speak TLS.
    pub fn speaks_tls(&self, public_key: &str) -> Result<bool, Error> {
        let speaks_tls = self
            .store
            .query_row(
                "SELECT tls FROM peers WHERE public_key = ?1",
                [key_to_bytes(public_key)?],
                |r| r.get(0),
            )
            .optional()?;
        Ok(speaks_tls.unwrap_or(false))
    }

    /// Records for good that the peer with `public_key` speaks TLS. The peer must be recorded.
    pub fn latch_tls(&mut self, public_key: &str) -> Result<(), Error> {
        let updated = self.store.execute(
            "UPDATE peers SET tls = 1 WHERE public_key = ?1",
            [key_to_bytes(public_key)?],
        )?;
        ensure!(
            updated == 1,
            "no peer with the public key {public_key} is recorded"
        );
        Ok(())
    }

    /// Whether the data store records the peer with `public_key`.
    pub fn records_peer(&self, public_key: &str) -> Result<bool, Error> {
        Ok(node_store::announces(&self.store, &key_to_bytes(public_key)?)?.is_some())
    }

    /// The UDP port of the TLS API of the peer with `public_key`, the coordinator, which runs over
    /// QUIC at its internal address, or `None` if it is unknown.
    pub fn quic_port(&self, public_key: &str) -> Result<Option<u16>, Error> {
        let port = self
            .store
            .query_row(
                "SELECT quic_port FROM peers WHERE public_key = ?1",
                [key_to_bytes(public_key)?],
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
            params![key_to_bytes(public_key)?, port],
        )?;
        ensure!(
            updated == 1,
            "no peer with the public key {public_key} is recorded"
        );
        Ok(())
    }

    /// Runs `change` in one transaction, which holds the write lock from the start, so that a
    /// change made meanwhile by another process is neither missed nor overwritten.
    fn transact<T>(&mut self, change: impl FnOnce(&Scope) -> Result<T, Error>) -> Result<T, Error> {
        let tx = self.store.transaction()?;
        let result = change(&tx.scope())?;
        tx.commit()?;
        Ok(result)
    }

    /// Warns if the record of this client no longer holds the source address of its interface,
    /// which the coordination server has then withdrawn.
    fn warn_if_own_address_lost(&self) -> Result<(), Error> {
        let Some((own_key, address)) = &self.network.own else {
            return Ok(());
        };
        let own = node_store::load_peer(&self.store, &key_to_bytes(own_key)?)?;
        if own.is_some_and(|own| !own.holds(*address)) {
            log::warn!(
                "the coordination server no longer delegates this client's address {address} to \
                 it, so this client can no longer claim it."
            );
        }
        Ok(())
    }
}

/// Validates that `candidate` lies within `network`, and shares neither a delegation nor its
/// public key with a peer of `accepted`. Its name, if it has one, is valid, as every
/// [`innernet_shared::Hostname`] is.
fn check_reported(
    network: IpNet,
    candidate: &PeerContents,
    accepted: &[&PeerContents],
) -> Result<(), Error> {
    if let Some(outside) = candidate
        .delegations
        .iter()
        .find(|delegation| !network.contains(&delegation.net()))
    {
        bail!("{outside} is outside of the network {network}.");
    }
    if accepted.iter().any(|earlier| {
        earlier.public_key == candidate.public_key
            || earlier.delegations.iter().any(|delegation| {
                candidate
                    .delegations
                    .iter()
                    .any(|other| other.overlaps(delegation))
            })
    }) {
        bail!("its public key or one of its delegations is shared with an earlier peer.");
    }
    Ok(())
}

/// Merges `new_peers` into the data store of `tx`, dropping each that is invalid, and hands the
/// announcement of each to the node core, as [`DataStore::update`] describes. `invalid_peer_keys`
/// are the public keys of the peers that the server reported but that failed to deserialize. Each
/// accepted peer is stored without its announcement, which comes as `relay` tells.
fn update_reported_peers<'a>(
    tx: &Scope,
    network: &Network,
    new_peers: &'a [PeerContents],
    invalid_peer_keys: &[String],
    relay: Relay,
) -> Result<Vec<(&'a PeerContents, Error)>, Error> {
    let mut accepted: Vec<&'a PeerContents> = vec![];
    let mut dropped = vec![];
    for new_peer in new_peers.iter() {
        match check_reported(network.prefix, new_peer, &accepted) {
            Ok(()) => accepted.push(new_peer),
            Err(e) => dropped.push((new_peer, e)),
        }
    }

    // The server leaves disabled peers out of the state, so a stored peer that the state doesn't
    // report is disabled. A dropped peer was reported, so the stored peer with its public key
    // keeps its record unchanged.
    let reported: HashSet<&str> = new_peers
        .iter()
        .map(|peer| peer.public_key.as_str())
        .chain(invalid_peer_keys.iter().map(String::as_str))
        .collect();
    for stored in node_store::load_peers(tx)? {
        if !reported.contains(stored.public_key.as_str()) {
            tx.execute(
                "UPDATE peers SET is_disabled = 1 WHERE public_key = ?1",
                [key_to_bytes(&stored.public_key)?],
            )?;
        }
    }

    // The announcement of each accepted peer, as `relay` tells, which the node core decides.
    let all_types = accept::all_claim_types();
    let (checked_types, synthesized): (&[String], Vec<Option<SignedAnnouncement>>) = match relay {
        Relay::Announcements(claim_types) => (claim_types, vec![]),
        Relay::Synthesized => (
            &all_types,
            accepted
                .iter()
                .map(|peer| {
                    SignedAnnouncement::unsigned(&Announcement::synthetic(peer))
                        .inspect_err(|e| {
                            log::warn!("ignoring the announcement of peer {}: {e}", peer.public_key)
                        })
                        .ok()
                })
                .collect(),
        ),
        Relay::Unknown => (&[], vec![]),
    };
    let received: Vec<Received> = accepted
        .iter()
        .enumerate()
        .filter_map(|(index, peer)| {
            let announcement = match relay {
                Relay::Announcements(_) => peer.announcement.as_ref()?,
                Relay::Synthesized => synthesized[index].as_ref()?,
                Relay::Unknown => return None,
            };
            Some(Received {
                public_key: &peer.public_key,
                announcement,
                checked_types,
                repeats: true,
            })
        })
        .collect();
    let now = announcement::timestamp_now();
    let decided = tx.decide(&received, now)?;

    // A refused announcement is ignored, and the last one accepted from the peer stays. A peer
    // that claims what is pinned to another key without an accepted announcement is dropped, since
    // nothing of it could take effect.
    let mut refused = vec![];
    let mut taken: Vec<Accepted> = vec![];
    for (received, decided) in received.iter().zip(decided) {
        match decided {
            Ok(accepted) => taken.push(accepted),
            Err(Refusal::Pinned(conflict))
                if node_store::load_announcements(
                    tx,
                    Some(&key_to_bytes(received.public_key)?),
                )?
                .is_empty() =>
            {
                refused.push((received.public_key.to_string(), conflict));
            },
            Err(refusal) => log::warn!(
                "ignoring the announcement of peer {}: {refusal}",
                received.public_key
            ),
        }
    }
    for peer in accepted {
        if let Some((_, conflict)) = refused.iter().find(|(key, _)| key == &peer.public_key) {
            dropped.push((
                peer,
                anyhow!(
                    "PINNING ERROR: the peer claims what is pinned to another public key: \
                     {conflict}."
                ),
            ));
            continue;
        }
        // A peer is recorded before what it claims is pinned to its key.
        write_peer(tx, peer)
            .with_context(|| format!("failed to store peer {}", peer.public_key))?;
    }
    tx.apply(&taken)?;

    Ok(dropped)
}

/// Writes `peer`, but for its name, which is the one pinned to its key, its announcement, its
/// delegations and its endpoints. A new peer is recorded without a name. A delegation that the
/// data store records of another peer, which the server no longer reports as that peer's, follows
/// the peer that the server now reports it of.
fn write_peer(tx: &Connection, peer: &PeerContents) -> Result<(), Error> {
    let public_key = key_to_bytes(&peer.public_key)?;
    let invite_expires = peer
        .invite_expires
        .map(|time| time.duration_since(UNIX_EPOCH).map(|d| d.as_secs()))
        .transpose()?;
    tx.execute(
        "INSERT INTO peers (public_key, is_admin, is_disabled, is_redeemed,
                            persistent_keepalive_interval, invite_expires)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (public_key) DO UPDATE SET
           is_admin = excluded.is_admin,
           is_disabled = excluded.is_disabled,
           is_redeemed = excluded.is_redeemed,
           persistent_keepalive_interval = excluded.persistent_keepalive_interval,
           invite_expires = excluded.invite_expires",
        params![
            public_key,
            peer.is_admin,
            peer.is_disabled,
            peer.is_redeemed,
            peer.persistent_keepalive_interval,
            invite_expires,
        ],
    )?;

    tx.execute(
        "DELETE FROM delegations WHERE public_key = ?1",
        params![public_key],
    )?;
    for delegation in &peer.delegations {
        tx.execute(
            "INSERT INTO delegations (address, prefix_len, last, public_key) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (address) DO UPDATE SET prefix_len = excluded.prefix_len,
               last = excluded.last, public_key = excluded.public_key, reclaim = 0",
            params![
                node_store::ip_to_bytes(delegation.first()),
                delegation.prefix_len(),
                node_store::ip_to_bytes(delegation.last()),
                public_key,
            ],
        )?;
    }

    node_store::write_endpoints(tx, &public_key, EndpointKind::Endpoint, &peer.endpoint)?;
    node_store::write_endpoints(tx, &public_key, EndpointKind::Candidate, &peer.candidates)?;
    Ok(())
}

/// Replaces the CIDRs of the database with `cidrs`. They are only displayed, so of two CIDRs with
/// the same prefix or the same name, the first is kept.
fn write_cidrs(tx: &Connection, cidrs: &[Cidr]) -> Result<(), Error> {
    tx.execute("DELETE FROM cidrs", [])?;
    for cidr in cidrs {
        tx.execute(
            "INSERT INTO cidrs (address, prefix_len, name) VALUES (?1, ?2, ?3)
             ON CONFLICT DO NOTHING",
            params![
                node_store::ip_to_bytes(cidr.cidr.first()),
                cidr.cidr.prefix_len(),
                cidr.name
            ],
        )?;
    }
    Ok(())
}

/// Imports the legacy data store at `path` into the new database, if there is one. The import
/// refuses, rather than repairs, a data store that holds an invalid public key, a peer outside the
/// network or two records in conflict. The file itself is left untouched, so that earlier
/// versions still find their pins in it.
fn import_legacy(tx: &Scope, path: &Path) -> Result<(), Error> {
    let network = tx.network();
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
    let all_types = accept::all_claim_types();
    let mut imported = HashMap::new();
    for LegacyPeer { contents: peer, .. } in &peers {
        ensure!(
            network.contains(&peer.ip),
            "{}: peer {} at {} is outside of the network {}",
            path.display(),
            peer.public_key,
            peer.ip,
            network,
        );
        let imported_ip = *imported.entry(&peer.public_key).or_insert(peer.ip);
        ensure!(
            imported_ip == peer.ip,
            "{}: peer {} is at both {} and {}",
            path.display(),
            peer.public_key,
            imported_ip,
            peer.ip,
        );
        // An imported peer is taken to make the unsigned announcement of what the data store held
        // of it, as a server that predates announcements would report it, which the node core
        // accepts at once, so that what it claims, its name included, is pinned.
        let peer = PeerContents::from(peer.clone());
        (|| -> Result<(), Error> {
            write_peer(tx, &peer)?;
            let synthetic = SignedAnnouncement::unsigned(&Announcement::synthetic(&peer))?;
            let received = Received {
                public_key: &peer.public_key,
                announcement: &synthetic,
                checked_types: &all_types,
                repeats: true,
            };
            tx.accept_one(&received, 0)?
                .map_err(|refusal| anyhow!("{refusal}"))?;
            Ok(())
        })()
        .with_context(|| {
            format!(
                "{}: failed to import peer {} at {}",
                path.display(),
                peer.public_key,
                peer.display_address()
            )
        })?;
    }
    // A CIDR whose address has host bits set is the prefix of its network, as the server read it.
    let cidrs: Vec<Cidr> = cidrs.into_iter().map(Cidr::from).collect();
    write_cidrs(tx, &cidrs)?;
    log::info!(
        "imported {} peers from {} into the new data store.",
        peers.len(),
        path.display()
    );

    Ok(())
}

/// The coordinator, at its internal address, and this client, with the delegations
/// `delegations`, as the interface config and the invitation introduce them. Neither record has a
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
    use innernet_shared::{announcement::Claims, Cidr, LegacyCidrContents, LegacyPeerContents};
    use once_cell::sync::Lazy;
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

    fn open(dir: &Path, create: bool) -> Result<DataStore, Error> {
        DataStore::open_with_paths(&db_path(dir), &legacy_path(dir), network(*NETWORK), create)
    }

    /// The network `prefix`, without a record of this client.
    fn network(prefix: IpNet) -> Network {
        Network { prefix, own: None }
    }

    /// Writes a legacy data store of `peers` and `cidrs`, as earlier versions wrote it, with the
    /// server IDs of the peers and of the CIDRs, numbered from 1, each peer in the first CIDR.
    fn write_legacy(dir: &Path, peers: &[PeerContents], cidrs: &[Cidr]) {
        let peers: Vec<_> = peers
            .iter()
            .enumerate()
            .map(|(i, contents)| LegacyPeer {
                id: i as i64 + 1,
                contents: LegacyPeerContents::from_peer(contents, 1).unwrap(),
            })
            .collect();
        let cidrs: Vec<_> = cidrs
            .iter()
            .enumerate()
            .map(|(i, cidr)| LegacyCidr {
                id: i as i64 + 1,
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
            .update(
                &State {
                    peers: BASE_PEERS.to_owned(),
                    cidrs: BASE_CIDRS.to_owned(),
                    observed_endpoint: None,
                    invalid_peer_keys: vec![],
                },
                Relay::Synthesized,
            )
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
        assert_eq!(store.peers().unwrap(), &disabled(&BASE_PEERS)[..]);
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
        assert_eq!(store.peers().unwrap(), &wider[..]);
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
        let without = without;
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

        // The same public key reported at another IP is accepted, and the IP it held stays pinned
        // to it, but is no longer routed to it.
        let mut moved = BASE_PEERS.clone();
        moved[0].delegations = host("10.0.0.2");
        assert!(store.update_peers(&moved).is_empty());
        assert_eq!(store.peers().unwrap(), &moved[..]);
        assert_eq!(rows_of(&store, "prefix_pins", &BASE_PEERS[0].public_key), 2);
        assert_eq!(rows_of(&store, "delegations", &BASE_PEERS[0].public_key), 1);

        // Another key is refused at either IP, and the pinned peer is disabled, since the update
        // leaves it out.
        let other_key = "HX6Se15qwliiWM7l3iCVAtK+FXNfHRFeEq8UFRK8BBk=";
        for ip in ["10.0.0.1", "10.0.0.2"] {
            let mut other = BASE_PEERS[0].clone();
            other.delegations = host(ip);
            other.public_key = other_key.to_string();
            assert_eq!(store.update_peers(&[other]).len(), 1);
        }
        assert_eq!(store.peers().unwrap(), &disabled(&moved)[..]);

        // Other changes to a pinned peer are applied in place, but for its name, which stays
        // pinned, and new peers are added.
        let mut updated = BASE_PEERS.clone();
        updated[0].is_admin = true;
        let mut new_peer = BASE_PEERS[0].clone();
        new_peer.delegations = host("10.0.0.3");
        new_peer.public_key = other_key.to_string();
        new_peer.name = Some("new".parse().unwrap());
        updated.push(new_peer);
        let mut renamed = updated.clone();
        renamed[0].name = Some("renamed".parse().unwrap());
        assert!(store.update_peers(&renamed).is_empty());
        assert_eq!(store.peers().unwrap(), &updated[..]);
        assert_eq!(
            open(dir.path(), false).unwrap().peers().unwrap(),
            &updated[..]
        );
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
            .update(&state(&[base.clone(), invalid]), Relay::Synthesized)
            .unwrap()
            .is_empty());
        new_peer.name = None;
        assert_eq!(
            store.peers().unwrap(),
            [BASE_PEERS[0].clone(), new_peer.clone()]
        );

        // A stored peer renamed to an invalid name keeps the name pinned to its key, and stays
        // enabled.
        let mut renamed = base;
        renamed["name"] = "Blah".into();
        let renamed_new = serde_json::to_value(&new_peer).unwrap();
        assert!(store
            .update(&state(&[renamed, renamed_new]), Relay::Synthesized)
            .unwrap()
            .is_empty());
        assert_eq!(store.peers().unwrap(), [BASE_PEERS[0].clone(), new_peer]);
    }

    #[test]
    fn test_peers_without_a_name() {
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let mut store = open(dir.path(), false).unwrap();

        // Any number of peers can be without a name.
        let mut nameless = BASE_PEERS.clone();
        for (ip, key) in [
            ("10.0.0.2", "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes="),
            ("10.0.0.3", "HX6Se15qwliiWM7l3iCVAtK+FXNfHRFeEq8UFRK8BBk="),
        ] {
            nameless.push(PeerContents {
                name: None,
                delegations: host(ip),
                public_key: key.to_string(),
                ..BASE_PEERS[0].clone()
            });
        }
        assert!(store.update_peers(&nameless).is_empty());
        assert_eq!(store.peers().unwrap(), &nameless[..]);
        assert_eq!(
            open(dir.path(), false).unwrap().peers().unwrap(),
            &nameless[..]
        );

        // A peer without a name takes one that it claims, while an unsigned announcement that
        // claims no name leaves the name pinned to the key of a peer that has one.
        let mut named = nameless.clone();
        named[0].name = None;
        named[1].name = Some("named".parse().unwrap());
        assert!(store.update_peers(&named).is_empty());
        assert_eq!(store.peers().unwrap()[0], BASE_PEERS[0]);
        assert_eq!(store.peers().unwrap()[1].name, named[1].name);
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
        assert!(store.update(&state, Relay::Synthesized).unwrap().is_empty());
        assert_eq!(store.peers().unwrap(), *BASE_PEERS);

        // A peer that isn't reported at all is disabled.
        let state: State =
            serde_json::from_value(serde_json::json!({ "peers": [], "cidrs": *BASE_CIDRS }))
                .unwrap();
        store.update(&state, Relay::Synthesized).unwrap();
        assert_eq!(store.peers().unwrap(), &disabled(&BASE_PEERS)[..]);
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
        new_peer.public_key = "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes=".to_string();
        same_ip.push(new_peer);
        let dropped = store.update_peers(&same_ip);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].0, &same_ip[2]);
        assert_eq!(store.peers().unwrap(), &same_ip[..2]);

        // Of two new peers with the same public key, the first is kept and the second dropped.
        let mut same_public_key = same_ip[..2].to_vec();
        let mut new_peer = BASE_PEERS[0].clone();
        new_peer.name = Some("third".parse().unwrap());
        new_peer.delegations = host("10.0.0.3");
        new_peer.public_key = "9fNiSxgLIPEqRALrIpaK2a77aiPz/CZCpQVQtF7o4v0=".to_string();
        same_public_key.push(new_peer.clone());
        new_peer.delegations = host("10.0.0.4");
        same_public_key.push(new_peer);
        let dropped = store.update_peers(&same_public_key);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].0, &same_public_key[3]);
        assert_eq!(store.peers().unwrap(), &same_public_key[..3]);
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
        assert_eq!(store.peers().unwrap(), &disabled(&BASE_PEERS)[..]);
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
    fn test_introduce() {
        let dir = tempfile::tempdir().unwrap();
        let own_key = wireguard_control::KeyPair::generate();
        let config = introducing_config(&own_key);

        // A new data store pins the coordinator at its internal address, and this client to the
        // delegations that the invitation offers it, without a name.
        let mut store = DataStore::open_with_paths(
            &db_path(dir.path()),
            &legacy_path(dir.path()),
            Network::from_config(&config).unwrap(),
            true,
        )
        .unwrap();
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
        assert_eq!(
            peers[1].delegations,
            [offered[1], offered[0]],
            "sorted, as delegations are"
        );
        assert_eq!(peers[1].public_key, own_key.public.to_base64());
        assert_eq!(peers[1].name, None);

        // The coordinator is checked as every other peer is, so it may be reported at another
        // address, which then takes effect. Its unsigned announcement releases nothing, so its
        // internal address stays pinned to its key, and no other key can be reported at it.
        let mut moved = [COORDINATOR.clone()];
        moved[0].delegations = host("10.0.0.3");
        assert!(store.update_peers(&moved).is_empty());
        let coordinator = store
            .effective_peer(&COORDINATOR.public_key)
            .unwrap()
            .unwrap();
        assert_eq!(coordinator.delegations, host("10.0.0.3"));
        assert_eq!(coordinator.primary_ip, Some("10.0.0.3".parse().unwrap()));
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
        v4.invite_expires = Some(UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000));
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
            .update(
                &State {
                    peers: varied_peers(),
                    cidrs,
                    observed_endpoint: None,
                    invalid_peer_keys: vec![],
                },
                Relay::Synthesized,
            )
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
            assert_eq!(cidrs, &expected_cidrs[..]);
            assert_eq!(store.peers().unwrap(), &expected_peers[..]);
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
        let mut peer = BASE_PEERS[0].clone();
        peer.delegations = host("fd00::1");
        peer.endpoint = Some("[::ffff:203.0.113.1]:51820".parse().unwrap());
        let mut store = DataStore::open_with_paths(
            &db_path(dir.path()),
            &legacy_path(dir.path()),
            network("fd00::/64".parse().unwrap()),
            true,
        )
        .unwrap();
        assert!(store.update_peers(std::slice::from_ref(&peer)).is_empty());
        assert_eq!(store.peers().unwrap(), std::slice::from_ref(&peer));
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
        assert_eq!(store.peers().unwrap(), &expected_peers[..]);
        let mut expected_cidrs = varied_cidrs();
        expected_cidrs.sort_by_key(|c| c.cidr);
        assert_eq!(store.cidrs().unwrap(), &expected_cidrs[..]);

        // From then on the database is the data store, and the legacy one is never read again.
        store.update_peers(&[]);
        write_legacy(dir.path(), &[], &[]);
        let store = open(dir.path(), false).unwrap();
        assert_eq!(store.peers().unwrap(), &disabled(&expected_peers)[..]);
        write_legacy(dir.path(), &legacy_peers, &varied_cidrs());
        assert_eq!(std::fs::read(legacy_path(dir.path())).unwrap(), legacy);
    }

    #[test]
    fn test_connection_settings() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(dir.path(), true).unwrap();
        let conn = &*store.store;
        let pragma = |name| -> i64 { conn.pragma_query_value(None, name, |r| r.get(0)).unwrap() };
        assert_eq!(pragma("foreign_keys"), 1);
        assert_eq!(pragma("trusted_schema"), 0);
        assert_eq!(
            pragma("busy_timeout"),
            std::time::Duration::from_secs(5).as_millis() as i64
        );
        assert_eq!(pragma("application_id"), db::APPLICATION_ID as i64);
        assert_eq!(pragma("user_version"), db::SCHEMA_VERSION);
        assert!(conn
            .db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE)
            .unwrap());
        assert!(!conn
            .db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DQS_DML)
            .unwrap());
        assert!(!conn
            .db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DQS_DDL)
            .unwrap());

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
        set(db::SCHEMA_VERSION + 1, db::SCHEMA_VERSION);
        assert_eq!(
            open(dir.path(), false).unwrap().peers().unwrap(),
            *BASE_PEERS
        );
        let conn = Connection::open(db_path(dir.path())).unwrap();
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, db::SCHEMA_VERSION + 1);

        // One that needs a newer reader is refused.
        set(db::SCHEMA_VERSION + 1, db::SCHEMA_VERSION + 1);
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
        impostor.public_key = "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes=".to_string();
        let mut with_impostor = BASE_PEERS.clone();
        with_impostor.push(impostor);
        assert_eq!(daemon.update_peers(&with_impostor).len(), 1);
        let mut expected = BASE_PEERS.clone();
        expected.extend(disabled(&[pinned]));
        assert_eq!(daemon.peers().unwrap(), &expected[..]);
        assert_eq!(
            open(dir.path(), false).unwrap().peers().unwrap(),
            &expected[..]
        );
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
                        assert!(store.update(&state, Relay::Synthesized).unwrap().is_empty());
                    }
                });
            }
        });
        assert_eq!(open(dir.path(), false).unwrap().peers().unwrap().len(), 1);
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

    /// A peer that holds the key `keypair`, with the delegations 10.0.1.0/24 and 10.0.2.1/32,
    /// for which the server reports the endpoint 203.0.113.9:4000.
    fn announcing_peer(keypair: &wireguard_control::KeyPair) -> PeerContents {
        PeerContents {
            name: Some("announcer".parse().unwrap()),
            delegations: vec![
                "10.0.1.0/24".parse().unwrap(),
                "10.0.2.1/32".parse().unwrap(),
            ],
            public_key: keypair.public.to_base64(),
            endpoint: Some("203.0.113.9:4000".parse().unwrap()),
            candidates: vec![],
            ..BASE_PEERS[0].clone()
        }
    }

    /// The prefixes of `prefixes`.
    fn prefixes(prefixes: &[&str]) -> Vec<Prefix> {
        prefixes
            .iter()
            .map(|prefix| prefix.parse().unwrap())
            .collect()
    }

    /// Signs announcements of `keypair`.
    fn signer(
        keypair: &wireguard_control::KeyPair,
    ) -> impl Fn(&Announcement) -> SignedAnnouncement {
        let private_key =
            innernet_shared::xeddsa::PrivateKey::from_base64(&keypair.private.to_base64()).unwrap();
        move |announcement| announcement.sign(&private_key).unwrap()
    }

    #[test]
    fn test_announcements() {
        let dir = tempfile::tempdir().unwrap();
        let open = |create| open(dir.path(), create).unwrap();
        let keypair = wireguard_control::KeyPair::generate();
        let sign = signer(&keypair);
        let key = keypair.public.to_base64();
        let announces = |store: &DataStore| -> bool {
            store
                .store
                .query_row(
                    "SELECT announces FROM peers WHERE public_key = ?1",
                    [key_to_bytes(&key).unwrap()],
                    |r| r.get(0),
                )
                .unwrap()
        };
        let reported = |announcement: Option<SignedAnnouncement>| {
            vec![PeerContents {
                announcement,
                ..announcing_peer(&keypair)
            }]
        };
        let pins = |store: &DataStore| -> Vec<Prefix> {
            store
                .pins()
                .unwrap()
                .into_iter()
                .map(|(_, prefix)| prefix)
                .collect()
        };
        let all_types = announcement::CLAIM_TYPES.map(String::from);

        // A peer that has never announced takes effect as the unsigned announcement that the
        // server makes of it, and its delegations and its name are pinned to its key.
        let mut store = open(true);
        let synthetic = Announcement::synthetic(&announcing_peer(&keypair));
        assert!(store
            .relay_peers(&reported(Some(
                SignedAnnouncement::unsigned(&synthetic).unwrap()
            )))
            .is_empty());
        let effective = store.effective_peers().unwrap().remove(0);
        assert_eq!(effective.delegations, announcing_peer(&keypair).delegations);
        assert_eq!(
            effective.allowed_ips(),
            announcing_peer(&keypair).allowed_ips()
        );
        assert!(!announces(&store));
        assert!(!store.announces(&key).unwrap());
        assert_eq!(pins(&store), announcing_peer(&keypair).delegations);
        assert_eq!(
            store.peers().unwrap()[0].name,
            announcing_peer(&keypair).name
        );

        // Its first signed announcement latches it, and it then takes effect as it announces: what
        // the server reports of its delegations, its name and its endpoint takes no effect, its
        // allowed IPs are shrunk to its delegation, and what it no longer claims is released.
        let first = Announcement {
            timestamp: announcement::timestamp_now(),
            claims: Claims {
                delegation: prefixes(&["10.0.1.0/25", "10.0.2.1/32"]),
                name: Some("claimed".parse().unwrap()),
            },
            allowed_ips: prefixes(&["10.0.1.0/26", "10.0.2.0/24"]),
            primary_ip: Some("10.0.1.1".parse().unwrap()),
            // The endpoints keep their order, which isn't that of their addresses.
            endpoints: vec![
                "198.51.100.1:51820".parse().unwrap(),
                "peer.example.com:1".parse().unwrap(),
                "192.0.2.1:51820".parse().unwrap(),
            ],
        };
        let signed = sign(&first);
        assert!(store
            .relay_peers(&reported(Some(signed.clone())))
            .is_empty());
        assert!(announces(&store));
        assert!(store.announces(&key).unwrap());
        let announced = |store: &DataStore| {
            assert_eq!(store.announcement(&key).unwrap(), Some(first.clone()));
            let effective = store.effective_peers().unwrap().remove(0);
            assert_eq!(effective.delegations, first.claims.delegation);
            assert_eq!(
                effective.allowed_ips,
                Some(prefixes(&["10.0.1.0/26", "10.0.2.1/32"]))
            );
            assert_eq!(
                effective.hosts_fallback(),
                Some("10.0.1.1".parse().unwrap())
            );
            assert_eq!(effective.name, first.claims.name);
            assert_eq!(effective.endpoint.as_ref(), first.endpoints.first());
            assert_eq!(effective.candidates, first.endpoints[1..]);
            assert_eq!(pins(store), first.claims.delegation);
        };
        announced(&store);
        // The peer is stored without the signed bytes, and reads back as it was decoded.
        assert_eq!(store.peers().unwrap()[0].announcement, None);
        announced(&open(false));

        // A server that leaves the announcement out, relays an older one, one that it forged or
        // altered, or an unsigned one, can't take it back: the last accepted one stays.
        let older = sign(&Announcement {
            timestamp: first.timestamp - 1,
            ..Default::default()
        });
        let forged = signer(&wireguard_control::KeyPair::generate())(&Announcement {
            timestamp: first.timestamp + 1,
            ..Default::default()
        });
        let mut altered = sign(&Announcement {
            timestamp: first.timestamp + 1,
            ..Default::default()
        });
        altered.payload.push(0);
        let ahead = sign(&Announcement {
            timestamp: announcement::timestamp_now() + 3_600_000_000_000,
            ..Default::default()
        });
        let unsigned = SignedAnnouncement::unsigned(&Announcement {
            timestamp: first.timestamp + 1,
            ..synthetic.clone()
        })
        .unwrap();
        for relayed in [
            None,
            Some(older),
            Some(forged),
            Some(altered),
            Some(ahead),
            Some(unsigned),
        ] {
            assert!(store.relay_peers(&reported(relayed)).is_empty());
            announced(&store);
        }
        // So can't one that predates announcements, of which this client makes the unsigned
        // announcement of each peer.
        assert!(store.update_peers(&reported(None)).is_empty());
        announced(&store);
        announced(&open(false));

        // Nothing relayed is accepted while this client doesn't know which types of claims the
        // server checks, and only the claims of the types that it checks are accepted, while
        // statements are taken whatever it checks.
        let mut store = open(false);
        let renamed = Announcement {
            timestamp: first.timestamp + 1,
            claims: Claims {
                name: Some("renamed".parse().unwrap()),
                ..first.claims.clone()
            },
            ..first.clone()
        };
        let update = |store: &mut DataStore, types: Option<&[String]>| {
            let state = State {
                peers: reported(Some(sign(&renamed))),
                cidrs: vec![],
                observed_endpoint: None,
                invalid_peer_keys: vec![],
            };
            let relay = match types {
                Some(types) => Relay::Announcements(types),
                None => Relay::Unknown,
            };
            assert!(store.update(&state, relay).unwrap().is_empty());
        };
        update(&mut store, None);
        announced(&store);
        let some_types = ["delegation".to_string()];
        update(&mut store, Some(&some_types));
        let partial = Announcement {
            claims: Claims {
                name: None,
                ..renamed.claims.clone()
            },
            ..renamed.clone()
        };
        assert_eq!(store.announcement(&key).unwrap(), Some(partial.clone()));
        assert_eq!(store.effective_peers().unwrap()[0].name, None);
        assert_eq!(store.peers().unwrap()[0].name, None);
        // The same announcement relayed again, once the server checks more types, is read again.
        update(&mut store, Some(&all_types));
        assert_eq!(store.announcement(&key).unwrap(), Some(renamed.clone()));
        assert_eq!(
            store.effective_peers().unwrap()[0].name,
            renamed.claims.name
        );

        // A newer one replaces it, and one that states no allowed IPs routes nothing.
        let silent = Announcement {
            timestamp: first.timestamp + 2,
            allowed_ips: vec![],
            ..renamed.clone()
        };
        assert!(store.relay_peers(&reported(Some(sign(&silent)))).is_empty());
        assert!(!store.effective_peers().unwrap()[0].is_routed());
        assert_eq!(pins(&store), first.claims.delegation);

        // This client records its own announcements the same way, each newer than the last.
        let own = Announcement {
            timestamp: first.timestamp + 3,
            ..first.clone()
        };
        store
            .accept_announcement(&key, &sign(&own), &all_types)
            .unwrap();
        assert!(store
            .accept_announcement(&key, &sign(&own), &all_types)
            .is_err());
        assert!(store
            .accept_announcement(&key, &signed, &all_types)
            .is_err());
        assert_eq!(store.announcement(&key).unwrap(), Some(own.clone()));
    }

    #[test]
    fn test_claims_move_between_keys() {
        // A prefix or a name that a peer stops claiming is released, and another key may claim it
        // in the same update, while what a peer claims is refused to another key: its
        // announcement is ignored, and it keeps what it claimed before.
        let dir = tempfile::tempdir().unwrap();
        let mut store = open(dir.path(), true).unwrap();
        let [mover, taker] = [(); 2].map(|_| wireguard_control::KeyPair::generate());
        let peer = |keypair: &wireguard_control::KeyPair, name: &str| PeerContents {
            name: Some(name.parse().unwrap()),
            delegations: vec![],
            public_key: keypair.public.to_base64(),
            ..BASE_PEERS[0].clone()
        };
        let announcement = |timestamp, delegation: &[&str], name: &str| Announcement {
            timestamp,
            claims: Claims {
                delegation: prefixes(delegation),
                name: Some(name.parse().unwrap()),
            },
            allowed_ips: prefixes(delegation),
            primary_ip: Some(prefixes(delegation)[0].first()),
            ..Default::default()
        };
        let state = |mover_announces: &Announcement, taker_announces: &Announcement| {
            vec![
                PeerContents {
                    announcement: Some(signer(&mover)(mover_announces)),
                    ..peer(&mover, "mover")
                },
                PeerContents {
                    announcement: Some(signer(&taker)(taker_announces)),
                    ..peer(&taker, "taker")
                },
            ]
        };
        let claimed = |store: &DataStore, keypair: &wireguard_control::KeyPair| {
            let peer = store
                .effective_peers()
                .unwrap()
                .into_iter()
                .find(|peer| peer.public_key == keypair.public.to_base64())
                .unwrap();
            (peer.delegations, peer.name.map(|name| name.to_string()))
        };
        let now = announcement::timestamp_now();

        let mover_first = announcement(now, &["10.0.1.0/24"], "mover");
        let taker_first = announcement(now, &["10.0.2.0/24"], "taker");
        assert!(store
            .relay_peers(&state(&mover_first, &taker_first))
            .is_empty());

        // The taker can't take what the mover claims.
        let grabbing = announcement(now + 1, &["10.0.1.128/25", "10.0.2.0/24"], "mover");
        assert!(store
            .relay_peers(&state(&mover_first, &grabbing))
            .is_empty());
        assert_eq!(
            claimed(&store, &taker),
            (prefixes(&["10.0.2.0/24"]), Some("taker".into()))
        );

        // Once the mover moves, in the same update, it can.
        let mover_moved = announcement(now + 2, &["10.0.3.0/24"], "moved");
        let taker_took = announcement(now + 2, &["10.0.1.0/24", "10.0.2.0/24"], "mover");
        assert!(store
            .relay_peers(&state(&mover_moved, &taker_took))
            .is_empty());
        assert_eq!(
            claimed(&store, &mover),
            (prefixes(&["10.0.3.0/24"]), Some("moved".into()))
        );
        assert_eq!(
            claimed(&store, &taker),
            (
                prefixes(&["10.0.1.0/24", "10.0.2.0/24"]),
                Some("mover".into())
            )
        );

        // Two keys that claim the same new prefix are both refused.
        let mover_grabs = announcement(now + 3, &["10.0.3.0/24", "10.0.4.0/24"], "moved");
        let taker_grabs = announcement(now + 3, &["10.0.2.0/24", "10.0.4.0/25"], "mover");
        assert!(store
            .relay_peers(&state(&mover_grabs, &taker_grabs))
            .is_empty());
        assert_eq!(claimed(&store, &mover).0, prefixes(&["10.0.3.0/24"]));
        assert_eq!(
            claimed(&store, &taker).0,
            prefixes(&["10.0.1.0/24", "10.0.2.0/24"])
        );
        let reopened = open(dir.path(), false).unwrap();
        assert_eq!(claimed(&reopened, &mover).0, prefixes(&["10.0.3.0/24"]));
    }

    #[test]
    fn test_names_are_pinned() {
        // The names of peers are pinned as soon as a data store of an earlier version is imported.
        // An unsigned announcement, which the server makes for a peer that has never signed one,
        // releases no name, so the server can neither rename such a peer nor move its name to
        // another key, even by swapping two names in one update.
        let dir = tempfile::tempdir().unwrap();
        let other_key = "HX6Se15qwliiWM7l3iCVAtK+FXNfHRFeEq8UFRK8BBk=";
        let mut other = BASE_PEERS[0].clone();
        other.public_key = other_key.to_string();
        other.delegations = host("10.0.0.2");
        other.name = Some("other".parse().unwrap());
        write_legacy(dir.path(), &[BASE_PEERS[0].clone(), other.clone()], &[]);
        let mut store = open(dir.path(), false).unwrap();
        let names = |store: &DataStore| {
            store
                .peers()
                .unwrap()
                .iter()
                .map(|peer| peer.display_name().to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(&store), ["blah", "other"]);

        let renamed = |peer: &PeerContents, name: &str| PeerContents {
            name: Some(name.parse().unwrap()),
            ..peer.clone()
        };
        assert!(store
            .update_peers(&[BASE_PEERS[0].clone(), renamed(&other, "renamed")])
            .is_empty());
        assert_eq!(names(&store), ["blah", "other"]);
        assert!(store
            .update_peers(&[renamed(&BASE_PEERS[0], "other"), renamed(&other, "blah")])
            .is_empty());
        assert_eq!(names(&store), ["blah", "other"]);
        assert_eq!(names(&open(dir.path(), false).unwrap()), ["blah", "other"]);

        // A new peer that the server names as another key's pinned name is refused.
        let mut new = other.clone();
        new.public_key = "OmxANP9F6BAFC8+gGVmgQTEfanMMF+kge3y/eVEICes=".to_string();
        new.delegations = host("10.0.0.3");
        new.name = Some("blah".parse().unwrap());
        let reported = [BASE_PEERS[0].clone(), other.clone(), new];
        assert_eq!(store.update_peers(&reported).len(), 1);
        assert_eq!(store.peers().unwrap().len(), 2);
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

    /// The number of rows of `table` that belong to the public key `key`.
    fn rows_of(store: &DataStore, table: &str, key: &str) -> i64 {
        store
            .store
            .query_row(
                &format!("SELECT count(*) FROM {table} WHERE public_key = ?1"),
                [key_to_bytes(key).unwrap()],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn test_database_keeps_consistency() {
        // The database refuses to pin a name to two keys, a pin of an unknown kind, and to delete a
        // peer while what refers to it remains. An operator releases a prefix pin by deleting it,
        // and a name by clearing it.
        let dir = tempfile::tempdir().unwrap();
        setup_basic_store(dir.path());
        let store = open(dir.path(), false).unwrap();
        let key = key_to_bytes(&BASE_PEERS[0].public_key).unwrap();
        let other = key_to_bytes("HX6Se15qwliiWM7l3iCVAtK+FXNfHRFeEq8UFRK8BBk=").unwrap();
        let conn = &*store.store;
        conn.execute_batch(&format!(
            "INSERT INTO peers (public_key, name) VALUES (x'{other}', 'other');
             INSERT INTO prefix_pins VALUES (x'0a000002', 32, x'0a000002', x'{other}', 1, 1);
             INSERT INTO delegations (address, prefix_len, last, public_key)
               VALUES (x'0a000002', 32, x'0a000002', x'{other}');",
            other = hex(&other),
        ))
        .unwrap();
        for refused in [
            "INSERT INTO prefix_pins VALUES (x'0a000003', 32, x'0a000003', x'{key}', 0, 1)",
            "UPDATE peers SET name = 'blah' WHERE public_key = x'{other}'",
            "DELETE FROM peers WHERE public_key = x'{key}'",
        ] {
            let refused = refused
                .replace("{key}", &hex(&key))
                .replace("{other}", &hex(&other));
            assert!(
                conn.execute_batch(&refused).is_err(),
                "{refused} was accepted"
            );
        }
        // A pin is released by deleting it.
        conn.execute_batch(&format!(
            "DELETE FROM prefix_pins WHERE public_key = x'{other}';
             UPDATE peers SET name = NULL WHERE public_key = x'{other}';",
            other = hex(&other),
        ))
        .unwrap();
        drop(store);
        assert_eq!(
            open(dir.path(), false).unwrap().peers().unwrap()[0],
            BASE_PEERS[0]
        );
    }
}
