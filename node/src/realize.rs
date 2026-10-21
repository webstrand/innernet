//! The output adapters, which realize a [`Snapshot`]: a [`TunnelBackend`], which configures the
//! tunnel, and a [`NamePublisher`], which publishes the names. Each is a trait, implemented by
//! [`WireGuard`] and [`HostsFile`]; another backend, such as an in-process WireGuard without a
//! network device, implements the same trait.

use crate::snapshot::Snapshot;
use innernet_shared::{wg::DeviceExt as _, Endpoint, Error, HostsOpts, Peer, PeerChange};
use std::{collections::BTreeMap, net::IpAddr};
use wireguard_control::{Backend, Device, DeviceUpdate, InterfaceName, PeerConfigBuilder};

/// What a tunnel backend changed of a peer when it realized a snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Realized {
    pub public_key: String,
    /// Whether the tunnel held the peer before.
    pub existed: bool,
    /// The peer as the tunnel now holds it, or `None` if it was removed.
    pub new: Option<Peer>,
    pub changes: Vec<PeerChange>,
}

/// The tunnel of a node, which holds the peers of a snapshot.
pub trait TunnelBackend {
    /// Brings the tunnel in line with `snapshot`: it holds every enabled peer of the snapshot, as
    /// the snapshot configures it, and no other. Returns what it changed of each peer.
    fn realize(&mut self, snapshot: &Snapshot) -> Result<Vec<Realized>, Error>;
}

/// The publisher of the names of a node.
pub trait NamePublisher {
    fn publish(&mut self, snapshot: &Snapshot) -> Result<(), Error>;
}

/// The tunnel as a WireGuard interface, in the kernel or in userspace, as `wireguard-control`
/// configures it.
#[derive(Clone, Debug)]
pub struct WireGuard {
    pub interface: InterfaceName,
    pub backend: Backend,
    /// The endpoint at which each peer is reached instead of the one that it states, by IP, as
    /// the node's config overrides them.
    pub endpoint_overrides: BTreeMap<IpAddr, Endpoint>,
}

impl TunnelBackend for WireGuard {
    /// Diffs the peers of the interface with those of `snapshot`, and applies the difference.
    fn realize(&mut self, snapshot: &Snapshot) -> Result<Vec<Realized>, Error> {
        let device = Device::get(&self.interface, self.backend)?;
        let diffs = device.diff(&snapshot.peers, &self.endpoint_overrides);
        let realized = diffs
            .iter()
            .map(|diff| Realized {
                public_key: diff.public_key().to_base64(),
                existed: diff.old.is_some(),
                new: diff.new.cloned(),
                changes: diff.changes().to_vec(),
            })
            .collect();
        let updates: Vec<PeerConfigBuilder> =
            diffs.into_iter().map(PeerConfigBuilder::from).collect();
        if !updates.is_empty() {
            DeviceUpdate::new()
                .add_peers(&updates)
                .apply(&self.interface, self.backend)?;
        }
        Ok(realized)
    }
}

/// The names written to the hosts file, under the hostnames that the host suffix gives them.
pub struct HostsFile {
    pub interface: InterfaceName,
    pub opts: HostsOpts,
}

impl NamePublisher for HostsFile {
    fn publish(&mut self, snapshot: &Snapshot) -> Result<(), Error> {
        innernet_shared::update_hosts_file(
            &self.interface,
            &self.opts,
            snapshot.peers.iter().filter(|peer| !peer.is_disabled),
        )?;
        Ok(())
    }
}
