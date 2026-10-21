//! The output adapters, which realize a [`Snapshot`]: a [`TunnelBackend`], which configures the
//! tunnel, and a [`NamePublisher`], which publishes the names. Each is a trait, implemented by
//! [`WireGuard`] and [`DnsServer`]; another backend, such as an in-process WireGuard without a
//! network device, or another publisher, implements the same trait.

use crate::{
    dns::{Names, Server},
    events::{poll_wireguard, EventSource, TunnelEvents},
    nat::NatTraverse,
    snapshot::Snapshot,
};
use innernet_shared::{
    interface_config::DnsInfo, wg::DeviceExt as _, Endpoint, Error, Peer, PeerChange,
};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
};
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

    /// The NAT traversal of the peers that `realized` changed, if the backend traverses NATs.
    fn traverse(&self, _realized: &[Realized]) -> Result<Option<NatTraverse>, Error> {
        Ok(None)
    }

    /// A subscription to what the tunnel observes of its peers, in the current runtime.
    fn events(&self) -> TunnelEvents {
        TunnelEvents::none()
    }
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
    /// The source of the events of the interface, which polls the device.
    pub events: EventSource,
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

    fn traverse(&self, realized: &[Realized]) -> Result<Option<NatTraverse>, Error> {
        NatTraverse::new(
            self.interface,
            self.backend,
            &self.endpoint_overrides,
            realized,
        )
        .map(Some)
    }

    fn events(&self) -> TunnelEvents {
        let (interface, backend) = (self.interface, self.backend);
        self.events.subscribe(|source| {
            tokio::spawn(poll_wireguard(interface, backend, source));
        })
    }
}

/// The names published by a DNS server, each under the hostname that the host suffix gives it, as
/// [`Names::of`] makes them.
pub struct DnsServer {
    pub interface: InterfaceName,
    pub host_suffix: Option<String>,
    pub server: Server,
}

impl NamePublisher for DnsServer {
    fn publish(&mut self, snapshot: &Snapshot) -> Result<(), Error> {
        self.server.set_names(Names::of(
            &self.interface,
            self.host_suffix.as_deref(),
            snapshot,
        ));
        Ok(())
    }
}

/// The DNS server of a node's interface, as the `[dns]` table of its config wants it: running at
/// the listen address of the table, publishing the names of the node's snapshot, or stopped.
pub struct DnsService {
    pub interface: InterfaceName,
    pub host_suffix: Option<String>,
    /// The running server, with the listen address of the table that started it, which may differ
    /// from the address that it listens at in its port.
    running: Option<(SocketAddr, DnsServer)>,
}

impl DnsService {
    pub fn new(interface: InterfaceName, host_suffix: Option<String>) -> Self {
        Self {
            interface,
            host_suffix,
            running: None,
        }
    }

    /// Brings the server in line with `dns`, the `[dns]` table of the config, if it has one, and
    /// publishes the names of `snapshot`: a server without a table is stopped, as is one whose
    /// listen address changed, which then starts again at the new address. A server that fails to
    /// start is warned of and tried again at the next update.
    pub async fn update(&mut self, dns: Option<&DnsInfo>, snapshot: &Snapshot) {
        let name = self.interface.as_str_lossy().to_string();
        if let Some((listen, running)) = self.running.take() {
            if dns.is_some_and(|dns| dns.listen == listen) {
                self.running = Some((listen, running));
            } else {
                log::info!(
                    "{name}: stopping the DNS server at {}.",
                    running.server.listen
                );
                running.server.stop().await;
            }
        }
        let Some(DnsInfo { listen }) = dns else {
            return;
        };
        if let Some((_, running)) = &mut self.running {
            // Publishing to a running server never fails.
            let _ = running.publish(snapshot);
            return;
        }
        let names = Names::of(&self.interface, self.host_suffix.as_deref(), snapshot);
        match Server::spawn(*listen, names) {
            Ok(server) => {
                log::info!(
                    "{name}: answering DNS for the names of peers at {}.",
                    server.listen
                );
                let published = DnsServer {
                    interface: self.interface,
                    host_suffix: self.host_suffix.clone(),
                    server,
                };
                self.running = Some((*listen, published));
            },
            Err(e) => log::warn!("{name}: failed to start the DNS server at {listen}: {e}"),
        }
    }

    /// The listen address of the table that started the running server, if one runs.
    pub fn listen(&self) -> Option<SocketAddr> {
        self.running.as_ref().map(|(listen, _)| *listen)
    }

    pub async fn stop(&mut self) {
        if let Some((_, running)) = self.running.take() {
            running.server.stop().await;
        }
    }
}
