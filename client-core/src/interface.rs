pub use innernet_shared::interface_config::InterfaceConfig;
pub use wireguard_control::InterfaceName;

use crate::{
    data_store::DataStore,
    rest_client::{RestClient, RestError},
    HostsOpts, NatOpts, NetworkOpts, WrappedIoError,
};
use anyhow::{bail, Context as _, Error};
use colored::{ColoredString, Colorize};
use innernet_node::{
    events::EventSource,
    realize::{Realized, WireGuard},
    runtime::{self, Link, Node, Round},
    snapshot::{self, Snapshot},
    store,
};
use innernet_shared::{
    wg, Endpoint, Peer, PeerChange, RedeemContents, State, REDEEM_TRANSITION_WAIT,
};
use std::{io, path::Path};
use thiserror::Error;
use wireguard_control::{Backend, Device, DeviceUpdate};

#[derive(Debug, Error)]
pub enum RedeemInviteError {
    #[error("Error accessing innernet interface config file: {0}")]
    InterfaceConfigAccess(WrappedIoError),
    #[error("Config file for innernet interface {0} already exists.")]
    InterfaceConfigExists(InterfaceName),
    #[error("Data store for innernet interface {0} already exists.")]
    DataStoreExists(InterfaceName),
    #[error("Error accessing the data store: {0:#}")]
    DataStoreAccess(Error),
    #[error("Error introducing the coordinator and this client into the data store: {0:#}")]
    DataStoreIntroduction(Error),
    #[error("Error making a REST request: {0}")]
    RestRequest(#[from] RestError),
    #[error("Could not resolve server address for endpoint {endpoint}: {error}")]
    ServerAddressResolve {
        endpoint: Endpoint,
        error: io::Error,
    },
    #[error("WireGuard interface {0} already exists.")]
    WireguardInterfaceExists(InterfaceName),
    #[error("Error managing the Wireguard interface {interface}: {error}")]
    WireguardOperation {
        interface: InterfaceName,
        error: io::Error,
    },
}

/// Redeem an invitation to join an innernet network.
///
/// - Brings the WireGuard interface up.
/// - Generates a fresh key pair and uses the public part to redeem the invite and the private part
///   to update the WireGuard interface.
/// - Creates the data store with the coordinator and this client, as the config introduces them.
/// - Bails if either a WireGuard or an innernet `interface` of the same name already exists and
///   brings the interface down if it was already up.
pub async fn redeem_invite(
    config_dir: &Path,
    data_dir: &Path,
    network_opts: &NetworkOpts,
    interface: &InterfaceName,
    config: InterfaceConfig,
) -> Result<(), RedeemInviteError> {
    let config_path = InterfaceConfig::build_config_file_path(config_dir, interface)
        .map_err(RedeemInviteError::InterfaceConfigAccess)?;

    if config_path.exists() {
        return Err(RedeemInviteError::InterfaceConfigExists(*interface));
    }
    if DataStore::exists(data_dir, interface).map_err(RedeemInviteError::DataStoreAccess)? {
        return Err(RedeemInviteError::DataStoreExists(*interface));
    }

    if Device::list(network_opts.backend)
        .iter()
        .flatten()
        .any(|name| name == interface)
    {
        return Err(RedeemInviteError::WireguardInterfaceExists(*interface));
    }

    log::info!(
        "bringing up interface {}.",
        interface.as_str_lossy().yellow()
    );

    let endpoint = &config.server.external_endpoint;
    let resolved_endpoint =
        endpoint
            .resolve()
            .map_err(|e| RedeemInviteError::ServerAddressResolve {
                endpoint: endpoint.clone(),
                error: e,
            })?;

    wg::up(
        interface,
        &config.interface.private_key,
        config.interface.address,
        config.interface.listen_port,
        Some((
            &config.server.public_key,
            config.server.internal_endpoint.ip(),
            resolved_endpoint,
        )),
        network_opts,
    )
    .map_err(|e| RedeemInviteError::WireguardOperation {
        interface: *interface,
        error: e,
    })?;

    update_keypair(network_opts, interface, &config_path, data_dir, config)
        .await
        .inspect_err(|e| {
            log::error!("failed to update keypair (is the innernet server reachable?): {e}.",);
            log::info!("bringing down the interface.");
            if let Err(e) = wg::down(interface, network_opts.backend) {
                log::warn!("failed to bring down interface: {}.", e);
            };
        })?;

    Ok(())
}

async fn update_keypair(
    network_opts: &NetworkOpts,
    interface: &InterfaceName,
    config_path: &Path,
    data_dir: &Path,
    mut config: InterfaceConfig,
) -> Result<(), RedeemInviteError> {
    log::info!("Generating new keypair.");
    let keypair = wireguard_control::KeyPair::generate();

    log::info!(
        "Registering keypair with server (at {}).",
        config.server.internal_endpoint
    );
    RestClient::new(&config.server)
        .http_form::<_, ()>(
            "POST",
            "/user/redeem",
            RedeemContents {
                public_key: keypair.public.to_base64(),
            },
        )
        .await?;

    config.interface.private_key = keypair.private.to_base64();
    config
        .save_new(config_path, 0o600)
        .map_err(RedeemInviteError::InterfaceConfigAccess)?;
    log::info!(
        "New keypair registered. Copied config to {}.\n",
        config_path.to_string_lossy().yellow()
    );

    DataStore::open_or_create(data_dir, interface, &config)
        .and_then(|mut store| store.introduce(&config))
        .map_err(RedeemInviteError::DataStoreIntroduction)?;

    log::info!("Changing keys and waiting 5s for server's WireGuard interface to transition.",);
    DeviceUpdate::new()
        .set_private_key(keypair.private)
        .apply(interface, network_opts.backend)
        .map_err(|e| RedeemInviteError::WireguardOperation {
            interface: *interface,
            error: e,
        })?;
    tokio::time::sleep(REDEEM_TRANSITION_WAIT).await;

    Ok(())
}

/// Fetches the state of `interface` from the coordinator, configures the interface from it, and
/// takes the steps of the NAT traversal of the peers that changed, as one round of the node does,
/// bringing the interface up first if `bring_up_interface` allows it.
pub async fn fetch(
    config_dir: &Path,
    data_dir: &Path,
    network_opts: &NetworkOpts,
    hosts_opts: &HostsOpts,
    nat: &NatOpts,
    interface: &InterfaceName,
    bring_up_interface: bool,
) -> Result<(), Error> {
    let round = round(
        config_dir,
        data_dir,
        network_opts,
        hosts_opts,
        nat,
        interface,
        bring_up_interface,
        &EventSource::default(),
    )
    .await?;
    runtime::settle(round).await
}

/// Runs a round of the node of `interface`: reads its config, brings the interface up if
/// `bring_up_interface` allows it and it isn't up, and runs the round of the node through its link
/// to the coordinator, with `events`, the source of the events of the interface, which a node that
/// runs rounds keeps from one to the next.
#[allow(clippy::too_many_arguments)]
pub async fn round(
    config_dir: &Path,
    data_dir: &Path,
    network_opts: &NetworkOpts,
    hosts_opts: &HostsOpts,
    nat: &NatOpts,
    interface: &InterfaceName,
    bring_up_interface: bool,
    events: &EventSource,
) -> Result<Round, Error> {
    hosts_opts.warn_of_hosts_file_options();
    let config = InterfaceConfig::from_interface(config_dir, interface)?;
    let interface_up = interface_is_up(network_opts.backend, interface);

    if !interface_up {
        if !bring_up_interface {
            bail!(
                "Interface is not up. Use 'innernet up {}' instead",
                interface
            );
        }

        log::info!(
            "bringing up interface {}.",
            interface.as_str_lossy().yellow()
        );
        let resolved_endpoint = config
            .server
            .external_endpoint
            .resolve()
            .context(config.server.external_endpoint.to_string())?;
        wg::up(
            interface,
            &config.interface.private_key,
            config.interface.address,
            config.interface.listen_port,
            Some((
                &config.server.public_key,
                config.server.internal_endpoint.ip(),
                resolved_endpoint,
            )),
            network_opts,
        )
        .context(interface.to_string())?;
    }

    log::info!(
        "fetching state for {} from server...",
        interface.as_str_lossy().yellow()
    );
    for (peer_ip, endpoint_override) in config.peer_endpoint_overrides() {
        log::debug!(
            "overriding peer IP {} with endpoint {}",
            peer_ip,
            endpoint_override
        );
    }
    let device = Device::get(interface, network_opts.backend)?;
    let mut node = Node {
        interface: *interface,
        listen_port: device.listen_port.unwrap_or(51820),
        nat: nat.clone(),
        tunnel: Box::new(WireGuard {
            interface: *interface,
            backend: network_opts.backend,
            endpoint_overrides: config.peer_endpoint_overrides().clone(),
            events: events.clone(),
        }),
        names: None,
    };
    let mut link = RemoteLink {
        interface: *interface,
        store: DataStore::open_or_create(data_dir, interface, &config)?,
        rest_client: RestClient::new(&config.server),
        fetched: false,
    };
    let round = node.round(&mut link).await?;

    let peers = link.store.peers()?;
    for realized in &round.realized {
        print_peer_diff(&peers, realized);
    }
    if !round.realized.is_empty() || !interface_up {
        println!();
        log::info!("updated interface {}\n", interface.as_str_lossy().yellow());
    } else {
        log::info!("{}", "peers are already up to date".green());
    }
    Ok(round)
}

/// A client's link to its coordinator, over the API.
struct RemoteLink<'a> {
    interface: InterfaceName,
    store: DataStore,
    rest_client: RestClient<'a>,
    /// Whether the last sync reached the coordinator.
    fetched: bool,
}

impl Link for RemoteLink<'_> {
    /// Fetches the state from the coordinator, and merges it into the data store, which validates
    /// it before any of it reaches the interface. A coordinator that can't be reached leaves the
    /// data store as it is, unless the data store holds no peer to configure.
    async fn sync(&mut self) -> Result<(), Error> {
        self.fetched = false;
        let state = match self.rest_client.http::<State>("GET", "/user/state").await {
            Ok(state) => state,
            Err(e) if e.is_transport_error() => {
                if self.store.peers()?.is_empty() {
                    bail!(
                        "Could not connect to the innernet server and there are no cached peers, \
                         exiting."
                    )
                }
                log::warn!(
                    "Could not connect to the innernet server, proceeding with cached state \
                     instead."
                );
                return Ok(());
            },
            Err(e) => bail!(e),
        };
        let dropped = self
            .store
            .update(&state)
            .context(self.interface.to_string())?;
        for (peer, e) in dropped {
            log::warn!(
                "{}: dropping peer {} at {} from the update: {}",
                self.interface.as_str_lossy().yellow(),
                peer.public_key,
                peer.ip,
                e
            );
        }
        self.fetched = true;
        Ok(())
    }

    fn snapshot(&self) -> Result<Snapshot, Error> {
        Ok(snapshot::snapshot(store::load_peers(self.store.store())?))
    }

    /// Reports `candidates` to a coordinator that the last sync reached.
    async fn report_candidates(&mut self, candidates: Vec<Endpoint>) -> Result<(), Error> {
        if !self.fetched {
            return Ok(());
        }
        for candidate in &candidates {
            log::debug!("  candidate: {}", candidate);
        }
        match self
            .rest_client
            .http_form::<_, ()>("PUT", "/user/candidates", &candidates)
            .await
        {
            Err(e) if e.has_status_of(404) => {
                log::warn!("your network is using an old version of innernet-server that doesn't support NAT traversal candidate reporting.");
                Ok(())
            },
            Err(e) => Err(e.into()),
            Ok(()) => {
                log::debug!("candidates successfully reported");
                Ok(())
            },
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum ChangeAction {
    Added,
    Modified,
    Removed,
}

impl ChangeAction {
    fn colored_output(&self) -> ColoredString {
        match self {
            Self::Added => "added".green(),
            Self::Modified => "modified".yellow(),
            Self::Removed => "removed".red(),
        }
    }
}

fn print_peer_diff(peers: &[Peer], diff: &Realized) {
    let public_key = &diff.public_key;

    let change_action = match (diff.existed, &diff.new) {
        (false, _) => ChangeAction::Added,
        (true, Some(_)) => ChangeAction::Modified,
        (true, None) => ChangeAction::Removed,
    };

    // Grab the peer name from either the new data, or the historical data (if the peer is removed).
    let peer_hostname = match &diff.new {
        Some(peer) => Some(peer.name.clone()),
        None => peers
            .iter()
            .find(|p| &p.public_key == public_key)
            .map(|p| p.name.clone()),
    };
    let peer_name = peer_hostname.as_deref().unwrap_or("[unknown]");

    if change_action == ChangeAction::Modified
        && diff
            .changes
            .iter()
            .all(|c| *c == PeerChange::NatTraverseReattempt)
    {
        // If this peer was "modified" but the only change is a NAT Traversal Reattempt,
        // don't bother printing this peer.
        return;
    }

    log::info!(
        "  peer {} ({}...) was {}.",
        peer_name.yellow(),
        public_key[..10].dimmed(),
        change_action.colored_output(),
    );

    for change in &diff.changes {
        if let PeerChange::Endpoint { .. } = change {
            log::info!("    {}", change);
        } else {
            log::debug!("    {}", change);
        }
    }
}

pub fn interface_is_up(backend: Backend, interface_name: &InterfaceName) -> bool {
    match Device::list(backend) {
        Ok(interfaces) => interfaces.contains(interface_name),
        _ => false,
    }
}
