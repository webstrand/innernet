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
    realize::{DnsService, Realized, WireGuard},
    runtime::{self, Link, Node, Round},
    snapshot::Snapshot,
};
use innernet_shared::{
    interface_config::{ResolvedInvitation, FEATURE_TLS},
    wg, Endpoint, IoErrorContext, PeerChange, PeerContents, Prefix, RedeemContents,
    REDEEM_TRANSITION_WAIT,
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

/// Redeem an invitation to join an innernet network, resolved into the config of the interface
/// and the delegations that it offers.
///
/// - Brings the WireGuard interface up.
/// - Generates a fresh key pair and uses the public part to redeem the invite and the private part
///   to update the WireGuard interface.
/// - Creates the data store with the coordinator and this client, as the invitation introduces
///   them, and writes the config, both before redeeming the invitation. If the redemption fails,
///   both are removed.
/// - Bails if either a WireGuard or an innernet `interface` of the same name already exists and
///   brings the interface down if it was already up.
pub async fn redeem_invite(
    config_dir: &Path,
    data_dir: &Path,
    network_opts: &NetworkOpts,
    interface: &InterfaceName,
    invitation: ResolvedInvitation,
) -> Result<(), RedeemInviteError> {
    let ResolvedInvitation {
        config,
        delegations,
    } = invitation;
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

    update_keypair(
        network_opts,
        interface,
        &config_path,
        data_dir,
        config,
        &delegations,
    )
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
    invitation: InterfaceConfig,
    delegations: &[Prefix],
) -> Result<(), RedeemInviteError> {
    log::info!("Generating new keypair.");
    let keypair = wireguard_control::KeyPair::generate();
    let mut config = invitation.clone();
    config.interface.private_key = keypair.private.to_base64();

    // The data store and the config are ready before the invitation is spent, so that redeeming it
    // leaves both behind. Until the server answers, the invitation is the authority on whether the
    // server speaks TLS, and at which QUIC port.
    let server_key = &config.server.public_key;
    let mut store = DataStore::create_new(data_dir, interface, &config)
        .map_err(RedeemInviteError::DataStoreIntroduction)?;
    let introduced = (|| -> Result<(), Error> {
        store.introduce(&config, delegations)?;
        if config.server.has_feature(FEATURE_TLS) {
            store.latch_tls(server_key)?;
        }
        if let Some(port) = config.server.quic_port {
            store.set_quic_port(server_key, port)?;
        }
        Ok(())
    })();
    if let Err(e) = introduced {
        discard_data_store(store, data_dir, interface);
        return Err(RedeemInviteError::DataStoreIntroduction(e));
    }

    // The config is written next to its final path, so that renaming it into place doesn't cross
    // file systems. Its extension isn't that of a config, so it isn't taken for an interface.
    let new_config_path = config_path.with_extension("conf.new");
    if let Err(e) = config.save_new(&new_config_path, 0o600) {
        discard_data_store(store, data_dir, interface);
        return Err(RedeemInviteError::InterfaceConfigAccess(e));
    }

    log::info!(
        "Registering keypair with server (at {}).",
        config.server.internal_endpoint
    );
    let redeemed = async {
        let rest_client = RestClient::new(&invitation, invitation.server.has_feature(FEATURE_TLS))?
            .on_interface(interface);
        rest_client
            .http_form::<_, ()>(
                "POST",
                "/user/redeem",
                RedeemContents {
                    public_key: keypair.public.to_base64(),
                },
            )
            .await?;
        Ok::<_, RestError>(rest_client)
    }
    .await;
    let rest_client = match redeemed {
        Ok(rest_client) => rest_client,
        Err(e) => {
            if let Err(e) = std::fs::remove_file(&new_config_path) {
                log::warn!(
                    "failed to remove {}: {e}",
                    new_config_path.to_string_lossy().yellow()
                );
            }
            discard_data_store(store, data_dir, interface);
            return Err(e.into());
        },
    };

    std::fs::rename(&new_config_path, config_path)
        .with_path(&new_config_path)
        .map_err(RedeemInviteError::InterfaceConfigAccess)?;
    log::info!(
        "New keypair registered. Copied config to {}.\n",
        config_path.to_string_lossy().yellow()
    );
    // What the server stated when it answered, such as a QUIC port that the invitation didn't
    // state, is recorded as a fetch would record it.
    record_coordinator(&mut store, &config, &rest_client);
    drop(rest_client);

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

/// Removes the data store that a redemption created, when the invitation wasn't redeemed.
fn discard_data_store(store: DataStore, data_dir: &Path, interface: &InterfaceName) {
    if let Err(e) = store.discard(data_dir, interface) {
        log::warn!("failed to remove the data store: {e:#}");
    }
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
        &mut NodeState::default(),
    )
    .await?;
    runtime::settle(round).await
}

/// What the node of an interface keeps from one round to the next.
#[derive(Default)]
pub struct NodeState {
    /// The source of the events of the interface.
    pub events: EventSource,
    /// The DNS server of the interface, which a node that runs rounds runs while the config has a
    /// `[dns]` table, and a node that runs one round doesn't.
    pub dns: Option<DnsService>,
}

/// Runs a round of the node of `interface`: reads its config, brings the interface up if
/// `bring_up_interface` allows it and it isn't up, runs the round of the node through its link to
/// the coordinator, and publishes the names of the round's snapshot to the DNS server of `state`,
/// what the node keeps from one round to the next.
#[allow(clippy::too_many_arguments)]
pub async fn round(
    config_dir: &Path,
    data_dir: &Path,
    network_opts: &NetworkOpts,
    hosts_opts: &HostsOpts,
    nat: &NatOpts,
    interface: &InterfaceName,
    bring_up_interface: bool,
    state: &mut NodeState,
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
    let store = DataStore::open_or_create(data_dir, interface, &config)?;
    let peers = store.peers()?;
    config.refuse_ip_keyed_endpoint_overrides(&peers)?;
    for peer in &peers {
        if let Some(endpoint_override) = config.endpoint_override_for_peer(peer) {
            log::debug!(
                "overriding peer {} ({}) with endpoint {}",
                peer.display_name(),
                peer.public_key,
                endpoint_override
            );
        }
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
            events: state.events.clone(),
        }),
    };
    let mut link = RemoteLink {
        interface: *interface,
        config: &config,
        store,
        rest_client: RestClient::for_interface(&config, data_dir, interface)?,
        fetched: false,
    };
    let round = node.round(&mut link).await?;
    if let Some(dns) = &mut state.dns {
        dns.update(config.dns.as_ref(), &round.snapshot).await;
    }

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
    config: &'a InterfaceConfig,
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
        let state = match self.rest_client.get_state().await {
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
                peer.display_address(),
                e
            );
        }
        record_coordinator(&mut self.store, self.config, &self.rest_client);
        self.fetched = true;
        Ok(())
    }

    fn snapshot(&self) -> Result<Snapshot, Error> {
        self.store.snapshot()
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

/// Records in `store` that the coordinator speaks TLS, and the QUIC port at which it answered, as
/// `rest_client` learned them. A data store that the client first made without an invitation, as
/// when the client was upgraded from v2.0.0, records the coordinator only once the server reports
/// it; until then, nothing is recorded.
fn record_coordinator(store: &mut DataStore, config: &InterfaceConfig, rest_client: &RestClient) {
    if !rest_client.speaks_tls() {
        return;
    }
    let server_key = &config.server.public_key;
    let mut record = || -> Result<(), Error> {
        if !store.records_peer(server_key)? {
            return Ok(());
        }
        if !store.speaks_tls(server_key)? {
            store.latch_tls(server_key)?;
        }
        match rest_client.quic_port() {
            Some(port) if store.quic_port(server_key)? != Some(port) => {
                store.set_quic_port(server_key, port)
            },
            _ => Ok(()),
        }
    };
    if let Err(e) = record() {
        log::warn!("failed to record that the innernet server speaks TLS, and its port: {e:#}");
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

fn print_peer_diff(peers: &[PeerContents], diff: &Realized) {
    let public_key = &diff.public_key;

    let change_action = match (diff.existed, &diff.new) {
        (false, _) => ChangeAction::Added,
        (true, Some(_)) => ChangeAction::Modified,
        (true, None) => ChangeAction::Removed,
    };

    // Grab the peer name from either the new data, or the historical data (if the peer is removed).
    let peer_name = match &diff.new {
        Some(peer) => Some(peer.display_name()),
        None => peers
            .iter()
            .find(|p| &p.public_key == public_key)
            .map(|p| p.display_name()),
    }
    .unwrap_or("[unknown]");

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
