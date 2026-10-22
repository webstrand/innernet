pub use innernet_shared::interface_config::InterfaceConfig;
pub use wireguard_control::InterfaceName;

use crate::{
    data_store::{DataStore, Relay},
    rest_client::{RestClient, RestError},
    HostsOpts, NatOpts, NetworkOpts, WrappedIoError,
};
use anyhow::{bail, Context as _, Error};
use colored::{ColoredString, Colorize};
use innernet_node::{
    events::EventSource,
    realize::{DnsService, Realized, WireGuard},
    runtime::{self, Link, Node, Round},
    snapshot::{Own, Snapshot, SnapshotConfig},
};
use innernet_shared::{
    announcement::SignedAnnouncement,
    interface_config::{ResolvedInvitation, FEATURE_TLS},
    wg, Endpoint, IoErrorContext, PeerChange, PeerContents, Prefix, RedeemContents,
    ServerCapabilities, State, REDEEM_TRANSITION_WAIT,
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
    let rest_client = RestClient::for_interface(&config, data_dir, interface)?;
    let device = Device::get(interface, network_opts.backend)?;
    let listen_port = device.listen_port.unwrap_or(51820);
    let mut node = Node {
        interface: *interface,
        info: config.interface.clone(),
        listen_port,
        nat: nat.clone(),
        snapshot_config: SnapshotConfig::default(),
        tunnel: Box::new(WireGuard {
            interface: *interface,
            backend: network_opts.backend,
            endpoint_overrides: config.peer_endpoint_overrides().clone(),
            events: state.events.clone(),
        }),
    };
    let mut link = RemoteLink {
        store,
        rest_client: &rest_client,
        config: &config,
        interface,
        state: None,
        claim_types: None,
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

    // A server that checks no claims accepts no announcement, and takes what it relays of this
    // client as this client reports it.
    if link.state.is_some() && link.claim_types.as_deref() == Some(&[]) {
        report_candidates(&rest_client, nat, listen_port).await?
    }

    Ok(round)
}

/// A client's link to its coordinator, over the API: each round fetches the state and merges it
/// into the data store, as [`DataStore::update`] does, and the client announces itself to the
/// coordinator.
struct RemoteLink<'a> {
    store: DataStore,
    rest_client: &'a RestClient<'a>,
    config: &'a InterfaceConfig,
    interface: &'a InterfaceName,
    /// The state that the coordinator reported in the last round, or `None` if the client could not
    /// reach the coordinator and goes on with what its data store holds.
    state: Option<State>,
    claim_types: Option<Vec<String>>,
}

impl Link for RemoteLink<'_> {
    async fn sync(&mut self) -> Result<(), Error> {
        let interface = self.interface;
        self.state = match self.rest_client.get_state().await {
            Ok(state) => Some(state),
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
                None
            },
            Err(e) => bail!(e),
        };
        let Some(state) = &self.state else {
            self.claim_types = None;
            return Ok(());
        };

        // The types of claims that the server checks, of which this client accepts the claims of
        // the announcements that the server relays, and announces its own.
        self.claim_types = claim_types(self.rest_client).await;

        // The data store validates the reported state before any of it reaches the interface. A
        // server that doesn't speak TLS relays no announcements, so each of its peers is taken to
        // make the unsigned announcement of what the server reports of it.
        let relay = match self.claim_types.as_deref() {
            _ if !self.rest_client.speaks_tls() => Relay::Synthesized,
            Some(claim_types) => Relay::Announcements(claim_types),
            None => Relay::Unknown,
        };
        let dropped = self
            .store
            .update(state, relay)
            .context(interface.to_string())?;
        for (peer, e) in dropped {
            log::warn!(
                "{}: dropping peer {} at {} from the update: {}",
                interface.as_str_lossy().yellow(),
                peer.public_key,
                peer.display_address(),
                e
            );
        }
        record_coordinator(&mut self.store, self.config, self.rest_client);
        Ok(())
    }

    fn snapshot(&self, config: &SnapshotConfig, own: Option<Own>) -> Result<Snapshot, Error> {
        self.store.snapshot_as(config, own)
    }

    fn last_announced(&self, public_key: &str) -> Result<Option<u64>, Error> {
        Ok(self
            .store
            .announcement(public_key)?
            .map(|announcement| announcement.timestamp))
    }

    fn assignment(&self) -> Result<Option<PeerContents>, Error> {
        let own_key = self.config.interface.public_key()?;
        Ok(self.state.as_ref().and_then(|state| {
            state
                .peers
                .iter()
                .find(|peer| peer.public_key == own_key)
                .cloned()
        }))
    }

    fn claim_types(&self) -> Option<Vec<String>> {
        self.state.as_ref().and(self.claim_types.clone())
    }

    fn observed_endpoint(&self) -> Option<Endpoint> {
        self.state.as_ref()?.observed_endpoint.clone()
    }

    async fn announce(
        &mut self,
        signed: &SignedAnnouncement,
        claim_types: &[String],
    ) -> Result<(), Error> {
        self.rest_client
            .http_form::<_, ()>("PUT", "/user/announcement", signed)
            .await?;
        let own_key = self.config.interface.public_key()?;
        self.store
            .accept_announcement(&own_key, signed, claim_types)
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

/// The types of claims that the coordination server checks in announcements, as its capabilities
/// state them: none for a server that doesn't speak TLS, which accepts no announcement, or `None`,
/// with a warning, if this client can't read them.
async fn claim_types(rest_client: &RestClient<'_>) -> Option<Vec<String>> {
    if !rest_client.speaks_tls() {
        return Some(vec![]);
    }
    match rest_client
        .http::<ServerCapabilities>("GET", "/user/capabilities")
        .await
    {
        Ok(capabilities) => Some(capabilities.announcement_claims),
        Err(e) => {
            log::warn!("failed to read the capabilities of the innernet server: {e}");
            None
        },
    }
}

async fn report_candidates(
    rest_client: &RestClient<'_>,
    nat: &NatOpts,
    listen_port: u16,
) -> Result<(), Error> {
    let candidates = runtime::local_candidates(nat, listen_port)?;
    log::info!(
        "reporting {} interface address{} as NAT traversal candidates",
        candidates.len(),
        if candidates.len() == 1 { "" } else { "es" },
    );
    for candidate in &candidates {
        log::debug!("  candidate: {}", candidate);
    }
    if let Err(e) = rest_client
        .http_form::<_, ()>("PUT", "/user/candidates", &candidates)
        .await
    {
        if e.has_status_of(404) {
            log::warn!("your network is using an old version of innernet-server that doesn't support NAT traversal candidate reporting.")
        } else {
            return Err(e.into());
        }
    }

    log::debug!("candidates successfully reported");
    Ok(())
}

pub fn interface_is_up(backend: Backend, interface_name: &InterfaceName) -> bool {
    match Device::list(backend) {
        Ok(interfaces) => interfaces.contains(interface_name),
        _ => false,
    }
}
