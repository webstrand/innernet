pub use innernet_shared::interface_config::InterfaceConfig;
pub use wireguard_control::InterfaceName;

use crate::{
    data_store::DataStore,
    nat::{self, NatTraverse},
    rest_client::{RestClient, RestError},
    HostsOpts, NatOpts, NetworkOpts, WrappedIoError,
};
use anyhow::{bail, Context as _, Error};
use colored::{ColoredString, Colorize};
use innernet_shared::{
    announcement::{self, Announcement, AnnouncementSigner, DnsAnnouncement, Received},
    get_local_addrs, peer_hostname, prefix_set, update_hosts_file,
    wg::{self, DeviceExt as _},
    Endpoint, Peer, PeerChange, PeerDiff, RedeemContents, State, REDEEM_TRANSITION_WAIT,
};
#[cfg(target_os = "linux")]
use ipnet::IpNet;
use std::{
    io,
    net::{IpAddr, SocketAddr},
    path::Path,
    thread,
    time::{Duration, Instant},
};
use thiserror::Error;
use wireguard_control::{Backend, Device, DeviceUpdate, Key, PeerConfigBuilder};

#[derive(Debug, Error)]
pub enum RedeemInviteError {
    #[error("Error accessing innernet interface config file: {0}")]
    InterfaceConfigAccess(WrappedIoError),
    #[error("Config file for innernet interface {0} already exists.")]
    InterfaceConfigExists(InterfaceName),
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
/// - Bails if either a WireGuard or an innernet `interface` of the same name already exists and
///   brings the interface down if it was already up.
pub fn redeem_invite(
    config_dir: &Path,
    network_opts: &NetworkOpts,
    interface: &InterfaceName,
    config: InterfaceConfig,
) -> Result<(), RedeemInviteError> {
    let config_path = InterfaceConfig::build_config_file_path(config_dir, interface)
        .map_err(RedeemInviteError::InterfaceConfigAccess)?;

    if config_path.exists() {
        return Err(RedeemInviteError::InterfaceConfigExists(*interface));
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

    update_keypair(network_opts, interface, &config_path, config).inspect_err(|e| {
        log::error!("failed to update keypair (is the innernet server reachable?): {e}.",);
        log::info!("bringing down the interface.");
        if let Err(e) = wg::down(interface, network_opts.backend) {
            log::warn!("failed to bring down interface: {}.", e);
        };
    })?;

    Ok(())
}

fn update_keypair(
    network_opts: &NetworkOpts,
    interface: &InterfaceName,
    config_path: &Path,
    mut config: InterfaceConfig,
) -> Result<(), RedeemInviteError> {
    log::info!("Generating new keypair.");
    let keypair = wireguard_control::KeyPair::generate();

    log::info!(
        "Registering keypair with server (at {}).",
        config.server.internal_endpoint
    );
    RestClient::new(&config)?.http_form::<_, ()>(
        "POST",
        "/user/redeem",
        RedeemContents {
            public_key: keypair.public.to_base64(),
        },
    )?;

    config.interface.private_key = keypair.private.to_base64();
    config
        .save_new(config_path, 0o600)
        .map_err(RedeemInviteError::InterfaceConfigAccess)?;
    log::info!(
        "New keypair registered. Copied config to {}.\n",
        config_path.to_string_lossy().yellow()
    );

    log::info!("Changing keys and waiting 5s for server's WireGuard interface to transition.",);
    DeviceUpdate::new()
        .set_private_key(keypair.private)
        .apply(interface, network_opts.backend)
        .map_err(|e| RedeemInviteError::WireguardOperation {
            interface: *interface,
            error: e,
        })?;
    thread::sleep(REDEEM_TRANSITION_WAIT);

    Ok(())
}

pub fn fetch(
    config_dir: &Path,
    data_dir: &Path,
    network_opts: &NetworkOpts,
    hosts_opts: &HostsOpts,
    nat: &NatOpts,
    interface: &InterfaceName,
    bring_up_interface: bool,
) -> Result<(), Error> {
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
    let mut store = DataStore::open_or_create(data_dir, interface, &config)?;
    let rest_client = RestClient::new(&config)?;
    let mut state = match rest_client.http::<State>("GET", "/user/state") {
        Ok(state) => Some(state),
        Err(e) if e.is_transport_error() => {
            if store.peers().is_empty() {
                bail!(
                    "Could not connect to the innernet server and there are no cached peers, \
                     exiting."
                )
            }

            log::warn!(
                "Could not connect to the innernet server, proceeding with cached state instead."
            );
            None
        },
        Err(e) => bail!(e),
    };

    let device = Device::get(interface, network_opts.backend)?;
    let own_public_key = device
        .public_key
        .clone()
        .context("the interface has no private key")?;
    let network = Key::from_base64(&config.server.public_key)
        .map_err(|_| anyhow::anyhow!("the server's public key in the config is invalid"))?;

    if let Some(state) = &mut state {
        warn_about_server_endpoint_override(&config, &own_public_key, &state.peers);
        // The announcements are applied before the update, so that the data store keeps the
        // announcement that it accepted from each peer, and the endpoints derived from it.
        apply_announcements(
            &store,
            &mut state.peers,
            &network,
            nat.max_clock_ahead.clone().into(),
        );

        let refused = store.update(state).context(interface.to_string())?;
        for refusal in refused {
            match refusal.delegation {
                Some(prefix) => log::warn!(
                    "{}: dropping delegation {} of peer {}: {}",
                    interface.as_str_lossy().yellow(),
                    prefix,
                    refusal.peer.display_name(),
                    refusal.error
                ),
                None => log::warn!(
                    "{}: dropping peer {}: {}",
                    interface.as_str_lossy().yellow(),
                    refusal.peer.display_name(),
                    refusal.error
                ),
            }
        }
    }

    // The interface is configured from the enabled peers of the data store, with the local peer
    // endpoint overrides applied. An override follows the public key of its peer.
    let peers = store.peers();
    for peer in peers {
        if let Some(endpoint_override) = config.endpoint_override_for_peer(peer) {
            log::debug!(
                "overriding peer {} ({}) with endpoint {}",
                peer.display_name(),
                peer.public_key,
                endpoint_override
            );
        }
    }

    let modifications = device.diff(peers, config.peer_endpoint_overrides());

    let updates = modifications
        .iter()
        .inspect(|diff| print_peer_diff(&store, diff))
        .cloned()
        .map(PeerConfigBuilder::from)
        .collect::<Vec<_>>();

    if !updates.is_empty() || !interface_up {
        DeviceUpdate::new()
            .add_peers(&updates)
            .apply(interface, network_opts.backend)
            .context(interface.to_string())?;

        if !hosts_opts.no_write_hosts {
            update_hosts_file(
                interface,
                hosts_opts,
                peers.iter().filter(|peer| !peer.is_disabled),
            )?;
        }

        println!();
        log::info!("updated interface {}\n", interface.as_str_lossy().yellow());
    } else {
        log::info!("{}", "peers are already up to date".green());
    }
    let interface_updated_time = Instant::now();

    let own_peer = peers
        .iter()
        .find(|p| p.public_key == own_public_key.to_base64());
    add_extra_addresses(interface, &config.interface.extra_addresses, own_peer);
    let listen_port = device.listen_port.unwrap_or(51820);
    if state.is_some() {
        // Fails before anything is sent if the private key doesn't match the interface.
        let signer = AnnouncementSigner::new(&config.interface.private_key, &own_public_key)
            .context(interface.to_string())?;
        report_announcement(
            &rest_client,
            nat,
            listen_port,
            &config,
            interface,
            hosts_opts,
            own_peer,
            &signer,
            &network,
        )?;
    }

    if nat.no_nat_traversal {
        log::debug!("NAT traversal explicitly disabled, not attempting.");
    } else {
        let mut nat_traverse =
            NatTraverse::new(interface, &config, network_opts.backend, &modifications)?;

        // Give time for handshakes with recently changed endpoints to complete before attempting traversal.
        if !nat_traverse.is_finished() {
            thread::sleep(nat::STEP_INTERVAL - interface_updated_time.elapsed());
        }
        loop {
            if nat_traverse.is_finished() {
                break;
            }
            log::info!(
                "Attempting to establish connection with {} remaining unconnected peers...",
                nat_traverse.remaining()
            );
            nat_traverse.step()?;
        }
    }

    Ok(())
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

fn print_peer_diff(store: &DataStore, diff: &PeerDiff) {
    let public_key = diff.public_key().to_base64();

    let change_action = match (diff.old, diff.new) {
        (None, Some(_)) => ChangeAction::Added,
        (Some(_), Some(_)) => ChangeAction::Modified,
        (Some(_), None) => ChangeAction::Removed,
        _ => unreachable!("PeerDiff can't be None -> None"),
    };

    // Grab the peer name from either the new data, or the historical data (if the peer is removed).
    let peer_name = match diff.new {
        Some(peer) => Some(peer.display_name()),
        None => store
            .peers()
            .iter()
            .find(|p| p.public_key == public_key)
            .map(|p| p.display_name()),
    }
    .unwrap_or("[unknown]");

    if change_action == ChangeAction::Modified
        && diff
            .changes()
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

    for change in diff.changes() {
        if let PeerChange::Endpoint { .. } = change {
            log::info!("    {}", change);
        } else {
            log::debug!("    {}", change);
        }
    }
}

/// Replaces each peer's endpoints with those derived from its signed announcement.
///
/// The announcement used is the newer of the one received from the server and the one last
/// accepted from the peer, kept with the peer in `store`. Once one has been accepted from a
/// peer, the unsigned endpoints the server sends for it are disregarded.
fn apply_announcements(
    store: &DataStore,
    peers: &mut [Peer],
    network: &Key,
    max_clock_ahead: Duration,
) {
    let now = announcement::timestamp_now();
    for peer in peers {
        let Ok(signer) = Key::from_base64(&peer.public_key) else {
            continue;
        };
        let accepted = store
            .peers()
            .iter()
            .find(|p| p.public_key == peer.public_key)
            .and_then(|p| p.announcement.as_ref());
        let received = peer.contents.announcement.take();
        let (selected, outcome) = announcement::select(
            accepted,
            received.as_ref(),
            network,
            &signer,
            now,
            max_clock_ahead,
        );

        match outcome {
            Received::Nothing | Received::Unchanged | Received::Accepted => {},
            Received::Stale => log::warn!(
                "the server sent an older announcement for peer {} than one already \
                 accepted; ignoring it.",
                peer.display_name()
            ),
            Received::TooFarAhead => log::warn!(
                "the announcement for peer {} is dated too far in the future; ignoring \
                 it for now. Either its clock or this one is wrong.",
                peer.display_name()
            ),
            Received::Invalid => log::warn!(
                "the server sent an announcement for peer {} that isn't signed by its \
                 key; ignoring it.",
                peer.display_name()
            ),
            Received::UnknownCritical(tag) => log::warn!(
                "the announcement for peer {} needs a newer innernet (critical \
                 extension {tag:#06x}); ignoring it.",
                peer.display_name()
            ),
        }

        // Until an announcement has been accepted from the peer, its unsigned endpoints are
        // used, since the server could equally have withheld the announcement.
        if let Some(selected) = selected {
            let (endpoint, candidates) = selected
                .announcement
                .endpoints(peer.observed_endpoint.as_ref());
            peer.contents.endpoint = endpoint;
            peer.contents.candidates = candidates;
            peer.contents.announcement = Some(selected.clone());
        }
    }
}

/// The extra addresses that lie within one of the delegations of `own_peer`, this peer as
/// fetched, warning about the others.
fn valid_extra_addresses(extra_addresses: &[IpAddr], own_peer: Option<&Peer>) -> Vec<IpAddr> {
    let delegations = own_peer.map_or(&[][..], |peer| &peer.delegations[..]);
    extra_addresses
        .iter()
        .copied()
        .filter(|address| {
            let is_delegated = delegations.iter().any(|d| d.contains(address));
            if !is_delegated {
                log::warn!(
                    "extra address {address} is not within any of this peer's delegations; not \
                     adding it to the interface."
                );
            }
            is_delegated
        })
        .collect()
}

/// Adds those of the extra addresses that are delegated to this peer and missing from the
/// interface. Addresses are never removed, since some may not have been added by innernet.
fn add_extra_addresses(
    interface: &InterfaceName,
    extra_addresses: &[IpAddr],
    own_peer: Option<&Peer>,
) {
    if extra_addresses.is_empty() {
        return;
    }
    let extra_addresses = valid_extra_addresses(extra_addresses, own_peer);
    #[cfg(not(target_os = "linux"))]
    if !extra_addresses.is_empty() {
        log::warn!(
            "extra addresses are only supported on Linux; not adding them to {}.",
            interface
        );
    }
    #[cfg(target_os = "linux")]
    {
        let present = match wg::get_addrs(interface) {
            Ok(present) => present,
            Err(e) => {
                log::warn!("failed to list the interface's addresses: {e}; not adding extra ones.");
                return;
            },
        };
        for address in extra_addresses {
            if present.contains(&address) {
                continue;
            }
            match wg::set_addr(interface, IpNet::from(address)) {
                Ok(()) => log::info!("added extra address {address} to the interface."),
                Err(e) => log::warn!("failed to add extra address {address}: {e}."),
            }
        }
    }
}

/// Warns if the server holds an endpoint override for this peer that isn't in the local
/// config, as set by `override-endpoint` before announcements were signed. It is not signed,
/// so peers that verify announcements won't use it.
fn warn_about_server_endpoint_override(
    config: &InterfaceConfig,
    own_public_key: &Key,
    peers: &[Peer],
) {
    if config.interface.external_endpoint.is_some() {
        return;
    }
    let own_public_key = own_public_key.to_base64();
    let Some(own) = peers.iter().find(|p| p.public_key == own_public_key) else {
        return;
    };
    // Without an override, the server reports the observed endpoint as the endpoint.
    if let (Some(endpoint), Some(observed)) = (&own.endpoint, &own.observed_endpoint) {
        if endpoint != observed {
            log::warn!(
                "the server has an endpoint override ({endpoint}) for this peer that isn't in \
                 the local config, so peers will not use it. Run 'innernet override-endpoint' \
                 to set it again, or 'innernet override-endpoint --unset' to clear it."
            );
        }
    }
}

/// Signs and reports this peer's announcement: the endpoints it can be reached at, which are its
/// override from the local config and its local interface addresses as NAT traversal
/// candidates, the parts of its delegations that the local config selects, and the nameserver
/// that the local config offers. `own_peer` is this peer as the data store holds it.
#[allow(clippy::too_many_arguments)]
fn report_announcement(
    rest_client: &RestClient,
    nat: &NatOpts,
    listen_port: u16,
    config: &InterfaceConfig,
    interface: &InterfaceName,
    hosts_opts: &HostsOpts,
    own_peer: Option<&Peer>,
    signer: &AnnouncementSigner,
    network: &Key,
) -> Result<(), Error> {
    let delegations = own_peer.map_or(&[][..], |peer| &peer.delegations[..]);
    let mut candidates = local_candidates(nat, listen_port)?;
    candidates.truncate(10);
    let endpoint = config.interface.external_endpoint.clone();
    // Let peers use the endpoint the server observes unless this peer knows a public one.
    let allow_observed = match &endpoint {
        Some(endpoint) => endpoint.is_host_unspecified(),
        None => !candidates.iter().any(Endpoint::is_public_ipv4),
    };
    let signed = signer.sign(
        network,
        Announcement {
            timestamp: announcement::timestamp_now(),
            endpoint,
            candidates,
            allow_observed,
            delegations: prefix_set::select(delegations, &config.interface.announce_delegations()),
            dns: dns_announcement(config, interface, hosts_opts, own_peer),
            extensions: vec![],
        },
    )?;

    match rest_client.http_form::<_, ()>("PUT", "/user/announcement", &signed) {
        Ok(()) => log::debug!("signed announcement successfully reported"),
        Err(e) if e.has_status_of(404) => {
            log::warn!(
                "your network is using an old version of innernet-server that doesn't relay \
                 signed announcements."
            );
            report_candidates(rest_client, signed.announcement.candidates)?;
        },
        Err(e) if e.has_status_of(422) => log::warn!(
            "the server rejected this peer's announcement as dated too far in the \
             future; this clock or the server's may be wrong. Peers keep using the previous one."
        ),
        Err(e) if e.has_status_of(409) => log::warn!(
            "the server holds a newer announcement than this one; the clock may have \
             gone backwards. Peers keep using the newer one."
        ),
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// The nameserver that the local config offers, with its zone, which defaults to this peer's
/// hostname. Without a zone and a name to derive it from, or with an invalid zone, none is
/// offered.
fn dns_announcement(
    config: &InterfaceConfig,
    interface: &InterfaceName,
    hosts_opts: &HostsOpts,
    own_peer: Option<&Peer>,
) -> Option<DnsAnnouncement> {
    let nameserver = config.interface.announce_nameserver?;
    let zone = match &config.interface.announce_zone {
        Some(zone) => zone.clone(),
        None => {
            let name = own_peer.and_then(|peer| peer.name.as_ref());
            match name
                .and_then(|name| peer_hostname(interface, hosts_opts.host_suffix.as_deref(), name))
            {
                Some(zone) => zone,
                None => {
                    log::warn!(
                        "this peer has no hostname to serve as the zone of its nameserver; set \
                         announce-zone to offer it."
                    );
                    return None;
                },
            }
        },
    };
    if !innernet_domain::is_canonical_domain(&zone) {
        log::warn!("the zone {zone:?} of this peer's nameserver is not a valid domain name; not offering it.");
        return None;
    }
    Some(DnsAnnouncement { nameserver, zone })
}

fn local_candidates(nat: &NatOpts, listen_port: u16) -> Result<Vec<Endpoint>, Error> {
    let candidates: Vec<Endpoint> = get_local_addrs()?
        .filter(|ip| !nat.is_excluded(*ip))
        .map(|addr| SocketAddr::from((addr, listen_port)).into())
        .collect::<Vec<Endpoint>>();
    log::info!(
        "reporting {} interface address{} as NAT traversal candidates",
        candidates.len(),
        if candidates.len() == 1 { "" } else { "es" },
    );
    for candidate in &candidates {
        log::debug!("  candidate: {}", candidate);
    }
    Ok(candidates)
}

fn report_candidates(rest_client: &RestClient, candidates: Vec<Endpoint>) -> Result<(), Error> {
    if let Err(e) = rest_client.http_form::<_, ()>("PUT", "/user/candidates", &candidates) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use innernet_shared::{announcement::SignedAnnouncement, PeerContents};
    use wireguard_control::KeyPair;

    struct Fixture {
        _dir: tempfile::TempDir,
        store: DataStore,
        network: Key,
        signer: AnnouncementSigner,
        peer: Peer,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let config: InterfaceConfig = serde_json::from_value(serde_json::json!({
                "interface": {
                    "network-name": "test0",
                    "address": "10.0.0.3/16",
                    "private-key": KeyPair::generate().private.to_base64(),
                },
                "server": {
                    "public-key": KeyPair::generate().public.to_base64(),
                    "external-endpoint": "198.51.100.1:51820",
                    "internal-endpoint": "10.0.0.1:51820",
                },
            }))
            .unwrap();
            let store =
                DataStore::open_or_create(dir.path(), &"test0".parse().unwrap(), &config).unwrap();
            let keypair = KeyPair::generate();
            let signer =
                AnnouncementSigner::new(&keypair.private.to_base64(), &keypair.public).unwrap();
            let peer = Peer {
                id: 1,
                contents: PeerContents {
                    name: Some("peer".parse().unwrap()),
                    ip: "10.0.0.2".parse().unwrap(),
                    cidr_id: 1,
                    public_key: keypair.public.to_base64(),
                    endpoint: Some("203.0.113.66:1".parse().unwrap()),
                    persistent_keepalive_interval: None,
                    is_admin: false,
                    is_disabled: false,
                    is_redeemed: true,
                    invite_expires: None,
                    candidates: vec!["203.0.113.66:2".parse().unwrap()],
                    announcement: None,
                    observed_endpoint: Some("198.51.100.7:40000".parse().unwrap()),
                    delegations: vec![],
                },
            };
            Self {
                _dir: dir,
                store,
                network: KeyPair::generate().public,
                signer,
                peer,
            }
        }

        fn sign(&self, timestamp: u64, endpoint: &str) -> SignedAnnouncement {
            self.signer
                .sign(
                    &self.network,
                    Announcement {
                        timestamp,
                        endpoint: Some(endpoint.parse().unwrap()),
                        candidates: vec!["192.168.1.2:51820".parse().unwrap()],
                        allow_observed: false,
                        delegations: vec![],
                        dns: None,
                        extensions: vec![],
                    },
                )
                .unwrap()
        }

        /// Applies announcements to a peer as received from the server, saves the result like
        /// `fetch` does, and returns it.
        fn fetch(&mut self, received: Option<SignedAnnouncement>) -> Peer {
            let mut state = State {
                peers: vec![self.peer.clone()],
                cidrs: vec![],
            };
            state.peers[0].contents.announcement = received;
            apply_announcements(
                &self.store,
                &mut state.peers,
                &self.network,
                announcement::DEFAULT_MAX_CLOCK_AHEAD,
            );
            assert!(self.store.update(&state).unwrap().is_empty());
            state.peers.pop().unwrap()
        }
    }

    #[test]
    fn test_unsigned_endpoints_used_until_latched() {
        let mut f = Fixture::new();
        let peer = f.fetch(None);
        assert_eq!(peer.endpoint, f.peer.endpoint);
        assert_eq!(peer.candidates, f.peer.candidates);
    }

    #[test]
    fn test_latched_announcement_overrides_server() {
        let mut f = Fixture::new();
        let first = f.sign(10, "203.0.113.1:51820");
        let peer = f.fetch(Some(first.clone()));
        assert_eq!(peer.endpoint, Some("203.0.113.1:51820".parse().unwrap()));
        // allow_observed is off, so the observed endpoint is not added.
        assert_eq!(peer.candidates, first.announcement.candidates);

        // Withheld, forged, or stale: the accepted announcement keeps being used.
        let mut forged = f.sign(20, "203.0.113.1:51820");
        forged.announcement.endpoint = Some("203.0.113.66:1".parse().unwrap());
        let stale = f.sign(5, "203.0.113.5:51820");
        for received in [None, Some(forged), Some(stale)] {
            let peer = f.fetch(received);
            assert_eq!(peer.endpoint, Some("203.0.113.1:51820".parse().unwrap()));
            assert_eq!(peer.announcement.as_ref(), Some(&first));
        }

        let newer = f.sign(30, "203.0.113.3:51820");
        let peer = f.fetch(Some(newer.clone()));
        assert_eq!(peer.endpoint, Some("203.0.113.3:51820".parse().unwrap()));
        assert_eq!(peer.announcement, Some(newer));
    }

    #[test]
    fn test_invalid_announcement_before_latching() {
        let mut f = Fixture::new();
        let mut forged = f.sign(10, "203.0.113.1:51820");
        forged.announcement.timestamp = 11;
        let peer = f.fetch(Some(forged));
        assert_eq!(peer.announcement, None);
        assert_eq!(peer.endpoint, f.peer.endpoint);
    }

    fn peer_with_delegations(delegations: &[&str]) -> Peer {
        let mut peer = Fixture::new().peer;
        peer.contents.delegations = delegations.iter().map(|d| d.parse().unwrap()).collect();
        peer
    }

    fn addrs(addrs: &[&str]) -> Vec<IpAddr> {
        addrs.iter().map(|a| a.parse().unwrap()).collect()
    }

    #[test]
    fn test_valid_extra_addresses() {
        let peer = peer_with_delegations(&["10.0.0.32/28", "10.0.0.7/32", "fd00::1:0/112"]);
        let extra = addrs(&[
            "10.0.0.33",
            "10.0.0.47",
            "10.0.0.48",
            "10.0.0.7",
            "10.0.0.2",
            "fd00::1:5",
            "fd00::2:5",
        ]);
        assert_eq!(
            valid_extra_addresses(&extra, Some(&peer)),
            addrs(&["10.0.0.33", "10.0.0.47", "10.0.0.7", "fd00::1:5"])
        );
        assert!(valid_extra_addresses(&extra, None).is_empty());
        let peer = peer_with_delegations(&[]);
        assert!(valid_extra_addresses(&extra, Some(&peer)).is_empty());
    }

    #[test]
    fn test_dns_announcement() {
        let interface: InterfaceName = "test0".parse().unwrap();
        let config = |zone: Option<&str>| -> InterfaceConfig {
            let mut interface = serde_json::json!({
                "network-name": "test0",
                "address": "10.0.0.3/16",
                "private-key": KeyPair::generate().private.to_base64(),
                "announce-nameserver": "10.0.0.3:53",
            });
            if let Some(zone) = zone {
                interface["announce-zone"] = zone.into();
            }
            serde_json::from_value(serde_json::json!({
                "interface": interface,
                "server": {
                    "public-key": KeyPair::generate().public.to_base64(),
                    "external-endpoint": "198.51.100.1:51820",
                    "internal-endpoint": "10.0.0.1:51820",
                },
            }))
            .unwrap()
        };
        let hosts = |suffix: Option<&str>| HostsOpts {
            hosts_path: "/nonexistent".into(),
            no_write_hosts: true,
            host_suffix: suffix.map(str::to_string),
        };
        let peer = Fixture::new().peer;
        let zone = |zone, suffix, peer: Option<&Peer>| {
            dns_announcement(&config(zone), &interface, &hosts(suffix), peer).map(|dns| dns.zone)
        };
        let name = peer.name.as_deref().unwrap().to_string();

        // The zone defaults to the peer's hostname under the local host suffix.
        assert_eq!(
            zone(None, None, Some(&peer)),
            Some(format!("{name}.test0.wg"))
        );
        assert_eq!(
            zone(None, Some("lan"), Some(&peer)),
            Some(format!("{name}.lan"))
        );
        assert_eq!(zone(None, Some(""), Some(&peer)), Some(name));
        // A configured zone takes precedence, and an invalid one offers nothing.
        assert_eq!(
            zone(Some("example.com"), None, Some(&peer)).as_deref(),
            Some("example.com")
        );
        assert_eq!(zone(Some("Example.com"), None, Some(&peer)), None);
        // Without a name, only a configured zone offers the nameserver.
        let mut nameless = peer.clone();
        nameless.contents.name = None;
        assert_eq!(zone(None, None, Some(&nameless)), None);
        assert_eq!(zone(None, None, None), None);
        assert_eq!(
            zone(Some("example.com"), None, Some(&nameless)).as_deref(),
            Some("example.com")
        );

        let dns = dns_announcement(&config(None), &interface, &hosts(None), Some(&peer)).unwrap();
        assert_eq!(dns.nameserver, "10.0.0.3:53".parse().unwrap());
    }
}
