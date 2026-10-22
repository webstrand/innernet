use crate::util::all_installed;
use anyhow::{anyhow, bail, Context as _, Error};
use clap::{ArgAction, Parser, Subcommand};
use colored::*;
use dialoguer::{Confirm, Input};
use indoc::eprintdoc;
use innernet_client_core::{
    admin,
    data_store::DataStore,
    interface::{fetch, redeem_invite, round, NodeState},
    peer::coordinator_info,
    rest_client::RestClient,
    DEFAULT_CONFIG_DIR, DEFAULT_DATA_DIR,
};
use innernet_node::{
    addresses,
    events::EventSource,
    realize::DnsService,
    runtime::{self, Triggers},
};
use innernet_shared::{
    interface_config::{InterfaceConfig, Invitation},
    prompts, wg,
    wg::PeerInfoExt,
    AddCidrOpts, AddDeleteAssociationOpts, AddPeerOpts, CidrTree, DelegationOpts, DeleteCidrOpts,
    EnableDisablePeerOpts, HostsOpts, InstallOpts, Interface, IoErrorContext, NatOpts, NetworkOpts,
    PeerContents, Prefix, RenameCidrOpts, RenamePeerOpts, WrappedIoError,
};
use std::{
    collections::HashMap,
    fs::File,
    io,
    path::{Path, PathBuf},
    time::Duration,
};
use util::{human_duration, human_size};
use wireguard_control::{Device, InterfaceName, PeerInfo};

mod util;

struct PeerState<'a> {
    /// The peer as it takes effect.
    peer: &'a PeerContents,
    /// The peer as the coordination server reports it, with the ranges that it assigns this
    /// client as the delegations of this client.
    assigned: &'a PeerContents,
    /// Whether the peer has announced.
    announces: bool,
    info: Option<&'a PeerInfo>,
}

macro_rules! println_pad {
    ($pad:expr, $($arg:tt)*) => {
        print!("{:pad$}", "", pad = $pad);
        println!($($arg)*);
    }
}

#[derive(Clone, Debug, Parser)]
#[command(name = "innernet", author, version, about)]
struct Opts {
    #[clap(subcommand)]
    command: Option<Command>,

    /// Verbose output, use -vv for even higher verbositude
    #[clap(short, long, action = ArgAction::Count)]
    verbose: u8,

    #[clap(short, long, default_value = DEFAULT_CONFIG_DIR)]
    config_dir: PathBuf,

    #[clap(short, long, default_value = DEFAULT_DATA_DIR)]
    data_dir: PathBuf,

    #[clap(flatten)]
    network: NetworkOpts,
}

#[derive(Clone, Debug, Subcommand)]
enum Command {
    /// Install a new innernet config
    #[clap(alias = "redeem")]
    Install {
        /// Path to the invitation file
        invite: PathBuf,

        /// The local WireGuard listen port
        #[clap(long)]
        listen_port: Option<u16>,

        #[clap(flatten)]
        hosts: HostsOpts,

        #[clap(flatten)]
        install_opts: InstallOpts,

        #[clap(flatten)]
        nat: NatOpts,
    },

    /// Enumerate all innernet connections
    #[clap(alias = "list")]
    Show {
        /// One-line peer list
        #[clap(short, long)]
        short: bool,

        /// Display peers in a tree based on the CIDRs
        #[clap(short, long)]
        tree: bool,

        interface: Option<Interface>,
    },

    /// Bring up your local interface, and update it with latest peer list
    Up {
        /// Enable daemon mode i.e. keep the process running, while fetching
        /// the latest peer list periodically
        #[clap(short, long)]
        daemon: bool,

        /// Keep fetching the latest peer list at the specified interval in
        /// seconds. Valid only in daemon mode
        #[clap(long, default_value = "60")]
        interval: u64,

        #[clap(flatten)]
        hosts: HostsOpts,

        #[clap(flatten)]
        nat: NatOpts,

        interface: Option<Interface>,
    },

    /// Fetch and update your local interface with the latest peer list
    Fetch {
        interface: Interface,

        #[clap(flatten)]
        hosts: HostsOpts,

        #[clap(flatten)]
        nat: NatOpts,
    },

    /// Uninstall an innernet network.
    Uninstall {
        interface: Interface,

        /// Bypass confirmation
        #[clap(long)]
        yes: bool,
    },

    /// Bring down the interface (equivalent to 'wg-quick down INTERFACE')
    Down { interface: Interface },

    /// Add a new peer
    ///
    /// By default, you'll be prompted interactively to create a peer, but you can
    /// also specify all the options in the command, eg:
    ///
    /// --name 'person' --cidr 'humans' --admin false --auto-ip --save-config 'person.toml' --yes
    AddPeer {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: AddPeerOpts,
    },

    /// Rename a peer
    ///
    /// By default, you'll be prompted interactively to select a peer, but you can
    /// also specify all the options in the command, eg:
    ///
    /// --name 'person' --new-name 'human'
    RenamePeer {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: RenamePeerOpts,
    },

    /// Add a new CIDR
    AddCidr {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: AddCidrOpts,
    },

    /// Rename a CIDR
    ///
    /// By default, you'll be prompted interactively to select a CIDR, but you can
    /// also specify all the options in the command, eg:
    ///
    /// --name 'group' --new-name 'family'
    RenameCidr {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: RenameCidrOpts,
    },

    /// Delete a CIDR
    DeleteCidr {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: DeleteCidrOpts,
    },

    /// List CIDRs
    ListCidrs {
        interface: Interface,

        /// Display CIDRs in tree format
        #[clap(short, long)]
        tree: bool,
    },

    /// Disable an enabled peer
    DisablePeer {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: EnableDisablePeerOpts,
    },

    /// Enable a disabled peer
    EnablePeer {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: EnableDisablePeerOpts,
    },

    /// Delegate a prefix of a peer's CIDR to the peer
    ///
    /// The server must speak TLS. The prefix must be aligned, lie within the peer's CIDR, hold
    /// neither the network nor the broadcast address of the CIDR, and share no address with
    /// another delegation.
    AddDelegation {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: DelegationOpts,
    },

    /// Withdraw a delegation from a peer
    ///
    /// The server must speak TLS. Every node that has seen the peer keeps the prefix pinned to the
    /// peer's key, and refuses it to another peer. A peer left without a delegation is in effect
    /// disabled.
    WithdrawDelegation {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: DelegationOpts,
    },

    /// Mark a delegation of a peer to be reclaimed
    ///
    /// The server must speak TLS. A marked delegation stops being delegated to the peer once the
    /// peer, having claimed some of it, announces without claiming any of it, so that a
    /// cooperative peer can move.
    ReclaimDelegation {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: DelegationOpts,
    },

    /// Add an association between CIDRs
    AddAssociation {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: AddDeleteAssociationOpts,
    },

    /// Delete an association between CIDRs
    DeleteAssociation {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: AddDeleteAssociationOpts,
    },

    /// List existing assocations between CIDRs
    ListAssociations { interface: Interface },

    /// Generate shell completion scripts
    Completions {
        #[clap(value_enum)]
        shell: clap_complete::Shell,
    },
}

async fn install(
    opts: &Opts,
    hosts_opts: &HostsOpts,
    install_opts: &InstallOpts,
    nat_opts: &NatOpts,
    invite: &Path,
    listen_port: Option<u16>,
) -> Result<(), Error> {
    let mut invite_file = File::open(invite).with_path(invite)?;
    innernet_shared::warn_on_dangerous_mode(&invite_file, invite).with_path(invite)?;
    let mut invitation = Invitation::from_file(&mut invite_file)?.resolve()?;
    if let Some(listen_port) = listen_port {
        invitation.config.interface.listen_port = Some(listen_port);
    }

    let network_name = &invitation.config.interface.network_name;
    let interface_name = if install_opts.default_name {
        network_name.clone()
    } else if let Some(ref iface) = install_opts.name {
        iface.clone()
    } else {
        Input::with_theme(&*prompts::THEME)
            .with_prompt("Interface name")
            .default(network_name.clone())
            .interact()?
    };

    let interface_name = interface_name.parse()?;
    redeem_invite(
        &opts.config_dir,
        &opts.data_dir,
        &opts.network,
        &interface_name,
        invitation,
    )
    .await?;

    let mut fetch_success = false;
    for _ in 0..3 {
        if fetch(
            &opts.config_dir,
            &opts.data_dir,
            &opts.network,
            hosts_opts,
            nat_opts,
            &interface_name,
            true,
        )
        .await
        .is_ok()
        {
            fetch_success = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    if !fetch_success {
        log::warn!(
            "Failed to fetch peers from server, you will need to manually run the 'up' command.",
        );
    }

    if install_opts.delete_invite
        || Confirm::with_theme(&*prompts::THEME)
            .wait_for_newline(true)
            .with_prompt(format!(
                "Delete invitation file \"{}\" now? (It's no longer needed)",
                invite.to_string_lossy().yellow()
            ))
            .default(true)
            .interact()?
    {
        std::fs::remove_file(invite).with_path(invite)?;
    }

    eprintdoc!(
        "
        {star} Done!

            {interface} has been {installed}.

            See the manpage or innernet GitHub repo for more detailed instruction on managing your
            interface and network. Have fun!

    ",
        star = "[*]".dimmed(),
        interface = interface_name.to_string().yellow(),
        installed = "installed".green(),
    );
    if cfg!(target_os = "linux") {
        eprintdoc!(
            "
                It's recommended to now keep the interface automatically refreshing via systemd:

                    {systemctl_enable}{interface}
        ",
            interface = interface_name.to_string().yellow(),
            systemctl_enable = "systemctl enable --now innernet@".yellow(),
        );
    } else if cfg!(target_os = "macos") {
        eprintdoc!("
            It's recommended to now keep the interface automatically refreshing, which you can
            do via a launchd script (easier macOS helpers to be added to innernet in a later version).

            Ex. to run innernet in a 60s update loop:

                {daemon_mode} {interface}
        ",
            interface = interface_name.to_string().yellow(),
            daemon_mode = "innernet up -d --interval 60".yellow());
    } else {
        eprintdoc!(
            "
            It's recommended to now keep the interface automatically refreshing via whatever service
            system your distribution provides.

            Ex. to run innernet in a 60s update loop:

                {daemon_mode} {interface}
        ",
            interface = interface_name.to_string().yellow(),
            daemon_mode = "innernet up -d --interval 60".yellow()
        );
    }
    Ok(())
}

async fn up(
    specific_interface: Option<Interface>,
    opts: &Opts,
    loop_interval: Option<Duration>,
    hosts_opts: HostsOpts,
    nat_opts: &NatOpts,
) -> Result<(), Error> {
    let installed = || -> Result<Vec<Interface>, Error> {
        Ok(match &specific_interface {
            Some(iface) => vec![iface.clone()],
            None => all_installed(&opts.config_dir)?,
        })
    };
    let Some(interval) = loop_interval else {
        for interface in installed()? {
            fetch(
                &opts.config_dir,
                &opts.data_dir,
                &opts.network,
                &hosts_opts,
                nat_opts,
                &interface,
                true,
            )
            .await?;
        }
        return Ok(());
    };

    // An endpoint override keyed by IP does not resolve itself, so it is fatal at startup.
    for interface in installed()? {
        let config = InterfaceConfig::from_interface(&opts.config_dir, &interface)
            .with_context(|| interface.to_string())?;
        let peers = if DataStore::exists(&opts.data_dir, &interface)? {
            DataStore::open(&opts.data_dir, &interface, &config)?.peers()?
        } else {
            vec![]
        };
        config.refuse_ip_keyed_endpoint_overrides(&peers)?;
    }

    // Each interface runs its node's rounds in a task of its own, at the interval, whenever the
    // host's addresses change, and on the timers of NAT traversal. The interfaces are listed again
    // at each interval, so that one installed or uninstalled meanwhile starts or stops.
    let mut running: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        let interfaces = match installed() {
            Ok(interfaces) => interfaces,
            Err(e) => {
                log::error!("failed to list the installed interfaces: {e:#}");
                continue;
            },
        };
        running.retain(|name, task| {
            let installed = interfaces
                .iter()
                .any(|interface| interface.to_string() == *name);
            if !installed {
                task.abort();
            }
            installed
        });
        for interface in interfaces {
            if running.contains_key(&interface.to_string()) {
                continue;
            }
            let (config_dir, data_dir, network) =
                (opts.config_dir.clone(), opts.data_dir.clone(), opts.network);
            let (hosts, nat) = (hosts_opts.clone(), nat_opts.clone());
            let name = interface.to_string();
            let task = tokio::task::spawn_local(async move {
                let mut state = NodeState {
                    events: EventSource::default(),
                    dns: Some(DnsService::new(*interface, hosts.host_suffix.clone())),
                };
                let triggers = Triggers {
                    changed: None,
                    interval: Some(interval),
                    addresses: addresses::Watcher::new(ADDRESS_SETTLE)
                        .inspect_err(|e| log::warn!("can't watch the host's addresses: {e}"))
                        .ok(),
                };
                runtime::run(triggers, async || {
                    round(
                        &config_dir,
                        &data_dir,
                        &network,
                        &hosts,
                        &nat,
                        &interface,
                        true,
                        &mut state,
                    )
                    .await
                })
                .await
            });
            running.insert(name, task);
        }
    }
}

/// How long the watcher of the host's addresses waits for a burst of changes to settle.
const ADDRESS_SETTLE: Duration = Duration::from_millis(200);

fn uninstall(interface: &InterfaceName, opts: &Opts, yes: bool) -> Result<(), Error> {
    let config = InterfaceConfig::get_path(&opts.config_dir, interface);

    if !config.exists() && !DataStore::exists(&opts.data_dir, interface)? {
        bail!(
            "No network named \"{}\" exists.",
            interface.as_str_lossy().yellow()
        );
    }

    if yes
        || Confirm::with_theme(&*prompts::THEME)
            .with_prompt(format!(
                "Permanently delete network \"{}\"?",
                interface.as_str_lossy().yellow()
            ))
            .default(false)
            .wait_for_newline(true)
            .interact()?
    {
        log::info!("bringing down interface (if up).");
        wg::down(interface, opts.network.backend).ok();
        std::fs::remove_file(&config)
            .with_path(&config)
            .map_err(|e| log::warn!("{}", e.to_string().yellow()))
            .ok();
        for data in DataStore::get_paths(&opts.data_dir, interface) {
            match std::fs::remove_file(&data) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                result => {
                    result
                        .with_path(&data)
                        .map_err(|e| log::warn!("{}", e.to_string().yellow()))
                        .ok();
                },
            }
        }
        log::info!(
            "network {} is uninstalled.",
            interface.as_str_lossy().yellow()
        );
    }
    Ok(())
}

fn list_cidrs(interface: &InterfaceName, opts: &Opts, tree: bool) -> Result<(), Error> {
    let config = InterfaceConfig::from_interface(&opts.config_dir, interface)?;
    let data_store = DataStore::open(&opts.data_dir, interface, &config)?;

    let cidrs = data_store.cidrs()?;
    if tree {
        let cidr_tree = CidrTree::new(&cidrs);
        colored::control::set_override(false);
        print_tree(&cidr_tree, &[], 0, false, &config);
        colored::control::unset_override();
    } else {
        for cidr in &cidrs {
            println!("{} {}", cidr.cidr, cidr.name.escape_debug());
        }
    }
    Ok(())
}

fn show(opts: &Opts, short: bool, tree: bool, interface: Option<Interface>) -> Result<(), Error> {
    let interfaces = interface.map_or_else(
        || Device::list(opts.network.backend),
        |interface| Ok(vec![*interface]),
    )?;

    let devices = interfaces
        .into_iter()
        .map(|name| -> Result<Option<_>, Error> {
            // Skip WireGuard interfaces that aren't managed by innernet.
            if !DataStore::exists(&opts.data_dir, &name)? {
                return Ok(None);
            }

            // Error on interfaces that *are* managed by innernet but are not readable.
            let device = Device::get(&name, opts.network.backend).with_str(name.as_str_lossy())?;
            let config = InterfaceConfig::from_interface(&opts.config_dir, &name)?;
            let store = DataStore::open(&opts.data_dir, &name, &config)?;
            config.refuse_ip_keyed_endpoint_overrides(&store.peers()?)?;

            Ok(Some((device, store, config)))
        })
        // Filter out Ok(None).
        .filter_map(Result::transpose)
        .collect::<Result<Vec<_>, _>>()?;

    if devices.is_empty() {
        log::info!("No innernet networks currently running.");
        return Ok(());
    }

    for (device_info, store, interface_config) in devices {
        let public_key = match &device_info.public_key {
            Some(key) => key.to_base64(),
            None => {
                log::warn!(
                    "network {} is missing public key.",
                    device_info.name.to_string().yellow()
                );
                continue;
            },
        };

        let assigned = store.peers()?;
        let peers = store.effective_peers()?;
        let cidrs = store.cidrs()?;
        let state_of = |public_key: &str, info| {
            let index = assigned.iter().position(|p| p.public_key == public_key)?;
            Some(PeerState {
                peer: &peers[index],
                assigned: &assigned[index],
                announces: store.announces(public_key).unwrap_or(false),
                info,
            })
        };
        let me = state_of(&public_key, None).ok_or_else(|| anyhow!("missing peer info"))?;

        let mut peer_states = device_info
            .peers
            .iter()
            .map(|info| {
                let public_key = info.config.public_key.to_base64();
                state_of(&public_key, Some(info))
                    .ok_or_else(|| anyhow!("peer {} isn't an innernet peer.", public_key))
            })
            .collect::<Result<Vec<PeerState>, _>>()?;
        peer_states.push(me);

        print_interface(&device_info, short || tree)?;
        // Peers without an address come last.
        peer_states.sort_by_key(|peer| {
            let fallback = peer.peer.hosts_fallback();
            (fallback.is_none(), fallback)
        });
        let verbose = opts.verbose > 0;

        if tree {
            let cidr_tree = CidrTree::new(&cidrs);
            print_tree(&cidr_tree, &peer_states, 1, verbose, &interface_config);
        } else {
            for peer_state in peer_states {
                let endpoint_has_local_override = interface_config
                    .endpoint_override_for_peer(peer_state.peer)
                    .is_some();
                print_peer(&peer_state, short, 1, verbose, endpoint_has_local_override);
            }
        }
        print_unrouted_pins(&store, &peers, verbose);
    }
    Ok(())
}

/// Prints the prefixes pinned to a peer's key that aren't routed to it whole, with the reason:
/// those of a disabled peer, those that the coordination server has withdrawn from a peer that
/// has never signed an announcement, which stay pinned since an unsigned announcement releases
/// nothing, and those that the allowed IPs of a peer leave out, whole or in part. A prefix stays
/// pinned while the peer claims it, whether or not it is routed, so that no other peer can take
/// it, and an announcement that conflicts with it is refused; this lists what holds such
/// prefixes. `peers` are those of `store` as they take effect.
fn print_unrouted_pins(store: &DataStore, peers: &[PeerContents], verbose: bool) {
    let pins = match store.pins() {
        Ok(pins) => pins,
        Err(e) => {
            log::warn!("failed to read the pins: {e:#}");
            return;
        },
    };
    let mut unrouted: Vec<(Prefix, &PeerContents, &str)> = pins
        .into_iter()
        .filter_map(|(pinned, prefix)| {
            let peer = peers.iter().find(|p| p.public_key == pinned.public_key)?;
            let routed = peer.allowed_ips.as_deref().unwrap_or(&peer.delegations);
            let reason = if peer.is_disabled {
                "disabled"
            } else if !peer
                .delegations
                .iter()
                .any(|claimed| claimed.contains(&prefix))
            {
                "withdrawn"
            } else if !routed.iter().any(|routed| routed.overlaps(&prefix)) {
                "not allowed"
            } else if !routed.iter().any(|routed| routed.contains(&prefix)) {
                "allowed in part"
            } else {
                return None;
            };
            Some((prefix, peer, reason))
        })
        .collect();
    if unrouted.is_empty() {
        return;
    }
    unrouted.sort_by_key(|(prefix, ..)| *prefix);
    println!("  {}:", "pinned, not routed".bold());
    for (prefix, peer, reason) in unrouted {
        let public_key = if verbose {
            peer.public_key.clone()
        } else {
            format!("{}…", &peer.public_key[..10])
        };
        println!(
            "    {}: {} ({}), {}",
            prefix.to_string().yellow(),
            peer.display_name().escape_debug(),
            public_key.dimmed(),
            reason
        );
    }
}

fn print_tree(
    cidr: &CidrTree,
    peers: &[PeerState],
    level: usize,
    verbose: bool,
    interface_config: &InterfaceConfig,
) {
    println_pad!(
        level * 2,
        "{} {}",
        cidr.cidr.to_string().bold().blue(),
        cidr.name.escape_debug().to_string().blue(),
    );

    let mut children: Vec<_> = cidr.children().collect();
    children.sort();
    children
        .iter()
        .for_each(|child| print_tree(child, peers, level + 1, verbose, interface_config));

    for peer in peers
        .iter()
        .filter(|p| p.assigned.cidr(cidr.all()) == Some(&**cidr))
    {
        let endpoint_has_local_override = interface_config
            .endpoint_override_for_peer(peer.peer)
            .is_some();
        print_peer(peer, true, level, verbose, endpoint_has_local_override);
    }
}

fn print_interface(device_info: &Device, short: bool) -> Result<(), Error> {
    if short {
        let listen_port_str = device_info
            .listen_port
            .map(|p| format!("(:{p}) "))
            .unwrap_or_default();
        println!(
            "{} {}",
            device_info.name.to_string().green().bold(),
            listen_port_str.dimmed(),
        );
    } else {
        println!(
            "{}: {}",
            "network".green().bold(),
            device_info.name.to_string().green(),
        );
        if let Some(listen_port) = device_info.listen_port {
            println!("  {}: {}", "listening port".bold(), listen_port);
        }
    }
    Ok(())
}

fn print_peer(
    peer: &PeerState,
    short: bool,
    level: usize,
    verbose: bool,
    endpoint_has_local_override: bool,
) {
    let pad = level * 2;
    let PeerState {
        peer,
        assigned,
        announces,
        info,
    } = peer;
    let public_key = if verbose {
        &peer.public_key
    } else {
        &format!("{}…", &peer.public_key[..10])
    };

    let endpoint_override_msg = if endpoint_has_local_override {
        " (endpoint overridden locally)"
    } else {
        ""
    };

    if short {
        let connected = info
            .map(|info| info.is_recently_connected())
            .unwrap_or_default();
        let is_you = info.is_none();

        println_pad!(
            pad,
            "| {} {}: {} ({}{}){endpoint_override_msg}",
            if connected || is_you {
                "◉".bold()
            } else {
                "◯".dimmed()
            },
            peer.display_address().yellow().bold(),
            peer.display_name().yellow(),
            if is_you { "you, " } else { "" },
            public_key.dimmed(),
        );
    } else {
        println_pad!(
            pad,
            "{}: {} ({})",
            "peer".yellow().bold(),
            peer.display_name().yellow(),
            public_key.yellow(),
        );
        println_pad!(
            pad,
            "  {}: {}",
            "delegation".bold(),
            peer.display_delegations()
        );
        // A peer that announces states what it accepts traffic for, and its primary IP; this
        // client also sees the ranges that the server assigns it.
        if *announces {
            let allowed_ips = peer.allowed_ips.as_deref().unwrap_or(&peer.delegations);
            let allowed_ips: Vec<String> = allowed_ips.iter().map(Prefix::to_string).collect();
            println_pad!(
                pad,
                "  {}: {}",
                "allowed ips".bold(),
                if allowed_ips.is_empty() {
                    "[none]".to_string()
                } else {
                    allowed_ips.join(", ")
                }
            );
            println_pad!(pad, "  {}: {}", "primary ip".bold(), peer.display_address());
            if info.is_none() && assigned.delegations != peer.delegations {
                println_pad!(
                    pad,
                    "  {}: {}",
                    "assigned".bold(),
                    assigned.display_delegations()
                );
            }
        }
        if let Some(info) = info {
            if let Some(endpoint) = info.config.endpoint {
                println_pad!(
                    pad,
                    "  {}: {endpoint}{endpoint_override_msg}",
                    "endpoint".bold(),
                );
            }
            if let Some(last_handshake) = info.stats.last_handshake_time {
                let duration = last_handshake.elapsed().expect("horrible clock problem");
                println_pad!(
                    pad,
                    "  {}: {}",
                    "last handshake".bold(),
                    human_duration(duration),
                );
            }
            if info.stats.tx_bytes > 0 || info.stats.rx_bytes > 0 {
                println_pad!(
                    pad,
                    "  {}: {} received, {} sent",
                    "transfer".bold(),
                    human_size(info.stats.rx_bytes),
                    human_size(info.stats.tx_bytes),
                );
            }
        }
    }
}

fn main() {
    let opts = Opts::parse();
    util::init_logger(opts.verbose);

    // Every command runs on one runtime, on this thread.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to start the runtime");
    let result = tokio::task::LocalSet::new().block_on(&runtime, run(&opts));
    if let Err(e) = result {
        println!();
        log::error!("{:#}\n", e);
        if let Some(e) = e.downcast_ref::<WrappedIoError>() {
            util::permissions_helptext(&opts.config_dir, &opts.data_dir, e);
        }
        if let Some(e) = e.downcast_ref::<io::Error>() {
            util::permissions_helptext(&opts.config_dir, &opts.data_dir, e);
        }
        std::process::exit(1);
    }
}

async fn run(opts: &Opts) -> Result<(), Error> {
    let command = opts.command.clone().unwrap_or(Command::Show {
        short: false,
        tree: false,
        interface: None,
    });

    // Binds the config of the admin client of `interface`, and its client of the API.
    macro_rules! admin_client {
        ($interface:expr, $config:ident, $rest_client:ident) => {
            let $config = InterfaceConfig::from_interface(&opts.config_dir, &$interface)?;
            let $rest_client = RestClient::for_interface(&$config, &opts.data_dir, &$interface)?;
        };
    }

    match command {
        Command::Install {
            invite,
            listen_port,
            hosts,
            install_opts,
            nat,
        } => install(opts, &hosts, &install_opts, &nat, &invite, listen_port).await?,
        Command::Show {
            short,
            tree,
            interface,
        } => show(opts, short, tree, interface)?,
        Command::Fetch {
            interface,
            hosts,
            nat,
        } => {
            fetch(
                &opts.config_dir,
                &opts.data_dir,
                &opts.network,
                &hosts,
                &nat,
                &interface,
                false,
            )
            .await?;
        },
        Command::Up {
            interface,
            daemon,
            hosts,
            nat,
            interval,
        } => {
            up(
                interface,
                opts,
                daemon.then(|| Duration::from_secs(interval)),
                hosts,
                &nat,
            )
            .await?
        },
        Command::Down { interface } => wg::down(&interface, opts.network.backend)?,
        Command::Uninstall { interface, yes } => uninstall(&interface, opts, yes)?,
        Command::AddPeer {
            interface,
            sub_opts,
        } => {
            admin_client!(interface, config, rest_client);
            let server = coordinator_info(&config, &opts.data_dir, &interface)?;
            admin::add_peer(&rest_client, &interface, &server, sub_opts).await?
        },
        Command::RenamePeer {
            interface,
            sub_opts,
        } => {
            admin_client!(interface, _config, rest_client);
            admin::rename_peer(&rest_client, sub_opts).await?
        },
        Command::AddCidr {
            interface,
            sub_opts,
        } => {
            admin_client!(interface, _config, rest_client);
            admin::add_cidr(&rest_client, sub_opts).await?
        },
        Command::RenameCidr {
            interface,
            sub_opts,
        } => {
            admin_client!(interface, _config, rest_client);
            admin::rename_cidr(&rest_client, sub_opts).await?
        },
        Command::DeleteCidr {
            interface,
            sub_opts,
        } => {
            admin_client!(interface, _config, rest_client);
            admin::delete_cidr(&rest_client, sub_opts).await?
        },
        Command::ListCidrs { interface, tree } => list_cidrs(&interface, opts, tree)?,
        Command::DisablePeer {
            interface,
            sub_opts,
        } => {
            admin_client!(interface, _config, rest_client);
            admin::enable_or_disable_peer(&rest_client, sub_opts, false).await?
        },
        Command::EnablePeer {
            interface,
            sub_opts,
        } => {
            admin_client!(interface, _config, rest_client);
            admin::enable_or_disable_peer(&rest_client, sub_opts, true).await?
        },
        Command::AddDelegation {
            interface,
            sub_opts,
        } => {
            admin_client!(interface, _config, rest_client);
            admin::add_delegation(&rest_client, sub_opts).await?
        },
        Command::WithdrawDelegation {
            interface,
            sub_opts,
        } => {
            admin_client!(interface, _config, rest_client);
            admin::withdraw_delegation(&rest_client, sub_opts).await?
        },
        Command::ReclaimDelegation {
            interface,
            sub_opts,
        } => {
            admin_client!(interface, _config, rest_client);
            admin::reclaim_delegation(&rest_client, sub_opts).await?
        },
        Command::AddAssociation {
            interface,
            sub_opts,
        } => {
            admin_client!(interface, _config, rest_client);
            admin::add_association(&rest_client, sub_opts).await?
        },
        Command::DeleteAssociation {
            interface,
            sub_opts,
        } => {
            admin_client!(interface, _config, rest_client);
            admin::delete_association(&rest_client, sub_opts).await?
        },
        Command::ListAssociations { interface } => {
            admin_client!(interface, _config, rest_client);
            admin::list_associations(&rest_client).await?
        },
        Command::Completions { shell } => {
            use clap::CommandFactory;
            let mut app = Opts::command();
            let app_name = app.get_name().to_string();
            clap_complete::generate(shell, &mut app, app_name, &mut std::io::stdout());
            std::process::exit(0);
        },
    }

    Ok(())
}
