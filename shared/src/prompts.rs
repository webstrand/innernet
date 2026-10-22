use crate::{
    check_delegations, hosts_fallback, interface_config::InterfaceInfo, peer::NewPeerInfo,
    AddCidrOpts, AddDeleteAssociationOpts, AddPeerOpts, Association, Cidr, CidrTree,
    DelegationOpts, DeleteCidrOpts, EnableDisablePeerOpts, Endpoint, Error, Hostname, IpNetExt,
    ListenPortOpts, OverridePeerEndpointOpts, PeerContents, Prefix, RenameCidrOpts, RenamePeerOpts,
};
use anyhow::{anyhow, bail};
use colored::*;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use innernet_publicip::Preference;
use once_cell::sync::Lazy;
use std::{
    collections::BTreeMap,
    fmt::{Debug, Display},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
};

pub static THEME: Lazy<ColorfulTheme> = Lazy::new(ColorfulTheme::default);

pub fn ensure_interactive(prompt: &str) -> Result<(), io::Error> {
    if atty::is(atty::Stream::Stdin) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            format!("Prompt \"{prompt}\" failed because TTY isn't connected."),
        ))
    }
}

pub fn confirm(prompt: &str) -> Result<bool, dialoguer::Error> {
    ensure_interactive(prompt)?;
    Confirm::with_theme(&*THEME)
        .wait_for_newline(true)
        .with_prompt(prompt)
        .default(false)
        .interact()
}

pub fn select<'a, T: ToString>(
    prompt: &str,
    items: &'a [T],
) -> Result<(usize, &'a T), dialoguer::Error> {
    ensure_interactive(prompt)?;
    let choice = Select::with_theme(&*THEME)
        .with_prompt(prompt)
        .items(items)
        .interact()?;
    Ok((choice, &items[choice]))
}

pub enum Prefill<T> {
    Default(T),
    Editable(String),
    None,
}

pub fn input<T>(prompt: &str, prefill: Prefill<T>) -> Result<T, dialoguer::Error>
where
    T: Clone + FromStr + Display,
    T::Err: Display + Debug,
{
    ensure_interactive(prompt)?;
    let input = Input::with_theme(&*THEME);
    match prefill {
        Prefill::Default(value) => input.default(value),
        Prefill::Editable(value) => input.with_initial_text(value),
        _ => input,
    }
    .with_prompt(prompt)
    // TODO(mbernat): workaround for https://github.com/console-rs/dialoguer/issues/330
    .interact_text()
}

/// Bring up a prompt to create a new CIDR. Returns the CIDR request.
///
/// The parent of a CIDR is the smallest CIDR that holds it, so the CIDR must lie within the parent
/// that the operator selects, and in none of its children; the CIDR is refused before the server
/// is asked otherwise.
pub fn add_cidr(cidrs: &[Cidr], request: &AddCidrOpts) -> Result<Option<Cidr>, Error> {
    let parent_cidr = if let Some(parent_name) = &request.parent {
        cidrs
            .iter()
            .find(|cidr| &cidr.name == parent_name)
            .ok_or_else(|| anyhow!("No parent CIDR with that name exists."))?
    } else {
        choose_cidr(cidrs, "Parent CIDR")?
    };

    let name = if let Some(name) = &request.name {
        name.clone()
    } else {
        input("Name", Prefill::None)?
    };

    let cidr: Prefix = if let Some(cidr) = request.cidr {
        Prefix::new(cidr)?
    } else {
        input("CIDR", Prefill::None)?
    };

    let cidr_request = Cidr {
        name: name.to_string(),
        cidr,
    };
    if let Some(existing) = cidrs.iter().find(|existing| existing.cidr == cidr) {
        bail!(
            "The CIDR {cidr} exists already, as {}.",
            existing.name.escape_debug()
        );
    }
    let parent = cidr_request.parent(cidrs);
    if parent != Some(parent_cidr) {
        bail!(
            "The CIDR {cidr} can't be a child of {parent_cidr}: the smallest CIDR that holds it is \
             {}.",
            parent.map_or("none".to_string(), |parent| parent.to_string())
        );
    }

    Ok(
        if request.yes || confirm(&format!("Create CIDR \"{}\"?", cidr_request.name))? {
            Some(cidr_request)
        } else {
            None
        },
    )
}

/// Bring up a prompt to rename an existing CIDR. Returns the CIDR with its new name, and its old
/// name.
pub fn rename_cidr(cidrs: &[Cidr], args: &RenameCidrOpts) -> Result<Option<(Cidr, String)>, Error> {
    let old_cidr = if let Some(name) = &args.name {
        cidrs
            .iter()
            .find(|c| &c.name == name)
            .ok_or_else(|| anyhow!("CIDR '{}' does not exist", name))?
            .clone()
    } else {
        let (cidr_index, _) = select(
            "CIDR to rename",
            &cidrs
                .iter()
                .map(|ep| ep.name.escape_debug().to_string())
                .collect::<Vec<_>>(),
        )?;
        cidrs[cidr_index].clone()
    };
    let old_name = old_cidr.name.clone();
    let new_name = if let Some(name) = &args.new_name {
        name.clone()
    } else {
        input("New Name", Prefill::None)?
    };

    let mut new_cidr = old_cidr;
    new_cidr.name.clone_from(&new_name);

    Ok(
        if args.yes
            || confirm(&format!(
                "Rename CIDR {} to {}?",
                old_name.escape_debug().to_string().yellow(),
                new_name.yellow()
            ))?
        {
            Some((new_cidr, old_name))
        } else {
            None
        },
    )
}

/// Bring up a prompt to delete a CIDR, which has neither peers nor child CIDRs. Returns the CIDR
/// as it was listed.
pub fn delete_cidr(
    cidrs: &[Cidr],
    peers: &[PeerContents],
    request: &DeleteCidrOpts,
) -> Result<Cidr, Error> {
    let eligible_cidrs: Vec<_> = cidrs
        .iter()
        .filter(|cidr| {
            !peers.iter().any(|peer| peer.cidr(cidrs) == Some(*cidr))
                && !cidrs.iter().any(|other| other.parent(cidrs) == Some(*cidr))
        })
        .collect();
    let cidr = if let Some(name) = &request.name {
        cidrs
            .iter()
            .find(|cidr| &cidr.name == name)
            .ok_or_else(|| anyhow!("CIDR {} doesn't exist or isn't eligible for deletion", name))?
    } else {
        select("Delete CIDR", &eligible_cidrs)?.1
    };

    if request.yes || confirm(&format!("Delete CIDR \"{}\"?", cidr.name.escape_debug()))? {
        Ok(cidr.clone())
    } else {
        Err(anyhow!("Canceled"))
    }
}

pub fn choose_cidr<'a>(cidrs: &'a [Cidr], text: &'static str) -> Result<&'a Cidr, Error> {
    let eligible_cidrs: Vec<_> = cidrs
        .iter()
        .filter(|cidr| cidr.name != "innernet-server")
        .collect();
    Ok(select(text, &eligible_cidrs)?.1)
}

pub fn choose_association<'a>(
    associations: &'a [Association],
    cidrs: &'a [Cidr],
    args: &AddDeleteAssociationOpts,
) -> Result<&'a Association, Error> {
    match (&args.cidr1, &args.cidr2) {
        (Some(cidr1_name), Some(cidr2_name)) => {
            let cidr1 = find_cidr(cidrs, cidr1_name)?;
            let cidr2 = find_cidr(cidrs, cidr2_name)?;
            associations
                .iter()
                .find(|association| association.associates(&cidr1.cidr, &cidr2.cidr))
                .ok_or_else(|| anyhow!("CIDR association does not exist"))
        },
        _ => {
            let names: Vec<_> = associations
                .iter()
                .map(|association| describe_association(association, cidrs))
                .collect();
            let (index, _) = select("Association", &names)?;

            Ok(&associations[index])
        },
    }
}

/// The association for display, by the names of its CIDRs among `cidrs`, escaped since the server
/// chose them, or by the prefix of a CIDR that isn't among them.
pub fn describe_association(association: &Association, cidrs: &[Cidr]) -> String {
    let name = |prefix: &Prefix| {
        cidrs.iter().find(|cidr| cidr.cidr == *prefix).map_or_else(
            || prefix.to_string(),
            |cidr| cidr.name.escape_debug().to_string(),
        )
    };
    format!(
        "{} <=> {}",
        name(&association.cidr_1),
        name(&association.cidr_2)
    )
}

fn find_cidr<'a>(cidrs: &'a [Cidr], name: &str) -> Result<&'a Cidr, Error> {
    cidrs
        .iter()
        .find(|c| c.name == name)
        .ok_or_else(|| anyhow!("can't find cidr '{}'", name))
}

fn find_or_prompt_cidr<'a>(
    cidrs: &'a [Cidr],
    sub_opt: &Option<String>,
    prompt: &'static str,
) -> Result<&'a Cidr, Error> {
    if let Some(name) = sub_opt {
        find_cidr(cidrs, name)
    } else {
        choose_cidr(cidrs, prompt)
    }
}

pub fn add_association<'a>(
    cidrs: &'a [Cidr],
    args: &AddDeleteAssociationOpts,
) -> Result<Option<(&'a Cidr, &'a Cidr)>, Error> {
    let cidr1 = find_or_prompt_cidr(cidrs, &args.cidr1, "First CIDR")?;
    let cidr2 = find_or_prompt_cidr(cidrs, &args.cidr2, "Second CIDR")?;

    Ok(
        if args.yes
            || confirm(&format!(
                "Add association: {} <=> {}?",
                cidr1.name.escape_debug().to_string().yellow().bold(),
                cidr2.name.escape_debug().to_string().yellow().bold()
            ))?
        {
            Some((cidr1, cidr2))
        } else {
            None
        },
    )
}

pub fn print_invitation_info(peer: &PeerContents, target_file_name: &str) {
    println!(
        "\nPeer \"{}\" added\n\
         Peer invitation file written to {}\n\
         Please send it to them securely (eg. via magic-wormhole) \
         to bootstrap them onto the network.",
        peer.display_name().bold(),
        target_file_name.bold()
    );
}

pub fn delete_association<'a>(
    associations: &'a [Association],
    cidrs: &'a [Cidr],
    args: &AddDeleteAssociationOpts,
) -> Result<Option<&'a Association>, Error> {
    let association = choose_association(associations, cidrs, args)?;

    Ok(
        if args.yes
            || confirm(&format!(
                "Delete association {}?",
                describe_association(association, cidrs)
            ))?
        {
            Some(association)
        } else {
            None
        },
    )
}

/// Bring up a prompt to gather information about a new peer. Returns [`NewPeerInfo`] and a path
/// where the invite file should be saved.
pub fn gather_new_peer_info(
    peers: &[PeerContents],
    cidr_tree: &CidrTree,
    args: &AddPeerOpts,
) -> Result<Option<(NewPeerInfo, String)>, Error> {
    let leaves = cidr_tree.leaves();

    let cidr = if let Some(parent_name) = &args.cidr {
        leaves
            .iter()
            .find(|cidr| &cidr.name == parent_name)
            .ok_or_else(|| anyhow!("No eligible CIDR with that name exists."))?
    } else {
        choose_cidr(&leaves[..], "Eligible CIDRs for peer")?
    };

    let delegation = if let Some(delegation) = args.delegation {
        // A wider delegation is checked as the server checks it, so that a refusal is explained
        // before the server is asked.
        if !cidr.cidr.contains(&delegation) {
            bail!("{delegation} is outside the CIDR {}", cidr.cidr);
        }
        let others: Vec<(Prefix, String)> = peers
            .iter()
            .flat_map(|peer| {
                peer.delegations
                    .iter()
                    .map(move |prefix| (*prefix, format!("peer {}", peer.display_name())))
            })
            .collect();
        check_delegations(
            &[delegation],
            &cidr_tree.prefixes(),
            others
                .iter()
                .map(|(prefix, holder)| (prefix, holder.as_str())),
        )?;
        delegation
    } else {
        let mut available_ip = None;
        let net = cidr.cidr.net();
        let candidate_ips = net.hosts().filter(|ip| net.is_assignable(ip));
        for ip in candidate_ips {
            if !peers.iter().any(|peer| peer.holds(ip)) {
                available_ip = Some(ip);
                break;
            }
        }

        let available_ip = available_ip.expect("No IPs in this CIDR are avavilable");

        let ip = if let Some(ip) = args.ip {
            ip
        } else if args.auto_ip {
            available_ip
        } else {
            input("IP", Prefill::Default(available_ip))?
        };
        Prefix::host(ip)
    };

    let name = if let Some(name) = &args.name {
        name.clone()
    } else {
        input("Name", Prefill::None)?
    };

    let is_admin = if let Some(is_admin) = args.admin {
        is_admin
    } else {
        confirm(&format!("Make {name} an admin?"))?
    };

    let invite_expires = if let Some(invite_expires) = &args.invite_expires {
        invite_expires.clone()
    } else {
        input(
            "Invite expires after",
            Prefill::Default("14d".parse().map_err(|s: &str| anyhow!(s))?),
        )?
    };

    let invite_save_path = if let Some(location) = &args.save_config {
        location.clone()
    } else {
        input(
            "Save peer invitation file to",
            Prefill::Default(format!("{name}.toml")),
        )?
    };

    if args.yes || confirm(&format!("Create peer {}?", name.yellow()))? {
        let input = NewPeerInfo {
            name,
            delegations: vec![delegation],
            is_admin,
            invite_expires,
        };

        Ok(Some((input, invite_save_path)))
    } else {
        Ok(None)
    }
}

/// Bring up a prompt to rename an existing peer. Returns the peer request and the peer to rename,
/// by which alone a peer without a name can be told.
pub fn rename_peer<'a>(
    peers: &'a [PeerContents],
    args: &RenamePeerOpts,
) -> Result<Option<(PeerContents, &'a PeerContents)>, Error> {
    let eligible_peers = peers
        .iter()
        .filter(|p| p.name.as_deref() != Some("innernet-server"))
        .collect::<Vec<_>>();
    let old_peer = if let Some(name) = &args.name {
        eligible_peers
            .into_iter()
            .find(|p| p.name.as_ref() == Some(name))
            .ok_or_else(|| anyhow!("Peer '{}' does not exist", name))?
    } else {
        let (peer_index, _) = select(
            "Peer to rename",
            &eligible_peers
                .iter()
                .map(|ep| format!("{} ({})", ep.display_name(), ep.display_address()))
                .collect::<Vec<_>>(),
        )?;
        eligible_peers[peer_index]
    };
    let new_name: Hostname = if let Some(name) = &args.new_name {
        name.clone()
    } else {
        input("New Name", Prefill::None)?
    };

    let new_peer = PeerContents {
        name: Some(new_name.clone()),
        ..old_peer.clone()
    };

    Ok(
        if args.yes
            || confirm(&format!(
                "Rename peer {} to {}?",
                old_peer.display_name().yellow(),
                new_name.yellow()
            ))?
        {
            Some((new_peer, old_peer))
        } else {
            None
        },
    )
}

/// Presents a selection and confirmation of eligible peers for either disabling or enabling,
/// and returns back the ID of the selected peer.
pub fn enable_or_disable_peer(
    peers: &[PeerContents],
    args: &EnableDisablePeerOpts,
    enable: bool,
) -> Result<Option<PeerContents>, Error> {
    let enabled_peers: Vec<_> = peers
        .iter()
        .filter(|peer| enable && peer.is_disabled || !enable && !peer.is_disabled)
        .collect();

    let peer = if let Some(name) = &args.name {
        enabled_peers
            .into_iter()
            .find(|p| p.name.as_ref() == Some(name))
            .ok_or_else(|| anyhow!("Peer '{}' does not exist", name))?
    } else {
        let peer_selection: Vec<_> = enabled_peers
            .iter()
            .map(|peer| format!("{} ({})", peer.display_name(), peer.display_address()))
            .collect();
        let (index, _) = select(
            &format!("Peer to {}able", if enable { "en" } else { "dis" }),
            &peer_selection,
        )?;
        enabled_peers[index]
    };

    Ok(
        if args.yes
            || confirm(&format!(
                "{}able peer {}?",
                if enable { "En" } else { "Dis" },
                peer.display_name().yellow()
            ))?
        {
            Some(peer.clone())
        } else {
            None
        },
    )
}

/// Selects the peer of `peers` whose delegations change: the one named by `args`, or one that the
/// operator selects among `peers` that `eligible` accepts.
fn select_delegated_peer<'a>(
    peers: &'a [PeerContents],
    args: &DelegationOpts,
    eligible: impl Fn(&PeerContents) -> bool,
    prompt: &str,
) -> Result<&'a PeerContents, Error> {
    if let Some(name) = &args.name {
        return peers
            .iter()
            .find(|peer| peer.name.as_ref() == Some(name))
            .ok_or_else(|| anyhow!("Peer '{name}' does not exist"));
    }
    let eligible: Vec<_> = peers.iter().filter(|peer| eligible(peer)).collect();
    if eligible.is_empty() {
        bail!("No peer is eligible.");
    }
    let selection: Vec<_> = eligible
        .iter()
        .map(|peer| {
            format!(
                "{} ({}) {}",
                peer.display_name(),
                peer.display_delegations(),
                peer.public_key
            )
        })
        .collect();
    let (index, _) = select(prompt, &selection)?;
    Ok(eligible[index])
}

/// The warning printed when `delegations` would move the hosts fallback address of `peer`, at
/// which the name of a peer that has never announced resolves, and at which clients that predate
/// TLS reach it, or `None` if it stays. A peer that announces is named at the primary IP that it
/// states instead.
pub fn hosts_fallback_notice(peer: &PeerContents, delegations: &[Prefix]) -> Option<String> {
    if peer.announcement.is_some() {
        return None;
    }
    let new = hosts_fallback(delegations);
    let old = peer.hosts_fallback();
    if new == old {
        return None;
    }
    let display = |ip: Option<IpAddr>| ip.map_or("[none]".to_string(), |ip| ip.to_string());
    Some(format!(
        "This moves the hosts fallback address of peer {}, the lowest address of its \
         delegations, at which its name resolves and clients that predate TLS reach it, from {} \
         to {}.",
        peer.display_name(),
        display(old),
        display(new),
    ))
}

/// Bring up a prompt to delegate a prefix to a peer of `peers`, whose CIDRs are `cidrs`. Returns
/// the peer and its delegations with the prefix added. The prefix is checked as the server checks
/// it, against the peer's CIDR and the delegations of the other peers, so that a refusal is
/// explained before the server is asked.
pub fn add_delegation<'a>(
    peers: &'a [PeerContents],
    cidrs: &[Cidr],
    args: &DelegationOpts,
) -> Result<Option<(&'a PeerContents, Vec<Prefix>)>, Error> {
    let peer = select_delegated_peer(peers, args, |_| true, "Peer to delegate a prefix to")?;
    let prefix: Prefix = match args.prefix {
        Some(prefix) => prefix,
        None => input("Prefix to delegate", Prefill::None)?,
    };
    if peer.delegations.contains(&prefix) {
        bail!(
            "{prefix} is delegated to peer {} already",
            peer.display_name()
        );
    }
    let cidrs: Vec<Prefix> = cidrs.iter().map(|cidr| cidr.cidr).collect();
    let others: Vec<(Prefix, String)> = peers
        .iter()
        .filter(|other| other.public_key != peer.public_key)
        .flat_map(|other| {
            other
                .delegations
                .iter()
                .map(move |delegation| (*delegation, format!("peer {}", other.display_name())))
        })
        .collect();
    let mut delegations = peer.delegations.clone();
    delegations.push(prefix);
    delegations.sort();
    check_delegations(
        &delegations,
        &cidrs,
        others
            .iter()
            .map(|(prefix, holder)| (prefix, holder.as_str())),
    )?;

    if let Some(notice) = hosts_fallback_notice(peer, &delegations) {
        log::warn!("{notice}");
    }
    Ok(
        if args.yes
            || confirm(&format!(
                "Delegate {} to peer {}?",
                prefix.to_string().yellow(),
                peer.display_name().yellow()
            ))?
        {
            Some((peer, delegations))
        } else {
            None
        },
    )
}

/// Selects the delegation of `peer` that `args` names, or one that the operator selects, with
/// `prompt`.
fn select_delegation(
    peer: &PeerContents,
    args: &DelegationOpts,
    prompt: &str,
) -> Result<Prefix, Error> {
    match args.prefix {
        Some(prefix) => {
            if !peer.delegations.contains(&prefix) {
                bail!(
                    "{prefix} is not a delegation of peer {}, whose delegations are {}",
                    peer.display_name(),
                    peer.display_delegations()
                );
            }
            Ok(prefix)
        },
        None => {
            if peer.delegations.is_empty() {
                bail!("Peer {} has no delegation.", peer.display_name());
            }
            Ok(*select(prompt, &peer.delegations)?.1)
        },
    }
}

/// Bring up a prompt to withdraw a delegation from a peer of `peers`. Returns the peer and its
/// delegations without the withdrawn one.
pub fn withdraw_delegation<'a>(
    peers: &'a [PeerContents],
    args: &DelegationOpts,
) -> Result<Option<(&'a PeerContents, Vec<Prefix>)>, Error> {
    let peer = select_delegated_peer(
        peers,
        args,
        |peer| !peer.delegations.is_empty(),
        "Peer to withdraw a delegation from",
    )?;
    let prefix = select_delegation(peer, args, "Delegation to withdraw")?;
    let delegations: Vec<Prefix> = peer
        .delegations
        .iter()
        .filter(|delegation| **delegation != prefix)
        .copied()
        .collect();

    if let Some(notice) = hosts_fallback_notice(peer, &delegations) {
        log::warn!("{notice}");
    }
    Ok(
        if args.yes
            || confirm(&format!(
                "Withdraw {} from peer {}? The server refuses if the peer claims any of it.",
                prefix.to_string().yellow(),
                peer.display_name().yellow()
            ))?
        {
            Some((peer, delegations))
        } else {
            None
        },
    )
}

/// Bring up a prompt to mark a delegation of a peer of `peers` to be reclaimed: it stops being
/// delegated to the peer once the peer, having claimed some of it, announces without claiming any
/// of it, so that a cooperative peer can move. Returns the peer and the delegation to mark.
pub fn reclaim_delegation<'a>(
    peers: &'a [PeerContents],
    args: &DelegationOpts,
) -> Result<Option<(&'a PeerContents, Prefix)>, Error> {
    let peer = select_delegated_peer(
        peers,
        args,
        |peer| !peer.delegations.is_empty(),
        "Peer whose delegation to mark",
    )?;
    let prefix = select_delegation(peer, args, "Delegation to mark")?;
    Ok(
        if args.yes
            || confirm(&format!(
                "Mark {} of peer {} to be reclaimed once the peer stops claiming it?",
                prefix.to_string().yellow(),
                peer.display_name().yellow()
            ))?
        {
            Some((peer, prefix))
        } else {
            None
        },
    )
}

pub fn set_listen_port(
    interface: &InterfaceInfo,
    args: ListenPortOpts,
) -> Result<Option<Option<u16>>, Error> {
    let listen_port = if let Some(listen_port) = args.listen_port {
        Some(listen_port)
    } else if !args.unset {
        Some(input(
            "Listen port",
            Prefill::Default(interface.listen_port.unwrap_or(51820)),
        )?)
    } else {
        None
    };

    let confirmation = Confirm::with_theme(&*THEME)
        .wait_for_newline(true)
        .with_prompt(
            &(if let Some(port) = &listen_port {
                format!("Set listen port to {port}?")
            } else {
                "Unset and randomize listen port?".to_string()
            }),
        )
        .default(false);

    if listen_port == interface.listen_port {
        println!("No change necessary - interface already has this setting.");
        Ok(None)
    } else if args.yes || confirmation.interact()? {
        Ok(Some(listen_port))
    } else {
        Ok(None)
    }
}

pub fn unspecified_ip_and_auto_detection_flow() -> Result<Option<IpAddr>, Error> {
    if confirm_unspecified_ip_usage()? {
        Ok(Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)))
    } else {
        ip_auto_detection_flow()
    }
}

pub fn ip_auto_detection_flow() -> Result<Option<IpAddr>, Error> {
    let ip_addr = if confirm_ip_auto_detection()? {
        innernet_publicip::get_any(Preference::Ipv4)
    } else {
        None
    };

    Ok(ip_addr)
}

fn confirm_ip_auto_detection() -> Result<bool, Error> {
    let answer = Confirm::with_theme(&*THEME)
        .wait_for_newline(true)
        .with_prompt("Auto-detect external endpoint IP address (via DNS query to 9.9.9.9)?")
        .interact()?;

    Ok(answer)
}

fn confirm_unspecified_ip_usage() -> Result<bool, Error> {
    log::info!(
        "Note: use unspecified IP address (all zeros) if you do not have a fixed global IP but the \
         port is forwarded." 
    );
    let answer = Confirm::with_theme(&*THEME)
        .wait_for_newline(true)
        .with_prompt("Use an unspecified IP address and override just the port?")
        .interact()?;

    Ok(answer)
}

pub fn input_external_endpoint(
    external_ip: Option<IpAddr>,
    listen_port: u16,
) -> Result<Endpoint, Error> {
    let endpoint = input(
        "External endpoint",
        match external_ip {
            Some(ip) => Prefill::Editable(SocketAddr::new(ip, listen_port).to_string()),
            None => Prefill::None,
        },
    )?;

    Ok(endpoint)
}

/// Bring up a prompt to override the endpoint for an existing peer.
/// Returns the peer and desired endpoint.
pub fn override_peer_endpoint_prompt(
    peers: &[PeerContents],
    peer_endpoint_overrides: &BTreeMap<String, Endpoint>,
    args: &OverridePeerEndpointOpts,
) -> Result<Option<(PeerContents, Option<Endpoint>)>, Error> {
    let eligible_peers = peers
        .iter()
        .filter(|p| p.name.as_deref() != Some("innernet-server"))
        // If we're unsetting, filter eligible_peers to just be peers that have
        // an override already set.
        .filter(|p| !args.unset || peer_endpoint_overrides.contains_key(&p.public_key))
        .collect::<Vec<_>>();

    let peer = if let Some(name) = &args.name {
        let Some(peer) = eligible_peers
            .into_iter()
            .find(|p| p.name.as_ref() == Some(name))
        else {
            return if args.unset && peers.iter().any(|p| p.name.as_ref() == Some(name)) {
                log::info!("Peer '{name}' does not have an override set");
                Ok(None)
            } else {
                Err(anyhow!("Peer '{name}' does not exist"))
            };
        };
        peer.clone()
    } else {
        let message = if args.unset {
            if eligible_peers.is_empty() {
                bail!("No peers have an override endpoint set");
            }

            "Peer endpoint override to unset"
        } else {
            "Peer endpoint to override"
        };

        let (peer_index, _) = select(
            message,
            &eligible_peers
                .iter()
                .map(|ep| format!("{} ({})", ep.display_name(), ep.display_address()))
                .collect::<Vec<_>>(),
        )?;
        eligible_peers[peer_index].clone()
    };

    let endpoint: Option<Endpoint> = if args.unset {
        None
    } else if let Some(endpoint) = &args.endpoint {
        Some(endpoint.clone())
    } else {
        Some(input("Endpoint", Prefill::None)?)
    };

    let confirm_msg = if let Some(endpoint) = &endpoint {
        &format!(
            "Override endpoint for peer {} ({}) to {}?",
            peer.display_name().yellow(),
            peer.display_address(),
            endpoint,
        )
    } else {
        &format!(
            "Unset endpoint override for peer {} ({})?",
            peer.display_name().yellow(),
            peer.display_address(),
        )
    };

    Ok(if args.yes || confirm(confirm_msg)? {
        Some((peer, endpoint))
    } else {
        None
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(name: &str, public_key: &str, delegations: &[&str]) -> PeerContents {
        PeerContents {
            name: Some(name.parse().unwrap()),
            delegations: delegations.iter().map(|d| d.parse().unwrap()).collect(),
            public_key: public_key.to_owned(),
            endpoint: None,
            persistent_keepalive_interval: None,
            is_admin: false,
            is_disabled: false,
            is_redeemed: true,
            invite_expires: None,
            candidates: vec![],
            announcement: None,
            allowed_ips: None,
            primary_ip: None,
        }
    }

    fn opts(name: &str, prefix: &str) -> DelegationOpts {
        DelegationOpts {
            name: Some(name.parse().unwrap()),
            prefix: Some(prefix.parse().unwrap()),
            yes: true,
        }
    }

    #[test]
    fn test_new_peer_with_a_delegation() {
        use clap::Parser;

        #[derive(Parser)]
        struct Command {
            #[clap(flatten)]
            opts: AddPeerOpts,
        }
        let parse = |args: &[&str]| {
            Command::try_parse_from(
                [
                    "add-peer",
                    "--name",
                    "peer3",
                    "--cidr",
                    "cidr",
                    "--admin",
                    "false",
                    "--invite-expires",
                    "1h",
                    "--save-config",
                    "peer3.toml",
                    "--yes",
                ]
                .iter()
                .chain(args),
            )
            .map(|command| command.opts)
        };
        let peers = [peer(
            "peer1",
            "4CNZorWVtohO64n6AAaH/JyFjIIgBFrfJK2SGtKjzEE=",
            &["10.0.0.16/28"],
        )];
        let cidrs = [Cidr {
            name: "cidr".into(),
            cidr: "10.0.0.0/24".parse().unwrap(),
        }];
        let tree = CidrTree::new(&cidrs);
        let offered = |args: &[&str]| {
            gather_new_peer_info(&peers, &tree, &parse(args).unwrap())
                .map(|info| info.unwrap().0.delegations)
        };

        // A new peer is offered the prefix it is given, a single IP, or the first free IP.
        assert_eq!(
            offered(&["--delegation", "10.0.0.32/28"]).unwrap(),
            ["10.0.0.32/28".parse::<Prefix>().unwrap()]
        );
        assert_eq!(
            offered(&["--ip", "10.0.0.7"]).unwrap(),
            ["10.0.0.7/32".parse::<Prefix>().unwrap()]
        );
        assert_eq!(
            offered(&["--auto-ip"]).unwrap(),
            ["10.0.0.1/32".parse::<Prefix>().unwrap()]
        );

        // A prefix that another peer holds is refused with an explanation, and the prefix goes
        // with neither an IP nor an automatic one.
        let error = offered(&["--delegation", "10.0.0.0/27"])
            .unwrap_err()
            .to_string();
        assert!(error.contains("network or broadcast"), "{error}");
        let error = offered(&["--delegation", "10.0.0.24/29"])
            .unwrap_err()
            .to_string();
        assert!(error.contains("delegated to peer peer1"), "{error}");
        assert!(parse(&["--delegation", "10.0.0.32/28", "--ip", "10.0.0.7"]).is_err());
        assert!(parse(&["--delegation", "10.0.0.32/28", "--auto-ip"]).is_err());
        assert!(parse(&["--delegation", "10.0.0.33/28"]).is_err());
    }

    #[test]
    fn test_cidrs_by_prefix() {
        let cidr = |name: &str, cidr: &str| Cidr {
            name: name.into(),
            cidr: cidr.parse().unwrap(),
        };
        let cidrs = [
            cidr("root", "10.0.0.0/16"),
            cidr("users", "10.0.1.0/24"),
            cidr("empty", "10.0.2.0/24"),
        ];
        let add = |parent: &str, prefix: &str| {
            add_cidr(
                &cidrs,
                &AddCidrOpts {
                    name: Some("new".parse().unwrap()),
                    cidr: Some(prefix.parse().unwrap()),
                    parent: Some(parent.into()),
                    yes: true,
                },
            )
        };

        // A new CIDR is named by its prefix, without a parent, and must lie in the parent
        // selected, and in none of its children.
        assert_eq!(
            add("root", "10.0.3.0/24").unwrap(),
            Some(cidr("new", "10.0.3.0/24"))
        );
        assert_eq!(
            add("users", "10.0.1.64/26").unwrap(),
            Some(cidr("new", "10.0.1.64/26"))
        );
        for (parent, prefix, reason) in [
            (
                "root",
                "10.0.1.64/26",
                "smallest CIDR that holds it is users",
            ),
            ("users", "10.1.0.0/24", "is none"),
            ("root", "10.0.2.0/24", "exists already"),
            ("root", "10.0.3.5/24", "not aligned"),
        ] {
            let error = add(parent, prefix).unwrap_err().to_string();
            assert!(error.contains(reason), "{prefix}: {error}");
        }

        // Only a CIDR without peers and without children may be deleted.
        let peers = [peer(
            "peer1",
            "4CNZorWVtohO64n6AAaH/JyFjIIgBFrfJK2SGtKjzEE=",
            &["10.0.1.9/32"],
        )];
        let delete = |name: &str| {
            delete_cidr(
                &cidrs,
                &peers,
                &DeleteCidrOpts {
                    name: Some(name.into()),
                    yes: true,
                },
            )
        };
        assert_eq!(delete("empty").unwrap(), cidrs[2]);
    }

    #[test]
    fn test_change_delegations() {
        let peers = [
            peer(
                "peer1",
                "4CNZorWVtohO64n6AAaH/JyFjIIgBFrfJK2SGtKjzEE=",
                &["10.0.0.9/32"],
            ),
            peer(
                "peer2",
                "GBfQ6Xqdrw2WsNsW8ZsANpyDLeffy6XqwOYpAyyZ3AQ=",
                &["10.0.0.2/32"],
            ),
        ];
        let cidrs = [Cidr {
            name: "cidr".into(),
            cidr: "10.0.0.0/24".parse().unwrap(),
        }];

        // An addition is checked as the server checks it, and returns the whole set.
        let (_, delegations) = add_delegation(&peers, &cidrs, &opts("peer1", "10.0.0.16/28"))
            .unwrap()
            .unwrap();
        assert_eq!(
            delegations,
            ["10.0.0.9/32", "10.0.0.16/28"].map(|d| d.parse::<Prefix>().unwrap())
        );
        assert!(add_delegation(&peers, &cidrs, &opts("peer1", "10.0.0.9/32")).is_err());
        let error = add_delegation(&peers, &cidrs, &opts("peer1", "10.0.0.0/30"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("network or broadcast"), "{error}");
        let error = add_delegation(&peers, &cidrs, &opts("peer1", "10.0.0.2/31"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("delegated to peer peer2"), "{error}");

        // An addition below the lowest address moves the hosts fallback address.
        let lower: Vec<Prefix> = vec![
            "10.0.0.4/32".parse().unwrap(),
            "10.0.0.9/32".parse().unwrap(),
        ];
        let notice = hosts_fallback_notice(&peers[0], &lower).unwrap();
        assert!(notice.contains("from 10.0.0.9 to 10.0.0.4"), "{notice}");
        assert!(hosts_fallback_notice(&peers[0], &delegations).is_none());

        // Only a delegation of the peer is withdrawn.
        let (_, delegations) = withdraw_delegation(&peers, &opts("peer1", "10.0.0.9/32"))
            .unwrap()
            .unwrap();
        assert!(delegations.is_empty());
        assert!(withdraw_delegation(&peers, &opts("peer1", "10.0.0.2/32")).is_err());

        // Only a delegation of the peer is marked to be reclaimed.
        let (peer, prefix) = reclaim_delegation(&peers, &opts("peer1", "10.0.0.9/32"))
            .unwrap()
            .unwrap();
        assert_eq!(peer.public_key, peers[0].public_key);
        assert_eq!(prefix, "10.0.0.9/32".parse().unwrap());
        assert!(reclaim_delegation(&peers, &opts("peer1", "10.0.0.2/32")).is_err());
    }
}
