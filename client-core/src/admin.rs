//! The admin commands, which an admin client sends to the coordinator over its API: `innernet`
//! as an admin peer of a network, and `innernet-server` as the coordinator's own peer. Each takes
//! the client of the API and what its prompt needs, and prompts for what its options leave out.

use crate::{peer::invite, rest_client::RestClient};
use anyhow::{anyhow, Error};
use colored::*;
use indoc::eprintdoc;
use innernet_shared::{
    interface_config::ServerInfo, prompts, AddCidrOpts, AddDeleteAssociationOpts, AddPeerOpts,
    Association, AssociationContents, Cidr, CidrTree, DeleteCidrOpts, EnableDisablePeerOpts,
    PeerContents, RenameCidrOpts, RenamePeerOpts,
};
use wireguard_control::InterfaceName;

pub async fn add_cidr(rest_client: &RestClient<'_>, sub_opts: AddCidrOpts) -> Result<(), Error> {
    log::info!("Fetching CIDRs");
    let cidrs: Vec<Cidr> = rest_client.get_cidrs().await?;

    if let Some(cidr_request) = prompts::add_cidr(&cidrs, &sub_opts)? {
        log::info!("Creating CIDR...");
        let cidr: Cidr = rest_client.create_cidr(&cidr_request).await?;

        eprintdoc!(
            "
            CIDR \"{cidr_name}\" added.

            Right now, peers within {cidr_name} can only see peers in the same CIDR
            , and in the special \"infra\" CIDR that includes the innernet server peer.

            You'll need to add more associations for peers in diffent CIDRs to communicate.
            ",
            cidr_name = cidr.name.bold()
        );
    } else {
        log::info!("exited without creating CIDR.");
    }

    Ok(())
}

pub async fn rename_cidr(
    rest_client: &RestClient<'_>,
    sub_opts: RenameCidrOpts,
) -> Result<(), Error> {
    log::info!("Fetching CIDRs");
    let cidrs: Vec<Cidr> = rest_client.get_cidrs().await?;

    if let Some((cidr_request, old_name)) = prompts::rename_cidr(&cidrs, &sub_opts)? {
        log::info!("Renaming CIDR...");

        let id = cidrs
            .iter()
            .find(|c| c.name == old_name)
            .ok_or_else(|| anyhow!("CIDR not found."))?
            .id;

        rest_client
            .http_form::<_, ()>("PUT", &format!("/admin/cidrs/{id}"), cidr_request)
            .await?;
        log::info!("CIDR renamed.");
    } else {
        log::info!("Exited without renaming CIDR.");
    }

    Ok(())
}

pub async fn delete_cidr(
    rest_client: &RestClient<'_>,
    sub_opts: DeleteCidrOpts,
) -> Result<(), Error> {
    println!("Fetching eligible CIDRs");
    let cidrs: Vec<Cidr> = rest_client.get_cidrs().await?;
    let peers = rest_client.get_peers().await?;

    let cidr_id = prompts::delete_cidr(&cidrs, &peers, &sub_opts)?;

    println!("Deleting CIDR...");
    rest_client
        .http::<()>("DELETE", &format!("/admin/cidrs/{cidr_id}"))
        .await?;

    println!("CIDR deleted.");

    Ok(())
}

/// Adds a peer, and saves its invitation, which names the coordinator as `server` does, as
/// [`invite`] completes it.
pub async fn add_peer(
    rest_client: &RestClient<'_>,
    interface: &InterfaceName,
    server: &ServerInfo,
    sub_opts: AddPeerOpts,
) -> Result<(), Error> {
    log::info!("Fetching CIDRs");
    let cidrs = rest_client.get_cidrs().await?;
    log::info!("Fetching peers");
    let peers = rest_client.get_peers().await?;
    let cidr_tree = CidrTree::new(&cidrs[..]);

    if let Some((new_peer_info, target_path)) =
        prompts::gather_new_peer_info(&peers, &cidr_tree, &sub_opts)?
    {
        log::info!("Creating peer...");
        let (peer, invitation) = invite(
            rest_client,
            interface,
            server,
            &cidrs,
            &peers,
            new_peer_info,
        )
        .await?;

        invitation.save_new(&target_path)?;
        prompts::print_invitation_info(&peer, &target_path);
    } else {
        log::info!("Exited without creating peer.");
    }

    Ok(())
}

pub async fn rename_peer(
    rest_client: &RestClient<'_>,
    sub_opts: RenamePeerOpts,
) -> Result<(), Error> {
    log::info!("Fetching peers");
    let peers = rest_client.get_peers().await?;

    if let Some((peer_request, listed)) = prompts::rename_peer(&peers, &sub_opts)? {
        log::info!("Renaming peer...");
        rest_client.update_peer(listed, &peer_request).await?;
        log::info!("Peer renamed.");
    } else {
        log::info!("exited without renaming peer.");
    }

    Ok(())
}

pub async fn enable_or_disable_peer(
    rest_client: &RestClient<'_>,
    sub_opts: EnableDisablePeerOpts,
    enable: bool,
) -> Result<(), Error> {
    log::info!("Fetching peers.");
    let peers = rest_client.get_peers().await?;

    if let Some(peer) = prompts::enable_or_disable_peer(&peers[..], &sub_opts, enable)? {
        let contents = PeerContents {
            is_disabled: !enable,
            ..peer.clone()
        };
        rest_client.update_peer(&peer, &contents).await?;
    } else {
        log::info!("exiting without enabling or disabling peer.");
    }

    Ok(())
}

pub async fn add_association(
    rest_client: &RestClient<'_>,
    sub_opts: AddDeleteAssociationOpts,
) -> Result<(), Error> {
    log::info!("Fetching CIDRs");
    let cidrs: Vec<Cidr> = rest_client.get_cidrs().await?;

    let association = if let (Some(ref cidr1), Some(ref cidr2)) = (&sub_opts.cidr1, &sub_opts.cidr2)
    {
        let cidr1 = cidrs
            .iter()
            .find(|c| &c.name == cidr1)
            .ok_or_else(|| anyhow!("can't find cidr '{}'", cidr1))?;
        let cidr2 = cidrs
            .iter()
            .find(|c| &c.name == cidr2)
            .ok_or_else(|| anyhow!("can't find cidr '{}'", cidr2))?;
        (cidr1, cidr2)
    } else if let Some((cidr1, cidr2)) = prompts::add_association(&cidrs[..], &sub_opts)? {
        (cidr1, cidr2)
    } else {
        log::info!("exiting without adding association.");
        return Ok(());
    };

    rest_client
        .http_form::<_, ()>(
            "POST",
            "/admin/associations",
            AssociationContents {
                cidr_id_1: association.0.id,
                cidr_id_2: association.1.id,
            },
        )
        .await?;

    Ok(())
}

pub async fn delete_association(
    rest_client: &RestClient<'_>,
    sub_opts: AddDeleteAssociationOpts,
) -> Result<(), Error> {
    log::info!("Fetching CIDRs");
    let cidrs: Vec<Cidr> = rest_client.get_cidrs().await?;
    log::info!("Fetching associations");
    let associations: Vec<Association> = rest_client.http("GET", "/admin/associations").await?;

    if let Some(association) =
        prompts::delete_association(&associations[..], &cidrs[..], &sub_opts)?
    {
        rest_client
            .http::<()>("DELETE", &format!("/admin/associations/{}", association.id))
            .await?;
    } else {
        log::info!("exiting without adding association.");
    }

    Ok(())
}

pub async fn list_associations(rest_client: &RestClient<'_>) -> Result<(), Error> {
    log::info!("Fetching CIDRs");
    let cidrs: Vec<Cidr> = rest_client.get_cidrs().await?;
    log::info!("Fetching associations");
    let associations: Vec<Association> = rest_client.http("GET", "/admin/associations").await?;

    for association in associations {
        println!(
            "{}: {} <=> {}",
            association.id,
            cidrs
                .iter()
                .find(|c| c.id == association.cidr_id_1)
                .unwrap()
                .name
                .yellow(),
            cidrs
                .iter()
                .find(|c| c.id == association.cidr_id_2)
                .unwrap()
                .name
                .yellow()
        );
    }

    Ok(())
}
