pub use innernet_shared::peer::NewPeerInfo;

use crate::{
    rest_client::{AdminApi, RestClient, RestError},
    Cidr, Invitation, PeerContents,
};
use anyhow::Result;
use innernet_shared::{
    interface_config::{InterfaceConfig, ServerInfo, FEATURE_TLS},
    CidrTree,
};
use std::path::Path;
use thiserror::Error;
use wireguard_control::{InterfaceName, KeyPair};

#[derive(Debug, Error)]
pub enum CreatePeerError {
    // TODO(mbernat): Use a custom error type in the InterfaceConfig methods.
    #[error("Error accessing innernet interface config file: {0}")]
    InterfaceConfigAccess(anyhow::Error),
    #[error("Error making a REST request: {0}")]
    RestRequest(#[from] RestError),
}

/// Create a new innernet peer and an [`Invitation`] they can use to join the network, as
/// the admin client of `interface` in `config_dir` and `data_dir`, as [`invite`] does.
pub async fn create_peer(
    config_dir: &Path,
    data_dir: &Path,
    interface: &InterfaceName,
    existing_cidrs: &[Cidr],
    existing_peers: &[PeerContents],
    new_peer_info: NewPeerInfo,
) -> Result<(PeerContents, Invitation), CreatePeerError> {
    let interface_config = InterfaceConfig::from_interface(config_dir, interface)
        .map_err(CreatePeerError::InterfaceConfigAccess)?;
    let rest_client = RestClient::for_interface(&interface_config, data_dir, interface)?;
    invite(
        &rest_client,
        interface,
        &interface_config.server,
        existing_cidrs,
        existing_peers,
        new_peer_info,
    )
    .await
}

/// Creates a new innernet peer through `rest_client`, an admin client of the coordinator of
/// `interface`, which `server` names, and an [`Invitation`] that the peer can use to join the
/// network.
///
/// The invitation offers the peer's delegations within the network, without a source address. A
/// server that predates TLS offers a single address, and the invitation is of the format of
/// v2.0.0, which names it, so that clients that predate TLS can redeem it.
///
/// The coordinator is the peer with the key of `server`, which authenticated the server. The
/// invitation names it at the endpoint of its peer in `existing_peers`, if it has one, and at the
/// external endpoint of `server` otherwise. It states that the server speaks TLS only if the
/// server answered this client over TLS.
pub async fn invite(
    rest_client: &RestClient<'_>,
    interface: &InterfaceName,
    server: &ServerInfo,
    existing_cidrs: &[Cidr],
    existing_peers: &[PeerContents],
    new_peer_info: NewPeerInfo,
) -> Result<(PeerContents, Invitation), CreatePeerError> {
    let keypair = KeyPair::generate();
    let peer_contents = new_peer_info.into_peer_contents(&keypair);
    let peer = rest_client.create_peer(&peer_contents).await?;

    let mut server_info = server.clone();
    server_info.features = if rest_client.speaks_tls() {
        vec![FEATURE_TLS.to_string()]
    } else {
        vec![]
    };
    if let Some(endpoint) = existing_peers
        .iter()
        .find(|p| p.public_key == server_info.public_key)
        .and_then(|p| p.endpoint.clone())
    {
        server_info.external_endpoint = endpoint;
    }

    let network = CidrTree::new(existing_cidrs).cidr;
    let invitation = match rest_client.admin_api().await? {
        AdminApi::ByKey => Invitation::offering(
            interface,
            &keypair,
            network,
            peer.delegations.clone(),
            server_info,
        ),
        AdminApi::Legacy => {
            let address = peer
                .hosts_fallback()
                .and_then(|ip| ipnet::IpNet::new(ip, network.prefix_len()).ok())
                .expect("a peer that a server in plain HTTP creates has an address");
            Invitation::legacy(interface, &keypair, address, server_info)
        },
    };

    Ok((peer, invitation))
}
