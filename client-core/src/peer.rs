pub use innernet_shared::peer::NewPeerInfo;

use crate::{
    rest_client::{RestClient, RestError},
    Cidr, Peer, PeerInvitation,
};
use anyhow::Result;
use innernet_shared::{
    interface_config::{InterfaceConfig, InterfaceInfo, FEATURE_TLS},
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

/// Create a new innernet [`Peer`] and a [`PeerInvitation`] they can use to join the network.
pub async fn create_peer(
    config_dir: &Path,
    data_dir: &Path,
    interface: &InterfaceName,
    existing_cidrs: &[Cidr],
    existing_peers: &[Peer],
    new_peer_info: NewPeerInfo,
) -> Result<(Peer, PeerInvitation), CreatePeerError> {
    let interface_config = InterfaceConfig::from_interface(config_dir, interface)
        .map_err(CreatePeerError::InterfaceConfigAccess)?;
    let rest_client = RestClient::for_interface(&interface_config, data_dir, interface)?;

    let keypair = KeyPair::generate();
    let peer_contents = new_peer_info.into_peer_contents(&keypair);
    let peer = rest_client.create_peer(&peer_contents).await?;

    let cidr_tree = CidrTree::new(existing_cidrs);
    let address = &cidr_tree
        .ip_net_for(peer.ip)
        .expect("Peer's IpNet address to be valid because the peer was created successfully.");
    let interface_info = InterfaceInfo::new(interface, &keypair, *address);

    // The coordinator is the peer with the key of the interface config, which authenticated the
    // server. Its record holds its current endpoint, if it has one. The invitation states that
    // the server speaks TLS only if the server answered this client over TLS.
    let mut server_info = interface_config.server.clone();
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

    Ok((peer, PeerInvitation::new(interface_info, server_info)))
}
