use anyhow::{Context, Error};
use env_logger::Env;
use innernet_client_core::{
    interface::{InterfaceConfig, InterfaceName},
    peer::{create_peer, NewPeerInfo},
    rest_client::RestClient,
    DEFAULT_CONFIG_DIR, DEFAULT_DATA_DIR,
};
use innernet_shared::{prompts, Prefix};
use std::{
    env,
    net::{IpAddr, Ipv4Addr},
    path::Path,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let config_dir = Path::new(DEFAULT_CONFIG_DIR);
    let data_dir = Path::new(DEFAULT_DATA_DIR);
    let interface = env::args().nth(1).context("Usage: add_peer <interface>")?;

    let interface: InterfaceName = interface.parse()?;
    let interface_config = InterfaceConfig::from_interface(config_dir, &interface)?;
    let rest_client = RestClient::for_interface(&interface_config, data_dir, &interface)?;
    let cidrs = rest_client.get_cidrs().await?;
    let peers = rest_client.get_peers().await?;

    let new_peer_info = NewPeerInfo {
        name: "joe".parse().unwrap(),
        delegations: vec![Prefix::host(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))],
        is_admin: false,
        invite_expires: "1m".parse().unwrap(),
    };

    let target_path = "invitation.toml";
    let (peer, invitation) = create_peer(
        config_dir,
        data_dir,
        &interface,
        &cidrs,
        &peers,
        new_peer_info,
    )
    .await?;
    invitation.save_new(target_path)?;
    prompts::print_invitation_info(&peer, target_path);

    Ok(())
}
