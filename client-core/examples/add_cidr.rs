use anyhow::{Context, Error};
use env_logger::Env;
use innernet_client_core::{
    interface::{InterfaceConfig, InterfaceName},
    rest_client::RestClient,
    Cidr, DEFAULT_CONFIG_DIR, DEFAULT_DATA_DIR,
};
use std::{env, path::Path};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let config_dir = Path::new(DEFAULT_CONFIG_DIR);
    let data_dir = Path::new(DEFAULT_DATA_DIR);
    let interface = env::args().nth(1).context("Usage: add_cidr <interface>")?;

    let interface: InterfaceName = interface.parse()?;
    let interface_config = InterfaceConfig::from_interface(config_dir, &interface)?;
    let rest_client = RestClient::for_interface(&interface_config, data_dir, &interface)?;

    // The parent of the new CIDR is the smallest CIDR that holds it.
    let name = "example".to_owned();
    let cidr = "10.49.65.0/24".parse()?;

    let cidr = rest_client.create_cidr(&Cidr { name, cidr }).await?;
    dbg!(&cidr);

    Ok(())
}
