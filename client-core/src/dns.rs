//! The DNS servers of `innernet up --daemon`, one for each interface whose config has a
//! `[dns]` table, each the DNS server of the node core, [`innernet_node::dns`].

use crate::{data_store::DataStore, interface::InterfaceConfig};
use anyhow::Error;
use innernet_node::{realize::DnsService, snapshot::Snapshot};
use innernet_shared::interface_config::DnsInfo;
use std::{collections::BTreeMap, path::Path};
use wireguard_control::InterfaceName;

/// The DNS servers that `innernet up --daemon` runs, one for each interface whose config has a
/// `[dns]` table, by the name of the interface.
#[derive(Default)]
pub struct Servers {
    running: BTreeMap<String, DnsService>,
}

impl Servers {
    /// Brings the DNS servers in line with the configs in `config_dir` of `interfaces`, the
    /// interfaces installed now, and the data stores in `data_dir`, as [`DnsService::update`]
    /// does for each: each publishes the names of the snapshot of the data store of its interface,
    /// with the hostnames of the peers under `host_suffix`. The DNS server of an interface that is
    /// gone is stopped. A DNS server whose config or data store can't be read keeps running as it
    /// is.
    pub async fn update(
        &mut self,
        interfaces: &[InterfaceName],
        config_dir: &Path,
        data_dir: &Path,
        host_suffix: Option<&str>,
    ) {
        let names: Vec<String> = interfaces.iter().map(ToString::to_string).collect();
        let gone: Vec<String> = self
            .running
            .keys()
            .filter(|name| !names.contains(name))
            .cloned()
            .collect();
        for name in gone {
            if let Some(mut service) = self.running.remove(&name) {
                service.stop().await;
            }
        }
        for interface in interfaces {
            let name = interface.to_string();
            match configured(interface, config_dir, data_dir) {
                Ok(configured) => {
                    let service = self.running.entry(name).or_insert_with(|| {
                        DnsService::new(*interface, host_suffix.map(str::to_string))
                    });
                    match &configured {
                        Some((dns, snapshot)) => service.update(Some(dns), snapshot).await,
                        None => service.update(None, &Snapshot::default()).await,
                    }
                },
                Err(e) => log::warn!(
                    "{}: failed to read the configuration of the DNS server: {e:#}",
                    interface.as_str_lossy()
                ),
            }
        }
    }
}

/// The `[dns]` table of the config of `interface` in `config_dir`, and the snapshot of its data
/// store in `data_dir`, or `None` if its config has no DNS server.
fn configured(
    interface: &InterfaceName,
    config_dir: &Path,
    data_dir: &Path,
) -> Result<Option<(DnsInfo, Snapshot)>, Error> {
    let config = InterfaceConfig::from_interface(config_dir, interface)?;
    let Some(dns) = config.dns.clone() else {
        return Ok(None);
    };
    let store = DataStore::open(data_dir, interface, &config)?;
    Ok(Some((dns, store.snapshot(None)?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, UdpSocket};

    #[tokio::test]
    async fn test_servers_follow_the_config() {
        let dir = tempfile::tempdir().unwrap();
        let (config_dir, data_dir) = (dir.path().join("config"), dir.path().join("data"));
        std::fs::create_dir_all(&data_dir).unwrap();
        let interface: InterfaceName = "e2e".parse().unwrap();
        let (own, server) = (
            wireguard_control::KeyPair::generate(),
            wireguard_control::KeyPair::generate(),
        );
        let write_config = |listen: Option<&str>| {
            let mut toml = format!(
                "[interface]\nnetwork-name = \"e2e\"\naddress = \"10.66.0.2/16\"\n\
                 private-key = \"{}\"\n\n[server]\npublic-key = \"{}\"\n\
                 external-endpoint = \"203.0.113.1:51820\"\n\
                 internal-endpoint = \"10.66.0.1:51820\"\n",
                own.private.to_base64(),
                server.public.to_base64(),
            );
            if let Some(listen) = listen {
                toml.push_str(&format!("\n[dns]\nlisten = \"{listen}\"\n"));
            }
            let path = InterfaceConfig::build_config_file_path(&config_dir, &interface).unwrap();
            std::fs::write(&path, toml).unwrap();
            innernet_shared::chmod(&std::fs::File::open(&path).unwrap(), 0o600).unwrap();
            toml::from_str::<InterfaceConfig>(&std::fs::read_to_string(&path).unwrap()).unwrap()
        };
        let mut servers = Servers::default();
        macro_rules! update {
            ($servers:expr, $interfaces:expr) => {
                $servers
                    .update($interfaces, &config_dir, &data_dir, None)
                    .await
            };
        }
        let listening = |servers: &Servers| {
            servers
                .running
                .values()
                .filter_map(DnsService::listen)
                .collect::<Vec<_>>()
        };

        // A port free for both UDP and TCP when it is chosen. Tests that run alongside may take it
        // before the DNS server binds it, so each start below tries a few ports.
        let free_address = || loop {
            let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = tcp.local_addr().unwrap();
            if UdpSocket::bind(address).is_ok() {
                return address;
            }
        };
        macro_rules! start {
            ($servers:expr) => {{
                let mut started = None;
                for _ in 0..5 {
                    let address = free_address();
                    write_config(Some(&address.to_string()));
                    update!($servers, &[interface]);
                    if listening($servers) == [address] {
                        started = Some(address);
                        break;
                    }
                }
                started.expect("the DNS server started at none of 5 free ports")
            }};
        }

        // A config without the table runs no DNS server, and one with it runs one once the data
        // store exists.
        let config = write_config(None);
        update!(&mut servers, &[interface]);
        assert!(listening(&servers).is_empty());
        write_config(Some(&free_address().to_string()));
        update!(&mut servers, &[interface]);
        assert!(listening(&servers).is_empty());
        DataStore::open_or_create(&data_dir, &interface, &config).unwrap();
        let started = start!(&mut servers);
        assert!(servers.running["e2e"].forwarding().unwrap().is_none());

        // A new forward key takes effect without moving it. The table ends the config, so the key
        // appended to it lies within the table.
        let path = InterfaceConfig::build_config_file_path(&config_dir, &interface).unwrap();
        let toml = std::fs::read_to_string(&path).unwrap() + "forward = [\"*\"]\n";
        std::fs::write(&path, toml).unwrap();
        update!(&mut servers, &[interface]);
        assert_eq!(listening(&servers), [started]);
        assert!(servers.running["e2e"].forwarding().unwrap().selects("b"));

        // A new listen address moves it, and removing the table or the interface stops it.
        write_config(Some("127.0.0.1:0"));
        update!(&mut servers, &[interface]);
        assert_eq!(listening(&servers), ["127.0.0.1:0".parse().unwrap()]);
        write_config(None);
        update!(&mut servers, &[interface]);
        assert!(listening(&servers).is_empty());
        let last = start!(&mut servers);
        update!(&mut servers, &[]);
        assert!(listening(&servers).is_empty());
        // Its address is free again.
        UdpSocket::bind(last).unwrap();
    }
}
