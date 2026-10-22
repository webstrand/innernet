//! The config of a server: its node, described as a client's interface is, the coordinator that
//! runs beside it, and the DNS server of the node.

use anyhow::Context as _;
use colored::*;
use innernet_shared::{
    interface_config::{DnsInfo, InterfaceInfo},
    Endpoint, Error, IoErrorContext,
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::prelude::*,
    net::IpAddr,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};
use wireguard_control::{Key, KeyPair};

/// The listen port of a server whose config states none.
const DEFAULT_LISTEN_PORT: u16 = 51820;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConfigFile {
    /// The server's node, with the keys of a client's `[interface]` table. Its address is the
    /// node's primary IP, at which the coordinator serves its API.
    pub interface: InterfaceInfo,

    #[serde(default)]
    pub coordinator: CoordinatorTable,

    /// The DNS server that the server's node runs, as every node runs it, or `None` if it runs
    /// none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsInfo>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CoordinatorTable {
    /// The UDP port of the TLS API, which runs over QUIC at the server's address. The kernel's
    /// WireGuard holds the listen port on every address, so the API needs a port of its own. The
    /// server refuses to start without it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic_port: Option<u16>,

    /// Whether the server serves the legacy API, in plain HTTP over TCP on the listen port, to
    /// clients that predate TLS, which it identifies by their source address, and to clients
    /// upgraded from v2.0.0, which ask it for the QUIC port. On unless the config turns it off.
    #[serde(default = "yes", skip_serializing_if = "is_yes")]
    pub legacy_api: bool,

    /// The endpoint at which an invitee first reaches the server, which invitations state. From
    /// then on, peers reach the server where its announcements state. The server's node announces
    /// it as its endpoint while `external-endpoint` states none. The server refuses to start
    /// without it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_endpoint: Option<Endpoint>,
}

impl Default for CoordinatorTable {
    fn default() -> Self {
        Self {
            quic_port: None,
            legacy_api: true,
            bootstrap_endpoint: None,
        }
    }
}

fn yes() -> bool {
    true
}

fn is_yes(value: &bool) -> bool {
    *value
}

/// The config of innernet-server 2.0.0, whose keys lie at the top level, which this version reads
/// only to refuse it, with the same config in the layout of this version.
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct V2ConfigFile {
    private_key: String,
    listen_port: u16,
    address: IpAddr,
    network_cidr_prefix: u8,
}

/// The refusal of a config in the layout of innernet-server 2.0.0, with `0`, the same config in
/// the layout of this version.
#[derive(Debug)]
pub struct V2Layout(pub ConfigFile);

impl std::fmt::Display for V2Layout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the config is in the layout of innernet-server 2.0.0, which this version doesn't \
             read; in this version's layout, it is:\n\n{}",
            self.0.to_toml().unwrap_or_default()
        )
    }
}

impl std::error::Error for V2Layout {}

impl ConfigFile {
    pub fn new(interface: InterfaceInfo, coordinator: CoordinatorTable) -> Self {
        Self {
            interface,
            coordinator,
            dns: None,
        }
    }

    /// Writes the config to `path`, which only the creation of a network does.
    pub fn write_to_path<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .with_path(&path)?;
        innernet_shared::chmod(&file, 0o600)?;
        file.write_all(self.to_toml()?.as_bytes()).with_path(path)?;
        Ok(())
    }

    pub fn to_toml(&self) -> Result<String, Error> {
        Ok(toml::to_string(self)?)
    }

    /// The config at `path`. A config in the layout of innernet-server 2.0.0, whose keys lie at
    /// the top level, is refused as [`V2Layout`], with the network named after the file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let path = path.as_ref();
        let mut file = File::open(path).with_path(path)?;
        if innernet_shared::chmod(&file, 0o600)? {
            println!(
                "{} updated permissions for {} to 0600.",
                "[!]".yellow(),
                path.display()
            );
        }
        let mut text = String::new();
        file.read_to_string(&mut text).with_path(path)?;
        let value: toml::Table = toml::from_str(&text)?;
        if value.contains_key("interface") {
            return Ok(toml::from_str(&text)?);
        }
        let network_name = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .context("the config file is named after no network")?
            .to_string();
        let v2: V2ConfigFile = toml::from_str(&text)?;
        let mut interface = InterfaceInfo::new(
            &network_name.parse()?,
            &KeyPair::from_private(Key::from_base64(&v2.private_key)?),
            IpNet::new(v2.address, v2.network_cidr_prefix)?,
        );
        interface.listen_port = Some(v2.listen_port);
        Err(V2Layout(Self::new(interface, CoordinatorTable::default())).into())
    }

    /// The primary IP of the server's node, at which the coordinator serves its API.
    pub fn address(&self) -> IpAddr {
        self.interface.address.addr()
    }

    /// The port at which the server's WireGuard listens.
    pub fn listen_port(&self) -> u16 {
        self.interface.listen_port.unwrap_or(DEFAULT_LISTEN_PORT)
    }

    /// The prefix of the network.
    pub fn network(&self) -> IpNet {
        self.interface.address.trunc()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v2_config_is_refused() -> Result<(), Error> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("wg0.conf");
        std::fs::write(
            &path,
            "private-key = \"kOg3HWw0ZE4tdhyA7kZGRUwAxp04i48yD3ElXNSNkmM=\"\nlisten-port = \
             51820\naddress = \"10.66.0.1\"\nnetwork-cidr-prefix = 16\n",
        )?;
        let error = ConfigFile::from_file(&path).unwrap_err();
        let V2Layout(config) = error.downcast_ref::<V2Layout>().unwrap();
        assert_eq!(config.interface.network_name, "wg0");
        assert_eq!(config.interface.address, "10.66.0.1/16".parse::<IpNet>()?);
        assert_eq!(config.listen_port(), 51820);
        // The config that the refusal names is read as it is.
        std::fs::write(&path, config.to_toml()?)?;
        assert_eq!(
            ConfigFile::from_file(&path)?.interface.private_key,
            config.interface.private_key
        );
        Ok(())
    }
}
