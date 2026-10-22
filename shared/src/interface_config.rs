use crate::{chmod, ensure_dirs_exist, Endpoint, Error, IoErrorContext, Peer, WrappedIoError};
use indoc::writedoc;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
use wireguard_control::{InterfaceName, KeyPair};

/// This struct contains everything necessary to establish an innernet connection: information about
/// a local innernet interface and a remote innernet server.
#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct InterfaceConfig {
    /// The information to bring up the interface.
    pub interface: InterfaceInfo,

    /// The necessary contact information for the server.
    pub server: ServerInfo,

    /// The DNS server for the names of the peers of this interface, which `innernet up --daemon`
    /// runs while this table is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsInfo>,

    /// A configurable map of peer IP addresses to Endpoints which should
    /// be used as the WireGuard endpoint for that peer.
    #[serde(default)]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    peer_endpoint_overrides: BTreeMap<IpAddr, Endpoint>,
}

/// The `[dns]` table of the config: a DNS server that answers queries for the hostnames of the
/// peers, with their addresses, and refuses queries for any other name. innernet doesn't
/// configure the system resolver to use it.
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct DnsInfo {
    /// The address at which the server answers queries, over both UDP and TCP, such as
    /// `127.0.0.55:53`; `0.0.0.0` or `[::]` listens at every address. It should be a loopback
    /// address, and its port one that only a privileged user may bind, since a local user who
    /// binds it while the server doesn't answers for the names of peers.
    pub listen: SocketAddr,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct InterfaceInfo {
    /// The interface name (i.e. "tonari")
    pub network_name: String,

    /// The invited peer's internal IP address that's been allocated to it, inside
    /// the entire network's CIDR prefix.
    pub address: IpNet,

    /// WireGuard private key (base64)
    pub private_key: String,

    /// The local listen port. A random port will be used if `None`.
    pub listen_port: Option<u16>,
}

impl InterfaceInfo {
    pub fn new(network_name: &InterfaceName, keypair: &KeyPair, address: IpNet) -> Self {
        Self {
            network_name: network_name.to_string(),
            private_key: keypair.private.to_base64(),
            address,
            listen_port: None,
        }
    }
}

#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct ServerInfo {
    /// The server's WireGuard public key
    pub public_key: String,

    /// The external internet endpoint to reach the server.
    pub external_endpoint: Endpoint,

    /// An internal endpoint in the WireGuard network that hosts the coordination API.
    pub internal_endpoint: SocketAddr,

    /// What the server supports, as the invitation states it, such as [`FEATURE_TLS`]. A client
    /// reads it only when it redeems the invitation, and ignores features that it doesn't know.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
}

/// The feature of a server that speaks TLS. A client that redeems an invitation stating it never
/// falls back to plain HTTP for the server.
pub const FEATURE_TLS: &str = "tls";

impl ServerInfo {
    pub fn new(server_peer: &Peer, internal_endpoint: SocketAddr) -> Self {
        Self {
            external_endpoint: server_peer
                .endpoint
                .clone()
                .expect("The innernet server should have a WireGuard endpoint"),
            internal_endpoint,
            public_key: server_peer.public_key.clone(),
            features: vec![],
        }
    }

    /// Whether the invitation states that the server supports `feature`.
    pub fn has_feature(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }
}

impl InterfaceConfig {
    pub fn new(interface: InterfaceInfo, server: ServerInfo) -> Self {
        InterfaceConfig {
            interface,
            server,
            dns: None,
            peer_endpoint_overrides: BTreeMap::new(),
        }
    }

    /// Save a new config file, failing if it already exists.
    pub fn save_new(&self, path: impl AsRef<Path>, mode: u32) -> Result<(), WrappedIoError> {
        let path = path.as_ref();
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(mode)
            .open(path)
            .with_path(path)?;

        chmod(&file, mode).with_path(path)?;

        file.write_all(self.as_toml().as_bytes()).with_path(path)?;

        Ok(())
    }

    /// Overwrites the config file if it already exists.
    pub fn save(&self, config_dir: &Path, interface: &InterfaceName) -> Result<PathBuf, Error> {
        let path = Self::build_config_file_path(config_dir, interface)?;
        File::create(&path)
            .with_path(&path)?
            .write_all(self.as_toml().as_bytes())?;

        Ok(path)
    }

    fn as_toml(&self) -> String {
        toml::to_string(self).unwrap()
    }

    pub fn from_file(file: &mut File) -> Result<Self, Error> {
        let mut toml = String::new();
        file.read_to_string(&mut toml)?;
        Ok(toml::from_str(&toml)?)
    }

    pub fn from_interface(config_dir: &Path, interface: &InterfaceName) -> Result<Self, Error> {
        let path = Self::build_config_file_path(config_dir, interface)?;
        let mut file = File::open(&path).with_path(&path)?;
        crate::warn_on_dangerous_mode(&file, &path).with_path(&path)?;
        Self::from_file(&mut file)
    }

    pub fn get_path(config_dir: &Path, interface: &InterfaceName) -> PathBuf {
        config_dir
            .join(interface.to_string())
            .with_extension("conf")
    }

    pub fn build_config_file_path(
        config_dir: &Path,
        interface: &InterfaceName,
    ) -> Result<PathBuf, WrappedIoError> {
        ensure_dirs_exist(&[config_dir])?;
        Ok(Self::get_path(config_dir, interface))
    }

    pub fn peer_endpoint_overrides(&self) -> &BTreeMap<IpAddr, Endpoint> {
        &self.peer_endpoint_overrides
    }

    pub fn set_endpoint_override_for_peer(&mut self, peer_ip: IpAddr, endpoint: Endpoint) {
        self.peer_endpoint_overrides.insert(peer_ip, endpoint);
    }

    pub fn unset_endpoint_override_for_peer(&mut self, peer_ip: IpAddr) {
        self.peer_endpoint_overrides.remove(&peer_ip);
    }
}

impl InterfaceInfo {
    pub fn public_key(&self) -> Result<String, Error> {
        Ok(wireguard_control::Key::from_base64(&self.private_key)?
            .get_public()
            .to_base64())
    }
}

#[must_use]
pub struct PeerInvitation {
    interface_config: InterfaceConfig,
}

impl PeerInvitation {
    pub fn new(interface: InterfaceInfo, server: ServerInfo) -> Self {
        Self {
            interface_config: InterfaceConfig::new(interface, server),
        }
    }

    /// Save a new invitation file, failing if it already exists.
    pub fn save_new(&self, path: impl AsRef<Path>) -> Result<(), io::Error> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;

        writedoc!(
            file,
            r"
                    # This is an invitation file to an innernet network.
                    #
                    # To join, you must install innernet.
                    # See https://github.com/tonarino/innernet for instructions.
                    #
                    # If you have innernet, just run:
                    #
                    #   innernet install <this file>
                    #
                    # Don't edit the contents below unless you love chaos and dysfunction.
                "
        )?;

        file.write_all(self.interface_config.as_toml().as_bytes())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVITATION: &str = r#"
        [interface]
        network-name = "test"
        address = "10.0.0.2/24"
        private-key = "kOg3HWw0ZE4tdhyA7kZGRUwAxp04i48yD3ElXNSNkmM="

        [server]
        public-key = "dz0/Fjmj7oRBSGxgWXSkE3n9R3k19kJOj127FzJZ81g="
        external-endpoint = "203.0.113.1:51820"
        internal-endpoint = "10.0.0.1:51820"
    "#;

    #[test]
    fn test_features() {
        // An invitation from a server that predates features states none, and is written back
        // without them.
        let config: InterfaceConfig = toml::from_str(INVITATION).unwrap();
        assert!(config.server.features.is_empty());
        assert!(!config.server.has_feature(FEATURE_TLS));
        assert!(!toml::to_string(&config).unwrap().contains("features"));

        // Features that the client doesn't know are kept but ignored.
        let invitation = INVITATION.replace(
            "[server]",
            "[server]\nfeatures = [\"tls\", \"from-the-future\"]",
        );
        let config: InterfaceConfig = toml::from_str(&invitation).unwrap();
        assert!(config.server.has_feature(FEATURE_TLS));
        let config: InterfaceConfig = toml::from_str(&toml::to_string(&config).unwrap()).unwrap();
        assert_eq!(config.server.features, ["tls", "from-the-future"]);
    }
}
