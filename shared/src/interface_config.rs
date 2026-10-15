use crate::{
    chmod, ensure_dirs_exist, prefix_set::PrefixSelector, Endpoint, Error, IoErrorContext, Peer,
    WrappedIoError,
};
use indoc::writedoc;
use ipnet::IpNet;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
use wireguard_control::{InterfaceName, Key, KeyPair};

/// This struct contains everything necessary to establish an innernet connection: information about
/// a local innernet interface and a remote innernet server.
#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct InterfaceConfig {
    /// The information to bring up the interface.
    pub interface: InterfaceInfo,

    /// The necessary contact information for the server.
    pub server: ServerInfo,

    /// The DNS forwarder for the peers of this interface that offer a nameserver. `innernet up
    /// --daemon` runs it while this section is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_forwarder: Option<DnsForwarderInfo>,

    /// A configurable map of peer public keys (base64) to Endpoints which should
    /// be used as the WireGuard endpoint for that peer.
    #[serde(default, deserialize_with = "deserialize_peer_endpoint_overrides")]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    peer_endpoint_overrides: BTreeMap<String, Endpoint>,
}

/// Deserializes endpoint overrides, refusing any not keyed by a peer's public key, such as
/// the peer IPs that older versions keyed them by.
fn deserialize_peer_endpoint_overrides<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, Endpoint>, D::Error> {
    BTreeMap::<String, Endpoint>::deserialize(deserializer)?
        .into_iter()
        .map(|(key, endpoint)| {
            if let Ok(ip) = key.parse::<IpAddr>() {
                return Err(D::Error::custom(format!(
                    "the endpoint override for {ip} is keyed by the peer's IP, which is no longer \
                     supported. Key it by the peer's public key instead, or remove it and set it \
                     again with 'innernet override-peer-endpoint'."
                )));
            }
            let public_key = Key::from_base64(&key).map_err(|_| {
                D::Error::custom(format!(
                    "the endpoint override key '{key}' is not a peer's public key"
                ))
            })?;
            Ok((public_key.to_base64(), endpoint))
        })
        .collect()
}

/// A DNS forwarder that answers queries for the hostnames of the peers that offer a nameserver,
/// and for the names under them, from the peers' nameservers. It refuses queries for any other
/// name. innernet does not configure the system resolver to use it.
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct DnsForwarderInfo {
    /// The address to answer queries at, over both UDP and TCP (e.g. "127.0.0.1:5353").
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

    /// The endpoint this peer announces that it can be reached at, set by `override-endpoint`.
    /// Kept locally so that the peer never signs an endpoint it learned from the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_endpoint: Option<Endpoint>,

    /// More addresses of this peer, each within one of its delegations, to put on the interface
    /// besides `address`, which remains its default source address. Supported on Linux only.
    /// innernet adds those missing when bringing the interface up and on each fetch, but never
    /// removes any: one removed from here, or withdrawn, stays on the interface until it is
    /// brought down or the address is removed by hand.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_addresses: Vec<IpAddr>,

    /// The parts of this peer's delegations that it announces it accepts traffic for: prefixes
    /// to include and, written `!prefix`, prefixes to exclude, in any order. Peers route to this
    /// peer only the parts it announces. When absent, every delegation is announced whole, as
    /// `["0.0.0.0/0", "::/0"]` would.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub announce_delegations: Option<Vec<PrefixSelector>>,

    /// The nameserver that this peer offers for names under its own name. It must be at this
    /// peer's address or within the parts of its delegations that it announces, or peers
    /// disregard it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub announce_nameserver: Option<SocketAddr>,

    /// The domain that the nameserver answers for, which peers substitute for this peer's name.
    /// When absent, it is this peer's name followed by the local host suffix, and a peer without a
    /// name offers no nameserver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub announce_zone: Option<String>,
}

impl InterfaceInfo {
    pub fn new(network_name: &InterfaceName, keypair: &KeyPair, address: IpNet) -> Self {
        Self {
            network_name: network_name.to_string(),
            private_key: keypair.private.to_base64(),
            address,
            listen_port: None,
            external_endpoint: None,
            extra_addresses: vec![],
            announce_delegations: None,
            announce_nameserver: None,
            announce_zone: None,
        }
    }

    /// The selection of the delegations that this peer announces.
    pub fn announce_delegations(&self) -> Vec<PrefixSelector> {
        self.announce_delegations
            .clone()
            .unwrap_or_else(PrefixSelector::all)
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
}

impl ServerInfo {
    pub fn new(server_peer: &Peer, internal_endpoint: SocketAddr) -> Self {
        Self {
            external_endpoint: server_peer
                .endpoint
                .clone()
                .expect("The innernet server should have a WireGuard endpoint"),
            internal_endpoint,
            public_key: server_peer.public_key.clone(),
        }
    }
}

impl InterfaceConfig {
    fn new(interface: InterfaceInfo, server: ServerInfo) -> Self {
        InterfaceConfig {
            interface,
            server,
            dns_forwarder: None,
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

    /// Endpoint overrides keyed by the peer's base64 public key.
    pub fn peer_endpoint_overrides(&self) -> &BTreeMap<String, Endpoint> {
        &self.peer_endpoint_overrides
    }

    pub fn endpoint_override_for_peer(&self, peer: &Peer) -> Option<&Endpoint> {
        self.peer_endpoint_overrides.get(&peer.public_key)
    }

    pub fn set_endpoint_override_for_peer(&mut self, peer: &Peer, endpoint: Endpoint) {
        self.peer_endpoint_overrides
            .insert(peer.public_key.clone(), endpoint);
    }

    pub fn unset_endpoint_override_for_peer(&mut self, peer: &Peer) {
        self.peer_endpoint_overrides.remove(&peer.public_key);
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
    use crate::PeerContents;

    const OLD_KEY: &str = "4CNZorWVtohO64n6AAaH/JyFjIIgBFrfJK2SGtKjzEE=";
    const NEW_KEY: &str = "GBfQ6Xqdrw2WsNsW8ZsANpyDLeffy6XqwOYpAyyZ3AQ=";

    fn peer(ip: &str, public_key: &str) -> Peer {
        Peer {
            id: 1,
            contents: PeerContents {
                name: Some("peer1".parse().unwrap()),
                ip: ip.parse().unwrap(),
                cidr_id: 1,
                public_key: public_key.to_owned(),
                endpoint: None,
                persistent_keepalive_interval: None,
                is_admin: false,
                is_disabled: false,
                is_redeemed: true,
                invite_expires: None,
                candidates: vec![],
                announcement: None,
                observed_endpoint: None,
                delegations: vec![],
            },
        }
    }

    fn parse(overrides: &str) -> Result<InterfaceConfig, toml::de::Error> {
        toml::from_str(&format!(
            r#"
            [interface]
            network-name = "test"
            address = "10.0.0.2/24"
            private-key = "{OLD_KEY}"
            listen-port = 51820

            [server]
            public-key = "{OLD_KEY}"
            external-endpoint = "203.0.113.1:51820"
            internal-endpoint = "10.0.0.1:51820"

            [peer-endpoint-overrides]
            {overrides}
            "#
        ))
    }

    fn config(overrides: &str) -> InterfaceConfig {
        parse(overrides).unwrap()
    }

    #[test]
    fn test_override_follows_public_key_not_ip() {
        let mut config = config("");
        let endpoint: Endpoint = "198.51.100.7:51820".parse().unwrap();
        config.set_endpoint_override_for_peer(&peer("10.0.0.3", OLD_KEY), endpoint.clone());

        // Same key at a new IP keeps the override, a new key at the old IP doesn't get it.
        assert_eq!(
            config.endpoint_override_for_peer(&peer("10.0.0.9", OLD_KEY)),
            Some(&endpoint)
        );
        assert_eq!(
            config.endpoint_override_for_peer(&peer("10.0.0.3", NEW_KEY)),
            None
        );
    }

    #[test]
    fn test_override_keys_must_be_public_keys() {
        let endpoint = "\"198.51.100.7:51820\"";
        let key = KeyPair::generate().public.to_base64();
        let loaded = parse(&format!("\"{key}\" = {endpoint}")).unwrap();
        assert!(loaded.peer_endpoint_overrides().contains_key(&key));

        // Older versions keyed overrides by peer IP.
        let error = parse(&format!("\"10.0.0.3\" = {endpoint}")).unwrap_err();
        assert!(
            error.to_string().contains("keyed by the peer's IP"),
            "{error}"
        );
        let error = parse(&format!("\"fd00::3\" = {endpoint}")).unwrap_err();
        assert!(
            error.to_string().contains("keyed by the peer's IP"),
            "{error}"
        );

        let error = parse(&format!("\"peer1\" = {endpoint}")).unwrap_err();
        assert!(
            error.to_string().contains("not a peer's public key"),
            "{error}"
        );
    }

    #[test]
    fn test_extra_addresses() {
        let config = config("");
        assert!(config.interface.extra_addresses.is_empty());
        assert!(!config.as_toml().contains("extra-addresses"));

        let config: InterfaceConfig = toml::from_str(&config.as_toml().replace(
            "[interface]\n",
            "[interface]\nextra-addresses = [\"10.0.0.40\", \"fd00::40\"]\n",
        ))
        .unwrap();
        assert_eq!(
            config.interface.extra_addresses,
            ["10.0.0.40", "fd00::40"].map(|a| a.parse::<IpAddr>().unwrap())
        );
        let reloaded: InterfaceConfig = toml::from_str(&config.as_toml()).unwrap();
        assert_eq!(
            reloaded.interface.extra_addresses,
            config.interface.extra_addresses
        );
    }

    #[test]
    fn test_announce_delegations() {
        let config = config("");
        assert_eq!(config.interface.announce_delegations, None);
        assert_eq!(
            config.interface.announce_delegations(),
            PrefixSelector::all()
        );
        assert!(!config.as_toml().contains("announce-delegations"));

        let with = |value: &str| {
            toml::from_str::<InterfaceConfig>(&config.as_toml().replace(
                "[interface]\n",
                &format!("[interface]\nannounce-delegations = {value}\n"),
            ))
        };
        let config = with(r#"["10.0.0.32/28", "!10.0.0.40/31", "fd00::/64"]"#).unwrap();
        assert_eq!(
            config.interface.announce_delegations(),
            ["10.0.0.32/28", "!10.0.0.40/31", "fd00::/64"]
                .map(|s| s.parse::<PrefixSelector>().unwrap())
        );
        let reloaded: InterfaceConfig = toml::from_str(&config.as_toml()).unwrap();
        assert_eq!(
            reloaded.interface.announce_delegations,
            config.interface.announce_delegations
        );

        // An empty list announces nothing, and a malformed entry is refused.
        assert_eq!(with("[]").unwrap().interface.announce_delegations(), vec![]);
        assert!(with(r#"["10.0.0.40"]"#).is_err());
    }

    #[test]
    fn test_dns_forwarder() {
        let config = config("");
        assert_eq!(config.dns_forwarder, None);
        assert!(!config.as_toml().contains("dns-forwarder"));

        let toml = config.as_toml().replace(
            "[server]\n",
            "[dns-forwarder]\nlisten = \"127.0.0.1:5353\"\n\n[server]\n",
        );
        let config: InterfaceConfig = toml::from_str(&toml).unwrap();
        assert_eq!(
            config.dns_forwarder,
            Some(DnsForwarderInfo {
                listen: "127.0.0.1:5353".parse().unwrap()
            })
        );
        let reloaded: InterfaceConfig = toml::from_str(&config.as_toml()).unwrap();
        assert_eq!(reloaded.dns_forwarder, config.dns_forwarder);
    }
}
