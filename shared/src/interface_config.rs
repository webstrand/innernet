use crate::{
    chmod, ensure_dirs_exist, hosts_fallback, Endpoint, Error, Hostname, IoErrorContext,
    PeerContents, Prefix, WrappedIoError,
};
use anyhow::{anyhow, bail};
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

    /// The DNS server for the names of the peers of this interface, which `innernet up --daemon`
    /// runs while this table is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsInfo>,

    /// The endpoints that this client uses for peers instead of those that the server reports.
    #[serde(default, skip_serializing_if = "EndpointOverrides::is_empty")]
    peer_endpoint_overrides: EndpointOverrides,
}

/// The `[peer-endpoint-overrides]` table of the config: endpoints keyed by the peer's public key,
/// in its canonical base64 encoding.
///
/// Versions before this one keyed overrides by peer IP. An IP-keyed entry is held apart, in
/// `by_ip`, where no lookup reaches it, so that
/// [`InterfaceConfig::refuse_ip_keyed_endpoint_overrides`] can refuse it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(
    try_from = "BTreeMap<String, Endpoint>",
    into = "BTreeMap<String, Endpoint>"
)]
struct EndpointOverrides {
    /// The overrides in use, keyed by the peer's canonical base64 public key.
    by_public_key: BTreeMap<String, Endpoint>,
    /// The overrides keyed by peer IP, which are refused.
    by_ip: BTreeMap<IpAddr, Endpoint>,
}

impl EndpointOverrides {
    fn is_empty(&self) -> bool {
        self.by_public_key.is_empty() && self.by_ip.is_empty()
    }
}

impl TryFrom<BTreeMap<String, Endpoint>> for EndpointOverrides {
    type Error = String;

    fn try_from(table: BTreeMap<String, Endpoint>) -> Result<Self, Self::Error> {
        let mut overrides = Self::default();
        for (key, endpoint) in table {
            // A base64 public key never parses as an IP.
            let duplicate = if let Ok(ip) = key.parse::<IpAddr>() {
                overrides.by_ip.insert(ip, endpoint).is_some()
            } else if let Ok(public_key) = Key::from_base64(&key) {
                overrides
                    .by_public_key
                    .insert(public_key.to_base64(), endpoint)
                    .is_some()
            } else {
                return Err(format!(
                    "the endpoint override key {key:?} is neither a peer's public key nor a \
                     peer IP"
                ));
            };
            if duplicate {
                return Err(format!(
                    "the endpoint override key {key:?} names a peer that another key names too"
                ));
            }
        }
        Ok(overrides)
    }
}

impl From<EndpointOverrides> for BTreeMap<String, Endpoint> {
    fn from(overrides: EndpointOverrides) -> Self {
        let by_ip = overrides
            .by_ip
            .into_iter()
            .map(|(ip, endpoint)| (ip.to_string(), endpoint));
        overrides.by_public_key.into_iter().chain(by_ip).collect()
    }
}

/// The `[dns]` table of the config of a client or of the server: a DNS server that answers queries
/// for the hostnames of the peers. It answers for the hostname of a peer itself, with the peer's
/// address, unless the peer offers a nameserver and `forward` selects it, in which case it answers
/// for the hostname and the names under it from the peer's nameserver. It refuses queries for any
/// other name. innernet doesn't configure the system resolver to use it.
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct DnsInfo {
    /// The address at which the server answers queries, over both UDP and TCP, such as
    /// `127.0.0.55:53`; `0.0.0.0` or `[::]` listens at every address. It should be a loopback
    /// address, since anyone who can reach it can query the nameservers of peers through it, and
    /// its port should be one that only a privileged user may bind, since a local user who binds
    /// it while the server doesn't answers for the names of peers.
    pub listen: SocketAddr,

    /// The peers to whose nameservers the server forwards queries, none by default.
    #[serde(default, skip_serializing_if = "Forwarding::is_none")]
    pub forward: Forwarding,
}

/// The peers to whose nameservers a DNS server forwards queries, as a list of selectors: `"*"`
/// selects every peer, a peer's name selects that peer, and a peer's name after `!` excludes that
/// peer, whatever else selects it. A peer is forwarded to if a selector selects it and none
/// excludes it, so a list of exclusions alone forwards to no peer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Forwarding(pub Vec<ForwardSelector>);

impl Forwarding {
    /// Whether the server forwards to no peer, since no selector selects one.
    pub fn is_none(&self) -> bool {
        !self
            .0
            .iter()
            .any(|selector| !matches!(selector, ForwardSelector::Except(_)))
    }

    /// Whether the server forwards queries to the nameserver of the peer named `name`.
    pub fn selects(&self, name: &str) -> bool {
        let mut selected = false;
        for selector in &self.0 {
            match selector {
                ForwardSelector::All => selected = true,
                ForwardSelector::Peer(peer) => selected |= **peer == *name,
                ForwardSelector::Except(peer) if **peer == *name => return false,
                ForwardSelector::Except(_) => {},
            }
        }
        selected
    }

    /// The names of peers that the selectors name, each once.
    pub fn named(&self) -> impl Iterator<Item = &Hostname> {
        let mut named: Vec<&Hostname> = self
            .0
            .iter()
            .filter_map(|selector| match selector {
                ForwardSelector::All => None,
                ForwardSelector::Peer(peer) | ForwardSelector::Except(peer) => Some(peer),
            })
            .collect();
        named.sort();
        named.dedup();
        named.into_iter()
    }
}

/// A selector of [`Forwarding`]: `"*"`, a peer's name, or a peer's name after `!`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub enum ForwardSelector {
    All,
    Peer(Hostname),
    Except(Hostname),
}

impl TryFrom<String> for ForwardSelector {
    type Error = String;

    fn try_from(selector: String) -> Result<Self, Self::Error> {
        if selector == "*" {
            return Ok(Self::All);
        }
        let (except, name) = match selector.strip_prefix('!') {
            Some(name) => (true, name),
            None => (false, selector.as_str()),
        };
        let name = name.parse::<Hostname>().map_err(|_| {
            format!(
                "the forward selector {selector:?} is neither \"*\" nor a peer's name, with or \
                 without \"!\""
            )
        })?;
        Ok(if except {
            Self::Except(name)
        } else {
            Self::Peer(name)
        })
    }
}

impl From<ForwardSelector> for String {
    fn from(selector: ForwardSelector) -> Self {
        match selector {
            ForwardSelector::All => "*".to_string(),
            ForwardSelector::Peer(name) => name.to_string(),
            ForwardSelector::Except(name) => format!("!{name}"),
        }
    }
}

#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct InterfaceInfo {
    /// The interface name (i.e. "tonari")
    pub network_name: String,

    /// The invited peer's internal IP address that's been allocated to it, inside
    /// the entire network's CIDR prefix. It is the primary IP that this client announces, at
    /// which its name resolves, and which must lie within the delegation that it claims.
    pub address: IpNet,

    /// WireGuard private key (base64)
    pub private_key: String,

    /// The local listen port. A random port will be used if `None`.
    pub listen_port: Option<u16>,

    /// The endpoint that this client announces, at which other peers reach it, or `None` to
    /// announce the endpoint at which the server observes it, if `announce_observed_endpoint`
    /// allows it. An endpoint whose host is unspecified, such as `0.0.0.0:51820`, takes the host
    /// of the observed endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_endpoint: Option<Endpoint>,

    /// Whether this client announces the endpoint at which the server observes it, as the state
    /// reports it: as its endpoint if `external_endpoint` is `None`, to complete the host of an
    /// `external_endpoint` whose host is unspecified, and otherwise as its first candidate. This
    /// client signs it like the rest of its announcement.
    #[serde(default = "yes", skip_serializing_if = "is_yes")]
    pub announce_observed_endpoint: bool,

    /// The delegation that this client claims in its announcements: prefixes each within one of
    /// the ranges that the server assigns it, or `None` for every assigned range whole. The
    /// addresses that it claims are its own: no other key may take them while it claims them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<Vec<Prefix>>,

    /// The prefixes that this client states that it accepts traffic for, which other peers route
    /// to it, or `None` for all of its delegation. Other peers shrink them to the delegation that
    /// it claims; a narrower list routes nothing of the rest of the delegation here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_ips: Option<Vec<Prefix>>,

    /// The addresses that this client assigns itself on its interface besides the address of
    /// `address`, each within the delegation that it claims.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_addresses: Vec<IpAddr>,

    /// The address and port of the nameserver that the node announces for its own name and the
    /// names under it, which must lie within the delegation that it claims.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub announce_nameserver: Option<SocketAddr>,

    /// The domain that the nameserver of `announce_nameserver` answers for, a canonical domain, or
    /// `None` for the node's own hostname, as its host suffix names it. Peers forward queries for
    /// their own hostname of the node to the nameserver with this domain in its place.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_zone"
    )]
    pub announce_zone: Option<String>,

    /// How long, in milliseconds, the node waits once the host's addresses change before it runs a
    /// round, so that the changes of a burst, such as those of a link that comes up, take one
    /// round. 200 when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_settle_ms: Option<u64>,
}

/// How long a node waits for the host's addresses to settle when its config doesn't say.
pub const DEFAULT_ADDRESS_SETTLE: std::time::Duration = std::time::Duration::from_millis(200);

/// Reads a zone, which must be a canonical domain.
fn deserialize_zone<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    let zone = String::deserialize(deserializer)?;
    if !innernet_domain::is_canonical_domain(&zone) {
        return Err(serde::de::Error::custom(format!(
            "the zone {:?} is not a canonical domain",
            zone
        )));
    }
    Ok(Some(zone))
}

fn yes() -> bool {
    true
}

fn is_yes(value: &bool) -> bool {
    *value
}

impl InterfaceInfo {
    pub fn new(network_name: &InterfaceName, keypair: &KeyPair, address: IpNet) -> Self {
        Self {
            network_name: network_name.to_string(),
            private_key: keypair.private.to_base64(),
            address,
            listen_port: None,
            external_endpoint: None,
            announce_observed_endpoint: true,
            delegation: None,
            allowed_ips: None,
            extra_addresses: vec![],
            announce_nameserver: None,
            announce_zone: None,
            address_settle_ms: None,
        }
    }

    /// How long the node waits for the host's addresses to settle once they change.
    pub fn address_settle(&self) -> std::time::Duration {
        self.address_settle_ms
            .map_or(DEFAULT_ADDRESS_SETTLE, std::time::Duration::from_millis)
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

    /// The UDP port of the server's TLS API, which runs over QUIC at the address of
    /// `internal_endpoint`, as the invitation states it. An invitation from a server that predates
    /// the port lacks it, and a client then asks the server for it in plain HTTP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic_port: Option<u16>,
}

/// The feature of a server that speaks TLS. A client that redeems an invitation stating it never
/// falls back to plain HTTP for the server.
pub const FEATURE_TLS: &str = "tls";

impl ServerInfo {
    pub fn new(server_peer: &PeerContents, internal_endpoint: SocketAddr) -> Self {
        Self {
            external_endpoint: server_peer
                .endpoint
                .clone()
                .expect("The innernet server should have a WireGuard endpoint"),
            internal_endpoint,
            public_key: server_peer.public_key.clone(),
            features: vec![],
            quic_port: None,
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
            peer_endpoint_overrides: EndpointOverrides::default(),
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

    /// The endpoint overrides, keyed by the peer's canonical base64 public key.
    pub fn peer_endpoint_overrides(&self) -> &BTreeMap<String, Endpoint> {
        &self.peer_endpoint_overrides.by_public_key
    }

    pub fn endpoint_override_for_peer(&self, peer: &PeerContents) -> Option<&Endpoint> {
        self.peer_endpoint_overrides
            .by_public_key
            .get(&peer.public_key)
    }

    /// Fails if the config keys an endpoint override by peer IP, as versions before this one wrote
    /// them, which this version doesn't read. The error names each override as this version reads
    /// it: keyed by the public key of the peer of `peers` that holds the IP, if exactly one does.
    pub fn refuse_ip_keyed_endpoint_overrides(&self, peers: &[PeerContents]) -> Result<(), Error> {
        let by_ip = &self.peer_endpoint_overrides.by_ip;
        if by_ip.is_empty() {
            return Ok(());
        }
        let mut lines = vec![];
        for (ip, endpoint) in by_ip {
            let mut holders = peers.iter().filter(|peer| peer.holds(*ip));
            match (holders.next(), holders.next()) {
                (Some(peer), None) => {
                    lines.push(format!("\"{}\" = \"{endpoint}\" # {ip}", peer.public_key))
                },
                _ => lines.push(format!(
                    "# \"{ip}\" = \"{endpoint}\": not exactly one peer holds {ip}"
                )),
            }
        }
        bail!(
            "{}: the config keys endpoint overrides by peer IP, which this version doesn't read; \
             [peer-endpoint-overrides] must key them by the peer's public key:\n{}",
            self.interface.network_name,
            lines.join("\n")
        )
    }
}

impl InterfaceInfo {
    pub fn public_key(&self) -> Result<String, Error> {
        Ok(wireguard_control::Key::from_base64(&self.private_key)?
            .get_public()
            .to_base64())
    }
}

/// An invitation to join a network: the key with which the invited peer redeems it, what the
/// server offers the peer, and how to reach the server. Redeeming an invitation turns it into an
/// [`InterfaceConfig`], with [`Invitation::resolve`].
///
/// An invitation offers delegations within the network, and names no source address: the client
/// picks one within the delegations. An invitation of the format of v2.0.0, which a server that
/// predates TLS writes, and which an admin client writes for such a server, names the address of
/// the peer instead, and no delegations.
#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
#[must_use]
pub struct Invitation {
    pub interface: InvitedInterface,
    pub server: ServerInfo,
}

/// The `[interface]` table of an [`Invitation`].
#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct InvitedInterface {
    /// The interface name (i.e. "tonari")
    pub network_name: String,

    /// The source address of the peer, with the prefix of the network. An invitation of the
    /// format of v2.0.0 names it, and offers it alone. In an invitation that offers delegations,
    /// it is optional, and selects the source address within them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<IpNet>,

    /// The WireGuard private key (base64) with which the invitation is redeemed.
    pub private_key: String,

    /// The network that the peer joins, which holds its delegations. Absent from an invitation
    /// of the format of v2.0.0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_cidr: Option<IpNet>,

    /// The delegations that the server offers the peer. Absent from an invitation of the format
    /// of v2.0.0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegations: Option<Vec<Prefix>>,

    /// The local listen port. A random port will be used if `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
}

/// An invitation resolved into the config of the interface that redeems it, and the delegations
/// that it offers the peer.
#[derive(Clone, Debug)]
pub struct ResolvedInvitation {
    pub config: InterfaceConfig,
    pub delegations: Vec<Prefix>,
}

impl Invitation {
    /// An invitation for the peer of `keypair` to the network `network_cidr` of `network_name`,
    /// offering it `delegations`, without a source address.
    pub fn offering(
        network_name: &InterfaceName,
        keypair: &KeyPair,
        network_cidr: IpNet,
        delegations: Vec<Prefix>,
        server: ServerInfo,
    ) -> Self {
        Self {
            interface: InvitedInterface {
                network_name: network_name.to_string(),
                address: None,
                private_key: keypair.private.to_base64(),
                network_cidr: Some(network_cidr.trunc()),
                delegations: Some(delegations),
                listen_port: None,
            },
            server,
        }
    }

    /// An invitation of the format of v2.0.0, as servers that predate TLS write it: for the peer
    /// of `keypair` at `address`, with the prefix of the network.
    pub fn legacy(
        network_name: &InterfaceName,
        keypair: &KeyPair,
        address: IpNet,
        server: ServerInfo,
    ) -> Self {
        Self {
            interface: InvitedInterface {
                network_name: network_name.to_string(),
                address: Some(address),
                private_key: keypair.private.to_base64(),
                network_cidr: None,
                delegations: None,
                listen_port: None,
            },
            server,
        }
    }

    pub fn from_file(file: &mut File) -> Result<Self, Error> {
        let mut toml = String::new();
        file.read_to_string(&mut toml)?;
        Ok(toml::from_str(&toml)?)
    }

    /// The config of the interface that redeems the invitation, and the delegations that it
    /// offers.
    ///
    /// An invitation that offers delegations must state the network that holds them, every
    /// delegation must lie within it, and no two delegations may share an address. The source
    /// address of the interface is the address that the invitation names, which must lie within
    /// the delegations, or else the lowest address of the delegations, with the prefix of the
    /// network. An invitation of the format of v2.0.0 must name an address, which it offers as a
    /// host prefix.
    pub fn resolve(self) -> Result<ResolvedInvitation, Error> {
        let InvitedInterface {
            network_name,
            address,
            private_key,
            network_cidr,
            delegations,
            listen_port,
        } = self.interface;
        let (address, delegations) = match delegations {
            Some(mut delegations) => {
                let network = network_cidr
                    .ok_or_else(|| {
                        anyhow!(
                            "the invitation offers delegations without the network-cidr that \
                             holds them"
                        )
                    })?
                    .trunc();
                delegations.sort();
                if let Some(pair) = delegations
                    .windows(2)
                    .find(|pair| pair[0].overlaps(&pair[1]))
                {
                    bail!(
                        "the invitation offers {} and {}, which overlap",
                        pair[0],
                        pair[1]
                    );
                }
                if let Some(outside) = delegations
                    .iter()
                    .find(|delegation| !network.contains(&delegation.net()))
                {
                    bail!(
                        "the invitation offers {outside}, which is outside the network {network}"
                    );
                }
                let source = match address {
                    Some(address) => {
                        let ip = address.addr();
                        if !delegations.iter().any(|d| d.contains_addr(&ip)) {
                            bail!(
                                "the address {ip} of the invitation lies outside the delegations \
                                 that it offers"
                            );
                        }
                        ip
                    },
                    None => hosts_fallback(&delegations)
                        .ok_or_else(|| anyhow!("the invitation offers no delegation"))?,
                };
                (IpNet::new(source, network.prefix_len())?, delegations)
            },
            None => {
                let address = address.ok_or_else(|| {
                    anyhow!("the invitation names neither an address nor delegations")
                })?;
                (address, vec![Prefix::host(address.addr())])
            },
        };
        let interface = InterfaceInfo {
            network_name,
            address,
            private_key,
            listen_port,
            external_endpoint: None,
            announce_observed_endpoint: true,
            delegation: None,
            allowed_ips: None,
            extra_addresses: vec![],
            announce_nameserver: None,
            announce_zone: None,
            address_settle_ms: None,
        };
        Ok(ResolvedInvitation {
            config: InterfaceConfig::new(interface, self.server),
            delegations,
        })
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

        file.write_all(toml::to_string(self).unwrap().as_bytes())?;

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

    #[test]
    fn test_announce_nameserver() {
        // A config without a nameserver is written back without one.
        let config: InterfaceConfig = toml::from_str(INVITATION).unwrap();
        assert_eq!(config.interface.announce_nameserver, None);
        assert_eq!(config.interface.announce_zone, None);
        assert!(!toml::to_string(&config).unwrap().contains("announce-"));

        let with = |lines: &str| {
            toml::from_str::<InterfaceConfig>(
                &INVITATION.replace("[interface]", &format!("[interface]\n{lines}")),
            )
        };
        let config =
            with("announce-nameserver = \"10.0.0.2:53\"\nannounce-zone = \"example.com\"").unwrap();
        assert_eq!(
            config.interface.announce_nameserver,
            Some("10.0.0.2:53".parse().unwrap())
        );
        assert_eq!(
            config.interface.announce_zone.as_deref(),
            Some("example.com")
        );
        let config: InterfaceConfig = toml::from_str(&toml::to_string(&config).unwrap()).unwrap();
        assert_eq!(
            config.interface.announce_zone.as_deref(),
            Some("example.com")
        );

        // A zone that isn't a canonical domain is refused with the config.
        for zone in ["Example.com", "example.com.", "", "10.0.0.1"] {
            assert!(
                with(&format!("announce-zone = {zone:?}")).is_err(),
                "{zone}"
            );
        }
    }

    #[test]
    fn test_dns() {
        let config: InterfaceConfig = toml::from_str(INVITATION).unwrap();
        assert_eq!(config.dns, None);
        assert!(!toml::to_string(&config).unwrap().contains("[dns]"));

        // A table without `forward` forwards to no peer, and is written back without it.
        let with = |table: &str| {
            toml::from_str::<InterfaceConfig>(
                &INVITATION.replace("[server]", &format!("[dns]\n{table}\n\n[server]")),
            )
        };
        let config = with("listen = \"127.0.0.55:53\"").unwrap();
        let dns = Some(DnsInfo {
            listen: "127.0.0.55:53".parse().unwrap(),
            forward: Forwarding::default(),
        });
        assert_eq!(config.dns, dns);
        let written = toml::to_string(&config).unwrap();
        assert!(!written.contains("forward"), "{written}");
        let config: InterfaceConfig = toml::from_str(&written).unwrap();
        assert_eq!(config.dns, dns);

        // The selectors are read and written back as they are spelled.
        let config = with("listen = \"127.0.0.55:53\"\nforward = [\"*\", \"!b\", \"c\"]").unwrap();
        let forward = &config.dns.as_ref().unwrap().forward;
        assert_eq!(
            forward.0,
            [
                ForwardSelector::All,
                ForwardSelector::Except("b".parse().unwrap()),
                ForwardSelector::Peer("c".parse().unwrap()),
            ]
        );
        let written = toml::to_string(&config).unwrap();
        assert!(
            written.contains(r#"forward = ["*", "!b", "c"]"#),
            "{written}"
        );

        // A selector that is neither "*" nor a peer's name, with or without "!", is refused.
        for selector in ["", "!", "!*", "B", "**", "!!b"] {
            assert!(
                with(&format!(
                    "listen = \"127.0.0.55:53\"\nforward = [{selector:?}]"
                ))
                .is_err(),
                "{selector}"
            );
        }
    }

    #[test]
    fn test_forwarding() {
        let forwarding = |selectors: &[&str]| {
            Forwarding(
                selectors
                    .iter()
                    .map(|selector| selector.to_string().try_into().unwrap())
                    .collect(),
            )
        };
        let selected = |forwarding: &Forwarding| {
            ["a", "b", "c"]
                .into_iter()
                .filter(|name| forwarding.selects(name))
                .collect::<Vec<_>>()
        };
        assert_eq!(selected(&forwarding(&[])), [] as [&str; 0]);
        assert_eq!(selected(&forwarding(&["*"])), ["a", "b", "c"]);
        assert_eq!(selected(&forwarding(&["a", "c"])), ["a", "c"]);
        // An exclusion wins over every selector, wherever it stands.
        assert_eq!(selected(&forwarding(&["*", "!b"])), ["a", "c"]);
        assert_eq!(selected(&forwarding(&["!b", "*", "b"])), ["a", "c"]);
        // Exclusions alone select no peer.
        assert_eq!(selected(&forwarding(&["!b"])), [] as [&str; 0]);
        assert!(forwarding(&["!b"]).is_none());
        assert!(!forwarding(&["a"]).is_none());

        let named = forwarding(&["*", "b", "!a", "!b"]);
        assert_eq!(
            named.named().map(|name| &**name).collect::<Vec<_>>(),
            ["a", "b"]
        );
    }

    #[test]
    fn test_quic_port() {
        // An invitation from a server that predates the QUIC port lacks it, and is written back
        // without it.
        let config: InterfaceConfig = toml::from_str(INVITATION).unwrap();
        assert_eq!(config.server.quic_port, None);
        assert!(!toml::to_string(&config).unwrap().contains("quic-port"));

        // A new invitation states it in its [server] table.
        let invitation = INVITATION.replace("[server]", "[server]\nquic-port = 41641");
        let config: InterfaceConfig = toml::from_str(&invitation).unwrap();
        assert_eq!(config.server.quic_port, Some(41641));
        let config: InterfaceConfig = toml::from_str(&toml::to_string(&config).unwrap()).unwrap();
        assert_eq!(config.server.quic_port, Some(41641));
    }

    /// An invitation offering delegations.
    const OFFERING: &str = r#"
        [interface]
        network-name = "test"
        private-key = "kOg3HWw0ZE4tdhyA7kZGRUwAxp04i48yD3ElXNSNkmM="
        network-cidr = "10.0.0.0/16"
        delegations = ["10.0.1.0/24", "10.0.0.9/32"]

        [server]
        public-key = "dz0/Fjmj7oRBSGxgWXSkE3n9R3k19kJOj127FzJZ81g="
        external-endpoint = "203.0.113.1:51820"
        internal-endpoint = "10.0.0.1:51820"
        features = ["tls"]
    "#;

    fn prefixes(prefixes: &[&str]) -> Vec<Prefix> {
        prefixes
            .iter()
            .map(|prefix| prefix.parse().unwrap())
            .collect()
    }

    #[test]
    fn test_resolve_invitation() {
        // The source address is the lowest address of the delegations, with the prefix of the
        // network.
        let invitation: Invitation = toml::from_str(OFFERING).unwrap();
        let resolved = invitation.clone().resolve().unwrap();
        assert_eq!(
            resolved.config.interface.address,
            "10.0.0.9/16".parse::<IpNet>().unwrap()
        );
        assert_eq!(
            resolved.delegations,
            prefixes(&["10.0.0.9/32", "10.0.1.0/24"])
        );
        assert!(resolved.config.server.has_feature(FEATURE_TLS));

        // An address that the invitation names selects the source address within them.
        let mut named = invitation.clone();
        named.interface.address = Some("10.0.1.7/16".parse().unwrap());
        assert_eq!(
            named.resolve().unwrap().config.interface.address,
            "10.0.1.7/16".parse::<IpNet>().unwrap()
        );

        // An address outside the delegations, a delegation outside the network, a missing network,
        // an empty offer and delegations that overlap are refused.
        let mut outside = invitation.clone();
        outside.interface.address = Some("10.0.2.7/16".parse().unwrap());
        let mut beyond = invitation.clone();
        beyond.interface.delegations = Some(prefixes(&["10.1.0.0/24"]));
        let mut without_network = invitation.clone();
        without_network.interface.network_cidr = None;
        let mut empty = invitation.clone();
        empty.interface.delegations = Some(vec![]);
        let mut overlapping = invitation.clone();
        overlapping.interface.delegations =
            Some(prefixes(&["10.0.1.0/24", "10.0.0.9/32", "10.0.1.128/25"]));
        let mut duplicate = invitation.clone();
        duplicate.interface.delegations = Some(prefixes(&["10.0.0.9/32", "10.0.0.9/32"]));
        for (refused, reason) in [
            (outside, "outside the delegations"),
            (beyond, "outside the network"),
            (without_network, "network-cidr"),
            (empty, "no delegation"),
            (overlapping, "10.0.1.0/24 and 10.0.1.128/25, which overlap"),
            (duplicate, "overlap"),
        ] {
            let error = refused.resolve().unwrap_err().to_string();
            assert!(error.contains(reason), "{error}");
        }

        // An invitation of the format of v2.0.0 offers its address as a host prefix.
        let legacy: Invitation = toml::from_str(INVITATION).unwrap();
        let resolved = legacy.resolve().unwrap();
        assert_eq!(
            resolved.config.interface.address,
            "10.0.0.2/24".parse::<IpNet>().unwrap()
        );
        assert_eq!(resolved.delegations, prefixes(&["10.0.0.2/32"]));
        let mut neither: Invitation = toml::from_str(INVITATION).unwrap();
        neither.interface.address = None;
        assert!(neither.resolve().is_err());
    }

    #[test]
    fn test_write_invitations() {
        let keypair = KeyPair::generate();
        let interface: InterfaceName = "test".parse().unwrap();
        let server: ServerInfo = toml::from_str::<Invitation>(OFFERING).unwrap().server;
        let written = |invitation: &Invitation| -> toml::Table {
            toml::from_str::<toml::Table>(&toml::to_string(invitation).unwrap()).unwrap()
                ["interface"]
                .as_table()
                .unwrap()
                .clone()
        };

        // An invitation offers delegations, and names no address.
        let offering = Invitation::offering(
            &interface,
            &keypair,
            "10.0.0.0/16".parse().unwrap(),
            prefixes(&["10.0.0.9/32"]),
            server.clone(),
        );
        let table = written(&offering);
        assert!(!table.contains_key("address"));
        assert_eq!(table["network-cidr"].as_str(), Some("10.0.0.0/16"));
        assert_eq!(table["delegations"][0].as_str(), Some("10.0.0.9/32"));

        // One of the format of v2.0.0 names the address, which a client that predates TLS reads
        // into its config, and nothing else.
        let legacy =
            Invitation::legacy(&interface, &keypair, "10.0.0.9/16".parse().unwrap(), server);
        let table = written(&legacy);
        assert_eq!(table["address"].as_str(), Some("10.0.0.9/16"));
        assert!(!table.contains_key("network-cidr") && !table.contains_key("delegations"));
        let config: InterfaceConfig = toml::from_str(&toml::to_string(&legacy).unwrap()).unwrap();
        assert_eq!(
            config.interface.address,
            "10.0.0.9/16".parse::<IpNet>().unwrap()
        );
    }

    const KEY_A: &str = "4CNZorWVtohO64n6AAaH/JyFjIIgBFrfJK2SGtKjzEE=";
    const KEY_B: &str = "GBfQ6Xqdrw2WsNsW8ZsANpyDLeffy6XqwOYpAyyZ3AQ=";

    fn peer(ip: &str, public_key: &str) -> PeerContents {
        PeerContents {
            name: Some("peer1".parse().unwrap()),
            delegations: vec![Prefix::host(ip.parse().unwrap())],
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
            nameserver: None,
        }
    }

    fn parse(overrides: &str) -> Result<InterfaceConfig, toml::de::Error> {
        toml::from_str(&format!(
            "{INVITATION}\n[peer-endpoint-overrides]\n{overrides}"
        ))
    }

    /// The `[peer-endpoint-overrides]` table as `config` is written back.
    fn written_overrides(config: &InterfaceConfig) -> BTreeMap<String, Endpoint> {
        #[derive(Deserialize)]
        #[serde(rename_all = "kebab-case")]
        struct Written {
            #[serde(default)]
            peer_endpoint_overrides: BTreeMap<String, Endpoint>,
        }
        toml::from_str::<Written>(&config.as_toml())
            .unwrap()
            .peer_endpoint_overrides
    }

    fn endpoint(endpoint: &str) -> Endpoint {
        endpoint.parse().unwrap()
    }

    #[test]
    fn test_endpoint_overrides_keyed_by_public_key() {
        let config = parse(&format!("\"{KEY_A}\" = \"198.51.100.7:51820\"")).unwrap();

        // The override follows the key, wherever its peer is, and never the IP.
        assert_eq!(
            config.endpoint_override_for_peer(&peer("10.0.0.9", KEY_A)),
            Some(&endpoint("198.51.100.7:51820"))
        );
        assert_eq!(
            config.endpoint_override_for_peer(&peer("10.0.0.9", KEY_B)),
            None
        );
        assert_eq!(
            written_overrides(&config),
            config.peer_endpoint_overrides().clone()
        );

        // A key that is neither a public key nor an IP is refused.
        let error = parse("\"peer1\" = \"198.51.100.7:51820\"").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("neither a peer's public key nor a peer IP"),
            "{error}"
        );
    }

    #[test]
    fn test_address_settle() {
        let config = parse("").unwrap();
        assert_eq!(config.interface.address_settle(), DEFAULT_ADDRESS_SETTLE);
        let text = INVITATION.replace("[interface]\n", "[interface]\naddress-settle-ms = 50\n");
        let config: InterfaceConfig = toml::from_str(&text).unwrap();
        assert_eq!(
            config.interface.address_settle(),
            std::time::Duration::from_millis(50)
        );
    }

    #[test]
    fn test_ip_keyed_endpoint_overrides_are_refused() {
        // A config that an earlier version wrote keys its overrides by IP, which are unused, and
        // refused, each named as this version reads it.
        let config = parse(&format!(
            "\"10.0.0.3\" = \"198.51.100.7:51820\"\n\"10.0.0.4\" = \"198.51.100.8:51820\"\n\
             \"{KEY_B}\" = \"198.51.100.10:51820\""
        ))
        .unwrap();
        assert_eq!(config.peer_endpoint_overrides().len(), 1);
        let peers = [peer("10.0.0.3", KEY_A), peer("10.0.0.5", KEY_B)];
        let error = config
            .refuse_ip_keyed_endpoint_overrides(&peers)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&format!("\"{KEY_A}\" = \"198.51.100.7:51820\" # 10.0.0.3")),
            "{error}"
        );
        assert!(
            error.contains("not exactly one peer holds 10.0.0.4"),
            "{error}"
        );

        let keyed = parse(&format!("\"{KEY_B}\" = \"198.51.100.10:51820\"")).unwrap();
        assert!(keyed.refuse_ip_keyed_endpoint_overrides(&peers).is_ok());
    }
}
