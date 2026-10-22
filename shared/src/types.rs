use crate::{wg::PeerInfoExt, Prefix};
use anyhow::{anyhow, Error};
use clap::{
    builder::{PossibleValuesParser, TypedValueParser},
    Args,
};
use ipnet::{IpNet, PrefixLenError};
use serde::{de, Deserialize, Deserializer, Serialize};
use std::{
    fmt::{self, Display, Formatter},
    io,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, SystemTime},
    vec,
};
use url::Host;
use wireguard_control::{
    AllowedIp, Backend, InterfaceName, InvalidInterfaceName, Key, PeerConfig, PeerConfigBuilder,
    PeerInfo,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    name: InterfaceName,
}

impl FromStr for Interface {
    type Err = InvalidInterfaceName;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        if !innernet_domain::is_canonical_label(name) {
            Err(InvalidInterfaceName::InvalidChars)
        } else {
            Ok(Self {
                name: name.parse()?,
            })
        }
    }
}

impl Deref for Interface {
    type Target = InterfaceName;

    fn deref(&self) -> &Self::Target {
        &self.name
    }
}

impl Display for Interface {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// An external endpoint that supports both IP and domain name hosts.
pub struct Endpoint {
    host: Host,
    port: u16,
}

impl From<SocketAddr> for Endpoint {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4addr) => Self {
                host: Host::Ipv4(*v4addr.ip()),
                port: v4addr.port(),
            },
            SocketAddr::V6(v6addr) => Self {
                host: Host::Ipv6(*v6addr.ip()),
                port: v6addr.port(),
            },
        }
    }
}

impl FromStr for Endpoint {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.rsplitn(2, ':').collect::<Vec<&str>>().as_slice() {
            [port, host] => {
                let port = port.parse().map_err(|_| "couldn't parse port")?;
                let host = Host::parse(host).map_err(|_| "couldn't parse host")?;
                Ok(Endpoint { host, port })
            },
            _ => Err("couldn't parse in form of 'host:port'"),
        }
    }
}

impl Serialize for Endpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Endpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct EndpointVisitor;
        impl serde::de::Visitor<'_> for EndpointVisitor {
            type Value = Endpoint;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid host:port endpoint")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                s.parse().map_err(serde::de::Error::custom)
            }
        }
        deserializer.deserialize_str(EndpointVisitor)
    }
}

impl Display for Endpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.host.fmt(f)?;
        f.write_str(":")?;
        self.port.fmt(f)
    }
}

impl Endpoint {
    pub fn resolve(&self) -> Result<SocketAddr, io::Error> {
        let mut addrs = self.to_string().to_socket_addrs()?;
        addrs.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "failed to resolve address".to_string(),
            )
        })
    }

    /// Returns true if the endpoint host is unspecified e.g. 0.0.0.0
    pub fn is_host_unspecified(&self) -> bool {
        match self.host {
            Host::Ipv4(ip) => ip.is_unspecified(),
            Host::Ipv6(ip) => ip.is_unspecified(),
            Host::Domain(_) => false,
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The host of the endpoint, if it is an IP address.
    pub fn ip(&self) -> Option<IpAddr> {
        match &self.host {
            Host::Ipv4(ip) => Some(IpAddr::V4(*ip)),
            Host::Ipv6(ip) => Some(IpAddr::V6(*ip)),
            Host::Domain(_) => None,
        }
    }

    /// The host of the endpoint, if it is a domain name.
    pub fn domain(&self) -> Option<&str> {
        match &self.host {
            Host::Domain(domain) => Some(domain),
            Host::Ipv4(_) | Host::Ipv6(_) => None,
        }
    }

    /// The endpoint at `domain`, which must be a domain name rather than an IP address.
    pub fn from_domain(domain: &str, port: u16) -> Result<Self, &'static str> {
        match Host::parse(domain) {
            Ok(host @ Host::Domain(_)) => Ok(Self { host, port }),
            _ => Err("not a domain name"),
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(tag = "option", content = "content")]
pub enum EndpointContents {
    Set(Endpoint),
    Unset,
}

impl From<EndpointContents> for Option<Endpoint> {
    fn from(endpoint: EndpointContents) -> Self {
        match endpoint {
            EndpointContents::Set(addr) => Some(addr),
            EndpointContents::Unset => None,
        }
    }
}

impl From<Option<Endpoint>> for EndpointContents {
    fn from(option: Option<Endpoint>) -> Self {
        match option {
            Some(addr) => Self::Set(addr),
            None => Self::Unset,
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct AssociationContents {
    pub cidr_id_1: i64,
    pub cidr_id_2: i64,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Association {
    pub id: i64,

    #[serde(flatten)]
    pub contents: AssociationContents,
}

impl Deref for Association {
    type Target = AssociationContents;

    fn deref(&self) -> &Self::Target {
        &self.contents
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, PartialOrd, Eq, Ord)]
pub struct CidrContents {
    pub name: String,
    pub cidr: IpNet,
    pub parent: Option<i64>,
}

impl CidrContents {
    pub fn new(name: String, cidr: IpNet, parent: &Cidr) -> Self {
        Self {
            name,
            cidr,
            parent: Some(parent.id),
        }
    }
}

impl Deref for CidrContents {
    type Target = IpNet;

    fn deref(&self) -> &Self::Target {
        &self.cidr
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, PartialOrd, Eq, Ord)]
pub struct Cidr {
    pub id: i64,

    #[serde(flatten)]
    pub contents: CidrContents,
}

impl Display for Cidr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.cidr)
    }
}

impl Deref for Cidr {
    type Target = CidrContents;

    fn deref(&self) -> &Self::Target {
        &self.contents
    }
}

#[derive(Clone, PartialEq, PartialOrd, Eq, Ord)]
pub struct CidrTree<'a> {
    cidrs: &'a [Cidr],
    contents: &'a Cidr,
}

impl std::ops::Deref for CidrTree<'_> {
    type Target = Cidr;

    fn deref(&self) -> &Self::Target {
        self.contents
    }
}

impl<'a> CidrTree<'a> {
    pub fn new(cidrs: &'a [Cidr]) -> Self {
        let root = cidrs
            .iter()
            .min_by_key(|c| c.cidr.prefix_len())
            .expect("failed to find root CIDR");
        Self::with_root(cidrs, root)
    }

    pub fn with_root(cidrs: &'a [Cidr], root: &'a Cidr) -> Self {
        Self {
            cidrs,
            contents: root,
        }
    }

    pub fn children(&self) -> impl Iterator<Item = CidrTree<'_>> {
        self.cidrs
            .iter()
            .filter(move |c| c.parent == Some(self.contents.id))
            .map(move |c| CidrTree {
                cidrs: self.cidrs,
                contents: c,
            })
    }

    pub fn leaves(&self) -> Vec<Cidr> {
        if !self.cidrs.iter().any(|cidr| cidr.parent == Some(self.id)) {
            vec![self.contents.clone()]
        } else {
            self.children().flat_map(|child| child.leaves()).collect()
        }
    }

    pub fn ip_net_for(&self, ip: IpAddr) -> Result<IpNet, PrefixLenError> {
        IpNet::new(ip, self.contents.prefix_len())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RedeemContents {
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct InstallOpts {
    /// Set a specific interface name
    #[clap(long, conflicts_with = "default_name")]
    pub name: Option<String>,

    /// Use the network name inside the invitation as the interface name
    #[clap(long = "default-name")]
    pub default_name: bool,

    /// Delete the invitation after a successful install
    #[clap(short, long)]
    pub delete_invite: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct AddPeerOpts {
    /// Name of new peer
    #[clap(long)]
    pub name: Option<Hostname>,

    /// Specify desired IP of new peer (within parent CIDR)
    #[clap(long, conflicts_with = "auto_ip")]
    pub ip: Option<IpAddr>,

    /// Auto-assign the peer the first available IP within the CIDR
    #[clap(long = "auto-ip")]
    pub auto_ip: bool,

    /// Name of CIDR to add new peer under
    #[clap(long)]
    pub cidr: Option<String>,

    /// Make new peer an admin?
    #[clap(long)]
    pub admin: Option<bool>,

    /// Bypass confirmation
    #[clap(long)]
    pub yes: bool,

    /// Save the config to the given location
    #[clap(long)]
    pub save_config: Option<String>,

    /// Invite expiration period (eg. '30d', '7w', '2h', '60m', '1000s')
    #[clap(long)]
    pub invite_expires: Option<Timestring>,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct RenamePeerOpts {
    /// Name of peer to rename
    #[clap(long)]
    pub name: Option<Hostname>,

    /// The new name of the peer
    #[clap(long)]
    pub new_name: Option<Hostname>,

    /// Bypass confirmation
    #[clap(long)]
    pub yes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct EnableDisablePeerOpts {
    /// Name of peer to enable/disable
    #[clap(long)]
    pub name: Option<Hostname>,

    /// Bypass confirmation
    #[clap(long, requires("name"))]
    pub yes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct AddCidrOpts {
    /// The CIDR name (eg. 'engineers')
    #[clap(long)]
    pub name: Option<Hostname>,

    /// The CIDR network (eg. '10.42.5.0/24')
    #[clap(long)]
    pub cidr: Option<IpNet>,

    /// The CIDR parent name
    #[clap(long)]
    pub parent: Option<String>,

    /// Bypass confirmation
    #[clap(long)]
    pub yes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct RenameCidrOpts {
    /// Name of CIDR to rename
    #[clap(long)]
    pub name: Option<String>,

    /// The new name of the CIDR
    #[clap(long)]
    pub new_name: Option<String>,

    /// Bypass confirmation
    #[clap(long)]
    pub yes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct DeleteCidrOpts {
    /// The CIDR name (eg. 'engineers')
    #[clap(long)]
    pub name: Option<String>,

    /// Bypass confirmation
    #[clap(long)]
    pub yes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct AddDeleteAssociationOpts {
    /// The first cidr to associate
    pub cidr1: Option<String>,

    /// The second cidr to associate
    pub cidr2: Option<String>,

    /// Bypass confirmation
    #[clap(long)]
    pub yes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct ListenPortOpts {
    /// The listen port you'd like to set for the interface
    #[clap(short, long)]
    pub listen_port: Option<u16>,

    /// Unset the local listen port to use a randomized port
    #[clap(short, long, conflicts_with = "listen_port")]
    pub unset: bool,

    /// Bypass confirmation
    #[clap(long)]
    pub yes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct OverrideEndpointOpts {
    /// The external endpoint that you'd like the innernet server to broadcast to other peers. The
    /// IP address may be unspecified (all zeros), in which case the server will try to resolve it
    /// based on its most recent connection. The port will still be used, even if you decide to use
    /// an unspecified IP address.
    #[clap(short, long)]
    pub endpoint: Option<Endpoint>,

    /// Unset an existing override to use the automatic endpoint discovery
    #[clap(short, long, conflicts_with = "endpoint")]
    pub unset: bool,

    /// Bypass confirmation
    #[clap(long)]
    pub yes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct OverridePeerEndpointOpts {
    /// Name of peer whose endpoint you want to override
    #[clap(long)]
    pub name: Option<Hostname>,

    /// The external endpoint that you'd like to use for a given peer
    #[clap(short, long)]
    pub endpoint: Option<Endpoint>,

    /// Unset an existing local endpoint override for this peer
    #[clap(short, long, conflicts_with = "endpoint")]
    pub unset: bool,

    /// Bypass confirmation
    #[clap(long)]
    pub yes: bool,
}

#[derive(Debug, Clone, Args)]
pub struct NatOpts {
    #[clap(long)]
    /// Don't attempt NAT traversal. Note that this still will report candidates
    /// unless you also specify to exclude all NAT candidates.
    pub no_nat_traversal: bool,

    #[clap(long)]
    /// Exclude one or more CIDRs from NAT candidate reporting.
    /// ex. --exclude-nat-candidates '0.0.0.0/0' would report no candidates.
    pub exclude_nat_candidates: Vec<IpNet>,

    #[clap(long, conflicts_with = "exclude_nat_candidates")]
    /// Don't report any candidates to coordinating server.
    /// Shorthand for --exclude-nat-candidates '0.0.0.0/0'.
    pub no_nat_candidates: bool,
}

impl NatOpts {
    pub fn all_disabled() -> Self {
        Self {
            no_nat_traversal: true,
            exclude_nat_candidates: vec![],
            no_nat_candidates: true,
        }
    }

    /// Check if an IP is allowed to be reported as a candidate.
    pub fn is_excluded(&self, ip: IpAddr) -> bool {
        self.no_nat_candidates
            || self
                .exclude_nat_candidates
                .iter()
                .any(|network| network.contains(&ip))
    }
}

#[derive(Debug, Clone, Copy, Args)]
pub struct NetworkOpts {
    #[clap(long)]
    /// Whether the routing should be done by innernet or is done by an
    /// external tool like e.g. babeld.
    pub no_routing: bool,

    #[clap(long, default_value_t, value_parser = PossibleValuesParser::new(Backend::variants()).map(|s| s.parse::<Backend>().unwrap()))]
    /// Specify a WireGuard backend to use.
    /// If not set, innernet will auto-select based on availability.
    pub backend: Backend,

    #[clap(long)]
    /// Specify the desired MTU for your interface (default: 1280).
    pub mtu: Option<u32>,
}

#[derive(Clone, Debug, Args)]
pub struct HostsOpts {
    /// Ignored: innernet no longer writes a hosts file. Accepted so that existing invocations
    /// keep working.
    #[clap(long = "hosts-path", hide = true)]
    pub hosts_path: Option<PathBuf>,

    /// Ignored: innernet no longer writes a hosts file. Accepted so that existing invocations
    /// keep working.
    #[clap(long = "no-write-hosts", hide = true)]
    pub no_write_hosts: bool,

    /// Use a different suffix for the hostnames of peers that the DNS server answers for, than
    /// 'INTERFACE.wg', ex. --host-suffix 'evilnet' names peers: PEER.evilnet
    #[clap(long = "host-suffix", value_parser = parse_host_suffix)]
    pub host_suffix: Option<String>,
}

impl HostsOpts {
    /// Warns of the options of the hosts file, which innernet no longer writes.
    pub fn warn_of_hosts_file_options(&self) {
        if self.hosts_path.is_some() || self.no_write_hosts {
            log::warn!(
                "innernet no longer writes a hosts file, so --hosts-path and --no-write-hosts \
                 have no effect."
            );
        }
    }
}

/// Parses a host suffix: labels that are each a valid hostname, separated by dots. An empty
/// suffix, which named the peers in the hosts file by their bare names, is refused: every
/// hostname lies under a suffix.
fn parse_host_suffix(suffix: &str) -> Result<String, String> {
    if suffix.is_empty() {
        Err("the host suffix must not be empty".to_string())
    } else if suffix.split('.').all(Hostname::is_valid) {
        Ok(suffix.to_string())
    } else {
        Err("each dot-separated label must be a valid hostname".to_string())
    }
}

/// A peer, without the ID by which the API of plain-HTTP sessions names it. The API of TLS
/// sessions names a peer by its public key, and transfers peers in this form. A peer that a server
/// in plain HTTP transfers, as a [`LegacyPeer`], converts into this form, without the ID.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PeerContents {
    /// The name of the peer, or `None` if it has none. A peer without a name has `null` as its
    /// name, or no name at all. A name that is not a valid [`Hostname`] deserializes as no name,
    /// so that a client can read peers from a server that allows other names; the server refuses
    /// such a name on its own API.
    #[serde(default, deserialize_with = "deserialize_peer_name")]
    pub name: Option<Hostname>,
    pub ip: IpAddr,
    pub cidr_id: i64,
    #[serde(deserialize_with = "deserialize_public_key")]
    pub public_key: String,
    pub endpoint: Option<Endpoint>,
    pub persistent_keepalive_interval: Option<u16>,
    pub is_admin: bool,
    pub is_disabled: bool,
    pub is_redeemed: bool,
    pub invite_expires: Option<SystemTime>,
    #[serde(default)]
    pub candidates: Vec<Endpoint>,
}

impl PeerContents {
    /// The public key of the peer in the URL-safe base64 alphabet, padding included, by which a
    /// path of the admin API names the peer in TLS sessions.
    pub fn api_path_segment(&self) -> String {
        self.public_key.replace('+', "-").replace('/', "_")
    }

    /// The name of the peer for display, or "[unnamed]" if it has none.
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or("[unnamed]")
    }

    /// The address at which the name of the peer resolves, or `None` if the peer has none.
    pub fn hosts_fallback(&self) -> Option<IpAddr> {
        Some(self.ip)
    }

    /// The address of the peer for display: its hosts fallback address, or "[no delegation]" if
    /// it has none.
    pub fn display_address(&self) -> String {
        match self.hosts_fallback() {
            Some(ip) => ip.to_string(),
            None => "[no delegation]".to_string(),
        }
    }

    /// The prefixes that WireGuard routes to the peer.
    pub fn allowed_ips(&self) -> Vec<AllowedIp> {
        vec![Prefix::host(self.ip).allowed_ip()]
    }

    /// Whether the address `ip` is the peer's.
    pub fn holds(&self, ip: IpAddr) -> bool {
        self.ip == ip
    }
}

impl AsRef<PeerContents> for PeerContents {
    fn as_ref(&self) -> &PeerContents {
        self
    }
}

impl Display for PeerContents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.display_name(), self.public_key)
    }
}

/// A peer and its tag: the body of `GET /admin/peers/{key}` in TLS sessions. A change to the peer
/// carries the tag, and the server refuses the change if the peer has changed since. The tag
/// leaves out the peer's endpoint and candidates, which the peer reports on its own.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct TaggedPeer {
    pub peer: PeerContents,
    pub tag: String,
}

/// The changes that an admin may make to a peer: the body of `PUT /admin/peers/{key}` in TLS
/// sessions. `tag` is that of the peer as the admin read it. `name` is `null` for a peer without a
/// name, and must be present, so that an update that leaves it out can't remove the name.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PeerUpdate {
    pub tag: String,
    #[serde(deserialize_with = "Option::deserialize")]
    pub name: Option<Hostname>,
    pub is_admin: bool,
    pub is_disabled: bool,
}

impl PeerUpdate {
    /// The changes that set the peer with the tag `tag` to the name, admin role and disabled
    /// state of `contents`.
    pub fn new(tag: String, contents: &PeerContents) -> Self {
        Self {
            tag,
            name: contents.name.clone(),
            is_admin: contents.is_admin,
            is_disabled: contents.is_disabled,
        }
    }
}

/// The endpoint and candidates stored for a peer, as the peer or an admin set them, without the
/// endpoint that the server observes.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PeerEndpoints {
    pub endpoint: Option<Endpoint>,
    #[serde(default)]
    pub candidates: Vec<Endpoint>,
}

/// A peer's endpoints and their tag: the body of `GET` and `PUT /admin/peers/{key}/endpoints` in
/// TLS sessions. The endpoints are tagged apart from the rest of the peer. A `PUT` carries the
/// tag of the endpoints as the admin read them, and the server refuses it if they have changed
/// since.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct TaggedPeerEndpoints {
    pub endpoints: PeerEndpoints,
    pub tag: String,
}

/// Deserializes a WireGuard public key, refusing an invalid key and normalizing a valid one to its
/// canonical base64 encoding, so that public keys can be compared as strings.
fn deserialize_public_key<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let public_key = String::deserialize(deserializer)?;
    Key::from_base64(&public_key)
        .map(|key| key.to_base64())
        .map_err(|_| de::Error::custom(format!("invalid public key {public_key:?}")))
}

/// Deserializes the name of a peer, a string or `null`. A string that is not a valid [`Hostname`]
/// is read as no name.
fn deserialize_peer_name<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Hostname>, D::Error> {
    let name = Option::<String>::deserialize(deserializer)?;
    Ok(name.and_then(|name| Hostname::try_from(name).ok()))
}

/// What can be read of a peer that failed to deserialize, to identify it.
#[derive(Deserialize)]
struct PeerIdentity {
    public_key: Option<String>,
}

/// A peer of a list, of the form `T`, which may fail to deserialize without failing the list.
#[derive(Deserialize)]
#[serde(untagged)]
enum MaybePeer<T> {
    Valid(T),
    Invalid(PeerIdentity),
    Unrecognized(de::IgnoredAny),
}

/// The peers of `peers` that deserialized, and the canonical public keys of those that didn't but
/// whose public key is valid, each of which is dropped with a warning.
fn split_valid_peers<T>(peers: Vec<MaybePeer<T>>) -> (Vec<T>, Vec<String>) {
    let mut valid = vec![];
    let mut invalid_keys = vec![];
    for peer in peers {
        match peer {
            MaybePeer::Valid(peer) => valid.push(peer),
            MaybePeer::Invalid(PeerIdentity { public_key }) => {
                log::warn!(
                    "ignoring an invalid peer with public key {}.",
                    public_key.as_deref().unwrap_or("[unknown]"),
                );
                if let Some(key) = public_key.and_then(|key| Key::from_base64(&key).ok()) {
                    invalid_keys.push(key.to_base64());
                }
            },
            MaybePeer::Unrecognized(_) => log::warn!("ignoring an invalid peer."),
        }
    }
    (valid, invalid_keys)
}

/// A peer as clients that predate TLS know it, without its ID: the form of the peers of the API
/// of plain-HTTP sessions, and of the data store of earlier versions. The API of TLS sessions
/// transfers peers as [`PeerContents`].
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct LegacyPeerContents {
    /// The name of the peer. Clients that predate TLS can't read a peer without a name, so the
    /// view of plain-HTTP sessions leaves such peers out. A name that is not a valid
    /// [`Hostname`] deserializes as no name, as in [`PeerContents`].
    #[serde(default, deserialize_with = "deserialize_peer_name")]
    pub name: Option<Hostname>,
    pub ip: IpAddr,
    pub cidr_id: i64,
    #[serde(deserialize_with = "deserialize_public_key")]
    pub public_key: String,
    pub endpoint: Option<Endpoint>,
    pub persistent_keepalive_interval: Option<u16>,
    pub is_admin: bool,
    pub is_disabled: bool,
    pub is_redeemed: bool,
    pub invite_expires: Option<SystemTime>,
    #[serde(default)]
    pub candidates: Vec<Endpoint>,
}

impl LegacyPeerContents {
    /// `peer` as clients that predate TLS know it, or `None` if they can't represent it: a peer
    /// without a name.
    pub fn from_peer(peer: &PeerContents) -> Option<Self> {
        peer.name.as_ref()?;
        Some(Self {
            name: peer.name.clone(),
            ip: peer.ip,
            cidr_id: peer.cidr_id,
            public_key: peer.public_key.clone(),
            endpoint: peer.endpoint.clone(),
            persistent_keepalive_interval: peer.persistent_keepalive_interval,
            is_admin: peer.is_admin,
            is_disabled: peer.is_disabled,
            is_redeemed: peer.is_redeemed,
            invite_expires: peer.invite_expires,
            candidates: peer.candidates.clone(),
        })
    }
}

impl From<LegacyPeerContents> for PeerContents {
    fn from(peer: LegacyPeerContents) -> Self {
        Self {
            name: peer.name,
            ip: peer.ip,
            cidr_id: peer.cidr_id,
            public_key: peer.public_key,
            endpoint: peer.endpoint,
            persistent_keepalive_interval: peer.persistent_keepalive_interval,
            is_admin: peer.is_admin,
            is_disabled: peer.is_disabled,
            is_redeemed: peer.is_redeemed,
            invite_expires: peer.invite_expires,
            candidates: peer.candidates,
        }
    }
}

/// A peer with the ID by which the API of plain-HTTP sessions names it, as clients that predate
/// TLS transfer peers. The API of TLS sessions transfers peers without an ID, as
/// [`PeerContents`].
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct LegacyPeer {
    pub id: i64,

    #[serde(flatten)]
    pub contents: LegacyPeerContents,
}

impl Deref for LegacyPeer {
    type Target = LegacyPeerContents;

    fn deref(&self) -> &Self::Target {
        &self.contents
    }
}

impl DerefMut for LegacyPeer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.contents
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerChange {
    AllowedIPs {
        old: Vec<AllowedIp>,
        new: Vec<AllowedIp>,
    },
    PersistentKeepalive {
        old: Option<u16>,
        new: Option<u16>,
    },
    Endpoint {
        old: Option<SocketAddr>,
        new: Option<SocketAddr>,
    },
    NatTraverseReattempt,
}

impl Display for PeerChange {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllowedIPs { old, new } => write!(f, "Allowed IPs: {old:?} => {new:?}"),
            Self::PersistentKeepalive { old, new } => write!(
                f,
                "Persistent Keepalive: {} => {}",
                old.display_string(),
                new.display_string()
            ),
            Self::Endpoint { old, new } => write!(
                f,
                "Endpoint: {} => {}",
                old.display_string(),
                new.display_string()
            ),
            Self::NatTraverseReattempt => write!(f, "NAT Traversal Reattempt"),
        }
    }
}

trait OptionExt {
    fn display_string(&self) -> String;
}

impl<T: std::fmt::Debug> OptionExt for Option<T> {
    fn display_string(&self) -> String {
        match self {
            Some(x) => {
                format!("{x:?}")
            },
            None => "[none]".to_string(),
        }
    }
}

/// Encompasses the logic for comparing the peer configuration currently on the WireGuard interface
/// to a (potentially) more current peer configuration from the innernet server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerDiff<'a> {
    pub old: Option<&'a PeerConfig>,
    pub new: Option<&'a PeerContents>,
    builder: PeerConfigBuilder,
    changes: Vec<PeerChange>,
}

impl<'a> PeerDiff<'a> {
    /// `endpoint_override`, if any, replaces the endpoint of `new`.
    pub fn new(
        old_info: Option<&'a PeerInfo>,
        new: Option<&'a PeerContents>,
        endpoint_override: Option<&Endpoint>,
    ) -> Result<Option<Self>, Error> {
        let old = old_info.map(|p| &p.config);
        match (old_info, new) {
            (Some(old), Some(new)) if old.config.public_key.to_base64() != new.public_key => Err(
                anyhow!("old and new peer configs have different public keys"),
            ),
            (None, None) => Ok(None),
            _ => Ok(
                Self::peer_config_builder(old_info, new, endpoint_override).map(
                    |(builder, changes)| Self {
                        old,
                        new,
                        builder,
                        changes,
                    },
                ),
            ),
        }
    }

    pub fn public_key(&self) -> &Key {
        self.builder.public_key()
    }

    pub fn changes(&self) -> &[PeerChange] {
        &self.changes
    }

    fn peer_config_builder(
        old_info: Option<&PeerInfo>,
        new: Option<&PeerContents>,
        endpoint_override: Option<&Endpoint>,
    ) -> Option<(PeerConfigBuilder, Vec<PeerChange>)> {
        let old = old_info.map(|p| &p.config);
        let public_key = match (old, new) {
            (Some(old), _) => old.public_key.clone(),
            (_, Some(new)) => Key::from_base64(&new.public_key).unwrap(),
            _ => return None,
        };
        let mut builder = PeerConfigBuilder::new(&public_key);
        let mut changes = vec![];

        // Remove peer from interface if they're deleted or disabled, and we can return early.
        if new.is_none() || matches!(new, Some(new) if new.is_disabled) {
            return Some((builder.remove(), changes));
        }
        // diff.new is now guaranteed to be a Some(_) variant.
        let new = new.unwrap();

        let new_allowed_ips = new.allowed_ips();
        // The interface doesn't necessarily list allowed IPs in the order they were added.
        let sorted = |ips: &[AllowedIp]| {
            let mut ips = ips.to_vec();
            ips.sort_by_key(|ip| (ip.address, ip.cidr));
            ips
        };
        if old.is_none()
            || matches!(old, Some(old) if sorted(&old.allowed_ips) != sorted(&new_allowed_ips))
        {
            builder = builder
                .replace_allowed_ips()
                .add_allowed_ips(&new_allowed_ips);
            changes.push(PeerChange::AllowedIPs {
                old: old.map(|o| o.allowed_ips.clone()).unwrap_or_default(),
                new: new_allowed_ips,
            });
        }

        if old.is_none()
            || matches!(old, Some(old) if old.persistent_keepalive_interval != new.persistent_keepalive_interval)
        {
            builder = match new.persistent_keepalive_interval {
                Some(interval) => builder.set_persistent_keepalive_interval(interval),
                None => builder.unset_persistent_keepalive(),
            };
            changes.push(PeerChange::PersistentKeepalive {
                old: old.and_then(|p| p.persistent_keepalive_interval),
                new: new.persistent_keepalive_interval,
            });
        }

        // We won't update the endpoint if there's already a stable connection.
        if !old_info
            .map(|info| info.is_recently_connected())
            .unwrap_or_default()
        {
            let mut endpoint_changed = false;
            let resolved = endpoint_override
                .or(new.endpoint.as_ref())
                .and_then(|e| e.resolve().ok());
            if let Some(addr) = resolved {
                if old.is_none() || matches!(old, Some(old) if old.endpoint != resolved) {
                    builder = builder.set_endpoint(addr);
                    changes.push(PeerChange::Endpoint {
                        old: old.and_then(|p| p.endpoint),
                        new: Some(addr),
                    });
                    endpoint_changed = true;
                }
            }
            if !endpoint_changed && !new.candidates.is_empty() {
                changes.push(PeerChange::NatTraverseReattempt)
            }
        }

        if !changes.is_empty() {
            Some((builder, changes))
        } else {
            None
        }
    }
}

impl From<&PeerContents> for PeerConfigBuilder {
    fn from(peer: &PeerContents) -> Self {
        PeerDiff::new(None, Some(peer), None)
            .expect("No Err on explicitly set peer data")
            .expect("None -> Some(peer) will always create a PeerDiff")
            .into()
    }
}

impl From<PeerDiff<'_>> for PeerConfigBuilder {
    /// Turn a PeerDiff into a minimal set of instructions to update the WireGuard interface,
    /// hopefully minimizing dropped packets and other interruptions.
    fn from(diff: PeerDiff) -> Self {
        diff.builder
    }
}

/// This model is sent as a response to the /state endpoint, and is meant
/// to include all the data a client needs to update its WireGuard interface.
///
/// The API of TLS sessions sends the peers without IDs. A state that a server sends in plain HTTP,
/// as [`LegacyState`], converts into this form, without the IDs.
#[derive(Debug, Clone, Serialize)]
pub struct State {
    /// This list will be only the peers visible to the user requesting this
    /// information, not including disabled peers or peers from other CIDRs
    /// that the user's CIDR is not authorized to communicate with.
    pub peers: Vec<PeerContents>,

    /// At the moment, this is all CIDRs, regardless of whether the peer is
    /// eligible to communicate with them or not.
    pub cidrs: Vec<Cidr>,

    /// The public keys of the peers that failed to deserialize, which the server nonetheless
    /// reported. It is never sent.
    #[serde(skip)]
    pub invalid_peer_keys: Vec<String>,
}

impl<'de> Deserialize<'de> for State {
    /// Deserializes a state, dropping with a warning each peer that fails to deserialize, but
    /// keeping its public key in `invalid_peer_keys` if the key is valid.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Fields {
            peers: Vec<MaybePeer<PeerContents>>,
            cidrs: Vec<Cidr>,
        }

        let Fields { peers, cidrs } = Fields::deserialize(deserializer)?;
        let (peers, invalid_peer_keys) = split_valid_peers(peers);
        Ok(Self {
            peers,
            cidrs,
            invalid_peer_keys,
        })
    }
}

/// The state that the API of plain-HTTP sessions sends, in which each peer has the ID that
/// clients that predate TLS expect.
#[derive(Debug, Clone, Serialize)]
pub struct LegacyState {
    pub peers: Vec<LegacyPeer>,
    pub cidrs: Vec<Cidr>,

    /// The public keys of the peers that failed to deserialize, as in [`State`]. It is never
    /// sent.
    #[serde(skip)]
    pub invalid_peer_keys: Vec<String>,
}

impl<'de> Deserialize<'de> for LegacyState {
    /// Deserializes a state as [`State`] does, dropping with a warning each peer that fails to
    /// deserialize, but keeping its public key in `invalid_peer_keys` if the key is valid.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Fields {
            peers: Vec<MaybePeer<LegacyPeer>>,
            cidrs: Vec<Cidr>,
        }

        let Fields { peers, cidrs } = Fields::deserialize(deserializer)?;
        let (peers, invalid_peer_keys) = split_valid_peers(peers);
        Ok(Self {
            peers,
            cidrs,
            invalid_peer_keys,
        })
    }
}

impl From<LegacyState> for State {
    /// The state without the IDs of the peers.
    fn from(state: LegacyState) -> Self {
        Self {
            peers: state
                .peers
                .into_iter()
                .map(|peer| peer.contents.into())
                .collect(),
            cidrs: state.cidrs,
            invalid_peer_keys: state.invalid_peer_keys,
        }
    }
}

/// This model is sent as a response to the /capabilities endpoint.
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct ServerCapabilities {
    #[serde(default)]
    pub unspecified_ip_in_override_endpoint: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timestring {
    timestring: String,
    seconds: u64,
}

impl Display for Timestring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.timestring)
    }
}

impl FromStr for Timestring {
    type Err = &'static str;

    fn from_str(timestring: &str) -> Result<Self, Self::Err> {
        if timestring.len() < 2 {
            Err("timestring isn't long enough!")
        } else {
            let (n, suffix) = timestring.split_at(timestring.len() - 1);
            let n: u64 = n.parse().map_err(|_| {
                "invalid timestring (a number followed by a time unit character, eg. '15m')"
            })?;
            let multiplier = match suffix {
                "s" => Ok(1),
                "m" => Ok(60),
                "h" => Ok(60 * 60),
                "d" => Ok(60 * 60 * 24),
                "w" => Ok(60 * 60 * 24 * 7),
                _ => Err("invalid timestring suffix (must be one of 's', 'm', 'h', 'd', or 'w')"),
            }?;

            Ok(Self {
                timestring: timestring.to_string(),
                seconds: n * multiplier,
            })
        }
    }
}

impl From<Timestring> for Duration {
    fn from(timestring: Timestring) -> Self {
        Duration::from_secs(timestring.seconds)
    }
}

/// The name of a peer. Its hostname is this name, followed by the host suffix.
///
/// A parsed or deserialized name must match [`Hostname::is_valid`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Hostname(String);

impl Hostname {
    /// Whether `name` is a single canonical label, which may be a number, since a suffix always
    /// follows it in its hostname.
    pub fn is_valid(name: &str) -> bool {
        innernet_domain::is_canonical_label(name)
    }
}

impl FromStr for Hostname {
    type Err = &'static str;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        if Self::is_valid(name) {
            Ok(Self(name.to_string()))
        } else {
            Err("invalid hostname string (only lowercase alphanumeric with dashes)")
        }
    }
}

impl TryFrom<String> for Hostname {
    type Error = String;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        if Self::is_valid(&name) {
            Ok(Self(name))
        } else {
            Err(format!("invalid hostname {name:?}"))
        }
    }
}

impl Deref for Hostname {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for Hostname {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub trait IoErrorContext<T> {
    fn with_path<P: AsRef<Path>>(self, path: P) -> Result<T, WrappedIoError>;
    fn with_str<S: Into<String>>(self, context: S) -> Result<T, WrappedIoError>;
}

impl<T> IoErrorContext<T> for Result<T, std::io::Error> {
    fn with_path<P: AsRef<Path>>(self, path: P) -> Result<T, WrappedIoError> {
        self.with_str(path.as_ref().to_string_lossy())
    }

    fn with_str<S: Into<String>>(self, context: S) -> Result<T, WrappedIoError> {
        self.map_err(|e| WrappedIoError {
            io_error: e,
            context: context.into(),
        })
    }
}

#[derive(Debug)]
pub struct WrappedIoError {
    io_error: std::io::Error,
    context: String,
}

impl Display for WrappedIoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{} - {}", self.context, self.io_error)
    }
}

impl Deref for WrappedIoError {
    type Target = std::io::Error;

    fn deref(&self) -> &Self::Target {
        &self.io_error
    }
}

impl std::error::Error for WrappedIoError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use wireguard_control::{Key, PeerConfigBuilder, PeerStats};

    #[test]
    fn test_parse_host_suffix() {
        for valid in ["evilnet", "wg.example.com"] {
            assert_eq!(parse_host_suffix(valid).as_deref(), Ok(valid));
        }
        for invalid in [
            "",
            "evil net",
            "wg\nexample.com",
            "wg#1",
            ".wg",
            "wg.",
            "Wg",
            "wgé",
        ] {
            assert!(parse_host_suffix(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn test_peer_no_diff() {
        const PUBKEY: &str = "4CNZorWVtohO64n6AAaH/JyFjIIgBFrfJK2SGtKjzEE=";
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let peer = PeerContents {
            name: Some("peer1".parse().unwrap()),
            ip,
            cidr_id: 1,
            public_key: PUBKEY.to_owned(),
            endpoint: None,
            persistent_keepalive_interval: None,
            is_admin: false,
            is_disabled: false,
            is_redeemed: true,
            invite_expires: None,
            candidates: vec![],
        };
        let builder =
            PeerConfigBuilder::new(&Key::from_base64(PUBKEY).unwrap()).add_allowed_ip(ip, 32);

        let config = builder.into_peer_config();
        let info = PeerInfo {
            config,
            stats: Default::default(),
        };

        let diff = PeerDiff::new(Some(&info), Some(&peer), None).unwrap();

        println!("{diff:?}");
        assert_eq!(diff, None);
    }

    #[test]
    fn test_peer_diff() {
        const PUBKEY: &str = "4CNZorWVtohO64n6AAaH/JyFjIIgBFrfJK2SGtKjzEE=";
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let peer = PeerContents {
            name: Some("peer1".parse().unwrap()),
            ip,
            cidr_id: 1,
            public_key: PUBKEY.to_owned(),
            endpoint: None,
            persistent_keepalive_interval: Some(15),
            is_admin: false,
            is_disabled: false,
            is_redeemed: true,
            invite_expires: None,
            candidates: vec![],
        };
        let builder =
            PeerConfigBuilder::new(&Key::from_base64(PUBKEY).unwrap()).add_allowed_ip(ip, 32);

        let config = builder.into_peer_config();
        let info = PeerInfo {
            config,
            stats: Default::default(),
        };
        let diff = PeerDiff::new(Some(&info), Some(&peer), None).unwrap();

        println!("{peer:?}");
        println!("{:?}", info.config);
        assert!(diff.is_some());
    }

    #[test]
    fn test_peer_diff_handshake_time() {
        const PUBKEY: &str = "4CNZorWVtohO64n6AAaH/JyFjIIgBFrfJK2SGtKjzEE=";
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let peer = PeerContents {
            name: Some("peer1".parse().unwrap()),
            ip,
            cidr_id: 1,
            public_key: PUBKEY.to_owned(),
            endpoint: Some("1.1.1.1:1111".parse().unwrap()),
            persistent_keepalive_interval: None,
            is_admin: false,
            is_disabled: false,
            is_redeemed: true,
            invite_expires: None,
            candidates: vec![],
        };
        let builder =
            PeerConfigBuilder::new(&Key::from_base64(PUBKEY).unwrap()).add_allowed_ip(ip, 32);

        let config = builder.into_peer_config();
        let mut info = PeerInfo {
            config,
            stats: PeerStats {
                last_handshake_time: Some(SystemTime::now() - Duration::from_secs(200)),
                ..Default::default()
            },
        };

        // If there hasn't been a recent handshake, endpoint should be being set.
        assert!(matches!(
            PeerDiff::new(Some(&info), Some(&peer), None),
            Ok(Some(_))
        ));

        // If there *has* been a recent handshake, endpoint should *not* be being set.
        info.stats.last_handshake_time = Some(SystemTime::now());
        assert!(matches!(
            PeerDiff::new(Some(&info), Some(&peer), None),
            Ok(None)
        ));
    }

    #[test]
    fn test_peer_diff_endpoint_override() {
        const PUBKEY: &str = "4CNZorWVtohO64n6AAaH/JyFjIIgBFrfJK2SGtKjzEE=";
        let peer = PeerContents {
            name: Some("peer1".parse().unwrap()),
            ip: "10.0.0.1".parse().unwrap(),
            cidr_id: 1,
            public_key: PUBKEY.to_owned(),
            endpoint: Some("1.1.1.1:1111".parse().unwrap()),
            persistent_keepalive_interval: None,
            is_admin: false,
            is_disabled: false,
            is_redeemed: true,
            invite_expires: None,
            candidates: vec![],
        };
        let endpoint_override: Endpoint = "2.2.2.2:2222".parse().unwrap();

        // The override replaces the endpoint of the peer.
        let diff = PeerDiff::new(None, Some(&peer), Some(&endpoint_override))
            .unwrap()
            .unwrap();
        assert!(diff.changes().contains(&PeerChange::Endpoint {
            old: None,
            new: Some("2.2.2.2:2222".parse().unwrap()),
        }));
    }

    #[test]
    fn test_deserialize_public_key() {
        const PUBKEY: &str = "4CNZorWVtohO64n6AAaH/JyFjIIgBFrfJK2SGtKjzEE=";
        let deserialize = |public_key| {
            deserialize_public_key(de::value::StrDeserializer::<de::value::Error>::new(
                public_key,
            ))
        };

        assert_eq!(deserialize(PUBKEY).unwrap(), PUBKEY);
        // An unpadded encoding of the same key is normalized to the canonical encoding.
        assert_eq!(deserialize(PUBKEY.trim_end_matches('=')).unwrap(), PUBKEY);
        assert!(deserialize("abc").is_err());
        assert!(deserialize("").is_err());
    }

    #[test]
    fn test_deserialize_hostname() {
        use serde::de::value::{Error, StrDeserializer};
        let deserialize = |name| Hostname::deserialize(StrDeserializer::<Error>::new(name));

        assert_eq!(*deserialize("peer-1").unwrap(), *"peer-1");
        // A suffix usually follows a peer name, so it may be a number.
        assert_eq!(*deserialize("08").unwrap(), *"08");
        assert_eq!("08".parse::<Hostname>(), Ok(deserialize("08").unwrap()));
        assert!(deserialize("a.b").is_err());
        assert!("a.b".parse::<Hostname>().is_err());
        assert!(deserialize("").is_err());
        assert!(deserialize("Peer").is_err());
        assert!(deserialize("peer\n10.0.0.1 example.com").is_err());
        assert!(deserialize(&"a".repeat(64)).is_err());
    }

    #[test]
    fn test_peers_without_a_name() {
        const PUBKEY: &str = "4CNZorWVtohO64n6AAaH/JyFjIIgBFrfJK2SGtKjzEE=";
        let peer = |name: serde_json::Value| {
            serde_json::from_value::<PeerContents>(serde_json::json!({
                "name": name,
                "ip": "10.0.0.1",
                "cidr_id": 1,
                "public_key": PUBKEY,
                "endpoint": null,
                "persistent_keepalive_interval": null,
                "is_admin": false,
                "is_disabled": false,
                "is_redeemed": true,
                "invite_expires": null,
            }))
        };

        // A peer has no name if its name is null or missing, and is sent with a null name.
        let nameless = peer(serde_json::json!(null)).unwrap();
        assert_eq!(nameless.name, None);
        assert_eq!(nameless.display_name(), "[unnamed]");
        assert_eq!(
            serde_json::to_value(&nameless).unwrap()["name"],
            serde_json::json!(null)
        );
        let mut missing = serde_json::to_value(&nameless).unwrap();
        missing.as_object_mut().unwrap().remove("name");
        assert_eq!(
            serde_json::from_value::<PeerContents>(missing).unwrap(),
            nameless
        );
        assert_eq!(
            peer("peer-1".into()).unwrap().name,
            Some("peer-1".parse().unwrap())
        );
        // A name that is not valid is read as no name.
        assert_eq!(peer("Peer".into()).unwrap(), nameless);
        assert_eq!(peer("peer\n10.0.0.1 example.com".into()).unwrap(), nameless);
        // A name that is not a string fails to deserialize.
        assert!(peer(1.into()).is_err());

        // An update carries the name, or null, but never leaves it out.
        let update: PeerUpdate = serde_json::from_value(serde_json::json!({
            "tag": "ab", "name": null, "is_admin": false, "is_disabled": false,
        }))
        .unwrap();
        assert_eq!(update.name, None);
        assert!(serde_json::from_value::<PeerUpdate>(serde_json::json!({
            "tag": "ab", "is_admin": false, "is_disabled": false,
        }))
        .is_err());
    }

    #[test]
    fn test_state_keeps_peers_with_invalid_names() {
        // A peer whose name is not valid is kept in the state as a peer without a name, as a
        // server that allows other names reports it.
        const PUBKEY: &str = "4CNZorWVtohO64n6AAaH/JyFjIIgBFrfJK2SGtKjzEE=";
        let peer = serde_json::json!({
            "id": 1,
            "name": "peer\n10.0.0.1 example.com",
            "ip": "10.0.0.1",
            "cidr_id": 1,
            "public_key": PUBKEY,
            "endpoint": null,
            "persistent_keepalive_interval": null,
            "is_admin": false,
            "is_disabled": false,
            "is_redeemed": true,
            "invite_expires": null,
        });
        let state: State =
            serde_json::from_value(serde_json::json!({ "peers": [peer], "cidrs": [] })).unwrap();
        assert_eq!(state.peers.len(), 1);
        assert_eq!(state.peers[0].name, None);
        assert_eq!(state.peers[0].public_key, PUBKEY);
        assert!(state.invalid_peer_keys.is_empty());
    }

    #[test]
    fn test_legacy_state() {
        // A state that a server sends in plain HTTP drops each invalid peer, keeping its key, and
        // converts into a state without IDs.
        const PUBKEY: &str = "4CNZorWVtohO64n6AAaH/JyFjIIgBFrfJK2SGtKjzEE=";
        const INVALID_KEY: &str = "GBfQ6Xqdrw2WsNsW8ZsANpyDLeffy6XqwOYpAyyZ3AQ=";
        let peer = |id: i64, ip: &str, public_key: &str| {
            serde_json::json!({
                "id": id,
                "name": "peer1",
                "ip": ip,
                "cidr_id": 1,
                "public_key": public_key,
                "endpoint": null,
                "persistent_keepalive_interval": null,
                "is_admin": false,
                "is_disabled": false,
                "is_redeemed": true,
                "invite_expires": null,
            })
        };
        let state: LegacyState = serde_json::from_value(serde_json::json!({
            "peers": [peer(1, "10.0.0.1", PUBKEY), peer(2, "not an IP", INVALID_KEY)],
            "cidrs": [],
        }))
        .unwrap();
        assert_eq!(state.peers.len(), 1);
        assert_eq!(state.peers[0].id, 1);
        assert_eq!(state.invalid_peer_keys, [INVALID_KEY]);

        let state = State::from(state);
        assert_eq!(state.peers[0].public_key, PUBKEY);
        assert_eq!(state.peers[0].ip.to_string(), "10.0.0.1");
        assert_eq!(state.invalid_peer_keys, [INVALID_KEY]);
        assert!(LegacyPeerContents::from_peer(&PeerContents {
            name: None,
            ..state.peers[0].clone()
        })
        .is_none());
    }
}
