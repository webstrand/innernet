use crate::{announcement::SignedAnnouncement, wg::PeerInfoExt, IpNetExt, DEFAULT_HOSTS_PATH};
use anyhow::{anyhow, bail, Error};
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

    /// Returns the endpoint with its host replaced by `host`'s, keeping the port.
    pub fn with_host_of(&self, host: &Endpoint) -> Self {
        Self {
            host: host.host.clone(),
            port: self.port,
        }
    }

    /// Whether the host is an IPv4 address that is routable on the public internet.
    pub fn is_public_ipv4(&self) -> bool {
        let Host::Ipv4(ip) = self.host else {
            return false;
        };
        let [a, b, ..] = ip.octets();
        !(ip.is_unspecified()
            || ip.is_loopback()
            || ip.is_private()
            || ip.is_link_local()
            || ip.is_broadcast()
            || ip.is_documentation()
            || ip.is_multicast()
            || (a == 100 && (64..128).contains(&b)) // Shared address space (CGNAT)
            || a >= 240)
    }

    /// Appends the canonical encoding used in signed announcements.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        match &self.host {
            Host::Ipv4(ip) => {
                out.push(4);
                out.extend_from_slice(&ip.octets());
            },
            Host::Ipv6(ip) => {
                out.push(6);
                out.extend_from_slice(&ip.octets());
            },
            Host::Domain(domain) => {
                out.push(b'D');
                out.extend_from_slice(&(domain.len() as u16).to_le_bytes());
                out.extend_from_slice(domain.as_bytes());
            },
        }
        out.extend_from_slice(&self.port.to_le_bytes());
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
pub struct DeleteForgetPeerOpts {
    /// Name of the peer to delete/forget
    #[clap(long)]
    pub name: Option<Hostname>,

    /// Bypasses confirmation
    #[clap(long, requires("name"))]
    pub yes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct AddDeleteDelegationOpts {
    /// Name of the peer the prefix is delegated to
    #[clap(long)]
    pub name: Option<Hostname>,

    /// The prefix, within the peer's CIDR (eg. '10.42.1.32/28', or '10.42.1.40/32' for a
    /// single address)
    #[clap(long)]
    pub prefix: Option<IpNet>,

    /// Bypass confirmation
    #[clap(long)]
    pub yes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct ForgetDelegationOpts {
    /// The delegated prefix to forget (eg. '10.42.1.32/28')
    #[clap(long)]
    pub prefix: Option<IpNet>,

    /// Bypasses confirmation
    #[clap(long, requires("prefix"))]
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

    #[clap(long, default_value = "10m")]
    /// How far ahead of this machine's clock a peer's signed announcement may be
    /// dated. Announcements dated further ahead are ignored until they are near enough. Must
    /// comfortably exceed 37s, the difference between TAI and UTC, plus any clock skew.
    pub max_clock_ahead: Timestring,
}

impl NatOpts {
    pub fn all_disabled() -> Self {
        Self {
            no_nat_traversal: true,
            exclude_nat_candidates: vec![],
            no_nat_candidates: true,
            max_clock_ahead: "10m".parse().unwrap(),
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
    /// The path to write hosts to
    #[clap(long = "hosts-path", default_value = DEFAULT_HOSTS_PATH)]
    pub hosts_path: PathBuf,

    /// Don't write to any hosts files
    #[clap(long = "no-write-hosts", conflicts_with = "hosts_path")]
    pub no_write_hosts: bool,

    /// Use a different suffix for hosts, than 'INTERFACE.wg' , ex.
    /// --host-suffix 'evilnet' names peers: PEER.evilnet, and
    /// --host-suffix '' gives peers no suffix, just: PEER
    #[clap(long = "host-suffix")]
    pub host_suffix: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PeerContents {
    /// The name of the peer. A peer without a name, or whose name is invalid, has `None`.
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
    /// The endpoints the peer announced, signed with its own key. Recipients that have once
    /// verified one for a peer disregard `endpoint` and `candidates` from then on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub announcement: Option<SignedAnnouncement>,
    /// The endpoint the server last observed the peer's WireGuard traffic coming from, which
    /// recipients only use if the peer's announcement allows it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_endpoint: Option<Endpoint>,
    /// Aligned prefixes of the peer's CIDR routed to the peer besides `ip`, as if each of their
    /// addresses were a peer with the same key. `ip` remains the peer's own address, the only
    /// one by which it is known to the server and its name resolves.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegations: Vec<IpNet>,
}

impl PeerContents {
    /// The parts of the peer's delegations that its announcement accepts traffic for: each
    /// announced prefix that lies within one of its delegations. Other announced prefixes are
    /// disregarded, and a peer without an announcement accepts traffic for none of its
    /// delegations.
    pub fn announced_delegations(&self) -> Vec<IpNet> {
        let Some(announcement) = &self.announcement else {
            return vec![];
        };
        let mut announced: Vec<IpNet> = vec![];
        for prefix in &announcement.announcement.delegations {
            let prefix = prefix.trunc();
            if self.delegations.iter().any(|d| d.contains(&prefix)) && !announced.contains(&prefix)
            {
                announced.push(prefix);
            }
        }
        announced
    }

    /// The nameserver that the peer announces, if it is reachable through the peer and its zone
    /// is a canonical domain name: at the peer's own address, or within the parts of its
    /// delegations that it announces.
    pub fn announced_dns(&self) -> Option<&crate::announcement::DnsAnnouncement> {
        let dns = self.announcement.as_ref()?.announcement.dns.as_ref()?;
        let address = dns.nameserver.ip();
        let is_reachable = address == self.ip
            || self
                .announced_delegations()
                .iter()
                .any(|prefix| prefix.contains(&address));
        (is_reachable && innernet_domain::is_canonical_domain(&dns.zone)).then_some(dns)
    }

    /// The prefixes WireGuard routes to the peer: its own address, then the parts of its
    /// delegations that it announces.
    pub fn allowed_ips(&self) -> Vec<AllowedIp> {
        std::iter::once(IpNet::from(self.ip))
            .chain(self.announced_delegations())
            .map(|net| AllowedIp {
                address: net.network(),
                cidr: net.prefix_len(),
            })
            .collect()
    }
}

/// Checks that `prefix` can be delegated to `peer`, whose CIDR is `cidr`, given all the peers of
/// the network, disabled and unredeemed ones included since they still hold their addresses.
///
/// A delegation must be what the addresses of that many peers in `cidr` would be: an aligned
/// prefix of assignable addresses that no peer's address or other delegation overlaps.
pub fn check_delegation(
    prefix: &IpNet,
    peer: &Peer,
    cidr: &IpNet,
    peers: &[Peer],
) -> Result<(), Error> {
    if prefix.trunc() != *prefix {
        bail!(
            "{prefix} is not aligned, its address must be {}",
            prefix.trunc()
        );
    }
    if !cidr.contains(prefix) {
        bail!("{prefix} is outside {}'s CIDR {cidr}", peer.display_name());
    }
    if !cidr.is_assignable(&prefix.network()) || !cidr.is_assignable(&prefix.broadcast()) {
        bail!("{prefix} includes the network or broadcast address of {cidr}");
    }
    let overlaps = |other: &IpNet| other.contains(prefix) || prefix.contains(other);
    for other in peers {
        if prefix.contains(&other.ip) {
            bail!(
                "{prefix} includes the address of peer {}",
                other.display_name()
            );
        }
        if let Some(delegation) = other.delegations.iter().find(|d| overlaps(d)) {
            bail!(
                "{prefix} overlaps {delegation}, delegated to peer {}",
                other.display_name()
            );
        }
    }
    Ok(())
}

impl PeerContents {
    /// The public key of the peer in the URL-safe base64 alphabet, padding included, by which a
    /// path of the admin API names the peer.
    pub fn api_path_segment(&self) -> String {
        self.public_key.replace('+', "-").replace('/', "_")
    }

    /// The name of the peer for display, or "[unnamed]" if it has none.
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or("[unnamed]")
    }
}

/// Deserializes a peer name, so that an invalid name becomes `None` rather than failing the
/// deserialization of the peer, and of every peer alongside it.
fn deserialize_peer_name<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Hostname>, D::Error> {
    let Some(name) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };
    match Hostname::try_from(name) {
        Ok(name) => Ok(Some(name)),
        Err(e) => {
            log::warn!("treating peer as unnamed: {e}");
            Ok(None)
        },
    }
}

/// Deserializes a WireGuard public key, refusing an invalid key and normalizing a valid one to its
/// canonical base64 encoding, so that public keys can be compared as strings.
fn deserialize_public_key<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let public_key = String::deserialize(deserializer)?;
    Key::from_base64(&public_key)
        .map(|key| key.to_base64())
        .map_err(|_| de::Error::custom(format!("invalid public key {public_key:?}")))
}

/// The endpoint and candidates stored for a peer, the body of `GET` and
/// `PUT /admin/peers/{peer}/endpoints`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PeerEndpoints {
    pub endpoint: Option<Endpoint>,
    #[serde(default)]
    pub candidates: Vec<Endpoint>,
}

/// The body of `POST /admin/peers/delegations/{peer}`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DelegationContents {
    pub prefix: IpNet,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Peer {
    pub id: i64,

    #[serde(flatten)]
    pub contents: PeerContents,
}

impl AsRef<Peer> for Peer {
    fn as_ref(&self) -> &Peer {
        self
    }
}

impl Deref for Peer {
    type Target = PeerContents;

    fn deref(&self) -> &Self::Target {
        &self.contents
    }
}

impl DerefMut for Peer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.contents
    }
}

impl Display for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.display_name(), self.public_key)
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
    pub new: Option<&'a Peer>,
    builder: PeerConfigBuilder,
    changes: Vec<PeerChange>,
}

impl<'a> PeerDiff<'a> {
    /// `endpoint_override`, if any, replaces the endpoint of `new`.
    pub fn new(
        old_info: Option<&'a PeerInfo>,
        new: Option<&'a Peer>,
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
        new: Option<&Peer>,
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

impl From<&Peer> for PeerConfigBuilder {
    fn from(peer: &Peer) -> Self {
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
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct State {
    /// This list will be only the peers visible to the user requesting this
    /// information, not including disabled peers or peers from other CIDRs
    /// that the user's CIDR is not authorized to communicate with.
    pub peers: Vec<Peer>,

    /// At the moment, this is all CIDRs, regardless of whether the peer is
    /// eligible to communicate with them or not.
    pub cidrs: Vec<Cidr>,
}

/// This model is sent as a response to the /capabilities endpoint.
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct ServerCapabilities {
    #[serde(default)]
    pub unspecified_ip_in_override_endpoint: bool,
    /// Whether the server supports `DELETE /admin/peers/permanent/{peer}`.
    #[serde(default)]
    pub permanent_peer_delete: bool,
    /// Whether the server supports `PUT /user/announcement`.
    #[serde(default)]
    pub signed_announcements: bool,
    /// Whether the server supports `POST /admin/peers/delegations/{peer}` and
    /// `DELETE /admin/peers/delegations/{peer}/{prefix}`.
    #[serde(default)]
    pub delegations: bool,
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

/// The name of a peer. The hosts file names the peer by this name, followed by the host suffix
/// unless the operator sets an empty one.
///
/// A parsed or deserialized name must match [`Hostname::is_valid`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Hostname(String);

impl Hostname {
    /// Whether `name` is a canonical relative domain, which may contain dots and may be a number,
    /// since a suffix usually follows it in the hosts file.
    pub fn is_valid(name: &str) -> bool {
        innernet_domain::is_canonical_relative_domain(name)
    }
}

impl FromStr for Hostname {
    type Err = &'static str;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        if Self::is_valid(name) {
            Ok(Self(name.to_string()))
        } else {
            Err("invalid hostname string (only lowercase alphanumeric with dashes and dots)")
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
    fn test_peer_no_diff() {
        const PUBKEY: &str = "4CNZorWVtohO64n6AAaH/JyFjIIgBFrfJK2SGtKjzEE=";
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let peer = Peer {
            id: 1,
            contents: PeerContents {
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
                announcement: None,
                observed_endpoint: None,
                delegations: vec![],
            },
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
        let peer = Peer {
            id: 1,
            contents: PeerContents {
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
                announcement: None,
                observed_endpoint: None,
                delegations: vec![],
            },
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
        let peer = Peer {
            id: 1,
            contents: PeerContents {
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
                announcement: None,
                observed_endpoint: None,
                delegations: vec![],
            },
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
        let peer = Peer {
            id: 1,
            contents: PeerContents {
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
                announcement: None,
                observed_endpoint: None,
                delegations: vec![],
            },
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
    fn test_deserialize_hostname() {
        use serde::de::value::{Error, StrDeserializer};
        let deserialize = |name| Hostname::deserialize(StrDeserializer::<Error>::new(name));

        assert_eq!(*deserialize("peer-1").unwrap(), *"peer-1");
        // A suffix usually follows a peer name, so it may contain dots and be a number.
        assert_eq!(*deserialize("08").unwrap(), *"08");
        assert_eq!(*deserialize("a.b").unwrap(), *"a.b");
        assert_eq!("a.08".parse::<Hostname>(), Ok(deserialize("a.08").unwrap()));
        assert!(deserialize("").is_err());
        assert!(deserialize("Peer").is_err());
        assert!(deserialize("peer\n10.0.0.1 example.com").is_err());
        assert!(deserialize(&"a".repeat(64)).is_err());
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
    fn test_deserialize_peer_name() {
        #[derive(Deserialize)]
        struct Named {
            #[serde(default, deserialize_with = "deserialize_peer_name")]
            name: Option<Hostname>,
        }
        let deserialize = |toml| toml::from_str::<Named>(toml).unwrap().name;

        assert_eq!(
            deserialize(r#"name = "peer-1""#),
            Some("peer-1".parse().unwrap())
        );
        // A missing or invalid name makes the peer unnamed, rather than failing.
        assert_eq!(deserialize(""), None);
        assert_eq!(deserialize(r#"name = "Peer""#), None);
        assert_eq!(deserialize(r#"name = "peer\n10.0.0.1 example.com""#), None);
    }

    fn peer_with(name: &str, ip: &str, delegations: &[&str]) -> Peer {
        Peer {
            id: 1,
            contents: PeerContents {
                name: Some(name.parse().unwrap()),
                ip: ip.parse().unwrap(),
                cidr_id: 1,
                public_key: Key::generate_private().get_public().to_base64(),
                endpoint: None,
                persistent_keepalive_interval: None,
                is_admin: false,
                is_disabled: false,
                is_redeemed: true,
                invite_expires: None,
                candidates: vec![],
                announcement: None,
                observed_endpoint: None,
                delegations: delegations.iter().map(|d| d.parse().unwrap()).collect(),
            },
        }
    }

    /// `peer` with an announcement of `prefixes`, unsigned, as only the routing of an accepted
    /// announcement matters here.
    fn announcing(mut peer: Peer, prefixes: &[&str]) -> Peer {
        peer.contents.announcement = Some(crate::announcement::SignedAnnouncement {
            announcement: crate::announcement::Announcement {
                timestamp: 1,
                endpoint: None,
                candidates: vec![],
                allow_observed: false,
                delegations: prefixes.iter().map(|p| p.parse().unwrap()).collect(),
                dns: None,
                extensions: vec![],
            },
            signature: vec![],
        });
        peer
    }

    fn info_with_allowed_ips(peer: &Peer, allowed_ips: &[&str]) -> PeerInfo {
        let allowed_ips: Vec<AllowedIp> =
            allowed_ips.iter().map(|ip| ip.parse().unwrap()).collect();
        let builder = PeerConfigBuilder::new(&Key::from_base64(&peer.public_key).unwrap())
            .add_allowed_ips(&allowed_ips);
        PeerInfo {
            config: builder.into_peer_config(),
            stats: Default::default(),
        }
    }

    #[test]
    fn test_allowed_ips_include_announced_delegations() {
        let allowed_ips =
            |peer: &Peer| PeerConfigBuilder::from(peer).into_peer_config().allowed_ips;
        let ips =
            |ips: &[&str]| -> Vec<AllowedIp> { ips.iter().map(|ip| ip.parse().unwrap()).collect() };
        let peer = peer_with("peer1", "10.0.0.1", &["10.0.0.32/28", "10.0.0.7/32"]);

        // Without an announcement, only the peer's own address is routed.
        assert_eq!(allowed_ips(&peer), ips(&["10.0.0.1/32"]));

        let all = announcing(peer.clone(), &["10.0.0.32/28", "10.0.0.7/32"]);
        assert_eq!(
            allowed_ips(&all),
            ips(&["10.0.0.1/32", "10.0.0.32/28", "10.0.0.7/32"])
        );

        // Parts of a delegation are routed, prefixes beyond the delegations are disregarded,
        // and duplicates are routed once.
        let partial = announcing(
            peer.clone(),
            &[
                "10.0.0.40/29",
                "10.0.0.40/29",
                "10.0.0.32/27",
                "10.0.0.6/31",
                "10.0.0.64/28",
            ],
        );
        assert_eq!(allowed_ips(&partial), ips(&["10.0.0.1/32", "10.0.0.40/29"]));
        assert_eq!(
            partial.announced_delegations(),
            vec!["10.0.0.40/29".parse::<IpNet>().unwrap()]
        );

        let peer = announcing(
            peer_with("peer1", "fd00::1", &["fd00::1:0/112"]),
            &["fd00::1:0/112"],
        );
        let config = PeerConfigBuilder::from(&peer).into_peer_config();
        assert_eq!(
            config.allowed_ips,
            ["fd00::1/128", "fd00::1:0/112"].map(|ip| ip.parse::<AllowedIp>().unwrap())
        );
    }

    #[test]
    fn test_announced_dns() {
        let with_dns = |nameserver: &str, zone: &str| {
            let mut peer = announcing(
                peer_with("peer1", "10.0.0.1", &["10.0.0.32/28"]),
                &["10.0.0.32/29"],
            );
            peer.contents
                .announcement
                .as_mut()
                .unwrap()
                .announcement
                .dns = Some(crate::announcement::DnsAnnouncement {
                nameserver: nameserver.parse().unwrap(),
                zone: zone.into(),
            });
            peer
        };

        // At the peer's own address, or within the announced part of a delegation.
        assert!(with_dns("10.0.0.1:53", "example.com")
            .announced_dns()
            .is_some());
        assert!(with_dns("10.0.0.33:5353", "example.com")
            .announced_dns()
            .is_some());
        // Within a delegation but not its announced part, or outside the peer altogether.
        assert!(with_dns("10.0.0.41:53", "example.com")
            .announced_dns()
            .is_none());
        assert!(with_dns("10.0.0.2:53", "example.com")
            .announced_dns()
            .is_none());
        assert!(with_dns("192.0.2.1:53", "example.com")
            .announced_dns()
            .is_none());
        // A zone that is not a canonical domain name.
        assert!(with_dns("10.0.0.1:53", "Example.com")
            .announced_dns()
            .is_none());
        assert!(with_dns("10.0.0.1:53", "example.com.")
            .announced_dns()
            .is_none());
        assert!(with_dns("10.0.0.1:53", "10.0.0.1")
            .announced_dns()
            .is_none());
        // Without an announcement, or one without a nameserver.
        assert!(peer_with("peer1", "10.0.0.1", &[])
            .announced_dns()
            .is_none());
        assert!(announcing(peer_with("peer1", "10.0.0.1", &[]), &[])
            .announced_dns()
            .is_none());
    }

    #[test]
    fn test_peer_diff_delegations() {
        let peer = announcing(
            peer_with("peer1", "10.0.0.1", &["10.0.0.32/28", "10.0.0.7/32"]),
            &["10.0.0.32/28", "10.0.0.7/32"],
        );

        // The same allowed IPs, listed in another order, are no change.
        let info = info_with_allowed_ips(&peer, &["10.0.0.7/32", "10.0.0.1/32", "10.0.0.32/28"]);
        assert_eq!(PeerDiff::new(Some(&info), Some(&peer), None).unwrap(), None);

        // A delegation added or withdrawn replaces the allowed IPs.
        for allowed_ips in [
            &["10.0.0.1/32", "10.0.0.32/28"][..],
            &["10.0.0.1/32", "10.0.0.32/28", "10.0.0.7/32", "10.0.0.64/28"],
        ] {
            let info = info_with_allowed_ips(&peer, allowed_ips);
            let diff = PeerDiff::new(Some(&info), Some(&peer), None)
                .unwrap()
                .unwrap();
            assert!(matches!(
                diff.changes(),
                [PeerChange::AllowedIPs { new, .. }] if *new == peer.allowed_ips()
            ));
            let config = PeerConfigBuilder::from(diff).into_peer_config();
            assert_eq!(config.allowed_ips, peer.allowed_ips());
        }
    }

    #[test]
    fn test_check_delegation() {
        let cidr: IpNet = "10.0.0.0/24".parse().unwrap();
        let peers = [
            peer_with("peer1", "10.0.0.1", &["10.0.0.32/28"]),
            peer_with("peer2", "10.0.0.2", &[]),
        ];
        let check =
            |prefix: &str| check_delegation(&prefix.parse().unwrap(), &peers[1], &cidr, &peers);

        assert!(check("10.0.0.64/28").is_ok());
        assert!(check("10.0.0.3/32").is_ok());
        assert!(check("10.0.0.254/32").is_ok());
        for (prefix, reason) in [
            ("10.0.0.65/28", "not aligned"),
            ("10.0.1.0/28", "outside"),
            ("fd00::/120", "outside"),
            ("10.0.0.0/23", "outside"),
            ("10.0.0.0/32", "network or broadcast"),
            ("10.0.0.240/28", "network or broadcast"),
            ("10.0.0.0/24", "network or broadcast"),
            ("10.0.0.2/32", "address of peer peer2"),
            ("10.0.0.0/30", "network or broadcast"),
            ("10.0.0.32/28", "overlaps 10.0.0.32/28"),
            ("10.0.0.40/29", "overlaps 10.0.0.32/28"),
            ("10.0.0.32/27", "overlaps 10.0.0.32/28"),
            ("10.0.0.2/31", "address of peer peer2"),
        ] {
            let error = check(prefix).unwrap_err().to_string();
            assert!(error.contains(reason), "{prefix}: {error}");
        }

        // In IPv6, only the network address is unassignable.
        let cidr: IpNet = "fd00::/112".parse().unwrap();
        let peers = [peer_with("peer1", "fd00::1", &[])];
        let check =
            |prefix: &str| check_delegation(&prefix.parse().unwrap(), &peers[0], &cidr, &peers);
        assert!(check("fd00::ffff/128").is_ok());
        assert!(check("fd00::ff00/120").is_ok());
        assert!(check("fd00::/128").is_err());
        assert!(check("fd00::1/128").is_err());
    }
}
