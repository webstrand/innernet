//! Aligned prefixes of addresses, and the rules that the delegations of a peer follow.

use crate::IpNetExt;
use anyhow::{bail, Error};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    fmt::{self, Display, Formatter},
    net::IpAddr,
    str::FromStr,
};
use wireguard_control::AllowedIp;

/// An aligned prefix of addresses: an address whose host bits are all zero, and a prefix length.
///
/// A prefix parses and deserializes from the form `address/length`, and refuses an address with
/// host bits set, so that the address of a prefix is always its first address. A prefix
/// serializes in the same form. Prefixes are ordered by their first address, IPv4 before IPv6,
/// then by their length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Prefix(IpNet);

/// The error of a prefix that is not valid: one that does not parse, or one whose address has
/// host bits set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefixError(String);

impl Display for PrefixError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PrefixError {}

impl Prefix {
    /// The prefix `net`, which must have no host bits set.
    pub fn new(net: IpNet) -> Result<Self, PrefixError> {
        if net.trunc() != net {
            return Err(PrefixError(format!(
                "{net} is not aligned: its address has host bits set, and must be {}",
                net.trunc()
            )));
        }
        Ok(Self(net))
    }

    /// The prefix of the single address `ip`: a `/32` in IPv4, a `/128` in IPv6.
    pub fn host(ip: IpAddr) -> Self {
        Self(IpNet::from(ip))
    }

    /// The prefix as an [`IpNet`], whose address is the first address of the prefix.
    pub fn net(&self) -> IpNet {
        self.0
    }

    /// The first address of the prefix.
    pub fn first(&self) -> IpAddr {
        self.0.network()
    }

    /// The last address of the prefix.
    pub fn last(&self) -> IpAddr {
        self.0.broadcast()
    }

    pub fn prefix_len(&self) -> u8 {
        self.0.prefix_len()
    }

    /// Whether the prefix holds a single address.
    pub fn is_host(&self) -> bool {
        self.0.prefix_len() == self.0.max_prefix_len()
    }

    /// Whether the prefix holds the address `ip`.
    pub fn contains_addr(&self, ip: &IpAddr) -> bool {
        self.0.contains(ip)
    }

    /// Whether the prefix holds every address of `other`.
    pub fn contains(&self, other: &Prefix) -> bool {
        self.0.contains(&other.0)
    }

    /// Whether the prefix and `other` share an address. Two aligned prefixes share an address
    /// only if one contains the other.
    pub fn overlaps(&self, other: &Prefix) -> bool {
        self.contains(other) || other.contains(self)
    }

    /// The prefix as a WireGuard allowed IP, which routes the prefix to a peer.
    pub fn allowed_ip(&self) -> AllowedIp {
        AllowedIp {
            address: self.first(),
            cidr: self.prefix_len(),
        }
    }
}

impl Ord for Prefix {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.first(), self.prefix_len()).cmp(&(other.first(), other.prefix_len()))
    }
}

impl PartialOrd for Prefix {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for Prefix {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for Prefix {
    type Err = PrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let net = s
            .parse::<IpNet>()
            .map_err(|_| PrefixError(format!("{s:?} is not a prefix such as 10.42.1.0/24")))?;
        Self::new(net)
    }
}

impl TryFrom<String> for Prefix {
    type Error = PrefixError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<Prefix> for String {
    fn from(prefix: Prefix) -> Self {
        prefix.to_string()
    }
}

impl From<Prefix> for IpNet {
    fn from(prefix: Prefix) -> Self {
        prefix.0
    }
}

/// The hosts fallback address of a peer whose delegations are `delegations`: the lowest address
/// of all of them, or `None` for a peer without a delegation. The name of the peer resolves to
/// this address, and the view of plain-HTTP sessions gives it as the peer's IP.
///
/// Delegations hold neither network nor broadcast addresses, so the lowest address of a
/// delegation is an address that a peer can use as its own.
pub fn hosts_fallback(delegations: &[Prefix]) -> Option<IpAddr> {
    delegations.iter().map(Prefix::first).min()
}

/// The smallest of `cidrs` that holds `prefix`, which may be `prefix` itself. Aligned prefixes
/// either nest or share no address, so the CIDRs that hold a prefix form a chain, and the smallest
/// of them is the one with the longest prefix.
pub fn smallest_cidr_holding(prefix: &Prefix, cidrs: &[Prefix]) -> Option<Prefix> {
    cidrs
        .iter()
        .filter(|cidr| cidr.contains(prefix))
        .max_by_key(|cidr| cidr.prefix_len())
        .copied()
}

/// The parent of the CIDR `cidr` among `cidrs`: the smallest of them that holds it, other than
/// itself, or `None` for a CIDR that no other holds, such as the root of the network.
pub fn parent_cidr(cidr: &Prefix, cidrs: &[Prefix]) -> Option<Prefix> {
    cidrs
        .iter()
        .filter(|other| *other != cidr && other.contains(cidr))
        .max_by_key(|other| other.prefix_len())
        .copied()
}

/// The CIDR of a peer whose delegations are `delegations`, among `cidrs`: the smallest CIDR that
/// holds them all, or `None` for a peer without a delegation, or one whose delegations no CIDR
/// holds. A peer whose delegations follow the rules of [`check_delegations`] has its delegations
/// all in this CIDR, which has no child CIDR.
pub fn cidr_of_delegations(delegations: &[Prefix], cidrs: &[Prefix]) -> Option<Prefix> {
    if delegations.is_empty() {
        return None;
    }
    cidrs
        .iter()
        .filter(|cidr| {
            delegations
                .iter()
                .all(|delegation| cidr.contains(delegation))
        })
        .max_by_key(|cidr| cidr.prefix_len())
        .copied()
}

/// Checks that a peer may hold `delegations` together, in the network whose CIDRs are `cidrs`,
/// while `others`, each with the name by which an error names its holder, are delegated to other
/// peers. Returns the CIDR of the peer, which its delegations determine, or `None` for a peer
/// without a delegation.
///
/// The delegations of a peer all lie within one CIDR, the smallest CIDR that holds each of them,
/// and that CIDR must have no child CIDR, since peers belong only to CIDRs without children. The
/// first and last addresses of each delegation must be assignable in the CIDR, so that a
/// delegation never holds the network or broadcast address of the CIDR. No two delegations may
/// share an address, whether they are delegated to the same peer or not.
///
/// That a peer's delegations lie in one CIDR is a rule of this check, rather than a property of
/// the server's schema, so that it can be lifted for peers that span CIDRs.
pub fn check_delegations<'a>(
    delegations: &[Prefix],
    cidrs: &[Prefix],
    others: impl IntoIterator<Item = (&'a Prefix, &'a str)>,
) -> Result<Option<Prefix>, Error> {
    let mut peer_cidr: Option<(Prefix, Prefix)> = None;
    for prefix in delegations {
        let Some(cidr) = smallest_cidr_holding(prefix, cidrs) else {
            bail!("{prefix} is outside every CIDR");
        };
        match peer_cidr {
            Some((first, first_cidr)) if first_cidr != cidr => bail!(
                "{first} lies in the CIDR {first_cidr} and {prefix} in the CIDR {cidr}, but the \
                 delegations of a peer all lie in one CIDR"
            ),
            Some(_) => {},
            None => peer_cidr = Some((*prefix, cidr)),
        }
    }
    let Some((_, cidr)) = peer_cidr else {
        return Ok(None);
    };
    if let Some(child) = cidrs
        .iter()
        .find(|other| parent_cidr(other, cidrs) == Some(cidr))
    {
        bail!(
            "the CIDR {cidr} has a child CIDR, {child}, and peers belong only to CIDRs without \
             children"
        );
    }
    let net = cidr.net();
    for (i, prefix) in delegations.iter().enumerate() {
        if !net.is_assignable(&prefix.first()) || !net.is_assignable(&prefix.last()) {
            bail!("{prefix} includes the network or broadcast address of the CIDR {cidr}");
        }
        if let Some(other) = delegations[..i].iter().find(|other| other.overlaps(prefix)) {
            bail!("{prefix} overlaps {other}, another of the delegations");
        }
    }
    for (other, holder) in others {
        if let Some(prefix) = delegations.iter().find(|prefix| prefix.overlaps(other)) {
            bail!("{prefix} overlaps {other}, which is delegated to {holder}");
        }
    }
    Ok(Some(cidr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    #[test]
    fn test_parse() {
        assert_eq!(
            prefix("10.0.0.32/28").net(),
            "10.0.0.32/28".parse().unwrap()
        );
        assert_eq!(prefix("10.0.0.32/28").first().to_string(), "10.0.0.32");
        assert_eq!(prefix("10.0.0.32/28").last().to_string(), "10.0.0.47");
        assert_eq!(prefix("fd00::/120").last().to_string(), "fd00::ff");
        assert!(prefix("10.0.0.7/32").is_host());
        assert!(!prefix("10.0.0.6/31").is_host());
        assert_eq!(
            Prefix::host("fd00::1".parse().unwrap()),
            prefix("fd00::1/128")
        );

        // An address with host bits set, or anything that isn't a prefix, is refused.
        for invalid in ["10.0.0.33/28", "fd00::1/120", "10.0.0.1", "", "10.0.0.0/33"] {
            assert!(invalid.parse::<Prefix>().is_err(), "{invalid}");
        }
        let error = "10.0.0.33/28".parse::<Prefix>().unwrap_err().to_string();
        assert!(error.contains("10.0.0.32/28"), "{error}");
    }

    #[test]
    fn test_serde() {
        use serde::de::{
            value::{Error, StrDeserializer},
            IntoDeserializer,
        };
        let deserialize =
            |s: &'static str| Prefix::deserialize::<StrDeserializer<Error>>(s.into_deserializer());
        assert_eq!(deserialize("10.0.0.32/28").unwrap(), prefix("10.0.0.32/28"));
        assert!(deserialize("10.0.0.33/28").is_err());
        assert_eq!(String::from(prefix("fd00::/120")), "fd00::/120");
    }

    #[test]
    fn test_order_and_overlap() {
        let mut prefixes = vec![
            prefix("fd00::/120"),
            prefix("10.0.0.32/28"),
            prefix("10.0.0.32/27"),
            prefix("10.0.0.7/32"),
        ];
        prefixes.sort();
        assert_eq!(
            prefixes,
            [
                prefix("10.0.0.7/32"),
                prefix("10.0.0.32/27"),
                prefix("10.0.0.32/28"),
                prefix("fd00::/120"),
            ]
        );
        assert!(prefix("10.0.0.32/27").overlaps(&prefix("10.0.0.40/29")));
        assert!(prefix("10.0.0.40/29").overlaps(&prefix("10.0.0.32/27")));
        assert!(!prefix("10.0.0.32/28").overlaps(&prefix("10.0.0.48/28")));
        assert!(!prefix("10.0.0.0/8").overlaps(&prefix("::/0")));
        assert!(prefix("10.0.0.32/28").contains_addr(&"10.0.0.47".parse().unwrap()));
        assert!(!prefix("10.0.0.32/28").contains_addr(&"10.0.0.48".parse().unwrap()));
        assert_eq!(
            prefix("10.0.0.32/28").allowed_ip(),
            "10.0.0.32/28".parse::<AllowedIp>().unwrap()
        );
    }

    #[test]
    fn test_hosts_fallback() {
        assert_eq!(hosts_fallback(&[]), None);
        // The lowest address of all the delegations, IPv4 before IPv6.
        let delegations = [
            prefix("fd00::/120"),
            prefix("10.0.0.32/28"),
            prefix("10.0.0.7/32"),
        ];
        assert_eq!(
            hosts_fallback(&delegations),
            Some("10.0.0.7".parse().unwrap())
        );
        assert_eq!(
            hosts_fallback(&[prefix("fd00::1:0/112"), prefix("fd00::2/128")]),
            Some("fd00::2".parse().unwrap())
        );
    }

    #[test]
    fn test_cidr_tree() {
        let cidrs = [
            prefix("10.0.0.0/16"),
            prefix("10.0.1.0/24"),
            prefix("10.0.1.0/26"),
            prefix("fd00::/64"),
        ];
        assert_eq!(parent_cidr(&cidrs[0], &cidrs), None);
        assert_eq!(parent_cidr(&cidrs[1], &cidrs), Some(cidrs[0]));
        assert_eq!(parent_cidr(&cidrs[2], &cidrs), Some(cidrs[1]));
        assert_eq!(parent_cidr(&cidrs[3], &cidrs), None);
        assert_eq!(
            smallest_cidr_holding(&prefix("10.0.1.7/32"), &cidrs),
            Some(cidrs[2])
        );
        assert_eq!(
            smallest_cidr_holding(&prefix("10.0.1.0/24"), &cidrs),
            Some(cidrs[1])
        );
        assert_eq!(smallest_cidr_holding(&prefix("10.1.0.0/32"), &cidrs), None);
        assert_eq!(
            cidr_of_delegations(&[prefix("10.0.1.7/32"), prefix("10.0.1.64/26")], &cidrs),
            Some(cidrs[1])
        );
        assert_eq!(cidr_of_delegations(&[], &cidrs), None);
    }

    #[test]
    fn test_check_delegation() {
        let cidr = prefix("10.0.0.0/24");
        let cidrs = [prefix("10.0.0.0/8"), cidr];
        let others = [
            (prefix("10.0.0.1/32"), "peer1"),
            (prefix("10.0.0.32/28"), "peer1"),
            (prefix("10.0.0.2/32"), "peer2"),
        ];
        let others = || others.iter().map(|(prefix, holder)| (prefix, *holder));
        let check = |delegations: &[&str]| {
            let delegations: Vec<Prefix> = delegations.iter().map(|d| prefix(d)).collect();
            check_delegations(&delegations, &cidrs, others())
        };

        // The CIDR of the delegations is returned.
        assert_eq!(check(&[]).unwrap(), None);
        assert_eq!(check(&["10.0.0.64/28"]).unwrap(), Some(cidr));
        assert!(check(&["10.0.0.3/32", "10.0.0.64/28"]).is_ok());
        assert!(check(&["10.0.0.254/32"]).is_ok());
        for (delegations, reason) in [
            (&["10.0.1.0/28"][..], "has a child CIDR"),
            (&["fd00::/120"], "outside every CIDR"),
            (&["10.0.0.0/23"], "has a child CIDR"),
            (&["10.0.0.3/32", "10.0.1.0/28"], "lie in one CIDR"),
            (&["11.0.0.0/24"], "outside every CIDR"),
            (&["10.0.0.0/32"], "network or broadcast"),
            (&["10.0.0.240/28"], "network or broadcast"),
            (&["10.0.0.0/24"], "network or broadcast"),
            (&["10.0.0.0/30"], "network or broadcast"),
            (&["10.0.0.2/32"], "delegated to peer2"),
            (&["10.0.0.2/31"], "delegated to peer"),
            (&["10.0.0.32/28"], "overlaps 10.0.0.32/28"),
            (&["10.0.0.40/29"], "overlaps 10.0.0.32/28"),
            (&["10.0.0.32/27"], "overlaps 10.0.0.32/28"),
            (
                &["10.0.0.64/28", "10.0.0.66/32"],
                "another of the delegations",
            ),
            (
                &["10.0.0.64/28", "10.0.0.64/28"],
                "another of the delegations",
            ),
        ] {
            let error = check(delegations).unwrap_err().to_string();
            assert!(error.contains(reason), "{delegations:?}: {error}");
        }

        // A CIDR of one or two addresses has neither a network nor a broadcast address.
        let cidrs = [prefix("10.0.0.1/32")];
        assert!(check_delegations(&[prefix("10.0.0.1/32")], &cidrs, []).is_ok());
        let cidrs = [prefix("10.0.0.2/31")];
        assert!(check_delegations(&[prefix("10.0.0.2/31")], &cidrs, []).is_ok());

        // In IPv6, only the network address is unassignable.
        let cidrs = [prefix("fd00::/112")];
        let check = |delegation: &str| check_delegations(&[prefix(delegation)], &cidrs, []);
        assert!(check("fd00::ffff/128").is_ok());
        assert!(check("fd00::ff00/120").is_ok());
        assert!(check("fd00::/128").is_err());
        assert!(check("fd00::/120").is_err());
    }
}
