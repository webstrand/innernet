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
/// of all of them, or `None` for a peer without a delegation. The hosts file names the peer at
/// this address, and the view of plain-HTTP sessions gives it as the peer's IP.
///
/// Delegations hold neither network nor broadcast addresses, so the lowest address of a
/// delegation is an address that a peer can use as its own.
pub fn hosts_fallback(delegations: &[Prefix]) -> Option<IpAddr> {
    delegations.iter().map(Prefix::first).min()
}

/// Checks that a peer of the CIDR `cidr` may hold `delegations` together, while `others`, each
/// with the name by which an error names its holder, are delegated to other peers.
///
/// Each delegation must lie within `cidr`, and its first and last addresses must be assignable
/// there, so that a delegation never holds the network or broadcast address of the CIDR. No two
/// delegations may share an address, whether they are delegated to the same peer or not.
pub fn check_delegations<'a>(
    delegations: &[Prefix],
    cidr: &IpNet,
    others: impl IntoIterator<Item = (&'a Prefix, &'a str)>,
) -> Result<(), Error> {
    for (i, prefix) in delegations.iter().enumerate() {
        if !cidr.contains(&prefix.net()) {
            bail!("{prefix} is outside the CIDR {cidr}");
        }
        if !cidr.is_assignable(&prefix.first()) || !cidr.is_assignable(&prefix.last()) {
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
    Ok(())
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
    fn test_check_delegation() {
        let cidr: IpNet = "10.0.0.0/24".parse().unwrap();
        let others = [
            (prefix("10.0.0.1/32"), "peer1"),
            (prefix("10.0.0.32/28"), "peer1"),
            (prefix("10.0.0.2/32"), "peer2"),
        ];
        let others = || others.iter().map(|(prefix, holder)| (prefix, *holder));
        let check = |delegations: &[&str]| {
            let delegations: Vec<Prefix> = delegations.iter().map(|d| prefix(d)).collect();
            check_delegations(&delegations, &cidr, others())
        };

        assert!(check(&[]).is_ok());
        assert!(check(&["10.0.0.64/28"]).is_ok());
        assert!(check(&["10.0.0.3/32", "10.0.0.64/28"]).is_ok());
        assert!(check(&["10.0.0.254/32"]).is_ok());
        for (delegations, reason) in [
            (&["10.0.1.0/28"][..], "outside"),
            (&["fd00::/120"], "outside"),
            (&["10.0.0.0/23"], "outside"),
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
        let cidr: IpNet = "10.0.0.1/32".parse().unwrap();
        assert!(check_delegations(&[prefix("10.0.0.1/32")], &cidr, []).is_ok());
        let cidr: IpNet = "10.0.0.2/31".parse().unwrap();
        assert!(check_delegations(&[prefix("10.0.0.2/31")], &cidr, []).is_ok());

        // In IPv6, only the network address is unassignable.
        let cidr: IpNet = "fd00::/112".parse().unwrap();
        let check = |delegation: &str| check_delegations(&[prefix(delegation)], &cidr, []);
        assert!(check("fd00::ffff/128").is_ok());
        assert!(check("fd00::ff00/120").is_ok());
        assert!(check("fd00::/128").is_err());
        assert!(check("fd00::/120").is_err());
    }
}
