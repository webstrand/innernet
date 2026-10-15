//! Arithmetic on sets of addresses given as prefixes, for selecting the delegated prefixes that a
//! peer announces.

use ipnet::IpNet;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, net::IpAddr, str::FromStr};

/// An entry of a prefix selection: a prefix to include, or one to exclude, written `!prefix`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrefixSelector {
    Include(IpNet),
    Exclude(IpNet),
}

impl PrefixSelector {
    /// The selection of every address, of both families.
    pub fn all() -> Vec<Self> {
        vec![
            Self::Include("0.0.0.0/0".parse().unwrap()),
            Self::Include("::/0".parse().unwrap()),
        ]
    }
}

impl FromStr for PrefixSelector {
    type Err = ipnet::AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.strip_prefix('!') {
            Some(prefix) => Ok(Self::Exclude(prefix.trim().parse()?)),
            None => Ok(Self::Include(s.trim().parse()?)),
        }
    }
}

impl fmt::Display for PrefixSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Include(prefix) => write!(f, "{prefix}"),
            Self::Exclude(prefix) => write!(f, "!{prefix}"),
        }
    }
}

impl Serialize for PrefixSelector {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PrefixSelector {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse()
            .map_err(|_| de::Error::custom(format!("invalid prefix selector {s:?}")))
    }
}

/// The parts of `delegations` that `selection` selects: the addresses within one of the
/// delegations and one of the included prefixes, but within none of the excluded prefixes. The
/// order of `selection` is irrelevant.
///
/// The result is the fewest aligned prefixes that cover those addresses within each delegation,
/// so that each prefix lies within one delegation, and equals it if the whole delegation is
/// selected.
pub fn select(delegations: &[IpNet], selection: &[PrefixSelector]) -> Vec<IpNet> {
    let included: Vec<IpNet> = selection
        .iter()
        .filter_map(|selector| match selector {
            PrefixSelector::Include(prefix) => Some(*prefix),
            PrefixSelector::Exclude(_) => None,
        })
        .collect();
    let excluded: Vec<IpNet> = selection
        .iter()
        .filter_map(|selector| match selector {
            PrefixSelector::Exclude(prefix) => Some(*prefix),
            PrefixSelector::Include(_) => None,
        })
        .collect();

    let mut selected = vec![];
    for delegation in delegations {
        let family = Family::of(delegation);
        let ranges = intersect(&[Range::of(delegation)], &family.ranges(included.iter()));
        let ranges = subtract(&ranges, &family.ranges(excluded.iter()));
        for range in ranges {
            selected.extend(family.prefixes(range));
        }
    }
    selected
}

/// An inclusive range of addresses of one family, as integers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Range {
    start: u128,
    end: u128,
}

impl Range {
    fn of(prefix: &IpNet) -> Self {
        Self {
            start: to_int(prefix.network()),
            end: to_int(prefix.broadcast()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

impl Family {
    fn of(prefix: &IpNet) -> Self {
        match prefix {
            IpNet::V4(_) => Self::V4,
            IpNet::V6(_) => Self::V6,
        }
    }

    fn bits(self) -> u8 {
        match self {
            Self::V4 => 32,
            Self::V6 => 128,
        }
    }

    /// The sorted, disjoint ranges covered by those of `prefixes` of this family.
    fn ranges<'a>(self, prefixes: impl Iterator<Item = &'a IpNet>) -> Vec<Range> {
        let mut ranges: Vec<Range> = prefixes
            .filter(|prefix| Family::of(prefix) == self)
            .map(Range::of)
            .collect();
        ranges.sort();
        let mut merged: Vec<Range> = vec![];
        for range in ranges {
            match merged.last_mut() {
                Some(last) if range.start <= last.end.saturating_add(1) => {
                    last.end = last.end.max(range.end);
                },
                _ => merged.push(range),
            }
        }
        merged
    }

    /// The fewest aligned prefixes that cover `range` exactly.
    fn prefixes(self, range: Range) -> Vec<IpNet> {
        let bits = u32::from(self.bits());
        let mut prefixes = vec![];
        let mut start = range.start;
        loop {
            // The largest block aligned at `start` that doesn't extend past the end.
            let mut size_bits = start.trailing_zeros().min(bits);
            while size_bits > 0 && block_end(start, size_bits) > range.end {
                size_bits -= 1;
            }
            let prefix_len = (bits - size_bits) as u8;
            let address = from_int(self, start);
            prefixes.push(IpNet::new(address, prefix_len).expect("prefix length within bits"));
            let end = block_end(start, size_bits);
            if end >= range.end {
                break;
            }
            start = end + 1;
        }
        prefixes
    }
}

/// The last address of the block of `2^size_bits` addresses starting at `start`.
fn block_end(start: u128, size_bits: u32) -> u128 {
    if size_bits >= 128 {
        u128::MAX
    } else {
        start + ((1u128 << size_bits) - 1)
    }
}

fn to_int(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(address) => u128::from(u32::from(address)),
        IpAddr::V6(address) => u128::from(address),
    }
}

fn from_int(family: Family, value: u128) -> IpAddr {
    match family {
        Family::V4 => IpAddr::V4((value as u32).into()),
        Family::V6 => IpAddr::V6(value.into()),
    }
}

/// The ranges covered by both `a` and `b`, both sorted and disjoint.
fn intersect(a: &[Range], b: &[Range]) -> Vec<Range> {
    let mut out = vec![];
    for x in a {
        for y in b {
            let start = x.start.max(y.start);
            let end = x.end.min(y.end);
            if start <= end {
                out.push(Range { start, end });
            }
        }
    }
    out.sort();
    out
}

/// The ranges covered by `a` but not by `b`, both sorted and disjoint.
fn subtract(a: &[Range], b: &[Range]) -> Vec<Range> {
    let mut out = vec![];
    for x in a {
        let mut start = x.start;
        let mut exhausted = false;
        for y in b {
            if y.end < start || y.start > x.end {
                continue;
            }
            if y.start > start {
                out.push(Range {
                    start,
                    end: y.start - 1,
                });
            }
            if y.end >= x.end {
                exhausted = true;
                break;
            }
            start = y.end + 1;
        }
        if !exhausted {
            out.push(Range { start, end: x.end });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(prefixes: &[&str]) -> Vec<IpNet> {
        prefixes.iter().map(|p| p.parse().unwrap()).collect()
    }

    fn selection(selectors: &[&str]) -> Vec<PrefixSelector> {
        selectors.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn test_parse_and_display() {
        assert_eq!(
            "10.0.0.0/8".parse::<PrefixSelector>().unwrap(),
            PrefixSelector::Include("10.0.0.0/8".parse().unwrap())
        );
        assert_eq!(
            "!fd00::/64".parse::<PrefixSelector>().unwrap(),
            PrefixSelector::Exclude("fd00::/64".parse().unwrap())
        );
        assert!("10.0.0.1".parse::<PrefixSelector>().is_err());
        assert!("!".parse::<PrefixSelector>().is_err());
        for s in ["10.0.0.0/8", "!fd00::/64"] {
            assert_eq!(s.parse::<PrefixSelector>().unwrap().to_string(), s);
        }
    }

    #[test]
    fn test_all_selects_every_delegation() {
        let delegations = nets(&["10.0.0.32/28", "10.0.0.48/28", "fd00::1:0/112"]);
        assert_eq!(select(&delegations, &PrefixSelector::all()), delegations);
        // Adjacent delegations aren't merged into a prefix that neither contains.
        assert!(!select(&delegations, &PrefixSelector::all())
            .contains(&"10.0.0.32/27".parse().unwrap()));
    }

    #[test]
    fn test_nothing_selected() {
        let delegations = nets(&["10.0.0.32/28"]);
        assert_eq!(select(&delegations, &[]), vec![]);
        assert_eq!(select(&delegations, &selection(&["!10.0.0.0/8"])), vec![]);
        assert_eq!(select(&delegations, &selection(&["10.1.0.0/16"])), vec![]);
        // A family without delegations selects nothing.
        assert_eq!(select(&delegations, &selection(&["::/0"])), vec![]);
        assert_eq!(select(&[], &PrefixSelector::all()), vec![]);
    }

    #[test]
    fn test_included_part_of_a_delegation() {
        let delegations = nets(&["10.0.0.32/28"]);
        assert_eq!(
            select(&delegations, &selection(&["10.0.0.40/29"])),
            nets(&["10.0.0.40/29"])
        );
        // An included prefix larger than the delegation is cut down to it.
        assert_eq!(
            select(&delegations, &selection(&["10.0.0.0/24"])),
            nets(&["10.0.0.32/28"])
        );
    }

    #[test]
    fn test_exclusion() {
        let delegations = nets(&["10.0.0.32/28"]);
        assert_eq!(
            select(&delegations, &selection(&["0.0.0.0/0", "!10.0.0.42/31"])),
            nets(&["10.0.0.32/29", "10.0.0.40/31", "10.0.0.44/30"])
        );
        assert_eq!(
            select(&delegations, &selection(&["0.0.0.0/0", "!10.0.0.32/32"])),
            nets(&[
                "10.0.0.33/32",
                "10.0.0.34/31",
                "10.0.0.36/30",
                "10.0.0.40/29"
            ])
        );
        assert_eq!(
            select(&delegations, &selection(&["0.0.0.0/0", "!10.0.0.47/32"])),
            nets(&[
                "10.0.0.32/29",
                "10.0.0.40/30",
                "10.0.0.44/31",
                "10.0.0.46/32"
            ])
        );
    }

    #[test]
    fn test_order_is_irrelevant() {
        let delegations = nets(&["10.0.0.32/28", "fd00::1:0/112"]);
        let a = selection(&[
            "!10.0.0.40/29",
            "0.0.0.0/0",
            "fd00::1:0/113",
            "!fd00::1:10/124",
        ]);
        let mut b = a.clone();
        b.reverse();
        assert_eq!(select(&delegations, &a), select(&delegations, &b));
    }

    #[test]
    fn test_overlapping_selectors() {
        let delegations = nets(&["10.0.0.32/28"]);
        assert_eq!(
            select(
                &delegations,
                &selection(&[
                    "10.0.0.32/29",
                    "10.0.0.36/30",
                    "10.0.0.40/30",
                    "!10.0.0.33/32",
                    "!10.0.0.32/31"
                ])
            ),
            nets(&["10.0.0.34/31", "10.0.0.36/30", "10.0.0.40/30"])
        );
    }

    #[test]
    fn test_ipv6() {
        let delegations = nets(&["fd00::1:0/112"]);
        assert_eq!(
            select(&delegations, &selection(&["::/0", "!fd00::1:8000/113"])),
            nets(&["fd00::1:0/113"])
        );
        assert_eq!(
            select(&delegations, &selection(&["::/0", "!fd00::1:1/128"])),
            nets(&[
                "fd00::1:0/128",
                "fd00::1:2/127",
                "fd00::1:4/126",
                "fd00::1:8/125",
                "fd00::1:10/124",
                "fd00::1:20/123",
                "fd00::1:40/122",
                "fd00::1:80/121",
                "fd00::1:100/120",
                "fd00::1:200/119",
                "fd00::1:400/118",
                "fd00::1:800/117",
                "fd00::1:1000/116",
                "fd00::1:2000/115",
                "fd00::1:4000/114",
                "fd00::1:8000/113",
            ])
        );
    }

    #[test]
    fn test_whole_address_space() {
        // The extremes of both families don't overflow.
        assert_eq!(
            select(&nets(&["0.0.0.0/0"]), &PrefixSelector::all()),
            nets(&["0.0.0.0/0"])
        );
        assert_eq!(
            select(&nets(&["::/0"]), &PrefixSelector::all()),
            nets(&["::/0"])
        );
        assert_eq!(
            select(&nets(&["::/0"]), &selection(&["::/0", "!::/1"])),
            nets(&["8000::/1"])
        );
        assert_eq!(
            select(&nets(&["255.255.255.255/32"]), &PrefixSelector::all()),
            nets(&["255.255.255.255/32"])
        );
    }

    #[test]
    fn test_every_result_lies_within_one_delegation() {
        let delegations = nets(&["10.0.0.0/28", "10.0.0.16/28", "10.0.0.64/26", "fd00::/120"]);
        let selection = selection(&[
            "10.0.0.4/30",
            "10.0.0.8/29",
            "10.0.0.16/30",
            "10.0.0.64/27",
            "!10.0.0.70/31",
            "fd00::/121",
        ]);
        let selected = select(&delegations, &selection);
        for prefix in &selected {
            assert!(
                delegations.iter().any(|d| d.contains(prefix)),
                "{prefix} lies within no delegation"
            );
        }
        assert_eq!(
            selected,
            nets(&[
                "10.0.0.4/30",
                "10.0.0.8/29",
                "10.0.0.16/30",
                "10.0.0.64/30",
                "10.0.0.68/31",
                "10.0.0.72/29",
                "10.0.0.80/28",
                "fd00::/121",
            ])
        );
    }
}
