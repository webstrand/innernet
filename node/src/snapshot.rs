//! The output of the node: what it configures, as a snapshot of what its store holds.
//!
//! A [`Snapshot`] is the desired state that the output adapters realize: the peers of the tunnel
//! with what each is routed and where it is reached, the node's own addresses, and the names and
//! zones that the node publishes. The node makes it of what it accepted alone, and never reads
//! what the operating system holds back as truth.

use innernet_shared::{
    announcement::{Announcement, Nameserver},
    PeerContents, Prefix,
};
use std::{collections::BTreeMap, net::IpAddr};

/// How a node configures what it accepted.
#[derive(Clone, Copy, Debug, Default)]
pub struct SnapshotConfig {
    /// Whether the node routes the primary IP of each peer to it besides the allowed IPs that the
    /// peer states, as the coordinator does, so that it reaches every peer at the address at
    /// which its name resolves, whatever the peer states.
    pub route_primary_ip: bool,
}

/// The node itself, as its config describes it.
#[derive(Clone, Copy, Debug)]
pub struct Own<'a> {
    /// The public key of the node, whose peer is its own record.
    pub public_key: &'a str,
    /// The address of the node's interface, which it holds whatever it claims.
    pub address: IpAddr,
    /// Further addresses that the node holds on its interface, each only while it lies within
    /// the delegation that the node claims.
    pub extra: &'a [IpAddr],
}

/// What a node configures: its desired state, which the output adapters realize.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// The peers as they take effect, each with the prefixes that the tunnel routes to it, its
    /// endpoint, the first that it announces, and its candidates, the others in their order. The
    /// tunnel holds the enabled peers that are routed a prefix.
    pub peers: Vec<PeerContents>,
    /// The addresses of the node's own interface: the address of its config first, then those of
    /// its further addresses that lie within the delegation that it claims.
    pub own_addresses: Vec<IpAddr>,
    /// The address of each name that the node publishes: the primary IP of each enabled peer that
    /// claims a name, one that offers a nameserver included.
    pub names: BTreeMap<String, IpAddr>,
    /// The nameserver that each enabled peer that claims a name offers for its name and the names
    /// under it, by that name.
    pub zones: BTreeMap<String, Nameserver>,
}

/// `record`, the node's record of a peer, as it takes effect with `announcement`, the last
/// announcement of the peer that the node accepted, as [`PeerContents::effective_with`] combines
/// them. A peer of which the node accepted no announcement is routed nothing, and has no name.
pub fn effective(record: &PeerContents, announcement: Option<&Announcement>) -> PeerContents {
    let none = Announcement::default();
    record.effective_with(Some(announcement.unwrap_or(&none)))
}

/// `peer`, as it takes effect, with its primary IP routed to it besides its allowed IPs, as the
/// coordinator routes it.
pub fn with_primary_ip(peer: &PeerContents) -> PeerContents {
    let mut allowed_ips = peer.allowed_ips.clone().unwrap_or(peer.delegations.clone());
    if let Some(primary_ip) = peer.primary_ip {
        if !allowed_ips
            .iter()
            .any(|prefix| prefix.contains_addr(&primary_ip))
        {
            allowed_ips.push(Prefix::host(primary_ip));
            allowed_ips.sort();
        }
    }
    PeerContents {
        allowed_ips: Some(allowed_ips),
        ..peer.clone()
    }
}

/// The snapshot of the store of `conn`: of every peer that it records, with the last announcement
/// of it that the node accepted, as [`snapshot`] makes it.
pub fn of_store(
    conn: &rusqlite::Connection,
    config: &SnapshotConfig,
    own: Option<Own>,
) -> Result<Snapshot, rusqlite::Error> {
    let peers = crate::store::load_peers(conn)?;
    let announcements = crate::store::load_announcements(conn, None)?;
    Ok(snapshot(
        config,
        peers.iter().map(|peer| {
            (
                peer,
                announcements
                    .get(&peer.public_key)
                    .map(|stored| &stored.announcement),
            )
        }),
        own,
    ))
}

/// The snapshot of `peers`, each the node's record of a peer with the last announcement of it
/// that the node accepted, if any, as `config` configures them, for `own`, the node itself, if
/// its config describes it. Each peer takes effect as [`effective`] makes it.
pub fn snapshot<'a>(
    config: &SnapshotConfig,
    peers: impl IntoIterator<Item = (&'a PeerContents, Option<&'a Announcement>)>,
    own: Option<Own>,
) -> Snapshot {
    let mut snapshot = Snapshot::default();
    for (record, announcement) in peers {
        let peer = effective(record, announcement);
        let peer = if config.route_primary_ip {
            with_primary_ip(&peer)
        } else {
            peer
        };
        if let Some(name) = peer.name.as_ref().filter(|_| !peer.is_disabled) {
            if let Some(ip) = peer.hosts_fallback() {
                snapshot.names.insert(name.to_string(), ip);
            }
            if let Some(nameserver) = &peer.nameserver {
                snapshot.zones.insert(name.to_string(), nameserver.clone());
            }
        }
        snapshot.peers.push(peer);
    }
    if let Some(own) = own {
        let own_peer = snapshot
            .peers
            .iter()
            .find(|peer| peer.public_key == own.public_key);
        snapshot.own_addresses.push(own.address);
        for address in own.extra {
            if own_peer.is_some_and(|own| own.holds(*address)) && *address != own.address {
                snapshot.own_addresses.push(*address);
            }
        }
    }
    snapshot
}

#[cfg(test)]
mod tests {
    use super::*;
    use innernet_shared::announcement::Claims;

    fn record(name: &str, ip: &str) -> PeerContents {
        PeerContents {
            name: Some(name.parse().unwrap()),
            delegations: vec![Prefix::host(ip.parse().unwrap())],
            public_key: wireguard_control::KeyPair::generate().public.to_base64(),
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

    fn announcement(name: Option<&str>, delegation: &str, primary_ip: &str) -> Announcement {
        let delegation: Vec<Prefix> = vec![delegation.parse().unwrap()];
        Announcement {
            claims: Claims {
                delegation: delegation.clone(),
                name: name.map(|name| name.parse().unwrap()),
            },
            allowed_ips: delegation,
            primary_ip: Some(primary_ip.parse().unwrap()),
            ..Default::default()
        }
    }

    #[test]
    fn test_snapshot() {
        let plain = record("recorded", "10.0.0.2");
        let plain_announced = announcement(Some("plain"), "10.0.0.0/30", "10.0.0.2");
        let silent = record("silent", "10.0.0.3");
        let dns = record("dns", "10.0.0.4");
        let dns_announced = Announcement {
            nameserver: Some(Nameserver {
                address: "10.0.0.4:53".parse().unwrap(),
                zone: "example.com".into(),
            }),
            ..announcement(Some("dns"), "10.0.0.4/32", "10.0.0.4")
        };
        let disabled = PeerContents {
            is_disabled: true,
            ..record("disabled", "10.0.0.5")
        };
        let disabled_announced = announcement(Some("disabled"), "10.0.0.5/32", "10.0.0.5");
        let own = Own {
            public_key: &plain.public_key,
            address: "10.0.0.2".parse().unwrap(),
            extra: &["10.0.0.3".parse().unwrap(), "10.0.0.9".parse().unwrap()],
        };
        let peers = [
            (&plain, Some(&plain_announced)),
            (&silent, None),
            (&dns, Some(&dns_announced)),
            (&disabled, Some(&disabled_announced)),
        ];
        let snapshot = super::snapshot(&SnapshotConfig::default(), peers, Some(own));

        // Each peer takes effect as it announced: one without an accepted announcement is routed
        // nothing, and has no name.
        assert_eq!(snapshot.peers[0].name, plain_announced.claims.name);
        assert!(!snapshot.peers[1].is_routed());
        assert_eq!(snapshot.peers[1].name, None);

        // The names are those that the enabled peers claim, at their primary IPs, that of a peer
        // that offers a nameserver included, and the zones are those of the enabled peers.
        assert_eq!(
            snapshot.names,
            [
                ("dns".to_string(), "10.0.0.4".parse().unwrap()),
                ("plain".to_string(), "10.0.0.2".parse().unwrap()),
            ]
            .into()
        );
        assert_eq!(
            snapshot.zones,
            [("dns".to_string(), dns_announced.nameserver.clone().unwrap())].into()
        );

        // The node holds its address, and those of its further addresses that it claims.
        assert_eq!(
            snapshot.own_addresses,
            [
                "10.0.0.2".parse::<IpAddr>().unwrap(),
                "10.0.0.3".parse().unwrap()
            ]
        );
    }

    #[test]
    fn test_route_primary_ip() {
        // The coordinator routes the primary IP of a peer to it, whatever allowed IPs it states.
        let peer = record("peer", "10.0.0.2");
        let announced = Announcement {
            allowed_ips: vec![],
            ..announcement(Some("peer"), "10.0.0.0/30", "10.0.0.2")
        };
        let config = SnapshotConfig {
            route_primary_ip: true,
        };
        let snapshot = snapshot(&config, [(&peer, Some(&announced))], None);
        assert_eq!(
            snapshot.peers[0].allowed_ips,
            Some(vec![Prefix::host("10.0.0.2".parse().unwrap())])
        );
        let snapshot = super::snapshot(
            &SnapshotConfig::default(),
            [(&peer, Some(&announced))],
            None,
        );
        assert_eq!(snapshot.peers[0].allowed_ips, Some(vec![]));
        assert!(snapshot.own_addresses.is_empty());
    }
}
