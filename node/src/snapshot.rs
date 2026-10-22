//! The output of the node: what it configures, as a snapshot of what its store holds.
//!
//! A [`Snapshot`] is the desired state that the output adapters realize: the peers of the tunnel
//! with what each is routed and where it is reached, and those whose names the node publishes.
//! The node makes it of what it accepted alone, and never reads what the operating system holds
//! back as truth.

use innernet_shared::{announcement::Announcement, PeerContents};

/// What a node configures: its desired state, which the output adapters realize.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// The peers as they take effect, each with the prefixes that the tunnel routes to it, its
    /// endpoint, the first that it announces, and its candidates, the others in their order. The
    /// tunnel holds the enabled peers that are routed a prefix, whose names the node publishes.
    pub peers: Vec<PeerContents>,
}

/// `record`, the node's record of a peer, as it takes effect with `announcement`, the last
/// announcement of the peer that the node accepted, as [`PeerContents::effective_with`] combines
/// them. A peer of which the node accepted no announcement is routed nothing, and has no name.
pub fn effective(record: &PeerContents, announcement: Option<&Announcement>) -> PeerContents {
    let none = Announcement::default();
    record.effective_with(Some(announcement.unwrap_or(&none)))
}

/// The snapshot of the store of `conn`: of every peer that it records, with the last announcement
/// of it that the node accepted, as [`snapshot`] makes it.
pub fn of_store(conn: &rusqlite::Connection) -> Result<Snapshot, rusqlite::Error> {
    let peers = crate::store::load_peers(conn)?;
    let announcements = crate::store::load_announcements(conn, None)?;
    Ok(snapshot(peers.iter().map(|peer| {
        (
            peer,
            announcements
                .get(&peer.public_key)
                .map(|stored| &stored.announcement),
        )
    })))
}

/// The snapshot of `peers`, each the node's record of a peer with the last announcement of it
/// that the node accepted, if any. Each peer takes effect as [`effective`] makes it.
pub fn snapshot<'a>(
    peers: impl IntoIterator<Item = (&'a PeerContents, Option<&'a Announcement>)>,
) -> Snapshot {
    Snapshot {
        peers: peers
            .into_iter()
            .map(|(record, announcement)| effective(record, announcement))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innernet_shared::{announcement::Claims, Prefix};

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
        let peers = [(&plain, Some(&plain_announced)), (&silent, None)];
        let snapshot = super::snapshot(peers);

        // Each peer takes effect as it announced: one without an accepted announcement is routed
        // nothing, and has no name.
        assert_eq!(snapshot.peers[0].name, plain_announced.claims.name);
        assert_eq!(
            snapshot.peers[0].hosts_fallback(),
            Some("10.0.0.2".parse().unwrap())
        );
        assert!(!snapshot.peers[1].is_routed());
        assert_eq!(snapshot.peers[1].name, None);
    }
}
