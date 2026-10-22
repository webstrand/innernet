//! The output of the node: what it configures, as a snapshot of what its store holds.
//!
//! A [`Snapshot`] is the desired state that the output adapters realize: the peers of the tunnel,
//! and those whose names the node publishes. The node makes it of what it recorded alone, and
//! never reads what the operating system holds back as truth.

use innernet_shared::PeerContents;

/// What a node configures: its desired state, which the output adapters realize.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// The peers that the node records. The tunnel holds the enabled ones, whose names the node
    /// publishes.
    pub peers: Vec<PeerContents>,
}

/// The snapshot of `peers`, the peers that the node records.
pub fn snapshot(peers: impl IntoIterator<Item = PeerContents>) -> Snapshot {
    Snapshot {
        peers: peers.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot() {
        let peer = |name: &str, ip: &str, is_disabled| PeerContents {
            name: Some(name.parse().unwrap()),
            delegations: vec![innernet_shared::Prefix::host(ip.parse().unwrap())],
            cidr_id: 0,
            public_key: wireguard_control::KeyPair::generate().public.to_base64(),
            endpoint: None,
            persistent_keepalive_interval: None,
            is_admin: false,
            is_disabled,
            is_redeemed: true,
            invite_expires: None,
            candidates: vec![],
        };
        let snapshot = snapshot([peer("a", "10.0.0.2", false), peer("b", "10.0.0.3", true)]);

        // The snapshot holds every peer, disabled ones included.
        assert_eq!(snapshot.peers.len(), 2);
        assert!(snapshot.peers[1].is_disabled);
    }
}
