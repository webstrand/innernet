use crate::{Hostname, PeerContents, Prefix, Timestring, PERSISTENT_KEEPALIVE_INTERVAL_SECS};
use std::time::SystemTime;
use wireguard_control::KeyPair;

pub struct NewPeerInfo {
    pub name: Hostname,
    /// The delegations that the server offers the new peer.
    pub delegations: Vec<Prefix>,
    pub cidr_id: i64,
    pub is_admin: bool,
    pub invite_expires: Timestring,
}

impl NewPeerInfo {
    pub fn into_peer_contents(self, keypair: &KeyPair) -> PeerContents {
        PeerContents {
            name: Some(self.name),
            delegations: self.delegations,
            cidr_id: self.cidr_id,
            public_key: keypair.public.to_base64(),
            endpoint: None,
            is_admin: self.is_admin,
            is_disabled: false,
            is_redeemed: false,
            persistent_keepalive_interval: Some(PERSISTENT_KEEPALIVE_INTERVAL_SECS),
            invite_expires: Some(SystemTime::now() + self.invite_expires.into()),
            candidates: vec![],
        }
    }
}
