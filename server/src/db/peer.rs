use super::DatabaseCidr;
use crate::ServerError;
use innernet_node::{
    store::{self, key_to_bytes, EndpointKind},
    Store,
};
use innernet_shared::{Endpoint, Hostname, Peer, PeerContents, PERSISTENT_KEEPALIVE_INTERVAL_SECS};
use rusqlite::{params, Connection};
use std::{
    net::IpAddr,
    ops::{Deref, DerefMut},
    time::SystemTime,
};
use wireguard_control::Key;

/// A peer of the coordinator's database, with the ID by which the API of plain HTTP names it, as
/// [`DatabasePeer::list`] numbers them, and the ID of its CIDR, the smallest CIDR that holds its
/// IP.
#[derive(Debug)]
pub struct DatabasePeer {
    pub inner: Peer,
}

impl From<Peer> for DatabasePeer {
    fn from(inner: Peer) -> Self {
        Self { inner }
    }
}

impl Deref for DatabasePeer {
    type Target = Peer;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for DatabasePeer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl DatabasePeer {
    /// Creates the peer `contents`, which must lie within the CIDR that it names, a CIDR without
    /// child CIDRs, at an address that the CIDR can assign, and which the server's node must
    /// accept: a valid name that no other peer has, and an address and a key that are pinned to
    /// no other key and address.
    pub fn create(store: &Store, contents: PeerContents) -> Result<Self, ServerError> {
        log::info!("creating peer {:?}", contents);

        if !Hostname::is_valid(&contents.name) {
            log::warn!("peer name is invalid, must conform to hostname(7) requirements.");
            return Err(ServerError::InvalidQuery);
        }

        let cidr = DatabaseCidr::get(store, contents.cidr_id)?;
        if !cidr.cidr.contains(&contents.ip) {
            log::warn!("tried to add peer with IP outside of parent CIDR range.");
            return Err(ServerError::InvalidQuery);
        }
        if DatabaseCidr::list(store)?
            .iter()
            .any(|other| other.parent == Some(cidr.id))
        {
            log::warn!("tried to add peer to a CIDR that has child CIDRs.");
            return Err(ServerError::InvalidQuery);
        }
        if !innernet_shared::IpNetExt::is_assignable(&cidr.cidr, &contents.ip) {
            println!(
                "Peer IP {} is not unicast assignable in CIDR {}",
                contents.ip, cidr.cidr
            );
            return Err(ServerError::InvalidQuery);
        }

        let key = key_to_bytes(&contents.public_key).map_err(|_| ServerError::InvalidQuery)?;
        if let Err(refusal) = store.accept(&[&contents])?.remove(0) {
            log::warn!("the server's node refuses the peer: {refusal}");
            return Err(ServerError::InvalidQuery);
        }
        let id = Self::get_by_key(store, &key)?
            .ok_or(ServerError::NotFound)?
            .id;
        Ok(Peer { id, contents }.into())
    }

    /// Applies the changes an admin may make to the peer: its name, whether it is an admin, and
    /// whether it is disabled. The other fields of `contents` are ignored. The peer alone sets its
    /// endpoint and candidates, and its IP, public key and CIDR never change.
    pub fn update(&mut self, store: &Store, contents: PeerContents) -> Result<(), ServerError> {
        if !Hostname::is_valid(&contents.name) {
            log::warn!("peer name is invalid, must conform to hostname(7) requirements.");
            return Err(ServerError::InvalidQuery);
        }
        let updated = PeerContents {
            name: contents.name,
            is_admin: contents.is_admin,
            is_disabled: contents.is_disabled,
            ..self.stored(store)?
        };
        if let Err(refusal) = store.accept(&[&updated])?.remove(0) {
            log::warn!("the server's node refuses the change: {refusal}");
            return Err(ServerError::InvalidQuery);
        }
        self.contents.name = updated.name;
        self.contents.is_admin = updated.is_admin;
        self.contents.is_disabled = updated.is_disabled;
        Ok(())
    }

    /// The record of the peer as the node holds it.
    fn stored(&self, conn: &Connection) -> Result<PeerContents, ServerError> {
        store::load_peer(conn, &self.key()?)?.ok_or(ServerError::NotFound)
    }

    fn key(&self) -> Result<[u8; 32], ServerError> {
        key_to_bytes(&self.public_key).map_err(|_| ServerError::NotFound)
    }

    /// Sets the endpoint that the peer reports for itself.
    pub fn set_endpoint(
        &mut self,
        conn: &Connection,
        endpoint: Option<Endpoint>,
    ) -> Result<(), ServerError> {
        store::write_endpoints(conn, &self.key()?, EndpointKind::Endpoint, &endpoint)?;
        self.contents.endpoint = endpoint;
        Ok(())
    }

    /// Sets the candidates that the peer reports for itself.
    pub fn set_candidates(
        &mut self,
        conn: &Connection,
        candidates: Vec<Endpoint>,
    ) -> Result<(), ServerError> {
        store::write_endpoints(conn, &self.key()?, EndpointKind::Candidate, &candidates)?;
        self.contents.candidates = candidates;
        Ok(())
    }

    pub fn disable(conn: &Connection, id: i64) -> Result<(), ServerError> {
        let key = Self::get(conn, id)?.key()?;
        conn.execute(
            "UPDATE peers SET is_disabled = 1 WHERE public_key = ?1",
            params![key],
        )?;
        Ok(())
    }

    /// Redeems the invitation with the key `pubkey`, the invitee's own. The node never moves a pin
    /// to another key, so the invitation, which nothing but the server has seen, is deleted with
    /// what is pinned to its key, and the redeemed peer recorded in its place.
    pub fn redeem(&mut self, store: &Store, pubkey: &str) -> Result<(), ServerError> {
        if self.is_redeemed {
            return Err(ServerError::Gone);
        }

        if matches!(self.invite_expires, Some(time) if time < SystemTime::now()) {
            return Err(ServerError::Unauthorized);
        }

        key_to_bytes(pubkey).map_err(|_| ServerError::InvalidQuery)?;
        let redeemed = PeerContents {
            public_key: pubkey.into(),
            is_redeemed: true,
            ..self.stored(store)?
        };
        let tx = store.unchecked_transaction()?;
        store::forget_peer(&tx, &self.key()?)?;
        if let Err(refusal) = store.accept(&[&redeemed])?.remove(0) {
            log::warn!("the server's node refuses the redeemed peer: {refusal}");
            return Err(ServerError::InvalidQuery);
        }
        tx.commit()?;
        self.contents.public_key = pubkey.into();
        self.contents.is_redeemed = true;
        Ok(())
    }

    pub fn get(conn: &Connection, id: i64) -> Result<Self, ServerError> {
        Self::list(conn)?
            .into_iter()
            .find(|peer| peer.id == id)
            .ok_or(ServerError::NotFound)
    }

    fn get_by_key(conn: &Connection, key: &[u8; 32]) -> Result<Option<Self>, ServerError> {
        Ok(Self::list(conn)?
            .into_iter()
            .find(|peer| key_to_bytes(&peer.public_key).ok() == Some(*key)))
    }

    /// The server's own peer, the one with the public key `key` of the server's config.
    pub fn own(conn: &Connection, key: &Key) -> Result<Self, ServerError> {
        Self::get_by_key(conn, &key.0)?.ok_or(ServerError::NotFound)
    }

    /// The peer at `ip`, as the pins of the node find it.
    pub fn get_from_ip(conn: &Connection, ip: IpAddr) -> Result<Self, rusqlite::Error> {
        let holder = store::holders_of(conn, ip)?
            .pop()
            .ok_or(rusqlite::Error::QueryReturnedNoRows)?;
        Self::get_by_key(conn, &holder)
            .map_err(|_| rusqlite::Error::QueryReturnedNoRows)?
            .ok_or(rusqlite::Error::QueryReturnedNoRows)
    }

    /// The enabled, redeemed peers that the peer sees: those within its own CIDR, within an infra
    /// CIDR, or within a CIDR associated with a CIDR that holds the peer's CIDR, its own or one of
    /// its ancestors.
    pub fn get_all_allowed_peers(&self, conn: &Connection) -> Result<Vec<Self>, ServerError> {
        let cidrs = DatabaseCidr::list(conn)?;
        let associations = super::DatabaseAssociation::list(conn)?;
        let own = cidrs.iter().find(|cidr| cidr.id == self.cidr_id);

        let mut visible: Vec<ipnet::IpNet> = cidrs
            .iter()
            .filter(|cidr| DatabaseCidr::is_infra(conn, cidr.id).unwrap_or(false))
            .map(|cidr| cidr.cidr)
            .collect();
        if let Some(own) = own {
            visible.push(own.cidr);
            let holds_own = |id: i64| {
                cidrs
                    .iter()
                    .any(|cidr| cidr.id == id && cidr.cidr.contains(&own.cidr))
            };
            for association in &associations {
                let other = if holds_own(association.cidr_id_1) {
                    Some(association.cidr_id_2)
                } else if holds_own(association.cidr_id_2) {
                    Some(association.cidr_id_1)
                } else {
                    None
                };
                if let Some(cidr) = other.and_then(|id| cidrs.iter().find(|cidr| cidr.id == id)) {
                    visible.push(cidr.cidr);
                }
            }
        }

        Ok(Self::list_enabled(conn)?
            .into_iter()
            .filter(|peer| visible.iter().any(|cidr| cidr.contains(&peer.ip)))
            .collect())
    }

    /// Every peer, ordered by IP, each with its ID, its position from 1 in that order, by which the
    /// API of plain HTTP names it. The IDs are consistent within one response, which is all that
    /// the clients of that API rely on: creating or deleting a peer renumbers the peers after it.
    pub fn list(conn: &Connection) -> Result<Vec<Self>, ServerError> {
        let cidrs = DatabaseCidr::list(conn)?;
        Ok(store::load_peers(conn)?
            .into_iter()
            .zip(1..)
            .map(|(mut contents, id)| {
                contents.cidr_id = cidrs
                    .iter()
                    .filter(|cidr| cidr.cidr.contains(&contents.ip))
                    .max_by_key(|cidr| cidr.cidr.prefix_len())
                    .map(|cidr| cidr.id)
                    .unwrap_or(0);
                contents.persistent_keepalive_interval = Some(PERSISTENT_KEEPALIVE_INTERVAL_SECS);
                Peer { id, contents }.into()
            })
            .collect())
    }

    pub fn list_enabled(conn: &Connection) -> Result<Vec<Self>, ServerError> {
        Ok(Self::list(conn)?
            .into_iter()
            .filter(|peer| peer.is_redeemed && !peer.is_disabled)
            .collect())
    }

    /// Deletes the invitations that expired before now, each with what is pinned to its key.
    pub fn delete_expired_invites(conn: &Connection) -> Result<usize, ServerError> {
        let now = SystemTime::now();
        let expired: Vec<[u8; 32]> = store::load_peers(conn)?
            .into_iter()
            .filter(|peer| !peer.is_redeemed && peer.invite_expires.is_some_and(|t| t < now))
            .filter_map(|peer| key_to_bytes(&peer.public_key).ok())
            .collect();
        for key in &expired {
            store::forget_peer(conn, key)?;
        }
        Ok(expired.len())
    }
}
