use super::DatabaseCidr;
use crate::ServerError;
use innernet_node::{
    store::{self, ip_to_bytes, key_to_bytes, prefix_from_row, row_key, EndpointKind},
    Store,
};
use innernet_shared::{
    check_delegations, xeddsa, Endpoint, LegacyPeer, LegacyPeerContents, PeerContents, Prefix,
    PERSISTENT_KEEPALIVE_INTERVAL_SECS,
};
use ipnet::IpNet;
use rusqlite::{params, Connection};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    ops::{Deref, DerefMut},
    time::SystemTime,
};
use wireguard_control::Key;

/// A peer of the coordinator's database, with the ID of its CIDR, the smallest CIDR that holds its
/// IP.
#[derive(Debug)]
pub struct DatabasePeer {
    pub inner: PeerContents,
    /// Whether the peer must authenticate over TLS with its key, and is refused when it connects
    /// in plain HTTP, authenticated only by its source IP: the node's `tls` of the peer. Set from
    /// creation for every peer that the server creates, and for good once a peer that predates
    /// TLS connects over TLS.
    pub requires_tls: bool,
}

impl Deref for DatabasePeer {
    type Target = PeerContents;

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
    /// The peer as the API of plain-HTTP sessions transfers it, with the ID `id`, which
    /// [`Self::plain_http_ids`] gives it, or `None` if clients that predate TLS can't represent
    /// it, as [`LegacyPeerContents::from_peer`] tells.
    pub fn legacy(&self, id: i64) -> Option<LegacyPeer> {
        Some(LegacyPeer {
            id,
            contents: LegacyPeerContents::from_peer(&self.inner)?,
        })
    }

    /// The IDs by which the API of plain-HTTP sessions names the peers, by public key: the
    /// position of each peer, from 1, in [`Self::list`]. The database stores no such ID. The IDs
    /// are consistent within one response, which is all that clients that predate TLS rely on,
    /// but not from one response to the next: creating or deleting a peer renumbers the peers
    /// after it.
    pub fn plain_http_ids(conn: &Connection) -> Result<HashMap<String, i64>, ServerError> {
        Ok(Self::list(conn)?
            .into_iter()
            .zip(1..)
            .map(|(peer, id)| (peer.inner.public_key, id))
            .collect())
    }

    /// Creates the peer `contents`, which the server offers its IP as a host-prefix delegation.
    /// The delegation must follow the rules of [`check_delegations`] within the CIDR that the peer
    /// names, a CIDR without child CIDRs, and the server's node must accept the peer: a name, if
    /// it has one, that no other peer has, and an address and a key that are pinned to no other
    /// key and address.
    pub fn create(store: &Store, contents: PeerContents) -> Result<Self, ServerError> {
        log::info!("creating peer {:?}", contents);

        if !Self::is_valid_public_key(&contents.public_key) {
            log::warn!("peer public key is invalid.");
            return Err(ServerError::InvalidQuery);
        }

        let cidr = DatabaseCidr::get(store, contents.cidr_id)?;
        if DatabaseCidr::list(store)?
            .iter()
            .any(|other| other.parent == Some(cidr.id))
        {
            log::warn!("tried to add peer to a CIDR that has child CIDRs.");
            return Err(ServerError::InvalidQuery);
        }
        check_new_delegations(store, &[Prefix::host(contents.ip)], &cidr.cidr, None)?;

        let key = key_to_bytes(&contents.public_key).map_err(|_| ServerError::InvalidQuery)?;
        let tx = store.unchecked_transaction()?;
        if let Err(refusal) = store.accept(&[&contents])?.remove(0) {
            log::warn!("the server's node refuses the peer: {refusal}");
            return Err(ServerError::InvalidQuery);
        }
        // A peer that the server creates is redeemed and used by a client that speaks TLS, so
        // that nothing else on its machine can act as the peer, and above all as an admin. Only
        // peers that existed before the server spoke TLS may still use plain HTTP.
        tx.execute(
            "UPDATE peers SET tls = 1 WHERE public_key = ?1",
            params![key],
        )?;
        tx.commit()?;
        Ok(Self {
            inner: contents,
            requires_tls: true,
        })
    }

    /// Peers are looked up by the key they authenticate with over TLS, encoded canonically.
    fn is_valid_public_key(public_key: &str) -> bool {
        Key::from_base64(public_key)
            .is_ok_and(|key| xeddsa::is_valid_public_key(&key) && key.to_base64() == public_key)
    }

    /// Applies the changes an admin may make to the peer: its name, which it may lose, whether it
    /// is an admin, and whether it is disabled. The other fields of `contents` are ignored. The
    /// peer alone sets its endpoint and candidates, and its IP, public key and CIDR never change.
    pub fn update(&mut self, store: &Store, contents: PeerContents) -> Result<(), ServerError> {
        if contents.is_admin && !self.is_admin && !self.requires_tls {
            log::warn!(
                "refusing to make {} an admin before it connects over TLS.",
                **self
            );
            return Err(ServerError::PromotionRequiresTls);
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
        self.inner.name = updated.name;
        self.inner.is_admin = updated.is_admin;
        self.inner.is_disabled = updated.is_disabled;
        Ok(())
    }

    /// The record of the peer as the node holds it.
    fn stored(&self, conn: &Connection) -> Result<PeerContents, ServerError> {
        store::load_peer(conn, &self.key()?)?.ok_or(ServerError::NotFound)
    }

    fn key(&self) -> Result<[u8; 32], ServerError> {
        key_to_bytes(&self.public_key).map_err(|_| ServerError::NotFound)
    }

    /// The peer as the database now holds it, found by its public key.
    pub fn reload(&self, conn: &Connection) -> Result<Self, ServerError> {
        Self::get_by_key(conn, &self.key()?)?.ok_or(ServerError::NotFound)
    }

    /// Sets the endpoint that the peer reports for itself.
    pub fn set_endpoint(
        &mut self,
        conn: &Connection,
        endpoint: Option<Endpoint>,
    ) -> Result<(), ServerError> {
        store::write_endpoints(conn, &self.key()?, EndpointKind::Endpoint, &endpoint)?;
        self.inner.endpoint = endpoint;
        Ok(())
    }

    /// Sets the candidates that the peer reports for itself.
    pub fn set_candidates(
        &mut self,
        conn: &Connection,
        candidates: Vec<Endpoint>,
    ) -> Result<(), ServerError> {
        store::write_endpoints(conn, &self.key()?, EndpointKind::Candidate, &candidates)?;
        self.inner.candidates = candidates;
        Ok(())
    }

    /// Sets the endpoint and candidates of the peer together, on its behalf, so that a failure
    /// can't leave the endpoint changed and the candidates stale.
    pub fn set_endpoints(
        &mut self,
        conn: &Connection,
        endpoint: Option<Endpoint>,
        candidates: Vec<Endpoint>,
    ) -> Result<(), ServerError> {
        let key = self.key()?;
        let tx = conn.unchecked_transaction()?;
        store::write_endpoints(&tx, &key, EndpointKind::Endpoint, &endpoint)?;
        store::write_endpoints(&tx, &key, EndpointKind::Candidate, &candidates)?;
        tx.commit()?;
        self.inner.endpoint = endpoint;
        self.inner.candidates = candidates;
        Ok(())
    }

    /// Requires the peer to authenticate over TLS from now on.
    pub fn set_requires_tls(&mut self, conn: &Connection) -> Result<(), ServerError> {
        conn.execute(
            "UPDATE peers SET tls = 1 WHERE public_key = ?1",
            params![self.key()?],
        )?;
        self.requires_tls = true;
        Ok(())
    }

    /// Redeems the invitation with the key `pubkey`, the invitee's own. The node never moves a pin
    /// to another key, so the invitation, which nothing but the server has seen, is deleted with
    /// what is pinned to its key, and the redeemed peer recorded in its place, latched to TLS if the
    /// invitation was.
    pub fn redeem(&mut self, store: &Store, pubkey: &str) -> Result<(), ServerError> {
        if self.is_redeemed {
            return Err(ServerError::Gone);
        }

        if matches!(self.invite_expires, Some(time) if time < SystemTime::now()) {
            return Err(ServerError::Unauthorized);
        }

        if !Self::is_valid_public_key(pubkey) {
            log::warn!("refusing to redeem {} with an invalid public key.", **self);
            return Err(ServerError::InvalidQuery);
        }
        let key = key_to_bytes(pubkey).map_err(|_| ServerError::InvalidQuery)?;
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
        if self.requires_tls {
            tx.execute(
                "UPDATE peers SET tls = 1 WHERE public_key = ?1",
                params![key],
            )?;
        }
        tx.commit()?;
        self.inner.public_key = pubkey.into();
        self.inner.is_redeemed = true;
        Ok(())
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

    /// The peer with the public key `key`.
    pub fn get_from_public_key(conn: &Connection, key: &Key) -> Result<Self, rusqlite::Error> {
        Self::get_by_key(conn, &key.0)
            .map_err(|_| rusqlite::Error::QueryReturnedNoRows)?
            .ok_or(rusqlite::Error::QueryReturnedNoRows)
    }

    /// The peer whose delegations hold the address `ip`.
    pub fn get_by_address(conn: &Connection, ip: IpAddr) -> Result<Self, rusqlite::Error> {
        // Delegations never overlap, so only the one with the highest first address at or below
        // `ip` may hold it.
        let address = ip_to_bytes(ip);
        let (public_key, last): ([u8; 32], Vec<u8>) = conn.query_row(
            "SELECT public_key, last FROM delegations
             WHERE length(address) = length(?1) AND address <= ?1
             ORDER BY address DESC LIMIT 1",
            params![address],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if address > last {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        Self::get_by_key(conn, &public_key)
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

    /// Every peer, ordered by IP.
    pub fn list(conn: &Connection) -> Result<Vec<Self>, ServerError> {
        let cidrs = DatabaseCidr::list(conn)?;
        let latched = Self::latched(conn)?;
        Ok(store::load_peers(conn)?
            .into_iter()
            .map(|mut contents| {
                contents.cidr_id = cidrs
                    .iter()
                    .filter(|cidr| cidr.cidr.contains(&contents.ip))
                    .max_by_key(|cidr| cidr.cidr.prefix_len())
                    .map(|cidr| cidr.id)
                    .unwrap_or(0);
                contents.persistent_keepalive_interval = Some(PERSISTENT_KEEPALIVE_INTERVAL_SECS);
                Self {
                    requires_tls: latched.contains(&contents.public_key),
                    inner: contents,
                }
            })
            .collect())
    }

    /// The public keys of the peers latched to TLS.
    fn latched(conn: &Connection) -> Result<HashSet<String>, rusqlite::Error> {
        let mut stmt = conn.prepare_cached("SELECT public_key FROM peers WHERE tls = 1")?;
        let keys = stmt.query_map([], |row| store::row_key(row, 0))?;
        keys.collect()
    }

    pub fn list_enabled(conn: &Connection) -> Result<Vec<Self>, ServerError> {
        Ok(Self::list(conn)?
            .into_iter()
            .filter(|peer| peer.is_redeemed && !peer.is_disabled)
            .collect())
    }

    /// When the first of the invitations expires, if any does.
    pub fn next_invite_expiry(conn: &Connection) -> Result<Option<SystemTime>, ServerError> {
        Ok(store::load_peers(conn)?
            .into_iter()
            .filter(|peer| !peer.is_redeemed)
            .filter_map(|peer| peer.invite_expires)
            .min())
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

/// Checks that `delegations` may be delegated together to a peer of the CIDR `cidr`, as
/// [`check_delegations`] does, given the delegations that the database holds for other peers than
/// the one with the public key `holder`, if any. A delegation that breaks the rules is refused as
/// [`ServerError::Delegation`], which explains why.
pub(crate) fn check_new_delegations(
    conn: &Connection,
    delegations: &[Prefix],
    cidr: &IpNet,
    holder: Option<&[u8; 32]>,
) -> Result<(), ServerError> {
    let mut stmt = conn.prepare_cached(
        "SELECT d.address, d.prefix_len, p.public_key, p.name
         FROM delegations d JOIN peers p ON p.public_key = d.public_key
         WHERE length(d.address) = length(?1) AND d.address <= ?2 AND ?1 <= d.last
           AND p.public_key IS NOT ?3",
    )?;
    let mut others = vec![];
    for delegation in delegations {
        let mut rows = stmt.query(params![
            ip_to_bytes(delegation.first()),
            ip_to_bytes(delegation.last()),
            holder,
        ])?;
        while let Some(row) = rows.next()? {
            let prefix = prefix_from_row(row.get(0)?, row.get(1)?)?;
            let holder = match row.get::<_, Option<String>>(3)? {
                Some(name) => format!("peer {name}"),
                None => format!("the peer with public key {}", row_key(row, 2)?),
            };
            others.push((prefix, holder));
        }
    }
    let others = others
        .iter()
        .map(|(prefix, holder)| (prefix, holder.as_str()));
    check_delegations(delegations, cidr, others).map_err(|e| {
        log::warn!("refusing delegations {delegations:?}: {e}");
        ServerError::Delegation(e.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test;
    use innernet_shared::Error;
    use std::time::Duration;

    #[test]
    fn test_delegations_follow_their_peer() -> Result<(), Error> {
        let server = test::Server::new()?;
        let store = server.db();
        let store = store.lock();
        let (ip, other) = if cfg!(feature = "v6-test") {
            ("fd00:1337::3:0:0:9", "fd00:1337::3:0:0:a")
        } else {
            ("10.80.128.9", "10.80.128.10")
        };
        let delegations = |key: &Key| -> Result<i64, rusqlite::Error> {
            store.query_row(
                "SELECT count(*) FROM delegations WHERE public_key = ?1",
                [key.0],
                |r| r.get(0),
            )
        };
        let mut invitee = DatabasePeer::create(
            &store,
            PeerContents {
                is_redeemed: false,
                ..test::user_peer_contents("invitee", ip)?
            },
        )?;
        let old_key = Key::from_base64(&invitee.public_key)?;
        assert_eq!(delegations(&old_key)?, 1);
        assert_eq!(
            DatabasePeer::get_by_address(&store, ip.parse()?)?.public_key,
            invitee.public_key
        );
        assert!(matches!(
            DatabasePeer::get_by_address(&store, other.parse()?),
            Err(rusqlite::Error::QueryReturnedNoRows)
        ));

        // The delegation follows the peer to its new key.
        let new_key = wireguard_control::KeyPair::generate().public;
        invitee.redeem(&store, &new_key.to_base64())?;
        assert_eq!(delegations(&old_key)?, 0);
        assert_eq!(delegations(&new_key)?, 1);
        assert_eq!(
            DatabasePeer::get_by_address(&store, ip.parse()?)?.public_key,
            new_key.to_base64()
        );
        Ok(())
    }

    #[test]
    fn test_invitations_expire() -> Result<(), Error> {
        let server = test::Server::new()?;
        let store = server.db();
        let store = store.lock();
        assert_eq!(DatabasePeer::next_invite_expiry(&store)?, None);

        // An invitation that has expired is the next to expire, and is deleted with its pin, so
        // that its address can be offered again.
        let ip = if cfg!(feature = "v6-test") {
            "fd00:1337::2:0:0:9"
        } else {
            "10.80.64.9"
        };
        let expires = SystemTime::now() - Duration::from_secs(60);
        let invitation = PeerContents {
            is_redeemed: false,
            invite_expires: Some(expires),
            ..test::developer_peer_contents("invited", ip)?
        };
        DatabasePeer::create(&store, invitation)?;
        let next = DatabasePeer::next_invite_expiry(&store)?.unwrap();
        assert!(next <= expires && next > expires - Duration::from_secs(1));
        assert_eq!(DatabasePeer::delete_expired_invites(&store)?, 1);
        assert_eq!(DatabasePeer::next_invite_expiry(&store)?, None);
        assert!(DatabasePeer::get_by_address(&store, ip.parse()?).is_err());
        DatabasePeer::create(&store, test::developer_peer_contents("again", ip)?)?;
        Ok(())
    }
}
