use super::{DatabaseAssociation, DatabaseCidr};
use crate::ServerError;
use innernet_node::{
    accept::Refusal,
    store::{self, ip_to_bytes, key_to_bytes, prefix_from_row, row_key, EndpointKind},
    Store,
};
use innernet_shared::{
    check_delegations, cidr_of_delegations, xeddsa, Endpoint, LegacyPeer, LegacyPeerContents,
    PeerContents, Prefix, PERSISTENT_KEEPALIVE_INTERVAL_SECS,
};
use rusqlite::{params, Connection};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    ops::{Deref, DerefMut},
    time::SystemTime,
};
use wireguard_control::Key;

/// A peer of the coordinator's database.
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
    /// [`Self::plain_http_ids`] gives it, and the ID of its CIDR, the CIDR of its delegations,
    /// among `cidrs`, every CIDR, as [`DatabaseCidr::id_of`] numbers them, or `None` if clients
    /// that predate TLS can't represent it, as [`LegacyPeerContents::from_peer`] tells: a peer
    /// without a name or without a hosts fallback address, which has no CIDR either.
    pub fn legacy(&self, id: i64, cidrs: &[DatabaseCidr]) -> Option<LegacyPeer> {
        let cidr = cidr_of_delegations(&self.delegations, &DatabaseCidr::prefixes(cidrs))?;
        let cidr_id = DatabaseCidr::id_of(&cidr, cidrs)?;
        Some(LegacyPeer {
            id,
            contents: LegacyPeerContents::from_peer(&self.inner, cidr_id)?,
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

    /// Creates the peer `contents`, offering it its delegations, of which it must have at least
    /// one. The delegations must follow the rules of [`check_delegations`], which give the peer
    /// its CIDR, and the server's node must accept the peer: a name, if it has one, that no other
    /// peer has, and delegations that overlap no prefix pinned to another key.
    pub fn create(store: &Store, mut contents: PeerContents) -> Result<Self, ServerError> {
        contents.delegations.sort();
        log::info!("creating peer {:?}", contents);

        if !Self::is_valid_public_key(&contents.public_key) {
            log::warn!("peer public key is invalid.");
            return Err(ServerError::InvalidQuery);
        }

        if contents.delegations.is_empty() {
            return Err(ServerError::Delegation(
                "a new peer must be offered at least one delegation".into(),
            ));
        }
        check_new_delegations(store, &contents.delegations, None)?;

        let key = key_to_bytes(&contents.public_key).map_err(|_| ServerError::InvalidQuery)?;
        let tx = store.unchecked_transaction()?;
        if let Err(refusal) = store.accept(&[&contents])?.remove(0) {
            log::warn!("the server's node refuses the peer: {refusal}");
            return Err(refused(refusal));
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
    /// peer alone sets its endpoint and candidates, its delegations change with
    /// [`Self::set_delegations`], and its public key never changes.
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
            return Err(refused(refusal));
        }
        self.inner.name = updated.name;
        self.inner.is_admin = updated.is_admin;
        self.inner.is_disabled = updated.is_disabled;
        Ok(())
    }

    /// Replaces the delegations of the peer with `delegations` as a whole, together or not at
    /// all. The delegations must follow the rules of [`check_delegations`], with the delegations
    /// of the other peers. A peer with delegations keeps its CIDR: the new delegations, if any,
    /// must lie in the CIDR of the current ones, so that a change never moves the peer to another
    /// CIDR, and so changes what it sees. The server's node must accept them: no delegation may
    /// overlap a prefix pinned to another key, as one that was delegated to another peer stays.
    /// The peer may be left without a delegation, which leaves it in effect disabled, except the
    /// server's own peer, the one with the public key `server_key`, which must keep the delegation
    /// that holds `internal_address`, the address that the server serves its API on.
    pub fn set_delegations(
        &mut self,
        store: &Store,
        mut delegations: Vec<Prefix>,
        server_key: &Key,
        internal_address: IpAddr,
    ) -> Result<(), ServerError> {
        delegations.sort();
        let key = self.key()?;
        if key == server_key.0
            && !delegations
                .iter()
                .any(|delegation| delegation.contains_addr(&internal_address))
        {
            return Err(ServerError::Delegation(format!(
                "the server's own peer must keep a delegation that holds {internal_address}, the \
                 internal address of the server"
            )));
        }
        let new_cidr = check_new_delegations(store, &delegations, Some(&key))?;
        let cidrs = DatabaseCidr::prefixes(&DatabaseCidr::list(store)?);
        match (cidr_of_delegations(&self.delegations, &cidrs), new_cidr) {
            (Some(old), Some(new)) if old != new => {
                return Err(ServerError::Delegation(format!(
                    "the delegations of the peer lie in its CIDR {old}, and a change of them \
                     can't move it to the CIDR {new}"
                )))
            },
            _ => {},
        }

        let updated = PeerContents {
            delegations,
            ..self.stored(store)?
        };
        let tx = store.unchecked_transaction()?;
        if let Err(refusal) = store.accept(&[&updated])?.remove(0) {
            log::warn!("the server's node refuses the delegations: {refusal}");
            return Err(refused(refusal));
        }
        tx.commit()?;
        self.inner.delegations = updated.delegations;
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
            return Err(refused(refusal));
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

    /// The enabled, redeemed peers that the peer sees: those whose CIDR lies within the peer's own
    /// CIDR, within an infra CIDR, which every peer sees, or within a CIDR associated with a CIDR
    /// that holds the peer's CIDR, its own or one of its ancestors. A peer's CIDR is that of its
    /// delegations, so a peer without a delegation is seen by none, and sees only the peers of
    /// the infra CIDRs.
    pub fn get_all_allowed_peers(&self, conn: &Connection) -> Result<Vec<Self>, ServerError> {
        let cidrs = DatabaseCidr::prefixes(&DatabaseCidr::list(conn)?);
        let associations = DatabaseAssociation::list(conn)?;
        let cidr_of = |peer: &Self| cidr_of_delegations(&peer.delegations, &cidrs);

        // The CIDRs whose peers, and those of their descendants, the peer sees.
        let mut visible = DatabaseCidr::infra(conn)?;
        if let Some(own) = cidr_of(self) {
            visible.push(own);
            let holds_own = |cidr: &Prefix| cidr.contains(&own);
            for association in &associations {
                if holds_own(&association.cidr_1) {
                    visible.push(association.cidr_2);
                }
                if holds_own(&association.cidr_2) {
                    visible.push(association.cidr_1);
                }
            }
        }

        Ok(Self::list_enabled(conn)?
            .into_iter()
            .filter(|peer| {
                cidr_of(peer).is_some_and(|cidr| visible.iter().any(|seen| seen.contains(&cidr)))
            })
            .collect())
    }

    /// Every peer, ordered by hosts fallback address, those without one last.
    pub fn list(conn: &Connection) -> Result<Vec<Self>, ServerError> {
        let latched = Self::latched(conn)?;
        Ok(store::load_peers(conn)?
            .into_iter()
            .map(|mut contents| {
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

/// The error of a change that the server's node refuses with `refusal`: the delegations that it
/// refuses are explained, as [`check_new_delegations`] explains those that break the rules.
fn refused(refusal: Refusal) -> ServerError {
    match refusal {
        Refusal::Pinned { .. } | Refusal::Overlapping | Refusal::OutsideNetwork { .. } => {
            ServerError::Delegation(refusal.to_string())
        },
        _ => ServerError::InvalidQuery,
    }
}

/// Checks that `delegations` may be delegated together to a peer, as [`check_delegations`] does,
/// given the CIDRs of the database and the delegations that it holds for other peers than the one
/// with the public key `holder`, if any. Returns the CIDR of the peer, which its delegations
/// determine, or `None` for a peer without a delegation. A delegation that breaks the rules is
/// refused as [`ServerError::Delegation`], which explains why.
pub(crate) fn check_new_delegations(
    conn: &Connection,
    delegations: &[Prefix],
    holder: Option<&[u8; 32]>,
) -> Result<Option<Prefix>, ServerError> {
    let cidrs = DatabaseCidr::prefixes(&DatabaseCidr::list(conn)?);
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
    check_delegations(delegations, &cidrs, others).map_err(|e| {
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
