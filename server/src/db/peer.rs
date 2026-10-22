use super::{
    atomically, ip_to_bytes, key_to_bytes, prefix_from_row, DatabaseAssociation, DatabaseCidr,
};
use crate::ServerError;
use innernet_node::{
    accept::{self, Received, Refusal},
    store::{self as node_store, row_key, write_endpoints, EndpointKind},
    Store,
};
use innernet_shared::{
    announcement::{self, Announcement, SignedAnnouncement},
    check_delegations, cidr_of_delegations, xeddsa, Endpoint, LegacyPeer, LegacyPeerContents,
    PeerContents, Prefix, PERSISTENT_KEEPALIVE_INTERVAL_SECS,
};
use rusqlite::{params, types::Type, OptionalExtension as _};
use std::{
    collections::HashMap,
    net::IpAddr,
    ops::{Deref, DerefMut},
    time::{Duration, SystemTime},
};
use wireguard_control::Key;

/// The columns of `peers` that [`DatabasePeer::from_row`] reads, in its order.
static COLUMNS: &[&str] = &[
    "public_key",
    "is_admin",
    "is_disabled",
    "is_redeemed",
    "invite_expires",
    "tls",
    "announces",
];

#[derive(Debug)]
pub struct DatabasePeer {
    pub inner: PeerContents,
    /// Whether the peer must authenticate over TLS with its key, and is refused when it
    /// connects in plain HTTP, authenticated only by its source IP. Set from creation for every
    /// peer that the server creates, and for good once a peer that predates TLS connects over
    /// TLS.
    pub requires_tls: bool,
    /// The last announcement of the peer that the server's node core accepted, as it stored it
    /// decoded: the last that the peer signed, or, for a peer that has never announced, the last
    /// unsigned one that the server made of it, or `None` if the node core has accepted none. The
    /// bytes that the server relays of a signed one are the record's `announcement`, which the
    /// server never decodes again.
    pub announced: Option<Announcement>,
    /// Whether the peer has signed an announcement that the server accepted, after which only its
    /// signed announcements are accepted.
    pub announces: bool,
    /// The ranges of the peer's delegations, its assigned ranges, that are marked to be
    /// reclaimed: each stops being assigned once the peer, having claimed some of it, announces
    /// without claiming any of it.
    pub reclaim: Vec<Prefix>,
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
    /// The peer as the API of plain-HTTP sessions transfers it, as it takes effect, with the ID
    /// `id`, which [`Self::plain_http_ids`] gives it, and the ID of its CIDR, the CIDR of its
    /// delegations, among `cidrs`, every CIDR, as [`DatabaseCidr::id_of`] numbers them, or `None`
    /// if clients that predate TLS can't represent it, as [`LegacyPeerContents::from_peer`] tells:
    /// a peer without a name or without a hosts fallback address, which has no CIDR either. Such
    /// clients can't check announcements, so they get what the announcement of the peer, if any,
    /// makes of it.
    pub fn legacy(&self, id: i64, cidrs: &[DatabaseCidr]) -> Option<LegacyPeer> {
        let cidr = cidr_of_delegations(&self.delegations, &DatabaseCidr::prefixes(cidrs))?;
        let cidr_id = DatabaseCidr::id_of(&cidr, cidrs)?;
        Some(LegacyPeer {
            id,
            contents: LegacyPeerContents::from_peer(&self.effective(), cidr_id)?,
        })
    }

    /// The IDs by which the API of plain-HTTP sessions names the peers, by public key: the
    /// position of each peer, from 1, in [`Self::list`]. The database stores no such ID. The IDs
    /// are consistent within one response, which is all that clients that predate TLS rely on,
    /// but not from one response to the next: creating or deleting a peer renumbers the peers
    /// after it.
    pub fn plain_http_ids(store: &Store) -> Result<HashMap<String, i64>, ServerError> {
        Ok(Self::list(store)?
            .into_iter()
            .zip(1..)
            .map(|(peer, id)| (peer.inner.public_key, id))
            .collect())
    }

    /// Whether the peer has ever signed an announcement.
    pub fn has_announced(&self) -> bool {
        self.announces
    }

    /// The last announcement that the peer signed and the server accepted, if any.
    pub fn signed_announcement(&self) -> Option<&Announcement> {
        self.announced.as_ref().filter(|_| self.announces)
    }

    /// The peer as it takes effect, as [`innernet_node::snapshot::effective`] makes it of the last
    /// announcement of it that the server's node core accepted, signed or not. A peer of which the
    /// node core has accepted none is routed nothing, and has no name, as on every client.
    pub fn effective(&self) -> PeerContents {
        innernet_node::snapshot::effective(&self.inner, self.announced.as_ref())
    }

    /// Creates the peer `contents`, offering it its delegations, of which it must have at least
    /// one. The delegations must follow the rules of [`check_delegations`], which give the peer
    /// its CIDR.
    pub fn create(store: &Store, mut contents: PeerContents) -> Result<Self, ServerError> {
        contents.delegations.sort();
        // Only the peer itself announces.
        contents.announcement = None;
        contents.allowed_ips = None;
        contents.primary_ip = None;
        let PeerContents {
            name,
            delegations,
            public_key,
            endpoint,
            is_admin,
            is_disabled,
            is_redeemed,
            invite_expires,
            candidates,
            ..
        } = &contents;
        log::info!("creating peer {:?}", contents);

        if !Self::is_valid_public_key(public_key) {
            log::warn!("peer public key is invalid.");
            return Err(ServerError::InvalidQuery);
        }

        if delegations.is_empty() {
            return Err(ServerError::Delegation(
                "a new peer must be offered at least one delegation".into(),
            ));
        }
        check_new_delegations(store, delegations, None)?;

        let invite_expires = invite_expires
            .map(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .flatten()
            .map(|t| t.as_secs());

        // A peer created by this version is redeemed and used by a client that speaks TLS, so
        // that nothing else on its machine can act as the peer, and above all as an admin. Only
        // peers that existed before the server spoke TLS may still use plain HTTP.
        let requires_tls = true;

        let key = key_to_bytes(public_key)?;
        atomically(store, || {
            store.execute(
                "INSERT INTO peers (public_key, is_admin, is_disabled,
                                    is_redeemed, invite_expires, tls)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    key,
                    is_admin,
                    is_disabled,
                    is_redeemed,
                    invite_expires,
                    requires_tls,
                ],
            )?;
            offer_name(store, &key, name.as_deref())?;
            for delegation in delegations {
                insert_delegation(store, &key, delegation)?;
            }
            write_endpoints(store, &key, EndpointKind::Endpoint, endpoint)?;
            write_endpoints(store, &key, EndpointKind::Candidate, candidates)?;
            Self::admit_synthesized(store)
        })?;
        let mut peer = Self {
            inner: contents,
            requires_tls,
            announced: None,
            announces: false,
            reclaim: vec![],
        };
        peer.reload_announced(store)?;
        Ok(peer)
    }

    /// Peers are looked up by the key they authenticate with over TLS, encoded canonically.
    fn is_valid_public_key(public_key: &str) -> bool {
        Key::from_base64(public_key)
            .is_ok_and(|key| xeddsa::is_valid_public_key(&key) && key.to_base64() == public_key)
    }

    /// The public key of the peer, as the database holds it.
    fn key(&self) -> Result<[u8; 32], ServerError> {
        key_to_bytes(&self.public_key)
    }

    /// The peer as the database now holds it, found by its public key.
    pub fn reload(&self, store: &Store) -> Result<Self, ServerError> {
        Ok(Self::get_from_public_key(store, &Key(self.key()?))?)
    }

    /// Applies the changes an admin may make to the peer: the name offered to it, whether it is an
    /// admin, and whether it is disabled. The other fields of `contents` are ignored. The peer
    /// alone sets its endpoint and candidates, its delegations, which give it its CIDR, change
    /// with [`Self::set_delegations`], and its public key never changes.
    pub fn update(&mut self, store: &Store, contents: PeerContents) -> Result<(), ServerError> {
        if contents.is_admin && !self.is_admin && !self.requires_tls {
            log::warn!(
                "refusing to make {} an admin before it connects over TLS.",
                **self
            );
            return Err(ServerError::PromotionRequiresTls);
        }

        let key = self.key()?;
        atomically(store, || {
            store.execute(
                "UPDATE peers SET is_admin = ?2, is_disabled = ?3 WHERE public_key = ?1",
                params![key, contents.is_admin, contents.is_disabled],
            )?;
            offer_name(store, &key, contents.name.as_deref())?;
            Self::admit_synthesized(store)
        })?;

        self.inner.name = contents.name;
        self.inner.is_admin = contents.is_admin;
        self.inner.is_disabled = contents.is_disabled;
        self.reload_announced(store)
    }

    /// Replaces the delegations of the peer, the ranges assigned to it, with `delegations` as a
    /// whole: withdraws those that `delegations` leaves out and adds the others, and marks those
    /// of `reclaim` to be reclaimed, together or not at all. The delegations must follow the rules
    /// of [`check_delegations`], with the delegations of the other peers, and every range of
    /// `reclaim` must be one of them. A peer with delegations keeps its CIDR: the new delegations,
    /// if any, must lie in the CIDR of the current ones, so that a change never moves the peer to
    /// another CIDR, and so changes what it sees. The peer may be left without a delegation, which
    /// leaves it in effect disabled and without a CIDR, except the server's own peer, the one with
    /// the public key `server_key`, which must keep the delegation that holds `internal_address`,
    /// the address that the server serves its API on.
    ///
    /// The ranges must still hold every prefix of the delegation that the peer claims in the last
    /// announcement that it signed and the server accepted, since the server never takes back what
    /// a peer claims; a change that would is refused as [`ServerError::DelegationClaimed`]. The
    /// unsigned announcement that the server makes of a peer that has never announced claims every
    /// range, and doesn't hold them: what it pinned stays pinned to the peer's key, as on every
    /// client.
    pub fn set_delegations(
        &mut self,
        store: &Store,
        mut delegations: Vec<Prefix>,
        mut reclaim: Vec<Prefix>,
        server_key: &Key,
        internal_address: IpAddr,
    ) -> Result<(), ServerError> {
        delegations.sort();
        reclaim.sort();
        reclaim.dedup();
        if let Some(range) = reclaim.iter().find(|range| !delegations.contains(range)) {
            return Err(ServerError::Delegation(format!(
                "{range} is marked to be reclaimed, but is not one of the delegations"
            )));
        }
        // The more specific reason comes first: the server's own peer claims its delegations, but
        // keeps the one that holds the internal address because the API runs there.
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
        if let Some(claimed) = self.signed_announcement().and_then(|announcement| {
            announcement
                .claims
                .delegation
                .iter()
                .find(|claimed| !delegations.iter().any(|range| range.contains(claimed)))
        }) {
            return Err(ServerError::DelegationClaimed(format!(
                "the peer claims {claimed} in its announcement, so it must stay within one of its \
                 delegations"
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

        atomically(store, || {
            for withdrawn in self
                .delegations
                .iter()
                .filter(|old| !delegations.contains(old))
            {
                store.execute(
                    "DELETE FROM delegations WHERE address = ?1 AND prefix_len = ?2
                       AND public_key = ?3",
                    params![ip_to_bytes(withdrawn.first()), withdrawn.prefix_len(), key],
                )?;
            }
            for added in delegations
                .iter()
                .filter(|new| !self.delegations.contains(new))
            {
                insert_delegation(store, &key, added)?;
            }
            for range in &delegations {
                store.execute(
                    "UPDATE delegations SET reclaim = ?3 WHERE address = ?1 AND prefix_len = ?2",
                    params![
                        ip_to_bytes(range.first()),
                        range.prefix_len(),
                        reclaim.contains(range)
                    ],
                )?;
            }
            Self::admit_synthesized(store)
        })?;
        self.inner.delegations = delegations;
        self.reclaim = reclaim;
        self.reload_announced(store)
    }

    /// Sets the endpoint that the peer reports for itself.
    pub fn set_endpoint(
        &mut self,
        store: &Store,
        endpoint: Option<Endpoint>,
    ) -> Result<(), ServerError> {
        let key = self.key()?;
        atomically(store, || {
            write_endpoints(store, &key, EndpointKind::Endpoint, &endpoint)?;
            Self::admit_synthesized(store)
        })?;
        self.inner.endpoint = endpoint;
        self.reload_announced(store)
    }

    /// Sets the candidates that the peer reports for itself.
    pub fn set_candidates(
        &mut self,
        store: &Store,
        candidates: Vec<Endpoint>,
    ) -> Result<(), ServerError> {
        let key = self.key()?;
        atomically(store, || {
            write_endpoints(store, &key, EndpointKind::Candidate, &candidates)?;
            Self::admit_synthesized(store)
        })?;
        self.inner.candidates = candidates;
        self.reload_announced(store)
    }

    /// Accepts `signed`, an announcement of the peer, at the time `now`, as
    /// [`announcement::timestamp_now`] reads it. The coordinator's rules come first: the peer
    /// itself must sign it, make only claims of the types of [`announcement::CLAIM_TYPES`], and
    /// claim only what it is assigned, with a primary IP within its claimed delegation, as
    /// [`Announcement::check_assigned`] tells. The node core then accepts it as every node accepts
    /// what its coordinator vouches for, within the network of `node`: signed by the peer, newer
    /// than the last one accepted from it, not too far ahead of `now`, and claiming nothing pinned
    /// to another key. The server can't narrow what the peer signed, so it accepts the
    /// announcement whole or refuses it, each refusal as its [`ServerError`], and nothing of a
    /// refused one is stored.
    ///
    /// A range of the peer marked to be reclaimed, some of which the last signed announcement
    /// claimed and none of which this one claims, stops being assigned to the peer, so that a
    /// cooperative peer can move from it.
    ///
    /// The first announcement of a peer whose client was upgraded from plain HTTP replaces the
    /// endpoint and candidates that the peer had set over plain HTTP.
    pub fn announce(
        &mut self,
        store: &Store,
        signed: SignedAnnouncement,
        now: u64,
    ) -> Result<(), ServerError> {
        let key = self.key()?;
        if !signed.is_signed() {
            return Err(Refusal::Unsigned.into());
        }
        let opened = signed.open(&Key(key))?;
        signed.check_claim_types(&announcement::CLAIM_TYPES)?;
        opened
            .check_assigned(&self.inner.delegations, self.inner.name.as_ref())
            .map_err(|unassigned| ServerError::AnnouncementUnassigned(unassigned.to_string()))?;
        let all_types = accept::all_claim_types();
        let received = Received {
            public_key: &self.inner.public_key,
            announcement: &signed,
            checked_types: &all_types,
            repeats: false,
        };
        let previous = self
            .signed_announcement()
            .map(|previous| previous.claims.delegation.clone())
            .unwrap_or_default();
        let (accepted, reclaimed) = atomically(store, || {
            let accepted = store.accept_one(&received, now)??;
            let claims = |claimed: &[Prefix], range: &Prefix| {
                claimed.iter().any(|prefix| prefix.overlaps(range))
            };
            let reclaimed: Vec<Prefix> = self
                .reclaim
                .iter()
                .filter(|range| {
                    claims(&previous, range)
                        && !claims(&accepted.announcement.claims.delegation, range)
                })
                .copied()
                .collect();
            store.execute(
                "DELETE FROM endpoints WHERE public_key = ?1 AND kind IN (?2, ?3)",
                params![
                    key,
                    EndpointKind::Endpoint as i64,
                    EndpointKind::Candidate as i64
                ],
            )?;
            store.execute(
                "INSERT INTO relayed_announcements (public_key, payload, signature)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT (public_key) DO UPDATE SET
                   payload = excluded.payload, signature = excluded.signature",
                params![key, signed.payload, signed.signature],
            )?;
            for range in &reclaimed {
                store.execute(
                    "DELETE FROM delegations WHERE address = ?1 AND prefix_len = ?2
                       AND public_key = ?3",
                    params![ip_to_bytes(range.first()), range.prefix_len(), key],
                )?;
            }
            // What the announcement released may be what a peer that has never announced waits
            // for.
            Self::admit_synthesized(store)?;
            Ok((accepted, reclaimed))
        })?;
        for range in &reclaimed {
            log::info!("reclaimed {range} from {}.", **self);
        }
        self.inner.announcement = Some(signed);
        self.announced = Some(accepted.announcement);
        self.announces = true;
        self.inner.endpoint = None;
        self.inner.candidates = vec![];
        self.inner
            .delegations
            .retain(|range| !reclaimed.contains(range));
        self.reclaim.retain(|range| !reclaimed.contains(range));
        Ok(())
    }

    /// Hands the server's node core the unsigned announcement that the server makes of each peer
    /// that has never signed one, invitations included, as [`Announcement::synthetic`] makes it of
    /// what the server records of the peer, relayed on the server's own word, as a client takes it.
    /// The node core accepts or refuses it as every node does, as [`innernet_node::accept`]
    /// describes; a refusal is logged. What the server offers and assigns gates only what it
    /// accepts from now on, so a name that the server offers a peer while another key claims it
    /// takes no effect.
    ///
    /// The server calls it whenever what it records of such a peer changes, when it accepts a
    /// signed announcement, which may release what such a peer claims, and when it opens the
    /// database.
    pub fn admit_synthesized(store: &Store) -> Result<(), ServerError> {
        let peers: Vec<Self> = Self::list(store)?
            .into_iter()
            .filter(|peer| !peer.announces)
            .collect();
        let mut synthesized = vec![];
        for peer in &peers {
            match SignedAnnouncement::unsigned(&Announcement::synthetic(&peer.inner)) {
                Ok(unsigned) => synthesized.push((peer, unsigned)),
                Err(e) => log::warn!("making no announcement of peer {}: {e}", **peer),
            }
        }
        let all_types = accept::all_claim_types();
        let received: Vec<Received> = synthesized
            .iter()
            .map(|(peer, announcement)| Received {
                public_key: &peer.inner.public_key,
                announcement,
                checked_types: &all_types,
                repeats: true,
            })
            .collect();
        let now = announcement::timestamp_now();
        let decided = store.accept(&received, now)?;
        for ((peer, _), decided) in synthesized.iter().zip(decided) {
            if let Err(refusal) = decided {
                log::warn!(
                    "the server's node refuses the announcement that the server makes of peer \
                     {}: {refusal}",
                    peer.inner
                );
            }
        }
        Ok(())
    }

    /// Reads again the last announcement of the peer that the node core accepted.
    fn reload_announced(&mut self, store: &Store) -> Result<(), ServerError> {
        let key = self.key()?;
        self.announced = node_store::load_announcements(store, Some(&key))?
            .remove(&self.inner.public_key)
            .map(|stored| stored.announcement);
        Ok(())
    }

    /// Requires the peer to authenticate over TLS from now on.
    pub fn set_requires_tls(&mut self, store: &Store) -> Result<(), ServerError> {
        store.execute(
            "UPDATE peers SET tls = 1 WHERE public_key = ?1",
            params![self.key()?],
        )?;
        self.requires_tls = true;
        Ok(())
    }

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

        // The invitation's key was never the peer's, so nothing stays pinned to it: what the node
        // holds of the invitation goes, and what the server assigns and offers it follows the new
        // key, which the node then takes as it takes every peer that has never announced.
        let old_key = self.key()?;
        let new_key = key_to_bytes(pubkey)?;
        let redeemed = atomically(store, || {
            store.execute(
                "DELETE FROM announcements WHERE public_key = ?1",
                params![old_key],
            )?;
            store.execute(
                "DELETE FROM prefix_pins WHERE public_key = ?1",
                params![old_key],
            )?;
            let updated = store.execute(
                "UPDATE peers SET is_redeemed = 1, public_key = ?1, name = NULL
                 WHERE public_key = ?2 AND is_redeemed = 0",
                params![new_key, old_key],
            )?;
            if updated == 0 {
                return Err(ServerError::NotFound);
            }
            Self::admit_synthesized(store)
        });
        redeemed?;
        self.inner.public_key = pubkey.into();
        self.inner.is_redeemed = true;
        self.reload_announced(store)
    }

    /// Reads a peer from a row of [`COLUMNS`], without the name offered to it, its delegations,
    /// endpoint and candidates, and its announcement, which [`load`] fills in.
    fn from_row(row: &rusqlite::Row) -> Result<Self, rusqlite::Error> {
        let public_key = row_key(row, 0)?;
        let is_admin = row.get(1)?;
        let is_disabled = row.get(2)?;
        let is_redeemed = row.get(3)?;
        let invite_expires = row
            .get::<_, Option<u64>>(4)?
            .map(|unixtime| SystemTime::UNIX_EPOCH + Duration::from_secs(unixtime));
        let requires_tls = row.get(5)?;
        let announces = row.get(6)?;

        let persistent_keepalive_interval = Some(PERSISTENT_KEEPALIVE_INTERVAL_SECS);

        let inner = PeerContents {
            name: None,
            delegations: vec![],
            public_key,
            endpoint: None,
            persistent_keepalive_interval,
            is_admin,
            is_disabled,
            is_redeemed,
            invite_expires,
            candidates: vec![],
            announcement: None,
            allowed_ips: None,
            primary_ip: None,
        };
        Ok(Self {
            inner,
            requires_tls,
            announced: None,
            announces,
            reclaim: vec![],
        })
    }

    /// The peers of the rows that `sql` selects with `params`, each filled in as [`load`] does
    /// it, ordered by their hosts fallback addresses, those without one last, then by their
    /// public keys.
    fn query(
        store: &Store,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> Result<Vec<Self>, rusqlite::Error> {
        let mut stmt = store.prepare_cached(sql)?;
        let mut peers = stmt
            .query_map(params, Self::from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        load(store, &mut peers)?;
        peers.sort_by(|a, b| {
            let order = |peer: &Self| {
                let fallback = peer.hosts_fallback();
                (fallback.is_none(), fallback)
            };
            order(a)
                .cmp(&order(b))
                .then_with(|| a.public_key.cmp(&b.public_key))
        });
        Ok(peers)
    }

    /// The peer of the row that `sql` selects with `params`, filled in as [`load`] does it.
    fn query_one(
        store: &Store,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> Result<Self, rusqlite::Error> {
        let mut peer = store.query_row(sql, params, Self::from_row)?;
        load(store, std::slice::from_mut(&mut peer))?;
        Ok(peer)
    }

    /// The peer whose delegations hold the address `ip`.
    pub fn get_by_address(store: &Store, ip: IpAddr) -> Result<Self, rusqlite::Error> {
        // Delegations never overlap, so only the one with the highest first address at or below
        // `ip` may hold it.
        let address = ip_to_bytes(ip);
        let (public_key, last): ([u8; 32], Vec<u8>) = store.query_row(
            "SELECT public_key, last FROM delegations
             WHERE length(address) = length(?1) AND address <= ?1
             ORDER BY address DESC LIMIT 1",
            params![address],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if address > last {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        Self::get_from_public_key(store, &Key(public_key))
    }

    pub fn get_from_public_key(store: &Store, public_key: &Key) -> Result<Self, rusqlite::Error> {
        Self::query_one(
            store,
            &format!(
                "SELECT {} FROM peers WHERE public_key = ?1",
                COLUMNS.join(", ")
            ),
            params![public_key.0],
        )
    }

    /// The enabled, redeemed peers that the peer sees: the server's own peer, the one with the
    /// public key `server_key`, which every peer sees, and those whose CIDR lies within the peer's
    /// own CIDR, within an infra CIDR, which every peer sees, or within a CIDR associated with a
    /// CIDR that holds the peer's CIDR, its own or one of its ancestors. A peer's CIDR is that of
    /// its delegations, so a peer without a delegation is seen by none, and sees only the
    /// coordinator and the peers of the infra CIDRs.
    pub fn get_all_allowed_peers(
        &self,
        store: &Store,
        server_key: &Key,
    ) -> Result<Vec<Self>, ServerError> {
        let server_key = server_key.to_base64();
        let cidrs = DatabaseCidr::prefixes(&DatabaseCidr::list(store)?);
        let associations = DatabaseAssociation::list(store)?;
        let cidr_of = |peer: &Self| cidr_of_delegations(&peer.delegations, &cidrs);

        // The CIDRs whose peers, and those of their descendants, the peer sees.
        let mut visible = DatabaseCidr::infra(store)?;
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

        Ok(Self::list_enabled(store)?
            .into_iter()
            .filter(|peer| {
                peer.public_key == server_key
                    || cidr_of(peer)
                        .is_some_and(|cidr| visible.iter().any(|seen| seen.contains(&cidr)))
            })
            .collect())
    }

    /// Every peer, ordered by hosts fallback address.
    pub fn list(store: &Store) -> Result<Vec<Self>, ServerError> {
        Ok(Self::query(
            store,
            &format!("SELECT {} FROM peers", COLUMNS.join(", ")),
            params![],
        )?)
    }

    pub fn list_enabled(store: &Store) -> Result<Vec<Self>, ServerError> {
        Ok(Self::query(
            store,
            &format!(
                "SELECT {} FROM peers WHERE peers.is_redeemed = 1 AND peers.is_disabled = 0",
                COLUMNS.join(", ")
            ),
            params![],
        )?)
    }

    /// When the next invitation expires, if any does.
    pub fn next_invite_expiry(store: &Store) -> Result<Option<SystemTime>, ServerError> {
        let next: Option<u64> = store.query_row(
            "SELECT min(invite_expires) FROM peers WHERE is_redeemed = 0",
            [],
            |row| row.get(0),
        )?;
        Ok(next.map(|secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs)))
    }

    /// Deletes the invitations that expired, with everything that the node holds of them, as
    /// [`innernet_node::store::forget_peer`] does. Returns how many it deleted.
    pub fn delete_expired_invites(store: &Store) -> Result<usize, ServerError> {
        let unix_now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Something is horribly wrong with system time.");
        atomically(store, || {
            let expired: Vec<Vec<u8>> = store
                .prepare(
                    "SELECT public_key FROM peers WHERE is_redeemed = 0 AND invite_expires < ?1",
                )?
                .query_map(params![unix_now.as_secs()], |row| row.get(0))?
                .collect::<Result<_, _>>()?;
            for key in &expired {
                let key: [u8; 32] = key
                    .as_slice()
                    .try_into()
                    .map_err(|_| ServerError::InvalidQuery)?;
                node_store::forget_peer(store, &key)?;
            }
            Ok(expired.len())
        })
    }
}

/// Checks that `delegations` may be delegated together to a peer, as [`check_delegations`] does,
/// given the CIDRs of the database and the delegations that it holds for other peers than the one
/// with the public key `holder`, if any. Returns the CIDR of the peer, which its delegations
/// determine, or `None` for a peer without a delegation. A delegation that breaks the rules is
/// refused as [`ServerError::Delegation`], which explains why.
pub(crate) fn check_new_delegations(
    store: &Store,
    delegations: &[Prefix],
    holder: Option<&[u8; 32]>,
) -> Result<Option<Prefix>, ServerError> {
    let cidrs = DatabaseCidr::prefixes(&DatabaseCidr::list(store)?);
    let mut stmt = store.prepare_cached(
        "SELECT d.address, d.prefix_len, p.public_key, o.name
         FROM delegations d JOIN peers p ON p.public_key = d.public_key
              LEFT JOIN offered_names o ON o.public_key = p.public_key
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
            let public_key = row_key(row, 2)?;
            let holder = match row.get::<_, Option<String>>(3)? {
                Some(name) => format!("peer {name}"),
                None => format!("the peer with public key {public_key}"),
            };
            others.push((prefix, holder, public_key));
        }
    }
    let named = others
        .iter()
        .map(|(prefix, holder, _)| (prefix, holder.as_str()));
    check_delegations(delegations, &cidrs, named).map_err(|e| {
        log::warn!("refusing delegations {delegations:?}: {e}");
        let reason = e.to_string();
        // Delegations that are refused only for those of other peers overlap one of them, which
        // the error names, as check_delegations finds it.
        if check_delegations(delegations, &cidrs, []).is_err() {
            return ServerError::Delegation(reason);
        }
        others
            .iter()
            .find_map(|(held, _, holder)| {
                let prefix = delegations.iter().find(|prefix| prefix.overlaps(held))?;
                Some(ServerError::DelegationTaken {
                    reason: reason.clone(),
                    prefix: *prefix,
                    held: *held,
                    holder: holder.clone(),
                })
            })
            .unwrap_or(ServerError::Delegation(reason))
    })
}

/// Delegates `prefix` to the peer with the public key `key`. No address is delegated twice,
/// whether to the same peer or to two, so a prefix that overlaps a delegation is refused.
pub(crate) fn insert_delegation(
    store: &Store,
    key: &[u8; 32],
    prefix: &Prefix,
) -> Result<(), ServerError> {
    let overlapping: Option<Vec<u8>> = store
        .query_row(
            "SELECT address FROM delegations
             WHERE last >= ?1 AND address <= ?2 AND length(address) = length(?1)",
            params![ip_to_bytes(prefix.first()), ip_to_bytes(prefix.last())],
            |row| row.get(0),
        )
        .optional()?;
    if overlapping.is_some() {
        return Err(ServerError::Delegation(format!(
            "{prefix} overlaps a delegation"
        )));
    }
    store.execute(
        "INSERT INTO delegations (address, prefix_len, last, public_key) VALUES (?1, ?2, ?3, ?4)",
        params![
            ip_to_bytes(prefix.first()),
            prefix.prefix_len(),
            ip_to_bytes(prefix.last()),
            key
        ],
    )?;
    Ok(())
}

/// Peers by public key, and the public key of the only one, as the database holds it, if there is
/// only one.
type Index<'a> = (HashMap<String, &'a mut DatabasePeer>, Option<[u8; 32]>);

/// The peers of `peers` by public key, and the public key of the only one, as the database holds
/// it, so that a single peer is looked up by its key, and more than one by reading every row.
fn index(peers: &mut [DatabasePeer]) -> Result<Index<'_>, rusqlite::Error> {
    let by_key: HashMap<String, &mut DatabasePeer> = peers
        .iter_mut()
        .map(|peer| (peer.public_key.clone(), peer))
        .collect();
    let only_key = match by_key.keys().next() {
        Some(key) if by_key.len() == 1 => Some(
            key_to_bytes(key)
                .map_err(|_| rusqlite::Error::InvalidParameterName("public key".into()))?,
        ),
        _ => None,
    };
    Ok((by_key, only_key))
}

/// Fills in each of `peers` from the database: the name offered to it, its delegations, its
/// endpoint and candidates, and its last accepted announcement, decoded, and as the bytes that
/// the server relays.
fn load(store: &Store, peers: &mut [DatabasePeer]) -> Result<(), rusqlite::Error> {
    if peers.is_empty() {
        return Ok(());
    }
    load_offered_names(store, peers)?;
    load_delegations(store, peers)?;
    load_announcements(store, peers)?;
    load_endpoints(store, peers)?;
    load_relayed(store, peers)
}

/// Fills in the name offered to each of `peers` from the database.
fn load_offered_names(store: &Store, peers: &mut [DatabasePeer]) -> Result<(), rusqlite::Error> {
    let (mut by_key, only_key) = index(peers)?;
    let mut stmt = store.prepare_cached(
        "SELECT public_key, name FROM offered_names WHERE ?1 IS NULL OR public_key = ?1",
    )?;
    let mut rows = stmt.query(params![only_key])?;
    while let Some(row) = rows.next()? {
        if let Some(peer) = by_key.get_mut(&row_key(row, 0)?) {
            let name: String = row.get(1)?;
            peer.inner.name = Some(name.parse().map_err(|_| {
                rusqlite::Error::InvalidColumnType(1, "hostname".into(), Type::Text)
            })?);
        }
    }
    Ok(())
}

/// Fills in the last announcement of each of `peers` that the node core accepted, as it stores it
/// decoded.
fn load_announcements(store: &Store, peers: &mut [DatabasePeer]) -> Result<(), rusqlite::Error> {
    let (mut by_key, only_key) = index(peers)?;
    for (public_key, stored) in node_store::load_announcements(store, only_key.as_ref())? {
        if let Some(peer) = by_key.get_mut(&public_key) {
            peer.announced = Some(stored.announcement);
        }
    }
    Ok(())
}

/// Fills in the bytes of the last announcement accepted from each of `peers`, which the server
/// relays.
fn load_relayed(store: &Store, peers: &mut [DatabasePeer]) -> Result<(), rusqlite::Error> {
    let (mut by_key, only_key) = index(peers)?;
    let mut stmt = store.prepare_cached(
        "SELECT public_key, payload, signature FROM relayed_announcements
         WHERE ?1 IS NULL OR public_key = ?1",
    )?;
    let mut rows = stmt.query(params![only_key])?;
    while let Some(row) = rows.next()? {
        if let Some(peer) = by_key.get_mut(&row_key(row, 0)?) {
            peer.inner.announcement = Some(SignedAnnouncement {
                payload: row.get(1)?,
                signature: Some(row.get(2)?),
            });
        }
    }
    Ok(())
}

/// Offers `name` to the peer with the public key `key`, in place of any name offered to it, or no
/// name if `name` is `None`.
fn offer_name(store: &Store, key: &[u8; 32], name: Option<&str>) -> Result<(), ServerError> {
    store.execute(
        "DELETE FROM offered_names WHERE public_key = ?1",
        params![key],
    )?;
    if let Some(name) = name {
        store.execute(
            "INSERT INTO offered_names (public_key, name) VALUES (?1, ?2)",
            params![key, name],
        )?;
    }
    Ok(())
}

/// Fills in the delegations of each of `peers` from the database, in their order.
fn load_delegations(store: &Store, peers: &mut [DatabasePeer]) -> Result<(), rusqlite::Error> {
    let (mut by_key, only_key) = index(peers)?;
    let mut stmt = store.prepare_cached(
        "SELECT public_key, address, prefix_len, reclaim FROM delegations
         WHERE ?1 IS NULL OR public_key = ?1
         ORDER BY length(address), address",
    )?;
    let mut rows = stmt.query(params![only_key])?;
    while let Some(row) = rows.next()? {
        if let Some(peer) = by_key.get_mut(&row_key(row, 0)?) {
            let range = prefix_from_row(row.get(1)?, row.get(2)?)?;
            peer.inner.delegations.push(range);
            if row.get(3)? {
                peer.reclaim.push(range);
            }
        }
    }
    Ok(())
}

/// Fills in the endpoint and candidates of each of `peers` that the server records apart from
/// its announcements, those that a peer that has never announced set.
fn load_endpoints(store: &Store, peers: &mut [DatabasePeer]) -> Result<(), rusqlite::Error> {
    let (mut by_key, only_key) = index(peers)?;
    for (public_key, endpoints) in node_store::load_endpoints(store, only_key.as_ref())? {
        if let Some(peer) = by_key.get_mut(&public_key) {
            peer.inner.endpoint = endpoints.endpoint;
            peer.inner.candidates = endpoints.candidates;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test;
    use innernet_shared::Error;
    use ipnet::IpNet;

    /// Addresses of the user CIDR: the IP of a new peer, a wider prefix, an address within it,
    /// the first address past it, and an address between user2's IP and the prefix.
    fn user_addresses() -> [&'static str; 5] {
        if cfg!(feature = "v6-test") {
            [
                "fd00:1337::3:0:0:9",
                "fd00:1337::3:0:1:0/112",
                "fd00:1337::3:0:1:ff",
                "fd00:1337::3:0:2:0",
                "fd00:1337::3:0:0:ff",
            ]
        } else {
            [
                "10.80.128.9",
                "10.80.130.0/24",
                "10.80.130.200",
                "10.80.131.0",
                "10.80.129.200",
            ]
        }
    }

    #[test]
    fn test_delegations_follow_their_peer() -> Result<(), Error> {
        let server = test::Server::new()?;
        let store = server.db.lock();
        let [ip, wider, within, past, between] = user_addresses();
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
        insert_delegation(&store, &old_key.0, &wider.parse()?)?;

        // The peer is found by any address of its delegations, and by no other.
        let found = DatabasePeer::get_by_address(&store, within.parse()?)?;
        assert_eq!(found.public_key, invitee.public_key);
        assert_eq!(
            found.delegations,
            [Prefix::host(ip.parse()?), wider.parse()?]
        );
        assert_eq!(found.hosts_fallback(), Some(ip.parse()?));
        for address in [past, between] {
            assert!(matches!(
                DatabasePeer::get_by_address(&store, address.parse()?),
                Err(rusqlite::Error::QueryReturnedNoRows)
            ));
        }

        // The invitation is a peer of the node, which pins what it is assigned to its key.
        let rows = |table: &str, key: &Key| -> Result<i64, rusqlite::Error> {
            store.query_row(
                &format!("SELECT count(*) FROM {table} WHERE public_key = ?1"),
                [key.0],
                |r| r.get(0),
            )
        };
        assert_eq!(rows("prefix_pins", &old_key)?, 1);
        assert_eq!(rows("announcements", &old_key)?, 1);

        // The delegations follow the peer to its new key, while what the node held of the
        // invitation goes, and the node takes the peer anew under its key.
        let new_key = wireguard_control::KeyPair::generate().public;
        invitee.redeem(&store, &new_key.to_base64())?;
        assert_eq!(delegations(&old_key)?, 0);
        assert_eq!(delegations(&new_key)?, 2);
        for table in ["prefix_pins", "announcements", "peers"] {
            assert_eq!(rows(table, &old_key)?, 0, "{table}");
        }
        assert_eq!(rows("prefix_pins", &new_key)?, 2);
        assert_eq!(rows("announcements", &new_key)?, 1);
        let redeemed = DatabasePeer::get_by_address(&store, within.parse()?)?;
        assert_eq!(redeemed.public_key, new_key.to_base64());

        // They go with their peer when it is deleted, as an expired invitation is.
        let expired = DatabasePeer::create(
            &store,
            PeerContents {
                is_redeemed: false,
                invite_expires: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1)),
                ..test::user_peer_contents("expired", between)?
            },
        )?;
        let expired_key = Key::from_base64(&expired.public_key)?;
        assert_eq!(delegations(&expired_key)?, 1);
        assert_eq!(
            DatabasePeer::next_invite_expiry(&store)?,
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        );
        assert_eq!(DatabasePeer::delete_expired_invites(&store)?, 1);
        assert_eq!(delegations(&expired_key)?, 0);
        assert_eq!(DatabasePeer::next_invite_expiry(&store)?, None);
        assert!(DatabasePeer::get_by_address(&store, between.parse()?).is_err());
        Ok(())
    }

    #[test]
    fn test_delegations_never_overlap_nor_change() -> Result<(), Error> {
        let server = test::Server::new()?;
        let store = server.db.lock();
        let [_, wider, ..] = user_addresses();
        let user1 = test::peer(&store, test::USER1_PEER_ID);
        let user2 = test::peer(&store, test::USER2_PEER_ID);
        let user1_key = Key::from_base64(&user1.public_key)?;
        let user2_key = Key::from_base64(&user2.public_key)?;
        insert_delegation(&store, &user1_key.0, &wider.parse()?)?;
        let wider: Prefix = wider.parse()?;
        let narrower = Prefix::new(IpNet::new(wider.first(), wider.prefix_len() + 1)?)?;
        let enclosing = Prefix::new(IpNet::new(wider.first(), wider.prefix_len() - 1)?.trunc())?;

        // No other delegation shares an address with one, whether of the same peer or not.
        for (key, prefix) in [
            (&user2_key, wider),
            (&user2_key, narrower),
            (&user2_key, enclosing),
            (&user1_key, narrower),
            (&user2_key, user1.delegations[0]),
        ] {
            assert!(
                insert_delegation(&store, &key.0, &prefix).is_err(),
                "{prefix}"
            );
        }
        assert_eq!(
            test::peer(&store, test::USER1_PEER_ID).delegations,
            [user1.delegations[0], wider]
        );

        // The server explains the delegations it refuses to a new peer.
        let taken = test::user_peer_contents("user3", &wider.last().to_string())?;
        match DatabasePeer::create(&store, taken) {
            Err(ServerError::DelegationTaken {
                reason,
                prefix,
                held,
                holder,
            }) => {
                assert!(reason.contains("delegated to peer user1"), "{reason}");
                assert_eq!((prefix, held), (Prefix::host(wider.last()), wider));
                assert_eq!(holder, user1.public_key);
            },
            other => panic!("{other:?}"),
        }
        Ok(())
    }

    #[test]
    fn test_peers_without_a_delegation() -> Result<(), Error> {
        // A peer whose delegations are all gone has no address: it is listed last, and the view
        // of plain-HTTP sessions leaves it out.
        let server = test::Server::new()?;
        let store = server.db.lock();
        let cidrs = DatabaseCidr::list(&store)?;
        let user1 = test::peer(&store, test::USER1_PEER_ID);
        let legacy = user1.legacy(test::USER1_PEER_ID, &cidrs).unwrap();
        assert_eq!(Some(legacy.ip), user1.hosts_fallback());
        assert_eq!(legacy.cidr_id, test::USER_CIDR_ID);
        store.execute(
            "DELETE FROM delegations WHERE public_key = ?1",
            [Key::from_base64(&user1.public_key)?.0],
        )?;
        let user1 =
            DatabasePeer::get_from_public_key(&store, &Key::from_base64(&user1.public_key)?)?;
        assert!(user1.delegations.is_empty());
        assert!(user1.legacy(test::USER1_PEER_ID, &cidrs).is_none());
        let listed = DatabasePeer::list(&store)?;
        assert_eq!(listed.last().unwrap().public_key, user1.public_key);
        assert!(listed[..listed.len() - 1]
            .windows(2)
            .all(|pair| pair[0].hosts_fallback() < pair[1].hosts_fallback()));
        Ok(())
    }

    #[test]
    fn test_plain_http_ids() -> Result<(), Error> {
        // The view of plain-HTTP sessions numbers the peers and the CIDRs as it answers: every
        // peer names a CIDR of the view, every CIDR a parent of the view, and the IDs are the
        // same as long as the database is.
        let server = test::Server::new()?;
        let store = server.db.lock();
        let view = || -> Result<_, Error> {
            let cidrs = DatabaseCidr::list(&store)?;
            let ids = DatabasePeer::plain_http_ids(&store)?;
            let peers: Vec<_> = DatabasePeer::list(&store)?
                .iter()
                .filter_map(|peer| peer.legacy(ids[&peer.public_key], &cidrs))
                .collect();
            let cidrs: Vec<_> = cidrs.iter().map(|cidr| cidr.legacy(&cidrs)).collect();
            Ok((peers, cidrs))
        };
        let (peers, cidrs) = view()?;
        assert_eq!(view()?, (peers.clone(), cidrs.clone()));
        let cidr_ids: Vec<i64> = cidrs.iter().map(|cidr| cidr.id).collect();
        assert_eq!(cidr_ids, (1..=cidrs.len() as i64).collect::<Vec<_>>());
        assert!(peers.iter().all(|peer| cidr_ids.contains(&peer.cidr_id)));
        assert!(cidrs
            .iter()
            .all(|cidr| cidr.parent.is_none_or(|parent| cidr_ids.contains(&parent))));
        let peer_ids: Vec<i64> = peers.iter().map(|peer| peer.id).collect();
        assert_eq!(peer_ids, (1..=peers.len() as i64).collect::<Vec<_>>());

        // A new CIDR between the admin CIDR and the developer CIDR renumbers those after it.
        if cfg!(feature = "v6-test") {
            return Ok(());
        }
        DatabaseCidr::create(&store, "between".into(), "10.80.2.0/24".parse()?)?;
        let (peers, cidrs) = view()?;
        let between = cidrs.iter().find(|cidr| cidr.name == "between").unwrap();
        assert_eq!(
            (between.id, between.parent),
            (test::DEVELOPER_CIDR_ID, Some(test::ROOT_CIDR_ID))
        );
        let developer = cidrs.iter().find(|cidr| cidr.name == "developer").unwrap();
        assert_eq!(developer.id, test::DEVELOPER_CIDR_ID + 1);
        let cidr_ids: Vec<i64> = cidrs.iter().map(|cidr| cidr.id).collect();
        assert!(peers.iter().all(|peer| cidr_ids.contains(&peer.cidr_id)));
        Ok(())
    }

    #[test]
    fn test_endpoints_follow_their_peer() -> Result<(), Error> {
        let server = test::Server::new()?;
        let store = server.db.lock();
        // The endpoints that the peers set, apart from those that their announcements state.
        let endpoints = || -> Result<i64, rusqlite::Error> {
            store.query_row(
                "SELECT count(*) FROM endpoints WHERE kind IN (0, 1)",
                [],
                |r| r.get(0),
            )
        };
        let ip = if cfg!(feature = "v6-test") {
            "fd00:1337::3:0:0:9"
        } else {
            "10.80.128.9"
        };
        let mut invitee = DatabasePeer::create(
            &store,
            PeerContents {
                is_redeemed: false,
                ..test::user_peer_contents("invitee", ip)?
            },
        )?;
        // The server's own peer has an endpoint.
        let others = endpoints()?;

        // Endpoints of every shape round-trip, and the candidates keep their order.
        let endpoint: Endpoint = "vpn.example.com:51820".parse().unwrap();
        let candidates: Vec<Endpoint> = vec![
            "[2001:db8::1]:4000".parse().unwrap(),
            "192.0.2.1:1".parse().unwrap(),
            "0.0.0.0:51820".parse().unwrap(),
        ];
        invitee.set_endpoint(&store, Some(endpoint.clone()))?;
        invitee.set_candidates(&store, candidates.clone())?;
        let stored = invitee.reload(&store)?;
        assert_eq!(stored.endpoint, Some(endpoint.clone()));
        assert_eq!(stored.candidates, candidates);
        assert_eq!(endpoints()?, others + 4);

        // They follow the peer to its new key.
        let new_key = wireguard_control::KeyPair::generate().public;
        invitee.redeem(&store, &new_key.to_base64())?;
        let redeemed = DatabasePeer::get_from_public_key(&store, &new_key)?;
        assert_eq!(redeemed.endpoint, Some(endpoint.clone()));
        assert_eq!(redeemed.candidates, candidates);

        // They go with their peer when it is deleted, as an expired invitation is.
        let expired_ip = if cfg!(feature = "v6-test") {
            "fd00:1337::3:0:0:a"
        } else {
            "10.80.128.10"
        };
        let mut expired = DatabasePeer::create(
            &store,
            PeerContents {
                is_redeemed: false,
                invite_expires: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1)),
                ..test::user_peer_contents("expired", expired_ip)?
            },
        )?;
        expired.set_endpoint(&store, Some(endpoint))?;
        assert_eq!(endpoints()?, others + 5);
        assert_eq!(DatabasePeer::delete_expired_invites(&store)?, 1);
        assert_eq!(endpoints()?, others + 4);
        Ok(())
    }
}
