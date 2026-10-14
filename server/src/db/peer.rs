use super::DatabaseCidr;
use crate::ServerError;
use innernet_shared::{
    announcement::SignedAnnouncement, xeddsa, IpNetExt, Peer, PeerContents,
    PERSISTENT_KEEPALIVE_INTERVAL_SECS,
};
use rusqlite::{params, types::Type, Connection};
use std::{
    net::IpAddr,
    ops::{Deref, DerefMut},
    time::{Duration, SystemTime},
};
use wireguard_control::Key;

pub static CREATE_TABLE_SQL: &str = "CREATE TABLE peers (
      id              INTEGER PRIMARY KEY,
      name            TEXT UNIQUE,                  /* The canonical name for the peer, or NULL if it has none.         */
      ip              TEXT NOT NULL UNIQUE,         /* The WireGuard-internal IP address assigned to the peer.          */
      public_key      TEXT NOT NULL UNIQUE,         /* The WireGuard public key of the peer.                            */
      endpoint        TEXT,                         /* The optional external endpoint ([ip]:[port]) of the peer.        */
      cidr_id         INTEGER NOT NULL,             /* The ID of the peer's parent CIDR.                                */
      is_admin        INTEGER DEFAULT 0 NOT NULL,   /* Admin capabilities are per-peer, not per-CIDR.                   */
      is_disabled     INTEGER DEFAULT 0 NOT NULL,   /* Is the peer disabled? (only disabled peers can be deleted)       */
      is_redeemed     INTEGER DEFAULT 0 NOT NULL,   /* Has the peer redeemed their invite yet?                          */
      invite_expires  INTEGER,                      /* The UNIX time that an invited peer can no longer redeem.         */
      candidates      TEXT,                         /* A list of additional endpoints that peers can use to connect.    */
      announcement    TEXT,                         /* The peer's latest signed endpoint announcement (JSON).           */
      requires_tls    INTEGER DEFAULT 0 NOT NULL,   /* Must the peer authenticate over TLS rather than by its IP?       */
      FOREIGN KEY (cidr_id)
         REFERENCES cidrs (id)
            ON UPDATE RESTRICT
            ON DELETE RESTRICT
    )";

pub static COLUMNS: &[&str] = &[
    "id",
    "name",
    "ip",
    "cidr_id",
    "public_key",
    "endpoint",
    "is_admin",
    "is_disabled",
    "is_redeemed",
    "invite_expires",
    "candidates",
    "announcement",
    "requires_tls",
];

#[derive(Debug)]
pub struct DatabasePeer {
    pub inner: Peer,
    /// Whether the peer must authenticate over TLS with its key, and is refused when it
    /// connects in plain HTTP, authenticated only by its source IP. Set for good once the
    /// peer has connected over TLS, and from creation for admins.
    pub requires_tls: bool,
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
    pub fn create(conn: &Connection, contents: PeerContents) -> Result<Self, ServerError> {
        // Announcements can only be made by the peer itself, through `set_announcement`.
        let contents = PeerContents {
            announcement: None,
            observed_endpoint: None,
            ..contents
        };
        let PeerContents {
            name,
            ip,
            cidr_id,
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

        let cidr = DatabaseCidr::get(conn, *cidr_id)?;
        if !cidr.cidr.contains(ip) {
            log::warn!("tried to add peer with IP outside of parent CIDR range.");
            return Err(ServerError::InvalidQuery);
        }

        if !cidr.cidr.is_assignable(ip) {
            println!(
                "Peer IP {} is not unicast assignable in CIDR {}",
                ip, cidr.cidr
            );
            return Err(ServerError::InvalidQuery);
        }

        let invite_expires = invite_expires
            .map(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .flatten()
            .map(|t| t.as_secs());

        let candidates = serde_json::to_string(candidates)?;

        // Admins only ever come into existence on a client that connects over TLS, so that
        // nothing else on their machine can act with their rights.
        let requires_tls = *is_admin;

        conn.execute(
            &format!(
                "INSERT INTO peers ({}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, ?11)",
                COLUMNS[1..].join(", ")
            ),
            params![
                name.as_deref(),
                ip.to_string(),
                cidr_id,
                &public_key,
                endpoint.as_ref().map(|endpoint| endpoint.to_string()),
                is_admin,
                is_disabled,
                is_redeemed,
                invite_expires,
                candidates,
                requires_tls,
            ],
        )?;
        let id = conn.last_insert_rowid();
        Ok(Self {
            inner: Peer { id, contents },
            requires_tls,
        })
    }

    /// Peers are looked up by the key they authenticate with over TLS, encoded canonically.
    fn is_valid_public_key(public_key: &str) -> bool {
        Key::from_base64(public_key)
            .is_ok_and(|key| xeddsa::is_valid_public_key(&key) && key.to_base64() == public_key)
    }

    /// Update self with new contents, validating them and updating the backend in the process.
    pub fn update(&mut self, conn: &Connection, contents: PeerContents) -> Result<(), ServerError> {
        // We will only allow updates of certain fields at this point, disregarding any requests
        // for changes of IP address, public key, or parent CIDR, for security reasons.
        //
        // In the future, we may allow re-assignments of peers to new CIDRs, but it's easiest to
        // disregard that case for now to prevent possible attacks.
        if contents.is_admin && !self.is_admin && !self.requires_tls {
            log::warn!(
                "refusing to make {} an admin before it connects over TLS.",
                **self
            );
            return Err(ServerError::PromotionRequiresTls);
        }
        let new_contents = PeerContents {
            name: contents.name,
            endpoint: contents.endpoint,
            is_admin: contents.is_admin,
            is_disabled: contents.is_disabled,
            candidates: contents.candidates,
            ..self.contents.clone()
        };

        let new_candidates = serde_json::to_string(&new_contents.candidates)?;
        conn.execute(
            "UPDATE peers SET
                name = ?2,
                endpoint = ?3,
                is_admin = ?4,
                is_disabled = ?5,
                candidates = ?6
            WHERE id = ?1",
            params![
                self.id,
                new_contents.name.as_deref(),
                new_contents
                    .endpoint
                    .as_ref()
                    .map(|endpoint| endpoint.to_string()),
                new_contents.is_admin,
                new_contents.is_disabled,
                new_candidates,
            ],
        )?;

        self.contents = new_contents;
        Ok(())
    }

    /// Stores an announcement already verified to be newer than the current one, and mirrors
    /// its candidates for clients that don't understand announcements.
    pub fn set_announcement(
        &mut self,
        conn: &Connection,
        announcement: SignedAnnouncement,
    ) -> Result<(), ServerError> {
        let candidates = announcement.announcement.candidates.clone();
        conn.execute(
            "UPDATE peers SET announcement = ?2, candidates = ?3 WHERE id = ?1",
            params![
                self.id,
                serde_json::to_string(&announcement)?,
                serde_json::to_string(&candidates)?,
            ],
        )?;
        self.contents.announcement = Some(announcement);
        self.contents.candidates = candidates;
        Ok(())
    }

    /// Requires the peer to authenticate over TLS from now on.
    pub fn set_requires_tls(&mut self, conn: &Connection) -> Result<(), ServerError> {
        conn.execute(
            "UPDATE peers SET requires_tls = 1 WHERE id = ?1",
            params![self.id],
        )?;
        self.requires_tls = true;
        Ok(())
    }

    pub fn disable(conn: &Connection, id: i64) -> Result<(), ServerError> {
        match conn.execute(
            "UPDATE peers SET is_disabled = 1 WHERE id = ?1",
            params![id],
        )? {
            0 => Err(ServerError::NotFound),
            _ => Ok(()),
        }
    }

    /// Permanently deletes a disabled peer, freeing its name and IP for reuse.
    ///
    /// Clients pin each peer's (IP, public key) pair, so clients that have seen this peer
    /// refuse a new peer at the same IP until `innernet forget-peer` has been run on them.
    pub fn delete(conn: &Connection, id: i64) -> Result<(), ServerError> {
        match conn.execute(
            "DELETE FROM peers WHERE id = ?1 AND is_disabled = 1",
            params![id],
        )? {
            0 => {
                // An enabled peer is distinguished from a nonexistent one.
                Self::get(conn, id)?;
                log::warn!("refusing to delete peer {id}, it must be disabled first.");
                Err(ServerError::InvalidQuery)
            },
            _ => Ok(()),
        }
    }

    pub fn redeem(&mut self, conn: &Connection, pubkey: &str) -> Result<(), ServerError> {
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

        match conn.execute(
            "UPDATE peers SET is_redeemed = 1, public_key = ?1, announcement = NULL
            WHERE id = ?2 AND is_redeemed = 0",
            params![pubkey, self.id],
        )? {
            0 => Err(ServerError::NotFound),
            _ => {
                self.contents.public_key = pubkey.into();
                self.contents.is_redeemed = true;
                self.contents.announcement = None;
                Ok(())
            },
        }
    }

    fn from_row(row: &rusqlite::Row) -> Result<Self, rusqlite::Error> {
        let id = row.get(0)?;
        let name = row
            .get::<_, Option<String>>(1)?
            .map(|name| name.parse())
            .transpose()
            .map_err(|_| rusqlite::Error::InvalidColumnType(1, "hostname".into(), Type::Text))?;
        let ip: IpAddr = row
            .get::<_, String>(2)?
            .parse()
            .map_err(|_| rusqlite::Error::InvalidColumnType(2, "ip".into(), Type::Text))?;
        let cidr_id = row.get(3)?;
        let public_key = row.get(4)?;
        let endpoint = row
            .get::<_, Option<String>>(5)?
            .and_then(|endpoint| endpoint.parse().ok());
        let is_admin = row.get(6)?;
        let is_disabled = row.get(7)?;
        let is_redeemed = row.get(8)?;
        let invite_expires = row
            .get::<_, Option<u64>>(9)?
            .map(|unixtime| SystemTime::UNIX_EPOCH + Duration::from_secs(unixtime));

        let candidates = if let Some(candidates) = row.get::<_, Option<String>>(10)? {
            serde_json::from_str(&candidates).map_err(|_| {
                rusqlite::Error::InvalidColumnType(10, "candidates (json)".into(), Type::Text)
            })?
        } else {
            vec![]
        };

        let announcement = if let Some(announcement) = row.get::<_, Option<String>>(11)? {
            serde_json::from_str(&announcement).map_err(|_| {
                rusqlite::Error::InvalidColumnType(11, "announcement (json)".into(), Type::Text)
            })?
        } else {
            None
        };

        let requires_tls = row.get(12)?;

        let persistent_keepalive_interval = Some(PERSISTENT_KEEPALIVE_INTERVAL_SECS);

        let inner = Peer {
            id,
            contents: PeerContents {
                name,
                ip,
                cidr_id,
                public_key,
                endpoint,
                persistent_keepalive_interval,
                is_admin,
                is_disabled,
                is_redeemed,
                invite_expires,
                candidates,
                announcement,
                observed_endpoint: None,
            },
        };
        Ok(Self {
            inner,
            requires_tls,
        })
    }

    pub fn get(conn: &Connection, id: i64) -> Result<Self, ServerError> {
        let result = conn.query_row(
            &format!("SELECT {} FROM peers WHERE id = ?1", COLUMNS.join(", ")),
            params![id],
            Self::from_row,
        )?;

        Ok(result)
    }

    pub fn get_from_ip(conn: &Connection, ip: IpAddr) -> Result<Self, rusqlite::Error> {
        let result = conn.query_row(
            &format!("SELECT {} FROM peers WHERE ip = ?1", COLUMNS.join(", ")),
            params![ip.to_string()],
            Self::from_row,
        )?;

        Ok(result)
    }

    pub fn get_from_public_key(
        conn: &Connection,
        public_key: &Key,
    ) -> Result<Self, rusqlite::Error> {
        conn.query_row(
            &format!(
                "SELECT {} FROM peers WHERE public_key = ?1",
                COLUMNS.join(", ")
            ),
            params![public_key.to_base64()],
            Self::from_row,
        )
    }

    pub fn get_all_allowed_peers(&self, conn: &Connection) -> Result<Vec<Self>, ServerError> {
        // This query is a handful, so an explanation of what's happening, and what each CTE does (https://sqlite.org/lang_with.html):
        //
        // 1. parent_of: Enumerate all ancestor CIDRs of the CIDR associated with peer.
        // 2. associated: Enumerate all auth associations between any of the above enumerated CIDRs.
        // 3. associated_subcidrs: For each association, list all peers by enumerating down each
        //    associated CIDR's children and listing any peers belonging to them.
        //
        // NOTE that a forced association is created with the special "infra" CIDR with id 2 (1 being the root).
        let mut stmt = conn.prepare_cached(
            &format!("WITH
                parent_of(id, parent) AS (
                    SELECT id, parent FROM cidrs WHERE id = ?1
                    UNION ALL
                    SELECT cidrs.id, cidrs.parent FROM cidrs JOIN parent_of ON parent_of.parent = cidrs.id
                ),
                associated(cidr_id) as (
                    SELECT associations.cidr_id_2 FROM associations, parent_of WHERE associations.cidr_id_1 = parent_of.id
                    UNION
                    SELECT associations.cidr_id_1 FROM associations, parent_of WHERE associations.cidr_id_2 = parent_of.id
                ),
                associated_subcidrs(cidr_id) AS (
                    VALUES(?1), (2)
                    UNION
                    SELECT cidr_id FROM associated
                    UNION
                    SELECT id FROM cidrs, associated_subcidrs WHERE cidrs.parent=associated_subcidrs.cidr_id
                )
                SELECT DISTINCT {}
                FROM peers
                JOIN associated_subcidrs ON peers.cidr_id=associated_subcidrs.cidr_id
                WHERE peers.is_disabled = 0 AND peers.is_redeemed = 1;",
                COLUMNS.iter().map(|col| format!("peers.{col}")).collect::<Vec<_>>().join(", ")
            ),
        )?;
        let peers = stmt
            .query_map(params![self.cidr_id], Self::from_row)?
            .collect::<Result<_, _>>()?;
        Ok(peers)
    }

    pub fn list(conn: &Connection) -> Result<Vec<Self>, ServerError> {
        let mut stmt = conn.prepare_cached(&format!("SELECT {} FROM peers", COLUMNS.join(", ")))?;
        let peer_iter = stmt.query_map(params![], Self::from_row)?;

        Ok(peer_iter.collect::<Result<_, _>>()?)
    }

    pub fn list_enabled(conn: &Connection) -> Result<Vec<Self>, ServerError> {
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT {} FROM peers WHERE peers.is_redeemed = 1 AND peers.is_disabled = 0",
            COLUMNS.join(", ")
        ))?;
        let peer_iter = stmt.query_map(params![], Self::from_row)?;

        Ok(peer_iter.collect::<Result<_, _>>()?)
    }

    pub fn delete_expired_invites(conn: &Connection) -> Result<usize, ServerError> {
        let unix_now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Something is horribly wrong with system time.");
        let deleted = conn.execute(
            "DELETE FROM peers
            WHERE is_redeemed = 0 AND invite_expires < ?1",
            params![unix_now.as_secs()],
        )?;

        Ok(deleted)
    }
}
