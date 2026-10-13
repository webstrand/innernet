use rusqlite::params;

pub mod association;
pub mod cidr;
pub mod peer;

pub use association::DatabaseAssociation;
pub use cidr::DatabaseCidr;
pub use peer::DatabasePeer;

const INVITE_EXPIRATION_VERSION: usize = 1;
const ENDPOINT_CANDIDATES_VERSION: usize = 2;
const NULLABLE_PEER_NAME_VERSION: usize = 3;
const ANNOUNCEMENT_VERSION: usize = 4;

pub const CURRENT_VERSION: usize = ANNOUNCEMENT_VERSION;

pub fn auto_migrate(conn: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    let old_version: usize = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    log::debug!("user_version: {}", old_version);

    if old_version < INVITE_EXPIRATION_VERSION {
        conn.execute(
            "ALTER TABLE peers ADD COLUMN invite_expires INTEGER",
            params![],
        )?;
    }

    if old_version < ENDPOINT_CANDIDATES_VERSION {
        conn.execute("ALTER TABLE peers ADD COLUMN candidates TEXT", params![])?;
    }

    if old_version < NULLABLE_PEER_NAME_VERSION {
        // SQLite cannot drop the NOT NULL constraint of a column, so the table is rebuilt. No
        // other table references the peers table. The schema is that of this version, since each
        // later version adds its columns in its own migration.
        conn.execute_batch(
            "BEGIN;
             ALTER TABLE peers RENAME TO peers_old;
             CREATE TABLE peers (
               id              INTEGER PRIMARY KEY,
               name            TEXT UNIQUE,
               ip              TEXT NOT NULL UNIQUE,
               public_key      TEXT NOT NULL UNIQUE,
               endpoint        TEXT,
               cidr_id         INTEGER NOT NULL,
               is_admin        INTEGER DEFAULT 0 NOT NULL,
               is_disabled     INTEGER DEFAULT 0 NOT NULL,
               is_redeemed     INTEGER DEFAULT 0 NOT NULL,
               invite_expires  INTEGER,
               candidates      TEXT,
               FOREIGN KEY (cidr_id)
                  REFERENCES cidrs (id)
                     ON UPDATE RESTRICT
                     ON DELETE RESTRICT
             );
             INSERT INTO peers SELECT id, name, ip, public_key, endpoint, cidr_id, is_admin,
               is_disabled, is_redeemed, invite_expires, candidates FROM peers_old;
             DROP TABLE peers_old;
             COMMIT;",
        )?;
    }

    if old_version < ANNOUNCEMENT_VERSION {
        conn.execute("ALTER TABLE peers ADD COLUMN announcement TEXT", params![])?;
    }

    if old_version != CURRENT_VERSION {
        conn.pragma_update(None, "user_version", CURRENT_VERSION)?;
        log::info!(
            "migrated db version from {} to {}",
            old_version,
            CURRENT_VERSION
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migrate_nullable_peer_name() -> Result<(), rusqlite::Error> {
        let conn = rusqlite::Connection::open_in_memory()?;
        conn.execute(
            &peer::CREATE_TABLE_SQL.replace("TEXT UNIQUE", "TEXT NOT NULL UNIQUE"),
            params![],
        )?;
        conn.pragma_update(None, "user_version", ENDPOINT_CANDIDATES_VERSION)?;
        conn.execute(
            "INSERT INTO peers (name, ip, cidr_id, public_key) VALUES ('peer1', '10.0.0.1', 1, 'a')",
            params![],
        )?;
        let insert_nameless =
            "INSERT INTO peers (ip, cidr_id, public_key) VALUES ('10.0.0.2', 1, 'b')";
        assert!(conn.execute(insert_nameless, params![]).is_err());

        auto_migrate(&conn)?;

        // The existing peer is kept, and a peer can now be without a name.
        let name: String =
            conn.query_row("SELECT name FROM peers WHERE id = 1", [], |r| r.get(0))?;
        assert_eq!(name, "peer1");
        conn.execute(insert_nameless, params![])?;

        Ok(())
    }
}
