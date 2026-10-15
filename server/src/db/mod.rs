use rusqlite::params;

pub mod association;
pub mod cidr;
pub mod peer;

pub use association::DatabaseAssociation;
pub use cidr::DatabaseCidr;
pub use peer::DatabasePeer;

const INVITE_EXPIRATION_VERSION: usize = 1;
const ENDPOINT_CANDIDATES_VERSION: usize = 2;

pub const CURRENT_VERSION: usize = ENDPOINT_CANDIDATES_VERSION;

/// Migrates the database to [`CURRENT_VERSION`].
///
/// Each migration checks whether it already ran rather than trusting `user_version` alone: a
/// version that doesn't know a migration rewrites `user_version` to its own when it opens the
/// database, so after a downgrade and an upgrade, migrations that already ran are run again.
pub fn auto_migrate(conn: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    let old_version: usize = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    log::debug!("user_version: {}", old_version);

    if old_version < INVITE_EXPIRATION_VERSION && !has_column(conn, "peers", "invite_expires")? {
        conn.execute(
            "ALTER TABLE peers ADD COLUMN invite_expires INTEGER",
            params![],
        )?;
    }

    if old_version < ENDPOINT_CANDIDATES_VERSION && !has_column(conn, "peers", "candidates")? {
        conn.execute("ALTER TABLE peers ADD COLUMN candidates TEXT", params![])?;
    }

    // A newer version's database keeps its version, so that its migrations aren't run again.
    if old_version < CURRENT_VERSION {
        conn.pragma_update(None, "user_version", CURRENT_VERSION)?;
        log::info!(
            "migrated db version from {} to {}",
            old_version,
            CURRENT_VERSION
        );
    }

    Ok(())
}

/// Whether `table` has a column named `column`.
fn has_column(
    conn: &rusqlite::Connection,
    table: &str,
    column: &str,
) -> Result<bool, rusqlite::Error> {
    conn.query_row(
        "SELECT count(*) FROM pragma_table_info(?1) WHERE name = ?2",
        params![table, column],
        |row| row.get::<_, i64>(0),
    )
    .map(|count| count > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migrate_again() -> Result<(), rusqlite::Error> {
        // A database whose user_version was rewritten to an older version, as a downgrade does,
        // migrates again without failing.
        let conn = rusqlite::Connection::open_in_memory()?;
        conn.execute(cidr::CREATE_TABLE_SQL, params![])?;
        conn.execute(peer::CREATE_TABLE_SQL, params![])?;
        conn.execute(association::CREATE_TABLE_SQL, params![])?;
        for version in 0..CURRENT_VERSION {
            conn.pragma_update(None, "user_version", version)?;
            auto_migrate(&conn)?;
            let migrated: usize = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
            assert_eq!(migrated, CURRENT_VERSION);
        }

        // A newer version's database keeps its version.
        conn.pragma_update(None, "user_version", CURRENT_VERSION + 1)?;
        auto_migrate(&conn)?;
        let version: usize = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        assert_eq!(version, CURRENT_VERSION + 1);
        Ok(())
    }
}
