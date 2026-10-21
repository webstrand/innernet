//! A table to describe which CIDRs another CIDR is allowed to peer with.
//!
//! A peer belongs to one parent CIDR, and can by default see all peers within that parent.

use super::DatabaseCidr;
use crate::ServerError;
use innernet_node::store::{self, ip_to_bytes};
use innernet_shared::{Association, AssociationContents, Prefix};
use rusqlite::{params, Connection};
use std::ops::{Deref, DerefMut};

#[derive(Debug)]
pub struct DatabaseAssociation {
    pub inner: Association,
}

impl From<Association> for DatabaseAssociation {
    fn from(inner: Association) -> Self {
        Self { inner }
    }
}

impl Deref for DatabaseAssociation {
    type Target = Association;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for DatabaseAssociation {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl DatabaseAssociation {
    pub fn create(
        conn: &Connection,
        contents: AssociationContents,
    ) -> Result<Association, ServerError> {
        let AssociationContents {
            cidr_id_1,
            cidr_id_2,
        } = &contents;
        let cidrs = DatabaseCidr::list(conn)?;
        let prefix_of = |id: &i64| {
            cidrs
                .iter()
                .find(|cidr| cidr.id == *id)
                .and_then(|cidr| Prefix::new(cidr.cidr).ok())
                .ok_or(ServerError::InvalidQuery)
        };
        let (prefix_1, prefix_2) = (prefix_of(cidr_id_1)?, prefix_of(cidr_id_2)?);

        let existing = Self::list(conn)?.into_iter().any(|association| {
            let pair = (association.cidr_id_1, association.cidr_id_2);
            pair == (*cidr_id_1, *cidr_id_2) || pair == (*cidr_id_2, *cidr_id_1)
        });
        if existing {
            return Err(ServerError::InvalidQuery);
        }

        conn.execute(
            "INSERT INTO associations (address_1, prefix_len_1, address_2, prefix_len_2)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                ip_to_bytes(prefix_1.first()),
                prefix_1.prefix_len(),
                ip_to_bytes(prefix_2.first()),
                prefix_2.prefix_len()
            ],
        )?;
        let id = Self::list(conn)?
            .iter()
            .find(|association| {
                association.cidr_id_1 == contents.cidr_id_1
                    && association.cidr_id_2 == contents.cidr_id_2
            })
            .map(|association| association.id)
            .ok_or(ServerError::NotFound)?;
        Ok(Association { id, contents })
    }

    pub fn delete(conn: &Connection, id: i64) -> Result<(), ServerError> {
        let (prefix_1, prefix_2) = Self::stored(conn)?
            .into_iter()
            .zip(1..)
            .find(|(_, position)| *position == id)
            .map(|(pair, _)| pair)
            .ok_or(ServerError::NotFound)?;
        conn.execute(
            "DELETE FROM associations
             WHERE address_1 = ?1 AND prefix_len_1 = ?2 AND address_2 = ?3 AND prefix_len_2 = ?4",
            params![
                ip_to_bytes(prefix_1.first()),
                prefix_1.prefix_len(),
                ip_to_bytes(prefix_2.first()),
                prefix_2.prefix_len()
            ],
        )?;
        Ok(())
    }

    /// The associations, each as its pair of prefixes, in the order of the table.
    fn stored(conn: &Connection) -> Result<Vec<(Prefix, Prefix)>, ServerError> {
        let mut stmt = conn.prepare_cached(
            "SELECT address_1, prefix_len_1, address_2, prefix_len_2 FROM associations",
        )?;
        let mut rows = stmt.query([])?;
        let mut stored = vec![];
        while let Some(row) = rows.next()? {
            stored.push((
                store::prefix_from_row(row.get(0)?, row.get(1)?)?,
                store::prefix_from_row(row.get(2)?, row.get(3)?)?,
            ));
        }
        Ok(stored)
    }

    /// The associations, numbered from 1 in the order of the table, as the API of plain HTTP
    /// names them, each with the CIDRs that it joins by their IDs.
    pub fn list(conn: &Connection) -> Result<Vec<Association>, ServerError> {
        let cidrs = DatabaseCidr::list(conn)?;
        let id_of = |prefix: &Prefix| {
            cidrs
                .iter()
                .find(|cidr| cidr.cidr == prefix.net())
                .map(|cidr| cidr.id)
                .unwrap_or(0)
        };
        Ok(Self::stored(conn)?
            .into_iter()
            .zip(1..)
            .map(|((prefix_1, prefix_2), id)| Association {
                id,
                contents: AssociationContents {
                    cidr_id_1: id_of(&prefix_1),
                    cidr_id_2: id_of(&prefix_2),
                },
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use crate::test;
    use innernet_shared::{CidrContents, Error};

    use super::*;

    #[tokio::test]
    async fn test_double_add() -> Result<(), Error> {
        let server = test::Server::new()?;

        let contents = AssociationContents {
            cidr_id_1: 1,
            cidr_id_2: 2,
        };
        let contents_flipped = AssociationContents {
            cidr_id_1: 2,
            cidr_id_2: 1,
        };
        let res = server
            .form_request(
                test::ADMIN_PEER_IP,
                "POST",
                "/v1/admin/associations",
                &contents,
            )
            .await;
        assert!(res.status().is_success());

        let res = server
            .form_request(
                test::ADMIN_PEER_IP,
                "POST",
                "/v1/admin/associations",
                &contents,
            )
            .await;
        assert!(res.status().is_client_error());

        let res = server
            .form_request(
                test::ADMIN_PEER_IP,
                "POST",
                "/v1/admin/associations",
                &contents_flipped,
            )
            .await;
        assert!(res.status().is_client_error());
        Ok(())
    }

    #[tokio::test]
    async fn test_nonexistent_cidr_id() -> Result<(), Error> {
        let server = test::Server::new()?;

        // Verify both provided CIDR IDs exist
        let last_cidr_id: i64 =
            server
                .db()
                .lock()
                .query_row("SELECT COUNT(*) FROM cidrs", params![], |r| r.get(0))?;
        let contents = AssociationContents {
            cidr_id_1: 1,
            cidr_id_2: last_cidr_id + 1,
        };
        let res = server
            .form_request(
                test::ADMIN_PEER_IP,
                "POST",
                "/v1/admin/associations",
                &contents,
            )
            .await;
        assert!(!res.status().is_success());

        let cidr = CidrContents {
            name: "experimental".to_string(),
            cidr: test::EXPERIMENTAL_CIDR.parse()?,
            parent: Some(test::ROOT_CIDR_ID),
        };

        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/cidrs", &cidr)
            .await;
        assert!(res.status().is_success());

        let res = server
            .form_request(
                test::ADMIN_PEER_IP,
                "POST",
                "/v1/admin/associations",
                &contents,
            )
            .await;
        assert!(res.status().is_success());

        Ok(())
    }
}
