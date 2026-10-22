//! A table to describe which CIDRs another CIDR is allowed to peer with.
//!
//! A peer belongs to one parent CIDR, and can by default see all peers within that parent.

use super::{ip_to_bytes, prefix_from_row, DatabaseCidr};
use crate::ServerError;
use innernet_node::Store;
use innernet_shared::{Association, Prefix};
use rusqlite::params;

/// The table of associations of servers that predate the rebuild of the database, which names
/// each association, and its CIDRs, by an ID.
#[cfg(test)]
pub static ORIGIN_TABLE_SQL: &str = "CREATE TABLE associations (
      id         INTEGER PRIMARY KEY,
      cidr_id_1  INTEGER NOT NULL,
      cidr_id_2  INTEGER NOT NULL,
      UNIQUE(cidr_id_1, cidr_id_2),
      FOREIGN KEY (cidr_id_1)
         REFERENCES cidrs (id)
            ON UPDATE RESTRICT
            ON DELETE RESTRICT,
      FOREIGN KEY (cidr_id_2)
         REFERENCES cidrs (id)
            ON UPDATE RESTRICT
            ON DELETE RESTRICT
    )";

/// An association of two CIDRs, whose peers see each other's. `cidr_1` is the lower of the two
/// prefixes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseAssociation {
    pub cidr_1: Prefix,
    pub cidr_2: Prefix,
}

impl DatabaseAssociation {
    /// The association as the API of TLS sessions transfers it.
    pub fn contents(&self) -> Association {
        Association {
            cidr_1: self.cidr_1,
            cidr_2: self.cidr_2,
        }
    }

    /// Associates the CIDRs `a` and `b`, which must be two CIDRs that no association names yet,
    /// in either order.
    pub fn create(store: &Store, a: Prefix, b: Prefix) -> Result<Self, ServerError> {
        let (cidr_1, cidr_2) = (a.min(b), a.max(b));
        if cidr_1 == cidr_2 {
            log::warn!("tried to associate the CIDR {cidr_1} with itself.");
            return Err(ServerError::InvalidQuery);
        }
        for prefix in [cidr_1, cidr_2] {
            if matches!(
                DatabaseCidr::get(store, &prefix),
                Err(ServerError::NotFound)
            ) {
                log::warn!("tried to associate the CIDR {prefix}, which doesn't exist.");
                return Err(ServerError::InvalidQuery);
            }
        }
        // An existing association of the two refuses the new one.
        store.execute(
            "INSERT INTO associations (address_1, prefix_len_1, address_2, prefix_len_2)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                ip_to_bytes(cidr_1.first()),
                cidr_1.prefix_len(),
                ip_to_bytes(cidr_2.first()),
                cidr_2.prefix_len()
            ],
        )?;
        Ok(Self { cidr_1, cidr_2 })
    }

    /// Deletes the association of the CIDRs `a` and `b`, in either order, or refuses with
    /// [`ServerError::NotFound`] if there is none.
    pub fn delete(store: &Store, a: &Prefix, b: &Prefix) -> Result<(), ServerError> {
        let (cidr_1, cidr_2) = (a.min(b), a.max(b));
        let deleted = store.execute(
            "DELETE FROM associations WHERE address_1 = ?1 AND prefix_len_1 = ?2
               AND address_2 = ?3 AND prefix_len_2 = ?4",
            params![
                ip_to_bytes(cidr_1.first()),
                cidr_1.prefix_len(),
                ip_to_bytes(cidr_2.first()),
                cidr_2.prefix_len()
            ],
        )?;
        match deleted {
            0 => Err(ServerError::NotFound),
            _ => Ok(()),
        }
    }

    /// Every association, ordered by its CIDRs.
    pub fn list(store: &Store) -> Result<Vec<Self>, ServerError> {
        let mut stmt = store.prepare_cached(
            "SELECT address_1, prefix_len_1, address_2, prefix_len_2 FROM associations
             ORDER BY length(address_1), address_1, prefix_len_1,
                      length(address_2), address_2, prefix_len_2",
        )?;
        let associations = stmt.query_map(params![], |row| {
            Ok(Self {
                cidr_1: prefix_from_row(row.get(0)?, row.get(1)?)?,
                cidr_2: prefix_from_row(row.get(2)?, row.get(3)?)?,
            })
        })?;
        Ok(associations.collect::<Result<Vec<_>, rusqlite::Error>>()?)
    }
}

#[cfg(test)]
mod tests {
    use crate::test;
    use hyper::StatusCode;
    use innernet_shared::Error;

    use super::*;

    #[tokio::test]
    async fn test_associations_by_prefix_over_tls() -> Result<(), Error> {
        // A TLS session names associations by the prefixes of their CIDRs, in either order.
        let server = test::Server::new()?;
        let developer: Prefix = test::DEVELOPER_CIDR.parse()?;
        let user: Prefix = test::USER_CIDR.parse()?;
        let association = Association {
            cidr_1: user,
            cidr_2: developer,
        };
        let post = |association: serde_json::Value| {
            server.form_request(
                test::ADMIN_PEER_IP,
                "POST",
                "/admin/associations",
                association,
            )
        };
        let res = server
            .form_request(
                test::ADMIN_PEER_IP,
                "POST",
                "/admin/associations",
                association,
            )
            .await;
        assert_eq!(res.status(), StatusCode::CREATED);
        let flipped = Association {
            cidr_1: developer,
            cidr_2: user,
        };
        let res = post(serde_json::to_value(flipped)?).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        // IDs aren't understood.
        let res = post(serde_json::json!({ "cidr_id_1": 1, "cidr_id_2": 2 })).await;
        assert!(res.status().is_client_error());

        let res = server
            .request(test::ADMIN_PEER_IP, "GET", "/admin/associations")
            .await;
        let listed: Vec<Association> = test::cbor_body(res).await?;
        assert_eq!(listed, [flipped]);

        // A deletion names the CIDRs in either order, and an unknown association is not found.
        let path = format!("/admin/associations/{}", association.api_path());
        let res = server.request(test::ADMIN_PEER_IP, "DELETE", &path).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        let res = server.request(test::ADMIN_PEER_IP, "DELETE", &path).await;
        test::problem(res, &innernet_shared::problem::NO_SUCH_ASSOCIATION).await?;
        // A path that names no pair of prefixes is no route of the server.
        for path in [
            "/admin/associations/1",
            &format!("/admin/associations/{}", user.api_path_segment()),
            &format!(
                "/admin/associations/{}/{}/x",
                user.api_path_segment(),
                developer.api_path_segment()
            ),
        ] {
            let res = server.request(test::ADMIN_PEER_IP, "DELETE", path).await;
            test::blank_problem(res, StatusCode::NOT_FOUND).await?;
        }

        // A deletion carries no body, and a content type that announces one is a malformed
        // request.
        let req = server.body_request("DELETE", &path, &test::content_type(), vec![]);
        let res = server.raw_request(test::ADMIN_PEER_IP, req).await;
        test::blank_problem(res, StatusCode::BAD_REQUEST).await?;
        Ok(())
    }

    #[test]
    fn test_associations_name_two_cidrs_once() -> Result<(), Error> {
        let server = test::Server::new()?;
        let store = server.db.lock();
        let developer: Prefix = test::DEVELOPER_CIDR.parse()?;
        let user: Prefix = test::USER_CIDR.parse()?;

        // A pair is held once, the lower prefix first, whichever order names it.
        let created = DatabaseAssociation::create(&store, user, developer)?;
        assert_eq!((created.cidr_1, created.cidr_2), (developer, user));
        assert!(DatabaseAssociation::create(&store, developer, user).is_err());
        assert!(DatabaseAssociation::create(&store, user, user).is_err());
        let absent: Prefix = test::EXPERIMENTAL_CIDR.parse()?;
        assert!(DatabaseAssociation::create(&store, absent, user).is_err());
        assert_eq!(
            DatabaseAssociation::list(&store)?,
            std::slice::from_ref(&created)
        );

        // The association is deleted, and then no longer found.
        DatabaseAssociation::delete(&store, &user, &developer)?;
        assert!(matches!(
            DatabaseAssociation::delete(&store, &user, &developer),
            Err(ServerError::NotFound)
        ));

        // A CIDR that an association names can't be deleted.
        let experimental = DatabaseCidr::create(&store, "experimental".into(), absent)?;
        let association = DatabaseAssociation::create(&store, experimental.prefix, developer)?;
        assert!(DatabaseCidr::delete(&store, &absent).is_err());
        DatabaseAssociation::delete(&store, &association.cidr_1, &association.cidr_2)?;
        DatabaseCidr::delete(&store, &absent)?;
        Ok(())
    }
}
