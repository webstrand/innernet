use crate::ServerError;
use innernet_node::store::{self, ip_to_bytes, StoredCidr};
use innernet_shared::{Cidr, CidrContents, Prefix};
use rusqlite::{params, Connection};
use std::ops::{Deref, DerefMut};

/// A CIDR of the coordinator's database, with the ID by which the API of plain HTTP names it, as
/// [`DatabaseCidr::list`] numbers them, and the ID of its parent, the smallest other CIDR that
/// holds it.
pub struct DatabaseCidr {
    inner: Cidr,
}

impl From<Cidr> for DatabaseCidr {
    fn from(inner: Cidr) -> Self {
        Self { inner }
    }
}

impl Deref for DatabaseCidr {
    type Target = Cidr;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for DatabaseCidr {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl DatabaseCidr {
    /// Creates the CIDR `contents`, which must lie at its place in the tree, under its parent,
    /// a CIDR that no peer lies in, and overlap none of its siblings. A CIDR without a parent is
    /// the root.
    pub fn create(conn: &Connection, contents: CidrContents) -> Result<Cidr, ServerError> {
        let CidrContents { name, cidr, parent } = &contents;

        log::debug!("creating {:?}", contents);

        let cidrs = Self::list(conn)?;
        if let Some(parent_id) = parent {
            let parent_cidr = cidrs
                .iter()
                .find(|current| current.id == *parent_id)
                .ok_or(ServerError::NotFound)?;
            let attached_peers = super::DatabasePeer::list(conn)?
                .iter()
                .any(|peer| peer.cidr_id == *parent_id);
            if attached_peers {
                log::warn!("tried to add a CIDR to a parent that has peers assigned to it.");
                return Err(ServerError::InvalidQuery);
            }

            let closest_parent = cidrs
                .iter()
                .filter(|current| current.cidr.contains(cidr))
                .max_by_key(|current| current.cidr.prefix_len());
            match closest_parent {
                Some(closest_parent) if closest_parent.id != *parent_id => {
                    log::warn!("tried to add a CIDR at the incorrect place in the tree (should be added to {}).", closest_parent.name);
                    return Err(ServerError::InvalidQuery);
                },
                None => {
                    log::warn!("tried to add a CIDR outside of the root network range.");
                    return Err(ServerError::InvalidQuery);
                },
                _ => {},
            }

            if !parent_cidr.cidr.contains(&cidr.network())
                || !parent_cidr.cidr.contains(&cidr.broadcast())
            {
                log::warn!("tried to add a CIDR with a network range outside of its parent.");
                return Err(ServerError::InvalidQuery);
            }
        }

        let overlapping_sibling = cidrs
            .iter()
            .filter(|current| current.parent == *parent)
            .map(|sibling| sibling.cidr)
            .any(|sibling| {
                cidr.contains(&sibling.network())
                    || cidr.contains(&sibling.broadcast())
                    || sibling.contains(&cidr.network())
                    || sibling.contains(&cidr.broadcast())
            });
        if overlapping_sibling {
            log::warn!("tried to add a CIDR that overlaps with a sibling.");
            return Err(ServerError::InvalidQuery);
        }

        let prefix = Prefix::new(cidr.trunc()).map_err(|_| ServerError::InvalidQuery)?;
        store::insert_cidr(
            conn,
            &StoredCidr {
                prefix,
                name: name.clone(),
                infra: false,
            },
        )?;
        let id = Self::id_of(conn, &prefix)?.ok_or(ServerError::NotFound)?;
        Ok(Cidr { id, contents })
    }

    /// The CIDRs as the node records them, each with its ID, its position from 1 in the order of
    /// their prefixes, by which the API of plain HTTP names it. The IDs are consistent within one
    /// response, which is all that the clients of that API rely on: creating or deleting a CIDR
    /// renumbers the CIDRs after it.
    fn stored(conn: &Connection) -> Result<Vec<(i64, StoredCidr)>, ServerError> {
        Ok((1..).zip(store::load_cidrs(conn)?).collect())
    }

    /// The ID of the CIDR of `prefix`, if there is one.
    fn id_of(conn: &Connection, prefix: &Prefix) -> Result<Option<i64>, ServerError> {
        Ok(Self::stored(conn)?
            .into_iter()
            .find(|(_, cidr)| cidr.prefix == *prefix)
            .map(|(id, _)| id))
    }

    /// The prefix of the CIDR with the ID `id`.
    fn prefix_of(conn: &Connection, id: i64) -> Result<Prefix, ServerError> {
        Self::stored(conn)?
            .into_iter()
            .find(|(position, _)| *position == id)
            .map(|(_, cidr)| cidr.prefix)
            .ok_or(ServerError::NotFound)
    }

    /// Marks the CIDR with the ID `id` as infra, whose peers every peer sees.
    pub fn set_infra(conn: &Connection, id: i64) -> Result<(), ServerError> {
        let prefix = Self::prefix_of(conn, id)?;
        conn.execute(
            "UPDATE cidrs SET infra = 1 WHERE address = ?1 AND prefix_len = ?2",
            params![ip_to_bytes(prefix.first()), prefix.prefix_len()],
        )?;
        Ok(())
    }

    /// Whether the CIDR with the ID `id` is infra.
    pub fn is_infra(conn: &Connection, id: i64) -> Result<bool, ServerError> {
        Ok(Self::stored(conn)?
            .into_iter()
            .any(|(position, cidr)| position == id && cidr.infra))
    }

    /// Update self with new contents, validating them and updating the backend in the process.
    /// Currently this only supports updating the name and ignores changes to any other field.
    pub fn update(&mut self, conn: &Connection, contents: CidrContents) -> Result<(), ServerError> {
        let new_contents = CidrContents {
            name: contents.name,
            ..self.contents.clone()
        };

        let prefix = Self::prefix_of(conn, self.id)?;
        conn.execute(
            "UPDATE cidrs SET name = ?3 WHERE address = ?1 AND prefix_len = ?2",
            params![
                ip_to_bytes(prefix.first()),
                prefix.prefix_len(),
                &*new_contents.name
            ],
        )?;

        self.contents = new_contents;
        Ok(())
    }

    /// Deletes the CIDR with the ID `id`, which must hold no peer and no other CIDR. The database
    /// refuses to delete one that an association names.
    pub fn delete(conn: &Connection, id: i64) -> Result<(), ServerError> {
        let cidrs = Self::list(conn)?;
        let cidr = cidrs
            .iter()
            .find(|cidr| cidr.id == id)
            .ok_or(ServerError::NotFound)?;
        let holds_peer = super::DatabasePeer::list(conn)?.iter().any(|peer| {
            peer.delegations
                .iter()
                .any(|delegation| cidr.cidr.contains(&delegation.net()))
        });
        let holds_cidr = cidrs.iter().any(|other| other.parent == Some(id));
        if holds_peer || holds_cidr {
            log::warn!("tried to delete a CIDR that holds peers or other CIDRs.");
            return Err(ServerError::InvalidQuery);
        }
        let prefix = Self::prefix_of(conn, id)?;
        conn.execute(
            "DELETE FROM cidrs WHERE address = ?1 AND prefix_len = ?2",
            params![ip_to_bytes(prefix.first()), prefix.prefix_len()],
        )?;
        Ok(())
    }

    pub fn get(conn: &Connection, id: i64) -> Result<Cidr, ServerError> {
        Self::list(conn)?
            .into_iter()
            .find(|cidr| cidr.id == id)
            .ok_or(ServerError::NotFound)
    }

    /// Every CIDR, ordered by prefix, each with its ID, as [`Self::stored`] numbers them, and the
    /// smallest other CIDR that holds it as its parent.
    pub fn list(conn: &Connection) -> Result<Vec<Cidr>, ServerError> {
        let mut cidrs: Vec<Cidr> = Self::stored(conn)?
            .into_iter()
            .map(|(id, cidr)| Cidr {
                id,
                contents: CidrContents {
                    name: cidr.name,
                    cidr: cidr.prefix.net(),
                    parent: None,
                },
            })
            .collect();
        let parents: Vec<Option<i64>> = cidrs
            .iter()
            .map(|child| {
                cidrs
                    .iter()
                    .filter(|cidr| cidr.cidr != child.cidr && cidr.cidr.contains(&child.cidr))
                    .max_by_key(|cidr| cidr.cidr.prefix_len())
                    .map(|cidr| cidr.id)
            })
            .collect();
        for (cidr, parent) in cidrs.iter_mut().zip(parents) {
            cidr.contents.parent = parent;
        }
        Ok(cidrs)
    }
}
