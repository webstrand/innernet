use super::{ip_to_bytes, prefix_from_row};
use crate::ServerError;
use innernet_node::Store;
use innernet_shared::{
    parent_cidr, smallest_cidr_holding, Cidr, LegacyCidr, LegacyCidrContents, Prefix,
};
use rusqlite::{params, OptionalExtension as _};

/// The table of CIDRs of servers that predate the rebuild of the database, which names each CIDR,
/// and its parent, by an ID.
#[cfg(test)]
pub static ORIGIN_TABLE_SQL: &str = "CREATE TABLE cidrs (
      id               INTEGER PRIMARY KEY,
      name             TEXT NOT NULL UNIQUE,
      ip               TEXT NOT NULL,
      prefix           INTEGER NOT NULL,
      parent           INTEGER REFERENCES cidrs,
      UNIQUE(ip, prefix),
      FOREIGN KEY (parent)
         REFERENCES cidrs (id)
            ON UPDATE RESTRICT
            ON DELETE RESTRICT
    )";

/// A CIDR, identified by its prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseCidr {
    pub name: String,
    pub prefix: Prefix,
}

impl DatabaseCidr {
    /// Marks the CIDR `prefix` infra, so that every peer sees its peers.
    pub fn set_infra(store: &Store, prefix: &Prefix) -> Result<(), ServerError> {
        store.execute(
            "UPDATE cidrs SET infra = 1 WHERE address = ?1 AND prefix_len = ?2",
            params![ip_to_bytes(prefix.first()), prefix.prefix_len()],
        )?;
        Ok(())
    }

    /// The infra CIDRs, whose peers every peer sees.
    pub fn infra(store: &Store) -> Result<Vec<Prefix>, ServerError> {
        let mut stmt =
            store.prepare_cached("SELECT address, prefix_len FROM cidrs WHERE infra = 1")?;
        let prefixes = stmt
            .query_map([], |row| prefix_from_row(row.get(0)?, row.get(1)?))?
            .collect::<Result<_, _>>()?;
        Ok(prefixes)
    }

    /// The prefixes of `cidrs`.
    pub fn prefixes(cidrs: &[Self]) -> Vec<Prefix> {
        cidrs.iter().map(|cidr| cidr.prefix).collect()
    }

    /// The CIDR as the API of TLS sessions transfers it.
    pub fn contents(&self) -> Cidr {
        Cidr {
            name: self.name.clone(),
            cidr: self.prefix,
        }
    }

    /// The ID by which the API of plain-HTTP sessions names the CIDR `prefix`: its position, from
    /// 1, among `cidrs`, every CIDR in the order of [`Self::list`]. The database stores no such
    /// ID. The IDs are consistent within one response, but creating or deleting a CIDR renumbers
    /// the CIDRs after it.
    pub fn id_of(prefix: &Prefix, cidrs: &[Self]) -> Option<i64> {
        cidrs
            .iter()
            .position(|cidr| cidr.prefix == *prefix)
            .map(|index| index as i64 + 1)
    }

    /// The CIDR as the API of plain-HTTP sessions transfers it, with its ID, and the ID of its
    /// parent, the smallest CIDR that holds it, among `cidrs`, every CIDR in the order of
    /// [`Self::list`], which must hold the CIDR.
    pub fn legacy(&self, cidrs: &[Self]) -> LegacyCidr {
        let parent = parent_cidr(&self.prefix, &Self::prefixes(cidrs))
            .and_then(|parent| Self::id_of(&parent, cidrs));
        LegacyCidr {
            id: Self::id_of(&self.prefix, cidrs).expect("`cidrs` holds the CIDR"),
            contents: LegacyCidrContents {
                name: self.name.clone(),
                cidr: self.prefix.net(),
                parent,
            },
        }
    }

    /// Creates the CIDR `prefix`, named `name`, at the place in the tree that its prefix gives
    /// it. It must not hold another CIDR, since that would move the CIDRs that it holds in the
    /// tree. Its parent must not be the CIDR of a peer, since peers belong only to CIDRs without
    /// children.
    pub fn create(store: &Store, name: String, prefix: Prefix) -> Result<Self, ServerError> {
        log::debug!("creating CIDR {name} ({prefix})");
        let cidrs = Self::list(store)?;
        if let Some(held) = cidrs.iter().find(|cidr| prefix.contains(&cidr.prefix)) {
            log::warn!(
                "tried to add the CIDR {prefix}, which is or holds the CIDR {} ({}).",
                held.name,
                held.prefix
            );
            return Err(ServerError::InvalidQuery);
        }
        let prefixes = Self::prefixes(&cidrs);
        if let Some(parent) = parent_cidr(&prefix, &prefixes) {
            if holds_peers(store, &parent, &prefixes)? {
                log::warn!("tried to add a CIDR to the parent {parent}, which has peers.");
                return Err(ServerError::InvalidQuery);
            }
        }

        store.execute(
            "INSERT INTO cidrs (address, prefix_len, name) VALUES (?1, ?2, ?3)",
            params![ip_to_bytes(prefix.first()), prefix.prefix_len(), name],
        )?;
        Ok(Self { name, prefix })
    }

    /// Renames the CIDR. Nothing else of a CIDR changes.
    pub fn rename(&mut self, store: &Store, name: String) -> Result<(), ServerError> {
        store.execute(
            "UPDATE cidrs SET name = ?3 WHERE address = ?1 AND prefix_len = ?2",
            params![
                ip_to_bytes(self.prefix.first()),
                self.prefix.prefix_len(),
                name
            ],
        )?;
        self.name = name;
        Ok(())
    }

    /// Deletes the CIDR `prefix`, which must have no child CIDR, no peer, and no association.
    pub fn delete(store: &Store, prefix: &Prefix) -> Result<(), ServerError> {
        let cidrs = Self::list(store)?;
        if !cidrs.iter().any(|cidr| cidr.prefix == *prefix) {
            return Err(ServerError::NotFound);
        }
        let prefixes = Self::prefixes(&cidrs);
        if prefixes
            .iter()
            .any(|other| parent_cidr(other, &prefixes) == Some(*prefix))
        {
            log::warn!("tried to delete the CIDR {prefix}, which has child CIDRs.");
            return Err(ServerError::InvalidQuery);
        }
        if holds_peers(store, prefix, &prefixes)? {
            log::warn!("tried to delete the CIDR {prefix}, which has peers.");
            return Err(ServerError::InvalidQuery);
        }
        // An association that names the CIDR refuses the deletion.
        store.execute(
            "DELETE FROM cidrs WHERE address = ?1 AND prefix_len = ?2",
            params![ip_to_bytes(prefix.first()), prefix.prefix_len()],
        )?;
        Ok(())
    }

    fn from_row(row: &rusqlite::Row) -> Result<Self, rusqlite::Error> {
        Ok(Self {
            prefix: prefix_from_row(row.get(0)?, row.get(1)?)?,
            name: row.get(2)?,
        })
    }

    /// The CIDR `prefix`, or [`ServerError::NotFound`].
    pub fn get(store: &Store, prefix: &Prefix) -> Result<Self, ServerError> {
        store.query_row(
            "SELECT address, prefix_len, name FROM cidrs WHERE address = ?1 AND prefix_len = ?2",
            params![ip_to_bytes(prefix.first()), prefix.prefix_len()],
            Self::from_row,
        )
        .optional()?
        .ok_or(ServerError::NotFound)
    }

    /// Every CIDR, ordered by prefix.
    pub fn list(store: &Store) -> Result<Vec<Self>, ServerError> {
        let mut stmt = store.prepare_cached(
            "SELECT address, prefix_len, name FROM cidrs
             ORDER BY length(address), address, prefix_len",
        )?;
        let cidrs = stmt.query_map(params![], Self::from_row)?;
        Ok(cidrs.collect::<Result<Vec<_>, rusqlite::Error>>()?)
    }
}

/// Whether the CIDR `cidr`, one of `cidrs`, is the CIDR of a peer: whether it is the smallest of
/// `cidrs` that holds a delegation.
fn holds_peers(store: &Store, cidr: &Prefix, cidrs: &[Prefix]) -> Result<bool, ServerError> {
    let mut stmt = store.prepare_cached(
        "SELECT address, prefix_len FROM delegations
         WHERE length(address) = length(?1) AND address <= ?2 AND ?1 <= last",
    )?;
    let mut rows = stmt.query(params![ip_to_bytes(cidr.first()), ip_to_bytes(cidr.last())])?;
    while let Some(row) = rows.next()? {
        let delegation = prefix_from_row(row.get(0)?, row.get(1)?)?;
        if smallest_cidr_holding(&delegation, cidrs) == Some(*cidr) {
            return Ok(true);
        }
    }
    Ok(false)
}
