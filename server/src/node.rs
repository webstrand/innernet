//! The coordinator's own node, which links to the coordinator in the same process.

use crate::{coordinator::Db, db::DatabasePeer};
use anyhow::Error;
use innernet_node::{
    runtime::Link,
    snapshot::{self, Snapshot, SnapshotConfig},
};
use innernet_shared::Endpoint;
use wireguard_control::Key;

/// The link of the coordinator's own node to the coordinator. The coordinator writes the
/// database that they share, the node's store, itself, so there is nothing to fetch, and the
/// node's candidates reach the coordinator's record of its own peer directly.
pub struct LocalLink {
    pub db: Db,
    /// The public key of the server's own peer, the node's.
    pub key: Key,
}

impl Link for LocalLink {
    async fn sync(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn snapshot(&self, config: &SnapshotConfig) -> Result<Snapshot, Error> {
        Ok(snapshot::of_store(&self.db.lock(), config)?)
    }

    async fn report_candidates(&mut self, candidates: Vec<Endpoint>) -> Result<(), Error> {
        let store = self.db.lock();
        DatabasePeer::get_from_public_key(&store, &self.key)?.set_candidates(&store, candidates)?;
        Ok(())
    }
}
