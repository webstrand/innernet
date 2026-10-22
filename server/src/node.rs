//! The coordinator's own node, which links to the coordinator in the same process.

use crate::{
    db::{key_to_bytes, DatabasePeer},
    Db,
};
use anyhow::Error;
use innernet_node::{
    accept,
    runtime::Link,
    snapshot::{self, Own, Snapshot, SnapshotConfig},
    store,
};
use innernet_shared::{
    announcement::{self, Announcement, SignedAnnouncement},
    Endpoint, PeerContents,
};
use wireguard_control::Key;

/// The link of the coordinator's own node to the coordinator. The coordinator writes the
/// database that they share, the node's store, itself, so there is nothing to fetch, and the
/// node's announcement reaches the coordinator's checks by a call.
pub struct LocalLink {
    pub db: Db,
    /// The public key of the server's own peer, the node's.
    pub server_key: Key,
    /// The endpoint at which peers first reach the coordinator, which the node announces as its
    /// own when it states none, since nothing observes it.
    pub bootstrap: Option<Endpoint>,
}

impl LocalLink {
    fn coordinator(&self) -> Result<DatabasePeer, Error> {
        Ok(DatabasePeer::get_from_public_key(
            &self.db.lock(),
            &self.server_key,
        )?)
    }
}

impl Link for LocalLink {
    async fn sync(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn snapshot(&self, config: &SnapshotConfig, own: Option<Own>) -> Result<Snapshot, Error> {
        Ok(snapshot::of_store(&self.db.lock(), config, own)?)
    }

    fn last_announced(&self, public_key: &str) -> Result<Option<u64>, Error> {
        let key = key_to_bytes(public_key)?;
        Ok(store::load_announcements(&self.db.lock(), Some(&key))?
            .remove(public_key)
            .map(|stored| stored.announcement.timestamp))
    }

    fn assignment(&self) -> Result<Option<PeerContents>, Error> {
        Ok(Some(self.coordinator()?.inner))
    }

    fn claim_types(&self) -> Option<Vec<String>> {
        Some(accept::all_claim_types())
    }

    /// The bootstrap endpoint, or, without one, the endpoint recorded at initialization until
    /// the node first announces, and the preferred endpoint that it last announced after.
    fn observed_endpoint(&self) -> Option<Endpoint> {
        if self.bootstrap.is_some() {
            return self.bootstrap.clone();
        }
        let me = self.coordinator().ok()?;
        match me.signed_announcement() {
            Some(announced) => announced.endpoints.first().cloned(),
            None => me.endpoint.clone(),
        }
    }

    fn current_announcement(&self) -> Option<Announcement> {
        self.coordinator().ok()?.signed_announcement().cloned()
    }

    async fn announce(&mut self, signed: &SignedAnnouncement, _: &[String]) -> Result<(), Error> {
        let store = self.db.lock();
        let mut me = DatabasePeer::get_from_public_key(&store, &self.server_key)?;
        me.announce(&store, signed.clone(), announcement::timestamp_now())?;
        Ok(())
    }
}
