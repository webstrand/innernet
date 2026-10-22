//! The runtime of a node: the rounds that every node runs, whatever its role, and the loop that
//! runs them. A round brings the node's store up to date through its [`Link`] to the coordinator,
//! configures the tunnel and publishes the names of what the store holds, announces the node
//! itself, and starts the NAT traversal of the peers that it changed.
//!
//! A round runs when the coordinator signals a change of the store through [`StoreChanged`], when
//! the host's addresses change, and, for a node that polls its coordinator, at its interval. The
//! steps of NAT traversal are timers of the same loop.
//!
//! A client links to its coordinator over the API, and polls it. The coordinator's own node links
//! to the coordinator in the same process, which writes the node's store itself.

use crate::{
    addresses,
    events::{TunnelEvent, TunnelEvents},
    nat::{NatTraverse, STEP_INTERVAL},
    own,
    realize::{DnsService, Realized, TunnelBackend},
    snapshot::{Own, Snapshot, SnapshotConfig},
};
use anyhow::{Context as _, Error};
use innernet_shared::{
    announcement::{self, Announcement, SignedAnnouncement},
    get_local_addrs,
    interface_config::{DnsInfo, InterfaceInfo},
    peer_hostname, Endpoint, NatOpts, PeerContents, Prefix,
};
use std::{future::pending, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{sync::Notify, time::Instant};
use wireguard_control::{InterfaceName, Key};

/// The signal by which a coordinator that writes its node's store tells the node that the store
/// changed, so that the node runs a round at once. A signal given while the node runs a round
/// makes it run another.
#[derive(Clone, Debug, Default)]
pub struct StoreChanged(Arc<Notify>);

impl StoreChanged {
    pub fn notify(&self) {
        self.0.notify_one();
    }

    /// Waits until the store changes.
    pub async fn changed(&self) {
        self.0.notified().await
    }
}

/// A node's link to its coordinator, through which its store holds what the coordinator relays,
/// and its own announcement reaches the coordinator.
#[allow(async_fn_in_trait)]
pub trait Link {
    /// Brings the node's store up to date with the coordinator.
    async fn sync(&mut self) -> Result<(), Error>;

    /// The snapshot of the node's store, as `config` configures it, for `own`.
    fn snapshot(&self, config: &SnapshotConfig, own: Option<Own>) -> Result<Snapshot, Error>;

    /// The timestamp of the last announcement of the peer with `public_key` that the node's store
    /// accepted.
    fn last_announced(&self, public_key: &str) -> Result<Option<u64>, Error>;

    /// The node's record as the coordinator assigns it: the ranges among which it claims its
    /// delegation, and the name that it is offered.
    fn assignment(&self) -> Result<Option<PeerContents>, Error>;

    /// The types of claims that the coordinator checks, none if it accepts no announcement, or
    /// `None` if the node can't tell.
    fn claim_types(&self) -> Option<Vec<String>>;

    /// The endpoint at which the coordinator observes the node, if any.
    fn observed_endpoint(&self) -> Option<Endpoint>;

    /// The node's own last announcement, as the coordinator holds it.
    fn current_announcement(&self) -> Option<Announcement>;

    /// Hands `signed`, the node's own announcement, to the coordinator, which checks the claims
    /// of `claim_types`, and records it in the node's store once the coordinator accepted it.
    async fn announce(
        &mut self,
        signed: &SignedAnnouncement,
        claim_types: &[String],
    ) -> Result<(), Error>;
}

/// A node, as the config of its interface describes it.
pub struct Node {
    pub interface: InterfaceName,
    pub info: InterfaceInfo,
    /// The port at which the tunnel listens, at which the other addresses of the host are the
    /// node's candidates.
    pub listen_port: u16,
    /// Which addresses of the host are no candidates, and whether the node traverses NATs.
    pub nat: NatOpts,
    /// The host suffix, under which the node names the peers, itself included.
    pub host_suffix: Option<String>,
    pub snapshot_config: SnapshotConfig,
    pub tunnel: Box<dyn TunnelBackend + Send>,
    /// The DNS server of the node, if the node runs one, as `dns` configures it.
    pub names: Option<(DnsService, DnsInfo)>,
}

pub struct Round {
    pub snapshot: Snapshot,
    pub realized: Vec<Realized>,
    /// The NAT traversal of the peers that the round changed, unless NAT traversal is off.
    pub nat: Option<NatTraverse>,
    /// What the tunnel observes from the round on.
    pub events: TunnelEvents,
}

impl Node {
    /// Runs a round through `link`: brings the store up to date, configures the tunnel and the
    /// DNS server from its snapshot, announces the node, and starts the NAT traversal of the peers
    /// that it changed. A failure to announce is logged and fails nothing, so that the node keeps
    /// what it has configured.
    pub async fn round(&mut self, link: &mut impl Link) -> Result<Round, Error> {
        link.sync().await?;
        let own_key = self.public_key()?;
        let snapshot = link.snapshot(
            &self.snapshot_config,
            Some(Own {
                public_key: &own_key,
                address: self.info.address.addr(),
                extra: &self.info.extra_addresses,
            }),
        )?;
        for address in &self.info.extra_addresses {
            if !snapshot.own_addresses.contains(address) {
                own::warn_once(format!(
                    "not adding the extra address {address}, which lies within no prefix that \
                     this node claims."
                ));
            }
        }
        let events = self.tunnel.events();
        let realized = self.tunnel.realize(&snapshot)?;
        if let Some((names, dns)) = &mut self.names {
            names.update(Some(dns), &snapshot).await;
        }
        if let Err(e) = self.announce(link).await {
            log::warn!("failed to announce this node: {e:#}");
        }
        let nat = match self.nat.no_nat_traversal {
            true => None,
            false => self.tunnel.traverse(&realized)?,
        };
        Ok(Round {
            snapshot,
            realized,
            nat,
            events,
        })
    }

    /// Announces the node through `link`, as [`own::own_announcement`] makes the announcement of
    /// what the coordinator assigns it, with the endpoints at the other addresses of the host as
    /// its candidates and the nameserver that [`own::own_nameserver`] selects. An announcement
    /// that would change nothing but its timestamp isn't made, nor one to a coordinator that
    /// accepts none, or whose claim types the node can't tell.
    pub async fn announce(&self, link: &mut impl Link) -> Result<(), Error> {
        let Some(claim_types) = link.claim_types().filter(|types| !types.is_empty()) else {
            return Ok(());
        };
        let own_key = self.public_key()?;
        let own = link
            .assignment()?
            .context("the coordinator reports no record of this node")?;
        let last = link.last_announced(&own_key)?;
        let mut announcement = own::own_announcement(
            &self.info,
            &own,
            self.candidates()?,
            link.observed_endpoint().as_ref(),
            &claim_types,
            last,
            announcement::timestamp_now(),
        );
        let hostname = own
            .name
            .as_deref()
            .and_then(|name| peer_hostname(&self.interface, self.host_suffix.as_deref(), name));
        announcement.nameserver = own::own_nameserver(
            &self.info,
            &announcement.claims.delegation,
            hostname.as_deref(),
        );
        if own::is_unchanged(&announcement, link.current_announcement().as_ref()) {
            log::debug!("this node's announcement is unchanged, so it isn't made again.");
            return Ok(());
        }
        let signed = own::sign(&announcement, &self.info.private_key, last)?;
        log::info!(
            "announcing {} and {} endpoint{}.",
            if announcement.claims.delegation.is_empty() {
                "no delegation".to_string()
            } else {
                announcement
                    .claims
                    .delegation
                    .iter()
                    .map(Prefix::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            announcement.endpoints.len(),
            if announcement.endpoints.len() == 1 {
                ""
            } else {
                "s"
            },
        );
        link.announce(&signed, &claim_types).await
    }

    pub fn public_key(&self) -> Result<String, Error> {
        Ok(Key::from_base64(&self.info.private_key)?
            .get_public()
            .to_base64())
    }

    /// The endpoints at which other peers try the node during NAT traversal.
    pub fn candidates(&self) -> Result<Vec<Endpoint>, Error> {
        local_candidates(&self.nat, self.listen_port)
    }
}

/// The endpoints at the addresses of the host, at `listen_port`, that `nat` doesn't exclude.
pub fn local_candidates(nat: &NatOpts, listen_port: u16) -> Result<Vec<Endpoint>, Error> {
    Ok(get_local_addrs()?
        .filter(|ip| !nat.is_excluded(*ip))
        .map(|addr| SocketAddr::from((addr, listen_port)).into())
        .collect())
}

/// What wakes a node for a round, besides the round that it runs first.
#[derive(Default)]
pub struct Triggers {
    /// The signal of the coordinator that writes the node's store.
    pub changed: Option<StoreChanged>,
    /// How often the node polls its coordinator.
    pub interval: Option<Duration>,
    /// The watcher of the host's addresses, which the node's candidates follow.
    pub addresses: Option<addresses::Watcher>,
}

enum Wake {
    Round,
    NatStep,
    Tunnel(TunnelEvent),
}

impl Triggers {
    /// Waits until a trigger fires, the next interval elapses at `next_poll`, the next step of
    /// NAT traversal is due at `nat_step`, or the tunnel reports one of `events`. A watcher of the
    /// addresses that fails is dropped with a warning, and the node then follows the other
    /// triggers.
    async fn next(
        &mut self,
        next_poll: Option<Instant>,
        nat_step: Option<Instant>,
        events: &mut TunnelEvents,
    ) -> Wake {
        let changed = async {
            match &self.changed {
                Some(changed) => changed.changed().await,
                None => pending().await,
            }
        };
        let addresses = async {
            match &mut self.addresses {
                Some(watcher) => Some(watcher.changed().await),
                None => pending().await,
            }
        };
        let watched = tokio::select! {
            () = changed => None,
            watched = addresses => watched,
            () = sleep_until(next_poll) => None,
            () = sleep_until(nat_step) => return Wake::NatStep,
            Some(event) = events.next() => return Wake::Tunnel(event),
        };
        if let Some(Err(e)) = watched {
            log::warn!("stopped watching the host's addresses: {e}");
            self.addresses = None;
        }
        Wake::Round
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => pending().await,
    }
}

/// Runs the rounds that `round` makes, the first at once and then whenever `triggers` fire, and
/// the steps of the NAT traversal that each starts, each [`STEP_INTERVAL`] after the last, until
/// the peers connect or run out of candidates. A handshake that the tunnel reports ends the
/// traversal of its peer at once. A round's traversal replaces the one under way. A round that
/// fails is logged, and the node keeps what it configured last.
pub async fn run(mut triggers: Triggers, mut round: impl AsyncFnMut() -> Result<Round, Error>) {
    let mut nat: Option<(NatTraverse, Instant)> = None;
    let mut events = TunnelEvents::none();
    loop {
        let started = Instant::now();
        match round().await {
            Ok(round) => {
                events = round.events;
                nat = round
                    .nat
                    .filter(|traverse| !traverse.is_finished())
                    .map(|traverse| (traverse, started + STEP_INTERVAL));
            },
            Err(e) => log::error!("the round failed, so the node keeps what it has: {e:#}"),
        }
        let next_poll = triggers.interval.map(|interval| started + interval);
        loop {
            let due = nat.as_ref().map(|(_, due)| *due);
            match triggers.next(next_poll, due, &mut events).await {
                Wake::Round => break,
                Wake::Tunnel(TunnelEvent::HandshakeCompleted { public_key }) => {
                    if let Some((traverse, _)) = &mut nat {
                        log::debug!("the tunnel completed a handshake with {public_key}.");
                        if traverse.refresh_remaining().is_err() || traverse.is_finished() {
                            nat = None;
                        }
                    }
                },
                Wake::Tunnel(_) => {},
                Wake::NatStep => {
                    if let Some((traverse, due)) = &mut nat {
                        match step(traverse) {
                            Ok(true) => *due += STEP_INTERVAL,
                            Ok(false) => nat = None,
                            Err(e) => {
                                log::warn!("NAT traversal failed: {e:#}");
                                nat = None;
                            },
                        }
                    }
                },
            }
        }
    }
}

/// Takes the steps of `round`'s NAT traversal, each [`STEP_INTERVAL`] after the last, until the
/// peers connect or run out of candidates, as a node that runs one round does.
pub async fn settle(round: Round) -> Result<(), Error> {
    let Some(mut traverse) = round.nat else {
        return Ok(());
    };
    while !traverse.is_finished() {
        tokio::time::sleep(STEP_INTERVAL).await;
        if !step(&mut traverse)? {
            break;
        }
    }
    Ok(())
}

/// Takes a step of `traverse`, and returns whether peers remain to traverse to.
fn step(traverse: &mut NatTraverse) -> Result<bool, Error> {
    traverse.refresh_remaining()?;
    if traverse.is_finished() {
        log::debug!("NAT traversal is finished.");
        return Ok(false);
    }
    log::info!(
        "Attempting to establish connection with {} remaining unconnected peers...",
        traverse.remaining()
    );
    traverse.step()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[tokio::test]
    async fn test_store_changed() {
        let changed = StoreChanged::default();
        let waited = tokio::time::timeout(Duration::from_millis(1), changed.changed()).await;
        assert!(waited.is_err());
        // A signal given before the node waits is kept until it does, once.
        changed.notify();
        changed.changed().await;
        let waited = tokio::time::timeout(Duration::from_millis(1), changed.changed()).await;
        assert!(waited.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn test_run_follows_its_triggers() {
        let changed = StoreChanged::default();
        let triggers = Triggers {
            changed: Some(changed.clone()),
            interval: Some(Duration::from_secs(60)),
            addresses: None,
        };
        let rounds = Cell::new(0);
        let runner = run(triggers, async || {
            rounds.set(rounds.get() + 1);
            Ok(Round {
                snapshot: Snapshot::default(),
                realized: vec![],
                nat: None,
                events: TunnelEvents::none(),
            })
        });
        let observe = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            assert_eq!(rounds.get(), 1);
            changed.notify();
            tokio::time::sleep(Duration::from_secs(1)).await;
            assert_eq!(rounds.get(), 2);
            tokio::time::sleep(Duration::from_secs(60)).await;
            assert_eq!(rounds.get(), 3);
        };
        tokio::select! {
            () = runner => unreachable!("the loop runs forever"),
            () = observe => {},
        }
    }
}
