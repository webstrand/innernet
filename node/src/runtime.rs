//! The runtime of a node: the rounds that every node runs, whatever its role, and the loop that
//! runs them. A round brings the node's store up to date through its [`Link`] to the coordinator,
//! configures the tunnel from what the store holds, reports the node's candidates, and starts the
//! NAT traversal of the peers that it changed. The host publishes the names of the round's
//! snapshot.
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
    realize::{Realized, TunnelBackend},
    snapshot::Snapshot,
};
use anyhow::Error;
use innernet_shared::{get_local_addrs, Endpoint, NatOpts};
use std::{future::pending, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{sync::Notify, time::Instant};
use wireguard_control::InterfaceName;

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

/// A node's link to its coordinator, through which its store holds what the coordinator reports,
/// and its own candidates reach the coordinator.
#[allow(async_fn_in_trait)]
pub trait Link {
    /// Brings the node's store up to date with the coordinator.
    async fn sync(&mut self) -> Result<(), Error>;

    /// The snapshot of the node's store.
    fn snapshot(&self) -> Result<Snapshot, Error>;

    /// Reports `candidates`, the endpoints at which other peers try the node during NAT
    /// traversal, to the coordinator.
    async fn report_candidates(&mut self, candidates: Vec<Endpoint>) -> Result<(), Error>;
}

/// A node: its tunnel, and what decides its candidates.
pub struct Node {
    pub interface: InterfaceName,
    /// The port at which the tunnel listens, at which the other addresses of the host are the
    /// node's candidates.
    pub listen_port: u16,
    /// Which addresses of the host are no candidates, and whether the node traverses NATs.
    pub nat: NatOpts,
    pub tunnel: Box<dyn TunnelBackend + Send>,
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
    /// Runs a round through `link`: brings the store up to date, configures the tunnel from its
    /// snapshot, reports the node's candidates, and starts the NAT traversal of the peers that it
    /// changed. A failure to report the candidates is logged and fails nothing, so that the node
    /// keeps what it has configured.
    pub async fn round(&mut self, link: &mut impl Link) -> Result<Round, Error> {
        link.sync().await?;
        let snapshot = link.snapshot()?;
        let events = self.tunnel.events();
        let realized = self.tunnel.realize(&snapshot)?;
        let candidates = self.candidates()?;
        log::info!(
            "reporting {} interface address{} as NAT traversal candidates",
            candidates.len(),
            if candidates.len() == 1 { "" } else { "es" },
        );
        if let Err(e) = link.report_candidates(candidates).await {
            log::warn!("failed to report this node's candidates: {e:#}");
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
