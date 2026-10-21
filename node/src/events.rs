//! The events of a tunnel, the other direction of [`TunnelBackend`](crate::realize::TunnelBackend):
//! what the tunnel observes of its peers, which consumers such as the coordinator's observed
//! endpoints and NAT traversal follow.
//!
//! A backend starts its source of events once, when it is first asked for them, and every
//! consumer subscribes to the same source. The source runs while any subscriber or the backend
//! holds it. A source that the kernel pushes, such as one attached to the kernel's WireGuard,
//! takes the place of [`poll_wireguard`] behind the same [`EventSource`] without a change to the
//! consumers, and falls back to polling where it can't attach.

use innernet_shared::wg::PeerInfoExt;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, OnceLock, Weak},
    time::{Duration, SystemTime},
};
use tokio::sync::broadcast;
use wireguard_control::{Backend, Device, InterfaceName};

/// How often [`poll_wireguard`] reads the device.
pub const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// How many events a subscriber may fall behind by before it misses some.
const CAPACITY: usize = 256;

/// What a tunnel observes of one of its peers, each named by its public key in base64.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelEvent {
    /// The peer is now reached at `endpoint`, as when it roams, or was first seen there.
    EndpointChanged {
        public_key: String,
        endpoint: SocketAddr,
    },
    /// A handshake with the peer completed.
    HandshakeCompleted { public_key: String },
    /// The peer, which had connected, hasn't completed a handshake for as long as WireGuard keeps
    /// a session.
    PeerSilent { public_key: String },
}

type Shared = OnceLock<broadcast::Sender<TunnelEvent>>;

/// The source of a tunnel's events, which a backend holds, started by the first subscription.
#[derive(Clone, Debug, Default)]
pub struct EventSource(Arc<Shared>);

impl EventSource {
    /// Subscribes to the events of the source, calling `start` with a handle of the source the
    /// first time, to start what produces them. What `start` starts sends to the source for as long
    /// as [`SourceHandle::sender`] gives it a sender, and stops once it doesn't.
    pub fn subscribe(&self, start: impl FnOnce(SourceHandle)) -> TunnelEvents {
        let mut started = false;
        let sender = self.0.get_or_init(|| {
            started = true;
            broadcast::channel(CAPACITY).0
        });
        let receiver = sender.subscribe();
        if started {
            start(SourceHandle(Arc::downgrade(&self.0)));
        }
        TunnelEvents {
            receiver: Some(receiver),
            _source: Some(self.0.clone()),
        }
    }
}

/// A handle of an [`EventSource`] that doesn't keep it alive.
pub struct SourceHandle(Weak<Shared>);

impl SourceHandle {
    /// The sender of the source, unless nothing holds the source any longer.
    pub fn sender(&self) -> Option<broadcast::Sender<TunnelEvent>> {
        self.0.upgrade()?.get().cloned()
    }
}

/// A subscription to the events of a tunnel.
pub struct TunnelEvents {
    receiver: Option<broadcast::Receiver<TunnelEvent>>,
    _source: Option<Arc<Shared>>,
}

impl TunnelEvents {
    /// A subscription to a tunnel that observes nothing.
    pub fn none() -> Self {
        Self {
            receiver: None,
            _source: None,
        }
    }

    /// The next event, or `None` once the tunnel observes nothing more. A subscriber that falls
    /// behind misses the events that it fell behind by.
    pub async fn next(&mut self) -> Option<TunnelEvent> {
        let receiver = self.receiver.as_mut()?;
        loop {
            match receiver.recv().await {
                Ok(event) => return Some(event),
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    log::debug!("missed {missed} events of the tunnel");
                },
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

/// What the device last showed of a peer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Seen {
    endpoint: Option<SocketAddr>,
    handshake: Option<SystemTime>,
    connected: bool,
}

/// The events between what the device showed of the peer with `public_key`, `previous`, if it
/// showed it, and what it shows now, `current`. The first reading, `first`, reports where each peer
/// is reached, but no handshake.
fn diff(
    public_key: &str,
    previous: Option<&Seen>,
    current: &Seen,
    first: bool,
) -> Vec<TunnelEvent> {
    let mut events = vec![];
    if let Some(endpoint) = current.endpoint {
        if previous.is_none_or(|previous| previous.endpoint != current.endpoint) {
            events.push(TunnelEvent::EndpointChanged {
                public_key: public_key.to_string(),
                endpoint,
            });
        }
    }
    let previous_handshake = previous.and_then(|previous| previous.handshake);
    if !first && current.handshake.is_some() && current.handshake > previous_handshake {
        events.push(TunnelEvent::HandshakeCompleted {
            public_key: public_key.to_string(),
        });
    }
    if previous.is_some_and(|previous| previous.connected) && !current.connected {
        events.push(TunnelEvent::PeerSilent {
            public_key: public_key.to_string(),
        });
    }
    events
}

/// Reads the device of `interface` every [`POLL_INTERVAL`], in the kernel or in userspace, and
/// sends to `source` the events between each reading and the last, until nothing holds the source.
pub async fn poll_wireguard(interface: InterfaceName, backend: Backend, source: SourceHandle) {
    let mut last: HashMap<String, Seen> = HashMap::new();
    let mut first = true;
    let mut interval = tokio::time::interval(POLL_INTERVAL);
    loop {
        interval.tick().await;
        let Some(sender) = source.sender() else {
            return;
        };
        let device = match Device::get(&interface, backend) {
            Ok(device) => device,
            Err(e) => {
                log::debug!("failed to read the tunnel's peers: {e}");
                continue;
            },
        };
        let mut seen = HashMap::new();
        for peer in &device.peers {
            let public_key = peer.config.public_key.to_base64();
            let current = Seen {
                endpoint: peer.config.endpoint,
                handshake: peer.stats.last_handshake_time,
                connected: peer.is_recently_connected(),
            };
            for event in diff(&public_key, last.get(&public_key), &current, first) {
                // Nothing may be subscribed at the moment, which loses nothing that matters.
                let _ = sender.send(event);
            }
            seen.insert(public_key, current);
        }
        last = seen;
        first = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff() {
        let endpoint: SocketAddr = "192.0.2.1:51820".parse().unwrap();
        let roamed: SocketAddr = "192.0.2.2:51820".parse().unwrap();
        let at = |secs| Some(SystemTime::UNIX_EPOCH + Duration::from_secs(secs));
        let seen = |endpoint, handshake, connected| Seen {
            endpoint,
            handshake,
            connected,
        };
        let changed = |endpoint| TunnelEvent::EndpointChanged {
            public_key: "k".into(),
            endpoint,
        };
        let handshake = TunnelEvent::HandshakeCompleted {
            public_key: "k".into(),
        };

        // The first reading reports where a peer is reached, but no handshake.
        let first = seen(Some(endpoint), at(5), true);
        assert_eq!(diff("k", None, &first, true), [changed(endpoint)]);
        // Nothing changed, nothing is reported.
        assert!(diff("k", Some(&first), &first, false).is_empty());
        // A newer handshake, at a new endpoint.
        let later = seen(Some(roamed), at(9), true);
        assert_eq!(
            diff("k", Some(&first), &later, false),
            [changed(roamed), handshake.clone()]
        );
        // A peer that appears with a handshake completed it since the last reading.
        assert_eq!(
            diff("k", None, &seen(None, at(9), true), false),
            [handshake]
        );
        // A peer that stops connecting falls silent, once.
        let silent = seen(Some(roamed), at(9), false);
        assert_eq!(
            diff("k", Some(&later), &silent, false),
            [TunnelEvent::PeerSilent {
                public_key: "k".into()
            }]
        );
        assert!(diff("k", Some(&silent), &silent, false).is_empty());
    }

    #[tokio::test]
    async fn test_source_runs_while_held() {
        let source = EventSource::default();
        let mut handle = None;
        let mut events = source.subscribe(|started| handle = Some(started));
        let handle = handle.expect("the first subscription starts the source");
        // A second subscription shares what the first started.
        let mut second = source.subscribe(|_| panic!("started twice"));
        handle
            .sender()
            .unwrap()
            .send(TunnelEvent::HandshakeCompleted {
                public_key: "k".into(),
            })
            .unwrap();
        assert!(events.next().await.is_some());
        assert!(second.next().await.is_some());
        drop((source, events, second));
        assert!(handle.sender().is_none());
    }
}
