//! When a node reattempts the NAT traversal of a peer that it hasn't connected to, which a round
//! would otherwise start anew for every such peer, whether or not the peer is online.
//!
//! A peer that no source has seen alive for [`FRESH`] is gone: the node reattempts it after a
//! quarter of the time since it was last seen, so that a peer that left a minute ago is tried at
//! every round, and one gone for hours once every [`MAX_WAIT`]. A peer that the coordinator saw
//! within [`FRESH`] is alive but unreachable from the node: the node reattempts it after
//! [`MIN_WAIT`], doubled for each attempt since the peer last changed, up to [`MAX_WAIT`]. The
//! sources are the coordinator's last handshake with the peer, the timestamp of the peer's last
//! announcement, the tunnel's last handshake with it, and the time at which the node started,
//! which every peer is taken to have been seen at, so that a node that starts tries every peer.
//!
//! A peer changes, and is reattempted at once, when the tunnel completes a handshake with it, when
//! its endpoint or its candidates change, and when it comes back from gone.

use innernet_shared::{Endpoint, PeerContents};
use std::{
    collections::HashMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;

/// How long since a peer was last seen it is still taken to be alive.
pub const FRESH: Duration = Duration::from_secs(5 * 60);

/// The wait before the second attempt at a peer that is alive but unreachable.
pub const MIN_WAIT: Duration = Duration::from_secs(60);

/// The longest wait between two attempts at a peer.
pub const MAX_WAIT: Duration = Duration::from_secs(60 * 60);

/// When each source last saw a peer alive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sighting {
    /// When the coordinator last completed a handshake with the peer, as it reported it.
    pub coordinator: Option<Instant>,
    /// The timestamp of the peer's last announcement, in seconds since the Unix epoch, by the
    /// peer's clock.
    pub announced: Option<u64>,
    /// When the tunnel last completed a handshake with the peer.
    pub handshake: Option<SystemTime>,
}

impl Sighting {
    /// The time `ago` before `now`, or `now` if `ago` lies in the future.
    fn before(now: Instant, wall: SystemTime, at: SystemTime) -> Instant {
        let ago = wall.duration_since(at).unwrap_or_default();
        now.checked_sub(ago).unwrap_or(now)
    }

    /// When any source last saw the peer, at `now`, which the clock of the host reads as `wall`.
    /// An announcement stamped in the future is taken to be made `now`.
    fn last_seen(&self, now: Instant, wall: SystemTime) -> Option<Instant> {
        let announced = self
            .announced
            .map(|secs| Self::before(now, wall, UNIX_EPOCH + Duration::from_secs(secs)));
        let handshake = self.handshake.map(|at| Self::before(now, wall, at));
        [self.coordinator, announced, handshake]
            .into_iter()
            .flatten()
            .max()
    }

    /// Whether the coordinator saw the peer within [`FRESH`] of `now`.
    fn coordinator_fresh(&self, now: Instant) -> bool {
        self.coordinator
            .is_some_and(|at| now.saturating_duration_since(at) < FRESH)
    }
}

/// What the node last attempted of a peer.
#[derive(Clone, Debug)]
struct Attempts {
    /// When the node last attempted the peer.
    last: Instant,
    /// How many times the node attempted the peer since it last changed.
    count: u32,
    /// Whether the peer was alive at the last attempt.
    alive: bool,
    /// The tunnel's last handshake with the peer, its endpoint and its candidates, at the last
    /// attempt, against which a change is told.
    handshake: Option<SystemTime>,
    endpoint: Option<Endpoint>,
    candidates: Vec<Endpoint>,
}

/// The attempts of a node at each peer that it hasn't connected to.
#[derive(Debug)]
pub struct Retries {
    /// When the node started.
    started: Instant,
    peers: HashMap<String, Attempts>,
}

impl Retries {
    pub fn new(started: Instant) -> Self {
        Self {
            started,
            peers: HashMap::new(),
        }
    }

    /// Records that the node attempts `peer` at `now`, which changed, and returns `true`, or,
    /// for a reattempt, returns whether one is due, recording it if it is. `sighting` is when each
    /// source last saw the peer, at `now`, which the clock of the host reads as `wall`.
    pub fn attempt(
        &mut self,
        peer: &PeerContents,
        sighting: &Sighting,
        reattempt: bool,
        now: Instant,
        wall: SystemTime,
    ) -> bool {
        let alive = sighting.coordinator_fresh(now);
        let fresh = Attempts {
            last: now,
            count: 1,
            alive,
            handshake: sighting.handshake,
            endpoint: peer.endpoint.clone(),
            candidates: peer.candidates.clone(),
        };
        let attempts = match self.peers.get_mut(&peer.public_key) {
            Some(attempts) if reattempt => attempts,
            _ => {
                self.peers.insert(peer.public_key.clone(), fresh);
                return true;
            },
        };
        let changed = (alive && !attempts.alive)
            || sighting.handshake > attempts.handshake
            || peer.endpoint != attempts.endpoint
            || peer.candidates != attempts.candidates;
        if changed {
            *attempts = fresh;
            return true;
        }
        attempts.alive = alive;
        let wait = if alive {
            MIN_WAIT.saturating_mul(1 << (attempts.count - 1).min(16))
        } else {
            let last_seen = sighting
                .last_seen(now, wall)
                .map_or(self.started, |seen| seen.max(self.started));
            now.saturating_duration_since(last_seen) / 4
        }
        .min(MAX_WAIT);
        if now.saturating_duration_since(attempts.last) < wait {
            log::debug!(
                "not reattempting peer {} for another {}s.",
                peer.display_name(),
                (wait - now.saturating_duration_since(attempts.last)).as_secs()
            );
            return false;
        }
        attempts.last = now;
        attempts.count = attempts.count.saturating_add(1);
        true
    }

    /// Forgets every peer but those for which `keep` holds.
    pub fn retain(&mut self, mut keep: impl FnMut(&str) -> bool) {
        self.peers.retain(|public_key, _| keep(public_key));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerContents {
        PeerContents {
            name: Some("peer".parse().unwrap()),
            delegations: vec!["10.0.0.2/32".parse().unwrap()],
            public_key: wireguard_control::KeyPair::generate().public.to_base64(),
            endpoint: Some("192.0.2.1:51820".parse().unwrap()),
            persistent_keepalive_interval: None,
            is_admin: false,
            is_disabled: false,
            is_redeemed: true,
            invite_expires: None,
            candidates: vec![],
            announcement: None,
            allowed_ips: None,
            primary_ip: None,
            nameserver: None,
        }
    }

    /// The minutes after `start`, of `minutes`, at which `retries` reattempts `peer`, as
    /// `sighting` gives the sources at each.
    fn reattempts(
        retries: &mut Retries,
        peer: &PeerContents,
        start: Instant,
        minutes: std::ops::Range<u64>,
        sighting: impl Fn(Instant) -> Sighting,
    ) -> Vec<u64> {
        let wall = SystemTime::now();
        minutes
            .filter(|minute| {
                let now = start + Duration::from_secs(minute * 60);
                retries.attempt(peer, &sighting(now), true, now, wall)
            })
            .collect()
    }

    #[test]
    fn test_gone_peer_backs_off_to_the_longest_wait() {
        let start = Instant::now();
        let peer = peer();
        let mut retries = Retries::new(start);
        let wall = SystemTime::now();
        assert!(retries.attempt(&peer, &Sighting::default(), false, start, wall));
        // A peer that no source sees is taken to be seen when the node started: it is tried at
        // every round at first, ever more rarely after, and once an hour at last.
        let attempted = reattempts(&mut retries, &peer, start, 1..24 * 60, |_| {
            Sighting::default()
        });
        assert_eq!(attempted[..4], [1, 2, 3, 4]);
        let gaps: Vec<_> = attempted.windows(2).map(|w| w[1] - w[0]).collect();
        assert!(gaps.windows(2).all(|w| w[0] <= w[1]));
        assert_eq!(gaps.last(), Some(&60));
        assert!(attempted.len() < 50);
    }

    #[test]
    fn test_gone_peer_is_retried_by_its_last_sighting() {
        let start = Instant::now();
        let peer = peer();
        let mut retries = Retries::new(start - Duration::from_secs(86400));
        let wall = SystemTime::now();
        let long_gone = Sighting {
            coordinator: Some(start - Duration::from_secs(3 * 86400)),
            announced: wall
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|now| now.as_secs() - 2 * 86400),
            handshake: None,
        };
        assert!(retries.attempt(&peer, &long_gone, false, start, wall));
        let later = |secs| {
            (
                start + Duration::from_secs(secs),
                wall + Duration::from_secs(secs),
            )
        };
        // The coordinator and the announcement saw the peer days ago: it waits an hour.
        let (now, now_wall) = later(120);
        assert!(!retries.attempt(&peer, &long_gone, true, now, now_wall));

        // The tunnel saw another such peer five minutes before the first attempt, which is the
        // last sighting: it is tried once a quarter of the time since then has passed.
        let peer = PeerContents {
            public_key: wireguard_control::KeyPair::generate().public.to_base64(),
            ..peer
        };
        let recently_gone = Sighting {
            handshake: Some(wall - Duration::from_secs(5 * 60)),
            ..long_gone
        };
        assert!(retries.attempt(&peer, &recently_gone, false, start, wall));
        let (now, now_wall) = later(60);
        assert!(!retries.attempt(&peer, &recently_gone, true, now, now_wall));
        let (now, now_wall) = later(120);
        assert!(retries.attempt(&peer, &recently_gone, true, now, now_wall));
    }

    #[test]
    fn test_alive_peer_backs_off_by_its_attempts() {
        let start = Instant::now();
        let peer = peer();
        let mut retries = Retries::new(start - Duration::from_secs(86400));
        let wall = SystemTime::now();
        let alive = |now: Instant| Sighting {
            coordinator: Some(now - Duration::from_secs(30)),
            ..Sighting::default()
        };
        assert!(retries.attempt(&peer, &alive(start), false, start, wall));
        // The coordinator sees the peer at every round, yet the node never reaches it: the waits
        // double from a minute up to an hour.
        let attempted = reattempts(&mut retries, &peer, start, 1..12 * 60, alive);
        assert_eq!(attempted[..6], [1, 3, 7, 15, 31, 63]);
        let gaps: Vec<_> = attempted.windows(2).map(|w| w[1] - w[0]).collect();
        assert_eq!(gaps.last(), Some(&60));
    }

    #[test]
    fn test_changed_peer_is_retried_at_once() {
        let start = Instant::now();
        let mut peer = peer();
        let mut retries = Retries::new(start - Duration::from_secs(86400));
        let wall = SystemTime::now();
        let gone = Sighting::default();
        assert!(retries.attempt(&peer, &gone, false, start, wall));
        let mut now = start + Duration::from_secs(60);
        assert!(!retries.attempt(&peer, &gone, true, now, wall));

        // A peer that comes back from gone.
        let alive = Sighting {
            coordinator: Some(now),
            ..Sighting::default()
        };
        assert!(retries.attempt(&peer, &alive, true, now, wall));
        now += Duration::from_secs(10);
        assert!(!retries.attempt(&peer, &alive, true, now, wall));

        // A peer with new candidates.
        peer.candidates = vec!["198.51.100.1:51820".parse().unwrap()];
        assert!(retries.attempt(&peer, &alive, true, now, wall));
        assert!(!retries.attempt(&peer, &alive, true, now, wall));

        // A peer with which the tunnel completed a handshake.
        let shaken = Sighting {
            handshake: Some(wall),
            ..alive
        };
        assert!(retries.attempt(&peer, &shaken, true, now, wall));
        assert!(!retries.attempt(&peer, &shaken, true, now, wall));
    }
}
