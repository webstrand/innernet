//! Signed endpoint announcements.
//!
//! A peer signs the endpoints it can be reached at with its WireGuard private key, using
//! [XEdDSA](crate::xeddsa), and the coordinating server relays the result to the other peers. Recipients verify
//! it against the public key they have pinned for that peer, so the server cannot announce
//! endpoints on the peer's behalf.
//!
//! The server relays announcements as structured data, and each recipient re-derives the signed
//! bytes from it with [`EndpointAnnouncement::encode`]. Fields added by future versions are
//! carried as [`Extension`]s, which every version encodes the same way whether or not it
//! understands them, so that older servers and recipients don't break newer signatures.

use crate::{
    xeddsa::{self, PrivateKey},
    Endpoint,
};
use anyhow::{bail, Error};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::time::Duration;
use wireguard_control::Key;

/// Domain separator for endpoint announcements. Only changes on an incompatible format change.
const CONTEXT: &[u8] = b"innernet/v1/peer-endpoints\0";

/// Extension tags with this bit set alter the meaning of the other fields, so an announcement
/// carrying one that the recipient doesn't understand must not be used.
pub const CRITICAL_EXTENSION: u16 = 0x8000;

pub const SIGNATURE_LENGTH: usize = xeddsa::SIGNATURE_LENGTH;

/// The default for how far ahead of the receiver's clock an announcement's timestamp may be.
/// Accepting one from the distant future would stop the peer's later announcements from being
/// accepted until then, as could happen if its clock were wrong or manipulated. The limit caps
/// how long the peer can be held up, and must comfortably exceed the 37 s between `CLOCK_TAI`
/// and `CLOCK_REALTIME` plus clock skew.
pub const DEFAULT_MAX_CLOCK_AHEAD: Duration = Duration::from_secs(10 * 60);

/// Whether `timestamp` is further ahead of `now`, both from [`timestamp_now`], than
/// `max_ahead` allows.
pub fn is_too_far_ahead(timestamp: u64, now: u64, max_ahead: Duration) -> bool {
    let max_ahead = u64::try_from(max_ahead.as_nanos()).unwrap_or(u64::MAX);
    timestamp > now.saturating_add(max_ahead)
}

/// The endpoints a peer can be reached at, as stated by the peer itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointAnnouncement {
    /// Orders announcements from the same peer: recipients only accept a greater timestamp than
    /// the last one they accepted. Nanoseconds of `CLOCK_TAI` (or `CLOCK_REALTIME`) by
    /// convention, see [`timestamp_now`], but any increasing value is valid.
    pub timestamp: u64,

    /// The endpoint peers should use. An unspecified host (e.g. `0.0.0.0:51820`) asks for the
    /// host to be completed with the observed endpoint's, which requires `allow_observed`.
    pub endpoint: Option<Endpoint>,

    /// Further endpoints to try during NAT traversal.
    #[serde(default)]
    pub candidates: Vec<Endpoint>,

    /// Whether recipients may also use the endpoint the server observes this peer connecting
    /// from, which cannot be verified.
    #[serde(default)]
    pub allow_observed: bool,

    /// Fields from newer versions, in strictly increasing tag order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<Extension>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extension {
    pub tag: u16,
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
}

impl Extension {
    pub fn is_critical(&self) -> bool {
        self.tag & CRITICAL_EXTENSION != 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAnnouncement {
    pub announcement: EndpointAnnouncement,
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
}

impl EndpointAnnouncement {
    /// The canonical encoding that is signed. Every variable-length item is length-prefixed and
    /// integers are little-endian.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.push(u8::from(self.allow_observed));
        match &self.endpoint {
            None => out.push(0),
            Some(endpoint) => {
                out.push(1);
                endpoint.encode(&mut out);
            },
        }
        out.extend_from_slice(&(self.candidates.len() as u32).to_le_bytes());
        for candidate in &self.candidates {
            candidate.encode(&mut out);
        }
        out.extend_from_slice(&(self.extensions.len() as u32).to_le_bytes());
        for extension in &self.extensions {
            out.extend_from_slice(&extension.tag.to_le_bytes());
            out.extend_from_slice(&(extension.data.len() as u32).to_le_bytes());
            out.extend_from_slice(&extension.data);
        }
        out
    }

    /// The first critical extension this version doesn't understand, if any. None are
    /// understood yet.
    pub fn unknown_critical_extension(&self) -> Option<u16> {
        self.extensions
            .iter()
            .find(|extension| extension.is_critical())
            .map(|extension| extension.tag)
    }

    /// The endpoint and candidates to use for the peer, given the endpoint the server observed
    /// it at. The observed endpoint completes an absent endpoint or one with an unspecified
    /// host, and is otherwise added to the candidates, but only if `allow_observed` is set.
    pub fn endpoints(&self, observed: Option<&Endpoint>) -> (Option<Endpoint>, Vec<Endpoint>) {
        let observed = observed.filter(|_| self.allow_observed);
        let endpoint = match (&self.endpoint, observed) {
            (None, observed) => observed.cloned(),
            (Some(endpoint), Some(observed)) if endpoint.is_host_unspecified() => {
                Some(endpoint.with_host_of(observed))
            },
            (Some(endpoint), _) if endpoint.is_host_unspecified() => None,
            (Some(endpoint), _) => Some(endpoint.clone()),
        };
        let mut candidates = self.candidates.clone();
        if let Some(observed) = observed {
            if endpoint.as_ref() != Some(observed) && !candidates.contains(observed) {
                candidates.push(observed.clone());
            }
        }
        (endpoint, candidates)
    }

    fn has_canonical_extensions(&self) -> bool {
        self.extensions.windows(2).all(|w| w[0].tag < w[1].tag)
    }

    fn message<'a>(
        network: &'a Key,
        signer: &'a Key,
        length: &'a [u8; 8],
        body: &'a [u8],
    ) -> [&'a [u8]; 5] {
        [CONTEXT, network.as_bytes(), signer.as_bytes(), length, body]
    }
}

impl SignedAnnouncement {
    /// Whether this announcement was signed by `signer` for the network identified by the
    /// server's public key `network`. `signer` must be the key pinned for the peer, never one
    /// taken from the announcement or its surroundings.
    pub fn verify(&self, network: &Key, signer: &Key) -> bool {
        if !self.announcement.has_canonical_extensions() {
            return false;
        }
        let body = self.announcement.encode();
        let length = (body.len() as u64).to_le_bytes();
        xeddsa::verify(
            signer,
            &EndpointAnnouncement::message(network, signer, &length, &body),
            &self.signature,
        )
    }
}

/// How a received announcement compares with the last one accepted from the same peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Received {
    /// Nothing was received.
    Nothing,
    /// The timestamp equals the accepted one's, so it was ignored.
    Unchanged,
    /// The signature verified and the timestamp is newer.
    Accepted,
    /// The timestamp is older than the accepted one's.
    Stale,
    /// The timestamp is further in the future than the receiver allows. It may be
    /// accepted later, once it is near enough.
    TooFarAhead,
    /// The signature didn't verify.
    Invalid,
    /// The signature verified, but the announcement carries a critical extension that this
    /// version doesn't understand.
    UnknownCritical(u16),
}

/// Chooses the announcement to use for a peer from the one last accepted from it (if any) and
/// the one just received (if any), and reports what was made of the received one.
///
/// `signer` must be the peer's pinned public key. The accepted announcement is re-verified, so
/// it may be read back from untrusted storage; one that fails is treated as absent. `now` is
/// the receiver's [`timestamp_now`], and `max_ahead` how far ahead of it a received
/// announcement may be dated.
pub fn select<'a>(
    accepted: Option<&'a SignedAnnouncement>,
    received: Option<&'a SignedAnnouncement>,
    network: &Key,
    signer: &Key,
    now: u64,
    max_ahead: Duration,
) -> (Option<&'a SignedAnnouncement>, Received) {
    let accepted = accepted.filter(|accepted| accepted.verify(network, signer));
    let Some(received) = received else {
        return (accepted, Received::Nothing);
    };
    if let Some(accepted) = accepted {
        let (new, old) = (
            received.announcement.timestamp,
            accepted.announcement.timestamp,
        );
        if new == old {
            return (Some(accepted), Received::Unchanged);
        } else if new < old {
            return (Some(accepted), Received::Stale);
        }
    }
    if is_too_far_ahead(received.announcement.timestamp, now, max_ahead) {
        (accepted, Received::TooFarAhead)
    } else if !received.verify(network, signer) {
        (accepted, Received::Invalid)
    } else if let Some(tag) = received.announcement.unknown_critical_extension() {
        (accepted, Received::UnknownCritical(tag))
    } else {
        (Some(received), Received::Accepted)
    }
}

/// Signs announcements with an interface's WireGuard private key.
pub struct AnnouncementSigner {
    private_key: PrivateKey,
    public_key: Key,
}

impl AnnouncementSigner {
    /// Decodes a base64 WireGuard private key and checks that it derives `public_key`, the
    /// interface's own public key, so that a decoding mistake is caught before anything is
    /// signed.
    pub fn new(private_key: &str, public_key: &Key) -> Result<Self, Error> {
        let private_key = PrivateKey::from_base64(private_key)?;
        if private_key.public_key() != public_key {
            bail!("private key does not derive the interface's public key");
        }
        Ok(Self {
            private_key,
            public_key: public_key.clone(),
        })
    }

    pub fn public_key(&self) -> &Key {
        &self.public_key
    }

    pub fn sign(
        &self,
        network: &Key,
        mut announcement: EndpointAnnouncement,
    ) -> Result<SignedAnnouncement, Error> {
        announcement
            .extensions
            .sort_by_key(|extension| extension.tag);
        if !announcement.has_canonical_extensions() {
            bail!("announcement has duplicate extension tags");
        }
        let body = announcement.encode();
        let length = (body.len() as u64).to_le_bytes();
        let signature = self
            .private_key
            .sign(&EndpointAnnouncement::message(
                network,
                &self.public_key,
                &length,
                &body,
            ))
            .to_vec();
        Ok(SignedAnnouncement {
            announcement,
            signature,
        })
    }
}

/// The conventional announcement timestamp: nanoseconds since the epoch of `CLOCK_TAI` where
/// available, which doesn't step backwards over leap seconds, otherwise `CLOCK_REALTIME`.
pub fn timestamp_now() -> u64 {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(timestamp) = clock_nanos(libc::CLOCK_TAI) {
        return timestamp;
    }
    clock_nanos(libc::CLOCK_REALTIME).expect("CLOCK_REALTIME is always available")
}

fn clock_nanos(clock: libc::clockid_t) -> Option<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable timespec.
    if unsafe { libc::clock_gettime(clock, &mut ts) } != 0 {
        return None;
    }
    let seconds = u64::try_from(ts.tv_sec).ok()?;
    seconds
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(ts.tv_nsec).ok()?)
}

mod base64_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        BASE64.decode(encoded).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wireguard_control::KeyPair;

    fn announcement() -> EndpointAnnouncement {
        EndpointAnnouncement {
            timestamp: 1,
            endpoint: Some("0.0.0.0:51820".parse().unwrap()),
            candidates: vec![
                "192.168.1.2:51820".parse().unwrap(),
                "[fd00::2]:51820".parse().unwrap(),
                "peer.example.com:51820".parse().unwrap(),
            ],
            allow_observed: true,
            extensions: vec![],
        }
    }

    fn setup() -> (KeyPair, Key, AnnouncementSigner) {
        let keypair = KeyPair::generate();
        let network = KeyPair::generate().public;
        let signer =
            AnnouncementSigner::new(&keypair.private.to_base64(), &keypair.public).unwrap();
        (keypair, network, signer)
    }

    #[test]
    fn test_sign_and_verify() {
        let (keypair, network, signer) = setup();
        let signed = signer.sign(&network, announcement()).unwrap();
        assert_eq!(signed.signature.len(), SIGNATURE_LENGTH);
        assert!(signed.verify(&network, &keypair.public));
    }

    #[test]
    fn test_survives_json_round_trip() {
        let (keypair, network, signer) = setup();
        let mut announcement = announcement();
        announcement.extensions = vec![Extension {
            tag: 7,
            data: vec![1, 2, 3],
        }];
        let signed = signer.sign(&network, announcement).unwrap();
        let json = serde_json::to_string(&signed).unwrap();
        let decoded: SignedAnnouncement = serde_json::from_str(&json).unwrap();
        assert!(decoded.verify(&network, &keypair.public));
    }

    #[test]
    fn test_rejects_wrong_key_or_network() {
        let (keypair, network, signer) = setup();
        let signed = signer.sign(&network, announcement()).unwrap();
        assert!(!signed.verify(&network, &KeyPair::generate().public));
        assert!(!signed.verify(&KeyPair::generate().public, &keypair.public));
    }

    #[test]
    fn test_rejects_tampering() {
        let (keypair, network, signer) = setup();
        let signed = signer.sign(&network, announcement()).unwrap();
        let tamper: [fn(&mut EndpointAnnouncement); 6] = [
            |a| a.timestamp += 1,
            |a| a.allow_observed = false,
            |a| a.endpoint = Some("203.0.113.9:51820".parse().unwrap()),
            |a| a.candidates.pop().map(drop).unwrap_or_default(),
            |a| a.candidates.swap(0, 1),
            |a| {
                a.extensions.push(Extension {
                    tag: 1,
                    data: vec![],
                })
            },
        ];
        for tamper in tamper {
            let mut tampered = signed.clone();
            tamper(&mut tampered.announcement);
            assert!(!tampered.verify(&network, &keypair.public));
        }
    }

    #[test]
    fn test_moving_bytes_between_fields_changes_encoding() {
        let mut a = announcement();
        a.candidates = vec!["1.2.3.4:1".parse().unwrap()];
        a.endpoint = None;
        let mut b = a.clone();
        b.endpoint = b.candidates.pop();
        assert_ne!(a.encode(), b.encode());
    }

    #[test]
    fn test_extension_order() {
        let (keypair, network, signer) = setup();
        let mut announcement = announcement();
        announcement.extensions = vec![
            Extension {
                tag: 2,
                data: vec![],
            },
            Extension {
                tag: 1,
                data: vec![],
            },
        ];
        // The signer sorts them...
        let signed = signer.sign(&network, announcement).unwrap();
        assert_eq!(signed.announcement.extensions[0].tag, 1);
        assert!(signed.verify(&network, &keypair.public));
        // ...and a duplicate tag is refused.
        let mut duplicate = signed.announcement.clone();
        duplicate.extensions[1].tag = 1;
        assert!(signer.sign(&network, duplicate).is_err());
    }

    #[test]
    fn test_unknown_critical_extension() {
        let mut announcement = announcement();
        announcement.extensions = vec![Extension {
            tag: 3,
            data: vec![],
        }];
        assert_eq!(announcement.unknown_critical_extension(), None);
        announcement.extensions.push(Extension {
            tag: CRITICAL_EXTENSION | 3,
            data: vec![],
        });
        assert_eq!(
            announcement.unknown_critical_extension(),
            Some(CRITICAL_EXTENSION | 3)
        );
    }

    #[test]
    fn test_signer_rejects_mismatched_public_key() {
        let keypair = KeyPair::generate();
        let other = KeyPair::generate();
        assert!(AnnouncementSigner::new(&keypair.private.to_base64(), &other.public).is_err());
        assert!(AnnouncementSigner::new("not base64!", &keypair.public).is_err());
    }

    #[test]
    fn test_timestamp_increases() {
        let a = timestamp_now();
        let b = timestamp_now();
        assert!(a > 1_600_000_000_000_000_000);
        assert!(b >= a);
    }

    fn endpoint(s: &str) -> Endpoint {
        s.parse().unwrap()
    }

    #[test]
    fn test_endpoints_observed_requires_opt_in() {
        let observed = endpoint("198.51.100.7:40000");
        let mut a = announcement();
        a.endpoint = None;
        a.candidates = vec![endpoint("192.168.1.2:51820")];

        a.allow_observed = false;
        assert_eq!(a.endpoints(Some(&observed)), (None, a.candidates.clone()));

        a.allow_observed = true;
        assert_eq!(
            a.endpoints(Some(&observed)),
            (Some(observed.clone()), a.candidates.clone())
        );
    }

    #[test]
    fn test_endpoints_complete_unspecified_host() {
        let observed = endpoint("198.51.100.7:40000");
        let mut a = announcement();
        a.endpoint = Some(endpoint("0.0.0.0:51820"));
        a.candidates = vec![];

        assert_eq!(
            a.endpoints(Some(&observed)),
            (Some(endpoint("198.51.100.7:51820")), vec![observed.clone()])
        );
        assert_eq!(a.endpoints(None), (None, vec![]));
        a.allow_observed = false;
        assert_eq!(a.endpoints(Some(&observed)), (None, vec![]));
    }

    #[test]
    fn test_endpoints_observed_appended_once() {
        let observed = endpoint("198.51.100.7:40000");
        let mut a = announcement();
        a.endpoint = Some(endpoint("203.0.113.1:51820"));
        a.candidates = vec![endpoint("192.168.1.2:51820")];

        let (e, c) = a.endpoints(Some(&observed));
        assert_eq!(e, a.endpoint);
        assert_eq!(c, vec![endpoint("192.168.1.2:51820"), observed.clone()]);

        a.candidates.push(observed.clone());
        assert_eq!(a.endpoints(Some(&observed)).1, a.candidates);
    }

    #[test]
    fn test_select() {
        const NOW: u64 = 1_000;
        const MAX: Duration = DEFAULT_MAX_CLOCK_AHEAD;
        let (keypair, network, signer) = setup();
        let sign = |timestamp| {
            let mut a = announcement();
            a.timestamp = timestamp;
            signer.sign(&network, a).unwrap()
        };
        let (old, new) = (sign(10), sign(20));
        let key = &keypair.public;

        assert_eq!(
            select(None, None, &network, key, NOW, MAX),
            (None, Received::Nothing)
        );
        assert_eq!(
            select(Some(&old), None, &network, key, NOW, MAX),
            (Some(&old), Received::Nothing)
        );
        assert_eq!(
            select(None, Some(&old), &network, key, NOW, MAX),
            (Some(&old), Received::Accepted)
        );
        assert_eq!(
            select(Some(&old), Some(&new), &network, key, NOW, MAX),
            (Some(&new), Received::Accepted)
        );
        assert_eq!(
            select(Some(&new), Some(&old), &network, key, NOW, MAX),
            (Some(&new), Received::Stale)
        );

        // An equal timestamp is ignored without being verified.
        let mut forged = new.clone();
        forged.announcement.candidates.clear();
        assert_eq!(
            select(Some(&new), Some(&forged), &network, key, NOW, MAX),
            (Some(&new), Received::Unchanged)
        );

        // A newer forgery falls back to the accepted one, or to nothing.
        forged.announcement.timestamp = 30;
        assert_eq!(
            select(Some(&new), Some(&forged), &network, key, NOW, MAX),
            (Some(&new), Received::Invalid)
        );
        assert_eq!(
            select(None, Some(&forged), &network, key, NOW, MAX),
            (None, Received::Invalid)
        );

        // A forged "accepted" announcement read back from storage is disregarded.
        assert_eq!(
            select(Some(&forged), Some(&old), &network, key, NOW, MAX),
            (Some(&old), Received::Accepted)
        );

        let mut critical = announcement();
        critical.timestamp = 40;
        critical.extensions = vec![Extension {
            tag: CRITICAL_EXTENSION | 1,
            data: vec![],
        }];
        let critical = signer.sign(&network, critical).unwrap();
        assert_eq!(
            select(Some(&new), Some(&critical), &network, key, NOW, MAX),
            (
                Some(&new),
                Received::UnknownCritical(CRITICAL_EXTENSION | 1)
            )
        );

        // Too far ahead of the receiver's clock: not accepted now, but later.
        let ahead = MAX.as_nanos() as u64;
        let future = sign(NOW + ahead + 1);
        assert_eq!(
            select(Some(&new), Some(&future), &network, key, NOW, MAX),
            (Some(&new), Received::TooFarAhead)
        );
        assert_eq!(
            select(None, Some(&future), &network, key, NOW, MAX),
            (None, Received::TooFarAhead)
        );
        assert_eq!(
            select(Some(&new), Some(&future), &network, key, NOW + 1, MAX),
            (Some(&future), Received::Accepted)
        );
        assert_eq!(
            select(Some(&new), Some(&sign(u64::MAX)), &network, key, NOW, MAX),
            (Some(&new), Received::TooFarAhead)
        );

        // A tighter limit is honoured.
        let tight = Duration::from_nanos(100);
        assert_eq!(
            select(
                Some(&new),
                Some(&sign(NOW + 101)),
                &network,
                key,
                NOW,
                tight
            ),
            (Some(&new), Received::TooFarAhead)
        );
        assert_eq!(
            select(
                Some(&new),
                Some(&sign(NOW + 100)),
                &network,
                key,
                NOW,
                tight
            )
            .1,
            Received::Accepted
        );
    }

    #[test]
    fn test_survives_peer_json_round_trip() {
        let (keypair, network, signer) = setup();
        let mut announcement = announcement();
        announcement.timestamp = u64::MAX;
        announcement.extensions = vec![Extension {
            tag: u16::MAX,
            data: vec![0; 3],
        }];
        let signed = signer.sign(&network, announcement).unwrap();
        let mut peer: crate::Peer = serde_json::from_value(serde_json::json!({
            "id": 1,
            "name": "peer",
            "ip": "10.0.0.2",
            "cidr_id": 1,
            "public_key": keypair.public.to_base64(),
            "endpoint": null,
            "persistent_keepalive_interval": null,
            "is_admin": false,
            "is_disabled": false,
            "is_redeemed": true,
            "invite_expires": null,
        }))
        .unwrap();
        assert_eq!(peer.announcement, None);
        peer.contents.announcement = Some(signed);
        peer.contents.observed_endpoint = Some(endpoint("198.51.100.7:40000"));

        let json = serde_json::to_string(&peer).unwrap();
        let decoded: crate::Peer = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, peer);
        assert!(decoded
            .announcement
            .as_ref()
            .unwrap()
            .verify(&network, &keypair.public));
    }
}
