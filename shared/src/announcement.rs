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
use wireguard_control::Key;

/// Domain separator for endpoint announcements. Only changes on an incompatible format change.
const CONTEXT: &[u8] = b"innernet/v1/peer-endpoints\0";

/// Extension tags with this bit set alter the meaning of the other fields, so an announcement
/// carrying one that the recipient doesn't understand must not be used.
pub const CRITICAL_EXTENSION: u16 = 0x8000;

pub const SIGNATURE_LENGTH: usize = xeddsa::SIGNATURE_LENGTH;

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
}
