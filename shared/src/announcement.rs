//! Signed announcements: what a peer claims of the resources that the server delegates to it, and
//! what it states about itself.
//!
//! A peer signs an [`Announcement`] with its WireGuard key, using [XEdDSA](crate::xeddsa). The
//! server stores the signed bytes and relays them to the other peers unchanged, as a
//! [`SignedAnnouncement`]. Each recipient checks the signature over those bytes before it decodes
//! them, so that the server can neither forge nor alter what a peer announces, and nothing is ever
//! encoded again to be checked.
//!
//! An announcement holds two kinds of fields. A claim is a field whose validity depends on what
//! only the server knows: the [`Claims`] state the delegation of the peer, the prefixes that it
//! claims of the ranges that the server assigns it, and its name, one of those that the server
//! offers it. The server checks each claim, and refuses an announcement that claims what it
//! doesn't assign; it can't narrow what a peer signed. Every recipient pins a claim to the key of
//! the peer while the last announcement accepted from the peer makes it, so that no other key can
//! take what the peer claims, whatever the server reports. A statement is any other field: what
//! the peer states about itself, which recipients check against its claims. A peer states its
//! allowed IPs, the prefixes that it accepts traffic for, its primary IP, the address at which its
//! name resolves, the endpoints at which it is reached, in the order in which peers try them, and
//! the nameserver that it offers for the names under its own.
//!
//! For a peer that has never announced, such as one whose client predates announcements, the
//! server makes an unsigned announcement of what it records of the peer, as
//! [`Announcement::synthetic`] makes it, and relays it in the same shape, without the signature. A
//! recipient handles both alike, with one difference: an unsigned announcement may pin what it
//! claims, but never releases what is pinned, since the server alone could otherwise move what a
//! peer holds to another key. A peer's first signed announcement that a recipient accepts latches
//! the peer: from then on, the recipient accepts only signed announcements of it.
//!
//! The payload is an [`Announcement`] in the deterministic encoding of CBOR ([`crate::cbor`]), as a
//! map with text keys. Keys, prefixes and addresses are text, as everywhere on the wire. The claims
//! are the map under the key `claims`, each type of claim, as [`CLAIM_TYPES`] names them, under a
//! key of its own; the statements are the other keys of the payload. The server refuses an
//! announcement with a claim of a type that it doesn't check, and states the types that it checks
//! in its capabilities, so that a client announces only those, and accepts of a relayed
//! announcement only the claims of those types: a server that predates a type of claim can't relay
//! a claim of that type that it never checked. A recipient ignores the statements that it doesn't
//! know. The signed message is [`DOMAIN`], the public key of the peer, and the payload, in that
//! order. It names no network: a peer's key belongs to one network, and an announcement that
//! named the coordinator would no longer hold once the network changed coordinators.

use crate::{cbor, hosts_fallback, xeddsa, Endpoint, Hostname, PeerContents, Prefix};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::BTreeMap,
    fmt::{self, Display, Formatter},
    net::{IpAddr, SocketAddr},
    time::{Duration, SystemTime},
};
use wireguard_control::Key;

/// The domain separator of the signed message, which changes only with an incompatible change of
/// the format.
pub const DOMAIN: &[u8] = b"innernet announcement v1\0";

/// The longest payload that a peer may sign, and that a recipient reads.
pub const MAX_PAYLOAD_LEN: usize = 4096;

/// The most endpoints that an announcement may carry.
pub const MAX_ENDPOINTS: usize = 11;

/// How far ahead of the recipient's clock the timestamp of an announcement may be. An announcement
/// from the distant future would hold up every later one of the peer until then, as a wrong clock
/// could date it, so the limit caps how long the peer can be held up.
pub const MAX_CLOCK_AHEAD: Duration = Duration::from_secs(10 * 60);

/// The types of claims that this version understands, each the key of its claims in [`Claims`].
pub const CLAIM_TYPES: [&str; 2] = ["delegation", "name"];

/// What a peer claims and states about itself: the payload of a [`SignedAnnouncement`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Announcement {
    /// Orders the announcements of a peer: each must be greater than the last that a recipient
    /// accepted from the peer. Nanoseconds since the UNIX epoch, as [`timestamp_now`] reads them.
    pub timestamp: u64,

    /// The resources that the peer claims.
    #[serde(default)]
    pub claims: Claims,

    /// The prefixes that the peer accepts traffic for, which other peers route to it. Each
    /// recipient shrinks them to the delegation that the peer claims, as [`shrink_to`] does,
    /// rather than refuse the announcement, so that a later version may state more.
    #[serde(default, rename = "allowedIps", skip_serializing_if = "Vec::is_empty")]
    pub allowed_ips: Vec<Prefix>,

    /// The address at which the name of the peer resolves, and which the server always routes to
    /// it.
    /// The server refuses an announcement without one, or with one outside the claimed
    /// delegation; other recipients take it as it is.
    #[serde(
        default,
        rename = "primaryIp",
        skip_serializing_if = "Option::is_none",
        with = "ip_as_text"
    )]
    pub primary_ip: Option<IpAddr>,

    /// The endpoints at which peers reach the peer, the preferred first, in the order in which
    /// peers try them, at most [`MAX_ENDPOINTS`]. An endpoint whose host is unspecified, such as
    /// `0.0.0.0:51820`, can't be reached, and takes no effect.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<Endpoint>,

    /// The nameserver that the peer offers for its own name and the names under it. A recipient
    /// takes it only if it lies within the delegation that the peer claims; one that the allowed
    /// IPs don't route is merely unreachable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nameserver: Option<Nameserver>,
}

/// A nameserver that a peer offers for its own name and the names under it.
///
/// Each recipient names the peer by its own hostname for it, such as `peer.wg0.wg`, which differs
/// between recipients with different host suffixes. The nameserver answers for `zone` instead: a
/// recipient that forwards a query replaces its hostname of the peer with `zone`, and `zone` with
/// its hostname again in the response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nameserver {
    /// The address and port at which the nameserver answers, within the delegation of the peer,
    /// so that queries reach it through the tunnel to the peer. The address isn't unspecified,
    /// and the port isn't 0.
    #[serde(with = "socket_addr_as_text")]
    pub address: SocketAddr,

    /// The domain that the nameserver answers for, a canonical domain as
    /// [`innernet_domain::is_canonical_domain`] accepts it, so at most 253 bytes long.
    pub zone: String,
}

impl Nameserver {
    /// Checks that the address is neither unspecified nor at port 0, and that the zone is a
    /// canonical domain.
    pub fn check(&self) -> Result<(), String> {
        if self.address.ip().is_unspecified() || self.address.port() == 0 {
            return Err(format!(
                "the nameserver address {} can't be reached",
                self.address
            ));
        }
        if !innernet_domain::is_canonical_domain(&self.zone) {
            return Err(format!(
                "the zone {} is not a canonical domain",
                self.zone.escape_debug()
            ));
        }
        Ok(())
    }
}

/// The claims of an announcement, each type under its key of [`CLAIM_TYPES`]. A claim that an
/// announcement leaves out claims nothing of its type.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// The delegation of the peer: the prefixes that it claims of the ranges that the server
    /// assigns it, sorted, no two of which share an address. The addresses are the peer's, nobody
    /// else may use them, and the server may not assign them to another peer.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "crate::types::deserialize_delegations"
    )]
    pub delegation: Vec<Prefix>,

    /// The name of the peer, one of those that the server offers it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<Hostname>,
}

/// An announcement as a peer signed it, and as the server stores and relays it: the payload, the
/// exact bytes that were signed, and the signature. In CBOR, both are byte strings; in
/// human-readable formats, such as JSON, base64 text. An announcement that the server makes for a
/// peer that has never announced has no signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAnnouncement {
    #[serde(with = "bytes")]
    pub payload: Vec<u8>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "option_bytes"
    )]
    pub signature: Option<Vec<u8>>,
}

/// Why an announcement is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnnouncementError {
    /// The payload is longer than [`MAX_PAYLOAD_LEN`].
    TooLarge,
    /// The signature isn't that of the peer over the payload.
    BadSignature,
    /// The payload isn't an announcement, or one that breaks the rules of announcements.
    Malformed(String),
    /// The payload claims a type of resource that the recipient doesn't check.
    UnknownClaim(String),
    /// The timestamp isn't greater than that of the last announcement accepted from the peer.
    Stale { timestamp: u64, last: u64 },
    /// The timestamp is further ahead of the recipient's clock than [`MAX_CLOCK_AHEAD`].
    TooFarAhead,
}

impl Display for AnnouncementError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => write!(f, "the announcement is longer than {MAX_PAYLOAD_LEN} bytes"),
            Self::BadSignature => f.write_str("the signature of the announcement is not valid"),
            Self::Malformed(reason) => write!(f, "the announcement is malformed: {reason}"),
            Self::UnknownClaim(claim) => write!(
                f,
                "the announcement makes a claim of the type {}, which is not checked",
                claim.escape_debug()
            ),
            Self::Stale { timestamp, last } => write!(
                f,
                "the announcement of timestamp {timestamp} is not newer than the last one, of \
                 timestamp {last}"
            ),
            Self::TooFarAhead => write!(
                f,
                "the timestamp of the announcement is more than {} seconds ahead of the clock",
                MAX_CLOCK_AHEAD.as_secs()
            ),
        }
    }
}

impl std::error::Error for AnnouncementError {}

impl Announcement {
    /// Signs the announcement with `private_key`.
    pub fn sign(
        &self,
        private_key: &xeddsa::PrivateKey,
    ) -> Result<SignedAnnouncement, AnnouncementError> {
        let payload =
            cbor::to_vec(self).map_err(|e| AnnouncementError::Malformed(e.to_string()))?;
        SignedAnnouncement::sign(payload, private_key)
    }

    /// The announcement that the server makes for a peer that has never announced, from `peer`,
    /// what it records of the peer: it claims every delegation of the peer and its name, accepts
    /// traffic for all of its delegation, has the lowest address of its delegation as its primary
    /// IP, and is reached at the endpoint that the server records, then at the candidates that
    /// it records, into which the server has put the endpoint that it observes, as
    /// [`legacy_endpoints`] orders them. Its timestamp is 0, so that the first announcement that
    /// the peer signs is newer.
    pub fn synthetic(peer: &PeerContents) -> Self {
        Self {
            timestamp: 0,
            claims: Claims {
                delegation: peer.delegations.clone(),
                name: peer.name.clone(),
            },
            allowed_ips: peer.delegations.clone(),
            primary_ip: hosts_fallback(&peer.delegations),
            endpoints: legacy_endpoints(peer.endpoint.as_ref(), &peer.candidates),
            nameserver: None,
        }
    }

    /// Checks the announcement against `assigned`, the ranges that the server assigns the peer
    /// that made it, and `name`, the name that the server offers it, as the server does before it
    /// accepts the announcement: each prefix of the delegation must lie within an assigned range,
    /// the name must be the one offered, if the peer claims one, and the primary IP must be
    /// stated and lie within the delegation.
    pub fn check_assigned(
        &self,
        assigned: &[Prefix],
        name: Option<&Hostname>,
    ) -> Result<(), Unassigned> {
        if let Some(claimed) = &self.claims.name {
            if name != Some(claimed) {
                return Err(Unassigned::Name(claimed.clone()));
            }
        }
        if let Some(prefix) = self
            .claims
            .delegation
            .iter()
            .find(|prefix| !assigned.iter().any(|range| range.contains(prefix)))
        {
            return Err(Unassigned::Prefix(*prefix));
        }
        match self.primary_ip {
            None => Err(Unassigned::NoPrimaryIp),
            Some(ip) if !self.claims.delegation.iter().any(|d| d.contains_addr(&ip)) => {
                Err(Unassigned::PrimaryIpOutside(ip))
            },
            Some(_) => Ok(()),
        }
    }
}

/// Why a coordinator refuses an announcement: it claims what isn't assigned or offered to its
/// peer, as [`Announcement::check_assigned`] tells.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unassigned {
    /// The claimed name isn't the one offered to the peer.
    Name(Hostname),
    /// The claimed prefix lies within no range assigned to the peer.
    Prefix(Prefix),
    /// The announcement states no primary IP.
    NoPrimaryIp,
    /// The primary IP lies within no prefix of the claimed delegation.
    PrimaryIpOutside(IpAddr),
}

impl Display for Unassigned {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => write!(f, "the name {name} is not offered to the peer"),
            Self::Prefix(prefix) => {
                write!(f, "{prefix} lies within no range assigned to the peer")
            },
            Self::NoPrimaryIp => f.write_str("the announcement states no primary IP"),
            Self::PrimaryIpOutside(ip) => write!(
                f,
                "the primary IP {ip} lies within no prefix of the claimed delegation"
            ),
        }
    }
}

impl std::error::Error for Unassigned {}

impl Claims {
    /// Leaves out the claims of the types that `types` doesn't list, as if the peer made none of
    /// them.
    pub fn retain_types(&mut self, types: &[String]) {
        let listed = |claim: &str| types.iter().any(|listed| listed == claim);
        if !listed("delegation") {
            self.delegation = vec![];
        }
        if !listed("name") {
            self.name = None;
        }
    }
}

/// The endpoints of a peer as an announcement orders them, of `endpoint` and `candidates`, as a
/// peer that predates announcements sets them in plain HTTP: `endpoint` first, if any, then the
/// candidates that differ from it, at most [`MAX_ENDPOINTS`] in all.
pub fn legacy_endpoints(endpoint: Option<&Endpoint>, candidates: &[Endpoint]) -> Vec<Endpoint> {
    let mut endpoints: Vec<Endpoint> = endpoint.into_iter().cloned().collect();
    for candidate in candidates {
        if !endpoints.contains(candidate) {
            endpoints.push(candidate.clone());
        }
    }
    endpoints.truncate(MAX_ENDPOINTS);
    endpoints
}

/// The prefixes of `allowed` shrunk to `delegation`: of each prefix of `allowed` and each of
/// `delegation` that overlap, the smaller, which aligned prefixes always nest. The result is
/// sorted, and holds no prefix that another of it holds, nor any address outside `delegation`.
pub fn shrink_to(allowed: &[Prefix], delegation: &[Prefix]) -> Vec<Prefix> {
    let mut shrunk: Vec<Prefix> = allowed
        .iter()
        .flat_map(|allowed| {
            delegation.iter().filter_map(move |claimed| {
                if claimed.contains(allowed) {
                    Some(*allowed)
                } else if allowed.contains(claimed) {
                    Some(*claimed)
                } else {
                    None
                }
            })
        })
        .collect();
    shrunk.sort();
    shrunk.dedup();
    let nested = |prefix: &Prefix, all: &[Prefix]| {
        all.iter()
            .any(|other| other != prefix && other.contains(prefix))
    };
    let all = shrunk.clone();
    shrunk.retain(|prefix| !nested(prefix, &all));
    shrunk
}

impl SignedAnnouncement {
    /// Signs `payload`, the bytes of an announcement as they are, with `private_key`.
    pub fn sign(
        payload: Vec<u8>,
        private_key: &xeddsa::PrivateKey,
    ) -> Result<Self, AnnouncementError> {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(AnnouncementError::TooLarge);
        }
        let signature = private_key
            .sign(&message(private_key.public_key(), &payload))
            .to_vec();
        Ok(Self {
            payload,
            signature: Some(signature),
        })
    }

    /// `announcement` without a signature, as the server makes it for a peer that has never
    /// announced.
    pub fn unsigned(announcement: &Announcement) -> Result<Self, AnnouncementError> {
        let payload =
            cbor::to_vec(announcement).map_err(|e| AnnouncementError::Malformed(e.to_string()))?;
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(AnnouncementError::TooLarge);
        }
        Ok(Self {
            payload,
            signature: None,
        })
    }

    /// Whether the announcement carries a signature, which [`Self::open`] checks.
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Checks the signature of the announcement, that of the peer with the public key `signer`,
    /// and only then decodes the payload. `signer` must be the key of the peer, never one taken
    /// from the announcement. An announcement without a signature is refused.
    pub fn open(&self, signer: &Key) -> Result<Announcement, AnnouncementError> {
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(AnnouncementError::TooLarge);
        }
        let Some(signature) = &self.signature else {
            return Err(AnnouncementError::BadSignature);
        };
        if !xeddsa::verify(signer, &message(signer, &self.payload), signature) {
            return Err(AnnouncementError::BadSignature);
        }
        self.decode()
    }

    /// Decodes the payload without checking the signature, as the holder of an announcement that
    /// it checked when it accepted it does, and as a recipient reads an unsigned one.
    pub fn decode(&self) -> Result<Announcement, AnnouncementError> {
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(AnnouncementError::TooLarge);
        }
        let announcement: Announcement = cbor::from_slice(&self.payload)
            .map_err(|e| AnnouncementError::Malformed(e.to_string()))?;
        if announcement.endpoints.len() > MAX_ENDPOINTS {
            return Err(AnnouncementError::Malformed(format!(
                "it has more than {MAX_ENDPOINTS} endpoints"
            )));
        }
        if let Some(nameserver) = &announcement.nameserver {
            nameserver.check().map_err(AnnouncementError::Malformed)?;
        }
        Ok(announcement)
    }

    /// Checks that the payload makes only claims of the types of `checked`, whether or not this
    /// version understands the others.
    pub fn check_claim_types(&self, checked: &[&str]) -> Result<(), AnnouncementError> {
        #[derive(Deserialize)]
        struct Payload {
            #[serde(default)]
            claims: BTreeMap<String, de::IgnoredAny>,
        }
        let payload: Payload = cbor::from_slice(&self.payload)
            .map_err(|e| AnnouncementError::Malformed(e.to_string()))?;
        match payload
            .claims
            .into_keys()
            .find(|claim| !checked.contains(&claim.as_str()))
        {
            Some(claim) => Err(AnnouncementError::UnknownClaim(claim)),
            None => Ok(()),
        }
    }
}

/// The signed message of the payload `payload` of the peer `signer`. The domain separator and the
/// key have fixed lengths, so the parts can't be confused.
fn message<'a>(signer: &'a Key, payload: &'a [u8]) -> [&'a [u8]; 3] {
    [DOMAIN, signer.as_bytes(), payload]
}

/// Checks that `timestamp`, that of an announcement received at the time `now`, is greater than
/// `last`, that of the last announcement accepted from the same peer, if any, and not further
/// ahead of `now` than [`MAX_CLOCK_AHEAD`], as [`check_not_ahead`] checks it.
pub fn check_timestamp(
    timestamp: u64,
    last: Option<u64>,
    now: u64,
) -> Result<(), AnnouncementError> {
    if let Some(last) = last.filter(|last| timestamp <= *last) {
        return Err(AnnouncementError::Stale { timestamp, last });
    }
    check_not_ahead(timestamp, now)
}

/// Checks that `timestamp`, that of an announcement received at the time `now`, is not further
/// ahead of `now` than [`MAX_CLOCK_AHEAD`].
pub fn check_not_ahead(timestamp: u64, now: u64) -> Result<(), AnnouncementError> {
    let max_ahead = u64::try_from(MAX_CLOCK_AHEAD.as_nanos()).unwrap_or(u64::MAX);
    if timestamp > now.saturating_add(max_ahead) {
        return Err(AnnouncementError::TooFarAhead);
    }
    Ok(())
}

/// The time as an announcement dates it: nanoseconds since the UNIX epoch.
pub fn timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

impl PeerContents {
    /// The peer as it takes effect with `announcement`, the last announcement accepted from it,
    /// or as the server records it, without an announcement. Its delegations are those that it
    /// claims, its allowed IPs those that it states shrunk to them, its primary IP and name those
    /// that it states and claims, its endpoint the first of the endpoints that it states, and its
    /// candidates the others, in their order, but for those whose host is unspecified, and its
    /// nameserver the one that it states, if it lies within its delegations. What the server
    /// reports of the delegations and the name of a peer that has announced takes no effect.
    pub fn effective_with(&self, announcement: Option<&Announcement>) -> PeerContents {
        let Some(announcement) = announcement else {
            return PeerContents {
                allowed_ips: None,
                primary_ip: None,
                nameserver: None,
                ..self.clone()
            };
        };
        let delegations = announcement.claims.delegation.clone();
        let nameserver = announcement.nameserver.clone().filter(|nameserver| {
            delegations
                .iter()
                .any(|d| d.contains_addr(&nameserver.address.ip()))
        });
        let mut candidates: Vec<Endpoint> = announcement
            .endpoints
            .iter()
            .filter(|endpoint| !endpoint.is_host_unspecified())
            .cloned()
            .collect();
        let endpoint = (!candidates.is_empty()).then(|| candidates.remove(0));
        PeerContents {
            name: announcement.claims.name.clone(),
            allowed_ips: Some(shrink_to(&announcement.allowed_ips, &delegations)),
            delegations,
            endpoint,
            candidates,
            primary_ip: announcement.primary_ip,
            nameserver,
            ..self.clone()
        }
    }

    /// The peer as it takes effect with the announcement that `self` holds, as
    /// [`Self::effective_with`] combines them, which the holder must have checked when it
    /// accepted it, or, for a peer without one, as the server records it, as the unsigned
    /// announcement that the server makes of it would make it. A peer whose announcement can't be
    /// decoded is routed nothing.
    pub fn effective(&self) -> PeerContents {
        match self.announcement.as_ref().map(SignedAnnouncement::decode) {
            None => self.effective_with(None),
            Some(Ok(announcement)) => self.effective_with(Some(&announcement)),
            Some(Err(e)) => {
                log::warn!(
                    "routing nothing to peer {}, whose stored announcement is invalid: {e}",
                    self.public_key
                );
                self.effective_with(Some(&Announcement::default()))
            },
        }
    }
}

/// Bytes, as byte strings in CBOR, and as base64 text in human-readable formats.
mod bytes {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&BASE64.encode(bytes))
        } else {
            serializer.serialize_bytes(bytes)
        }
    }

    /// Reads bytes from a byte string, and, in a human-readable format, from base64 text. serde
    /// buffers the values that it can't tell apart before it reads them, such as the peers of a
    /// state, each of which may fail to read alone, and the buffer counts as human-readable
    /// whatever the format, so a byte string is read there too.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        struct Visitor {
            text: bool,
        }

        impl de::Visitor<'_> for Visitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a byte string")
            }

            fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Vec<u8>, E> {
                Ok(bytes.to_vec())
            }

            fn visit_byte_buf<E: de::Error>(self, bytes: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(bytes)
            }

            fn visit_str<E: de::Error>(self, text: &str) -> Result<Vec<u8>, E> {
                if !self.text {
                    return Err(E::invalid_type(de::Unexpected::Str(text), &self));
                }
                BASE64.decode(text).map_err(E::custom)
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_any(Visitor { text: true })
        } else {
            deserializer.deserialize_byte_buf(Visitor { text: false })
        }
    }
}

/// Optional bytes, as [`bytes`] transfers them.
mod option_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(
        bytes: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => super::bytes::serialize(bytes, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        super::bytes::deserialize(deserializer).map(Some)
    }
}

/// A socket address as text, whatever the format, as the TLS API transfers it.
mod socket_addr_as_text {
    use super::*;

    pub fn serialize<S: Serializer>(
        address: &SocketAddr,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_str(address)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<SocketAddr, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

/// An address as text, whatever the format, as the TLS API transfers it.
mod ip_as_text {
    use super::*;

    pub fn serialize<S: Serializer>(
        address: &Option<IpAddr>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match address {
            Some(address) => serializer.collect_str(address),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<IpAddr>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|address| address.parse().map_err(de::Error::custom))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wireguard_control::KeyPair;

    fn keys() -> (KeyPair, xeddsa::PrivateKey) {
        let keypair = KeyPair::generate();
        let private_key = xeddsa::PrivateKey::from_base64(&keypair.private.to_base64()).unwrap();
        (keypair, private_key)
    }

    fn prefixes(prefixes: &[&str]) -> Vec<Prefix> {
        prefixes
            .iter()
            .map(|prefix| prefix.parse().unwrap())
            .collect()
    }

    fn claims() -> Claims {
        Claims {
            delegation: prefixes(&["10.0.0.32/28", "fd00::/112"]),
            name: Some("peer".parse().unwrap()),
        }
    }

    fn announcement() -> Announcement {
        Announcement {
            timestamp: 1,
            claims: claims(),
            allowed_ips: prefixes(&["10.0.0.32/29", "fd00::/112"]),
            primary_ip: Some("10.0.0.33".parse().unwrap()),
            endpoints: vec![
                "203.0.113.9:51820".parse().unwrap(),
                "192.0.2.2:51820".parse().unwrap(),
                "peer.example.com:51820".parse().unwrap(),
            ],
            nameserver: Some(nameserver("10.0.0.34:53", "example.com")),
        }
    }

    fn nameserver(address: &str, zone: &str) -> Nameserver {
        Nameserver {
            address: address.parse().unwrap(),
            zone: zone.into(),
        }
    }

    fn peer(public_key: &Key) -> PeerContents {
        PeerContents {
            name: Some("peer".parse().unwrap()),
            delegations: prefixes(&["10.0.0.0/24", "fd00::/64"]),
            public_key: public_key.to_base64(),
            endpoint: Some("198.51.100.1:1".parse().unwrap()),
            persistent_keepalive_interval: None,
            is_admin: false,
            is_disabled: false,
            is_redeemed: true,
            invite_expires: None,
            candidates: vec!["198.51.100.2:2".parse().unwrap()],
            announcement: None,
            allowed_ips: None,
            primary_ip: None,
            nameserver: None,
        }
    }

    /// Signs `payload`, whatever it holds, with `private_key` as the key of `keypair`.
    fn sign_raw(
        keypair: &KeyPair,
        private_key: &xeddsa::PrivateKey,
        payload: Vec<u8>,
    ) -> SignedAnnouncement {
        SignedAnnouncement {
            signature: Some(
                private_key
                    .sign(&message(&keypair.public, &payload))
                    .to_vec(),
            ),
            payload,
        }
    }

    #[test]
    fn test_signed_bytes_are_checked_as_they_are() {
        let (keypair, private_key) = keys();
        let signed = announcement().sign(&private_key).unwrap();
        assert_eq!(signed.payload, cbor::to_vec(&announcement()).unwrap());
        assert_eq!(signed.open(&keypair.public), Ok(announcement()));

        // The signature binds the payload and the peer, and the message is the domain separator,
        // the peer's key and the payload, and nothing else.
        let other = KeyPair::generate().public;
        assert_eq!(signed.open(&other), Err(AnnouncementError::BadSignature));
        assert!(xeddsa::verify(
            &keypair.public,
            &[DOMAIN, keypair.public.as_bytes(), &signed.payload],
            signed.signature.as_ref().unwrap()
        ));
        let mut tampered = signed.clone();
        *tampered.payload.last_mut().unwrap() ^= 1;
        assert_eq!(
            tampered.open(&keypair.public),
            Err(AnnouncementError::BadSignature)
        );
        let mut tampered = signed.clone();
        tampered.signature.as_mut().unwrap()[0] ^= 1;
        assert_eq!(
            tampered.open(&keypair.public),
            Err(AnnouncementError::BadSignature)
        );

        // An unsigned announcement is never opened, only decoded.
        let unsigned = SignedAnnouncement::unsigned(&announcement()).unwrap();
        assert_eq!(unsigned.payload, signed.payload);
        assert!(!unsigned.is_signed());
        assert_eq!(
            unsigned.open(&keypair.public),
            Err(AnnouncementError::BadSignature)
        );
        assert_eq!(unsigned.decode(), Ok(announcement()));
    }

    #[test]
    fn test_claims_are_a_map_of_their_own() {
        #[derive(Deserialize)]
        struct Payload {
            timestamp: u64,
            claims: BTreeMap<String, de::IgnoredAny>,
            #[serde(rename = "allowedIps")]
            allowed_ips: Vec<String>,
            #[serde(rename = "primaryIp")]
            primary_ip: String,
            endpoints: Vec<String>,
        }
        let payload: Payload = cbor::from_slice(&cbor::to_vec(&announcement()).unwrap()).unwrap();
        assert_eq!(payload.timestamp, 1);
        let mut types: Vec<&str> = payload.claims.keys().map(String::as_str).collect();
        let mut known = CLAIM_TYPES.to_vec();
        types.sort();
        known.sort();
        assert_eq!(types, known);
        // The statements lie beside the claims, as text.
        assert_eq!(payload.allowed_ips, ["10.0.0.32/29", "fd00::/112"]);
        assert_eq!(payload.primary_ip, "10.0.0.33");
        assert_eq!(payload.endpoints.len(), 3);
        assert_eq!(payload.endpoints[0], "203.0.113.9:51820");

        // An announcement that claims nothing still has the map, empty.
        let nothing = Announcement {
            timestamp: 1,
            ..Default::default()
        };
        #[derive(Deserialize)]
        struct Claimed {
            claims: BTreeMap<String, de::IgnoredAny>,
        }
        let payload: Claimed = cbor::from_slice(&cbor::to_vec(&nothing).unwrap()).unwrap();
        assert!(payload.claims.is_empty());
    }

    #[test]
    fn test_unknown_keys_are_kept_and_ignored() {
        // A later version adds a statement, and a type of claim, which a recipient ignores, while
        // the signature still covers the bytes that hold them.
        #[derive(Serialize)]
        struct LaterClaims<'a> {
            #[serde(flatten)]
            claims: &'a Claims,
            relay: bool,
        }
        #[derive(Serialize)]
        struct Later<'a> {
            timestamp: u64,
            claims: LaterClaims<'a>,
            #[serde(rename = "primaryIp")]
            primary_ip: &'a str,
            note: &'a str,
        }
        let (keypair, private_key) = keys();
        let announcement = Announcement {
            timestamp: 1,
            claims: claims(),
            primary_ip: Some("10.0.0.33".parse().unwrap()),
            ..Default::default()
        };
        let payload = cbor::to_vec(&Later {
            timestamp: announcement.timestamp,
            claims: LaterClaims {
                claims: &announcement.claims,
                relay: true,
            },
            primary_ip: "10.0.0.33",
            note: "not a claim",
        })
        .unwrap();
        let signed = sign_raw(&keypair, &private_key, payload);
        assert_eq!(signed.open(&keypair.public), Ok(announcement));

        // A recipient that checks claims refuses the type of claim that it doesn't check, and only
        // that: a statement is no claim.
        assert_eq!(
            signed.check_claim_types(&CLAIM_TYPES),
            Err(AnnouncementError::UnknownClaim("relay".into()))
        );
        let mut checked = CLAIM_TYPES.to_vec();
        checked.push("relay");
        assert_eq!(signed.check_claim_types(&checked), Ok(()));
        assert_eq!(
            sign_raw(
                &keypair,
                &private_key,
                cbor::to_vec(&self::announcement()).unwrap()
            )
            .check_claim_types(&CLAIM_TYPES),
            Ok(())
        );
    }

    #[test]
    fn test_retain_types() {
        let mut retained = claims();
        retained.retain_types(&CLAIM_TYPES.map(String::from));
        assert_eq!(retained, claims());
        retained.retain_types(&["name".to_string()]);
        assert_eq!(
            retained,
            Claims {
                name: claims().name,
                ..Default::default()
            }
        );
        retained.retain_types(&[]);
        assert_eq!(retained, Claims::default());
    }

    #[test]
    fn test_refuses_malformed_payloads() {
        let (keypair, private_key) = keys();
        let sign = |payload: Vec<u8>| sign_raw(&keypair, &private_key, payload);

        // Prefixes are text, as everywhere on the wire, and two of the delegation that overlap
        // are refused.
        let text = cbor::to_vec(&announcement()).unwrap();
        assert!(sign(text.clone()).open(&keypair.public).is_ok());
        #[derive(Deserialize)]
        struct Texts {
            delegation: Vec<String>,
        }
        #[derive(Deserialize)]
        struct Payload {
            claims: Texts,
        }
        let texts: Payload = cbor::from_slice(&text).unwrap();
        assert_eq!(texts.claims.delegation, ["10.0.0.32/28", "fd00::/112"]);
        #[derive(Serialize)]
        struct Overlapping {
            delegation: [&'static str; 2],
        }
        #[derive(Serialize)]
        struct WithOverlapping {
            timestamp: u64,
            claims: Overlapping,
        }
        let overlapping = WithOverlapping {
            timestamp: 1,
            claims: Overlapping {
                delegation: ["10.0.0.0/24", "10.0.0.0/25"],
            },
        };
        assert!(matches!(
            sign(cbor::to_vec(&overlapping).unwrap()).open(&keypair.public),
            Err(AnnouncementError::Malformed(_))
        ));

        // A payload that isn't in the deterministic encoding is refused, even signed.
        let mut longer = vec![0xb9, 0x00];
        longer.extend_from_slice(&text[1..]);
        assert!(matches!(
            sign(longer.clone()).open(&keypair.public),
            Err(AnnouncementError::Malformed(_))
        ));
        assert!(matches!(
            sign(longer).check_claim_types(&CLAIM_TYPES),
            Err(AnnouncementError::Malformed(_))
        ));

        // So are a payload that is too long and too many endpoints.
        assert_eq!(
            sign(vec![0; MAX_PAYLOAD_LEN + 1]).open(&keypair.public),
            Err(AnnouncementError::TooLarge)
        );
        let crowded = Announcement {
            endpoints: vec!["192.0.2.1:1".parse().unwrap(); MAX_ENDPOINTS + 1],
            ..Default::default()
        };
        assert!(matches!(
            sign(cbor::to_vec(&crowded).unwrap()).open(&keypair.public),
            Err(AnnouncementError::Malformed(_))
        ));
    }

    #[test]
    fn test_signed_announcements_in_cbor_and_json() {
        let (_, private_key) = keys();
        let signed = announcement().sign(&private_key).unwrap();
        // A map of two byte strings, the payload holding the signed bytes as they are.
        #[derive(Deserialize)]
        struct Members {
            payload: cbor::ByteBuf,
            signature: cbor::ByteBuf,
        }
        let members: Members = cbor::from_slice(&cbor::to_vec(&signed).unwrap()).unwrap();
        assert_eq!(members.payload.0, signed.payload);
        assert_eq!(members.signature.0.len(), xeddsa::SIGNATURE_LENGTH);
        // An unsigned announcement is the same map without the signature.
        #[derive(Deserialize)]
        struct Payload {
            payload: cbor::ByteBuf,
            signature: Option<cbor::ByteBuf>,
        }
        let unsigned = SignedAnnouncement::unsigned(&announcement()).unwrap();
        let read: Payload = cbor::from_slice(&cbor::to_vec(&unsigned).unwrap()).unwrap();
        assert_eq!(read.payload.0, signed.payload);
        assert!(read.signature.is_none());
        assert_eq!(
            cbor::from_slice::<SignedAnnouncement>(&cbor::to_vec(&unsigned).unwrap()).unwrap(),
            unsigned
        );
        assert_eq!(
            cbor::from_slice::<SignedAnnouncement>(&cbor::to_vec(&signed).unwrap()).unwrap(),
            signed
        );
        // A byte string only: the payload in base64 text is refused in CBOR.
        #[derive(Serialize)]
        struct Text {
            payload: String,
            signature: String,
        }
        let text = Text {
            payload: "AA==".into(),
            signature: "AA==".into(),
        };
        assert!(cbor::from_slice::<SignedAnnouncement>(&cbor::to_vec(&text).unwrap()).is_err());

        let json = serde_json::to_string(&signed).unwrap();
        assert_eq!(
            serde_json::from_str::<SignedAnnouncement>(&json).unwrap(),
            signed
        );
    }

    #[test]
    fn test_relayed_in_a_state() {
        // A state reads each of its peers alone, through a buffer, which keeps the payload and
        // the signature byte strings.
        let (keypair, private_key) = keys();
        let mut peer = peer(&keypair.public);
        peer.announcement = Some(announcement().sign(&private_key).unwrap());
        let state = crate::State {
            peers: vec![peer],
            cidrs: vec![],
            observed_endpoint: Some("203.0.113.9:4000".parse().unwrap()),
            invalid_peer_keys: vec![],
        };
        let read: crate::State = cbor::from_slice(&cbor::to_vec(&state).unwrap()).unwrap();
        assert_eq!(read.peers, state.peers);
        assert!(read.invalid_peer_keys.is_empty());
    }

    #[test]
    fn test_timestamps() {
        let now = 1_000_000_000_000;
        assert!(check_timestamp(now, None, now).is_ok());
        assert!(check_timestamp(now, Some(now - 1), now).is_ok());
        assert_eq!(
            check_timestamp(now, Some(now), now),
            Err(AnnouncementError::Stale {
                timestamp: now,
                last: now
            })
        );
        assert!(check_timestamp(now - 1, Some(now), now).is_err());
        let ahead = now + MAX_CLOCK_AHEAD.as_nanos() as u64;
        assert!(check_timestamp(ahead, None, now).is_ok());
        assert_eq!(
            check_timestamp(ahead + 1, None, now),
            Err(AnnouncementError::TooFarAhead)
        );
        assert_eq!(
            check_not_ahead(ahead + 1, now),
            Err(AnnouncementError::TooFarAhead)
        );
        assert!(check_not_ahead(ahead, now).is_ok());
        assert!(timestamp_now() > now);
    }

    #[test]
    fn test_check_assigned() {
        let assigned = prefixes(&["10.0.0.0/24", "fd00::/64"]);
        let name: Hostname = "peer".parse().unwrap();
        let check =
            |announcement: &Announcement| announcement.check_assigned(&assigned, Some(&name));
        assert_eq!(check(&announcement()), Ok(()));
        // The peer claims of its assigned ranges, but never beyond them.
        let mut wider = announcement();
        wider.claims.delegation = prefixes(&["10.0.0.0/23"]);
        assert!(check(&wider).is_err());
        let mut renamed = announcement();
        renamed.claims.name = Some("other".parse().unwrap());
        assert!(check(&renamed).is_err());
        assert!(announcement().check_assigned(&assigned, None).is_err());
        let mut unnamed = announcement();
        unnamed.claims.name = None;
        assert_eq!(check(&unnamed), Ok(()));
        // The primary IP is stated, within the claimed delegation, not merely an assigned range.
        let mut outside = announcement();
        outside.primary_ip = Some("10.0.0.1".parse().unwrap());
        assert!(check(&outside).is_err());
        let mut none = announcement();
        none.primary_ip = None;
        assert!(check(&none).is_err());
        // Allowed IPs beyond the delegation are no reason to refuse it.
        let mut beyond = announcement();
        beyond.allowed_ips = prefixes(&["10.0.0.0/8"]);
        assert_eq!(check(&beyond), Ok(()));
    }

    #[test]
    fn test_nameserver() {
        let (keypair, private_key) = keys();
        let open = |nameserver: Nameserver| {
            let announcement = Announcement {
                nameserver: Some(nameserver),
                ..announcement()
            };
            sign_raw(&keypair, &private_key, cbor::to_vec(&announcement).unwrap())
                .open(&keypair.public)
        };

        // The nameserver is a statement, its address text, as everywhere on the wire.
        #[derive(Deserialize)]
        struct Text {
            address: String,
            zone: String,
        }
        #[derive(Deserialize)]
        struct Payload {
            nameserver: Text,
        }
        let payload: Payload = cbor::from_slice(&cbor::to_vec(&announcement()).unwrap()).unwrap();
        assert_eq!(payload.nameserver.address, "10.0.0.34:53");
        assert_eq!(payload.nameserver.zone, "example.com");
        assert!(open(nameserver("[fd00::1]:5353", "a.example.com")).is_ok());

        // A nameserver that can't be reached, or a zone that isn't a canonical domain, makes the
        // announcement malformed.
        for (address, zone) in [
            ("0.0.0.0:53", "example.com"),
            ("10.0.0.34:0", "example.com"),
            ("10.0.0.34:53", "Example.com"),
            ("10.0.0.34:53", "example.com."),
            ("10.0.0.34:53", ""),
            ("10.0.0.34:53", "10.0.0.1"),
        ] {
            assert!(
                matches!(
                    open(nameserver(address, zone)),
                    Err(AnnouncementError::Malformed(_))
                ),
                "{address} {zone}"
            );
        }
        let long = vec!["a".repeat(63); 4].join(".");
        assert!(matches!(
            open(nameserver("10.0.0.34:53", &long)),
            Err(AnnouncementError::Malformed(_))
        ));

        // The server doesn't check where it lies, but it takes effect only within the claimed
        // delegation, whatever the allowed IPs route.
        let peer = peer(&keypair.public);
        assert_eq!(
            announcement().check_assigned(&peer.delegations, peer.name.as_ref()),
            Ok(())
        );
        let mut announced = announcement();
        announced.allowed_ips = vec![];
        assert_eq!(
            peer.effective_with(Some(&announced)).nameserver,
            announcement().nameserver
        );
        announced.nameserver = Some(nameserver("10.0.0.1:53", "example.com"));
        assert_eq!(
            announced.check_assigned(&peer.delegations, peer.name.as_ref()),
            Ok(())
        );
        assert_eq!(peer.effective_with(Some(&announced)).nameserver, None);
        assert_eq!(peer.effective_with(None).nameserver, None);
    }

    #[test]
    fn test_shrink_to() {
        let delegation = prefixes(&["10.0.0.32/28", "10.0.1.0/24", "fd00::/112"]);
        assert_eq!(
            shrink_to(
                &prefixes(&[
                    "10.0.0.0/16",
                    "10.0.1.128/25",
                    "10.0.1.130/32",
                    "10.9.0.0/16"
                ]),
                &delegation
            ),
            prefixes(&["10.0.0.32/28", "10.0.1.0/24"])
        );
        assert_eq!(
            shrink_to(&prefixes(&["10.0.0.40/29", "fd00::1/128"]), &delegation),
            prefixes(&["10.0.0.40/29", "fd00::1/128"])
        );
        assert!(shrink_to(&[], &delegation).is_empty());
        assert!(shrink_to(&delegation, &[]).is_empty());
    }

    #[test]
    fn test_effective() {
        let (keypair, private_key) = keys();
        let mut peer = peer(&keypair.public);

        // A peer that has never announced takes effect as the server reports it.
        let synthetic = peer.effective();
        assert_eq!(synthetic, peer);
        assert_eq!(
            synthetic.allowed_ips(),
            peer.delegations
                .iter()
                .map(Prefix::allowed_ip)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            synthetic.hosts_fallback(),
            Some("10.0.0.0".parse().unwrap())
        );
        assert_eq!(
            peer.effective_with(Some(&Announcement::synthetic(&peer)))
                .allowed_ips(),
            synthetic.allowed_ips()
        );
        // The unsigned announcement orders the endpoint that the server records before the
        // candidates, which leave it out, at most MAX_ENDPOINTS in all.
        let endpoint: Endpoint = "198.51.100.1:1".parse().unwrap();
        let candidate: Endpoint = "198.51.100.2:2".parse().unwrap();
        assert_eq!(
            Announcement::synthetic(&peer).endpoints,
            [endpoint.clone(), candidate.clone()]
        );
        assert_eq!(
            legacy_endpoints(Some(&endpoint), &[endpoint.clone(), candidate.clone()]),
            [endpoint.clone(), candidate.clone()]
        );
        assert_eq!(
            legacy_endpoints(None, std::slice::from_ref(&candidate)),
            [candidate]
        );
        assert_eq!(
            legacy_endpoints(Some(&endpoint), &vec![endpoint.clone(); 20]).len(),
            1
        );
        let many: Vec<Endpoint> = (1..=20)
            .map(|port| format!("192.0.2.1:{port}").parse().unwrap())
            .collect();
        let ordered = legacy_endpoints(Some(&endpoint), &many);
        assert_eq!(ordered.len(), MAX_ENDPOINTS);
        assert_eq!(ordered[0], endpoint);
        assert_eq!(ordered[1..], many[..MAX_ENDPOINTS - 1]);

        // One that has announced takes effect as its announcement makes it, whatever the server
        // reports of its delegations and its name.
        let mut announced = announcement();
        announced.allowed_ips.push("10.1.0.0/24".parse().unwrap());
        peer.announcement = Some(announced.sign(&private_key).unwrap());
        peer.name = Some("renamed".parse().unwrap());
        peer.delegations = prefixes(&["10.0.0.0/25"]);
        let effective = peer.effective();
        assert_eq!(effective, peer.effective_with(Some(&announced)));
        assert_eq!(effective.delegations, claims().delegation);
        assert_eq!(
            effective.allowed_ips,
            Some(prefixes(&["10.0.0.32/29", "fd00::/112"]))
        );
        assert_eq!(
            effective.hosts_fallback(),
            Some("10.0.0.33".parse().unwrap())
        );
        assert_eq!(effective.name, claims().name);
        // The first endpoint is the one that WireGuard uses, the others the candidates, in order.
        assert_eq!(
            effective.endpoint.as_ref(),
            announcement().endpoints.first()
        );
        assert_eq!(effective.candidates, announcement().endpoints[1..]);

        // An endpoint whose host is unspecified can't be reached, so it takes no effect, and the
        // next one is preferred.
        let mut unspecified = announcement();
        unspecified.endpoints[0] = "0.0.0.0:51820".parse().unwrap();
        let effective = peer.effective_with(Some(&unspecified));
        assert_eq!(effective.endpoint.as_ref(), unspecified.endpoints.get(1));
        assert_eq!(effective.candidates, unspecified.endpoints[2..]);
        unspecified.endpoints.truncate(1);
        assert_eq!(peer.effective_with(Some(&unspecified)).endpoint, None);

        // A peer that states no allowed IPs is routed nothing, and one that claims nothing is in
        // effect disabled.
        let mut silent = announcement();
        silent.allowed_ips = vec![];
        assert!(peer.effective_with(Some(&silent)).allowed_ips().is_empty());
        assert!(!peer
            .effective_with(Some(&Announcement::default()))
            .is_routed());

        // A stored announcement that can't be decoded routes nothing.
        peer.announcement = Some(SignedAnnouncement {
            payload: vec![0xff],
            signature: Some(vec![0; 64]),
        });
        assert!(!peer.effective().is_routed());
    }
}
