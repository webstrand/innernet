//! Problem details (RFC 9457), in which the API of TLS sessions explains each error.
//!
//! A problem is a map with the string keys of RFC 9457: `type`, `title`, `status`, `detail` and
//! `instance`, and the extension members of its type. It travels in CBOR, in the deterministic
//! encoding, with the content type `application/problem+cbor`, which carries no version, or in the
//! debug view of the API, as [`crate::media_type`] describes it. The concise problem details of
//! RFC 9290, which are made for CoAP, are not used.
//!
//! A client decides on the type of a problem alone; its status is advisory, so that a problem
//! keeps its meaning over another transport than HTTP. An error without a meaning of innernet's
//! own has the type `about:blank`, and its status carries the meaning. innernet's own types are
//! listed in [`PROBLEM_TYPES`], and in `doc/problems.md`.

use crate::{types::deserialize_public_key, Prefix};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt::{self, Display, Formatter};

/// The content type of a problem in CBOR.
pub const CONTENT_TYPE: &str = "application/problem+cbor";

/// The content type of a problem in the debug view, in CBOR diagnostic notation, which answers a
/// request that gets the debug view of the API.
pub const DIAGNOSTIC_CONTENT_TYPE: &str = "application/problem+cbor-diagnostic";

/// Whether the value of a `Content-Type` header names a problem in CBOR, whatever the case of the
/// media type and whatever its parameters.
pub fn is_content_type(header: &str) -> bool {
    let essence = header.split(';').next().unwrap_or_default().trim();
    essence.eq_ignore_ascii_case(CONTENT_TYPE)
}

/// The type of a problem without a meaning of innernet's own, whose status carries the meaning.
pub const ABOUT_BLANK: &str = "about:blank";

/// A type of problem of innernet's own: its URI, which never changes, the title of every problem
/// of the type, and the status that the server answers it with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProblemType {
    pub uri: &'static str,
    pub title: &'static str,
    pub status: u16,
}

impl ProblemType {
    /// A problem of this type, which `detail` explains.
    pub fn problem(&self, detail: impl Into<String>) -> Problem {
        Problem {
            problem_type: self.uri.to_string(),
            title: Some(self.title.to_string()),
            status: Some(self.status),
            detail: Some(detail.into()),
            ..Problem::about_blank(self.status, None)
        }
    }
}

/// The peer must connect over TLS: it has connected over TLS before, and so may no longer use
/// plain HTTP. Only a plain-HTTP session meets this problem, and is told in text instead.
pub const TLS_REQUIRED: ProblemType = ProblemType {
    uri: "urn:uuid:89b644bc-0770-472b-a3bc-09d1b32671ab",
    title: "The peer must connect over TLS",
    status: 401,
};

/// Only a peer that has connected over TLS can be made an admin.
pub const PROMOTION_REQUIRES_TLS: ProblemType = ProblemType {
    uri: "urn:uuid:1ca511f1-e703-4be8-b81e-c2a4e3491971",
    title: "Only a peer that has connected over TLS can be made an admin",
    status: 422,
};

/// The peer has changed since it was read: the tag of the change is stale.
pub const PEER_CHANGED: ProblemType = ProblemType {
    uri: "urn:uuid:6b53f45a-cd2d-4f6b-9d24-676d699d3186",
    title: "The peer has changed since it was read",
    status: 409,
};

/// The CIDR has changed since it was read: the tag of the change is stale.
pub const CIDR_CHANGED: ProblemType = ProblemType {
    uri: "urn:uuid:94053d8e-85af-4eff-9cc3-ac9feb41dc58",
    title: "The CIDR has changed since it was read",
    status: 409,
};

/// A change of a tagged resource carries no tag.
pub const TAG_MISSING: ProblemType = ProblemType {
    uri: "urn:uuid:97c8ab2c-72e8-4c22-8329-8328530f14c6",
    title: "The change carries no tag",
    status: 400,
};

/// No peer has the public key that the path names.
pub const NO_SUCH_PEER: ProblemType = ProblemType {
    uri: "urn:uuid:231e8a92-c48e-4982-855e-3998840439fb",
    title: "No peer has this public key",
    status: 404,
};

/// No CIDR has the prefix that the path names.
pub const NO_SUCH_CIDR: ProblemType = ProblemType {
    uri: "urn:uuid:e97fda0b-cfc5-4c54-8761-442df29a96bc",
    title: "No CIDR has this prefix",
    status: 404,
};

/// No association joins the CIDRs that the path names.
pub const NO_SUCH_ASSOCIATION: ProblemType = ProblemType {
    uri: "urn:uuid:03638e35-e88a-463b-87cf-8ee3fd4e5e69",
    title: "No association joins these CIDRs",
    status: 404,
};

/// Delegations that break the rules of delegations. When a delegation overlaps one that another
/// peer holds, the problem names them in the extension members `prefix`, `held` and `holder`.
pub const DELEGATION_REFUSED: ProblemType = ProblemType {
    uri: "urn:uuid:08ea2dd5-0cbf-4efc-b0ef-d154acd09982",
    title: "The delegations break the rules of delegations",
    status: 422,
};

/// The route requires a client key, and the connection has none: the client connected without
/// authenticating with its key, and must connect again with it. An anonymous connection is told
/// the same for a path that the server has no route for, so that it can't probe for routes.
pub const CLIENT_KEY_REQUIRED: ProblemType = ProblemType {
    uri: "urn:uuid:305a37cb-49a7-43e6-ac4e-999d31323fff",
    title: "Client key required",
    status: 403,
};

/// Every type of problem of innernet's own.
pub const PROBLEM_TYPES: [ProblemType; 10] = [
    TLS_REQUIRED,
    PROMOTION_REQUIRES_TLS,
    PEER_CHANGED,
    CIDR_CHANGED,
    TAG_MISSING,
    NO_SUCH_PEER,
    NO_SUCH_CIDR,
    NO_SUCH_ASSOCIATION,
    DELEGATION_REFUSED,
    CLIENT_KEY_REQUIRED,
];

/// A problem detail. Members that a problem lacks are left out, and members that a recipient
/// doesn't know are ignored, as RFC 9457 requires; a problem without a type has the type
/// `about:blank`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Problem {
    /// The URI of the type of the problem, on which a client decides.
    #[serde(rename = "type", default = "about_blank")]
    pub problem_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The status that the server answered the problem with, which is advisory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// Of [`DELEGATION_REFUSED`]: the delegation that overlaps one of another peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<Prefix>,
    /// Of [`DELEGATION_REFUSED`]: the delegation of another peer that `prefix` overlaps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<Prefix>,
    /// Of [`DELEGATION_REFUSED`]: the public key of the peer that holds `held`, in base64.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_public_key"
    )]
    pub holder: Option<String>,
}

fn about_blank() -> String {
    ABOUT_BLANK.to_string()
}

impl Problem {
    /// A problem without a meaning of innernet's own, which the status `status` carries, with the
    /// title `title`, which should be the reason phrase of the status.
    pub fn about_blank(status: u16, title: Option<&str>) -> Self {
        Self {
            problem_type: about_blank(),
            title: title.map(str::to_string),
            status: Some(status),
            detail: None,
            instance: None,
            prefix: None,
            held: None,
            holder: None,
        }
    }

    /// Whether the problem is of the type `problem_type`.
    pub fn is(&self, problem_type: &ProblemType) -> bool {
        self.problem_type == problem_type.uri
    }
}

impl Display for Problem {
    /// The detail of the problem, or else its title, or else its type.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let explanation = self.detail.as_deref().or(self.title.as_deref());
        f.write_str(explanation.unwrap_or(&self.problem_type))
    }
}

fn deserialize_optional_public_key<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    struct PublicKey(String);
    impl<'de> Deserialize<'de> for PublicKey {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserialize_public_key(deserializer).map(PublicKey)
        }
    }
    Ok(Option::<PublicKey>::deserialize(deserializer)?.map(|key| key.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor;
    use std::collections::{BTreeMap, HashSet};

    #[test]
    fn test_problem_types_are_distinct_uuids() {
        let uris: HashSet<_> = PROBLEM_TYPES.iter().map(|t| t.uri).collect();
        assert_eq!(uris.len(), PROBLEM_TYPES.len());
        for problem_type in PROBLEM_TYPES {
            let uuid = problem_type.uri.strip_prefix("urn:uuid:").unwrap();
            let groups: Vec<_> = uuid.split('-').map(str::len).collect();
            assert_eq!(groups, [8, 4, 4, 4, 12], "{uuid}");
            assert!(uuid.chars().all(|c| c == '-' || c.is_ascii_hexdigit()));
            // A random UUID, of version 4 and of the variant of RFC 9562.
            assert_eq!(&uuid[14..15], "4", "{uuid}");
            assert!("89ab".contains(&uuid[19..20]), "{uuid}");
        }
    }

    #[test]
    fn test_problems_are_documented() {
        let doc = include_str!("../../doc/problems.md");
        for problem_type in PROBLEM_TYPES {
            let line = doc
                .lines()
                .find(|line| line.contains(problem_type.uri))
                .unwrap_or_else(|| panic!("{} is missing", problem_type.uri));
            assert!(line.contains(problem_type.title), "{line}");
            assert!(
                line.contains(&format!("| {} |", problem_type.status)),
                "{line}"
            );
        }
    }

    #[test]
    fn test_problems_in_cbor() {
        // A problem is a map with the string keys of RFC 9457, without the members it lacks.
        let mut problem = DELEGATION_REFUSED.problem("10.0.0.0/30 overlaps 10.0.0.0/31");
        problem.prefix = Some("10.0.0.0/30".parse().unwrap());
        problem.held = Some("10.0.0.0/31".parse().unwrap());
        problem.holder = Some(wireguard_control::Key([7; 32]).to_base64());
        let encoded = cbor::to_vec(&problem).unwrap();
        let value = cbor_core::Value::decode(&encoded).unwrap();
        assert_eq!(value["type"].as_str().unwrap(), DELEGATION_REFUSED.uri);
        assert_eq!(value["status"].to_u16().unwrap(), 422);
        assert_eq!(
            value["holder"].as_str().unwrap(),
            wireguard_control::Key([7; 32]).to_base64()
        );
        assert_eq!(value["held"].as_str().unwrap(), "10.0.0.0/31");
        let keys: Vec<String> =
            cbor::from_slice::<BTreeMap<String, serde::de::IgnoredAny>>(&encoded)
                .unwrap()
                .into_keys()
                .collect();
        assert_eq!(
            keys,
            ["detail", "held", "holder", "prefix", "status", "title", "type"]
        );
        assert_eq!(cbor::from_slice::<Problem>(&encoded).unwrap(), problem);

        let blank = Problem::about_blank(404, Some("Not Found"));
        let encoded = cbor::to_vec(&blank).unwrap();
        let keys: Vec<String> =
            cbor::from_slice::<BTreeMap<String, serde::de::IgnoredAny>>(&encoded)
                .unwrap()
                .into_keys()
                .collect();
        assert_eq!(keys, ["status", "title", "type"]);

        // A problem without a type is of the type about:blank, and unknown members are ignored.
        #[derive(Serialize)]
        struct Other {
            status: u16,
            other: &'static str,
        }
        let other = cbor::to_vec(&Other {
            status: 500,
            other: "ignored",
        })
        .unwrap();
        let other: Problem = cbor::from_slice(&other).unwrap();
        assert_eq!(other, Problem::about_blank(500, None));
        assert!(!other.is(&NO_SUCH_PEER));
        assert_eq!(other.to_string(), "about:blank");
    }
}
