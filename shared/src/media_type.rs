//! The media types of the API of TLS sessions, which version its bodies, and the negotiation of
//! the representation of a response.
//!
//! A body of the API is CBOR in the deterministic encoding of [`crate::cbor`], under the media type
//! `application/vnd.innernet+cbor` with the required parameter `version`, as in
//! `application/vnd.innernet+cbor; version=1`. One version covers the whole API: the media type
//! says which version a body belongs to, and the route says which schema within that version it
//! follows. Paths carry no version.
//!
//! `Content-Type` states the version of a request body, and the server refuses a body without a
//! version, or of a version that it doesn't read. `Accept` names the versions that a client reads,
//! each in an entry of its own, with `q` weights, and the server answers in the version of the
//! highest weight, then the newest. An entry of the media type without a version is malformed and
//! ignored. A missing `Accept`, or `*/*` or `application/*` without an entry that names a version
//! that the server writes, gets the debug view: the newest version in CBOR diagnostic notation,
//! under `application/vnd.innernet+cbor-diagnostic` with its version, which is no stable format.
//!
//! Media types are parsed with the `mime` crate: names are case-insensitive, values may be quoted,
//! and `version` is compared exactly, so that `version=01` names no version.

use crate::cbor;
use cbor_core::{EncodeFormat, SequenceWriter};
use mime::Mime;
use serde::Serialize;

/// The media type of the bodies of the API, without its version.
pub const MEDIA_TYPE: &str = "application/vnd.innernet+cbor";

/// The media type of the debug view, without its version.
pub const DIAGNOSTIC_MEDIA_TYPE: &str = "application/vnd.innernet+cbor-diagnostic";

/// The newest version of the API.
pub const VERSION: u32 = 1;

/// The versions of the API that this build reads and writes.
pub const VERSIONS: &[u32] = &[VERSION];

/// The media type of a body of the version `version`, with its version.
pub fn content_type(version: u32) -> String {
    format!("{MEDIA_TYPE}; version={version}")
}

/// The value of `Accept` that a client sends with every request: the media type of the newest
/// version of the API.
pub fn accept() -> String {
    content_type(VERSION)
}

/// The media type of the debug view of the version `version`, with its version.
pub fn diagnostic_content_type(version: u32) -> String {
    format!("{DIAGNOSTIC_MEDIA_TYPE}; version={version}")
}

/// The representation of a response, as [`negotiate`] chooses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Representation {
    /// CBOR, in the version that it holds.
    Cbor(u32),
    /// The debug view of the version that it holds, in CBOR diagnostic notation.
    Diagnostic(u32),
}

impl Representation {
    /// The media type of a body in this representation, with its version.
    pub fn content_type(&self) -> String {
        match self {
            Representation::Cbor(version) => content_type(*version),
            Representation::Diagnostic(version) => diagnostic_content_type(*version),
        }
    }

    /// `value` in this representation: in the deterministic encoding of CBOR, or in the debug
    /// view.
    pub fn encode<T: Serialize + ?Sized>(&self, value: &T) -> Result<Vec<u8>, cbor::Error> {
        match self {
            Representation::Cbor(_) => cbor::to_vec(value),
            Representation::Diagnostic(version) => Ok(to_diagnostic(*version, value)?.into_bytes()),
        }
    }
}

/// `value` in the debug view of the version `version`: a comment line that names the media type
/// to ask for instead, and `value` in CBOR diagnostic notation, pretty-printed.
pub fn to_diagnostic<T: Serialize + ?Sized>(
    version: u32,
    value: &T,
) -> Result<String, cbor::Error> {
    let encoded = cbor::to_vec(value)?;
    let value = cbor_core::Value::decode(&encoded).expect("an encoded value decodes");
    let mut text = format!(
        "# unstable debug view; use Accept: {}\n",
        content_type(version)
    )
    .into_bytes();
    SequenceWriter::new(&mut text, EncodeFormat::DiagnosticPretty)
        .write_item(&value)
        .expect("writing to a vector can't fail");
    text.push(b'\n');
    Ok(String::from_utf8(text).expect("diagnostic notation is UTF-8"))
}

/// The version of a request body whose `Content-Type` is `header`, if the header names the media
/// type of the API with a version among `versions`, and no other parameter. Any other content
/// type, the media type without a version, and an unknown version are `None`.
pub fn body_version(header: &str, versions: &[u32]) -> Option<u32> {
    let mime: Mime = header.trim().parse().ok()?;
    if mime.essence_str() != MEDIA_TYPE {
        return None;
    }
    let mut params = mime.params();
    let (name, value) = params.next()?;
    if name != "version" || params.next().is_some() {
        return None;
    }
    versions
        .iter()
        .copied()
        .find(|version| value.as_str() == version.to_string())
}

/// An entry of `Accept`: a media range, its parameters, and its weight in thousandths.
struct Entry {
    mime: Mime,
    /// The parameters of the media range, those before `q`.
    params: Vec<(String, String)>,
    weight: u16,
}

impl Entry {
    /// Parses an entry of `Accept`, or `None` for a malformed one. The parameters after `q` are
    /// extensions of the entry, which are ignored.
    fn parse(entry: &str) -> Option<Self> {
        let mime: Mime = entry.trim().parse().ok()?;
        let mut params = vec![];
        let mut weight = None;
        for (name, value) in mime.params() {
            if name == "q" {
                weight = Some(parse_weight(value.as_str())?);
                break;
            }
            params.push((
                name.as_str().to_ascii_lowercase(),
                value.as_str().to_string(),
            ));
        }
        Some(Self {
            mime,
            params,
            weight: weight.unwrap_or(1000),
        })
    }
}

/// Parses a weight, `0` to `1` with at most three decimals, in thousandths.
fn parse_weight(weight: &str) -> Option<u16> {
    let (whole, decimals) = weight.split_once('.').unwrap_or((weight, ""));
    if decimals.len() > 3 || !decimals.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let thousandths: u16 = format!("{decimals:0<3}").parse().ok()?;
    match whole {
        "0" => Some(thousandths),
        "1" if thousandths == 0 => Some(1000),
        _ => None,
    }
}

/// Splits the value of `Accept` into its entries, on the commas outside quoted strings.
fn split_entries(accept: &str) -> Vec<&str> {
    let mut entries = vec![];
    let mut quoted = false;
    let mut start = 0;
    for (i, c) in accept.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                entries.push(&accept[start..i]);
                start = i + 1;
            },
            _ => {},
        }
    }
    entries.push(&accept[start..]);
    entries
}

/// Chooses the representation of a response to a request whose `Accept` is `accept`, among the
/// versions `versions`, or `None` if the request accepts none of them.
///
/// Each version is weighted by the entry that names the media type with that version; the first
/// such entry counts. An entry of the media type without a version, or with any other parameter,
/// is malformed and ignored, and an entry with a weight of 0 excludes its version. The version of
/// the highest weight wins, then the newest. Without such a version, the debug view of the newest
/// version is chosen for a missing `Accept`, and for `application/*` or `*/*` with a weight above
/// 0, the more specific of the two deciding.
pub fn negotiate(accept: Option<&str>, versions: &[u32]) -> Option<Representation> {
    let newest = *versions.iter().max()?;
    let Some(accept) = accept else {
        return Some(Representation::Diagnostic(newest));
    };
    let entries: Vec<Entry> = split_entries(accept)
        .into_iter()
        .filter(|entry| !entry.trim().is_empty())
        .filter_map(Entry::parse)
        .collect();

    let weight_of = |version: u32| {
        entries
            .iter()
            .find(|entry| {
                entry.mime.essence_str() == MEDIA_TYPE
                    && matches!(
                        &entry.params[..],
                        [(name, value)] if name == "version" && *value == version.to_string()
                    )
            })
            .map_or(0, |entry| entry.weight)
    };
    let best = versions
        .iter()
        .map(|&version| (weight_of(version), version))
        .filter(|(weight, _)| *weight > 0)
        .max();
    if let Some((_, version)) = best {
        return Some(Representation::Cbor(version));
    }

    let wildcard = |range: &str| {
        entries
            .iter()
            .find(|entry| entry.mime.essence_str() == range && entry.params.is_empty())
            .map(|entry| entry.weight)
    };
    let weight = wildcard("application/*").or_else(|| wildcard("*/*"));
    (weight > Some(0)).then_some(Representation::Diagnostic(newest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use Representation::{Cbor, Diagnostic};

    #[test]
    fn test_body_version() {
        for header in [
            "application/vnd.innernet+cbor; version=1",
            "application/vnd.innernet+cbor;version=1",
            "Application/VND.innernet+CBOR; Version=1",
            "application/vnd.innernet+cbor; version=\"1\"",
        ] {
            assert_eq!(body_version(header, &[1]), Some(1), "{header}");
        }
        assert_eq!(body_version(&content_type(1), VERSIONS), Some(1));
        for header in [
            "application/vnd.innernet+cbor",
            "application/vnd.innernet+cbor; version=2",
            "application/vnd.innernet+cbor; version=01",
            "application/vnd.innernet+cbor; version=1; charset=binary",
            "application/vnd.innernet+cbor; version=1; version=1",
            "application/cbor",
            "application/vnd.innernet+cbor-diagnostic; version=1",
            "application/json; version=1",
            "",
        ] {
            assert_eq!(body_version(header, &[1]), None, "{header}");
        }
        assert_eq!(
            body_version("application/vnd.innernet+cbor; version=2", &[1, 2]),
            Some(2)
        );
    }

    #[test]
    fn test_negotiates_versions() {
        let ours = "application/vnd.innernet+cbor";
        for (accept, expected) in [
            (format!("{ours}; version=1"), Some(Cbor(1))),
            (
                format!("{ours}; version=1, application/problem+cbor"),
                Some(Cbor(1)),
            ),
            (format!("{ours};VERSION=\"1\""), Some(Cbor(1))),
            (format!("{ours}; version=2"), None),
            (format!("{ours}; version=01"), None),
            // An entry without a version is malformed, and ignored.
            (ours.to_string(), None),
            (format!("{ours}; version=1; q=0"), None),
            (format!("{ours}; version=1; q=0.001"), Some(Cbor(1))),
            // Extensions after the weight are ignored, but not other parameters before it.
            (format!("{ours}; version=1; q=0.5; ext=1"), Some(Cbor(1))),
            (format!("{ours}; version=1; charset=binary"), None),
            // A malformed weight makes a malformed entry.
            (format!("{ours}; version=1; q=2"), None),
            (format!("{ours}; version=1; q=0.5000"), None),
            ("application/problem+cbor".to_string(), None),
            (String::new(), None),
        ] {
            assert_eq!(negotiate(Some(&accept), &[1]), expected, "{accept}");
        }

        // The highest weight wins, then the newest version.
        for (accept, expected) in [
            (format!("{ours}; version=1, {ours}; version=2"), Cbor(2)),
            (format!("{ours}; version=2, {ours}; version=1"), Cbor(2)),
            (
                format!("{ours}; version=1, {ours}; version=2; q=0.9"),
                Cbor(1),
            ),
            (
                format!("{ours}; version=1; q=0.5, {ours}; version=2; q=0.4"),
                Cbor(1),
            ),
            (
                format!("{ours}; version=2; q=0, {ours}; version=1; q=0.1"),
                Cbor(1),
            ),
            (
                format!("{ours}; version=3, {ours}; version=1; q=0.1"),
                Cbor(1),
            ),
            // The first entry for a version counts.
            (
                format!("{ours}; version=2; q=0.1, {ours}; version=2, {ours}; version=1; q=0.2"),
                Cbor(1),
            ),
        ] {
            assert_eq!(
                negotiate(Some(&accept), &[1, 2]),
                Some(expected),
                "{accept}"
            );
        }
    }

    #[test]
    fn test_negotiates_the_debug_view() {
        let ours = "application/vnd.innernet+cbor";
        assert_eq!(negotiate(None, &[1, 2]), Some(Diagnostic(2)));
        for (accept, expected) in [
            ("*/*", Some(Diagnostic(1))),
            ("application/*", Some(Diagnostic(1))),
            ("text/html, application/*;q=0.1", Some(Diagnostic(1))),
            ("*/*; q=0", None),
            // The more specific range decides.
            ("*/*, application/*; q=0", None),
            ("application/*; q=0.2, */*; q=0", Some(Diagnostic(1))),
            ("text/*", None),
            ("*/*; version=1", None),
            // A version that the server writes wins over a wildcard, whatever its weight, but
            // one that it doesn't leaves the wildcard.
            (&format!("*/*, {ours}; version=1; q=0.1"), Some(Cbor(1))),
            (&format!("*/*, {ours}; version=2"), Some(Diagnostic(1))),
            (&format!("*/*, {ours}; version=1; q=0"), Some(Diagnostic(1))),
        ] {
            assert_eq!(negotiate(Some(accept), &[1]), expected, "{accept}");
        }
    }

    #[test]
    fn test_splits_entries_outside_quotes() {
        assert_eq!(
            split_entries(r#"a/b; x="1,2", c/d"#),
            [r#"a/b; x="1,2""#, " c/d"]
        );
        let accept = "application/vnd.innernet+cbor; version=1; ext=\"a,b\", text/plain";
        assert_eq!(negotiate(Some(accept), &[1]), None);
        let accept = "application/vnd.innernet+cbor; version=1; q=1; ext=\"a,b\", text/plain";
        assert_eq!(negotiate(Some(accept), &[1]), Some(Cbor(1)));
    }

    #[test]
    fn test_debug_view() {
        #[derive(Serialize)]
        struct Value {
            name: &'static str,
            tag: crate::Tag,
        }
        let value = Value {
            name: "peer",
            tag: crate::Tag::new(vec![0xab]),
        };
        let text = to_diagnostic(1, &value).unwrap();
        let mut lines = text.lines();
        assert_eq!(
            lines.next(),
            Some("# unstable debug view; use Accept: application/vnd.innernet+cbor; version=1")
        );
        assert!(text.ends_with("}\n"), "{text}");
        assert!(text.contains("\"name\": \"peer\""), "{text}");
        assert!(text.contains("h'ab'"), "{text}");
        assert_eq!(
            Representation::Diagnostic(1).encode(&value).unwrap(),
            text.into_bytes()
        );
        assert_eq!(
            Representation::Diagnostic(1).content_type(),
            "application/vnd.innernet+cbor-diagnostic; version=1"
        );
    }
}
