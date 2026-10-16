//! The encoding of the bodies of the API of TLS sessions: CBOR (RFC 8949), in its core
//! deterministic encoding (section 4.2.1).
//!
//! A value has exactly one encoding: integers, lengths and floats take their shortest form, every
//! length is definite, and the keys of a map are sorted by the bytewise lexicographic order of
//! their encodings. Decoding refuses any other encoding of a value, so that a value read from a
//! peer encodes again to the bytes that the peer sent, as a signature over the encoding requires.
//!
//! Types serialize as they do in JSON, but for those that tell the two apart with
//! [`serde::Serializer::is_human_readable`], which is false in CBOR. Public keys and prefixes are
//! text in CBOR, as in JSON.

use serde::{de::DeserializeOwned, Serialize};
use std::fmt::{self, Display, Formatter};

/// The media type of CBOR, which the bodies of TLS sessions carry in `Content-Type`.
pub const CONTENT_TYPE: &str = "application/cbor";

/// The error of a value that fails to encode, or of bytes that fail to decode: bytes that are not
/// a single data item in the deterministic encoding, or one that doesn't deserialize as the type
/// that is read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(String);

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "invalid CBOR: {}", self.0)
    }
}

impl std::error::Error for Error {}

/// Encodes `value` in the core deterministic encoding.
pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
    cbor_core::Value::serialized(value)
        .map(|value| value.encode())
        .map_err(|e| Error(e.to_string()))
}

/// Decodes `bytes`, which must hold a single data item in the core deterministic encoding, and
/// nothing else.
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    let value = cbor_core::Value::decode(bytes).map_err(|e| Error(e.to_string()))?;
    value.deserialized().map_err(|e| Error(e.to_string()))
}

/// Whether the value of a `Content-Type` header names CBOR, whatever the case of the media type
/// and whatever its parameters.
pub fn is_content_type(header: &str) -> bool {
    let essence = header.split(';').next().unwrap_or_default().trim();
    essence.eq_ignore_ascii_case(CONTENT_TYPE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::collections::HashMap;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The encoding of `value` in hex.
    fn encoded<T: Serialize + ?Sized>(value: &T) -> String {
        hex(&to_vec(value).unwrap())
    }

    #[test]
    fn test_map_keys_are_sorted_by_their_encoding() {
        // The fields are declared out of order. The shorter key sorts first, whatever its letters,
        // since the encoding of a key starts with its length.
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Fields {
            bb: u8,
            b: u8,
            a: u8,
        }

        let fields = Fields { bb: 3, b: 2, a: 1 };
        assert_eq!(encoded(&fields), "a361610161620262626203");
        assert_eq!(
            from_slice::<Fields>(&to_vec(&fields).unwrap()).unwrap(),
            fields
        );

        // A map encodes the same whatever the order in which its keys were inserted.
        let keys = ["peers", "cidrs", "a", "zz", "tag", "name"];
        let forward: HashMap<_, _> = keys.iter().map(|key| (*key, 1)).collect();
        let backward: HashMap<_, _> = keys.iter().rev().map(|key| (*key, 1)).collect();
        let expected = [
            "a6",
            "6161",
            "01",
            "627a7a",
            "01",
            "63746167",
            "01",
            "646e616d65",
            "01",
            "656369647273",
            "01",
            "657065657273",
            "01",
        ]
        .concat();
        assert_eq!(encoded(&forward), expected);
        assert_eq!(encoded(&backward), expected);
    }

    #[test]
    fn test_integers_take_their_shortest_form() {
        for (value, expected) in [
            (0u64, "00"),
            (23, "17"),
            (24, "1818"),
            (255, "18ff"),
            (256, "190100"),
            (65_535, "19ffff"),
            (65_536, "1a00010000"),
            (u32::MAX as u64, "1affffffff"),
            (1 << 32, "1b0000000100000000"),
        ] {
            assert_eq!(encoded(&value), expected, "{value}");
        }
        // The type of an integer doesn't change its encoding.
        assert_eq!(encoded(&1u8), encoded(&1u64));
        assert_eq!(encoded(&1i64), "01");
        for (value, expected) in [(-1i64, "20"), (-24, "37"), (-25, "3818"), (-257, "390100")] {
            assert_eq!(encoded(&value), expected, "{value}");
        }
    }

    #[test]
    fn test_lengths_take_their_shortest_form() {
        assert_eq!(encoded(&"a".repeat(23))[..2], *"77");
        assert_eq!(encoded(&"a".repeat(24))[..4], *"7818");
        assert_eq!(encoded(&"a".repeat(256))[..6], *"790100");
        assert_eq!(encoded(&vec![0u8; 23])[..2], *"97");
        assert_eq!(encoded(&vec![0u8; 24])[..4], *"9818");
        let map: HashMap<u16, u8> = (0..24).map(|key| (key, 0)).collect();
        assert_eq!(encoded(&map)[..4], *"b818");
        // A sequence of unknown length is encoded with its length, never as an indefinite one.
        struct Unsized;
        impl Serialize for Unsized {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_seq((0..3u8).filter(|_| true))
            }
        }
        assert_eq!(encoded(&Unsized), "83000102");
    }

    #[test]
    fn test_floats_take_their_shortest_form() {
        assert_eq!(encoded(&1.5f64), "f93e00");
        assert_eq!(encoded(&100_000.0f64), "fa47c35000");
        assert_eq!(encoded(&1.1f64), "fb3ff199999999999a");
    }

    #[test]
    fn test_refuses_other_encodings() {
        for (bytes, what) in [
            ("1805", "an integer in a longer form than needed"),
            ("780161", "a length in a longer form than needed"),
            ("a2616201616101", "a map whose keys are out of order"),
            ("9f01ff", "an indefinite length"),
            ("0101", "trailing bytes"),
            ("", "nothing"),
        ] {
            assert!(
                from_slice::<serde::de::IgnoredAny>(&unhex(bytes)).is_err(),
                "{what}"
            );
        }
        assert!(from_slice::<u8>(&unhex("05")).is_ok());
    }

    #[test]
    fn test_content_type() {
        assert!(is_content_type("application/cbor"));
        assert!(is_content_type("Application/CBOR; charset=binary"));
        assert!(!is_content_type("application/json"));
        assert!(!is_content_type("application/cbor-seq"));
    }
}
