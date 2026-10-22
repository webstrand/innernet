//! Validation of canonical domain names and labels that name hosts.
//!
//! A canonical domain consists of one or more labels separated by dots, and is at most 253 bytes
//! long. Each label consists of 1 to 63 lowercase ASCII letters, digits and hyphens, and neither
//! starts nor ends with a hyphen, as described in hostname(7) and RFC 1123. A canonical domain is
//! in the canonical form of RFC 4034, section 6.2, which has no uppercase letters, so every name
//! has a single spelling.
//!
//! Punycode labels of the form "xn--" are not decoded, checked for normalization, or in any other
//! way validated.
//!
//! [`is_canonical_domain`] also requires that a name does not end in a number. Its final label is
//! neither all ASCII digits nor a `0x` prefix followed by zero or more hexadecimal digits. The
//! WHATWG URL Standard parses a host that ends in a number as an IPv4 address, and rejects the
//! host if that parse fails. Every canonical name that `inet_aton` reads as an address also ends
//! in a number, and `getaddrinfo` returns such a name as an address without looking it up.
//!
//! The rule examines only the final label, so every suffix of an accepted name, that is, every
//! name formed by removing leading labels, also satisfies it. [`is_canonical_domain`] therefore
//! refuses "servername.0", whose final label "0" reads as 0.0.0.0.
//!
//! [`is_canonical_relative_domain`] omits that requirement, for a name that is followed by a
//! suffix, such as a peer name followed by the name of its network. [`is_canonical_label`]
//! checks a single label, which may also be a number, and [`is_canonical_domain_label`] checks a
//! single label that must not be a number.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LabelKind {
    /// Not a canonical hostname label.
    Invalid,
    /// A canonical label that the WHATWG URL parser does not treat as a number.
    Valid,
    /// A canonical label that the WHATWG URL parser treats as a number: ASCII digits only, or a
    /// `0x` prefix followed by zero or more hexadecimal digits.
    Num,
}

// `LabelKind` and `Option<LabelKind>` must each occupy one byte. The compiler encodes the `None`
// of `Option` in a discriminant value that `LabelKind` leaves unused. These assertions fail the
// build if a change to the enum increases either size.
const _: () = assert!(std::mem::size_of::<LabelKind>() == 1);
const _: () = assert!(std::mem::size_of::<Option<LabelKind>>() == 1);

/// Classifies a single label as invalid, non-numeric, or numeric.
fn classify_label(label: &str) -> LabelKind {
    let b = label.as_bytes();
    if !(1..=63).contains(&b.len()) {
        return LabelKind::Invalid;
    }
    let (hex, body) = match b {
        // A label must not start or end with a hyphen.
        [b'-', ..] | [.., b'-'] => return LabelKind::Invalid,
        // A 0x prefix marks a hexadecimal number. The WHATWG URL parser reads a bare "0x" as 0.
        [b'0', b'x', rest @ ..] => (true, rest),
        _ => (false, b),
    };
    let mut numeric = true;
    for &c in body {
        if !matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'-') {
            return LabelKind::Invalid;
        }
        numeric &= if hex {
            c.is_ascii_hexdigit()
        } else {
            c.is_ascii_digit()
        };
    }
    if numeric {
        LabelKind::Num
    } else {
        LabelKind::Valid
    }
}

/// Whether `label` is a single canonical label, which may be a number.
pub fn is_canonical_label(label: &str) -> bool {
    classify_label(label) != LabelKind::Invalid
}

/// Whether `label` is a canonical label that is not a number. Such a label is a canonical domain
/// on its own.
pub fn is_canonical_domain_label(label: &str) -> bool {
    classify_label(label) == LabelKind::Valid
}

/// Whether `name` is a canonical domain that does not end in a number.
pub fn is_canonical_domain(name: &str) -> bool {
    if !(1..=253).contains(&name.len()) {
        return false;
    }
    // The WHATWG URL Standard requires a host whose final label is a number to parse as an IPv4
    // address, and rejects the host otherwise. Every canonical name that inet_aton reads as an
    // address also ends in such a label.
    let mut labels = name.rsplit('.').map(classify_label);
    labels.next() == Some(LabelKind::Valid) && labels.all(|kind| kind != LabelKind::Invalid)
}

/// Whether `name` is a canonical domain that may end in a number, since a suffix follows it.
pub fn is_canonical_relative_domain(name: &str) -> bool {
    (1..=253).contains(&name.len()) && name.split('.').all(is_canonical_label)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &[&str] = &[
        "a", "peer-1", "a--b", "foo.bar", "1a", "1.a", "0x1g", "127.1.a",
    ];

    #[test]
    fn test_valid() {
        let long_label = "a".repeat(63);
        let long_name = [long_label.as_str(); 4].join(".");
        for name in VALID
            .iter()
            .copied()
            .chain([&long_label[..], &long_name[..253]])
        {
            assert!(is_canonical_domain(name), "{name:?} is canonical");
            assert!(is_canonical_relative_domain(name), "{name:?} is canonical");
        }
    }

    #[test]
    fn test_invalid() {
        let long_name = ["a".repeat(63).as_str(); 5].join(".");
        for name in [
            "",
            "-a",
            "a-",
            "a..b",
            "a.",
            ".a",
            "a_b",
            "a b",
            "a\n1.2.3.4 b",
            "Peer",
            "foo.BAR",
            "0X1g",
            "0xFFg",
            "0X",
            "0xFF",
            &"a".repeat(64),
            &long_name[..254],
        ] {
            assert!(!is_canonical_domain(name), "{name:?} is not canonical");
            assert!(
                !is_canonical_relative_domain(name),
                "{name:?} is not canonical"
            );
        }
    }

    #[test]
    fn test_ends_in_number() {
        for name in [
            "0",
            "10.0.0.1",
            "127.1",
            "2130706433",
            "0x7f.1",
            "0x7f000001",
            "017700000001",
            "1.2.3.256",
            "4294967296",
            "1.16777216",
            "0x",
            "1.2.3.4.5",
            "foo.127.1",
            "a.0xff.0x100",
            "08",
            "foo.08",
            "a.1",
            "x.0",
            "servername.0",
            "hostname.65537",
            "0x1ff.1",
            "1.0x1ff.1",
        ] {
            assert!(!is_canonical_domain(name), "{name:?} ends in a number");
            assert!(is_canonical_relative_domain(name), "{name:?} is relative");
        }
    }

    #[test]
    fn test_is_canonical_label() {
        for label in ["a", "peer-1", "08", "0x"] {
            assert!(is_canonical_label(label), "{label:?} is canonical");
        }
        for label in ["", "a.b", "-a", "A", &"a".repeat(64)] {
            assert!(!is_canonical_label(label), "{label:?} is not canonical");
        }
    }

    #[test]
    fn test_is_canonical_domain_label() {
        for label in ["a", "peer-1", "0x1g"] {
            assert!(is_canonical_domain_label(label), "{label:?} is a domain");
        }
        for label in ["08", "10", "0x", "0x7f", "a.b", "A"] {
            assert!(
                !is_canonical_domain_label(label),
                "{label:?} is not a domain"
            );
        }
    }

    #[test]
    fn test_classify_label() {
        for label in ["0", "255", "256", "0377", "08", "0x", "0xff", "0x100"] {
            assert_eq!(classify_label(label), LabelKind::Num, "{label:?}");
        }
        for label in ["a", "0x1g", "1a"] {
            assert_eq!(classify_label(label), LabelKind::Valid, "{label:?}");
        }
        for label in ["0X", "0xFF", "A"] {
            assert_eq!(classify_label(label), LabelKind::Invalid, "{label:?}");
        }
    }

    /// Whether the `inet_aton` of the C library reads `name` as an IPv4 address.
    #[cfg(unix)]
    fn inet_aton(name: &str) -> bool {
        let name = std::ffi::CString::new(name).unwrap();
        let mut addr = libc::in_addr { s_addr: 0 };
        unsafe { inet_aton_c(name.as_ptr(), &mut addr) != 0 }
    }

    #[cfg(unix)]
    extern "C" {
        #[link_name = "inet_aton"]
        fn inet_aton_c(cp: *const libc::c_char, inp: *mut libc::in_addr) -> libc::c_int;
    }

    /// [`is_canonical_domain`] refuses every name of up to six characters, over an alphabet of
    /// number syntax, that `inet_aton` reads as an address. It also refuses names that `inet_aton`
    /// does not read as an address, such as "0x" and "servername.0".
    #[cfg(unix)]
    #[test]
    fn test_refuses_inet_aton() {
        const ALPHABET: &[u8] = b"0123789afxX.";
        let mut name = vec![];
        fn visit(name: &mut Vec<u8>, depth: usize) {
            let s = std::str::from_utf8(name).unwrap();
            if !s.is_empty() && inet_aton(s) {
                assert!(!is_canonical_domain(s), "{s:?}");
            }
            if depth == 6 {
                return;
            }
            for &c in ALPHABET {
                name.push(c);
                visit(name, depth + 1);
                name.pop();
            }
        }
        visit(&mut name, 0);
    }
}
