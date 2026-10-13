//! XEdDSA signatures with WireGuard (X25519) keys, as specified in
//! <https://signal.org/docs/specifications/xeddsa/>.
//!
//! The signer uses the Edwards form of its key with the sign bit fixed to 0, negating its
//! private scalar where necessary, so that signatures are standard Ed25519 signatures under
//! [`PrivateKey::ed25519_public_key`], which anyone holding the X25519 public key can derive.

use anyhow::{anyhow, bail, Error};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    montgomery::MontgomeryPoint,
    scalar::clamp_integer,
    Scalar,
};
use rand::{rngs::OsRng, CryptoRng, TryRngCore as _};
use sha2::{Digest, Sha512};
use wireguard_control::Key;
use zeroize::Zeroizing;

pub const SIGNATURE_LENGTH: usize = 64;

/// Prefixes the nonce hash, `hash_1` in the specification: the little-endian encoding of
/// 2^256 - 2, which no encoding of a curve point or scalar starts with.
const NONCE_HASH_PREFIX: [u8; 32] = {
    let mut prefix = [0xff; 32];
    prefix[0] = 0xfe;
    prefix
};

/// The Edwards form, with sign bit 0, of a WireGuard public key that is the canonical
/// encoding of a point in the prime-order subgroup, as every honestly generated key is.
fn edwards_from_x25519(key: &Key) -> Option<EdwardsPoint> {
    let point = MontgomeryPoint(key.0).to_edwards(0)?;
    let canonical = point.to_montgomery().0 == key.0;
    (canonical && point.is_torsion_free() && !point.is_small_order()).then_some(point)
}

/// Whether `key` is a canonical encoding of a point in the prime-order subgroup. Rejects
/// low-order points, for which anyone could produce signatures, and points on the twist.
pub fn is_valid_public_key(key: &Key) -> bool {
    edwards_from_x25519(key).is_some()
}

/// The Edwards form, with sign bit 0, of a valid WireGuard public key: the key that its
/// XEdDSA signatures verify under as Ed25519.
pub fn ed25519_public_key(public_key: &Key) -> Option<CompressedEdwardsY> {
    edwards_from_x25519(public_key).map(|point| point.compress())
}

/// A WireGuard private key, able to make XEdDSA signatures.
pub struct PrivateKey {
    /// The Edwards private scalar, negated if necessary so that `a·B` has sign bit 0.
    scalar: Zeroizing<Scalar>,
    public_key: Key,
    ed25519_public_key: CompressedEdwardsY,
}

impl PrivateKey {
    /// Decodes a base64 WireGuard private key.
    pub fn from_base64(private_key: &str) -> Result<Self, Error> {
        let mut buffer = Zeroizing::new([0u8; 48]);
        let length = BASE64
            .decode_slice(private_key.trim(), &mut buffer[..])
            .map_err(|_| anyhow!("private key is not valid base64"))?;
        if length != 32 {
            bail!("private key is {length} bytes, expected 32");
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(&buffer[..32]);
        Ok(Self::from_bytes(&bytes))
    }

    fn from_bytes(bytes: &[u8; 32]) -> Self {
        let clamped = Zeroizing::new(clamp_integer(*bytes));
        let mut scalar = Zeroizing::new(Scalar::from_bytes_mod_order(*clamped));
        let point = EdwardsPoint::mul_base(&scalar);
        let mut ed25519_public_key = point.compress();
        if ed25519_public_key.0[31] & 0x80 != 0 {
            *scalar = -*scalar;
            ed25519_public_key.0[31] &= 0x7f;
        }
        Self {
            scalar,
            public_key: Key(point.to_montgomery().0),
            ed25519_public_key,
        }
    }

    /// The WireGuard public key.
    pub fn public_key(&self) -> &Key {
        &self.public_key
    }

    /// The Edwards form of the public key, with sign bit 0, under which signatures verify as
    /// standard Ed25519.
    pub fn ed25519_public_key(&self) -> &CompressedEdwardsY {
        &self.ed25519_public_key
    }

    /// Signs the concatenation of `message`'s parts.
    pub fn sign(&self, message: &[&[u8]]) -> [u8; SIGNATURE_LENGTH] {
        self.sign_with_rng(message, &mut OsRng.unwrap_err())
    }

    /// Signs the concatenation of `message`'s parts, with `Z` drawn from `rng`.
    pub fn sign_with_rng(
        &self,
        message: &[&[u8]],
        rng: &mut impl CryptoRng,
    ) -> [u8; SIGNATURE_LENGTH] {
        let mut random = Zeroizing::new([0u8; 64]);
        rng.fill_bytes(&mut random[..]);

        let mut nonce_hash = Sha512::new()
            .chain_update(NONCE_HASH_PREFIX)
            .chain_update(self.scalar.as_bytes());
        for part in message {
            nonce_hash.update(part);
        }
        nonce_hash.update(&random[..]);
        let nonce = Zeroizing::new(scalar_from_hash(nonce_hash));

        let nonce_point = EdwardsPoint::mul_base(&nonce).compress();
        let challenge = challenge(&nonce_point, &self.ed25519_public_key, message);
        let s = *nonce + challenge * *self.scalar;

        let mut signature = [0u8; SIGNATURE_LENGTH];
        signature[..32].copy_from_slice(nonce_point.as_bytes());
        signature[32..].copy_from_slice(s.as_bytes());
        signature
    }
}

/// Whether `signature` is `public_key`'s XEdDSA signature of the concatenation of `message`'s
/// parts.
pub fn verify(public_key: &Key, message: &[&[u8]], signature: &[u8]) -> bool {
    let Ok(signature) = <&[u8; SIGNATURE_LENGTH]>::try_from(signature) else {
        return false;
    };
    let Some(point) = edwards_from_x25519(public_key) else {
        return false;
    };
    let nonce_point = CompressedEdwardsY(signature[..32].try_into().unwrap());
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(
        signature[32..].try_into().unwrap(),
    )) else {
        return false;
    };
    let challenge = challenge(&nonce_point, &point.compress(), message);
    // R = s·B - h·A, compared by encoding as the specification does.
    let expected = EdwardsPoint::vartime_double_scalar_mul_basepoint(&-challenge, &point, &s);
    expected.compress() == nonce_point
}

/// `h = SHA-512(R ‖ A ‖ M) mod L`.
fn challenge(
    nonce_point: &CompressedEdwardsY,
    public_key: &CompressedEdwardsY,
    message: &[&[u8]],
) -> Scalar {
    let mut hash = Sha512::new()
        .chain_update(nonce_point.as_bytes())
        .chain_update(public_key.as_bytes());
    for part in message {
        hash.update(part);
    }
    scalar_from_hash(hash)
}

fn scalar_from_hash(hash: Sha512) -> Scalar {
    let mut wide = Zeroizing::new([0u8; 64]);
    wide.copy_from_slice(&hash.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wireguard_control::KeyPair;

    fn key() -> (KeyPair, PrivateKey) {
        let keypair = KeyPair::generate();
        let private_key = PrivateKey::from_base64(&keypair.private.to_base64()).unwrap();
        (keypair, private_key)
    }

    #[test]
    fn test_public_key_matches_wireguard() {
        for _ in 0..16 {
            let (keypair, private_key) = key();
            assert_eq!(private_key.public_key(), &keypair.public);
            assert_eq!(
                edwards_from_x25519(&keypair.public).unwrap().compress(),
                *private_key.ed25519_public_key()
            );
        }
    }

    #[test]
    fn test_sign_and_verify() {
        // Enough keys that both signs of `k·B` are covered.
        for _ in 0..32 {
            let (keypair, private_key) = key();
            let signature = private_key.sign(&[b"mess", b"age"]);
            assert!(verify(&keypair.public, &[b"message"], &signature));
            assert!(verify(&keypair.public, &[b"me", b"ssage"], &signature));
            assert!(!verify(&keypair.public, &[b"messagf"], &signature));
            assert!(!verify(
                &KeyPair::generate().public,
                &[b"message"],
                &signature
            ));
        }
    }

    #[test]
    fn test_signatures_are_randomized() {
        let (_, private_key) = key();
        assert_ne!(private_key.sign(&[b"m"]), private_key.sign(&[b"m"]));
    }

    #[test]
    fn test_rejects_malformed_signatures() {
        let (keypair, private_key) = key();
        let signature = private_key.sign(&[b"message"]);
        assert!(!verify(&keypair.public, &[b"message"], &signature[..63]));

        // s + L is congruent to s, but isn't its canonical encoding.
        let l = (Scalar::ZERO - Scalar::ONE).as_bytes().map(u16::from);
        let mut malleated = signature;
        let mut carry = 1; // L - 1 + 1
        for (byte, l) in malleated[32..].iter_mut().zip(l) {
            let sum = u16::from(*byte) + l + carry;
            *byte = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0);
        assert!(!verify(&keypair.public, &[b"message"], &malleated));
    }

    #[test]
    fn test_rejects_invalid_public_keys() {
        assert!(is_valid_public_key(&KeyPair::generate().public));
        // u = 0 and u = 1 are of low order, u = p - 1 has no Edwards equivalent.
        let mut one = [0; 32];
        one[0] = 1;
        let mut p_minus_1 = [0xff; 32];
        p_minus_1[0] = 0xec;
        p_minus_1[31] = 0x7f;
        for u in [[0; 32], one, p_minus_1] {
            assert!(!is_valid_public_key(&Key(u)));
        }
        // A valid key with the unused top bit set, which X25519 ignores.
        let mut non_canonical = KeyPair::generate().public;
        non_canonical.0[31] |= 0x80;
        assert!(!is_valid_public_key(&non_canonical));
        // A point of mixed order: a valid key plus a point of order 2.
        let order_two = MontgomeryPoint([0; 32]).to_edwards(0).unwrap();
        let valid = edwards_from_x25519(&KeyPair::generate().public).unwrap();
        let mixed = Key((valid + order_two).to_montgomery().0);
        assert!(!is_valid_public_key(&mixed));
    }

    fn from_hex<const N: usize>(hex: &str) -> [u8; N] {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    }

    /// Yields fixed bytes, to make signatures reproducible.
    struct FixedRng(Vec<u8>);

    impl rand::RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            unimplemented!()
        }

        fn next_u64(&mut self) -> u64 {
            unimplemented!()
        }

        fn fill_bytes(&mut self, dst: &mut [u8]) {
            let rest = self.0.split_off(dst.len());
            dst.copy_from_slice(&self.0);
            self.0 = rest;
        }
    }

    impl CryptoRng for FixedRng {}

    /// Signatures made by p2panda-encryption 0.7.1's independent implementation of the
    /// specification, given the same `Z`, for a key whose `k·B` has each sign bit.
    #[test]
    fn test_known_answers() {
        let message = b"innernet xeddsa test vector";
        let vectors = [
            (
                [1; 32],
                "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209",
                "f400927857aaf64114f561baacb379708c79a1dc1476ab573216a4020764bde5\
                 45c143dbb9609c22ab855d60925a997603d78a3f20d154abd8ddfa6974eedf6b",
                "268a77c68dd4fdde2eb30cb5578ffdc5b7b246459fd27ea39a1df7652c642b4e\
                 1d0b861fac60b24eed24242e404a0f36c76bc2d98beceae0a3138ba35fb1ff02",
            ),
            (
                [0; 32],
                "2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74",
                "f2a76980dfc7a4924b326a129e9e7c7ee381ff8caa2e4fd1ee76966fd1b01909\
                 7897bdd7ad188ad93ce0bbd215ecfd558fdba78d259c451f7d72b48d7b03a652",
                "b89d8c9d40fbed4657c07b740caa7fe658382007ccfb3012fb0b132fac6b6555\
                 91911163d37192fc0bf8fe93ef42c763a93b75974aeb64a69f98b64b0678ee03",
            ),
        ];
        let mut sign_bits = vec![];
        for (private, public, random, signature) in vectors {
            let private_key = PrivateKey::from_bytes(&private);
            let public_key = Key(from_hex(public));
            assert_eq!(private_key.public_key(), &public_key);
            let point =
                EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(clamp_integer(private)));
            sign_bits.push(point.compress().0[31] >> 7);

            let random: [u8; 64] = from_hex(random);
            let signature: [u8; 64] = from_hex(signature);
            let signed = private_key.sign_with_rng(&[message], &mut FixedRng(random.to_vec()));
            assert_eq!(signed, signature);
            assert!(verify(&public_key, &[message], &signature));
        }
        assert_eq!(sign_bits, [0, 1]);
    }
}
