//! Mutually authenticated TLS between peers and the coordinating server.
//!
//! Each side authenticates with its WireGuard key. A WireGuard (X25519) key can't sign, so the key
//! is presented in its Edwards form with sign bit 0 and the handshake is signed with XEdDSA, which
//! makes standard Ed25519 signatures under it. Verification uses the crypto provider's unmodified
//! Ed25519 implementation.
//!
//! A peer presents its key as an RFC 7250 raw public key. The server presents its key in a
//! self-signed X.509 certificate, so that tools that know no raw public keys, such as curl with
//! `--pinnedpubkey`, can reach it. A client takes the key out of the certificate, and ignores
//! the certificate's own signature and dates: the handshake signature proves the key.
//!
//! The recipient maps the presented point back to the X25519 key, the identity that it pins.
//! Only the sign-0 form is accepted, so each X25519 key has exactly one presentation.

use crate::xeddsa::{self, PrivateKey};
use anyhow::{anyhow, Error};
use curve25519_dalek::edwards::CompressedEdwardsY;
use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        AlwaysResolvesClientRawPublicKeys, Resumption,
    },
    crypto::{verify_tls13_signature_with_raw_key, CryptoProvider, WebPkiSupportedAlgorithms},
    pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime},
    server::{
        danger::{ClientCertVerified, ClientCertVerifier},
        ClientHello, NoServerSessionStorage, ResolvesServerCert,
    },
    sign::{CertifiedKey, Signer, SigningKey},
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig,
    SignatureAlgorithm, SignatureScheme,
};
use std::{fmt, sync::Arc};
use wireguard_control::Key;

/// The DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410), followed by the 32-byte key.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The first byte of a TLS handshake record, which no HTTP request line starts with.
pub const TLS_HANDSHAKE_RECORD: u8 = 0x16;

pub(crate) fn ed25519_spki(point: &CompressedEdwardsY) -> Vec<u8> {
    let mut spki = ED25519_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(point.as_bytes());
    spki
}

/// The X25519 public key presented as an Ed25519 SubjectPublicKeyInfo, if it is one.
pub fn x25519_from_spki(spki: &[u8]) -> Option<Key> {
    let point = spki.strip_prefix(&ED25519_SPKI_PREFIX[..])?;
    let point = CompressedEdwardsY::from_slice(point).ok()?;
    // XEdDSA keys have sign bit 0.
    if point.0[31] & 0x80 != 0 {
        return None;
    }
    let key = Key(point.decompress()?.to_montgomery().0);
    // The key must be valid, and map back to exactly the presented encoding.
    (xeddsa::ed25519_public_key(&key) == Some(point)).then_some(key)
}

/// The X25519 public key the peer authenticated with on a TLS connection.
pub fn peer_public_key(certificates: Option<&[CertificateDer<'_>]>) -> Option<Key> {
    match certificates? {
        [spki] => x25519_from_spki(spki.as_ref()),
        _ => None,
    }
}

/// The SubjectPublicKeyInfo of the X.509 certificate `certificate`, if it parses as one.
fn certificate_spki(certificate: &CertificateDer<'_>) -> Option<Vec<u8>> {
    let certificate = webpki::EndEntityCert::try_from(certificate).ok()?;
    Some(certificate.subject_public_key_info().to_vec())
}

/// The DER encoding (X.690) of the element with the tag `tag` whose contents are `parts`, one
/// after the other.
fn der(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let len: usize = parts.iter().map(|part| part.len()).sum();
    let mut encoded = vec![tag];
    match len {
        0..=0x7f => encoded.push(len as u8),
        0x80..=0xff => encoded.extend([0x81, len as u8]),
        _ => encoded.extend([0x82, (len >> 8) as u8, len as u8]),
    }
    for part in parts {
        encoded.extend_from_slice(part);
    }
    encoded
}

/// The AlgorithmIdentifier of Ed25519 (RFC 8410), without parameters.
const ED25519_ALGORITHM: [u8; 7] = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

/// The common name of the subject and the issuer of the server's certificate.
const CERTIFICATE_NAME: &str = "innernet-server";

/// The self-signed X.509 certificate (RFC 5280) that the server presents its key in, signed with
/// XEdDSA under that key.
///
/// The certificate follows a minimal fixed template, in which only the key and the signature
/// vary: version 3, serial number 1, the subject and issuer `CN=innernet-server`, a validity from
/// 1970 to the end of 9999, the value that RFC 5280 gives a certificate without a well-defined
/// expiration date, and no extensions. Clients pin the key, and ignore everything else, so nothing
/// else carries meaning.
fn server_certificate(private_key: &PrivateKey) -> Vec<u8> {
    let common_name = der(0x0c, &[CERTIFICATE_NAME.as_bytes()]);
    // Name ::= SEQUENCE OF SET OF { id-at-commonName, UTF8String }
    let name = der(
        0x30,
        &[&der(
            0x31,
            &[&der(0x30, &[&[0x06, 0x03, 0x55, 0x04, 0x03], &common_name])],
        )],
    );
    // A UTCTime before 2050, and a GeneralizedTime after, as RFC 5280 requires.
    let validity = der(
        0x30,
        &[
            &der(0x17, &[b"700101000000Z"]),
            &der(0x18, &[b"99991231235959Z"]),
        ],
    );
    let spki = ed25519_spki(private_key.ed25519_public_key());
    let tbs_certificate = der(
        0x30,
        &[
            // [0] EXPLICIT Version v3
            &[0xa0, 0x03, 0x02, 0x01, 0x02],
            // CertificateSerialNumber 1
            &[0x02, 0x01, 0x01],
            &ED25519_ALGORITHM,
            &name,
            &validity,
            &name,
            &spki,
        ],
    );
    let signature = private_key.sign(&[&tbs_certificate]);
    // A BIT STRING without unused bits.
    let signature_value = der(0x03, &[&[0], &signature]);
    der(
        0x30,
        &[&tbs_certificate, &ED25519_ALGORITHM, &signature_value],
    )
}

/// A WireGuard private key signing TLS handshakes as Ed25519.
struct XEdDsaKey {
    private_key: Arc<PrivateKey>,
    spki: Vec<u8>,
}

impl XEdDsaKey {
    fn new(private_key: &str) -> Result<Self, Error> {
        let private_key = PrivateKey::from_base64(private_key)?;
        let spki = ed25519_spki(private_key.ed25519_public_key());
        Ok(Self {
            private_key: Arc::new(private_key),
            spki,
        })
    }

    /// The key, presented as a raw public key.
    fn certified(self) -> Arc<CertifiedKey> {
        let spki = CertificateDer::from(self.spki.clone());
        Arc::new(CertifiedKey::new(vec![spki], Arc::new(self)))
    }

    /// The key, presented in the server's self-signed certificate, which is built once, here.
    fn certified_by_itself(self) -> Arc<CertifiedKey> {
        let certificate = CertificateDer::from(server_certificate(&self.private_key));
        Arc::new(CertifiedKey::new(vec![certificate], Arc::new(self)))
    }
}

/// Presents the server's key in its self-signed certificate to every client.
#[derive(Debug)]
struct ServerCertificate(Arc<CertifiedKey>);

impl ResolvesServerCert for ServerCertificate {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

impl fmt::Debug for XEdDsaKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XEdDsaKey")
            .field("public_key", &self.private_key.public_key().to_base64())
            .finish_non_exhaustive()
    }
}

impl SigningKey for XEdDsaKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ED25519)
            .then(|| Box::new(XEdDsaSigner(self.private_key.clone())) as Box<dyn Signer>)
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(&self.spki[..]))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

struct XEdDsaSigner(Arc<PrivateKey>);

impl fmt::Debug for XEdDsaSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XEdDsaSigner")
    }
}

impl Signer for XEdDsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        Ok(self.0.sign(&[message]).to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Verifies the handshake signature `dss` of `message` under the key of the SubjectPublicKeyInfo
/// `spki`.
fn verify_signature(
    algorithms: &WebPkiSupportedAlgorithms,
    message: &[u8],
    spki: &[u8],
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    verify_tls13_signature_with_raw_key(
        message,
        &SubjectPublicKeyInfoDer::from(spki),
        dss,
        algorithms,
    )
}

fn tls12_unsupported() -> Result<HandshakeSignatureValid, rustls::Error> {
    Err(rustls::Error::General("TLS 1.2 is not supported".into()))
}

/// Accepts only the server's pinned WireGuard key, in the certificate that the server presents.
/// The certificate's own signature and dates are ignored: the handshake signature, which
/// [`Self::verify_tls13_signature`] checks under the key, proves that the server holds the key.
/// The verifier doesn't require raw public keys, so that the client asks for the server's
/// certificate.
#[derive(Debug)]
struct ServerKeyVerifier {
    server_public_key: Key,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for ServerKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let key = certificate_spki(end_entity).and_then(|spki| x25519_from_spki(&spki));
        match key {
            Some(key) if intermediates.is_empty() && key == self.server_public_key => {
                Ok(ServerCertVerified::assertion())
            },
            _ => Err(CertificateError::ApplicationVerificationFailure.into()),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        tls12_unsupported()
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let spki = certificate_spki(cert).ok_or(CertificateError::BadEncoding)?;
        verify_signature(&self.algorithms, message, &spki, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// Accepts any well-formed WireGuard key; whether it belongs to a peer is up to the server,
/// which reads it back with [`peer_public_key`].
#[derive(Debug)]
struct PeerKeyVerifier {
    algorithms: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for PeerKeyVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        match x25519_from_spki(end_entity.as_ref()) {
            Some(_) if intermediates.is_empty() => Ok(ClientCertVerified::assertion()),
            _ => Err(CertificateError::ApplicationVerificationFailure.into()),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        tls12_unsupported()
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_signature(&self.algorithms, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// The server's TLS configuration: TLS 1.3 only, authenticating with the server's WireGuard
/// private key, in its self-signed certificate, and requiring the client to authenticate with its
/// own, as a raw public key. Sessions are never resumed and early data is refused, so every
/// connection is authenticated afresh.
pub fn server_config(private_key: &str) -> Result<Arc<ServerConfig>, Error> {
    let provider = provider();
    let verifier = PeerKeyVerifier {
        algorithms: provider.signature_verification_algorithms,
    };
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(verifier))
        .with_cert_resolver(Arc::new(ServerCertificate(
            XEdDsaKey::new(private_key)?.certified_by_itself(),
        )));
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}

/// A peer's TLS configuration: TLS 1.3 only, authenticating with the peer's WireGuard private
/// key and accepting only the server's pinned public key.
pub fn client_config(
    private_key: &str,
    server_public_key: &str,
) -> Result<Arc<ClientConfig>, Error> {
    let server_public_key = Key::from_base64(server_public_key)
        .map_err(|_| anyhow!("the server's public key is invalid"))?;
    let provider = provider();
    let verifier = ServerKeyVerifier {
        server_public_key,
        algorithms: provider.signature_verification_algorithms,
    };
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(
            XEdDsaKey::new(private_key)?.certified(),
        )));
    config.resumption = Resumption::disabled();
    config.enable_sni = false;
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{ClientConnection, ServerConnection};
    use wireguard_control::KeyPair;

    /// Runs a handshake in memory, returning the key the server saw the client authenticate
    /// with.
    fn handshake(
        client: Arc<ClientConfig>,
        server: Arc<ServerConfig>,
    ) -> Result<Option<Key>, rustls::Error> {
        let name = ServerName::IpAddress(std::net::Ipv4Addr::new(10, 0, 0, 1).into());
        let mut client = ClientConnection::new(client, name)?;
        let mut server = ServerConnection::new(server)?;
        for _ in 0..10 {
            let mut buffer = Vec::new();
            client.write_tls(&mut buffer).unwrap();
            server.read_tls(&mut &buffer[..]).unwrap();
            server.process_new_packets()?;
            buffer.clear();
            server.write_tls(&mut buffer).unwrap();
            client.read_tls(&mut &buffer[..]).unwrap();
            client.process_new_packets()?;
            if !client.is_handshaking() && !server.is_handshaking() {
                // The server presents its self-signed certificate.
                let [certificate] = client.peer_certificates().unwrap() else {
                    panic!("the server presented more than its certificate");
                };
                assert!(webpki::EndEntityCert::try_from(certificate).is_ok());
                return Ok(peer_public_key(server.peer_certificates()));
            }
        }
        panic!("handshake didn't complete");
    }

    fn private(keypair: &KeyPair) -> String {
        keypair.private.to_base64()
    }

    #[test]
    fn test_mutual_authentication() {
        // Enough keys that both signs of `A` are covered.
        for _ in 0..16 {
            let (server, client) = (KeyPair::generate(), KeyPair::generate());
            let seen = handshake(
                client_config(&private(&client), &server.public.to_base64()).unwrap(),
                server_config(&private(&server)).unwrap(),
            )
            .unwrap();
            assert_eq!(seen, Some(client.public));
        }
    }

    #[test]
    fn test_client_rejects_wrong_server_key() {
        let (server, client) = (KeyPair::generate(), KeyPair::generate());
        let pinned = KeyPair::generate().public.to_base64();
        let result = handshake(
            client_config(&private(&client), &pinned).unwrap(),
            server_config(&private(&server)).unwrap(),
        );
        assert!(matches!(
            result,
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure
            ))
        ));
    }

    #[test]
    fn test_server_certificate() {
        for _ in 0..16 {
            let keypair = KeyPair::generate();
            let private_key = PrivateKey::from_base64(&private(&keypair)).unwrap();
            let certificate = server_certificate(&private_key);

            // The certificate parses as X.509, and holds the key's SubjectPublicKeyInfo.
            let spki = ed25519_spki(private_key.ed25519_public_key());
            let der = CertificateDer::from(&certificate[..]);
            assert_eq!(certificate_spki(&der), Some(spki.clone()));

            // It is signed with the key, over its TBSCertificate, which follows the header of
            // the outer SEQUENCE, of three bytes, and which is followed by the signature
            // algorithm and the signature, in the last 64 bytes.
            assert_eq!(&certificate[..2], [0x30, 0x81]);
            assert_eq!(certificate[2] as usize, certificate.len() - 3);
            let tbs_len = certificate[5] as usize + 3;
            let tbs = &certificate[3..3 + tbs_len];
            assert_eq!(
                &certificate[3 + tbs_len..3 + tbs_len + 7],
                ED25519_ALGORITHM
            );
            let signature = &certificate[certificate.len() - 64..];
            let spki = SubjectPublicKeyInfoDer::from(&spki[..]);
            let verifier = webpki::RawPublicKeyEntity::try_from(&spki).unwrap();
            assert!(verifier
                .verify_signature(webpki::ring::ED25519, tbs, signature)
                .is_ok());
        }
    }

    #[test]
    fn test_client_takes_the_key_out_of_the_certificate() {
        let keypair = KeyPair::generate();
        let private_key = PrivateKey::from_base64(&private(&keypair)).unwrap();
        let verifier = ServerKeyVerifier {
            server_public_key: keypair.public.clone(),
            algorithms: provider().signature_verification_algorithms,
        };
        let verify = |certificate: Vec<u8>| {
            let name = ServerName::IpAddress(std::net::Ipv4Addr::new(10, 0, 0, 1).into());
            verifier.verify_server_cert(
                &CertificateDer::from(certificate),
                &[],
                &name,
                &[],
                UnixTime::now(),
            )
        };

        // The certificate's own signature is ignored: the handshake signature proves the key.
        let mut certificate = server_certificate(&private_key);
        assert!(verify(certificate.clone()).is_ok());
        let last = certificate.len() - 1;
        certificate[last] ^= 1;
        assert!(verify(certificate).is_ok());

        // A raw public key isn't a certificate, and another key isn't the pinned one.
        assert!(verify(ed25519_spki(private_key.ed25519_public_key())).is_err());
        let other = PrivateKey::from_base64(&private(&KeyPair::generate())).unwrap();
        assert!(verify(server_certificate(&other)).is_err());
    }

    #[test]
    fn test_signatures_are_standard_ed25519() {
        for _ in 0..32 {
            let private_key = PrivateKey::from_base64(&private(&KeyPair::generate())).unwrap();
            let signature = private_key.sign(&[b"message"]);
            let spki = ed25519_spki(private_key.ed25519_public_key());
            let spki = SubjectPublicKeyInfoDer::from(&spki[..]);
            let verifier = webpki::RawPublicKeyEntity::try_from(&spki).unwrap();
            let ed25519 = webpki::ring::ED25519;
            assert!(verifier
                .verify_signature(ed25519, b"message", &signature)
                .is_ok());
        }
    }

    #[test]
    fn test_spki_round_trip() {
        for _ in 0..32 {
            let keypair = KeyPair::generate();
            let key = XEdDsaKey::new(&private(&keypair)).unwrap();
            assert_eq!(x25519_from_spki(&key.spki).as_ref(), Some(&keypair.public));

            // The negated point maps to the same X25519 key, but isn't its presentation.
            let point = CompressedEdwardsY::from_slice(&key.spki[12..]).unwrap();
            let negated = ed25519_spki(&(-point.decompress().unwrap()).compress());
            assert_eq!(x25519_from_spki(&negated), None);
        }
        assert_eq!(x25519_from_spki(&[0; 44]), None);
        assert_eq!(x25519_from_spki(&ED25519_SPKI_PREFIX), None);
        // A low-order point.
        let identity = curve25519_dalek::EdwardsPoint::default().compress();
        assert_eq!(x25519_from_spki(&ed25519_spki(&identity)), None);
    }
}
