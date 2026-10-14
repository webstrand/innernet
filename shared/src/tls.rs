//! Mutually authenticated TLS between peers and the coordinating server.
//!
//! Each side authenticates with its WireGuard key, presented as an RFC 7250 raw public key. A
//! WireGuard (X25519) key can't sign, so the key is presented in its Edwards form with sign
//! bit 0 and the handshake is signed with XEdDSA, which makes standard Ed25519 signatures
//! under it. Verification uses the crypto provider's unmodified Ed25519 implementation.
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
        AlwaysResolvesServerRawPublicKeys, NoServerSessionStorage,
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

    fn certified(self) -> Arc<CertifiedKey> {
        let spki = CertificateDer::from(self.spki.clone());
        Arc::new(CertifiedKey::new(vec![spki], Arc::new(self)))
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

fn verify_signature(
    algorithms: &WebPkiSupportedAlgorithms,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    verify_tls13_signature_with_raw_key(
        message,
        &SubjectPublicKeyInfoDer::from(cert.as_ref()),
        dss,
        algorithms,
    )
}

fn tls12_unsupported() -> Result<HandshakeSignatureValid, rustls::Error> {
    Err(rustls::Error::General("TLS 1.2 is not supported".into()))
}

/// Accepts only the server's pinned WireGuard key.
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
        match x25519_from_spki(end_entity.as_ref()) {
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
        verify_signature(&self.algorithms, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
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
/// private key and requiring the client to authenticate with its own. Sessions are never
/// resumed and early data is refused, so every connection is authenticated afresh.
pub fn server_config(private_key: &str) -> Result<Arc<ServerConfig>, Error> {
    let provider = provider();
    let verifier = PeerKeyVerifier {
        algorithms: provider.signature_verification_algorithms,
    };
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(verifier))
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(
            XEdDsaKey::new(private_key)?.certified(),
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
