//! Certificate pinning for Passyble Server's self-signed certificate.
//!
//! A pin is `sha256:` + base64url (no padding) of the SHA-256 of the leaf certificate's DER
//! SubjectPublicKeyInfo. Pins replace CA validation: chain, host name and dates are not checked,
//! but the handshake signature is, which proves the server holds the pinned key.

use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::encoding::b64url_encode;
use crate::i18n::tr;
use crate::{PassError, Result};

const PIN_PREFIX: &str = "sha256:";

/// `sha256:<base64url(SHA-256(SubjectPublicKeyInfo DER))>` of a DER certificate, or `None` if it
/// can't be parsed.
pub fn spki_pin(cert_der: &[u8]) -> Option<String> {
    let spki = spki_from_cert(cert_der)?;
    Some(format!(
        "{PIN_PREFIX}{}",
        b64url_encode(Sha256::digest(spki).to_vec())
    ))
}

/// Trims the pins and checks their form (`sha256:` + 43 base64url characters = 32 bytes).
pub(crate) fn normalize_pins(pins: &[String]) -> Result<Vec<String>> {
    pins.iter()
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(|pin| {
            let valid = pin.strip_prefix(PIN_PREFIX).is_some_and(|hash| {
                hash.len() == 43
                    && hash
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            });
            if valid {
                Ok(pin.to_string())
            } else {
                Err(PassError::InvalidInput(tr!(
                    "pinning.invalid_pin",
                    pin = format!("{pin:?}")
                )))
            }
        })
        .collect()
}

/// Accepts exactly the server keys whose SPKI SHA-256 is pinned, and remembers the pin of a
/// rejected certificate so the caller can report [`PassError::CertificateChanged`].
#[derive(Debug)]
pub(crate) struct PinVerifier {
    pins: Vec<String>,
    provider: Arc<CryptoProvider>,
    /// Pin of the last certificate that matched no pin.
    rejected: Mutex<Option<String>>,
}

impl PinVerifier {
    pub(crate) fn new(pins: Vec<String>) -> Arc<Self> {
        Arc::new(Self {
            pins,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            rejected: Mutex::new(None),
        })
    }

    /// A rustls client configuration that verifies the server with this verifier only.
    pub(crate) fn client_config(self: &Arc<Self>) -> Result<Arc<rustls::ClientConfig>> {
        let config = rustls::ClientConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|_| PassError::Network(tr!("pinning.tls_setup")))?
            .dangerous()
            .with_custom_certificate_verifier(self.clone())
            .with_no_client_auth();
        Ok(Arc::new(config))
    }

    /// The pin of a certificate this verifier rejected, if any.
    pub(crate) fn rejected(&self) -> Option<String> {
        self.rejected
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        let pin =
            spki_pin(end_entity).ok_or(Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if self.pins.iter().any(|p| p == &pin) {
            Ok(ServerCertVerified::assertion())
        } else {
            *self.rejected.lock().unwrap_or_else(|p| p.into_inner()) = Some(pin);
            Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Trust on first use: connects to a Passyble Server without verifying its certificate and returns
/// the pin of the leaf certificate's SubjectPublicKeyInfo (the handshake signature is still checked).
/// Blocking. The pin proves nothing by itself, so show it to the user and keep it only after they
/// confirm. Errors: `InvalidInput` (bad address, or `http://`), `Network` (can't connect, not TLS).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn fetch_server_pin(url: String) -> Result<String> {
    use std::io::Write;
    use std::net::ToSocketAddrs;
    use std::time::Duration;

    let base = crate::normalize_server_url(url)?;
    let parsed = url::Url::parse(&base)
        .map_err(|_| PassError::InvalidInput(tr!("server.invalid_address")))?;
    if parsed.scheme() != "https" {
        return Err(PassError::InvalidInput(tr!("pinning.plain_http")));
    }
    let host = match parsed.host() {
        Some(url::Host::Domain(d)) => d.to_string(),
        Some(url::Host::Ipv4(ip)) => ip.to_string(),
        Some(url::Host::Ipv6(ip)) => ip.to_string(),
        None => return Err(PassError::InvalidInput(tr!("server.invalid_address"))),
    };
    let port = parsed.port_or_known_default().unwrap_or(443);
    let server_name = ServerName::try_from(host.clone()).map_err(|_| {
        PassError::InvalidInput(tr!("pinning.invalid_host", host = format!("{host:?}")))
    })?;

    let verifier = Arc::new(RecordingVerifier {
        provider: Arc::new(rustls::crypto::ring::default_provider()),
        seen: Mutex::new(None),
    });
    let config = rustls::ClientConfig::builder_with_provider(verifier.provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|_| PassError::Network(tr!("pinning.tls_setup")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|_| PassError::Network(tr!("pinning.tls_setup")))?;

    // The system's reason (no such host, refused, timed out) isn't for the user.
    let connect_err = |_: std::io::Error| {
        PassError::Network(tr!("pinning.cant_connect", host = format!("{host}:{port}")))
    };
    let addrs: Vec<_> = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(connect_err)?
        .collect();
    let mut last_err = None;
    let mut sock = None;
    for addr in addrs {
        match std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
            Ok(s) => {
                sock = Some(s);
                break;
            }
            Err(e) => last_err = Some(e),
        }
    }
    let mut sock = match sock {
        Some(s) => s,
        None => {
            return Err(connect_err(last_err.unwrap_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "no address found")
            })))
        }
    };
    let _ = sock.set_read_timeout(Some(Duration::from_secs(15)));
    let _ = sock.set_write_timeout(Some(Duration::from_secs(15)));
    while conn.is_handshaking() {
        if conn.complete_io(&mut sock).is_err() {
            // A handshake that fails after the certificate (e.g. a bad signature) must not return
            // the pin; one that failed before it has none to return anyway.
            return Err(PassError::Network(tr!(
                "pinning.handshake_failed",
                host = format!("{host}:{port}")
            )));
        }
    }
    conn.send_close_notify();
    let _ = conn.complete_io(&mut sock);
    let _ = sock.flush();
    let seen = verifier
        .seen
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    seen.ok_or_else(|| {
        PassError::Network(tr!(
            "pinning.no_certificate",
            host = format!("{host}:{port}")
        ))
    })
}

/// Accepts any server certificate but records its pin (for [`fetch_server_pin`]); still verifies
/// the handshake signature against the presented certificate.
#[derive(Debug)]
struct RecordingVerifier {
    provider: Arc<CryptoProvider>,
    seen: Mutex<Option<String>>,
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        let pin =
            spki_pin(end_entity).ok_or(Error::InvalidCertificate(CertificateError::BadEncoding))?;
        *self.seen.lock().unwrap_or_else(|p| p.into_inner()) = Some(pin);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// One DER TLV.
struct Tlv<'a> {
    tag: u8,
    /// Tag, length and content.
    whole: &'a [u8],
    content: &'a [u8],
    rest: &'a [u8],
}

fn der_tlv(input: &[u8]) -> Option<Tlv<'_>> {
    let tag = *input.first()?;
    let first = *input.get(1)? as usize;
    let (len, header) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *input.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let end = header.checked_add(len)?;
    if end > input.len() {
        return None;
    }
    Some(Tlv {
        tag,
        whole: &input[..end],
        content: &input[header..end],
        rest: &input[end..],
    })
}

/// Extracts the DER SubjectPublicKeyInfo from an X.509 certificate.
fn spki_from_cert(cert: &[u8]) -> Option<&[u8]> {
    let cert = der_tlv(cert)?;
    if cert.tag != 0x30 {
        return None;
    }
    let tbs = der_tlv(cert.content)?;
    if tbs.tag != 0x30 {
        return None;
    }
    let mut rest = tbs.content;
    if rest.first() == Some(&0xa0) {
        rest = der_tlv(rest)?.rest;
    }
    for _ in 0..5 {
        rest = der_tlv(rest)?.rest;
    }
    let spki = der_tlv(rest)?;
    (spki.tag == 0x30).then_some(spki.whole)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::PublicKeyData;

    #[test]
    fn spki_matches_rcgen() {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let spki = spki_from_cert(generated.cert.der()).unwrap();
        assert_eq!(
            spki,
            generated.signing_key.subject_public_key_info().as_slice()
        );
        let pin = spki_pin(generated.cert.der()).unwrap();
        assert!(pin.starts_with("sha256:"));
        assert_eq!(pin.len(), "sha256:".len() + 43);
        assert_eq!(normalize_pins(&[format!(" {pin} ")]).unwrap(), vec![pin]);
        assert!(spki_from_cert(b"\x30\x03\x02\x01\x00").is_none());
        assert!(spki_from_cert(b"").is_none());
    }

    #[test]
    fn pin_form_is_checked() {
        assert!(normalize_pins(&["md5:abc".into()]).is_err());
        assert!(normalize_pins(&["sha256:short".into()]).is_err());
        assert!(normalize_pins(&[format!("sha256:{}", "A".repeat(42) + "+")]).is_err());
        assert!(normalize_pins(&["".into(), "  ".into()])
            .unwrap()
            .is_empty());
    }
}
