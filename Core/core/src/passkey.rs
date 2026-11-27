//! A software WebAuthn authenticator. Keys are ES256 (P-256), attestation is `none`, and the
//! credential is flagged backup-eligible/backed-up because the vault syncs it. Every new passkey
//! also gets a WebAuthn PRF secret.

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use sha2::{Digest, Sha256};
use url::Url;

use crate::encoding::b64url_encode;
use crate::i18n::tr;
use crate::matching::normalize_cert;
use crate::model::Passkey;
use crate::{now_ms, PassError, Result};

/// Identifies Pass as the authenticator model. Random, fixed forever.
pub const AAGUID: [u8; 16] = [
    0x5a, 0x1d, 0x4c, 0x2e, 0x8b, 0x7f, 0x4e, 0x0a, 0x9c, 0x3d, 0x61, 0xf2, 0x0b, 0x58, 0xa4, 0x93,
];

const COSE_ES256: i64 = -7;
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PasskeyCreation {
    pub passkey: Passkey,
    pub credential_id: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    /// SubjectPublicKeyInfo DER, as returned by `AuthenticatorAttestationResponse.getPublicKey()`.
    pub public_key_spki: Vec<u8>,
    pub public_key_algorithm: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PasskeyAssertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    /// ASN.1 DER ECDSA signature over `authenticator_data || client_data_hash`.
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn sha256(data: Vec<u8>) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

/// Creates a new passkey and the registration response data for it.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn passkey_create(
    rp_id: String,
    rp_name: Option<String>,
    user_handle: Vec<u8>,
    user_name: String,
    user_display_name: String,
    client_data_hash: Vec<u8>,
    algorithms: Vec<i64>,
) -> Result<PasskeyCreation> {
    if !algorithms.is_empty() && !algorithms.contains(&COSE_ES256) {
        // The site doesn't accept ES256, the only key type Passyble makes.
        return Err(PassError::InvalidInput(tr!(
            "passkey.unsupported_algorithm"
        )));
    }
    check_hash(&client_data_hash)?;
    if rp_id.is_empty() {
        return Err(PassError::InvalidInput(tr!("passkey.bad_request")));
    }
    if user_handle.is_empty() || user_handle.len() > 64 {
        return Err(PassError::InvalidInput(tr!("passkey.bad_request")));
    }

    let signing_key = new_signing_key();
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_sec1_point(false);
    let (x, y) = (
        point.x().expect("uncompressed point"),
        point.y().expect("uncompressed point"),
    );
    let credential_id = crate::crypto::random_bytes::<16>().to_vec();

    let mut auth_data =
        auth_data_prefix(&rp_id, FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT, 0);
    auth_data.extend_from_slice(&AAGUID);
    auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(&credential_id);
    auth_data.extend_from_slice(&cose_es256_key(x, y));

    let mut attestation_object = vec![0xa3];
    cbor_text(&mut attestation_object, "fmt");
    cbor_text(&mut attestation_object, "none");
    cbor_text(&mut attestation_object, "attStmt");
    attestation_object.push(0xa0);
    cbor_text(&mut attestation_object, "authData");
    cbor_bytes(&mut attestation_object, &auth_data);

    // The WebAuthn PRF secret (`credRandom`) is made now, once, and kept inside the private key,
    // so it lives and syncs exactly as long as the passkey does.
    let prf_secret =
        zeroize::Zeroizing::new(crate::crypto::random_bytes::<{ crate::prf::PRF_LEN }>());
    let private_key_pkcs8 = signing_key
        .to_pkcs8_der()
        .ok()
        .and_then(|der| crate::prf::pkcs8_with_prf_secret(der.as_bytes(), &prf_secret))
        .ok_or_else(|| PassError::Crypto(tr!("error.internal")))?;
    let public_key_spki = verifying_key
        .to_public_key_der()
        .map_err(|_| PassError::Crypto(tr!("error.internal")))?
        .into_vec();

    let passkey = Passkey {
        credential_id: credential_id.clone(),
        rp_id,
        rp_name,
        user_handle,
        user_name,
        user_display_name,
        private_key_pkcs8,
        sign_count: 0,
        discoverable: true,
        created_at: now_ms(),
    };
    Ok(PasskeyCreation {
        passkey,
        credential_id,
        attestation_object,
        authenticator_data: auth_data,
        public_key_spki,
        public_key_algorithm: COSE_ES256,
    })
}

/// A new random P-256 key from [`crate::crypto::random_bytes`], which avoids p256's newer
/// `rand_core` traits. An invalid scalar (about 2^-32) is drawn again; the bytes are zeroized.
pub(crate) fn new_signing_key() -> SigningKey {
    loop {
        let bytes = zeroize::Zeroizing::new(crate::crypto::random_bytes::<32>());
        if let Ok(key) = SigningKey::from_slice(&bytes[..]) {
            return key;
        }
    }
}

/// Signs an assertion with a stored passkey. The caller is responsible for user presence:
/// only call this after the user approved the sign-in.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn passkey_assert(
    passkey: Passkey,
    client_data_hash: Vec<u8>,
    user_verified: bool,
) -> Result<PasskeyAssertion> {
    check_hash(&client_data_hash)?;
    let signing_key = SigningKey::from_pkcs8_der(&passkey.private_key_pkcs8)
        .map_err(|_| PassError::Crypto(tr!("passkey.damaged")))?;
    let mut flags = FLAG_UP | FLAG_BE | FLAG_BS;
    if user_verified {
        flags |= FLAG_UV;
    }
    // Synced passkeys report a constant 0 counter so devices never disagree.
    let authenticator_data = auth_data_prefix(&passkey.rp_id, flags, 0);
    let mut message = authenticator_data.clone();
    message.extend_from_slice(&client_data_hash);
    let signature: Signature = signing_key.sign(&message);
    Ok(PasskeyAssertion {
        credential_id: passkey.credential_id,
        authenticator_data,
        signature: signature.to_der().as_bytes().to_vec(),
        user_handle: passkey.user_handle,
    })
}

/// Builds `clientDataJSON` exactly as browsers serialise it (fixed key order).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn client_data_json(
    kind: String,
    challenge: Vec<u8>,
    origin: String,
    cross_origin: bool,
    android_package: Option<String>,
) -> String {
    let mut json = format!(
        "{{\"type\":{},\"challenge\":{},\"origin\":{},\"crossOrigin\":{}",
        serde_json::Value::String(kind),
        serde_json::Value::String(b64url_encode(challenge)),
        serde_json::Value::String(origin),
        cross_origin
    );
    if let Some(package) = android_package {
        json.push_str(&format!(
            ",\"androidPackageName\":{}",
            serde_json::Value::String(package)
        ));
    }
    json.push('}');
    json
}

/// The WebAuthn origin Android uses for native apps: `android:apk-key-hash:<b64url(sha256(cert))>`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn android_origin(cert_sha256: Vec<u8>) -> String {
    format!("android:apk-key-hash:{}", b64url_encode(cert_sha256))
}

/// The RP ID must be the origin's host or a registrable suffix of it, and the origin must be secure.
/// Only web origins are accepted; native Android callers use [`assetlinks_allows`].
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn rp_id_valid_for_origin(rp_id: String, origin: String) -> bool {
    let Ok(origin) = Url::parse(&origin) else {
        return false;
    };
    let Some(host) = origin.host_str().map(str::to_ascii_lowercase) else {
        return false;
    };
    let secure = match origin.scheme() {
        "https" => true,
        "http" => host == "localhost" || host.ends_with(".localhost"),
        _ => false,
    };
    let rp_id = rp_id.to_ascii_lowercase();
    if !secure || rp_id.is_empty() {
        return false;
    }
    if host == rp_id {
        return true;
    }
    // An IP address only matches itself: "0.1" is not a registrable suffix of "10.0.0.1".
    if !matches!(origin.host(), Some(url::Host::Domain(_))) {
        return false;
    }
    if !host.ends_with(&format!(".{rp_id}")) {
        return false;
    }
    // The RP ID may not be a public suffix (e.g. "com" or "github.io").
    match psl::domain_str(&rp_id) {
        Some(domain) => rp_id == domain || rp_id.ends_with(&format!(".{domain}")),
        None => false,
    }
}

/// Digital Asset Links check: does `assetlinks.json` (served by the RP) let this Android app
/// use the site's credentials?
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn assetlinks_allows(json: String, package_name: String, cert_sha256: Vec<u8>) -> bool {
    let Ok(serde_json::Value::Array(statements)) = serde_json::from_str::<serde_json::Value>(&json)
    else {
        return false;
    };
    // A SHA-256 digest; anything else (e.g. empty) would match fingerprints that normalise to "".
    if cert_sha256.len() != 32 {
        return false;
    }
    let wanted_cert = crate::encoding::hex(&cert_sha256);
    statements.iter().any(|statement| {
        let relation_ok = statement["relation"].as_array().is_some_and(|relations| {
            relations.iter().any(|r| {
                matches!(
                    r.as_str(),
                    Some(
                        "delegate_permission/common.get_login_creds"
                            | "delegate_permission/common.handle_all_urls"
                    )
                )
            })
        });
        let target = &statement["target"];
        relation_ok
            && target["namespace"] == "android_app"
            && target["package_name"] == package_name.as_str()
            && target["sha256_cert_fingerprints"]
                .as_array()
                .is_some_and(|certs| {
                    certs
                        .iter()
                        .filter_map(|c| c.as_str())
                        .any(|c| normalize_cert(c) == wanted_cert)
                })
    })
}

fn check_hash(hash: &[u8]) -> Result<()> {
    if hash.len() == 32 {
        Ok(())
    } else {
        Err(PassError::InvalidInput(tr!("passkey.bad_request")))
    }
}

fn auth_data_prefix(rp_id: &str, flags: u8, sign_count: u32) -> Vec<u8> {
    let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
    data.push(flags);
    data.extend_from_slice(&sign_count.to_be_bytes());
    data
}

/// COSE_Key for an EC2 P-256 public key in CTAP2 canonical order: {1:2, 3:-7, -1:1, -2:x, -3:y}.
fn cose_es256_key(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut key = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21];
    cbor_bytes(&mut key, x);
    key.push(0x22);
    cbor_bytes(&mut key, y);
    key
}

fn cbor_header(out: &mut Vec<u8>, major: u8, len: usize) {
    let major = major << 5;
    match len {
        0..=23 => out.push(major | len as u8),
        24..=0xff => out.extend_from_slice(&[major | 24, len as u8]),
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        _ => {
            out.push(major | 26);
            out.extend_from_slice(&(len as u32).to_be_bytes());
        }
    }
}

fn cbor_bytes(out: &mut Vec<u8>, data: &[u8]) {
    cbor_header(out, 2, data.len());
    out.extend_from_slice(data);
}

fn cbor_text(out: &mut Vec<u8>, text: &str) {
    cbor_header(out, 3, text.len());
    out.extend_from_slice(text.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rp_id_rules() {
        assert!(rp_id_valid_for_origin(
            "example.com".into(),
            "https://example.com".into()
        ));
        assert!(rp_id_valid_for_origin(
            "example.com".into(),
            "https://login.example.com".into()
        ));
        assert!(!rp_id_valid_for_origin(
            "login.example.com".into(),
            "https://example.com".into()
        ));
        assert!(!rp_id_valid_for_origin(
            "example.com".into(),
            "http://example.com".into()
        ));
        assert!(!rp_id_valid_for_origin(
            "com".into(),
            "https://example.com".into()
        ));
        assert!(!rp_id_valid_for_origin(
            "github.io".into(),
            "https://alice.github.io".into()
        ));
        assert!(!rp_id_valid_for_origin(
            "ample.com".into(),
            "https://example.com".into()
        ));
        assert!(rp_id_valid_for_origin(
            "localhost".into(),
            "http://localhost:8080".into()
        ));
        assert!(!rp_id_valid_for_origin(
            "example.com".into(),
            "android:apk-key-hash:abc".into()
        ));
        // IP origins: the address itself only, never a numeric "suffix".
        assert!(rp_id_valid_for_origin(
            "10.0.0.1".into(),
            "https://10.0.0.1".into()
        ));
        assert!(!rp_id_valid_for_origin(
            "0.1".into(),
            "https://10.0.0.1".into()
        ));
        assert!(!rp_id_valid_for_origin(
            "0.0.1".into(),
            "https://10.0.0.1".into()
        ));
    }

    #[test]
    fn client_data_is_browser_shaped() {
        let json = client_data_json(
            "webauthn.get".into(),
            vec![1, 2, 3],
            "https://a.com".into(),
            false,
            None,
        );
        assert_eq!(
            json,
            r#"{"type":"webauthn.get","challenge":"AQID","origin":"https://a.com","crossOrigin":false}"#
        );
        let json = client_data_json(
            "webauthn.create".into(),
            vec![],
            "android:apk-key-hash:x".into(),
            false,
            Some("com.a".into()),
        );
        assert!(json.ends_with(r#""androidPackageName":"com.a"}"#));
    }

    #[test]
    fn assetlinks() {
        let cert: Vec<u8> = (0..32).map(|i| 0xa0 + i).collect();
        let fingerprint = cert
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        let json = format!(
            r#"[{{"relation":["delegate_permission/common.get_login_creds"],
            "target":{{"namespace":"android_app","package_name":"com.example",
            "sha256_cert_fingerprints":["{fingerprint}"]}}}}]"#
        );
        assert!(assetlinks_allows(
            json.clone(),
            "com.example".into(),
            cert.clone()
        ));
        assert!(!assetlinks_allows(
            json.clone(),
            "com.evil".into(),
            cert.clone()
        ));
        let mut other = cert.clone();
        other[31] ^= 1;
        assert!(!assetlinks_allows(json, "com.example".into(), other));
        // An empty digest must not match a fingerprint that normalises to nothing.
        let junk = r#"[{"relation":["delegate_permission/common.get_login_creds"],
            "target":{"namespace":"android_app","package_name":"com.example",
            "sha256_cert_fingerprints":["zz"]}}]"#;
        assert!(!assetlinks_allows(
            junk.into(),
            "com.example".into(),
            vec![]
        ));
        assert!(!assetlinks_allows(
            "{}".into(),
            "com.example".into(),
            vec![]
        ));
    }
}
