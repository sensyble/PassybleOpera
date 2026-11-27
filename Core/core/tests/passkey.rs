use ciborium::value::Value;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use pass_core::*;
use sha2::Digest;

fn map_get<'a>(map: &'a [(Value, Value)], key: &Value) -> &'a Value {
    &map.iter().find(|(k, _)| k == key).expect("key present").1
}

#[test]
fn registration_and_assertion_verify_like_a_relying_party() {
    let client_data = client_data_json(
        "webauthn.create".into(),
        vec![42; 32],
        "https://example.com".into(),
        false,
        None,
    );
    let created = passkey_create(
        "example.com".into(),
        Some("Example".into()),
        b"user-1".to_vec(),
        "alice".into(),
        "Alice".into(),
        sha256(client_data.into_bytes()),
        vec![-7],
    )
    .unwrap();

    // Attestation object: {"fmt": "none", "attStmt": {}, "authData": bytes}
    let att: Value = ciborium::from_reader(created.attestation_object.as_slice()).unwrap();
    let att = att.as_map().unwrap();
    assert_eq!(
        map_get(att, &Value::Text("fmt".into())),
        &Value::Text("none".into())
    );
    assert_eq!(
        map_get(att, &Value::Text("attStmt".into())),
        &Value::Map(vec![])
    );
    let auth_data = map_get(att, &Value::Text("authData".into()))
        .as_bytes()
        .unwrap()
        .clone();
    assert_eq!(auth_data, created.authenticator_data);

    assert_eq!(
        &auth_data[..32],
        sha2::Sha256::digest(b"example.com").as_slice()
    );
    let flags = auth_data[32];
    assert_eq!(flags & 0x01, 0x01, "UP");
    assert_eq!(flags & 0x04, 0x04, "UV");
    assert_eq!(flags & 0x18, 0x18, "BE+BS");
    assert_eq!(flags & 0x40, 0x40, "AT");
    assert_eq!(&auth_data[37..53], &AAGUID);
    let id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    assert_eq!(
        &auth_data[55..55 + id_len],
        created.credential_id.as_slice()
    );

    // COSE key matches the SPKI public key
    let cose: Value = ciborium::from_reader(&auth_data[55 + id_len..]).unwrap();
    let cose = cose.as_map().unwrap();
    assert_eq!(
        map_get(cose, &Value::Integer(1.into())),
        &Value::Integer(2.into())
    );
    assert_eq!(
        map_get(cose, &Value::Integer(3.into())),
        &Value::Integer((-7).into())
    );
    let x = map_get(cose, &Value::Integer((-2).into()))
        .as_bytes()
        .unwrap();
    let y = map_get(cose, &Value::Integer((-3).into()))
        .as_bytes()
        .unwrap();
    let spki_key = VerifyingKey::from_public_key_der(&created.public_key_spki).unwrap();
    let point = spki_key.to_sec1_point(false);
    assert_eq!(point.x().unwrap().as_slice(), x.as_slice());
    assert_eq!(point.y().unwrap().as_slice(), y.as_slice());

    // Assertion signature verifies with the registered key.
    let client_data = client_data_json(
        "webauthn.get".into(),
        vec![7; 32],
        "https://example.com".into(),
        false,
        None,
    );
    let hash = sha256(client_data.into_bytes());
    let assertion = passkey_assert(created.passkey.clone(), hash.clone(), true).unwrap();
    assert_eq!(assertion.credential_id, created.credential_id);
    assert_eq!(assertion.user_handle, b"user-1");
    assert_eq!(assertion.authenticator_data.len(), 37);
    assert_eq!(
        assertion.authenticator_data[32] & 0x40,
        0,
        "no attested data in assertions"
    );
    let mut signed = assertion.authenticator_data.clone();
    signed.extend_from_slice(&hash);
    let signature = Signature::from_der(&assertion.signature).unwrap();
    spki_key
        .verify(&signed, &signature)
        .expect("signature verifies");

    let not_verified = passkey_assert(created.passkey, hash, false).unwrap();
    assert_eq!(not_verified.authenticator_data[32] & 0x04, 0);
}

#[test]
fn rejects_unsupported_requests() {
    let hash = vec![0; 32];
    assert!(passkey_create(
        "a.com".into(),
        None,
        vec![1],
        "u".into(),
        "u".into(),
        hash.clone(),
        vec![-257]
    )
    .is_err());
    assert!(passkey_create(
        "a.com".into(),
        None,
        vec![1],
        "u".into(),
        "u".into(),
        vec![0; 31],
        vec![]
    )
    .is_err());
    assert!(passkey_create(
        "a.com".into(),
        None,
        vec![],
        "u".into(),
        "u".into(),
        hash,
        vec![]
    )
    .is_err());
}

#[test]
fn android_origin_format() {
    assert_eq!(android_origin(vec![0xfb; 4]), "android:apk-key-hash:-_v7-w");
}

fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// A fixed P-256 key as p256 0.13 wrote it into vaults: PKCS#8 private key, its
/// SubjectPublicKeyInfo, and the RFC 6979 (deterministic) signature it made over `FIXED_MESSAGE`.
/// Every passkey already saved in a vault is in this format.
const FIXED_PKCS8: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104200b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186a144034200049ed4fbadf89bb1cd3cbdd03737c6b55eb21667ef44baba27dca0daaa8527f1c03c52e145bc96ba39bc898fd2bc041afde2fb6c995555554cc3a4e2f2cafe58fc";
const FIXED_SPKI: &str = "3059301306072a8648ce3d020106082a8648ce3d030107034200049ed4fbadf89bb1cd3cbdd03737c6b55eb21667ef44baba27dca0daaa8527f1c03c52e145bc96ba39bc898fd2bc041afde2fb6c995555554cc3a4e2f2cafe58fc";
const FIXED_MESSAGE: &[u8] = b"passyble fixed passkey test message";
const FIXED_SIGNATURE: &str = "3045022100b9981873fff155d4ebc6523c5d3cd9dc3de0ce54be0d9be642a1b0c78d89932202207ae0ce9daec5737b999cace0b8093304f56e30e311dbd6d1786a272bdb3530c9";

#[test]
fn a_saved_passkey_still_signs_and_verifies_against_its_fixed_key() {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};

    let pkcs8 = from_hex(FIXED_PKCS8);
    let spki = from_hex(FIXED_SPKI);
    let public = VerifyingKey::from_public_key_der(&spki).unwrap();

    // The stored key loads, re-encodes to the same bytes and has the same public key.
    let key = SigningKey::from_pkcs8_der(&pkcs8).unwrap();
    assert_eq!(key.to_pkcs8_der().unwrap().as_bytes(), pkcs8.as_slice());
    assert_eq!(
        key.verifying_key().to_public_key_der().unwrap().as_bytes(),
        spki.as_slice()
    );

    // The 0.13 signature still verifies, and signing is still deterministic.
    let old = Signature::from_der(&from_hex(FIXED_SIGNATURE)).unwrap();
    public.verify(FIXED_MESSAGE, &old).unwrap();
    let again: Signature = key.sign(FIXED_MESSAGE);
    assert_eq!(again.to_der().as_bytes(), from_hex(FIXED_SIGNATURE).as_slice());

    // A WebAuthn assertion from the saved passkey verifies against the fixed public key.
    let passkey = Passkey {
        credential_id: vec![1; 16],
        rp_id: "example.com".into(),
        rp_name: Some("Example".into()),
        user_handle: b"user-1".to_vec(),
        user_name: "demo@example.com".into(),
        user_display_name: "Demo".into(),
        private_key_pkcs8: pkcs8.clone(),
        sign_count: 0,
        discoverable: true,
        created_at: 0,
    };
    let hash = sha256(b"client data".to_vec());
    let assertion = passkey_assert(passkey, hash.clone(), true).unwrap();
    let mut signed = assertion.authenticator_data.clone();
    signed.extend_from_slice(&hash);
    let signature = Signature::from_der(&assertion.signature).unwrap();
    public.verify(&signed, &signature).unwrap();
    signed[0] ^= 1;
    assert!(public.verify(&signed, &signature).is_err());
}
