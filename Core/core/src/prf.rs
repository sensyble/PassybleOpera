//! The WebAuthn PRF extension (WebAuthn Level 3 §10.1.4): input `x` gives
//! `HMAC-SHA-256(credRandom, SHA-256("WebAuthn PRF" || 0x00 || x))` with a random 32-byte secret
//! made with the passkey. The secret is a PKCS#8 attribute next to the private key (RFC 5208), so
//! it syncs and merges exactly like the key, and older clients that skip attributes still sign.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::encoding::b64url_encode;
use crate::i18n::tr;
use crate::model::Passkey;
use crate::{PassError, Result};

/// DER of OID 2.25.6552552139013998651363784758755423571 (a UUID OID, X.667:
/// `04edf9c3-63e7-404b-b041-8ab93c5d7553`), Passyble's PKCS#8 attribute for the PRF secret.
/// Fixed forever.
pub const PRF_SECRET_OID: [u8; 21] = [
    0x06, 0x13, 0x69, 0x89, 0xed, 0xfc, 0xf0, 0xec, 0xbe, 0xba, 0x81, 0x97, 0xb0, 0xa0, 0xe2, 0xd7,
    0x93, 0xe2, 0xf5, 0xea, 0x53,
];

/// Length of the secret, of a salt and of an output.
pub const PRF_LEN: usize = 32;

/// The PRF results for one or two inputs.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PrfValues {
    pub first: Vec<u8>,
    pub second: Option<Vec<u8>>,
}

impl std::fmt::Debug for PrfValues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Outputs are key material.
        f.debug_struct("PrfValues")
            .field("second", &self.second.is_some())
            .finish_non_exhaustive()
    }
}

/// One DER TLV at the start of `data`: (tag, contents, the rest). Single-byte tags and definite
/// lengths only.
fn read_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = data.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (&first, mut rest) = rest.split_first()?;
    let len = match first {
        0..=0x7f => first as usize,
        0x81..=0x84 => {
            let n = (first & 0x7f) as usize;
            if rest.len() < n {
                return None;
            }
            let (bytes, after) = rest.split_at(n);
            rest = after;
            bytes.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize)
        }
        _ => return None,
    };
    if rest.len() < len {
        return None;
    }
    let (contents, after) = rest.split_at(len);
    Some((tag, contents, after))
}

fn push_tlv(out: &mut Vec<u8>, tag: u8, contents: &[u8]) {
    out.push(tag);
    let len = contents.len();
    match len {
        0..=0x7f => out.push(len as u8),
        0x80..=0xff => out.extend_from_slice(&[0x81, len as u8]),
        _ => {
            out.push(0x82);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
    }
    out.extend_from_slice(contents);
}

/// `pkcs8` (a `PrivateKeyInfo` without attributes, as p256 writes it) with the PRF secret
/// attribute added. `None` if it isn't such a structure. Only for a passkey being created: two
/// devices adding a secret later could add different ones and change the derived key.
pub(crate) fn pkcs8_with_prf_secret(pkcs8: &[u8], secret: &[u8; PRF_LEN]) -> Option<Vec<u8>> {
    let (tag, contents, rest) = read_tlv(pkcs8)?;
    if tag != 0x30 || !rest.is_empty() {
        return None;
    }
    // version, algorithm, privateKey and nothing else: `attributes [0]` goes after privateKey
    // and before a v2 `publicKey [1]`, so refuse anything with context-specific fields already.
    let mut cur = contents;
    let mut fields = 0;
    while !cur.is_empty() {
        let (t, _, r) = read_tlv(cur)?;
        if t & 0xc0 == 0x80 {
            return None;
        }
        fields += 1;
        cur = r;
    }
    if fields != 3 {
        return None;
    }
    let mut value = Vec::new();
    push_tlv(&mut value, 0x04, secret);
    let mut values = Vec::new();
    push_tlv(&mut values, 0x31, &value);
    let mut attribute = PRF_SECRET_OID.to_vec();
    attribute.extend_from_slice(&values);
    let mut attribute_seq = Vec::new();
    push_tlv(&mut attribute_seq, 0x30, &attribute);
    let mut body = contents.to_vec();
    push_tlv(&mut body, 0xa0, &attribute_seq);
    let mut out = Vec::new();
    push_tlv(&mut out, 0x30, &body);
    Some(out)
}

/// The PRF secret kept in a passkey's PKCS#8, if it has exactly one.
pub(crate) fn pkcs8_prf_secret(pkcs8: &[u8]) -> Option<[u8; PRF_LEN]> {
    let (tag, contents, rest) = read_tlv(pkcs8)?;
    if tag != 0x30 || !rest.is_empty() {
        return None;
    }
    let mut found: Option<[u8; PRF_LEN]> = None;
    let mut cur = contents;
    while !cur.is_empty() {
        let (t, c, r) = read_tlv(cur)?;
        cur = r;
        if t != 0xa0 {
            continue;
        }
        let mut attributes = c;
        while !attributes.is_empty() {
            let (at, ac, ar) = read_tlv(attributes)?;
            attributes = ar;
            if at != 0x30 || !ac.starts_with(&PRF_SECRET_OID) {
                continue;
            }
            let (st, sc, srest) = read_tlv(&ac[PRF_SECRET_OID.len()..])?;
            let (vt, vc, vrest) = read_tlv(sc)?;
            if st != 0x31 || !srest.is_empty() || vt != 0x04 || !vrest.is_empty() {
                return None;
            }
            let secret: [u8; PRF_LEN] = vc.try_into().ok()?;
            if found.is_some() {
                // Two secrets: never guess which one derives the user's key.
                return None;
            }
            found = Some(secret);
        }
    }
    found
}

/// The PRF secret is immutable once made: a passkey in `after` whose match in `before` has a PRF
/// secret gets `before`'s private key back whenever its own differs. No client changes a
/// passkey's key, so this only undoes a bug or a forged copy. Returns whether anything changed.
pub(crate) fn keep_prf_secrets(before: &[Passkey], after: &mut [Passkey]) -> bool {
    let mut restored = false;
    for pk in after.iter_mut() {
        let Some(old) = before
            .iter()
            .find(|old| old.credential_id == pk.credential_id)
        else {
            continue;
        };
        if old.private_key_pkcs8 != pk.private_key_pkcs8
            && pkcs8_prf_secret(&old.private_key_pkcs8).is_some()
        {
            pk.private_key_pkcs8 = old.private_key_pkcs8.clone();
            restored = true;
        }
    }
    restored
}

/// WebAuthn's salt for a PRF input: `SHA-256("WebAuthn PRF" || 0x00 || input)`.
pub fn prf_salt(input: &[u8]) -> [u8; PRF_LEN] {
    let mut h = Sha256::new();
    h.update(b"WebAuthn PRF");
    h.update([0u8]);
    h.update(input);
    h.finalize().into()
}

fn hmac_sha256(key: &[u8; PRF_LEN], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// CTAP2 `hmac-secret` with already-hashed salts: `HMAC-SHA-256(credRandom, salt)`. `None` for a
/// passkey without a PRF secret.
pub fn passkey_hmac_secret(
    passkey: &Passkey,
    salt1: &[u8; PRF_LEN],
    salt2: Option<&[u8; PRF_LEN]>,
) -> Option<PrfValues> {
    let secret = zeroize::Zeroizing::new(pkcs8_prf_secret(&passkey.private_key_pkcs8)?);
    Some(PrfValues {
        first: hmac_sha256(&secret, salt1),
        second: salt2.map(|s| hmac_sha256(&secret, s)),
    })
}

/// Whether the passkey has a PRF secret.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn passkey_prf_available(passkey: Passkey) -> bool {
    pkcs8_prf_secret(&passkey.private_key_pkcs8).is_some()
}

/// Evaluates the passkey's PRF at WebAuthn PRF inputs (`eval.first`, `eval.second` as the site
/// gave them; hashed here with the "WebAuthn PRF" context). `None` for a passkey without a PRF.
/// Only call this after the user approved the sign-in, like `passkey_assert`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn passkey_prf_eval(
    passkey: Passkey,
    first: Vec<u8>,
    second: Option<Vec<u8>>,
) -> Option<PrfValues> {
    let salt2 = second.as_deref().map(prf_salt);
    passkey_hmac_secret(&passkey, &prf_salt(&first), salt2.as_ref())
}

/// Why a request's `prf` input must be refused, as the WebAuthn client would (a `DOMException`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrfRequestError {
    /// `NotSupportedError`: `evalByCredential` at registration, or at authentication without
    /// `allowCredentials`.
    NotSupported,
    /// `SyntaxError`: an `evalByCredential` key that is empty, not base64url or not in
    /// `allowCredentials`; or input that isn't the extension's JSON.
    Syntax,
}

impl PrfRequestError {
    /// The `DOMException` name.
    pub fn dom_name(self) -> &'static str {
        match self {
            PrfRequestError::NotSupported => "NotSupportedError",
            PrfRequestError::Syntax => "SyntaxError",
        }
    }
}

struct PrfInput {
    first: Vec<u8>,
    second: Option<Vec<u8>>,
}

struct PrfInputs {
    eval: Option<PrfInput>,
    /// `evalByCredential` was given (even empty).
    by_credential_present: bool,
    by_credential: Vec<(String, PrfInput)>,
}

fn present(v: Option<&Value>) -> Option<&Value> {
    v.filter(|v| !v.is_null())
}

/// A base64url value of `AuthenticationExtensionsPRFValuesJSON` (padding and the standard
/// alphabet tolerated, as WebAuthn JSON parsers do).
fn binary(v: &Value) -> std::result::Result<Vec<u8>, PrfRequestError> {
    let s = v.as_str().ok_or(PrfRequestError::Syntax)?;
    crate::encoding::b64url_decode(s.to_string()).map_err(|_| PrfRequestError::Syntax)
}

fn values(v: &Value) -> std::result::Result<PrfInput, PrfRequestError> {
    let obj = v.as_object().ok_or(PrfRequestError::Syntax)?;
    let first = binary(present(obj.get("first")).ok_or(PrfRequestError::Syntax)?)?;
    let second = present(obj.get("second")).map(binary).transpose()?;
    Ok(PrfInput { first, second })
}

fn inputs(v: &Value) -> std::result::Result<PrfInputs, PrfRequestError> {
    let empty = Map::new();
    let obj = match v {
        Value::Null => &empty,
        Value::Object(o) => o,
        _ => return Err(PrfRequestError::Syntax),
    };
    let eval = present(obj.get("eval")).map(values).transpose()?;
    let by = present(obj.get("evalByCredential"));
    let by_credential = match by {
        None => Vec::new(),
        Some(Value::Object(m)) => m
            .iter()
            .map(|(k, v)| Ok((k.clone(), values(v)?)))
            .collect::<std::result::Result<_, _>>()?,
        Some(_) => return Err(PrfRequestError::Syntax),
    };
    Ok(PrfInputs {
        eval,
        by_credential_present: by.is_some(),
        by_credential,
    })
}

/// A credential id key of `evalByCredential`: strict base64url (padding ignored), non-empty.
fn credential_key(key: &str) -> Option<Vec<u8>> {
    let trimmed = key.trim_end_matches('=');
    if trimmed.is_empty() {
        return None;
    }
    URL_SAFE_NO_PAD
        .decode(trimmed)
        .ok()
        .filter(|id| !id.is_empty())
}

fn results(values: &PrfValues) -> Value {
    let mut out = Map::new();
    out.insert("first".into(), b64url_encode(values.first.clone()).into());
    if let Some(second) = &values.second {
        out.insert("second".into(), b64url_encode(second.clone()).into());
    }
    Value::Object(out)
}

fn evaluate(passkey: &Passkey, input: &PrfInput) -> Option<PrfValues> {
    passkey_prf_eval(passkey.clone(), input.first.clone(), input.second.clone())
}

/// Registration, client steps 1 (WebAuthn §10.1.4): `evalByCredential` is not allowed.
pub fn prf_registration_check(input: &Value) -> std::result::Result<(), PrfRequestError> {
    if inputs(input)?.by_credential_present {
        return Err(PrfRequestError::NotSupported);
    }
    Ok(())
}

/// The `prf` client extension output of a registration whose request had `prf: input`, for the
/// passkey just created: `{"enabled": true}` and, when `eval` was given, `results` (as platform
/// authenticators do). `enabled` is false for a passkey without a PRF.
pub fn prf_registration_output(
    input: &Value,
    passkey: &Passkey,
) -> std::result::Result<Value, PrfRequestError> {
    prf_registration_check(input)?;
    let parsed = inputs(input)?;
    let enabled = pkcs8_prf_secret(&passkey.private_key_pkcs8).is_some();
    let mut out = json!({ "enabled": enabled });
    if let Some(values) = parsed.eval.as_ref().and_then(|e| evaluate(passkey, e)) {
        out["results"] = results(&values);
    }
    Ok(out)
}

/// Authentication, client steps 1 and 2 (WebAuthn §10.1.4): `evalByCredential` needs `allowCredentials`,
/// and each of its keys must be the base64url id of one of them.
pub fn prf_authentication_check(
    input: &Value,
    allow_credentials: &[Vec<u8>],
) -> std::result::Result<(), PrfRequestError> {
    let parsed = inputs(input)?;
    if !parsed.by_credential.is_empty() && allow_credentials.is_empty() {
        return Err(PrfRequestError::NotSupported);
    }
    for (key, _) in &parsed.by_credential {
        match credential_key(key) {
            Some(id) if allow_credentials.contains(&id) => {}
            _ => return Err(PrfRequestError::Syntax),
        }
    }
    Ok(())
}

/// The `prf` client extension output of an assertion with `passkey` whose request had
/// `prf: input`: `{}`, or `{"results": {"first", "second"?}}` when an input applies to this
/// credential (its `evalByCredential` entry, else `eval`) and the passkey has a PRF.
pub fn prf_authentication_output(
    input: &Value,
    allow_credentials: &[Vec<u8>],
    passkey: &Passkey,
) -> std::result::Result<Value, PrfRequestError> {
    prf_authentication_check(input, allow_credentials)?;
    let parsed = inputs(input)?;
    let chosen = parsed
        .by_credential
        .iter()
        .find(|(key, _)| credential_key(key).as_deref() == Some(passkey.credential_id.as_slice()))
        .map(|(_, v)| v)
        .or(parsed.eval.as_ref());
    let mut out = json!({});
    if let Some(values) = chosen.and_then(|e| evaluate(passkey, e)) {
        out["results"] = results(&values);
    }
    Ok(out)
}

fn parse_json(prf_json: &str) -> std::result::Result<Value, PrfRequestError> {
    serde_json::from_str(prf_json).map_err(|_| PrfRequestError::Syntax)
}

fn bad_request(_: PrfRequestError) -> PassError {
    PassError::InvalidInput(tr!("passkey.bad_request"))
}

/// For apps: `prf_json` is the `extensions.prf` value of a `PublicKeyCredentialCreationOptionsJSON`.
/// The `DOMException` name to fail the registration with (`NotSupportedError`, `SyntaxError`), or
/// `None` when the request is fine. Check before asking the user anything.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn webauthn_prf_create_error(prf_json: String) -> Option<String> {
    parse_json(&prf_json)
        .and_then(|v| prf_registration_check(&v))
        .err()
        .map(|e| e.dom_name().to_string())
}

/// For apps: the `prf` entry of `clientExtensionResults` (JSON) for the passkey just created by
/// a request whose `extensions.prf` was `prf_json`. `InvalidInput` when
/// [`webauthn_prf_create_error`] would name an error.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn webauthn_prf_create_output(prf_json: String, passkey: Passkey) -> Result<String> {
    let input = parse_json(&prf_json).map_err(bad_request)?;
    prf_registration_output(&input, &passkey)
        .map(|v| v.to_string())
        .map_err(bad_request)
}

/// For apps: `prf_json` is the `extensions.prf` value of a `PublicKeyCredentialRequestOptionsJSON`
/// whose `allowCredentials` ids are `allow_credentials`. The `DOMException` name to fail the
/// sign-in with, or `None` when the request is fine. Check before asking the user anything.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn webauthn_prf_get_error(prf_json: String, allow_credentials: Vec<Vec<u8>>) -> Option<String> {
    parse_json(&prf_json)
        .and_then(|v| prf_authentication_check(&v, &allow_credentials))
        .err()
        .map(|e| e.dom_name().to_string())
}

/// For apps: the `prf` entry of `clientExtensionResults` (JSON) for an assertion with `passkey`.
/// Only call this after the user approved the sign-in. `InvalidInput` when
/// [`webauthn_prf_get_error`] would name an error.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn webauthn_prf_get_output(
    prf_json: String,
    allow_credentials: Vec<Vec<u8>>,
    passkey: Passkey,
) -> Result<String> {
    let input = parse_json(&prf_json).map_err(bad_request)?;
    prf_authentication_output(&input, &allow_credentials, &passkey)
        .map(|v| v.to_string())
        .map_err(bad_request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex;
    use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The seed of the WebAuthn Level 3 PRF test vectors (§16.17.1).
    const SEED: &[u8] = b"WebAuthn PRF test vectors";

    fn seeded(byte: u8) -> Vec<u8> {
        let mut v = SEED.to_vec();
        v.push(byte);
        v
    }

    fn spec_cred_random() -> [u8; 32] {
        Sha256::digest(seeded(0x06)).into()
    }

    /// A passkey whose PRF secret is the spec's `authenticator_cred_random`.
    fn spec_passkey() -> Passkey {
        let key = crate::passkey::new_signing_key();
        let der = key.to_pkcs8_der().unwrap().as_bytes().to_vec();
        Passkey {
            credential_id: b"cred-1".to_vec(),
            rp_id: "example.com".into(),
            private_key_pkcs8: pkcs8_with_prf_secret(&der, &spec_cred_random()).unwrap(),
            ..Default::default()
        }
    }

    fn old_passkey() -> Passkey {
        let key = crate::passkey::new_signing_key();
        Passkey {
            credential_id: b"old".to_vec(),
            rp_id: "example.com".into(),
            private_key_pkcs8: key.to_pkcs8_der().unwrap().as_bytes().to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn webauthn_level3_test_vectors() {
        // §16.17.1.2: the inputs, the salts the client computes and the authenticator's outputs.
        assert_eq!(
            hex(&spec_cred_random()),
            "437e065e723a98b2f08f39d8baf7c53ecb3c363c5e5104bdaaf5d5ca2e028154"
        );
        let first = seeded(0x02);
        let second = seeded(0x03);
        assert_eq!(
            hex(&first),
            "576562417574686e20505246207465737420766563746f727302"
        );
        assert_eq!(
            hex(&prf_salt(&first)),
            "527413ebb48293772df30f031c5ac4650c7de14bf9498671ae163447b6a772b3"
        );
        assert_eq!(
            hex(&prf_salt(&second)),
            "d68ac03329a10ee5e0ec834492bb9a96a0e547baf563bf78ccbe8789b22e776b"
        );
        let out = passkey_prf_eval(spec_passkey(), first.clone(), Some(second)).unwrap();
        assert_eq!(
            hex(&out.first),
            "3c33e07d202c3b029cc21f1722767021bf27d595933b3d2b6a1b9d5dddc77fae"
        );
        assert_eq!(
            hex(out.second.as_ref().unwrap()),
            "a62a8773b19cda90d7ed4ef72a80a804320dbd3997e2f663805ad1fd3293d50b"
        );
        let single = passkey_prf_eval(spec_passkey(), first, None).unwrap();
        assert_eq!(single.first, out.first);
        assert_eq!(single.second, None);
        // The CTAP-level entry point takes the salts as they are.
        let salt: [u8; 32] =
            unhex("527413ebb48293772df30f031c5ac4650c7de14bf9498671ae163447b6a772b3")
                .try_into()
                .unwrap();
        assert_eq!(
            passkey_hmac_secret(&spec_passkey(), &salt, None)
                .unwrap()
                .first,
            out.first
        );
    }

    #[test]
    fn independent_known_answer() {
        // HMAC-SHA-256 and SHA-256 by a second route (RFC 4231 test case 2 checks the HMAC).
        let mut mac = Hmac::<Sha256>::new_from_slice(b"Jefe").unwrap();
        mac.update(b"what do ya want for nothing?");
        assert_eq!(
            hex(&mac.finalize().into_bytes()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // An all-zero secret and the empty input, computed independently (Python hashlib/hmac).
        let key = crate::passkey::new_signing_key();
        let der = key.to_pkcs8_der().unwrap().as_bytes().to_vec();
        let pk = Passkey {
            private_key_pkcs8: pkcs8_with_prf_secret(&der, &[0u8; 32]).unwrap(),
            ..Default::default()
        };
        assert_eq!(
            hex(&prf_salt(b"")),
            "6a7e64b2aa34c92736143a062fa149aff1bd8bb3f7ee6f346885481f9414a3d3"
        );
        assert_eq!(
            hex(&passkey_prf_eval(pk, vec![], None).unwrap().first),
            "1f798e25a2b73774247bc031549d5ec36f7e6536695ddd848a852332ab1b1a2f"
        );
    }

    #[test]
    fn the_secret_lives_in_the_pkcs8_and_signing_still_works() {
        let pk = spec_passkey();
        assert!(passkey_prf_available(pk.clone()));
        assert_eq!(
            pkcs8_prf_secret(&pk.private_key_pkcs8),
            Some(spec_cred_random())
        );
        // The same decoder every shipped client signs with.
        let key = p256::ecdsa::SigningKey::from_pkcs8_der(&pk.private_key_pkcs8).unwrap();
        let plain = key.to_pkcs8_der().unwrap();
        assert!(pk.private_key_pkcs8.starts_with(&[0x30]));
        assert!(pk.private_key_pkcs8.len() > plain.as_bytes().len());
        // A key without the attribute has no PRF; adding one twice is refused.
        assert_eq!(pkcs8_prf_secret(plain.as_bytes()), None);
        assert!(!passkey_prf_available(old_passkey()));
        assert_eq!(passkey_prf_eval(old_passkey(), vec![1], None), None);
        assert_eq!(pkcs8_with_prf_secret(&pk.private_key_pkcs8, &[1; 32]), None);
        // Garbage and truncation never panic and never yield a secret.
        for n in 0..pk.private_key_pkcs8.len() {
            assert_eq!(pkcs8_prf_secret(&pk.private_key_pkcs8[..n]), None);
        }
        assert_eq!(pkcs8_prf_secret(b"PRIVATE-KEY"), None);
        assert_eq!(pkcs8_prf_secret(&[]), None);
    }

    #[test]
    fn two_secrets_are_ambiguous() {
        // Hand-made: the attribute twice. Never pick one.
        let pk = spec_passkey();
        let (_, contents, _) = read_tlv(&pk.private_key_pkcs8).unwrap();
        let mut cur = contents;
        let mut body = Vec::new();
        let mut attrs = Vec::new();
        while !cur.is_empty() {
            let (t, c, r) = read_tlv(cur).unwrap();
            if t == 0xa0 {
                attrs = c.to_vec();
            } else {
                push_tlv(&mut body, t, c);
            }
            cur = r;
        }
        let doubled = [attrs.clone(), attrs].concat();
        push_tlv(&mut body, 0xa0, &doubled);
        let mut der = Vec::new();
        push_tlv(&mut der, 0x30, &body);
        assert_eq!(pkcs8_prf_secret(&der), None);
        assert!(p256::ecdsa::SigningKey::from_pkcs8_der(&der).is_ok());
    }

    fn b64u(data: &[u8]) -> String {
        b64url_encode(data.to_vec())
    }

    #[test]
    fn registration_outputs() {
        let pk = spec_passkey();
        let out = prf_registration_output(&json!({}), &pk).unwrap();
        assert_eq!(out, json!({ "enabled": true }));
        let out = prf_registration_output(&Value::Null, &pk).unwrap();
        assert_eq!(out, json!({ "enabled": true }));
        let first = seeded(0x02);
        let out =
            prf_registration_output(&json!({ "eval": { "first": b64u(&first) } }), &pk).unwrap();
        assert_eq!(out["enabled"], true);
        assert_eq!(
            out["results"]["first"],
            b64u(&unhex(
                "3c33e07d202c3b029cc21f1722767021bf27d595933b3d2b6a1b9d5dddc77fae"
            ))
        );
        assert!(out["results"].get("second").is_none());
        // A passkey without a PRF: enabled false, no results.
        let out = prf_registration_output(&json!({ "eval": { "first": "AQID" } }), &old_passkey())
            .unwrap();
        assert_eq!(out, json!({ "enabled": false }));
        // evalByCredential is for assertions only.
        assert_eq!(
            prf_registration_check(&json!({ "evalByCredential": {} })),
            Err(PrfRequestError::NotSupported)
        );
        assert_eq!(
            prf_registration_check(&json!({ "eval": { "first": "not base64!" } })),
            Err(PrfRequestError::Syntax)
        );
        assert_eq!(
            prf_registration_check(&json!({ "eval": {} })),
            Err(PrfRequestError::Syntax)
        );
        assert_eq!(
            prf_registration_check(&json!("x")),
            Err(PrfRequestError::Syntax)
        );
        assert_eq!(
            prf_registration_check(&json!({ "eval": null, "evalByCredential": null })),
            Ok(())
        );
    }

    #[test]
    fn authentication_outputs() {
        let pk = spec_passkey();
        let other = b"cred-2".to_vec();
        let allow = vec![pk.credential_id.clone(), other.clone()];
        let first = seeded(0x02);
        let second = seeded(0x03);
        let r1 = b64u(&unhex(
            "3c33e07d202c3b029cc21f1722767021bf27d595933b3d2b6a1b9d5dddc77fae",
        ));
        let r2 = b64u(&unhex(
            "a62a8773b19cda90d7ed4ef72a80a804320dbd3997e2f663805ad1fd3293d50b",
        ));
        // No input: an empty output.
        assert_eq!(
            prf_authentication_output(&json!({}), &[], &pk).unwrap(),
            json!({})
        );
        // eval with two inputs.
        let input = json!({ "eval": { "first": b64u(&first), "second": b64u(&second) } });
        assert_eq!(
            prf_authentication_output(&input, &[], &pk).unwrap(),
            json!({ "results": { "first": r1, "second": r2 } })
        );
        // evalByCredential wins over eval for its credential; eval for the others.
        let input = json!({
            "eval": { "first": b64u(&second) },
            "evalByCredential": {
                b64u(&pk.credential_id): { "first": b64u(&first) },
                b64u(&other): { "first": "AQID" },
            }
        });
        assert_eq!(
            prf_authentication_output(&input, &allow, &pk).unwrap(),
            json!({ "results": { "first": r1 } })
        );
        let input = json!({
            "eval": { "first": b64u(&second) },
            "evalByCredential": { b64u(&other): { "first": "AQID" } }
        });
        assert_eq!(
            prf_authentication_output(&input, &allow, &pk).unwrap(),
            json!({ "results": { "first": r2 } })
        );
        // Only evalByCredential, for another credential: nothing.
        let input = json!({ "evalByCredential": { b64u(&other): { "first": "AQID" } } });
        assert_eq!(
            prf_authentication_output(&input, &allow, &pk).unwrap(),
            json!({})
        );
        // A passkey without a PRF: no results, never an error.
        let input = json!({ "eval": { "first": "AQID" } });
        assert_eq!(
            prf_authentication_output(&input, &[], &old_passkey()).unwrap(),
            json!({})
        );
    }

    #[test]
    fn eval_by_credential_keys_are_validated() {
        let id = b"cred-1".to_vec();
        let entry = json!({ "first": "AQID" });
        let with_key = |key: &str| json!({ "evalByCredential": { key: entry.clone() } });
        // Without allowCredentials.
        assert_eq!(
            prf_authentication_check(&with_key(&b64u(&id)), &[]),
            Err(PrfRequestError::NotSupported)
        );
        // Empty evalByCredential is fine without allowCredentials.
        assert_eq!(
            prf_authentication_check(&json!({ "evalByCredential": {} }), &[]),
            Ok(())
        );
        let allow = vec![id.clone()];
        assert_eq!(
            prf_authentication_check(&with_key(&b64u(&id)), &allow),
            Ok(())
        );
        // Padding is ignored.
        assert_eq!(
            prf_authentication_check(&with_key(&format!("{}==", b64u(&id))), &allow),
            Ok(())
        );
        for bad in ["", "=", "not base64!", "Y3JlZC0y", "Y3J+ZC0x", "Y3J/ZC0x"] {
            assert_eq!(
                prf_authentication_check(&with_key(bad), &allow),
                Err(PrfRequestError::Syntax),
                "{bad:?}"
            );
        }
        assert_eq!(
            prf_authentication_check(&json!({ "evalByCredential": [] }), &allow),
            Err(PrfRequestError::Syntax)
        );
    }

    #[test]
    fn app_wrappers() {
        let pk = spec_passkey();
        assert_eq!(webauthn_prf_create_error("{}".into()), None);
        assert_eq!(
            webauthn_prf_create_error(r#"{"evalByCredential":{}}"#.into()).as_deref(),
            Some("NotSupportedError")
        );
        assert_eq!(
            webauthn_prf_create_error("not json".into()).as_deref(),
            Some("SyntaxError")
        );
        assert_eq!(
            webauthn_prf_create_output("{}".into(), pk.clone()).unwrap(),
            r#"{"enabled":true}"#
        );
        assert!(
            webauthn_prf_create_output(r#"{"evalByCredential":{}}"#.into(), pk.clone()).is_err()
        );
        assert_eq!(
            webauthn_prf_get_error(r#"{"evalByCredential":{"AQ":{"first":""}}}"#.into(), vec![])
                .as_deref(),
            Some("NotSupportedError")
        );
        assert_eq!(
            webauthn_prf_get_error(
                r#"{"evalByCredential":{"AQ":{"first":""}}}"#.into(),
                vec![vec![2]]
            )
            .as_deref(),
            Some("SyntaxError")
        );
        assert_eq!(
            webauthn_prf_get_output("{}".into(), vec![], pk).unwrap(),
            "{}"
        );
    }
}
