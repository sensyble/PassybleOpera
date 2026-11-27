//! The Passyble password, the Secret Key and the account key (AK).
//!
//! The password and a random per-device Secret Key derive the sign-in key and the key that wraps AK,
//! so the service, which keeps only public keys and wrapped blobs, can't test a password guess.

use std::sync::Arc;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::crypto::{self, Key, KEY_LEN, NONCE_LEN};
use crate::encoding::{b64url_decode, b64url_encode};
use crate::i18n::tr;
use crate::server_auth::hkdf_sha256;
use crate::share::keys::{hpke_keypair, hpke_open, hpke_public_of, hpke_seal, valid_enc_pub, KEY_BYTES};
use crate::vault::KdfParams;
use crate::{PassError, Result};

/// The longest Passyble password, in characters (after NFC).
pub const ACCOUNT_PASSWORD_MAX_CHARS: u32 = 128;

const MASTER_INFO: &[u8] = b"passyble-account-master/v1";
const AUTH_INFO: &[u8] = b"passyble-account-auth/v1";
const WRAP_INFO: &[u8] = b"passyble-account-wrap/v1";
const PRF_INFO: &[u8] = b"pass/ak-prf/v1";
const RECOVERY_INFO: &[u8] = b"pass/ak-recovery/v1";
const RECOVERY_SIGN_INFO: &[u8] = b"pass/recovery-sign/v1";
const SK_WRAP_INFO: &[u8] = b"pass/sk-wrap/v1";
const AK_SIGN_INFO: &[u8] = b"pass/ak-sign/v1";
/// The Secret Key's checksum domain (the recovery code's is `recovery::RECOVERY_DOMAIN`).
const SECRET_KEY_DOMAIN: &[u8] = b"pass/secret-key/v1:";
/// The written Secret Key starts with this (its format version).
const SECRET_KEY_PREFIX: &str = "P1";
/// Bytes of a Secret Key (the recovery code's secret length).
const SECRET_KEY_LEN: usize = crate::recovery::SECRET_LEN;

/// Client bounds of the account's Argon2id parameters. The lower bound (the vault default) stops a
/// hostile service from making guessing cheap for someone who also holds the Secret Key; the upper
/// bound stops it from making the device allocate gigabytes.
const MIN_M_KIB: u32 = 64 * 1024;
const MAX_M_KIB: u32 = 1024 * 1024;
const MIN_T: u32 = 3;
const MAX_T: u32 = 20;
const MAX_P: u32 = 16;

/// Salt length bounds, in bytes.
const MIN_SALT: usize = 16;
const MAX_SALT: usize = 64;

/// Bytes of the random values each side of a device approval adds.
const APPROVAL_NONCE_LEN: usize = 32;

/// Argon2id parameters of the Passyble password (the salt travels separately).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AccountKdf {
    pub alg: String,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for AccountKdf {
    /// The vault default: 64 MiB, 3 passes, 1 lane (also the lowest the apps accept).
    fn default() -> Self {
        Self {
            alg: "argon2id".into(),
            m_kib: MIN_M_KIB,
            t: MIN_T,
            p: 1,
        }
    }
}

impl AccountKdf {
    pub(crate) fn check(&self) -> Result<()> {
        let ok = self.alg == "argon2id"
            && (MIN_M_KIB..=MAX_M_KIB).contains(&self.m_kib)
            && (MIN_T..=MAX_T).contains(&self.t)
            && (1..=MAX_P).contains(&self.p);
        if ok {
            Ok(())
        } else {
            Err(PassError::Crypto(tr!("account_key.unsafe_parameters")))
        }
    }
}

/// A key wrapped with XChaCha20-Poly1305: the nonce and the ciphertext, base64url.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AccountWrap {
    pub nonce: String,
    pub ct: String,
}

/// The account key and the Secret Key sealed to a new device's one-time X25519 key (HPKE, base
/// mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305): the encapsulated key and the
/// ciphertext, base64url.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SealedAccountKey {
    pub enc: String,
    pub ct: String,
}

/// A new recovery code ([`AccountKey::new_recovery`]). Show `code` once (in the Emergency Kit) and
/// upload the rest; the code itself is never stored anywhere.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AccountRecovery {
    /// `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`, the format of vault recovery codes.
    pub code: String,
    /// Names this code; a new code gets a new id.
    pub rec_id: String,
    /// Ed25519 public key (base64url) of the key the code derives: the service checks a reset's
    /// signature with it ([`account_recovery_sign`]).
    pub verify_pub: String,
    /// AK wrapped by the code. The same bytes go into every linked vault header.
    pub wrap: AccountWrap,
}

/// Never the code in debug output.
impl std::fmt::Debug for AccountRecovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountRecovery")
            .field("rec_id", &self.rec_id)
            .field("verify_pub", &self.verify_pub)
            .finish_non_exhaustive()
    }
}

fn internal() -> PassError {
    PassError::Crypto(tr!("error.internal"))
}

fn damaged() -> PassError {
    PassError::InvalidInput(tr!("encoding.damaged"))
}

pub(crate) fn json_tail(prefix: &[u8], value: &impl Serialize) -> Result<Vec<u8>> {
    let mut out = prefix.to_vec();
    out.extend(serde_json::to_vec(value).map_err(|_| internal())?);
    Ok(out)
}

fn decode_fixed<const N: usize>(b64: &str) -> Result<Zeroizing<[u8; N]>> {
    let bytes = Zeroizing::new(b64url_decode(b64.to_string())?);
    let mut out = Zeroizing::new([0u8; N]);
    if bytes.len() != N {
        return Err(damaged());
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn check_account(account: &str) -> Result<()> {
    if account.is_empty() || account.len() > 254 || account.chars().any(char::is_control) {
        return Err(PassError::InvalidInput(tr!("share.bad_account")));
    }
    Ok(())
}

fn salt_bytes(salt: &str) -> Result<Vec<u8>> {
    let bytes = b64url_decode(salt.to_string())?;
    if !(MIN_SALT..=MAX_SALT).contains(&bytes.len()) {
        return Err(PassError::Crypto(tr!("account_key.invalid_salt")));
    }
    Ok(bytes)
}

/// HKDF-SHA256 (RFC 5869) with `salt` and one 32-byte output block.
fn hkdf_salted(salt: &[u8], ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut extract = <Hmac<Sha256> as Mac>::new_from_slice(salt).expect("any key length");
    extract.update(ikm);
    let prk: Zeroizing<[u8; 32]> = Zeroizing::new(extract.finalize().into_bytes().into());
    let mut expand = <Hmac<Sha256> as Mac>::new_from_slice(&prk[..]).expect("any key length");
    expand.update(info);
    expand.update(&[1]);
    Zeroizing::new(expand.finalize().into_bytes().into())
}

fn seal_wrap(key: &[u8; KEY_LEN], plain: &[u8], aad: &[u8]) -> Result<AccountWrap> {
    let (nonce, ct) = crypto::seal(key, plain, aad)?;
    Ok(AccountWrap {
        nonce: b64url_encode(nonce.to_vec()),
        ct: b64url_encode(ct),
    })
}

/// Opens a wrap; `None` if it doesn't open (wrong key, another account, damaged).
fn open_wrap_bytes(key: &[u8; KEY_LEN], wrap: &AccountWrap, aad: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let nonce = b64url_decode(wrap.nonce.clone()).ok()?;
    let ct = b64url_decode(wrap.ct.clone()).ok()?;
    if nonce.len() != NONCE_LEN {
        return None;
    }
    crypto::open(key, &nonce, &ct, aad)
}

fn open_wrap(key: &[u8; KEY_LEN], wrap: &AccountWrap, aad: &[u8]) -> Option<Key> {
    Key::from_slice(&open_wrap_bytes(key, wrap, aad)?)
}

/// `ak_id`: base64url of the first 16 bytes of HMAC-SHA256(AK, `"pass/ak-id/v1:" + account`).
pub(crate) fn ak_id_of(ak: &[u8], account: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(ak).expect("any key length");
    mac.update(b"pass/ak-id/v1:");
    mac.update(account.as_bytes());
    b64url_encode(mac.finalize().into_bytes()[..16].to_vec())
}

/// NFC of `password`: the same password typed on Windows, Android and iOS keyboards gives the same
/// bytes. Refuses an empty password and one over [`ACCOUNT_PASSWORD_MAX_CHARS`].
pub(crate) fn normalize_password(password: &str) -> Result<Zeroizing<String>> {
    let normalized = Zeroizing::new(password.nfc().collect::<String>());
    if normalized.is_empty() {
        return Err(PassError::InvalidInput(tr!("server.empty_password")));
    }
    if normalized.chars().count() as u32 > ACCOUNT_PASSWORD_MAX_CHARS {
        return Err(PassError::InvalidInput(tr!(
            "account_key.password_too_long",
            max = ACCOUNT_PASSWORD_MAX_CHARS
        )));
    }
    Ok(normalized)
}

fn signing_key(seed: &[u8; 32]) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(seed)
}

fn sign_b64(key: &ed25519_dalek::SigningKey, msg: &[u8]) -> String {
    use ed25519_dalek::Signer;
    b64url_encode(key.sign(msg).to_bytes().to_vec())
}

fn public_b64(key: &ed25519_dalek::SigningKey) -> String {
    b64url_encode(key.verifying_key().to_bytes().to_vec())
}

/// Whether `sig` (base64url) is a valid strict Ed25519 signature of `msg` by `public` (base64url).
fn verify_b64(public: &str, msg: &[u8], sig: &str) -> bool {
    let (Ok(public), Ok(sig)) = (decode_fixed::<32>(public), decode_fixed::<64>(sig)) else {
        return false;
    };
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&public) else {
        return false;
    };
    key.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sig))
        .is_ok()
}

/// The Secret Key: 128 random bits made on the device at sign-up, mixed into the password's key
/// derivation and never sent. Written `P1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`, with the recovery
/// code's alphabet and checksum in a separate domain so the two are never confused. Useless without
/// the password, so it sits in the OS keychain without a gesture.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct SecretKey {
    secret: Zeroizing<[u8; SECRET_KEY_LEN]>,
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKey").finish_non_exhaustive()
    }
}

impl SecretKey {
    pub(crate) fn bytes(&self) -> &[u8; SECRET_KEY_LEN] {
        &self.secret
    }

    fn from_array(secret: [u8; SECRET_KEY_LEN]) -> SecretKey {
        SecretKey {
            secret: Zeroizing::new(secret),
        }
    }

    /// Reads a written Secret Key: case, spaces and dashes don't matter, the `P1` prefix may be
    /// left out. A recovery code typed here is named as such.
    pub fn read(text: &str) -> Result<SecretKey> {
        let compact: Zeroizing<String> = Zeroizing::new(
            text.chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .collect::<String>()
                .to_ascii_uppercase(),
        );
        let body = compact.strip_prefix(SECRET_KEY_PREFIX).unwrap_or(&compact);
        match crate::recovery::decode_in(SECRET_KEY_DOMAIN, body) {
            Ok(secret) => Ok(SecretKey::from_array(*secret)),
            Err(e) => {
                if crate::recovery::decode(body).is_ok() {
                    Err(PassError::InvalidInput(tr!("account_key.recovery_code_not_secret_key")))
                } else {
                    Err(e)
                }
            }
        }
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl SecretKey {
    /// A new random Secret Key (sign-up, "New Secret Key", an e-mail reset, after admin recovery).
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn generate() -> Arc<SecretKey> {
        Arc::new(SecretKey::from_array(crypto::random_bytes::<SECRET_KEY_LEN>()))
    }

    /// [`SecretKey::read`]: typed, pasted, or from the Emergency Kit's QR.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn parse(text: String) -> Result<Arc<SecretKey>> {
        let text = Zeroizing::new(text);
        Ok(Arc::new(SecretKey::read(&text)?))
    }

    /// `P1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`: for the Emergency Kit and the OS keychain.
    pub fn text(&self) -> String {
        format!(
            "{SECRET_KEY_PREFIX}-{}",
            crate::recovery::encode_in(SECRET_KEY_DOMAIN, &self.secret).as_str()
        )
    }
}

/// Whether `text` is a well-formed Secret Key, for checking the input as the user types.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn secret_key_valid_format(text: String) -> bool {
    SecretKey::read(&text).is_ok()
}

/// What the Passyble password and the Secret Key derive for one account: the sign-in key (its
/// public half goes to the account service) and `wrap_key` (opens the password wrap of AK), with
/// the salt and parameters they came from.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct AccountPassword {
    auth: ed25519_dalek::SigningKey,
    wrap_key: Key,
    salt: String,
    kdf: AccountKdf,
}

impl std::fmt::Debug for AccountPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountPassword")
            .field("salt", &self.salt)
            .field("kdf", &self.kdf)
            .finish_non_exhaustive()
    }
}

impl AccountPassword {
    /// Derives both keys (one Argon2id run) for `password` and `secret_key` with the account's
    /// base64url `salt` and `kdf` from the account service's prelogin.
    pub fn derive(
        password: &str,
        secret_key: &SecretKey,
        salt: &str,
        kdf: &AccountKdf,
    ) -> Result<AccountPassword> {
        kdf.check()?;
        let salt_raw = salt_bytes(salt)?;
        let password = normalize_password(password)?;
        let params = KdfParams {
            alg: kdf.alg.clone(),
            m_kib: kdf.m_kib,
            t: kdf.t,
            p: kdf.p,
            salt: String::new(),
        };
        let pw_key = crypto::derive_kek_bytes(password.as_bytes(), &params, &salt_raw)?;
        let master = hkdf_salted(secret_key.bytes(), pw_key.as_slice(), MASTER_INFO);
        let auth = signing_key(&hkdf_sha256(master.as_slice(), AUTH_INFO));
        let wrap_key = Key::from_array(*hkdf_sha256(master.as_slice(), WRAP_INFO));
        Ok(AccountPassword {
            auth,
            wrap_key,
            salt: b64url_encode(salt_raw),
            kdf: kdf.clone(),
        })
    }

    /// AAD of the password wrap: `"pass/ak-pw/v1:" + JSON[account, ak_id, salt, kdf]`.
    fn wrap_aad(&self, account: &str, ak_id: &str) -> Result<Vec<u8>> {
        json_tail(b"pass/ak-pw/v1:", &(account, ak_id, &self.salt, &self.kdf))
    }
}

/// What a sign-in signs: `"pass/sign-in/v1:" + JSON[email, nonce, device_name, platform]`.
pub(crate) fn sign_in_message(
    email: &str,
    nonce: &str,
    device_name: &str,
    platform: &str,
) -> Result<Vec<u8>> {
    json_tail(b"pass/sign-in/v1:", &(email, nonce, device_name, platform))
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl AccountPassword {
    /// [`AccountPassword::derive`]: for signing in, with the salt and parameters of the account.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new(
        password: String,
        secret_key: &SecretKey,
        salt: String,
        kdf: AccountKdf,
    ) -> Result<Arc<AccountPassword>> {
        let password = Zeroizing::new(password);
        Ok(Arc::new(Self::derive(&password, secret_key, &salt, &kdf)?))
    }

    /// For a new password (sign-up, a password change, a reset): a fresh random salt and the
    /// default parameters (or stronger ones the user chose, never weaker).
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn with_new_salt(
        password: String,
        secret_key: &SecretKey,
        kdf: Option<AccountKdf>,
    ) -> Result<Arc<AccountPassword>> {
        let password = Zeroizing::new(password);
        let salt = b64url_encode(crypto::random_bytes::<16>().to_vec());
        Ok(Arc::new(Self::derive(
            &password,
            secret_key,
            &salt,
            &kdf.unwrap_or_default(),
        )?))
    }

    /// The base64url Ed25519 public key the account service keeps to check sign-ins.
    pub fn auth_pub(&self) -> String {
        public_b64(&self.auth)
    }

    /// Signs the account service's sign-in `nonce` (from prelogin): base64url Ed25519 signature
    /// over `"pass/sign-in/v1:" + JSON[email, nonce, device_name, platform]`.
    pub fn sign_in(
        &self,
        email: String,
        nonce: String,
        device_name: String,
        platform: String,
    ) -> Result<String> {
        Ok(sign_b64(
            &self.auth,
            &sign_in_message(&email, &nonce, &device_name, &platform)?,
        ))
    }

    /// The base64url salt the keys were derived with.
    pub fn salt(&self) -> String {
        self.salt.clone()
    }

    pub fn kdf(&self) -> AccountKdf {
        self.kdf.clone()
    }

    /// Opens the account's password wrap: the account key, or `InvalidPassword` if the password
    /// and Secret Key don't open it ("Check your password and Secret Key").
    pub fn open_account_key(
        &self,
        account: String,
        ak_id: String,
        wrap: AccountWrap,
    ) -> Result<Arc<AccountKey>> {
        let aad = self.wrap_aad(&account, &ak_id)?;
        let ak = open_wrap(&self.wrap_key, &wrap, &aad).ok_or(PassError::InvalidPassword)?;
        AccountKey::checked(account, ak, &ak_id).map(Arc::new)
    }
}

/// Whether `sig` is the sign-in signature by `auth_pub` (what the account service checks; here
/// for tests and vectors).
pub fn account_sign_in_verify(
    auth_pub: &str,
    email: &str,
    nonce: &str,
    device_name: &str,
    platform: &str,
    sig: &str,
) -> bool {
    sign_in_message(email, nonce, device_name, platform)
        .is_ok_and(|msg| verify_b64(auth_pub, &msg, sig))
}

/// The account key, open on this device. Kept under the device's protection between opens
/// (Windows Hello, Android Keystore, iOS Keychain: [`AccountKey::to_bytes`]), dropped on a full
/// lock.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct AccountKey {
    account: String,
    ak: Key,
    ak_id: String,
}

impl std::fmt::Debug for AccountKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountKey")
            .field("account", &self.account)
            .field("ak_id", &self.ak_id)
            .finish_non_exhaustive()
    }
}

impl AccountKey {
    fn from_key(account: String, ak: Key) -> Result<AccountKey> {
        check_account(&account)?;
        let ak_id = ak_id_of(ak.as_slice(), &account);
        Ok(AccountKey { account, ak, ak_id })
    }

    /// `ak` for `account`, refused unless it is the key named `ak_id`.
    fn checked(account: String, ak: Key, ak_id: &str) -> Result<AccountKey> {
        let key = Self::from_key(account, ak)?;
        if !crypto::ct_eq(key.ak_id.as_bytes(), ak_id.as_bytes()) {
            return Err(PassError::Crypto(tr!("account_key.wrong_key")));
        }
        Ok(key)
    }

    pub(crate) fn key(&self) -> &Key {
        &self.ak
    }

    pub(crate) fn account_ref(&self) -> &str {
        &self.account
    }

    pub(crate) fn ak_id_ref(&self) -> &str {
        &self.ak_id
    }

    /// AAD of a PRF wrap: `"pass/ak-prf/v1:" + JSON[account, ak_id, credential_id]`.
    fn prf_aad(account: &str, ak_id: &str, credential_id: &str) -> Result<Vec<u8>> {
        json_tail(b"pass/ak-prf/v1:", &(account, ak_id, credential_id))
    }

    /// AAD of `sk_wrap`: `"pass/sk-wrap/v1:" + JSON[account, ak_id]`.
    fn sk_wrap_aad(&self) -> Result<Vec<u8>> {
        json_tail(b"pass/sk-wrap/v1:", &(&self.account, &self.ak_id))
    }

    fn sk_wrap_key(&self) -> Key {
        Key::from_array(*hkdf_sha256(self.ak.as_slice(), SK_WRAP_INFO))
    }

    fn ak_sign_key(&self) -> ed25519_dalek::SigningKey {
        signing_key(&hkdf_sha256(self.ak.as_slice(), AK_SIGN_INFO))
    }

    /// AK followed by the Secret Key: what device approval seals.
    fn with_secret_key(&self, secret_key: &SecretKey) -> Zeroizing<Vec<u8>> {
        let mut plain = Zeroizing::new(Vec::with_capacity(KEY_LEN + SECRET_KEY_LEN));
        plain.extend_from_slice(self.ak.as_slice());
        plain.extend_from_slice(secret_key.bytes());
        plain
    }
}

/// The key a PRF output wraps AK with: HKDF(PRF output, `"pass/ak-prf/v1"`). The output must be
/// the 32 bytes WebAuthn's PRF extension gives.
fn prf_key(prf_output: &[u8]) -> Result<Key> {
    if prf_output.len() != 32 {
        return Err(PassError::InvalidInput(tr!("account_key.bad_prf")));
    }
    Ok(Key::from_array(*hkdf_sha256(prf_output, PRF_INFO)))
}

/// What `ak_sign` signs for a request that adds, replaces or deletes a key blob:
/// `"pass/ak-sign/v1:" + JSON[account, nonce, method, path, base64url(SHA-256(body))]`.
pub(crate) fn request_message(
    account: &str,
    nonce: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<Vec<u8>> {
    let digest = b64url_encode(Sha256::digest(body).to_vec());
    json_tail(
        b"pass/ak-sign/v1:",
        &(account, nonce, method.to_ascii_uppercase(), path, digest),
    )
}

/// Whether `sig` is `ak_sign`'s signature of the request (what the account service checks; here
/// for tests and vectors).
pub fn account_request_verify(
    ak_sign_pub: &str,
    account: &str,
    nonce: &str,
    method: &str,
    path: &str,
    body: &[u8],
    sig: &str,
) -> bool {
    request_message(account, nonce, method, path, body)
        .is_ok_and(|msg| verify_b64(ak_sign_pub, &msg, sig))
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl AccountKey {
    /// A new random account key for `account` (sign-up, or replacing the key).
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn generate(account: String) -> Result<Arc<AccountKey>> {
        Ok(Arc::new(Self::from_key(account, crypto::random_key())?))
    }

    /// The key kept by this device ([`AccountKey::to_bytes`]), refused unless it is the account's
    /// `ak_id`.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn from_bytes(account: String, key: Vec<u8>, ak_id: String) -> Result<Arc<AccountKey>> {
        let key = Zeroizing::new(key);
        let ak = Key::from_slice(&key).ok_or_else(damaged)?;
        Ok(Arc::new(Self::checked(account, ak, &ak_id)?))
    }

    pub fn account(&self) -> String {
        self.account.clone()
    }

    /// Names this key (base64url, 22 characters); the service keeps it next to every wrap.
    pub fn ak_id(&self) -> String {
        self.ak_id.clone()
    }

    /// The short fingerprint Settings shows: the first 8 bytes of `ak_id` as 4 groups of 4 hex
    /// digits.
    pub fn fingerprint(&self) -> String {
        let raw = b64url_decode(self.ak_id.clone()).unwrap_or_default();
        let hex = crate::encoding::hex(&raw[..raw.len().min(8)]).to_ascii_uppercase();
        hex.as_bytes()
            .chunks(4)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join("-")
    }

    /// The raw key, to keep under the device's protection. Never upload it.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.ak.to_vec()
    }

    /// The public half of `ak_sign` (base64url), which the account service keeps to check
    /// key-changing requests.
    pub fn ak_sign_pub(&self) -> String {
        public_b64(&self.ak_sign_key())
    }

    /// Signs a request that adds, replaces or deletes a key blob: the service's fresh `nonce`, the
    /// HTTP `method` and `path`, and the exact `body` bytes sent.
    pub fn sign_request(
        &self,
        nonce: String,
        method: String,
        path: String,
        body: Vec<u8>,
    ) -> Result<String> {
        Ok(sign_b64(
            &self.ak_sign_key(),
            &request_message(&self.account, &nonce, &method, &path, &body)?,
        ))
    }

    /// AK wrapped by the password's `wrap_key`, for the account service.
    pub fn password_wrap(&self, password: &AccountPassword) -> Result<AccountWrap> {
        let aad = password.wrap_aad(&self.account, &self.ak_id)?;
        seal_wrap(&password.wrap_key, self.ak.as_slice(), &aad)
    }

    /// The Secret Key wrapped under AK (`sk_wrap`), for the account service: every path that
    /// yields AK then yields the Secret Key.
    pub fn secret_key_wrap(&self, secret_key: &SecretKey) -> Result<AccountWrap> {
        seal_wrap(&self.sk_wrap_key(), secret_key.bytes(), &self.sk_wrap_aad()?)
    }

    /// Opens `sk_wrap`: the account's Secret Key.
    pub fn open_secret_key(&self, wrap: AccountWrap) -> Result<Arc<SecretKey>> {
        let plain = open_wrap_bytes(&self.sk_wrap_key(), &wrap, &self.sk_wrap_aad()?)
            .ok_or_else(|| PassError::Crypto(tr!("account_key.wrong_key")))?;
        let secret: [u8; SECRET_KEY_LEN] = plain.as_slice().try_into().map_err(|_| damaged())?;
        Ok(Arc::new(SecretKey::from_array(secret)))
    }

    /// Whether `password` is this account's Passyble password, checked with one Argon2id run
    /// against this device's copy of the salt, parameters and password wrap. Nothing is kept.
    /// `false` when it can't be told (a stale or damaged copy).
    pub fn is_account_password(
        &self,
        password: String,
        salt: String,
        kdf: AccountKdf,
        pw_wrap: AccountWrap,
        sk_wrap: AccountWrap,
    ) -> bool {
        let password = Zeroizing::new(password);
        let Ok(secret_key) = self.open_secret_key(sk_wrap) else {
            return false;
        };
        let Ok(derived) = AccountPassword::derive(&password, &secret_key, &salt, &kdf) else {
            return false;
        };
        derived
            .wrap_aad(&self.account, &self.ak_id)
            .ok()
            .and_then(|aad| open_wrap(&derived.wrap_key, &pw_wrap, &aad))
            .is_some_and(|ak| ak.as_slice() == self.ak.as_slice())
    }

    /// The rule for a vault's own password: the master password rule
    /// ([`crate::require_master_password`] with `context`) and not the Passyble password. Such a
    /// vault has no Secret Key, so reusing the Passyble password would let a copy of the file be
    /// used to guess it. `InvalidInput` with the reason in the core's language.
    pub fn require_second_password(
        &self,
        password: String,
        context: crate::MasterPasswordContext,
        salt: String,
        kdf: AccountKdf,
        pw_wrap: AccountWrap,
        sk_wrap: AccountWrap,
    ) -> Result<()> {
        let password = Zeroizing::new(password);
        crate::require_master_password(&password, &context)?;
        if self.is_account_password(password.to_string(), salt, kdf, pw_wrap, sk_wrap) {
            return Err(PassError::InvalidInput(tr!(
                "account_key.second_password_is_account_password"
            )));
        }
        Ok(())
    }

    /// AK wrapped by a passkey's PRF output, for the account service (one wrap per credential).
    /// Refuses an output that isn't 32 bytes.
    pub fn prf_wrap(&self, prf_output: Vec<u8>, credential_id: String) -> Result<AccountWrap> {
        let prf_output = Zeroizing::new(prf_output);
        let key = prf_key(&prf_output)?;
        let aad = Self::prf_aad(&self.account, &self.ak_id, &credential_id)?;
        seal_wrap(&key, self.ak.as_slice(), &aad)
    }

    /// A new recovery code for this key. Replaces the old one on the account service and in each
    /// linked vault header ([`crate::Vault::set_account_recovery`]).
    pub fn new_recovery(&self) -> Result<AccountRecovery> {
        let (secret, code) = crate::recovery::generate();
        let rec_id = uuid::Uuid::new_v4().to_string();
        let key = Key::from_array(*hkdf_sha256(secret.as_slice(), RECOVERY_INFO));
        let aad = recovery_aad(&self.account, &self.ak_id, &rec_id)?;
        let wrap = seal_wrap(&key, self.ak.as_slice(), &aad)?;
        let signing = recovery_signing_key(secret.as_slice());
        Ok(AccountRecovery {
            code: code.to_string(),
            rec_id,
            verify_pub: public_b64(&signing),
            wrap,
        })
    }

    /// Approves a new device's request by number matching: `typed_code` is what the user typed
    /// after reading the 6 digits on the new device ([`DeviceApprovalKeys::code`]). Anything else is
    /// refused, so a request the user didn't start goes nowhere. Checks the new device's commitment
    /// against `r_n` and seals AK and the Secret Key to its one-time key, bound to the exchange.
    /// Never pass a code the app computed itself.
    #[allow(clippy::too_many_arguments)]
    pub fn approve_device(
        &self,
        secret_key: &SecretKey,
        request_id: String,
        enc_pub: String,
        commitment: String,
        r_n: String,
        r_a: String,
        typed_code: String,
    ) -> Result<SealedAccountKey> {
        let t = Transcript::checked(&request_id, &self.account, &enc_pub, &commitment, &r_n, &r_a)?;
        let digits: String = typed_code.chars().filter(char::is_ascii_digit).collect();
        if !crypto::ct_eq(digits.as_bytes(), t.code()?.as_bytes()) {
            return Err(PassError::Crypto(tr!("account_key.approval_code_mismatch")));
        }
        self.seal_for(secret_key, &t)
    }

    /// Approves a new device whose approval QR this device scanned ([`parse_approval_qr`]): the
    /// QR carries the new device's key and `r_n`, so the camera did the matching. `commitment`
    /// and `r_a` are the request's, as for [`AccountKey::approve_device`].
    pub fn approve_device_qr(
        &self,
        secret_key: &SecretKey,
        qr: ApprovalQr,
        commitment: String,
        r_a: String,
    ) -> Result<SealedAccountKey> {
        let t = Transcript::checked(
            &qr.request_id,
            &self.account,
            &qr.enc_pub,
            &commitment,
            &qr.r_n,
            &r_a,
        )?;
        self.seal_for(secret_key, &t)
    }

    /// Approves a new device that scanned this device's invitation QR ([`DeviceInvitation`]):
    /// checks its MAC over `enc_pub` (only a device that saw the QR can make it) and seals AK and the
    /// Secret Key to `enc_pub`.
    pub fn approve_invitation(
        &self,
        secret_key: &SecretKey,
        invitation: &DeviceInvitation,
        invitation_id: String,
        enc_pub: String,
        mac: String,
    ) -> Result<SealedAccountKey> {
        let mismatch = || PassError::Crypto(tr!("account_key.approval_mismatch"));
        if !invitation.check(invitation_id.clone(), enc_pub.clone(), mac) {
            return Err(mismatch());
        }
        let public = decode_fixed::<KEY_BYTES>(&enc_pub).map_err(|_| mismatch())?;
        if !valid_enc_pub(&public) {
            return Err(mismatch());
        }
        let info = invitation_info(&invitation_id, &self.account, &b64url_encode(public.to_vec()))?;
        let (enc, ct) = hpke_seal(&public, &info, &self.with_secret_key(secret_key))?;
        Ok(SealedAccountKey {
            enc: b64url_encode(enc),
            ct: b64url_encode(ct),
        })
    }
}

impl AccountKey {
    fn seal_for(&self, secret_key: &SecretKey, t: &Transcript) -> Result<SealedAccountKey> {
        let (enc, ct) = hpke_seal(&t.enc_pub, &t.seal_info()?, &self.with_secret_key(secret_key))?;
        Ok(SealedAccountKey {
            enc: b64url_encode(enc),
            ct: b64url_encode(ct),
        })
    }
}

/// Opens the account key with a passkey's PRF output (after a verified assertion by
/// `credential_id`); `InvalidPassword` if it doesn't open.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn account_key_open_prf(
    account: String,
    ak_id: String,
    prf_output: Vec<u8>,
    credential_id: String,
    wrap: AccountWrap,
) -> Result<Arc<AccountKey>> {
    let prf_output = Zeroizing::new(prf_output);
    let key = prf_key(&prf_output)?;
    let aad = AccountKey::prf_aad(&account, &ak_id, &credential_id)?;
    let ak = open_wrap(&key, &wrap, &aad).ok_or(PassError::InvalidPassword)?;
    Ok(Arc::new(AccountKey::checked(account, ak, &ak_id)?))
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl AccountKey {
    /// Opts this account in to admin-assisted recovery by the organisation `key.org`. Checks that
    /// `key` was made by `creator`, an admin whose keys are pinned in the member's home vault `home`
    /// (`Crypto` otherwise, so a recovery key planted by the service is never enrolled), then wraps
    /// the account key to it. Every admin of the organisation can then open every linked vault.
    pub fn admin_recovery_enroll(
        &self,
        key: crate::OrgRecoveryKey,
        creator: crate::PublicKeys,
        kind: crate::OrgKind,
        home: &crate::Vault,
    ) -> Result<crate::RecoveryEnrollment> {
        if home.is_shared() {
            return Err(PassError::InvalidInput(tr!("share.keys_in_shared")));
        }
        home.require_pinned(&creator, crate::PERSONAL_SCOPE)?;
        let vault_id = format!(
            "{}{}",
            crate::share::org_recovery::ACCOUNT_KEY_PREFIX,
            self.ak_id
        );
        crate::share::org_recovery::enroll(&self.ak, &vault_id, &self.account, &key, &creator, kind)
    }
}

/// The account key from an admin's approval of this device's recovery request (made with
/// `admin_recovery_request(org, account, "ak:" + ak_id)`): checks the approval's signature against
/// `approver` and opens the key with the request's one-time `secret`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn account_key_from_admin_recovery(
    approval: crate::RecoveryApproval,
    secret: String,
    approver: crate::PublicKeys,
) -> Result<Arc<AccountKey>> {
    let secret = Zeroizing::new(secret);
    let ak_id = approval
        .vault_id
        .strip_prefix(crate::share::org_recovery::ACCOUNT_KEY_PREFIX)
        .ok_or_else(|| PassError::Crypto(tr!("account_key.wrong_key")))?
        .to_string();
    let ak = crate::share::org_recovery::open_approval(&approval, &secret, &approver)?;
    Ok(Arc::new(AccountKey::checked(approval.account, ak, &ak_id)?))
}

/// AAD of the recovery wrap: `"pass/ak-recovery/v1:" + JSON[account, ak_id, rec_id]`. Everything
/// in it is also in a linked vault's header, so the code opens the header copy offline.
pub(crate) fn recovery_aad(account: &str, ak_id: &str, rec_id: &str) -> Result<Vec<u8>> {
    json_tail(b"pass/ak-recovery/v1:", &(account, ak_id, rec_id))
}

fn recovery_signing_key(secret: &[u8]) -> ed25519_dalek::SigningKey {
    signing_key(&hkdf_sha256(secret, RECOVERY_SIGN_INFO))
}

/// What the code's key signs to reset the password: `"pass/recovery-challenge/v1:" +
/// JSON[account, rec_id, challenge]`.
fn recovery_message(account: &str, rec_id: &str, challenge: &str) -> Result<Vec<u8>> {
    json_tail(b"pass/recovery-challenge/v1:", &(account, rec_id, challenge))
}

/// Opens a recovery wrap with the code: AK, or `InvalidPassword` for a code that doesn't open it
/// (`InvalidInput` for a code with a typo).
pub(crate) fn open_recovery(
    account: &str,
    ak_id: &str,
    code: &str,
    rec_id: &str,
    wrap: &AccountWrap,
) -> Result<AccountKey> {
    let secret = crate::recovery::decode(code)?;
    let key = Key::from_array(*hkdf_sha256(secret.as_slice(), RECOVERY_INFO));
    let aad = recovery_aad(account, ak_id, rec_id)?;
    let ak = open_wrap(&key, wrap, &aad).ok_or(PassError::InvalidPassword)?;
    AccountKey::checked(account.to_string(), ak, ak_id)
}

/// Opens the account key with the recovery code and the account's recovery wrap (released by the
/// service after [`account_recovery_sign`]'s signature verified).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn account_key_open_recovery(
    account: String,
    ak_id: String,
    recovery_code: String,
    rec_id: String,
    wrap: AccountWrap,
) -> Result<Arc<AccountKey>> {
    let recovery_code = Zeroizing::new(recovery_code);
    Ok(Arc::new(open_recovery(
        &account,
        &ak_id,
        &recovery_code,
        &rec_id,
        &wrap,
    )?))
}

/// The base64url Ed25519 public key `recovery_code` derives (the account's `verify_pub` when the
/// code is current).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn account_recovery_verify_pub(recovery_code: String) -> Result<String> {
    let recovery_code = Zeroizing::new(recovery_code);
    let secret = crate::recovery::decode(&recovery_code)?;
    Ok(public_b64(&recovery_signing_key(secret.as_slice())))
}

/// Signs the account service's reset `challenge` with the key `recovery_code` derives (base64url
/// Ed25519 signature): proves the code without sending it.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn account_recovery_sign(
    recovery_code: String,
    account: String,
    rec_id: String,
    challenge: String,
) -> Result<String> {
    let recovery_code = Zeroizing::new(recovery_code);
    let secret = crate::recovery::decode(&recovery_code)?;
    Ok(sign_b64(
        &recovery_signing_key(secret.as_slice()),
        &recovery_message(&account, &rec_id, &challenge)?,
    ))
}

/// Whether `sig` is the recovery key's signature of the reset `challenge` (what the account
/// service checks; here for tests and vectors).
pub fn account_recovery_verify(
    verify_pub: &str,
    account: &str,
    rec_id: &str,
    challenge: &str,
    sig: &str,
) -> bool {
    recovery_message(account, rec_id, challenge).is_ok_and(|msg| verify_b64(verify_pub, &msg, sig))
}

/// One device approval exchange, checked.
struct Transcript {
    request_id: String,
    account: String,
    enc_pub: [u8; KEY_BYTES],
    enc_pub_b64: String,
    r_n: String,
    r_a: String,
}

fn commitment_of(enc_pub: &[u8], r_n: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"pass/approve-commit/v1:");
    h.update(enc_pub);
    h.update(r_n);
    b64url_encode(h.finalize().to_vec())
}

impl Transcript {
    /// Checks the new device's key and that `r_n` opens its `commitment`.
    fn checked(
        request_id: &str,
        account: &str,
        enc_pub: &str,
        commitment: &str,
        r_n: &str,
        r_a: &str,
    ) -> Result<Transcript> {
        let mismatch = || PassError::Crypto(tr!("account_key.approval_mismatch"));
        check_account(account)?;
        if request_id.is_empty() {
            return Err(mismatch());
        }
        let public = decode_fixed::<KEY_BYTES>(enc_pub).map_err(|_| mismatch())?;
        if !valid_enc_pub(&public) {
            return Err(mismatch());
        }
        let r_n_raw = decode_fixed::<APPROVAL_NONCE_LEN>(r_n).map_err(|_| mismatch())?;
        let r_a_raw = decode_fixed::<APPROVAL_NONCE_LEN>(r_a).map_err(|_| mismatch())?;
        let expected = commitment_of(public.as_slice(), r_n_raw.as_slice());
        if !crypto::ct_eq(expected.as_bytes(), commitment.trim().as_bytes()) {
            return Err(mismatch());
        }
        Ok(Transcript {
            request_id: request_id.to_string(),
            account: account.to_string(),
            enc_pub: *public,
            enc_pub_b64: b64url_encode(public.to_vec()),
            r_n: b64url_encode(r_n_raw.to_vec()),
            r_a: b64url_encode(r_a_raw.to_vec()),
        })
    }

    fn tail(&self, prefix: &[u8]) -> Result<Vec<u8>> {
        json_tail(
            prefix,
            &(
                &self.request_id,
                &self.account,
                &self.enc_pub_b64,
                &self.r_n,
                &self.r_a,
            ),
        )
    }

    /// The 6 digits both screens show: SHA-256(`"pass/approve-sas/v1:" + JSON[request_id,
    /// account, enc_pub, r_n, r_a]`), its first 8 bytes as a number modulo one million.
    fn code(&self) -> Result<String> {
        let digest = Sha256::digest(self.tail(b"pass/approve-sas/v1:")?);
        let n = u64::from_be_bytes(digest[..8].try_into().expect("8 bytes")) % 1_000_000;
        Ok(format!("{n:06}"))
    }

    /// HPKE `info` of the sealed keys: `"pass/approve-ak/v1:" + JSON[the same]`.
    fn seal_info(&self) -> Result<Vec<u8>> {
        self.tail(b"pass/approve-ak/v1:")
    }
}

/// HPKE `info` of keys sealed through an invitation QR: `"pass/add-ak/v1:" + JSON[invitation,
/// account, enc_pub]`.
fn invitation_info(invitation: &str, account: &str, enc_pub: &str) -> Result<Vec<u8>> {
    json_tail(b"pass/add-ak/v1:", &(invitation, account, enc_pub))
}

/// HMAC-SHA256(s, `"pass/add/v1:" + invitation + enc_pub`), base64url.
fn invitation_mac(s: &[u8], invitation: &str, enc_pub: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(s).expect("any key length");
    mac.update(b"pass/add/v1:");
    mac.update(invitation.as_bytes());
    mac.update(enc_pub.as_bytes());
    b64url_encode(mac.finalize().into_bytes().to_vec())
}

/// A random value for the approving device's side of the exchange (`r_a`), base64url.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn device_approval_nonce() -> String {
    b64url_encode(crypto::random_bytes::<APPROVAL_NONCE_LEN>().to_vec())
}

/// The 6-digit code the approving device shows, after checking that the new device's revealed
/// `r_n` opens its `commitment` (`Crypto` error if not: deny the request).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn device_approval_code(
    request_id: String,
    account: String,
    enc_pub: String,
    commitment: String,
    r_n: String,
    r_a: String,
) -> Result<String> {
    Transcript::checked(&request_id, &account, &enc_pub, &commitment, &r_n, &r_a)?.code()
}

/// What a new device's approval QR carries (`passyble:approve/v1?id=<request>&k=<enc_pub>&r=<r_n>`).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ApprovalQr {
    pub request_id: String,
    pub enc_pub: String,
    pub r_n: String,
}

/// What an approving device's invitation QR carries (`passyble:add/v1?inv=<id>&t=<t>&s=<s>`).
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct InvitationQr {
    pub invitation_id: String,
    /// The one-time token the account service checks (it keeps its hash).
    pub token: String,
    /// The MAC key, never sent to the service.
    pub mac_key: String,
}

impl std::fmt::Debug for InvitationQr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvitationQr")
            .field("invitation_id", &self.invitation_id)
            .finish_non_exhaustive()
    }
}

/// The `key=value` pairs of a `passyble:<what>/v1?...` link; `None` for another link.
fn link_params(text: &str, what: &str) -> Option<Vec<(String, String)>> {
    let rest = text.trim().strip_prefix(&format!("passyble:{what}/v1?"))?;
    rest.split('&')
        .map(|pair| {
            let (k, v) = pair.split_once('=')?;
            let v = percent_encoding::percent_decode_str(v).decode_utf8().ok()?;
            Some((k.to_string(), v.into_owned()))
        })
        .collect()
}

fn param(params: &[(String, String)], key: &str) -> Option<String> {
    params.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}

fn bad_qr() -> PassError {
    PassError::InvalidInput(tr!("account_key.bad_qr"))
}

/// Reads a new device's approval QR (on the approving device, which then checks that the request
/// on the service carries the same `enc_pub`, and approves with `r_n` from the QR: the camera
/// authenticated the key, nothing to compare).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn parse_approval_qr(text: String) -> Result<ApprovalQr> {
    let p = link_params(&text, "approve").ok_or_else(bad_qr)?;
    let (Some(request_id), Some(enc_pub), Some(r_n)) = (param(&p, "id"), param(&p, "k"), param(&p, "r"))
    else {
        return Err(bad_qr());
    };
    decode_fixed::<KEY_BYTES>(&enc_pub).map_err(|_| bad_qr())?;
    decode_fixed::<APPROVAL_NONCE_LEN>(&r_n).map_err(|_| bad_qr())?;
    Ok(ApprovalQr {
        request_id,
        enc_pub,
        r_n,
    })
}

/// Reads an approving device's invitation QR (on the new device).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn parse_invitation_qr(text: String) -> Result<InvitationQr> {
    let p = link_params(&text, "add").ok_or_else(bad_qr)?;
    let (Some(invitation_id), Some(token), Some(mac_key)) =
        (param(&p, "inv"), param(&p, "t"), param(&p, "s"))
    else {
        return Err(bad_qr());
    };
    decode_fixed::<32>(&mac_key).map_err(|_| bad_qr())?;
    Ok(InvitationQr {
        invitation_id,
        token,
        mac_key,
    })
}

/// The new device's side of a device approval: a one-time X25519 key pair and a random `r_n`.
/// It sends [`DeviceApprovalKeys::enc_pub`] and [`DeviceApprovalKeys::commitment`] with its
/// request, and either shows [`DeviceApprovalKeys::approval_qr`] for the approving device to scan,
/// or reveals `r_n` once the approving device sent `r_a` and shows [`DeviceApprovalKeys::code`];
/// or it scans the approving device's invitation QR and sends
/// [`DeviceApprovalKeys::invitation_mac`]. Then it opens the sealed keys.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct DeviceApprovalKeys {
    enc_sk: Zeroizing<[u8; KEY_BYTES]>,
    enc_pub: [u8; KEY_BYTES],
    r_n: Zeroizing<[u8; APPROVAL_NONCE_LEN]>,
}

impl std::fmt::Debug for DeviceApprovalKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceApprovalKeys").finish_non_exhaustive()
    }
}

impl DeviceApprovalKeys {
    fn transcript(&self, request_id: &str, account: &str, r_a: &str) -> Result<Transcript> {
        Transcript::checked(
            request_id,
            account,
            &self.enc_pub(),
            &self.commitment(),
            &self.reveal(),
            r_a,
        )
    }

    fn open_with(&self, info: &[u8], account: String, ak_id: &str, sealed: SealedAccountKey) -> Result<Arc<ApprovedKeys>> {
        let enc = b64url_decode(sealed.enc)?;
        let ct = b64url_decode(sealed.ct)?;
        let plain = hpke_open(&self.enc_sk, info, &enc, &ct)
            .ok_or_else(|| PassError::Crypto(tr!("account_key.approval_mismatch")))?;
        if plain.len() != KEY_LEN + SECRET_KEY_LEN {
            return Err(damaged());
        }
        let ak = Key::from_slice(&plain[..KEY_LEN]).ok_or_else(damaged)?;
        let secret: [u8; SECRET_KEY_LEN] = plain[KEY_LEN..].try_into().map_err(|_| damaged())?;
        Ok(Arc::new(ApprovedKeys {
            account_key: Arc::new(AccountKey::checked(account, ak, ak_id)?),
            secret_key: Arc::new(SecretKey::from_array(secret)),
        }))
    }
}

/// What an approval gives a new device: the account key and the Secret Key.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[derive(Debug)]
pub struct ApprovedKeys {
    account_key: Arc<AccountKey>,
    secret_key: Arc<SecretKey>,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl ApprovedKeys {
    pub fn account_key(&self) -> Arc<AccountKey> {
        self.account_key.clone()
    }

    /// The fingerprint of the account key that arrived ([`AccountKey::fingerprint`]), for the new
    /// device to show before using it. It catches a service that sealed a key of its own.
    pub fn fingerprint(&self) -> String {
        self.account_key.fingerprint()
    }

    pub fn secret_key(&self) -> Arc<SecretKey> {
        self.secret_key.clone()
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl DeviceApprovalKeys {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new() -> Arc<DeviceApprovalKeys> {
        let (enc_sk, enc_pub) = hpke_keypair();
        Arc::new(DeviceApprovalKeys {
            enc_sk,
            enc_pub,
            r_n: Zeroizing::new(crypto::random_bytes::<APPROVAL_NONCE_LEN>()),
        })
    }

    /// Keys kept with [`DeviceApprovalKeys::secret`] while the request waits (the app may be
    /// closed in between).
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn restore(secret: String) -> Result<Arc<DeviceApprovalKeys>> {
        let secret = Zeroizing::new(secret);
        let raw = decode_fixed::<{ KEY_BYTES + APPROVAL_NONCE_LEN }>(&secret)?;
        let mut enc_sk = Zeroizing::new([0u8; KEY_BYTES]);
        enc_sk.copy_from_slice(&raw[..KEY_BYTES]);
        let mut r_n = Zeroizing::new([0u8; APPROVAL_NONCE_LEN]);
        r_n.copy_from_slice(&raw[KEY_BYTES..]);
        let enc_pub = hpke_public_of(&enc_sk).ok_or_else(damaged)?;
        Ok(Arc::new(DeviceApprovalKeys {
            enc_sk,
            enc_pub,
            r_n,
        }))
    }

    /// The private half, for the device's secure storage only (base64url). Delete it once the
    /// keys arrived or the request ended.
    pub fn secret(&self) -> String {
        let mut raw = Zeroizing::new(Vec::with_capacity(KEY_BYTES + APPROVAL_NONCE_LEN));
        raw.extend_from_slice(self.enc_sk.as_slice());
        raw.extend_from_slice(self.r_n.as_slice());
        b64url_encode(raw.to_vec())
    }

    /// The one-time X25519 public key, base64url.
    pub fn enc_pub(&self) -> String {
        b64url_encode(self.enc_pub.to_vec())
    }

    /// SHA-256(`"pass/approve-commit/v1:" + enc_pub + r_n`), base64url: sent with the request,
    /// before the approving device's `r_a` is known.
    pub fn commitment(&self) -> String {
        commitment_of(&self.enc_pub, self.r_n.as_slice())
    }

    /// `r_n`, base64url: revealed only after the approving device's `r_a` arrived (code variant),
    /// or shown in the QR (QR variant).
    pub fn reveal(&self) -> String {
        b64url_encode(self.r_n.to_vec())
    }

    /// The QR this device shows for the approving device to scan:
    /// `passyble:approve/v1?id=<request>&k=<enc_pub>&r=<r_n>`.
    pub fn approval_qr(&self, request_id: String) -> String {
        let id = percent_encoding::utf8_percent_encode(&request_id, percent_encoding::NON_ALPHANUMERIC);
        format!("passyble:approve/v1?id={id}&k={}&r={}", self.enc_pub(), self.reveal())
    }

    /// The MAC this device sends with its key after scanning an invitation QR.
    pub fn invitation_mac(&self, qr: InvitationQr) -> Result<String> {
        let s = decode_fixed::<32>(&qr.mac_key).map_err(|_| bad_qr())?;
        Ok(invitation_mac(s.as_slice(), &qr.invitation_id, &self.enc_pub()))
    }

    /// The 6-digit code this device shows, the same as on the approving device.
    pub fn code(&self, request_id: String, account: String, r_a: String) -> Result<String> {
        self.transcript(&request_id, &account, &r_a)?.code()
    }

    /// Opens the keys the approving device sealed (QR or code variant) and checks the account key
    /// is the account's `ak_id`.
    pub fn open(
        &self,
        request_id: String,
        account: String,
        ak_id: String,
        r_a: String,
        sealed: SealedAccountKey,
    ) -> Result<Arc<ApprovedKeys>> {
        let info = self.transcript(&request_id, &account, &r_a)?.seal_info()?;
        self.open_with(&info, account, &ak_id, sealed)
    }

    /// Opens the keys sealed through an invitation QR.
    pub fn open_invitation(
        &self,
        invitation_id: String,
        account: String,
        ak_id: String,
        sealed: SealedAccountKey,
    ) -> Result<Arc<ApprovedKeys>> {
        let info = invitation_info(&invitation_id, &account, &self.enc_pub())?;
        self.open_with(&info, account, &ak_id, sealed)
    }
}

/// The approving device's side of an invitation QR: a one-time token `t` (the account service
/// keeps its hash) and a MAC key `s` that only goes into the QR.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct DeviceInvitation {
    token: String,
    mac_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for DeviceInvitation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceInvitation").finish_non_exhaustive()
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl DeviceInvitation {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new() -> Arc<DeviceInvitation> {
        Arc::new(DeviceInvitation {
            token: b64url_encode(crypto::random_bytes::<16>().to_vec()),
            mac_key: Zeroizing::new(crypto::random_bytes::<32>()),
        })
    }

    /// The token to register with the account service (it answers with the invitation id).
    pub fn token(&self) -> String {
        self.token.clone()
    }

    /// The QR to show: `passyble:add/v1?inv=<id>&t=<t>&s=<s>`. Valid 2 minutes, once.
    pub fn qr(&self, invitation_id: String) -> String {
        let id = percent_encoding::utf8_percent_encode(&invitation_id, percent_encoding::NON_ALPHANUMERIC);
        format!(
            "passyble:add/v1?inv={id}&t={}&s={}",
            self.token,
            b64url_encode(self.mac_key.to_vec())
        )
    }

    /// Whether `mac` proves that the device which sent `enc_pub` scanned this QR.
    pub fn check(&self, invitation_id: String, enc_pub: String, mac: String) -> bool {
        let expected = invitation_mac(self.mac_key.as_slice(), &invitation_id, &enc_pub);
        crypto::ct_eq(expected.as_bytes(), mac.trim().as_bytes())
    }
}

/// What the one-page Emergency Kit shows (each app lays it out and prints it to PDF on the device).
/// The password is never in it: the page has a blank line for it.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct EmergencyKit {
    pub email: String,
    /// Where to sign in: `https://account.passyble.com`.
    pub sign_in_url: String,
    pub account: String,
    /// `P1-XXXXX-...`.
    pub secret_key: String,
    /// The setup QR's text (e-mail, account id, Secret Key; never the password):
    /// `passyble:kit/v1?e=<email>&a=<account>&k=<secret key>`.
    pub setup_qr: String,
    /// In its own box on the page, when the kit includes it.
    pub recovery_code: Option<String>,
}

impl std::fmt::Debug for EmergencyKit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmergencyKit")
            .field("email", &self.email)
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

/// The Emergency Kit for `email`'s account with this Secret Key and, at sign-up or after a new
/// code, the recovery code.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn emergency_kit(
    email: String,
    account: String,
    secret_key: &SecretKey,
    recovery_code: Option<String>,
) -> EmergencyKit {
    let enc = |v: &str| percent_encoding::utf8_percent_encode(v, percent_encoding::NON_ALPHANUMERIC).to_string();
    let text = secret_key.text();
    EmergencyKit {
        setup_qr: format!("passyble:kit/v1?e={}&a={}&k={}", enc(&email), enc(&account), text),
        email,
        sign_in_url: "https://account.passyble.com".into(),
        account,
        secret_key: text,
        recovery_code,
    }
}

/// What the Emergency Kit's setup QR carries.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct KitQr {
    pub email: String,
    pub account: String,
    /// `P1-XXXXX-...` (checked).
    pub secret_key: String,
}

impl std::fmt::Debug for KitQr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KitQr")
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}

/// Reads the Emergency Kit's setup QR ("Scan your Emergency Kit").
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn parse_kit_qr(text: String) -> Result<KitQr> {
    let text = Zeroizing::new(text);
    let p = link_params(&text, "kit").ok_or_else(bad_qr)?;
    let (Some(email), Some(account), Some(k)) = (param(&p, "e"), param(&p, "a"), param(&p, "k")) else {
        return Err(bad_qr());
    };
    let secret_key = SecretKey::read(&k)?.text();
    Ok(KitQr {
        email,
        account,
        secret_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &str = "AAECAwQFBgcICQoLDA0ODw";

    fn sk() -> SecretKey {
        SecretKey::from_array([0x5a; SECRET_KEY_LEN])
    }

    fn password(pw: &str) -> AccountPassword {
        AccountPassword::derive(pw, &sk(), SALT, &AccountKdf::default()).unwrap()
    }

    #[test]
    fn kdf_bounds() {
        assert!(AccountKdf::default().check().is_ok());
        for weak in [
            AccountKdf { m_kib: 19 * 1024, ..Default::default() },
            AccountKdf { t: 2, ..Default::default() },
            AccountKdf { p: 0, ..Default::default() },
            AccountKdf { m_kib: 2 * 1024 * 1024, ..Default::default() },
            AccountKdf { alg: "argon2i".into(), ..Default::default() },
        ] {
            assert!(AccountPassword::derive("pw", &sk(), SALT, &weak).is_err());
        }
        // A salt shorter than 16 bytes.
        assert!(AccountPassword::derive("pw", &sk(), "AAEC", &AccountKdf::default()).is_err());
    }

    #[test]
    fn nfc_makes_one_password_of_two_spellings() {
        let composed = password("caf\u{e9} na\u{ef}ve");
        let decomposed = password("cafe\u{301} nai\u{308}ve");
        assert_eq!(composed.auth_pub(), decomposed.auth_pub());
        assert_ne!(composed.auth_pub(), password("cafe naive").auth_pub());
    }

    #[test]
    fn the_secret_key_changes_every_key() {
        let a = password("correct horse battery staple");
        let b = AccountPassword::derive(
            "correct horse battery staple",
            &SecretKey::from_array([0x5b; SECRET_KEY_LEN]),
            SALT,
            &AccountKdf::default(),
        )
        .unwrap();
        assert_ne!(a.auth_pub(), b.auth_pub());
        assert_ne!(a.wrap_key.as_slice(), b.wrap_key.as_slice());
        // A wrap made with one Secret Key doesn't open with another: "Check your Secret Key".
        let ak = AccountKey::generate("acc_1".into()).unwrap();
        let wrap = ak.password_wrap(&a).unwrap();
        assert!(matches!(
            b.open_account_key("acc_1".into(), ak.ak_id(), wrap),
            Err(PassError::InvalidPassword)
        ));
    }

    #[test]
    fn secret_keys_and_recovery_codes_are_never_confused() {
        let k = sk();
        let text = k.text();
        assert!(text.starts_with("P1-"), "{text}");
        assert_eq!(text.len(), 3 + 35);
        assert_eq!(SecretKey::read(&text).unwrap().bytes(), k.bytes());
        // Forgiving: case, spaces, no prefix.
        let sloppy = text.to_lowercase().replace('-', " ");
        assert_eq!(SecretKey::read(&sloppy).unwrap().bytes(), k.bytes());
        assert_eq!(SecretKey::read(&text[3..]).unwrap().bytes(), k.bytes());
        // A recovery code is named as such; a Secret Key is no recovery code.
        let code = crate::recovery::encode(&[0x5a; 16]);
        assert!(matches!(SecretKey::read(&code), Err(PassError::InvalidInput(_))));
        assert!(core_message_is_key(&SecretKey::read(&code).unwrap_err(), "account_key.recovery_code_not_secret_key"));
        assert!(crate::recovery::decode(&text[3..]).is_err());
        assert!(!secret_key_valid_format("P1-12345".into()));
    }

    fn core_message_is_key(e: &PassError, key: &str) -> bool {
        crate::core_message_is(e.to_string(), key.into())
    }

    #[test]
    fn password_length_limits() {
        assert!(normalize_password("").is_err());
        assert!(normalize_password(&"a".repeat(128)).is_ok());
        assert!(normalize_password(&"a".repeat(129)).is_err());
    }

    #[test]
    fn sign_in_signatures_bind_the_nonce_and_the_device() {
        let pw = password("correct horse battery staple");
        let sig = pw
            .sign_in("a@example.com".into(), "n1".into(), "Laptop".into(), "windows".into())
            .unwrap();
        assert!(account_sign_in_verify(&pw.auth_pub(), "a@example.com", "n1", "Laptop", "windows", &sig));
        assert!(!account_sign_in_verify(&pw.auth_pub(), "a@example.com", "n2", "Laptop", "windows", &sig));
        assert!(!account_sign_in_verify(&pw.auth_pub(), "b@example.com", "n1", "Laptop", "windows", &sig));
        assert!(!account_sign_in_verify(&pw.auth_pub(), "a@example.com", "n1", "Phone", "windows", &sig));
    }

    #[test]
    fn password_wrap_round_trip_and_substitution() {
        let pw = password("correct horse battery staple");
        let ak = AccountKey::generate("acc_1".into()).unwrap();
        let wrap = ak.password_wrap(&pw).unwrap();
        let opened = pw
            .open_account_key("acc_1".into(), ak.ak_id(), wrap.clone())
            .unwrap();
        assert_eq!(opened.to_bytes(), ak.to_bytes());
        assert!(pw.open_account_key("acc_2".into(), ak.ak_id(), wrap.clone()).is_err());
        assert!(matches!(
            password("wrong horse battery staple").open_account_key("acc_1".into(), ak.ak_id(), wrap.clone()),
            Err(PassError::InvalidPassword)
        ));
        let other = AccountKey::generate("acc_1".into()).unwrap();
        let other_wrap = other.password_wrap(&pw).unwrap();
        assert!(pw.open_account_key("acc_1".into(), ak.ak_id(), other_wrap).is_err());
    }

    #[test]
    fn every_path_to_ak_gives_the_secret_key() {
        let ak = AccountKey::generate("acc_1".into()).unwrap();
        let wrap = ak.secret_key_wrap(&sk()).unwrap();
        assert_eq!(ak.open_secret_key(wrap.clone()).unwrap().bytes(), sk().bytes());
        let other = AccountKey::generate("acc_1".into()).unwrap();
        assert!(other.open_secret_key(wrap).is_err());
    }

    #[test]
    fn a_second_password_must_not_be_the_passyble_password() {
        let account_pw = "rotate cobalt meadow lantern 82";
        let ak = AccountKey::generate("acc_1".into()).unwrap();
        let pw_wrap = ak.password_wrap(&password(account_pw)).unwrap();
        let sk_wrap = ak.secret_key_wrap(&sk()).unwrap();
        let kdf = AccountKdf::default();
        let is = |pw: &str| {
            ak.is_account_password(pw.into(), SALT.into(), kdf.clone(), pw_wrap.clone(), sk_wrap.clone())
        };
        assert!(is(account_pw));
        assert!(!is("rotate cobalt meadow lantern 83"));
        // Copies that can't tell: another key's Secret Key wrap, another salt.
        let other = AccountKey::generate("acc_1".into()).unwrap();
        let other_sk = other.secret_key_wrap(&sk()).unwrap();
        assert!(!ak.is_account_password(account_pw.into(), SALT.into(), kdf.clone(), pw_wrap.clone(), other_sk));
        assert!(!ak.is_account_password(
            account_pw.into(),
            "AQECAwQFBgcICQoLDA0ODw".into(),
            kdf.clone(),
            pw_wrap.clone(),
            sk_wrap.clone()
        ));

        let rule = |pw: &str| {
            ak.require_second_password(
                pw.into(),
                crate::MasterPasswordContext::default(),
                SALT.into(),
                kdf.clone(),
                pw_wrap.clone(),
                sk_wrap.clone(),
            )
        };
        // It passes the master password rule: refused only for being the Passyble password.
        assert!(crate::require_master_password(account_pw, &Default::default()).is_ok());
        assert!(matches!(rule(account_pw), Err(PassError::InvalidInput(_))));
        assert!(matches!(rule("short"), Err(PassError::InvalidInput(_))));
        assert!(rule("harbor velvet quarry tundra 41").is_ok());
    }

    #[test]
    fn key_changes_are_signed_with_ak_sign() {
        let ak = AccountKey::generate("acc_1".into()).unwrap();
        let body = br#"{"x":1}"#.to_vec();
        let sig = ak
            .sign_request("n1".into(), "put".into(), "/v1/account-key/password".into(), body.clone())
            .unwrap();
        let p = ak.ak_sign_pub();
        assert!(account_request_verify(&p, "acc_1", "n1", "PUT", "/v1/account-key/password", &body, &sig));
        assert!(!account_request_verify(&p, "acc_1", "n1", "PUT", "/v1/account-key/password", br#"{"x":2}"#, &sig));
        assert!(!account_request_verify(&p, "acc_1", "n2", "PUT", "/v1/account-key/password", &body, &sig));
        assert!(!account_request_verify(&p, "acc_1", "n1", "POST", "/v1/account-key/password", &body, &sig));
        let other = AccountKey::generate("acc_1".into()).unwrap();
        assert!(!account_request_verify(&other.ak_sign_pub(), "acc_1", "n1", "PUT", "/v1/account-key/password", &body, &sig));
    }

    #[test]
    fn prf_wrap_round_trip_and_substitution() {
        let ak = AccountKey::generate("acc_1".into()).unwrap();
        let prf = vec![9u8; 32];
        let wrap = ak.prf_wrap(prf.clone(), "cred-1".into()).unwrap();
        let opened =
            account_key_open_prf("acc_1".into(), ak.ak_id(), prf.clone(), "cred-1".into(), wrap.clone())
                .unwrap();
        assert_eq!(opened.to_bytes(), ak.to_bytes());
        assert!(account_key_open_prf("acc_1".into(), ak.ak_id(), prf.clone(), "cred-2".into(), wrap.clone()).is_err());
        assert!(account_key_open_prf("acc_1".into(), ak.ak_id(), vec![8u8; 32], "cred-1".into(), wrap.clone()).is_err());
        assert!(ak.prf_wrap(vec![1u8; 16], "cred-1".into()).is_err());
    }

    #[test]
    fn recovery_code_opens_and_signs() {
        let ak = AccountKey::generate("acc_1".into()).unwrap();
        let r = ak.new_recovery().unwrap();
        let opened = account_key_open_recovery(
            "acc_1".into(),
            ak.ak_id(),
            r.code.to_lowercase().replace('-', " "),
            r.rec_id.clone(),
            r.wrap.clone(),
        )
        .unwrap();
        assert_eq!(opened.to_bytes(), ak.to_bytes());
        assert_eq!(account_recovery_verify_pub(r.code.clone()).unwrap(), r.verify_pub);
        let sig = account_recovery_sign(r.code.clone(), "acc_1".into(), r.rec_id.clone(), "chal".into())
            .unwrap();
        assert!(account_recovery_verify(&r.verify_pub, "acc_1", &r.rec_id, "chal", &sig));
        assert!(!account_recovery_verify(&r.verify_pub, "acc_1", &r.rec_id, "other", &sig));
        assert!(!account_recovery_verify(&r.verify_pub, "acc_2", &r.rec_id, "chal", &sig));
        let other = ak.new_recovery().unwrap();
        assert!(matches!(
            account_key_open_recovery("acc_1".into(), ak.ak_id(), other.code, r.rec_id.clone(), r.wrap.clone()),
            Err(PassError::InvalidPassword)
        ));
        assert!(!format!("{r:?}").contains(&r.code));
    }

    #[test]
    fn device_approval_by_code_and_by_the_new_devices_qr() {
        let ak = AccountKey::generate("acc_1".into()).unwrap();
        let n = DeviceApprovalKeys::new();
        let r_a = device_approval_nonce();
        let code_a = device_approval_code(
            "req-1".into(),
            "acc_1".into(),
            n.enc_pub(),
            n.commitment(),
            n.reveal(),
            r_a.clone(),
        )
        .unwrap();
        assert_eq!(code_a.len(), 6);
        assert_eq!(n.code("req-1".into(), "acc_1".into(), r_a.clone()).unwrap(), code_a);
        // The QR variant: the approving device reads r_n from the QR.
        let qr = parse_approval_qr(n.approval_qr("req-1".into())).unwrap();
        assert_eq!(qr.enc_pub, n.enc_pub());
        let sealed = ak
            .approve_device_qr(&sk(), qr, n.commitment(), r_a.clone())
            .unwrap();
        let n2 = DeviceApprovalKeys::restore(n.secret()).unwrap();
        let got = n2
            .open("req-1".into(), "acc_1".into(), ak.ak_id(), r_a.clone(), sealed.clone())
            .unwrap();
        assert_eq!(got.account_key().to_bytes(), ak.to_bytes());
        assert_eq!(got.secret_key().bytes(), sk().bytes());
        assert!(n.open("req-2".into(), "acc_1".into(), ak.ak_id(), r_a.clone(), sealed.clone()).is_err());
        assert!(n.open("req-1".into(), "acc_1".into(), ak.ak_id(), device_approval_nonce(), sealed).is_err());
    }

    /// Number matching: the approving device approves only with the 6 digits the new
    /// device shows, typed by the user; a tap, a wrong code or the code of another request does
    /// nothing. The new device then shows the fingerprint of the key it got.
    #[test]
    fn a_device_is_approved_only_with_the_code_typed_from_its_screen() {
        let ak = AccountKey::generate("acc_1".into()).unwrap();
        let n = DeviceApprovalKeys::new();
        let r_a = device_approval_nonce();
        let shown = n.code("req-1".into(), "acc_1".into(), r_a.clone()).unwrap();
        let approve = |typed: &str| {
            ak.approve_device(
                &sk(),
                "req-1".into(),
                n.enc_pub(),
                n.commitment(),
                n.reveal(),
                r_a.clone(),
                typed.to_string(),
            )
        };
        assert!(approve("").is_err());
        let wrong = format!("{:06}", (shown.parse::<u32>().unwrap() + 1) % 1_000_000);
        let err = approve(&wrong).unwrap_err();
        assert!(
            crate::core_message_is(format!("{err}"), "account_key.approval_code_mismatch".into()),
            "{err:?}"
        );
        // An attacker's request (another device's key): its code is on the attacker's screen, so
        // the user can't type it from their own new device.
        let attacker = DeviceApprovalKeys::new();
        let attackers_code = attacker.code("req-1".into(), "acc_1".into(), r_a.clone()).unwrap();
        if attackers_code != shown {
            assert!(approve(&attackers_code).is_err());
        }
        // Typed with a space in the middle: approved.
        let typed = format!("{} {}", &shown[..3], &shown[3..]);
        let sealed = approve(&typed).unwrap();
        let got = n
            .open("req-1".into(), "acc_1".into(), ak.ak_id(), r_a, sealed)
            .unwrap();
        assert_eq!(got.fingerprint(), ak.fingerprint());
    }

    /// A breached service plays the approving device and seals an account key of its own to the
    /// new device: it opens (the service also gave the `ak_id`), but its fingerprint is not the
    /// one the user's other device shows in Settings.
    #[test]
    fn a_key_the_service_sealed_shows_another_fingerprint() {
        let real = AccountKey::generate("acc_1".into()).unwrap();
        let fake = AccountKey::generate("acc_1".into()).unwrap();
        let n = DeviceApprovalKeys::new();
        let r_a = device_approval_nonce();
        let code = n.code("req-1".into(), "acc_1".into(), r_a.clone()).unwrap();
        let sealed = fake
            .approve_device(&sk(), "req-1".into(), n.enc_pub(), n.commitment(), n.reveal(), r_a.clone(), code)
            .unwrap();
        let got = n
            .open("req-1".into(), "acc_1".into(), fake.ak_id(), r_a, sealed)
            .unwrap();
        assert_ne!(got.fingerprint(), real.fingerprint());
        assert_eq!(got.fingerprint(), fake.fingerprint());
    }

    #[test]
    fn device_approval_refuses_a_wrong_reveal() {
        let ak = AccountKey::generate("acc_1".into()).unwrap();
        let n = DeviceApprovalKeys::new();
        let r_a = device_approval_nonce();
        let wrong = device_approval_nonce();
        assert!(device_approval_code("req-1".into(), "acc_1".into(), n.enc_pub(), n.commitment(), wrong.clone(), r_a.clone()).is_err());
        let typed = n.code("req-1".into(), "acc_1".into(), r_a.clone()).unwrap();
        assert!(ak
            .approve_device(&sk(), "req-1".into(), n.enc_pub(), n.commitment(), wrong, r_a.clone(), typed.clone())
            .is_err());
        let m = DeviceApprovalKeys::new();
        assert!(ak
            .approve_device(&sk(), "req-1".into(), m.enc_pub(), n.commitment(), n.reveal(), r_a.clone(), typed)
            .is_err());
        let code_n = n.code("req-1".into(), "acc_1".into(), r_a.clone()).unwrap();
        let code_m = device_approval_code("req-1".into(), "acc_1".into(), m.enc_pub(), m.commitment(), m.reveal(), r_a).unwrap();
        assert_ne!(code_n, code_m);
    }

    #[test]
    fn invitation_qr_only_works_for_the_device_that_scanned_it() {
        let ak = AccountKey::generate("acc_1".into()).unwrap();
        let inv = DeviceInvitation::new();
        let qr_text = inv.qr("inv_1".into());
        let qr = parse_invitation_qr(qr_text).unwrap();
        assert_eq!(qr.token, inv.token());
        let n = DeviceApprovalKeys::new();
        let mac = n.invitation_mac(qr.clone()).unwrap();
        let sealed = ak
            .approve_invitation(&sk(), &inv, "inv_1".into(), n.enc_pub(), mac.clone())
            .unwrap();
        let got = n
            .open_invitation("inv_1".into(), "acc_1".into(), ak.ak_id(), sealed)
            .unwrap();
        assert_eq!(got.account_key().to_bytes(), ak.to_bytes());
        assert_eq!(got.secret_key().bytes(), sk().bytes());
        // A key the service swapped in has no valid MAC; nor does another invitation's.
        let m = DeviceApprovalKeys::new();
        assert!(ak.approve_invitation(&sk(), &inv, "inv_1".into(), m.enc_pub(), mac.clone()).is_err());
        assert!(ak.approve_invitation(&sk(), &inv, "inv_2".into(), n.enc_pub(), mac).is_err());
        let other = DeviceInvitation::new();
        let mac2 = n.invitation_mac(parse_invitation_qr(other.qr("inv_1".into())).unwrap()).unwrap();
        assert!(ak.approve_invitation(&sk(), &inv, "inv_1".into(), n.enc_pub(), mac2).is_err());
        assert!(parse_invitation_qr("passyble:add/v1?inv=x".into()).is_err());
        assert!(!format!("{qr:?}").contains(&qr.mac_key));
    }

    #[test]
    fn the_emergency_kit_qr_round_trips() {
        let kit = emergency_kit("ana+x@example.com".into(), "acc_1".into(), &sk(), Some("CODE".into()));
        assert_eq!(kit.secret_key, sk().text());
        assert!(!kit.setup_qr.contains("CODE"), "the recovery code stays off the QR");
        let back = parse_kit_qr(kit.setup_qr.clone()).unwrap();
        assert_eq!(back.email, "ana+x@example.com");
        assert_eq!(back.account, "acc_1");
        assert_eq!(back.secret_key, sk().text());
        assert!(parse_kit_qr("passyble:kit/v1?e=a&a=b&k=P1-00000".into()).is_err());
        assert!(!format!("{kit:?}").contains(&kit.secret_key));
    }

    #[test]
    fn stored_key_is_checked_against_ak_id() {
        let ak = AccountKey::generate("acc_1".into()).unwrap();
        assert!(AccountKey::from_bytes("acc_1".into(), ak.to_bytes(), ak.ak_id()).is_ok());
        assert!(AccountKey::from_bytes("acc_2".into(), ak.to_bytes(), ak.ak_id()).is_err());
        assert_eq!(ak.ak_id().len(), 22);
        assert_eq!(ak.fingerprint().len(), 19);
    }

    #[test]
    fn an_admin_recovers_the_account_key_for_a_family_member() {
        use crate::{admin_recovery_approve, admin_recovery_request, org_recovery_create, OrgKind, UserKeyset};
        let admin = UserKeyset::generate("acc_dad").unwrap();
        let home = crate::vault::test_home_pinning(&[admin.public_keys()]);
        let key =
            org_recovery_create(&admin, "org_home", OrgKind::Family, vec![], &home).unwrap();
        let ak = AccountKey::generate("acc_mia".into()).unwrap();
        let enrollment = ak
            .admin_recovery_enroll(key.clone(), admin.public_keys(), OrgKind::Family, &home)
            .unwrap();
        assert_eq!(enrollment.vault_id, format!("ak:{}", ak.ak_id()));
        let request = admin_recovery_request("org_home", "acc_mia", &enrollment.vault_id).unwrap();
        let approval =
            admin_recovery_approve(
                key,
                &admin,
                enrollment,
                request.request.clone(),
                &crate::recovery_request_code(request.request.clone()).unwrap(),
            )
            .unwrap();
        let opened =
            account_key_from_admin_recovery(approval.clone(), request.secret.clone(), admin.public_keys())
                .unwrap();
        assert_eq!(opened.to_bytes(), ak.to_bytes());
        let mut other = approval;
        other.vault_id = "some-vault".into();
        assert!(account_key_from_admin_recovery(other, request.secret, admin.public_keys()).is_err());
    }

    /// The shared vectors (`core/tests/account_key_vectors.json`), from fixed inputs and nonces.
    /// `PASS_WRITE_VECTORS=1` writes the file instead of checking it.
    fn vectors() -> serde_json::Value {
        use serde_json::json;
        let b64 = |b: &[u8]| b64url_encode(b.to_vec());
        let secret_key = SecretKey::from_array([0x99; SECRET_KEY_LEN]);
        let mut passwords = Vec::new();
        for (password, salt) in [
            ("correct horse battery staple", "AAECAwQFBgcICQoLDA0ODw"),
            // NFC: the same password composed and decomposed gives the same keys.
            ("caf\u{e9} cr\u{e8}me br\u{fb}l\u{e9}e 2026", "_____________________w"),
            ("cafe\u{301} cre\u{300}me bru\u{302}le\u{301}e 2026", "_____________________w"),
            ("\u{43f}\u{430}\u{440}\u{43e}\u{43b}\u{44c} \u{2713} Passyble", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"),
        ] {
            let kdf = AccountKdf::default();
            let pw = AccountPassword::derive(password, &secret_key, salt, &kdf).unwrap();
            passwords.push(json!({
                "password": password,
                "password_utf8_hex": crate::encoding::hex(password.as_bytes()),
                "salt": salt,
                "kdf": kdf,
                "auth_pub": pw.auth_pub(),
                "wrap_key": b64(pw.wrap_key.as_slice()),
            }));
        }
        let account = "acc_7Qh2xY";
        let email = "ana@example.com";
        let ak = AccountKey::from_key(account.into(), Key::from_array([0x11; 32])).unwrap();
        let nonce = [0x22u8; NONCE_LEN];
        let wrap = |key: &[u8; KEY_LEN], plain: &[u8], aad: &[u8]| {
            json!({
                "aad": String::from_utf8(aad.to_vec()).unwrap(),
                "nonce": b64(&nonce),
                "ct": b64(&crypto::seal_with_nonce(key, &nonce, plain, aad).unwrap()),
            })
        };
        let pw = AccountPassword::derive("correct horse battery staple", &secret_key, "AAECAwQFBgcICQoLDA0ODw", &AccountKdf::default()).unwrap();
        let pw_aad = pw.wrap_aad(account, &ak.ak_id).unwrap();
        let sign_in_nonce = "bm9uY2UtZm9yLXNpZ24taW4";
        let sign_in = pw
            .sign_in(email.into(), sign_in_nonce.into(), "Laptop".into(), "windows".into())
            .unwrap();
        let prf_output = [0x33u8; 32];
        let prf_k = prf_key(&prf_output).unwrap();
        let prf_aad = AccountKey::prf_aad(account, &ak.ak_id, "Y3JlZC0x").unwrap();
        let secret = [0x44u8; 16];
        let code = crate::recovery::encode(&secret);
        let rec_id = "0f5b8f8e-8e43-4b8f-9a39-6a3c2b7d9e10";
        let rec_k = Key::from_array(*hkdf_sha256(&secret, RECOVERY_INFO));
        let rec_aad = recovery_aad(account, &ak.ak_id, rec_id).unwrap();
        let signing = recovery_signing_key(&secret);
        let challenge = "c2lnbi1tZS1wbGVhc2U";
        let rec_sig = sign_b64(&signing, &recovery_message(account, rec_id, challenge).unwrap());
        let vault_id = "6c1d8a52-7d6f-4c0e-8f53-1b9e2a4d7c31";
        let vk = [0x55u8; 32];
        let mut vk_aad = b"pass/account-vk/v1:".to_vec();
        vk_aad.extend(serde_json::to_vec(&(vault_id, account, &ak.ak_id)).unwrap());
        let enc_sk = [0x66u8; 32];
        let enc_pub = hpke_public_of(&enc_sk).unwrap();
        let r_n = [0x77u8; 32];
        let r_a = [0x88u8; 32];
        let commitment = commitment_of(&enc_pub, &r_n);
        let t = Transcript::checked("req_1", account, &b64(&enc_pub), &commitment, &b64(&r_n), &b64(&r_a)).unwrap();
        let body = br#"{"salt":"AAECAwQFBgcICQoLDA0ODw"}"#;
        let req_nonce = "a2V5LWNoYW5nZS1ub25jZQ";
        let req_sig = ak
            .sign_request(req_nonce.into(), "PUT".into(), "/v1/account-key/password".into(), body.to_vec())
            .unwrap();
        let mac_key = [0xabu8; 32];
        json!({
            "comment": "Passyble password, Secret Key and account key. base64url without padding throughout; wraps are XChaCha20-Poly1305 with the given nonce; signatures Ed25519. Checked by the pass-core tests and the account service.",
            "secret_key": { "bytes": b64(secret_key.bytes()), "text": secret_key.text() },
            "passwords": passwords,
            "account": account,
            "email": email,
            "sign_in": {
                "nonce": sign_in_nonce, "device_name": "Laptop", "platform": "windows",
                "message": String::from_utf8(sign_in_message(email, sign_in_nonce, "Laptop", "windows").unwrap()).unwrap(),
                "auth_pub": pw.auth_pub(), "sig": sign_in,
            },
            "ak": b64(ak.ak.as_slice()),
            "ak_id": ak.ak_id,
            "ak_sign_pub": ak.ak_sign_pub(),
            "request_signature": {
                "nonce": req_nonce, "method": "PUT", "path": "/v1/account-key/password",
                "body": String::from_utf8(body.to_vec()).unwrap(),
                "message": String::from_utf8(request_message(account, req_nonce, "PUT", "/v1/account-key/password", body).unwrap()).unwrap(),
                "sig": req_sig,
            },
            "password_wrap": wrap(&pw.wrap_key, ak.ak.as_slice(), &pw_aad),
            "sk_wrap": wrap(&ak.sk_wrap_key(), secret_key.bytes(), &ak.sk_wrap_aad().unwrap()),
            "prf": {
                "prf_output": b64(&prf_output),
                "credential_id": "Y3JlZC0x",
                "key": b64(prf_k.as_slice()),
                "wrap": wrap(&prf_k, ak.ak.as_slice(), &prf_aad),
            },
            "recovery": {
                "secret": b64(&secret),
                "code": code.to_string(),
                "rec_id": rec_id,
                "key": b64(rec_k.as_slice()),
                "wrap": wrap(&rec_k, ak.ak.as_slice(), &rec_aad),
                "verify_pub": public_b64(&signing),
                "challenge": challenge,
                "message": String::from_utf8(recovery_message(account, rec_id, challenge).unwrap()).unwrap(),
                "sig": rec_sig,
            },
            "vault_slot": {
                "vault_id": vault_id,
                "vk": b64(&vk),
                "wrap": wrap(&ak.ak, &vk, &vk_aad),
            },
            "device_approval": {
                "request_id": "req_1",
                "enc_pub": b64(&enc_pub),
                "r_n": b64(&r_n),
                "r_a": b64(&r_a),
                "commitment": commitment,
                "code": t.code().unwrap(),
                "seal_info": String::from_utf8(t.seal_info().unwrap()).unwrap(),
                "qr": format!("passyble:approve/v1?id=req_1&k={}&r={}", b64(&enc_pub), b64(&r_n)),
            },
            "invitation": {
                "invitation_id": "inv_1",
                "mac_key": b64(&mac_key),
                "enc_pub": b64(&enc_pub),
                "mac": invitation_mac(&mac_key, "inv_1", &b64(&enc_pub)),
                "seal_info": String::from_utf8(invitation_info("inv_1", account, &b64(&enc_pub)).unwrap()).unwrap(),
            },
            "emergency_kit_qr": emergency_kit(email.into(), account.into(), &secret_key, None).setup_qr,
        })
    }

    #[test]
    fn shared_vectors() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/account_key_vectors.json");
        let ours = vectors();
        if std::env::var_os("PASS_WRITE_VECTORS").is_some() {
            let mut text = serde_json::to_string_pretty(&ours).unwrap();
            text.push('\n');
            std::fs::write(&path, text).unwrap();
            return;
        }
        let theirs: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(ours, theirs);
        assert_eq!(ours["passwords"][1]["auth_pub"], ours["passwords"][2]["auth_pub"]);
        assert_eq!(ours["passwords"][1]["wrap_key"], ours["passwords"][2]["wrap_key"]);
    }
}
