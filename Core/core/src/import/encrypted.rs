//! Password-protected exports of other apps: detection, key-derivation bounds, and the encrypted
//! JSON formats of Bitwarden, Aegis and 2FAS. KDF parameters come from the file, so they are bounded
//! and heavier files are refused instead of hanging or exhausting memory. Keys and plaintext are
//! zeroized when dropped.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{invalid, json_formats, Collector, ImportFormat, MAX_IMPORT_BYTES};
use crate::i18n::tr;
use crate::{PassError, Result};

/// The secrets an encrypted export is opened with.
pub(crate) struct Unlock<'a> {
    pub password: &'a str,
    /// A KeePass key file, if the database needs one.
    #[cfg_attr(not(feature = "import-kdbx"), allow(dead_code))]
    pub key_file: Option<&'a [u8]>,
}

/// A password-protected export that [`crate::import_parse_with_password`] can open. No secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ImportEncryption {
    /// What the file is, in the core's language: "Bitwarden (JSON)", "KeePass (KDBX)", "Aegis",
    /// "2FAS", "Proton Pass", "Passyble (JSON)", "PGP" or "ZIP".
    pub source: String,
    /// The export format, when it is known before the file is opened (not for a PGP file or a
    /// ZIP whose members are encrypted).
    pub format: Option<ImportFormat>,
    /// A KeePass database: it may need a key file, with or instead of a password.
    pub key_file: bool,
}

/// The kinds of encrypted export.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Passyble,
    Bitwarden,
    /// Encrypted with the Bitwarden account key: can't be opened here.
    BitwardenAccount,
    Aegis,
    TwoFas,
    Keepass,
    /// An OpenPGP message encrypted with a passphrase (Proton Pass, or any such file).
    Pgp,
    /// A Proton Pass ZIP whose `data.pgp` is encrypted with a passphrase.
    ProtonZip,
    /// A ZIP with password-protected members (ZipCrypto or AES).
    Zip,
}

impl Kind {
    pub fn format(self) -> Option<ImportFormat> {
        match self {
            Self::Passyble => Some(ImportFormat::PassybleJson),
            Self::Bitwarden | Self::BitwardenAccount => Some(ImportFormat::BitwardenJson),
            Self::Aegis => Some(ImportFormat::Aegis),
            Self::TwoFas => Some(ImportFormat::TwoFas),
            Self::Keepass => Some(ImportFormat::Keepass),
            Self::ProtonZip => Some(ImportFormat::ProtonPass),
            Self::Pgp | Self::Zip => None,
        }
    }

    pub fn name(self) -> String {
        match self {
            Self::Pgp => tr!("import.encrypted_kind.pgp"),
            Self::Zip => tr!("import.encrypted_kind.zip"),
            other => other.format().map(ImportFormat::name).unwrap_or_default(),
        }
    }
}

/// Whether `data` is a password-protected export this build can open, and which. `None` for any other
/// file, including ones that can't be opened with a password (Bitwarden's account-restricted export).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn import_encryption(data: Vec<u8>, file_name: String) -> Option<ImportEncryption> {
    let _ = file_name;
    let kind = detect(&data).filter(|k| *k != Kind::BitwardenAccount)?;
    Some(ImportEncryption {
        source: kind.name(),
        format: kind.format(),
        key_file: kind == Kind::Keepass,
    })
}

/// The kind of encrypted export `data` is, if any.
pub(crate) fn detect(data: &[u8]) -> Option<Kind> {
    if data.len() > MAX_IMPORT_BYTES {
        return None;
    }
    if crate::export::is_encrypted(data) {
        return Some(Kind::Passyble);
    }
    if data.starts_with(super::KDBX_MAGIC) {
        return cfg!(feature = "import-kdbx").then_some(Kind::Keepass);
    }
    if data.starts_with(super::ZIP_MAGIC) {
        return super::archive::encryption(data);
    }
    if super::pgp::is_binary(data) {
        return cfg!(feature = "import-pgp").then_some(Kind::Pgp);
    }
    let text = super::decode_text(data, &mut Collector::default());
    let trimmed = text.trim_start();
    if trimmed.starts_with("-----BEGIN PGP MESSAGE") {
        return cfg!(feature = "import-pgp").then_some(Kind::Pgp);
    }
    if trimmed.starts_with('{') && has_marker(trimmed) {
        let value: Value = serde_json::from_str(trimmed).ok()?;
        return json_kind(&value);
    }
    None
}

/// Cheap test before parsing a JSON file only to look for encryption.
pub(crate) fn has_marker(text: &str) -> bool {
    ["\"encrypted\"", "\"servicesEncrypted\"", "\"slots\""]
        .iter()
        .any(|m| text.contains(m))
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s.eq_ignore_ascii_case("true"),
        Some(Value::Number(n)) => n.as_i64() != Some(0),
        _ => false,
    }
}

/// The kind of an encrypted JSON export (Bitwarden, Aegis, 2FAS), if `v` is one.
pub(crate) fn json_kind(v: &Value) -> Option<Kind> {
    let obj = v.as_object()?;
    if truthy(obj.get("encrypted"))
        && (obj.contains_key("data")
            || obj.contains_key("items")
            || obj.contains_key("encKeyValidation_DO_NOT_EDIT"))
    {
        return Some(if truthy(obj.get("passwordProtected")) {
            Kind::Bitwarden
        } else {
            Kind::BitwardenAccount
        });
    }
    if obj.contains_key("header") && obj.get("db").is_some_and(Value::is_string) {
        return Some(Kind::Aegis);
    }
    let encrypted_services = obj
        .get("servicesEncrypted")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.trim().is_empty());
    let no_services = obj
        .get("services")
        .and_then(Value::as_array)
        .is_none_or(|s| s.is_empty());
    if encrypted_services && no_services {
        return Some(Kind::TwoFas);
    }
    None
}

/// "This … export is protected with a password", for a file that reaches the parser without one.
pub(crate) fn password_needed(kind: Kind) -> PassError {
    invalid(tr!("import.password_needed", format = kind.name()))
}

pub(crate) fn damaged(kind: Kind) -> PassError {
    invalid(tr!("import.encrypted_damaged", format = kind.name()))
}

pub(crate) fn too_heavy(kind: Kind) -> PassError {
    invalid(tr!("import.kdf_too_heavy", format = kind.name()))
}

pub(crate) fn unsupported_kdf(kind: Kind) -> PassError {
    invalid(tr!("import.kdf_unsupported", format = kind.name()))
}

/// Opens an encrypted JSON export (`kind` from [`json_kind`]) and parses what it holds.
pub(crate) fn parse_json(
    v: &Value,
    kind: Kind,
    format: Option<ImportFormat>,
    c: &mut Collector,
    unlock: Option<&Unlock<'_>>,
) -> Result<ImportFormat> {
    let target = kind.format().unwrap_or(ImportFormat::BitwardenJson);
    if format.is_some_and(|f| f != target) {
        return Err(invalid(tr!(
            "import.not_format",
            format = format.map(ImportFormat::name).unwrap_or_default()
        )));
    }
    if kind == Kind::BitwardenAccount {
        return Err(invalid(tr!("import.bitwarden_account_restricted")));
    }
    let unlock = unlock.ok_or_else(|| password_needed(kind))?;
    if unlock.password.is_empty() {
        return Err(invalid(tr!("import.enter_password")));
    }
    let plain = match kind {
        Kind::Bitwarden => bitwarden(v, unlock.password)?,
        Kind::Aegis => aegis(v, unlock.password)?,
        Kind::TwoFas => twofas(v, unlock.password)?,
        _ => return Err(password_needed(kind)),
    };
    // A decrypted export that claims to be encrypted again would loop: refuse it.
    if json_kind(&plain).is_some() {
        return Err(damaged(kind));
    }
    json_formats::parse(&plain, target, c)?;
    Ok(target)
}

/// Most PBKDF2 iterations accepted (Bitwarden allows up to 2 000 000).
pub(crate) const MAX_PBKDF2_ITERATIONS: u32 = 5_000_000;
/// Most Argon2 memory accepted, in KiB (1 GiB, as for Passyble's own exports).
pub(crate) const MAX_ARGON2_KIB: u64 = 1024 * 1024;
/// Most Argon2 passes accepted.
pub(crate) const MAX_ARGON2_PASSES: u64 = 100;
/// Most Argon2 lanes accepted.
pub(crate) const MAX_ARGON2_LANES: u64 = 64;
/// Most Argon2 work accepted: memory (KiB) × passes (16 GiB-passes: 1 GiB × 16, 64 MiB × 256).
pub(crate) const MAX_ARGON2_WORK: u64 = 16 * 1024 * 1024;
/// Most scrypt memory accepted (128 · r · N bytes: 1 GiB; Aegis uses 32 MiB).
pub(crate) const MAX_SCRYPT_BYTES: u64 = 1024 * 1024 * 1024;
/// Most scrypt work accepted (N · r · p; Aegis uses 2^18).
pub(crate) const MAX_SCRYPT_WORK: u64 = 1 << 26;
/// Most AES-KDF rounds accepted (KeePass; its "1 second" default is a few million to some tens
/// of millions on current PCs).
#[cfg_attr(not(feature = "import-kdbx"), allow(dead_code))]
pub(crate) const MAX_AES_KDF_ROUNDS: u64 = 300_000_000;

pub(crate) fn check_pbkdf2(kind: Kind, iterations: u64) -> Result<u32> {
    if iterations == 0 {
        return Err(damaged(kind));
    }
    if iterations > u64::from(MAX_PBKDF2_ITERATIONS) {
        return Err(too_heavy(kind));
    }
    Ok(iterations as u32)
}

/// Checks Argon2 parameters (memory in KiB). Returns them as `argon2` takes them.
pub(crate) fn check_argon2(
    kind: Kind,
    memory_kib: u64,
    passes: u64,
    lanes: u64,
) -> Result<(u32, u32, u32)> {
    if memory_kib == 0 || passes == 0 || lanes == 0 || memory_kib < 8 * lanes {
        return Err(damaged(kind));
    }
    if memory_kib > MAX_ARGON2_KIB
        || passes > MAX_ARGON2_PASSES
        || lanes > MAX_ARGON2_LANES
        || memory_kib.saturating_mul(passes) > MAX_ARGON2_WORK
    {
        return Err(too_heavy(kind));
    }
    Ok((memory_kib as u32, passes as u32, lanes as u32))
}

/// Checks scrypt parameters. Returns log2(N).
pub(crate) fn check_scrypt(kind: Kind, n: u64, r: u64, p: u64) -> Result<u8> {
    if n < 2 || !n.is_power_of_two() || r == 0 || p == 0 {
        return Err(damaged(kind));
    }
    let memory = 128u64.saturating_mul(r).saturating_mul(n);
    let work = n.saturating_mul(r).saturating_mul(p);
    if memory > MAX_SCRYPT_BYTES || work > MAX_SCRYPT_WORK || r > 64 || p > 64 {
        return Err(too_heavy(kind));
    }
    Ok(n.trailing_zeros() as u8)
}

#[cfg_attr(not(feature = "import-kdbx"), allow(dead_code))]
pub(crate) fn check_aes_kdf(kind: Kind, rounds: u64) -> Result<()> {
    if rounds > MAX_AES_KDF_ROUNDS {
        return Err(too_heavy(kind));
    }
    Ok(())
}

/// Standard base64, with or without padding; whitespace (Android's line breaks) is ignored.
pub(crate) fn b64(s: &str) -> Option<Vec<u8>> {
    let clean: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    STANDARD
        .decode(&clean)
        .or_else(|_| STANDARD_NO_PAD.decode(clean.trim_end_matches('=')))
        .ok()
}

pub(crate) fn hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn u64_of(v: &Value, key: &str) -> Option<u64> {
    v.get(key).and_then(|x| {
        x.as_u64()
            .or_else(|| x.as_str().and_then(|s| s.trim().parse().ok()))
    })
}

/// AES-256-GCM; `ct` ends with the 16-byte tag. `None` if it doesn't authenticate.
fn gcm_open(key: &[u8], nonce: &[u8], ct: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if key.len() != 32 || nonce.len() != 12 || ct.len() < 16 {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .ok()
        .map(Zeroizing::new)
}

fn json_of(kind: Kind, plain: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(plain).map_err(|_| damaged(kind))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    serde_json::from_str(text).map_err(|_| damaged(kind))
}

/// Bitwarden's stretched user key: AES-256-CBC key and HMAC-SHA256 key.
struct BitwardenKey {
    enc: Zeroizing<[u8; 32]>,
    mac: Zeroizing<[u8; 32]>,
}

fn bitwarden_key(v: &Value, password: &str) -> Result<BitwardenKey> {
    const KIND: Kind = Kind::Bitwarden;
    let salt = str_of(v, "salt");
    if salt.is_empty() {
        return Err(damaged(KIND));
    }
    let iterations = u64_of(v, "kdfIterations").ok_or_else(|| damaged(KIND))?;
    let mut master = Zeroizing::new([0u8; 32]);
    match u64_of(v, "kdfType").unwrap_or(0) {
        0 => {
            let rounds = check_pbkdf2(KIND, iterations)?;
            pbkdf2::pbkdf2_hmac::<Sha256>(
                password.as_bytes(),
                salt.as_bytes(),
                rounds,
                master.as_mut(),
            );
        }
        1 => {
            let memory_mib = u64_of(v, "kdfMemory").ok_or_else(|| damaged(KIND))?;
            let lanes = u64_of(v, "kdfParallelism").ok_or_else(|| damaged(KIND))?;
            let (m, t, p) = check_argon2(KIND, memory_mib.saturating_mul(1024), iterations, lanes)?;
            let params = argon2::Params::new(m, t, p, Some(32)).map_err(|_| damaged(KIND))?;
            let salt_hash = Sha256::digest(salt.as_bytes());
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                .hash_password_into(password.as_bytes(), &salt_hash, master.as_mut())
                .map_err(|_| damaged(KIND))?;
        }
        _ => return Err(unsupported_kdf(KIND)),
    }
    let hk = hkdf::Hkdf::<Sha256>::from_prk(master.as_ref()).map_err(|_| damaged(KIND))?;
    let mut key = BitwardenKey {
        enc: Zeroizing::new([0u8; 32]),
        mac: Zeroizing::new([0u8; 32]),
    };
    hk.expand(b"enc", key.enc.as_mut())
        .and_then(|_| hk.expand(b"mac", key.mac.as_mut()))
        .map_err(|_| damaged(KIND))?;
    Ok(key)
}

/// Why an EncString didn't open.
#[derive(Debug, PartialEq, Eq)]
enum EncStringError {
    /// Not a well-formed type 2 EncString.
    Malformed,
    /// The MAC doesn't match: wrong key (or altered data).
    Mac,
}

/// Opens a type 2 EncString (`2.<iv>|<ct>|<mac>`, AES-256-CBC + HMAC-SHA256).
fn open_enc_string(
    s: &str,
    key: &BitwardenKey,
) -> std::result::Result<Zeroizing<Vec<u8>>, EncStringError> {
    let rest = s
        .trim()
        .strip_prefix("2.")
        .ok_or(EncStringError::Malformed)?;
    let mut parts = rest.split('|');
    let (Some(iv), Some(ct), Some(mac), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(EncStringError::Malformed);
    };
    let iv = b64(iv)
        .filter(|v| v.len() == 16)
        .ok_or(EncStringError::Malformed)?;
    let ct = b64(ct)
        .filter(|v| !v.is_empty() && v.len().is_multiple_of(16))
        .ok_or(EncStringError::Malformed)?;
    let mac = b64(mac)
        .filter(|v| v.len() == 32)
        .ok_or(EncStringError::Malformed)?;
    let mut hmac = <Hmac<Sha256> as Mac>::new_from_slice(key.mac.as_ref())
        .map_err(|_| EncStringError::Malformed)?;
    hmac.update(&iv);
    hmac.update(&ct);
    hmac.verify_slice(&mac).map_err(|_| EncStringError::Mac)?;
    let plain = cbc::Decryptor::<aes::Aes256>::new_from_slices(key.enc.as_ref(), &iv)
        .map_err(|_| EncStringError::Malformed)?
        .decrypt_padded_vec_mut::<Pkcs7>(&ct)
        .map_err(|_| EncStringError::Malformed)?;
    Ok(Zeroizing::new(plain))
}

/// Opens a password-protected Bitwarden export: the plain Bitwarden JSON it holds.
fn bitwarden(v: &Value, password: &str) -> Result<Value> {
    const KIND: Kind = Kind::Bitwarden;
    let validation = str_of(v, "encKeyValidation_DO_NOT_EDIT");
    let data = str_of(v, "data");
    if validation.is_empty() || data.is_empty() {
        return Err(damaged(KIND));
    }
    let key = bitwarden_key(v, password)?;
    match open_enc_string(validation, &key) {
        Ok(_) => {}
        Err(EncStringError::Mac) => return Err(PassError::InvalidPassword),
        Err(EncStringError::Malformed) => return Err(damaged(KIND)),
    }
    let plain = open_enc_string(data, &key).map_err(|_| damaged(KIND))?;
    json_of(KIND, &plain)
}

/// Most password slots tried (each costs one scrypt).
const MAX_AEGIS_SLOTS: usize = 8;

fn aegis(v: &Value, password: &str) -> Result<Value> {
    const KIND: Kind = Kind::Aegis;
    let header = v.get("header").ok_or_else(|| damaged(KIND))?;
    let slots: Vec<&Value> = header
        .get("slots")
        .and_then(Value::as_array)
        .map(|s| s.iter().filter(|s| u64_of(s, "type") == Some(1)).collect())
        .unwrap_or_default();
    if slots.is_empty() {
        return Err(invalid(tr!("import.aegis_no_password_slot")));
    }
    // Check every slot's parameters before deriving anything.
    let mut checked = Vec::new();
    for slot in slots.iter().take(MAX_AEGIS_SLOTS) {
        let (n, r, p) = (
            u64_of(slot, "n").ok_or_else(|| damaged(KIND))?,
            u64_of(slot, "r").ok_or_else(|| damaged(KIND))?,
            u64_of(slot, "p").ok_or_else(|| damaged(KIND))?,
        );
        let log_n = check_scrypt(KIND, n, r, p)?;
        checked.push((*slot, log_n, r as u32, p as u32));
    }
    let mut master = None;
    for (slot, log_n, r, p) in checked {
        let salt = hex(str_of(slot, "salt")).ok_or_else(|| damaged(KIND))?;
        let wrapped = hex(str_of(slot, "key")).ok_or_else(|| damaged(KIND))?;
        let kp = slot.get("key_params").ok_or_else(|| damaged(KIND))?;
        let nonce = hex(str_of(kp, "nonce")).ok_or_else(|| damaged(KIND))?;
        let tag = hex(str_of(kp, "tag")).ok_or_else(|| damaged(KIND))?;
        let params = scrypt::Params::new(log_n, r, p, 32).map_err(|_| damaged(KIND))?;
        let mut derived = Zeroizing::new([0u8; 32]);
        scrypt::scrypt(password.as_bytes(), &salt, &params, derived.as_mut())
            .map_err(|_| damaged(KIND))?;
        let mut ct = wrapped;
        ct.extend_from_slice(&tag);
        if let Some(key) = gcm_open(derived.as_ref(), &nonce, &ct) {
            master = Some(key);
            break;
        }
    }
    let master = master.ok_or(PassError::InvalidPassword)?;
    let params = header.get("params").ok_or_else(|| damaged(KIND))?;
    let nonce = hex(str_of(params, "nonce")).ok_or_else(|| damaged(KIND))?;
    let tag = hex(str_of(params, "tag")).ok_or_else(|| damaged(KIND))?;
    let mut ct = b64(str_of(v, "db")).ok_or_else(|| damaged(KIND))?;
    ct.extend_from_slice(&tag);
    let plain = gcm_open(&master, &nonce, &ct).ok_or_else(|| damaged(KIND))?;
    let db = json_of(KIND, &plain)?;
    Ok(json!({
        "version": v.get("version").cloned().unwrap_or(Value::from(1)),
        "header": { "slots": null, "params": null },
        "db": db,
    }))
}

/// 2FAS derives its backup key with PBKDF2-HMAC-SHA256, 10 000 iterations, 256 bits.
const TWOFAS_ITERATIONS: u32 = 10_000;

/// `<ciphertext+tag>:<salt>:<iv>`, each base64.
fn twofas_parts(s: &str) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut parts = s.trim().split(':');
    let (Some(ct), Some(salt), Some(iv), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    Some((b64(ct)?, b64(salt).filter(|s| !s.is_empty())?, b64(iv)?))
}

fn twofas(v: &Value, password: &str) -> Result<Value> {
    const KIND: Kind = Kind::TwoFas;
    let (ct, salt, iv) =
        twofas_parts(str_of(v, "servicesEncrypted")).ok_or_else(|| damaged(KIND))?;
    // One derivation per salt (the reference and the services share one).
    let mut keys: Vec<(Vec<u8>, Zeroizing<[u8; 32]>)> = Vec::new();
    let mut key_for = |salt: &[u8]| -> Zeroizing<[u8; 32]> {
        if let Some((_, k)) = keys.iter().find(|(s, _)| s == salt) {
            return k.clone();
        }
        let mut k = Zeroizing::new([0u8; 32]);
        pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, TWOFAS_ITERATIONS, k.as_mut());
        keys.push((salt.to_vec(), k.clone()));
        k
    };
    let reference = str_of(v, "reference");
    let verified = if reference.trim().is_empty() {
        false
    } else {
        let (rct, rsalt, riv) = twofas_parts(reference).ok_or_else(|| damaged(KIND))?;
        gcm_open(key_for(&rsalt).as_ref(), &riv, &rct).ok_or(PassError::InvalidPassword)?;
        true
    };
    let plain = gcm_open(key_for(&salt).as_ref(), &iv, &ct).ok_or(if verified {
        damaged(KIND)
    } else {
        PassError::InvalidPassword
    })?;
    let services = json_of(KIND, &plain)?;
    if !services.is_array() {
        return Err(damaged(KIND));
    }
    let mut out = v.clone();
    if let Some(obj) = out.as_object_mut() {
        obj.remove("servicesEncrypted");
        obj.remove("reference");
        obj.insert("services".into(), services);
    }
    Ok(out)
}

/// Builders of encrypted exports for the tests (the formats as the apps write them).
#[cfg(test)]
pub(crate) mod testing {
    use aes::cipher::BlockEncryptMut;

    use super::*;

    fn gcm_seal(key: &[u8], nonce: &[u8], plain: &[u8]) -> Vec<u8> {
        Aes256Gcm::new_from_slice(key)
            .unwrap()
            .encrypt(Nonce::from_slice(nonce), plain)
            .unwrap()
    }

    fn enc_string(key: &BitwardenKey, iv: [u8; 16], plain: &[u8]) -> String {
        let ct = cbc::Encryptor::<aes::Aes256>::new_from_slices(key.enc.as_ref(), &iv)
            .unwrap()
            .encrypt_padded_vec_mut::<Pkcs7>(plain);
        let mut hmac = <Hmac<Sha256> as Mac>::new_from_slice(key.mac.as_ref()).unwrap();
        hmac.update(&iv);
        hmac.update(&ct);
        let mac = hmac.finalize().into_bytes();
        format!(
            "2.{}|{}|{}",
            STANDARD.encode(iv),
            STANDARD.encode(&ct),
            STANDARD.encode(mac)
        )
    }

    /// A Bitwarden password-protected export of `plain` (a plain Bitwarden JSON export).
    /// `kdf`: `json!({"kdfType": 0, "kdfIterations": 1000})` or the Argon2id fields.
    pub fn bitwarden(plain: &str, password: &str, kdf: Value) -> String {
        let mut file = json!({
            "encrypted": true,
            "passwordProtected": true,
            "salt": "c2FsdHNhbHRzYWx0c2FsdA==",
            "kdfMemory": null,
            "kdfParallelism": null,
        });
        for (k, val) in kdf.as_object().unwrap() {
            file[k] = val.clone();
        }
        let key = bitwarden_key(&file, password).unwrap();
        file["encKeyValidation_DO_NOT_EDIT"] =
            enc_string(&key, [7; 16], b"1f0a4c2e-5b6d-4e7f-8a9b-0c1d2e3f4a5b").into();
        file["data"] = enc_string(&key, [9; 16], plain.as_bytes()).into();
        file.to_string()
    }

    /// An Aegis encrypted vault holding `db` (the plain `db` object), scrypt N = 2^`log_n`.
    pub fn aegis(db: &Value, password: &str, log_n: u8) -> String {
        let master = [0x42u8; 32];
        let salt = [0x11u8; 32];
        let params = scrypt::Params::new(log_n, 8, 1, 32).unwrap();
        let mut derived = [0u8; 32];
        scrypt::scrypt(password.as_bytes(), &salt, &params, &mut derived).unwrap();
        let key_nonce = [0x21u8; 12];
        let wrapped = gcm_seal(&derived, &key_nonce, &master);
        let (wct, wtag) = wrapped.split_at(32);
        let db_nonce = [0x31u8; 12];
        let sealed = gcm_seal(&master, &db_nonce, db.to_string().as_bytes());
        let (dct, dtag) = sealed.split_at(sealed.len() - 16);
        let hx = crate::encoding::hex;
        json!({
            "version": 1,
            "header": {
                "slots": [
                    { "type": 2, "uuid": "b", "key": hx(&[0u8; 32]), "key_params": { "nonce": hx(&[0u8; 12]), "tag": hx(&[0u8; 16]) } },
                    {
                        "type": 1, "uuid": "a", "key": hx(wct),
                        "key_params": { "nonce": hx(&key_nonce), "tag": hx(wtag) },
                        "n": 1u64 << log_n, "r": 8, "p": 1, "salt": hx(&salt),
                        "repaired": true, "is_backup": false
                    }
                ],
                "params": { "nonce": hx(&db_nonce), "tag": hx(dtag) }
            },
            "db": STANDARD.encode(dct),
        })
        .to_string()
    }

    /// A 2FAS encrypted backup of `services` (the plain services array), as 2FAS for Android
    /// writes it (base64 with line breaks).
    pub fn twofas(services: &Value, password: &str) -> String {
        let salt = [0x55u8; 256];
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, TWOFAS_ITERATIONS, &mut key);
        let wrap = |b: &[u8]| {
            let s = STANDARD.encode(b);
            s.as_bytes()
                .chunks(76)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
                + "\n"
        };
        let part = |plain: &[u8]| {
            let nonce: [u8; 12] = rand::random();
            let ct = gcm_seal(&key, &nonce, plain);
            format!("{}:{}:{}", wrap(&ct), wrap(&salt), wrap(&nonce))
        };
        json!({
            "services": [],
            "groups": [],
            "updatedAt": 1_700_000_000_000u64,
            "schemaVersion": 4,
            "appVersionCode": 5000000,
            "appVersionName": "5.0.0",
            "appOrigin": "android",
            "servicesEncrypted": part(services.to_string().as_bytes()),
            "reference": part(b"tRViSsLKzd86Hprh4ceC2OP7xazn4rrt4xhfEUbOjxLX8Rc3mkISXE0lWbmnWfggogbBJhtYgpK6fMl1D6mtsy92R3HkdGfwuXbzLebqVFJsR7IZ2w58t938iymwG4824igYy1wi6n2WDpO1Q1P69zwJGs2F5a1qP4MyIiDSD7NCV2OvidXQCBnDlGfmz0f1BQySRkkt4ryiJeCjD2o4QsveJ9uDBUn8ELyOrESv5R5DMDkD4iAF8TXU7KyoJujd"),
        })
        .to_string()
    }
}
