//! Exports: a Bitwarden-compatible CSV, Passyble's own JSON, and that JSON encrypted with a password.
//! Every export holds secrets in readable form; items in the trash are left out. The encrypted form
//! is XChaCha20-Poly1305 under an Argon2id key, with AAD `"passyble/export/v1:"` plus the `kdf`
//! object serialized in the order alg, m_kib, t, p, salt.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::encoding::{b64_decode, b64_encode};
use crate::i18n::tr;
use crate::import::{invalid, normalize_totp, Collector};
use crate::model::{Item, ItemKind};
use crate::vault::{KdfParams, Vault};
use crate::{PassError, Result};

/// `format` of a Passyble JSON export.
pub(crate) const EXPORT_FORMAT: &str = "passyble-export";
/// `format` of an encrypted Passyble export.
pub(crate) const ENCRYPTED_FORMAT: &str = "passyble-export-encrypted";
const VERSION: u32 = 1;
const EXPORT_AAD: &str = "passyble/export/v1:";

#[derive(Serialize)]
struct ExportFile<'a> {
    format: &'a str,
    version: u32,
    exported_at: i64,
    items: &'a [Item],
}

#[derive(Serialize, Deserialize)]
struct EncryptedFile {
    format: String,
    version: u32,
    kdf: KdfParams,
    nonce: String,
    ct: String,
}

/// The live items, sorted by title.
fn export_items(vault: &Vault) -> Vec<Item> {
    if !vault.can_reveal_secrets() {
        return Vec::new();
    }
    vault.items()
}

/// Passyble's JSON export of `items`.
pub(crate) fn items_json(items: &[Item], now: i64) -> String {
    serde_json::to_string_pretty(&ExportFile {
        format: EXPORT_FORMAT,
        version: VERSION,
        exported_at: now,
        items,
    })
    .unwrap_or_default()
}

/// Every live item as Passyble JSON, including passkey private keys and password history. Unencrypted.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn export_json(vault: Arc<Vault>) -> String {
    items_json(&export_items(&vault), crate::now_ms())
}

/// Every live item as a Bitwarden-compatible CSV.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn export_csv(vault: Arc<Vault>) -> String {
    items_csv(&export_items(&vault))
}

/// [`export_json`] encrypted with `password` (Argon2id, XChaCha20-Poly1305). `InvalidInput` for an empty password.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn export_encrypted_json(vault: Arc<Vault>, password: String) -> Result<Vec<u8>> {
    if !vault.can_reveal_secrets() {
        return Err(PassError::InvalidInput(tr!("share.fill_only")));
    }
    encrypt_export(
        export_json(vault).as_bytes(),
        &password,
        KdfParams::default(),
    )
}

/// Opens an encrypted Passyble export. `InvalidPassword` for a wrong password, `InvalidInput` if `data`
/// is not an encrypted export or its KDF parameters are out of bounds.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn export_decrypt(data: Vec<u8>, password: String) -> Result<Vec<u8>> {
    let file: EncryptedFile =
        serde_json::from_slice(&data).map_err(|_| invalid(tr!("export.not_encrypted_export")))?;
    if file.format != ENCRYPTED_FORMAT {
        return Err(invalid(tr!("export.not_encrypted_export")));
    }
    if file.version > VERSION {
        return Err(invalid(tr!("export.newer_version")));
    }
    check_kdf(&file.kdf)?;
    let salt = b64_decode(&file.kdf.salt).map_err(|_| invalid(tr!("export.damaged")))?;
    let key = crate::crypto::derive_kek(&password, &file.kdf, &salt)?;
    let nonce = b64_decode(&file.nonce).map_err(|_| invalid(tr!("export.damaged")))?;
    let ct = b64_decode(&file.ct).map_err(|_| invalid(tr!("export.damaged")))?;
    let plain = crate::crypto::open(&key, &nonce, &ct, &export_aad(&file.kdf)?)
        .ok_or(PassError::InvalidPassword)?;
    Ok(plain.to_vec())
}

/// Whether `data` is an encrypted Passyble export.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn export_is_encrypted(data: Vec<u8>) -> bool {
    is_encrypted(&data)
}

pub(crate) fn is_encrypted(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data.get(..512).unwrap_or(data));
    text.trim_start().starts_with('{')
        && text.contains(ENCRYPTED_FORMAT)
        && serde_json::from_slice::<EncryptedFile>(data).is_ok_and(|f| f.format == ENCRYPTED_FORMAT)
}

fn export_aad(kdf: &KdfParams) -> Result<Vec<u8>> {
    let mut aad = EXPORT_AAD.as_bytes().to_vec();
    aad.extend(serde_json::to_vec(kdf).map_err(|_| PassError::Crypto(tr!("error.internal")))?);
    Ok(aad)
}

/// The same bounds as a vault header's KDF (an untrusted file must not make us allocate gigabytes).
fn check_kdf(kdf: &KdfParams) -> Result<()> {
    if kdf.alg != "argon2id"
        || kdf.m_kib > 1024 * 1024
        || !(1..=20).contains(&kdf.t)
        || !(1..=16).contains(&kdf.p)
    {
        return Err(invalid(tr!("export.unsupported_kdf")));
    }
    Ok(())
}

pub(crate) fn encrypt_export(plain: &[u8], password: &str, mut kdf: KdfParams) -> Result<Vec<u8>> {
    if password.is_empty() {
        return Err(invalid(tr!("export.choose_password")));
    }
    check_kdf(&kdf)?;
    let salt = crate::crypto::random_bytes::<16>();
    kdf.salt = b64_encode(&salt);
    let key = crate::crypto::derive_kek(password, &kdf, &salt)?;
    let (nonce, ct) = crate::crypto::seal(&key, plain, &export_aad(&kdf)?)?;
    serde_json::to_vec_pretty(&EncryptedFile {
        format: ENCRYPTED_FORMAT.into(),
        version: VERSION,
        kdf,
        nonce: b64_encode(&nonce),
        ct: b64_encode(&ct),
    })
    .map_err(|_| PassError::Crypto(tr!("error.internal")))
}

/// `name: value` lines for the CSV's `fields` column (newlines in values become spaces).
fn field_lines(item: &Item) -> String {
    let mut lines: Vec<(String, String)> = Vec::new();
    let mut push = |name: &str, value: &str| {
        if !value.trim().is_empty() {
            lines.push((name.to_string(), value.to_string()));
        }
    };
    if let Some(card) = item.card.as_ref().filter(|_| item.kind == ItemKind::Card) {
        push("Cardholder name", &card.cardholder_name);
        push("Number", &card.number);
        push("Brand", &card.brand);
        if card.expiry_month > 0 || card.expiry_year > 0 {
            push(
                "Expiry",
                &format!("{:02}/{:04}", card.expiry_month, card.expiry_year),
            );
        }
        push("Security code", &card.security_code);
        push("PIN", &card.pin);
    }
    if let Some(id) = item
        .identity
        .as_ref()
        .filter(|_| item.kind == ItemKind::Identity)
    {
        for (name, value) in [
            ("Title", &id.honorific),
            ("First name", &id.first_name),
            ("Middle name", &id.middle_name),
            ("Last name", &id.last_name),
            ("Email", &id.email),
            ("Phone", &id.phone),
            ("Address 1", &id.address1),
            ("Address 2", &id.address2),
            ("Address 3", &id.address3),
            ("City", &id.city),
            ("State", &id.region),
            ("Postal code", &id.postal_code),
            ("Country", &id.country),
            ("Company", &id.company),
            ("Birth date", &id.birth_date),
        ] {
            push(name, value);
        }
    }
    for f in &item.fields {
        push(&f.name, &f.value);
    }
    lines
        .into_iter()
        .map(|(n, v)| {
            let flat = |s: &str| s.replace(['\r', '\n'], " ");
            format!("{}: {}", flat(&n), flat(&v))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn items_csv(items: &[Item]) -> String {
    let mut w = csv::WriterBuilder::new().from_writer(Vec::new());
    let _ = w.write_record([
        "folder",
        "favorite",
        "type",
        "name",
        "notes",
        "fields",
        "reprompt",
        "login_uri",
        "login_username",
        "login_password",
        "login_totp",
    ]);
    for item in items {
        let login = item.kind == ItemKind::Login;
        let uris: Vec<String> = item
            .urls
            .iter()
            .cloned()
            .chain(
                item.android_apps
                    .iter()
                    .map(|a| format!("androidapp://{}", a.package)),
            )
            .collect();
        let _ = w.write_record([
            item.tags.first().map(String::as_str).unwrap_or_default(),
            if item.favorite { "1" } else { "" },
            if login { "login" } else { "note" },
            item.title.as_str(),
            item.notes.as_str(),
            field_lines(item).as_str(),
            "0",
            if login { uris.join(",") } else { String::new() }.as_str(),
            if login { item.username.as_str() } else { "" },
            if login { item.password.as_str() } else { "" },
            if login {
                item.totp.as_deref().unwrap_or_default()
            } else {
                ""
            },
        ]);
    }
    w.into_inner()
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default()
}

/// Reads a Passyble JSON export into `c`. 2FA secrets and passkey keys are checked like any import's;
/// trashed items are skipped.
pub(crate) fn parse_passyble(v: &Value, c: &mut Collector) -> Result<()> {
    let format = v.get("format").and_then(Value::as_str).unwrap_or_default();
    if format == ENCRYPTED_FORMAT {
        return Err(invalid(tr!("export.encrypted")));
    }
    if format != EXPORT_FORMAT {
        return Err(invalid(tr!("export.not_export")));
    }
    if v.get("version").and_then(Value::as_u64).unwrap_or(1) > u64::from(VERSION) {
        return Err(invalid(tr!("export.newer_version")));
    }
    let items = v
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(tr!("export.no_items")))?;
    for (n, value) in items.iter().enumerate() {
        if c.full() {
            break;
        }
        let mut item: Item = match serde_json::from_value(value.clone()) {
            Ok(item) => item,
            Err(_) => {
                c.skip(
                    tr!("import.entry_number", number = n + 1),
                    tr!("import.skip.unreadable"),
                );
                continue;
            }
        };
        let label = c.label(&item.title);
        if item.is_trashed() {
            c.skip(label, tr!("import.skip.in_trash"));
            continue;
        }
        match normalize_totp(item.totp.as_deref().unwrap_or_default()) {
            Ok(totp) => item.totp = totp,
            Err(reason) => {
                c.warn(tr!(
                    "import.totp_not_imported",
                    entry = label,
                    reason = reason
                ));
                item.totp = None;
            }
        }
        item.passkeys.retain(|pk| {
            use p256::pkcs8::DecodePrivateKey;
            let ok = p256::ecdsa::SigningKey::from_pkcs8_der(&pk.private_key_pkcs8).is_ok();
            if !ok {
                c.warn(tr!(
                    "import.passkey_not_imported",
                    entry = label,
                    site = pk.rp_id,
                    reason = tr!("import.passkey.unusable_key")
                ));
            }
            ok
        });
        if item.kind != ItemKind::Card {
            item.card = None;
        }
        if item.kind != ItemKind::Identity {
            item.identity = None;
        }
        item.fields
            .retain(|f| !(f.name.trim().is_empty() && f.value.is_empty()));
        item.tags = crate::model::normalize_tags(&item.tags);
        c.push_item(item);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast() -> KdfParams {
        KdfParams {
            m_kib: 64,
            t: 1,
            p: 1,
            ..Default::default()
        }
    }

    #[test]
    fn encrypted_export_round_trips_and_detects_tampering() {
        let plain = br#"{"format":"passyble-export","version":1,"items":[]}"#;
        let sealed = encrypt_export(plain, "pw", fast()).unwrap();
        assert!(is_encrypted(&sealed));
        assert!(!is_encrypted(plain));
        assert_eq!(export_decrypt(sealed.clone(), "pw".into()).unwrap(), plain);
        assert!(matches!(
            export_decrypt(sealed.clone(), "wrong".into()),
            Err(PassError::InvalidPassword)
        ));
        let mut file: Value = serde_json::from_slice(&sealed).unwrap();
        file["kdf"]["t"] = 2.into();
        assert!(export_decrypt(serde_json::to_vec(&file).unwrap(), "pw".into()).is_err());
        file["kdf"]["m_kib"] = (8 * 1024 * 1024).into();
        assert!(matches!(
            export_decrypt(serde_json::to_vec(&file).unwrap(), "pw".into()),
            Err(PassError::InvalidInput(_))
        ));
        assert!(encrypt_export(plain, "", fast()).is_err());
    }
}
