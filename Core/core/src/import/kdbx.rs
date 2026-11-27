//! KeePass databases (`.kdbx` 3.1 and 4, KeePass 1 `.kdb`) opened through the `keepass` crate. The
//! outer header is read first to bound the key derivation the file asks for, since the crate would
//! run whatever the file says. The recycle bin is skipped; attachments, history and icons are not
//! imported.

/// Reads the KDF parameters from the outer header and refuses heavy ones. `Ok` when the header
/// can't be read: the crate then reports the damage.
#[cfg_attr(not(feature = "import-kdbx"), allow(dead_code))]
pub(crate) fn check_header(data: &[u8]) -> crate::Result<()> {
    use super::encrypted::{check_aes_kdf, check_argon2, Kind};

    let u16_at = |i: usize| data.get(i..i + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |i: usize| {
        data.get(i..i + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let Some(sig2) = u32_at(4) else {
        return Ok(());
    };
    match sig2 {
        // KeePass 1: fixed 124-byte header, rounds at the end.
        0xB54B_FB65 => {
            if let Some(rounds) = u32_at(120) {
                check_aes_kdf(Kind::Keepass, u64::from(rounds))?;
            }
            Ok(())
        }
        0xB54B_FB67 => {
            let major = u16_at(10).unwrap_or(0);
            let wide = major >= 4;
            let mut pos = 12;
            // A header has a dozen fields; never loop on garbage.
            for _ in 0..64 {
                let Some(&id) = data.get(pos) else {
                    return Ok(());
                };
                let (len, body) = if wide {
                    (u32_at(pos + 1).map(|l| l as usize), pos + 5)
                } else {
                    (u16_at(pos + 1).map(usize::from), pos + 3)
                };
                let Some(len) = len else {
                    return Ok(());
                };
                let Some(value) = data.get(body..body.saturating_add(len)) else {
                    return Ok(());
                };
                match id {
                    0 => return Ok(()),
                    // KDBX 3: TransformRounds.
                    6 if !wide => {
                        if let Ok(b) = <[u8; 8]>::try_from(value) {
                            check_aes_kdf(Kind::Keepass, u64::from_le_bytes(b))?;
                        }
                    }
                    // KDBX 4: KdfParameters (a VariantDictionary).
                    11 if wide => {
                        let params = variant_dictionary(value);
                        let get = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| *v);
                        if let Some(rounds) = get("R") {
                            check_aes_kdf(Kind::Keepass, rounds)?;
                        }
                        if let (Some(m), Some(i)) = (get("M"), get("I")) {
                            check_argon2(Kind::Keepass, m / 1024, i, get("P").unwrap_or(1))?;
                        }
                    }
                    _ => {}
                }
                pos = body + len;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// The integer entries (UInt32 / UInt64 / Int32 / Int64) of a KDBX 4 VariantDictionary.
#[cfg_attr(not(feature = "import-kdbx"), allow(dead_code))]
fn variant_dictionary(data: &[u8]) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    let mut pos = 2; // version
    let i32_at = |i: usize| {
        data.get(i..i + 4)
            .map(|b| i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    for _ in 0..64 {
        let Some(&kind) = data.get(pos) else {
            break;
        };
        if kind == 0 {
            break;
        }
        let Some(name_len) = i32_at(pos + 1).and_then(|l| usize::try_from(l).ok()) else {
            break;
        };
        let name_at = pos + 5;
        let Some(name) = data.get(name_at..name_at.saturating_add(name_len)) else {
            break;
        };
        let value_len_at = name_at + name_len;
        let Some(value_len) = i32_at(value_len_at).and_then(|l| usize::try_from(l).ok()) else {
            break;
        };
        let value_at = value_len_at + 4;
        let Some(value) = data.get(value_at..value_at.saturating_add(value_len)) else {
            break;
        };
        let number = match (kind, value.len()) {
            (0x04, 4) => Some(u64::from(u32::from_le_bytes(
                value.try_into().unwrap_or([0; 4]),
            ))),
            (0x05, 8) => Some(u64::from_le_bytes(value.try_into().unwrap_or([0; 8]))),
            (0x0C, 4) => Some(i32::from_le_bytes(value.try_into().unwrap_or([0; 4])).max(0) as u64),
            (0x0D, 8) => Some(i64::from_le_bytes(value.try_into().unwrap_or([0; 8])).max(0) as u64),
            _ => None,
        };
        if let Some(n) = number {
            out.push((String::from_utf8_lossy(name).into_owned(), n));
        }
        pos = value_at + value_len;
    }
    out
}

#[cfg(feature = "import-kdbx")]
mod imp {
    use keepass::db::{EntryRef, GroupId};
    use keepass::error::{DatabaseKeyError, DatabaseOpenError};
    use keepass::{Database, DatabaseKey};

    use super::super::encrypted::Unlock;
    use super::super::otp_formats::build_otpauth;
    use super::super::{invalid, Collector, Draft, ImportFormat};
    use crate::i18n::tr;
    use crate::model::{FieldKind, Passkey};
    use crate::{PassError, Result};

    /// Fields with a meaning of their own (not copied as custom fields).
    const STANDARD: [&str; 5] = ["Title", "UserName", "Password", "URL", "Notes"];

    pub(crate) fn parse(
        data: &[u8],
        unlock: &Unlock<'_>,
        c: &mut Collector,
    ) -> Result<ImportFormat> {
        super::check_header(data)?;
        let mut key = DatabaseKey::new();
        if !unlock.password.is_empty() {
            key = key.with_password(unlock.password);
        }
        if let Some(mut file) = unlock.key_file {
            key = key
                .with_keyfile(&mut file)
                .map_err(|_| invalid(tr!("import.keepass_key_file_unreadable")))?;
        }
        if key.is_empty() {
            return Err(invalid(tr!("import.enter_password")));
        }
        let db = Database::parse(data, key).map_err(open_error)?;
        read(&db, c);
        Ok(ImportFormat::Keepass)
    }

    fn open_error(e: DatabaseOpenError) -> PassError {
        match e {
            DatabaseOpenError::Key(DatabaseKeyError::IncorrectKey) => PassError::InvalidPassword,
            DatabaseOpenError::Key(DatabaseKeyError::EmptyKey) => {
                invalid(tr!("import.enter_password"))
            }
            DatabaseOpenError::Key(_) => invalid(tr!("import.keepass_key_file_unreadable")),
            DatabaseOpenError::UnsupportedVersion | DatabaseOpenError::VersionParse(_) => {
                invalid(tr!("import.keepass_unsupported"))
            }
            // A failing decryption (padding, block HMAC) after a key that seemed right is a wrong key for KDBX 3.
            DatabaseOpenError::Cryptography(_) => PassError::InvalidPassword,
            _ => invalid(tr!("import.keepass_unreadable")),
        }
    }

    /// A KeePass time (`Option<chrono::NaiveDateTime>`, UTC) as Unix milliseconds, 0 if unset.
    macro_rules! ms {
        ($t:expr) => {
            $t.map(|t| t.and_utc().timestamp_millis())
                .unwrap_or(0)
                .max(0)
        };
    }

    fn read(db: &Database, c: &mut Collector) {
        let bin = db.recycle_bin().map(|g| g.id());
        let mut attachments: Vec<String> = Vec::new();
        // (group, path below the root, in the recycle bin); a stack, not recursion, whatever
        // the nesting.
        let mut stack: Vec<(GroupId, Vec<String>, bool)> =
            vec![(db.root().id(), Vec::new(), false)];
        let mut groups = 0usize;
        while let Some((id, path, trashed)) = stack.pop() {
            groups += 1;
            if groups > super::super::MAX_ENTRIES {
                break;
            }
            let Some(group) = db.group(id) else {
                continue;
            };
            for entry in group.entries() {
                if c.full() {
                    break;
                }
                let label = c.label(entry.get_title().unwrap_or_default());
                if trashed {
                    c.skip(label, tr!("import.skip.keepass_recycle_bin"));
                    continue;
                }
                let names: Vec<&str> = entry.attachments_named().map(|(n, _)| n).collect();
                if !names.is_empty() && attachments.len() < 20 {
                    attachments.push(format!("{label} ({})", names.join(", ")));
                }
                add_entry(&entry, &path, c);
            }
            let children: Vec<GroupId> = group.group_ids().collect();
            for child in children.into_iter().rev() {
                let Some(child_group) = db.group(child) else {
                    continue;
                };
                let in_bin = trashed || Some(child) == bin;
                let mut child_path = path.clone();
                let name = child_group.name.trim().to_string();
                if !name.is_empty() {
                    child_path.push(name);
                }
                stack.push((child, child_path, in_bin));
            }
        }
        if !attachments.is_empty() {
            c.warn(tr!(
                "import.keepass_attachments",
                entries = attachments.join("; ")
            ));
        }
    }

    fn add_entry(entry: &EntryRef<'_>, path: &[String], c: &mut Collector) {
        let get = |k: &str| entry.get(k).unwrap_or_default().to_string();
        let mut d = Draft {
            title: get("Title"),
            username: get("UserName"),
            password: get("Password"),
            notes: get("Notes"),
            created_at: ms!(entry.times.creation),
            updated_at: ms!(entry.times.last_modification),
            ..Default::default()
        };
        let url = get("URL");
        if !url.trim().is_empty() {
            d.urls.push(url);
        }
        if !path.is_empty() {
            d.tags.push(path.join("/"));
        }
        d.tags
            .extend(entry.tags.iter().filter(|t| !t.trim().is_empty()).cloned());
        let (totp, totp_fields) = totp_of(entry, &d.title, &d.username);
        d.totp = totp;
        let label = c.label(&d.title);
        let passkey = passkey_of(entry);
        match passkey {
            Some(Ok(p)) => d.passkeys.push(p),
            Some(Err(reason)) => c.warn(tr!(
                "import.passkey_not_imported",
                entry = label,
                site = get("KPEX_PASSKEY_RELYING_PARTY"),
                reason = reason
            )),
            None => {}
        }
        let mut names: Vec<&String> = entry.fields.keys().collect();
        names.sort();
        for name in names {
            let value = &entry.fields[name];
            let text = value.get();
            if STANDARD.contains(&name.as_str())
                || totp_fields.contains(&name.as_str())
                || name.starts_with("KPEX_PASSKEY_")
                || text.trim().is_empty()
            {
                continue;
            }
            if name.starts_with("KP2A_URL") {
                d.urls.push(text.clone());
                continue;
            }
            let kind = if value.is_protected() {
                FieldKind::Hidden
            } else {
                FieldKind::Text
            };
            d.field(name, text, kind);
        }
        c.add(d);
    }

    /// The entry's TOTP (an `otpauth://` URI or a base32 secret) and which fields it came from.
    fn totp_of(entry: &EntryRef<'_>, title: &str, user: &str) -> (String, Vec<&'static str>) {
        let get = |k: &str| entry.get(k).map(str::trim).filter(|v| !v.is_empty());
        if let Some(otp) = get("otp") {
            return (otp.to_string(), vec!["otp"]);
        }
        // KeePass 2.47+: TimeOtp-Secret[-Hex|-Base32|-Base64], -Length, -Period, -Algorithm.
        let secret = get("TimeOtp-Secret-Base32")
            .and_then(|s| crate::encoding::base32_decode(s).ok())
            .or_else(|| {
                get("TimeOtp-Secret-Hex")
                    .and_then(|s| super::super::encrypted::hex(&s.replace(' ', "")))
            })
            .or_else(|| get("TimeOtp-Secret-Base64").and_then(super::super::encrypted::b64))
            .or_else(|| get("TimeOtp-Secret").map(|s| s.as_bytes().to_vec()));
        if let Some(secret) = secret.filter(|s| !s.is_empty()) {
            let algorithm = match get("TimeOtp-Algorithm").unwrap_or_default() {
                "HMAC-SHA-256" => "SHA256",
                "HMAC-SHA-512" => "SHA512",
                _ => "SHA1",
            };
            let digits = get("TimeOtp-Length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(6);
            let period = get("TimeOtp-Period")
                .and_then(|v| v.parse().ok())
                .unwrap_or(30);
            return (
                build_otpauth(
                    title.trim(),
                    user.trim(),
                    &secret,
                    algorithm,
                    digits,
                    period,
                ),
                vec![
                    "TimeOtp-Secret",
                    "TimeOtp-Secret-Hex",
                    "TimeOtp-Secret-Base32",
                    "TimeOtp-Secret-Base64",
                    "TimeOtp-Length",
                    "TimeOtp-Period",
                    "TimeOtp-Algorithm",
                ],
            );
        }
        // KeeOtp / KeePassXC before 2.6: "TOTP Seed" (base32) and "TOTP Settings" ("30;6").
        if let Some(seed) = get("TOTP Seed") {
            let fields = vec!["TOTP Seed", "TOTP Settings"];
            let settings = get("TOTP Settings").unwrap_or("30;6");
            let mut parts = settings.split(';').map(str::trim);
            let period: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(30);
            let digits = parts.next().unwrap_or("6");
            if digits.eq_ignore_ascii_case("S") {
                return ("steam://".to_string() + seed, fields);
            }
            let digits: u32 = digits.parse().unwrap_or(6);
            return match crate::encoding::base32_decode(seed) {
                Ok(secret) if !secret.is_empty() => (
                    build_otpauth(title.trim(), user.trim(), &secret, "SHA1", digits, period),
                    fields,
                ),
                // Let the collector report the unreadable secret.
                _ => (seed.to_string(), fields),
            };
        }
        (String::new(), Vec::new())
    }

    /// A KeePassXC passkey (`KPEX_PASSKEY_*` fields), if the entry has one.
    fn passkey_of(entry: &EntryRef<'_>) -> Option<std::result::Result<Passkey, String>> {
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::DecodePrivateKey;

        let get = |k: &str| entry.get(k).map(str::trim).unwrap_or_default();
        let pem = get("KPEX_PASSKEY_PRIVATE_KEY_PEM");
        if pem.is_empty() {
            return None;
        }
        Some((|| {
            let rp_id = get("KPEX_PASSKEY_RELYING_PARTY").to_ascii_lowercase();
            if rp_id.is_empty() {
                return Err(tr!("import.passkey.no_relying_party"));
            }
            let body: String = pem
                .lines()
                .filter(|l| !l.starts_with("-----"))
                .collect::<Vec<_>>()
                .join("");
            let pkcs8 = super::super::encrypted::b64(&body)
                .ok_or_else(|| tr!("import.passkey.no_private_key"))?;
            SigningKey::from_pkcs8_der(&pkcs8).map_err(|_| tr!("import.passkey.unusable_key"))?;
            let credential_id = crate::b64url_decode(get("KPEX_PASSKEY_CREDENTIAL_ID").to_string())
                .ok()
                .filter(|id| !id.is_empty())
                .ok_or_else(|| tr!("import.passkey.bad_credential_id"))?;
            let user_handle = match get("KPEX_PASSKEY_USER_HANDLE") {
                "" => Vec::new(),
                h => crate::b64url_decode(h.to_string())
                    .map_err(|_| tr!("import.passkey.bad_user_handle"))?,
            };
            Ok(Passkey {
                credential_id,
                rp_id,
                rp_name: None,
                user_handle,
                user_name: get("KPEX_PASSKEY_USERNAME").to_string(),
                user_display_name: String::new(),
                private_key_pkcs8: pkcs8,
                sign_count: 0,
                discoverable: true,
                created_at: ms!(entry.times.creation),
            })
        })())
    }
}

#[cfg(feature = "import-kdbx")]
pub(crate) use imp::parse;

#[cfg(not(feature = "import-kdbx"))]
pub(crate) fn parse(
    _data: &[u8],
    _unlock: &super::encrypted::Unlock<'_>,
    _c: &mut super::Collector,
) -> crate::Result<super::ImportFormat> {
    Err(super::invalid(crate::i18n::tr!("import.keepass_database")))
}
