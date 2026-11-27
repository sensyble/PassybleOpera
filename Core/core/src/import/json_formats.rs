//! JSON exports: Bitwarden, Proton Pass (`data.json`), 1Password (`export.data` of a `.1pux`),
//! plus detection of the authenticator JSON formats.

use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey;
use serde_json::Value;

use std::collections::HashMap;

use super::{
    brand_id, encrypted_error, epoch_to_ms, invalid, iso8601_to_ms, otp_formats, parse_expiry,
    Collector, Draft, ImportFormat,
};
use crate::i18n::tr;
use crate::model::{CardData, FieldKind, IdentityData, ItemKind, Passkey};
use crate::Result;

pub(crate) fn detect(v: &Value) -> Option<ImportFormat> {
    let obj = v.as_object()?;
    let has = |k: &str| obj.contains_key(k);
    let format = obj
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or_default();
    Some(
        if format == crate::export::EXPORT_FORMAT || format == crate::export::ENCRYPTED_FORMAT {
            ImportFormat::PassybleJson
        } else if has("encrypted")
            && (has("items") || has("data") || has("encKeyValidation_DO_NOT_EDIT"))
        {
            ImportFormat::BitwardenJson
        } else if has("db") && has("header") {
            ImportFormat::Aegis
        } else if has("services") || has("servicesEncrypted") {
            ImportFormat::TwoFas
        } else if obj.get("vaults").is_some_and(Value::is_object) {
            ImportFormat::ProtonPass
        } else if obj.get("accounts").is_some_and(Value::is_array) {
            ImportFormat::OnePassword
        } else if obj.get("items").is_some_and(Value::is_array) {
            ImportFormat::BitwardenJson
        } else {
            return None;
        },
    )
}

pub(crate) fn parse(v: &Value, format: ImportFormat, c: &mut Collector) -> Result<()> {
    match format {
        ImportFormat::BitwardenJson => parse_bitwarden(v, c),
        ImportFormat::ProtonPass => parse_proton(v, c),
        ImportFormat::OnePassword => parse_1pux(v, c),
        ImportFormat::Aegis => otp_formats::parse_aegis(v, c),
        ImportFormat::TwoFas => otp_formats::parse_twofas(v, c),
        ImportFormat::PassybleJson => crate::export::parse_passyble(v, c),
        other => Err(invalid(tr!("import.not_format", format = other.name()))),
    }
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn arr<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

fn i64_of(v: &Value, key: &str) -> i64 {
    v.get(key)
        .and_then(|x| {
            x.as_i64()
                .or_else(|| x.as_str().and_then(|s| s.trim().parse().ok()))
        })
        .unwrap_or(0)
}

/// A string or number value as text (`""` if neither).
fn s_or_num(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(t)) => t.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn truthy(v: Option<&Value>) -> Option<bool> {
    match v? {
        Value::Bool(b) => Some(*b),
        Value::String(s) => Some(s.eq_ignore_ascii_case("true")),
        Value::Number(n) => Some(n.as_i64() != Some(0)),
        _ => None,
    }
}

// ---- Bitwarden ------------------------------------------------------------------------------

fn parse_bitwarden(v: &Value, c: &mut Collector) -> Result<()> {
    if truthy(v.get("encrypted")) == Some(true) {
        return Err(encrypted_error("Bitwarden"));
    }
    let items = v
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(tr!("import.bitwarden_no_items")))?;
    // Folders (personal vault) and collections (organization export) become tags.
    let names = |key: &str| -> HashMap<String, String> {
        arr(v, key)
            .iter()
            .map(|f| (s(f, "id").to_string(), s(f, "name").to_string()))
            .filter(|(id, name)| !id.is_empty() && !name.trim().is_empty())
            .collect()
    };
    let folders = names("folders");
    let collections = names("collections");
    for it in items {
        if c.full() {
            break;
        }
        let name = s(it, "name");
        let label = c.label(name);
        if it.get("deletedDate").is_some_and(|d| !d.is_null()) {
            c.skip(label, tr!("import.skip.bitwarden_trash"));
            continue;
        }
        let mut d = Draft {
            title: name.to_string(),
            notes: s(it, "notes").to_string(),
            favorite: truthy(it.get("favorite")).unwrap_or(false),
            created_at: iso8601_to_ms(s(it, "creationDate")),
            updated_at: iso8601_to_ms(s(it, "revisionDate")),
            ..Default::default()
        };
        if let Some(folder) = folders.get(s(it, "folderId")) {
            d.tags.push(folder.clone());
        }
        for id in arr(it, "collectionIds").iter().filter_map(Value::as_str) {
            if let Some(name) = collections.get(id) {
                d.tags.push(name.clone());
            }
        }
        match i64_of(it, "type") {
            1 => {}
            2 => d.kind = ItemKind::Note,
            3 => {
                d.kind = ItemKind::Card;
                let card = it.get("card").unwrap_or(&Value::Null);
                d.card = Some(CardData {
                    cardholder_name: s(card, "cardholderName").to_string(),
                    number: s(card, "number").to_string(),
                    expiry_month: u32::try_from(i64_of(card, "expMonth"))
                        .ok()
                        .filter(|m| (1..=12).contains(m))
                        .unwrap_or(0),
                    expiry_year: parse_expiry(&format!("01/{}", s_or_num(card, "expYear"))).1,
                    security_code: s(card, "code").to_string(),
                    brand: brand_id(s(card, "brand")),
                    ..Default::default()
                });
            }
            4 => {
                d.kind = ItemKind::Identity;
                let id = it.get("identity").unwrap_or(&Value::Null);
                d.identity = Some(IdentityData {
                    honorific: s(id, "title").to_string(),
                    first_name: s(id, "firstName").to_string(),
                    middle_name: s(id, "middleName").to_string(),
                    last_name: s(id, "lastName").to_string(),
                    email: s(id, "email").to_string(),
                    phone: s(id, "phone").to_string(),
                    address1: s(id, "address1").to_string(),
                    address2: s(id, "address2").to_string(),
                    address3: s(id, "address3").to_string(),
                    city: s(id, "city").to_string(),
                    region: s(id, "state").to_string(),
                    postal_code: s(id, "postalCode").to_string(),
                    country: s(id, "country").to_string(),
                    company: s(id, "company").to_string(),
                    birth_date: String::new(),
                });
                d.field(
                    &tr!("import.field.username"),
                    s(id, "username"),
                    FieldKind::Text,
                );
                d.field(&tr!("import.field.ssn"), s(id, "ssn"), FieldKind::Hidden);
                d.field(
                    &tr!("import.field.passport_number"),
                    s(id, "passportNumber"),
                    FieldKind::Hidden,
                );
                d.field(
                    &tr!("import.field.license_number"),
                    s(id, "licenseNumber"),
                    FieldKind::Hidden,
                );
            }
            5 => {
                c.skip(label, tr!("import.skip.ssh_keys"));
                continue;
            }
            other => {
                c.skip(label, tr!("import.skip.unknown_type", kind = other));
                continue;
            }
        }
        for f in arr(it, "fields") {
            // 0 text, 1 hidden, 2 boolean; 3 is a "linked" field that only points at another.
            let kind = match i64_of(f, "type") {
                1 => FieldKind::Hidden,
                3 => continue,
                _ => FieldKind::Text,
            };
            d.field(s(f, "name"), &s_or_num(f, "value"), kind);
        }
        if let Some(login) = it.get("login").filter(|l| l.is_object()) {
            d.username = s(login, "username").to_string();
            d.password = s(login, "password").to_string();
            d.totp = s(login, "totp").to_string();
            d.urls = arr(login, "uris")
                .iter()
                .map(|u| s(u, "uri").to_string())
                .collect();
            for cred in arr(login, "fido2Credentials") {
                match bitwarden_passkey(cred) {
                    Ok(pk) => d.passkeys.push(pk),
                    Err(why) => c.warn(tr!(
                        "import.passkey_not_imported",
                        entry = label,
                        site = s(cred, "rpId"),
                        reason = why
                    )),
                }
            }
        }
        c.add(d);
    }
    Ok(())
}

/// Bitwarden credential ids are a GUID string (credentials Bitwarden created) or `b64.` +
/// base64url (imported ones).
fn bitwarden_credential_id(id: &str) -> Option<Vec<u8>> {
    let id = id.trim();
    if let Some(b64) = id.strip_prefix("b64.") {
        return crate::b64url_decode(b64.to_string()).ok();
    }
    let hex: String = id.chars().filter(|c| *c != '-').collect();
    if hex.len() == 32 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return (0..16)
            .map(|i| u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok())
            .collect();
    }
    crate::b64url_decode(id.to_string()).ok()
}

fn bitwarden_passkey(cred: &Value) -> std::result::Result<Passkey, String> {
    let algorithm = s(cred, "keyAlgorithm");
    let curve = s(cred, "keyCurve");
    if !(algorithm.is_empty() || algorithm.eq_ignore_ascii_case("ECDSA"))
        || !(curve.is_empty() || curve.eq_ignore_ascii_case("P-256"))
    {
        return Err(tr!("import.passkey.unsupported_key"));
    }
    let rp_id = s(cred, "rpId").trim().to_ascii_lowercase();
    if rp_id.is_empty() {
        return Err(tr!("import.passkey.no_relying_party"));
    }
    let pkcs8 = crate::b64url_decode(s(cred, "keyValue").to_string())
        .map_err(|_| tr!("import.passkey.no_private_key"))?;
    SigningKey::from_pkcs8_der(&pkcs8).map_err(|_| tr!("import.passkey.unusable_key"))?;
    let credential_id = bitwarden_credential_id(s(cred, "credentialId"))
        .filter(|id| !id.is_empty())
        .ok_or_else(|| tr!("import.passkey.bad_credential_id"))?;
    let user_handle = match s(cred, "userHandle") {
        "" => Vec::new(),
        h => crate::b64url_decode(h.to_string())
            .map_err(|_| tr!("import.passkey.bad_user_handle"))?,
    };
    let rp_name = s(cred, "rpName").trim();
    Ok(Passkey {
        credential_id,
        rp_id,
        rp_name: (!rp_name.is_empty()).then(|| rp_name.to_string()),
        user_handle,
        user_name: s(cred, "userName").to_string(),
        user_display_name: s(cred, "userDisplayName").to_string(),
        private_key_pkcs8: pkcs8,
        sign_count: u32::try_from(i64_of(cred, "counter")).unwrap_or(0),
        discoverable: truthy(cred.get("discoverable")).unwrap_or(true),
        created_at: iso8601_to_ms(s(cred, "creationDate")),
    })
}

// ---- Proton Pass ----------------------------------------------------------------------------

fn parse_proton(v: &Value, c: &mut Collector) -> Result<()> {
    if truthy(v.get("encrypted")) == Some(true) {
        return Err(encrypted_error("Proton Pass"));
    }
    let vaults = v
        .get("vaults")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(tr!("import.proton_no_vaults")))?;
    // With several vaults, each item is tagged with its vault's name.
    let tag_vaults = vaults.len() > 1;
    for vault in vaults.values() {
        let vault_name = s(vault, "name").trim().to_string();
        for it in arr(vault, "items") {
            if c.full() {
                return Ok(());
            }
            let data = it.get("data").unwrap_or(&Value::Null);
            let meta = data.get("metadata").unwrap_or(&Value::Null);
            let name = s(meta, "name");
            let label = c.label(name);
            if i64_of(it, "state") == 2 {
                c.skip(label, tr!("import.skip.proton_trash"));
                continue;
            }
            let mut d = Draft {
                title: name.to_string(),
                notes: s(meta, "note").to_string(),
                favorite: truthy(it.get("pinned")).unwrap_or(false),
                created_at: epoch_to_ms(i64_of(it, "createTime")),
                updated_at: epoch_to_ms(i64_of(it, "modifyTime")),
                ..Default::default()
            };
            if tag_vaults && !vault_name.is_empty() {
                d.tags.push(vault_name.clone());
            }
            let content = data.get("content").unwrap_or(&Value::Null);
            match s(data, "type") {
                "login" => {
                    d.username = match s(content, "itemUsername") {
                        "" => s(content, "username").to_string(),
                        u => u.to_string(),
                    };
                    d.email = s(content, "itemEmail").to_string();
                    d.password = s(content, "password").to_string();
                    d.totp = s(content, "totpUri").to_string();
                    d.urls = arr(content, "urls")
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect();
                    for pk in arr(content, "passkeys") {
                        c.warn(tr!(
                            "import.proton_passkey",
                            entry = label,
                            site = match s(pk, "rpId") {
                                "" => s(pk, "domain"),
                                rp => rp,
                            }
                        ));
                    }
                }
                "note" => d.kind = ItemKind::Note,
                "alias" => {
                    c.skip(label, tr!("import.skip.proton_alias"));
                    continue;
                }
                "creditCard" => {
                    d.kind = ItemKind::Card;
                    let (expiry_month, expiry_year) = parse_expiry(s(content, "expirationDate"));
                    d.card = Some(CardData {
                        cardholder_name: s(content, "cardholderName").to_string(),
                        number: s(content, "number").to_string(),
                        expiry_month,
                        expiry_year,
                        security_code: s(content, "verificationNumber").to_string(),
                        pin: s(content, "pin").to_string(),
                        brand: String::new(),
                    });
                }
                "identity" => {
                    d.kind = ItemKind::Identity;
                    proton_identity(content, &mut d);
                }
                other => {
                    c.skip(
                        label,
                        if other.is_empty() {
                            tr!("import.skip.unknown_items")
                        } else {
                            tr!("import.skip.unsupported_type", kind = other)
                        },
                    );
                    continue;
                }
            }
            for f in arr(data, "extraFields") {
                let value = f
                    .get("data")
                    .map(|d| s(d, "content"))
                    .unwrap_or_default()
                    .to_string();
                match s(f, "type") {
                    "totp" if d.totp.trim().is_empty() => d.totp = value,
                    "hidden" | "totp" => d.field(s(f, "fieldName"), &value, FieldKind::Hidden),
                    _ => d.field(s(f, "fieldName"), &value, FieldKind::Text),
                }
            }
            c.add(d);
        }
    }
    Ok(())
}

/// Proton Pass identity content: the main fields into [`IdentityData`], the rest (work and
/// social details, IDs, extra fields and sections) into custom fields.
fn proton_identity(content: &Value, d: &mut Draft) {
    let mut first = s(content, "firstName").to_string();
    let mut last = s(content, "lastName").to_string();
    let full = s(content, "fullName").trim();
    if first.is_empty() && last.is_empty() && !full.is_empty() {
        match full.rsplit_once(' ') {
            Some((f, l)) => {
                first = f.to_string();
                last = l.to_string();
            }
            None => first = full.to_string(),
        }
    }
    let mut address2 = String::new();
    for key in ["floor", "county"] {
        let v = s(content, key).trim();
        if !v.is_empty() {
            if !address2.is_empty() {
                address2.push_str(", ");
            }
            address2.push_str(v);
        }
    }
    d.identity = Some(IdentityData {
        first_name: first,
        middle_name: s(content, "middleName").to_string(),
        last_name: last,
        email: s(content, "email").to_string(),
        phone: s(content, "phoneNumber").to_string(),
        address1: s(content, "streetAddress").to_string(),
        address2,
        city: s(content, "city").to_string(),
        region: s(content, "stateOrProvince").to_string(),
        postal_code: s(content, "zipOrPostalCode").to_string(),
        country: s(content, "countryOrRegion").to_string(),
        company: s(content, "organization").to_string(),
        birth_date: s(content, "birthdate").to_string(),
        ..Default::default()
    });
    let hidden = ["socialSecurityNumber", "passportNumber", "licenseNumber"];
    for (key, name) in [
        ("gender", tr!("import.field.gender")),
        ("socialSecurityNumber", tr!("import.field.ssn")),
        ("passportNumber", tr!("import.field.passport_number")),
        ("licenseNumber", tr!("import.field.license_number")),
        ("website", tr!("import.field.website")),
        ("xHandle", tr!("import.field.x_handle")),
        ("secondPhoneNumber", tr!("import.field.second_phone")),
        ("linkedin", "LinkedIn".to_string()),
        ("reddit", "Reddit".to_string()),
        ("facebook", "Facebook".to_string()),
        ("yahoo", "Yahoo".to_string()),
        ("instagram", "Instagram".to_string()),
        ("company", tr!("import.field.company")),
        ("jobTitle", tr!("import.field.job_title")),
        ("personalWebsite", tr!("import.field.personal_website")),
        ("workPhoneNumber", tr!("import.field.work_phone")),
        ("workEmail", tr!("import.field.work_email")),
    ] {
        let kind = if hidden.contains(&key) {
            FieldKind::Hidden
        } else if key.to_ascii_lowercase().contains("website") {
            FieldKind::Url
        } else {
            FieldKind::Text
        };
        d.field(&name, s(content, key), kind);
    }
    let extra_lists = [
        "extraPersonalDetails",
        "extraAddressDetails",
        "extraContactDetails",
        "extraWorkDetails",
    ];
    let sections = arr(content, "extraSections")
        .iter()
        .flat_map(|sec| arr(sec, "sectionFields"));
    for f in extra_lists
        .iter()
        .flat_map(|k| arr(content, k))
        .chain(sections)
    {
        let value = f.get("data").map(|x| s(x, "content")).unwrap_or_default();
        let kind = if s(f, "type") == "hidden" {
            FieldKind::Hidden
        } else {
            FieldKind::Text
        };
        d.field(s(f, "fieldName"), value, kind);
    }
}

// ---- 1Password (1PUX) -----------------------------------------------------------------------

/// Why a 1Password item of an unsupported category is skipped ("passports aren't supported").
fn onepassword_unsupported(uuid: &str) -> String {
    match uuid {
        "002" => tr!("import.skip.one_password.payment_cards"),
        "004" => tr!("import.skip.one_password.identities"),
        "006" => tr!("import.skip.one_password.documents"),
        "100" => tr!("import.skip.one_password.software_licenses"),
        "101" => tr!("import.skip.one_password.bank_accounts"),
        "102" => tr!("import.skip.one_password.databases"),
        "103" => tr!("import.skip.one_password.driver_licenses"),
        "105" => tr!("import.skip.one_password.memberships"),
        "106" => tr!("import.skip.one_password.passports"),
        "109" => tr!("import.skip.one_password.wireless_routers"),
        "110" => tr!("import.skip.one_password.servers"),
        "111" => tr!("import.skip.one_password.email_accounts"),
        "112" => tr!("import.skip.one_password.api_credentials"),
        "114" => tr!("import.skip.ssh_keys"),
        "115" => tr!("import.skip.one_password.crypto_wallets"),
        _ => tr!("import.skip.one_password.other"),
    }
}

fn parse_1pux(v: &Value, c: &mut Collector) -> Result<()> {
    let accounts = v
        .get("accounts")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(tr!("import.one_password_no_accounts")))?;
    // With several vaults, each item is tagged with its vault's name.
    let vault_count: usize = accounts.iter().map(|a| arr(a, "vaults").len()).sum();
    for account in accounts {
        for vault in arr(account, "vaults") {
            let name = vault
                .get("attrs")
                .map(|a| s(a, "name"))
                .unwrap_or_default()
                .trim();
            let tag = (vault_count > 1 && !name.is_empty()).then_some(name);
            for it in arr(vault, "items") {
                if c.full() {
                    return Ok(());
                }
                parse_1pux_item(it, tag, c);
            }
        }
    }
    Ok(())
}

/// A 1PUX field value as text: strings, numbers, `{"email": {"email_address": …}}`, dates.
fn onepux_text(key: &str, val: &Value) -> Option<String> {
    match val {
        Value::String(t) => Some(t.clone()),
        Value::Number(n) if key == "date" => {
            n.as_i64().map(|secs| super::merge::ymd(epoch_to_ms(secs)))
        }
        Value::Number(n) => Some(n.to_string()),
        Value::Object(o) if key == "email" => o
            .get("email_address")
            .and_then(Value::as_str)
            .map(str::to_string),
        _ => None,
    }
}

fn parse_1pux_item(it: &Value, vault_tag: Option<&str>, c: &mut Collector) {
    let overview = it.get("overview").unwrap_or(&Value::Null);
    let details = it.get("details").unwrap_or(&Value::Null);
    let title = s(overview, "title");
    let label = c.label(title);
    match s(it, "state") {
        "" | "active" => {}
        state => {
            c.skip(label, tr!("import.skip.one_password_state", state = state));
            return;
        }
    }
    let mut d = Draft {
        title: title.to_string(),
        notes: s(details, "notesPlain").to_string(),
        favorite: i64_of(it, "favIndex") > 0,
        created_at: epoch_to_ms(i64_of(it, "createdAt")),
        updated_at: epoch_to_ms(i64_of(it, "updatedAt")),
        ..Default::default()
    };
    d.tags.extend(vault_tag.map(str::to_string));
    d.tags.extend(
        arr(overview, "tags")
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string),
    );
    match s(it, "categoryUuid") {
        "001" => {}
        "005" => d.password = s(details, "password").to_string(),
        "003" => d.kind = ItemKind::Note,
        "002" => {
            d.kind = ItemKind::Card;
            d.card = Some(CardData::default());
        }
        "004" => {
            d.kind = ItemKind::Identity;
            d.identity = Some(IdentityData::default());
        }
        other => {
            c.skip(label, onepassword_unsupported(other));
            return;
        }
    }
    let mut urls: Vec<String> = arr(overview, "urls")
        .iter()
        .map(|u| s(u, "url").to_string())
        .collect();
    let main_url = s(overview, "url");
    if !main_url.is_empty() && !urls.iter().any(|u| u == main_url) {
        urls.insert(0, main_url.to_string());
    }
    d.urls = urls;
    for field in arr(details, "loginFields") {
        match s(field, "designation") {
            "username" => d.username = s(field, "value").to_string(),
            "password" => d.password = s(field, "value").to_string(),
            _ => {}
        }
    }
    let mut passkey_warned = false;
    for section in arr(details, "sections") {
        for field in arr(section, "fields") {
            let Some(value) = field.get("value").and_then(Value::as_object) else {
                continue;
            };
            let name = s(field, "title");
            let id = s(field, "id");
            if let Some(card) = d.card.as_mut() {
                if onepux_card_field(card, id, value) {
                    continue;
                }
            }
            if let Some(identity) = d.identity.as_mut() {
                if onepux_identity_field(identity, id, value) {
                    continue;
                }
            }
            for (key, val) in value {
                match key.as_str() {
                    "totp" => {
                        let t = val.as_str().unwrap_or_default();
                        if d.totp.trim().is_empty() {
                            d.totp = t.to_string();
                        } else if !t.is_empty() {
                            d.field(name, t, FieldKind::Hidden);
                        }
                    }
                    "passkey" => {
                        if !passkey_warned {
                            passkey_warned = true;
                            c.warn(tr!("import.one_password_passkey", entry = label));
                        }
                    }
                    _ => {
                        let Some(text) = onepux_text(key, val) else {
                            continue;
                        };
                        let kind = match key.as_str() {
                            "concealed" | "creditCardNumber" => FieldKind::Hidden,
                            "url" => FieldKind::Url,
                            _ => FieldKind::Text,
                        };
                        d.field(name, &text, kind);
                    }
                }
            }
        }
    }
    c.add(d);
}

/// A field of a 1Password credit card section into `card`; `false` if it isn't one.
fn onepux_card_field(
    card: &mut CardData,
    id: &str,
    value: &serde_json::Map<String, Value>,
) -> bool {
    let text = |key: &str| onepux_text(key, value.get(key)?);
    match id {
        "cardholder" => card.cardholder_name = text("string").unwrap_or_default(),
        "ccnum" => {
            card.number = text("creditCardNumber")
                .or_else(|| text("string"))
                .unwrap_or_default()
        }
        "cvv" => {
            card.security_code = text("concealed")
                .or_else(|| text("string"))
                .unwrap_or_default()
        }
        "pin" => card.pin = text("concealed").unwrap_or_default(),
        "type" => card.brand = brand_id(&text("creditCardType").unwrap_or_default()),
        "expiry" => {
            let (m, y) = parse_expiry(&text("monthYear").unwrap_or_default());
            card.expiry_month = m;
            card.expiry_year = y;
        }
        _ => return false,
    }
    true
}

/// A field of a 1Password identity section into `identity`; `false` if it isn't one.
fn onepux_identity_field(
    identity: &mut IdentityData,
    id: &str,
    value: &serde_json::Map<String, Value>,
) -> bool {
    let text = || {
        value
            .iter()
            .find_map(|(k, v)| onepux_text(k, v))
            .unwrap_or_default()
    };
    match id {
        "firstname" => identity.first_name = text(),
        "initial" => identity.middle_name = text(),
        "lastname" => identity.last_name = text(),
        "birthdate" => identity.birth_date = text(),
        "company" => identity.company = text(),
        "email" => identity.email = text(),
        "defphone" | "cellphone" | "homephone" if identity.phone.is_empty() => {
            identity.phone = text()
        }
        "address" => {
            let Some(addr) = value.get("address") else {
                return false;
            };
            identity.address1 = s(addr, "street").to_string();
            identity.city = s(addr, "city").to_string();
            identity.region = s(addr, "state").to_string();
            identity.postal_code = s(addr, "zip").to_string();
            identity.country = s(addr, "country").to_string();
        }
        _ => return false,
    }
    true
}
