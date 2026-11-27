//! Authenticator exports: `otpauth://` links, Google Authenticator's `otpauth-migration://`
//! export, Aegis and 2FAS.

use std::collections::BTreeMap;

use serde_json::Value;
use url::Url;

use super::{encrypted_error, invalid, starts_with_ci, Collector, Draft, ImportFormat};
use crate::encoding::{base32_decode, base32_encode};
use crate::i18n::tr;
use crate::{PassError, Result};

/// Reads every `otpauth://` and `otpauth-migration://` link in `text` (separated by whitespace,
/// quotes or commas).
pub(crate) fn parse_otp_text(text: &str, c: &mut Collector) -> Result<ImportFormat> {
    let mut migration = false;
    let mut batches: BTreeMap<i64, (i64, Vec<i64>)> = BTreeMap::new();
    let mut found = 0usize;
    for token in text
        .split(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | ',' | '<' | '>' | ';'))
    {
        let token = token.trim();
        if starts_with_ci(token, "otpauth-migration://") {
            migration = true;
            found += 1;
            if let Err(e) = parse_migration_uri(token, c, &mut batches) {
                c.skip(
                    tr!("import.google_authenticator_export"),
                    tr!(
                        "import.skip.migration_unreadable",
                        detail = super::short_error(&e)
                    ),
                );
            }
        } else if starts_with_ci(token, "otpauth://") {
            found += 1;
            parse_otpauth_uri(token, c);
        }
        if c.full() {
            break;
        }
    }
    if found == 0 {
        return Err(invalid(tr!("import.no_otp_links")));
    }
    for (size, seen) in batches.values() {
        let mut seen = seen.clone();
        seen.sort_unstable();
        seen.dedup();
        if (seen.len() as i64) < *size {
            c.warn(tr!(
                "import.google_authenticator_batches",
                total = size,
                imported = seen.len()
            ));
        }
    }
    Ok(if migration {
        ImportFormat::GoogleAuthenticator
    } else {
        ImportFormat::OtpauthUris
    })
}

fn parse_otpauth_uri(uri: &str, c: &mut Collector) {
    let label = Url::parse(uri)
        .ok()
        .map(|u| decode_label(u.path()))
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| tr!("import.otpauth_link"));
    match crate::totp_parse(uri.to_string()) {
        Ok(config) => {
            let account = config.account.clone().unwrap_or_default();
            c.add(Draft {
                title: config
                    .issuer
                    .clone()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| account.clone()),
                username: account,
                totp: uri.to_string(),
                ..Default::default()
            })
        }
        Err(e) => c.skip(label, super::short_error(&e)),
    }
}

fn decode_label(path: &str) -> String {
    let path = path.trim_start_matches('/');
    url::form_urlencoded::parse(format!("x={}", path.replace('+', "%2B")).as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

// ---- Google Authenticator ---------------------------------------------------------------------

#[derive(Default)]
struct OtpParameters {
    secret: Vec<u8>,
    name: String,
    issuer: String,
    algorithm: u64,
    digits: u64,
    otp_type: u64,
}

#[derive(Default)]
struct MigrationPayload {
    otps: Vec<OtpParameters>,
    batch_size: i64,
    batch_index: i64,
    batch_id: i64,
}

fn parse_migration_uri(
    uri: &str,
    c: &mut Collector,
    batches: &mut BTreeMap<i64, (i64, Vec<i64>)>,
) -> Result<()> {
    let url = Url::parse(uri).map_err(|_| invalid(tr!("import.bad_link")))?;
    let data = url
        .query_pairs()
        .find(|(k, _)| k == "data")
        .map(|(_, v)| v.into_owned())
        .ok_or_else(|| invalid(tr!("import.link_no_data")))?;
    let bytes = crate::b64url_decode(data.replace(' ', "+"))?;
    let payload = decode_payload(&bytes)?;
    if payload.batch_size > 1 {
        let entry = batches
            .entry(payload.batch_id)
            .or_insert((payload.batch_size, Vec::new()));
        entry.1.push(payload.batch_index);
    }
    for otp in payload.otps {
        let issuer = otp.issuer.trim().to_string();
        // The name is "account" or "Issuer:account".
        let account = match otp.name.split_once(':') {
            Some((prefix, rest)) if issuer.is_empty() || prefix.trim() == issuer => {
                rest.trim().to_string()
            }
            _ => otp.name.trim().to_string(),
        };
        let label = c.label(if issuer.is_empty() { &account } else { &issuer });
        if otp.otp_type == 1 {
            c.skip(label, tr!("import.skip.hotp"));
            continue;
        }
        let algorithm = match otp.algorithm {
            0 | 1 => "SHA1",
            2 => "SHA256",
            3 => "SHA512",
            _ => {
                c.skip(label, tr!("import.skip.md5"));
                continue;
            }
        };
        if otp.secret.is_empty() {
            c.skip(label, tr!("import.skip.no_secret"));
            continue;
        }
        let digits = if otp.digits == 2 { 8 } else { 6 };
        c.add(Draft {
            title: if issuer.is_empty() {
                account.clone()
            } else {
                issuer.clone()
            },
            username: account.clone(),
            totp: build_otpauth(&issuer, &account, &otp.secret, algorithm, digits, 30),
            ..Default::default()
        });
    }
    Ok(())
}

/// Minimal protobuf reader for `MigrationPayload` (bounded, no recursion beyond one level).
struct Proto<'a> {
    buf: &'a [u8],
    pos: usize,
}

enum Field<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Fixed,
}

impl<'a> Proto<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for i in 0..10 {
            let byte = *self.buf.get(self.pos).ok_or_else(truncated)?;
            self.pos += 1;
            value |= u64::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(invalid(tr!("import.malformed_export")))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or_else(truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn next(&mut self) -> Result<Option<(u64, Field<'a>)>> {
        if self.pos >= self.buf.len() {
            return Ok(None);
        }
        let key = self.varint()?;
        let field = match key & 7 {
            0 => Field::Varint(self.varint()?),
            1 => {
                self.take(8)?;
                Field::Fixed
            }
            2 => {
                let len = usize::try_from(self.varint()?).map_err(|_| truncated())?;
                Field::Bytes(self.take(len)?)
            }
            5 => {
                self.take(4)?;
                Field::Fixed
            }
            _ => return Err(invalid(tr!("import.malformed_export"))),
        };
        Ok(Some((key >> 3, field)))
    }
}

fn truncated() -> PassError {
    invalid(tr!("import.export_incomplete"))
}

fn decode_payload(bytes: &[u8]) -> Result<MigrationPayload> {
    let mut payload = MigrationPayload::default();
    let mut p = Proto::new(bytes);
    while let Some((tag, field)) = p.next()? {
        match (tag, field) {
            (1, Field::Bytes(b)) => {
                if payload.otps.len() >= super::MAX_ENTRIES {
                    return Err(invalid(tr!("import.too_many_otp_entries")));
                }
                payload.otps.push(decode_otp(b)?);
            }
            (3, Field::Varint(v)) => payload.batch_size = v as i32 as i64,
            (4, Field::Varint(v)) => payload.batch_index = v as i32 as i64,
            (5, Field::Varint(v)) => payload.batch_id = v as i32 as i64,
            _ => {}
        }
    }
    Ok(payload)
}

fn decode_otp(bytes: &[u8]) -> Result<OtpParameters> {
    let mut otp = OtpParameters::default();
    let mut p = Proto::new(bytes);
    while let Some((tag, field)) = p.next()? {
        match (tag, field) {
            (1, Field::Bytes(b)) => otp.secret = b.to_vec(),
            (2, Field::Bytes(b)) => otp.name = String::from_utf8_lossy(b).into_owned(),
            (3, Field::Bytes(b)) => otp.issuer = String::from_utf8_lossy(b).into_owned(),
            (4, Field::Varint(v)) => otp.algorithm = v,
            (5, Field::Varint(v)) => otp.digits = v,
            (6, Field::Varint(v)) => otp.otp_type = v,
            _ => {}
        }
    }
    Ok(otp)
}

// ---- otpauth URIs ---------------------------------------------------------------------------

fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Builds a standard `otpauth://totp/Issuer:account?secret=…` URI.
pub(crate) fn build_otpauth(
    issuer: &str,
    account: &str,
    secret: &[u8],
    algorithm: &str,
    digits: u32,
    period: u32,
) -> String {
    let label = match (issuer.is_empty(), account.is_empty()) {
        (false, false) => format!("{}:{}", pct(issuer), pct(account)),
        (false, true) => pct(issuer),
        (true, _) => pct(account),
    };
    let mut uri = format!("otpauth://totp/{label}?secret={}", base32_encode(secret));
    if !issuer.is_empty() {
        uri.push_str(&format!("&issuer={}", pct(issuer)));
    }
    uri.push_str(&format!(
        "&algorithm={algorithm}&digits={digits}&period={period}"
    ));
    uri
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn u32_of(v: &Value, key: &str, default: u32) -> u32 {
    v.get(key)
        .and_then(|x| {
            x.as_u64()
                .or_else(|| x.as_str().and_then(|s| s.trim().parse().ok()))
        })
        .and_then(|x| u32::try_from(x).ok())
        .unwrap_or(default)
}

/// Common tail of Aegis and 2FAS: validates the parameters and adds the entry.
#[allow(clippy::too_many_arguments)]
fn add_totp(
    c: &mut Collector,
    issuer: &str,
    account: &str,
    secret_b32: &str,
    algorithm: &str,
    digits: u32,
    period: u32,
    notes: String,
    favorite: bool,
) {
    let issuer = issuer.trim();
    let account = account.trim();
    let label = c.label(if issuer.is_empty() { account } else { issuer });
    let algorithm = match algorithm.trim().to_ascii_uppercase().as_str() {
        "" | "SHA1" => "SHA1",
        "SHA256" => "SHA256",
        "SHA512" => "SHA512",
        other => {
            c.skip(
                label,
                tr!("import.skip.unsupported_algorithm", algorithm = other),
            );
            return;
        }
    };
    let secret = match base32_decode(secret_b32) {
        Ok(s) if !s.is_empty() => s,
        _ => {
            c.skip(label, tr!("import.skip.bad_secret"));
            return;
        }
    };
    if !(6..=10).contains(&digits) || !(1..=3600).contains(&period) {
        c.skip(
            label,
            tr!(
                "import.skip.unsupported_code_format",
                digits = digits,
                period = period
            ),
        );
        return;
    }
    c.add(Draft {
        title: if issuer.is_empty() {
            account.to_string()
        } else {
            issuer.to_string()
        },
        username: account.to_string(),
        totp: build_otpauth(issuer, account, &secret, algorithm, digits, period),
        notes,
        favorite,
        ..Default::default()
    });
}

// ---- Aegis ----------------------------------------------------------------------------------

pub(crate) fn parse_aegis(v: &Value, c: &mut Collector) -> Result<()> {
    let header_slots = v.get("header").and_then(|h| h.get("slots"));
    if v.get("db").is_some_and(Value::is_string) || header_slots.is_some_and(|s| !s.is_null()) {
        return Err(encrypted_error("Aegis"));
    }
    let entries = v
        .get("db")
        .and_then(|db| db.get("entries"))
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(tr!("import.aegis_no_entries")))?;
    for e in entries {
        if c.full() {
            break;
        }
        let kind = str_of(e, "type").to_ascii_lowercase();
        let name = str_of(e, "name");
        let issuer = str_of(e, "issuer");
        if kind != "totp" {
            let label = c.label(if issuer.is_empty() { name } else { issuer });
            c.skip(
                label,
                tr!("import.skip.unsupported_codes", kind = kind.to_uppercase()),
            );
            continue;
        }
        let info = e.get("info").unwrap_or(&Value::Null);
        add_totp(
            c,
            issuer,
            name,
            str_of(info, "secret"),
            str_of(info, "algo"),
            u32_of(info, "digits", 6),
            u32_of(info, "period", 30),
            str_of(e, "note").to_string(),
            e.get("favorite").and_then(Value::as_bool).unwrap_or(false),
        );
    }
    Ok(())
}

// ---- 2FAS -----------------------------------------------------------------------------------

pub(crate) fn parse_twofas(v: &Value, c: &mut Collector) -> Result<()> {
    let services = v.get("services").and_then(Value::as_array);
    let encrypted = v
        .get("servicesEncrypted")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty());
    if encrypted && services.is_none_or(|s| s.is_empty()) {
        return Err(encrypted_error("2FAS"));
    }
    let services = services.ok_or_else(|| invalid(tr!("import.two_fas_no_services")))?;
    for s in services {
        if c.full() {
            break;
        }
        let otp = s.get("otp").unwrap_or(&Value::Null);
        let issuer = match str_of(otp, "issuer") {
            "" => str_of(s, "name"),
            i => i,
        };
        let account = match str_of(otp, "account") {
            "" => str_of(otp, "label"),
            a => a,
        };
        let token_type = str_of(otp, "tokenType").to_ascii_uppercase();
        if !token_type.is_empty() && token_type != "TOTP" {
            let label = c.label(issuer);
            c.skip(
                label,
                tr!("import.skip.unsupported_codes", kind = token_type),
            );
            continue;
        }
        add_totp(
            c,
            issuer,
            account,
            str_of(s, "secret"),
            str_of(otp, "algorithm"),
            u32_of(otp, "digits", 6),
            u32_of(otp, "period", 30),
            String::new(),
            false,
        );
    }
    Ok(())
}
