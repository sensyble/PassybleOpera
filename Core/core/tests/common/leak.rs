//! Canary vaults and the canary scanner for the "nothing leaves a device unencrypted" tests.
//! [`Needles::scan`] finds the canaries in captured bytes, plain or inside base64, hex, JSON and
//! percent escapes and gzip, a few layers deep. The includer brings the core's types into scope
//! (`use super::*`), so unit and integration tests share this file.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::io::Read;

use base64::Engine;

use super::*;

/// Base32, so the TOTP parser accepts it; found through `canary`.
pub const TOTP_SECRET: &str = "CANARYTOTPSECRETAAAAAAAA";
/// A card number with no known brand (so the canary brand is kept), digits only once stored.
pub const CARD_NUMBER: &str = "9137 7300 4210 5583";

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// A recognisable byte pattern (every byte has the high bit set, so it is never ASCII).
pub fn pattern(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (seed ^ (i as u8).wrapping_mul(37)) | 0x80)
        .collect()
}

pub fn user_handle() -> Vec<u8> {
    pattern(0x17, 16)
}
pub fn private_key() -> Vec<u8> {
    pattern(0x5e, 48)
}
pub fn credential_id() -> Vec<u8> {
    pattern(0x6c, 20)
}

/// The strings and byte patterns searched for. Text needles are compared in lowercase.
pub struct Needles {
    /// (name, lowercase bytes): any hit is a leak.
    secret: Vec<(String, Vec<u8>)>,
    /// Raw byte patterns: any hit is a leak.
    binary: Vec<(String, Vec<u8>)>,
    /// (name, lowercase bytes): cleartext by design, located for the report.
    admin: Vec<(String, Vec<u8>)>,
}

impl Needles {
    pub fn new() -> Needles {
        let text = |s: &str| (s.to_string(), s.to_ascii_lowercase().into_bytes());
        let digits: String = CARD_NUMBER.chars().filter(char::is_ascii_digit).collect();
        Needles {
            secret: vec![
                // Every text canary contains "canary" (`CANARY-...`, `canary-...` URLs and
                // addresses, `com.canary_...` packages, the TOTP secret).
                text("canary"),
                text(&digits),
                text(CARD_NUMBER),
            ],
            binary: [
                ("user_handle", user_handle()),
                ("private_key_pkcs8", private_key()),
                ("credential_id", credential_id()),
            ]
            .into_iter()
            .map(|(n, b)| (n.to_string(), b[..12].to_vec()))
            .collect(),
            admin: Vec::new(),
        }
    }

    /// A secret only known at run time (a recovery code), in the forms it could be written.
    pub fn add_secret(&mut self, name: &str, value: &str) {
        let lower = value.to_ascii_lowercase();
        self.secret
            .push((name.to_string(), lower.clone().into_bytes()));
        let bare: String = lower.chars().filter(|c| *c != '-' && *c != ' ').collect();
        if bare != lower {
            self.secret
                .push((format!("{name} (bare)"), bare.into_bytes()));
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hit {
    pub source: String,
    pub needle: String,
    /// The decoding layers that led to it (`raw`, `b64@2/raw`, ...).
    pub path: String,
    pub admin: bool,
}

fn find(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    let first = needle[0];
    let mut i = 0;
    while let Some(p) = hay[i..=hay.len() - needle.len()]
        .iter()
        .position(|&b| b == first)
    {
        let at = i + p;
        if hay[at..].starts_with(needle) {
            return true;
        }
        i = at + 1;
        if i > hay.len() - needle.len() {
            break;
        }
    }
    false
}

fn is_b64(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_')
}

/// Maximal runs of bytes matching `class`, at least `min` long.
fn runs(bytes: &[u8], class: fn(u8) -> bool, min: usize) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, &b) in bytes.iter().enumerate() {
        match (class(b), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= min {
                    out.push(&bytes[s..i]);
                }
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        if bytes.len() - s >= min {
            out.push(&bytes[s..]);
        }
    }
    out
}

fn b64_lenient() -> base64::engine::GeneralPurpose {
    base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    )
}

/// `run` decoded as base64 starting `offset` characters in, both alphabets at once (they differ
/// only in `+/` against `-_`).
fn b64_at(run: &[u8], offset: usize) -> Option<Vec<u8>> {
    let tail = run.get(offset..)?;
    // Unpadded is fine; only a lone last character (never valid base64) is dropped.
    let usable = if tail.len() % 4 == 1 {
        tail.len() - 1
    } else {
        tail.len()
    };
    if usable < 8 {
        return None;
    }
    let std: Vec<u8> = tail[..usable]
        .iter()
        .map(|&b| match b {
            b'-' => b'+',
            b'_' => b'/',
            b => b,
        })
        .collect();
    b64_lenient().decode(std).ok()
}

fn hex_at(run: &[u8], offset: usize) -> Option<Vec<u8>> {
    let tail = run.get(offset..)?;
    let pairs = tail.len() / 2;
    if pairs < 6 {
        return None;
    }
    let digit = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    (0..pairs)
        .map(|i| Some(digit(tail[2 * i])? << 4 | digit(tail[2 * i + 1])?))
        .collect()
}

/// `\uXXXX` and `\/` undone (JSON escapes).
fn json_unescape(bytes: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('u') => {
                    chars.next();
                    let hex: String = chars.by_ref().take(4).collect();
                    match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                        Some(ch) => out.push(ch),
                        None => out.push_str(&hex),
                    }
                }
                Some('/') => {
                    chars.next();
                    out.push('/');
                }
                _ => out.push(c),
            }
        } else {
            out.push(c);
        }
    }
    out.into_bytes()
}

fn percent_decode(bytes: &[u8]) -> Vec<u8> {
    percent_encoding::percent_decode(bytes).collect()
}

/// HTTP chunk headers (`\r\n<hex>\r\n`) removed, so a body split into chunks reads as one.
fn dechunk(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"\r\n") {
            let mut j = i + 2;
            while j < bytes.len() && bytes[j].is_ascii_hexdigit() {
                j += 1;
            }
            if j > i + 2 && bytes[j..].starts_with(b"\r\n") {
                i = j + 2;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

const MAX_DEPTH: usize = 4;

impl Needles {
    pub fn scan(&self, source: &str, bytes: &[u8], hits: &mut BTreeSet<Hit>) {
        self.scan_at(source, bytes, "raw", 0, hits);
        if bytes.windows(2).any(|w| w == b"\r\n") {
            self.scan_at(source, &dechunk(bytes), "dechunked", 1, hits);
        }
    }

    fn scan_at(
        &self,
        source: &str,
        bytes: &[u8],
        path: &str,
        depth: usize,
        hits: &mut BTreeSet<Hit>,
    ) {
        let lower = bytes.to_ascii_lowercase();
        let mut hit = |needle: &str, admin: bool| {
            hits.insert(Hit {
                source: source.to_string(),
                needle: needle.to_string(),
                path: path.to_string(),
                admin,
            });
        };
        for (name, n) in &self.secret {
            if find(&lower, n) {
                hit(name, false);
            }
        }
        for (name, n) in &self.binary {
            if find(bytes, n) {
                hit(name, false);
            }
        }
        for (name, n) in &self.admin {
            if find(&lower, n) {
                hit(name, true);
            }
        }
        if depth >= MAX_DEPTH {
            return;
        }
        if bytes.starts_with(&[0x1f, 0x8b]) {
            let mut out = Vec::new();
            // A truncated stream (a base64 run cut short) still yields what came before the cut.
            let _ = flate2::read::GzDecoder::new(bytes).read_to_end(&mut out);
            if !out.is_empty() {
                self.scan_at(source, &out, &format!("{path}/gzip"), depth + 1, hits);
            }
        }
        for run in runs(bytes, is_b64, 10) {
            for offset in 0..4 {
                if let Some(d) = b64_at(run, offset) {
                    self.scan_at(source, &d, &format!("{path}/b64@{offset}"), depth + 1, hits);
                }
            }
        }
        for run in runs(bytes, |b| b.is_ascii_hexdigit(), 14) {
            for offset in 0..2 {
                if let Some(d) = hex_at(run, offset) {
                    self.scan_at(source, &d, &format!("{path}/hex@{offset}"), depth + 1, hits);
                }
            }
        }
        if find(bytes, b"\\u") || find(bytes, b"\\/") {
            self.scan_at(
                source,
                &json_unescape(bytes),
                &format!("{path}/json"),
                depth + 1,
                hits,
            );
        }
        if bytes.contains(&b'%') {
            let d = percent_decode(bytes);
            if d != bytes {
                self.scan_at(source, &d, &format!("{path}/pct"), depth + 1, hits);
            }
        }
    }
}

pub fn canary(tag: &str, field: &str) -> String {
    format!("CANARY-{tag}-{field}-7f3a")
}

pub fn passkey(tag: &str) -> Passkey {
    Passkey {
        credential_id: credential_id(),
        rp_id: format!("canary-{tag}-rpid-7f3a.example"),
        rp_name: Some(canary(tag, "rpname")),
        user_handle: user_handle(),
        user_name: canary(tag, "pkusername"),
        user_display_name: canary(tag, "pkdisplayname"),
        private_key_pkcs8: private_key(),
        sign_count: 3,
        discoverable: true,
        created_at: now_ms(),
    }
}

/// Fills `v` with one item of every kind, every field a canary; edits the login's password three
/// times (a history) and records a use.
pub fn fill(v: &Vault, tag: &str) {
    let c = |f: &str| canary(tag, f);
    let login = v
        .upsert(Item {
            kind: ItemKind::Login,
            title: c("title"),
            username: c("username"),
            password: c("password0"),
            urls: vec![
                format!("https://canary-{tag}-url-7f3a.example/login"),
                format!("https://canary-{tag}-url2-7f3a.example"),
            ],
            android_apps: vec![AndroidApp {
                package: format!("com.canary_{tag}_pkg"),
                cert_sha256: None,
                ..Default::default()
            }],
            totp: Some(format!(
                "otpauth://totp/CANARY-{tag}-totplabel-7f3a?secret={TOTP_SECRET}&issuer=CANARY-{tag}-issuer-7f3a"
            )),
            passkeys: vec![passkey(tag)],
            notes: c("notes"),
            favorite: true,
            fields: vec![
                CustomField {
                    name: c("fieldname"),
                    value: c("fieldvalue"),
                    kind: FieldKind::Hidden,
                },
                CustomField {
                    name: c("urlfieldname"),
                    value: format!("https://canary-{tag}-fieldurl-7f3a.example"),
                    kind: FieldKind::Url,
                },
            ],
            tags: vec![c("tag1"), c("tag2")],
            ..Default::default()
        })
        .unwrap();
    for i in 1..=3 {
        std::thread::sleep(std::time::Duration::from_millis(2));
        let mut item = v.get(login.id.clone()).unwrap();
        item.password = c(&format!("password{i}"));
        v.upsert(item).unwrap();
    }
    assert_eq!(v.get(login.id.clone()).unwrap().password_history.len(), 3);
    v.upsert(Item {
        kind: ItemKind::Note,
        title: c("notetitle"),
        notes: c("notebody"),
        tags: vec![c("notetag")],
        fields: vec![CustomField {
            name: c("notefieldname"),
            value: c("notefieldvalue"),
            kind: FieldKind::Text,
        }],
        ..Default::default()
    })
    .unwrap();
    let card = v
        .upsert(Item {
            kind: ItemKind::Card,
            title: c("cardtitle"),
            notes: c("cardnotes"),
            card: Some(CardData {
                cardholder_name: c("holder"),
                number: CARD_NUMBER.into(),
                expiry_month: 7,
                expiry_year: 2031,
                security_code: c("cvv"),
                pin: c("pin"),
                brand: c("brand"),
            }),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(card.card.unwrap().brand, c("brand").to_ascii_lowercase());
    v.upsert(Item {
        kind: ItemKind::Identity,
        title: c("idtitle"),
        identity: Some(IdentityData {
            honorific: c("honorific"),
            first_name: c("first"),
            middle_name: c("middle"),
            last_name: c("last"),
            email: format!("canary-{tag}-idemail-7f3a@example.com"),
            phone: c("phone"),
            address1: c("address1"),
            address2: c("address2"),
            address3: c("address3"),
            city: c("city"),
            region: c("region"),
            postal_code: c("postal"),
            country: c("country"),
            company: c("company"),
            birth_date: c("birth"),
        }),
        ..Default::default()
    })
    .unwrap();
    v.record_use(login.id, now_ms()).unwrap();
}

/// The vault settings of a personal vault: an alias service with its API token, and the e-mail
/// generator's addresses.
pub fn fill_settings(v: &Vault, tag: &str) {
    v.set_alias_config(AliasConfig {
        service: AliasService::SimpleLogin,
        token: canary(tag, "aliastoken"),
        base_url: format!("https://canary-{tag}-aliasbase-7f3a.example"),
        domain: String::new(),
    })
    .unwrap();
    v.set_email_generator_settings(EmailGeneratorSettings {
        address: format!("canary-{tag}-genaddress-7f3a@example.com"),
        domain: format!("canary-{tag}-catchall-7f3a.example"),
    })
    .unwrap();
    assert_eq!(v.alias_configs().len(), 1);
}

/// Scans every `(source, bytes)` and fails with the list of hits, if any.
pub fn assert_no_canary(needles: &Needles, captured: &[(String, Vec<u8>)]) {
    let mut hits = BTreeSet::new();
    for (source, bytes) in captured {
        needles.scan(source, bytes, &mut hits);
    }
    assert!(hits.is_empty(), "canaries found: {hits:#?}");
}

/// The plain-HTTP rule: every request goes over HTTPS, or to a loopback or private address.
pub fn assert_https_or_local(url: &str) {
    assert!(
        url.starts_with("https://") || !plain_http_refused(url.to_string()),
        "plain HTTP to a public address: {url}"
    );
}

/// An uploaded vault file never carries the device's local-only fields (the sync state, a home
/// vault's unconfirmed member changes).
pub fn assert_no_local_fields(source: &str, file: &[u8]) {
    let json: serde_json::Value = serde_json::from_slice(file)
        .unwrap_or_else(|e| panic!("{source} is not a vault file: {e}"));
    assert_eq!(json["format"], "pass-vault", "{source}");
    for local in ["sync", "local_members"] {
        assert!(json.get(local).is_none(), "{source} carries `{local}`");
    }
}
