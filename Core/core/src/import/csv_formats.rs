//! CSV exports. All of them are "one row per login" with different column names, so one reader
//! maps columns by name and each format only adds its quirks.

use std::collections::HashMap;

use super::{brand_id, invalid, parse_expiry, split_tags, Collector, Draft, ImportFormat};
use crate::i18n::tr;
use crate::model::{CardData, FieldKind, IdentityData, ItemKind};
use crate::Result;

fn reader(text: &str) -> csv::Reader<&[u8]> {
    csv::ReaderBuilder::new()
        .flexible(true)
        .has_headers(true)
        .trim(csv::Trim::Headers)
        .from_reader(text.as_bytes())
}

fn header_map(text: &str) -> Option<HashMap<String, usize>> {
    let mut r = reader(text);
    let headers = r.headers().ok()?;
    let mut map = HashMap::new();
    for (i, h) in headers.iter().enumerate() {
        map.entry(h.trim().trim_matches('"').to_ascii_lowercase())
            .or_insert(i);
    }
    Some(map)
}

/// Recognises a CSV export from its header row.
pub(crate) fn detect(text: &str) -> Option<ImportFormat> {
    let h = header_map(text)?;
    let has = |k: &str| h.contains_key(k);
    let all = |ks: &[&str]| ks.iter().all(|k| has(k));
    Some(if all(&["login_uri", "login_password"]) {
        ImportFormat::BitwardenCsv
    } else if all(&["httprealm", "formactionorigin"]) {
        ImportFormat::FirefoxCsv
    } else if all(&["type", "name", "email", "password", "totp", "vault"]) {
        ImportFormat::ProtonPassCsv
    } else if all(&["group", "title", "username", "password", "url", "notes"]) {
        ImportFormat::KeepassxcCsv
    } else if all(&["url", "password", "extra", "grouping"]) {
        ImportFormat::LastpassCsv
    } else if has("username2")
        || all(&["title", "password", "note", "category"])
        || all(&["cc_number", "account_holder"])
        || all(&["item_name", "first_name", "last_name", "place_of_birth"])
    {
        ImportFormat::DashlaneCsv
    } else if has("otpauth") && (has("archived") || has("tags") || has("favorite")) {
        ImportFormat::OnePasswordCsv
    } else if all(&["title", "url", "username", "password"]) && has("otpauth") {
        ImportFormat::AppleCsv
    } else if all(&["name", "url", "username", "password"]) {
        ImportFormat::ChromeCsv
    } else if has("password") && (has("url") || has("title") || has("name") || has("username"))
        || has("title") && (has("notes") || has("note"))
    {
        ImportFormat::GenericCsv
    } else {
        return None;
    })
}

struct Columns {
    map: HashMap<String, usize>,
}

impl Columns {
    fn find(&self, names: &[&str]) -> Option<usize> {
        names.iter().find_map(|n| self.map.get(*n).copied())
    }
}

fn cell(record: &csv::StringRecord, idx: Option<usize>) -> String {
    idx.and_then(|i| record.get(i))
        .unwrap_or_default()
        .trim_matches('\u{feff}')
        .to_string()
}

fn truthy(s: &str) -> bool {
    matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "y" | "x" | "*"
    )
}

/// Several exports pack multiple URLs into one cell, separated by commas (and spaces).
fn split_urls(s: &str) -> Vec<String> {
    let parts: Vec<&str> = s
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect();
    if parts.len() > 1 && parts.iter().all(|p| !p.contains(' ')) {
        parts.into_iter().map(str::to_string).collect()
    } else {
        vec![s.trim().to_string()]
    }
}

pub(crate) fn parse(text: &str, format: ImportFormat, c: &mut Collector) -> Result<()> {
    let map = header_map(text).ok_or_else(|| invalid(tr!("import.csv_no_header")))?;
    let cols = Columns { map };
    if format == ImportFormat::DashlaneCsv {
        if cols.map.contains_key("cc_number") {
            return parse_dashlane_payments(text, &cols, c);
        }
        if cols.map.contains_key("first_name") && cols.map.contains_key("item_name") {
            return parse_dashlane_personal(text, &cols, c);
        }
    }
    let title = cols.find(&["name", "title"]);
    let url = cols.find(&[
        "url",
        "login_uri",
        "website",
        "uri",
        "web site",
        "urls",
        "login url",
    ]);
    let username = cols.find(&["username", "login_username", "login", "user name", "user"]);
    let email = cols.find(&["email", "e-mail"]);
    let password = cols.find(&["password", "login_password"]);
    let notes = cols.find(&["notes", "note", "extra", "comments", "comment"]);
    let totp = cols.find(&[
        "totp",
        "otpauth",
        "login_totp",
        "otpurl",
        "otpsecret",
        "otp",
        "one-time password",
    ]);
    let kind_col = cols.find(&["type"]);
    let favorite = cols.find(&["favorite", "fav"]);
    let group = cols.find(&["group", "grouping", "folder", "collections"]);
    let tags_col = cols.find(&["tags", "category"]);
    let fields = cols.find(&["fields"]);
    let archived = cols.find(&["archived"]);
    let alt_users = [cols.find(&["username2"]), cols.find(&["username3"])];
    if password.is_none() && notes.is_none() && totp.is_none() {
        return Err(invalid(tr!("import.csv_no_columns")));
    }

    let mut r = reader(text);
    for (row, record) in r.records().enumerate() {
        if c.full() {
            break;
        }
        let record = match record {
            Ok(r) => r,
            Err(_) => {
                c.skip(
                    tr!("import.row_number", number = row + 2),
                    tr!("import.skip.unreadable_row"),
                );
                continue;
            }
        };
        if record.iter().all(|f| f.trim().is_empty()) {
            continue;
        }
        let mut d = Draft {
            title: cell(&record, title),
            username: cell(&record, username),
            email: cell(&record, email),
            password: cell(&record, password),
            notes: cell(&record, notes),
            totp: cell(&record, totp),
            favorite: truthy(&cell(&record, favorite)),
            ..Default::default()
        };
        let url_cell = cell(&record, url);
        d.urls = match format {
            ImportFormat::BitwardenCsv | ImportFormat::ProtonPassCsv => split_urls(&url_cell),
            _ => vec![url_cell.trim().to_string()],
        };
        let label = c.label(if d.title.is_empty() {
            &url_cell
        } else {
            &d.title
        });
        let kind = cell(&record, kind_col).to_ascii_lowercase();
        let group_name = cell(&record, group);
        d.tags = group_tags(format, &group_name);
        d.tags.extend(split_tags(&cell(&record, tags_col)));

        match format {
            ImportFormat::BitwardenCsv => {
                match kind.as_str() {
                    "" | "login" => {}
                    "note" => d.kind = ItemKind::Note,
                    other => {
                        c.skip(label, tr!("import.skip.unsupported_type", kind = other));
                        continue;
                    }
                }
                // Custom fields: "name: value" lines (hidden ones aren't marked).
                let custom = cell(&record, fields);
                for line in custom.lines().filter(|l| !l.trim().is_empty()) {
                    match line.split_once(':') {
                        Some((k, v)) => d.field(k, v, FieldKind::Text),
                        None => d.field("", line, FieldKind::Text),
                    }
                }
            }
            ImportFormat::ProtonPassCsv => match kind.as_str() {
                "" | "login" => {}
                "note" => d.kind = ItemKind::Note,
                other => {
                    c.skip(label, tr!("import.skip.unsupported_type", kind = other));
                    continue;
                }
            },
            ImportFormat::FirefoxCsv if url_cell.starts_with("chrome://") => {
                c.skip(label, tr!("import.skip.firefox_account"));
                continue;
            }
            ImportFormat::LastpassCsv if url_cell.trim().eq_ignore_ascii_case("http://sn") => {
                d.kind = ItemKind::Note;
                d.urls.clear();
                lastpass_note_type(&mut d);
            }
            ImportFormat::KeepassxcCsv
                if group_name.to_ascii_lowercase().contains("recycle bin") =>
            {
                c.skip(label, tr!("import.skip.keepass_recycle_bin"));
                continue;
            }
            ImportFormat::DashlaneCsv => {
                for alt in alt_users {
                    let v = cell(&record, alt);
                    if !v.trim().is_empty() {
                        d.field(
                            &tr!("import.field.alternative_username"),
                            &v,
                            FieldKind::Text,
                        );
                    }
                }
            }
            ImportFormat::OnePasswordCsv if truthy(&cell(&record, archived)) => {
                c.skip(label, tr!("import.skip.one_password_archived"));
                continue;
            }
            _ => {}
        }
        if d.kind == ItemKind::Login
            && password.is_none()
            && url.is_none()
            && username.is_none()
            && totp.is_none()
        {
            d.kind = ItemKind::Note;
        }
        c.add(d);
    }
    Ok(())
}

/// The tags of a folder / group cell. KeePassXC's root group (`Root/…`) is dropped and LastPass
/// nests folders with `\`.
fn group_tags(format: ImportFormat, group: &str) -> Vec<String> {
    let group = group.trim();
    if group.is_empty() {
        return Vec::new();
    }
    let tag = match format {
        ImportFormat::KeepassxcCsv => {
            let mut parts: Vec<&str> = group.split('/').collect();
            if parts
                .first()
                .is_some_and(|p| p.trim().eq_ignore_ascii_case("root"))
            {
                parts.remove(0);
            }
            parts.join("/")
        }
        ImportFormat::LastpassCsv => group.replace('\\', "/"),
        _ => group.to_string(),
    };
    if tag.trim().is_empty() {
        Vec::new()
    } else {
        vec![tag]
    }
}

/// LastPass secure notes of type "Credit Card" and "Address" (`NoteType:` lines in the notes)
/// become a card and an identity; their `Notes:` stay the notes.
fn lastpass_note_type(d: &mut Draft) {
    let text = d.notes.replace("\r\n", "\n");
    let Some(rest) = text.strip_prefix("NoteType:") else {
        return;
    };
    let mut lines = rest.lines();
    let note_type = lines.next().unwrap_or_default().trim().to_string();
    let mut map: HashMap<String, String> = HashMap::new();
    let mut notes = String::new();
    let mut in_notes = false;
    for line in lines {
        if in_notes {
            notes.push('\n');
            notes.push_str(line);
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k == "Notes" {
                in_notes = true;
                notes = v.to_string();
                continue;
            }
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    let get = |k: &str| map.get(k).cloned().unwrap_or_default();
    match note_type.as_str() {
        "Credit Card" => {
            let (expiry_month, expiry_year) = parse_expiry(&get("Expiration Date"));
            d.kind = ItemKind::Card;
            d.card = Some(CardData {
                cardholder_name: get("Name on Card"),
                number: get("Number"),
                expiry_month,
                expiry_year,
                security_code: get("Security Code"),
                brand: brand_id(&get("Type")),
                ..Default::default()
            });
        }
        "Address" => {
            // Phones are JSON (`{"num":"…","ext":"","cc3l":"USA"}`) in newer exports.
            let phone = get("Phone");
            let phone = serde_json::from_str::<serde_json::Value>(&phone)
                .ok()
                .and_then(|v| v.get("num").and_then(|n| n.as_str()).map(str::to_string))
                .unwrap_or(phone);
            let birthday = get("Birthday");
            d.kind = ItemKind::Identity;
            d.identity = Some(IdentityData {
                honorific: get("Title"),
                first_name: get("First Name"),
                middle_name: get("Middle Name"),
                last_name: get("Last Name"),
                email: get("Email Address"),
                phone,
                address1: get("Address 1"),
                address2: get("Address 2"),
                address3: get("Address 3"),
                city: get("City / Town"),
                region: match get("State") {
                    s if s.is_empty() => get("County"),
                    s => s,
                },
                postal_code: get("Zip / Postal Code"),
                country: get("Country"),
                company: get("Company"),
                birth_date: if birthday.trim_matches(',').trim().is_empty() {
                    String::new()
                } else {
                    birthday
                },
            });
            d.field(
                &tr!("import.field.username"),
                &get("Username"),
                FieldKind::Text,
            );
        }
        _ => return,
    }
    d.notes = notes.trim().to_string();
}

/// Dashlane `payments.csv`: payment cards, and bank accounts as notes with custom fields.
fn parse_dashlane_payments(text: &str, cols: &Columns, c: &mut Collector) -> Result<()> {
    let col = |n: &str| cols.find(&[n]);
    let mut r = reader(text);
    for record in r.records() {
        if c.full() {
            break;
        }
        let Ok(record) = record else {
            continue;
        };
        if record.iter().all(|f| f.trim().is_empty()) {
            continue;
        }
        let get = |n: &str| cell(&record, col(n));
        let mut d = Draft {
            title: match get("name") {
                n if n.trim().is_empty() => get("account_name"),
                n => n,
            },
            notes: get("note"),
            ..Default::default()
        };
        match get("type").to_ascii_lowercase().as_str() {
            "payment_card" | "" => {
                d.kind = ItemKind::Card;
                let month: u32 = get("expiration_month").trim().parse().unwrap_or(0);
                d.card = Some(CardData {
                    cardholder_name: get("account_holder"),
                    number: get("cc_number"),
                    expiry_month: if (1..=12).contains(&month) { month } else { 0 },
                    expiry_year: parse_expiry(&format!("01/{}", get("expiration_year"))).1,
                    security_code: get("code"),
                    ..Default::default()
                });
            }
            "bank" => {
                d.kind = ItemKind::Note;
                d.field(
                    &tr!("import.field.account_holder"),
                    &get("account_holder"),
                    FieldKind::Text,
                );
                d.field(
                    &tr!("import.field.account_number"),
                    &get("account_number"),
                    FieldKind::Hidden,
                );
                d.field(
                    &tr!("import.field.routing_number"),
                    &get("routing_number"),
                    FieldKind::Text,
                );
                d.field(
                    &tr!("import.field.bank"),
                    &get("issuing_bank"),
                    FieldKind::Text,
                );
                d.field(
                    &tr!("import.field.country"),
                    &get("country"),
                    FieldKind::Text,
                );
            }
            other => {
                let label = c.label(&d.title);
                c.skip(label, tr!("import.skip.unsupported_type", kind = other));
                continue;
            }
        }
        c.add(d);
    }
    Ok(())
}

/// Dashlane `personalInfo.csv`: one row per name, email, phone, address or website. They become
/// one identity; values beyond the first of each kind go to custom fields.
fn parse_dashlane_personal(text: &str, cols: &Columns, c: &mut Collector) -> Result<()> {
    let col = |n: &str| cols.find(&[n]);
    let mut d = Draft {
        kind: ItemKind::Identity,
        title: tr!("import.title.dashlane_personal"),
        ..Default::default()
    };
    let mut id = IdentityData::default();
    let mut r = reader(text);
    let set = |slot: &mut String, value: String, name: &str, d: &mut Draft| {
        if value.trim().is_empty() {
            return;
        }
        if slot.trim().is_empty() {
            *slot = value;
        } else if *slot != value {
            d.field(name, &value, FieldKind::Text);
        }
    };
    for record in r.records() {
        let Ok(record) = record else {
            continue;
        };
        let get = |n: &str| cell(&record, col(n));
        match get("type").to_ascii_lowercase().as_str() {
            "name" => {
                set(
                    &mut id.honorific,
                    get("title"),
                    &tr!("import.field.title"),
                    &mut d,
                );
                set(
                    &mut id.first_name,
                    get("first_name"),
                    &tr!("import.field.first_name"),
                    &mut d,
                );
                set(
                    &mut id.middle_name,
                    get("middle_name"),
                    &tr!("import.field.middle_name"),
                    &mut d,
                );
                set(
                    &mut id.last_name,
                    get("last_name"),
                    &tr!("import.field.last_name"),
                    &mut d,
                );
                set(
                    &mut id.birth_date,
                    get("date_of_birth"),
                    &tr!("import.field.birth_date"),
                    &mut d,
                );
                d.field(
                    &tr!("import.field.place_of_birth"),
                    &get("place_of_birth"),
                    FieldKind::Text,
                );
            }
            "email" => set(
                &mut id.email,
                get("email"),
                &tr!("import.field.email"),
                &mut d,
            ),
            "number" => set(
                &mut id.phone,
                get("phone_number"),
                &tr!("import.field.phone"),
                &mut d,
            ),
            "address" => {
                set(
                    &mut id.address1,
                    get("address"),
                    &tr!("import.field.address"),
                    &mut d,
                );
                let extra: Vec<String> = ["address_building", "address_apartment", "address_floor"]
                    .iter()
                    .map(|k| get(k))
                    .filter(|v| !v.trim().is_empty())
                    .collect();
                set(
                    &mut id.address2,
                    extra.join(", "),
                    &tr!("import.field.address"),
                    &mut d,
                );
                set(&mut id.city, get("city"), &tr!("import.field.city"), &mut d);
                set(
                    &mut id.region,
                    get("state"),
                    &tr!("import.field.state"),
                    &mut d,
                );
                set(
                    &mut id.postal_code,
                    get("zip"),
                    &tr!("import.field.postal_code"),
                    &mut d,
                );
                set(
                    &mut id.country,
                    get("country"),
                    &tr!("import.field.country"),
                    &mut d,
                );
            }
            "website" => d.field(&tr!("import.field.website"), &get("url"), FieldKind::Url),
            "company" => set(
                &mut id.company,
                get("item_name"),
                &tr!("import.field.company"),
                &mut d,
            ),
            _ => {}
        }
        if !get("job_title").trim().is_empty() {
            d.field(
                &tr!("import.field.job_title"),
                &get("job_title"),
                FieldKind::Text,
            );
        }
    }
    d.identity = Some(id);
    c.add(d);
    Ok(())
}
