//! Checks the locale catalogs against the code: every key used by `tr!` / `trn!` exists in
//! `en.json` with matching placeholders, and other catalogs only have keys `en.json` has.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::i18n::plural_category;

const CATEGORIES: [&str; 6] = ["zero", "one", "two", "few", "many", "other"];

/// Catalog keys the apps match on through `core_message_is` / `core_message_arg`. Renaming one
/// breaks the apps.
pub(crate) const APP_MATCHED_KEYS: &[&str] = &[
    "alias.*",
    "gdrive.*",
    "gdrive.api_disabled",
    "gdrive.app_folder_denied",
    "gdrive.busy",
    "gdrive.refused",
    "gdrive.storage_full",
    "gdrive.vault_gone",
    "gdrive.vault_removed",
    // Network failures in plain words (core/src/net.rs), for the apps to tell apart: an untrusted
    // certificate (the "Trust this server?" step), an expired one, a server error, and so on.
    "net.*",
    "net.certificate_dates",
    "net.untrusted_certificate",
    "pinning.cant_connect",
    "server.auth_failed",
    "server.cant_send_email",
    "server.too_many_*",
    "server.too_many_attempts",
    "server.unexpected_answer",
    "server.unknown_language",
    "server.unsafe_parameters",
    "server.unsupported.*",
    "server.no_devices_api",
    "server.no_security_events",
    "server.password_change_required",
    "server.unsupported.sign_in",
    "server.unsupported.two_factor",
    "vault.different_key",
    "vault.different_vault",
    "webdav.auth_failed",
    "webdav.no_parent_folder",
    "webdav.quota_reached",
    "webdav.quota_reached_detail",
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn load(file: &Path) -> Map<String, Value> {
    let text = std::fs::read_to_string(file).unwrap_or_else(|e| panic!("{file:?}: {e}"));
    match serde_json::from_str(&text) {
        Ok(Value::Object(map)) => map,
        Ok(_) => panic!("{file:?}: not a JSON object"),
        Err(e) => panic!("{file:?}: not valid JSON: {e}"),
    }
}

fn english() -> Map<String, Value> {
    load(&root().join("locales/en.json"))
}

/// The `{name}` placeholders of a text.
fn placeholders(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = text;
    while let Some(open) = rest.find('{') {
        rest = &rest[open + 1..];
        let len = rest
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
            .count();
        if len > 0 && rest[len..].starts_with('}') {
            out.insert(rest[..len].to_string());
        }
    }
    out
}

/// The placeholders of an entry (all plural forms together); `{count}` of a plural is implied.
fn entry_placeholders(value: &Value) -> BTreeSet<String> {
    match value {
        Value::Object(forms) => {
            let mut set: BTreeSet<String> = forms
                .values()
                .filter_map(Value::as_str)
                .flat_map(placeholders)
                .collect();
            set.remove("count");
            set
        }
        other => placeholders(other.as_str().unwrap_or_default()),
    }
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

/// Source without `//` comments (doc examples aren't uses).
fn code(file: &Path) -> String {
    std::fs::read_to_string(file)
        .unwrap()
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

struct Use {
    key: String,
    plural: bool,
    params: Vec<String>,
    file: String,
}

/// Every `tr!("key", name = …)` / `trn!("key", count, name = …)` in the core's code, except
/// this file and i18n.rs (their tests use made-up keys and catalogs).
fn uses() -> Vec<Use> {
    let mut files = Vec::new();
    rust_files(&root().join("src"), &mut files);
    let mut out = Vec::new();
    for file in files {
        let name = file.file_name().unwrap().to_string_lossy().to_string();
        if name == "i18n.rs" || name == "i18n_tests.rs" {
            continue;
        }
        let src = code(&file);
        for (macro_name, plural) in [("trn!(", true), ("tr!(", false)] {
            let mut from = 0;
            while let Some(found) = src[from..].find(macro_name) {
                let start = from + found;
                from = start + macro_name.len();
                // Skip identifiers that merely end in the macro name.
                if src[..start]
                    .chars()
                    .last()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_')
                {
                    continue;
                }
                let args = &src[from..];
                let args_trimmed = args.trim_start();
                let Some(after_quote) = args_trimmed.strip_prefix('"') else {
                    continue;
                };
                let key: String = after_quote.chars().take_while(|c| *c != '"').collect();
                let mut depth = 1;
                let mut top = String::new();
                let mut in_str = false;
                let mut prev = ' ';
                for c in args.chars() {
                    if in_str {
                        if c == '"' && prev != '\\' {
                            in_str = false;
                        }
                        prev = c;
                        continue;
                    }
                    match c {
                        '"' => in_str = true,
                        '(' | '[' | '{' => depth += 1,
                        ')' | ']' | '}' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ if depth == 1 => top.push(c),
                        _ => {}
                    }
                    prev = c;
                }
                let params = top
                    .split(',')
                    .skip(1)
                    .filter_map(|part| {
                        let (name, rest) = part.split_once('=')?;
                        let name = name.trim();
                        (!rest.starts_with('=')
                            && !name.is_empty()
                            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
                        .then(|| name.to_string())
                    })
                    .collect();
                out.push(Use {
                    key,
                    plural,
                    params,
                    file: file
                        .strip_prefix(root())
                        .unwrap_or(&file)
                        .display()
                        .to_string(),
                });
            }
        }
    }
    out
}

#[test]
fn english_catalog_is_well_formed() {
    let en = english();
    let meta = en.get("_meta").expect("_meta");
    assert!(
        meta["name"].is_string() && meta["native"].is_string(),
        "_meta needs name and native"
    );
    for (key, value) in &en {
        if key == "_meta" {
            continue;
        }
        let parts: Vec<&str> = key.split('.').collect();
        assert!(
            parts.len() >= 2
                && parts.iter().all(|p| !p.is_empty()
                    && p.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')),
            "{key}: keys are dotted lower-case words"
        );
        match value {
            Value::String(s) => assert!(!s.trim().is_empty(), "{key}: empty"),
            Value::Object(forms) => {
                assert!(
                    forms.get("other").is_some_and(Value::is_string),
                    "{key}: a plural needs \"other\""
                );
                assert!(
                    forms.get("one").is_some_and(Value::is_string),
                    "{key}: English plurals have \"one\""
                );
                for (category, text) in forms {
                    assert!(
                        CATEGORIES.contains(&category.as_str()),
                        "{key}: unknown category {category}"
                    );
                    assert!(
                        text.as_str().is_some_and(|t| !t.trim().is_empty()),
                        "{key}.{category}: empty"
                    );
                }
            }
            _ => panic!("{key}: a text or a plural object"),
        }
    }
}

#[test]
fn every_key_used_is_in_english_with_its_placeholders() {
    let en = english();
    let mut problems = Vec::new();
    let all = uses();
    assert!(all.len() > 100, "the scan found only {} uses", all.len());
    for u in &all {
        let where_ = format!("{} ({})", u.key, u.file);
        let Some(value) = en.get(&u.key) else {
            problems.push(format!("missing: {where_}"));
            continue;
        };
        if u.plural && !value.is_object() {
            problems.push(format!("not a plural (trn!): {where_}"));
        }
        if !u.plural && value.is_object() {
            problems.push(format!("a plural used as text (use trn!): {where_}"));
        }
        let wanted = entry_placeholders(value);
        let given: BTreeSet<String> = u.params.iter().cloned().collect();
        let missing: Vec<_> = wanted.difference(&given).collect();
        if !missing.is_empty() {
            problems.push(format!("{where_}: placeholders not filled: {missing:?}"));
        }
        let extra: Vec<_> = given.difference(&wanted).collect();
        if !extra.is_empty() {
            problems.push(format!("{where_}: no such placeholder: {extra:?}"));
        }
    }
    assert!(problems.is_empty(), "\n  {}", problems.join("\n  "));
}

#[test]
fn english_has_no_unused_keys() {
    let used: BTreeSet<String> = uses().into_iter().map(|u| u.key).collect();
    let unused: Vec<String> = english()
        .keys()
        .filter(|k| *k != "_meta" && !used.contains(*k))
        .cloned()
        .collect();
    assert!(
        unused.is_empty(),
        "keys in en.json that no tr!/trn! uses:\n  {}",
        unused.join("\n  ")
    );
}

#[test]
fn keys_the_apps_match_exist() {
    let en = english();
    for key in APP_MATCHED_KEYS {
        let found = match key.strip_suffix('*') {
            Some(prefix) => en.keys().any(|k| k.starts_with(prefix)),
            None => en.contains_key(*key),
        };
        assert!(
            found,
            "{key}: the apps match it (core_message_is), keep it in en.json"
        );
    }
}

/// The core's messages are shown to users as they are: no build or setup wording, admin commands,
/// documentation paths, HTTP status codes or crypto names.
#[test]
fn english_has_no_developer_text() {
    const BANNED: &[&str] = &[
        "this build",
        "compiled",
        "pass-server",
        "docs/",
        ".md",
        "HTTP ",
        "Google Cloud",
        "base64",
        "KDF",
        "TLS",
        "nonce",
        "ciphertext",
        "relying party",
        "otpauth URI",
        "ETag",
        "..=",
    ];
    let mut problems = Vec::new();
    for (key, value) in english() {
        let texts: Vec<String> = match &value {
            Value::String(s) => vec![s.clone()],
            Value::Object(forms) if key != "_meta" => forms
                .values()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            _ => Vec::new(),
        };
        for text in texts {
            for banned in BANNED {
                if text.contains(banned) {
                    problems.push(format!("{key}: {banned:?} in {text:?}"));
                }
            }
        }
    }
    assert!(problems.is_empty(), "\n  {}", problems.join("\n  "));
}

/// The plural categories a language uses (the core's rules, `plural_category`).
fn categories_of(language: &str) -> BTreeSet<&'static str> {
    let mut out: BTreeSet<&'static str> = (0..=1000)
        .chain([1_000_000, 2_000_000])
        .map(|n| plural_category(language, n))
        .collect();
    out.insert("other");
    out
}

#[test]
fn other_catalogs_match_english() {
    let en = english();
    let mut problems = Vec::new();
    let mut files: Vec<PathBuf> = std::fs::read_dir(root().join("locales"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    let mut missing_report = BTreeMap::new();
    for file in files {
        let code = file.file_stem().unwrap().to_string_lossy().to_string();
        if code == "en" {
            continue;
        }
        let catalog = load(&file);
        match catalog.get("_meta") {
            Some(m) if m["name"].is_string() && m["native"].is_string() => {}
            _ => problems.push(format!(
                "{code}.json: _meta needs \"name\" (in English) and \"native\""
            )),
        }
        let valid = categories_of(&code);
        for (key, value) in &catalog {
            if key == "_meta" {
                continue;
            }
            let Some(source) = en.get(key) else {
                problems.push(format!(
                    "{code}.json: {key} isn't in en.json (renamed or removed?)"
                ));
                continue;
            };
            if source.is_object() != value.is_object() {
                problems.push(format!("{code}.json: {key} must be shaped as in en.json"));
                continue;
            }
            match value {
                Value::Object(forms) => {
                    if !forms.get("other").is_some_and(Value::is_string) {
                        problems.push(format!("{code}.json: {key} needs \"other\""));
                    }
                    for (category, text) in forms {
                        if !valid.contains(category.as_str()) {
                            problems.push(format!(
                                "{code}.json: {key}: \"{category}\" is not a plural category of {code} ({valid:?})"
                            ));
                        } else if !text.as_str().is_some_and(|t| !t.trim().is_empty()) {
                            problems.push(format!("{code}.json: {key}.{category}: empty"));
                        }
                    }
                }
                Value::String(s) if s.trim().is_empty() => problems.push(format!(
                    "{code}.json: {key}: empty (leave it out to show English)"
                )),
                Value::String(_) => {}
                _ => problems.push(format!("{code}.json: {key}: not a text")),
            }
            let (want, have) = (entry_placeholders(source), entry_placeholders(value));
            if want != have {
                problems.push(format!(
                    "{code}.json: {key}: placeholders {have:?}, en.json has {want:?}"
                ));
            }
        }
        let missing = en
            .keys()
            .filter(|k| *k != "_meta" && !catalog.contains_key(*k))
            .count();
        missing_report.insert(code, missing);
    }
    for (code, missing) in missing_report.iter().filter(|(_, m)| **m > 0) {
        println!("Core/core/locales/{code}.json: {missing} texts missing (English is shown)");
    }
    assert!(problems.is_empty(), "\n  {}", problems.join("\n  "));
}
