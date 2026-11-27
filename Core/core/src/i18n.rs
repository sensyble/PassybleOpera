//! The core's user-facing text in the app's language. Catalogs are `locales/<tag>.json` (`en.json`
//! is the source), embedded at build time; a missing key falls back to English, then to the key.
//! Apps tell core messages apart with [`core_message_is`] and a catalog key, so those keys are a
//! stable API: don't rename them.

use std::fmt::Display;
use std::sync::{OnceLock, RwLock};

use serde_json::{Map, Value};

// `CATALOGS`: (language tag, JSON text) of every locales/*.json, from build.rs.
include!(concat!(env!("OUT_DIR"), "/core_catalogs.rs"));

/// The source language: every key is in its catalog.
pub(crate) const SOURCE: &str = "en";

/// A text in the core's language: `tr!("key")` or `tr!("key", name = value, …)` (any `Display`
/// value) for the `{name}` placeholders.
macro_rules! tr {
    ($key:literal) => {
        $crate::i18n::text($key, &[])
    };
    ($key:literal, $($name:ident = $value:expr),+ $(,)?) => {
        $crate::i18n::text($key, &[$((stringify!($name), &$value as &dyn ::std::fmt::Display)),+])
    };
}

/// A plural text for `count` in the core's language, with `{count}` and any other placeholders
/// filled: `trn!("key", n)` or `trn!("key", n, name = value, …)`.
macro_rules! trn {
    ($key:literal, $count:expr) => {
        $crate::i18n::plural($key, $count as i64, &[])
    };
    ($key:literal, $count:expr, $($name:ident = $value:expr),+ $(,)?) => {
        $crate::i18n::plural($key, $count as i64, &[$((stringify!($name), &$value as &dyn ::std::fmt::Display)),+])
    };
}

pub(crate) use {tr, trn};

struct Catalog {
    code: &'static str,
    entries: Map<String, Value>,
}

fn catalogs() -> &'static [Catalog] {
    static PARSED: OnceLock<Vec<Catalog>> = OnceLock::new();
    PARSED.get_or_init(|| {
        let mut list: Vec<Catalog> = CATALOGS
            .iter()
            .filter_map(|(code, text)| match serde_json::from_str::<Value>(text) {
                Ok(Value::Object(entries)) => Some(Catalog { code, entries }),
                // The tests check every catalog; a broken one only loses its language here.
                _ => None,
            })
            .collect();
        list.sort_by_key(|c| (c.code != SOURCE, c.code));
        list
    })
}

fn catalog(code: &str) -> Option<&'static Catalog> {
    catalogs().iter().find(|c| c.code == code)
}

static LANGUAGE: RwLock<&'static str> = RwLock::new(SOURCE);

/// Sets the language of the core's messages from then on: a BCP 47 tag (`de`, `zh-CN`, `pt-BR`; Android's
/// `in` and `zh-Hans` work too). `None`, an empty tag or a language without a catalog: English. Matching:
/// the exact tag, Chinese by script (`zh-Hans`, `zh-SG` → `zh-CN`), old codes (`in` → `id`), else the base
/// language (`hi-IN` → `hi`). Process-wide. Messages already made keep their language.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn set_language(language: Option<String>) {
    let code = language.as_deref().and_then(match_tag).unwrap_or(SOURCE);
    *LANGUAGE.write().unwrap_or_else(|e| e.into_inner()) = code;
}

/// The active language, e.g. `en`, `zh-CN`.
pub(crate) fn language() -> &'static str {
    #[cfg(test)]
    if let Some(code) = test_support::language() {
        return code;
    }
    *LANGUAGE.read().unwrap_or_else(|e| e.into_inner())
}

/// The catalog for a BCP 47 / Android / Windows language tag (see [`set_language`]).
pub(crate) fn match_tag(tag: &str) -> Option<&'static str> {
    let tag = tag.trim().replace('_', "-");
    if tag.is_empty() {
        return None;
    }
    let lower = tag.to_ascii_lowercase();
    let find = |code: &str| {
        catalogs()
            .iter()
            .find(|c| c.code.eq_ignore_ascii_case(code))
            .map(|c| c.code)
    };
    if let Some(code) = find(&lower) {
        return Some(code);
    }
    let parts: Vec<&str> = lower.split('-').collect();
    let base = match parts[0] {
        "in" => "id",
        "iw" => "he",
        "ji" => "yi",
        other => other,
    };
    if base == "zh" {
        let traditional = parts[1..]
            .iter()
            .any(|p| matches!(*p, "hant" | "tw" | "hk" | "mo"));
        return if traditional {
            find("zh-TW")
        } else {
            find("zh-CN").or_else(|| find("zh"))
        };
    }
    find(base).or_else(|| {
        catalogs()
            .iter()
            .find(|c| c.code.split('-').next().unwrap_or("") == base)
            .map(|c| c.code)
    })
}

/// The CLDR plural category of the integer `n` in `language`: `one`, `many` or `other` (the rules
/// of en, es, fr, de, zh-CN, ja, ko, hi and id, plus a few related languages; others use
/// English's).
pub(crate) fn plural_category(language: &str, n: i64) -> &'static str {
    let n = n.unsigned_abs();
    let base = language.split(['-', '_']).next().unwrap_or(language);
    match base {
        "id" | "ja" | "ko" | "zh" | "th" | "vi" | "ms" | "my" => "other",
        "fr" | "hi" | "bn" | "fa" | "gu" | "kn" | "zu" | "am" => match n {
            0 | 1 => "one",
            _ if base == "fr" && n.is_multiple_of(1_000_000) => "many",
            _ => "other",
        },
        "es" | "it" | "pt" | "ca" => match n {
            1 => "one",
            _ if n != 0 && n.is_multiple_of(1_000_000) => "many",
            _ => "other",
        },
        _ => {
            if n == 1 {
                "one"
            } else {
                "other"
            }
        }
    }
}

/// A text or a plural object that can be shown (`other` is required).
fn usable(v: &Value) -> bool {
    v.as_str().is_some_and(|s| !s.is_empty()) || v.get("other").is_some_and(Value::is_string)
}

/// The entry for `key` in the active language, else English.
fn lookup(key: &str) -> Option<Value> {
    #[cfg(test)]
    if let Some(v) = test_support::entry(key) {
        return Some(v);
    }
    catalog(language())
        .and_then(|c| c.entries.get(key))
        .filter(|v| usable(v))
        .or_else(|| {
            catalog(SOURCE)
                .and_then(|c| c.entries.get(key))
                .filter(|v| usable(v))
        })
        .cloned()
}

fn fill(template: &str, args: &[(&str, &dyn Display)]) -> String {
    let mut out = String::with_capacity(template.len() + 16);
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let close = after.find('}');
        let name = close.map(|c| &after[..c]);
        match name.and_then(|name| args.iter().find(|(n, _)| *n == name)) {
            Some((_, value)) => {
                out.push_str(&value.to_string());
                rest = &after[close.unwrap_or(0) + 1..];
            }
            None => {
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The text for `key` in the core's language (English if it has none, else the key itself) with
/// the `{name}` placeholders filled. Use [`tr!`].
pub(crate) fn text(key: &str, args: &[(&str, &dyn Display)]) -> String {
    match lookup(key) {
        Some(Value::String(s)) => fill(&s, args),
        Some(v) => fill(v["other"].as_str().unwrap_or(key), args),
        None => key.to_string(),
    }
}

/// The plural text for `key` and `count` (see [`plural_category`]), with `{count}` filled too.
/// Use [`trn!`].
pub(crate) fn plural(key: &str, count: i64, args: &[(&str, &dyn Display)]) -> String {
    let template = match lookup(key) {
        Some(Value::String(s)) => s,
        Some(v) => v
            .get(plural_category(language(), count))
            .and_then(Value::as_str)
            .or_else(|| v["other"].as_str())
            .unwrap_or(key)
            .to_string(),
        None => key.to_string(),
    };
    let mut all: Vec<(&str, &dyn Display)> = vec![("count", &count)];
    all.extend_from_slice(args);
    fill(&template, &all)
}

#[derive(Debug, PartialEq)]
enum Part<'a> {
    Text(&'a str),
    Slot(&'a str),
}

/// A template as literal text and `{name}` slots (other braces are text).
fn parts(template: &str) -> Vec<Part<'_>> {
    let mut out = Vec::new();
    let mut text_start = 0;
    let mut i = 0;
    let bytes = template.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'{' {
            let name_len = template[i + 1..]
                .bytes()
                .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
                .count();
            if name_len > 0 && bytes.get(i + 1 + name_len) == Some(&b'}') {
                if text_start < i {
                    out.push(Part::Text(&template[text_start..i]));
                }
                out.push(Part::Slot(&template[i + 1..i + 1 + name_len]));
                i += name_len + 2;
                text_start = i;
                continue;
            }
        }
        i += 1;
    }
    if text_start < template.len() {
        out.push(Part::Text(&template[text_start..]));
    }
    out
}

/// Whether `message` contains a text made from `template`, and the values of its slots. The
/// match may start and end anywhere in `message` (it may carry an error kind prefix, or be
/// wrapped in another message); a slot at the end takes the rest of the message.
fn match_template(message: &str, template: &str) -> Option<Vec<(String, String)>> {
    let parts = parts(template);
    if !parts
        .iter()
        .any(|p| matches!(p, Part::Text(t) if !t.trim().is_empty()))
    {
        return None; // nothing to recognise it by
    }
    let mut captures = Vec::new();
    match_from(message, 0, &parts, None, false, &mut captures).then_some(captures)
}

/// Backtracking matcher for [`match_template`]: `open` is a slot that started at a position and
/// waits for the next text; `anchored`: the next text must follow right here.
fn match_from(
    message: &str,
    pos: usize,
    parts: &[Part],
    open: Option<(&str, usize)>,
    anchored: bool,
    captures: &mut Vec<(String, String)>,
) -> bool {
    let Some((first, rest)) = parts.split_first() else {
        if let Some((name, start)) = open {
            captures.push((name.to_string(), message[start..].to_string()));
        }
        return true;
    };
    match first {
        Part::Slot(name) => {
            if let Some((prev, start)) = open {
                // Two slots in a row: the first one is empty.
                captures.push((prev.to_string(), message[start..start].to_string()));
            }
            match_from(message, pos, rest, Some((name, pos)), false, captures)
        }
        Part::Text(text) => {
            if open.is_none() && anchored {
                return message[pos..].starts_with(text)
                    && match_from(message, pos + text.len(), rest, None, true, captures);
            }
            let mut from = pos;
            while let Some(found) = message[from..].find(text) {
                let at = from + found;
                let mark = captures.len();
                if let Some((name, start)) = open {
                    captures.push((name.to_string(), message[start..at].to_string()));
                }
                if match_from(message, at + text.len(), rest, None, true, captures) {
                    return true;
                }
                captures.truncate(mark);
                from = at + message[at..].chars().next().map_or(1, char::len_utf8);
            }
            false
        }
    }
}

/// The templates of `key` in every catalog (all plural forms), English first.
fn templates_of(key: &str) -> Vec<String> {
    let mut out = Vec::new();
    for c in catalogs() {
        let keys: Vec<&String> = match key.strip_suffix('*') {
            Some(prefix) => c.entries.keys().filter(|k| k.starts_with(prefix)).collect(),
            None => c
                .entries
                .get_key_value(key)
                .map(|(k, _)| k)
                .into_iter()
                .collect(),
        };
        for k in keys {
            match &c.entries[k] {
                Value::String(s) => out.push(s.clone()),
                Value::Object(forms) if k != "_meta" => {
                    out.extend(forms.values().filter_map(Value::as_str).map(str::to_string))
                }
                _ => {}
            }
        }
    }
    #[cfg(test)]
    out.extend(test_support::templates(key));
    out
}

/// Whether `message` (a `PassError` payload, or its whole text with the kind prefix) is the core's text `key`,
/// in English or any catalog language. A key ending in `*` stands for every key it starts (`gdrive.*`).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn core_message_is(message: String, key: String) -> bool {
    templates_of(&key)
        .iter()
        .any(|t| match_template(&message, t).is_some())
}

/// The value of the placeholder `name` in `message` when it is the core's text `key` (see
/// [`core_message_is`]), e.g. `minutes` of `server.too_many_attempts`. `None` if it isn't.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn core_message_arg(message: String, key: String, name: String) -> Option<String> {
    templates_of(&key).iter().find_map(|t| {
        let captures = match_template(&message, t)?;
        captures
            .into_iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v)
    })
}

/// A language and catalog for one test thread, so tests can check translated texts without
/// changing the process-wide language other tests rely on.
#[cfg(test)]
pub(crate) mod test_support {
    use std::cell::RefCell;

    use serde_json::{Map, Value};

    thread_local! {
        static ACTIVE: RefCell<Option<(&'static str, Map<String, Value>)>> = const { RefCell::new(None) };
    }

    /// Uses `entries` as the catalog of `code` on this thread until the guard is dropped.
    pub(crate) fn with_catalog(code: &'static str, entries: Value) -> Guard {
        let Value::Object(map) = entries else {
            panic!("a catalog is a JSON object")
        };
        ACTIVE.with(|a| *a.borrow_mut() = Some((code, map)));
        Guard
    }

    pub(crate) struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            ACTIVE.with(|a| *a.borrow_mut() = None);
        }
    }

    pub(super) fn language() -> Option<&'static str> {
        ACTIVE.with(|a| a.borrow().as_ref().map(|(code, _)| *code))
    }

    pub(super) fn entry(key: &str) -> Option<Value> {
        ACTIVE.with(|a| {
            a.borrow()
                .as_ref()
                .and_then(|(_, map)| map.get(key).cloned())
                .filter(super::usable)
        })
    }

    pub(super) fn templates(key: &str) -> Vec<String> {
        ACTIVE.with(|a| {
            let a = a.borrow();
            let Some((_, map)) = a.as_ref() else {
                return Vec::new();
            };
            map.iter()
                .filter(|(k, _)| match key.strip_suffix('*') {
                    Some(prefix) => k.starts_with(prefix),
                    None => *k == key,
                })
                .flat_map(|(_, v)| match v {
                    Value::String(s) => vec![s.clone()],
                    Value::Object(forms) => forms
                        .values()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect(),
                    _ => Vec::new(),
                })
                .collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn plural_rules() {
        for (lang, n, want) in [
            ("en", 1, "one"),
            ("en", 0, "other"),
            ("en", 2, "other"),
            ("de", 1, "one"),
            ("de", 0, "other"),
            ("fr", 0, "one"),
            ("fr", 1, "one"),
            ("fr", 2, "other"),
            ("fr", 1_000_000, "many"),
            ("es", 1, "one"),
            ("es", 0, "other"),
            ("es", 2_000_000, "many"),
            ("hi", 0, "one"),
            ("hi", 1, "one"),
            ("hi", 2, "other"),
            ("zh-CN", 1, "other"),
            ("ja", 1, "other"),
            ("ko", 5, "other"),
            ("id", 1, "other"),
        ] {
            assert_eq!(plural_category(lang, n), want, "{lang} {n}");
        }
    }

    #[test]
    fn placeholders_are_filled() {
        let host = "pass.example.com";
        assert_eq!(
            fill("Can't reach {host}.", &[("host", &host)]),
            "Can't reach pass.example.com."
        );
        assert_eq!(fill("{a}{b} {c}", &[("a", &1), ("b", &2)]), "12 {c}");
        assert_eq!(fill("no { brace", &[]), "no { brace");
    }

    #[test]
    fn english_by_default_and_fallbacks() {
        assert_eq!(language(), SOURCE);
        assert_eq!(
            tr!("server.enter_address"),
            "enter the server address",
            "English is the default"
        );
        assert_eq!(
            tr!("no.such.key"),
            "no.such.key",
            "a missing key shows itself"
        );
        // No catalog ships for Esperanto, so a missing text can only come from English.
        let _eo = test_support::with_catalog(
            "eo",
            json!({ "server.enter_address": "Enigu la adreson de la servilo" }),
        );
        assert_eq!(
            tr!("server.enter_address"),
            "Enigu la adreson de la servilo"
        );
        assert_eq!(
            tr!("server.enter_user"),
            "enter your user name",
            "a text the catalog lacks is English"
        );
    }

    #[test]
    fn plurals_by_language() {
        assert_eq!(
            trn!("merge.websites", 1),
            "website",
            "English one (the count is left out)"
        );
        assert_eq!(trn!("merge.websites", 3), "3 websites");
        let _fr = test_support::with_catalog(
            "fr",
            json!({ "merge.websites": { "one": "{count} site", "other": "{count} sites" } }),
        );
        assert_eq!(trn!("merge.websites", 0), "0 site", "French 0 is singular");
        assert_eq!(trn!("merge.websites", 2), "2 sites");
        let _ja = test_support::with_catalog(
            "ja",
            json!({ "merge.websites": { "other": "{count} 件のウェブサイト" } }),
        );
        assert_eq!(trn!("merge.websites", 1), "1 件のウェブサイト");
    }

    #[test]
    fn language_tags() {
        assert_eq!(match_tag("en-US"), Some("en"));
        assert_eq!(match_tag("EN_gb"), Some("en"));
        assert_eq!(match_tag(""), None);
        assert_eq!(match_tag("xx-none"), None);
        let has = |code: &str| catalog(code).is_some();
        if has("zh-CN") {
            assert_eq!(match_tag("zh-Hans-CN"), Some("zh-CN"));
            assert_eq!(match_tag("zh-SG"), Some("zh-CN"));
            assert_eq!(match_tag("zh-Hans"), Some("zh-CN"));
        }
        if !has("zh-TW") {
            assert_eq!(match_tag("zh-Hant-HK"), None);
        }
        if has("id") {
            assert_eq!(match_tag("in"), Some("id"));
            assert_eq!(match_tag("in-ID"), Some("id"));
        }
        if has("hi") {
            assert_eq!(match_tag("hi-IN"), Some("hi"));
        }
        set_language(Some("en-US".into()));
        assert_eq!(tr!("server.enter_user"), "enter your user name");
        set_language(None);
    }

    #[test]
    fn templates_match_messages() {
        assert_eq!(
            parts("{action}: HTTP {code} {"),
            vec![
                Part::Slot("action"),
                Part::Text(": HTTP "),
                Part::Slot("code"),
                Part::Text(" {"),
            ]
        );
        let t = "{action}: too many failed attempts; try again in {minutes} minutes";
        let m = "network error: sign in: too many failed attempts; try again in 15 minutes";
        let caps = match_template(m, t).unwrap();
        assert!(caps.contains(&("minutes".into(), "15".into())), "{caps:?}");
        assert!(match_template("sign in: HTTP 500", t).is_none());
        let caps = match_template(
            "upload: storage quota reached: 80 MB of 100 MB used.",
            "{action}: storage quota reached: {detail}",
        )
        .unwrap();
        assert!(caps.contains(&("detail".into(), "80 MB of 100 MB used.".into())));
        assert!(match_template("a: b: x y", "{p}: x {q}").is_some());
        assert!(match_template("anything", "{a}: {b}").is_none());
    }

    /// A key the apps match (`core_message_is`) recognises only its own messages: no other text
    /// of the core, in any language, contains one of its templates.
    #[test]
    fn app_matched_keys_match_only_their_own_messages() {
        // Meant overlaps: the quota message with the server's detail is still "quota reached", and a
        // device the server signed out is an authentication failure too.
        const MEANT: &[(&str, &str)] = &[
            ("webdav.quota_reached", "webdav.quota_reached_detail"),
            ("webdav.auth_failed", "server.auth_failed"),
            ("alias.*", "server.address_scheme"),
        ];
        let sample = |template: &str| -> String {
            parts(template)
                .into_iter()
                .map(|p| match p {
                    Part::Text(t) => t.to_string(),
                    Part::Slot(_) => "Example".to_string(),
                })
                .collect()
        };
        let mut problems = Vec::new();
        for key in crate::i18n_tests::APP_MATCHED_KEYS {
            let own = |k: &str| match key.strip_suffix('*') {
                Some(prefix) => k.starts_with(prefix),
                None => k == *key,
            };
            let templates = templates_of(key);
            for c in catalogs() {
                for (k, v) in &c.entries {
                    if k == "_meta" || own(k) || MEANT.contains(&(*key, k.as_str())) {
                        continue;
                    }
                    let forms: Vec<&str> = match v {
                        Value::String(s) => vec![s.as_str()],
                        Value::Object(f) => f.values().filter_map(Value::as_str).collect(),
                        _ => Vec::new(),
                    };
                    for form in forms {
                        let message = sample(form);
                        if let Some(t) = templates
                            .iter()
                            .find(|t| match_template(&message, t).is_some())
                        {
                            problems.push(format!(
                                "{}.json {k} ({message:?}) looks like {key} ({t:?})",
                                c.code
                            ));
                        }
                    }
                }
            }
        }
        assert!(problems.is_empty(), "\n  {}", problems.join("\n  "));
    }

    #[test]
    fn core_messages_are_recognised_in_any_language() {
        let english = tr!("webdav.auth_failed", action = "upload");
        assert!(core_message_is(
            english.clone(),
            "webdav.auth_failed".into()
        ));
        assert!(core_message_is(
            format!("network error: {english}"),
            "webdav.*".into()
        ));
        assert!(!core_message_is(english, "server.auth_failed".into()));

        let _de = test_support::with_catalog(
            "de",
            json!({
                "webdav.auth_failed": "{action}: Anmeldung abgelehnt",
                "server.too_many_attempts": {
                    "one": "{action}: zu viele Versuche; in {count} Minute erneut versuchen",
                    "other": "{action}: zu viele Versuche; in {count} Minuten erneut versuchen"
                }
            }),
        );
        let german = tr!("webdav.auth_failed", action = "hochladen");
        assert_eq!(german, "hochladen: Anmeldung abgelehnt");
        assert!(core_message_is(german, "webdav.auth_failed".into()));
        let wait = trn!("server.too_many_attempts", 5, action = "anmelden");
        assert_eq!(
            core_message_arg(wait, "server.too_many_attempts".into(), "count".into()),
            Some("5".into())
        );
        assert_eq!(
            core_message_arg(
                "sign in: too many failed attempts; try again in 15 minutes".into(),
                "server.too_many_attempts".into(),
                "count".into()
            ),
            Some("15".into()),
            "English still matches while another language is active"
        );
    }
}
