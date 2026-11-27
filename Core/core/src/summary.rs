//! The list a locked vault keeps showing ("soft lock"): a summary of each item without any
//! secret, so the apps keep their list, search and site icons after an auto-lock while every
//! secret is gone with the vault key. Never a password, 2FA secret, notes, custom field value, full
//! card number or private key. Clients keep it only device-bound and encrypted, never synced.

use serde::{Deserialize, Serialize};

use crate::matching::{
    android_app_match, normalize_cert, parse_loose, registrable_domain, url_suggestion_tier,
    MatchQuality,
};
use crate::model::{AndroidApp, Item, ItemKind, UrlRule};
use crate::search::normalize;
use crate::usage::ItemUsage;

/// A passkey as the locked list shows it: whose account, for which site. No key material.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PasskeySummary {
    pub rp_id: String,
    pub user_name: String,
    pub user_display_name: String,
    /// The credential id (public: the site stores it and sends it in its allow-list).
    pub credential_id: Vec<u8>,
}

/// One item of the locked list. Built by [`crate::Vault::summaries`] while unlocked. Also JSON
/// (serde, the field names as here) for the WebAssembly bindings.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ItemSummary {
    pub id: String,
    pub kind: ItemKind,
    pub title: String,
    pub username: String,
    /// The stored website entries (for matching a page and for site icons).
    pub urls: Vec<String>,
    /// Linked Android apps (package names and public signing-certificate digests).
    pub android_apps: Vec<AndroidApp>,
    /// The site the item is shown with: the registrable domain (or host) of its first website,
    /// `""` if it has none.
    pub domain: String,
    pub has_password: bool,
    pub has_totp: bool,
    pub has_notes: bool,
    pub passkeys: Vec<PasskeySummary>,
    pub favorite: bool,
    pub created_at: i64,
    pub updated_at: i64,
    /// Uses on every device ([`crate::Vault::record_use`]).
    #[cfg_attr(feature = "uniffi", uniffi(default = 0))]
    pub use_count: u64,
    /// The last use on any device (Unix milliseconds), 0 if never used.
    #[cfg_attr(feature = "uniffi", uniffi(default = 0))]
    pub last_used: i64,
    /// Sort key for "most used first": higher first, 0 if never used.
    #[cfg_attr(feature = "uniffi", uniffi(default = 0))]
    pub rank: i64,
    /// The item's tags ([`Item::tags`]).
    #[cfg_attr(feature = "uniffi", uniffi(default = []))]
    pub tags: Vec<String>,
    /// A card item's public part: never the full number, security code or PIN.
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub card: Option<CardSummary>,
    /// An identity item's name, email and company.
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub identity: Option<IdentitySummary>,
    /// Whether the item has custom fields (their values are not in the summary).
    #[cfg_attr(feature = "uniffi", uniffi(default = false))]
    pub has_fields: bool,
    /// When it went to the trash (only in [`crate::Vault::trash_summaries`]); `None` otherwise.
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub trashed_at: Option<i64>,
    /// How the website entries match pages ([`Item::url_rules`]).
    #[cfg_attr(feature = "uniffi", uniffi(default = []))]
    pub url_rules: Vec<UrlRule>,
}

/// What lists show of a card: the brand, the last four digits and the expiry.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CardSummary {
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub cardholder_name: String,
    /// See [`crate::CardData::brand`].
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub brand: String,
    /// The last four digits only (`""` without a number).
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub last4: String,
    #[cfg_attr(feature = "uniffi", uniffi(default = 0))]
    pub expiry_month: u32,
    #[cfg_attr(feature = "uniffi", uniffi(default = 0))]
    pub expiry_year: u32,
}

/// What lists show of an identity.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct IdentitySummary {
    /// First, middle and last name.
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub full_name: String,
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub email: String,
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub company: String,
}

/// A tag and how many items carry it ([`crate::Vault::tags`], [`summaries_tags`]).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct TagCount {
    pub tag: String,
    pub count: u32,
}

impl ItemSummary {
    /// The summary of `item`: everything but its secrets.
    pub fn of(item: &Item) -> ItemSummary {
        ItemSummary {
            id: item.id.clone(),
            kind: item.kind,
            title: item.title.clone(),
            username: item.username.clone(),
            urls: item.urls.clone(),
            url_rules: item.url_rules.clone(),
            android_apps: item.android_apps.clone(),
            domain: primary_domain(&item.urls),
            has_password: !item.password.is_empty(),
            has_totp: item.has_totp(),
            has_notes: !item.notes.trim().is_empty(),
            passkeys: item
                .passkeys
                .iter()
                .map(|p| PasskeySummary {
                    rp_id: p.rp_id.clone(),
                    user_name: p.user_name.clone(),
                    user_display_name: p.user_display_name.clone(),
                    credential_id: p.credential_id.clone(),
                })
                .collect(),
            favorite: item.favorite,
            created_at: item.created_at,
            updated_at: item.updated_at,
            use_count: 0,
            last_used: 0,
            rank: 0,
            tags: item.tags.clone(),
            card: item.card.as_ref().map(|c| CardSummary {
                cardholder_name: c.cardholder_name.clone(),
                brand: c.brand.clone(),
                last4: c.last4(),
                expiry_month: c.expiry_month,
                expiry_year: c.expiry_year,
            }),
            identity: item.identity.as_ref().map(|i| IdentitySummary {
                full_name: i.full_name(),
                email: i.email.clone(),
                company: i.company.clone(),
            }),
            has_fields: item.fields.iter().any(|f| !crate::is_ai_access_field(f)),
            trashed_at: item.trashed_at,
        }
    }

    /// This summary with `usage` ([`crate::Vault::usage`]).
    pub fn with_usage(mut self, usage: ItemUsage) -> ItemSummary {
        self.use_count = usage.count;
        self.last_used = usage.last_used;
        self.rank = usage.rank;
        self
    }
}

/// Counts tags (each item's tags are already distinct), sorted by name (case-insensitive). Tags
/// that differ only in case count as one.
pub(crate) fn count_tags<'a>(tag_lists: impl Iterator<Item = &'a [String]>) -> Vec<TagCount> {
    let mut counts: Vec<(String, TagCount)> = Vec::new();
    let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for tags in tag_lists {
        for tag in tags {
            let key = normalize(tag);
            match index.get(&key) {
                Some(&i) => counts[i].1.count += 1,
                None => {
                    index.insert(key.clone(), counts.len());
                    counts.push((
                        key,
                        TagCount {
                            tag: tag.clone(),
                            count: 1,
                        },
                    ));
                }
            }
        }
    }
    counts.sort_by(|a, b| a.0.cmp(&b.0));
    counts.into_iter().map(|(_, c)| c).collect()
}

/// Whether `tags` holds `wanted` or a tag nested under it (`work` matches `Work` and
/// `Work/Clients`, not `Workshop`). Case- and diacritic-insensitive; surrounding `/` and spaces
/// in `wanted` are ignored. An empty `wanted` matches nothing.
pub(crate) fn has_tag(tags: &[String], wanted: &str) -> bool {
    let wanted = crate::model::normalize_tags(&[wanted.to_string()]);
    let Some(wanted) = wanted.first().map(|w| normalize(w)) else {
        return false;
    };
    tags.iter().any(|t| {
        let t = normalize(t);
        t == wanted
            || t.strip_prefix(&wanted)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// Every tag of a locked list with its item count (as [`crate::Vault::tags`]).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn summaries_tags(index: Vec<ItemSummary>) -> Vec<TagCount> {
    count_tags(index.iter().map(|i| i.tags.as_slice()))
}

/// Items of a locked list carrying `tag` or a tag nested under it (case-insensitive), by title
/// (as [`crate::Vault::items_with_tag`]). The search also takes `tag:<name>` (or `#<name>`) words.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn summaries_with_tag(index: Vec<ItemSummary>, tag: String) -> Vec<ItemSummary> {
    let mut found: Vec<ItemSummary> = index
        .into_iter()
        .filter(|i| has_tag(&i.tags, &tag))
        .collect();
    found.sort_by_cached_key(|i| i.title.to_lowercase());
    found
}

/// Favorites first, then the most used, then by title.
pub(crate) fn suggested_order(a: &ItemSummary, b: &ItemSummary) -> std::cmp::Ordering {
    b.favorite
        .cmp(&a.favorite)
        .then(b.rank.cmp(&a.rank))
        .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
}

/// URL entry prefixes that pin a login to a desktop app for auto-type: `windows:<exe>` and
/// `macos:<bundle id>`.
pub const APP_PIN_PREFIXES: &[&str] = &["windows:", "macos:"];

/// The app a URL entry pins its login to (`windows:putty.exe` gives `putty.exe`), `None` for
/// websites and other entries. The prefix is matched in any case; an empty app is no pin.
pub fn app_pin(entry: &str) -> Option<&str> {
    let entry = entry.trim();
    APP_PIN_PREFIXES.iter().find_map(|prefix| {
        let head = entry.get(..prefix.len())?;
        if !head.eq_ignore_ascii_case(prefix) {
            return None;
        }
        Some(entry[prefix.len()..].trim()).filter(|app| !app.is_empty())
    })
}

/// A website entry (`https://…`, `http://…` or a bare host), not an app pin or an `androidapp://` link.
pub(crate) fn is_web_entry(entry: &str) -> bool {
    let entry = entry.trim();
    if entry.is_empty() || is_pin_prefixed(entry) {
        return false;
    }
    match entry.split_once("://") {
        Some((scheme, _)) => matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https"),
        None => !entry.contains(':') || entry.contains('.'),
    }
}

/// Whether `entry` starts with an app pin prefix, even with nothing after it.
fn is_pin_prefixed(entry: &str) -> bool {
    APP_PIN_PREFIXES.iter().any(|prefix| {
        entry
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    })
}

/// The lower-case host of a website entry.
fn web_host(entry: &str) -> Option<String> {
    if !is_web_entry(entry) {
        return None;
    }
    parse_loose(entry)?
        .host_str()
        .filter(|h| !h.is_empty())
        .map(str::to_ascii_lowercase)
}

/// The registrable domain (or host) of the first website entry, `""` if there is none.
fn primary_domain(urls: &[String]) -> String {
    urls.iter()
        .find_map(|u| web_host(u))
        .map(|host| registrable_domain(host.clone()).unwrap_or(host))
        .unwrap_or_default()
}

/// Logins of `index` with the given match quality, best first, then favorites, the most used and
/// by title (as `Vault::find_for_url`).
fn logins_where(
    index: Vec<ItemSummary>,
    mut score: impl FnMut(&ItemSummary) -> MatchQuality,
) -> Vec<ItemSummary> {
    let mut found: Vec<(MatchQuality, ItemSummary)> = index
        .into_iter()
        .filter(|i| i.kind == ItemKind::Login)
        .filter_map(|i| {
            let q = score(&i);
            (q > MatchQuality::None).then_some((q, i))
        })
        .collect();
    found.sort_by(|(qa, a), (qb, b)| qb.cmp(qa).then_with(|| suggested_order(a, b)));
    found.into_iter().map(|(_, i)| i).collect()
}

/// `Vault::find_for_url` over a locked list: the logins for a web page, in the same order.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn summaries_for_url(index: Vec<ItemSummary>, url: String) -> Vec<ItemSummary> {
    let Some(page) = parse_loose(&url) else {
        return Vec::new();
    };
    logins_where(index, |i| url_suggestion_tier(&i.urls, &i.url_rules, &page))
}

/// [`summaries_for_url`] over borrowed summaries, for a caller that keeps its lists between
/// pages (the desktop agent's `logins.find`): nothing is copied but the answer.
pub fn summaries_for_url_in<'a>(
    index: impl IntoIterator<Item = &'a ItemSummary>,
    url: &str,
) -> Vec<&'a ItemSummary> {
    let Some(page) = parse_loose(url) else {
        return Vec::new();
    };
    let mut found: Vec<(MatchQuality, &ItemSummary)> = index
        .into_iter()
        .filter(|i| i.kind == ItemKind::Login)
        .filter_map(|i| {
            let q = url_suggestion_tier(&i.urls, &i.url_rules, &page);
            (q > MatchQuality::None).then_some((q, i))
        })
        .collect();
    found.sort_by(|(qa, a), (qb, b)| qb.cmp(qa).then_with(|| suggested_order(a, b)));
    found.into_iter().map(|(_, i)| i).collect()
}

/// `Vault::find_for_android_app` over a locked list. A stored certificate digest must match.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn summaries_for_android_app(
    index: Vec<ItemSummary>,
    package: String,
    cert_sha256: Option<String>,
) -> Vec<ItemSummary> {
    let cert = cert_sha256
        .as_deref()
        .map(normalize_cert)
        .filter(|c| !c.is_empty());
    logins_where(index, |i| {
        android_app_match(
            &i.android_apps,
            &i.urls,
            &i.url_rules,
            &package,
            cert.as_deref(),
        )
    })
}

/// `Vault::search` over a locked list: fuzzy search over titles, usernames, websites, linked apps and
/// passkey names (no notes), best match first, then favorites, most used, then title. An empty query
/// returns everything by title.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn summaries_search(index: Vec<ItemSummary>, query: String) -> Vec<ItemSummary> {
    crate::search::summaries_search_with_notes(index, Default::default(), query)
}

/// Items of a locked list with a passkey for `rp_id` (case-insensitive): the most used first
/// (as `Vault::find_passkeys`), then by title.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn summaries_with_passkeys(index: Vec<ItemSummary>, rp_id: String) -> Vec<ItemSummary> {
    let mut found: Vec<ItemSummary> = index
        .into_iter()
        .filter(|i| {
            i.passkeys
                .iter()
                .any(|p| p.rp_id.eq_ignore_ascii_case(&rp_id))
        })
        .collect();
    found.sort_by(|a, b| {
        b.rank
            .cmp(&a.rank)
            .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
    });
    found
}

/// `index` in suggestion order: favorites first, then most used, then title.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn summaries_suggested(mut index: Vec<ItemSummary>) -> Vec<ItemSummary> {
    index.sort_by(suggested_order);
    index
}

/// `index` for a "Most used" view: by [`ItemSummary::rank`] (higher first), then title; never-used last.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn summaries_most_used(mut index: Vec<ItemSummary>) -> Vec<ItemSummary> {
    index.sort_by(|a, b| {
        b.rank
            .cmp(&a.rank)
            .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
    });
    index
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Passkey, PasswordHistoryEntry};

    #[test]
    fn app_pins_name_the_app() {
        assert_eq!(app_pin("windows:putty.exe"), Some("putty.exe"));
        assert_eq!(app_pin(" Windows: Putty.exe "), Some("Putty.exe"));
        assert_eq!(
            app_pin("macos:com.apple.Terminal"),
            Some("com.apple.Terminal")
        );
        assert_eq!(
            app_pin("MACOS:com.apple.Terminal"),
            Some("com.apple.Terminal")
        );
        for not_a_pin in [
            "macos:",
            "windows: ",
            "https://example.com",
            "example.com",
            "macos.example.com",
            "androidapp://com.example",
            "otpauth://totp/x",
            "",
        ] {
            assert_eq!(app_pin(not_a_pin), None, "{not_a_pin}");
        }
        assert_eq!(app_pin("m\u{e9}cos:x"), None);
    }

    #[test]
    fn only_websites_are_web_entries() {
        for web in [
            "https://github.com/login",
            "http://192.168.1.1",
            "github.com",
            "example.com:8443/x",
            "macos.example.com",
            "intranet",
        ] {
            assert!(is_web_entry(web), "{web}");
        }
        for other in [
            "windows:putty.exe",
            "WINDOWS:Putty.exe",
            "macos:com.apple.Terminal",
            "MacOS:com.apple.Terminal",
            "macos:",
            "androidapp://com.example.app",
            "otpauth://totp/x",
            "file:///C:/x.exe",
            "",
        ] {
            assert!(!is_web_entry(other), "{other}");
        }
    }

    fn item() -> Item {
        Item {
            id: "1".into(),
            title: "GitHub".into(),
            username: "octo".into(),
            password: "hunter2-secret".into(),
            urls: vec![
                "windows:gh.exe".into(),
                "https://www.github.com/login".into(),
            ],
            android_apps: vec![AndroidApp {
                package: "com.github.android".into(),
                cert_sha256: Some("AB:CD".into()),
                ..Default::default()
            }],
            totp: Some("JBSWY3DPEHPK3PXP".into()),
            notes: "recovery codes: 1111".into(),
            passkeys: vec![Passkey {
                credential_id: vec![1, 2, 3],
                rp_id: "github.com".into(),
                user_name: "octo".into(),
                user_display_name: "Octo Cat".into(),
                private_key_pkcs8: b"PRIVATE-KEY-BYTES".to_vec(),
                user_handle: b"HANDLE".to_vec(),
                ..Default::default()
            }],
            password_history: vec![PasswordHistoryEntry {
                password: "old-secret".into(),
                replaced_at: 1,
            }],
            favorite: true,
            updated_at: 42,
            ..Default::default()
        }
    }

    #[test]
    fn a_summary_has_no_secrets() {
        let summary = ItemSummary::of(&item());
        assert_eq!(summary.domain, "github.com");
        assert!(summary.has_password && summary.has_totp && summary.has_notes);
        assert_eq!(summary.passkeys[0].user_name, "octo");
        assert_eq!(summary.updated_at, 42);
        let dump = format!("{summary:?}");
        for secret in [
            "hunter2",
            "JBSWY3DPEHPK3PXP",
            "recovery",
            "old-secret",
            "PRIVATE",
            "HANDLE",
        ] {
            assert!(!dump.contains(secret), "{secret} in {dump}");
        }
        let bytes = format!("{:?}", b"PRIVATE-KEY-BYTES".to_vec());
        assert!(!dump.contains(&bytes[1..bytes.len() - 1]));
    }

    #[test]
    fn locked_lists_match_like_the_vault() {
        let mut other = item();
        other.id = "2".into();
        other.title = "Gist".into();
        other.favorite = false;
        other.urls = vec!["https://gist.github.com".into()];
        other.android_apps.clear();
        let note = Item {
            id: "3".into(),
            kind: ItemKind::Note,
            title: "github note".into(),
            urls: vec!["https://github.com".into()],
            ..Default::default()
        };
        let index: Vec<ItemSummary> = [item(), other, note].iter().map(ItemSummary::of).collect();
        let ids = |found: Vec<ItemSummary>| found.into_iter().map(|i| i.id).collect::<Vec<_>>();
        assert_eq!(
            ids(summaries_for_url(
                index.clone(),
                "https://gist.github.com/x".into()
            )),
            ["2", "1"]
        );
        assert_eq!(
            ids(summaries_for_url(index.clone(), "https://evil.io".into())),
            Vec::<String>::new()
        );
        assert_eq!(
            ids(summaries_for_android_app(
                index.clone(),
                "com.github.android".into(),
                Some("abcd".into())
            )),
            ["1"]
        );
        assert!(summaries_for_android_app(
            index.clone(),
            "com.github.android".into(),
            Some("ffff".into())
        )
        .is_empty());
        assert_eq!(ids(summaries_search(index.clone(), "GIS".into())), ["2"]);
        assert_eq!(ids(summaries_search(index.clone(), "".into())).len(), 3);
        assert_eq!(
            ids(summaries_with_passkeys(index, "GitHub.com".into())),
            ["2", "1"]
        );
    }
}
