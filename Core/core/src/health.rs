//! Password health report, an offline strength estimate, and k-anonymity helpers for the Have I
//! Been Pwned breach check. Only the first 5 hex characters of a password's SHA-1 ever leave the
//! device.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use sha1::{Digest, Sha1};

use crate::i18n::tr;
use crate::model::{Item, ItemKind};
use crate::sites;
use crate::summary::ItemSummary;
use crate::vault::Vault;
use crate::{PassError, Result};

/// A password unchanged for longer than this (365 days) is "old".
pub const OLD_PASSWORD_MS: i64 = 365 * 24 * 60 * 60 * 1000;

/// Usernames and site names shorter than this are not looked for in passwords.
pub(crate) const MIN_NAME_LEN: usize = 4;

/// How guessable a password is ([`password_strength`]).
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PasswordStrength {
    /// 0 very weak, 1 weak, 2 fair, 3 good, 4 strong.
    pub score: u32,
    /// The estimated guessing entropy in bits.
    pub entropy_bits: f64,
}

/// One item in a [`HealthReport`] list. No secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct HealthItem {
    pub item_id: String,
    pub title: String,
    pub username: String,
    /// Registrable domain of the first website (as [`ItemSummary::domain`]).
    pub domain: String,
    /// [`PasswordStrength::score`] of its password (0 without one).
    pub score: u32,
    /// When the password was last changed (Unix ms; `updated_at` when unknown).
    pub password_changed_at: i64,
    /// How many live items share this password (1: none other; 0: no password).
    pub reuse_count: u32,
}

/// Items sharing one password.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ReusedGroup {
    /// Two or more, by title.
    pub items: Vec<HealthItem>,
}

/// Logins that look like the same account (as `find_duplicates`).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct DuplicateSet {
    /// Two or more, most recently changed first (merging keeps the first one).
    pub items: Vec<HealthItem>,
}

/// An item with a saved `http://` address ([`HealthReport::insecure`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct InsecureItem {
    pub item: HealthItem,
    /// Its `http://` addresses to public sites, as saved.
    pub urls: Vec<String>,
    /// Every one is a domain name without a port, so [`health_use_https`] may change them.
    pub can_use_https: bool,
}

/// An item whose site offers more protection than it uses ([`HealthReport::no_two_factor`],
/// [`HealthReport::passkeys`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SiteItem {
    pub item: HealthItem,
    /// Two-factor methods (`totp`, `security_key`, `sms`, `call`, `email`, `app`, `device`) or
    /// passkey modes (`passwordless`, `mfa`), as [`crate::SiteSecurity`].
    pub methods: Vec<String>,
    /// How to turn it on, from the directory (`https://…`); `""` if it has no link.
    pub docs_url: String,
}

/// The vault's password health ([`password_health`]). No secrets.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct HealthReport {
    /// Live items with a password that were checked.
    pub checked: u32,
    /// Score ≤ 1, weakest first.
    pub weak: Vec<HealthItem>,
    /// Groups of items sharing a password, largest group first.
    pub reused: Vec<ReusedGroup>,
    /// Unchanged for more than [`OLD_PASSWORD_MS`], oldest first.
    pub old: Vec<HealthItem>,
    /// Checked items in none of the password problem lists.
    pub healthy: u32,
    /// Passwords that contain the username or the site's name (not weak ones), by title.
    pub contains_name: Vec<HealthItem>,
    /// Items saved with an `http://` address to a public site, by title.
    pub insecure: Vec<InsecureItem>,
    /// Items for sites that offer two-factor sign-in, without an authenticator secret or a
    /// passkey, by title.
    pub no_two_factor: Vec<SiteItem>,
    /// Items for sites that support passkeys, without one, by title.
    pub passkeys: Vec<SiteItem>,
    /// Live logins with a username or website but no password, passkey or authenticator secret,
    /// by title. Not in `checked`.
    pub no_password: Vec<HealthItem>,
    /// Logins saved more than once (the same site and username), by title of the first.
    pub duplicates: Vec<DuplicateSet>,
}

/// A HIBP range query for a password: what to ask for and what to look for in the answer.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct HibpQuery {
    /// The first 5 characters of the uppercase hex SHA-1: GET
    /// `https://api.pwnedpasswords.com/range/<prefix>`.
    pub prefix: String,
    /// The other 35 characters: pass to [`hibp_match`] with the response. Keep it in memory only.
    pub suffix: String,
}

/// Password health of the vault's live items at the current time.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn password_health(vault: Arc<Vault>) -> HealthReport {
    health_report(&vault.items(), crate::now_ms())
}

fn health_item(item: &Item, reuse_count: u32) -> HealthItem {
    HealthItem {
        item_id: item.id.clone(),
        title: item.title.clone(),
        username: item.username.clone(),
        domain: ItemSummary::of(item).domain,
        score: password_strength(item.password.clone()).score,
        password_changed_at: if item.password_changed_at > 0 {
            item.password_changed_at
        } else {
            item.updated_at
        },
        reuse_count,
    }
}

/// The health report for `items` at `now` (Unix ms). Items in the trash are ignored.
pub fn health_report(items: &[Item], now: i64) -> HealthReport {
    let live: Vec<&Item> = items.iter().filter(|i| !i.is_trashed()).collect();
    let checked: Vec<&Item> = live
        .iter()
        .copied()
        .filter(|i| !i.password.is_empty())
        .collect();
    let mut by_password: HashMap<&str, Vec<usize>> = HashMap::new();
    for (n, item) in checked.iter().enumerate() {
        by_password
            .entry(item.password.as_str())
            .or_default()
            .push(n);
    }
    let entries: Vec<HealthItem> = checked
        .iter()
        .map(|item| health_item(item, by_password[item.password.as_str()].len() as u32))
        .collect();
    let by_title =
        |a: &HealthItem, b: &HealthItem| a.title.to_lowercase().cmp(&b.title.to_lowercase());
    let is_old = |e: &HealthItem| {
        e.password_changed_at > 0 && now.saturating_sub(e.password_changed_at) > OLD_PASSWORD_MS
    };

    let mut weak: Vec<HealthItem> = entries.iter().filter(|e| e.score <= 1).cloned().collect();
    weak.sort_by(|a, b| a.score.cmp(&b.score).then_with(|| by_title(a, b)));

    let mut old: Vec<HealthItem> = entries.iter().filter(|e| is_old(e)).cloned().collect();
    old.sort_by(|a, b| {
        a.password_changed_at
            .cmp(&b.password_changed_at)
            .then_with(|| by_title(a, b))
    });

    let mut reused: Vec<ReusedGroup> = by_password
        .values()
        .filter(|members| members.len() > 1)
        .map(|members| {
            let mut items: Vec<HealthItem> = members.iter().map(|&n| entries[n].clone()).collect();
            items.sort_by(by_title);
            ReusedGroup { items }
        })
        .collect();
    reused.sort_by(|a, b| {
        b.items
            .len()
            .cmp(&a.items.len())
            .then_with(|| by_title(&a.items[0], &b.items[0]))
    });

    let mut contains_name = Vec::new();
    let mut insecure = Vec::new();
    let mut no_two_factor = Vec::new();
    let mut passkeys = Vec::new();
    for (item, entry) in checked.iter().zip(&entries) {
        if entry.score > 1 && password_contains_name(item) {
            contains_name.push(entry.clone());
        }
        let http: Vec<&String> = item.urls.iter().filter(|u| is_insecure_url(u)).collect();
        if !http.is_empty() {
            insecure.push(InsecureItem {
                item: entry.clone(),
                can_use_https: http.iter().all(|u| https_upgrade(u).is_some()),
                urls: http.into_iter().cloned().collect(),
            });
        }
        if item.passkeys.is_empty() {
            if !item.has_totp() {
                if let Some(site) = sites::two_factor_for(&item.urls) {
                    no_two_factor.push(SiteItem {
                        item: entry.clone(),
                        methods: sites::two_factor_methods(site.codes),
                        docs_url: sites::docs_url(site.docs),
                    });
                }
            }
            if let Some(site) = sites::passkeys_for(&item.urls) {
                passkeys.push(SiteItem {
                    item: entry.clone(),
                    methods: sites::passkey_modes(site.codes),
                    docs_url: sites::docs_url(site.docs),
                });
            }
        }
    }
    contains_name.sort_by(by_title);
    insecure.sort_by(|a, b| by_title(&a.item, &b.item));
    no_two_factor.sort_by(|a, b| by_title(&a.item, &b.item));
    passkeys.sort_by(|a, b| by_title(&a.item, &b.item));

    let mut no_password: Vec<HealthItem> = live
        .iter()
        .filter(|i| {
            i.kind == ItemKind::Login
                && i.password.is_empty()
                && i.passkeys.is_empty()
                && !i.has_totp()
                && (!i.username.trim().is_empty() || i.urls.iter().any(|u| !u.trim().is_empty()))
        })
        .map(|i| health_item(i, 0))
        .collect();
    no_password.sort_by(by_title);

    let reuse_of = |item: &Item| {
        by_password
            .get(item.password.as_str())
            .map_or(0, |m| m.len() as u32)
    };
    let live_items: Vec<Item> = live.iter().map(|&i| i.clone()).collect();
    let by_id: HashMap<&str, &Item> = live.iter().map(|i| (i.id.as_str(), *i)).collect();
    let duplicates: Vec<DuplicateSet> = crate::import::duplicate_groups(&live_items)
        .into_iter()
        .map(|g| DuplicateSet {
            items: g
                .item_ids
                .iter()
                .filter_map(|id| by_id.get(id.as_str()))
                .map(|i| health_item(i, reuse_of(i)))
                .collect(),
        })
        .filter(|set| set.items.len() > 1)
        .collect();

    let flagged: HashSet<&str> = contains_name
        .iter()
        .chain(insecure.iter().map(|i| &i.item))
        .map(|e| e.item_id.as_str())
        .collect();
    let healthy = entries
        .iter()
        .filter(|e| {
            e.score > 1 && e.reuse_count <= 1 && !is_old(e) && !flagged.contains(e.item_id.as_str())
        })
        .count() as u32;
    HealthReport {
        checked: entries.len() as u32,
        weak,
        reused,
        old,
        healthy,
        contains_name,
        insecure,
        no_two_factor,
        passkeys,
        no_password,
        duplicates,
    }
}

/// Whether the item's password contains its username (or an email address's local part) or its
/// site's name (the first label of the registrable domain), case and leetspeak ignored.
fn password_contains_name(item: &Item) -> bool {
    let password = fold_name(&item.password);
    username_names(&item.username, false)
        .iter()
        .chain(site_names(&item.urls).iter())
        .any(|n| password.contains(fold_name(n).as_str()))
}

/// `s` in lower case with leetspeak undone (`P@ss` → `pass`), for name matching. Zeroized on drop
/// (it may be a password).
pub(crate) fn fold_name(s: &str) -> zeroize::Zeroizing<String> {
    zeroize::Zeroizing::new(s.chars().map(unleet).collect())
}

/// The names a password should not contain from a username: the whole username and, for an
/// e-mail address, the part before `@`; with `parts`, also the pieces between `.`, `_`, `-`, `+`
/// and spaces (`john.smith` → `john`, `smith`). Lower case, at least [`MIN_NAME_LEN`] characters.
pub(crate) fn username_names(username: &str, parts: bool) -> Vec<String> {
    let user = username.trim().to_lowercase();
    let mut names: Vec<String> = Vec::new();
    let local = user.split_once('@').map(|(l, _)| l.to_string());
    if let Some(local) = &local {
        names.push(local.clone());
    }
    if parts {
        let source = local.as_deref().unwrap_or(&user);
        names.extend(source.split(['.', '_', '-', '+', ' ']).map(str::to_string));
    }
    names.push(user);
    names.retain(|n| n.chars().count() >= MIN_NAME_LEN);
    names.sort();
    names.dedup();
    names
}

/// The site names a password should not contain: the first label of each website's registrable
/// domain (`google` for `accounts.google.com`; IP addresses have none), lower case, at least
/// [`MIN_NAME_LEN`] characters.
pub(crate) fn site_names(urls: &[String]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for url in urls {
        if let Some(host) = sites::web_host(url) {
            if let Some(domain) = crate::matching::registrable_domain_of_host(&host) {
                if domain.parse::<IpAddr>().is_err() {
                    names.push(domain.split('.').next().unwrap_or("").to_string());
                }
            }
        }
    }
    names.retain(|n| n.chars().count() >= MIN_NAME_LEN);
    names.sort();
    names.dedup();
    names
}

/// Whether a host is local or private, where plain `http` is normal: `localhost`, single-label
/// names (`router`, `nas`), the special-use and home-network suffixes (`.local`, `.lan`,
/// `.home.arpa`, `.home`, `.internal`, `.intranet`, `.localdomain`, `.localhost`, `.test`,
/// `.example`, `.invalid`), loopback, private (10/8, 172.16/12, 192.168/16), link-local,
/// shared (100.64/10, carrier-grade NAT and VPNs) and unique-local IPv6 addresses.
pub(crate) fn is_private_host(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Ipv4(ip) => private_v4(ip),
        url::Host::Ipv6(ip) => private_v6(ip),
        url::Host::Domain(name) => {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            if !name.contains('.') {
                return true;
            }
            const SUFFIXES: &[&str] = &[
                "localhost",
                "local",
                "lan",
                "home.arpa",
                "home",
                "internal",
                "intranet",
                "localdomain",
                "test",
                "example",
                "invalid",
            ];
            SUFFIXES.iter().any(|s| {
                name.strip_suffix(s)
                    .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
            })
        }
    }
}

fn private_v4(ip: &Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || (a == 100 && (64..128).contains(&b))
}

fn private_v6(ip: &Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    ip.is_loopback()
        || ip.is_unspecified()
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
        || ip.to_ipv4_mapped().is_some_and(|v4| private_v4(&v4))
}

/// Whether a saved address is `http://` to a public site.
pub(crate) fn is_insecure_url(entry: &str) -> bool {
    let entry = entry.trim();
    if !entry
        .get(..7)
        .is_some_and(|s| s.eq_ignore_ascii_case("http://"))
    {
        return false;
    }
    match url::Url::parse(entry) {
        Ok(url) => url.host().is_some_and(|h| !is_private_host(&h)),
        Err(_) => false,
    }
}

/// `entry` with `https://` instead of `http://`, if it is an insecure address that can safely
/// change: a domain name (not an IP address) without a port. Everything after the scheme stays.
fn https_upgrade(entry: &str) -> Option<String> {
    if !is_insecure_url(entry) {
        return None;
    }
    let trimmed = entry.trim();
    let url = url::Url::parse(trimmed).ok()?;
    if !matches!(url.host(), Some(url::Host::Domain(_))) || url.port().is_some() {
        return None;
    }
    Some(format!("https://{}", &trimmed[7..]))
}

/// "Change to https": changes every `http://` address of item `item_id` that
/// [`InsecureItem::can_use_https`] allows to `https://` and saves the item in the vault (the
/// caller saves the vault and syncs). Returns how many addresses changed (0: none could).
/// `NotFound` if there is no such live item.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn health_use_https(vault: Arc<Vault>, item_id: String) -> Result<u32> {
    let mut item = vault
        .get(item_id.clone())
        .ok_or_else(|| PassError::NotFound(tr!("vault.no_item")))?;
    let mut changed = 0;
    for url in &mut item.urls {
        if let Some(https) = https_upgrade(url) {
            *url = https;
            changed += 1;
        }
    }
    if changed > 0 {
        vault.upsert(item)?;
    }
    Ok(changed)
}

/// Common passwords and words people build passwords from (lower case). A hit costs ~11 bits.
const COMMON: &[&str] = &[
    "password",
    "passwort",
    "passw0rd",
    "qwerty",
    "qwertz",
    "azerty",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "login",
    "admin",
    "administrator",
    "princess",
    "sunshine",
    "football",
    "baseball",
    "soccer",
    "hockey",
    "basketball",
    "iloveyou",
    "trustno",
    "shadow",
    "superman",
    "batman",
    "spiderman",
    "michael",
    "jennifer",
    "jordan",
    "hunter",
    "ranger",
    "buster",
    "thomas",
    "robert",
    "daniel",
    "andrew",
    "joshua",
    "matthew",
    "jessica",
    "ashley",
    "charlie",
    "george",
    "harley",
    "pepper",
    "ginger",
    "tigger",
    "cookie",
    "summer",
    "winter",
    "spring",
    "autumn",
    "january",
    "february",
    "march",
    "april",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
    "monday",
    "friday",
    "sunday",
    "secret",
    "freedom",
    "whatever",
    "starwars",
    "pokemon",
    "minecraft",
    "computer",
    "internet",
    "google",
    "facebook",
    "apple",
    "samsung",
    "microsoft",
    "windows",
    "hello",
    "flower",
    "lovely",
    "love",
    "angel",
    "baby",
    "lucky",
    "happy",
    "money",
    "silver",
    "golden",
    "orange",
    "banana",
    "cheese",
    "chocolate",
    "coffee",
    "purple",
    "yellow",
    "black",
    "white",
    "killer",
    "matrix",
    "mustang",
    "ferrari",
    "corvette",
    "london",
    "paris",
    "berlin",
    "america",
    "canada",
    "germany",
    "france",
    "school",
    "family",
    "forever",
    "change",
    "access",
    "default",
    "guest",
    "test",
    "user",
    "root",
    "toor",
    "pass",
    "abc",
    "asdf",
    "zxcv",
    "qazwsx",
    "passpass",
    "changeme",
    "abcdef",
    "nothing",
    "maggie",
    "buddy",
    "bailey",
    "soccer",
    "dakota",
    "chelsea",
    "liverpool",
    "arsenal",
    "united",
    "barcelona",
    "madrid",
    "player",
    "gamer",
    "dancer",
    "music",
    "guitar",
    "rockstar",
    "ninja",
    "pirate",
    "wizard",
    "phoenix",
    "tiger",
    "eagle",
    "falcon",
    "wolf",
    "bear",
    "lion",
    "horse",
    "dolphin",
    "butterfly",
    "rainbow",
    "diamond",
    "crystal",
    "heaven",
    "jesus",
    "christ",
    "god",
    "blessed",
    "peace",
    "kitten",
    "puppy",
    "doggy",
    "kitty",
];

/// The bundled list of common passwords.
const COMMON_PASSWORDS: &str = include_str!("../data/common-passwords.txt");

fn common_passwords() -> &'static HashSet<&'static str> {
    static SET: std::sync::OnceLock<HashSet<&'static str>> = std::sync::OnceLock::new();
    SET.get_or_init(|| {
        COMMON_PASSWORDS
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    })
}

/// `s` without up to `max` characters matching `pred` at its end.
fn strip_end(s: &str, pred: impl Fn(char) -> bool, max: usize) -> &str {
    let mut end = s.len();
    for (taken, (at, c)) in s.char_indices().rev().enumerate() {
        if taken >= max || !pred(c) {
            break;
        }
        end = at;
    }
    &s[..end]
}

/// Whether `password` is on the bundled list of common passwords, also with capitals, leetspeak
/// (`P@ssw0rd`) and up to 4 digits and 2 symbols added at the end (`Dragon2024!`). Offline.
pub(crate) fn is_common_password(password: &str) -> bool {
    let list = common_passwords();
    let lower = zeroize::Zeroizing::new(password.trim().to_lowercase());
    if lower.is_empty() {
        return false;
    }
    let symbol = |c: char| c.is_ascii_punctuation() || c == ' ';
    let base = strip_end(lower.as_str(), symbol, 2);
    let base = strip_end(base, |c| c.is_ascii_digit(), 4);
    let base = strip_end(base, symbol, 2);
    let unleet_base = fold_name(base);
    let unleet_whole = fold_name(&lower);
    let base_ok = base.chars().count() >= 3;
    list.contains(lower.as_str())
        || list.contains(unleet_whole.as_str())
        || (base_ok && (list.contains(base) || list.contains(unleet_base.as_str())))
}

/// Keyboard rows for walk detection.
const ROWS: &[&str] = &[
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
    "qwertzuiop",
    "yxcvbnm",
    "azertyuiop",
    "qsdfghjklm",
    "wxcvbn",
];

pub(crate) fn unleet(c: char) -> char {
    match c {
        '0' => 'o',
        '1' | '!' | '|' => 'i',
        '3' => 'e',
        '4' | '@' => 'a',
        '5' | '$' => 's',
        '7' => 't',
        '8' => 'b',
        '9' => 'g',
        other => other.to_ascii_lowercase(),
    }
}

/// The size of the character pool `password` draws from.
fn pool_size(chars: &[char]) -> f64 {
    let mut pool = 0;
    if chars.iter().any(char::is_ascii_lowercase) {
        pool += 26;
    }
    if chars.iter().any(char::is_ascii_uppercase) {
        pool += 26;
    }
    if chars.iter().any(char::is_ascii_digit) {
        pool += 10;
    }
    if chars
        .iter()
        .any(|c| c.is_ascii() && !c.is_ascii_alphanumeric())
    {
        pool += 33;
    }
    if chars.iter().any(|c| !c.is_ascii()) {
        pool += 100;
    }
    f64::from(pool.max(10))
}

/// Length of the dictionary word (≥ 3 letters, leetspeak and case ignored) at the start of `s`,
/// and its extra cost in bits (capitals, substitutions).
fn word_at(s: &[char]) -> Option<(usize, f64)> {
    let plain: String = s.iter().take(16).map(|&c| unleet(c)).collect();
    let mut best: Option<usize> = None;
    for word in COMMON {
        let n = word.chars().count();
        if n >= 3
            && n <= plain.chars().count()
            && plain.starts_with(word)
            && best.is_none_or(|b| n > b)
        {
            best = Some(n);
        }
    }
    let n = best?;
    let piece = &s[..n];
    let upper = piece.iter().filter(|c| c.is_ascii_uppercase()).count();
    let leet = piece.iter().filter(|c| !c.is_ascii_alphabetic()).count();
    let mut extra = 0.0;
    if upper > 0 && !(upper == 1 && piece[0].is_ascii_uppercase()) && upper < n {
        extra += (n as f64).log2() * upper as f64 / 2.0 + 1.0;
    } else if upper > 0 {
        extra += 1.0;
    }
    extra += leet as f64;
    Some((n, (COMMON.len() as f64).log2() + extra))
}

/// Length of a run of one character at the start of `s` (≥ 3).
fn repeat_at(s: &[char]) -> Option<usize> {
    let n = s.iter().take_while(|&&c| c == s[0]).count();
    (n >= 3).then_some(n)
}

/// Length of an ascending or descending sequence (`abc`, `987`) or keyboard walk at the start of
/// `s` (≥ 3, walks ≥ 4).
fn sequence_at(s: &[char]) -> Option<usize> {
    if s.len() < 3 {
        return None;
    }
    let step = s[1] as i32 - s[0] as i32;
    let mut n = 0;
    if step == 1 || step == -1 {
        n = 2;
        while n < s.len() && s[n] as i32 - s[n - 1] as i32 == step {
            n += 1;
        }
    }
    // The rows are ASCII: only the ASCII start of `s` can match, and byte and character indices
    // agree there (slicing past a multi-byte character would panic).
    let lower: String = s
        .iter()
        .take_while(|c| c.is_ascii())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    for row in ROWS {
        let rev: String = row.chars().rev().collect();
        for r in [row.to_string(), rev] {
            let mut k = 0;
            while k < lower.len() && k < 24 && r.contains(&lower[..=k]) {
                k += 1;
            }
            if k >= 4 {
                n = n.max(k);
            }
        }
    }
    (n >= 3).then_some(n)
}

/// A year 1900-2099 at the start of `s`.
fn year_at(s: &[char]) -> bool {
    s.len() >= 4
        && s[..4].iter().all(char::is_ascii_digit)
        && matches!((s[0], s[1]), ('1', '9') | ('2', '0'))
}

/// A keyboard for walk detection: its rows (unshifted, then shifted, one key per character) and
/// how far each row starts to the right, in key widths.
struct Layout {
    rows: &'static [(&'static str, &'static str, f64)],
    /// Keys on neighbouring rows touch when their centres are at most this far apart sideways.
    reach: f64,
}

/// US QWERTY (staggered rows) and the number pad.
const LAYOUTS: &[Layout] = &[
    Layout {
        rows: &[
            ("`1234567890-=", "~!@#$%^&*()_+", 0.0),
            ("qwertyuiop[]\\", "QWERTYUIOP{}|", 1.5),
            ("asdfghjkl;'", "ASDFGHJKL:\"", 1.75),
            ("zxcvbnm,./", "ZXCVBNM<>?", 2.25),
        ],
        reach: 0.75,
    },
    Layout {
        rows: &[
            ("789", "789", 0.0),
            ("456", "456", 0.0),
            ("123", "123", 0.0),
            ("0", "0", 0.0),
        ],
        reach: 1.0,
    },
];

/// Each change of direction in a keyboard walk costs this much more.
const TURN_BITS: f64 = 2.5;

/// Where `c` is on `layout`: (row, position from the left).
fn key_of(layout: &Layout, c: char) -> Option<(i32, f64)> {
    layout.rows.iter().enumerate().find_map(|(r, (plain, shifted, offset))| {
        plain
            .chars()
            .position(|k| k == c)
            .or_else(|| shifted.chars().position(|k| k == c))
            .map(|x| (r as i32, x as f64 + offset))
    })
}

/// The direction from key `a` to a neighbouring key `b`, or `None` when they don't touch.
fn step_between(layout: &Layout, a: (i32, f64), b: (i32, f64)) -> Option<(i32, i32)> {
    let (dr, dx) = (b.0 - a.0, b.1 - a.1);
    let touch = match dr {
        0 => (dx.abs() - 1.0).abs() < 1e-6,
        -1 | 1 => dx.abs() <= layout.reach + 1e-6,
        _ => false,
    };
    touch.then(|| (dr, if dx.abs() < 1e-6 { 0 } else { dx.signum() as i32 }))
}

/// Keyboard walks at the start of `s`: each key next to the one before (`qwerty`, `1qaz2wsx`'s
/// `1qaz`, `zaqxsw`, `147258` on the number pad). Every usable length with its number of turns:
/// 3 keys in a straight line, or 4 and more with any turns. Longest per layout.
fn walk_at(s: &[char]) -> Vec<(usize, u32)> {
    let mut out: Vec<(usize, u32)> = Vec::new();
    for layout in LAYOUTS {
        let Some(mut at) = s.first().and_then(|&c| key_of(layout, c)) else {
            continue;
        };
        let mut dir: Option<(i32, i32)> = None;
        let mut turns = 0u32;
        for (len, &c) in s.iter().enumerate().skip(1).take(63) {
            let Some(next) = key_of(layout, c) else {
                break;
            };
            let Some(step) = step_between(layout, at, next) else {
                break;
            };
            if dir.is_some_and(|d| d != step) {
                turns += 1;
            }
            dir = Some(step);
            at = next;
            let keys = len + 1;
            if keys >= 4 || (keys == 3 && turns == 0) {
                out.push((keys, turns));
            }
        }
    }
    out
}

/// An estimate of how guessable `password` is. Nothing is stored or sent.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn password_strength(password: String) -> PasswordStrength {
    let password = zeroize::Zeroizing::new(password);
    strength_of(&password)
}

/// What the cheapest cover of a password is made of ([`strength_detail`]), for telling the user
/// why it is easy to guess.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Patterns {
    /// Common words (`password`, `dragon`), also capitalised or in leetspeak.
    pub words: bool,
    /// Runs of one character (`aaaa`) or a repeated block (`abcabc`, `Tiger7Tiger7`).
    pub repeats: bool,
    /// Sequences (`abcd`, `4321`) and keyboard walks (`qwerty`, `1qaz2wsx`, `147258`).
    pub sequences: bool,
    /// Years 1900-2099.
    pub years: bool,
}

impl Patterns {
    /// Repeats or sequences: what a person fixes by typing something less regular.
    pub fn regular(self) -> bool {
        self.repeats || self.sequences
    }
}

/// A [`PasswordStrength`] and what made it cheap.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StrengthDetail {
    pub strength: PasswordStrength,
    pub patterns: Patterns,
}

#[derive(Clone, Copy)]
enum Piece {
    Char,
    Word,
    Repeat,
    Sequence,
    Year,
}

/// Blocks up to this many characters are looked for repeated (`abcabc`).
const MAX_BLOCK: usize = 32;

/// How many times the first `k` characters of `s` repeat back to back from its start (1: once).
fn block_repeats(s: &[char], k: usize) -> usize {
    let mut reps = 1;
    while (reps + 1) * k <= s.len() && s[reps * k..(reps + 1) * k] == s[..k] {
        reps += 1;
    }
    reps
}

/// The cheapest cover of `chars` by dynamic programming over positions: its cost in bits and the
/// kinds of pieces it used. `blocks`: also cover a repeated block (`abcabc`) by the cost of one
/// block plus the number of repeats; looked for one level deep (a block's own cover has none).
fn cover(chars: &[char], char_bits: f64, blocks: bool) -> (f64, Patterns) {
    let n = chars.len();
    let mut best = vec![f64::INFINITY; n + 1];
    let mut how: Vec<(usize, Piece)> = vec![(0, Piece::Char); n + 1];
    best[0] = 0.0;
    for i in 0..n {
        if !best[i].is_finite() {
            continue;
        }
        let s = &chars[i..n];
        let mut relax = |len: usize, bits: f64, piece: Piece| {
            if len > 0 && i + len <= n && best[i] + bits < best[i + len] {
                best[i + len] = best[i] + bits;
                how[i + len] = (i, piece);
            }
        };
        relax(1, char_bits, Piece::Char);
        if let Some((len, bits)) = word_at(s) {
            relax(len, bits, Piece::Word);
        }
        if let Some(len) = repeat_at(s) {
            for l in 3..=len {
                relax(l, char_bits + (l as f64).log2(), Piece::Repeat);
            }
        }
        if let Some(len) = sequence_at(s) {
            for l in 3..=len {
                relax(l, char_bits + (l as f64).log2() + 1.0, Piece::Sequence);
            }
        }
        for (len, turns) in walk_at(s) {
            let bits = char_bits + (len as f64).log2() + 1.0 + f64::from(turns) * TURN_BITS;
            relax(len, bits, Piece::Sequence);
        }
        if year_at(s) {
            relax(4, 7.0, Piece::Year);
        }
        if blocks {
            for k in 2..=(s.len() / 2).min(MAX_BLOCK) {
                let reps = block_repeats(s, k);
                if reps >= 2 {
                    let (block, _) = cover(&s[..k], char_bits, false);
                    let bits = block + (reps as f64).log2() + 1.0;
                    relax(k * reps, bits, Piece::Repeat);
                }
            }
        }
    }
    let mut patterns = Patterns::default();
    let mut at = n;
    while at > 0 {
        let (from, piece) = how[at];
        match piece {
            Piece::Char => {}
            Piece::Word => patterns.words = true,
            Piece::Repeat => patterns.repeats = true,
            Piece::Sequence => patterns.sequences = true,
            Piece::Year => patterns.years = true,
        }
        at = from;
    }
    (best[n], patterns)
}

/// The score (0 to 4) of an estimate in bits: < 28 very weak, < 36 weak, < 60 fair, < 80 good,
/// else strong.
pub(crate) fn score_of_bits(bits: f64) -> u32 {
    match bits {
        b if b < 28.0 => 0,
        b if b < 36.0 => 1,
        b if b < 60.0 => 2,
        b if b < 80.0 => 3,
        _ => 4,
    }
}

/// [`password_strength`] of a borrowed password; its working copies are zeroized.
pub(crate) fn strength_of(password: &str) -> PasswordStrength {
    strength_detail(password).strength
}

/// [`strength_of`] and the kinds of pieces that made the password cheap to guess.
pub(crate) fn strength_detail(password: &str) -> StrengthDetail {
    let chars: zeroize::Zeroizing<Vec<char>> = zeroize::Zeroizing::new(password.chars().collect());
    if chars.is_empty() {
        return StrengthDetail {
            strength: PasswordStrength {
                score: 0,
                entropy_bits: 0.0,
            },
            patterns: Patterns::default(),
        };
    }
    let char_bits = pool_size(&chars).log2();
    // The cheapest cover of the first 256 characters; any more count as random characters.
    let n = chars.len().min(256);
    let (cover_bits, patterns) = cover(&chars[..n], char_bits, true);
    // Several pieces: their order and how they were joined cost a little more.
    let bits = cover_bits
        + if n > 0 {
            (n as f64).log2().min(4.0)
        } else {
            0.0
        };
    let bits = if chars.len() > n {
        bits + (chars.len() - n) as f64 * char_bits
    } else {
        bits
    };
    let whole: zeroize::Zeroizing<String> =
        zeroize::Zeroizing::new(chars.iter().map(|&c| unleet(c)).collect());
    let bits = if COMMON.contains(&whole.trim_end_matches(|c: char| c.is_ascii_digit()))
        && whole.len() <= 12
    {
        bits.min(16.0)
    } else {
        bits
    };
    // On the list of common passwords: among the first guesses, whatever its pieces.
    let bits = if is_common_password(password) {
        bits.min(16.0)
    } else {
        bits
    };
    StrengthDetail {
        strength: PasswordStrength {
            score: score_of_bits(bits),
            entropy_bits: (bits * 10.0).round() / 10.0,
        },
        patterns,
    }
}

/// The HIBP range query for `password`: the first 5 and the other 35 characters of its uppercase
/// hex SHA-1. Only the prefix may be sent anywhere.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn hibp_prefix(password: String) -> HibpQuery {
    let hex = crate::encoding::hex(&Sha1::digest(password.as_bytes())).to_ascii_uppercase();
    HibpQuery {
        prefix: hex[..5].to_string(),
        suffix: hex[5..].to_string(),
    }
}

/// How often the password behind `suffix` appears in a HIBP range response (`SUFFIX:COUNT`
/// lines; padding lines with count 0 are ignored); 0 if it doesn't. Case-insensitive.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn hibp_match(range_response: String, suffix: String) -> u64 {
    let suffix = suffix.trim();
    range_response
        .lines()
        .filter_map(|line| line.trim().split_once(':'))
        .find(|(s, _)| s.trim().eq_ignore_ascii_case(suffix))
        .and_then(|(_, count)| count.trim().parse().ok())
        .unwrap_or(0)
}

/// Asks HIBP (`api.pwnedpasswords.com`, k-anonymity with padding) how often `password` appears in
/// breaches; 0 if never. Sends only the 5-character hash prefix. Blocking: call it off the UI
/// thread. `Network` if the service can't be reached.
#[cfg(feature = "webdav")]
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn hibp_check(password: String) -> crate::Result<u64> {
    let query = hibp_prefix(password);
    let body = hibp_range(&query.prefix)?;
    Ok(hibp_match(body, query.suffix))
}

/// The padded HIBP range answer for one 5-character `prefix` (`SUFFIX:COUNT` lines, padding
/// lines with count 0): `GET https://api.pwnedpasswords.com/range/<prefix>` with
/// `Add-Padding: true`, so every answer has about the same size. Nothing but the prefix is sent.
/// For checking many passwords: one request per distinct prefix, its answer matched against every
/// suffix with that prefix (`hibp_match`). Blocking; `Network` if the service can't be reached.
#[cfg(feature = "webdav")]
pub fn hibp_range(prefix: &str) -> crate::Result<String> {
    const API: &str = "https://api.pwnedpasswords.com";
    let action = tr!("action.breach_check");
    if prefix.len() != 5 || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(PassError::Network(crate::net::unexpected_answer(&action)));
    }
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .build();
    agent
        .get(&format!("{API}/range/{prefix}"))
        .set("Add-Padding", "true")
        .set("User-Agent", "Passyble")
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(code, _) => crate::net::status_error(&action, code),
            ureq::Error::Transport(t) => crate::net::transport_error(&action, &t, API, || {
                crate::net::unexpected_answer(&action)
            }),
        })?
        .into_string()
        .map_err(|e| crate::net::read_error(&action, &e, || crate::net::unexpected_answer(&action)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(p: &str) -> u32 {
        password_strength(p.into()).score
    }

    #[test]
    fn strength_estimates_are_sensible() {
        for weak in [
            "",
            "123456",
            "password",
            "P@ssw0rd",
            "qwerty123",
            "aaaaaaaa",
            "abcdefgh",
            "Summer2023",
            "letmein!",
            "iloveyou1",
            "dragon99",
        ] {
            assert!(
                score(weak) <= 1,
                "{weak}: {:?}",
                password_strength(weak.into())
            );
        }
        for strong in [
            "x7#Rq!9vLm@2Wz$e",
            "correct-horse-battery-staple-orbit",
            "bodefa-kitusa-mepiro-gavuno",
        ] {
            assert!(
                score(strong) >= 3,
                "{strong}: {:?}",
                password_strength(strong.into())
            );
        }
        assert!(
            password_strength("Tr0ub4dor&3xyz".into()).entropy_bits
                > password_strength("Tr0ub4dor".into()).entropy_bits
        );
        // Very long input stays cheap and strong.
        assert_eq!(score(&"aZ9!".repeat(200)), 4);
    }

    #[test]
    fn walks_and_repeated_blocks_are_cheap() {
        for regular in [
            "1qaz2wsx3edc4rfv",
            "zaq12wsxcde3",
            "qazwsxedcrfvtgb",
            "147258369147",
            "abcabcabcabc",
            "Tiger7Tiger7Tiger7",
            "kx7!kx7!kx7!kx7!",
        ] {
            let d = strength_detail(regular);
            assert!(d.strength.score <= 2, "{regular}: {d:?}");
            assert!(d.patterns.regular(), "{regular}: {d:?}");
        }
        // A few neighbouring keys inside a random password cost little.
        assert!(score("Wq8#vB2@rTz9mK4e") >= 3);
        let d = strength_detail("x7#Rq!9vLm@2Wz$e");
        assert!(!d.patterns.regular(), "{d:?}");
        assert!(strength_detail("dragonmonkey").patterns.words);
        // Non-ASCII characters never break the row check (slicing inside a multi-byte character would panic).
        assert!(score("äöüßéèñçøåæœ") >= 3);
        assert!(score("ä") <= 1);
        assert!(strength_detail("ghjkl€ä").patterns.sequences);
    }

    #[test]
    fn hibp_helpers_follow_the_range_api() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let q = hibp_prefix("password".into());
        assert_eq!(q.prefix, "5BAA6");
        assert_eq!(q.suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
        let response = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                        1e4c9b93f3f0682250b6cf8331b7ee68fd8:9659365\r\n\
                        011053FD0102E94D6AE2F8B83D76FAF94F6:0\r\n";
        assert_eq!(hibp_match(response.into(), q.suffix.clone()), 9_659_365);
        assert_eq!(
            hibp_match(
                response.into(),
                "011053FD0102E94D6AE2F8B83D76FAF94F6".into()
            ),
            0,
            "padding"
        );
        assert_eq!(hibp_match("".into(), q.suffix), 0);
    }

    fn item(title: &str, url: &str, user: &str, password: &str) -> Item {
        Item {
            id: title.to_lowercase(),
            kind: ItemKind::Login,
            title: title.into(),
            username: user.into(),
            password: password.into(),
            urls: if url.is_empty() {
                vec![]
            } else {
                vec![url.into()]
            },
            ..Default::default()
        }
    }

    const STRONG: &str = "Xk9#mQ2!vLp7@wZ4";

    #[test]
    fn http_addresses_to_public_sites_are_unsecured() {
        for bad in [
            "http://example.com",
            "HTTP://Example.com/login",
            "  http://shop.example.co.uk/a?b=c  ",
            "http://8.8.8.8/",
            "http://example.com:8080",
            "http://[2001:db8::1]/",
            "http://100.128.0.1",
            "http://172.32.0.1",
            "http://notlocal.com",
            "http://lan.example.com",
        ] {
            assert!(is_insecure_url(bad), "{bad}");
        }
        for fine in [
            "https://example.com",
            "example.com",
            "ftp://example.com",
            "windows:notepad.exe",
            "androidapp://com.example",
            "http://",
            "http://localhost:3000",
            "http://LOCALHOST",
            "http://app.localhost",
            "http://127.0.0.1",
            "http://127.8.9.1:8000",
            "http://10.0.0.1",
            "http://172.16.0.1",
            "http://172.31.255.254",
            "http://192.168.1.1",
            "http://169.254.1.1",
            "http://100.64.0.1",
            "http://0.0.0.0",
            "http://[::1]:8080",
            "http://[fd00::1]/",
            "http://[fe80::1]/",
            "http://[::ffff:192.168.0.1]/",
            "http://router",
            "http://nas/admin",
            "http://printer.local",
            "http://printer.local.",
            "http://nas.lan",
            "http://hub.home.arpa",
            "http://pi.home",
            "http://wiki.corp.internal",
            "http://site.test",
        ] {
            assert!(!is_insecure_url(fine), "{fine}");
        }
    }

    #[test]
    fn only_plain_domains_switch_to_https() {
        assert_eq!(
            https_upgrade("http://example.com/login?x=1").as_deref(),
            Some("https://example.com/login?x=1")
        );
        assert_eq!(
            https_upgrade(" HTTP://Example.com ").as_deref(),
            Some("https://Example.com")
        );
        // The default port is no port.
        assert_eq!(
            https_upgrade("http://example.com:80/").as_deref(),
            Some("https://example.com:80/")
        );
        assert_eq!(https_upgrade("http://example.com:8080"), None, "port");
        assert_eq!(https_upgrade("http://8.8.8.8"), None, "IP address");
        assert_eq!(https_upgrade("http://192.168.1.1"), None, "private");
        assert_eq!(https_upgrade("https://example.com"), None);
    }

    #[test]
    fn passwords_with_the_username_or_site_name() {
        let has = |url: &str, user: &str, password: &str| {
            password_contains_name(&item("T", url, user, password))
        };
        assert!(has("https://x.example", "marianne", "Marianne!2024#xyz"));
        assert!(has(
            "https://x.example",
            "marianne@mail.example",
            "q9#marianneZ!"
        ));
        assert!(
            has("https://x.example", "marianne", "M4r1anne-k3y-9vQ"),
            "leetspeak"
        );
        assert!(has("https://accounts.dropbox.com", "", "MyDropbox!2020x"));
        assert!(!has("https://x.example", "ann", "ann-q9#Lz!vX2w"), "short");
        assert!(
            !has("https://bbc.co.uk", "", "bbc-q9#Lz!vX2w"),
            "short site"
        );
        assert!(!has("https://x.example", "marianne", STRONG));
        assert!(!has("http://192.168.10.20", "", "192.168-q9#Lz!vX2w"));
    }

    #[test]
    fn the_report_finds_every_problem() {
        let now = 10 * OLD_PASSWORD_MS;
        let mut items = vec![
            item("Fine", "https://fine.example", "f", STRONG),
            item(
                "Http",
                "http://shop.example.com/login",
                "h",
                "Hq7$Lm2#Rt9!Vw4%",
            ),
            item(
                "Http port",
                "http://shop.example.com:8080",
                "p",
                "Pq7$Lm2#Rt9!Vw4%",
            ),
            item("Router", "http://192.168.1.1", "admin", "Rq7$Lm2#Rt9!Vw4%"),
            item(
                "Named",
                "https://named.example",
                "marianne",
                "Marianne#9vQz!Lw",
            ),
            item("Weak named", "https://w.example", "dragon", "dragon99"),
            item(
                "GitHub",
                "https://github.com/login",
                "octo",
                "Gq7$Lm2#Rt9!Vw4%",
            ),
            item(
                "Google",
                "https://accounts.google.com",
                "me",
                "Oq7$Lm2#Rt9!Vw4%",
            ),
            item("Empty", "https://empty.example", "e", ""),
            item("Copy 1", "https://dup.example", "same", "Dq7$Lm2#Rt9!Vw4%"),
            item("Copy 2", "https://dup.example", "Same", "Eq7$Lm2#Rt9!Vw4%"),
        ];
        // GitHub with an authenticator secret and a passkey: neither suggestion.
        items.push(Item {
            totp: Some("JBSWY3DPEHPK3PXP".into()),
            passkeys: vec![crate::model::Passkey::default()],
            ..item(
                "GitHub 2",
                "https://github.com",
                "octo2",
                "Zq7$Lm2#Rt9!Vw4%",
            )
        });
        // Authenticator-only and passkey-only logins have nothing missing.
        items.push(Item {
            totp: Some("JBSWY3DPEHPK3PXP".into()),
            ..item("Codes only", "https://codes.example", "c", "")
        });
        items.push(Item {
            passkeys: vec![crate::model::Passkey::default()],
            ..item("Passkey only", "https://pk.example", "k", "")
        });
        // A note without anything, and a trashed login with every problem.
        items.push(Item {
            kind: ItemKind::Note,
            ..item("Note", "", "", "")
        });
        items.push(Item {
            trashed_at: Some(5),
            ..item("Trashed", "http://github.com", "marianne", "")
        });
        for i in &mut items {
            i.password_changed_at = now - 1000;
        }
        let r = health_report(&items, now);
        let titles = |list: &[HealthItem]| list.iter().map(|i| i.title.clone()).collect::<Vec<_>>();
        assert_eq!(r.checked, 11);
        assert_eq!(titles(&r.weak), ["Weak named"]);
        assert_eq!(titles(&r.contains_name), ["Named"], "weak ones left out");
        let insecure: Vec<(&str, bool)> = r
            .insecure
            .iter()
            .map(|i| (i.item.title.as_str(), i.can_use_https))
            .collect();
        assert_eq!(insecure, [("Http", true), ("Http port", false)]);
        assert_eq!(r.insecure[0].urls, ["http://shop.example.com/login"]);
        let tfa: Vec<&str> = r
            .no_two_factor
            .iter()
            .map(|i| i.item.title.as_str())
            .collect();
        assert_eq!(tfa, ["GitHub", "Google"]);
        assert!(r.no_two_factor[0].methods.contains(&"totp".to_string()));
        assert!(r.no_two_factor[0].docs_url.starts_with("https://"));
        let pk: Vec<&str> = r.passkeys.iter().map(|i| i.item.title.as_str()).collect();
        assert!(
            pk.contains(&"GitHub") && !pk.contains(&"GitHub 2"),
            "{pk:?}"
        );
        assert_eq!(titles(&r.no_password), ["Empty"]);
        assert_eq!(r.duplicates.len(), 1);
        let mut dup = titles(&r.duplicates[0].items);
        dup.sort();
        assert_eq!(dup, ["Copy 1", "Copy 2"]);
        // Healthy: not weak, named or on an unsecured site (2FA and passkeys don't count).
        assert_eq!(r.healthy, 11 - 1 - 1 - 2);
        assert!(!format!("{r:?}").contains("Rq7$"));
    }
}
