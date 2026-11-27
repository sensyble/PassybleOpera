//! Checks a password before it is saved and returns warnings (saving is never blocked).
//! Everything runs on the device and copies of the password are zeroized. Without a vault only the
//! checks of the password itself run.

use std::sync::Arc;

use crate::health::{
    fold_name, is_common_password, score_of_bits, site_names, strength_detail, username_names,
    MIN_NAME_LEN,
};
use crate::i18n::tr;
use crate::model::Item;
use crate::vault::Vault;
use crate::{PassError, Result};

/// Passwords shorter than this (in characters) get [`PasswordIssueKind::Short`].
pub const PASSWORD_MIN_LENGTH: u32 = 12;

/// Below this, [`PasswordIssueKind::Short`] is [`IssueSeverity::High`].
const VERY_SHORT: u32 = 8;

/// Only this much of a (pasted) password is looked at.
const MAX_CHECKED_CHARS: usize = 4096;

/// What a password is checked against ([`password_issues`]). No secrets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PasswordContext {
    /// The login's username or e-mail address (`""`: none).
    pub username: String,
    /// Its websites (`https://…` or a bare host); other entries are ignored.
    pub urls: Vec<String>,
    /// Its Android apps (package names, `com.example.app`; `androidapp://` is accepted too).
    pub android_apps: Vec<String>,
    /// Its title (`""`: none); a one-word title is looked for like a site's name.
    pub title: String,
    /// The item being edited (`""` for a new one): its own password does not count as reuse.
    pub item_id: String,
}

/// One problem found by [`password_issues`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum PasswordIssueKind {
    Common,
    Weak,
    Reused,
    UsedBefore,
    ContainsUsername,
    ContainsSite,
    Short,
}

impl PasswordIssueKind {
    /// The code in JSON (desktop agent, Windows app): `common`, `weak`, `reused`, `used_before`,
    /// `contains_username`, `contains_site`, `short`.
    pub fn as_str(self) -> &'static str {
        match self {
            PasswordIssueKind::Common => "common",
            PasswordIssueKind::Weak => "weak",
            PasswordIssueKind::Reused => "reused",
            PasswordIssueKind::UsedBefore => "used_before",
            PasswordIssueKind::ContainsUsername => "contains_username",
            PasswordIssueKind::ContainsSite => "contains_site",
            PasswordIssueKind::Short => "short",
        }
    }
}

/// How much an issue matters (the apps may colour it).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum IssueSeverity {
    High,
    Medium,
    Low,
}

impl IssueSeverity {
    /// `high`, `medium` or `low`.
    pub fn as_str(self) -> &'static str {
        match self {
            IssueSeverity::High => "high",
            IssueSeverity::Medium => "medium",
            IssueSeverity::Low => "low",
        }
    }
}

/// A problem with the password and what the message needs. No secrets: `name` is the part of
/// the username, site or title (as given in the [`PasswordContext`]) that was found.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PasswordIssue {
    pub kind: PasswordIssueKind,
    pub severity: IssueSeverity,
    /// [`PasswordIssueKind::Reused`]: how many other logins have this password; else 0.
    pub count: u32,
    /// [`PasswordIssueKind::ContainsUsername`] / [`PasswordIssueKind::ContainsSite`]: the name
    /// found (lower case); else `""`.
    pub name: String,
    /// [`PasswordIssueKind::Short`]: [`PASSWORD_MIN_LENGTH`]; else 0.
    pub min_length: u32,
}

/// The result of [`password_issues`]. No secrets.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PasswordCheck {
    /// [`crate::PasswordStrength::score`]: 0 very weak … 4 strong.
    pub score: u32,
    pub entropy_bits: f64,
    /// `very_weak`, `weak`, `fair`, `good` or `strong` (`""` for an empty password).
    pub label: String,
    /// Most important first (severity, then the order of [`PasswordIssueKind`]). Empty: nothing
    /// to say.
    pub issues: Vec<PasswordIssue>,
    /// The vault was open, so Reused and UsedBefore were checked too.
    pub vault_checked: bool,
}

/// The label of a strength score.
pub fn strength_label(score: u32) -> &'static str {
    match score {
        0 => "very_weak",
        1 => "weak",
        2 => "fair",
        3 => "good",
        _ => "strong",
    }
}

/// Checks `password` before it is saved. `vault` is the unlocked vault (for reuse checks), or `None`
/// while locked.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn password_issues(
    vault: Option<Arc<Vault>>,
    password: String,
    context: PasswordContext,
) -> PasswordCheck {
    let password = zeroize::Zeroizing::new(password);
    match vault {
        Some(vault) => {
            vault.with_live_items(|items| password_issues_in(Some(items), &password, &context))
        }
        None => password_issues_in(None, &password, &context),
    }
}

/// [`password_issues`] over `items` (the vault's live items; `None`: locked).
pub fn password_issues_in(
    items: Option<&mut dyn Iterator<Item = &Item>>,
    password: &str,
    context: &PasswordContext,
) -> PasswordCheck {
    if password.is_empty() {
        return PasswordCheck {
            score: 0,
            entropy_bits: 0.0,
            label: String::new(),
            issues: Vec::new(),
            vault_checked: items.is_some(),
        };
    }
    let end = password
        .char_indices()
        .nth(MAX_CHECKED_CHARS)
        .map_or(password.len(), |(at, _)| at);
    let password = &password[..end];
    let strength = crate::health::strength_of(password);
    let chars = password.chars().count() as u32;
    let mut issues: Vec<PasswordIssue> = Vec::new();
    let issue = |kind, severity| PasswordIssue {
        kind,
        severity,
        count: 0,
        name: String::new(),
        min_length: 0,
    };

    let common = is_common_password(password);
    if common {
        issues.push(issue(PasswordIssueKind::Common, IssueSeverity::High));
    } else if strength.score <= 1 {
        issues.push(issue(PasswordIssueKind::Weak, IssueSeverity::High));
    }

    let vault_checked = items.is_some();
    if let Some(items) = items {
        let (reused, used_before) = vault_uses(items, password, &context.item_id);
        if reused > 0 {
            issues.push(PasswordIssue {
                count: reused,
                ..issue(PasswordIssueKind::Reused, IssueSeverity::High)
            });
        }
        if used_before {
            issues.push(issue(PasswordIssueKind::UsedBefore, IssueSeverity::Medium));
        }
    }

    let folded = fold_name(password);
    let found = |names: Vec<String>| {
        names
            .into_iter()
            .find(|n| folded.contains(fold_name(n).as_str()))
    };
    if let Some(name) = found(username_names(&context.username, true)) {
        issues.push(PasswordIssue {
            name,
            ..issue(PasswordIssueKind::ContainsUsername, IssueSeverity::Medium)
        });
    }
    if let Some(name) = found(context_site_names(context)) {
        issues.push(PasswordIssue {
            name,
            ..issue(PasswordIssueKind::ContainsSite, IssueSeverity::Medium)
        });
    }

    if chars < PASSWORD_MIN_LENGTH {
        let severity = if chars < VERY_SHORT {
            IssueSeverity::High
        } else if strength.score >= 3 {
            IssueSeverity::Low
        } else {
            IssueSeverity::Medium
        };
        issues.push(PasswordIssue {
            min_length: PASSWORD_MIN_LENGTH,
            ..issue(PasswordIssueKind::Short, severity)
        });
    }

    issues.sort_by_key(|i| (i.severity, i.kind));
    let score = if common { 0 } else { strength.score };
    PasswordCheck {
        score,
        entropy_bits: strength.entropy_bits,
        label: strength_label(score).to_string(),
        issues,
        vault_checked,
    }
}

/// How many live items other than `item_id` have `password`, and whether `item_id` had it before
/// (in its history, not as its current password).
fn vault_uses(
    items: &mut dyn Iterator<Item = &Item>,
    password: &str,
    item_id: &str,
) -> (u32, bool) {
    let mut reused = 0;
    let mut used_before = false;
    for item in items {
        if !item_id.is_empty() && item.id == item_id {
            used_before = item.password != password
                && item.password_history.iter().any(|h| h.password == password);
        } else if item.password == password {
            reused += 1;
        }
    }
    (reused, used_before)
}

/// Labels of Android package names that say nothing about the app.
const GENERIC_PACKAGE_LABELS: &[&str] = &[
    "android", "apps", "mobile", "client", "main", "free", "lite", "release", "prod",
];

/// The site and app names of `context`: website names ([`site_names`]), distinctive labels of its
/// Android packages, and a one-word title.
fn context_site_names(context: &PasswordContext) -> Vec<String> {
    let mut names = site_names(&context.urls);
    for app in &context.android_apps {
        let package = app.trim();
        let package = package
            .strip_prefix("androidapp://")
            .unwrap_or(package)
            .to_ascii_lowercase();
        // `com.netflix.mediaclient`: skip the first label (the reversed domain's top level).
        names.extend(
            package
                .split('.')
                .skip(1)
                .filter(|l| l.len() >= MIN_NAME_LEN && !GENERIC_PACKAGE_LABELS.contains(l))
                .map(str::to_string),
        );
    }
    let title = context.title.trim().to_lowercase();
    if !title.is_empty() && !title.contains(char::is_whitespace) {
        // A domain as title ("netflix.com"): its first label.
        let word = title.split('.').next().unwrap_or("").to_string();
        if word.chars().count() >= MIN_NAME_LEN {
            names.push(word);
        }
    }
    names.sort();
    names.dedup();
    names
}

/// A new master password needs at least this many characters.
pub const MASTER_PASSWORD_MIN_LENGTH: u32 = 12;

/// And at least this strength score (3: "good", an estimate of 60 bits or more).
pub const MASTER_PASSWORD_MIN_SCORE: u32 = 3;

/// A name from the [`MasterPasswordContext`] found in the password costs this much to guess.
const NAME_BITS: f64 = 6.0;

/// Always treated as known: the app's own name.
const APP_NAMES: &[&str] = &["passyble"];

/// What a new master password should not be built from. No secrets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MasterPasswordContext {
    /// The user's e-mail addresses and user names (Google account, Passyble Server account) and
    /// the vault's name, as far as the app knows them. Empty entries are ignored; e-mail
    /// addresses and names count whole and in pieces (`john.smith@example.com`: `john`, `smith`),
    /// pieces of at least 4 characters.
    pub names: Vec<String>,
}

/// Why a new master password is refused ([`master_password_check`]), in the order the apps show
/// them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum MasterPasswordIssue {
    /// Fewer than [`MASTER_PASSWORD_MIN_LENGTH`] characters ("Use at least 12 characters").
    TooShort,
    /// On the list of common passwords, also with capitals, leetspeak, digits or symbols added.
    Common,
    /// Built from the e-mail address, user name or vault name: without them it would pass the
    /// strength check, or come much closer ([`MasterPasswordCheck::name`]: the name found).
    ContainsName,
    /// Repeated characters or blocks, sequences (`abcd`, `1234`) or keyboard walks (`qwerty`).
    Pattern,
    /// Too easy to guess (always there when the strength is below the rule): the fix is more
    /// words or random characters.
    Guessable,
}

impl MasterPasswordIssue {
    /// The code in JSON (desktop app, browser extension): `too_short`, `common`, `contains_name`,
    /// `pattern`, `guessable`.
    pub fn as_str(self) -> &'static str {
        match self {
            MasterPasswordIssue::TooShort => "too_short",
            MasterPasswordIssue::Common => "common",
            MasterPasswordIssue::ContainsName => "contains_name",
            MasterPasswordIssue::Pattern => "pattern",
            MasterPasswordIssue::Guessable => "guessable",
        }
    }
}

/// The result of [`master_password_check`]. No secrets (`name` is a piece of a name the app
/// passed in).
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MasterPasswordCheck {
    /// The password may become the master password.
    pub ok: bool,
    /// The strength score counted as the rule does (names known, a common password 0): 0 very
    /// weak … 4 strong; [`MASTER_PASSWORD_MIN_SCORE`] or more passes.
    pub score: u32,
    /// [`strength_label`] of `score` (`""` for an empty password).
    pub label: String,
    pub entropy_bits: f64,
    /// Empty when `ok`, and for an empty password (nothing typed yet: no reasons to show).
    pub issues: Vec<MasterPasswordIssue>,
    /// [`MasterPasswordIssue::ContainsName`]: the name found (lower case); else `""`.
    pub name: String,
    /// [`MASTER_PASSWORD_MIN_LENGTH`], for the "at least N characters" text.
    pub min_length: u32,
}

/// Checks a new master password against the length and strength rule as the user types.
/// Offline, nothing is kept; the copies made while checking are zeroized.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn master_password_check(
    password: String,
    context: MasterPasswordContext,
) -> MasterPasswordCheck {
    let password = zeroize::Zeroizing::new(password);
    check_master_password(&password, &context)
}

/// `Ok` if `password` may become the master password, else `InvalidInput` with a short reason in
/// the core's language: for the places that set one (the apps' commands, the browser's vault),
/// after the form has shown the reasons from [`master_password_check`].
pub fn require_master_password(password: &str, context: &MasterPasswordContext) -> Result<()> {
    if check_master_password(password, context).ok {
        Ok(())
    } else {
        Err(PassError::InvalidInput(tr!(
            "master_password.too_weak",
            min = MASTER_PASSWORD_MIN_LENGTH
        )))
    }
}

/// [`master_password_check`] of a borrowed password.
pub fn check_master_password(password: &str, context: &MasterPasswordContext) -> MasterPasswordCheck {
    let none = |issues| MasterPasswordCheck {
        ok: false,
        score: 0,
        label: String::new(),
        entropy_bits: 0.0,
        issues,
        name: String::new(),
        min_length: MASTER_PASSWORD_MIN_LENGTH,
    };
    if password.is_empty() {
        return none(Vec::new());
    }
    let end = password
        .char_indices()
        .nth(MAX_CHECKED_CHARS)
        .map_or(password.len(), |(at, _)| at);
    let password = &password[..end];
    let chars: zeroize::Zeroizing<Vec<char>> = zeroize::Zeroizing::new(password.chars().collect());
    let detail = strength_detail(password);
    let common = is_common_password(password);

    // The names in the password are known to the attacker: what is left, plus a few bits a name.
    let (named_bits, name, rest_patterns) = match names_in(&chars, context) {
        Some((rest, found, first)) => {
            let rest_detail = strength_detail(&rest);
            let bits = if rest.is_empty() {
                0.0
            } else {
                rest_detail.strength.entropy_bits
            } + NAME_BITS * found as f64;
            (Some(bits.min(detail.strength.entropy_bits)), first, rest_detail.patterns)
        }
        None => (None, String::new(), detail.patterns),
    };
    let bits = if common {
        detail.strength.entropy_bits.min(16.0)
    } else {
        named_bits.unwrap_or(detail.strength.entropy_bits)
    };
    let score = if common { 0 } else { score_of_bits(bits) };

    let mut issues = Vec::new();
    if (chars.len() as u32) < MASTER_PASSWORD_MIN_LENGTH {
        issues.push(MasterPasswordIssue::TooShort);
    }
    let mut found_name = String::new();
    if common {
        issues.push(MasterPasswordIssue::Common);
    } else if score < MASTER_PASSWORD_MIN_SCORE {
        // The names made the difference: without them the password would be a lot stronger.
        let names_matter = named_bits
            .is_some_and(|b| b + NAME_BITS < detail.strength.entropy_bits);
        if names_matter {
            issues.push(MasterPasswordIssue::ContainsName);
            found_name = name;
        }
        if detail.patterns.regular() || (names_matter && rest_patterns.regular()) {
            issues.push(MasterPasswordIssue::Pattern);
        }
        issues.push(MasterPasswordIssue::Guessable);
    }
    MasterPasswordCheck {
        ok: issues.is_empty(),
        score,
        label: strength_label(score).to_string(),
        entropy_bits: (bits * 10.0).round() / 10.0,
        issues,
        name: found_name,
        min_length: MASTER_PASSWORD_MIN_LENGTH,
    }
}

/// The names of `context` (and [`APP_NAMES`]) found in `chars`, case and leetspeak ignored: the
/// password without them, how many were found and the first (longest) one. `None` if there are
/// none.
fn names_in(
    chars: &[char],
    context: &MasterPasswordContext,
) -> Option<(zeroize::Zeroizing<String>, usize, String)> {
    let mut names: Vec<String> = context
        .names
        .iter()
        .flat_map(|n| username_names(n, true))
        .chain(APP_NAMES.iter().map(|n| n.to_string()))
        .collect();
    // Longest first, so `john.smith` is taken before `john` and `smith`.
    names.sort_by(|a, b| b.chars().count().cmp(&a.chars().count()).then(a.cmp(b)));
    names.dedup();
    let folded: zeroize::Zeroizing<Vec<char>> =
        zeroize::Zeroizing::new(chars.iter().map(|&c| crate::health::unleet(c)).collect());
    let mut taken = vec![false; chars.len()];
    let mut found = 0;
    let mut first = String::new();
    for name in &names {
        let needle: Vec<char> = fold_name(name).chars().collect();
        if needle.len() < MIN_NAME_LEN || needle.len() > folded.len() {
            continue;
        }
        let mut at = 0;
        while at + needle.len() <= folded.len() {
            if folded[at..at + needle.len()] == needle[..]
                && !taken[at..at + needle.len()].iter().any(|&t| t)
            {
                taken[at..at + needle.len()].iter_mut().for_each(|t| *t = true);
                found += 1;
                if first.is_empty() {
                    first = name.clone();
                }
                at += needle.len();
            } else {
                at += 1;
            }
        }
    }
    if found == 0 {
        return None;
    }
    let rest: zeroize::Zeroizing<String> = zeroize::Zeroizing::new(
        chars
            .iter()
            .zip(&taken)
            .filter(|(_, &t)| !t)
            .map(|(&c, _)| c)
            .collect(),
    );
    Some((rest, found, first))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ItemKind, PasswordHistoryEntry};

    const STRONG: &str = "Xk9#mQ2!vLp7@wZ4";

    fn login(id: &str, password: &str) -> Item {
        Item {
            id: id.into(),
            kind: ItemKind::Login,
            title: id.into(),
            password: password.into(),
            ..Default::default()
        }
    }

    fn check(items: Option<&[Item]>, password: &str, context: &PasswordContext) -> PasswordCheck {
        match items {
            Some(items) => password_issues_in(Some(&mut items.iter()), password, context),
            None => password_issues_in(None, password, context),
        }
    }

    fn kinds(c: &PasswordCheck) -> Vec<PasswordIssueKind> {
        c.issues.iter().map(|i| i.kind).collect()
    }

    fn find(c: &PasswordCheck, kind: PasswordIssueKind) -> Option<&PasswordIssue> {
        c.issues.iter().find(|i| i.kind == kind)
    }

    #[test]
    fn a_strong_password_has_no_issues() {
        let c = check(Some(&[]), STRONG, &PasswordContext::default());
        assert!(c.issues.is_empty(), "{c:?}");
        assert!(c.score >= 3);
        assert!(c.vault_checked);
        assert!(["good", "strong"].contains(&c.label.as_str()));
    }

    #[test]
    fn empty_password_says_nothing() {
        let c = check(None, "", &PasswordContext::default());
        assert!(c.issues.is_empty());
        assert_eq!(c.label, "");
        assert!(!c.vault_checked);
    }

    #[test]
    fn common_passwords_are_found_with_variations() {
        for p in [
            "123456",
            "password",
            "Password",
            "P@ssw0rd",
            "iloveyou",
            "Dragon2024!",
            "qwerty123",
            "monkey1",
            "sunshine!!",
            "Liverpool1",
            "woaini1314",
        ] {
            let c = check(None, p, &PasswordContext::default());
            assert_eq!(
                find(&c, PasswordIssueKind::Common).map(|i| i.severity),
                Some(IssueSeverity::High),
                "{p}: {c:?}"
            );
            assert!(find(&c, PasswordIssueKind::Weak).is_none(), "{p}");
            assert_eq!(c.score, 0, "{p}");
            assert_eq!(c.label, "very_weak");
        }
        for p in [
            STRONG,
            "correct-horse-battery-staple-orbit",
            "dragon83749201",
        ] {
            let c = check(None, p, &PasswordContext::default());
            assert!(find(&c, PasswordIssueKind::Common).is_none(), "{p}");
        }
    }

    #[test]
    fn weak_passwords_are_easy_to_guess() {
        let c = check(None, "kkkkkkkkkkkk", &PasswordContext::default());
        assert!(find(&c, PasswordIssueKind::Common).is_none());
        assert_eq!(
            find(&c, PasswordIssueKind::Weak).map(|i| i.severity),
            Some(IssueSeverity::High),
            "{c:?}"
        );
        assert!(c.score <= 1);
    }

    #[test]
    fn short_passwords_name_the_minimum() {
        let very = check(None, "x7#Rq!", &PasswordContext::default());
        let short = find(&very, PasswordIssueKind::Short).unwrap();
        assert_eq!(short.severity, IssueSeverity::High);
        assert_eq!(short.min_length, PASSWORD_MIN_LENGTH);
        let c = check(None, "x7#Rq!9vLm@", &PasswordContext::default());
        assert!(c.score >= 3, "{c:?}");
        assert_eq!(
            find(&c, PasswordIssueKind::Short).map(|i| i.severity),
            Some(IssueSeverity::Low)
        );
        assert!(find(
            &check(None, STRONG, &PasswordContext::default()),
            PasswordIssueKind::Short
        )
        .is_none());
    }

    #[test]
    fn reuse_counts_other_live_logins_but_not_the_edited_one() {
        let items = vec![
            login("a", STRONG),
            login("b", STRONG),
            login("c", STRONG),
            login("d", "something-else-entirely-9!"),
        ];
        let new = check(Some(&items), STRONG, &PasswordContext::default());
        let reused = find(&new, PasswordIssueKind::Reused).unwrap();
        assert_eq!(reused.count, 3);
        assert_eq!(reused.severity, IssueSeverity::High);
        let editing_a = PasswordContext {
            item_id: "a".into(),
            ..Default::default()
        };
        let c = check(Some(&items), STRONG, &editing_a);
        assert_eq!(find(&c, PasswordIssueKind::Reused).unwrap().count, 2);
        let editing_d = PasswordContext {
            item_id: "d".into(),
            ..Default::default()
        };
        let unique = check(Some(&items), "something-else-entirely-9!", &editing_d);
        assert!(
            find(&unique, PasswordIssueKind::Reused).is_none(),
            "{unique:?}"
        );
    }

    #[test]
    fn reuse_ignores_items_in_the_trash_through_the_vault() {
        let vault = Vault::create_with_kdf(
            "pw",
            "device",
            crate::KdfParams {
                m_kib: 64,
                t: 1,
                p: 1,
                ..Default::default()
            },
        )
        .unwrap();
        let a = vault.upsert(login("", STRONG)).unwrap();
        let b = vault.upsert(login("", STRONG)).unwrap();
        vault.delete(b.id.clone()).unwrap();
        let c = password_issues(
            Some(vault.clone()),
            STRONG.into(),
            PasswordContext::default(),
        );
        assert_eq!(find(&c, PasswordIssueKind::Reused).unwrap().count, 1);
        let c = password_issues(
            Some(vault),
            STRONG.into(),
            PasswordContext {
                item_id: a.id,
                ..Default::default()
            },
        );
        assert!(find(&c, PasswordIssueKind::Reused).is_none(), "{c:?}");
        assert!(c.vault_checked);
    }

    #[test]
    fn locked_checks_only_the_password_itself() {
        let c = password_issues(
            None,
            "password".into(),
            PasswordContext {
                username: "alex".into(),
                ..Default::default()
            },
        );
        assert!(!c.vault_checked);
        assert_eq!(kinds(&c)[0], PasswordIssueKind::Common);
        assert!(find(&c, PasswordIssueKind::Reused).is_none());
        assert!(find(&c, PasswordIssueKind::UsedBefore).is_none());
        let empty = check(Some(&[]), "password", &PasswordContext::default());
        assert!(empty.vault_checked);
        assert_eq!(
            kinds(&empty),
            kinds(&check(None, "password", &Default::default()))
        );
    }

    #[test]
    fn a_previous_password_of_the_same_login_is_used_before() {
        let mut item = login("a", "Current-Pass-4471!x");
        item.password_history = vec![PasswordHistoryEntry {
            password: STRONG.into(),
            replaced_at: 1,
        }];
        let items = vec![item];
        let ctx = PasswordContext {
            item_id: "a".into(),
            ..Default::default()
        };
        let c = check(Some(&items), STRONG, &ctx);
        assert_eq!(
            find(&c, PasswordIssueKind::UsedBefore).map(|i| i.severity),
            Some(IssueSeverity::Medium)
        );
        let same = check(Some(&items), "Current-Pass-4471!x", &ctx);
        assert!(find(&same, PasswordIssueKind::UsedBefore).is_none());
        let other = check(Some(&items), STRONG, &PasswordContext::default());
        assert!(other.issues.is_empty(), "{other:?}");
    }

    #[test]
    fn names_in_the_password_are_found() {
        let ctx = PasswordContext {
            username: "John.Smith@example.com".into(),
            urls: vec!["https://accounts.netflix.com/login".into()],
            ..Default::default()
        };
        let c = check(None, "Sm1th#Rq9vLm@2Wz", &ctx);
        let user = find(&c, PasswordIssueKind::ContainsUsername).unwrap();
        assert_eq!(user.name, "smith");
        assert_eq!(user.severity, IssueSeverity::Medium);
        let c = check(None, "Rq9vLm@2Wz-NETFL1X", &ctx);
        assert_eq!(
            find(&c, PasswordIssueKind::ContainsSite).unwrap().name,
            "netflix"
        );
        assert!(find(&c, PasswordIssueKind::ContainsUsername).is_none());
        let app = PasswordContext {
            android_apps: vec!["com.spotify.music".into()],
            ..Default::default()
        };
        assert_eq!(
            find(
                &check(None, "Rq9vLm@2Wz-spotify", &app),
                PasswordIssueKind::ContainsSite
            )
            .unwrap()
            .name,
            "spotify"
        );
        let titled = PasswordContext {
            title: "Steam".into(),
            ..Default::default()
        };
        assert!(find(
            &check(None, "Rq9vLm@2Wz-steam", &titled),
            PasswordIssueKind::ContainsSite
        )
        .is_some());
        let short = PasswordContext {
            username: "bo".into(),
            urls: vec!["https://x.com".into()],
            ..Default::default()
        };
        assert!(check(None, "bo-x-Rq9vLm@2Wz#k", &short).issues.is_empty());
    }

    #[test]
    fn issues_come_most_important_first() {
        let items = vec![login("other", "alex1234")];
        let ctx = PasswordContext {
            username: "alex1234".into(),
            ..Default::default()
        };
        let c = check(Some(&items), "alex1234", &ctx);
        let severities: Vec<IssueSeverity> = c.issues.iter().map(|i| i.severity).collect();
        let mut sorted = severities.clone();
        sorted.sort();
        assert_eq!(severities, sorted, "{c:?}");
        assert!(find(&c, PasswordIssueKind::Reused).is_some());
        assert!(find(&c, PasswordIssueKind::ContainsUsername).is_some());
        assert!(find(&c, PasswordIssueKind::Short).is_some());
    }

    #[test]
    fn codes_are_stable() {
        assert_eq!(PasswordIssueKind::UsedBefore.as_str(), "used_before");
        assert_eq!(PasswordIssueKind::ContainsSite.as_str(), "contains_site");
        assert_eq!(IssueSeverity::Low.as_str(), "low");
        assert_eq!(strength_label(4), "strong");
    }

    fn master(password: &str, names: &[&str]) -> MasterPasswordCheck {
        check_master_password(
            password,
            &MasterPasswordContext {
                names: names.iter().map(|n| n.to_string()).collect(),
            },
        )
    }

    const ALEX: &[&str] = &["alex.smith@example.com", "Family vault"];

    #[test]
    fn master_rule_refuses_long_but_trivial_passwords() {
        for p in [
            "aaaaaaaaaaaaaaaa",
            "abcdefghijklmnop",
            "1234567890123456",
            "qwertyuiopasdfgh",
            "1qaz2wsx3edc4rfv",
            "zaq12wsxcde34rfv",
            "147258369147258",
            "abcabcabcabcabc",
            "Tiger7Tiger7Tiger7",
            "password1234",
            "Password1234!",
            "P@ssw0rd2024!!",
            "iloveyou2024",
            "dragonmonkeysunshine",
            "passyble12345",
        ] {
            let c = master(p, &[]);
            assert!(!c.ok, "{p}: {c:?}");
            assert!(c.score < MASTER_PASSWORD_MIN_SCORE, "{p}: {c:?}");
            assert!(
                c.issues.contains(&MasterPasswordIssue::Common)
                    || c.issues.contains(&MasterPasswordIssue::Guessable),
                "{p}: {c:?}"
            );
        }
        let walk = master("1qaz2wsx3edc4rfv", &[]);
        assert!(walk.issues.contains(&MasterPasswordIssue::Pattern), "{walk:?}");
        let common = master("Password1234!", &[]);
        assert_eq!(common.issues, vec![MasterPasswordIssue::Common]);
        assert_eq!(common.label, "very_weak");
    }

    #[test]
    fn master_rule_refuses_the_users_own_names() {
        for p in [
            "alex.smith@example.com",
            "AlexSmith2024!!",
            "Sm1th-Alex-1990",
            "familyvault2024",
            "Family vault 1234",
        ] {
            let c = master(p, ALEX);
            assert!(!c.ok, "{p}: {c:?}");
            assert!(
                c.issues.contains(&MasterPasswordIssue::ContainsName),
                "{p}: {c:?}"
            );
            assert!(!c.name.is_empty(), "{p}");
        }
        // Without the context the same password may pass: the names are what makes it weak.
        assert!(master("Sm1th-Alex-1990", &[]).score > master("Sm1th-Alex-1990", ALEX).score);
        // A long passphrase that happens to contain a name still passes.
        let c = master("alex-orbit-candle-meadow-violin", ALEX);
        assert!(c.ok, "{c:?}");
    }

    #[test]
    fn master_rule_accepts_random_passwords_and_passphrases() {
        for p in [
            "x7#Rq!9vLm@2Wz$e",
            "correct-horse-battery-staple-orbit",
            "bodefa-kitusa-mepiro-gavuno",
            "Tiger lamp river 7 cloud",
            "kqzmvbrtlwpxe",
            "Wq8#vB2@rTz9",
        ] {
            let c = master(p, ALEX);
            assert!(c.ok, "{p}: {c:?}");
            assert!(c.issues.is_empty(), "{p}");
            assert!(c.score >= MASTER_PASSWORD_MIN_SCORE);
            assert!(require_master_password(p, &MasterPasswordContext::default()).is_ok());
        }
        // What Passyble generates passes.
        for _ in 0..20 {
            let phrase = crate::generate_passphrase(crate::PASSPHRASE_DEFAULT_WORDS, "-".into());
            assert!(master(&phrase, &[]).ok, "{phrase}");
            let random = crate::generate_password(crate::PasswordOptions::default()).unwrap();
            assert!(master(&random, &[]).ok, "{random}");
        }
    }

    #[test]
    fn master_rule_minimum_length_is_twelve() {
        assert_eq!(MASTER_PASSWORD_MIN_LENGTH, 12);
        // Random but 11 characters: only too short.
        let c = master("x7#Rq!9vLm@", &[]);
        assert_eq!(c.issues, vec![MasterPasswordIssue::TooShort], "{c:?}");
        assert!(!c.ok);
        assert_eq!(c.min_length, 12);
        let c = master("x7#Rq!9vLm@2", &[]);
        assert!(c.ok, "{c:?}");
        assert!(master("äöüßéèñçøåæœ", &[]).issues.iter().all(|i| *i != MasterPasswordIssue::TooShort));
        // Short and trivial: every reason, in order.
        let c = master("aaaa", &[]);
        assert_eq!(c.issues.first(), Some(&MasterPasswordIssue::TooShort));
        assert_eq!(c.issues.last(), Some(&MasterPasswordIssue::Guessable));
    }

    #[test]
    fn master_rule_says_nothing_before_typing_and_refuses_on_require() {
        let c = master("", ALEX);
        assert!(!c.ok);
        assert!(c.issues.is_empty());
        assert_eq!(c.label, "");
        let e = require_master_password("password1234", &MasterPasswordContext::default());
        assert!(matches!(e, Err(PassError::InvalidInput(_))), "{e:?}");
        assert!(require_master_password("", &MasterPasswordContext::default()).is_err());
        assert_eq!(
            master_password_check("Tiger7Tiger7Tiger7".into(), MasterPasswordContext::default()),
            master("Tiger7Tiger7Tiger7", &[])
        );
        assert_eq!(MasterPasswordIssue::ContainsName.as_str(), "contains_name");
        assert_eq!(MasterPasswordIssue::TooShort.as_str(), "too_short");
    }
}
