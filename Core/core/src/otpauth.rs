//! `otpauth://` links from outside the app (QR scanners, web pages, other apps). Such a link is untrusted
//! input carrying a secret, so parsing is stricter than [`crate::totp_parse`]: bounded input, no user info,
//! port, fragment or repeated parameters, and values from the link are never echoed in errors.
//! [`Vault::add_otpauth_link`] is the only write, after the user confirmed. Clients never log the link.

use url::Url;

use crate::i18n::tr;
use crate::matching::registrable_domain;
use crate::model::{Item, ItemKind};
use crate::summary::ItemSummary;
use crate::totp::{self, TotpAlgorithm, UriError};
use crate::vault::Vault;
use crate::{PassError, Result};

/// The longest link accepted, in bytes. Real ones are a few hundred.
pub const MAX_OTPAUTH_LINK: usize = 2048;
/// The longest issuer or account accepted, in characters.
const MAX_LABEL: usize = 256;
/// The shortest secret accepted, in bytes (as the browser extension's editor).
const MIN_SECRET: usize = 10;
/// The longest secret accepted, in bytes (SHA-512's block size).
const MAX_SECRET: usize = 128;
/// How many logins [`otpauth_matches`] offers.
const MAX_MATCHES: usize = 5;

/// A link that passed [`otpauth_parse_link`].
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct OtpauthLink {
    pub issuer: Option<String>,
    pub account: Option<String>,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period: u32,
    /// The clean `otpauth://totp/...` link to store. Holds the secret: for
    /// [`Vault::add_otpauth_link`] only, never for a screen or a log.
    pub uri: String,
}

impl std::fmt::Debug for OtpauthLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtpauthLink")
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish_non_exhaustive()
    }
}

/// A login an [`OtpauthLink`] could be added to.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct OtpauthMatch {
    pub id: String,
    pub title: String,
    pub username: String,
    /// It already has a 2FA code: adding replaces it, so the app says so and asks for that.
    pub has_totp: bool,
    /// The link's account is this login's username.
    pub account_matches: bool,
    /// The one to preselect: the best login without a 2FA code whose name or website matches the
    /// issuer. At most one; none means "a new login" is preselected.
    pub suggested: bool,
}

fn invalid(message: String) -> PassError {
    PassError::InvalidInput(message)
}

/// Reads an `otpauth://totp/...` link from outside the app.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn otpauth_parse_link(link: String) -> Result<OtpauthLink> {
    let link = link.trim();
    if link.len() > MAX_OTPAUTH_LINK {
        return Err(invalid(tr!("totp.link_too_long")));
    }
    let scheme_ok = link
        .get(..10)
        .is_some_and(|s| s.eq_ignore_ascii_case("otpauth://"));
    // Control characters are refused first: `Url::parse` silently drops tabs and line breaks.
    if !scheme_ok || link.chars().any(char::is_control) {
        return Err(invalid(tr!("totp.invalid_uri")));
    }
    let url = Url::parse(link).map_err(|_| invalid(tr!("totp.invalid_uri")))?;
    let unusual = !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.fragment().is_some();
    if unusual || has_repeated_parameter(&url) {
        return Err(invalid(tr!("totp.invalid_uri")));
    }
    let config = totp::parse_url(&url).map_err(|e| match e {
        UriError::Invalid => invalid(tr!("totp.invalid_uri")),
        UriError::Hotp => invalid(tr!("totp.hotp_unsupported")),
        UriError::NotTotp => invalid(tr!("totp.not_totp")),
        UriError::Secret => invalid(tr!("totp.link_bad_secret")),
        UriError::Algorithm(_) => invalid(tr!("totp.link_bad_algorithm")),
        UriError::Digits(_) => invalid(tr!("totp.link_bad_digits")),
        UriError::Period(_) => invalid(tr!("totp.link_bad_period")),
    })?;
    if config.secret.is_empty() {
        return Err(invalid(tr!("totp.link_no_secret")));
    }
    if !(MIN_SECRET..=MAX_SECRET).contains(&config.secret.len()) {
        return Err(invalid(tr!("totp.link_bad_secret")));
    }
    let issuer = config.issuer.as_deref().and_then(clean_label);
    let account = config.account.as_deref().and_then(clean_label);
    let too_long = |s: &Option<String>| s.as_ref().is_some_and(|s| s.chars().count() > MAX_LABEL);
    if too_long(&issuer) || too_long(&account) {
        return Err(invalid(tr!("totp.link_too_long")));
    }
    let uri = crate::import::build_otpauth(
        issuer.as_deref().unwrap_or_default(),
        account.as_deref().unwrap_or_default(),
        &config.secret,
        config.algorithm.uri_name(),
        config.digits,
        config.period,
    );
    Ok(OtpauthLink {
        issuer,
        account,
        algorithm: config.algorithm,
        digits: config.digits,
        period: config.period,
        uri,
    })
}

/// Two values for one parameter: which one counts differs between readers, so it is refused.
fn has_repeated_parameter(url: &Url) -> bool {
    let mut seen: Vec<String> = Vec::new();
    for (key, _) in url.query_pairs() {
        let key = key.to_ascii_lowercase();
        if seen.contains(&key) {
            return true;
        }
        seen.push(key);
    }
    false
}

/// A label without control characters and the invisible characters that can make it read as
/// something else (text direction overrides, zero-width characters); runs of spaces become one.
/// `None` if nothing is left.
fn clean_label(label: &str) -> Option<String> {
    let kept: String = label
        .chars()
        .filter(|c| !c.is_control() && !is_invisible_format(*c))
        .collect();
    let clean = kept.split_whitespace().collect::<Vec<_>>().join(" ");
    (!clean.is_empty()).then_some(clean)
}

fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{FEFF}'
    )
}

/// Letters and digits in lower case, one entry per word.
fn words(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// All the words of the shorter name are in the longer one ("Google" and "Google Accounts", not
/// "Mail" and "Gmail", not "The Company" and "The Verge").
fn names_overlap(a: &[String], b: &[String]) -> bool {
    let (short, long) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    !short.is_empty()
        && short.concat().chars().count() >= 3
        && short.iter().all(|w| long.contains(w))
}

/// The website's name in a registrable domain: `github` in `github.com`.
fn domain_name(domain: &str) -> &str {
    domain.split('.').next().unwrap_or(domain)
}

/// How well `issuer` names a login with this title and these registrable domains; 0 is not at all.
fn issuer_strength(issuer: &str, title: &str, domains: &[String]) -> u32 {
    let issuer_words = words(issuer);
    let key = issuer_words.concat();
    if key.is_empty() {
        return 0;
    }
    let issuer_domain = (issuer.contains('.') && !issuer.contains(char::is_whitespace))
        .then(|| registrable_domain(issuer.to_string()))
        .flatten();
    if issuer_domain.as_ref().is_some_and(|d| domains.contains(d)) {
        return 100;
    }
    let same_as_domain = |key: &str, domain: &String| words(domain_name(domain)).concat() == key;
    if domains.iter().any(|d| same_as_domain(&key, d)) {
        return 90;
    }
    let title_words = words(title);
    let title_key = title_words.concat();
    let issuer_domain_key = issuer_domain
        .as_deref()
        .map(|d| words(domain_name(d)).concat());
    if title_key == key || issuer_domain_key.as_deref() == Some(title_key.as_str()) {
        return 80;
    }
    let overlaps_domain = domains
        .iter()
        .any(|d| names_overlap(&issuer_words, &words(domain_name(d))));
    if names_overlap(&issuer_words, &title_words) || overlaps_domain {
        return 60;
    }
    0
}

/// The logins an `otpauth://` link with this issuer and account could belong to, best first. An
/// account alone counts only for a link without an issuer, and is listed but never suggested.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn otpauth_matches(
    issuer: Option<String>,
    account: Option<String>,
    items: Vec<ItemSummary>,
) -> Vec<OtpauthMatch> {
    let issuer = issuer.unwrap_or_default();
    let account = account.unwrap_or_default().to_lowercase();
    let mut found: Vec<(u32, bool, OtpauthMatch)> = Vec::new();
    for item in items {
        if item.kind != ItemKind::Login {
            continue;
        }
        let username = item.username.trim().to_lowercase();
        let same_account = !account.is_empty() && username == account;
        let same_name = !account.is_empty()
            && !username.is_empty()
            && account.split('@').next() == username.split('@').next();
        let mut domains: Vec<String> = item
            .urls
            .iter()
            .filter_map(|u| registrable_domain(u.clone()))
            .collect();
        if !item.domain.is_empty() {
            domains.push(item.domain.clone());
        }
        let strength = issuer_strength(&issuer, &item.title, &domains);
        let by_issuer = strength > 0;
        if !by_issuer && !(issuer.trim().is_empty() && same_account) {
            continue;
        }
        let bonus = match (same_account, same_name) {
            (true, _) => 30,
            (false, true) => 10,
            (false, false) => 0,
        };
        found.push((
            strength + bonus,
            by_issuer,
            OtpauthMatch {
                id: item.id,
                title: item.title,
                username: item.username,
                has_totp: item.has_totp,
                account_matches: same_account,
                suggested: false,
            },
        ));
    }
    found.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.2.has_totp.cmp(&b.2.has_totp))
            .then_with(|| a.2.title.to_lowercase().cmp(&b.2.title.to_lowercase()))
    });
    found.truncate(MAX_MATCHES);
    let best = found
        .iter_mut()
        .find(|(_, by_issuer, m)| *by_issuer && !m.has_totp);
    if let Some(best) = best {
        best.2.suggested = true;
    }
    found.into_iter().map(|(_, _, m)| m).collect()
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Vault {
    /// Adds a link the user confirmed: to the login `target`, or to a new login named after its issuer or
    /// account (`fallback_title` if neither). A login that has a 2FA code keeps it unless `replace` is set.
    /// The caller saves the vault.
    pub fn add_otpauth_link(
        &self,
        link: OtpauthLink,
        target: Option<String>,
        replace: bool,
        fallback_title: String,
    ) -> Result<Item> {
        crate::totp_parse(link.uri.clone())?;
        let item = match target {
            Some(id) => {
                let mut item = self
                    .get(id)
                    .filter(|item| item.kind == ItemKind::Login)
                    .ok_or_else(|| invalid(tr!("totp.link_item_gone")))?;
                if item.totp.as_deref().is_some_and(|t| !t.trim().is_empty()) && !replace {
                    return Err(invalid(tr!("totp.link_has_code")));
                }
                item.totp = Some(link.uri);
                item
            }
            None => Item {
                kind: ItemKind::Login,
                title: link
                    .issuer
                    .clone()
                    .or_else(|| link.account.clone())
                    .unwrap_or(fallback_title),
                username: link.account.clone().unwrap_or_default(),
                totp: Some(link.uri),
                ..Default::default()
            },
        };
        self.upsert(item)
    }
}

#[cfg(test)]
#[path = "otpauth_tests.rs"]
mod tests;
