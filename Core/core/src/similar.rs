//! Similar sites: another site's logins offered on a page that has none of its own, such as
//! `amazon.de` with a login for `amazon.com` or a login titled "GitHub" on `github.example.com`.
//! A pick still goes through the cross-site fill prompt. Sites under a shared public suffix are
//! kept apart, and a login whose site the page imitates is never suggested.

use crate::lookalike::{entry_host, readable, split_domain, KnownSites, LookalikeCheck};
use crate::model::{url_rule_of, ItemKind, UrlMatch};
use crate::summary::ItemSummary;

/// The shortest name a login's website may share with the page.
const MIN_SAME_NAME: usize = 2;
/// The shortest name a title is matched with, as a whole word.
const MIN_TITLE_WORD: usize = 3;
/// From this length on, a name matches anywhere in a title ("MyAmazon").
const MIN_TITLE_INSIDE: usize = 5;

/// Why a login is similar to the page ([`similar_logins`]). Ordered strongest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SimilarReason {
    /// A website of the login has the page's name under another suffix or subdomain.
    SameName,
    /// The login's title holds the page's name.
    Title,
}

impl SimilarReason {
    /// The reason as the agent protocol names it.
    pub fn as_str(self) -> &'static str {
        match self {
            SimilarReason::SameName => "same_name",
            SimilarReason::Title => "title",
        }
    }
}

/// One login [`similar_logins`] found: its position in the list it was given, and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimilarLogin {
    pub index: usize,
    pub reason: SimilarReason,
}

/// A web page: its registrable domain and name. `None` for anything else (an Android app, an IP
/// address, a single-label host, a public suffix itself).
fn page_site(page: &str) -> Option<(String, String)> {
    entry_site(page).filter(|(_, name)| !name.is_empty())
}

/// The name of a page's site (`amazon` for `https://www.amazon.co.uk/`, `alice` for
/// `https://alice.github.io/`): what the extension prefills its vault search with. `None` where
/// [`similar_logins`] finds nothing either.
pub fn site_name(page: &str) -> Option<String> {
    page_site(page).map(|(_, name)| name)
}

/// The registrable domain and name of a login's website entry (web entries only).
fn entry_site(entry: &str) -> Option<(String, String)> {
    let (host, url) = entry_host(entry)?;
    url?;
    let (domain, suffix) = split_domain(&host)?;
    let name = readable(domain.strip_suffix(&suffix)?.strip_suffix('.')?).to_lowercase();
    Some((domain, name))
}

/// Whether `title` holds `name`: as a word (letters and digits around it don't continue it), or
/// anywhere for a long name.
fn title_holds(title: &str, name: &str) -> bool {
    let length = name.chars().count();
    if length < MIN_TITLE_WORD {
        return false;
    }
    let title = title.to_lowercase();
    let word = |c: Option<char>| c.is_some_and(char::is_alphanumeric);
    let mut start = 0;
    while let Some(at) = title[start..].find(name) {
        let i = start + at;
        if length >= MIN_TITLE_INSIDE
            || (!word(title[..i].chars().next_back())
                && !word(title[i + name.len()..].chars().next()))
        {
            return true;
        }
        start = i + name.chars().next().map_or(1, char::len_utf8);
    }
    false
}

/// Why `login` is similar to the page of `domain` and `name`, if it is. `None` for a login of
/// the page's own site (whatever the entry's rule: a login the user hid there, or kept to another
/// host of it, is not offered there as another site's), and an entry the user hid
/// ([`UrlMatch::Never`]) suggests nothing.
fn similar(login: &ItemSummary, domain: &str, name: &str) -> Option<SimilarReason> {
    let mut same_name = false;
    for entry in &login.urls {
        let Some((other, other_name)) = entry_site(entry) else {
            continue;
        };
        if other == domain {
            return None;
        }
        if other_name == name
            && name.chars().count() >= MIN_SAME_NAME
            && url_rule_of(&login.url_rules, entry) != UrlMatch::Never
        {
            same_name = true;
        }
    }
    if same_name {
        Some(SimilarReason::SameName)
    } else if title_holds(&login.title, name) {
        Some(SimilarReason::Title)
    } else {
        None
    }
}

/// Logins of other sites that `page` (a URL) may be the site of: at most `limit`, the strongest
/// reason first, then favorites, the most used (`rank`), then by title. `logins`: the logins to
/// look at (other kinds are skipped); `known`: every site of the vault, for the lookalike check
/// (a page of any of them is no lookalike). Logins whose site the page looks like are left out.
pub fn similar_logins(
    page: &str,
    logins: &[ItemSummary],
    known: &KnownSites,
    limit: usize,
) -> Vec<SimilarLogin> {
    let Some((domain, name)) = page_site(page) else {
        return Vec::new();
    };
    let check = LookalikeCheck::new_known(page, known);
    let mut found: Vec<SimilarLogin> = logins
        .iter()
        .enumerate()
        .filter(|(_, login)| login.kind == ItemKind::Login)
        .filter_map(|(index, login)| {
            let reason = similar(login, &domain, &name)?;
            let lookalike = check
                .as_ref()
                .and_then(|c| c.against(login.urls.iter().map(String::as_str)));
            lookalike
                .is_none()
                .then_some(SimilarLogin { index, reason })
        })
        .collect();
    found.sort_by(|a, b| {
        let (x, y) = (&logins[a.index], &logins[b.index]);
        a.reason
            .cmp(&b.reason)
            .then(y.favorite.cmp(&x.favorite))
            .then(y.rank.cmp(&x.rank))
            .then_with(|| x.title.to_lowercase().cmp(&y.title.to_lowercase()))
    });
    found.truncate(limit);
    found
}

#[cfg(test)]
#[path = "similar_tests.rs"]
mod tests;
