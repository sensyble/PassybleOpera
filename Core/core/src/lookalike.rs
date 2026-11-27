//! Lookalike sites: whether a page imitates a site the user has a login for. Autofill only offers
//! the logins of the page's own site, so the risk is the user filling, copying or saving a login
//! by hand on a phishing page. Registrable domains (Public Suffix List) are compared for
//! homographs, typos and a known domain placed in another site's host or path.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::OnceLock;

use crate::matching::parse_loose;

/// Why a page looks like one of the user's sites ([`Lookalike::reason`]). Ordered strongest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum LookalikeReason {
    /// The same name to the eye: letters of another alphabet, accents, digits for letters.
    Homograph,
    /// The site's whole domain placed in front of another domain (`paypal.com.example.net`).
    DomainInSubdomain,
    /// One or two letters added, missing, changed or swapped (`paypall.com`).
    Typo,
    /// The site's domain in the page's path (`example.net/paypal.com/signin`).
    DomainInPath,
    /// The site's name joined with other words (`paypal-login.com`).
    NameInDomain,
}

impl LookalikeReason {
    /// The reason as the agent protocol and the browser extension name it.
    pub fn as_str(self) -> &'static str {
        match self {
            LookalikeReason::Homograph => "homograph",
            LookalikeReason::DomainInSubdomain => "domain_in_subdomain",
            LookalikeReason::Typo => "typo",
            LookalikeReason::DomainInPath => "domain_in_path",
            LookalikeReason::NameInDomain => "name_in_domain",
        }
    }
}

/// A page that looks like one of the user's sites without being it ([`lookalike_of`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Lookalike {
    /// The user's site the page looks like: its registrable domain, readable (`paypal.com`).
    pub domain: String,
    /// The page's host as the browser has it (international names in their `xn--` form, which
    /// shows the difference): `xn--pypal-4ve.com`. For an Android app, its package name.
    pub host: String,
    pub reason: LookalikeReason,
}

/// Whether `page` (a URL or host; `androidapp://<package>` for an Android app) looks like one of
/// the sites of `site_urls` without being one of them. `site_urls`: the websites (URLs or hosts,
/// `androidapp://` entries too) of the login about to be filled or copied, or of every login for a
/// save. `known_urls`: other websites the user has logins for or linked to the login; a page of
/// one of those (same registrable domain) is never a lookalike. Either may be empty.
///
/// `None` when the page is one of the sites (or a subdomain of one), unparsable, an IP address or
/// a single-label host, or when nothing looks alike. The strongest reason wins
/// ([`LookalikeReason`]); between sites with the same reason, the first in `site_urls`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn lookalike_of(
    page: String,
    site_urls: Vec<String>,
    known_urls: Vec<String>,
) -> Option<Lookalike> {
    let check = LookalikeCheck::new(&page, known_urls.iter().map(String::as_str))?;
    check.against(site_urls.iter().map(String::as_str))
}

/// [`lookalike_of`] for many logins against one page: the page and the known sites are read once
/// ([`LookalikeCheck::new`]), then each login is checked on its own ([`LookalikeCheck::against`]).
pub struct LookalikeCheck {
    page: Page,
}

impl LookalikeCheck {
    /// `None` when `page` can't be a lookalike at all: unparsable, an IP address, a single-label
    /// host, or a page of one of the `known` sites (the same registrable domain).
    pub fn new<'a>(page: &str, known: impl IntoIterator<Item = &'a str>) -> Option<LookalikeCheck> {
        let page = Page::parse(page)?;
        for url in known {
            if site_domain(url).is_some_and(|d| d == page.domain) {
                return None;
            }
        }
        Some(LookalikeCheck { page })
    }

    /// [`LookalikeCheck::new`] with the known sites read once ([`KnownSites`]).
    pub fn new_known(page: &str, known: &KnownSites) -> Option<LookalikeCheck> {
        let page = Page::parse(page)?;
        (!known.domains.contains(&page.domain)).then_some(LookalikeCheck { page })
    }

    /// The site of `site_urls` the page looks like (see [`lookalike_of`]); `None` if the page is
    /// one of them.
    pub fn against<'a>(&self, site_urls: impl IntoIterator<Item = &'a str>) -> Option<Lookalike> {
        let mut seen = HashSet::new();
        let mut sites = Vec::new();
        for url in site_urls {
            let Some(site) = Site::parse(url) else {
                continue;
            };
            if site.domain == self.page.domain {
                return None;
            }
            if seen.insert(site.domain.clone()) {
                sites.push(site);
            }
        }
        let mut best: Option<(LookalikeReason, &Site)> = None;
        for site in &sites {
            if let Some(reason) = self.page.resembles(site) {
                if best.is_none_or(|(r, _)| reason < r) {
                    best = Some((reason, site));
                }
            }
        }
        best.map(|(reason, site)| Lookalike {
            domain: readable(&site.domain),
            host: self.page.shown.clone(),
            reason,
        })
    }
}

/// The sites of a vault's items, parsed once and kept by the vault until its items change, so a
/// page costs a set lookup and a pass over the distinct sites. Built with
/// [`KnownSites::from_urls`] for [`LookalikeCheck::new_known`] outside the core.
pub struct KnownSites {
    /// The registrable domain of every entry of every item ([`site_domain`]), for
    /// [`LookalikeCheck::new_known`].
    domains: HashSet<String>,
    /// The distinct sites of the logins ([`Site::parse`]), first seen first.
    sites: Vec<Site>,
    /// [`Site::domain`] of `sites`.
    site_domains: HashSet<String>,
    /// For each login given to [`KnownSites::new`], in that order, its sites (indexes into `sites`).
    logins: Vec<Vec<usize>>,
}

impl KnownSites {
    /// The `known` sites of [`LookalikeCheck::new`], read once.
    pub fn from_urls<'a>(urls: impl IntoIterator<Item = &'a str>) -> KnownSites {
        KnownSites {
            domains: urls.into_iter().filter_map(site_domain).collect(),
            sites: Vec::new(),
            site_domains: HashSet::new(),
            logins: Vec::new(),
        }
    }

    /// `all`: the [`login_sites`] of every item; `logins`: those of the logins, in a fixed order
    /// that [`KnownSites::lookalike_for_save`]'s `order` refers to.
    pub(crate) fn new(all: &[Vec<String>], logins: &[Vec<String>]) -> KnownSites {
        let domains = all
            .iter()
            .flatten()
            .filter_map(|u| site_domain(u))
            .collect();
        let mut index: HashMap<String, usize> = HashMap::new();
        let mut sites = Vec::new();
        let logins = logins
            .iter()
            .map(|urls| {
                let mut own = Vec::new();
                for url in urls {
                    let Some(site) = Site::parse(url) else {
                        continue;
                    };
                    let at = *index.entry(site.domain.clone()).or_insert_with(|| {
                        sites.push(site);
                        sites.len() - 1
                    });
                    if !own.contains(&at) {
                        own.push(at);
                    }
                }
                own
            })
            .collect();
        KnownSites {
            domains,
            site_domains: index.into_keys().collect(),
            sites,
            logins,
        }
    }

    /// [`LookalikeCheck::against`] the sites of every login, the logins in `order` (indexes of
    /// the logins given to [`KnownSites::new`]; called only when two sites tie): the same answer
    /// as `LookalikeCheck::new(page, [])?.against(<their sites in that order>)`.
    pub(crate) fn lookalike_for_save(
        &self,
        page: &str,
        order: impl FnOnce() -> Vec<usize>,
    ) -> Option<Lookalike> {
        let page = Page::parse(page)?;
        if self.site_domains.contains(&page.domain) {
            return None;
        }
        let mut best: Option<LookalikeReason> = None;
        let mut tied: Vec<usize> = Vec::new();
        for (i, site) in self.sites.iter().enumerate() {
            let Some(reason) = page.resembles(site) else {
                continue;
            };
            match best {
                Some(b) if reason > b => {}
                Some(b) if reason == b => tied.push(i),
                _ => {
                    best = Some(reason);
                    tied = vec![i];
                }
            }
        }
        let reason = best?;
        let site = if tied.len() == 1 {
            tied[0]
        } else {
            // The first of the tied sites in the logins' order.
            order()
                .into_iter()
                .filter_map(|login| self.logins.get(login))
                .flatten()
                .copied()
                .find(|s| tied.contains(s))
                .unwrap_or(tied[0])
        };
        Some(Lookalike {
            domain: readable(&self.sites[site].domain),
            host: page.shown.clone(),
            reason,
        })
    }
}

/// The sites of a login for [`LookalikeCheck`]: its website entries and its linked Android apps
/// (as `androidapp://<package>`).
pub fn login_sites(urls: &[String], android_apps: &[crate::model::AndroidApp]) -> Vec<String> {
    urls.iter()
        .cloned()
        .chain(
            android_apps
                .iter()
                .map(|app| format!("androidapp://{}", app.package)),
        )
        .collect()
}

/// The host of a website entry: a URL or bare host (http or https), or `androidapp://<package>`
/// as the host its package name reads as backwards (`com.paypal.android` is
/// `android.paypal.com`). Lowercase, without a trailing dot. `None` for anything else.
pub(crate) fn entry_host(entry: &str) -> Option<(String, Option<url::Url>)> {
    let entry = entry.trim();
    if let Some(package) = strip_prefix_ignore_case(entry, "androidapp://") {
        let package = package.trim_end_matches('/').to_ascii_lowercase();
        if package.is_empty() || !package.contains('.') {
            return None;
        }
        let host: Vec<&str> = package.split('.').rev().collect();
        return Some((host.join("."), None));
    }
    let url = parse_loose(entry)?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let host = url.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    Some((host, Some(url)))
}

fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then(|| &s[prefix.len()..])
}

/// The registrable domain of `host` and its public suffix; `None` for IP addresses, single-label
/// hosts and public suffixes themselves.
pub(crate) fn split_domain(host: &str) -> Option<(String, String)> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<IpAddr>().is_ok() || !host.contains('.') {
        return None;
    }
    let domain = psl::domain_str(host)?;
    let suffix = psl::suffix_str(domain)?;
    Some((domain.to_string(), suffix.to_string()))
}

/// The registrable domain of a website entry ([`entry_host`]).
fn site_domain(entry: &str) -> Option<String> {
    let (host, _) = entry_host(entry)?;
    split_domain(&host).map(|(domain, _)| domain)
}

/// The readable form of an ASCII domain: international labels (`xn--`) in Unicode.
pub(crate) fn readable(domain: &str) -> String {
    if domain.contains("xn--") {
        url::quirks::domain_to_unicode(domain)
    } else {
        domain.to_string()
    }
}

/// A site of the user's: its registrable domain and name.
struct Site {
    /// The registrable domain, ASCII (`paypal.com`, `xn--bcher-kva.de`).
    domain: String,
    /// The name (the registrable domain without the suffix), readable: `paypal`, `bücher`.
    name: String,
    /// The name's skeleton ([`skeleton`]).
    skeleton: Vec<char>,
}

impl Site {
    fn parse(entry: &str) -> Option<Site> {
        let (host, _) = entry_host(entry)?;
        let (domain, suffix) = split_domain(&host)?;
        let name = readable(domain.strip_suffix(&suffix)?.strip_suffix('.')?);
        if name.is_empty() {
            return None;
        }
        Some(Site {
            skeleton: skeleton(&name),
            domain,
            name,
        })
    }
}

/// The page being checked.
struct Page {
    /// The host, ASCII.
    host: String,
    /// What [`Lookalike::host`] shows: the host, or an Android app's package name.
    shown: String,
    domain: String,
    name: String,
    skeleton: Vec<char>,
    /// The name has letters outside ASCII (an `xn--` label).
    international: bool,
    /// The name mixes Latin letters with Cyrillic, Greek or Armenian ones.
    mixed_script: bool,
    /// The skeletons of the name's hyphenated words, when it has more than one.
    words: Vec<Vec<char>>,
    /// The path's segments, percent-decoded and lowercase (none for a host or an app).
    path: Vec<String>,
}

impl Page {
    fn parse(input: &str) -> Option<Page> {
        let (host, url) = entry_host(input)?;
        let (domain, suffix) = split_domain(&host)?;
        let name = readable(domain.strip_suffix(&suffix)?.strip_suffix('.')?);
        if name.is_empty() {
            return None;
        }
        let shown = match strip_prefix_ignore_case(input.trim(), "androidapp://") {
            Some(package) => package.trim_end_matches('/').to_ascii_lowercase(),
            None => host.clone(),
        };
        let words: Vec<Vec<char>> = if name.contains('-') {
            name.split('-')
                .filter(|w| !w.is_empty())
                .map(skeleton)
                .collect()
        } else {
            Vec::new()
        };
        let path = url
            .map(|url| {
                url.path()
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .map(|s| {
                        percent_encoding::percent_decode_str(s)
                            .decode_utf8_lossy()
                            .to_lowercase()
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(Page {
            international: !name.is_ascii(),
            mixed_script: mixed_script(&name),
            skeleton: skeleton(&name),
            words,
            path,
            host,
            shown,
            domain,
            name,
        })
    }

    /// How this page looks like `site` (another registrable domain), if it does.
    fn resembles(&self, site: &Site) -> Option<LookalikeReason> {
        let n = site.skeleton.len();
        // Read the same, written differently.
        if n >= 3 && self.name != site.name && self.skeleton == site.skeleton {
            return Some(LookalikeReason::Homograph);
        }
        if n >= 3 && self.domain_in_subdomain(site) {
            return Some(LookalikeReason::DomainInSubdomain);
        }
        if n >= 5 {
            let max = if self.mixed_script || n >= 9 { 2 } else { 1 };
            let d = distance(&self.skeleton, &site.skeleton, max);
            if (1..=max).contains(&d) {
                return Some(if self.international {
                    LookalikeReason::Homograph
                } else {
                    LookalikeReason::Typo
                });
            }
        }
        if n >= 3
            && self
                .path
                .iter()
                .any(|segment| contains_at_boundary(segment, &site.domain, |c| !c.is_alphanumeric()))
        {
            return Some(LookalikeReason::DomainInPath);
        }
        if n >= 4 && self.words.contains(&site.skeleton) {
            return Some(LookalikeReason::NameInDomain);
        }
        None
    }

    /// The site's domain (or the same with hyphens for dots) inside the page's host, between
    /// dots or hyphens: `paypal.com.example.net`, `paypal-com.example.net`, `paypal.com-x.net`.
    fn domain_in_subdomain(&self, site: &Site) -> bool {
        let boundary = |c: char| c == '.' || c == '-';
        contains_at_boundary(&self.host, &site.domain, boundary)
            || contains_at_boundary(&self.host, &site.domain.replace('.', "-"), boundary)
    }
}

/// `needle` in `haystack` with a boundary (start, end or a character `is_boundary` accepts) on
/// both sides.
fn contains_at_boundary(haystack: &str, needle: &str, is_boundary: impl Fn(char) -> bool) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    let mut from = 0;
    while let Some(at) = haystack[from..].find(needle) {
        let start = from + at;
        let end = start + needle.len();
        let before = haystack[..start].chars().next_back();
        let after = haystack[end..].chars().next();
        if before.is_none_or(&is_boundary) && after.is_none_or(&is_boundary) {
            return true;
        }
        from = start + haystack[start..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

/// The script of a letter, for [`mixed_script`]: only those that have Latin look-alikes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Script {
    Latin,
    Greek,
    Cyrillic,
    Armenian,
    Other,
}

fn script(c: char) -> Script {
    match c as u32 {
        0x41..=0x5A | 0x61..=0x7A | 0xC0..=0x24F | 0x1E00..=0x1EFF => Script::Latin,
        0x370..=0x3FF | 0x1F00..=0x1FFF => Script::Greek,
        0x400..=0x52F => Script::Cyrillic,
        0x530..=0x58F => Script::Armenian,
        _ => Script::Other,
    }
}

/// A name that mixes Latin letters with Greek, Cyrillic or Armenian ones (`pаypal` with a
/// Cyrillic `а`). Digits and hyphens belong to no script.
fn mixed_script(name: &str) -> bool {
    let mut latin = false;
    let mut lookalike = false;
    for c in name.chars().filter(|c| c.is_alphabetic()) {
        match script(c) {
            Script::Latin => latin = true,
            Script::Greek | Script::Cyrillic | Script::Armenian => lookalike = true,
            Script::Other => {}
        }
    }
    latin && lookalike
}

/// Letters that look like a plain Latin letter (or digit) and the one they look like. A small,
/// hand-picked part of Unicode's confusables (TR #39): the alphabets and accents a domain name
/// can carry that read as Latin. Wider tables (CJK, symbols) would only add false alarms here:
/// those names don't read as a Latin one in the first place.
const FOLDS: &[(char, &str)] = &[
    ('a', "àáâãäåāăąǎȁȃȧạảấầẩẫậắằẳẵặɑαа"),
    ('b', "ƀḃḅḇƅьЬ"),
    ('c', "çćĉċčсϲ"),
    ('d', "ďđḋḍḏḑḓԁɗ"),
    ('e', "èéêëēĕėęěȅȇȩẹẻẽếềểễệеҽ"),
    ('f', "ḟƒ"),
    ('g', "ĝğġģǧǵɡḡց"),
    ('h', "ĥħḣḥḧḩḫһհ"),
    ('i', "ìíîïĩīĭįıǐȉȋḭḯỉịіιї"),
    ('j', "ĵǰјϳ"),
    ('k', "ķǩḱḳḵκк"),
    ('l', "ĺļľŀłḷḹḻḽӏ1"),
    ('m', "ḿṁṃм"),
    ('n', "ñńņňŉǹṅṇṉṋոη"),
    ('o', "òóôõöøōŏőơǒǫǭȍȏȫȭȯȱọỏốồổỗộớờởỡợοоօσ0"),
    ('p', "ṕṗрρ"),
    ('q', "ԛզ"),
    ('r', "ŕŗřȑȓṙṛṝṟг"),
    ('s', "śŝşšșṡṣѕ"),
    ('t', "ţťŧțṫṭṯṱτт"),
    ('u', "ùúûüũūŭůűųưǔǖǘǚǜȕȗụủứừửữựυս"),
    ('v', "ṽṿνѵ"),
    ('w', "ŵẁẃẅẇẉωԝ"),
    ('x', "ẋẍхχ"),
    ('y', "ýÿŷȳẏẙỳỵỷỹуγү"),
    ('z', "źżžẑẓẕ"),
];

fn folds() -> &'static HashMap<char, char> {
    static FOLD: OnceLock<HashMap<char, char>> = OnceLock::new();
    FOLD.get_or_init(|| {
        FOLDS
            .iter()
            .flat_map(|(to, from)| from.chars().map(move |c| (c, *to)))
            .collect()
    })
}

/// What a name looks like: every letter folded to the Latin letter it looks like ([`FOLDS`]),
/// `ß`, `æ` and `œ` spelled out, then `rn` read as `m` and `vv` as `w`. Hyphens and the rest are
/// kept, so `pay-pal` is still one letter away from `paypal`.
fn skeleton(name: &str) -> Vec<char> {
    let fold = folds();
    let mut out = Vec::with_capacity(name.len());
    for c in name.chars().flat_map(char::to_lowercase) {
        match c {
            'ß' => out.extend(['s', 's']),
            'æ' => out.extend(['a', 'e']),
            'œ' => out.extend(['o', 'e']),
            _ => out.push(fold.get(&c).copied().unwrap_or(c)),
        }
    }
    let mut folded = Vec::with_capacity(out.len());
    let mut i = 0;
    while i < out.len() {
        match (out[i], out.get(i + 1)) {
            ('r', Some('n')) => {
                folded.push('m');
                i += 2;
            }
            ('v', Some('v')) => {
                folded.push('w');
                i += 2;
            }
            (c, _) => {
                folded.push(c);
                i += 1;
            }
        }
    }
    folded
}

/// The optimal string alignment distance (Levenshtein plus swaps of two neighbours) between `a`
/// and `b`, or `max + 1` once it is known to be more than `max`.
fn distance(a: &[char], b: &[char], max: usize) -> usize {
    if a.len().abs_diff(b.len()) > max {
        return max + 1;
    }
    let width = b.len() + 1;
    let mut rows = vec![0usize; 3 * width];
    let (mut before, mut prev, mut cur) = (0, width, 2 * width);
    for (j, cell) in rows[prev..prev + width].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        rows[cur] = i;
        let mut row_min = i;
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut d = (rows[prev + j] + 1)
                .min(rows[cur + j - 1] + 1)
                .min(rows[prev + j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d = d.min(rows[before + j - 2] + 1);
            }
            rows[cur + j] = d;
            row_min = row_min.min(d);
        }
        if row_min > max {
            return max + 1;
        }
        (before, prev, cur) = (prev, cur, before);
    }
    rows[prev + b.len()].min(max + 1)
}

#[cfg(test)]
#[path = "lookalike_tests.rs"]
mod tests;
