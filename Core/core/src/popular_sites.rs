//! Popular websites and apps, to name a new login and fill in its website. The list is compiled
//! in from `core/data/popular-sites.txt`, most popular first; nothing is looked up online. The
//! names are only suggestions: they never decide which logins a page or an app is offered.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::OnceLock;

use crate::matching::{parse_loose, registrable_domain_of_host};
use crate::search::normalize;

const DATA: &str = include_str!("../data/popular-sites.txt");

/// The most suggestions one call returns, whatever `limit` asks for.
pub const MAX_SITE_SUGGESTIONS: u32 = 50;
/// Longer queries find nothing (no name or domain in the list is this long).
const MAX_QUERY_CHARS: usize = 256;

/// A popular site suggested for a name or website being typed ([`site_suggestions`]).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SiteSuggestion {
    /// The name to give the login: the site's name, or the other name the query matched
    /// (`Gmail` for Google).
    pub name: String,
    /// Its website, a bare domain (`google.com`): the domain the query matched, else the main one.
    pub domain: String,
}

/// A name or other name of a site, folded for matching.
struct Name {
    text: &'static str,
    /// Lower case, without accents, spaces or punctuation (`bankofamerica`).
    compact: String,
    /// The words after the first, folded the same way (`of`, `america`).
    later_words: Vec<String>,
}

impl Name {
    fn new(text: &'static str) -> Name {
        let folded = normalize(text);
        let mut words = folded
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty());
        words.next();
        Name {
            text,
            compact: folded.chars().filter(|c| c.is_alphanumeric()).collect(),
            later_words: words.map(str::to_string).collect(),
        }
    }
}

struct Site {
    /// The site's name first, then its other names.
    names: Vec<Name>,
    /// The main domain first.
    domains: Vec<&'static str>,
}

#[derive(Default)]
struct Sites {
    /// Most popular first.
    list: Vec<Site>,
    by_domain: HashMap<&'static str, usize>,
    by_package: HashMap<&'static str, usize>,
}

/// The comma-separated parts of a field, trimmed, without empty ones.
fn parts(field: Option<&'static str>) -> impl Iterator<Item = &'static str> {
    field
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
}

impl Sites {
    /// Parses `name|domains|packages|other names` lines. Comments, blank lines and lines without
    /// a name or domain are skipped; a domain or package already listed keeps its first site.
    fn parse(text: &'static str) -> Sites {
        let mut sites = Sites::default();
        for line in text.lines() {
            let line = line.trim_end_matches('\r');
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split('|');
            let name = fields.next().unwrap_or("").trim();
            let domains: Vec<&str> = parts(fields.next()).collect();
            if name.is_empty() || domains.is_empty() {
                continue;
            }
            let packages: Vec<&str> = parts(fields.next()).collect();
            let index = sites.list.len();
            for domain in &domains {
                sites.by_domain.entry(domain).or_insert(index);
            }
            for package in packages {
                sites.by_package.entry(package).or_insert(index);
            }
            let names = std::iter::once(name)
                .chain(parts(fields.next()))
                .map(Name::new)
                .collect();
            sites.list.push(Site { names, domains });
        }
        sites
    }

    /// The site of `host` (lower case): the host itself, then each parent domain down to its
    /// registrable domain. `None` for IP addresses, single labels and public suffixes.
    fn for_host(&self, host: &str) -> Option<&Site> {
        let host = host.trim_end_matches('.');
        if host.parse::<IpAddr>().is_ok() || host.starts_with('[') || !host.contains('.') {
            return None;
        }
        let registrable = registrable_domain_of_host(host)?;
        let mut candidate = host;
        loop {
            if let Some(&index) = self.by_domain.get(candidate) {
                return Some(&self.list[index]);
            }
            if candidate.len() <= registrable.len() {
                return None;
            }
            candidate = candidate.split_once('.')?.1;
        }
    }
}

fn sites() -> &'static Sites {
    static SITES: OnceLock<Sites> = OnceLock::new();
    SITES.get_or_init(|| Sites::parse(DATA))
}

/// A query as typed, read both as a name and as a website.
struct Query {
    /// Folded like [`Name::compact`].
    compact: String,
    /// Its words, folded.
    words: Vec<String>,
    /// As a website: lower case, without scheme, `www.`, port, path or query (`amazon.de`).
    domain: String,
}

impl Query {
    fn new(text: &str) -> Query {
        let folded = normalize(text.trim());
        let words = folded
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .map(str::to_string)
            .collect();
        let compact = folded.chars().filter(|c| c.is_alphanumeric()).collect();
        let lower = text.trim().to_lowercase();
        let rest = lower
            .strip_prefix("https://")
            .or_else(|| lower.strip_prefix("http://"))
            .unwrap_or(&lower);
        let rest = rest.strip_prefix("www.").unwrap_or(rest);
        let host = rest.split(['/', '?', '#', ':']).next().unwrap_or("");
        let domain = host.trim_end_matches('.').to_string();
        Query {
            compact,
            words,
            domain,
        }
    }

    /// How well `site` matches and what to suggest, `None` if not. Tier 0 is the whole name or a
    /// whole domain, 1 the start of either, 2 the start of a later word of the name.
    fn rank(&self, site: &'static Site) -> Option<(u8, SiteSuggestion)> {
        let mut best: Option<(u8, &'static str, &'static str)> = None;
        let main = site.domains[0];
        let mut offer = |tier: u8, name: &'static str, domain: &'static str| {
            if best.is_none_or(|(t, _, _)| tier < t) {
                best = Some((tier, name, domain));
            }
        };
        if !self.domain.is_empty() {
            for &domain in &site.domains {
                if domain == self.domain {
                    offer(0, site.names[0].text, domain);
                } else if domain.starts_with(&self.domain) {
                    offer(1, site.names[0].text, domain);
                }
            }
        }
        if !self.compact.is_empty() {
            for name in &site.names {
                if name.compact == self.compact {
                    offer(0, name.text, main);
                } else if name.compact.starts_with(&self.compact) {
                    offer(1, name.text, main);
                } else if self.words_start_later(name) {
                    offer(2, name.text, main);
                }
            }
        }
        best.map(|(tier, name, domain)| {
            (
                tier,
                SiteSuggestion {
                    name: name.to_string(),
                    domain: domain.to_string(),
                },
            )
        })
    }

    /// Whether each query word starts a word of `name` after its first (in any order).
    fn words_start_later(&self, name: &Name) -> bool {
        !self.words.is_empty()
            && self
                .words
                .iter()
                .all(|q| name.later_words.iter().any(|w| w.starts_with(q.as_str())))
    }
}

/// Popular sites for a name or website being typed, best match first, at most `limit` (capped
/// at [`MAX_SITE_SUGGESTIONS`]). Matches names (case, accents and punctuation ignored, other names
/// too) and domains; the more popular site wins a tie. Empty for an empty query or no match.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn site_suggestions(query: String, limit: u32) -> Vec<SiteSuggestion> {
    let limit = limit.min(MAX_SITE_SUGGESTIONS) as usize;
    if limit == 0 || query.chars().count() > MAX_QUERY_CHARS {
        return Vec::new();
    }
    let query = Query::new(&query);
    if query.compact.is_empty() && query.domain.is_empty() {
        return Vec::new();
    }
    let mut tiers: [Vec<SiteSuggestion>; 3] = Default::default();
    for site in &sites().list {
        if let Some((tier, suggestion)) = query.rank(site) {
            let tier = usize::from(tier);
            if tier == 0 && tiers[0].len() >= limit {
                break;
            }
            if tiers[tier].len() < limit {
                tiers[tier].push(suggestion);
            }
        }
    }
    tiers.into_iter().flatten().take(limit).collect()
}

/// The name of a popular site for a website (a URL or a host): `GitHub` for
/// `https://github.com/login`, `AWS` for `signin.aws.amazon.com`. `None` for a site not in the
/// list, an IP address, a single-label host or a site on a shared hosting platform.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn site_for_domain(domain: String) -> Option<String> {
    let url = parse_loose(&domain)?;
    let host = url.host_str()?.to_ascii_lowercase();
    sites()
        .for_host(&host)
        .map(|site| site.names[0].text.to_string())
}

/// The popular site of an Android app, by its package name (`com.netflix.mediaclient`): its name
/// and main domain. `None` for an app not in the list. Only for naming a new login: an app is
/// never offered a site's logins because of this.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn site_for_android_app(package: String) -> Option<SiteSuggestion> {
    let sites = sites();
    let site = &sites.list[*sites.by_package.get(package.trim())?];
    Some(SiteSuggestion {
        name: site.names[0].text.to_string(),
        domain: site.domains[0].to_string(),
    })
}

#[cfg(test)]
#[path = "popular_sites_tests.rs"]
mod tests;
