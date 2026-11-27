use std::net::IpAddr;

use url::Url;

use crate::model::{url_rule_of, AndroidApp, UrlMatch, UrlRule};

/// How well a stored URL matches the page being filled. Higher is better.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MatchQuality {
    None = 0,
    /// Same registrable domain (eTLD+1), e.g. `accounts.example.com` vs `www.example.com`.
    Domain = 1,
    /// Same host.
    Host = 2,
    /// Same origin and the page path starts with the stored path.
    Exact = 3,
}

/// Parses a URL the way users type them: a missing scheme means https.
pub(crate) fn parse_loose(input: &str) -> Option<Url> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }
    let url = match Url::parse(input) {
        Ok(url) if url.has_host() => url,
        _ => Url::parse(&format!("https://{input}")).ok()?,
    };
    url.host_str()?;
    Some(url)
}

/// The registrable domain (eTLD+1) of a host or URL, using the Public Suffix List.
/// IP addresses and single-label hosts such as `localhost` are returned unchanged.
/// Returns `None` for public suffixes themselves (`co.uk`) and unparsable input.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn registrable_domain(host_or_url: String) -> Option<String> {
    let url = parse_loose(&host_or_url)?;
    let host = url.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    registrable_domain_of_host(&host)
}

pub(crate) fn registrable_domain_of_host(host: &str) -> Option<String> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.parse::<IpAddr>().is_ok() || !host.contains('.') {
        return Some(host.to_string());
    }
    psl::domain_str(host).map(str::to_string)
}

pub(crate) fn url_match(stored: &str, page: &Url) -> MatchQuality {
    match parse_loose(stored) {
        Some(stored) => url_match_parsed(&stored, page),
        None => MatchQuality::None,
    }
}

/// [`url_match`] of an entry under its rule: [`UrlMatch::Host`] keeps only matches of the same
/// host (on the entry's port when it names one), [`UrlMatch::Never`] matches nothing.
pub(crate) fn ruled_match(stored: &str, rule: UrlMatch, page: &Url) -> MatchQuality {
    match rule {
        UrlMatch::Subdomains => url_match(stored, page),
        UrlMatch::Never => MatchQuality::None,
        UrlMatch::Host => {
            let Some(stored) = parse_loose(stored) else {
                return MatchQuality::None;
            };
            let quality = url_match_parsed(&stored, page);
            let port_ok = stored
                .port()
                .is_none_or(|port| page.port_or_known_default() == Some(port));
            if quality >= MatchQuality::Host && port_ok {
                quality
            } else {
                MatchQuality::None
            }
        }
    }
}

/// Whether the website `url` is on a shared hosting platform, where anyone can take a name
/// (`alice.github.io`, `shop.web.app`: a suffix of the Public Suffix List's private section), so
/// the editor suggests [`UrlMatch::Host`] for it. Only a suggestion: nothing changes by itself.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn url_suggests_host_only(url: String) -> bool {
    let Some(url) = parse_loose(&url) else {
        return false;
    };
    let Some(url::Host::Domain(host)) = url.host() else {
        return false;
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    psl::suffix(host.as_bytes()).is_some_and(|s| s.typ() == Some(psl::Type::Private))
}

/// The last two labels of a host (`example.com` of `a.b.example.com`), the whole host if it
/// has fewer.
fn last_two_labels(host: &str) -> &str {
    let host = host.trim_end_matches('.');
    match host.rmatch_indices('.').nth(1) {
        Some((at, _)) => &host[at + 1..],
        None => host,
    }
}

/// [`url_match`] of an entry parsed already ([`parse_loose`]).
pub(crate) fn url_match_parsed(stored: &Url, page: &Url) -> MatchQuality {
    if !matches!(stored.scheme(), "http" | "https") || !matches!(page.scheme(), "http" | "https") {
        return MatchQuality::None;
    }
    // Never hand an https credential to a plain-http page.
    if stored.scheme() == "https" && page.scheme() == "http" && !is_local(page) {
        return MatchQuality::None;
    }
    let (Some(stored_host), Some(page_host)) = (stored.host_str(), page.host_str()) else {
        return MatchQuality::None;
    };
    let stored_host = stored_host.to_ascii_lowercase();
    let page_host = page_host.to_ascii_lowercase();
    if stored_host == page_host {
        let same_port = stored.port_or_known_default() == page.port_or_known_default();
        if same_port && stored.path() != "/" && page.path().starts_with(stored.path()) {
            return MatchQuality::Exact;
        }
        return MatchQuality::Host;
    }
    // Two hosts of one registrable domain (at least two labels: two different hosts that are IP
    // addresses or single labels are never one domain) end in the same two labels. Most entries
    // are of other sites: they are told apart here, without two Public Suffix List lookups each.
    if !last_two_labels(&stored_host).eq_ignore_ascii_case(last_two_labels(&page_host)) {
        return MatchQuality::None;
    }
    match (
        registrable_domain_of_host(&stored_host),
        registrable_domain_of_host(&page_host),
    ) {
        (Some(a), Some(b)) if a == b && stored_host.contains('.') => MatchQuality::Domain,
        _ => MatchQuality::None,
    }
}

/// A host as compared for saving: lowercase, without a trailing dot or leading `www.`.
fn save_host(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    match host.strip_prefix("www.") {
        Some(rest) if rest.contains('.') => rest.to_string(),
        _ => host,
    }
}

/// Whether a login saved for `stored` (matched by `rule`) is one a sign-in submitted on `page` may
/// update (save banner, Android save): it matches `page` ([`ruled_match`]: http(s), never https to
/// plain http, never an entry the user hid) on the same host, `www.` or not, ignoring ports and paths.
/// Another subdomain of the site (`example.com` for `app.example.com`, `a.example.com` for
/// `b.example.com`) is not the same host: its login is still offered for filling there
/// ([`MatchQuality::Domain`]), but a new password typed there is saved as a new login.
pub(crate) fn same_login_host(stored: &str, rule: UrlMatch, page: &Url) -> bool {
    if ruled_match(stored, rule, page) == MatchQuality::None {
        return false;
    }
    match (
        parse_loose(stored).as_ref().and_then(Url::host_str),
        page.host_str(),
    ) {
        (Some(a), Some(b)) => save_host(a) == save_host(b),
        _ => false,
    }
}

/// How good a login is for updating from a sign-in submitted on `page` (`Vault::find_for_save`):
/// [`url_suggestion_tier`] of its entries for the page's own host ([`same_login_host`]),
/// [`MatchQuality::None`] without one. An entry the user hid ([`UrlMatch::Never`]) counts here as
/// [`UrlMatch::Subdomains`] would: signing in with a login picked by hand updates it instead of
/// offering to save it again as a new login.
pub(crate) fn save_tier(urls: &[String], rules: &[UrlRule], page: &Url) -> MatchQuality {
    urls.iter()
        .filter_map(|u| {
            let rule = match url_rule_of(rules, u) {
                UrlMatch::Never => UrlMatch::Subdomains,
                rule => rule,
            };
            same_login_host(u, rule, page).then(|| ruled_match(u, rule, page))
        })
        .max()
        .unwrap_or(MatchQuality::None)
        .min(MatchQuality::Host)
}

/// The canonical address a page names (`<link rel="canonical">`, read by the browser extension)
/// that a sign-in submitted on `page_url` may share its login with, as an origin
/// (`https://example.com`); `None` when it may not. Accepted only when both are `https`, both
/// hosts are domain names (not IP addresses) of the same registrable domain (eTLD+1, the Public
/// Suffix List: `alice.github.io` and `bob.github.io` are two sites), and the canonical host is
/// another host than the page's (`www.` or not). Whatever page script claims, another site is
/// never accepted: the page is only trusted to say which host of its own site is the main one.
pub fn canonical_save_origin(page_url: &str, canonical_url: &str) -> Option<String> {
    let page = Url::parse(page_url.trim()).ok()?;
    let canonical = Url::parse(canonical_url.trim()).ok()?;
    if page.scheme() != "https" || canonical.scheme() != "https" {
        return None;
    }
    let (Some(url::Host::Domain(page_host)), Some(url::Host::Domain(host))) =
        (page.host(), canonical.host())
    else {
        return None;
    };
    let (page_host, host) = (save_host(page_host), save_host(host));
    if page_host == host || !page_host.contains('.') || !host.contains('.') {
        return None;
    }
    match (
        registrable_domain_of_host(&page_host),
        registrable_domain_of_host(&host),
    ) {
        (Some(a), Some(b)) if a == b => Some(canonical.origin().ascii_serialization()),
        _ => None,
    }
}

/// A stored website entry read once for [`url_suggestion_tier`]-style matching against many pages
/// ([`crate::SearchIndex::for_url`], [`crate::KeptMatcher`]): only what the match needs (whether it
/// is https, its host and registrable domain), a fraction of a parsed [`Url`].
pub(crate) struct MatchUrl {
    https: bool,
    host: Box<str>,
    /// [`UrlMatch::Host`]: the same host only, on `port` when the entry names one.
    host_only: bool,
    port: Option<u16>,
    /// [`registrable_domain_of_host`] of `host`, when the host has a dot (a single label never
    /// matches another host by its domain).
    domain: Option<Box<str>>,
}

/// The page side of [`MatchUrl::tier`], read once per page.
pub(crate) struct MatchPage {
    /// http, or https.
    web: bool,
    plain_http: bool,
    local: bool,
    host: String,
    port: Option<u16>,
    domain: Option<String>,
}

impl MatchPage {
    pub(crate) fn of(page: &Url) -> MatchPage {
        let host = page.host_str().unwrap_or_default().to_ascii_lowercase();
        MatchPage {
            web: matches!(page.scheme(), "http" | "https"),
            plain_http: page.scheme() == "http",
            local: is_local(page),
            port: page.port_or_known_default(),
            domain: registrable_domain_of_host(&host),
            host,
        }
    }
}

impl MatchUrl {
    /// `None` for an entry that never matches a page (not http or https, no host, or
    /// [`UrlMatch::Never`]).
    pub(crate) fn parse(stored: &str, rule: UrlMatch) -> Option<MatchUrl> {
        if rule == UrlMatch::Never {
            return None;
        }
        let url = parse_loose(stored)?;
        if !matches!(url.scheme(), "http" | "https") {
            return None;
        }
        let host = url.host_str()?.to_ascii_lowercase();
        let domain = if host.contains('.') {
            registrable_domain_of_host(&host).map(String::into_boxed_str)
        } else {
            None
        };
        let host_only = rule == UrlMatch::Host;
        Some(MatchUrl {
            https: url.scheme() == "https",
            host: host.into_boxed_str(),
            host_only,
            port: url.port().filter(|_| host_only),
            domain,
        })
    }

    /// [`url_match`] capped at [`MatchQuality::Host`], as [`url_suggestion_tier`] reads it.
    pub(crate) fn tier(&self, page: &MatchPage) -> MatchQuality {
        if !page.web || (self.https && page.plain_http && !page.local) {
            return MatchQuality::None;
        }
        if *self.host == *page.host {
            if self.port.is_some_and(|port| page.port != Some(port)) {
                return MatchQuality::None;
            }
            return MatchQuality::Host;
        }
        if self.host_only {
            return MatchQuality::None;
        }
        match (&self.domain, &page.domain) {
            (Some(a), Some(b)) if **a == **b => MatchQuality::Domain,
            _ => MatchQuality::None,
        }
    }
}

/// The entries of `urls` that can match a page under their `rules`, read once.
pub(crate) fn match_urls(urls: &[String], rules: &[UrlRule]) -> Box<[MatchUrl]> {
    urls.iter()
        .filter_map(|u| MatchUrl::parse(u, url_rule_of(rules, u)))
        .collect()
}

/// [`url_suggestion_tier`] over entries read once ([`MatchUrl`]).
pub(crate) fn tier_of(urls: &[MatchUrl], page: &MatchPage) -> MatchQuality {
    urls.iter()
        .map(|u| u.tier(page))
        .max()
        .unwrap_or(MatchQuality::None)
}

pub(crate) fn urls_match(urls: &[String], rules: &[UrlRule], page: &Url) -> MatchQuality {
    urls.iter()
        .map(|u| ruled_match(u, url_rule_of(rules, u), page))
        .max()
        .unwrap_or(MatchQuality::None)
}

/// How a page's logins are ordered (`Vault::find_for_url`, `summaries_for_url`): the best match of
/// [`urls_match`], with a matching path ([`MatchQuality::Exact`]) ranked like the same host, so
/// usage decides between the logins of one host whatever path each was saved with (an imported
/// login keeps the sign-in page's path, one Passyble saved keeps only the origin). Another
/// subdomain of the site ([`MatchQuality::Domain`]) still ranks below.
pub(crate) fn url_suggestion_tier(urls: &[String], rules: &[UrlRule], page: &Url) -> MatchQuality {
    urls_match(urls, rules, page).min(MatchQuality::Host)
}

/// How an item's linked Android apps (or legacy `androidapp://` URLs) match `package`, signed with
/// `cert` (normalised, see [`normalize_cert`]) (`Vault::find_for_android_app`). Entries the user
/// hid ([`AndroidApp::never_show`], an `androidapp://` URL ruled [`UrlMatch::Never`]) never match.
pub(crate) fn android_app_match(
    apps: &[AndroidApp],
    urls: &[String],
    rules: &[UrlRule],
    package: &str,
    cert: Option<&str>,
) -> MatchQuality {
    let quality = |app: &AndroidApp| {
        if app.never_show || app.package != package {
            return MatchQuality::None;
        }
        match app.cert_sha256.as_deref().map(normalize_cert) {
            None => MatchQuality::Host,
            Some(stored) if cert == Some(stored.as_str()) => MatchQuality::Exact,
            Some(_) => MatchQuality::None,
        }
    };
    let linked = apps.iter().map(quality).max().unwrap_or(MatchQuality::None);
    let legacy = format!("androidapp://{package}");
    if linked > MatchQuality::None {
        linked
    } else if urls
        .iter()
        .any(|u| u.trim().eq_ignore_ascii_case(&legacy) && url_rule_of(rules, u) != UrlMatch::Never)
    {
        MatchQuality::Domain
    } else {
        MatchQuality::None
    }
}

fn is_local(url: &Url) -> bool {
    match url.host_str() {
        Some("localhost") => true,
        Some(h) => h
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback()),
        None => false,
    }
}

/// Normalises a certificate digest: lowercase hex without separators.
pub(crate) fn normalize_cert(cert: &str) -> String {
    cert.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(stored: &str, page: &str) -> MatchQuality {
        url_match(stored, &Url::parse(page).unwrap())
    }

    #[test]
    fn registrable_domains() {
        assert_eq!(
            registrable_domain("https://accounts.google.com/x".into()).as_deref(),
            Some("google.com")
        );
        assert_eq!(
            registrable_domain("foo.bar.co.uk".into()).as_deref(),
            Some("bar.co.uk")
        );
        assert_eq!(registrable_domain("co.uk".into()), None);
        assert_eq!(
            registrable_domain("http://localhost:8080".into()).as_deref(),
            Some("localhost")
        );
        assert_eq!(
            registrable_domain("192.168.1.1".into()).as_deref(),
            Some("192.168.1.1")
        );
        // github.io is a public suffix: user sites must not share credentials.
        assert_eq!(
            registrable_domain("alice.github.io".into()).as_deref(),
            Some("alice.github.io")
        );
    }

    fn same_host(stored: &str, page: &str) -> bool {
        same_login_host(stored, UrlMatch::Subdomains, &Url::parse(page).unwrap())
    }

    fn ruled(stored: &str, rule: UrlMatch, page: &str) -> MatchQuality {
        ruled_match(stored, rule, &Url::parse(page).unwrap())
    }

    #[test]
    fn subdomain_rule_is_the_match_of_entries_without_a_rule() {
        for (stored, page) in [
            ("https://example.com", "https://example.com/login"),
            ("https://example.com", "https://app.example.com/"),
            ("https://www.example.com", "https://example.com:8443/"),
            (
                "https://login.example.com/sso",
                "https://login.example.com/sso/x",
            ),
            ("https://example.com", "https://example.org/"),
            ("https://alice.github.io", "https://bob.github.io/"),
            ("https://bank.com", "http://bank.com/"),
        ] {
            assert_eq!(ruled(stored, UrlMatch::Subdomains, page), q(stored, page));
        }
        assert_eq!(
            ruled(
                "https://example.com",
                UrlMatch::Subdomains,
                "https://app.example.com/"
            ),
            MatchQuality::Domain
        );
    }

    #[test]
    fn host_rule_matches_only_its_host_and_port() {
        let host = |stored: &str, page: &str| ruled(stored, UrlMatch::Host, page);
        assert_eq!(
            host("https://example.com", "https://example.com/login"),
            MatchQuality::Host
        );
        assert_eq!(
            host("https://example.com/login", "https://example.com/login/x"),
            MatchQuality::Exact
        );
        assert_eq!(
            host("example.com", "https://EXAMPLE.com/"),
            MatchQuality::Host
        );
        // No subdomain, no parent, no `www.` variant.
        assert_eq!(
            host("https://example.com", "https://app.example.com/"),
            MatchQuality::None
        );
        assert_eq!(
            host("https://app.example.com", "https://example.com/"),
            MatchQuality::None
        );
        assert_eq!(
            host("https://www.example.com", "https://example.com/"),
            MatchQuality::None
        );
        // A port in the entry must be the page's; without one, any port.
        assert_eq!(
            host("https://example.com:8443", "https://example.com:8443/"),
            MatchQuality::Host
        );
        assert_eq!(
            host("https://example.com:8443", "https://example.com/"),
            MatchQuality::None
        );
        assert_eq!(
            host("https://example.com:8443", "https://example.com:9443/"),
            MatchQuality::None
        );
        assert_eq!(
            host("https://example.com", "https://example.com:8443/"),
            MatchQuality::Host
        );
        assert_eq!(
            host("https://example.com:443", "https://example.com/"),
            MatchQuality::Host
        );
        assert_eq!(
            host("http://localhost:3000", "http://localhost:3000/login"),
            MatchQuality::Host
        );
        assert_eq!(
            host("http://localhost:3000", "http://localhost:4000/"),
            MatchQuality::None
        );
        // Still never https to plain http.
        assert_eq!(
            host("https://bank.com", "http://bank.com/"),
            MatchQuality::None
        );
    }

    #[test]
    fn never_rule_matches_nothing() {
        for page in ["https://example.com/", "https://app.example.com/"] {
            assert_eq!(
                ruled("https://example.com", UrlMatch::Never, page),
                MatchQuality::None
            );
        }
        let rules = [UrlRule {
            url: "https://example.com".into(),
            rule: UrlMatch::Never,
        }];
        let urls = [
            "https://example.com".to_string(),
            "https://example.org".to_string(),
        ];
        let page = Url::parse("https://example.com/").unwrap();
        assert_eq!(
            url_suggestion_tier(&urls, &rules, &page),
            MatchQuality::None
        );
        assert_eq!(url_suggestion_tier(&urls, &[], &page), MatchQuality::Host);
        // A sign-in on the hidden entry's host still finds the login to update.
        assert_eq!(save_tier(&urls, &rules, &page), MatchQuality::Host);
    }

    #[test]
    fn save_tier_honours_the_host_rule() {
        let urls = ["https://www.example.com".to_string()];
        let host = [UrlRule {
            url: urls[0].clone(),
            rule: UrlMatch::Host,
        }];
        let bare = Url::parse("https://example.com/").unwrap();
        assert_eq!(save_tier(&urls, &[], &bare), MatchQuality::Domain);
        assert_eq!(save_tier(&urls, &host, &bare), MatchQuality::None);
        let www = Url::parse("https://www.example.com/login").unwrap();
        assert_eq!(save_tier(&urls, &host, &www), MatchQuality::Host);
        let other = Url::parse("https://app.example.com/").unwrap();
        assert_eq!(save_tier(&urls, &[], &other), MatchQuality::None);
    }

    #[test]
    fn hidden_android_apps_never_match() {
        let app = |never_show| AndroidApp {
            package: "com.example".into(),
            cert_sha256: None,
            never_show,
        };
        assert_eq!(
            android_app_match(&[app(false)], &[], &[], "com.example", None),
            MatchQuality::Host
        );
        assert_eq!(
            android_app_match(&[app(true)], &[], &[], "com.example", None),
            MatchQuality::None
        );
        let legacy = ["androidapp://com.example".to_string()];
        let never = [UrlRule {
            url: legacy[0].clone(),
            rule: UrlMatch::Never,
        }];
        assert_eq!(
            android_app_match(&[], &legacy, &[], "com.example", None),
            MatchQuality::Domain
        );
        assert_eq!(
            android_app_match(&[], &legacy, &never, "com.example", None),
            MatchQuality::None
        );
    }

    #[test]
    fn shared_hosting_sites_suggest_the_host_rule() {
        for url in [
            "https://alice.github.io",
            "shop.web.app",
            "https://my-app.herokuapp.com/login",
            "https://myblog.blogspot.com",
        ] {
            assert!(url_suggests_host_only(url.into()), "{url}");
        }
        for url in [
            "https://github.com",
            "https://accounts.google.com",
            "https://bbc.co.uk",
            "http://localhost:3000",
            "https://192.168.1.1",
            "",
            "androidapp://com.example",
        ] {
            assert!(!url_suggests_host_only(url.into()), "{url}");
        }
    }

    #[test]
    fn save_host_matching() {
        assert!(same_host(
            "https://example.com",
            "https://example.com/login"
        ));
        assert!(same_host("example.com", "https://EXAMPLE.com:8443/"));
        assert!(same_host(
            "https://app.example.com/sign-in",
            "https://app.example.com/"
        ));
        assert!(same_host("https://www.example.com", "https://example.com/"));
        assert!(same_host("https://example.com", "https://www.example.com/"));
        assert!(same_host(
            "https://www.app.example.com",
            "https://app.example.com/"
        ));
        assert!(!same_host(
            "https://example.com",
            "https://app.example.com/"
        ));
        assert!(!same_host(
            "https://www.example.com",
            "https://app.example.com/"
        ));
        assert!(!same_host(
            "https://app.example.com",
            "https://example.com/"
        ));
        assert!(!same_host(
            "https://a.example.com",
            "https://b.example.com/"
        ));
        assert!(!same_host("https://example.org", "https://example.com/"));
        assert!(!same_host(
            "https://example.com",
            "https://example.com.evil.io/"
        ));
        assert!(!same_host("https://bank.com", "http://bank.com/"));
        assert!(!same_host("androidapp://com.foo", "https://foo.com/"));
        assert!(same_host(
            "http://localhost:3000",
            "http://localhost:3000/login"
        ));
        assert!(!same_host("https://www.com", "https://com/"));
    }

    #[test]
    fn canonical_hosts_of_the_same_site_only() {
        let c = |page: &str, canonical: &str| canonical_save_origin(page, canonical);
        assert_eq!(
            c(
                "https://app.example.com/login",
                "https://example.com/welcome"
            )
            .as_deref(),
            Some("https://example.com")
        );
        assert_eq!(
            c("https://app.example.com/", "https://WWW.Example.com:8443/x").as_deref(),
            Some("https://www.example.com:8443")
        );
        assert_eq!(
            c("https://a.example.co.uk/", "https://b.example.co.uk/").as_deref(),
            Some("https://b.example.co.uk")
        );
        assert_eq!(c("https://evil.com/login", "https://bank.com/"), None);
        assert_eq!(c("https://bank.com.evil.io/", "https://bank.com/"), None);
        assert_eq!(
            c("https://alice.github.io/", "https://bob.github.io/"),
            None
        );
        assert_eq!(c("https://alice.github.io/", "https://github.io/"), None);
        assert_eq!(c("http://app.example.com/", "https://example.com/"), None);
        assert_eq!(c("https://app.example.com/", "http://example.com/"), None);
        assert_eq!(c("https://example.com/a", "https://example.com/b"), None);
        assert_eq!(c("https://www.example.com/", "https://example.com/"), None);
        assert_eq!(c("https://10.0.0.1/", "https://10.0.0.2/"), None);
        assert_eq!(c("https://intranet/", "https://wiki/"), None);
        assert_eq!(c("https://app.example.com/", ""), None);
        assert_eq!(c("https://app.example.com/", "/relative"), None);
        assert_eq!(c("https://app.example.com/", "javascript:alert(1)"), None);
    }

    #[test]
    fn url_matching() {
        assert_eq!(
            q("github.com", "https://github.com/login"),
            MatchQuality::Host
        );
        assert_eq!(
            q("https://github.com/login", "https://github.com/login?x=1"),
            MatchQuality::Exact
        );
        assert_eq!(
            q("https://www.github.com", "https://github.com/"),
            MatchQuality::Domain
        );
        assert_eq!(
            q("https://github.com", "https://github.com.evil.io/"),
            MatchQuality::None
        );
        assert_eq!(
            q("https://alice.github.io", "https://mallory.github.io/"),
            MatchQuality::None
        );
        assert_eq!(
            q("https://bank.com", "http://bank.com/"),
            MatchQuality::None
        );
        assert_eq!(
            q("http://localhost:3000", "http://localhost:3000/login"),
            MatchQuality::Host
        );
        assert_eq!(
            q("androidapp://com.foo", "https://foo.com"),
            MatchQuality::None
        );
    }
}
