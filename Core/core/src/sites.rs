//! Offline lists of the websites that offer two-factor sign-in and passkeys, for Password health,
//! compiled in from `core/data/` (refreshed with `scripts/update-site-security.mjs`). A host
//! matches itself, then each parent down to the registrable domain, then the shortest entry of the
//! same registrable domain. IP addresses and single-label hosts never match.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::matching::{parse_loose, registrable_domain_of_host};

const TWO_FACTOR_DATA: &str = include_str!("../data/2fa-directory.tsv");
const PASSKEY_DATA: &str = include_str!("../data/passkeys-directory.tsv");

/// What the offline directories know about a website ([`site_security`]).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SiteSecurity {
    /// The ways the site offers a second step at sign-in, strongest first: `totp` (an
    /// authenticator app, which Passyble can be), `security_key`, `sms`, `call`, `email`, `app`
    /// (the site's own app), `device` (the site's own code device). Empty: none known.
    pub two_factor: Vec<String>,
    /// How to turn it on (an `https://` link), `""` if the directory has none.
    pub two_factor_docs: String,
    /// Passkey support: `passwordless` (sign in with a passkey instead of the password) and/or
    /// `mfa` (a passkey as the second step). Empty: none known.
    pub passkeys: Vec<String>,
    /// How to add a passkey (an `https://` link), `""` if the directory has none.
    pub passkey_docs: String,
}

/// One directory entry: its letter codes and its documentation link (without `https://`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Entry<'a> {
    pub codes: &'a str,
    pub docs: &'a str,
}

/// A parsed directory: entries by domain, and for each registrable domain its shortest entry.
#[derive(Debug, Default)]
pub(crate) struct Directory<'a> {
    by_host: HashMap<&'a str, Entry<'a>>,
    by_domain: HashMap<String, &'a str>,
}

impl<'a> Directory<'a> {
    /// Parses `domain TAB codes TAB docs` lines; comments, blank and malformed lines are skipped,
    /// and the first line wins for a domain listed twice.
    pub(crate) fn parse(text: &'a str) -> Directory<'a> {
        let mut dir = Directory::default();
        for line in text.lines() {
            let line = line.trim_end_matches('\r');
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split('\t');
            let (Some(domain), Some(codes)) = (parts.next(), parts.next()) else {
                continue;
            };
            let docs = parts.next().unwrap_or("");
            if domain.is_empty()
                || codes.is_empty()
                || !domain.contains('.')
                || domain.bytes().any(|b| b.is_ascii_uppercase() || b == b' ')
                || dir.by_host.contains_key(domain)
            {
                continue;
            }
            dir.by_host.insert(domain, Entry { codes, docs });
            if let Some(reg) = registrable_domain_of_host(domain) {
                let slot = dir.by_domain.entry(reg).or_insert(domain);
                if (domain.len(), domain) < (slot.len(), *slot) {
                    *slot = domain;
                }
            }
        }
        dir
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_host.len()
    }

    /// The entry for `host` (lower case, see the module docs).
    pub(crate) fn lookup(&self, host: &str) -> Option<Entry<'a>> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') || !host.contains('.')
        {
            return None;
        }
        let reg = registrable_domain_of_host(&host)?;
        let mut candidate = host.as_str();
        loop {
            if let Some(entry) = self.by_host.get(candidate) {
                return Some(*entry);
            }
            if candidate.len() <= reg.len() {
                break;
            }
            match candidate.split_once('.') {
                Some((_, parent)) => candidate = parent,
                None => break,
            }
        }
        self.by_domain
            .get(&reg)
            .and_then(|key| self.by_host.get(key))
            .copied()
    }
}

fn two_factor_directory() -> &'static Directory<'static> {
    static DIR: OnceLock<Directory<'static>> = OnceLock::new();
    DIR.get_or_init(|| Directory::parse(TWO_FACTOR_DATA))
}

fn passkey_directory() -> &'static Directory<'static> {
    static DIR: OnceLock<Directory<'static>> = OnceLock::new();
    DIR.get_or_init(|| Directory::parse(PASSKEY_DATA))
}

/// The two-factor method names of letter codes (`t` → `totp`, …), strongest first.
pub(crate) fn two_factor_methods(codes: &str) -> Vec<String> {
    [
        ('t', "totp"),
        ('u', "security_key"),
        ('s', "sms"),
        ('c', "call"),
        ('e', "email"),
        ('a', "app"),
        ('h', "device"),
    ]
    .iter()
    .filter(|(c, _)| codes.contains(*c))
    .map(|(_, name)| name.to_string())
    .collect()
}

/// The passkey modes of letter codes (`p` → `passwordless`, `m` → `mfa`).
pub(crate) fn passkey_modes(codes: &str) -> Vec<String> {
    [('p', "passwordless"), ('m', "mfa")]
        .iter()
        .filter(|(c, _)| codes.contains(*c))
        .map(|(_, name)| name.to_string())
        .collect()
}

/// A stored documentation link as a full address (`https://` added unless it says `http://`).
pub(crate) fn docs_url(docs: &str) -> String {
    if docs.is_empty() || docs.starts_with("http://") || docs.starts_with("https://") {
        docs.to_string()
    } else {
        format!("https://{docs}")
    }
}

/// The host of a website entry (`https://…`, `http://…` or a bare host), lower case.
pub(crate) fn web_host(entry: &str) -> Option<String> {
    if !crate::summary::is_web_entry(entry) {
        return None;
    }
    let url = parse_loose(entry)?;
    url.host_str()
        .filter(|h| !h.is_empty())
        .map(str::to_ascii_lowercase)
}

/// The two-factor entry for the first of `urls` the directory knows.
pub(crate) fn two_factor_for(urls: &[String]) -> Option<Entry<'static>> {
    urls.iter()
        .filter_map(|u| web_host(u))
        .find_map(|h| two_factor_directory().lookup(&h))
}

/// The passkey entry for the first of `urls` the directory knows.
pub(crate) fn passkeys_for(urls: &[String]) -> Option<Entry<'static>> {
    urls.iter()
        .filter_map(|u| web_host(u))
        .find_map(|h| passkey_directory().lookup(&h))
}

/// What the bundled directories know about the website `url` (a URL or bare host): two-factor methods
/// and passkey support. `None` if neither lists it.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn site_security(url: String) -> Option<SiteSecurity> {
    let urls = [url];
    let tfa = two_factor_for(&urls);
    let pk = passkeys_for(&urls);
    if tfa.is_none() && pk.is_none() {
        return None;
    }
    Some(SiteSecurity {
        two_factor: tfa.map(|e| two_factor_methods(e.codes)).unwrap_or_default(),
        two_factor_docs: tfa.map(|e| docs_url(e.docs)).unwrap_or_default(),
        passkeys: pk.map(|e| passkey_modes(e.codes)).unwrap_or_default(),
        passkey_docs: pk.map(|e| docs_url(e.docs)).unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "# comment\n\
        example.com\tts\twww.example.com/2fa\n\
        aws.example.com\ttu\taws.example.com/mfa\n\
        mail.sample.org\tt\tsample.org/a\n\
        drive.sample.org\ts\tsample.org/b\n\
        bbc.co.uk\te\t\n\
        UPPER.com\tt\tx\n\
        nodot\tt\tx\n\
        broken line\n\
        example.com\th\tduplicate\n\
        \n";

    #[test]
    fn the_directory_parses_and_skips_bad_lines() {
        let dir = Directory::parse(SAMPLE);
        assert_eq!(dir.len(), 5);
        assert_eq!(
            dir.lookup("example.com"),
            Some(Entry {
                codes: "ts",
                docs: "www.example.com/2fa"
            })
        );
        assert_eq!(dir.lookup("bbc.co.uk").unwrap().docs, "");
        assert!(dir.lookup("upper.com").is_none());
    }

    #[test]
    fn matching_walks_up_to_the_registrable_domain() {
        let dir = Directory::parse(SAMPLE);
        assert_eq!(dir.lookup("www.example.com").unwrap().codes, "ts");
        assert_eq!(dir.lookup("WWW.Example.COM.").unwrap().codes, "ts");
        assert_eq!(dir.lookup("signin.aws.example.com").unwrap().codes, "tu");
        assert_eq!(dir.lookup("aws.example.com").unwrap().codes, "tu");
        // Only subdomain entries: the registrable domain falls back to the shortest one
        // (`mail.sample.org`, before `drive.sample.org`).
        assert_eq!(dir.lookup("sample.org").unwrap().docs, "sample.org/a");
        assert_eq!(dir.lookup("www.sample.org").unwrap().docs, "sample.org/a");
        assert_eq!(dir.lookup("drive.sample.org").unwrap().docs, "sample.org/b");
        assert_eq!(dir.lookup("mail.sample.org").unwrap().docs, "sample.org/a");
        // Public suffixes stay apart: `co.uk` is not a site, `news.co.uk` is not `bbc.co.uk`.
        assert_eq!(dir.lookup("www.bbc.co.uk").unwrap().codes, "e");
        assert!(dir.lookup("news.co.uk").is_none());
        assert!(dir.lookup("co.uk").is_none());
        assert!(dir.lookup("example.com.evil.net").is_none());
        assert!(dir.lookup("notexample.com").is_none());
        assert!(dir.lookup("192.168.1.1").is_none());
        assert!(dir.lookup("localhost").is_none());
    }

    #[test]
    fn codes_become_method_names() {
        assert_eq!(two_factor_methods("tusceah").len(), 7);
        assert_eq!(two_factor_methods("se"), ["sms", "email"]);
        assert_eq!(two_factor_methods("ut"), ["totp", "security_key"]);
        assert_eq!(passkey_modes("pm"), ["passwordless", "mfa"]);
        assert_eq!(passkey_modes("m"), ["mfa"]);
        assert_eq!(docs_url("a.example/x"), "https://a.example/x");
        assert_eq!(docs_url("http://a.example/x"), "http://a.example/x");
        assert_eq!(docs_url(""), "");
    }

    #[test]
    fn the_bundled_directories_load() {
        let tfa = two_factor_directory();
        let pk = passkey_directory();
        assert!(tfa.len() > 1000, "{}", tfa.len());
        assert!(pk.len() > 100, "{}", pk.len());
        let lines = |text: &str| {
            text.lines()
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .count()
        };
        assert_eq!(tfa.len(), lines(TWO_FACTOR_DATA));
        assert_eq!(pk.len(), lines(PASSKEY_DATA));
        for text in [TWO_FACTOR_DATA, PASSKEY_DATA] {
            for line in text.lines().filter(|l| !l.starts_with('#')) {
                let fields: Vec<&str> = line.split('\t').collect();
                assert_eq!(fields.len(), 3, "{line}");
                assert!(fields[1].chars().all(|c| "tusceahpm".contains(c)), "{line}");
                assert!(fields[2].is_ascii() && !fields[2].contains(' '), "{line}");
            }
        }
        let github = site_security("https://github.com/login".into()).unwrap();
        assert!(github.two_factor.contains(&"totp".to_string()));
        assert!(github.two_factor_docs.starts_with("https://"));
        assert!(!github.passkeys.is_empty());
        let google = site_security("accounts.google.com".into()).unwrap();
        assert!(google.two_factor.contains(&"totp".to_string()));
        assert!(site_security("https://intranet.invalid".into()).is_none());
        assert!(site_security("http://192.168.0.1".into()).is_none());
        assert!(site_security("windows:notepad.exe".into()).is_none());
    }
}
