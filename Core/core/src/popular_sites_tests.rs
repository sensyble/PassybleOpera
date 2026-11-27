use super::*;

fn suggest(query: &str, limit: u32) -> Vec<(String, String)> {
    site_suggestions(query.into(), limit)
        .into_iter()
        .map(|s| (s.name, s.domain))
        .collect()
}

fn first(query: &str) -> Option<(String, String)> {
    suggest(query, 5).into_iter().next()
}

fn pair(name: &str, domain: &str) -> Option<(String, String)> {
    Some((name.to_string(), domain.to_string()))
}

fn name_for(site: &str) -> Option<String> {
    site_for_domain(site.into())
}

#[test]
fn the_list_is_large_and_clean() {
    let sites = sites();
    assert!(
        (1000..=2000).contains(&sites.list.len()),
        "{} sites",
        sites.list.len()
    );
    let mut names = std::collections::HashSet::new();
    let mut domains = std::collections::HashSet::new();
    let mut problems = Vec::new();
    for site in &sites.list {
        let name = site.names[0].text;
        if !names.insert(name.to_lowercase()) {
            problems.push(format!("{name}: listed twice"));
        }
        if site.names[0].compact.is_empty() {
            problems.push(format!("{name}: no letters"));
        }
        for other in &site.names {
            if other.text.chars().any(|c| matches!(c as u32, 0x2013 | 0x2014)) {
                problems.push(format!("{}: a long dash", other.text));
            }
        }
        for &domain in &site.domains {
            if !domains.insert(domain) {
                problems.push(format!("{domain}: listed twice"));
            }
            let host_like = domain.contains('.')
                && domain
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-.".contains(&b));
            if !host_like {
                problems.push(format!("{name}: {domain} is not a lower-case host"));
                continue;
            }
            // A site of its own, not a public suffix (`co.uk`) or a hosting platform's
            // (`github.io`), whose users' sites would all get this name.
            match registrable_domain_of_host(domain) {
                None => problems.push(format!("{name}: {domain} is a public suffix")),
                Some(reg) if domain != reg && !domain.ends_with(&format!(".{reg}")) => {
                    problems.push(format!("{name}: {domain} is not under {reg}"))
                }
                Some(_) => {}
            }
            if sites.for_host(domain).map(|s| s.names[0].text) != Some(name) {
                problems.push(format!("{name}: {domain} names another site"));
            }
        }
    }
    for package in sites.by_package.keys() {
        if !package.contains('.') || package.contains([' ', '|', '/']) {
            problems.push(format!("{package}: not a package name"));
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
}

#[test]
fn names_suggest_their_website() {
    assert_eq!(first("Netflix"), pair("Netflix", "netflix.com"));
    assert_eq!(first("netf"), pair("Netflix", "netflix.com"));
    assert_eq!(first("github"), pair("GitHub", "github.com"));
    assert_eq!(
        first("Bank of Am"),
        pair("Bank of America", "bankofamerica.com")
    );
    assert_eq!(
        first("bankofamerica"),
        pair("Bank of America", "bankofamerica.com")
    );
    assert_eq!(first("h&m"), pair("H&M", "hm.com"));
    assert_eq!(first("AT&T"), pair("AT&T", "att.com"));
    assert_eq!(first("x"), pair("X", "x.com"));
}

#[test]
fn case_accents_and_punctuation_are_ignored() {
    assert_eq!(first("NETFLIX"), pair("Netflix", "netflix.com"));
    assert_eq!(
        first("societe gen"),
        pair("Société Générale", "societegenerale.com")
    );
    assert_eq!(
        first("Société"),
        pair("Société Générale", "societegenerale.com")
    );
    assert_eq!(first("el pais"), pair("El País", "elpais.com"));
    assert_eq!(first("chickfila"), pair("Chick-fil-A", "chick-fil-a.com"));
    assert_eq!(first("  spotify  "), pair("Spotify", "spotify.com"));
}

#[test]
fn other_names_suggest_the_site() {
    assert_eq!(first("Twitter"), pair("Twitter", "x.com"));
    assert_eq!(first("gmail"), pair("Gmail", "google.com"));
    assert_eq!(first("hotmail"), pair("Hotmail", "outlook.com"));
    assert_eq!(first("fortnite"), pair("Fortnite", "epicgames.com"));
}

#[test]
fn websites_suggest_their_name() {
    assert_eq!(first("amazon.de"), pair("Amazon", "amazon.de"));
    assert_eq!(first("amazon.co"), pair("Amazon", "amazon.com"));
    assert_eq!(first("amazon.co.u"), pair("Amazon", "amazon.co.uk"));
    assert_eq!(
        first("https://www.netflix.com/browse"),
        pair("Netflix", "netflix.com")
    );
    assert_eq!(first("www.githu"), pair("GitHub", "github.com"));
    assert_eq!(
        first("drive.google"),
        pair("Google Drive", "drive.google.com")
    );
    assert_eq!(first("twitter.com"), pair("X", "twitter.com"));
}

#[test]
fn whole_matches_come_first_then_popular_sites() {
    // `Amazon` itself before the Amazon services and sites named "Amazon...".
    let amazon = suggest("amazon", 10);
    assert_eq!(amazon[0], ("Amazon".to_string(), "amazon.com".to_string()));
    assert!(amazon.len() > 3);
    // Name prefixes before later words.
    let chase = suggest("chase", 10);
    assert_eq!(chase[0].0, "Chase");
    assert!(chase.iter().any(|(name, _)| name == "Chase UK"));
    assert_eq!(suggest("goo", 3)[0].0, "Google");
    // Later words: "america" finds Bank of America, after sites whose name starts with it.
    let america = suggest("america", 20);
    let bofa = america.iter().position(|(n, _)| n == "Bank of America");
    let amex = america.iter().position(|(n, _)| n == "American Express");
    assert!(amex.unwrap() < bofa.unwrap(), "{america:?}");
}

#[test]
fn limits_and_empty_queries() {
    assert!(suggest("", 10).is_empty());
    assert!(suggest("   ", 10).is_empty());
    assert!(suggest("!!", 10).is_empty());
    assert!(suggest("netflix", 0).is_empty());
    assert_eq!(suggest("a", 3).len(), 3);
    assert_eq!(
        suggest("a", 1000).len(),
        MAX_SITE_SUGGESTIONS as usize,
        "capped"
    );
    assert!(suggest(&"a".repeat(MAX_QUERY_CHARS + 1), 10).is_empty());
    assert!(suggest("zzzzqqqq", 10).is_empty());
    // One suggestion per site.
    let amazon = suggest("amazon", 50);
    let mains: Vec<_> = amazon.iter().filter(|(n, _)| n == "Amazon").collect();
    assert_eq!(mains.len(), 1, "{amazon:?}");
}

#[test]
fn a_website_gets_its_sites_name() {
    assert_eq!(name_for("https://github.com/login"), Some("GitHub".into()));
    assert_eq!(name_for("www.netflix.com"), Some("Netflix".into()));
    assert_eq!(name_for("NETFLIX.COM"), Some("Netflix".into()));
    assert_eq!(
        name_for("https://www.amazon.co.uk/ap/signin"),
        Some("Amazon".into())
    );
    assert_eq!(name_for("signin.aws.amazon.com"), Some("AWS".into()));
    assert_eq!(
        name_for("https://mail.google.com/mail/u/0"),
        Some("Google".into())
    );
    assert_eq!(name_for("drive.google.com"), Some("Google Drive".into()));
    assert_eq!(
        name_for("login.microsoftonline.com"),
        Some("Microsoft".into())
    );
    assert_eq!(
        name_for("https://outlook.live.com/mail"),
        Some("Outlook".into())
    );
    assert_eq!(name_for("acme.atlassian.net"), Some("Atlassian".into()));
    assert_eq!(name_for("twitter.com"), Some("X".into()));
}

#[test]
fn unknown_and_shared_sites_get_no_name() {
    assert_eq!(name_for("example.com"), None);
    assert_eq!(
        name_for("alice.github.io"),
        None,
        "github.io is a public suffix"
    );
    assert_eq!(name_for("netflix.com.example.net"), None);
    assert_eq!(name_for("notnetflix.com"), None);
    assert_eq!(name_for("localhost"), None);
    assert_eq!(name_for("192.168.1.1"), None);
    assert_eq!(name_for("co.uk"), None);
    assert_eq!(name_for(""), None);
}

#[test]
fn android_apps_find_their_site() {
    assert_eq!(
        site_for_android_app("com.netflix.mediaclient".into()),
        Some(SiteSuggestion {
            name: "Netflix".into(),
            domain: "netflix.com".into()
        })
    );
    assert_eq!(
        site_for_android_app("com.twitter.android".into()).map(|s| s.name),
        Some("X".into())
    );
    assert_eq!(site_for_android_app("com.example.unknown".into()), None);
    assert_eq!(site_for_android_app(String::new()), None);
}

#[test]
fn the_parser_skips_bad_lines() {
    let sites = Sites::parse(
        "# comment\n\n|nodomain.com\nNo domain|\nFirst|one.com,two.com|com.one.app|Uno\r\nSecond|two.com,three.com|com.one.app\n",
    );
    assert_eq!(sites.list.len(), 2);
    assert_eq!(
        sites.for_host("two.com").map(|s| s.names[0].text),
        Some("First")
    );
    assert_eq!(
        sites.for_host("three.com").map(|s| s.names[0].text),
        Some("Second")
    );
    assert_eq!(sites.by_package.get("com.one.app"), Some(&0));
    assert_eq!(sites.list[0].names[1].text, "Uno");
}

#[test]
fn fast_enough_to_run_on_every_key() {
    let started = std::time::Instant::now();
    for query in ["a", "go", "bank of", "amazon.co", "société", "zzzz"] {
        site_suggestions(query.into(), 8);
    }
    // Generous for debug builds; a release build answers in well under a millisecond.
    assert!(
        started.elapsed().as_millis() < 500,
        "{:?}",
        started.elapsed()
    );
}
