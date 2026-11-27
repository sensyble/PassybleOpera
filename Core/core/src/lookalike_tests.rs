use super::*;
use crate::model::{AndroidApp, Item};

fn sites(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// The reason `page` looks like one of `known`, `None` if it doesn't.
fn check(page: &str, known: &[&str]) -> Option<LookalikeReason> {
    lookalike_of(page.into(), sites(known), Vec::new()).map(|l| l.reason)
}

/// The user's sites in the examples below.
const VAULT: &[&str] = &[
    "https://www.paypal.com/signin",
    "https://accounts.google.com",
    "https://www.apple.com",
    "https://login.microsoftonline.com",
    "https://www.microsoft.com",
    "https://github.com/login",
    "https://www.amazon.com",
    "https://www.facebook.com",
    "https://secure.chase.com",
    "https://www.bbc.co.uk",
    "https://www.linkedin.com",
    "https://onlinebanking.wellsfargo.com",
    "https://alice.github.io",
];

#[test]
fn homographs_in_other_alphabets() {
    // Cyrillic а in paypal (the classic IDN attack), whole-Cyrillic "аррlе" (а, р, р and
    // palochka ӏ), Greek ο in google.
    for page in [
        "https://pаypal.com/signin",
        "https://www.xn--pypal-4ve.com/",
        "https://аррӏе.com",
        "https://gοοgle.com",
        "https://micrоsoft.com",
    ] {
        assert_eq!(check(page, VAULT), Some(LookalikeReason::Homograph), "{page}");
    }
    let found = lookalike_of("https://pаypal.com/".into(), sites(VAULT), Vec::new()).unwrap();
    assert_eq!(found.domain, "paypal.com");
    // The page as the browser has it: the xn-- form shows the difference.
    assert_eq!(found.host, "xn--pypal-4ve.com");
}

#[test]
fn homographs_in_ascii() {
    for page in [
        "https://paypa1.com",
        "https://g00gle.com",
        "https://rnicrosoft.com",
        "https://www.arnazon.com",
        "https://linkedln.com",
    ] {
        let reason = check(page, VAULT);
        assert!(
            matches!(
                reason,
                Some(LookalikeReason::Homograph) | Some(LookalikeReason::Typo)
            ),
            "{page}: {reason:?}"
        );
    }
    assert_eq!(check("paypa1.com", VAULT), Some(LookalikeReason::Homograph));
    assert_eq!(check("rnicrosoft.com", VAULT), Some(LookalikeReason::Homograph));
}

#[test]
fn accents_and_mixed_scripts() {
    assert_eq!(check("https://pàypal.com", VAULT), Some(LookalikeReason::Homograph));
    assert_eq!(check("https://amazön.com", VAULT), Some(LookalikeReason::Homograph));
    // Mixed script and one more letter changed: still a homograph.
    assert_eq!(check("https://pаypai.com", VAULT), Some(LookalikeReason::Homograph));
    assert!(mixed_script("pаypal"));
    assert!(!mixed_script("paypal"));
    assert!(!mixed_script("пример"));
    assert!(!mixed_script("bücher"));
}

#[test]
fn typos() {
    for page in [
        "https://paypall.com",   // added
        "https://paypl.com",     // missing
        "https://pyapal.com",    // swapped
        "https://paypai.com",    // changed
        "https://pay-pal.com",   // hyphen added
        "https://faceboook.com", // doubled
        "https://amazom.de",     // other suffix
        "https://micosoft.com",
        "https://wellsfarqo.com",
        "https://wellsfagro.com",
        "https://wellfsarg0.com", // two changes on a long name
    ] {
        assert_eq!(check(page, VAULT), Some(LookalikeReason::Typo), "{page}");
    }
}

#[test]
fn the_domain_in_a_subdomain_or_path() {
    for page in [
        "https://paypal.com.account-verify.net/signin",
        "https://www.paypal.com.example.ru",
        "https://paypal-com.example.net",
        "https://paypal.com-secure.net",
        "https://login.microsoftonline.com.evil.example",
    ] {
        assert_eq!(
            check(page, VAULT),
            Some(LookalikeReason::DomainInSubdomain),
            "{page}"
        );
    }
    for page in [
        "https://example.net/paypal.com/signin",
        "https://sites.example.org/www.paypal.com",
        "https://example.net/secure/paypal.com-login.html",
        "https://example.net/%70aypal.com/", // percent-encoded
    ] {
        assert_eq!(check(page, VAULT), Some(LookalikeReason::DomainInPath), "{page}");
    }
}

#[test]
fn the_name_with_other_words() {
    assert_eq!(
        check("https://paypal-login.com", VAULT),
        Some(LookalikeReason::NameInDomain)
    );
    assert_eq!(
        check("https://secure-chase-alerts.com", VAULT),
        Some(LookalikeReason::NameInDomain)
    );
    assert_eq!(
        check("https://apple-id-support.net", VAULT),
        Some(LookalikeReason::NameInDomain)
    );
}

#[test]
fn the_strongest_reason_wins() {
    // A homograph name and paypal.com in front: the homograph is named.
    assert_eq!(
        check("https://paypal.com.paypa1.net", VAULT),
        Some(LookalikeReason::Homograph)
    );
    // paypal.com in front of a name that is also a typo of it: the address trick is named.
    assert_eq!(
        check("https://paypal.com.paypall.net", VAULT),
        Some(LookalikeReason::DomainInSubdomain)
    );
    // A homograph of one site beats a typo of another listed before it.
    let found = lookalike_of(
        "https://g00gle.com".into(),
        sites(&["https://goggle.com", "https://google.com"]),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(found.domain, "google.com");
    assert_eq!(found.reason, LookalikeReason::Homograph);
    // The same reason for two sites: the first listed.
    let found = lookalike_of(
        "https://paypl.com".into(),
        sites(&["https://paypa.com", "https://paypal.com"]),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(found.domain, "paypa.com");
}

#[test]
fn never_the_site_itself_or_its_subdomains() {
    for page in [
        "https://www.paypal.com",
        "https://paypal.com/signin",
        "https://www.paypal.com/paypal.com", // the site's own path
        "https://checkout.paypal.com",
        "https://myaccount.google.com",
        "https://mail.google.com",
        "https://www.microsoft.com",
        "https://account.microsoft.com",
        "http://github.com",
        "https://bbc.co.uk",
        "https://alice.github.io/blog",
    ] {
        assert_eq!(check(page, VAULT), None, "{page}");
    }
}

#[test]
fn no_false_alarms_for_other_real_sites() {
    for page in [
        // The same name under another suffix: a country site.
        "https://www.amazon.de",
        "https://amazon.co.uk",
        "https://www.google.fr",
        "https://www.paypal.me",
        "https://www.bbc.com",
        // Other people's pages on a shared host (a public suffix): not alice.github.io.
        "https://bob.github.io",
        // Short names are left to the exact match: bbc and bbq are both real.
        "https://bbq.co.uk",
        // Different enough.
        "https://gitlab.com",
        "https://chess.com",
        "https://apply.example.com",
        "https://www.microsoftstore.example",
        "https://applebees.com",
        "https://googleusercontent.com",
        "https://wikipedia.org",
        "https://example.com/news/paypalcom-review",
        // A query string is not the path: sign-in pages carry return addresses there.
        "https://auth.example.com/login?continue=https://www.paypal.com/",
        // IP addresses, single-label hosts, suffixes, junk.
        "http://192.168.1.1/",
        "http://[::1]:8080/",
        "http://localhost:3000",
        "https://co.uk",
        "",
        "not a url",
        "windows:paypal.exe",
    ] {
        assert_eq!(check(page, VAULT), None, "{page}");
    }
}

#[test]
fn sites_the_user_has_or_linked_are_never_lookalikes() {
    // paypa1.com would look like paypal.com, but the user has a login for it too.
    assert_eq!(
        lookalike_of(
            "https://paypa1.com".into(),
            sites(&["https://paypal.com"]),
            sites(&["https://www.paypa1.com"]),
        ),
        None
    );
    // Linked to the same login.
    assert_eq!(
        check("https://paypa1.com", &["https://paypal.com", "paypa1.com"]),
        None
    );
    // A subdomain of a known site.
    assert_eq!(
        lookalike_of(
            "https://login.paypa1.com".into(),
            sites(&["https://paypal.com"]),
            sites(&["paypa1.com"]),
        ),
        None
    );
}

#[test]
fn android_apps() {
    // An app whose package reads as a lookalike of the login's site.
    let found = lookalike_of(
        "androidapp://com.paypa1.android".into(),
        sites(&["https://www.paypal.com"]),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(found.reason, LookalikeReason::Homograph);
    assert_eq!(found.domain, "paypal.com");
    assert_eq!(found.host, "com.paypa1.android");
    // The site's own app (by its package), and a linked app, aren't.
    assert_eq!(check("androidapp://com.paypal.android.p2pmobile", VAULT), None);
    assert_eq!(
        check(
            "androidapp://com.paypa1.wallet",
            &["https://paypal.com", "androidapp://com.paypa1.wallet"]
        ),
        None
    );
    assert_eq!(check("androidapp://nodots", VAULT), None);
}

#[test]
fn international_sites_of_the_user() {
    // The user's own site has an international name; its ASCII twin looks like it.
    let found = lookalike_of(
        "https://bucher.de".into(),
        sites(&["https://bücher.de"]),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(found.domain, "bücher.de");
    assert_eq!(found.reason, LookalikeReason::Homograph);
    assert_eq!(check("https://www.bücher.de", &["https://bücher.de"]), None);
}

#[test]
fn skeletons() {
    let s = |name: &str| skeleton(name).into_iter().collect::<String>();
    assert_eq!(s("pаypal"), "paypal");
    assert_eq!(s("rnicrosoft"), "microsoft");
    assert_eq!(s("vvikipedia"), "wikipedia");
    assert_eq!(s("g00gle"), "google");
    assert_eq!(s("straße"), "strasse");
    assert_eq!(s("PayPal"), "paypal");
}

#[test]
fn edit_distance() {
    let d = |a: &str, b: &str, max| {
        distance(
            &a.chars().collect::<Vec<_>>(),
            &b.chars().collect::<Vec<_>>(),
            max,
        )
    };
    assert_eq!(d("paypal", "paypal", 2), 0);
    assert_eq!(d("paypal", "pyapal", 2), 1);
    assert_eq!(d("paypal", "paypall", 2), 1);
    assert_eq!(d("paypal", "paypl", 2), 1);
    assert_eq!(d("paypal", "pqypql", 2), 2);
    assert_eq!(d("paypal", "google", 2), 3);
    assert_eq!(d("ab", "abcdef", 2), 3);
    assert_eq!(d("", "ab", 2), 2);
}

#[test]
fn boundaries() {
    let dots = |c: char| c == '.' || c == '-';
    assert!(contains_at_boundary("paypal.com.x.net", "paypal.com", dots));
    assert!(contains_at_boundary("a.paypal.com-x.net", "paypal.com", dots));
    assert!(!contains_at_boundary("mypaypal.com.x.net", "paypal.com", dots));
    assert!(!contains_at_boundary("paypal.community.net", "paypal.com", dots));
    assert!(contains_at_boundary("xpaypal.com.paypal.com.y", "paypal.com", dots));
}

#[test]
fn fast_enough_for_every_page() {
    // A few thousand logins, against a page that looks like none of them (the slowest case:
    // every site is looked at).
    let known: Vec<String> = (0..5000)
        .map(|i| format!("https://login.site{i}example.com/path"))
        .collect();
    let start = std::time::Instant::now();
    for _ in 0..3 {
        assert_eq!(
            lookalike_of(
                "https://www.unrelated-page.example.org/a/b".into(),
                known.clone(),
                Vec::new()
            ),
            None
        );
    }
    let each = start.elapsed() / 3;
    // Generous for an unoptimised test build on a busy machine; a release build is far faster.
    assert!(each.as_millis() < 500, "{each:?}");
}

fn vault() -> std::sync::Arc<crate::Vault> {
    crate::Vault::create_with_kdf(
        "pw",
        "test",
        crate::KdfParams {
            m_kib: 64,
            t: 1,
            p: 1,
            ..Default::default()
        },
    )
    .unwrap()
}

fn login(vault: &crate::Vault, title: &str, urls: &[&str]) -> Item {
    vault
        .upsert(Item {
            title: title.into(),
            username: "alice".into(),
            password: "pw".into(),
            urls: sites(urls),
            ..Default::default()
        })
        .unwrap()
}

#[test]
fn vault_checks() {
    let v = vault();
    let paypal = login(&v, "PayPal", &["https://www.paypal.com"]);
    let chess = login(&v, "Chess", &["https://chess.com"]);
    let shop = v
        .upsert(Item {
            title: "Shop".into(),
            urls: sites(&["https://shop.example"]),
            android_apps: vec![AndroidApp {
                package: "com.shopapp.android".into(),
                cert_sha256: None,
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

    // Filling the PayPal login by hand on a lookalike.
    let found = v
        .lookalike_for_url("https://paypa1.com/login".into(), paypal.id.clone())
        .unwrap();
    assert_eq!(found.domain, "paypal.com");
    // On its own site, or on another site of the vault: no warning.
    assert_eq!(
        v.lookalike_for_url("https://www.paypal.com".into(), paypal.id.clone()),
        None
    );
    assert_eq!(
        v.lookalike_for_url("https://chess.com".into(), paypal.id.clone()),
        None
    );
    // Another login's site that doesn't look like this one.
    assert_eq!(
        v.lookalike_for_url("https://paypa1.com".into(), chess.id.clone()),
        None
    );
    // Unknown item.
    assert_eq!(
        v.lookalike_for_url("https://paypa1.com".into(), "nope".into()),
        None
    );
    // A linked app counts as one of the login's sites.
    assert_eq!(
        v.lookalike_for_url("androidapp://com.shopapp.android".into(), shop.id.clone()),
        None
    );

    // Saving a new login on a lookalike of a site of the vault.
    let found = v.lookalike_for_save("https://www.paypal.com.secure-id.net/".into()).unwrap();
    assert_eq!(found.domain, "paypal.com");
    assert_eq!(found.reason, LookalikeReason::DomainInSubdomain);
    assert_eq!(v.lookalike_for_save("https://paypal.com".into()), None);
    assert_eq!(v.lookalike_for_save("https://news.example.org".into()), None);
    // A trashed login doesn't count.
    let mut trashed = paypal.clone();
    trashed.trashed_at = Some(crate::now_ms());
    v.upsert(trashed).unwrap();
    assert_eq!(v.lookalike_for_save("https://paypa1.com".into()), None);
}

#[test]
fn login_sites_lists_apps() {
    let apps = vec![AndroidApp {
        package: "com.example.app".into(),
        cert_sha256: None,
        ..Default::default()
    }];
    assert_eq!(
        login_sites(&sites(&["https://example.com"]), &apps),
        sites(&["https://example.com", "androidapp://com.example.app"])
    );
}
