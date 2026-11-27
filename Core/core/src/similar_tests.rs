use super::*;
use crate::model::Item;

fn login(title: &str, urls: &[&str]) -> ItemSummary {
    let item = Item {
        title: title.into(),
        username: "me".into(),
        urls: urls.iter().map(|u| u.to_string()).collect(),
        ..Default::default()
    };
    ItemSummary::of(&item)
}

/// Every site of `logins`, as the agent hands them to [`similar_logins`].
fn known(logins: &[ItemSummary]) -> KnownSites {
    KnownSites::from_urls(
        logins
            .iter()
            .flat_map(|l| l.urls.iter().map(String::as_str)),
    )
}

/// The titles [`similar_logins`] finds on `page` among `logins`, with their reasons.
fn found(page: &str, logins: &[ItemSummary]) -> Vec<(String, SimilarReason)> {
    similar_logins(page, logins, &known(logins), 10)
        .into_iter()
        .map(|s| (logins[s.index].title.clone(), s.reason))
        .collect()
}

fn titles(page: &str, logins: &[ItemSummary]) -> Vec<String> {
    found(page, logins).into_iter().map(|(t, _)| t).collect()
}

#[test]
fn the_same_name_under_another_public_suffix() {
    let logins = [
        login("Amazon US", &["https://www.amazon.com/"]),
        login("Amazon DE", &["amazon.de"]),
        login("Bank", &["https://bank.example.com"]),
    ];
    // co.uk is one suffix: amazon.co.uk's name is amazon.
    assert_eq!(
        found("https://www.amazon.co.uk/ap/signin", &logins),
        [
            ("Amazon DE".to_string(), SimilarReason::SameName),
            ("Amazon US".to_string(), SimilarReason::SameName),
        ]
    );
    assert_eq!(
        titles("https://amazon.fr/", &logins),
        ["Amazon DE", "Amazon US"]
    );
    assert!(titles("https://shop.test-store.org/", &logins).is_empty());
}

#[test]
fn the_same_name_at_any_subdomain() {
    let logins = [login("Acme", &["https://login.acme.io/sso"])];
    assert_eq!(
        found("https://acme.com/login", &logins),
        [("Acme".to_string(), SimilarReason::SameName)]
    );
    assert_eq!(titles("https://app.acme.co.uk/", &logins), ["Acme"]);
}

#[test]
fn never_the_pages_own_site() {
    // A login of the page's registrable domain is the page's own (the menu lists it already).
    let logins = [
        login("Example", &["https://example.com"]),
        login(
            "Example shop",
            &["https://example.de", "https://shop.example.com"],
        ),
    ];
    assert!(titles("https://shop.example.com/", &logins).is_empty());
    assert!(titles("https://www.example.com/", &logins).is_empty());
}

#[test]
fn shared_public_suffixes_are_sites_of_their_own() {
    // github.io is a public suffix: alice.github.io and bob.github.io are two sites, named alice and bob.
    let logins = [
        login("Bob's blog", &["https://bob.github.io"]),
        login("GitHub", &["https://github.com/login"]),
        login("Alice", &["https://alice.com"]),
    ];
    assert_eq!(site_name("https://alice.github.io/"), Some("alice".into()));
    assert_eq!(site_name("https://www.bbc.co.uk/"), Some("bbc".into()));
    assert_eq!(
        found("https://alice.github.io/admin", &logins),
        [("Alice".to_string(), SimilarReason::SameName)]
    );
    assert!(titles("https://carol.github.io/", &logins).is_empty());
    // github.com's name is github: neither github.io site has it.
    assert!(titles(
        "https://github.com/",
        &[login("Bob's blog", &["https://bob.github.io"])]
    )
    .is_empty());
}

#[test]
fn titles_that_hold_the_name() {
    let logins = [
        login("BBC iPlayer", &[]),
        login("Abbcd", &[]),
        login("IKEA Family", &["https://family.example.net"]),
        login("Mikea", &[]),
        login("MyAmazon", &[]),
    ];
    // Three or four letters: a word of the title.
    assert_eq!(
        found("https://www.bbc.co.uk/", &logins),
        [("BBC iPlayer".to_string(), SimilarReason::Title)]
    );
    assert_eq!(titles("https://ikea.com/", &logins), ["IKEA Family"]);
    // Five letters or more: anywhere in it.
    assert_eq!(titles("https://amazon.es/", &logins), ["MyAmazon"]);
    // Two letters: only a website with that name, never a title.
    assert!(titles("https://my.com/", &logins).is_empty());
    assert_eq!(
        titles(
            "https://ab.com/",
            &[login("Ab", &["https://ab.de"]), login("Ab tools", &[])]
        ),
        ["Ab"]
    );
}

#[test]
fn lookalikes_are_never_similar() {
    // paypal-secure.com looks like paypal.com (its name joined with another word): the login of
    // paypal.com is left out although its title holds the page's name; a login that really is of a
    // paypal-secure site is offered.
    let logins = [
        login("PayPal-Secure", &["https://www.paypal.com"]),
        login("Card portal", &["https://paypal-secure.de"]),
    ];
    assert_eq!(
        found("https://paypal-secure.com/login", &logins),
        [("Card portal".to_string(), SimilarReason::SameName)]
    );
    // The same name under another suffix is no lookalike: offered.
    assert_eq!(titles("https://paypal.de/", &logins), ["PayPal-Secure"]);
}

#[test]
fn best_first_then_favorites_most_used_and_titles() {
    let mut fav = login("Zed Amazon", &[]);
    fav.favorite = true;
    let mut used = login("Amazon work", &["https://amazon.de"]);
    used.rank = 5;
    let logins = [
        login("Amazon Prime", &[]),
        login("Amazon home", &["https://amazon.com"]),
        fav,
        used,
        login("Amazon Music", &[]),
    ];
    assert_eq!(
        titles("https://amazon.co.jp/", &logins),
        [
            "Amazon work",
            "Amazon home",
            "Zed Amazon",
            "Amazon Music",
            "Amazon Prime"
        ]
    );
    let first = similar_logins("https://amazon.co.jp/", &logins, &known(&logins), 3);
    assert_eq!(first.len(), 3);
    assert_eq!(logins[first[2].index].title, "Zed Amazon");
}

#[test]
fn only_logins_and_only_web_pages() {
    let mut card = login("Amazon card", &[]);
    card.kind = ItemKind::Card;
    let logins = [card, login("Amazon", &["https://amazon.com"])];
    assert_eq!(titles("https://amazon.de/", &logins), ["Amazon"]);
    for page in [
        "http://192.168.1.1/",
        "http://localhost:8080/",
        "androidapp://com.amazon.mShop",
        "chrome://settings",
        "https://co.uk/",
        "",
    ] {
        assert!(titles(page, &logins).is_empty(), "{page}");
        assert_eq!(site_name(page), None, "{page}");
    }
}
