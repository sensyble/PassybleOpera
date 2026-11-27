//! Website rules (`Item::url_rules`, `AndroidApp::never_show`): how each rule matches, that items
//! without rules behave and are sealed the same as in older versions, and that rules survive sync
//! and the locked list.

use pass_core::*;
use std::sync::Arc;

fn fast_kdf() -> KdfParams {
    KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
        ..Default::default()
    }
}

fn new_vault(device: &str) -> Arc<Vault> {
    Vault::create_with_kdf("correct horse", device, fast_kdf()).unwrap()
}

fn rule(url: &str, rule: UrlMatch) -> UrlRule {
    UrlRule {
        url: url.into(),
        rule,
    }
}

fn login(title: &str, urls: &[&str], rules: Vec<UrlRule>) -> Item {
    Item {
        title: title.into(),
        username: title.to_lowercase(),
        password: "hunter2".into(),
        urls: urls.iter().map(|u| u.to_string()).collect(),
        url_rules: rules,
        ..Default::default()
    }
}

fn titles(items: &[Item]) -> Vec<&str> {
    items.iter().map(|i| i.title.as_str()).collect()
}

/// Three logins of one site: one with no rule, one kept to its host, one hidden.
fn site_vault() -> Arc<Vault> {
    let vault = new_vault("laptop");
    vault
        .upsert(login("Default", &["https://example.com"], vec![]))
        .unwrap();
    vault
        .upsert(login(
            "Host",
            &["https://example.com"],
            vec![rule("https://example.com", UrlMatch::Host)],
        ))
        .unwrap();
    vault
        .upsert(login(
            "Hidden",
            &["https://example.com"],
            vec![rule("https://example.com", UrlMatch::Never)],
        ))
        .unwrap();
    vault
}

#[test]
fn items_without_rules_read_and_seal_as_before() {
    let old = r#"{"kind": "login", "title": "Old", "urls": ["https://example.com"],
        "android_apps": [{"package": "com.example", "cert_sha256": null}]}"#;
    let item: Item = serde_json::from_str(old).unwrap();
    assert!(item.url_rules.is_empty());
    assert_eq!(item.url_rule("https://example.com"), UrlMatch::Subdomains);
    assert!(!item.android_apps[0].never_show);
    let json = serde_json::to_value(&item).unwrap();
    assert!(json.get("url_rules").is_none(), "{json}");
    assert!(
        json["android_apps"][0].get("never_show").is_none(),
        "{json}"
    );
}

#[test]
fn unknown_rules_from_a_newer_client_read_as_the_default() {
    let item: Item = serde_json::from_str(
        r#"{"title": "T", "urls": ["https://a.example"],
            "url_rules": [{"url": "https://a.example", "rule": "path_only"}]}"#,
    )
    .unwrap();
    assert_eq!(item.url_rule("https://a.example"), UrlMatch::Subdomains);
    for (name, want) in [
        ("subdomains", UrlMatch::Subdomains),
        ("host", UrlMatch::Host),
        ("never", UrlMatch::Never),
    ] {
        assert_eq!(serde_json::to_value(want).unwrap(), name);
        let back: UrlMatch = serde_json::from_value(name.into()).unwrap();
        assert_eq!(back, want);
    }
}

/// What an older client without rules reads: the websites as plain strings, the apps without the
/// flag. Unknown keys are ignored, so it opens a vault with rules and loses no website.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OldApp {
    package: String,
    #[serde(default)]
    cert_sha256: Option<String>,
    #[serde(default)]
    never_show: Option<serde_json::Value>,
}

#[derive(serde::Deserialize)]
struct OldItem {
    urls: Vec<String>,
    android_apps: Vec<serde_json::Value>,
}

#[test]
fn rules_are_extra_keys_an_older_client_ignores() {
    let vault = new_vault("laptop");
    let mut item = login(
        "Shop",
        &["https://shop.example", "https://pay.example"],
        vec![rule("https://pay.example", UrlMatch::Never)],
    );
    item.android_apps = vec![AndroidApp {
        package: "com.shop".into(),
        never_show: true,
        ..Default::default()
    }];
    let saved = vault.upsert(item).unwrap();
    let json = serde_json::to_value(&saved).unwrap();
    let old: OldItem = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(old.urls, ["https://shop.example", "https://pay.example"]);
    let app: OldApp = serde_json::from_value(old.android_apps[0].clone()).unwrap();
    assert_eq!((app.package.as_str(), app.cert_sha256), ("com.shop", None));
    assert!(app.never_show.is_some());
    assert_eq!(json["url_rules"][0]["rule"], "never");
}

#[test]
fn upsert_keeps_only_rules_that_change_something() {
    let vault = new_vault("laptop");
    let saved = vault
        .upsert(login(
            "Shop",
            &["https://shop.example", "https://pay.example"],
            vec![
                rule("https://shop.example", UrlMatch::Subdomains),
                rule("https://gone.example", UrlMatch::Never),
                rule("https://pay.example", UrlMatch::Host),
                rule("https://pay.example", UrlMatch::Never),
            ],
        ))
        .unwrap();
    assert_eq!(
        saved.url_rules,
        [rule("https://pay.example", UrlMatch::Host)]
    );
    // Removing the website drops its rule.
    let mut edited = saved.clone();
    edited.urls.retain(|u| u != "https://pay.example");
    assert!(vault.upsert(edited).unwrap().url_rules.is_empty());
}

#[test]
fn each_rule_decides_where_a_login_is_suggested() {
    let vault = site_vault();
    assert_eq!(
        titles(&vault.find_for_url("https://example.com/login".into())),
        ["Default", "Host"]
    );
    assert_eq!(
        titles(&vault.find_for_url("https://app.example.com/".into())),
        ["Default"]
    );
    assert!(vault.find_for_url("https://example.org/".into()).is_empty());
    // A hidden login is still found by search and by id.
    let hidden = vault.search("Hidden".into());
    assert_eq!(titles(&hidden), ["Hidden"]);
    assert!(vault.get(hidden[0].id.clone()).is_some());
}

#[test]
fn host_rule_with_a_port_matches_that_port_only() {
    let vault = new_vault("laptop");
    vault
        .upsert(login(
            "Router",
            &["https://192.168.1.1:8443"],
            vec![rule("https://192.168.1.1:8443", UrlMatch::Host)],
        ))
        .unwrap();
    assert_eq!(
        titles(&vault.find_for_url("https://192.168.1.1:8443/".into())),
        ["Router"]
    );
    assert!(vault.find_for_url("https://192.168.1.1/".into()).is_empty());
    assert!(vault
        .find_for_url("https://192.168.1.1:9443/".into())
        .is_empty());
}

#[test]
fn save_prompts_honour_the_rules() {
    let vault = site_vault();
    // On the host itself every login may be updated, the hidden one too: a sign-in with a login
    // filled by hand updates it instead of saving it again.
    let mut on_host = titles(&vault.find_for_save("https://example.com/login".into()))
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    on_host.sort();
    assert_eq!(on_host, ["Default", "Hidden", "Host"]);
    // A `www.` variant is the same host for the default rule, not for "same host only".
    let www = vault.find_for_save("https://www.example.com/".into());
    assert!(!titles(&www).contains(&"Host"), "{:?}", titles(&www));
    assert!(titles(&www).contains(&"Default"));
}

#[test]
fn locked_list_and_matchers_honour_the_rules() {
    let vault = site_vault();
    let summaries = vault.summaries();
    let names =
        |found: Vec<ItemSummary>| -> Vec<String> { found.into_iter().map(|s| s.title).collect() };
    assert_eq!(
        names(summaries_for_url(
            summaries.clone(),
            "https://example.com/".into()
        )),
        ["Default", "Host"]
    );
    assert_eq!(
        names(summaries_for_url(
            summaries.clone(),
            "https://app.example.com/".into()
        )),
        ["Default"]
    );
    let kept = KeptMatcher::new(summaries.clone());
    let at = |places: Vec<u32>| -> Vec<String> {
        places
            .into_iter()
            .map(|p| summaries[p as usize].title.clone())
            .collect()
    };
    assert_eq!(
        at(kept.for_url("https://example.com/".into())),
        ["Default", "Host"]
    );
    assert_eq!(
        at(kept.for_url("https://app.example.com/".into())),
        ["Default"]
    );
    let index = SearchIndex::new(
        vec![VaultSummaries {
            summaries: summaries.clone(),
            ..Default::default()
        }],
        Default::default(),
    );
    let found: Vec<String> = index
        .for_url("https://app.example.com/".into())
        .into_iter()
        .map(|s| s.summary.title)
        .collect();
    assert_eq!(found, ["Default"]);
}

#[test]
fn hidden_android_apps_are_not_suggested() {
    let vault = new_vault("phone");
    let app = |never_show| AndroidApp {
        package: "com.example".into(),
        never_show,
        ..Default::default()
    };
    let mut shown = login("Shown", &[], vec![]);
    shown.android_apps = vec![app(false)];
    let mut hidden = login("Hidden", &[], vec![]);
    hidden.android_apps = vec![app(true)];
    vault.upsert(shown).unwrap();
    vault.upsert(hidden).unwrap();
    assert_eq!(
        titles(&vault.find_for_android_app("com.example".into(), None)),
        ["Shown"]
    );
    let summaries = vault.summaries();
    let found: Vec<String> =
        summaries_for_android_app(summaries.clone(), "com.example".into(), None)
            .into_iter()
            .map(|s| s.title)
            .collect();
    assert_eq!(found, ["Shown"]);
    let kept = KeptMatcher::new(summaries.clone());
    let places = kept.for_android_app("com.example".into(), None);
    assert_eq!(places.len(), 1);
    assert_eq!(summaries[places[0] as usize].title, "Shown");
}

#[test]
fn rules_survive_reopening_and_export() {
    let vault = site_vault();
    let reopened = Vault::unlock(
        vault.serialize().unwrap(),
        "correct horse".into(),
        "laptop".into(),
    )
    .unwrap();
    let rules_of = |v: &Vault| {
        let mut rules: Vec<(String, Vec<UrlRule>)> = v
            .items()
            .into_iter()
            .map(|i| (i.title, i.url_rules))
            .collect();
        rules.sort_by(|a, b| a.0.cmp(&b.0));
        rules
    };
    assert_eq!(rules_of(&reopened), rules_of(&vault));

    let sealed = export_encrypted_json(vault.clone(), "export pw".into()).unwrap();
    let batch =
        import_parse_with_password(sealed, "export.json".into(), "export pw".into()).unwrap();
    let fresh = new_vault("other");
    batch.commit(fresh.clone()).unwrap();
    assert_eq!(rules_of(&fresh), rules_of(&vault));
    // The CSV keeps the websites only.
    let csv = export_csv(vault.clone());
    assert!(!csv.contains("never") && csv.contains("https://example.com"));
}

#[test]
fn concurrent_rule_edits_keep_one_rule_per_website() {
    let laptop = new_vault("laptop");
    let mut item = login("Shop", &["https://shop.example"], vec![]);
    item.android_apps = vec![AndroidApp {
        package: "com.shop".into(),
        ..Default::default()
    }];
    let item = laptop.upsert(item).unwrap();
    let phone = Vault::unlock_with_key(
        laptop.serialize().unwrap(),
        laptop.export_vault_key(),
        "phone".into(),
    )
    .unwrap();

    let mut on_laptop = item.clone();
    on_laptop.url_rules = vec![rule("https://shop.example", UrlMatch::Host)];
    on_laptop.android_apps[0].never_show = true;
    laptop.upsert(on_laptop).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(3));
    let mut on_phone = item.clone();
    on_phone.urls.push("https://pay.example".into());
    on_phone.url_rules = vec![
        rule("https://shop.example", UrlMatch::Never),
        rule("https://pay.example", UrlMatch::Host),
    ];
    phone.upsert(on_phone).unwrap();

    for _ in 0..2 {
        phone.merge_remote(laptop.serialize().unwrap()).unwrap();
        laptop.merge_remote(phone.serialize().unwrap()).unwrap();
    }
    for v in [&laptop, &phone] {
        let kept = v.get(item.id.clone()).unwrap();
        assert_eq!(v.items().len(), 1);
        let shop: Vec<&UrlRule> = kept
            .url_rules
            .iter()
            .filter(|r| r.url == "https://shop.example")
            .collect();
        assert_eq!(shop.len(), 1, "{:?}", kept.url_rules);
        assert_eq!(kept.url_rule("https://pay.example"), UrlMatch::Host);
        assert_eq!(kept.android_apps.len(), 1, "{:?}", kept.android_apps);
    }
    assert_eq!(
        laptop.get(item.id.clone()).unwrap(),
        phone.get(item.id.clone()).unwrap()
    );
}

#[test]
fn similar_logins_skip_hidden_websites() {
    let summaries = |rules: Vec<UrlRule>| {
        vec![ItemSummary::of(&login(
            "Store",
            &["https://amazon.de"],
            rules,
        ))]
    };
    let known = KnownSites::from_urls(["https://amazon.de"]);
    let shown = summaries(vec![]);
    assert_eq!(
        similar_logins("https://amazon.com/", &shown, &known, 5).len(),
        1
    );
    let hidden = summaries(vec![rule("https://amazon.de", UrlMatch::Never)]);
    assert!(similar_logins("https://amazon.com/", &hidden, &known, 5).is_empty());
}

#[test]
fn a_hidden_login_is_still_a_login_of_its_page_when_picked_by_hand() {
    let vault = site_vault();
    let mut found: Vec<String> = vault
        .logins_of_page("https://example.com/".into())
        .into_iter()
        .map(|i| i.title)
        .collect();
    found.sort();
    assert_eq!(found, ["Default", "Hidden", "Host"]);
    assert!(vault.logins_of_page("https://example.org/".into()).is_empty());

    let phone = new_vault("phone");
    let mut hidden = login("Hidden app", &[], vec![]);
    hidden.android_apps = vec![AndroidApp {
        package: "com.example".into(),
        never_show: true,
        ..Default::default()
    }];
    phone.upsert(hidden).unwrap();
    assert!(phone
        .find_for_android_app("com.example".into(), None)
        .is_empty());
    assert_eq!(
        titles(&phone.logins_of_android_app("com.example".into(), None)),
        ["Hidden app"]
    );
}
