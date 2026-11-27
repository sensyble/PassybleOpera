use super::*;
use crate::{KdfParams, Vault};
use std::sync::Arc;

const SECRET: &str = "JBSWY3DPEHPK3PXP";

fn parse(link: &str) -> Result<OtpauthLink> {
    otpauth_parse_link(link.to_string())
}

fn message(link: &str) -> String {
    match parse(link) {
        Err(PassError::InvalidInput(m)) => m,
        other => panic!("{link}: expected a refusal, got {other:?}"),
    }
}

fn vault() -> Arc<Vault> {
    Vault::create_with_kdf(
        "pw",
        "dev",
        KdfParams {
            m_kib: 64,
            t: 1,
            p: 1,
            ..Default::default()
        },
    )
    .unwrap()
}

#[test]
fn reads_a_valid_link() {
    let link = parse(&format!(
        "otpauth://totp/Demo:alice@example.com?secret={SECRET}&issuer=Demo"
    ))
    .unwrap();
    assert_eq!(link.issuer.as_deref(), Some("Demo"));
    assert_eq!(link.account.as_deref(), Some("alice@example.com"));
    assert_eq!(link.algorithm, TotpAlgorithm::Sha1);
    assert_eq!((link.digits, link.period), (6, 30));
    // The clean link means the same.
    let again = crate::totp_parse(link.uri.clone()).unwrap();
    assert_eq!(again.issuer.as_deref(), Some("Demo"));
    assert_eq!(again.account.as_deref(), Some("alice@example.com"));
    assert_eq!(crate::encoding::base32_encode(&again.secret), SECRET);
}

#[test]
fn reads_every_setting_and_either_case() {
    let link = parse(&format!(
        "OTPAUTH://TOTP/Demo%20Co:al%20ice?SECRET={SECRET}&algorithm=sha256&digits=8&period=60"
    ))
    .unwrap();
    assert_eq!(link.issuer.as_deref(), Some("Demo Co"));
    assert_eq!(link.account.as_deref(), Some("al ice"));
    assert_eq!(link.algorithm, TotpAlgorithm::Sha256);
    assert_eq!((link.digits, link.period), (8, 60));
    assert!(link.uri.contains("algorithm=SHA256&digits=8&period=60"));
    assert_eq!(crate::totp_generate(link.uri, 59).unwrap().code.len(), 8);
}

#[test]
fn the_issuer_parameter_wins_and_no_label_is_fine() {
    let link = parse(&format!(
        "otpauth://totp/Label:bob?secret={SECRET}&issuer=Param"
    ))
    .unwrap();
    assert_eq!(link.issuer.as_deref(), Some("Param"));
    assert_eq!(link.account.as_deref(), Some("bob"));
    let link = parse(&format!("otpauth://totp/?secret={SECRET}")).unwrap();
    assert_eq!((link.issuer, link.account), (None, None));
}

#[test]
fn nothing_else_from_the_link_reaches_the_stored_link() {
    let link = parse(&format!(
        "otpauth://totp/Demo:alice?secret={SECRET}&issuer=Demo&image=https://evil.example/x.png&next=javascript:alert(1)"
    ))
    .unwrap();
    assert!(!link.uri.contains("evil"), "{}", link.uri);
    assert!(!link.uri.contains("javascript"), "{}", link.uri);
}

#[test]
fn the_debug_text_has_no_secret() {
    let link = parse(&format!("otpauth://totp/Demo:alice?secret={SECRET}")).unwrap();
    assert!(!format!("{link:?}").contains(SECRET));
}

#[test]
fn long_values_are_refused() {
    let too_long = "too long";
    let long_link = format!("otpauth://totp/Demo?secret={SECRET}&x={}", "a".repeat(3000));
    assert!(message(&long_link).contains(too_long));
    let long_label = format!("otpauth://totp/{}?secret={SECRET}", "a".repeat(300));
    assert!(message(&long_label).contains(too_long));
    let long_issuer = format!(
        "otpauth://totp/x?secret={SECRET}&issuer={}",
        "a".repeat(300)
    );
    assert!(message(&long_issuer).contains(too_long));
    // Exactly at the limit, a label is fine.
    let at_limit = format!("otpauth://totp/{}?secret={SECRET}", "a".repeat(256));
    assert!(parse(&at_limit).is_ok());
    // A secret larger than any hash block.
    let long_secret = format!("otpauth://totp/x?secret={}", "A".repeat(400));
    assert!(message(&long_secret).contains("setup key"));
}

#[test]
fn script_like_labels_stay_plain_text() {
    let link = parse(&format!(
        "otpauth://totp/%3Cscript%3Ealert(1)%3C%2Fscript%3E:%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E?secret={SECRET}"
    ))
    .unwrap();
    // Text, not markup: the apps render it as text. Encoded in the stored link.
    assert_eq!(link.issuer.as_deref(), Some("<script>alert(1)</script>"));
    assert_eq!(
        link.account.as_deref(),
        Some("<img src=x onerror=alert(1)>")
    );
    assert!(!link.uri.contains('<'), "{}", link.uri);
}

#[test]
fn invisible_characters_are_removed_from_labels() {
    // A right-to-left override, a zero-width space and a line break can't be seen on screen.
    let link = parse(&format!(
        "otpauth://totp/%E2%80%AEGit%E2%80%8BHub:al%0Aice%20%20x?secret={SECRET}"
    ))
    .unwrap();
    assert_eq!(link.issuer.as_deref(), Some("GitHub"));
    assert_eq!(link.account.as_deref(), Some("alice x"));
    // Nothing left is no label.
    let link = parse(&format!("otpauth://totp/%E2%80%AE?secret={SECRET}")).unwrap();
    assert_eq!(link.account, None);
}

#[test]
fn a_missing_or_bad_secret_is_refused_without_repeating_it() {
    assert!(message("otpauth://totp/Demo:alice?issuer=Demo").contains("no setup key"));
    assert!(message("otpauth://totp/Demo:alice?secret=").contains("no setup key"));
    for bad in ["NOT-BASE32!!", "189", "AAAA", "%3Cscript%3E"] {
        let m = message(&format!("otpauth://totp/Demo:alice?secret={bad}"));
        assert!(m.contains("setup key"), "{bad}: {m}");
        assert!(
            !m.contains('!') && !m.contains("189") && !m.contains("script"),
            "{m}"
        );
    }
}

#[test]
fn unknown_settings_are_refused_without_repeating_them() {
    for (query, words) in [
        ("algorithm=MD5", "algorithm"),
        ("algorithm=%3Cb%3EMD5", "algorithm"),
        ("digits=4", "code length"),
        ("digits=99", "code length"),
        ("digits=abc", "code length"),
        ("period=0", "interval"),
        ("period=99999", "interval"),
        ("period=abc", "interval"),
    ] {
        let m = message(&format!("otpauth://totp/x?secret={SECRET}&{query}"));
        assert!(m.contains(words), "{query}: {m}");
        let value = query.split('=').nth(1).unwrap();
        assert!(!m.contains(value), "{query} repeats its value: {m}");
    }
}

#[test]
fn other_kinds_get_a_plain_message() {
    assert!(message(&format!("otpauth://hotp/x?secret={SECRET}&counter=1")).contains("HOTP"));
    assert!(message(&format!("otpauth://steam/x?secret={SECRET}")).contains("time-based"));
    assert!(
        message(&format!("otpauth://totp.evil.example/x?secret={SECRET}")).contains("time-based")
    );
}

#[test]
fn anything_unusual_is_refused() {
    for link in [
        "".to_string(),
        "not a link".to_string(),
        SECRET.to_string(),
        "https://example.com/?secret=JBSWY3DPEHPK3PXP".to_string(),
        "otpauth-migration://offline?data=abc".to_string(),
        "otpauth:".to_string(),
        "otpauth://".to_string(),
        format!("otpauth:/totp/x?secret={SECRET}"),
        format!("otpauth://user:pw@totp/x?secret={SECRET}"),
        format!("otpauth://totp:443/x?secret={SECRET}"),
        format!("otpauth://totp/x?secret={SECRET}#fragment"),
        format!("otpauth://totp/x\n?secret={SECRET}"),
        format!("otpauth://totp/x?secret={SECRET}\tissuer=y"),
        format!("otpauth://totp/x?secret={SECRET}&secret=GEZDGNBVGY3TQOJQ"),
        format!("otpauth://totp/x?issuer=a&ISSUER=b&secret={SECRET}"),
        "otpauth://é".to_string(),
        "ééééééééééééééé".to_string(),
    ] {
        assert!(parse(&link).is_err(), "{link}");
    }
}

fn summary(
    id: &str,
    kind: ItemKind,
    title: &str,
    username: &str,
    urls: &[&str],
    has_totp: bool,
) -> ItemSummary {
    let item = Item {
        id: id.to_string(),
        kind,
        title: title.to_string(),
        username: username.to_string(),
        urls: urls.iter().map(|u| u.to_string()).collect(),
        totp: has_totp.then(|| SECRET.to_string()),
        ..Default::default()
    };
    ItemSummary::of(&item)
}

fn login(title: &str, urls: &[&str]) -> Vec<ItemSummary> {
    vec![summary("a", ItemKind::Login, title, "", urls, false)]
}

fn matches(
    issuer: Option<&str>,
    account: Option<&str>,
    items: Vec<ItemSummary>,
) -> Vec<OtpauthMatch> {
    otpauth_matches(
        issuer.map(str::to_string),
        account.map(str::to_string),
        items,
    )
}

fn ids(found: &[OtpauthMatch]) -> Vec<&str> {
    found.iter().map(|m| m.id.as_str()).collect()
}

#[test]
fn the_website_beats_the_title_and_the_account_breaks_ties() {
    let found = matches(
        Some("GitHub"),
        Some("alice@example.com"),
        vec![
            summary("title", ItemKind::Login, "GitHub", "other", &[], false),
            summary(
                "site",
                ItemKind::Login,
                "Work code",
                "other",
                &["https://github.com/login"],
                false,
            ),
            summary(
                "both",
                ItemKind::Login,
                "Code",
                "Alice@Example.com",
                &["github.com"],
                false,
            ),
            summary(
                "unrelated",
                ItemKind::Login,
                "Bank",
                "alice@example.com",
                &["https://bank.example"],
                false,
            ),
        ],
    );
    assert_eq!(ids(&found), ["both", "site", "title"]);
    assert!(found[0].account_matches && found[0].suggested);
    assert!(!found[1].suggested && !found[2].suggested);
}

#[test]
fn matches_issuers_written_differently() {
    let github = &["https://www.github.com"];
    for issuer in [
        "github.com",
        "www.github.com",
        "GitHub",
        "GitHub Enterprise",
    ] {
        assert_eq!(
            matches(Some(issuer), None, login("Code host", github)).len(),
            1,
            "{issuer}"
        );
    }
    assert_eq!(
        matches(Some("Google Accounts"), None, login("Google", &[])).len(),
        1
    );
    assert_eq!(
        matches(Some("github"), None, login("Git Hub", &[])).len(),
        1
    );
}

#[test]
fn does_not_match_on_a_shared_word_or_part_of_one() {
    assert!(matches(Some("Mail"), None, login("Gmail", &[])).is_empty());
    assert!(matches(Some("The Company"), None, login("The Verge", &[])).is_empty());
    assert!(matches(Some("A"), None, login("A B", &[])).is_empty());
    assert!(matches(Some("<>"), None, login("<>", &[])).is_empty());
}

#[test]
fn only_logins_match() {
    let found = matches(
        Some("Demo"),
        None,
        vec![
            summary("note", ItemKind::Note, "Demo", "", &[], false),
            summary("card", ItemKind::Card, "Demo", "", &[], false),
        ],
    );
    assert!(found.is_empty());
}

#[test]
fn a_login_with_a_code_is_listed_but_never_suggested() {
    // The page can't steer the user into replacing a working code.
    let found = matches(
        Some("GitHub"),
        Some("alice"),
        vec![
            summary(
                "code",
                ItemKind::Login,
                "GitHub",
                "alice",
                &["github.com"],
                true,
            ),
            summary(
                "free",
                ItemKind::Login,
                "GitHub spare",
                "",
                &["github.com"],
                false,
            ),
        ],
    );
    assert_eq!(ids(&found), ["code", "free"]);
    assert!(found[0].has_totp && !found[0].suggested);
    assert!(found[1].suggested);
    let only = matches(
        Some("GitHub"),
        None,
        vec![summary("code", ItemKind::Login, "GitHub", "", &[], true)],
    );
    assert_eq!(only.len(), 1);
    assert!(!only[0].suggested);
}

#[test]
fn an_account_alone_is_listed_only_without_an_issuer_and_not_suggested() {
    let items = || {
        vec![summary(
            "a",
            ItemKind::Login,
            "Anything",
            "alice@example.com",
            &[],
            false,
        )]
    };
    assert!(matches(Some("Other"), Some("alice@example.com"), items()).is_empty());
    let found = matches(None, Some("alice@example.com"), items());
    assert_eq!(ids(&found), ["a"]);
    assert!(found[0].account_matches && !found[0].suggested);
    assert!(matches(None, None, items()).is_empty());
}

#[test]
fn at_most_a_few_are_offered() {
    let items = (0..20)
        .map(|i| summary(&format!("{i}"), ItemKind::Login, "Demo", "", &[], false))
        .collect();
    assert_eq!(matches(Some("Demo"), None, items).len(), MAX_MATCHES);
}

#[test]
fn adds_to_a_new_login() {
    let vault = vault();
    let link = parse(&format!("otpauth://totp/Demo:alice?secret={SECRET}")).unwrap();
    let saved = vault
        .add_otpauth_link(link.clone(), None, false, "2FA code".into())
        .unwrap();
    assert_eq!(saved.kind, ItemKind::Login);
    assert_eq!(saved.title, "Demo");
    assert_eq!(saved.username, "alice");
    assert_eq!(saved.totp.as_deref(), Some(link.uri.as_str()));
    // Named after the account, or in the app's words.
    let link = parse(&format!("otpauth://totp/bob?secret={SECRET}")).unwrap();
    let saved = vault.add_otpauth_link(link, None, false, "x".into());
    assert_eq!(saved.unwrap().title, "bob");
    let link = parse(&format!("otpauth://totp/?secret={SECRET}")).unwrap();
    let saved = vault.add_otpauth_link(link, None, false, "2FA code".into());
    assert_eq!(saved.unwrap().title, "2FA code");
}

#[test]
fn adds_to_a_login_and_keeps_everything_else() {
    let vault = vault();
    let login = vault
        .upsert(Item {
            kind: ItemKind::Login,
            title: "GitHub".into(),
            username: "alice".into(),
            password: "hunter2".into(),
            ..Default::default()
        })
        .unwrap();
    let link = parse(&format!("otpauth://totp/Other:bob?secret={SECRET}")).unwrap();
    let saved = vault
        .add_otpauth_link(link.clone(), Some(login.id.clone()), false, String::new())
        .unwrap();
    assert_eq!(saved.id, login.id);
    assert_eq!(saved.title, "GitHub");
    assert_eq!(saved.username, "alice");
    assert_eq!(saved.password, "hunter2");
    assert_eq!(saved.totp.as_deref(), Some(link.uri.as_str()));
    assert_eq!(vault.summaries().len(), 1);
}

#[test]
fn a_login_keeps_its_code_unless_the_user_chose_to_replace_it() {
    let vault = vault();
    let login = vault
        .upsert(Item {
            kind: ItemKind::Login,
            title: "GitHub".into(),
            totp: Some("GEZDGNBVGY3TQOJQ".into()),
            ..Default::default()
        })
        .unwrap();
    let link = parse(&format!("otpauth://totp/GitHub?secret={SECRET}")).unwrap();
    let refused =
        vault.add_otpauth_link(link.clone(), Some(login.id.clone()), false, String::new());
    assert!(refused.is_err());
    let stored = vault.get(login.id.clone()).unwrap().totp;
    assert_eq!(stored.as_deref(), Some("GEZDGNBVGY3TQOJQ"));
    let saved = vault
        .add_otpauth_link(link.clone(), Some(login.id), true, String::new())
        .unwrap();
    assert_eq!(saved.totp.as_deref(), Some(link.uri.as_str()));
}

#[test]
fn only_a_login_that_is_there_can_take_a_code() {
    let vault = vault();
    let link = parse(&format!("otpauth://totp/x?secret={SECRET}")).unwrap();
    let gone = vault.add_otpauth_link(link.clone(), Some("gone".into()), false, String::new());
    assert!(gone.is_err());
    let note = vault
        .upsert(Item {
            kind: ItemKind::Note,
            title: "Note".into(),
            ..Default::default()
        })
        .unwrap();
    assert!(vault
        .add_otpauth_link(link, Some(note.id), true, String::new())
        .is_err());
    assert_eq!(vault.summaries().len(), 1, "nothing was added");
}
