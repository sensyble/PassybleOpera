//! Read-only mode ("Update required"): the agent refuses every fill, save, edit, passkey,
//! auto-type and sync, and still lets the user unlock, view, copy and export.

#![cfg(feature = "native")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use pass_agent::app_versions::{Cache, Requirement};
use pass_agent::{
    Agent, AgentConfig, Consent, ErrorCode, PasskeyChoice, PlatformCreateRequest,
    PlatformGetRequest, Ui, READ_ONLY_METHODS, UPDATE_REQUIRED_MESSAGE,
};
use pass_core::{Item, ItemKind, WebDavConfig};
use serde_json::{json, Value};

#[derive(Default)]
struct FakeUi {
    copied: Mutex<Vec<String>>,
    shown: Mutex<Vec<String>>,
}

impl Ui for FakeUi {
    fn request_unlock(&self) -> bool {
        false
    }
    fn confirm_passkey_create(&self, _rp_id: &str, _user: &str) -> Consent {
        Consent::Approve { item_id: None }
    }
    fn choose_passkey(&self, _rp_id: &str, options: &[PasskeyChoice]) -> Option<usize> {
        (!options.is_empty()).then_some(0)
    }
    fn show_totp_popup(&self, _item_id: &str, _title: &str) {}
    fn notify_lock_state(&self, _locked: bool) {}
    fn copy_to_clipboard(&self, text: &str) -> bool {
        self.copied.lock().unwrap().push(text.into());
        true
    }
    fn show_item(&self, item_id: &str) -> bool {
        self.shown.lock().unwrap().push(item_id.into());
        true
    }
    fn confirm_card_fill(&self, _request: &pass_agent::CardFillRequest) -> Option<bool> {
        Some(true)
    }
    fn show_server_pairing(&self, _link: &str) -> bool {
        true
    }
}

fn setup(ui: Arc<FakeUi>) -> (tempfile::TempDir, Arc<Agent>) {
    let dir = tempfile::tempdir().unwrap();
    let agent = Agent::new(
        AgentConfig {
            vault_path: dir.path().join("pass.vault"),
            device_id: "laptop".into(),
            auto_lock: Duration::from_secs(900),
            // Unreachable on purpose: a sync that ran would fail.
            webdav: Some(WebDavConfig {
                url: "http://127.0.0.1:9/pass.vault".into(),
                username: "me".into(),
                password: "pw".into(),
                pins: vec![],
            }),
            gdrive: None,
            kept_list: None,
        },
        ui,
    );
    (dir, agent)
}

fn call(agent: &Agent, method: &str, params: Value) -> Value {
    let line = json!({ "id": 1, "method": method, "params": params }).to_string();
    serde_json::from_str(&agent.handle_line(&line)).unwrap()
}

fn add_github(agent: &Agent) -> Item {
    agent
        .vault()
        .unwrap()
        .upsert(Item {
            title: "GitHub".into(),
            username: "octo".into(),
            password: "hunter2".into(),
            urls: vec!["https://github.com".into()],
            totp: Some("JBSWY3DPEHPK3PXP".into()),
            ..Default::default()
        })
        .unwrap()
}

fn add_card(agent: &Agent) -> Item {
    agent
        .vault()
        .unwrap()
        .upsert(Item {
            kind: ItemKind::Card,
            title: "Visa".into(),
            card: Some(pass_core::CardData {
                number: "4111111111111111".into(),
                security_code: "123".into(),
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap()
}

/// Every method the extension can send that read-only mode refuses, with params that would
/// otherwise get past parsing.
fn blocked_requests(id: &str, card_id: &str) -> Vec<(&'static str, Value)> {
    let url = "https://github.com/login";
    vec![
        ("logins.find", json!({ "url": url })),
        ("logins.fill", json!({ "url": url, "id": id })),
        ("logins.fill_cross", json!({ "url": "https://example.com/", "id": id })),
        ("logins.save", json!({ "url": url, "username": "octo", "password": "new" })),
        ("logins.save_check", json!({ "url": url, "username": "octo", "password": "new" })),
        ("logins.get_for_edit", json!({ "url": url, "id": id })),
        ("logins.update", json!({ "url": url, "id": id, "password": "new" })),
        ("logins.create", json!({ "url": url, "username": "u", "password": "p" })),
        ("logins.delete", json!({ "url": url, "id": id })),
        ("logins.restore", json!({ "url": url, "id": id })),
        ("totp.get", json!({ "url": url, "id": id })),
        ("totp.popup", json!({ "url": url, "id": id })),
        ("totp.set", json!({ "url": url, "id": id, "secret": "JBSWY3DPEHPK3PXP" })),
        ("totp.from_image", json!({ "url": url, "image": "AA" })),
        ("notes.create", json!({ "fields": { "title": "Recovery codes", "notes": "1111" } })),
        ("notes.append", json!({ "id": id, "text": "5555" })),
        ("items.import", json!({ "file": "AAAA", "key": "AAAA" })),
        ("otp.outcome", json!({ "url": url, "outcome": "filled" })),
        ("cards.fill", json!({ "url": url, "id": card_id })),
        ("cards.fill", json!({ "url": url, "id": card_id, "purpose": "copy" })),
        ("identities.fill", json!({ "url": url, "id": id })),
        ("passkey.find", json!({ "origin": "https://github.com" })),
        ("passkey.create_options", json!({ "origin": "https://github.com" })),
        ("passkey.create", json!({ "origin": "https://github.com", "options": {} })),
        ("passkey.get", json!({ "origin": "https://github.com", "options": {} })),
        ("server.pair", json!({ "link": "pass+server://example.com?token=x" })),
        ("generate.email", json!({ "url": url })),
        ("a.method.added.later", json!({})),
    ]
}

#[test]
fn every_blocked_request_answers_update_required() {
    let ui = Arc::new(FakeUi::default());
    let (_dir, agent) = setup(ui);
    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    let card = add_card(&agent);
    let before = agent.vault().unwrap().get(github.id.clone()).unwrap();

    agent.set_update_required(true);
    assert!(agent.update_required());
    for (method, params) in blocked_requests(&github.id, &card.id) {
        let r = call(&agent, method, params.clone());
        assert_eq!(r["error"]["code"], "update_required", "{method} {params}");
        assert_eq!(r["error"]["message"], UPDATE_REQUIRED_MESSAGE, "{method}");
        assert!(r.get("result").is_none(), "{method}");
    }
    let after = agent.vault().unwrap().get(github.id.clone()).unwrap();
    assert!(after == before, "the vault changed");
    assert_eq!(agent.vault().unwrap().items().len(), 2);

    // The sign-in handoff with the extension carries no vault data: answered (here by a UI
    // without a Passyble account).
    for method in [
        "account.peer",
        "account.handoff_begin",
        "account.sign_out",
        "account.peer_signed_out",
    ] {
        let r = call(&agent, method, json!({}));
        assert_eq!(r["error"]["code"], "not_supported", "{method}: {r}");
    }

    // Lifted: the same requests are answered again (whatever their own answer is).
    agent.set_update_required(false);
    for (method, params) in blocked_requests(&github.id, &card.id) {
        let r = call(&agent, method, params);
        assert_ne!(r["error"]["code"], "update_required", "{method}");
    }
}

#[test]
fn status_says_update_required_only_while_read_only() {
    let (_dir, agent) = setup(Arc::default());
    let status = call(&agent, "status", json!({}));
    assert!(status["result"].get("update_required").is_none());
    agent.set_update_required(true);
    let status = call(&agent, "status", json!({}));
    assert_eq!(status["result"]["update_required"], true);
    assert_eq!(status["result"]["locked"], true);
}

#[test]
fn unlock_view_copy_and_export_still_work() {
    let ui = Arc::new(FakeUi::default());
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    let card = add_card(&agent);
    agent.save_and_lock().unwrap();
    agent.set_update_required(true);

    let r = call(&agent, "unlock.password", json!({ "password": "master" }));
    assert!(r.get("error").is_none(), "{r}");
    assert!(!agent.is_locked());

    let found = call(&agent, "logins.search", json!({ "query": "git" }));
    assert_eq!(found["result"]["items"][0]["id"], github.id.as_str());
    let shown = call(&agent, "app.show_item", json!({ "url": "https://example.com/", "id": github.id }));
    assert!(shown.get("error").is_none(), "{shown}");
    assert_eq!(*ui.shown.lock().unwrap(), std::slice::from_ref(&github.id));
    let cards = call(&agent, "cards.list", json!({ "url": "https://shop.example/" }));
    assert!(cards.get("error").is_none(), "{cards}");

    for field in ["username", "password", "totp"] {
        let r = call(&agent, "logins.copy", json!({ "id": github.id, "field": field }));
        assert_eq!(r["result"]["copied"], true, "{field}: {r}");
    }
    let r = call(
        &agent,
        "cards.fill",
        json!({ "url": "https://shop.example/", "id": card.id, "purpose": "copy", "field": "number" }),
    );
    assert!(r.get("error").is_none(), "{r}");
    let copied = ui.copied.lock().unwrap().clone();
    assert_eq!(copied[0], "octo");
    assert_eq!(copied[1], "hunter2");
    assert_eq!(copied[2].len(), 6);
    assert_eq!(copied[3], "4111111111111111");

    // Copies aren't counted as uses: read-only mode writes nothing.
    let vault = agent.vault().unwrap();
    assert_eq!(vault.usage(github.id.clone()).count, 0);
    assert!(!vault.is_dirty());

    let exported = pass_core::export_json(vault.clone());
    assert!(exported.contains("hunter2"));
    assert!(pass_core::export_csv(vault).contains("octo"));

    // The generators and local checks don't touch the vault.
    for (method, params) in [
        ("generate", json!({})),
        ("generate.options", json!({})),
        ("generate.username", json!({})),
        ("password.check", json!({ "password": "hunter2" })),
    ] {
        let r = call(&agent, method, params);
        assert_ne!(r["error"]["code"], "update_required", "{method}");
    }

    let r = call(&agent, "lock", json!({}));
    assert_eq!(r["result"]["locked"], true);
}

#[test]
fn the_allowed_list_is_what_the_docs_say() {
    assert_eq!(
        READ_ONLY_METHODS,
        [
            "status",
            "unlock",
            "unlock.options",
            "unlock.password",
            "unlock.hello",
            "unlock.cancel",
            "lock",
            "logins.search",
            "logins.copy",
            "cards.list",
            "cards.fill",
            "identities.list",
            "notes.list",
            "notes.get",
            "app.show_item",
            "icons.get",
            "password.check",
            "generate",
            "generate.options",
            "generate.username",
            "generate.copy",
            "vaults.list",
            "vaults.pins",
            "vaults.own",
            "vaults.switch",
            "app.show_teams",
            "account.status",
            "app.show_account",
            "account.peer",
            "account.handoff_to_extension",
            "account.handoff_begin",
            "account.handoff_finish",
            "account.sign_out",
            "account.peer_signed_out",
        ]
    );
    let card_copy = json!({ "purpose": "copy", "field": "number" });
    assert!(pass_agent::read_only_allows("cards.fill", &card_copy));
    assert!(!pass_agent::read_only_allows("cards.fill", &json!({})));
    assert!(!pass_agent::read_only_allows("logins.fill", &json!({})));
}

#[test]
fn auto_type_finds_nothing_and_sync_does_nothing() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    add_github(&agent);
    assert_eq!(agent.find_for_window("GitHub - Browser", "app.exe").len(), 1);

    agent.set_update_required(true);
    assert!(agent.find_for_window("GitHub - Browser", "app.exe").is_empty());
    assert!(agent.match_window("GitHub - Browser", "app.exe").is_empty());
    // The WebDAV account is unreachable: a sync that ran would fail.
    assert_eq!(agent.sync().unwrap(), None);

    agent.set_update_required(false);
    assert!(agent.sync().is_err());
}

#[test]
fn the_windows_passkey_provider_is_refused() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    let request = PlatformCreateRequest {
        rp_id: "example.com".into(),
        rp_name: Some("Example".into()),
        user_handle: vec![1; 8],
        user_name: "me".into(),
        user_display_name: None,
        client_data_hash: vec![7; 32],
        algorithms: vec![-7],
        exclude_credentials: vec![],
    };
    let yes = |_: &str| true;
    agent.platform_passkey_create(request.clone(), &yes).unwrap();

    agent.set_update_required(true);
    let created = agent.platform_passkey_create(request, &yes);
    assert_eq!(created.unwrap_err().code, ErrorCode::UpdateRequired);
    let got = agent.platform_passkey_get(
        PlatformGetRequest {
            rp_id: "example.com".into(),
            client_data_hash: vec![7; 32],
            allow_credentials: vec![],
        },
        &yes,
    );
    assert_eq!(got.unwrap_err().code, ErrorCode::UpdateRequired);
    // The passkey made before is still there to view.
    assert_eq!(agent.passkey_metadata().unwrap().len(), 1);
}

#[test]
fn the_cache_decides_and_never_blocks_without_data() {
    let agent_for = |cache: &Cache| {
        let (dir, agent) = setup(Arc::default());
        agent.set_update_required(cache.requirement("0.1.0", "windows").is_required());
        (dir, agent)
    };
    let (_d1, agent) = agent_for(&Cache::default());
    assert!(!agent.update_required());

    let mut cache = Cache::default();
    // Offline at the first start: still nothing.
    cache.record(None, 1);
    let (_d2, agent) = agent_for(&cache);
    assert!(!agent.update_required());

    cache.record(
        Some(r#"{"v":1,"platforms":{"windows":{"minimum":"0.2.0","message":"Please update"}}}"#),
        2,
    );
    // Offline later: the cached answer still applies.
    cache.record(None, 3);
    assert_eq!(
        cache.requirement("0.1.0", "windows"),
        Requirement::Required {
            minimum: "0.2.0".into(),
            message: Some("Please update".into())
        }
    );
    let (_d3, agent) = agent_for(&cache);
    assert!(agent.update_required());
    // The updated app is not blocked by the same cache.
    assert_eq!(cache.requirement("0.2.0", "windows"), Requirement::None);
}

#[test]
fn secure_notes_still_open_and_copy() {
    let ui = Arc::new(FakeUi::default());
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let note = agent
        .vault()
        .unwrap()
        .upsert(Item {
            kind: ItemKind::Note,
            title: "Recovery codes".into(),
            notes: "1111-2222".into(),
            ..Default::default()
        })
        .unwrap();
    agent.set_update_required(true);
    let list = call(&agent, "notes.list", json!({}));
    assert_eq!(list["result"]["items"][0]["id"], note.id.as_str(), "{list}");
    let opened = call(&agent, "notes.get", json!({ "id": note.id }));
    assert_eq!(opened["result"]["notes"], "1111-2222", "{opened}");
    let copied = call(&agent, "notes.get", json!({ "id": note.id, "copy": true }));
    assert_eq!(copied["result"]["copied"], true, "{copied}");
    assert_eq!(*ui.copied.lock().unwrap(), ["1111-2222"]);
}
