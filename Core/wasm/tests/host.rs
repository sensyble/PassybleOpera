//! [`BrowserHost`], the code under the WebAssembly bindings. Runs natively and as WebAssembly in
//! Node.

use std::sync::Arc;
use std::time::Duration;

use pass_agent::clock::ManualClock;
use pass_core::{Item, ItemKind, Vault};
use pass_wasm::{BrowserConfig, BrowserHost, GRANT_TTL};
use serde_json::{json, Value};

const PASSWORD: &str = "correct horse battery staple";
const URL: &str = "https://github.com/login";

/// The vault file the desktop app made (`write_the_fixture` below): one login, `PASSWORD`.
const NATIVE_VAULT: &[u8] = include_bytes!("fixtures/native.vault");

fn config() -> BrowserConfig {
    serde_json::from_value(json!({ "device_id": "chrome-on-linux" })).unwrap()
}

fn host() -> (BrowserHost, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::at_system_time());
    (
        BrowserHost::with_clock(config(), clock.clone()).unwrap(),
        clock,
    )
}

fn value(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

fn ok<T: std::fmt::Debug>(result: Result<Value, T>) -> Value {
    result.unwrap()
}

/// One protocol request, with what the extension's background may add.
fn request(host: &BrowserHost, method: &str, params: Value, extra: Value) -> Value {
    let mut line = json!({ "id": 7, "method": method, "params": params });
    if let Value::Object(extra) = extra {
        line.as_object_mut().unwrap().extend(extra);
    }
    let answer = value(&host.handle(&line.to_string()));
    assert_eq!(answer["id"], 7, "{answer}");
    answer
}

fn call(host: &BrowserHost, method: &str, params: Value) -> Value {
    request(host, method, params, json!({}))
}

fn result(host: &BrowserHost, method: &str, params: Value) -> Value {
    let answer = call(host, method, params);
    assert!(answer.get("error").is_none(), "{method}: {answer}");
    answer["result"].clone()
}

fn error(answer: &Value) -> &str {
    answer["error"]["code"].as_str().unwrap_or("(no error)")
}

fn effects(host: &BrowserHost) -> Vec<Value> {
    serde_json::from_str::<Vec<Value>>(&host.take_effects()).unwrap()
}

fn save_login(host: &BrowserHost) -> String {
    result(
        host,
        "logins.save",
        json!({ "url": URL, "username": "octo", "password": "hunter2-Long-enough" }),
    )["id"]
        .as_str()
        .unwrap()
        .to_string()
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn without_a_vault_only_status_answers() {
    let (host, _) = host();
    assert!(!host.has_vault());
    let status = result(&host, "status", json!({}));
    assert_eq!(status["vault"], false);
    assert_eq!(status["locked"], true);
    let features: Vec<&str> = status["features"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(features.contains(&"vault.browser"), "{features:?}");
    assert!(!features.contains(&"unlock.hello_browser"));
    assert!(
        !features.contains(&"totp.from_image"),
        "no QR reader in this build"
    );
    assert!(!features.contains(&"icons.get"));
    assert!(
        features.contains(&"notes.create"),
        "the popup's New note works here too"
    );
    assert!(
        features.contains(&"notes.append"),
        "the context menu's Save selection to a note too"
    );
    assert!(
        !features.contains(&"items.import"),
        "nothing moves into the browser vault"
    );
    for method in ["logins.find", "unlock.password", "lock", "generate"] {
        assert_eq!(
            error(&call(&host, method, json!({ "url": URL }))),
            "no_vault"
        );
    }
    assert_eq!(error(&ok_err(host.unlock(PASSWORD))), "no_vault");
    assert!(host.export().is_err());
    assert!(host.take_save().is_none());
}

/// An `Err` as the envelope's JSON.
fn ok_err(result: pass_wasm::HostResult) -> Value {
    value(&pass_wasm::envelope(result))
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn create_applies_the_master_password_rule() {
    let (host, _) = host();
    for weak in ["password1234", "aaaaaaaaaaaaaaaa", "short"] {
        assert_eq!(error(&ok_err(host.create(weak))), "invalid_params", "{weak}");
    }
    assert!(!host.has_vault());
    let check = value(&pass_wasm::master_password_check_json(
        "alex.smith@example.com",
        r#"["alex.smith@example.com", 7]"#,
    ));
    assert_eq!(check["ok"], false);
    assert!(check["issues"]
        .as_array()
        .unwrap()
        .contains(&json!("contains_name")));
    assert_eq!(check["min_length"], 12);
    let good = value(&pass_wasm::master_password_check_json(PASSWORD, "not json"));
    assert_eq!(good["ok"], true, "{good}");
    assert_eq!(good["issues"], json!([]));
    ok(host.create(PASSWORD));
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn popular_sites_answer_without_a_vault() {
    let netflix = json!({ "name": "Netflix", "domain": "netflix.com" });
    let sites = value(&pass_wasm::site_suggestions_json("netf", 3));
    assert_eq!(sites[0], netflix);
    assert_eq!(value(&pass_wasm::site_suggestions_json("", 3)), json!([]));
    // The agent protocol's methods once there is a vault (before, `siteSuggestions` answers),
    // locked or not.
    let (host, _) = host();
    ok(host.create(PASSWORD));
    ok(host.lock(true));
    let query = json!({ "query": "amazon.de", "limit": 1 });
    let amazon = json!({ "name": "Amazon", "domain": "amazon.de" });
    assert_eq!(
        result(&host, "sites.suggest", query),
        json!({ "sites": [amazon] })
    );
    let github = json!({ "url": "https://github.com/login" });
    assert_eq!(
        result(&host, "sites.name_for", github),
        json!({ "name": "GitHub" })
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn create_fill_lock_and_unlock() {
    let (host, _) = host();
    let created = ok(host.create(PASSWORD));
    assert!(created["vault_id"]
        .as_str()
        .is_some_and(|id| !id.is_empty()));
    assert!(created["grant"].as_str().is_some_and(|g| g.len() >= 40));
    // The new file is the extension's to store.
    let file = host.take_save().expect("the new vault file");
    assert_eq!(
        Vault::unlock(file, PASSWORD.into(), "x".into())
            .unwrap()
            .vault_id(),
        created["vault_id"].as_str().unwrap()
    );
    assert_eq!(error(&ok_err(host.create(PASSWORD))), "invalid_state");
    assert_eq!(result(&host, "status", json!({}))["vault"], true);
    let id = save_login(&host);
    assert!(host.take_save().is_some(), "an edit is saved at once");
    assert!(effects(&host).iter().any(|e| e["type"] == "vault_changed"));
    let found = result(&host, "logins.find", json!({ "url": URL }));
    assert_eq!(found["items"][0]["id"], id.as_str());
    assert_eq!(found["locked"], false);
    let filled = result(&host, "logins.fill", json!({ "url": URL, "id": id }));
    assert_eq!(filled["password"], "hunter2-Long-enough");
    // The URL binding is the agent's: another site gets nothing.
    let other = call(
        &host,
        "logins.fill",
        json!({ "url": "https://evil.example/", "id": id }),
    );
    assert_eq!(error(&other), "url_mismatch");
    // The use is saved by a tick once due (no threads in the browser).
    assert!(host.next_tick().unwrap() <= pass_agent::USE_SAVE_DELAY);
    // A soft lock keeps the list for the menus, without secrets.
    assert_eq!(ok(host.lock(false)), json!({ "locked": true }));
    assert!(
        host.take_save().is_some(),
        "the waiting use was saved by the lock"
    );
    let listed = result(&host, "logins.find", json!({ "url": URL }));
    assert_eq!(listed["locked"], true);
    assert_eq!(listed["items"][0]["username"], "octo");
    assert_eq!(
        error(&call(&host, "logins.fill", json!({ "url": URL, "id": id }))),
        "locked"
    );
    assert_eq!(error(&ok_err(host.unlock("wrong"))), "wrong_password");
    let unlocked = ok(host.unlock(PASSWORD));
    assert_eq!(unlocked["locked"], false);
    assert!(unlocked["grant"].is_string());
    let locks: Vec<bool> = effects(&host)
        .iter()
        .filter(|e| e["type"] == "lock_state")
        .map(|e| e["locked"].as_bool().unwrap())
        .collect();
    assert_eq!(locks, vec![true, false]);
    // Locking completely drops the list too.
    ok(host.lock(true));
    assert_eq!(
        error(&call(&host, "logins.find", json!({ "url": URL }))),
        "locked"
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn the_vault_file_round_trips_and_a_desktop_vault_opens_byte_for_byte() {
    // A file the desktop app wrote (natively) opens here, and comes back out unchanged.
    let (host, _) = host();
    let loaded = ok(host.load(NATIVE_VAULT.to_vec()));
    let native = Vault::unlock(NATIVE_VAULT.to_vec(), PASSWORD.into(), "x".into()).unwrap();
    assert_eq!(loaded["vault_id"], native.vault_id().as_str());
    assert_eq!(
        host.export().unwrap(),
        NATIVE_VAULT,
        "locked: the very file"
    );
    ok(host.unlock(PASSWORD));
    // Unlocked and read, not changed: still the very file (nothing rewritten in another form).
    result(
        &host,
        "logins.find",
        json!({ "url": "https://example.com/" }),
    );
    assert_eq!(
        host.export().unwrap(),
        NATIVE_VAULT,
        "unlocked: the very file"
    );
    assert!(host.take_save().is_none());
    let found = result(
        &host,
        "logins.find",
        json!({ "url": "https://example.com/" }),
    );
    assert_eq!(found["items"][0]["username"], "ann");
    let id = found["items"][0]["id"].as_str().unwrap().to_string();
    let filled = result(
        &host,
        "logins.fill",
        json!({ "url": "https://example.com/", "id": id }),
    );
    assert_eq!(filled["password"], "pw-from-the-desktop");
    // An edit here, then the file goes back to the desktop: the desktop's own core opens it.
    save_login(&host);
    let exported = host.export().unwrap();
    let back = Vault::unlock(exported.clone(), PASSWORD.into(), "laptop".into()).unwrap();
    assert_eq!(back.vault_id(), native.vault_id());
    let mut users: Vec<String> = back.items().into_iter().map(|i| i.username).collect();
    users.sort();
    assert_eq!(users, ["ann", "octo"]);
    // The desktop merges it into its own copy as with any synced copy.
    let merged = native.merge_remote(exported.clone()).unwrap();
    assert_eq!(merged.added, 1);
    // And another browser loads the exported file.
    let (other, _) = host_with_file(exported);
    ok(other.unlock(PASSWORD));
    assert_eq!(
        result(&other, "logins.find", json!({ "url": URL }))["items"][0]["username"],
        "octo"
    );
    // Only while locked: an open vault isn't replaced under the user.
    assert_eq!(
        error(&ok_err(other.load(NATIVE_VAULT.to_vec()))),
        "invalid_state"
    );
    ok(other.lock(true));
    assert_eq!(
        error(&ok_err(other.load(b"not a vault".to_vec()))),
        "invalid_params"
    );
}

fn host_with_file(file: Vec<u8>) -> (BrowserHost, Arc<ManualClock>) {
    let (host, clock) = host();
    ok(host.load(file));
    (host, clock)
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_restarted_service_worker_opens_the_vault_with_the_kept_key() {
    let (host, _) = host();
    ok(host.create(PASSWORD));
    let id = save_login(&host);
    let key = host.vault_key().expect("unlocked");
    assert_eq!(key.len(), 32);
    let file = host.export().unwrap();
    // A new instance: the file from IndexedDB, the key from storage.session.
    let (again, clock) = host_with_file(file);
    let idle = Duration::from_secs(60);
    assert_eq!(
        ok(again.unlock_with_key(&key, idle.as_millis() as u64)),
        json!({ "locked": false })
    );
    assert_eq!(again.idle(), idle);
    let filled = result(&again, "logins.fill", json!({ "url": URL, "id": id }));
    assert_eq!(filled["password"], "hunter2-Long-enough");
    // The auto-lock keeps its schedule (15 minutes by default).
    clock.advance(Duration::from_secs(15 * 60));
    again.tick();
    assert!(again.vault_key().is_none(), "locked");
    // A key that doesn't belong to the vault.
    let (third, _) = host_with_file(again.export().unwrap());
    assert_eq!(
        error(&ok_err(third.unlock_with_key(&[7u8; 32], 0))),
        "wrong_password"
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn per_fill_verification_travels_with_the_request_as_a_grant() {
    let clock = Arc::new(ManualClock::at_system_time());
    let config: BrowserConfig =
        serde_json::from_value(json!({ "device_id": "edge", "verify_each_fill": true })).unwrap();
    let host = BrowserHost::with_clock(config, clock.clone()).unwrap();
    ok(host.create(PASSWORD));
    let id = save_login(&host);
    let fill = json!({ "url": URL, "id": id });
    assert_eq!(
        error(&call(&host, "logins.fill", fill.clone())),
        "verification_required"
    );
    // A wrong password gives no grant.
    assert_eq!(
        error(&ok_err(host.verify_password("nope"))),
        "wrong_password"
    );
    let grant = ok(host.verify_password(PASSWORD))["grant"].clone();
    // A grant that isn't one counts for nothing.
    let forged = request(
        &host,
        "logins.fill",
        fill.clone(),
        json!({ "grant": "abc" }),
    );
    assert_eq!(error(&forged), "verification_required");
    let filled = request(
        &host,
        "logins.fill",
        fill.clone(),
        json!({ "grant": grant }),
    );
    assert_eq!(filled["result"]["password"], "hunter2-Long-enough");
    // Used up.
    let again = request(
        &host,
        "logins.fill",
        fill.clone(),
        json!({ "grant": grant }),
    );
    assert_eq!(error(&again), "verification_required");
    // And short-lived.
    let late = ok(host.verify_password(PASSWORD))["grant"].clone();
    clock.advance(GRANT_TTL + Duration::from_secs(1));
    let expired = request(&host, "logins.fill", fill.clone(), json!({ "grant": late }));
    assert_eq!(error(&expired), "verification_required");
    // The unlock a fill asked for counts as its verification.
    ok(host.lock(false));
    let unlock_grant = ok(host.unlock(PASSWORD))["grant"].clone();
    let filled = request(
        &host,
        "logins.fill",
        fill.clone(),
        json!({ "grant": unlock_grant }),
    );
    assert!(filled.get("result").is_some(), "{filled}");
    // Locking drops grants not used yet.
    let unused = ok(host.verify_password(PASSWORD))["grant"].clone();
    ok(host.lock(false));
    ok(host.unlock(PASSWORD));
    let dropped = request(
        &host,
        "logins.fill",
        fill.clone(),
        json!({ "grant": unused }),
    );
    assert_eq!(error(&dropped), "verification_required");
    // Turned off: fills go through again.
    ok(host.set_options(r#"{"verify_each_fill": false}"#));
    assert!(call(&host, "logins.fill", fill).get("result").is_some());
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn fills_the_user_confirms_in_an_extension_page_carry_confirmed() {
    let (host, _) = host();
    ok(host.create(PASSWORD));
    save_login(&host);
    let hits = result(&host, "logins.search", json!({ "query": "github" }));
    let id = hits["items"][0]["id"].as_str().unwrap().to_string();
    let cross = json!({ "url": "https://other.example/", "id": id });
    // Without the popup's confirmation: refused.
    assert_eq!(
        error(&call(&host, "logins.fill_cross", cross.clone())),
        "cancelled"
    );
    let confirmed = request(
        &host,
        "logins.fill_cross",
        cross,
        json!({ "confirmed": true }),
    );
    assert_eq!(
        confirmed["result"]["password"], "hunter2-Long-enough",
        "{confirmed}"
    );
    // A payment card the same way.
    let vault = host.agent().peek_vault().unwrap();
    let card = vault
        .upsert(Item {
            kind: ItemKind::Card,
            title: "Visa".into(),
            card: Some(pass_core::CardData {
                number: "4111111111111111".into(),
                expiry_month: 12,
                expiry_year: 2030,
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap();
    let fill = json!({ "url": "https://shop.example/pay", "id": card.id });
    assert_eq!(error(&call(&host, "cards.fill", fill.clone())), "cancelled");
    let filled = request(&host, "cards.fill", fill, json!({ "confirmed": true }));
    assert_eq!(filled["result"]["number"], "4111111111111111", "{filled}");
    // `confirmed` must be `true`, nothing else.
    let cross = json!({ "url": "https://other.example/", "id": id });
    let fake = request(
        &host,
        "logins.fill_cross",
        cross,
        json!({ "confirmed": "yes" }),
    );
    assert_eq!(error(&fake), "cancelled");
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn copies_come_back_as_effects_and_the_desktop_windows_are_not_supported() {
    let (host, _) = host();
    ok(host.create(PASSWORD));
    let id = save_login(&host);
    effects(&host);
    let password = result(&host, "generate", json!({ "length": 24 }))["password"]
        .as_str()
        .unwrap()
        .to_string();
    result(&host, "generate.copy", json!({ "password": password }));
    result(
        &host,
        "logins.copy",
        json!({ "id": id, "field": "username", "url": URL }),
    );
    let copies: Vec<String> = effects(&host)
        .into_iter()
        .filter(|e| e["type"] == "copy")
        .map(|e| e["text"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(copies, vec![password, "octo".to_string()]);
    assert!(effects(&host).is_empty(), "taken once");
    for (method, params) in [
        ("totp.popup", json!({ "url": URL, "id": id })),
        ("app.show_item", json!({ "url": URL, "id": id })),
        ("server.pair", json!({ "link": "pass.example.com" })),
    ] {
        assert_eq!(
            error(&call(&host, method, params)),
            "not_supported",
            "{method}"
        );
    }
    // The desktop's own unlock window doesn't exist here: the extension opens its popup.
    ok(host.lock(false));
    assert_eq!(error(&call(&host, "unlock", json!({}))), "cancelled");
    // A passkey request without the page card's consent is declined, never waits.
    ok(host.unlock(PASSWORD));
    let create = call(
        &host,
        "passkey.create",
        json!({
            "origin": "https://github.com",
            "rp": { "id": "github.com", "name": "GitHub" },
            "user": { "id": "dXNlcg", "name": "octo" },
            "challenge": "Y2hhbGxlbmdl",
        }),
    );
    assert_eq!(error(&create), "cancelled");
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn options_change_the_auto_lock_and_the_list() {
    let (host, clock) = host();
    ok(host.create(PASSWORD));
    save_login(&host);
    ok(host.set_options(r#"{"auto_lock_secs": 60, "keep_list": false}"#));
    assert!(host.vault_key().is_some(), "still open");
    assert!(host.next_tick().unwrap() <= Duration::from_secs(60));
    clock.advance(Duration::from_secs(60));
    host.tick();
    assert!(host.vault_key().is_none());
    // Without the list kept, a lock is complete.
    assert_eq!(
        error(&call(&host, "logins.find", json!({ "url": URL }))),
        "locked"
    );
    assert_eq!(
        error(&ok_err(host.set_options(r#"{"nope": 1}"#))),
        "invalid_params"
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn the_config_needs_a_device_id() {
    assert!(BrowserHost::from_json(r#"{"device_id": ""}"#).is_err());
    assert!(BrowserHost::from_json(r#"{}"#).is_err());
    assert!(BrowserHost::from_json(r#"{"device_id": "x", "unknown": 1}"#).is_err());
    assert!(BrowserHost::from_json(r#"{"device_id": "x"}"#).is_ok());
}

/// Writes `tests/fixtures/native.vault`: a vault the desktop's core makes, cheap Argon2id so the
/// WebAssembly tests stay quick. `cargo test -p pass-wasm --test host -- --ignored`.
#[cfg(not(target_arch = "wasm32"))]
#[test]
#[ignore]
fn write_the_fixture() {
    let kdf = pass_core::KdfParams {
        m_kib: 1024,
        t: 1,
        p: 1,
        ..pass_core::KdfParams::default()
    };
    let vault = Vault::create_with_kdf(PASSWORD, "desktop", kdf).unwrap();
    vault
        .upsert(Item {
            kind: ItemKind::Login,
            title: "Example".into(),
            username: "ann".into(),
            password: "pw-from-the-desktop".into(),
            urls: vec!["https://example.com".into()],
            ..Default::default()
        })
        .unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native.vault");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, vault.serialize().unwrap()).unwrap();
}

/// "Available to AI tools" (pass-core `AiAccess`, a custom field) survives the browser vault: a
/// desktop vault with a shared login, edited in the extension's own vault and read back by the
/// desktop, is still shared. The browser vault has no `ai.*` methods.
#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn the_ai_tools_mark_survives_the_browser_vault() {
    let desktop = Vault::create(PASSWORD.into(), "desktop".into()).unwrap();
    let mut login = Item {
        kind: ItemKind::Login,
        title: "GitHub".into(),
        username: "octo".into(),
        password: "hunter2-Long-enough".into(),
        urls: vec!["https://github.com".into()],
        ..Default::default()
    };
    login.set_ai_access(Some(pass_core::AiAccess::Allow));
    let id = desktop.upsert(login).unwrap().id;
    let (host, _) = host_with_file(desktop.serialize().unwrap());
    ok(host.unlock(PASSWORD));
    result(
        &host,
        "logins.update",
        json!({ "url": URL, "id": id, "fields": { "title": "GitHub (browser)", "password": "another-Long-one-2" } }),
    );
    assert!(call(&host, "ai.list", json!({})).get("error").is_some());
    let back = Vault::unlock(host.export().unwrap(), PASSWORD.into(), "desktop".into()).unwrap();
    let item = back.get(id).unwrap();
    assert_eq!(item.title, "GitHub (browser)");
    assert_eq!(item.ai_access(), Some(pass_core::AiAccess::Allow));
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn secure_notes_open_with_a_grant_and_copy_as_an_effect() {
    let clock = Arc::new(ManualClock::at_system_time());
    let config: BrowserConfig =
        serde_json::from_value(json!({ "device_id": "edge", "verify_each_fill": true })).unwrap();
    let host = BrowserHost::with_clock(config, clock).unwrap();
    ok(host.create(PASSWORD));
    let features = result(&host, "status", json!({}))["features"].clone();
    for feature in ["notes.list", "items.favorite"] {
        assert!(
            features.as_array().unwrap().contains(&json!(feature)),
            "{feature}: {features}"
        );
    }
    let note = result(
        &host,
        "notes.create",
        json!({ "fields": { "title": "Recovery codes", "notes": "1111-2222" } }),
    );
    let id = note["id"].as_str().unwrap().to_string();
    save_login(&host);

    // Listed by title only (the login and the text stay out).
    let list = result(&host, "notes.list", json!({}));
    assert_eq!(list["items"].as_array().unwrap().len(), 1, "{list}");
    assert_eq!(list["items"][0]["title"], "Recovery codes");
    assert_eq!(list["items"][0]["favorite"], false);
    assert!(!list.to_string().contains("1111"));
    let found = result(&host, "logins.find", json!({ "url": URL }));
    assert_eq!(found["items"][0]["favorite"], false, "{found}");

    // "Confirm each fill" on: the text only with a grant, as a password copied from the search.
    let get = json!({ "id": id });
    assert_eq!(
        error(&call(&host, "notes.get", get.clone())),
        "verification_required"
    );
    let grant = ok(host.verify_password(PASSWORD))["grant"].clone();
    let opened = request(&host, "notes.get", get, json!({ "grant": grant }));
    assert_eq!(opened["result"]["notes"], "1111-2222", "{opened}");

    // A copy is an effect the extension writes; the answer has no text.
    effects(&host);
    let grant = ok(host.verify_password(PASSWORD))["grant"].clone();
    let copied = request(
        &host,
        "notes.get",
        json!({ "id": id, "copy": true }),
        json!({ "grant": grant }),
    );
    assert_eq!(copied["result"], json!({ "copied": true }), "{copied}");
    let copies: Vec<Value> = effects(&host)
        .into_iter()
        .filter(|e| e["type"] == "copy")
        .collect();
    assert_eq!(copies.len(), 1);
    assert_eq!(copies[0]["text"], "1111-2222");

    // Locked (the list kept): titles still, the text not.
    ok(host.lock(false));
    let kept = result(&host, "notes.list", json!({}));
    assert_eq!(kept["locked"], true);
    assert_eq!(kept["items"][0]["title"], "Recovery codes");
    assert_eq!(
        error(&call(&host, "notes.get", json!({ "id": id }))),
        "locked"
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_selection_is_added_to_a_note_as_a_new_line() {
    let clock = Arc::new(ManualClock::at_system_time());
    let config: BrowserConfig =
        serde_json::from_value(json!({ "device_id": "edge", "verify_each_fill": true })).unwrap();
    let host = BrowserHost::with_clock(config, clock).unwrap();
    ok(host.create(PASSWORD));
    let note = result(
        &host,
        "notes.create",
        json!({ "fields": { "title": "Reading list", "notes": "Rust book" } }),
    );
    let id = note["id"].as_str().unwrap().to_string();
    let append = json!({ "id": id, "text": "Demo article" });

    // "Confirm each fill" on: a change to the note needs a grant, as an edit does.
    assert_eq!(
        error(&call(&host, "notes.append", append.clone())),
        "verification_required"
    );
    effects(&host);
    let grant = ok(host.verify_password(PASSWORD))["grant"].clone();
    let added = request(&host, "notes.append", append, json!({ "grant": grant }));
    assert_eq!(added["result"]["title"], "Reading list", "{added}");
    assert!(!added.to_string().contains("Rust book"), "no text in the answer");
    assert!(effects(&host).iter().any(|e| e["type"] == "vault_changed"));

    ok(host.set_options(r#"{"verify_each_fill": false}"#));
    let more = json!({ "id": id, "text": "Second article" });
    assert!(call(&host, "notes.append", more).get("result").is_some());
    let opened = result(&host, "notes.get", json!({ "id": id }));
    assert_eq!(opened["notes"], "Rust book\nDemo article\nSecond article");

    ok(host.lock(false));
    let locked = json!({ "id": id, "text": "x" });
    assert_eq!(error(&call(&host, "notes.append", locked)), "locked");
}
