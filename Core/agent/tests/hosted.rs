//! The agent on a host that keeps the vault file and drives the timers itself (a [`MemoryStore`],
//! a [`ManualClock`] and [`Timers::Host`]), as the extension's WebAssembly build does. Run natively.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pass_agent::clock::ManualClock;
use pass_agent::store::MemoryStore;
use pass_agent::{
    Agent, AgentConfig, AgentHost, CardFillRequest, Consent, CrossFillRequest, PasskeyChoice,
    Timers, Ui, USE_SAVE_DELAY,
};
use pass_core::Vault;
use serde_json::{json, Value};

const PASSWORD: &str = "correct horse battery staple";
const AUTO_LOCK: Duration = Duration::from_secs(15 * 60);

/// Says yes to what the extension decides in the page, copies, and counts lock changes.
#[derive(Default)]
struct TestUi {
    locks: Mutex<Vec<bool>>,
    copied: Mutex<Vec<String>>,
}

impl Ui for TestUi {
    fn request_unlock(&self) -> bool {
        false
    }
    fn confirm_passkey_create(&self, _: &str, _: &str) -> Consent {
        Consent::Deny
    }
    fn choose_passkey(&self, _: &str, _: &[PasskeyChoice]) -> Option<usize> {
        None
    }
    fn show_totp_popup(&self, _: &str, _: &str) {}
    fn notify_lock_state(&self, locked: bool) {
        self.locks.lock().unwrap().push(locked);
    }
    fn copy_to_clipboard(&self, text: &str) -> bool {
        self.copied.lock().unwrap().push(text.into());
        true
    }
    fn confirm_cross_fill(&self, _: &CrossFillRequest) -> Option<bool> {
        Some(true)
    }
    fn confirm_card_fill(&self, _: &CardFillRequest) -> Option<bool> {
        Some(true)
    }
}

fn config(vault_path: PathBuf) -> AgentConfig {
    AgentConfig::new(vault_path, "browser".into(), AUTO_LOCK)
}

/// A vault file to start from (one Argon2id run with the vault defaults).
fn vault_file() -> Vec<u8> {
    Vault::create(PASSWORD.into(), "laptop".into())
        .unwrap()
        .serialize()
        .unwrap()
}

/// A path that is not on disk: the hosted agent must never touch the file system.
fn browser_path() -> PathBuf {
    PathBuf::from("indexeddb:passyble").join("pass.vault")
}

struct Hosted {
    agent: Arc<Agent>,
    store: Arc<MemoryStore>,
    clock: Arc<ManualClock>,
    ui: Arc<TestUi>,
}

fn hosted(file: Option<Vec<u8>>) -> Hosted {
    let store = Arc::new(MemoryStore::new());
    if let Some(file) = file {
        store.put(&browser_path(), file);
    }
    let clock = Arc::new(ManualClock::at_system_time());
    let ui = Arc::new(TestUi::default());
    let agent = Agent::with_host(
        config(browser_path()),
        ui.clone(),
        AgentHost {
            store: store.clone(),
            clock: clock.clone(),
            timers: Timers::Host,
        },
    );
    Hosted {
        agent,
        store,
        clock,
        ui,
    }
}

fn call(agent: &Agent, method: &str, params: Value) -> Value {
    let line = json!({ "id": 1, "method": method, "params": params }).to_string();
    serde_json::from_str(&agent.handle_line(&line)).unwrap()
}

fn ok(agent: &Agent, method: &str, params: Value) -> Value {
    let answer = call(agent, method, params);
    assert!(answer.get("error").is_none(), "{method}: {answer}");
    answer["result"].clone()
}

fn written(store: &MemoryStore) -> Vec<PathBuf> {
    store.take_written().into_iter().map(|(p, _)| p).collect()
}

#[test]
fn a_hosted_agent_keeps_the_vault_file_in_its_store_only() {
    let h = hosted(None);
    assert!(!h.agent.vault_exists());
    h.agent.create_vault(PASSWORD).unwrap();
    assert!(!h.agent.is_locked());
    assert!(!Path::new("indexeddb:passyble").exists(), "nothing on disk");
    // The new file went to the store, for the host to copy to IndexedDB.
    let file = h.store.get(&browser_path()).expect("the vault file");
    assert_eq!(written(&h.store), vec![browser_path()]);
    assert_eq!(
        h.agent.vault_file_id(),
        Vault::unlock(file, PASSWORD.into(), "x".into())
            .ok()
            .map(|v| v.vault_id())
    );
    ok(&h.agent, "lock", json!({}));
    assert!(h.agent.is_locked());
    ok(&h.agent, "unlock.password", json!({ "password": PASSWORD }));
    assert_eq!(*h.ui.locks.lock().unwrap(), vec![false, true, false]);
}

#[test]
fn a_use_is_saved_when_the_host_ticks_after_the_delay() {
    let h = hosted(Some(vault_file()));
    ok(&h.agent, "unlock.password", json!({ "password": PASSWORD }));
    let _ = h.store.take_written();
    let url = "https://github.com/login";
    let id = ok(
        &h.agent,
        "logins.save",
        json!({ "url": url, "username": "octo", "password": "hunter2-Long-enough" }),
    )["id"]
        .as_str()
        .unwrap()
        .to_string();
    // The save wrote at once (an edit).
    assert_eq!(written(&h.store), vec![browser_path()]);
    // Nothing pending: the next tick is the auto-lock's.
    assert_eq!(h.agent.next_tick(), Some(AUTO_LOCK));
    // A fill counts a use, saved later (no thread here: the host's tick writes it).
    ok(&h.agent, "logins.fill", json!({ "url": url, "id": id }));
    assert_eq!(h.agent.next_tick(), Some(USE_SAVE_DELAY));
    h.agent.tick();
    assert!(written(&h.store).is_empty(), "not yet");
    h.clock.advance(USE_SAVE_DELAY / 2);
    assert_eq!(h.agent.next_tick(), Some(USE_SAVE_DELAY / 2));
    // More uses within the delay are one write.
    ok(&h.agent, "logins.fill", json!({ "url": url, "id": id }));
    h.clock.advance(USE_SAVE_DELAY / 2);
    assert_eq!(h.agent.next_tick(), Some(Duration::ZERO));
    h.agent.tick();
    assert_eq!(written(&h.store), vec![browser_path()]);
    let saved = Vault::unlock(
        h.store.get(&browser_path()).unwrap(),
        PASSWORD.into(),
        "x".into(),
    )
    .unwrap();
    // Two fills a moment apart are one use (`pass_core::USE_DEDUPE_MS`).
    assert_eq!(saved.usage(id).count, 1);
    assert_eq!(h.agent.next_tick(), Some(AUTO_LOCK - USE_SAVE_DELAY / 2));
}

#[test]
fn the_auto_lock_runs_on_the_host_clock() {
    let h = hosted(Some(vault_file()));
    ok(&h.agent, "unlock.password", json!({ "password": PASSWORD }));
    h.clock.advance(AUTO_LOCK - Duration::from_secs(1));
    h.agent.tick();
    assert!(!h.agent.is_locked());
    // Background requests are not use; others are.
    ok(&h.agent, "status", json!({}));
    assert_eq!(h.agent.next_tick(), Some(Duration::from_secs(1)));
    h.clock.advance(Duration::from_secs(1));
    h.agent.tick();
    assert!(h.agent.is_locked());
    assert_eq!(
        h.agent.next_tick(),
        None,
        "nothing to wait for while locked"
    );
    // A soft lock: the list stays for the menus.
    assert!(h.agent.is_soft_locked());
}

#[test]
fn an_agent_started_again_carries_the_idle_time_over() {
    let h = hosted(Some(vault_file()));
    ok(&h.agent, "unlock.password", json!({ "password": PASSWORD }));
    let key = h.agent.peek_vault().unwrap().export_vault_key();
    // The service worker stopped: a new agent on the same file, unlocked with the kept key.
    let again = hosted(h.store.get(&browser_path()));
    again.agent.unlock_with_key(key).unwrap();
    again.agent.set_idle_for(AUTO_LOCK - Duration::from_secs(5));
    assert_eq!(again.agent.next_tick(), Some(Duration::from_secs(5)));
    again.clock.advance(Duration::from_secs(5));
    again.agent.tick();
    assert!(again.agent.is_locked());
}

#[test]
fn a_file_the_host_puts_in_while_unlocked_is_merged_at_the_next_request() {
    let file = vault_file();
    let h = hosted(Some(file.clone()));
    ok(&h.agent, "unlock.password", json!({ "password": PASSWORD }));
    // Another device added a login to the same vault (a synced copy).
    let other = Vault::unlock(file, PASSWORD.into(), "phone".into()).unwrap();
    other
        .upsert(pass_core::Item {
            kind: pass_core::ItemKind::Login,
            title: "Example".into(),
            username: "ann".into(),
            password: "pw-from-the-phone".into(),
            urls: vec!["https://example.com".into()],
            ..Default::default()
        })
        .unwrap();
    h.store.put(&browser_path(), other.serialize().unwrap());
    let found = ok(
        &h.agent,
        "logins.find",
        json!({ "url": "https://example.com/" }),
    );
    assert_eq!(found["items"][0]["username"], "ann");
}

#[test]
fn copies_from_a_hosted_agent_go_to_its_ui() {
    let h = hosted(Some(vault_file()));
    ok(&h.agent, "unlock.password", json!({ "password": PASSWORD }));
    let password = ok(&h.agent, "generate", json!({ "length": 24 }))["password"]
        .as_str()
        .unwrap()
        .to_string();
    ok(&h.agent, "generate.copy", json!({ "password": password }));
    assert_eq!(*h.ui.copied.lock().unwrap(), vec![password]);
}

// ---- the same answers on both hosts ----------------------------------------------------------

#[cfg(feature = "native")]
mod same_answers {
    use pass_agent::store::VaultStore;

    use super::*;

    /// Replaces what differs between two runs of the same requests by nature: new ids (numbered in
    /// order of appearance), generated passwords, 2FA codes and timestamps.
    fn normalize(value: &Value, ids: &mut Vec<String>) -> Value {
        let uuid = |s: &str| {
            s.len() == 36
                && s.chars().enumerate().all(|(i, c)| match i {
                    8 | 13 | 18 | 23 => c == '-',
                    _ => c.is_ascii_hexdigit(),
                })
        };
        match value {
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(k, v)| {
                        // A 2FA code is digits; an error's code is a word, and stays.
                        let otp = k == "code"
                            && v.as_str()
                                .is_some_and(|c| c.bytes().all(|b| b.is_ascii_digit()));
                        let volatile = otp
                            || k == "remaining_secs"
                            || k.ends_with("_at")
                            || k.ends_with("_ms");
                        let v = if volatile && !v.is_null() {
                            json!("*")
                        } else {
                            normalize(v, ids)
                        };
                        (k.clone(), v)
                    })
                    .collect(),
            ),
            Value::Array(list) => Value::Array(list.iter().map(|v| normalize(v, ids)).collect()),
            Value::String(s) if uuid(s) => {
                let n = match ids.iter().position(|known| known == s) {
                    Some(n) => n,
                    None => {
                        ids.push(s.clone());
                        ids.len() - 1
                    }
                };
                json!(format!("id#{n}"))
            }
            other => other.clone(),
        }
    }

    /// One scripted session of the extension: locked requests, a wrong and a right master password,
    /// saves and edits, fills, 2FA, search and copy, generators, checks, lock and unlock again.
    /// `{id}` in a request is the login the first save created. Returns the normalized answers.
    fn script(agent: &Agent) -> Vec<Value> {
        let url = "https://github.com/login";
        let steps: Vec<(&str, Value)> = vec![
            ("status", json!({})),
            ("logins.find", json!({ "url": url })),
            ("unlock.options", json!({})),
            ("unlock.password", json!({ "password": "not it" })),
            ("unlock.password", json!({ "password": PASSWORD })),
            ("status", json!({})),
            (
                "logins.save_check",
                json!({ "url": url, "username": "octo", "password": "hunter2-Long-enough" }),
            ),
            (
                "logins.save",
                json!({ "url": url, "username": "octo", "password": "hunter2-Long-enough" }),
            ),
            (
                "logins.save_check",
                json!({ "url": url, "username": "octo", "password": "hunter2-Long-enough" }),
            ),
            ("logins.find", json!({ "url": "https://github.com/" })),
            ("logins.fill", json!({ "url": url, "id": "{id}" })),
            (
                "logins.fill",
                json!({ "url": "https://evil.example/", "id": "{id}" }),
            ),
            (
                "totp.set",
                json!({ "url": url, "id": "{id}", "totp": "JBSWY3DPEHPK3PXP" }),
            ),
            ("logins.fill", json!({ "url": url, "id": "{id}" })),
            ("totp.get", json!({ "url": url })),
            ("otp.outcome", json!({ "url": url, "outcome": "used" })),
            (
                "logins.create",
                json!({ "url": "https://example.com/", "fields": { "username": "ann", "password": "Pw-for-example-1" } }),
            ),
            ("logins.search", json!({ "query": "exam" })),
            ("logins.get_for_edit", json!({ "url": url, "id": "{id}" })),
            (
                "logins.update",
                json!({ "url": url, "id": "{id}", "fields": { "notes": "a note" } }),
            ),
            (
                "logins.copy",
                json!({ "id": "{id}", "field": "username", "url": url }),
            ),
            ("password.check", json!({ "password": "password1" })),
            ("generate.options", json!({})),
            ("cards.list", json!({ "url": "https://shop.example/" })),
            ("identities.list", json!({ "url": "https://shop.example/" })),
            (
                "passkey.find",
                json!({ "origin": "https://github.com", "rpId": "github.com" }),
            ),
            ("logins.delete", json!({ "url": url, "id": "{id}" })),
            ("logins.restore", json!({ "url": url, "id": "{id}" })),
            ("totp.popup", json!({ "url": url, "id": "{id}" })),
            ("app.show_item", json!({ "url": url, "id": "{id}" })),
            ("no.such.method", json!({})),
            ("lock", json!({})),
            ("status", json!({})),
            ("logins.find", json!({ "url": url })),
            ("logins.fill", json!({ "url": url, "id": "{id}" })),
            ("unlock.password", json!({ "password": PASSWORD })),
            ("logins.fill", json!({ "url": url, "id": "{id}" })),
        ];
        let mut first_id: Option<String> = None;
        let mut ids = Vec::new();
        let mut answers = Vec::new();
        for (method, params) in steps {
            let text = params.to_string();
            let text = match &first_id {
                Some(id) => text.replace("{id}", id),
                None => text,
            };
            let answer = call(agent, method, serde_json::from_str(&text).unwrap());
            if method == "logins.save" && first_id.is_none() {
                first_id = answer["result"]["id"].as_str().map(str::to_string);
            }
            answers.push(json!({ "method": method, "answer": normalize(&answer, &mut ids) }));
        }
        answers
    }

    #[test]
    fn the_hosted_agent_answers_like_the_desktop_agent() {
        let file = vault_file();
        // The desktop: the file on disk, the system clock, the save thread.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pass.vault");
        std::fs::write(&path, &file).unwrap();
        let native = Agent::new(config(path.clone()), Arc::new(TestUi::default()));
        // The browser: the same file in memory, a clock the host drives (here: the time now).
        let h = hosted(Some(file));
        let desktop = script(&native);
        let browser = script(&h.agent);
        assert_eq!(desktop.len(), browser.len());
        // The script really did something: the last fill gave the password, and these failed.
        assert_eq!(
            browser.last().unwrap()["answer"]["result"]["password"],
            "hunter2-Long-enough"
        );
        let errors: Vec<&str> = browser
            .iter()
            .filter_map(|a| a["answer"]["error"]["code"].as_str())
            .collect();
        assert_eq!(
            errors,
            [
                "locked",
                "wrong_password",
                "url_mismatch",
                "not_supported",
                "invalid_params",
                "locked"
            ],
            "{browser:#?}"
        );
        for (d, b) in desktop.iter().zip(&browser) {
            assert_eq!(d, b, "the same request, a different answer");
        }
        native.save().unwrap();
        h.agent.save().unwrap();
        let on_disk =
            Vault::unlock(std::fs::read(&path).unwrap(), PASSWORD.into(), "x".into()).unwrap();
        let in_memory = Vault::unlock(
            h.store.read(&browser_path()).unwrap(),
            PASSWORD.into(),
            "x".into(),
        )
        .unwrap();
        let logins = |v: &Vault| {
            let mut list: Vec<(String, String, String, String)> = v
                .items()
                .into_iter()
                .map(|i| (i.title, i.username, i.password, i.notes))
                .collect();
            list.sort();
            list
        };
        assert_eq!(logins(&on_disk), logins(&in_memory));
        assert_eq!(logins(&on_disk).len(), 2);
    }
}
