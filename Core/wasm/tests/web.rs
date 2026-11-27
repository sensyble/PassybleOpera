//! The JavaScript API (`BrowserAgent`, `setKdf`) as WebAssembly in Node: what crosses the boundary,
//! and the hand-over of Argon2id to the host's function. `tests/host.rs` covers the behaviour.
#![cfg(target_arch = "wasm32")]

use js_sys::Function;
use pass_wasm::{set_kdf, BrowserAgent};
use serde_json::{json, Value};
use wasm_bindgen_test::wasm_bindgen_test;

const PASSWORD: &str = "correct horse battery staple";
const URL: &str = "https://github.com/login";

fn value(text: impl Into<String>) -> Value {
    serde_json::from_str(&text.into()).unwrap()
}

fn agent() -> BrowserAgent {
    BrowserAgent::new(r#"{"device_id":"node"}"#).unwrap_or_else(|_| panic!("config"))
}

fn handle(agent: &BrowserAgent, method: &str, params: Value) -> Value {
    let line = json!({ "id": 1, "method": method, "params": params }).to_string();
    value(String::from(agent.handle(line)))
}

#[wasm_bindgen_test]
fn the_api_round_trips_a_vault() {
    let agent = agent();
    assert!(!agent.has_vault());
    let created = value(agent.create(PASSWORD.into()));
    assert!(created["result"]["grant"].is_string(), "{created}");
    let file = agent.take_save().expect("the new file");
    let saved = handle(
        &agent,
        "logins.save",
        json!({ "url": URL, "username": "octo", "password": "hunter2-Long-enough" }),
    );
    let id = saved["result"]["id"].as_str().unwrap().to_string();
    let filled = handle(&agent, "logins.fill", json!({ "url": URL, "id": id }));
    assert_eq!(filled["result"]["password"], "hunter2-Long-enough");
    let effects = value(String::from(agent.take_effects()));
    assert!(effects
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["type"] == "vault_changed"));
    // The key for storage.session, and a restart with it.
    let key = agent.vault_key().expect("unlocked").to_vec();
    assert_eq!(key.len(), 32);
    let exported = agent.export_vault().unwrap();
    assert_ne!(exported, file, "the login is in the newer file");
    assert!(agent.next_tick_ms().is_some());
    agent.tick();
    assert_eq!(value(agent.lock(false))["result"]["locked"], true);
    assert!(agent.vault_key().is_none());
    let again = self::agent();
    assert_eq!(
        value(again.load(exported.clone()))["result"]["vault_id"],
        created["result"]["vault_id"]
    );
    assert_eq!(
        value(again.unlock_with_key(key, 5000.0))["result"]["locked"],
        false
    );
    assert!(again.idle_ms() >= 5000.0);
    let filled = handle(&again, "logins.fill", json!({ "url": URL, "id": id }));
    assert_eq!(filled["result"]["password"], "hunter2-Long-enough");
    // The password way, with the vault's default Argon2id in this module (no kdf set).
    let third = self::agent();
    third.load(exported);
    assert_eq!(
        value(third.unlock("wrong".into()))["error"]["code"],
        "wrong_password"
    );
    assert_eq!(
        value(third.unlock(PASSWORD.into()))["result"]["locked"],
        false
    );
    assert_eq!(
        value(third.verify_password(PASSWORD.into()))["result"]["grant"]
            .as_str()
            .map(str::len),
        Some(43)
    );
    assert_eq!(
        value(third.set_options(r#"{"verify_each_fill":true}"#))["result"],
        json!({})
    );
}

#[wasm_bindgen_test]
fn argon2id_goes_to_the_host_function_when_one_is_set() {
    // A host function that counts its calls and gives a key of the wrong size: the core refuses
    // it (no vault is made with a key that didn't come from Argon2id).
    let calls = Function::new_with_args(
        "secret, salt, m, t, p",
        "globalThis.kdfCalls = (globalThis.kdfCalls || 0) + 1; \
         globalThis.kdfArgs = [secret.length, salt.length, m, t, p]; \
         return new Uint8Array(16);",
    );
    set_kdf(Some(calls));
    let agent = agent();
    let created = value(agent.create(PASSWORD.into()));
    assert!(created["error"].is_object(), "{created}");
    let global = js_sys::global();
    let get = |name: &str| js_sys::Reflect::get(&global, &name.into()).unwrap();
    assert_eq!(get("kdfCalls").as_f64(), Some(1.0));
    let args: Vec<f64> = js_sys::Array::from(&get("kdfArgs"))
        .iter()
        .map(|v| v.as_f64().unwrap())
        .collect();
    // The password's bytes, a 16-byte salt and the vault defaults (64 MiB, t = 3, p = 1).
    assert_eq!(args, vec![PASSWORD.len() as f64, 16.0, 65536.0, 3.0, 1.0]);
    // A host function that throws is a failed key derivation, not a crash.
    set_kdf(Some(Function::new_no_args("throw new Error('no kdf')")));
    assert!(value(agent.create(PASSWORD.into()))["error"].is_object());
    // Back to the module's own Argon2id.
    set_kdf(None);
    assert!(value(agent.create(PASSWORD.into()))["result"].is_object());
}
