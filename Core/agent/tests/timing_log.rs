//! A failed request is logged with its error code only, never the message (which can name a site
//! or an item). Its own test binary because the log path is read from the environment once.

#![cfg(feature = "native")]

use std::sync::Arc;
use std::time::Duration;

use pass_agent::{Agent, AgentConfig, Consent, PasskeyChoice, Ui};
use pass_core::b64url_encode;
use serde_json::{json, Value};

struct QuietUi;

impl Ui for QuietUi {
    fn request_unlock(&self) -> bool {
        false
    }
    fn confirm_passkey_create(&self, _rp_id: &str, _user_name: &str) -> Consent {
        Consent::Deny
    }
    fn choose_passkey(&self, _rp_id: &str, _options: &[PasskeyChoice]) -> Option<usize> {
        None
    }
    fn show_totp_popup(&self, _item_id: &str, _title: &str) {}
    fn notify_lock_state(&self, _locked: bool) {}
}

fn call(agent: &Agent, method: &str, params: Value) -> Value {
    let line = json!({ "id": 1, "method": method, "params": params }).to_string();
    serde_json::from_str(&agent.handle_line(&line)).unwrap()
}

#[test]
fn failed_passkey_requests_log_their_error_code_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("timing.log");
    // Before the first trace: the sink reads the variable once.
    std::env::set_var(pass_agent::timing::ENV, &log);
    let agent = Agent::new(
        AgentConfig {
            vault_path: dir.path().join("pass.vault"),
            device_id: "laptop".into(),
            auto_lock: Duration::from_secs(900),
            webdav: None,
            gdrive: None,
            kept_list: None,
        },
        Arc::new(QuietUi),
    );
    let get = json!({
        "origin": "https://login.example.com",
        "rpId": "example.com",
        "challenge": b64url_encode(vec![1; 32]),
    });

    let find = call(
        &agent,
        "passkey.find",
        json!({ "origin": "https://login.example.com", "rpId": "example.com" }),
    );
    assert_eq!(find["error"]["code"], "locked", "{find}");
    assert_eq!(
        call(&agent, "passkey.get", get.clone())["error"]["code"],
        "locked"
    );

    agent.create_vault("master").unwrap();
    let miss = call(&agent, "passkey.get", get);
    assert_eq!(miss["error"]["code"], "not_found", "{miss}");
    let ok = call(
        &agent,
        "passkey.find",
        json!({ "origin": "https://login.example.com", "rpId": "example.com" }),
    );
    assert!(ok["result"]["items"].is_array(), "{ok}");
    // The error message for a bad RP ID names the sites, so it must not reach the log.
    let bad = call(
        &agent,
        "passkey.find",
        json!({ "origin": "https://login.example.com", "rpId": "evil.example.org" }),
    );
    assert_eq!(bad["error"]["code"], "url_mismatch", "{bad}");

    let text = std::fs::read_to_string(&log).unwrap();
    let steps: Vec<&str> = text
        .lines()
        .filter(|l| l.contains(": answered"))
        .map(|l| {
            // "<time> app #<n> <step> +<total>ms (+<delta>ms)"
            let step = l.splitn(4, ' ').nth(3).unwrap();
            step.rsplitn(3, ' ').nth(2).unwrap()
        })
        .collect();
    assert_eq!(
        steps,
        [
            "passkey.find: answered with an error (locked)",
            "passkey.get: answered with an error (locked)",
            "passkey.get: answered with an error (not_found)",
            "passkey.find: answered",
            "passkey.find: answered with an error (url_mismatch)",
        ],
        "{text}"
    );
    for leak in [
        "example",
        "Vault is locked",
        "no passkey",
        "is not valid",
        "https",
    ] {
        assert!(!text.contains(leak), "{leak:?} in the timing log:\n{text}");
    }
}
