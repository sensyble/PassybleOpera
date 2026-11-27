//! Harness for the browser end-to-end tests: a real agent with a throwaway vault and a UI that
//! answers every prompt itself. One JSON request per line on stdin, one response per line on stdout.
//! `PASS_E2E_VERIFY=1` makes user verification succeed, `PASS_E2E_DENY=1` declines passkey saves.

use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pass_agent::{Agent, AgentConfig, Consent, PasskeyChoice, Reason, Ui, Verification};

struct AutoUi {
    verify: bool,
    deny: bool,
}

impl Ui for AutoUi {
    fn request_unlock(&self) -> bool {
        false
    }
    fn confirm_passkey_create(&self, _rp_id: &str, _user_name: &str) -> Consent {
        if self.deny {
            Consent::Deny
        } else {
            Consent::Approve { item_id: None }
        }
    }
    fn choose_passkey(&self, _rp_id: &str, options: &[PasskeyChoice]) -> Option<usize> {
        (!options.is_empty()).then_some(0)
    }
    fn show_totp_popup(&self, _item_id: &str, _title: &str) {}
    fn notify_lock_state(&self, _locked: bool) {}
    fn verify_user(&self, _reason: &Reason) -> Verification {
        if self.verify {
            Verification::Verified
        } else {
            Verification::Allowed
        }
    }
    fn require_verification(&self, _reason: &Reason) -> Verification {
        if self.verify {
            Verification::Verified
        } else {
            Verification::Refused
        }
    }
}

fn flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| v == "1")
}

fn main() {
    let dir = std::env::temp_dir().join(format!("pass-e2e-agent-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp folder");
    let ui = Arc::new(AutoUi {
        verify: flag("PASS_E2E_VERIFY"),
        deny: flag("PASS_E2E_DENY"),
    });
    let agent = Agent::new(
        AgentConfig {
            vault_path: dir.join("pass.vault"),
            device_id: "e2e".into(),
            auto_lock: Duration::from_secs(3600),
            webdav: None,
            gdrive: None,
            kept_list: None,
        },
        ui,
    );
    agent.create_vault("master").expect("create vault");

    // One thread per request, as on the IPC server; responses are matched by id.
    let out = Arc::new(Mutex::new(std::io::stdout()));
    let mut workers = Vec::new();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let (agent, out) = (agent.clone(), out.clone());
        workers.push(std::thread::spawn(move || {
            let response = agent.handle_line(&line);
            let mut out = out.lock().unwrap();
            let _ = writeln!(out, "{response}");
            let _ = out.flush();
        }));
    }
    for w in workers {
        let _ = w.join();
    }
    let _ = std::fs::remove_dir_all(&dir);
}
