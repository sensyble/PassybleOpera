#![cfg(feature = "native")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use pass_agent::{
    AccountError, AccountPeer, AccountSummary, Agent, AgentConfig, CardFillRequest, Consent,
    CrossFillRequest, HandoffCode, HandoffRequest, ItemSecret, LockKind, PasskeyChoice,
    PasskeyPick, Reason, SyncFailure, SyncReport, Ui, UnlockAttempt, UnlockOptions, Verification,
    WindowMatch,
};
use pass_core::{
    b64url_decode, b64url_encode, CardData, IdentityData, Item, ItemKind, UrlMatch, UrlRule, Vault,
};
use serde_json::{json, Value};

#[derive(Default)]
struct FakeUi {
    deny_passkeys: bool,
    popups: Mutex<Vec<String>>,
    lock_events: Mutex<Vec<bool>>,
    pairing: Option<Mutex<Vec<String>>>,
    /// `Some(answer)`: record `verify_user` calls and answer with it. `None`: the default hook.
    verify: Option<bool>,
    verifications: Mutex<Vec<String>>,
    /// `require_verification`: `Some(answer)` records the call and answers `Verified` / `Refused`.
    /// `None` models a PC without Windows Hello, whatever `verify` says.
    required: Option<bool>,
    required_calls: Mutex<Vec<String>>,
    /// `app.show_item` calls (`Ui::show_item` answers true).
    shown_items: Mutex<Vec<String>>,
    /// `Ui::vault_changed` calls.
    vault_changes: Mutex<usize>,
    /// `Ui::copy_to_clipboard`: `true` records the text, `false` is a UI without the hook.
    copy_supported: bool,
    copied: Mutex<Vec<String>>,
    /// `Ui::confirm_cross_fill`'s answer (`None`: no such prompt); every call is recorded.
    cross: Option<bool>,
    cross_requests: Mutex<Vec<CrossFillRequest>>,
    /// `Ui::confirm_card_fill`'s answer (`None`: no such prompt); every call is recorded.
    card: Option<bool>,
    card_requests: Mutex<Vec<CardFillRequest>>,
    /// `Ui::unlock_options().hello`.
    hello_offered: bool,
    /// `Ui::unlock_with_hello`: `Some(password)` unlocks [`FakeUi::agent`] with it, `None` answers
    /// `hello_answer`.
    hello_unlocks_with: Option<String>,
    hello_answer: Option<UnlockAttempt>,
    hello_calls: Mutex<usize>,
    /// `Ui::unlock_with_password`: `Some(answer)` stands for the desktop app's own unlock. `None`
    /// keeps the default hook.
    password_answer: Option<UnlockAttempt>,
    passwords: Mutex<Vec<String>>,
    /// `Ui::hello_in_browser`.
    hello_browser: bool,
    /// `Ui::cancel_unlock`'s answer; each call records `ipc::request_client_pid()`.
    cancel_answer: bool,
    cancel_calls: Mutex<Vec<Option<u32>>>,
    /// `Ui::credential_used` calls.
    uses: Mutex<usize>,
    /// `Some(wait)`: `verify_user` waits this long (a prompt on screen), then runs the auto-lock
    /// tick and records whether it locked the vault.
    tick_during_verify: Option<Duration>,
    locked_during_verify: Mutex<Vec<bool>>,
    agent: Mutex<Option<std::sync::Weak<Agent>>>,
    /// `Agent::unlock_requested_for` as each unlock reached `notify_lock_state(false)`.
    unlocked_for: Mutex<Vec<Option<String>>>,
    /// `verify_item` calls: (item id, "password" / "code" / "pending code" / "passkey").
    item_checks: Mutex<Vec<(String, &'static str)>>,
    /// `Ui::choose_passkey_for_browser`: `Some(answer)` replaces the default; calls are counted.
    passkey_pick: Option<PasskeyPick>,
    passkey_choices: Mutex<usize>,
    /// `Ui::account_summary`'s answer (`None`: a UI without a Passyble account).
    account: Option<AccountSummary>,
    /// `app.show_account` calls: whether each asked to sign in.
    account_shown: Mutex<Vec<bool>>,
    /// `Ui::account_peer`'s answer (`None`: a UI without a Passyble account); the handoff
    /// methods follow it (signed in: a code for the extension; signed out and accepting: a
    /// challenge).
    peer: Option<AccountPeer>,
    /// The handoff calls, in order: the method's short name and what it got.
    handoffs: Mutex<Vec<String>>,
    /// `Ui::sync_now`'s answer (`None`: the agent syncs by itself); calls are counted.
    sync_answer: Option<SyncReport>,
    sync_calls: Mutex<usize>,
}

impl FakeUi {
    fn the_agent(&self) -> Option<Arc<Agent>> {
        self.agent
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|a| a.upgrade())
    }
}

impl Ui for FakeUi {
    fn request_unlock(&self) -> bool {
        false
    }
    fn unlock_options(&self) -> UnlockOptions {
        UnlockOptions {
            hello: self.hello_offered,
        }
    }
    fn unlock_with_password(&self, password: &str) -> Option<UnlockAttempt> {
        let answer = self.password_answer.clone()?;
        self.passwords.lock().unwrap().push(password.into());
        Some(answer)
    }
    fn unlock_with_hello(&self) -> UnlockAttempt {
        *self.hello_calls.lock().unwrap() += 1;
        if let Some(password) = &self.hello_unlocks_with {
            let agent = self
                .agent
                .lock()
                .unwrap()
                .as_ref()
                .and_then(|a| a.upgrade());
            return match agent.map(|a| a.unlock(password)) {
                Some(Ok(())) => UnlockAttempt::Unlocked,
                _ => UnlockAttempt::Failed("no agent".into()),
            };
        }
        self.hello_answer
            .clone()
            .unwrap_or(UnlockAttempt::Unavailable("Windows Hello is off".into()))
    }
    fn cancel_unlock(&self) -> bool {
        self.cancel_calls
            .lock()
            .unwrap()
            .push(pass_agent::ipc::request_client_pid());
        self.cancel_answer
    }
    fn hello_in_browser(&self) -> bool {
        self.hello_browser
    }
    fn confirm_passkey_create(&self, _rp_id: &str, _user: &str) -> Consent {
        if self.deny_passkeys {
            Consent::Deny
        } else {
            Consent::Approve { item_id: None }
        }
    }
    fn choose_passkey(&self, _rp_id: &str, options: &[PasskeyChoice]) -> Option<usize> {
        (!options.is_empty()).then_some(0)
    }
    fn choose_passkey_for_browser(&self, rp_id: &str, options: &[PasskeyChoice]) -> PasskeyPick {
        *self.passkey_choices.lock().unwrap() += 1;
        self.passkey_pick.unwrap_or_else(|| {
            self.choose_passkey(rp_id, options)
                .map_or(PasskeyPick::Cancelled, PasskeyPick::Chosen)
        })
    }
    fn show_totp_popup(&self, item_id: &str, _title: &str) {
        self.popups.lock().unwrap().push(item_id.into());
    }
    fn notify_lock_state(&self, locked: bool) {
        self.lock_events.lock().unwrap().push(locked);
        if !locked {
            let wanted = self.the_agent().and_then(|a| a.unlock_requested_for());
            self.unlocked_for.lock().unwrap().push(wanted);
        }
    }
    fn verify_user(&self, reason: &Reason) -> Verification {
        if let Some(wait) = self.tick_during_verify {
            std::thread::sleep(wait);
            if let Some(agent) = self.the_agent() {
                agent.tick();
                self.locked_during_verify
                    .lock()
                    .unwrap()
                    .push(agent.is_locked());
            }
        }
        match self.verify {
            Some(answer) => {
                self.verifications.lock().unwrap().push(reason.to_string());
                if answer {
                    Verification::Verified
                } else {
                    Verification::Refused
                }
            }
            None => Verification::Allowed,
        }
    }
    fn verify_item(&self, reason: &Reason, item_id: &str, secret: ItemSecret) -> Verification {
        let kind = match secret {
            ItemSecret::Password => "password",
            ItemSecret::Code {
                follows_fill: false,
            } => "code",
            ItemSecret::Code { follows_fill: true } => "pending code",
            ItemSecret::Passkey => "passkey",
        };
        self.item_checks
            .lock()
            .unwrap()
            .push((item_id.to_string(), kind));
        match secret {
            ItemSecret::Code { follows_fill: true } => Verification::Allowed,
            _ => self.verify_user(reason),
        }
    }
    fn require_verification(&self, reason: &Reason) -> Verification {
        self.required_calls.lock().unwrap().push(reason.to_string());
        match self.required {
            Some(true) => Verification::Verified,
            Some(false) | None => Verification::Refused,
        }
    }
    fn vault_changed(&self) {
        *self.vault_changes.lock().unwrap() += 1;
    }
    fn credential_used(&self) {
        *self.uses.lock().unwrap() += 1;
    }
    fn show_item(&self, item_id: &str) -> bool {
        self.shown_items.lock().unwrap().push(item_id.into());
        true
    }
    fn account_summary(&self) -> Option<AccountSummary> {
        self.account.clone()
    }
    fn show_account(&self, sign_in: bool) -> bool {
        self.account_shown.lock().unwrap().push(sign_in);
        self.account.is_some()
    }
    fn account_peer(&self) -> Option<AccountPeer> {
        self.peer.clone()
    }
    fn handoff_to_extension(
        &self,
        code_challenge: &str,
        device_name: &str,
    ) -> Result<HandoffCode, AccountError> {
        let peer = self.peer.clone().ok_or(AccountError::NotSupported)?;
        self.handoffs
            .lock()
            .unwrap()
            .push(format!("to_extension {code_challenge} {device_name}"));
        if !peer.signed_in {
            return Err(AccountError::InvalidState("not signed in".into()));
        }
        Ok(HandoffCode {
            code: "pac_for_the_extension".into(),
            email: peer.email.unwrap_or_default(),
        })
    }
    fn handoff_begin(&self) -> Result<HandoffRequest, AccountError> {
        let peer = self.peer.clone().ok_or(AccountError::NotSupported)?;
        self.handoffs.lock().unwrap().push("begin".into());
        if peer.signed_in || !peer.accepts_handoff {
            return Err(AccountError::InvalidState("no handoff now".into()));
        }
        Ok(HandoffRequest {
            code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into(),
            device_name: "Passyble on PC".into(),
        })
    }
    fn handoff_finish(&self, code: &str) -> Result<String, AccountError> {
        self.peer.as_ref().ok_or(AccountError::NotSupported)?;
        self.handoffs.lock().unwrap().push(format!("finish {code}"));
        match code {
            "pac_good" => Ok("ada@example.com".into()),
            _ => Err(AccountError::Failed("That sign-in code has expired".into())),
        }
    }
    fn sign_out_from_extension(&self) -> Result<(), AccountError> {
        self.peer.as_ref().ok_or(AccountError::NotSupported)?;
        self.handoffs.lock().unwrap().push("sign_out".into());
        Ok(())
    }
    fn peer_signed_out(&self) -> Result<(), AccountError> {
        self.peer.as_ref().ok_or(AccountError::NotSupported)?;
        self.handoffs.lock().unwrap().push("peer_signed_out".into());
        Ok(())
    }
    fn sync_now(&self) -> Option<SyncReport> {
        *self.sync_calls.lock().unwrap() += 1;
        self.sync_answer.clone()
    }
    fn copy_to_clipboard(&self, text: &str) -> bool {
        if self.copy_supported {
            self.copied.lock().unwrap().push(text.into());
        }
        self.copy_supported
    }
    fn confirm_cross_fill(&self, request: &CrossFillRequest) -> Option<bool> {
        self.cross_requests.lock().unwrap().push(request.clone());
        self.cross
    }
    fn confirm_card_fill(&self, request: &CardFillRequest) -> Option<bool> {
        self.card_requests.lock().unwrap().push(request.clone());
        self.card
    }
    fn show_server_pairing(&self, link: &str) -> bool {
        match &self.pairing {
            Some(shown) => {
                shown.lock().unwrap().push(link.into());
                true
            }
            None => false,
        }
    }
}

fn setup(ui: Arc<FakeUi>) -> (tempfile::TempDir, Arc<Agent>) {
    let dir = tempfile::tempdir().unwrap();
    let agent = Agent::new(
        AgentConfig {
            vault_path: dir.path().join("pass.vault"),
            device_id: "laptop".into(),
            auto_lock: Duration::from_secs(900),
            webdav: None,
            gdrive: None,
            kept_list: None,
        },
        ui.clone(),
    );
    *ui.agent.lock().unwrap() = Some(Arc::downgrade(&agent));
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
            password: "pw".into(),
            urls: vec!["https://github.com".into()],
            totp: Some("JBSWY3DPEHPK3PXP".into()),
            ..Default::default()
        })
        .unwrap()
}

#[test]
fn locked_vault_reports_locked() {
    let (_dir, agent) = setup(Arc::default());
    assert_eq!(call(&agent, "status", json!({}))["result"]["locked"], true);
    assert_eq!(
        call(
            &agent,
            "logins.find",
            json!({ "url": "https://github.com" })
        )["error"]["code"],
        "locked"
    );
    assert_eq!(
        call(&agent, "unlock", json!({}))["error"]["code"],
        "cancelled"
    );
    assert_eq!(
        call(&agent, "nope", json!({}))["error"]["code"],
        "invalid_params"
    );
}

#[test]
fn fill_flow_with_pending_otp() {
    let ui = Arc::new(FakeUi::default());
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    assert_eq!(*ui.lock_events.lock().unwrap(), [false]);
    let item = add_github(&agent);

    let found = call(
        &agent,
        "logins.find",
        json!({ "url": "https://github.com/login" }),
    );
    assert_eq!(found["result"]["items"][0]["id"], item.id.as_str());
    assert_eq!(found["result"]["items"][0]["has_totp"], true);
    assert_eq!(found["result"]["pending_otp"], Value::Null);

    // Another site can't fetch this item by id.
    let stolen = call(
        &agent,
        "logins.fill",
        json!({ "url": "https://evil.example", "id": item.id }),
    );
    assert_eq!(stolen["error"]["code"], "url_mismatch");
    assert_eq!(
        call(
            &agent,
            "totp.get",
            json!({ "url": "https://evil.example", "id": item.id })
        )["error"]["code"],
        "url_mismatch"
    );

    let filled = call(
        &agent,
        "logins.fill",
        json!({ "url": "https://github.com/login", "id": item.id }),
    );
    assert_eq!(filled["result"]["password"], "pw");
    assert_eq!(filled["result"]["totp"]["code"].as_str().unwrap().len(), 6);

    // The 2FA page on the same site gets the code without naming the item.
    let pending = call(
        &agent,
        "logins.find",
        json!({ "url": "https://github.com/sessions/two-factor" }),
    );
    assert_eq!(pending["result"]["pending_otp"]["id"], item.id.as_str());
    let code = call(
        &agent,
        "totp.get",
        json!({ "url": "https://github.com/sessions/two-factor" }),
    );
    assert_eq!(code["result"]["id"], item.id.as_str());
    assert!(code["result"]["remaining_secs"].as_u64().unwrap() <= 30);
    assert_eq!(
        call(&agent, "totp.get", json!({ "url": "https://gitlab.com" }))["error"]["code"],
        "not_found"
    );

    call(
        &agent,
        "totp.popup",
        json!({ "url": "https://github.com", "id": item.id }),
    );
    assert_eq!(
        ui.popups.lock().unwrap().as_slice(),
        std::slice::from_ref(&item.id)
    );

    agent.lock();
    assert_eq!(
        call(&agent, "totp.get", json!({ "url": "https://github.com" }))["error"]["code"],
        "locked"
    );
}

/// Sign in on one subdomain, and the code page on another subdomain of the same site gets the
/// pending code without a second verification. Another site gets nothing.
#[test]
fn pending_otp_on_another_subdomain() {
    let ui = Arc::new(FakeUi {
        verify: Some(true),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let item = agent
        .vault()
        .unwrap()
        .upsert(Item {
            title: "Example".into(),
            username: "alice".into(),
            password: "pw".into(),
            urls: vec!["https://example.com".into()],
            totp: Some("JBSWY3DPEHPK3PXP".into()),
            ..Default::default()
        })
        .unwrap();
    let filled = call(
        &agent,
        "logins.fill",
        json!({ "url": "https://login.example.com/signin", "id": item.id }),
    );
    assert_eq!(filled["result"]["password"], "pw");
    assert_eq!(ui.verifications.lock().unwrap().len(), 1);

    let page = "https://auth.example.com/mfa";
    let found = call(&agent, "logins.find", json!({ "url": page }));
    assert_eq!(found["result"]["pending_otp"]["id"], item.id.as_str());
    let code = call(&agent, "totp.get", json!({ "url": page }));
    assert_eq!(code["result"]["id"], item.id.as_str());
    assert_eq!(code["result"]["code"].as_str().unwrap().len(), 6);
    let by_id = call(&agent, "totp.get", json!({ "url": page, "id": item.id }));
    assert_eq!(by_id["result"]["id"], item.id.as_str());
    assert_eq!(
        ui.verifications.lock().unwrap().len(),
        1,
        "the pending code continues the verified fill"
    );

    for other in ["https://example.org/mfa", "https://example.com.evil.io/"] {
        let found = call(&agent, "logins.find", json!({ "url": other }));
        assert_eq!(found["result"]["pending_otp"], Value::Null, "{other}");
        assert_eq!(
            call(&agent, "totp.get", json!({ "url": other }))["error"]["code"],
            "not_found",
            "{other}"
        );
    }
}

#[test]
fn save_creates_then_updates() {
    let (dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    let r = call(
        &agent,
        "logins.save",
        json!({ "url": "https://www.example.co.uk/signup", "username": "a@b.c", "password": "one" }),
    );
    let id = r["result"]["id"].as_str().unwrap().to_string();
    let r = call(
        &agent,
        "logins.save",
        json!({ "url": "https://www.example.co.uk/settings", "username": "A@b.c", "password": "two" }),
    );
    assert_eq!(r["result"]["id"], id.as_str());
    let item = agent.vault().unwrap().get(id).unwrap();
    assert_eq!(item.title, "example.co.uk");
    assert_eq!(item.urls, ["https://www.example.co.uk"]);
    assert_eq!(item.password, "two");

    let bytes = std::fs::read(dir.path().join("pass.vault")).unwrap();
    let reopened = Vault::unlock(bytes, "master".into(), "x".into()).unwrap();
    assert_eq!(reopened.items().len(), 1);
}

#[test]
fn passkey_register_then_sign_in() {
    use p256::ecdsa::signature::Verifier;
    use p256::pkcs8::DecodePublicKey;

    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    let create = json!({
        "origin": "https://login.example.com",
        "rp": { "id": "example.com", "name": "Example" },
        "user": { "id": b64url_encode(b"u1".to_vec()), "name": "alice", "displayName": "Alice" },
        "challenge": b64url_encode(vec![1; 32]),
        "pubKeyCredParams": [{ "type": "public-key", "alg": -8 }, { "type": "public-key", "alg": -7 }],
    });
    let reg = call(&agent, "passkey.create", create.clone())["result"].clone();
    let credential_id = reg["credentialId"].as_str().unwrap().to_string();
    let client_data: Value = serde_json::from_slice(
        &b64url_decode(reg["clientDataJSON"].as_str().unwrap().into()).unwrap(),
    )
    .unwrap();
    assert_eq!(client_data["type"], "webauthn.create");
    assert_eq!(client_data["origin"], "https://login.example.com");

    let mut again = create.clone();
    again["excludeCredentials"] = json!([{ "id": credential_id }]);
    assert_eq!(
        call(&agent, "passkey.create", again)["error"]["code"],
        "invalid_state"
    );

    // RP ID that doesn't belong to the origin.
    let mut bad = create.clone();
    bad["rp"]["id"] = "other.com".into();
    assert_eq!(
        call(&agent, "passkey.create", bad)["error"]["code"],
        "url_mismatch"
    );

    let mut rsa_only = create;
    rsa_only["pubKeyCredParams"] = json!([{ "type": "public-key", "alg": -257 }]);
    assert_eq!(
        call(&agent, "passkey.create", rsa_only)["error"]["code"],
        "not_supported"
    );

    let get = json!({ "origin": "https://example.com", "rpId": "example.com", "challenge": b64url_encode(vec![2; 32]) });
    let assertion = call(&agent, "passkey.get", get)["result"].clone();
    assert_eq!(assertion["credentialId"], credential_id.as_str());
    assert_eq!(
        assertion["userHandle"],
        b64url_encode(b"u1".to_vec()).as_str()
    );

    let decode = |k: &str| b64url_decode(assertion[k].as_str().unwrap().into()).unwrap();
    let key = p256::ecdsa::VerifyingKey::from_public_key_der(
        &b64url_decode(reg["publicKey"].as_str().unwrap().into()).unwrap(),
    )
    .unwrap();
    let mut signed = decode("authenticatorData");
    signed.extend(pass_core::sha256(decode("clientDataJSON")));
    key.verify(
        &signed,
        &p256::ecdsa::Signature::from_der(&decode("signature")).unwrap(),
    )
    .unwrap();

    let none = json!({ "origin": "https://example.org", "challenge": b64url_encode(vec![2; 32]) });
    assert_eq!(
        call(&agent, "passkey.get", none)["error"]["code"],
        "not_found"
    );
}

/// The flags byte of authenticator data (after the 32-byte rpIdHash).
fn uv_flag(auth_data_b64: &Value) -> bool {
    b64url_decode(auth_data_b64.as_str().unwrap().into()).unwrap()[32] & 0x04 != 0
}

#[test]
fn uv_flag_only_after_real_verification() {
    let create = json!({
        "origin": "https://example.com",
        "rp": { "id": "example.com", "name": "Example" },
        "user": { "id": b64url_encode(b"u1".to_vec()), "name": "alice" },
        "challenge": b64url_encode(vec![1; 32]),
    });
    let get = json!({ "origin": "https://example.com", "challenge": b64url_encode(vec![2; 32]) });
    for (verify, uv) in [(None, false), (Some(true), true)] {
        let (_dir, agent) = setup(Arc::new(FakeUi {
            verify,
            ..Default::default()
        }));
        agent.create_vault("master").unwrap();
        let reg = call(&agent, "passkey.create", create.clone())["result"].clone();
        assert_eq!(uv_flag(&reg["authenticatorData"]), uv, "{verify:?}");
        // The copy inside the attestation object says the same.
        let auth_data = b64url_decode(reg["authenticatorData"].as_str().unwrap().into()).unwrap();
        let att = b64url_decode(reg["attestationObject"].as_str().unwrap().into()).unwrap();
        assert!(att
            .windows(auth_data.len())
            .any(|w| w == auth_data.as_slice()));
        let assertion = call(&agent, "passkey.get", get.clone())["result"].clone();
        assert_eq!(uv_flag(&assertion["authenticatorData"]), uv, "{verify:?}");
        // User presence is always reported.
        assert_ne!(
            b64url_decode(assertion["authenticatorData"].as_str().unwrap().into()).unwrap()[32]
                & 0x01,
            0
        );
    }
}

#[test]
fn passkeys_need_a_web_origin() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    for origin in [
        "null",
        "file:///C:/page.html",
        "chrome-extension://abcdef",
        "data:text/html,hi",
        "https://example.com/path",
        "ftp://example.com",
        "",
    ] {
        let create = json!({
            "origin": origin,
            "rp": { "id": "example.com" },
            "user": { "id": b64url_encode(b"u1".to_vec()), "name": "alice" },
            "challenge": b64url_encode(vec![1; 32]),
        });
        assert_eq!(
            call(&agent, "passkey.create", create)["error"]["code"],
            "url_mismatch",
            "{origin}"
        );
        let mut no_rp = json!({
            "origin": origin,
            "rp": {},
            "user": { "id": b64url_encode(b"u1".to_vec()), "name": "alice" },
            "challenge": b64url_encode(vec![1; 32]),
        });
        assert_eq!(
            call(&agent, "passkey.create", no_rp.clone())["error"]["code"],
            "url_mismatch",
            "{origin}"
        );
        no_rp["rp"] = json!({ "id": "" });
        assert_eq!(
            call(&agent, "passkey.create", no_rp)["error"]["code"],
            "url_mismatch",
            "{origin}"
        );
        for rp_id in [json!("example.com"), Value::Null] {
            let get =
                json!({ "origin": origin, "rpId": rp_id, "challenge": b64url_encode(vec![2; 32]) });
            assert_eq!(
                call(&agent, "passkey.get", get)["error"]["code"],
                "url_mismatch",
                "{origin}"
            );
        }
    }
    // A port is part of the origin.
    let create = json!({
        "origin": "https://example.com:8443",
        "rp": { "id": "example.com" },
        "user": { "id": b64url_encode(b"u1".to_vec()), "name": "alice" },
        "challenge": b64url_encode(vec![1; 32]),
    });
    assert!(call(&agent, "passkey.create", create)["result"]["credentialId"].is_string());
}

#[test]
fn declined_passkey_is_cancelled() {
    let (_dir, agent) = setup(Arc::new(FakeUi {
        deny_passkeys: true,
        ..Default::default()
    }));
    agent.create_vault("master").unwrap();
    let create = json!({
        "origin": "https://example.com", "rp": { "name": "Example" },
        "user": { "id": "dTE", "name": "alice" }, "challenge": "AAAA",
    });
    assert_eq!(
        call(&agent, "passkey.create", create)["error"]["code"],
        "cancelled"
    );
}

#[test]
fn picks_up_changes_written_by_a_sync_client() {
    let (dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    let path = dir.path().join("pass.vault");

    // Another device edits its copy; OneDrive replaces our file and leaves a conflict copy.
    let phone = Vault::unlock(
        std::fs::read(&path).unwrap(),
        "master".into(),
        "phone".into(),
    )
    .unwrap();
    phone
        .upsert(Item {
            title: "From phone".into(),
            urls: vec!["a.com".into()],
            ..Default::default()
        })
        .unwrap();
    std::thread::sleep(Duration::from_millis(20));
    std::fs::write(&path, phone.serialize().unwrap()).unwrap();
    phone
        .upsert(Item {
            title: "Conflict copy".into(),
            ..Default::default()
        })
        .unwrap();
    std::fs::write(
        dir.path().join("pass-DESKTOP-42.vault"),
        phone.serialize().unwrap(),
    )
    .unwrap();

    let found = call(&agent, "logins.find", json!({ "url": "https://a.com" }));
    assert_eq!(found["result"]["items"][0]["title"], "From phone");

    agent.lock();
    agent.unlock("master").unwrap();
    let titles: Vec<String> = agent
        .vault()
        .unwrap()
        .items()
        .into_iter()
        .map(|i| i.title)
        .collect();
    assert_eq!(titles, ["Conflict copy", "From phone"]);
    assert!(!dir.path().join("pass-DESKTOP-42.vault").exists());
}

/// Another device's copy of the vault in `path` with one item titled `title`.
fn copy_with_item(path: &std::path::Path, title: &str) -> Vec<u8> {
    let other = Vault::unlock(
        std::fs::read(path).unwrap(),
        "master".into(),
        "phone".into(),
    )
    .unwrap();
    other
        .upsert(Item {
            title: title.into(),
            ..Default::default()
        })
        .unwrap();
    other.serialize().unwrap()
}

fn vault_titles(agent: &Agent) -> Vec<String> {
    let mut titles: Vec<String> = agent
        .vault()
        .unwrap()
        .items()
        .into_iter()
        .map(|i| i.title)
        .collect();
    titles.sort();
    titles
}

#[test]
fn unlock_leaves_manual_backups_alone() {
    let (dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    let path = dir.path().join("pass.vault");
    let backups = [
        "pass-backup.vault",
        "pass-old.vault",
        "pass (old).vault",
        "pass backup.vault",
        "pass-2024-01-01.vault",
        "pass.bak.vault",
        "pass-unsaved-abc.vault",
        "pass-unsaved-.vault",
        "pass (conflicted copy.vault",
        "pass (1)x.vault",
        "pass.sync-conflict-2024-x.vault",
        "passport.vault",
        "pass-DESKTOP-.vault",
    ];
    for name in backups {
        std::fs::write(dir.path().join(name), copy_with_item(&path, "Backup")).unwrap();
    }
    agent.lock();
    agent.unlock("master").unwrap();
    for name in backups {
        assert!(dir.path().join(name).exists(), "{name} was removed");
    }
    assert!(vault_titles(&agent).is_empty(), "a backup was merged");
}

#[test]
fn unlock_merges_and_removes_each_kind_of_conflict_copy() {
    let (dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    let path = dir.path().join("pass.vault");
    let copies = [
        "pass-unsaved-1700000000000.vault",
        "pass-DESKTOP-42.vault",
        "pass-DESKTOP-ABC123-2.vault",
        "pass-LAPTOP.vault",
        "pass (Anna's conflicted copy 2024-05-01).vault",
        "pass (Anna's conflicted copy 2024-05-01) (1).vault",
        "pass.sync-conflict-20240501-123456-ABCDEFG.vault",
        "pass.sync-conflict-20240501-123456-ABCDEFG-HIJKLMN.vault",
        "pass (1).vault",
        "pass (12).vault",
    ];
    for (n, name) in copies.iter().enumerate() {
        std::fs::write(
            dir.path().join(name),
            copy_with_item(&path, &format!("Copy {n:02}")),
        )
        .unwrap();
    }
    agent.lock();
    agent.unlock("master").unwrap();
    for name in copies {
        assert!(!dir.path().join(name).exists(), "{name} was not removed");
    }
    let expected: Vec<String> = (0..copies.len()).map(|n| format!("Copy {n:02}")).collect();
    assert_eq!(vault_titles(&agent), expected);
}

#[test]
fn icloud_drive_copies_are_merged_only_in_icloud_drive() {
    let others = [
        "pass 1.vault",
        "pass 02.vault",
        "pass 100.vault",
        "pass 2024.vault",
        "pass2.vault",
    ];
    for icloud in [true, false] {
        let (dir, agent) = setup(Arc::default());
        let folder = if icloud {
            dir.path()
                .join("Library")
                .join("Mobile Documents")
                .join("com~apple~CloudDocs")
                .join("Pass")
        } else {
            dir.path().join("Documents")
        };
        std::fs::create_dir_all(&folder).unwrap();
        let path = folder.join("pass.vault");
        let mut config = agent.config();
        config.vault_path = path.clone();
        agent.reconfigure(config);
        agent.create_vault("master").unwrap();
        std::fs::write(folder.join("pass 2.vault"), copy_with_item(&path, "Copy")).unwrap();
        for name in others {
            std::fs::write(folder.join(name), copy_with_item(&path, "Other")).unwrap();
        }
        agent.lock();
        agent.unlock("master").unwrap();
        assert_eq!(
            folder.join("pass 2.vault").exists(),
            !icloud,
            "icloud {icloud}"
        );
        let expected: Vec<String> = if icloud {
            vec!["Copy".into()]
        } else {
            Vec::new()
        };
        assert_eq!(vault_titles(&agent), expected, "icloud {icloud}");
        for name in others {
            assert!(folder.join(name).exists(), "{name} was removed");
        }
    }
}

#[test]
fn lock_method_locks_and_saves() {
    let ui = Arc::new(FakeUi::default());
    let (dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let path = dir.path().join("pass.vault");
    add_github(&agent);
    let features = call(&agent, "status", json!({}))["result"]["features"].clone();
    assert!(features.as_array().unwrap().contains(&json!("lock")));

    let locked = call(&agent, "lock", json!({}));
    assert_eq!(locked["result"], json!({ "locked": true }));
    assert!(agent.is_locked());
    assert_eq!(*ui.lock_events.lock().unwrap(), [false, true]);
    assert_eq!(titles_in(&path), ["GitHub"], "saved before locking");
    assert_eq!(
        code(&call(
            &agent,
            "logins.get_for_edit",
            json!({ "url": "https://github.com", "id": "x" })
        )),
        "locked"
    );

    // Idempotent: again, with no new lock event.
    let again = call(&agent, "lock", json!({}));
    assert_eq!(again["result"], json!({ "locked": true }));
    assert_eq!(*ui.lock_events.lock().unwrap(), [false, true]);
    agent.unlock("master").unwrap();
    assert_eq!(vault_titles(&agent), ["GitHub"]);
}

#[test]
fn lock_method_keeps_edits_that_could_not_be_saved() {
    let ui = Arc::new(FakeUi::default());
    let (dir, agent) = setup(ui);
    agent.create_vault("master").unwrap();
    let path = dir.path().join("pass.vault");
    add_github(&agent);
    let blocked = block_writes(&path);
    let locked = call(&agent, "lock", json!({}));
    assert_eq!(locked["result"], json!({ "locked": true }));
    assert!(agent.is_locked());
    assert!(titles_in(&path).is_empty());
    drop(blocked);
    agent.unlock("master").unwrap();
    assert_eq!(vault_titles(&agent), ["GitHub"]);
    assert_eq!(titles_in(&path), ["GitHub"]);
}

#[test]
fn auto_lock() {
    let ui = Arc::new(FakeUi::default());
    let dir = tempfile::tempdir().unwrap();
    let agent = Agent::new(
        AgentConfig {
            vault_path: dir.path().join("v.vault"),
            device_id: "d".into(),
            auto_lock: Duration::ZERO,
            webdav: None,
            gdrive: None,
            kept_list: None,
        },
        ui.clone(),
    );
    agent.create_vault("m").unwrap();
    agent.tick();
    assert!(agent.is_locked());
    assert_eq!(*ui.lock_events.lock().unwrap(), [false, true]);
}

#[test]
fn browsing_alone_does_not_keep_the_vault_unlocked() {
    let dir = tempfile::tempdir().unwrap();
    let agent = Agent::new(
        AgentConfig {
            vault_path: dir.path().join("v.vault"),
            device_id: "d".into(),
            // Sleeps only ever run long: the "still unlocked" check gets the slack (700 ms).
            auto_lock: Duration::from_millis(1500),
            webdav: None,
            gdrive: None,
            kept_list: None,
        },
        Arc::new(FakeUi::default()),
    );
    agent.create_vault("m").unwrap();
    add_github(&agent);
    let find = json!({ "url": "https://github.com/login" });
    std::thread::sleep(Duration::from_millis(800));
    // The extension looks up every page with a login form: not activity.
    assert!(call(&agent, "logins.find", find.clone())["result"]["items"][0]["id"].is_string());
    std::thread::sleep(Duration::from_millis(800));
    agent.tick();
    assert!(agent.is_locked());
    // Soft-locked: still listed, marked locked.
    let listed = call(&agent, "logins.find", find);
    assert_eq!(listed["result"]["locked"], true);
    assert_eq!(listed["result"]["items"][0]["username"], "octo");

    // A fill is.
    agent.unlock("m").unwrap();
    let id = agent.vault().unwrap().items()[0].id.clone();
    std::thread::sleep(Duration::from_millis(800));
    let fill = json!({ "url": "https://github.com/login", "id": id });
    assert_eq!(
        call(&agent, "logins.fill", fill)["result"]["password"],
        "pw"
    );
    std::thread::sleep(Duration::from_millis(800));
    agent.tick();
    assert!(!agent.is_locked());
}

#[test]
fn reconfigure_applies_live() {
    let ui = Arc::new(FakeUi::default());
    let (dir, agent) = setup(ui.clone());
    agent.create_vault("m").unwrap();

    // A new auto-lock time applies without locking.
    let mut config = agent.config();
    config.auto_lock = Duration::from_secs(60);
    assert!(!agent.reconfigure(config.clone()));
    assert!(!agent.is_locked());
    assert_eq!(agent.config().auto_lock, Duration::from_secs(60));

    // A different vault file locks, and nothing is written to the new place.
    config.vault_path = dir.path().join("other.vault");
    assert!(agent.reconfigure(config));
    assert!(agent.is_locked());
    assert!(!agent.vault_exists());
    assert!(dir.path().join("pass.vault").exists());
    assert_eq!(*ui.lock_events.lock().unwrap(), [false, true]);
}

#[test]
fn window_matching_for_auto_type() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("m").unwrap();
    let vault = agent.vault().unwrap();
    vault
        .upsert(Item {
            title: "Steam".into(),
            urls: vec!["windows:steam.exe".into()],
            ..Default::default()
        })
        .unwrap();
    vault
        .upsert(Item {
            title: "Discord".into(),
            urls: vec!["https://discord.com".into()],
            ..Default::default()
        })
        .unwrap();
    let titles = |w: &str, e: &str| {
        agent
            .find_for_window(w, e)
            .into_iter()
            .map(|i| i.title)
            .collect::<Vec<_>>()
    };
    assert_eq!(titles("Sign in", "steam.exe"), ["Steam"]);
    assert_eq!(titles("Discord - Login", "discord.exe"), ["Discord"]);
    assert!(titles("Notepad", "notepad.exe").is_empty());

    // Only a site name in the title (a chat channel, a document, a browser tab) is a weak match:
    // auto-type asks before typing it.
    vault
        .upsert(Item {
            title: "Work account".into(),
            urls: vec!["https://github.com".into()],
            ..Default::default()
        })
        .unwrap();
    let kinds = |w: &str, e: &str| {
        agent
            .match_window(w, e)
            .into_iter()
            .map(|(m, i)| (m, i.title))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        kinds("#github-alerts - Slack", "slack.exe"),
        [(WindowMatch::SiteName, "Work account".to_string())]
    );
    assert_eq!(
        kinds("Steam", "steam.exe"),
        [(WindowMatch::Pinned, "Steam".to_string())]
    );
    assert_eq!(
        kinds("Discord", "discord.exe"),
        [(WindowMatch::Title, "Discord".to_string())]
    );

    // macOS pins by bundle ID: exactly, in any case, never by prefix, and never as a site name.
    vault
        .upsert(Item {
            title: "Shell".into(),
            urls: vec!["macos:com.apple.Terminal".into()],
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        kinds("bash", "com.apple.Terminal"),
        [(WindowMatch::Pinned, "Shell".to_string())]
    );
    assert_eq!(
        kinds("bash", "COM.APPLE.TERMINAL"),
        [(WindowMatch::Pinned, "Shell".to_string())]
    );
    assert!(kinds("bash", "com.apple.TerminalFoo").is_empty());
    assert!(kinds("bash", "com.apple").is_empty());
    assert!(kinds("Apple Terminal news", "com.example.reader").is_empty());
    // A Windows pin with the same name still pins (one vault, both desktops).
    assert_eq!(
        kinds("Sign in", "steam.exe"),
        [(WindowMatch::Pinned, "Steam".to_string())]
    );
}

/// Makes every write of `path` fail (its temporary file can't be created) until the returned
/// guard is dropped.
fn block_writes(path: &std::path::Path) -> impl Drop {
    struct Unblock(std::path::PathBuf);
    impl Drop for Unblock {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir(&self.0);
        }
    }
    let tmp = path.with_extension("vault.tmp");
    std::fs::create_dir(&tmp).unwrap();
    Unblock(tmp)
}

fn titles_in(path: &std::path::Path) -> Vec<String> {
    Vault::unlock(std::fs::read(path).unwrap(), "master".into(), "x".into())
        .unwrap()
        .items()
        .into_iter()
        .map(|i| i.title)
        .collect()
}

#[test]
fn a_failed_write_is_retried_by_the_next_save() {
    let (dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    let path = dir.path().join("pass.vault");
    add_github(&agent);
    {
        let _blocked = block_writes(&path);
        assert!(agent.save().is_err());
    }
    // The vault no longer looks dirty to pass-core, but the edit still has to reach the file.
    agent.save().unwrap();
    assert_eq!(titles_in(&path), ["GitHub"]);
}

#[test]
fn locking_keeps_edits_that_could_not_be_saved() {
    let ui = Arc::new(FakeUi::default());
    let (dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let path = dir.path().join("pass.vault");
    add_github(&agent);
    let blocked = block_writes(&path);
    agent.save_and_lock().unwrap();
    assert!(agent.is_locked());
    assert_eq!(*ui.lock_events.lock().unwrap(), [false, true]);
    assert!(
        titles_in(&path).is_empty(),
        "the vault file itself is unchanged"
    );
    let stashed: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("pass-unsaved-") && n.ends_with(".vault"))
        .collect();
    assert_eq!(stashed.len(), 1);
    drop(blocked);

    // The next unlock merges the copy in and removes it.
    agent.unlock("master").unwrap();
    let titles: Vec<String> = agent
        .vault()
        .unwrap()
        .items()
        .into_iter()
        .map(|i| i.title)
        .collect();
    assert_eq!(titles, ["GitHub"]);
    assert!(!dir.path().join(&stashed[0]).exists());
    assert_eq!(titles_in(&path), ["GitHub"]);
}

#[test]
fn auto_lock_keeps_edits_that_could_not_be_saved() {
    let ui = Arc::new(FakeUi::default());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pass.vault");
    let agent = Agent::new(
        AgentConfig {
            vault_path: path.clone(),
            device_id: "d".into(),
            auto_lock: Duration::ZERO,
            webdav: None,
            gdrive: None,
            kept_list: None,
        },
        ui,
    );
    agent.create_vault("master").unwrap();
    add_github(&agent);
    {
        let _blocked = block_writes(&path);
        agent.tick();
    }
    assert!(agent.is_locked());
    agent.unlock("master").unwrap();
    assert_eq!(agent.vault().unwrap().items()[0].title, "GitHub");
}

#[cfg(unix)]
#[test]
fn ipc_roundtrip() {
    use interprocess::local_socket::traits::Stream as _;
    use std::io::{BufRead, BufReader, Write};

    let runtime = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_RUNTIME_DIR", runtime.path());
    let (_dir, agent) = setup(Arc::default());
    let server = pass_agent::ipc::Server::start(agent).unwrap();

    let (recv, mut send) = pass_agent::ipc::connect().unwrap().split();
    let mut lines = BufReader::new(recv).lines();
    send.write_all(b"{\"id\":5,\"method\":\"status\",\"params\":{}}\n")
        .unwrap();
    let reply: Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    assert_eq!(reply["id"], 5);
    assert_eq!(reply["result"]["locked"], true);
    assert_eq!(reply["result"]["version"], pass_agent::VERSION);

    server.notify("lock_state", json!({ "locked": true }));
    let event: Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    assert_eq!(event["event"], "lock_state");
}

#[test]
fn server_pair_shows_the_dialog_without_applying_anything() {
    const LINK: &str = "pass+server://pass.example.com:8443/dav/alice/personal.vault?v=1&user=alice&token=pst_t&name=Laptop&pin=sha256:novcWsacBi2IRLwBIN7QCQVpLOAGPBXRFHKFijjSE-g";
    let ui = Arc::new(FakeUi {
        pairing: Some(Mutex::default()),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    // Works while locked: the desktop app asks the user before anything is stored.
    let r = call(
        &agent,
        "server.pair",
        json!({ "link": format!("  {LINK}
") }),
    );
    assert_eq!(r["result"]["shown"], true, "{r}");
    assert_eq!(r["result"]["host"], "pass.example.com:8443");
    assert_eq!(r["result"]["user"], "alice");
    assert!(r["result"].get("token").is_none());
    assert_eq!(*ui.pairing.as_ref().unwrap().lock().unwrap(), [LINK]);
    assert!(agent.config().webdav.is_none());

    for bad in [
        json!({}),
        json!({ "link": "https://me:pw@example.com" }),
        json!({ "link": "ftp://example.com" }),
        json!({ "link": "not an address" }),
        json!({ "link": "https://example.com/?x=1" }),
        // Unencrypted over the internet: refused like core's `normalize_server_url` does.
        json!({ "link": "http://pass.example.com:8443" }),
        json!({ "link": "x".repeat(5000) }),
    ] {
        assert_eq!(
            call(&agent, "server.pair", bad)["error"]["code"],
            "invalid_params"
        );
    }
    assert_eq!(ui.pairing.as_ref().unwrap().lock().unwrap().len(), 1);
    assert_eq!(r["result"]["sign_in"], false);

    // A token-less sign-in link (`pass-server invite`) opens the sign-in form.
    const SIGN_IN: &str = "pass+server://pass.example.com:8443/?v=1&user=bob";
    let r = call(&agent, "server.pair", json!({ "link": SIGN_IN }));
    assert_eq!(r["result"]["shown"], true, "{r}");
    assert_eq!(r["result"]["sign_in"], true);
    assert_eq!(r["result"]["user"], "bob");
    assert_eq!(ui.pairing.as_ref().unwrap().lock().unwrap().len(), 2);

    // A plain server address opens the sign-in form with the address (the app checks the
    // certificate there).
    for (typed, address, host) in [
        (
            " pass.example.com:8443/ ",
            "https://pass.example.com:8443",
            "pass.example.com:8443",
        ),
        (
            "https://example.org/pass/",
            "https://example.org/pass",
            "example.org",
        ),
        (
            "http://10.0.0.5:8080",
            "http://10.0.0.5:8080",
            "10.0.0.5:8080",
        ),
    ] {
        let r = call(&agent, "server.pair", json!({ "link": typed }));
        assert_eq!(r["result"]["shown"], true, "{r}");
        assert_eq!(r["result"]["sign_in"], true);
        assert_eq!(r["result"]["address"], true);
        assert_eq!(r["result"]["host"], host);
        assert!(r["result"]["user"].is_null());
        assert_eq!(
            ui.pairing.as_ref().unwrap().lock().unwrap().last().unwrap(),
            address
        );
    }

    // A UI without the dialog.
    let (_dir, agent) = setup(Arc::default());
    assert_eq!(
        call(&agent, "server.pair", json!({ "link": LINK }))["error"]["code"],
        "not_supported"
    );
}

#[test]
fn per_fill_verification_gates_secrets() {
    // Refused: nothing leaves the vault.
    let ui = Arc::new(FakeUi {
        verify: Some(false),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let item = add_github(&agent);
    let url = "https://github.com/login";
    let refused = call(&agent, "logins.fill", json!({ "url": url, "id": item.id }));
    assert_eq!(refused["error"]["code"], "cancelled");
    assert!(refused.get("result").is_none());
    assert_eq!(
        call(&agent, "totp.get", json!({ "url": url, "id": item.id }))["error"]["code"],
        "cancelled"
    );
    assert_eq!(
        call(&agent, "totp.popup", json!({ "url": url, "id": item.id }))["error"]["code"],
        "cancelled"
    );
    assert!(ui.popups.lock().unwrap().is_empty());
    // Listing matches (no secrets) is not gated.
    assert!(
        call(&agent, "logins.find", json!({ "url": url }))["result"]["items"][0]["id"].is_string()
    );
    assert_eq!(ui.verifications.lock().unwrap().len(), 3);
    assert!(ui.verifications.lock().unwrap()[0].contains("GitHub"));

    // Allowed: the fill asks once; the 2FA code of the login just filled doesn't ask again.
    let ui = Arc::new(FakeUi {
        verify: Some(true),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let item = add_github(&agent);
    let filled = call(&agent, "logins.fill", json!({ "url": url, "id": item.id }));
    assert_eq!(filled["result"]["password"], "pw");
    assert_eq!(ui.verifications.lock().unwrap().len(), 1);
    let code = call(
        &agent,
        "totp.get",
        json!({ "url": "https://github.com/sessions/two-factor" }),
    );
    assert_eq!(code["result"]["id"], item.id.as_str());
    call(&agent, "totp.popup", json!({ "url": url, "id": item.id }));
    assert_eq!(ui.verifications.lock().unwrap().len(), 1);
}

#[test]
fn declined_verification_cancels_passkey_sign_in() {
    let ui = Arc::new(FakeUi::default());
    let (_dir, agent) = setup(ui);
    agent.create_vault("master").unwrap();
    let created = call(
        &agent,
        "passkey.create",
        json!({
            "origin": "https://webauthn.io",
            "rp": { "id": "webauthn.io", "name": "WebAuthn.io" },
            "user": { "id": b64url_encode(b"user-1".to_vec()), "name": "alice" },
            "challenge": b64url_encode(b"challenge".to_vec()),
            "pubKeyCredParams": [ { "type": "public-key", "alg": -7 } ],
        }),
    );
    assert!(created["result"]["credentialId"].is_string(), "{created}");

    // Same vault file, a UI that refuses verification.
    let refusing = Arc::new(FakeUi {
        verify: Some(false),
        ..Default::default()
    });
    let agent2 = Agent::new(agent.config(), refusing.clone());
    agent.lock();
    agent2.unlock("master").unwrap();
    let get = call(
        &agent2,
        "passkey.get",
        json!({
            "origin": "https://webauthn.io",
            "rpId": "webauthn.io",
            "challenge": b64url_encode(b"challenge-2".to_vec()),
        }),
    );
    assert_eq!(get["error"]["code"], "cancelled");
    assert_eq!(refusing.verifications.lock().unwrap().len(), 1);
}

/// Registers a passkey for `name` at example.com and returns its b64url credential ID.
fn register_example_passkey(agent: &Agent, name: &str) -> String {
    let created = call(
        agent,
        "passkey.create",
        json!({
            "origin": "https://login.example.com",
            "rp": { "id": "example.com", "name": "Example" },
            "user": { "id": b64url_encode(name.as_bytes().to_vec()), "name": name },
            "challenge": b64url_encode(vec![1; 32]),
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
        }),
    );
    created["result"]["credentialId"]
        .as_str()
        .unwrap_or_else(|| panic!("{created}"))
        .to_string()
}

fn find_example_passkeys(agent: &Agent, extra: Value) -> Value {
    let mut params = json!({ "origin": "https://login.example.com", "rpId": "example.com" });
    for (k, v) in extra.as_object().unwrap() {
        params[k] = v.clone();
    }
    call(agent, "passkey.find", params)
}

#[test]
fn passkey_find_lists_the_sites_passkeys_without_secrets() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    add_github(&agent);
    let alice = register_example_passkey(&agent, "alice");
    let bob = register_example_passkey(&agent, "bob");

    let found = find_example_passkeys(&agent, json!({}));
    let items = found["result"]["items"].as_array().unwrap().clone();
    assert_eq!(items.len(), 2, "{found}");
    assert_eq!(found["result"]["locked"], false);
    assert_eq!(found["result"]["rp_id"], "example.com");
    let mut names: Vec<&str> = items
        .iter()
        .map(|i| i["user_name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["alice", "bob"]);
    for item in &items {
        // Which login, which passkey: nothing more (no key, no user handle).
        let mut keys: Vec<&String> = item.as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "credential_id",
                "id",
                "title",
                "user_display_name",
                "user_name",
                "vault_id"
            ]
        );
        assert!(item["id"].as_str().is_some_and(|id| !id.is_empty()));
    }

    // The site's allowCredentials narrows it, like passkey.get.
    let only = find_example_passkeys(&agent, json!({ "allowCredentials": [{ "id": bob }] }));
    let only = only["result"]["items"].as_array().unwrap().clone();
    assert_eq!(only.len(), 1);
    assert_eq!(only[0]["credential_id"], bob.as_str());
    assert_eq!(
        find_example_passkeys(&agent, json!({ "allowCredentials": [{ "id": "AAAA" }] }))["result"]
            ["items"],
        json!([])
    );
    assert_eq!(
        code(&find_example_passkeys(
            &agent,
            json!({ "allowCredentials": [{ "id": "not base64url!" }] })
        )),
        "invalid_params"
    );

    // The RP ID rules of passkey.get: the default is the origin's host, another site is refused.
    let default_rp = call(
        &agent,
        "passkey.find",
        json!({ "origin": "https://example.com" }),
    );
    assert_eq!(default_rp["result"]["items"].as_array().unwrap().len(), 2);
    let sub = call(
        &agent,
        "passkey.find",
        json!({ "origin": "https://login.example.com" }),
    );
    assert_eq!(sub["result"]["rp_id"], "login.example.com");
    assert_eq!(sub["result"]["items"], json!([]), "an exact RP ID match");
    for (origin, rp_id) in [
        ("https://login.example.com", "other.com"),
        ("https://example.com.evil.test", "example.com"),
        ("null", "example.com"),
    ] {
        let refused = call(
            &agent,
            "passkey.find",
            json!({ "origin": origin, "rpId": rp_id }),
        );
        assert_eq!(code(&refused), "url_mismatch", "{origin} {rp_id}");
    }

    // Soft-locked: the same list from the kept summaries, said to be locked. Fully locked: none.
    agent.lock_as(LockKind::Soft);
    let kept = find_example_passkeys(&agent, json!({}));
    assert_eq!(kept["result"]["locked"], true, "{kept}");
    assert_eq!(kept["result"]["items"].as_array().unwrap().len(), 2);
    agent.unlock("master").unwrap();
    agent.lock_as(LockKind::Full);
    assert_eq!(code(&find_example_passkeys(&agent, json!({}))), "locked");
    let _ = alice;
}

#[test]
fn a_passkey_picked_in_the_browser_signs_in_without_a_second_choice() {
    let ui = Arc::new(FakeUi {
        verify: Some(true),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let alice = register_example_passkey(&agent, "alice");
    let bob = register_example_passkey(&agent, "bob");
    let items = find_example_passkeys(&agent, json!({}))["result"]["items"].clone();
    let item_of = |cid: &str| {
        items
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["credential_id"] == cid)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let get = |extra: Value| {
        let mut params = json!({ "origin": "https://login.example.com", "rpId": "example.com",
            "challenge": b64url_encode(vec![2; 32]) });
        for (k, v) in extra.as_object().unwrap() {
            params[k] = v.clone();
        }
        call(&agent, "passkey.get", params)
    };

    // The page's own request: which one? (the prompt window).
    assert!(get(json!({}))["result"]["credentialId"].is_string());
    assert_eq!(*ui.passkey_choices.lock().unwrap(), 1);

    // Picked in the extension's prompt or menu: that passkey, no window, and the per-fill check
    // knows the login it is for.
    ui.item_checks.lock().unwrap().clear();
    let picked = get(json!({ "id": item_of(&bob), "credentialId": bob }));
    assert_eq!(picked["result"]["credentialId"], bob.as_str(), "{picked}");
    assert_eq!(*ui.passkey_choices.lock().unwrap(), 1, "no second choice");
    assert_eq!(
        *ui.item_checks.lock().unwrap(),
        [(item_of(&bob), "passkey")]
    );
    // Its UV flag comes from that check (Verified here).
    assert!(uv_flag(&picked["result"]["authenticatorData"]));

    // A passkey of another login than the one named: nothing to sign with.
    assert_eq!(
        code(&get(json!({ "id": item_of(&bob), "credentialId": alice }))),
        "not_found"
    );
    assert_eq!(
        code(&get(json!({ "id": item_of(&bob), "credentialId": "%%" }))),
        "invalid_params"
    );
    assert_eq!(*ui.passkey_choices.lock().unwrap(), 1);
}

/// The params of a `passkey.create` at login.example.com for `name`, with `extra` on top.
fn example_create(name: &str, extra: Value) -> Value {
    let mut params = json!({
        "origin": "https://login.example.com",
        "rp": { "id": "example.com", "name": "Example" },
        "user": { "id": b64url_encode(name.as_bytes().to_vec()), "name": name },
        "challenge": b64url_encode(vec![1; 32]),
        "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
    });
    for (k, v) in extra.as_object().unwrap() {
        params[k] = v.clone();
    }
    params
}

fn add_example_login(agent: &Agent, username: &str) -> Item {
    agent
        .vault()
        .unwrap()
        .upsert(Item {
            title: "Example".into(),
            username: username.into(),
            password: "pw".into(),
            urls: vec!["https://example.com".into()],
            ..Default::default()
        })
        .unwrap()
}

#[test]
fn passkey_create_options_say_what_the_save_card_offers_without_secrets() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    add_github(&agent);
    let alice = add_example_login(&agent, "alice@example.com");
    let other = add_example_login(&agent, "carol");
    let options = |extra: Value| {
        let mut params = json!({ "origin": "https://login.example.com", "rpId": "example.com",
            "userName": "Alice@Example.com" });
        for (k, v) in extra.as_object().unwrap() {
            params[k] = v.clone();
        }
        call(&agent, "passkey.create_options", params)
    };

    let offered = options(json!({}));
    let result = &offered["result"];
    assert_eq!(result["rp_id"], "example.com", "{offered}");
    assert_eq!(result["locked"], false);
    assert_eq!(result["excluded"], false);
    assert_eq!(result["vault"], Value::Null, "one vault: nothing to say");
    // The site's logins (not GitHub), titles and user names only; the one of the request's user
    // name (case-insensitive) is suggested.
    let mut ids: Vec<&str> = result["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    ids.sort_unstable();
    let mut expected = [alice.id.as_str(), other.id.as_str()];
    expected.sort_unstable();
    assert_eq!(ids, expected);
    for candidate in result["candidates"].as_array().unwrap() {
        let mut keys: Vec<&String> = candidate.as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(keys, ["id", "title", "username", "vault_id"]);
    }
    assert_eq!(result["suggested"], alice.id.as_str());
    assert_eq!(
        options(json!({ "userName": "dave" }))["result"]["suggested"],
        Value::Null
    );

    // An excluded credential already in the vault: the card ends the request at once.
    let cid = register_example_passkey(&agent, "erin");
    assert_eq!(
        options(json!({ "excludeCredentials": [{ "id": cid }] }))["result"]["excluded"],
        true
    );
    assert_eq!(
        options(json!({ "excludeCredentials": [{ "id": "AAAA" }] }))["result"]["excluded"],
        false
    );
    assert_eq!(
        code(&options(
            json!({ "excludeCredentials": [{ "id": "not base64url!" }] })
        )),
        "invalid_params"
    );
    // The RP ID rules of passkey.create.
    assert_eq!(
        code(&options(json!({ "rpId": "other.com" }))),
        "url_mismatch"
    );

    // Soft-locked: the same from the kept list, said to be locked. Fully locked: nothing.
    agent.lock_as(LockKind::Soft);
    let kept = options(json!({ "excludeCredentials": [{ "id": cid }] }));
    assert_eq!(kept["result"]["locked"], true, "{kept}");
    assert_eq!(kept["result"]["excluded"], true);
    assert_eq!(kept["result"]["candidates"].as_array().unwrap().len(), 3);
    agent.unlock("master").unwrap();
    agent.lock_as(LockKind::Full);
    assert_eq!(code(&options(json!({}))), "locked");
}

#[test]
fn a_passkey_saved_in_the_browser_needs_no_consent_window() {
    // The consent window would say no: a request that reaches it fails.
    let ui = Arc::new(FakeUi {
        deny_passkeys: true,
        verify: Some(true),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    let alice = add_example_login(&agent, "alice");
    assert_eq!(
        code(&call(
            &agent,
            "passkey.create",
            example_create("zed", json!({}))
        )),
        "cancelled",
        "no consent from the browser: the window asks"
    );

    // Kept with the login chosen in the card; the per-fill check sets the UV flag.
    let changes = *ui.vault_changes.lock().unwrap();
    let saved = call(
        &agent,
        "passkey.create",
        example_create("alice", json!({ "consent": { "itemId": alice.id } })),
    );
    let cid = saved["result"]["credentialId"]
        .as_str()
        .unwrap_or_else(|| panic!("{saved}"))
        .to_string();
    assert_eq!(
        *ui.verifications.lock().unwrap(),
        ["Save a passkey for example.com"]
    );
    let found = find_example_passkeys(&agent, json!({}))["result"]["items"].clone();
    assert_eq!(found[0]["id"], alice.id.as_str());
    assert_eq!(found[0]["credential_id"], cid.as_str());
    assert_eq!(
        *ui.vault_changes.lock().unwrap(),
        changes + 1,
        "windows and the Windows passkey provider hear of it"
    );

    // No login chosen ("New login"): a new login for the site.
    let new_login = call(
        &agent,
        "passkey.create",
        example_create("bob", json!({ "consent": {} })),
    );
    assert!(
        new_login["result"]["credentialId"].is_string(),
        "{new_login}"
    );
    let count = || {
        find_example_passkeys(&agent, json!({}))["result"]["items"]
            .as_array()
            .unwrap()
            .len()
    };
    assert_eq!(count(), 2);

    // Another site's login, or an unknown one: refused, nothing saved.
    for id in [github.id.as_str(), "no-such-item"] {
        let refused = call(
            &agent,
            "passkey.create",
            example_create("carol", json!({ "consent": { "item_id": id } })),
        );
        assert_eq!(code(&refused), "url_mismatch", "{id}: {refused}");
    }
    // The excluded check still applies.
    let again = call(
        &agent,
        "passkey.create",
        example_create(
            "alice",
            json!({ "consent": {}, "excludeCredentials": [{ "id": cid }] }),
        ),
    );
    assert_eq!(code(&again), "invalid_state");
    assert_eq!(count(), 2);
}

#[test]
fn a_declined_check_keeps_a_browser_consented_passkey_out() {
    let ui = Arc::new(FakeUi {
        verify: Some(false),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let refused = call(
        &agent,
        "passkey.create",
        example_create("alice", json!({ "consent": {} })),
    );
    assert_eq!(code(&refused), "cancelled");
    assert_eq!(
        find_example_passkeys(&agent, json!({}))["result"]["items"],
        json!([])
    );
}

#[test]
fn use_another_device_hands_the_sign_in_to_the_browser() {
    for (pick, expected) in [
        (PasskeyPick::Elsewhere, "not_found"),
        (PasskeyPick::Cancelled, "cancelled"),
        (PasskeyPick::Chosen(7), "cancelled"),
    ] {
        let ui = Arc::new(FakeUi {
            passkey_pick: Some(pick),
            ..Default::default()
        });
        let (_dir, agent) = setup(ui.clone());
        agent.create_vault("master").unwrap();
        register_example_passkey(&agent, "alice");
        let get = call(
            &agent,
            "passkey.get",
            json!({ "origin": "https://login.example.com", "rpId": "example.com",
                "challenge": b64url_encode(vec![2; 32]) }),
        );
        // `not_found`: the extension lets the browser's own WebAuthn take over.
        assert_eq!(code(&get), expected, "{pick:?}: {get}");
        assert_eq!(*ui.passkey_choices.lock().unwrap(), 1);
    }
}

fn uv_create_params(user_verification: Option<&str>) -> Value {
    let mut create = json!({
        "origin": "https://example.com",
        "rp": { "id": "example.com", "name": "Example" },
        "user": { "id": b64url_encode(b"u1".to_vec()), "name": "alice" },
        "challenge": b64url_encode(vec![1; 32]),
        "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
    });
    if let Some(uv) = user_verification {
        create["authenticatorSelection"] = json!({ "userVerification": uv });
    }
    create
}

fn uv_get_params(user_verification: Option<&str>) -> Value {
    let mut get =
        json!({ "origin": "https://example.com", "challenge": b64url_encode(vec![2; 32]) });
    if let Some(uv) = user_verification {
        get["userVerification"] = json!(uv);
    }
    get
}

#[test]
fn required_user_verification_sets_uv() {
    let ui = Arc::new(FakeUi {
        required: Some(true),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let reg = call(&agent, "passkey.create", uv_create_params(Some("required")));
    assert!(reg["result"]["credentialId"].is_string(), "{reg}");
    assert!(uv_flag(&reg["result"]["authenticatorData"]));
    let assertion = call(&agent, "passkey.get", uv_get_params(Some("required")));
    assert!(assertion["result"]["signature"].is_string(), "{assertion}");
    assert!(uv_flag(&assertion["result"]["authenticatorData"]));
    // Both went through the strict hook, not the per-fill one.
    let calls = ui.required_calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert!(calls[0].contains("example.com"));
    assert!(ui.verifications.lock().unwrap().is_empty());
}

#[test]
fn required_user_verification_without_real_verification_is_not_supported() {
    // A plain consent click (`Allowed`) or a declined / unavailable Hello can't satisfy it, and
    // no passkey is stored.
    for (verify, required) in [(None, None), (Some(true), Some(false))] {
        let ui = Arc::new(FakeUi {
            verify,
            required,
            ..Default::default()
        });
        let (_dir, agent) = setup(ui.clone());
        agent.create_vault("master").unwrap();
        let reg = call(&agent, "passkey.create", uv_create_params(Some("required")));
        assert_eq!(reg["error"]["code"], "not_supported", "{reg}");
        assert!(agent.vault().unwrap().items().is_empty());
        assert_eq!(ui.required_calls.lock().unwrap().len(), 1);

        // Register one the ordinary way, then ask to sign in with "required".
        let reg = call(
            &agent,
            "passkey.create",
            uv_create_params(Some("preferred")),
        );
        assert!(reg["result"]["credentialId"].is_string(), "{reg}");
        let get = call(&agent, "passkey.get", uv_get_params(Some("required")));
        assert_eq!(get["error"]["code"], "not_supported", "{get}");
        assert_eq!(ui.required_calls.lock().unwrap().len(), 2);
    }
}

#[test]
fn preferred_and_discouraged_user_verification_keep_the_ordinary_flow() {
    for uv in [None, Some("preferred"), Some("discouraged"), Some("bogus")] {
        // Consent only: works, no UV flag, the strict hook is never asked.
        let ui = Arc::new(FakeUi::default());
        let (_dir, agent) = setup(ui.clone());
        agent.create_vault("master").unwrap();
        let reg = call(&agent, "passkey.create", uv_create_params(uv));
        assert!(!uv_flag(&reg["result"]["authenticatorData"]), "{uv:?}");
        let assertion = call(&agent, "passkey.get", uv_get_params(uv));
        assert!(
            !uv_flag(&assertion["result"]["authenticatorData"]),
            "{uv:?}"
        );
        assert!(ui.required_calls.lock().unwrap().is_empty());

        // Hello on the per-fill policy: UV set.
        let ui = Arc::new(FakeUi {
            verify: Some(true),
            ..Default::default()
        });
        let (_dir, agent) = setup(ui.clone());
        agent.create_vault("master").unwrap();
        let reg = call(&agent, "passkey.create", uv_create_params(uv));
        assert!(uv_flag(&reg["result"]["authenticatorData"]), "{uv:?}");
        assert!(ui.required_calls.lock().unwrap().is_empty());
    }
}

// ---- editing from the extension popup ----------------------------------------------------------

fn add_example(agent: &Agent) -> Item {
    agent
        .vault()
        .unwrap()
        .upsert(Item {
            title: "Example".into(),
            username: "alice".into(),
            password: "example-pw".into(),
            urls: vec!["https://example.com".into()],
            ..Default::default()
        })
        .unwrap()
}

fn code(response: &Value) -> &str {
    response["error"]["code"].as_str().unwrap_or("")
}

#[test]
fn status_advertises_editing() {
    let (_dir, agent) = setup(Arc::default());
    let features = call(&agent, "status", json!({}))["result"]["features"].clone();
    assert!(features.as_array().unwrap().contains(&json!("edit")));
    #[cfg(feature = "import-qr")]
    assert!(features
        .as_array()
        .unwrap()
        .contains(&json!("totp.from_image")));
}

#[test]
fn edits_are_bound_to_the_page_origin() {
    let ui = Arc::new(FakeUi::default());
    let (_dir, agent) = setup(ui.clone());
    let url = "https://github.com/login";
    assert_eq!(
        code(&call(
            &agent,
            "logins.get_for_edit",
            json!({ "url": url, "id": "x" })
        )),
        "locked"
    );
    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    let example = add_example(&agent);

    // Its own login: every editable field, but never the 2FA secret.
    let got = call(
        &agent,
        "logins.get_for_edit",
        json!({ "url": url, "id": github.id }),
    );
    let r = &got["result"];
    assert_eq!(r["password"], "pw");
    assert_eq!(r["urls"], json!(["https://github.com"]));
    assert_eq!(r["totp"]["digits"], 6);
    assert_eq!(r["totp"]["code"].as_str().unwrap().len(), 6);
    assert!(!got.to_string().contains("JBSWY3DPEHPK3PXP"));

    // Another site's login can't be read, changed, deleted, shown or given a 2FA secret.
    let other = |method: &str, extra: Value| {
        let mut params = json!({ "url": url, "id": example.id });
        params
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        call(&agent, method, params)
    };
    let refused = other("logins.get_for_edit", json!({}));
    assert_eq!(code(&refused), "url_mismatch");
    assert!(!refused.to_string().contains("example-pw"));
    assert_eq!(
        code(&other(
            "logins.update",
            json!({ "fields": { "password": "stolen" } })
        )),
        "url_mismatch"
    );
    assert_eq!(code(&other("logins.delete", json!({}))), "url_mismatch");
    assert_eq!(code(&other("app.show_item", json!({}))), "url_mismatch");
    assert_eq!(
        code(&other("totp.set", json!({ "totp": "JBSWY3DPEHPK3PXP" }))),
        "url_mismatch"
    );
    let unchanged = agent.vault().unwrap().get(example.id.clone()).unwrap();
    assert_eq!(unchanged.password, "example-pw");
    assert!(!unchanged.has_totp());
    assert!(ui.shown_items.lock().unwrap().is_empty());
    assert_eq!(*ui.vault_changes.lock().unwrap(), 0);
    assert_eq!(
        code(&call(
            &agent,
            "logins.get_for_edit",
            json!({ "url": url, "id": "nope" })
        )),
        "not_found"
    );

    // "Open in Passyble" for its own login.
    let shown = call(
        &agent,
        "app.show_item",
        json!({ "url": url, "id": github.id }),
    );
    assert_eq!(shown["result"]["shown"], true);
    assert_eq!(*ui.shown_items.lock().unwrap(), [github.id.as_str()]);
}

#[test]
fn update_checks_and_applies_fields() {
    let ui = Arc::new(FakeUi::default());
    let (dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let mut github = add_github(&agent);
    github.urls.push("windows:git.exe".into());
    let github = agent.vault().unwrap().upsert(github).unwrap();
    let url = "https://github.com/settings";
    let update = |fields: Value| {
        call(
            &agent,
            "logins.update",
            json!({ "url": url, "id": github.id, "fields": fields }),
        )
    };
    for bad in [
        json!({ "title": "two\nlines" }),
        json!({ "urls": ["javascript:alert(1)"] }),
        json!({ "urls": ["https://user:pw@github.com"] }),
        json!({ "totp": "not base32!" }),
        json!({ "totp": "JBSW" }),
        json!({ "password": "x".repeat(5000) }),
        json!({ "favorite": true }),
    ] {
        assert_eq!(code(&update(bad.clone())), "invalid_params", "{bad}");
    }
    assert_eq!(*ui.vault_changes.lock().unwrap(), 0);

    let res = update(json!({
        "username": " octocat ", "password": "new pw", "notes": "line 1\nline 2",
        "urls": ["https://github.com", "gist.github.com"], "totp": null,
    }));
    assert_eq!(res["result"]["username"], "octocat");
    assert_eq!(res["result"]["has_totp"], false);
    let item = agent.vault().unwrap().get(github.id.clone()).unwrap();
    assert_eq!(item.password, "new pw");
    assert_eq!(item.notes, "line 1\nline 2");
    assert_eq!(item.title, "GitHub", "fields not sent are kept");
    // The auto-type entry the editor doesn't show is kept.
    assert_eq!(
        item.urls,
        [
            "https://github.com",
            "https://gist.github.com",
            "windows:git.exe"
        ]
    );
    assert!(item.totp.is_none());
    assert_eq!(*ui.vault_changes.lock().unwrap(), 1);
    // Saved to the file.
    let reopened = Vault::unlock(
        std::fs::read(dir.path().join("pass.vault")).unwrap(),
        "master".into(),
        "laptop".into(),
    )
    .unwrap();
    assert_eq!(reopened.get(github.id.clone()).unwrap().password, "new pw");
}

#[test]
fn editor_websites_carry_their_rules() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    let status = call(&agent, "status", json!({}));
    assert!(status["result"]["features"]
        .as_array()
        .unwrap()
        .contains(&json!("url_rules")));
    let mut github = add_github(&agent);
    github.urls.push("windows:git.exe".into());
    github.url_rules = vec![UrlRule {
        url: "windows:git.exe".into(),
        rule: UrlMatch::Never,
    }];
    let github = agent.vault().unwrap().upsert(github).unwrap();
    let url = "https://github.com/settings";
    let edit = call(
        &agent,
        "logins.get_for_edit",
        json!({ "url": url, "id": github.id }),
    );
    assert_eq!(edit["result"]["url_rules"], json!([]), "app pins aren't shown");

    let res = call(
        &agent,
        "logins.update",
        json!({ "url": url, "id": github.id, "fields": {
            "urls": ["https://github.com", "gist.github.com"],
            "url_rules": [
                { "url": "https://github.com", "rule": "host" },
                { "url": "gist.github.com", "rule": "never" },
            ],
        } }),
    );
    assert!(res["error"].is_null(), "{res}");
    let item = agent.vault().unwrap().get(github.id.clone()).unwrap();
    assert_eq!(item.url_rule("https://github.com"), UrlMatch::Host);
    assert_eq!(item.url_rule("https://gist.github.com"), UrlMatch::Never);
    assert_eq!(item.url_rule("windows:git.exe"), UrlMatch::Never);
    let edit = call(
        &agent,
        "logins.get_for_edit",
        json!({ "url": url, "id": github.id }),
    );
    assert_eq!(
        edit["result"]["url_rules"],
        json!([
            { "url": "https://github.com", "rule": "host" },
            { "url": "https://gist.github.com", "rule": "never" },
        ])
    );
    // Websites sent without rules keep theirs.
    call(
        &agent,
        "logins.update",
        json!({ "url": url, "id": github.id, "fields": { "title": "GitHub!" } }),
    );
    let item = agent.vault().unwrap().get(github.id.clone()).unwrap();
    assert_eq!(item.url_rules.len(), 3);

    // Hidden on gist: not offered there, still filled when picked, and no "save" banner after.
    let gist = "https://gist.github.com/login";
    let found = call(&agent, "logins.find", json!({ "url": gist }));
    assert_eq!(found["result"]["items"], json!([]));
    let filled = call(&agent, "logins.fill", json!({ "url": gist, "id": github.id }));
    assert_eq!(filled["result"]["password"], "pw");
    let d = plain(
        call(
            &agent,
            "logins.save_check",
            json!({ "url": gist, "username": "octo", "password": "pw" }),
        )["result"]
            .clone(),
    );
    assert_eq!(d["action"], "none");
    // Kept to github.com: not offered on its subdomains.
    let found = call(&agent, "logins.find", json!({ "url": "https://api.github.com/" }));
    assert_eq!(found["result"]["items"], json!([]));

    let bad = json!({ "url_rules": [{ "url": "javascript:alert(1)", "rule": "host" }] });
    let res = call(
        &agent,
        "logins.update",
        json!({ "url": url, "id": github.id, "fields": bad }),
    );
    assert_eq!(code(&res), "invalid_params");

    let hint = |site: &str| call(&agent, "sites.rule_hint", json!({ "url": site }))["result"].clone();
    assert_eq!(hint("alice.github.io"), json!({ "suggested": "host" }));
    assert_eq!(hint("https://github.com"), json!({ "suggested": null }));
}

#[test]
fn sites_suggest_websites_and_names_without_a_vault() {
    let (_dir, agent) = setup(Arc::default());
    assert!(call(&agent, "status", json!({}))["result"]["features"]
        .as_array()
        .unwrap()
        .contains(&json!("sites.suggest")));

    let suggest = |params: Value| call(&agent, "sites.suggest", params)["result"].clone();
    let netflix = suggest(json!({ "query": "netf" }));
    assert_eq!(
        netflix["sites"][0],
        json!({ "name": "Netflix", "domain": "netflix.com" })
    );
    let typed = suggest(json!({ "query": "amazon.de", "limit": 1 }));
    assert_eq!(
        typed,
        json!({ "sites": [{ "name": "Amazon", "domain": "amazon.de" }] })
    );
    let many = suggest(json!({ "query": "a" }));
    let count = many["sites"].as_array().unwrap().len();
    assert_eq!(count, 8, "the default limit");
    let capped = suggest(json!({ "query": "a", "limit": 500 }));
    assert_eq!(capped["sites"].as_array().unwrap().len(), 50);
    assert_eq!(suggest(json!({ "query": "" })), json!({ "sites": [] }));
    let long = call(&agent, "sites.suggest", json!({ "query": "a".repeat(300) }));
    assert_eq!(code(&long), "invalid_params");
    let missing = call(&agent, "sites.suggest", json!({}));
    assert_eq!(code(&missing), "invalid_params");

    let name = |url: &str| call(&agent, "sites.name_for", json!({ "url": url }))["result"].clone();
    assert_eq!(name("www.github.com/login"), json!({ "name": "GitHub" }));
    assert_eq!(name("signin.aws.amazon.com"), json!({ "name": "AWS" }));
    assert_eq!(name("alice.github.io"), json!({ "name": null }));
    assert_eq!(name("example.com"), json!({ "name": null }));
}

#[test]
fn create_defaults_to_the_page() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    let res = call(
        &agent,
        "logins.create",
        json!({ "url": "https://www.github.com/signup?x=1", "fields": { "username": "octo", "password": "pw" } }),
    );
    let id = res["result"]["id"].as_str().unwrap().to_string();
    let item = agent.vault().unwrap().get(id.clone()).unwrap();
    assert_eq!(item.title, "github.com");
    assert_eq!(item.urls, ["https://www.github.com"]);
    let found = call(
        &agent,
        "logins.find",
        json!({ "url": "https://www.github.com/login" }),
    );
    assert_eq!(found["result"]["items"][0]["id"], id.as_str());

    // Title, websites and a 2FA secret given.
    let res = call(
        &agent,
        "logins.create",
        json!({ "url": "https://example.com/", "fields": {
            "title": "Work", "urls": ["login.example.com"], "totp": "jbsw y3dp ehpk 3pxp" } }),
    );
    let item = agent
        .vault()
        .unwrap()
        .get(res["result"]["id"].as_str().unwrap().into())
        .unwrap();
    assert_eq!(item.title, "Work");
    assert_eq!(item.urls, ["https://login.example.com"]);
    assert_eq!(item.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));

    // Not from a web page.
    for url in ["file:///C:/x.html", "chrome://settings", "null"] {
        assert_eq!(
            code(&call(
                &agent,
                "logins.create",
                json!({ "url": url, "fields": {} })
            )),
            "url_mismatch",
            "{url}"
        );
    }
}

#[test]
fn notes_create_adds_a_secure_note() {
    // Every verification refused: adding a note must not ask for one.
    let ui = Arc::new(FakeUi {
        verify: Some(false),
        ..Default::default()
    });
    let (dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let features = call(&agent, "status", json!({}))["result"]["features"].clone();
    assert!(features
        .as_array()
        .unwrap()
        .contains(&json!("notes.create")));

    let text = "Recovery codes\n1111-2222\n3333-4444\t(spare)";
    let res = call(
        &agent,
        "notes.create",
        json!({ "fields": { "title": "  Recovery codes for github.com ", "notes": text } }),
    );
    assert_eq!(res["result"]["kind"], "note");
    assert_eq!(res["result"]["title"], "Recovery codes for github.com");
    assert_eq!(res["result"]["vault"]["home"], true);
    let id = res["result"]["id"].as_str().unwrap().to_string();
    let item = agent.vault().unwrap().get(id.clone()).unwrap();
    assert_eq!(item.kind, ItemKind::Note);
    assert_eq!(item.title, "Recovery codes for github.com", "trimmed");
    assert_eq!(item.notes, text, "line breaks and tabs kept");
    assert!(item.urls.is_empty() && item.password.is_empty() && item.totp.is_none());
    assert_eq!(*ui.vault_changes.lock().unwrap(), 1);
    assert!(
        ui.verifications.lock().unwrap().is_empty(),
        "adding asks nothing"
    );
    // A note is no site's login.
    let found = call(
        &agent,
        "logins.find",
        json!({ "url": "https://github.com/" }),
    );
    assert_eq!(found["result"]["items"], json!([]));
    // Saved to the file.
    let reopened = Vault::unlock(
        std::fs::read(dir.path().join("pass.vault")).unwrap(),
        "master".into(),
        "laptop".into(),
    )
    .unwrap();
    assert_eq!(reopened.get(id).unwrap().notes, text);

    // Refused: no title, a title with a line break, control characters in the text, too long,
    // unknown fields.
    for params in [
        json!({ "fields": { "notes": "x" } }),
        json!({ "fields": { "title": "  ", "notes": "x" } }),
        json!({ "fields": { "title": "a\nb", "notes": "x" } }),
        json!({ "fields": { "title": "a", "notes": "bell\u{7}" } }),
        json!({ "fields": { "title": "a", "notes": "x".repeat(20_001) } }),
        json!({ "fields": { "title": "a", "password": "pw" } }),
    ] {
        assert_eq!(
            code(&call(&agent, "notes.create", params.clone())),
            "invalid_params",
            "{params}"
        );
    }
    // A vault that isn't open.
    assert_eq!(
        code(&call(
            &agent,
            "notes.create",
            json!({ "fields": { "title": "a" }, "vault": "no-such-vault" })
        )),
        "not_found"
    );
    assert_eq!(
        agent.vault().unwrap().items().len(),
        1,
        "nothing else added"
    );

    agent.lock();
    assert_eq!(
        code(&call(
            &agent,
            "notes.create",
            json!({ "fields": { "title": "a", "notes": "b" } })
        )),
        "locked"
    );
}

#[test]
fn notes_append_adds_a_line_and_keeps_the_text() {
    let ui = Arc::new(FakeUi {
        verify: Some(true),
        ..Default::default()
    });
    let (dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let features = call(&agent, "status", json!({}))["result"]["features"].clone();
    assert!(features
        .as_array()
        .unwrap()
        .contains(&json!("notes.append")));
    let reading = add_note(&agent, "Reading list", "Rust book", false);
    let empty = add_note(&agent, "Ideas", "", false);
    let ends = add_note(&agent, "Quotes", "First quote\n", false);

    let res = call(
        &agent,
        "notes.append",
        json!({ "id": reading.id, "text": "  Demo article\thttps://example.com/demo \n" }),
    );
    assert_eq!(res["result"]["id"], reading.id.as_str(), "{res}");
    assert_eq!(res["result"]["title"], "Reading list");
    assert_eq!(res["result"]["kind"], "note");
    assert_eq!(res["result"]["vault"]["home"], true);
    assert!(res["result"].get("notes").is_none(), "no text in the answer");
    let again = call(
        &agent,
        "notes.append",
        json!({ "id": reading.id, "text": "Line one\nLine two" }),
    );
    assert!(again["error"].is_null(), "{again}");
    let text = |id: &str| agent.vault().unwrap().get(id.into()).unwrap().notes;
    assert_eq!(
        text(&reading.id),
        "Rust book\nDemo article\thttps://example.com/demo\nLine one\nLine two"
    );
    call(&agent, "notes.append", json!({ "id": empty.id, "text": "First" }));
    assert_eq!(text(&empty.id), "First", "no blank first line");
    call(&agent, "notes.append", json!({ "id": ends.id, "text": "Second" }));
    assert_eq!(text(&ends.id), "First quote\nSecond", "no blank line between");
    // A change: verified like a login's edit, once while the grant lasts.
    assert_eq!(
        *ui.verifications.lock().unwrap(),
        [
            "Save changes to Reading list",
            "Save changes to Ideas",
            "Save changes to Quotes"
        ]
    );
    assert_eq!(*ui.vault_changes.lock().unwrap(), 4);
    let reopened = Vault::unlock(
        std::fs::read(dir.path().join("pass.vault")).unwrap(),
        "master".into(),
        "laptop".into(),
    )
    .unwrap();
    assert_eq!(reopened.get(reading.id.clone()).unwrap().notes, text(&reading.id));

    // Refused, the note unchanged: nothing to add, control characters, too long, unknown
    // fields, no id.
    let before = text(&reading.id);
    for params in [
        json!({ "id": reading.id, "text": " \n\t " }),
        json!({ "id": reading.id, "text": "bell\u{7}" }),
        json!({ "id": reading.id, "text": "x".repeat(20_001) }),
        json!({ "id": reading.id, "text": "x", "title": "Renamed" }),
        json!({ "text": "x" }),
    ] {
        assert_eq!(
            code(&call(&agent, "notes.append", params.clone())),
            "invalid_params",
            "{params}"
        );
    }
    assert_eq!(text(&reading.id), before);
    // A note grows up to the notes limit (20,000 characters, the line break counted), not past
    // it, and a text that doesn't fit is refused whole.
    let full = add_note(&agent, "Full", &"z".repeat(19_990), false);
    let fits = call(&agent, "notes.append", json!({ "id": full.id, "text": "ü".repeat(9) }));
    assert!(fits["error"].is_null(), "{fits}");
    assert_eq!(text(&full.id).chars().count(), 20_000);
    let partly = add_note(&agent, "Nearly full", &"z".repeat(19_990), false);
    assert_eq!(
        code(&call(
            &agent,
            "notes.append",
            json!({ "id": partly.id, "text": "0123456789" })
        )),
        "invalid_params"
    );
    assert_eq!(text(&partly.id), "z".repeat(19_990), "nothing partly added");
    // Only live notes: not a login, not one in the trash, not an unknown id.
    let github = add_github(&agent);
    let trashed = add_note(&agent, "Old", "old", false);
    agent.vault().unwrap().delete(trashed.id.clone()).unwrap();
    for id in [github.id.as_str(), trashed.id.as_str(), "no-such-note"] {
        assert_eq!(
            code(&call(&agent, "notes.append", json!({ "id": id, "text": "x" }))),
            "not_found",
            "{id}"
        );
    }
    assert_eq!(agent.vault().unwrap().get(github.id.clone()).unwrap().notes, "");

    agent.lock();
    assert_eq!(
        code(&call(
            &agent,
            "notes.append",
            json!({ "id": reading.id, "text": "x" })
        )),
        "locked"
    );
}

#[test]
fn notes_append_declined_changes_nothing() {
    let ui = Arc::new(FakeUi {
        verify: Some(false),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let note = add_note(&agent, "Reading list", "Rust book", false);
    let res = call(
        &agent,
        "notes.append",
        json!({ "id": note.id, "text": "Demo article" }),
    );
    assert_eq!(code(&res), "cancelled", "{res}");
    assert_eq!(
        agent.vault().unwrap().get(note.id.clone()).unwrap().notes,
        "Rust book"
    );
    assert_eq!(*ui.vault_changes.lock().unwrap(), 0);
}

#[test]
fn notes_append_is_rate_limited_with_the_edits() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    let note = add_note(&agent, "Log", "", false);
    let codes: Vec<String> = (0..31)
        .map(|i| {
            let params = json!({ "id": note.id, "text": format!("entry {i}") });
            code(&call(&agent, "notes.append", params)).to_string()
        })
        .collect();
    assert!(codes[..30].iter().all(String::is_empty), "{codes:?}");
    assert_eq!(codes[30], "rate_limited");
}

#[test]
fn delete_then_undo_from_the_same_site() {
    let ui = Arc::new(FakeUi::default());
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    let url = "https://github.com/login";
    let res = call(
        &agent,
        "logins.delete",
        json!({ "url": url, "id": github.id }),
    );
    assert_eq!(res["result"]["undo_secs"], 60);
    assert!(agent.vault().unwrap().get(github.id.clone()).is_none());
    // Undo only from the site it was deleted on.
    assert_eq!(
        code(&call(
            &agent,
            "logins.restore",
            json!({ "url": "https://example.com/", "id": github.id })
        )),
        "not_found"
    );
    let restored = call(
        &agent,
        "logins.restore",
        json!({ "url": "https://gist.github.com/", "id": github.id }),
    );
    assert_eq!(restored["result"]["id"], github.id.as_str());
    let item = agent.vault().unwrap().get(github.id.clone()).unwrap();
    assert_eq!(item.password, "pw");
    assert!(item.has_totp());
    // Once.
    assert_eq!(
        code(&call(
            &agent,
            "logins.restore",
            json!({ "url": url, "id": github.id })
        )),
        "not_found"
    );
    // Locking drops the copy.
    call(
        &agent,
        "logins.delete",
        json!({ "url": url, "id": github.id }),
    );
    agent.save_and_lock().unwrap();
    agent.unlock("master").unwrap();
    assert_eq!(
        code(&call(
            &agent,
            "logins.restore",
            json!({ "url": url, "id": github.id })
        )),
        "not_found"
    );
    assert_eq!(*ui.vault_changes.lock().unwrap(), 3);
}

/// A generated password saved over a login's password keeps the old one in the history, and
/// `logins.restore` from the same site undoes the update once.
#[test]
fn a_password_update_keeps_the_old_password_and_can_be_undone() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    let url = "https://github.com/settings/password";
    let res = call(
        &agent,
        "logins.save",
        json!({ "url": url, "id": github.id, "username": "octo", "password": "Gen-new" }),
    );
    assert_eq!(res["result"]["id"], github.id.as_str());
    let item = agent.vault().unwrap().get(github.id.clone()).unwrap();
    assert_eq!(item.password, "Gen-new");
    assert_eq!(item.password_history.len(), 1);
    assert_eq!(item.password_history[0].password, "pw");
    // Undo only from the site it was saved on.
    assert_eq!(
        code(&call(
            &agent,
            "logins.restore",
            json!({ "url": "https://example.com/", "id": github.id })
        )),
        "not_found"
    );
    let restored = call(
        &agent,
        "logins.restore",
        json!({ "url": "https://github.com/settings", "id": github.id }),
    );
    assert_eq!(restored["result"]["id"], github.id.as_str());
    let item = agent.vault().unwrap().get(github.id.clone()).unwrap();
    assert_eq!(item.password, "pw");
    assert!(item.has_totp());
    // The generated password isn't lost: it is the history's newest entry now.
    assert_eq!(item.password_history[0].password, "Gen-new");
    assert_eq!(
        code(&call(
            &agent,
            "logins.restore",
            json!({ "url": url, "id": github.id })
        )),
        "not_found"
    );
    // A save that changes nothing leaves nothing to undo.
    let same = call(
        &agent,
        "logins.save",
        json!({ "url": url, "id": github.id, "username": "octo", "password": "pw" }),
    );
    assert_eq!(same["result"]["unchanged"], true);
    assert_eq!(
        code(&call(
            &agent,
            "logins.restore",
            json!({ "url": url, "id": github.id })
        )),
        "not_found"
    );
}

#[test]
fn totp_set_checks_the_secret() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    let example = add_example(&agent);
    let url = "https://example.com/account";
    // Preview (no id): settings and code, nothing stored.
    let link = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=8";
    let preview = call(&agent, "totp.set", json!({ "url": url, "totp": link }));
    assert_eq!(preview["result"]["issuer"], "Example");
    assert_eq!(preview["result"]["account"], "alice");
    assert_eq!(preview["result"]["code"].as_str().unwrap().len(), 8);
    assert!(!preview.to_string().contains("JBSWY3DPEHPK3PXP"));
    assert!(!agent
        .vault()
        .unwrap()
        .get(example.id.clone())
        .unwrap()
        .has_totp());
    for bad in [
        "",
        "hello!",
        "JBSWY3DP",
        "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP",
        "otpauth-migration://offline?data=AAAA",
    ] {
        assert_eq!(
            code(&call(
                &agent,
                "totp.set",
                json!({ "url": url, "totp": bad })
            )),
            "invalid_params",
            "{bad}"
        );
    }
    // With id: stored; `otpauth` / `item_id` aliases accepted.
    let set = call(
        &agent,
        "totp.set",
        json!({ "url": url, "item_id": example.id, "otpauth": link }),
    );
    assert_eq!(set["result"]["has_totp"], true);
    assert_eq!(set["result"]["totp"]["digits"], 8);
    let item = agent.vault().unwrap().get(example.id.clone()).unwrap();
    assert_eq!(item.totp.as_deref(), Some(link));
    // Empty with id removes it.
    let removed = call(
        &agent,
        "totp.set",
        json!({ "url": url, "id": example.id, "totp": null }),
    );
    assert_eq!(removed["result"]["has_totp"], false);
}

#[test]
fn editing_honours_per_fill_verification() {
    let ui = Arc::new(FakeUi {
        verify: Some(false),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    let url = "https://github.com/";
    let refused = call(
        &agent,
        "logins.get_for_edit",
        json!({ "url": url, "id": github.id }),
    );
    assert_eq!(code(&refused), "cancelled");
    assert!(refused.get("result").is_none());
    assert_eq!(
        code(&call(
            &agent,
            "logins.update",
            json!({ "url": url, "id": github.id, "fields": { "password": "x" } })
        )),
        "cancelled"
    );
    assert_eq!(
        code(&call(
            &agent,
            "logins.create",
            json!({ "url": url, "fields": { "password": "x" } })
        )),
        "cancelled"
    );
    assert_eq!(agent.vault().unwrap().items().len(), 1);
    assert_eq!(
        agent
            .vault()
            .unwrap()
            .get(github.id.clone())
            .unwrap()
            .password,
        "pw"
    );

    // Verified: opening the editor asks once; saving that login doesn't ask again.
    let ui = Arc::new(FakeUi {
        verify: Some(true),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    call(
        &agent,
        "logins.get_for_edit",
        json!({ "url": url, "id": github.id }),
    );
    call(
        &agent,
        "logins.update",
        json!({ "url": url, "id": github.id, "fields": { "password": "x" } }),
    );
    assert_eq!(ui.verifications.lock().unwrap().len(), 1);
    assert!(ui.verifications.lock().unwrap()[0].contains("GitHub"));
}

#[test]
fn edits_are_rate_limited() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    let params = json!({ "url": "https://github.com/", "id": github.id });
    let codes: Vec<String> = (0..31)
        .map(|_| code(&call(&agent, "logins.get_for_edit", params.clone())).to_string())
        .collect();
    assert!(codes[..30].iter().all(String::is_empty));
    assert_eq!(codes[30], "rate_limited");
}

/// A PNG of a QR code holding `text`, base64url.
#[cfg(feature = "import-qr")]
fn qr_png(text: &str) -> String {
    let code = qrcode::QrCode::new(text.as_bytes()).unwrap();
    let width = code.width() as u32;
    let colors = code.to_colors();
    let (scale, quiet) = (5u32, 4u32);
    let side = (width + 2 * quiet) * scale;
    let img = image::GrayImage::from_fn(side, side, |x, y| {
        let (mx, my) = (x / scale, y / scale);
        let dark = mx >= quiet
            && my >= quiet
            && mx < quiet + width
            && my < quiet + width
            && colors[((my - quiet) * width + (mx - quiet)) as usize] == qrcode::Color::Dark;
        image::Luma([if dark { 0 } else { 255 }])
    });
    let mut png = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .unwrap();
    b64url_encode(png)
}

#[cfg(feature = "import-qr")]
#[test]
fn totp_from_a_qr_code_on_the_page() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    let example = add_example(&agent);
    let url = "https://example.com/security/2fa";
    let link = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example";
    let png = qr_png(link);

    // Without id: the link and its settings, for the editor to save.
    let read = call(&agent, "totp.from_image", json!({ "url": url, "png": png }));
    assert_eq!(read["result"]["totp"], link);
    assert_eq!(read["result"]["issuer"], "Example");
    assert_eq!(read["result"]["account"], "alice");
    assert!(!agent
        .vault()
        .unwrap()
        .get(example.id.clone())
        .unwrap()
        .has_totp());

    // With id: attached to that login (of this site only).
    let attached = call(
        &agent,
        "totp.from_image",
        json!({ "url": url, "id": example.id, "image": png }),
    );
    assert_eq!(attached["result"]["has_totp"], true);
    assert!(!attached.to_string().contains("JBSWY3DPEHPK3PXP"));
    assert_eq!(
        agent
            .vault()
            .unwrap()
            .get(example.id.clone())
            .unwrap()
            .totp
            .as_deref(),
        Some(link)
    );
    assert_eq!(
        code(&call(
            &agent,
            "totp.from_image",
            json!({ "url": "https://github.com/", "id": example.id, "image": png })
        )),
        "url_mismatch"
    );

    // A QR code that isn't a 2FA one, a Google Authenticator export, no QR code, bad data.
    assert_eq!(
        code(&call(
            &agent,
            "totp.from_image",
            json!({ "url": url, "image": qr_png("https://example.com/") })
        )),
        "not_found"
    );
    assert_eq!(
        code(&call(
            &agent,
            "totp.from_image",
            json!({ "url": url, "image": qr_png("otpauth-migration://offline?data=AAAA") })
        )),
        "invalid_params"
    );
    let mut blank = Vec::new();
    image::GrayImage::from_pixel(64, 64, image::Luma([255]))
        .write_to(
            &mut std::io::Cursor::new(&mut blank),
            image::ImageFormat::Png,
        )
        .unwrap();
    assert_eq!(
        code(&call(
            &agent,
            "totp.from_image",
            json!({ "url": url, "image": b64url_encode(blank) })
        )),
        "not_found"
    );
    assert_eq!(
        code(&call(
            &agent,
            "totp.from_image",
            json!({ "url": url, "image": "not base64!" })
        )),
        "invalid_params"
    );
    // Not from a web page.
    assert_eq!(
        code(&call(
            &agent,
            "totp.from_image",
            json!({ "url": "file:///x", "image": png })
        )),
        "url_mismatch"
    );
}

// ---- save banner decision ----------------------------------------------------------------------

fn save_check(agent: &Agent, params: Value) -> Value {
    let mut params = params;
    params["url"] = json!("https://github.com/session");
    plain(call(agent, "logins.save_check", params)["result"].clone())
}

/// An answer without the fields that name vaults (`vault`, `vaults`, `vault_id`,
/// `default_vault`), for tests with only the home vault, where they always name it.
fn plain(mut v: Value) -> Value {
    fn strip(v: &mut Value) {
        match v {
            Value::Object(map) => {
                for key in ["vault", "vaults", "vault_id", "default_vault"] {
                    map.remove(key);
                }
                map.values_mut().for_each(strip);
            }
            Value::Array(items) => items.iter_mut().for_each(strip),
            _ => {}
        }
    }
    strip(&mut v);
    v
}

#[test]
fn save_check_decides_the_banner_without_sending_passwords() {
    let ui = Arc::new(FakeUi::default());
    let (_dir, agent) = setup(ui.clone());
    assert_eq!(
        call(
            &agent,
            "logins.save_check",
            json!({ "url": "https://github.com", "username": "octo", "password": "pw" })
        )["error"]["code"],
        "locked"
    );
    agent.create_vault("master").unwrap();
    let github = add_github(&agent); // octo / pw

    // 1. Same username (trimmed, any case) and password: no banner.
    let d = save_check(&agent, json!({ "username": " OCTO ", "password": "pw" }));
    assert_eq!(
        d,
        json!({ "action": "none", "id": github.id, "title": "GitHub" })
    );
    // 2. Same username, another password: update the password.
    let d = save_check(&agent, json!({ "username": "octo", "password": "new-pw" }));
    assert_eq!(d["action"], "update_password");
    assert_eq!(d["id"], github.id.as_str());
    // 3. Another username (or e-mail), the password of exactly one login: update the username.
    let d = save_check(
        &agent,
        json!({ "username": "octo@example.com", "password": "pw" }),
    );
    assert_eq!(d["action"], "update_username");
    assert_eq!(d["id"], github.id.as_str());
    // 4. Otherwise: save a new login.
    let d = save_check(
        &agent,
        json!({ "username": "someone", "password": "other" }),
    );
    assert_eq!(d, json!({ "action": "save_new" }));
    // The password Pass just filled for that login: no banner, whatever the username.
    let d = save_check(
        &agent,
        json!({ "username": "typo", "password": "pw", "filled_id": github.id }),
    );
    assert_eq!(d["action"], "none");
    // A password change form: the login just filled gets the new password.
    let d = save_check(
        &agent,
        json!({ "username": "", "password": "changed", "kind": "change", "filled_id": github.id }),
    );
    assert_eq!(d["action"], "update_password");
    // No answer ever carries a stored password.
    assert!(!d.to_string().contains("\"pw\""));

    // The same password on two logins of the site: not "exactly one", so save a new one.
    agent
        .vault()
        .unwrap()
        .upsert(Item {
            title: "GitHub work".into(),
            username: "octo-work".into(),
            password: "pw".into(),
            urls: vec!["https://github.com".into()],
            ..Default::default()
        })
        .unwrap();
    let d = save_check(&agent, json!({ "username": "third", "password": "pw" }));
    assert_eq!(d["action"], "save_new");
}

#[test]
fn another_subdomains_login_is_never_updated() {
    let ui = Arc::new(FakeUi::default());
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let add = |title: &str, url: &str| {
        agent
            .vault()
            .unwrap()
            .upsert(Item {
                title: title.into(),
                username: "me".into(),
                password: "pw".into(),
                urls: vec![url.into()],
                ..Default::default()
            })
            .unwrap()
    };
    let bare = add("Example", "https://example.com");
    let a = add("A", "https://a.example.com/login");
    let check = |url: &str, params: Value| {
        let mut params = params;
        params["url"] = json!(url);
        plain(call(&agent, "logins.save_check", params)["result"].clone())
    };
    let new_pw = json!({ "username": "me", "password": "new-pw" });

    // The same host, `www.` or not: update.
    let d = check("https://example.com/session", new_pw.clone());
    assert_eq!(
        (d["action"].as_str(), d["id"].as_str()),
        (Some("update_password"), Some(bare.id.as_str()))
    );
    let d = check("https://www.example.com/session", new_pw.clone());
    assert_eq!(d["id"], bare.id.as_str());
    let d = check("https://a.example.com/", new_pw.clone());
    assert_eq!(d["id"], a.id.as_str());
    // A child of a saved parent, a sibling, and the parent of a saved child: a new login.
    for url in ["https://app.example.com/", "https://b.example.com/"] {
        assert_eq!(
            check(url, new_pw.clone()),
            json!({ "action": "save_new" }),
            "{url}"
        );
    }
    // Another username with a saved password ("Update username?"): not across subdomains either.
    let d = check(
        "https://b.example.com/",
        json!({ "username": "you", "password": "pw" }),
    );
    assert_eq!(d["action"], "save_new");
    // A password change form on another subdomain, with that subdomain's login just filled and
    // without a username: a new login there, the filled one keeps its password.
    let d = check(
        "https://b.example.com/",
        json!({ "username": "", "password": "changed", "kind": "change", "filled_id": bare.id }),
    );
    assert_eq!(d["action"], "save_new");
    // The same username and password saved for another subdomain: offered there already.
    let d = check(
        "https://b.example.com/",
        json!({ "username": "me", "password": "pw" }),
    );
    assert_eq!(d["action"], "none");
    // Another site: a new login, as always.
    let d = check("https://example.org/", new_pw.clone());
    assert_eq!(d["action"], "save_new");

    // `logins.save` follows the same rule: another subdomain's login is left as it is ...
    let saved = call(
        &agent,
        "logins.save",
        json!({ "url": "https://app.example.com/login", "username": "me", "password": "new-pw" }),
    )["result"]
        .clone();
    let new_id = saved["id"].as_str().unwrap().to_string();
    assert!(new_id != bare.id && new_id != a.id);
    let vault = agent.vault().unwrap();
    assert_eq!(vault.get(bare.id.clone()).unwrap().password, "pw");
    assert_eq!(vault.get(a.id.clone()).unwrap().password, "pw");
    let added = vault.get(new_id.clone()).unwrap();
    assert_eq!(added.urls, ["https://app.example.com"]);
    assert_eq!(added.password, "new-pw");
    // ... even when its id is sent (an older banner): a new login, never that one's password.
    let r = call(
        &agent,
        "logins.save",
        json!({ "url": "https://b.example.com/", "id": bare.id, "username": "me", "password": "b-pw" }),
    )["result"]
        .clone();
    assert!(r["id"] != bare.id.as_str());
    assert_eq!(vault.get(bare.id.clone()).unwrap().password, "pw");
    let r = call(
        &agent,
        "logins.save",
        json!({ "url": "https://b.example.com/", "id": a.id, "username": "you", "password": "pw", "update": "username" }),
    )["result"]
        .clone();
    assert!(r["id"] != a.id.as_str());
    assert_eq!(vault.get(a.id.clone()).unwrap().username, "me");
    // The same host, `www.` or not, is updated in place.
    let r = call(
        &agent,
        "logins.save",
        json!({ "url": "https://www.example.com/", "username": "me", "password": "www-pw" }),
    )["result"]
        .clone();
    assert_eq!(r["id"], bare.id.as_str());
    assert_eq!(vault.get(bare.id.clone()).unwrap().password, "www-pw");
}

#[test]
fn a_canonical_host_of_the_same_site_shares_its_login() {
    let ui = Arc::new(FakeUi::default());
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let vault = agent.vault().unwrap();
    let bare = vault
        .upsert(Item {
            title: "Example".into(),
            username: "me".into(),
            password: "pw".into(),
            urls: vec!["https://example.com".into()],
            ..Default::default()
        })
        .unwrap();
    let check = |url: &str, canonical: Option<&str>| {
        let mut params = json!({ "url": url, "username": "me", "password": "new-pw" });
        if let Some(c) = canonical {
            params["canonical_url"] = json!(c);
        }
        call(&agent, "logins.save_check", params)["result"].clone()
    };
    // Accepted: app.example.com says example.com is canonical, so its login is updated.
    let d = check(
        "https://app.example.com/login",
        Some("https://example.com/"),
    );
    assert_eq!(d["action"], "update_password");
    assert_eq!(d["id"], bare.id.as_str());
    // Missing, from another site, a public-suffix sibling, or on a plain-http page: no sharing.
    assert_eq!(
        check("https://app.example.com/login", None)["action"],
        "save_new"
    );
    assert_eq!(
        check("https://app.example.com/login", Some("https://evil.com/"))["action"],
        "save_new"
    );
    assert_eq!(
        check("http://app.example.com/login", Some("https://example.com/"))["action"],
        "save_new"
    );
    vault
        .upsert(Item {
            title: "Alice".into(),
            username: "me".into(),
            password: "pw".into(),
            urls: vec!["https://alice.github.io".into()],
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        check("https://bob.github.io/", Some("https://alice.github.io/"))["action"],
        "save_new"
    );
    // A page of another site claiming a login's host is ignored by `logins.save` too.
    let r = call(
        &agent,
        "logins.save",
        json!({ "url": "https://evil.com/", "username": "me", "password": "stolen", "canonical_url": "https://example.com/" }),
    )["result"]
        .clone();
    assert!(r["id"] != bare.id.as_str());
    assert_eq!(vault.get(bare.id.clone()).unwrap().password, "pw");
    let evil = vault.get(r["id"].as_str().unwrap().into()).unwrap();
    assert_eq!(evil.urls, ["https://evil.com"]);

    // `logins.save` with an accepted canonical host: the canonical login is updated and gets this
    // page's address too, so both hosts share it from now on.
    let r = call(
        &agent,
        "logins.save",
        json!({ "url": "https://app.example.com/login", "username": "me", "password": "new-pw", "canonical_url": "https://example.com/" }),
    )["result"]
        .clone();
    assert_eq!(r["id"], bare.id.as_str());
    let item = vault.get(bare.id.clone()).unwrap();
    assert_eq!(item.password, "new-pw");
    assert_eq!(
        item.urls,
        ["https://example.com", "https://app.example.com"]
    );
    assert_eq!(
        check("https://app.example.com/", None)["id"],
        bare.id.as_str()
    );
    // A new login is saved under the canonical host and this page's.
    let r = call(
        &agent,
        "logins.save",
        json!({ "url": "https://shop.example.net/sign-up", "username": "new", "password": "pw2", "canonical_url": "https://www.example.net/" }),
    )["result"]
        .clone();
    let added = vault.get(r["id"].as_str().unwrap().into()).unwrap();
    assert_eq!(
        added.urls,
        ["https://www.example.net", "https://shop.example.net"]
    );
}

#[test]
fn save_can_update_only_the_username() {
    let ui = Arc::new(FakeUi::default());
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    let url = "https://github.com/session";
    let r = call(
        &agent,
        "logins.save",
        json!({ "url": url, "id": github.id, "username": "octo@example.com", "password": "ignored", "update": "username" }),
    );
    assert_eq!(r["result"]["id"], github.id.as_str());
    let item = agent.vault().unwrap().get(github.id.clone()).unwrap();
    assert_eq!(item.username, "octo@example.com");
    assert_eq!(item.password, "pw", "the password is kept");
    // Bound to the site, and needs an id.
    assert_eq!(
        call(
            &agent,
            "logins.save",
            json!({ "url": "https://example.com/", "id": github.id, "username": "x", "password": "y", "update": "username" })
        )["error"]["code"],
        "url_mismatch"
    );
    assert_eq!(
        call(
            &agent,
            "logins.save",
            json!({ "url": url, "username": "x", "password": "y", "update": "username" })
        )["error"]["code"],
        "invalid_params"
    );
    // Saving the login exactly as stored writes nothing.
    let before = agent
        .vault()
        .unwrap()
        .get(github.id.clone())
        .unwrap()
        .updated_at;
    let changes = *ui.vault_changes.lock().unwrap();
    call(
        &agent,
        "logins.save",
        json!({ "url": url, "username": "OCTO@example.com", "password": "pw" }),
    );
    assert_eq!(
        agent
            .vault()
            .unwrap()
            .get(github.id.clone())
            .unwrap()
            .updated_at,
        before
    );
    assert_eq!(*ui.vault_changes.lock().unwrap(), changes);
}

/// A cache entry as the app writes it (`pass_core::site_icon_cache_*`): `SPI1`, status 1 (icon),
/// the fetch time (i64 Unix ms, little endian), the PNG.
#[cfg(feature = "icons")]
fn cache_icon(dir: &std::path::Path, domain: &str, png: &[u8]) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let mut data = b"SPI1\x01".to_vec();
    data.extend_from_slice(&now.to_le_bytes());
    data.extend_from_slice(png);
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join(pass_core::site_icon_cache_file_name(domain.into())),
        data,
    )
    .unwrap();
}

#[cfg(feature = "icons")]
#[test]
fn icons_only_for_logins_of_the_page() {
    let (dir, agent) = setup(Arc::default());
    let cache = dir.path().join("icons");
    let github_png = b"\x89PNG\r\n\x1a\ngithub".to_vec();
    cache_icon(&cache, "github.com", &github_png);
    cache_icon(&cache, "example.com", b"\x89PNG\r\n\x1a\nexample");
    // Not a PNG: not passed on.
    cache_icon(&cache, "gitlab.com", b"<svg/>");
    let page = json!({ "url": "https://github.com/login" });
    let icons_get = |params: Value| call(&agent, "icons.get", params)["result"].clone();
    let none = json!({ "icons": {}, "items": {} });

    assert!(call(&agent, "status", json!({}))["result"]["features"]
        .as_array()
        .unwrap()
        .contains(&json!("icons.get")));
    // Locked: empty, and no unlock prompt (FakeUi would refuse it: `cancelled`).
    agent.set_icon_cache_dir(Some(cache.clone()));
    assert_eq!(icons_get(page.clone()), none);

    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    let example = add_example(&agent);
    agent
        .vault()
        .unwrap()
        .upsert(Item {
            title: "GitLab".into(),
            urls: vec!["https://www.gitlab.com".into()],
            ..Default::default()
        })
        .unwrap();
    let result = icons_get(page.clone());
    // Standard base64 of `github_png`, padded.
    let expected = "data:image/png;base64,iVBORw0KGgpnaXRodWI=";
    assert_eq!(
        result,
        json!({ "icons": { "github.com": expected }, "items": { github.id.clone(): "github.com" } })
    );
    // The example.com icon is cached too, but its login doesn't match this page.
    assert_eq!(
        icons_get(json!({ "url": "https://github.com/", "domains": ["example.com"] })),
        none
    );
    assert_eq!(
        icons_get(json!({ "url": "https://example.com/", "domains": ["example.com"] }))["items"]
            [example.id.as_str()],
        "example.com"
    );
    assert_eq!(icons_get(json!({ "url": "https://gitlab.com/" })), none);

    // "Show website icons" off.
    agent.set_icon_cache_dir(None);
    assert_eq!(icons_get(page.clone()), none);

    // Soft-locked: still there (from the kept list); fully locked: empty, not `locked`.
    agent.set_icon_cache_dir(Some(cache));
    agent.lock();
    let soft = call(&agent, "icons.get", page.clone());
    assert_eq!(soft["error"], Value::Null);
    assert_ne!(soft["result"], none);
    agent.lock_as(LockKind::Full);
    let locked = call(&agent, "icons.get", page);
    assert_eq!(locked["error"], Value::Null);
    assert_eq!(locked["result"], none);
}

#[test]
fn otp_outcomes_teach_the_agent_which_sites_skip_2fa() {
    let (dir, agent) = setup(Arc::default());
    let history = dir.path().join("local").join("otp-history.json");
    agent.set_otp_history_file(Some(history.clone()));
    agent.create_vault("master").unwrap();
    let item = add_github(&agent);
    let login = json!({ "url": "https://github.com/login", "id": item.id });
    let outcome = |o: &str| {
        call(
            &agent,
            "otp.outcome",
            json!({ "url": "https://github.com/", "outcome": o }),
        )
    };

    // Only outcomes of a Pass fill count; nonsense is refused.
    assert_eq!(outcome("skipped")["result"]["recorded"], false);
    assert_eq!(outcome("maybe")["error"]["code"], "invalid_params");
    assert_eq!(
        call(
            &agent,
            "otp.outcome",
            json!({ "url": "https://github.com/" })
        )["error"]["code"],
        "invalid_params"
    );

    let filled = call(&agent, "logins.fill", login.clone());
    assert_eq!(filled["result"]["skips_2fa"], false);
    let first = outcome("skipped");
    assert_eq!(
        first["result"],
        json!({ "recorded": true, "skips_2fa": false })
    );

    call(&agent, "logins.fill", login.clone());
    assert_eq!(
        outcome("skipped")["result"]["skips_2fa"],
        true,
        "two sign-ins in a row without 2FA"
    );
    let found = call(
        &agent,
        "logins.find",
        json!({ "url": "https://github.com/" }),
    );
    assert_eq!(found["result"]["pending_otp"]["skips_2fa"], true);
    assert_eq!(
        call(&agent, "logins.fill", login.clone())["result"]["skips_2fa"],
        true
    );
    // Another site is not affected.
    assert_eq!(
        call(
            &agent,
            "otp.outcome",
            json!({ "url": "https://gitlab.com/", "outcome": "skipped" })
        )["result"]["skips_2fa"],
        false
    );

    // That fill: "skipped" first, then a code field showed up after all and got the code.
    assert_eq!(outcome("skipped")["result"]["skips_2fa"], true);
    assert_eq!(
        outcome("used")["result"]["skips_2fa"],
        false,
        "the stronger outcome replaces it"
    );
    assert_eq!(
        agent.otp_outcomes("https://github.com"),
        [
            pass_agent::OtpOutcome::Skipped,
            pass_agent::OtpOutcome::Skipped,
            pass_agent::OtpOutcome::Used
        ]
    );

    // Kept on this device under hashed keys, and read back by a new agent (locked: still answers).
    let text = std::fs::read_to_string(&history).unwrap();
    assert!(!text.contains("github"), "{text}");
    call(&agent, "logins.fill", login.clone());
    outcome("skipped");
    call(&agent, "logins.fill", login);
    outcome("skipped");
    let again = Agent::new(agent.config(), Arc::new(FakeUi::default()));
    again.set_otp_history_file(Some(history));
    assert!(again.skips_2fa("https://github.com/"));
    assert_eq!(
        call(
            &again,
            "otp.outcome",
            json!({ "url": "https://github.com/", "outcome": "asked" })
        )["result"],
        json!({ "recorded": false, "skips_2fa": true })
    );
}

// ---- searching the vault from the popup ---------------------------------------------------------

fn add_login(agent: &Agent, title: &str, username: &str, urls: &[&str]) -> Item {
    agent
        .vault()
        .unwrap()
        .upsert(Item {
            title: title.into(),
            username: username.into(),
            password: format!("{title}-secret"),
            urls: urls.iter().map(|u| u.to_string()).collect(),
            ..Default::default()
        })
        .unwrap()
}

fn search(agent: &Agent, query: &str) -> Value {
    call(agent, "logins.search", json!({ "query": query }))
}

fn titles(result: &Value) -> Vec<String> {
    result["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["title"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn status_advertises_search() {
    let (_dir, agent) = setup(Arc::default());
    let features = call(&agent, "status", json!({}))["result"]["features"].clone();
    assert!(features
        .as_array()
        .unwrap()
        .contains(&json!("logins.search")));
}

/// `logins.search` keeps what it read of the vault between keystrokes; an edit, a new login, a
/// use (the order) and a lock are seen by the next search all the same.
#[test]
fn search_follows_changes_between_keystrokes() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    add_login(&agent, "GitLab", "octo", &["https://gitlab.com"]);
    assert_eq!(titles(&search(&agent, "git")), ["GitHub", "GitLab"]);
    assert_eq!(titles(&search(&agent, "git")), ["GitHub", "GitLab"]);
    let vault = agent.vault().unwrap();
    for _ in 0..3 {
        vault
            .record_use(vault.items()[1].id.clone(), 1_750_000_000_000)
            .unwrap();
    }
    assert_eq!(titles(&search(&agent, "git")), ["GitLab", "GitHub"]);
    let mut renamed = vault.get(github.id.clone()).unwrap();
    renamed.title = "Gitea".into();
    vault.upsert(renamed).unwrap();
    add_login(&agent, "Gitter", "octo", &["https://gitter.im"]);
    assert_eq!(titles(&search(&agent, "git")), ["GitLab", "Gitea", "Gitter"]);
    agent.lock_as(LockKind::Full);
    assert_eq!(code(&search(&agent, "git")), "locked");
}

#[test]
fn search_lists_logins_without_secrets() {
    let (_dir, agent) = setup(Arc::default());
    assert_eq!(code(&search(&agent, "git")), "locked");
    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    add_example(&agent);
    add_login(
        &agent,
        "My GitHub mirror",
        "mirror",
        &["https://git.example.org"],
    );
    add_login(&agent, "gitea", "admin", &["windows:gitea.exe"]);
    add_login(
        &agent,
        "Work",
        "bob",
        &["windows:x.exe", "https://www.gitlab.com/users"],
    );
    agent
        .vault()
        .unwrap()
        .upsert(Item {
            kind: pass_core::ItemKind::Note,
            title: "GitHub recovery codes".into(),
            ..Default::default()
        })
        .unwrap();

    // The core's fuzzy search: titles starting with the query first, then the other matches,
    // each by title (any case). Notes never.
    let found = search(&agent, " GIT ");
    assert_eq!(
        titles(&found),
        ["gitea", "GitHub", "My GitHub mirror", "Work"]
    );
    assert_eq!(found["result"]["truncated"], false);
    assert_eq!(
        plain(found["result"]["items"][1].clone()),
        json!({ "id": github.id, "title": "GitHub", "username": "octo", "domain": "github.com", "has_totp": true,
            "favorite": false })
    );
    assert_eq!(found["result"]["items"][3]["domain"], "gitlab.com");
    assert_eq!(found["result"]["items"][0]["domain"], "");
    let text = found.to_string();
    for secret in [
        "\"pw\"",
        "JBSWY3DPEHPK3PXP",
        "-secret",
        "password",
        "urls",
        "notes",
    ] {
        assert!(!text.contains(secret), "{secret} in {text}");
    }
    // Username and website host match too; `windows:` entries don't.
    assert_eq!(titles(&search(&agent, "alic")), ["Example"]);
    assert_eq!(titles(&search(&agent, "example.org")), ["My GitHub mirror"]);
    assert!(titles(&search(&agent, "gitea.exe")).is_empty());
    // Every word somewhere, in any order, typos allowed.
    assert_eq!(titles(&search(&agent, "githbu octo")), ["GitHub"]);

    // No enumeration with an empty or one-letter query; at most 128 characters.
    let long = "x".repeat(129);
    for bad in ["", " ", "g", " é ", long.as_str()] {
        assert_eq!(code(&search(&agent, bad)), "invalid_params", "{bad:?}");
    }
    assert_eq!(search(&agent, &"x".repeat(128))["error"], Value::Null);

    // `limit`: default 20, clamped to 1..=50.
    let one = call(
        &agent,
        "logins.search",
        json!({ "query": "git", "limit": 0 }),
    );
    assert_eq!(titles(&one), ["gitea"]);
    assert_eq!(one["result"]["truncated"], true);
    for n in 0..55 {
        add_login(&agent, &format!("Bulk {n:02}"), "", &[]);
    }
    let bulk = search(&agent, "bulk");
    assert_eq!(titles(&bulk).len(), 20);
    assert_eq!(bulk["result"]["truncated"], true);
    let max = call(
        &agent,
        "logins.search",
        json!({ "query": "bulk", "limit": 1000 }),
    );
    assert_eq!(titles(&max).len(), 50);
    assert_eq!(titles(&max)[0], "Bulk 00");
}

#[test]
fn search_is_rate_limited() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    for _ in 0..120 {
        assert_eq!(search(&agent, "git")["error"], Value::Null);
    }
    assert_eq!(code(&search(&agent, "git")), "rate_limited");
}

#[test]
fn generate_copy_copies_only_a_password_generate_returned() {
    let ui = Arc::new(FakeUi {
        copy_supported: true,
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    let generate = || {
        call(&agent, "generate", json!({}))["result"]["password"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let copy = |password: &str| call(&agent, "generate.copy", json!({ "password": password }));

    // Never anything else: not a value of the caller's, nothing before it generated anything.
    assert_eq!(code(&copy("attacker's text")), "not_found");
    let password = generate();
    assert_eq!(code(&copy("attacker's text")), "not_found");
    assert_eq!(
        code(&call(&agent, "generate.copy", json!({}))),
        "invalid_params"
    );
    assert!(ui.copied.lock().unwrap().is_empty());

    // Works without a vault (it isn't in one), asks nothing, and the answer has no value in it.
    let r = copy(&password);
    assert_eq!(r["result"], json!({ "copied": true }));
    assert_eq!(*ui.copied.lock().unwrap(), [password.as_str()]);
    assert!(ui.verifications.lock().unwrap().is_empty());
    assert_eq!(uses(&ui), 0);

    // Again, as long as it is remembered; older ones go first.
    copy(&password);
    assert_eq!(ui.copied.lock().unwrap().len(), 2);
    for _ in 0..16 {
        generate();
    }
    assert_eq!(code(&copy(&password)), "not_found");
    let latest = generate();
    assert_eq!(copy(&latest)["result"]["copied"], true);

    // Rate limited like `logins.copy`.
    for _ in 0..40 {
        copy(&latest);
    }
    assert_eq!(code(&copy(&latest)), "rate_limited");
}

#[test]
fn generate_without_symbols_has_letters_and_digits_only() {
    let ui = Arc::new(FakeUi::default());
    let (_dir, agent) = setup(ui.clone());
    for _ in 0..50 {
        let r = call(&agent, "generate", json!({ "length": 24, "symbols": false }));
        let password = r["result"]["password"].as_str().unwrap().to_string();
        assert_eq!(password.chars().count(), 24);
        assert!(password.chars().all(|c| c.is_ascii_alphanumeric()), "{password}");
        assert!(password.chars().any(|c| c.is_ascii_lowercase()), "{password}");
        assert!(password.chars().any(|c| c.is_ascii_uppercase()), "{password}");
        assert!(password.chars().any(|c| c.is_ascii_digit()), "{password}");
    }
    // Missing or true: with symbols.
    for params in [json!({}), json!({ "symbols": true })] {
        let r = call(&agent, "generate", params);
        let password = r["result"]["password"].as_str().unwrap().to_string();
        assert!(password.chars().any(|c| !c.is_ascii_alphanumeric()), "{password}");
    }
}

#[test]
fn generate_copy_needs_a_ui_with_a_clipboard() {
    let ui = Arc::new(FakeUi::default());
    let (_dir, agent) = setup(ui.clone());
    let password = call(&agent, "generate", json!({}))["result"]["password"]
        .as_str()
        .unwrap()
        .to_string();
    let r = call(&agent, "generate.copy", json!({ "password": password }));
    assert_eq!(code(&r), "not_supported");
}

#[test]
fn copy_needs_a_search_hit_or_the_page() {
    let ui = Arc::new(FakeUi {
        verify: Some(true),
        copy_supported: true,
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    let example = add_example(&agent);
    let copy = |id: &str, field: &str, url: Option<&str>| {
        let mut params = json!({ "id": id, "field": field });
        if let Some(url) = url {
            params["url"] = json!(url);
        }
        call(&agent, "logins.copy", params)
    };

    // Not searched for, and not of the page: refused.
    assert_eq!(code(&copy(&github.id, "username", None)), "url_mismatch");
    assert_eq!(
        code(&copy(&github.id, "password", Some("https://example.com/"))),
        "url_mismatch"
    );
    assert_eq!(code(&copy("nope", "username", None)), "not_found");
    assert_eq!(code(&copy(&github.id, "notes", None)), "invalid_params");
    assert!(ui.copied.lock().unwrap().is_empty());
    assert!(ui.verifications.lock().unwrap().is_empty());

    // A login of the page needs no search.
    let r = copy(&github.id, "username", Some("https://github.com/login"));
    assert_eq!(r["result"], json!({ "copied": true, "field": "username" }));

    search(&agent, "github");
    // The username is in the search result already: no verification.
    copy(&github.id, "username", None);
    assert!(ui.verifications.lock().unwrap().is_empty());
    let r = copy(&github.id, "password", None);
    assert_eq!(r["result"], json!({ "copied": true, "field": "password" }));
    let r = copy(&github.id, "totp", None);
    assert_eq!(r["result"]["copied"], true);
    assert_eq!(
        *ui.verifications.lock().unwrap(),
        ["Copy the password of GitHub", "Copy the 2FA code of GitHub"]
    );
    let copied = ui.copied.lock().unwrap().clone();
    assert_eq!(copied[..3], ["octo", "octo", "pw"]);
    assert_eq!(copied[3].len(), 6);
    // The value never comes back.
    assert!(!r.to_string().contains(&copied[3]));

    // Example wasn't in that search; with its page it is, but it has no 2FA secret.
    assert_eq!(code(&copy(&example.id, "totp", None)), "url_mismatch");
    assert_eq!(
        code(&copy(&example.id, "totp", Some("https://example.com/"))),
        "not_found"
    );
}

#[test]
fn copy_honours_verification_and_the_hook() {
    let ui = Arc::new(FakeUi {
        verify: Some(false),
        copy_supported: true,
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    search(&agent, "github");
    let copy = |field: &str| {
        call(
            &agent,
            "logins.copy",
            json!({ "id": github.id, "field": field }),
        )
    };
    assert_eq!(code(&copy("password")), "cancelled");
    assert_eq!(code(&copy("totp")), "cancelled");
    assert_eq!(copy("username")["result"]["copied"], true);
    assert_eq!(*ui.copied.lock().unwrap(), ["octo"]);

    // A UI without the clipboard hook.
    let (_dir2, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    search(&agent, "github");
    assert_eq!(
        code(&call(
            &agent,
            "logins.copy",
            json!({ "id": github.id, "field": "password" })
        )),
        "not_supported"
    );
}

#[test]
fn copy_of_the_pages_own_login_is_verified_like_its_fill() {
    let ui = Arc::new(FakeUi {
        verify: Some(true),
        copy_supported: true,
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    let copy = |field: &str, url: Option<&str>| {
        let mut params = json!({ "id": github.id, "field": field });
        if let Some(url) = url {
            params["url"] = json!(url);
        }
        call(&agent, "logins.copy", params)
    };

    // The popup's copy for the tab's own login: the per-fill policy knows which login it is.
    let r = copy("password", Some("https://github.com/login"));
    assert_eq!(
        r["result"],
        json!({ "copied": true, "field": "password" }),
        "{r}"
    );
    assert!(
        !r.to_string().contains("\"pw\""),
        "the value never comes back"
    );
    assert_eq!(
        copy("totp", Some("https://github.com/login"))["result"]["copied"],
        true
    );
    assert_eq!(
        *ui.item_checks.lock().unwrap(),
        [(github.id.clone(), "password"), (github.id.clone(), "code")]
    );
    assert_eq!(
        *ui.verifications.lock().unwrap(),
        ["Copy the password of GitHub", "Copy the 2FA code of GitHub"]
    );

    // After a fill, the code of that login follows it (as totp.get does).
    call(
        &agent,
        "logins.fill",
        json!({ "url": "https://github.com/login", "id": github.id }),
    );
    ui.item_checks.lock().unwrap().clear();
    ui.verifications.lock().unwrap().clear();
    copy("totp", Some("https://github.com/sessions/two-factor"));
    assert_eq!(
        *ui.item_checks.lock().unwrap(),
        [(github.id.clone(), "pending code")]
    );
    assert!(ui.verifications.lock().unwrap().is_empty(), "no new prompt");

    // A search result of another site: the general policy, every time.
    search(&agent, "github");
    ui.item_checks.lock().unwrap().clear();
    ui.verifications.lock().unwrap().clear();
    copy("password", None);
    assert!(ui.item_checks.lock().unwrap().is_empty());
    assert_eq!(
        *ui.verifications.lock().unwrap(),
        ["Copy the password of GitHub"]
    );
}

#[test]
fn copy_is_rate_limited() {
    let ui = Arc::new(FakeUi {
        copy_supported: true,
        ..Default::default()
    });
    let (_dir, agent) = setup(ui);
    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    search(&agent, "github");
    let params = json!({ "id": github.id, "field": "username" });
    for _ in 0..30 {
        assert_eq!(
            call(&agent, "logins.copy", params.clone())["error"],
            Value::Null
        );
    }
    assert_eq!(code(&call(&agent, "logins.copy", params)), "rate_limited");
}

#[test]
fn fill_cross_asks_before_filling_another_site() {
    let ui = Arc::new(FakeUi {
        verify: Some(true),
        cross: Some(true),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    let fill =
        |url: &str, id: &str| call(&agent, "logins.fill_cross", json!({ "url": url, "id": id }));
    let page = "https://evil.example/login";

    // Only logins of the page or a search hit; only web pages.
    assert_eq!(code(&fill(page, &github.id)), "url_mismatch");
    assert_eq!(code(&fill(page, "nope")), "not_found");
    assert_eq!(code(&fill("chrome://settings", &github.id)), "url_mismatch");
    assert!(ui.cross_requests.lock().unwrap().is_empty());

    search(&agent, "octo");
    let r = fill(page, &github.id);
    assert_eq!(r["result"]["username"], "octo");
    assert_eq!(r["result"]["password"], "pw");
    assert_eq!(r["result"]["cross"], true);
    assert_eq!(r["result"]["totp"]["code"].as_str().unwrap().len(), 6);
    assert_eq!(
        *ui.cross_requests.lock().unwrap(),
        [CrossFillRequest {
            item_id: github.id.clone(),
            title: "GitHub".into(),
            username: "octo".into(),
            item_domain: "github.com".into(),
            page_host: "evil.example".into(),
            lookalike: None,
        }]
    );
    assert_eq!(
        *ui.verifications.lock().unwrap(),
        ["Fill your GitHub login into evil.example"]
    );
    // No pending 2FA code for the other site.
    assert_eq!(agent.pending_otp(page), None);

    // A login of the page: like `logins.fill`, no extra prompt.
    let r = fill("https://github.com/login", &github.id);
    assert_eq!(r["result"]["cross"], false);
    assert_eq!(r["result"]["password"], "pw");
    assert_eq!(ui.cross_requests.lock().unwrap().len(), 1);
    assert_eq!(
        ui.verifications.lock().unwrap().last().unwrap(),
        "Fill your GitHub login"
    );
    assert!(agent.pending_otp("https://github.com/").is_some());
}

#[test]
fn lookalike_pages_are_named_in_search_fill_cross_and_save_check() {
    let ui = Arc::new(FakeUi {
        verify: Some(true),
        cross: Some(true),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    add_login(&agent, "Example", "ann", &["https://example.org"]);
    let lookalike = "https://www.gíthub.com/login";

    // The search marks the results whose site the page looks like.
    let found = call(
        &agent,
        "logins.search",
        json!({ "query": "octo", "url": lookalike }),
    );
    let like = &found["result"]["items"][0]["lookalike"];
    assert_eq!(like["domain"], "github.com");
    assert_eq!(like["reason"], "homograph");
    // The host as the browser has it, international letters in their xn-- form.
    assert!(like["host"].as_str().unwrap().starts_with("www.xn--"), "{like}");
    // Not without a page, not on an unrelated page, not on the login's own site or another
    // site of the vault.
    for url in [
        None,
        Some("https://news.example.net/"),
        Some("https://gist.github.com/"),
        Some("https://example.org/"),
        Some("chrome://settings"),
    ] {
        let mut params = json!({ "query": "octo" });
        if let Some(url) = url {
            params["url"] = json!(url);
        }
        let found = call(&agent, "logins.search", params);
        assert_eq!(found["result"]["items"][0]["lookalike"], Value::Null, "{url:?}");
    }

    // The desktop prompt of a cross fill gets it too.
    let r = call(
        &agent,
        "logins.fill_cross",
        json!({ "url": lookalike, "id": github.id }),
    );
    assert_eq!(r["result"]["cross"], true);
    let asked = ui.cross_requests.lock().unwrap().last().cloned().unwrap();
    let like = asked.lookalike.unwrap();
    assert_eq!(like.domain, "github.com");
    assert_eq!(like.reason, pass_core::LookalikeReason::Homograph);

    // A new login on a lookalike: the save banner warns.
    let check = call(
        &agent,
        "logins.save_check",
        json!({ "url": "https://github.com.sign-in.example.net/", "username": "octo", "password": "x" }),
    )["result"]
        .clone();
    assert_eq!(check["action"], "save_new");
    assert_eq!(check["lookalike"]["domain"], "github.com");
    assert_eq!(check["lookalike"]["reason"], "domain_in_subdomain");
    let check = call(
        &agent,
        "logins.save_check",
        json!({ "url": "https://news.example.net/", "username": "octo", "password": "x" }),
    )["result"]
        .clone();
    assert_eq!(check["action"], "save_new");
    assert_eq!(check["lookalike"], Value::Null);
}

#[test]
fn fill_cross_declined_or_without_a_prompt() {
    for (answer, expected) in [(Some(false), "cancelled"), (None, "not_supported")] {
        let ui = Arc::new(FakeUi {
            verify: Some(true),
            cross: answer,
            ..Default::default()
        });
        let (_dir, agent) = setup(ui.clone());
        agent.create_vault("master").unwrap();
        let github = add_github(&agent);
        search(&agent, "github");
        let r = call(
            &agent,
            "logins.fill_cross",
            json!({ "url": "https://example.com/", "id": github.id }),
        );
        assert_eq!(code(&r), expected);
        assert!(!r.to_string().contains("\"pw\""));
        assert_eq!(ui.cross_requests.lock().unwrap().len(), 1);
        assert!(ui.verifications.lock().unwrap().is_empty());
    }
}

#[test]
fn similar_sites_for_a_page_without_logins() {
    let ui = Arc::new(FakeUi {
        verify: Some(true),
        cross: Some(true),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    let similar = |url: &str, limit: Option<i64>| {
        let mut params = json!({ "url": url });
        if let Some(limit) = limit {
            params["limit"] = json!(limit);
        }
        call(&agent, "logins.similar", params)
    };
    assert_eq!(code(&similar("https://www.amazon.co.uk/", None)), "locked");
    agent.create_vault("master").unwrap();
    let us = add_login(&agent, "Amazon US", "ann", &["https://www.amazon.com/"]);
    add_login(&agent, "Amazon DE", "ann", &["https://amazon.de"]);
    add_login(&agent, "Amazon Prime", "ann", &[]);
    add_login(&agent, "Amazon work", "ann", &["https://amazon.com.au"]);
    add_github(&agent);
    add_login(&agent, "PayPal-Secure", "pat", &["https://www.paypal.com"]);

    // The same name under another suffix first, then the title; three by default.
    let r = similar("https://www.amazon.co.uk/ap/signin", None);
    assert_eq!(titles(&r), ["Amazon DE", "Amazon US", "Amazon work"], "{r}");
    assert_eq!(r["result"]["name"], "amazon");
    assert_eq!(r["result"]["items"][0]["reason"], "same_name");
    assert_eq!(r["result"]["items"][0]["username"], "ann");
    assert_eq!(r["result"]["items"][0]["domain"], "amazon.de");
    assert!(!r.to_string().contains("secret"), "no passwords: {r}");
    let r = similar("https://www.amazon.co.uk/", Some(10));
    assert_eq!(
        titles(&r),
        ["Amazon DE", "Amazon US", "Amazon work", "Amazon Prime"]
    );
    assert_eq!(r["result"]["items"][3]["reason"], "title");
    assert_eq!(
        titles(&similar("https://amazon.fr/", Some(1))),
        ["Amazon DE"]
    );

    // A lookalike of a saved site is never suggested, nor a login of the page's own site.
    assert!(titles(&similar("https://paypal-secure.com/", None)).is_empty());
    assert_eq!(
        titles(&similar("https://smile.amazon.com/", None)),
        ["Amazon DE", "Amazon work", "Amazon Prime"]
    );
    // Web pages only.
    assert_eq!(code(&similar("chrome://settings", None)), "url_mismatch");

    // A suggestion can be cross-filled (with the prompt) without a search first.
    let r = call(
        &agent,
        "logins.fill_cross",
        json!({ "url": "https://www.amazon.co.uk/", "id": us.id }),
    );
    assert_eq!(r["result"]["cross"], true, "{r}");
    assert_eq!(r["result"]["password"], "Amazon US-secret");
    assert_eq!(r["result"]["domain"], "amazon.com");
    assert_eq!(r["result"]["title"], "Amazon US");
    assert_eq!(ui.cross_requests.lock().unwrap().len(), 1);
}

#[test]
fn add_url_only_for_the_fill_that_just_happened() {
    let ui = Arc::new(FakeUi {
        verify: Some(true),
        cross: Some(true),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let us = add_login(&agent, "Amazon US", "ann", &["https://www.amazon.com/"]);
    let other = add_login(&agent, "Other", "bob", &["https://other.example"]);
    let page = "https://www.amazon.co.uk/ap/signin";
    let fill = |id: &str| {
        let r = call(
            &agent,
            "logins.fill_cross",
            json!({ "url": page, "id": id }),
        );
        assert_eq!(r["result"]["cross"], true, "{r}");
        r["result"]["add_url_token"].as_str().unwrap().to_string()
    };
    let add = |id: &str, url: &str, token: &str| {
        call(
            &agent,
            "logins.add_url",
            json!({ "id": id, "url": url, "token": token }),
        )
    };
    call(&agent, "logins.search", json!({ "query": "amazon" }));
    call(&agent, "logins.search", json!({ "query": "other" }));

    // No fill, no token: nothing.
    assert_eq!(code(&add(&us.id, page, "made-up")), "not_found");
    assert_eq!(code(&add(&us.id, page, "")), "not_found");

    // The token is for that login and that page's origin, and for one try.
    let token = fill(&us.id);
    assert!(token.len() >= 32, "{token}");
    assert_ne!(fill(&us.id), token, "a new token for each fill");
    assert_eq!(code(&add(&other.id, page, &token)), "not_found");
    assert_eq!(code(&add(&us.id, page, &token)), "not_found", "used up");
    let token = fill(&us.id);
    assert_eq!(
        code(&add(&us.id, "https://evil.example/", &token)),
        "not_found"
    );
    let token = fill(&us.id);
    assert_eq!(
        code(&add(&us.id, "http://www.amazon.co.uk/", &token)),
        "not_found",
        "another scheme is another origin"
    );
    let changes = *ui.vault_changes.lock().unwrap();

    // The real thing: the page's origin is added (any path of it), once.
    let token = fill(&us.id);
    let r = add(&us.id, "https://www.amazon.co.uk/ap/signin?x=1", &token);
    assert_eq!(r["result"]["added"], true, "{r}");
    assert_eq!(r["result"]["title"], "Amazon US");
    let saved = agent.vault().unwrap().get(us.id.clone()).unwrap();
    assert_eq!(
        saved.urls,
        ["https://www.amazon.com/", "https://www.amazon.co.uk"]
    );
    assert_eq!(*ui.vault_changes.lock().unwrap(), changes + 1);
    assert_eq!(code(&add(&us.id, page, &token)), "not_found", "replayed");

    // From now on it is a login of the page: filled as its own, no prompt and no token.
    let found = call(&agent, "logins.find", json!({ "url": page }));
    assert_eq!(titles(&found), ["Amazon US"]);
    let asked = ui.cross_requests.lock().unwrap().len();
    let r = call(
        &agent,
        "logins.fill_cross",
        json!({ "url": page, "id": us.id }),
    );
    assert_eq!(r["result"]["cross"], false);
    assert_eq!(r["result"]["add_url_token"], Value::Null);
    assert_eq!(ui.cross_requests.lock().unwrap().len(), asked);

    // A lock drops the tokens; adding needs the vault unlocked.
    let token = fill(&other.id);
    agent.lock_as(LockKind::Full);
    assert_eq!(code(&add(&other.id, page, &token)), "locked");
    agent.unlock("master").unwrap();
    assert_eq!(code(&add(&other.id, page, &token)), "not_found");
}

#[test]
fn a_cross_fill_on_a_lookalike_says_so() {
    let ui = Arc::new(FakeUi {
        verify: Some(true),
        cross: Some(true),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui);
    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    search(&agent, "github");
    let r = call(
        &agent,
        "logins.fill_cross",
        json!({ "url": "https://www.gíthub.com/login", "id": github.id }),
    );
    assert_eq!(r["result"]["cross"], true);
    assert_eq!(r["result"]["lookalike"]["domain"], "github.com");
    assert_eq!(r["result"]["lookalike"]["reason"], "homograph");
    assert!(r["result"]["add_url_token"].is_string());
    let r = call(
        &agent,
        "logins.fill_cross",
        json!({ "url": "https://example.net/", "id": github.id }),
    );
    assert_eq!(r["result"]["lookalike"], Value::Null);
}

#[test]
fn sync_now_syncs_through_the_app_and_needs_the_vault_unlocked() {
    let report = SyncReport {
        synced: 1,
        failed: vec![SyncFailure {
            vault: "Family".into(),
            reason: "Can't reach the server".into(),
        }],
        no_sync: false,
    };
    let ui = Arc::new(FakeUi {
        sync_answer: Some(report),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    let features = call(&agent, "status", json!({}))["result"]["features"].clone();
    assert!(features.as_array().unwrap().contains(&json!("sync.now")), "{features}");
    // Locked: refused, and the app isn't asked.
    assert_eq!(code(&call(&agent, "sync.now", json!({}))), "locked");
    assert_eq!(*ui.sync_calls.lock().unwrap(), 0);
    agent.create_vault("master").unwrap();
    let answer = call(&agent, "sync.now", json!({}));
    assert_eq!(
        answer["result"],
        json!({
            "synced": 1,
            "failed": [{ "vault": "Family", "reason": "Can't reach the server" }],
            "no_sync": false,
        })
    );
    assert_eq!(*ui.sync_calls.lock().unwrap(), 1);
    // Read-only mode (update required): no sync.
    agent.set_update_required(true);
    assert_eq!(code(&call(&agent, "sync.now", json!({}))), "update_required");
    assert_eq!(*ui.sync_calls.lock().unwrap(), 1);
}

#[test]
fn sync_now_without_the_app_says_no_vault_has_sync() {
    // The UI leaves it to the agent: a vault without a sync account and no shared vaults.
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    assert_eq!(
        call(&agent, "sync.now", json!({}))["result"],
        json!({ "synced": 0, "failed": [], "no_sync": true })
    );
}

#[test]
fn account_status_and_screen_for_the_extension_in_app_mode() {
    // A UI without a Passyble account: both not_supported (the extension signs in itself then).
    let dir = tempfile::tempdir().unwrap();
    let bare = Agent::new(
        AgentConfig {
            vault_path: dir.path().join("pass.vault"),
            device_id: "laptop".into(),
            auto_lock: Duration::from_secs(900),
            webdav: None,
            gdrive: None,
            kept_list: None,
        },
        Arc::new(BareUi),
    );
    assert_eq!(
        code(&call(&bare, "account.status", json!({}))),
        "not_supported"
    );
    let shown = call(&bare, "app.show_account", json!({ "sign_in": true }));
    assert_eq!(code(&shown), "not_supported");

    let signed_in = AccountSummary {
        signed_in: true,
        email: Some("ada@example.com".into()),
    };
    let ui = Arc::new(FakeUi {
        account: Some(signed_in),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    // Locked too, and nothing but these two fields.
    for kind in [None, Some(LockKind::Soft), Some(LockKind::Full)] {
        if let Some(kind) = kind {
            agent.lock_as(kind);
        }
        let status = call(&agent, "account.status", json!({}));
        assert_eq!(
            status["result"],
            json!({ "signed_in": true, "email": "ada@example.com" }),
            "{status}"
        );
    }
    let open = call(&agent, "app.show_account", json!({}));
    assert_eq!(open["result"], json!({ "shown": true }), "{open}");
    let sign_in = call(&agent, "app.show_account", json!({ "sign_in": true }));
    assert_eq!(sign_in["result"], json!({ "shown": true }), "{sign_in}");
    assert_eq!(ui.account_shown.lock().unwrap().as_slice(), &[false, true]);
    let bad = call(&agent, "app.show_account", json!({ "sign_in": "yes" }));
    assert_eq!(code(&bad), "invalid_params");
    assert!(agent.is_locked(), "neither asks to unlock");

    // Signed out: no e-mail, even if the UI had one at hand.
    let ui = Arc::new(FakeUi {
        account: Some(AccountSummary {
            signed_in: false,
            email: Some("old@example.com".into()),
        }),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui);
    let status = call(&agent, "account.status", json!({}));
    assert_eq!(
        status["result"],
        json!({ "signed_in": false, "email": null }),
        "{status}"
    );
}

#[test]
fn the_sign_in_handoff_between_the_app_and_the_extension() {
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    // A UI without a Passyble account: every method not_supported (the extension does nothing).
    let bare = Arc::new(FakeUi::default());
    let (_dir, agent) = setup(bare.clone());
    for (method, params) in [
        ("account.peer", json!({})),
        (
            "account.handoff_to_extension",
            json!({ "code_challenge": challenge, "device_name": "Chrome" }),
        ),
        ("account.handoff_begin", json!({})),
        ("account.handoff_finish", json!({ "code": "pac_good" })),
        ("account.sign_out", json!({})),
        ("account.peer_signed_out", json!({})),
    ] {
        let r = call(&agent, method, params);
        assert_eq!(code(&r), "not_supported", "{method}: {r}");
    }
    assert!(bare.handoffs.lock().unwrap().is_empty());

    // The app signed in: the extension gets a code of its own, locked too.
    let ui = Arc::new(FakeUi {
        peer: Some(AccountPeer {
            signed_in: true,
            email: Some("ada@example.com".into()),
            accepts_handoff: true,
            sign_out_extension: true,
        }),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    agent.lock_as(LockKind::Full);
    let peer = call(&agent, "account.peer", json!({}));
    // A sign-out request means nothing while the app is signed in.
    assert_eq!(
        peer["result"],
        json!({
            "signed_in": true,
            "email": "ada@example.com",
            "accepts_handoff": true,
            "sign_out_extension": false,
        }),
        "{peer}"
    );
    let to = call(
        &agent,
        "account.handoff_to_extension",
        json!({ "code_challenge": challenge, "device_name": " Chrome on PC\n" }),
    );
    assert_eq!(
        to["result"],
        json!({ "code": "pac_for_the_extension", "email": "ada@example.com" }),
        "{to}"
    );
    // Only a real S256 challenge goes to the UI; the device name is cleaned.
    for bad in [
        json!({ "code_challenge": "short", "device_name": "Chrome" }),
        json!({ "code_challenge": format!("{}=", &challenge[..42]), "device_name": "Chrome" }),
        json!({ "device_name": "Chrome" }),
    ] {
        let r = call(&agent, "account.handoff_to_extension", bad.clone());
        assert_eq!(code(&r), "invalid_params", "{bad}: {r}");
    }
    // Signed in: no sign-in from the extension.
    let begin = call(&agent, "account.handoff_begin", json!({}));
    assert_eq!(code(&begin), "invalid_state", "{begin}");
    assert_eq!(
        ui.handoffs.lock().unwrap().as_slice(),
        &[
            format!("to_extension {challenge} Chrome on PC"),
            "begin".into()
        ]
    );
    // The extension's sign-out with "also sign out of the Passyble app".
    let out = call(&agent, "account.sign_out", json!({}));
    assert_eq!(out["result"], json!({ "signed_out": true }), "{out}");
    assert!(agent.is_locked(), "no method asks to unlock");

    // The app signed out and taking a sign-in from the extension.
    let ui = Arc::new(FakeUi {
        peer: Some(AccountPeer {
            signed_in: false,
            email: Some("old@example.com".into()),
            accepts_handoff: true,
            sign_out_extension: false,
        }),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    let peer = call(&agent, "account.peer", json!({}));
    assert_eq!(
        peer["result"],
        json!({
            "signed_in": false,
            "email": null,
            "accepts_handoff": true,
            "sign_out_extension": false,
        }),
        "{peer}"
    );
    let begin = call(&agent, "account.handoff_begin", json!({}));
    assert_eq!(
        begin["result"],
        json!({ "code_challenge": challenge, "device_name": "Passyble on PC" }),
        "{begin}"
    );
    let finish = call(
        &agent,
        "account.handoff_finish",
        json!({ "code": "pac_good" }),
    );
    assert_eq!(
        finish["result"],
        json!({ "signed_in": true, "email": "ada@example.com" }),
        "{finish}"
    );
    let expired = call(
        &agent,
        "account.handoff_finish",
        json!({ "code": "pac_old" }),
    );
    assert_eq!(code(&expired), "internal", "{expired}");
    for bad in [
        json!({}),
        json!({ "code": "" }),
        json!({ "code": "pac bad" }),
    ] {
        let r = call(&agent, "account.handoff_finish", bad.clone());
        assert_eq!(code(&r), "invalid_params", "{bad}: {r}");
    }
    let to = call(
        &agent,
        "account.handoff_to_extension",
        json!({ "code_challenge": challenge }),
    );
    assert_eq!(code(&to), "invalid_state", "{to}");

    // Signed out with "also sign out of the browser extension": the address it signed out of.
    let ui = Arc::new(FakeUi {
        peer: Some(AccountPeer {
            signed_in: false,
            email: Some("ada@example.com".into()),
            accepts_handoff: true,
            sign_out_extension: true,
        }),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    let peer = call(&agent, "account.peer", json!({}));
    assert_eq!(peer["result"]["email"], "ada@example.com", "{peer}");
    assert_eq!(peer["result"]["sign_out_extension"], true, "{peer}");
    let done = call(&agent, "account.peer_signed_out", json!({}));
    assert_eq!(done["result"], json!({}), "{done}");
    assert_eq!(
        ui.handoffs.lock().unwrap().as_slice(),
        &["peer_signed_out".to_string()]
    );
}

#[test]
fn show_item_for_a_search_hit() {
    let ui = Arc::new(FakeUi::default());
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    let show = || {
        call(
            &agent,
            "app.show_item",
            json!({ "url": "https://example.com/", "id": github.id }),
        )
    };
    assert_eq!(code(&show()), "url_mismatch");
    search(&agent, "github");
    assert_eq!(show()["result"]["shown"], true);
    assert_eq!(
        ui.shown_items.lock().unwrap().as_slice(),
        std::slice::from_ref(&github.id)
    );
}

#[test]
fn lock_forgets_search_hits() {
    let ui = Arc::new(FakeUi {
        copy_supported: true,
        ..Default::default()
    });
    let (_dir, agent) = setup(ui);
    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    search(&agent, "github");
    let params = json!({ "id": github.id, "field": "username" });
    assert_eq!(
        call(&agent, "logins.copy", params.clone())["error"],
        Value::Null
    );
    // A soft lock keeps them (ids only), so a copy started from the search works after unlocking.
    agent.save_and_lock().unwrap();
    agent.unlock("master").unwrap();
    assert_eq!(
        call(&agent, "logins.copy", params.clone())["error"],
        Value::Null
    );
    // A full lock forgets them.
    agent.save_and_lock_as(LockKind::Full).unwrap();
    agent.unlock("master").unwrap();
    assert_eq!(code(&call(&agent, "logins.copy", params)), "url_mismatch");
}

#[test]
fn save_check_can_ignore_the_generated_draft() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    add_github(&agent);
    // The extension auto-saved the password it generated on the sign-up page.
    let draft = agent
        .vault()
        .unwrap()
        .upsert(Item {
            title: "github.com".into(),
            username: "newbie".into(),
            password: "generated".into(),
            urls: vec!["https://github.com".into()],
            ..Default::default()
        })
        .unwrap();
    let submitted = json!({ "username": "newbie", "password": "generated", "kind": "signup" });
    assert_eq!(save_check(&agent, submitted.clone())["action"], "none");
    let mut params = submitted;
    params["ignore_id"] = json!(draft.id);
    assert_eq!(
        plain(save_check(&agent, params)),
        json!({ "action": "save_new" })
    );
}

fn save_check_at(agent: &Agent, url: &str, username: &str, password: &str) -> Value {
    call(
        agent,
        "logins.save_check",
        json!({ "url": url, "username": username, "password": password }),
    )["result"]
        .clone()
}

fn save_check_code(agent: &Agent, url: &str) -> String {
    code(&call(
        agent,
        "logins.save_check",
        json!({ "url": url, "username": "octo", "password": "pw" }),
    ))
    .to_string()
}

#[test]
fn save_check_never_offers_a_login_saved_as_is() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    let github = add_github(&agent); // octo / pw, https://github.com
    let at =
        |url: &str, user: &str, pw: &str| save_check_at(&agent, url, user, pw)["action"].clone();
    let page = "https://github.com/session";

    // The same username in any case and with spaces around it, the same password: no banner.
    for user in ["octo", " OCTO ", "Octo\t", "\u{a0}oCtO\u{a0}"] {
        assert_eq!(at(page, user, "pw"), "none", "{user:?}");
    }
    // The password is compared exactly: no trimming, case counts.
    assert_eq!(at(page, "octo", "pw "), "update_password");
    assert_eq!(at(page, "octo", "PW"), "update_password");
    // Identifier-first sign-in whose username step wasn't captured: a saved password is a saved login.
    assert_eq!(at(page, "", "pw"), "none");
    assert_eq!(at(page, "  ", "pw"), "none");
    assert_eq!(at(page, "", "unknown"), "save_new");
    // Another username: "Update username" (one login has the password) or a new login.
    assert_eq!(at(page, "someone", "pw"), "update_username");
    assert_eq!(at(page, "someone", "other"), "save_new");

    // Site matching, as for filling: other paths, www and other subdomains of the site count; plain
    // http counts for a login saved for https (never filled there, but it is the same login).
    for url in [
        "https://github.com/",
        "https://www.github.com/login?return_to=x",
        "https://gist.github.com/auth",
        "http://github.com/session",
        "http://www.github.com/",
        "https://github.com:443/session",
    ] {
        assert_eq!(at(url, "OCTO", "pw"), "none", "{url}");
    }
    // A plain-http page doesn't get "Update password" for the https login (it can't be saved there).
    assert_eq!(at("http://github.com/session", "octo", "new"), "save_new");
    // Another site isn't this one.
    assert_eq!(at("https://notgithub.com/", "octo", "pw"), "save_new");
    assert_eq!(at("https://github.io/", "octo", "pw"), "save_new");

    // Saved with http, typed on https: the same login.
    agent
        .vault()
        .unwrap()
        .upsert(Item {
            title: "Old".into(),
            username: "me@example.com".into(),
            password: "old-pw".into(),
            urls: vec!["http://www.example.com/login".into()],
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        at("https://login.example.com/", "ME@example.com", "old-pw"),
        "none"
    );

    // Two logins with the same username: the one whose password it is makes it "saved".
    agent
        .vault()
        .unwrap()
        .upsert(Item {
            title: "GitHub (old)".into(),
            username: "octo".into(),
            password: "older".into(),
            urls: vec!["https://github.com".into()],
            ..Default::default()
        })
        .unwrap();
    assert_eq!(at(page, "octo", "older"), "none");
    assert_eq!(at(page, "octo", "pw"), "none");

    // A login in the trash doesn't count: a new one is offered (the trashed one stays restorable).
    let vault = agent.vault().unwrap();
    for item in vault.find_for_url("https://github.com".into()) {
        vault.delete(item.id).unwrap();
    }
    assert_eq!(at(page, "octo", "pw"), "save_new");
    vault.restore(github.id.clone()).unwrap();
    assert_eq!(at(page, "octo", "pw"), "none");

    // Locked, soft or full: the agent can't compare passwords and says so (the extension waits).
    agent.lock_as(LockKind::Soft);
    assert_eq!(save_check_code(&agent, page), "locked");
    // The soft-locked list still tells that a login with this username is saved for the site.
    let listed = call(&agent, "logins.find", json!({ "url": page }));
    assert_eq!(listed["result"]["locked"], true);
    assert!(listed["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["username"] == "octo"));
    assert!(!listed.to_string().contains("\"pw\""));
    agent.unlock("master").unwrap();
    agent.lock_as(LockKind::Full);
    assert_eq!(save_check_code(&agent, page), "locked");
}

#[test]
fn save_check_change_form_without_username_updates_the_login_it_changes() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    let github = add_github(&agent); // octo / pw
    agent
        .vault()
        .unwrap()
        .upsert(Item {
            title: "GitHub work".into(),
            username: "octo-work".into(),
            password: "work-pw".into(),
            urls: vec!["https://github.com".into()],
            ..Default::default()
        })
        .unwrap();
    let change = |password: &str| {
        save_check(
            &agent,
            json!({ "username": "", "password": password, "kind": "change", "filled_id": github.id }),
        )
    };
    // The new password happens to be another login's: still a change of the login just filled.
    let d = change("work-pw");
    assert_eq!(d["action"], "update_password");
    assert_eq!(d["id"], github.id.as_str());
    // Unchanged: nothing to update.
    assert_eq!(change("pw")["action"], "none");
}

#[test]
fn save_writes_nothing_for_a_login_saved_as_is() {
    let ui = Arc::new(FakeUi::default());
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let github = add_github(&agent); // octo / pw
    let older = agent
        .vault()
        .unwrap()
        .upsert(Item {
            title: "GitHub (old)".into(),
            username: "octo".into(),
            password: "older".into(),
            urls: vec!["https://github.com".into()],
            ..Default::default()
        })
        .unwrap();
    let changes = *ui.vault_changes.lock().unwrap();
    let count = || agent.vault().unwrap().items().len();
    let before = count();
    for (url, username, password, id) in [
        ("https://github.com/session", " Octo ", "pw", &github.id),
        // The second login with this username: not overwritten with the other's password.
        ("https://github.com/session", "octo", "older", &older.id),
        // Identifier-first, no username captured.
        ("https://github.com/session", "", "pw", &github.id),
        // Plain http, saved for https.
        ("http://www.github.com/", "OCTO", "pw", &github.id),
    ] {
        let r = call(
            &agent,
            "logins.save",
            json!({ "url": url, "username": username, "password": password }),
        );
        assert_eq!(
            plain(r["result"].clone()),
            json!({ "id": id, "unchanged": true }),
            "{url} {username:?}"
        );
    }
    assert_eq!(count(), before);
    assert_eq!(*ui.vault_changes.lock().unwrap(), changes);
    let vault = agent.vault().unwrap();
    assert_eq!(vault.get(github.id.clone()).unwrap().password, "pw");
    assert_eq!(vault.get(older.id.clone()).unwrap().password, "older");
    // A new password for a username that two logins have still updates one of them.
    let r = call(
        &agent,
        "logins.save",
        json!({ "url": "https://github.com/", "username": "octo", "password": "newest" }),
    );
    assert!(r["result"].get("unchanged").is_none(), "{r}");
    assert_eq!(count(), before);
}

#[cfg(feature = "icons")]
#[test]
fn icons_by_id_only_for_search_hits() {
    let (dir, agent) = setup(Arc::default());
    let cache = dir.path().join("icons");
    cache_icon(&cache, "github.com", b"\x89PNG\r\n\x1a\ngithub");
    cache_icon(&cache, "example.com", b"\x89PNG\r\n\x1a\nexample");
    agent.set_icon_cache_dir(Some(cache));
    let icons_get = |params: Value| call(&agent, "icons.get", params);
    let none = json!({ "icons": {}, "items": {} });

    assert_eq!(code(&icons_get(json!({}))), "invalid_params");
    let too_many: Vec<String> = (0..51).map(|n| n.to_string()).collect();
    assert_eq!(
        code(&icons_get(json!({ "ids": too_many }))),
        "invalid_params"
    );

    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    let example = add_example(&agent);
    let ids = json!({ "ids": [github.id, example.id, "nope"] });
    assert_eq!(icons_get(ids.clone())["result"], none);

    search(&agent, "github");
    let result = icons_get(ids.clone())["result"].clone();
    assert_eq!(result["items"], json!({ github.id.clone(): "github.com" }));
    assert_eq!(
        result["icons"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        ["github.com"]
    );

    // Soft-locked: the search hits keep their icons; fully locked: empty, never `locked`.
    agent.lock();
    assert_ne!(icons_get(ids.clone())["result"], none);
    agent.lock_as(LockKind::Full);
    assert_eq!(icons_get(ids)["result"], none);
}

// ---- soft lock: the list stays, the secrets go --------------------------------------------------

fn add_secret_login(agent: &Agent) -> Item {
    agent
        .vault()
        .unwrap()
        .upsert(Item {
            title: "GitHub".into(),
            username: "octo".into(),
            password: "hunter2-SECRET".into(),
            urls: vec!["https://github.com".into()],
            totp: Some("JBSWY3DPEHPK3PXP".into()),
            notes: "recovery NOTE-SECRET".into(),
            ..Default::default()
        })
        .unwrap()
}

fn assert_no_secrets(text: &str) {
    for secret in ["hunter2", "JBSWY3DPEHPK3PXP", "NOTE-SECRET"] {
        assert!(!text.contains(secret), "{secret} leaked: {text}");
    }
}

#[test]
fn soft_lock_keeps_the_list_without_secrets() {
    let ui = Arc::new(FakeUi::default());
    let (_dir, agent) = setup(ui.clone());
    assert!(
        agent.summaries().is_none(),
        "no list before the first unlock"
    );
    agent.create_vault("master").unwrap();
    let github = add_secret_login(&agent);
    agent.lock();
    assert!(agent.is_locked());
    assert!(agent.is_soft_locked());
    assert!(agent.vault().is_none());
    assert_eq!(*ui.lock_events.lock().unwrap(), [false, true]);
    let list = agent.summaries().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].username, "octo");
    assert!(list[0].has_password && list[0].has_totp && list[0].has_notes);
    assert_no_secrets(&format!("{list:?}"));

    let status = call(&agent, "status", json!({}));
    assert_eq!(status["result"]["locked"], true);
    assert_eq!(status["result"]["soft_locked"], true);
    assert!(status["result"]["features"]
        .as_array()
        .unwrap()
        .contains(&json!("locked.list")));

    let find = call(
        &agent,
        "logins.find",
        json!({ "url": "https://github.com/login" }),
    );
    assert_eq!(find["result"]["locked"], true);
    assert_eq!(find["result"]["items"][0]["id"], json!(github.id));
    assert_eq!(find["result"]["items"][0]["has_totp"], true);
    assert_eq!(find["result"]["pending_otp"], Value::Null);
    assert_no_secrets(&find.to_string());
    let found = search(&agent, "git");
    assert_eq!(found["result"]["locked"], true);
    assert_eq!(titles(&found), ["GitHub"]);
    assert_no_secrets(&found.to_string());
}

#[test]
fn soft_locked_secrets_need_an_unlock() {
    let ui = Arc::new(FakeUi {
        copy_supported: true,
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let github = add_secret_login(&agent);
    let url = "https://github.com/login";
    agent.save_and_lock().unwrap();
    assert!(agent.is_soft_locked());

    let id = json!(github.id);
    for (method, params) in [
        ("logins.fill", json!({ "url": url, "id": id })),
        ("totp.get", json!({ "url": url, "id": id })),
        ("totp.popup", json!({ "url": url, "id": id })),
        ("logins.get_for_edit", json!({ "url": url, "id": id })),
        (
            "logins.update",
            json!({ "url": url, "id": id, "fields": { "password": "new" } }),
        ),
        (
            "logins.save",
            json!({ "url": url, "username": "octo", "password": "new" }),
        ),
        (
            "logins.copy",
            json!({ "url": url, "id": id, "field": "password" }),
        ),
        (
            "logins.copy",
            json!({ "url": url, "id": id, "field": "totp" }),
        ),
        ("logins.fill_cross", json!({ "url": url, "id": id })),
    ] {
        let response = call(&agent, method, params);
        assert_eq!(code(&response), "locked", "{method}: {response}");
    }
    // The username is in the list: it copies without unlocking.
    let copied = call(
        &agent,
        "logins.copy",
        json!({ "url": url, "id": id, "field": "username" }),
    );
    assert_eq!(copied["result"]["copied"], true, "{copied}");
    assert_eq!(*ui.copied.lock().unwrap(), ["octo"]);
    // Not for a login of another site that no search returned.
    let elsewhere = call(
        &agent,
        "logins.copy",
        json!({ "url": "https://evil.example", "id": id, "field": "username" }),
    );
    assert_eq!(code(&elsewhere), "url_mismatch");
    assert!(agent.is_locked(), "nothing above unlocked the vault");

    // After the unlock the same request goes through.
    agent.unlock("master").unwrap();
    assert!(!agent.is_soft_locked());
    let fill = call(&agent, "logins.fill", json!({ "url": url, "id": id }));
    assert_eq!(fill["result"]["password"], "hunter2-SECRET");
    let find = call(&agent, "logins.find", json!({ "url": url }));
    assert_eq!(find["result"]["locked"], false);
}

#[test]
fn full_lock_drops_the_list() {
    let ui = Arc::new(FakeUi::default());
    let (dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    add_secret_login(&agent);
    let find = json!({ "url": "https://github.com" });

    // Soft, then "Lock completely": the second step still tells the windows.
    agent.lock();
    agent.lock_as(LockKind::Full);
    assert!(agent.is_locked() && !agent.is_soft_locked());
    assert!(agent.summaries().is_none());
    assert_eq!(*ui.lock_events.lock().unwrap(), [false, true, true]);
    assert_eq!(code(&call(&agent, "logins.find", find.clone())), "locked");
    assert_eq!(code(&search(&agent, "git")), "locked");
    assert_eq!(
        call(&agent, "status", json!({}))["result"]["soft_locked"],
        false
    );

    // Straight to full.
    agent.unlock("master").unwrap();
    agent.save_and_lock_as(LockKind::Full).unwrap();
    assert!(agent.summaries().is_none());

    // "Keep list visible when locked" off: every lock is full, and turning it off drops a kept list.
    agent.unlock("master").unwrap();
    agent.lock();
    assert!(agent.is_soft_locked());
    agent.set_keep_list(false);
    assert!(!agent.is_soft_locked());
    agent.unlock("master").unwrap();
    agent.lock();
    assert!(agent.summaries().is_none());
    agent.set_keep_list(true);

    // Another vault file: nothing of this one stays.
    agent.unlock("master").unwrap();
    agent.lock();
    assert!(agent.is_soft_locked());
    let mut config = agent.config();
    config.vault_path = dir.path().join("other.vault");
    agent.reconfigure(config);
    assert!(agent.summaries().is_none());
}

#[test]
fn auto_lock_is_a_soft_lock_and_the_list_follows_edits() {
    let ui = Arc::new(FakeUi::default());
    let dir = tempfile::tempdir().unwrap();
    let agent = Agent::new(
        AgentConfig {
            vault_path: dir.path().join("v.vault"),
            device_id: "d".into(),
            auto_lock: Duration::ZERO,
            webdav: None,
            gdrive: None,
            kept_list: None,
        },
        ui.clone(),
    );
    agent.create_vault("m").unwrap();
    add_secret_login(&agent);
    agent.tick();
    assert!(agent.is_soft_locked());
    agent.unlock("m").unwrap();
    add_login(&agent, "Example", "ex", &["https://example.com"]);
    // While unlocked the list is the vault's own.
    assert_eq!(agent.summaries().unwrap().len(), 2);
    agent.tick();
    let titles: Vec<String> = agent
        .summaries()
        .unwrap()
        .iter()
        .map(|i| i.title.clone())
        .collect();
    assert_eq!(titles, ["Example", "GitHub"]);
}

fn add_used_login(agent: &Agent, title: &str, url: &str) -> Item {
    agent
        .vault()
        .unwrap()
        .upsert(Item {
            title: title.into(),
            username: title.to_lowercase(),
            password: format!("{title}-pw"),
            urls: vec![url.into()],
            ..Default::default()
        })
        .unwrap()
}

/// Waits up to [`pass_agent::USE_SAVE_DELAY`] plus 5 s for `done`.
fn eventually(done: impl Fn() -> bool) -> bool {
    let until = std::time::Instant::now() + pass_agent::USE_SAVE_DELAY + Duration::from_secs(5);
    while std::time::Instant::now() < until {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    done()
}

fn listed_titles(result: &Value) -> Vec<String> {
    result["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["title"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn fills_are_counted_and_the_most_used_login_comes_first() {
    let ui = Arc::new(FakeUi {
        copy_supported: true,
        ..Default::default()
    });
    let (dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let alpha = add_used_login(&agent, "Alpha", "https://example.com");
    let beta = add_used_login(&agent, "Beta", "https://example.com");
    agent.save().unwrap();
    let find = || {
        call(
            &agent,
            "logins.find",
            json!({ "url": "https://example.com/login" }),
        )
    };
    assert_eq!(listed_titles(&find()), ["Alpha", "Beta"]);

    // A fill counts as a use: Beta is suggested first now. Nothing about the item changes.
    let before = agent.vault().unwrap().get(beta.id.clone()).unwrap();
    let revision = agent.sync_pending().unwrap().1;
    let filled = call(
        &agent,
        "logins.fill",
        json!({ "url": "https://example.com/login", "id": beta.id }),
    );
    assert_eq!(filled["result"]["password"], "Beta-pw");
    assert_eq!(listed_titles(&find()), ["Beta", "Alpha"]);
    let vault = agent.vault().unwrap();
    assert_eq!(vault.usage(beta.id.clone()).count, 1);
    assert_eq!(vault.get(beta.id.clone()).unwrap(), before);
    assert_eq!(
        agent.sync_pending().unwrap().1,
        revision,
        "a use doesn't start the edit debounce"
    );
    assert!(!agent.usage_sync_due());

    // Saved to the file a moment later, on a thread of its own (the fill didn't wait for it).
    let on_disk = || {
        Vault::unlock(
            std::fs::read(dir.path().join("pass.vault")).unwrap(),
            "master".into(),
            "x".into(),
        )
        .unwrap()
        .usage(beta.id.clone())
        .count
    };
    assert!(eventually(|| on_disk() == 1), "the use reaches the file");
    assert!(!vault.is_dirty());

    // Search orders the same way (after titles starting with the query).
    assert_eq!(listed_titles(&search(&agent, "example")), ["Beta", "Alpha"]);
    // Favorites still come first.
    vault
        .upsert(Item {
            favorite: true,
            ..alpha.clone()
        })
        .unwrap();
    assert_eq!(listed_titles(&find()), ["Alpha", "Beta"]);
    assert_eq!(listed_titles(&search(&agent, "example")), ["Alpha", "Beta"]);

    // The soft-locked list keeps the order.
    vault
        .upsert(Item {
            favorite: false,
            ..alpha.clone()
        })
        .unwrap();
    agent.lock_as(LockKind::Soft);
    let locked = find();
    assert_eq!(locked["result"]["locked"], true);
    assert_eq!(listed_titles(&locked), ["Beta", "Alpha"]);
}

#[test]
fn a_fill_moves_a_login_above_one_saved_with_the_page_path() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    // Imported from a browser with the sign-in page's path, and one Passyble saved (origin only).
    add_used_login(&agent, "Imported", "https://example.com/login");
    let saved = add_used_login(&agent, "Saved", "https://example.com");
    let find = || {
        call(
            &agent,
            "logins.find",
            json!({ "url": "https://example.com/login" }),
        )
    };
    assert_eq!(listed_titles(&find()), ["Imported", "Saved"]);
    let filled = call(
        &agent,
        "logins.fill",
        json!({ "url": "https://example.com/login", "id": saved.id }),
    );
    assert_eq!(filled["result"]["password"], "Saved-pw");
    assert_eq!(listed_titles(&find()), ["Saved", "Imported"]);
}

#[test]
fn copies_and_passkey_sign_ins_are_uses() {
    let ui = Arc::new(FakeUi {
        copy_supported: true,
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    let count = |agent: &Agent| agent.vault().unwrap().usage(github.id.clone()).count;

    // A username copy is no use; a password copy is.
    let copy = |field: &str| {
        call(
            &agent,
            "logins.copy",
            json!({ "id": github.id, "field": field, "url": "https://github.com/" }),
        )
    };
    assert_eq!(copy("username")["result"]["copied"], true);
    assert_eq!(count(&agent), 0);
    assert_eq!(copy("password")["result"]["copied"], true);
    assert_eq!(count(&agent), 1);

    // A passkey sign-in counts for the login holding the passkey.
    let create = json!({
        "origin": "https://example.com",
        "rp": { "id": "example.com", "name": "Example" },
        "user": { "id": b64url_encode(b"u1".to_vec()), "name": "alice", "displayName": "Alice" },
        "challenge": b64url_encode(vec![1; 32]),
        "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
    });
    assert_eq!(call(&agent, "passkey.create", create)["error"], Value::Null);
    let vault = agent.vault().unwrap();
    let holder = vault.find_passkeys("example.com".into(), vec![])[0]
        .item_id
        .clone();
    assert_eq!(vault.usage(holder.clone()).count, 0, "creating is no use");
    let get = json!({ "origin": "https://example.com", "rpId": "example.com", "challenge": b64url_encode(vec![2; 32]) });
    assert_eq!(call(&agent, "passkey.get", get)["error"], Value::Null);
    assert_eq!(vault.usage(holder).count, 1);
}

#[test]
fn a_2fa_code_the_user_picks_is_a_use() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    let github = add_github(&agent);
    let count = |agent: &Agent| agent.vault().unwrap().usage(github.id.clone()).count;
    // Copied from the popup (or picked in the menu): the login is used.
    let code = call(
        &agent,
        "totp.get",
        json!({ "url": "https://github.com/", "id": github.id }),
    );
    assert_eq!(code["result"]["id"], github.id.as_str());
    assert_eq!(count(&agent), 1);
    // Another site's request is refused and counts nothing.
    let stolen = call(
        &agent,
        "totp.get",
        json!({ "url": "https://evil.example", "id": github.id }),
    );
    assert_eq!(stolen["error"]["code"], "url_mismatch");
    assert_eq!(count(&agent), 1);
}

#[test]
fn auto_type_suggests_the_most_used_login_first() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("m").unwrap();
    let vault = agent.vault().unwrap();
    for title in ["Steam main", "Steam alt"] {
        vault
            .upsert(Item {
                title: title.into(),
                urls: vec!["windows:steam.exe".into()],
                ..Default::default()
            })
            .unwrap();
    }
    let titles = || {
        agent
            .find_for_window("Sign in", "steam.exe")
            .into_iter()
            .map(|i| i.title)
            .collect::<Vec<_>>()
    };
    assert_eq!(titles(), ["Steam alt", "Steam main"]);
    let main = agent.find_for_window("Sign in", "steam.exe")[1].clone();
    agent.record_use(&main.id);
    assert_eq!(titles(), ["Steam main", "Steam alt"]);
}

// ---- unlocking from the extension's own form (unlock.options / unlock.password / unlock.hello) ----

fn locked_vault(ui: Arc<FakeUi>) -> (tempfile::TempDir, Arc<Agent>, String) {
    let (dir, agent) = setup(ui);
    agent.create_vault("master").unwrap();
    let id = add_github(&agent).id;
    agent.save_and_lock().unwrap();
    assert!(agent.is_locked());
    (dir, agent, id)
}

#[test]
fn status_advertises_inline_unlock() {
    let (_dir, agent) = setup(Arc::default());
    let features = call(&agent, "status", json!({}))["result"]["features"].clone();
    assert!(features
        .as_array()
        .unwrap()
        .contains(&json!("unlock.inline")));
}

#[test]
fn inline_unlock_with_the_master_password() {
    let ui = Arc::new(FakeUi::default());
    let (_dir, agent, id) = locked_vault(ui.clone());
    let options = call(&agent, "unlock.options", json!({}));
    assert_eq!(
        options["result"],
        json!({ "locked": true, "password": true, "hello": false })
    );

    let wrong = call(&agent, "unlock.password", json!({ "password": "nope" }));
    assert_eq!(code(&wrong), "wrong_password");
    assert_eq!(
        wrong["error"]["message"],
        "Wrong master password. Check Caps Lock and try again."
    );
    assert!(!wrong.to_string().contains("nope"), "{wrong}");
    assert!(agent.is_locked());

    let events = ui.lock_events.lock().unwrap().len();
    let right = call(&agent, "unlock.password", json!({ "password": "master" }));
    assert_eq!(right["result"], json!({ "locked": false }), "{right}");
    assert!(!agent.is_locked());
    assert_eq!(ui.lock_events.lock().unwrap()[events..], [false]);
    // The request the extension retries goes through now.
    let fill = call(
        &agent,
        "logins.fill",
        json!({ "url": "https://github.com/login", "id": id }),
    );
    assert_eq!(fill["result"]["password"], "pw", "{fill}");
    // Unlocked: nothing to do, whatever the password; Windows Hello is never offered.
    assert_eq!(
        call(&agent, "unlock.password", json!({ "password": "x" }))["result"]["locked"],
        false
    );
    assert_eq!(
        call(&agent, "unlock.options", json!({}))["result"],
        json!({ "locked": false, "password": true, "hello": false })
    );
}

/// The extension fills as soon as `unlock.password` answers. The app hears of the unlock before
/// the answer leaves, so it can count it as this fill's verification, and the fill itself never
/// writes the vault file (the use is saved a moment later).
#[test]
fn a_fill_right_after_an_unlock_goes_straight_through() {
    let ui = Arc::new(FakeUi {
        verify: Some(true),
        ..Default::default()
    });
    let (dir, agent, id) = locked_vault(ui.clone());
    let path = dir.path().join("pass.vault");
    let unlocked = call(&agent, "unlock.password", json!({ "password": "master" }));
    assert_eq!(unlocked["result"]["locked"], false, "{unlocked}");
    assert_eq!(ui.lock_events.lock().unwrap().last(), Some(&false));
    let before = std::fs::read(&path).unwrap();

    let started = std::time::Instant::now();
    let fill = call(
        &agent,
        "logins.fill",
        json!({ "url": "https://github.com/login", "id": id }),
    );
    let took = started.elapsed();
    assert_eq!(fill["result"]["password"], "pw", "{fill}");
    assert_eq!(ui.verifications.lock().unwrap().len(), 1);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "the fill doesn't write the vault file"
    );
    assert!(took < Duration::from_secs(1), "{took:?}");
    // The use reaches the file on its own, a moment later.
    assert!(eventually(|| std::fs::read(&path).unwrap() != before));
    let on_disk =
        Vault::unlock(std::fs::read(&path).unwrap(), "master".into(), "x".into()).unwrap();
    assert_eq!(on_disk.usage(id).count, 1);
}

/// Locking right after a fill keeps the use: the lock saves what is still waiting.
#[test]
fn locking_saves_a_use_that_was_still_waiting() {
    let (dir, agent, id) = locked_vault(Arc::default());
    agent.unlock("master").unwrap();
    let fill = call(
        &agent,
        "logins.fill",
        json!({ "url": "https://github.com/login", "id": id }),
    );
    assert_eq!(fill["result"]["password"], "pw", "{fill}");
    agent.save_and_lock().unwrap();
    let path = dir.path().join("pass.vault");
    let on_disk =
        Vault::unlock(std::fs::read(&path).unwrap(), "master".into(), "x".into()).unwrap();
    assert_eq!(on_disk.usage(id).count, 1);
}

/// A slow save (a sync client or antivirus holding the vault file, so the rename is retried for
/// about a second) must not hold the agent's state and block requests.
#[cfg(windows)]
#[test]
fn requests_dont_wait_for_a_slow_vault_write() {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 1;
    let (dir, agent, id) = locked_vault(Arc::default());
    agent.unlock("master").unwrap();
    let path = dir.path().join("pass.vault");
    // Open without FILE_SHARE_DELETE: replacing the file fails until it is closed.
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&path)
        .unwrap();
    add_example(&agent);
    let saving = {
        let agent = agent.clone();
        std::thread::spawn(move || {
            let started = std::time::Instant::now();
            let result = agent.save();
            (result, started.elapsed())
        })
    };
    // Give the save time to reach the retries.
    std::thread::sleep(Duration::from_millis(300));
    let started = std::time::Instant::now();
    let fill = call(
        &agent,
        "logins.fill",
        json!({ "url": "https://github.com/login", "id": id }),
    );
    let find = call(
        &agent,
        "logins.find",
        json!({ "url": "https://github.com/login" }),
    );
    let took = started.elapsed();
    assert_eq!(fill["result"]["password"], "pw", "{fill}");
    assert_eq!(
        find["result"]["items"].as_array().unwrap().len(),
        1,
        "{find}"
    );
    let (result, saving_took) = saving.join().unwrap();
    assert!(result.is_err(), "the file stayed held");
    assert!(saving_took >= Duration::from_millis(600), "{saving_took:?}");
    assert!(
        took < Duration::from_millis(300),
        "requests waited {took:?}"
    );
    drop(holder);
    // The edit wasn't lost: the next save writes it.
    agent.save().unwrap();
    assert_eq!(titles_in(&path).len(), 2);
}

#[test]
fn inline_unlock_checks_its_input() {
    let (_dir, agent, _) = locked_vault(Arc::default());
    for params in [
        json!({}),
        json!({ "password": "" }),
        json!({ "password": 7 }),
        json!({ "password": "x".repeat(1025) }),
    ] {
        let response = call(&agent, "unlock.password", params.clone());
        assert_eq!(code(&response), "invalid_params", "{params}: {response}");
    }
    assert!(agent.is_locked());
}

#[test]
fn inline_unlock_attempts_are_rate_limited() {
    let (_dir, agent, _) = locked_vault(Arc::default());
    for _ in 0..5 {
        let response = call(&agent, "unlock.password", json!({ "password": "guess" }));
        assert_eq!(code(&response), "wrong_password");
    }
    // Even the right password waits now.
    let limited = call(&agent, "unlock.password", json!({ "password": "master" }));
    assert_eq!(code(&limited), "rate_limited");
    assert!(agent.is_locked());
}

#[test]
fn inline_unlock_uses_the_desktop_apps_unlock() {
    let ui = Arc::new(FakeUi {
        password_answer: Some(UnlockAttempt::Failed("The vault file is in use".into())),
        ..Default::default()
    });
    let (_dir, agent, _) = locked_vault(ui.clone());
    let response = call(&agent, "unlock.password", json!({ "password": "master" }));
    assert_eq!(code(&response), "internal");
    assert_eq!(response["error"]["message"], "The vault file is in use");
    assert_eq!(*ui.passwords.lock().unwrap(), ["master"]);

    let ui = Arc::new(FakeUi {
        password_answer: Some(UnlockAttempt::WrongPassword),
        ..Default::default()
    });
    let (_dir, agent, _) = locked_vault(ui);
    let response = call(&agent, "unlock.password", json!({ "password": "master" }));
    assert_eq!(code(&response), "wrong_password");

    // An app that says "unlocked" while the vault is still locked is not believed.
    let ui = Arc::new(FakeUi {
        password_answer: Some(UnlockAttempt::Unlocked),
        ..Default::default()
    });
    let (_dir, agent, _) = locked_vault(ui);
    let response = call(&agent, "unlock.password", json!({ "password": "master" }));
    assert_eq!(code(&response), "internal");
}

#[test]
fn inline_unlock_with_windows_hello() {
    let ui = Arc::new(FakeUi {
        hello_offered: true,
        hello_unlocks_with: Some("master".into()),
        ..Default::default()
    });
    let (_dir, agent, _) = locked_vault(ui.clone());
    assert_eq!(
        call(&agent, "unlock.options", json!({}))["result"]["hello"],
        true
    );
    let response = call(&agent, "unlock.hello", json!({}));
    assert_eq!(response["result"], json!({ "locked": false }), "{response}");
    assert!(!agent.is_locked());
    // Already unlocked: no prompt.
    assert_eq!(
        call(&agent, "unlock.hello", json!({}))["result"]["locked"],
        false
    );
    assert_eq!(*ui.hello_calls.lock().unwrap(), 1);
}

/// `for` on an unlock names the login it is for, readable by the app while the unlock is pending.
/// An unlock for nothing in particular names none.
#[test]
fn an_unlock_for_a_fill_names_its_login() {
    let ui = Arc::new(FakeUi {
        hello_offered: true,
        hello_unlocks_with: Some("master".into()),
        ..Default::default()
    });
    let (_dir, agent, id) = locked_vault(ui.clone());
    ui.unlocked_for.lock().unwrap().clear();
    let response = call(&agent, "unlock.hello", json!({ "for": id }));
    assert_eq!(response["result"]["locked"], false, "{response}");
    assert_eq!(*ui.unlocked_for.lock().unwrap(), [Some(id.clone())]);
    assert_eq!(agent.unlock_requested_for(), None, "not after the answer");

    // The extension's master password form, and an unlock for nothing in particular.
    agent.save_and_lock().unwrap();
    let response = call(
        &agent,
        "unlock.password",
        json!({ "password": "master", "for": id }),
    );
    assert_eq!(response["result"]["locked"], false, "{response}");
    agent.save_and_lock().unwrap();
    assert_eq!(
        call(&agent, "unlock.hello", json!({}))["result"]["locked"],
        false
    );
    // Anything that can't be an item id is no `for` (and no reason to refuse the unlock).
    agent.save_and_lock().unwrap();
    let response = call(&agent, "unlock.hello", json!({ "for": "x".repeat(500) }));
    assert_eq!(response["result"]["locked"], false, "{response}");
    agent.save_and_lock().unwrap();
    let response = call(&agent, "unlock.hello", json!({ "for": 7 }));
    assert_eq!(response["result"]["locked"], false, "{response}");
    assert_eq!(
        *ui.unlocked_for.lock().unwrap(),
        [Some(id.clone()), Some(id), None, None, None]
    );
}

/// Passwords and 2FA codes are checked with the login's id, and the code of the login just filled
/// is marked as following that fill.
#[test]
fn fills_and_codes_are_checked_per_login() {
    let ui = Arc::new(FakeUi {
        verify: Some(true),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let item = add_github(&agent);
    let url = "https://github.com/login";
    let fill = call(&agent, "logins.fill", json!({ "url": url, "id": item.id }));
    assert_eq!(fill["result"]["password"], "pw", "{fill}");
    let pending = call(&agent, "totp.get", json!({ "url": url }));
    assert!(pending["result"]["code"].is_string(), "{pending}");
    // Picked by id from the menu: the same login as the pending code, so it follows the fill too.
    let picked = call(&agent, "totp.get", json!({ "url": url, "id": item.id }));
    assert!(picked["result"]["code"].is_string(), "{picked}");
    assert_eq!(
        *ui.item_checks.lock().unwrap(),
        [
            (item.id.clone(), "password"),
            (item.id.clone(), "pending code"),
            (item.id.clone(), "pending code"),
        ]
    );
    // The pending code asked nothing of the user.
    assert_eq!(ui.verifications.lock().unwrap().len(), 1);
}

#[test]
fn inline_hello_cancelled_or_unavailable() {
    for (answer, expected) in [
        (Some(UnlockAttempt::Cancelled), "cancelled"),
        (None, "not_supported"),
        (
            Some(UnlockAttempt::Unavailable(
                "Passyble asks for your master password every 7 days.".into(),
            )),
            "not_supported",
        ),
        // The app says unlocked, the vault isn't: treated as cancelled.
        (Some(UnlockAttempt::Unlocked), "cancelled"),
    ] {
        let ui = Arc::new(FakeUi {
            hello_answer: answer.clone(),
            ..Default::default()
        });
        let (_dir, agent, _) = locked_vault(ui);
        let response = call(&agent, "unlock.hello", json!({}));
        assert_eq!(code(&response), expected, "{answer:?}: {response}");
        assert!(agent.is_locked());
    }
}

/// A UI with only the required hooks: every optional one keeps its default.
struct BareUi;

impl Ui for BareUi {
    fn request_unlock(&self) -> bool {
        false
    }
    fn confirm_passkey_create(&self, _rp_id: &str, _user: &str) -> Consent {
        Consent::Deny
    }
    fn choose_passkey(&self, _rp_id: &str, _options: &[PasskeyChoice]) -> Option<usize> {
        None
    }
    fn show_totp_popup(&self, _item_id: &str, _title: &str) {}
    fn notify_lock_state(&self, _locked: bool) {}
}

fn features_of(agent: &Agent) -> Vec<Value> {
    call(agent, "status", json!({}))["result"]["features"]
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn unlock_cancel_with_the_default_ui_cancels_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let agent = Agent::new(
        AgentConfig {
            vault_path: dir.path().join("pass.vault"),
            device_id: "laptop".into(),
            auto_lock: Duration::from_secs(900),
            webdav: None,
            gdrive: None,
            kept_list: None,
        },
        Arc::new(BareUi),
    );
    agent.create_vault("master").unwrap();
    agent.save_and_lock().unwrap();
    let response = call(&agent, "unlock.cancel", json!({}));
    assert_eq!(
        response["result"],
        json!({ "cancelled": false }),
        "{response}"
    );
    assert!(agent.is_locked());
    // Without the UI's support the extension uses its own Windows Hello flow.
    assert!(!features_of(&agent).contains(&json!("unlock.hello_browser")));
}

#[test]
fn unlock_cancel_asks_the_ui() {
    let ui = Arc::new(FakeUi {
        cancel_answer: true,
        ..Default::default()
    });
    let (_dir, agent, _) = locked_vault(ui.clone());
    let response = call(&agent, "unlock.cancel", json!({}));
    assert_eq!(
        response["result"],
        json!({ "cancelled": true }),
        "{response}"
    );
    assert!(agent.is_locked());
    // Also unlocked (the Hello prompt may have just finished) and with extra params.
    agent.unlock("master").unwrap();
    let response = call(&agent, "unlock.cancel", json!({ "unused": 1 }));
    assert_eq!(response["result"]["cancelled"], true, "{response}");
    // Called outside an IPC request thread: no client process.
    assert_eq!(*ui.cancel_calls.lock().unwrap(), [None, None]);

    let ui = Arc::new(FakeUi::default());
    let (_dir, agent, _) = locked_vault(ui.clone());
    let response = call(&agent, "unlock.cancel", json!({}));
    assert_eq!(
        response["result"],
        json!({ "cancelled": false }),
        "{response}"
    );
    assert_eq!(ui.cancel_calls.lock().unwrap().len(), 1);
}

#[test]
fn status_advertises_hello_in_the_browser_only_when_the_ui_does_it() {
    let (_dir, agent) = setup(Arc::default());
    assert!(!features_of(&agent).contains(&json!("unlock.hello_browser")));
    let (_dir, agent) = setup(Arc::new(FakeUi {
        hello_browser: true,
        ..Default::default()
    }));
    let features = features_of(&agent);
    assert!(features.contains(&json!("unlock.hello_browser")));
    assert!(features.contains(&json!("unlock.inline")));
}

#[test]
fn no_ipc_client_outside_a_request() {
    assert_eq!(pass_agent::ipc::request_client_pid(), None);
}

/// After a restart the list kept on disk makes the agent start soft-locked: logins are listed as
/// `locked`, and filling needs an unlock.
#[cfg(windows)]
#[test]
fn starts_soft_locked_from_the_kept_list() {
    let dir = tempfile::tempdir().unwrap();
    let config = AgentConfig {
        vault_path: dir.path().join("pass.vault"),
        device_id: "laptop".into(),
        auto_lock: Duration::from_secs(900),
        webdav: None,
        gdrive: None,
        kept_list: Some(dir.path().join("kept").join("vault-1.bin")),
    };
    {
        let agent = Agent::new(config.clone(), Arc::new(FakeUi::default()));
        agent.create_vault("master").unwrap();
        add_github(&agent);
        // Quitting: a full lock. The list leaves memory but stays on disk.
        agent.save_and_lock_as(LockKind::Full).unwrap();
    }
    let sealed = std::fs::read(config.kept_list.as_ref().unwrap()).unwrap();
    assert!(!String::from_utf8_lossy(&sealed).contains("GitHub"));

    let ui = Arc::new(FakeUi::default());
    let agent = Agent::new(config.clone(), ui.clone());
    *ui.agent.lock().unwrap() = Some(Arc::downgrade(&agent));
    assert_eq!(
        call(&agent, "status", json!({}))["result"]["soft_locked"],
        false
    );
    assert!(agent.restore_kept_list());
    let status = call(&agent, "status", json!({}));
    assert_eq!(status["result"]["locked"], true);
    assert_eq!(status["result"]["soft_locked"], true);

    let found = call(
        &agent,
        "logins.find",
        json!({ "url": "https://github.com/login" }),
    );
    assert_eq!(found["result"]["locked"], true);
    assert_eq!(found["result"]["items"][0]["title"], "GitHub");
    assert_eq!(found["result"]["items"][0]["username"], "octo");
    assert_eq!(found["result"]["items"][0]["has_totp"], true);
    let id = found["result"]["items"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!found.to_string().contains("\"pw\""), "{found}");
    let searched = call(&agent, "logins.search", json!({ "query": "git" }));
    assert_eq!(searched["result"]["locked"], true);
    assert_eq!(searched["result"]["items"][0]["id"], id);

    // Picking it: locked until the user unlocks, then it fills.
    let fill = json!({ "id": id, "url": "https://github.com/login" });
    assert_eq!(
        call(&agent, "logins.fill", fill.clone())["error"]["code"],
        "locked"
    );
    assert_eq!(
        call(&agent, "unlock.password", json!({ "password": "master" }))["result"]["locked"],
        false
    );
    assert_eq!(
        call(&agent, "logins.fill", fill)["result"]["password"],
        "pw"
    );

    // "Lock completely": gone from disk too, so the next start shows nothing until an unlock.
    agent.save_and_lock_as(LockKind::Full).unwrap();
    agent.forget_kept_list();
    assert!(!config.kept_list.as_ref().unwrap().exists());
    let agent = Agent::new(config, Arc::new(FakeUi::default()));
    assert!(!agent.restore_kept_list());
    assert!(agent.is_locked() && !agent.is_soft_locked());
}

// ---- cards and identities (cards.*, identities.*) ----------------------------------------------

fn add_card(agent: &Agent, title: &str, number: &str) -> Item {
    agent
        .vault()
        .unwrap()
        .upsert(Item {
            kind: ItemKind::Card,
            title: title.into(),
            card: Some(CardData {
                cardholder_name: "Ada Lovelace".into(),
                number: number.into(),
                expiry_month: 4,
                expiry_year: 2029,
                security_code: "737".into(),
                pin: "9876".into(),
                brand: String::new(),
            }),
            ..Default::default()
        })
        .unwrap()
}

fn add_identity(agent: &Agent) -> Item {
    agent
        .vault()
        .unwrap()
        .upsert(Item {
            kind: ItemKind::Identity,
            title: "Home".into(),
            identity: Some(IdentityData {
                first_name: "Ada".into(),
                middle_name: "King".into(),
                last_name: "Lovelace".into(),
                email: "ada@example.org".into(),
                phone: "+44 20 7946 0000".into(),
                address1: "12 St James's Square".into(),
                city: "London".into(),
                postal_code: "SW1Y 4JH".into(),
                country: "GB".into(),
                company: "Analytical Engines Ltd".into(),
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap()
}

const SHOP: &str = "https://shop.example/checkout";

#[test]
fn status_advertises_cards_and_identities() {
    let (_dir, agent) = setup(Arc::default());
    let features = call(&agent, "status", json!({}))["result"]["features"].clone();
    let features = features.as_array().unwrap();
    assert!(features.contains(&json!("cards")));
    assert!(features.contains(&json!("identities")));
}

#[test]
fn cards_list_has_no_secrets_and_skips_trash_and_logins() {
    let ui = Arc::new(FakeUi::default());
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    add_github(&agent);
    let visa = add_card(&agent, "", "4242 4242 4242 4242");
    let old = add_card(&agent, "Old card", "5555555555554444");
    agent.vault().unwrap().delete(old.id.clone()).unwrap();
    add_identity(&agent);

    let list = plain(call(&agent, "cards.list", json!({ "url": SHOP })));
    let items = list["result"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{list}");
    assert_eq!(
        items[0],
        json!({ "id": visa.id, "title": "Visa •••• 4242", "cardholder_name": "Ada Lovelace",
            "brand": "visa", "last4": "4242", "expiry_month": 4, "expiry_year": 2029,
            "favorite": false })
    );
    assert_eq!(list["result"]["locked"], false);
    let text = list.to_string();
    assert!(!text.contains("4242424242424242") && !text.contains("737") && !text.contains("9876"));
    assert!(
        ui.card_requests.lock().unwrap().is_empty(),
        "listing never prompts"
    );

    // Secure pages only: https, or http on this device.
    for bad in [
        "http://shop.example/",
        "file:///C:/pay.html",
        "chrome://newtab",
    ] {
        assert_eq!(
            call(&agent, "cards.list", json!({ "url": bad }))["error"]["code"],
            "url_mismatch",
            "{bad}"
        );
    }
    assert!(call(
        &agent,
        "cards.list",
        json!({ "url": "http://localhost:3000/" })
    )["result"]["items"]
        .is_array());

    // Soft-locked: the kept list (no secrets), `locked: true`. Fully locked: `locked`.
    agent.lock();
    let soft = call(&agent, "cards.list", json!({ "url": SHOP }));
    assert_eq!(soft["result"]["locked"], true);
    assert_eq!(soft["result"]["items"][0]["last4"], "4242");
    assert_eq!(
        call(&agent, "cards.fill", json!({ "url": SHOP, "id": visa.id }))["error"]["code"],
        "locked"
    );
    agent.lock_as(LockKind::Full);
    assert_eq!(
        call(&agent, "cards.list", json!({ "url": SHOP }))["error"]["code"],
        "locked"
    );
}

#[test]
fn cards_fill_asks_every_time_then_verifies() {
    let ui = Arc::new(FakeUi {
        card: Some(true),
        verify: Some(true),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let visa = add_card(&agent, "Work card", "4242424242424242");

    for _ in 0..2 {
        let filled = call(
            &agent,
            "cards.fill",
            json!({ "url": "https://js.stripe.com/v3/inner.html", "id": visa.id,
                "top_url": "https://shop.example/checkout" }),
        );
        assert_eq!(
            filled["result"],
            json!({ "cardholder_name": "Ada Lovelace", "number": "4242424242424242",
                "expiry_month": 4, "expiry_year": 2029, "security_code": "737", "brand": "visa" }),
            "{filled}"
        );
        assert!(!filled.to_string().contains("9876"), "never the PIN");
    }
    let requests = ui.card_requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 2, "a prompt for every fill");
    assert_eq!(
        requests[0],
        CardFillRequest {
            item_id: visa.id.clone(),
            title: "Work card".into(),
            brand: "visa".into(),
            last4: "4242".into(),
            page_host: "js.stripe.com".into(),
            top_host: "shop.example".into(),
            copy: false,
        }
    );
    assert_eq!(
        *ui.verifications.lock().unwrap(),
        [
            "Fill your Work card card on js.stripe.com",
            "Fill your Work card card on js.stripe.com"
        ]
    );
    // A use of the card (most used first; uses within a minute count once).
    let used = agent.summaries().unwrap();
    assert!(used.iter().any(|i| i.id == visa.id && i.use_count == 1));

    // The popup's copy says so; the top page is left out when it is the page itself.
    call(
        &agent,
        "cards.fill",
        json!({ "url": SHOP, "id": visa.id, "top_url": SHOP, "purpose": "copy" }),
    );
    let last = ui.card_requests.lock().unwrap().last().cloned().unwrap();
    assert!(last.copy);
    assert_eq!(last.page_host, "shop.example");
    assert_eq!(last.top_host, "");
}

#[test]
fn cards_fill_copy_with_a_field_copies_in_the_app() {
    let ui = Arc::new(FakeUi {
        card: Some(true),
        verify: Some(true),
        copy_supported: true,
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let visa = add_card(&agent, "Work card", "4242424242424242");
    let copy = |field: &str| {
        call(
            &agent,
            "cards.fill",
            json!({ "url": SHOP, "id": visa.id, "purpose": "copy", "field": field }),
        )
    };
    for field in ["number", "security_code"] {
        let r = copy(field);
        assert_eq!(
            r["result"],
            json!({ "copied": true, "field": field }),
            "{r}"
        );
        assert!(
            !r.to_string().contains("4242") && !r.to_string().contains("737"),
            "no card value goes to the browser"
        );
    }
    assert_eq!(*ui.copied.lock().unwrap(), ["4242424242424242", "737"]);
    assert_eq!(
        ui.card_requests.lock().unwrap().len(),
        2,
        "asked every time"
    );
    assert!(ui.card_requests.lock().unwrap().iter().all(|r| r.copy));

    // A field only goes with purpose "copy", and only these two.
    for params in [
        json!({ "url": SHOP, "id": visa.id, "field": "number" }),
        json!({ "url": SHOP, "id": visa.id, "purpose": "copy", "field": "pin" }),
    ] {
        assert_eq!(
            call(&agent, "cards.fill", params)["error"]["code"],
            "invalid_params"
        );
    }
    assert_eq!(
        ui.card_requests.lock().unwrap().len(),
        2,
        "refused before asking"
    );

    // A UI that can't copy: the card is returned for the extension to copy.
    let ui = Arc::new(FakeUi {
        card: Some(true),
        ..Default::default()
    });
    let (_dir2, agent) = setup(ui);
    agent.create_vault("master").unwrap();
    let visa = add_card(&agent, "Work card", "4242424242424242");
    let r = call(
        &agent,
        "cards.fill",
        json!({ "url": SHOP, "id": visa.id, "purpose": "copy", "field": "number" }),
    );
    assert_eq!(r["result"]["number"], "4242424242424242");
}

#[test]
fn cards_fill_refusals() {
    let ui = Arc::new(FakeUi {
        card: Some(false),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let visa = add_card(&agent, "", "4242424242424242");
    let github = add_github(&agent);
    let fill = |url: &str, id: &str| call(&agent, "cards.fill", json!({ "url": url, "id": id }));

    // Declined in the prompt.
    assert_eq!(fill(SHOP, &visa.id)["error"]["code"], "cancelled");
    // Insecure pages never reach the prompt; nor do logins, unknown or trashed items.
    assert_eq!(
        fill("http://shop.example/", &visa.id)["error"]["code"],
        "url_mismatch"
    );
    assert_eq!(fill(SHOP, &github.id)["error"]["code"], "not_found");
    assert_eq!(fill(SHOP, "nope")["error"]["code"], "not_found");
    assert_eq!(
        call(&agent, "cards.fill", json!({ "url": SHOP }))["error"]["code"],
        "invalid_params"
    );
    agent.vault().unwrap().delete(visa.id.clone()).unwrap();
    assert_eq!(fill(SHOP, &visa.id)["error"]["code"], "not_found");
    assert_eq!(ui.card_requests.lock().unwrap().len(), 1);
    assert!(agent.summaries().unwrap().iter().all(|i| i.use_count == 0));

    // A UI without the prompt: not_supported. The per-fill policy refusing: cancelled.
    let no_prompt = Arc::new(FakeUi::default());
    let (_dir2, agent2) = setup(no_prompt);
    agent2.create_vault("master").unwrap();
    let card = add_card(&agent2, "", "4242424242424242");
    assert_eq!(
        call(&agent2, "cards.fill", json!({ "url": SHOP, "id": card.id }))["error"]["code"],
        "not_supported"
    );
    let refuses = Arc::new(FakeUi {
        card: Some(true),
        verify: Some(false),
        ..Default::default()
    });
    let (_dir3, agent3) = setup(refuses.clone());
    agent3.create_vault("master").unwrap();
    let card = add_card(&agent3, "", "4242424242424242");
    assert_eq!(
        call(&agent3, "cards.fill", json!({ "url": SHOP, "id": card.id }))["error"]["code"],
        "cancelled"
    );
    assert_eq!(refuses.verifications.lock().unwrap().len(), 1);
}

// ---- saving cards typed into a checkout form (cards.save_check, cards.save) -------------------

fn card_check(agent: &Agent, number: &str, month: u32, year: u32) -> Value {
    call(
        agent,
        "cards.save_check",
        json!({ "url": SHOP, "number": number, "expiry_month": month, "expiry_year": year }),
    )
}

#[test]
fn card_save_check_decides_without_handing_out_numbers() {
    // Every verification refused: checking and saving a card must not ask for one.
    let ui = Arc::new(FakeUi {
        verify: Some(false),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let features = call(&agent, "status", json!({}))["result"]["features"].clone();
    assert!(features.as_array().unwrap().contains(&json!("cards.save")));
    let visa = add_card(&agent, "", "4242 4242 4242 4242");

    // A new number: save_new, with the brand and last four digits of the typed one only.
    let new = card_check(&agent, "5555 5555 5555 4444", 8, 31);
    assert_eq!(new["result"]["action"], "save_new", "{new}");
    assert_eq!(new["result"]["brand"], "mastercard");
    assert_eq!(new["result"]["last4"], "4444");
    let home = agent.vault().unwrap().vault_id();
    assert_eq!(new["result"]["default_vault"], home.as_str());
    assert_eq!(new["result"]["vaults"][0]["home"], true);
    assert!(!new.to_string().contains("5555555555554444"));

    // The same number with the same expiry (2-digit year or 4): nothing to offer.
    for year in [29, 2029] {
        let none = card_check(&agent, "4242-4242-4242-4242", 4, year);
        assert_eq!(none["result"]["action"], "none", "{none}");
        assert_eq!(none["result"]["id"], visa.id.as_str());
    }
    // No expiry typed: nothing new either.
    let none = call(
        &agent,
        "cards.save_check",
        json!({ "url": SHOP, "number": "4242424242424242" }),
    );
    assert_eq!(none["result"]["action"], "none", "{none}");

    // Another expiry: update_expiry, naming the saved card (never its number or code).
    let update = card_check(&agent, "4242424242424242", 5, 31);
    assert_eq!(update["result"]["action"], "update_expiry", "{update}");
    assert_eq!(update["result"]["id"], visa.id.as_str());
    assert_eq!(update["result"]["title"], "Visa •••• 4242");
    assert_eq!(update["result"]["saved_expiry_month"], 4);
    assert_eq!(update["result"]["saved_expiry_year"], 2029);
    assert_eq!(update["result"]["last4"], "4242");
    let text = update.to_string();
    assert!(!text.contains("4242424242424242") && !text.contains("737") && !text.contains("9876"));

    // A trashed card doesn't count.
    agent.vault().unwrap().delete(visa.id.clone()).unwrap();
    assert_eq!(
        card_check(&agent, "4242424242424242", 4, 29)["result"]["action"],
        "save_new"
    );

    // Refused: not Luhn-valid, too short or long, letters, a bad expiry, an insecure page.
    for number in [
        "4242424242424241",
        "42424242424",
        "42424242424242424242",
        "4242abcd42424242",
    ] {
        assert_eq!(
            code(&card_check(&agent, number, 4, 29)),
            "invalid_params",
            "{number}"
        );
    }
    assert_eq!(
        code(&card_check(&agent, "4242424242424242", 13, 29)),
        "invalid_params"
    );
    assert_eq!(
        code(&call(
            &agent,
            "cards.save_check",
            json!({ "url": "http://shop.example/", "number": "4242424242424242" })
        )),
        "url_mismatch"
    );
    assert!(ui.verifications.lock().unwrap().is_empty());
    assert!(ui.card_requests.lock().unwrap().is_empty());

    // Locked (soft or fully): locked, so the banner's Save unlocks and asks again.
    agent.lock();
    assert_eq!(
        code(&card_check(&agent, "4242424242424242", 4, 29)),
        "locked"
    );
    agent.lock_as(LockKind::Full);
    assert_eq!(
        code(&card_check(&agent, "4242424242424242", 4, 29)),
        "locked"
    );
}

#[test]
fn card_save_adds_or_updates_without_a_security_code() {
    let ui = Arc::new(FakeUi {
        verify: Some(false),
        ..Default::default()
    });
    let (dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();

    // A new card: number (digits only), expiry, holder; a security code sent along is ignored.
    let saved = call(
        &agent,
        "cards.save",
        json!({ "url": SHOP, "number": "4242 4242 4242 4242", "expiry_month": 4,
                "expiry_year": 29, "cardholder_name": "  Ada Lovelace ",
                "security_code": "123" }),
    );
    assert_eq!(saved["result"]["title"], "Visa •••• 4242", "{saved}");
    assert_eq!(saved["result"]["vault"]["home"], true);
    assert_eq!(saved["result"]["last4"], "4242");
    assert!(!saved.to_string().contains("4242424242424242"));
    let id = saved["result"]["id"].as_str().unwrap().to_string();
    let item = agent.vault().unwrap().get(id.clone()).unwrap();
    assert_eq!(item.kind, ItemKind::Card);
    let card = item.card.clone().unwrap();
    assert_eq!(card.number, "4242424242424242");
    assert_eq!((card.expiry_month, card.expiry_year), (4, 2029));
    assert_eq!(card.cardholder_name, "Ada Lovelace");
    assert_eq!(card.brand, "visa");
    assert!(card.security_code.is_empty() && card.pin.is_empty());
    assert!(item.urls.is_empty(), "a card belongs to no site");
    assert_eq!(*ui.vault_changes.lock().unwrap(), 1);
    assert!(
        ui.verifications.lock().unwrap().is_empty(),
        "saving asks nothing"
    );
    let reopened = Vault::unlock(
        std::fs::read(dir.path().join("pass.vault")).unwrap(),
        "master".into(),
        "laptop".into(),
    )
    .unwrap();
    assert!(reopened.get(id.clone()).is_some(), "written to the file");

    // A second Save of the same card adds no duplicate.
    let again = call(
        &agent,
        "cards.save",
        json!({ "url": SHOP, "number": "4242424242424242", "expiry_month": 4, "expiry_year": 2029 }),
    );
    assert_eq!(again["result"]["unchanged"], true, "{again}");
    assert_eq!(again["result"]["id"], id.as_str());
    // Without an id, a new expiry for the same number updates that card.
    let renewed = call(
        &agent,
        "cards.save",
        json!({ "url": SHOP, "number": "4242424242424242", "expiry_month": 5, "expiry_year": 31 }),
    );
    assert_eq!(renewed["result"]["updated"], true, "{renewed}");
    let count_cards = || {
        agent
            .vault()
            .unwrap()
            .items()
            .iter()
            .filter(|i| i.kind == ItemKind::Card)
            .count()
    };
    assert_eq!(count_cards(), 1);

    // With id: "Update card expiry?". The holder is only filled in when the card has none.
    let card_id = add_card(&agent, "Work card", "5555555555554444").id;
    let updated = call(
        &agent,
        "cards.save",
        json!({ "url": SHOP, "id": card_id, "number": "5555 5555 5555 4444",
                "expiry_month": 12, "expiry_year": 2032, "cardholder_name": "Someone Else" }),
    );
    assert_eq!(updated["result"]["updated"], true, "{updated}");
    assert_eq!(updated["result"]["title"], "Work card");
    let card = agent
        .vault()
        .unwrap()
        .get(card_id.clone())
        .unwrap()
        .card
        .unwrap();
    assert_eq!((card.expiry_month, card.expiry_year), (12, 2032));
    assert_eq!(card.cardholder_name, "Ada Lovelace", "kept");
    assert_eq!(card.security_code, "737", "kept");
    // The id must be a card with that number: another card's id changes nothing.
    let other = call(
        &agent,
        "cards.save",
        json!({ "url": SHOP, "id": card_id, "number": "4242424242424242",
                "expiry_month": 1, "expiry_year": 2040 }),
    );
    assert_eq!(code(&other), "not_found", "{other}");

    // A title, and a vault that isn't open.
    let titled = call(
        &agent,
        "cards.save",
        json!({ "url": SHOP, "number": "378282246310005", "expiry_month": 3,
                "expiry_year": 2030, "title": "Travel" }),
    );
    assert_eq!(titled["result"]["title"], "Travel", "{titled}");
    assert_eq!(titled["result"]["brand"], "amex");
    assert_eq!(
        code(&call(
            &agent,
            "cards.save",
            json!({ "url": SHOP, "number": "6011111111111117", "vault": "no-such-vault" })
        )),
        "not_found"
    );
    for (bad, expected) in [
        (
            json!({ "url": SHOP, "number": "6011111111111117", "title": "a\nb" }),
            "invalid_params",
        ),
        (
            json!({ "url": SHOP, "number": "6011111111111117", "cardholder_name": "x".repeat(257) }),
            "invalid_params",
        ),
        (
            json!({ "url": SHOP, "number": "6011111111111118" }),
            "invalid_params",
        ),
        (
            json!({ "url": "http://shop.example/", "number": "6011111111111117" }),
            "url_mismatch",
        ),
    ] {
        assert_eq!(
            code(&call(&agent, "cards.save", bad.clone())),
            expected,
            "{bad}"
        );
    }
    assert_eq!(count_cards(), 3, "nothing else added");

    agent.lock();
    assert_eq!(
        code(&call(
            &agent,
            "cards.save",
            json!({ "url": SHOP, "number": "6011111111111117" })
        )),
        "locked"
    );
}

#[test]
fn identities_list_and_fill() {
    let ui = Arc::new(FakeUi {
        verify: Some(false),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let home = add_identity(&agent);
    let visa = add_card(&agent, "", "4242424242424242");

    let list = plain(call(&agent, "identities.list", json!({ "url": SHOP })));
    assert_eq!(
        list["result"]["items"],
        json!([{ "id": home.id, "title": "Home", "full_name": "Ada King Lovelace",
            "email": "ada@example.org", "company": "Analytical Engines Ltd", "favorite": false }])
    );
    assert!(
        !list.to_string().contains("London"),
        "no address in the list"
    );

    let filled = call(
        &agent,
        "identities.fill",
        json!({ "url": SHOP, "id": home.id }),
    );
    let r = &filled["result"];
    assert_eq!(r["first_name"], "Ada");
    assert_eq!(r["full_name"], "Ada King Lovelace");
    assert_eq!(r["address1"], "12 St James's Square");
    assert_eq!(r["city"], "London");
    assert_eq!(r["postal_code"], "SW1Y 4JH");
    assert_eq!(r["country"], "GB");
    assert_eq!(r["phone"], "+44 20 7946 0000");
    assert_eq!(r["region"], "");
    // No prompt beyond the unlocked vault (the refusing verify hook is never asked).
    assert!(ui.verifications.lock().unwrap().is_empty());
    assert!(ui.card_requests.lock().unwrap().is_empty());
    assert!(agent
        .summaries()
        .unwrap()
        .iter()
        .any(|i| i.id == home.id && i.use_count == 1));

    assert_eq!(
        call(
            &agent,
            "identities.fill",
            json!({ "url": "http://shop.example/", "id": home.id })
        )["error"]["code"],
        "url_mismatch"
    );
    assert_eq!(
        call(
            &agent,
            "identities.fill",
            json!({ "url": SHOP, "id": visa.id })
        )["error"]["code"],
        "not_found"
    );
    agent.lock();
    assert_eq!(
        call(&agent, "identities.list", json!({ "url": SHOP }))["result"]["locked"],
        true
    );
    assert_eq!(
        call(
            &agent,
            "identities.fill",
            json!({ "url": SHOP, "id": home.id })
        )["error"]["code"],
        "locked"
    );
}

#[test]
fn generate_username_works_while_locked() {
    let (_dir, agent) = setup(Arc::default());
    let features = call(&agent, "status", json!({}))["result"]["features"].clone();
    for f in ["generate.username", "generate.email"] {
        assert!(features.as_array().unwrap().contains(&json!(f)), "{f}");
    }
    let name = call(&agent, "generate.username", json!({}))["result"]["username"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        name.contains('-') && name.chars().next().unwrap().is_ascii_uppercase(),
        "{name}"
    );
    let chars = call(
        &agent,
        "generate.username",
        json!({ "kind": "characters", "length": 9 }),
    )["result"]["username"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(chars.len(), 9);
    assert_eq!(
        call(&agent, "generate.username", json!({ "kind": "nope" }))["error"]["code"],
        "invalid_params"
    );
    assert_eq!(
        call(&agent, "generate.username", json!({ "separator": "/" }))["error"]["code"],
        "invalid_params"
    );
    // Addresses and services are in the vault: locked, nothing.
    assert_eq!(
        call(&agent, "generate.options", json!({}))["error"]["code"],
        "locked"
    );
    assert_eq!(
        call(&agent, "generate.email", json!({ "kind": "plus" }))["error"]["code"],
        "locked"
    );
}

#[test]
fn generate_email_from_the_vaults_settings() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    let options = call(&agent, "generate.options", json!({}));
    assert_eq!(
        options["result"],
        json!({ "plus": false, "catch_all": false, "aliases": [] })
    );
    assert_eq!(
        call(&agent, "generate.email", json!({ "kind": "plus" }))["error"]["code"],
        "not_found"
    );
    assert_eq!(
        call(&agent, "generate.email", json!({ "kind": "alias" }))["error"]["code"],
        "not_found"
    );

    let vault = agent.vault().unwrap();
    vault
        .set_email_generator_settings(pass_core::EmailGeneratorSettings {
            address: "alex@example.com".into(),
            domain: "mydomain.com".into(),
        })
        .unwrap();
    vault
        .set_alias_config(pass_core::AliasConfig {
            service: pass_core::AliasService::DuckDuckGo,
            token: "secret-ddg-token".into(),
            ..Default::default()
        })
        .unwrap();
    let options = call(&agent, "generate.options", json!({}));
    assert_eq!(
        options["result"],
        json!({
            "plus": true,
            "catch_all": true,
            "aliases": [{ "id": "duckduckgo", "name": "DuckDuckGo", "default": true }]
        })
    );
    // No address or token goes to the browser.
    let text = options.to_string();
    assert!(!text.contains("alex@") && !text.contains("secret-ddg-token"));

    let plus = call(
        &agent,
        "generate.email",
        json!({ "kind": "plus", "url": "https://github.com/join" }),
    )["result"]["email"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        plus.starts_with("alex+") && plus.ends_with("@example.com"),
        "{plus}"
    );
    assert!(!plus.contains("github"), "the site only with website: true");
    let tagged = call(
        &agent,
        "generate.email",
        json!({ "kind": "catch_all", "url": "https://github.com/join", "website": true }),
    );
    assert_eq!(tagged["result"]["email"], "github@mydomain.com");
    assert_eq!(
        call(
            &agent,
            "generate.email",
            json!({ "kind": "alias", "service": "nope" })
        )["error"]["code"],
        "invalid_params"
    );
    assert_eq!(
        call(
            &agent,
            "generate.email",
            json!({ "kind": "alias", "service": "fastmail" })
        )["error"]["code"],
        "not_found"
    );
    assert_eq!(
        call(&agent, "generate.email", json!({ "kind": "other" }))["error"]["code"],
        "invalid_params"
    );
}

// ---- password.check: local checks of a password about to be saved ---------------------------

fn codes(result: &Value) -> Vec<String> {
    result["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["code"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn password_check_finds_problems_and_reuse_but_not_the_edited_login() {
    let ui = Arc::new(FakeUi::default());
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    assert!(call(&agent, "status", json!({}))["result"]["features"]
        .as_array()
        .unwrap()
        .contains(&json!("password.check")));
    let strong = "Xk9#mQ2!vLp7@wZ4";
    let vault = agent.vault().unwrap();
    let a = vault
        .upsert(Item {
            title: "GitHub".into(),
            username: "octo".into(),
            password: strong.into(),
            urls: vec!["https://github.com".into()],
            ..Default::default()
        })
        .unwrap();
    vault
        .upsert(Item {
            title: "Shop".into(),
            password: strong.into(),
            urls: vec!["https://shop.example".into()],
            ..Default::default()
        })
        .unwrap();

    let new = call(
        &agent,
        "password.check",
        json!({ "password": strong, "username": "octo", "url": "https://github.com/join" }),
    )["result"]
        .clone();
    assert_eq!(new["vault_checked"], true);
    assert_eq!(codes(&new), ["reused"]);
    assert_eq!(new["issues"][0]["count"], 2);
    assert_eq!(new["issues"][0]["severity"], "high");
    // The login being updated is not "another login".
    let editing = call(
        &agent,
        "password.check",
        json!({ "password": strong, "id": a.id, "url": "https://github.com/login" }),
    )["result"]
        .clone();
    assert_eq!(editing["issues"][0]["count"], 1);

    let bad = call(
        &agent,
        "password.check",
        json!({ "password": "Octocat1", "username": "octocat@example.com", "url": "https://github.com" }),
    )["result"]
        .clone();
    let found = codes(&bad);
    assert!(found.contains(&"contains_username".to_string()), "{bad}");
    assert!(found.contains(&"short".to_string()), "{bad}");
    let short = bad["issues"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["code"] == "short")
        .unwrap()
        .clone();
    assert_eq!(short["min_length"], 12);
    let site = call(
        &agent,
        "password.check",
        json!({ "password": "Rq9vLm@2Wz-github", "url": "https://github.com/login" }),
    )["result"]
        .clone();
    assert_eq!(codes(&site), ["contains_site"]);
    assert_eq!(site["issues"][0]["name"], "github");

    let common =
        call(&agent, "password.check", json!({ "password": "P@ssw0rd" }))["result"].clone();
    assert_eq!(codes(&common)[0], "common");
    assert_eq!(common["label"], "very_weak");
    // Nothing secret in the answer, ever.
    for result in [&new, &editing, &bad, &site, &common] {
        let text = result.to_string();
        assert!(!text.contains(strong) && !text.contains("P@ssw0rd") && !text.contains("Octocat1"));
    }
    let empty = call(&agent, "password.check", json!({ "password": "" }))["result"].clone();
    assert_eq!(codes(&empty), Vec::<String>::new());
}

#[test]
fn password_check_while_locked_checks_only_the_password() {
    let ui = Arc::new(FakeUi::default());
    let (_dir, agent) = setup(ui.clone());
    // No vault yet (fully locked).
    let locked =
        call(&agent, "password.check", json!({ "password": "password" }))["result"].clone();
    assert_eq!(locked["vault_checked"], false);
    assert_eq!(codes(&locked)[0], "common");

    agent.create_vault("master").unwrap();
    let strong = "Xk9#mQ2!vLp7@wZ4";
    for title in ["A", "B"] {
        agent
            .vault()
            .unwrap()
            .upsert(Item {
                title: title.into(),
                password: strong.into(),
                ..Default::default()
            })
            .unwrap();
    }
    agent.lock();
    assert!(agent.is_locked());
    // Soft-locked: no reuse check (the kept list has no passwords), and no unlock prompt.
    let soft = call(&agent, "password.check", json!({ "password": strong }))["result"].clone();
    assert_eq!(soft["vault_checked"], false);
    assert_eq!(codes(&soft), Vec::<String>::new());
    assert!(agent.is_locked());
}

#[test]
fn password_check_validates_input_and_is_rate_limited() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    assert_eq!(
        call(&agent, "password.check", json!({}))["error"]["code"],
        "invalid_params"
    );
    assert_eq!(
        call(
            &agent,
            "password.check",
            json!({ "password": "x".repeat(5000) })
        )["error"]["code"],
        "invalid_params"
    );
    let mut limited = false;
    for _ in 0..200 {
        let res = call(&agent, "password.check", json!({ "password": "abc" }));
        if res["error"]["code"] == "rate_limited" {
            limited = true;
            break;
        }
    }
    assert!(limited, "checks are rate limited");
}

#[test]
fn password_check_is_not_vault_activity() {
    let dir = tempfile::tempdir().unwrap();
    let agent = Agent::new(
        AgentConfig {
            vault_path: dir.path().join("v.vault"),
            device_id: "d".into(),
            auto_lock: Duration::from_millis(1500),
            webdav: None,
            gdrive: None,
            kept_list: None,
        },
        Arc::new(FakeUi::default()),
    );
    agent.create_vault("m").unwrap();
    std::thread::sleep(Duration::from_millis(800));
    let res = call(
        &agent,
        "password.check",
        json!({ "password": "Xk9#mQ2!vLp7@wZ4" }),
    );
    assert_eq!(res["result"]["vault_checked"], true);
    std::thread::sleep(Duration::from_millis(800));
    agent.tick();
    assert!(agent.is_locked());
}

// ---- activity: what keeps the vault from auto-locking ---------------------------------------------

fn setup_lock(ui: Arc<FakeUi>, auto_lock: Duration) -> (tempfile::TempDir, Arc<Agent>) {
    let (dir, agent) = setup(ui);
    let mut config = agent.config();
    config.auto_lock = auto_lock;
    agent.reconfigure(config);
    (dir, agent)
}

/// How long the tests wait before a request, so "the timer restarted" (idle shorter than this
/// afterwards) and "it didn't" (at least this long) are told apart without racing the clock.
const PAUSE: Duration = Duration::from_millis(60);

fn uses(ui: &FakeUi) -> usize {
    *ui.uses.lock().unwrap()
}

#[test]
fn background_requests_are_not_activity() {
    let ui = Arc::new(FakeUi::default());
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("m").unwrap();
    let item = add_github(&agent);
    let page = "https://github.com/login";
    std::thread::sleep(PAUSE);
    let background = [
        ("status", json!({})),
        ("logins.find", json!({ "url": page })),
        ("logins.similar", json!({ "url": "https://github.de/" })),
        (
            "logins.save_check",
            json!({ "url": page, "username": "octo", "password": "other" }),
        ),
        (
            "password.check",
            json!({ "password": "Xk9#mQ2!vLp7@wZ4", "url": page }),
        ),
        ("icons.get", json!({ "url": page })),
        ("otp.outcome", json!({ "url": page, "outcome": "asked" })),
        ("cards.list", json!({ "url": page })),
        (
            "cards.save_check",
            json!({ "url": "https://shop.example/", "number": "4242424242424242" }),
        ),
        ("identities.list", json!({ "url": page })),
        ("notes.list", json!({})),
        ("generate", json!({})),
        ("generate.options", json!({})),
        ("unlock.options", json!({})),
        ("unlock.cancel", json!({})),
        (
            "passkey.find",
            json!({ "origin": "https://github.com", "rpId": "github.com" }),
        ),
        (
            "passkey.create_options",
            json!({ "origin": "https://github.com", "rpId": "github.com" }),
        ),
        ("vaults.pins", json!({})),
    ];
    for (method, params) in background {
        let answer = call(&agent, method, params);
        assert!(
            answer.get("result").is_some() || method == "icons.get",
            "{method}: {answer}"
        );
        assert!(agent.idle_for() >= PAUSE, "{method} counted as activity");
    }
    assert_eq!(uses(&ui), 0);
    // Exactly the methods listed as background ones.
    assert_eq!(pass_agent::BACKGROUND_METHODS.len(), 27);

    // A fill is use: the timer starts again and so does the per-fill grace period.
    let fill = call(&agent, "logins.fill", json!({ "url": page, "id": item.id }));
    assert_eq!(fill["result"]["password"], "pw");
    assert!(agent.idle_for() < PAUSE);
    assert_eq!(uses(&ui), 1);
}

#[test]
fn every_kind_of_credential_use_counts() {
    let ui = Arc::new(FakeUi {
        copy_supported: true,
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("m").unwrap();
    let item = add_github(&agent);
    let page = "https://github.com/login";
    let mut expected = 0;
    let mut used = |method: &str, params: Value| {
        std::thread::sleep(PAUSE);
        let answer = call(&agent, method, params);
        assert!(answer.get("result").is_some(), "{method}: {answer}");
        assert!(agent.idle_for() < PAUSE, "{method} did not count");
        expected += 1;
        assert_eq!(uses(&ui), expected, "{method}");
    };
    used("logins.fill", json!({ "url": page, "id": item.id }));
    // The pending code of that fill, and a code the user picked.
    used("totp.get", json!({ "url": page }));
    used("totp.get", json!({ "url": page, "id": item.id }));
    for field in ["username", "password", "totp"] {
        used(
            "logins.copy",
            json!({ "url": page, "id": item.id, "field": field }),
        );
    }
}

#[test]
fn a_cancelled_or_failed_fill_does_not_count() {
    let ui = Arc::new(FakeUi {
        verify: Some(false),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("m").unwrap();
    let item = add_github(&agent);
    std::thread::sleep(PAUSE);
    // Windows Hello declined.
    let refused = call(
        &agent,
        "logins.fill",
        json!({ "url": "https://github.com/login", "id": item.id }),
    );
    assert_eq!(refused["error"]["code"], "cancelled");
    // Another site's login, an unknown login.
    let mismatch = call(
        &agent,
        "logins.fill",
        json!({ "url": "https://evil.example/login", "id": item.id }),
    );
    assert_eq!(mismatch["error"]["code"], "url_mismatch");
    let unknown = call(
        &agent,
        "logins.fill",
        json!({ "url": "https://github.com/login", "id": "nope" }),
    );
    assert_eq!(unknown["error"]["code"], "not_found");
    assert!(agent.idle_for() >= PAUSE);
    assert_eq!(uses(&ui), 0);
}

#[test]
fn uses_restart_the_auto_lock_at_the_chosen_time_and_never_add_up() {
    let ui = Arc::new(FakeUi::default());
    let (_dir, agent) = setup_lock(ui, Duration::from_millis(400));
    agent.create_vault("m").unwrap();
    let item = add_github(&agent);
    let fill = json!({ "url": "https://github.com/login", "id": item.id });
    // Ten fills in a row, each well inside the timeout: still unlocked after more than the
    // timeout in total.
    for _ in 0..10 {
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            call(&agent, "logins.fill", fill.clone())["result"]["password"],
            "pw"
        );
        agent.tick();
        assert!(!agent.is_locked());
    }
    // But they don't add up: the timeout after the last fill locks it.
    std::thread::sleep(Duration::from_millis(450));
    agent.tick();
    assert!(agent.is_locked());
}

#[test]
fn the_auto_lock_waits_for_a_fill_in_progress() {
    let ui = Arc::new(FakeUi {
        verify: Some(true),
        // The Windows Hello prompt stays up past the auto-lock time.
        tick_during_verify: Some(Duration::from_millis(500)),
        ..Default::default()
    });
    let (_dir, agent) = setup_lock(ui.clone(), Duration::from_millis(300));
    agent.create_vault("m").unwrap();
    let item = add_github(&agent);
    let fill = json!({ "url": "https://github.com/login", "id": item.id });
    assert_eq!(
        call(&agent, "logins.fill", fill)["result"]["password"],
        "pw"
    );
    assert_eq!(*ui.locked_during_verify.lock().unwrap(), [false]);
    // The fill counted once it went through.
    agent.tick();
    assert!(!agent.is_locked());
    assert_eq!(uses(&ui), 1);
}

#[test]
fn a_fill_declined_after_the_timeout_lets_the_auto_lock_happen() {
    let ui = Arc::new(FakeUi {
        verify: Some(false),
        tick_during_verify: Some(Duration::from_millis(500)),
        ..Default::default()
    });
    let (_dir, agent) = setup_lock(ui.clone(), Duration::from_millis(300));
    agent.create_vault("m").unwrap();
    let item = add_github(&agent);
    let fill = json!({ "url": "https://github.com/login", "id": item.id });
    assert_eq!(
        call(&agent, "logins.fill", fill)["error"]["code"],
        "cancelled"
    );
    // Held off while the prompt was up, due as soon as it was declined.
    assert_eq!(*ui.locked_during_verify.lock().unwrap(), [false]);
    agent.tick();
    assert!(agent.is_locked());
    assert_eq!(uses(&ui), 0);
}

#[test]
fn the_app_s_own_uses_count_too() {
    let ui = Arc::new(FakeUi::default());
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("m").unwrap();
    let item = add_github(&agent);
    std::thread::sleep(PAUSE);
    // Looking for the window's logins (the auto-type hotkey) isn't use by itself...
    assert_eq!(agent.match_window("GitHub - Sign in", "app.exe").len(), 1);
    assert!(agent.idle_for() >= PAUSE);
    assert!(agent.peek_vault().is_some());
    assert!(agent.idle_for() >= PAUSE);
    // ... typing the login is (auto-type, a copy in the window, the Windows passkey provider).
    agent.record_use(&item.id);
    assert!(agent.idle_for() < PAUSE);
    assert_eq!(uses(&ui), 1);
    agent.note_use();
    assert_eq!(uses(&ui), 2);
    // Nothing while locked.
    agent.lock();
    agent.note_use();
    agent.record_use(&item.id);
    assert_eq!(uses(&ui), 2);
}

/// Records every hook that would put something in front of the user. Requests the extension
/// sends on its own must never reach one.
#[derive(Default)]
struct PromptTrap {
    prompts: Mutex<Vec<&'static str>>,
}

impl PromptTrap {
    fn hit(&self, hook: &'static str) {
        self.prompts.lock().unwrap().push(hook);
    }
    fn prompts(&self) -> Vec<&'static str> {
        self.prompts.lock().unwrap().clone()
    }
}

impl Ui for PromptTrap {
    fn request_unlock(&self) -> bool {
        self.hit("request_unlock");
        false
    }
    fn unlock_options(&self) -> UnlockOptions {
        // Windows Hello could unlock right now: still nothing may start it by itself.
        UnlockOptions { hello: true }
    }
    fn unlock_with_password(&self, _password: &str) -> Option<UnlockAttempt> {
        self.hit("unlock_with_password");
        Some(UnlockAttempt::Cancelled)
    }
    fn unlock_with_hello(&self) -> UnlockAttempt {
        self.hit("unlock_with_hello");
        UnlockAttempt::Cancelled
    }
    fn hello_in_browser(&self) -> bool {
        true
    }
    fn confirm_passkey_create(&self, _rp_id: &str, _user: &str) -> Consent {
        self.hit("confirm_passkey_create");
        Consent::Deny
    }
    fn choose_passkey(&self, _rp_id: &str, _options: &[PasskeyChoice]) -> Option<usize> {
        self.hit("choose_passkey");
        None
    }
    fn show_totp_popup(&self, _item_id: &str, _title: &str) {
        self.hit("show_totp_popup");
    }
    fn notify_lock_state(&self, _locked: bool) {}
    fn verify_user(&self, _reason: &Reason) -> Verification {
        self.hit("verify_user");
        Verification::Refused
    }
    fn require_verification(&self, _reason: &Reason) -> Verification {
        self.hit("require_verification");
        Verification::Refused
    }
    fn show_server_pairing(&self, _link: &str) -> bool {
        self.hit("show_server_pairing");
        false
    }
    fn show_item(&self, _item_id: &str) -> bool {
        self.hit("show_item");
        false
    }
    fn show_account(&self, _sign_in: bool) -> bool {
        self.hit("show_account");
        false
    }
    fn confirm_cross_fill(&self, _request: &CrossFillRequest) -> Option<bool> {
        self.hit("confirm_cross_fill");
        Some(false)
    }
    fn confirm_card_fill(&self, _request: &CardFillRequest) -> Option<bool> {
        self.hit("confirm_card_fill");
        Some(false)
    }
}

/// What the extension sends without the user asking: on browser start, page loads and field
/// focus, for the save banner, checks, icons, 2FA outcomes and a page's passkey request.
fn automatic_requests() -> Vec<(&'static str, Value)> {
    let page = "https://github.com/login";
    vec![
        ("status", json!({})),
        ("logins.find", json!({ "url": page })),
        (
            "logins.save_check",
            json!({ "url": page, "username": "octo", "password": "new-pw", "kind": "login" }),
        ),
        (
            "password.check",
            json!({ "password": "hunter2", "url": page }),
        ),
        ("icons.get", json!({ "url": page })),
        ("otp.outcome", json!({ "url": page, "outcome": "asked" })),
        (
            "cards.list",
            json!({ "url": "https://shop.example/checkout" }),
        ),
        (
            "cards.save_check",
            json!({ "url": "https://shop.example/checkout", "number": "4242424242424242" }),
        ),
        (
            "identities.list",
            json!({ "url": "https://shop.example/checkout" }),
        ),
        ("generate", json!({})),
        ("generate.options", json!({})),
        ("unlock.options", json!({})),
        ("unlock.cancel", json!({})),
        // The account line of the extension's Options and setup pages (app mode).
        ("account.status", json!({})),
        // The sign-in handoff's look at the app's account (browser mode).
        ("account.peer", json!({})),
        // A page's pending passkey request: what the extension may offer on its own.
        (
            "passkey.find",
            json!({ "origin": "https://github.com", "rpId": "github.com" }),
        ),
        // A page's create(): what the extension's save card offers.
        (
            "passkey.create_options",
            json!({ "origin": "https://github.com", "rpId": "github.com", "userName": "octo" }),
        ),
        // The pending code of a fill (no id): the 2FA page asks on its own.
        (
            "totp.get",
            json!({ "url": "https://github.com/sessions/two-factor" }),
        ),
    ]
}

fn trap_agent() -> (tempfile::TempDir, Arc<Agent>, Arc<PromptTrap>) {
    let ui = Arc::new(PromptTrap::default());
    let dir = tempfile::tempdir().unwrap();
    let agent = Agent::new(
        AgentConfig {
            vault_path: dir.path().join("pass.vault"),
            device_id: "laptop".into(),
            auto_lock: Duration::from_secs(900),
            webdav: None,
            gdrive: None,
            kept_list: None,
        },
        ui.clone(),
    );
    agent.create_vault("master").unwrap();
    add_github(&agent);
    (dir, agent, ui)
}

#[test]
fn requests_the_extension_sends_on_its_own_never_prompt() {
    let (_dir, agent, ui) = trap_agent();
    for state in ["unlocked", "soft-locked", "locked"] {
        match state {
            "unlocked" => {}
            "soft-locked" => agent.lock_as(LockKind::Soft),
            _ => {
                agent.unlock("master").unwrap();
                agent.lock_as(LockKind::Full);
            }
        }
        for (method, params) in automatic_requests() {
            let response = call(&agent, method, params);
            assert!(
                ui.prompts().is_empty(),
                "{state}: {method} reached {:?}: {response}",
                ui.prompts()
            );
            // Locked: no unlock prompt, the answer says so (or there is simply nothing to give).
            if state != "unlocked" {
                let code = response["error"]["code"].as_str().unwrap_or("");
                assert_ne!(code, "cancelled", "{state}: {method}: {response}");
            }
        }
        assert_eq!(agent.is_locked(), state != "unlocked", "{state}");
    }
}

#[test]
fn a_page_passkey_request_while_locked_answers_locked_without_an_unlock_prompt() {
    let (_dir, agent, ui) = trap_agent();
    for kind in [LockKind::Soft, LockKind::Full] {
        agent.lock_as(kind);
        // A sign-in page restored at browser start that asks for a passkey as it loads: the
        // extension falls back to the browser's own WebAuthn on `locked`.
        let get = call(&agent, "passkey.get", uv_get_params(None));
        assert_eq!(code(&get), "locked", "{get}");
        let create = call(&agent, "passkey.create", uv_create_params(Some("required")));
        assert_eq!(code(&create), "locked", "{create}");
        assert!(ui.prompts().is_empty(), "{:?}", ui.prompts());
        agent.unlock("master").unwrap();
    }
}

#[test]
fn background_methods_are_the_automatic_ones() {
    // Every method the extension sends on its own is a background method (no activity for the
    // auto-lock), except the pending 2FA code, which continues a fill the user made.
    let automatic: Vec<&str> = automatic_requests()
        .into_iter()
        .map(|(method, _)| method)
        .filter(|m| *m != "totp.get")
        .collect();
    for method in &automatic {
        assert!(
            pass_agent::BACKGROUND_METHODS.contains(method),
            "{method} is not a background method"
        );
    }
}

#[test]
fn passkey_prf_extension_for_the_browser() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    // A WhatsApp-like site: PRF at creation with an input, then at sign-in.
    let input = b64url_encode(b"backup key salt".to_vec());
    let reg = call(
        &agent,
        "passkey.create",
        example_create(
            "alice",
            json!({ "extensions": { "prf": { "eval": { "first": input } } } }),
        ),
    )["result"]
        .clone();
    let prf = &reg["clientExtensionResults"]["prf"];
    assert_eq!(prf["enabled"], true);
    let at_create = prf["results"]["first"].as_str().unwrap().to_string();
    assert_eq!(b64url_decode(at_create.clone()).unwrap().len(), 32);
    let credential_id = reg["credentialId"].as_str().unwrap().to_string();

    let get = |extensions: Value| {
        call(
            &agent,
            "passkey.get",
            json!({
                "origin": "https://example.com",
                "rpId": "example.com",
                "challenge": b64url_encode(vec![2; 32]),
                "allowCredentials": [{ "type": "public-key", "id": credential_id }],
                "extensions": extensions,
            }),
        )
    };
    // The same input gives the same output, every time; a second input its own output.
    let second = b64url_encode(b"next key".to_vec());
    let got = get(json!({ "prf": { "eval": { "first": input, "second": second } } }));
    let results = &got["result"]["clientExtensionResults"]["prf"]["results"];
    assert_eq!(results["first"], at_create.as_str());
    assert!(results["second"].is_string());
    assert_ne!(results["second"], results["first"]);
    // evalByCredential for this credential wins over eval.
    let got = get(json!({ "prf": {
        "eval": { "first": second },
        "evalByCredential": { credential_id.clone(): { "first": input } },
    } }));
    assert_eq!(
        got["result"]["clientExtensionResults"]["prf"]["results"]["first"],
        at_create.as_str()
    );
    // prf: {} at sign-in: an empty output; no prf: none at all.
    let got = get(json!({ "prf": {} }));
    assert_eq!(got["result"]["clientExtensionResults"]["prf"], json!({}));
    let got = get(json!({}));
    assert_eq!(got["result"]["clientExtensionResults"], json!({}));
    // Keys of evalByCredential that aren't in allowCredentials: SyntaxError (invalid_params).
    let got = get(json!({ "prf": { "evalByCredential": { "AQID": { "first": input } } } }));
    assert_eq!(got["error"]["code"], "invalid_params");
    // evalByCredential at creation: NotSupportedError (not_supported), before any prompt.
    let bad = example_create(
        "bob",
        json!({ "extensions": { "prf": { "evalByCredential": {} } } }),
    );
    assert_eq!(
        call(&agent, "passkey.create", bad)["error"]["code"],
        "not_supported"
    );
    // prf: {} at creation: enabled, no results.
    let reg = call(
        &agent,
        "passkey.create",
        example_create("carol", json!({ "extensions": { "prf": {} } })),
    )["result"]
        .clone();
    assert_eq!(
        reg["clientExtensionResults"]["prf"],
        json!({ "enabled": true })
    );
    // The status says the agent answers PRF.
    let status = call(&agent, "status", json!({}))["result"].clone();
    assert!(status["features"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f == "passkey.prf"));
}

/// What `items.import` moves of a vault kept in the browser (the extension's own): its file and
/// key, base64url.
fn browser_vault(items: Vec<Item>) -> (String, String) {
    let vault = Vault::create("browser master".into(), "browser".into()).unwrap();
    for item in items {
        vault.upsert(item).unwrap();
    }
    let file = b64url_encode(vault.serialize().unwrap());
    let key = b64url_encode(vault.export_vault_key());
    (file, key)
}

fn site_login(site: &str, user: &str, pw: &str) -> Item {
    Item {
        title: site.into(),
        username: user.into(),
        password: pw.into(),
        urls: vec![format!("https://{site}")],
        ..Default::default()
    }
}

#[test]
fn items_import_moves_the_browser_vault_in() {
    // Every verification refused: adding the browser's items must not ask for one.
    let ui = Arc::new(FakeUi {
        verify: Some(false),
        ..Default::default()
    });
    let (dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let features = call(&agent, "status", json!({}))["result"]["features"].clone();
    assert!(features
        .as_array()
        .unwrap()
        .contains(&json!("items.import")));
    // Here already: the same GitHub login, and the same note.
    let app = agent.vault().unwrap();
    app.upsert(site_login("github.com", "octo", "pw")).unwrap();
    let wifi = Item {
        kind: ItemKind::Note,
        title: "Wi-Fi".into(),
        notes: "hunter2".into(),
        ..Default::default()
    };
    app.upsert(wifi.clone()).unwrap();

    let passkey = pass_core::Passkey {
        credential_id: vec![1, 2, 3],
        rp_id: "example.com".into(),
        user_handle: vec![9],
        user_name: "ann".into(),
        user_display_name: "Ann".into(),
        private_key_pkcs8: vec![7; 8],
        ..Default::default()
    };
    let (file, key) = browser_vault(vec![
        // An exact duplicate (www. and case don't matter): skipped.
        site_login("www.github.com", "Octo", "pw"),
        // The same account with a 2FA secret the app's copy lacks: moved, nothing lost.
        Item {
            totp: Some("JBSWY3DPEHPK3PXP".into()),
            notes: "recovery: 1111".into(),
            ..site_login("github.com", "octo", "pw")
        },
        Item {
            passkeys: vec![passkey.clone()],
            ..site_login("example.com", "ann", "")
        },
        site_login("gitlab.com", "octo", "pw2"),
        wifi.clone(),
        Item {
            kind: ItemKind::Card,
            title: "Visa".into(),
            card: Some(CardData {
                cardholder_name: "Ann Example".into(),
                number: "4111111111111111".into(),
                ..Default::default()
            }),
            ..Default::default()
        },
    ]);
    let before = app.items().len();
    let res = call(&agent, "items.import", json!({ "file": file, "key": key }));
    let result = &res["result"];
    assert_eq!(result["total"], 6, "{res}");
    assert_eq!(result["added"], 4);
    assert_eq!(result["skipped"], 2);
    assert_eq!(result["failed"], json!([]));
    assert_eq!(result["failed_count"], 0);
    assert_eq!(result["vault"]["home"], true);
    let items = app.items();
    assert_eq!(items.len(), before + 4);
    let with_totp = items
        .iter()
        .find(|i| i.has_totp())
        .expect("the 2FA secret moved");
    assert_eq!(with_totp.notes, "recovery: 1111");
    let with_passkey = items
        .iter()
        .find(|i| !i.passkeys.is_empty())
        .expect("the passkey moved");
    assert_eq!(with_passkey.passkeys[0].credential_id, vec![1, 2, 3]);
    assert!(
        items
            .iter()
            .any(|i| i.kind == ItemKind::Card
                && i.card.as_ref().unwrap().number == "4111111111111111")
    );
    assert_eq!(
        items.iter().filter(|i| i.title == "Wi-Fi").count(),
        1,
        "the same note isn't added twice"
    );
    assert_eq!(*ui.vault_changes.lock().unwrap(), 1, "saved once");
    assert!(
        ui.verifications.lock().unwrap().is_empty(),
        "adding asks nothing"
    );
    let reopened = Vault::unlock(
        std::fs::read(dir.path().join("pass.vault")).unwrap(),
        "master".into(),
        "laptop".into(),
    )
    .unwrap();
    assert_eq!(reopened.items().len(), before + 4, "saved to the file");

    // Moving the same vault again adds nothing: every item is here now.
    let again = call(&agent, "items.import", json!({ "file": file, "key": key }));
    assert_eq!(again["result"]["added"], 0, "{again}");
    assert_eq!(again["result"]["skipped"], 6);
    assert_eq!(*ui.vault_changes.lock().unwrap(), 1, "nothing to save");

    // Another vault's key, a file that isn't a vault, a vault that isn't open, unknown fields.
    let (_, other_key) = browser_vault(vec![]);
    assert_eq!(
        code(&call(
            &agent,
            "items.import",
            json!({ "file": file, "key": other_key })
        )),
        "wrong_password"
    );
    for params in [
        json!({ "file": "AAAA", "key": key }),
        json!({ "file": "", "key": key }),
        json!({ "file": file, "key": key, "extra": true }),
        json!({ "file": file }),
    ] {
        assert_eq!(
            code(&call(&agent, "items.import", params.clone())),
            "invalid_params",
            "{params}"
        );
    }
    assert_eq!(
        code(&call(
            &agent,
            "items.import",
            json!({ "file": file, "key": key, "vault": "no-such-vault" })
        )),
        "not_found"
    );

    agent.lock();
    assert_eq!(
        code(&call(
            &agent,
            "items.import",
            json!({ "file": file, "key": key })
        )),
        "locked"
    );
}

// ---- favorites and secure notes (items.favorite, notes.list, notes.get) -------------------------

fn add_note(agent: &Agent, title: &str, text: &str, favorite: bool) -> Item {
    agent
        .vault()
        .unwrap()
        .upsert(Item {
            kind: ItemKind::Note,
            title: title.into(),
            notes: text.into(),
            favorite,
            ..Default::default()
        })
        .unwrap()
}

fn favorite(agent: &Agent, item: &Item) -> Item {
    agent
        .vault()
        .unwrap()
        .upsert(Item {
            favorite: true,
            ..item.clone()
        })
        .unwrap()
}

/// `(id, favorite)` of each item of a listing answer.
fn favorites(answer: &Value) -> Vec<(String, bool)> {
    answer["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("{answer}"))
        .iter()
        .map(|i| {
            (
                i["id"].as_str().unwrap().to_string(),
                i["favorite"].as_bool().unwrap(),
            )
        })
        .collect()
}

#[test]
fn status_advertises_notes_and_favorites() {
    let (_dir, agent) = setup(Arc::default());
    let features = call(&agent, "status", json!({}))["result"]["features"].clone();
    let features = features.as_array().unwrap();
    assert!(features.contains(&json!("items.favorite")));
    assert!(features.contains(&json!("notes.list")));
}

#[test]
fn item_lists_say_which_items_are_favorites() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    let other = add_github(&agent);
    let work = agent
        .vault()
        .unwrap()
        .upsert(Item {
            title: "GitHub work".into(),
            username: "octo-work".into(),
            password: "pw2".into(),
            urls: vec!["https://github.com".into()],
            ..Default::default()
        })
        .unwrap();
    let starred = favorite(&agent, &work);
    let card = favorite(&agent, &add_card(&agent, "Work card", "4242424242424242"));
    add_identity(&agent);

    // The favorite first on its site, then the other.
    let page = json!({ "url": "https://github.com/login" });
    assert_eq!(
        favorites(&call(&agent, "logins.find", page.clone())),
        [(starred.id.clone(), true), (other.id.clone(), false)]
    );
    let searched = favorites(&call(&agent, "logins.search", json!({ "query": "github" })));
    assert!(
        searched.contains(&(starred.id.clone(), true)),
        "{searched:?}"
    );
    assert!(
        searched.contains(&(other.id.clone(), false)),
        "{searched:?}"
    );
    let similar = favorites(&call(
        &agent,
        "logins.similar",
        json!({ "url": "https://github.de/" }),
    ));
    assert!(similar.contains(&(starred.id.clone(), true)), "{similar:?}");
    assert_eq!(
        favorites(&call(&agent, "cards.list", json!({ "url": SHOP }))),
        [(card.id.clone(), true)]
    );
    let identities = call(&agent, "identities.list", json!({ "url": SHOP }));
    assert_eq!(identities["result"]["items"][0]["favorite"], false);

    // Soft-locked: the kept list knows them too.
    agent.lock();
    let kept = call(&agent, "logins.find", page);
    assert_eq!(kept["result"]["locked"], true);
    assert_eq!(favorites(&kept)[0], (starred.id, true));
}

#[test]
fn notes_list_has_titles_only() {
    let ui = Arc::new(FakeUi {
        verify: Some(false),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let wifi = add_note(&agent, "Wifi at home", "demo-wifi-pass", false);
    let codes = add_note(&agent, "Recovery codes", "1111-2222 3333-4444", true);
    let old = add_note(&agent, "Old codes", "9999-0000", false);
    agent.vault().unwrap().delete(old.id.clone()).unwrap();
    add_github(&agent);

    let list = call(&agent, "notes.list", json!({}));
    assert_eq!(
        plain(list.clone())["result"],
        json!({
            "items": [
                { "id": codes.id, "title": "Recovery codes", "favorite": true,
                    "updated": codes.updated_at },
                { "id": wifi.id, "title": "Wifi at home", "favorite": false,
                    "updated": wifi.updated_at },
            ],
            "truncated": false, "locked": false,
        }),
        "favorites first, no trash, no logins"
    );
    assert!(list["result"]["items"][0]["vault_id"].is_string());
    assert_eq!(list["result"]["vaults"][0]["home"], true);
    let text = list.to_string();
    assert!(
        !text.contains("1111") && !text.contains("demo-wifi-pass"),
        "never the text"
    );
    assert!(
        ui.verifications.lock().unwrap().is_empty(),
        "listing never asks"
    );

    // The query matches titles (every word, any order), never the text.
    let titles = |query: &str| -> Vec<String> {
        call(&agent, "notes.list", json!({ "query": query }))["result"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["title"].as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(titles("CODES recovery"), ["Recovery codes"]);
    assert_eq!(titles("  "), ["Recovery codes", "Wifi at home"]);
    assert!(titles("1111").is_empty());
    assert!(titles("old").is_empty(), "trash left out");

    let limited = call(&agent, "notes.list", json!({ "limit": 1 }));
    assert_eq!(limited["result"]["items"].as_array().unwrap().len(), 1);
    assert_eq!(limited["result"]["truncated"], true);
    assert_eq!(
        call(&agent, "notes.list", json!({ "query": "x".repeat(129) }))["error"]["code"],
        "invalid_params"
    );

    // Soft-locked: from the kept list (titles only). Fully locked: `locked`.
    agent.lock();
    let soft = call(&agent, "notes.list", json!({}));
    assert_eq!(soft["result"]["locked"], true);
    assert_eq!(soft["result"]["items"][0]["title"], "Recovery codes");
    agent.lock_as(LockKind::Full);
    assert_eq!(
        call(&agent, "notes.list", json!({}))["error"]["code"],
        "locked"
    );
}

#[test]
fn notes_get_asks_every_time_and_copies_in_the_app() {
    let ui = Arc::new(FakeUi {
        verify: Some(true),
        copy_supported: true,
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let codes = add_note(&agent, "Recovery codes", "1111-2222\n3333-4444", true);
    let empty = add_note(&agent, "Empty", "", false);
    let login = add_github(&agent);

    for _ in 0..2 {
        let opened = call(&agent, "notes.get", json!({ "id": codes.id }));
        let r = &opened["result"];
        assert_eq!(r["notes"], "1111-2222\n3333-4444", "{opened}");
        assert_eq!(r["id"], codes.id.as_str());
        assert_eq!(r["title"], "Recovery codes");
        assert_eq!(r["favorite"], true);
        assert_eq!(r["vault"]["home"], true);
    }
    assert_eq!(
        *ui.verifications.lock().unwrap(),
        [
            "Show your Recovery codes note",
            "Show your Recovery codes note"
        ],
        "verified every time"
    );

    // Copied by the app: the text never goes to the browser.
    let copied = call(&agent, "notes.get", json!({ "id": codes.id, "copy": true }));
    assert_eq!(copied["result"], json!({ "copied": true }), "{copied}");
    assert_eq!(*ui.copied.lock().unwrap(), ["1111-2222\n3333-4444"]);
    assert_eq!(
        ui.verifications.lock().unwrap().last().map(String::as_str),
        Some("Copy your Recovery codes note")
    );
    assert_eq!(
        call(&agent, "notes.get", json!({ "id": empty.id, "copy": true }))["result"],
        json!({ "copied": false })
    );
    // A use of the note (most used first).
    let used = agent.summaries().unwrap();
    assert!(used.iter().any(|i| i.id == codes.id && i.use_count == 1));

    // Notes only, live ones only.
    for id in [login.id.as_str(), "no-such-id"] {
        assert_eq!(
            call(&agent, "notes.get", json!({ "id": id }))["error"]["code"],
            "not_found",
            "{id}"
        );
    }
    agent.vault().unwrap().delete(empty.id.clone()).unwrap();
    assert_eq!(
        call(&agent, "notes.get", json!({ "id": empty.id }))["error"]["code"],
        "not_found"
    );

    // Soft-locked: the kept list has no text, so `locked` (the extension unlocks and asks again).
    agent.lock();
    assert_eq!(
        call(&agent, "notes.get", json!({ "id": codes.id }))["error"]["code"],
        "locked"
    );
}

#[test]
fn notes_get_refusals() {
    // Declined: nothing leaves the vault.
    let ui = Arc::new(FakeUi {
        verify: Some(false),
        copy_supported: true,
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();
    let codes = add_note(&agent, "Recovery codes", "1111-2222", false);
    for params in [
        json!({ "id": codes.id }),
        json!({ "id": codes.id, "copy": true }),
    ] {
        let r = call(&agent, "notes.get", params);
        assert_eq!(r["error"]["code"], "cancelled", "{r}");
        assert!(!r.to_string().contains("1111"));
    }
    assert!(ui.copied.lock().unwrap().is_empty());

    // A UI without a clipboard can't copy (the text isn't handed out instead).
    let ui = Arc::new(FakeUi {
        verify: Some(true),
        ..Default::default()
    });
    let (_dir2, agent) = setup(ui);
    agent.create_vault("master").unwrap();
    let codes = add_note(&agent, "Recovery codes", "1111-2222", false);
    let r = call(&agent, "notes.get", json!({ "id": codes.id, "copy": true }));
    assert_eq!(r["error"]["code"], "not_supported", "{r}");
    assert!(!r.to_string().contains("1111"));

    // At most 30 a minute.
    let mut last = Value::Null;
    for _ in 0..31 {
        last = call(&agent, "notes.get", json!({ "id": codes.id }));
    }
    assert_eq!(last["error"]["code"], "rate_limited");
}
