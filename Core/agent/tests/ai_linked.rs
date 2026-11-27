// The connector for AI tools (`ai.*`) with linked vaults: marked items of every open vault, each
// with its vault; in a shared vault every use asks; a fill-only member's AI tool gets no secret;
// a vault kept from AI tools by policy doesn't exist for them; read-only mode refuses runs and
// reveals. Demo accounts and passwords only.
#![cfg(feature = "native")]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pass_agent::{
    Agent, AgentConfig, AiDecision, AiRevealRequest, AiRunRequest, Consent, LinkedVaultConfig,
    PasskeyChoice, Ui, VaultRef,
};
use pass_core::{AiAccess, Item, ItemKind, MemberRole, SharedKind, UserKeyset, Vault};
use serde_json::{json, Value};

struct TeamUi {
    runs: Mutex<Vec<AiRunRequest>>,
    reveals: Mutex<Vec<AiRevealRequest>>,
    /// `ai_allows_vault` for shared vaults (the organisation's export policy in the app).
    shared_allowed: AtomicBool,
}

impl Default for TeamUi {
    fn default() -> Self {
        TeamUi {
            runs: Mutex::default(),
            reveals: Mutex::default(),
            shared_allowed: AtomicBool::new(true),
        }
    }
}

impl Ui for TeamUi {
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
    fn confirm_ai_run(&self, request: &AiRunRequest) -> Option<AiDecision> {
        self.runs.lock().unwrap().push(request.clone());
        Some(AiDecision::Once)
    }
    fn confirm_ai_reveal(&self, request: &AiRevealRequest) -> Option<bool> {
        self.reveals.lock().unwrap().push(request.clone());
        Some(true)
    }
    fn ai_allows_vault(&self, _vault: &VaultRef) -> bool {
        self.shared_allowed.load(Ordering::SeqCst)
    }
}

const BOB: &str = "acc_bob";

fn login(title: &str, password: &str, access: AiAccess) -> Item {
    let mut item = Item {
        kind: ItemKind::Login,
        title: title.into(),
        username: "deploy-bot".into(),
        password: password.into(),
        urls: vec!["https://deploy.example.com".into()],
        totp: Some("JBSWY3DPEHPK3PXP".into()),
        ..Default::default()
    };
    item.set_ai_access(Some(access));
    item
}

/// A home vault of Alice's in which she verified `keys` (compared the fingerprint).
fn home_verifying(keys: &pass_core::PublicKeys) -> std::sync::Arc<Vault> {
    let kdf = pass_core::KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
        ..Default::default()
    };
    let home = Vault::create_with_kdf("demo master", "alice-home", kdf).unwrap();
    home.pin_contact(keys.clone(), pass_core::PERSONAL_SCOPE, &keys.fingerprint())
        .unwrap();
    home
}

/// Alice's shared vault with Bob in `role` and one login she marked "Allow without asking".
fn shared_file(alice: &UserKeyset, bob: &UserKeyset, role: MemberRole, title: &str, path: &Path) {
    let vault =
        Vault::create_shared(alice, SharedKind::Org, Some("org_acme".into()), "alice").unwrap();
    let bob_keys = bob.public_keys();
    vault
        .add_member(bob_keys.clone(), role, None, &home_verifying(&bob_keys))
        .unwrap();
    vault
        .upsert(login(title, &format!("{title}-secret"), AiAccess::Allow))
        .unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, vault.serialize().unwrap()).unwrap();
}

struct Setup {
    _dir: tempfile::TempDir,
    ui: Arc<TeamUi>,
    agent: Arc<Agent>,
}

fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let ui = Arc::new(TeamUi::default());
    let agent = Agent::new(
        AgentConfig::new(
            dir.path().join("pass.vault"),
            "bob-laptop".into(),
            Duration::from_secs(900),
        ),
        ui.clone(),
    );
    agent.create_vault("demo master").unwrap();
    let home = agent.vault().unwrap();
    let bob = home.ensure_user_keyset(BOB).unwrap();
    home.upsert(login("Mine", "my-own-pass", AiAccess::Allow))
        .unwrap();
    agent.save().unwrap();
    let alice = UserKeyset::generate("acc_alice").unwrap();
    let path = |k: &str| -> PathBuf { dir.path().join("shared").join(format!("{k}.vault")) };
    shared_file(&alice, &bob, MemberRole::Edit, "Eng", &path("eng"));
    shared_file(&alice, &bob, MemberRole::View, "Support", &path("support"));
    shared_file(&alice, &bob, MemberRole::Fill, "Deploy", &path("deploy"));
    agent.set_linked_vaults(
        ["eng", "support", "deploy"]
            .iter()
            .map(|k| LinkedVaultConfig::local(&format!("o-acme/{k}"), k, BOB, path(k)))
            .collect(),
    );
    assert_eq!(agent.open_vaults().len(), 4, "the shared vaults are open");
    Setup {
        _dir: dir,
        ui,
        agent,
    }
}

fn ai(agent: &Agent, method: &str, params: Value) -> Value {
    let line = json!({ "id": 1, "method": method, "params": params }).to_string();
    serde_json::from_str(&agent.handle_ai_line(&line)).unwrap()
}

fn run(agent: &Agent, item: &str, field: &str) -> Value {
    ai(
        agent,
        "ai.run",
        json!({
            "client": { "name": "claude-code" },
            "env": [{ "name": "SECRET", "item": item, "field": field }],
            "command": "tool",
            "program": "/usr/bin/tool",
            "cwd": "/work",
        }),
    )
}

fn listed(agent: &Agent) -> Vec<Value> {
    ai(agent, "ai.list", json!({}))["result"]["items"]
        .as_array()
        .unwrap()
        .clone()
}

fn by_title<'a>(items: &'a [Value], title: &str) -> &'a Value {
    items
        .iter()
        .find(|i| i["title"] == title)
        .unwrap_or_else(|| panic!("{title} not in {items:?}"))
}

#[test]
fn every_open_vault_takes_part_and_a_shared_vault_always_asks() {
    let t = setup();
    let items = listed(&t.agent);
    assert_eq!(items.len(), 4, "{items:?}");
    let mine = by_title(&items, "Mine");
    assert_eq!(mine["access"], "allow");
    assert_eq!(mine["vault"]["shared"], false);
    // Alice marked hers "Allow without asking"; on Bob's PC it asks.
    let eng = by_title(&items, "Eng");
    assert_eq!(eng["access"], "ask");
    assert_eq!(eng["vault"]["name"], "eng");
    assert_eq!(eng["vault"]["shared"], true);
    assert!(eng["fields"].as_array().unwrap().contains(&json!("password")));

    // The home vault's "Allow without asking" holds: no prompt.
    let r = run(&t.agent, "Mine", "password");
    assert_eq!(r["result"]["env"]["SECRET"], "my-own-pass", "{r}");
    assert_eq!(r["result"]["approval"], "without_asking");
    assert!(t.ui.runs.lock().unwrap().is_empty());

    // The editor's vault: asked, and the prompt names the vault.
    let r = run(&t.agent, "Eng", "password");
    assert_eq!(r["result"]["env"]["SECRET"], "Eng-secret", "{r}");
    assert_eq!(r["result"]["approval"], "once");
    let runs = t.ui.runs.lock().unwrap().clone();
    assert_eq!(runs.len(), 1);
    assert!(runs[0].secrets[0].asks);
    assert_eq!(runs[0].secrets[0].vault.as_deref(), Some("eng"));

    // A view member's AI tool may use the secrets too (nothing is written).
    let r = run(&t.agent, "Support", "password");
    assert_eq!(r["result"]["env"]["SECRET"], "Support-secret", "{r}");
}

#[test]
fn a_fill_only_members_ai_tool_gets_no_secret() {
    let t = setup();
    let items = listed(&t.agent);
    let deploy = by_title(&items, "Deploy");
    assert_eq!(deploy["vault"]["fill_only"], true);
    let fields: Vec<&str> = deploy["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    assert_eq!(fields, ["username", "website"]);
    for field in ["password", "totp"] {
        let r = run(&t.agent, "Deploy", field);
        assert_eq!(r["error"]["code"], "fill_only", "{field}: {r}");
        let r = ai(
            &t.agent,
            "ai.reveal",
            json!({ "item": "Deploy", "field": field }),
        );
        assert_eq!(r["error"]["code"], "fill_only", "{field}: {r}");
    }
    assert!(t.ui.runs.lock().unwrap().is_empty());
    assert!(t.ui.reveals.lock().unwrap().is_empty());
    // What the member may see in the app: still asked.
    let r = run(&t.agent, "Deploy", "username");
    assert_eq!(r["result"]["env"]["SECRET"], "deploy-bot", "{r}");
    assert_eq!(t.ui.runs.lock().unwrap().len(), 1);
}

#[test]
fn a_vault_the_policy_keeps_in_the_app_does_not_exist_for_ai_tools() {
    let t = setup();
    t.ui.shared_allowed.store(false, Ordering::SeqCst);
    let items = listed(&t.agent);
    assert_eq!(items.len(), 1, "{items:?}");
    assert_eq!(items[0]["title"], "Mine");
    // One vault left: no vault in the answer.
    assert!(items[0].get("vault").is_none());
    let r = run(&t.agent, "Eng", "password");
    assert_eq!(r["error"]["code"], "not_found", "{r}");
    let r = ai(&t.agent, "ai.reveal", json!({ "item": "Eng" }));
    assert_eq!(r["error"]["code"], "not_found", "{r}");
    assert!(t.ui.runs.lock().unwrap().is_empty());
}

#[test]
fn a_reveal_names_the_shared_vault() {
    let t = setup();
    let r = ai(
        &t.agent,
        "ai.reveal",
        json!({ "item": "Support", "field": "password", "reason": "debugging" }),
    );
    assert_eq!(r["result"]["value"], "Support-secret", "{r}");
    let reveals = t.ui.reveals.lock().unwrap().clone();
    assert_eq!(reveals[0].vault.as_deref(), Some("support"));
}

#[test]
fn read_only_mode_refuses_runs_and_reveals() {
    let t = setup();
    t.agent.set_update_required(true);
    assert_eq!(listed(&t.agent).len(), 4);
    let r = run(&t.agent, "Mine", "password");
    assert_eq!(r["error"]["code"], "update_required", "{r}");
    let r = ai(&t.agent, "ai.reveal", json!({ "item": "Mine" }));
    assert_eq!(r["error"]["code"], "update_required", "{r}");
    t.agent.set_update_required(false);
    assert!(run(&t.agent, "Mine", "password")["result"].is_object());
}
