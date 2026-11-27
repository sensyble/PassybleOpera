//! The `ai.*` requests of the connector for AI tools (`passyble-mcp`), at the agent: which
//! connections may send them, what a UI without AI prompts answers, grants and locks, limits.
#![cfg(feature = "native")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use pass_agent::{Agent, AgentConfig, AiDecision, AiRunRequest, Consent, PasskeyChoice, Ui};
use pass_core::{AiAccess, Item};
use serde_json::{json, Value};

#[derive(Default)]
struct TestUi {
    /// `confirm_ai_run`'s answer; `None`: a UI without AI prompts (the trait's default).
    run: Option<AiDecision>,
    run_prompts: Mutex<Vec<AiRunRequest>>,
    /// How long `confirm_ai_run` takes to answer, and how many are up at once (most seen).
    answer_after: Duration,
    showing: Mutex<(usize, usize)>,
}

impl Ui for TestUi {
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
    fn confirm_ai_run(&self, request: &AiRunRequest) -> Option<AiDecision> {
        self.run_prompts.lock().unwrap().push(request.clone());
        {
            let mut showing = self.showing.lock().unwrap();
            showing.0 += 1;
            showing.1 = showing.1.max(showing.0);
        }
        std::thread::sleep(self.answer_after);
        self.showing.lock().unwrap().0 -= 1;
        self.run
    }
}

fn setup(ui: Arc<TestUi>) -> (tempfile::TempDir, Arc<Agent>) {
    let dir = tempfile::tempdir().unwrap();
    let agent = Agent::new(
        AgentConfig::new(
            dir.path().join("pass.vault"),
            "laptop".into(),
            Duration::from_secs(900),
        ),
        ui,
    );
    agent.create_vault("master").unwrap();
    (dir, agent)
}

fn shared(agent: &Agent, title: &str, access: Option<AiAccess>) -> Item {
    let mut item = Item {
        title: title.into(),
        username: "me".into(),
        password: format!("{title}-secret"),
        urls: vec![format!("https://{}.example", title.to_lowercase())],
        ..Default::default()
    };
    item.set_ai_access(access);
    agent.vault().unwrap().upsert(item).unwrap()
}

fn ai(agent: &Agent, method: &str, params: Value) -> Value {
    let line = json!({ "id": 1, "method": method, "params": params }).to_string();
    serde_json::from_str(&agent.handle_ai_line(&line)).unwrap()
}

fn browser(agent: &Agent, method: &str, params: Value) -> Value {
    let line = json!({ "id": 1, "method": method, "params": params }).to_string();
    serde_json::from_str(&agent.handle_line(&line)).unwrap()
}

fn run_params(item: &str) -> Value {
    json!({
        "client": { "name": "claude-code", "version": "2", "process": "claude.exe" },
        "env": [{ "name": "TOKEN", "item": item, "field": "password" }],
        "command": "tool",
        "program": "/usr/bin/tool",
        "args": ["--flag"],
        "cwd": "/work",
    })
}

#[test]
fn ai_methods_and_browser_methods_stay_apart() {
    let (_dir, agent) = setup(Arc::default());
    shared(&agent, "Api", Some(AiAccess::Allow));
    // The browser protocol has no `ai.*`...
    for method in ["ai.status", "ai.list", "ai.run", "ai.reveal"] {
        let r = browser(&agent, method, json!({}));
        assert_eq!(r["error"]["code"], "invalid_params", "{method}: {r}");
        assert!(r["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unknown method"));
    }
    // ...and the AI protocol nothing else.
    for method in [
        "status",
        "logins.find",
        "logins.fill",
        "logins.search",
        "cards.list",
    ] {
        let r = ai(&agent, method, json!({ "url": "https://api.example" }));
        assert_eq!(r["error"]["code"], "invalid_params", "{method}: {r}");
    }
    let status = ai(&agent, "ai.status", json!({}));
    assert_eq!(status["result"]["locked"], false);
}

#[test]
fn a_ui_without_ai_prompts_allows_only_what_needs_none() {
    let (_dir, agent) = setup(Arc::default());
    let ask = shared(&agent, "Ask", Some(AiAccess::Ask));
    shared(&agent, "Auto", Some(AiAccess::Allow));
    shared(&agent, "Hidden", None);
    let r = ai(&agent, "ai.run", run_params(&ask.id));
    assert_eq!(r["error"]["code"], "not_supported", "{r}");
    let r = ai(&agent, "ai.run", run_params("Auto"));
    assert_eq!(r["result"]["env"]["TOKEN"], "Auto-secret", "{r}");
    assert_eq!(r["result"]["approval"], "without_asking");
    let r = ai(
        &agent,
        "ai.reveal",
        json!({ "item": "Auto", "reason": "x" }),
    );
    assert_eq!(r["error"]["code"], "not_supported", "{r}");
    // Unshared items don't exist for AI tools.
    let r = ai(&agent, "ai.run", run_params("Hidden"));
    assert_eq!(r["error"]["code"], "not_found");
    let list = ai(&agent, "ai.list", json!({}));
    let titles: Vec<&str> = list["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles.len(), 2);
    assert!(!titles.contains(&"Hidden"));
    assert!(!list.to_string().contains("-secret"));
}

#[test]
fn locked_without_unlock_is_a_clean_error_and_is_logged() {
    let (_dir, agent) = setup(Arc::default());
    shared(&agent, "Auto", Some(AiAccess::Allow));
    agent.lock();
    let r = ai(&agent, "ai.run", run_params("Auto"));
    assert_eq!(r["error"]["code"], "locked", "{r}");
    assert_eq!(agent.ai_log()[0].outcome, pass_agent::AiOutcome::Locked);
}

#[test]
fn grants_end_with_every_lock_and_vault_switch() {
    let ui = Arc::new(TestUi {
        run: Some(AiDecision::UntilLock),
        ..Default::default()
    });
    let (dir, agent) = setup(ui.clone());
    shared(&agent, "Ask", Some(AiAccess::Ask));
    let r = ai(&agent, "ai.run", run_params("Ask"));
    assert_eq!(r["result"]["approval"], "until_lock", "{r}");
    assert_eq!(agent.ai_grants().len(), 1);
    let r = ai(&agent, "ai.run", run_params("Ask"));
    assert_eq!(r["result"]["approval"], "grant");
    assert_eq!(ui.run_prompts.lock().unwrap().len(), 1);
    // Revoke from Settings.
    let grant = agent.ai_grants()[0].clone();
    assert!(agent.ai_revoke(&grant.item_id, &grant.client_key));
    assert!(agent.ai_grants().is_empty());
    ai(&agent, "ai.run", run_params("Ask"));
    assert_eq!(agent.ai_grants().len(), 1);
    // Another vault file: the grants go with the old one.
    let mut config = agent.config();
    config.vault_path = dir.path().join("other.vault");
    agent.reconfigure(config);
    assert!(agent.ai_grants().is_empty());
}

#[test]
fn ai_requests_are_rate_limited_and_not_activity() {
    let (_dir, agent) = setup(Arc::default());
    shared(&agent, "Auto", Some(AiAccess::Allow));
    std::thread::sleep(Duration::from_millis(50));
    let idle = agent.idle_for();
    for _ in 0..pass_agent_rate() {
        assert!(ai(&agent, "ai.list", json!({}))["result"].is_object());
    }
    let r = ai(&agent, "ai.list", json!({}));
    assert_eq!(r["error"]["code"], "rate_limited");
    // An AI tool alone never keeps the vault unlocked.
    assert!(agent.idle_for() >= idle);
}

/// `AI_REQUESTS_PER_MINUTE` (protocol/ai.rs).
fn pass_agent_rate() -> usize {
    30
}

#[test]
fn bad_run_requests_are_refused_before_any_prompt() {
    let ui = Arc::new(TestUi {
        run: Some(AiDecision::Once),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    shared(&agent, "Ask", Some(AiAccess::Ask));
    let mut bad = Vec::new();
    for (key, value) in [
        ("env", json!([])),
        ("env", json!([{ "name": "PATH", "item": "Ask" }])),
        ("env", json!([{ "name": "LD_PRELOAD", "item": "Ask" }])),
        ("env", json!([{ "name": "1X", "item": "Ask" }])),
        (
            "env",
            json!([{ "name": "A", "item": "Ask" }, { "name": "a", "item": "Ask" }]),
        ),
        (
            "env",
            json!([{ "name": "A", "item": "Ask", "field": "nope" }]),
        ),
        ("args", json!(["a\u{0}b"])),
        ("program", json!("")),
        ("cwd", json!("")),
    ] {
        let mut p = run_params("Ask");
        p[key] = value.clone();
        let r = ai(&agent, "ai.run", p);
        bad.push((key, value, r));
    }
    for (key, value, r) in &bad {
        assert_eq!(r["error"]["code"], "invalid_params", "{key}={value}: {r}");
    }
    assert!(ui.run_prompts.lock().unwrap().is_empty());
    // The prompt shows exactly what runs.
    let r = ai(&agent, "ai.run", run_params("Ask"));
    assert_eq!(r["result"]["env"]["TOKEN"], "Ask-secret");
    let prompts = ui.run_prompts.lock().unwrap();
    assert_eq!(prompts[0].command_line(), "/usr/bin/tool --flag");
    assert_eq!(prompts[0].cwd, "/work");
    assert_eq!(prompts[0].client.label(), "Claude Code (claude.exe)");
    assert_eq!(prompts[0].timeout_secs, 60);
}

/// The extension's editor (the same handlers run in its WebAssembly vault) never touches custom
/// fields: an edit of a shared login keeps it shared.
#[test]
fn an_extension_edit_keeps_the_ai_mark() {
    let (_dir, agent) = setup(Arc::default());
    let item = shared(&agent, "Github", Some(AiAccess::Allow));
    let r = browser(
        &agent,
        "logins.update",
        json!({ "url": "https://github.example/login", "id": item.id,
            "fields": { "title": "GitHub (edited)", "password": "new" } }),
    );
    assert!(r["result"].is_object(), "{r}");
    let edited = agent.vault().unwrap().get(item.id).unwrap();
    assert_eq!(edited.title, "GitHub (edited)");
    assert_eq!(edited.ai_access(), Some(AiAccess::Allow));
}

/// A server started for the app: the connector's executable may send `ai.*` only, any other
/// allowed client may not send `ai.*`. Here the test binary itself plays each in turn.
#[cfg(any(windows, target_os = "linux"))]
#[test]
fn ipc_roles_follow_the_executable() {
    use interprocess::local_socket::traits::Stream as _;
    use std::io::{BufRead, BufReader, Write};

    let me = std::env::current_exe().unwrap();
    let (_dir, agent) = setup(Arc::default());
    let ask = |method: &str| -> Value {
        let (recv, mut send) = pass_agent::ipc::connect().unwrap().split();
        send.write_all(
            format!("{}\n", json!({ "id": 9, "method": method, "params": {} })).as_bytes(),
        )
        .unwrap();
        let line = BufReader::new(recv).lines().next().unwrap().unwrap();
        serde_json::from_str(&line).unwrap()
    };
    let runtime = tempfile::tempdir().unwrap();
    let name = |role: &str| {
        #[cfg(windows)]
        std::env::set_var(
            "USERNAME",
            format!("pass-ai-roles-{role}-{}", std::process::id()),
        );
        #[cfg(unix)]
        {
            let dir = runtime.path().join(role);
            std::fs::create_dir_all(&dir).unwrap();
            std::env::set_var("XDG_RUNTIME_DIR", dir);
        }
    };

    name("ai");
    let _ai = pass_agent::ipc::Server::start_restricted_with_ai(
        agent.clone(),
        Vec::new(),
        vec![me.clone()],
    )
    .unwrap();
    assert_eq!(ask("ai.status")["result"]["locked"], false);
    assert_eq!(ask("status")["error"]["code"], "invalid_params");

    name("browser");
    let _browser =
        pass_agent::ipc::Server::start_restricted_with_ai(agent.clone(), vec![me], Vec::new())
            .unwrap();
    assert_eq!(ask("status")["result"]["locked"], false);
    assert_eq!(ask("ai.status")["error"]["code"], "invalid_params");
    drop(runtime);
}

/// One approval prompt at a time; a few requests wait behind it, the rest are refused at once.
#[test]
fn prompts_come_one_at_a_time_and_a_flood_is_refused() {
    let ui = Arc::new(TestUi {
        run: Some(AiDecision::Once),
        answer_after: Duration::from_millis(300),
        ..Default::default()
    });
    let (_dir, agent) = setup(ui.clone());
    shared(&agent, "Ask", Some(AiAccess::Ask));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let agent = agent.clone();
            std::thread::spawn(move || ai(&agent, "ai.run", run_params("Ask")))
        })
        .collect();
    let answers: Vec<Value> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    let allowed = answers.iter().filter(|a| a["result"].is_object()).count();
    let refused = answers
        .iter()
        .filter(|a| a["error"]["code"] == "rate_limited")
        .count();
    assert_eq!(allowed + refused, 8, "{answers:?}");
    assert!((1..=4).contains(&allowed), "{allowed}");
    assert!(refused >= 4, "{refused}");
    assert_eq!(ui.showing.lock().unwrap().1, 1, "never two prompts at once");
}
