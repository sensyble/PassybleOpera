// Linked vaults: the home vault and the shared vaults its account can open, in one agent. Demo
// accounts and passwords only.
#![cfg(feature = "native")]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pass_agent::{
    Agent, AgentConfig, Consent, LinkedVaultConfig, LockKind, OwnVault, PasskeyChoice,
    PasswordPolicy, PasswordPolicyMode, TeamsSummary, Ui, VaultKind,
};
use pass_core::{Item, ItemKind, MemberRole, SharedKind, UserKeyset, Vault};
use serde_json::{json, Value};

#[derive(Default)]
struct TeamUi {
    copied: Mutex<Vec<String>>,
    teams: Mutex<Vec<String>>,
    vault_changes: Mutex<u32>,
    password_policy: Mutex<Option<PasswordPolicy>>,
    own: Mutex<Option<Vec<OwnVault>>>,
    switched: Mutex<Vec<String>>,
}

impl Ui for TeamUi {
    fn request_unlock(&self) -> bool {
        false
    }
    fn confirm_passkey_create(&self, _rp_id: &str, _user: &str) -> Consent {
        Consent::Approve { item_id: None }
    }
    fn choose_passkey(&self, _rp_id: &str, _options: &[PasskeyChoice]) -> Option<usize> {
        Some(0)
    }
    fn show_totp_popup(&self, _item_id: &str, _title: &str) {}
    fn notify_lock_state(&self, _locked: bool) {}
    fn copy_to_clipboard(&self, text: &str) -> bool {
        self.copied.lock().unwrap().push(text.to_string());
        true
    }
    fn vault_changed(&self) {
        *self.vault_changes.lock().unwrap() += 1;
    }
    fn teams_summary(&self) -> Option<TeamsSummary> {
        Some(TeamsSummary {
            invites: 1,
            to_confirm: 2,
            notices: 0,
        })
    }
    fn show_teams(&self, section: &str) -> bool {
        self.teams.lock().unwrap().push(section.to_string());
        true
    }
    fn password_policy(&self) -> Option<PasswordPolicy> {
        self.password_policy.lock().unwrap().clone()
    }
    fn own_vaults(&self) -> Option<Vec<OwnVault>> {
        self.own.lock().unwrap().clone()
    }
    fn switch_vault(&self, id: &str) -> Option<bool> {
        self.switched.lock().unwrap().push(id.to_string());
        Some(true)
    }
}

const BOB: &str = "acc_bob";
const SITE: &str = "https://deploy.example.com/login";

fn call(agent: &Agent, method: &str, params: Value) -> Value {
    let line = json!({ "id": 1, "method": method, "params": params }).to_string();
    serde_json::from_str(&agent.handle_line(&line)).unwrap()
}

fn code(answer: &Value) -> &str {
    answer["error"]["code"].as_str().unwrap_or("")
}

fn agent_at(dir: &std::path::Path, ui: Arc<TeamUi>) -> Arc<Agent> {
    Agent::new(
        AgentConfig {
            vault_path: dir.join("pass.vault"),
            device_id: "bob-laptop".into(),
            auto_lock: Duration::from_secs(900),
            webdav: None,
            gdrive: None,
            kept_list: None,
        },
        ui,
    )
}

fn login(title: &str, username: &str, password: &str, url: &str) -> Item {
    Item {
        kind: ItemKind::Login,
        title: title.into(),
        username: username.into(),
        password: password.into(),
        urls: vec![url.into()],
        ..Default::default()
    }
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

/// Alice's shared vault with Bob in `role` and one login; its file at `path`.
fn shared_file(
    alice: &UserKeyset,
    bob: &UserKeyset,
    role: MemberRole,
    title: &str,
    path: &PathBuf,
) -> String {
    let vault =
        Vault::create_shared(alice, SharedKind::Org, Some("org_acme".into()), "alice").unwrap();
    let bob_keys = bob.public_keys();
    vault
        .add_member(bob_keys.clone(), role, None, &home_verifying(&bob_keys))
        .unwrap();
    vault
        .upsert(login(title, "deploy-bot", "shared-secret-1", SITE))
        .unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, vault.serialize().unwrap()).unwrap();
    vault.vault_id()
}

struct Setup {
    dir: tempfile::TempDir,
    ui: Arc<TeamUi>,
    agent: Arc<Agent>,
    alice: UserKeyset,
    /// (key, vault id) of the Engineering (`edit`), Support (`view`) and Deploy (`fill`) vaults.
    eng: (String, String),
    support: (String, String),
    deploy: (String, String),
    home_login: Item,
}

fn configs(dir: &std::path::Path) -> Vec<LinkedVaultConfig> {
    ["eng", "support", "deploy"]
        .iter()
        .map(|k| {
            LinkedVaultConfig::local(
                &format!("o-acme/{k}"),
                &format!("{k} vault"),
                BOB,
                dir.join("shared").join(format!("{k}.vault")),
            )
        })
        .collect()
}

fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let ui = Arc::new(TeamUi::default());
    let agent = agent_at(dir.path(), ui.clone());
    agent.create_vault("demo master").unwrap();
    let home = agent.vault().unwrap();
    let bob = home.ensure_user_keyset(BOB).unwrap();
    let home_login = home
        .upsert(login("Deploy (mine)", "bob", "my-own-pass", SITE))
        .unwrap();
    agent.save().unwrap();
    let alice = UserKeyset::generate("acc_alice").unwrap();
    let cfg = configs(dir.path());
    let eng = shared_file(&alice, &bob, MemberRole::Edit, "Deploy (eng)", &cfg[0].path);
    let support = shared_file(
        &alice,
        &bob,
        MemberRole::View,
        "Deploy (support)",
        &cfg[1].path,
    );
    let deploy = shared_file(
        &alice,
        &bob,
        MemberRole::Fill,
        "Deploy (fill)",
        &cfg[2].path,
    );
    agent.set_linked_vaults(cfg.clone());
    Setup {
        dir,
        ui,
        agent,
        alice,
        eng: (cfg[0].key.clone(), eng),
        support: (cfg[1].key.clone(), support),
        deploy: (cfg[2].key.clone(), deploy),
        home_login,
    }
}

fn found(agent: &Agent) -> Value {
    call(agent, "logins.find", json!({ "url": SITE }))["result"].clone()
}

fn id_in(answer: &Value, vault_id: &str) -> String {
    answer["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["vault_id"] == vault_id)
        .unwrap_or_else(|| panic!("no item of {vault_id} in {answer}"))["id"]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn every_open_vault_is_listed_with_its_vault() {
    let t = setup();
    let status = call(&t.agent, "status", json!({}));
    assert!(status["result"]["features"]
        .as_array()
        .unwrap()
        .contains(&json!("vaults")));
    let answer = found(&t.agent);
    assert_eq!(answer["items"].as_array().unwrap().len(), 4, "{answer}");
    let vaults = answer["vaults"].as_array().unwrap();
    assert_eq!(vaults.len(), 4);
    assert_eq!(vaults[0]["home"], true);
    assert_eq!(vaults[0]["kind"], "personal");
    assert_eq!(vaults[1]["id"], t.eng.1.as_str());
    assert_eq!(vaults[1]["kind"], "org");
    assert_eq!(vaults[1]["role"], "edit");
    assert_eq!(vaults[1]["name"], "eng vault");
    assert_eq!(
        (vaults[2]["role"].as_str(), vaults[2]["can_edit"].as_bool()),
        (Some("view"), Some(false))
    );
    assert_eq!(
        (
            vaults[3]["role"].as_str(),
            vaults[3]["can_reveal"].as_bool()
        ),
        (Some("fill"), Some(false))
    );
    // In one order as if they were one vault (by title here), each with its vault.
    let titles: Vec<&str> = answer["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["title"].as_str().unwrap())
        .collect();
    assert_eq!(
        titles,
        [
            "Deploy (eng)",
            "Deploy (fill)",
            "Deploy (mine)",
            "Deploy (support)"
        ]
    );
    let home = t.agent.home_ref().unwrap().id;
    assert_eq!(id_in(&answer, &home), t.home_login.id);
    let status = t.agent.linked_status();
    assert!(
        status.iter().all(|s| s.open && s.error.is_none()),
        "{status:?}"
    );
    assert_eq!(t.agent.open_vaults().len(), 4);
    assert_eq!(
        t.agent.vault_of_item(&t.home_login.id).unwrap().0.kind,
        VaultKind::Personal
    );
}

#[test]
fn a_fill_only_login_is_filled_but_never_shown_or_copied() {
    let t = setup();
    let id = id_in(&found(&t.agent), &t.deploy.1);
    let fill = call(&t.agent, "logins.fill", json!({ "url": SITE, "id": id }));
    assert_eq!(fill["result"]["password"], "shared-secret-1");
    assert_eq!(fill["result"]["vault"]["role"], "fill");
    assert_eq!(fill["result"]["vault"]["can_reveal"], false);
    let copy = call(
        &t.agent,
        "logins.copy",
        json!({ "url": SITE, "id": id, "field": "password" }),
    );
    assert_eq!(code(&copy), "fill_only", "{copy}");
    let edit = call(
        &t.agent,
        "logins.get_for_edit",
        json!({ "url": SITE, "id": id }),
    );
    assert_eq!(code(&edit), "fill_only", "{edit}");
    // Its username may be copied.
    let user = call(
        &t.agent,
        "logins.copy",
        json!({ "url": SITE, "id": id, "field": "username" }),
    );
    assert_eq!(user["result"]["copied"], true, "{user}");
    assert_eq!(*t.ui.copied.lock().unwrap(), ["deploy-bot"]);
}

#[test]
fn view_and_fill_members_change_nothing() {
    let t = setup();
    let answer = found(&t.agent);
    for vault in [&t.support.1, &t.deploy.1] {
        let id = id_in(&answer, vault);
        let update = call(
            &t.agent,
            "logins.update",
            json!({ "url": SITE, "id": id, "fields": { "title": "Mine now" } }),
        );
        assert_eq!(code(&update), "read_only", "{update}");
        let delete = call(&t.agent, "logins.delete", json!({ "url": SITE, "id": id }));
        assert_eq!(code(&delete), "read_only", "{delete}");
        let totp = call(
            &t.agent,
            "totp.set",
            json!({ "url": SITE, "id": id, "totp": "JBSWY3DPEHPK3PXPJBSWY3DP" }),
        );
        assert_eq!(code(&totp), "read_only", "{totp}");
    }
    // A viewer opens the login read-only in the editor.
    let id = id_in(&answer, &t.support.1);
    let edit = call(
        &t.agent,
        "logins.get_for_edit",
        json!({ "url": SITE, "id": id }),
    );
    assert_eq!(edit["result"]["read_only"], true, "{edit}");
    assert_eq!(edit["result"]["vault"]["role"], "view");
    // A new login can't go into their vaults.
    for vault in [&t.support.1, &t.deploy.1] {
        let create = call(
            &t.agent,
            "logins.create",
            json!({ "url": SITE, "vault": vault, "fields": { "username": "x" } }),
        );
        assert_eq!(code(&create), "read_only", "{create}");
    }
    // An editor's vault takes changes, saved to its local copy.
    let id = id_in(&answer, &t.eng.1);
    let update = call(
        &t.agent,
        "logins.update",
        json!({ "url": SITE, "id": id, "fields": { "title": "Deploy (renamed)" } }),
    );
    assert_eq!(update["result"]["title"], "Deploy (renamed)", "{update}");
    assert_eq!(update["result"]["vault"]["id"], t.eng.1.as_str());
    let file = std::fs::read(t.dir.path().join("shared").join("eng.vault")).unwrap();
    let bob = t.agent.vault().unwrap().user_keyset(BOB).unwrap().unwrap();
    let reread = Vault::open_shared(&file, &bob, None, "check").unwrap();
    assert!(reread.items().iter().any(|i| i.title == "Deploy (renamed)"));
}

#[test]
fn the_save_banner_offers_the_vaults_a_login_can_go_to() {
    let t = setup();
    // Bob signs in with the shared bot account and a new password: only the editor's copy may be
    // updated (the viewer's and the fill member's never are).
    let check = call(
        &t.agent,
        "logins.save_check",
        json!({ "url": SITE, "username": "deploy-bot", "password": "rotated-2" }),
    )["result"]
        .clone();
    assert_eq!(check["action"], "update_password", "{check}");
    assert_eq!(check["vault"]["id"], t.eng.1.as_str());
    // A new account: the vaults that may take it, home first, and the default.
    let check = call(
        &t.agent,
        "logins.save_check",
        json!({ "url": "https://new.example.org/", "username": "newbie", "password": "pw-1" }),
    )["result"]
        .clone();
    assert_eq!(check["action"], "save_new", "{check}");
    let offered: Vec<&str> = check["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["id"].as_str().unwrap())
        .collect();
    let home = t.agent.home_ref().unwrap().id;
    assert_eq!(offered, [home.as_str(), t.eng.1.as_str()]);
    assert_eq!(check["default_vault"], home.as_str());
    // Saved into the vault the user picked.
    let saved = call(
        &t.agent,
        "logins.save",
        json!({ "url": "https://new.example.org/", "username": "newbie", "password": "pw-1",
                "vault": t.eng.1 }),
    );
    assert_eq!(saved["result"]["vault"]["id"], t.eng.1.as_str(), "{saved}");
    let eng = t.agent.shared_vault(&t.eng.1).unwrap();
    assert!(eng.items().iter().any(|i| i.username == "newbie"));
    // The next one for that site goes there by default.
    assert_eq!(
        t.agent
            .default_save_vault(Some("https://new.example.org/x")),
        Some(t.eng.1.clone())
    );
    let refused = call(
        &t.agent,
        "logins.save",
        json!({ "url": "https://other.example.org/", "username": "a", "password": "b",
                "vault": t.support.1 }),
    );
    assert_eq!(code(&refused), "read_only", "{refused}");
    // Saved as is in any vault: nothing to offer.
    let none = call(
        &t.agent,
        "logins.save_check",
        json!({ "url": SITE, "username": "deploy-bot", "password": "shared-secret-1" }),
    )["result"]
        .clone();
    assert_eq!(none["action"], "none", "{none}");
}

#[test]
fn a_soft_lock_keeps_every_vaults_list_and_an_unlock_opens_them_again() {
    let t = setup();
    t.agent.save_and_lock_as(LockKind::Soft).unwrap();
    let answer = found(&t.agent);
    assert_eq!(answer["locked"], true);
    assert_eq!(answer["items"].as_array().unwrap().len(), 4, "{answer}");
    assert_eq!(answer["vaults"].as_array().unwrap().len(), 4);
    let id = id_in(&answer, &t.eng.1);
    assert_eq!(
        code(&call(
            &t.agent,
            "logins.fill",
            json!({ "url": SITE, "id": id })
        )),
        "locked"
    );
    let list = call(&t.agent, "vaults.list", json!({}))["result"].clone();
    assert_eq!(list["vaults"].as_array().unwrap().len(), 4, "{list}");
    assert_eq!(list["vaults"][1]["open"], false);
    t.agent.unlock("demo master").unwrap();
    let fill = call(&t.agent, "logins.fill", json!({ "url": SITE, "id": id }));
    assert_eq!(fill["result"]["vault"]["id"], t.eng.1.as_str(), "{fill}");
    // A full lock forgets them.
    t.agent.save_and_lock_as(LockKind::Full).unwrap();
    assert_eq!(
        code(&call(&t.agent, "logins.find", json!({ "url": SITE }))),
        "locked"
    );
}

#[test]
fn vaults_list_and_show_teams() {
    let t = setup();
    let list = call(&t.agent, "vaults.list", json!({}))["result"].clone();
    let vaults = list["vaults"].as_array().unwrap();
    assert_eq!(vaults.len(), 4, "{list}");
    assert_eq!(vaults[0]["home"], true);
    assert_eq!(vaults[0]["items"], 1);
    assert_eq!(vaults[1]["items"], 1);
    assert_eq!(vaults[1]["open"], true);
    assert_eq!(vaults[1]["error"], Value::Null);
    assert_eq!(
        list["teams"],
        json!({ "invites": 1, "to_confirm": 2, "notices": 0 })
    );
    let shown = call(&t.agent, "app.show_teams", json!({ "section": "confirm" }));
    assert_eq!(shown["result"]["shown"], true);
    call(&t.agent, "app.show_teams", json!({ "section": "<script>" }));
    assert_eq!(*t.ui.teams.lock().unwrap(), ["confirm", ""]);
}

#[test]
fn a_teams_second_password_rule_shows_and_its_vaults_stay_read_only_until_met() {
    let t = setup();
    let list = call(&t.agent, "vaults.list", json!({}))["result"].clone();
    assert_eq!(list["password_policy"], Value::Null, "no rule: choice");
    *t.ui.password_policy.lock().unwrap() = Some(PasswordPolicy {
        mode: PasswordPolicyMode::SecondPassword,
        action_needed: true,
        title: "Your team requires a second password".into(),
        message: "Give Personal its own password.".into(),
    });
    // The app hands the team's vaults over as not writable while the rule isn't met.
    let mut cfg = configs(t.dir.path());
    cfg[0].writable = false;
    t.agent.set_linked_vaults(cfg.clone());
    let list = call(&t.agent, "vaults.list", json!({}))["result"].clone();
    assert_eq!(
        list["password_policy"],
        json!({ "mode": "second_password", "action_needed": true,
                "title": "Your team requires a second password",
                "message": "Give Personal its own password." })
    );
    let eng = list["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == t.eng.1.as_str())
        .unwrap()
        .clone();
    assert_eq!(eng["can_edit"], false, "{eng}");
    assert_eq!(eng["open"], true, "still readable");
    let id = id_in(&found(&t.agent), &t.eng.1);
    let update = call(
        &t.agent,
        "logins.update",
        json!({ "url": SITE, "id": id, "fields": { "title": "Changed" } }),
    );
    assert_eq!(code(&update), "read_only", "{update}");
    let create = call(
        &t.agent,
        "logins.create",
        json!({ "url": SITE, "vault": t.eng.1, "fields": { "username": "x" } }),
    );
    assert_eq!(code(&create), "read_only", "{create}");
    let fill = call(&t.agent, "logins.fill", json!({ "url": SITE, "id": id }));
    assert_eq!(fill["result"]["password"], "shared-secret-1", "{fill}");
    // Met: writable again.
    cfg[0].writable = true;
    t.agent.set_linked_vaults(cfg);
    let update = call(
        &t.agent,
        "logins.update",
        json!({ "url": SITE, "id": id, "fields": { "title": "Changed" } }),
    );
    assert_eq!(update["result"]["title"], "Changed", "{update}");
}

#[test]
fn a_vault_that_cant_be_opened_says_why() {
    let t = setup();
    // A vault shared with another account of the same name but other keys.
    let stranger = UserKeyset::generate(BOB).unwrap();
    let path = t.dir.path().join("shared").join("other.vault");
    shared_file(&t.alice, &stranger, MemberRole::Edit, "Other", &path);
    let mut cfg = configs(t.dir.path());
    cfg.push(LinkedVaultConfig::local("o-acme/other", "other", BOB, path));
    // And one whose keys this home vault doesn't hold.
    let path = t.dir.path().join("shared").join("nokeys.vault");
    let carol = UserKeyset::generate("acc_carol").unwrap();
    shared_file(&t.alice, &carol, MemberRole::Edit, "No keys", &path);
    cfg.push(LinkedVaultConfig::local(
        "o-acme/nokeys",
        "nokeys",
        "acc_carol",
        path,
    ));
    t.agent.set_linked_vaults(cfg);
    let status = t.agent.linked_status();
    let of = |key: &str| status.iter().find(|s| s.key == key).unwrap();
    let other = of("o-acme/other").error.clone().unwrap();
    assert_eq!(other.code, "keys_mismatch", "{other:?}");
    assert_eq!(
        of("o-acme/nokeys").error.as_ref().unwrap().code,
        "no_keyset"
    );
    assert!(of(&t.eng.0).open);
    let list = call(&t.agent, "vaults.list", json!({}))["result"].clone();
    let other = list["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "other")
        .unwrap()
        .clone();
    assert_eq!(other["open"], false);
    assert_eq!(other["error"]["code"], "keys_mismatch");
}

#[test]
fn items_move_and_copy_between_vaults() {
    let t = setup();
    let moved = t
        .agent
        .transfer_item(&t.home_login.id, &t.eng.1, true)
        .unwrap();
    assert_ne!(moved.id, t.home_login.id);
    assert!(t
        .agent
        .vault()
        .unwrap()
        .get(t.home_login.id.clone())
        .is_none());
    assert_eq!(t.agent.vault_of_item(&moved.id).unwrap().0.id, t.eng.1);
    // Not into a vault the user can't change, and nothing copied out of a fill-only vault.
    assert!(t
        .agent
        .transfer_item(&moved.id, &t.support.1, false)
        .is_err());
    let fill_id = id_in(&found(&t.agent), &t.deploy.1);
    let home = t.agent.home_ref().unwrap().id;
    assert!(t.agent.transfer_item(&fill_id, &home, false).is_err());
    // A viewer may copy into their own vault.
    let view_id = id_in(&found(&t.agent), &t.support.1);
    let copy = t.agent.transfer_item(&view_id, &home, false).unwrap();
    assert_eq!(copy.password, "shared-secret-1");
}

#[test]
fn passkeys_and_auto_type_span_the_vaults() {
    let t = setup();
    // Auto-type sees the shared logins too.
    let matches = t
        .agent
        .find_for_window("Deploy (fill) - Console", "console.exe");
    assert!(
        matches.iter().any(|i| i.title == "Deploy (fill)"),
        "{matches:?}"
    );
    // A passkey saved with the editor's login goes into that vault.
    let eng_id = id_in(&found(&t.agent), &t.eng.1);
    let options = call(
        &t.agent,
        "passkey.create_options",
        json!({ "origin": "https://deploy.example.com", "userName": "deploy-bot" }),
    )["result"]
        .clone();
    let candidates: Vec<&str> = options["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert!(candidates.contains(&eng_id.as_str()), "{options}");
    // The viewer's and the fill member's logins can't take a passkey.
    assert_eq!(candidates.len(), 2, "{options}");
    let made = call(
        &t.agent,
        "passkey.create",
        json!({
            "origin": "https://deploy.example.com",
            "rp": { "id": "deploy.example.com", "name": "Deploy" },
            "user": { "id": "dXNlcg", "name": "deploy-bot" },
            "challenge": "Y2hhbGxlbmdl",
            "pubKeyCredParams": [ { "type": "public-key", "alg": -7 } ],
            "consent": { "itemId": eng_id },
        }),
    );
    assert_eq!(made["result"]["vault"]["id"], t.eng.1.as_str(), "{made}");
    let found = call(
        &t.agent,
        "passkey.find",
        json!({ "origin": "https://deploy.example.com" }),
    )["result"]
        .clone();
    assert_eq!(found["items"][0]["vault_id"], t.eng.1.as_str(), "{found}");
    let metadata = t.agent.passkey_metadata().unwrap();
    assert_eq!(metadata.len(), 1);
}

#[test]
fn a_restart_opens_the_shared_vaults_again_and_a_dropped_one_goes() {
    let t = setup();
    let eng_id = id_in(&found(&t.agent), &t.eng.1);
    t.agent.save_and_lock_as(LockKind::Full).unwrap();
    drop(t.agent);
    let agent = agent_at(t.dir.path(), t.ui.clone());
    agent.set_linked_vaults(configs(t.dir.path()));
    agent.unlock("demo master").unwrap();
    let answer = found(&agent);
    assert_eq!(answer["items"].as_array().unwrap().len(), 4, "{answer}");
    assert_eq!(id_in(&answer, &t.eng.1), eng_id);
    // The user left Support: it's gone from every list.
    agent.remove_shared(&t.support.0, true);
    let answer = found(&agent);
    assert_eq!(answer["items"].as_array().unwrap().len(), 3);
    assert!(!t.dir.path().join("shared").join("support.vault").exists());
    // A list without Deploy closes it.
    let cfg: Vec<LinkedVaultConfig> = configs(t.dir.path())
        .into_iter()
        .filter(|c| c.key == t.eng.0)
        .collect();
    agent.set_linked_vaults(cfg);
    assert_eq!(agent.open_vaults().len(), 2);
    assert!(*t.ui.vault_changes.lock().unwrap() > 0);
}

#[test]
fn a_shared_vault_made_here_is_listed_and_saved() {
    let t = setup();
    let home = t.agent.vault().unwrap();
    let bob = home.user_keyset(BOB).unwrap().unwrap();
    let vault = Vault::create_shared(&bob, SharedKind::Direct, None, "bob-laptop").unwrap();
    let path = t.dir.path().join("shared").join("direct.vault");
    let config = LinkedVaultConfig::local("u-bob/direct", "Shared with Alice", BOB, path.clone());
    t.agent.add_shared(config, vault.clone()).unwrap();
    assert!(path.exists());
    let vault_ref = t
        .agent
        .open_vaults()
        .into_iter()
        .find(|(r, _)| r.id == vault.vault_id())
        .unwrap()
        .0;
    assert_eq!(vault_ref.kind, VaultKind::Direct);
    assert_eq!(vault_ref.role, Some(MemberRole::Manage));
    // A members change through the app, saved to its copy.
    let shared = t.agent.shared_vault(&vault.vault_id()).unwrap();
    let alice_keys = t.alice.public_keys();
    let home = t.agent.vault().unwrap();
    home.pin_contact(
        alice_keys.clone(),
        pass_core::PERSONAL_SCOPE,
        &alice_keys.fingerprint(),
    )
    .unwrap();
    shared
        .add_member(alice_keys, MemberRole::Edit, None, &home)
        .unwrap();
    t.agent.save_shared(&vault.vault_id()).unwrap();
    let file = std::fs::read(&path).unwrap();
    assert!(Vault::open_shared(&file, &t.alice, None, "alice").is_ok());
    assert!(t.agent.take_linked_notices().is_empty());
}

/// The shared vaults' lists are kept for the next start beside the home vault's (DPAPI), shown
/// soft-locked with their roles, and deleted with it.
#[cfg(windows)]
#[test]
fn shared_vault_lists_survive_a_restart() {
    let t = setup();
    let kept = t.dir.path().join("kept").join("v1.bin");
    let with_list = || {
        Agent::new(
            AgentConfig {
                vault_path: t.dir.path().join("pass.vault"),
                device_id: "bob-laptop".into(),
                auto_lock: Duration::from_secs(900),
                webdav: None,
                gdrive: None,
                kept_list: Some(kept.clone()),
            },
            t.ui.clone(),
        )
    };
    let cfg = configs(t.dir.path());
    let first = with_list();
    first.unlock("demo master").unwrap();
    first.set_linked_vaults(cfg.clone());
    assert_eq!(first.open_vaults().len(), 4);
    first.save_and_lock_as(LockKind::Full).unwrap();
    let shared_files = || {
        std::fs::read_dir(kept.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("v1.shared."))
            .count()
    };
    assert_eq!(shared_files(), 3);

    // The next start: the home vault's list, then the shared vaults' once they are listed.
    let next = with_list();
    assert!(next.restore_kept_list());
    next.set_linked_vaults(cfg.clone());
    let answer = found(&next);
    assert_eq!(answer["locked"], true);
    assert_eq!(answer["items"].as_array().unwrap().len(), 4, "{answer}");
    let groups = next.all_summaries().unwrap();
    let deploy = groups.iter().find(|(r, _)| r.id == t.deploy.1).unwrap();
    assert_eq!(deploy.0.role, Some(MemberRole::Fill));
    assert!(!deploy.0.can_reveal && !deploy.0.can_edit);
    let eng = groups.iter().find(|(r, _)| r.id == t.eng.1).unwrap();
    assert!(eng.0.can_edit && eng.0.kind == VaultKind::Org);

    // Leaving one deletes its list; "Lock completely" deletes the others.
    next.remove_shared(&t.support.0, false);
    assert_eq!(shared_files(), 2);
    next.forget_kept_list();
    assert_eq!(shared_files(), 0);
    assert!(next.all_summaries().is_none());
}

/// Someone else's vault opened through emergency access is listed until the next lock,
/// read-only.
#[test]
fn a_session_vault_shows_until_the_lock() {
    let t = setup();
    let other = Vault::create_shared(&t.alice, SharedKind::Org, None, "alice").unwrap();
    other
        .upsert(login("Alice's bank", "alice", "alice-secret", SITE))
        .unwrap();
    t.agent
        .add_session_vault("Vault of alice@example.com", other.clone())
        .unwrap();
    let vaults = t.agent.open_vaults();
    let (session, _) = vaults
        .iter()
        .find(|(r, _)| r.id == other.vault_id())
        .unwrap();
    assert_eq!(session.kind, VaultKind::Emergency);
    assert!(!session.can_edit && session.can_reveal);
    assert!(t.agent.vault_of_item(&other.items()[0].id).is_some());
    t.agent.save_and_lock_as(LockKind::Soft).unwrap();
    t.agent.unlock("demo master").unwrap();
    assert!(t
        .agent
        .open_vaults()
        .iter()
        .all(|(r, _)| r.id != other.vault_id()));
}

/// A passkey in a shared vault keeps its WebAuthn PRF secret inside the item: a fill-only member
/// signs in with it, PRF included (the site gets the PRF's output), and never sees the secret.
#[test]
fn a_fill_only_member_signs_in_with_a_shared_passkey_and_its_prf() {
    let dir = tempfile::tempdir().unwrap();
    let ui = Arc::new(TeamUi::default());
    let agent = agent_at(dir.path(), ui);
    agent.create_vault("demo master").unwrap();
    let bob = agent.vault().unwrap().ensure_user_keyset(BOB).unwrap();
    agent.save().unwrap();
    let alice = UserKeyset::generate("acc_alice").unwrap();
    let path = dir.path().join("shared").join("deploy.vault");
    let shared =
        Vault::create_shared(&alice, SharedKind::Org, Some("org_acme".into()), "alice").unwrap();
    let bob_keys = bob.public_keys();
    shared
        .add_member(bob_keys.clone(), MemberRole::Fill, None, &home_verifying(&bob_keys))
        .unwrap();
    let created = pass_core::passkey_create(
        "deploy.example.com".into(),
        None,
        b"bot".to_vec(),
        "deploy-bot".into(),
        "deploy-bot".into(),
        vec![0; 32],
        vec![-7],
    )
    .unwrap();
    assert!(pass_core::passkey_prf_available(created.passkey.clone()));
    let input = b"backup key salt".to_vec();
    let expected = pass_core::passkey_prf_eval(created.passkey.clone(), input.clone(), None)
        .unwrap()
        .first;
    let item = shared
        .upsert(login("Deploy", "deploy-bot", "shared-secret-1", SITE))
        .unwrap();
    shared
        .add_passkey(Some(item.id), created.passkey, Some(SITE.into()))
        .unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, shared.serialize().unwrap()).unwrap();
    agent.set_linked_vaults(vec![LinkedVaultConfig::local(
        "o-acme/deploy",
        "Deploy",
        BOB,
        path,
    )]);

    let credential = pass_core::b64url_encode(created.credential_id.clone());
    let got = call(
        &agent,
        "passkey.get",
        json!({
            "origin": "https://deploy.example.com",
            "rpId": "deploy.example.com",
            "challenge": pass_core::b64url_encode(vec![2; 32]),
            "allowCredentials": [{ "type": "public-key", "id": credential }],
            "extensions": { "prf": { "eval": { "first": pass_core::b64url_encode(input) } } },
        }),
    );
    let first = got["result"]["clientExtensionResults"]["prf"]["results"]["first"]
        .as_str()
        .unwrap_or_else(|| panic!("{got}"));
    assert_eq!(pass_core::b64url_decode(first.into()).unwrap(), expected);
    // What the member's apps get of the passkey has no key and no secret.
    let found = call(
        &agent,
        "passkey.find",
        json!({ "origin": "https://deploy.example.com" }),
    );
    let text = found.to_string();
    assert!(found["result"]["items"][0].is_object(), "{found}");
    assert!(!text.contains("private"), "{found}");
}

/// A card as Alice adds it to her shared vault file `name` (`support`, `eng`, ...).
fn add_shared_card(t: &Setup, name: &str, number: &str) {
    let path = t.dir.path().join("shared").join(format!("{name}.vault"));
    let vault =
        Vault::open_shared(&std::fs::read(&path).unwrap(), &t.alice, None, "alice").unwrap();
    vault
        .upsert(Item {
            kind: ItemKind::Card,
            card: Some(pass_core::CardData {
                cardholder_name: "Deploy Team".into(),
                number: number.into(),
                expiry_month: 4,
                expiry_year: 2029,
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap();
    std::fs::write(&path, vault.serialize().unwrap()).unwrap();
}

#[test]
fn the_card_banner_updates_only_editable_vaults_and_offers_them() {
    let t = setup();
    add_shared_card(&t, "support", "4242424242424242");
    add_shared_card(&t, "eng", "5555555555554444");
    t.agent.save_and_lock_as(LockKind::Full).unwrap();
    t.agent.unlock("demo master").unwrap();
    let shop = "https://shop.example/checkout";
    let check = |number: &str| {
        call(
            &t.agent,
            "cards.save_check",
            json!({ "url": shop, "number": number, "expiry_month": 5, "expiry_year": 2031 }),
        )["result"]
            .clone()
    };
    // Saved only in a vault Bob can view: nothing to offer, it fills from there.
    let viewed = check("4242424242424242");
    assert_eq!(viewed["action"], "none", "{viewed}");
    assert_eq!(viewed["vault"]["id"], t.support.1.as_str());
    // In the editor's vault: its expiry may be updated there.
    let edited = check("5555555555554444");
    assert_eq!(edited["action"], "update_expiry", "{edited}");
    assert_eq!(edited["vault"]["id"], t.eng.1.as_str());
    let id = edited["id"].as_str().unwrap();
    let saved = call(
        &t.agent,
        "cards.save",
        json!({ "url": shop, "id": id, "number": "5555555555554444",
                "expiry_month": 5, "expiry_year": 2031 }),
    );
    assert_eq!(saved["result"]["vault"]["id"], t.eng.1.as_str(), "{saved}");
    let eng = t.agent.shared_vault(&t.eng.1).unwrap();
    let card = eng.get(id.to_string()).unwrap().card.unwrap();
    assert_eq!((card.expiry_month, card.expiry_year), (5, 2031));
    // A new card: the vaults that may take it, home first; the home vault by default.
    let new = check("378282246310005");
    assert_eq!(new["action"], "save_new", "{new}");
    let home = t.agent.home_ref().unwrap().id;
    let offered: Vec<&str> = new["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["id"].as_str().unwrap())
        .collect();
    assert_eq!(offered, [home.as_str(), t.eng.1.as_str()]);
    assert_eq!(new["default_vault"], home.as_str());
    let refused = call(
        &t.agent,
        "cards.save",
        json!({ "url": shop, "number": "378282246310005", "vault": t.support.1 }),
    );
    assert_eq!(code(&refused), "read_only", "{refused}");
    let into_eng = call(
        &t.agent,
        "cards.save",
        json!({ "url": shop, "number": "378282246310005", "vault": t.eng.1 }),
    );
    assert_eq!(
        into_eng["result"]["vault"]["id"],
        t.eng.1.as_str(),
        "{into_eng}"
    );
}

fn pins(agent: &Agent) -> Value {
    call(agent, "vaults.pins", json!({}))["result"]["pins"].clone()
}

#[test]
fn pins_keep_the_vaults_the_user_can_see_in_their_order() {
    let t = setup();
    assert!(call(&t.agent, "status", json!({}))["result"]["features"]
        .as_array()
        .unwrap()
        .contains(&json!("vaults.pins")));
    assert_eq!(pins(&t.agent), json!([]));
    let home = t.agent.vault().unwrap().vault_id();
    *t.ui.own.lock().unwrap() = Some(vec![OwnVault {
        id: "work".into(),
        vault_id: Some("work-vault".into()),
        name: "Work".into(),
        ..Default::default()
    }]);
    let saved = call(
        &t.agent,
        "vaults.set_pins",
        json!({ "ids": [t.support.1, "gone", home, "work-vault", t.support.1] }),
    );
    assert_eq!(
        saved["result"],
        json!({ "pins": [t.support.1, home, "work-vault"], "max": 5 })
    );
    assert_eq!(pins(&t.agent), json!([t.support.1, home, "work-vault"]));
    assert_eq!(t.agent.vault().unwrap().pinned_vaults().len(), 3);

    let six = json!({ "ids": [home, t.eng.1, t.support.1, t.deploy.1, "work-vault", "gone"] });
    assert_eq!(
        call(&t.agent, "vaults.set_pins", six)["result"]["pins"]
            .as_array()
            .unwrap()
            .len(),
        5,
        "an unknown sixth is dropped"
    );
    *t.ui.own.lock().unwrap() = Some(vec![
        OwnVault {
            id: "work".into(),
            vault_id: Some("work-vault".into()),
            ..Default::default()
        },
        OwnVault {
            id: "old".into(),
            vault_id: Some("old-vault".into()),
            ..Default::default()
        },
    ]);
    let six = json!({ "ids": [home, t.eng.1, t.support.1, t.deploy.1, "work-vault", "old-vault"] });
    assert_eq!(
        code(&call(&t.agent, "vaults.set_pins", six)),
        "invalid_params"
    );

    let browser =
        json!({ "ids": ["opened-by-the-extension", home], "known": ["opened-by-the-extension"] });
    assert_eq!(
        call(&t.agent, "vaults.set_pins", browser)["result"]["pins"],
        json!(["opened-by-the-extension", home])
    );

    t.agent.lock();
    assert_eq!(code(&call(&t.agent, "vaults.pins", json!({}))), "locked");
}

#[test]
fn a_pin_of_a_shared_vault_not_opened_yet_is_kept() {
    let t = setup();
    let home = t.agent.vault().unwrap().vault_id();
    t.agent
        .vault()
        .unwrap()
        .set_pinned_vaults(vec!["later-vault".into()])
        .unwrap();
    // A listed vault this session hasn't opened (no file yet): its id is unknown.
    let mut cfg = configs(t.dir.path());
    cfg.push(LinkedVaultConfig::local(
        "o-acme/new",
        "new vault",
        BOB,
        t.dir.path().join("shared").join("new.vault"),
    ));
    t.agent.set_linked_vaults(cfg);
    let ids = json!({ "ids": ["later-vault", home, "never-saved"] });
    let saved = call(&t.agent, "vaults.set_pins", ids.clone());
    assert_eq!(saved["result"]["pins"], json!(["later-vault", home]));

    t.agent.set_linked_vaults(configs(t.dir.path()));
    let saved = call(&t.agent, "vaults.set_pins", ids);
    assert_eq!(saved["result"]["pins"], json!([home]));
}

#[test]
fn items_move_into_a_vault_the_user_can_edit() {
    let t = setup();
    assert_eq!(
        code(&call(
            &t.agent,
            "items.move",
            json!({ "id": t.home_login.id, "vault": t.support.1 })
        )),
        "read_only"
    );
    let support_item = id_in(&found(&t.agent), &t.support.1);
    assert_eq!(
        code(&call(
            &t.agent,
            "items.move",
            json!({ "id": support_item, "vault": t.eng.1 })
        )),
        "read_only"
    );
    let home = t.agent.vault().unwrap().vault_id();
    assert_eq!(
        code(&call(
            &t.agent,
            "items.move",
            json!({ "id": t.home_login.id, "vault": home })
        )),
        "invalid_params"
    );
    let moved = call(
        &t.agent,
        "items.move",
        json!({ "id": t.home_login.id, "vault": t.eng.1 }),
    )["result"]
        .clone();
    assert_eq!(moved["vault"]["id"], t.eng.1.as_str());
    assert_eq!(moved["moved_from"], t.home_login.id.as_str());
    assert_ne!(moved["id"], t.home_login.id.as_str());
    assert!(t
        .agent
        .vault()
        .unwrap()
        .get(t.home_login.id.clone())
        .is_none());
    let titles: Vec<Value> = found(&t.agent)["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["vault_id"] == t.eng.1.as_str())
        .map(|i| i["title"].clone())
        .collect();
    assert!(titles.contains(&json!("Deploy (mine)")), "{titles:?}");
}

#[test]
fn vaults_own_and_switch_go_through_the_app() {
    let t = setup();
    assert_eq!(
        code(&call(&t.agent, "vaults.own", json!({}))),
        "not_supported"
    );
    *t.ui.own.lock().unwrap() = Some(vec![
        OwnVault {
            id: "home".into(),
            name: "Personal".into(),
            active: true,
            ..Default::default()
        },
        OwnVault {
            id: "work".into(),
            name: "Work".into(),
            ..Default::default()
        },
    ]);
    let own = call(&t.agent, "vaults.own", json!({}))["result"].clone();
    assert_eq!(own["vaults"][1]["name"], "Work");
    assert_eq!(own["vaults"][0]["active"], true);
    assert_eq!(
        call(&t.agent, "vaults.switch", json!({ "id": "home" }))["result"],
        json!({ "switching": false })
    );
    assert_eq!(
        code(&call(&t.agent, "vaults.switch", json!({ "id": "nope" }))),
        "not_found"
    );
    t.agent.lock();
    assert_eq!(
        call(&t.agent, "vaults.switch", json!({ "id": "work" }))["result"],
        json!({ "switching": true })
    );
    assert_eq!(*t.ui.switched.lock().unwrap(), ["work"]);
}

#[test]
fn a_fill_only_members_notes_are_listed_but_never_shown() {
    let dir = tempfile::tempdir().unwrap();
    let ui = Arc::new(TeamUi::default());
    let agent = agent_at(dir.path(), ui.clone());
    agent.create_vault("demo master").unwrap();
    let bob = agent.vault().unwrap().ensure_user_keyset(BOB).unwrap();
    agent.save().unwrap();
    let alice = UserKeyset::generate("acc_alice").unwrap();
    let cfg = configs(dir.path());
    let shared =
        Vault::create_shared(&alice, SharedKind::Org, Some("org_acme".into()), "alice").unwrap();
    let bob_keys = bob.public_keys();
    shared
        .add_member(
            bob_keys.clone(),
            MemberRole::Fill,
            None,
            &home_verifying(&bob_keys),
        )
        .unwrap();
    let note = shared
        .upsert(Item {
            kind: ItemKind::Note,
            title: "Deploy recovery codes".into(),
            notes: "1111-2222".into(),
            ..Default::default()
        })
        .unwrap();
    std::fs::create_dir_all(cfg[2].path.parent().unwrap()).unwrap();
    std::fs::write(&cfg[2].path, shared.serialize().unwrap()).unwrap();
    agent.set_linked_vaults(vec![cfg[2].clone()]);

    let list = call(&agent, "notes.list", json!({}));
    assert_eq!(list["result"]["items"][0]["id"], note.id.as_str(), "{list}");
    assert_eq!(
        list["result"]["items"][0]["vault_id"],
        shared.vault_id().as_str()
    );
    assert_eq!(list["result"]["vaults"][0]["can_reveal"], false);
    for params in [
        json!({ "id": note.id }),
        json!({ "id": note.id, "copy": true }),
    ] {
        let r = call(&agent, "notes.get", params);
        assert_eq!(code(&r), "fill_only", "{r}");
        assert!(!r.to_string().contains("1111"));
    }
    assert!(ui.copied.lock().unwrap().is_empty());
}

/// Bob's agent with Alice's shared vault holding one note, Bob in `role`; the note's id.
fn shared_note(role: MemberRole) -> (tempfile::TempDir, Arc<TeamUi>, Arc<Agent>, String) {
    let dir = tempfile::tempdir().unwrap();
    let ui = Arc::new(TeamUi::default());
    let agent = agent_at(dir.path(), ui.clone());
    agent.create_vault("demo master").unwrap();
    let bob = agent.vault().unwrap().ensure_user_keyset(BOB).unwrap();
    agent.save().unwrap();
    let alice = UserKeyset::generate("acc_alice").unwrap();
    let cfg = configs(dir.path());
    let shared =
        Vault::create_shared(&alice, SharedKind::Org, Some("org_acme".into()), "alice").unwrap();
    let bob_keys = bob.public_keys();
    shared
        .add_member(bob_keys.clone(), role, None, &home_verifying(&bob_keys))
        .unwrap();
    let note = shared
        .upsert(Item {
            kind: ItemKind::Note,
            title: "Team reading list".into(),
            notes: "Demo handbook".into(),
            ..Default::default()
        })
        .unwrap();
    std::fs::create_dir_all(cfg[0].path.parent().unwrap()).unwrap();
    std::fs::write(&cfg[0].path, shared.serialize().unwrap()).unwrap();
    agent.set_linked_vaults(vec![cfg[0].clone()]);
    (dir, ui, agent, note.id)
}

#[test]
fn notes_append_only_where_the_member_may_edit() {
    for (role, refused) in [(MemberRole::View, "read_only"), (MemberRole::Fill, "read_only")] {
        let (_dir, ui, agent, id) = shared_note(role);
        let r = call(
            &agent,
            "notes.append",
            json!({ "id": id, "text": "Demo article" }),
        );
        assert_eq!(code(&r), refused, "{role:?}: {r}");
        assert_eq!(*ui.vault_changes.lock().unwrap(), 0, "{role:?}");
    }
    let (_dir, ui, agent, id) = shared_note(MemberRole::Edit);
    let r = call(
        &agent,
        "notes.append",
        json!({ "id": id, "text": "Demo article" }),
    );
    assert_eq!(r["result"]["id"], id.as_str(), "{r}");
    assert_eq!(r["result"]["vault"]["role"], "edit");
    let got = call(&agent, "notes.get", json!({ "id": id }));
    assert_eq!(got["result"]["notes"], "Demo handbook\nDemo article", "{got}");
    assert_eq!(*ui.vault_changes.lock().unwrap(), 1);
}
