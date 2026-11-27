//! Teams and Family in the browser extension: shared vaults, search and save across vaults,
//! policies, and secure send against the core's test vectors. Runs natively and as WebAssembly in
//! Node. Demo accounts and passwords only.

use pass_core::{MemberRole, SharedKind, UserKeyset, Vault};
use pass_wasm::teams;
use pass_wasm::BrowserHost;
use serde_json::{json, Value};

const PASSWORD: &str = "correct horse battery staple";
const VECTORS: &str = include_str!("../../core/tests/send_vectors.json");

fn host() -> BrowserHost {
    let host = BrowserHost::from_json(r#"{"device_id":"chrome-teams"}"#).unwrap();
    host.create(PASSWORD).unwrap();
    host
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn the_open_page_opens_the_cores_test_vectors() {
    let cases: Value = serde_json::from_str(VECTORS).unwrap();
    for case in cases.as_array().unwrap() {
        let s = |k: &str| case[k].as_str().unwrap().to_string();
        let ciphertext = pass_core::b64url_decode(s("ciphertext")).unwrap();
        let (header, data) = teams::send_open(
            ciphertext,
            &s("meta"),
            &s("key"),
            case["password"].as_str().map(str::to_string),
        )
        .unwrap();
        assert_eq!(header["kind"], case["kind"]);
        assert_eq!(header["name"], case["name"]);
        assert_eq!(
            data.as_slice(),
            pass_core::b64url_decode(s("data")).unwrap().as_slice()
        );
        let info = teams::send_info(&s("meta")).unwrap();
        assert_eq!(info["has_password"], case["password"].is_string());
        if let Some(password) = case["password"].as_str() {
            let auth = teams::send_password_auth(&s("meta"), password.into()).unwrap();
            assert_eq!(auth["auth"], case["password_auth"]);
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_send_round_trips_through_the_module() {
    let expires = js_now() + 3_600_000;
    let options = json!({ "kind": "file", "name": "plan.txt", "mime": "text/plain",
                          "expires_at": expires, "max_views": 2 });
    let (ciphertext, info) = teams::send_seal(b"demo plan".to_vec(), &options.to_string()).unwrap();
    let key = info["key"].as_str().unwrap();
    let link = teams::send_link("https://send.passyble.com/s", "x1", key).unwrap();
    let parsed = teams::send_parse_link(link["link"].as_str().unwrap()).unwrap();
    let (header, data) = teams::send_open(
        ciphertext.clone(),
        info["meta"].as_str().unwrap(),
        parsed["key"].as_str().unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(header["name"], "plan.txt");
    assert_eq!(data.as_slice(), b"demo plan");
    // A link without its fragment opens nothing.
    assert!(teams::send_parse_link("https://send.passyble.com/s/x1").is_err());
    assert!(teams::send_seal(vec![], r#"{"kind":"text"}"#).is_err());
}

fn js_now() -> i64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now() as i64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_shared_vault_opens_with_the_extension_vaults_keyset() {
    let host = host();
    let made = host.ensure_keyset("acc_bob").unwrap();
    assert!(made["fingerprint"].as_str().unwrap().contains('-'));
    assert!(
        host.take_save().is_some(),
        "the keyset is saved in the vault"
    );
    let bob_keys: pass_core::PublicKeys =
        serde_json::from_value(made["public_keys"].clone()).unwrap();
    let checked = teams::public_keys_check(&serde_json::to_string(&bob_keys).unwrap()).unwrap();
    assert_eq!(checked["valid"], true);

    // Alice (on another device) makes a team vault and adds Bob as an editor.
    let alice = UserKeyset::generate("acc_alice").unwrap();
    let team = Vault::create_shared(&alice, SharedKind::Org, Some("org_acme".into()), "a").unwrap();
    let alice_home = Vault::create_with_kdf(
        "demo master",
        "alice-home",
        pass_core::KdfParams {
            m_kib: 64,
            t: 1,
            p: 1,
            ..Default::default()
        },
    )
    .unwrap();
    alice_home
        .pin_contact(bob_keys.clone(), pass_core::PERSONAL_SCOPE, &bob_keys.fingerprint())
        .unwrap();
    team.add_member(bob_keys, MemberRole::Edit, None, &alice_home)
        .unwrap();
    team.upsert(pass_core::Item {
        title: "Router".into(),
        username: "admin".into(),
        password: "router-demo-pass".into(),
        urls: vec!["https://router.example".into()],
        ..Default::default()
    })
    .unwrap();

    let shared = host
        .open_shared(team.serialize().unwrap(), "acc_bob")
        .unwrap();
    assert!(
        host.take_save().is_some(),
        "the accepted list is remembered"
    );
    // Bob hasn't compared Alice's fingerprint yet; after he does, she is verified.
    assert_eq!(shared.signer_status().unwrap()["status"], "not_pinned");
    let alice_keys = serde_json::to_string(&alice.public_keys()).unwrap();
    assert!(host
        .pin_contact(&alice_keys, "personal", "AAAAA-AAAAA")
        .is_err());
    host.pin_contact(&alice_keys, "personal", &alice.public_keys().fingerprint())
        .unwrap();
    assert_eq!(shared.signer_status().unwrap()["status"], "pinned");
    assert_eq!(
        host.contact_pin_status(&alice_keys, "personal").unwrap()["status"],
        "pinned"
    );
    assert_eq!(host.contact_pins().unwrap().as_array().unwrap().len(), 1);
    // A key the service swapped in for Alice is reported, not wrapped to.
    let planted = UserKeyset::generate("acc_alice").unwrap().public_keys();
    let swap = json!([{ "op": "replace_keys", "keys": planted }]).to_string();
    let problems = host.unpinned_changes(&swap).unwrap();
    assert_eq!(problems[0]["status"], "changed");
    assert_eq!(
        problems[0]["pinned_fingerprint"],
        alice.public_keys().fingerprint()
    );
    let info = shared.info().unwrap();
    assert_eq!(info["role"], "edit");
    assert_eq!(info["signer_fingerprint"], alice.fingerprint());
    let summaries = shared.summaries().unwrap();
    let id = summaries["summaries"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let item: Value = serde_json::from_str(&shared.item(&id)).unwrap();
    assert_eq!(item["password"], "router-demo-pass");

    // Search and the save banner across the extension's vault and the shared one.
    let groups = json!([host.home_summaries().unwrap(), summaries]).to_string();
    let found = teams::multi_for_url_json(&groups, "https://router.example/login").unwrap();
    assert_eq!(found[0]["vault_id"], team.vault_id());
    // The same over lists read once (`SearchIndex`), while the home list's stamp holds.
    let index = teams::search_index(&groups).unwrap();
    assert_eq!(
        teams::index_for_url_json(&index, "https://router.example/login").unwrap(),
        found
    );
    for query in ["rout", "admin", "zzz", ""] {
        assert_eq!(
            teams::index_search_json(&index, query).unwrap(),
            teams::multi_search_json(&groups, query).unwrap()
        );
    }
    let stamp = host.home_stamp().unwrap();
    assert_eq!(host.home_stamp().unwrap(), stamp);
    let target =
        teams::multi_default_save_vault_json(&groups, Some("https://router.example".into()), None)
            .unwrap();
    assert_eq!(target["vault_id"], team.vault_id());

    // Bob copies the router login to his own vault; Alice changes members; Bob merges.
    let copied = shared.transfer(&id, "to_home", false).unwrap();
    assert!(copied["id"].is_string());
    assert_ne!(host.home_stamp().unwrap(), stamp, "the home list changed");
    assert!(shared.transfer(&id, "sideways", false).is_err());
    team.set_member_role("acc_bob", MemberRole::View).unwrap();
    let merged = shared.merge(team.serialize().unwrap()).unwrap();
    assert_eq!(merged["notice"], Value::Null);
    assert_eq!(shared.info().unwrap()["role"], "view");
    let mut edited = item.clone();
    edited["title"] = "Renamed".into();
    assert!(
        shared.upsert(&edited.to_string()).is_err(),
        "a viewer can't edit"
    );
    // A manager's change through JSON is refused for a viewer.
    let change = json!([{ "op": "set_role", "account": "acc_alice", "role": "edit" }]);
    assert!(shared.change_members(&change.to_string()).is_err());
    assert!(!shared.save().unwrap().is_empty());
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn policies_answer_in_json() {
    let policy = r#"{"master_password_min_strength":"good","max_auto_lock_minutes":10,
                     "export_allowed":false,"require_two_step":true}"#;
    let local = r#"{"master_password_score":1,"auto_lock_secs":3600,"two_step_enabled":false}"#;
    let v = teams::policy_check(policy, local).unwrap();
    let rules: Vec<&str> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["rule"].as_str().unwrap())
        .collect();
    assert_eq!(rules, ["master_password_strength", "auto_lock", "two_step"]);
    let allows = teams::policy_allows(Some(policy), Some(3600)).unwrap();
    assert_eq!(
        allows,
        json!({ "export": false, "sharing_outside": true, "auto_lock_secs": 600 })
    );
    let none = teams::policy_allows(None, None).unwrap();
    assert_eq!(
        none,
        json!({ "export": true, "sharing_outside": true, "auto_lock_secs": null })
    );
    assert!(teams::policy_check("[1]", local).is_err());
}
