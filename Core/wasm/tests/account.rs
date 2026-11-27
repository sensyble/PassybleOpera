//! Passyble accounts in the browser vault: a linked vault opens with the account key, the key
//! comes from the password and Secret Key or from another device's approval, and the JSON reads
//! what the account service sends. Runs natively.

use pass_core::{
    account_sign_in_verify, device_approval_nonce, AccountKdf, AccountKey, AccountPassword,
    DeviceApprovalKeys, Item, SecretKey, Vault,
};
use pass_wasm::account::{
    kit_qr, parse_kdf, parse_sealed, parse_wrap, qr_svg, secret_key, secret_key_text, vault_access,
    wrap_json,
};
use pass_wasm::{BrowserConfig, BrowserHost};
use serde_json::{json, Value};

const ACCOUNT: &str = "acc_demo";

fn host() -> BrowserHost {
    let config: BrowserConfig =
        serde_json::from_value(json!({ "device_id": "chrome-demo" })).unwrap();
    BrowserHost::new(config).unwrap()
}

/// A linked vault file with one demo login, as the desktop app makes it.
fn linked_file(ak: &AccountKey) -> Vec<u8> {
    let vault = Vault::create_for_account(ak, "laptop".into()).unwrap();
    vault
        .upsert(Item {
            title: "Demo".into(),
            username: "demo@example.com".into(),
            password: "demo-only".into(),
            urls: vec!["https://example.com".into()],
            ..Default::default()
        })
        .unwrap();
    vault.serialize().unwrap()
}

/// The account key of `core/tests/account_key_vectors.json`, the vectors the account service and
/// the extension's tests also use.
fn vector_account_key() -> std::sync::Arc<AccountKey> {
    let v: Value =
        serde_json::from_str(include_str!("../../core/tests/account_key_vectors.json")).unwrap();
    let raw = pass_core::b64url_decode(v["ak"].as_str().unwrap().into()).unwrap();
    AccountKey::from_bytes(
        v["account"].as_str().unwrap().into(),
        raw,
        v["ak_id"].as_str().unwrap().into(),
    )
    .unwrap()
}

/// A vault linked to the vectors' account key, with one demo login. The extension's tests open it
/// in the real WebAssembly with that key.
const LINKED_VAULT: &[u8] = include_bytes!("fixtures/linked.vault");

#[test]
fn the_linked_fixture_opens_with_the_vectors_account_key() {
    let ak = vector_account_key();
    let access = vault_access(LINKED_VAULT).unwrap();
    assert_eq!(access["kind"], "account");
    assert_eq!(access["ak_id"], Value::String(ak.ak_id()));
    let host = host();
    host.load(LINKED_VAULT.to_vec()).unwrap();
    host.unlock_with_account_key(&ak).unwrap();
    let titles: Vec<String> = host
        .agent()
        .peek_vault()
        .unwrap()
        .items()
        .into_iter()
        .map(|i| i.title)
        .collect();
    assert_eq!(titles, vec!["Demo"]);
}

/// Writes `fixtures/linked.vault` again (only when the vault format changes on purpose):
/// `cargo test -p pass-wasm --test account -- --ignored`.
#[test]
#[ignore]
fn write_the_linked_fixture() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/linked.vault");
    std::fs::write(path, linked_file(&vector_account_key())).unwrap();
}

fn code(e: pass_agent::RpcError) -> String {
    e.code.as_str().to_string()
}

#[test]
fn a_linked_vault_opens_in_the_browser_with_the_account_key() {
    let ak = AccountKey::generate(ACCOUNT.into()).unwrap();
    let file = linked_file(&ak);
    let access = vault_access(&file).unwrap();
    assert_eq!(access["kind"], "account");
    assert_eq!(access["account"], ACCOUNT);
    assert_eq!(access["ak_id"], Value::String(ak.ak_id()));
    assert_eq!(access["account_recovery"], false);

    let host = host();
    assert_eq!(code(host.vault_access().unwrap_err()), "no_vault");
    host.load(file).unwrap();
    assert_eq!(host.vault_access().unwrap()["kind"], "account");

    // No master password opens it, and another key of the account neither.
    assert!(host.unlock("anything at all").is_err());
    let other = AccountKey::generate(ACCOUNT.into()).unwrap();
    assert_eq!(
        code(host.unlock_with_account_key(&other).unwrap_err()),
        "invalid_params"
    );
    assert!(host.agent().is_locked());

    let opened = host.unlock_with_account_key(&ak).unwrap();
    assert_eq!(opened["locked"], false);
    assert!(opened["grant"].as_str().is_some_and(|g| !g.is_empty()));
    let titles: Vec<String> = host
        .agent()
        .peek_vault()
        .unwrap()
        .items()
        .into_iter()
        .map(|i| i.title)
        .collect();
    assert_eq!(titles, vec!["Demo"]);

    // The Passyble password checked again while unlocked: only this vault's key gives a grant.
    assert!(host.verify_account_key(&ak).unwrap()["grant"].is_string());
    assert_eq!(
        code(host.verify_account_key(&other).unwrap_err()),
        "wrong_password"
    );

    // A restarted service worker opens it with the vault key, as any browser vault.
    let vk = host.vault_key().unwrap();
    host.lock(true).unwrap();
    assert_eq!(code(host.verify_account_key(&ak).unwrap_err()), "locked");
    host.unlock_with_key(&vk, 0).unwrap();
    assert!(!host.agent().is_locked());
}

#[test]
fn the_password_and_secret_key_open_the_account_key_from_the_service_blobs() {
    let sk = SecretKey::generate();
    let ak = AccountKey::generate(ACCOUNT.into()).unwrap();
    // Sign-up in an app: a fresh salt, the default parameters, the password wrap uploaded.
    let made = AccountPassword::with_new_salt("a demo passphrase only".into(), &sk, None).unwrap();
    let pw_wrap = wrap_json(&ak.password_wrap(&made).unwrap());
    let sk_wrap = wrap_json(&ak.secret_key_wrap(&sk).unwrap());

    // The browser: prelogin's salt and kdf as JSON, the Secret Key as typed, the wrap as sent.
    let prelogin = json!({ "salt": made.salt(), "kdf": { "alg": "argon2id", "m_kib": 65536, "t": 3, "p": 1 } });
    let kdf = parse_kdf(&prelogin["kdf"].to_string()).unwrap();
    assert_eq!(kdf, AccountKdf::default());
    let typed = secret_key(&sk.text().to_lowercase().replace('-', " ")).unwrap();
    let derived = AccountPassword::new(
        "a demo passphrase only".into(),
        &typed,
        prelogin["salt"].as_str().unwrap().into(),
        kdf.clone(),
    )
    .unwrap();
    assert_eq!(derived.auth_pub(), made.auth_pub());
    let sig = derived
        .sign_in(
            "demo@example.com".into(),
            "nonce-1".into(),
            "Chrome on Windows".into(),
            "web".into(),
        )
        .unwrap();
    assert!(account_sign_in_verify(
        &made.auth_pub(),
        "demo@example.com",
        "nonce-1",
        "Chrome on Windows",
        "web",
        &sig
    ));

    let opened = derived
        .open_account_key(ACCOUNT.into(), ak.ak_id(), parse_wrap(&pw_wrap).unwrap())
        .unwrap();
    assert_eq!(opened.ak_id(), ak.ak_id());
    assert_eq!(
        opened
            .open_secret_key(parse_wrap(&sk_wrap).unwrap())
            .unwrap()
            .text(),
        sk.text()
    );

    // A wrong password is wrong_password, with nothing opened.
    let wrong =
        AccountPassword::new("another passphrase".into(), &typed, made.salt(), kdf).unwrap();
    let err = wrong
        .open_account_key(ACCOUNT.into(), ak.ak_id(), parse_wrap(&pw_wrap).unwrap())
        .unwrap_err();
    assert_eq!(
        pass_wasm::account::key_error(err).code.as_str(),
        "wrong_password"
    );
    // Parameters below the apps' minimum are refused before any Argon2id run.
    let weak = parse_kdf(r#"{"alg":"argon2id","m_kib":19456,"t":2,"p":1}"#).unwrap();
    assert!(AccountPassword::new("x".into(), &typed, made.salt(), weak).is_err());
    assert!(parse_wrap("{}").is_err());
}

#[test]
fn a_new_browser_gets_the_account_key_and_secret_key_from_an_approving_device() {
    let sk = SecretKey::generate();
    let ak = AccountKey::generate(ACCOUNT.into()).unwrap();
    let request_id = "akq_demo".to_string();

    // This browser asks, and keeps its keys across a service worker restart.
    let mine = DeviceApprovalKeys::new();
    let kept = DeviceApprovalKeys::restore(mine.secret()).unwrap();
    assert_eq!(kept.enc_pub(), mine.enc_pub());
    assert!(mine
        .approval_qr(request_id.clone())
        .starts_with("passyble:approve/v1?id=akq%5Fdemo&k="));

    // The code variant: the approving device's r_a, the same six digits on both screens.
    let r_a = device_approval_nonce();
    let theirs = pass_core::device_approval_code(
        request_id.clone(),
        ACCOUNT.into(),
        mine.enc_pub(),
        mine.commitment(),
        mine.reveal(),
        r_a.clone(),
    )
    .unwrap();
    assert_eq!(
        kept.code(request_id.clone(), ACCOUNT.into(), r_a.clone())
            .unwrap(),
        theirs
    );
    assert_eq!(theirs.len(), 6);

    let sealed = ak
        .approve_device(
            &sk,
            request_id.clone(),
            mine.enc_pub(),
            mine.commitment(),
            mine.reveal(),
            r_a.clone(),
            // What the user typed from this browser's screen.
            theirs.clone(),
        )
        .unwrap();
    let wire = json!({ "enc": sealed.enc, "ct": sealed.ct }).to_string();
    let approved = kept
        .open(
            request_id.clone(),
            ACCOUNT.into(),
            ak.ak_id(),
            r_a.clone(),
            parse_sealed(&wire).unwrap(),
        )
        .unwrap();
    assert_eq!(approved.account_key().ak_id(), ak.ak_id());
    assert_eq!(approved.secret_key().text(), sk.text());

    // The keys open the linked vault here.
    let host = host();
    host.load(linked_file(&ak)).unwrap();
    host.unlock_with_account_key(&approved.account_key())
        .unwrap();

    // Another account's key id, or another r_a: nothing opens.
    let other = AccountKey::generate(ACCOUNT.into()).unwrap();
    assert!(kept
        .open(
            request_id.clone(),
            ACCOUNT.into(),
            other.ak_id(),
            r_a,
            parse_sealed(&wire).unwrap()
        )
        .is_err());
    assert!(kept
        .open(
            request_id,
            ACCOUNT.into(),
            ak.ak_id(),
            device_approval_nonce(),
            parse_sealed(&wire).unwrap()
        )
        .is_err());
}

#[test]
fn secret_keys_kit_qr_and_qr_codes_read_as_the_apps_read_them() {
    let sk = SecretKey::generate();
    let text = sk.text();
    let squeezed = text.replace('-', "").to_lowercase();
    assert_eq!(
        secret_key_text(&squeezed).unwrap()["text"],
        Value::String(text.clone())
    );
    assert_eq!(
        secret_key_text(&text[3..]).unwrap()["text"],
        Value::String(text.clone())
    );
    let refused = secret_key_text("P1-not-a-secret-key").unwrap_err();
    assert_eq!(refused.code.as_str(), "invalid_params");

    let kit = pass_core::emergency_kit("demo@example.com".into(), ACCOUNT.into(), &sk, None);
    let read = kit_qr(&kit.setup_qr).unwrap();
    assert_eq!(read["email"], "demo@example.com");
    assert_eq!(read["account"], ACCOUNT);
    assert_eq!(read["secret_key"], Value::String(text));
    assert!(kit_qr("passyble:approve/v1?id=x").is_err());

    let qr = qr_svg("passyble:approve/v1?id=akq_demo&k=AAAA&r=BBBB").unwrap();
    let size = qr["size"].as_u64().unwrap();
    assert!(size >= 21 + 8, "{size}");
    assert!(qr["path"].as_str().unwrap().starts_with('M'));
}
