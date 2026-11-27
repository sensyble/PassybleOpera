//! `pass-wasm-kdf` derives exactly pass-core's keys. A separate test binary because the Argon2id
//! runner is global.

use pass_core::{set_argon2id_runner, Vault};
use pass_wasm::{BrowserConfig, BrowserHost};
use serde_json::json;

const PASSWORD: &str = "correct horse battery staple";

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn the_kdf_module_and_the_core_derive_the_same_keys() {
    let config: BrowserConfig = serde_json::from_value(json!({ "device_id": "brave" })).unwrap();
    // The vault defaults (64 MiB, t = 3, p = 1) through the module, as in the browser.
    set_argon2id_runner(Some(pass_wasm_kdf::argon2id));
    let host = BrowserHost::new(config).unwrap();
    host.create(PASSWORD).unwrap();
    let file = host.export().unwrap();
    // A desktop vault (the fixture) opens through the module too.
    let fixture = include_bytes!("fixtures/native.vault").to_vec();
    let through_module = Vault::unlock(fixture.clone(), PASSWORD.into(), "x".into());
    // The core's own Argon2id opens what the module made.
    set_argon2id_runner(None);
    let by_core = Vault::unlock(file, PASSWORD.into(), "laptop".into()).unwrap();
    assert_eq!(
        by_core.vault_id(),
        host.agent().peek_vault().unwrap().vault_id()
    );
    assert_eq!(
        through_module.unwrap().vault_id(),
        Vault::unlock(fixture, PASSWORD.into(), "x".into())
            .unwrap()
            .vault_id()
    );
    // Deterministic: the same inputs, the same key.
    let salt = [9u8; 16];
    assert_eq!(
        pass_wasm_kdf::argon2id(b"secret", &salt, 2048, 2, 1),
        pass_wasm_kdf::argon2id(b"secret", &salt, 2048, 2, 1)
    );
}
