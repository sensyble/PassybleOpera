//! The WebAuthn PRF secret of a passkey survives everything that keeps the passkey: saving and
//! opening the vault, edits, syncs and merges, the encrypted export and its import, and clients
//! that know nothing about it (an older pass-core, a JSON round trip through an app). See
//! core/src/prf.rs for why it lives inside the passkey's PKCS#8.

use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use pass_core::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// A random P-256 key (p256 0.14's own random-number traits need a newer rand_core than the
/// core's; pass-core draws the 32 bytes itself the same way).
fn random_signing_key() -> p256::ecdsa::SigningKey {
    use rand::RngCore;
    loop {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        if let Ok(key) = p256::ecdsa::SigningKey::from_slice(&bytes) {
            return key;
        }
    }
}

fn fast_kdf() -> KdfParams {
    KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
        ..Default::default()
    }
}

const PASSWORD: &str = "correct horse";

fn new_vault(device: &str) -> Arc<Vault> {
    Vault::create_with_kdf(PASSWORD, device, fast_kdf()).unwrap()
}

fn reopen(vault: &Vault, device: &str) -> Arc<Vault> {
    Vault::unlock(vault.serialize().unwrap(), PASSWORD.into(), device.into()).unwrap()
}

fn create_passkey(rp: &str, user: &str) -> PasskeyCreation {
    passkey_create(
        rp.into(),
        Some("Example".into()),
        user.as_bytes().to_vec(),
        user.into(),
        user.into(),
        vec![7; 32],
        vec![-7],
    )
    .unwrap()
}

/// A WhatsApp-like backup key: the PRF at a fixed input.
fn backup_key(pk: &Passkey) -> Option<Vec<u8>> {
    passkey_prf_eval(pk.clone(), b"backup-key-input".to_vec(), None).map(|v| v.first)
}

/// The vault's copy of the passkey with `credential_id`.
fn stored(vault: &Vault, credential_id: &[u8]) -> Passkey {
    vault
        .items()
        .into_iter()
        .flat_map(|i| i.passkeys)
        .find(|p| p.credential_id == credential_id)
        .expect("passkey in the vault")
}

/// Signs like any client (every shipped one signs through pass-core's `passkey_assert`).
fn signs(pk: &Passkey) -> bool {
    passkey_assert(pk.clone(), vec![1; 32], true).is_ok()
        && p256::ecdsa::SigningKey::from_pkcs8_der(&pk.private_key_pkcs8).is_ok()
}

/// Vault with one login holding a new passkey; returns the vault, the item id, the passkey and
/// its backup key.
fn vault_with_passkey(device: &str) -> (Arc<Vault>, String, Passkey, Vec<u8>) {
    let vault = new_vault(device);
    let created = create_passkey("whatsapp.com", "alice");
    let key = backup_key(&created.passkey).expect("new passkeys have a PRF");
    let item = vault
        .add_passkey(None, created.passkey.clone(), None)
        .unwrap();
    (vault, item.id, created.passkey, key)
}

#[test]
fn new_passkeys_have_a_prf_and_old_ones_dont() {
    let created = create_passkey("example.com", "alice");
    assert!(passkey_prf_available(created.passkey.clone()));
    assert!(signs(&created.passkey));
    // Two passkeys: two different secrets.
    let other = create_passkey("example.com", "bob");
    assert_ne!(backup_key(&created.passkey), backup_key(&other.passkey));
    // A passkey from before PRF support (a plain PKCS#8): no PRF, and none is made on use.
    let key = random_signing_key();
    let old = Passkey {
        private_key_pkcs8: key.to_pkcs8_der().unwrap().as_bytes().to_vec(),
        ..created.passkey.clone()
    };
    assert!(!passkey_prf_available(old.clone()));
    assert_eq!(backup_key(&old), None);
    let vault = new_vault("laptop");
    let item = vault.add_passkey(None, old.clone(), None).unwrap();
    passkey_assert(stored(&vault, &old.credential_id), vec![1; 32], true).unwrap();
    assert_eq!(vault.get(item.id).unwrap().passkeys[0], old);
}

#[test]
fn survives_saving_and_opening_the_vault() {
    let (vault, id, pk, key) = vault_with_passkey("laptop");
    for device in ["laptop", "phone", "tablet"] {
        let copy = reopen(&vault, device);
        let again = stored(&copy, &pk.credential_id);
        assert_eq!(again.private_key_pkcs8, pk.private_key_pkcs8);
        assert_eq!(backup_key(&again).as_ref(), Some(&key));
        assert!(signs(&again));
        assert!(copy.get(id.clone()).is_some());
    }
}

#[test]
fn survives_edits_of_the_login() {
    let (vault, id, pk, key) = vault_with_passkey("laptop");
    // Every kind of edit an app makes: title, password (history), notes, custom fields, tags,
    // favorite, a second passkey, the trash and back.
    let mut item = vault.get(id.clone()).unwrap();
    item.title = "WhatsApp backup".into();
    item.password = "new password".into();
    item.notes = "notes".into();
    item.tags = vec!["Chat".into()];
    item.favorite = true;
    item.fields.push(CustomField {
        name: "PIN".into(),
        value: "1234".into(),
        kind: FieldKind::Hidden,
    });
    vault.upsert(item).unwrap();
    let mut item = vault.get(id.clone()).unwrap();
    item.passkeys
        .push(create_passkey("whatsapp.com", "alice-2").passkey);
    vault.upsert(item).unwrap();
    vault.delete(id.clone()).unwrap();
    vault.restore(id.clone()).unwrap();
    let after = stored(&vault, &pk.credential_id);
    assert_eq!(backup_key(&after), Some(key.clone()));
    // Custom fields never hold it.
    let item = vault.get(id.clone()).unwrap();
    assert_eq!(item.fields.len(), 1);
    assert!(item.fields.iter().all(|f| f.name == "PIN"));
    assert_eq!(
        backup_key(&stored(&reopen(&vault, "x"), &pk.credential_id)),
        Some(key)
    );
}

#[test]
fn an_edit_cannot_replace_or_drop_the_secret_of_a_passkey() {
    let (vault, id, pk, key) = vault_with_passkey("laptop");
    // A client (bug or tampering) hands back the passkey with another key, a plain key, or
    // a key with another secret: the stored key stays.
    let plain = p256::ecdsa::SigningKey::from_pkcs8_der(&pk.private_key_pkcs8)
        .unwrap()
        .to_pkcs8_der()
        .unwrap()
        .as_bytes()
        .to_vec();
    let other_secret = create_passkey("whatsapp.com", "mallory")
        .passkey
        .private_key_pkcs8;
    for replacement in [plain, other_secret, b"junk".to_vec()] {
        let mut item = vault.get(id.clone()).unwrap();
        item.passkeys[0].private_key_pkcs8 = replacement;
        let saved = vault.upsert(item).unwrap();
        assert_eq!(saved.passkeys[0].private_key_pkcs8, pk.private_key_pkcs8);
        assert_eq!(
            backup_key(&stored(&vault, &pk.credential_id)),
            Some(key.clone())
        );
    }
    // Removing the passkey on purpose still works (a user's choice in the editor).
    let mut item = vault.get(id.clone()).unwrap();
    item.passkeys.clear();
    assert!(vault.upsert(item).unwrap().passkeys.is_empty());
}

#[test]
fn survives_syncs_and_merges() {
    let (laptop, id, pk, key) = vault_with_passkey("laptop");
    let phone = reopen(&laptop, "phone");
    // The phone edits the login later (it has the passkey from the sync): its version wins.
    let mut item = phone.get(id.clone()).unwrap();
    item.title = "Edited on the phone".into();
    phone.upsert(item).unwrap();
    laptop.merge_remote(phone.serialize().unwrap()).unwrap();
    assert_eq!(laptop.get(id.clone()).unwrap().title, "Edited on the phone");
    assert_eq!(
        backup_key(&stored(&laptop, &pk.credential_id)),
        Some(key.clone())
    );
    let mut item = laptop.get(id.clone()).unwrap();
    item.notes = "laptop".into();
    laptop.upsert(item).unwrap();
    phone.merge_remote(laptop.serialize().unwrap()).unwrap();
    assert_eq!(
        backup_key(&stored(&phone, &pk.credential_id)),
        Some(key.clone())
    );
    // Merging a copy into itself, or an older copy, changes nothing.
    let before = laptop.serialize().unwrap();
    laptop.merge_remote(before.clone()).unwrap();
    phone.merge_remote(before).unwrap();
    assert_eq!(
        backup_key(&stored(&phone, &pk.credential_id)),
        Some(key.clone())
    );
    assert_eq!(backup_key(&stored(&laptop, &pk.credential_id)), Some(key));
}

#[test]
fn a_merge_never_replaces_one_secret_with_another() {
    let (laptop, id, pk, key) = vault_with_passkey("laptop");
    let phone = reopen(&laptop, "phone");
    // The phone's copy ends up with the same credential id but another key (two edits, so the
    // phone's own edit guard can't see it: a forged or buggy copy).
    let mut item = phone.get(id.clone()).unwrap();
    let mut forged = item.passkeys[0].clone();
    forged.private_key_pkcs8 = create_passkey("whatsapp.com", "x")
        .passkey
        .private_key_pkcs8;
    item.passkeys.clear();
    phone.upsert(item).unwrap();
    let mut item = phone.get(id.clone()).unwrap();
    item.passkeys.push(forged);
    item.title = "newer".into();
    phone.upsert(item).unwrap();
    laptop.merge_remote(phone.serialize().unwrap()).unwrap();
    // The newer version is taken (title), with the laptop's key for that credential.
    assert_eq!(laptop.get(id.clone()).unwrap().title, "newer");
    assert_eq!(
        backup_key(&stored(&laptop, &pk.credential_id)),
        Some(key.clone())
    );
    // ...and it is kept when the vault is saved and opened again.
    assert_eq!(
        backup_key(&stored(&reopen(&laptop, "laptop"), &pk.credential_id)),
        Some(key)
    );
}

#[test]
fn survives_the_encrypted_export_and_its_import() {
    let (vault, _, pk, key) = vault_with_passkey("laptop");
    let file = export_encrypted_json(vault.clone(), "export password".into()).unwrap();
    let batch =
        import_parse_with_password(file.clone(), "export.json".into(), "export password".into())
            .unwrap();
    let imported_pk = batch
        .report()
        .items
        .iter()
        .flat_map(|i| i.passkeys.clone())
        .find(|p| p.credential_id == pk.credential_id)
        .unwrap();
    assert_eq!(backup_key(&imported_pk), Some(key.clone()));
    // Into a new vault (a restore on a new device).
    let fresh = new_vault("new-phone");
    batch.commit(fresh.clone()).unwrap();
    assert_eq!(
        backup_key(&stored(&fresh, &pk.credential_id)),
        Some(key.clone())
    );
    assert!(signs(&stored(&fresh, &pk.credential_id)));
    // Into the same vault: the passkey is already there and stays as it is.
    import_parse_with_password(file, "export.json".into(), "export password".into())
        .unwrap()
        .commit(vault.clone())
        .unwrap();
    assert_eq!(backup_key(&stored(&vault, &pk.credential_id)), Some(key));
}

#[test]
fn the_plain_exports_carry_it_only_with_the_private_key() {
    let (vault, _, pk, _) = vault_with_passkey("laptop");
    // Passyble JSON carries passkeys with their private keys (and so the secret, inside them),
    // in no other field.
    let json: serde_json::Value = serde_json::from_str(&export_json(vault.clone())).unwrap();
    let exported = &json["items"][0]["passkeys"][0];
    let mut keys: Vec<&String> = exported.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "created_at",
            "credential_id",
            "discoverable",
            "private_key_pkcs8",
            "rp_id",
            "rp_name",
            "sign_count",
            "user_display_name",
            "user_handle",
            "user_name"
        ]
    );
    assert!(json["items"][0].get("fields").is_none());
    // The CSV has no passkeys, so no key and no secret.
    let csv = export_csv(vault);
    let b64 = |d: &[u8]| {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(d)
    };
    assert!(!csv.contains(&b64(&pk.private_key_pkcs8)));
    assert!(!csv.contains(&b64url_encode(pk.private_key_pkcs8.clone())));
}

/// The item JSON as the first vault format had it: what an older client's structs keep when
/// it reads an item and writes it back (serde drops keys it doesn't know).
#[derive(Serialize, Deserialize)]
struct OldItem {
    #[serde(default)]
    id: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    urls: Vec<String>,
    #[serde(default)]
    totp: Option<String>,
    #[serde(default)]
    passkeys: Vec<OldPasskey>,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    favorite: bool,
    #[serde(default)]
    created_at: i64,
    #[serde(default)]
    updated_at: i64,
}

#[derive(Serialize, Deserialize)]
struct OldPasskey {
    credential_id: String,
    rp_id: String,
    #[serde(default)]
    rp_name: Option<String>,
    user_handle: String,
    user_name: String,
    user_display_name: String,
    private_key_pkcs8: String,
    #[serde(default)]
    sign_count: u32,
    #[serde(default)]
    discoverable: bool,
    #[serde(default)]
    created_at: i64,
}

#[test]
fn an_older_client_keeps_it_when_it_edits_and_saves_the_login() {
    let (vault, id, pk, key) = vault_with_passkey("laptop");
    let item = vault.get(id.clone()).unwrap();
    // The older client reads the item into its own structs, edits it and writes it back.
    let mut old: OldItem = serde_json::from_value(serde_json::to_value(&item).unwrap()).unwrap();
    old.title = "edited by an old client".into();
    old.password = "changed".into();
    let back: Item = serde_json::from_value(serde_json::to_value(&old).unwrap()).unwrap();
    // Its signing code (the same pkcs8/der decoder in every shipped version) still works.
    assert!(signs(&back.passkeys[0]));
    vault.upsert(back).unwrap();
    let after = stored(&vault, &pk.credential_id);
    assert_eq!(after.private_key_pkcs8, pk.private_key_pkcs8);
    assert_eq!(backup_key(&after), Some(key.clone()));
    // The same through an app's JSON (the desktop UI, the extension, a UniFFI record).
    let value = serde_json::to_value(vault.get(id.clone()).unwrap()).unwrap();
    let text = serde_json::to_string_pretty(&value).unwrap();
    let back: Item = serde_json::from_str(&text).unwrap();
    vault.upsert(back).unwrap();
    assert_eq!(
        backup_key(&stored(&vault, &pk.credential_id)),
        Some(key.clone())
    );
    // A sync with the older client's device: it merges and saves the vault without knowing.
    let old_device = reopen(&vault, "old-device");
    let mut item = old_device.get(id.clone()).unwrap();
    item.notes = "old device".into();
    old_device.upsert(item).unwrap();
    vault.merge_remote(old_device.serialize().unwrap()).unwrap();
    assert_eq!(backup_key(&stored(&vault, &pk.credential_id)), Some(key));
}

#[test]
fn prf_through_the_app_json_after_a_round_trip() {
    let (vault, _, pk, _) = vault_with_passkey("laptop");
    let copy = reopen(&vault, "phone");
    let again = stored(&copy, &pk.credential_id);
    let input = r#"{"eval":{"first":"YmFja3VwLWtleS1pbnB1dA"}}"#; // b64url("backup-key-input")
    let created = webauthn_prf_create_output(input.into(), pk.clone()).unwrap();
    let got = webauthn_prf_get_output(input.into(), vec![], again).unwrap();
    let created: serde_json::Value = serde_json::from_str(&created).unwrap();
    let got: serde_json::Value = serde_json::from_str(&got).unwrap();
    assert_eq!(created["enabled"], true);
    assert_eq!(created["results"]["first"], got["results"]["first"]);
    assert_eq!(
        got["results"]["first"],
        b64url_encode(backup_key(&pk).unwrap())
    );
}
