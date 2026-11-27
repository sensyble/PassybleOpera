//! Vaults linked to a Passyble account (file version 3): linking and unlinking, merges between
//! linked and unlinked copies, what the file's host can and can't do, and the account recovery
//! code's copy in the header.

use pass_core::*;
use serde_json::Value;
use std::sync::Arc;

fn fast_kdf() -> KdfParams {
    KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
        ..Default::default()
    }
}

fn new_vault(device: &str) -> Arc<Vault> {
    let v = Vault::create_with_kdf("correct horse", device, fast_kdf()).unwrap();
    v.upsert(Item {
        title: "GitHub".into(),
        password: "hunter2".into(),
        ..Default::default()
    })
    .unwrap();
    v
}

fn json(file: &[u8]) -> Value {
    serde_json::from_slice(file).unwrap()
}

fn titles(v: &Vault) -> Vec<String> {
    v.items().into_iter().map(|i| i.title).collect()
}

fn add(v: &Vault, title: &str) {
    v.upsert(Item {
        title: title.into(),
        ..Default::default()
    })
    .unwrap();
}

#[test]
fn linking_keeps_the_vault_key_and_the_items() {
    let ak = AccountKey::generate("acc_mia".into()).unwrap();
    let v = new_vault("laptop");
    let vk = v.export_vault_key();
    let v1 = v.serialize().unwrap();
    v.link_to_account(&ak).unwrap();
    assert_eq!(v.export_vault_key(), vk, "no item is re-encrypted");
    let file = v.serialize().unwrap();
    let doc = json(&file);
    assert_eq!(doc["version"], 3);
    assert_eq!(doc["access"], "account");
    assert_eq!(doc["kdf"]["alg"], "none", "no password slot");
    assert_eq!(doc["wrapped_key"]["ct"], "");
    assert_eq!(doc["account"]["account"], "acc_mia");
    assert_eq!(doc["account"]["ak_id"], ak.ak_id());
    // Item ciphertexts are the same bytes as before linking.
    assert_eq!(json(&v1)["items"], doc["items"]);

    let access = vault_file_access(file.clone()).unwrap();
    assert_eq!(access.kind, "account");
    assert_eq!(access.ak_id.as_deref(), Some(ak.ak_id().as_str()));
    assert_eq!(vault_file_access(v1.clone()).unwrap().kind, "password");

    let opened = Vault::unlock_with_account_key(file.clone(), &ak, "phone".into()).unwrap();
    assert_eq!(titles(&opened), vec!["GitHub"]);
    assert_eq!(opened.account_link().unwrap().account, "acc_mia");
    assert!(Vault::unlock_with_key(file.clone(), vk, "tablet".into()).is_ok());
    // After linking, the master password is refused with a clear message.
    let err = Vault::unlock(file.clone(), "correct horse".into(), "x".into()).unwrap_err();
    assert!(matches!(err, PassError::InvalidInput(_)));
    assert!(core_message_is(err.to_string(), "vault.opens_with_account".into()), "{err}");
    // Another account key (another account, or this account's replaced key) is refused.
    let other = AccountKey::generate("acc_mia".into()).unwrap();
    assert!(Vault::unlock_with_account_key(file.clone(), &other, "x".into()).is_err());
    let stranger = AccountKey::generate("acc_bob".into()).unwrap();
    assert!(Vault::unlock_with_account_key(file, &stranger, "x".into()).is_err());
}

#[test]
fn a_linked_vault_has_no_master_password_or_vault_recovery_code() {
    let ak = AccountKey::generate("acc_mia".into()).unwrap();
    let v = new_vault("laptop");
    v.create_recovery_code().unwrap();
    v.link_to_account(&ak).unwrap();
    assert!(!v.has_recovery_code(), "the vault recovery code goes with the password slot");
    assert!(v.create_recovery_code().is_err());
    assert!(v.change_master_password("new".into()).is_err());
    assert!(v.check_password("correct horse".into()).is_err());
    assert!(json(&v.serialize().unwrap()).get("recovery").is_none());
}

#[test]
fn a_new_vault_can_be_linked_from_the_start() {
    let ak = AccountKey::generate("acc_mia".into()).unwrap();
    let v = Vault::create_for_account(&ak, "laptop".into()).unwrap();
    add(&v, "Bank");
    let file = v.serialize().unwrap();
    assert_eq!(json(&file)["version"], 3);
    let opened = Vault::unlock_with_account_key(file, &ak, "phone".into()).unwrap();
    assert_eq!(titles(&opened), vec!["Bank"]);
}

#[test]
fn linked_and_unlinked_copies_merge_both_ways() {
    let ak = AccountKey::generate("acc_mia".into()).unwrap();
    let laptop = new_vault("laptop");
    let before = laptop.serialize().unwrap();
    let phone = Vault::unlock(before.clone(), "correct horse".into(), "phone".into()).unwrap();

    laptop.link_to_account(&ak).unwrap();
    add(&phone, "Phone item");
    // The phone merges the linked copy: the newer authenticated header wins, so it is linked too.
    phone.merge_remote(laptop.serialize().unwrap()).unwrap();
    assert!(phone.account_link().is_some());
    let phone_file = phone.serialize().unwrap();
    assert_eq!(json(&phone_file)["version"], 3);
    laptop.merge_remote(phone_file).unwrap();
    assert_eq!(titles(&laptop), vec!["GitHub", "Phone item"]);
    assert!(laptop.account_link().is_some());

    // An older v1 copy (a backup) merges its items but never takes the header back.
    let backup = Vault::unlock(before, "correct horse".into(), "old".into()).unwrap();
    add(&backup, "From the backup");
    laptop.merge_remote(backup.serialize().unwrap()).unwrap();
    assert!(laptop.account_link().is_some());
    assert!(titles(&laptop).contains(&"From the backup".to_string()));

    // Unlinking always gives a new key: a device still on the old one can't merge the unlinked
    // copy and opens it with the new password instead, which then merges the old copy in.
    let unlinked = Vault::unlock_with_account_key(laptop.serialize().unwrap(), &ak, "desk".into()).unwrap();
    unlinked.unlink_from_account("a separate vault password".into()).unwrap();
    let file = unlinked.serialize().unwrap();
    assert!(laptop.merge_remote(file.clone()).is_err());
    assert_eq!(json(&file)["version"], 1);
    let reopened = Vault::unlock(file, "a separate vault password".into(), "x".into()).unwrap();
    assert!(reopened.account_link().is_none());
    reopened.merge_remote(laptop.serialize().unwrap()).unwrap();
    assert!(reopened.account_link().is_none());
    assert!(titles(&reopened).contains(&"From the backup".to_string()));
}

/// Rewrites a field of a v3 file and bumps its header timestamp, as a file host could.
fn tampered(file: &[u8], edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut doc = json(file);
    edit(&mut doc);
    let ts = doc["header_updated_at"].as_i64().unwrap();
    doc["header_updated_at"] = (ts + 1000).into();
    serde_json::to_vec(&doc).unwrap()
}

#[test]
fn the_file_host_cant_swap_or_strip_the_account_slots() {
    let ak = AccountKey::generate("acc_mia".into()).unwrap();
    let recovery = ak.new_recovery().unwrap();
    let v = new_vault("laptop");
    v.link_to_account(&ak).unwrap();
    v.set_account_recovery(recovery.rec_id.clone(), recovery.wrap.clone()).unwrap();
    let file = v.serialize().unwrap();

    // Another vault's slot (the host holds several files of this account).
    let other = new_vault("laptop");
    other.link_to_account(&ak).unwrap();
    let other_slot = json(&other.serialize().unwrap())["account"].clone();
    let attacks: Vec<Vec<u8>> = vec![
        tampered(&file, |d| d["account"] = other_slot),
        tampered(&file, |d| {
            d.as_object_mut().unwrap().remove("account_recovery");
        }),
        tampered(&file, |d| d["account_recovery"]["rec_id"] = "someone-else".into()),
        tampered(&file, |d| {
            // Back to a v1 header with a password slot of the host's choosing.
            let attacker = Vault::create_with_kdf("host password", "h", fast_kdf()).unwrap();
            let a = json(&attacker.serialize().unwrap());
            d["version"] = 1.into();
            d["kdf"] = a["kdf"].clone();
            d["wrapped_key"] = a["wrapped_key"].clone();
        }),
    ];
    for attack in attacks {
        let target = Vault::unlock_with_account_key(file.clone(), &ak, "phone".into()).unwrap();
        // Either the merge refuses the copy, or it keeps its own header.
        let _ = target.merge_remote(attack);
        let link = target.account_link().expect("still linked");
        assert_eq!(link.ak_id, ak.ak_id());
        assert_eq!(link.recovery_id.as_deref(), Some(recovery.rec_id.as_str()));
        let out = target.serialize().unwrap();
        assert!(Vault::unlock_with_account_key(out.clone(), &ak, "x".into()).is_ok());
        assert!(account_key_from_vault_file(out, recovery.code.clone()).is_ok());
    }
    // A stripped header copy doesn't verify, so opening it with the device key drops the
    // unauthenticated recovery copy instead of vouching for it.
    let stripped = tampered(&file, |d| d["account_recovery"]["rec_id"] = "x".into());
    let opened = Vault::unlock_with_key(stripped, v.export_vault_key(), "y".into()).unwrap();
    assert_eq!(opened.account_link().unwrap().recovery_id, None);
}

#[test]
fn readers_refuse_versions_they_dont_know() {
    let ak = AccountKey::generate("acc_mia".into()).unwrap();
    let v = new_vault("laptop");
    v.link_to_account(&ak).unwrap();
    let file = v.serialize().unwrap();
    // What older Passyble versions see: an unknown version (they accept only 1 and 2), and a
    // header whose `kdf` they couldn't use anyway.
    let doc = json(&file);
    assert_eq!(doc["version"], 3);
    assert_eq!(doc["kdf"]["alg"], "none");
    let later = tampered(&file, |d| d["version"] = 4.into());
    let err = Vault::unlock_with_account_key(later, &ak, "x".into()).unwrap_err();
    assert!(err.to_string().contains("newer version"), "{err}");
    let broken = tampered(&file, |d| {
        d.as_object_mut().unwrap().remove("account");
    });
    assert!(Vault::unlock_with_account_key(broken, &ak, "x".into()).is_err());
}

#[test]
fn a_separate_password_rotates_the_key_and_cuts_the_account_off() {
    let ak = AccountKey::generate("acc_mia".into()).unwrap();
    let v = new_vault("laptop");
    v.link_to_account(&ak).unwrap();
    let linked_file = v.serialize().unwrap();
    let old_vk = v.export_vault_key();

    v.unlink_from_account("my separate vault password".into()).unwrap();
    assert_ne!(v.export_vault_key(), old_vk, "new vault key");
    assert!(v.account_link().is_none());
    add(&v, "Written after the opt-out");
    let file = v.serialize().unwrap();
    let doc = json(&file);
    assert_eq!(doc["version"], 1);
    assert!(doc.get("account").is_none());
    assert!(doc.get("account_recovery").is_none());
    // AK opens neither the new file nor, through an old copy, anything written later.
    assert!(Vault::unlock_with_account_key(file.clone(), &ak, "x".into()).is_err());
    let old = Vault::unlock_with_account_key(linked_file.clone(), &ak, "x".into()).unwrap();
    assert!(old.merge_remote(file.clone()).is_err(), "the old key can't read the new copy");
    assert!(!titles(&old).contains(&"Written after the opt-out".to_string()));
    let reopened = Vault::unlock(file, "my separate vault password".into(), "x".into()).unwrap();
    assert_eq!(titles(&reopened), vec!["GitHub", "Written after the opt-out"]);
    // The old linked copy still merges into it (its key is a previous key).
    reopened.merge_remote(linked_file).unwrap();
    assert!(reopened.account_link().is_none());

    // And back in: link again without a new key.
    reopened.link_to_account(&ak).unwrap();
    let back = Vault::unlock_with_account_key(reopened.serialize().unwrap(), &ak, "x".into()).unwrap();
    assert_eq!(titles(&back).len(), 2);
}

#[test]
fn a_home_vault_with_a_separate_password_keeps_its_sharing_keys() {
    let ak = AccountKey::generate("acc_mia".into()).unwrap();
    let home = new_vault("laptop");
    assert!(!home.holds_sharing_keys());
    let keyset = home.ensure_user_keyset("acc_mia").unwrap();
    assert!(home.holds_sharing_keys());
    home.link_to_account(&ak).unwrap();
    let shared = Vault::create_shared(&keyset, SharedKind::Org, Some("grp_team".into()), "laptop").unwrap();
    add(&shared, "Team login");
    let shared_file = shared.serialize().unwrap();
    assert!(Vault::open_shared_with_home(shared_file.clone(), &home, "acc_mia", "laptop").is_ok());

    home.unlink_from_account("a second password".into()).unwrap();
    assert!(home.account_link().is_none());
    let file = home.serialize().unwrap();
    assert!(Vault::unlock_with_account_key(file.clone(), &ak, "x".into()).is_err());
    let reopened = Vault::unlock(file, "a second password".into(), "phone".into()).unwrap();
    assert!(reopened.holds_sharing_keys());
    let opened = Vault::open_shared_with_home(shared_file, &reopened, "acc_mia", "phone").unwrap();
    assert_eq!(titles(&opened), vec!["Team login"]);
}

#[test]
fn the_recovery_code_opens_a_copy_of_the_file_offline() {
    let ak = AccountKey::generate("acc_mia".into()).unwrap();
    let recovery = ak.new_recovery().unwrap();
    let v = new_vault("laptop");
    v.link_to_account(&ak).unwrap();
    let without = v.serialize().unwrap();
    assert!(matches!(
        Vault::unlock_with_recovery_code(without, recovery.code.clone(), "x".into()),
        Err(PassError::NotFound(_))
    ));
    assert_eq!(v.account_recovery_copy(), None);
    v.set_account_recovery(recovery.rec_id.clone(), recovery.wrap.clone()).unwrap();
    assert_eq!(v.account_link().unwrap().recovery_id.as_deref(), Some(recovery.rec_id.as_str()));
    // The copy reads back as the service gave it, for another vault this device links.
    let copy = v.account_recovery_copy().unwrap();
    assert_eq!((copy.rec_id.as_str(), &copy.wrap), (recovery.rec_id.as_str(), &recovery.wrap));
    let other = new_vault("laptop");
    other.link_to_account(&ak).unwrap();
    other.set_account_recovery(copy.rec_id, copy.wrap).unwrap();
    assert!(Vault::unlock_with_recovery_code(other.serialize().unwrap(), recovery.code.clone(), "x".into()).is_ok());
    let file = v.serialize().unwrap();
    assert!(vault_file_access(file.clone()).unwrap().account_recovery);

    let opened = Vault::unlock_with_recovery_code(file.clone(), recovery.code.clone(), "x".into()).unwrap();
    assert_eq!(titles(&opened), vec!["GitHub"]);
    let recovered = account_key_from_vault_file(file.clone(), recovery.code.clone()).unwrap();
    assert_eq!(recovered.to_bytes(), ak.to_bytes());
    // A replaced code no longer opens copies saved after the replacement.
    let newer = ak.new_recovery().unwrap();
    v.set_account_recovery(newer.rec_id.clone(), newer.wrap.clone()).unwrap();
    let file = v.serialize().unwrap();
    assert!(matches!(
        Vault::unlock_with_recovery_code(file.clone(), recovery.code.clone(), "x".into()),
        Err(PassError::InvalidPassword)
    ));
    assert!(Vault::unlock_with_recovery_code(file.clone(), newer.code.clone(), "x".into()).is_ok());
    // A typo is caught before any key work.
    assert!(matches!(
        Vault::unlock_with_recovery_code(file, "12345".into(), "x".into()),
        Err(PassError::InvalidInput(_))
    ));
}

#[test]
fn a_new_account_key_relinks_and_drops_the_old_recovery_copy() {
    let ak = AccountKey::generate("acc_mia".into()).unwrap();
    let recovery = ak.new_recovery().unwrap();
    let v = new_vault("laptop");
    v.link_to_account(&ak).unwrap();
    v.set_account_recovery(recovery.rec_id, recovery.wrap).unwrap();
    let new_ak = AccountKey::generate("acc_mia".into()).unwrap();
    v.link_to_account(&new_ak).unwrap();
    let link = v.account_link().unwrap();
    assert_eq!(link.ak_id, new_ak.ak_id());
    assert_eq!(link.recovery_id, None, "the old copy wraps the old key");
    let file = v.serialize().unwrap();
    assert!(Vault::unlock_with_account_key(file.clone(), &new_ak, "x".into()).is_ok());
    assert!(Vault::unlock_with_account_key(file, &ak, "x".into()).is_err());
}

#[test]
fn shared_vaults_are_never_linked() {
    let keyset = UserKeyset::new("acc_mia").unwrap();
    let shared = Vault::create_shared(&keyset, SharedKind::Direct, None, "laptop").unwrap();
    let ak = AccountKey::generate("acc_mia".into()).unwrap();
    assert!(shared.link_to_account(&ak).is_err());
}

#[test]
fn emergency_grants_open_linked_vaults_and_go_stale_on_rotation() {
    let owner_ak = AccountKey::generate("acc_olivia".into()).unwrap();
    let v = new_vault("laptop");
    v.link_to_account(&owner_ak).unwrap();
    let carol = UserKeyset::generate("acc_carol").unwrap();
    let full = v
        .emergency_grant("acc_olivia", carol.public_keys(), EmergencyAccess::Full, 24)
        .unwrap();
    let file = v.serialize().unwrap();
    // The contact opens the linked vault with the released grant, never with AK.
    let opened = Vault::open_emergency(file, full.grant.clone(), &full.release_secret, &carol, "c")
        .unwrap();
    assert_eq!(titles(&opened), vec!["GitHub"]);
    // Full access to a linked vault: the contact relinks it to their own account.
    let carol_ak = AccountKey::generate("acc_carol".into()).unwrap();
    opened.link_to_account(&carol_ak).unwrap();
    let taken = opened.serialize().unwrap();
    assert!(Vault::unlock_with_account_key(taken.clone(), &carol_ak, "c".into()).is_ok());
    assert!(Vault::unlock_with_account_key(taken, &owner_ak, "o".into()).is_err());
    // The owner gives the vault a separate password with a new key: the grant is stale.
    assert!(v.emergency_grant_current(full.grant.clone()));
    v.unlink_from_account("a separate password".into()).unwrap();
    assert!(!v.emergency_grant_current(full.grant));
}
