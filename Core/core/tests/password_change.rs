//! `Vault::change_password`: checked password changes, with and without replacing the vault key.

use pass_core::*;
use std::sync::Arc;

fn fast_kdf() -> KdfParams {
    KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
        ..Default::default()
    }
}

fn item(title: &str) -> Item {
    Item {
        title: title.into(),
        password: "pw".into(),
        ..Default::default()
    }
}

fn titles(v: &Arc<Vault>) -> Vec<String> {
    let mut t: Vec<String> = v.items().into_iter().map(|i| i.title).collect();
    t.sort();
    t
}

#[test]
fn checks_the_old_password_and_replaces_the_key() {
    let laptop = Vault::create_with_kdf("admin chose this", "laptop", fast_kdf()).unwrap();
    laptop.upsert(item("GitHub")).unwrap();
    let key = laptop.export_vault_key();
    assert_eq!(
        laptop
            .change_password("wrong".into(), "mine now".into())
            .unwrap_err(),
        PassError::InvalidPassword
    );
    assert!(matches!(
        laptop.change_password("admin chose this".into(), String::new()),
        Err(PassError::InvalidInput(_))
    ));
    laptop
        .change_password("admin chose this".into(), "mine now".into())
        .unwrap();
    // A new vault key with every password change.
    assert_ne!(laptop.export_vault_key(), key);
    let file = laptop.serialize().unwrap();
    assert_eq!(
        Vault::unlock(file.clone(), "admin chose this".into(), "x".into()).unwrap_err(),
        PassError::InvalidPassword
    );
    let again = Vault::unlock(file.clone(), "mine now".into(), "x".into()).unwrap();
    assert_eq!(titles(&again), ["GitHub"]);
    // The old key opens nothing: the apps store the new one for Windows Hello / biometrics.
    assert!(Vault::unlock_with_key(file.clone(), key, "x".into()).is_err());
    assert!(Vault::unlock_with_key(file, laptop.export_vault_key(), "x".into()).is_ok());
}

/// The attack a new key per password change prevents: a server (or a Drive revision, a backup)
/// keeps a copy from before the change and serves it, and the attacker cracks the old, weaker
/// password. That copy shows only what it held then; its key opens nothing written after the
/// change.
#[test]
fn an_old_copy_cracked_with_the_old_password_reads_nothing_written_later() {
    let laptop = Vault::create_with_kdf("summer2019", "laptop", fast_kdf()).unwrap();
    laptop.upsert(item("Old login")).unwrap();
    let kept_by_server = laptop.serialize().unwrap();
    laptop
        .change_password("summer2019".into(), "a much longer passphrase now".into())
        .unwrap();
    laptop.upsert(item("New bank")).unwrap();
    let current = laptop.serialize().unwrap();
    // The attacker opens the old copy with the cracked old password and takes its key.
    let cracked = Vault::unlock(kept_by_server, "summer2019".into(), "x".into()).unwrap();
    assert_eq!(titles(&cracked), ["Old login"]);
    let old_key = cracked.export_vault_key();
    // Neither the old password nor the old key opens the current file.
    assert_eq!(
        Vault::unlock(current.clone(), "summer2019".into(), "x".into()).unwrap_err(),
        PassError::InvalidPassword
    );
    assert!(Vault::unlock_with_key(current.clone(), old_key, "x".into()).is_err());
    // Merging the current file into the cracked copy fails too: nothing new leaks through it.
    assert!(cracked.merge_remote(current).is_err());
    assert_eq!(titles(&cracked), ["Old login"]);
}

#[test]
fn rotating_the_key_re_encrypts_and_still_merges_old_copies() {
    let laptop = Vault::create_with_kdf("admin chose this", "laptop", fast_kdf()).unwrap();
    laptop.upsert(item("GitHub")).unwrap();
    let old_file = laptop.serialize().unwrap();
    // A phone opened the vault before the change and edits offline.
    let phone = Vault::unlock(old_file.clone(), "admin chose this".into(), "phone".into()).unwrap();
    phone.upsert(item("Bank")).unwrap();
    let old_key = laptop.export_vault_key();

    laptop
        .change_password("admin chose this".into(), "mine now".into())
        .unwrap();
    assert_ne!(laptop.export_vault_key(), old_key);
    let new_file = laptop.serialize().unwrap();
    // Every item was re-encrypted: no ciphertext of the old file survives.
    let old_json: serde_json::Value = serde_json::from_slice(&old_file).unwrap();
    let new_json = String::from_utf8(new_file.clone()).unwrap();
    for record in old_json["items"].as_array().unwrap() {
        assert!(!new_json.contains(record["ct"].as_str().unwrap()));
    }
    // The old password and the old key open nothing.
    assert_eq!(
        Vault::unlock(new_file.clone(), "admin chose this".into(), "x".into()).unwrap_err(),
        PassError::InvalidPassword
    );
    assert!(Vault::unlock_with_key(new_file.clone(), old_key, "x".into()).is_err());

    // The phone's old-key copy merges into the rotated vault (its items are re-encrypted)...
    let stats = laptop.merge_remote(phone.serialize().unwrap()).unwrap();
    assert_eq!(stats.added, 1);
    assert_eq!(titles(&laptop), ["Bank", "GitHub"]);
    // ...and the old header never replaces the new one, whatever its timestamp.
    let merged = laptop.serialize().unwrap();
    let reopened = Vault::unlock(merged.clone(), "mine now".into(), "y".into()).unwrap();
    assert_eq!(titles(&reopened), ["Bank", "GitHub"]);
    // A device that opens the rotated file later can still merge old copies (the old key is
    // stored in the file, sealed with the new one).
    assert_eq!(reopened.merge_remote(old_file.clone()).unwrap().added, 0);
    // The phone, still on the old key, can't merge the new file: it must unlock with the new
    // password.
    assert!(matches!(
        phone.merge_remote(merged.clone()),
        Err(PassError::Crypto(_))
    ));

    // A second rotation keeps the whole chain.
    reopened
        .change_password("mine now".into(), "third one".into())
        .unwrap();
    let third = Vault::unlock(
        reopened.serialize().unwrap(),
        "third one".into(),
        "z".into(),
    )
    .unwrap();
    third.merge_remote(old_file).unwrap();
    third.merge_remote(merged).unwrap();
    assert_eq!(titles(&third), ["Bank", "GitHub"]);
}

#[test]
fn an_unlocked_device_can_adopt_a_password_set_elsewhere() {
    // E.g. the password was reset on the server and no device knows the old one any more, but
    // this one is still unlocked (Windows Hello): it re-wraps the vault without the old password.
    let pc = Vault::create_with_kdf("forgotten", "pc", fast_kdf()).unwrap();
    pc.upsert(item("Mail")).unwrap();
    pc.change_master_password("new from reset".into()).unwrap();
    let v = Vault::unlock(pc.serialize().unwrap(), "new from reset".into(), "x".into()).unwrap();
    assert_eq!(titles(&v), ["Mail"]);
}
