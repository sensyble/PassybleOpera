//! Recovery codes: `Vault::create_recovery_code`, `Vault::unlock_with_recovery_code` and how the
//! recovery block in the header merges, survives older clients and resists the file's host.

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

fn bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

/// `file` as a client without recovery codes writes it back: without the block.
fn without_recovery(file: &[u8]) -> Vec<u8> {
    let mut v = json(file);
    v.as_object_mut().unwrap().remove("recovery");
    bytes(&v)
}

fn titles(v: &Vault) -> Vec<String> {
    v.items().into_iter().map(|i| i.title).collect()
}

fn opens_with(file: &[u8], code: &str) -> Result<Arc<Vault>> {
    Vault::unlock_with_recovery_code(file.to_vec(), code.into(), "rescue".into())
}

#[test]
fn a_recovery_code_unlocks_and_a_new_password_can_be_set() {
    let laptop = new_vault("laptop");
    assert!(!laptop.has_recovery_code());
    assert_eq!(laptop.recovery_code_created_at(), None);
    assert!(json(&laptop.serialize().unwrap()).get("recovery").is_none());

    let code = laptop.create_recovery_code().unwrap();
    assert!(recovery_code_valid_format(code.clone()));
    assert_eq!(code.len(), 35);
    assert!(laptop.has_recovery_code());
    assert!(laptop.recovery_code_created_at().unwrap() > 0);
    assert!(laptop.is_dirty());
    let file = laptop.serialize().unwrap();
    assert!(json(&file)["recovery"]["wrapped_key"]["ct"].is_string());
    assert!(!String::from_utf8_lossy(&file).contains(&code));

    // The code opens the vault, also typed sloppily; the vault key is the same (a Windows Hello
    // or biometric copy of it keeps working).
    let rescued = opens_with(&file, &code).unwrap();
    assert_eq!(titles(&rescued), ["GitHub"]);
    assert_eq!(rescued.export_vault_key(), laptop.export_vault_key());
    let sloppy = code.to_lowercase().replace('-', " ");
    assert!(opens_with(&file, &sloppy).is_ok());
    assert!(rescued.has_recovery_code());

    // A new master password without the old one. It comes with a new vault key, so the code, which
    // wrapped the old key, goes: the apps show a new one right away.
    rescued
        .change_master_password("battery staple".into())
        .unwrap();
    let after = rescued.serialize().unwrap();
    assert_eq!(
        Vault::unlock(after.clone(), "correct horse".into(), "x".into()).unwrap_err(),
        PassError::InvalidPassword
    );
    assert!(Vault::unlock(after.clone(), "battery staple".into(), "x".into()).is_ok());
    assert!(!rescued.has_recovery_code());
    assert!(opens_with(&after, &code).is_err());

    let newer = rescued.create_recovery_code().unwrap();
    assert_ne!(newer, code);
    let replaced = rescued.serialize().unwrap();
    assert_eq!(
        opens_with(&replaced, &code).unwrap_err(),
        PassError::InvalidPassword
    );
    assert!(opens_with(&replaced, &newer).is_ok());

    // Removed: nothing opens it any more.
    rescued.remove_recovery_code().unwrap();
    assert!(!rescued.has_recovery_code());
    let removed = rescued.serialize().unwrap();
    assert!(json(&removed).get("recovery").is_none());
    assert!(matches!(
        opens_with(&removed, &newer),
        Err(PassError::NotFound(_))
    ));
    // Removing again changes nothing.
    rescued.remove_recovery_code().unwrap();
    assert!(!rescued.is_dirty());
}

#[test]
fn wrong_codes_and_typos() {
    let laptop = new_vault("laptop");
    let file_without = laptop.serialize().unwrap();
    let code = laptop.create_recovery_code().unwrap();
    let file = laptop.serialize().unwrap();

    // A typo is caught before any key derivation.
    let mut typo: Vec<char> = code.chars().collect();
    typo[3] = if typo[3] == 'A' { 'B' } else { 'A' };
    let typo: String = typo.into_iter().collect();
    assert!(!recovery_code_valid_format(typo.clone()));
    assert!(matches!(
        opens_with(&file, &typo),
        Err(PassError::InvalidInput(_))
    ));
    assert!(matches!(
        opens_with(&file, "1234"),
        Err(PassError::InvalidInput(_))
    ));
    assert!(matches!(
        opens_with(&file, ""),
        Err(PassError::InvalidInput(_))
    ));
    // The master password is no recovery code.
    assert!(matches!(
        opens_with(&file, "correct horse"),
        Err(PassError::InvalidInput(_))
    ));

    // A well-formed code of another vault.
    let other = new_vault("other").create_recovery_code().unwrap();
    assert!(recovery_code_valid_format(other.clone()));
    assert_eq!(
        opens_with(&file, &other).unwrap_err(),
        PassError::InvalidPassword
    );
    // A vault without a code.
    assert!(matches!(
        opens_with(&file_without, &code),
        Err(PassError::NotFound(_))
    ));
}

#[test]
fn the_code_syncs_to_other_devices_with_the_header() {
    let laptop = new_vault("laptop");
    let phone = Vault::unlock(
        laptop.serialize().unwrap(),
        "correct horse".into(),
        "phone".into(),
    )
    .unwrap();

    let code = laptop.create_recovery_code().unwrap();
    phone.merge_remote(laptop.serialize().unwrap()).unwrap();
    assert!(phone.has_recovery_code());
    assert_eq!(
        phone.recovery_code_created_at(),
        laptop.recovery_code_created_at()
    );
    assert!(opens_with(&phone.serialize().unwrap(), &code).is_ok());

    let file = laptop.serialize().unwrap();
    assert!(opens_with(&file, &code).is_ok());

    // An older copy (before the code) changes nothing.
    let mut old = json(&file);
    old.as_object_mut().unwrap().remove("recovery");
    old["header_updated_at"] = (old["header_updated_at"].as_i64().unwrap() - 10).into();
    laptop.merge_remote(bytes(&old)).unwrap();
    assert!(laptop.has_recovery_code());

    // Removal spreads too.
    laptop.remove_recovery_code().unwrap();
    phone.merge_remote(laptop.serialize().unwrap()).unwrap();
    assert!(!phone.has_recovery_code());
    // ...and the phone's older copy with the code doesn't bring it back.
    let before_removal = file;
    phone.merge_remote(before_removal.clone()).unwrap();
    laptop.merge_remote(before_removal).unwrap();
    assert!(!phone.has_recovery_code());
    assert!(!laptop.has_recovery_code());
}

#[test]
fn replacing_the_vault_key_drops_the_code() {
    let laptop = new_vault("laptop");
    let code = laptop.create_recovery_code().unwrap();
    let before = laptop.serialize().unwrap();
    laptop
        .change_password("correct horse".into(), "battery staple".into())
        .unwrap();
    assert!(!laptop.has_recovery_code());
    let after = laptop.serialize().unwrap();
    assert!(matches!(
        opens_with(&after, &code),
        Err(PassError::NotFound(_))
    ));
    // The copy from before the rotation still opens with it (that copy is what the old key
    // opens anyway), but merging it brings no code back.
    assert!(opens_with(&before, &code).is_ok());
    laptop.merge_remote(before).unwrap();
    assert!(!laptop.has_recovery_code());
}

#[test]
fn older_clients_open_merge_and_resave_vaults_with_a_code() {
    let laptop = new_vault("laptop");
    let phone = Vault::unlock(
        laptop.serialize().unwrap(),
        "correct horse".into(),
        "phone".into(),
    )
    .unwrap();
    let code = laptop.create_recovery_code().unwrap();
    let file = laptop.serialize().unwrap();

    // `header_auth` doesn't cover the block, so an older client authenticates this header as
    // before (it adopts password changes), and ignores the unknown field when it reads the file.
    // What it writes back has no block: the same header without it.
    let old_client_copy = without_recovery(&file);
    assert!(Vault::unlock(old_client_copy.clone(), "correct horse".into(), "x".into()).is_ok());
    phone.merge_remote(old_client_copy.clone()).unwrap();
    assert!(
        !phone.has_recovery_code(),
        "a newer header, adopted as it is"
    );

    // A device with the code keeps it when the older client's copy comes back...
    laptop.merge_remote(old_client_copy.clone()).unwrap();
    assert!(laptop.has_recovery_code());
    // ...and its next upload (`remote_is_behind`) brings it back to the others: the same header
    // with a code that verifies for it is taken over.
    phone.merge_remote(laptop.serialize().unwrap()).unwrap();
    assert!(phone.has_recovery_code());
    assert!(opens_with(&phone.serialize().unwrap(), &code).is_ok());

    // A password change on a client that never had the code ends it too.
    let old_client = Vault::unlock(old_client_copy, "correct horse".into(), "old".into()).unwrap();
    assert!(!old_client.has_recovery_code());
    old_client
        .change_master_password("battery staple".into())
        .unwrap();
    // This client's password change gives a new key too: the laptop opens the new file with the
    // new password (its old key can't merge it), and the code is gone there as well.
    let changed = old_client.serialize().unwrap();
    assert!(laptop.merge_remote(changed.clone()).is_err());
    let reopened = Vault::unlock(changed, "battery staple".into(), "x".into()).unwrap();
    assert!(!reopened.has_recovery_code());
}

#[test]
fn the_files_host_cannot_swap_replay_or_plant_a_recovery_block() {
    let laptop = new_vault("laptop");
    let phone = Vault::unlock(
        laptop.serialize().unwrap(),
        "correct horse".into(),
        "phone".into(),
    )
    .unwrap();
    let old_code = laptop.create_recovery_code().unwrap();
    let with_old = json(&laptop.serialize().unwrap());
    let code = laptop.create_recovery_code().unwrap();
    let genuine = json(&laptop.serialize().unwrap());

    let edited = |edit: &dyn Fn(&mut Value)| {
        let mut f = genuine.clone();
        edit(&mut f);
        bytes(&f)
    };
    // The host's own vault and code: a block it could produce.
    let host = new_vault("host");
    let host_code = host.create_recovery_code().unwrap();
    let host_block = json(&host.serialize().unwrap())["recovery"].clone();

    let attacks: [(&str, Vec<u8>); 4] = [
        // The replaced code's block, put back next to the current header.
        (
            "replay",
            edited(&|f| f["recovery"] = with_old["recovery"].clone()),
        ),
        // A block wrapping a key under the host's code.
        ("plant", edited(&|f| f["recovery"] = host_block.clone())),
        // The genuine block with a field changed.
        (
            "swap",
            edited(&|f| f["recovery"]["kdf"] = with_old["recovery"]["kdf"].clone()),
        ),
        ("date", edited(&|f| f["recovery"]["created_at"] = 1.into())),
    ];
    for (what, file) in &attacks {
        // Merged: the header is adopted (it is genuine), the block is not.
        let p = Vault::unlock(
            phone.serialize().unwrap(),
            "correct horse".into(),
            "p".into(),
        )
        .unwrap();
        p.merge_remote(file.clone()).unwrap();
        assert!(!p.has_recovery_code(), "{what}");
        let resaved = p.serialize().unwrap();
        assert!(opens_with(&resaved, &old_code).is_err(), "{what}");
        assert!(opens_with(&resaved, &host_code).is_err(), "{what}");
        // Unlocked from the tampered file with the password: the block is dropped there too.
        let u = Vault::unlock(file.clone(), "correct horse".into(), "u".into()).unwrap();
        assert!(!u.has_recovery_code(), "{what}");
        // The genuine copy (the laptop's next upload) brings the current code.
        p.merge_remote(bytes(&genuine)).unwrap();
        assert!(p.has_recovery_code(), "{what}");
        assert!(opens_with(&p.serialize().unwrap(), &code).is_ok(), "{what}");
        // A device with the code keeps it.
        laptop.merge_remote(file.clone()).unwrap();
        assert!(laptop.has_recovery_code(), "{what}");
    }
    // The host's code never opens the vault: its block is bound to the host's vault, and would
    // not hold this vault's key anyway.
    assert_eq!(
        opens_with(&attacks[1].1, &host_code).unwrap_err(),
        PassError::InvalidPassword
    );
    // The replayed block still opens the file it is in: the old code wraps the same vault key
    // (removing or replacing a code can't revoke copies of the file made before; replace the
    // vault key for that).
    assert!(opens_with(&attacks[0].1, &old_code).is_ok());

    // Stripping the block from a newer header: devices behind adopt the header without it, the
    // device with the code keeps it, and its next upload restores it everywhere.
    let stripped = without_recovery(&laptop.serialize().unwrap());
    phone.merge_remote(stripped.clone()).unwrap();
    assert!(!phone.has_recovery_code());
    laptop.merge_remote(stripped).unwrap();
    assert!(laptop.has_recovery_code());
    phone.merge_remote(laptop.serialize().unwrap()).unwrap();
    assert!(phone.has_recovery_code());

    // A newer header can't be faked to carry a planted block (header_auth fails, nothing is
    // adopted).
    let mut forged = genuine.clone();
    forged["header_updated_at"] = (genuine["header_updated_at"].as_i64().unwrap() + 1000).into();
    forged["recovery"] = host_block;
    let fresh = Vault::unlock(bytes(&with_old), "correct horse".into(), "f".into()).unwrap();
    fresh.merge_remote(bytes(&forged)).unwrap();
    assert!(opens_with(&fresh.serialize().unwrap(), &host_code).is_err());
    assert!(opens_with(&fresh.serialize().unwrap(), &old_code).is_ok());
}

#[test]
fn recovery_kdf_parameters_are_bounded() {
    let laptop = new_vault("laptop");
    let code = laptop.create_recovery_code().unwrap();
    let mut f = json(&laptop.serialize().unwrap());
    f["recovery"]["kdf"]["m_kib"] = (4u64 * 1024 * 1024).into();
    assert!(matches!(
        opens_with(&bytes(&f), &code),
        Err(PassError::Corrupt(_))
    ));
}
