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

fn new_vault(device: &str) -> Arc<Vault> {
    Vault::create_with_kdf("correct horse", device, fast_kdf()).unwrap()
}

fn login(title: &str, url: &str, user: &str) -> Item {
    Item {
        title: title.into(),
        username: user.into(),
        password: "hunter2".into(),
        urls: vec![url.into()],
        ..Default::default()
    }
}

#[test]
fn roundtrip_and_wrong_password() {
    let vault = new_vault("laptop");
    let saved = vault
        .upsert(Item {
            totp: Some("JBSWY3DPEHPK3PXP".into()),
            ..login("GitHub", "github.com", "octo")
        })
        .unwrap();
    assert!(!saved.id.is_empty());
    assert!(saved.created_at > 0 && saved.updated_at >= saved.created_at);
    assert!(vault.is_dirty());

    let file = vault.serialize().unwrap();
    assert!(!vault.is_dirty());
    let text = String::from_utf8(file.clone()).unwrap();
    assert!(
        !text.contains("GitHub") && !text.contains("octo") && !text.contains("hunter2"),
        "secrets leaked"
    );

    let reopened = Vault::unlock(file.clone(), "correct horse".into(), "phone".into()).unwrap();
    assert_eq!(reopened.get(saved.id.clone()).unwrap(), saved);
    assert_eq!(reopened.vault_id(), vault.vault_id());
    assert_eq!(
        Vault::unlock(file.clone(), "wrong".into(), "phone".into()).unwrap_err(),
        PassError::InvalidPassword
    );

    let by_key =
        Vault::unlock_with_key(file.clone(), vault.export_vault_key(), "phone".into()).unwrap();
    assert_eq!(by_key.items().len(), 1);
    assert_eq!(
        Vault::unlock_with_key(file, vec![7; 32], "phone".into()).unwrap_err(),
        PassError::InvalidPassword
    );
}

#[test]
fn tampering_is_detected() {
    let vault = new_vault("laptop");
    vault.upsert(login("A", "a.com", "a")).unwrap();
    let mut json: serde_json::Value = serde_json::from_slice(&vault.serialize().unwrap()).unwrap();
    // Moving a ciphertext to another item id breaks the AAD binding.
    json["items"][0]["id"] = "someone-else".into();
    let err = Vault::unlock(
        serde_json::to_vec(&json).unwrap(),
        "correct horse".into(),
        "x".into(),
    )
    .unwrap_err();
    assert!(matches!(err, PassError::Corrupt(_)));
}

#[test]
fn invalid_totp_is_rejected_and_blank_cleared() {
    let vault = new_vault("laptop");
    assert!(vault
        .upsert(Item {
            totp: Some("not base32!".into()),
            ..login("A", "a.com", "a")
        })
        .is_err());
    let item = vault
        .upsert(Item {
            totp: Some("  ".into()),
            ..login("A", "a.com", "a")
        })
        .unwrap();
    assert_eq!(item.totp, None);
}

#[test]
fn url_and_app_matching() {
    let vault = new_vault("laptop");
    vault
        .upsert(login(
            "Google",
            "https://accounts.google.com",
            "me@gmail.com",
        ))
        .unwrap();
    vault.upsert(login("GitHub", "github.com", "octo")).unwrap();
    vault
        .upsert(Item {
            android_apps: vec![AndroidApp {
                package: "com.github.android".into(),
                cert_sha256: Some("AB:CD".into()),
                ..Default::default()
            }],
            ..login("GitHub app", "github.com", "octo2")
        })
        .unwrap();

    let titles = |items: Vec<Item>| items.into_iter().map(|i| i.title).collect::<Vec<_>>();
    assert_eq!(
        titles(vault.find_for_url("https://mail.google.com/".into())),
        ["Google"]
    );
    assert_eq!(
        titles(vault.find_for_url("https://github.com/login".into())),
        ["GitHub", "GitHub app"]
    );
    assert!(vault
        .find_for_url("https://github.com.evil.example/".into())
        .is_empty());
    assert_eq!(
        titles(vault.find_for_android_app("com.github.android".into(), Some("abcd".into()))),
        ["GitHub app"]
    );
    assert!(vault
        .find_for_android_app("com.github.android".into(), Some("ffff".into()))
        .is_empty());
    assert!(vault
        .find_for_android_app("com.github.android".into(), None)
        .is_empty());
    assert_eq!(
        titles(vault.search("OCTO".into())),
        ["GitHub", "GitHub app"]
    );
}

#[test]
fn logins_to_update_are_the_page_hosts_only() {
    let vault = new_vault("laptop");
    vault
        .upsert(login("Bare", "https://example.com", "me"))
        .unwrap();
    vault
        .upsert(login("App", "https://app.example.com/login", "me"))
        .unwrap();
    vault
        .upsert(login("Www B", "https://www.b.example.com", "me"))
        .unwrap();
    vault
        .upsert(login("Other", "https://example.org", "me"))
        .unwrap();
    let titles = |items: Vec<Item>| items.into_iter().map(|i| i.title).collect::<Vec<_>>();
    let save = |url: &str| titles(vault.find_for_save(url.into()));

    // Same host; `www.` is the bare domain.
    assert_eq!(save("https://example.com/sign-in"), ["Bare"]);
    assert_eq!(save("https://www.example.com/"), ["Bare"]);
    assert_eq!(save("https://app.example.com/"), ["App"]);
    assert_eq!(save("https://b.example.com/"), ["Www B"]);
    // Another subdomain of the site: nothing to update (a new login is saved) ...
    assert!(save("https://c.example.com/").is_empty());
    assert!(save("https://new.app.example.com/").is_empty());
    // ... though its logins are still offered for filling.
    assert_eq!(
        titles(vault.find_for_url("https://c.example.com/".into())),
        ["App", "Bare", "Www B"]
    );
    assert!(save("https://example.net/").is_empty());
    assert!(save("not a url at all").is_empty());
}

#[test]
fn merge_is_per_item_and_converges() {
    let laptop = new_vault("laptop");
    let a = laptop.upsert(login("A", "a.com", "a")).unwrap();
    let b = laptop.upsert(login("B", "b.com", "b")).unwrap();
    let c = laptop.upsert(login("C", "c.com", "c")).unwrap();
    let base = laptop.serialize().unwrap();
    let phone = Vault::unlock(base, "correct horse".into(), "phone".into()).unwrap();

    // Concurrent, non-conflicting edits on both sides plus a delete.
    laptop
        .upsert(Item {
            password: "laptop-pw".into(),
            ..a.clone()
        })
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2));
    phone
        .upsert(Item {
            password: "phone-pw".into(),
            ..b.clone()
        })
        .unwrap();
    phone.delete_permanently(c.id.clone()).unwrap();
    let d = phone.upsert(login("D", "d.com", "d")).unwrap();

    let stats = laptop.merge_remote(phone.serialize().unwrap()).unwrap();
    assert_eq!(
        stats,
        MergeStats {
            added: 1,
            updated: 1,
            deleted: 1,
            unchanged: 1
        }
    );
    laptop.merge_remote(phone.serialize().unwrap()).unwrap(); // idempotent
    phone.merge_remote(laptop.serialize().unwrap()).unwrap();

    for v in [&laptop, &phone] {
        assert_eq!(v.get(a.id.clone()).unwrap().password, "laptop-pw");
        assert_eq!(v.get(b.id.clone()).unwrap().password, "phone-pw");
        assert!(v.get(c.id.clone()).is_none());
        assert!(v.get(d.id.clone()).is_some());
    }
    assert_eq!(laptop.items(), phone.items());

    // An old copy can't resurrect the deleted item.
    let stale = laptop.merge_remote(phone.serialize().unwrap()).unwrap();
    assert_eq!(stale.added + stale.updated + stale.deleted, 0);
}

/// A password change comes with a new vault key: a device still on the old key can't merge the new
/// file (it asks for the new password), and once it has it, it merges its old copy in without
/// losing anything.
#[test]
fn master_password_change_propagates() {
    let laptop = new_vault("laptop");
    let phone = Vault::unlock(
        laptop.serialize().unwrap(),
        "correct horse".into(),
        "phone".into(),
    )
    .unwrap();
    laptop
        .change_master_password_with_kdf("battery staple", fast_kdf())
        .unwrap();
    phone.upsert(login("Offline", "offline.com", "o")).unwrap();
    assert!(matches!(
        phone.merge_remote(laptop.serialize().unwrap()),
        Err(PassError::Crypto(_))
    ));
    let file = laptop.serialize().unwrap();
    assert_eq!(
        Vault::unlock(file.clone(), "correct horse".into(), "x".into()).unwrap_err(),
        PassError::InvalidPassword
    );
    let reopened = Vault::unlock(file, "battery staple".into(), "phone".into()).unwrap();
    reopened.merge_remote(phone.serialize().unwrap()).unwrap();
    assert!(reopened.items().iter().any(|i| i.title == "Offline"));
}

#[test]
fn merge_rejects_other_vaults() {
    let a = new_vault("a");
    let b = new_vault("b");
    assert!(matches!(
        a.merge_remote(b.serialize().unwrap()),
        Err(PassError::Conflict(_))
    ));
}

#[test]
fn passkeys_attach_to_matching_login() {
    let vault = new_vault("laptop");
    let existing = vault
        .upsert(login("Example", "https://example.com", "alice"))
        .unwrap();
    let hash = sha256(b"client data".to_vec());
    let created = passkey_create(
        "example.com".into(),
        Some("Example".into()),
        vec![1, 2, 3],
        "alice".into(),
        "Alice".into(),
        hash.clone(),
        vec![-7, -257],
    )
    .unwrap();
    let item = vault
        .add_passkey(None, created.passkey.clone(), None)
        .unwrap();
    assert_eq!(
        item.id, existing.id,
        "passkey should join the existing login"
    );
    assert_eq!(item.passkeys.len(), 1);

    // Re-registering the same user replaces the old credential.
    let again = passkey_create(
        "example.com".into(),
        None,
        vec![1, 2, 3],
        "alice".into(),
        "Alice".into(),
        hash.clone(),
        vec![],
    )
    .unwrap();
    let item = vault
        .add_passkey(Some(existing.id.clone()), again.passkey.clone(), None)
        .unwrap();
    assert_eq!(item.passkeys.len(), 1);
    assert_eq!(item.passkeys[0].credential_id, again.credential_id);

    // A different user gets a new login.
    let bob = passkey_create(
        "example.com".into(),
        None,
        vec![9],
        "bob".into(),
        "Bob".into(),
        hash,
        vec![],
    )
    .unwrap();
    let bob_item = vault.add_passkey(None, bob.passkey, None).unwrap();
    assert_ne!(bob_item.id, existing.id);
    assert_eq!(bob_item.urls, ["https://example.com"]);

    assert_eq!(vault.find_passkeys("example.com".into(), vec![]).len(), 2);
    assert_eq!(
        vault
            .find_passkeys("EXAMPLE.com".into(), vec![again.credential_id.clone()])
            .len(),
        1
    );
    assert!(vault.find_passkeys("example.org".into(), vec![]).is_empty());
}

fn file_json(vault: &Vault) -> serde_json::Value {
    serde_json::from_slice(&vault.serialize().unwrap()).unwrap()
}

fn to_bytes(json: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(json).unwrap()
}

#[test]
fn unlock_refuses_kdf_parameters_too_expensive_to_run() {
    // The header is cleartext and arrives through sync: 4 GiB or a billion passes would crash
    // (allocation failure aborts on Android) or hang every unlock.
    let vault = new_vault("laptop");
    let file = file_json(&vault);
    for (key, value) in [("m_kib", 4_000_000u64), ("t", 1_000_000_000), ("p", 1000)] {
        let mut bad = file.clone();
        bad["kdf"][key] = value.into();
        assert!(matches!(
            Vault::unlock(to_bytes(&bad), "correct horse".into(), "x".into()),
            Err(PassError::Corrupt(_))
        ));
    }
    let mut other_alg = file.clone();
    other_alg["kdf"]["alg"] = "scrypt".into();
    assert!(Vault::unlock(to_bytes(&other_alg), "correct horse".into(), "x".into()).is_err());
    assert!(Vault::create_with_kdf(
        "pw",
        "x",
        KdfParams {
            m_kib: 8 * 1024 * 1024,
            ..fast_kdf()
        }
    )
    .is_err());
    assert!(Vault::unlock(to_bytes(&file), "correct horse".into(), "x".into()).is_ok());
}

#[test]
fn merge_ignores_forged_tombstones_and_versions() {
    // Whoever stores the file (a WebDAV host, a cloud folder) sees the cleartext merge metadata.
    // Editing it must not delete or roll back items on the devices that merge the file.
    let laptop = new_vault("laptop");
    let a = laptop.upsert(login("A", "a.com", "a")).unwrap();
    let b = laptop.upsert(login("B", "b.com", "b")).unwrap();
    let original = file_json(&laptop);
    let index = |json: &serde_json::Value, id: &str| {
        json["items"]
            .as_array()
            .unwrap()
            .iter()
            .position(|r| r["id"] == id)
            .unwrap()
    };

    // A forged tombstone with a far-future timestamp.
    let mut forged = original.clone();
    let i = index(&forged, &a.id);
    let record = forged["items"][i].as_object_mut().unwrap();
    record.insert("deleted".into(), true.into());
    record.insert("updated_at".into(), (i64::MAX / 2).into());
    record.remove("nonce");
    record.remove("ct");
    let stats = laptop.merge_remote(to_bytes(&forged)).unwrap();
    assert_eq!(stats.deleted, 0);
    assert_eq!(laptop.get(a.id.clone()).unwrap().password, "hunter2");

    // An old ciphertext replayed with a newer timestamp fails authentication and is ignored
    // (not a merge error, which would stop sync from ever repairing the remote copy).
    laptop
        .upsert(Item {
            password: "changed".into(),
            ..b.clone()
        })
        .unwrap();
    let mut replayed = original.clone();
    let i = index(&replayed, &b.id);
    replayed["items"][i]["updated_at"] = (i64::MAX / 2).into();
    assert_eq!(laptop.merge_remote(to_bytes(&replayed)).unwrap().updated, 0);
    assert_eq!(laptop.get(b.id.clone()).unwrap().password, "changed");
    // A damaged record of an item this vault doesn't have is still an error.
    let mut unknown = replayed.clone();
    unknown["items"][i]["id"] = "never-seen".into();
    assert!(matches!(
        laptop.merge_remote(to_bytes(&unknown)),
        Err(PassError::Corrupt(_))
    ));

    let phone = Vault::unlock(
        laptop.serialize().unwrap(),
        "correct horse".into(),
        "phone".into(),
    )
    .unwrap();
    phone.delete_permanently(a.id.clone()).unwrap();
    assert_eq!(
        laptop
            .merge_remote(phone.serialize().unwrap())
            .unwrap()
            .deleted,
        1
    );
    assert!(laptop.get(a.id).is_none());
}

#[test]
fn merge_adopts_only_authenticated_headers() {
    let laptop = new_vault("laptop");
    laptop.upsert(login("A", "a.com", "a")).unwrap();
    let before = file_json(&laptop);
    laptop
        .change_master_password_with_kdf("battery staple", fast_kdf())
        .unwrap();
    let after = file_json(&laptop);
    // A device that opened the vault after the change (a password change gives a new key, so
    // the others open it with the new password).
    let phone = Vault::unlock(to_bytes(&after), "battery staple".into(), "phone".into()).unwrap();
    let newer = after["header_updated_at"].as_i64().unwrap() + 1000;

    let unlocks_with = |vault: &Vault, password: &str| {
        Vault::unlock(vault.serialize().unwrap(), password.into(), "x".into()).is_ok()
    };
    let tampered = |edit: &dyn Fn(&mut serde_json::Value)| {
        let mut file = after.clone();
        file["header_updated_at"] = newer.into();
        edit(&mut file);
        to_bytes(&file)
    };
    let attacks: [(&str, Vec<u8>); 4] = [
        // Garbage wrapped key: every device would lose master-password unlock.
        (
            "wrapped key",
            tampered(&|f| f["wrapped_key"]["ct"] = "AAAA".into()),
        ),
        // The old password's header, replayed with a newer timestamp.
        (
            "replay",
            tampered(&|f| {
                f["kdf"] = before["kdf"].clone();
                f["wrapped_key"] = before["wrapped_key"].clone();
            }),
        ),
        // Parameters that hang or crash the next unlock.
        ("kdf", tampered(&|f| f["kdf"]["t"] = 1_000_000.into())),
        // No authenticator at all (stripped).
        (
            "stripped",
            tampered(&|f| {
                f.as_object_mut().unwrap().remove("header_auth");
            }),
        ),
    ];
    for (what, file) in attacks {
        // Refused, or merged without taking the header: the password stays the new one.
        let _ = phone.merge_remote(file);
        assert!(unlocks_with(&phone, "battery staple"), "{what}");
        assert!(!unlocks_with(&phone, "correct horse"), "{what}");
    }
    phone.merge_remote(to_bytes(&after)).unwrap();
    assert!(unlocks_with(&phone, "battery staple"));
}

#[test]
fn android_apps_with_a_verified_certificate_rank_first() {
    let vault = new_vault("phone");
    let app = |cert: Option<&str>| AndroidApp {
        package: "com.bank".into(),
        cert_sha256: cert.map(str::to_string),
        ..Default::default()
    };
    vault
        .upsert(Item {
            urls: vec!["androidapp://com.bank".into()],
            ..login("Legacy", "", "a")
        })
        .unwrap();
    vault
        .upsert(Item {
            android_apps: vec![app(None)],
            ..login("Unpinned", "", "b")
        })
        .unwrap();
    vault
        .upsert(Item {
            android_apps: vec![app(Some("AB:CD"))],
            ..login("Pinned", "", "c")
        })
        .unwrap();
    let titles = |cert: Option<&str>| {
        vault
            .find_for_android_app("com.bank".into(), cert.map(str::to_string))
            .into_iter()
            .map(|i| i.title)
            .collect::<Vec<_>>()
    };
    // The verified login first; unverified ones still match (first use) but after it. The
    // caller sees which are unverified (no cert_sha256 for the package) and pins them.
    assert_eq!(titles(Some("abcd")), ["Pinned", "Unpinned", "Legacy"]);
    // Another signer: only the unverified entries, never the pinned one.
    assert_eq!(titles(Some("ffff")), ["Unpinned", "Legacy"]);
    // A garbage caller digest doesn't match a pinned entry either.
    assert_eq!(titles(Some("zz")), ["Unpinned", "Legacy"]);
}
