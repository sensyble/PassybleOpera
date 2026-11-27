//! Usage counts (`Vault::record_use`): stored sealed in the vault file, merged as a grow-only
//! counter per device, never an edit, and the most used logins suggested first.

use pass_core::*;
use std::sync::Arc;

const DAY: i64 = 24 * 60 * 60 * 1000;
const NOW: i64 = 1_760_000_000_000;

fn fast_kdf() -> KdfParams {
    KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
        ..Default::default()
    }
}

fn new_vault(device: &str) -> Arc<Vault> {
    Vault::create_with_kdf("pw", device, fast_kdf()).unwrap()
}

fn copy(vault: &Vault, device: &str) -> Arc<Vault> {
    Vault::unlock(vault.serialize().unwrap(), "pw".into(), device.into()).unwrap()
}

fn login(title: &str, url: &str) -> Item {
    Item {
        title: title.into(),
        username: "me".into(),
        password: "hunter2".into(),
        urls: vec![url.into()],
        ..Default::default()
    }
}

fn file_json(vault: &Vault) -> serde_json::Value {
    serde_json::from_slice(&vault.serialize().unwrap()).unwrap()
}

fn titles(items: Vec<Item>) -> Vec<String> {
    items.into_iter().map(|i| i.title).collect()
}

fn use_n(vault: &Vault, id: &str, n: i64, at: i64) {
    for k in 0..n {
        vault.record_use(id.into(), at + k * USE_DEDUPE_MS).unwrap();
    }
}

#[test]
fn a_use_is_no_edit() {
    let vault = new_vault("laptop");
    let a = vault.upsert(login("A", "https://a.com")).unwrap();
    let before = vault.get(a.id.clone()).unwrap();
    vault.serialize().unwrap();
    let revision = vault.revision();
    // Pretend everything was synced: no sync state yet means "pending" anyway.
    assert!(vault.sync_pending());

    vault.record_use(a.id.clone(), NOW).unwrap();
    assert!(vault.is_dirty(), "a use is saved");
    assert_eq!(vault.revision(), revision, "a use is no edit to debounce");
    assert_eq!(vault.get(a.id.clone()).unwrap(), before, "item untouched");
    assert_eq!(vault.usage(a.id.clone()).count, 1);
    assert_eq!(vault.usage(a.id.clone()).last_used, NOW);

    // Kept in the local file, sealed: no item id or count in clear.
    let json = file_json(&vault);
    let usage = json["usage"].as_array().unwrap();
    assert_eq!(usage.len(), 1);
    assert_eq!(usage[0]["device_id"], "laptop");
    assert!(!usage[0].to_string().contains(&a.id));
    let reopened = copy(&vault, "laptop");
    assert_eq!(reopened.usage(a.id.clone()).count, 1);
    // The item record is byte-for-byte what it was.
    let item_records = |v: &serde_json::Value| v["items"].clone();
    assert_eq!(item_records(&json), item_records(&file_json(&reopened)));

    assert!(matches!(
        vault.record_use("nope".into(), NOW),
        Err(PassError::NotFound(_))
    ));
}

#[test]
fn devices_merge_as_a_grow_only_counter_without_conflicts() {
    let laptop = new_vault("laptop");
    let a = laptop.upsert(login("A", "https://a.com")).unwrap();
    let b = laptop.upsert(login("B", "https://b.com")).unwrap();
    let phone = copy(&laptop, "phone");

    use_n(&laptop, &a.id, 3, NOW);
    use_n(&phone, &a.id, 2, NOW + DAY);
    use_n(&phone, &b.id, 1, NOW);
    // A concurrent real edit on the phone after the laptop's uses: kept.
    phone
        .upsert(Item {
            password: "edited".into(),
            ..a.clone()
        })
        .unwrap();

    let into_laptop = laptop.merge_remote(phone.serialize().unwrap()).unwrap();
    assert_eq!(into_laptop.updated, 1, "only the real edit is an update");
    assert_eq!(into_laptop.added, 0);
    let into_phone = phone.merge_remote(laptop.serialize().unwrap()).unwrap();
    assert_eq!(
        into_phone.updated + into_phone.added + into_phone.deleted,
        0
    );

    for v in [&laptop, &phone] {
        let ua = v.usage(a.id.clone());
        assert_eq!(ua.count, 5);
        assert_eq!(ua.last_used, NOW + DAY + USE_DEDUPE_MS);
        assert_eq!(v.usage(b.id.clone()).count, 1);
        assert_eq!(v.get(a.id.clone()).unwrap().password, "edited");
        assert_eq!(v.items().len(), 2, "no duplicate or conflict copies");
    }
    assert_eq!(laptop.usage(a.id.clone()), phone.usage(a.id.clone()));

    // Merging again (or an old copy) changes nothing.
    let old = laptop.serialize().unwrap();
    use_n(&laptop, &a.id, 1, NOW + 3 * DAY);
    laptop.merge_remote(old).unwrap();
    laptop.merge_remote(phone.serialize().unwrap()).unwrap();
    assert_eq!(laptop.usage(a.id.clone()).count, 6);

    // A use on one side and an edit on the other, in either order: no edit is lost.
    let c = laptop.upsert(login("C", "https://c.com")).unwrap();
    phone.merge_remote(laptop.serialize().unwrap()).unwrap();
    phone
        .upsert(Item {
            title: "C renamed".into(),
            ..c.clone()
        })
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2));
    laptop.record_use(c.id.clone(), NOW).unwrap();
    laptop.merge_remote(phone.serialize().unwrap()).unwrap();
    phone.merge_remote(laptop.serialize().unwrap()).unwrap();
    for v in [&laptop, &phone] {
        assert_eq!(v.get(c.id.clone()).unwrap().title, "C renamed");
        assert_eq!(v.usage(c.id.clone()).count, 1);
    }
}

#[test]
fn a_restored_copy_of_this_device_loses_no_uses() {
    let laptop = new_vault("laptop");
    let a = laptop.upsert(login("A", "https://a.com")).unwrap();
    let b = laptop.upsert(login("B", "https://b.com")).unwrap();
    use_n(&laptop, &a.id, 2, NOW);
    let synced = laptop.serialize().unwrap();
    // The laptop goes on (and syncs that), then is restored from the older file and used again.
    use_n(&laptop, &a.id, 3, NOW + DAY);
    let newer = laptop.serialize().unwrap();
    let restored = Vault::unlock(synced, "pw".into(), "laptop".into()).unwrap();
    use_n(&restored, &b.id, 1, NOW + 2 * DAY);
    restored.merge_remote(newer).unwrap();
    // Per item the larger count of the two copies: 3 newer uses of A were counted on top of 2.
    assert_eq!(restored.usage(a.id.clone()).count, 5);
    assert_eq!(restored.usage(b.id.clone()).count, 1);
    laptop.merge_remote(restored.serialize().unwrap()).unwrap();
    assert_eq!(laptop.usage(a.id.clone()), restored.usage(a.id.clone()));
    assert_eq!(laptop.usage(b.id.clone()).count, 1);
}

#[test]
fn older_clients_drop_usage_but_lose_nothing_else() {
    let laptop = new_vault("laptop");
    let a = laptop.upsert(login("A", "https://a.com")).unwrap();
    use_n(&laptop, &a.id, 2, NOW);

    // An older client reads the file (unknown fields are ignored) and writes it back without them.
    let mut json = file_json(&laptop);
    json.as_object_mut().unwrap().remove("usage");
    json.as_object_mut().unwrap().remove("sync");
    let old_client_copy = serde_json::to_vec(&json).unwrap();
    let opened = Vault::unlock(old_client_copy.clone(), "pw".into(), "old".into()).unwrap();
    assert_eq!(opened.items().len(), 1);
    assert_eq!(opened.usage(a.id.clone()).count, 0);

    // Merging that copy keeps this device's usage.
    let stats = laptop.merge_remote(old_client_copy).unwrap();
    assert_eq!(stats.updated + stats.deleted, 0);
    assert_eq!(laptop.usage(a.id.clone()).count, 2);

    // A vault without usage writes no `usage` field at all (byte-compatible with older files).
    let plain = new_vault("x");
    plain.upsert(login("A", "https://a.com")).unwrap();
    assert!(file_json(&plain).get("usage").is_none());
}

#[test]
fn damaged_or_foreign_usage_is_ignored() {
    let laptop = new_vault("laptop");
    let a = laptop.upsert(login("A", "https://a.com")).unwrap();
    use_n(&laptop, &a.id, 2, NOW);
    let mut json = file_json(&laptop);
    // A bumped version (the AAD binds it) and a blob for another device copied from this one.
    let mut forged = json["usage"][0].clone();
    forged["device_id"] = "evil".into();
    json["usage"].as_array_mut().unwrap().push(forged);
    json["usage"][0]["updated_at"] = serde_json::json!(i64::MAX / 2);
    let bytes = serde_json::to_vec(&json).unwrap();

    // Still opens; the bad blobs simply count for nothing.
    let opened = Vault::unlock(bytes.clone(), "pw".into(), "phone".into()).unwrap();
    assert_eq!(opened.usage(a.id.clone()).count, 0);
    let fresh = copy(&laptop, "laptop");
    fresh.merge_remote(bytes).unwrap();
    assert_eq!(fresh.usage(a.id.clone()).count, 2);
}

#[test]
fn usage_survives_a_key_rotation() {
    let laptop = new_vault("laptop");
    let a = laptop.upsert(login("A", "https://a.com")).unwrap();
    let phone = copy(&laptop, "phone");
    use_n(&phone, &a.id, 4, NOW);
    let before_rotation = phone.serialize().unwrap();
    use_n(&laptop, &a.id, 1, NOW);
    laptop
        .change_password("pw".into(), "pw2".into())
        .unwrap();
    // A copy sealed with the old key still merges, and is re-sealed with the new one.
    laptop.merge_remote(before_rotation).unwrap();
    assert_eq!(laptop.usage(a.id.clone()).count, 5);
    let reopened =
        Vault::unlock(laptop.serialize().unwrap(), "pw2".into(), "laptop".into()).unwrap();
    assert_eq!(reopened.usage(a.id.clone()).count, 5);
}

#[test]
fn at_most_sixteen_devices_are_kept() {
    let first = new_vault("d00");
    let a = first.upsert(login("A", "https://a.com")).unwrap();
    let base = first.serialize().unwrap();
    let hub = Vault::unlock(base.clone(), "pw".into(), "hub".into()).unwrap();
    for n in 0..20 {
        let device = Vault::unlock(base.clone(), "pw".into(), format!("d{n:02}")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        device.record_use(a.id.clone(), NOW + n).unwrap();
        hub.merge_remote(device.serialize().unwrap()).unwrap();
    }
    let json = file_json(&hub);
    let devices: Vec<String> = json["usage"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["device_id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(devices.len(), MAX_USAGE_DEVICES);
    // The ones that wrote theirs last.
    assert!(!devices.contains(&"d00".to_string()) && devices.contains(&"d19".to_string()));
    // A device that records a use is the latest, so its counts are kept (and another's dropped).
    hub.record_use(a.id.clone(), NOW).unwrap();
    let json = file_json(&hub);
    assert!(json["usage"]
        .as_array()
        .unwrap()
        .iter()
        .any(|u| u["device_id"] == "hub"));
    assert_eq!(json["usage"].as_array().unwrap().len(), MAX_USAGE_DEVICES);
    assert!(!json["usage"]
        .as_array()
        .unwrap()
        .iter()
        .any(|u| u["device_id"] == "d04"));
}

#[test]
fn deleted_items_drop_out_of_this_devices_counts() {
    let laptop = new_vault("laptop");
    let a = laptop.upsert(login("A", "https://a.com")).unwrap();
    let b = laptop.upsert(login("B", "https://b.com")).unwrap();
    use_n(&laptop, &a.id, 1, NOW);
    // In the trash it keeps its counts (it may come back)...
    laptop.delete(a.id.clone()).unwrap();
    assert!(laptop.record_use(a.id.clone(), NOW).is_err(), "not live");
    assert_eq!(copy(&laptop, "laptop").usage(a.id.clone()).count, 1);
    // ...deleted for good it doesn't.
    laptop.delete_permanently(a.id.clone()).unwrap();
    laptop.record_use(b.id.clone(), NOW).unwrap();
    let reopened = copy(&laptop, "laptop");
    assert_eq!(reopened.usage(a.id.clone()).count, 0);
    assert_eq!(reopened.usage(b.id.clone()).count, 1);
}

#[test]
fn the_most_used_logins_come_first() {
    let vault = new_vault("laptop");
    let rare = vault.upsert(login("Alpha", "https://example.com")).unwrap();
    let often = vault.upsert(login("Beta", "https://example.com")).unwrap();
    let never = vault
        .upsert(login("Aardvark", "https://example.com"))
        .unwrap();
    let recent = vault.upsert(login("Gamma", "https://example.com")).unwrap();
    // Matching decides first: an exact host beats the registrable domain.
    let exact = vault
        .upsert(login("Zulu", "https://login.example.com"))
        .unwrap();
    use_n(&vault, &rare.id, 1, NOW - 60 * DAY);
    use_n(&vault, &often.id, 20, NOW - 10 * DAY);
    use_n(&vault, &recent.id, 1, NOW);
    let _ = (&never, &exact);

    let found = titles(vault.find_for_url("https://login.example.com/x".into()));
    assert_eq!(found, ["Zulu", "Beta", "Gamma", "Alpha", "Aardvark"]);

    // Favorites still come first.
    vault
        .upsert(Item {
            favorite: true,
            ..never.clone()
        })
        .unwrap();
    let found = titles(vault.find_for_url("https://example.com".into()));
    assert_eq!(found[0], "Aardvark");
    assert_eq!(&found[1..3], ["Beta", "Gamma"]);

    // The locked list ranks the same, and carries the counts.
    let index = vault.summaries();
    let summary = index.iter().find(|s| s.id == often.id).unwrap();
    assert_eq!(summary.use_count, 20);
    assert!(summary.rank > 0);
    let locked: Vec<String> = summaries_for_url(index.clone(), "https://example.com".into())
        .into_iter()
        .map(|s| s.title)
        .collect();
    assert_eq!(locked, found);
    let most_used: Vec<String> = summaries_most_used(index.clone())
        .into_iter()
        .map(|s| s.title)
        .collect();
    assert_eq!(most_used, ["Beta", "Gamma", "Alpha", "Aardvark", "Zulu"]);
    let suggested: Vec<String> = summaries_suggested(index)
        .into_iter()
        .map(|s| s.title)
        .collect();
    assert_eq!(suggested, ["Aardvark", "Beta", "Gamma", "Alpha", "Zulu"]);

    // Searching the vault stays by title (the vault list's order).
    assert_eq!(titles(vault.search("".into()))[0], "Aardvark");
}

#[test]
fn a_stored_path_does_not_outrank_the_most_used_login_of_the_host() {
    let vault = new_vault("laptop");
    // Imported from a browser: the sign-in page's path. Saved by Passyble: the origin only.
    let imported = vault
        .upsert(login("Imported", "https://example.com/login"))
        .unwrap();
    let saved = vault.upsert(login("Saved", "https://example.com")).unwrap();
    let other = vault
        .upsert(login("Other subdomain", "https://shop.example.com"))
        .unwrap();
    use_n(&vault, &saved.id, 5, NOW - DAY);
    use_n(&vault, &other.id, 9, NOW - DAY);
    use_n(&vault, &imported.id, 1, NOW - 40 * DAY);

    let page = "https://example.com/login?next=/home";
    // The most used login of the host first, wherever each was saved; another subdomain after.
    let expected = ["Saved", "Imported", "Other subdomain"];
    assert_eq!(titles(vault.find_for_url(page.into())), expected);
    let locked: Vec<String> = summaries_for_url(vault.summaries(), page.into())
        .into_iter()
        .map(|s| s.title)
        .collect();
    assert_eq!(locked, expected);

    // Used more now, the imported login comes first.
    use_n(&vault, &imported.id, 20, NOW);
    assert_eq!(
        titles(vault.find_for_url(page.into())),
        ["Imported", "Saved", "Other subdomain"]
    );
}

#[test]
fn the_most_used_passkey_comes_first() {
    let vault = new_vault("laptop");
    let passkey = |user: &str, id: u8| Passkey {
        credential_id: vec![id],
        rp_id: "example.com".into(),
        user_handle: vec![id],
        user_name: user.into(),
        user_display_name: user.into(),
        ..Default::default()
    };
    let a = vault
        .add_passkey(
            None,
            passkey("alice", 1),
            Some("https://example.com".into()),
        )
        .unwrap();
    let b = vault
        .add_passkey(None, passkey("bob", 2), Some("https://example.com".into()))
        .unwrap();
    let order = |v: &Vault| -> Vec<String> {
        v.find_passkeys("example.com".into(), vec![])
            .into_iter()
            .map(|m| m.passkey.user_name)
            .collect()
    };
    assert_eq!(order(&vault), ["alice", "bob"]);
    vault.record_use(b.id.clone(), NOW).unwrap();
    assert_eq!(order(&vault), ["bob", "alice"]);
    let locked: Vec<String> = summaries_with_passkeys(vault.summaries(), "example.com".into())
        .into_iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(locked, [b.id, a.id]);
}

#[test]
fn usage_waits_for_a_sync_up_to_six_hours() {
    let vault = new_vault("laptop");
    let a = vault.upsert(login("A", "https://a.com")).unwrap();
    assert!(!vault.usage_sync_pending());
    vault.record_use(a.id.clone(), NOW).unwrap();
    assert!(vault.usage_sync_pending());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    assert!(!vault.usage_sync_due(now));
    assert!(vault.usage_sync_due(now + USAGE_SYNC_INTERVAL_MS + 1000));
    // After a restart it counts from the unlock.
    let reopened = copy(&vault, "laptop");
    assert!(reopened.usage_sync_pending());
    assert!(!reopened.usage_sync_due(now));
    assert!(reopened.usage_sync_due(now + USAGE_SYNC_INTERVAL_MS + 1000));
}
