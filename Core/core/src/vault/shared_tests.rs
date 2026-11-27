//! Shared vaults: the sharing rules and the attacks they stop. Demo accounts and passwords only.

use super::*;
use crate::share::keys::WrappedKey;
use crate::share::members::{entries_digest, MembersFile};
use crate::vault::{key_from_vec, RecordFile, FORMAT, VERSION, VERSION_SHARED};
use crate::{
    GroupMember, Item, MemberChange, MemberRole, PinStatus, SharedKind, PERSONAL_SCOPE,
};
use serde_json::Value;

fn fast_kdf() -> KdfParams {
    KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
        ..Default::default()
    }
}

fn keys(account: &str) -> UserKeyset {
    UserKeyset::generate(account).unwrap()
}

fn login(title: &str, password: &str) -> Item {
    Item {
        title: title.into(),
        username: "kim".into(),
        password: password.into(),
        urls: vec![format!("https://{}.example", title.to_lowercase())],
        ..Default::default()
    }
}

fn bytes(v: &Vault) -> Vec<u8> {
    v.serialize().unwrap()
}

fn json(v: &Vault) -> Value {
    serde_json::from_slice(&bytes(v)).unwrap()
}

fn to_bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

fn titles(v: &Vault) -> Vec<String> {
    v.items().into_iter().map(|i| i.title).collect()
}

fn members_of(v: &Value) -> MembersFile {
    serde_json::from_value(v["members"].clone()).unwrap()
}

/// `me`'s home vault, with the keys of `people` pinned (compared with them).
fn home_pinning(me: &UserKeyset, people: &[&UserKeyset]) -> Arc<Vault> {
    let home = Vault::create_with_kdf("demo master", "home", fast_kdf()).unwrap();
    home.store_user_keyset(me).unwrap();
    for p in people {
        let keys = p.public_keys();
        home.pin_contact(keys.clone(), PERSONAL_SCOPE, &keys.fingerprint())
            .unwrap();
    }
    home
}

fn tick() {
    std::thread::sleep(std::time::Duration::from_millis(3));
}

/// Alice makes a team vault and adds Bob (edit) and Victor (view).
struct Team {
    alice: UserKeyset,
    bob: UserKeyset,
    victor: UserKeyset,
    vault: Arc<Vault>,
}

fn team() -> Team {
    let alice = keys("acc_alice");
    let bob = keys("acc_bob");
    let victor = keys("acc_victor");
    let vault = Vault::create_shared(
        &alice,
        SharedKind::Org,
        Some("org_acme".into()),
        "alice-laptop",
    )
    .unwrap();
    vault
        .change_members_unchecked(vec![
            MemberChange::Add {
                keys: bob.public_keys(),
                role: MemberRole::Edit,
                group: None,
            },
            MemberChange::Add {
                keys: victor.public_keys(),
                role: MemberRole::View,
                group: Some("grp_support".into()),
            },
        ])
        .unwrap();
    vault.upsert(login("Router", "router-pass-1")).unwrap();
    Team {
        alice,
        bob,
        victor,
        vault,
    }
}

fn is_err_text(r: Result<impl std::fmt::Debug>, key: &str) -> bool {
    match r {
        Err(e) => {
            let text = match &e {
                PassError::Crypto(t)
                | PassError::Conflict(t)
                | PassError::InvalidInput(t)
                | PassError::NotFound(t)
                | PassError::Corrupt(t) => t.clone(),
                other => format!("{other:?}"),
            };
            crate::i18n::core_message_is(text, key.to_string())
        }
        Ok(v) => panic!("expected {key}, got {v:?}"),
    }
}

#[test]
fn a_member_opens_the_vault_with_their_keys_and_edits_merge_back() {
    let t = team();
    let file = bytes(&t.vault);
    let parsed = parse_file(&file).unwrap();
    assert!(parsed.is_shared());
    assert_eq!(parsed.version, VERSION_SHARED);

    let bob = Vault::open_shared(&file, &t.bob, None, "bob-phone").unwrap();
    assert_eq!(titles(&bob), ["Router"]);
    let info = bob.shared_info().unwrap();
    assert_eq!(info.role, MemberRole::Edit);
    assert_eq!(info.kind, SharedKind::Org);
    assert_eq!(info.org.as_deref(), Some("org_acme"));
    assert_eq!(info.epoch, 2);
    assert_eq!(info.key_epoch, 1);
    assert!(info.anchored);
    let victor_info = info
        .members
        .iter()
        .find(|m| m.account == "acc_victor")
        .unwrap();
    assert_eq!(victor_info.group.as_deref(), Some("grp_support"));
    assert_eq!(victor_info.fingerprint, t.victor.fingerprint());
    assert!(bob.can_edit() && bob.can_reveal_secrets());

    bob.upsert(login("Printer", "printer-pass")).unwrap();
    t.vault.merge_remote(bytes(&bob)).unwrap();
    assert_eq!(titles(&t.vault), ["Printer", "Router"]);
}

#[test]
fn a_direct_share_is_flagged_as_such() {
    let alice = keys("acc_alice");
    let bob = keys("acc_bob");
    let v = Vault::create_shared(&alice, SharedKind::Direct, None, "alice-laptop").unwrap();
    v.add_member_unchecked(bob.public_keys(), MemberRole::Edit, None)
        .unwrap();
    let opened = Vault::open_shared(&bytes(&v), &bob, None, "bob-phone").unwrap();
    let info = opened.shared_info().unwrap();
    assert_eq!(info.kind, SharedKind::Direct);
    let others: Vec<&str> = info.others().map(|m| m.account.as_str()).collect();
    assert_eq!(others, ["acc_alice"]);
}

#[test]
fn passwords_device_keys_and_recovery_codes_never_open_a_shared_vault() {
    let t = team();
    let file = bytes(&t.vault);
    assert!(is_err_text(
        Vault::unlock(file.clone(), "router-pass-1".into(), "d".into()),
        "share.needs_keys"
    ));
    assert!(is_err_text(
        Vault::unlock_with_key(file.clone(), t.vault.export_vault_key(), "d".into()),
        "share.needs_keys"
    ));
    let (_, code) = crate::recovery::generate();
    assert!(is_err_text(
        Vault::unlock_with_recovery_code(file, code.to_string(), "d".into()),
        "share.needs_keys"
    ));
    assert!(is_err_text(
        t.vault.change_master_password("x".into()),
        "share.no_password"
    ));
    assert!(is_err_text(
        t.vault.create_recovery_code(),
        "share.no_password"
    ));
}

/// The reader of clients without sharing: the v1 `VaultFile` (the fields it requires) and its
/// version check.
#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct ReleasedV1File {
    format: String,
    version: u32,
    vault_id: String,
    header_updated_at: i64,
    kdf: KdfParams,
    wrapped_key: Sealed,
    key_check: Sealed,
    items: Vec<RecordFile>,
}

fn released_parse(file: &[u8]) -> std::result::Result<ReleasedV1File, &'static str> {
    let parsed: ReleasedV1File = serde_json::from_slice(file).map_err(|_| "vault.not_a_vault")?;
    if parsed.format != FORMAT {
        return Err("vault.not_a_vault");
    }
    if parsed.version != VERSION {
        return Err("vault.unsupported_version");
    }
    Ok(parsed)
}

#[test]
fn clients_that_predate_sharing_say_it_needs_a_newer_passyble() {
    let t = team();
    let file = bytes(&t.vault);
    // An older client reads it far enough to see the version, so it says "made by a newer version
    // of Passyble" instead of "not a Passyble vault".
    assert_eq!(
        released_parse(&file).err(),
        Some("vault.unsupported_version")
    );
    // And this reader reports a later version the same way, whatever else that version changed.
    let later = serde_json::json!({ "format": "pass-vault", "version": 4, "vault_id": "x" });
    assert!(is_err_text(
        parse_file(&to_bytes(&later)),
        "vault.unsupported_version"
    ));
    // Older clients say the same of a vault linked to a Passyble account (version 3).
    let linked = Vault::create_with_kdf("pw", "d", fast_kdf()).unwrap();
    linked
        .link_to_account(&crate::AccountKey::generate("acc_x".into()).unwrap())
        .unwrap();
    assert_eq!(
        released_parse(&linked.serialize().unwrap()).err(),
        Some("vault.unsupported_version")
    );
    // A shared vault's file without its members block is no vault.
    let mut broken = json(&t.vault);
    broken.as_object_mut().unwrap().remove("members");
    assert!(is_err_text(
        parse_file(&to_bytes(&broken)),
        "vault.not_a_vault"
    ));
}

#[test]
fn the_host_cannot_swap_a_members_public_key() {
    let t = team();
    let mallory = keys("acc_mallory");
    let mut doctored = json(&t.vault);
    // Bob's entry gets Mallory's keys, so the next rotation would wrap the key for her.
    let entries = doctored["members"]["entries"].as_array_mut().unwrap();
    let bob = entries
        .iter_mut()
        .find(|e| e["account"] == "acc_bob")
        .unwrap();
    bob["enc_pub"] = Value::String(mallory.public_keys().enc_pub);
    bob["sig_pub"] = Value::String(mallory.public_keys().sig_pub);
    let plain = to_bytes(&doctored);
    // Recomputing the entries digest doesn't help: the manager's signature covers it.
    let mut redigested = doctored.clone();
    let m = members_of(&redigested);
    redigested["members"]["cert"]["entries_digest"] =
        Value::String(entries_digest(&m.entries).unwrap());
    let redigested = to_bytes(&redigested);

    for file in [&plain, &redigested] {
        assert!(is_err_text(
            Vault::open_shared(file, &t.bob, None, "bob"),
            "share.members_invalid"
        ));
        assert!(is_err_text(
            Vault::open_shared(file, &mallory, None, "mallory"),
            "share.members_invalid"
        ));
        // Merged into Alice's copy, the list is not adopted.
        let before = t.vault.shared_info().unwrap();
        t.vault.merge_remote(file.clone()).unwrap();
        assert_eq!(t.vault.shared_info().unwrap(), before);
    }
    // Alice's next rotation still wraps the key for Bob's real keys.
    t.vault.remove_member("acc_victor").unwrap();
    let rotated = bytes(&t.vault);
    assert!(Vault::open_shared(&rotated, &t.bob, None, "bob").is_ok());
    assert!(is_err_text(
        Vault::open_shared(&rotated, &mallory, None, "m"),
        "share.not_a_member"
    ));
}

#[test]
fn an_older_members_list_is_not_accepted_again() {
    let t = team();
    let old = bytes(&t.vault);
    let bob = Vault::open_shared(&old, &t.bob, None, "bob").unwrap();
    let trust_old = bob.share_trust().unwrap();
    assert_eq!(trust_old.epoch(), 2);

    t.vault.remove_member("acc_victor").unwrap();
    let new = bytes(&t.vault);
    let bob_new = Vault::open_shared(&new, &t.bob, Some(&trust_old), "bob").unwrap();
    let trust = bob_new.share_trust().unwrap();
    assert_eq!((trust.epoch(), trust.key_epoch()), (3, 2));
    assert!(trust.ahead_of(&trust_old));

    // The host serves the old file again (Victor still in it, the old key): refused.
    assert!(is_err_text(
        Vault::open_shared(&old, &t.bob, Some(&trust), "bob"),
        "share.members_rollback"
    ));
    // Merged in, its list is ignored; its items are under the old key, which is an earlier key.
    bob_new.merge_remote(old).unwrap();
    assert_eq!(bob_new.shared_info().unwrap().epoch, 3);
    assert!(!bob_new
        .shared_info()
        .unwrap()
        .members
        .iter()
        .any(|m| m.account == "acc_victor"));
}

#[test]
fn a_removed_member_can_open_neither_the_new_file_nor_its_key() {
    let t = team();
    let before = bytes(&t.vault);
    let victor = Vault::open_shared(&before, &t.victor, None, "victor").unwrap();
    let old_vk = victor.export_vault_key();
    let old_entry = members_of(&json(&t.vault))
        .entries
        .into_iter()
        .find(|e| e.account == "acc_victor")
        .unwrap();

    let info = t.vault.remove_member("acc_victor").unwrap();
    assert_eq!(info.key_epoch, 2);
    t.vault.upsert(login("Payroll", "payroll-pass")).unwrap();
    let after = bytes(&t.vault);

    assert!(is_err_text(
        Vault::open_shared(&after, &t.victor, None, "victor"),
        "share.not_a_member"
    ));
    // The old key doesn't open the new file.
    let parsed = parse_file(&after).unwrap();
    assert!(check_key(&parsed, &key_from_vec(&old_vk).unwrap()).is_err());
    // The old wrapped key doesn't open for the new epoch either.
    assert!(unwrap_vault_key(&t.victor, &old_entry.wrapped_key, &parsed.vault_id, 2).is_none());
    // Victor's open copy can't follow the new list.
    assert!(is_err_text(
        victor.merge_remote(after.clone()),
        "share.removed"
    ));
    assert!(!titles(&victor).contains(&"Payroll".to_string()));
    // Bob still can.
    let bob = Vault::open_shared(&after, &t.bob, None, "bob").unwrap();
    assert_eq!(titles(&bob), ["Payroll", "Router"]);
}

/// A list signed by `signer` after `prev`, with `entries` (wrapped keys left as they are).
fn forge(
    vault_id: &str,
    genesis: &str,
    signer: &UserKeyset,
    prev: &MembersFile,
    entries: Vec<MemberFile>,
    vk: &Key,
) -> MembersFile {
    sign_members(
        vault_id,
        genesis,
        signer,
        Some(prev),
        entries,
        prev.cert.key_epoch,
        vk,
    )
    .unwrap()
}

#[test]
fn a_viewer_cannot_forge_a_members_list() {
    let t = team();
    let file = json(&t.vault);
    let vault_id = file["vault_id"].as_str().unwrap().to_string();
    let genesis: GenesisFile = serde_json::from_value(file["genesis"].clone()).unwrap();
    let gd = verify_genesis(&vault_id, &genesis).unwrap();
    let current = members_of(&file);
    let victor = Vault::open_shared(&to_bytes(&file), &t.victor, None, "victor").unwrap();
    let trust = victor.share_trust().unwrap();
    let vk = key_from_vec(&victor.export_vault_key()).unwrap();
    // Victor can't edit in the core either.
    assert!(is_err_text(
        victor.upsert(login("Mine", "x")),
        "share.read_only"
    ));
    assert!(is_err_text(
        victor.add_member_unchecked(keys("acc_eve").public_keys(), MemberRole::View, None),
        "share.not_manager"
    ));

    // Victor makes himself a manager and signs the list himself.
    let mut entries = current.entries.clone();
    for e in &mut entries {
        if e.account == "acc_victor" {
            e.role = "manage".into();
        }
    }
    let forged = forge(&vault_id, &gd, &t.victor, &current, entries, &vk);
    let mut doctored = file.clone();
    doctored["members"] = serde_json::to_value(&forged).unwrap();
    let doctored = to_bytes(&doctored);
    assert!(is_err_text(
        Vault::open_shared(&doctored, &t.bob, None, "bob"),
        "share.members_invalid"
    ));
    assert!(is_err_text(
        Vault::open_shared(&doctored, &t.bob, Some(&trust), "bob"),
        "share.members_invalid"
    ));
    let before = t.vault.shared_info().unwrap();
    t.vault.merge_remote(doctored).unwrap();
    assert_eq!(t.vault.shared_info().unwrap(), before);

    // Or cuts the chain, so a first-time member can't trace the list back: refused too while
    // the vault is young enough for the whole chain to be in the file.
    let dan = keys("acc_dan");
    let mut entries = current.entries.clone();
    for e in &mut entries {
        if e.account == "acc_victor" {
            e.role = "manage".into();
        }
    }
    entries.push(MemberFile {
        account: "acc_dan".into(),
        role: "edit".into(),
        enc_pub: b64_encode(dan.enc_pub()),
        sig_pub: b64_encode(dan.sig_pub()),
        group: None,
        wrapped_key: wrap_vault_key(dan.enc_pub(), &vault_id, "acc_dan", 1, &vk).unwrap(),
        added_by: "acc_victor".into(),
        added_at: 1,
    });
    let mut cut = forge(&vault_id, &gd, &t.victor, &current, entries, &vk);
    cut.chain.clear();
    let mut doctored = file.clone();
    doctored["members"] = serde_json::to_value(&cut).unwrap();
    assert!(is_err_text(
        Vault::open_shared(&to_bytes(&doctored), &dan, None, "dan"),
        "share.members_invalid"
    ));
}

#[test]
fn entries_must_be_sorted_unique_and_match_the_certificate() {
    let t = team();
    let file = json(&t.vault);
    let mut dup = file.clone();
    let first = dup["members"]["entries"][0].clone();
    dup["members"]["entries"]
        .as_array_mut()
        .unwrap()
        .push(first);
    assert!(is_err_text(
        Vault::open_shared(&to_bytes(&dup), &t.bob, None, "b"),
        "share.members_invalid"
    ));
    let mut role = file.clone();
    let entries = role["members"]["entries"].as_array_mut().unwrap();
    let victor = entries
        .iter_mut()
        .find(|e| e["account"] == "acc_victor")
        .unwrap();
    victor["role"] = Value::String("manage".into());
    assert!(is_err_text(
        Vault::open_shared(&to_bytes(&role), &t.bob, None, "b"),
        "share.members_invalid"
    ));
}

#[test]
fn the_wrapped_key_is_bound_to_its_vault() {
    // Alice manages two vaults with Bob. Even a list she signs herself, with Bob's wrapped key
    // copied from the other vault, doesn't give Bob a key: the HPKE info names the vault.
    let alice = keys("acc_alice");
    let bob = keys("acc_bob");
    let a = Vault::create_shared(&alice, SharedKind::Org, None, "alice").unwrap();
    let b = Vault::create_shared(&alice, SharedKind::Org, None, "alice").unwrap();
    a.add_member_unchecked(bob.public_keys(), MemberRole::Edit, None)
        .unwrap();
    b.add_member_unchecked(bob.public_keys(), MemberRole::Edit, None)
        .unwrap();
    let fa = json(&a);
    let mut fb = json(&b);
    let bob_in_a = members_of(&fa)
        .entry("acc_bob")
        .unwrap()
        .wrapped_key
        .clone();
    let vault_id = fb["vault_id"].as_str().unwrap().to_string();
    let genesis: GenesisFile = serde_json::from_value(fb["genesis"].clone()).unwrap();
    let gd = verify_genesis(&vault_id, &genesis).unwrap();
    let current = members_of(&fb);
    let mut entries = current.entries.clone();
    for e in &mut entries {
        if e.account == "acc_bob" {
            e.wrapped_key = bob_in_a.clone();
        }
    }
    let vk = key_from_vec(&b.export_vault_key()).unwrap();
    let swapped = forge(&vault_id, &gd, &alice, &current, entries, &vk);
    fb["members"] = serde_json::to_value(&swapped).unwrap();
    assert!(is_err_text(
        Vault::open_shared(&to_bytes(&fb), &bob, None, "bob"),
        "share.members_invalid"
    ));
    // A wrapped key that is garbage altogether fails the same way.
    let garbage = WrappedKey {
        enc: b64_encode(&[7u8; 32]),
        ct: b64_encode(&[9u8; 48]),
    };
    assert!(unwrap_vault_key(&bob, &garbage, &vault_id, 1).is_none());
}

#[test]
fn another_genesis_under_the_same_id_is_refused() {
    let t = team();
    let bob = Vault::open_shared(&bytes(&t.vault), &t.bob, None, "bob").unwrap();
    let trust = bob.share_trust().unwrap();
    // A vault made by Mallory, given the team vault's id.
    let mallory = keys("acc_mallory");
    let fake = Vault::create_shared(&mallory, SharedKind::Org, None, "m").unwrap();
    fake.add_member_unchecked(t.bob.public_keys(), MemberRole::Edit, None)
        .unwrap();
    let mut file = json(&fake);
    let real_id = json(&t.vault)["vault_id"].clone();
    file["vault_id"] = real_id;
    // Re-signing under the new id is what she would have to do; without it the genesis fails.
    assert!(Vault::open_shared(&to_bytes(&file), &t.bob, Some(&trust), "bob").is_err());
    // Merged into Bob's copy: refused.
    assert!(bob.merge_remote(to_bytes(&file)).is_err());
}

#[test]
fn two_managers_changing_members_at_once_converge() {
    let t = team();
    let carol = keys("acc_carol");
    t.vault
        .add_member_unchecked(carol.public_keys(), MemberRole::Manage, None)
        .unwrap();
    let base = bytes(&t.vault);
    let alice = Vault::open_shared(&base, &t.alice, None, "alice").unwrap();
    let carol_v = Vault::open_shared(&base, &carol, None, "carol").unwrap();
    let dan = keys("acc_dan");
    tick();
    alice
        .add_member_unchecked(dan.public_keys(), MemberRole::Edit, None)
        .unwrap();
    carol_v
        .set_member_role("acc_bob", MemberRole::View)
        .unwrap();
    let a_info = alice.shared_info().unwrap();
    let c_info = carol_v.shared_info().unwrap();
    assert_eq!(a_info.epoch, c_info.epoch);

    // One list wins; the losing manager's device applies its change again on top (no one has to
    // do it by hand), and one more round of syncs spreads that.
    alice.merge_remote(bytes(&carol_v)).unwrap();
    carol_v.merge_remote(bytes(&alice)).unwrap();
    alice.merge_remote(bytes(&carol_v)).unwrap();
    let a = alice.shared_info().unwrap();
    let c = carol_v.shared_info().unwrap();
    assert_eq!(a.members, c.members, "both copies settle on the same list");
    assert_eq!(a.epoch, c.epoch);
    assert!(a.members.iter().any(|m| m.account == "acc_dan"));
    assert!(a
        .members
        .iter()
        .any(|m| m.account == "acc_bob" && m.role == MemberRole::View));
    let reapplied = alice
        .take_members_notice()
        .into_iter()
        .chain(carol_v.take_members_notice())
        .map(|n| n.reapplied.len())
        .sum::<usize>();
    assert_eq!(
        reapplied, 1,
        "exactly one of the two changes lost and came back"
    );
    // Dan, added by whichever won, opens the merged file.
    assert!(Vault::open_shared(&bytes(&alice), &dan, None, "dan").is_ok());
}

#[test]
fn a_removal_wins_over_a_concurrent_change_and_no_item_is_lost() {
    let t = team();
    let carol = keys("acc_carol");
    t.vault
        .add_member_unchecked(carol.public_keys(), MemberRole::Manage, None)
        .unwrap();
    let base = bytes(&t.vault);
    let alice = Vault::open_shared(&base, &t.alice, None, "alice").unwrap();
    let carol_v = Vault::open_shared(&base, &carol, None, "carol").unwrap();
    let dan = keys("acc_dan");
    tick();
    // Alice removes Victor (a new key); Carol adds Dan (same key) and saves an item meanwhile.
    alice.remove_member("acc_victor").unwrap();
    alice.upsert(login("Alarm", "alarm-pass")).unwrap();
    carol_v
        .add_member_unchecked(dan.public_keys(), MemberRole::Edit, None)
        .unwrap();
    carol_v.upsert(login("Wifi", "wifi-pass")).unwrap();

    carol_v.merge_remote(bytes(&alice)).unwrap();
    alice.merge_remote(bytes(&carol_v)).unwrap();
    let a = alice.shared_info().unwrap();
    assert_eq!(a.key_epoch, 2);
    assert_eq!(a.members, carol_v.shared_info().unwrap().members);
    assert!(!a.members.iter().any(|m| m.account == "acc_victor"));
    assert_eq!(titles(&alice), ["Alarm", "Router", "Wifi"]);
    assert_eq!(titles(&carol_v), ["Alarm", "Router", "Wifi"]);
    let merged = bytes(&carol_v);
    assert!(is_err_text(
        Vault::open_shared(&merged, &t.victor, None, "v"),
        "share.not_a_member"
    ));
    assert!(Vault::open_shared(&merged, &t.bob, None, "bob").is_ok());
}

#[test]
fn two_concurrent_removals_keep_both_keys_and_every_item() {
    let t = team();
    let carol = keys("acc_carol");
    let erin = keys("acc_erin");
    t.vault
        .change_members_unchecked(vec![
            MemberChange::Add {
                keys: carol.public_keys(),
                role: MemberRole::Manage,
                group: None,
            },
            MemberChange::Add {
                keys: erin.public_keys(),
                role: MemberRole::Edit,
                group: None,
            },
        ])
        .unwrap();
    let base = bytes(&t.vault);
    let alice = Vault::open_shared(&base, &t.alice, None, "alice").unwrap();
    let carol_v = Vault::open_shared(&base, &carol, None, "carol").unwrap();
    tick();
    alice.remove_member("acc_victor").unwrap();
    alice.upsert(login("Alarm", "alarm-pass")).unwrap();
    carol_v.remove_member("acc_erin").unwrap();
    carol_v.upsert(login("Wifi", "wifi-pass")).unwrap();

    alice.merge_remote(bytes(&carol_v)).unwrap();
    carol_v.merge_remote(bytes(&alice)).unwrap();
    alice.merge_remote(bytes(&carol_v)).unwrap();
    assert_eq!(
        alice.shared_info().unwrap().members,
        carol_v.shared_info().unwrap().members
    );
    assert_eq!(alice.export_vault_key(), carol_v.export_vault_key());
    assert_eq!(titles(&alice), ["Alarm", "Router", "Wifi"]);
    assert_eq!(titles(&carol_v), ["Alarm", "Router", "Wifi"]);
}

#[test]
fn a_member_follows_a_key_rotation_without_losing_unsynced_edits() {
    let t = team();
    let bob = Vault::open_shared(&bytes(&t.vault), &t.bob, None, "bob").unwrap();
    bob.upsert(login("Offline", "offline-pass")).unwrap();
    let bob_unsynced = bytes(&bob);

    t.vault.remove_member("acc_victor").unwrap();
    let rotated = bytes(&t.vault);
    // Bob's open vault adopts the new key from the new list.
    bob.merge_remote(rotated).unwrap();
    assert_eq!(bob.shared_info().unwrap().key_epoch, 2);
    assert_eq!(bob.export_vault_key(), t.vault.export_vault_key());
    assert_eq!(titles(&bob), ["Offline", "Router"]);
    // Alice merges Bob's upload; and his copy from before the rotation still merges.
    t.vault.merge_remote(bytes(&bob)).unwrap();
    t.vault.merge_remote(bob_unsynced).unwrap();
    assert_eq!(titles(&t.vault), ["Offline", "Router"]);
}

#[test]
fn view_and_fill_roles_limit_what_the_core_does() {
    let t = team();
    let fiona = keys("acc_fiona");
    t.vault
        .add_member_unchecked(fiona.public_keys(), MemberRole::Fill, None)
        .unwrap();
    let file = bytes(&t.vault);
    let fill = Vault::open_shared(&file, &fiona, None, "fiona").unwrap();
    let view = Vault::open_shared(&file, &t.victor, None, "victor").unwrap();
    let home = Vault::create_with_kdf("demo master", "fiona", fast_kdf()).unwrap();

    assert!(!fill.can_reveal_secrets() && !fill.can_edit());
    assert!(view.can_reveal_secrets() && !view.can_edit());
    // Fill-only: logins are there to fill, but the core won't copy or export them.
    let id = fill.items()[0].id.clone();
    assert!(is_err_text(
        fill.copy_item_to(&id, &home),
        "share.fill_only"
    ));
    assert!(crate::export::export_json(fill.clone()).contains("\"items\": []"));
    assert!(is_err_text(
        crate::export::export_encrypted_json(fill.clone(), "x".into()),
        "share.fill_only"
    ));
    // View: may copy into an own vault, may not move out or change anything.
    assert!(view.copy_item_to(&id, &home).is_ok());
    assert!(is_err_text(
        view.move_item_to(&id, &home),
        "share.read_only"
    ));
    assert!(is_err_text(view.delete(id.clone()), "share.read_only"));
    assert_eq!(view.empty_trash(), 0);
    // And nobody but a manager changes the list.
    let bob = Vault::open_shared(&file, &t.bob, None, "bob").unwrap();
    assert!(is_err_text(
        bob.remove_member("acc_victor"),
        "share.not_manager"
    ));
}

#[test]
fn items_move_and_copy_between_personal_and_shared_vaults() {
    let t = team();
    let home = Vault::create_with_kdf("demo master", "alice", fast_kdf()).unwrap();
    let mut item = login("Bank", "bank-pass-1");
    item.notes = "branch 12".into();
    let item = home.upsert(item).unwrap();
    let mut changed = item.clone();
    changed.password = "bank-pass-2".into();
    home.upsert(changed).unwrap();
    home.add_passkey(
        Some(item.id.clone()),
        crate::Passkey {
            credential_id: vec![1, 2, 3],
            rp_id: "bank.example".into(),
            user_handle: vec![4],
            user_name: "kim".into(),
            private_key_pkcs8: vec![5, 6],
            ..Default::default()
        },
        None,
    )
    .unwrap();
    let original = home.get(item.id.clone()).unwrap();

    // Copy: a new item in the shared vault with the history and passkeys; the original stays.
    let copied = home.copy_item_to(&item.id, &t.vault).unwrap();
    assert_ne!(copied.id, item.id);
    assert_eq!(copied.password, "bank-pass-2");
    assert_eq!(copied.password_history, original.password_history);
    assert_eq!(copied.passkeys, original.passkeys);
    assert_eq!(copied.created_at, original.created_at);
    assert_eq!(copied.notes, "branch 12");
    assert!(home.get(item.id.clone()).is_some());

    // Move back out of the shared vault: the shared copy is deleted for good (it syncs).
    let moved = t.vault.move_item_to(&copied.id, &home).unwrap();
    assert!(t.vault.get(copied.id.clone()).is_none());
    assert!(t.vault.trashed_items().iter().all(|i| i.id != copied.id));
    assert_eq!(moved.passkeys, original.passkeys);
    assert_eq!(home.items().len(), 2);
    // Not into the same vault.
    assert!(is_err_text(
        home.copy_item_to(&moved.id, &home),
        "share.same_vault"
    ));
}

#[test]
fn the_keyset_and_trust_live_in_the_home_vault() {
    let home = Vault::create_with_kdf("demo master", "bob-phone", fast_kdf()).unwrap();
    assert!(home.user_keyset("acc_bob").unwrap().is_none());
    let bob = home.ensure_user_keyset("acc_bob").unwrap();
    assert_eq!(
        home.ensure_user_keyset("acc_bob").unwrap().public_keys(),
        bob.public_keys()
    );
    // It survives a save and an unlock with the master password, and is no item.
    let reopened = Vault::unlock(bytes(&home), "demo master".into(), "bob-phone".into()).unwrap();
    assert_eq!(
        reopened
            .user_keyset("acc_bob")
            .unwrap()
            .unwrap()
            .public_keys(),
        bob.public_keys()
    );
    assert!(reopened.items().is_empty());
    // The private keys are not in the file in the clear.
    let file = String::from_utf8(bytes(&reopened)).unwrap();
    assert!(!file.contains(&bob.to_stored().to_string()));

    // Opening through the home vault remembers the list, and the newer list replaces it.
    let alice = keys("acc_alice");
    let shared = Vault::create_shared(&alice, SharedKind::Org, None, "alice").unwrap();
    shared
        .add_member_unchecked(bob.public_keys(), MemberRole::Edit, None)
        .unwrap();
    let old = bytes(&shared);
    let opened =
        Vault::open_shared_with_home(old.clone(), &reopened, "acc_bob", "bob-phone").unwrap();
    let vault_id = opened.vault_id();
    assert_eq!(reopened.stored_share_trust(&vault_id).unwrap().epoch(), 2);
    shared
        .add_member_unchecked(keys("acc_dan").public_keys(), MemberRole::View, None)
        .unwrap();
    Vault::open_shared_with_home(bytes(&shared), &reopened, "acc_bob", "bob-phone").unwrap();
    assert_eq!(reopened.stored_share_trust(&vault_id).unwrap().epoch(), 3);
    // An older trust record doesn't replace a newer one; the old file is now a rollback.
    assert!(!reopened
        .remember_share_trust(&opened.share_trust().unwrap())
        .unwrap());
    assert!(is_err_text(
        Vault::open_shared_with_home(old.clone(), &reopened, "acc_bob", "bob-phone"),
        "share.members_rollback"
    ));
    // Keys never go into a shared vault.
    assert!(is_err_text(
        opened.store_user_keyset(&bob),
        "share.keys_in_shared"
    ));
}

#[test]
fn a_group_syncs_its_members_and_leaves_direct_members_alone() {
    let t = team();
    let dan = keys("acc_dan");
    let erin = keys("acc_erin");
    let home = home_pinning(&t.alice, &[&dan, &erin, &t.bob]);
    let info = t
        .vault
        .sync_group(
            "grp_eng",
            vec![
                GroupMember {
                    keys: dan.public_keys(),
                    role: MemberRole::Edit,
                },
                GroupMember {
                    keys: erin.public_keys(),
                    role: MemberRole::View,
                },
                // Bob is a direct member already: left as he is.
                GroupMember {
                    keys: t.bob.public_keys(),
                    role: MemberRole::View,
                },
            ],
            &home,
        )
        .unwrap()
        .unwrap();
    let group_of = |info: &SharedInfo, a: &str| {
        info.members
            .iter()
            .find(|m| m.account == a)
            .map(|m| (m.role, m.group.clone()))
    };
    assert_eq!(
        group_of(&info, "acc_dan"),
        Some((MemberRole::Edit, Some("grp_eng".into())))
    );
    assert_eq!(group_of(&info, "acc_bob"), Some((MemberRole::Edit, None)));
    assert_eq!(info.key_epoch, 1);
    // Nothing to do the second time.
    assert!(t
        .vault
        .sync_group(
            "grp_eng",
            vec![
                GroupMember {
                    keys: dan.public_keys(),
                    role: MemberRole::Edit
                },
                GroupMember {
                    keys: erin.public_keys(),
                    role: MemberRole::View
                }
            ],
            &home
        )
        .unwrap()
        .is_none());
    // Erin leaves the group: removed, with a new key. Victor's group isn't touched.
    let info = t
        .vault
        .sync_group(
            "grp_eng",
            vec![GroupMember {
                keys: dan.public_keys(),
                role: MemberRole::Manage,
            }],
            &home,
        )
        .unwrap()
        .unwrap();
    assert_eq!(group_of(&info, "acc_erin"), None);
    assert_eq!(
        group_of(&info, "acc_dan"),
        Some((MemberRole::Manage, Some("grp_eng".into())))
    );
    assert_eq!(
        group_of(&info, "acc_victor"),
        Some((MemberRole::View, Some("grp_support".into())))
    );
    assert_eq!(info.key_epoch, 2);
}

#[test]
fn member_changes_keep_a_manager_and_refuse_self_removal() {
    let t = team();
    // Alice is the only manager: she can't leave (or be removed) until another one is there.
    assert!(is_err_text(
        t.vault.remove_member("acc_alice"),
        "share.last_manager"
    ));
    assert!(is_err_text(t.vault.leave_shared(), "share.last_manager"));
    assert!(is_err_text(
        t.vault.set_member_role("acc_alice", MemberRole::Edit),
        "share.last_manager"
    ));
    assert!(is_err_text(
        t.vault
            .add_member_unchecked(t.bob.public_keys(), MemberRole::View, None),
        "share.member_exists"
    ));
    assert!(is_err_text(
        t.vault.remove_member("acc_nobody"),
        "share.no_member"
    ));
    let mut bad = keys("acc_eve").public_keys();
    bad.account = "acc_mallory".into();
    assert!(is_err_text(
        t.vault.add_member_unchecked(bad, MemberRole::View, None),
        "share.bad_keys"
    ));
    // A member with new keys (a lost home vault) gets the key again under a new key epoch.
    let bob2 = keys("acc_bob");
    let info = t
        .vault
        .change_members_unchecked(vec![MemberChange::ReplaceKeys {
            keys: bob2.public_keys(),
        }])
        .unwrap();
    assert_eq!(info.key_epoch, 2);
    let file = bytes(&t.vault);
    assert!(Vault::open_shared(&file, &bob2, None, "bob").is_ok());
    assert!(is_err_text(
        Vault::open_shared(&file, &t.bob, None, "bob"),
        "share.keys_mismatch"
    ));
}

#[test]
fn a_list_from_beyond_the_remembered_chain_is_not_trusted_blindly() {
    let t = team();
    let bob = Vault::open_shared(&bytes(&t.vault), &t.bob, None, "bob").unwrap();
    let trust = bob.share_trust().unwrap();
    // More changes than the file keeps certificates of.
    for i in 0..(crate::share::members::MAX_CHAIN + 2) {
        let role = if i % 2 == 0 {
            MemberRole::Edit
        } else {
            MemberRole::View
        };
        t.vault.set_member_role("acc_victor", role).unwrap();
    }
    let file = bytes(&t.vault);
    assert!(is_err_text(
        Vault::open_shared(&file, &t.bob, Some(&trust), "bob"),
        "share.members_unverified"
    ));
    // A first open takes it on first use, and says so, with the signer's fingerprint to compare.
    let fresh = Vault::open_shared(&file, &t.bob, None, "bob").unwrap();
    let info = fresh.shared_info().unwrap();
    assert!(!info.anchored);
    assert_eq!(info.signed_by, "acc_alice");
    assert_eq!(info.signer_fingerprint, Some(t.alice.fingerprint()));
    // With the remembered chain up to date it verifies again.
    let mut recent = Vault::open_shared(&file, &t.bob, None, "bob")
        .unwrap()
        .share_trust()
        .unwrap();
    recent.path.drain(..recent.path.len() - 1);
    t.vault
        .set_member_role("acc_victor", MemberRole::Edit)
        .unwrap();
    let next = Vault::open_shared(&bytes(&t.vault), &t.bob, Some(&recent), "bob").unwrap();
    assert!(next.shared_info().unwrap().anchored);
}

#[test]
fn sync_notices_a_new_members_list() {
    let t = team();
    let base = parse_file(&bytes(&t.vault)).unwrap();
    let fp = base.fingerprint();
    assert_eq!(fp, t.vault.lock().fingerprint());
    t.vault
        .set_member_role("acc_victor", MemberRole::Edit)
        .unwrap();
    assert_ne!(t.vault.lock().fingerprint(), fp);
    #[cfg(feature = "sync-core")]
    assert!(t.vault.remote_is_behind(&base));
}

/// Random member changes and item edits by two managers and an editor, merged in random order:
/// every copy ends with the same members list, the same key and the same items.
#[test]
fn members_and_items_converge_for_random_histories() {
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }
    let pool: Vec<UserKeyset> = (0..4).map(|i| keys(&format!("acc_extra{i}"))).collect();
    for seed in 1..=12u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let alice = keys("acc_alice");
        let carol = keys("acc_carol");
        let bob = keys("acc_bob");
        let origin = Vault::create_shared(&alice, SharedKind::Org, None, "origin").unwrap();
        origin
            .change_members_unchecked(vec![
                MemberChange::Add {
                    keys: carol.public_keys(),
                    role: MemberRole::Manage,
                    group: None,
                },
                MemberChange::Add {
                    keys: bob.public_keys(),
                    role: MemberRole::Edit,
                    group: None,
                },
            ])
            .unwrap();
        let base = bytes(&origin);
        let devices = [
            Vault::open_shared(&base, &alice, None, "a").unwrap(),
            Vault::open_shared(&base, &carol, None, "c").unwrap(),
            Vault::open_shared(&base, &bob, None, "b").unwrap(),
        ];
        let mut n = 0;
        for _ in 0..14 {
            let d = rng.below(3);
            let v = &devices[d];
            match rng.below(4) {
                0 | 1 => {
                    n += 1;
                    v.upsert(login(&format!("Item{seed}x{n}"), "p")).unwrap();
                }
                2 if d < 2 => {
                    let k = &pool[rng.below(pool.len())];
                    let present = v
                        .shared_info()
                        .unwrap()
                        .members
                        .iter()
                        .any(|m| m.account == k.account());
                    if present {
                        v.remove_member(k.account()).unwrap();
                    } else {
                        v.add_member_unchecked(k.public_keys(), MemberRole::View, None)
                            .unwrap();
                    }
                }
                _ => {
                    let (from, to) = (rng.below(3), rng.below(3));
                    if from != to {
                        devices[to].merge_remote(bytes(&devices[from])).unwrap();
                    }
                }
            }
            tick();
        }
        // Full sync, a few times round: a change that lost is applied again by its manager's
        // device, which the next round spreads.
        for _ in 0..4 {
            for from in 0..3 {
                for to in 0..3 {
                    if from != to {
                        devices[to].merge_remote(bytes(&devices[from])).unwrap();
                    }
                }
            }
        }
        let first = devices[0].shared_info().unwrap();
        for v in &devices[1..] {
            let info = v.shared_info().unwrap();
            assert_eq!(info.members, first.members, "seed {seed}: members converge");
            assert_eq!(
                (info.epoch, info.key_epoch),
                (first.epoch, first.key_epoch),
                "seed {seed}"
            );
            assert_eq!(
                v.export_vault_key(),
                devices[0].export_vault_key(),
                "seed {seed}: key"
            );
            assert_eq!(
                titles(v),
                titles(&devices[0]),
                "seed {seed}: items converge"
            );
        }
        assert_eq!(titles(&devices[0]).len(), n, "seed {seed}: no item lost");
    }
}

/// Alice and Carol manage; each opens the same file.
fn two_managers() -> (Team, UserKeyset, Arc<Vault>, Arc<Vault>) {
    let t = team();
    let carol = keys("acc_carol");
    t.vault
        .add_member_unchecked(carol.public_keys(), MemberRole::Manage, None)
        .unwrap();
    let base = bytes(&t.vault);
    let alice = Vault::open_shared(&base, &t.alice, None, "alice").unwrap();
    let carol_v = Vault::open_shared(&base, &carol, None, "carol").unwrap();
    tick();
    (t, carol, alice, carol_v)
}

#[test]
fn the_signer_and_their_fingerprint_are_shown() {
    let t = team();
    let bob = Vault::open_shared(&bytes(&t.vault), &t.bob, None, "bob").unwrap();
    let info = bob.shared_info().unwrap();
    assert_eq!(info.signed_by, "acc_alice");
    assert_eq!(info.signer_fingerprint, Some(t.alice.fingerprint()));
}

#[test]
fn a_lost_member_change_is_applied_again_and_reported() {
    let (t, carol, alice, carol_v) = two_managers();
    let dan = keys("acc_dan");
    // Alice adds Dan; Carol removes Victor at the same time (a new key, so Carol's list wins).
    alice
        .add_member_unchecked(dan.public_keys(), MemberRole::Edit, None)
        .unwrap();
    carol_v.remove_member("acc_victor").unwrap();
    assert!(alice.take_members_notice().is_none());

    alice.merge_remote(bytes(&carol_v)).unwrap();
    let info = alice.shared_info().unwrap();
    assert!(info.members.iter().any(|m| m.account == "acc_dan"));
    assert!(!info.members.iter().any(|m| m.account == "acc_victor"));
    assert_eq!(
        info.signed_by, "acc_alice",
        "re-signed on top of Carol's list"
    );
    let notice = alice.take_members_notice().unwrap();
    assert_eq!(notice.reapplied.len(), 1);
    assert!(matches!(
        &notice.reapplied[0],
        MemberChange::Add { keys, .. } if keys.account == "acc_dan"
    ));
    assert!(notice.dropped.is_empty());
    assert!(alice.take_members_notice().is_none(), "taken once");

    // Carol takes Alice's list (hers is in its chain: nothing of hers to apply again).
    carol_v.merge_remote(bytes(&alice)).unwrap();
    assert!(carol_v.take_members_notice().is_none());
    assert_eq!(
        carol_v.shared_info().unwrap().members,
        alice.shared_info().unwrap().members
    );
    assert_eq!(carol_v.export_vault_key(), alice.export_vault_key());
    let merged = bytes(&carol_v);
    assert!(Vault::open_shared(&merged, &dan, None, "dan").is_ok());
    assert!(Vault::open_shared(&merged, &carol, None, "carol").is_ok());
    assert!(Vault::open_shared(&merged, &t.victor, None, "victor").is_err());
}

#[test]
fn a_lost_change_that_no_longer_makes_sense_is_dropped() {
    let (_t, _carol, alice, carol_v) = two_managers();
    // Alice changes Victor's role while Carol removes him.
    alice
        .set_member_role("acc_victor", MemberRole::Edit)
        .unwrap();
    carol_v.remove_member("acc_victor").unwrap();
    alice.merge_remote(bytes(&carol_v)).unwrap();
    let notice = alice.take_members_notice().unwrap();
    assert!(notice.reapplied.is_empty());
    assert!(matches!(
        &notice.dropped[..],
        [MemberChange::SetRole { account, .. }] if account == "acc_victor"
    ));
    assert!(!alice
        .shared_info()
        .unwrap()
        .members
        .iter()
        .any(|m| m.account == "acc_victor"));
}

#[test]
fn a_lost_change_is_dropped_when_its_manager_no_longer_manages() {
    let (_t, _carol, alice, carol_v) = two_managers();
    let dan = keys("acc_dan");
    alice
        .add_member_unchecked(dan.public_keys(), MemberRole::Edit, None)
        .unwrap();
    // Carol makes Alice an editor and removes Victor (a new key: Carol's list wins).
    carol_v
        .change_members_unchecked(vec![
            MemberChange::SetRole {
                account: "acc_alice".into(),
                role: MemberRole::Edit,
            },
            MemberChange::Remove {
                account: "acc_victor".into(),
            },
        ])
        .unwrap();
    alice.merge_remote(bytes(&carol_v)).unwrap();
    let info = alice.shared_info().unwrap();
    assert_eq!(info.role, MemberRole::Edit);
    assert!(!info.members.iter().any(|m| m.account == "acc_dan"));
    let notice = alice.take_members_notice().unwrap();
    assert!(notice.reapplied.is_empty());
    assert_eq!(notice.dropped.len(), 1);
    assert_eq!(
        info.members,
        carol_v.shared_info().unwrap().members,
        "nothing new was signed"
    );
}

#[test]
fn a_change_built_on_is_not_applied_twice() {
    let (_t, _carol, alice, carol_v) = two_managers();
    let dan = keys("acc_dan");
    alice
        .add_member_unchecked(dan.public_keys(), MemberRole::Edit, None)
        .unwrap();
    carol_v.merge_remote(bytes(&alice)).unwrap();
    carol_v
        .set_member_role("acc_bob", MemberRole::View)
        .unwrap();
    alice.merge_remote(bytes(&carol_v)).unwrap();
    assert!(alice.take_members_notice().is_none());
    assert_eq!(alice.shared_info().unwrap().signed_by, "acc_carol");
    assert_eq!(
        alice.shared_info().unwrap().members,
        carol_v.shared_info().unwrap().members
    );
}

#[test]
fn a_manager_can_leave_and_the_next_manager_replaces_the_key() {
    let (t, carol, alice, _carol_v) = two_managers();
    let before = alice.shared_info().unwrap().key_epoch;
    alice.leave_shared().unwrap();
    let info = alice.shared_info().unwrap();
    assert!(!info.members.iter().any(|m| m.account == "acc_alice"));
    assert_eq!(info.key_epoch, before + 1);
    assert_eq!(info.signer_fingerprint, None, "the signer left the list");
    assert!(!alice.can_edit());
    let left_key = alice.export_vault_key();
    let file = bytes(&alice);
    assert!(is_err_text(
        Vault::open_shared(&file, &t.alice, None, "alice"),
        "share.not_a_member"
    ));
    // Bob (an editor) opens the list Alice signed and changes nothing about it.
    let bob = Vault::open_shared(&file, &t.bob, None, "bob").unwrap();
    assert_eq!(bob.export_vault_key(), left_key);
    assert!(bob.take_members_notice().is_none());
    // Carol, a remaining manager, replaces the key Alice's device made, at once.
    let carol_v = Vault::open_shared(&file, &carol, None, "carol").unwrap();
    let notice = carol_v.take_members_notice().unwrap();
    assert!(notice.rotated_after_leave);
    let info = carol_v.shared_info().unwrap();
    assert_eq!(info.key_epoch, before + 2);
    assert_eq!(info.signer_fingerprint, Some(carol.fingerprint()));
    assert_ne!(carol_v.export_vault_key(), left_key);
    // Bob follows Carol's list; the item written with Alice's key is still there.
    bob.upsert(login("Printer", "printer-pass")).unwrap();
    carol_v.merge_remote(bytes(&bob)).unwrap();
    bob.merge_remote(bytes(&carol_v)).unwrap();
    assert_eq!(bob.export_vault_key(), carol_v.export_vault_key());
    assert_eq!(titles(&carol_v), ["Printer", "Router"]);
    // A merge (not just an open) also rotates after a leave.
    let (_t2, carol2, alice2, carol2_v) = two_managers();
    alice2.leave_shared().unwrap();
    carol2_v.merge_remote(bytes(&alice2)).unwrap();
    assert!(carol2_v.take_members_notice().unwrap().rotated_after_leave);
    assert_eq!(
        carol2_v.shared_info().unwrap().signer_fingerprint,
        Some(carol2.fingerprint())
    );
}

#[test]
fn a_lost_leave_is_applied_again() {
    let (_t, _carol, alice, carol_v) = two_managers();
    alice.leave_shared().unwrap();
    // Carol removes Victor at the same time; both lists rotate, one wins by its digest.
    carol_v.remove_member("acc_victor").unwrap();
    // Whichever won, after both merges Alice and Victor are out, and the key is one Alice's
    // device never had: Carol's device made it, applying her removal again or rotating after
    // Alice's leave.
    alice.merge_remote(bytes(&carol_v)).unwrap();
    carol_v.merge_remote(bytes(&alice)).unwrap();
    let info = carol_v.shared_info().unwrap();
    assert!(!info.members.iter().any(|m| m.account == "acc_alice"));
    assert!(!info.members.iter().any(|m| m.account == "acc_victor"));
    assert_ne!(carol_v.export_vault_key(), alice.export_vault_key());
    assert_eq!(info.signed_by, "acc_carol");
}

#[test]
fn one_home_vault_keeps_one_keyset_for_every_backends_account_id() {
    let home = Vault::create_with_kdf("demo master", "bob", fast_kdf()).unwrap();
    let cloud = home.publish_keys_for("acc_01JBOB").unwrap();
    let server = home.publish_keys_for("bob").unwrap();
    cloud.verify().unwrap();
    server.verify().unwrap();
    assert_eq!(cloud.fingerprint(), server.fingerprint(), "the same keys");
    assert_ne!(cloud.sig, server.sig);
    let mut moved = cloud.clone();
    moved.account = "bob".into();
    assert!(
        moved.verify().is_err(),
        "a signature for one id isn't one for the other"
    );
    // A server vault lists Bob as "bob"; the keyset under that id opens it.
    let alice = keys("alice");
    let vault = Vault::create_shared(&alice, SharedKind::Direct, None, "a").unwrap();
    vault.add_member_unchecked(server, MemberRole::Edit, None).unwrap();
    let opened = Vault::open_shared_with_home(bytes(&vault), &home, "bob", "bob-phone").unwrap();
    assert_eq!(opened.shared_info().unwrap().account, "bob");
    // Under the Cloud id it isn't a member of that server's vault.
    assert!(Vault::open_shared_with_home(bytes(&vault), &home, "acc_01JBOB", "b").is_err());
}

/// Alice's home vault keeps her keyset; she and Carol (both managers) open the same file.
fn two_managers_with_home() -> (Team, Arc<Vault>, Arc<Vault>, Arc<Vault>) {
    let t = team();
    let carol = keys("acc_carol");
    t.vault
        .add_member_unchecked(carol.public_keys(), MemberRole::Manage, None)
        .unwrap();
    let base = bytes(&t.vault);
    let home = Vault::create_with_kdf("demo master", "alice", fast_kdf()).unwrap();
    home.store_user_keyset(&t.alice).unwrap();
    let alice = Vault::open_shared_with_home(base.clone(), &home, "acc_alice", "alice").unwrap();
    let carol_v = Vault::open_shared(&base, &carol, None, "carol").unwrap();
    tick();
    (t, home, alice, carol_v)
}

#[test]
fn a_lost_member_change_is_applied_again_after_a_restart() {
    let (_t, home, alice, carol_v) = two_managers_with_home();
    let dan = keys("acc_dan");
    alice
        .add_member_unchecked(dan.public_keys(), MemberRole::Edit, None)
        .unwrap();
    assert!(home.remember_trust_of(&alice).unwrap());
    assert!(home.is_dirty(), "the home vault is to be saved");
    let home_file = json(&home);
    assert!(home_file.get("local_members").is_some());
    let shared_file = bytes(&alice);
    // Nothing about the change is readable in the home vault's file.
    assert!(!home_file.to_string().contains("acc_dan"));

    // Alice's app restarts; Carol removed Victor meanwhile (a new key: Carol's list wins).
    let home = Vault::unlock(to_bytes(&home_file), "demo master".into(), "alice".into()).unwrap();
    let alice = Vault::open_shared_with_home(shared_file, &home, "acc_alice", "alice").unwrap();
    assert!(alice.take_members_notice().is_none());
    carol_v.remove_member("acc_victor").unwrap();
    alice.merge_remote(bytes(&carol_v)).unwrap();
    let info = alice.shared_info().unwrap();
    assert!(info.members.iter().any(|m| m.account == "acc_dan"));
    assert!(!info.members.iter().any(|m| m.account == "acc_victor"));
    let notice = alice.take_members_notice().unwrap();
    assert!(matches!(
        &notice.reapplied[..],
        [MemberChange::Add { keys, .. }] if keys.account == "acc_dan"
    ));

    // Once Carol has Alice's list, nothing is left to keep.
    home.remember_trust_of(&alice).unwrap();
    carol_v.merge_remote(bytes(&alice)).unwrap();
    alice.merge_remote(bytes(&carol_v)).unwrap();
    assert!(home.remember_trust_of(&alice).unwrap());
    assert!(json(&home).get("local_members").is_none());
}

#[test]
fn a_change_lost_before_the_restart_is_applied_again_on_open() {
    let (_t, home, alice, carol_v) = two_managers_with_home();
    let dan = keys("acc_dan");
    alice
        .add_member_unchecked(dan.public_keys(), MemberRole::Edit, None)
        .unwrap();
    home.remember_trust_of(&alice).unwrap();
    // A sync merged Carol's winning list and saved the shared vault, but the app quit before
    // the change was applied again and before the home vault was saved.
    carol_v.remove_member("acc_victor").unwrap();
    let home_file = bytes(&home);
    let home = Vault::unlock(home_file, "demo master".into(), "alice".into()).unwrap();
    let alice = Vault::open_shared_with_home(bytes(&carol_v), &home, "acc_alice", "alice").unwrap();
    let info = alice.shared_info().unwrap();
    assert!(info.members.iter().any(|m| m.account == "acc_dan"));
    assert_eq!(info.signed_by, "acc_alice");
    assert_eq!(alice.take_members_notice().unwrap().reapplied.len(), 1);
}

#[test]
fn a_confirmed_change_is_not_applied_again_on_open() {
    let (_t, home, alice, carol_v) = two_managers_with_home();
    let dan = keys("acc_dan");
    alice
        .add_member_unchecked(dan.public_keys(), MemberRole::Edit, None)
        .unwrap();
    home.remember_trust_of(&alice).unwrap();
    // Carol built on Alice's list; Alice's device merged it but quit before saving home.
    carol_v.merge_remote(bytes(&alice)).unwrap();
    carol_v
        .set_member_role("acc_bob", MemberRole::View)
        .unwrap();
    let home = Vault::unlock(bytes(&home), "demo master".into(), "alice".into()).unwrap();
    let alice = Vault::open_shared_with_home(bytes(&carol_v), &home, "acc_alice", "alice").unwrap();
    assert!(alice.take_members_notice().is_none());
    assert_eq!(alice.shared_info().unwrap().signed_by, "acc_carol");
    assert!(json(&home).get("local_members").is_none());
}

// Pinned contact keys: the attacks of a breached account service.

#[test]
fn pins_follow_the_home_vault_and_refuse_a_wrong_comparison() {
    let alice = keys("acc_alice");
    let bob = keys("acc_bob");
    let home = home_pinning(&alice, &[]);
    let b = bob.public_keys();
    assert_eq!(
        home.contact_pin_status(b.clone(), PERSONAL_SCOPE).unwrap(),
        PinStatus::NotPinned
    );
    // Alice's own keys need no comparison.
    assert_eq!(
        home.contact_pin_status(alice.public_keys(), PERSONAL_SCOPE).unwrap(),
        PinStatus::Pinned
    );
    // A fingerprint that isn't Bob's: nothing pinned.
    let other = keys("acc_bob").public_keys().fingerprint();
    assert!(is_err_text(
        home.pin_contact(b.clone(), PERSONAL_SCOPE, &other),
        "share.fingerprint_mismatch"
    ));
    assert!(home.contact_pins().is_empty());
    // Typed with spaces and lower case: still Bob's.
    let typed = b.fingerprint().to_lowercase().replace('-', " ");
    let pin = home.pin_contact(b.clone(), PERSONAL_SCOPE, &typed).unwrap();
    assert_eq!(pin.fingerprint, b.fingerprint());
    assert_eq!(
        home.contact_pin_status(b.clone(), PERSONAL_SCOPE).unwrap(),
        PinStatus::Pinned
    );
    // Scoped keys (a Team's work keyset) are pinned on their own.
    assert_eq!(
        home.contact_pin_status(b.clone(), "org:grp_acme").unwrap(),
        PinStatus::NotPinned
    );
    assert!(is_err_text(
        home.contact_pin_status(b.clone(), "work"),
        "share.bad_scope"
    ));
    // The pins are sealed settings of the home vault: another device has them after a sync, the
    // file holds no fingerprint in clear, and a shared vault keeps none.
    let file = bytes(&home);
    assert!(!String::from_utf8_lossy(&file).contains(&b.fingerprint()));
    assert!(!String::from_utf8_lossy(&file).contains(&b.enc_pub));
    let laptop = Vault::unlock(file, "demo master".into(), "alice-laptop".into()).unwrap();
    assert_eq!(laptop.contact_pins(), vec![pin]);
    let shared = Vault::create_shared(&alice, SharedKind::Direct, None, "d").unwrap();
    assert!(is_err_text(
        shared.pin_contact(b.clone(), PERSONAL_SCOPE, &b.fingerprint()),
        "share.keys_in_shared"
    ));
    home.unpin_contact("acc_bob", PERSONAL_SCOPE).unwrap();
    assert!(home.contact_pins().is_empty());
}

#[test]
fn a_server_that_swaps_a_members_keys_gets_no_wrap() {
    let alice = keys("acc_alice");
    let bob = keys("acc_bob");
    let home = home_pinning(&alice, &[&bob]);
    let vault =
        Vault::create_shared(&alice, SharedKind::Org, Some("org_acme".into()), "d").unwrap();
    vault
        .add_member(bob.public_keys(), MemberRole::Edit, None, &home)
        .unwrap();
    // The service now hands out its own keyset under Bob's account (genuinely self-signed).
    let planted = keys("acc_bob").public_keys();
    let swap = vec![MemberChange::ReplaceKeys {
        keys: planted.clone(),
    }];
    let problems = home.unpinned_changes(swap.clone());
    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].account, "acc_bob");
    assert_eq!(problems[0].fingerprint, planted.fingerprint());
    assert_eq!(
        problems[0].status,
        PinStatus::Changed {
            pinned_fingerprint: bob.public_keys().fingerprint()
        }
    );
    let before = vault.shared_info().unwrap();
    assert!(is_err_text(
        vault.change_members_pinned(swap.clone(), &home),
        "share.keys_changed"
    ));
    // The raw call refuses any new key, so an app can't skip the check.
    assert!(is_err_text(
        vault.change_members(swap),
        "share.needs_verified_keys"
    ));
    assert_eq!(vault.shared_info().unwrap(), before);
    // Adding the swapped keys to another vault is refused the same way.
    let other = Vault::create_shared(&alice, SharedKind::Direct, None, "d").unwrap();
    assert!(is_err_text(
        other.add_member(planted.clone(), MemberRole::Edit, None, &home),
        "share.keys_changed"
    ));
    // Only a new comparison with Bob replaces the pin, and it remembers the old fingerprint.
    let pin = home
        .pin_contact(planted.clone(), PERSONAL_SCOPE, &planted.fingerprint())
        .unwrap();
    assert_eq!(
        pin.previous_fingerprint,
        Some(bob.public_keys().fingerprint())
    );
    vault
        .change_members_pinned(vec![MemberChange::ReplaceKeys { keys: planted }], &home)
        .unwrap();
}

#[test]
fn a_server_that_adds_a_confirmed_member_gets_no_wrap() {
    let alice = keys("acc_alice");
    let bob = keys("acc_bob");
    let home = home_pinning(&alice, &[&bob]);
    let vault =
        Vault::create_shared(&alice, SharedKind::Org, Some("org_acme".into()), "d").unwrap();
    // The service says "Mallory is a confirmed member" and hands out her keys with Bob's.
    let mallory = keys("acc_mallory").public_keys();
    let changes = vec![
        MemberChange::Add {
            keys: bob.public_keys(),
            role: MemberRole::Edit,
            group: None,
        },
        MemberChange::Add {
            keys: mallory.clone(),
            role: MemberRole::Manage,
            group: None,
        },
    ];
    let problems = home.unpinned_changes(changes.clone());
    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].account, "acc_mallory");
    assert_eq!(problems[0].status, PinStatus::NotPinned);
    assert!(is_err_text(
        vault.change_members_pinned(changes, &home),
        "share.keys_not_verified"
    ));
    assert_eq!(vault.shared_info().unwrap().members.len(), 1);
    // A department sync with her in it is refused as a whole; without her it goes ahead.
    let group = |with_mallory: bool| {
        let mut m = vec![GroupMember {
            keys: bob.public_keys(),
            role: MemberRole::Edit,
        }];
        if with_mallory {
            m.push(GroupMember {
                keys: mallory.clone(),
                role: MemberRole::Edit,
            });
        }
        m
    };
    assert!(is_err_text(
        vault.sync_group("grp_eng", group(true), &home),
        "share.keys_not_verified"
    ));
    let info = vault
        .sync_group("grp_eng", group(false), &home)
        .unwrap()
        .unwrap();
    assert!(info.members.iter().all(|m| m.account != "acc_mallory"));
    // The vault file wraps the key to Alice and Bob only.
    let file = members_of(&json(&vault));
    assert_eq!(file.entries.len(), 2);
    assert!(file.entries.iter().all(|e| e.enc_pub != mallory.enc_pub));
}

#[test]
fn a_first_open_shows_whether_the_signer_is_verified() {
    let alice = keys("acc_alice");
    let bob = keys("acc_bob");
    let alice_home = home_pinning(&alice, &[&bob]);
    let vault = Vault::create_shared(&alice, SharedKind::Direct, None, "d").unwrap();
    vault
        .add_member(bob.public_keys(), MemberRole::Edit, None, &alice_home)
        .unwrap();
    // Bob never compared with Alice: "not verified yet".
    let bob_home = home_pinning(&bob, &[]);
    let opened =
        Vault::open_shared_with_home(bytes(&vault), &bob_home, "acc_bob", "bob").unwrap();
    assert_eq!(
        bob_home.shared_signer_status(&opened),
        Some(PinStatus::NotPinned)
    );
    // After comparing: verified.
    let a = alice.public_keys();
    bob_home
        .pin_contact(a.clone(), PERSONAL_SCOPE, &a.fingerprint())
        .unwrap();
    assert_eq!(bob_home.shared_signer_status(&opened), Some(PinStatus::Pinned));
    // A fake "vault from Alice" the service made with its own keys under her name: loud.
    let fake_alice = keys("acc_alice");
    let fake = Vault::create_shared(&fake_alice, SharedKind::Direct, None, "d").unwrap();
    fake.change_members_unchecked(vec![MemberChange::Add {
        keys: bob.public_keys(),
        role: MemberRole::Edit,
        group: None,
    }])
    .unwrap();
    let opened =
        Vault::open_shared_with_home(bytes(&fake), &bob_home, "acc_bob", "bob").unwrap();
    assert_eq!(
        bob_home.shared_signer_status(&opened),
        Some(PinStatus::Changed {
            pinned_fingerprint: a.fingerprint()
        })
    );
    assert_eq!(bob_home.shared_signer_status(&bob_home), None);
}
