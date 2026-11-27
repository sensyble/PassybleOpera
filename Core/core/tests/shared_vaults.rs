//! Shared vaults through the public API: each person's home vault holds their keyset, the account
//! service passes public keys around (here: their JSON), and the shared vault's file syncs like any
//! other. Demo accounts and passwords only.

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

fn home(device: &str) -> Arc<Vault> {
    Vault::create_with_kdf("demo master password", device, fast_kdf()).unwrap()
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

fn titles(v: &Vault) -> Vec<String> {
    v.items().into_iter().map(|i| i.title).collect()
}

#[test]
fn a_family_shares_a_vault_and_a_member_leaves() {
    // Alice and Bob each have a home vault; joining the family makes their keysets.
    let alice_home = home("alice-laptop");
    let bob_home = home("bob-phone");
    let alice_keys = alice_home.ensure_user_keyset("acc_alice").unwrap();
    let bob_public = bob_home
        .ensure_user_keyset("acc_bob")
        .unwrap()
        .public_keys();
    let from_service = PublicKeys::from_json(&bob_public.to_json()).unwrap();
    from_service.verify().unwrap();
    // Alice compares the fingerprint with Bob before confirming him: her home vault pins it.
    assert_eq!(from_service.fingerprint(), bob_public.fingerprint());
    alice_home
        .pin_contact(from_service.clone(), PERSONAL_SCOPE, &bob_public.fingerprint())
        .unwrap();

    let family = Vault::create_shared(
        &alice_keys,
        SharedKind::Org,
        Some("org_family".into()),
        "alice-laptop",
    )
    .unwrap();
    family
        .add_member(from_service, MemberRole::Edit, None, &alice_home)
        .unwrap();
    family.upsert(login("Streaming", "stream-pass")).unwrap();
    let uploaded = family.serialize().unwrap();

    let bob_family =
        Vault::open_shared_with_home(uploaded.clone(), &bob_home, "acc_bob", "bob-phone").unwrap();
    assert_eq!(titles(&bob_family), ["Streaming"]);
    assert_eq!(bob_family.shared_role(), Some(MemberRole::Edit));
    let info = bob_family.shared_info().unwrap();
    assert_eq!(info.created_by, "acc_alice");
    assert!(info.anchored);
    assert!(bob_home.stored_share_trust(&family.vault_id()).is_some());

    let mine = bob_home.upsert(login("Groceries", "grocer-pass")).unwrap();
    bob_home.move_item_to(&mine.id, &bob_family).unwrap();
    assert!(bob_home.get(mine.id.clone()).is_none());
    family
        .merge_remote(bob_family.serialize().unwrap())
        .unwrap();
    assert_eq!(titles(&family), ["Groceries", "Streaming"]);

    // Bob leaves: Alice removes him, which rotates the key.
    family.remove_member("acc_bob").unwrap();
    family.upsert(login("Bank", "bank-pass")).unwrap();
    let after = family.serialize().unwrap();
    assert!(Vault::open_shared_with_home(after.clone(), &bob_home, "acc_bob", "bob-phone").is_err());
    assert!(bob_family.merge_remote(after).is_err());
    assert!(!titles(&bob_family).contains(&"Bank".to_string()));
}

#[test]
fn an_item_is_shared_with_one_person_through_a_direct_share() {
    let alice_home = home("alice-laptop");
    let bob_home = home("bob-phone");
    let alice = alice_home.ensure_user_keyset("acc_alice").unwrap();
    let bob = bob_home.ensure_user_keyset("acc_bob").unwrap();
    let wifi = alice_home.upsert(login("Wifi", "wifi-pass")).unwrap();

    let share = Vault::create_shared(&alice, SharedKind::Direct, None, "alice-laptop").unwrap();
    let bob_keys = bob.public_keys();
    alice_home
        .pin_contact(bob_keys.clone(), PERSONAL_SCOPE, &bob_keys.fingerprint())
        .unwrap();
    share
        .add_member(bob_keys, MemberRole::View, None, &alice_home)
        .unwrap();
    let copied = alice_home.copy_item_to(&wifi.id, &share).unwrap();
    assert_ne!(copied.id, wifi.id);
    assert!(alice_home.get(wifi.id.clone()).is_some());

    let bob_share =
        Vault::open_shared_with_home(share.serialize().unwrap(), &bob_home, "acc_bob", "bob")
            .unwrap();
    let info = bob_share.shared_info().unwrap();
    assert_eq!(info.kind, SharedKind::Direct);
    assert_eq!(
        info.others().map(|m| m.account.clone()).collect::<Vec<_>>(),
        ["acc_alice"]
    );
    assert_eq!(bob_share.items()[0].password, "wifi-pass");
    // A viewer can't change it, but can keep a copy in their own vault.
    assert!(bob_share.upsert(login("Mine", "x")).is_err());
    bob_share.copy_item_to(&copied.id, &bob_home).unwrap();
    assert_eq!(titles(&bob_home), ["Wifi"]);
}

#[test]
fn the_keyset_follows_the_home_vault_to_another_device() {
    let phone = home("bob-phone");
    let keys = phone.ensure_user_keyset("acc_bob").unwrap();
    // The laptop gets the home vault through sync and unlocks it with the master password.
    let laptop = Vault::unlock(
        phone.serialize().unwrap(),
        "demo master password".into(),
        "bob-laptop".into(),
    )
    .unwrap();
    let on_laptop = laptop.user_keyset("acc_bob").unwrap().unwrap();
    assert_eq!(on_laptop.public_keys(), keys.public_keys());
    assert_eq!(on_laptop.fingerprint(), keys.fingerprint());
}
