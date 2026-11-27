//! Emergency access, admin-assisted recovery, several open vaults and secure send through the
//! public API. Demo accounts and passwords only.

use pass_core::{
    admin_recovery_approve, admin_recovery_request, multi_default_save_vault, multi_for_url,
    multi_search, multi_vault_summaries, org_recovery_create, recovery_request_code, send_info,
    send_link, send_open,
    send_parse_link, send_seal, EmergencyAccess, Item, KdfParams, MemberRole, OrgKind, PassError,
    SendContent, SendKind, SendOptions, SharedKind, UserKeyset, Vault, PERSONAL_SCOPE,
};

fn fast_kdf() -> KdfParams {
    KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
        ..Default::default()
    }
}

fn home(device: &str) -> std::sync::Arc<Vault> {
    let v = Vault::create_with_kdf("demo master password", device, fast_kdf()).unwrap();
    v.upsert(Item {
        title: "Bank".into(),
        username: "olivia".into(),
        password: "bank-demo-pass".into(),
        urls: vec!["https://bank.example".into()],
        ..Default::default()
    })
    .unwrap();
    v
}

#[test]
fn emergency_access_opens_after_release_with_the_access_the_owner_chose() {
    let owner = home("olivia-laptop");
    let owner_keys = owner.ensure_user_keyset("acc_olivia").unwrap();
    let carol_home = home("carol-phone");
    let carol = carol_home.ensure_user_keyset("acc_carol").unwrap();
    let file = owner.serialize().unwrap();

    let view = owner
        .emergency_grant("acc_olivia", carol.public_keys(), EmergencyAccess::View, 72)
        .unwrap();
    assert!(!owner.is_dirty(), "granting changes nothing in the vault");
    assert!(owner.emergency_grant_current(view.grant.clone()));
    let seen = Vault::open_emergency(
        file.clone(),
        view.grant.clone(),
        &view.release_secret,
        &carol,
        "carol-phone",
    )
    .unwrap();
    assert!(seen.is_read_only());
    assert_eq!(seen.items()[0].password, "bank-demo-pass");
    assert!(matches!(
        seen.upsert(Item {
            title: "Mine now".into(),
            ..Default::default()
        }),
        Err(PassError::InvalidInput(_))
    ));
    assert!(seen.change_master_password("taken over".into()).is_err());
    assert!(seen.create_recovery_code().is_err());
    // Before the release (no secret, or a guessed one) it doesn't open.
    let guessed = pass_core::b64url_encode(vec![9u8; 32]);
    assert!(
        Vault::open_emergency(file.clone(), view.grant.clone(), &guessed, &carol, "c").is_err()
    );
    // Not for anyone else.
    let dave = UserKeyset::generate("acc_dave").unwrap();
    assert!(Vault::open_emergency(
        file.clone(),
        view.grant.clone(),
        &view.release_secret,
        &dave,
        "d"
    )
    .is_err());
    // Not as the owner's own contact, nor for a shared vault.
    assert!(owner
        .emergency_grant(
            "acc_olivia",
            owner_keys.public_keys(),
            EmergencyAccess::Full,
            24
        )
        .is_err());
    let shared = Vault::create_shared(&owner_keys, SharedKind::Org, None, "o").unwrap();
    assert!(shared
        .emergency_grant("acc_olivia", carol.public_keys(), EmergencyAccess::Full, 24)
        .is_err());

    // Full access: a takeover with a new master password, the owner's keyset included.
    let full = owner
        .emergency_grant(
            "acc_olivia",
            carol.public_keys(),
            EmergencyAccess::Full,
            24 * 7,
        )
        .unwrap();
    let taken = Vault::open_emergency(
        file.clone(),
        full.grant.clone(),
        &full.release_secret,
        &carol,
        "carol-phone",
    )
    .unwrap();
    assert!(!taken.is_read_only());
    assert!(taken.user_keyset("acc_olivia").unwrap().is_some());
    taken
        .change_master_password_with_kdf("carol's new master", fast_kdf())
        .unwrap();
    let after = taken.serialize().unwrap();
    assert!(Vault::unlock(after, "carol's new master".into(), "x".into()).is_ok());

    // A new key on the owner's side makes the grants stale.
    owner
        .change_password(
            "demo master password".into(),
            "olivia's new master".into(),
        )
        .unwrap();
    assert!(!owner.emergency_grant_current(full.grant.clone()));
    let rotated = owner.serialize().unwrap();
    assert!(matches!(
        Vault::open_emergency(rotated, full.grant, &full.release_secret, &carol, "c"),
        Err(PassError::Crypto(_))
    ));
}

#[test]
fn admin_assisted_recovery_restores_a_teams_member_and_shows_who_did_it() {
    let alice = UserKeyset::generate("acc_alice").unwrap();
    let bob = UserKeyset::generate("acc_bob").unwrap();
    let alice_home = home("alice-laptop");
    let bob_keys = bob.public_keys();
    alice_home
        .pin_contact(bob_keys.clone(), PERSONAL_SCOPE, &bob_keys.fingerprint())
        .unwrap();
    let key =
        org_recovery_create(&alice, "org_acme", OrgKind::Team, vec![bob_keys], &alice_home)
            .unwrap();
    let mia = home("mia-laptop");
    // Mia compared Alice's fingerprint when she joined.
    let alice_keys = alice.public_keys();
    mia.pin_contact(alice_keys.clone(), PERSONAL_SCOPE, &alice_keys.fingerprint())
        .unwrap();
    assert!(
        mia.admin_recovery_enrollments().is_empty(),
        "off by default"
    );
    let enrollment = mia
        .admin_recovery_enroll(key.clone(), alice.public_keys(), "acc_mia", OrgKind::Team)
        .unwrap();
    assert_eq!(mia.admin_recovery_enrollments()[0].org, "org_acme");
    assert!(mia.admin_recovery_enrollment_current(enrollment.clone()));
    let file = mia.serialize().unwrap();

    // Mia forgot her master password: a request from her new phone, approved by Bob.
    let request = admin_recovery_request("org_acme", "acc_mia", &mia.vault_id()).unwrap();
    // Mia reads the code on her phone to Bob, who types it.
    let code = recovery_request_code(request.request.clone()).unwrap();
    let approval = admin_recovery_approve(
        key.clone(),
        &bob,
        enrollment.clone(),
        request.request.clone(),
        &code,
    )
    .unwrap();
    // The approval is checked against the approving admin's keys.
    assert!(Vault::unlock_with_admin_recovery(
        file.clone(),
        approval.clone(),
        &request.secret,
        alice.public_keys(),
        "mia-phone"
    )
    .is_err());
    let restored = Vault::unlock_with_admin_recovery(
        file.clone(),
        approval.clone(),
        &request.secret,
        bob.public_keys(),
        "mia-phone",
    )
    .unwrap();
    assert_eq!(restored.items()[0].title, "Bank");
    let log = restored.admin_recovery_log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].approved_by, "acc_bob");
    assert_eq!(log[0].approver_fingerprint, bob.fingerprint());
    restored
        .change_master_password_with_kdf("mia's new master", fast_kdf())
        .unwrap();
    let after = restored.serialize().unwrap();
    // The new password came with a new vault key, which the admin never saw: Mia's laptop,
    // still on the old key, can't merge the new file and opens it with the new password, and
    // sees the use there.
    assert!(mia.merge_remote(after.clone()).is_err());
    let mia = Vault::unlock(after, "mia's new master".into(), "mia-laptop".into()).unwrap();
    assert_eq!(mia.admin_recovery_log().len(), 1);
    assert!(!mia.admin_recovery_enrollment_current(enrollment.clone()));

    // Opting out forgets the enrollment; a new key makes the service's copy useless.
    mia.admin_recovery_withdraw("org_acme").unwrap();
    assert!(mia.admin_recovery_enrollments().is_empty());
    mia.change_password("mia's new master".into(), "newer".into())
        .unwrap();
    assert!(!mia.admin_recovery_enrollment_current(enrollment));
    assert!(org_recovery_create(&alice, "org_home", OrgKind::Family, vec![], &mia).is_ok());
}

#[test]
fn search_and_save_across_open_vaults_keep_the_vault() {
    let olivia = home("olivia-laptop");
    let keys = olivia.ensure_user_keyset("acc_olivia").unwrap();
    let team = Vault::create_shared(&keys, SharedKind::Org, Some("org_acme".into()), "o").unwrap();
    team.upsert(Item {
        title: "Bank (team)".into(),
        username: "finance".into(),
        password: "team-demo-pass".into(),
        urls: vec!["https://bank.example/login".into()],
        ..Default::default()
    })
    .unwrap();
    let groups = multi_vault_summaries(vec![olivia.clone(), team.clone()]);
    assert_eq!(groups[1].shared, Some(SharedKind::Org));
    assert_eq!(groups[1].role, Some(MemberRole::Manage));
    let found = multi_for_url(groups.clone(), "https://bank.example".into());
    let vaults: Vec<&str> = found.iter().map(|r| r.vault_id.as_str()).collect();
    assert_eq!(found.len(), 2);
    assert!(vaults.contains(&olivia.vault_id().as_str()));
    assert!(vaults.contains(&team.vault_id().as_str()));
    let hit = multi_search(groups.clone(), "team".into());
    assert_eq!(hit[0].vault_id, team.vault_id());
    assert!(team.get(hit[0].summary.id.clone()).is_some());
    assert_eq!(
        multi_default_save_vault(groups, Some("https://new.example".into()), None),
        Some(olivia.vault_id())
    );
}

#[test]
fn a_send_round_trips_through_its_link() {
    let content = SendContent {
        kind: SendKind::Text,
        name: String::new(),
        mime: String::new(),
        data: b"door code 0451".to_vec(),
    };
    let options = SendOptions {
        expires_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
            + 3_600_000,
        max_views: 1,
        password: None,
    };
    let sealed = send_seal(content, options).unwrap();
    let link = send_link("https://send.passyble.com/s", "Ab12", &sealed.key).unwrap();
    assert!(!sealed.meta.contains(&sealed.key));
    let parsed = send_parse_link(&link).unwrap();
    assert_eq!(parsed.send_id, "Ab12");
    assert_eq!(send_info(sealed.meta.clone()).unwrap().max_views, 1);
    let opened = send_open(sealed.ciphertext, sealed.meta, parsed.key, None).unwrap();
    assert_eq!(opened.data, b"door code 0451");
}
