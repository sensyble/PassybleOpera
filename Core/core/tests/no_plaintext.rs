//! Nothing leaves a device unencrypted: canary vaults go through the paths that write or send vault
//! data besides the sync transports, and every byte they produce is searched for the canaries.
//! Google Drive is checked in `src/gdrive/tests.rs`. No network, demo data only.

use std::collections::BTreeSet;
use std::sync::Arc;

use pass_core::*;

#[path = "common/leak.rs"]
mod leak;

fn fast_kdf() -> KdfParams {
    KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
        ..Default::default()
    }
}

/// A personal vault with every canary, settings, a keyset and a recovery code (its code added to
/// the needles).
fn canary_vault(needles: &mut leak::Needles, tag: &str) -> Arc<Vault> {
    let v = Vault::create_with_kdf("demo master password", tag, fast_kdf()).unwrap();
    leak::fill(&v, tag);
    leak::fill_settings(&v, tag);
    v.ensure_user_keyset(&format!("acc_{tag}")).unwrap();
    needles.add_secret("recovery code", &v.create_recovery_code().unwrap());
    v
}

#[test]
fn the_scanner_finds_canaries_in_every_encoding() {
    use base64::Engine;
    let needles = leak::Needles::new();
    let secret = leak::canary("t", "probe");
    let b64 = base64::engine::general_purpose::STANDARD;
    let url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut gz = Vec::new();
    {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
        enc.write_all(secret.as_bytes()).unwrap();
        enc.finish().unwrap();
    }
    let hex: String = secret.bytes().map(|b| format!("{b:02x}")).collect();
    let escaped: String = secret
        .chars()
        .map(|c| format!("\\u{:04x}", c as u32))
        .collect();
    let forms: Vec<Vec<u8>> = vec![
        secret.to_lowercase().into_bytes(),
        format!("x{}", b64.encode(format!("ab{secret}"))).into_bytes(),
        format!("{{\"ct\":\"{}\"}}", url.encode(format!("z{secret}"))).into_bytes(),
        hex.into_bytes(),
        escaped.into_bytes(),
        secret.replace('-', "%2D").into_bytes(),
        b64.encode(b64.encode(&gz)).into_bytes(),
        [b"pre".as_slice(), &leak::private_key()[..20]].concat(),
    ];
    for (i, form) in forms.iter().enumerate() {
        let mut hits = BTreeSet::new();
        needles.scan("probe", form, &mut hits);
        assert!(!hits.is_empty(), "form {i} not found");
    }
    let mut none = BTreeSet::new();
    needles.scan(
        "clean",
        b"{\"id\":\"9b1d\",\"ct\":\"q83vEjRWeJA=\"}",
        &mut none,
    );
    assert!(none.is_empty(), "{none:?}");
}

/// The vault file as each device keeps it (with its local-only parts) and as it is uploaded, a
/// shared vault's file, the encrypted export, and what goes to the account service for keys,
/// emergency access, admin recovery and a secure send: no canary in any of them.
#[test]
fn files_exports_and_account_service_uploads_carry_no_secret() {
    let mut needles = leak::Needles::new();
    let home = canary_vault(&mut needles, "home");
    let keys = home.ensure_user_keyset("acc_home").unwrap();
    let team =
        Vault::create_shared(&keys, SharedKind::Org, Some("org_acme".into()), "laptop").unwrap();
    leak::fill(&team, "team");
    let bob = UserKeyset::generate("acc_bob").unwrap();
    let bob_keys = bob.public_keys();
    home.pin_contact(bob_keys.clone(), PERSONAL_SCOPE, &bob_keys.fingerprint())
        .unwrap();
    team.add_member(bob_keys, MemberRole::Edit, Some("grp_eng".into()), &home)
        .unwrap();
    home.remember_trust_of(&team).unwrap();

    let mut captured: Vec<(String, Vec<u8>)> = Vec::new();
    let local = home.serialize().unwrap();
    captured.push(("home vault file".into(), local.clone()));
    let shared = team.serialize().unwrap();
    leak::assert_no_local_fields("shared vault file", &shared);
    captured.push(("shared vault file".into(), shared));
    let export = export_encrypted_json(home.clone(), "export demo password 2026".into()).unwrap();
    assert!(export_is_encrypted(export.clone()));
    captured.push(("encrypted export".into(), export));
    let published = home.publish_keys_for("acc_home").unwrap();
    captured.push((
        "public keys".into(),
        serde_json::to_vec(&published).unwrap(),
    ));
    let grant = home
        .emergency_grant("acc_home", bob.public_keys(), EmergencyAccess::View, 48)
        .unwrap();
    captured.push((
        "emergency grant".into(),
        serde_json::to_vec(&grant.grant).unwrap(),
    ));
    let admin = UserKeyset::generate("acc_admin").unwrap();
    let admin_keys = admin.public_keys();
    home.pin_contact(admin_keys.clone(), PERSONAL_SCOPE, &admin_keys.fingerprint())
        .unwrap();
    let key = org_recovery_create(&admin, "org_acme", OrgKind::Team, vec![admin_keys], &home)
        .unwrap();
    let enrollment = home
        .admin_recovery_enroll(key, admin.public_keys(), "acc_home", OrgKind::Team)
        .unwrap();
    captured.push((
        "admin recovery enrollment".into(),
        serde_json::to_vec(&enrollment).unwrap(),
    ));
    let sealed = send_seal(
        SendContent {
            kind: SendKind::File,
            name: leak::canary("send", "filename.txt"),
            mime: "text/plain".into(),
            data: leak::canary("send", "content").into_bytes(),
        },
        SendOptions {
            expires_at: leak::now_ms() + 3_600_000,
            max_views: 2,
            password: Some(leak::canary("send", "password")),
        },
    )
    .unwrap();
    captured.push(("send ciphertext".into(), sealed.ciphertext.clone()));
    captured.push(("send meta".into(), sealed.meta.clone().into_bytes()));
    if let Some(auth) = &sealed.password_auth {
        captured.push(("send password proof".into(), auth.clone().into_bytes()));
    }
    leak::assert_no_canary(&needles, &captured);

    // The local file keeps the device's sync state and member changes; both are sealed or hashes.
    let json: serde_json::Value = serde_json::from_slice(&local).unwrap();
    assert_eq!(json["format"], "pass-vault");
}

/// What goes to Have I Been Pwned (5 hex digits of a SHA-1, never more), what a website icon fetch
/// reveals (the host name, by design), and what error messages say: no canary in any.
#[test]
fn lookups_and_messages_carry_no_secret() {
    let mut needles = leak::Needles::new();
    let home = canary_vault(&mut needles, "msg");
    let mut captured: Vec<(String, Vec<u8>)> = Vec::new();

    for item in home.items() {
        let mut passwords = vec![item.password.clone()];
        passwords.extend(item.password_history.iter().map(|h| h.password.clone()));
        for p in passwords.into_iter().filter(|p| !p.is_empty()) {
            let q = hibp_prefix(p);
            assert!(q.prefix.len() == 5 && q.prefix.bytes().all(|b| b.is_ascii_hexdigit()));
            captured.push(("hibp prefix".into(), q.prefix.into_bytes()));
        }
        for url in &item.urls {
            // `.example` is under no public suffix: no icon request at all.
            assert_eq!(site_icon_domain(url.clone()), None, "{url}");
        }
    }
    // A real site: the host name is all an icon fetch sends, to that host itself, never the
    // path, the query or the user name in the address.
    let url =
        "https://CANARY-user:CANARY-pw@www.canary-icons-7f3a.com:8443/login?u=CANARY-q#CANARY-f";
    assert_eq!(
        site_icon_domain(url.into()).as_deref(),
        Some("canary-icons-7f3a.com")
    );
    // Anything but a 5-digit hex prefix is refused before any request.
    let refused = hibp_range(&leak::canary("msg", "hibp")).unwrap_err();
    captured.push((
        "hibp refusal".into(),
        format!("{refused} {refused:?}").into_bytes(),
    ));

    let file = home.serialize().unwrap();
    let wrong = Vault::unlock(file.clone(), "not the password".into(), "x".into()).unwrap_err();
    captured.push((
        "wrong password".into(),
        format!("{wrong} {wrong:?}").into_bytes(),
    ));
    let other = Vault::create_with_kdf("demo master password", "y", fast_kdf()).unwrap();
    let foreign = other.merge_remote(file.clone()).unwrap_err();
    captured.push((
        "foreign merge".into(),
        format!("{foreign} {foreign:?}").into_bytes(),
    ));
    let mut damaged = file.clone();
    let at = damaged.len() / 2;
    damaged[at] ^= 0x55;
    if let Err(e) = Vault::unlock(damaged, "demo master password".into(), "x".into()) {
        captured.push(("damaged file".into(), format!("{e} {e:?}").into_bytes()));
    }
    for item in home.items() {
        // The secrets themselves never show in debug output (titles and names may: the core
        // logs nothing, and the apps never log items).
        let shown = format!(
            "{:?} {:?} {:?}",
            item.card, item.password_history, item.passkeys
        );
        for secret in [leak::canary("msg", "cvv"), leak::canary("msg", "pin")] {
            assert!(!shown.contains(&secret), "{shown}");
        }
        assert!(
            !shown.contains("password0") && !shown.contains("password1"),
            "{shown}"
        );
    }
    captured.push(("vault debug".into(), format!("{home:?}").into_bytes()));
    leak::assert_no_canary(&needles, &captured);
}
