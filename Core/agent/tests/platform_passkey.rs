//! The clientDataHash variant of the passkey handlers, used by the Windows passkey plugin.

#![cfg(feature = "native")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use pass_agent::{
    Agent, AgentConfig, Consent, ErrorCode, PasskeyChoice, PlatformCreateRequest,
    PlatformGetRequest, Ui,
};

#[derive(Default)]
struct FakeUi {
    deny: bool,
    creates: AtomicUsize,
    choices: Mutex<Vec<usize>>,
}

impl Ui for FakeUi {
    fn request_unlock(&self) -> bool {
        false
    }
    fn confirm_passkey_create(&self, _rp_id: &str, _user: &str) -> Consent {
        self.creates.fetch_add(1, Ordering::SeqCst);
        if self.deny {
            Consent::Deny
        } else {
            Consent::Approve { item_id: None }
        }
    }
    fn choose_passkey(&self, _rp_id: &str, options: &[PasskeyChoice]) -> Option<usize> {
        self.choices.lock().unwrap().push(options.len());
        (!options.is_empty()).then_some(options.len() - 1)
    }
    fn show_totp_popup(&self, _item_id: &str, _title: &str) {}
    fn notify_lock_state(&self, _locked: bool) {}
}

fn setup(ui: Arc<FakeUi>) -> (tempfile::TempDir, Arc<Agent>) {
    let dir = tempfile::tempdir().unwrap();
    let agent = Agent::new(
        AgentConfig {
            vault_path: dir.path().join("pass.vault"),
            device_id: "laptop".into(),
            auto_lock: Duration::from_secs(900),
            webdav: None,
            gdrive: None,
            kept_list: None,
        },
        ui,
    );
    (dir, agent)
}

fn create_request(user: &str, handle: u8) -> PlatformCreateRequest {
    PlatformCreateRequest {
        rp_id: "Example.com".into(),
        rp_name: Some("Example".into()),
        user_handle: vec![handle; 8],
        user_name: user.into(),
        user_display_name: None,
        client_data_hash: vec![7; 32],
        algorithms: vec![-8, -7],
        exclude_credentials: vec![],
    }
}

fn yes(_: &str) -> bool {
    true
}

#[test]
fn locked_vault_asks_to_unlock_then_cancels() {
    let (_dir, agent) = setup(Arc::default());
    let err = agent
        .platform_passkey_create(create_request("alice", 1), &yes)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Cancelled);
    assert_eq!(agent.passkey_metadata(), None);
}

#[test]
fn create_then_get_with_client_data_hash() {
    let ui = Arc::new(FakeUi::default());
    let (_dir, agent) = setup(ui.clone());
    agent.create_vault("master").unwrap();

    let verified = Mutex::new(Vec::new());
    let verify = |user: &str| {
        verified.lock().unwrap().push(user.to_string());
        true
    };
    let created = agent
        .platform_passkey_create(create_request("alice", 1), &verify)
        .unwrap();
    assert_eq!(ui.creates.load(Ordering::SeqCst), 1);
    assert_eq!(*verified.lock().unwrap(), ["alice"]);
    // rpIdHash || flags (UP|UV|BE|BS|AT) || counter || attested credential data
    assert_eq!(created.authenticator_data[32], 0x5d);
    assert_eq!(
        &created.authenticator_data[37..53],
        &pass_core::AAGUID,
        "AAGUID"
    );

    let meta = agent.passkey_metadata().unwrap();
    assert_eq!(meta.len(), 1);
    assert_eq!(meta[0].rp_id, "example.com");
    assert_eq!(meta[0].rp_name, "Example");
    assert_eq!(meta[0].user_name, "alice");
    assert_eq!(meta[0].user_display_name, "alice");
    assert_eq!(meta[0].credential_id, created.credential_id);
    assert_eq!(meta[0].user_handle, vec![1; 8]);

    // Excluded: the RP already has this credential.
    let mut again = create_request("alice", 1);
    again.exclude_credentials = vec![created.credential_id.clone()];
    assert_eq!(
        agent.platform_passkey_create(again, &yes).unwrap_err().code,
        ErrorCode::InvalidState
    );

    // Sign in: one match, so no picker; the signature covers authData || clientDataHash.
    let hash = vec![9u8; 32];
    let assertion = agent
        .platform_passkey_get(
            PlatformGetRequest {
                rp_id: "example.com".into(),
                client_data_hash: hash.clone(),
                allow_credentials: vec![],
            },
            &verify,
        )
        .unwrap();
    assert!(ui.choices.lock().unwrap().is_empty());
    assert_eq!(assertion.credential_id, created.credential_id);
    assert_eq!(assertion.user_handle, vec![1; 8]);
    assert_eq!(assertion.user_name, "alice");
    assert_eq!(assertion.authenticator_data[32], 0x1d); // UP|UV|BE|BS

    let item = agent
        .vault()
        .unwrap()
        .items()
        .into_iter()
        .find(|i| !i.passkeys.is_empty())
        .unwrap();
    assert_eq!(item.urls, ["https://example.com"]);
    // A sign-in through Windows counts as a use of the login (most used first).
    assert_eq!(agent.vault().unwrap().usage(item.id.clone()).count, 1);
    let spki = {
        use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};
        let sk =
            p256::ecdsa::SigningKey::from_pkcs8_der(&item.passkeys[0].private_key_pkcs8).unwrap();
        sk.verifying_key().to_public_key_der().unwrap()
    };
    let key = VerifyingKey::from_public_key_der(spki.as_bytes()).unwrap();
    let mut message = assertion.authenticator_data.clone();
    message.extend_from_slice(&hash);
    key.verify(
        &message,
        &Signature::from_der(&assertion.signature).unwrap(),
    )
    .unwrap();

    // A second account for the same RP: now the picker decides.
    agent
        .platform_passkey_create(create_request("bob", 2), &yes)
        .unwrap();
    let assertion = agent
        .platform_passkey_get(
            PlatformGetRequest {
                rp_id: "example.com".into(),
                client_data_hash: hash.clone(),
                allow_credentials: vec![],
            },
            &yes,
        )
        .unwrap();
    assert_eq!(*ui.choices.lock().unwrap(), [2]);
    assert_eq!(assertion.user_name, "bob"); // FakeUi picks the last (sorted by user name)

    // The allow list narrows it down to one credential again.
    let assertion = agent
        .platform_passkey_get(
            PlatformGetRequest {
                rp_id: "example.com".into(),
                client_data_hash: hash,
                allow_credentials: vec![created.credential_id.clone()],
            },
            &yes,
        )
        .unwrap();
    assert_eq!(assertion.user_name, "alice");
    assert_eq!(agent.passkey_metadata().unwrap().len(), 2);
}

#[test]
fn refusals_map_to_error_codes() {
    let ui = Arc::new(FakeUi {
        deny: true,
        ..Default::default()
    });
    let (_dir, agent) = setup(ui);
    agent.create_vault("master").unwrap();

    assert_eq!(
        agent
            .platform_passkey_create(create_request("alice", 1), &yes)
            .unwrap_err()
            .code,
        ErrorCode::Cancelled
    );
    let mut rs256_only = create_request("alice", 1);
    rs256_only.algorithms = vec![-257];
    assert_eq!(
        agent
            .platform_passkey_create(rs256_only, &yes)
            .unwrap_err()
            .code,
        ErrorCode::NotSupported
    );
    assert_eq!(
        agent
            .platform_passkey_get(
                PlatformGetRequest {
                    rp_id: "example.com".into(),
                    client_data_hash: vec![0; 32],
                    allow_credentials: vec![],
                },
                &yes,
            )
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    assert_eq!(agent.passkey_metadata(), Some(vec![]));
}

#[test]
fn failed_user_verification_stores_nothing() {
    let (_dir, agent) = setup(Arc::default());
    agent.create_vault("master").unwrap();
    let err = agent
        .platform_passkey_create(create_request("alice", 1), &|_| false)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Cancelled);
    assert_eq!(agent.passkey_metadata(), Some(vec![]));
}
