//! A vault linked to a Passyble account (file version 3): made linked from the start, opened
//! with the account key, and refusing a master password.
#![cfg(feature = "native")]

use std::sync::Arc;
use std::time::Duration;

use pass_agent::{Agent, AgentConfig, Consent, PasskeyChoice, Ui};
use pass_core::{vault_file_access, AccountKey, Item, PassError};

struct NoUi;

impl Ui for NoUi {
    fn request_unlock(&self) -> bool {
        false
    }
    fn confirm_passkey_create(&self, _rp_id: &str, _user_name: &str) -> Consent {
        Consent::Deny
    }
    fn choose_passkey(&self, _rp_id: &str, _options: &[PasskeyChoice]) -> Option<usize> {
        None
    }
    fn show_totp_popup(&self, _item_id: &str, _title: &str) {}
    fn notify_lock_state(&self, _locked: bool) {}
}

#[test]
fn a_linked_vault_is_made_and_opened_with_the_account_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pass.vault");
    let agent = Agent::new(
        AgentConfig::new(path.clone(), "laptop".into(), Duration::from_secs(900)),
        Arc::new(NoUi),
    );
    let ak = AccountKey::generate("acc_demo".into()).unwrap();
    agent.create_vault_for_account(&ak).unwrap();
    agent
        .vault()
        .unwrap()
        .upsert(Item {
            title: "Demo".into(),
            password: "demo-only".into(),
            ..Default::default()
        })
        .unwrap();
    agent.save_and_lock().unwrap();

    let file = agent.vault_file_bytes().unwrap();
    let access = vault_file_access(file).unwrap();
    assert_eq!(access.kind, "account");
    assert_eq!(access.account.as_deref(), Some("acc_demo"));
    assert_eq!(access.ak_id, Some(ak.ak_id()));

    // No master password opens it; another account key neither.
    assert!(agent.unlock("anything at all").is_err());
    let other = AccountKey::generate("acc_demo".into()).unwrap();
    assert!(matches!(
        agent.unlock_with_account_key(&other),
        Err(PassError::InvalidInput(_))
    ));
    assert!(agent.is_locked());

    agent.unlock_with_account_key(&ak).unwrap();
    let titles: Vec<String> = agent.vault().unwrap().items().into_iter().map(|i| i.title).collect();
    assert_eq!(titles, vec!["Demo"]);
    // A second vault can't be made where one is.
    assert!(agent.create_vault_for_account(&ak).is_err());
}
