//! Saves of the vault file racing other writers on the same PC: a sync client (OneDrive, Dropbox,
//! Syncthing) that puts another device's copy in place while the agent saves, a save that fails
//! while a second unlock replaces the vault in memory. Each test is a fixed interleaving.
#![cfg(feature = "native")]

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pass_agent::store::{FileStore, Replaced, Stamp, VaultStore};
use pass_agent::{Agent, AgentConfig, AgentHost, CardFillRequest, Consent, CrossFillRequest};
use pass_agent::{PasskeyChoice, Ui};
use pass_core::{Item, Vault};

const PASSWORD: &str = "master";

struct NoUi;

impl Ui for NoUi {
    fn request_unlock(&self) -> bool {
        false
    }
    fn confirm_passkey_create(&self, _: &str, _: &str) -> Consent {
        Consent::Deny
    }
    fn choose_passkey(&self, _: &str, _: &[PasskeyChoice]) -> Option<usize> {
        None
    }
    fn show_totp_popup(&self, _: &str, _: &str) {}
    fn notify_lock_state(&self, _: bool) {}
    fn copy_to_clipboard(&self, _: &str) -> bool {
        false
    }
    fn confirm_cross_fill(&self, _: &CrossFillRequest) -> Option<bool> {
        None
    }
    fn confirm_card_fill(&self, _: &CardFillRequest) -> Option<bool> {
        None
    }
}

/// The real file store, with a sync client that puts `intruders` in place (one per call) right
/// after the agent has read and merged the file and before its write lands: the moment a lost
/// update would happen.
#[derive(Default)]
struct RacingStore {
    intruders: Mutex<Vec<Vec<u8>>>,
    /// Put a copy in before every write, forever (a file that keeps changing).
    always: Mutex<Option<Vec<u8>>>,
    /// Put a copy in once, right after the next read (while an unlock checks the password).
    after_read: Mutex<Option<Vec<u8>>>,
}

impl RacingStore {
    fn intrude(&self, path: &Path) {
        let next = self.intruders.lock().unwrap().pop();
        let next = next.or_else(|| self.always.lock().unwrap().clone());
        if let Some(bytes) = next {
            // A different modification time than the agent's last write, as a sync client gives
            // the copy it downloads.
            std::thread::sleep(Duration::from_millis(20));
            std::fs::write(path, bytes).unwrap();
        }
    }
}

impl VaultStore for RacingStore {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        let bytes = FileStore.read(path);
        if let Some(copy) = self.after_read.lock().unwrap().take() {
            std::thread::sleep(Duration::from_millis(20));
            std::fs::write(path, copy).unwrap();
        }
        bytes
    }
    fn exists(&self, path: &Path) -> bool {
        FileStore.exists(path)
    }
    fn write(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        FileStore.write(path, bytes)
    }
    fn replace(&self, path: &Path, bytes: &[u8], expected: Option<Stamp>) -> io::Result<Replaced> {
        self.intrude(path);
        FileStore.replace(path, bytes, expected)
    }
    fn stamp(&self, path: &Path) -> Option<Stamp> {
        FileStore.stamp(path)
    }
    fn remove(&self, path: &Path) -> io::Result<()> {
        FileStore.remove(path)
    }
    fn siblings(&self, path: &Path) -> Vec<PathBuf> {
        FileStore.siblings(path)
    }
}

fn agent_with(store: Arc<dyn VaultStore>) -> (tempfile::TempDir, Arc<Agent>, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pass.vault");
    let agent = Agent::with_host(
        AgentConfig::new(path.clone(), "laptop".into(), Duration::from_secs(900)),
        Arc::new(NoUi),
        AgentHost {
            timers: pass_agent::Timers::Thread,
            ..AgentHost::hosted(store)
        },
    );
    (dir, agent, path)
}

fn titles_in(path: &Path) -> Vec<String> {
    let mut titles: Vec<String> =
        Vault::unlock(std::fs::read(path).unwrap(), PASSWORD.into(), "x".into())
            .unwrap()
            .items()
            .into_iter()
            .map(|i| i.title)
            .collect();
    titles.sort();
    titles
}

fn add(vault: &Vault, title: &str) {
    vault
        .upsert(Item {
            title: title.into(),
            password: "pw".into(),
            ..Default::default()
        })
        .unwrap();
}

/// Another device's copy, as a sync client puts it in place: the file on disk plus `title`.
fn phone_copy(path: &Path, title: &str) -> Vec<u8> {
    let phone = Vault::unlock(std::fs::read(path).unwrap(), PASSWORD.into(), "phone".into()).unwrap();
    add(&phone, title);
    phone.serialize().unwrap()
}

/// The agent merged the file and encrypted its own edit; before its rename, OneDrive puts in the
/// phone's copy. The save must see the file changed, merge the copy and write both, or the
/// phone's item is lost.
#[test]
fn a_copy_put_in_place_during_a_save_is_merged_not_overwritten() {
    let store = Arc::new(RacingStore::default());
    let (_dir, agent, path) = agent_with(store.clone());
    agent.create_vault(PASSWORD).unwrap();

    store.intruders.lock().unwrap().push(phone_copy(&path, "From phone"));
    add(&agent.vault().unwrap(), "From laptop");
    agent.save().unwrap();

    assert_eq!(titles_in(&path), ["From laptop", "From phone"]);
    // Nothing is left to save, and the file isn't read again for nothing.
    agent.save().unwrap();
    assert_eq!(titles_in(&path), ["From laptop", "From phone"]);
}

/// The same race while locking (the save runs under the state lock).
#[test]
fn a_copy_put_in_place_while_locking_is_merged_not_overwritten() {
    let store = Arc::new(RacingStore::default());
    let (_dir, agent, path) = agent_with(store.clone());
    agent.create_vault(PASSWORD).unwrap();

    store.intruders.lock().unwrap().push(phone_copy(&path, "From phone"));
    add(&agent.vault().unwrap(), "From laptop");
    agent.save_and_lock().unwrap();
    assert!(agent.is_locked());
    assert_eq!(titles_in(&path), ["From laptop", "From phone"]);
}

/// A file that changes before every write: the save gives up for now without overwriting it,
/// keeps the edit in memory, and writes everything once the file holds still. Locking in that
/// state keeps a copy beside the file instead of dropping the edit.
#[test]
fn a_file_that_keeps_changing_is_never_overwritten_unread() {
    let store = Arc::new(RacingStore::default());
    let (dir, agent, path) = agent_with(store.clone());
    agent.create_vault(PASSWORD).unwrap();

    *store.always.lock().unwrap() = Some(phone_copy(&path, "From phone"));
    add(&agent.vault().unwrap(), "From laptop");
    assert!(agent.save().is_err(), "gives up while the file keeps changing");
    assert_eq!(titles_in(&path), ["From phone"], "the other copy is untouched");

    *store.always.lock().unwrap() = None;
    agent.save().unwrap();
    assert_eq!(titles_in(&path), ["From laptop", "From phone"]);

    // Changing forever while locking: the edit goes to a copy the next unlock merges.
    *store.always.lock().unwrap() = Some(phone_copy(&path, "Second phone item"));
    add(&agent.vault().unwrap(), "Second laptop item");
    agent.save_and_lock().unwrap();
    *store.always.lock().unwrap() = None;
    let stashes = std::fs::read_dir(dir.path())
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("pass-unsaved-"))
        .count();
    assert_eq!(stashes, 1);
    agent.unlock(PASSWORD).unwrap();
    agent.save().unwrap();
    assert_eq!(
        titles_in(&path),
        ["From laptop", "From phone", "Second laptop item", "Second phone item"]
    );
}

/// A copy put in place while the master password is checked (after the unlock read the file,
/// before it finished) is merged by the next save, not mistaken for the file that was read.
#[test]
fn a_copy_put_in_place_during_unlock_is_merged() {
    let store = Arc::new(RacingStore::default());
    let (_dir, agent, path) = agent_with(store.clone());
    agent.create_vault(PASSWORD).unwrap();
    agent.save_and_lock().unwrap();

    *store.after_read.lock().unwrap() = Some(phone_copy(&path, "From phone"));
    agent.unlock(PASSWORD).unwrap();
    add(&agent.vault().unwrap(), "From laptop");
    agent.save().unwrap();
    assert_eq!(titles_in(&path), ["From laptop", "From phone"]);
}

/// A save that failed (a sync client held the file) leaves the edit only in memory; a second
/// unlock while unlocked (Windows Hello after a refresh, a repeated request) must not replace
/// that vault with the older file and drop the edit.
#[test]
fn unlocking_again_keeps_edits_that_were_not_saved() {
    let (dir, agent, path) = agent_with(Arc::new(FileStore));
    agent.create_vault(PASSWORD).unwrap();
    add(&agent.vault().unwrap(), "Unsaved");
    {
        // A folder where the temporary file goes makes the write fail.
        let blocker = path.with_extension("vault.tmp");
        std::fs::create_dir(&blocker).unwrap();
        assert!(agent.save().is_err());
        std::fs::remove_dir(&blocker).unwrap();
    }
    assert!(titles_in(&path).is_empty(), "not in the file yet");

    agent.unlock(PASSWORD).unwrap();
    let titles: Vec<String> = agent.vault().unwrap().items().into_iter().map(|i| i.title).collect();
    assert_eq!(titles, ["Unsaved"]);
    assert_eq!(titles_in(&path), ["Unsaved"], "and written by the unlock's save");
    drop(dir);
}
