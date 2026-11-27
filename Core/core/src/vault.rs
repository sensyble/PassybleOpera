use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{self, Key, KEY_LEN};
use crate::encoding::{b64_decode, b64_encode};
use crate::i18n::tr;
use crate::lookalike::{login_sites, KnownSites, Lookalike, LookalikeCheck};
use crate::matching::{
    android_app_match, normalize_cert, parse_loose, save_tier, url_suggestion_tier,
    MatchQuality,
};
use crate::model::{
    AndroidApp, Item, ItemKind, Passkey, PasswordHistoryEntry, MAX_PASSWORD_HISTORY,
    TRASH_RETENTION_MS,
};
use crate::settings::VaultSettings;
use crate::usage::{
    item_usage, DeviceUsage, ItemUsage, UseCount, MAX_USAGE_DEVICES, USAGE_SYNC_INTERVAL_MS,
};
use crate::{now_ms, PassError, Result};

mod account;
mod contacts;
#[cfg(test)]
pub(crate) use contacts::test_home_pinning;
mod field_merge;
mod pins;
mod shared;
mod teams;
pub use account::{
    account_key_from_vault_file, vault_file_access, AccountRecoveryWrap, VaultAccess, VaultAccountLink,
};
use account::{AccountRecoveryCopy, AccountSlot};
use field_merge::{ItemMeta, Joined, Side, META_KEY};
pub use pins::MAX_PINNED_VAULTS;
pub use teams::AdminRecoveryStatus;
use shared::SharedState;

const FORMAT: &str = "pass-vault";
const VERSION: u32 = 1;
/// The version of a shared vault's file: its key is wrapped for each member instead of by a
/// master password. Clients without sharing refuse it with
/// "vault.unsupported_version" ("needs a newer version of Passyble").
const VERSION_SHARED: u32 = 2;
/// The version of a personal vault linked to a Passyble account: its key is wrapped by the
/// account key instead of by a master password. Older clients refuse it
/// with "vault.unsupported_version".
const VERSION_ACCOUNT: u32 = 3;

/// Argon2id parameters stored in the vault header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub alg: String,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    #[serde(default)]
    pub salt: String,
}

/// Upper bounds on the Argon2id parameters a vault file may ask for. The header is cleartext and
/// comes from synced files: without a cap, a hostile copy could force huge allocations or hours
/// of work (an allocation failure aborts the app on Android).
const MAX_M_KIB: u32 = 1024 * 1024;
const MAX_T: u32 = 20;
const MAX_P: u32 = 16;

impl KdfParams {
    /// Rejects an unknown algorithm and parameters too expensive to run on a phone.
    pub(crate) fn check(&self) -> Result<()> {
        if self.alg != "argon2id" {
            return Err(PassError::Corrupt(tr!("vault.unsupported_kdf")));
        }
        if self.m_kib > MAX_M_KIB
            || !(1..=MAX_T).contains(&self.t)
            || !(1..=MAX_P).contains(&self.p)
        {
            return Err(PassError::Corrupt(tr!("vault.kdf_out_of_range")));
        }
        Ok(())
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            alg: "argon2id".into(),
            m_kib: 64 * 1024,
            t: 3,
            p: 1,
            salt: String::new(),
        }
    }
}

/// The vault file to store, from [`Vault::save_snapshot`], and the generation to pass to
/// [`Vault::mark_saved`] once it is stored.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SaveSnapshot {
    pub bytes: Vec<u8>,
    pub generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MergeStats {
    pub added: u32,
    pub updated: u32,
    pub deleted: u32,
    pub unchanged: u32,
}

/// What one sync (WebDAV, Passyble Server, Google Drive) did.
#[cfg(feature = "sync-core")]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SyncResult {
    /// What the remote copy changed locally.
    pub stats: MergeStats,
    /// Whether the merged vault was uploaded.
    pub uploaded: bool,
    /// Whether the remote file did not exist and was created.
    pub created_remote: bool,
    /// Size in bytes of the remote copy after this sync, when known without an extra request.
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub remote_bytes: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PasskeyMatch {
    pub item_id: String,
    pub item_title: String,
    pub passkey: Passkey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Sealed {
    nonce: String,
    ct: String,
}

/// Local-only sync bookkeeping: what the WebDAV copy looked like after the last successful sync.
/// Stored in the local vault file only, never uploaded, and holds nothing secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SyncState {
    /// [`url_key`] of the WebDAV URL this state belongs to. Another URL starts from scratch.
    pub url: String,
    /// The remote file's ETag, when the server sent one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    /// [`versions_fingerprint`] of the remote file at that ETag.
    pub fingerprint: String,
    /// Size in bytes of the remote file at that ETag, from the last transfer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
}

/// Short, non-reversible key for a WebDAV URL (the local file must not reveal the account).
// Sync only (webdav, gdrive, gdrive-core): unused in builds without it, such as the browser extension's.
#[cfg_attr(not(feature = "sync-core"), allow(dead_code))]
pub(crate) fn url_key(url: &str) -> String {
    b64_encode(&Sha256::digest(url.trim().as_bytes())[..12])
}

/// The items' fingerprint ([`versions_fingerprint`]) with the settings blob's version mixed in
/// when there is one. Without settings it is unchanged, so saved sync states stay valid.
fn with_settings_fingerprint(content: String, settings: Option<(i64, &str)>) -> String {
    let Some((updated_at, device_id)) = settings else {
        return content;
    };
    let mut h = Sha256::new();
    h.update(content.as_bytes());
    h.update(b"\0settings");
    h.update(updated_at.to_be_bytes());
    h.update((device_id.len() as u64).to_be_bytes());
    h.update(device_id.as_bytes());
    b64_encode(&h.finalize()[..16])
}

/// AAD of the settings blob: binds it to its vault and version.
fn settings_aad(vault_id: &str, updated_at: i64, device_id: &str) -> Result<Vec<u8>> {
    let mut aad = b"pass/settings/v1:".to_vec();
    aad.extend(
        serde_json::to_vec(&(vault_id, updated_at, device_id))
            .map_err(|_| PassError::Crypto(tr!("error.internal")))?,
    );
    Ok(aad)
}

/// The vault's settings in the file ([`crate::settings`]): sealed with the vault key, AAD
/// [`settings_aad`]. (`updated_at`, `device_id`) is the blob's version.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct SettingsFile {
    updated_at: i64,
    device_id: String,
    nonce: String,
    ct: String,
}

struct SettingsRecord {
    updated_at: i64,
    device_id: String,
    data: VaultSettings,
    /// Ciphertext cached since the last change.
    sealed: Option<Sealed>,
}

impl SettingsRecord {
    fn version(&self) -> (i64, &str) {
        (self.updated_at, &self.device_id)
    }
}

/// Opens the settings blob; `None` if it is damaged or not this vault's (then ignored, and
/// replaced by this device's own settings with the next save).
fn decrypt_settings(vault_id: &str, vk: &Key, f: &SettingsFile) -> Option<SettingsRecord> {
    let sealed = Sealed {
        nonce: f.nonce.clone(),
        ct: f.ct.clone(),
    };
    let aad = settings_aad(vault_id, f.updated_at, &f.device_id).ok()?;
    let plain = open(vk, &sealed, &aad).ok()??;
    let data: VaultSettings = serde_json::from_slice(&plain).ok()?;
    Some(SettingsRecord {
        updated_at: f.updated_at,
        device_id: f.device_id.clone(),
        data,
        sealed: Some(sealed),
    })
}

/// Hash of the header timestamp and every record's version, sorted by id, and the recovery code's
/// id when there is one. Copies with the same fingerprint hold the same data. Without a recovery
/// code the hash is the one older versions computed, so their saved sync states stay valid.
fn versions_fingerprint<'a>(
    header_updated_at: i64,
    sorted_records: impl Iterator<Item = (&'a str, i64, &'a str)>,
    recovery_id: Option<&str>,
) -> String {
    let mut h = Sha256::new();
    h.update(header_updated_at.to_be_bytes());
    for (id, updated_at, device_id) in sorted_records {
        h.update((id.len() as u64).to_be_bytes());
        h.update(id.as_bytes());
        h.update(updated_at.to_be_bytes());
        h.update((device_id.len() as u64).to_be_bytes());
        h.update(device_id.as_bytes());
    }
    if let Some(id) = recovery_id {
        // A copy without the block (written by an older client) must differ, so a sync that
        // finds the server's copy "already merged" still sees what is missing.
        h.update(b"\0recovery");
        h.update((id.len() as u64).to_be_bytes());
        h.update(id.as_bytes());
    }
    b64_encode(&h.finalize()[..16])
}

/// Separates the usage part of a fingerprint ([`full_fingerprint`]); not in the base64 alphabet.
const USAGE_FP_SEP: char = '|';

/// Hash of every usage blob's version (device id, `updated_at`), sorted by device.
fn usage_fingerprint<'a>(sorted_blobs: impl Iterator<Item = (&'a str, i64)>) -> String {
    let mut h = Sha256::new();
    h.update(b"usage");
    for (device_id, updated_at) in sorted_blobs {
        h.update((device_id.len() as u64).to_be_bytes());
        h.update(device_id.as_bytes());
        h.update(updated_at.to_be_bytes());
    }
    b64_encode(&h.finalize()[..12])
}

/// The fingerprint of a whole copy: the items' ([`versions_fingerprint`]), followed by the usage
/// blobs' when there are any. Without usage it is the items' fingerprint alone.
fn full_fingerprint(content: String, usage: Option<String>) -> String {
    match usage {
        Some(usage) => format!("{content}{USAGE_FP_SEP}{usage}"),
        None => content,
    }
}

/// The (items, usage) parts of a [`full_fingerprint`]; usage `""` when it has none.
fn split_fingerprint(fp: &str) -> (&str, &str) {
    fp.split_once(USAGE_FP_SEP).unwrap_or((fp, ""))
}

/// AAD of a device's usage blob: binds it to its vault, device and version.
fn usage_aad(vault_id: &str, device_id: &str, updated_at: i64) -> Result<Vec<u8>> {
    let mut aad = b"pass/usage/v1:".to_vec();
    aad.extend(
        serde_json::to_vec(&(vault_id, device_id, updated_at))
            .map_err(|_| PassError::Crypto(tr!("error.internal")))?,
    );
    Ok(aad)
}

/// One device's usage counts in the file (see [`crate::usage`]): sealed with the vault key, AAD
/// [`usage_aad`]. Only that device writes it; `updated_at` is its version.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct UsageFile {
    device_id: String,
    updated_at: i64,
    nonce: String,
    ct: String,
}

struct UsageRecord {
    updated_at: i64,
    usage: DeviceUsage,
    /// Ciphertext cached since the last change.
    sealed: Option<Sealed>,
}

/// Opens a usage blob; `None` if it is damaged or not this vault's (it is then ignored: usage is
/// a hint, never worth refusing a vault over).
fn decrypt_usage(vault_id: &str, vk: &Key, u: &UsageFile) -> Option<UsageRecord> {
    let sealed = Sealed {
        nonce: u.nonce.clone(),
        ct: u.ct.clone(),
    };
    let aad = usage_aad(vault_id, &u.device_id, u.updated_at).ok()?;
    let plain = open(vk, &sealed, &aad).ok()??;
    let usage: DeviceUsage = serde_json::from_slice(&plain).ok()?;
    Some(UsageRecord {
        updated_at: u.updated_at,
        usage,
        sealed: Some(sealed),
    })
}

/// The optional recovery code ([`Vault::create_recovery_code`]): the vault key wrapped by a key
/// derived from the code's secret, plus an authenticator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RecoveryFile {
    /// Random id of this code (a new code gets a new id).
    id: String,
    /// When the code was made (Unix ms), for "Recovery code: created …".
    created_at: i64,
    /// Argon2id parameters and salt for the code's secret (bounded like the header's).
    kdf: KdfParams,
    /// The vault key sealed with the recovery key, AAD [`recovery_vk_aad`].
    wrapped_key: Sealed,
    /// An empty message sealed with the vault key, AAD [`recovery_aad`]: binds this block to the
    /// vault and the header's `header_updated_at`, so only a holder of the vault key can add or change
    /// it and an old block can't be put back next to a newer header.
    auth: Sealed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct VaultFile {
    format: String,
    version: u32,
    vault_id: String,
    header_updated_at: i64,
    kdf: KdfParams,
    wrapped_key: Sealed,
    /// The vault id encrypted with the vault key, so a key can be checked even in an empty vault.
    key_check: Sealed,
    items: Vec<RecordFile>,
    /// Local file only; see [`SyncState`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sync: Option<SyncState>,
    /// Local file of a home vault only, never uploaded: the member changes this device signed in
    /// shared vaults that no other copy has confirmed yet ([`Inner::pending_members`]), sealed
    /// with the vault key (AAD [`local_members_aad`]), so a change that loses to a concurrent
    /// one after the app restarted is still applied again. Older clients ignore it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    local_members: Option<Sealed>,
    /// Vault keys replaced by [`Vault::change_password`] with `rotate_key`, each sealed with the
    /// current key (AAD `pass/prevkey/v1:<vault_id>`), so copies encrypted with an older key can
    /// still be merged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    previous_keys: Vec<Sealed>,
    /// Authenticates the header (`header_updated_at`, `kdf`, `wrapped_key`) with the vault key: an
    /// empty message sealed with AAD [`header_aad`]. A merge adopts a newer header only when this
    /// verifies, so whoever stores the file can't swap in a broken or replayed wrapped key and lock
    /// every device out. Files without it never have their headers adopted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    header_auth: Option<Sealed>,
    /// How often each item was used, one sealed blob per device ([`crate::usage`]). Older clients
    /// drop it when they write the file; the devices that recorded the uses upload them again.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    usage: Vec<UsageFile>,
    /// The recovery code, if one was made ([`RecoveryFile`]). Part of the header: it changes with
    /// `header_updated_at` and is merged with it. Older clients drop it; see [`Vault::merge_parsed`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery: Option<RecoveryFile>,
    /// Settings kept in the vault ([`crate::settings`]). Older clients drop it when they write the file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    settings: Option<SettingsFile>,
    /// Shared vaults (version 2) only: `"members"`, the key is wrapped for the members.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    access: Option<String>,
    /// Shared vaults only: who made the vault, the root of trust of the members list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    genesis: Option<crate::share::members::GenesisFile>,
    /// Shared vaults only: the signed members list with the vault key wrapped for each member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    members: Option<crate::share::members::MembersFile>,
    /// Linked vaults (version 3) only: the vault key wrapped by the account key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account: Option<AccountSlot>,
    /// Linked vaults only, optional: the account key wrapped by the account's recovery code, so
    /// the code and a copy of the file open the vault without the account service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_recovery: Option<AccountRecoveryCopy>,
}

impl VaultFile {
    /// Whether this is a shared vault's file (version 2).
    pub(crate) fn is_shared(&self) -> bool {
        self.version == VERSION_SHARED
    }

    /// Whether this is a vault linked to a Passyble account (version 3).
    pub(crate) fn is_linked(&self) -> bool {
        self.version == VERSION_ACCOUNT
    }

    #[cfg_attr(not(feature = "sync-core"), allow(dead_code))]
    pub(crate) fn fingerprint(&self) -> String {
        let mut records: Vec<&RecordFile> = self.items.iter().collect();
        records.sort_by(|a, b| a.id.cmp(&b.id));
        let content = versions_fingerprint(
            self.header_updated_at,
            records
                .into_iter()
                .map(|r| (r.id.as_str(), r.updated_at, r.device_id.as_str())),
            self.recovery.as_ref().map(|r| r.id.as_str()),
        );
        let content = with_settings_fingerprint(
            content,
            self.settings
                .as_ref()
                .map(|s| (s.updated_at, s.device_id.as_str())),
        );
        let content = shared::with_members_fingerprint(
            content,
            self.members.as_ref().map(|m| m.cert.sig.as_str()),
        );
        let mut blobs: Vec<(&str, i64)> = self
            .usage
            .iter()
            .map(|u| (u.device_id.as_str(), u.updated_at))
            .collect();
        blobs.sort();
        full_fingerprint(
            content,
            (!blobs.is_empty()).then(|| usage_fingerprint(blobs.into_iter())),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RecordFile {
    id: String,
    updated_at: i64,
    device_id: String,
    #[serde(default)]
    deleted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ct: Option<String>,
}

struct Record {
    id: String,
    updated_at: i64,
    device_id: String,
    item: Option<Item>,
    /// Ciphertext cached since the last change, so unchanged items keep their bytes.
    sealed: Option<Sealed>,
    /// The version's merge metadata ([`field_merge`]), sealed with the item. `None` for a
    /// tombstone and for a version without valid metadata (written by an older client, a
    /// conflict copy), which merges by the whole-item rule.
    meta: Option<ItemMeta>,
}

impl Record {
    fn version(&self) -> (i64, &str) {
        (self.updated_at, &self.device_id)
    }
}

struct Inner {
    vault_id: String,
    device_id: String,
    vk: Key,
    kdf: KdfParams,
    wrapped_key: Sealed,
    key_check: Sealed,
    header_updated_at: i64,
    records: BTreeMap<String, Record>,
    dirty: bool,
    /// Moves with every [`Inner::mark_dirty`]; see [`Vault::save_snapshot`].
    dirty_generation: u64,
    last_ts: i64,
    sync: Option<SyncState>,
    /// Home vault: unconfirmed member changes by shared vault id (`vault/shared.rs`,
    /// [`VaultFile::local_members`]); local file only.
    pending_members: PendingMembers,
    /// Bumped on every change to the contents (edits and merges); see [`Vault::revision`].
    revision: u64,
    /// Earlier vault keys (after a key rotation) with their sealed form for the file.
    previous_keys: Vec<(Key, Sealed)>,
    /// See [`VaultFile::header_auth`]. `None` when the header could not be vouched for (an older
    /// file unlocked with a device key); it is set again by the next password change.
    header_auth: Option<Sealed>,
    /// Usage counts by device id ([`crate::usage`]).
    usage: BTreeMap<String, UsageRecord>,
    /// Since when (Unix ms) this vault has usage the sync server hasn't seen; for
    /// [`Vault::usage_sync_due`]. In memory only: after a restart it counts from the unlock.
    usage_since: Option<i64>,
    /// The recovery code ([`RecoveryFile`]); only ever one whose `auth` verified (or that this
    /// vault sealed). Its `auth` is re-sealed with every header change ([`Inner::seal_header`]).
    recovery: Option<RecoveryFile>,
    /// Settings kept in the vault ([`crate::settings`]).
    settings: Option<SettingsRecord>,
    /// A shared vault's members list and this device's keys for it (`vault/shared.rs`); `None`
    /// for a personal vault.
    shared: Option<SharedState>,
    /// Opened for viewing only (emergency access with view rights, `vault/teams.rs`): no edits,
    /// no settings, no new master password or recovery code. In memory only.
    read_only: bool,
    /// What searching and the lookalike checks read of the items, kept between calls.
    caches: Caches,
    /// A vault linked to a Passyble account: the vault key wrapped by the account key
    /// (`vault/account.rs`). `kdf` and `wrapped_key` are then placeholders.
    account: Option<AccountSlot>,
    /// A linked vault's copy of the account recovery wrap ([`VaultFile::account_recovery`]).
    account_recovery: Option<AccountRecoveryCopy>,
}

/// Work on the items kept from one call to the next, each for the [`Inner::revision`] it was made
/// at: a search per keystroke and a lookalike check per page don't parse and normalize every
/// item again. In memory only, dropped with the vault on lock; it holds nothing the items don't
/// (no passwords: what search and the checks read).
#[derive(Default)]
struct Caches {
    search: Option<(u64, Arc<SearchDocs>)>,
    sites: Option<(u64, Arc<VaultSites>)>,
}

/// The live items' search fields ([`crate::search::Doc::index`]), by item id.
struct SearchDocs(Vec<(String, crate::search::SearchDoc)>);

/// The live items' sites for the lookalike checks, and the ids of the logins in
/// [`KnownSites::new`]'s order.
struct VaultSites {
    known: KnownSites,
    logins: Vec<String>,
}

/// An unlocked vault. All methods are thread-safe.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct Vault {
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("vault_id", &self.lock().vault_id)
            .finish_non_exhaustive()
    }
}

fn vk_aad(vault_id: &str) -> Vec<u8> {
    format!("pass/vk/v1:{vault_id}").into_bytes()
}

fn key_check_aad(vault_id: &str) -> Vec<u8> {
    format!("pass/keycheck/v1:{vault_id}").into_bytes()
}

/// AAD of records written by older clients: binds the ciphertext to its vault and item, but not
/// to its version. Still read; never written.
fn item_aad(vault_id: &str, item_id: &str) -> Vec<u8> {
    format!("pass/item/v1:{vault_id}:{item_id}").into_bytes()
}

/// AAD of a record (v2): also binds its version and whether it is a tombstone (sealed with an
/// empty message), so whoever stores the file can't mark items deleted or bump timestamps in the
/// cleartext merge metadata.
fn record_aad(
    vault_id: &str,
    item_id: &str,
    updated_at: i64,
    device_id: &str,
    deleted: bool,
) -> Result<Vec<u8>> {
    let mut aad = b"pass/item/v2:".to_vec();
    aad.extend(
        serde_json::to_vec(&(vault_id, item_id, updated_at, device_id, deleted))
            .map_err(|_| PassError::Crypto(tr!("error.internal")))?,
    );
    Ok(aad)
}

fn local_members_aad(vault_id: &str) -> Vec<u8> {
    format!("pass/local-members/v1:{vault_id}").into_bytes()
}

/// Unconfirmed member changes of shared vaults, kept in the home vault: by shared vault id, the
/// digest of the list each change made and the changes, the oldest first.
pub(crate) type PendingMembers = BTreeMap<String, Vec<(String, Vec<crate::share::MemberChange>)>>;

fn prev_key_aad(vault_id: &str) -> Vec<u8> {
    format!("pass/prevkey/v1:{vault_id}").into_bytes()
}

fn header_aad(
    vault_id: &str,
    header_updated_at: i64,
    kdf: &KdfParams,
    wrapped_key: &Sealed,
) -> Result<Vec<u8>> {
    let mut aad = format!("pass/header/v1:{vault_id}:").into_bytes();
    aad.extend(
        serde_json::to_vec(&(header_updated_at, kdf, wrapped_key))
            .map_err(|_| PassError::Crypto(tr!("error.internal")))?,
    );
    Ok(aad)
}

/// Whether `file`'s header carries a valid [`VaultFile::header_auth`] under `vk`.
fn header_authentic(file: &VaultFile, vk: &Key) -> bool {
    let Some(auth) = &file.header_auth else {
        return false;
    };
    let aad = match &file.account {
        Some(slot) => account::header_aad(
            &file.vault_id,
            file.header_updated_at,
            slot,
            file.account_recovery.as_ref(),
        ),
        None => header_aad(
            &file.vault_id,
            file.header_updated_at,
            &file.kdf,
            &file.wrapped_key,
        ),
    };
    aad.and_then(|aad| open(vk, auth, &aad))
    .is_ok_and(|plain| plain.is_some_and(|p| p.is_empty()))
}

/// AAD of the vault key wrapped with a recovery code's key.
fn recovery_vk_aad(vault_id: &str, recovery_id: &str) -> Vec<u8> {
    format!("pass/recovery-vk/v1:{vault_id}:{recovery_id}").into_bytes()
}

/// AAD of [`RecoveryFile::auth`]: the vault, the header version it belongs to and every other
/// field of the block.
fn recovery_aad(vault_id: &str, header_updated_at: i64, r: &RecoveryFile) -> Result<Vec<u8>> {
    let mut aad = format!("pass/recovery/v1:{vault_id}:").into_bytes();
    aad.extend(
        serde_json::to_vec(&(
            header_updated_at,
            &r.id,
            r.created_at,
            &r.kdf,
            &r.wrapped_key,
        ))
        .map_err(|_| PassError::Crypto(tr!("error.internal")))?,
    );
    Ok(aad)
}

/// Whether `r` was sealed by a holder of `vk` for the header at `header_updated_at`.
fn recovery_authentic(vault_id: &str, header_updated_at: i64, r: &RecoveryFile, vk: &Key) -> bool {
    recovery_aad(vault_id, header_updated_at, r)
        .and_then(|aad| open(vk, &r.auth, &aad))
        .is_ok_and(|plain| plain.is_some_and(|p| p.is_empty()))
}

/// `file`'s recovery block if it verifies under `vk` with the file's header version.
fn file_recovery(file: &VaultFile, vk: &Key) -> Option<RecoveryFile> {
    file.recovery
        .as_ref()
        .filter(|r| recovery_authentic(&file.vault_id, file.header_updated_at, r, vk))
        .cloned()
}

/// Opens a file's `previous_keys` with its current key `vk`.
fn open_previous_keys(file: &VaultFile, vk: &Key) -> Result<Vec<(Key, Sealed)>> {
    file.previous_keys
        .iter()
        .map(|sealed| {
            let plain = open(vk, sealed, &prev_key_aad(&file.vault_id))?
                .ok_or_else(|| PassError::Corrupt(tr!("vault.previous_key_failed")))?;
            Ok((key_from_vec(&plain)?, sealed.clone()))
        })
        .collect()
}

fn seal(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Sealed> {
    let (nonce, ct) = crypto::seal(key, plaintext, aad)?;
    Ok(Sealed {
        nonce: b64_encode(&nonce),
        ct: b64_encode(&ct),
    })
}

fn open(key: &[u8; KEY_LEN], sealed: &Sealed, aad: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
    Ok(crypto::open(
        key,
        &b64_decode(&sealed.nonce)?,
        &b64_decode(&sealed.ct)?,
        aad,
    ))
}

/// The two fields every version of the file has, read first: a file from a later version that
/// changed the rest is reported as such, not as "not a vault".
#[derive(Deserialize)]
struct FileProbe {
    format: String,
    version: u32,
}

pub(crate) fn parse_file(file: &[u8]) -> Result<VaultFile> {
    let check = |format: &str, version: u32| {
        if format != FORMAT {
            return Err(PassError::Corrupt(tr!("vault.not_a_vault")));
        }
        if version != VERSION && version != VERSION_SHARED && version != VERSION_ACCOUNT {
            return Err(PassError::Corrupt(tr!("vault.unsupported_version")));
        }
        Ok(())
    };
    // One pass over the file; only one that doesn't read as a vault is read again for its
    // format and version (a later version's file is told apart from something else).
    let mut parsed: VaultFile = match serde_json::from_slice(file) {
        Ok(parsed) => parsed,
        Err(_) => {
            let probe: FileProbe = serde_json::from_slice(file)
                .map_err(|_| PassError::Corrupt(tr!("vault.not_a_vault")))?;
            check(&probe.format, probe.version)?;
            return Err(PassError::Corrupt(tr!("vault.not_a_vault")));
        }
    };
    check(&parsed.format, parsed.version)?;
    if parsed.is_shared() {
        if parsed.access.as_deref() != Some(shared::ACCESS_MEMBERS)
            || parsed.genesis.is_none()
            || parsed.members.is_none()
        {
            return Err(PassError::Corrupt(tr!("vault.not_a_vault")));
        }
        // No password and no recovery code open a shared vault: a block of either kind in the
        // file is ignored, whoever put it there.
        parsed.recovery = None;
        parsed.header_auth = None;
        parsed.account = None;
        parsed.account_recovery = None;
    } else if parsed.is_linked() {
        if parsed.access.as_deref() != Some(account::ACCESS_ACCOUNT) || parsed.account.is_none() {
            return Err(PassError::Corrupt(tr!("vault.not_a_vault")));
        }
        // A linked vault has no password slot, so no vault recovery code either.
        parsed.recovery = None;
        parsed.genesis = None;
        parsed.members = None;
    } else {
        // Members only mean something in a shared vault's file, the account slots in a linked
        // vault's.
        parsed.access = None;
        parsed.genesis = None;
        parsed.members = None;
        parsed.account = None;
        parsed.account_recovery = None;
    }
    Ok(parsed)
}

fn key_from_vec(bytes: &[u8]) -> Result<Key> {
    Key::from_slice(bytes).ok_or(PassError::InvalidPassword)
}

fn check_key(file: &VaultFile, vk: &Key) -> Result<()> {
    match open(vk, &file.key_check, &key_check_aad(&file.vault_id))? {
        Some(plain) if plain.as_slice() == file.vault_id.as_bytes() => Ok(()),
        _ => Err(PassError::InvalidPassword),
    }
}

fn decrypt_records(
    vault_id: &str,
    vk: &Key,
    items: Vec<RecordFile>,
) -> Result<BTreeMap<String, Record>> {
    let mut records = BTreeMap::new();
    for decrypted in decrypt_all(vault_id, vk, items) {
        // The local file: legacy (v1) records are trusted and re-sealed as v2 on the next save.
        let (record, _) = decrypted?;
        records.insert(record.id.clone(), record);
    }
    Ok(records)
}

/// Below this many records one thread decrypts them all; above, up to [`DECRYPT_THREADS`] share
/// the work (a 5 000-item vault opens about three times faster on a phone's four slow cores).
const PARALLEL_DECRYPT_MIN: usize = 512;
const DECRYPT_THREADS: usize = 4;

/// [`decrypt_record`] of every record, in order. The same work split over a few threads for a
/// large vault (none in WebAssembly, which has no threads).
fn decrypt_all(vault_id: &str, vk: &Key, items: Vec<RecordFile>) -> Vec<Result<(Record, bool)>> {
    let one = |r: RecordFile| decrypt_owned(vault_id, vk, r);
    let threads = if cfg!(target_arch = "wasm32") || items.len() < PARALLEL_DECRYPT_MIN {
        1
    } else {
        std::thread::available_parallelism()
            .map_or(1, |n| n.get())
            .min(DECRYPT_THREADS)
    };
    if threads <= 1 {
        return items.into_iter().map(one).collect();
    }
    let chunk = items.len().div_ceil(threads);
    let mut parts: Vec<Vec<RecordFile>> = Vec::with_capacity(threads);
    let mut rest = items;
    while rest.len() > chunk {
        let tail = rest.split_off(chunk);
        parts.push(std::mem::replace(&mut rest, tail));
    }
    parts.push(rest);
    std::thread::scope(|scope| {
        let parts: Vec<_> = parts
            .into_iter()
            .map(|part| scope.spawn(move || part.into_iter().map(one).collect::<Vec<_>>()))
            .collect();
        parts
            .into_iter()
            .flat_map(|part| match part.join() {
                Ok(done) => done,
                Err(panic) => std::panic::resume_unwind(panic),
            })
            .collect()
    })
}

/// Decrypts one record. The flag says whether its version (`updated_at`, `device_id`, `deleted`)
/// is authenticated ([`record_aad`]); `false` for v1 records and tag-less tombstones, which keep
/// no cached ciphertext so they are re-sealed as v2 on the next save.
fn decrypt_record(vault_id: &str, vk: &Key, r: &RecordFile) -> Result<(Record, bool)> {
    decrypt_owned(vault_id, vk, r.clone())
}

/// [`decrypt_record`] of a record read from a file that isn't needed afterwards: its strings
/// move into the record instead of being copied (a large vault's ciphertexts are megabytes).
fn decrypt_owned(vault_id: &str, vk: &Key, mut r: RecordFile) -> Result<(Record, bool)> {
    let aad = record_aad(vault_id, &r.id, r.updated_at, &r.device_id, r.deleted)?;
    let stored = match (r.nonce.take(), r.ct.take()) {
        (Some(nonce), Some(ct)) => Some(Sealed { nonce, ct }),
        _ => None,
    };
    let (item, sealed, authentic) = if r.deleted {
        let authentic = match &stored {
            Some(sealed) => open(vk, sealed, &aad).is_ok_and(|p| p.is_some_and(|p| p.is_empty())),
            None => false,
        };
        (None, stored.filter(|_| authentic), authentic)
    } else {
        // Without a nonce or a ciphertext there is nothing to open.
        let sealed = stored.ok_or_else(|| PassError::Corrupt(tr!("vault.item_failed")))?;
        let (plain, authentic) = match open(vk, &sealed, &aad)? {
            Some(plain) => (plain, true),
            None => (
                open(vk, &sealed, &item_aad(vault_id, &r.id))?
                    .ok_or_else(|| PassError::Corrupt(tr!("vault.item_failed")))?,
                false,
            ),
        };
        let (mut item, meta) =
            item_and_meta(&plain).map_err(|_| PassError::Corrupt(tr!("vault.item_failed")))?;
        item.id = r.id.clone();
        item.updated_at = r.updated_at;
        // Metadata is trusted only on an authenticated version, and only if it names that very
        // version: a client that re-sealed the JSON as it found it under a new version (keeping
        // metadata it doesn't understand) must not have its edit merged against a stale base.
        let meta = meta
            .filter(|_| authentic)
            .filter(|m| m.valid_for((r.updated_at, &r.device_id)));
        (Some((item, meta)), authentic.then_some(sealed), authentic)
    };
    let (item, meta) = match item {
        Some((item, meta)) => (Some(item), meta),
        None => (None, None),
    };
    Ok((
        Record {
            id: r.id,
            updated_at: r.updated_at,
            device_id: r.device_id,
            item,
            sealed,
            meta,
        },
        authentic,
    ))
}

/// [`Item::from_stored_json`] and [`stored_meta`] of a sealed item's JSON in one pass, so opening a
/// large vault reads each item once. The metadata is `None` when it is missing or doesn't parse,
/// as [`stored_meta`] reads it; it never fails the item.
fn item_and_meta(plain: &[u8]) -> serde_json::Result<(Item, Option<ItemMeta>)> {
    use serde::de::{DeserializeSeed, IntoDeserializer, MapAccess, Visitor};

    /// The item's own map, with the metadata's key and value taken out on the way.
    struct Intercept<'m, A> {
        map: A,
        meta: &'m mut Option<ItemMeta>,
        at_meta: bool,
    }

    impl<'de, A: MapAccess<'de>> MapAccess<'de> for Intercept<'_, A> {
        type Error = A::Error;

        fn next_key_seed<K: DeserializeSeed<'de>>(
            &mut self,
            seed: K,
        ) -> Result<Option<K::Value>, A::Error> {
            match self.map.next_key_seed(KeySeed(seed))? {
                Some((key, at_meta)) => {
                    self.at_meta = at_meta;
                    Ok(Some(key))
                }
                None => Ok(None),
            }
        }

        fn next_value_seed<V: DeserializeSeed<'de>>(
            &mut self,
            seed: V,
        ) -> Result<V::Value, A::Error> {
            if !self.at_meta {
                return self.map.next_value_seed(seed);
            }
            // `Item` has no field of this name: it skips the value, which went to `meta`.
            let value: serde_json::Value = self.map.next_value()?;
            *self.meta = serde_json::from_value::<Option<ItemMeta>>(value)
                .ok()
                .flatten();
            seed.deserialize(().into_deserializer())
        }
    }

    /// A key for `Item`, and whether it is [`META_KEY`].
    struct KeySeed<K>(K);

    impl<'de, K: DeserializeSeed<'de>> DeserializeSeed<'de> for KeySeed<K> {
        type Value = (K::Value, bool);

        fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            d.deserialize_str(self)
        }
    }

    impl<'de, K: DeserializeSeed<'de>> Visitor<'de> for KeySeed<K> {
        type Value = (K::Value, bool);

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a field name")
        }

        fn visit_str<E: serde::de::Error>(self, key: &str) -> Result<Self::Value, E> {
            let at_meta = key == META_KEY;
            self.0
                .deserialize(key.into_deserializer())
                .map(|k| (k, at_meta))
        }
    }

    struct ItemSeed<'m>(&'m mut Option<ItemMeta>);

    impl<'de> DeserializeSeed<'de> for ItemSeed<'_> {
        type Value = Item;

        fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Item, D::Error> {
            d.deserialize_map(self)
        }
    }

    impl<'de> Visitor<'de> for ItemSeed<'_> {
        type Value = Item;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("an item")
        }

        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Item, A::Error> {
            Item::deserialize(serde::de::value::MapAccessDeserializer::new(Intercept {
                map,
                meta: self.0,
                at_meta: false,
            }))
        }
    }

    let mut meta = None;
    let mut de = serde_json::Deserializer::from_slice(plain);
    let item = ItemSeed(&mut meta).deserialize(&mut de)?;
    de.end()?;
    Ok((item.read_back(), meta))
}

/// The merge metadata in a sealed item's JSON ([`META_KEY`]), if there is one that parses.
#[cfg(test)]
fn stored_meta(plain: &[u8]) -> Option<ItemMeta> {
    #[derive(Deserialize)]
    struct WithMeta {
        #[serde(default)]
        merge: Option<ItemMeta>,
    }
    serde_json::from_slice::<WithMeta>(plain).ok()?.merge
}

/// The JSON sealed for a live item version: the item as older clients read it
/// ([`Item::stored_json`]) plus its merge metadata under [`META_KEY`].
fn sealed_item_json(item: &Item, meta: Option<&ItemMeta>) -> serde_json::Result<Vec<u8>> {
    let Some(meta) = meta else {
        return item.stored_json();
    };
    let mut value = item.stored_value()?;
    if let Some(obj) = value.as_object_mut() {
        obj.insert(META_KEY.into(), serde_json::to_value(meta)?);
    }
    serde_json::to_vec(&value)
}

/// The passwords of `lost`, a version of an item that loses a merge to `kept`, that `kept` shows
/// no sign of having seen: its current password (filed under when it was set) and entries of its
/// password history, as history entries for `kept`.
///
/// Versions without merge metadata ([`field_merge`]) merge as whole items, so without this, two
/// devices that edit one item between syncs (one of them an older client) lose the earlier
/// device's change, which may be the only copy of a new password the site now expects. An edit
/// made on top of `lost` always shows its passwords ([`Vault::upsert`] moves a replaced password
/// into the history, and merging joins histories), so a password that is neither the winner's
/// nor in its history was set where the winner's writer couldn't see it. A full history drops
/// its oldest entries, so a password older than every entry still kept is left out.
fn unseen_passwords(lost: &Item, kept: &Item) -> Vec<PasswordHistoryEntry> {
    let seen = |password: &str| {
        password.is_empty()
            || password == kept.password
            || kept.password_history.iter().any(|h| h.password == password)
    };
    let oldest = (kept.password_history.len() >= MAX_PASSWORD_HISTORY)
        .then(|| kept.password_history.iter().map(|h| h.replaced_at).min())
        .flatten();
    let dropped = |at: i64| oldest.is_some_and(|oldest| at < oldest);
    let mut unseen = Vec::new();
    let set_at = if lost.password_changed_at > 0 {
        lost.password_changed_at
    } else {
        lost.updated_at
    };
    if !seen(&lost.password) && !dropped(set_at) {
        // Filed under when it was set: the same on every device and for every later version
        // of `lost` (a rescue elsewhere makes a new version of it, with a new `updated_at`).
        unseen.push(PasswordHistoryEntry {
            password: lost.password.clone(),
            replaced_at: set_at,
        });
    }
    for h in &lost.password_history {
        if !seen(&h.password)
            && !dropped(h.replaced_at)
            && !unseen.iter().any(|u: &PasswordHistoryEntry| u.password == h.password)
        {
            unseen.push(h.clone());
        }
    }
    unseen
}

/// Marks the version a merge makes to keep a losing version's passwords ([`unseen_passwords`]):
/// it has the winning version's `updated_at` and the winner's device id with this character
/// added. That is the very next version after the winner's in the merge order (no device id
/// sorts between `d` and `d` followed by U+0000), so the rescue wins over the winner and over
/// nothing else: every version that beats the winner (an edit made on top of it, a deletion of
/// it, a concurrent version that wins the tie) beats the rescue too, and the outcome doesn't
/// depend on which of them a device sees first. Two devices that rescue into the same winner
/// make the same version; if they rescued different passwords, the next merge joins them into
/// the version after that one.
const RESCUE_MARK: char = '\u{0}';

fn is_rescue(device_id: &str) -> bool {
    device_id.ends_with(RESCUE_MARK)
}

/// `kept` with the `rescued` passwords in its history: newest first by date (then by password,
/// so every device that rescues the same passwords ends with the same list), at most
/// [`MAX_PASSWORD_HISTORY`].
fn with_rescued(kept: &Item, rescued: &[PasswordHistoryEntry]) -> Item {
    let mut item = kept.clone();
    for r in rescued {
        if r.password != item.password && !item.password_history.iter().any(|h| h.password == r.password) {
            item.password_history.push(r.clone());
        }
    }
    item.password_history
        .sort_by(|a, b| b.replaced_at.cmp(&a.replaced_at).then_with(|| a.password.cmp(&b.password)));
    item.password_history.truncate(MAX_PASSWORD_HISTORY);
    item
}

impl Inner {
    fn next_ts(&mut self, at_least: i64) -> i64 {
        // Saturating: a record from a far-future clock (or a hostile file) must not overflow.
        let ts = now_ms()
            .max(self.last_ts.saturating_add(1))
            .max(at_least.saturating_add(1));
        self.last_ts = ts;
        ts
    }

    /// Items that are neither deleted nor in the trash.
    fn live_items(&self) -> impl Iterator<Item = &Item> {
        self.records
            .values()
            .filter_map(|r| r.item.as_ref())
            .filter(|i| !i.is_trashed())
    }

    /// The live items' search fields, made again only after a change ([`Caches`]).
    fn search_docs(&mut self) -> Arc<SearchDocs> {
        let revision = self.revision;
        if let Some((at, docs)) = &self.caches.search {
            if *at == revision {
                return docs.clone();
            }
        }
        let docs = Arc::new(SearchDocs(
            self.live_items()
                .map(|i| (i.id.clone(), crate::search::Doc::of_item(i).index()))
                .collect(),
        ));
        self.caches.search = Some((revision, docs.clone()));
        docs
    }

    /// The live items' sites for the lookalike checks, made again only after a change
    /// ([`Caches`]).
    fn vault_sites(&mut self) -> Arc<VaultSites> {
        let revision = self.revision;
        if let Some((at, sites)) = &self.caches.sites {
            if *at == revision {
                return sites.clone();
            }
        }
        let all: Vec<Vec<String>> = self
            .live_items()
            .map(|i| login_sites(&i.urls, &i.android_apps))
            .collect();
        let (ids, logins): (Vec<String>, Vec<Vec<String>>) = self
            .live_items()
            .filter(|i| i.kind == ItemKind::Login)
            .map(|i| (i.id.clone(), login_sites(&i.urls, &i.android_apps)))
            .unzip();
        let sites = Arc::new(VaultSites {
            known: KnownSites::new(&all, &logins),
            logins: ids,
        });
        self.caches.sites = Some((revision, sites.clone()));
        sites
    }

    fn trashed_items(&self) -> impl Iterator<Item = &Item> {
        self.records
            .values()
            .filter_map(|r| r.item.as_ref())
            .filter(|i| i.is_trashed())
    }

    /// The item `id` if it is live (not deleted, not in the trash).
    fn live(&self, id: &str) -> Option<&Item> {
        self.records
            .get(id)
            .and_then(|r| r.item.as_ref())
            .filter(|i| !i.is_trashed())
    }

    /// Replaces item `id` (live or trashed) with a tombstone: a deletion that syncs. `false` if
    /// there is no such item.
    ///
    /// The tombstone's version is the deleted record's plus one millisecond, not the current time.
    /// It still replaces the version it deletes (and every older copy), but an edit another device
    /// made to that version without seeing the deletion (a restore from the trash, a new password)
    /// is later and wins: the item comes back with that edit instead of the edit being deleted
    /// unseen. This matters most for the automatic purge: a laptop opened after a month purges its
    /// trash before it syncs, and must not delete an item a phone restored and kept using
    /// meanwhile.
    fn tombstone(&mut self, id: &str) -> bool {
        let prev_ts = match self.records.get(id) {
            Some(r) if r.item.is_some() => r.updated_at,
            _ => return false,
        };
        let ts = prev_ts.saturating_add(1);
        self.last_ts = self.last_ts.max(ts);
        let device_id = self.device_id.clone();
        let record = self.records.get_mut(id).expect("checked above");
        record.item = None;
        record.sealed = None;
        record.meta = None;
        record.updated_at = ts;
        record.device_id = device_id;
        self.changed();
        true
    }

    /// Purges items that have been in the trash for [`TRASH_RETENTION_MS`] at `now`. Every
    /// device does the same, so the tombstones converge whichever writes first.
    fn purge_expired(&mut self, now: i64) -> u32 {
        // A viewer's device can't upload its deletions; the editors' devices purge.
        if self.check_writable().is_err() {
            return 0;
        }
        let expired: Vec<String> = self
            .trashed_items()
            .filter(|i| {
                i.trashed_at
                    .is_some_and(|at| now.saturating_sub(at) >= TRASH_RETENTION_MS)
            })
            .map(|i| i.id.clone())
            .collect();
        let mut purged = 0;
        for id in expired {
            if self.tombstone(&id) {
                purged += 1;
            }
        }
        purged
    }

    fn put(&mut self, mut item: Item) -> Item {
        let previous = self.records.get(&item.id);
        let prev_ts = previous.map_or(0, |r| r.updated_at);
        if item.created_at == 0 {
            item.created_at = previous
                .and_then(|r| r.item.as_ref())
                .map_or(0, |i| i.created_at);
        }
        let ts = self.next_ts(prev_ts);
        if item.created_at == 0 {
            item.created_at = ts;
        }
        item.updated_at = ts;
        // Which parts this edit changed, against the version it replaces (field_merge).
        let stamp = (ts, self.device_id.clone());
        let meta = match self.records.get(&item.id) {
            Some(Record {
                item: Some(prev),
                meta,
                updated_at,
                device_id,
                ..
            }) => ItemMeta::after_edit(prev, meta.as_ref(), (*updated_at, device_id), &item, stamp),
            _ => ItemMeta::new_item(stamp),
        };
        let record = Record {
            id: item.id.clone(),
            updated_at: ts,
            device_id: self.device_id.clone(),
            item: Some(item.clone()),
            sealed: None,
            meta: Some(meta),
        };
        self.records.insert(item.id.clone(), record);
        self.changed();
        item
    }

    /// Merges `remote`, a version of an item from another copy of the vault, into this vault's
    /// version part by part ([`field_merge`]), when both are live versions with merge metadata
    /// and differ. Adds a conflict copy for a version that lost a concurrent change of a field.
    /// `false` when that doesn't apply (a tombstone, a new item, the same version, a version
    /// without metadata or one that isn't authenticated): the caller merges by the whole-item
    /// rule.
    fn join_record(
        &mut self,
        file: &VaultFile,
        key: &Key,
        same_key: bool,
        remote: &RecordFile,
        stats: &mut MergeStats,
    ) -> bool {
        if remote.deleted {
            return false;
        }
        let Some(local) = self.records.get(&remote.id) else {
            return false;
        };
        if local.version() == (remote.updated_at, remote.device_id.as_str()) {
            return false;
        }
        let (Some(local_item), Some(local_meta)) = (local.item.as_ref(), local.meta.as_ref())
        else {
            return false;
        };
        let Ok((mut theirs, true)) = decrypt_record(&file.vault_id, key, remote) else {
            return false;
        };
        let (Some(their_item), Some(their_meta)) = (theirs.item.as_ref(), theirs.meta.as_ref())
        else {
            return false;
        };
        let Some(outcome) = field_merge::join(
            &remote.id,
            &Side {
                version: local.version(),
                item: local_item,
                meta: local_meta,
            },
            &Side {
                version: (theirs.updated_at, &theirs.device_id),
                item: their_item,
                meta: their_meta,
            },
        ) else {
            return false;
        };
        // A passkey's WebAuthn PRF secret never changes (src/prf.rs): whatever the join takes
        // from their version, a passkey this vault has keeps our key.
        let ours = local_item.passkeys.clone();
        let record = match outcome.joined {
            Joined::Left => {
                stats.unchanged += 1;
                None
            }
            Joined::Right => {
                let kept = theirs
                    .item
                    .as_mut()
                    .is_some_and(|i| crate::prf::keep_prf_secrets(&ours, &mut i.passkeys));
                if !same_key || kept {
                    // Re-encrypted with the current key on the next save.
                    theirs.sealed = None;
                }
                Some(theirs)
            }
            Joined::New { mut item, meta } => {
                crate::prf::keep_prf_secrets(&ours, &mut item.passkeys);
                Some(Record {
                    id: remote.id.clone(),
                    updated_at: meta.v.0,
                    device_id: meta.v.1.clone(),
                    item: Some(*item),
                    sealed: None,
                    meta: Some(meta),
                })
            }
        };
        if let Some(record) = record {
            stats.updated += 1;
            self.last_ts = self.last_ts.max(record.updated_at);
            self.records.insert(record.id.clone(), record);
            self.changed();
        }
        for mut copy in outcome.copies {
            // Made once: a copy this vault has (or had, and the user deleted) stays as it is.
            if self.records.contains_key(&copy.id) {
                continue;
            }
            crate::prf::keep_prf_secrets(&ours, &mut copy.item.passkeys);
            stats.added += 1;
            self.last_ts = self.last_ts.max(copy.version.0);
            self.records.insert(
                copy.id.clone(),
                Record {
                    id: copy.id,
                    updated_at: copy.version.0,
                    device_id: copy.version.1,
                    item: Some(copy.item),
                    sealed: None,
                    meta: None,
                },
            );
            self.changed();
        }
        true
    }

    /// `usage` without counts for items this vault knows are deleted.
    fn live_usage(&self, usage: &DeviceUsage) -> DeviceUsage {
        let mut live = usage.clone();
        live.items
            .retain(|id, _| !self.records.get(id).is_some_and(|r| r.item.is_none()));
        live
    }

    /// Merges the usage blobs of `remote` (sealed with `remote_key`) per device, as a grow-only
    /// counter: the blob that has everything the other has is kept; if each has counts the other
    /// lacks, they are merged per item (larger count, later use) into a new version. Damaged blobs
    /// are ignored. Marks the vault dirty but not [`Vault::revision`].
    fn merge_usage(&mut self, remote: &VaultFile, remote_key: &Key, same_key: bool) {
        let mut changed = false;
        for u in &remote.usage {
            let local = self.usage.get(&u.device_id);
            // Skip only the very same blob. The same `updated_at` is no proof of the same counts:
            // a device restored from an old file and used again can stamp a different blob with
            // a version it already wrote (timestamps are milliseconds, coarser on some clocks).
            if local.is_some_and(|l| {
                l.updated_at == u.updated_at
                    && l.sealed
                        .as_ref()
                        .is_some_and(|s| s.nonce == u.nonce && s.ct == u.ct)
            }) {
                continue;
            }
            let Some(mut theirs) = decrypt_usage(&remote.vault_id, remote_key, u) else {
                continue;
            };
            if !same_key {
                theirs.sealed = None;
            }
            self.last_ts = self.last_ts.max(theirs.updated_at);
            let ours = local.map(|l| (l.updated_at, self.live_usage(&l.usage)));
            let adopted = match ours {
                None => Some(theirs),
                Some((ours_at, ours)) => {
                    let theirs_live = self.live_usage(&theirs.usage);
                    let mut merged = ours.clone();
                    merged.merge(&theirs_live);
                    match (merged == ours, merged == theirs_live) {
                        (true, true) => (theirs.updated_at > ours_at).then_some(theirs),
                        (false, true) => Some(theirs),
                        (true, false) if theirs.updated_at == ours_at => {
                            // Ours has more under the same version: give it a new one, so the
                            // fingerprint changes and the other copies get the larger counts.
                            let at = self.next_ts(ours_at);
                            if let Some(l) = self.usage.get_mut(&u.device_id) {
                                l.updated_at = at;
                                l.sealed = None;
                            }
                            changed = true;
                            None
                        }
                        (true, false) => None,
                        (false, false) => {
                            let at = self.next_ts(ours_at.max(theirs.updated_at));
                            Some(UsageRecord {
                                updated_at: at,
                                usage: merged,
                                sealed: None,
                            })
                        }
                    }
                }
            };
            if let Some(record) = adopted {
                self.usage.insert(u.device_id.clone(), record);
                changed = true;
            }
        }
        if changed {
            self.prune_usage();
            self.mark_dirty();
        }
    }

    /// Merges the settings blob of `remote` (sealed with `remote_key`) per key, the later version
    /// winning ([`VaultSettings::merge`]). When each copy has keys the other lacks, the merge gets a
    /// new version so every copy converges. A damaged blob is ignored.
    fn merge_settings(&mut self, remote: &VaultFile, remote_key: &Key, same_key: bool) {
        let Some(f) = &remote.settings else {
            return;
        };
        if self.settings.as_ref().is_some_and(|l| {
            l.version() == (f.updated_at, f.device_id.as_str())
                && l.sealed
                    .as_ref()
                    .is_some_and(|s| s.nonce == f.nonce && s.ct == f.ct)
        }) {
            return;
        }
        let Some(mut theirs) = decrypt_settings(&remote.vault_id, remote_key, f) else {
            return;
        };
        if !same_key {
            theirs.sealed = None;
        }
        self.last_ts = self
            .last_ts
            .max(theirs.updated_at)
            .max(theirs.data.latest());
        let adopted = match &self.settings {
            None => Some(theirs),
            Some(ours) => {
                let mut merged = ours.data.clone();
                merged.merge(&theirs.data);
                let ours_version = (ours.updated_at, ours.device_id.clone());
                let theirs_version = (theirs.updated_at, theirs.device_id.clone());
                match (merged == ours.data, merged == theirs.data) {
                    (true, true) => (theirs_version > ours_version).then_some(theirs),
                    (false, true) => Some(theirs),
                    (true, false) if theirs_version == ours_version => {
                        // Ours has more under the same version: give it a new one.
                        let at = self.next_ts(ours_version.0);
                        let device_id = self.device_id.clone();
                        if let Some(s) = self.settings.as_mut() {
                            s.updated_at = at;
                            s.device_id = device_id;
                            s.sealed = None;
                        }
                        self.changed();
                        None
                    }
                    (true, false) => None,
                    (false, false) => {
                        let at = self.next_ts(ours_version.0.max(theirs_version.0));
                        Some(SettingsRecord {
                            updated_at: at,
                            device_id: self.device_id.clone(),
                            data: merged,
                            sealed: None,
                        })
                    }
                }
            }
        };
        if let Some(record) = adopted {
            self.settings = Some(record);
            self.changed();
        }
    }

    /// Sets (or with `None` removes) setting `key`; `false` when that changes nothing.
    fn set_setting(&mut self, key: &str, value: Option<String>) -> bool {
        let previous = self
            .settings
            .as_ref()
            .map_or(0, |s| s.updated_at.max(s.data.latest()));
        let unchanged = match &self.settings {
            Some(s) => s.data.get(key) == value.as_deref(),
            None => value.is_none(),
        };
        if unchanged {
            return false;
        }
        let at = self.next_ts(previous);
        let device_id = self.device_id.clone();
        let record = self.settings.get_or_insert_with(|| SettingsRecord {
            updated_at: at,
            device_id: device_id.clone(),
            data: VaultSettings::default(),
            sealed: None,
        });
        record.data.set(key, value, at, &device_id);
        record.updated_at = at;
        record.device_id = device_id;
        record.sealed = None;
        self.changed();
        true
    }

    fn setting(&self, key: &str) -> Option<&str> {
        self.settings.as_ref().and_then(|s| s.data.get(key))
    }

    /// Replaces the vault key with `new_vk`: the current key, the earlier ones and `extra` (keys
    /// of other copies, from a shared vault's merge) become previous keys sealed with the new
    /// one, so copies encrypted with any of them still merge; every item, the usage and the
    /// settings are re-encrypted on the next save.
    fn replace_key(&mut self, new_vk: Key, extra: Vec<Key>) -> Result<()> {
        let vault_id = self.vault_id.clone();
        let key_check = seal(&new_vk, vault_id.as_bytes(), &key_check_aad(&vault_id))?;
        let mut previous: Vec<(Key, Sealed)> = Vec::with_capacity(self.previous_keys.len() + 1);
        for key in self
            .previous_keys
            .iter()
            .map(|(k, _)| k.clone())
            .chain(std::iter::once(self.vk.clone()))
            .chain(extra)
        {
            if key.as_slice() == new_vk.as_slice()
                || previous.iter().any(|(k, _)| k.as_slice() == key.as_slice())
            {
                continue;
            }
            let sealed = seal(&new_vk, key.as_slice(), &prev_key_aad(&vault_id))?;
            previous.push((key, sealed));
        }
        self.previous_keys = previous;
        self.vk = new_vk;
        self.key_check = key_check;
        for record in self.records.values_mut() {
            record.sealed = None;
        }
        for record in self.usage.values_mut() {
            record.sealed = None;
        }
        if let Some(settings) = self.settings.as_mut() {
            settings.sealed = None;
        }
        Ok(())
    }

    /// Authenticates the current header with the current vault key.
    fn seal_header(&mut self) -> Result<()> {
        let aad = match &self.account {
            Some(slot) => account::header_aad(
                &self.vault_id,
                self.header_updated_at,
                slot,
                self.account_recovery.as_ref(),
            )?,
            None => header_aad(
                &self.vault_id,
                self.header_updated_at,
                &self.kdf,
                &self.wrapped_key,
            )?,
        };
        self.header_auth = Some(seal(&self.vk, b"", &aad)?);
        if let Some(r) = &self.recovery {
            let aad = recovery_aad(&self.vault_id, self.header_updated_at, r)?;
            let auth = seal(&self.vk, b"", &aad)?;
            if let Some(r) = self.recovery.as_mut() {
                r.auth = auth;
            }
        }
        Ok(())
    }

    /// A new header version (a recovery code made or removed): a newer `header_updated_at`, so
    /// merges spread it like a password change, sealed again.
    fn bump_header(&mut self) -> Result<()> {
        let header_ts = self.header_updated_at;
        self.header_updated_at = self.next_ts(header_ts);
        self.seal_header()?;
        self.changed();
        Ok(())
    }

    /// Marks a change to the contents: to be saved, and (via the fingerprint) to be synced.
    fn changed(&mut self) {
        self.mark_dirty();
        self.revision = self.revision.wrapping_add(1);
    }

    /// Marks something to be saved (an edit, a merge, usage, the sync state). Every call moves
    /// [`Inner::dirty_generation`], so [`Vault::mark_saved`] can tell whether anything changed
    /// after the snapshot that was written.
    fn mark_dirty(&mut self) {
        self.dirty = true;
        self.dirty_generation = self.dirty_generation.wrapping_add(1);
    }

    fn fingerprint(&self) -> String {
        let content = versions_fingerprint(
            self.header_updated_at,
            self.records
                .values()
                .map(|r| (r.id.as_str(), r.updated_at, r.device_id.as_str())),
            self.recovery.as_ref().map(|r| r.id.as_str()),
        );
        let content =
            with_settings_fingerprint(content, self.settings.as_ref().map(SettingsRecord::version));
        let content = shared::with_members_fingerprint(
            content,
            self.shared.as_ref().map(|s| s.members.cert.sig.as_str()),
        );
        full_fingerprint(
            content,
            (!self.usage.is_empty()).then(|| {
                usage_fingerprint(self.usage.iter().map(|(d, u)| (d.as_str(), u.updated_at)))
            }),
        )
    }

    /// Whether the (items, usage) parts of this vault's fingerprint differ from the last sync's.
    fn unsynced(&self) -> (bool, bool) {
        let Some(state) = &self.sync else {
            return (true, !self.usage.is_empty());
        };
        let ours = self.fingerprint();
        let (content, usage) = split_fingerprint(&ours);
        let (synced_content, synced_usage) = split_fingerprint(&state.fingerprint);
        (content != synced_content, usage != synced_usage)
    }

    /// Clears [`Inner::usage_since`] once the server has all usage.
    #[cfg_attr(not(feature = "sync-core"), allow(dead_code))]
    fn note_usage_synced(&mut self) {
        if self.usage_since.is_some() && !self.unsynced().1 {
            self.usage_since = None;
        }
    }

    /// Every device's counts for item `id`, summed.
    fn usage_of(&self, id: &str) -> ItemUsage {
        item_usage(self.usage.values().filter_map(|u| u.usage.items.get(id)))
    }

    /// Keeps the usage of the [`MAX_USAGE_DEVICES`] devices that wrote theirs last. The same rule
    /// on every device (no preference for its own), so they all keep the same ones and never
    /// upload each other's pruning back and forth. A device that records a use is the latest.
    fn prune_usage(&mut self) {
        if self.usage.len() <= MAX_USAGE_DEVICES {
            return;
        }
        let mut order: Vec<(i64, String)> = self
            .usage
            .iter()
            .map(|(d, u)| (u.updated_at, d.clone()))
            .collect();
        order.sort_by(|a, b| b.cmp(a));
        for (_, device) in order.into_iter().skip(MAX_USAGE_DEVICES) {
            self.usage.remove(&device);
        }
    }

    /// The vault file. `local`: include the local-only [`SyncState`] (the file on this device),
    /// otherwise leave it out (the copy uploaded for other devices).
    fn encode_file(&mut self, local: bool) -> Result<Vec<u8>> {
        let mut file = self.seal_all()?;
        if local {
            file.sync = self.sync.clone();
            if !self.pending_members.is_empty() {
                let json = Zeroizing::new(
                    serde_json::to_vec(&self.pending_members)
                        .map_err(|_| PassError::Crypto(tr!("error.internal")))?,
                );
                file.local_members =
                    Some(seal(&self.vk, &json, &local_members_aad(&self.vault_id))?);
            }
        }
        serde_json::to_vec(&file).map_err(|_| PassError::Crypto(tr!("error.internal")))
    }

    fn seal_all(&mut self) -> Result<VaultFile> {
        let mut items = Vec::with_capacity(self.records.len());
        for record in self.records.values_mut() {
            let deleted = record.item.is_none();
            if record.sealed.is_none() {
                // A tombstone seals an empty message: it authenticates the deletion.
                let plain = Zeroizing::new(match &record.item {
                    Some(item) => sealed_item_json(item, record.meta.as_ref())
                        .map_err(|_| PassError::Crypto(tr!("error.internal")))?,
                    None => Vec::new(),
                });
                let aad = record_aad(
                    &self.vault_id,
                    &record.id,
                    record.updated_at,
                    &record.device_id,
                    deleted,
                )?;
                record.sealed = Some(seal(&self.vk, &plain, &aad)?);
            }
            let (nonce, ct) = match &record.sealed {
                Some(sealed) => (Some(sealed.nonce.clone()), Some(sealed.ct.clone())),
                None => (None, None),
            };
            items.push(RecordFile {
                id: record.id.clone(),
                updated_at: record.updated_at,
                device_id: record.device_id.clone(),
                deleted,
                nonce,
                ct,
            });
        }
        let mut usage = Vec::with_capacity(self.usage.len());
        for (device_id, record) in self.usage.iter_mut() {
            if record.sealed.is_none() {
                if *device_id == self.device_id {
                    // This device's counts for deleted items are of no use to anyone.
                    let records = &self.records;
                    record
                        .usage
                        .items
                        .retain(|id, _| !records.get(id).is_some_and(|r| r.item.is_none()));
                }
                let plain = Zeroizing::new(
                    serde_json::to_vec(&record.usage)
                        .map_err(|_| PassError::Crypto(tr!("error.internal")))?,
                );
                let aad = usage_aad(&self.vault_id, device_id, record.updated_at)?;
                record.sealed = Some(seal(&self.vk, &plain, &aad)?);
            }
            let sealed = record.sealed.as_ref().expect("sealed above");
            usage.push(UsageFile {
                device_id: device_id.clone(),
                updated_at: record.updated_at,
                nonce: sealed.nonce.clone(),
                ct: sealed.ct.clone(),
            });
        }
        let settings = match self.settings.as_mut() {
            Some(record) => {
                if record.sealed.is_none() {
                    let plain = Zeroizing::new(
                        serde_json::to_vec(&record.data)
                            .map_err(|_| PassError::Crypto(tr!("error.internal")))?,
                    );
                    let aad = settings_aad(&self.vault_id, record.updated_at, &record.device_id)?;
                    record.sealed = Some(seal(&self.vk, &plain, &aad)?);
                }
                let sealed = record.sealed.as_ref().expect("sealed above");
                Some(SettingsFile {
                    updated_at: record.updated_at,
                    device_id: record.device_id.clone(),
                    nonce: sealed.nonce.clone(),
                    ct: sealed.ct.clone(),
                })
            }
            None => None,
        };
        if let Some(shared) = &self.shared {
            return Ok(VaultFile {
                format: FORMAT.into(),
                version: VERSION_SHARED,
                vault_id: self.vault_id.clone(),
                header_updated_at: self.header_updated_at,
                kdf: shared::stub_kdf(),
                wrapped_key: shared::stub_wrapped_key(),
                key_check: self.key_check.clone(),
                items,
                sync: None,
                local_members: None,
                previous_keys: self.previous_keys.iter().map(|(_, s)| s.clone()).collect(),
                header_auth: None,
                usage,
                recovery: None,
                settings,
                access: Some(shared::ACCESS_MEMBERS.into()),
                genesis: Some(shared.genesis.clone()),
                members: Some(shared.members.clone()),
                account: None,
                account_recovery: None,
            });
        }
        if let Some(slot) = &self.account {
            return Ok(VaultFile {
                format: FORMAT.into(),
                version: VERSION_ACCOUNT,
                vault_id: self.vault_id.clone(),
                header_updated_at: self.header_updated_at,
                kdf: shared::stub_kdf(),
                wrapped_key: shared::stub_wrapped_key(),
                key_check: self.key_check.clone(),
                items,
                sync: None,
                local_members: None,
                previous_keys: self.previous_keys.iter().map(|(_, s)| s.clone()).collect(),
                header_auth: self.header_auth.clone(),
                usage,
                recovery: None,
                settings,
                access: Some(account::ACCESS_ACCOUNT.into()),
                genesis: None,
                members: None,
                account: Some(slot.clone()),
                account_recovery: self.account_recovery.clone(),
            });
        }
        Ok(VaultFile {
            format: FORMAT.into(),
            version: VERSION,
            vault_id: self.vault_id.clone(),
            header_updated_at: self.header_updated_at,
            kdf: self.kdf.clone(),
            wrapped_key: self.wrapped_key.clone(),
            key_check: self.key_check.clone(),
            items,
            sync: None,
            local_members: None,
            previous_keys: self.previous_keys.iter().map(|(_, s)| s.clone()).collect(),
            header_auth: self.header_auth.clone(),
            usage,
            recovery: self.recovery.clone(),
            settings,
            access: None,
            genesis: None,
            members: None,
            account: None,
            account_recovery: None,
        })
    }
}

impl Vault {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Runs `f` over the live items (not in the trash) without copying them, under the vault's
    /// lock (`f` must not call back into the vault).
    pub(crate) fn with_live_items<R>(
        &self,
        f: impl FnOnce(&mut dyn Iterator<Item = &Item>) -> R,
    ) -> R {
        let inner = self.lock();
        let mut items = inner.live_items();
        f(&mut items)
    }

    /// How many live items the vault holds, without copying them.
    pub fn item_count(&self) -> usize {
        self.lock().live_items().count()
    }

    /// A number that moves with every change that can change [`Vault::summaries`] (and some that
    /// can't): rebuild a [`crate::SearchIndex`] when it moves. Per vault object, from 0.
    pub fn list_generation(&self) -> u64 {
        self.lock().dirty_generation
    }

    /// Creates a vault with explicit KDF parameters (tests and benchmarks use cheap ones).
    pub fn create_with_kdf(
        master_password: &str,
        device_id: &str,
        mut kdf: KdfParams,
    ) -> Result<Arc<Vault>> {
        if master_password.is_empty() {
            return Err(PassError::InvalidInput(tr!("vault.empty_password")));
        }
        kdf.check()?;
        let vault_id = uuid::Uuid::new_v4().to_string();
        let salt = crypto::random_bytes::<16>();
        kdf.salt = b64_encode(&salt);
        let kek = crypto::derive_kek(master_password, &kdf, &salt)?;
        let vk = crypto::random_key();
        let wrapped_key = seal(&kek, vk.as_slice(), &vk_aad(&vault_id))?;
        let key_check = seal(&vk, vault_id.as_bytes(), &key_check_aad(&vault_id))?;
        let now = now_ms();
        let mut inner = Inner {
            vault_id,
            device_id: device_id.to_string(),
            vk,
            kdf,
            wrapped_key,
            key_check,
            header_updated_at: now,
            records: BTreeMap::new(),
            dirty: true,
            dirty_generation: 0,
            last_ts: now,
            sync: None,
            pending_members: BTreeMap::new(),
            revision: 0,
            previous_keys: Vec::new(),
            header_auth: None,
            usage: BTreeMap::new(),
            usage_since: None,
            recovery: None,
            settings: None,
            shared: None,
            read_only: false,
            caches: Default::default(),
            account: None,
            account_recovery: None,
        };
        inner.seal_header()?;
        Ok(Arc::new(Vault {
            inner: Mutex::new(inner),
        }))
    }

    /// `header_proven`: the header's wrapped key was just opened with the master password, so the
    /// header may be (re-)authenticated if the file has no valid [`VaultFile::header_auth`].
    fn from_file(
        mut file: VaultFile,
        vk: Key,
        device_id: String,
        header_proven: bool,
        shared: Option<SharedState>,
    ) -> Result<Arc<Vault>> {
        check_key(&file, &vk)?;
        let authentic = header_authentic(&file, &vk);
        // A block that doesn't verify (damaged, or put back by the file's host) is dropped.
        let recovery = file_recovery(&file, &vk);
        let items = std::mem::take(&mut file.items);
        let records = decrypt_records(&file.vault_id, &vk, items)?;
        let previous_keys = open_previous_keys(&file, &vk)?;
        let usage: BTreeMap<String, UsageRecord> = file
            .usage
            .iter()
            .filter_map(|u| Some((u.device_id.clone(), decrypt_usage(&file.vault_id, &vk, u)?)))
            .collect();
        let settings = file
            .settings
            .as_ref()
            .and_then(|f| decrypt_settings(&file.vault_id, &vk, f));
        let pending_members: PendingMembers = file
            .local_members
            .as_ref()
            .and_then(|sealed| open(&vk, sealed, &local_members_aad(&file.vault_id)).ok()?)
            .and_then(|json| serde_json::from_slice(&json).ok())
            .unwrap_or_default();
        let last_ts = records
            .values()
            .map(|r| r.updated_at)
            .chain(usage.values().map(|u| u.updated_at))
            .chain(settings.iter().map(|s| s.updated_at.max(s.data.latest())))
            .max()
            .unwrap_or(0)
            .max(file.header_updated_at);
        let mut inner = Inner {
            vault_id: file.vault_id,
            device_id,
            vk,
            kdf: file.kdf,
            wrapped_key: file.wrapped_key,
            key_check: file.key_check,
            header_updated_at: file.header_updated_at,
            records,
            dirty: false,
            dirty_generation: 0,
            last_ts,
            sync: file.sync,
            pending_members,
            revision: 0,
            previous_keys,
            header_auth: file.header_auth.filter(|_| authentic),
            usage,
            usage_since: None,
            recovery,
            settings,
            shared,
            read_only: false,
            caches: Default::default(),
            account: file.account,
            // The copy is only kept when the header that carries it verified.
            account_recovery: file.account_recovery.filter(|_| authentic),
        };
        if !authentic && header_proven && inner.shared.is_none() {
            inner.seal_header()?;
        }
        inner.purge_expired(now_ms());
        if inner.unsynced().1 {
            inner.usage_since = Some(now_ms());
        }
        Ok(Arc::new(Vault {
            inner: Mutex::new(inner),
        }))
    }

    /// Changes the master password with explicit KDF parameters, with a new vault key
    /// ([`Vault::change_password`]).
    pub fn change_master_password_with_kdf(
        &self,
        new_password: &str,
        kdf: KdfParams,
    ) -> Result<()> {
        self.rekey(new_password, kdf, false)
    }

    /// Gives the vault a new password (fresh salt, `kdf`'s parameters) and a new vault key: every
    /// item is re-encrypted on the next save, and the old key is kept (sealed with the new one) so
    /// older copies can still be merged. A copy of the file from before the change (kept by a
    /// server, Google Drive's revisions or a backup) opens only with the old password, and even
    /// cracked it gives only the old key: nothing written afterwards. The recovery code wrapped the
    /// old key and goes (offer a new one), and emergency grants and admin recovery enrolments of
    /// this vault go stale ([`Vault::emergency_grant_current`],
    /// [`Vault::admin_recovery_enrollment_current`] turn false). The KEK is derived before anything
    /// changes, so a failure leaves the vault as it was.
    ///
    /// `unlink`: the vault is linked to an account and gets this password instead
    /// ([`Vault::unlink_from_account`]); otherwise a linked vault is refused.
    fn rekey(&self, new_password: &str, mut kdf: KdfParams, unlink: bool) -> Result<()> {
        shared::refuse_password(&self.lock())?;
        if !unlink {
            account::refuse_linked(&self.lock())?;
        }
        self.lock().check_writable()?;
        if new_password.is_empty() {
            return Err(PassError::InvalidInput(tr!("vault.empty_password")));
        }
        kdf.check()?;
        let salt = crypto::random_bytes::<16>();
        kdf.salt = b64_encode(&salt);
        let kek = crypto::derive_kek(new_password, &kdf, &salt)?;
        let mut inner = self.lock();
        let vault_id = inner.vault_id.clone();
        inner.replace_key(crypto::random_key(), Vec::new())?;
        // The recovery code wraps the old key, and can't be re-wrapped without the code (shown
        // once, never stored). Whoever knew the old password may have had the old key, so nothing
        // derived from it may unlock the new one: the code goes.
        inner.recovery = None;
        inner.wrapped_key = seal(&kek, inner.vk.as_slice(), &vk_aad(&vault_id))?;
        inner.kdf = kdf;
        if unlink {
            inner.account = None;
            inner.account_recovery = None;
        }
        let header_ts = inner.header_updated_at;
        inner.header_updated_at = inner.next_ts(header_ts);
        inner.seal_header()?;
        inner.changed();
        Ok(())
    }

    /// Checks `password` against the wrapped key in this vault's header.
    fn password_matches(&self, password: &str) -> Result<bool> {
        let (kdf, wrapped, vault_id, vk) = {
            let inner = self.lock();
            shared::refuse_password(&inner)?;
            account::refuse_linked(&inner)?;
            (
                inner.kdf.clone(),
                inner.wrapped_key.clone(),
                inner.vault_id.clone(),
                inner.vk.clone(),
            )
        };
        kdf.check()?;
        let salt = b64_decode(&kdf.salt)?;
        let kek = crypto::derive_kek(password, &kdf, &salt)?;
        Ok(open(&kek, &wrapped, &vk_aad(&vault_id))?
            .is_some_and(|key| crypto::ct_eq(key.as_slice(), vk.as_slice())))
    }

    /// The encrypted vault file for upload (without the local sync state) and its
    /// [`versions_fingerprint`], taken atomically. Leaves the dirty flag alone.
    #[cfg(feature = "sync-core")]
    pub(crate) fn snapshot(&self) -> Result<(Vec<u8>, String)> {
        let mut inner = self.lock();
        let bytes = inner.encode_file(false)?;
        Ok((bytes, inner.fingerprint()))
    }

    /// The remote state recorded by the last successful sync with `url_key`.
    #[cfg(feature = "sync-core")]
    pub(crate) fn sync_state(&self, url_key: &str) -> Option<SyncState> {
        self.lock().sync.clone().filter(|s| s.url == url_key)
    }

    /// Records what the remote file looks like now. Marks the vault dirty when this changes the
    /// state, so the caller's usual save-if-dirty persists it.
    #[cfg(feature = "sync-core")]
    pub(crate) fn set_sync_state(&self, state: SyncState) {
        let mut inner = self.lock();
        if inner.sync.as_ref() != Some(&state) {
            inner.sync = Some(state);
            inner.mark_dirty();
        }
        inner.note_usage_synced();
    }

    /// True when this vault's versions differ from `fingerprint`.
    #[cfg(feature = "sync-core")]
    pub(crate) fn differs_from(&self, fingerprint: &str) -> bool {
        self.lock().fingerprint() != fingerprint
    }

    #[cfg(feature = "sync-core")]
    /// True when `remote_file` lacks something this vault has, i.e. it should be re-uploaded.
    pub(crate) fn remote_is_behind(&self, remote: &VaultFile) -> bool {
        let inner = self.lock();
        if inner.header_updated_at > remote.header_updated_at {
            return true;
        }
        // Another members list than ours: had it won, the merge would have adopted it.
        if let Some(shared) = &inner.shared {
            if remote.members.as_ref().map(|m| &m.cert) != Some(&shared.members.cert) {
                return true;
            }
        }
        // Same header, but the remote copy lacks this vault's recovery code (an older client
        // wrote it and dropped the block, or the host stripped it) or has another one: upload.
        // Never the other way round: a copy whose code this vault lacks is not overwritten.
        if inner.header_updated_at == remote.header_updated_at {
            // The same for a linked vault's copy of the account recovery wrap.
            if inner.account_recovery.is_some()
                && remote.account_recovery != inner.account_recovery
            {
                return true;
            }
            if let Some(ours) = &inner.recovery {
                let theirs = file_recovery(remote, &inner.vk);
                if theirs.as_ref().map(|r| &r.id) != Some(&ours.id) {
                    return true;
                }
            }
        }
        // Settings this copy lacks, or an older version of them. (A copy with newer settings has
        // been merged in by now, so a difference means ours is the one to keep.)
        if let Some(ours) = &inner.settings {
            if remote
                .settings
                .as_ref()
                .map(|s| (s.updated_at, s.device_id.as_str()))
                != Some(ours.version())
            {
                return true;
            }
        }
        let remote_versions: BTreeMap<&str, (i64, &str)> = remote
            .items
            .iter()
            .map(|r| (r.id.as_str(), (r.updated_at, r.device_id.as_str())))
            .collect();
        let remote_usage: BTreeMap<&str, i64> = remote
            .usage
            .iter()
            .map(|u| (u.device_id.as_str(), u.updated_at))
            .collect();
        inner
            .records
            .values()
            .any(|r| remote_versions.get(r.id.as_str()) != Some(&r.version()))
            || inner
                .usage
                .iter()
                .any(|(d, u)| remote_usage.get(d.as_str()) != Some(&u.updated_at))
    }

    /// [`Vault::upsert`]; `keep_created`: a new item keeps its `created_at` when it has one
    /// (imports keep the source's creation date).
    pub(crate) fn upsert_with(&self, mut item: Item, keep_created: bool) -> Result<Item> {
        if let Some(totp) = item.totp.as_deref().map(str::trim) {
            if totp.is_empty() {
                item.totp = None;
            } else {
                crate::totp::totp_parse(totp.to_string())?;
            }
        }
        item.normalize()?;
        if item.id.trim().is_empty() {
            item.id = uuid::Uuid::new_v4().to_string();
            if !keep_created || item.created_at < 0 {
                item.created_at = 0;
            }
        }
        let mut inner = self.lock();
        inner.check_writable()?;
        let now = now_ms();
        if let Some(prev) = inner.records.get(&item.id).and_then(|r| r.item.as_ref()) {
            // A passkey's WebAuthn PRF secret never changes (src/prf.rs).
            crate::prf::keep_prf_secrets(&prev.passkeys, &mut item.passkeys);
        }
        match inner.records.get(&item.id).and_then(|r| r.item.as_ref()) {
            Some(prev) if prev.password != item.password => {
                // The replaced password isn't dropped: it goes to the item's history.
                item.keep_replaced_password(&prev.password, now);
                if item.password.is_empty() {
                    item.password_changed_at = 0;
                } else if item.password_changed_at == 0
                    || item.password_changed_at == prev.password_changed_at
                {
                    item.password_changed_at = now;
                }
            }
            Some(prev) => {
                if item.password_changed_at == 0 {
                    item.password_changed_at = prev.password_changed_at;
                }
            }
            None => {
                if item.password.is_empty() {
                    item.password_changed_at = 0;
                } else if item.password_changed_at <= 0 {
                    item.password_changed_at = if item.updated_at > 0 {
                        item.updated_at.min(now)
                    } else {
                        now
                    };
                }
            }
        }
        Ok(inner.put(item))
    }

    /// Item lookup by a matching rule shared by the url- and app-based finders: best match
    /// first, then favorites, then the most used ([`crate::usage`]), then by title.
    fn logins_where(&self, mut score: impl FnMut(&Item) -> MatchQuality) -> Vec<Item> {
        let inner = self.lock();
        let mut found: Vec<(MatchQuality, i64, Item)> = inner
            .live_items()
            .filter(|i| i.kind == ItemKind::Login)
            .filter_map(|i| {
                let q = score(i);
                (q > MatchQuality::None).then(|| (q, inner.usage_of(&i.id).rank, i.clone()))
            })
            .collect();
        found.sort_by(|(qa, ra, a), (qb, rb, b)| {
            qb.cmp(qa)
                .then(b.favorite.cmp(&a.favorite))
                .then(rb.cmp(ra))
                .then(a.title.to_lowercase().cmp(&b.title.to_lowercase()))
        });
        found.into_iter().map(|(_, _, i)| i).collect()
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Vault {
    /// Creates a new, empty vault protected by `master_password`.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn create(master_password: String, device_id: String) -> Result<Arc<Vault>> {
        Self::create_with_kdf(&master_password, &device_id, KdfParams::default())
    }

    /// Unlocks a vault file with the master password.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn unlock(file: Vec<u8>, master_password: String, device_id: String) -> Result<Arc<Vault>> {
        let parsed = parse_file(&file)?;
        shared::refuse_shared(&parsed)?;
        account::refuse_linked_file(&parsed)?;
        parsed.kdf.check()?;
        let salt = b64_decode(&parsed.kdf.salt)?;
        let kek = crypto::derive_kek(&master_password, &parsed.kdf, &salt)?;
        let vk = open(&kek, &parsed.wrapped_key, &vk_aad(&parsed.vault_id))?
            .ok_or(PassError::InvalidPassword)?;
        let vk = key_from_vec(&vk)?;
        Self::from_file(parsed, vk, device_id, true, None)
    }

    /// Unlocks with a vault key previously obtained from [`Vault::export_vault_key`]
    /// (for biometric / Windows Hello unlock).
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn unlock_with_key(
        file: Vec<u8>,
        vault_key: Vec<u8>,
        device_id: String,
    ) -> Result<Arc<Vault>> {
        let parsed = parse_file(&file)?;
        shared::refuse_shared(&parsed)?;
        let vk = key_from_vec(&vault_key)?;
        Self::from_file(parsed, vk, device_id, false, None)
    }

    pub fn vault_id(&self) -> String {
        self.lock().vault_id.clone()
    }

    pub fn export_vault_key(&self) -> Vec<u8> {
        self.lock().vk.to_vec()
    }

    /// The encrypted vault file for this device's storage (with the local-only sync state). Clears
    /// the dirty flag before the bytes are stored: use [`Vault::save_snapshot`] when a write can
    /// fail.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut inner = self.lock();
        inner.purge_expired(now_ms());
        let bytes = inner.encode_file(true)?;
        inner.dirty = false;
        Ok(bytes)
    }

    /// [`Vault::serialize`] without clearing the dirty flag, so a failed write leaves the vault
    /// dirty and the next save writes it again. Once the bytes are stored, pass the snapshot's
    /// `generation` to [`Vault::mark_saved`].
    pub fn save_snapshot(&self) -> Result<SaveSnapshot> {
        let mut inner = self.lock();
        inner.purge_expired(now_ms());
        let bytes = inner.encode_file(true)?;
        Ok(SaveSnapshot {
            bytes,
            generation: inner.dirty_generation,
        })
    }

    /// The bytes of the [`Vault::save_snapshot`] with this `generation` are stored: clears the
    /// dirty flag, unless something changed since that snapshot was taken.
    pub fn mark_saved(&self, generation: u64) {
        let mut inner = self.lock();
        if inner.dirty_generation == generation {
            inner.dirty = false;
        }
    }

    /// True when the vault has changes that are not saved to its file yet.
    pub fn is_dirty(&self) -> bool {
        self.lock().dirty
    }

    /// True when this vault holds changes the sync server had not seen as of the last successful
    /// sync (or it was never synced), so the next sync uploads. Survives restarts. Usage counts
    /// don't count here; see [`Vault::usage_sync_pending`] and [`Vault::usage_sync_due`].
    pub fn sync_pending(&self) -> bool {
        self.lock().unsynced().0
    }

    /// True when this vault has usage counts the sync server hasn't seen. The next sync (for any
    /// reason) uploads them; on their own they wait for [`Vault::usage_sync_due`].
    pub fn usage_sync_pending(&self) -> bool {
        self.lock().unsynced().1
    }

    /// True when usage counts have waited for a sync for [`USAGE_SYNC_INTERVAL_MS`] (6 hours) at
    /// `now_ms`: time to sync for them alone. Measured from the first unsynced use since the
    /// last sync, or from the unlock.
    pub fn usage_sync_due(&self, now_ms: i64) -> bool {
        let inner = self.lock();
        inner
            .usage_since
            .is_some_and(|since| now_ms.saturating_sub(since) >= USAGE_SYNC_INTERVAL_MS)
            && inner.unsynced().1
    }

    /// Counts one use of login `item_id` on this device at `now_ms` (a fill, an auto-type, a copied
    /// password, a passkey sign-in); uses of one item within a minute count once
    /// ([`crate::usage`]). Changes no item, version or [`Vault::revision`], only the dirty flag,
    /// and is no reason to sync on its own. `NotFound` for an unknown or deleted item.
    pub fn record_use(&self, item_id: String, now_ms: i64) -> Result<()> {
        let mut inner = self.lock();
        if inner.live(&item_id).is_none() {
            return Err(PassError::NotFound(tr!("vault.no_item")));
        }
        let device_id = inner.device_id.clone();
        let prev = inner.usage.get(&device_id).map_or(0, |u| u.updated_at);
        let ts = inner.next_ts(prev);
        let record = inner.usage.entry(device_id).or_insert_with(|| UsageRecord {
            updated_at: 0,
            usage: DeviceUsage::default(),
            sealed: None,
        });
        record.usage.record(&item_id, now_ms);
        record.updated_at = ts;
        record.sealed = None;
        inner.prune_usage();
        inner.mark_dirty();
        if inner.usage_since.is_none() {
            inner.usage_since = Some(crate::now_ms());
        }
        Ok(())
    }

    /// How much item `id` was used, over every device (zeros if never, or unknown).
    pub fn usage(&self, id: String) -> ItemUsage {
        self.lock().usage_of(&id)
    }

    /// A counter that changes whenever the vault's contents change (local edits and merged
    /// changes), for debouncing: sync a few seconds after it stops changing. Starts at 0 on
    /// unlock; not persisted.
    pub fn revision(&self) -> u64 {
        self.lock().revision
    }

    pub fn change_master_password(&self, new_password: String) -> Result<()> {
        let kdf = KdfParams {
            salt: String::new(),
            ..self.lock().kdf.clone()
        };
        self.change_master_password_with_kdf(&new_password, kdf)
    }

    /// Whether `password` is the current master password (one Argon2id run; changes nothing).
    pub fn check_password(&self, password: String) -> Result<bool> {
        self.password_matches(&password)
    }

    /// Changes the master password after checking the current one (`InvalidPassword` if wrong),
    /// always with a new vault key ([`Vault::change_master_password_with_kdf`]), so an old copy of
    /// the file cracked with the old password reads nothing written later. Save and sync
    /// afterwards, then on a Passyble Server drop the old versions
    /// ([`crate::server_purge_versions`]) and offer a new recovery code.
    pub fn change_password(&self, old_password: String, new_password: String) -> Result<()> {
        if !self.password_matches(&old_password)? {
            return Err(PassError::InvalidPassword);
        }
        let kdf = KdfParams {
            salt: String::new(),
            ..self.lock().kdf.clone()
        };
        self.rekey(&new_password, kdf, false)
    }

    /// All live items (not in the trash) sorted by title.
    pub fn items(&self) -> Vec<Item> {
        let mut items: Vec<Item> = self.lock().live_items().cloned().collect();
        items.sort_by_cached_key(|i| i.title.to_lowercase());
        items
    }

    /// The locked list (`ItemSummary`): every live item without its secrets, sorted by title.
    /// Kept in memory by the apps after a soft lock; never written anywhere.
    pub fn summaries(&self) -> Vec<crate::summary::ItemSummary> {
        let inner = self.lock();
        let mut found: Vec<crate::summary::ItemSummary> = inner
            .live_items()
            .map(|item| crate::summary::ItemSummary::of(item).with_usage(inner.usage_of(&item.id)))
            .collect();
        found.sort_by_cached_key(|i| i.title.to_lowercase());
        found
    }

    /// The live item `id`; `None` if unknown, deleted or in the trash (see
    /// [`Vault::trashed_items`]).
    pub fn get(&self, id: String) -> Option<Item> {
        self.lock().live(&id).cloned()
    }

    /// Inserts or replaces an item (a blank id creates one), normalized: card number digits only,
    /// brand derived, tags trimmed and de-duplicated, card or identity data only on its own kind.
    /// When the password changes, `password_changed_at` becomes now (unless the caller set another
    /// time) and the replaced password goes to `password_history` (at most
    /// [`crate::MAX_PASSWORD_HISTORY`]). With `trashed_at` set the item goes to (or stays in) the
    /// trash; upserting a trashed item's copy without it restores the item.
    pub fn upsert(&self, item: Item) -> Result<Item> {
        {
            let inner = self.lock();
            let prev = inner.records.get(&item.id).and_then(|r| r.item.as_ref());
            crate::limits::check_item(&item, prev)?;
        }
        self.upsert_with(item, false)
    }

    /// Moves a live item to the trash (`trashed_at` = now). It leaves every list and finder until
    /// [`Vault::restore`]; [`Vault::purge`], [`Vault::empty_trash`] or [`TRASH_RETENTION_MS`] delete
    /// it for good. `NotFound` if the item is unknown, deleted or already in the trash.
    pub fn delete(&self, id: String) -> Result<()> {
        let mut inner = self.lock();
        inner.check_writable()?;
        let mut item = inner
            .live(&id)
            .cloned()
            .ok_or_else(|| PassError::NotFound(tr!("vault.no_item")))?;
        item.trashed_at = Some(now_ms());
        inner.put(item);
        Ok(())
    }

    /// Deletes an item for good (live or in the trash): a tombstone, which syncs as a deletion.
    /// `NotFound` if there is no such item.
    pub fn delete_permanently(&self, id: String) -> Result<()> {
        let mut inner = self.lock();
        inner.check_writable()?;
        if inner.tombstone(&id) {
            Ok(())
        } else {
            Err(PassError::NotFound(tr!("vault.no_item")))
        }
    }

    /// Takes an item out of the trash. `NotFound` unless it is in the trash.
    pub fn restore(&self, id: String) -> Result<Item> {
        let mut inner = self.lock();
        inner.check_writable()?;
        let mut item = inner
            .records
            .get(&id)
            .and_then(|r| r.item.clone())
            .filter(Item::is_trashed)
            .ok_or_else(|| PassError::NotFound(tr!("vault.no_item_in_trash")))?;
        item.trashed_at = None;
        Ok(inner.put(item))
    }

    /// Deletes an item in the trash for good (a tombstone). `NotFound` unless it is in the
    /// trash (use [`Vault::delete_permanently`] for a live item).
    pub fn purge(&self, id: String) -> Result<()> {
        let mut inner = self.lock();
        inner.check_writable()?;
        if !inner
            .records
            .get(&id)
            .and_then(|r| r.item.as_ref())
            .is_some_and(Item::is_trashed)
        {
            return Err(PassError::NotFound(tr!("vault.no_item_in_trash")));
        }
        inner.tombstone(&id);
        Ok(())
    }

    /// Deletes every item in the trash for good. Returns how many.
    pub fn empty_trash(&self) -> u32 {
        let mut inner = self.lock();
        if inner.check_writable().is_err() {
            return 0;
        }
        let ids: Vec<String> = inner.trashed_items().map(|i| i.id.clone()).collect();
        ids.iter().filter(|id| inner.tombstone(id)).count() as u32
    }

    /// Purges the items that have been in the trash longer than [`TRASH_RETENTION_MS`] at `now_ms`.
    /// Returns how many.
    pub fn purge_expired_trash(&self, now_ms: i64) -> u32 {
        self.lock().purge_expired(now_ms)
    }

    /// The items in the trash, most recently trashed first.
    pub fn trashed_items(&self) -> Vec<Item> {
        let mut items: Vec<Item> = self.lock().trashed_items().cloned().collect();
        items.sort_by(|a, b| {
            b.trashed_at
                .cmp(&a.trashed_at)
                .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
        });
        items
    }

    /// [`Vault::trashed_items`] without secrets, for the trash view.
    pub fn trash_summaries(&self) -> Vec<crate::summary::ItemSummary> {
        let inner = self.lock();
        let mut found: Vec<crate::summary::ItemSummary> = inner
            .trashed_items()
            .map(|item| crate::summary::ItemSummary::of(item).with_usage(inner.usage_of(&item.id)))
            .collect();
        found.sort_by(|a, b| {
            b.trashed_at
                .cmp(&a.trashed_at)
                .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
        });
        found
    }

    /// Every tag of the live items with how many items carry it, sorted by name
    /// (case-insensitive). Exact tags only: `Work/Clients` doesn't count for `Work`.
    pub fn tags(&self) -> Vec<crate::summary::TagCount> {
        crate::summary::count_tags(self.lock().live_items().map(|i| i.tags.as_slice()))
    }

    /// Live items carrying `tag` or a tag nested under it (`Work` also finds `Work/Clients`),
    /// case-insensitive, sorted by title.
    pub fn items_with_tag(&self, tag: String) -> Vec<Item> {
        let mut items: Vec<Item> = self
            .lock()
            .live_items()
            .filter(|i| crate::summary::has_tag(&i.tags, &tag))
            .cloned()
            .collect();
        items.sort_by_cached_key(|i| i.title.to_lowercase());
        items
    }

    /// Fuzzy search ([`crate::search`]) over titles, usernames, websites, apps, passkey names and
    /// notes: best matches first, then favorites, the most used, then by title. An empty query lists
    /// every item by title.
    pub fn search(&self, query: String) -> Vec<Item> {
        if crate::search::Query::parse(&query).is_empty() {
            return self.items();
        }
        let mut inner = self.lock();
        let docs = inner.search_docs();
        let inner = &*inner;
        let live: Vec<(&Item, &crate::search::SearchDoc)> = docs
            .0
            .iter()
            .filter_map(|(id, doc)| Some((inner.live(id)?, doc)))
            .collect();
        crate::search::rank_by(
            live,
            &query,
            |q, (_, doc)| crate::search::score_indexed(q, doc),
            |(i, _)| &i.title,
            |(i, _)| (i.favorite, inner.usage_of(&i.id).rank),
        )
        .into_iter()
        .map(|(i, _)| i.clone())
        .collect()
    }

    /// Logins for a web page: the same host first, then other subdomains of the site; within
    /// each, favorites, the most used and by title (a stored path that matches doesn't rank
    /// higher, so it can't hide the most used login of the host).
    pub fn find_for_url(&self, url: String) -> Vec<Item> {
        let Some(page) = parse_loose(&url) else {
            return Vec::new();
        };
        self.logins_where(|item| url_suggestion_tier(&item.urls, &item.url_rules, &page))
    }

    /// Every login of a web page whatever its website rules ([`crate::UrlMatch`]), in the order of
    /// [`Vault::find_for_url`]: the logins a pick by hand may fill there, and that tell whether a
    /// submitted login is saved already. The rules only decide what is offered on their own.
    pub fn logins_of_page(&self, url: String) -> Vec<Item> {
        let Some(page) = parse_loose(&url) else {
            return Vec::new();
        };
        self.logins_where(|item| url_suggestion_tier(&item.urls, &[], &page))
    }

    /// The logins a sign-in, sign-up or password change submitted on a web page may update: those of
    /// [`Vault::find_for_url`] saved for the page's own host, `www.` or not, in the same order. A
    /// login of another subdomain of the site is left out, so a new password typed there is saved as
    /// a new login for that subdomain; it is still offered for filling.
    pub fn find_for_save(&self, url: String) -> Vec<Item> {
        let Some(page) = parse_loose(&url) else {
            return Vec::new();
        };
        self.logins_where(|item| save_tier(&item.urls, &item.url_rules, &page))
    }

    /// Logins for a native Android app. A stored certificate digest must match.
    ///
    /// An entry without a stored digest (typed in, imported) matches on the package name alone and
    /// ranks below verified entries (and those below legacy `androidapp://` URLs). Once the user
    /// confirms such a fill, the caller should store the digest it verified (`upsert`), so another
    /// app installed later under the same package name no longer matches.
    pub fn find_for_android_app(&self, package: String, cert_sha256: Option<String>) -> Vec<Item> {
        let cert = cert_sha256
            .as_deref()
            .map(normalize_cert)
            .filter(|c| !c.is_empty());
        self.logins_where(|item| {
            android_app_match(
                &item.android_apps,
                &item.urls,
                &item.url_rules,
                &package,
                cert.as_deref(),
            )
        })
    }

    /// [`Vault::find_for_android_app`] with the apps the user hid ([`AndroidApp::never_show`],
    /// [`crate::UrlMatch::Never`]) too: the logins a pick by hand may fill into that app.
    pub fn logins_of_android_app(
        &self,
        package: String,
        cert_sha256: Option<String>,
    ) -> Vec<Item> {
        let cert = cert_sha256
            .as_deref()
            .map(normalize_cert)
            .filter(|c| !c.is_empty());
        self.logins_where(|item| {
            let apps: Vec<AndroidApp> = item
                .android_apps
                .iter()
                .map(|a| AndroidApp {
                    never_show: false,
                    ..a.clone()
                })
                .collect();
            android_app_match(&apps, &item.urls, &[], &package, cert.as_deref())
        })
    }

    /// Whether the page `url` (or `androidapp://<package>`) looks like the site of login `item_id`
    /// without being it (`paypa1.com` for a `paypal.com` login), to warn before a hand-picked login
    /// is filled or copied there. `None` when the login belongs to the page, the page is the site
    /// of any item in the vault, the item is unknown, or nothing looks alike.
    pub fn lookalike_for_url(&self, url: String, item_id: String) -> Option<Lookalike> {
        let mut inner = self.lock();
        inner.live(&item_id)?;
        let sites = inner.vault_sites();
        let item = inner.live(&item_id)?;
        LookalikeCheck::new_known(&url, &sites.known)?.against(
            login_sites(&item.urls, &item.android_apps)
                .iter()
                .map(String::as_str),
        )
    }

    /// Whether a new login saved on the page `url` (or `androidapp://<package>`) would be for a
    /// lookalike of a site the user has a login for (`crate::lookalike`), to warn on the save
    /// prompt. `None` when the page is the site of a login in the vault or nothing looks alike.
    pub fn lookalike_for_save(&self, url: String) -> Option<Lookalike> {
        let mut inner = self.lock();
        let sites = inner.vault_sites();
        let inner = &*inner;
        sites.known.lookalike_for_save(&url, || {
            // The most used first, so the site named is the likeliest one.
            let mut order: Vec<usize> = (0..sites.logins.len()).collect();
            order.sort_by_key(|&i| std::cmp::Reverse(inner.usage_of(&sites.logins[i]).rank));
            order
        })
    }

    /// Passkeys for an RP, optionally restricted to the request's allow-list.
    pub fn find_passkeys(
        &self,
        rp_id: String,
        allow_credential_ids: Vec<Vec<u8>>,
    ) -> Vec<PasskeyMatch> {
        let inner = self.lock();
        let mut found: Vec<PasskeyMatch> = inner
            .live_items()
            .flat_map(|item| {
                item.passkeys
                    .iter()
                    .filter(|pk| pk.rp_id.eq_ignore_ascii_case(&rp_id))
                    .filter(|pk| {
                        allow_credential_ids.is_empty()
                            || allow_credential_ids.contains(&pk.credential_id)
                    })
                    .map(|pk| PasskeyMatch {
                        item_id: item.id.clone(),
                        item_title: item.title.clone(),
                        passkey: pk.clone(),
                    })
            })
            .collect();
        // The most used first ([`crate::usage`]), then by account name.
        found.sort_by_cached_key(|m| {
            (
                std::cmp::Reverse(inner.usage_of(&m.item_id).rank),
                m.passkey.user_name.clone(),
            )
        });
        found
    }

    /// Stores a newly created passkey. Without `item_id` it is attached to an existing login
    /// for the same site and username when there is one, otherwise a new login is created.
    /// A passkey for the same RP and user handle replaces the old one.
    pub fn add_passkey(
        &self,
        item_id: Option<String>,
        passkey: Passkey,
        url: Option<String>,
    ) -> Result<Item> {
        let site = url
            .clone()
            .unwrap_or_else(|| format!("https://{}", passkey.rp_id));
        let target = match item_id {
            Some(id) => Some(
                self.get(id.clone())
                    .ok_or_else(|| PassError::NotFound(tr!("vault.no_item")))?,
            ),
            None => self.find_for_url(site.clone()).into_iter().find(|i| {
                !passkey.user_name.is_empty() && i.username.eq_ignore_ascii_case(&passkey.user_name)
            }),
        };
        let mut item = target.unwrap_or_else(|| Item {
            kind: ItemKind::Login,
            title: passkey
                .rp_name
                .clone()
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| passkey.rp_id.clone()),
            username: passkey.user_name.clone(),
            urls: vec![site],
            ..Default::default()
        });
        item.passkeys.retain(|pk| {
            !(pk.rp_id.eq_ignore_ascii_case(&passkey.rp_id)
                && pk.user_handle == passkey.user_handle)
        });
        item.passkeys.push(passkey);
        self.upsert(item)
    }

    /// Merges another copy of this vault (e.g. downloaded from sync) into this one.
    pub fn merge_remote(&self, remote_file: Vec<u8>) -> Result<MergeStats> {
        self.merge_parsed(&parse_file(&remote_file)?)
    }
}

/// Recovery code (format in `crate::recovery`).
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Vault {
    /// Unlocks a vault file with its recovery code, for a forgotten master password; then set a new
    /// one with [`Vault::change_master_password`], save and sync. The vault key stays, so device
    /// keys (biometric / Windows Hello) keep working.
    ///
    /// `InvalidInput` for a malformed code ([`crate::recovery_code_valid_format`]), `NotFound` if
    /// the file has no recovery code, `InvalidPassword` for a code that doesn't open it.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn unlock_with_recovery_code(
        file: Vec<u8>,
        recovery_code: String,
        device_id: String,
    ) -> Result<Arc<Vault>> {
        let secret = crate::recovery::decode(&recovery_code)?;
        let parsed = parse_file(&file)?;
        shared::refuse_shared(&parsed)?;
        if parsed.is_linked() {
            // A linked vault opens with the account's recovery code (its header copy).
            let ak = account::account_key_of_file(&parsed, &recovery_code)?;
            let vk = account::open_slot(&parsed, &ak)?;
            return Self::from_file(parsed, vk, device_id, false, None);
        }
        let r = parsed
            .recovery
            .as_ref()
            .ok_or_else(|| PassError::NotFound(tr!("vault.no_recovery_code")))?;
        r.kdf.check()?;
        let salt = b64_decode(&r.kdf.salt)?;
        let kek = crypto::derive_kek_bytes(secret.as_slice(), &r.kdf, &salt)?;
        let vk = open(
            &kek,
            &r.wrapped_key,
            &recovery_vk_aad(&parsed.vault_id, &r.id),
        )?
        .ok_or(PassError::InvalidPassword)?;
        let vk = key_from_vec(&vk)?;
        // The key opened the block, and `from_file` checks it against the key check, so it is
        // this vault's key whether or not the block's `auth` still verifies. The header is not
        // re-authenticated: it wasn't opened with the master password.
        Self::from_file(parsed, vk, device_id, false, None)
    }

    /// Makes a new recovery code for this vault and returns it, the only time it can be read: the
    /// vault keeps the vault key wrapped by a key derived from it (Argon2id, the vault's parameters),
    /// never the code. Replaces any earlier code. Save and sync afterwards.
    pub fn create_recovery_code(&self) -> Result<String> {
        shared::refuse_password(&self.lock())?;
        account::refuse_linked(&self.lock())?;
        self.lock().check_writable()?;
        let (secret, code) = crate::recovery::generate();
        let mut kdf = KdfParams {
            salt: String::new(),
            ..self.lock().kdf.clone()
        };
        kdf.check()?;
        let salt = crypto::random_bytes::<16>();
        kdf.salt = b64_encode(&salt);
        // Derived before anything changes, so a failure leaves the vault as it was.
        let kek = crypto::derive_kek_bytes(secret.as_slice(), &kdf, &salt)?;
        let id = uuid::Uuid::new_v4().to_string();
        let mut inner = self.lock();
        let wrapped_key = seal(
            &kek,
            inner.vk.as_slice(),
            &recovery_vk_aad(&inner.vault_id, &id),
        )?;
        inner.recovery = Some(RecoveryFile {
            id,
            created_at: now_ms(),
            kdf,
            wrapped_key,
            // Sealed by `seal_header` below.
            auth: Sealed {
                nonce: String::new(),
                ct: String::new(),
            },
        });
        inner.bump_header()?;
        Ok(code.to_string())
    }

    /// Removes the recovery code: copies saved from now on can't be opened with it, older copies
    /// still can. No change if there is none. Save and sync afterwards.
    pub fn remove_recovery_code(&self) -> Result<()> {
        let mut inner = self.lock();
        inner.check_writable()?;
        if inner.recovery.take().is_some() {
            inner.bump_header()?;
        }
        Ok(())
    }

    pub fn has_recovery_code(&self) -> bool {
        self.lock().recovery.is_some()
    }

    /// When the recovery code was made (Unix ms); `None` without one.
    pub fn recovery_code_created_at(&self) -> Option<i64> {
        self.lock().recovery.as_ref().map(|r| r.created_at)
    }
}

/// Settings kept in the vault ([`crate::settings`]).
impl Vault {
    pub(crate) fn setting(&self, key: &str) -> Option<String> {
        self.lock().setting(key).map(str::to_string)
    }

    #[cfg(test)]
    pub(crate) fn lock_fingerprint_for_tests(&self) -> String {
        self.lock().fingerprint()
    }

    pub(crate) fn setting_keys(&self, prefix: &str) -> Vec<String> {
        self.lock()
            .settings
            .as_ref()
            .map(|s| {
                s.data
                    .keys_with_prefix(prefix)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Sets (or with `None` removes) setting `key`: saved with the vault and synced like an edit.
    /// `true` if that changed something.
    pub(crate) fn put_setting(&self, key: &str, value: Option<String>) -> Result<bool> {
        if !crate::settings::valid_key(key) {
            return Err(PassError::InvalidInput(format!("setting key {key:?}")));
        }
        if value
            .as_ref()
            .is_some_and(|v| v.len() > crate::settings::MAX_VALUE_LEN)
        {
            return Err(PassError::InvalidInput(tr!("settings.too_long")));
        }
        let mut inner = self.lock();
        inner.check_writable()?;
        Ok(inner.set_setting(key, value))
    }
}

/// What [`Vault::move_usage`] changed in this device's usage counts, so an undo can put it back.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct UsageMove {
    from: String,
    into: String,
    /// This device's counts for `from` and `into` before the move.
    from_before: Option<UseCount>,
    into_before: Option<UseCount>,
    moved: bool,
}

impl Vault {
    /// Adds every device's uses of item `from` to item `into` (merging two items). The sum goes into
    /// this device's own counts, the only ones a device may raise. Like [`Vault::record_use`] it
    /// changes no item and no version, only the dirty flag.
    pub(crate) fn move_usage(&self, from: &str, into: &str) -> UsageMove {
        let mut inner = self.lock();
        let total = inner.usage_of(from);
        let device_id = inner.device_id.clone();
        let mine = inner.usage.get(&device_id);
        let mut moved = UsageMove {
            from: from.to_string(),
            into: into.to_string(),
            from_before: mine.and_then(|u| u.usage.items.get(from).copied()),
            into_before: mine.and_then(|u| u.usage.items.get(into).copied()),
            moved: false,
        };
        if total.count == 0 || from == into {
            return moved;
        }
        let prev = mine.map_or(0, |u| u.updated_at);
        let ts = inner.next_ts(prev);
        let record = inner.usage.entry(device_id).or_insert_with(|| UsageRecord {
            updated_at: 0,
            usage: DeviceUsage::default(),
            sealed: None,
        });
        let entry = record.usage.items.entry(into.to_string()).or_default();
        entry.count = entry.count.saturating_add(total.count);
        entry.last_used = entry.last_used.max(total.last_used);
        record.updated_at = ts;
        record.sealed = None;
        inner.prune_usage();
        inner.mark_dirty();
        if inner.usage_since.is_none() {
            inner.usage_since = Some(now_ms());
        }
        moved.moved = true;
        moved
    }

    /// Undoes a [`Vault::move_usage`]: this device's counts for both items as they were before. Once
    /// the moved counts were synced another device's copy may raise them again, so totals can stay a
    /// little high.
    pub(crate) fn restore_usage(&self, moved: &UsageMove) {
        if !moved.moved {
            return;
        }
        let mut inner = self.lock();
        let device_id = inner.device_id.clone();
        let prev = inner.usage.get(&device_id).map_or(0, |u| u.updated_at);
        let ts = inner.next_ts(prev);
        let record = inner.usage.entry(device_id).or_insert_with(|| UsageRecord {
            updated_at: 0,
            usage: DeviceUsage::default(),
            sealed: None,
        });
        for (id, before) in [
            (&moved.from, moved.from_before),
            (&moved.into, moved.into_before),
        ] {
            match before {
                Some(count) => {
                    record.usage.items.insert(id.clone(), count);
                }
                None => {
                    record.usage.items.remove(id);
                }
            }
        }
        record.updated_at = ts;
        record.sealed = None;
        inner.mark_dirty();
        if inner.usage_since.is_none() {
            inner.usage_since = Some(now_ms());
        }
    }
}

impl Vault {
    /// [`Vault::merge_remote`] for an already parsed file.
    pub(crate) fn merge_parsed(&self, remote: &VaultFile) -> Result<MergeStats> {
        let mut inner = self.lock();
        if remote.vault_id != inner.vault_id || remote.is_shared() != inner.shared.is_some() {
            return Err(PassError::Conflict(tr!("vault.different_vault")));
        }
        if inner.shared.is_some() {
            // The members list first: a newer list may bring a new key, which the items below
            // are then merged with.
            inner.merge_members(remote)?;
        }
        // The current key, or a key this vault replaced (a copy from before a key rotation).
        let remote_key: Key = if check_key(remote, &inner.vk).is_ok() {
            inner.vk.clone()
        } else {
            inner
                .previous_keys
                .iter()
                .map(|(k, _)| k)
                .find(|k| check_key(remote, k).is_ok())
                .cloned()
                .ok_or_else(|| PassError::Crypto(tr!("vault.different_key")))?
        };
        let same_key = remote_key.as_slice() == inner.vk.as_slice();

        let mut stats = MergeStats::default();
        // Passwords of the version that lost a merge that the winner shows no sign of having
        // seen ([`unseen_passwords`]): kept in the winner's password history below.
        let mut rescued: BTreeMap<String, Vec<PasswordHistoryEntry>> = BTreeMap::new();
        for remote_record in &remote.items {
            if inner.join_record(remote, &remote_key, same_key, remote_record, &mut stats) {
                continue;
            }
            // The whole-item rule: a tombstone on either side, or a version without merge
            // metadata (an older client's, a conflict copy, a legacy record).
            let remote_version = (remote_record.updated_at, remote_record.device_id.as_str());
            let newer = match inner.records.get(&remote_record.id) {
                None => true,
                Some(local) => remote_version > local.version(),
            };
            if !newer {
                stats.unchanged += 1;
                // An older version of an item this vault has: ours wins. If it is an edit made
                // without having seen ours (another device's concurrent change), its password
                // must not vanish with it. Only strictly older live records are opened, so an
                // ordinary sync (the same versions on both sides) decrypts nothing here. The one
                // exception is a rescue version ([`RESCUE_MARK`]) of the same item on both
                // sides: two devices may each have rescued other passwords into it, so both are
                // read and joined into the next one.
                let local_item = inner
                    .records
                    .get(&remote_record.id)
                    .filter(|local| {
                        remote_version < local.version()
                            || (remote_version == local.version()
                                && is_rescue(&local.device_id))
                    })
                    .and_then(|local| local.item.as_ref());
                if let (Some(local_item), false) = (local_item, remote_record.deleted) {
                    if let Ok((older, true)) =
                        decrypt_record(&remote.vault_id, &remote_key, remote_record)
                    {
                        if let Some(older) = older.item.as_ref() {
                            let lost = unseen_passwords(older, local_item);
                            if !lost.is_empty() {
                                rescued.entry(remote_record.id.clone()).or_default().extend(lost);
                            }
                        }
                    }
                }
                continue;
            }
            let decrypted = decrypt_record(&remote.vault_id, &remote_key, remote_record);
            let (mut record, authentic) = match decrypted {
                Ok(decrypted) => decrypted,
                // A damaged copy of an item this vault has (e.g. an old ciphertext given a new
                // timestamp): keep ours, and the next sync uploads it over the damaged one.
                Err(PassError::Corrupt(_)) if inner.records.contains_key(&remote_record.id) => {
                    stats.unchanged += 1;
                    continue;
                }
                Err(e) => return Err(e),
            };
            // A version nobody vouches for (an older client's record, or cleartext metadata
            // edited by the file's host: a forged tombstone, a bumped timestamp) may add an item
            // this vault has never seen, but never replaces or deletes one it has. The next sync
            // uploads this vault's version over it (`remote_is_behind`).
            if !authentic && inner.records.contains_key(&record.id) {
                stats.unchanged += 1;
                continue;
            }
            if !same_key {
                // Re-encrypted with the current key on the next save.
                record.sealed = None;
            }
            // A passkey's WebAuthn PRF secret never changes (src/prf.rs): a copy of a passkey
            // this vault has, with another key, keeps ours (sealed again on the next save).
            if let (Some(local), Some(remote_item)) = (
                inner.records.get(&record.id).and_then(|r| r.item.as_ref()),
                record.item.as_mut(),
            ) {
                if crate::prf::keep_prf_secrets(&local.passkeys, &mut remote_item.passkeys) {
                    record.sealed = None;
                }
            }
            let existed = inner
                .records
                .get(&record.id)
                .is_some_and(|r| r.item.is_some());
            match (&record.item, existed) {
                (None, true) => stats.deleted += 1,
                (None, false) => stats.unchanged += 1,
                (Some(_), true) => stats.updated += 1,
                (Some(_), false) => stats.added += 1,
            }
            // The remote version replaces ours: keep our password if it never saw it.
            let local_item = inner.records.get(&record.id).and_then(|r| r.item.as_ref());
            if let (Some(kept), Some(local_item)) = (record.item.as_ref(), local_item) {
                let lost = unseen_passwords(local_item, kept);
                if !lost.is_empty() {
                    rescued.entry(record.id.clone()).or_default().extend(lost);
                }
            }
            inner.last_ts = inner.last_ts.max(record.updated_at);
            inner.records.insert(record.id.clone(), record);
            inner.changed();
        }
        // Each rescued password goes into the winning version's history, as a new version of the
        // item right after the winner's ([`RESCUE_MARK`]), which the next sync spreads. Every
        // device that sees the same versions makes the same rescue (password, date and order are
        // fixed), so the copies agree, and nothing is rescued twice: afterwards the password is in
        // the history.
        for (id, lost) in rescued {
            let Some(winner) = inner.records.get(&id) else {
                continue;
            };
            let Some(item) = winner.item.as_ref() else {
                continue;
            };
            let mut kept = with_rescued(item, &lost);
            if kept.password_history == item.password_history {
                continue;
            }
            let ts = winner.updated_at;
            let device_id = format!("{}{RESCUE_MARK}", winner.device_id);
            kept.updated_at = ts;
            // The winner's merge metadata, for the rescue version, with the password part
            // (whose history the rescue changed) under a stamp of its own: an edit made on top of
            // the winner without having seen the rescue doesn't drop the rescued passwords.
            let meta = winner
                .meta
                .as_ref()
                .map(|meta| field_merge::rescued(meta, &kept, (ts, device_id.clone())));
            let record = Record {
                id: id.clone(),
                updated_at: ts,
                device_id,
                item: Some(kept),
                sealed: None,
                meta,
            };
            inner.records.insert(id, record);
            inner.changed();
        }
        // A header wrapping an older key is never adopted, whatever its timestamp, and neither is
        // one the vault key doesn't vouch for (VaultFile::header_auth): the file's host could
        // otherwise replace the wrapped key or the KDF parameters (or replay an old password's
        // header with a new timestamp), and the next save here would make the vault unopenable
        // with the master password or open it with an old one.
        if same_key
            && inner.shared.is_none()
            && remote.header_updated_at > inner.header_updated_at
            && (remote.is_linked() || remote.kdf.check().is_ok())
            && header_authentic(remote, &remote_key)
        {
            // Linked or not, the newer authenticated header wins.
            inner.account = remote.account.clone();
            inner.account_recovery = remote.account_recovery.clone();
            inner.kdf = remote.kdf.clone();
            inner.wrapped_key = remote.wrapped_key.clone();
            inner.header_auth = remote.header_auth.clone();
            // The recovery code goes with the header: a newer header without one (the code was
            // removed, or an older client changed the password) has none.
            inner.recovery = file_recovery(remote, &remote_key);
            for (key, sealed) in open_previous_keys(remote, &remote_key)? {
                if !inner
                    .previous_keys
                    .iter()
                    .any(|(k, _)| k.as_slice() == key.as_slice())
                {
                    inner.previous_keys.push((key, sealed));
                }
            }
            inner.header_updated_at = remote.header_updated_at;
            inner.last_ts = inner.last_ts.max(remote.header_updated_at);
            inner.changed();
        } else if same_key
            && inner.shared.is_none()
            && remote.header_updated_at == inner.header_updated_at
        {
            // The same header, with a recovery code this copy lacks: this copy came through an
            // older client (which drops the block) or a host that stripped it; the block only
            // verifies with this very header version, so it is the current code. Two codes made
            // at the same millisecond on two devices: the greater id wins on both.
            if let Some(theirs) = file_recovery(remote, &remote_key) {
                if inner
                    .recovery
                    .as_ref()
                    .is_none_or(|ours| theirs.id > ours.id)
                {
                    inner.recovery = Some(theirs);
                    inner.changed();
                }
            }
        }
        inner.merge_usage(remote, &remote_key, same_key);
        inner.merge_settings(remote, &remote_key, same_key);
        // Member changes of this device that lost to a concurrent list, applied again.
        inner.after_members_merge();
        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_kdf() -> KdfParams {
        KdfParams {
            m_kib: 64,
            t: 1,
            p: 1,
            ..Default::default()
        }
    }

    fn item(title: &str) -> Item {
        Item {
            title: title.into(),
            ..Default::default()
        }
    }

    /// Reading an item and its merge metadata in one pass gives what the two parses gave, for
    /// what this vault seals and for JSON others might have written.
    #[test]
    fn item_and_meta_reads_what_two_parses_read() {
        let vault = Vault::create_with_kdf("pw", "phone", fast_kdf()).unwrap();
        let mut saved = vec![
            vault.upsert(item("Plain")).unwrap(),
            vault
                .upsert(Item {
                    kind: ItemKind::Card,
                    title: "Card".into(),
                    card: Some(crate::model::CardData {
                        number: "4111111111111111".into(),
                        ..Default::default()
                    }),
                    fields: vec![crate::model::CustomField {
                        name: "merge".into(),
                        value: "{\"merge\":1}".into(),
                        kind: Default::default(),
                    }],
                    ..Default::default()
                })
                .unwrap(),
        ];
        let mut edited = saved[0].clone();
        edited.password = "a \"merge\": value".into();
        saved.push(vault.upsert(edited).unwrap());
        let file = vault.serialize().unwrap();
        let parsed = parse_file(&file).unwrap();
        let vk = key_from_vec(&vault.export_vault_key()).unwrap();
        let mut plains: Vec<Vec<u8>> = parsed
            .items
            .iter()
            .map(|r| {
                let sealed = Sealed {
                    nonce: r.nonce.clone().unwrap(),
                    ct: r.ct.clone().unwrap(),
                };
                let aad =
                    record_aad(&parsed.vault_id, &r.id, r.updated_at, &r.device_id, false).unwrap();
                open(&vk, &sealed, &aad).unwrap().unwrap().to_vec()
            })
            .collect();
        assert!(
            plains.iter().any(|p| stored_meta(p).is_some()),
            "no metadata sealed"
        );
        for extra in [
            r#"{"title":"no meta"}"#,
            r#"{"merge":null,"title":"null meta"}"#,
            r#"{"title":"bad meta","merge":{"base":"nonsense"}}"#,
            r#"{"merge":7,"title":"wrong type"}"#,
            r#"{"title":"nested","card":{"merge":1},"unknown":{"merge":{"x":1}}}"#,
            r#"{"title":"escaped key","merge":null}"#,
        ] {
            plains.push(extra.as_bytes().to_vec());
        }
        for plain in &plains {
            let (item, meta) = item_and_meta(plain).unwrap();
            assert_eq!(item, Item::from_stored_json(plain).unwrap());
            assert_eq!(
                serde_json::to_value(&meta).unwrap(),
                serde_json::to_value(stored_meta(plain)).unwrap(),
                "{}",
                String::from_utf8_lossy(plain)
            );
        }
        assert!(item_and_meta(b"{\"title\":").is_err());
        assert!(item_and_meta(b"{\"title\":\"x\"} trailing").is_err());
        // The one-pass reader relies on `Item` having no field of this name.
        assert!(serde_json::to_value(Item::default())
            .unwrap()
            .get(META_KEY)
            .is_none());
    }

    /// Rewrites `file` the way clients before record AAD v2 wrote it: items sealed with the v1
    /// AAD, tombstones without a tag, no header authenticator.
    fn as_legacy(file: &[u8], vk: &[u8]) -> Vec<u8> {
        let vk = key_from_vec(vk).unwrap();
        let mut parsed = parse_file(file).unwrap();
        let vault_id = parsed.vault_id.clone();
        for r in &mut parsed.items {
            if r.deleted {
                r.nonce = None;
                r.ct = None;
                continue;
            }
            let sealed = Sealed {
                nonce: r.nonce.clone().unwrap(),
                ct: r.ct.clone().unwrap(),
            };
            let aad = record_aad(&vault_id, &r.id, r.updated_at, &r.device_id, false).unwrap();
            let plain = open(&vk, &sealed, &aad).unwrap().unwrap();
            let legacy = seal(&vk, &plain, &item_aad(&vault_id, &r.id)).unwrap();
            r.nonce = Some(legacy.nonce);
            r.ct = Some(legacy.ct);
        }
        parsed.header_auth = None;
        serde_json::to_vec(&parsed).unwrap()
    }

    /// Two different usage blobs of one device that carry the same `updated_at` (a copy restored
    /// from an old file and used again, on a clock too coarse to tell the two writes apart) must
    /// still merge per item, whichever way they meet.
    #[test]
    fn same_device_usage_blobs_with_equal_versions_still_merge() {
        let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
        let a = laptop.upsert(item("A")).unwrap();
        let b = laptop.upsert(item("B")).unwrap();
        for k in 0..2 {
            laptop
                .record_use(a.id.clone(), 1_000_000 + k * crate::usage::USE_DEDUPE_MS)
                .unwrap();
        }
        let synced = laptop.serialize().unwrap();
        for k in 0..3 {
            laptop
                .record_use(a.id.clone(), 9_000_000 + k * crate::usage::USE_DEDUPE_MS)
                .unwrap();
        }
        let newer = laptop.serialize().unwrap();
        let version = laptop.lock().usage["laptop"].updated_at;

        let restored = Vault::unlock(synced, "pw".into(), "laptop".into()).unwrap();
        restored.record_use(b.id.clone(), 20_000_000).unwrap();
        {
            let mut inner = restored.lock();
            let record = inner.usage.get_mut("laptop").unwrap();
            record.updated_at = version;
            record.sealed = None;
        }
        let restored_file = restored.serialize().unwrap();

        restored.merge_remote(newer).unwrap();
        assert_eq!(restored.usage(a.id.clone()).count, 5);
        assert_eq!(restored.usage(b.id.clone()).count, 1);

        laptop.merge_remote(restored_file).unwrap();
        assert_eq!(laptop.usage(a.id.clone()).count, 5);
        assert_eq!(laptop.usage(b.id.clone()).count, 1);
    }

    /// Our blob has everything the remote one has and shares its version: it gets a new version,
    /// so the next sync uploads the larger counts instead of seeing nothing to do.
    #[test]
    fn a_larger_usage_blob_with_an_equal_version_is_republished() {
        let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
        let a = laptop.upsert(item("A")).unwrap();
        laptop.record_use(a.id.clone(), 1_000_000).unwrap();
        let old = laptop.serialize().unwrap();
        laptop.record_use(a.id.clone(), 9_000_000).unwrap();
        let version = laptop.lock().usage["laptop"].updated_at;
        let old_version = {
            let remote = Vault::unlock(old.clone(), "pw".into(), "other".into()).unwrap();
            let mut inner = remote.lock();
            inner.usage.get_mut("laptop").unwrap().updated_at = version;
            inner.usage.get_mut("laptop").unwrap().sealed = None;
            drop(inner);
            remote.serialize().unwrap()
        };
        laptop.merge_remote(old_version).unwrap();
        assert_eq!(laptop.usage(a.id.clone()).count, 2);
        assert!(laptop.lock().usage["laptop"].updated_at > version);
    }

    /// A copy without this vault's recovery code (an older client wrote it, or the host stripped
    /// it) is re-uploaded, and its fingerprint differs so the "already merged" shortcut of a sync
    /// doesn't hide it. A vault without a code keeps the fingerprint older versions computed.
    #[test]
    #[cfg(feature = "sync-core")]
    fn copies_missing_the_recovery_code_are_behind() {
        let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
        laptop.upsert(item("A")).unwrap();
        let plain = parse_file(&laptop.serialize().unwrap()).unwrap();
        let mut records: Vec<&RecordFile> = plain.items.iter().collect();
        records.sort_by(|a, b| a.id.cmp(&b.id));
        let old_style = versions_fingerprint(
            plain.header_updated_at,
            records
                .iter()
                .map(|r| (r.id.as_str(), r.updated_at, r.device_id.as_str())),
            None,
        );
        assert_eq!(plain.fingerprint(), old_style);
        assert!(!laptop.remote_is_behind(&plain));

        laptop.create_recovery_code().unwrap();
        let with = parse_file(&laptop.serialize().unwrap()).unwrap();
        assert!(!laptop.remote_is_behind(&with));
        assert!(!laptop.differs_from(&with.fingerprint()));
        let mut stripped = with.clone();
        stripped.recovery = None;
        assert!(laptop.remote_is_behind(&stripped));
        assert_ne!(stripped.fingerprint(), with.fingerprint());
        // The other way round: a copy with a code this vault lacks is not overwritten.
        let phone = Vault::unlock(
            serde_json::to_vec(&stripped).unwrap(),
            "pw".into(),
            "phone".into(),
        )
        .unwrap();
        assert!(!phone.has_recovery_code());
        assert!(!phone.remote_is_behind(&with));
        phone.merge_parsed(&with).unwrap();
        assert!(phone.has_recovery_code());
        assert!(!phone.differs_from(&with.fingerprint()));
    }

    #[test]
    fn legacy_files_still_open_and_merge_but_cannot_override() {
        let old = Vault::create_with_kdf("pw", "old", fast_kdf()).unwrap();
        let kept = old.upsert(item("Kept")).unwrap();
        let gone = old.upsert(item("Gone")).unwrap();
        old.delete_permanently(gone.id.clone()).unwrap();
        let key = old.export_vault_key();
        let legacy = as_legacy(&old.serialize().unwrap(), &key);

        // An older client's file opens (password or device key) and is re-sealed as v2.
        let a = Vault::unlock(legacy.clone(), "pw".into(), "a".into()).unwrap();
        assert_eq!(a.items().len(), 1);
        assert!(Vault::unlock_with_key(legacy.clone(), key.clone(), "b".into()).is_ok());
        let resaved = parse_file(&a.serialize().unwrap()).unwrap();
        assert!(header_authentic(&resaved, &key_from_vec(&key).unwrap()));
        for r in &resaved.items {
            let (_, authentic) = decrypt_record(&resaved.vault_id, &a.lock().vk, r).unwrap();
            assert!(authentic, "{} not re-sealed", r.id);
        }

        // Legacy records may add items a vault has never seen...
        let fresh =
            Vault::unlock_with_key(a.serialize().unwrap(), key.clone(), "fresh".into()).unwrap();
        fresh.lock().records.clear();
        let stats = fresh.merge_remote(legacy.clone()).unwrap();
        assert_eq!(stats.added, 1);

        // ...but a newer legacy version never replaces or deletes an item this vault has.
        old.upsert(Item {
            password: "newer".into(),
            ..kept.clone()
        })
        .unwrap();
        let edited = as_legacy(&old.serialize().unwrap(), &key);
        assert_eq!(a.merge_remote(edited).unwrap().updated, 0);
        old.delete_permanently(kept.id.clone()).unwrap();
        let deleted = as_legacy(&old.serialize().unwrap(), &key);
        assert_eq!(a.merge_remote(deleted).unwrap().deleted, 0);
        assert_eq!(a.get(kept.id).unwrap().password, "");
    }

    /// The plaintext of item `id` as sealed in `file`.
    fn stored_plain(file: &[u8], vk: &[u8], id: &str) -> serde_json::Value {
        let vk = key_from_vec(vk).unwrap();
        let parsed = parse_file(file).unwrap();
        let r = parsed.items.iter().find(|r| r.id == id).unwrap();
        let sealed = Sealed {
            nonce: r.nonce.clone().unwrap(),
            ct: r.ct.clone().unwrap(),
        };
        let aad = record_aad(
            &parsed.vault_id,
            &r.id,
            r.updated_at,
            &r.device_id,
            r.deleted,
        )
        .unwrap();
        serde_json::from_slice(&open(&vk, &sealed, &aad).unwrap().unwrap()).unwrap()
    }

    /// Rewrites record `id` of `file` the way a client without cards, custom fields, tags and the
    /// trash would save it after editing it: its own (old) item JSON, re-sealed at `updated_at`.
    fn as_old_client_edit(
        file: &[u8],
        vk: &[u8],
        id: &str,
        plain: &serde_json::Value,
        updated_at: i64,
    ) -> Vec<u8> {
        let key = key_from_vec(vk).unwrap();
        let mut parsed = parse_file(file).unwrap();
        let vault_id = parsed.vault_id.clone();
        let r = parsed.items.iter_mut().find(|r| r.id == id).unwrap();
        r.updated_at = updated_at;
        r.device_id = "old-client".into();
        let aad = record_aad(&vault_id, id, updated_at, "old-client", false).unwrap();
        let sealed = seal(&key, &serde_json::to_vec(plain).unwrap(), &aad).unwrap();
        r.nonce = Some(sealed.nonce);
        r.ct = Some(sealed.ct);
        serde_json::to_vec(&parsed).unwrap()
    }

    /// What an older client's item parser accepts: unknown fields ignored, but only the kinds it
    /// knew (an unknown kind fails, which would fail the whole vault).
    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    struct OldItem {
        #[serde(default)]
        kind: OldKind,
        #[serde(default)]
        title: String,
        #[serde(default)]
        notes: String,
    }

    #[derive(serde::Deserialize, Default)]
    #[serde(rename_all = "snake_case")]
    enum OldKind {
        #[default]
        Login,
        Note,
    }

    #[test]
    fn old_format_items_open_with_defaults() {
        let vault = Vault::create_with_kdf("pw", "d", fast_kdf()).unwrap();
        let saved = vault.upsert(item("Old")).unwrap();
        let key = vault.export_vault_key();
        let file = vault.serialize().unwrap();
        // An item JSON exactly as the first format wrote it (every field, none of the new ones).
        let old = serde_json::json!({"id": saved.id, "kind": "login", "title": "Old", "username": "u",
            "password": "p", "urls": ["https://old.example"], "android_apps": [], "totp": null, "passkeys": [],
            "notes": "n", "favorite": true, "created_at": 1, "updated_at": 2});
        let file = as_old_client_edit(&file, &key, &saved.id, &old, saved.updated_at + 1);
        let reopened = Vault::unlock(file, "pw".into(), "d".into()).unwrap();
        let item = reopened.get(saved.id.clone()).unwrap();
        assert_eq!(
            (item.kind, item.title.as_str(), item.favorite),
            (ItemKind::Login, "Old", true)
        );
        assert!(item.card.is_none() && item.identity.is_none());
        assert!(item.fields.is_empty() && item.tags.is_empty());
        assert_eq!((item.trashed_at, item.password_changed_at), (None, 0));
        assert!(item.url_rules.is_empty());
        // A plain item still seals without any of the new keys.
        let plain = stored_plain(&vault.serialize().unwrap(), &key, &saved.id);
        for k in [
            "card",
            "identity",
            "fields",
            "tags",
            "trashed_at",
            "password_changed_at",
            "url_rules",
        ] {
            assert!(plain.get(k).is_none(), "{k} in {plain}");
        }
    }

    #[test]
    fn cards_and_identities_are_stored_as_notes_for_older_clients() {
        let vault = Vault::create_with_kdf("pw", "d", fast_kdf()).unwrap();
        let card = vault
            .upsert(Item {
                kind: ItemKind::Card,
                title: "Visa".into(),
                card: Some(crate::model::CardData {
                    number: "4111 1111 1111 1111".into(),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .unwrap();
        let identity = vault
            .upsert(Item {
                kind: ItemKind::Identity,
                title: "Me".into(),
                ..Default::default()
            })
            .unwrap();
        let key = vault.export_vault_key();
        let file = vault.serialize().unwrap();
        for (id, sub) in [(&card.id, "card"), (&identity.id, "identity")] {
            let plain = stored_plain(&file, &key, id);
            assert_eq!(plain["kind"], "note");
            assert!(plain.get(sub).is_some());
            // An older client parses it (as a note) instead of refusing the vault.
            let old: OldItem = serde_json::from_value(plain).unwrap();
            assert!(matches!(old.kind, OldKind::Note));
        }
        let reopened = Vault::unlock(file, "pw".into(), "d".into()).unwrap();
        assert_eq!(reopened.get(card.id.clone()).unwrap().kind, ItemKind::Card);
        assert_eq!(
            reopened.get(card.id).unwrap().card.unwrap().number,
            "4111111111111111"
        );
        assert_eq!(reopened.get(identity.id).unwrap().kind, ItemKind::Identity);
    }

    #[test]
    fn new_fields_survive_merges_with_old_client_copies() {
        let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
        let x = laptop.upsert(item("X")).unwrap();
        let y = laptop.upsert(item("Y")).unwrap();
        let key = laptop.export_vault_key();
        // An older client takes this copy...
        let old_copy = laptop.serialize().unwrap();
        // ...while the laptop gives X tags, custom fields and a trash date-free edit.
        let rich = laptop
            .upsert(Item {
                tags: vec!["Work".into()],
                fields: vec![crate::model::CustomField {
                    name: "PIN".into(),
                    value: "1234".into(),
                    kind: crate::model::FieldKind::Hidden,
                }],
                ..x.clone()
            })
            .unwrap();
        // The old client edits Y (re-sealing it with its own, older item JSON) and leaves X's
        // record as it was.
        let old_y = serde_json::json!({"id": y.id, "kind": "login", "title": "Y edited"});
        let edited = as_old_client_edit(&old_copy, &key, &y.id, &old_y, crate::now_ms() + 10_000);
        let stats = laptop.merge_remote(edited.clone()).unwrap();
        assert_eq!((stats.updated, stats.added), (1, 0));
        assert_eq!(laptop.get(y.id.clone()).unwrap().title, "Y edited");
        let kept = laptop.get(x.id.clone()).unwrap();
        assert_eq!(kept.tags, rich.tags);
        assert_eq!(kept.fields, rich.fields);
        // The other way round (a new device merging the old copy and then the laptop) agrees.
        let phone = Vault::unlock(edited, "pw".into(), "phone".into()).unwrap();
        phone.merge_remote(laptop.serialize().unwrap()).unwrap();
        assert_eq!(phone.items(), laptop.items());
    }

    /// The "Available to AI tools" mark (crate::ai) is a custom field, so it survives everything
    /// that keeps custom fields: sealing, reopening, an edit by a client that knows nothing about
    /// AI tools (the Android app saves the whole UniFFI `Item`, fields included; the extension's
    /// editor never touches `fields`), and merges either way. A client without custom fields drops
    /// it, which unshares the item.
    #[test]
    fn ai_tools_mark_survives_round_trips_merges_and_other_clients() {
        use crate::{AiAccess, AI_ACCESS_FIELD};
        let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
        let mut api = item("API");
        api.fields.push(crate::model::CustomField {
            name: "Region".into(),
            value: "eu".into(),
            kind: crate::model::FieldKind::Text,
        });
        api.set_ai_access(Some(AiAccess::Allow));
        let api = laptop.upsert(api).unwrap();
        let plain_item = laptop.upsert(item("Plain")).unwrap();
        assert_eq!(api.ai_access(), Some(AiAccess::Allow));
        let key = laptop.export_vault_key();
        let file = laptop.serialize().unwrap();

        // Sealed as an ordinary text field; an item without it seals unchanged.
        let stored = stored_plain(&file, &key, &api.id);
        assert_eq!(stored["fields"][1]["name"], AI_ACCESS_FIELD);
        assert_eq!(stored["fields"][1]["value"], "Allow without asking");
        assert_eq!(stored["fields"][1]["kind"], "text");
        assert!(stored_plain(&file, &key, &plain_item.id)
            .get("fields")
            .is_none());

        let phone = Vault::unlock(file.clone(), "pw".into(), "phone".into()).unwrap();
        assert_eq!(
            phone.get(api.id.clone()).unwrap().ai_access(),
            Some(AiAccess::Allow)
        );

        // An edit through the whole item (Android: `Vault::upsert` of the UniFFI record).
        let mut edited = phone.get(api.id.clone()).unwrap();
        edited.title = "API (phone)".into();
        edited.password = "new".into();
        let edited = phone.upsert(edited).unwrap();
        assert_eq!(edited.ai_access(), Some(AiAccess::Allow));
        assert_eq!(edited.fields.len(), 2);

        // A client that keeps the JSON it parsed (any client with custom fields) edits the title.
        let mut other = stored.clone();
        other["title"] = "API (other client)".into();
        let other_file = as_old_client_edit(&file, &key, &api.id, &other, crate::now_ms() + 10_000);
        laptop.merge_remote(other_file.clone()).unwrap();
        let merged = laptop.get(api.id.clone()).unwrap();
        assert_eq!(merged.title, "API (other client)");
        assert_eq!(merged.ai_access(), Some(AiAccess::Allow));

        // Both directions agree, and the phone's edit (older) loses to the newer one with the mark.
        phone.merge_remote(laptop.serialize().unwrap()).unwrap();
        laptop.merge_remote(phone.serialize().unwrap()).unwrap();
        assert_eq!(phone.items(), laptop.items());
        assert_eq!(
            phone.get(api.id.clone()).unwrap().ai_access(),
            Some(AiAccess::Allow)
        );

        // Unsharing on one device unshares everywhere after a merge.
        let mut unshare = laptop.get(api.id.clone()).unwrap();
        unshare.set_ai_access(None);
        laptop.upsert(unshare).unwrap();
        phone.merge_remote(laptop.serialize().unwrap()).unwrap();
        assert_eq!(phone.get(api.id.clone()).unwrap().ai_access(), None);
        assert_eq!(phone.get(api.id.clone()).unwrap().fields.len(), 1);

        // A client without custom fields drops the mark when it saves the item: unshared.
        let mut shared = laptop.get(api.id.clone()).unwrap();
        shared.set_ai_access(Some(AiAccess::Ask));
        laptop.upsert(shared).unwrap();
        let file = laptop.serialize().unwrap();
        let ancient = serde_json::json!({"id": api.id, "kind": "login", "title": "API"});
        let ancient_file =
            as_old_client_edit(&file, &key, &api.id, &ancient, crate::now_ms() + 20_000);
        laptop.merge_remote(ancient_file).unwrap();
        assert_eq!(laptop.get(api.id).unwrap().ai_access(), None);
    }

    #[test]
    fn imports_never_share_with_ai_tools() {
        use crate::AiAccess;
        let vault = Vault::create_with_kdf("pw", "d", fast_kdf()).unwrap();
        let mut shared = item("Shared");
        shared.set_ai_access(Some(AiAccess::Allow));
        vault.upsert(shared).unwrap();
        // Passyble's own export keeps the mark (it is a field of the item)...
        let json = crate::export_json(vault);
        assert!(json.contains(crate::AI_ACCESS_FIELD));
        // ...but importing that file doesn't share anything.
        let report = crate::parse_import(json.as_bytes(), "export.json", None).unwrap();
        assert_eq!(report.items.len(), 1);
        assert_eq!(report.items[0].ai_access(), None);
    }

    #[test]
    fn unlocking_purges_trash_older_than_the_retention() {
        let vault = Vault::create_with_kdf("pw", "d", fast_kdf()).unwrap();
        let now = crate::now_ms();
        let old = vault
            .upsert(Item {
                trashed_at: Some(now - TRASH_RETENTION_MS - 1000),
                ..item("Old trash")
            })
            .unwrap();
        let recent = vault
            .upsert(Item {
                trashed_at: Some(now - 1000),
                ..item("Recent trash")
            })
            .unwrap();
        // The file as written before the purge (serialize() itself would purge).
        let file = vault.lock().encode_file(true).unwrap();
        let reopened = Vault::unlock(file, "pw".into(), "d".into()).unwrap();
        assert!(reopened.is_dirty());
        let trash: Vec<String> = reopened.trashed_items().into_iter().map(|i| i.id).collect();
        assert_eq!(trash, [recent.id]);
        assert!(
            reopened.lock().records[&old.id].item.is_none(),
            "a tombstone"
        );
        assert_eq!(vault.trashed_items().len(), 2);
        vault.serialize().unwrap();
        assert_eq!(vault.trashed_items().len(), 1);
        assert_eq!(vault.purge_expired_trash(now + TRASH_RETENTION_MS), 1);
        assert!(vault.trashed_items().is_empty());
    }

    #[test]
    fn timestamps_saturate_instead_of_overflowing() {
        let vault = Vault::create_with_kdf("pw", "d", fast_kdf()).unwrap();
        let first = vault.upsert(item("A")).unwrap();
        {
            let mut inner = vault.lock();
            inner.last_ts = i64::MAX;
            inner.records.get_mut(&first.id).unwrap().updated_at = i64::MAX;
        }
        let edited = vault.upsert(first.clone()).unwrap();
        assert_eq!(edited.updated_at, i64::MAX);
        vault.delete(first.id).unwrap();
        assert!(vault.serialize().is_ok());
    }

    /// The merge metadata is sealed inside the item's JSON, under a key older clients don't know:
    /// they read the item normally (serde ignores unknown keys), and when they re-seal it after an
    /// edit their `Item` has nowhere to keep it, so their version has none.
    #[test]
    fn older_clients_read_items_with_merge_metadata_and_drop_it_when_they_edit() {
        let vault = Vault::create_with_kdf("pw", "d", fast_kdf()).unwrap();
        let saved = vault.upsert(item("X")).unwrap();
        let key = vault.export_vault_key();
        let plain = stored_plain(&vault.serialize().unwrap(), &key, &saved.id);
        assert!(plain.get(META_KEY).is_some(), "{plain}");
        let old: OldItem = serde_json::from_value(plain.clone()).unwrap();
        assert_eq!(old.title, "X");
        // What an older client writes back after editing it: its own Item, re-serialized.
        let read: Item = serde_json::from_value(plain).unwrap();
        assert_eq!(read.title, "X");
        assert!(serde_json::to_value(&read).unwrap().get(META_KEY).is_none());
    }

    /// A client that keeps JSON it doesn't understand and re-seals an item under a new version of
    /// its own carries the metadata of the version it read. That metadata names another version,
    /// so it is ignored and the item merges by the whole-item rule (newer wins, the other side's
    /// password is rescued): trusting it would take the old client's notes for unchanged and drop
    /// them without a trace.
    #[test]
    fn merge_metadata_of_another_version_is_not_trusted() {
        let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
        let x = laptop
            .upsert(Item {
                password: "one".into(),
                ..item("X")
            })
            .unwrap();
        let key = laptop.export_vault_key();
        let base_file = laptop.serialize().unwrap();
        laptop
            .upsert(Item {
                notes: "laptop note".into(),
                password: "two".into(),
                ..x.clone()
            })
            .unwrap();

        let mut plain = stored_plain(&base_file, &key, &x.id);
        plain["notes"] = "old client note".into();
        let edited = as_old_client_edit(&base_file, &key, &x.id, &plain, crate::now_ms() + 10_000);
        let parsed = parse_file(&edited).unwrap();
        let r = parsed.items.iter().find(|r| r.id == x.id).unwrap();
        let (record, authentic) = decrypt_record(&parsed.vault_id, &laptop.lock().vk, r).unwrap();
        assert!(authentic);
        assert!(record.meta.is_none(), "metadata naming another version is ignored");

        laptop.merge_remote(edited).unwrap();
        let kept = laptop.get(x.id.clone()).unwrap();
        assert_eq!(kept.notes, "old client note", "the newer version wins whole");
        assert_eq!(kept.password, "one");
        assert!(
            kept.password_history.iter().any(|h| h.password == "two"),
            "the laptop's password is rescued"
        );
        assert_eq!(laptop.items().len(), 1, "no conflict copy");
    }

    /// An older client's edit (no metadata) merges by the whole-item rule; edits that upgraded
    /// devices make on top of it carry metadata again (that version counting as one write of
    /// every field), so they merge field by field.
    #[test]
    fn edits_on_top_of_an_older_clients_version_merge_field_by_field_again() {
        let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
        let x = laptop.upsert(item("X")).unwrap();
        let key = laptop.export_vault_key();
        let old = serde_json::json!({"id": x.id, "kind": "login", "title": "X", "username": "u",
            "password": "p", "notes": ""});
        let file = as_old_client_edit(
            &laptop.serialize().unwrap(),
            &key,
            &x.id,
            &old,
            crate::now_ms() + 50,
        );
        laptop.merge_remote(file).unwrap();
        assert!(laptop.lock().records[&x.id].meta.is_none());
        let phone = Vault::unlock(laptop.serialize().unwrap(), "pw".into(), "phone".into()).unwrap();

        let current = laptop.get(x.id.clone()).unwrap();
        laptop
            .upsert(Item {
                notes: "laptop note".into(),
                ..current.clone()
            })
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(3));
        phone
            .upsert(Item {
                username: "u.phone".into(),
                ..current
            })
            .unwrap();
        laptop.merge_remote(phone.serialize().unwrap()).unwrap();
        phone.merge_remote(laptop.serialize().unwrap()).unwrap();
        for v in [&laptop, &phone] {
            let kept = v.get(x.id.clone()).unwrap();
            assert_eq!((kept.notes.as_str(), kept.username.as_str()), ("laptop note", "u.phone"));
            assert_eq!(v.items().len(), 1);
        }
        assert_eq!(laptop.items(), phone.items());
    }

    /// The merge metadata costs little: an item edited on two devices (with UUID device ids)
    /// carries a few hundred bytes of it.
    #[test]
    fn merge_metadata_stays_small() {
        let laptop =
            Vault::create_with_kdf("pw", "8d5c1f0e-3b7a-4c55-9a51-0f6f3f0b2c11", fast_kdf())
                .unwrap();
        let x = laptop.upsert(item("X")).unwrap();
        let phone = Vault::unlock(
            laptop.serialize().unwrap(),
            "pw".into(),
            "2a9e7d64-7f0c-4f3e-8b8e-3c4d5e6f7a8b".into(),
        )
        .unwrap();
        phone
            .upsert(Item {
                notes: "n".into(),
                password: "p".into(),
                ..x.clone()
            })
            .unwrap();
        laptop.merge_remote(phone.serialize().unwrap()).unwrap();
        let key = laptop.export_vault_key();
        let plain = stored_plain(&laptop.serialize().unwrap(), &key, &x.id);
        let meta = serde_json::to_vec(&plain[META_KEY]).unwrap();
        assert!(meta.len() < 400, "{} bytes: {}", meta.len(), plain[META_KEY]);
    }
}
