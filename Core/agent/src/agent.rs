use std::collections::{HashMap, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard, Weak};
use std::time::Duration;

use pass_core::{registrable_domain, Item, ItemKind, ItemSummary, PassError, Vault};

#[path = "linked.rs"]
mod linked;
pub(crate) use linked::{payload, ListStamp, Listed, Opened};
pub use linked::{
    LinkedError, LinkedNotice, LinkedStatus, LinkedVaultConfig, PasswordPolicy, PasswordPolicyMode,
    TeamsSummary, VaultKind, VaultRef,
};

use crate::clock::{Clock, Instant};
use crate::store::{Replaced, Stamp, VaultStore};
use crate::Ui;

/// How long a filled login keeps offering its TOTP code on the next screen.
pub const PENDING_OTP_TTL: Duration = Duration::from_secs(180);

/// Longest the auto-lock waits past its timeout for a request in progress ([`Agent::busy`]): a
/// prompt left open (they give up after 2 minutes) can't keep the vault unlocked for long.
pub const BUSY_HOLD_MAX: Duration = Duration::from_secs(5 * 60);

/// Whether the auto-lock is due: `idle` reached `auto_lock` and no request is in progress
/// (`busy`), unless one has held it off for [`BUSY_HOLD_MAX`] already.
pub fn auto_lock_due(idle: Duration, auto_lock: Duration, busy: bool) -> bool {
    idle >= auto_lock && (!busy || idle >= auto_lock.saturating_add(BUSY_HOLD_MAX))
}

#[derive(Clone, Debug)]
pub struct AgentConfig {
    /// The vault file. Put it in a OneDrive/Dropbox/Syncthing folder for folder-based sync.
    pub vault_path: PathBuf,
    pub device_id: String,
    pub auto_lock: Duration,
    #[cfg(feature = "webdav")]
    pub webdav: Option<pass_core::WebDavConfig>,
    /// Google Drive backup. The app holds the OAuth tokens and passes a fresh access token to
    /// [`Agent::sync_gdrive`]. Never set together with `webdav`.
    #[cfg(feature = "gdrive")]
    pub gdrive: Option<GDriveTarget>,
    /// Where this vault's soft-lock list is kept between runs (sealed, no secrets). `None`: memory
    /// only.
    pub kept_list: Option<PathBuf>,
}

impl AgentConfig {
    /// A configuration without sync and without a list kept on disk.
    pub fn new(vault_path: PathBuf, device_id: String, auto_lock: Duration) -> AgentConfig {
        AgentConfig {
            vault_path,
            device_id,
            auto_lock,
            #[cfg(feature = "webdav")]
            webdav: None,
            #[cfg(feature = "gdrive")]
            gdrive: None,
            kept_list: None,
        }
    }
}

/// Which Google account a vault is backed up to, and the name kept with the Drive file (for the
/// restore list on a new device).
#[cfg(feature = "gdrive")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GDriveTarget {
    /// The account's e-mail address (from Drive `about.get`); keys the app's refresh token.
    pub account: String,
    /// The vault's display name (`GDriveConfig::vault_name`).
    pub vault_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingOtp {
    pub item_id: String,
    pub title: String,
}

/// How [`Agent::lock_as`] locks the vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockKind {
    /// The vault key and every secret are dropped, but the list of items without secrets
    /// ([`ItemSummary`]) stays in memory, so titles and usernames can still be shown.
    Soft,
    /// Everything is dropped, the list too.
    Full,
}

struct State {
    vault: Option<Arc<Vault>>,
    /// The list kept while soft-locked ([`LockKind::Soft`]).
    index: Option<Arc<Vec<ItemSummary>>>,
    /// The vault revision last written to [`AgentConfig::kept_list`] since the unlock, and when.
    kept_written: Option<u64>,
    kept_written_at: Option<Instant>,
    /// Nothing is written to [`AgentConfig::kept_list`] until the next unlock.
    kept_paused: bool,
    /// The last use of the unlocked vault: the auto-lock runs from here.
    last_activity: Instant,
    /// Idle time before `last_activity` that still counts ([`Agent::set_idle_for`]). Kept apart
    /// because a monotonic clock can't always go back that far (in WebAssembly it starts near
    /// zero with the service worker).
    idle_before: Duration,
    /// Requests in progress ([`Agent::busy`]): the auto-lock waits for them, so a fill isn't cut
    /// off while its Windows Hello prompt is up.
    busy: usize,
    /// The vault file's [`Stamp`] when we last read or wrote it.
    file_mtime: Option<Stamp>,
    /// A save is writing the vault file outside this lock: the file changing meanwhile is that
    /// write, not a sync client, so it isn't read back.
    writing: bool,
    pending_otp: HashMap<String, (String, Instant)>,
    /// The last write failed after `Vault::serialize` had already cleared the dirty flag, so the
    /// next save must write even though the vault looks clean.
    unsaved: bool,
    /// Logins deleted from the browser extension, for `logins.restore`. Memory only.
    deleted: Vec<DeletedLogin>,
    /// When recent edit requests arrived, per kind (rate limit).
    edits: HashMap<&'static str, VecDeque<Instant>>,
    /// Logins the user was verified for in the extension's editor, so saving the edit doesn't ask
    /// again.
    edit_grants: HashMap<String, Instant>,
    /// Logins `logins.search` returned, which the popup may then copy from or cross-fill.
    search_hits: HashMap<String, Instant>,
    /// What `logins.search` read of the lists, for the next keystroke (`protocol/search.rs`).
    /// Dropped with `search_hits`.
    search_lists: Option<Arc<crate::protocol::search::SearchLists>>,
    /// The cross-site fills of the last minutes (`logins.fill_cross` of another site's login),
    /// each with the one-time token its answer carried, so `logins.add_url` can add that page to
    /// that login and nothing else. Dropped on lock and after [`CROSS_FILL_GRANT`]; at most
    /// [`MAX_CROSS_FILLS`].
    cross_fills: Vec<CrossFill>,
    /// Hashes of the passwords `generate` returned, so `generate.copy` copies those and nothing
    /// else. Never the passwords.
    generated: VecDeque<(Instant, Vec<u8>)>,
    /// The shared vaults beside the home vault (`linked.rs`).
    linked: linked::LinkedState,
}

/// How long [`Agent::record_use`] waits before saving the use, so the fill is answered first and a
/// burst of uses is one write.
pub const USE_SAVE_DELAY: Duration = Duration::from_secs(2);

/// At most one write of the kept list per this long while the vault is edited; unlocking and
/// locking write it at once.
pub const KEPT_LIST_THROTTLE: Duration = Duration::from_secs(10);

/// How long a login found with `logins.search` can be copied from or cross-filled.
pub const SEARCH_GRANT: Duration = Duration::from_secs(600);

/// Search hits remembered at most (the oldest go first).
const MAX_SEARCH_HITS: usize = 500;

/// How long the page of a cross-site fill can be added to the login that was filled
/// (`logins.add_url` with the fill's `add_url_token`).
pub const CROSS_FILL_GRANT: Duration = Duration::from_secs(600);

/// Cross-site fills remembered at most (the oldest go first).
const MAX_CROSS_FILLS: usize = 16;

/// A cross-site fill (`logins.fill_cross` of another site's login), for `logins.add_url`.
struct CrossFill {
    token: String,
    item_id: String,
    /// The page's origin (`https://a.example`).
    origin: String,
    at: Instant,
}

/// How long a password from `generate` can be copied with `generate.copy`: as long as the
/// extension keeps it for the page (its menu may have been open for a while before the pick).
pub const GENERATED_GRANT: Duration = Duration::from_secs(600);

/// Generated passwords remembered at most (the oldest go first).
const MAX_GENERATED: usize = 16;

/// How long opening a login in the extension's editor covers saving it without asking again.
pub const EDIT_GRANT: Duration = Duration::from_secs(600);

/// How long a login deleted from the browser extension can be restored.
pub const DELETE_UNDO_WINDOW: Duration = Duration::from_secs(60);

/// A login deleted from the browser extension, kept for its Undo.
pub(crate) struct DeletedLogin {
    pub vault_id: String,
    /// Registrable domain of the page it was deleted from: Undo must come from the same site.
    pub site: String,
    pub item: Item,
    pub at: Instant,
}

/// See [`Agent::busy`].
pub(crate) struct Busy<'a>(&'a Agent);

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        let mut state = self.0.state();
        state.busy = state.busy.saturating_sub(1);
    }
}

/// How the agent runs the timers that may wait (the save of a use, [`Agent::save_soon`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timers {
    /// On a thread of the agent's own (the desktop app).
    Thread,
    /// The host calls [`Agent::tick`] when [`Agent::next_tick`] says (WebAssembly has no threads).
    Host,
}

/// What the agent runs on: where the vault file is kept, the clock, and how its timers run.
#[derive(Clone)]
pub struct AgentHost {
    pub store: Arc<dyn VaultStore>,
    pub clock: Arc<dyn Clock>,
    pub timers: Timers,
}

impl AgentHost {
    /// The desktop: the vault file on disk, the system clock, a thread for the save delay.
    #[cfg(feature = "native")]
    pub fn native() -> AgentHost {
        AgentHost {
            store: Arc::new(crate::store::FileStore),
            clock: Arc::new(crate::clock::SystemClock),
            timers: Timers::Thread,
        }
    }

    /// A host that keeps the vault file itself and drives the timers ([`Timers::Host`]).
    pub fn hosted(store: Arc<dyn VaultStore>) -> AgentHost {
        AgentHost {
            store,
            clock: Arc::new(crate::clock::SystemClock),
            timers: Timers::Host,
        }
    }
}

pub struct Agent {
    /// Changed at runtime by [`Agent::reconfigure`]. Lock order: `state` before `config`, and
    /// a `config` guard is never held while taking `state`.
    config: RwLock<AgentConfig>,
    pub(crate) ui: Arc<dyn Ui>,
    state: Mutex<State>,
    /// One write of the vault file at a time. [`Agent::save`] writes while holding only this, not
    /// `state`, so requests (a fill, the list) never wait for the disk. Lock order: `sync_lock`,
    /// then `file_lock`, then `state`.
    file_lock: Mutex<()>,
    /// Wakes the thread that saves [`Agent::save_soon`]'s changes (started on first use).
    saver: Mutex<Option<mpsc::Sender<()>>>,
    /// This agent, for that thread (which must not keep it alive).
    me: Weak<Agent>,
    /// One sync at a time, so two runs can't both create the remote file or record each other's
    /// stale ETag.
    #[cfg_attr(not(feature = "webdav"), allow(dead_code))]
    sync_lock: Mutex<()>,
    /// "Keep list visible when locked": the default lock is [`LockKind::Soft`] or
    /// [`LockKind::Full`].
    keep_list: AtomicBool,
    /// The app's website icon cache, read by `icons.get`. `None`: no icons.
    icon_cache_dir: RwLock<Option<PathBuf>>,
    /// How the 2FA step went per site after a fill (`otp.outcome`, `skips_2fa`).
    otp_history: Mutex<crate::otp_history::OtpHistory>,
    /// Seals the kept list on disk; `None`: memory only.
    kept_sealer: Mutex<Option<Arc<dyn crate::kept_list::Sealer>>>,
    /// Pending unlocks the browser asked for to fill a login: (number, item id). See
    /// [`Agent::unlock_requested_for`].
    unlock_for: Mutex<Vec<(u64, String)>>,
    store: Arc<dyn VaultStore>,
    clock: Arc<dyn Clock>,
    timers: Timers,
    /// [`Timers::Host`]: when [`Agent::save_soon`]'s save is due.
    save_due: Mutex<Option<Instant>>,
    /// Read-only mode: this app is below the minimum version.
    pub(crate) update_required: AtomicBool,
    /// One write of a shared vault's local copy at a time (`linked.rs`).
    shared_lock: Mutex<()>,
    /// The connector for AI tools: grants, the log of recent requests, denials (`ai.rs`).
    /// Lock order: never held while taking `state`.
    pub(crate) ai: Mutex<crate::ai::AiState>,
    /// One AI approval prompt at a time.
    pub(crate) ai_prompts: crate::ai::AiPrompts,
}

/// Longest item id an unlock request may name with `for` (ids are UUIDs); longer ones are ignored.
const MAX_FOR_ID: usize = 128;

/// Numbers the entries of `Agent::unlock_for`.
static NEXT_UNLOCK_FOR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// An unlock asked for the fill of a login, registered until dropped ([`Agent::unlocking_for`]).
pub(crate) struct UnlockFor<'a> {
    agent: &'a Agent,
    number: Option<u64>,
}

impl Drop for UnlockFor<'_> {
    fn drop(&mut self) {
        if let Some(number) = self.number {
            self.agent
                .unlock_for
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .retain(|(n, _)| *n != number);
        }
    }
}

/// How a desktop window matched a login for auto-type ([`Agent::match_window`]), weakest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum WindowMatch {
    /// A site's name (`github` for github.com) appears in the window title. Weak: chat windows,
    /// documents and browser tabs mention site names too, so this is never typed without asking.
    SiteName,
    /// The item's title appears in the window title.
    Title,
    /// The item is pinned to the window's app (`windows:<exe>`, `macos:<bundle id>`).
    Pinned,
}

/// The `vault file: ` prefix lets the app tell file errors from a damaged vault.
fn io_err(e: io::Error) -> PassError {
    PassError::Corrupt(format!("vault file: {e}"))
}

#[cfg(feature = "webdav")]
fn same_webdav(a: &AgentConfig, b: &AgentConfig) -> bool {
    a.webdav == b.webdav && same_gdrive(a, b)
}

#[cfg(not(feature = "webdav"))]
fn same_webdav(_a: &AgentConfig, _b: &AgentConfig) -> bool {
    true
}

/// The same Google account (a renamed vault keeps the vault unlocked).
#[cfg(feature = "gdrive")]
fn same_gdrive(a: &AgentConfig, b: &AgentConfig) -> bool {
    a.gdrive.as_ref().map(|g| &g.account) == b.gdrive.as_ref().map(|g| &g.account)
}

#[cfg(all(feature = "webdav", not(feature = "gdrive")))]
fn same_gdrive(_a: &AgentConfig, _b: &AgentConfig) -> bool {
    true
}

/// A vault file write prepared under the state lock and done outside it ([`Agent::save`]).
struct PendingWrite {
    vault: Arc<Vault>,
    path: PathBuf,
    bytes: Vec<u8>,
    /// The file's stamp the bytes were merged against ([`Agent::reload_locked`]): the write only
    /// replaces a file that still has it ([`VaultStore::replace`]).
    seen: Option<Stamp>,
}

/// How often a save reads, merges and tries again when the vault file keeps changing under it
/// (a sync client putting in other devices' copies) before it gives up for now. The edits stay
/// in memory and are written by the next save; locking keeps a copy beside the file.
const SAVE_ATTEMPTS: usize = 4;

/// The error of a save that gave up because the file kept changing ([`SAVE_ATTEMPTS`]).
fn file_kept_changing() -> PassError {
    PassError::Conflict("the vault file kept changing while it was saved".into())
}

/// Where a vault that couldn't be saved to `path` is kept instead: a sibling that the next unlock
/// merges in and removes.
fn stash_path(path: &Path, ms: i64) -> PathBuf {
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "pass".into());
    path.with_file_name(format!("{stem}-unsaved-{}.vault", ms.max(0)))
}

/// Whether `dir` is in iCloud Drive: `~/Library/Mobile Documents` on macOS, the `iCloudDrive`
/// folder of iCloud for Windows.
fn in_icloud_drive(dir: &Path) -> bool {
    let names: Vec<String> = dir
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect();
    names
        .windows(2)
        .any(|w| w[0] == "library" && w[1] == "mobile documents")
        || names.iter().any(|n| n == "iclouddrive")
}

/// Whether `file_name` is iCloud Drive's conflict copy of `<stem>.vault`: `<stem> <n>.vault`, `n`
/// from 2 to 99. Only checked in iCloud Drive folders ([`in_icloud_drive`]), where iCloud names
/// copies this way; elsewhere `pass 2.vault` is the user's own file.
fn is_icloud_copy(stem: &str, file_name: &str) -> bool {
    file_name
        .strip_suffix(".vault")
        .and_then(|n| n.strip_prefix(stem))
        .and_then(|rest| rest.strip_prefix(' '))
        .filter(|n| {
            (1..=2).contains(&n.len())
                && !n.starts_with('0')
                && n.chars().all(|c| c.is_ascii_digit())
        })
        .and_then(|n| n.parse::<u32>().ok())
        .is_some_and(|n| (2..=99).contains(&n))
}

/// Whether `file_name` is a conflict copy of `<stem>.vault` made by a sync client, or one of the
/// agent's own `-unsaved-` stashes. Anything else is the user's file and is never merged or
/// deleted.
///
/// * agent stash: `<stem>-unsaved-<ms>.vault`
/// * OneDrive: `<stem>-<COMPUTERNAME>.vault`, `<stem>-<COMPUTERNAME>-<n>.vault` (upper case, at
///   least one letter, so `pass-backup.vault` and `pass-2024-01-01.vault` don't match)
/// * Dropbox: `<stem> (<name>'s conflicted copy <date>).vault`, also with a ` (<n>)` after it
/// * Syncthing: `<stem>.sync-conflict-<YYYYMMDD>-<HHMMSS>-<ID>.vault`
/// * Google Drive: `<stem> (<n>).vault`
fn is_conflict_copy(stem: &str, file_name: &str) -> bool {
    let Some(rest) = file_name
        .strip_suffix(".vault")
        .and_then(|n| n.strip_prefix(stem))
    else {
        return false;
    };
    let all = |s: &str, f: fn(char) -> bool| !s.is_empty() && s.chars().all(f);
    let numbered = |s: &str| {
        s.strip_prefix(" (")
            .and_then(|s| s.strip_suffix(')'))
            .is_some_and(|n| all(n, |c| c.is_ascii_digit()))
    };
    if let Some(ms) = rest.strip_prefix("-unsaved-") {
        return all(ms, |c| c.is_ascii_digit());
    }
    if let Some(name) = rest.strip_prefix('-') {
        // Starts and ends with a letter or digit; a trailing `-<n>` is covered by the `-`.
        let edge =
            |c: Option<char>| c.is_some_and(|c| c.is_ascii_uppercase() || c.is_ascii_digit());
        return name.chars().any(|c| c.is_ascii_uppercase())
            && edge(name.chars().next())
            && edge(name.chars().last())
            && name
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-');
    }
    if let Some(sync) = rest.strip_prefix(".sync-conflict-") {
        let parts: Vec<&str> = sync.split('-').collect();
        // Newer Syncthing adds `-<modified by>` (a device ID) after the 7-character ID.
        return matches!(parts.len(), 3 | 4)
            && parts[0].len() == 8
            && parts[1].len() == 6
            && all(parts[0], |c| c.is_ascii_digit())
            && all(parts[1], |c| c.is_ascii_digit())
            && parts[2..]
                .iter()
                .all(|p| all(p, |c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)));
    }
    if numbered(rest) {
        return true;
    }
    // Dropbox: ` (<who>'s conflicted copy <date>)`, then possibly ` (<n>)`.
    let Some(inner) = rest.strip_prefix(" (") else {
        return false;
    };
    let inner = match inner.rfind(") (") {
        Some(at) if numbered(&inner[at + 1..]) => &inner[..at + 1],
        _ => inner,
    };
    inner
        .strip_suffix(')')
        .is_some_and(|i| i.contains(" conflicted copy") || i.starts_with("conflicted copy"))
}

impl Agent {
    /// An agent for the desktop ([`AgentHost::native`]).
    #[cfg(feature = "native")]
    pub fn new(config: AgentConfig, ui: Arc<dyn Ui>) -> Arc<Agent> {
        Agent::with_host(config, ui, AgentHost::native())
    }

    /// An agent on `host` (see [`AgentHost`]).
    pub fn with_host(config: AgentConfig, ui: Arc<dyn Ui>, host: AgentHost) -> Arc<Agent> {
        let started = host.clock.now();
        Arc::new_cyclic(|me| Agent {
            config: RwLock::new(config),
            ui,
            file_lock: Mutex::new(()),
            saver: Mutex::new(None),
            me: me.clone(),
            state: Mutex::new(State {
                vault: None,
                index: None,
                kept_written: None,
                kept_written_at: None,
                kept_paused: false,
                last_activity: started,
                idle_before: Duration::ZERO,
                busy: 0,
                file_mtime: None,
                writing: false,
                pending_otp: HashMap::new(),
                unsaved: false,
                deleted: Vec::new(),
                edits: HashMap::new(),
                edit_grants: HashMap::new(),
                search_hits: HashMap::new(),
                search_lists: None,
                cross_fills: Vec::new(),
                generated: VecDeque::new(),
                linked: Default::default(),
            }),
            shared_lock: Mutex::new(()),
            sync_lock: Mutex::new(()),
            keep_list: AtomicBool::new(true),
            icon_cache_dir: RwLock::new(None),
            otp_history: Mutex::new(Default::default()),
            kept_sealer: Mutex::new(crate::kept_list::platform_sealer()),
            unlock_for: Mutex::new(Vec::new()),
            store: host.store,
            clock: host.clock,
            timers: host.timers,
            save_due: Mutex::new(None),
            update_required: AtomicBool::new(false),
            ai: Mutex::default(),
            ai_prompts: Default::default(),
        })
    }

    /// Now, on the agent's monotonic clock ([`AgentHost::clock`]).
    pub(crate) fn now(&self) -> Instant {
        self.clock.now()
    }

    /// Time since `at` on the agent's clock (zero if `at` is later).
    pub(crate) fn since(&self, at: Instant) -> Duration {
        self.now().saturating_duration_since(at)
    }

    /// Now in Unix milliseconds, on the agent's clock.
    pub(crate) fn unix_ms(&self) -> i64 {
        self.clock.unix_ms()
    }

    fn kept_sealer(&self) -> Option<Arc<dyn crate::kept_list::Sealer>> {
        self.kept_sealer
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    #[cfg(all(test, feature = "native"))]
    pub(crate) fn set_kept_sealer(&self, sealer: Option<Arc<dyn crate::kept_list::Sealer>>) {
        *self.kept_sealer.lock().unwrap_or_else(|p| p.into_inner()) = sealer;
    }

    #[cfg(all(test, feature = "native"))]
    pub(crate) fn expire_kept_throttle(&self) {
        self.state().kept_written_at = None;
    }

    /// Writes the list of `vault` (or `items`, already built from it) to [`AgentConfig::kept_list`].
    /// Without `force`, only if the vault changed and [`KEPT_LIST_THROTTLE`] has passed. A failed
    /// write is logged and retried by a later tick.
    fn write_kept_list_locked(
        &self,
        state: &mut State,
        vault: &Vault,
        items: Option<&[ItemSummary]>,
        force: bool,
    ) {
        if !self.keeps_list() || state.kept_paused {
            return;
        }
        let Some(path) = self.cfg().kept_list.clone() else {
            return;
        };
        let Some(sealer) = self.kept_sealer() else {
            return;
        };
        let revision = vault.revision();
        let throttled = state
            .kept_written_at
            .is_some_and(|at| self.since(at) < KEPT_LIST_THROTTLE);
        if !force && (state.kept_written == Some(revision) || throttled) {
            return;
        }
        state.kept_written_at = Some(self.now());
        let built;
        let items = match items {
            Some(items) => items,
            None => {
                built = vault.summaries();
                &built
            }
        };
        let saved_at = self.unix_ms();
        match crate::kept_list::save(&path, sealer.as_ref(), &vault.vault_id(), items, saved_at) {
            Ok(()) => state.kept_written = Some(revision),
            Err(e) => eprintln!("pass-agent: could not keep the list for the next start: {e}"),
        }
    }

    /// At start-up: loads the list kept on disk for this vault, so the agent begins soft-locked.
    /// Only if the vault file is readable and is the vault the list was written for. `true` if it
    /// was loaded.
    pub fn restore_kept_list(&self) -> bool {
        let (path, vault_path) = {
            let config = self.cfg();
            (config.kept_list.clone(), config.vault_path.clone())
        };
        let (Some(path), Some(sealer)) = (path, self.kept_sealer()) else {
            return false;
        };
        let restorable = |state: &State| {
            self.keeps_list()
                && !state.kept_paused
                && state.vault.is_none()
                && state.index.is_none()
        };
        if !restorable(&self.state()) {
            return false;
        }
        // The vault file can't be read (a cloud folder still syncing): nothing shown, list kept.
        let Some(vault_id) = self.vault_file_id_at(&vault_path) else {
            return false;
        };
        let Some(items) = crate::kept_list::load(&path, sealer.as_ref(), &vault_id) else {
            return false;
        };
        let loaded = {
            let mut state = self.state();
            let current = {
                let config = self.cfg();
                config.kept_list.as_deref() == Some(path.as_path())
                    && config.vault_path == vault_path
            };
            let fits = current && restorable(&state);
            if fits {
                state.index = Some(Arc::new(items));
                state.linked.home_id = Some(vault_id.clone());
            }
            fits
        };
        if loaded {
            self.ui.notify_lock_state(true);
            self.restore_shared_kept_lists();
        }
        loaded
    }

    /// Deletes the kept list on disk and in memory; nothing is written again until the next
    /// unlock.
    pub fn forget_kept_list(&self) {
        let dropped = {
            let mut state = self.state();
            state.kept_paused = true;
            state.kept_written = None;
            if let Some(path) = self.cfg().kept_list.clone() {
                crate::kept_list::remove(&path);
            }
            self.remove_shared_kept_lists();
            if state.vault.is_none() {
                state.linked.kept.clear();
            }
            let dropped = state.vault.is_none() && state.index.take().is_some();
            if dropped {
                state.search_hits.clear();
                state.search_lists = None;
            }
            dropped
        };
        if dropped {
            self.ui.notify_lock_state(true);
        }
    }

    /// Registers an unlock the browser asked for to fill login `item_id` (`for`), until the guard
    /// is dropped. `None` (or an id that can't be one) registers nothing.
    pub(crate) fn unlocking_for(&self, item_id: Option<String>) -> UnlockFor<'_> {
        let number = item_id
            .filter(|id| !id.is_empty() && id.len() <= MAX_FOR_ID)
            .map(|id| {
                let number = NEXT_UNLOCK_FOR.fetch_add(1, Ordering::Relaxed);
                self.unlock_for
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push((number, id));
                number
            });
        UnlockFor {
            agent: self,
            number,
        }
    }

    /// The login the latest pending unlock request from the browser is for, so the app can count
    /// that unlock as the verification of that one fill. `None`: no such request.
    pub fn unlock_requested_for(&self) -> Option<String> {
        self.unlock_for
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .last()
            .map(|(_, id)| id.clone())
    }

    pub(crate) fn otp_history(&self) -> MutexGuard<'_, crate::otp_history::OtpHistory> {
        self.otp_history.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Where the app keeps website icons (`None` turns `icons.get` off). The agent only reads
    /// this cache; the app fills it.
    pub fn set_icon_cache_dir(&self, dir: Option<PathBuf>) {
        *self
            .icon_cache_dir
            .write()
            .unwrap_or_else(|p| p.into_inner()) = dir;
    }

    /// See [`Agent::set_icon_cache_dir`].
    pub fn icon_cache_dir(&self) -> Option<PathBuf> {
        self.icon_cache_dir
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn cfg(&self) -> RwLockReadGuard<'_, AgentConfig> {
        self.config.read().unwrap_or_else(|p| p.into_inner())
    }

    fn cfg_mut(&self) -> RwLockWriteGuard<'_, AgentConfig> {
        self.config.write().unwrap_or_else(|p| p.into_inner())
    }

    /// A snapshot of the current configuration.
    pub fn config(&self) -> AgentConfig {
        self.cfg().clone()
    }

    /// Applies new settings without a restart. A different vault file, device id or WebDAV
    /// account first saves the vault to the old location and then locks it, so nothing unlocked
    /// for one configuration is written to another. A new auto-lock time just takes effect.
    /// Returns `true` if this locked an unlocked vault.
    pub fn reconfigure(&self, config: AgentConfig) -> bool {
        let relock = {
            let current = self.cfg();
            current.vault_path != config.vault_path
                || current.device_id != config.device_id
                || !same_webdav(&current, &config)
        };
        if !relock {
            *self.cfg_mut() = config;
            return false;
        }
        // The shared vaults belong to this vault's account: saved, then forgotten with it (the app
        // lists the next vault's with `set_linked_vaults`).
        self.remember_dirty_linked();
        self.write_dirty_linked();
        self.ai_forget_grants();
        let (was_unlocked, had_list) = {
            let _file = self.file_lock();
            let mut state = self.state();
            state.linked = Default::default();
            let _ = self.save_or_stash_locked(&mut state);
            // The vault left keeps its list on disk for the next time it is opened.
            if let Some(vault) = state.vault.clone() {
                self.write_kept_list_locked(&mut state, &vault, None, true);
            }
            state.kept_written = None;
            state.kept_written_at = None;
            *self.cfg_mut() = config;
            state.pending_otp.clear();
            state.deleted.clear();
            state.edit_grants.clear();
            state.cross_fills.clear();
            state.search_hits.clear();
            state.search_lists = None;
            state.file_mtime = None;
            state.unsaved = false;
            // Another vault: nothing of this one stays on screen.
            let had_list = state.index.take().is_some();
            (state.vault.take().is_some(), had_list)
        };
        if was_unlocked || had_list {
            self.ui.notify_lock_state(true);
        }
        was_unlocked
    }

    /// Replaces only the WebDAV account and keeps the vault unlocked, for callers that have just
    /// synced the unlocked vault with the new account themselves.
    #[cfg(feature = "webdav")]
    pub fn set_webdav(&self, webdav: Option<pass_core::WebDavConfig>) {
        self.cfg_mut().webdav = webdav;
    }

    /// Replaces only the Google Drive target and keeps the vault unlocked, like
    /// [`Agent::set_webdav`].
    #[cfg(feature = "gdrive")]
    pub fn set_gdrive(&self, gdrive: Option<GDriveTarget>) {
        self.cfg_mut().gdrive = gdrive;
    }

    /// A sync account (WebDAV / Passyble Server or Google Drive) is configured.
    pub fn has_sync_account(&self) -> bool {
        let config = self.cfg();
        #[cfg(feature = "gdrive")]
        if config.gdrive.is_some() {
            return true;
        }
        #[cfg(feature = "webdav")]
        if config.webdav.is_some() {
            return true;
        }
        let _ = &config;
        false
    }

    pub fn vault_exists(&self) -> bool {
        let path = self.cfg().vault_path.clone();
        self.store.exists(&path)
    }

    pub fn is_locked(&self) -> bool {
        self.state().vault.is_none()
    }

    /// Locked, but with the list of items kept ([`LockKind::Soft`]).
    pub fn is_soft_locked(&self) -> bool {
        let state = self.state();
        state.vault.is_none() && state.index.is_some()
    }

    /// The vault's items without secrets: built from the unlocked vault, or the list kept by a soft
    /// lock. `None` when fully locked. Not activity.
    pub fn summaries(&self) -> Option<Arc<Vec<ItemSummary>>> {
        let (vault, index) = {
            let state = self.state();
            (state.vault.clone(), state.index.clone())
        };
        match vault {
            Some(vault) => Some(Arc::new(vault.summaries())),
            None => index,
        }
    }

    /// How many items the vault holds: the unlocked vault's, or the list a soft lock keeps. `None`
    /// when fully locked. Not activity.
    pub fn item_count(&self) -> Option<usize> {
        let (vault, index) = {
            let state = self.state();
            (state.vault.clone(), state.index.clone())
        };
        match vault {
            Some(vault) => Some(vault.item_count()),
            None => index.map(|list| list.len()),
        }
    }

    /// "Keep list visible when locked" (on by default). Off: every lock is [`LockKind::Full`], and
    /// the list kept in memory and on disk is dropped.
    pub fn set_keep_list(&self, keep: bool) {
        self.keep_list.store(keep, Ordering::Relaxed);
        if keep {
            let mut state = self.state();
            state.kept_written = None;
            state.kept_written_at = None;
            return;
        }
        let dropped = {
            let mut state = self.state();
            state.kept_written = None;
            if let Some(path) = self.cfg().kept_list.clone() {
                crate::kept_list::remove(&path);
            }
            self.remove_shared_kept_lists();
            if state.vault.is_none() {
                state.linked.kept.clear();
            }
            state.vault.is_none() && state.index.take().is_some()
        };
        if dropped {
            self.ui.notify_lock_state(true);
        }
    }

    /// See [`Agent::set_keep_list`].
    pub fn keeps_list(&self) -> bool {
        self.keep_list.load(Ordering::Relaxed)
    }

    /// The lock "Lock", auto-lock, Win+L and sleep use: soft unless the list is not to be kept.
    fn default_lock(&self) -> LockKind {
        if self.keeps_list() {
            LockKind::Soft
        } else {
            LockKind::Full
        }
    }

    /// The unlocked vault, refreshing the inactivity timer. Requests that count only once they
    /// succeed use [`Agent::peek_vault`].
    pub fn vault(&self) -> Option<Arc<Vault>> {
        let now = self.now();
        let mut state = self.state();
        state.last_activity = now;
        state.idle_before = Duration::ZERO;
        state.vault.clone()
    }

    /// The unlocked vault without refreshing the inactivity timer.
    pub fn peek_vault(&self) -> Option<Arc<Vault>> {
        self.state().vault.clone()
    }

    /// The user just used the unlocked vault: the auto-lock starts again from now. Nothing while
    /// locked.
    pub fn note_activity(&self) {
        let now = self.now();
        let mut state = self.state();
        if state.vault.is_some() {
            state.last_activity = now;
            state.idle_before = Duration::ZERO;
        }
    }

    /// A credential was just used successfully: [`Agent::note_activity`] and
    /// [`Ui::credential_used`]. Call only after the use succeeded. Nothing while locked.
    pub fn note_use(&self) {
        if self.is_locked() {
            return;
        }
        self.note_activity();
        self.ui.credential_used();
    }

    /// Holds the auto-lock off while a request that may count as use is in progress (see
    /// [`auto_lock_due`]); counting it is up to the caller once it succeeded.
    pub(crate) fn busy(&self) -> Busy<'_> {
        self.state().busy += 1;
        Busy(self)
    }

    /// For the sync scheduler: whether the vault has changes the server hasn't seen, and its
    /// revision. `None` while locked. Not activity.
    pub fn sync_pending(&self) -> Option<(bool, u64)> {
        let vault = self.state().vault.clone()?;
        Some((vault.sync_pending(), vault.revision()))
    }

    /// For the sync scheduler: usage counts have waited [`pass_core::USAGE_SYNC_INTERVAL_MS`] for
    /// a sync and should be uploaded on their own. `false` while locked.
    pub fn usage_sync_due(&self) -> bool {
        self.state()
            .vault
            .clone()
            .is_some_and(|vault| vault.usage_sync_due(self.unix_ms()))
    }

    /// Counts a use of login `item_id` so the most used logins are suggested first, saves it
    /// [`USE_SAVE_DELAY`] later, and calls [`Agent::note_use`]. A locked vault or unknown item is
    /// ignored. Call only once the use succeeded.
    pub fn record_use(&self, item_id: &str) {
        let Some(vault) = self.peek_vault() else {
            return;
        };
        // Read-only mode writes nothing, usage counts included.
        if self.update_required() {
            self.note_use();
            return;
        }
        let _ = &vault;
        // In whichever open vault holds the login (`linked.rs`).
        if self.record_use_in_vaults(item_id) {
            self.save_soon();
        }
        self.note_use();
    }

    /// Saves the vault [`USE_SAVE_DELAY`] from now, one save for every call within that time.
    /// Never blocks. With [`Timers::Host`] the save is only scheduled for the next due
    /// [`Agent::tick`].
    pub fn save_soon(&self) {
        if self.timers == Timers::Host {
            let due = self.now() + USE_SAVE_DELAY;
            self.save_due
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get_or_insert(due);
            return;
        }
        let mut saver = self.saver.lock().unwrap_or_else(|p| p.into_inner());
        if saver.as_ref().is_some_and(|tx| tx.send(()).is_ok()) {
            return;
        }
        let (tx, rx) = mpsc::channel::<()>();
        let me = self.me.clone();
        let started = std::thread::Builder::new()
            .name("pass-agent-save".into())
            .spawn(move || {
                // Ends with the agent (its sender goes with it).
                while rx.recv().is_ok() {
                    let due = Instant::now() + USE_SAVE_DELAY;
                    loop {
                        let left = due.saturating_duration_since(Instant::now());
                        match rx.recv_timeout(left) {
                            Ok(()) => continue,
                            Err(mpsc::RecvTimeoutError::Timeout) => break,
                            Err(mpsc::RecvTimeoutError::Disconnected) => return,
                        }
                    }
                    let Some(agent) = me.upgrade() else { return };
                    if let Err(e) = agent.save() {
                        // Kept in memory (dirty): the next save writes it.
                        eprintln!("pass-agent: could not save a use: {e}");
                    }
                }
            });
        if started.is_ok() && tx.send(()).is_ok() {
            *saver = Some(tx);
        } else if let Err(e) = self.save() {
            eprintln!("pass-agent: could not save a use: {e}");
        }
    }

    /// Time since the vault was last used ([`Agent::note_activity`]).
    pub fn idle_for(&self) -> Duration {
        let now = self.now();
        idle_since(&self.state(), now)
    }

    /// Counts `idle` as time without use already, for a host that restarted the agent with the
    /// vault still unlocked, so the auto-lock keeps its schedule. Nothing while locked.
    pub fn set_idle_for(&self, idle: Duration) {
        let now = self.now();
        let mut state = self.state();
        if state.vault.is_some() {
            state.last_activity = now;
            state.idle_before = idle;
        }
    }

    pub fn create_vault(&self, master_password: &str) -> Result<(), PassError> {
        self.create_with(|device_id| Vault::create(master_password.to_string(), device_id))
    }

    /// A new vault linked to the Passyble account of `account_key` from the start (file version
    /// 3): it opens with the Passyble password, not a master password of its own.
    pub fn create_vault_for_account(
        &self,
        account_key: &pass_core::AccountKey,
    ) -> Result<(), PassError> {
        self.create_with(|device_id| Vault::create_for_account(account_key, device_id))
    }

    fn create_with(
        &self,
        make: impl FnOnce(String) -> Result<Arc<Vault>, PassError>,
    ) -> Result<(), PassError> {
        if self.vault_exists() {
            return Err(PassError::Conflict(
                "a vault already exists at this location".into(),
            ));
        }
        let config = self.config();
        let seen = self.store.stamp(&config.vault_path);
        let vault = make(config.device_id)?;
        self.install(vault, &config.vault_path, seen)?;
        if !self.store.exists(&config.vault_path) {
            // Nothing to come back to: don't let the user fill a vault that has no file.
            self.lock_as(LockKind::Full);
            return Err(io_err(io::Error::other(
                "the new vault file could not be written",
            )));
        }
        Ok(())
    }

    pub fn unlock(&self, master_password: &str) -> Result<(), PassError> {
        let config = self.config();
        let seen = self.store.stamp(&config.vault_path);
        let bytes = self.store.read(&config.vault_path).map_err(io_err)?;
        let vault = Vault::unlock(bytes, master_password.to_string(), config.device_id)?;
        self.install(vault, &config.vault_path, seen)
    }

    /// Unlock a vault linked to a Passyble account (file version 3) with the account key (from
    /// the Passyble password, or kept on this device under Windows Hello).
    pub fn unlock_with_account_key(
        &self,
        account_key: &pass_core::AccountKey,
    ) -> Result<(), PassError> {
        let config = self.config();
        let seen = self.store.stamp(&config.vault_path);
        let bytes = self.store.read(&config.vault_path).map_err(io_err)?;
        let vault = Vault::unlock_with_account_key(bytes, account_key, config.device_id)?;
        self.install(vault, &config.vault_path, seen)
    }

    /// The vault file at the configured location, as stored (the windows read its header to pick
    /// the unlock screen, `pass_core::vault_file_access`).
    pub fn vault_file_bytes(&self) -> Option<Vec<u8>> {
        let path = self.cfg().vault_path.clone();
        self.store.read(&path).ok()
    }

    /// Unlock with a vault key released by Windows Hello / the OS keychain.
    pub fn unlock_with_key(&self, vault_key: Vec<u8>) -> Result<(), PassError> {
        let config = self.config();
        let seen = self.store.stamp(&config.vault_path);
        let bytes = self.store.read(&config.vault_path).map_err(io_err)?;
        crate::timing::mark("unlock: vault file read");
        let vault = Vault::unlock_with_key(bytes, vault_key, config.device_id)?;
        crate::timing::mark("unlock: vault opened");
        self.install(vault, &config.vault_path, seen)
    }

    /// The id of the vault in the current vault file (from its cleartext header, without decoding
    /// the rest), `None` if the file can't be read or isn't a vault.
    pub fn vault_file_id(&self) -> Option<String> {
        let path = self.cfg().vault_path.clone();
        self.vault_file_id_at(&path)
    }

    fn vault_file_id_at(&self, path: &Path) -> Option<String> {
        let bytes = self.store.read(path).ok()?;
        crate::kept_list::vault_id_of(&bytes)
    }

    /// Makes `vault`, read from `path`, the unlocked vault, unless the configuration moved to
    /// another file in the meantime.
    ///
    /// `seen`: the file's stamp from before it was read, so a copy a sync client puts in place
    /// while the master password is checked (a second or so) is merged by the next save instead
    /// of being taken for the file that was read.
    fn install(
        &self,
        vault: Arc<Vault>,
        path: &Path,
        seen: Option<Stamp>,
    ) -> Result<(), PassError> {
        {
            let _file = self.file_lock();
            let mut state = self.state();
            if self.cfg().vault_path.as_path() != path {
                return Err(PassError::Conflict(
                    "the vault location changed while unlocking".into(),
                ));
            }
            // Unlocking while already unlocked: the vault in memory may hold edits its file
            // doesn't have yet. Merge them into the vault just read, or if that fails (another
            // key), stash them beside the file for the next unlock.
            if let Some(previous) = state.vault.take() {
                if previous.is_dirty() || state.unsaved {
                    let kept = previous
                        .serialize()
                        .and_then(|bytes| vault.merge_remote(bytes.clone()).map(|_| bytes));
                    if let Err(e) = kept {
                        let stash = stash_path(path, self.unix_ms());
                        let written = previous
                            .serialize()
                            .map_err(|e| io::Error::other(e.to_string()))
                            .and_then(|bytes| self.store.write(&stash, &bytes));
                        match written {
                            Ok(()) => eprintln!(
                                "pass-agent: unsaved edits could not be merged ({e}); kept a copy at {}",
                                stash.display()
                            ),
                            Err(w) => {
                                // Nothing could keep them: stay as we were rather than drop them.
                                state.vault = Some(previous);
                                return Err(io_err(w));
                            }
                        }
                    }
                }
            }
            state.linked.home_id = Some(vault.vault_id());
            state.vault = Some(vault);
            state.index = None;
            state.last_activity = self.now();
            state.idle_before = Duration::ZERO;
            state.file_mtime = seen;
            state.unsaved = false;
            state.kept_paused = false;
            state.kept_written = None;
            state.kept_written_at = None;
        }
        self.merge_conflict_copies();
        crate::timing::mark("unlock: conflict copies checked");
        // The vault is unlocked now whatever the save does: a failed write must not leave the
        // agent unlocked while the windows think it is locked. The next save retries it.
        if let Err(e) = self.save() {
            eprintln!("pass-agent: could not save the vault after unlocking: {e}");
        }
        crate::timing::mark("unlock: saved");
        // The shared vaults open with it (their keys are in the home vault), before anyone hears
        // of the unlock, so the first list already has their logins.
        self.open_linked();
        crate::timing::mark("unlock: shared vaults opened");
        // Notify before writing the kept list: the extension is waiting to fill the login the
        // user picked while locked.
        self.ui.notify_lock_state(false);
        crate::timing::mark("unlock done");
        {
            let mut state = self.state();
            if let Some(vault) = state.vault.clone() {
                self.write_kept_list_locked(&mut state, &vault, None, true);
            }
        }
        crate::timing::mark("unlock: kept list written");
        Ok(())
    }

    /// Drops the unlocked vault without saving it, soft or full per [`Agent::set_keep_list`]; see
    /// [`Agent::save_and_lock`].
    pub fn lock(&self) {
        self.lock_as(self.default_lock());
    }

    /// Drops the unlocked vault without saving it. [`LockKind::Soft`] keeps the list of items only
    /// while "Keep list visible when locked" is on.
    pub fn lock_as(&self, kind: LockKind) {
        // "Allow until the vault locks" ends here, whatever kind of lock.
        self.ai_forget_grants();
        let kind = if self.keeps_list() {
            kind
        } else {
            LockKind::Full
        };
        // A use still waiting to be saved goes with the vault (`save_and_lock` saved it).
        self.save_due
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        let changed = {
            let mut state = self.state();
            state.pending_otp.clear();
            state.deleted.clear();
            state.edit_grants.clear();
            state.cross_fills.clear();
            state.unsaved = false;
            let vault = state.vault.take();
            // A full lock writes the kept list too: quitting and updating are full locks.
            let wanted =
                kind == LockKind::Soft || (self.keeps_list() && self.cfg().kept_list.is_some());
            let list = vault
                .as_ref()
                .filter(|_| wanted)
                .map(|v| Arc::new(v.summaries()));
            if let (Some(vault), Some(list)) = (&vault, &list) {
                self.write_kept_list_locked(&mut state, vault, Some(list.as_slice()), true);
                if self.cfg().kept_list.is_some() {
                    self.write_shared_kept_lists_locked(&state);
                }
            }
            state.kept_written = None;
            state.kept_written_at = None;
            // The shared vaults lock with it; a soft lock keeps their lists (in memory only).
            if vault.is_some() {
                state.linked.lock(kind == LockKind::Soft && list.is_some());
            } else if kind == LockKind::Full {
                state.linked.lock(false);
            }
            match kind {
                LockKind::Soft => {
                    // Search hits are only ids, so they are kept: a copy started from a search
                    // still works after unlocking for it.
                    if let Some(list) = list {
                        state.index = Some(list);
                    }
                    vault.is_some()
                }
                LockKind::Full => {
                    state.search_hits.clear();
                    state.search_lists = None;
                    let had_list = state.index.take().is_some();
                    vault.is_some() || had_list
                }
            }
        };
        if changed {
            self.ui.notify_lock_state(true);
        }
    }

    /// [`Agent::save_and_lock`] with a [`LockKind`] ("Lock completely" is [`LockKind::Full`]).
    pub fn save_and_lock_as(&self, kind: LockKind) -> Result<(), PassError> {
        // The shared vaults first (their records go into the home vault's write below).
        self.remember_dirty_linked();
        self.write_dirty_linked();
        let result = {
            let _file = self.file_lock();
            let mut state = self.state();
            self.save_or_stash_locked(&mut state)
        };
        self.lock_as(kind);
        result
    }

    /// Saves and locks. If the vault file can't be written, the vault is written beside it as
    /// `<name>-unsaved-<ms>.vault` for the next unlock to merge in. `Err` only if even that failed
    /// (the edits are lost).
    pub fn save_and_lock(&self) -> Result<(), PassError> {
        self.save_and_lock_as(self.default_lock())
    }

    /// Call periodically (every few seconds): applies the auto-lock timeout. With [`Timers::Host`]
    /// it also writes a save that is due ([`Agent::save_soon`]); call it at [`Agent::next_tick`].
    pub fn tick(&self) {
        self.run_due_save();
        let expired = {
            let now = self.now();
            let state = self.state();
            let auto_lock = self.cfg().auto_lock;
            state.vault.is_some()
                && auto_lock_due(idle_since(&state, now), auto_lock, state.busy > 0)
        };
        if expired {
            if let Err(e) = self.save_and_lock() {
                eprintln!("pass-agent: auto-lock could not save the vault: {e}");
            }
            return;
        }
        let mut state = self.state();
        if let Some(vault) = state.vault.clone() {
            self.write_kept_list_locked(&mut state, &vault, None, false);
        }
    }

    /// [`Timers::Host`]: the save [`Agent::save_soon`] scheduled, once it is due.
    fn run_due_save(&self) {
        let due = {
            let mut due = self.save_due.lock().unwrap_or_else(|p| p.into_inner());
            match *due {
                Some(at) if self.now() >= at => due.take().is_some(),
                _ => false,
            }
        };
        if due {
            if let Err(e) = self.save() {
                // Kept in memory (dirty): the next save writes it.
                eprintln!("pass-agent: could not save a use: {e}");
            }
        }
    }

    /// For [`Timers::Host`]: how long until [`Agent::tick`] has something to do (a pending save or
    /// the auto-lock). `None` when there is nothing to wait for. Ask again after each request.
    pub fn next_tick(&self) -> Option<Duration> {
        let now = self.now();
        let save = self
            .save_due
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .map(|at| at.saturating_duration_since(now));
        let lock = {
            let state = self.state();
            state.vault.as_ref().map(|_| {
                let idle = idle_since(&state, now);
                self.cfg().auto_lock.saturating_sub(idle)
            })
        };
        match (save, lock) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    fn file_lock(&self) -> MutexGuard<'_, ()> {
        self.file_lock.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Persists the vault if it changed, merging in changes a sync client wrote first. Holds the
    /// state lock only to encrypt, not for the write, so other requests don't wait for the disk.
    pub fn save(&self) -> Result<(), PassError> {
        // The home vault's records of changed shared vaults go into this write; the shared
        // vaults' own copies are written after it (`linked.rs`).
        self.remember_dirty_linked();
        let result = {
            let _file = self.file_lock();
            self.save_with_file_lock(|_| true)
        };
        self.write_dirty_linked();
        result
    }

    /// The body of [`Agent::save`] (call with `file_lock` held): read and merge what a sync client
    /// put in the file, encrypt, write only if the file is still the one merged, and start over
    /// when it is not. `wanted` sees the state before each attempt; `false` skips the save (the
    /// vault was locked or replaced meanwhile).
    fn save_with_file_lock(&self, wanted: impl Fn(&State) -> bool) -> Result<(), PassError> {
        for _ in 0..SAVE_ATTEMPTS {
            let write = {
                let mut state = self.state();
                if !wanted(&state) {
                    return Ok(());
                }
                self.prepare_write_locked(&mut state)?
            };
            let Some(write) = write else {
                return Ok(());
            };
            if self.finish_write(write)? {
                return Ok(());
            }
        }
        Err(file_kept_changing())
    }

    /// The bytes [`Agent::save`] writes (`None`: nothing to write), with `state.writing` set.
    /// Call with `file_lock` held.
    fn prepare_write_locked(&self, state: &mut State) -> Result<Option<PendingWrite>, PassError> {
        let seen = self.reload_locked(state)?;
        let Some(vault) = state.vault.clone() else {
            return Ok(None);
        };
        let path = self.cfg().vault_path.clone();
        if !vault.is_dirty() && !state.unsaved && self.store.exists(&path) {
            return Ok(None);
        }
        // `serialize` clears the dirty flag, so a failed write is remembered in `unsaved`.
        let bytes = vault.serialize()?;
        state.unsaved = true;
        state.writing = true;
        Ok(Some(PendingWrite {
            vault,
            path,
            bytes,
            seen,
        }))
    }

    /// Writes what [`Agent::prepare_write_locked`] prepared, without the state lock, then records
    /// it (unless the vault was locked or replaced meanwhile). Call with `file_lock` held.
    /// `Ok(false)`: the file changed since it was merged, nothing was written (the edits stay
    /// `unsaved`); read it again and retry.
    fn finish_write(&self, write: PendingWrite) -> Result<bool, PassError> {
        let written = self.store.replace(&write.path, &write.bytes, write.seen);
        let mut state = self.state();
        state.writing = false;
        let current = state
            .vault
            .as_ref()
            .is_some_and(|v| Arc::ptr_eq(v, &write.vault))
            && self.cfg().vault_path == write.path;
        match written {
            Ok(Replaced::Written(stamp)) => {
                if current {
                    state.unsaved = false;
                    state.file_mtime = stamp;
                }
                Ok(true)
            }
            Ok(Replaced::Changed) => Ok(false),
            Err(e) => Err(io_err(e)),
        }
    }

    /// [`Agent::save`] while the caller holds the state lock (locking): the write happens under
    /// it. Call with `file_lock` held.
    fn save_locked(&self, state: &mut State) -> Result<(), PassError> {
        for _ in 0..SAVE_ATTEMPTS {
            let Some(write) = self.prepare_write_locked(state)? else {
                return Ok(());
            };
            state.writing = false;
            match self
                .store
                .replace(&write.path, &write.bytes, write.seen)
                .map_err(io_err)?
            {
                Replaced::Written(stamp) => {
                    state.unsaved = false;
                    state.file_mtime = stamp;
                    return Ok(());
                }
                // Someone else's copy landed after the merge: merge it too and write again.
                Replaced::Changed => continue,
            }
        }
        Err(file_kept_changing())
    }

    /// [`Agent::save_locked`], or if that fails, the vault written to a sibling file that the next
    /// unlock merges in (see [`Agent::save_and_lock`]).
    fn save_or_stash_locked(&self, state: &mut State) -> Result<(), PassError> {
        let error = match self.save_locked(state) {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };
        let Some(vault) = state.vault.clone() else {
            return Err(error);
        };
        let stash = stash_path(&self.cfg().vault_path, self.unix_ms());
        let bytes = vault.serialize()?;
        self.store.write(&stash, &bytes).map_err(|e| {
            eprintln!("pass-agent: could not save the vault ({error}) nor keep a copy: {e}");
            io_err(e)
        })?;
        eprintln!(
            "pass-agent: could not save the vault ({error}); kept a copy at {}",
            stash.display()
        );
        state.unsaved = false;
        Ok(())
    }

    /// If OneDrive/Dropbox/Syncthing replaced the vault file, merge the new copy in.
    pub fn reload_if_changed(&self) -> Result<(), PassError> {
        let mut state = self.state();
        self.reload_locked(&mut state).map(|_| ())
    }

    /// Merges the vault file in if it changed since it was last read or written. Returns the
    /// stamp the file had before it was read (`None`: no file): everything in the file with that
    /// stamp is in the vault now, so a save may replace a file that still has it.
    fn reload_locked(&self, state: &mut State) -> Result<Option<Stamp>, PassError> {
        let path = self.cfg().vault_path.clone();
        let current = self.store.stamp(&path);
        let Some(vault) = state.vault.clone() else {
            return Ok(current);
        };
        if state.writing {
            // Our own save is replacing the file right now.
            return Ok(current);
        }
        if current.is_none() || current == state.file_mtime {
            return Ok(current);
        }
        let bytes = self.store.read(&path).map_err(io_err)?;
        vault.merge_remote(bytes)?;
        state.file_mtime = current;
        Ok(current)
    }

    /// Merges in and removes sync clients' conflict copies and the agent's own `-unsaved-` copies
    /// ([`is_conflict_copy`]). Any other file sharing the name is left alone.
    fn merge_conflict_copies(&self) {
        let Some(vault) = self.state().vault.clone() else {
            return;
        };
        let path = self.cfg().vault_path.clone();
        let (Some(_), Some(stem), Some(name)) = (path.parent(), path.file_stem(), path.file_name())
        else {
            return;
        };
        let stem = stem.to_string_lossy().to_string();
        let icloud = path.parent().is_some_and(in_icloud_drive);
        for sibling in self.store.siblings(&path) {
            let Some(file_name) = sibling.file_name() else {
                continue;
            };
            let file_name = file_name.to_string_lossy();
            let copy = is_conflict_copy(&stem, &file_name)
                || (icloud && is_icloud_copy(&stem, &file_name));
            if file_name == name.to_string_lossy() || !copy {
                continue;
            }
            let Ok(bytes) = self.store.read(&sibling) else {
                continue;
            };
            // Only remove files that really were copies of this vault.
            if vault.merge_remote(bytes).is_ok() {
                let _ = self.store.remove(&sibling);
            }
        }
    }

    /// `sync.now` without the app's own sync ([`crate::Ui::sync_now`] answered `None`): the home
    /// vault's WebDAV / Passyble Server account and every shared vault, each counted once it
    /// synced. A Google Drive account needs the app, so here it is neither synced nor failed.
    /// Blocking.
    pub fn sync_report(&self) -> crate::SyncReport {
        let mut report = crate::SyncReport::default();
        #[cfg(feature = "webdav")]
        {
            let linked = self.linked_configs();
            if !self.has_sync_account() && linked.is_empty() {
                report.no_sync = true;
                return report;
            }
            match self.sync() {
                Ok(Some(_)) => report.synced += 1,
                Ok(None) => {}
                Err(e) => report.failed.push(crate::SyncFailure {
                    vault: self.ui.vault_name().unwrap_or_default(),
                    reason: e.to_string(),
                }),
            }
            for (key, result) in self.sync_linked() {
                let vault = linked
                    .iter()
                    .find(|c| c.key == key)
                    .map(|c| c.name.clone())
                    .unwrap_or(key);
                match result {
                    Ok(Some(_)) => report.synced += 1,
                    Ok(None) => {}
                    Err(e) => report.failed.push(crate::SyncFailure {
                        vault,
                        reason: e.to_string(),
                    }),
                }
            }
        }
        #[cfg(not(feature = "webdav"))]
        {
            report.no_sync = true;
        }
        report
    }

    /// Syncs with the WebDAV account (`pass_core::webdav_sync`: one conditional request when
    /// nothing changed on either side) and saves. Blocking.
    #[cfg(feature = "webdav")]
    pub fn sync(&self) -> Result<Option<pass_core::SyncResult>, PassError> {
        if self.update_required() {
            return Ok(None);
        }
        let _one_at_a_time = self.sync_lock.lock().unwrap_or_else(|p| p.into_inner());
        // Read under one lock, so a vault switched in the meantime is never synced with the
        // previous vault's account.
        let (config, vault) = {
            let state = self.state();
            let Some(config) = self.cfg().webdav.clone() else {
                return Ok(None);
            };
            let Some(vault) = state.vault.clone() else {
                return Err(PassError::InvalidPassword);
            };
            (config, vault)
        };
        let result = pass_core::webdav_sync(vault.clone(), config)?;
        self.save_if_current(&vault)?;
        Ok(Some(result))
    }

    /// Saves, unless `vault` was locked or replaced while it synced.
    #[cfg(feature = "webdav")]
    fn save_if_current(&self, vault: &Arc<Vault>) -> Result<(), PassError> {
        let _file = self.file_lock();
        self.save_with_file_lock(|state| {
            state.vault.as_ref().is_some_and(|v| Arc::ptr_eq(v, vault))
        })
    }

    /// Syncs with the Google Drive app folder and saves. Blocking. A refused token is
    /// `PassError::AuthRequired`. `Ok(None)` when Google Drive isn't configured, or when `account`
    /// is no longer the configured account, so a vault never lands in another account's Drive.
    #[cfg(feature = "gdrive")]
    pub fn sync_gdrive(
        &self,
        account: &str,
        access_token: &str,
    ) -> Result<Option<pass_core::SyncResult>, PassError> {
        if self.update_required() {
            return Ok(None);
        }
        let _one_at_a_time = self.sync_lock.lock().unwrap_or_else(|p| p.into_inner());
        let (target, vault) = {
            let state = self.state();
            let Some(target) = self.cfg().gdrive.clone() else {
                return Ok(None);
            };
            if !target.account.eq_ignore_ascii_case(account) {
                return Ok(None);
            }
            let Some(vault) = state.vault.clone() else {
                return Err(PassError::InvalidPassword);
            };
            (target, vault)
        };
        let result = pass_core::gdrive_sync(
            vault.clone(),
            pass_core::GDriveConfig {
                access_token: access_token.to_string(),
                vault_name: target.vault_name,
                start_again: false,
            },
        )?;
        self.save_if_current(&vault)?;
        Ok(Some(result))
    }

    // ---- pending OTP ------------------------------------------------------------------------

    fn domain_key(url: &str) -> Option<String> {
        registrable_domain(url.to_string())
    }

    pub(crate) fn remember_otp(&self, url: &str, item_id: &str) {
        if let Some(domain) = Self::domain_key(url) {
            let now = self.now();
            self.state()
                .pending_otp
                .insert(domain, (item_id.to_string(), now + PENDING_OTP_TTL));
            // The extension reports how the 2FA step goes (`otp.outcome`).
            self.otp_history().begin_at(url, now);
        }
    }

    /// The login whose password was just filled on this site and that still owes a TOTP code.
    pub fn pending_otp(&self, url: &str) -> Option<PendingOtp> {
        let domain = Self::domain_key(url)?;
        let item_id = {
            let now = self.now();
            let mut state = self.state();
            state.pending_otp.retain(|_, (_, expires)| *expires > now);
            state.vault.as_ref()?;
            state.pending_otp.get(&domain)?.0.clone()
        };
        let item = self.any_item(&item_id)?;
        Some(PendingOtp {
            item_id: item.id,
            title: item.title,
        })
    }

    // ---- edits from the browser extension -----------------------------------------------------

    /// Counts one request of `kind` and says whether it is within `max` per `per` (sliding window).
    pub(crate) fn within_rate(&self, kind: &'static str, max: usize, per: Duration) -> bool {
        let now = self.now();
        let mut state = self.state();
        let recent = state.edits.entry(kind).or_default();
        while recent
            .front()
            .is_some_and(|t| now.duration_since(*t) >= per)
        {
            recent.pop_front();
        }
        if recent.len() >= max {
            return false;
        }
        recent.push_back(now);
        true
    }

    /// The user was verified for editing login `id` (see [`EDIT_GRANT`]).
    pub(crate) fn grant_edit(&self, id: &str) {
        let now = self.now();
        let mut state = self.state();
        state
            .edit_grants
            .retain(|_, at| now.saturating_duration_since(*at) < EDIT_GRANT);
        state.edit_grants.insert(id.to_string(), now);
    }

    /// Whether login `id` is open in the extension's editor with a recent verification.
    pub(crate) fn edit_granted(&self, id: &str) -> bool {
        let now = self.now();
        self.state()
            .edit_grants
            .get(id)
            .is_some_and(|at| now.saturating_duration_since(*at) < EDIT_GRANT)
    }

    /// Remembers a password `generate` just returned, as a hash (see [`GENERATED_GRANT`]).
    pub(crate) fn remember_generated(&self, password: &str) {
        let now = self.now();
        let mut state = self.state();
        forget_old_generated(&mut state.generated, now);
        state
            .generated
            .push_back((now, pass_core::sha256(password.as_bytes().to_vec())));
        if state.generated.len() > MAX_GENERATED {
            state.generated.pop_front();
        }
    }

    /// True when `generate` returned `password` a moment ago ([`Agent::remember_generated`]).
    pub(crate) fn recently_generated(&self, password: &str) -> bool {
        let hash = pass_core::sha256(password.as_bytes().to_vec());
        let now = self.now();
        let mut state = self.state();
        forget_old_generated(&mut state.generated, now);
        state.generated.iter().any(|(_, known)| *known == hash)
    }

    /// The lists `logins.search` read last time, if any.
    pub(crate) fn kept_search(&self) -> Option<Arc<crate::protocol::search::SearchLists>> {
        self.state().search_lists.clone()
    }

    /// Keeps what `logins.search` read for the next keystroke.
    pub(crate) fn keep_search(&self, lists: Arc<crate::protocol::search::SearchLists>) {
        self.state().search_lists = Some(lists);
    }

    /// Remembers the logins `logins.search` just returned (see [`SEARCH_GRANT`]).
    pub(crate) fn remember_search_hits(&self, ids: &[String]) {
        let now = self.now();
        let mut state = self.state();
        state
            .search_hits
            .retain(|_, at| now.duration_since(*at) < SEARCH_GRANT);
        for id in ids {
            state.search_hits.insert(id.clone(), now);
        }
        let excess = state.search_hits.len().saturating_sub(MAX_SEARCH_HITS);
        if excess > 0 {
            let mut oldest: Vec<(Instant, String)> = state
                .search_hits
                .iter()
                .map(|(id, at)| (*at, id.clone()))
                .collect();
            oldest.sort();
            for (_, id) in oldest.into_iter().take(excess) {
                state.search_hits.remove(&id);
            }
        }
    }

    /// Remembers a cross-site fill of login `item_id` into a page of `origin`; returns the
    /// one-time token that lets `logins.add_url` add that origin to that login.
    pub(crate) fn remember_cross_fill(&self, item_id: &str, origin: &str) -> String {
        let token = pass_core::random_token();
        let now = self.now();
        let mut state = self.state();
        state
            .cross_fills
            .retain(|f| now.saturating_duration_since(f.at) < CROSS_FILL_GRANT);
        state.cross_fills.push(CrossFill {
            token: token.clone(),
            item_id: item_id.to_string(),
            origin: origin.to_string(),
            at: now,
        });
        let excess = state.cross_fills.len().saturating_sub(MAX_CROSS_FILLS);
        state.cross_fills.drain(..excess);
        token
    }

    /// Takes the cross-site fill of `token` (one use) if it filled login `item_id` into a page of
    /// `origin` moments ago. A token that doesn't match is used up all the same.
    pub(crate) fn take_cross_fill(&self, token: &str, item_id: &str, origin: &str) -> bool {
        let now = self.now();
        let mut state = self.state();
        state
            .cross_fills
            .retain(|f| now.saturating_duration_since(f.at) < CROSS_FILL_GRANT);
        let Some(at) = state
            .cross_fills
            .iter()
            .position(|f| !token.is_empty() && f.token.as_bytes() == token.as_bytes())
        else {
            return false;
        };
        let fill = state.cross_fills.remove(at);
        fill.item_id == item_id && fill.origin == origin
    }

    /// Whether login `id` was returned by a recent `logins.search`.
    pub(crate) fn search_hit(&self, id: &str) -> bool {
        let now = self.now();
        self.state()
            .search_hits
            .get(id)
            .is_some_and(|at| now.saturating_duration_since(*at) < SEARCH_GRANT)
    }

    /// Keeps a copy of a login just deleted from the browser extension for its Undo.
    pub(crate) fn remember_deleted(&self, vault_id: &str, site: &str, item: Item) {
        let now = self.now();
        let mut state = self.state();
        state.deleted.retain(|d| {
            now.saturating_duration_since(d.at) < DELETE_UNDO_WINDOW && d.item.id != item.id
        });
        state.deleted.push(DeletedLogin {
            vault_id: vault_id.to_string(),
            site: site.to_string(),
            item,
            at: now,
        });
        let excess = state.deleted.len().saturating_sub(20);
        state.deleted.drain(..excess);
    }

    /// The copy of login `id`, deleted from a page of `site` in vault `vault_id`, if it is still
    /// within the undo window.
    pub(crate) fn take_deleted(&self, vault_id: &str, site: &str, id: &str) -> Option<Item> {
        let now = self.now();
        let mut state = self.state();
        state
            .deleted
            .retain(|d| now.saturating_duration_since(d.at) < DELETE_UNDO_WINDOW);
        let index = state
            .deleted
            .iter()
            .position(|d| d.vault_id == vault_id && d.site == site && d.item.id == id)?;
        Some(state.deleted.remove(index).item)
    }

    // ---- native (non-browser) apps ----------------------------------------------------------

    /// Logins for a desktop window, used by the auto-type hotkey. Items pinned to the app
    /// (`windows:<exe name>` or `macos:<bundle id>` in their URLs) match first; otherwise the
    /// window title is matched against item titles and site names.
    pub fn find_for_window(&self, window_title: &str, exe_name: &str) -> Vec<Item> {
        self.match_window(window_title, exe_name)
            .into_iter()
            .map(|(_, i)| i)
            .collect()
    }

    /// [`Agent::find_for_window`] with how each login matched: strongest first, then favorites,
    /// then the most used, then by title. Not activity. Nothing in read-only mode.
    pub fn match_window(&self, window_title: &str, exe_name: &str) -> Vec<(WindowMatch, Item)> {
        if self.update_required() {
            return Vec::new();
        }
        // Every open vault: the home vault and the shared ones (`linked.rs`).
        let Some(opened) = self.opened() else {
            return Vec::new();
        };
        let title = window_title.to_lowercase();
        let exe = exe_name.to_lowercase();
        let scored: Vec<(WindowMatch, Item)> = opened
            .0
            .iter()
            .flat_map(|(_, v)| v.items())
            .filter(|i| i.kind == ItemKind::Login)
            .filter_map(|item| {
                // `windows:<exe>` or `macos:<bundle id>`: the whole name, in any case (bundle
                // IDs are case-insensitive), never a prefix of it.
                // An entry the user hid (`UrlMatch::Never`) is never matched on its own.
                let shown = |u: &&String| item.url_rule(u) != pass_core::UrlMatch::Never;
                let pinned = item
                    .urls
                    .iter()
                    .filter(shown)
                    .filter_map(|u| pass_core::app_pin(u))
                    .any(|app| !exe.is_empty() && app.eq_ignore_ascii_case(&exe));
                if pinned {
                    return Some((WindowMatch::Pinned, item));
                }
                let item_title = item.title.to_lowercase();
                if item_title.len() >= 3 && title.contains(&item_title) {
                    return Some((WindowMatch::Title, item));
                }
                let site_named = item
                    .urls
                    .iter()
                    .filter(shown)
                    // An app pin names no site (`macos:com.apple.Terminal` is not apple.terminal).
                    .filter(|u| pass_core::app_pin(u).is_none())
                    .filter_map(|u| registrable_domain(u.clone()))
                    .any(|domain| {
                        let label = domain.split('.').next().unwrap_or_default();
                        label.len() >= 4 && title.contains(label)
                    });
                site_named.then_some((WindowMatch::SiteName, item))
            })
            .collect();
        let mut ranked: Vec<(WindowMatch, i64, Item)> = scored
            .into_iter()
            .map(|(m, item)| {
                let rank = opened
                    .holding(&item.id)
                    .map(|(_, v)| v.usage(item.id.clone()).rank)
                    .unwrap_or(0);
                (m, rank, item)
            })
            .collect();
        ranked.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then(b.2.favorite.cmp(&a.2.favorite))
                .then(b.1.cmp(&a.1))
                .then_with(|| a.2.title.cmp(&b.2.title))
        });
        ranked.into_iter().map(|(m, _, item)| (m, item)).collect()
    }
}

/// Time without use at `now` ([`Agent::idle_for`]).
fn idle_since(state: &State, now: Instant) -> Duration {
    now.saturating_duration_since(state.last_activity)
        .saturating_add(state.idle_before)
}

/// Drops what is older than [`GENERATED_GRANT`].
fn forget_old_generated(generated: &mut VecDeque<(Instant, Vec<u8>)>, now: Instant) {
    generated.retain(|(at, _)| now.duration_since(*at) < GENERATED_GRANT);
}

#[cfg(test)]
mod icloud_tests {
    use super::{in_icloud_drive, is_icloud_copy};
    use std::path::Path;

    #[test]
    fn icloud_drive_folders() {
        assert!(in_icloud_drive(Path::new(
            "/Users/me/Library/Mobile Documents/com~apple~CloudDocs/Pass"
        )));
        // iCloud for Windows: C:/Users/me/iCloudDrive.
        assert!(in_icloud_drive(Path::new("/Users/me/iCloudDrive/Pass")));
        assert!(!in_icloud_drive(Path::new("/Users/me/Documents/Pass")));
        assert!(!in_icloud_drive(Path::new(
            "/Users/me/Dropbox/Mobile Documents"
        )));
    }

    #[test]
    fn icloud_copy_names() {
        for name in [
            "pass 2.vault",
            "pass 9.vault",
            "pass 42.vault",
            "pass 99.vault",
        ] {
            assert!(is_icloud_copy("pass", name), "{name}");
        }
        for name in [
            "pass.vault",
            "pass 1.vault",
            "pass 02.vault",
            "pass 100.vault",
            "pass 2024.vault",
            "pass2.vault",
            "pass  2.vault",
            "pass 2.vault.tmp",
            "passport 2.vault",
        ] {
            assert!(!is_icloud_copy("pass", name), "{name}");
        }
    }
}

#[cfg(test)]
mod generated_tests {
    use super::{forget_old_generated, GENERATED_GRANT};
    use crate::clock::Instant;
    use std::collections::VecDeque;
    use std::time::Duration;

    #[test]
    fn a_generated_password_is_forgotten_after_the_grant() {
        let at = Instant::now();
        let mut generated = VecDeque::from([(at, vec![1u8])]);
        forget_old_generated(
            &mut generated,
            at + GENERATED_GRANT - Duration::from_secs(1),
        );
        assert_eq!(generated.len(), 1);
        forget_old_generated(&mut generated, at + GENERATED_GRANT);
        assert!(generated.is_empty());
    }
}

#[cfg(test)]
mod activity_tests {
    use super::{auto_lock_due, BUSY_HOLD_MAX};
    use std::time::Duration;

    #[test]
    fn auto_lock_is_due_after_the_chosen_time_without_use() {
        let min = |m: u64| Duration::from_secs(m * 60);
        let lock = min(15);
        assert!(!auto_lock_due(Duration::ZERO, lock, false));
        assert!(!auto_lock_due(min(14), lock, false));
        assert!(auto_lock_due(min(15), lock, false));
        assert!(auto_lock_due(min(60), lock, false));
        // A request in progress (a fill waiting for Windows Hello) holds it off, but not forever.
        assert!(!auto_lock_due(min(16), lock, true));
        assert!(!auto_lock_due(
            lock + BUSY_HOLD_MAX - Duration::from_secs(1),
            lock,
            true
        ));
        assert!(auto_lock_due(lock + BUSY_HOLD_MAX, lock, true));
        // No overflow with a huge setting.
        assert!(!auto_lock_due(min(1), Duration::MAX, true));
    }
}
