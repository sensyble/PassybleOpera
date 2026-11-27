//! Linked vaults: the home vault the app unlocked and the shared vaults its Passyble account can
//! open, held side by side by one agent. Shared vaults open through the home vault, which holds
//! the user's keyset and trust records. Item ids are unique across vaults, so requests name items
//! by id alone.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use pass_core::{Item, ItemSummary, MemberRole, MembersNotice, PassError, SharedKind, Vault};
use serde::Serialize;

use super::Agent;

/// One shared vault this account can open, as the app learns it from the server. The app hands
/// over the list after every unlock and refresh.
#[derive(Clone, Debug, PartialEq)]
pub struct LinkedVaultConfig {
    /// Stable key before the vault id is known: the server path `<owner>/<vault>`.
    pub key: String,
    /// What to call it (the registry's label; else the vault's name on the server).
    pub name: String,
    /// This user's account id on that backend: Passyble Cloud `acc_…`, a self-hosted Passyble
    /// Server's user name. The home vault must hold a keyset for it
    /// (`Vault::ensure_user_keyset` / `Vault::publish_keys_for`).
    pub account: String,
    /// The local copy (the desktop app: `%LOCALAPPDATA%\Pass\shared\<hash>.vault`). Written
    /// through the agent's [`crate::store::VaultStore`] only.
    pub path: PathBuf,
    /// The file on the server: its WebDAV URL, the device's token as the password, the pins.
    /// `None`: a local copy only (tests).
    #[cfg(feature = "webdav")]
    pub webdav: Option<pass_core::WebDavConfig>,
    /// The server takes uploads from this account (`whoami` `writable`; false for view and fill
    /// members and while the organisation's plan isn't live). False: sync only downloads and
    /// merges, never uploads, and nothing in the vault may be changed here.
    pub writable: bool,
    /// The organisation in the account service's registry, if any (display, policies).
    pub org: Option<String>,
}

impl LinkedVaultConfig {
    /// A local-only entry (no server): tests, and hosts that sync the file themselves.
    pub fn local(key: &str, name: &str, account: &str, path: PathBuf) -> LinkedVaultConfig {
        LinkedVaultConfig {
            key: key.to_string(),
            name: name.to_string(),
            account: account.to_string(),
            path,
            #[cfg(feature = "webdav")]
            webdav: None,
            writable: true,
            org: None,
        }
    }
}

/// What kind of vault an item is in (the wire `kind`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultKind {
    /// The home vault.
    Personal,
    /// A Team's or Family's shared vault.
    Org,
    /// Shared with one person ("Shared with Bob").
    Direct,
    /// Someone else's vault opened through emergency access, for this session only.
    Emergency,
}

impl From<SharedKind> for VaultKind {
    fn from(kind: SharedKind) -> VaultKind {
        match kind {
            SharedKind::Org => VaultKind::Org,
            SharedKind::Direct => VaultKind::Direct,
        }
    }
}

/// A vault as the protocol shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VaultRef {
    pub id: String,
    /// The home vault: the app's name for it (`Ui::vault_name`), `""` when it has none.
    pub name: String,
    pub home: bool,
    pub kind: VaultKind,
    /// `None` in the home vault.
    pub role: Option<MemberRole>,
    /// Items may be added, changed and deleted here (false for view and fill members, and for a
    /// vault the server takes no uploads for).
    pub can_edit: bool,
    /// Passwords may be shown and copied (false for fill members).
    pub can_reveal: bool,
}

/// Why a shared vault isn't open (an entry of `teams_errors`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LinkedError {
    pub code: String,
    pub message: String,
}

/// One entry of [`Agent::linked_status`].
#[derive(Clone, Debug, Serialize)]
pub struct LinkedStatus {
    pub key: String,
    pub name: String,
    pub org: Option<String>,
    /// `None` until it was opened once in this session.
    pub vault: Option<VaultRef>,
    pub open: bool,
    pub items: usize,
    pub error: Option<LinkedError>,
    /// The last sync that reached the server (Unix ms).
    pub last_sync_ms: Option<i64>,
    pub writable: bool,
}

/// What a merge or an open did to a shared vault's members list on this device's behalf
/// (`Vault::take_members_notice`), for the app to tell the user once.
#[derive(Clone, Debug)]
pub struct LinkedNotice {
    pub vault_id: String,
    pub name: String,
    pub notice: MembersNotice,
}

/// What waits for the user in the app (`vaults.list` `teams`, from [`crate::Ui::teams_summary`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct TeamsSummary {
    /// Invitations to accept or decline.
    pub invites: u32,
    /// People whose keys this user may confirm.
    pub to_confirm: u32,
    /// Notices not seen yet (shared with you, removed, members notices).
    pub notices: u32,
}

/// A Team's password rule (`vaults.list` `password_policy`, from [`crate::Ui::password_policy`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PasswordPolicy {
    pub mode: PasswordPolicyMode,
    /// The rule isn't met on this device.
    pub action_needed: bool,
    /// What to show, in the app's language.
    pub title: String,
    pub message: String,
}

/// The modes a [`PasswordPolicy`] has (a Team's `choice` has none).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PasswordPolicyMode {
    /// The home vault opens with a password of its own, apart from the Passyble password.
    SecondPassword,
    /// Every vault opens with the Passyble password.
    OnePassword,
}

/// An open shared vault.
#[derive(Clone)]
pub(crate) struct OpenShared {
    pub key: String,
    pub kind: VaultKind,
    pub vault: Arc<Vault>,
}

/// What the agent learned about one listed vault (kept across locks).
#[derive(Clone, Default)]
pub(crate) struct Runtime {
    vault_id: Option<String>,
    kind: Option<VaultKind>,
    role: Option<MemberRole>,
    can_reveal: bool,
    error: Option<LinkedError>,
    last_sync_ms: Option<i64>,
}

/// The agent's linked vaults (part of its state, under the same lock).
#[derive(Default)]
pub(crate) struct LinkedState {
    pub configs: Vec<LinkedVaultConfig>,
    /// The open shared vaults, in list order (only while the home vault is unlocked).
    pub open: Vec<OpenShared>,
    /// A soft lock's lists of the shared vaults, with their [`VaultRef`].
    pub kept: Vec<(VaultRef, Arc<Vec<ItemSummary>>)>,
    runtime: HashMap<String, Runtime>,
    notices: Vec<LinkedNotice>,
    /// The home vault's id, for its [`VaultRef`] while soft-locked (set by unlocks and by the
    /// list kept across a restart).
    pub home_id: Option<String>,
    /// Vaults shown until the next lock and never saved (emergency access), with their refs.
    pub session: Vec<(VaultRef, Arc<Vault>)>,
}

impl LinkedState {
    fn config(&self, key: &str) -> Option<&LinkedVaultConfig> {
        self.configs.iter().find(|c| c.key == key)
    }

    fn vault_ref(&self, open: &OpenShared) -> VaultRef {
        let config = self.config(&open.key);
        let vault = &open.vault;
        VaultRef {
            id: vault.vault_id(),
            name: config.map(|c| c.name.clone()).unwrap_or_default(),
            home: false,
            kind: open.kind,
            role: vault.shared_role(),
            can_edit: config.is_some_and(|c| c.writable) && vault.can_edit(),
            can_reveal: vault.can_reveal_secrets(),
        }
    }

    /// Drops the open vaults (a lock): with `keep`, their lists are kept for the soft lock.
    pub(crate) fn lock(&mut self, keep: bool) {
        self.session.clear();
        let open = std::mem::take(&mut self.open);
        self.kept = if keep {
            open.iter()
                .map(|o| (self.vault_ref(&o.clone()), Arc::new(o.vault.summaries())))
                .collect()
        } else {
            Vec::new()
        };
    }

    fn set_error(&mut self, key: &str, error: Option<LinkedError>) {
        self.runtime.entry(key.to_string()).or_default().error = error;
    }
}

/// FNV-1a (64 bits): a short, stable name part for a shared vault's kept list.
fn fnv1a(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in text.bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

fn kind_name(kind: VaultKind) -> &'static str {
    match kind {
        VaultKind::Personal => "personal",
        VaultKind::Org => "org",
        VaultKind::Direct => "direct",
        VaultKind::Emergency => "emergency",
    }
}

fn kind_of_name(name: &str) -> VaultKind {
    match name {
        "direct" => VaultKind::Direct,
        _ => VaultKind::Org,
    }
}

/// The wire code of an error opening or syncing a shared vault (`teams_errors`).
pub(crate) fn error_code(e: &PassError) -> &'static str {
    let text = payload(e);
    let is = |key: &str| pass_core::core_message_is(text.clone(), key.to_string());
    match e {
        PassError::NotFound(_) if is("share.no_keyset") => "no_keyset",
        PassError::Crypto(_) if is("share.not_a_member") || is("share.removed") => "not_a_member",
        PassError::Crypto(_) if is("share.keys_mismatch") => "keys_mismatch",
        PassError::Crypto(_) if is("share.members_unverified") || is("share.members_invalid") => {
            "untrusted"
        }
        PassError::Conflict(_) if is("share.members_rollback") => "rollback",
        // Passyble Server's shared vault codes (pass-core `SHARED_VAULT_ERRORS`).
        PassError::Network(_) if is("server.read_only_member") => "read_only_member",
        PassError::Network(_) if is("server.subscription_inactive") => "subscription_inactive",
        PassError::Network(_) if is("server.account_suspended") => "account_suspended",
        PassError::Network(_) if is("server.no_vault_access") => "not_a_member",
        PassError::Network(_) | PassError::CertificateChanged(_) => "network",
        _ => "internal",
    }
}

/// The core's own words of an error, without the kind prefix (`crypto failure: `, ...), which
/// is what `pass_core::core_message_is` recognises.
pub(crate) fn payload(e: &PassError) -> String {
    match e {
        PassError::Corrupt(t)
        | PassError::Crypto(t)
        | PassError::InvalidInput(t)
        | PassError::NotFound(t)
        | PassError::Network(t)
        | PassError::Conflict(t)
        | PassError::CertificateChanged(t)
        | PassError::AuthRequired(t) => t.clone(),
        PassError::InvalidPassword => e.to_string(),
    }
}

fn linked_error(e: &PassError) -> LinkedError {
    LinkedError {
        code: error_code(e).to_string(),
        message: e.to_string(),
    }
}

/// The open vaults for one request, the home vault first.
#[derive(Clone)]
pub(crate) struct Opened(pub Vec<(VaultRef, Arc<Vault>)>);

impl Opened {
    /// The vault holding live (or trashed) item `id`.
    pub fn holding(&self, id: &str) -> Option<&(VaultRef, Arc<Vault>)> {
        self.0.iter().find(|(_, v)| v.get(id.to_string()).is_some())
    }

    pub fn by_id(&self, vault_id: &str) -> Option<&(VaultRef, Arc<Vault>)> {
        self.0.iter().find(|(r, _)| r.id == vault_id)
    }

    /// Every vault's logins for `url` (`Vault::find_for_url`), the home vault's first.
    pub fn find_for_url(&self, url: &str) -> Vec<Item> {
        self.0
            .iter()
            .flat_map(|(_, v)| v.find_for_url(url.to_string()))
            .collect()
    }

    /// Every vault's logins of `url` whatever their website rules (`Vault::logins_of_page`), the
    /// home vault's first.
    pub fn logins_of_page(&self, url: &str) -> Vec<Item> {
        self.0
            .iter()
            .flat_map(|(_, v)| v.logins_of_page(url.to_string()))
            .collect()
    }

    /// The first open vault (the home vault first) with a login whose site `url` looks like
    /// without being it (`Vault::lookalike_for_save`), for the save banner's warning.
    pub fn lookalike_for_save(&self, url: &str) -> Option<pass_core::Lookalike> {
        self.0
            .iter()
            .find_map(|(_, v)| v.lookalike_for_save(url.to_string()))
    }

    /// The editable vaults' logins a submit on `url` may update (`Vault::find_for_save`).
    pub fn find_for_save(&self, url: &str) -> Vec<Item> {
        self.0
            .iter()
            .filter(|(r, _)| r.can_edit)
            .flat_map(|(_, v)| v.find_for_save(url.to_string()))
            .collect()
    }

    pub fn ref_of(&self, item_id: &str) -> Option<&VaultRef> {
        self.holding(item_id).map(|(r, _)| r)
    }

    pub fn editable(&self) -> Vec<VaultRef> {
        self.0
            .iter()
            .filter(|(r, _)| r.can_edit)
            .map(|(r, _)| r.clone())
            .collect()
    }

    /// pass-core `multi_default_save_vault` over these vaults.
    pub fn default_save(&self, url: Option<&str>) -> Option<String> {
        let groups = self
            .0
            .iter()
            .map(|(r, v)| pass_core::VaultSummaries {
                vault_id: r.id.clone(),
                shared: if r.home {
                    None
                } else {
                    v.shared_info().map(|i| i.kind)
                },
                role: r.role,
                can_edit: r.can_edit,
                can_reveal: r.can_reveal,
                summaries: if url.is_some() {
                    v.summaries()
                } else {
                    Vec::new()
                },
            })
            .collect();
        pass_core::multi_default_save_vault(groups, url.map(str::to_string), None)
    }
}

/// One list of [`ListSources`]: an open vault, or a list a soft lock kept.
pub(crate) enum ListSource {
    Open(VaultRef, Arc<Vault>),
    Kept(VaultRef, Arc<Vec<ItemSummary>>),
}

/// The vaults (or kept lists) a [`Listed`] is made of, the home vault first.
pub(crate) struct ListSources {
    pub list: Vec<ListSource>,
    pub locked: bool,
}

impl ListSources {
    /// The summaries of every list ([`Vault::summaries`] of each open vault).
    pub fn listed(&self) -> Listed {
        Listed {
            groups: self
                .list
                .iter()
                .map(|s| match s {
                    ListSource::Open(r, v) => (r.clone(), Arc::new(v.summaries())),
                    ListSource::Kept(r, l) => (r.clone(), l.clone()),
                })
                .collect(),
            locked: self.locked,
        }
    }

    /// What these lists are now, to tell later whether they changed ([`ListStamp::is`]). Holds
    /// no vault: a stamp never keeps a locked vault alive.
    pub fn stamp(&self) -> ListStamp {
        ListStamp {
            list: self
                .list
                .iter()
                .map(|s| match s {
                    ListSource::Open(r, v) => (
                        r.clone(),
                        Held::Open(Arc::downgrade(v), v.list_generation()),
                    ),
                    ListSource::Kept(r, l) => (r.clone(), Held::Kept(Arc::downgrade(l))),
                })
                .collect(),
            locked: self.locked,
        }
    }
}

enum Held {
    Open(std::sync::Weak<Vault>, u64),
    Kept(std::sync::Weak<Vec<ItemSummary>>),
}

/// [`ListSources::stamp`]: the vaults and lists by identity, and each vault's
/// [`Vault::list_generation`].
pub(crate) struct ListStamp {
    list: Vec<(VaultRef, Held)>,
    locked: bool,
}

impl ListStamp {
    /// Whether `sources` are the lists stamped, unchanged.
    pub fn is(&self, sources: &ListSources) -> bool {
        self.locked == sources.locked
            && self.list.len() == sources.list.len()
            && self
                .list
                .iter()
                .zip(&sources.list)
                .all(|((r, held), s)| match (held, s) {
                    (Held::Open(w, generation), ListSource::Open(sr, v)) => {
                        r == sr
                            && std::ptr::eq(w.as_ptr(), Arc::as_ptr(v))
                            && *generation == v.list_generation()
                    }
                    (Held::Kept(w), ListSource::Kept(sr, l)) => {
                        r == sr && std::ptr::eq(w.as_ptr(), Arc::as_ptr(l))
                    }
                    _ => false,
                })
    }
}

/// Every vault's list without secrets for one request, the home vault first, and whether the
/// vault is locked (the lists a soft lock kept).
pub(crate) struct Listed {
    pub groups: Vec<(VaultRef, Arc<Vec<ItemSummary>>)>,
    pub locked: bool,
}

impl Listed {
    /// Every list as one, the home vault's first: single-vault queries over it give the order of
    /// pass-core's `multi_*` calls.
    pub fn all(&self) -> Vec<ItemSummary> {
        self.groups
            .iter()
            .flat_map(|(_, list)| list.iter().cloned())
            .collect()
    }

    pub fn ref_of(&self, item_id: &str) -> Option<&VaultRef> {
        self.groups
            .iter()
            .find(|(_, list)| list.iter().any(|i| i.id == item_id))
            .map(|(r, _)| r)
    }

    /// The `vaults` table for an answer listing `ids`: each vault holding one of them, in the
    /// order of the open vaults (the home vault first).
    pub fn table<'a>(&self, ids: impl IntoIterator<Item = &'a str>) -> Vec<VaultRef> {
        let ids: Vec<&str> = ids.into_iter().collect();
        self.groups
            .iter()
            .filter(|(_, list)| list.iter().any(|i| ids.contains(&i.id.as_str())))
            .map(|(r, _)| r.clone())
            .collect()
    }
}

impl Agent {
    fn home_ref_of(&self, vault: &Vault) -> VaultRef {
        VaultRef {
            id: vault.vault_id(),
            name: self.ui.vault_name().unwrap_or_default(),
            home: true,
            kind: VaultKind::Personal,
            role: None,
            can_edit: true,
            can_reveal: true,
        }
    }

    /// The open vaults, the home vault first; `None` while locked. Not activity.
    pub(crate) fn opened(&self) -> Option<Opened> {
        let (home, shared) = {
            let state = self.state();
            let home = state.vault.clone()?;
            let mut shared: Vec<(VaultRef, Arc<Vault>)> = state
                .linked
                .open
                .iter()
                .map(|o| (state.linked.vault_ref(o), o.vault.clone()))
                .collect();
            shared.extend(state.linked.session.iter().cloned());
            (home, shared)
        };
        // Outside the state lock: the app's name for the vault may take its own locks.
        let mut all = vec![(self.home_ref_of(&home), home)];
        all.extend(shared);
        Some(Opened(all))
    }

    /// Every vault's list (unlocked, or the lists a soft lock kept); `None` fully locked.
    pub(crate) fn listed_vaults(&self) -> Option<Listed> {
        self.list_sources().map(|s| s.listed())
    }

    /// Where [`Agent::listed_vaults`] comes from, before the summaries are made.
    pub(crate) fn list_sources(&self) -> Option<ListSources> {
        let (home, index, shared, kept) = {
            let state = self.state();
            let mut shared: Vec<(VaultRef, Arc<Vault>)> = state
                .linked
                .open
                .iter()
                .map(|o| (state.linked.vault_ref(o), o.vault.clone()))
                .collect();
            shared.extend(state.linked.session.iter().cloned());
            (
                state.vault.clone(),
                state.index.clone(),
                shared,
                state.linked.kept.clone(),
            )
        };
        match home {
            Some(home) => {
                let mut list = vec![ListSource::Open(self.home_ref_of(&home), home)];
                list.extend(shared.into_iter().map(|(r, v)| ListSource::Open(r, v)));
                Some(ListSources {
                    list,
                    locked: false,
                })
            }
            None => {
                let index = index?;
                let home = VaultRef {
                    id: self.state().linked.home_id.clone().unwrap_or_default(),
                    name: self.ui.vault_name().unwrap_or_default(),
                    home: true,
                    kind: VaultKind::Personal,
                    role: None,
                    can_edit: true,
                    can_reveal: true,
                };
                let mut list = vec![ListSource::Kept(home, index)];
                list.extend(kept.into_iter().map(|(r, l)| ListSource::Kept(r, l)));
                Some(ListSources { list, locked: true })
            }
        }
    }

    // ---- the app's API ---------------------------------------------------------------------

    /// Replaces the list of linked vaults. While unlocked, opens the new ones that have a local
    /// copy and closes (after saving) the ones no longer listed; locked, the list waits for the
    /// next unlock. Not activity.
    pub fn set_linked_vaults(&self, list: Vec<LinkedVaultConfig>) {
        let dropped: Vec<(PathBuf, OpenShared)> = {
            let mut state = self.state();
            let linked = &mut state.linked;
            let keys: Vec<String> = list.iter().map(|c| c.key.clone()).collect();
            let (keep, drop): (Vec<OpenShared>, Vec<OpenShared>) = std::mem::take(&mut linked.open)
                .into_iter()
                .partition(|o| keys.contains(&o.key));
            // Saved to where they were kept before the list forgets them.
            let drop = drop
                .into_iter()
                .filter_map(|o| Some((linked.config(&o.key)?.path.clone(), o)))
                .collect();
            linked.configs = list;
            linked.open = keep;
            linked.kept.retain(|(r, _)| {
                linked
                    .runtime
                    .iter()
                    .any(|(k, rt)| keys.contains(k) && rt.vault_id.as_deref() == Some(&r.id))
            });
            linked.runtime.retain(|k, _| keys.contains(k));
            drop
        };
        for (path, o) in dropped {
            if o.vault.is_dirty() {
                let _one = self.shared_lock.lock().unwrap_or_else(|p| p.into_inner());
                if let Err(e) = self.write_shared(&path, &o.vault) {
                    eprintln!("pass-agent: could not save a shared vault: {e}");
                }
            }
        }
        if !self.is_locked() {
            self.open_linked();
        } else {
            // A start: the list came after the home vault's kept list.
            self.restore_shared_kept_lists();
        }
    }

    pub fn linked_configs(&self) -> Vec<LinkedVaultConfig> {
        self.state().linked.configs.clone()
    }

    /// Every listed shared vault with what the agent knows of it. Not activity.
    pub fn linked_status(&self) -> Vec<LinkedStatus> {
        let state = self.state();
        let linked = &state.linked;
        linked
            .configs
            .iter()
            .map(|c| {
                let open = linked.open.iter().find(|o| o.key == c.key);
                let rt = linked.runtime.get(&c.key).cloned().unwrap_or_default();
                let vault = match open {
                    Some(o) => Some(linked.vault_ref(o)),
                    None => rt.vault_id.clone().map(|id| VaultRef {
                        id,
                        name: c.name.clone(),
                        home: false,
                        kind: rt.kind.unwrap_or(VaultKind::Org),
                        role: rt.role,
                        can_edit: false,
                        can_reveal: rt.can_reveal,
                    }),
                };
                let items = match open {
                    Some(o) => o.vault.item_count(),
                    None => vault
                        .as_ref()
                        .and_then(|r| linked.kept.iter().find(|(k, _)| k.id == r.id))
                        .map(|(_, l)| l.len())
                        .unwrap_or(0),
                };
                LinkedStatus {
                    key: c.key.clone(),
                    name: c.name.clone(),
                    org: c.org.clone(),
                    vault,
                    open: open.is_some(),
                    items,
                    error: rt.error.clone(),
                    last_sync_ms: rt.last_sync_ms,
                    writable: c.writable,
                }
            })
            .collect()
    }

    /// The open vaults, the home vault first; empty while locked. Not activity.
    pub fn open_vaults(&self) -> Vec<(VaultRef, Arc<Vault>)> {
        self.opened().map(|o| o.0).unwrap_or_default()
    }

    /// Shows `vault` beside the others until the next lock, under `name`, never saved: someone
    /// else's vault opened through emergency access (kind `emergency`). Its items can be shown,
    /// filled and copied into another vault, not changed. Replaces a session vault with the same
    /// id. `InvalidPassword` while locked.
    pub fn add_session_vault(&self, name: &str, vault: Arc<Vault>) -> Result<(), PassError> {
        let mut state = self.state();
        if state.vault.is_none() {
            return Err(PassError::InvalidPassword);
        }
        let id = vault.vault_id();
        let vault_ref = VaultRef {
            id: id.clone(),
            name: name.to_string(),
            home: false,
            kind: VaultKind::Emergency,
            role: None,
            can_edit: false,
            can_reveal: true,
        };
        let session = &mut state.linked.session;
        session.retain(|(r, _)| r.id != id);
        session.push((vault_ref, vault));
        Ok(())
    }

    // ---- shared vaults' lists kept between runs (kept_list.rs) ---------------------------------

    /// The prefix of the shared vaults' kept lists: beside the home vault's `<stem>.bin`.
    fn shared_kept_prefix(&self) -> Option<(PathBuf, String)> {
        let home = self.cfg().kept_list.clone()?;
        let stem = home.file_stem()?.to_string_lossy().to_string();
        Some((home.parent()?.to_path_buf(), format!("{stem}.shared.")))
    }

    /// Where shared vault `key`'s list is kept between runs.
    fn shared_kept_path(&self, key: &str) -> Option<PathBuf> {
        let (dir, prefix) = self.shared_kept_prefix()?;
        let safe: String = key
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .take(64)
            .collect();
        Some(dir.join(format!("{prefix}{safe}-{:016x}.bin", fnv1a(key))))
    }

    /// Deletes every shared vault's kept list (with the home vault's: the setting turned off,
    /// "Lock completely", signed out).
    pub(crate) fn remove_shared_kept_lists(&self) {
        let Some((dir, prefix)) = self.shared_kept_prefix() else {
            return;
        };
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return;
        };
        for entry in entries.filter_map(Result::ok) {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(&prefix) && name.ends_with(".bin") {
                crate::kept_list::remove(&entry.path());
            }
        }
    }

    /// Writes the lists of the open shared vaults for the next start, as the home vault's is
    /// written (a lock while "Keep list visible when locked" is on). Called with the state lock
    /// held, before the shared vaults close.
    pub(super) fn write_shared_kept_lists_locked(&self, state: &super::State) {
        if !self.keeps_list() || state.kept_paused {
            return;
        }
        let Some(sealer) = self.kept_sealer() else {
            return;
        };
        let saved_at = self.unix_ms();
        for open in &state.linked.open {
            let Some(path) = self.shared_kept_path(&open.key) else {
                continue;
            };
            let vault_ref = state.linked.vault_ref(open);
            let stored = crate::kept_list::StoredRef {
                kind: kind_name(vault_ref.kind).to_string(),
                role: vault_ref.role.map(|r| r.as_str().to_string()),
                can_edit: vault_ref.can_edit,
                can_reveal: vault_ref.can_reveal,
            };
            let items = open.vault.summaries();
            if let Err(e) = crate::kept_list::save_shared(
                &path,
                sealer.as_ref(),
                &vault_ref.id,
                &stored,
                &items,
                saved_at,
            ) {
                eprintln!("pass-agent: could not keep a shared vault's list: {e}");
            }
        }
    }

    /// While soft-locked with the home vault's kept list (a start): the kept lists of the listed
    /// shared vaults whose local copy is the vault the list was written for. Called after
    /// [`Agent::restore_kept_list`] and when the list of shared vaults is set.
    pub(crate) fn restore_shared_kept_lists(&self) {
        let Some(sealer) = self.kept_sealer() else {
            return;
        };
        let restorable = |state: &super::State| {
            self.keeps_list()
                && !state.kept_paused
                && state.vault.is_none()
                && state.index.is_some()
        };
        let configs = {
            let state = self.state();
            if !restorable(&state) {
                return;
            }
            let have: Vec<String> = state
                .linked
                .kept
                .iter()
                .map(|(r, _)| r.id.clone())
                .collect();
            state
                .linked
                .configs
                .iter()
                .filter(|c| {
                    state
                        .linked
                        .runtime
                        .get(&c.key)
                        .and_then(|rt| rt.vault_id.as_ref())
                        .is_none_or(|id| !have.contains(id))
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        let mut found = Vec::new();
        for config in configs {
            let Some(path) = self.shared_kept_path(&config.key) else {
                continue;
            };
            if !path.exists() {
                continue;
            }
            let Some(vault_id) = self.vault_file_id_at(&config.path) else {
                continue;
            };
            let Some((stored, items)) =
                crate::kept_list::load_shared(&path, sealer.as_ref(), &vault_id)
            else {
                continue;
            };
            let role = stored
                .role
                .as_deref()
                .and_then(|r| serde_json::from_value::<MemberRole>(serde_json::json!(r)).ok());
            let vault_ref = VaultRef {
                id: vault_id,
                name: config.name.clone(),
                home: false,
                kind: kind_of_name(&stored.kind),
                role,
                can_edit: stored.can_edit && config.writable,
                can_reveal: stored.can_reveal,
            };
            found.push((config.key.clone(), vault_ref, Arc::new(items)));
        }
        if found.is_empty() {
            return;
        }
        {
            let mut state = self.state();
            if !restorable(&state) {
                return;
            }
            for (key, vault_ref, items) in found {
                if state.linked.kept.iter().any(|(r, _)| r.id == vault_ref.id) {
                    continue;
                }
                let rt = state.linked.runtime.entry(key).or_default();
                rt.vault_id = Some(vault_ref.id.clone());
                rt.kind = Some(vault_ref.kind);
                rt.role = vault_ref.role;
                rt.can_reveal = vault_ref.can_reveal;
                state.linked.kept.push((vault_ref, items));
            }
        }
        self.ui.notify_lock_state(true);
    }

    /// Drops the session vault `vault_id` (see [`Agent::add_session_vault`]).
    pub fn remove_session_vault(&self, vault_id: &str) {
        self.state()
            .linked
            .session
            .retain(|(r, _)| r.id != vault_id);
    }

    /// The home vault's [`VaultRef`]; `None` while locked.
    pub fn home_ref(&self) -> Option<VaultRef> {
        let home = self.peek_vault()?;
        Some(self.home_ref_of(&home))
    }

    /// An open shared vault by its vault id. Save it with [`Agent::save_shared`] after a change.
    pub fn shared_vault(&self, vault_id: &str) -> Option<Arc<Vault>> {
        self.state()
            .linked
            .open
            .iter()
            .find(|o| o.vault.vault_id() == vault_id)
            .map(|o| o.vault.clone())
    }

    /// The open vault (home or shared) holding item `item_id`.
    pub fn vault_of_item(&self, item_id: &str) -> Option<(VaultRef, Arc<Vault>)> {
        self.opened()?.holding(item_id).cloned()
    }

    /// Every vault's list without secrets: unlocked, or the lists a soft lock kept. `None` fully
    /// locked. Not activity.
    pub fn all_summaries(&self) -> Option<Vec<(VaultRef, Arc<Vec<ItemSummary>>)>> {
        self.listed_vaults().map(|l| l.groups)
    }

    /// The vault a new login for `url` goes to by default (pass-core `multi_default_save_vault`
    /// over the vaults that may be edited); `None` while locked.
    pub fn default_save_vault(&self, url: Option<&str>) -> Option<String> {
        self.opened()?.default_save(url)
    }

    /// The local copy of shared vault `key`, if it is listed.
    fn shared_path(&self, key: &str) -> Option<PathBuf> {
        self.state().linked.config(key).map(|c| c.path.clone())
    }

    fn key_of(&self, vault_id: &str) -> Option<String> {
        self.state()
            .linked
            .open
            .iter()
            .find(|o| o.vault.vault_id() == vault_id)
            .map(|o| o.key.clone())
    }

    /// Writes `vault` (a shared vault) to `path`. It stays marked to be saved if the write fails
    /// (or it changed meanwhile), so the next save writes it again.
    fn write_shared(&self, path: &std::path::Path, vault: &Vault) -> Result<(), PassError> {
        let snapshot = vault.save_snapshot()?;
        self.store
            .write(path, &snapshot.bytes)
            .map_err(|e| PassError::Corrupt(format!("vault file: {e}")))?;
        vault.mark_saved(snapshot.generation);
        Ok(())
    }

    /// Remembers in the home vault what every open shared vault's members list is now (the trust
    /// records and the unconfirmed member changes) and collects their members notices.
    fn remember_linked(&self) {
        let (home, open) = {
            let state = self.state();
            let Some(home) = state.vault.clone() else {
                return;
            };
            (home, state.linked.open.clone())
        };
        let mut notices = Vec::new();
        for o in &open {
            if let Err(e) = home.remember_trust_of(&o.vault) {
                eprintln!("pass-agent: could not remember a shared vault's members list: {e}");
            }
            if let Some(notice) = o.vault.take_members_notice() {
                notices.push((o.key.clone(), o.vault.vault_id(), notice));
            }
        }
        if !notices.is_empty() {
            let mut state = self.state();
            for (key, vault_id, notice) in notices {
                let name = state
                    .linked
                    .config(&key)
                    .map(|c| c.name.clone())
                    .unwrap_or_default();
                state.linked.notices.push(LinkedNotice {
                    vault_id,
                    name,
                    notice,
                });
            }
        }
    }

    /// Before the home vault is saved ([`Agent::save`]): the home vault's records of every open
    /// shared vault that changed (trust, unconfirmed member changes), so they go into the same
    /// write.
    pub(crate) fn remember_dirty_linked(&self) {
        let dirty = {
            let state = self.state();
            state.vault.is_some() && state.linked.open.iter().any(|o| o.vault.is_dirty())
        };
        if dirty {
            self.remember_linked();
        }
    }

    /// After the home vault is saved ([`Agent::save`]): writes every open shared vault that
    /// changed. Errors are logged; the vault stays marked to be saved and the next save writes it.
    pub(crate) fn write_dirty_linked(&self) {
        let open = {
            let state = self.state();
            if state.vault.is_none() {
                return;
            }
            state
                .linked
                .open
                .iter()
                .filter(|o| o.vault.is_dirty())
                .filter_map(|o| Some((state.linked.config(&o.key)?.path.clone(), o.clone())))
                .collect::<Vec<_>>()
        };
        if open.is_empty() {
            return;
        }
        let _one = self.shared_lock.lock().unwrap_or_else(|p| p.into_inner());
        for (path, o) in open {
            if let Err(e) = self.write_shared(&path, &o.vault) {
                eprintln!("pass-agent: could not save a shared vault: {e}");
            }
        }
    }

    /// Opens every listed shared vault that has a local copy and isn't open yet, through the home
    /// vault (call while unlocked). Errors go to [`Agent::linked_status`].
    pub(crate) fn open_linked(&self) {
        let (home, device, todo) = {
            let state = self.state();
            let Some(home) = state.vault.clone() else {
                return;
            };
            let todo: Vec<LinkedVaultConfig> = state
                .linked
                .configs
                .iter()
                .filter(|c| !state.linked.open.iter().any(|o| o.key == c.key))
                .cloned()
                .collect();
            (home, self.cfg().device_id.clone(), todo)
        };
        let mut opened = Vec::new();
        let mut errors = Vec::new();
        for config in todo {
            if !self.store.exists(&config.path) {
                continue;
            }
            let result = self
                .store
                .read(&config.path)
                .map_err(|e| PassError::Corrupt(format!("vault file: {e}")))
                .and_then(|bytes| {
                    Vault::open_shared_with_home(bytes, &home, &config.account, &device)
                });
            match result {
                Ok(vault) => opened.push((config.key.clone(), vault)),
                Err(e) => errors.push((config.key.clone(), linked_error(&e))),
            }
        }
        self.adopt_opened(opened, errors);
        self.remember_linked();
        if home.is_dirty() {
            if let Err(e) = self.save() {
                eprintln!("pass-agent: could not save the vault after opening shared vaults: {e}");
            }
        }
    }

    /// Puts freshly opened shared vaults into the open list (unless the home vault was locked
    /// meanwhile) and records errors.
    fn adopt_opened(&self, opened: Vec<(String, Arc<Vault>)>, errors: Vec<(String, LinkedError)>) {
        let mut state = self.state();
        if state.vault.is_none() {
            return;
        }
        for (key, error) in errors {
            state.linked.set_error(&key, Some(error));
        }
        for (key, vault) in opened {
            if state.linked.config(&key).is_none() {
                continue;
            }
            let kind = vault
                .shared_info()
                .map(|i| VaultKind::from(i.kind))
                .unwrap_or(VaultKind::Org);
            let rt = state.linked.runtime.entry(key.clone()).or_default();
            rt.vault_id = Some(vault.vault_id());
            rt.kind = Some(kind);
            rt.role = vault.shared_role();
            rt.can_reveal = vault.can_reveal_secrets();
            rt.error = None;
            let id = vault.vault_id();
            state
                .linked
                .open
                .retain(|o| o.key != key && o.vault.vault_id() != id);
            state.linked.open.push(OpenShared { key, kind, vault });
        }
        let order: Vec<String> = state.linked.configs.iter().map(|c| c.key.clone()).collect();
        state
            .linked
            .open
            .sort_by_key(|o| order.iter().position(|k| *k == o.key));
        state.linked.kept.clear();
    }

    /// Writes a shared vault's local copy after a change made through [`Agent::shared_vault`]
    /// (members, items), and the home vault's records of it.
    pub fn save_shared(&self, vault_id: &str) -> Result<(), PassError> {
        let key = self
            .key_of(vault_id)
            .ok_or_else(|| PassError::NotFound("that shared vault isn't open".into()))?;
        let path = self
            .shared_path(&key)
            .ok_or_else(|| PassError::NotFound("that shared vault isn't listed".into()))?;
        let vault = self
            .shared_vault(vault_id)
            .ok_or_else(|| PassError::NotFound("that shared vault isn't open".into()))?;
        self.remember_linked();
        {
            let _one = self.shared_lock.lock().unwrap_or_else(|p| p.into_inner());
            self.write_shared(&path, &vault)?;
        }
        self.save()
    }

    /// A shared vault just made (`Vault::create_shared`) or downloaded and opened by the app:
    /// written to `config.path`, listed (replacing an entry with the same key) and opened. Upload
    /// it with [`Agent::sync_shared`].
    pub fn add_shared(
        &self,
        config: LinkedVaultConfig,
        vault: Arc<Vault>,
    ) -> Result<(), PassError> {
        let home = self.peek_vault().ok_or(PassError::InvalidPassword)?;
        if !vault.is_shared() {
            return Err(PassError::InvalidInput("not a shared vault".into()));
        }
        {
            let _one = self.shared_lock.lock().unwrap_or_else(|p| p.into_inner());
            self.write_shared(&config.path, &vault)?;
        }
        let key = config.key.clone();
        {
            let mut state = self.state();
            state.linked.configs.retain(|c| c.key != key);
            state.linked.configs.push(config);
        }
        self.adopt_opened(vec![(key, vault.clone())], Vec::new());
        home.remember_trust_of(&vault)?;
        self.save()
    }

    /// Opens `bytes`, a downloaded file of listed shared vault `key` (its first download), through
    /// the home vault, and keeps it as the local copy.
    pub fn open_shared_file(&self, key: &str, bytes: Vec<u8>) -> Result<(), PassError> {
        let home = self.peek_vault().ok_or(PassError::InvalidPassword)?;
        let config = self
            .state()
            .linked
            .config(key)
            .cloned()
            .ok_or_else(|| PassError::NotFound("that shared vault isn't listed".into()))?;
        let device = self.cfg().device_id.clone();
        let vault = match Vault::open_shared_with_home(bytes, &home, &config.account, &device) {
            Ok(v) => v,
            Err(e) => {
                self.state().linked.set_error(key, Some(linked_error(&e)));
                return Err(e);
            }
        };
        {
            let _one = self.shared_lock.lock().unwrap_or_else(|p| p.into_inner());
            self.write_shared(&config.path, &vault)?;
        }
        self.adopt_opened(vec![(key.to_string(), vault)], Vec::new());
        self.remember_linked();
        self.save()
    }

    /// Drops shared vault `key` from the list (the user left it, or was removed); with
    /// `delete_file` its local copy too.
    pub fn remove_shared(&self, key: &str, delete_file: bool) {
        let (path, gone) = {
            let mut state = self.state();
            let path = state.linked.config(key).map(|c| c.path.clone());
            state.linked.configs.retain(|c| c.key != key);
            let gone: Vec<OpenShared> = state
                .linked
                .open
                .iter()
                .filter(|o| o.key == key)
                .cloned()
                .collect();
            state.linked.open.retain(|o| o.key != key);
            let mut ids: Vec<String> = gone.iter().map(|o| o.vault.vault_id()).collect();
            if let Some(id) = state
                .linked
                .runtime
                .get(key)
                .and_then(|rt| rt.vault_id.clone())
            {
                ids.push(id);
            }
            state.linked.kept.retain(|(r, _)| !ids.contains(&r.id));
            state.linked.runtime.remove(key);
            (path, gone)
        };
        if let Some(kept) = self.shared_kept_path(key) {
            crate::kept_list::remove(&kept);
        }
        if let Some(path) = path {
            if delete_file {
                let _ = self.store.remove(&path);
            } else if let Some(o) = gone.first() {
                let _ = self.write_shared(&path, &o.vault);
            }
        }
        self.ui.vault_changed();
    }

    /// Moves (`remove`) or copies item `item_id` into the open vault `target_vault_id`, and
    /// saves both. The core refuses a copy out of a fill-only vault, a move out of a vault the
    /// user can't edit, and any change in a target they can't edit.
    pub fn transfer_item(
        &self,
        item_id: &str,
        target_vault_id: &str,
        remove: bool,
    ) -> Result<Item, PassError> {
        let opened = self.opened().ok_or(PassError::InvalidPassword)?;
        let (source_ref, source) = opened
            .holding(item_id)
            .cloned()
            .ok_or_else(|| PassError::NotFound("no such item".into()))?;
        let (target_ref, target) = opened
            .by_id(target_vault_id)
            .cloned()
            .ok_or_else(|| PassError::NotFound("that vault isn't open".into()))?;
        if !target_ref.can_edit || (remove && !source_ref.can_edit) {
            return Err(PassError::InvalidInput(
                "You can use this vault's logins but not change them".into(),
            ));
        }
        let item = if remove {
            source.move_item_to(item_id, &target)?
        } else {
            source.copy_item_to(item_id, &target)?
        };
        self.save()?;
        self.ui.vault_changed();
        Ok(item)
    }

    /// The members notices collected by opens and syncs since the last call.
    pub fn take_linked_notices(&self) -> Vec<LinkedNotice> {
        std::mem::take(&mut self.state().linked.notices)
    }

    /// An open shared vault the server takes uploads for has changes it hasn't seen (for the
    /// sync scheduler). `false` while locked.
    pub fn linked_sync_pending(&self) -> bool {
        let state = self.state();
        state.linked.open.iter().any(|o| {
            state.linked.config(&o.key).is_some_and(|c| c.writable) && o.vault.sync_pending()
        })
    }

    /// Records the use of `item_id` in the vault that holds it (`Vault::record_use`). In a shared
    /// vault that takes no uploads from this account the count stays on this device.
    pub(crate) fn record_use_in_vaults(&self, item_id: &str) -> bool {
        let Some(opened) = self.opened() else {
            return false;
        };
        let Some((_, vault)) = opened.holding(item_id) else {
            return false;
        };
        vault
            .record_use(item_id.to_string(), self.unix_ms())
            .is_ok()
    }

    /// The live item `id` in whichever open vault holds it.
    pub(crate) fn any_item(&self, id: &str) -> Option<Item> {
        let opened = self.opened()?;
        let (_, vault) = opened.holding(id)?;
        vault.get(id.to_string())
    }
}

#[cfg(feature = "webdav")]
impl Agent {
    /// Syncs every listed shared vault (the first download included) and saves them and the
    /// home vault. Read-only mode (update required): nothing. Blocking.
    pub fn sync_linked(&self) -> Vec<(String, Result<Option<pass_core::SyncResult>, PassError>)> {
        let keys: Vec<String> = self
            .state()
            .linked
            .configs
            .iter()
            .map(|c| c.key.clone())
            .collect();
        keys.into_iter()
            .map(|key| {
                let result = self.sync_shared(&key);
                (key, result)
            })
            .collect()
    }

    /// Syncs shared vault `key` with its file on the server. A vault the server takes no uploads
    /// for is only downloaded and merged. `Ok(None)`: not synced (no server, locked, read-only
    /// mode).
    pub fn sync_shared(&self, key: &str) -> Result<Option<pass_core::SyncResult>, PassError> {
        if self.update_required() {
            return Ok(None);
        }
        let _one_at_a_time = self.sync_lock.lock().unwrap_or_else(|p| p.into_inner());
        let (config, open) = {
            let state = self.state();
            if state.vault.is_none() {
                return Err(PassError::InvalidPassword);
            }
            let Some(config) = state.linked.config(key).cloned() else {
                return Err(PassError::NotFound("that shared vault isn't listed".into()));
            };
            let open = state
                .linked
                .open
                .iter()
                .find(|o| o.key == key)
                .map(|o| o.vault.clone());
            (config, open)
        };
        let Some(webdav) = config.webdav.clone() else {
            return Ok(None);
        };
        let result = self.sync_shared_with(&config, open, webdav);
        let now = self.unix_ms();
        {
            let mut state = self.state();
            let rt = state.linked.runtime.entry(key.to_string()).or_default();
            match &result {
                Ok(_) => {
                    rt.error = None;
                    rt.last_sync_ms = Some(now);
                }
                Err(e) => rt.error = Some(linked_error(e)),
            }
            // A list that no longer has this account (removed) or other keys for it: closed.
            if let Err(e) = &result {
                if matches!(error_code(e), "not_a_member" | "keys_mismatch") {
                    state.linked.open.retain(|o| o.key != key);
                }
            }
        }
        if result.is_ok() {
            self.ui.vault_changed();
        }
        result
    }

    fn sync_shared_with(
        &self,
        config: &LinkedVaultConfig,
        open: Option<Arc<Vault>>,
        webdav: pass_core::WebDavConfig,
    ) -> Result<Option<pass_core::SyncResult>, PassError> {
        let Some(vault) = open else {
            let bytes = pass_core::webdav_download(webdav)?;
            let size = bytes.len() as u64;
            self.open_shared_file(&config.key, bytes)?;
            return Ok(Some(pass_core::SyncResult {
                stats: Default::default(),
                uploaded: false,
                created_remote: false,
                remote_bytes: Some(size),
            }));
        };
        let result = if config.writable && vault.can_edit() {
            let mut result = pass_core::webdav_sync(vault.clone(), webdav.clone())?;
            // A lost member change applied again by the merge, or a key replaced after a manager
            // left: upload it now rather than at the next edit.
            if vault.sync_pending() {
                let again = pass_core::webdav_sync(vault.clone(), webdav)?;
                result.uploaded |= again.uploaded;
                result.remote_bytes = again.remote_bytes.or(result.remote_bytes);
            }
            result
        } else {
            let bytes = pass_core::webdav_download(webdav)?;
            let size = bytes.len() as u64;
            let stats = vault.merge_remote(bytes)?;
            pass_core::SyncResult {
                stats,
                uploaded: false,
                created_remote: false,
                remote_bytes: Some(size),
            }
        };
        self.remember_linked();
        {
            let _one = self.shared_lock.lock().unwrap_or_else(|p| p.into_inner());
            if vault.is_dirty() {
                self.write_shared(&config.path, &vault)?;
            }
        }
        self.save()?;
        Ok(Some(result))
    }
}
