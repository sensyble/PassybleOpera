//! Merging two items the user picked, and suggesting authenticator entries to merge with their login.
//! Every single-value field is the user's pick ([`MergePicks`]); the password not kept goes to the history,
//! and passkeys move unchanged so they keep working.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::apply::{alnum, host_key, hosts, issuer_matches, same_text};
use super::merge::{append_notes, totp_secret, url_key, ymd};
use crate::i18n::tr;
use crate::model::{Item, ItemKind, PasswordHistoryEntry, MAX_PASSWORD_HISTORY};
use crate::vault::{UsageMove, Vault};
use crate::{PassError, Result};

/// One of the two items being merged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum MergeSide {
    A,
    B,
}

impl MergeSide {
    fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

/// Which notes the merged item keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum MergeNotes {
    A,
    B,
    /// The primary item's notes, a blank line, then the other's (once if one contains the other).
    Both,
}

/// What the user picked. `None` keeps the default ([`MergePreview::picks`] has every pick resolved).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MergePicks {
    /// The item whose id stays (the other is deleted). Default: the one with a password.
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub primary: Option<MergeSide>,
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub title: Option<MergeSide>,
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub username: Option<MergeSide>,
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub password: Option<MergeSide>,
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub totp: Option<MergeSide>,
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub notes: Option<MergeNotes>,
    /// A title typed by the user. When it has text (after trimming) it is the merged title and the
    /// `title` pick is ignored.
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub custom_title: Option<String>,
}

/// A field that holds one value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum MergeField {
    Title,
    Username,
    Password,
    Totp,
    Notes,
}

/// How a field compares between the two items.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum MergeFieldState {
    /// Neither has it.
    Empty,
    /// Both have the same value (2FA: the same secret).
    Same,
    OnlyA,
    OnlyB,
    /// Both have it, with different values: the user picks one.
    Differs,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MergeFieldPlan {
    pub field: MergeField,
    pub state: MergeFieldState,
}

/// What merging the two items looks like. No secret values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MergePlan {
    /// Title, username, password, 2FA and notes, in that order.
    pub fields: Vec<MergeFieldPlan>,
    /// The primary item unless the user picks: the one with a password (A when both or neither).
    pub default_primary: MergeSide,
    /// Websites, Android apps and passkeys of the merged item (both items', without repeats).
    pub urls: u32,
    pub android_apps: u32,
    pub passkeys: u32,
}

/// The merged item as it would be saved, for the live preview. Holds secrets (it is the item).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MergePreview {
    pub plan: MergePlan,
    /// Every pick as used (the user's, the defaults for the rest).
    pub picks: MergePicks,
    /// The merged item, with the primary item's id.
    pub item: Item,
    /// Passwords added to the history by this merge (0 or 1).
    pub history_added: u32,
    /// A 2FA secret not kept was noted in the notes.
    pub totp_noted: bool,
}

/// Outcome of [`merge_pair`].
#[derive(Clone, Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MergeOutcome {
    /// The merged item as saved.
    pub item: Item,
    /// The item that was deleted.
    pub removed_id: String,
    /// Puts both items back ([`MergeUndo::restore`]).
    pub undo: Arc<MergeUndo>,
}

/// Both items as they were before a [`merge_pair`], to undo it. Memory only (it holds secrets).
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct MergeUndo {
    vault_id: String,
    kept: Item,
    removed: Item,
    usage: UsageMove,
    done: Mutex<bool>,
}

impl std::fmt::Debug for MergeUndo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MergeUndo")
            .field("kept", &self.kept.id)
            .field("removed", &self.removed.id)
            .finish_non_exhaustive()
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl MergeUndo {
    pub fn kept_id(&self) -> String {
        self.kept.id.clone()
    }

    pub fn removed_id(&self) -> String {
        self.removed.id.clone()
    }

    /// Title of the merged item before the merge.
    pub fn kept_title(&self) -> String {
        self.kept.title.clone()
    }

    /// Puts both items back with newer versions (so they win after sync) and restores the usage counts.
    /// Once only. Returns the item that had kept its id.
    pub fn restore(&self, vault: Arc<Vault>) -> Result<Item> {
        if vault.vault_id() != self.vault_id {
            return Err(PassError::InvalidInput(tr!("merge.other_vault")));
        }
        let mut done = self.done.lock().unwrap_or_else(|p| p.into_inner());
        if *done {
            return Err(PassError::InvalidInput(tr!("merge.already_undone")));
        }
        let kept = vault.upsert(self.kept.clone())?;
        vault.upsert(self.removed.clone())?;
        vault.restore_usage(&self.usage);
        *done = true;
        Ok(kept)
    }
}

/// A pair worth merging: an authenticator entry (2FA secret, no password) and the login it belongs
/// to (same website, issuer or title; same username, or one of them has none). No secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MergeSuggestion {
    /// The login (item A of the merge, kept by default).
    pub login_id: String,
    pub login_title: String,
    /// The authenticator entry (item B).
    pub otp_id: String,
    pub otp_title: String,
    pub username: String,
    /// The login's first website, if any.
    pub url: Option<String>,
}

/// An item "Merge with…" offers, best match first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MergeCandidate {
    pub id: String,
    /// How alike the two look (same website, title or issuer, username). 0: no sign at all.
    pub score: u32,
}

fn text_state(a: &str, b: &str, same: impl Fn(&str, &str) -> bool) -> MergeFieldState {
    match (a.trim().is_empty(), b.trim().is_empty()) {
        (true, true) => MergeFieldState::Empty,
        (false, true) => MergeFieldState::OnlyA,
        (true, false) => MergeFieldState::OnlyB,
        (false, false) if same(a.trim(), b.trim()) => MergeFieldState::Same,
        _ => MergeFieldState::Differs,
    }
}

fn field_state(a: &Item, b: &Item, field: MergeField) -> MergeFieldState {
    match field {
        MergeField::Title => text_state(&a.title, &b.title, |x, y| x == y),
        MergeField::Username => text_state(&a.username, &b.username, same_text),
        MergeField::Password => match (a.password.is_empty(), b.password.is_empty()) {
            (true, true) => MergeFieldState::Empty,
            (false, true) => MergeFieldState::OnlyA,
            (true, false) => MergeFieldState::OnlyB,
            _ if a.password == b.password => MergeFieldState::Same,
            _ => MergeFieldState::Differs,
        },
        MergeField::Totp => {
            match (
                totp_secret(a.totp.as_deref()),
                totp_secret(b.totp.as_deref()),
            ) {
                (None, None) => MergeFieldState::Empty,
                (Some(_), None) => MergeFieldState::OnlyA,
                (None, Some(_)) => MergeFieldState::OnlyB,
                (Some(x), Some(y)) if x == y => MergeFieldState::Same,
                _ => MergeFieldState::Differs,
            }
        }
        MergeField::Notes => text_state(&a.notes, &b.notes, |x, y| x == y),
    }
}

const FIELDS: [MergeField; 5] = [
    MergeField::Title,
    MergeField::Username,
    MergeField::Password,
    MergeField::Totp,
    MergeField::Notes,
];

fn default_primary(a: &Item, b: &Item) -> MergeSide {
    if a.password.is_empty() && !b.password.is_empty() {
        MergeSide::B
    } else {
        MergeSide::A
    }
}

/// The default side of a single-value field: the one that has a value; when both have different
/// values the one changed last; otherwise (the same, none, a tie) the primary item.
fn default_side(a: &Item, b: &Item, state: MergeFieldState, primary: MergeSide) -> MergeSide {
    match state {
        MergeFieldState::OnlyA => MergeSide::A,
        MergeFieldState::OnlyB => MergeSide::B,
        MergeFieldState::Differs if a.updated_at > b.updated_at => MergeSide::A,
        MergeFieldState::Differs if b.updated_at > a.updated_at => MergeSide::B,
        _ => primary,
    }
}

fn plan(a: &Item, b: &Item) -> MergePlan {
    let mut urls: HashSet<String> = HashSet::new();
    let mut apps: HashSet<&str> = HashSet::new();
    let mut passkeys: HashSet<&[u8]> = HashSet::new();
    for item in [a, b] {
        urls.extend(item.urls.iter().map(|u| url_key(u)));
        apps.extend(item.android_apps.iter().map(|x| x.package.as_str()));
        passkeys.extend(item.passkeys.iter().map(|p| p.credential_id.as_slice()));
    }
    MergePlan {
        fields: FIELDS
            .iter()
            .map(|&field| MergeFieldPlan {
                field,
                state: field_state(a, b, field),
            })
            .collect(),
        default_primary: default_primary(a, b),
        urls: urls.len() as u32,
        android_apps: apps.len() as u32,
        passkeys: passkeys.len() as u32,
    }
}

fn state_of(plan: &MergePlan, field: MergeField) -> MergeFieldState {
    plan.fields
        .iter()
        .find(|f| f.field == field)
        .map_or(MergeFieldState::Empty, |f| f.state)
}

/// `picks` with every default filled in.
fn resolve(a: &Item, b: &Item, plan: &MergePlan, picks: &MergePicks) -> MergePicks {
    let primary = picks.primary.unwrap_or(plan.default_primary);
    let side = |pick: Option<MergeSide>, field| {
        pick.unwrap_or_else(|| default_side(a, b, state_of(plan, field), primary))
    };
    // Same 2FA secret twice: keep the full otpauth:// link over a bare secret.
    let totp = picks.totp.unwrap_or_else(|| {
        let state = state_of(plan, MergeField::Totp);
        let link = |i: &Item| {
            i.totp
                .as_deref()
                .is_some_and(|t| t.trim().starts_with("otpauth://"))
        };
        if state == MergeFieldState::Same && link(a) != link(b) {
            if link(a) {
                MergeSide::A
            } else {
                MergeSide::B
            }
        } else {
            default_side(a, b, state, primary)
        }
    });
    let notes = picks
        .notes
        .unwrap_or(match state_of(plan, MergeField::Notes) {
            MergeFieldState::OnlyA => MergeNotes::A,
            MergeFieldState::OnlyB => MergeNotes::B,
            MergeFieldState::Differs => MergeNotes::Both,
            _ if primary == MergeSide::A => MergeNotes::A,
            _ => MergeNotes::B,
        });
    MergePicks {
        primary: Some(primary),
        title: Some(side(picks.title, MergeField::Title)),
        username: Some(side(picks.username, MergeField::Username)),
        password: Some(side(picks.password, MergeField::Password)),
        totp: Some(totp),
        notes: Some(notes),
        custom_title: picks
            .custom_title
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_string),
    }
}

fn check_pair(a: &Item, b: &Item) -> Result<()> {
    if !a.id.is_empty() && a.id == b.id {
        return Err(PassError::InvalidInput(tr!("merge.choose_different")));
    }
    if a.kind != b.kind {
        return Err(PassError::InvalidInput(tr!("merge.different_kinds")));
    }
    Ok(())
}

/// The merged item for `picks`; `now` dates the password history entry and the 2FA note.
fn build(a: &Item, b: &Item, plan: MergePlan, picks: &MergePicks, now: i64) -> MergePreview {
    let picks = resolve(a, b, &plan, picks);
    let get = |side: MergeSide| if side == MergeSide::A { a } else { b };
    let primary = picks.primary.unwrap_or(MergeSide::A);
    let (p, o) = (get(primary), get(primary.other()));
    let mut out = p.clone();

    let title_from = get(picks.title.unwrap_or(primary));
    out.title = if title_from.title.trim().is_empty() {
        get(picks.title.unwrap_or(primary).other())
            .title
            .trim()
            .to_string()
    } else {
        title_from.title.trim().to_string()
    };
    if let Some(custom) = &picks.custom_title {
        out.title = custom.clone();
    }
    out.username = get(picks.username.unwrap_or(primary)).username.clone();

    // Password: the one picked stays, the other goes to the history; both histories are kept.
    let kept_from = picks.password.unwrap_or(primary);
    out.password = get(kept_from).password.clone();
    let lost = &get(kept_from.other()).password;
    let mut history: Vec<PasswordHistoryEntry> = Vec::new();
    let mut history_added = 0;
    if !lost.is_empty() && *lost != out.password {
        history.push(PasswordHistoryEntry {
            password: lost.clone(),
            replaced_at: now,
        });
        history_added = 1;
    }
    history.extend(a.password_history.iter().cloned());
    history.extend(b.password_history.iter().cloned());
    history.sort_by_key(|h| std::cmp::Reverse(h.replaced_at));
    let mut seen: HashSet<String> = HashSet::from([out.password.clone()]);
    history.retain(|h| !h.password.is_empty() && seen.insert(h.password.clone()));
    history.truncate(MAX_PASSWORD_HISTORY);
    out.password_history = history;

    // 2FA: the one picked stays; a different secret not kept is noted, so no account gets locked out.
    let totp_from = picks.totp.unwrap_or(primary);
    let kept_totp = get(totp_from).totp.clone().filter(|t| !t.trim().is_empty());
    let lost_totp = get(totp_from.other()).totp.as_deref().map(str::trim);
    let totp_note = lost_totp
        .filter(|t| !t.is_empty())
        .filter(|t| totp_secret(Some(t)) != totp_secret(kept_totp.as_deref()))
        .map(|t| tr!("merge.previous_totp", date = ymd(now), secret = t));
    out.totp = kept_totp;

    out.notes = match picks.notes.unwrap_or(MergeNotes::Both) {
        MergeNotes::A => a.notes.clone(),
        MergeNotes::B => b.notes.clone(),
        MergeNotes::Both => {
            let mut notes = p.notes.clone();
            append_notes(&mut notes, &o.notes);
            notes
        }
    };
    let totp_noted = totp_note.is_some();
    if let Some(line) = totp_note {
        append_notes(&mut out.notes, &line);
    }

    let mut url_keys: HashSet<String> = out.urls.iter().map(|u| url_key(u)).collect();
    for url in &o.urls {
        if url_keys.insert(url_key(url)) {
            out.push_url_from(o, url);
        }
    }
    let mut packages: HashSet<String> =
        out.android_apps.iter().map(|x| x.package.clone()).collect();
    for app in &o.android_apps {
        if packages.insert(app.package.clone()) {
            out.android_apps.push(app.clone());
        }
    }
    let mut credentials: HashSet<Vec<u8>> = out
        .passkeys
        .iter()
        .map(|k| k.credential_id.clone())
        .collect();
    for pk in &o.passkeys {
        if credentials.insert(pk.credential_id.clone()) {
            out.passkeys.push(pk.clone());
        }
    }
    super::merge::absorb_details(&mut out, o);
    out.favorite = a.favorite || b.favorite;
    out.created_at = [a.created_at, b.created_at]
        .into_iter()
        .filter(|&c| c > 0)
        .min()
        .unwrap_or(0);

    MergePreview {
        plan,
        picks,
        item: out,
        history_added,
        totp_noted,
    }
}

/// What merging `a` and `b` with `picks` gives (nothing is saved), for the merge sheet's live
/// preview. `InvalidInput` for the same item twice or a login with a note.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn merge_preview(a: Item, b: Item, picks: MergePicks) -> Result<MergePreview> {
    check_pair(&a, &b)?;
    let plan = plan(&a, &b);
    Ok(build(&a, &b, plan, &picks, crate::now_ms()))
}

/// Merges items `a_id` and `b_id` as `picks` says: the primary keeps its id and gets the other's usage
/// counts, the other is deleted. The caller saves, syncs and keeps [`MergeOutcome::undo`].
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn merge_pair(
    vault: Arc<Vault>,
    a_id: String,
    b_id: String,
    picks: MergePicks,
) -> Result<MergeOutcome> {
    if a_id == b_id {
        return Err(PassError::InvalidInput(tr!("merge.choose_different")));
    }
    let get = |id: &String| {
        vault
            .get(id.clone())
            .ok_or_else(|| PassError::NotFound(tr!("vault.no_item")))
    };
    let (a, b) = (get(&a_id)?, get(&b_id)?);
    check_pair(&a, &b)?;
    let plan = plan(&a, &b);
    let preview = build(&a, &b, plan, &picks, crate::now_ms());
    let (kept, removed) = match preview.picks.primary {
        Some(MergeSide::B) => (b, a),
        _ => (a, b),
    };
    let saved = vault.upsert(preview.item)?;
    // Deleted for good, not trashed: the merged item holds everything and Undo restores it.
    vault.delete_permanently(removed.id.clone())?;
    let usage = vault.move_usage(&removed.id, &saved.id);
    Ok(MergeOutcome {
        item: saved,
        removed_id: removed.id.clone(),
        undo: Arc::new(MergeUndo {
            vault_id: vault.vault_id(),
            kept,
            removed,
            usage,
            done: Mutex::new(false),
        }),
    })
}

/// A 2FA secret and nothing else a login needs: what authenticator apps export.
fn is_otp_only(item: &Item) -> bool {
    item.kind == ItemKind::Login
        && item.has_totp()
        && item.password.is_empty()
        && item.passkeys.is_empty()
}

fn domains(hosts: &[String]) -> Vec<String> {
    hosts
        .iter()
        .map(|h| crate::matching::registrable_domain_of_host(h).unwrap_or_else(|| h.clone()))
        .collect()
}

/// The issuer of an authenticator entry (from its otpauth:// link, else its title), normalised.
fn issuer_of(item: &Item) -> String {
    let issuer = item
        .totp
        .as_deref()
        .and_then(|t| crate::totp_parse(t.to_string()).ok())
        .and_then(|c| c.issuer)
        .filter(|i| !i.trim().is_empty())
        .unwrap_or_else(|| item.title.clone());
    alnum(&issuer)
}

/// Prepared for comparing many pairs.
struct Facts<'a> {
    item: &'a Item,
    hosts: Vec<String>,
    domains: Vec<String>,
    title: String,
    issuer: String,
}

impl<'a> Facts<'a> {
    fn of(item: &'a Item) -> Self {
        let hosts = hosts(item);
        Self {
            domains: domains(&hosts),
            hosts,
            title: alnum(&item.title),
            issuer: if item.has_totp() {
                issuer_of(item)
            } else {
                String::new()
            },
            item,
        }
    }
}

/// Signs that `x` and `y` are the same site: 4 a shared website host, 3 the same domain, 3 the same
/// title or a 2FA issuer that names the other's site or title, 1 one title within the other; 0 none.
fn site_score(x: &Facts, y: &Facts) -> u32 {
    if x.hosts.iter().any(|h| y.hosts.contains(h)) {
        return 4;
    }
    if x.domains.iter().any(|d| y.domains.contains(d)) {
        return 3;
    }
    if !x.title.is_empty() && x.title == y.title {
        return 3;
    }
    if issuer_matches(y.item, &y.hosts, &x.issuer) || issuer_matches(x.item, &x.hosts, &y.issuer) {
        return 3;
    }
    let within = |a: &str, b: &str| a.chars().count() >= 3 && b.contains(a);
    if within(&x.title, &y.title) || within(&y.title, &x.title) {
        return 1;
    }
    0
}

fn username_score(x: &Item, y: &Item) -> Option<u32> {
    let (a, b) = (x.username.trim(), y.username.trim());
    if a.is_empty() || b.is_empty() {
        Some(0)
    } else if same_text(a, b) {
        Some(2)
    } else {
        None
    }
}

/// Authenticator entries that look like they belong to a login (see [`MergeSuggestion`]). Each item is in
/// at most one suggestion, best pairs first.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn merge_suggestions(vault: Arc<Vault>) -> Vec<MergeSuggestion> {
    suggestions(&vault.items())
}

pub(crate) fn suggestions(items: &[Item]) -> Vec<MergeSuggestion> {
    let otps: Vec<Facts> = items
        .iter()
        .filter(|i| is_otp_only(i))
        .map(Facts::of)
        .collect();
    if otps.is_empty() {
        return Vec::new();
    }
    let logins: Vec<Facts> = items
        .iter()
        .filter(|i| i.kind == ItemKind::Login && !i.password.is_empty())
        .map(Facts::of)
        .collect();
    let mut pairs: Vec<(u32, usize, usize)> = Vec::new();
    for (oi, otp) in otps.iter().enumerate() {
        let secret = totp_secret(otp.item.totp.as_deref());
        for (li, login) in logins.iter().enumerate() {
            let login_secret = totp_secret(login.item.totp.as_deref());
            if login_secret.is_some() && login_secret != secret {
                continue; // a different 2FA secret: not obviously the same account
            }
            let Some(user) = username_score(otp.item, login.item) else {
                continue;
            };
            let site = site_score(otp, login);
            if site >= 3 {
                pairs.push((site + user, oi, li));
            }
        }
    }
    // Best first; ties by title so the result doesn't depend on the vault's order.
    pairs.sort_by(|x, y| {
        y.0.cmp(&x.0)
            .then_with(|| logins[x.2].item.title.cmp(&logins[y.2].item.title))
            .then_with(|| otps[x.1].item.title.cmp(&otps[y.1].item.title))
    });
    let (mut used_otp, mut used_login) = (HashSet::new(), HashSet::new());
    let mut out: Vec<MergeSuggestion> = Vec::new();
    for (_, oi, li) in pairs {
        if used_otp.contains(&oi) || used_login.contains(&li) {
            continue;
        }
        used_otp.insert(oi);
        used_login.insert(li);
        let (otp, login) = (otps[oi].item, logins[li].item);
        out.push(MergeSuggestion {
            login_id: login.id.clone(),
            login_title: login.title.clone(),
            otp_id: otp.id.clone(),
            otp_title: otp.title.clone(),
            username: if login.username.trim().is_empty() {
                otp.username.clone()
            } else {
                login.username.clone()
            },
            url: login.urls.iter().find(|u| host_key(u).is_some()).cloned(),
        });
    }
    out.sort_by_key(|s| s.login_title.to_lowercase());
    out
}

/// The items "Merge with…" offers for item `id` (same kind, not itself), likeliest first.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn merge_candidates(vault: Arc<Vault>, id: String) -> Vec<MergeCandidate> {
    candidates(&vault.items(), &id)
}

pub(crate) fn candidates(items: &[Item], id: &str) -> Vec<MergeCandidate> {
    let Some(me) = items.iter().find(|i| i.id == id) else {
        return Vec::new();
    };
    let mine = Facts::of(me);
    let mut out: Vec<(u32, &Item)> = items
        .iter()
        .filter(|i| i.id != id && i.kind == me.kind)
        .map(|other| {
            let site = site_score(&mine, &Facts::of(other));
            let user = match username_score(me, other) {
                Some(2) => 2,
                _ => 0,
            };
            (if site > 0 { site + user } else { 0 }, other)
        })
        .collect();
    // Stable: equal scores keep the vault's order (by title).
    out.sort_by_key(|x| std::cmp::Reverse(x.0));
    out.into_iter()
        .map(|(score, item)| MergeCandidate {
            id: item.id.clone(),
            score,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AndroidApp, Passkey};
    use crate::vault::KdfParams;

    const SECRET: &str = "JBSWY3DPEHPK3PXP";
    const OTHER_SECRET: &str = "GEZDGNBVGY3TQOJQ";
    const USE_GAP: i64 = crate::usage::USE_DEDUPE_MS * 2;

    fn vault() -> Arc<Vault> {
        Vault::create_with_kdf(
            "pw",
            "dev",
            KdfParams {
                m_kib: 64,
                t: 1,
                p: 1,
                ..Default::default()
            },
        )
        .unwrap()
    }

    fn login(title: &str, user: &str, password: &str, url: &str) -> Item {
        Item {
            title: title.into(),
            username: user.into(),
            password: password.into(),
            urls: if url.is_empty() {
                vec![]
            } else {
                vec![url.into()]
            },
            ..Default::default()
        }
    }

    fn otp(title: &str, user: &str, secret: &str) -> Item {
        Item {
            title: title.into(),
            username: user.into(),
            totp: Some(format!(
                "otpauth://totp/{title}:{user}?secret={secret}&issuer={title}"
            )),
            ..Default::default()
        }
    }

    fn passkey(id: u8) -> Passkey {
        Passkey {
            credential_id: vec![id; 16],
            rp_id: "github.com".into(),
            user_handle: vec![7, id],
            user_name: "me".into(),
            user_display_name: "Me".into(),
            private_key_pkcs8: vec![1, 2, 3],
            ..Default::default()
        }
    }

    fn history(entries: &[(&str, i64)]) -> Vec<PasswordHistoryEntry> {
        entries
            .iter()
            .map(|&(p, at)| PasswordHistoryEntry {
                password: p.into(),
                replaced_at: at,
            })
            .collect()
    }

    fn state(p: &MergePreview, field: MergeField) -> MergeFieldState {
        state_of(&p.plan, field)
    }

    fn with_id(id: &str, item: Item) -> Item {
        Item {
            id: id.into(),
            ..item
        }
    }

    #[test]
    fn authenticator_entry_joins_its_login_by_default() {
        let mut a = otp("GitHub", "me@example.com", SECRET);
        a.id = "otp".into();
        a.updated_at = 300;
        a.favorite = true;
        let mut b = login("GitHub", "me@example.com", "hunter2", "https://github.com");
        b.id = "login".into();
        b.updated_at = 100;
        b.created_at = 50;
        b.notes = "recovery codes in the safe".into();

        let p = merge_preview(a.clone(), b.clone(), MergePicks::default()).unwrap();
        assert_eq!(p.plan.default_primary, MergeSide::B);
        assert_eq!(p.item.id, "login");
        assert_eq!(p.item.password, "hunter2");
        assert_eq!(p.item.totp, a.totp);
        assert_eq!(p.item.urls, vec!["https://github.com".to_string()]);
        assert_eq!(p.item.notes, "recovery codes in the safe");
        assert!(p.item.favorite, "a favorite if either was");
        assert_eq!(p.item.created_at, 50);
        assert!(p.item.password_history.is_empty());
        assert_eq!(p.history_added, 0);
        assert!(!p.totp_noted);
        assert_eq!(state(&p, MergeField::Title), MergeFieldState::Same);
        assert_eq!(state(&p, MergeField::Username), MergeFieldState::Same);
        assert_eq!(state(&p, MergeField::Password), MergeFieldState::OnlyB);
        assert_eq!(state(&p, MergeField::Totp), MergeFieldState::OnlyA);
        assert_eq!(state(&p, MergeField::Notes), MergeFieldState::OnlyB);
        assert_eq!(
            p.picks,
            MergePicks {
                primary: Some(MergeSide::B),
                title: Some(MergeSide::B),
                username: Some(MergeSide::B),
                password: Some(MergeSide::B),
                totp: Some(MergeSide::A),
                notes: Some(MergeNotes::B),
                custom_title: None,
            }
        );
        let other = merge_preview(
            a,
            b,
            MergePicks {
                primary: Some(MergeSide::A),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(other.item.id, "otp");
        assert_eq!(other.item.password, "hunter2");
        assert_eq!(other.item.notes, "recovery codes in the safe");
    }

    #[test]
    fn differing_fields_default_to_the_newer_item_and_follow_picks() {
        let mut a = login("GitHub", "me", "old-pass", "https://github.com");
        a.updated_at = 100;
        let mut b = login(
            "GitHub (work)",
            "me@work",
            "new-pass",
            "https://github.com/",
        );
        b.updated_at = 200;
        let p = merge_preview(a.clone(), b.clone(), MergePicks::default()).unwrap();
        assert_eq!(p.plan.default_primary, MergeSide::A, "both have a password");
        assert_eq!(p.item.id, a.id);
        assert_eq!(p.item.title, "GitHub (work)");
        assert_eq!(p.item.username, "me@work");
        assert_eq!(p.item.password, "new-pass");
        assert_eq!(p.item.password_history.len(), 1);
        assert_eq!(p.item.password_history[0].password, "old-pass");
        assert!(p.item.password_history[0].replaced_at > 0);
        assert_eq!(p.history_added, 1);
        assert_eq!(p.item.urls, ["https://github.com"]);
        assert_eq!(p.plan.urls, 1);

        let picked = merge_preview(
            a,
            b,
            MergePicks {
                title: Some(MergeSide::A),
                username: Some(MergeSide::A),
                password: Some(MergeSide::A),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(picked.item.title, "GitHub");
        assert_eq!(picked.item.username, "me");
        assert_eq!(picked.item.password, "old-pass");
        assert_eq!(picked.item.password_history[0].password, "new-pass");
    }

    #[test]
    fn a_custom_title_overrides_the_title_pick() {
        let a = login("GitHub", "me", "old-pass", "https://github.com");
        let b = login("GitHub (work)", "me", "new-pass", "https://github.com");
        let with = |t: Option<&str>| MergePicks {
            title: Some(MergeSide::A),
            custom_title: t.map(str::to_string),
            ..Default::default()
        };
        let p = merge_preview(a.clone(), b.clone(), with(Some("  My GitHub  "))).unwrap();
        assert_eq!(p.item.title, "My GitHub");
        assert_eq!(p.picks.custom_title.as_deref(), Some("My GitHub"));
        for blank in [Some(""), Some("   "), None] {
            let p = merge_preview(a.clone(), b.clone(), with(blank)).unwrap();
            assert_eq!(p.item.title, "GitHub");
            assert_eq!(p.picks.custom_title, None);
        }
        let v = vault();
        let a = v.upsert(a).unwrap();
        let b = v.upsert(b).unwrap();
        let out = merge_pair(v, a.id, b.id, with(Some("Mine"))).unwrap();
        assert_eq!(out.item.title, "Mine");
    }

    #[test]
    fn same_age_conflicts_keep_the_primary_items_value() {
        let p = merge_preview(
            login("A", "a", "pa", ""),
            login("B", "b", "pb", ""),
            MergePicks::default(),
        )
        .unwrap();
        assert_eq!(
            (p.item.title.as_str(), p.item.password.as_str()),
            ("A", "pa")
        );
        let p = merge_preview(
            login("A", "a", "pa", ""),
            login("B", "b", "pb", ""),
            MergePicks {
                primary: Some(MergeSide::B),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            (p.item.title.as_str(), p.item.password.as_str()),
            ("B", "pb")
        );
    }

    #[test]
    fn password_histories_are_united_newest_first_and_capped() {
        let mut a = login("X", "u", "current-a", "");
        a.updated_at = 10;
        a.password_history = history(&[("old-1", 50), ("shared", 40)]);
        let mut b = login("X", "u", "current-b", "");
        b.updated_at = 20;
        b.password_history = history(&[("shared", 45), ("current-a", 30), ("old-2", 60)]);
        let p = merge_preview(a.clone(), b.clone(), MergePicks::default()).unwrap();
        assert_eq!(p.item.password, "current-b");
        let got: Vec<&str> = p
            .item
            .password_history
            .iter()
            .map(|h| h.password.as_str())
            .collect();
        assert_eq!(got, ["current-a", "old-2", "old-1", "shared"]);
        assert_eq!(p.item.password_history[3].replaced_at, 45);

        a.password_history = (0..MAX_PASSWORD_HISTORY as i64)
            .map(|i| PasswordHistoryEntry {
                password: format!("a{i}"),
                replaced_at: i,
            })
            .collect();
        b.password_history = (0..5)
            .map(|i| PasswordHistoryEntry {
                password: format!("b{i}"),
                replaced_at: 100 + i,
            })
            .collect();
        let p = merge_preview(a, b, MergePicks::default()).unwrap();
        assert_eq!(p.item.password_history.len(), MAX_PASSWORD_HISTORY);
        assert_eq!(p.item.password_history[0].password, "current-a");
        assert_eq!(p.item.password_history[1].password, "b4");
        assert!(p
            .item
            .password_history
            .windows(2)
            .all(|w| w[0].replaced_at >= w[1].replaced_at));
    }

    #[test]
    fn notes_are_joined_unless_one_is_picked() {
        let mut a = login("X", "u", "p", "");
        a.notes = "first".into();
        let mut b = login("X", "u", "p", "");
        b.notes = "second".into();
        let p = merge_preview(a.clone(), b.clone(), MergePicks::default()).unwrap();
        assert_eq!(state(&p, MergeField::Notes), MergeFieldState::Differs);
        assert_eq!(p.picks.notes, Some(MergeNotes::Both));
        assert_eq!(p.item.notes, "first\n\nsecond");
        let primary_b = merge_preview(
            a.clone(),
            b.clone(),
            MergePicks {
                primary: Some(MergeSide::B),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            primary_b.item.notes, "second\n\nfirst",
            "the kept item's notes first"
        );
        let only_b = merge_preview(
            a.clone(),
            b.clone(),
            MergePicks {
                notes: Some(MergeNotes::B),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(only_b.item.notes, "second");
        b.notes = "first\nmore".into();
        let p = merge_preview(b, a, MergePicks::default()).unwrap();
        assert_eq!(p.item.notes, "first\nmore");
    }

    #[test]
    fn a_2fa_secret_not_kept_is_noted() {
        let mut a = otp("GitHub", "me", SECRET);
        a.updated_at = 1;
        let mut b = otp("GitHub", "me", OTHER_SECRET);
        b.password = "pw".into();
        b.updated_at = 2;
        let p = merge_preview(a.clone(), b.clone(), MergePicks::default()).unwrap();
        assert_eq!(state(&p, MergeField::Totp), MergeFieldState::Differs);
        assert_eq!(p.item.totp, b.totp);
        assert!(p.totp_noted);
        assert!(p.item.notes.starts_with("Previous 2FA secret (replaced "));
        assert!(p.item.notes.contains(SECRET));

        let mut c = login("GitHub", "me", "pw", "");
        c.totp = Some(SECRET.into());
        let p = merge_preview(c, a.clone(), MergePicks::default()).unwrap();
        assert_eq!(state(&p, MergeField::Totp), MergeFieldState::Same);
        assert_eq!(p.item.totp, a.totp);
        assert!(!p.totp_noted);
        assert!(p.item.notes.is_empty());
    }

    #[test]
    fn websites_apps_and_passkeys_are_united() {
        let mut a = login("GitHub", "me", "pw", "https://github.com");
        a.urls.push("https://GitHub.com/".into());
        a.android_apps = vec![AndroidApp {
            package: "com.github.android".into(),
            cert_sha256: None,
            ..Default::default()
        }];
        a.passkeys = vec![passkey(1)];
        let mut b = login("GitHub", "me", "", "https://github.com/");
        b.urls.push("https://gist.github.com".into());
        b.android_apps = a.android_apps.clone();
        b.passkeys = vec![passkey(1), passkey(2)];
        let p = merge_preview(a, b, MergePicks::default()).unwrap();
        assert_eq!(
            p.item.urls,
            [
                "https://github.com",
                "https://GitHub.com/",
                "https://gist.github.com"
            ]
        );
        assert_eq!(p.plan.urls, 2, "github.com once, gist once");
        assert_eq!(p.item.android_apps.len(), 1);
        assert_eq!(p.plan.android_apps, 1);
        assert_eq!(p.item.passkeys, vec![passkey(1), passkey(2)]);
        assert_eq!(p.plan.passkeys, 2);
    }

    #[test]
    fn refuses_a_note_with_a_login_and_the_same_item_twice() {
        let note = with_id(
            "n",
            Item {
                kind: ItemKind::Note,
                title: "n".into(),
                ..Default::default()
            },
        );
        let l = with_id("l", login("l", "", "p", ""));
        assert!(matches!(
            merge_preview(note.clone(), l, MergePicks::default()),
            Err(PassError::InvalidInput(_))
        ));
        assert!(matches!(
            merge_preview(note.clone(), note, MergePicks::default()),
            Err(PassError::InvalidInput(_))
        ));
        let v = vault();
        let saved = v.upsert(login("x", "", "p", "")).unwrap();
        assert!(merge_pair(v.clone(), saved.id.clone(), saved.id, MergePicks::default()).is_err());
        assert!(matches!(
            merge_pair(v, "nope".into(), "neither".into(), MergePicks::default()),
            Err(PassError::NotFound(_))
        ));
    }

    #[test]
    fn merging_in_the_vault_moves_passkeys_and_usage_and_undo_restores_both() {
        let v = vault();
        let mut l = login("GitHub", "me", "hunter2", "https://github.com");
        l.password_history = history(&[("older", 5)]);
        let l = v.upsert(l).unwrap();
        let mut o = otp("GitHub", "me", SECRET);
        o.passkeys = vec![passkey(9)];
        let o = v.upsert(o).unwrap();
        let now = crate::now_ms();
        v.record_use(l.id.clone(), now - 10 * USE_GAP).unwrap();
        v.record_use(l.id.clone(), now - 5 * USE_GAP).unwrap();
        v.record_use(o.id.clone(), now).unwrap();
        assert_eq!(v.usage(l.id.clone()).count, 2);

        let out = merge_pair(v.clone(), o.id.clone(), l.id.clone(), MergePicks::default()).unwrap();
        assert_eq!(out.item.id, l.id, "the login keeps its id");
        assert_eq!(out.removed_id, o.id);
        assert!(v.get(o.id.clone()).is_none());
        let merged = v.get(l.id.clone()).unwrap();
        assert_eq!(merged.password, "hunter2");
        assert_eq!(merged.totp, o.totp);
        assert_eq!(merged.password_history, l.password_history);
        let found = v.find_passkeys("github.com".into(), vec![vec![9; 16]]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].item_id, l.id);
        assert_eq!(found[0].passkey.user_handle, vec![7, 9]);
        let usage = v.usage(l.id.clone());
        assert_eq!(usage.count, 3);
        assert_eq!(usage.last_used, now);
        assert_eq!(out.undo.kept_id(), l.id);
        assert_eq!(out.undo.removed_id(), o.id);

        assert!(!v.serialize().unwrap().is_empty());
        let restored = out.undo.restore(v.clone()).unwrap();
        assert_eq!(restored.id, l.id);
        let strip = |i: Item| Item { updated_at: 0, ..i };
        assert_eq!(strip(v.get(l.id.clone()).unwrap()), strip(l.clone()));
        assert_eq!(strip(v.get(o.id.clone()).unwrap()), strip(o.clone()));
        assert!(v.get(o.id.clone()).unwrap().updated_at > o.updated_at);
        assert_eq!(v.usage(l.id.clone()).count, 2);
        assert_eq!(v.usage(o.id.clone()).count, 1);
        assert!(out.undo.restore(v.clone()).is_err(), "only once");

        let again = merge_pair(v.clone(), l.id.clone(), o.id, MergePicks::default()).unwrap();
        assert!(again.undo.restore(vault()).is_err());
        assert!(again.undo.restore(v).is_ok());
    }

    #[test]
    fn suggests_authenticator_entries_for_matching_logins() {
        let items = vec![
            with_id(
                "gh",
                login("GitHub", "me@example.com", "pw", "https://github.com"),
            ),
            with_id("gh-otp", otp("GitHub", "me@example.com", SECRET)),
            with_id(
                "google",
                login("Gmail", "", "pw", "https://accounts.google.com"),
            ),
            with_id("google-otp", otp("Google", "me@gmail.com", SECRET)),
            with_id(
                "dropbox",
                login("Dropbox", "alice", "pw", "https://dropbox.com"),
            ),
            with_id("dropbox-otp", otp("Dropbox", "bob", SECRET)),
            with_id(
                "aws",
                Item {
                    totp: Some(OTHER_SECRET.into()),
                    ..login("AWS", "me", "pw", "https://aws.amazon.com")
                },
            ),
            with_id("aws-otp", otp("AWS", "me", SECRET)),
            with_id("router", login("Router", "admin", "pw", "")),
            with_id("router-otp", otp("router", "admin", SECRET)),
            with_id("steam-otp", otp("Steam", "me", SECRET)),
        ];
        let got = suggestions(&items);
        let pairs: Vec<(&str, &str)> = got
            .iter()
            .map(|s| (s.login_id.as_str(), s.otp_id.as_str()))
            .collect();
        assert_eq!(
            pairs,
            [
                ("gh", "gh-otp"),
                ("google", "google-otp"),
                ("router", "router-otp")
            ]
        );
        assert_eq!(got[1].username, "me@gmail.com", "the login has none");
        assert_eq!(got[0].url.as_deref(), Some("https://github.com"));
    }

    #[test]
    fn each_item_is_suggested_once() {
        let items = vec![
            with_id("gh-1", login("GitHub", "me", "pw", "https://github.com")),
            with_id("gh-2", login("GitHub", "", "pw2", "https://github.com")),
            with_id("otp-1", otp("GitHub", "me", SECRET)),
            with_id("otp-2", otp("GitHub", "me", OTHER_SECRET)),
        ];
        let got = suggestions(&items);
        assert_eq!(got.len(), 2);
        assert!(got.iter().any(|s| s.login_id == "gh-1"));
        assert!(got.iter().any(|s| s.login_id == "gh-2"));
        assert_ne!(got[0].otp_id, got[1].otp_id);
    }

    #[test]
    fn candidates_rank_likely_matches_first() {
        let items = vec![
            with_id("amazon", login("Amazon", "me", "pw", "https://amazon.com")),
            with_id("gh", login("GitHub", "me", "pw", "https://github.com")),
            with_id("gist", login("Gist", "me", "pw", "https://gist.github.com")),
            with_id("gh-otp", otp("GitHub", "me", SECRET)),
            with_id("gh-other", login("GitHub", "someone", "pw", "")),
            with_id("zz", login("Zebra", "", "pw", "")),
            with_id(
                "note",
                Item {
                    kind: ItemKind::Note,
                    title: "GitHub".into(),
                    ..Default::default()
                },
            ),
        ];
        let ranked = candidates(&items, "gh");
        let ids: Vec<&str> = ranked.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["gist", "gh-otp", "gh-other", "amazon", "zz"]);
        assert!(ranked[0].score > ranked[2].score);
        assert_eq!(ranked[3].score, 0);
        assert!(candidates(&items, "missing").is_empty());
    }
}
