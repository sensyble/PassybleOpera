//! Adds imported items to a vault without creating duplicates. Entries matching an existing item or
//! each other form a clash group, resolved by an [`ImportDecision`] (skip, merge or keep both). The
//! defaults skip identical entries and merge the rest, so importing the same file twice changes nothing.

use std::collections::{HashMap, HashSet};

use super::merge::{self, Member};
use super::{
    ClashKind, ImportAction, ImportDecision, ImportEntry, ImportGroup, ImportPreview, ImportReport,
    ImportResult, MergeSource,
};
use crate::matching::parse_loose;
use crate::model::{Item, ItemKind};
use crate::vault::Vault;
use crate::Result;

struct Slot {
    /// What the item looks like with the entries matched so far filled in (for matching only).
    item: Item,
    /// Index into the existing items, for a vault item.
    existing: Option<usize>,
    cluster: Option<usize>,
    /// [`hosts`] of `item`, kept in step with it (re-parsing URLs on every comparison would make big imports quadratic).
    hosts: Vec<String>,
}

/// The pool plus an index of its logins by host, so a login with websites is compared only
/// with the items sharing one of its hosts.
#[derive(Default)]
struct Pool {
    slots: Vec<Slot>,
    by_host: HashMap<String, Vec<usize>>,
}

impl Pool {
    fn index(&mut self, i: usize) {
        for host in &self.slots[i].hosts {
            let list = self.by_host.entry(host.clone()).or_default();
            if list.last() != Some(&i) {
                list.push(i);
            }
        }
    }

    fn push(&mut self, item: Item, existing: Option<usize>, cluster: Option<usize>) {
        let hosts = hosts(&item);
        self.slots.push(Slot {
            item,
            existing,
            cluster,
            hosts,
        });
        self.index(self.slots.len() - 1);
    }

    /// Call after changing `slots[i].item`.
    fn refresh(&mut self, i: usize) {
        self.slots[i].hosts = hosts(&self.slots[i].item);
        self.index(i);
    }
}

pub(crate) fn host_key(url: &str) -> Option<String> {
    let parsed = parse_loose(url)?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let host = parsed
        .host_str()?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    Some(host.strip_prefix("www.").unwrap_or(&host).to_string())
}

pub(crate) fn hosts(item: &Item) -> Vec<String> {
    item.urls.iter().filter_map(|u| host_key(u)).collect()
}

pub(crate) fn same_text(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

pub(crate) fn alnum(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_authenticator_entry(item: &Item) -> bool {
    item.password.is_empty() && item.urls.is_empty() && item.has_totp()
}

/// Does `existing` (with its [`hosts`]) look like the account of the issuer `issuer` (already
/// [`alnum`]-normalised)?
pub(crate) fn issuer_matches(existing: &Item, existing_hosts: &[String], issuer: &str) -> bool {
    if issuer.is_empty() {
        return false;
    }
    if alnum(&existing.title) == issuer {
        return true;
    }
    existing_hosts.iter().any(|host| {
        let domain =
            crate::matching::registrable_domain_of_host(host).unwrap_or_else(|| host.clone());
        domain
            .split('.')
            .next()
            .is_some_and(|label| alnum(label) == issuer)
            || alnum(&domain) == issuer
            || alnum(host) == issuer
    })
}

/// A card's number, digits only.
fn card_digits(item: &Item) -> String {
    item.card
        .as_ref()
        .map(|c| c.number.chars().filter(char::is_ascii_digit).collect())
        .unwrap_or_default()
}

/// An identity's name and email, for matching.
fn identity_key(item: &Item) -> (String, String) {
    item.identity
        .as_ref()
        .map(|i| (i.full_name().to_lowercase(), i.email.trim().to_lowercase()))
        .unwrap_or_default()
}

/// Indices (in pool order) of the items `imported` matches.
fn candidates(pool: &Pool, imported: &Item) -> Vec<usize> {
    if imported.kind == ItemKind::Card {
        // The same card number; cards without a number by title.
        let digits = card_digits(imported);
        return (0..pool.slots.len())
            .filter(|&i| {
                let e = &pool.slots[i].item;
                e.kind == ItemKind::Card
                    && if digits.is_empty() {
                        card_digits(e).is_empty() && same_text(&e.title, &imported.title)
                    } else {
                        card_digits(e) == digits
                    }
            })
            .collect();
    }
    if imported.kind == ItemKind::Identity {
        // The same title, name and email.
        let key = identity_key(imported);
        return (0..pool.slots.len())
            .filter(|&i| {
                let e = &pool.slots[i].item;
                e.kind == ItemKind::Identity
                    && same_text(&e.title, &imported.title)
                    && identity_key(e) == key
            })
            .collect();
    }
    if imported.kind == ItemKind::Note {
        return (0..pool.slots.len())
            .filter(|&i| {
                let e = &pool.slots[i].item;
                e.kind == ItemKind::Note
                    && same_text(&e.title, &imported.title)
                    && e.notes.contains(imported.notes.trim())
            })
            .collect();
    }
    let import_hosts = hosts(imported);
    if !import_hosts.is_empty() {
        let mut found: Vec<usize> = import_hosts
            .iter()
            .filter_map(|h| pool.by_host.get(h))
            .flatten()
            .copied()
            .collect();
        found.sort_unstable();
        found.dedup();
        found.retain(|&i| {
            let slot = &pool.slots[i];
            slot.item.kind == imported.kind
                && same_text(&slot.item.username, &imported.username)
                && slot.hosts.iter().any(|h| import_hosts.contains(h))
        });
        return found;
    }
    let authenticator = is_authenticator_entry(imported).then(|| {
        let config = imported
            .totp
            .as_deref()
            .and_then(|t| crate::totp_parse(t.to_string()).ok());
        let issuer = config
            .as_ref()
            .and_then(|c| c.issuer.clone())
            .unwrap_or_else(|| imported.title.clone());
        let account = if imported.username.is_empty() {
            config.and_then(|c| c.account).unwrap_or_default()
        } else {
            imported.username.clone()
        };
        (alnum(&issuer), account)
    });
    (0..pool.slots.len())
        .filter(|&i| {
            let slot = &pool.slots[i];
            let e = &slot.item;
            if e.kind != imported.kind {
                return false;
            }
            match &authenticator {
                Some((issuer, account)) => {
                    same_text(&e.username, account) && issuer_matches(e, &slot.hosts, issuer)
                }
                None => {
                    e.urls.is_empty()
                        && same_text(&e.title, &imported.title)
                        && same_text(&e.username, &imported.username)
                }
            }
        })
        .collect()
}

/// Same account with a different password or 2FA secret.
fn conflicts(existing: &Item, imported: &Item) -> bool {
    if existing.kind != ItemKind::Login {
        return false;
    }
    let password = !existing.password.is_empty()
        && !imported.password.is_empty()
        && existing.password != imported.password;
    let totp = match (
        merge::totp_secret(existing.totp.as_deref()),
        merge::totp_secret(imported.totp.as_deref()),
    ) {
        (Some(a), Some(b)) => a != b,
        _ => false,
    };
    password || totp
}

/// Fills what `slot` lacks from `imported` (missing password / 2FA, websites), so later entries
/// of the file match what the merged item will look like.
fn absorb(slot: &mut Item, imported: &Item) {
    if slot.password.is_empty() {
        slot.password = imported.password.clone();
    }
    if !slot.has_totp() {
        slot.totp = imported.totp.clone();
    }
    for url in &imported.urls {
        let key = merge::url_key(url);
        if !slot.urls.iter().any(|u| merge::url_key(u) == key) {
            slot.push_url_from(imported, url);
        }
    }
    merge::append_notes(&mut slot.notes, &imported.notes);
    merge::absorb_details(slot, imported);
}

/// Entries of the file that belong together, with the vault item they match (if any).
struct Cluster {
    existing: Option<usize>,
    /// Indices into the imported items, in file order.
    imports: Vec<usize>,
}

/// Groups the imported items by account. Pure.
fn cluster(existing: &[Item], imported: &[Item]) -> Vec<Cluster> {
    let mut pool = Pool::default();
    for (i, item) in existing.iter().enumerate() {
        pool.push(item.clone(), Some(i), None);
    }
    let mut clusters: Vec<Cluster> = Vec::new();
    for (k, original) in imported.iter().enumerate() {
        let found = candidates(&pool, original);
        let compatible = |i: &usize| !conflicts(&pool.slots[*i].item, original);
        // A vault item wins over an earlier entry of the file; a compatible one over a clash.
        let (in_vault, in_file): (Vec<usize>, Vec<usize>) = found
            .iter()
            .partition(|&&i| pool.slots[i].existing.is_some());
        let pick = in_vault
            .iter()
            .copied()
            .find(compatible)
            .or_else(|| in_vault.first().copied())
            .or_else(|| in_file.iter().copied().find(compatible))
            .or_else(|| in_file.first().copied());
        match pick {
            Some(s) => {
                let c = match pool.slots[s].cluster {
                    Some(c) => c,
                    None => {
                        clusters.push(Cluster {
                            existing: pool.slots[s].existing,
                            imports: Vec::new(),
                        });
                        pool.slots[s].cluster = Some(clusters.len() - 1);
                        clusters.len() - 1
                    }
                };
                clusters[c].imports.push(k);
                absorb(&mut pool.slots[s].item, original);
                pool.refresh(s);
            }
            None => {
                clusters.push(Cluster {
                    existing: None,
                    imports: vec![k],
                });
                let mut item = original.clone();
                item.id.clear();
                pool.push(item, None, Some(clusters.len() - 1));
            }
        }
    }
    clusters
}

/// Stable id of a clash group: its first entry, and the vault item it matches.
fn group_id(c: &Cluster, existing: &[Item]) -> String {
    match c.existing {
        Some(e) => format!("import#{}+{}", c.imports[0], existing[e].id),
        None => format!("import#{}", c.imports[0]),
    }
}

/// The choice id of entry `k` of the file.
pub(crate) fn import_choice(k: usize) -> String {
    format!("import#{k}")
}

pub(crate) const EXISTING_CHOICE: &str = "existing";

/// The import worked out against a vault: what each entry becomes and what gets written.
pub(crate) struct Plan {
    pub entries: Vec<ImportEntry>,
    pub groups: Vec<ImportGroup>,
    /// Items to upsert: merged existing items (with their id) and new ones (empty id).
    pub writes: Vec<Item>,
    pub added: u32,
    pub merged: u32,
    /// New items added next to a matching one (Keep both).
    pub kept_both: u32,
    /// Entries with nothing new.
    pub duplicates: u32,
    /// Entries skipped by a decision.
    pub skipped: u32,
}

fn entry(original: &Item, group: Option<&str>) -> ImportEntry {
    ImportEntry {
        kind: original.kind,
        title: original.title.clone(),
        username: original.username.clone(),
        url: original.urls.first().cloned(),
        has_password: !original.password.is_empty(),
        has_totp: original.has_totp(),
        passkeys: original.passkeys.len() as u32,
        has_notes: !original.notes.trim().is_empty(),
        action: ImportAction::Add,
        target_id: None,
        target_title: None,
        adds: Vec::new(),
        group: group.map(str::to_string),
    }
}

/// Works out what importing `imported` into a vault holding `existing` does, with `decisions`
/// (by group id; groups without one get their default). Pure; `now` dates password history.
pub(crate) fn plan(
    existing: &[Item],
    imported: &[Item],
    decisions: &HashMap<String, ImportDecision>,
    now: i64,
) -> Plan {
    let clusters = cluster(existing, imported);
    let mut known_passkeys: HashSet<Vec<u8>> = existing
        .iter()
        .flat_map(|i| i.passkeys.iter().map(|p| p.credential_id.clone()))
        .collect();
    // Entries with ids cleared and passkeys already in the vault (or an earlier entry) removed:
    // a credential lives in one item only.
    let mut clean: Vec<Item> = Vec::with_capacity(imported.len());
    for original in imported {
        let mut item = original.clone();
        item.id.clear();
        item.updated_at = original.updated_at.max(0);
        item.passkeys
            .retain(|p| known_passkeys.insert(p.credential_id.clone()));
        clean.push(item);
    }

    let mut plan = Plan {
        entries: imported.iter().map(|i| entry(i, None)).collect(),
        groups: Vec::new(),
        writes: Vec::new(),
        added: 0,
        merged: 0,
        kept_both: 0,
        duplicates: 0,
        skipped: 0,
    };
    for c in &clusters {
        if c.existing.is_none() && c.imports.len() == 1 {
            plan.writes.push(clean[c.imports[0]].clone());
            plan.added += 1;
            continue;
        }
        let id = group_id(c, existing);
        let mut members: Vec<Member> = Vec::with_capacity(c.imports.len() + 1);
        if let Some(e) = c.existing {
            members.push(Member {
                choice_id: EXISTING_CHOICE.to_string(),
                source: MergeSource::Existing,
                item: &existing[e],
            });
        }
        for &k in &c.imports {
            members.push(Member {
                choice_id: import_choice(k),
                source: MergeSource::Import,
                item: &clean[k],
            });
        }
        let analysis = merge::analyse(&members);
        let kind = match c.existing {
            None => ClashKind::InFileDuplicate,
            Some(_) if analysis.identical() => ClashKind::Identical,
            Some(_) => ClashKind::Differs,
        };
        let default = match kind {
            ClashKind::Identical => ImportDecision::Skip,
            _ => ImportDecision::default_merge(),
        };
        let decision = decisions
            .get(&id)
            .cloned()
            .unwrap_or_else(|| default.clone());
        let base = members[0].item;
        let existing_item = c.existing.map(|e| &existing[e]);
        for &k in &c.imports {
            let e = &mut plan.entries[k];
            e.group = Some(id.clone());
            e.target_id = existing_item.map(|x| x.id.clone());
            e.target_title = Some(base.title.clone());
        }
        match &decision {
            ImportDecision::Skip => {
                let action = if kind == ClashKind::Identical {
                    plan.duplicates += c.imports.len() as u32;
                    ImportAction::Duplicate
                } else {
                    plan.skipped += c.imports.len() as u32;
                    ImportAction::Skip
                };
                for &k in &c.imports {
                    plan.entries[k].action = action;
                }
            }
            ImportDecision::KeepBoth => {
                for (n, &k) in c.imports.iter().enumerate() {
                    plan.writes.push(clean[k].clone());
                    plan.added += 1;
                    let separate = existing_item.is_some() || n > 0;
                    if separate {
                        plan.kept_both += 1;
                    } else {
                        plan.entries[k].target_title = None;
                    }
                    plan.entries[k].action = if separate {
                        ImportAction::Conflict
                    } else {
                        ImportAction::Add
                    };
                }
            }
            ImportDecision::Merge { .. } => {
                let merged = merge::merge(&members, &decision, now);
                match existing_item {
                    Some(before) if merge::same_content(before, &merged) => {
                        plan.duplicates += c.imports.len() as u32;
                        for &k in &c.imports {
                            plan.entries[k].action = ImportAction::Duplicate;
                        }
                    }
                    Some(before) => {
                        let adds = merge::changes(before, &merged);
                        plan.merged += c.imports.len() as u32;
                        for &k in &c.imports {
                            plan.entries[k].action = ImportAction::Merge;
                            plan.entries[k].adds = adds.clone();
                        }
                        plan.writes.push(merged);
                    }
                    None => {
                        plan.added += 1;
                        plan.merged += c.imports.len() as u32 - 1;
                        for (n, &k) in c.imports.iter().enumerate() {
                            let e = &mut plan.entries[k];
                            if n == 0 {
                                e.action = ImportAction::Add;
                                e.target_title = None;
                            } else {
                                // Into the new item (no `target_id`): nothing to list in `adds`.
                                e.action = ImportAction::Merge;
                                e.target_title = Some(merged.title.clone());
                            }
                        }
                        plan.writes.push(merged);
                    }
                }
            }
        }
        plan.groups.push(ImportGroup {
            id,
            kind,
            title: base.title.clone(),
            username: base.username.clone(),
            url: base
                .urls
                .first()
                .or_else(|| members.iter().find_map(|m| m.item.urls.first()))
                .cloned(),
            existing_id: existing_item.map(|x| x.id.clone()),
            existing_title: existing_item.map(|x| x.title.clone()),
            entries: c.imports.iter().map(|&k| k as u32).collect(),
            password_choices: analysis.password_choices(&members),
            totp_choices: analysis.totp_choices(&members),
            title_choices: analysis.title_choices(&members),
            differs: analysis.differs,
            default_decision: default,
        });
    }
    plan
}

pub(crate) fn preview(report: &ImportReport, plan: Plan) -> ImportPreview {
    let count = |a: ImportAction| plan.entries.iter().filter(|e| e.action == a).count() as u32;
    ImportPreview {
        format: report.format,
        format_name: report.format.name(),
        to_add: plan.added,
        to_merge: count(ImportAction::Merge),
        conflicts: plan.kept_both,
        duplicates: plan.duplicates,
        skipped: report.skipped.clone(),
        warnings: report.warnings.clone(),
        clashes: plan.groups.len() as u32,
        groups: plan.groups,
        entries: plan.entries,
    }
}

pub(crate) fn commit(
    vault: &Vault,
    report: &ImportReport,
    decisions: &HashMap<String, ImportDecision>,
) -> Result<ImportResult> {
    let plan = plan(&vault.items(), &report.items, decisions, crate::now_ms());
    let mut failed = 0u32;
    for mut item in plan.writes {
        // Notes merged from several entries stay within the cap (or the stored copy's length).
        let stored = vault.get(item.id.clone()).map_or(0, |i| i.notes.chars().count());
        crate::limits::truncate_chars(&mut item.notes, crate::MAX_NOTES_CHARS.max(stored));
        // Items were validated while parsing; a failure here only skips that item.
        if vault.upsert_with(item, true).is_err() {
            failed += 1;
        }
    }
    Ok(ImportResult {
        added: plan.added.saturating_sub(failed),
        merged: plan.merged,
        conflicts: plan.kept_both,
        skipped: plan.duplicates + plan.skipped + report.skipped.len() as u32 + failed,
    })
}
