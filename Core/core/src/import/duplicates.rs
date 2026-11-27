//! Finds duplicate logins already in the vault: same website and username (case-insensitive), or,
//! both without a username, the same password. [`merge_items`] folds a group into its first item
//! like an import merge and deletes the others for good, not to the trash.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use super::apply::hosts;
use super::merge::{self, Member};
use super::{ClashKind, DuplicateGroup, ImportDecision, MergeChoice, MergeSource};
use crate::i18n::tr;
use crate::model::{Item, ItemKind};
use crate::vault::Vault;
use crate::{PassError, Result};

fn find(parent: &mut [usize], mut i: usize) -> usize {
    while parent[i] != i {
        parent[i] = parent[parent[i]];
        i = parent[i];
    }
    i
}

fn members(items: &[Item]) -> Vec<Member<'_>> {
    items
        .iter()
        .map(|item| Member {
            choice_id: item.id.clone(),
            source: MergeSource::Vault,
            item,
        })
        .collect()
}

/// Groups of logins that look like the same account. No secrets.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn find_duplicates(vault: Arc<Vault>) -> Vec<DuplicateGroup> {
    duplicate_groups(&vault.items())
}

pub(crate) fn duplicate_groups(items: &[Item]) -> Vec<DuplicateGroup> {
    let logins: Vec<&Item> = items.iter().filter(|i| i.kind == ItemKind::Login).collect();
    let mut parent: Vec<usize> = (0..logins.len()).collect();
    let mut first_with: HashMap<(String, String), usize> = HashMap::new();
    for (i, item) in logins.iter().enumerate() {
        let user = item.username.trim().to_lowercase();
        let account = if !user.is_empty() {
            format!("u:{user}")
        } else if !item.password.is_empty() {
            format!("p:{}", item.password)
        } else {
            continue;
        };
        for host in hosts(item) {
            match first_with.get(&(host.clone(), account.clone())) {
                Some(&j) => {
                    let (a, b) = (find(&mut parent, i), find(&mut parent, j));
                    parent[a] = b;
                }
                None => {
                    first_with.insert((host, account.clone()), i);
                }
            }
        }
    }
    let mut sets: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in 0..logins.len() {
        let root = find(&mut parent, i);
        sets.entry(root).or_default().push(i);
    }
    let mut groups: Vec<DuplicateGroup> = sets
        .into_values()
        .filter(|set| set.len() > 1)
        .map(|set| {
            let mut group: Vec<Item> = set.iter().map(|&i| logins[i].clone()).collect();
            group.sort_by(|a, b| b.updated_at.cmp(&a.updated_at).then(a.id.cmp(&b.id)));
            describe(&group)
        })
        .collect();
    groups.sort_by_key(|g| g.title.to_lowercase());
    groups
}

fn describe(group: &[Item]) -> DuplicateGroup {
    let members = members(group);
    let a = merge::analyse(&members);
    let base = &group[0];
    DuplicateGroup {
        id: base.id.clone(),
        kind: if a.identical() {
            ClashKind::Identical
        } else {
            ClashKind::Differs
        },
        title: base.title.clone(),
        username: base.username.clone(),
        url: group.iter().find_map(|i| i.urls.first()).cloned(),
        item_ids: group.iter().map(|i| i.id.clone()).collect(),
        items: group
            .iter()
            .map(|i| MergeChoice {
                id: i.id.clone(),
                source: MergeSource::Vault,
                label: i.title.clone(),
                modified_at: i.updated_at,
                is_default: i.id == base.id,
            })
            .collect(),
        password_choices: a.password_choices(&members),
        totp_choices: a.totp_choices(&members),
        title_choices: a.title_choices(&members),
        differs: a.differs,
        default_decision: ImportDecision::default_merge(),
    }
}

/// Merges the items `ids` into the first one (its id stays; the others are deleted) as `decision`
/// says (choice ids are item ids). `Skip` and `KeepBoth` change nothing and return `None`. The
/// caller saves and syncs afterwards.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn merge_items(
    vault: Arc<Vault>,
    ids: Vec<String>,
    decision: ImportDecision,
) -> Result<Option<Item>> {
    if !matches!(decision, ImportDecision::Merge { .. }) {
        return Ok(None);
    }
    let mut items: Vec<Item> = Vec::with_capacity(ids.len());
    for id in &ids {
        if items.iter().any(|i| &i.id == id) {
            continue;
        }
        let item = vault
            .get(id.clone())
            .ok_or_else(|| PassError::NotFound(tr!("vault.no_item")))?;
        items.push(item);
    }
    if items.len() < 2 {
        return Err(PassError::InvalidInput(tr!("merge.choose_two")));
    }
    if items.iter().any(|i| i.kind != items[0].kind) {
        return Err(PassError::InvalidInput(tr!("merge.different_kinds")));
    }
    let merged = merge::merge(&members(&items), &decision, crate::now_ms());
    let saved = vault.upsert(merged)?;
    for item in &items[1..] {
        // Everything it had is in the merged item: no copy in the trash.
        vault.delete_permanently(item.id.clone())?;
    }
    Ok(Some(saved))
}
