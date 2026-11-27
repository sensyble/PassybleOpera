//! Field-by-field merge of two versions of one item. Each version carries sealed metadata
//! ([`ItemMeta`]): a stamp per part and a version vector, enough for a three-way merge without the
//! common ancestor. When both sides changed a part, the newer value wins and the other stays
//! reachable (password history, joined lists or a conflict copy). Any sync order converges.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::model::{Item, PasswordHistoryEntry, MAX_PASSWORD_HISTORY};

/// A write's version: the `(updated_at, device_id)` of the `upsert` that set a value.
pub(crate) type Stamp = (i64, String);

/// The key of [`ItemMeta`] in a sealed item's JSON. Older clients ignore it, and drop it when
/// they re-seal the item after an edit (their version then carries none).
pub(crate) const META_KEY: &str = "merge";

/// First character of the device id of a version made by a merge ([`join`]) and of the stamp of a
/// value a merge made ([`joined_stamp`]). It sorts before every real device id, so at the same
/// `updated_at` the merge loses to a tombstone or an edit (the deletion of a version deletes the
/// merges made of it, as it deletes that version).
const MERGE_MARK: char = '\u{1}';

/// First character of the device id of a conflict copy's version ([`conflict_copy`]).
const COPY_MARK: char = '\u{2}';

/// What a conflict copy's title gets. Not translated: every device makes the same copy, so its
/// contents can't depend on the language of the device that made it.
pub(crate) const CONFLICT_SUFFIX: &str = " (conflict)";

/// The password part: the password with when it was set and the history of earlier ones.
const PASSWORD: &str = "password";
/// Object fields whose own fields are parts of their own (`card.number`, `identity.email`); the
/// object's name is a part too, holding whether it is there at all.
const NESTED: [&str; 2] = ["card", "identity"];
/// Lists whose concurrent changes are joined (nothing either side added is dropped). Entries are
/// told apart by [`entry_key`]: for the same entry, the kept side's version wins.
const LISTS: [&str; 6] = [
    "urls",
    "url_rules",
    "android_apps",
    "passkeys",
    "tags",
    "fields",
];
/// Parts whose losing value is no data worth a copy: the newer value is simply kept. (Whether an
/// item has a card or identity at all is one of them: its fields are parts of their own, and a
/// field that would be left without its card is handled by [`canonicalize`].)
const NO_COPY: [&str; 4] = ["favorite", "trashed_at", "card", "identity"];

/// Merge metadata of one item version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ItemMeta {
    /// The version this belongs to. A version whose metadata names another version (an older
    /// client that re-sealed the JSON as it found it under a new version) is merged by the
    /// whole-item rule instead.
    pub v: Stamp,
    /// The stamp of every part not listed in `f`.
    pub d: Stamp,
    /// Parts whose stamp differs from `d`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub f: BTreeMap<String, Stamp>,
    /// For each device, the newest of its writes this version includes.
    pub s: BTreeMap<String, i64>,
}

/// Bounds on what a sealed [`ItemMeta`] may hold (a damaged one is ignored, not trusted).
const MAX_ENTRIES: usize = 4096;

impl ItemMeta {
    /// The metadata of a new item, written at `stamp`: every part set by that write.
    pub(crate) fn new_item(stamp: Stamp) -> ItemMeta {
        ItemMeta {
            s: BTreeMap::from([(stamp.1.clone(), stamp.0)]),
            v: stamp.clone(),
            d: stamp,
            f: BTreeMap::new(),
        }
    }

    /// The metadata of the version `new` that a write at `stamp` makes on top of `prev`: the
    /// parts it changed get `stamp`, the others keep theirs. A previous version without metadata
    /// (an older client's, a conflict copy) counts as one write that set every part.
    pub(crate) fn after_edit(
        prev: &Item,
        prev_meta: Option<&ItemMeta>,
        prev_version: (i64, &str),
        new: &Item,
        stamp: Stamp,
    ) -> ItemMeta {
        let base = match prev_meta {
            Some(meta) => meta.clone(),
            None => ItemMeta::new_item((prev_version.0, prev_version.1.to_string())),
        };
        let (old, now) = (parts(prev), parts(new));
        let mut f = base.f;
        for name in old.keys().chain(now.keys()) {
            if old.get(name) != now.get(name) {
                f.insert(name.clone(), stamp.clone());
            }
        }
        f.retain(|_, s| *s != base.d);
        let mut s = base.s;
        let seen = s.entry(stamp.1.clone()).or_insert(stamp.0);
        *seen = (*seen).max(stamp.0);
        ItemMeta {
            v: stamp,
            d: base.d,
            f,
            s,
        }
    }

    /// Whether this metadata belongs to `version` and is consistent (every stamp is within its
    /// own context, nothing is newer than the version itself).
    pub(crate) fn valid_for(&self, version: (i64, &str)) -> bool {
        self.v.0 == version.0
            && self.v.1 == version.1
            && self.s.len() <= MAX_ENTRIES
            && self.f.len() <= MAX_ENTRIES
            && self.s.values().all(|&t| t <= version.0)
            && self.has_seen(&self.d)
            && self.f.values().all(|s| self.has_seen(s))
    }

    fn stamp(&self, part: &str) -> &Stamp {
        self.f.get(part).unwrap_or(&self.d)
    }

    /// Whether this version includes the write `stamp`.
    fn has_seen(&self, stamp: &Stamp) -> bool {
        self.s.get(&stamp.1).is_some_and(|&t| t >= stamp.0)
    }
}

/// One side of a [`join`]: a live item version with its metadata.
pub(crate) struct Side<'a> {
    pub version: (i64, &'a str),
    pub item: &'a Item,
    pub meta: &'a ItemMeta,
}

/// Which version a [`join`] keeps.
pub(crate) enum Joined {
    /// The left side as it is (it already has everything the right side has).
    Left,
    /// The right side as it is.
    Right,
    /// A new version made of both, with its metadata (`meta.v` is its version).
    New { item: Box<Item>, meta: ItemMeta },
}

/// A conflict copy to add: the losing version of an item kept as an item of its own.
pub(crate) struct ConflictCopy {
    pub id: String,
    pub version: Stamp,
    pub item: Item,
}

pub(crate) struct Outcome {
    pub joined: Joined,
    pub copies: Vec<ConflictCopy>,
}

/// The parts of `item`: each top-level field, each field of a card or identity, and the password
/// with its history. Absent ones are left out.
fn parts(item: &Item) -> BTreeMap<String, Value> {
    let Ok(Value::Object(mut obj)) = serde_json::to_value(item) else {
        return BTreeMap::new();
    };
    for key in ["id", "updated_at", "created_at"] {
        obj.remove(key);
    }
    let mut out = BTreeMap::new();
    let mut password = Map::new();
    for key in ["password", "password_changed_at", "password_history"] {
        if let Some(v) = obj.remove(key).filter(|v| !v.is_null()) {
            password.insert(key.into(), v);
        }
    }
    out.insert(PASSWORD.to_string(), Value::Object(password));
    for (key, value) in obj {
        if value.is_null() {
            continue;
        }
        if NESTED.contains(&key.as_str()) {
            if let Value::Object(fields) = value {
                for (field, v) in fields.into_iter().filter(|(_, v)| !v.is_null()) {
                    out.insert(format!("{key}.{field}"), v);
                }
                out.insert(key, Value::Bool(true));
                continue;
            }
        }
        out.insert(key, value);
    }
    out
}

/// The item made of `parts` ([`parts`] reversed). `None` if they don't make an item (a damaged
/// value), which makes the caller fall back to the whole-item rule.
fn rebuild(
    id: &str,
    created_at: i64,
    updated_at: i64,
    parts: &BTreeMap<String, Value>,
) -> Option<Item> {
    let mut obj = Map::new();
    let mut nested: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    for (name, value) in parts {
        if name == PASSWORD {
            if let Value::Object(password) = value {
                obj.extend(password.clone());
            }
            continue;
        }
        if let Some((outer, field)) = name.split_once('.') {
            if NESTED.contains(&outer) {
                nested
                    .entry(outer.to_string())
                    .or_default()
                    .insert(field.to_string(), value.clone());
                continue;
            }
        }
        if NESTED.contains(&name.as_str()) {
            nested.entry(name.clone()).or_default();
            continue;
        }
        obj.insert(name.clone(), value.clone());
    }
    for (outer, fields) in nested {
        if parts.get(&outer) == Some(&Value::Bool(true)) {
            obj.insert(outer, Value::Object(fields));
        }
    }
    obj.insert("id".into(), id.into());
    obj.insert("created_at".into(), created_at.into());
    obj.insert("updated_at".into(), updated_at.into());
    serde_json::from_value(Value::Object(obj)).ok()
}

/// The password part as typed fields (serialized exactly as `Item` serializes them).
#[derive(Default, Serialize, Deserialize)]
struct PasswordPart {
    #[serde(default)]
    password: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    password_changed_at: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    password_history: Vec<PasswordHistoryEntry>,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

fn password_part(v: Option<&Value>) -> PasswordPart {
    v.and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default()
}

/// The password `kept` with the history of both sides, and the `other` side's own password (set
/// by the write `other_stamp`) when it differs: nothing either side had is dropped. One entry per
/// password (its latest date), newest first, then by password, at most [`MAX_PASSWORD_HISTORY`],
/// so the result doesn't depend on the order of the sides or of earlier merges.
fn join_passwords(
    kept: Option<&Value>,
    other: Option<&Value>,
    other_stamp: &Stamp,
) -> Option<Value> {
    let (kept, other) = (password_part(kept), password_part(other));
    let mut dates: BTreeMap<String, i64> = BTreeMap::new();
    let mut add = |password: &str, at: i64| {
        if !password.is_empty() {
            let date = dates.entry(password.to_string()).or_insert(at);
            *date = (*date).max(at);
        }
    };
    for h in kept
        .password_history
        .iter()
        .chain(other.password_history.iter())
    {
        add(&h.password, h.replaced_at);
    }
    if other.password != kept.password {
        let set_at = if other.password_changed_at > 0 {
            other.password_changed_at
        } else {
            other_stamp.0
        };
        add(&other.password, set_at);
    }
    dates.remove(&kept.password);
    let mut history: Vec<PasswordHistoryEntry> = dates
        .into_iter()
        .map(|(password, replaced_at)| PasswordHistoryEntry {
            password,
            replaced_at,
        })
        .collect();
    history.sort_by(|a, b| {
        b.replaced_at
            .cmp(&a.replaced_at)
            .then_with(|| a.password.cmp(&b.password))
    });
    history.truncate(MAX_PASSWORD_HISTORY);
    serde_json::to_value(PasswordPart {
        password_history: history,
        ..kept
    })
    .ok()
}

/// `kept`'s entries, then the `other` list's entries it lacks (passkeys by credential id, other
/// lists by value), in their order.
fn join_lists(name: &str, kept: Option<&Value>, other: Option<&Value>) -> Option<Value> {
    let list = |v: Option<&Value>| match v {
        Some(Value::Array(a)) => a.clone(),
        _ => Vec::new(),
    };
    let mut out = list(kept);
    for entry in list(other) {
        if !out
            .iter()
            .any(|e| entry_key(name, e) == entry_key(name, &entry))
        {
            out.push(entry);
        }
    }
    (!out.is_empty()).then_some(Value::Array(out))
}

/// What tells two entries of list `name` apart: a passkey by its credential, a website's rule by
/// its website, a linked app by its package and certificate (not whether it is hidden), anything
/// else by its whole value.
fn entry_key(name: &str, v: &Value) -> Value {
    let field = |key: &str| v.get(key).cloned().unwrap_or(Value::Null);
    match name {
        "passkeys" => field("credential_id"),
        "url_rules" => field("url"),
        "android_apps" => Value::Array(vec![field("package"), field("cert_sha256")]),
        _ => v.clone(),
    }
}

/// A total order on part values, to choose between two values with the same stamp (which only
/// happens when [`canonicalize`] dropped a card or identity field, or after a damaged write).
fn value_key(v: Option<&Value>) -> String {
    v.map(Value::to_string).unwrap_or_default()
}

/// The stamp of a value that a merge made of two others (two password histories or two lists
/// joined), newer than both and recorded in the merged version's context. A later edit made on
/// top of either original value hasn't seen it, so it is concurrent and joined in turn: nothing
/// the merge added is dropped. Derived from the value, so two devices that make the same join
/// make the same stamp.
fn joined_stamp(name: &str, value: Option<&Value>, after: i64) -> Stamp {
    let digest = Sha256::new()
        .chain_update(name.as_bytes())
        .chain_update([0])
        .chain_update(value_key(value).as_bytes())
        .finalize();
    (
        after.saturating_add(1),
        format!("{MERGE_MARK}{}", crate::encoding::hex(&digest[..8])),
    )
}

/// The metadata of a rescue version (`RESCUE_MARK` in vault.rs), which keeps a losing
/// version's passwords in the history of the version `meta` belongs to: that metadata for
/// `version`, with the password part, whose history the rescue changed, under a stamp of its own
/// ([`joined_stamp`]).
pub(crate) fn rescued(meta: &ItemMeta, item: &Item, version: Stamp) -> ItemMeta {
    let mut meta = meta.clone();
    let stamp = joined_stamp(
        PASSWORD,
        parts(item).get(PASSWORD),
        version.0.saturating_sub(1),
    );
    let seen = meta.s.entry(stamp.1.clone()).or_insert(stamp.0);
    *seen = (*seen).max(stamp.0);
    meta.f.insert(PASSWORD.to_string(), stamp);
    meta.v = version;
    meta
}

/// The merged value and stamp of one part, and whether it was a conflict: both sides changed
/// it concurrently to different values, and the value not kept is data a copy must keep.
fn join_part(
    name: &str,
    (vl, sl, l): (Option<&Value>, &Stamp, &ItemMeta),
    (vr, sr, r): (Option<&Value>, &Stamp, &ItemMeta),
) -> (Option<Value>, Stamp, bool) {
    if vl == vr {
        return (vl.cloned(), sl.max(sr).clone(), false);
    }
    let joined = |value: Option<Value>| {
        let stamp = if value.as_ref() == vl {
            sl.clone()
        } else if value.as_ref() == vr {
            sr.clone()
        } else {
            joined_stamp(name, value.as_ref(), sl.0.max(sr.0))
        };
        (value, stamp, false)
    };
    // Which side wins: the newer write; for one write that two versions hold differently, the
    // greater value (a total order, so both devices choose alike).
    let left_wins = if sl == sr {
        value_key(vl) > value_key(vr)
    } else {
        sl > sr
    };
    let (kept, kept_stamp, kept_meta, other, other_stamp) = if left_wins {
        (vl, sl, l, vr, sr)
    } else {
        (vr, sr, r, vl, sl)
    };
    if name == PASSWORD {
        // The newer password, and the histories joined even after a later edit made on top of the
        // other value: no client ever removes a history entry, and two processes of one device (an
        // app and its AutoFill extension) share a device id, so the context can take an edit made
        // on a stale copy for one made on top of the other. For a true later edit the join changes
        // nothing (`upsert` put the replaced password into the history).
        return joined(join_passwords(kept, other, other_stamp));
    }
    if sl != sr && kept_meta.has_seen(other_stamp) {
        // A later edit made on top of the other value: it simply replaces it.
        return (kept.cloned(), kept_stamp.clone(), false);
    }
    // Concurrent: both sides changed this part without seeing each other's change.
    if LISTS.contains(&name) {
        joined(join_lists(name, kept, other))
    } else {
        (kept.cloned(), kept_stamp.clone(), !NO_COPY.contains(&name))
    }
}

/// Gives merged parts the shape `Item::normalize` gives an item, which is also the shape that
/// reads back the same from the file: a card only on a card, an identity only on an identity (a
/// secure note with a card would read back as a card). Fields dropped that way (one device
/// changed the item's kind while another edited its card) are conflicts like any other.
fn canonicalize(merged: &mut BTreeMap<String, Value>, conflicts: &mut BTreeSet<String>) {
    let kind = merged
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("login")
        .to_string();
    for outer in NESTED {
        if kind == outer {
            merged.insert(outer.to_string(), Value::Bool(true));
            continue;
        }
        merged.remove(outer);
        let prefix = format!("{outer}.");
        let dropped: Vec<String> = merged
            .keys()
            .filter(|name| name.starts_with(&prefix))
            .cloned()
            .collect();
        for name in dropped {
            merged.remove(&name);
            conflicts.insert(name);
        }
    }
}

/// Merges two live versions of item `id` part by part. `None` if the parts don't make an item,
/// so the caller falls back to the whole-item rule.
pub(crate) fn join(id: &str, l: &Side<'_>, r: &Side<'_>) -> Option<Outcome> {
    let (pl, pr) = (parts(l.item), parts(r.item));
    let names: BTreeSet<&String> = pl
        .keys()
        .chain(pr.keys())
        .chain(l.meta.f.keys())
        .chain(r.meta.f.keys())
        .collect();
    let d = l.meta.d.clone().max(r.meta.d.clone());
    let mut merged: BTreeMap<String, Value> = BTreeMap::new();
    let mut f: BTreeMap<String, Stamp> = BTreeMap::new();
    let mut conflicts: BTreeSet<String> = BTreeSet::new();
    for name in names {
        let (value, stamp, conflict) = join_part(
            name,
            (pl.get(name), l.meta.stamp(name), l.meta),
            (pr.get(name), r.meta.stamp(name), r.meta),
        );
        if conflict {
            conflicts.insert(name.clone());
        }
        if let Some(value) = value {
            merged.insert(name.clone(), value);
        }
        if stamp != d {
            f.insert(name.clone(), stamp);
        }
    }
    canonicalize(&mut merged, &mut conflicts);
    // A side whose value of a conflicting part didn't make it into the merged item is kept as a
    // conflict copy.
    let lost = |side: &BTreeMap<String, Value>| {
        conflicts
            .iter()
            .any(|name| side.get(name) != merged.get(name))
    };
    let (left_lost, right_lost) = (lost(&pl), lost(&pr));
    // The context: everything either side includes, and the values this merge made.
    let mut s = l.meta.s.clone();
    for (device, &t) in r.meta.s.iter().chain(f.values().map(|(t, d)| (d, t))) {
        let seen = s.entry(device.clone()).or_insert(t);
        *seen = (*seen).max(t);
    }
    let created_at = match (l.item.created_at, r.item.created_at) {
        (a, b) if a > 0 && b > 0 => a.min(b),
        (a, b) => a.max(b),
    };
    let same_as = |side: &Side<'_>, side_parts: &BTreeMap<String, Value>| {
        *side_parts == merged
            && side.item.created_at == created_at
            && side.meta.d == d
            && side.meta.f == f
            && side.meta.s == s
    };
    let joined = match (same_as(l, &pl), same_as(r, &pr)) {
        // The same contents under two versions (two devices merged the same edits in different
        // orders): both keep the greater version.
        (true, true) if r.version > l.version => Joined::Right,
        (true, _) => Joined::Left,
        (false, true) => Joined::Right,
        (false, false) => {
            let digest = Sha256::new()
                .chain_update(serde_json::to_vec(&(&merged, created_at, &d, &f, &s)).ok()?)
                .finalize();
            let version = (
                l.version.0.max(r.version.0).saturating_add(1),
                format!("{MERGE_MARK}{}", crate::encoding::hex(&digest[..8])),
            );
            let item = Box::new(rebuild(id, created_at, version.0, &merged)?);
            Joined::New {
                item,
                meta: ItemMeta {
                    v: version,
                    d,
                    f,
                    s,
                },
            }
        }
    };
    let mut copies = Vec::new();
    if left_lost && !matches!(joined, Joined::Left) {
        copies.push(conflict_copy(id, l));
    }
    if right_lost && !matches!(joined, Joined::Right) {
        copies.push(conflict_copy(id, r));
    }
    Some(Outcome { joined, copies })
}

/// The conflict copy of `loser`, a version of item `id` that lost a concurrent change of a field:
/// that version as an item of its own, titled "… (conflict)". Its id and version come from `id`
/// and the losing version, so every device that sees the same conflict makes the same copy (and
/// a copy the user deleted stays deleted: its tombstone is newer). A copy carries no merge
/// metadata: until someone edits it, it merges by the whole-item rule.
fn conflict_copy(id: &str, loser: &Side<'_>) -> ConflictCopy {
    let digest = Sha256::new()
        .chain_update(b"pass/conflict-copy/v1:")
        .chain_update(
            serde_json::to_vec(&(id, loser.version.0, loser.version.1)).unwrap_or_default(),
        )
        .finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // A UUID like any other item id (version 8: custom).
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let copy_id = uuid::Uuid::from_bytes(bytes).to_string();
    let mut item = loser.item.clone();
    item.id = copy_id.clone();
    item.title = format!("{}{CONFLICT_SUFFIX}", item.title.trim_end());
    item.updated_at = loser.version.0;
    let content = Sha256::digest(serde_json::to_vec(&item).unwrap_or_default());
    let version = (
        loser.version.0,
        format!("{COPY_MARK}{}", crate::encoding::hex(&content[..8])),
    );
    ConflictCopy {
        id: copy_id,
        version,
        item,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CardData, ItemKind};

    #[test]
    fn parts_rebuild_the_item() {
        let item = Item {
            id: "x".into(),
            kind: ItemKind::Card,
            title: "Visa".into(),
            password: "pw".into(),
            password_changed_at: 5,
            card: Some(CardData {
                number: "4111".into(),
                expiry_month: 3,
                ..Default::default()
            }),
            tags: vec!["Work".into()],
            created_at: 1,
            updated_at: 2,
            ..Default::default()
        };
        let p = parts(&item);
        assert_eq!(p["card"], Value::Bool(true));
        assert_eq!(p["card.number"], "4111");
        assert!(!p.contains_key("card.pin"), "empty values are absent");
        assert_eq!(rebuild("x", 1, 2, &p).unwrap(), item);
        // An empty card is still a card.
        let empty = Item {
            card: Some(CardData::default()),
            ..item.clone()
        };
        assert_eq!(rebuild("x", 1, 2, &parts(&empty)).unwrap(), empty);
    }

    #[test]
    fn metadata_names_its_version_and_stays_consistent() {
        let a = ItemMeta::new_item((10, "a".into()));
        assert!(a.valid_for((10, "a")));
        assert!(!a.valid_for((11, "a")), "another version");
        assert!(!a.valid_for((10, "b")));
        let before = Item::default();
        let after = Item {
            notes: "n".into(),
            ..Default::default()
        };
        let b = ItemMeta::after_edit(&before, Some(&a), (10, "a"), &after, (20, "b".into()));
        assert!(b.valid_for((20, "b")));
        assert_eq!(b.stamp("notes"), &(20, "b".to_string()));
        assert_eq!(b.stamp("title"), &(10, "a".to_string()));
        assert_eq!(b.s, BTreeMap::from([("a".into(), 10), ("b".into(), 20)]));
        let mut forged = b.clone();
        forged.f.insert("title".into(), (15, "c".into()));
        assert!(!forged.valid_for((20, "b")), "a stamp outside the context");
    }
}
