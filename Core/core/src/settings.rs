//! Settings kept inside the vault, encrypted and synced with it (such as the e-mail alias
//! services' API tokens). One blob sealed next to the items, so a change never touches an item's
//! version. Each key merges last-writer-wins and a removed key stays as a tombstone so the removal
//! syncs. Older clients drop the blob when they write the file; devices that have it upload it again.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// One setting and its version.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SettingEntry {
    /// `None`: removed (a tombstone).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub updated_at: i64,
    pub device_id: String,
}

impl SettingEntry {
    fn version(&self) -> (i64, &str, Option<&str>) {
        (self.updated_at, &self.device_id, self.value.as_deref())
    }
}

impl Drop for SettingEntry {
    fn drop(&mut self) {
        if let Some(v) = self.value.as_mut() {
            v.zeroize();
        }
    }
}

/// The sealed contents of the settings blob.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(crate) struct VaultSettings {
    #[serde(default)]
    pub entries: BTreeMap<String, SettingEntry>,
}

/// Values can be API tokens: never in debug output.
impl std::fmt::Debug for VaultSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultSettings")
            .field("keys", &self.entries.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// Longest key and value [`VaultSettings::set`] accepts.
pub(crate) const MAX_KEY_LEN: usize = 64;
pub(crate) const MAX_VALUE_LEN: usize = 16 * 1024;

/// Keys are short lowercase names: `[a-z0-9._-]`.
pub(crate) fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= MAX_KEY_LEN
        && key.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

impl VaultSettings {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).and_then(|e| e.value.as_deref())
    }

    /// The keys that have a value, starting with `prefix`.
    pub fn keys_with_prefix<'a>(&'a self, prefix: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.entries
            .iter()
            .filter(move |(k, e)| k.starts_with(prefix) && e.value.is_some())
            .map(|(k, _)| k.as_str())
    }

    /// Sets (or with `None` removes) `key` at version (`at`, `device_id`). `false` when that
    /// changes nothing (the same value, or removing what isn't there).
    pub fn set(&mut self, key: &str, value: Option<String>, at: i64, device_id: &str) -> bool {
        let current = self.entries.get(key);
        if current.map(|e| e.value.as_deref()) == Some(value.as_deref())
            || (current.is_none() && value.is_none())
        {
            return false;
        }
        self.entries.insert(
            key.to_string(),
            SettingEntry {
                value,
                updated_at: at,
                device_id: device_id.to_string(),
            },
        );
        true
    }

    /// Per key, the later version (then the greater device id, then the greater value, so every
    /// device picks the same one). Commutative and idempotent.
    pub fn merge(&mut self, other: &VaultSettings) {
        for (key, theirs) in &other.entries {
            match self.entries.get(key) {
                Some(ours) if ours.version() >= theirs.version() => {}
                _ => {
                    self.entries.insert(key.clone(), theirs.clone());
                }
            }
        }
    }

    /// The latest version of any entry (0 if none), for the vault's clock.
    pub fn latest(&self) -> i64 {
        self.entries
            .values()
            .map(|e| e.updated_at)
            .max()
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        assert!(valid_key("alias.simplelogin"));
        assert!(valid_key("email"));
        for bad in ["", "Alias", "a b", "a/b", &"x".repeat(65)] {
            assert!(!valid_key(bad), "{bad}");
        }
    }

    #[test]
    fn set_and_merge_per_key() {
        let mut a = VaultSettings::default();
        assert!(a.set("x", Some("1".into()), 10, "a"));
        assert!(!a.set("x", Some("1".into()), 11, "a"));
        assert!(!a.set("gone", None, 11, "a"));
        let mut b = VaultSettings::default();
        b.set("y", Some("2".into()), 12, "b");
        b.set("x", Some("old".into()), 5, "b");

        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);
        assert_eq!(ab, ba);
        assert_eq!(ab.get("x"), Some("1"));
        assert_eq!(ab.get("y"), Some("2"));
        let mut again = ab.clone();
        again.merge(&ab);
        assert_eq!(again, ab);

        assert!(b.set("y", None, 20, "b"));
        ab.merge(&b);
        assert_eq!(ab.get("y"), None);
        assert_eq!(ab.keys_with_prefix("").collect::<Vec<_>>(), vec!["x"]);
        assert_eq!(ab.latest(), 20);
    }

    #[test]
    fn debug_hides_values() {
        let mut s = VaultSettings::default();
        s.set("alias.duckduckgo", Some("secret-token".into()), 1, "d");
        let text = format!("{s:?}");
        assert!(text.contains("alias.duckduckgo"));
        assert!(!text.contains("secret-token"));
    }
}
