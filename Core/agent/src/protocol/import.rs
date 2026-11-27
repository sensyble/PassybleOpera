//! `items.import`: moves the vault the browser extension kept in the browser into this app.
//!
//! The extension sends the encrypted vault file and its key. The file is opened in memory, never
//! written to disk, and every live item that isn't an exact duplicate is added as a new item. It
//! only adds, so it asks nothing.

use std::collections::HashSet;

use pass_core::{b64url_decode, Item, ItemKind, Vault};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{read_only, vault_json, ErrorCode, RpcError, RpcResult};
use crate::Agent;

/// The browser vault file, decoded (the native host takes at most 8 MiB per message, base64url).
const MAX_FILE: usize = 6 * 1024 * 1024;
/// At most this many items per move (a browser vault is far smaller).
const MAX_ITEMS: usize = 20_000;
/// At most this many items named in `failed`.
const MAX_FAILED: usize = 50;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ImportParams {
    /// The browser vault's encrypted file (base64url).
    file: String,
    /// Its vault key (base64url), from the browser vault opened with its master password.
    key: String,
    /// The vault the items go into (an id from a `vaults` table); default the home vault.
    #[serde(default)]
    vault: Option<String>,
}

fn invalid(message: impl Into<String>) -> RpcError {
    RpcError::new(ErrorCode::InvalidParams, message)
}

/// A website's comparison key: its host, lower case, without `www.` (a bare host counts too).
fn host_key(url: &str) -> Option<String> {
    let url = url.trim();
    let parsed = url::Url::parse(url)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https"))
        .or_else(|| {
            (!url.contains("://"))
                .then(|| url::Url::parse(&format!("https://{url}")).ok())
                .flatten()
        })?;
    let host = parsed
        .host_str()?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    Some(host.strip_prefix("www.").unwrap_or(&host).to_string())
}

fn hosts(item: &Item) -> HashSet<String> {
    item.urls.iter().filter_map(|u| host_key(u)).collect()
}

/// The same site: a website in common, or, both without one, the same title.
fn same_site(a: &Item, b: &Item) -> bool {
    let (ha, hb) = (hosts(a), hosts(b));
    if ha.is_empty() && hb.is_empty() {
        return a.title.trim().eq_ignore_ascii_case(b.title.trim());
    }
    !ha.is_disjoint(&hb)
}

fn totp_key(totp: Option<&str>) -> Option<String> {
    let t = totp.map(str::trim).filter(|t| !t.is_empty())?;
    Some(
        pass_core::totp_parse(t.to_string())
            .map(|c| pass_core::b64url_encode(c.secret))
            .unwrap_or_else(|_| t.to_string()),
    )
}

/// `incoming` adds nothing to `here`: no other 2FA secret, no passkey `here` lacks, no other notes.
fn brings_nothing_new(incoming: &Item, here: &Item) -> bool {
    let totp = totp_key(incoming.totp.as_deref());
    let totp_ok = totp.is_none() || totp == totp_key(here.totp.as_deref());
    let passkeys_ok = incoming.passkeys.iter().all(|p| {
        here.passkeys
            .iter()
            .any(|h| h.credential_id == p.credential_id)
    });
    let notes = incoming.notes.trim();
    let notes_ok = notes.is_empty() || notes == here.notes.trim();
    totp_ok && passkeys_ok && notes_ok
}

/// What two items are compared on: everything but their id, times, favorite flag, password
/// history and tags.
fn content(item: &Item) -> Value {
    let plain = Item {
        id: String::new(),
        created_at: 0,
        updated_at: 0,
        favorite: false,
        password_changed_at: 0,
        password_history: Vec::new(),
        tags: Vec::new(),
        trashed_at: None,
        ..item.clone()
    };
    serde_json::to_value(plain).unwrap_or(Value::Null)
}

/// An exact duplicate of `incoming` is in `existing` already.
fn is_duplicate(existing: &[Item], incoming: &Item) -> bool {
    match incoming.kind {
        ItemKind::Login => existing.iter().any(|here| {
            here.kind == ItemKind::Login
                && here.password == incoming.password
                && here
                    .username
                    .trim()
                    .eq_ignore_ascii_case(incoming.username.trim())
                && same_site(incoming, here)
                && brings_nothing_new(incoming, here)
        }),
        _ => {
            let wanted = content(incoming);
            existing
                .iter()
                .any(|here| here.kind == incoming.kind && content(here) == wanted)
        }
    }
}

/// A copy of `item` to add as a new item: no id (the vault gives one), out of the trash.
fn fresh_copy(item: &Item) -> Item {
    Item {
        id: String::new(),
        trashed_at: None,
        ..item.clone()
    }
}

impl Agent {
    /// `items.import`: adds every live item of the browser vault file to `vault` (default the
    /// home vault). Counts once against the edit limit.
    pub(super) fn rpc_items_import(&self, p: ImportParams) -> RpcResult {
        let opened = self.opened_or_locked()?;
        self.edit_rate()?;
        let file = b64url_decode(p.file.trim().to_string())
            .map_err(|_| invalid("This is not a Passyble vault file"))?;
        if file.is_empty() || file.len() > MAX_FILE {
            return Err(invalid("This is not a Passyble vault file"));
        }
        let key = b64url_decode(p.key.trim().to_string()).map_err(|_| invalid("Bad vault key"))?;
        let source =
            Vault::unlock_with_key(file, key, "browser-move".into()).map_err(|e| match e {
                pass_core::PassError::InvalidPassword => RpcError::new(
                    ErrorCode::WrongPassword,
                    "This key doesn't open the vault file",
                ),
                _ => invalid("This is not a Passyble vault file"),
            })?;
        let id = match p.vault.as_deref().filter(|v| !v.is_empty()) {
            Some(id) => id.to_string(),
            None => opened
                .0
                .iter()
                .find(|(r, _)| r.home)
                .map(|(r, _)| r.id.clone())
                .ok_or_else(read_only)?,
        };
        let (vault_ref, vault) = opened
            .by_id(&id)
            .cloned()
            .ok_or_else(|| RpcError::new(ErrorCode::NotFound, "that vault isn't open"))?;
        if !vault_ref.can_edit {
            return Err(read_only());
        }
        let incoming = source.items();
        if incoming.len() > MAX_ITEMS {
            return Err(invalid("Too many items to move at once"));
        }
        let mut existing = vault.items();
        let (mut added, mut skipped) = (0usize, 0usize);
        let mut failed: Vec<Value> = Vec::new();
        let mut failures = 0usize;
        for item in &incoming {
            if is_duplicate(&existing, item) {
                skipped += 1;
                continue;
            }
            match vault.upsert(fresh_copy(item)) {
                Ok(saved) => {
                    added += 1;
                    existing.push(saved);
                }
                Err(e) => {
                    failures += 1;
                    if failed.len() < MAX_FAILED {
                        failed.push(json!({
                            "title": item.title.chars().take(256).collect::<String>(),
                            "kind": item.kind.as_str(),
                            "message": e.to_string(),
                        }));
                    }
                }
            }
        }
        if added > 0 {
            self.edited()?;
        }
        Ok(json!({
            "total": incoming.len(),
            "added": added,
            "skipped": skipped,
            "failed_count": failures,
            "failed": failed,
            "vault": vault_json(&vault_ref),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(site: &str, user: &str, pw: &str) -> Item {
        Item {
            title: site.into(),
            username: user.into(),
            password: pw.into(),
            urls: vec![format!("https://{site}/")],
            ..Default::default()
        }
    }

    #[test]
    fn a_login_with_the_same_site_username_and_password_is_a_duplicate() {
        let here = vec![login("www.github.com", "Ann", "pw")];
        assert!(is_duplicate(&here, &login("github.com", "ann ", "pw")));
        assert!(!is_duplicate(&here, &login("github.com", "ann", "other")));
        assert!(!is_duplicate(&here, &login("gitlab.com", "ann", "pw")));
        assert!(!is_duplicate(&here, &login("github.com", "bob", "pw")));
        // It brings a 2FA secret or notes the login here lacks: moved, nothing is lost.
        let with_totp = Item {
            totp: Some("JBSWY3DPEHPK3PXP".into()),
            ..login("github.com", "ann", "pw")
        };
        assert!(!is_duplicate(&here, &with_totp));
        let with_notes = Item {
            notes: "recovery codes".into(),
            ..login("github.com", "ann", "pw")
        };
        assert!(!is_duplicate(&here, &with_notes));
    }

    #[test]
    fn other_kinds_are_duplicates_only_with_the_same_content() {
        let note = Item {
            kind: ItemKind::Note,
            title: "Wi-Fi".into(),
            notes: "hunter2".into(),
            ..Default::default()
        };
        let here = vec![Item {
            id: "x".into(),
            created_at: 5,
            favorite: true,
            ..note.clone()
        }];
        assert!(is_duplicate(&here, &note));
        let other = Item {
            notes: "hunter3".into(),
            ..note.clone()
        };
        assert!(!is_duplicate(&here, &other));
    }
}
