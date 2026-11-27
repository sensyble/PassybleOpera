//! Teams and Family for the browser extension and the secure-send page: shared vaults opened with
//! the keyset in the extension's own vault (the home vault), search and save across vaults,
//! organisation policies and secure send.

use std::sync::Arc;

use pass_agent::{Agent, ErrorCode, RpcError};
use pass_core::{
    multi_default_save_vault, multi_for_url, multi_search, policy_allows_export,
    policy_allows_share, policy_auto_lock_secs, policy_parse, policy_violations,
    public_keys_fingerprint, Item, LocalSecurity, MemberChange, OrgPolicy, PinStatus, PublicKeys,
    SearchIndex, SendContent, SendKind, SendOptions, Vault, VaultSummaries,
};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::host::{BrowserHost, HostResult};

fn parse<T: DeserializeOwned>(what: &str, text: &str) -> Result<T, RpcError> {
    serde_json::from_str(text)
        .map_err(|e| RpcError::new(ErrorCode::InvalidParams, format!("{what}: {e}")))
}

fn value<T: serde::Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap_or(Value::Null)
}

fn policy_of(json: Option<&str>) -> Result<Option<OrgPolicy>, RpcError> {
    json.filter(|j| !j.trim().is_empty())
        .map(policy_parse)
        .transpose()
        .map_err(RpcError::from)
}

// Secure send. The open page needs only these.

/// `sendSeal(data, options)`: `options` is `{"kind": "text" | "file", "name"?, "mime"?,
/// "expires_at", "max_views"?, "password"?}`.
#[derive(Deserialize)]
struct SealOptions {
    kind: SendKind,
    #[serde(default)]
    name: String,
    #[serde(default)]
    mime: String,
    expires_at: i64,
    #[serde(default)]
    max_views: u32,
    #[serde(default)]
    password: Option<String>,
}

/// Encrypts a send: the ciphertext to upload, and `{"meta", "key", "password_auth"}`.
pub fn send_seal(data: Vec<u8>, options: &str) -> Result<(Vec<u8>, Value), RpcError> {
    let options = Zeroizing::new(options.to_string());
    let o: SealOptions = parse("options", &options)?;
    let sealed = pass_core::send_seal(
        SendContent {
            kind: o.kind,
            name: o.name,
            mime: o.mime,
            data,
        },
        SendOptions {
            expires_at: o.expires_at,
            max_views: o.max_views,
            password: o.password.map(|p| Zeroizing::new(p).to_string()),
        },
    )?;
    let meta = json!({
        "meta": sealed.meta,
        "key": sealed.key,
        "password_auth": sealed.password_auth,
    });
    Ok((sealed.ciphertext, meta))
}

/// Opens a send: `{"kind", "name", "mime"}` and the content.
pub fn send_open(
    ciphertext: Vec<u8>,
    meta: &str,
    key: &str,
    password: Option<String>,
) -> Result<(Value, Zeroizing<Vec<u8>>), RpcError> {
    let content = pass_core::send_open(ciphertext, meta.into(), key.into(), password)?;
    let header = json!({
        "kind": content.kind,
        "name": content.name,
        "mime": content.mime,
    });
    Ok((header, Zeroizing::new(content.data.clone())))
}

pub fn send_info(meta: &str) -> HostResult {
    Ok(value(&pass_core::send_info(meta.into())?))
}

pub fn send_password_auth(meta: &str, password: String) -> HostResult {
    Ok(json!({ "auth": pass_core::send_password_auth(meta.into(), password)? }))
}

pub fn send_link(base: &str, send_id: &str, key: &str) -> HostResult {
    Ok(json!({ "link": pass_core::send_link(base, send_id, key)? }))
}

pub fn send_parse_link(link: &str) -> HostResult {
    let parsed = pass_core::send_parse_link(link)?;
    Ok(json!({ "send_id": parsed.send_id, "key": parsed.key }))
}

// Policies.

/// `[{"rule", "message"}]` for `local` (`{"master_password_score"?, "auto_lock_secs"?,
/// "two_step_enabled"}`) under `policy` (the account service's JSON).
pub fn policy_check(policy: &str, local: &str) -> HostResult {
    let policy = policy_parse(policy)?;
    let local: LocalSecurity = parse("local", local)?;
    Ok(value(&policy_violations(policy, local)))
}

/// What `policy` (absent: no organisation) allows: `{"export", "sharing_outside",
/// "auto_lock_secs"}`, the last for the user's `chosen` auto-lock.
pub fn policy_allows(policy: Option<&str>, chosen_auto_lock_secs: Option<u64>) -> HostResult {
    let policy = policy_of(policy)?;
    Ok(json!({
        "export": policy_allows_export(policy.clone()),
        "sharing_outside": policy_allows_share(policy.clone(), false),
        "auto_lock_secs": policy_auto_lock_secs(policy.unwrap_or_default(), chosen_auto_lock_secs),
    }))
}

// Search and save across vaults.

/// `groups`: a JSON array of `VaultSummaries` (`{"vault_id", "shared", "role", "can_edit",
/// "can_reveal", "summaries"}`), from `summaries()` of the home vault and each `SharedVault`.
pub fn multi_search_json(groups: &str, query: &str) -> HostResult {
    let groups: Vec<VaultSummaries> = parse("groups", groups)?;
    Ok(value(&multi_search(groups, query.into())))
}

pub fn multi_for_url_json(groups: &str, url: &str) -> HostResult {
    let groups: Vec<VaultSummaries> = parse("groups", groups)?;
    Ok(value(&multi_for_url(groups, url.into())))
}

/// A [`SearchIndex`] of `groups` (as [`multi_search_json`] takes them), read once for many
/// keystrokes and pages.
pub fn search_index(groups: &str) -> Result<Arc<SearchIndex>, RpcError> {
    let groups: Vec<VaultSummaries> = parse("groups", groups)?;
    Ok(SearchIndex::new(groups, Default::default()))
}

/// [`multi_search_json`] over an index.
pub fn index_search_json(index: &SearchIndex, query: &str) -> HostResult {
    Ok(value(&index.search(query.into())))
}

/// [`multi_for_url_json`] over an index.
pub fn index_for_url_json(index: &SearchIndex, url: &str) -> HostResult {
    Ok(value(&index.for_url(url.into())))
}

/// `{"vault_id": … | null}`: where a new login for `url` is saved by default.
pub fn multi_default_save_vault_json(
    groups: &str,
    url: Option<String>,
    preferred: Option<String>,
) -> HostResult {
    let groups: Vec<VaultSummaries> = parse("groups", groups)?;
    Ok(json!({ "vault_id": multi_default_save_vault(groups, url, preferred) }))
}

/// `{"status": "pinned" | "not_pinned" | "changed", "pinned_fingerprint"?}`.
fn pin_status_json(status: &PinStatus) -> Value {
    match status {
        PinStatus::Pinned => json!({ "status": "pinned" }),
        PinStatus::NotPinned => json!({ "status": "not_pinned" }),
        PinStatus::Changed { pinned_fingerprint } => {
            json!({ "status": "changed", "pinned_fingerprint": pinned_fingerprint })
        }
    }
}

/// `{"valid", "fingerprint"}` of public keys from the account service.
pub fn public_keys_check(keys: &str) -> HostResult {
    let keys: PublicKeys = parse("keys", keys)?;
    Ok(json!({
        "valid": keys.verify().is_ok(),
        "fingerprint": public_keys_fingerprint(keys),
    }))
}

// Shared vaults, with the extension's vault as the home vault.

impl BrowserHost {
    fn home(&self) -> Result<Arc<Vault>, RpcError> {
        self.agent()
            .peek_vault()
            .ok_or_else(|| RpcError::new(ErrorCode::Locked, "The vault is locked"))
    }

    /// The keyset of `account` in this browser's vault, made first if there is none:
    /// `{"public_keys", "fingerprint"}` (upload the public keys to the account service). Then
    /// store `takeSave()`.
    pub fn ensure_keyset(&self, account: &str) -> HostResult {
        let home = self.home()?;
        let keyset = home.ensure_user_keyset(account)?;
        self.agent().save()?;
        Ok(json!({
            "public_keys": keyset.public_keys(),
            "fingerprint": keyset.fingerprint(),
        }))
    }

    /// This browser's vault's list, for searching across vaults with the shared ones.
    pub fn home_summaries(&self) -> HostResult {
        Ok(value(&self.home()?.vault_summaries()))
    }

    /// A string that stays the same while [`BrowserHost::home_summaries`] would: the vault, this
    /// unlock of it, and its [`Vault::list_generation`]. `None` while locked. JavaScript keeps the
    /// summaries (and a [`SearchIndex`]) while it doesn't change, instead of asking for every
    /// summary on every request.
    pub fn home_stamp(&self) -> Option<String> {
        let home = self.home().ok()?;
        Some(format!(
            "{}:{:p}:{}",
            home.vault_id(),
            Arc::as_ptr(&home),
            home.list_generation()
        ))
    }

    /// The contact keys this user verified, kept in this browser's vault (`ContactPin`s).
    pub fn contact_pins(&self) -> HostResult {
        Ok(value(&self.home()?.contact_pins()))
    }

    /// What this user's pins say about `keys` (public keys JSON) in `scope` (`"personal"`):
    /// [`pin_status_json`].
    pub fn contact_pin_status(&self, keys: &str, scope: &str) -> HostResult {
        let keys: PublicKeys = parse("keys", keys)?;
        Ok(pin_status_json(&self.home()?.contact_pin_status(keys, scope)?))
    }

    /// Pins `keys` after the user compared `compared` with the person (refused when it isn't
    /// their fingerprint). The `ContactPin`; this browser's vault is saved.
    pub fn pin_contact(&self, keys: &str, scope: &str, compared: &str) -> HostResult {
        let keys: PublicKeys = parse("keys", keys)?;
        let pin = self.home()?.pin_contact(keys, scope, compared)?;
        self.agent().save()?;
        Ok(value(&pin))
    }

    /// The changes (JSON `MemberChange`s) whose keys this user hasn't verified:
    /// `[{"account", "fingerprint", "status", "pinned_fingerprint"?}]`, empty when all are.
    pub fn unpinned_changes(&self, changes: &str) -> HostResult {
        let changes: Vec<MemberChange> = parse("changes", changes)?;
        let problems: Vec<Value> = self
            .home()?
            .unpinned_changes(changes)
            .into_iter()
            .map(|p| {
                let mut v = pin_status_json(&p.status);
                v["account"] = p.account.into();
                v["fingerprint"] = p.fingerprint.into();
                v
            })
            .collect();
        Ok(Value::Array(problems))
    }

    /// Opens a shared vault's file with `account`'s keyset from this browser's vault, which
    /// remembers the members list it accepted (then store `takeSave()`).
    pub fn open_shared(&self, file: Vec<u8>, account: &str) -> Result<SharedVault, RpcError> {
        let home = self.home()?;
        let vault = Vault::open_shared_with_home(file, &home, account, self.device_id())?;
        self.agent().save()?;
        Ok(SharedVault {
            vault,
            home,
            agent: self.agent().clone(),
        })
    }
}

/// One open shared vault ([`BrowserHost::open_shared`]). The extension keeps its file (IndexedDB,
/// like the home vault's) and syncs it with the server itself.
pub struct SharedVault {
    vault: Arc<Vault>,
    home: Arc<Vault>,
    agent: Arc<Agent>,
}

impl SharedVault {
    pub fn vault(&self) -> &Arc<Vault> {
        &self.vault
    }

    /// `SharedInfo`: members, roles, this account's role, `anchored`, the signer's fingerprint.
    pub fn info(&self) -> HostResult {
        Ok(value(&self.vault.shared_info()))
    }

    /// `VaultSummaries` (no secrets): for the menus, search across vaults and the soft lock.
    pub fn summaries(&self) -> HostResult {
        Ok(value(&self.vault.vault_summaries()))
    }

    /// One item with its secrets, JSON (`null` if there is none). For a fill-only member the
    /// extension fills it but never shows or copies the password (`can_reveal` false).
    pub fn item(&self, id: &str) -> Zeroizing<String> {
        let item = self.vault.get(id.to_string());
        Zeroizing::new(serde_json::to_string(&item).unwrap_or_else(|_| "null".into()))
    }

    /// Adds or changes an item (JSON as `item` gives it): `{"id"}`.
    pub fn upsert(&self, item: &str) -> HostResult {
        let item = Zeroizing::new(item.to_string());
        let item: Item = parse("item", &item)?;
        let saved = self.vault.upsert(item)?;
        Ok(json!({ "id": saved.id }))
    }

    pub fn delete(&self, id: &str) -> HostResult {
        self.vault.delete(id.to_string())?;
        Ok(json!({}))
    }

    /// Merges a copy from the server: `{"added", "updated", "deleted", "unchanged", "notice"}`,
    /// `notice` as `takeNotice`. Then upload `save()` if `dirty`, and store `takeSave()` of the
    /// home vault (the accepted list is remembered there).
    pub fn merge(&self, file: Vec<u8>) -> HostResult {
        let stats = self.vault.merge_remote(file)?;
        if self.home.remember_trust_of(&self.vault)? {
            self.agent.save()?;
        }
        Ok(json!({
            "added": stats.added,
            "updated": stats.updated,
            "deleted": stats.deleted,
            "unchanged": stats.unchanged,
            "dirty": self.vault.is_dirty(),
            "notice": self.vault.take_members_notice(),
        }))
    }

    /// The encrypted file to store and upload.
    pub fn save(&self) -> Result<Vec<u8>, RpcError> {
        Ok(self.vault.serialize()?)
    }

    /// Member changes (a manager): a JSON array of `MemberChange` (`{"op": "add", "keys",
    /// "role", "group"}`, …). Every key it wraps to must be pinned in this browser's vault
    /// ([`BrowserHost::pin_contact`]; refused otherwise, see [`BrowserHost::unpinned_changes`]).
    /// The new `SharedInfo`; then upload `save()`.
    pub fn change_members(&self, changes: &str) -> HostResult {
        let changes: Vec<MemberChange> = parse("changes", changes)?;
        Ok(value(&self.vault.change_members_pinned(changes, &self.home)?))
    }

    /// What this user's pins say about the manager who signed the current members list
    /// ([`pin_status_json`]), `null` when that manager left: show it with
    /// `SharedInfo.signer_fingerprint` on a first open.
    pub fn signer_status(&self) -> HostResult {
        Ok(self
            .home
            .shared_signer_status(&self.vault)
            .map(|s| pin_status_json(&s))
            .unwrap_or(Value::Null))
    }

    /// This account leaves (a manager while another remains). Upload `save()`, then delete the
    /// file.
    pub fn leave(&self) -> HostResult {
        self.vault.leave_shared()?;
        Ok(json!({}))
    }

    /// `MembersNotice` since the last call, or `null`.
    pub fn take_notice(&self) -> HostResult {
        Ok(value(&self.vault.take_members_notice()))
    }

    /// Copies or moves item `id` between this vault and the home vault (`direction`:
    /// `"to_home"` or `"from_home"`): `{"id"}` of the new item. Then save both.
    pub fn transfer(&self, id: &str, direction: &str, remove: bool) -> HostResult {
        let (from, to) = match direction {
            "to_home" => (&self.vault, &self.home),
            "from_home" => (&self.home, &self.vault),
            _ => {
                return Err(RpcError::new(
                    ErrorCode::InvalidParams,
                    "direction: \"to_home\" or \"from_home\"",
                ))
            }
        };
        let item = if remove {
            from.move_item_to(id, to)?
        } else {
            from.copy_item_to(id, to)?
        };
        self.agent.save()?;
        Ok(json!({ "id": item.id }))
    }
}
