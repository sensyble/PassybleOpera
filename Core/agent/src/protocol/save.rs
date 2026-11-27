//! `logins.save_check`: what the extension's banner should offer after a form submit. Stored
//! passwords are compared here so they never go to the browser; the answer is only a decision.

use std::time::Duration;

use pass_core::Item;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{vault_json, vaults_json, ErrorCode, RpcError, RpcResult};
use crate::agent::Opened;
use crate::Agent;

/// Each check tells whether a typed password is a saved one, so keep it slow.
const CHECKS_PER_MINUTE: usize = 30;

#[derive(Deserialize)]
pub(super) struct SaveCheckParams {
    url: String,
    #[serde(default)]
    username: String,
    password: String,
    /// `"login"` (default), `"signup"` or `"change"`.
    #[serde(default)]
    kind: Option<String>,
    /// The login filled on this site moments ago, if any.
    #[serde(default)]
    filled_id: Option<String>,
    /// Left out of the comparison: the extension's auto-saved draft of a password generated on
    /// this page, which would otherwise make every answer `none`.
    #[serde(default)]
    ignore_id: Option<String>,
    /// The page's `<link rel="canonical">` address, as the extension read it.
    #[serde(default)]
    canonical_url: Option<String>,
}

/// The canonical origin a submit on `url` shares its login with. `canonical_url` comes from the
/// page, so it is untrusted and checked again here.
pub(super) fn canonical_origin(url: &str, canonical_url: Option<&str>) -> Option<String> {
    pass_core::canonical_save_origin(url, canonical_url?)
}

/// The logins a submit on `url` may update: those of the page's host, then those of an accepted
/// canonical host, so both hosts share one login. Never another subdomain's, and only in vaults
/// this user may edit.
pub(super) fn save_scope(vaults: &Opened, url: &str, canonical: Option<&str>) -> Vec<Item> {
    let mut items = vaults.find_for_save(url);
    if let Some(canonical) = canonical {
        for item in vaults.find_for_save(canonical) {
            if !items.iter().any(|i| i.id == item.id) {
                items.push(item);
            }
        }
    }
    items
}

/// The same account name: trimmed, case-insensitive.
pub(super) fn same_login_name(a: &str, b: &str) -> bool {
    let (a, b) = (a.trim(), b.trim());
    !a.is_empty() && a.to_lowercase() == b.to_lowercase()
}

/// Constant-time comparison with the saved password.
pub(super) fn same_password(item: &Item, password: &str) -> bool {
    pass_core::secrets_equal(&item.password, password)
}

/// The login with the same username and password. Without a username (a password-only form),
/// any login with this password.
pub(super) fn saved_as_is<'a>(
    items: &'a [Item],
    username: &str,
    password: &str,
) -> Option<&'a Item> {
    let anyone = username.trim().is_empty();
    items
        .iter()
        .find(|i| (anyone || same_login_name(&i.username, username)) && same_password(i, password))
}

/// The https address of a plain-http page. Logins saved for https are never filled there, but
/// typing the same credentials there isn't a new login either.
fn https_twin(url: &str) -> Option<String> {
    let mut page = url::Url::parse(url).ok()?;
    if page.scheme() != "http" {
        return None;
    }
    page.set_scheme("https").ok()?;
    Some(page.into())
}

/// A login of the site of `url` (or its https address) that already has these credentials.
pub(super) fn already_saved(
    vaults: &Opened,
    url: &str,
    username: &str,
    password: &str,
    ignore: Option<&str>,
) -> Option<Item> {
    let urls = std::iter::once(url.to_string()).chain(https_twin(url));
    urls.into_iter().find_map(|url| {
        let mut items = vaults.logins_of_page(&url);
        items.retain(|i| Some(i.id.as_str()) != ignore);
        saved_as_is(&items, username, password).cloned()
    })
}

/// The answer, with the vault of the login it names (`vault`); `save_new` also lists the vaults
/// a new login can go to (`vaults`, those this user may edit) and the default one.
fn decision(vaults: &Opened, url: &str, action: &str, item: Option<&Item>) -> Value {
    let mut answer = match item {
        Some(item) => json!({ "action": action, "id": item.id, "title": item.title }),
        None => json!({ "action": action }),
    };
    if let Some(vault) = item.and_then(|i| vaults.ref_of(&i.id)) {
        answer["vault"] = vault_json(vault);
    }
    if action == "save_new" {
        answer["vaults"] = vaults_json(&vaults.editable());
        answer["default_vault"] = json!(vaults.default_save(Some(url)));
    }
    answer
}

impl Agent {
    /// `logins.save_check`, in order:
    /// 1. the login just filled, or the same credentials already saved for the site: `none`;
    /// 2. the same username, another password: `update_password`;
    /// 3. a password change form with a clear target: `update_password`, or `none` if unchanged;
    /// 4. another username with the password of exactly one login: `update_username`;
    /// 5. otherwise `save_new`.
    ///
    /// Steps 2 to 4 only update a login of the page's own host (or its verified canonical host).
    /// Step 1 looks at every login of the site. The answer never carries a password.
    pub(super) fn rpc_save_check(&self, p: SaveCheckParams) -> RpcResult {
        // Like `logins.find`: the extension asks on its own after a form submit, which isn't use.
        let vaults = self
            .opened()
            .ok_or_else(|| RpcError::new(ErrorCode::Locked, "Vault is locked"))?;
        let decision = |action: &str, item: Option<&Item>| decision(&vaults, &p.url, action, item);
        if !self.within_rate("save_check", CHECKS_PER_MINUTE, Duration::from_secs(60)) {
            return Err(RpcError::new(
                ErrorCode::RateLimited,
                "Too many checks. Wait a minute",
            ));
        }
        if p.password.is_empty() {
            return Ok(decision("none", None));
        }
        // Every login of the site tells whether this one is saved already, but only logins of the
        // page's own host are updated.
        let mut site = vaults.logins_of_page(&p.url);
        let canonical = canonical_origin(&p.url, p.canonical_url.as_deref());
        let mut items = save_scope(&vaults, &p.url, canonical.as_deref());
        if let Some(ignored) = p.ignore_id.as_deref() {
            site.retain(|i| i.id != ignored);
            items.retain(|i| i.id != ignored);
        }
        let filled_id = p.filled_id.as_deref();
        if let Some(item) = filled_id
            .and_then(|id| site.iter().find(|i| i.id == id))
            .filter(|i| same_password(i, &p.password))
        {
            return Ok(decision("none", Some(item)));
        }
        // Only if it belongs to this host; another subdomain's login is never changed here.
        let filled = filled_id.and_then(|id| items.iter().find(|i| i.id == id));
        let only = if items.len() == 1 {
            items.first()
        } else {
            None
        };
        let change_target = if p.kind.as_deref() == Some("change") {
            filled.or(only)
        } else {
            None
        };
        let username_given = !p.username.trim().is_empty();
        // Without a username, a change form's target wins over another login that happens to
        // have the same password.
        if username_given || change_target.is_none() {
            if let Some(item) = already_saved(
                &vaults,
                &p.url,
                &p.username,
                &p.password,
                p.ignore_id.as_deref(),
            ) {
                return Ok(decision("none", Some(&item)));
            }
        }
        let same_user: Vec<&Item> = items
            .iter()
            .filter(|i| same_login_name(&i.username, &p.username))
            .collect();
        if let Some(item) = same_user.first() {
            return Ok(decision("update_password", Some(item)));
        }
        if let Some(item) = change_target {
            let action = if same_password(item, &p.password) {
                "none"
            } else {
                "update_password"
            };
            return Ok(decision(action, Some(item)));
        }
        let by_password: Vec<&Item> = items
            .iter()
            .filter(|i| same_password(i, &p.password))
            .collect();
        if let ([item], true) = (by_password.as_slice(), username_given) {
            return Ok(decision("update_username", Some(item)));
        }
        let mut answer = decision("save_new", None);
        // A new login for a page that looks like one of the user's sites without being it
        // (`paypa1.com` with a `paypal.com` login): the banner warns before it is saved.
        if let Some(found) = vaults.lookalike_for_save(&p.url) {
            answer["lookalike"] = super::search::lookalike_json(&found);
        }
        Ok(answer)
    }
}
