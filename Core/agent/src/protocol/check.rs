//! `password.check`: local checks of a password the extension is about to save. Nothing is
//! looked up online, and the password is never kept or logged. Reuse is only checked while the
//! vault is unlocked (`vault_checked`).

use std::time::Duration;

use pass_core::{password_issues, PasswordCheck, PasswordContext};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{ErrorCode, RpcError, RpcResult};
use crate::Agent;

/// The popup's editor checks while the user types (debounced).
const CHECKS_PER_MINUTE: usize = 120;
const MAX_PASSWORD: usize = 4096;
const MAX_USERNAME: usize = 512;
const MAX_URL: usize = 2048;
const MAX_TITLE: usize = 256;
const MAX_ID: usize = 128;

#[derive(Deserialize)]
pub(super) struct CheckParams {
    password: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    url: String,
    /// The login being edited or updated: its own password is not "reused".
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    title: String,
}

impl Agent {
    pub(super) fn rpc_password_check(&self, p: CheckParams) -> RpcResult {
        let mut password = zeroize::Zeroizing::new(p.password);
        if password.len() > MAX_PASSWORD
            || p.username.len() > MAX_USERNAME
            || p.url.len() > MAX_URL
            || p.title.len() > MAX_TITLE
            || p.id.as_ref().is_some_and(|id| id.len() > MAX_ID)
        {
            return Err(RpcError::new(ErrorCode::InvalidParams, "value too long"));
        }
        if !self.within_rate("password_check", CHECKS_PER_MINUTE, Duration::from_secs(60)) {
            return Err(RpcError::new(
                ErrorCode::RateLimited,
                "Too many checks. Wait a minute",
            ));
        }
        let context = PasswordContext {
            username: p.username,
            urls: if p.url.is_empty() {
                vec![]
            } else {
                vec![p.url]
            },
            android_apps: vec![],
            title: p.title,
            item_id: p.id.unwrap_or_default(),
        };
        // Not activity: it runs while the user types. `password_issues` zeroizes the password.
        let check = password_issues(self.peek_vault(), std::mem::take(&mut *password), context);
        Ok(check_json(&check))
    }
}

/// A [`pass_core::PasswordCheck`] as the JSON `password.check` answers with.
pub fn check_json(check: &PasswordCheck) -> Value {
    let issues: Vec<Value> = check
        .issues
        .iter()
        .map(|i| {
            let mut v = json!({ "code": i.kind.as_str(), "severity": i.severity.as_str() });
            if i.count > 0 {
                v["count"] = json!(i.count);
            }
            if !i.name.is_empty() {
                v["name"] = json!(i.name);
            }
            if i.min_length > 0 {
                v["min_length"] = json!(i.min_length);
            }
            v
        })
        .collect();
    json!({
        "score": check.score,
        "label": check.label,
        "entropy_bits": check.entropy_bits,
        "issues": issues,
        "vault_checked": check.vault_checked,
    })
}
