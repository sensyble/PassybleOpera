//! Read-only mode, for an app below the minimum version (see [`crate::app_versions`]).
//!
//! Nobody is locked out of their passwords: unlocking, viewing and copying keep working.
//! Everything that fills, saves, changes or syncs the vault answers `update_required`.

use std::sync::atomic::Ordering;

use serde_json::Value;

use crate::protocol::{ErrorCode, RpcError};
use crate::Agent;

/// The `update_required` error's message.
pub const UPDATE_REQUIRED_MESSAGE: &str = "Update the Passyble app to keep filling";

/// The browser requests still answered in read-only mode. Anything else, including methods added
/// later, is refused.
pub const READ_ONLY_METHODS: &[&str] = &[
    "status",
    "unlock",
    "unlock.options",
    "unlock.password",
    "unlock.hello",
    "unlock.cancel",
    "lock",
    "logins.search",
    "logins.copy",
    "cards.list",
    "cards.fill",
    "identities.list",
    "notes.list",
    "notes.get",
    "app.show_item",
    "icons.get",
    "password.check",
    "generate",
    "generate.options",
    "generate.username",
    "generate.copy",
    "vaults.list",
    "vaults.pins",
    "vaults.own",
    "vaults.switch",
    "app.show_teams",
    "account.status",
    "app.show_account",
    "account.peer",
    "account.handoff_to_extension",
    "account.handoff_begin",
    "account.handoff_finish",
    "account.sign_out",
    "account.peer_signed_out",
];

/// Whether `method` with `params` may run in read-only mode. `cards.fill` is allowed only as a
/// copy the desktop app makes itself, never a fill.
pub fn allows(method: &str, params: &Value) -> bool {
    if method == "cards.fill" {
        return params.get("purpose").and_then(Value::as_str) == Some("copy")
            && params.get("field").and_then(Value::as_str).is_some();
    }
    READ_ONLY_METHODS.contains(&method)
}

pub(crate) fn update_required() -> RpcError {
    RpcError::new(ErrorCode::UpdateRequired, UPDATE_REQUIRED_MESSAGE)
}

impl Agent {
    /// Turns read-only mode on or off. Applies from the next request.
    pub fn set_update_required(&self, on: bool) {
        self.update_required.store(on, Ordering::SeqCst);
    }

    /// Whether read-only mode is on.
    pub fn update_required(&self) -> bool {
        self.update_required.load(Ordering::SeqCst)
    }

    /// `Err(update_required)` in read-only mode.
    #[cfg_attr(not(feature = "native"), allow(dead_code))]
    pub(crate) fn check_writable(&self) -> Result<(), RpcError> {
        if self.update_required() {
            Err(update_required())
        } else {
            Ok(())
        }
    }
}
