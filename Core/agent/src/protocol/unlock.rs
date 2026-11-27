//! Unlocking from the browser extension's own unlock form.
//!
//! The master password is handed to the vault or the desktop app once and is never logged or
//! kept. Attempts are limited per minute, failed or not.

use std::time::Duration;

use pass_core::PassError;
use serde::Deserialize;
use serde_json::json;

use super::{ErrorCode, RpcError, RpcResult};
use crate::{Agent, UnlockAttempt};

/// `unlock.password` attempts per minute, wrong or right.
pub(crate) const PASSWORD_ATTEMPTS_PER_MINUTE: usize = 5;
/// Longer than any master password a person types; more is refused before any work.
const MAX_PASSWORD: usize = 1024;

/// Same text the desktop app shows for a wrong master password.
pub(crate) const WRONG_PASSWORD: &str = "Wrong master password. Check Caps Lock and try again.";

#[derive(Deserialize)]
pub(super) struct PasswordParams {
    password: String,
    /// See [`ForParams`].
    #[serde(default, rename = "for")]
    item: Option<String>,
}

/// `{ "for": "<item id>" }`: a fill waits for this unlock, and the unlock counts as that fill's
/// verification.
#[derive(Default, Deserialize)]
pub(super) struct ForParams {
    #[serde(default, rename = "for")]
    pub(super) item: Option<String>,
}

/// Params that don't parse read as none, never as a reason to refuse.
pub(super) fn for_params(params: serde_json::Value) -> ForParams {
    serde_json::from_value(params).unwrap_or_default()
}

fn unlocked() -> RpcResult {
    Ok(json!({ "locked": false }))
}

fn answer(attempt: UnlockAttempt) -> RpcResult {
    match attempt {
        UnlockAttempt::Unlocked => unlocked(),
        UnlockAttempt::WrongPassword => {
            Err(RpcError::new(ErrorCode::WrongPassword, WRONG_PASSWORD))
        }
        UnlockAttempt::Cancelled => Err(RpcError::new(ErrorCode::Cancelled, "unlock cancelled")),
        UnlockAttempt::Unavailable(why) => Err(RpcError::new(ErrorCode::NotSupported, why)),
        UnlockAttempt::Failed(why) => Err(RpcError::new(ErrorCode::Internal, why)),
    }
}

impl Agent {
    /// `unlock.options`: what the extension's unlock form may offer. Not activity.
    pub(super) fn rpc_unlock_options(&self) -> RpcResult {
        let locked = self.is_locked();
        let hello = locked && self.ui.unlock_options().hello;
        Ok(json!({ "locked": locked, "password": true, "hello": hello }))
    }

    /// `unlock.password`: unlocks the active vault with the typed master password.
    pub(super) fn rpc_unlock_password(&self, p: PasswordParams) -> RpcResult {
        if p.password.is_empty() || p.password.len() > MAX_PASSWORD {
            return Err(RpcError::new(
                ErrorCode::InvalidParams,
                "Enter your master password",
            ));
        }
        if !self.is_locked() {
            return unlocked();
        }
        if !self.within_rate(
            "unlock.password",
            PASSWORD_ATTEMPTS_PER_MINUTE,
            Duration::from_secs(60),
        ) {
            return Err(RpcError::new(
                ErrorCode::RateLimited,
                "Too many attempts. Wait a minute, then try again.",
            ));
        }
        let _for = self.unlocking_for(p.item.clone());
        let attempt = match self.ui.unlock_with_password(&p.password) {
            Some(attempt) => attempt,
            None => match self.unlock(&p.password) {
                Ok(()) => UnlockAttempt::Unlocked,
                Err(PassError::InvalidPassword) => UnlockAttempt::WrongPassword,
                Err(e) => UnlockAttempt::Failed(e.to_string()),
            },
        };
        drop(p);
        if attempt == UnlockAttempt::Unlocked && self.is_locked() {
            return Err(RpcError::new(
                ErrorCode::Internal,
                "The vault is still locked",
            ));
        }
        answer(attempt)
    }

    /// `unlock.hello`: Windows Hello for the active vault (the desktop app shows the prompt).
    pub(super) fn rpc_unlock_hello(&self, p: ForParams) -> RpcResult {
        if !self.is_locked() {
            return unlocked();
        }
        let _for = self.unlocking_for(p.item);
        let attempt = self.ui.unlock_with_hello();
        if attempt == UnlockAttempt::Unlocked && self.is_locked() {
            return Err(RpcError::new(ErrorCode::Cancelled, "unlock cancelled"));
        }
        answer(attempt)
    }

    /// `unlock.cancel`: cancels a pending Windows Hello prompt. Never prompts.
    pub(super) fn rpc_unlock_cancel(&self) -> RpcResult {
        Ok(json!({ "cancelled": self.ui.cancel_unlock() }))
    }
}
