//! `account.*`: the same-computer sign-in handoff between the desktop app and the extension.
//!
//! The signed-in side gets a sign-in code bound to the S256 challenge of a verifier only the other
//! side holds, so each side has its own session and no token is copied. These work while locked
//! and never log a code, token or verifier.

use serde::Deserialize;
use serde_json::json;

use super::{ErrorCode, RpcError, RpcResult};
use crate::{AccountError, Agent};

/// A PKCE `S256` challenge: 32 bytes of SHA-256, base64url without padding.
const CHALLENGE_LEN: usize = 43;
/// The longest device name kept, as the Passyble service keeps it.
const MAX_DEVICE_NAME: usize = 64;
/// The longest sign-in code taken (the service's are `pac_` and 43 characters).
const MAX_CODE: usize = 256;

#[derive(Deserialize)]
pub(super) struct ToExtensionParams {
    code_challenge: String,
    #[serde(default)]
    device_name: String,
}

#[derive(Deserialize)]
pub(super) struct FinishParams {
    code: String,
}

fn no_account() -> RpcError {
    RpcError::new(
        ErrorCode::NotSupported,
        "this Passyble app has no Passyble account",
    )
}

fn answer_error(e: AccountError) -> RpcError {
    match e {
        AccountError::NotSupported => no_account(),
        AccountError::InvalidState(message) => RpcError::new(ErrorCode::InvalidState, message),
        AccountError::Failed(message) => RpcError::new(ErrorCode::Internal, message),
    }
}

fn invalid(message: &str) -> RpcError {
    RpcError::new(ErrorCode::InvalidParams, message)
}

/// 43 base64url characters, as `S256` gives.
fn challenge_ok(challenge: &str) -> bool {
    challenge.len() == CHALLENGE_LEN
        && challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Trimmed, without control characters, at most [`MAX_DEVICE_NAME`] characters (may be empty:
/// the service names it then).
fn clean_device_name(name: &str) -> String {
    name.trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_DEVICE_NAME)
        .collect()
}

/// A sign-in code as the service makes them: printable ASCII without spaces, not too long.
fn code_ok(code: &str) -> bool {
    !code.is_empty() && code.len() <= MAX_CODE && code.bytes().all(|b| b.is_ascii_graphic())
}

impl Agent {
    /// `account.peer`: signed in or not, the e-mail address (while signed in, or the address of a
    /// sign-out that asks the extension to sign out too), whether the app takes a sign-in from the
    /// extension, and whether the extension should sign out.
    pub(super) fn rpc_account_peer(&self) -> RpcResult {
        let peer = self.ui.account_peer().ok_or_else(no_account)?;
        let email = peer
            .email
            .filter(|e| !e.is_empty() && (peer.signed_in || peer.sign_out_extension));
        Ok(json!({
            "signed_in": peer.signed_in,
            "email": email,
            "accepts_handoff": peer.accepts_handoff,
            "sign_out_extension": peer.sign_out_extension && !peer.signed_in,
        }))
    }

    /// `account.handoff_to_extension`: a sign-in code for the extension from the signed-in app.
    pub(super) fn rpc_handoff_to_extension(&self, p: ToExtensionParams) -> RpcResult {
        if !challenge_ok(&p.code_challenge) {
            return Err(invalid("code_challenge is not an S256 challenge"));
        }
        let device_name = clean_device_name(&p.device_name);
        let handoff = self
            .ui
            .handoff_to_extension(&p.code_challenge, &device_name)
            .map_err(answer_error)?;
        Ok(json!({ "code": handoff.code, "email": handoff.email }))
    }

    /// `account.handoff_begin`: the signed-out app's challenge for a sign-in from the extension.
    pub(super) fn rpc_handoff_begin(&self) -> RpcResult {
        let request = self.ui.handoff_begin().map_err(answer_error)?;
        Ok(json!({
            "code_challenge": request.code_challenge,
            "device_name": request.device_name,
        }))
    }

    /// `account.handoff_finish`: the app redeems the extension's code with its pending verifier.
    pub(super) fn rpc_handoff_finish(&self, p: FinishParams) -> RpcResult {
        if !code_ok(&p.code) {
            return Err(invalid("code is not a sign-in code"));
        }
        let email = self.ui.handoff_finish(&p.code).map_err(answer_error)?;
        Ok(json!({ "signed_in": true, "email": email }))
    }

    /// `account.sign_out`: the extension's sign-out with "also sign out of the Passyble app".
    pub(super) fn rpc_account_sign_out(&self) -> RpcResult {
        self.ui.sign_out_from_extension().map_err(answer_error)?;
        Ok(json!({ "signed_out": true }))
    }

    /// `account.peer_signed_out`: the extension followed the app's sign-out.
    pub(super) fn rpc_peer_signed_out(&self) -> RpcResult {
        self.ui.peer_signed_out().map_err(answer_error)?;
        Ok(json!({}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenges_codes_and_device_names() {
        assert!(challenge_ok("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
        assert!(!challenge_ok("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c"));
        assert!(!challenge_ok("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM"));
        assert!(!challenge_ok(""));
        assert!(code_ok("pac_abc"));
        assert!(!code_ok(""));
        assert!(!code_ok("pac abc"));
        assert!(!code_ok(&"a".repeat(MAX_CODE + 1)));
        assert_eq!(clean_device_name("  Chrome\n on PC "), "Chrome on PC");
        assert_eq!(clean_device_name(&"x".repeat(100)).len(), MAX_DEVICE_NAME);
    }
}
