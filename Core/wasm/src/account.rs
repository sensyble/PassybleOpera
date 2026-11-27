//! Passyble accounts in the browser extension. A vault linked to an account opens with the account
//! key (AK), which comes from the Passyble password and Secret Key or from another device of the
//! account. The cryptography is pass-core's; this module is the JSON boundary. Argon2id runs through
//! the `setKdf` runner, a fresh small instance per run, so the vault module never grows by 64 MiB.

use pass_agent::{ErrorCode, RpcError};
use pass_core::{
    vault_file_access, AccountKdf, AccountKey, AccountWrap, PassError, SealedAccountKey, SecretKey,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::host::{no_vault, BrowserHost, HostResult};

/// A pass-core error of the account key code as the extension takes it: a password and Secret
/// Key that don't open the wrap (or an AK that doesn't open the vault) are `wrong_password`;
/// everything else as the agent maps it (`invalid_params` for bad input, with the core's text).
pub fn key_error(e: PassError) -> RpcError {
    match e {
        PassError::InvalidPassword => wrong_key(),
        PassError::Crypto(message) => RpcError::new(ErrorCode::InvalidParams, message),
        other => other.into(),
    }
}

fn wrong_key() -> RpcError {
    RpcError::new(
        ErrorCode::WrongPassword,
        "Check your Passyble password and Secret Key",
    )
}

fn parse<T: DeserializeOwned>(what: &str, text: &str) -> Result<T, RpcError> {
    serde_json::from_str(text)
        .map_err(|e| RpcError::new(ErrorCode::InvalidParams, format!("{what}: {e}")))
}

/// The account's Argon2id parameters as the account service gives them (`{"alg", "m_kib", "t",
/// "p"}`); pass-core checks the bounds when it derives.
pub fn parse_kdf(json: &str) -> Result<AccountKdf, RpcError> {
    parse("kdf", json)
}

/// A wrap as the account service gives it (`{"nonce", "ct"}`, base64url).
pub fn parse_wrap(json: &str) -> Result<AccountWrap, RpcError> {
    parse("wrap", json)
}

/// Keys sealed to a new device as the account service gives them (`{"enc", "ct"}`, base64url).
pub fn parse_sealed(json: &str) -> Result<SealedAccountKey, RpcError> {
    parse("sealed", json)
}

/// A wrap for the account service, as JSON.
pub fn wrap_json(wrap: &AccountWrap) -> String {
    json!({ "nonce": wrap.nonce, "ct": wrap.ct }).to_string()
}

/// A kdf for the account service, as JSON.
pub fn kdf_json(kdf: &AccountKdf) -> String {
    serde_json::to_value(kdf).unwrap_or(Value::Null).to_string()
}

/// A typed or pasted Secret Key (spaces, dashes and case don't matter, the `P1` may be left out):
/// pass-core's [`SecretKey`], or `invalid_params` with the core's text (a recovery code typed
/// here is named as such).
pub fn secret_key(text: &str) -> Result<SecretKey, RpcError> {
    SecretKey::read(text).map_err(key_error)
}

/// `{"text"}`: the Secret Key written the one way it is kept (`P1-XXXXX-...`).
pub fn secret_key_text(text: &str) -> HostResult {
    let text = Zeroizing::new(text.to_string());
    Ok(json!({ "text": secret_key(&text)?.text() }))
}

/// `{"kind", "account", "ak_id", "account_recovery"}`: what a vault file opens with, read without
/// opening it (`"password"`, `"account"` for a vault linked to a Passyble account, `"members"`).
pub fn vault_access(file: &[u8]) -> HostResult {
    let access = vault_file_access(file.to_vec()).map_err(RpcError::from)?;
    Ok(json!({
        "kind": access.kind,
        "account": access.account,
        "ak_id": access.ak_id,
        "account_recovery": access.account_recovery,
    }))
}

/// `{"email", "account", "secret_key"}` from the Emergency Kit's setup QR
/// (`passyble:kit/v1?...`).
pub fn kit_qr(text: &str) -> HostResult {
    let kit = pass_core::parse_kit_qr(text.to_string()).map_err(key_error)?;
    Ok(json!({ "email": kit.email, "account": kit.account, "secret_key": kit.secret_key }))
}

/// `{"size", "path"}`: a QR code of `text` (error correction M) as one SVG path in a `size` by
/// `size` square of modules, the quiet zone included (as the desktop app draws its QR codes).
pub fn qr_svg(text: &str) -> HostResult {
    let code = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M)
        .map_err(|e| RpcError::new(ErrorCode::InvalidParams, e.to_string()))?;
    let width = code.width();
    let quiet = 4;
    let mut path = String::new();
    for (i, c) in code.to_colors().iter().enumerate() {
        if *c == qrcode::Color::Dark {
            let (x, y) = (i % width + quiet, i / width + quiet);
            path.push_str(&format!("M{x} {y}h1v1h-1z"));
        }
    }
    Ok(json!({ "size": width + 2 * quiet, "path": path }))
}

impl BrowserHost {
    /// What this browser's vault file opens with ([`vault_access`]); `no_vault` without one.
    pub fn vault_access(&self) -> HostResult {
        let file = self.agent().vault_file_bytes().ok_or_else(no_vault)?;
        vault_access(&file)
    }

    /// Opens this browser's vault, linked to a Passyble account (file version 3), with the account
    /// key. `invalid_params` when the vault isn't linked or is linked to another account or another
    /// key of it (the key was replaced: sign in again), `wrong_password` if the key doesn't open it.
    /// Answers `{ "locked": false, "grant" }`, like [`BrowserHost::unlock`].
    pub fn unlock_with_account_key(&self, account_key: &AccountKey) -> HostResult {
        if !self.has_vault() {
            return Err(no_vault());
        }
        self.agent()
            .unlock_with_account_key(account_key)
            .map_err(key_error)?;
        Ok(json!({ "locked": false, "grant": self.issue_grant() }))
    }

    /// The Passyble password checked while a linked vault is unlocked ("Confirm each fill",
    /// passkeys that demand user verification): the account key it opened must be the one this
    /// vault is linked to. Answers `{ "grant" }` for one request, like
    /// [`BrowserHost::verify_password`].
    pub fn verify_account_key(&self, account_key: &AccountKey) -> HostResult {
        let vault = self
            .agent()
            .peek_vault()
            .ok_or_else(|| RpcError::new(ErrorCode::Locked, "Vault is locked"))?;
        let linked = vault.account_link().is_some_and(|link| {
            link.account == account_key.account() && link.ak_id == account_key.ak_id()
        });
        if !linked {
            return Err(wrong_key());
        }
        Ok(json!({ "grant": self.issue_grant() }))
    }
}
