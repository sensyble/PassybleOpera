//! Username and e-mail generation for the extension. The extension never holds alias service
//! tokens or the user's addresses; it only gets the generated name or address.
//!
//! `generate.copy` only copies a password `generate` returned a moment ago, so it can't be used
//! to write anything else to the clipboard.

use std::time::Duration;

use pass_core::{
    generate_email, generate_username, AliasService, EmailKind, EmailOptions, PassError,
    UsernameKind, UsernameOptions,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{ErrorCode, RpcError, RpcResult};
use crate::Agent;

/// Each new alias is an account change at the service.
const ALIASES_PER_MINUTE: usize = 10;
const COPIES_PER_MINUTE: usize = 30;
const MINUTE: Duration = Duration::from_secs(60);

#[derive(Deserialize)]
pub(super) struct CopyParams {
    password: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct UsernameParams {
    /// `words` (default), `word_number` or `characters`.
    kind: Option<String>,
    capitalize: Option<bool>,
    include_number: Option<bool>,
    separator: Option<String>,
    length: Option<u32>,
}

#[derive(Deserialize)]
pub(super) struct EmailParams {
    /// `plus`, `catch_all` or `alias`.
    kind: String,
    #[serde(default)]
    url: Option<String>,
    /// Use the website as the tag, or send it to the alias service as a note. Off unless the
    /// user asked.
    #[serde(default)]
    website: bool,
    /// `alias`: a service id; the default service when missing.
    #[serde(default)]
    service: Option<String>,
}

/// The user-facing text of a core error (without its English kind prefix).
pub(crate) fn core_text(e: &PassError) -> String {
    match e {
        PassError::Corrupt(m)
        | PassError::Crypto(m)
        | PassError::InvalidInput(m)
        | PassError::NotFound(m)
        | PassError::Network(m)
        | PassError::Conflict(m)
        | PassError::CertificateChanged(m)
        | PassError::AuthRequired(m) => m.clone(),
        PassError::InvalidPassword => e.to_string(),
    }
}

fn rpc_error(e: PassError) -> RpcError {
    let code = match e {
        PassError::NotFound(_) => ErrorCode::NotFound,
        PassError::InvalidInput(_) => ErrorCode::InvalidParams,
        _ => ErrorCode::Internal,
    };
    RpcError::new(code, core_text(&e))
}

impl Agent {
    pub(super) fn rpc_generate_copy(&self, p: CopyParams) -> RpcResult {
        let password = zeroize::Zeroizing::new(p.password);
        if !self.within_rate("generate_copy", COPIES_PER_MINUTE, MINUTE) {
            return Err(RpcError::new(
                ErrorCode::RateLimited,
                "Too many copies. Wait a minute and try again",
            ));
        }
        if !self.recently_generated(&password) {
            return Err(RpcError::new(
                ErrorCode::NotFound,
                "not a password generated here just now",
            ));
        }
        if !self.ui.copy_to_clipboard(&password) {
            return Err(RpcError::new(
                ErrorCode::NotSupported,
                "this Passyble app can't copy to the clipboard",
            ));
        }
        Ok(json!({ "copied": true }))
    }

    pub(super) fn rpc_generate_username(&self, p: UsernameParams) -> RpcResult {
        let d = UsernameOptions::default();
        let kind = match p.kind.as_deref().unwrap_or("words") {
            "words" => UsernameKind::Words,
            "word_number" => UsernameKind::WordNumber,
            "characters" => UsernameKind::Characters,
            other => {
                return Err(RpcError::new(
                    ErrorCode::InvalidParams,
                    format!("unknown kind {other}"),
                ))
            }
        };
        let username = generate_username(UsernameOptions {
            kind,
            capitalize: p.capitalize.unwrap_or(d.capitalize),
            include_number: p.include_number.unwrap_or(d.include_number),
            separator: p.separator.unwrap_or(d.separator),
            length: p.length.unwrap_or(d.length),
        })
        .map_err(rpc_error)?;
        Ok(json!({ "username": username }))
    }

    pub(super) fn rpc_generate_options(&self) -> RpcResult {
        let vault = self.unlocked()?;
        let email = vault.email_generator_settings();
        let default = vault.alias_default_service();
        let aliases: Vec<Value> = vault
            .alias_configs()
            .iter()
            .map(|c| {
                json!({
                    "id": c.service.id(),
                    "name": c.service.name(),
                    "default": Some(c.service) == default,
                })
            })
            .collect();
        Ok(json!({
            "plus": !email.address.is_empty(),
            "catch_all": !email.domain.is_empty(),
            "aliases": aliases,
        }))
    }

    pub(super) fn rpc_generate_email(&self, p: EmailParams) -> RpcResult {
        let vault = self.unlocked()?;
        let website = p.url.filter(|_| p.website);
        let email = match p.kind.as_str() {
            "plus" | "catch_all" => {
                let saved = vault.email_generator_settings();
                let plus = p.kind == "plus";
                if (plus && saved.address.is_empty()) || (!plus && saved.domain.is_empty()) {
                    return Err(RpcError::new(
                        ErrorCode::NotFound,
                        "Set up the e-mail generator in Passyble: Settings, Generator.",
                    ));
                }
                generate_email(EmailOptions {
                    kind: if plus {
                        EmailKind::PlusAddress
                    } else {
                        EmailKind::CatchAll
                    },
                    address: saved.address,
                    domain: saved.domain,
                    website,
                })
                .map_err(rpc_error)?
            }
            "alias" => {
                let service = match p.service.as_deref() {
                    None | Some("") => None,
                    Some(id) => Some(AliasService::from_id(id).ok_or_else(|| {
                        RpcError::new(ErrorCode::InvalidParams, format!("unknown service {id}"))
                    })?),
                };
                if !self.within_rate(
                    "alias",
                    ALIASES_PER_MINUTE,
                    std::time::Duration::from_secs(60),
                ) {
                    return Err(RpcError::new(
                        ErrorCode::RateLimited,
                        "Too many new aliases. Wait a minute.",
                    ));
                }
                self.alias(&vault, service, website)?
            }
            other => {
                return Err(RpcError::new(
                    ErrorCode::InvalidParams,
                    format!("unknown kind {other}"),
                ))
            }
        };
        Ok(json!({ "email": email }))
    }

    #[cfg(feature = "webdav")]
    fn alias(
        &self,
        vault: &pass_core::Vault,
        service: Option<AliasService>,
        website: Option<String>,
    ) -> Result<String, RpcError> {
        vault.generate_alias(service, website).map_err(rpc_error)
    }

    #[cfg(not(feature = "webdav"))]
    fn alias(
        &self,
        _vault: &pass_core::Vault,
        _service: Option<AliasService>,
        _website: Option<String>,
    ) -> Result<String, RpcError> {
        Err(RpcError::new(
            ErrorCode::NotSupported,
            "This build has no e-mail alias services.",
        ))
    }
}
