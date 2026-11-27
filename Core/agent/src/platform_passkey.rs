//! Passkey ceremonies for an operating-system WebAuthn client (the Windows 11 passkey plugin API).
//!
//! The platform has already built the client data and checked the RP ID against the caller, so
//! these take the `clientDataHash` directly.

use pass_core::{passkey_assert, passkey_create};

use crate::{Agent, Consent, ErrorCode, PasskeyChoice, RpcError};

const COSE_ES256: i64 = -7;

/// `authenticatorMakeCredential` as decoded from the platform's CTAP2 request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlatformCreateRequest {
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_handle: Vec<u8>,
    pub user_name: String,
    pub user_display_name: Option<String>,
    pub client_data_hash: Vec<u8>,
    /// COSE algorithms the RP accepts; empty means "any".
    pub algorithms: Vec<i64>,
    /// Credential ids the RP already knows for this account.
    pub exclude_credentials: Vec<Vec<u8>>,
}

/// The new credential, ready to be encoded as the CTAP2 response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlatformCreated {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
}

/// `authenticatorGetAssertion` as decoded from the platform's CTAP2 request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlatformGetRequest {
    pub rp_id: String,
    pub client_data_hash: Vec<u8>,
    /// Empty for a discoverable-credential request.
    pub allow_credentials: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlatformAssertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
}

/// What the platform's autofill cache may know about a passkey: no key material.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PasskeyMetadata {
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub rp_name: String,
    pub user_handle: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
}

impl Agent {
    /// Unlocks first if needed. Not activity by itself.
    fn unlocked_for_platform(&self) -> Result<std::sync::Arc<pass_core::Vault>, RpcError> {
        if let Some(vault) = self.peek_vault() {
            return Ok(vault);
        }
        if !self.ui.request_unlock() {
            return Err(RpcError::new(ErrorCode::Cancelled, "unlock cancelled"));
        }
        self.peek_vault()
            .ok_or_else(|| RpcError::new(ErrorCode::Locked, "Vault is locked"))
    }

    /// Creates and stores a passkey after the consent prompt and `verify_user`, which gets the
    /// user name and returns `false` when verification failed or was cancelled.
    pub fn platform_passkey_create(
        &self,
        req: PlatformCreateRequest,
        verify_user: &dyn Fn(&str) -> bool,
    ) -> Result<PlatformCreated, RpcError> {
        self.check_writable()?;
        if req.rp_id.is_empty() {
            return Err(RpcError::new(ErrorCode::InvalidParams, "empty rp id"));
        }
        if !req.algorithms.is_empty() && !req.algorithms.contains(&COSE_ES256) {
            return Err(RpcError::new(
                ErrorCode::NotSupported,
                "only ES256 passkeys are supported",
            ));
        }
        let rp_id = req.rp_id.to_ascii_lowercase();
        let _busy = self.busy();
        self.unlocked_for_platform()?;
        let opened = self
            .opened()
            .ok_or_else(|| RpcError::new(ErrorCode::Locked, "Vault is locked"))?;
        // Already in any open vault (the home vault or a shared one).
        if !req.exclude_credentials.is_empty()
            && opened.0.iter().any(|(_, v)| {
                !v.find_passkeys(rp_id.clone(), req.exclude_credentials.clone())
                    .is_empty()
            })
        {
            return Err(RpcError::new(
                ErrorCode::InvalidState,
                "a passkey for this account is already in Passyble",
            ));
        }
        let item_id = match self.ui.confirm_passkey_create(&rp_id, &req.user_name) {
            Consent::Approve { item_id } => item_id,
            Consent::Deny => return Err(RpcError::new(ErrorCode::Cancelled, "declined")),
        };
        if !verify_user(&req.user_name) {
            return Err(RpcError::new(
                ErrorCode::Cancelled,
                "user verification failed",
            ));
        }
        let display_name = req
            .user_display_name
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| req.user_name.clone());
        let created = passkey_create(
            rp_id,
            req.rp_name,
            req.user_handle,
            req.user_name,
            display_name,
            req.client_data_hash,
            req.algorithms,
        )?;
        // With its login, in that login's vault if this user may change it; a new login goes
        // into the vault a new login for the site goes into by default.
        let site = format!("https://{}", created.passkey.rp_id);
        let target = match &item_id {
            Some(id) => opened.holding(id).cloned(),
            None => opened
                .default_save(Some(&site))
                .and_then(|id| opened.by_id(&id).cloned()),
        };
        let (target_ref, vault) =
            target.ok_or_else(|| RpcError::new(ErrorCode::NotFound, "no such item"))?;
        if !target_ref.can_edit {
            return Err(crate::protocol::read_only());
        }
        vault.add_passkey(item_id, created.passkey, None)?;
        self.save()?;
        self.note_activity();
        Ok(PlatformCreated {
            credential_id: created.credential_id,
            authenticator_data: created.authenticator_data,
        })
    }

    /// Signs in with a stored passkey: picker (only when several match), then `verify_user`.
    pub fn platform_passkey_get(
        &self,
        req: PlatformGetRequest,
        verify_user: &dyn Fn(&str) -> bool,
    ) -> Result<PlatformAssertion, RpcError> {
        self.check_writable()?;
        let rp_id = req.rp_id.to_ascii_lowercase();
        if rp_id.is_empty() {
            return Err(RpcError::new(ErrorCode::InvalidParams, "empty rp id"));
        }
        let _busy = self.busy();
        self.unlocked_for_platform()?;
        // Every open vault's passkeys (fill-only members sign in with theirs too).
        let matches: Vec<pass_core::PasskeyMatch> = self
            .open_vaults()
            .iter()
            .flat_map(|(_, v)| v.find_passkeys(rp_id.clone(), req.allow_credentials.clone()))
            .collect();
        let index = match matches.len() {
            0 => {
                return Err(RpcError::new(
                    ErrorCode::NotFound,
                    "no passkey for this site in Passyble",
                ))
            }
            // The platform already showed which account; Windows Hello is the consent.
            1 => 0,
            _ => {
                let choices: Vec<PasskeyChoice> = matches
                    .iter()
                    .map(|m| PasskeyChoice {
                        item_id: m.item_id.clone(),
                        title: m.item_title.clone(),
                        user_name: m.passkey.user_name.clone(),
                    })
                    .collect();
                self.ui
                    .choose_passkey(&rp_id, &choices)
                    .filter(|i| *i < matches.len())
                    .ok_or_else(|| RpcError::new(ErrorCode::Cancelled, "cancelled"))?
            }
        };
        let chosen = matches[index].passkey.clone();
        if !verify_user(&chosen.user_name) {
            return Err(RpcError::new(
                ErrorCode::Cancelled,
                "user verification failed",
            ));
        }
        let user_name = chosen.user_name.clone();
        let user_display_name = chosen.user_display_name.clone();
        let assertion = passkey_assert(chosen, req.client_data_hash, true)?;
        self.record_use(&matches[index].item_id);
        Ok(PlatformAssertion {
            credential_id: assertion.credential_id,
            authenticator_data: assertion.authenticator_data,
            signature: assertion.signature,
            user_handle: assertion.user_handle,
            user_name,
            user_display_name,
        })
    }

    /// Metadata of every passkey in the open vaults (the home vault and the shared ones), sorted,
    /// or `None` while the vault is locked. Does not count as activity, so polling it never keeps
    /// the vault from auto-locking.
    pub fn passkey_metadata(&self) -> Option<Vec<PasskeyMetadata>> {
        let opened = self.opened()?;
        let mut list: Vec<PasskeyMetadata> =
            opened
                .0
                .iter()
                .flat_map(|(_, v)| v.items())
                .filter(|item| !item.passkeys.is_empty())
                .flat_map(|item| {
                    let title = item.title.clone();
                    item.passkeys.into_iter().map(move |pk| PasskeyMetadata {
                        rp_name: pk.rp_name.clone().filter(|n| !n.is_empty()).unwrap_or_else(
                            || {
                                if title.is_empty() {
                                    pk.rp_id.clone()
                                } else {
                                    title.clone()
                                }
                            },
                        ),
                        credential_id: pk.credential_id,
                        rp_id: pk.rp_id,
                        user_handle: pk.user_handle,
                        user_name: pk.user_name,
                        user_display_name: pk.user_display_name,
                    })
                })
                .collect();
        list.sort();
        list.dedup();
        Some(list)
    }
}
