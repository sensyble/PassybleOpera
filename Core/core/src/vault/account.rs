//! Personal vaults linked to a Passyble account (file version 3). The vault key is wrapped by the
//! account key instead of a master password, so a stolen linked file holds nothing to guess.
//! `header_auth` covers the account slot and the optional recovery copy, so the file's host can't
//! swap or strip either; the newer authenticated header wins a merge, linked or not.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::{
    key_from_vec, open, parse_file, seal, shared, Inner, KdfParams, Sealed, Vault, VaultFile,
};
use crate::account_key::{self, json_tail, AccountKey, AccountWrap};
use crate::crypto::Key;
use crate::encoding::{b64_decode, b64_encode, b64url_decode, b64url_encode};
use crate::i18n::tr;
use crate::{PassError, Result};

/// `access` of a linked vault's file.
pub(super) const ACCESS_ACCOUNT: &str = "account";

/// The vault key wrapped by the account key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AccountSlot {
    pub(super) account: String,
    pub(super) ak_id: String,
    pub(super) wrapped_key: Sealed,
}

/// A linked vault's copy of the account's recovery wrap of AK.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AccountRecoveryCopy {
    pub(super) rec_id: String,
    pub(super) wrapped_ak: Sealed,
}

/// What a vault file opens with, read without opening it ([`vault_file_access`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct VaultAccess {
    /// `"password"` (a master password), `"account"` (the Passyble password: linked) or
    /// `"members"` (a shared vault).
    pub kind: String,
    /// Linked vaults: the account and the account key's id.
    pub account: Option<String>,
    pub ak_id: Option<String>,
    /// Linked vaults: whether the header holds a copy of the account recovery wrap (the recovery
    /// code opens it offline).
    pub account_recovery: bool,
}

/// An open vault's link to the account ([`Vault::account_link`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct VaultAccountLink {
    pub account: String,
    pub ak_id: String,
    /// The recovery code whose wrap the header carries, if any: compare it with the account's
    /// current `rec_id` and call [`Vault::set_account_recovery`] when they differ.
    pub recovery_id: Option<String>,
}

/// The account's recovery wrap of AK as a linked vault's header keeps it
/// ([`Vault::account_recovery_copy`]): the same values [`Vault::set_account_recovery`] takes.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AccountRecoveryWrap {
    pub rec_id: String,
    pub wrap: AccountWrap,
}

fn account_vk_aad(vault_id: &str, account: &str, ak_id: &str) -> Result<Vec<u8>> {
    json_tail(b"pass/account-vk/v1:", &(vault_id, account, ak_id))
}

/// AAD of a linked vault's `header_auth`.
pub(super) fn header_aad(
    vault_id: &str,
    header_updated_at: i64,
    slot: &AccountSlot,
    recovery: Option<&AccountRecoveryCopy>,
) -> Result<Vec<u8>> {
    json_tail(
        b"pass/header/v3:",
        &(vault_id, header_updated_at, ACCESS_ACCOUNT, slot, recovery),
    )
}

/// A linked vault has no master password and no vault recovery code.
pub(super) fn refuse_linked(inner: &Inner) -> Result<()> {
    if inner.account.is_some() {
        Err(PassError::InvalidInput(tr!("vault.linked_no_password")))
    } else {
        Ok(())
    }
}

/// A linked vault's file doesn't open with a master password.
pub(super) fn refuse_linked_file(file: &VaultFile) -> Result<()> {
    if file.is_linked() {
        Err(PassError::InvalidInput(tr!("vault.opens_with_account")))
    } else {
        Ok(())
    }
}

/// Opens a linked file's vault key with `ak`.
pub(super) fn open_slot(file: &VaultFile, ak: &AccountKey) -> Result<Key> {
    let slot = file
        .account
        .as_ref()
        .ok_or_else(|| PassError::InvalidInput(tr!("vault.not_linked")))?;
    if slot.account != ak.account_ref() {
        return Err(PassError::InvalidInput(tr!("vault.other_account")));
    }
    if slot.ak_id != ak.ak_id_ref() {
        return Err(PassError::InvalidInput(tr!("vault.other_account_key")));
    }
    let aad = account_vk_aad(&file.vault_id, &slot.account, &slot.ak_id)?;
    let vk = open(ak.key(), &slot.wrapped_key, &aad)?.ok_or(PassError::InvalidPassword)?;
    key_from_vec(&vk)
}

/// The account key from a linked file's recovery copy and the account's recovery code.
pub(super) fn account_key_of_file(file: &VaultFile, recovery_code: &str) -> Result<AccountKey> {
    let slot = file
        .account
        .as_ref()
        .ok_or_else(|| PassError::InvalidInput(tr!("vault.not_linked")))?;
    let copy = file
        .account_recovery
        .as_ref()
        .ok_or_else(|| PassError::NotFound(tr!("vault.no_recovery_code")))?;
    let wrap = AccountWrap {
        nonce: b64url_encode(b64_decode(&copy.wrapped_ak.nonce)?),
        ct: b64url_encode(b64_decode(&copy.wrapped_ak.ct)?),
    };
    account_key::open_recovery(&slot.account, &slot.ak_id, recovery_code, &copy.rec_id, &wrap)
}

/// What `file` opens with, without opening it: the apps pick the unlock screen with it.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn vault_file_access(file: Vec<u8>) -> Result<VaultAccess> {
    let parsed = parse_file(&file)?;
    let kind = if parsed.is_shared() {
        shared::ACCESS_MEMBERS
    } else if parsed.is_linked() {
        ACCESS_ACCOUNT
    } else {
        "password"
    };
    Ok(VaultAccess {
        kind: kind.to_string(),
        account: parsed.account.as_ref().map(|s| s.account.clone()),
        ak_id: parsed.account.as_ref().map(|s| s.ak_id.clone()),
        account_recovery: parsed.account_recovery.is_some(),
    })
}

/// The account key from a copy of a linked vault and the account's recovery code, without the
/// account service (it is gone, or the user has no other way in). `NotFound` if the file carries
/// no recovery copy, `InvalidPassword` for a code that doesn't open it.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn account_key_from_vault_file(file: Vec<u8>, recovery_code: String) -> Result<Arc<AccountKey>> {
    let recovery_code = zeroize::Zeroizing::new(recovery_code);
    let parsed = parse_file(&file)?;
    if !parsed.is_linked() {
        return Err(PassError::InvalidInput(tr!("vault.not_linked")));
    }
    let ak = account_key_of_file(&parsed, &recovery_code)?;
    // The key must also open this vault: a copy whose slot and recovery copy disagree is damaged.
    open_slot(&parsed, &ak)?;
    Ok(Arc::new(ak))
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Vault {
    /// A new, empty vault linked to the account of `account_key` from the start.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn create_for_account(account_key: &AccountKey, device_id: String) -> Result<Arc<Vault>> {
        // A vault with a throwaway password, linked at once: the same code path as linking.
        let throwaway = zeroize::Zeroizing::new(b64url_encode(
            crate::crypto::random_bytes::<16>().to_vec(),
        ));
        let vault = Vault::create_with_kdf(
            &throwaway,
            &device_id,
            KdfParams {
                m_kib: 8,
                t: 1,
                ..KdfParams::default()
            },
        )?;
        vault.link_to_account(account_key)?;
        Ok(vault)
    }

    /// Opens a linked vault file with the account key. `InvalidInput` when the file isn't linked
    /// or is linked to another account or another key of this account (sign in again: the key
    /// was replaced), `InvalidPassword` if the key doesn't open it.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn unlock_with_account_key(
        file: Vec<u8>,
        account_key: &AccountKey,
        device_id: String,
    ) -> Result<Arc<Vault>> {
        let parsed = parse_file(&file)?;
        shared::refuse_shared(&parsed)?;
        let vk = open_slot(&parsed, account_key)?;
        // The slot opened with AK, which only the account's own devices hold: the header is
        // vouched for (and sealed again if it wasn't).
        Vault::from_file(parsed, vk, device_id, true, None)
    }

    /// The account this vault is linked to; `None` for a vault with its own password.
    pub fn account_link(&self) -> Option<VaultAccountLink> {
        let inner = self.lock();
        inner.account.as_ref().map(|slot| VaultAccountLink {
            account: slot.account.clone(),
            ak_id: slot.ak_id.clone(),
            recovery_id: inner.account_recovery.as_ref().map(|r| r.rec_id.clone()),
        })
    }

    /// Links this vault to the account of `account_key`: the vault key is wrapped by the account
    /// key, and the master password slot and the vault recovery code go. The vault key stays, so no
    /// item is re-encrypted and other devices' device keys keep working. Also re-links a linked
    /// vault to a new account key. Copies saved before keep the old master password slot. Save and
    /// sync afterwards.
    pub fn link_to_account(&self, account_key: &AccountKey) -> Result<()> {
        let mut inner = self.lock();
        shared::refuse_password(&inner)?;
        inner.check_writable()?;
        let vault_id = inner.vault_id.clone();
        let aad = account_vk_aad(&vault_id, account_key.account_ref(), account_key.ak_id_ref())?;
        let wrapped_key = seal(account_key.key(), inner.vk.as_slice(), &aad)?;
        // The recovery copy wraps AK: it stays only for the same account key.
        let same_key = inner.account.as_ref().is_some_and(|s| {
            s.account == account_key.account_ref() && s.ak_id == account_key.ak_id_ref()
        });
        if !same_key {
            inner.account_recovery = None;
        }
        inner.account = Some(AccountSlot {
            account: account_key.account_ref().to_string(),
            ak_id: account_key.ak_id_ref().to_string(),
            wrapped_key,
        });
        inner.kdf = shared::stub_kdf();
        inner.wrapped_key = shared::stub_wrapped_key();
        inner.recovery = None;
        inner.bump_header()
    }

    /// Puts the account's current recovery wrap (`rec_id`, `wrap` as the account service gives
    /// it) into this linked vault's header, replacing an older one. Save and sync afterwards.
    pub fn set_account_recovery(&self, rec_id: String, wrap: AccountWrap) -> Result<()> {
        let copy = AccountRecoveryCopy {
            rec_id,
            wrapped_ak: Sealed {
                nonce: b64_encode(&b64url_decode(wrap.nonce)?),
                ct: b64_encode(&b64url_decode(wrap.ct)?),
            },
        };
        let mut inner = self.lock();
        inner.check_writable()?;
        if inner.account.is_none() {
            return Err(PassError::InvalidInput(tr!("vault.not_linked")));
        }
        if inner.account_recovery.as_ref() == Some(&copy) {
            return Ok(());
        }
        inner.account_recovery = Some(copy);
        inner.bump_header()
    }

    /// Removes the recovery copy from this linked vault's header. No change without one.
    pub fn remove_account_recovery(&self) -> Result<()> {
        let mut inner = self.lock();
        inner.check_writable()?;
        if inner.account_recovery.take().is_some() {
            inner.bump_header()?;
        }
        Ok(())
    }

    /// The recovery wrap this linked vault's header carries, as the account service gives it
    /// (`rec_id`, wrap with base64url fields), so a device that never saw the account's current
    /// code can put the same copy into the other vaults it links. `None` without a copy.
    pub fn account_recovery_copy(&self) -> Option<AccountRecoveryWrap> {
        let inner = self.lock();
        let copy = inner.account_recovery.as_ref()?;
        Some(AccountRecoveryWrap {
            rec_id: copy.rec_id.clone(),
            wrap: AccountWrap {
                nonce: b64url_encode(b64_decode(&copy.wrapped_ak.nonce).ok()?),
                ct: b64url_encode(b64_decode(&copy.wrapped_ak.ct).ok()?),
            },
        })
    }

    /// Whether this vault holds the keys for shared vaults (the home vault). The keys stay in it
    /// whether or not it gets a separate password.
    pub fn holds_sharing_keys(&self) -> bool {
        !self.setting_keys(shared::KEYSET_SETTING).is_empty()
    }

    /// Gives this linked vault a separate password: back to a version 1 header wrapped by
    /// `new_password` (default Argon2id parameters), without the account slot and the recovery
    /// copy. The vault key is replaced too, so the account key, an admin enrollment or
    /// an old device copy can't read anything written later. The home vault keeps its sharing keys
    /// ([`Vault::holds_sharing_keys`]). Offer a vault recovery code afterwards; save and sync.
    pub fn unlink_from_account(&self, new_password: String) -> Result<()> {
        let new_password = zeroize::Zeroizing::new(new_password);
        if self.lock().account.is_none() {
            return Err(PassError::InvalidInput(tr!("vault.not_linked")));
        }
        self.rekey(&new_password, KdfParams::default(), true)
    }
}
