//! The vault side of emergency access and admin-assisted recovery: granting and opening,
//! enrolling and recovering. The cryptography is in `share::emergency` and `share::org_recovery`.

use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::{check_key, parse_file, shared, PassError, Result, Vault};
use crate::crypto;
use crate::encoding::hex;
use crate::i18n::tr;
use crate::now_ms;
use crate::share::emergency::{self, EmergencyAccess, EmergencyGrant, EmergencyGrantCreated};
use crate::share::org_recovery::{
    self, AdminRecoveryUse, OrgKind, OrgRecoveryKey, RecoveryApproval, RecoveryEnrollment,
};
use crate::share::{PublicKeys, UserKeyset};

/// Prefix of the vault setting that records an enrollment in admin-assisted recovery; the rest is
/// a hash of the organisation id.
const ENROLLMENT_SETTING: &str = "org.recovery.v1.";
/// The vault setting with the log of admin-assisted recoveries.
const RECOVERY_LOG_SETTING: &str = "org.recovery.log.v1";
/// Entries kept in that log, the newest last.
const MAX_RECOVERY_LOG: usize = 50;

/// An enrollment as the vault remembers it, so the apps can show "Admin recovery: on".
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AdminRecoveryStatus {
    pub org: String,
    pub key_id: String,
    pub enrolled_at: i64,
}

fn enrollment_setting(org: &str) -> String {
    format!(
        "{ENROLLMENT_SETTING}{}",
        &hex(&Sha256::digest(org.as_bytes()))[..32]
    )
}

fn personal_only(vault: &Vault) -> Result<()> {
    if vault.is_shared() {
        return Err(PassError::InvalidInput(tr!("emergency.personal_only")));
    }
    Ok(())
}

/// Emergency access.
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Vault {
    /// A grant of emergency access to this vault (a personal vault) for `contact`, whose keys
    /// the owner confirmed (fingerprint), with `access` after `wait_hours` (1 hour to 90 days)
    /// without a refusal. `owner` is this user's account id. Send the grant and its release
    /// secret to the account service; nothing changes in the vault, and nothing needs saving.
    pub fn emergency_grant(
        &self,
        owner: &str,
        contact: PublicKeys,
        access: EmergencyAccess,
        wait_hours: u32,
    ) -> Result<EmergencyGrantCreated> {
        personal_only(self)?;
        let (vk, vault_id) = {
            let inner = self.lock();
            inner.check_writable()?;
            (inner.vk.clone(), inner.vault_id.clone())
        };
        emergency::seal_grant(
            &vk,
            &vault_id,
            owner,
            &contact,
            access,
            wait_hours,
            now_ms(),
        )
    }

    /// Whether `grant` still holds this vault's key: `false` after a new master password with
    /// a new key, or for another vault's grant. The apps set stale grants up again.
    pub fn emergency_grant_current(&self, grant: EmergencyGrant) -> bool {
        let inner = self.lock();
        grant.vault_id == inner.vault_id
            && crypto::ct_eq(
                emergency::key_check(&inner.vk, &grant.grant_id, &grant.vault_id).as_bytes(),
                grant.key_check.as_bytes(),
            )
    }

    /// The contact opens the owner's vault `file` with a released grant (the release secret from
    /// the account service and the contact's keyset). [`EmergencyAccess::View`] opens it read-only
    /// ([`Vault::is_read_only`]); [`EmergencyAccess::Full`] lets the contact edit it and set a new
    /// master password ([`Vault::change_master_password`]), or, for a linked vault, link it
    /// to their own account ([`Vault::link_to_account`]). The contact never gets the owner's
    /// account key, but the owner's keyset is in the vault's settings, so full access also reaches
    /// the owner's shared vaults once the account service lets the contact download them.
    ///
    /// Errors: `Crypto` "not released yet" for a wrong or missing release secret, "damaged";
    /// `InvalidInput` for another account's grant, another vault's file or a shared vault; `Crypto`
    /// "stale" when the owner changed the vault key since.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn open_emergency(
        file: Vec<u8>,
        grant: EmergencyGrant,
        release_secret: &str,
        contact: &UserKeyset,
        device_id: &str,
    ) -> Result<Arc<Vault>> {
        let (vk, access) = emergency::open_grant(&grant, release_secret, contact)?;
        let parsed = parse_file(&file)?;
        if parsed.is_shared() {
            return Err(PassError::InvalidInput(tr!("emergency.personal_only")));
        }
        if parsed.vault_id != grant.vault_id {
            return Err(PassError::InvalidInput(tr!("emergency.wrong_vault")));
        }
        if check_key(&parsed, &vk).is_err() {
            return Err(PassError::Crypto(tr!("emergency.stale")));
        }
        let vault = Self::from_file(parsed, vk, device_id.to_string(), false, None)?;
        vault.lock().read_only = access == EmergencyAccess::View;
        Ok(vault)
    }

    /// Whether this vault was opened for viewing only (emergency access with view rights):
    /// edits, settings, a new master password and recovery codes are refused.
    pub fn is_read_only(&self) -> bool {
        self.lock().read_only
    }
}

/// Admin-assisted recovery, Teams and Families.
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Vault {
    /// Opts this vault (the member's home vault) in to admin-assisted recovery by the organisation
    /// `key.org`: checks that `key` was made by `creator`, an admin whose keys the member verified
    /// (pinned here; `Crypto` otherwise), wraps the vault key to it
    /// and records the enrollment. Upload the returned enrollment to the account service, and save.
    /// Refused for a shared vault. Enrolling again (a new organisation key) replaces the record.
    pub fn admin_recovery_enroll(
        &self,
        key: OrgRecoveryKey,
        creator: PublicKeys,
        account: &str,
        kind: OrgKind,
    ) -> Result<RecoveryEnrollment> {
        personal_only(self)?;
        self.require_pinned(&creator, crate::PERSONAL_SCOPE)?;
        let (vk, vault_id) = {
            let inner = self.lock();
            inner.check_writable()?;
            (inner.vk.clone(), inner.vault_id.clone())
        };
        let enrollment = org_recovery::enroll(&vk, &vault_id, account, &key, &creator, kind)?;
        let status = AdminRecoveryStatus {
            org: enrollment.org.clone(),
            key_id: enrollment.key_id.clone(),
            enrolled_at: enrollment.created_at,
        };
        self.put_setting(
            &enrollment_setting(&enrollment.org),
            Some(
                serde_json::to_string(&status)
                    .map_err(|_| PassError::Crypto(tr!("error.internal")))?,
            ),
        )?;
        Ok(enrollment)
    }

    /// The organisations this vault is enrolled with for admin-assisted recovery.
    pub fn admin_recovery_enrollments(&self) -> Vec<AdminRecoveryStatus> {
        let mut out: Vec<AdminRecoveryStatus> = self
            .setting_keys(ENROLLMENT_SETTING)
            .into_iter()
            .filter_map(|k| self.setting(&k))
            .filter_map(|json| serde_json::from_str(&json).ok())
            .collect();
        out.sort_by(|a, b| a.org.cmp(&b.org));
        out
    }

    /// Opts out: forgets the enrollment with `org` here. The app also asks the account service
    /// to delete its copy, which is what an admin would use. A copy the service kept could
    /// still open this vault key: after opting out, a new master password with a new key
    /// ([`Vault::change_password`] with `rotate_key`) makes it useless.
    pub fn admin_recovery_withdraw(&self, org: &str) -> Result<()> {
        self.put_setting(&enrollment_setting(org), None)?;
        Ok(())
    }

    /// Whether `enrollment` still holds this vault's key (`false` after a new key: enroll again).
    pub fn admin_recovery_enrollment_current(&self, enrollment: RecoveryEnrollment) -> bool {
        let inner = self.lock();
        enrollment.vault_id == inner.vault_id
            && crypto::ct_eq(
                org_recovery::key_check(
                    &inner.vk,
                    &enrollment.org,
                    &enrollment.account,
                    &enrollment.vault_id,
                )
                .as_bytes(),
                enrollment.key_check.as_bytes(),
            )
    }

    /// Opens the member's home vault `file` with an admin's approval of their recovery request:
    /// checks the approval's signature against `approver` (the admin's public keys, whose
    /// fingerprint the app shows), opens the vault key with the request's one-time `secret`, and
    /// records the use in the vault ([`Vault::admin_recovery_log`]). Then the member sets a new
    /// master password ([`Vault::change_master_password`]); save and sync.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn unlock_with_admin_recovery(
        file: Vec<u8>,
        approval: RecoveryApproval,
        secret: &str,
        approver: PublicKeys,
        device_id: &str,
    ) -> Result<Arc<Vault>> {
        let vk = org_recovery::open_approval(&approval, secret, &approver)?;
        let parsed = parse_file(&file)?;
        shared::refuse_shared(&parsed)?;
        if parsed.vault_id != approval.vault_id {
            return Err(PassError::InvalidInput(tr!("emergency.wrong_vault")));
        }
        let vault = Self::from_file(parsed, vk, device_id.to_string(), false, None)?;
        let mut log = vault.admin_recovery_log();
        log.push(AdminRecoveryUse {
            org: approval.org.clone(),
            request_id: approval.request_id.clone(),
            approved_by: approval.approved_by.clone(),
            approver_fingerprint: approver.fingerprint(),
            approved_at: approval.approved_at,
            completed_at: now_ms(),
        });
        if log.len() > MAX_RECOVERY_LOG {
            log.drain(..log.len() - MAX_RECOVERY_LOG);
        }
        vault.put_setting(
            RECOVERY_LOG_SETTING,
            Some(
                serde_json::to_string(&log)
                    .map_err(|_| PassError::Crypto(tr!("error.internal")))?,
            ),
        )?;
        Ok(vault)
    }

    /// Every admin-assisted recovery of this vault, the oldest first (shown in Settings, and as
    /// a notice on the member's other devices after the sync).
    pub fn admin_recovery_log(&self) -> Vec<AdminRecoveryUse> {
        self.setting(RECOVERY_LOG_SETTING)
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default()
    }
}
