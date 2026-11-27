//! Shared vaults: Family and Teams vaults, department vaults and direct shares. A shared vault is
//! an ordinary vault whose key is wrapped with HPKE for each member's keyset ([`UserKeyset`])
//! instead of a master password, under a members list that a manager signs.

pub(crate) mod contacts;
pub(crate) mod emergency;
pub(crate) mod keys;
pub(crate) mod members;
pub(crate) mod org_recovery;

use serde::{Deserialize, Serialize};

pub use contacts::{ContactPin, PinProblem, PinSource, PinStatus, ORG_SCOPE_PREFIX, PERSONAL_SCOPE};
pub use emergency::{EmergencyAccess, EmergencyGrant, EmergencyGrantCreated};
pub use keys::{public_keys_fingerprint, public_keys_verify, PublicKeys, UserKeyset};
pub(crate) use members::CertRef;
pub use org_recovery::{
    admin_recovery_approve, admin_recovery_request, org_recovery_create, org_recovery_rewrap,
    org_recovery_verify, recovery_request_code, AdminRecoveryUse, AdminWrap, OrgKind,
    OrgRecoveryKey, RecoveryApproval,
    RecoveryEnrollment, RecoveryRequest, RecoveryRequestPublic,
};

/// What a member may do in a shared vault. Ordered from the most to the least access.
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberRole {
    /// Edit, and add or remove people (sign the members list).
    Manage,
    /// Add, change and delete items.
    Edit,
    /// See everything, change nothing. The file's host refuses a viewer's upload; the vault key
    /// itself can't tell a viewer from an editor.
    View,
    /// Use logins without seeing their passwords. Enforced by the apps only: the device holds the
    /// vault key, so a modified app could read everything.
    Fill,
}

impl MemberRole {
    pub fn as_str(self) -> &'static str {
        match self {
            MemberRole::Manage => "manage",
            MemberRole::Edit => "edit",
            MemberRole::View => "view",
            MemberRole::Fill => "fill",
        }
    }

    /// A role as written in a members list. An unknown role (from a later version) is read as
    /// the least access, [`MemberRole::Fill`].
    pub fn parse(s: &str) -> MemberRole {
        match s {
            "manage" => MemberRole::Manage,
            "edit" => MemberRole::Edit,
            "view" => MemberRole::View,
            _ => MemberRole::Fill,
        }
    }

    /// May add, change and delete items.
    pub fn can_edit(self) -> bool {
        matches!(self, MemberRole::Manage | MemberRole::Edit)
    }

    /// May see and copy passwords and other secrets (not [`MemberRole::Fill`]).
    pub fn can_reveal(self) -> bool {
        self != MemberRole::Fill
    }

    /// May change the members list.
    pub fn can_manage(self) -> bool {
        self == MemberRole::Manage
    }
}

/// What kind of shared vault it is, for the apps' wording.
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedKind {
    /// An organisation's shared vault: a department vault of a team, or a family's vault.
    Org,
    /// A few people sharing with each other ("Shared with Bob"), usually two members.
    Direct,
}

impl SharedKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SharedKind::Org => "org",
            SharedKind::Direct => "direct",
        }
    }

    /// An unknown kind (from a later version) reads as [`SharedKind::Org`].
    pub fn parse(s: &str) -> SharedKind {
        match s {
            "direct" => SharedKind::Direct,
            _ => SharedKind::Org,
        }
    }
}

/// One member as the apps show it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MemberInfo {
    pub account: String,
    pub role: MemberRole,
    /// The group the member was added through ("via Engineering"), if any.
    pub group: Option<String>,
    /// Fingerprint of the member's keys, to compare with them.
    pub fingerprint: String,
    pub added_by: String,
    pub added_at: i64,
}

/// A shared vault's members list and this device's place in it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SharedInfo {
    pub vault_id: String,
    pub kind: SharedKind,
    /// The organisation it belongs to, if the creator named one.
    pub org: Option<String>,
    pub created_by: String,
    pub created_at: i64,
    /// Bumped with every list change; `key_epoch` with every key rotation.
    pub epoch: u64,
    pub key_epoch: u64,
    /// Who signed the current list.
    pub signed_by: String,
    /// This device's account and its role.
    pub account: String,
    pub role: MemberRole,
    /// Every member, sorted by account.
    pub members: Vec<MemberInfo>,
    /// `false` when the list could not be traced back to the vault's creation (first open on this
    /// device): the app should show the signer and fingerprint before the user relies on it.
    pub anchored: bool,
    /// Fingerprint of the signer's keys ([`Self::signed_by`]), to compare with them. `None` when
    /// the signer is no longer in the list; the app then shows the current managers' fingerprints.
    pub signer_fingerprint: Option<String>,
}

impl SharedInfo {
    /// The other members of a direct share, for "Shared with Bob".
    pub fn others(&self) -> impl Iterator<Item = &MemberInfo> {
        self.members.iter().filter(|m| m.account != self.account)
    }
}

/// One change to a members list; [`crate::Vault::change_members`] applies several at once
/// under one signature. JSON (WebAssembly): `{"op": "add", "keys", "role", "group"}`, `{"op":
/// "set_role", "account", "role"}`, `{"op": "set_group", "account", "group"}`, `{"op":
/// "replace_keys", "keys"}`, `{"op": "remove", "account"}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum MemberChange {
    /// Adds an account with keys the manager has confirmed, optionally on behalf of a group.
    Add {
        keys: PublicKeys,
        role: MemberRole,
        group: Option<String>,
    },
    SetRole {
        account: String,
        role: MemberRole,
    },
    SetGroup {
        account: String,
        group: Option<String>,
    },
    /// The member set up new keys (a lost home vault). Rotates the vault key, as the old private
    /// key may be in someone else's hands.
    ReplaceKeys {
        keys: PublicKeys,
    },
    /// Removes the member and rotates the vault key. A manager may remove themselves (leave)
    /// while another manager remains; see [`crate::Vault::leave_shared`].
    Remove {
        account: String,
    },
}

/// One member of a group (a department) as the account service lists it, with the keys the
/// manager confirmed: [`crate::Vault::sync_group`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct GroupMember {
    pub keys: PublicKeys,
    pub role: MemberRole,
}

/// What a merge or an open did to the members list on this device's behalf, for a notice
/// ("Your change to Engineering was applied again"): [`crate::Vault::take_members_notice`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MembersNotice {
    /// Changes that lost to a concurrent list and were applied again on top of the winner. Save
    /// and upload the vault.
    pub reapplied: Vec<MemberChange>,
    /// Changes that lost and could not be applied again (no longer a manager, or the change no
    /// longer makes sense). The app tells the user.
    pub dropped: Vec<MemberChange>,
    /// The vault key was rotated because the current list was signed by a manager who left (their
    /// device made the key it replaces). Save and upload the vault.
    pub rotated_after_leave: bool,
}

impl MembersNotice {
    pub(crate) fn is_empty(&self) -> bool {
        self.reapplied.is_empty() && self.dropped.is_empty() && !self.rotated_after_leave
    }

    pub(crate) fn absorb(&mut self, other: MembersNotice) {
        self.reapplied.extend(other.reapplied);
        self.dropped.extend(other.dropped);
        self.rotated_after_leave |= other.rotated_after_leave;
    }
}

/// What a device remembers about a shared vault between opens, so a host can't hand it an older
/// members list (a removed member put back) or another vault under the same id: the vault's
/// genesis and the lists it accepted, the newest last. Kept in the home vault's settings
/// ([`crate::Vault::remember_share_trust`]), so the user's other devices know it too.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareTrust {
    pub vault_id: String,
    /// Digest of the vault's genesis.
    pub genesis: String,
    pub(crate) path: Vec<CertRef>,
}

impl ShareTrust {
    /// Epoch of the newest list accepted.
    pub fn epoch(&self) -> u64 {
        self.path.last().map_or(0, |c| c.epoch)
    }

    pub fn key_epoch(&self) -> u64 {
        self.path.last().map_or(0, |c| c.key_epoch)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("plain strings and numbers")
    }

    pub fn from_json(json: &str) -> crate::Result<ShareTrust> {
        serde_json::from_str(json)
            .map_err(|_| crate::PassError::InvalidInput(crate::i18n::tr!("share.bad_trust")))
    }

    /// Whether `self` is ahead of `other` ([`CertRef::order`]), for keeping the newer of two.
    pub(crate) fn ahead_of(&self, other: &ShareTrust) -> bool {
        match (self.path.last(), other.path.last()) {
            (Some(a), Some(b)) => a.order() > b.order(),
            (Some(_), None) => true,
            _ => false,
        }
    }
}
