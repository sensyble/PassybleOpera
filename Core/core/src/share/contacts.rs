//! Pinned contact keys: the public keys of people and org admins this user has verified. Every
//! place that wraps a key to another person checks that person's keys against these pins first,
//! since a breached account service could hand out its own keys. Pins are home vault settings
//! (last writer wins per pin), so the service never sees them.

use serde::{Deserialize, Serialize};

use super::keys::valid_id;

/// The scope of a person's main keyset (one per person).
pub const PERSONAL_SCOPE: &str = "personal";

/// Prefix of a Team-scoped keyset's scope: `org:` and the Team's group id.
pub const ORG_SCOPE_PREFIX: &str = "org:";

/// Whether `scope` is [`PERSONAL_SCOPE`] or `org:` and a valid group id.
pub(crate) fn valid_scope(scope: &str) -> bool {
    scope == PERSONAL_SCOPE || scope.strip_prefix(ORG_SCOPE_PREFIX).is_some_and(valid_id)
}

/// How a pin was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum PinSource {
    /// The user compared the fingerprint with the person.
    Compared,
    /// Carried over from the person's pinned keys of another scope by a key move statement they
    /// signed.
    KeyMove,
}

/// A person's public keys this user verified, as kept in the home vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ContactPin {
    pub account: String,
    /// [`PERSONAL_SCOPE`] or `org:<group id>`.
    pub scope: String,
    /// `7K3QD-…` ([`crate::public_keys_fingerprint`]).
    pub fingerprint: String,
    /// X25519 public key, base64.
    pub enc_pub: String,
    /// Ed25519 public key, base64.
    pub sig_pub: String,
    /// When the keys were pinned (Unix ms).
    pub pinned_at: i64,
    pub source: PinSource,
    /// The fingerprint this pin replaced, when the person's keys changed and the user compared the
    /// new ones.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_fingerprint: Option<String>,
}

/// What this user's pins say about a person's keys.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum PinStatus {
    /// These are the keys the user compared (or the user's own).
    Pinned,
    /// No pin for this person and scope: compare the fingerprint before wrapping anything.
    NotPinned,
    /// The person's pin has other keys: the service offers keys the user never compared.
    Changed { pinned_fingerprint: String },
}

/// A change to a members list whose keys this user hasn't verified
/// ([`crate::Vault::unpinned_changes`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PinProblem {
    pub account: String,
    /// The fingerprint of the keys the change would wrap to.
    pub fingerprint: String,
    /// [`PinStatus::NotPinned`] or [`PinStatus::Changed`].
    pub status: PinStatus,
}

/// A fingerprint as people type or read it: letters and digits only, upper case (Crockford
/// base32 reads `O` as `0` and `I`, `L` as `1`).
pub(crate) fn normalize_fingerprint(text: &str) -> String {
    text.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_are_personal_or_a_team() {
        assert!(valid_scope(PERSONAL_SCOPE));
        assert!(valid_scope("org:grp_acme"));
        assert!(!valid_scope("org:"));
        assert!(!valid_scope("org:has space"));
        assert!(!valid_scope("work"));
        assert!(!valid_scope(""));
    }

    #[test]
    fn typed_fingerprints_compare_without_dashes_case_or_lookalikes() {
        assert_eq!(normalize_fingerprint("7k3qd-ab0il"), "7K3QDAB011");
        assert_eq!(normalize_fingerprint(" 7K3QD AB011 "), "7K3QDAB011");
        assert_eq!(
            normalize_fingerprint("7K3QD-ABO1L"),
            normalize_fingerprint("7k3qdab011")
        );
    }
}
