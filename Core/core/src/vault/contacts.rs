//! Pinned contact keys in the home vault ([`crate::share::contacts`]): what the user verified,
//! and the checks every key wrap to another person goes through.

use sha2::{Digest, Sha256};

use super::{PassError, Result, Vault};
use crate::encoding::hex;
use crate::i18n::tr;
use crate::now_ms;
use crate::share::contacts::{
    normalize_fingerprint, valid_scope, ContactPin, PinProblem, PinSource, PinStatus,
    PERSONAL_SCOPE,
};
use crate::share::keys::{key_bytes, PublicKeys};
use crate::share::MemberChange;

/// Prefix of a pin's setting; the rest is a hash of the account and the scope.
const PIN_SETTING: &str = "contacts.pin.v1.";

fn pin_setting(account: &str, scope: &str) -> String {
    let mut h = Sha256::new();
    h.update(account.as_bytes());
    h.update([0u8]);
    h.update(scope.as_bytes());
    format!("{PIN_SETTING}{}", &hex(&h.finalize())[..40])
}

fn bad_scope() -> PassError {
    PassError::InvalidInput(tr!("share.bad_scope"))
}

/// The error for a change that would wrap a key to unverified keys.
pub(crate) fn unpinned_error(problem: &PinProblem) -> PassError {
    match &problem.status {
        PinStatus::Changed { .. } => PassError::Crypto(tr!(
            "share.keys_changed",
            account = problem.account.as_str()
        )),
        _ => PassError::Crypto(tr!(
            "share.keys_not_verified",
            account = problem.account.as_str()
        )),
    }
}

/// The pinned contact keys (a personal vault only: the home vault).
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Vault {
    /// Every pin kept here, sorted by account then scope.
    pub fn contact_pins(&self) -> Vec<ContactPin> {
        let mut out: Vec<ContactPin> = self
            .setting_keys(PIN_SETTING)
            .into_iter()
            .filter_map(|k| {
                let pin: ContactPin = serde_json::from_str(&self.setting(&k)?).ok()?;
                (pin_setting(&pin.account, &pin.scope) == k).then_some(pin)
            })
            .collect();
        out.sort_by(|a, b| (&a.account, &a.scope).cmp(&(&b.account, &b.scope)));
        out
    }

    /// The pin of `account` for `scope`, if the user verified their keys.
    pub fn contact_pin(&self, account: &str, scope: &str) -> Option<ContactPin> {
        let json = self.setting(&pin_setting(account, scope))?;
        let pin: ContactPin = serde_json::from_str(&json).ok()?;
        (pin.account == account && pin.scope == scope).then_some(pin)
    }

    /// What the pins say about `keys` (scope `scope`): pinned, not pinned, or changed. The user's
    /// own keys (any keyset kept in this vault) count as pinned. `InvalidInput` for keys whose
    /// self-signature doesn't verify, or for an unknown scope.
    pub fn contact_pin_status(&self, keys: PublicKeys, scope: &str) -> Result<PinStatus> {
        if !valid_scope(scope) {
            return Err(bad_scope());
        }
        keys.verify()?;
        Ok(self.status_of(&keys.account, scope, &keys.enc_pub, &keys.sig_pub))
    }

    /// Pins `keys` for `scope` after the user compared `compared` (as typed or read, dashes and
    /// case don't matter) with the person: `Crypto` if it isn't these keys' fingerprint. Replaces
    /// an older pin of the same person (their keys changed and the user compared the new ones);
    /// the old fingerprint is kept as [`ContactPin::previous_fingerprint`]. Only in a personal
    /// vault. Save afterwards.
    pub fn pin_contact(&self, keys: PublicKeys, scope: &str, compared: &str) -> Result<ContactPin> {
        if self.is_shared() {
            return Err(PassError::InvalidInput(tr!("share.keys_in_shared")));
        }
        if !valid_scope(scope) {
            return Err(bad_scope());
        }
        keys.verify()?;
        let fingerprint = keys.fingerprint();
        if normalize_fingerprint(compared) != normalize_fingerprint(&fingerprint) {
            return Err(PassError::Crypto(tr!("share.fingerprint_mismatch")));
        }
        let kept = self.contact_pin(&keys.account, scope);
        if let Some(kept) = kept.as_ref().filter(|k| k.fingerprint == fingerprint) {
            return Ok(kept.clone());
        }
        let pin = ContactPin {
            account: keys.account.clone(),
            scope: scope.to_string(),
            fingerprint,
            enc_pub: keys.enc_pub,
            sig_pub: keys.sig_pub,
            pinned_at: now_ms(),
            source: PinSource::Compared,
            previous_fingerprint: kept.map(|p| p.fingerprint),
        };
        let json =
            serde_json::to_string(&pin).map_err(|_| PassError::Crypto(tr!("error.internal")))?;
        self.put_setting(&pin_setting(&pin.account, scope), Some(json))?;
        Ok(pin)
    }

    /// Forgets the pin of `account` for `scope` (the person left, or the user wants to compare
    /// again). Save afterwards.
    pub fn unpin_contact(&self, account: &str, scope: &str) -> Result<()> {
        if !valid_scope(scope) {
            return Err(bad_scope());
        }
        self.put_setting(&pin_setting(account, scope), None)?;
        Ok(())
    }

    /// The changes in `changes` that would wrap a vault key to keys this user hasn't verified
    /// (personal scope): every `Add` and `ReplaceKeys` whose keys aren't pinned. Empty when all is
    /// verified; [`Vault::change_members_pinned`] refuses them.
    pub fn unpinned_changes(&self, changes: Vec<MemberChange>) -> Vec<PinProblem> {
        changes
            .iter()
            .filter_map(|c| match c {
                MemberChange::Add { keys, .. } | MemberChange::ReplaceKeys { keys } => Some(keys),
                _ => None,
            })
            .filter_map(|keys| {
                let status =
                    self.status_of(&keys.account, PERSONAL_SCOPE, &keys.enc_pub, &keys.sig_pub);
                (status != PinStatus::Pinned).then(|| PinProblem {
                    account: keys.account.clone(),
                    fingerprint: keys.fingerprint(),
                    status,
                })
            })
            .collect()
    }

    /// What the pins say about the manager who signed `shared`'s current members list, shown on a
    /// first open. `None` for a personal vault or a signer no longer in the list.
    pub fn shared_signer_status(&self, shared: &Vault) -> Option<PinStatus> {
        let (account, enc_pub, sig_pub) = shared.signer_keys()?;
        Some(self.status_of(&account, PERSONAL_SCOPE, &enc_pub, &sig_pub))
    }
}

impl Vault {
    /// [`PinStatus`] of the public keys `enc_pub`, `sig_pub` (base64) of `account`.
    pub(crate) fn status_of(
        &self,
        account: &str,
        scope: &str,
        enc_pub: &str,
        sig_pub: &str,
    ) -> PinStatus {
        let (Ok(enc), Ok(sig)) = (key_bytes(enc_pub), key_bytes(sig_pub)) else {
            return PinStatus::NotPinned;
        };
        let offered = crate::share::keys::fingerprint(&enc, &sig);
        if scope == PERSONAL_SCOPE && self.is_own_keys(&enc, &sig) {
            return PinStatus::Pinned;
        }
        match self.contact_pin(account, scope) {
            Some(pin) if pin.fingerprint == offered => PinStatus::Pinned,
            Some(pin) => PinStatus::Changed {
                pinned_fingerprint: pin.fingerprint,
            },
            None => PinStatus::NotPinned,
        }
    }

    /// `Ok` when `keys` are pinned (or the user's own), else the error for the app to show.
    pub(crate) fn require_pinned(&self, keys: &PublicKeys, scope: &str) -> Result<()> {
        keys.verify()?;
        match self.status_of(&keys.account, scope, &keys.enc_pub, &keys.sig_pub) {
            PinStatus::Pinned => Ok(()),
            status => Err(unpinned_error(&PinProblem {
                account: keys.account.clone(),
                fingerprint: keys.fingerprint(),
                status,
            })),
        }
    }
}

/// A home vault with `people` pinned, for the core's unit tests.
#[cfg(test)]
pub(crate) fn test_home_pinning(people: &[PublicKeys]) -> std::sync::Arc<Vault> {
    let kdf = crate::KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
        ..Default::default()
    };
    let home = Vault::create_with_kdf("demo master", "home", kdf).unwrap();
    for keys in people {
        home.pin_contact(keys.clone(), PERSONAL_SCOPE, &keys.fingerprint())
            .unwrap();
    }
    home
}
