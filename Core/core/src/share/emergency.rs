//! Emergency access: the owner of a personal vault names a trusted contact, who can open the vault
//! after a waiting period during which the owner can refuse. The vault key is sealed with HPKE to
//! the contact, then with a key from a release secret the account service holds until the wait
//! ends, so neither can open it alone. The wait is the service's promise, not the crypto's.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use super::keys::{hpke_open, hpke_seal, key_bytes, valid_id, PublicKeys, UserKeyset, KEY_BYTES};
use crate::crypto::{self, Key, KEY_LEN, NONCE_LEN};
use crate::encoding::{b64_decode, b64_encode};
use crate::i18n::tr;
use crate::{PassError, Result};

/// The longest waiting period an owner can choose: 90 days.
pub const EMERGENCY_MAX_WAIT_HOURS: u32 = 90 * 24;

/// What the contact gets once the grant is released.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum EmergencyAccess {
    /// See and copy everything, change nothing. Enforced by the apps and the server (which
    /// refuses the contact's uploads), not by the crypto: the contact's device holds the vault key.
    View,
    /// Everything the owner can do, including setting a new master password (a takeover).
    Full,
}

impl EmergencyAccess {
    pub fn as_str(self) -> &'static str {
        match self {
            EmergencyAccess::View => "view",
            EmergencyAccess::Full => "full",
        }
    }
}

/// One grant as the account service stores it. Nothing in it is secret on its own: the blob
/// opens only with the contact's private key and the release secret together.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct EmergencyGrant {
    /// A new UUID for each grant.
    pub grant_id: String,
    pub vault_id: String,
    /// The owner's account id.
    pub owner: String,
    /// The contact's account id.
    pub contact: String,
    /// Fingerprint of the contact's keys the owner confirmed.
    pub contact_fingerprint: String,
    pub access: EmergencyAccess,
    /// How long the service waits after the contact asks, for the owner to refuse (1 hour to
    /// [`EMERGENCY_MAX_WAIT_HOURS`]).
    pub wait_hours: u32,
    pub created_at: i64,
    /// HMAC-SHA256 of the grant with the vault key: tells the owner's app whether the grant
    /// still holds the current key ([`crate::Vault::emergency_grant_current`]), and nobody else
    /// anything.
    pub key_check: String,
    /// The sealed vault key, base64 (opaque for the service).
    pub blob: String,
}

/// A new grant and its release secret, from [`crate::Vault::emergency_grant`]. Both go to the
/// account service; the secret is the part it must keep to itself until the release.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct EmergencyGrantCreated {
    pub grant: EmergencyGrant,
    /// The release secret, base64 (32 random bytes). Never shown and not kept on the owner's
    /// device.
    pub release_secret: String,
}

/// Never the release secret in debug output.
impl std::fmt::Debug for EmergencyGrantCreated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmergencyGrantCreated")
            .field("grant", &self.grant)
            .finish_non_exhaustive()
    }
}

/// What the HPKE seal holds.
#[derive(Serialize, Deserialize)]
struct Payload {
    v: u32,
    grant_id: String,
    vault_id: String,
    owner: String,
    contact: String,
    access: EmergencyAccess,
    /// The vault key, base64.
    vk: String,
}

impl Drop for Payload {
    fn drop(&mut self) {
        self.vk.zeroize();
    }
}

fn damaged() -> PassError {
    PassError::Crypto(tr!("emergency.damaged"))
}

fn internal() -> PassError {
    PassError::Crypto(tr!("error.internal"))
}

/// `HMAC-SHA256(vk, "pass/emergency-key/v1:" + JSON[grant_id, vault_id])`, base64.
pub(crate) fn key_check(vk: &Key, grant_id: &str, vault_id: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(vk.as_slice()).expect("any key length");
    mac.update(b"pass/emergency-key/v1:");
    mac.update(&serde_json::to_vec(&(grant_id, vault_id)).expect("strings"));
    b64_encode(&mac.finalize().into_bytes())
}

/// HPKE `info` of the inner seal: `"pass/emergency-vk/v1:" + JSON[grant_id, vault_id, owner,
/// contact]`.
fn vk_info(g: &EmergencyGrant) -> Vec<u8> {
    let mut info = b"pass/emergency-vk/v1:".to_vec();
    info.extend(
        serde_json::to_vec(&(&g.grant_id, &g.vault_id, &g.owner, &g.contact)).expect("strings"),
    );
    info
}

/// AAD of the outer seal: every field of the grant but the blob, so the service can't change
/// what the owner chose without the contact noticing.
fn blob_aad(g: &EmergencyGrant) -> Result<Vec<u8>> {
    let mut aad = b"pass/emergency/v1:".to_vec();
    aad.extend(
        serde_json::to_vec(&(
            &g.grant_id,
            &g.vault_id,
            &g.owner,
            &g.contact,
            &g.contact_fingerprint,
            g.access,
            g.wait_hours,
            g.created_at,
            &g.key_check,
        ))
        .map_err(|_| internal())?,
    );
    Ok(aad)
}

/// The outer key: HKDF-SHA256 of the release secret, salt `"pass/emergency-release/v1"`, info
/// the grant id.
fn release_key(secret: &[u8; KEY_LEN], grant_id: &str) -> Key {
    let mut okm = Key::zeroed();
    Hkdf::<Sha256>::new(Some(b"pass/emergency-release/v1"), secret)
        .expand(grant_id.as_bytes(), &mut okm[..])
        .expect("32 bytes is a valid length");
    okm
}

/// Seals `vk` (the vault `vault_id` of `owner`) for `contact`, with a fresh release secret.
pub(crate) fn seal_grant(
    vk: &Key,
    vault_id: &str,
    owner: &str,
    contact: &PublicKeys,
    access: EmergencyAccess,
    wait_hours: u32,
    now: i64,
) -> Result<EmergencyGrantCreated> {
    if !valid_id(owner) {
        return Err(PassError::InvalidInput(tr!("share.bad_account")));
    }
    contact.verify()?;
    if contact.account == owner {
        return Err(PassError::InvalidInput(tr!("emergency.not_yourself")));
    }
    if !(1..=EMERGENCY_MAX_WAIT_HOURS).contains(&wait_hours) {
        return Err(PassError::InvalidInput(tr!(
            "emergency.bad_wait",
            days = EMERGENCY_MAX_WAIT_HOURS / 24
        )));
    }
    let grant_id = uuid::Uuid::new_v4().to_string();
    let mut grant = EmergencyGrant {
        key_check: key_check(vk, &grant_id, vault_id),
        grant_id,
        vault_id: vault_id.to_string(),
        owner: owner.to_string(),
        contact: contact.account.clone(),
        contact_fingerprint: contact.fingerprint(),
        access,
        wait_hours,
        created_at: now,
        blob: String::new(),
    };
    let payload = Payload {
        v: 1,
        grant_id: grant.grant_id.clone(),
        vault_id: grant.vault_id.clone(),
        owner: grant.owner.clone(),
        contact: grant.contact.clone(),
        access,
        vk: b64_encode(vk.as_slice()),
    };
    let plain = Zeroizing::new(serde_json::to_vec(&payload).map_err(|_| internal())?);
    let (encapped, ct) = hpke_seal(&key_bytes(&contact.enc_pub)?, &vk_info(&grant), &plain)?;
    let mut inner = encapped;
    inner.extend_from_slice(&ct);
    let secret = Zeroizing::new(crypto::random_bytes::<KEY_LEN>());
    let outer = release_key(&secret, &grant.grant_id);
    let (nonce, sealed) = crypto::seal(&outer, &inner, &blob_aad(&grant)?)?;
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&sealed);
    grant.blob = b64_encode(&blob);
    Ok(EmergencyGrantCreated {
        grant,
        release_secret: b64_encode(secret.as_slice()),
    })
}

/// Opens a released grant with the contact's keyset: the vault key and the access.
pub(crate) fn open_grant(
    grant: &EmergencyGrant,
    release_secret: &str,
    contact: &UserKeyset,
) -> Result<(Key, EmergencyAccess)> {
    if grant.contact != contact.account() {
        return Err(PassError::InvalidInput(tr!("emergency.not_for_you")));
    }
    let secret = Zeroizing::new(b64_decode(release_secret).unwrap_or_default());
    let secret: &[u8; KEY_LEN] = secret
        .as_slice()
        .try_into()
        .map_err(|_| PassError::Crypto(tr!("emergency.locked")))?;
    let blob = b64_decode(&grant.blob).map_err(|_| damaged())?;
    if blob.len() < NONCE_LEN + KEY_BYTES {
        return Err(damaged());
    }
    let outer = release_key(secret, &grant.grant_id);
    let inner = crypto::open(
        &outer,
        &blob[..NONCE_LEN],
        &blob[NONCE_LEN..],
        &blob_aad(grant)?,
    )
    .ok_or_else(|| PassError::Crypto(tr!("emergency.locked")))?;
    if inner.len() < KEY_BYTES {
        return Err(damaged());
    }
    let plain = hpke_open(
        contact.enc_secret(),
        &vk_info(grant),
        &inner[..KEY_BYTES],
        &inner[KEY_BYTES..],
    )
    .ok_or_else(damaged)?;
    let payload: Payload = serde_json::from_slice(&plain).map_err(|_| damaged())?;
    if payload.v != 1
        || payload.grant_id != grant.grant_id
        || payload.vault_id != grant.vault_id
        || payload.owner != grant.owner
        || payload.contact != grant.contact
        || payload.access != grant.access
    {
        return Err(damaged());
    }
    let vk = Zeroizing::new(b64_decode(&payload.vk).map_err(|_| damaged())?);
    let vk: [u8; KEY_LEN] = vk.as_slice().try_into().map_err(|_| damaged())?;
    let vk = Key::from_array(vk);
    if !crypto::ct_eq(
        key_check(&vk, &grant.grant_id, &grant.vault_id).as_bytes(),
        grant.key_check.as_bytes(),
    ) {
        return Err(damaged());
    }
    Ok((vk, payload.access))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(access: EmergencyAccess) -> (Key, UserKeyset, EmergencyGrantCreated) {
        let vk = crypto::random_key();
        let contact = UserKeyset::generate("acc_carol").unwrap();
        let made = seal_grant(
            &vk,
            "vault-1",
            "acc_olivia",
            &contact.public_keys(),
            access,
            48,
            1_730_000_000_000,
        )
        .unwrap();
        (vk, contact, made)
    }

    #[test]
    fn the_contact_opens_a_released_grant_and_nobody_else_does() {
        let (vk, carol, made) = grant(EmergencyAccess::View);
        let (opened, access) = open_grant(&made.grant, &made.release_secret, &carol).unwrap();
        assert_eq!(opened.as_slice(), vk.as_slice());
        assert_eq!(access, EmergencyAccess::View);
        assert_eq!(made.grant.contact_fingerprint, carol.fingerprint());
        assert!(!format!("{made:?}").contains(&made.release_secret));

        // The contact without the release secret (before the release).
        let wrong = b64_encode(&[7u8; 32]);
        assert!(open_grant(&made.grant, &wrong, &carol).is_err());
        assert!(open_grant(&made.grant, "", &carol).is_err());
        // The service with the secret but without the contact's private key: another keyset
        // under the contact's account id can't open the inner seal.
        let impostor = UserKeyset::generate("acc_carol").unwrap();
        assert!(open_grant(&made.grant, &made.release_secret, &impostor).is_err());
        // Another account is told the grant isn't theirs.
        let dave = UserKeyset::generate("acc_dave").unwrap();
        assert!(open_grant(&made.grant, &made.release_secret, &dave).is_err());
    }

    #[test]
    fn the_service_cannot_change_what_the_owner_chose() {
        let (_, carol, made) = grant(EmergencyAccess::View);
        let mut full = made.grant.clone();
        full.access = EmergencyAccess::Full;
        assert!(open_grant(&full, &made.release_secret, &carol).is_err());
        let mut shorter = made.grant.clone();
        shorter.wait_hours = 1;
        assert!(open_grant(&shorter, &made.release_secret, &carol).is_err());
        let mut other_vault = made.grant.clone();
        other_vault.vault_id = "vault-2".into();
        assert!(open_grant(&other_vault, &made.release_secret, &carol).is_err());
        // A blob moved from another grant (same contact) doesn't open under this grant's id.
        let (_, _, second) = grant(EmergencyAccess::Full);
        let mut moved = made.grant.clone();
        moved.blob = second.grant.blob.clone();
        assert!(open_grant(&moved, &second.release_secret, &carol).is_err());
    }

    #[test]
    fn grants_check_their_inputs() {
        let vk = crypto::random_key();
        let olivia = UserKeyset::generate("acc_olivia").unwrap();
        let carol = UserKeyset::generate("acc_carol").unwrap().public_keys();
        let seal = |owner: &str, contact: &PublicKeys, wait: u32| {
            seal_grant(&vk, "v", owner, contact, EmergencyAccess::Full, wait, 0)
        };
        assert!(seal("acc_olivia", &olivia.public_keys(), 24).is_err());
        assert!(seal("acc_olivia", &carol, 0).is_err());
        assert!(seal("acc_olivia", &carol, EMERGENCY_MAX_WAIT_HOURS + 1).is_err());
        assert!(seal("bad id", &carol, 24).is_err());
        let mut forged = carol.clone();
        forged.account = "acc_mallory".into();
        assert!(seal("acc_olivia", &forged, 24).is_err());
        assert!(seal("acc_olivia", &carol, EMERGENCY_MAX_WAIT_HOURS).is_ok());
    }
}
