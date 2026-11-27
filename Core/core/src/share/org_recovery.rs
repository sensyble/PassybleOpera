//! Admin-assisted recovery for Teams and Families. A member who opts in wraps their home vault key
//! (or account key, as vault `"ak:" + ak_id`) to the organisation's recovery key, whose private
//! half exists only wrapped for each admin. Any admin can then read that vault: that is what opting
//! in means. To recover, an admin rewraps the key to the member's one-time request key and signs it.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::keys::{
    hpke_keypair, hpke_open, hpke_public_of, hpke_seal, key_bytes, valid_enc_pub, valid_id,
    verify_signature, PublicKeys, UserKeyset, KEY_BYTES,
};
use crate::crypto::{Key, KEY_LEN};
use crate::encoding::{b64_decode, b64_encode};
use crate::i18n::tr;
use crate::{now_ms, PassError, Result};

/// The kind of organisation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum OrgKind {
    Team,
    Family,
}

/// The recovery private key wrapped for one admin (HPKE to the admin's keyset).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AdminWrap {
    pub admin: String,
    pub enc: String,
    pub ct: String,
}

/// An organisation's recovery key as the account service stores it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct OrgRecoveryKey {
    pub org: String,
    /// Names this key pair: base64 of the first 16 bytes of SHA-256(`"pass/org-recovery-id/v1:"`
    /// + public key). A new key pair (after an admin left) has a new id, and members re-enroll.
    pub key_id: String,
    /// X25519 public key, base64.
    pub recovery_pub: String,
    pub created_by: String,
    pub created_at: i64,
    /// Ed25519 signature by `created_by` of [`key_message`], base64.
    pub sig: String,
    pub wraps: Vec<AdminWrap>,
}

/// A member's opt-in: their home vault key wrapped to the organisation's recovery key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RecoveryEnrollment {
    pub org: String,
    pub key_id: String,
    pub account: String,
    pub vault_id: String,
    pub created_at: i64,
    /// HMAC-SHA256 with the vault key: whether the enrollment still holds the vault's current
    /// key ([`crate::Vault::admin_recovery_enrollment_current`]).
    pub key_check: String,
    pub enc: String,
    pub ct: String,
}

/// The public part of a recovery request, for the account service and the admin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RecoveryRequestPublic {
    pub request_id: String,
    pub org: String,
    pub account: String,
    pub vault_id: String,
    /// The request's one-time X25519 public key, base64.
    pub enc_pub: String,
    pub created_at: i64,
}

/// A recovery request with its one-time private key ([`admin_recovery_request`]). The app keeps
/// `secret` in secure storage until the approval arrives, then deletes it.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RecoveryRequest {
    pub request: RecoveryRequestPublic,
    /// The one-time X25519 private key, base64.
    pub secret: String,
}

/// Never the request's private key in debug output.
impl std::fmt::Debug for RecoveryRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryRequest")
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

/// An admin's approval: the vault key wrapped to the request key, signed by the admin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RecoveryApproval {
    pub org: String,
    pub key_id: String,
    pub request_id: String,
    pub account: String,
    pub vault_id: String,
    pub request_enc_pub: String,
    pub approved_by: String,
    pub approved_at: i64,
    pub key_check: String,
    pub enc: String,
    pub ct: String,
    /// Ed25519 signature by `approved_by` of [`approval_message`], base64.
    pub sig: String,
}

/// One admin-assisted recovery as the member's vault records it ([`crate::Vault::admin_recovery_log`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AdminRecoveryUse {
    pub org: String,
    pub request_id: String,
    pub approved_by: String,
    /// Fingerprint of the approving admin's keys.
    pub approver_fingerprint: String,
    pub approved_at: i64,
    /// When this device completed it.
    pub completed_at: i64,
}

fn internal() -> PassError {
    PassError::Crypto(tr!("error.internal"))
}

fn invalid() -> PassError {
    PassError::Crypto(tr!("recovery.admin_invalid"))
}

/// The `vault_id` of an account key enrollment: `"ak:" + ak_id`.
pub(crate) const ACCOUNT_KEY_PREFIX: &str = "ak:";

fn json_tail(prefix: &[u8], value: &impl Serialize) -> Result<Vec<u8>> {
    let mut out = prefix.to_vec();
    out.extend(serde_json::to_vec(value).map_err(|_| internal())?);
    Ok(out)
}

/// [`OrgRecoveryKey::key_id`] of `recovery_pub`.
fn key_id_of(recovery_pub: &[u8; KEY_BYTES]) -> String {
    let mut h = Sha256::new();
    h.update(b"pass/org-recovery-id/v1:");
    h.update(recovery_pub);
    b64_encode(&h.finalize()[..16])
}

/// `"pass/org-recovery/v1:" + JSON[org, key_id, recovery_pub, created_by, created_at]`.
fn key_message(k: &OrgRecoveryKey) -> Result<Vec<u8>> {
    json_tail(
        b"pass/org-recovery/v1:",
        &(
            &k.org,
            &k.key_id,
            &k.recovery_pub,
            &k.created_by,
            k.created_at,
        ),
    )
}

fn wrap_info(org: &str, key_id: &str, admin: &str) -> Result<Vec<u8>> {
    json_tail(b"pass/org-recovery-sk/v1:", &(org, key_id, admin))
}

fn enrollment_info(e: &RecoveryEnrollment) -> Result<Vec<u8>> {
    if let Some(ak_id) = e.vault_id.strip_prefix(ACCOUNT_KEY_PREFIX) {
        return json_tail(
            b"pass/org-recovery-ak/v1:",
            &(&e.org, &e.key_id, &e.account, ak_id),
        );
    }
    json_tail(
        b"pass/org-recovery-vk/v1:",
        &(&e.org, &e.key_id, &e.account, &e.vault_id),
    )
}

fn grant_info(a: &RecoveryApproval) -> Result<Vec<u8>> {
    json_tail(
        b"pass/org-recovery-grant/v1:",
        &(
            &a.org,
            &a.request_id,
            &a.account,
            &a.vault_id,
            &a.approved_by,
            a.approved_at,
        ),
    )
}

/// `"pass/org-recovery-use/v1:" + JSON[org, key_id, request_id, account, vault_id,
/// request_enc_pub, approved_by, approved_at, key_check, enc, ct]`.
fn approval_message(a: &RecoveryApproval) -> Result<Vec<u8>> {
    json_tail(
        b"pass/org-recovery-use/v1:",
        &(
            &a.org,
            &a.key_id,
            &a.request_id,
            &a.account,
            &a.vault_id,
            &a.request_enc_pub,
            &a.approved_by,
            a.approved_at,
            &a.key_check,
            &a.enc,
            &a.ct,
        ),
    )
}

/// `HMAC-SHA256(vk, "pass/org-recovery-check/v1:" + JSON[org, account, vault_id])`, base64.
pub(crate) fn key_check(vk: &Key, org: &str, account: &str, vault_id: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(vk.as_slice()).expect("any key length");
    mac.update(b"pass/org-recovery-check/v1:");
    mac.update(&serde_json::to_vec(&(org, account, vault_id)).expect("strings"));
    b64_encode(&mac.finalize().into_bytes())
}

fn wraps_for(
    sk: &[u8; KEY_BYTES],
    org: &str,
    key_id: &str,
    admins: &[PublicKeys],
) -> Result<Vec<AdminWrap>> {
    let mut wraps: Vec<AdminWrap> = Vec::with_capacity(admins.len());
    for admin in admins {
        admin.verify()?;
        if wraps.iter().any(|w| w.admin == admin.account) {
            continue;
        }
        let (enc, ct) = hpke_seal(
            &key_bytes(&admin.enc_pub)?,
            &wrap_info(org, key_id, &admin.account)?,
            sk,
        )?;
        wraps.push(AdminWrap {
            admin: admin.account.clone(),
            enc: b64_encode(&enc),
            ct: b64_encode(&ct),
        });
    }
    wraps.sort_by(|a, b| a.admin.cmp(&b.admin));
    Ok(wraps)
}

/// Opens the recovery private key with `admin`'s keyset and checks it is the key's.
fn open_recovery_secret(
    key: &OrgRecoveryKey,
    admin: &UserKeyset,
) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let wrap = key
        .wraps
        .iter()
        .find(|w| w.admin == admin.account())
        .ok_or_else(|| PassError::InvalidInput(tr!("recovery.admin_not_admin")))?;
    let enc = b64_decode(&wrap.enc).map_err(|_| invalid())?;
    let ct = b64_decode(&wrap.ct).map_err(|_| invalid())?;
    let plain = hpke_open(
        admin.enc_secret(),
        &wrap_info(&key.org, &key.key_id, admin.account())?,
        &enc,
        &ct,
    )
    .ok_or_else(invalid)?;
    let mut sk = Zeroizing::new([0u8; KEY_BYTES]);
    if plain.len() != KEY_BYTES {
        return Err(invalid());
    }
    sk.copy_from_slice(&plain);
    let public = hpke_public_of(&sk).ok_or_else(invalid)?;
    if b64_encode(&public) != key.recovery_pub {
        return Err(invalid());
    }
    Ok(sk)
}

/// A new recovery key pair for `org`, made by `admin` and wrapped for `admins` (and `admin`).
/// Also replaces the key after an admin left, since they knew the old private key; members then
/// enroll again. Every one of `admins` must be pinned in `home`, the creating admin's home vault.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn org_recovery_create(
    admin: &UserKeyset,
    org: &str,
    kind: OrgKind,
    admins: Vec<PublicKeys>,
    home: &crate::Vault,
) -> Result<OrgRecoveryKey> {
    let _ = kind;
    if !valid_id(org) {
        return Err(PassError::InvalidInput(tr!("share.bad_org")));
    }
    for other in admins.iter().filter(|a| a.account != admin.account()) {
        home.require_pinned(other, super::contacts::PERSONAL_SCOPE)?;
    }
    let (sk, public) = hpke_keypair();
    let mut key = OrgRecoveryKey {
        org: org.to_string(),
        key_id: key_id_of(&public),
        recovery_pub: b64_encode(&public),
        created_by: admin.account().to_string(),
        created_at: now_ms(),
        sig: String::new(),
        wraps: Vec::new(),
    };
    key.sig = admin.sign(&key_message(&key)?);
    let mut everyone = vec![admin.public_keys()];
    everyone.extend(admins.into_iter().filter(|a| a.account != admin.account()));
    key.wraps = wraps_for(&sk, &key.org, &key.key_id, &everyone)?;
    Ok(key)
}

/// `key` wrapped also for `new_admins` (pinned in `home`), by an admin who has it. Removing a wrap
/// would not take back what that admin knew: make a new key with [`org_recovery_create`].
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn org_recovery_rewrap(
    key: OrgRecoveryKey,
    admin: &UserKeyset,
    new_admins: Vec<PublicKeys>,
    home: &crate::Vault,
) -> Result<OrgRecoveryKey> {
    for other in &new_admins {
        home.require_pinned(other, super::contacts::PERSONAL_SCOPE)?;
    }
    let sk = open_recovery_secret(&key, admin)?;
    let added = wraps_for(&sk, &key.org, &key.key_id, &new_admins)?;
    let mut key = key;
    for w in added {
        if !key.wraps.iter().any(|k| k.admin == w.admin) {
            key.wraps.push(w);
        }
    }
    key.wraps.sort_by(|a, b| a.admin.cmp(&b.admin));
    Ok(key)
}

/// Checks that `key` was made by `creator` (whose fingerprint the member's app shows): the
/// signature, the key id and the public key. Enrolling also needs `creator` pinned in the
/// member's home vault ([`crate::Vault::admin_recovery_enroll`]).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn org_recovery_verify(key: OrgRecoveryKey, creator: PublicKeys) -> Result<()> {
    verify_key(&key, &creator)
}

fn verify_key(key: &OrgRecoveryKey, creator: &PublicKeys) -> Result<()> {
    creator.verify()?;
    let public = key_bytes(&key.recovery_pub).map_err(|_| invalid())?;
    if creator.account != key.created_by
        || !valid_id(&key.org)
        || !valid_enc_pub(&public)
        || key_id_of(&public) != key.key_id
        || !verify_signature(&key_bytes(&creator.sig_pub)?, &key_message(key)?, &key.sig)
    {
        return Err(invalid());
    }
    Ok(())
}

/// A member's enrollment of the vault key `vk` (vault `vault_id`).
pub(crate) fn enroll(
    vk: &Key,
    vault_id: &str,
    account: &str,
    key: &OrgRecoveryKey,
    creator: &PublicKeys,
    kind: OrgKind,
) -> Result<RecoveryEnrollment> {
    let _ = kind;
    if !valid_id(account) {
        return Err(PassError::InvalidInput(tr!("share.bad_account")));
    }
    verify_key(key, creator)?;
    let mut e = RecoveryEnrollment {
        org: key.org.clone(),
        key_id: key.key_id.clone(),
        account: account.to_string(),
        vault_id: vault_id.to_string(),
        created_at: now_ms(),
        key_check: key_check(vk, &key.org, account, vault_id),
        enc: String::new(),
        ct: String::new(),
    };
    let (enc, ct) = hpke_seal(
        &key_bytes(&key.recovery_pub)?,
        &enrollment_info(&e)?,
        vk.as_slice(),
    )?;
    e.enc = b64_encode(&enc);
    e.ct = b64_encode(&ct);
    Ok(e)
}

/// A recovery request of `account` for its home vault `vault_id`, with a one-time key pair. Send
/// `request` to the account service; keep `secret` on the device until the approval comes.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn admin_recovery_request(org: &str, account: &str, vault_id: &str) -> Result<RecoveryRequest> {
    if !valid_id(org) || !valid_id(account) {
        return Err(PassError::InvalidInput(tr!("share.bad_account")));
    }
    let (sk, public) = hpke_keypair();
    Ok(RecoveryRequest {
        request: RecoveryRequestPublic {
            request_id: uuid::Uuid::new_v4().to_string(),
            org: org.to_string(),
            account: account.to_string(),
            vault_id: vault_id.to_string(),
            enc_pub: b64_encode(&public),
            created_at: now_ms(),
        },
        secret: b64_encode(sk.as_slice()),
    })
}

/// Characters of a [`recovery_request_code`]: four groups of four.
const REQUEST_CODE_CHARS: usize = 16;

/// The comparison code the member reads out to the admin on a call: the first 80 bits of
/// SHA-256(`"pass/org-recovery-code/v1:" + JSON[request_id, org, account, vault_id, enc_pub,
/// created_at]`) in Crockford base32, `7K3Q-D2MX-…`. It covers the one-time key, so a service
/// that swapped the key shows the admin another code; 80 bits keep a search for a key that
/// matches the member's code out of reach.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn recovery_request_code(request: RecoveryRequestPublic) -> Result<String> {
    let body = serde_json::to_vec(&(
        &request.request_id,
        &request.org,
        &request.account,
        &request.vault_id,
        &request.enc_pub,
        request.created_at,
    ))
    .map_err(|_| invalid())?;
    let mut h = Sha256::new();
    h.update(b"pass/org-recovery-code/v1:");
    h.update(&body);
    let digest = h.finalize();
    let bit = |i: usize| (digest[i / 8] >> (7 - i % 8)) & 1;
    let mut out = String::with_capacity(REQUEST_CODE_CHARS + 3);
    for c in 0..REQUEST_CODE_CHARS {
        if c > 0 && c % 4 == 0 {
            out.push('-');
        }
        let v = (0..5).fold(0usize, |v, b| (v << 1) | bit(c * 5 + b) as usize);
        out.push(crate::recovery::ALPHABET[v] as char);
    }
    Ok(out)
}

/// An admin approves `request` with `enrollment`: the vault key, opened with the recovery key,
/// wrapped to the request key and signed by `admin`. `code` is what the member read out
/// ([`recovery_request_code`]; dashes, case and look-alikes don't matter); a mismatch is refused
/// (`Crypto`, `recovery.code_mismatch`), since anyone holding the member's account can make a
/// request and a breached service can swap the request's key.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn admin_recovery_approve(
    key: OrgRecoveryKey,
    admin: &UserKeyset,
    enrollment: RecoveryEnrollment,
    request: RecoveryRequestPublic,
    code: &str,
) -> Result<RecoveryApproval> {
    let expected = recovery_request_code(request.clone())?;
    if super::contacts::normalize_fingerprint(code)
        != super::contacts::normalize_fingerprint(&expected)
    {
        return Err(PassError::Crypto(tr!("recovery.code_mismatch")));
    }
    if enrollment.org != key.org || request.org != key.org {
        return Err(PassError::InvalidInput(tr!("recovery.admin_other_org")));
    }
    if enrollment.key_id != key.key_id {
        return Err(PassError::InvalidInput(tr!("recovery.admin_stale")));
    }
    if request.account != enrollment.account || request.vault_id != enrollment.vault_id {
        return Err(PassError::InvalidInput(tr!("recovery.admin_mismatch")));
    }
    let request_pub = key_bytes(&request.enc_pub)?;
    if !valid_enc_pub(&request_pub) {
        return Err(PassError::InvalidInput(tr!("share.bad_keys")));
    }
    let sk = open_recovery_secret(&key, admin)?;
    let plain = hpke_open(
        &sk,
        &enrollment_info(&enrollment)?,
        &b64_decode(&enrollment.enc).map_err(|_| invalid())?,
        &b64_decode(&enrollment.ct).map_err(|_| invalid())?,
    )
    .ok_or_else(invalid)?;
    let vk: [u8; KEY_LEN] = plain.as_slice().try_into().map_err(|_| invalid())?;
    let vk = Key::from_array(vk);
    let check = key_check(
        &vk,
        &enrollment.org,
        &enrollment.account,
        &enrollment.vault_id,
    );
    if !crate::crypto::ct_eq(check.as_bytes(), enrollment.key_check.as_bytes()) {
        return Err(invalid());
    }
    let mut a = RecoveryApproval {
        org: key.org.clone(),
        key_id: key.key_id.clone(),
        request_id: request.request_id.clone(),
        account: request.account.clone(),
        vault_id: request.vault_id.clone(),
        request_enc_pub: request.enc_pub.clone(),
        approved_by: admin.account().to_string(),
        approved_at: now_ms(),
        key_check: check,
        enc: String::new(),
        ct: String::new(),
        sig: String::new(),
    };
    let (enc, ct) = hpke_seal(&request_pub, &grant_info(&a)?, vk.as_slice())?;
    a.enc = b64_encode(&enc);
    a.ct = b64_encode(&ct);
    a.sig = admin.sign(&approval_message(&a)?);
    Ok(a)
}

/// The member's side: checks `approval` against the approving admin's keys and opens the vault
/// key with the request's one-time `secret`.
pub(crate) fn open_approval(
    approval: &RecoveryApproval,
    secret: &str,
    approver: &PublicKeys,
) -> Result<Key> {
    approver.verify()?;
    if approver.account != approval.approved_by
        || !verify_signature(
            &key_bytes(&approver.sig_pub)?,
            &approval_message(approval)?,
            &approval.sig,
        )
    {
        return Err(invalid());
    }
    let secret = Zeroizing::new(b64_decode(secret).unwrap_or_default());
    let secret: &[u8; KEY_BYTES] = secret
        .as_slice()
        .try_into()
        .map_err(|_| PassError::InvalidInput(tr!("recovery.admin_wrong_request")))?;
    let public = hpke_public_of(secret).ok_or_else(invalid)?;
    if b64_encode(&public) != approval.request_enc_pub {
        return Err(PassError::InvalidInput(tr!("recovery.admin_wrong_request")));
    }
    let plain = hpke_open(
        secret,
        &grant_info(approval)?,
        &b64_decode(&approval.enc).map_err(|_| invalid())?,
        &b64_decode(&approval.ct).map_err(|_| invalid())?,
    )
    .ok_or_else(invalid)?;
    let vk: [u8; KEY_LEN] = plain.as_slice().try_into().map_err(|_| invalid())?;
    let vk = Key::from_array(vk);
    let check = key_check(&vk, &approval.org, &approval.account, &approval.vault_id);
    if !crate::crypto::ct_eq(check.as_bytes(), approval.key_check.as_bytes()) {
        return Err(invalid());
    }
    Ok(vk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::test_home_pinning;

    fn code_of(request: &RecoveryRequestPublic) -> String {
        recovery_request_code(request.clone()).unwrap()
    }

    struct Org {
        alice: UserKeyset,
        bob: UserKeyset,
        key: OrgRecoveryKey,
    }

    fn org() -> Org {
        let alice = UserKeyset::generate("acc_alice").unwrap();
        let bob = UserKeyset::generate("acc_bob").unwrap();
        let home = test_home_pinning(&[bob.public_keys()]);
        let key = org_recovery_create(
            &alice,
            "org_acme",
            OrgKind::Team,
            vec![bob.public_keys()],
            &home,
        )
        .unwrap();
        Org { alice, bob, key }
    }

    #[test]
    fn a_family_can_set_up_admin_recovery_too() {
        let alice = UserKeyset::generate("acc_alice").unwrap();
        let home = test_home_pinning(&[]);
        assert!(org_recovery_create(&alice, "org_home", OrgKind::Family, vec![], &home).is_ok());
        let o = org();
        let vk = crate::crypto::random_key();
        assert!(enroll(
            &vk,
            "v",
            "acc_mia",
            &o.key,
            &o.alice.public_keys(),
            OrgKind::Family
        )
        .is_ok());
    }

    #[test]
    fn an_enrolled_member_is_recovered_by_any_admin_and_the_use_is_signed() {
        let o = org();
        assert_eq!(o.key.wraps.len(), 2);
        org_recovery_verify(o.key.clone(), o.alice.public_keys()).unwrap();
        // The member checks the key against the admin who made it, not anyone else.
        assert!(org_recovery_verify(o.key.clone(), o.bob.public_keys()).is_err());
        let vk = crate::crypto::random_key();
        let e = enroll(
            &vk,
            "vault-mia",
            "acc_mia",
            &o.key,
            &o.alice.public_keys(),
            OrgKind::Team,
        )
        .unwrap();
        let req = admin_recovery_request("org_acme", "acc_mia", "vault-mia").unwrap();
        assert!(!format!("{req:?}").contains(&req.secret));
        // Bob (another admin) approves.
        let a = admin_recovery_approve(
            o.key.clone(),
            &o.bob,
            e.clone(),
            req.request.clone(),
            &code_of(&req.request),
        )
        .unwrap();
        assert_eq!(a.approved_by, "acc_bob");
        let opened = open_approval(&a, &req.secret, &o.bob.public_keys()).unwrap();
        assert_eq!(opened.as_slice(), vk.as_slice());
        // Signed by Bob: it doesn't check as Alice's, and nothing in it can be changed.
        assert!(open_approval(&a, &req.secret, &o.alice.public_keys()).is_err());
        let mut later = a.clone();
        later.approved_at += 1;
        assert!(open_approval(&later, &req.secret, &o.bob.public_keys()).is_err());
        // Another request's key can't open it.
        let other = admin_recovery_request("org_acme", "acc_mia", "vault-mia").unwrap();
        assert!(open_approval(&a, &other.secret, &o.bob.public_keys()).is_err());
    }

    #[test]
    fn approvals_check_who_asks_and_who_approves() {
        let o = org();
        let vk = crate::crypto::random_key();
        let e = enroll(
            &vk,
            "vault-mia",
            "acc_mia",
            &o.key,
            &o.alice.public_keys(),
            OrgKind::Team,
        )
        .unwrap();
        // A request for someone else's vault, or by someone else, is refused.
        let eve = admin_recovery_request("org_acme", "acc_eve", "vault-mia").unwrap();
        assert!(admin_recovery_approve(
            o.key.clone(),
            &o.alice,
            e.clone(),
            eve.request.clone(),
            &code_of(&eve.request)
        )
        .is_err());
        let other_vault = admin_recovery_request("org_acme", "acc_mia", "vault-x").unwrap();
        assert!(admin_recovery_approve(
            o.key.clone(),
            &o.alice,
            e.clone(),
            other_vault.request.clone(),
            &code_of(&other_vault.request)
        )
        .is_err());
        // Someone who isn't an admin has no wrap.
        let mallory = UserKeyset::generate("acc_mallory").unwrap();
        let req = admin_recovery_request("org_acme", "acc_mia", "vault-mia").unwrap();
        assert!(admin_recovery_approve(
            o.key.clone(),
            &mallory,
            e.clone(),
            req.request.clone(),
            &code_of(&req.request)
        )
        .is_err());
        // An enrollment for an older key is stale.
        let home = test_home_pinning(&[]);
        let newer =
            org_recovery_create(&o.alice, "org_acme", OrgKind::Team, vec![], &home).unwrap();
        assert!(admin_recovery_approve(
            newer.clone(),
            &o.alice,
            e.clone(),
            req.request.clone(),
            &code_of(&req.request)
        )
        .is_err());
        // A new admin added with rewrap can approve.
        let carol = UserKeyset::generate("acc_carol").unwrap();
        // Only to admins whose keys the rewrapping admin verified.
        assert!(
            org_recovery_rewrap(o.key.clone(), &o.bob, vec![carol.public_keys()], &home).is_err()
        );
        let bobs_home = test_home_pinning(&[carol.public_keys()]);
        let wider =
            org_recovery_rewrap(o.key.clone(), &o.bob, vec![carol.public_keys()], &bobs_home)
                .unwrap();
        assert_eq!(wider.wraps.len(), 3);
        assert_eq!(wider.sig, o.key.sig);
        assert!(admin_recovery_approve(
            wider,
            &carol,
            e,
            req.request.clone(),
            &code_of(&req.request)
        )
        .is_ok());
    }
}

#[cfg(test)]
mod pin_tests {
    use super::*;
    use crate::vault::test_home_pinning;

    /// A breached service publishes a recovery key under an admin keyset it made: the member's
    /// app never pinned that keyset, so nothing is wrapped to it.
    #[test]
    fn a_planted_recovery_key_is_never_enrolled() {
        let real_admin = UserKeyset::generate("acc_alice").unwrap();
        let fake_admin = UserKeyset::generate("acc_alice").unwrap();
        let mia_home = test_home_pinning(&[real_admin.public_keys()]);
        let planted = org_recovery_create(
            &fake_admin,
            "org_acme",
            OrgKind::Team,
            vec![],
            &test_home_pinning(&[]),
        )
        .unwrap();
        // Self-consistent, so the signature check alone would pass.
        org_recovery_verify(planted.clone(), fake_admin.public_keys()).unwrap();
        let err = mia_home
            .admin_recovery_enroll(planted, fake_admin.public_keys(), "acc_mia", OrgKind::Team)
            .unwrap_err();
        assert!(format!("{err:?}").contains("acc_alice"), "{err:?}");
        let ak = crate::AccountKey::generate("acc_mia".into()).unwrap();
        let real = org_recovery_create(
            &real_admin,
            "org_acme",
            OrgKind::Team,
            vec![],
            &test_home_pinning(&[]),
        )
        .unwrap();
        assert!(ak
            .admin_recovery_enroll(
                real.clone(),
                fake_admin.public_keys(),
                OrgKind::Team,
                &mia_home
            )
            .is_err());
        // The admin Mia compared with: enrolled.
        assert!(ak
            .admin_recovery_enroll(real, real_admin.public_keys(), OrgKind::Team, &mia_home)
            .is_ok());
    }

    #[test]
    fn a_recovery_key_is_wrapped_only_to_verified_admins() {
        let alice = UserKeyset::generate("acc_alice").unwrap();
        let mallory = UserKeyset::generate("acc_mallory").unwrap();
        assert!(org_recovery_create(
            &alice,
            "org_acme",
            OrgKind::Team,
            vec![mallory.public_keys()],
            &test_home_pinning(&[]),
        )
        .is_err());
    }
}

#[cfg(test)]
mod code_tests {
    use super::*;
    use crate::vault::test_home_pinning;

    fn setup() -> (
        UserKeyset,
        OrgRecoveryKey,
        RecoveryEnrollment,
        RecoveryRequest,
    ) {
        let alice = UserKeyset::generate("acc_alice").unwrap();
        let home = test_home_pinning(&[]);
        let key = org_recovery_create(&alice, "org_acme", OrgKind::Team, vec![], &home).unwrap();
        let vk = crate::crypto::random_key();
        let e = enroll(
            &vk,
            "vault-mia",
            "acc_mia",
            &key,
            &alice.public_keys(),
            OrgKind::Team,
        )
        .unwrap();
        let req = admin_recovery_request("org_acme", "acc_mia", "vault-mia").unwrap();
        (alice, key, e, req)
    }

    #[test]
    fn the_code_is_four_groups_and_names_the_request_key() {
        let (_, _, _, req) = setup();
        let code = recovery_request_code(req.request.clone()).unwrap();
        assert_eq!(code.len(), 19);
        assert_eq!(code.matches('-').count(), 3);
        assert_eq!(code, recovery_request_code(req.request.clone()).unwrap());
        let mut other = req.request.clone();
        other.enc_pub = admin_recovery_request("org_acme", "acc_mia", "vault-mia")
            .unwrap()
            .request
            .enc_pub;
        assert_ne!(code, recovery_request_code(other).unwrap());
    }

    /// The service swaps the request's one-time key for its own: the admin's app shows another
    /// code than the member's phone, and the code the member reads out is refused.
    #[test]
    fn a_swapped_request_key_is_never_approved() {
        let (alice, key, e, req) = setup();
        let members_code = recovery_request_code(req.request.clone()).unwrap();
        let planted = admin_recovery_request("org_acme", "acc_mia", "vault-mia").unwrap();
        let mut swapped = req.request.clone();
        swapped.enc_pub = planted.request.enc_pub.clone();
        assert_ne!(
            recovery_request_code(swapped.clone()).unwrap(),
            members_code
        );
        let err = admin_recovery_approve(key.clone(), &alice, e.clone(), swapped, &members_code)
            .unwrap_err();
        assert!(
            crate::core_message_is(format!("{err}"), "recovery.code_mismatch".into())
                || format!("{err:?}").contains(&crate::i18n::text("recovery.code_mismatch", &[])),
            "{err:?}"
        );
        // No code, a wrong one, or a slip: refused too.
        for wrong in ["", "AAAA-AAAA-AAAA-AAAA"] {
            assert!(admin_recovery_approve(
                key.clone(),
                &alice,
                e.clone(),
                req.request.clone(),
                wrong
            )
            .is_err());
        }
        // The member's code, typed in lower case without dashes: approved, and it opens.
        let typed = members_code.to_lowercase().replace('-', "");
        let approval = admin_recovery_approve(key, &alice, e, req.request.clone(), &typed).unwrap();
        assert!(open_approval(&approval, &req.secret, &alice.public_keys()).is_ok());
    }
}
