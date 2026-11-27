//! The members list of a shared vault and its signatures. Each list is signed by a manager of the
//! list before it, back to the vault's creator (the genesis); the file keeps earlier certificates
//! (the chain) so a device that missed changes can check every step. Unknown fields are dropped on
//! parse, so a list from a later format fails to verify instead of being half understood.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::keys::{key_bytes, valid_id, verify_signature, UserKeyset, WrappedKey, KEY_BYTES};
use super::MemberRole;
use crate::crypto::Key;
use crate::encoding::b64_encode;
use crate::i18n::tr;
use crate::{PassError, Result};

/// Certificates of earlier lists kept in the file.
pub(crate) const MAX_CHAIN: usize = 64;
/// Accepted lists a device remembers ([`super::ShareTrust`]), the newest last.
pub(crate) const MAX_PATH: usize = 64;
/// Members of one shared vault.
pub(crate) const MAX_MEMBERS: usize = 1000;

/// Who made the shared vault: the root of trust for the first members list. Never changes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GenesisFile {
    pub created_by: String,
    /// The creator's Ed25519 public key, base64.
    pub sig_pub: String,
    pub created_at: i64,
    /// `"org"` or `"direct"`. Kept as written, so a kind from a later version still verifies;
    /// [`super::SharedKind::parse`] reads an unknown one as `org`.
    pub kind: String,
    /// The organisation the vault belongs to, if any (an id of the account service).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    /// The creator's signature of [`genesis_message`], base64.
    pub sig: String,
}

/// One member of a list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MemberFile {
    pub account: String,
    /// `manage`, `edit`, `view` or `fill` ([`MemberRole`]); kept as written.
    pub role: String,
    /// X25519 public key the vault key is wrapped for, base64.
    pub enc_pub: String,
    /// Ed25519 public key, base64: the member's signatures count only if the member manages.
    pub sig_pub: String,
    /// The group (a department) the member was added through, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// The vault key wrapped for `enc_pub` ([`super::keys::wrap_vault_key`]).
    pub wrapped_key: WrappedKey,
    pub added_by: String,
    pub added_at: i64,
}

impl MemberFile {
    pub(crate) fn role(&self) -> MemberRole {
        MemberRole::parse(&self.role)
    }
}

/// A manager's signing key, as the certificate lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ManagerFile {
    pub account: String,
    pub sig_pub: String,
}

/// The signed part of a list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CertFile {
    /// 1 for the vault's first list, one more with every change.
    pub epoch: u64,
    /// 1 for the vault's first key, one more with every key rotation.
    pub key_epoch: u64,
    /// [`cert_digest`] of the list this one replaces; `None` only at epoch 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    /// The members with role `manage`, sorted by account: who may sign the next list.
    pub managers: Vec<ManagerFile>,
    /// [`entries_digest`] of the list's entries.
    pub entries_digest: String,
    /// [`vk_commitment`] of the vault key at `key_epoch`: binds the list to the key, so every
    /// member can check that the key wrapped for them is the one the manager signed for.
    pub vk_commitment: String,
    pub signed_by: String,
    /// Ed25519 signature of [`cert_message`] by `signed_by`, base64.
    pub sig: String,
}

/// The members block of a shared vault file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MembersFile {
    pub cert: CertFile,
    /// Sorted by account, one per account.
    pub entries: Vec<MemberFile>,
    /// Certificates of the earlier lists, newest first: `chain[0]` is the one `cert.prev` names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<CertFile>,
}

impl MembersFile {
    pub(crate) fn entry(&self, account: &str) -> Option<&MemberFile> {
        self.entries.iter().find(|e| e.account == account)
    }
}

/// One accepted list, as a device remembers it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct CertRef {
    pub key_epoch: u64,
    pub epoch: u64,
    pub digest: String,
}

impl CertRef {
    /// The order in which concurrent lists win: a later key first (a removal is never undone by
    /// a concurrent change that didn't rotate the key), then the later epoch, then the greater
    /// digest, so every device picks the same one.
    pub(crate) fn order(&self) -> (u64, u64, &str) {
        (self.key_epoch, self.epoch, &self.digest)
    }
}

fn internal() -> PassError {
    PassError::Crypto(tr!("error.internal"))
}

fn invalid() -> PassError {
    PassError::Crypto(tr!("share.members_invalid"))
}

fn sha256_b64(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    b64_encode(&h.finalize())
}

/// `"pass/genesis/v1:" + JSON[vault_id, created_by, sig_pub, created_at, kind, org]`.
pub(crate) fn genesis_message(vault_id: &str, g: &GenesisFile) -> Result<Vec<u8>> {
    let mut msg = b"pass/genesis/v1:".to_vec();
    msg.extend(
        serde_json::to_vec(&(
            vault_id,
            &g.created_by,
            &g.sig_pub,
            g.created_at,
            &g.kind,
            &g.org,
        ))
        .map_err(|_| internal())?,
    );
    Ok(msg)
}

/// Checks the genesis signature; returns its digest (part of every list's signed message, so a
/// list can't be moved to another vault made under the same id).
pub(crate) fn verify_genesis(vault_id: &str, g: &GenesisFile) -> Result<String> {
    if !valid_id(&g.created_by)
        || g.kind.is_empty()
        || g.org.as_deref().is_some_and(|o| !valid_id(o))
    {
        return Err(invalid());
    }
    let msg = genesis_message(vault_id, g)?;
    let sig_pub = key_bytes(&g.sig_pub).map_err(|_| invalid())?;
    if !verify_signature(&sig_pub, &msg, &g.sig) {
        return Err(invalid());
    }
    Ok(sha256_b64(&[
        b"pass/genesis-digest/v1:",
        &msg,
        g.sig.as_bytes(),
    ]))
}

/// A new genesis signed by `keyset`.
pub(crate) fn sign_genesis(
    vault_id: &str,
    keyset: &UserKeyset,
    created_at: i64,
    kind: &str,
    org: Option<String>,
) -> Result<GenesisFile> {
    let mut g = GenesisFile {
        created_by: keyset.account().to_string(),
        sig_pub: b64_encode(keyset.sig_pub()),
        created_at,
        kind: kind.to_string(),
        org,
        sig: String::new(),
    };
    g.sig = keyset.sign(&genesis_message(vault_id, &g)?);
    Ok(g)
}

/// `SHA-256("pass/members-entries/v1:" + JSON(entries))`, base64.
pub(crate) fn entries_digest(entries: &[MemberFile]) -> Result<String> {
    let json = serde_json::to_vec(entries).map_err(|_| internal())?;
    Ok(sha256_b64(&[b"pass/members-entries/v1:", &json]))
}

/// `HMAC-SHA256(vk, "pass/vk-commit/v1:" + JSON[vault_id, key_epoch])`, base64.
pub(crate) fn vk_commitment(vk: &Key, vault_id: &str, key_epoch: u64) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(vk.as_slice()).expect("any key length");
    mac.update(b"pass/vk-commit/v1:");
    mac.update(&serde_json::to_vec(&(vault_id, key_epoch)).expect("a string and a number"));
    b64_encode(&mac.finalize().into_bytes())
}

/// `"pass/members/v1:" + JSON[vault_id, genesis_digest, epoch, key_epoch, prev, managers,
/// entries_digest, vk_commitment, signed_by]`.
pub(crate) fn cert_message(vault_id: &str, genesis: &str, c: &CertFile) -> Result<Vec<u8>> {
    let mut msg = b"pass/members/v1:".to_vec();
    msg.extend(
        serde_json::to_vec(&(
            vault_id,
            genesis,
            c.epoch,
            c.key_epoch,
            &c.prev,
            &c.managers,
            &c.entries_digest,
            &c.vk_commitment,
            &c.signed_by,
        ))
        .map_err(|_| internal())?,
    );
    Ok(msg)
}

/// `SHA-256("pass/members-digest/v1:" + cert_message + sig)`, base64: names one signed list.
pub(crate) fn cert_digest(vault_id: &str, genesis: &str, c: &CertFile) -> Result<String> {
    let msg = cert_message(vault_id, genesis, c)?;
    Ok(sha256_b64(&[
        b"pass/members-digest/v1:",
        &msg,
        c.sig.as_bytes(),
    ]))
}

pub(crate) fn cert_ref(vault_id: &str, genesis: &str, c: &CertFile) -> Result<CertRef> {
    Ok(CertRef {
        key_epoch: c.key_epoch,
        epoch: c.epoch,
        digest: cert_digest(vault_id, genesis, c)?,
    })
}

/// The managers of `entries`, as a certificate lists them.
fn managers_of(entries: &[MemberFile]) -> Vec<ManagerFile> {
    entries
        .iter()
        .filter(|e| e.role() == MemberRole::Manage)
        .map(|e| ManagerFile {
            account: e.account.clone(),
            sig_pub: e.sig_pub.clone(),
        })
        .collect()
}

/// Checks `c`'s signature by a manager of `authority` (or, with `None`, by the genesis
/// creator). `c` must name `signed_by` among those allowed to sign.
fn signed_by_manager(
    vault_id: &str,
    genesis_digest: &str,
    genesis: &GenesisFile,
    c: &CertFile,
    authority: Option<&[ManagerFile]>,
) -> Result<()> {
    let sig_pub = match authority {
        Some(managers) => managers
            .iter()
            .find(|m| m.account == c.signed_by)
            .map(|m| m.sig_pub.as_str()),
        None => (c.signed_by == genesis.created_by).then_some(genesis.sig_pub.as_str()),
    }
    .ok_or_else(invalid)?;
    let sig_pub = key_bytes(sig_pub).map_err(|_| invalid())?;
    let msg = cert_message(vault_id, genesis_digest, c)?;
    if verify_signature(&sig_pub, &msg, &c.sig) {
        Ok(())
    } else {
        Err(invalid())
    }
}

/// Structural checks of the current list: entries sorted by account and unique, ids and keys
/// well-formed, the digest and the managers matching the certificate, at least one manager.
fn check_entries(m: &MembersFile) -> Result<()> {
    let entries = &m.entries;
    if entries.is_empty() || entries.len() > MAX_MEMBERS {
        return Err(invalid());
    }
    for w in entries.windows(2) {
        if w[0].account >= w[1].account {
            return Err(invalid());
        }
    }
    for e in entries {
        if !valid_id(&e.account)
            || !valid_id(&e.added_by)
            || e.role.is_empty()
            || e.group.as_deref().is_some_and(|g| !valid_id(g))
        {
            return Err(invalid());
        }
        let _: [u8; KEY_BYTES] = key_bytes(&e.enc_pub).map_err(|_| invalid())?;
        let _: [u8; KEY_BYTES] = key_bytes(&e.sig_pub).map_err(|_| invalid())?;
    }
    if entries_digest(entries)? != m.cert.entries_digest {
        return Err(invalid());
    }
    let managers = managers_of(entries);
    if managers.is_empty() || managers != m.cert.managers {
        return Err(invalid());
    }
    Ok(())
}

/// Why a list was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Rejected {
    /// Broken or not signed by someone allowed to sign it.
    Invalid,
    /// Signed correctly step by step, but none of its certificates is one this device accepted
    /// (too many changes since, another history, or a rollback).
    Unanchored,
}

/// The outcome of [`verify_members`].
#[derive(Debug, Clone)]
pub(crate) struct Verified {
    /// The list itself.
    pub current: CertRef,
    /// The accepted path if this list is adopted: earlier accepted lists, the oldest first, and
    /// this one last (at most [`MAX_PATH`]).
    pub path: Vec<CertRef>,
    /// Whether the list is tied to the genesis or to a list this device accepted before. `false`
    /// means trust on first use: the app shows who signed it.
    pub anchored: bool,
}

/// Verifies a members block.
///
/// `trusted` is the path of lists this device accepted ([`super::ShareTrust`]), the newest
/// last; empty on a first open. With a path, the newest certificate of the block that the path
/// contains is the anchor and every later one must be signed by a manager of the one before. On
/// a first open the oldest certificate in the file is the anchor: checked against the genesis if
/// it is the first list, otherwise taken on first use (signed by one of its own managers).
///
/// Whether the list should replace the one this device has is for the caller to decide with
/// [`CertRef::order`]: this only says whether it is genuine.
pub(crate) fn verify_members(
    vault_id: &str,
    genesis: &GenesisFile,
    genesis_digest: &str,
    m: &MembersFile,
    trusted: &[CertRef],
) -> std::result::Result<Verified, Rejected> {
    check_entries(m).map_err(|_| Rejected::Invalid)?;
    if m.cert.epoch == 0 || m.cert.key_epoch == 0 || (m.cert.epoch == 1) != m.cert.prev.is_none() {
        return Err(Rejected::Invalid);
    }
    // The certificates, newest first, as far back as they link up. A chain entry that doesn't
    // link is ignored with everything older (a damaged or doctored tail can only cost reach).
    let mut certs: Vec<(&CertFile, String)> = Vec::with_capacity(1 + m.chain.len());
    let digest =
        |c: &CertFile| cert_digest(vault_id, genesis_digest, c).map_err(|_| Rejected::Invalid);
    certs.push((&m.cert, digest(&m.cert)?));
    for parent in m.chain.iter().take(MAX_CHAIN) {
        let (child, _) = certs.last().expect("not empty");
        let d = digest(parent)?;
        let links = child.prev.as_deref() == Some(d.as_str())
            && parent.epoch.checked_add(1) == Some(child.epoch)
            && parent.key_epoch <= child.key_epoch
            && (parent.epoch == 1) == parent.prev.is_none();
        if !links {
            break;
        }
        certs.push((parent, d));
    }

    let (anchor, anchored, mut path) = if trusted.is_empty() {
        let last = certs.len() - 1;
        let (oldest, _) = certs[last];
        if oldest.epoch == 1 {
            signed_by_manager(vault_id, genesis_digest, genesis, oldest, None)
                .map_err(|_| Rejected::Invalid)?;
            (last, true, Vec::new())
        } else {
            // A writer keeps the last MAX_CHAIN certificates, so a list this young that no longer
            // reaches the genesis had its chain cut, perhaps to hide a step nobody may sign.
            if m.cert.epoch <= MAX_CHAIN as u64 + 1 {
                return Err(Rejected::Invalid);
            }
            signed_by_manager(
                vault_id,
                genesis_digest,
                genesis,
                oldest,
                Some(&oldest.managers),
            )
            .map_err(|_| Rejected::Invalid)?;
            (last, false, Vec::new())
        }
    } else {
        let found = certs
            .iter()
            .position(|(_, d)| trusted.iter().any(|t| &t.digest == d));
        let Some(i) = found else {
            return Err(Rejected::Unanchored);
        };
        let at = trusted
            .iter()
            .position(|t| t.digest == certs[i].1)
            .expect("found above");
        (i, true, trusted[..at].to_vec())
    };
    // Every step after the anchor: signed by a manager of the list before it.
    for j in (0..anchor).rev() {
        let (child, _) = certs[j];
        let (parent, _) = certs[j + 1];
        signed_by_manager(
            vault_id,
            genesis_digest,
            genesis,
            child,
            Some(&parent.managers),
        )
        .map_err(|_| Rejected::Invalid)?;
    }
    for (c, d) in certs[..=anchor].iter().rev() {
        path.push(CertRef {
            key_epoch: c.key_epoch,
            epoch: c.epoch,
            digest: d.clone(),
        });
    }
    if path.len() > MAX_PATH {
        path.drain(..path.len() - MAX_PATH);
    }
    Ok(Verified {
        current: path.last().cloned().expect("the list itself"),
        path,
        anchored,
    })
}

/// Signs a new list with `keyset` after `prev` (or the vault's first list without one): sorts
/// the entries, derives the managers and the digests, and keeps `prev`'s certificate in the
/// chain. The caller checks that `keyset` may sign (a manager of `prev`, or the creator).
pub(crate) fn sign_members(
    vault_id: &str,
    genesis_digest: &str,
    keyset: &UserKeyset,
    prev: Option<&MembersFile>,
    mut entries: Vec<MemberFile>,
    key_epoch: u64,
    vk: &Key,
) -> Result<MembersFile> {
    entries.sort_by(|a, b| a.account.cmp(&b.account));
    let (epoch, prev_digest, chain) = match prev {
        Some(p) => {
            let mut chain = Vec::with_capacity((p.chain.len() + 1).min(MAX_CHAIN));
            chain.push(p.cert.clone());
            chain.extend(p.chain.iter().take(MAX_CHAIN - 1).cloned());
            (
                p.cert.epoch + 1,
                Some(cert_digest(vault_id, genesis_digest, &p.cert)?),
                chain,
            )
        }
        None => (1, None, Vec::new()),
    };
    let mut cert = CertFile {
        epoch,
        key_epoch,
        prev: prev_digest,
        managers: managers_of(&entries),
        entries_digest: entries_digest(&entries)?,
        vk_commitment: vk_commitment(vk, vault_id, key_epoch),
        signed_by: keyset.account().to_string(),
        sig: String::new(),
    };
    cert.sig = keyset.sign(&cert_message(vault_id, genesis_digest, &cert)?);
    Ok(MembersFile {
        cert,
        entries,
        chain,
    })
}
