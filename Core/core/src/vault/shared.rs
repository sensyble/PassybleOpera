//! Shared vaults inside [`Vault`]: creating and opening one with the user's keyset, the members
//! list in the file and its merge, member changes (with a key rotation when someone leaves), moving
//! and copying items between vaults, and the home vault's keyset and trust records.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use super::{
    check_key, key_check_aad, open_previous_keys, parse_file, prev_key_aad, seal, Inner, Item,
    KdfParams, Key, PassError, Result, Sealed, Vault, VaultFile,
};
use crate::crypto;
use crate::encoding::{b64_encode, hex};
use crate::i18n::tr;
use crate::now_ms;
use crate::share::keys::{
    fingerprint, key_bytes, unwrap_vault_key, valid_id, wrap_vault_key, PublicKeys, UserKeyset,
};
use crate::share::members::{
    self, cert_ref, sign_genesis, sign_members, verify_genesis, verify_members, CertRef,
    GenesisFile, MemberFile, MembersFile, Rejected, MAX_MEMBERS,
};
use crate::share::contacts::PERSONAL_SCOPE;
use crate::share::{
    GroupMember, MemberChange, MemberInfo, MemberRole, MembersNotice, ShareTrust, SharedInfo,
    SharedKind,
};

/// `access` of a shared vault's file.
pub(super) const ACCESS_MEMBERS: &str = "members";

/// Prefix of the home vault setting that holds a keyset; the rest is a hash of the account id.
pub(super) const KEYSET_SETTING: &str = "account.keys.v1.";
/// Prefix of the home vault setting that holds a [`ShareTrust`]; the rest is a hash of the vault id.
const TRUST_SETTING: &str = "share.trust.v1.";

fn setting_key(prefix: &str, id: &str) -> String {
    format!("{prefix}{}", &hex(&Sha256::digest(id.as_bytes()))[..32])
}

fn invalid() -> PassError {
    PassError::Crypto(tr!("share.members_invalid"))
}

fn not_shared() -> PassError {
    PassError::InvalidInput(tr!("share.not_shared"))
}

/// A shared vault's members list and this device's place in it.
#[derive(Clone)]
pub(crate) struct SharedState {
    pub(super) account: String,
    /// The account's keyset: opens the wrapped key and signs list changes.
    pub(super) keyset: UserKeyset,
    pub(super) genesis: GenesisFile,
    pub(super) genesis_digest: String,
    /// The current list, verified.
    pub(super) members: MembersFile,
    /// The lists this vault accepted, the newest (the current) last.
    pub(super) path: Vec<CertRef>,
    /// See [`SharedInfo::anchored`].
    pub(super) anchored: bool,
    /// Member changes this device signed that no other copy has confirmed yet: the digest of the
    /// list each made, and the changes, the oldest first. Kept across restarts in the home
    /// vault's local file ([`Vault::remember_trust_of`], restored by
    /// [`Vault::open_shared_with_home`]). When a merge adopts a list that none of them is part
    /// of, they lost to a concurrent change and move to `lost`.
    pub(super) pending: Vec<(String, Vec<MemberChange>)>,
    /// Lost changes for [`Inner::after_members_merge`] to apply again.
    pub(super) lost: Vec<MemberChange>,
    /// What to tell the user ([`Vault::take_members_notice`]).
    pub(super) notice: MembersNotice,
}

impl SharedState {
    pub(super) fn new(
        keyset: &UserKeyset,
        genesis: GenesisFile,
        genesis_digest: String,
        members: MembersFile,
        path: Vec<CertRef>,
        anchored: bool,
    ) -> SharedState {
        SharedState {
            account: keyset.account().to_string(),
            keyset: keyset.clone(),
            genesis,
            genesis_digest,
            members,
            path,
            anchored,
            pending: Vec::new(),
            lost: Vec::new(),
            notice: MembersNotice::default(),
        }
    }

    fn role(&self) -> Option<MemberRole> {
        self.members.entry(&self.account).map(MemberFile::role)
    }

    /// Settles [`SharedState::pending`] against `remote`'s list: changes whose list is in it
    /// (its current certificate or its chain) are confirmed and forgotten. With `adopted` (the
    /// remote list replaces this one), the rest lost and go to [`SharedState::lost`].
    fn settle_pending(&mut self, vault_id: &str, remote: &MembersFile, adopted: bool) {
        if self.pending.is_empty() {
            return;
        }
        let digests: BTreeSet<String> = std::iter::once(&remote.cert)
            .chain(remote.chain.iter())
            .filter_map(|c| members::cert_digest(vault_id, &self.genesis_digest, c).ok())
            .collect();
        if let Some(i) = self.pending.iter().rposition(|(d, _)| digests.contains(d)) {
            self.pending.drain(..=i);
        }
        if adopted {
            for (_, changes) in self.pending.drain(..) {
                self.lost.extend(changes);
            }
        }
    }

    fn trust(&self, vault_id: &str) -> ShareTrust {
        ShareTrust {
            vault_id: vault_id.to_string(),
            genesis: self.genesis_digest.clone(),
            path: self.path.clone(),
        }
    }

    fn info(&self, vault_id: &str) -> SharedInfo {
        let cert = &self.members.cert;
        SharedInfo {
            vault_id: vault_id.to_string(),
            kind: SharedKind::parse(&self.genesis.kind),
            org: self.genesis.org.clone(),
            created_by: self.genesis.created_by.clone(),
            created_at: self.genesis.created_at,
            epoch: cert.epoch,
            key_epoch: cert.key_epoch,
            signed_by: cert.signed_by.clone(),
            account: self.account.clone(),
            role: self.role().unwrap_or(MemberRole::Fill),
            members: self
                .members
                .entries
                .iter()
                .map(|e| MemberInfo {
                    account: e.account.clone(),
                    role: e.role(),
                    group: e.group.clone(),
                    fingerprint: match (key_bytes(&e.enc_pub), key_bytes(&e.sig_pub)) {
                        (Ok(enc), Ok(sig)) => fingerprint(&enc, &sig),
                        _ => String::new(),
                    },
                    added_by: e.added_by.clone(),
                    added_at: e.added_at,
                })
                .collect(),
            anchored: self.anchored,
            signer_fingerprint: self.members.entry(&cert.signed_by).and_then(|e| {
                Some(fingerprint(
                    &key_bytes(&e.enc_pub).ok()?,
                    &key_bytes(&e.sig_pub).ok()?,
                ))
            }),
        }
    }
}

/// Splits changes that lost to a concurrent list into those to apply again on top of `members`
/// and those that no longer make sense; changes the winner already made are neither.
fn classify_lost(
    members: &MembersFile,
    me: &str,
    lost: Vec<MemberChange>,
) -> (Vec<MemberChange>, Vec<MemberChange>) {
    let manager = members
        .entry(me)
        .is_some_and(|e| e.role() == MemberRole::Manage);
    let mut redo = Vec::new();
    let mut dropped = Vec::new();
    let same_keys =
        |e: &MemberFile, k: &PublicKeys| e.enc_pub == k.enc_pub && e.sig_pub == k.sig_pub;
    for change in lost {
        // `None`: already so in the winning list; `Some(true)`: apply again; `Some(false)`: no
        // longer possible.
        let verdict = match &change {
            MemberChange::Add { keys, .. } => match members.entry(&keys.account) {
                None => Some(true),
                Some(e) if same_keys(e, keys) => None,
                Some(_) => Some(false),
            },
            MemberChange::SetRole { account, role } => match members.entry(account) {
                None => Some(false),
                Some(e) if e.role() == *role => None,
                Some(_) => Some(true),
            },
            MemberChange::SetGroup { account, group } => match members.entry(account) {
                None => Some(false),
                Some(e) if e.group == *group => None,
                Some(_) => Some(true),
            },
            MemberChange::ReplaceKeys { keys } => match members.entry(&keys.account) {
                None => Some(false),
                Some(e) if same_keys(e, keys) => None,
                Some(_) => Some(true),
            },
            MemberChange::Remove { account } => members.entry(account).map(|_| true),
        };
        match verdict {
            None => {}
            Some(true) if manager => redo.push(change),
            Some(_) => dropped.push(change),
        }
    }
    (redo, dropped)
}

/// The `kdf` written into a shared vault's file. No password opens a shared vault; the field is
/// there so clients without sharing can read the file far enough to see its version and say it
/// needs a newer Passyble (their reader requires `kdf` and `wrapped_key`).
pub(super) fn stub_kdf() -> KdfParams {
    KdfParams {
        alg: "none".into(),
        m_kib: 0,
        t: 0,
        p: 0,
        salt: String::new(),
    }
}

/// The `wrapped_key` written into a shared vault's file; see [`stub_kdf`].
pub(super) fn stub_wrapped_key() -> Sealed {
    Sealed {
        nonce: String::new(),
        ct: String::new(),
    }
}

/// The items' fingerprint with the members list's signature mixed in (a shared vault only), so
/// a copy with another list differs.
pub(super) fn with_members_fingerprint(content: String, sig: Option<&str>) -> String {
    let Some(sig) = sig else {
        return content;
    };
    let mut h = Sha256::new();
    h.update(content.as_bytes());
    h.update(b"\0members");
    h.update(sig.as_bytes());
    b64_encode(&h.finalize()[..16])
}

/// A shared vault's file can't be opened with a password, a device key or a recovery code.
pub(super) fn refuse_shared(file: &VaultFile) -> Result<()> {
    if file.is_shared() {
        Err(PassError::InvalidInput(tr!("share.needs_keys")))
    } else {
        Ok(())
    }
}

/// A shared vault has no master password and no recovery code.
pub(super) fn refuse_password(inner: &Inner) -> Result<()> {
    if inner.shared.is_some() {
        Err(PassError::InvalidInput(tr!("share.no_password")))
    } else {
        Ok(())
    }
}

/// Opens the vault key wrapped for `keyset` in `members` and checks it against the list's
/// commitment.
fn open_own_key(vault_id: &str, members: &MembersFile, keyset: &UserKeyset) -> Result<Key> {
    let entry = members
        .entry(keyset.account())
        .ok_or_else(|| PassError::Crypto(tr!("share.not_a_member")))?;
    if key_bytes(&entry.enc_pub)? != *keyset.enc_pub()
        || key_bytes(&entry.sig_pub)? != *keyset.sig_pub()
    {
        return Err(PassError::Crypto(tr!("share.keys_mismatch")));
    }
    let key_epoch = members.cert.key_epoch;
    let vk =
        unwrap_vault_key(keyset, &entry.wrapped_key, vault_id, key_epoch).ok_or_else(invalid)?;
    let commitment = members::vk_commitment(&vk, vault_id, key_epoch);
    if !crypto::ct_eq(commitment.as_bytes(), members.cert.vk_commitment.as_bytes()) {
        return Err(invalid());
    }
    Ok(vk)
}

/// What a members list that didn't verify means for the device: a rollback when it is not newer
/// than what the device accepted, otherwise a list the device can't tie to what it knows.
fn rejection(r: Rejected, theirs: &MembersFile, trusted: &[CertRef]) -> PassError {
    match r {
        Rejected::Invalid => invalid(),
        Rejected::Unanchored => {
            let theirs = (theirs.cert.key_epoch, theirs.cert.epoch);
            match trusted.last() {
                Some(last) if theirs <= (last.key_epoch, last.epoch) => {
                    PassError::Conflict(tr!("share.members_rollback"))
                }
                _ => PassError::Crypto(tr!("share.members_unverified")),
            }
        }
    }
}

impl Inner {
    /// `Ok` unless this is a shared vault where this device's role doesn't allow edits.
    pub(super) fn check_writable(&self) -> Result<()> {
        if self.read_only {
            return Err(PassError::InvalidInput(tr!("emergency.view_only")));
        }
        match &self.shared {
            None => Ok(()),
            Some(s) if s.role().is_some_and(MemberRole::can_edit) => Ok(()),
            Some(_) => Err(PassError::InvalidInput(tr!("share.read_only"))),
        }
    }

    fn can_reveal(&self) -> bool {
        self.shared
            .as_ref()
            .is_none_or(|s| s.role().is_some_and(MemberRole::can_reveal))
    }

    /// Whether `file` is encrypted with this vault's key or one it replaced.
    fn knows_key_of(&self, file: &VaultFile) -> bool {
        check_key(file, &self.vk).is_ok()
            || self
                .previous_keys
                .iter()
                .any(|(k, _)| check_key(file, k).is_ok())
    }

    /// Keeps `key` as an earlier key (sealed with the current one), so copies encrypted with it
    /// merge.
    fn add_previous_key(&mut self, key: Key) -> Result<()> {
        if key.as_slice() == self.vk.as_slice()
            || self
                .previous_keys
                .iter()
                .any(|(k, _)| k.as_slice() == key.as_slice())
        {
            return Ok(());
        }
        let sealed = seal(&self.vk, key.as_slice(), &prev_key_aad(&self.vault_id))?;
        self.previous_keys.push((key, sealed));
        self.mark_dirty();
        Ok(())
    }

    /// Takes over the earlier keys of `remote` when it has this vault's current key: keys of
    /// concurrent lists that another device kept ([`Inner::merge_members`]).
    fn adopt_previous_keys(&mut self, remote: &VaultFile) -> Result<()> {
        if check_key(remote, &self.vk).is_err() {
            return Ok(());
        }
        for (key, _) in open_previous_keys(remote, &self.vk).unwrap_or_default() {
            self.add_previous_key(key)?;
        }
        Ok(())
    }

    /// Merges the members list of `remote`, before its items.
    ///
    /// A list is adopted only if it verifies against the lists this vault accepted (every step
    /// signed by a manager of the step before) and comes later in [`CertRef::order`]: a later
    /// key epoch, then a later epoch, then the greater digest, so of two lists made at the same
    /// time from the same one every device picks the same. Adopting a list with a new key
    /// re-keys this vault (the old keys stay as earlier keys). A list that loses but verifies
    /// may still bring a key of its own (a key rotation that lost to a concurrent change): that
    /// key is kept as an earlier key so its items merge. A list that doesn't verify is ignored
    /// with its key, so its items merge only if they are encrypted with a key this vault knows.
    ///
    /// `Err` when the winning list no longer has this device's account (removed) or has other
    /// keys for it: the vault can't follow it.
    pub(super) fn merge_members(&mut self, remote: &VaultFile) -> Result<()> {
        let vault_id = self.vault_id.clone();
        let shared = self.shared.as_ref().ok_or_else(not_shared)?;
        let (Some(genesis), Some(theirs)) = (&remote.genesis, &remote.members) else {
            return Err(PassError::Corrupt(tr!("vault.not_a_vault")));
        };
        if *genesis != shared.genesis {
            return Err(PassError::Conflict(tr!("share.genesis_changed")));
        }
        if theirs.cert == shared.members.cert {
            let shared = self.shared.as_mut().expect("checked above");
            shared.settle_pending(&vault_id, theirs, false);
            return self.adopt_previous_keys(remote);
        }
        let Ok(verified) = verify_members(
            &vault_id,
            &shared.genesis,
            &shared.genesis_digest,
            theirs,
            &shared.path,
        ) else {
            return Ok(());
        };
        let ours = shared.path.last().cloned().ok_or_else(invalid)?;
        let keyset = shared.keyset.clone();
        if verified.current.order() > ours.order() {
            let entry = theirs
                .entry(keyset.account())
                .ok_or_else(|| PassError::Crypto(tr!("share.removed")))?;
            if key_bytes(&entry.enc_pub)? != *keyset.enc_pub()
                || key_bytes(&entry.sig_pub)? != *keyset.sig_pub()
            {
                return Err(PassError::Crypto(tr!("share.keys_mismatch")));
            }
            let same_key = theirs.cert.key_epoch == shared.members.cert.key_epoch
                && theirs.cert.vk_commitment == shared.members.cert.vk_commitment;
            if same_key {
                self.adopt_previous_keys(remote)?;
            } else {
                let vk = open_own_key(&vault_id, theirs, &keyset)?;
                check_key(remote, &vk).map_err(|_| invalid())?;
                let extra: Vec<Key> = open_previous_keys(remote, &vk)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(k, _)| k)
                    .collect();
                self.replace_key(vk, extra)?;
            }
            let shared = self.shared.as_mut().expect("checked above");
            shared.settle_pending(&vault_id, theirs, true);
            shared.members = theirs.clone();
            shared.path = verified.path;
            self.header_updated_at = self.header_updated_at.max(remote.header_updated_at);
            self.last_ts = self.last_ts.max(remote.header_updated_at);
            self.changed();
        } else {
            let shared = self.shared.as_mut().expect("checked above");
            shared.settle_pending(&vault_id, theirs, false);
            if !self.knows_key_of(remote) {
                if let Ok(vk) = open_own_key(&vault_id, theirs, &keyset) {
                    if check_key(remote, &vk).is_ok() {
                        self.add_previous_key(vk)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Takes back the unconfirmed member changes the home vault kept for this vault across a
    /// restart, checked against the list this copy opened with: changes the list was built on
    /// (in its chain) are confirmed; the change that made the current list stays unconfirmed
    /// (only another copy can confirm it); any other change lost to a list merged in before the
    /// restart and is applied again now when it still makes sense ([`Inner::after_members_merge`]).
    pub(super) fn restore_pending(&mut self, mut pending: Vec<(String, Vec<MemberChange>)>) {
        let vault_id = self.vault_id.clone();
        let Some(shared) = self.shared.as_mut() else {
            return;
        };
        if pending.is_empty() || !shared.pending.is_empty() {
            return;
        }
        let digest =
            |c: &members::CertFile| members::cert_digest(&vault_id, &shared.genesis_digest, c).ok();
        let current = digest(&shared.members.cert);
        let chain: BTreeSet<String> = shared.members.chain.iter().filter_map(digest).collect();
        if let Some(i) = pending.iter().rposition(|(d, _)| chain.contains(d)) {
            pending.drain(..=i);
        }
        let keep = match pending.last() {
            Some((d, _)) if Some(d) == current.as_ref() => pending.pop(),
            _ => None,
        };
        for (_, changes) in pending {
            shared.lost.extend(changes);
        }
        shared.pending.extend(keep);
        if !shared.lost.is_empty() {
            self.after_members_merge();
        }
    }

    /// What follows a merge of a shared vault, once its items are in: the member changes of this
    /// device that lost to a concurrent list are applied again on top of the winner when they
    /// still make sense and this account still manages the vault, and a list signed by a manager
    /// who left gets a new key. Both go into the notice.
    pub(super) fn after_members_merge(&mut self) {
        let Some(shared) = self.shared.as_mut() else {
            return;
        };
        let lost = std::mem::take(&mut shared.lost);
        let mut notice = MembersNotice::default();
        if !lost.is_empty() {
            let (redo, dropped) = classify_lost(&shared.members, &shared.account, lost);
            notice.dropped = dropped;
            if !redo.is_empty() {
                match self.change_members(redo.clone(), false) {
                    Ok(()) => notice.reapplied = redo,
                    Err(_) => notice.dropped.extend(redo),
                }
            }
        }
        notice.rotated_after_leave = self.rotate_after_leave();
        if let Some(shared) = self.shared.as_mut() {
            shared.notice.absorb(notice);
        }
    }

    /// A manager who leaves signs the list without themselves, and their device made its key
    /// (it re-encrypts the vault for the upload). The first remaining manager whose device sees
    /// such a list replaces the key, so the one who left can't read what is added later, even
    /// with the host's help. `true` if it did.
    pub(super) fn rotate_after_leave(&mut self) -> bool {
        let Some(s) = &self.shared else {
            return false;
        };
        let signer_left = s.members.entry(&s.members.cert.signed_by).is_none();
        if !signer_left || s.role() != Some(MemberRole::Manage) {
            return false;
        }
        self.change_members(Vec::new(), true).is_ok()
    }

    /// Applies `changes` to the members list as a new list signed by this device's keyset,
    /// with a new vault key when `rotate` or any change needs one.
    fn change_members(&mut self, changes: Vec<MemberChange>, mut rotate: bool) -> Result<()> {
        let requested = changes.clone();
        let vault_id = self.vault_id.clone();
        let shared = self.shared.as_ref().ok_or_else(not_shared)?;
        let me = shared.account.clone();
        let mine = shared
            .members
            .entry(&me)
            .ok_or_else(|| PassError::Crypto(tr!("share.not_a_member")))?;
        if mine.role() != MemberRole::Manage {
            return Err(PassError::InvalidInput(tr!("share.not_manager")));
        }
        if key_bytes(&mine.sig_pub)? != *shared.keyset.sig_pub() {
            return Err(PassError::Crypto(tr!("share.keys_mismatch")));
        }
        let mut entries = shared.members.entries.clone();
        let mut rewrap: BTreeSet<String> = BTreeSet::new();
        let now = now_ms();
        let find = |entries: &[MemberFile], account: &str| -> Result<usize> {
            entries
                .iter()
                .position(|e| e.account == account)
                .ok_or_else(|| PassError::NotFound(tr!("share.no_member")))
        };
        let check_group = |group: &Option<String>| -> Result<()> {
            if group.as_deref().is_some_and(|g| !valid_id(g)) {
                return Err(PassError::InvalidInput(tr!("share.bad_group")));
            }
            Ok(())
        };
        for change in changes {
            match change {
                MemberChange::Add { keys, role, group } => {
                    keys.verify()?;
                    check_group(&group)?;
                    if entries.iter().any(|e| e.account == keys.account) {
                        return Err(PassError::InvalidInput(tr!("share.member_exists")));
                    }
                    rewrap.insert(keys.account.clone());
                    entries.push(MemberFile {
                        account: keys.account,
                        role: role.as_str().into(),
                        enc_pub: keys.enc_pub,
                        sig_pub: keys.sig_pub,
                        group,
                        // Wrapped below.
                        wrapped_key: crate::share::keys::WrappedKey {
                            enc: String::new(),
                            ct: String::new(),
                        },
                        added_by: me.clone(),
                        added_at: now,
                    });
                }
                MemberChange::SetRole { account, role } => {
                    let i = find(&entries, &account)?;
                    entries[i].role = role.as_str().into();
                }
                MemberChange::SetGroup { account, group } => {
                    check_group(&group)?;
                    let i = find(&entries, &account)?;
                    entries[i].group = group;
                }
                MemberChange::ReplaceKeys { keys } => {
                    keys.verify()?;
                    if keys.account == me {
                        return Err(PassError::InvalidInput(tr!("share.not_yourself")));
                    }
                    let i = find(&entries, &keys.account)?;
                    entries[i].enc_pub = keys.enc_pub;
                    entries[i].sig_pub = keys.sig_pub;
                    rotate = true;
                }
                MemberChange::Remove { account } => {
                    // A manager may leave while another manager remains (checked below).
                    let i = find(&entries, &account)?;
                    entries.remove(i);
                    rotate = true;
                }
            }
        }
        if !entries.iter().any(|e| e.role() == MemberRole::Manage) {
            return Err(PassError::InvalidInput(tr!("share.last_manager")));
        }
        if entries.len() > MAX_MEMBERS {
            return Err(PassError::InvalidInput(tr!("share.too_many_members")));
        }
        entries.sort_by(|a, b| a.account.cmp(&b.account));
        if !rotate && entries == shared.members.entries {
            return Ok(());
        }
        let old_key_epoch = shared.members.cert.key_epoch;
        let (vk, key_epoch) = if rotate {
            (crypto::random_key(), old_key_epoch + 1)
        } else {
            (self.vk.clone(), old_key_epoch)
        };
        for e in entries.iter_mut() {
            if rotate || rewrap.contains(&e.account) {
                e.wrapped_key = wrap_vault_key(
                    &key_bytes(&e.enc_pub)?,
                    &vault_id,
                    &e.account,
                    key_epoch,
                    &vk,
                )?;
            }
        }
        let signed = sign_members(
            &vault_id,
            &shared.genesis_digest,
            &shared.keyset,
            Some(&shared.members),
            entries,
            key_epoch,
            &vk,
        )?;
        // What every other member's device will check.
        let verified = verify_members(
            &vault_id,
            &shared.genesis,
            &shared.genesis_digest,
            &signed,
            &shared.path,
        )
        .map_err(|_| PassError::Crypto(tr!("error.internal")))?;
        if rotate {
            self.replace_key(vk, Vec::new())?;
        }
        let shared = self.shared.as_mut().expect("checked above");
        shared.members = signed;
        if !requested.is_empty() {
            shared
                .pending
                .push((verified.current.digest.clone(), requested));
        }
        shared.path = verified.path;
        let header = self.header_updated_at;
        self.header_updated_at = self.next_ts(header);
        self.changed();
        Ok(())
    }
}

/// Shared vaults, as the apps use them (UniFFI).
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Vault {
    /// A new, empty shared vault made by `keyset`'s account, its first manager. `kind` decides the
    /// apps' wording (an organisation's vault or a direct share); `org` names its organisation, if
    /// any. Save and upload it.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn create_shared(
        keyset: &UserKeyset,
        kind: SharedKind,
        org: Option<String>,
        device_id: &str,
    ) -> Result<Arc<Vault>> {
        if org.as_deref().is_some_and(|o| !valid_id(o)) {
            return Err(PassError::InvalidInput(tr!("share.bad_org")));
        }
        let vault_id = uuid::Uuid::new_v4().to_string();
        let vk = crypto::random_key();
        let key_check = seal(&vk, vault_id.as_bytes(), &key_check_aad(&vault_id))?;
        let now = now_ms();
        let genesis = sign_genesis(&vault_id, keyset, now, kind.as_str(), org)?;
        let genesis_digest = verify_genesis(&vault_id, &genesis)?;
        let account = keyset.account().to_string();
        let me = MemberFile {
            account: account.clone(),
            role: MemberRole::Manage.as_str().into(),
            enc_pub: b64_encode(keyset.enc_pub()),
            sig_pub: b64_encode(keyset.sig_pub()),
            group: None,
            wrapped_key: wrap_vault_key(keyset.enc_pub(), &vault_id, &account, 1, &vk)?,
            added_by: account.clone(),
            added_at: now,
        };
        let members = sign_members(&vault_id, &genesis_digest, keyset, None, vec![me], 1, &vk)?;
        let path = vec![cert_ref(&vault_id, &genesis_digest, &members.cert)?];
        let inner = Inner {
            vault_id,
            device_id: device_id.to_string(),
            vk,
            kdf: stub_kdf(),
            wrapped_key: stub_wrapped_key(),
            key_check,
            header_updated_at: now,
            records: Default::default(),
            dirty: true,
            dirty_generation: 0,
            last_ts: now,
            sync: None,
            pending_members: Default::default(),
            revision: 0,
            previous_keys: Vec::new(),
            header_auth: None,
            usage: Default::default(),
            usage_since: None,
            recovery: None,
            settings: None,
            read_only: false,
            caches: Default::default(),
            account: None,
            account_recovery: None,
            shared: Some(SharedState::new(
                keyset,
                genesis,
                genesis_digest,
                members,
                path,
                true,
            )),
        };
        Ok(Arc::new(Vault {
            inner: Mutex::new(inner),
        }))
    }

    /// [`Vault::open_shared`] with the keyset and the trust record kept in `home`, the user's
    /// personal vault; records the accepted list in `home` (save `home` afterwards). What the
    /// apps use to open a shared vault.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn open_shared_with_home(
        file: Vec<u8>,
        home: &Vault,
        account: &str,
        device_id: &str,
    ) -> Result<Arc<Vault>> {
        let keyset = home
            .user_keyset(account)?
            .ok_or_else(|| PassError::NotFound(tr!("share.no_keyset")))?;
        let parsed = parse_file(&file)?;
        let trust = home.stored_share_trust(&parsed.vault_id);
        let pending = home.stored_pending_members(&parsed.vault_id);
        let vault = Self::open_shared_parsed(parsed, &keyset, trust.as_ref(), device_id)?;
        vault.lock().restore_pending(pending);
        home.remember_trust_of(&vault)?;
        Ok(vault)
    }

    pub fn is_shared(&self) -> bool {
        self.lock().shared.is_some()
    }

    /// The members list and this device's role; `None` for a personal vault.
    pub fn shared_info(&self) -> Option<SharedInfo> {
        let inner = self.lock();
        inner.shared.as_ref().map(|s| s.info(&inner.vault_id))
    }

    /// This device's role in a shared vault; `None` for a personal vault.
    pub fn shared_role(&self) -> Option<MemberRole> {
        self.lock().shared.as_ref().and_then(SharedState::role)
    }

    /// Whether items may be added, changed and deleted here (always in a personal vault).
    pub fn can_edit(&self) -> bool {
        self.lock().check_writable().is_ok()
    }

    /// Whether the apps may show and copy this vault's secrets: `false` for a fill-only member. The
    /// core can't enforce it (the item still holds the password for filling), so the apps hide
    /// Reveal, Copy, Export and the password history.
    pub fn can_reveal_secrets(&self) -> bool {
        self.lock().can_reveal()
    }

    /// Applies `changes` that wrap the key to no one new (roles, groups, removals) as one new
    /// members list signed with this device's keyset (managers only). A removal also rotates the
    /// vault key (the old one kept as an earlier key). Save and upload afterwards. `Add` and
    /// `ReplaceKeys` are refused (`InvalidInput`): use [`Vault::change_members_pinned`], which
    /// checks the keys against the user's pins.
    pub fn change_members(&self, changes: Vec<MemberChange>) -> Result<SharedInfo> {
        if changes
            .iter()
            .any(|c| matches!(c, MemberChange::Add { .. } | MemberChange::ReplaceKeys { .. }))
        {
            return Err(PassError::InvalidInput(tr!("share.needs_verified_keys")));
        }
        self.apply_member_changes(changes)
    }

    /// [`Vault::change_members`] for any change, after checking every key it would wrap the
    /// vault key to against the pins in `home`, the user's home vault: keys the user compared, or
    /// the user's own. Anything else is refused (`Crypto`)
    /// and nothing changes; [`Vault::unpinned_changes`] lists those people for the app to show
    /// with their fingerprints. A "confirmed" flag from the account service doesn't count.
    pub fn change_members_pinned(
        &self,
        changes: Vec<MemberChange>,
        home: &Vault,
    ) -> Result<SharedInfo> {
        if home.is_shared() {
            return Err(PassError::InvalidInput(tr!("share.keys_in_shared")));
        }
        for change in &changes {
            if let MemberChange::Add { keys, .. } | MemberChange::ReplaceKeys { keys } = change {
                home.require_pinned(keys, PERSONAL_SCOPE)?;
            }
        }
        self.apply_member_changes(changes)
    }

    /// Adds `keys` (pinned in `home`, [`Vault::change_members_pinned`]) with `role`.
    pub fn add_member(
        &self,
        keys: PublicKeys,
        role: MemberRole,
        group: Option<String>,
        home: &Vault,
    ) -> Result<SharedInfo> {
        self.change_members_pinned(vec![MemberChange::Add { keys, role, group }], home)
    }

    pub fn set_member_role(&self, account: &str, role: MemberRole) -> Result<SharedInfo> {
        self.change_members(vec![MemberChange::SetRole {
            account: account.to_string(),
            role,
        }])
    }

    /// Removes a member and rotates the vault key. The removed member keeps what their devices
    /// already downloaded; the apps offer to change the passwords they could see.
    pub fn remove_member(&self, account: &str) -> Result<SharedInfo> {
        self.change_members(vec![MemberChange::Remove {
            account: account.to_string(),
        }])
    }

    /// This device's account leaves the shared vault (a manager, while another manager remains): a
    /// new list without it, with a new key for everyone else. Upload, then delete this device's
    /// copy and tell the account service. The first remaining manager who syncs replaces the key
    /// again, since this device made it ([`MembersNotice::rotated_after_leave`]). A member who
    /// doesn't manage the vault leaves through the account service.
    pub fn leave_shared(&self) -> Result<()> {
        let me = {
            let inner = self.lock();
            let shared = inner.shared.as_ref().ok_or_else(not_shared)?;
            shared.account.clone()
        };
        self.change_members(vec![MemberChange::Remove { account: me }])
            .map(|_| ())
    }

    /// What merges and opens did to the members list on this device's behalf since the last
    /// call (changes applied again after losing to a concurrent change, changes dropped, a key
    /// replaced after a manager left); `None` when nothing happened or for a personal vault.
    pub fn take_members_notice(&self) -> Option<MembersNotice> {
        let mut inner = self.lock();
        let shared = inner.shared.as_mut()?;
        let notice = std::mem::take(&mut shared.notice);
        (!notice.is_empty()).then_some(notice)
    }

    /// A new vault key for the same members (a manager only), e.g. after a device was lost.
    pub fn rotate_shared_key(&self) -> Result<SharedInfo> {
        let mut inner = self.lock();
        inner.change_members(Vec::new(), true)?;
        let info = inner.shared.as_ref().map(|s| s.info(&inner.vault_id));
        info.ok_or_else(not_shared)
    }

    /// Brings the members added through `group` (a department) in line with the group's members as
    /// the account service lists them, with the keys the manager confirmed: adds the missing ones,
    /// updates their role, removes those who left the group (which rotates the key). Members added
    /// directly or through another group are left alone. Every key it adds must be pinned in `home`
    /// ([`Vault::change_members_pinned`]) or the whole sync is refused, so leave members whose keys
    /// the user hasn't compared out of `members`. `Ok(None)` when nothing changes.
    pub fn sync_group(
        &self,
        group: &str,
        members: Vec<GroupMember>,
        home: &Vault,
    ) -> Result<Option<SharedInfo>> {
        if !valid_id(group) {
            return Err(PassError::InvalidInput(tr!("share.bad_group")));
        }
        let changes = {
            let inner = self.lock();
            let shared = inner.shared.as_ref().ok_or_else(not_shared)?;
            let current = &shared.members.entries;
            let mut changes = Vec::new();
            for GroupMember { keys, role } in &members {
                match current.iter().find(|e| e.account == keys.account) {
                    None => changes.push(MemberChange::Add {
                        keys: keys.clone(),
                        role: *role,
                        group: Some(group.to_string()),
                    }),
                    Some(e) if e.group.as_deref() == Some(group) && e.role() != *role => changes
                        .push(MemberChange::SetRole {
                            account: e.account.clone(),
                            role: *role,
                        }),
                    Some(_) => {}
                }
            }
            for e in current {
                if e.group.as_deref() == Some(group)
                    && e.account != shared.account
                    && !members.iter().any(|m| m.keys.account == e.account)
                {
                    changes.push(MemberChange::Remove {
                        account: e.account.clone(),
                    });
                }
            }
            changes
        };
        if changes.is_empty() {
            return Ok(None);
        }
        self.change_members_pinned(changes, home).map(Some)
    }

    /// Copies item `id` into `target` (another vault) as a new item with a new id, keeping its
    /// contents, password history, passkeys and creation date. Needs a role here that may see
    /// secrets and one in `target` that may edit. Save both vaults afterwards.
    pub fn copy_item_to(&self, id: &str, target: &Vault) -> Result<Item> {
        self.transfer_item(id, target, false)
    }

    /// [`Vault::copy_item_to`], then deletes the original for good (a tombstone that syncs), so
    /// the item lives on only in `target`. Needs a role here that may edit.
    pub fn move_item_to(&self, id: &str, target: &Vault) -> Result<Item> {
        self.transfer_item(id, target, true)
    }
}

/// Shared vaults: the Rust-only part (the trust record as a value, the transfer itself).
impl Vault {
    fn apply_member_changes(&self, changes: Vec<MemberChange>) -> Result<SharedInfo> {
        let mut inner = self.lock();
        inner.change_members(changes, false)?;
        let info = inner.shared.as_ref().map(|s| s.info(&inner.vault_id));
        info.ok_or_else(not_shared)
    }

    /// Any change without the pin check, for tests that are about the members list itself.
    #[cfg(test)]
    pub(crate) fn change_members_unchecked(&self, changes: Vec<MemberChange>) -> Result<SharedInfo> {
        self.apply_member_changes(changes)
    }

    #[cfg(test)]
    pub(crate) fn add_member_unchecked(
        &self,
        keys: PublicKeys,
        role: MemberRole,
        group: Option<String>,
    ) -> Result<SharedInfo> {
        self.apply_member_changes(vec![MemberChange::Add { keys, role, group }])
    }

    /// The account and public keys (base64) of the manager who signed the current list, if they
    /// are still in it.
    pub(crate) fn signer_keys(&self) -> Option<(String, String, String)> {
        let inner = self.lock();
        let shared = inner.shared.as_ref()?;
        let e = shared.members.entry(&shared.members.cert.signed_by)?;
        Some((e.account.clone(), e.enc_pub.clone(), e.sig_pub.clone()))
    }

    /// Whether `enc_pub`, `sig_pub` are the public keys of a keyset kept in this (home) vault.
    pub(crate) fn is_own_keys(&self, enc_pub: &[u8; 32], sig_pub: &[u8; 32]) -> bool {
        self.setting_keys(KEYSET_SETTING)
            .into_iter()
            .filter_map(|k| self.setting(&k).map(zeroize::Zeroizing::new))
            .filter_map(|stored| UserKeyset::from_stored(&stored).ok())
            .any(|k| k.enc_pub() == enc_pub && k.sig_pub() == sig_pub)
    }

    /// Opens a shared vault's file with the member's keyset.
    ///
    /// `trust` is what this user's devices remember about the vault ([`Vault::share_trust`],
    /// kept in the home vault with [`Vault::remember_share_trust`]); `None` the first time. The
    /// genesis must be the remembered one, and the members list must verify against the lists
    /// accepted before and not be older than the newest of them (a rollback is `Conflict`, try a
    /// fresh download). The first time, the list is checked back to the vault's creation as far
    /// as the file reaches ([`SharedInfo::anchored`]).
    ///
    /// Errors: `InvalidInput` for a personal vault's file; `Crypto` when the list doesn't verify,
    /// the account isn't a member (or no longer is), or the list has other keys for it;
    /// `Conflict` for a rollback or another vault under the same id.
    pub fn open_shared(
        file: &[u8],
        keyset: &UserKeyset,
        trust: Option<&ShareTrust>,
        device_id: &str,
    ) -> Result<Arc<Vault>> {
        Self::open_shared_parsed(parse_file(file)?, keyset, trust, device_id)
    }

    fn open_shared_parsed(
        parsed: VaultFile,
        keyset: &UserKeyset,
        trust: Option<&ShareTrust>,
        device_id: &str,
    ) -> Result<Arc<Vault>> {
        let (Some(genesis), Some(members)) = (parsed.genesis.clone(), parsed.members.clone())
        else {
            return Err(not_shared());
        };
        let vault_id = parsed.vault_id.clone();
        let genesis_digest = verify_genesis(&vault_id, &genesis)?;
        let trusted: &[CertRef] = match trust {
            Some(t) => {
                if t.vault_id != vault_id {
                    return Err(PassError::InvalidInput(tr!("share.bad_trust")));
                }
                if t.genesis != genesis_digest {
                    return Err(PassError::Conflict(tr!("share.genesis_changed")));
                }
                &t.path
            }
            None => &[],
        };
        let verified = verify_members(&vault_id, &genesis, &genesis_digest, &members, trusted)
            .map_err(|r| rejection(r, &members, trusted))?;
        if let Some(last) = trusted.last() {
            if verified.current.order() < last.order() {
                return Err(PassError::Conflict(tr!("share.members_rollback")));
            }
        }
        let vk = open_own_key(&vault_id, &members, keyset)?;
        let shared = SharedState::new(
            keyset,
            genesis,
            genesis_digest,
            members,
            verified.path,
            verified.anchored,
        );
        let vault = Self::from_file(parsed, vk, device_id.to_string(), false, Some(shared))?;
        {
            let mut inner = vault.lock();
            if inner.rotate_after_leave() {
                if let Some(s) = inner.shared.as_mut() {
                    s.notice.rotated_after_leave = true;
                }
            }
        }
        Ok(vault)
    }

    /// What to remember about this shared vault between opens ([`Vault::remember_share_trust`]
    /// in the home vault); `None` for a personal vault. It moves on when a merge adopts a newer
    /// list, so store it again after syncing.
    pub fn share_trust(&self) -> Option<ShareTrust> {
        let inner = self.lock();
        inner.shared.as_ref().map(|s| s.trust(&inner.vault_id))
    }

    fn transfer_item(&self, id: &str, target: &Vault, remove: bool) -> Result<Item> {
        let (item, source) = {
            let inner = self.lock();
            if remove {
                inner.check_writable()?;
            } else if !inner.can_reveal() {
                return Err(PassError::InvalidInput(tr!("share.fill_only")));
            }
            let item = inner
                .live(id)
                .cloned()
                .ok_or_else(|| PassError::NotFound(tr!("vault.no_item")))?;
            (item, inner.vault_id.clone())
        };
        if target.vault_id() == source {
            return Err(PassError::InvalidInput(tr!("share.same_vault")));
        }
        target.lock().check_writable()?;
        let copy = Item {
            id: String::new(),
            trashed_at: None,
            ..item
        };
        let added = target.upsert_with(copy, true)?;
        if remove {
            self.delete_permanently(id.to_string())?;
        }
        Ok(added)
    }
}

/// The user's keyset and trust records in the home vault (a personal vault).
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Vault {
    /// Keeps `keyset` (private keys included) in this vault's settings: sealed with the vault
    /// key and synced with it. Only in a personal vault. Save afterwards.
    pub fn store_user_keyset(&self, keyset: &UserKeyset) -> Result<()> {
        if self.is_shared() {
            return Err(PassError::InvalidInput(tr!("share.keys_in_shared")));
        }
        let stored = keyset.to_stored();
        self.put_setting(
            &setting_key(KEYSET_SETTING, keyset.account()),
            Some(stored.to_string()),
        )?;
        Ok(())
    }

    /// The keyset of `account` kept in this vault, if any.
    pub fn user_keyset(&self, account: &str) -> Result<Option<Arc<UserKeyset>>> {
        let Some(stored) = self
            .setting(&setting_key(KEYSET_SETTING, account))
            .map(zeroize::Zeroizing::new)
        else {
            return Ok(None);
        };
        let keyset = UserKeyset::from_stored(&stored)?;
        if keyset.account() != account {
            return Err(PassError::Corrupt(tr!("share.bad_keys")));
        }
        Ok(Some(Arc::new(keyset)))
    }

    /// The keyset of `account`, made and stored here first if there is none (joining an
    /// organisation). Upload its [`UserKeyset::public_keys`] to the account service, and save.
    pub fn ensure_user_keyset(&self, account: &str) -> Result<Arc<UserKeyset>> {
        if let Some(keyset) = self.user_keyset(account)? {
            return Ok(keyset);
        }
        // One person, one keyset: the keys kept for another backend's account id (Passyble
        // Cloud and a self-hosted server name the person differently) under this id too.
        let existing = self
            .setting_keys(KEYSET_SETTING)
            .into_iter()
            .filter_map(|k| self.setting(&k).map(zeroize::Zeroizing::new))
            .find_map(|stored| UserKeyset::from_stored(&stored).ok());
        let keyset = match existing {
            Some(other) => other.with_account(account)?,
            None => UserKeyset::generate(account)?,
        };
        self.store_user_keyset(&keyset)?;
        Ok(Arc::new(keyset))
    }

    /// The public keys to publish on the backend that knows this user as `account` (Passyble
    /// Cloud: the `acc_` id; a self-hosted Passyble Server: the user name there), self-signed for
    /// that id; the keyset is made or reused first ([`Vault::ensure_user_keyset`]). Save after.
    pub fn publish_keys_for(&self, account: &str) -> Result<PublicKeys> {
        Ok(self.ensure_user_keyset(account)?.public_keys())
    }

    /// Remembers in this home vault the members list `shared` now has
    /// ([`Vault::remember_share_trust`]) and the member changes this device made there that no
    /// other copy has confirmed yet (local file only, never uploaded), so a change that loses to a
    /// concurrent one is applied again even after a restart. Call after every sync of `shared` and
    /// every member change in it, then save this vault. `true` if that changed what is kept;
    /// `false` for a personal `shared`.
    pub fn remember_trust_of(&self, shared: &Vault) -> Result<bool> {
        let Some(trust) = shared.share_trust() else {
            return Ok(false);
        };
        let trusted = self.remember_share_trust(&trust)?;
        let pending = shared.lock().shared.as_ref().map(|s| s.pending.clone());
        let kept = self.put_pending_members(&trust.vault_id, pending.unwrap_or_default());
        Ok(trusted || kept)
    }

    /// Forgets what this vault remembers about the shared vault `vault_id`, so the next open
    /// trusts the file as on a first open. For when the user confirmed, with the person who
    /// signed it, a list this device can't check.
    pub fn forget_share_trust(&self, vault_id: &str) -> Result<()> {
        self.put_setting(&setting_key(TRUST_SETTING, vault_id), None)?;
        self.put_pending_members(vault_id, Vec::new());
        Ok(())
    }
}

/// The trust records as values (Rust only; the apps use [`Vault::remember_trust_of`]).
impl Vault {
    /// What this vault remembers about the shared vault `vault_id`.
    pub fn stored_share_trust(&self, vault_id: &str) -> Option<ShareTrust> {
        self.setting(&setting_key(TRUST_SETTING, vault_id))
            .and_then(|json| ShareTrust::from_json(&json).ok())
            .filter(|t| t.vault_id == vault_id)
    }

    /// The unconfirmed member changes this home vault keeps for shared vault `vault_id`.
    fn stored_pending_members(&self, vault_id: &str) -> Vec<(String, Vec<MemberChange>)> {
        self.lock()
            .pending_members
            .get(vault_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Keeps `pending` for shared vault `vault_id` (none: forgets it); `true` if that changed
    /// anything, which marks this vault to be saved (not to be synced: local file only).
    fn put_pending_members(
        &self,
        vault_id: &str,
        pending: Vec<(String, Vec<MemberChange>)>,
    ) -> bool {
        let mut inner = self.lock();
        if inner.shared.is_some() || inner.pending_members.get(vault_id) == Some(&pending) {
            return false;
        }
        if pending.is_empty() {
            if inner.pending_members.remove(vault_id).is_none() {
                return false;
            }
        } else {
            inner.pending_members.insert(vault_id.to_string(), pending);
        }
        inner.mark_dirty();
        true
    }

    /// Remembers `trust` unless what is kept is already as new; `true` if it stored it. A record
    /// for another genesis under the same id is `Conflict` (forget it first, after asking the
    /// user). Save afterwards.
    pub fn remember_share_trust(&self, trust: &ShareTrust) -> Result<bool> {
        if self.is_shared() {
            return Err(PassError::InvalidInput(tr!("share.keys_in_shared")));
        }
        if let Some(kept) = self.stored_share_trust(&trust.vault_id) {
            if kept.genesis != trust.genesis {
                return Err(PassError::Conflict(tr!("share.genesis_changed")));
            }
            if !trust.ahead_of(&kept) {
                return Ok(false);
            }
        }
        self.put_setting(
            &setting_key(TRUST_SETTING, &trust.vault_id),
            Some(trust.to_json()),
        )
    }
}

#[cfg(test)]
#[path = "shared_tests.rs"]
mod tests;
