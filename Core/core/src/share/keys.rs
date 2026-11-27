//! A user's keyset for shared vaults: an X25519 key pair that vault keys are wrapped for, and an
//! Ed25519 key pair that signs members lists. The private keys live only in the user's home vault;
//! the self-signed public keys go to the account service so managers can add the user to a vault.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{Key, KEY_LEN};
use crate::encoding::{b64_decode, b64_encode};
use crate::i18n::tr;
use crate::{now_ms, PassError, Result};

/// Bytes of an X25519 or Ed25519 public key, and of either private key.
pub(crate) const KEY_BYTES: usize = 32;

/// Longest account id or group id the core accepts (they come from the account service).
pub(crate) const MAX_ID_LEN: usize = 128;

/// Whether `id` can be an account or group id: 1 to [`MAX_ID_LEN`] bytes, printable ASCII
/// without spaces. Ids go into signed and HPKE-bound strings, so nothing that could be confused
/// for a separator in a log or a UI.
pub(crate) fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_ID_LEN && id.bytes().all(|b| b.is_ascii_graphic())
}

fn bad_keys() -> PassError {
    PassError::InvalidInput(tr!("share.bad_keys"))
}

/// Decodes base64 into a 32-byte key.
pub(crate) fn key_bytes(b64: &str) -> Result<[u8; KEY_BYTES]> {
    let bytes = b64_decode(b64).map_err(|_| bad_keys())?;
    bytes.as_slice().try_into().map_err(|_| bad_keys())
}

/// The message of a public keys' self-signature: `"pass/userkeys/v1:" + account_id + enc_pub +
/// sig_pub + created_at`, the keys as their 32 raw bytes and `created_at` as 8 bytes big-endian.
/// Everything after the account id has a fixed length, so the concatenation is unambiguous.
fn self_signature_message(
    account: &str,
    enc_pub: &[u8; KEY_BYTES],
    sig_pub: &[u8; KEY_BYTES],
    created_at: i64,
) -> Vec<u8> {
    let mut msg = b"pass/userkeys/v1:".to_vec();
    msg.extend_from_slice(account.as_bytes());
    msg.extend_from_slice(enc_pub);
    msg.extend_from_slice(sig_pub);
    msg.extend_from_slice(&created_at.to_be_bytes());
    msg
}

/// Characters in a key fingerprint: six groups of five.
const FP_CHARS: usize = 30;

/// The fingerprint of a pair of public keys, for two people to compare (on the phone, side by
/// side): the first 150 bits of `SHA-256("pass/userkeys-fp/v1:" + enc_pub + sig_pub)` in the
/// recovery code's alphabet (Crockford's base32), six groups of five: `7K3QD-…`.
pub(crate) fn fingerprint(enc_pub: &[u8; KEY_BYTES], sig_pub: &[u8; KEY_BYTES]) -> String {
    let mut h = Sha256::new();
    h.update(b"pass/userkeys-fp/v1:");
    h.update(enc_pub);
    h.update(sig_pub);
    let digest = h.finalize();
    let bit = |i: usize| (digest[i / 8] >> (7 - i % 8)) & 1;
    let mut out = String::with_capacity(FP_CHARS + FP_CHARS / 5);
    for c in 0..FP_CHARS {
        if c > 0 && c % 5 == 0 {
            out.push('-');
        }
        let v = (0..5).fold(0usize, |v, b| (v << 1) | bit(c * 5 + b) as usize);
        out.push(crate::recovery::ALPHABET[v] as char);
    }
    out
}

/// Verifies an Ed25519 signature (strict: no malleable or small-order forms).
pub(crate) fn verify_signature(sig_pub: &[u8; KEY_BYTES], msg: &[u8], sig: &str) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(sig_pub) else {
        return false;
    };
    let Ok(sig) = b64_decode(sig) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&sig) else {
        return false;
    };
    key.verify_strict(msg, &sig).is_ok()
}

/// A user's public keys as the account service hands them out, self-signed for the account id.
/// The service could still hand out a key pair it made itself, so a manager confirms the
/// [`PublicKeys::fingerprint`] with the person before adding them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PublicKeys {
    pub account: String,
    /// X25519 public key, base64.
    pub enc_pub: String,
    /// Ed25519 public key, base64.
    pub sig_pub: String,
    /// When the keyset was made (Unix ms).
    pub created_at: i64,
    /// Ed25519 signature of [`self_signature_message`] with the keyset's signing key, base64.
    pub sig: String,
}

impl PublicKeys {
    /// Checks the self-signature and the key encodings.
    pub fn verify(&self) -> Result<()> {
        if !valid_id(&self.account) {
            return Err(bad_keys());
        }
        let enc_pub = key_bytes(&self.enc_pub)?;
        let sig_pub = key_bytes(&self.sig_pub)?;
        // A point that isn't on the curve is refused here rather than at the first wrap.
        <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&enc_pub).map_err(|_| bad_keys())?;
        let msg = self_signature_message(&self.account, &enc_pub, &sig_pub, self.created_at);
        if !verify_signature(&sig_pub, &msg, &self.sig) {
            return Err(bad_keys());
        }
        Ok(())
    }

    /// [`fingerprint`] of these keys; `""` if they don't decode.
    pub fn fingerprint(&self) -> String {
        match (key_bytes(&self.enc_pub), key_bytes(&self.sig_pub)) {
            (Ok(e), Ok(s)) => fingerprint(&e, &s),
            _ => String::new(),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("plain strings and numbers")
    }

    pub fn from_json(json: &str) -> Result<PublicKeys> {
        serde_json::from_str(json).map_err(|_| bad_keys())
    }
}

/// [`PublicKeys::verify`] for the bindings: `Ok` when the self-signature and the keys are valid.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn public_keys_verify(keys: PublicKeys) -> Result<()> {
    keys.verify()
}

/// [`PublicKeys::fingerprint`] for the bindings: `7K3QD-…`, `""` for keys that don't decode.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn public_keys_fingerprint(keys: PublicKeys) -> String {
    keys.fingerprint()
}

/// The stored form of a keyset (the value of the home vault setting).
#[derive(Serialize, Deserialize)]
struct StoredKeyset {
    v: u32,
    account: String,
    created_at: i64,
    enc_sk: String,
    sig_sk: String,
}

/// A user's keyset with its private keys. Stored only in the home vault's settings
/// ([`crate::Vault::store_user_keyset`]) and wiped from memory on drop. An object in the
/// bindings, so the private keys never cross into Kotlin, Swift or JavaScript.
#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct UserKeyset {
    account: String,
    created_at: i64,
    enc_sk: Zeroizing<[u8; KEY_BYTES]>,
    sig_sk: Zeroizing<[u8; KEY_BYTES]>,
    enc_pub: [u8; KEY_BYTES],
    sig_pub: [u8; KEY_BYTES],
}

/// Never the private keys in debug output.
impl std::fmt::Debug for UserKeyset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserKeyset")
            .field("account", &self.account)
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

impl UserKeyset {
    /// A new keyset for `account` from the OS random number generator.
    pub fn generate(account: &str) -> Result<UserKeyset> {
        if !valid_id(account) {
            return Err(PassError::InvalidInput(tr!("share.bad_account")));
        }
        let (sk, _) = X25519HkdfSha256::gen_keypair(&mut rand::rngs::OsRng);
        let mut enc_sk = Zeroizing::new([0u8; KEY_BYTES]);
        enc_sk.copy_from_slice(&Zeroizing::new(sk.to_bytes().to_vec()));
        let sig_sk = Zeroizing::new(crate::crypto::random_bytes::<KEY_BYTES>());
        Self::from_parts(account.to_string(), now_ms(), enc_sk, sig_sk)
    }

    fn from_parts(
        account: String,
        created_at: i64,
        enc_sk: Zeroizing<[u8; KEY_BYTES]>,
        sig_sk: Zeroizing<[u8; KEY_BYTES]>,
    ) -> Result<UserKeyset> {
        let sk = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(enc_sk.as_slice())
            .map_err(|_| bad_keys())?;
        let mut enc_pub = [0u8; KEY_BYTES];
        enc_pub.copy_from_slice(&X25519HkdfSha256::sk_to_pk(&sk).to_bytes());
        let sig_pub = SigningKey::from_bytes(&sig_sk).verifying_key().to_bytes();
        Ok(UserKeyset {
            account,
            created_at,
            enc_sk,
            sig_sk,
            enc_pub,
            sig_pub,
        })
    }

    pub fn account(&self) -> &str {
        &self.account
    }

    pub(crate) fn enc_pub(&self) -> &[u8; KEY_BYTES] {
        &self.enc_pub
    }

    pub(crate) fn sig_pub(&self) -> &[u8; KEY_BYTES] {
        &self.sig_pub
    }

    fn signed_for(&self, account: &str) -> PublicKeys {
        let msg = self_signature_message(account, &self.enc_pub, &self.sig_pub, self.created_at);
        PublicKeys {
            account: account.to_string(),
            enc_pub: b64_encode(&self.enc_pub),
            sig_pub: b64_encode(&self.sig_pub),
            created_at: self.created_at,
            sig: self.sign(&msg),
        }
    }

    /// This keyset (the same private keys) under another account id: what opens and signs the
    /// shared vaults of another backend, whose members lists name the person by that id.
    pub(crate) fn with_account(&self, account: &str) -> Result<UserKeyset> {
        if !valid_id(account) {
            return Err(PassError::InvalidInput(tr!("share.bad_account")));
        }
        let mut other = self.clone();
        other.account = account.to_string();
        Ok(other)
    }

    /// The X25519 private key, for opening HPKE seals to it (`share::emergency`,
    /// `share::org_recovery`).
    pub(crate) fn enc_secret(&self) -> &[u8; KEY_BYTES] {
        &self.enc_sk
    }

    /// Ed25519 signature of `msg`, base64.
    pub(crate) fn sign(&self, msg: &[u8]) -> String {
        let key = SigningKey::from_bytes(&self.sig_sk);
        b64_encode(&key.sign(msg).to_bytes())
    }

    /// The stored form (private keys included): a secret.
    pub(crate) fn to_stored(&self) -> Zeroizing<String> {
        let stored = StoredKeyset {
            v: 1,
            account: self.account.clone(),
            created_at: self.created_at,
            enc_sk: b64_encode(self.enc_sk.as_slice()),
            sig_sk: b64_encode(self.sig_sk.as_slice()),
        };
        let json = Zeroizing::new(serde_json::to_string(&stored).expect("plain strings"));
        let mut stored = stored;
        zeroize::Zeroize::zeroize(&mut stored.enc_sk);
        zeroize::Zeroize::zeroize(&mut stored.sig_sk);
        json
    }

    pub(crate) fn from_stored(json: &str) -> Result<UserKeyset> {
        let mut stored: StoredKeyset = serde_json::from_str(json).map_err(|_| bad_keys())?;
        let parts = (|| {
            if stored.v != 1 || !valid_id(&stored.account) {
                return Err(bad_keys());
            }
            let enc = Zeroizing::new(b64_decode(&stored.enc_sk).map_err(|_| bad_keys())?);
            let sig = Zeroizing::new(b64_decode(&stored.sig_sk).map_err(|_| bad_keys())?);
            let mut enc_sk = Zeroizing::new([0u8; KEY_BYTES]);
            let mut sig_sk = Zeroizing::new([0u8; KEY_BYTES]);
            if enc.len() != KEY_BYTES || sig.len() != KEY_BYTES {
                return Err(bad_keys());
            }
            enc_sk.copy_from_slice(&enc);
            sig_sk.copy_from_slice(&sig);
            Ok((enc_sk, sig_sk))
        })();
        zeroize::Zeroize::zeroize(&mut stored.enc_sk);
        zeroize::Zeroize::zeroize(&mut stored.sig_sk);
        let (enc_sk, sig_sk) = parts?;
        Self::from_parts(stored.account, stored.created_at, enc_sk, sig_sk)
    }
}

/// The keyset as the apps use it (UniFFI: `UserKeyset`).
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl UserKeyset {
    /// A new keyset for `account` (UniFFI constructor). Store it with
    /// [`crate::Vault::store_user_keyset`], or use [`crate::Vault::ensure_user_keyset`].
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new(account: &str) -> Result<std::sync::Arc<UserKeyset>> {
        Self::generate(account).map(std::sync::Arc::new)
    }

    pub fn account_id(&self) -> String {
        self.account.clone()
    }

    pub fn created_at(&self) -> i64 {
        self.created_at
    }

    /// The public half, self-signed for this keyset's account id, for the account service.
    pub fn public_keys(&self) -> PublicKeys {
        self.signed_for(&self.account)
    }

    /// The same public keys self-signed for another account id, so one keyset can be published
    /// under each backend's own id. A signature for one id never verifies for another.
    pub fn public_keys_for(&self, account: &str) -> Result<PublicKeys> {
        if !valid_id(account) {
            return Err(PassError::InvalidInput(tr!("share.bad_account")));
        }
        Ok(self.signed_for(account))
    }

    /// [`fingerprint`] of this keyset's public keys.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.enc_pub, &self.sig_pub)
    }
}

/// HPKE suite of every seal in this module and its users: base mode, DHKEM(X25519, HKDF-SHA256),
/// HKDF-SHA256, ChaCha20-Poly1305 (RFC 9180).
pub(crate) fn hpke_seal(
    enc_pub: &[u8; KEY_BYTES],
    info: &[u8],
    plain: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let pk = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(enc_pub).map_err(|_| bad_keys())?;
    let (encapped, ct) =
        hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256, _>(
            &OpModeS::Base,
            &pk,
            info,
            plain,
            b"",
            &mut rand::rngs::OsRng,
        )
        .map_err(|_| PassError::Crypto(tr!("crypto.encryption_failed")))?;
    Ok((encapped.to_bytes().to_vec(), ct))
}

/// Opens an [`hpke_seal`] with the X25519 private key `enc_sk`; `None` if it doesn't open.
pub(crate) fn hpke_open(
    enc_sk: &[u8; KEY_BYTES],
    info: &[u8],
    encapped: &[u8],
    ct: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let sk = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(enc_sk).ok()?;
    let encapped = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(encapped).ok()?;
    hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &sk,
        &encapped,
        info,
        ct,
        b"",
    )
    .ok()
    .map(Zeroizing::new)
}

/// A fresh X25519 key pair for HPKE: (private, public).
pub(crate) fn hpke_keypair() -> (Zeroizing<[u8; KEY_BYTES]>, [u8; KEY_BYTES]) {
    let (sk, pk) = X25519HkdfSha256::gen_keypair(&mut rand::rngs::OsRng);
    let mut secret = Zeroizing::new([0u8; KEY_BYTES]);
    secret.copy_from_slice(&Zeroizing::new(sk.to_bytes().to_vec()));
    let mut public = [0u8; KEY_BYTES];
    public.copy_from_slice(&pk.to_bytes());
    (secret, public)
}

/// The X25519 public key of `secret`; `None` if it isn't a valid private key.
pub(crate) fn hpke_public_of(secret: &[u8; KEY_BYTES]) -> Option<[u8; KEY_BYTES]> {
    let sk = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(secret).ok()?;
    let mut public = [0u8; KEY_BYTES];
    public.copy_from_slice(&X25519HkdfSha256::sk_to_pk(&sk).to_bytes());
    Some(public)
}

/// Whether `enc_pub` is a usable X25519 public key.
pub(crate) fn valid_enc_pub(enc_pub: &[u8; KEY_BYTES]) -> bool {
    <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(enc_pub).is_ok()
}

/// A vault key wrapped for one member with HPKE: the encapsulated key and the ciphertext, base64.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WrappedKey {
    pub enc: String,
    pub ct: String,
}

/// HPKE `info` of a member's wrapped vault key: `"pass/member-vk/v1:" + JSON[vault_id, account,
/// key_epoch]`. It binds the wrap to the vault, the member and the key generation, so a wrapped
/// key can't be moved to another vault, another member's entry or another epoch.
fn member_vk_info(vault_id: &str, account: &str, key_epoch: u64) -> Vec<u8> {
    let mut info = b"pass/member-vk/v1:".to_vec();
    info.extend(serde_json::to_vec(&(vault_id, account, key_epoch)).expect("strings and a number"));
    info
}

/// Wraps `vk` for the member whose X25519 public key is `enc_pub` (HPKE base mode,
/// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305; RFC 9180).
pub(crate) fn wrap_vault_key(
    enc_pub: &[u8; KEY_BYTES],
    vault_id: &str,
    account: &str,
    key_epoch: u64,
    vk: &Key,
) -> Result<WrappedKey> {
    let pk = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(enc_pub).map_err(|_| bad_keys())?;
    let info = member_vk_info(vault_id, account, key_epoch);
    let (encapped, ct) =
        hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256, _>(
            &OpModeS::Base,
            &pk,
            &info,
            vk.as_slice(),
            b"",
            &mut rand::rngs::OsRng,
        )
        .map_err(|_| PassError::Crypto(tr!("crypto.encryption_failed")))?;
    Ok(WrappedKey {
        enc: b64_encode(&encapped.to_bytes()),
        ct: b64_encode(&ct),
    })
}

/// Opens a vault key wrapped for `keyset` with [`wrap_vault_key`]; `None` if it doesn't open (not
/// for this keyset, another vault, member or epoch, or damaged).
pub(crate) fn unwrap_vault_key(
    keyset: &UserKeyset,
    wrapped: &WrappedKey,
    vault_id: &str,
    key_epoch: u64,
) -> Option<Key> {
    let sk = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(keyset.enc_sk.as_slice()).ok()?;
    let encapped =
        <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&b64_decode(&wrapped.enc).ok()?).ok()?;
    let ct = b64_decode(&wrapped.ct).ok()?;
    let info = member_vk_info(vault_id, &keyset.account, key_epoch);
    let plain = Zeroizing::new(
        hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &sk,
            &encapped,
            &info,
            &ct,
            b"",
        )
        .ok()?,
    );
    let key: [u8; KEY_LEN] = plain.as_slice().try_into().ok()?;
    Some(Key::from_array(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_keys_verify_and_resist_tampering() {
        let keys = UserKeyset::generate("acc_alice").unwrap();
        let public = keys.public_keys();
        public.verify().unwrap();
        assert_eq!(public.fingerprint(), keys.fingerprint());
        let round = PublicKeys::from_json(&public.to_json()).unwrap();
        assert_eq!(round, public);

        // Another account id, another key or another date breaks the self-signature.
        let mut other = public.clone();
        other.account = "acc_mallory".into();
        assert!(other.verify().is_err());
        let mallory = UserKeyset::generate("acc_mallory").unwrap().public_keys();
        let mut swapped = public.clone();
        swapped.enc_pub = mallory.enc_pub.clone();
        assert!(swapped.verify().is_err());
        let mut later = public.clone();
        later.created_at += 1;
        assert!(later.verify().is_err());
    }

    #[test]
    fn one_keyset_is_published_under_each_backends_account_id() {
        let keys = UserKeyset::generate("acc_01JALICE").unwrap();
        let cloud = keys.public_keys();
        let server = keys.public_keys_for("alice").unwrap();
        cloud.verify().unwrap();
        server.verify().unwrap();
        // The same keys, so the same fingerprint, under both ids.
        assert_eq!(cloud.enc_pub, server.enc_pub);
        assert_eq!(cloud.sig_pub, server.sig_pub);
        assert_eq!(cloud.fingerprint(), server.fingerprint());
        // A signature for one id never verifies for the other.
        let mut moved = cloud.clone();
        moved.account = "alice".into();
        assert!(moved.verify().is_err());
        let mut back = server.clone();
        back.account = "acc_01JALICE".into();
        assert!(back.verify().is_err());
        assert_ne!(cloud.sig, server.sig);
        assert!(keys.public_keys_for("with space").is_err());
        // The keyset under the other id signs as that id.
        let as_server = keys.with_account("alice").unwrap();
        assert_eq!(as_server.public_keys(), server);
        assert_eq!(as_server.fingerprint(), keys.fingerprint());
    }

    #[test]
    fn fingerprints_are_six_groups_of_five_in_the_recovery_alphabet() {
        let fp = UserKeyset::generate("acc_alice").unwrap().fingerprint();
        let groups: Vec<&str> = fp.split('-').collect();
        assert_eq!(groups.len(), 6);
        for g in groups {
            assert_eq!(g.len(), 5);
            assert!(g.bytes().all(|b| crate::recovery::ALPHABET.contains(&b)));
        }
        let other = UserKeyset::generate("acc_alice").unwrap().fingerprint();
        assert_ne!(fp, other);
    }

    #[test]
    fn stored_keyset_round_trips() {
        let keys = UserKeyset::generate("acc_alice").unwrap();
        let back = UserKeyset::from_stored(&keys.to_stored()).unwrap();
        assert_eq!(back.public_keys(), keys.public_keys());
        assert!(UserKeyset::from_stored("{}").is_err());
        assert!(!format!("{keys:?}").contains(&b64_encode(keys.sig_sk.as_slice())));
    }

    #[test]
    fn wrapped_key_is_bound_to_vault_member_and_epoch() {
        let alice = UserKeyset::generate("acc_alice").unwrap();
        let bob = UserKeyset::generate("acc_bob").unwrap();
        let vk: Key = crate::crypto::random_key();
        let wrapped = wrap_vault_key(alice.enc_pub(), "vault-1", "acc_alice", 3, &vk).unwrap();
        let opened = unwrap_vault_key(&alice, &wrapped, "vault-1", 3).unwrap();
        assert_eq!(opened.as_slice(), vk.as_slice());
        // Wrong vault id in the HPKE info.
        assert!(unwrap_vault_key(&alice, &wrapped, "vault-2", 3).is_none());
        // Wrong epoch.
        assert!(unwrap_vault_key(&alice, &wrapped, "vault-1", 4).is_none());
        // Another member's key can't open it.
        assert!(unwrap_vault_key(&bob, &wrapped, "vault-1", 3).is_none());
        // Wrapped for Alice's public key but under Bob's name: Bob's entry can't reuse it.
        let for_bob_name = wrap_vault_key(alice.enc_pub(), "vault-1", "acc_bob", 3, &vk).unwrap();
        assert!(unwrap_vault_key(&alice, &for_bob_name, "vault-1", 3).is_none());
    }

    #[test]
    fn ids_are_checked() {
        assert!(valid_id("acc_01HZY"));
        assert!(!valid_id(""));
        assert!(!valid_id("with space"));
        assert!(!valid_id(&"a".repeat(MAX_ID_LEN + 1)));
        assert!(UserKeyset::generate("bad id").is_err());
    }
}
