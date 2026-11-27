use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::vault::KdfParams;
use crate::{PassError, Result};

pub(crate) const KEY_LEN: usize = 32;
pub(crate) const NONCE_LEN: usize = 24;

/// A 32-byte key, kept in locked memory and zeroized on drop (`crate::secmem`).
pub(crate) type Key = crate::secmem::LockedKey;

pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

/// A random one-time token: 24 bytes from the OS, base64url (32 characters). For capabilities
/// handed to another process for a short while (the agent's `add_url_token`), never a key.
pub fn random_token() -> String {
    crate::encoding::b64url_encode(random_bytes::<24>().to_vec())
}

pub(crate) fn random_key() -> Key {
    let mut key = Key::zeroed();
    rand::rngs::OsRng.fill_bytes(&mut key[..]);
    key
}

/// Derives the key-encryption key from the master password with Argon2id.
pub(crate) fn derive_kek(password: &str, kdf: &KdfParams, salt: &[u8]) -> Result<Key> {
    derive_kek_bytes(password.as_bytes(), kdf, salt)
}

/// Runs Argon2id (version 0x13, 32-byte output) elsewhere: `secret`, `salt`, memory in KiB, passes
/// and lanes in; the key out, `None` on failure. Must match the `argon2` crate exactly.
///
/// Used by the browser extension's WebAssembly: running Argon2id with the vault defaults grows a
/// WebAssembly instance's memory to about 84 MiB and it never shrinks, so each run is handed to a
/// short-lived module.
pub type Argon2idRunner =
    fn(secret: &[u8], salt: &[u8], m_kib: u32, t: u32, p: u32) -> Option<[u8; KEY_LEN]>;

static ARGON2ID_RUNNER: std::sync::RwLock<Option<Argon2idRunner>> = std::sync::RwLock::new(None);

/// Sets (or with `None` clears) the runner used for every Argon2id derivation. Unset, the core
/// runs it itself.
pub fn set_argon2id_runner(runner: Option<Argon2idRunner>) {
    *ARGON2ID_RUNNER.write().unwrap_or_else(|p| p.into_inner()) = runner;
}

fn argon2id_runner() -> Option<Argon2idRunner> {
    *ARGON2ID_RUNNER.read().unwrap_or_else(|p| p.into_inner())
}

/// [`derive_kek`] for a secret that is bytes, not text (the recovery secret, `crate::recovery`).
pub(crate) fn derive_kek_bytes(secret: &[u8], kdf: &KdfParams, salt: &[u8]) -> Result<Key> {
    let params = Params::new(kdf.m_kib, kdf.t, kdf.p, Some(KEY_LEN))
        .map_err(|_| PassError::Crypto(crate::i18n::tr!("crypto.key_failed")))?;
    if let Some(runner) = argon2id_runner() {
        return runner(secret, salt, kdf.m_kib, kdf.t, kdf.p)
            .map(Key::from_array)
            .ok_or_else(|| PassError::Crypto(crate::i18n::tr!("crypto.key_failed")));
    }
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Key::zeroed();
    argon
        .hash_password_into(secret, salt, &mut out[..])
        .map_err(|_| PassError::Crypto(crate::i18n::tr!("crypto.key_failed")))?;
    Ok(out)
}

/// Constant-time equality (the lengths are not secret).
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// XChaCha20-Poly1305 with a fresh random nonce. Returns `(nonce, ciphertext)`.
pub(crate) fn seal(
    key: &[u8; KEY_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let nonce = random_bytes::<NONCE_LEN>();
    let ct = seal_with_nonce(key, &nonce, plaintext, aad)?;
    Ok((nonce, ct))
}

/// [`seal`] with a given nonce, for formats with test vectors (`crate::send`). The caller makes
/// sure a nonce is never used twice with one key: every other caller uses [`seal`].
pub(crate) fn seal_with_nonce(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| PassError::Crypto(crate::i18n::tr!("crypto.encryption_failed")))
}

/// Decrypts and authenticates; any tampering or a wrong key yields `None`.
pub(crate) fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    if nonce.len() != NONCE_LEN {
        return None;
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
        .map(Zeroizing::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `argon2` crate's output, as a runner must return.
    fn argon2_crate(
        secret: &[u8],
        salt: &[u8],
        m_kib: u32,
        t: u32,
        p: u32,
    ) -> Option<[u8; KEY_LEN]> {
        let params = Params::new(m_kib, t, p, Some(KEY_LEN)).ok()?;
        let mut out = [0u8; KEY_LEN];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(secret, salt, &mut out)
            .ok()?;
        Some(out)
    }

    static RUNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn counting_runner(
        secret: &[u8],
        salt: &[u8],
        m_kib: u32,
        t: u32,
        p: u32,
    ) -> Option<[u8; KEY_LEN]> {
        RUNS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        argon2_crate(secret, salt, m_kib, t, p)
    }

    #[test]
    fn a_runner_takes_over_argon2id_and_gives_the_same_key() {
        let kdf = KdfParams {
            m_kib: 1024,
            t: 1,
            ..KdfParams::default()
        };
        let salt = [7u8; 16];
        let own = derive_kek("pw", &kdf, &salt).unwrap();
        // Other tests derive keys concurrently; the runner gives the same result anyway.
        set_argon2id_runner(Some(counting_runner));
        let before = RUNS.load(std::sync::atomic::Ordering::SeqCst);
        let run = derive_kek("pw", &kdf, &salt);
        let after = RUNS.load(std::sync::atomic::Ordering::SeqCst);
        // Parameters the core refuses never reach the runner.
        let refused = derive_kek(
            "pw",
            &KdfParams {
                t: 0,
                ..kdf.clone()
            },
            &salt,
        );
        set_argon2id_runner(None);
        assert!(after > before, "the runner was used");
        assert_eq!(run.unwrap().as_slice(), own.as_slice());
        assert!(refused.is_err());
    }

    #[test]
    fn seal_open_roundtrip_and_tamper() {
        let key = random_key();
        let (nonce, mut ct) = seal(&key, b"secret", b"aad").unwrap();
        assert_eq!(
            open(&key, &nonce, &ct, b"aad").unwrap().as_slice(),
            b"secret"
        );
        assert!(open(&key, &nonce, &ct, b"other aad").is_none());
        ct[0] ^= 1;
        assert!(open(&key, &nonce, &ct, b"aad").is_none());
    }
}
