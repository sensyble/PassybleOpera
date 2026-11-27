//! Argon2id as a small standalone WebAssembly module. WebAssembly memory never shrinks, so the
//! long-lived vault instance hands each run to a fresh instance of this one, which is then dropped.
//! It must derive exactly the same key as pass-core.

/// Length of the key, as in pass-core.
pub const KEY_LEN: usize = 32;

/// Argon2id (version 0x13) with a 32-byte output: pass-core's key derivation. `None` for parameters
/// Argon2 refuses.
pub fn argon2id(secret: &[u8], salt: &[u8], m_kib: u32, t: u32, p: u32) -> Option<[u8; KEY_LEN]> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(m_kib, t, p, Some(KEY_LEN)).ok()?;
    let mut out = [0u8; KEY_LEN];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(secret, salt, &mut out)
        .ok()?;
    Some(out)
}

/// Room for `len` bytes in this instance's memory. Never freed: the host drops the instance.
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn kdf_alloc(len: usize) -> *mut u8 {
    let mut room = std::mem::ManuallyDrop::new(Vec::<u8>::with_capacity(len.max(1)));
    room.as_mut_ptr()
}

/// Writes the 32-byte key at `out_ptr`. Returns `0` on success, `1` for parameters Argon2
/// refuses.
///
/// # Safety
///
/// `secret_ptr` and `salt_ptr` must point at `secret_len` and `salt_len` readable bytes and
/// `out_ptr` at 32 writable bytes of this instance's memory (from [`kdf_alloc`]).
#[cfg(target_arch = "wasm32")]
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn kdf_argon2id(
    secret_ptr: *const u8,
    secret_len: usize,
    salt_ptr: *const u8,
    salt_len: usize,
    m_kib: u32,
    t: u32,
    p: u32,
    out_ptr: *mut u8,
) -> u32 {
    // SAFETY: the caller hands in buffers it allocated with `kdf_alloc` (see above).
    let (secret, salt, out) = unsafe {
        (
            std::slice::from_raw_parts(secret_ptr, secret_len),
            std::slice::from_raw_parts(salt_ptr, salt_len),
            std::slice::from_raw_parts_mut(out_ptr, KEY_LEN),
        )
    };
    match argon2id(secret, salt, m_kib, t, p) {
        Some(key) => {
            out.copy_from_slice(&key);
            0
        }
        None => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::argon2id;

    #[test]
    fn refuses_what_argon2_refuses() {
        assert!(argon2id(b"pw", &[0; 16], 8, 0, 1).is_none());
        assert!(argon2id(b"pw", &[0; 16], 64, 1, 1).is_some());
    }
}
