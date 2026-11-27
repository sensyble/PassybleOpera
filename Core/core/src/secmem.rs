//! Key material kept out of swap, the Windows pagefile and crash dumps, as far as an ordinary
//! process can. Every long-lived 32-byte key is a [`LockedKey`] in one small region, allocated
//! once, locked in RAM and left out of dumps where the system allows. Best effort: when locking is
//! refused or the region is full, keys still work, and every key is zeroized on drop.

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
use std::sync::{Mutex, OnceLock};

use zeroize::Zeroize;

use crate::crypto::KEY_LEN;

/// Size and alignment of the region: a whole number of pages on every system the apps run on
/// (4 KiB on x86-64, Windows and most Linux, 16 KiB on Apple silicon).
const REGION: usize = 16 * 1024;
const SLOTS: usize = REGION / KEY_LEN;
const WORDS: usize = SLOTS.div_ceil(64);

/// The region and which of its slots are taken.
struct Pool {
    base: NonNull<u8>,
    used: [u64; WORDS],
    /// Whether the system agreed to keep the region in RAM.
    locked: bool,
}

// SAFETY: the region is only ever reached through the pool's mutex (to hand out and take back
// slots) and through the `LockedKey` that owns a slot exclusively.
unsafe impl Send for Pool {}

impl Pool {
    fn new() -> Option<Pool> {
        let layout = std::alloc::Layout::from_size_align(REGION, REGION).ok()?;
        // SAFETY: the layout has a non-zero size. The region is never freed (it lives as long as
        // the process), so nothing can use it after it is gone.
        let base = NonNull::new(unsafe { std::alloc::alloc_zeroed(layout) })?;
        let locked = os::protect(base.as_ptr(), REGION);
        Some(Pool {
            base,
            used: [0; WORDS],
            locked,
        })
    }

    fn take(&mut self) -> Option<usize> {
        for (w, word) in self.used.iter_mut().enumerate() {
            if *word != u64::MAX {
                let bit = (!*word).trailing_zeros() as usize;
                let slot = w * 64 + bit;
                if slot >= SLOTS {
                    return None;
                }
                *word |= 1 << bit;
                return Some(slot);
            }
        }
        None
    }

    fn give_back(&mut self, slot: usize) {
        self.used[slot / 64] &= !(1u64 << (slot % 64));
    }

    fn slot_ptr(&self, slot: usize) -> NonNull<[u8; KEY_LEN]> {
        // SAFETY: `slot < SLOTS`, so the slot lies inside the region.
        unsafe { NonNull::new_unchecked(self.base.as_ptr().add(slot * KEY_LEN).cast()) }
    }
}

fn pool() -> Option<&'static Mutex<Pool>> {
    static POOL: OnceLock<Option<Mutex<Pool>>> = OnceLock::new();
    POOL.get_or_init(|| Pool::new().map(Mutex::new)).as_ref()
}

fn with_pool<T>(f: impl FnOnce(&mut Pool) -> T) -> Option<T> {
    let pool = pool()?;
    let mut guard = pool.lock().unwrap_or_else(|p| p.into_inner());
    Some(f(&mut guard))
}

/// Whether the key region is locked in RAM on this system (the first call sets the region up).
/// For diagnostics: the apps log it at start-up. `false` on a system without page locking (the
/// browser's WebAssembly) and when the system refused.
pub fn key_memory_locked() -> bool {
    with_pool(|p| p.locked).unwrap_or(false)
}

/// A 32-byte key in the locked region (or, when that is full, on the heap), zeroized on drop.
/// Derefs to `[u8; 32]`.
pub(crate) struct LockedKey {
    ptr: NonNull<[u8; KEY_LEN]>,
    /// The region's slot, or `None` for a key on the heap (a leaked `Box`).
    slot: Option<usize>,
}

// SAFETY: a `LockedKey` owns its bytes exclusively (a slot nobody else is handed, or its own box);
// shared access only reads them.
unsafe impl Send for LockedKey {}
unsafe impl Sync for LockedKey {}

impl LockedKey {
    /// An all-zero key, to be filled in place (so the secret is never copied around first).
    pub(crate) fn zeroed() -> LockedKey {
        let slot = with_pool(|p| p.take().map(|slot| (slot, p.slot_ptr(slot)))).flatten();
        match slot {
            Some((slot, ptr)) => {
                // SAFETY: the slot was just handed to us alone. Dropped keys are wiped already;
                // clearing it again keeps `zeroed` true whatever happened before.
                unsafe { ptr.as_ptr().write([0u8; KEY_LEN]) };
                LockedKey {
                    ptr,
                    slot: Some(slot),
                }
            }
            None => LockedKey {
                ptr: NonNull::from(Box::leak(Box::new([0u8; KEY_LEN]))),
                slot: None,
            },
        }
    }

    /// A key with these bytes; the caller's copy is zeroized.
    pub(crate) fn from_array(mut bytes: [u8; KEY_LEN]) -> LockedKey {
        let mut key = LockedKey::zeroed();
        key.copy_from_slice(&bytes);
        bytes.zeroize();
        key
    }

    /// A key from a slice of exactly 32 bytes.
    pub(crate) fn from_slice(bytes: &[u8]) -> Option<LockedKey> {
        if bytes.len() != KEY_LEN {
            return None;
        }
        let mut key = LockedKey::zeroed();
        key.copy_from_slice(bytes);
        Some(key)
    }

    #[cfg(test)]
    fn in_region(&self) -> bool {
        self.slot.is_some()
    }
}

impl Deref for LockedKey {
    type Target = [u8; KEY_LEN];

    fn deref(&self) -> &[u8; KEY_LEN] {
        // SAFETY: `ptr` is valid and owned by `self` until drop.
        unsafe { self.ptr.as_ref() }
    }
}

impl DerefMut for LockedKey {
    fn deref_mut(&mut self) -> &mut [u8; KEY_LEN] {
        // SAFETY: as above, and `&mut self` makes the access exclusive.
        unsafe { self.ptr.as_mut() }
    }
}

impl AsRef<[u8]> for LockedKey {
    fn as_ref(&self) -> &[u8] {
        &self[..]
    }
}

impl AsMut<[u8]> for LockedKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self[..]
    }
}

impl Clone for LockedKey {
    fn clone(&self) -> LockedKey {
        let mut copy = LockedKey::zeroed();
        copy.copy_from_slice(&self[..]);
        copy
    }
}

impl fmt::Debug for LockedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LockedKey(..)")
    }
}

impl Drop for LockedKey {
    fn drop(&mut self) {
        // SAFETY: `ptr` is still ours; this is the last use.
        unsafe { self.ptr.as_mut() }.zeroize();
        match self.slot {
            Some(slot) => {
                with_pool(|p| p.give_back(slot));
            }
            // SAFETY: a key without a slot came from `Box::leak` in `zeroed`.
            None => drop(unsafe { Box::from_raw(self.ptr.as_ptr()) }),
        }
    }
}

#[cfg(windows)]
mod os {
    use std::ffi::c_void;

    #[link(name = "kernel32")]
    extern "system" {
        fn VirtualLock(address: *mut c_void, size: usize) -> i32;
        fn GetModuleHandleW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    }

    type WerExclude = unsafe extern "system" fn(address: *const c_void, size: u32) -> i32;

    /// Locks the region in RAM and leaves it out of WER dumps. Returns whether it is locked.
    pub fn protect(base: *mut u8, len: usize) -> bool {
        // SAFETY: `base..base + len` is a live allocation of ours that is never freed.
        let locked = unsafe { VirtualLock(base.cast(), len) } != 0;
        // Looked up at run time: Windows 10 before 1703 has no such function.
        let kernel32: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
        // SAFETY: NUL-terminated names; the function pointer has the documented signature.
        unsafe {
            let module = GetModuleHandleW(kernel32.as_ptr());
            if !module.is_null() {
                let f = GetProcAddress(module, c"WerRegisterExcludedMemoryBlock".as_ptr().cast());
                if !f.is_null() {
                    let exclude: WerExclude = std::mem::transmute::<*mut c_void, WerExclude>(f);
                    let _ = exclude(base.cast_const().cast(), len as u32);
                }
            }
        }
        locked
    }
}

#[cfg(unix)]
mod os {
    use std::ffi::{c_int, c_void};

    extern "C" {
        fn mlock(address: *const c_void, len: usize) -> c_int;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        fn madvise(address: *mut c_void, len: usize, advice: c_int) -> c_int;
    }

    /// `MADV_DONTDUMP` (the same value on every Linux architecture).
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const MADV_DONTDUMP: c_int = 16;

    /// Locks the region in RAM and (Linux) leaves it out of core dumps. Returns whether it is
    /// locked.
    pub fn protect(base: *mut u8, len: usize) -> bool {
        // SAFETY: `base..base + len` is a live, page-aligned allocation of ours, never freed.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        unsafe {
            let _ = madvise(base.cast(), len, MADV_DONTDUMP);
        }
        // SAFETY: as above.
        unsafe { mlock(base.cast_const().cast(), len) == 0 }
    }
}

#[cfg(not(any(windows, unix)))]
mod os {
    /// No page locking here (the browser's WebAssembly): the region is ordinary memory.
    pub fn protect(_base: *mut u8, _len: usize) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_hold_their_bytes_and_clone_into_their_own_slot() {
        let mut key = LockedKey::zeroed();
        assert_eq!(*key, [0u8; KEY_LEN]);
        key.copy_from_slice(&[7u8; KEY_LEN]);
        let copy = key.clone();
        assert_eq!(*copy, [7u8; KEY_LEN]);
        assert_ne!(key.ptr, copy.ptr);
        key[0] = 1;
        assert_eq!(copy[0], 7, "a clone is independent");
        assert_eq!(LockedKey::from_array([9u8; KEY_LEN]).as_ref(), &[9u8; KEY_LEN]);
        assert!(LockedKey::from_slice(&[1u8; 31]).is_none());
        assert!(LockedKey::from_slice(&[1u8; 33]).is_none());
        assert_eq!(*LockedKey::from_slice(&[3u8; 32]).unwrap(), [3u8; KEY_LEN]);
    }

    #[test]
    fn a_dropped_key_is_wiped_and_its_slot_reused() {
        let key = LockedKey::from_array([0xA5; KEY_LEN]);
        assert!(key.in_region(), "the region has room for a test's keys");
        let ptr = key.ptr;
        drop(key);
        // SAFETY: the region is never freed; the slot is merely free again.
        let left = unsafe { *ptr.as_ptr() };
        assert_eq!(left, [0u8; KEY_LEN], "nothing of the key stays behind");
    }

    #[test]
    fn a_full_region_spills_to_the_heap_and_still_works() {
        // Other tests may hold a few slots at the same time; more keys than slots spill anyway.
        let keys: Vec<LockedKey> = (0..SLOTS + 10)
            .map(|i| LockedKey::from_array([(i % 251) as u8; KEY_LEN]))
            .collect();
        let on_heap = keys.iter().filter(|k| !k.in_region()).count();
        assert!(on_heap >= 10, "{on_heap} keys on the heap");
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(**key, [(i % 251) as u8; KEY_LEN]);
        }
        drop(keys);
        assert!(LockedKey::zeroed().in_region(), "slots come back after a drop");
    }

    #[test]
    fn debug_output_never_shows_the_key() {
        let key = LockedKey::from_array([0x41; KEY_LEN]);
        assert_eq!(format!("{key:?}"), "LockedKey(..)");
    }

    #[test]
    fn locking_reports_without_failing() {
        // Locking may be refused (a CI runner's RLIMIT_MEMLOCK); keys work either way.
        let _ = key_memory_locked();
        #[cfg(windows)]
        assert!(key_memory_locked(), "four pages fit any Windows working set");
    }
}
