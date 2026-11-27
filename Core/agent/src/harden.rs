//! Process hardening for the app and the native messaging host, called first thing in `main`:
//! no crash dumps and, on Windows and macOS, no memory access or debugger attach from other
//! processes of the same user. Debug builds skip it unless `PASSYBLE_HARDEN=1`; release builds
//! have no off switch, since an environment variable another program could set would undo it.

use std::fmt;
use std::sync::OnceLock;

/// The environment variable that turns hardening on in a debug build (`1`).
pub const HARDEN_ENV: &str = "PASSYBLE_HARDEN";

/// What [`harden_process`] managed to do.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Hardening {
    /// Whether hardening ran at all (always in release builds; see [`wanted`]).
    pub applied: bool,
    /// No crash or core dump of the process will be written.
    pub no_crash_dumps: bool,
    /// Other processes of the same user can't read or write the process' memory or attach a
    /// debugger: the DACL on Windows, `PT_DENY_ATTACH` on macOS. Always `false` on Linux.
    pub no_memory_access: bool,
    /// The vault keys' memory is locked in RAM, out of swap / the pagefile.
    pub key_memory_locked: bool,
}

impl fmt::Display for Hardening {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let yes = |b: bool| if b { "yes" } else { "no" };
        write!(
            f,
            "hardened {}, crash dumps off {}, memory closed to other processes {}, keys locked in RAM {}",
            yes(self.applied),
            yes(self.no_crash_dumps),
            yes(self.no_memory_access),
            yes(self.key_memory_locked)
        )
    }
}

/// Whether to harden: always in a release build, in a debug build only with `PASSYBLE_HARDEN=1`.
pub fn wanted(debug_build: bool, env: Option<&str>) -> bool {
    !debug_build || env.is_some_and(|v| v.trim() == "1")
}

static LAST: OnceLock<Hardening> = OnceLock::new();

/// Hardens this process if [`wanted`] (by the build profile and `PASSYBLE_HARDEN`). Never fails:
/// what the system refuses is left out and shows in the result. Call it once, first thing in
/// `main`, before any secret is in memory and before other threads start.
pub fn harden_process() -> Hardening {
    let env = std::env::var(HARDEN_ENV).ok();
    if wanted(cfg!(debug_assertions), env.as_deref()) {
        harden_process_now()
    } else {
        let result = Hardening {
            key_memory_locked: pass_core::key_memory_locked(),
            ..Hardening::default()
        };
        let _ = LAST.set(result);
        result
    }
}

/// Hardens this process whatever the build profile (tests, and [`harden_process`]).
pub fn harden_process_now() -> Hardening {
    let result = Hardening {
        applied: true,
        no_crash_dumps: os::no_crash_dumps(),
        no_memory_access: os::close_memory(),
        key_memory_locked: pass_core::key_memory_locked(),
    };
    let _ = LAST.set(result);
    result
}

/// The result of the first [`harden_process`] in this process, for the log and diagnostics.
pub fn last() -> Option<Hardening> {
    LAST.get().copied()
}

/// The access the user's own processes keep: `SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION |
/// PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE`.
#[cfg(any(windows, test))]
const USER_ACCESS: u32 = 0x0010_0000 | 0x1000 | 0x0400 | 0x0001;

/// `PROCESS_ALL_ACCESS`.
#[cfg(any(windows, test))]
const SYSTEM_ACCESS: u32 = 0x001F_FFFF;

/// The process' new security descriptor in SDDL: a protected DACL with the user's limited rights,
/// SYSTEM's full rights and `OWNER RIGHTS` limited to reading the descriptor (`RC`), which takes
/// away the owner's implicit `WRITE_DAC`.
#[cfg(any(windows, test))]
fn process_sddl(user_sid: &str) -> String {
    format!("D:P(A;;{USER_ACCESS:#010x};;;{user_sid})(A;;{SYSTEM_ACCESS:#010x};;;SY)(A;;RC;;;OW)")
}

#[cfg(windows)]
mod os {
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, SetKernelObjectSecurity, TokenUser, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Diagnostics::Debug::{
        GetErrorMode, SetErrorMode, SEM_NOGPFAULTERRORBOX,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// Windows Error Reporting is not invoked when the process crashes, so no dump of it is
    /// written (or sent). Child processes inherit the mode.
    pub fn no_crash_dumps() -> bool {
        // SAFETY: plain calls without pointers.
        unsafe {
            SetErrorMode(GetErrorMode() | SEM_NOGPFAULTERRORBOX);
            GetErrorMode() & SEM_NOGPFAULTERRORBOX != 0
        }
    }

    /// The current user's SID as a string (`S-1-5-21-...`).
    fn user_sid() -> Option<String> {
        // SAFETY: the token handle is closed below; the buffer is sized by the first call and
        // 8-byte aligned for TOKEN_USER; the SID string is freed with LocalFree.
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return None;
            }
            let mut needed = 0u32;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
            let mut buf = vec![0u64; (needed as usize).div_ceil(8).max(1)];
            let ok = GetTokenInformation(
                token,
                TokenUser,
                buf.as_mut_ptr().cast(),
                (buf.len() * 8) as u32,
                &mut needed,
            );
            CloseHandle(token);
            if ok == 0 {
                return None;
            }
            let user = &*(buf.as_ptr().cast::<TOKEN_USER>());
            let mut text: *mut u16 = std::ptr::null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut text) == 0 || text.is_null() {
                return None;
            }
            let len = (0..).take_while(|&i| *text.add(i) != 0).count();
            let sid = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
            LocalFree(text.cast());
            Some(sid)
        }
    }

    /// Replaces the process' DACL (`super::process_sddl`). The query rights stay for the IPC peer
    /// check, the installer's "is Passyble running" check and Task Manager; terminate stays so
    /// they can still close it.
    pub fn close_memory() -> bool {
        let Some(sid) = user_sid() else {
            return false;
        };
        let sddl: Vec<u16> = super::process_sddl(&sid)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: NUL-terminated SDDL; the descriptor is freed with LocalFree; the pseudo handle
        // of the current process needs no closing.
        unsafe {
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            ) == 0
            {
                return false;
            }
            let ok = SetKernelObjectSecurity(
                GetCurrentProcess(),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                sd,
            ) != 0;
            LocalFree(sd);
            ok
        }
    }
}

#[cfg(target_os = "macos")]
mod os {
    /// `RLIMIT_CORE` 0, soft and hard (children inherit it).
    pub fn no_crash_dumps() -> bool {
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: a valid rlimit.
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) == 0 }
    }

    /// `ptrace(PT_DENY_ATTACH)`: no debugger can attach from now on (one already attached makes the
    /// process exit, which is why debug builds skip this).
    pub fn close_memory() -> bool {
        // SAFETY: PT_DENY_ATTACH takes no address or data.
        unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) == 0 }
    }
}

#[cfg(target_os = "linux")]
mod os {
    /// `RLIMIT_CORE` 0, soft and hard (children inherit it).
    pub fn no_crash_dumps() -> bool {
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: a valid rlimit.
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) == 0 }
    }

    /// Not on Linux: `PR_SET_DUMPABLE` 0 would hide `/proc/<pid>/exe`, which the IPC peer check
    /// reads in both directions. Against ptrace from other processes this relies on Yama.
    pub fn close_memory() -> bool {
        false
    }
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
mod os {
    pub fn no_crash_dumps() -> bool {
        false
    }

    pub fn close_memory() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_builds_always_harden_debug_builds_only_on_request() {
        assert!(wanted(false, None));
        assert!(wanted(false, Some("0")), "release can't be talked out of it");
        assert!(wanted(false, Some("")));
        assert!(!wanted(true, None));
        assert!(!wanted(true, Some("0")));
        assert!(!wanted(true, Some("yes")));
        assert!(wanted(true, Some("1")));
        assert!(wanted(true, Some(" 1 ")));
    }

    #[test]
    fn the_user_keeps_only_wait_query_and_terminate() {
        // The rights that let another process read, write or take over this one.
        const PROCESS_VM_OPERATION: u32 = 0x0008;
        const PROCESS_VM_READ: u32 = 0x0010;
        const PROCESS_VM_WRITE: u32 = 0x0020;
        const PROCESS_DUP_HANDLE: u32 = 0x0040;
        const PROCESS_CREATE_THREAD: u32 = 0x0002;
        const PROCESS_CREATE_PROCESS: u32 = 0x0080;
        const PROCESS_SET_INFORMATION: u32 = 0x0200;
        const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
        const WRITE_DAC: u32 = 0x0004_0000;
        const WRITE_OWNER: u32 = 0x0008_0000;
        for right in [
            PROCESS_VM_OPERATION,
            PROCESS_VM_READ,
            PROCESS_VM_WRITE,
            PROCESS_DUP_HANDLE,
            PROCESS_CREATE_THREAD,
            PROCESS_CREATE_PROCESS,
            PROCESS_SET_INFORMATION,
            PROCESS_SUSPEND_RESUME,
            WRITE_DAC,
            WRITE_OWNER,
        ] {
            assert_eq!(USER_ACCESS & right, 0, "{right:#x}");
        }
        assert_eq!(USER_ACCESS, 0x0010_1401);
        assert_eq!(
            process_sddl("S-1-5-21-1-2-3-1001"),
            "D:P(A;;0x00101401;;;S-1-5-21-1-2-3-1001)(A;;0x001fffff;;;SY)(A;;RC;;;OW)"
        );
    }

    #[test]
    fn the_summary_names_each_measure() {
        let text = Hardening {
            applied: true,
            no_crash_dumps: true,
            no_memory_access: false,
            key_memory_locked: true,
        }
        .to_string();
        assert_eq!(
            text,
            "hardened yes, crash dumps off yes, memory closed to other processes no, keys locked in RAM yes"
        );
    }
}
