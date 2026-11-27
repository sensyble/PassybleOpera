//! Process hardening (`pass_agent::harden`) applied to a real process: this test binary starts a
//! copy of itself that hardens itself, then tries to open it the way another program of the same
//! user would.

#![cfg(feature = "native")]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

/// Set in the child copy: harden, say so, and wait to be ended.
const CHILD_ENV: &str = "PASS_HARDEN_TEST_CHILD";

/// The child's side. In the parent run (no `CHILD_ENV`) it does nothing.
#[test]
fn hardened_child() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let result = pass_agent::harden::harden_process_now();
    println!("ready {}", result.no_memory_access);
    std::thread::sleep(std::time::Duration::from_secs(60));
}

/// Starts the child and waits for its `ready` line; returns it and whether it closed its memory.
fn start_child() -> (std::process::Child, bool) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "hardened_child", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let out = child.stdout.take().unwrap();
    let mut closed = None;
    for line in BufReader::new(out).lines() {
        // libtest may print `test hardened_child ... ` on the same line first.
        let line = line.unwrap();
        if let Some((_, rest)) = line.split_once("ready ") {
            closed = Some(rest.trim() == "true");
            break;
        }
    }
    (child, closed.expect("the child hardened itself"))
}

#[cfg(windows)]
#[test]
fn other_processes_of_the_user_cannot_read_or_write_its_memory() {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ACCESS_DENIED};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, TerminateProcess, PROCESS_CREATE_THREAD,
        PROCESS_DUP_HANDLE, PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
        PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    };

    let (mut child, closed) = start_child();
    assert!(closed, "the DACL was set");
    let pid = child.id();
    // SAFETY: OpenProcess / CloseHandle / TerminateProcess on a child we own; every handle that
    // opens is closed.
    unsafe {
        for (name, access) in [
            ("PROCESS_VM_READ", PROCESS_VM_READ),
            ("PROCESS_VM_WRITE", PROCESS_VM_WRITE),
            ("PROCESS_VM_OPERATION", PROCESS_VM_OPERATION),
            ("PROCESS_CREATE_THREAD", PROCESS_CREATE_THREAD),
            ("PROCESS_DUP_HANDLE", PROCESS_DUP_HANDLE),
        ] {
            let handle = OpenProcess(access, 0, pid);
            let error = GetLastError();
            if !handle.is_null() {
                CloseHandle(handle);
                // An elevated test run with SeDebugPrivilege enabled passes every DACL.
                panic!("{name} was granted (is this test running as an administrator?)");
            }
            assert_eq!(error, ERROR_ACCESS_DENIED, "{name}");
        }
        // What the IPC peer check, the installer and Task Manager need still works.
        for (name, access) in [
            ("PROCESS_QUERY_LIMITED_INFORMATION", PROCESS_QUERY_LIMITED_INFORMATION),
            ("PROCESS_QUERY_INFORMATION", PROCESS_QUERY_INFORMATION),
            ("PROCESS_SYNCHRONIZE", PROCESS_SYNCHRONIZE),
        ] {
            let handle = OpenProcess(access, 0, pid);
            assert!(!handle.is_null(), "{name}");
            CloseHandle(handle);
        }
        // The IPC peer check reads the executable's path this way (ipc.rs, `process_image`).
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let read = QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
        CloseHandle(handle);
        assert_ne!(read, 0, "the process image can still be read");
        let image = String::from_utf16_lossy(&buf[..len as usize]);
        let me = std::env::current_exe().unwrap();
        assert!(
            image.eq_ignore_ascii_case(&me.to_string_lossy()),
            "{image} is {}",
            me.display()
        );
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        assert!(!handle.is_null(), "PROCESS_TERMINATE");
        assert_ne!(TerminateProcess(handle, 0), 0);
        CloseHandle(handle);
    }
    let _ = child.wait();
}

#[cfg(target_os = "linux")]
#[test]
fn linux_keeps_the_process_path_readable() {
    // PR_SET_DUMPABLE is left alone so the IPC peer check can still read /proc/<pid>/exe.
    let (mut child, closed) = start_child();
    assert!(!closed);
    let exe = std::fs::read_link(format!("/proc/{}/exe", child.id()));
    let _ = child.kill();
    let _ = child.wait();
    assert!(exe.is_ok(), "{exe:?}");
}
