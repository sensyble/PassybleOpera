//! Local IPC with the native-messaging host: a named pipe on Windows, a 0600 unix socket
//! elsewhere, one JSON message per line. Any process of the same user can connect, so
//! [`Server::start_restricted`] checks each peer's executable against an allow-list, and clients
//! check the server with [`server_is_allowed`] since another process could create the pipe first.

use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

use interprocess::local_socket::traits::{ListenerExt as _, Stream as _};
use interprocess::local_socket::{ListenerOptions, Name, SendHalf, Stream};
use serde_json::Value;

use crate::Agent;

fn user() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "default".into())
}

#[cfg(unix)]
pub fn socket_path() -> std::path::PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(dir) => std::path::PathBuf::from(dir).join("pass-agent.sock"),
        None => std::env::temp_dir().join(format!("pass-agent-{}.sock", user())),
    }
}

pub fn socket_name() -> io::Result<Name<'static>> {
    #[cfg(windows)]
    {
        use interprocess::local_socket::{GenericNamespaced, ToNsName};
        format!("pass-agent-{}", user())
            .to_ns_name::<GenericNamespaced>()
            .map(|n| n.into_owned())
    }
    #[cfg(unix)]
    {
        use interprocess::local_socket::{GenericFilePath, ToFsName};
        socket_path()
            .to_fs_name::<GenericFilePath>()
            .map(|n| n.into_owned())
    }
}

/// Connects to a running agent.
pub fn connect() -> io::Result<Stream> {
    Stream::connect(socket_name()?)
}

/// The process ID of the agent at the other end of a stream from [`connect`] (Windows only).
#[cfg(windows)]
pub fn server_process_id(stream: &Stream) -> Option<u32> {
    win::pipe_process_id(stream, win::PipeEnd::Server)
}

/// Whether the agent at the other end of a stream from [`connect`] runs one of the executables
/// in `allowed` (Windows: `GetNamedPipeServerProcessId` + `QueryFullProcessImageNameW`). A pipe
/// created by any other program, or by another user (whose process this user can't open), is
/// refused. Always `true` on other platforms.
#[cfg(windows)]
pub fn server_is_allowed(stream: &Stream, allowed: &[PathBuf]) -> bool {
    let allowed: Vec<PathBuf> = allowed.iter().map(|p| canonical(p)).collect();
    let pid = win::pipe_process_id(stream, win::PipeEnd::Server);
    let exe = pid.and_then(win::process_image);
    let ok = exe
        .as_deref()
        .is_some_and(|e| is_allowed_client(&canonical(e), &allowed));
    if !ok {
        eprintln!(
            "pass: the agent pipe is held by pid {pid:?} ({exe:?}), not by Passyble; refusing it"
        );
    }
    ok
}

/// macOS: the same check through `LOCAL_PEERPID` and `proc_pidpath`.
#[cfg(target_os = "macos")]
pub fn server_is_allowed(stream: &Stream, allowed: &[PathBuf]) -> bool {
    let allowed: Vec<PathBuf> = allowed.iter().map(|p| canonical(p)).collect();
    let pid = mac::peer_pid(stream);
    let exe = pid.and_then(mac::process_path).map(|e| canonical(&e));
    let ok = exe
        .as_deref()
        .is_some_and(|e| is_allowed_client(e, &allowed));
    if !ok {
        eprintln!(
            "pass: the agent socket is held by pid {pid:?} ({exe:?}), not by Passyble; refusing it"
        );
        if let Some(hint) = translocation_hint(exe.as_deref(), &allowed) {
            eprintln!("pass: {hint}");
        }
    }
    ok
}

/// Linux: the same check through `SO_PEERCRED` and `/proc/<pid>/exe`.
#[cfg(target_os = "linux")]
pub fn server_is_allowed(stream: &Stream, allowed: &[PathBuf]) -> bool {
    let allowed: Vec<PathBuf> = allowed.iter().map(|p| canonical(p)).collect();
    let pid = linux::peer_pid(stream);
    let exe = pid.and_then(linux::process_path);
    let ok = linux_peer_allowed(exe.as_deref(), &allowed, "pass");
    if !ok {
        eprintln!(
            "pass: the agent socket is held by pid {pid:?} ({exe:?}), not by Passyble; refusing it"
        );
    }
    ok
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub fn server_is_allowed(_stream: &Stream, _allowed: &[PathBuf]) -> bool {
    true
}

/// The suffix the kernel adds to `/proc/<pid>/exe` when the executable was deleted or replaced
/// (a package update while Passyble runs).
#[cfg(any(target_os = "linux", test))]
const REPLACED_SUFFIX: &str = " (deleted)";

/// Linux: whether the peer executable `exe` (from `/proc/<pid>/exe`) is exactly one of
/// `allowed`, compared byte for byte. A replaced binary (`" (deleted)"`) is refused. `who` names
/// the side in the log.
#[cfg(any(target_os = "linux", test))]
fn linux_peer_allowed(exe: Option<&Path>, allowed: &[PathBuf], who: &str) -> bool {
    let Some(exe) = exe else {
        return false;
    };
    if exe.as_os_str().to_string_lossy().ends_with(REPLACED_SUFFIX) {
        eprintln!(
            "{who}: the other end runs a replaced executable ({exe:?}); Passyble was updated, restart it"
        );
        return false;
    }
    // An absolute unix path (`Path::is_absolute` would mean a drive letter in the Windows tests).
    exe.as_os_str().to_string_lossy().starts_with('/')
        && allowed.iter().any(|a| a.as_os_str() == exe.as_os_str())
}

/// A log hint when the peer or the app runs from a Gatekeeper App Translocation copy, whose path
/// never matches the allowed one.
#[cfg(any(target_os = "macos", test))]
fn translocation_hint(peer: Option<&Path>, allowed: &[PathBuf]) -> Option<&'static str> {
    let translocated = |p: &Path| p.components().any(|c| c.as_os_str() == "AppTranslocation");
    (peer.is_some_and(translocated) || allowed.iter().any(|a| translocated(a))).then_some(
        "Passyble runs from a translocated copy; move Passyble to the Applications folder and open it again",
    )
}

/// `path` with symlinks and 8.3 names resolved, or as given if it doesn't exist (yet).
fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Windows paths compare case-insensitively, and `canonicalize` adds a `\\?\` prefix that
/// `QueryFullProcessImageNameW` doesn't. (macOS volumes are usually case-insensitive too.)
#[cfg(any(windows, target_os = "macos", test))]
fn path_key(path: &Path) -> String {
    let path = path.to_string_lossy();
    let path = path.strip_prefix(r"\\?\").unwrap_or(&path);
    path.replace('/', "\\").to_lowercase()
}

/// Whether the executable `exe` is one of `allowed`.
#[cfg(any(windows, target_os = "macos", test))]
fn is_allowed_client(exe: &Path, allowed: &[PathBuf]) -> bool {
    let exe = path_key(exe);
    !exe.is_empty() && allowed.iter().any(|a| path_key(a) == exe)
}

type Writer = Arc<Mutex<SendHalf>>;

thread_local! {
    /// The process at the other end of the IPC connection whose request this thread answers.
    static REQUEST_CLIENT: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

/// The process ID of the IPC client whose request the current thread is answering, so a
/// [`crate::Ui`] can tell browser requests from the app's own calls. `None` outside an IPC
/// request thread.
pub fn request_client_pid() -> Option<u32> {
    REQUEST_CLIENT.with(|c| c.get())
}

/// What a connection may ask for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    /// The browser protocol ([`Agent::handle_line`]): the native host, the app itself.
    Browser,
    /// The connector for AI tools: `ai.*` only ([`Agent::handle_ai_line`]), no pushed events.
    Ai,
    /// [`Server::start`] (tests): `ai.*` methods go to [`Agent::handle_ai_line`], the rest to
    /// [`Agent::handle_line`].
    Any,
}

/// The IPC server. Keeps track of connected hosts so events can be pushed to them.
#[derive(Default)]
pub struct Server {
    clients: Mutex<Vec<Writer>>,
    /// Executables allowed to connect, with what they may ask for (checked on Windows, macOS and
    /// Linux); `None` allows any process ([`Role::Any`]).
    #[cfg_attr(
        not(any(windows, target_os = "macos", target_os = "linux")),
        allow(dead_code)
    )]
    allowed_clients: Option<Vec<(PathBuf, Role)>>,
}

/// Whether a request line asks for an `ai.*` method (for [`Role::Any`]).
fn is_ai_request(line: &str) -> bool {
    serde_json::from_str::<Value>(line)
        .ok()
        .and_then(|v| v.get("method").and_then(Value::as_str).map(str::to_string))
        .is_some_and(|m| m.starts_with("ai."))
}

fn write_line(writer: &Writer, line: &str) -> io::Result<()> {
    let mut w = writer.lock().unwrap_or_else(|p| p.into_inner());
    w.write_all(line.as_bytes())?;
    w.write_all(b"\n")?;
    w.flush()
}

impl Server {
    /// Starts listening on a background thread; each connection gets its own thread. Any
    /// process that can open the socket may connect (tests, other platforms).
    pub fn start(agent: Arc<Agent>) -> io::Result<Arc<Server>> {
        Self::listen(agent, None)
    }

    /// Like [`Server::start`], but only processes running one of `allowed_clients` may connect.
    /// Others are disconnected and logged.
    pub fn start_restricted(
        agent: Arc<Agent>,
        allowed_clients: Vec<PathBuf>,
    ) -> io::Result<Arc<Server>> {
        Self::start_restricted_with_ai(agent, allowed_clients, Vec::new())
    }

    /// [`Server::start_restricted`] that also accepts the connector for AI tools from
    /// `ai_clients` (e.g. `passyble-mcp.exe` beside `Pass.exe`). Those connections may only send
    /// `ai.*` requests, and the others may not send any.
    pub fn start_restricted_with_ai(
        agent: Arc<Agent>,
        allowed_clients: Vec<PathBuf>,
        ai_clients: Vec<PathBuf>,
    ) -> io::Result<Arc<Server>> {
        let allowed = allowed_clients
            .iter()
            .map(|p| (canonical(p.as_path()), Role::Browser))
            .chain(
                ai_clients
                    .iter()
                    .map(|p| (canonical(p.as_path()), Role::Ai)),
            )
            .collect();
        Self::listen(agent, Some(allowed))
    }

    fn listen(
        agent: Arc<Agent>,
        allowed_clients: Option<Vec<(PathBuf, Role)>>,
    ) -> io::Result<Arc<Server>> {
        #[cfg(unix)]
        {
            let path = socket_path();
            // A socket file left over from a crash blocks binding; only remove it if nobody answers.
            if path.exists() && connect().is_err() {
                let _ = std::fs::remove_file(&path);
            }
        }
        let listener = ListenerOptions::new().name(socket_name()?).create_sync()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(socket_path(), std::fs::Permissions::from_mode(0o600))?;
        }
        let server = Arc::new(Server {
            clients: Mutex::default(),
            allowed_clients,
        });
        let accept_server = server.clone();
        thread::Builder::new()
            .name("pass-ipc-accept".into())
            .spawn(move || {
                for conn in listener.incoming().filter_map(Result::ok) {
                    let agent = agent.clone();
                    let server = accept_server.clone();
                    let _ = thread::Builder::new()
                        .name("pass-ipc-conn".into())
                        .spawn(move || server.serve(agent, conn));
                }
            })?;
        Ok(server)
    }

    /// The allowed executables of `role`.
    #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
    fn allowed_of(allowed: &[(PathBuf, Role)], role: Role) -> Vec<PathBuf> {
        allowed
            .iter()
            .filter(|(_, r)| *r == role)
            .map(|(p, _)| p.clone())
            .collect()
    }

    /// What the process at the other end of `conn` may ask for; `None`: it may not use the agent.
    #[cfg(windows)]
    fn client_role(&self, conn: &Stream) -> Option<Role> {
        let Some(allowed) = &self.allowed_clients else {
            return Some(Role::Any);
        };
        let pid = win::pipe_process_id(conn, win::PipeEnd::Client);
        let exe = pid.and_then(win::process_image);
        for role in [Role::Browser, Role::Ai] {
            let paths = Self::allowed_of(allowed, role);
            if exe
                .as_deref()
                .is_some_and(|e| is_allowed_client(&canonical(e), &paths))
            {
                return Some(role);
            }
        }
        eprintln!("pass-agent: rejected IPC connection from pid {pid:?} ({exe:?})");
        None
    }

    #[cfg(target_os = "macos")]
    fn client_role(&self, conn: &Stream) -> Option<Role> {
        let Some(allowed) = &self.allowed_clients else {
            return Some(Role::Any);
        };
        let pid = mac::peer_pid(conn);
        let exe = pid.and_then(mac::process_path).map(|e| canonical(&e));
        for role in [Role::Browser, Role::Ai] {
            let paths = Self::allowed_of(allowed, role);
            if exe.as_deref().is_some_and(|e| is_allowed_client(e, &paths)) {
                return Some(role);
            }
        }
        eprintln!("pass-agent: rejected IPC connection from pid {pid:?} ({exe:?})");
        let all: Vec<PathBuf> = allowed.iter().map(|(p, _)| p.clone()).collect();
        if let Some(hint) = translocation_hint(exe.as_deref(), &all) {
            eprintln!("pass-agent: {hint}");
        }
        None
    }

    #[cfg(target_os = "linux")]
    fn client_role(&self, conn: &Stream) -> Option<Role> {
        let Some(allowed) = &self.allowed_clients else {
            return Some(Role::Any);
        };
        let pid = linux::peer_pid(conn);
        let exe = pid.and_then(linux::process_path);
        for role in [Role::Browser, Role::Ai] {
            let paths = Self::allowed_of(allowed, role);
            if linux_peer_allowed(exe.as_deref(), &paths, "pass-agent") {
                return Some(role);
            }
        }
        eprintln!("pass-agent: rejected IPC connection from pid {pid:?} ({exe:?})");
        None
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    fn client_role(&self, _conn: &Stream) -> Option<Role> {
        Some(Role::Any)
    }

    fn serve(&self, agent: Arc<Agent>, conn: Stream) {
        let Some(role) = self.client_role(&conn) else {
            return;
        };
        if role == Role::Ai {
            return Self::serve_ai(agent, conn);
        }
        // Asked once per connection: every request on it comes from the same process.
        #[cfg(windows)]
        let client_pid = win::pipe_process_id(&conn, win::PipeEnd::Client);
        #[cfg(target_os = "macos")]
        let client_pid = mac::peer_pid(&conn);
        #[cfg(target_os = "linux")]
        let client_pid = linux::peer_pid(&conn);
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        let client_pid: Option<u32> = None;
        let (recv, send) = conn.split();
        let writer: Writer = Arc::new(Mutex::new(send));
        self.clients
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(writer.clone());
        for line in BufReader::new(recv).lines() {
            let Ok(line) = line else { break };
            if line.trim().is_empty() {
                continue;
            }
            // Requests may block on the user (unlock, passkey consent): answer each on its own
            // thread so a pending dialog doesn't hold up other requests from the same browser.
            let agent = agent.clone();
            let writer = writer.clone();
            thread::spawn(move || {
                if role == Role::Any && is_ai_request(&line) {
                    let mut response = agent.handle_ai_line(&line);
                    let _ = write_line(&writer, &response);
                    zeroize::Zeroize::zeroize(&mut response);
                    return;
                }
                REQUEST_CLIENT.with(|c| c.set(client_pid));
                let response = agent.handle_line(&line);
                let _ = write_line(&writer, &response);
            });
        }
        self.clients
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|w| !Arc::ptr_eq(w, &writer));
    }

    /// A connection of the connector for AI tools: `ai.*` requests only, each on its own thread
    /// (an approval prompt may wait for minutes), no pushed events, and no
    /// [`request_client_pid`] (its requests are not the browser's). Responses can carry secrets
    /// (`ai.run`, `ai.reveal`): cleared from memory once written.
    fn serve_ai(agent: Arc<Agent>, conn: Stream) {
        let (recv, send) = conn.split();
        let writer: Writer = Arc::new(Mutex::new(send));
        for line in BufReader::new(recv).lines() {
            let Ok(line) = line else { break };
            if line.trim().is_empty() {
                continue;
            }
            let agent = agent.clone();
            let writer = writer.clone();
            thread::spawn(move || {
                let mut response = agent.handle_ai_line(&line);
                let _ = write_line(&writer, &response);
                zeroize::Zeroize::zeroize(&mut response);
            });
        }
    }

    /// Pushes an event (`{"event": name, "data": data}`) to every connected host.
    pub fn notify(&self, event: &str, data: Value) {
        let line = serde_json::json!({ "event": event, "data": data }).to_string();
        self.clients
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|w| write_line(w, &line).is_ok());
    }
}

/// The peer of a unix socket on macOS. interprocess's `PeerCreds` has no PID on Darwin, so this
/// asks the socket itself.
#[cfg(target_os = "macos")]
mod mac {
    use std::ffi::c_void;
    use std::os::fd::{AsFd, AsRawFd};
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;

    use interprocess::local_socket::Stream;

    /// The process at the other end of `stream` (`getsockopt(SOL_LOCAL, LOCAL_PEERPID)`). Like
    /// the Windows check, it can race with that process exiting and its PID being reused.
    pub fn peer_pid(stream: &Stream) -> Option<u32> {
        let Stream::UdSocket(socket) = stream;
        let fd = socket.as_fd().as_raw_fd();
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        // SAFETY: `fd` is the stream's open socket; `pid` and `len` are valid for writes and
        // `len` holds the size of `pid`.
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                (&mut pid as *mut libc::pid_t).cast::<c_void>(),
                &mut len,
            )
        };
        (result == 0 && pid > 0).then_some(pid as u32)
    }

    /// The executable of process `pid` (`proc_pidpath`).
    pub fn process_path(pid: u32) -> Option<PathBuf> {
        let pid = i32::try_from(pid).ok()?;
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: `buf` has PROC_PIDPATHINFO_MAXSIZE writable bytes.
        let len =
            unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast::<c_void>(), buf.len() as u32) };
        if len <= 0 {
            return None;
        }
        buf.truncate(len as usize);
        Some(PathBuf::from(std::ffi::OsString::from_vec(buf)))
    }
}

/// The peer of a unix socket on Linux.
#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::c_void;
    use std::os::fd::{AsFd, AsRawFd};
    use std::path::PathBuf;

    use interprocess::local_socket::Stream;

    /// The process at the other end of `stream` (`getsockopt(SOL_SOCKET, SO_PEERCRED)`: the
    /// credentials the peer had when it connected). Like the Windows check, it can race with that
    /// process exiting and its PID being reused.
    pub fn peer_pid(stream: &Stream) -> Option<u32> {
        let Stream::UdSocket(socket) = stream;
        let fd = socket.as_fd().as_raw_fd();
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `fd` is the stream's open socket; `cred` and `len` are valid for writes and
        // `len` holds the size of `cred`.
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast::<c_void>(),
                &mut len,
            )
        };
        (result == 0 && cred.pid > 0).then_some(cred.pid as u32)
    }

    /// The executable of process `pid` (`/proc/<pid>/exe`). Another user's process can't be read,
    /// so it has none and is refused.
    pub fn process_path(pid: u32) -> Option<PathBuf> {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }
}

#[cfg(windows)]
mod win {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::{AsHandle, AsRawHandle};
    use std::path::PathBuf;

    use interprocess::local_socket::Stream;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Pipes::{
        GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    pub enum PipeEnd {
        Client,
        Server,
    }

    /// The process at one end of a named-pipe stream.
    pub fn pipe_process_id(stream: &Stream, end: PipeEnd) -> Option<u32> {
        let handle: HANDLE = match stream {
            Stream::NamedPipe(pipe) => pipe.as_handle().as_raw_handle(),
            #[allow(unreachable_patterns)]
            _ => return None,
        };
        let mut pid = 0u32;
        // SAFETY: `handle` is a live pipe handle owned by `stream`, which outlives the call.
        let ok = unsafe {
            match end {
                PipeEnd::Client => GetNamedPipeClientProcessId(handle, &mut pid),
                PipeEnd::Server => GetNamedPipeServerProcessId(handle, &mut pid),
            }
        };
        (ok != 0 && pid != 0).then_some(pid)
    }

    /// Full path of a process's executable.
    pub fn process_image(pid: u32) -> Option<PathBuf> {
        // SAFETY: plain Win32 calls; the process handle is closed before returning.
        unsafe {
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if process.is_null() {
                return None;
            }
            let mut buf = vec![0u16; 32 * 1024];
            let mut size = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(
                process,
                PROCESS_NAME_WIN32,
                buf.as_mut_ptr(),
                &mut size,
            );
            CloseHandle(process);
            if ok == 0 {
                return None;
            }
            Some(PathBuf::from(OsString::from_wide(&buf[..size as usize])))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_client_outside_a_request() {
        assert_eq!(request_client_pid(), None);
    }

    #[test]
    fn allowed_client_paths() {
        let allowed = [PathBuf::from(r"C:\Program Files\Pass\pass-native-host.exe")];
        let ok = |p: &str| is_allowed_client(Path::new(p), &allowed);
        assert!(ok(r"C:\Program Files\Pass\pass-native-host.exe"));
        assert!(ok(r"c:\program files\pass\PASS-NATIVE-HOST.EXE"));
        assert!(ok(r"\\?\C:\Program Files\Pass\pass-native-host.exe"));
        assert!(!ok(r"C:\Program Files\Pass\pass-native-host.exe.bak"));
        assert!(!ok(r"C:\Users\me\Downloads\pass-native-host.exe"));
        assert!(!ok(r"C:\Program Files\Pass\Pass.exe"));
        assert!(!ok(""));
        assert!(!is_allowed_client(
            Path::new(r"C:\Program Files\Pass\pass-native-host.exe"),
            &[]
        ));
    }

    #[test]
    fn mac_client_paths_and_translocation() {
        let allowed = [PathBuf::from(
            "/Applications/Passyble.app/Contents/MacOS/pass-native-host",
        )];
        let ok = |p: &str| is_allowed_client(Path::new(p), &allowed);
        assert!(ok(
            "/Applications/Passyble.app/Contents/MacOS/pass-native-host"
        ));
        assert!(!ok(
            "/Users/me/Downloads/Passyble.app/Contents/MacOS/pass-native-host"
        ));

        let moved = Path::new(
            "/private/var/folders/ab/xyz/T/AppTranslocation/0A1B/d/Passyble.app/Contents/MacOS/Pass",
        );
        assert!(translocation_hint(Some(moved), &allowed).is_some());
        let translocated_allowed = [moved.with_file_name("pass-native-host")];
        assert!(translocation_hint(None, &translocated_allowed).is_some());
        assert!(
            translocation_hint(Some(Path::new("/Users/me/Downloads/other")), &allowed).is_none()
        );
    }

    #[test]
    fn linux_client_paths() {
        let allowed = [
            PathBuf::from("/usr/bin/pass-native-host"),
            PathBuf::from("/tmp/.mount_PassAb12/usr/bin/Pass"),
        ];
        let ok = |p: &str| linux_peer_allowed(Some(Path::new(p)), &allowed, "test");
        assert!(ok("/usr/bin/pass-native-host"));
        assert!(ok("/tmp/.mount_PassAb12/usr/bin/Pass"));
        // Case-sensitive, exact: no prefix, no other mount, no relative path.
        assert!(!ok("/usr/bin/Pass-Native-Host"));
        assert!(!ok("/usr/bin/pass-native-host.bak"));
        assert!(!ok("/tmp/.mount_PassZz99/usr/bin/Pass"));
        assert!(!ok("/tmp/.mount_PassAb12"));
        assert!(!ok("usr/bin/pass-native-host"));
        assert!(!ok(""));
        // A binary replaced by an update is refused (restart Passyble).
        assert!(!ok("/usr/bin/pass-native-host (deleted)"));
        assert!(!linux_peer_allowed(None, &allowed, "test"));
        assert!(!linux_peer_allowed(
            Some(Path::new("/usr/bin/pass-native-host")),
            &[],
            "test"
        ));
    }
}
