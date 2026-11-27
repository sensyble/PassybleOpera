//! Where the agent keeps the vault file: on disk ([`FileStore`]) or in memory ([`MemoryStore`]) for
//! a host such as the browser extension, which copies the written files to IndexedDB itself.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Says whether a file was replaced since it was last seen (on disk: its modification time and
/// length). Opaque: only compared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp(StampKind);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StampKind {
    #[cfg_attr(not(feature = "native"), allow(dead_code))]
    Modified(std::time::SystemTime),
    /// Modification time and length: a sync client that puts in another device's copy usually
    /// gives it that device's modification time, and the length makes a clash of two equal
    /// times (a file system with a coarse clock, FAT or a network share) less likely to hide it.
    #[cfg_attr(not(feature = "native"), allow(dead_code))]
    File(std::time::SystemTime, u64),
    Version(u64),
}

impl Stamp {
    /// A file's modification time.
    #[cfg(feature = "native")]
    pub fn modified(time: std::time::SystemTime) -> Stamp {
        Stamp(StampKind::Modified(time))
    }

    /// A file's modification time and length (what [`FileStore`] uses).
    #[cfg(feature = "native")]
    pub fn of_file(time: std::time::SystemTime, len: u64) -> Stamp {
        Stamp(StampKind::File(time, len))
    }

    /// A version number that goes up with every write.
    pub fn version(version: u64) -> Stamp {
        Stamp(StampKind::Version(version))
    }
}

/// What [`VaultStore::replace`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Replaced {
    /// The file now holds the new contents, with this stamp (`None` if it can't be told).
    Written(Option<Stamp>),
    /// Someone else changed the file (its stamp is no longer the expected one), so it was left
    /// as it is: read it, merge it in and try again.
    Changed,
}

/// The agent's access to the vault file and the files next to it. Calls may block.
pub trait VaultStore: Send + Sync {
    /// The file's contents (`NotFound` when there is none).
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;
    /// Whether there is a file.
    fn exists(&self, path: &Path) -> bool;
    /// Replaces the file (or creates it) in one step: a reader sees the old contents or the new,
    /// never half of them.
    fn write(&self, path: &Path, bytes: &[u8]) -> io::Result<()>;
    /// [`VaultStore::write`], but only while the file's stamp is still `expected` (`None`: no
    /// file), checked as late as possible. A copy that a sync client put in place since the last
    /// read then gives `Changed` instead of being overwritten unread. [`FileStore`] checks before
    /// each rename attempt and takes the new stamp before the rename, so a copy that lands right
    /// after it is not mistaken for the agent's own.
    fn replace(&self, path: &Path, bytes: &[u8], expected: Option<Stamp>) -> io::Result<Replaced> {
        if self.stamp(path) != expected {
            return Ok(Replaced::Changed);
        }
        self.write(path, bytes)?;
        Ok(Replaced::Written(self.stamp(path)))
    }
    /// See [`Stamp`]; `None` when there is no file (or it can't be told).
    fn stamp(&self, path: &Path) -> Option<Stamp>;
    /// Deletes the file.
    fn remove(&self, path: &Path) -> io::Result<()>;
    /// The other files in the same folder as `path` (conflict copies of a sync client, the agent's
    /// own `-unsaved-` copies). Empty if the folder can't be listed.
    fn siblings(&self, path: &Path) -> Vec<PathBuf>;
}

/// The vault file on disk.
#[cfg(feature = "native")]
#[derive(Clone, Copy, Debug, Default)]
pub struct FileStore;

#[cfg(feature = "native")]
fn file_stamp(path: &Path) -> Option<Stamp> {
    let meta = std::fs::metadata(path).ok()?;
    Some(Stamp::of_file(meta.modified().ok()?, meta.len()))
}

/// Writes `bytes` to `path` through a temporary file and a rename, so a crash or power loss never
/// leaves half a vault. The temporary file is flushed before the rename and, on Unix, the folder
/// after it. On Windows the rename fails while another process has the target open without
/// delete sharing (a sync client or an antivirus), so it is retried for a moment.
///
/// `expected`: `Some(stamp)` makes this [`VaultStore::replace`]: before every rename attempt the
/// target must still have that stamp (`Some(None)`: still no file), otherwise the temporary file
/// is removed and the result is [`Replaced::Changed`]. `None`: replace whatever is there.
#[cfg(feature = "native")]
fn write_atomic(
    path: &Path,
    bytes: &[u8],
    expected: Option<Option<Stamp>>,
) -> io::Result<Replaced> {
    use std::fs;
    use std::io::Write;
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            fs::create_dir_all(dir)?;
        }
    }
    let tmp = path.with_extension("vault.tmp");
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    // A rename keeps the modification time, so this is the stamp the vault file has once the
    // rename is done (taken after the handle is closed, which may still update it).
    let written = file_stamp(&tmp);
    let mut attempt = 0;
    loop {
        if expected.is_some_and(|expected| file_stamp(path) != expected) {
            let _ = fs::remove_file(&tmp);
            return Ok(Replaced::Changed);
        }
        match fs::rename(&tmp, path) {
            Ok(()) => {
                sync_parent(path);
                return Ok(Replaced::Written(written));
            }
            Err(_) if attempt < RENAME_RETRIES => {
                attempt += 1;
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                return Err(e);
            }
        }
    }
}

/// Flushes the folder that holds `path`, so a rename into it is on the disk (Unix; best effort).
#[cfg(feature = "native")]
fn sync_parent(path: &Path) {
    #[cfg(unix)]
    {
        let dir = match path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir,
            _ => Path::new("."),
        };
        if let Ok(dir) = std::fs::File::open(dir) {
            let _ = dir.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Writes a whole file the way the agent writes the vault (temporary file, flush, rename, folder
/// flush), for code outside the agent that writes a vault file.
#[cfg(feature = "native")]
pub fn write_file_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomic(path, bytes, None).map(|_| ())
}

#[cfg(feature = "native")]
const RENAME_RETRIES: u32 = 10;

/// Set by the app: fetches a missing file that a cloud folder keeps only as a placeholder (iCloud
/// Drive's evicted files on macOS).
#[cfg(feature = "native")]
static MISSING_FILE_FETCHER: std::sync::OnceLock<fn(&Path) -> bool> = std::sync::OnceLock::new();

/// Sets the fetcher [`FileStore`] calls once when a file it reads or checks is missing; it
/// returns whether the file is there now (it may block while downloading). It can be set only
/// once; a later call is [`crate::AlreadySet`].
#[cfg(feature = "native")]
pub fn set_missing_file_fetcher(fetch: fn(&Path) -> bool) -> Result<(), crate::AlreadySet> {
    MISSING_FILE_FETCHER
        .set(fetch)
        .map_err(|_| crate::AlreadySet)
}

#[cfg(feature = "native")]
fn fetched(path: &Path) -> bool {
    MISSING_FILE_FETCHER.get().is_some_and(|fetch| fetch(path))
}

#[cfg(feature = "native")]
impl VaultStore for FileStore {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        match std::fs::read(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound && fetched(path) => std::fs::read(path),
            result => result,
        }
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists() || fetched(path)
    }

    fn write(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        write_atomic(path, bytes, None).map(|_| ())
    }

    fn replace(&self, path: &Path, bytes: &[u8], expected: Option<Stamp>) -> io::Result<Replaced> {
        write_atomic(path, bytes, Some(expected))
    }

    fn stamp(&self, path: &Path) -> Option<Stamp> {
        file_stamp(path)
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }

    fn siblings(&self, path: &Path) -> Vec<PathBuf> {
        let Some(dir) = path.parent() else {
            return Vec::new();
        };
        let dir = if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        };
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|p| p.as_path() != path)
            .collect()
    }
}

/// Files held in memory, for a host that stores them itself, and for tests.
#[derive(Debug, Default)]
pub struct MemoryStore {
    inner: Mutex<MemoryFiles>,
}

#[derive(Debug, Default)]
struct MemoryFiles {
    /// Contents and the version they were written with.
    files: BTreeMap<PathBuf, (Vec<u8>, u64)>,
    /// The last version handed out.
    version: u64,
    /// Files the agent wrote or removed since [`MemoryStore::take_written`] (`None`: removed).
    written: BTreeMap<PathBuf, Option<Vec<u8>>>,
}

impl MemoryFiles {
    fn next_version(&mut self) -> u64 {
        self.version += 1;
        self.version
    }
}

impl MemoryStore {
    pub fn new() -> MemoryStore {
        MemoryStore::default()
    }

    fn files(&self) -> std::sync::MutexGuard<'_, MemoryFiles> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The host puts in a file it read from its own storage (or replaces one). Not reported by
    /// [`MemoryStore::take_written`]. Replacing the open vault's file while it is unlocked is
    /// what a sync client does to a file on disk: the agent merges it in at its next request.
    pub fn put(&self, path: &Path, bytes: Vec<u8>) {
        let mut files = self.files();
        let version = files.next_version();
        files.files.insert(path.to_path_buf(), (bytes, version));
    }

    /// A file's contents, `None` if there is none.
    pub fn get(&self, path: &Path) -> Option<Vec<u8>> {
        self.files().files.get(path).map(|(bytes, _)| bytes.clone())
    }

    /// The host deletes a file (not reported by [`MemoryStore::take_written`]).
    pub fn delete(&self, path: &Path) {
        let mut files = self.files();
        files.files.remove(path);
        files.written.remove(path);
    }

    /// The files the agent wrote (`Some`, their latest contents) or removed (`None`) since the
    /// last call, for the host to store: each file once, in path order.
    pub fn take_written(&self) -> Vec<(PathBuf, Option<Vec<u8>>)> {
        std::mem::take(&mut self.files().written)
            .into_iter()
            .collect()
    }
}

impl VaultStore for MemoryStore {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.get(path)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such file"))
    }

    fn exists(&self, path: &Path) -> bool {
        self.files().files.contains_key(path)
    }

    fn write(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut files = self.files();
        let version = files.next_version();
        files
            .files
            .insert(path.to_path_buf(), (bytes.to_vec(), version));
        files
            .written
            .insert(path.to_path_buf(), Some(bytes.to_vec()));
        Ok(())
    }

    fn stamp(&self, path: &Path) -> Option<Stamp> {
        self.files()
            .files
            .get(path)
            .map(|(_, version)| Stamp::version(*version))
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        let mut files = self.files();
        if files.files.remove(path).is_none() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no such file"));
        }
        files.written.insert(path.to_path_buf(), None);
        Ok(())
    }

    fn siblings(&self, path: &Path) -> Vec<PathBuf> {
        let dir = path.parent();
        self.files()
            .files
            .keys()
            .filter(|p| p.as_path() != path && p.parent() == dir)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_store(store: &dyn VaultStore, dir: &Path) {
        let path = dir.join("pass.vault");
        assert!(!store.exists(&path));
        assert_eq!(
            store.read(&path).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(store.stamp(&path), None);
        store.write(&path, b"one").unwrap();
        assert!(store.exists(&path));
        assert_eq!(store.read(&path).unwrap(), b"one");
        let first = store.stamp(&path).expect("a stamp");
        assert_eq!(
            store.stamp(&path),
            Some(first),
            "unchanged file, same stamp"
        );
        // A coarse file system clock can give two quick writes the same time.
        std::thread::sleep(std::time::Duration::from_millis(20));
        store.write(&path, b"two").unwrap();
        assert_eq!(store.read(&path).unwrap(), b"two");
        assert_ne!(store.stamp(&path), Some(first), "a write changes the stamp");
        let copy = dir.join("pass (1).vault");
        store.write(&copy, b"copy").unwrap();
        assert_eq!(store.siblings(&path), vec![copy.clone()]);
        store.remove(&copy).unwrap();
        assert!(store.siblings(&path).is_empty());
        assert!(store.remove(&copy).is_err());
    }

    #[cfg(feature = "native")]
    #[test]
    fn the_file_store_keeps_the_vault_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        check_store(&FileStore, dir.path());
        let path = dir.path().join("pass.vault");
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        // No temporary file is left behind.
        assert!(!dir.path().join("pass.vault.tmp").exists());
        // A folder that doesn't exist yet is created.
        let nested = dir.path().join("a").join("b.vault");
        FileStore.write(&nested, b"x").unwrap();
        assert_eq!(std::fs::read(&nested).unwrap(), b"x");
    }

    #[test]
    fn the_memory_store_behaves_like_files() {
        let store = MemoryStore::new();
        check_store(&store, Path::new("browser"));
        // Another folder's files are not siblings.
        store
            .write(Path::new("other/pass (1).vault"), b"x")
            .unwrap();
        assert!(store.siblings(Path::new("browser/pass.vault")).is_empty());
    }

    #[test]
    fn the_host_hears_of_what_the_agent_wrote_once() {
        let store = MemoryStore::new();
        let path = Path::new("browser/pass.vault");
        // What the host puts in is not handed back.
        store.put(path, b"from indexeddb".to_vec());
        assert!(store.take_written().is_empty());
        let before = store.stamp(path);
        store.write(path, b"v1").unwrap();
        store.write(path, b"v2").unwrap();
        assert_ne!(store.stamp(path), before);
        assert_eq!(
            store.take_written(),
            vec![(path.to_path_buf(), Some(b"v2".to_vec()))]
        );
        assert!(store.take_written().is_empty());
        // A put replaces the file and changes the stamp, as a sync client's copy would.
        let stamp = store.stamp(path);
        store.put(path, b"replaced".to_vec());
        assert_ne!(store.stamp(path), stamp);
        assert_eq!(store.get(path).unwrap(), b"replaced");
        store.remove(path).unwrap();
        assert_eq!(store.take_written(), vec![(path.to_path_buf(), None)]);
        store.put(path, b"again".to_vec());
        store.delete(path);
        assert!(!store.exists(path));
        assert!(store.take_written().is_empty());
    }
}
