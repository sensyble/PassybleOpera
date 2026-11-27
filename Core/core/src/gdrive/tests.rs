//! Google Drive sync against an in-process fake of the Drive v3 endpoints, counting requests.

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use super::*;
use crate::{
    plain_http_refused, AliasConfig, AliasService, AndroidApp, CardData, CustomField,
    EmailGeneratorSettings, FieldKind, IdentityData, Item, ItemKind, KdfParams, Passkey,
};

/// The canary scanner and canary vaults, shared with `tests/no_plaintext.rs`.
#[path = "../../tests/common/leak.rs"]
mod leak;

const TOKEN: &str = "ya29.good";

#[derive(Clone, Default)]
struct FakeFile {
    name: String,
    content: Vec<u8>,
    version: u64,
    created: String,
    props: HashMap<String, String>,
    /// Every revision, oldest first; the last one is the head (holds `content`).
    revisions: Vec<FakeRevision>,
}

#[derive(Clone, Debug, Default)]
struct FakeRevision {
    id: String,
    content: Vec<u8>,
    keep_forever: bool,
}

#[derive(Default)]
struct Drive {
    files: BTreeMap<String, FakeFile>,
    next_id: u64,
    /// How much `version` grows per change (Drive only promises "monotonically increasing").
    step: u64,
    /// (method, path without query) of every request.
    log: Vec<(String, String)>,
    /// Every request as it arrived (URL, then the request line, headers and body), for the
    /// canary test.
    raw: Vec<(String, Vec<u8>)>,
    /// Answer 401 (expired token) / 403 insufficientPermissions to everything.
    expired: bool,
    scope_denied: bool,
    /// Another device's upload that lands right after the next download is served.
    after_download: Option<Vec<u8>>,
    /// Another device's upload that lands just before the next content upload (overwritten).
    before_upload: Option<Vec<u8>>,
    sessions: HashMap<String, (Option<String>, (serde_json::Value, bool))>,
    next_revision: u64,
    /// Whether the other devices' writes above pin their revision, as this version's uploads do
    /// (`keepRevisionForever`). Off: an older client.
    others_pin: bool,
    /// Refuse to pin (as Drive does past 200 pinned revisions): 403 to `keepRevisionForever`.
    refuse_pins: bool,
    /// `createdTime` of files created from now on (default: a fixed date long ago).
    created: Option<String>,
    /// Files `files.list` doesn't show yet (its index lags behind a create).
    hidden: Vec<String>,
    /// Answer this many `revisions.list` requests with 500.
    fail_revisions: u32,
    /// Another device's upload that lands just before the next metadata change (a rename).
    before_rename: Option<Vec<u8>>,
    /// Revisions Drive won't delete (400), besides the head, which it never deletes here.
    undeletable: Vec<String>,
    /// After this many more revision deletes, answer every one with 429 (too many requests).
    deletes_before_busy: Option<u32>,
}

impl Drive {
    fn take_log(&mut self) -> Vec<(String, String)> {
        std::mem::take(&mut self.log)
    }

    fn new_revision(&mut self, content: &[u8], keep_forever: bool) -> FakeRevision {
        self.next_revision += 1;
        FakeRevision {
            id: format!("rev{}", self.next_revision),
            content: content.to_vec(),
            keep_forever,
        }
    }

    /// Another device's upload (pinned if `others_pin`).
    fn write(&mut self, id: &str, content: Vec<u8>) {
        let pin = self.others_pin;
        self.write_pinned(id, content, pin);
    }

    fn write_pinned(&mut self, id: &str, content: Vec<u8>, pin: bool) {
        let step = self.step.max(1);
        let revision = self.new_revision(&content, pin);
        let f = self.files.get_mut(id).unwrap();
        f.content = content;
        f.version += step;
        f.revisions.push(revision);
    }

    /// A file created by another device (pinned if `others_pin`).
    fn insert(&mut self, name: &str, content: Vec<u8>, props: HashMap<String, String>) -> String {
        let pin = self.others_pin;
        self.insert_pinned(name, content, props, pin)
    }

    fn insert_pinned(
        &mut self,
        name: &str,
        content: Vec<u8>,
        props: HashMap<String, String>,
        pin: bool,
    ) -> String {
        self.next_id += 1;
        let id = format!("file{}", self.next_id);
        let revision = self.new_revision(&content, pin);
        let created = self
            .created
            .clone()
            .unwrap_or_else(|| format!("2026-10-09T10:00:{:02}.000Z", self.next_id));
        self.files.insert(
            id.clone(),
            FakeFile {
                name: name.into(),
                content,
                version: 1,
                created,
                props,
                revisions: vec![revision],
            },
        );
        id
    }

    /// Ids of the pinned revisions of the only file.
    fn pinned(&self) -> Vec<String> {
        let (_, f) = self.only_file();
        f.revisions
            .iter()
            .filter(|r| r.keep_forever)
            .map(|r| r.id.clone())
            .collect()
    }

    fn meta(&self, id: &str) -> serde_json::Value {
        let f = &self.files[id];
        json!({
            "id": id,
            "name": f.name,
            "version": f.version.to_string(),
            "md5Checksum": hex(&Sha256::digest(&f.content)[..16]),
            "modifiedTime": "2026-10-09T12:34:56.789Z",
            "createdTime": f.created,
            "size": f.content.len().to_string(),
            "appProperties": f.props,
            "headRevisionId": f.revisions.last().map(|r| r.id.clone()),
        })
    }

    fn only_file(&self) -> (String, FakeFile) {
        assert_eq!(self.files.len(), 1, "expected exactly one file");
        let (id, f) = self.files.iter().next().unwrap();
        (id.clone(), f.clone())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn props_of(v: &serde_json::Value) -> HashMap<String, String> {
    v.get("appProperties")
        .and_then(|p| p.as_object())
        .map(|o| {
            o.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// The media part of a `multipart/related` body (the second part).
fn multipart(body: &[u8], boundary: &str) -> (serde_json::Value, Vec<u8>) {
    let delimiter = format!("--{boundary}");
    let find = |hay: &[u8], needle: &[u8], from: usize| {
        hay[from..]
            .windows(needle.len())
            .position(|w| w == needle)
            .map(|p| p + from)
    };
    let headers_end = |from: usize| find(body, b"\r\n\r\n", from).unwrap() + 4;
    let first = find(body, delimiter.as_bytes(), 0).unwrap();
    let meta_start = headers_end(first);
    let second = find(body, delimiter.as_bytes(), meta_start).unwrap();
    let meta: serde_json::Value = serde_json::from_slice(&body[meta_start..second - 2]).unwrap();
    let media_start = headers_end(second);
    let end = find(body, format!("\r\n--{boundary}--").as_bytes(), media_start).unwrap();
    (meta, body[media_start..end].to_vec())
}

fn serve(drive: Arc<Mutex<Drive>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    let base_for_thread = base.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() {
                continue;
            }
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or("").to_string();
            let target = parts.next().unwrap_or("").to_string();
            let mut headers = Vec::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line.trim().is_empty() {
                    break;
                }
                let (k, v) = line.split_once(':').unwrap();
                headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
            }
            let header = |name: &str| {
                headers
                    .iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.clone())
            };
            let mut body = vec![0; header("content-length").map_or(0, |l| l.parse().unwrap())];
            reader.read_exact(&mut body).unwrap();
            let (path, query) = target.split_once('?').unwrap_or((&target, ""));
            let query: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
                .into_owned()
                .collect();
            let q = |k: &str| query.get(k).cloned().unwrap_or_default();
            let pin = q("keepRevisionForever") == "true";

            let mut d = drive.lock().unwrap();
            d.log.push((method.clone(), path.to_string()));
            let mut raw = request_line.clone().into_bytes();
            for (k, v) in &headers {
                raw.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
            }
            raw.extend_from_slice(b"\r\n");
            raw.extend_from_slice(&body);
            d.raw.push((format!("{base_for_thread}{target}"), raw));
            let ok = |v: serde_json::Value| (200, String::new(), v.to_string().into_bytes());
            let not_found = (
                404,
                String::new(),
                br#"{"error":{"code":404,"message":"File not found"}}"#.to_vec(),
            );
            let (status, extra, payload): (u16, String, Vec<u8>) = if d.expired
                || header("authorization").as_deref() != Some(&format!("Bearer {TOKEN}"))
            {
                (401, String::new(), br#"{"error":{"code":401,"message":"Invalid Credentials","errors":[{"reason":"authError"}]}}"#.to_vec())
            } else if pin && d.refuse_pins {
                (403, String::new(), br#"{"error":{"code":403,"message":"The maximum number of revisions that can be kept forever was reached.","errors":[{"reason":"revisionsKeepForeverLimit"}]}}"#.to_vec())
            } else if d.scope_denied {
                (403, String::new(), br#"{"error":{"code":403,"message":"Request had insufficient authentication scopes.","errors":[{"reason":"insufficientPermissions"}],"status":"PERMISSION_DENIED"}}"#.to_vec())
            } else {
                let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
                match (method.as_str(), segments.as_slice()) {
                    ("GET", ["drive", "v3", "about"]) => ok(json!({
                        "user": {"emailAddress": "alice@example.com", "displayName": "Alice"}
                    })),
                    ("GET", ["drive", "v3", "files"]) => {
                        assert_eq!(q("spaces"), "appDataFolder");
                        let filter = q("q");
                        // Every `name = '…'` of the query (`or`ed), none: all files.
                        let names: Vec<String> = filter
                            .split("name = '")
                            .skip(1)
                            .filter_map(|rest| rest.split_once('\'').map(|(n, _)| n.to_string()))
                            .collect();
                        let files: Vec<_> = d
                            .files
                            .iter()
                            .filter(|(id, _)| !d.hidden.contains(id))
                            .filter(|(_, f)| names.is_empty() || names.contains(&f.name))
                            .map(|(id, _)| d.meta(id))
                            .collect();
                        ok(json!({ "files": files }))
                    }
                    ("GET", ["drive", "v3", "files", id]) => match d.files.get(*id) {
                        None => not_found.clone(),
                        Some(f) if q("alt") == "media" => {
                            let content = f.content.clone();
                            if let Some(other) = d.after_download.take() {
                                let id = id.to_string();
                                d.write(&id, other);
                            }
                            (200, String::new(), content)
                        }
                        Some(_) => ok(d.meta(id)),
                    },
                    // A file without contents (the removal marker).
                    ("POST", ["drive", "v3", "files"]) => {
                        let meta: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        assert_eq!(meta["parents"], json!(["appDataFolder"]));
                        let id = d.insert_pinned(
                            meta["name"].as_str().unwrap(),
                            Vec::new(),
                            props_of(&meta),
                            false,
                        );
                        ok(json!({ "id": id }))
                    }
                    ("POST", ["upload", "drive", "v3", "files"])
                        if q("uploadType") == "multipart" =>
                    {
                        let ct = header("content-type").unwrap();
                        let boundary = ct.split_once("boundary=").unwrap().1.to_string();
                        let (meta, media) = multipart(&body, &boundary);
                        assert_eq!(meta["parents"], json!(["appDataFolder"]));
                        let id = d.insert_pinned(
                            meta["name"].as_str().unwrap(),
                            media,
                            props_of(&meta),
                            pin,
                        );
                        ok(d.meta(&id))
                    }
                    ("POST" | "PATCH", ["upload", "drive", "v3", "files", rest @ ..])
                        if q("uploadType") == "resumable" =>
                    {
                        let session = format!("s{}", d.sessions.len() + 1);
                        let meta: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        let target = rest.first().map(|s| s.to_string());
                        if target.as_ref().is_some_and(|t| !d.files.contains_key(t)) {
                            not_found.clone()
                        } else {
                            d.sessions.insert(session.clone(), (target, (meta, pin)));
                            (
                                200,
                                format!("Location: {base_for_thread}/session/{session}\r\n"),
                                Vec::new(),
                            )
                        }
                    }
                    ("PUT", ["session", session]) => {
                        let (target, (meta, pin)) = d.sessions.remove(*session).unwrap();
                        let id = match target {
                            Some(id) => {
                                d.write_pinned(&id, body, pin);
                                id
                            }
                            None => d.insert_pinned(
                                meta["name"].as_str().unwrap(),
                                body,
                                props_of(&meta),
                                pin,
                            ),
                        };
                        ok(d.meta(&id))
                    }
                    ("PATCH", ["upload", "drive", "v3", "files", id]) => {
                        assert_eq!(q("uploadType"), "media");
                        if !d.files.contains_key(*id) {
                            not_found.clone()
                        } else {
                            let id = id.to_string();
                            if let Some(other) = d.before_upload.take() {
                                d.write(&id, other);
                            }
                            d.write_pinned(&id, body, pin);
                            ok(d.meta(&id))
                        }
                    }
                    ("GET", ["drive", "v3", "files", _, "revisions"]) if d.fail_revisions > 0 => {
                        d.fail_revisions -= 1;
                        (500, String::new(), br#"{"error":{"code":500}}"#.to_vec())
                    }
                    ("GET", ["drive", "v3", "files", id, "revisions"]) => match d.files.get(*id) {
                        None => not_found.clone(),
                        Some(f) => ok(json!({
                            "revisions": f
                                .revisions
                                .iter()
                                .map(|r| json!({"id": r.id, "keepForever": r.keep_forever}))
                                .collect::<Vec<_>>()
                        })),
                    },
                    // Drive serves an old blob revision only when it is pinned ("Keep forever").
                    ("GET", ["drive", "v3", "files", id, "revisions", rev]) => {
                        let found = d.files.get(*id).and_then(|f| {
                            let head = f.revisions.last().map(|r| r.id.clone());
                            f.revisions
                                .iter()
                                .find(|r| r.id == *rev)
                                .map(|r| (r.clone(), head))
                        });
                        match found {
                            None => not_found.clone(),
                            Some((r, head)) if r.keep_forever || head.as_deref() == Some(*rev) => {
                                assert_eq!(q("alt"), "media");
                                (200, String::new(), r.content)
                            }
                            Some(_) => (403, String::new(), br#"{"error":{"code":403,"message":"Only revisions marked keepForever can be downloaded.","errors":[{"reason":"revisionNotDownloadable"}]}}"#.to_vec()),
                        }
                    }
                    ("PATCH", ["drive", "v3", "files", id, "revisions", rev]) => {
                        let meta: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        let revision = d
                            .files
                            .get_mut(*id)
                            .and_then(|f| f.revisions.iter_mut().find(|r| r.id == *rev));
                        match revision {
                            None => not_found.clone(),
                            Some(r) => {
                                r.keep_forever = meta["keepForever"].as_bool().unwrap();
                                let (id, keep) = (r.id.clone(), r.keep_forever);
                                ok(json!({"id": id, "keepForever": keep}))
                            }
                        }
                    }
                    ("PATCH", ["drive", "v3", "files", id]) => {
                        let id = id.to_string();
                        if let Some(other) = d.before_rename.take() {
                            d.write(&id, other);
                        }
                        let meta: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        let step = d.step.max(1);
                        match d.files.get_mut(&id) {
                            None => not_found.clone(),
                            Some(f) => {
                                // Drive's patch semantics: a `null` value removes the key.
                                let patch = meta.get("appProperties").and_then(|p| p.as_object());
                                for (k, v) in patch.into_iter().flatten() {
                                    match v.as_str() {
                                        Some(v) => f.props.insert(k.clone(), v.to_string()),
                                        None => f.props.remove(k),
                                    };
                                }
                                f.version += step;
                                ok(d.meta(&id))
                            }
                        }
                    }
                    ("DELETE", ["drive", "v3", "files", id, "revisions", rev]) => {
                        let busy = d.deletes_before_busy == Some(0);
                        if let Some(n) = d.deletes_before_busy.as_mut() {
                            *n = n.saturating_sub(1);
                        }
                        let refused = d.undeletable.iter().any(|r| r == rev);
                        match d.files.get_mut(*id) {
                            _ if busy => (429, String::new(), br#"{"error":{"code":429,"message":"Rate Limit Exceeded","errors":[{"reason":"rateLimitExceeded"}]}}"#.to_vec()),
                            None => not_found.clone(),
                            Some(f) => match f.revisions.iter().position(|r| r.id == *rev) {
                                None => not_found.clone(),
                                Some(i) if refused || i + 1 == f.revisions.len() => (400, String::new(), br#"{"error":{"code":400,"message":"The revision can't be deleted.","errors":[{"reason":"badRequest"}]}}"#.to_vec()),
                                Some(i) => {
                                    f.revisions.remove(i);
                                    (204, String::new(), Vec::new())
                                }
                            },
                        }
                    }
                    ("DELETE", ["drive", "v3", "files", id]) => match d.files.remove(*id) {
                        Some(_) => (204, String::new(), Vec::new()),
                        None => not_found.clone(),
                    },
                    _ => (400, String::new(), b"unexpected request".to_vec()),
                }
            };
            write!(
                stream,
                "HTTP/1.1 {status} X\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            )
            .unwrap();
            stream.write_all(&payload).unwrap();
        }
    });
    base
}

fn setup() -> (Arc<Mutex<Drive>>, Endpoints) {
    let drive = Arc::new(Mutex::new(Drive {
        step: 1,
        others_pin: true,
        ..Default::default()
    }));
    let base = serve(drive.clone());
    let endpoints = Endpoints {
        api: format!("{base}/drive/v3"),
        upload: format!("{base}/upload/drive/v3"),
        simple_upload_limit: SIMPLE_UPLOAD_LIMIT,
    };
    (drive, endpoints)
}

fn config(name: &str) -> GDriveConfig {
    GDriveConfig {
        access_token: TOKEN.into(),
        vault_name: name.into(),
        start_again: false,
    }
}

fn fast_kdf() -> KdfParams {
    KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
        ..Default::default()
    }
}

fn item(title: &str) -> Item {
    Item {
        title: title.into(),
        ..Default::default()
    }
}

fn titles(v: &Vault) -> Vec<String> {
    let mut t: Vec<String> = v.items().into_iter().map(|i| i.title).collect();
    t.sort();
    t
}

fn log(drive: &Arc<Mutex<Drive>>) -> Vec<(String, String)> {
    drive.lock().unwrap().take_log()
}

fn methods(drive: &Arc<Mutex<Drive>>) -> Vec<String> {
    log(drive)
        .into_iter()
        .map(|(m, p)| {
            let kind = if p.starts_with("/upload/") {
                "upload"
            } else if p.ends_with("/revisions") {
                "revisions"
            } else if p.contains("/revisions/") {
                "revision"
            } else if p == "/drive/v3/files" {
                "list"
            } else {
                "file"
            };
            format!("{m} {kind}")
        })
        .collect()
}

/// A second device with the same vault, from the Drive copy (as "Restore from Google Drive").
fn restore(base: &Endpoints, device: &str) -> Arc<Vault> {
    let vaults = list_with(base, TOKEN).unwrap();
    assert_eq!(vaults.len(), 1);
    let bytes = download_with(base, TOKEN, &vaults[0].file_id).unwrap();
    Vault::unlock(bytes, "pw".into(), device.into()).unwrap()
}

#[test]
fn first_sync_creates_then_idle_sync_is_one_small_request() {
    let (drive, base) = setup();
    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    laptop.upsert(item("A")).unwrap();

    let first = sync_with(&base, &laptop, &config("Personal")).unwrap();
    assert!(first.uploaded && first.created_remote);
    assert_eq!(methods(&drive), ["GET list", "POST upload", "GET list"]);
    {
        let d = drive.lock().unwrap();
        let (_, f) = d.only_file();
        assert_eq!(f.name, format!("pass-{}.vault", laptop.vault_id()));
        assert_eq!(f.props[PROP_VAULT_ID], laptop.vault_id());
        // The vault's name is the one readable value, so a new device can list vaults by name.
        assert_eq!(f.props[PROP_NAME], "Personal");
        assert_eq!(f.props.len(), 2, "{:?}", f.props);
        assert_eq!(first.remote_bytes, Some(f.content.len() as u64));
    }
    assert!(laptop.is_dirty(), "the sync state must be persisted");
    assert!(!laptop.sync_pending());

    let idle = sync_with(&base, &laptop, &config("Personal")).unwrap();
    assert!(!idle.uploaded && !idle.created_remote);
    assert_eq!(methods(&drive), ["GET file"]);
    let stored =
        |drive: &Arc<Mutex<Drive>>| drive.lock().unwrap().only_file().1.content.len() as u64;
    assert_eq!(idle.remote_bytes, Some(stored(&drive)));

    // A local edit: metadata + one media upload.
    laptop.upsert(item("B")).unwrap();
    assert!(laptop.sync_pending());
    let edit = sync_with(&base, &laptop, &config("Personal")).unwrap();
    assert!(edit.uploaded);
    // Then the revisions are checked (nothing overwritten) and the previous one is unpinned.
    assert_eq!(
        methods(&drive),
        [
            "GET file",
            "PATCH upload",
            "GET revisions",
            "PATCH revision"
        ]
    );
    assert_eq!(drive.lock().unwrap().pinned().len(), 1, "only the head");
    assert_eq!(edit.remote_bytes, Some(stored(&drive)));
    assert!(edit.remote_bytes > idle.remote_bytes, "the file grew");
    assert_eq!(
        sync_with(&base, &laptop, &config("Personal"))
            .unwrap()
            .stats
            .added,
        0
    );
    assert_eq!(methods(&drive), ["GET file"]);

    // The sync state survives a save + unlock (it lives in the local file).
    let reopened =
        Vault::unlock(laptop.serialize().unwrap(), "pw".into(), "laptop".into()).unwrap();
    sync_with(&base, &reopened, &config("Personal")).unwrap();
    assert_eq!(methods(&drive), ["GET file"]);
}

#[test]
fn two_devices_converge() {
    let (drive, base) = setup();
    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    laptop.upsert(item("A")).unwrap();
    sync_with(&base, &laptop, &config("Personal")).unwrap();

    let phone = restore(&base, "phone");
    log(&drive);
    let first = sync_with(&base, &phone, &config("Personal")).unwrap();
    assert!(!first.uploaded);
    assert_eq!(methods(&drive), ["GET list", "GET file", "GET revisions"]);
    sync_with(&base, &phone, &config("Personal")).unwrap();
    assert_eq!(methods(&drive), ["GET file"]);

    phone.upsert(item("P")).unwrap();
    sync_with(&base, &phone, &config("Personal")).unwrap();
    log(&drive);

    let pulled = sync_with(&base, &laptop, &config("Personal")).unwrap();
    assert_eq!(pulled.stats.added, 1);
    assert!(!pulled.uploaded);
    assert_eq!(methods(&drive), ["GET file", "GET file", "GET revisions"]);
    assert_eq!(titles(&laptop), ["A", "P"]);

    // Both changed: download + merge, re-check the version, then upload the union.
    laptop.upsert(item("L2")).unwrap();
    phone.upsert(item("P2")).unwrap();
    sync_with(&base, &phone, &config("Personal")).unwrap();
    log(&drive);
    let both = sync_with(&base, &laptop, &config("Personal")).unwrap();
    assert!(both.uploaded);
    assert_eq!(both.stats.added, 1);
    assert_eq!(
        methods(&drive),
        [
            "GET file",
            "GET file",
            "GET revisions",
            "GET file",
            "PATCH upload",
            "GET revisions",
            "PATCH revision"
        ]
    );
    assert_eq!(drive.lock().unwrap().pinned().len(), 1, "only the head");
    sync_with(&base, &phone, &config("Personal")).unwrap();
    assert_eq!(titles(&phone), ["A", "L2", "P", "P2"]);
    assert_eq!(titles(&laptop), titles(&phone));
}

#[test]
fn version_steps_larger_than_one_cost_nothing_extra() {
    let (drive, base) = setup();
    drive.lock().unwrap().step = 7;
    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    sync_with(&base, &laptop, &config("")).unwrap();
    laptop.upsert(item("A")).unwrap();
    sync_with(&base, &laptop, &config("")).unwrap();
    log(&drive);
    sync_with(&base, &laptop, &config("")).unwrap();
    assert_eq!(methods(&drive), ["GET file"]);
}

#[test]
fn a_write_during_the_merge_is_merged_not_overwritten() {
    let (drive, base) = setup();
    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    sync_with(&base, &laptop, &config("")).unwrap();
    let phone = restore(&base, "phone");
    let tablet = restore(&base, "tablet");
    sync_with(&base, &phone, &config("")).unwrap();

    phone.upsert(item("P")).unwrap();
    sync_with(&base, &phone, &config("")).unwrap();
    // The tablet uploads right after the laptop downloaded the phone's version.
    tablet.upsert(item("T")).unwrap();
    let (tablet_bytes, _) = tablet.snapshot().unwrap();
    drive.lock().unwrap().after_download = Some(tablet_bytes);

    laptop.upsert(item("L")).unwrap();
    let result = sync_with(&base, &laptop, &config("")).unwrap();
    assert!(result.uploaded);
    // The re-check before the upload noticed the new version: merged it, then uploaded.
    assert_eq!(titles(&laptop), ["L", "P", "T"]);
    let d = drive.lock().unwrap();
    let (_, f) = d.only_file();
    drop(d);
    let remote = Vault::unlock(f.content, "pw".into(), "x".into()).unwrap();
    assert_eq!(titles(&remote), ["L", "P", "T"]);
}

/// The phone's upload lands in the last moment before the laptop's, which overwrites it (Drive v3
/// has no conditional upload). Returns (laptop, phone) after the laptop's sync.
fn overwrite_the_phones_write(
    drive: &Arc<Mutex<Drive>>,
    base: &Endpoints,
    fail_check: bool,
) -> (Arc<Vault>, Arc<Vault>) {
    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    sync_with(base, &laptop, &config("")).unwrap();
    let phone = restore(base, "phone");
    sync_with(base, &phone, &config("")).unwrap();

    phone.upsert(item("P")).unwrap();
    let (phone_bytes, phone_fp) = phone.snapshot().unwrap();
    drive.lock().unwrap().before_upload = Some(phone_bytes);
    // What the phone would have recorded after its own upload.
    {
        let d = drive.lock().unwrap();
        let (id, f) = d.only_file();
        let key = url_key(&format!("gdrive:{}", phone.vault_id()));
        phone.set_sync_state(
            Known {
                file_id: id,
                version: f.version + 1,
                md5: String::new(),
                fingerprint: phone_fp,
                unverified: false,
                twins: false,
            }
            .state(&key),
        );
    }
    laptop.upsert(item("L")).unwrap();
    if fail_check {
        // The laptop's check right after its upload fails (no connection, say).
        drive.lock().unwrap().fail_revisions = 1;
    }
    log(drive);
    sync_with(base, &laptop, &config("")).unwrap();
    (laptop, phone)
}

fn remote_titles(drive: &Arc<Mutex<Drive>>) -> Vec<String> {
    let content = drive.lock().unwrap().only_file().1.content;
    titles(&Vault::unlock(content, "pw".into(), "x".into()).unwrap())
}

#[test]
fn an_overwritten_write_is_merged_by_the_device_that_overwrote_it() {
    let (drive, base) = setup();
    let (laptop, phone) = overwrite_the_phones_write(&drive, &base, false);
    // The laptop's check after its upload found the phone's pinned revision, merged it and
    // uploaded again, then unpinned everything but the new head.
    assert_eq!(
        methods(&drive),
        [
            "GET file",
            "PATCH upload",
            "GET revisions",
            "GET revision",
            "PATCH revision",
            "GET file",
            "PATCH upload",
            "GET revisions",
            "PATCH revision",
            "PATCH revision"
        ]
    );
    assert_eq!(titles(&laptop), ["L", "P"]);
    assert_eq!(remote_titles(&drive), ["L", "P"]);
    assert_eq!(drive.lock().unwrap().pinned().len(), 1, "only the head");
    // Even if the phone never syncs again, its write is in Drive: a new device gets it.
    assert_eq!(titles(&restore(&base, "tablet")), ["L", "P"]);
    // When it does sync, it just catches up.
    let back = sync_with(&base, &phone, &config("")).unwrap();
    assert!(!back.uploaded);
    assert_eq!(titles(&phone), ["L", "P"]);
}

#[test]
fn an_older_clients_overwritten_write_comes_back_on_its_next_sync() {
    let (drive, base) = setup();
    // The phone runs an older version: its revision isn't pinned, and Drive won't serve it.
    drive.lock().unwrap().others_pin = false;
    let (laptop, phone) = overwrite_the_phones_write(&drive, &base, false);
    assert_eq!(
        titles(&laptop),
        ["L"],
        "the laptop overwrote the phone's write"
    );

    // The phone sees a newer version, merges the laptop's copy, notices "P" is missing remotely
    // and uploads again; the laptop gets it on its next sync. Nothing is lost.
    let back = sync_with(&base, &phone, &config("")).unwrap();
    assert!(back.uploaded);
    assert_eq!(titles(&phone), ["L", "P"]);
    sync_with(&base, &laptop, &config("")).unwrap();
    assert_eq!(titles(&laptop), ["L", "P"]);
}

#[test]
fn an_interrupted_check_runs_on_the_next_sync() {
    let (drive, base) = setup();
    let (laptop, _phone) = overwrite_the_phones_write(&drive, &base, true);
    assert_eq!(titles(&laptop), ["L"]);
    // The pending check is in the local sync state, so it survives a restart.
    let laptop = Vault::unlock(laptop.serialize().unwrap(), "pw".into(), "laptop".into()).unwrap();
    log(&drive);
    let next = sync_with(&base, &laptop, &config("")).unwrap();
    assert!(next.uploaded);
    assert_eq!(titles(&laptop), ["L", "P"]);
    assert_eq!(remote_titles(&drive), ["L", "P"]);
    assert_eq!(drive.lock().unwrap().pinned().len(), 1, "only the head");
    // Checked now: the next idle sync is one small request again.
    log(&drive);
    sync_with(&base, &laptop, &config("")).unwrap();
    assert_eq!(methods(&drive), ["GET file"]);
}

#[test]
fn an_overwritten_write_survives_when_both_devices_go_away() {
    let (drive, base) = setup();
    // The laptop overwrote the phone's write and couldn't check; neither syncs again.
    let (_laptop, _phone) = overwrite_the_phones_write(&drive, &base, true);
    // A tablet set up from Drive syncs: the download comes with a look at the pinned revisions,
    // so it merges the phone's write and uploads the union.
    let tablet = restore(&base, "tablet");
    assert_eq!(titles(&tablet), ["L"]);
    let r = sync_with(&base, &tablet, &config("")).unwrap();
    assert!(r.uploaded);
    assert_eq!(titles(&tablet), ["L", "P"]);
    assert_eq!(remote_titles(&drive), ["L", "P"]);
    assert_eq!(drive.lock().unwrap().pinned().len(), 1, "only the head");
}

#[test]
fn refused_pins_fall_back_to_plain_uploads() {
    let (drive, base) = setup();
    drive.lock().unwrap().refuse_pins = true;
    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    laptop.upsert(item("A")).unwrap();
    let first = sync_with(&base, &laptop, &config("")).unwrap();
    assert!(first.created_remote);
    assert_eq!(
        methods(&drive),
        ["GET list", "POST upload", "POST upload", "GET list"]
    );
    laptop.upsert(item("B")).unwrap();
    assert!(sync_with(&base, &laptop, &config("")).unwrap().uploaded);
    // Not pinned: nothing to check, and nothing is unpinned.
    assert_eq!(
        methods(&drive),
        ["GET file", "PATCH upload", "PATCH upload", "GET revisions"]
    );
    assert!(drive.lock().unwrap().pinned().is_empty());
    assert_eq!(remote_titles(&drive), ["A", "B"]);
}

#[test]
fn a_rename_right_after_another_upload_does_not_hide_it() {
    let (drive, base) = setup();
    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    sync_with(&base, &laptop, &config("Personal")).unwrap();
    let phone = restore(&base, "phone");
    phone.upsert(item("P")).unwrap();
    // The phone's upload lands just before the laptop renames the vault on Drive.
    drive.lock().unwrap().before_rename = Some(phone.snapshot().unwrap().0);
    sync_with(&base, &laptop, &config("Work")).unwrap();
    assert!(titles(&laptop).is_empty());
    // The rename's new version isn't taken for "unchanged": the next sync downloads the phone's
    // write.
    let next = sync_with(&base, &laptop, &config("Work")).unwrap();
    assert_eq!(next.stats.added, 1);
    assert_eq!(titles(&laptop), ["P"]);
}

/// A time far ahead, so the fake's files count as just created.
const NOW_ISH: &str = "2099-01-01T00:00:00.000Z";

#[test]
fn twins_missing_from_the_first_listing_are_found_later() {
    let (drive, base) = setup();
    drive.lock().unwrap().created = Some(NOW_ISH.into());
    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    laptop.upsert(item("L")).unwrap();
    let phone = Vault::unlock(laptop.serialize().unwrap(), "pw".into(), "phone".into()).unwrap();
    phone.upsert(item("P")).unwrap();
    sync_with(&base, &laptop, &config("")).unwrap();
    // The phone creates its own copy at the same moment, and the listing shows neither copy to
    // the other device yet.
    let laptops = drive.lock().unwrap().files.keys().next().unwrap().clone();
    drive.lock().unwrap().hidden = vec![laptops.clone()];
    let r = sync_with(&base, &phone, &config("")).unwrap();
    assert!(r.created_remote);
    assert_eq!(drive.lock().unwrap().files.len(), 2);
    drive.lock().unwrap().hidden.clear();

    // The files are young, so the laptop's next sync looks them up by name, finds the twin,
    // merges it into the oldest and deletes it.
    log(&drive);
    let r = sync_with(&base, &laptop, &config("")).unwrap();
    assert!(r.uploaded && r.stats.added == 1);
    assert_eq!(methods(&drive)[..2], ["GET file", "GET list"]);
    assert_eq!(titles(&laptop), ["L", "P"]);
    assert!(drive.lock().unwrap().files.contains_key(&laptops));
    assert_eq!(remote_titles(&drive), ["L", "P"]);
    // The phone finds its copy gone and switches to the canonical one.
    sync_with(&base, &phone, &config("")).unwrap();
    assert_eq!(titles(&phone), ["L", "P"]);
    assert_eq!(drive.lock().unwrap().files.len(), 1);
}

#[test]
fn a_twin_that_changed_after_merging_is_kept_until_merged_again() {
    let (drive, base) = setup();
    drive.lock().unwrap().created = Some(NOW_ISH.into());
    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    laptop.upsert(item("L")).unwrap();
    let phone = Vault::unlock(laptop.serialize().unwrap(), "pw".into(), "phone".into()).unwrap();
    phone.upsert(item("P")).unwrap();
    sync_with(&base, &laptop, &config("")).unwrap();
    let laptops = drive.lock().unwrap().files.keys().next().unwrap().clone();
    drive.lock().unwrap().hidden = vec![laptops.clone()];
    sync_with(&base, &phone, &config("")).unwrap();
    drive.lock().unwrap().hidden.clear();
    let phones = drive
        .lock()
        .unwrap()
        .files
        .keys()
        .find(|id| **id != laptops)
        .unwrap()
        .clone();

    // Right after the laptop downloaded the phone's twin, the phone uploads to it again.
    phone.upsert(item("P2")).unwrap();
    drive.lock().unwrap().after_download = Some(phone.snapshot().unwrap().0);
    sync_with(&base, &laptop, &config("")).unwrap();
    assert_eq!(titles(&laptop), ["L", "P"]);
    // Changed since it was merged: not deleted.
    assert!(drive.lock().unwrap().files.contains_key(&phones));

    // The next sync merges it again, and deletes it now that it is unchanged.
    sync_with(&base, &laptop, &config("")).unwrap();
    assert_eq!(titles(&laptop), ["L", "P", "P2"]);
    assert_eq!(drive.lock().unwrap().files.len(), 1);
    assert_eq!(remote_titles(&drive), ["L", "P", "P2"]);
}

#[test]
fn duplicate_files_from_simultaneous_creation_are_folded_into_the_oldest() {
    let (drive, base) = setup();
    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    laptop.upsert(item("L")).unwrap();
    let phone = Vault::unlock(laptop.serialize().unwrap(), "pw".into(), "phone".into()).unwrap();
    phone.upsert(item("P")).unwrap();
    let name = file_name(&laptop.vault_id());
    let props = props(&laptop.vault_id(), "Personal");
    let (older, newer) = {
        let mut d = drive.lock().unwrap();
        let older = d.insert(&name, laptop.snapshot().unwrap().0, props.clone());
        let newer = d.insert(&name, phone.snapshot().unwrap().0, props);
        (older, newer)
    };
    let tablet = Vault::unlock(laptop.serialize().unwrap(), "pw".into(), "tablet".into()).unwrap();
    let result = sync_with(&base, &tablet, &config("Personal")).unwrap();
    assert!(result.uploaded);
    assert_eq!(titles(&tablet), ["L", "P"]);
    let d = drive.lock().unwrap();
    assert!(d.files.contains_key(&older) && !d.files.contains_key(&newer));
    let (_, f) = d.only_file();
    drop(d);
    let remote = Vault::unlock(f.content, "pw".into(), "x".into()).unwrap();
    assert_eq!(titles(&remote), ["L", "P"]);
    assert_eq!(list_with(&base, TOKEN).unwrap().len(), 1);
}

#[test]
fn a_deleted_file_is_created_again() {
    let (drive, base) = setup();
    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    laptop.upsert(item("A")).unwrap();
    sync_with(&base, &laptop, &config("")).unwrap();
    let id = drive.lock().unwrap().only_file().0;
    delete_with(&base, TOKEN, &id).unwrap();
    log(&drive);
    let again = sync_with(&base, &laptop, &config("")).unwrap();
    assert!(again.created_remote && again.uploaded);
    assert_eq!(
        methods(&drive),
        ["GET file", "GET list", "POST upload", "GET list"]
    );
}

// ---- "Delete old versions from Google Drive" and "Remove vault from Google Drive" ----------------

/// The revisions of the only file: (id, pinned, contents).
fn revisions_of(drive: &Arc<Mutex<Drive>>) -> Vec<(String, bool, Vec<u8>)> {
    let (_, f) = drive.lock().unwrap().only_file();
    f.revisions
        .into_iter()
        .map(|r| (r.id, r.keep_forever, r.content))
        .collect()
}

/// A vault synced three times (three revisions on Drive), then given a new password and synced
/// again: the old revisions still open with "pw".
fn vault_with_old_versions(base: &Endpoints) -> Arc<Vault> {
    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    for title in ["A", "B", "C"] {
        laptop.upsert(item(title)).unwrap();
        sync_with(base, &laptop, &config("Personal")).unwrap();
    }
    laptop.change_password("pw".into(), "new".into()).unwrap();
    sync_with(base, &laptop, &config("Personal")).unwrap();
    laptop
}

#[test]
fn old_versions_after_a_password_change_are_deleted_and_the_head_stays() {
    let (drive, base) = setup();
    let laptop = vault_with_old_versions(&base);
    let before = revisions_of(&drive);
    assert_eq!(before.len(), 4);
    let (old, head) = before.split_at(3);
    assert!(Vault::unlock(old[2].2.clone(), "pw".into(), "x".into()).is_ok());
    log(&drive);

    let result = old_versions_with(&base, &laptop, &config("Personal")).unwrap();
    assert_eq!(
        result,
        GDriveOldVersions {
            removed: 3,
            kept: 0,
            unfinished: false
        }
    );
    // In step already (one small request), then the file, its revisions and one delete each.
    // The head is never asked for: Drive can't delete it.
    assert_eq!(
        methods(&drive),
        [
            "GET file",
            "GET file",
            "GET revisions",
            "DELETE revision",
            "DELETE revision",
            "DELETE revision"
        ]
    );
    let after = revisions_of(&drive);
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].0, head[0].0, "the head stays");
    // What is left opens only with the new password, and holds everything.
    assert!(Vault::unlock(after[0].2.clone(), "pw".into(), "x".into()).is_err());
    let current = Vault::unlock(after[0].2.clone(), "new".into(), "x".into()).unwrap();
    assert_eq!(titles(&current), ["A", "B", "C"]);
    assert_eq!(titles(&laptop), ["A", "B", "C"]);

    // Nothing left to delete: no delete at all.
    let again = old_versions_with(&base, &laptop, &config("Personal")).unwrap();
    assert_eq!(again, GDriveOldVersions::default());
    assert!(!methods(&drive).iter().any(|m| m.starts_with("DELETE")));
}

#[test]
fn a_pinned_old_version_with_another_devices_write_is_merged_before_it_goes() {
    let (drive, base) = setup();
    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    laptop.upsert(item("L")).unwrap();
    sync_with(&base, &laptop, &config("")).unwrap();
    // The phone's write, overwritten before anyone merged it: a pinned revision under the head.
    let phone = restore(&base, "phone");
    phone.upsert(item("P")).unwrap();
    let (phone_bytes, _) = phone.snapshot().unwrap();
    {
        let mut d = drive.lock().unwrap();
        let id = d.only_file().0;
        let f = d.files.get_mut(&id).unwrap();
        let at = f.revisions.len() - 1;
        f.revisions.insert(
            at,
            FakeRevision {
                id: "stray".into(),
                content: phone_bytes,
                keep_forever: true,
            },
        );
    }

    let result = old_versions_with(&base, &laptop, &config("")).unwrap();
    assert!(!result.unfinished);
    // The phone's item came in and went up before the old version was deleted.
    assert_eq!(titles(&laptop), ["L", "P"]);
    assert_eq!(remote_titles(&drive), ["L", "P"]);
    let left = revisions_of(&drive);
    assert!(left.iter().all(|(id, _, _)| id != "stray"), "{left:?}");
    assert_eq!(left.len(), 1, "only the head");
}

#[test]
fn old_versions_drive_wont_delete_or_this_version_cant_read_are_kept() {
    let (drive, base) = setup();
    let laptop = vault_with_old_versions(&base);
    {
        let mut d = drive.lock().unwrap();
        let id = d.only_file().0;
        let first = d.files[&id].revisions[0].id.clone();
        d.undeletable.push(first);
        // A pinned copy in a format this version doesn't know (a newer app's).
        let f = d.files.get_mut(&id).unwrap();
        let at = f.revisions.len() - 1;
        f.revisions.insert(
            at,
            FakeRevision {
                id: "future".into(),
                content: b"PASS\x09 a format from the future".to_vec(),
                keep_forever: true,
            },
        );
    }
    let result = old_versions_with(&base, &laptop, &config("Personal")).unwrap();
    assert_eq!(
        result,
        GDriveOldVersions {
            removed: 2,
            kept: 2,
            unfinished: false
        }
    );
    let left: Vec<String> = revisions_of(&drive).into_iter().map(|r| r.0).collect();
    assert_eq!(left.len(), 3);
    assert!(left.contains(&"future".to_string()));
}

#[test]
fn drive_busy_part_way_keeps_what_was_deleted_and_says_so() {
    let (drive, base) = setup();
    let laptop = vault_with_old_versions(&base);
    drive.lock().unwrap().deletes_before_busy = Some(1);
    let partly = old_versions_with(&base, &laptop, &config("Personal")).unwrap();
    assert_eq!(
        partly,
        GDriveOldVersions {
            removed: 1,
            kept: 0,
            unfinished: true
        }
    );
    assert_eq!(revisions_of(&drive).len(), 3);

    // Busy from the first delete: the plain "Google Drive is busy" error, nothing deleted.
    drive.lock().unwrap().deletes_before_busy = Some(0);
    match old_versions_with(&base, &laptop, &config("Personal")) {
        Err(PassError::Network(m)) => assert!(crate::core_message_is(m, "gdrive.busy".into())),
        other => panic!("{other:?}"),
    }
    assert_eq!(revisions_of(&drive).len(), 3);

    // Later, the rest goes.
    drive.lock().unwrap().deletes_before_busy = None;
    let rest = old_versions_with(&base, &laptop, &config("Personal")).unwrap();
    assert_eq!(rest.removed, 2);
    assert_eq!(revisions_of(&drive).len(), 1);
}

#[test]
fn an_expired_sign_in_deletes_nothing() {
    let (drive, base) = setup();
    let laptop = vault_with_old_versions(&base);
    drive.lock().unwrap().expired = true;
    assert!(matches!(
        old_versions_with(&base, &laptop, &config("Personal")),
        Err(PassError::AuthRequired(_))
    ));
    assert!(matches!(
        remove_with(&base, TOKEN, &laptop.vault_id()),
        Err(PassError::AuthRequired(_))
    ));
    drive.lock().unwrap().expired = false;
    assert_eq!(revisions_of(&drive).len(), 4);
}

#[test]
fn removing_a_vault_deletes_only_its_files_and_stops_other_devices() {
    let (drive, base) = setup();
    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    laptop.upsert(item("A")).unwrap();
    sync_with(&base, &laptop, &config("Personal")).unwrap();
    let phone = restore(&base, "phone");
    sync_with(&base, &phone, &config("Personal")).unwrap();
    // Another vault in the same app folder, and a twin of this one (two devices created it at once).
    let work = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    sync_with(&base, &work, &config("Work")).unwrap();
    let id = laptop.vault_id();
    let twin = drive.lock().unwrap().insert(
        &file_name(&id),
        laptop.serialize().unwrap(),
        props(&id, "Personal"),
    );
    log(&drive);

    assert_eq!(remove_with(&base, TOKEN, &id).unwrap(), 2);
    // One listing of the app folder, the marker, then this vault's two files.
    assert_eq!(
        methods(&drive),
        ["GET list", "POST list", "DELETE file", "DELETE file"]
    );
    {
        let d = drive.lock().unwrap();
        assert!(!d.files.contains_key(&twin));
        let names: Vec<&str> = d.files.values().map(|f| f.name.as_str()).collect();
        assert_eq!(names.len(), 2, "{names:?}");
        assert!(names.contains(&file_name(&work.vault_id()).as_str()));
        let marker = d
            .files
            .values()
            .find(|f| f.name == format!("pass-{id}.removed"))
            .unwrap();
        assert!(marker.content.is_empty());
        assert_eq!(marker.props[PROP_REMOVED], id);
    }
    // "Restore from Google Drive" lists only the other vault; the marker isn't a vault.
    let listed = list_with(&base, TOKEN).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].vault_id, work.vault_id());
    // The local copies stay.
    assert_eq!(titles(&laptop), ["A"]);

    // The phone, still syncing it, stops instead of uploading it again, and keeps its copy.
    log(&drive);
    match sync_with(&base, &phone, &config("Personal")) {
        Err(PassError::NotFound(m)) => {
            assert!(crate::core_message_is(m, "gdrive.vault_removed".into()))
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(methods(&drive), ["GET file", "GET list"]);
    assert_eq!(titles(&phone), ["A"]);
    assert_eq!(list_with(&base, TOKEN).unwrap().len(), 1);

    // Removing again: nothing to delete, no second marker.
    log(&drive);
    assert_eq!(remove_with(&base, TOKEN, &id).unwrap(), 0);
    assert_eq!(methods(&drive), ["GET list"]);

    // Backed up again on purpose: the marker goes, the file comes back, other devices resume.
    let again = GDriveConfig {
        start_again: true,
        ..config("Personal")
    };
    assert!(sync_with(&base, &phone, &again).unwrap().created_remote);
    assert!(!drive
        .lock()
        .unwrap()
        .files
        .values()
        .any(|f| f.name.ends_with(".removed")));
    assert_eq!(list_with(&base, TOKEN).unwrap().len(), 2);
    sync_with(&base, &laptop, &config("Personal")).unwrap();
}

#[test]
fn removing_never_lists_or_deletes_with_a_made_up_vault_id() {
    let (drive, base) = setup();
    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    sync_with(&base, &laptop, &config("")).unwrap();
    log(&drive);
    for bad in ["", "  ", "x' or name contains 'pass", "../other", "*"] {
        assert!(remove_with(&base, TOKEN, bad).is_err(), "{bad:?}");
    }
    assert!(methods(&drive).is_empty());
    assert_eq!(drive.lock().unwrap().files.len(), 1);
}

#[test]
fn refused_tokens_are_auth_required() {
    let (drive, base) = setup();
    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    drive.lock().unwrap().expired = true;
    assert!(matches!(
        sync_with(&base, &laptop, &config("")),
        Err(PassError::AuthRequired(_))
    ));
    assert!(matches!(
        list_with(&base, TOKEN),
        Err(PassError::AuthRequired(_))
    ));
    {
        let mut d = drive.lock().unwrap();
        d.expired = false;
        d.scope_denied = true;
    }
    assert!(matches!(
        sync_with(&base, &laptop, &config("")),
        Err(PassError::AuthRequired(_))
    ));
    drive.lock().unwrap().scope_denied = false;
    let wrong = GDriveConfig {
        access_token: "ya29.someone-else".into(),
        vault_name: String::new(),
        start_again: false,
    };
    assert!(matches!(
        sync_with(&base, &laptop, &wrong),
        Err(PassError::AuthRequired(_))
    ));
    log(&drive);
    let empty = GDriveConfig::default();
    assert!(matches!(
        sync_with(&base, &laptop, &empty),
        Err(PassError::AuthRequired(_))
    ));
    assert!(log(&drive).is_empty());
}

#[test]
fn list_rename_account_and_big_files() {
    let (drive, mut base) = setup();
    let work = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    let home = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    sync_with(&base, &work, &config("Work")).unwrap();
    sync_with(&base, &home, &config("")).unwrap();
    drive
        .lock()
        .unwrap()
        .insert("notes.txt", b"hi".to_vec(), HashMap::new());
    let vaults = list_with(&base, TOKEN).unwrap();
    assert_eq!(vaults.len(), 2);
    let names: HashMap<String, String> = vaults
        .iter()
        .map(|v| (v.vault_id.clone(), v.name.clone()))
        .collect();
    assert_eq!(names[&work.vault_id()], "Work");
    assert_eq!(names[&home.vault_id()], "");
    assert!(vaults
        .iter()
        .all(|v| v.modified == 1_791_549_296_789 && v.size > 0));

    // Renamed on this device: one metadata PATCH, and no download afterwards (same MD5).
    log(&drive);
    sync_with(&base, &work, &config("Work (old)")).unwrap();
    assert_eq!(methods(&drive), ["GET file", "PATCH file"]);
    sync_with(&base, &work, &config("Work (old)")).unwrap();
    assert_eq!(methods(&drive), ["GET file"]);
    // Renamed by another device: the version moves but the contents don't; no download.
    let other = restore_one(&base, &work.vault_id());
    sync_with(&base, &other, &config("Work")).unwrap();
    log(&drive);
    sync_with(&base, &work, &config("")).unwrap();
    assert_eq!(methods(&drive), ["GET file"]);

    let account = account_with(&base, TOKEN).unwrap();
    assert_eq!(account.email, "alice@example.com");

    // Above the simple-upload limit: a resumable session (start + PUT), for create and update.
    base.simple_upload_limit = 16;
    let big = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    big.upsert(item("big")).unwrap();
    log(&drive);
    sync_with(&base, &big, &config("Big")).unwrap();
    assert_eq!(
        methods(&drive),
        ["GET list", "POST upload", "PUT file", "GET list"]
    );
    big.upsert(item("bigger")).unwrap();
    sync_with(&base, &big, &config("Big")).unwrap();
    assert_eq!(
        methods(&drive),
        [
            "GET file",
            "PATCH upload",
            "PUT file",
            "GET revisions",
            "PATCH revision"
        ]
    );
    let restored = Vault::unlock(
        download_with(
            &base,
            TOKEN,
            &list_with(&base, TOKEN)
                .unwrap()
                .into_iter()
                .find(|v| v.vault_id == big.vault_id())
                .unwrap()
                .file_id,
        )
        .unwrap(),
        "pw".into(),
        "x".into(),
    )
    .unwrap();
    assert_eq!(titles(&restored), ["big", "bigger"]);
    assert!(matches!(
        download_with(&base, TOKEN, "nope"),
        Err(PassError::NotFound(_))
    ));
}

fn restore_one(base: &Endpoints, vault_id: &str) -> Arc<Vault> {
    let v = list_with(base, TOKEN)
        .unwrap()
        .into_iter()
        .find(|v| v.vault_id == vault_id)
        .unwrap();
    Vault::unlock(
        download_with(base, TOKEN, &v.file_id).unwrap(),
        "pw".into(),
        "other".into(),
    )
    .unwrap()
}

#[test]
fn young_files_are_looked_up_by_name_less_often_after_their_first_hour() {
    const MIN: i64 = 60 * 1000;
    let now = 1_800_000_000_000;
    // First hour: every sync, whenever the last lookup was.
    assert!(twin_lookup_due(0, Some(now), now));
    assert!(twin_lookup_due(59 * MIN, Some(now - 1000), now));
    // Then at most every 10 minutes per file and process.
    assert!(twin_lookup_due(2 * 60 * MIN, None, now));
    assert!(!twin_lookup_due(2 * 60 * MIN, Some(now - 20 * 1000), now));
    assert!(!twin_lookup_due(2 * 60 * MIN, Some(now - 9 * MIN), now));
    assert!(twin_lookup_due(2 * 60 * MIN, Some(now - 10 * MIN), now));
    // A week old: never (only a known twin makes a sync look again).
    assert!(!twin_lookup_due(YOUNG_FILE_MS, None, now));
    // A creation time ahead of this device's clock is a brand-new file.
    let file = DriveFile {
        created_time: Some("2099-01-01T00:00:00.000Z".into()),
        ..DriveFile::default()
    };
    assert_eq!(file.age_ms(now), Some(0));
    assert_eq!(DriveFile::default().age_ms(now), None);
}

#[test]
fn an_unchanged_young_file_costs_one_request_between_lookups() {
    let (drive, base) = setup();
    // Created two hours ago: young, but past its first hour.
    let two_hours_ago = crate::clock::now_ms() - 2 * 60 * 60 * 1000;
    let created = {
        let secs = two_hours_ago / 1000;
        let days = secs.div_euclid(86_400);
        let rem = secs.rem_euclid(86_400);
        // Civil from days (Howard Hinnant), for an RFC 3339 timestamp.
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = yoe + era * 400 + i64::from(m <= 2);
        format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z",
            rem / 3600,
            rem % 3600 / 60,
            rem % 60
        )
    };
    assert!((rfc3339_ms(&created) - two_hours_ago).abs() < 1000);
    {
        let mut d = drive.lock().unwrap();
        d.created = Some(created);
        // The lookups are remembered per file id for the whole process: an id no other test uses.
        d.next_id = 9_000;
    }
    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    laptop.upsert(item("L")).unwrap();
    sync_with(&base, &laptop, &config("")).unwrap();
    // The first check of this file in this process looks it up by name; the next ones don't.
    log(&drive);
    sync_with(&base, &laptop, &config("")).unwrap();
    sync_with(&base, &laptop, &config("")).unwrap();
    let m = methods(&drive);
    assert_eq!(m.iter().filter(|m| *m == "GET list").count(), 1, "{m:?}");
    assert_eq!(m.iter().filter(|m| *m == "GET file").count(), 2, "{m:?}");
}

#[test]
fn timestamps_and_debug() {
    assert_eq!(rfc3339_ms("1970-01-01T00:00:00Z"), 0);
    assert_eq!(rfc3339_ms("2026-10-09T12:34:56.789Z"), 1_791_549_296_789);
    assert_eq!(
        rfc3339_ms("2026-10-09T14:34:56.789+02:00"),
        1_791_549_296_789
    );
    assert_eq!(rfc3339_ms("2000-02-29T00:00:00.5Z"), 951_782_400_500);
    assert_eq!(rfc3339_ms("garbage"), 0);
    // Out-of-range numbers: 0, not an arithmetic overflow.
    assert_eq!(rfc3339_ms("9223372036854775807-01-01T00:00:00Z"), 0);
    assert_eq!(rfc3339_ms("2026-10-09T12:34:56+9223372036854775807:00"), 0);
    assert_eq!(rfc3339_ms("2026-10-09T9223372036854775807:00:00Z"), 0);
    let shown = format!("{:?}", config("Work"));
    assert!(!shown.contains(TOKEN) && !shown.contains("Work"), "{shown}");
}

/// Drives an exchange the way the browser extension does (here with ureq instead of `fetch`).
fn drive_exchange<T: std::fmt::Debug + 'static>(
    mut exchange: Exchange<T>,
    mut step: Step<T>,
) -> Result<T> {
    let http = blocking::UreqTransport::new();
    loop {
        match step {
            Step::Done(out) => {
                assert!(exchange.is_done());
                return out;
            }
            Step::Send(request) => {
                step = match http.send_now(request, "test") {
                    Ok(response) => exchange.on_response(response),
                    Err(_) => exchange.on_failure(crate::http::FetchFailure::Unreachable),
                };
            }
        }
    }
}

#[test]
fn the_extension_drives_the_same_sync_request_by_request() {
    let (drive, base) = setup();
    // The browser creates the vault and its file in Drive, exactly as the apps would.
    let browser = Vault::create_with_kdf("pw", "chrome", fast_kdf()).unwrap();
    browser.upsert(item("B")).unwrap();
    let (exchange, first) = sync_exchange_with(base.clone(), browser.clone(), config("Personal"));
    let created = drive_exchange(exchange, first).unwrap();
    assert!(created.created_remote && created.uploaded);
    assert_eq!(methods(&drive), ["GET list", "POST upload", "GET list"]);

    let (exchange, first) = sync_exchange_with(base.clone(), browser.clone(), config("Personal"));
    let idle = drive_exchange(exchange, first).unwrap();
    assert!(!idle.uploaded);
    assert_eq!(methods(&drive), ["GET file"]);

    let (exchange, first) = list_exchange_with(base.clone(), TOKEN.into());
    let vaults = drive_exchange(exchange, first).unwrap();
    assert_eq!(vaults.len(), 1);
    assert_eq!(vaults[0].name, "Personal");
    let (exchange, first) =
        download_exchange_with(base.clone(), TOKEN.into(), vaults[0].file_id.clone());
    let bytes = drive_exchange(exchange, first).unwrap();

    // A phone (the apps' blocking sync) edits it; the browser merges, and both converge.
    let phone = Vault::unlock(bytes, "pw".into(), "phone".into()).unwrap();
    phone.upsert(item("P")).unwrap();
    sync_with(&base, &phone, &config("Personal")).unwrap();
    browser.upsert(item("B2")).unwrap();
    log(&drive);
    let (exchange, first) = sync_exchange_with(base.clone(), browser.clone(), config("Personal"));
    let merged = drive_exchange(exchange, first).unwrap();
    assert_eq!(merged.stats.added, 1);
    assert!(merged.uploaded);
    assert_eq!(
        methods(&drive),
        [
            "GET file",
            "GET file",
            "GET revisions",
            "GET file",
            "PATCH upload",
            "GET revisions",
            "PATCH revision"
        ]
    );
    sync_with(&base, &phone, &config("Personal")).unwrap();
    assert_eq!(titles(&browser), ["B", "B2", "P"]);
    assert_eq!(titles(&phone), ["B", "B2", "P"]);

    // A refused token and no connection end the exchange with the same errors as the apps get.
    drive.lock().unwrap().expired = true;
    let (exchange, first) = sync_exchange_with(base.clone(), browser.clone(), config(""));
    assert!(matches!(
        drive_exchange(exchange, first),
        Err(PassError::AuthRequired(_))
    ));
    drive.lock().unwrap().expired = false;
    let (mut exchange, first) = sync_exchange_with(base.clone(), browser.clone(), config(""));
    assert!(matches!(first, Step::Send(_)));
    match exchange.on_failure(crate::http::FetchFailure::Unreachable) {
        Step::Done(Err(PassError::Network(message))) => {
            assert!(message.contains("127.0.0.1"), "{message}")
        }
        other => panic!("{other:?}"),
    }
    log(&drive);
    let (exchange, first) = sync_exchange_with(base, browser, GDriveConfig::default());
    assert!(exchange.is_done());
    assert!(matches!(first, Step::Done(Err(PassError::AuthRequired(_)))));
    assert!(log(&drive).is_empty());
}

/// Nothing leaves a device for Google Drive unencrypted. Three devices (two apps and a browser
/// driving the exchange) fill a vault with every item kind, every field a canary, vault settings,
/// the user's keyset, a recovery code, a password history and usage, under a vault name that is a
/// canary too, and sync it back and forth. Every request the fake Drive got and every file and
/// revision it holds are then searched for the canaries in every encoding the scanner knows.
#[test]
fn google_drive_never_sees_a_vault_secret() {
    let (drive, base) = setup();
    let mut needles = leak::Needles::new();
    let name = leak::canary("laptop", "vaultname");
    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    leak::fill(&laptop, "laptop");
    leak::fill_settings(&laptop, "laptop");
    laptop.ensure_user_keyset("acc_canary").unwrap();
    needles.add_secret("recovery code", &laptop.create_recovery_code().unwrap());
    // The scanner finds the canaries in the items as they are before encryption.
    let mut plain = std::collections::BTreeSet::new();
    needles.scan(
        "items",
        &serde_json::to_vec(&laptop.items()).unwrap(),
        &mut plain,
    );
    assert!(plain.iter().any(|h| h.needle == "canary"), "{plain:?}");

    sync_with(&base, &laptop, &config(&name)).unwrap();
    let phone = restore(&base, "phone");
    leak::fill(&phone, "phone");
    sync_with(&base, &phone, &config(&name)).unwrap();
    sync_with(&base, &laptop, &config(&name)).unwrap();
    let browser = restore(&base, "browser");
    leak::fill(&browser, "browser");
    let (exchange, first) = sync_exchange_with(base.clone(), browser.clone(), config(&name));
    assert!(drive_exchange(exchange, first).unwrap().uploaded);
    sync_with(&base, &laptop, &config(&name)).unwrap();
    let merged = sync_with(&base, &phone, &config(&name)).unwrap();
    assert!(merged.stats.added > 0, "{merged:?}");
    assert_eq!(phone.items().len(), laptop.items().len());

    // What a device says when something fails, and its debug output, name no secret either.
    let mut said = vec![format!("{:?}", config(&name))];
    drive.lock().unwrap().expired = true;
    let refused = sync_with(&base, &laptop, &config(&name)).unwrap_err();
    said.push(format!("{refused} {refused:?}"));
    drive.lock().unwrap().expired = false;
    let (_, file) = drive.lock().unwrap().only_file();
    let wrong = Vault::unlock(file.content.clone(), "not pw".into(), "x".into()).unwrap_err();
    said.push(format!("{wrong} {wrong:?}"));

    // The one cleartext value allowed on Drive: the vault's name, so a new device can list vaults
    // before unlock. It is cut out of the requests and the file's properties before the scan,
    // asserted explicitly, and must not be anywhere else.
    let d = drive.lock().unwrap();
    let allowed = name.as_bytes();
    let without_name = |bytes: &[u8]| -> Vec<u8> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i..].starts_with(allowed) {
                i += allowed.len();
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        out
    };
    let mut captured: Vec<(String, Vec<u8>)> = Vec::new();
    let mut name_sent = false;
    for (url, raw) in &d.raw {
        leak::assert_https_or_local(url);
        name_sent |= raw.windows(allowed.len()).any(|w| w == allowed);
        captured.push((format!("request {url}"), without_name(raw)));
    }
    assert!(name_sent, "the vault's name is sent to Drive as the file's property");
    for (id, f) in &d.files {
        assert_eq!(
            f.props.get(PROP_NAME).map(String::as_str),
            Some(name.as_str()),
            "{:?}",
            f.props
        );
        assert_eq!(f.props.len(), 2, "the id and the name only: {:?}", f.props);
        assert!(
            !f.content.windows(allowed.len()).any(|w| w == allowed),
            "the vault's name is inside the file's bytes in the clear"
        );
        captured.push((
            format!("props of {id}"),
            without_name(&serde_json::to_vec(&f.props).unwrap()),
        ));
        leak::assert_no_local_fields(&format!("file {id}"), &f.content);
        captured.push((format!("file {id}"), f.content.clone()));
        for r in &f.revisions {
            leak::assert_no_local_fields(&format!("revision {}", r.id), &r.content);
            captured.push((format!("revision {}", r.id), r.content.clone()));
        }
    }
    for (i, text) in said.into_iter().enumerate() {
        captured.push((format!("message {i}"), text.into_bytes()));
    }
    assert!(captured.len() > 20, "{}", captured.len());
    leak::assert_no_canary(&needles, &captured);
}
