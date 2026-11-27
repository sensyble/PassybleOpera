//! Sync against a tiny in-process WebDAV-ish server that honours ETag preconditions, and counts
//! the requests a sync makes.
#![cfg(feature = "webdav")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use pass_core::*;

#[derive(Default)]
struct Store {
    body: Option<Vec<u8>>,
    version: u64,
    puts: u32,
    /// Answer `If-None-Match` on GET with 304 and send `ETag` on PUT, like Nextcloud and Pass
    /// Server. Off: a plain server that ignores both.
    conditional: bool,
    /// Send weak ETags (`W/"vN"`), and reject `If-Match` with them (strong comparison, RFC 9110),
    /// like many proxies and servers.
    weak: bool,
    /// (method, status, response body length) of every request.
    log: Vec<(String, u16, usize)>,
    /// Another device's upload that lands just before the next PUT (a lost race).
    race: Option<Vec<u8>>,
    /// Answer every PUT with this status, `Content-Type` and body instead of storing.
    reject: Option<(u16, &'static str, Vec<u8>)>,
    /// Handle the next PUT, then close the connection without answering (a timeout or a dropped
    /// connection after the server stored the upload).
    lose_put_answer: bool,
}

impl Store {
    fn take_log(&mut self) -> Vec<(String, u16, usize)> {
        std::mem::take(&mut self.log)
    }
}

fn serve(store: Arc<Mutex<Store>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let method = request_line
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string();
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
            assert_eq!(
                header("authorization").as_deref(),
                Some("Basic bWU6c2VjcmV0")
            ); // me:secret
            let mut body = vec![0; header("content-length").map_or(0, |l| l.parse().unwrap())];
            reader.read_exact(&mut body).unwrap();

            let mut store = store.lock().unwrap();
            let weak = store.weak;
            let tag = move |version: u64| {
                let prefix = if weak { "W/" } else { "" };
                format!("{prefix}\"v{version}\"")
            };
            let etag = tag(store.version);
            let (status, extra, payload) = match method.as_str() {
                "GET" => match &store.body {
                    Some(_)
                        if store.conditional
                            && header("if-none-match").as_deref() == Some(etag.as_str()) =>
                    {
                        (304, format!("ETag: {etag}\r\n"), Vec::new())
                    }
                    Some(b) => (200, format!("ETag: {etag}\r\n"), b.clone()),
                    None => (404, String::new(), Vec::new()),
                },
                "PUT" if store.reject.is_some() => {
                    let (status, content_type, payload) = store.reject.clone().unwrap();
                    (status, format!("Content-Type: {content_type}\r\n"), payload)
                }
                "PUT" => {
                    if let Some(other) = store.race.take() {
                        store.body = Some(other);
                        store.version += 1;
                    }
                    let etag = tag(store.version);
                    let ok = match (header("if-match"), header("if-none-match")) {
                        (Some(m), _) => store.body.is_some() && m == etag && !m.starts_with("W/"),
                        (_, Some(_)) => store.body.is_none(),
                        _ => true,
                    };
                    if ok {
                        store.body = Some(body);
                        store.version += 1;
                        store.puts += 1;
                        let extra = if store.conditional {
                            format!("ETag: {}\r\n", tag(store.version))
                        } else {
                            String::new()
                        };
                        (201, extra, Vec::new())
                    } else {
                        (412, String::new(), Vec::new())
                    }
                }
                _ => (405, String::new(), Vec::new()),
            };
            store.log.push((method.clone(), status, payload.len()));
            if method == "PUT" && std::mem::take(&mut store.lose_put_answer) {
                continue; // drops the connection unanswered
            }
            let reason = match status {
                200 => "OK",
                201 => "Created",
                304 => "Not Modified",
                404 => "Not Found",
                412 => "Precondition Failed",
                507 => "Insufficient Storage",
                _ => "Method Not Allowed",
            };
            // A 304 has no body and no Content-Length (RFC 9110, section 15.4.5).
            let length = if status == 304 {
                String::new()
            } else {
                format!("Content-Length: {}\r\n", payload.len())
            };
            write!(
                stream,
                "HTTP/1.1 {status} {reason}\r\n{extra}{length}Connection: close\r\n\r\n"
            )
            .unwrap();
            stream.write_all(&payload).unwrap();
        }
    });
    format!("http://{addr}/pass.vault")
}

fn fast_kdf() -> KdfParams {
    KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
        ..Default::default()
    }
}

fn setup(conditional: bool) -> (Arc<Mutex<Store>>, WebDavConfig) {
    setup_with(conditional, false)
}

fn setup_with(conditional: bool, weak: bool) -> (Arc<Mutex<Store>>, WebDavConfig) {
    let store = Arc::new(Mutex::new(Store {
        conditional,
        weak,
        ..Default::default()
    }));
    let config = WebDavConfig {
        url: serve(store.clone()),
        username: "me".into(),
        password: "secret".into(),
        pins: Vec::new(),
    };
    (store, config)
}

fn item(title: &str) -> Item {
    Item {
        title: title.into(),
        ..Default::default()
    }
}

fn requests(store: &Arc<Mutex<Store>>) -> Vec<(String, u16)> {
    store
        .lock()
        .unwrap()
        .take_log()
        .into_iter()
        .map(|(m, s, _)| (m, s))
        .collect()
}

fn req(method: &str, status: u16) -> (String, u16) {
    (method.to_string(), status)
}

#[test]
fn two_devices_converge_through_webdav() {
    // A plain server: no 304s and no ETag on PUT.
    let (store, config) = setup(false);

    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    laptop
        .upsert(Item {
            title: "A".into(),
            urls: vec!["a.com".into()],
            ..Default::default()
        })
        .unwrap();
    let first = webdav_sync(laptop.clone(), config.clone()).unwrap();
    assert!(first.uploaded && first.created_remote);
    assert!(
        laptop.is_dirty(),
        "sync must not hide unsaved local changes"
    );

    let phone = Vault::unlock(
        webdav_download(config.clone()).unwrap(),
        "pw".into(),
        "phone".into(),
    )
    .unwrap();
    assert_eq!(phone.items().len(), 1);
    phone.upsert(item("B")).unwrap();
    let r = webdav_sync(phone.clone(), config.clone()).unwrap();
    assert!(r.uploaded && !r.created_remote);

    let r = webdav_sync(laptop.clone(), config.clone()).unwrap();
    assert_eq!(r.stats.added, 1);
    assert!(!r.uploaded, "nothing new on the laptop");
    assert_eq!(laptop.items(), phone.items());

    // Nothing changed anywhere: one download, recognised as already merged; no upload.
    requests(&store);
    let r = webdav_sync(phone.clone(), config.clone()).unwrap();
    assert!(!r.uploaded);
    assert_eq!(r.stats, MergeStats::default());
    assert_eq!(requests(&store), [req("GET", 200)]);

    // A local edit: download + upload (unconditional: the server sends no ETags on PUT here, but
    // the GET's ETag is used for If-Match).
    phone.upsert(item("C")).unwrap();
    webdav_sync(phone.clone(), config.clone()).unwrap();
    assert_eq!(requests(&store), [req("GET", 200), req("PUT", 201)]);
}

#[test]
fn sync_reports_the_size_of_the_remote_copy() {
    let (store, config) = setup(true);
    let stored =
        |store: &Arc<Mutex<Store>>| store.lock().unwrap().body.as_ref().map(|b| b.len() as u64);
    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    laptop.upsert(item("A")).unwrap();

    // Uploaded: the bytes that were sent.
    let r = webdav_sync(laptop.clone(), config.clone()).unwrap();
    assert!(r.uploaded);
    assert!(r.remote_bytes.is_some_and(|n| n > 0));
    assert_eq!(r.remote_bytes, stored(&store));

    // A 304 sends no body but the size recorded by the last transfer still comes back.
    let r = webdav_sync(laptop.clone(), config.clone()).unwrap();
    assert!(!r.uploaded);
    assert_eq!(r.remote_bytes, stored(&store));

    // A local edit grows the file: the new upload's size.
    laptop.upsert(item("B")).unwrap();
    let r = webdav_sync(laptop.clone(), config.clone()).unwrap();
    assert!(r.uploaded);
    assert_eq!(r.remote_bytes, stored(&store));

    // Another device downloads it: the downloaded bytes.
    let phone = Vault::unlock(
        webdav_download(config.clone()).unwrap(),
        "pw".into(),
        "phone".into(),
    )
    .unwrap();
    let r = webdav_sync(phone.clone(), config.clone()).unwrap();
    assert_eq!(r.remote_bytes, stored(&store));
}

#[test]
fn unchanged_vault_costs_one_304() {
    let (store, config) = setup(true);
    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    laptop.upsert(item("A")).unwrap();
    assert!(laptop.sync_pending(), "never synced");

    let r = webdav_sync(laptop.clone(), config.clone()).unwrap();
    assert!(r.uploaded && r.created_remote);
    assert_eq!(requests(&store), [req("GET", 404), req("PUT", 201)]);
    assert!(!laptop.sync_pending());

    // Unchanged and clean: exactly one request, a 304 with no body.
    let r = webdav_sync(laptop.clone(), config.clone()).unwrap();
    assert!(!r.uploaded);
    assert_eq!(store.lock().unwrap().take_log(), [("GET".into(), 304, 0)]);

    // A local edit: 304 + PUT (If-Match the known ETag).
    let rev = laptop.revision();
    laptop.upsert(item("B")).unwrap();
    assert!(laptop.revision() != rev);
    assert!(laptop.sync_pending());
    let r = webdav_sync(laptop.clone(), config.clone()).unwrap();
    assert!(r.uploaded && !r.created_remote);
    assert_eq!(requests(&store), [req("GET", 304), req("PUT", 201)]);
    assert!(!laptop.sync_pending());

    // The state survives a restart: it is saved in the local file (and not uploaded).
    let local = laptop.serialize().unwrap();
    let uploaded = store.lock().unwrap().body.clone().unwrap();
    let has_sync = |bytes: &[u8]| {
        serde_json::from_slice::<serde_json::Value>(bytes)
            .unwrap()
            .get("sync")
            .is_some()
    };
    assert!(has_sync(&local));
    assert!(
        !has_sync(&uploaded),
        "local sync state must not be uploaded"
    );
    let laptop = Vault::unlock(local, "pw".into(), "laptop".into()).unwrap();
    assert!(!laptop.sync_pending());
    webdav_sync(laptop.clone(), config.clone()).unwrap();
    assert_eq!(requests(&store), [req("GET", 304)]);

    // A remote change: 200 + merge, no upload when there is nothing new here.
    let phone = Vault::unlock(uploaded, "pw".into(), "phone".into()).unwrap();
    assert!(
        phone.sync_pending(),
        "a downloaded copy has no sync state yet"
    );
    phone.upsert(item("C")).unwrap();
    webdav_sync(phone.clone(), config.clone()).unwrap();
    requests(&store);
    let r = webdav_sync(laptop.clone(), config.clone()).unwrap();
    assert_eq!(r.stats.added, 1);
    assert!(!r.uploaded);
    assert_eq!(requests(&store), [req("GET", 200)]);
    assert!(!laptop.sync_pending());
    // ... and the next check is a 304 again.
    webdav_sync(laptop.clone(), config.clone()).unwrap();
    assert_eq!(requests(&store), [req("GET", 304)]);

    // A remote change and a local one: 200 + merge + PUT.
    phone.upsert(item("D")).unwrap();
    webdav_sync(phone.clone(), config.clone()).unwrap();
    laptop.upsert(item("E")).unwrap();
    requests(&store);
    let r = webdav_sync(laptop.clone(), config.clone()).unwrap();
    assert!(r.uploaded && r.stats.added == 1);
    assert_eq!(requests(&store), [req("GET", 200), req("PUT", 201)]);

    webdav_sync(phone.clone(), config.clone()).unwrap();
    assert_eq!(laptop.items(), phone.items());

    // A different URL (another account) starts from scratch: a full download.
    let other = WebDavConfig {
        url: format!("{}?other", config.url),
        ..config.clone()
    };
    requests(&store);
    webdav_sync(laptop.clone(), other).unwrap();
    assert_eq!(requests(&store), [req("GET", 200)]);
}

#[test]
fn lost_race_after_304_retries() {
    let (store, config) = setup(true);
    let a = Vault::create_with_kdf("pw", "a", fast_kdf()).unwrap();
    webdav_sync(a.clone(), config.clone()).unwrap();
    let b = Vault::unlock(
        store.lock().unwrap().body.clone().unwrap(),
        "pw".into(),
        "b".into(),
    )
    .unwrap();
    webdav_sync(b.clone(), config.clone()).unwrap();

    // B's upload lands between A's 304 and A's PUT: 412, then a full download, merge, upload.
    b.upsert(item("from b")).unwrap();
    let (b_bytes, _) = (b.serialize().unwrap(), ());
    store.lock().unwrap().race = Some(b_bytes);
    a.upsert(item("from a")).unwrap();
    requests(&store);
    let r = webdav_sync(a.clone(), config.clone()).unwrap();
    assert!(r.uploaded && r.stats.added == 1);
    assert_eq!(
        requests(&store),
        [
            req("GET", 304),
            req("PUT", 412),
            req("GET", 200),
            req("PUT", 201)
        ]
    );
    assert!(!a.sync_pending());

    let r = webdav_sync(b.clone(), config.clone()).unwrap();
    assert!(!r.uploaded && r.stats.added == 1);
    assert_eq!(a.items(), b.items());

    // An ETag change without a content change (e.g. a server restore of the same bytes): one
    // download, recognised as already merged, nothing uploaded.
    store.lock().unwrap().version += 100;
    requests(&store);
    let r = webdav_sync(a.clone(), config.clone()).unwrap();
    assert!(!r.uploaded && r.stats == MergeStats::default());
    assert_eq!(requests(&store), [req("GET", 200)]);
    webdav_sync(a.clone(), config.clone()).unwrap();
    assert_eq!(requests(&store), [req("GET", 304)]);
}

#[test]
fn a_forged_tombstone_on_the_server_is_ignored_and_repaired() {
    // The server (or anyone who can write the file) marks an item deleted in the cleartext
    // metadata. Devices must keep the item and put it back on the server.
    let (store, config) = setup(true);
    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    let bank = laptop.upsert(item("Bank")).unwrap();
    webdav_sync(laptop.clone(), config.clone()).unwrap();

    {
        let mut store = store.lock().unwrap();
        let mut json: serde_json::Value =
            serde_json::from_slice(store.body.as_ref().unwrap()).unwrap();
        let record = json["items"][0].as_object_mut().unwrap();
        record.insert("deleted".into(), true.into());
        record.insert("updated_at".into(), (i64::MAX / 2).into());
        record.remove("nonce");
        record.remove("ct");
        store.body = Some(serde_json::to_vec(&json).unwrap());
        store.version += 1;
    }
    let r = webdav_sync(laptop.clone(), config.clone()).unwrap();
    assert_eq!(r.stats.deleted, 0);
    assert!(r.uploaded, "the device's version replaces the forged one");
    assert!(laptop.get(bank.id.clone()).is_some());

    let phone = Vault::unlock(
        webdav_download(config).unwrap(),
        "pw".into(),
        "phone".into(),
    )
    .unwrap();
    assert!(phone.get(bank.id).is_some());
}

#[test]
fn weak_etags_do_not_make_sync_fail() {
    // Every ETag is weak and If-Match is a strong comparison, so no conditional PUT can succeed.
    let (store, config) = setup_with(true, true);
    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    laptop.upsert(item("A")).unwrap();
    // Creating uses If-None-Match: *, which is unaffected.
    let r = webdav_sync(laptop.clone(), config.clone()).unwrap();
    assert!(r.uploaded && r.created_remote);

    let phone = Vault::unlock(
        webdav_download(config.clone()).unwrap(),
        "pw".into(),
        "phone".into(),
    )
    .unwrap();
    phone.upsert(item("B")).unwrap();
    requests(&store);
    // Weak If-Match tried once (412), then download + merge, then an unconditional PUT.
    let r = webdav_sync(phone.clone(), config.clone()).unwrap();
    assert!(r.uploaded && !r.created_remote);
    assert_eq!(
        requests(&store),
        [
            req("GET", 200),
            req("PUT", 412),
            req("GET", 200),
            req("PUT", 201)
        ]
    );

    // The laptop (304-path, weak known ETag) works the same way, and converges.
    laptop.upsert(item("C")).unwrap();
    let r = webdav_sync(laptop.clone(), config.clone()).unwrap();
    assert!(r.uploaded && r.stats.added == 1);
    let r = webdav_sync(phone.clone(), config.clone()).unwrap();
    assert!(!r.uploaded && r.stats.added == 1);
    assert_eq!(laptop.items(), phone.items());
    assert_eq!(phone.items().len(), 3);

    // Unchanged: still just a cheap 304 (weak comparison is fine for If-None-Match).
    requests(&store);
    webdav_sync(phone.clone(), config.clone()).unwrap();
    assert_eq!(requests(&store), [req("GET", 304)]);
}

#[test]
fn a_quota_rejection_shows_the_servers_message() {
    let (store, config) = setup(true);
    let vault = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    vault.upsert(item("A")).unwrap();
    let sync_error = |vault: &Arc<Vault>| match webdav_sync(vault.clone(), config.clone()) {
        Err(PassError::Network(m)) => m,
        other => panic!("expected a network error, got {other:?}"),
    };

    let message = "this account's storage is full (256 MiB); delete old vaults or ask the admin";
    store.lock().unwrap().reject = Some((
        507,
        "text/plain; charset=utf-8",
        format!("  {message}\n").into_bytes(),
    ));
    assert_eq!(
        sync_error(&vault),
        format!("upload: storage quota reached: {message}")
    );

    // Capped.
    store.lock().unwrap().reject = Some((507, "text/plain", "x".repeat(1000).into_bytes()));
    assert_eq!(
        sync_error(&vault),
        format!("upload: storage quota reached: {}", "x".repeat(300))
    );

    // Not text (wrong type, invalid UTF-8) or empty: no message, never the raw bytes.
    for (content_type, body) in [
        ("text/html", b"<b>full</b>".to_vec()),
        ("text/plain", vec![0xff, 0xfe, b'x']),
        ("text/plain", b" \n".to_vec()),
    ] {
        store.lock().unwrap().reject = Some((507, content_type, body));
        assert_eq!(sync_error(&vault), "upload: storage quota reached");
    }

    // Other statuses are the core's plain words, whatever their body says: never the body or
    // the status code.
    store.lock().unwrap().reject = Some((500, "text/plain", b"database on fire".to_vec()));
    assert_eq!(
        sync_error(&vault),
        "upload: the server has a problem right now. Try again later"
    );
    store.lock().unwrap().reject = Some((403, "text/plain", b"nope".to_vec()));
    assert_eq!(sync_error(&vault), "upload: authentication failed");
}

#[test]
fn usage_rides_along_with_the_next_sync() {
    let (store, config) = setup(true);
    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    let a = laptop.upsert(item("A")).unwrap();
    webdav_sync(laptop.clone(), config.clone()).unwrap();
    let phone = Vault::unlock(
        webdav_download(config.clone()).unwrap(),
        "pw".into(),
        "phone".into(),
    )
    .unwrap();
    webdav_sync(phone.clone(), config.clone()).unwrap();
    requests(&store);

    // A use is no reason to sync...
    laptop.record_use(a.id.clone(), 1_000).unwrap();
    assert!(!laptop.sync_pending());
    assert!(laptop.usage_sync_pending());
    // ...but a sync (for any other reason) uploads it: the 304, then one PUT.
    let r = webdav_sync(laptop.clone(), config.clone()).unwrap();
    assert!(r.uploaded);
    assert_eq!(r.stats, MergeStats::default());
    assert_eq!(requests(&store), [req("GET", 304), req("PUT", 201)]);
    assert!(!laptop.usage_sync_pending() && !laptop.sync_pending());
    webdav_sync(laptop.clone(), config.clone()).unwrap();
    assert_eq!(requests(&store), [req("GET", 304)]);

    // The other device gets the counts, without any item changing.
    let r = webdav_sync(phone.clone(), config.clone()).unwrap();
    assert_eq!(r.stats.added + r.stats.updated + r.stats.deleted, 0);
    assert!(!r.uploaded);
    assert_eq!(phone.usage(a.id.clone()).count, 1);
    assert!(!phone.usage_sync_pending());

    // An older client writes the file back without usage: the next sync puts it back.
    let mut json: serde_json::Value =
        serde_json::from_slice(&webdav_download(config.clone()).unwrap()).unwrap();
    json.as_object_mut().unwrap().remove("usage");
    {
        let mut s = store.lock().unwrap();
        s.body = Some(serde_json::to_vec(&json).unwrap());
        s.version += 1;
    }
    requests(&store);
    let r = webdav_sync(phone.clone(), config.clone()).unwrap();
    assert!(r.uploaded);
    let stored: serde_json::Value =
        serde_json::from_slice(&webdav_download(config.clone()).unwrap()).unwrap();
    assert_eq!(stored["usage"].as_array().map(Vec::len), Some(1));
    assert_eq!(phone.usage(a.id.clone()).count, 1);
}

/// Plain http:// to a public host is refused before anything is sent (the app password would cross
/// the internet unencrypted); a local network address and https:// keep working.
#[test]
fn plain_http_only_to_local_networks() {
    let public = WebDavConfig {
        url: "http://dav.example.org/remote.php/dav/files/me/pass.vault".into(),
        username: "me".into(),
        password: "app-password".into(),
        pins: vec![],
    };
    match webdav_exists(public.clone()) {
        Err(PassError::InvalidInput(m)) => {
            assert!(m.contains("https://dav.example.org"), "{m}");
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        webdav_download(public.clone()),
        Err(PassError::InvalidInput(_))
    ));
    let vault = Vault::create_with_kdf("pw", "phone", fast_kdf()).unwrap();
    assert!(matches!(
        webdav_sync(vault, public),
        Err(PassError::InvalidInput(_))
    ));
    assert!(plain_http_refused(
        "http://dav.example.org/pass.vault".into()
    ));

    // The test server listens on 127.0.0.1: plain http:// is fine there.
    let (_store, local) = setup(true);
    assert!(local.url.starts_with("http://127.0.0.1"));
    assert!(!plain_http_refused(local.url.clone()));
    let laptop = Vault::create_with_kdf("pw", "laptop", fast_kdf()).unwrap();
    assert!(webdav_sync(laptop, local).unwrap().created_remote);
}

fn titles(v: &Vault) -> Vec<String> {
    let mut t: Vec<String> = v.items().into_iter().map(|i| i.title).collect();
    t.sort();
    t
}

fn remote_titles(store: &Arc<Mutex<Store>>) -> Vec<String> {
    let body = store.lock().unwrap().body.clone().unwrap();
    titles(&Vault::unlock(body, "pw".into(), "x".into()).unwrap())
}

#[test]
fn an_upload_whose_answer_was_lost_is_never_repeated_blindly() {
    let (store, config) = setup(true);
    let a = Vault::create_with_kdf("pw", "a", fast_kdf()).unwrap();
    webdav_sync(a.clone(), config.clone()).unwrap();
    let b = Vault::unlock(
        store.lock().unwrap().body.clone().unwrap(),
        "pw".into(),
        "b".into(),
    )
    .unwrap();
    webdav_sync(b.clone(), config.clone()).unwrap();

    // A's upload is stored, but the answer never arrives: the sync fails and A still holds the
    // ETag from before.
    a.upsert(item("a1")).unwrap();
    store.lock().unwrap().lose_put_answer = true;
    assert!(webdav_sync(a.clone(), config.clone()).is_err());
    assert_eq!(remote_titles(&store), ["a1"]);
    b.upsert(item("b1")).unwrap();
    webdav_sync(b.clone(), config.clone()).unwrap();
    a.upsert(item("a2")).unwrap();

    // A's retry sends its old ETag: the server has moved on, so it downloads, merges and uploads
    // against the current ETag. Nothing of B's is overwritten.
    requests(&store);
    let r = webdav_sync(a.clone(), config.clone()).unwrap();
    assert!(r.uploaded && r.stats.added == 1);
    assert_eq!(requests(&store), [req("GET", 200), req("PUT", 201)]);
    assert_eq!(remote_titles(&store), ["a1", "a2", "b1"]);
    webdav_sync(b.clone(), config.clone()).unwrap();
    assert_eq!(titles(&b), ["a1", "a2", "b1"]);
}

#[test]
fn a_lost_answer_on_the_first_upload_is_recognised() {
    let (store, config) = setup(true);
    let a = Vault::create_with_kdf("pw", "a", fast_kdf()).unwrap();
    a.upsert(item("a1")).unwrap();
    store.lock().unwrap().lose_put_answer = true;
    assert!(webdav_sync(a.clone(), config.clone()).is_err());
    // The retry finds its own upload there: a download, nothing to merge or upload.
    requests(&store);
    let r = webdav_sync(a.clone(), config.clone()).unwrap();
    assert!(!r.uploaded && !r.created_remote);
    assert_eq!(requests(&store), [req("GET", 200)]);
    assert!(!a.sync_pending());
}

#[test]
fn two_devices_creating_the_remote_file_at_once_both_keep_their_items() {
    let (store, config) = setup(true);
    let a = Vault::create_with_kdf("pw", "a", fast_kdf()).unwrap();
    let b = Vault::unlock(a.serialize().unwrap(), "pw".into(), "b".into()).unwrap();
    a.upsert(item("from a")).unwrap();
    b.upsert(item("from b")).unwrap();
    // Both saw no file; B's first upload lands just before A's (`If-None-Match: *`).
    store.lock().unwrap().race = Some(b.serialize().unwrap());
    let r = webdav_sync(a.clone(), config.clone()).unwrap();
    assert!(r.uploaded && r.stats.added == 1);
    assert_eq!(
        requests(&store),
        [
            req("GET", 404),
            req("PUT", 412),
            req("GET", 200),
            req("PUT", 201)
        ]
    );
    assert_eq!(remote_titles(&store), ["from a", "from b"]);
}
