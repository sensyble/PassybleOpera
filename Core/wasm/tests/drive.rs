//! [`DriveCall`] against an in-memory fake of the Drive v3 calls: one browser creates a vault, a
//! second one downloads it and adds a login, and the first merges that in. Native only.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::BTreeMap;

use pass_wasm::drive::DriveCall;
use pass_wasm::{BrowserConfig, BrowserHost};
use serde_json::{json, Value};

const PASSWORD: &str = "correct horse battery staple";
const TOKEN: &str = "ya29.test";

#[derive(Default)]
struct FakeDrive {
    files: BTreeMap<String, (Value, Vec<u8>)>,
    log: Vec<String>,
    /// Every URL requested, and every byte sent (URLs, headers, bodies).
    urls: Vec<String>,
    sent: Vec<u8>,
    expired: bool,
}

impl FakeDrive {
    fn meta(&self, id: &str) -> Value {
        let (meta, content) = &self.files[id];
        let mut meta = meta.clone();
        meta["size"] = json!(content.len().to_string());
        meta["md5Checksum"] = json!(format!(
            "{:x}",
            content.len() * 31 + content.iter().map(|b| *b as usize).sum::<usize>()
        ));
        meta
    }

    /// One request: method, URL, headers and body in; status, headers and body out.
    fn answer(
        &mut self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> (u16, Vec<u8>) {
        let (path, query) = url.split_once('?').unwrap_or((url, ""));
        let path = path.trim_start_matches("https://www.googleapis.com");
        self.log.push(format!("{method} {path}"));
        self.urls.push(url.to_string());
        self.sent.extend_from_slice(url.as_bytes());
        for (k, v) in headers {
            self.sent.extend_from_slice(format!("{k}: {v} ").as_bytes());
        }
        self.sent.extend_from_slice(body);
        let auth = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.as_str());
        if self.expired || auth != Some(&format!("Bearer {TOKEN}")) {
            return (
                401,
                br#"{"error":{"code":401,"message":"Invalid Credentials"}}"#.to_vec(),
            );
        }
        let q: BTreeMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        let ok = |v: Value| (200, v.to_string().into_bytes());
        let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        match (method, segments.as_slice()) {
            ("GET", ["drive", "v3", "files"]) => {
                let name = q["q"]
                    .split_once("name = '")
                    .and_then(|(_, r)| r.split_once('\''))
                    .map(|(n, _)| n.to_string());
                let files: Vec<Value> = self
                    .files
                    .iter()
                    .filter(|(_, (m, _))| name.as_deref().is_none_or(|n| m["name"] == n))
                    .map(|(id, _)| self.meta(id))
                    .collect();
                ok(json!({ "files": files }))
            }
            ("GET", ["drive", "v3", "files", id]) => match self.files.get(*id) {
                None => (404, b"{}".to_vec()),
                Some((_, content)) if q.get("alt").map(String::as_str) == Some("media") => {
                    (200, content.clone())
                }
                Some(_) => ok(self.meta(id)),
            },
            ("POST", ["upload", "drive", "v3", "files"]) => {
                // multipart/related: the metadata part, then the media part, each after its headers.
                let parts: Vec<usize> = body
                    .windows(4)
                    .enumerate()
                    .filter(|(_, w)| *w == b"\r\n\r\n")
                    .map(|(i, _)| i + 4)
                    .collect();
                let meta_end = parts[0]
                    + body[parts[0]..]
                        .windows(2)
                        .position(|w| w == b"\r\n")
                        .unwrap();
                let mut meta: Value = serde_json::from_slice(&body[parts[0]..meta_end]).unwrap();
                let second = parts[1];
                let close = body.windows(4).rposition(|w| w == b"\r\n--").unwrap();
                let id = format!("f{}", self.files.len() + 1);
                meta["id"] = json!(id);
                meta["version"] = json!("1");
                meta["createdTime"] = json!(format!("2026-11-08T00:00:0{}Z", self.files.len()));
                meta["modifiedTime"] = json!("2026-11-08T10:00:00Z");
                self.files
                    .insert(id.clone(), (meta, body[second..close].to_vec()));
                ok(self.meta(&id))
            }
            ("PATCH", ["upload", "drive", "v3", "files", id]) => match self.files.get_mut(*id) {
                None => (404, b"{}".to_vec()),
                Some((meta, content)) => {
                    *content = body.to_vec();
                    let v: u64 = meta["version"].as_str().unwrap().parse().unwrap();
                    meta["version"] = json!((v + 1).to_string());
                    let id = id.to_string();
                    ok(self.meta(&id))
                }
            },
            _ => (400, b"unexpected".to_vec()),
        }
    }
}

/// Runs `call` against `drive` as the extension does with `fetch`.
fn run(drive: &mut FakeDrive, mut call: DriveCall) -> (Value, DriveCall) {
    let mut step: Value = serde_json::from_str(&call.begin()).unwrap();
    loop {
        if let Some(done) = step.get("done") {
            return (done.clone(), call);
        }
        let send = &step["send"];
        let headers: Vec<(String, String)> = send["headers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                (
                    p[0].as_str().unwrap().to_string(),
                    p[1].as_str().unwrap().to_string(),
                )
            })
            .collect();
        let body = call.take_body().unwrap_or_default();
        let (status, answer) = drive.answer(
            send["method"].as_str().unwrap(),
            send["url"].as_str().unwrap(),
            &headers,
            &body,
        );
        step = serde_json::from_str(&call.respond(
            status,
            r#"[["content-type","application/json"]]"#,
            answer,
        ))
        .unwrap();
    }
}

fn browser(device: &str) -> BrowserHost {
    let config: BrowserConfig = serde_json::from_value(json!({ "device_id": device })).unwrap();
    BrowserHost::new(config).unwrap()
}

fn titles(host: &BrowserHost) -> Vec<String> {
    let vault = host.agent().peek_vault().unwrap();
    let mut t: Vec<String> = vault.items().into_iter().map(|i| i.title).collect();
    t.sort();
    t
}

fn save_login(host: &BrowserHost, url: &str) {
    let line = json!({ "id": 1, "method": "logins.save", "params": { "url": url, "username": "octo", "password": "hunter2-Long-enough" } });
    let answer: Value = serde_json::from_str(&host.handle(&line.to_string())).unwrap();
    assert!(answer.get("error").is_none(), "{answer}");
}

#[test]
fn two_browsers_share_a_vault_through_drive() {
    let mut drive = FakeDrive::default();
    let chrome = browser("chrome");
    chrome.create(PASSWORD).unwrap();
    save_login(&chrome, "https://github.com/login");
    chrome.take_save();

    // The first sync creates the file, named for the other devices' lists, and keeps its state.
    let (done, _) = run(
        &mut drive,
        DriveCall::sync(&chrome, TOKEN, " Personal ").unwrap(),
    );
    assert_eq!(done["result"]["created_remote"], true, "{done}");
    assert_eq!(done["result"]["current"], true);
    assert!(
        chrome.take_save().is_some(),
        "the sync state is saved with the vault"
    );
    assert_eq!(
        drive.log,
        [
            "GET /drive/v3/files",
            "POST /upload/drive/v3/files",
            "GET /drive/v3/files"
        ]
    );

    // Another browser lists the vaults by name, downloads one and opens it.
    let (done, _) = run(&mut drive, DriveCall::list(TOKEN));
    let list = done["result"].as_array().unwrap().clone();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["name"], "Personal");
    assert_eq!(
        list[0]["vault_id"],
        chrome.agent().peek_vault().unwrap().vault_id()
    );
    let (done, mut call) = run(
        &mut drive,
        DriveCall::download(TOKEN, list[0]["file_id"].as_str().unwrap()),
    );
    let bytes = call.take_bytes().unwrap();
    assert_eq!(done["result"]["size"], bytes.len());
    let edge = browser("edge");
    edge.load(bytes).unwrap();
    edge.unlock(PASSWORD).unwrap();
    save_login(&edge, "https://gitlab.com/users/sign_in");
    let (done, _) = run(
        &mut drive,
        DriveCall::sync(&edge, TOKEN, "Personal").unwrap(),
    );
    assert_eq!(done["result"]["uploaded"], true, "{done}");

    // The first browser merges it in, and the pages hear about it.
    chrome.take_effects();
    drive.log.clear();
    let (done, _) = run(
        &mut drive,
        DriveCall::sync(&chrome, TOKEN, "Personal").unwrap(),
    );
    assert_eq!(done["result"]["added"], 1, "{done}");
    assert_eq!(titles(&chrome), titles(&edge));
    assert_eq!(titles(&chrome).len(), 2);
    assert!(chrome.take_save().is_some());
    assert!(chrome.take_effects().contains("vault_changed"));

    // Nothing changed anywhere: one metadata request.
    drive.log.clear();
    let (done, _) = run(
        &mut drive,
        DriveCall::sync(&chrome, TOKEN, "Personal").unwrap(),
    );
    assert_eq!(done["result"]["uploaded"], false);
    assert_eq!(drive.log.len(), 1);

    // Only encrypted bytes went to Google: no item field in any request. The vault's name is the
    // one readable value (so a new device can list vaults), and it is sent.
    assert!(
        drive.sent.windows(8).any(|w| w == b"Personal"),
        "the vault's name is sent to Drive"
    );
    for secret in ["octo", "hunter2-Long-enough", "github.com", "gitlab.com"] {
        let s = secret.as_bytes();
        assert!(
            !drive.sent.windows(s.len()).any(|w| w == s),
            "{secret} went to Drive"
        );
    }
    assert!(
        drive.urls.iter().all(|u| u.starts_with("https://")),
        "{:?}",
        drive.urls
    );
}

#[test]
fn refused_tokens_no_answer_and_a_locked_vault() {
    let mut drive = FakeDrive::default();
    let chrome = browser("chrome");
    chrome.create(PASSWORD).unwrap();
    drive.expired = true;
    let (done, _) = run(&mut drive, DriveCall::sync(&chrome, TOKEN, "").unwrap());
    assert_eq!(done["error"]["code"], "auth_required", "{done}");
    drive.expired = false;

    // No answer at all (offline): a network error, and the vault keeps what it has.
    let mut call = DriveCall::sync(&chrome, TOKEN, "").unwrap();
    let first: Value = serde_json::from_str(&call.begin()).unwrap();
    assert!(first.get("send").is_some());
    let done: Value = serde_json::from_str(&call.fail("offline")).unwrap();
    assert_eq!(done["done"]["error"]["code"], "network", "{done}");
    assert!(done["done"]["error"]["message"]
        .as_str()
        .unwrap()
        .contains("www.googleapis.com"));

    // An empty token never reaches Drive; a locked vault can't sync.
    let (done, _) = run(&mut drive, DriveCall::list(""));
    assert_eq!(done["error"]["code"], "auth_required");
    chrome.lock(true).unwrap();
    assert!(DriveCall::sync(&chrome, TOKEN, "").is_err());

    // A sync that finishes after the vault was locked doesn't save into the locked agent.
    chrome.unlock(PASSWORD).unwrap();
    let mut call = DriveCall::sync(&chrome, TOKEN, "").unwrap();
    let mut step: Value = serde_json::from_str(&call.begin()).unwrap();
    chrome.lock(true).unwrap();
    chrome.take_save();
    while step.get("done").is_none() {
        let send = step["send"].clone();
        let headers = vec![("Authorization".to_string(), format!("Bearer {TOKEN}"))];
        let body = call.take_body().unwrap_or_default();
        let (status, answer) = drive.answer(
            send["method"].as_str().unwrap(),
            send["url"].as_str().unwrap(),
            &headers,
            &body,
        );
        step = serde_json::from_str(&call.respond(status, "{}", answer)).unwrap();
    }
    assert_eq!(step["done"]["result"]["current"], false, "{step}");
    assert!(chrome.take_save().is_none());
}
