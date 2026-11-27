//! Sync through Google Drive, in the app's hidden folder (`appDataFolder`).
//! Drive only sees the encrypted vault file, one per vault (`pass-<vault id>.vault`), plus the vault
//! id and name in `appProperties` so a new device can list vaults before unlocking.
//! The algorithms run over a [`Transport`], blocking (`gdrive`) or request by request (`gdrive-core`).

use std::collections::HashMap;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::json;

use crate::http::{Exchange, HttpRequest, HttpResponse, Step, Transport};
use crate::i18n::tr;
use crate::vault::{parse_file, url_key, MergeStats, SyncResult, SyncState, Vault};
use crate::{PassError, Result};

const MAX_VAULT_BYTES: u64 = 64 * 1024 * 1024;
/// Largest JSON answer read (a file list, metadata, an error).
const MAX_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_ATTEMPTS: usize = 4;
/// Drive's limit for `uploadType=media` / `multipart`; larger files use a resumable session.
const SIMPLE_UPLOAD_LIMIT: usize = 5 * 1024 * 1024;
const FILE_FIELDS: &str =
    "id,name,version,md5Checksum,modifiedTime,createdTime,size,appProperties,headRevisionId";
/// Fields of `revisions.list`.
const REVISION_FIELDS: &str = "nextPageToken,revisions(id,keepForever)";
/// While the vault's file is younger than this, syncs also look the file up by name, to catch a
/// twin created at the same moment by another device that `files.list` didn't show yet.
const YOUNG_FILE_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// In its first hour the file is looked up by name on every sync (the listing lags by seconds to
/// minutes at most); after that, at most once per [`TWIN_LOOKUP_EVERY_MS`] per file and process,
/// so the apps' frequent checks (every 20 s while in use) stay one request each.
const FRESH_FILE_MS: i64 = 60 * 60 * 1000;
const TWIN_LOOKUP_EVERY_MS: i64 = 10 * 60 * 1000;
/// When this process last looked each file up by name (file id to Unix ms).
static TWIN_LOOKUPS: std::sync::Mutex<Option<HashMap<String, i64>>> = std::sync::Mutex::new(None);
const PROP_VAULT_ID: &str = "pass_vault_id";
const PROP_NAME: &str = "pass_vault_name";
const FILE_PREFIX: &str = "pass-";
const FILE_SUFFIX: &str = ".vault";
/// `pass-<vault id>.removed`, an empty file left by [`gdrive_remove_vault`]: the vault was removed
/// from this Google Drive on purpose, so other devices stop syncing it instead of uploading it again.
const REMOVED_SUFFIX: &str = ".removed";
const PROP_REMOVED: &str = "pass_removed_vault_id";
/// Named when Google Drive can't be reached and the failed request has no URL.
#[cfg(feature = "gdrive")]
const GOOGLE_API: &str = "https://www.googleapis.com";

/// What one Google Drive call needs.
#[derive(Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct GDriveConfig {
    /// A current OAuth 2.0 access token with the `drive.appdata` scope. Never stored by the core.
    pub access_token: String,
    /// Display name kept in `appProperties` for the restore list. Visible to Google. Empty: leave as is.
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub vault_name: String,
    /// The user turned the backup on just now ("Back up to Google Drive"): a removal another
    /// device recorded ("Remove vault from Google Drive", [`gdrive_remove_vault`]) is lifted and
    /// the file is created again. Off (background syncs): such a removal stops the sync with
    /// `gdrive.vault_removed`, so a device that still has the vault doesn't put it back.
    #[cfg_attr(feature = "uniffi", uniffi(default = false))]
    pub start_again: bool,
}

impl std::fmt::Debug for GDriveConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Neither the token nor the vault's name (the user's own words) goes into a log.
        f.debug_struct("GDriveConfig").finish_non_exhaustive()
    }
}

/// A vault backed up to this Google account's app folder ([`gdrive_list_vaults`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct GDriveVault {
    /// Drive file id, for [`gdrive_download`] / [`gdrive_delete`].
    pub file_id: String,
    /// The vault's id (as in `Vault::vault_id`).
    pub vault_id: String,
    /// Name given by the device that last named it; empty if none.
    pub name: String,
    /// Last change, Unix milliseconds (0 if Drive didn't say).
    pub modified: i64,
    /// File size in bytes.
    pub size: u64,
}

/// The Google account an access token belongs to, for display ("Backed up to alice@gmail.com").
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct GDriveAccount {
    pub email: String,
    pub display_name: String,
}

/// What "Delete old versions from Google Drive" did ([`gdrive_delete_old_versions`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct GDriveOldVersions {
    /// Old versions deleted now.
    pub removed: u32,
    /// Old versions left there: Drive wouldn't delete them, or they are copies this version of
    /// Passyble can't read (a newer app's, kept for the device that wrote them).
    pub kept: u32,
    /// Google Drive stopped answering (busy, offline) before every old version was done: what is
    /// deleted stays deleted, and trying again later does the rest.
    pub unfinished: bool,
}

/// Endpoints; tests point them at a local fake.
#[derive(Clone, Debug)]
pub(crate) struct Endpoints {
    pub api: String,
    pub upload: String,
    pub simple_upload_limit: usize,
}

impl Endpoints {
    fn google() -> Self {
        Self {
            api: "https://www.googleapis.com/drive/v3".into(),
            upload: "https://www.googleapis.com/upload/drive/v3".into(),
            simple_upload_limit: SIMPLE_UPLOAD_LIMIT,
        }
    }
}

/// Drive's `File` resource (the fields we ask for). `int64` values come as JSON strings.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DriveFile {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    md5_checksum: Option<String>,
    #[serde(default)]
    modified_time: Option<String>,
    #[serde(default)]
    created_time: Option<String>,
    #[serde(default)]
    size: Option<String>,
    #[serde(default)]
    app_properties: HashMap<String, String>,
    /// The revision holding the current contents (blob files only).
    #[serde(default)]
    head_revision_id: Option<String>,
}

/// One entry of `revisions.list`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DriveRevision {
    id: String,
    /// Pinned ("Keep forever"): Drive never purges it, and it can always be downloaded.
    #[serde(default)]
    keep_forever: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevisionList {
    #[serde(default)]
    revisions: Vec<DriveRevision>,
    #[serde(default)]
    next_page_token: Option<String>,
}

impl DriveFile {
    fn version(&self) -> u64 {
        self.version
            .as_deref()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }

    /// The file's size in bytes, when Drive reported it.
    fn bytes(&self) -> Option<u64> {
        self.size.as_deref().and_then(|s| s.parse().ok())
    }

    /// Milliseconds since the file was created, by this device's clock (`None`: unknown, counts as
    /// old). A creation time ahead of the clock is age 0. Clock skew of hours doesn't matter here.
    fn age_ms(&self, now: i64) -> Option<i64> {
        let created = self.created_time.as_deref().map_or(0, rfc3339_ms);
        (created > 0).then(|| now.saturating_sub(created).max(0))
    }

    /// Whether this sync looks the young file up by name ([`twin_lookup_due`]), noting it if so.
    fn twin_lookup_now(&self) -> bool {
        let now = crate::clock::now_ms();
        let Some(age) = self.age_ms(now) else {
            return false;
        };
        let mut lookups = TWIN_LOOKUPS.lock().unwrap_or_else(|p| p.into_inner());
        let lookups = lookups.get_or_insert_with(HashMap::new);
        let due = twin_lookup_due(age, lookups.get(&self.id).copied(), now);
        if due {
            lookups.insert(self.id.clone(), now);
        }
        due
    }
}

/// Whether a sync of a file `age` ms old looks it up by name, `last` being when this process last
/// did (Unix ms): always in its first hour, then at most every [`TWIN_LOOKUP_EVERY_MS`] until it is
/// [`YOUNG_FILE_MS`] old, never after that.
fn twin_lookup_due(age: i64, last: Option<i64>, now: i64) -> bool {
    if age >= YOUNG_FILE_MS {
        return false;
    }
    age < FRESH_FILE_MS || last.is_none_or(|t| now.saturating_sub(t) >= TWIN_LOOKUP_EVERY_MS)
}

/// Oldest first (`createdTime`, then id): the first is the canonical file when two devices created
/// it at the same time. Every device sorts the same way, so they all pick the same one.
fn sort_canonical(files: &mut [DriveFile]) {
    files.sort_by(|a, b| {
        let created = |f: &DriveFile| f.created_time.clone().unwrap_or_default();
        created(a).cmp(&created(b)).then(a.id.cmp(&b.id))
    });
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileList {
    #[serde(default)]
    files: Vec<DriveFile>,
    #[serde(default)]
    next_page_token: Option<String>,
}

/// The Drive v3 calls the sync uses, over a [`Transport`].
pub(crate) struct Api<'a, T> {
    http: &'a T,
    token: &'a str,
    base: &'a Endpoints,
}

/// `GET` / `PATCH` answered 404: the file is gone (deleted on another device, or another account).
type Maybe<T> = Option<T>;

impl<'a, T: Transport> Api<'a, T> {
    pub(crate) fn new(http: &'a T, token: &'a str, base: &'a Endpoints) -> Result<Self> {
        if token.trim().is_empty() {
            return Err(PassError::AuthRequired(tr!("gdrive.no_token")));
        }
        Ok(Self { http, token, base })
    }

    /// A request with the token, to `url` with `query` appended (form-encoded, as Drive expects).
    fn request(&self, method: &str, url: &str, query: &[(&str, &str)]) -> HttpRequest {
        HttpRequest::new(method, with_query(url, query))
            .header("Authorization", &format!("Bearer {}", self.token))
    }

    fn get(&self, url: &str, query: &[(&str, &str)]) -> HttpRequest {
        self.request("GET", url, query)
            .header("Cache-Control", "no-cache")
    }

    fn file_url(&self, id: &str) -> String {
        format!("{}/files/{}", self.base.api, encode(id))
    }

    async fn send(&self, request: HttpRequest, action: &str) -> Result<HttpResponse> {
        self.http.send(request, action).await
    }

    /// Metadata of one file; `None` on 404.
    async fn get_file(&self, id: &str) -> Result<Maybe<DriveFile>> {
        let action = tr!("action.check");
        let r = self
            .send(
                self.get(&self.file_url(id), &[("fields", FILE_FIELDS)]),
                &action,
            )
            .await?;
        match r.status {
            _ if r.is_success() => read_json(&action, &r).map(Some),
            404 => Ok(None),
            _ => Err(fail(&action, &r)),
        }
    }

    /// Every not-trashed file in the app folder matching `q` (all pages).
    async fn list(&self, q: &str) -> Result<Vec<DriveFile>> {
        let action = tr!("action.list");
        let mut files = Vec::new();
        let mut page: Option<String> = None;
        let fields = format!("nextPageToken,files({FILE_FIELDS})");
        loop {
            let mut query = vec![
                ("spaces", "appDataFolder"),
                ("q", q),
                ("fields", fields.as_str()),
                ("pageSize", "100"),
            ];
            if let Some(token) = &page {
                query.push(("pageToken", token.as_str()));
            }
            let r = self
                .send(
                    self.get(&format!("{}/files", self.base.api), &query),
                    &action,
                )
                .await?;
            if !r.is_success() {
                return Err(fail(&action, &r));
            }
            let list: FileList = read_json(&action, &r)?;
            files.extend(list.files);
            match list.next_page_token {
                Some(token) if !token.is_empty() && files.len() < 10_000 => page = Some(token),
                _ => return Ok(files),
            }
        }
    }

    /// The files named `name`, oldest first (`createdTime`, then id): the first is the canonical
    /// one when two devices created the file at the same time.
    async fn find(&self, name: &str) -> Result<Vec<DriveFile>> {
        let mut files = self
            .list(&format!(
                "name = '{}' and trashed = false",
                escape_query(name)
            ))
            .await?;
        files.retain(|f| f.name == name);
        sort_canonical(&mut files);
        Ok(files)
    }

    /// The file's contents; `None` on 404.
    async fn download(&self, id: &str) -> Result<Maybe<Vec<u8>>> {
        let action = tr!("action.download");
        let r = self
            .send(self.get(&self.file_url(id), &[("alt", "media")]), &action)
            .await?;
        match r.status {
            _ if r.is_success() => {
                let mut body = r.body;
                body.truncate(MAX_VAULT_BYTES as usize);
                Ok(Some(body))
            }
            404 => Ok(None),
            _ => Err(fail(&action, &r)),
        }
    }

    /// Creates `name` in the app folder with `bytes`, in one request (multipart) or a resumable
    /// session for big files. The first revision is pinned like every upload (see
    /// [`Api::update`]).
    async fn create(
        &self,
        name: &str,
        props: &HashMap<String, String>,
        bytes: &[u8],
    ) -> Result<DriveFile> {
        for pin in [true, false] {
            match self.create_once(name, props, bytes, pin).await? {
                Sent::Done(file) => return Ok(file),
                Sent::PinRefused => continue,
            }
        }
        Err(PassError::Network(tr!(
            "gdrive.refused",
            action = tr!("action.upload")
        )))
    }

    async fn create_once(
        &self,
        name: &str,
        props: &HashMap<String, String>,
        bytes: &[u8],
        pin: bool,
    ) -> Result<Sent<DriveFile>> {
        let action = tr!("action.upload");
        let metadata = json!({
            "name": name,
            "parents": ["appDataFolder"],
            "mimeType": "application/octet-stream",
            "appProperties": props,
        });
        let url = format!("{}/files", self.base.upload);
        if bytes.len() > self.base.simple_upload_limit {
            return Ok(
                match self.resumable("POST", &url, &metadata, bytes, pin).await? {
                    Sent::Done(file) => {
                        Sent::Done(file.ok_or_else(|| PassError::NotFound("file".into()))?)
                    }
                    Sent::PinRefused => Sent::PinRefused,
                },
            );
        }
        let boundary = format!("pass-{}", uuid::Uuid::new_v4().simple());
        let mut body = Vec::with_capacity(bytes.len() + 512);
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{metadata}\r\n\
                 --{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(bytes);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let request = self
            .request("POST", &url, &upload_query("multipart", pin))
            .header(
                "Content-Type",
                &format!("multipart/related; boundary={boundary}"),
            )
            .body(body);
        let r = self.send(request, &action).await?;
        if pin && pin_refused(&r) {
            return Ok(Sent::PinRefused);
        }
        if !r.is_success() {
            return Err(fail(&action, &r));
        }
        read_json(&action, &r).map(Sent::Done)
    }

    /// Replaces the file's contents; `None` on 404.
    ///
    /// The new revision is pinned (`keepRevisionForever`): Drive keeps it, and lets any device
    /// download it, until a later upload that contains it unpins it (see [`settle`]). That is
    /// what lets a device whose upload overwrote another device's write (Drive v3 has no
    /// conditional upload) find that write and merge it. Should Drive refuse to pin (at most 200
    /// pinned revisions per file), the upload is sent again without the pin.
    async fn update(&self, id: &str, bytes: &[u8]) -> Result<Maybe<DriveFile>> {
        for pin in [true, false] {
            match self.update_once(id, bytes, pin).await? {
                Sent::Done(file) => return Ok(file),
                Sent::PinRefused => continue,
            }
        }
        Err(PassError::Network(tr!(
            "gdrive.refused",
            action = tr!("action.upload")
        )))
    }

    async fn update_once(
        &self,
        id: &str,
        bytes: &[u8],
        pin: bool,
    ) -> Result<Sent<Maybe<DriveFile>>> {
        let action = tr!("action.upload");
        let url = format!("{}/files/{}", self.base.upload, encode(id));
        if bytes.len() > self.base.simple_upload_limit {
            return self.resumable("PATCH", &url, &json!({}), bytes, pin).await;
        }
        let request = self
            .request("PATCH", &url, &upload_query("media", pin))
            .header("Content-Type", "application/octet-stream")
            .body(bytes.to_vec());
        let r = self.send(request, &action).await?;
        if pin && pin_refused(&r) {
            return Ok(Sent::PinRefused);
        }
        match r.status {
            _ if r.is_success() => read_json(&action, &r).map(|f| Sent::Done(Some(f))),
            404 => Ok(Sent::Done(None)),
            _ => Err(fail(&action, &r)),
        }
    }

    /// A resumable upload in one chunk: start the session, then send the bytes. `None` when the
    /// file to update is gone (404 at the start).
    async fn resumable(
        &self,
        method: &str,
        url: &str,
        metadata: &serde_json::Value,
        bytes: &[u8],
        pin: bool,
    ) -> Result<Sent<Maybe<DriveFile>>> {
        let action = tr!("action.upload");
        let start = self
            .request(method, url, &upload_query("resumable", pin))
            .header("Content-Type", "application/json; charset=UTF-8")
            .header("X-Upload-Content-Type", "application/octet-stream")
            .header("X-Upload-Content-Length", &bytes.len().to_string())
            .body(metadata.to_string().into_bytes());
        let r = self.send(start, &action).await?;
        if r.status == 404 {
            return Ok(Sent::Done(None));
        }
        if pin && pin_refused(&r) {
            return Ok(Sent::PinRefused);
        }
        if !r.is_success() {
            return Err(fail(&action, &r));
        }
        let session = r
            .header("Location")
            .ok_or_else(|| PassError::Network(tr!("gdrive.no_upload_session", action = action)))?
            .to_string();
        let put = HttpRequest::new("PUT", session)
            .header("Authorization", &format!("Bearer {}", self.token))
            .header("Content-Type", "application/octet-stream")
            .body(bytes.to_vec());
        let r = self.send(put, &action).await?;
        if pin && pin_refused(&r) {
            return Ok(Sent::PinRefused);
        }
        if !r.is_success() {
            return Err(fail(&action, &r));
        }
        read_json(&action, &r).map(|f| Sent::Done(Some(f)))
    }

    /// Every revision of the file, in Drive's order (oldest first); `None` on 404.
    async fn revisions(&self, id: &str) -> Result<Maybe<Vec<DriveRevision>>> {
        let action = tr!("action.check");
        let url = format!("{}/revisions", self.file_url(id));
        let mut revisions = Vec::new();
        let mut page: Option<String> = None;
        loop {
            let mut query = vec![("fields", REVISION_FIELDS), ("pageSize", "1000")];
            if let Some(token) = &page {
                query.push(("pageToken", token.as_str()));
            }
            let r = self.send(self.get(&url, &query), &action).await?;
            match r.status {
                _ if r.is_success() => {}
                404 => return Ok(None),
                _ => return Err(fail(&action, &r)),
            }
            let list: RevisionList = read_json(&action, &r)?;
            revisions.extend(list.revisions);
            match list.next_page_token {
                Some(token) if !token.is_empty() && revisions.len() < 10_000 => page = Some(token),
                _ => return Ok(Some(revisions)),
            }
        }
    }

    /// The contents of one revision; `None` when Drive won't serve it (gone, or not downloadable).
    async fn download_revision(&self, id: &str, revision: &str) -> Result<Maybe<Vec<u8>>> {
        let action = tr!("action.download");
        let url = format!("{}/revisions/{}", self.file_url(id), encode(revision));
        let r = self
            .send(self.get(&url, &[("alt", "media")]), &action)
            .await?;
        match r.status {
            _ if r.is_success() => {
                let mut body = r.body;
                body.truncate(MAX_VAULT_BYTES as usize);
                Ok(Some(body))
            }
            404 => Ok(None),
            _ if pin_refused(&r) => Ok(None),
            _ => Err(fail(&action, &r)),
        }
    }

    /// Unpins a revision (`keepForever: false`): Drive may then purge it once it is no longer the
    /// head. 404 is fine.
    async fn unpin(&self, id: &str, revision: &str) -> Result<()> {
        let action = tr!("action.upload");
        let url = format!("{}/revisions/{}", self.file_url(id), encode(revision));
        let request = self
            .request("PATCH", &url, &[("fields", "id,keepForever")])
            .header("Content-Type", "application/json; charset=UTF-8")
            .body(json!({ "keepForever": false }).to_string().into_bytes());
        let r = self.send(request, &action).await?;
        match r.status {
            _ if r.is_success() => Ok(()),
            404 => Ok(()),
            _ => Err(fail(&action, &r)),
        }
    }

    /// Sets `appProperties` (metadata only).
    async fn set_props(
        &self,
        id: &str,
        props: &HashMap<String, String>,
    ) -> Result<Maybe<DriveFile>> {
        let action = tr!("action.rename");
        let request = self
            .request("PATCH", &self.file_url(id), &[("fields", FILE_FIELDS)])
            .header("Content-Type", "application/json; charset=UTF-8")
            .body(json!({ "appProperties": props }).to_string().into_bytes());
        let r = self.send(request, &action).await?;
        match r.status {
            _ if r.is_success() => read_json(&action, &r).map(Some),
            404 => Ok(None),
            _ => Err(fail(&action, &r)),
        }
    }

    /// Deletes a file for good (app-folder files never go to the trash). 404 is fine.
    async fn delete(&self, id: &str) -> Result<()> {
        let action = tr!("action.delete");
        let r = self
            .send(self.request("DELETE", &self.file_url(id), &[]), &action)
            .await?;
        match r.status {
            _ if r.is_success() => Ok(()),
            404 => Ok(()),
            _ => Err(fail(&action, &r)),
        }
    }

    /// Deletes one old revision of the file for good. Drive keeps the head (the current contents)
    /// whatever is asked.
    async fn delete_revision(&self, id: &str, revision: &str) -> Result<RevisionDelete> {
        let action = tr!("action.delete");
        let url = format!("{}/revisions/{}", self.file_url(id), encode(revision));
        let r = self
            .send(self.request("DELETE", &url, &[]), &action)
            .await?;
        match r.status {
            _ if r.is_success() => Ok(RevisionDelete::Deleted),
            404 => Ok(RevisionDelete::Gone),
            // A 400, or a 403 that isn't the token, the quota or the rate: Drive won't delete this
            // one (the only revision left, say).
            _ if pin_refused(&r) => Ok(RevisionDelete::Refused),
            _ => Err(fail(&action, &r)),
        }
    }

    /// Creates the empty removal marker `name` in the app folder (metadata only).
    async fn create_marker(&self, name: &str, props: &HashMap<String, String>) -> Result<()> {
        let action = tr!("action.delete");
        let metadata = json!({
            "name": name,
            "parents": ["appDataFolder"],
            "mimeType": "application/octet-stream",
            "appProperties": props,
        });
        let request = self
            .request("POST", &format!("{}/files", self.base.api), &[("fields", "id")])
            .header("Content-Type", "application/json; charset=UTF-8")
            .body(metadata.to_string().into_bytes());
        let r = self.send(request, &action).await?;
        if r.is_success() {
            Ok(())
        } else {
            Err(fail(&action, &r))
        }
    }

    /// [`Api::find`] for `name`, plus the removal markers named `removed`, in one request.
    async fn find_or_removed(
        &self,
        name: &str,
        removed: &str,
    ) -> Result<(Vec<DriveFile>, Vec<DriveFile>)> {
        let mut files = self
            .list(&format!(
                "(name = '{}' or name = '{}') and trashed = false",
                escape_query(name),
                escape_query(removed)
            ))
            .await?;
        let markers = files.iter().filter(|f| f.name == removed).cloned().collect();
        files.retain(|f| f.name == name);
        sort_canonical(&mut files);
        Ok((files, markers))
    }

    async fn about(&self) -> Result<GDriveAccount> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct User {
            #[serde(default)]
            email_address: String,
            #[serde(default)]
            display_name: String,
        }
        #[derive(Deserialize)]
        struct About {
            user: User,
        }
        let action = tr!("action.account");
        let r = self
            .send(
                self.get(
                    &format!("{}/about", self.base.api),
                    &[("fields", "user(emailAddress,displayName)")],
                ),
                &action,
            )
            .await?;
        if !r.is_success() {
            return Err(fail(&action, &r));
        }
        let about: About = read_json(&action, &r)?;
        Ok(GDriveAccount {
            email: about.user.email_address,
            display_name: about.user.display_name,
        })
    }
}

/// `url` with `query` appended, form-encoded (`a=1&b=x+y`), as an HTTP library's query builder does.
fn with_query(url: &str, query: &[(&str, &str)]) -> String {
    if query.is_empty() {
        return url.to_string();
    }
    let encoded: String = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(query)
        .finish();
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}{encoded}")
}

/// Percent-encodes a path segment (Drive ids are URL-safe already; this is belt and braces).
fn encode(segment: &str) -> String {
    percent_encoding::utf8_percent_encode(segment, percent_encoding::NON_ALPHANUMERIC).to_string()
}

/// A string literal inside a Drive `q` query.
fn escape_query(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

fn read_json<T: serde::de::DeserializeOwned>(action: &str, response: &HttpResponse) -> Result<T> {
    if response.body.len() > MAX_JSON_BYTES {
        return Err(PassError::Network(unexpected(action)));
    }
    serde_json::from_slice(&response.body).map_err(|_| PassError::Network(unexpected(action)))
}

/// `{action}: Google Drive's answer isn't what Passyble expects…`.
fn unexpected(action: &str) -> String {
    tr!("gdrive.unexpected_answer", action = action)
}

/// Google's JSON error: `{"error": {"code", "message", "errors": [{"reason"}], "status"}}`.
fn error_details(response: &HttpResponse) -> (String, String) {
    #[derive(Deserialize, Default)]
    struct Reason {
        #[serde(default)]
        reason: String,
    }
    #[derive(Deserialize, Default)]
    struct Inner {
        #[serde(default)]
        message: String,
        #[serde(default)]
        errors: Vec<Reason>,
        #[serde(default)]
        status: String,
    }
    #[derive(Deserialize, Default)]
    struct Body {
        #[serde(default)]
        error: Inner,
    }
    let text = &response.body[..response.body.len().min(64 * 1024)];
    let body: Body = serde_json::from_slice(text).unwrap_or_default();
    let reason = body
        .error
        .errors
        .first()
        .map(|r| r.reason.clone())
        .filter(|r| !r.is_empty())
        .unwrap_or(body.error.status);
    (reason, body.error.message)
}

/// Why Drive answered 403.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    /// The token lacks the scope (the user didn't grant it): sign in again.
    Auth,
    Quota,
    Busy,
    Disabled,
    /// Anything else, such as a request Drive won't do for this file.
    Other,
}

fn refusal(response: &HttpResponse) -> Refusal {
    let (reason, message) = error_details(response);
    let lower = message.to_lowercase();
    match reason.as_str() {
        _ if lower.contains("insufficient authentication scopes")
            || reason == "insufficientPermissions"
            || reason == "PERMISSION_DENIED" && lower.contains("scope") =>
        {
            Refusal::Auth
        }
        "storageQuotaExceeded" | "quotaExceeded" => Refusal::Quota,
        "rateLimitExceeded" | "userRateLimitExceeded" | "RESOURCE_EXHAUSTED" => Refusal::Busy,
        "accessNotConfigured" | "SERVICE_DISABLED" => Refusal::Disabled,
        _ => Refusal::Other,
    }
}

/// Maps an HTTP error status. A refused token (401, or 403 for a scope the user didn't grant) is
/// [`PassError::AuthRequired`]: the platform asks Google for access again.
fn fail(action: &str, response: &HttpResponse) -> PassError {
    match response.status {
        401 => PassError::AuthRequired(tr!("gdrive.sign_in_expired")),
        403 => match refusal(response) {
            Refusal::Auth => PassError::AuthRequired(tr!("gdrive.app_folder_denied")),
            Refusal::Quota => PassError::Network(tr!("gdrive.storage_full", action = action)),
            Refusal::Busy => PassError::Network(tr!("gdrive.busy", action = action)),
            Refusal::Disabled => PassError::Network(tr!("gdrive.api_disabled", action = action)),
            Refusal::Other => PassError::Network(tr!("gdrive.refused", action = action)),
        },
        429 => PassError::Network(tr!("gdrive.busy", action = action)),
        500..=599 => PassError::Network(tr!("gdrive.server_error", action = action)),
        _ => PassError::Network(tr!("gdrive.refused", action = action)),
    }
}

/// What an upload that asked Drive to pin its revision got.
enum Sent<T> {
    Done(T),
    /// Drive refused the request for a reason that isn't the token, the quota or the rate (most
    /// likely the limit of 200 pinned revisions per file): send it again without the pin.
    PinRefused,
}

/// A 400, or a 403 that isn't about the token, the quota, the rate or a disabled API.
fn pin_refused(response: &HttpResponse) -> bool {
    match response.status {
        400 => true,
        403 => refusal(response) == Refusal::Other,
        _ => false,
    }
}

/// The query of a content upload; `pin` asks Drive to keep the new revision forever.
fn upload_query(upload_type: &'static str, pin: bool) -> Vec<(&'static str, &'static str)> {
    let mut query = vec![("uploadType", upload_type), ("fields", FILE_FIELDS)];
    if pin {
        query.push(("keepRevisionForever", "true"));
    }
    query
}

/// `pass-<vault id>.vault`.
fn file_name(vault_id: &str) -> String {
    format!("{FILE_PREFIX}{vault_id}{FILE_SUFFIX}")
}

/// `pass-<vault id>.removed`, the marker [`gdrive_remove_vault`] leaves.
fn removed_file_name(vault_id: &str) -> String {
    format!("{FILE_PREFIX}{vault_id}{REMOVED_SUFFIX}")
}

/// What deleting one old revision got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RevisionDelete {
    Deleted,
    /// Already gone (404).
    Gone,
    /// Drive won't delete it.
    Refused,
}

fn props(vault_id: &str, name: &str) -> HashMap<String, String> {
    let mut props = HashMap::from([(PROP_VAULT_ID.to_string(), vault_id.to_string())]);
    if !name.trim().is_empty() {
        props.insert(PROP_NAME.to_string(), name.trim().to_string());
    }
    props
}

/// What the Drive file looked like after the last successful sync, kept in the vault's local
/// sync state (`SyncState::etag`, opaque there): `<file id> <version> <md5>`, then optional flags:
///
/// - `unverified`: this device uploaded, but hasn't checked yet that its upload overwrote no other
///   device's write (the check, [`settle`], was interrupted); the next sync does it.
/// - `twins`: a copy of the file that another device created at the same moment is still there
///   (it changed after it was merged, or deleting it failed); the next sync looks again.
///
/// Older versions read the first three fields and ignore the rest.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Known {
    file_id: String,
    version: u64,
    md5: String,
    fingerprint: String,
    unverified: bool,
    twins: bool,
}

impl Known {
    fn from_state(state: SyncState) -> Option<Self> {
        let etag = state.etag?;
        let mut parts = etag.split(' ');
        let file_id = parts.next()?.to_string();
        let version = parts.next()?.parse().ok()?;
        let md5 = parts.next().unwrap_or_default().to_string();
        let flags: Vec<&str> = parts.collect();
        (!file_id.is_empty()).then_some(Self {
            file_id,
            version,
            md5,
            fingerprint: state.fingerprint,
            unverified: flags.contains(&"unverified"),
            twins: flags.contains(&"twins"),
        })
    }

    fn of(file: &DriveFile, fingerprint: String) -> Self {
        Self {
            file_id: file.id.clone(),
            version: file.version(),
            md5: file.md5_checksum.clone().unwrap_or_default(),
            fingerprint,
            unverified: false,
            twins: false,
        }
    }

    fn state(&self, key: &str) -> SyncState {
        let mut etag = format!("{} {} {}", self.file_id, self.version, self.md5);
        if self.unverified {
            etag.push_str(" unverified");
        }
        if self.twins {
            etag.push_str(" twins");
        }
        SyncState {
            url: key.to_string(),
            etag: Some(etag),
            fingerprint: self.fingerprint.clone(),
            bytes: None,
        }
    }

    /// `file` holds the same contents as when we last synced: same file and version, or only its
    /// metadata changed (same MD5, e.g. another device renamed the vault).
    fn same_contents(&self, file: &DriveFile) -> bool {
        self.file_id == file.id
            && (self.version == file.version()
                || (!self.md5.is_empty()
                    && file.md5_checksum.as_deref() == Some(self.md5.as_str())))
    }
}

fn add(total: &mut MergeStats, stats: MergeStats) {
    total.added += stats.added;
    total.updated += stats.updated;
    total.deleted += stats.deleted;
    total.unchanged = stats.unchanged;
}

fn push_unique(list: &mut Vec<String>, id: &str) {
    if !list.iter().any(|x| x == id) {
        list.push(id.to_string());
    }
}

/// The sync itself (see [`gdrive_sync`]), over any transport.
async fn sync_flow<T: Transport>(
    api: &Api<'_, T>,
    vault: &Vault,
    config: &GDriveConfig,
) -> Result<SyncResult> {
    let vault_id = vault.vault_id();
    let name = file_name(&vault_id);
    let key = url_key(&format!("gdrive:{vault_id}"));
    let mut known = vault.sync_state(&key).and_then(Known::from_state);
    // This device synced a Drive file before: if it is gone and a removal marker is there, the
    // vault was removed from Drive on purpose (see [`GDriveConfig::start_again`]).
    let had_file = known.is_some();
    let removed_name = removed_file_name(&vault_id);
    let remember = |known: &Known| vault.set_sync_state(known.state(&key));
    let mut total = MergeStats::default();
    let mut created_remote = false;
    // Extra copies from two devices creating the file at once: merged here, deleted once the
    // canonical (oldest) file holds everything, if they haven't changed since they were merged.
    let mut duplicates: Vec<DriveFile> = Vec::new();
    let mut merged_duplicates: Vec<DriveFile> = Vec::new();
    // Revisions of the file being synced whose contents this vault holds: merged here, or
    // uploaded from here. Merging only adds (deletions are tombstones), so the list only grows
    // while the file stays the same.
    let mut contained: Vec<String> = Vec::new();

    for _ in 0..MAX_ATTEMPTS {
        // 1. Locate the file and its version.
        let mut current = match &known {
            Some(k) => api.get_file(&k.file_id).await?,
            None => None,
        };
        // A young file, or one with a twin still around, is also looked up by name: another
        // device may have created its own copy at the same moment, and right after creating,
        // `files.list` may not show it yet. Without this, both devices could keep syncing their
        // own copy and never see each other's changes.
        let mut twins_found = None;
        if let Some(file) = &current {
            if known.as_ref().is_some_and(|k| k.twins) || file.twin_lookup_now() {
                let mut same_name = api.find(&name).await?;
                if !same_name.iter().any(|f| f.id == file.id) {
                    same_name.push(file.clone());
                    sort_canonical(&mut same_name);
                }
                if same_name.len() > 1 {
                    twins_found = Some(same_name);
                } else if let Some(k) = known.as_mut().filter(|k| k.twins) {
                    k.twins = false;
                    remember(&*k);
                }
            }
        }
        if current.is_none() || twins_found.is_some() {
            // First sync, the file we knew is gone, or it has twins: look it up by name.
            let mut found = match twins_found {
                Some(found) => found,
                None => {
                    let (found, markers) = api.find_or_removed(&name, &removed_name).await?;
                    if found.is_empty() && !markers.is_empty() {
                        if had_file && !config.start_again {
                            return Err(PassError::NotFound(tr!("gdrive.vault_removed")));
                        }
                        // Backed up again on purpose (or a new device): lift the removal.
                        for marker in &markers {
                            api.delete(&marker.id).await?;
                        }
                    }
                    found
                }
            };
            if found.is_empty() {
                let (bytes, fingerprint) = vault.snapshot()?;
                let file = api
                    .create(&name, &props(&vault_id, &config.vault_name), &bytes)
                    .await?;
                let state = Known::of(&file, fingerprint);
                remember(&state);
                known = Some(state);
                created_remote = true;
                contained.clear();
                if let Some(rev) = &file.head_revision_id {
                    push_unique(&mut contained, rev);
                }
                // Another device may have created its own copy at the same moment. The listing
                // may not show ours yet: count it anyway.
                found = api.find(&name).await?;
                if !found.iter().any(|f| f.id == file.id) {
                    found.push(file.clone());
                    sort_canonical(&mut found);
                }
                if found.len() <= 1 {
                    return Ok(SyncResult {
                        stats: total,
                        uploaded: true,
                        created_remote,
                        remote_bytes: file.bytes().or(Some(bytes.len() as u64)),
                    });
                }
            }
            let canonical = found.remove(0);
            for f in found {
                if !duplicates.iter().any(|d| d.id == f.id) {
                    duplicates.push(f);
                }
            }
            if known.as_ref().is_some_and(|k| k.file_id != canonical.id) {
                known = None;
                contained.clear();
            }
            // Keep the metadata `files.get` just sent: the listing may lag behind it.
            current = match current.take() {
                Some(fresh) if fresh.id == canonical.id => Some(fresh),
                _ => Some(canonical),
            };
        }
        let Some(file) = current else { continue };

        // 2. Fold in duplicates (rare). A copy that isn't this vault is left alone.
        for dup in duplicates.iter().filter(|d| d.id != file.id) {
            if merged_duplicates.iter().any(|m| m.id == dup.id) {
                continue;
            }
            if let Some(bytes) = api.download(&dup.id).await? {
                if let Ok(parsed) = parse_file(&bytes) {
                    if let Ok(stats) = vault.merge_parsed(&parsed) {
                        add(&mut total, stats);
                        merged_duplicates.push(dup.clone());
                    }
                }
            }
        }

        // 3. Remote changed since our last sync? Download and merge.
        let base_version = file.version();
        let base_md5 = file.md5_checksum.clone().unwrap_or_default();
        match known.as_ref().filter(|k| k.same_contents(&file)) {
            Some(k) => {
                // Unchanged remotely (a rename at most): just note the new version.
                let mut state = Known {
                    version: base_version,
                    md5: if base_md5.is_empty() {
                        k.md5.clone()
                    } else {
                        base_md5.clone()
                    },
                    ..k.clone()
                };
                if state != *k {
                    remember(&state);
                    known = Some(state.clone());
                }
                // The head holds what this vault merged or uploaded last time.
                if let Some(head) = &file.head_revision_id {
                    push_unique(&mut contained, head);
                }
                if state.unverified && !vault.differs_from(&state.fingerprint) {
                    // The check after this device's last upload didn't finish: do it now.
                    if let Some(head) = &file.head_revision_id {
                        // Only the head is known to be in that upload (it is that upload).
                        let mut in_head = vec![head.clone()];
                        let settled = settle(
                            api,
                            vault,
                            &file.id,
                            head,
                            &state.fingerprint,
                            &mut in_head,
                            &mut total,
                        )
                        .await;
                        for rev in &in_head {
                            push_unique(&mut contained, rev);
                        }
                        if settled == Settled::Clean {
                            state.unverified = false;
                            remember(&state);
                            known = Some(state.clone());
                        }
                    }
                }
                if !vault.differs_from(&state.fingerprint) {
                    finish(
                        api,
                        vault,
                        config,
                        &file,
                        &key,
                        &mut known,
                        &merged_duplicates,
                    )
                    .await?;
                    return Ok(SyncResult {
                        stats: total,
                        uploaded: false,
                        created_remote,
                        remote_bytes: file.bytes(),
                    });
                }
            }
            None => {
                let Some(bytes) = api.download(&file.id).await? else {
                    known = None; // deleted between the two requests
                    contained.clear();
                    continue;
                };
                let parsed = parse_file(&bytes)?;
                let fingerprint = parsed.fingerprint();
                // Same contents as already merged (e.g. our own upload after a lost state).
                let seen = known
                    .as_ref()
                    .is_some_and(|k| k.file_id == file.id && k.fingerprint == fingerprint);
                if !seen {
                    add(&mut total, vault.merge_parsed(&parsed)?);
                }
                // Pinned revisions besides the head are uploads that a later upload may have
                // overwritten before the device that made them could check (see `settle`):
                // merge them too. Usually there are none.
                for rev in absorb_pinned(api, vault, &file, &contained, &mut total).await {
                    push_unique(&mut contained, &rev);
                }
                let twins = known
                    .as_ref()
                    .is_some_and(|k| k.file_id == file.id && k.twins);
                let state = Known {
                    twins,
                    ..Known::of(&file, fingerprint)
                };
                remember(&state);
                known = Some(state);
                if !vault.remote_is_behind(&parsed) {
                    finish(
                        api,
                        vault,
                        config,
                        &file,
                        &key,
                        &mut known,
                        &merged_duplicates,
                    )
                    .await?;
                    return Ok(SyncResult {
                        stats: total,
                        uploaded: false,
                        created_remote,
                        remote_bytes: file.bytes().or(Some(bytes.len() as u64)),
                    });
                }
                // Drive has no If-Match: recheck the version right before overwriting.
                match api.get_file(&file.id).await? {
                    Some(now) if now.version() == base_version => {
                        // Nothing landed since the first request: what we downloaded is the head.
                        if let Some(head) = now
                            .head_revision_id
                            .as_ref()
                            .or(file.head_revision_id.as_ref())
                        {
                            push_unique(&mut contained, head);
                        }
                    }
                    _ => continue,
                }
            }
        }

        // 4. Upload. Drive v3 has no conditional upload, so a write landing just before ours is
        // overwritten. Item-level merge makes that safe: the other device sees the new version on
        // its next sync, merges, and re-uploads its missing items.
        let (bytes, fingerprint) = vault.snapshot()?;
        let Some(uploaded) = api.update(&file.id, &bytes).await? else {
            known = None; // deleted meanwhile: find or create it again
            contained.clear();
            continue;
        };
        let twins = known.as_ref().is_some_and(|k| k.twins);
        let mut state = Known {
            unverified: uploaded.head_revision_id.is_some(),
            twins,
            ..Known::of(&uploaded, fingerprint.clone())
        };
        remember(&state);
        known = Some(state.clone());
        if let Some(ours) = uploaded.head_revision_id.clone() {
            match settle(
                api,
                vault,
                &uploaded.id,
                &ours,
                &fingerprint,
                &mut contained,
                &mut total,
            )
            .await
            {
                Settled::Clean => {
                    state.unverified = false;
                    remember(&state);
                    known = Some(state);
                }
                Settled::Unverified => {}
                Settled::Remerged => {
                    // Another device's write had been overwritten; it is merged now. Upload
                    // again so the file holds it.
                    push_unique(&mut contained, &ours);
                    continue;
                }
            }
        }
        finish(
            api,
            vault,
            config,
            &uploaded,
            &key,
            &mut known,
            &merged_duplicates,
        )
        .await?;
        return Ok(SyncResult {
            stats: total,
            uploaded: true,
            created_remote,
            remote_bytes: uploaded.bytes().or(Some(bytes.len() as u64)),
        });
    }
    Err(PassError::Conflict(tr!("gdrive.kept_changing")))
}

/// What [`settle`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Settled {
    /// No other device's write is missing from our upload.
    Clean,
    /// A write our upload had overwritten is merged into this vault now: upload again.
    Remerged,
    /// Couldn't check (a request failed): the next sync checks again.
    Unverified,
}

/// Checks, right after this device uploaded revision `ours` of `file_id`, that the upload
/// overwrote no other device's write, and cleans up the pins.
///
/// Every upload pins its revision (`keepRevisionForever`). A pinned revision other than `ours`
/// is either one this vault holds (`contained`: merged before the upload, or uploaded from here)
/// or another device's write that was overwritten before anyone merged it. The latter is
/// downloaded and merged here. A revision is unpinned only when its contents are part of `ours`
/// and `ours` is pinned itself, so at every moment each write is in the head, in a pinned
/// revision, or still on the device that made it. A pinned revision that doesn't parse or merge
/// (not this vault, or a format this version can't read) is left pinned for a device that can.
async fn settle<T: Transport>(
    api: &Api<'_, T>,
    vault: &Vault,
    file_id: &str,
    ours: &str,
    ours_fingerprint: &str,
    contained: &mut Vec<String>,
    total: &mut MergeStats,
) -> Settled {
    let revisions = match api.revisions(file_id).await {
        Ok(Some(revisions)) => revisions,
        _ => return Settled::Unverified,
    };
    let Some(mine) = revisions.iter().find(|r| r.id == ours) else {
        return Settled::Unverified;
    };
    let ours_pinned = mine.keep_forever;
    // Pinned revisions whose contents are in `ours`: may be unpinned.
    let mut covered: Vec<String> = Vec::new();
    // Pinned revisions merged just now.
    let mut merged: Vec<String> = Vec::new();
    let mut unverified = false;
    for rev in revisions.iter().filter(|r| r.keep_forever && r.id != ours) {
        if contained.contains(&rev.id) {
            covered.push(rev.id.clone());
            continue;
        }
        match api.download_revision(file_id, &rev.id).await {
            Ok(Some(bytes)) => {
                if let Ok(stats) = parse_file(&bytes).and_then(|p| vault.merge_parsed(&p)) {
                    add(total, stats);
                    merged.push(rev.id.clone());
                }
            }
            // Drive won't serve it (gone): nothing to merge.
            Ok(None) => {}
            Err(_) => unverified = true,
        }
    }
    // Merged and nothing changed: those revisions were in `ours` already.
    let remerged = !merged.is_empty() && vault.differs_from(ours_fingerprint);
    if !remerged {
        covered.append(&mut merged);
    }
    if ours_pinned {
        for rev in &covered {
            // Best effort: a pin left behind costs one download on a later sync.
            let _ = api.unpin(file_id, rev).await;
        }
    }
    if remerged {
        for rev in &merged {
            push_unique(contained, rev);
        }
        return Settled::Remerged;
    }
    if unverified {
        Settled::Unverified
    } else {
        Settled::Clean
    }
}

/// Merges the pinned revisions of `file` other than its head that this vault doesn't hold yet
/// (see [`settle`]), and returns their ids. Best effort: what fails stays pinned for later.
async fn absorb_pinned<T: Transport>(
    api: &Api<'_, T>,
    vault: &Vault,
    file: &DriveFile,
    contained: &[String],
    total: &mut MergeStats,
) -> Vec<String> {
    let Some(head) = &file.head_revision_id else {
        return Vec::new();
    };
    let Ok(Some(revisions)) = api.revisions(&file.id).await else {
        return Vec::new();
    };
    let mut merged = Vec::new();
    for rev in revisions
        .iter()
        .filter(|r| r.keep_forever && r.id != *head && !contained.contains(&r.id))
    {
        if let Ok(Some(bytes)) = api.download_revision(&file.id, &rev.id).await {
            if let Ok(stats) = parse_file(&bytes).and_then(|p| vault.merge_parsed(&p)) {
                add(total, stats);
                merged.push(rev.id.clone());
            }
        }
    }
    merged
}

/// The end of a successful sync: the name, then the merged duplicates.
async fn finish<T: Transport>(
    api: &Api<'_, T>,
    vault: &Vault,
    config: &GDriveConfig,
    file: &DriveFile,
    key: &str,
    known: &mut Option<Known>,
    merged_duplicates: &[DriveFile],
) -> Result<()> {
    rename_if_needed(api, vault, config, file, key, known).await?;
    let left = cleanup(api, merged_duplicates).await;
    if let Some(k) = known.as_mut().filter(|k| k.twins != left) {
        k.twins = left;
        vault.set_sync_state(k.state(key));
    }
    Ok(())
}

/// Keeps the file's `pass_vault_name` in step with the vault's name on this device (one metadata
/// request, only when it differs).
async fn rename_if_needed<T: Transport>(
    api: &Api<'_, T>,
    vault: &Vault,
    config: &GDriveConfig,
    file: &DriveFile,
    key: &str,
    known: &mut Option<Known>,
) -> Result<()> {
    let wanted = config.vault_name.trim();
    if wanted.is_empty()
        || (file.app_properties.get(PROP_NAME).map(String::as_str) == Some(wanted)
            && file.app_properties.contains_key(PROP_VAULT_ID))
    {
        return Ok(());
    }
    if let Some(updated) = api
        .set_props(&file.id, &props(&vault.vault_id(), wanted))
        .await?
    {
        // The version moved. Note it only if the contents are still the ones we know (same
        // MD5): another device's upload may have landed just before the rename, and noting
        // its version would make the next sync skip it.
        if let Some(k) = known.as_mut().filter(|k| {
            k.file_id == updated.id
                && !k.md5.is_empty()
                && updated.md5_checksum.as_deref() == Some(k.md5.as_str())
        }) {
            k.version = updated.version();
            vault.set_sync_state(k.state(key));
        }
    }
    Ok(())
}

/// Deletes the merged duplicates that haven't changed since they were merged (best effort:
/// another device may be doing the same). Returns `true` when one is left (it changed, so the
/// device writing to it must be merged again, or the delete failed): the next sync looks again.
async fn cleanup<T: Transport>(api: &Api<'_, T>, merged: &[DriveFile]) -> bool {
    let mut left = false;
    for dup in merged {
        match api.get_file(&dup.id).await {
            Ok(None) => {}
            Ok(Some(now)) if now.version() == dup.version() => {
                if api.delete(&dup.id).await.is_err() {
                    left = true;
                }
            }
            _ => left = true,
        }
    }
    left
}

/// "Delete old versions from Google Drive" (see [`gdrive_delete_old_versions`]).
async fn old_versions_flow<T: Transport>(
    api: &Api<'_, T>,
    vault: &Vault,
    config: &GDriveConfig,
) -> Result<GDriveOldVersions> {
    let key = url_key(&format!("gdrive:{}", vault.vault_id()));
    for _ in 0..MAX_ATTEMPTS {
        // In step with Drive first: the head then holds everything this vault has, uploaded with
        // its current key (after a password change, the new one).
        sync_flow(api, vault, config).await?;
        let Some(known) = vault.sync_state(&key).and_then(Known::from_state) else {
            return Err(PassError::NotFound(tr!("gdrive.vault_gone")));
        };
        let Some(file) = api.get_file(&known.file_id).await? else {
            continue; // deleted meanwhile: the sync finds out what happened
        };
        let Some(revisions) = api.revisions(&file.id).await? else {
            continue;
        };
        // Never the head, nor the newest revision Drive listed (they are the same normally).
        let keep: Vec<&str> = [
            file.head_revision_id.as_deref(),
            revisions.last().map(|r| r.id.as_str()),
        ]
        .into_iter()
        .flatten()
        .collect();
        let mut result = GDriveOldVersions::default();
        let mut old: Vec<&str> = Vec::new();
        for rev in revisions.iter().filter(|r| !keep.contains(&r.id.as_str())) {
            if !rev.keep_forever {
                // Unpinned: its contents were in a later upload when it was unpinned (`settle`).
                old.push(&rev.id);
                continue;
            }
            // Pinned: possibly another device's write a later upload overwrote, not merged yet.
            match api.download_revision(&file.id, &rev.id).await {
                Ok(Some(bytes)) => match parse_file(&bytes).map(|p| vault.merge_parsed(&p)) {
                    Ok(Ok(_)) => old.push(&rev.id),
                    // A copy under a key this vault no longer has (an old password's copy): what
                    // it holds is on the device that wrote it, which merges it when it updates.
                    Ok(Err(PassError::Crypto(_))) => old.push(&rev.id),
                    // Not readable by this version: left for the device that wrote it.
                    Ok(Err(_)) | Err(_) => result.kept += 1,
                },
                Ok(None) => {}
                Err(e @ PassError::AuthRequired(_)) => return Err(e),
                Err(_) => result.unfinished = true,
            }
        }
        if vault.differs_from(&known.fingerprint) {
            // An old version held something this vault lacked: upload it first, then look again.
            continue;
        }
        for rev in old {
            match api.delete_revision(&file.id, rev).await {
                Ok(RevisionDelete::Deleted) => result.removed += 1,
                Ok(RevisionDelete::Gone) => {}
                Ok(RevisionDelete::Refused) => result.kept += 1,
                Err(e @ PassError::AuthRequired(_)) => return Err(e),
                Err(e) if result.removed == 0 => return Err(e),
                Err(_) => {
                    result.unfinished = true;
                    break;
                }
            }
        }
        return Ok(result);
    }
    Err(PassError::Conflict(tr!("gdrive.kept_changing")))
}

/// "Remove vault from Google Drive" (see [`gdrive_remove_vault`]): the number of files deleted.
async fn remove_flow<T: Transport>(api: &Api<'_, T>, vault_id: &str) -> Result<u32> {
    let vault_id = vault_id.trim();
    // A vault id is a UUID; anything else can't be one of Passyble's files.
    if vault_id.is_empty() || !vault_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(PassError::NotFound(tr!("gdrive.vault_gone")));
    }
    let name = file_name(vault_id);
    let removed = removed_file_name(vault_id);
    // Only the app's own folder is listed (`spaces=appDataFolder`), and only this vault's files
    // (twins from two devices creating it at once included) are deleted from it.
    let files = api.list("trashed = false").await?;
    let ours: Vec<&DriveFile> = files
        .iter()
        .filter(|f| {
            f.name == name
                || f.app_properties.get(PROP_VAULT_ID).map(String::as_str) == Some(vault_id)
        })
        .collect();
    // The marker first: should a delete fail, other devices still don't upload the vault again.
    if !files.iter().any(|f| f.name == removed) {
        let marker = HashMap::from([(PROP_REMOVED.to_string(), vault_id.to_string())]);
        api.create_marker(&removed, &marker).await?;
    }
    let mut deleted = 0;
    for file in ours {
        api.delete(&file.id).await?;
        deleted += 1;
    }
    Ok(deleted)
}

async fn list_flow<T: Transport>(api: &Api<'_, T>) -> Result<Vec<GDriveVault>> {
    let files = api.list("trashed = false").await?;
    let mut vaults: Vec<GDriveVault> = files
        .into_iter()
        .filter_map(|f| {
            let from_name = f
                .name
                .strip_prefix(FILE_PREFIX)
                .and_then(|n| n.strip_suffix(FILE_SUFFIX))
                .map(str::to_string);
            let vault_id = f.app_properties.get(PROP_VAULT_ID).cloned().or(from_name)?;
            Some(GDriveVault {
                vault_id,
                name: f.app_properties.get(PROP_NAME).cloned().unwrap_or_default(),
                modified: f.modified_time.as_deref().map_or(0, rfc3339_ms),
                size: f.size.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
                file_id: f.id,
            })
        })
        .collect();
    vaults.sort_by(|a, b| b.modified.cmp(&a.modified).then(a.name.cmp(&b.name)));
    // Duplicates of one vault (simultaneous creation): list it once, the newest copy.
    let mut seen = std::collections::HashSet::new();
    vaults.retain(|v| seen.insert(v.vault_id.clone()));
    Ok(vaults)
}

async fn download_flow<T: Transport>(api: &Api<'_, T>, file_id: &str) -> Result<Vec<u8>> {
    api.download(file_id)
        .await?
        .ok_or_else(|| PassError::NotFound(tr!("gdrive.vault_gone")))
}

// ---- the apps: blocking calls over ureq ----------------------------------------------------------

#[cfg(feature = "gdrive")]
mod blocking {
    use std::io::Read;
    use std::time::Duration;

    use super::*;
    use crate::http::block_on;
    use crate::net;

    /// The apps' transport: ureq, answering inside `send`.
    pub(crate) struct UreqTransport {
        agent: ureq::Agent,
    }

    impl UreqTransport {
        pub(crate) fn new() -> Self {
            Self {
                agent: ureq::AgentBuilder::new()
                    .timeout_connect(Duration::from_secs(10))
                    .timeout(Duration::from_secs(60))
                    .build(),
            }
        }

        pub(crate) fn send_now(&self, request: HttpRequest, action: &str) -> Result<HttpResponse> {
            let mut call = self.agent.request(&request.method, &request.url);
            for (name, value) in &request.headers {
                call = call.set(name, value);
            }
            let sent =
                if request.body.is_empty() && matches!(request.method.as_str(), "GET" | "DELETE") {
                    call.call()
                } else {
                    call.send_bytes(&request.body)
                };
            let response = match sent {
                Ok(r) | Err(ureq::Error::Status(_, r)) => r,
                Err(ureq::Error::Transport(t)) => {
                    return Err(net::transport_error(action, &t, GOOGLE_API, || {
                        unexpected(action)
                    }))
                }
            };
            let status = response.status();
            let headers = response
                .headers_names()
                .into_iter()
                .filter_map(|name| {
                    let value = response.header(&name)?.to_string();
                    Some((name, value))
                })
                .collect();
            let mut body = Vec::new();
            response
                .into_reader()
                .take(MAX_VAULT_BYTES)
                .read_to_end(&mut body)
                .map_err(|e| net::read_error(action, &e, || unexpected(action)))?;
            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        }
    }

    impl Transport for UreqTransport {
        async fn send(&self, request: HttpRequest, action: &str) -> Result<HttpResponse> {
            self.send_now(request, action)
        }
    }

    /// Runs `f` against `base` with a fresh ureq transport.
    pub(crate) fn run<R, F>(base: &Endpoints, token: &str, f: F) -> Result<R>
    where
        F: AsyncFnOnce(&Api<'_, UreqTransport>) -> Result<R>,
    {
        let http = UreqTransport::new();
        let api = Api::new(&http, token, base)?;
        block_on(f(&api))
    }
}

/// [`gdrive_sync`] against `base`.
#[cfg(feature = "gdrive")]
pub(crate) fn sync_with(
    base: &Endpoints,
    vault: &Vault,
    config: &GDriveConfig,
) -> Result<SyncResult> {
    blocking::run(base, &config.access_token, async |api| {
        sync_flow(api, vault, config).await
    })
}

/// Syncs `vault` with its file in the Google Drive app folder. Blocking. A refused token is
/// [`PassError::AuthRequired`]. The Drive file id, version and MD5 are kept in the vault's local
/// sync state, so persist the vault if it is dirty afterwards.
#[cfg(feature = "gdrive")]
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn gdrive_sync(vault: Arc<Vault>, config: GDriveConfig) -> Result<SyncResult> {
    sync_with(&Endpoints::google(), &vault, &config)
}

#[cfg(feature = "gdrive")]
pub(crate) fn list_with(base: &Endpoints, access_token: &str) -> Result<Vec<GDriveVault>> {
    blocking::run(base, access_token, async |api| list_flow(api).await)
}

/// The vaults in this Google account's Pass app folder, newest first, for "Restore from Google
/// Drive". Only names, ids, sizes and dates: nothing is downloaded.
#[cfg(feature = "gdrive")]
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn gdrive_list_vaults(access_token: String) -> Result<Vec<GDriveVault>> {
    list_with(&Endpoints::google(), &access_token)
}

#[cfg(feature = "gdrive")]
pub(crate) fn download_with(
    base: &Endpoints,
    access_token: &str,
    file_id: &str,
) -> Result<Vec<u8>> {
    blocking::run(base, access_token, async |api| {
        download_flow(api, file_id).await
    })
}

/// Downloads a vault file (from [`gdrive_list_vaults`]) for setting up a new device. Unlock it
/// with `Vault::unlock`, then keep it in step with [`gdrive_sync`].
#[cfg(feature = "gdrive")]
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn gdrive_download(access_token: String, file_id: String) -> Result<Vec<u8>> {
    download_with(&Endpoints::google(), &access_token, &file_id)
}

#[cfg(feature = "gdrive")]
pub(crate) fn delete_with(base: &Endpoints, access_token: &str, file_id: &str) -> Result<()> {
    blocking::run(base, access_token, async |api| api.delete(file_id).await)
}

/// Deletes a vault's copy from Google Drive for good ("Stop backing up and delete the copy").
/// Local copies are not touched. 404 counts as done.
#[cfg(feature = "gdrive")]
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn gdrive_delete(access_token: String, file_id: String) -> Result<()> {
    delete_with(&Endpoints::google(), &access_token, &file_id)
}

#[cfg(feature = "gdrive")]
pub(crate) fn old_versions_with(
    base: &Endpoints,
    vault: &Vault,
    config: &GDriveConfig,
) -> Result<GDriveOldVersions> {
    blocking::run(base, &config.access_token, async |api| {
        old_versions_flow(api, vault, config).await
    })
}

/// Deletes the old versions Google Drive keeps of `vault`'s file ("Delete old versions from Google
/// Drive"), for instance after a password change, since they still open with the old password.
///
/// Syncs first so the head holds the current contents; the head always stays. A pinned old version
/// is merged before it goes, and any change it held is uploaded first. Versions this build can't
/// read, or that Drive won't delete, are `kept`; `unfinished` means try again later. Persist the
/// vault when it is dirty afterwards. Blocking.
#[cfg(feature = "gdrive")]
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn gdrive_delete_old_versions(
    vault: Arc<Vault>,
    config: GDriveConfig,
) -> Result<GDriveOldVersions> {
    old_versions_with(&Endpoints::google(), &vault, &config)
}

#[cfg(feature = "gdrive")]
pub(crate) fn remove_with(base: &Endpoints, access_token: &str, vault_id: &str) -> Result<u32> {
    blocking::run(base, access_token, async |api| {
        remove_flow(api, vault_id).await
    })
}

/// "Remove vault from Google Drive": deletes vault `vault_id`'s file (with its old versions, and
/// any twin) from the app folder and leaves a small marker there, so other devices syncing it stop
/// (`gdrive.vault_removed`) instead of uploading it again. Other vaults' files and anything outside
/// the app folder are never touched; local copies neither. Returns the number of files deleted
/// (0: none was there). Turn the backup off for the vault on this device afterwards. Blocking.
#[cfg(feature = "gdrive")]
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn gdrive_remove_vault(access_token: String, vault_id: String) -> Result<u32> {
    remove_with(&Endpoints::google(), &access_token, &vault_id)
}

#[cfg(feature = "gdrive")]
pub(crate) fn account_with(base: &Endpoints, access_token: &str) -> Result<GDriveAccount> {
    blocking::run(base, access_token, async |api| api.about().await)
}

/// The Google account of `access_token` (`about.get`, allowed with the `drive.appdata` scope).
#[cfg(feature = "gdrive")]
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn gdrive_account(access_token: String) -> Result<GDriveAccount> {
    account_with(&Endpoints::google(), &access_token)
}

// ---- the browser extension: the same code, one request at a time --------------------------------

/// An [`Exchange`] running `f` against `base` (a token refused before any request: `Done` at once).
fn exchange_with<R: 'static>(
    base: Endpoints,
    token: String,
    f: impl AsyncFnOnce(&Api<'_, crate::http::HostTransport>) -> Result<R> + 'static,
) -> (Exchange<R>, Step<R>) {
    Exchange::start(move |http| async move {
        let api = Api::new(&http, &token, &base)?;
        f(&api).await
    })
}

pub(crate) fn sync_exchange_with(
    base: Endpoints,
    vault: Arc<Vault>,
    config: GDriveConfig,
) -> (Exchange<SyncResult>, Step<SyncResult>) {
    let token = config.access_token.clone();
    exchange_with(base, token, async move |api| {
        sync_flow(api, &vault, &config).await
    })
}

/// [`gdrive_sync`] driven by the host request by request (the browser extension's `fetch`): the
/// same requests, merge and sync state. Persist the vault once it is `Done` (it is dirty then).
pub fn gdrive_sync_exchange(
    vault: Arc<Vault>,
    config: GDriveConfig,
) -> (Exchange<SyncResult>, Step<SyncResult>) {
    sync_exchange_with(Endpoints::google(), vault, config)
}

pub(crate) fn list_exchange_with(
    base: Endpoints,
    access_token: String,
) -> (Exchange<Vec<GDriveVault>>, Step<Vec<GDriveVault>>) {
    exchange_with(base, access_token, async |api| list_flow(api).await)
}

/// [`gdrive_list_vaults`], driven by the host.
pub fn gdrive_list_exchange(
    access_token: String,
) -> (Exchange<Vec<GDriveVault>>, Step<Vec<GDriveVault>>) {
    list_exchange_with(Endpoints::google(), access_token)
}

pub(crate) fn download_exchange_with(
    base: Endpoints,
    access_token: String,
    file_id: String,
) -> (Exchange<Vec<u8>>, Step<Vec<u8>>) {
    exchange_with(base, access_token, async move |api| {
        download_flow(api, &file_id).await
    })
}

/// [`gdrive_download`], driven by the host.
pub fn gdrive_download_exchange(
    access_token: String,
    file_id: String,
) -> (Exchange<Vec<u8>>, Step<Vec<u8>>) {
    download_exchange_with(Endpoints::google(), access_token, file_id)
}

/// [`gdrive_account`], driven by the host.
pub fn gdrive_account_exchange(
    access_token: String,
) -> (Exchange<GDriveAccount>, Step<GDriveAccount>) {
    exchange_with(Endpoints::google(), access_token, async |api| {
        api.about().await
    })
}

/// `2026-10-09T12:34:56.789Z` (or with an offset) → Unix milliseconds; 0 if unparsable.
fn rfc3339_ms(s: &str) -> i64 {
    fn num(s: &str) -> Option<i64> {
        s.parse().ok()
    }
    let parse = || -> Option<i64> {
        let (date, rest) = s.split_once(['T', 't', ' '])?;
        let mut d = date.split('-');
        let (y, m, day) = (num(d.next()?)?, num(d.next()?)?, num(d.next()?)?);
        let (time, offset_min) = if let Some(t) = rest.strip_suffix(['Z', 'z']) {
            (t, 0)
        } else {
            let at = rest.rfind(['+', '-'])?;
            let (t, off) = rest.split_at(at);
            let sign = if off.starts_with('-') { -1 } else { 1 };
            let (oh, om) = off[1..].split_once(':')?;
            let (oh, om) = (num(oh)?, num(om)?);
            if !(0..=24).contains(&oh) || !(0..=59).contains(&om) {
                return None;
            }
            (t, sign * (oh * 60 + om))
        };
        let (hms, frac) = time.split_once('.').unwrap_or((time, ""));
        let mut t = hms.split(':');
        let (h, mi, sec) = (num(t.next()?)?, num(t.next()?)?, num(t.next()?)?);
        let millis = format!("{frac:0<3}").get(..3).and_then(num).unwrap_or(0);
        // Out-of-range fields would overflow the arithmetic below (a panic in debug builds).
        let in_range = (0..=9999).contains(&y)
            && (1..=12).contains(&m)
            && (1..=31).contains(&day)
            && (0..=24).contains(&h)
            && (0..=59).contains(&mi)
            && (0..=60).contains(&sec)
            && (-24 * 60..=24 * 60).contains(&offset_min)
            && (0..=999).contains(&millis);
        if !in_range {
            return None;
        }
        // Days from civil (Howard Hinnant).
        let y = if m <= 2 { y - 1 } else { y };
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let mp = (m + 9) % 12;
        let doy = (153 * mp + 2) / 5 + day - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146_097 + doe - 719_468;
        Some(((days * 86_400 + h * 3600 + mi * 60 + sec - offset_min * 60) * 1000) + millis)
    };
    parse().unwrap_or(0)
}

#[cfg(all(test, feature = "gdrive"))]
mod tests;
