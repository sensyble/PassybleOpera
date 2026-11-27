//! Sync through any WebDAV server (Nextcloud, ownCloud, Synology, Apache mod_dav, …).
//! The server only ever sees the encrypted vault file.

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use crate::encoding::b64_encode;
use crate::i18n::tr;
use crate::net;
use crate::pinning::{normalize_pins, PinVerifier};
use crate::vault::{parse_file, url_key, MergeStats, SyncResult, SyncState, Vault};
use crate::{PassError, Result};

const MAX_VAULT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ATTEMPTS: usize = 4;

#[derive(Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct WebDavConfig {
    /// Full URL of the vault file, e.g. `https://cloud.example.com/remote.php/dav/files/me/pass.vault`.
    pub url: String,
    pub username: String,
    pub password: String,
    /// Certificate pins (`sha256:<base64url>`) from a Passyble Server pairing link. Empty: validate against
    /// the public CA roots. Non-empty: the server key must match one of them and CA validation is skipped.
    #[cfg_attr(feature = "uniffi", uniffi(default = []))]
    pub pins: Vec<String>,
}

impl std::fmt::Debug for WebDavConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebDavConfig")
            .field("url", &self.url)
            .field("username", &self.username)
            .field("pins", &self.pins)
            .finish_non_exhaustive()
    }
}

struct Remote {
    bytes: Vec<u8>,
    etag: Option<String>,
}

/// An HTTP agent for one operation, with the pin verifier when the config has pins.
struct Client {
    agent: ureq::Agent,
    pins: Option<Arc<PinVerifier>>,
    /// The vault's URL, for the host in "can't connect" messages.
    url: String,
}

fn client(config: &WebDavConfig) -> Result<Client> {
    // Plain http:// only to this device or a private network (same rule as Passyble Server addresses),
    // so the app password and the vault never cross the internet unencrypted.
    crate::server::check_plain_http(&config.url)?;
    let mut builder = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(60));
    let pins = normalize_pins(&config.pins)?;
    let verifier = if pins.is_empty() {
        None
    } else {
        let verifier = PinVerifier::new(pins);
        builder = builder.tls_config(verifier.client_config()?);
        Some(verifier)
    };
    Ok(Client {
        agent: builder.build(),
        pins: verifier,
        url: config.url.clone(),
    })
}

fn auth(config: &WebDavConfig) -> String {
    format!(
        "Basic {}",
        b64_encode(format!("{}:{}", config.username, config.password).as_bytes())
    )
}

impl Client {
    fn error(&self, action: &str, err: ureq::Error) -> PassError {
        // Passyble Server's shared vault and Passyble Cloud codes (a viewer's upload, a plan that
        // ended, a removed member): their own words, not "authentication failed".
        if let ureq::Error::Status(_, response) = &err {
            if let Some(e) = crate::server::shared_vault_error_of(response) {
                return e;
            }
        }
        match err {
            ureq::Error::Status(401 | 403, _) => {
                PassError::Network(tr!("webdav.auth_failed", action = action))
            }
            ureq::Error::Status(409, _) => {
                PassError::Network(tr!("webdav.no_parent_folder", action = action))
            }
            // Passyble Server's per-account storage quota; its text/plain body says what to do.
            ureq::Error::Status(507, response) => PassError::Network(
                match error_text(response).and_then(|text| net::plain_message(&text)) {
                    Some(message) => tr!(
                        "webdav.quota_reached_detail",
                        action = action,
                        detail = message
                    ),
                    None => tr!("webdav.quota_reached", action = action),
                },
            ),
            ureq::Error::Status(code, _) => net::status_error(action, code),
            ureq::Error::Transport(t) => match self.pins.as_ref().and_then(|v| v.rejected()) {
                Some(seen) => {
                    PassError::CertificateChanged(tr!("webdav.certificate_not_paired", key = seen))
                }
                None => {
                    net::transport_error(action, &t, &self.url, || net::unexpected_answer(action))
                }
            },
        }
    }
}

/// Longest server message shown in an error, in characters.
const MAX_ERROR_TEXT: usize = 300;

/// The body of an error response if it is `text/plain` and valid UTF-8: trimmed and capped.
fn error_text(response: ureq::Response) -> Option<String> {
    if response.content_type() != "text/plain" {
        return None;
    }
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(4096)
        .read_to_end(&mut bytes)
        .ok()?;
    let text = match std::str::from_utf8(&bytes) {
        Ok(t) => t,
        Err(e) if e.error_len().is_none() => std::str::from_utf8(&bytes[..e.valid_up_to()]).ok()?,
        Err(_) => return None,
    };
    let text = text.trim();
    (!text.is_empty()).then(|| text.chars().take(MAX_ERROR_TEXT).collect())
}

/// What a (conditional) GET returned.
enum Fetched {
    /// 304: the remote file still has the ETag we sent in `If-None-Match`. No body was sent.
    NotModified,
    /// 404: no file yet.
    Missing,
    Body(Remote),
}

/// GET, with `If-None-Match: <known_etag>` when there is one so an unchanged file costs a 304 and
/// no body.
fn fetch(client: &Client, config: &WebDavConfig, known_etag: Option<&str>) -> Result<Fetched> {
    let mut request = client
        .agent
        .get(&config.url)
        .set("Authorization", &auth(config))
        .set("Cache-Control", "no-cache");
    if let Some(etag) = known_etag {
        request = request.set("If-None-Match", etag);
    }
    match request.call() {
        Ok(response) if response.status() == 304 => Ok(Fetched::NotModified),
        Ok(response) => {
            let etag = response.header("ETag").map(str::to_string);
            let mut bytes = Vec::new();
            response
                .into_reader()
                .take(MAX_VAULT_BYTES)
                .read_to_end(&mut bytes)
                .map_err(|e| {
                    let action = tr!("action.download");
                    net::read_error(&action, &e, || net::unexpected_answer(&action))
                })?;
            Ok(Fetched::Body(Remote { bytes, etag }))
        }
        Err(ureq::Error::Status(404, _)) => Ok(Fetched::Missing),
        Err(err) => Err(client.error(&tr!("action.download"), err)),
    }
}

fn download(client: &Client, config: &WebDavConfig) -> Result<Option<Remote>> {
    match fetch(client, config, None)? {
        Fetched::Body(remote) => Ok(Some(remote)),
        Fetched::Missing => Ok(None),
        Fetched::NotModified => Err(PassError::Network(tr!(
            "webdav.unexpected_304",
            action = tr!("action.download")
        ))),
    }
}

enum Uploaded {
    /// Stored; the new ETag if the server sent one.
    Stored(Option<String>),
    /// 412: someone else wrote first.
    Conflict,
}

/// Uploads with optimistic concurrency.
fn upload(
    client: &Client,
    config: &WebDavConfig,
    bytes: &[u8],
    etag: Option<&str>,
    create: bool,
) -> Result<Uploaded> {
    let mut request = client
        .agent
        .put(&config.url)
        .set("Authorization", &auth(config))
        .set("Content-Type", "application/octet-stream");
    if create {
        request = request.set("If-None-Match", "*");
    } else if let Some(etag) = etag {
        request = request.set("If-Match", etag);
    }
    match request.send_bytes(bytes) {
        Ok(response) => Ok(Uploaded::Stored(
            response.header("ETag").map(str::to_string),
        )),
        Err(ureq::Error::Status(412, _)) => Ok(Uploaded::Conflict),
        Err(err) => Err(client.error(&tr!("action.upload"), err)),
    }
}

/// A weak ETag (`W/"..."`).
fn is_weak(etag: &str) -> bool {
    etag.trim_start().starts_with("W/")
}

/// Syncs `vault` with the WebDAV copy, talking to the server as little as possible. Blocking.
///
/// Uses the remote ETag and last-merged contents stored in the vault: an unchanged remote costs one
/// conditional `GET` (304), a changed one is downloaded and merged, and a `PUT` with `If-Match` follows
/// only when this vault has something the remote lacks. A `412` downloads, merges and retries. Servers
/// that ignore `If-None-Match` are handled by recognising already merged contents. Leaves the vault dirty
/// after a merge or sync-state change so the caller persists it.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn webdav_sync(vault: Arc<Vault>, config: WebDavConfig) -> Result<SyncResult> {
    let client = client(&config)?;
    let key = url_key(&config.url);
    let mut known = vault.sync_state(&key);
    let mut total = MergeStats::default();
    let mut weak_rejected = false;
    let done = |stats: MergeStats, uploaded: bool, created_remote: bool, remote_bytes| {
        Ok(SyncResult {
            stats,
            uploaded,
            created_remote,
            remote_bytes,
        })
    };
    for _ in 0..MAX_ATTEMPTS {
        let known_etag = known.as_ref().and_then(|k| k.etag.clone());
        let (etag, create) = match fetch(&client, &config, known_etag.as_deref())? {
            Fetched::NotModified => {
                let Some(state) = &known else {
                    return Err(PassError::Network(tr!(
                        "webdav.unexpected_304",
                        action = tr!("action.download")
                    )));
                };
                if !vault.differs_from(&state.fingerprint) {
                    return done(total, false, false, state.bytes);
                }
                (known_etag, false)
            }
            Fetched::Missing => (None, true),
            Fetched::Body(remote) => {
                let parsed = parse_file(&remote.bytes)?;
                let fingerprint = parsed.fingerprint();
                // Same contents as last time (server ignores If-None-Match or has no ETags): already merged.
                let seen = known.as_ref().is_some_and(|k| k.fingerprint == fingerprint);
                if !seen {
                    let stats = vault.merge_parsed(&parsed)?;
                    total.added += stats.added;
                    total.updated += stats.updated;
                    total.deleted += stats.deleted;
                    total.unchanged = stats.unchanged;
                }
                let state = SyncState {
                    url: key.clone(),
                    etag: remote.etag.clone(),
                    fingerprint,
                    bytes: Some(remote.bytes.len() as u64),
                };
                vault.set_sync_state(state.clone());
                known = Some(state);
                if !vault.remote_is_behind(&parsed) {
                    return done(total, false, false, Some(remote.bytes.len() as u64));
                }
                (remote.etag, false)
            }
        };
        // `If-Match` uses strong comparison (RFC 9110 §13.1.1), so a weak ETag can never match and every
        // conditional PUT would be a 412. Try once anyway, then download and merge again, and if the server
        // still only offers weak ETags upload unconditionally. Safe because merges are per item and
        // convergent: a write lost in that window is uploaded again by its device (`Vault::remote_is_behind`).
        let sent_weak = etag.as_deref().is_some_and(is_weak);
        let etag = if sent_weak && weak_rejected {
            None
        } else {
            etag
        };
        let (bytes, fingerprint) = vault.snapshot()?;
        match upload(&client, &config, &bytes, etag.as_deref(), create)? {
            Uploaded::Stored(new_etag) => {
                vault.set_sync_state(SyncState {
                    url: key,
                    etag: new_etag,
                    fingerprint,
                    bytes: Some(bytes.len() as u64),
                });
                return done(total, true, create, Some(bytes.len() as u64));
            }
            // Lost the race: download the other version unconditionally, merge and retry.
            Uploaded::Conflict => {
                weak_rejected |= sent_weak;
                if let Some(k) = known.as_mut() {
                    k.etag = None;
                }
            }
        }
    }
    Err(PassError::Conflict(tr!("webdav.kept_changing")))
}

/// Replaces the remote file with `vault` without merging, e.g. "Start a new empty vault" after a password
/// reset. Reads the current ETag (`HEAD`), then `PUT`s with `If-Match` (or `If-None-Match: *` if there is
/// no file); a `412` retries up to 4 times, then `Conflict`. Passyble Server keeps the replaced file as a
/// version. Records the sync state like [`webdav_sync`]; persist the vault afterwards.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn webdav_replace(config: WebDavConfig, vault: Arc<Vault>) -> Result<()> {
    let client = client(&config)?;
    let (bytes, fingerprint) = vault.snapshot()?;
    for _ in 0..MAX_ATTEMPTS {
        let current = match client
            .agent
            .head(&config.url)
            .set("Authorization", &auth(&config))
            .set("Cache-Control", "no-cache")
            .call()
        {
            Ok(r) => Some(r.header("ETag").map(str::to_string).ok_or_else(|| {
                PassError::Network(tr!("webdav.no_etag", action = tr!("action.replace")))
            })?),
            Err(ureq::Error::Status(404, _)) => None,
            Err(err) => return Err(client.error(&tr!("action.replace"), err)),
        };
        match upload(
            &client,
            &config,
            &bytes,
            current.as_deref(),
            current.is_none(),
        )? {
            Uploaded::Stored(etag) => {
                vault.set_sync_state(SyncState {
                    url: url_key(&config.url),
                    etag,
                    fingerprint,
                    bytes: Some(bytes.len() as u64),
                });
                return Ok(());
            }
            Uploaded::Conflict => continue,
        }
    }
    Err(PassError::Conflict(tr!("webdav.kept_changing")))
}

/// Fetches the vault file, for setting up a new device. Unlock the bytes with `Vault::unlock`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn webdav_download(config: WebDavConfig) -> Result<Vec<u8>> {
    download(&client(&config)?, &config)?
        .map(|remote| remote.bytes)
        .ok_or_else(|| PassError::NotFound(tr!("webdav.no_vault")))
}

/// Connection test: `true` if the vault file exists, `false` if the server answers 404 (a new
/// Passyble Server vault before its first upload). Authentication, access and certificate problems
/// are errors, as in [`webdav_sync`]. Blocking.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn webdav_exists(config: WebDavConfig) -> Result<bool> {
    let client = client(&config)?;
    match client
        .agent
        .head(&config.url)
        .set("Authorization", &auth(&config))
        .set("Cache-Control", "no-cache")
        .call()
    {
        Ok(_) => Ok(true),
        Err(ureq::Error::Status(404, _)) => Ok(false),
        Err(err) => Err(client.error(&tr!("action.connect"), err)),
    }
}
