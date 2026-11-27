//! Google Drive for the browser vault. pass-core's own Drive code runs here, and the extension
//! only performs the HTTP requests with `fetch` ([`pass_core::Exchange`]). It never decides
//! anything about the vault.
//!
//! A step is `{"send": {"method", "url", "headers"}}` or `{"done": {"result"}}` /
//! `{"done": {"error": {"code", "message"}}}`.
//! Error codes: `auth_required` (get a new token and retry once), `network` (retry later),
//! `conflict`, `not_found`, `corrupt`, `locked`, `internal`.

use std::sync::Arc;

use pass_agent::{Agent, ErrorCode, RpcError};
use pass_core::{
    Exchange, FetchFailure, GDriveAccount, GDriveConfig, GDriveVault, HttpRequest, HttpResponse,
    PassError, Step, SyncResult, Vault,
};
use serde_json::{json, Value};

use crate::host::BrowserHost;
use crate::ui::{BrowserUi, Effect};

/// The vault that was synced and the agent that should keep it.
struct SyncFinish {
    agent: Arc<Agent>,
    ui: Arc<BrowserUi>,
    vault: Arc<Vault>,
}

enum Op {
    Sync(Exchange<SyncResult>, SyncFinish),
    List(Exchange<Vec<GDriveVault>>),
    Download(Exchange<Vec<u8>>),
    Account(Exchange<GDriveAccount>),
}

/// One Google Drive operation, driven by the host: [`DriveCall::begin`], then for every `send` the
/// host's [`DriveCall::respond`] (any HTTP status) or [`DriveCall::fail`] (no answer), until `done`.
pub struct DriveCall {
    op: Op,
    first: Option<String>,
    body: Option<Vec<u8>>,
    bytes: Option<Vec<u8>>,
}

fn error_json(code: &str, message: &str) -> Value {
    json!({ "error": { "code": code, "message": message } })
}

/// The code and the user-facing text of a core error (without its English kind prefix).
fn pass_error(e: &PassError) -> Value {
    let (code, message) = match e {
        PassError::AuthRequired(m) => ("auth_required", m.as_str()),
        PassError::Network(m) => ("network", m.as_str()),
        PassError::Conflict(m) => ("conflict", m.as_str()),
        PassError::NotFound(m) => ("not_found", m.as_str()),
        PassError::Corrupt(m) | PassError::Crypto(m) => ("corrupt", m.as_str()),
        PassError::InvalidPassword => (
            "corrupt",
            "the Drive copy doesn't open with this vault's key",
        ),
        PassError::InvalidInput(m) | PassError::CertificateChanged(m) => ("internal", m.as_str()),
    };
    error_json(code, message)
}

impl SyncFinish {
    /// Saves what the sync merged, unless the vault was locked or replaced meanwhile.
    fn done(&self, result: &SyncResult) -> Value {
        let current = self
            .agent
            .peek_vault()
            .is_some_and(|v| Arc::ptr_eq(&v, &self.vault));
        if current {
            if let Err(e) = self.agent.save() {
                return pass_error(&e);
            }
            let s = &result.stats;
            if s.added + s.updated + s.deleted > 0 {
                self.ui.push_effect(Effect::VaultChanged);
            }
        }
        json!({ "result": {
            "uploaded": result.uploaded,
            "created_remote": result.created_remote,
            "added": result.stats.added,
            "updated": result.stats.updated,
            "deleted": result.stats.deleted,
            "remote_bytes": result.remote_bytes,
            "current": current,
        } })
    }
}

impl DriveCall {
    /// Syncs the open vault with its file in Drive (created there on the first sync). `vault_name`
    /// is kept with the file so other devices list it by name. `locked` while locked.
    pub fn sync(host: &BrowserHost, token: &str, vault_name: &str) -> Result<DriveCall, RpcError> {
        let vault = host
            .agent()
            .peek_vault()
            .ok_or_else(|| RpcError::new(ErrorCode::Locked, "Vault is locked"))?;
        let (exchange, first) = pass_core::gdrive_sync_exchange(
            vault.clone(),
            GDriveConfig {
                access_token: token.to_string(),
                vault_name: vault_name.trim().to_string(),
                start_again: false,
            },
        );
        let finish = SyncFinish {
            agent: host.agent().clone(),
            ui: host.ui().clone(),
            vault,
        };
        let mut call = DriveCall::new(Op::Sync(exchange, finish));
        call.first = Some(call.step_sync(first));
        Ok(call)
    }

    /// The vaults in the account's Passyble app folder, newest first. Nothing is downloaded.
    pub fn list(token: &str) -> DriveCall {
        let (exchange, first) = pass_core::gdrive_list_exchange(token.to_string());
        let mut call = DriveCall::new(Op::List(exchange));
        call.first = Some(call.step_list(first));
        call
    }

    /// One vault file: `{"size"}`, and the bytes with [`DriveCall::take_bytes`].
    pub fn download(token: &str, file_id: &str) -> DriveCall {
        let (exchange, first) =
            pass_core::gdrive_download_exchange(token.to_string(), file_id.to_string());
        let mut call = DriveCall::new(Op::Download(exchange));
        call.first = Some(call.step_download(first));
        call
    }

    /// The Google account of the token: `{"email", "display_name"}`.
    pub fn account(token: &str) -> DriveCall {
        let (exchange, first) = pass_core::gdrive_account_exchange(token.to_string());
        let mut call = DriveCall::new(Op::Account(exchange));
        call.first = Some(call.step_account(first));
        call
    }

    fn new(op: Op) -> DriveCall {
        DriveCall {
            op,
            first: None,
            body: None,
            bytes: None,
        }
    }

    /// The first step (once).
    pub fn begin(&mut self) -> String {
        self.first.take().unwrap_or_else(|| {
            json!({ "done": error_json("internal", "begin was called twice") }).to_string()
        })
    }

    /// The host's answer to the last `send`. `headers` is `[[name, value], ...]` or an object.
    pub fn respond(&mut self, status: u16, headers: &str, body: Vec<u8>) -> String {
        let response = HttpResponse {
            status,
            headers: parse_headers(headers),
            body,
        };
        self.advance(move |step| match step {
            Advance::Sync(ex) => ex.on_response(response).into(),
            Advance::List(ex) => ex.on_response(response).into(),
            Advance::Download(ex) => ex.on_response(response).into(),
            Advance::Account(ex) => ex.on_response(response).into(),
        })
    }

    /// The last `send` got no answer: `"offline"`, `"timeout"`, `"bad_address"`, ...
    pub fn fail(&mut self, kind: &str) -> String {
        let failure = FetchFailure::from_name(kind);
        self.advance(|step| match step {
            Advance::Sync(ex) => ex.on_failure(failure).into(),
            Advance::List(ex) => ex.on_failure(failure).into(),
            Advance::Download(ex) => ex.on_failure(failure).into(),
            Advance::Account(ex) => ex.on_failure(failure).into(),
        })
    }

    /// The body of the request of the last `send` (empty for most), taken once.
    pub fn take_body(&mut self) -> Option<Vec<u8>> {
        self.body.take()
    }

    /// A finished download's vault file, taken once.
    pub fn take_bytes(&mut self) -> Option<Vec<u8>> {
        self.bytes.take()
    }

    fn advance(&mut self, f: impl FnOnce(Advance<'_>) -> AnyStep) -> String {
        let step = match &mut self.op {
            Op::Sync(ex, _) => f(Advance::Sync(ex)),
            Op::List(ex) => f(Advance::List(ex)),
            Op::Download(ex) => f(Advance::Download(ex)),
            Op::Account(ex) => f(Advance::Account(ex)),
        };
        match step {
            AnyStep::Sync(s) => self.step_sync(s),
            AnyStep::List(s) => self.step_list(s),
            AnyStep::Download(s) => self.step_download(s),
            AnyStep::Account(s) => self.step_account(s),
        }
    }

    fn send(&mut self, request: HttpRequest) -> String {
        let HttpRequest {
            method,
            url,
            headers,
            body,
        } = request;
        self.body = Some(body);
        let headers: Vec<[String; 2]> = headers.into_iter().map(|(k, v)| [k, v]).collect();
        json!({ "send": { "method": method, "url": url, "headers": headers } }).to_string()
    }

    fn done(value: Value) -> String {
        json!({ "done": value }).to_string()
    }

    fn step_sync(&mut self, step: Step<SyncResult>) -> String {
        match step {
            Step::Send(r) => self.send(r),
            Step::Done(Ok(result)) => {
                let Op::Sync(_, finish) = &self.op else {
                    unreachable!()
                };
                Self::done(finish.done(&result))
            }
            Step::Done(Err(e)) => Self::done(pass_error(&e)),
        }
    }

    fn step_list(&mut self, step: Step<Vec<GDriveVault>>) -> String {
        match step {
            Step::Send(r) => self.send(r),
            Step::Done(Ok(vaults)) => {
                let list: Vec<Value> = vaults
                    .into_iter()
                    .map(|v| {
                        json!({ "file_id": v.file_id, "vault_id": v.vault_id, "name": v.name,
                                "modified": v.modified, "size": v.size })
                    })
                    .collect();
                Self::done(json!({ "result": list }))
            }
            Step::Done(Err(e)) => Self::done(pass_error(&e)),
        }
    }

    fn step_download(&mut self, step: Step<Vec<u8>>) -> String {
        match step {
            Step::Send(r) => self.send(r),
            Step::Done(Ok(bytes)) => {
                let size = bytes.len();
                self.bytes = Some(bytes);
                Self::done(json!({ "result": { "size": size } }))
            }
            Step::Done(Err(e)) => Self::done(pass_error(&e)),
        }
    }

    fn step_account(&mut self, step: Step<GDriveAccount>) -> String {
        match step {
            Step::Send(r) => self.send(r),
            Step::Done(Ok(a)) => Self::done(
                json!({ "result": { "email": a.email, "display_name": a.display_name } }),
            ),
            Step::Done(Err(e)) => Self::done(pass_error(&e)),
        }
    }
}

enum Advance<'a> {
    Sync(&'a mut Exchange<SyncResult>),
    List(&'a mut Exchange<Vec<GDriveVault>>),
    Download(&'a mut Exchange<Vec<u8>>),
    Account(&'a mut Exchange<GDriveAccount>),
}

enum AnyStep {
    Sync(Step<SyncResult>),
    List(Step<Vec<GDriveVault>>),
    Download(Step<Vec<u8>>),
    Account(Step<GDriveAccount>),
}

impl From<Step<SyncResult>> for AnyStep {
    fn from(s: Step<SyncResult>) -> Self {
        AnyStep::Sync(s)
    }
}
impl From<Step<Vec<GDriveVault>>> for AnyStep {
    fn from(s: Step<Vec<GDriveVault>>) -> Self {
        AnyStep::List(s)
    }
}
impl From<Step<Vec<u8>>> for AnyStep {
    fn from(s: Step<Vec<u8>>) -> Self {
        AnyStep::Download(s)
    }
}
impl From<Step<GDriveAccount>> for AnyStep {
    fn from(s: Step<GDriveAccount>) -> Self {
        AnyStep::Account(s)
    }
}

/// `[[name, value], ...]` (as `[...response.headers]` gives) or `{name: value}`.
fn parse_headers(text: &str) -> Vec<(String, String)> {
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Array(pairs)) => pairs
            .into_iter()
            .filter_map(|pair| {
                let pair = pair.as_array()?;
                Some((
                    pair.first()?.as_str()?.to_string(),
                    pair.get(1)?.as_str()?.to_string(),
                ))
            })
            .collect(),
        Ok(Value::Object(map)) => map
            .into_iter()
            .filter_map(|(k, v)| Some((k, v.as_str()?.to_string())))
            .collect(),
        _ => Vec::new(),
    }
}
