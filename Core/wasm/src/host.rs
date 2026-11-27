//! [`BrowserHost`]: the browser extension's vault as plain Rust. The WebAssembly bindings are a
//! thin layer over it.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use pass_agent::clock::{Clock, Instant, SystemClock};
use pass_agent::store::{MemoryStore, VaultStore};
use pass_agent::{Agent, AgentConfig, AgentHost, ErrorCode, LockKind, RpcError, Timers};
use pass_core::{b64url_encode, PassError};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

use crate::ui::{BrowserUi, RequestGrants};

/// The vault file's key in the in-memory store. Never a path on disk.
pub const VAULT_PATH: &str = "passyble/pass.vault";

/// How long a grant from [`BrowserHost::verify_password`] or an unlock may be attached to a
/// request: the extension retries the request right after verifying.
pub const GRANT_TTL: Duration = Duration::from_secs(120);

/// Grants kept at most (the oldest go first).
const MAX_GRANTS: usize = 8;

/// Longest master password accepted.
const MAX_PASSWORD: usize = 1024;

/// The settings the extension starts its vault with (`BrowserAgent` constructor, JSON).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserConfig {
    /// This browser's device id, so merges keep each device's changes apart.
    pub device_id: String,
    /// Lock after this many seconds without use (default 15 minutes).
    #[serde(default = "default_auto_lock")]
    pub auto_lock_secs: u64,
    /// A lock keeps the list of logins without secrets for the menus (soft lock; default on).
    #[serde(default = "yes")]
    pub keep_list: bool,
    /// Ask before each fill (`verification_required`; default off).
    #[serde(default)]
    pub verify_each_fill: bool,
}

fn default_auto_lock() -> u64 {
    15 * 60
}

fn yes() -> bool {
    true
}

/// [`BrowserHost::set_options`]: the settings that can change while the vault is open.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserOptions {
    pub auto_lock_secs: Option<u64>,
    pub keep_list: Option<bool>,
    pub verify_each_fill: Option<bool>,
}

struct Grant {
    /// SHA-256 of the token, base64url (the token itself is never kept).
    hash: String,
    expires: Instant,
}

/// The browser extension's own vault: a [`pass_agent::Agent`] whose vault file lives in memory
/// and whose timers the extension drives.
pub struct BrowserHost {
    agent: Arc<Agent>,
    ui: Arc<BrowserUi>,
    store: Arc<MemoryStore>,
    clock: Arc<dyn Clock>,
    grants: Mutex<Vec<Grant>>,
    device_id: String,
}

pub type HostResult = Result<Value, RpcError>;

fn rpc(code: ErrorCode, message: impl Into<String>) -> RpcError {
    RpcError::new(code, message)
}

pub(crate) fn no_vault() -> RpcError {
    rpc(ErrorCode::NoVault, "There is no vault in this browser yet")
}

/// A master password as the agent takes it: not empty, not absurdly long.
fn check_password(password: &str) -> Result<(), RpcError> {
    if password.is_empty() || password.len() > MAX_PASSWORD {
        return Err(rpc(ErrorCode::InvalidParams, "Enter your master password"));
    }
    Ok(())
}

/// `{"result": …}` or `{"error": {"code", "message"}}`: the protocol's envelope, without an id.
pub fn envelope(result: HostResult) -> String {
    match result {
        Ok(result) => json!({ "result": result }).to_string(),
        Err(e) => json!({ "error": { "code": e.code.as_str(), "message": e.message } }).to_string(),
    }
}

/// The master password rule for a password being typed (`pass_core::master_password_check`):
/// `names` is a JSON array of what it should not be built from (an e-mail address, the vault's
/// name; anything else counts as none). Answers `{ ok, score, label, entropy_bits, issues:
/// ["too_short" | "common" | "contains_name" | "pattern" | "guessable"], name, min_length }`, no
/// secrets. Needs no vault.
pub fn master_password_check_json(password: &str, names: &str) -> String {
    let names: Vec<String> = serde_json::from_str::<Vec<Value>>(names)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .take(16)
        .collect();
    let check =
        pass_core::check_master_password(password, &pass_core::MasterPasswordContext { names });
    json!({
        "ok": check.ok,
        "score": check.score,
        "label": check.label,
        "entropy_bits": check.entropy_bits,
        "issues": check.issues.iter().map(|i| i.as_str()).collect::<Vec<_>>(),
        "name": check.name,
        "min_length": check.min_length,
    })
    .to_string()
}

/// Popular sites for a name or website being typed in an editor (`pass_core::site_suggestions`):
/// a JSON array of `{ name, domain }`, best match first, at most `limit` (capped at 50). Needs
/// no vault; the query never leaves the device.
pub fn site_suggestions_json(query: &str, limit: u32) -> String {
    json!(pass_core::site_suggestions(query.to_string(), limit)).to_string()
}

impl BrowserHost {
    pub fn new(config: BrowserConfig) -> Result<BrowserHost, RpcError> {
        BrowserHost::with_clock(config, Arc::new(SystemClock))
    }

    /// [`BrowserHost::new`] from the constructor's JSON.
    pub fn from_json(config: &str) -> Result<BrowserHost, RpcError> {
        let config: BrowserConfig = serde_json::from_str(config)
            .map_err(|e| rpc(ErrorCode::InvalidParams, e.to_string()))?;
        BrowserHost::new(config)
    }

    /// [`BrowserHost::new`] on another clock (tests).
    pub fn with_clock(
        config: BrowserConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<BrowserHost, RpcError> {
        let device_id = config.device_id.trim();
        if device_id.is_empty() || device_id.len() > 128 {
            return Err(rpc(ErrorCode::InvalidParams, "device_id is required"));
        }
        let store = Arc::new(MemoryStore::new());
        let ui = Arc::new(BrowserUi::new(config.verify_each_fill));
        let agent = Agent::with_host(
            // No sync of its own (the extension drives Google Drive) and no list on disk.
            AgentConfig::new(
                PathBuf::from(VAULT_PATH),
                device_id.to_string(),
                Duration::from_secs(config.auto_lock_secs.max(1)),
            ),
            ui.clone(),
            AgentHost {
                store: store.clone(),
                clock: clock.clone(),
                timers: Timers::Host,
            },
        );
        agent.set_keep_list(config.keep_list);
        Ok(BrowserHost {
            agent,
            ui,
            store,
            clock,
            grants: Mutex::new(Vec::new()),
            device_id: device_id.to_string(),
        })
    }

    /// This browser's device id (the config's).
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    fn path() -> &'static Path {
        Path::new(VAULT_PATH)
    }

    /// The agent (tests, and calls the bindings don't wrap).
    pub fn agent(&self) -> &Arc<Agent> {
        &self.agent
    }

    /// The browser's Ui (its effects).
    pub fn ui(&self) -> &Arc<BrowserUi> {
        &self.ui
    }

    /// Whether this browser has a vault (created, or loaded with [`BrowserHost::load`]).
    pub fn has_vault(&self) -> bool {
        self.store.exists(Self::path())
    }

    /// Makes `file` this browser's vault. Only while locked (`invalid_state` otherwise). Answers
    /// `{ "vault_id" }`.
    pub fn load(&self, file: Vec<u8>) -> HostResult {
        if !self.agent.is_locked() {
            return Err(rpc(
                ErrorCode::InvalidState,
                "Lock the vault before opening another vault file",
            ));
        }
        let vault_id = pass_agent_vault_id(&file).ok_or_else(|| {
            rpc(
                ErrorCode::InvalidParams,
                "This is not a Passyble vault file",
            )
        })?;
        // Another vault (or the same one again): nothing of the old list stays.
        if self.agent.is_soft_locked() {
            self.agent.lock_as(LockKind::Full);
        }
        self.store.put(Self::path(), file);
        Ok(json!({ "vault_id": vault_id }))
    }

    /// Creates this browser's vault with the master password and opens it. `invalid_state` if
    /// there is one already. Answers `{ "vault_id", "grant" }`.
    pub fn create(&self, password: &str) -> HostResult {
        check_password(password)?;
        if !pass_core::check_master_password(password, &Default::default()).ok {
            return Err(rpc(
                ErrorCode::InvalidParams,
                "This master password is too easy to guess",
            ));
        }
        if self.has_vault() {
            return Err(rpc(
                ErrorCode::InvalidState,
                "There is a vault in this browser already",
            ));
        }
        self.agent.create_vault(password)?;
        let vault_id = self.agent.peek_vault().map(|v| v.vault_id());
        Ok(json!({ "vault_id": vault_id, "grant": self.issue_grant() }))
    }

    /// Unlocks with the master password, through the agent's `unlock.password` (same rate limit).
    /// Answers `{ "locked": false, "grant" }`.
    pub fn unlock(&self, password: &str) -> HostResult {
        check_password(password)?;
        if !self.has_vault() {
            return Err(no_vault());
        }
        let mut result = self
            .agent
            .handle("unlock.password", json!({ "password": password }))?;
        result["grant"] = json!(self.issue_grant());
        Ok(result)
    }

    /// Opens the vault with its kept key after the service worker restarted (no Argon2id).
    /// `idle_ms` carries the idle time over so the auto-lock keeps its schedule.
    pub fn unlock_with_key(&self, key: &[u8], idle_ms: u64) -> HostResult {
        if !self.has_vault() {
            return Err(no_vault());
        }
        if self.agent.is_locked() {
            self.agent
                .unlock_with_key(key.to_vec())
                .map_err(|e| match e {
                    PassError::InvalidPassword => rpc(
                        ErrorCode::WrongPassword,
                        "The kept key doesn't open this vault",
                    ),
                    other => other.into(),
                })?;
        }
        self.agent.set_idle_for(Duration::from_millis(idle_ms));
        Ok(json!({ "locked": false }))
    }

    /// Checks the master password while unlocked and answers `{ "grant" }`: a one-use token that
    /// marks one request within [`GRANT_TTL`] as verified.
    pub fn verify_password(&self, password: &str) -> HostResult {
        check_password(password)?;
        let vault = self
            .agent
            .peek_vault()
            .ok_or_else(|| rpc(ErrorCode::Locked, "Vault is locked"))?;
        if !vault.check_password(password.to_string())? {
            return Err(rpc(
                ErrorCode::WrongPassword,
                "Wrong master password. Check Caps Lock and try again.",
            ));
        }
        Ok(json!({ "grant": self.issue_grant() }))
    }

    /// Saves and locks. `completely: false` is the soft lock, which keeps the list of logins
    /// without secrets. Grants are dropped either way.
    pub fn lock(&self, completely: bool) -> HostResult {
        self.grants().clear();
        let kind = if completely {
            LockKind::Full
        } else {
            LockKind::Soft
        };
        self.agent.save_and_lock_as(kind)?;
        Ok(json!({ "locked": true }))
    }

    /// Applies [`BrowserOptions`] given as JSON.
    pub fn set_options(&self, options: &str) -> HostResult {
        let options: BrowserOptions = serde_json::from_str(options)
            .map_err(|e| rpc(ErrorCode::InvalidParams, e.to_string()))?;
        if let Some(secs) = options.auto_lock_secs {
            let mut config = self.agent.config();
            config.auto_lock = Duration::from_secs(secs.max(1));
            // Same file and device: the vault stays open.
            self.agent.reconfigure(config);
        }
        if let Some(keep) = options.keep_list {
            self.agent.set_keep_list(keep);
        }
        if let Some(on) = options.verify_each_fill {
            self.ui.set_verify_each_fill(on);
        }
        Ok(json!({}))
    }

    /// Answers one protocol request line as the agent does over native messaging. The background
    /// may add `"grant"` and `"confirmed": true` outside `params`; content scripts can never set
    /// them.
    pub fn handle(&self, line: &str) -> Zeroizing<String> {
        let mut request: Map<String, Value> = match serde_json::from_str(line) {
            Ok(Value::Object(request)) => request,
            // Not an object: the agent's own answer (`invalid_params`).
            _ => return Zeroizing::new(self.agent.handle_line(line)),
        };
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let grant = request.remove("grant");
        let confirmed = request.remove("confirmed") == Some(Value::Bool(true));
        let verified = grant
            .as_ref()
            .and_then(Value::as_str)
            .is_some_and(|token| self.redeem_grant(token));
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let early = |e: RpcError| {
            Zeroizing::new(
                json!({ "id": id, "error": { "code": e.code.as_str(), "message": e.message } })
                    .to_string(),
            )
        };
        let has_vault = self.has_vault();
        if !has_vault && method != "status" {
            return early(no_vault());
        }
        if method == "totp.popup" {
            // The desktop's always-on-top 2FA window; the extension's own toast covers it.
            return early(rpc(
                ErrorCode::NotSupported,
                "the 2FA window is part of the Passyble app",
            ));
        }
        let line = Zeroizing::new(Value::Object(request).to_string());
        self.ui.begin_request(RequestGrants {
            verified,
            confirmed,
        });
        let answer = Zeroizing::new(self.agent.handle_line(&line));
        self.ui.end_request();
        if method == "status" {
            if let Ok(Value::Object(mut answer)) = serde_json::from_str::<Value>(&answer) {
                if let Some(Value::Object(result)) = answer.get_mut("result") {
                    result.insert("vault".into(), json!(has_vault));
                }
                return Zeroizing::new(Value::Object(answer).to_string());
            }
        }
        answer
    }

    /// Runs the agent's timers. Call at [`BrowserHost::next_tick`] and after each request.
    pub fn tick(&self) {
        self.agent.tick();
    }

    /// When [`BrowserHost::tick`] has something to do; `None`: nothing to wait for.
    pub fn next_tick(&self) -> Option<Duration> {
        self.agent.next_tick()
    }

    /// Time since the vault was last used (for `unlock_with_key` after a restart).
    pub fn idle(&self) -> Duration {
        self.agent.idle_for()
    }

    /// What the extension must carry out ([`crate::ui::Effect`]), as a JSON array.
    pub fn take_effects(&self) -> Zeroizing<String> {
        self.ui.take_effects()
    }

    /// The encrypted vault file if the agent wrote it since the last call.
    pub fn take_save(&self) -> Option<Vec<u8>> {
        self.store
            .take_written()
            .into_iter()
            .find(|(path, _)| path.as_path() == Self::path())
            .and_then(|(_, bytes)| bytes)
    }

    /// The encrypted vault file now, saved first while unlocked.
    pub fn export(&self) -> Result<Vec<u8>, RpcError> {
        if !self.agent.is_locked() {
            self.agent.save()?;
        }
        self.store.get(Self::path()).ok_or_else(no_vault)
    }

    /// The unlocked vault's key, so a restarted service worker can
    /// [`BrowserHost::unlock_with_key`]. `None` while locked.
    pub fn vault_key(&self) -> Option<Zeroizing<Vec<u8>>> {
        self.agent
            .peek_vault()
            .map(|v| Zeroizing::new(v.export_vault_key()))
    }

    fn grants(&self) -> MutexGuard<'_, Vec<Grant>> {
        self.grants.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) fn issue_grant(&self) -> String {
        let mut token = Zeroizing::new([0u8; 32]);
        if getrandom::getrandom(token.as_mut()).is_err() {
            // No grant: the request just asks again.
            return String::new();
        }
        let token = b64url_encode(token.to_vec());
        let now = self.clock.now();
        let mut grants = self.grants();
        grants.retain(|g| g.expires > now);
        grants.push(Grant {
            hash: hash(&token),
            expires: now + GRANT_TTL,
        });
        let excess = grants.len().saturating_sub(MAX_GRANTS);
        grants.drain(..excess);
        token
    }

    /// Whether `token` is a live grant; it is used up either way.
    fn redeem_grant(&self, token: &str) -> bool {
        if token.is_empty() {
            return false;
        }
        let hash = hash(token);
        let now = self.clock.now();
        let mut grants = self.grants();
        grants.retain(|g| g.expires > now);
        match grants
            .iter()
            .position(|g| pass_core::secrets_equal(&g.hash, &hash))
        {
            Some(at) => {
                grants.remove(at);
                true
            }
            None => false,
        }
    }
}

fn hash(token: &str) -> String {
    b64url_encode(pass_core::sha256(token.as_bytes().to_vec()))
}

/// The vault id in a vault file's cleartext header, `None` if it isn't one.
fn pass_agent_vault_id(file: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct Header {
        format: String,
        vault_id: String,
    }
    serde_json::from_slice::<Header>(file)
        .ok()
        .filter(|h| h.format == "pass-vault" && !h.vault_id.is_empty())
        .map(|h| h.vault_id)
}
