//! `ai.*` requests from the Passyble connector for AI tools (MCP clients such as Claude Code).
//! Only that connector may send them, and `ipc::Server` checks its executable. Items not shared
//! with AI tools answer exactly like missing ones, none of these requests counts as activity for
//! the auto-lock, and in a shared vault every use asks, whatever the item's mark says.

use std::sync::Arc;
use std::time::Duration;

use pass_core::{totp_generate, AiAccess, FieldKind, Item, Vault};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

use super::{parse, ErrorCode, RpcError, RpcResult};
use crate::ai::{AiAction, AiOutcome};
use crate::{
    Agent, AiClient, AiDecision, AiGrant, AiLogEntry, AiRevealRequest, AiRunRequest, AiSecretUse,
    VaultKind, VaultRef, VERSION,
};

/// `ai.list`, `ai.run` and `ai.reveal` per minute, together; more answer `rate_limited`.
pub const AI_REQUESTS_PER_MINUTE: usize = 30;
const MINUTE: Duration = Duration::from_secs(60);

/// Longest client name, title, version or program name kept from the connector.
const MAX_CLIENT_TEXT: usize = 128;
/// Longest command, program or working directory.
const MAX_PATH_TEXT: usize = 4096;
const MAX_ARGS: usize = 256;
/// All arguments together.
const MAX_ARGS_BYTES: usize = 64 * 1024;
/// Environment variables one command may get from the vault.
const MAX_SECRETS: usize = 32;
const MAX_ENV_NAME: usize = 128;
/// Longest reason an AI may give for `ai.reveal`.
const MAX_REASON: usize = 500;
/// Longest item reference (id or title) or field name.
const MAX_REF: usize = 512;
/// A command's time limit when the AI names none, and the longest it may ask for (seconds).
pub const DEFAULT_TIMEOUT_SECS: u64 = 60;
pub const MAX_TIMEOUT_SECS: u64 = 600;

/// Variables a vault value may not replace: they decide which programs run and how.
const RESERVED_ENV: &[&str] = &["PATH", "PATHEXT", "COMSPEC", "SYSTEMROOT", "WINDIR"];

#[derive(Deserialize, Default)]
struct ClientParams {
    #[serde(default)]
    name: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    process: String,
}

impl ClientParams {
    fn into_client(self) -> AiClient {
        AiClient {
            name: clean(&self.name, MAX_CLIENT_TEXT),
            title: clean(&self.title, MAX_CLIENT_TEXT),
            version: clean(&self.version, MAX_CLIENT_TEXT),
            process: clean(&self.process, MAX_CLIENT_TEXT),
        }
    }
}

/// `text` trimmed, without control characters, at most `max` characters.
fn clean(text: &str, max: usize) -> String {
    text.trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect()
}

#[derive(Deserialize)]
pub(super) struct ListParams {
    #[serde(default)]
    client: ClientParams,
}

fn password_field() -> String {
    "password".into()
}

#[derive(Deserialize)]
struct EnvParam {
    name: String,
    item: String,
    #[serde(default = "password_field")]
    field: String,
}

#[derive(Deserialize)]
pub(super) struct RunParams {
    #[serde(default)]
    client: ClientParams,
    env: Vec<EnvParam>,
    command: String,
    program: String,
    #[serde(default)]
    args: Vec<String>,
    cwd: String,
    #[serde(default)]
    timeout_secs: Option<u64>,
}

#[derive(Deserialize)]
pub(super) struct DoneParams {
    request: u64,
    /// `finished`, `timed_out`, `cancelled` or `failed`.
    outcome: String,
    #[serde(default)]
    exit_code: Option<i32>,
}

#[derive(Deserialize)]
pub(super) struct RevealParams {
    #[serde(default)]
    client: ClientParams,
    item: String,
    #[serde(default = "password_field")]
    field: String,
    #[serde(default)]
    reason: String,
}

fn invalid(message: impl Into<String>) -> RpcError {
    RpcError::new(ErrorCode::InvalidParams, message)
}

fn not_shared(reference: &str) -> RpcError {
    RpcError::new(
        ErrorCode::NotFound,
        format!(
            "No item shared with AI tools matches \"{reference}\". Call list_items to see the items the user shared."
        ),
    )
}

fn denied() -> RpcError {
    RpcError::new(
        ErrorCode::Cancelled,
        "The user denied this request (or didn't answer within 2 minutes). Don't ask again unless the user tells you to.",
    )
}

/// One open vault whose marked items AI tools may use ([`Agent::ai_vaults`]).
#[derive(Clone)]
struct AiVault {
    vref: VaultRef,
    vault: Arc<Vault>,
}

impl AiVault {
    /// The vault's name for prompts and answers: `None` for the home vault.
    fn shared_name(&self) -> Option<String> {
        (!self.vref.home).then(|| self.vref.name.clone())
    }

    /// How using an item marked `access` asks here: always in a shared vault.
    fn access(&self, access: AiAccess) -> AiAccess {
        if self.vref.home {
            access
        } else {
            AiAccess::Ask
        }
    }

    fn json(&self) -> Value {
        json!({
            "name": self.vref.name,
            "kind": self.vref.kind,
            "shared": !self.vref.home,
            "fill_only": !self.vref.can_reveal,
        })
    }
}

/// An item shared with AI tools, the vault it is in and how using it asks there.
#[derive(Clone)]
struct SharedItem {
    item: Item,
    access: AiAccess,
    vault: AiVault,
}

/// One field of an item as AI tools name it, with its value.
struct FieldValue {
    name: String,
    value: Zeroizing<String>,
}

/// The fields of `item` an AI tool may use, by name: built-in fields with a value, then custom
/// fields (`custom:<name>` when a built-in has that name). Without `can_reveal` (a fill-only
/// member) no password, 2FA code, card number, security code, PIN or hidden field.
fn item_fields(item: &Item, now_secs: i64, can_reveal: bool) -> Vec<FieldValue> {
    const SECRETS: &[&str] = &["password", "totp", "card_number", "card_security_code", "card_pin"];
    let mut out: Vec<FieldValue> = Vec::new();
    let push = |out: &mut Vec<FieldValue>, name: &str, value: String| {
        if !can_reveal && SECRETS.contains(&name) {
            return;
        }
        if !value.is_empty() {
            out.push(FieldValue {
                name: name.to_string(),
                value: Zeroizing::new(value),
            });
        }
    };
    push(&mut out, "username", item.username.clone());
    push(&mut out, "password", item.password.clone());
    if let Some(totp) = item.totp.clone().filter(|t| !t.trim().is_empty()) {
        if let Ok(code) = totp_generate(totp, now_secs) {
            push(&mut out, "totp", code.code);
        }
    }
    push(&mut out, "notes", item.notes.clone());
    push(
        &mut out,
        "website",
        item.urls.first().cloned().unwrap_or_default(),
    );
    if let Some(card) = &item.card {
        push(&mut out, "card_number", card.number.clone());
        push(&mut out, "card_security_code", card.security_code.clone());
        push(&mut out, "card_pin", card.pin.clone());
        if card.expiry_month > 0 && card.expiry_year > 0 {
            push(
                &mut out,
                "card_expiry",
                format!("{:02}/{}", card.expiry_month, card.expiry_year),
            );
        }
        push(&mut out, "cardholder_name", card.cardholder_name.clone());
    }
    for field in item
        .fields
        .iter()
        .filter(|f| !pass_core::is_ai_access_field(f))
    {
        let name = field.name.trim();
        if name.is_empty() || field.value.is_empty() || (!can_reveal && field.kind == FieldKind::Hidden)
        {
            continue;
        }
        let name = if out.iter().any(|f| f.name.eq_ignore_ascii_case(name)) {
            format!("custom:{name}")
        } else {
            name.to_string()
        };
        if out.iter().any(|f| f.name.eq_ignore_ascii_case(&name)) {
            continue;
        }
        push(&mut out, &name, field.value.clone());
    }
    out
}

/// The field `name` of `fields`: exact, then ignoring case, then `custom:<name>`.
fn find_field(fields: Vec<FieldValue>, name: &str) -> Option<FieldValue> {
    let name = name.trim();
    let custom = format!("custom:{name}");
    let bare = name.strip_prefix("custom:").unwrap_or(name).trim();
    let pos = fields
        .iter()
        .position(|f| f.name == name)
        .or_else(|| {
            fields
                .iter()
                .position(|f| f.name.eq_ignore_ascii_case(name))
        })
        .or_else(|| {
            fields
                .iter()
                .position(|f| f.name.eq_ignore_ascii_case(&custom))
        })
        // `custom:API key` for a custom field listed as `API key`.
        .or_else(|| {
            fields
                .iter()
                .position(|f| f.name.eq_ignore_ascii_case(bare))
        })?;
    fields.into_iter().nth(pos)
}

fn check_env_name(name: &str) -> Result<(), RpcError> {
    let mut chars = name.chars();
    let valid = name.len() <= MAX_ENV_NAME
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid {
        return Err(invalid(format!(
            "\"{name}\" is not a valid environment variable name (letters, digits and _, not starting with a digit)"
        )));
    }
    let upper = name.to_ascii_uppercase();
    if RESERVED_ENV.contains(&upper.as_str())
        || upper.starts_with("LD_")
        || upper.starts_with("DYLD_")
    {
        return Err(invalid(format!(
            "{name} can't hold a secret: it decides which programs run. Use another name"
        )));
    }
    Ok(())
}

fn check_text(what: &str, value: &str, max: usize) -> Result<(), RpcError> {
    if value.trim().is_empty() {
        return Err(invalid(format!("{what} is empty")));
    }
    if value.len() > max {
        return Err(invalid(format!("{what} is too long")));
    }
    if value.contains('\0') {
        return Err(invalid(format!("{what} contains a NUL character")));
    }
    Ok(())
}

impl Agent {
    /// Handles one JSON request line from the connector for AI tools and returns the response
    /// line. Only `ai.*` methods; anything else is an unknown method.
    pub fn handle_ai_line(&self, line: &str) -> String {
        let request: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                return json!({ "id": null, "error": { "code": "invalid_params", "message": e.to_string() } }).to_string()
            }
        };
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
        match self.handle_ai(&method, params) {
            Ok(result) => json!({ "id": id, "result": result }),
            Err(e) => {
                json!({ "id": id, "error": { "code": e.code.as_str(), "message": e.message } })
            }
        }
        .to_string()
    }

    /// One `ai.*` request. Never activity for the auto-lock.
    pub fn handle_ai(&self, method: &str, params: Value) -> RpcResult {
        // A sync client may have replaced the file since the last request.
        let _ = self.reload_if_changed();
        match method {
            "ai.status" => Ok(json!({ "locked": self.is_locked(), "version": VERSION })),
            "ai.list" => self.rpc_ai_list(parse(params)?),
            "ai.run" => self.rpc_ai_run(parse(params)?),
            "ai.run_done" => self.rpc_ai_run_done(parse(params)?),
            "ai.reveal" => self.rpc_ai_reveal(parse(params)?),
            other => Err(invalid(format!("unknown method {other}"))),
        }
    }

    fn ai_rate(&self) -> Result<(), RpcError> {
        if self.within_rate("ai", AI_REQUESTS_PER_MINUTE, MINUTE) {
            Ok(())
        } else {
            Err(RpcError::new(
                ErrorCode::RateLimited,
                "Too many requests from AI tools. Wait a minute and try again",
            ))
        }
    }

    /// The open vaults AI tools may use, the home vault first: not one opened through emergency
    /// access, nor a shared vault the app keeps from them ([`crate::Ui::ai_allows_vault`]).
    fn ai_allowed_vaults(&self, opened: crate::agent::Opened) -> Vec<AiVault> {
        opened
            .0
            .into_iter()
            .filter(|(r, _)| {
                r.home || (r.kind != VaultKind::Emergency && self.ui.ai_allows_vault(r))
            })
            .map(|(vref, vault)| AiVault { vref, vault })
            .collect()
    }

    /// The unlocked vaults AI tools may use ([`Agent::ai_allowed_vaults`]); while locked, asks the
    /// user to unlock first (the app's unlock prompt).
    fn ai_vaults(&self, client: &AiClient, action: AiAction) -> Result<Vec<AiVault>, RpcError> {
        if let Some(opened) = self.opened() {
            return Ok(self.ai_allowed_vaults(opened));
        }
        if self.ui.request_unlock() {
            if let Some(opened) = self.opened() {
                return Ok(self.ai_allowed_vaults(opened));
            }
        }
        self.ai_log_entry(AiLogEntry {
            id: 0,
            at: 0,
            client: client.label(),
            action,
            items: Vec::new(),
            command: String::new(),
            cwd: String::new(),
            approval: None,
            outcome: AiOutcome::Locked,
            exit_code: None,
        });
        Err(RpcError::new(
            ErrorCode::Locked,
            "Passyble is locked and wasn't unlocked. Ask the user to unlock Passyble, then try again.",
        ))
    }

    /// Whether every vault in `used` is still open as it was (not locked, reopened or closed
    /// while a prompt waited).
    fn ai_still_open(&self, used: &[&AiVault]) -> bool {
        let Some(opened) = self.opened() else {
            return false;
        };
        used.iter().all(|u| {
            opened
                .by_id(&u.vref.id)
                .is_some_and(|(_, v)| Arc::ptr_eq(v, &u.vault))
        })
    }

    /// The item shared with AI tools that `reference` names (its id, or its title when only one
    /// shared item in all `vaults` has it), its vault and how using it asks. Unshared items
    /// answer as missing ones.
    fn shared_item(&self, vaults: &[AiVault], reference: &str) -> Result<SharedItem, RpcError> {
        let reference = reference.trim();
        if reference.is_empty() || reference.len() > MAX_REF {
            return Err(invalid("item must be an item id or title from list_items"));
        }
        let shared: Vec<SharedItem> = vaults
            .iter()
            .flat_map(|v| {
                v.vault.items().into_iter().filter_map(move |item| {
                    let access = v.access(item.ai_access()?);
                    Some(SharedItem {
                        item,
                        access,
                        vault: v.clone(),
                    })
                })
            })
            .collect();
        if let Some(found) = shared.iter().find(|s| s.item.id == reference) {
            return Ok(found.clone());
        }
        let by_title: Vec<&SharedItem> = shared
            .iter()
            .filter(|s| s.item.title.trim().to_lowercase() == reference.to_lowercase())
            .collect();
        match by_title.as_slice() {
            [one] => Ok((*one).clone()),
            [] => Err(not_shared(reference)),
            _ => Err(invalid(format!(
                "Several shared items are called \"{reference}\". Use the id from list_items"
            ))),
        }
    }

    /// The value of field `field` of `shared`'s item (in a fill-only member's vault, only the
    /// fields that member may see).
    fn ai_field(&self, shared: &SharedItem, field: &str) -> Result<FieldValue, RpcError> {
        if field.trim().is_empty() || field.len() > MAX_REF {
            return Err(invalid(
                "field must be one of the item's fields from list_items",
            ));
        }
        let item = &shared.item;
        let can_reveal = shared.vault.vref.can_reveal;
        if let Some(value) = find_field(item_fields(item, self.now_secs(), can_reveal), field) {
            return Ok(value);
        }
        if !can_reveal && find_field(item_fields(item, self.now_secs(), true), field).is_some() {
            return Err(RpcError::new(
                ErrorCode::FillOnly,
                format!(
                    "\"{}\" is in a shared vault where this user may fill logins but not see their secrets, so its \"{}\" can't be given to AI tools",
                    item.title,
                    field.trim()
                ),
            ));
        }
        Err(invalid(format!(
            "\"{}\" has no field \"{}\" with a value. Its fields are listed by list_items",
            item.title,
            field.trim()
        )))
    }

    /// Refuses `ai.run` and `ai.reveal` in read-only mode.
    fn ai_check_writable(&self) -> Result<(), RpcError> {
        if self.update_required() {
            Err(RpcError::new(
                ErrorCode::UpdateRequired,
                "Passyble needs an update before AI tools can use its secrets again. Ask the user to update the Passyble app.",
            ))
        } else {
            Ok(())
        }
    }

    fn rpc_ai_list(&self, p: ListParams) -> RpcResult {
        let client = p.client.into_client();
        self.ai_rate()?;
        let vaults = self.ai_vaults(&client, AiAction::List)?;
        let now = self.now_secs();
        let several = vaults.len() > 1;
        let items: Vec<Value> = vaults
            .iter()
            .flat_map(|v| {
                v.vault.items().into_iter().filter_map(move |item| {
                    let access = v.access(item.ai_access()?);
                    let fields: Vec<String> = item_fields(&item, now, v.vref.can_reveal)
                        .into_iter()
                        .map(|f| f.name)
                        .collect();
                    let mut entry = json!({
                        "id": item.id,
                        "title": item.title,
                        "kind": item.kind.as_str(),
                        "websites": item.urls,
                        "username": item.username,
                        "fields": fields,
                        "access": access.as_str(),
                    });
                    // Which vault, once more than one is open.
                    if several {
                        entry["vault"] = v.json();
                    }
                    Some(entry)
                })
            })
            .collect();
        self.ai_log_entry(AiLogEntry {
            id: 0,
            at: 0,
            client: client.label(),
            action: AiAction::List,
            items: Vec::new(),
            command: String::new(),
            cwd: String::new(),
            approval: None,
            outcome: AiOutcome::Listed,
            exit_code: None,
        });
        Ok(json!({ "items": items }))
    }

    fn rpc_ai_run(&self, p: RunParams) -> RpcResult {
        let client = p.client.into_client();
        // Checked before anything else: what the prompt shows is what runs.
        check_text("command", &p.command, MAX_PATH_TEXT)?;
        check_text("program", &p.program, MAX_PATH_TEXT)?;
        check_text("cwd", &p.cwd, MAX_PATH_TEXT)?;
        if p.args.len() > MAX_ARGS || p.args.iter().map(String::len).sum::<usize>() > MAX_ARGS_BYTES
        {
            return Err(invalid("too many or too long arguments"));
        }
        if p.args.iter().any(|a| a.contains('\0')) {
            return Err(invalid("an argument contains a NUL character"));
        }
        if p.env.is_empty() {
            return Err(invalid(
                "env is empty: name at least one environment variable and the item field it gets",
            ));
        }
        if p.env.len() > MAX_SECRETS {
            return Err(invalid(format!(
                "at most {MAX_SECRETS} environment variables"
            )));
        }
        for (i, e) in p.env.iter().enumerate() {
            check_env_name(&e.name)?;
            if p.env[..i]
                .iter()
                .any(|o| o.name.eq_ignore_ascii_case(&e.name))
            {
                return Err(invalid(format!("{} is named twice", e.name)));
            }
        }
        let timeout_secs = p
            .timeout_secs
            .unwrap_or(DEFAULT_TIMEOUT_SECS)
            .clamp(1, MAX_TIMEOUT_SECS);
        self.ai_check_writable()?;
        self.ai_rate()?;
        let vaults = self.ai_vaults(&client, AiAction::Run)?;
        let key = client.key();

        let mut uses: Vec<(AiSecretUse, AiAccess, FieldValue)> = Vec::new();
        let mut used: Vec<AiVault> = Vec::new();
        for e in &p.env {
            let shared = self.shared_item(&vaults, &e.item)?;
            let value = self.ai_field(&shared, &e.field)?;
            uses.push((
                AiSecretUse {
                    item_id: shared.item.id.clone(),
                    item_title: shared.item.title.clone(),
                    field: value.name.clone(),
                    env: e.name.clone(),
                    asks: false,
                    vault: shared.vault.shared_name(),
                },
                shared.access,
                value,
            ));
            used.push(shared.vault);
        }
        let mut titles: Vec<String> = Vec::new();
        for (u, _, _) in &uses {
            if !titles.contains(&u.item_title) {
                titles.push(u.item_title.clone());
            }
        }
        let refresh_asks = |uses: &mut Vec<(AiSecretUse, AiAccess, FieldValue)>| {
            for (u, access, _) in uses.iter_mut() {
                u.asks = *access == AiAccess::Ask && !self.ai_granted(&u.item_id, &key);
            }
            uses.iter().any(|(u, _, _)| u.asks)
        };
        let mut entry = AiLogEntry {
            id: 0,
            at: 0,
            client: client.label(),
            action: AiAction::Run,
            items: titles,
            command: crate::ai::command_line(&p.program, &p.args),
            cwd: p.cwd.clone(),
            approval: None,
            outcome: AiOutcome::Denied,
            exit_code: None,
        };
        let any_ask = uses.iter().any(|(_, a, _)| *a == AiAccess::Ask);
        let mut approval: &'static str = if any_ask { "grant" } else { "without_asking" };
        if refresh_asks(&mut uses) {
            if self.ai_denied_recently(&key) {
                self.ai_log_entry(entry);
                return Err(RpcError::new(
                    ErrorCode::Cancelled,
                    "The user denied several requests from this AI tool. Passyble won't ask again for 2 minutes.",
                ));
            }
            let epoch = self.ai_state().epoch;
            let Some(_slot) = self.ai_prompts.enter() else {
                return Err(RpcError::new(
                    ErrorCode::RateLimited,
                    "Passyble is already asking the user about other requests from AI tools. Try again in a moment.",
                ));
            };
            // The auto-lock waits for the user's answer (at most a few minutes).
            let _busy = self.busy();
            // A grant may have come while this request waited for the prompt.
            if refresh_asks(&mut uses) {
                let request = AiRunRequest {
                    client: client.clone(),
                    secrets: uses.iter().map(|(u, _, _)| u.clone()).collect(),
                    command: p.command.trim().to_string(),
                    program: p.program.clone(),
                    args: p.args.clone(),
                    cwd: p.cwd.clone(),
                    timeout_secs,
                };
                match self.ui.confirm_ai_run(&request) {
                    None => {
                        return Err(RpcError::new(
                            ErrorCode::NotSupported,
                            "This Passyble app can't ask the user about AI tools",
                        ))
                    }
                    Some(AiDecision::Deny) => {
                        self.ai_note_denial(&key);
                        self.ai_log_entry(entry);
                        return Err(denied());
                    }
                    Some(AiDecision::Once) => approval = "once",
                    Some(AiDecision::UntilLock) => {
                        approval = "until_lock";
                        let at = self.unix_ms();
                        let grants = uses
                            .iter()
                            .filter(|(u, _, _)| u.asks)
                            .map(|(u, _, _)| AiGrant {
                                item_id: u.item_id.clone(),
                                item_title: u.item_title.clone(),
                                client_key: key.clone(),
                                client: client.label(),
                                granted_at: at,
                            })
                            .collect();
                        self.ai_grant(epoch, grants);
                    }
                }
            }
        }
        // The vaults the user approved this for must still be the ones open.
        if !self.ai_still_open(&used.iter().collect::<Vec<_>>()) {
            entry.outcome = AiOutcome::Locked;
            self.ai_log_entry(entry);
            return Err(RpcError::new(
                ErrorCode::Locked,
                "Passyble was locked while the request waited. Try again after the user unlocks it.",
            ));
        }
        entry.approval = Some(approval);
        entry.outcome = AiOutcome::Running;
        let id = self.ai_log_entry(entry);
        let mut env = Map::new();
        for (u, _, value) in &uses {
            env.insert(u.env.clone(), Value::String(value.value.to_string()));
        }
        Ok(json!({
            "request": id,
            "approval": approval,
            "timeout_secs": timeout_secs,
            "env": env,
        }))
    }

    fn rpc_ai_run_done(&self, p: DoneParams) -> RpcResult {
        let outcome = match p.outcome.as_str() {
            "finished" => AiOutcome::Finished,
            "timed_out" => AiOutcome::TimedOut,
            "cancelled" => AiOutcome::Cancelled,
            "failed" => AiOutcome::Failed,
            _ => {
                return Err(invalid(
                    "outcome must be finished, timed_out, cancelled or failed",
                ))
            }
        };
        if !self.ai_log_finish(p.request, outcome, p.exit_code) {
            return Err(RpcError::new(
                ErrorCode::NotFound,
                "no such running command",
            ));
        }
        Ok(json!({}))
    }

    fn rpc_ai_reveal(&self, p: RevealParams) -> RpcResult {
        let client = p.client.into_client();
        let reason = clean(&p.reason, MAX_REASON);
        self.ai_check_writable()?;
        self.ai_rate()?;
        let vaults = self.ai_vaults(&client, AiAction::Reveal)?;
        let key = client.key();
        let shared = self.shared_item(&vaults, &p.item)?;
        let value = self.ai_field(&shared, &p.field)?;
        let item = &shared.item;
        let mut entry = AiLogEntry {
            id: 0,
            at: 0,
            client: client.label(),
            action: AiAction::Reveal,
            items: vec![item.title.clone()],
            command: value.name.clone(),
            cwd: String::new(),
            approval: None,
            outcome: AiOutcome::Denied,
            exit_code: None,
        };
        if self.ai_denied_recently(&key) {
            self.ai_log_entry(entry);
            return Err(RpcError::new(
                ErrorCode::Cancelled,
                "The user denied several requests from this AI tool. Passyble won't ask again for 2 minutes.",
            ));
        }
        let Some(_slot) = self.ai_prompts.enter() else {
            return Err(RpcError::new(
                ErrorCode::RateLimited,
                "Passyble is already asking the user about other requests from AI tools. Try again in a moment.",
            ));
        };
        let _busy = self.busy();
        // Asked every time: no grant and no "Allow without asking" covers a reveal.
        let request = AiRevealRequest {
            client: client.clone(),
            item_id: item.id.clone(),
            item_title: item.title.clone(),
            field: value.name.clone(),
            reason,
            vault: shared.vault.shared_name(),
        };
        match self.ui.confirm_ai_reveal(&request) {
            None => Err(RpcError::new(
                ErrorCode::NotSupported,
                "This Passyble app can't ask the user about AI tools",
            )),
            Some(false) => {
                self.ai_note_denial(&key);
                self.ai_log_entry(entry);
                Err(denied())
            }
            Some(true) => {
                if !self.ai_still_open(&[&shared.vault]) {
                    entry.outcome = AiOutcome::Locked;
                    self.ai_log_entry(entry);
                    return Err(RpcError::new(
                        ErrorCode::Locked,
                        "Passyble was locked while the request waited. Try again after the user unlocks it.",
                    ));
                }
                entry.approval = Some("once");
                entry.outcome = AiOutcome::Revealed;
                self.ai_log_entry(entry);
                Ok(json!({ "field": value.name, "value": value.value.as_str() }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pass_core::{CardData, CustomField, FieldKind};

    #[test]
    fn env_names() {
        for ok in ["GITHUB_TOKEN", "_x", "a1"] {
            assert!(check_env_name(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "1A",
            "A-B",
            "A B",
            "PATH",
            "path",
            "LD_PRELOAD",
            "DYLD_X",
            "ComSpec",
        ] {
            assert!(check_env_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn fields_by_name() {
        let mut item = Item {
            title: "T".into(),
            username: "u".into(),
            password: "p".into(),
            urls: vec!["https://a.example".into()],
            card: Some(CardData {
                number: "4111".into(),
                expiry_month: 3,
                expiry_year: 2031,
                ..Default::default()
            }),
            fields: vec![
                CustomField {
                    name: "API key".into(),
                    value: "k".into(),
                    kind: FieldKind::Hidden,
                },
                CustomField {
                    name: "Password".into(),
                    value: "other".into(),
                    kind: FieldKind::Hidden,
                },
                CustomField {
                    name: "empty".into(),
                    value: String::new(),
                    kind: FieldKind::Text,
                },
            ],
            ..Default::default()
        };
        item.set_ai_access(Some(AiAccess::Ask));
        let names: Vec<String> = item_fields(&item, 0, true)
            .into_iter()
            .map(|f| f.name)
            .collect();
        assert_eq!(
            names,
            [
                "username",
                "password",
                "website",
                "card_number",
                "card_expiry",
                "API key",
                "custom:Password"
            ]
        );
        let get =
            |n: &str| find_field(item_fields(&item, 0, true), n).map(|f| f.value.to_string());
        assert_eq!(get("password").as_deref(), Some("p"));
        assert_eq!(get("PASSWORD").as_deref(), Some("p"));
        assert_eq!(get("api KEY").as_deref(), Some("k"));
        assert_eq!(get("custom:Password").as_deref(), Some("other"));
        assert_eq!(get("custom:API key").as_deref(), Some("k"));
        assert_eq!(get("card_expiry").as_deref(), Some("03/2031"));
        assert_eq!(get("empty"), None);
        assert_eq!(get(pass_core::AI_ACCESS_FIELD), None);
    }
}
