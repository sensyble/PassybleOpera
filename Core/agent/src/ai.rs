//! State kept for the AI tools connector (`passyble-mcp`, started by MCP clients such as Claude
//! Code or Codex): "Allow until the vault locks" grants, recent denials and a log of recent
//! requests. All of it lives in memory only, grants end at every lock, and nothing here holds a
//! secret value.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use serde::Serialize;

use crate::clock::Instant;
use crate::Agent;

/// Entries the log of recent requests keeps (the oldest go first).
pub const MAX_LOG: usize = 200;

/// Requests that may be at the approval prompt at once (one is shown, up to three queue behind
/// it); more answer `rate_limited`, so a looping AI can't stack up dialogs.
pub(crate) const MAX_PROMPT_WAITERS: usize = 4;

/// Denials of one client within [`DENIAL_WINDOW`] after which its requests are refused without
/// asking until the window has passed.
pub(crate) const MAX_DENIALS: usize = 3;
pub(crate) const DENIAL_WINDOW: Duration = Duration::from_secs(120);

/// The MCP client that the connector speaks for, as the approval prompt and the log name it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct AiClient {
    /// `clientInfo.name` from MCP `initialize` (`claude-code`, `codex-mcp-client`, ...).
    pub name: String,
    /// `clientInfo.title`, if the client sent one.
    pub title: String,
    /// `clientInfo.version`.
    pub version: String,
    /// The program that started the connector, found by the connector from the OS (`claude.exe`,
    /// `codex.exe`); `""` if unknown.
    pub process: String,
}

impl AiClient {
    /// A readable name: the client's title, or a known client's name, or its `clientInfo.name`,
    /// with the program in parentheses (`Claude Code (claude.exe)`).
    pub fn label(&self) -> String {
        let name = if !self.title.trim().is_empty() {
            self.title.trim().to_string()
        } else {
            known_client(&self.name)
                .map(str::to_string)
                .unwrap_or_else(|| self.name.trim().to_string())
        };
        let name = if name.is_empty() {
            "Unknown AI tool".to_string()
        } else {
            name
        };
        if self.process.is_empty() {
            name
        } else {
            format!("{name} ({})", self.process)
        }
    }

    /// What a grant is bound to: the client's name and the program that started the connector.
    pub fn key(&self) -> String {
        format!(
            "{}|{}",
            self.name.trim().to_lowercase(),
            self.process.trim().to_lowercase()
        )
    }
}

/// Display names of MCP clients by their `clientInfo.name`.
fn known_client(name: &str) -> Option<&'static str> {
    Some(match name.trim().to_ascii_lowercase().as_str() {
        "claude-code" => "Claude Code",
        "claude-ai" | "claude desktop" => "Claude Desktop",
        "codex" | "codex-mcp-client" | "codex_mcp_client" => "Codex",
        "cursor" | "cursor-vscode" => "Cursor",
        "visual studio code" | "vscode" => "VS Code",
        "windsurf" | "windsurf-client" => "Windsurf",
        "gemini-cli" => "Gemini CLI",
        "zed" => "Zed",
        _ => return None,
    })
}

/// One secret a command gets, as the prompt shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AiSecretUse {
    pub item_id: String,
    pub item_title: String,
    /// The field, as `list_items` names it (`password`, `API key`, ...).
    pub field: String,
    /// The environment variable it goes into.
    pub env: String,
    /// This item needs the user's yes now ("Ask every time" and no grant for this client).
    pub asks: bool,
    /// The shared vault the item is in (its name), `None` in the home vault.
    pub vault: Option<String>,
}

/// "Let <client> run this command with <items>?" ([`crate::Ui::confirm_ai_run`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AiRunRequest {
    pub client: AiClient,
    pub secrets: Vec<AiSecretUse>,
    /// The command as the AI gave it (`gh`).
    pub command: String,
    /// The program that will run, resolved by the connector (`C:\Program Files\GitHub CLI\gh.exe`).
    pub program: String,
    pub args: Vec<String>,
    /// The working directory (absolute).
    pub cwd: String,
    pub timeout_secs: u64,
}

impl AiRunRequest {
    /// The program and its arguments as one line, quoted where needed: what the prompt shows.
    pub fn command_line(&self) -> String {
        command_line(&self.program, &self.args)
    }
}

/// `program` and `args` as one line: arguments with spaces, quotes or nothing in them are quoted
/// (display only; the connector passes the arguments as they are, without a shell).
pub fn command_line(program: &str, args: &[String]) -> String {
    let quote = |s: &str| -> String {
        if !s.is_empty()
            && !s
                .chars()
                .any(|c| c.is_whitespace() || c == '"' || c == '\'')
        {
            s.to_string()
        } else {
            format!("\"{}\"", s.replace('"', "\\\""))
        }
    };
    std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .map(quote)
        .collect::<Vec<_>>()
        .join(" ")
}

/// "Show <field> of <item> to <client>?" ([`crate::Ui::confirm_ai_reveal`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AiRevealRequest {
    pub client: AiClient,
    pub item_id: String,
    pub item_title: String,
    pub field: String,
    /// Why, in the AI's own words (untrusted; the prompt labels it as the AI's text). `""` if none.
    pub reason: String,
    /// The shared vault the item is in (its name), `None` in the home vault.
    pub vault: Option<String>,
}

/// The user's answer to [`crate::Ui::confirm_ai_run`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AiDecision {
    /// Refused, closed, or not answered within the prompt's time (about 2 minutes).
    Deny,
    /// This command only.
    Once,
    /// This command, and later ones of the same client with the same items, until the vault locks.
    UntilLock,
}

/// "Allow until the vault locks": `client` may use `item_id` without asking until the next lock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AiGrant {
    pub item_id: String,
    pub item_title: String,
    /// [`AiClient::key`].
    pub client_key: String,
    /// [`AiClient::label`].
    pub client: String,
    /// Unix ms.
    pub granted_at: i64,
}

/// What an AI tool asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AiAction {
    /// `list_items`.
    List,
    /// `run_with_secret`.
    Run,
    /// `reveal_secret`.
    Reveal,
}

/// How a request ended (so far).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AiOutcome {
    /// `list_items` answered.
    Listed,
    /// The user said no, closed the prompt or didn't answer in time; or the client was refused
    /// without asking after repeated denials.
    Denied,
    /// The vault was locked and wasn't unlocked.
    Locked,
    /// Approved (or allowed without asking); the command is running.
    Running,
    /// The command ran; see [`AiLogEntry::exit_code`].
    Finished,
    /// The command was stopped at its time limit.
    TimedOut,
    /// The MCP client cancelled the command, which was stopped.
    Cancelled,
    /// The command could not be started.
    Failed,
    /// The value was shown to the AI.
    Revealed,
}

/// One request in the log of recent requests (AI tools page in Settings). Never a secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AiLogEntry {
    pub id: u64,
    /// Unix ms.
    pub at: i64,
    /// [`AiClient::label`].
    pub client: String,
    pub action: AiAction,
    /// The items it used (titles), in order.
    pub items: Vec<String>,
    /// `run_with_secret`: [`command_line`]; `reveal_secret`: the field. `""` for `list_items`.
    pub command: String,
    /// `run_with_secret`: the working directory.
    pub cwd: String,
    /// How the use was approved: `once`, `until_lock`, `grant` (an earlier "Allow until the vault
    /// locks"), `without_asking` ("Allow without asking" items only); `None` when not approved.
    pub approval: Option<&'static str>,
    pub outcome: AiOutcome,
    /// [`AiOutcome::Finished`]: the command's exit code (`None` if it was ended by a signal).
    pub exit_code: Option<i32>,
}

#[derive(Default)]
pub(crate) struct AiState {
    grants: Vec<AiGrant>,
    /// Counts [`Agent::ai_forget_grants`]: a prompt answered after a lock grants nothing.
    pub(crate) epoch: u64,
    log: VecDeque<AiLogEntry>,
    next_id: u64,
    denials: HashMap<String, VecDeque<Instant>>,
}

/// One approval prompt at a time; see [`MAX_PROMPT_WAITERS`].
#[derive(Default)]
pub(crate) struct AiPrompts {
    slot: Mutex<()>,
    waiting: AtomicUsize,
}

/// Holds the prompt slot ([`AiPrompts`]) while alive.
pub(crate) struct PromptSlot<'a> {
    _slot: MutexGuard<'a, ()>,
    waiting: &'a AtomicUsize,
}

impl Drop for PromptSlot<'_> {
    fn drop(&mut self) {
        self.waiting.fetch_sub(1, Ordering::SeqCst);
    }
}

impl AiPrompts {
    /// Waits for the prompt slot, or `None` right away when [`MAX_PROMPT_WAITERS`] requests are
    /// waiting already.
    pub(crate) fn enter(&self) -> Option<PromptSlot<'_>> {
        if self.waiting.fetch_add(1, Ordering::SeqCst) >= MAX_PROMPT_WAITERS {
            self.waiting.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        let slot = self.slot.lock().unwrap_or_else(|p| p.into_inner());
        Some(PromptSlot {
            _slot: slot,
            waiting: &self.waiting,
        })
    }
}

impl Agent {
    pub(crate) fn ai_state(&self) -> MutexGuard<'_, AiState> {
        self.ai.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The standing permissions ("Allow until the vault locks") in effect, oldest first.
    pub fn ai_grants(&self) -> Vec<AiGrant> {
        self.ai_state().grants.clone()
    }

    /// Revokes the grant of `client_key` for `item_id`. `false` if there was none.
    pub fn ai_revoke(&self, item_id: &str, client_key: &str) -> bool {
        let mut ai = self.ai_state();
        let before = ai.grants.len();
        ai.grants
            .retain(|g| !(g.item_id == item_id && g.client_key == client_key));
        before != ai.grants.len()
    }

    /// The log of recent requests, newest first.
    pub fn ai_log(&self) -> Vec<AiLogEntry> {
        self.ai_state().log.iter().rev().cloned().collect()
    }

    /// Clears the log of recent requests.
    pub fn ai_clear_log(&self) {
        self.ai_state().log.clear();
    }

    /// Every lock ends the standing permissions.
    pub(crate) fn ai_forget_grants(&self) {
        let mut ai = self.ai_state();
        ai.grants.clear();
        ai.epoch += 1;
    }

    pub(crate) fn ai_granted(&self, item_id: &str, client_key: &str) -> bool {
        self.ai_state()
            .grants
            .iter()
            .any(|g| g.item_id == item_id && g.client_key == client_key)
    }

    /// Adds grants, unless the vault was locked since `epoch` was read.
    pub(crate) fn ai_grant(&self, epoch: u64, grants: Vec<AiGrant>) -> bool {
        let mut ai = self.ai_state();
        if ai.epoch != epoch {
            return false;
        }
        for grant in grants {
            if !ai
                .grants
                .iter()
                .any(|g| g.item_id == grant.item_id && g.client_key == grant.client_key)
            {
                ai.grants.push(grant);
            }
        }
        true
    }

    /// Logs a request; returns its id.
    pub(crate) fn ai_log_entry(&self, mut entry: AiLogEntry) -> u64 {
        let at = self.unix_ms();
        let mut ai = self.ai_state();
        ai.next_id += 1;
        entry.id = ai.next_id;
        entry.at = at;
        let id = entry.id;
        ai.log.push_back(entry);
        while ai.log.len() > MAX_LOG {
            ai.log.pop_front();
        }
        drop(ai);
        self.ui.ai_activity();
        id
    }

    /// Records how a running command ended. `false` if `id` isn't a running command.
    pub(crate) fn ai_log_finish(
        &self,
        id: u64,
        outcome: AiOutcome,
        exit_code: Option<i32>,
    ) -> bool {
        let mut ai = self.ai_state();
        let Some(entry) = ai
            .log
            .iter_mut()
            .find(|e| e.id == id && e.outcome == AiOutcome::Running)
        else {
            return false;
        };
        entry.outcome = outcome;
        entry.exit_code = exit_code;
        drop(ai);
        self.ui.ai_activity();
        true
    }

    /// Counts a denial of `client_key`.
    pub(crate) fn ai_note_denial(&self, client_key: &str) {
        let now = self.now();
        let mut ai = self.ai_state();
        let recent = ai.denials.entry(client_key.to_string()).or_default();
        recent.push_back(now);
        while recent.len() > MAX_DENIALS {
            recent.pop_front();
        }
    }

    /// Whether `client_key` was denied [`MAX_DENIALS`] times within [`DENIAL_WINDOW`].
    pub(crate) fn ai_denied_recently(&self, client_key: &str) -> bool {
        let now = self.now();
        let mut ai = self.ai_state();
        let Some(recent) = ai.denials.get_mut(client_key) else {
            return false;
        };
        while recent
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= DENIAL_WINDOW)
        {
            recent.pop_front();
        }
        recent.len() >= MAX_DENIALS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_labels_and_keys() {
        let client = AiClient {
            name: "claude-code".into(),
            version: "2.1.0".into(),
            process: "claude.exe".into(),
            ..Default::default()
        };
        assert_eq!(client.label(), "Claude Code (claude.exe)");
        assert_eq!(client.key(), "claude-code|claude.exe");
        let titled = AiClient {
            name: "x".into(),
            title: "My Tool".into(),
            ..Default::default()
        };
        assert_eq!(titled.label(), "My Tool");
        assert_eq!(AiClient::default().label(), "Unknown AI tool");
        assert_eq!(
            AiClient {
                name: "codex-mcp-client".into(),
                process: "codex.exe".into(),
                ..Default::default()
            }
            .label(),
            "Codex (codex.exe)"
        );
    }

    #[test]
    fn command_lines_quote_what_needs_it() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(command_line("gh", &args(&["api", "user"])), "gh api user");
        assert_eq!(
            command_line(
                r"C:\Program Files\gh.exe",
                &args(&["-H", "a b", "", r#"x"y"#])
            ),
            r#""C:\Program Files\gh.exe" -H "a b" "" "x\"y""#
        );
    }
}
