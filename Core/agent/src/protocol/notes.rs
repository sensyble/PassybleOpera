//! Secure notes in the extension popup: `notes.list` and `notes.get`.
//!
//! A note may hold recovery codes, so the list carries titles only and the text leaves the vault
//! only through `notes.get`, which is verified like copying a password from a search.

use std::time::Duration;

use pass_core::{summaries_suggested, ItemKind, ItemSummary};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{fill_only, vault_json, vaults_json, ErrorCode, RpcError, RpcResult};
use crate::{Agent, Reason};

const MAX_QUERY: usize = 128;
const DEFAULT_LIMIT: i64 = 100;
const MAX_LIMIT: i64 = 200;
const LISTS_PER_MINUTE: usize = 120;
const OPENS_PER_MINUTE: usize = 30;
const MINUTE: Duration = Duration::from_secs(60);

#[derive(Deserialize)]
pub(super) struct ListParams {
    /// Words the title must hold (any order, case ignored); none: every note.
    #[serde(default)]
    query: Option<String>,
    limit: Option<i64>,
}

#[derive(Deserialize)]
pub(super) struct GetParams {
    id: String,
    /// The app copies the text itself (cleared after 45 s, out of clipboard history) and the
    /// answer has none.
    #[serde(default)]
    copy: bool,
}

fn rate_limited() -> RpcError {
    RpcError::new(
        ErrorCode::RateLimited,
        "Too many requests. Wait a minute and try again",
    )
}

fn no_note() -> RpcError {
    RpcError::new(ErrorCode::NotFound, "no such note")
}

/// A note of the list: no text, nothing but what names it.
fn note_json(note: &ItemSummary) -> Value {
    json!({
        "id": note.id, "title": note.title, "favorite": note.favorite, "updated": note.updated_at,
    })
}

impl Agent {
    /// `notes.list`: the secure notes of every open vault in suggestion order, never their text.
    /// Not activity.
    pub(super) fn rpc_notes_list(&self, p: ListParams) -> RpcResult {
        let listed = self.listed_all()?;
        if !self.within_rate("notes_list", LISTS_PER_MINUTE, MINUTE) {
            return Err(rate_limited());
        }
        let query = p.query.unwrap_or_default().trim().to_lowercase();
        if query.chars().count() > MAX_QUERY {
            return Err(RpcError::new(ErrorCode::InvalidParams, "query is too long"));
        }
        let words: Vec<&str> = query.split_whitespace().collect();
        let limit = p.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT) as usize;
        let notes: Vec<ItemSummary> = listed
            .all()
            .into_iter()
            .filter(|i| i.kind == ItemKind::Note && i.trashed_at.is_none())
            .filter(|i| {
                let title = i.title.to_lowercase();
                words.iter().all(|w| title.contains(w))
            })
            .collect();
        let notes = summaries_suggested(notes);
        let truncated = notes.len() > limit;
        let shown = &notes[..notes.len().min(limit)];
        let items: Vec<Value> = shown
            .iter()
            .map(|n| {
                let mut row = note_json(n);
                row["vault_id"] = json!(listed.ref_of(&n.id).map(|r| r.id.clone()));
                row
            })
            .collect();
        let vaults = vaults_json(&listed.table(shown.iter().map(|n| n.id.as_str())));
        Ok(json!({
            "items": items, "truncated": truncated, "locked": listed.locked, "vaults": vaults,
        }))
    }

    /// `notes.get`: a secure note's text, verified every time. With `copy` the app copies it
    /// instead and the answer has no text.
    pub(super) fn rpc_notes_get(&self, p: GetParams) -> RpcResult {
        let opened = self.opened_or_locked()?;
        let (vault_ref, vault) = opened.holding(&p.id).cloned().ok_or_else(no_note)?;
        let item = vault
            .get(p.id.clone())
            .filter(|i| !i.is_trashed() && i.kind == ItemKind::Note)
            .ok_or_else(no_note)?;
        // A fill-only member's items are never shown or copied, and a note has nothing to fill.
        if !vault_ref.can_reveal {
            return Err(fill_only());
        }
        if !self.within_rate("notes_get", OPENS_PER_MINUTE, MINUTE) {
            return Err(rate_limited());
        }
        let title = item.title.clone();
        self.verified(if p.copy {
            Reason::CopyNote { title }
        } else {
            Reason::ShowNote { title }
        })?;
        self.record_use(&item.id);
        if p.copy {
            if item.notes.is_empty() {
                return Ok(json!({ "copied": false }));
            }
            if !self.ui.copy_to_clipboard(&item.notes) {
                return Err(RpcError::new(
                    ErrorCode::NotSupported,
                    "this Passyble app can't copy to the clipboard",
                ));
            }
            return Ok(json!({ "copied": true }));
        }
        Ok(json!({
            "id": item.id, "title": item.title, "notes": item.notes, "favorite": item.favorite,
            "updated": item.updated_at, "vault": vault_json(&vault_ref),
        }))
    }
}
