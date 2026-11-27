//! Editing logins from the extension popup.
//!
//! Same rules as fills: a login can only be read or changed from a page it belongs to, and only
//! after the per-fill verification. Input is checked again here, whatever the extension checked.

use std::time::Duration;

use pass_core::{
    b64url_decode, check_notes_length, registrable_domain, totp_parse, url_suggests_host_only,
    Item, ItemKind, TotpAlgorithm, UrlMatch, UrlRule, MAX_NOTES_CHARS,
};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};

use super::{fill_only, read_only, vault_json, ErrorCode, RpcError, RpcResult};
use crate::{Agent, Reason};

#[cfg(feature = "import-qr")]
pub(super) const FEATURES: &[&str] = &[
    "edit",
    "totp.from_image",
    "notes.create",
    "notes.append",
    "url_rules",
];
#[cfg(not(feature = "import-qr"))]
pub(super) const FEATURES: &[&str] = &["edit", "notes.create", "notes.append", "url_rules"];

const MAX_TITLE: usize = 256;
const MAX_USERNAME: usize = 512;
const MAX_PASSWORD: usize = 4096;
const MAX_URLS: usize = 32;
const MAX_URL: usize = 2048;
const MAX_TOTP: usize = 2048;
/// RFC 4226 asks for 128 bits; 80 bits (16 base32 characters) is the shortest seen in practice.
const MIN_TOTP_SECRET: usize = 10;
/// A screenshot of the visible tab.
const MAX_IMAGE: usize = 8 * 1024 * 1024;

const EDITS_PER_MINUTE: usize = 30;
const SCANS_PER_MINUTE: usize = 10;
const MINUTE: Duration = Duration::from_secs(60);

fn invalid(message: impl Into<String>) -> RpcError {
    RpcError::new(ErrorCode::InvalidParams, message)
}

/// `"totp": null` (remove) apart from no `totp` at all (keep).
fn present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(d).map(Some)
}

#[derive(Deserialize)]
pub(super) struct EditRef {
    url: String,
    #[serde(alias = "item_id")]
    id: String,
}

/// The editable fields. Missing ones are left as they are; `totp: null` or `""` removes 2FA.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct Fields {
    title: Option<String>,
    username: Option<String>,
    password: Option<String>,
    notes: Option<String>,
    urls: Option<Vec<String>>,
    /// The websites' rules (each `url` as in `urls`), replacing those of every website; missing:
    /// each website kept keeps its rule.
    url_rules: Option<Vec<UrlRule>>,
    #[serde(default, deserialize_with = "present")]
    totp: Option<Option<String>>,
}

#[derive(Deserialize)]
pub(super) struct UpdateParams {
    url: String,
    #[serde(alias = "item_id")]
    id: String,
    fields: Fields,
}

#[derive(Deserialize)]
pub(super) struct CreateParams {
    url: String,
    #[serde(default)]
    fields: Fields,
    /// The vault the new login goes into (an id from a `vaults` table); default the vault
    /// `logins.save_check` would offer first.
    #[serde(default)]
    vault: Option<String>,
}

/// A new secure note's fields: a title (required) and its text.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct NoteFields {
    title: Option<String>,
    notes: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct NoteCreateParams {
    #[serde(default)]
    fields: NoteFields,
    /// The vault the note goes into (an id from a `vaults` table); default the vault a new login
    /// would go into without a page.
    #[serde(default)]
    vault: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NoteAppendParams {
    id: String,
    text: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MoveParams {
    #[serde(alias = "item_id")]
    id: String,
    /// The vault it goes into (an id from a `vaults` table).
    vault: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuleHintParams {
    url: String,
}

#[derive(Deserialize)]
pub(super) struct TotpSetParams {
    url: String,
    #[serde(alias = "item_id")]
    id: Option<String>,
    /// An `otpauth://totp/…` link or a base32 secret; `null` or `""` removes 2FA (with `id`).
    #[serde(alias = "otpauth", alias = "secret")]
    totp: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct FromImageParams {
    url: String,
    #[serde(alias = "item_id")]
    id: Option<String>,
    /// PNG or JPEG, base64url.
    #[serde(alias = "png")]
    image: String,
}

/// A single-line text field: trimmed, no control characters, at most `max` characters.
fn line(field: &str, value: &str, max: usize) -> Result<String, RpcError> {
    let value = value.trim();
    if value.chars().count() > max {
        return Err(invalid(format!("{field} is too long")));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid(format!("{field} can't contain line breaks")));
    }
    Ok(value.to_string())
}

fn password(value: &str) -> Result<String, RpcError> {
    if value.chars().count() > MAX_PASSWORD {
        return Err(invalid("password is too long"));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid("password can't contain line breaks"));
    }
    Ok(value.to_string())
}

/// Notes replacing `before` (the stored notes, `None` for a new item): pass-core's cap, so a
/// note already over it can still be saved unchanged or shorter.
fn notes(value: &str, before: Option<&str>) -> Result<String, RpcError> {
    check_notes_length(value, before)?;
    if value
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err(invalid("notes contain control characters"));
    }
    Ok(value.to_string())
}

/// The text `notes.append` adds: trimmed, not empty, line breaks and tabs kept, no longer than a
/// note may be.
fn appended(value: &str) -> Result<&str, RpcError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(invalid("there is no text to add"));
    }
    if value.chars().count() > MAX_NOTES_CHARS {
        return Err(invalid("the text is too long"));
    }
    if value
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err(invalid("the text contains control characters"));
    }
    Ok(value)
}

/// `text` on a line of its own after what `notes` already holds.
fn with_line(notes: &str, text: &str) -> String {
    if notes.is_empty() {
        text.to_string()
    } else if notes.ends_with('\n') {
        format!("{notes}{text}")
    } else {
        format!("{notes}\n{text}")
    }
}

/// A website address for a login: `http`/`https` only (no scheme means `https://`), with a host
/// and no credentials. A bare origin is stored without the trailing `/`.
pub(crate) fn web_url(input: &str) -> Result<String, RpcError> {
    let input = input.trim();
    let bad = || invalid(format!("{input} is not a website address"));
    if input.is_empty() || input.len() > MAX_URL || input.chars().any(char::is_whitespace) {
        return Err(bad());
    }
    let with_scheme = if input.contains("://") {
        input.to_string()
    } else {
        format!("https://{input}")
    };
    let url = url::Url::parse(&with_scheme).map_err(|_| bad())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none_or(str::is_empty)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(bad());
    }
    if url.path() == "/" && url.query().is_none() && url.fragment().is_none() {
        return Ok(url.origin().ascii_serialization());
    }
    Ok(url.to_string())
}

/// Whether the editor shows a stored URL entry: websites, including bare hosts from imports.
/// App pins (`windows:<exe>`, `macos:<bundle id>`) and other schemes are kept but not shown.
pub(super) fn is_web_entry(entry: &str) -> bool {
    let entry = entry.trim();
    let pinned = pass_core::APP_PIN_PREFIXES.iter().any(|prefix| {
        entry
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    });
    if entry.is_empty() || pinned {
        return false;
    }
    match entry.split_once("://") {
        Some((scheme, _)) => matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https"),
        None => !entry.contains(':') || entry.contains('.'),
    }
}

/// A website as the editor sent it, as stored: an unchanged entry verbatim, else [`web_url`].
fn stored_entry(existing: &[String], entry: &str) -> Result<String, RpcError> {
    if existing.iter().any(|e| e == entry) && is_web_entry(entry) {
        Ok(entry.to_string())
    } else {
        web_url(entry)
    }
}

/// The new URL list: the edited websites (unchanged entries kept verbatim), then the entries the
/// editor doesn't show.
fn merge_urls(existing: &[String], edited: &[String]) -> Result<Vec<String>, RpcError> {
    if edited.len() > MAX_URLS {
        return Err(invalid("too many websites"));
    }
    let mut out: Vec<String> = Vec::new();
    for entry in edited {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let value = stored_entry(existing, entry)?;
        if !out.contains(&value) {
            out.push(value);
        }
    }
    out.extend(existing.iter().filter(|e| !is_web_entry(e)).cloned());
    Ok(out)
}

/// The new rules: `edited` for the websites (each named as the editor sent it, see
/// [`stored_entry`]), the rules of the entries the editor doesn't show kept. `Vault::upsert` drops
/// default rules and those of websites the item no longer has.
fn merge_rules(
    existing_urls: &[String],
    existing: &[UrlRule],
    edited: &[UrlRule],
) -> Result<Vec<UrlRule>, RpcError> {
    if edited.len() > MAX_URLS {
        return Err(invalid("too many websites"));
    }
    let mut out: Vec<UrlRule> = existing
        .iter()
        .filter(|r| !is_web_entry(&r.url))
        .cloned()
        .collect();
    for rule in edited {
        let entry = rule.url.trim();
        if entry.is_empty() {
            continue;
        }
        out.push(UrlRule {
            url: stored_entry(existing_urls, entry)?,
            rule: rule.rule,
        });
    }
    Ok(out)
}

/// A 2FA value from the editor: `None` to remove; otherwise a valid `otpauth://totp/…` link or a
/// base32 secret (spaces and dashes dropped, upper case).
pub(crate) fn totp_value(input: &str) -> Result<Option<String>, RpcError> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(None);
    }
    if input.chars().count() > MAX_TOTP {
        return Err(invalid("2FA secret is too long"));
    }
    let lower = input.to_ascii_lowercase();
    if lower.starts_with("otpauth-migration:") {
        return Err(invalid(
            "That's a Google Authenticator export. Import it in the Passyble app",
        ));
    }
    let uri = lower.starts_with("otpauth://");
    if !uri && input.chars().any(|c| c.is_control()) {
        return Err(invalid("2FA secret is not valid"));
    }
    let config = totp_parse(input.to_string())?;
    if config.secret.len() < MIN_TOTP_SECRET {
        return Err(invalid("2FA secret is too short"));
    }
    if uri {
        return Ok(Some(input.to_string()));
    }
    Ok(Some(
        input
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_uppercase(),
    ))
}

/// The 2FA settings without the secret, plus the current code.
fn totp_info(totp: &str, now_secs: i64) -> Option<Value> {
    let config = totp_parse(totp.to_string()).ok()?;
    let code = pass_core::totp_generate(totp.to_string(), now_secs).ok()?;
    Some(json!({
        "issuer": config.issuer,
        "account": config.account,
        "digits": config.digits,
        "period": config.period,
        "algorithm": match config.algorithm {
            TotpAlgorithm::Sha1 => "SHA1",
            TotpAlgorithm::Sha256 => "SHA256",
            TotpAlgorithm::Sha512 => "SHA512",
        },
        "code": code.code,
        "remaining_secs": code.remaining_secs,
    }))
}

/// What the popup's list shows for a login (no secrets).
fn summary(item: &Item) -> Value {
    json!({
        "id": item.id, "title": item.title, "username": item.username,
        "has_totp": item.has_totp(), "has_passkey": !item.passkeys.is_empty(),
    })
}

/// The page the request came from, which must be an http(s) URL.
pub(super) fn page(url: &str) -> Result<url::Url, RpcError> {
    url::Url::parse(url)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
        .ok_or_else(|| RpcError::new(ErrorCode::UrlMismatch, "not a web page"))
}

/// The registrable domain of the page (its host if it has none, e.g. `localhost`).
pub(super) fn site(page: &url::Url) -> String {
    let host = page.host_str().unwrap_or_default().to_string();
    registrable_domain(host.clone()).unwrap_or(host)
}

impl Fields {
    fn apply(self, item: &mut Item) -> Result<(), RpcError> {
        if let Some(title) = &self.title {
            item.title = line("title", title, MAX_TITLE)?;
        }
        if let Some(username) = &self.username {
            item.username = line("username", username, MAX_USERNAME)?;
        }
        if let Some(value) = &self.password {
            item.password = password(value)?;
        }
        if let Some(value) = &self.notes {
            item.notes = notes(value, Some(&item.notes))?;
        }
        let before = item.urls.clone();
        if let Some(urls) = &self.urls {
            item.urls = merge_urls(&before, urls)?;
        }
        if let Some(rules) = &self.url_rules {
            item.url_rules = merge_rules(&before, &item.url_rules, rules)?;
        }
        if let Some(totp) = &self.totp {
            item.totp = match totp {
                Some(value) => totp_value(value)?,
                None => None,
            };
        }
        Ok(())
    }
}

impl Agent {
    pub(super) fn edit_rate(&self) -> Result<(), RpcError> {
        if self.within_rate("edit", EDITS_PER_MINUTE, MINUTE) {
            Ok(())
        } else {
            Err(RpcError::new(
                ErrorCode::RateLimited,
                "Too many changes. Wait a minute and try again",
            ))
        }
    }

    /// [`Self::verified`] for a change to login `id`, unless it was opened in the editor with a
    /// verification moments ago.
    fn verified_edit(&self, id: &str, reason: Reason) -> Result<(), RpcError> {
        if self.edit_granted(id) {
            return Ok(());
        }
        self.verified(reason)?;
        self.grant_edit(id);
        Ok(())
    }

    /// Saves the vault after a change from the extension and tells the windows.
    pub(super) fn edited(&self) -> Result<(), RpcError> {
        self.save()?;
        self.ui.vault_changed();
        Ok(())
    }

    /// `logins.get_for_edit`: every editable field of a login of this site, verified like a fill.
    /// The 2FA secret stays in the vault; only its settings and current code are returned.
    pub(super) fn rpc_get_for_edit(&self, p: EditRef) -> RpcResult {
        self.unlocked()?;
        self.edit_rate()?;
        let (vault_ref, _, item) = self.item_in(&p.url, &p.id)?;
        // The editor shows the password: never for a fill-only member's login.
        if !vault_ref.can_reveal {
            return Err(fill_only());
        }
        self.verified(Reason::EditLogin {
            title: item.title.clone(),
        })?;
        self.grant_edit(&item.id);
        let urls: Vec<&String> = item.urls.iter().filter(|u| is_web_entry(u)).collect();
        let rules: Vec<&UrlRule> = item
            .url_rules
            .iter()
            .filter(|r| is_web_entry(&r.url))
            .collect();
        Ok(json!({
            "id": item.id,
            "title": item.title,
            "username": item.username,
            "password": item.password,
            "notes": item.notes,
            "urls": urls,
            "url_rules": rules,
            "totp": item.totp.as_deref().filter(|t| !t.trim().is_empty()).map(|t| {
                totp_info(t, self.now_secs()).unwrap_or_else(|| json!({ "invalid": true }))
            }),
            "has_passkey": !item.passkeys.is_empty(),
            "vault": vault_json(&vault_ref),
            // A view member's login: shown without Save or Delete.
            "read_only": !vault_ref.can_edit,
        }))
    }

    /// The login of this site `id` and its vault, for a change: `read_only` in a vault this user
    /// may not change.
    fn editable_item(
        &self,
        url: &str,
        id: &str,
    ) -> Result<(crate::VaultRef, std::sync::Arc<pass_core::Vault>, Item), RpcError> {
        let found = self.item_in(url, id)?;
        if !found.0.can_edit {
            return Err(read_only());
        }
        Ok(found)
    }

    /// `sites.rule_hint { url }`: the rule the editor suggests for a website it is given (`"host"`
    /// for a site on a shared hosting platform, [`url_suggests_host_only`]), `null` for none. Only
    /// a suggestion, shown in the website's menu; nothing is changed.
    pub(super) fn rpc_rule_hint(&self, p: RuleHintParams) -> RpcResult {
        if p.url.len() > MAX_URL {
            return Err(invalid("url is too long"));
        }
        let hint = url_suggests_host_only(p.url).then_some(UrlMatch::Host);
        Ok(json!({ "suggested": hint }))
    }

    /// `logins.update`: changes the given fields of a login of this site.
    pub(super) fn rpc_update(&self, p: UpdateParams) -> RpcResult {
        self.unlocked()?;
        self.edit_rate()?;
        let (vault_ref, vault, mut item) = self.editable_item(&p.url, &p.id)?;
        p.fields.apply(&mut item)?;
        self.verified_edit(
            &item.id,
            Reason::SaveChanges {
                title: item.title.clone(),
            },
        )?;
        let saved = vault.upsert(item)?;
        self.edited()?;
        Ok(with_vault(summary(&saved), &vault_ref))
    }

    /// `logins.create`: a new login for this site, defaulting to the page's origin and site name.
    pub(super) fn rpc_create(&self, p: CreateParams) -> RpcResult {
        let opened = self.opened_or_locked()?;
        self.edit_rate()?;
        let page = page(&p.url)?;
        let (vault_ref, vault) = self.save_target(&opened, p.vault.as_deref(), &p.url)?;
        let mut item = Item {
            kind: ItemKind::Login,
            title: site(&page),
            ..Default::default()
        };
        p.fields.apply(&mut item)?;
        if item.title.is_empty() {
            item.title = site(&page);
        }
        if item.urls.is_empty() {
            item.urls = vec![page.origin().ascii_serialization()];
        }
        self.verified(Reason::AddLogin { site: site(&page) })?;
        let saved = vault.upsert(item)?;
        self.grant_edit(&saved.id);
        self.edited()?;
        Ok(with_vault(summary(&saved), &vault_ref))
    }

    /// `notes.create`: a new secure note (a title and its text, no website). It adds an item
    /// without releasing any secret, so it asks nothing, and it is not bound to a page.
    pub(super) fn rpc_note_create(&self, p: NoteCreateParams) -> RpcResult {
        let opened = self.opened_or_locked()?;
        self.edit_rate()?;
        let title = line(
            "title",
            p.fields.title.as_deref().unwrap_or_default(),
            MAX_TITLE,
        )?;
        if title.is_empty() {
            return Err(invalid("a note needs a title"));
        }
        let text = notes(p.fields.notes.as_deref().unwrap_or_default(), None)?;
        let (vault_ref, vault) = super::new_item_vault(&opened, p.vault.as_deref())?;
        let saved = vault.upsert(Item {
            kind: ItemKind::Note,
            title,
            notes: text,
            ..Default::default()
        })?;
        self.edited()?;
        Ok(with_vault(
            json!({ "id": saved.id, "title": saved.title, "kind": saved.kind.as_str() }),
            &vault_ref,
        ))
    }

    /// `items.move`: moves item `id` between two open vaults the user can edit; it gets a new id
    /// there. Moving it into a shared vault shows it to that vault's members, so it is verified
    /// like an edit.
    pub(super) fn rpc_items_move(&self, p: MoveParams) -> RpcResult {
        let opened = self.opened_or_locked()?;
        self.edit_rate()?;
        let (source_ref, source) = opened
            .holding(&p.id)
            .cloned()
            .ok_or_else(|| RpcError::new(ErrorCode::NotFound, "no such item"))?;
        let item = source
            .get(p.id.clone())
            .ok_or_else(|| RpcError::new(ErrorCode::NotFound, "no such item"))?;
        let (target_ref, _) = opened
            .by_id(&p.vault)
            .ok_or_else(|| RpcError::new(ErrorCode::NotFound, "that vault isn't open"))?;
        if source_ref.id == target_ref.id {
            return Err(invalid("the item is in that vault already"));
        }
        if !source_ref.can_edit || !target_ref.can_edit {
            return Err(read_only());
        }
        self.verified_edit(
            &item.id,
            Reason::SaveChanges {
                title: item.title.clone(),
            },
        )?;
        let moved = self.transfer_item(&item.id, &target_ref.id, true)?;
        Ok(with_vault(
            json!({ "id": moved.id, "title": moved.title, "kind": moved.kind.as_str(), "moved_from": item.id }),
            target_ref,
        ))
    }

    /// `notes.append`: adds `text` as a new line at the end of secure note `id`, never replacing
    /// what it holds. Verified like `logins.update`; the answer carries no text.
    pub(super) fn rpc_note_append(&self, p: NoteAppendParams) -> RpcResult {
        let opened = self.opened_or_locked()?;
        self.edit_rate()?;
        let text = appended(&p.text)?;
        let no_note = || RpcError::new(ErrorCode::NotFound, "no such note");
        let (vault_ref, vault) = opened.holding(&p.id).cloned().ok_or_else(no_note)?;
        let live_note = || {
            vault
                .get(p.id.clone())
                .filter(|i| !i.is_trashed() && i.kind == ItemKind::Note)
                .ok_or_else(no_note)
        };
        let item = live_note()?;
        if !vault_ref.can_edit {
            return Err(read_only());
        }
        // A fill-only member never sees the note, so it can't add to it either.
        if !vault_ref.can_reveal {
            return Err(fill_only());
        }
        // All or nothing: a note that would pass the notes limit gets none of the text.
        let joined = |notes: &str| -> Result<String, RpcError> {
            let all = with_line(notes, text);
            check_notes_length(&all, Some(notes))?;
            Ok(all)
        };
        joined(&item.notes)?;
        self.verified_edit(&item.id, Reason::SaveChanges { title: item.title })?;
        // Read again: the note may have changed while the user was asked.
        let mut item = live_note()?;
        item.notes = joined(&item.notes)?;
        // The usual item update, so the vault's own checks on notes apply too.
        let saved = vault.upsert(item)?;
        self.edited()?;
        self.record_use(&saved.id);
        Ok(with_vault(
            json!({ "id": saved.id, "title": saved.title, "kind": saved.kind.as_str() }),
            &vault_ref,
        ))
    }

    /// `logins.delete`: keeps a copy in memory for [`crate::DELETE_UNDO_WINDOW`], dropped on lock.
    pub(super) fn rpc_delete(&self, p: EditRef) -> RpcResult {
        self.unlocked()?;
        self.edit_rate()?;
        let page = page(&p.url)?;
        let (_, vault, item) = self.editable_item(&p.url, &p.id)?;
        self.verified_edit(
            &item.id,
            Reason::DeleteLogin {
                title: item.title.clone(),
            },
        )?;
        vault.delete(item.id.clone())?;
        self.remember_deleted(&vault.vault_id(), &site(&page), item);
        self.edited()?;
        Ok(json!({ "undo_secs": crate::DELETE_UNDO_WINDOW.as_secs() }))
    }

    /// `logins.restore`: Undo for `logins.delete`, or for a password update by `logins.save`,
    /// from a page of the same site.
    pub(super) fn rpc_restore(&self, p: EditRef) -> RpcResult {
        let opened = self.opened_or_locked()?;
        self.edit_rate()?;
        let page = page(&p.url)?;
        // Back into the vault it was deleted (or updated) in, if this user may still change it.
        let (vault_ref, vault, item) = opened
            .0
            .iter()
            .filter(|(r, _)| r.can_edit)
            .find_map(|(r, v)| {
                self.take_deleted(&v.vault_id(), &site(&page), &p.id)
                    .map(|item| (r.clone(), v.clone(), item))
            })
            .ok_or_else(|| RpcError::new(ErrorCode::NotFound, "It's too late to undo that"))?;
        let restored = vault.upsert(item)?;
        self.edited()?;
        Ok(with_vault(summary(&restored), &vault_ref))
    }

    /// `totp.set`: with `id`, sets or removes the 2FA secret of a login of this site. Without
    /// `id`, only checks the value and returns a preview.
    pub(super) fn rpc_totp_set(&self, p: TotpSetParams) -> RpcResult {
        self.unlocked()?;
        self.edit_rate()?;
        let value = totp_value(p.totp.as_deref().unwrap_or_default())?;
        self.apply_totp(&p.url, p.id.as_deref(), value)
    }

    fn apply_totp(&self, url: &str, id: Option<&str>, value: Option<String>) -> RpcResult {
        let Some(id) = id else {
            let value = value.ok_or_else(|| invalid("2FA secret is empty"))?;
            page(url)?;
            return Ok(totp_info(&value, self.now_secs()).unwrap_or_else(|| json!({})));
        };
        let (vault_ref, vault, mut item) = self.editable_item(url, id)?;
        item.totp = value;
        self.verified_edit(
            &item.id,
            Reason::ChangeCode {
                title: item.title.clone(),
            },
        )?;
        let saved = vault.upsert(item)?;
        self.edited()?;
        let mut result = with_vault(summary(&saved), &vault_ref);
        if let Some(info) = saved
            .totp
            .as_deref()
            .and_then(|t| totp_info(t, self.now_secs()))
        {
            result["totp"] = info;
        }
        Ok(result)
    }

    /// `totp.from_image`: reads a 2FA QR code from a screenshot of the tab. With `id` it is saved
    /// like `totp.set`; without, the link is returned for the editor to save.
    pub(super) fn rpc_totp_from_image(&self, p: FromImageParams) -> RpcResult {
        self.unlocked()?;
        page(&p.url)?;
        if !self.within_rate("scan", SCANS_PER_MINUTE, MINUTE) {
            return Err(RpcError::new(
                ErrorCode::RateLimited,
                "Too many scans. Wait a minute and try again",
            ));
        }
        if p.image.len() > MAX_IMAGE / 3 * 4 + 4 {
            return Err(invalid("the image is too large"));
        }
        let image = b64url_decode(p.image).map_err(|_| invalid("image is not base64url"))?;
        let link = qr_otpauth(&image)?;
        let value = totp_value(&link)?;
        if p.id.is_some() {
            return self.apply_totp(&p.url, p.id.as_deref(), value);
        }
        let value = value.ok_or_else(|| invalid("2FA secret is empty"))?;
        let mut result = totp_info(&value, self.now_secs()).unwrap_or_else(|| json!({}));
        result["totp"] = json!(value);
        Ok(result)
    }

    /// `app.show_item`: "Open in Passyble" for a login of this site or a recent search result.
    /// Works soft-locked too.
    pub(super) fn rpc_show_item(&self, p: EditRef) -> RpcResult {
        let (list, _) = self.listed()?;
        if !list.iter().any(|i| i.id == p.id) {
            return Err(RpcError::new(ErrorCode::NotFound, "no such item"));
        }
        let of_page = pass_core::summaries_for_url(list.to_vec(), p.url.clone())
            .iter()
            .any(|i| i.id == p.id);
        if !of_page && !self.search_hit(&p.id) {
            return Err(RpcError::new(
                ErrorCode::UrlMismatch,
                "item does not belong to this site",
            ));
        }
        let id = p.id;
        if !self.ui.show_item(&id) {
            return Err(RpcError::new(
                ErrorCode::NotSupported,
                "this Passyble app can't show a login",
            ));
        }
        Ok(json!({ "shown": true }))
    }
}

/// An answer about one login with its vault (`vault`).
fn with_vault(mut answer: Value, vault: &crate::VaultRef) -> Value {
    answer["vault"] = vault_json(vault);
    answer
}

/// The first `otpauth://totp/…` link in the image's QR codes.
#[cfg(feature = "import-qr")]
fn qr_otpauth(image: &[u8]) -> Result<String, RpcError> {
    let texts = pass_core::qr_decode_image(image)
        .map_err(|_| RpcError::new(ErrorCode::NotFound, "No QR code found on this page"))?;
    let lower = |t: &String| t.trim().to_ascii_lowercase();
    if let Some(link) = texts
        .iter()
        .find(|t| lower(t).starts_with("otpauth://totp/"))
    {
        return Ok(link.trim().to_string());
    }
    if texts
        .iter()
        .any(|t| lower(t).starts_with("otpauth-migration:"))
    {
        return Err(invalid(
            "That's a Google Authenticator export. Import it in the Passyble app",
        ));
    }
    Err(RpcError::new(
        ErrorCode::NotFound,
        "No 2FA QR code found on this page",
    ))
}

#[cfg(not(feature = "import-qr"))]
fn qr_otpauth(_image: &[u8]) -> Result<String, RpcError> {
    Err(RpcError::new(
        ErrorCode::NotSupported,
        "this Passyble build can't read QR codes",
    ))
}

#[cfg(test)]
mod tests {
    use super::{is_web_entry, merge_urls, totp_value, web_url};

    #[test]
    fn website_addresses() {
        assert_eq!(web_url("github.com").unwrap(), "https://github.com");
        assert_eq!(
            web_url(" https://github.com/ ").unwrap(),
            "https://github.com"
        );
        assert_eq!(
            web_url("http://localhost:8080/login").unwrap(),
            "http://localhost:8080/login"
        );
        for bad in [
            "",
            "javascript:alert(1)",
            "ftp://example.com",
            "https://user:pw@example.com",
            "file:///C:/x",
            "a b.com",
            "data:text/html,hi",
        ] {
            assert!(web_url(bad).is_err(), "{bad}");
        }
        assert!(is_web_entry("github.com"));
        assert!(!is_web_entry("windows:putty.exe"));
        assert!(!is_web_entry("androidapp://com.example"));
        // App pins: macOS bundle IDs have dots, but are not hosts; any case; also unfinished.
        assert!(!is_web_entry("macos:com.apple.Terminal"));
        assert!(!is_web_entry("MacOS:com.apple.Terminal"));
        assert!(!is_web_entry("WINDOWS:Putty.exe"));
        assert!(!is_web_entry("macos:"));
        assert!(!is_web_entry(" macos:com.example.app "));
        // Not pins: a host that starts like one.
        assert!(is_web_entry("macos.example.com"));
        let merged = merge_urls(
            &["github.com".into(), "windows:git.exe".into()],
            &["github.com".into(), "gist.github.com".into(), "".into()],
        )
        .unwrap();
        assert_eq!(
            merged,
            ["github.com", "https://gist.github.com", "windows:git.exe"]
        );
    }

    #[test]
    fn totp_values() {
        assert_eq!(
            totp_value("jbsw y3dp ehpk 3pxp").unwrap().as_deref(),
            Some("JBSWY3DPEHPK3PXP")
        );
        assert_eq!(totp_value("  ").unwrap(), None);
        for bad in [
            "not base32!",
            "JBSW",
            "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1",
            "otpauth-migration://offline?data=abc",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=99",
        ] {
            assert!(totp_value(bad).is_err(), "{bad}");
        }
        let link = "otpauth://totp/GitHub:octo?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";
        assert_eq!(totp_value(link).unwrap().as_deref(), Some(link));
    }
}
