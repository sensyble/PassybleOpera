//! Request handling for the browser extension protocol.

mod account;
mod ai;
mod card_save;
pub mod check;
mod edit;
mod forms;
mod generate;
mod icons;
mod import;
mod notes;
mod otp_outcome;
mod save;
pub(crate) mod search;
mod sites;
mod unlock;
mod vaults;

use pass_core::{
    b64url_decode, b64url_encode, client_data_json, generate_password, passkey_assert,
    passkey_create, prf_authentication_check, prf_authentication_output, prf_registration_check,
    prf_registration_output, rp_id_valid_for_origin, sha256, totp_generate, Item, ItemKind,
    PassError, PasskeyCreation, PasswordOptions, PrfRequestError,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    Agent, Consent, ItemSecret, PasskeyChoice, PasskeyPick, Reason, Verification, VERSION,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    Locked,
    NotFound,
    UrlMismatch,
    Cancelled,
    InvalidState,
    NotSupported,
    InvalidParams,
    AgentUnavailable,
    Internal,
    /// Too many edit requests in a short time.
    RateLimited,
    /// `unlock.password`: the master password didn't open the vault.
    WrongPassword,
    /// The host must verify the user first, then send the request again with a grant.
    /// Only the extension's own vault answers this.
    VerificationRequired,
    /// The extension's own vault: there is no vault in this browser yet.
    NoVault,
    /// Read-only mode: this app is below the minimum version the owner set.
    UpdateRequired,
    /// The item is in a shared vault this user may use but not change (a view or fill member,
    /// or a vault the server takes no uploads for).
    ReadOnly,
    /// A fill-only member's login (or card): filled, never shown or copied.
    FillOnly,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Locked => "locked",
            ErrorCode::NotFound => "not_found",
            ErrorCode::UrlMismatch => "url_mismatch",
            ErrorCode::Cancelled => "cancelled",
            ErrorCode::InvalidState => "invalid_state",
            ErrorCode::NotSupported => "not_supported",
            ErrorCode::InvalidParams => "invalid_params",
            ErrorCode::AgentUnavailable => "agent_unavailable",
            ErrorCode::Internal => "internal",
            ErrorCode::RateLimited => "rate_limited",
            ErrorCode::WrongPassword => "wrong_password",
            ErrorCode::VerificationRequired => "verification_required",
            ErrorCode::NoVault => "no_vault",
            ErrorCode::UpdateRequired => "update_required",
            ErrorCode::ReadOnly => "read_only",
            ErrorCode::FillOnly => "fill_only",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError {
    pub code: ErrorCode,
    pub message: String,
}

impl RpcError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<PassError> for RpcError {
    fn from(e: PassError) -> Self {
        let text = e.to_string();
        let words = crate::agent::payload(&e);
        let is = |key: &str| pass_core::core_message_is(words.clone(), key.to_string());
        let code = match e {
            // The core's shared-vault role checks.
            PassError::InvalidInput(_) if is("share.read_only") || is("emergency.view_only") => {
                ErrorCode::ReadOnly
            }
            PassError::InvalidInput(_) if is("share.fill_only") => ErrorCode::FillOnly,
            PassError::NotFound(_) => ErrorCode::NotFound,
            PassError::InvalidInput(_) => ErrorCode::InvalidParams,
            _ => ErrorCode::Internal,
        };
        RpcError::new(code, text)
    }
}

/// A change in a vault this user may use but not change (`read_only`).
pub(crate) fn read_only() -> RpcError {
    RpcError::new(
        ErrorCode::ReadOnly,
        "You can use this vault's logins but not change them",
    )
}

/// The vault a new item goes into: `wanted` (an id from a `vaults` table), else the default one
/// without a page. `read_only` for a vault this user can't edit, `not_found` for one that isn't
/// open.
fn new_item_vault(
    opened: &crate::agent::Opened,
    wanted: Option<&str>,
) -> Result<InVault, RpcError> {
    let id = match wanted.filter(|w| !w.is_empty()) {
        Some(id) => id.to_string(),
        None => opened.default_save(None).ok_or_else(read_only)?,
    };
    let (vault_ref, vault) = opened
        .by_id(&id)
        .cloned()
        .ok_or_else(|| RpcError::new(ErrorCode::NotFound, "that vault isn't open"))?;
    if !vault_ref.can_edit {
        return Err(read_only());
    }
    Ok((vault_ref, vault))
}

/// A fill-only login's password (or a card's number) asked for anything but a fill (`fill_only`).
pub(crate) fn fill_only() -> RpcError {
    RpcError::new(
        ErrorCode::FillOnly,
        "This login can be filled but not shown or copied",
    )
}

/// A vault ref for an answer.
pub(crate) fn vault_json(vault: &crate::VaultRef) -> Value {
    serde_json::to_value(vault).unwrap_or(Value::Null)
}

/// The `vaults` table of a listing answer.
pub(crate) fn vaults_json(vaults: &[crate::VaultRef]) -> Value {
    Value::Array(vaults.iter().map(vault_json).collect())
}

type RpcResult = Result<Value, RpcError>;

/// An open vault: its [`crate::VaultRef`] and the vault.
type InVault = (crate::VaultRef, std::sync::Arc<pass_core::Vault>);

/// The feature names `status` advertises, including the ones that depend on the build, the
/// [`crate::Ui`] ([`crate::Ui::hello_in_browser`]) and the host ([`crate::Ui::host_features`]).
fn features(hello_in_browser: bool, host: &[&'static str]) -> Vec<&'static str> {
    let mut features = edit::FEATURES.to_vec();
    features.push("logins.search");
    features.push("logins.similar");
    features.push("logins.add_url");
    features.push("locked.list");
    features.push("unlock.inline");
    features.push("lock");
    features.push("cards");
    features.push("cards.save");
    features.push("identities");
    features.push("generate.username");
    features.push("generate.email");
    features.push("password.check");
    // Also covers `sites.name_for`.
    features.push("sites.suggest");
    // Shared vaults beside the home vault: `vault_id` / `vaults` / `vault` in answers, the
    // `read_only` and `fill_only` errors, `vaults.list` and `app.show_teams`.
    features.push("vaults");
    // `vaults.own` / `vaults.switch` answer `not_supported` on a host with one vault.
    features.push("vaults.pins");
    // `passkey.create` / `passkey.get` answer the WebAuthn PRF extension (`extensions.prf`).
    features.push("passkey.prf");
    features.push("sync.now");
    // `favorite` on the items of every list answer.
    features.push("items.favorite");
    features.push("notes.list");
    if cfg!(feature = "icons") {
        features.push("icons.get");
    }
    if hello_in_browser {
        features.push("unlock.hello_browser");
    }
    // The browser vault itself has nothing to move its items into, and its shared vaults are
    // opened by the extension, not here.
    if !host.contains(&"vault.browser") {
        features.push("items.import");
        features.push("items.move");
    }
    features.extend_from_slice(host);
    features
}

/// Requests the extension sends on its own (page loads, badge, banner checks, menus). They never
/// count as activity for the auto-lock, so browsing alone never keeps the vault unlocked.
pub const BACKGROUND_METHODS: &[&str] = &[
    "status",
    "logins.find",
    "logins.similar",
    "logins.save_check",
    "password.check",
    "icons.get",
    "otp.outcome",
    "cards.list",
    "cards.save_check",
    "identities.list",
    "notes.list",
    "generate",
    "generate.options",
    "unlock.options",
    "unlock.cancel",
    "passkey.find",
    "passkey.create_options",
    "vaults.list",
    "vaults.pins",
    "vaults.own",
    "account.status",
    "account.peer",
    "account.handoff_to_extension",
    "account.handoff_begin",
    "account.handoff_finish",
    "account.sign_out",
    "account.peer_signed_out",
];

fn is_background(method: &str) -> bool {
    BACKGROUND_METHODS.contains(&method)
}

/// Requests whose steps are timed: the path from picking a login or passkey to the filled page.
const TIMED_METHODS: &[&str] = &[
    "status",
    "unlock",
    "unlock.options",
    "unlock.password",
    "unlock.hello",
    "unlock.cancel",
    "logins.fill",
    "logins.fill_cross",
    "logins.copy",
    "totp.get",
    "totp.popup",
    "cards.fill",
    "passkey.find",
    "passkey.create_options",
    "passkey.create",
    "passkey.get",
];

fn is_timed(method: &str) -> bool {
    TIMED_METHODS.contains(&method)
}

/// `Ok(true)`: verified for real; `Ok(false)`: allowed without; `cancelled` if refused;
/// `verification_required` if the host verifies the user first and sends the request again.
fn verification_result(verification: Verification) -> Result<bool, RpcError> {
    match verification {
        Verification::Verified => Ok(true),
        Verification::Allowed => Ok(false),
        Verification::Refused => Err(RpcError::new(
            ErrorCode::Cancelled,
            "user verification cancelled",
        )),
        Verification::Required => Err(verification_required()),
    }
}

fn verification_required() -> RpcError {
    RpcError::new(
        ErrorCode::VerificationRequired,
        "Confirm it's you, then try again",
    )
}

fn parse<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T, RpcError> {
    serde_json::from_value(value)
        .map_err(|e| RpcError::new(ErrorCode::InvalidParams, e.to_string()))
}

fn b64(field: &str, value: &str) -> Result<Vec<u8>, RpcError> {
    b64url_decode(value.to_string()).map_err(|_| {
        RpcError::new(
            ErrorCode::InvalidParams,
            format!("{field} is not base64url"),
        )
    })
}

impl Agent {
    /// Now in Unix seconds (2FA codes), on the agent's clock.
    pub(crate) fn now_secs(&self) -> i64 {
        self.unix_ms().div_euclid(1000)
    }

    /// The login's current 2FA code, `None` without a (valid) secret.
    pub(crate) fn totp_json(&self, item: &Item) -> Option<Value> {
        let code = totp_generate(item.totp.clone()?, self.now_secs()).ok()?;
        Some(
            json!({ "code": code.code, "period": code.period, "remaining_secs": code.remaining_secs }),
        )
    }
}

#[derive(Deserialize)]
struct UrlParams {
    url: String,
}

#[derive(Deserialize)]
struct ItemParams {
    url: String,
    id: Option<String>,
}

#[derive(Deserialize)]
struct SaveParams {
    url: String,
    username: String,
    password: String,
    id: Option<String>,
    /// `"username"`: change login `id`'s username and keep its password. Otherwise the password
    /// is saved.
    update: Option<String>,
    /// The page's `<link rel="canonical">` address (checked again).
    #[serde(default)]
    canonical_url: Option<String>,
    /// The vault a new login goes into (`logins.save_check`'s `vaults`); default its
    /// `default_vault`.
    #[serde(default)]
    vault: Option<String>,
}

#[derive(Deserialize)]
struct ShowTeamsParams {
    #[serde(default)]
    section: Option<String>,
}

#[derive(Deserialize)]
struct ShowAccountParams {
    /// Start the app's account sign-in too (the extension's "Sign in" in app mode).
    #[serde(default)]
    sign_in: bool,
}

#[derive(Deserialize)]
struct PairParams {
    link: String,
}

/// Longest pairing link accepted from the extension (real ones are ~250 characters).
const MAX_LINK_LEN: usize = 4096;

/// Normalizes a server address typed by the user and returns it with its `host[:port]`.
///
/// It must accept exactly what core's `normalize_server_url` accepts, since the app signs in with
/// that. Plain `http://` is refused except for this device or a private network.
pub fn normalize_server_address(input: &str) -> Option<(String, String)> {
    let input = input.trim();
    if input.is_empty() || input.chars().any(char::is_whitespace) {
        return None;
    }
    let address = normalized_url(input)?;
    let url = url::Url::parse(&address).ok()?;
    let host = match url.port() {
        Some(port) => format!("{}:{port}", url.host_str()?),
        None => url.host_str()?.to_string(),
    };
    Some((address, host))
}

#[cfg(feature = "webdav")]
fn normalized_url(input: &str) -> Option<String> {
    pass_core::normalize_server_url(input.to_string()).ok()
}

/// Without sync support core has no `normalize_server_url`: same syntax rules, `https://` only.
#[cfg(not(feature = "webdav"))]
fn normalized_url(input: &str) -> Option<String> {
    let with_scheme = if input.contains("://") {
        input.to_string()
    } else {
        format!("https://{input}")
    };
    let url = url::Url::parse(&with_scheme).ok()?;
    if url.scheme() != "https"
        || url.host_str().is_none_or(str::is_empty)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    Some(url.as_str().trim_end_matches('/').to_string())
}

#[derive(Deserialize, Default)]
struct GenerateParams {
    length: Option<u32>,
    /// `false`: letters and digits only ("Letters and numbers only", for sites that reject symbols).
    symbols: Option<bool>,
}

#[derive(Deserialize)]
struct CredentialRef {
    id: String,
}

#[derive(Deserialize)]
struct Rp {
    id: Option<String>,
    name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct User {
    id: String,
    name: String,
    display_name: Option<String>,
}

#[derive(Deserialize)]
struct PubKeyParam {
    alg: i64,
}

/// `authenticatorSelection` of `passkey.create`; only `userVerification` matters here.
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticatorSelection {
    user_verification: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateParams {
    origin: String,
    rp: Rp,
    user: User,
    challenge: String,
    #[serde(default)]
    pub_key_cred_params: Vec<PubKeyParam>,
    #[serde(default)]
    exclude_credentials: Vec<CredentialRef>,
    #[serde(default)]
    cross_origin: bool,
    #[serde(default)]
    authenticator_selection: AuthenticatorSelection,
    /// Set when the user already said yes in the extension's card, so no consent window is shown.
    consent: Option<BrowserConsent>,
    #[serde(default)]
    extensions: Extensions,
}

/// The WebAuthn extensions of a `passkey.create` / `passkey.get` request, in WebAuthn JSON
/// (`AuthenticationExtensionsClientInputsJSON`, binary values base64url). Only `prf` is used.
#[derive(Default, Deserialize)]
struct Extensions {
    /// `AuthenticationExtensionsPRFInputsJSON`: answered in `clientExtensionResults.prf`.
    #[serde(default)]
    prf: Option<Value>,
}

/// A refused `prf` input: `not_supported` (a `NotSupportedError`) or `invalid_params` (a
/// `SyntaxError`). Both let the extension hand the request to the browser, which reports it.
fn prf_error(e: PrfRequestError) -> RpcError {
    match e {
        PrfRequestError::NotSupported => RpcError::new(
            ErrorCode::NotSupported,
            "prf: evalByCredential not supported here",
        ),
        PrfRequestError::Syntax => RpcError::new(ErrorCode::InvalidParams, "prf: invalid input"),
    }
}

/// The login the user chose in the extension's card to keep the passkey with, or none for a new
/// login.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserConsent {
    #[serde(default, alias = "item_id")]
    item_id: Option<String>,
    /// With no `item_id`: the vault the new login goes into (`passkey.create_options`' `vaults`).
    #[serde(default)]
    vault: Option<String>,
}

/// `passkey.create_options`: what the extension's "Save a passkey?" card offers. No secrets, no
/// prompt.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateOptionsParams {
    origin: String,
    rp_id: Option<String>,
    #[serde(default)]
    user_name: String,
    #[serde(default)]
    exclude_credentials: Vec<CredentialRef>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetParams {
    origin: String,
    /// Set when the user already picked a login in the extension.
    id: Option<String>,
    /// With `id`: the picked passkey's b64url credential ID, when the login has several.
    credential_id: Option<String>,
    rp_id: Option<String>,
    challenge: String,
    #[serde(default)]
    allow_credentials: Vec<CredentialRef>,
    #[serde(default)]
    cross_origin: bool,
    user_verification: Option<String>,
    #[serde(default)]
    extensions: Extensions,
}

/// `passkey.find`: the passkeys the vault has for a page's pending request. No secrets, no
/// prompt.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FindPasskeyParams {
    origin: String,
    rp_id: Option<String>,
    #[serde(default)]
    allow_credentials: Vec<CredentialRef>,
}

/// WebAuthn `userVerification: "required"`, case-sensitive. Missing or unknown values are weaker.
fn uv_required(value: &Option<String>) -> bool {
    value.as_deref() == Some("required")
}

/// The default RP ID is the origin's host, as in WebAuthn. `origin` must be a
/// serialised http(s) tuple origin: an opaque origin (`"null"`), another scheme or a path is
/// `url_mismatch`, whatever the RP ID.
fn effective_rp_id(rp_id: Option<String>, origin: &str) -> Result<String, RpcError> {
    let mismatch = || {
        RpcError::new(
            ErrorCode::UrlMismatch,
            format!("{origin} is not a web origin"),
        )
    };
    let url = url::Url::parse(origin).map_err(|_| mismatch())?;
    let tuple = url.origin();
    if !matches!(url.scheme(), "https" | "http")
        || !tuple.is_tuple()
        || tuple.ascii_serialization() != origin
    {
        return Err(mismatch());
    }
    let rp_id = match rp_id.filter(|r| !r.is_empty()) {
        Some(rp_id) => rp_id.to_ascii_lowercase(),
        None => url.host_str().ok_or_else(mismatch)?.to_string(),
    };
    if !rp_id_valid_for_origin(rp_id.clone(), origin.to_string()) {
        return Err(RpcError::new(
            ErrorCode::UrlMismatch,
            format!("{rp_id} is not valid for {origin}"),
        ));
    }
    Ok(rp_id)
}

/// The WebAuthn authenticator data flag UV (user verified).
const FLAG_UV: u8 = 0x04;

/// `pass_core::passkey_create` always reports UV. Clears it in the authenticator data and its copy
/// in the attestation object when only user presence happened. The `none` attestation signs
/// nothing, so editing the flags byte keeps the response valid.
fn clear_uv_flag(created: &mut PasskeyCreation) {
    // rpIdHash (32 bytes), then the flags byte.
    let Some(&flags) = created.authenticator_data.get(32) else {
        return;
    };
    let original = created.authenticator_data.clone();
    created.authenticator_data[32] = flags & !FLAG_UV;
    let att = &mut created.attestation_object;
    if let Some(at) = att
        .windows(original.len())
        .rposition(|w| w == original.as_slice())
    {
        att[at + 32] = flags & !FLAG_UV;
    }
}

impl Agent {
    /// Handles one JSON request line and returns the JSON response line.
    pub fn handle_line(&self, line: &str) -> String {
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
        match self.handle(&method, params) {
            Ok(result) => json!({ "id": id, "result": result }),
            Err(e) => {
                json!({ "id": id, "error": { "code": e.code.as_str(), "message": e.message } })
            }
        }
        .to_string()
    }

    pub fn handle(&self, method: &str, params: Value) -> RpcResult {
        let trace = (crate::timing::enabled() && is_timed(method))
            .then(|| crate::timing::Trace::begin(&format!("{method}: request received")));
        let _entered = crate::timing::enter(trace.clone());
        let result = self.handle_now(method, params);
        if let Some(trace) = trace {
            // Log the code only: messages can name a site or an item.
            trace.mark(&crate::timing::answered(
                method,
                result.as_ref().err().map(|e| e.code.as_str()),
            ));
        }
        result
    }

    fn handle_now(&self, method: &str, params: Value) -> RpcResult {
        if self.update_required() && !crate::read_only::allows(method, &params) {
            return Err(crate::read_only::update_required());
        }
        if matches!(method, "logins.find" | "logins.search") {
            self.ui.logins_requested();
        }
        // A sync client may have replaced the file since the last request.
        let _ = self.reload_if_changed();
        if is_background(method) {
            return self.dispatch(method, params);
        }
        // Only a successful request counts as activity. While it runs the auto-lock waits, so a
        // Windows Hello prompt isn't cut off by a lock.
        let _busy = self.busy();
        let result = self.dispatch(method, params);
        if result.is_ok() {
            self.note_activity();
        }
        result
    }

    fn dispatch(&self, method: &str, params: Value) -> RpcResult {
        match method {
            "status" => {
                let mut status = json!({
                    "locked": self.is_locked(),
                    "soft_locked": self.is_soft_locked(),
                    "version": VERSION,
                    "features": features(self.ui.hello_in_browser(), self.ui.host_features()),
                });
                // Only while read-only, so the usual answer stays as it was.
                if self.update_required() {
                    status["update_required"] = json!(true);
                }
                Ok(status)
            }
            "unlock" => self.rpc_unlock(unlock::for_params(params)),
            "lock" => self.rpc_lock(),
            "unlock.options" => self.rpc_unlock_options(),
            "unlock.password" => self.rpc_unlock_password(parse(params)?),
            "unlock.hello" => self.rpc_unlock_hello(unlock::for_params(params)),
            "unlock.cancel" => self.rpc_unlock_cancel(),
            "logins.find" => self.rpc_find(parse::<UrlParams>(params)?),
            "logins.fill" => self.rpc_fill(parse(params)?),
            "logins.save" => self.rpc_save(parse(params)?),
            "logins.save_check" => self.rpc_save_check(parse(params)?),
            "totp.get" => self.rpc_totp_get(parse(params)?),
            "totp.popup" => self.rpc_totp_popup(parse(params)?),
            "generate" => {
                let p: GenerateParams = parse(params)?;
                let password = generate_password(PasswordOptions {
                    length: p.length.unwrap_or(20).clamp(8, 128),
                    symbols: p.symbols.unwrap_or(true),
                    ..Default::default()
                })?;
                self.remember_generated(&password);
                Ok(json!({ "password": password }))
            }
            "generate.copy" => self.rpc_generate_copy(parse(params)?),
            "generate.username" => self.rpc_generate_username(parse(params)?),
            "generate.options" => self.rpc_generate_options(),
            "generate.email" => self.rpc_generate_email(parse(params)?),
            "password.check" => self.rpc_password_check(parse(params)?),
            "passkey.create" => self.rpc_passkey_create(parse(params)?),
            "passkey.get" => self.rpc_passkey_get(parse(params)?),
            "passkey.find" => self.rpc_passkey_find(parse(params)?),
            "passkey.create_options" => self.rpc_passkey_create_options(parse(params)?),
            "server.pair" => self.rpc_server_pair(parse(params)?),
            "logins.get_for_edit" => self.rpc_get_for_edit(parse(params)?),
            "logins.update" => self.rpc_update(parse(params)?),
            "sites.rule_hint" => self.rpc_rule_hint(parse(params)?),
            "sites.suggest" => self.rpc_sites_suggest(parse(params)?),
            "sites.name_for" => self.rpc_sites_name_for(parse(params)?),
            "logins.create" => self.rpc_create(parse(params)?),
            "logins.delete" => self.rpc_delete(parse(params)?),
            "logins.restore" => self.rpc_restore(parse(params)?),
            "totp.set" => self.rpc_totp_set(parse(params)?),
            "totp.from_image" => self.rpc_totp_from_image(parse(params)?),
            "notes.create" => self.rpc_note_create(parse(params)?),
            "notes.append" => self.rpc_note_append(parse(params)?),
            "items.import" => self.rpc_items_import(parse(params)?),
            "app.show_item" => self.rpc_show_item(parse(params)?),
            "icons.get" => self.rpc_icons_get(parse(params)?),
            "otp.outcome" => self.rpc_otp_outcome(parse(params)?),
            "logins.search" => self.rpc_search(parse(params)?),
            "logins.copy" => self.rpc_copy(parse(params)?),
            "logins.fill_cross" => self.rpc_fill_cross(parse(params)?),
            "logins.similar" => self.rpc_similar(parse(params)?),
            "logins.add_url" => self.rpc_add_url(parse(params)?),
            "cards.list" => self.rpc_cards_list(parse(params)?),
            "cards.fill" => self.rpc_cards_fill(parse(params)?),
            "cards.save_check" => self.rpc_cards_save_check(parse(params)?),
            "cards.save" => self.rpc_cards_save(parse(params)?),
            "identities.list" => self.rpc_identities_list(parse(params)?),
            "identities.fill" => self.rpc_identities_fill(parse(params)?),
            "notes.list" => self.rpc_notes_list(parse(params)?),
            "notes.get" => self.rpc_notes_get(parse(params)?),
            "vaults.list" => self.rpc_vaults_list(),
            "vaults.pins" => self.rpc_vaults_pins(),
            "vaults.set_pins" => self.rpc_vaults_set_pins(parse(params)?),
            "vaults.own" => self.rpc_vaults_own(),
            "vaults.switch" => self.rpc_vaults_switch(parse(params)?),
            "items.move" => self.rpc_items_move(parse(params)?),
            "app.show_teams" => self.rpc_show_teams(parse(params)?),
            "account.status" => self.rpc_account_status(),
            "app.show_account" => self.rpc_show_account(parse(params)?),
            "account.peer" => self.rpc_account_peer(),
            "account.handoff_to_extension" => self.rpc_handoff_to_extension(parse(params)?),
            "account.handoff_begin" => self.rpc_handoff_begin(),
            "account.handoff_finish" => self.rpc_handoff_finish(parse(params)?),
            "account.sign_out" => self.rpc_account_sign_out(),
            "account.peer_signed_out" => self.rpc_peer_signed_out(),
            "sync.now" => self.rpc_sync_now(),
            other => Err(RpcError::new(
                ErrorCode::InvalidParams,
                format!("unknown method {other}"),
            )),
        }
    }

    /// `lock`: the popup's Lock button, same as the tray's Lock (saves first).
    fn rpc_lock(&self) -> RpcResult {
        // The vault is locked even if saving failed. The OS error only goes to stderr.
        self.save_and_lock().map_err(|e| {
            eprintln!("pass-agent: locked, but the vault could not be saved: {e}");
            RpcError::new(
                ErrorCode::Internal,
                "Passyble is locked, but your latest changes could not be saved",
            )
        })?;
        Ok(json!({ "locked": true }))
    }

    /// The unlocked vault, without counting as activity.
    fn unlocked(&self) -> Result<std::sync::Arc<pass_core::Vault>, RpcError> {
        self.peek_vault()
            .ok_or_else(|| RpcError::new(ErrorCode::Locked, "Vault is locked"))
    }

    /// The items without secrets (from the vault or a soft lock's list), and whether the vault is
    /// locked. `locked` when fully locked.
    pub(crate) fn listed(
        &self,
    ) -> Result<(std::sync::Arc<Vec<pass_core::ItemSummary>>, bool), RpcError> {
        let listed = self.listed_all()?;
        Ok((std::sync::Arc::new(listed.all()), listed.locked))
    }

    /// Every vault's list with its [`crate::VaultRef`]; `locked` when fully locked.
    pub(crate) fn listed_all(&self) -> Result<crate::agent::Listed, RpcError> {
        self.listed_vaults()
            .ok_or_else(|| RpcError::new(ErrorCode::Locked, "Vault is locked"))
    }

    /// The open vaults, the home vault first; `locked` while locked. Not activity.
    pub(crate) fn opened_or_locked(&self) -> Result<crate::agent::Opened, RpcError> {
        self.opened()
            .ok_or_else(|| RpcError::new(ErrorCode::Locked, "Vault is locked"))
    }

    /// The item and the vault holding it, but only if it really belongs to the requesting site
    /// (whatever its website rules: a login the user hid there is still filled when picked).
    pub(crate) fn item_in(
        &self,
        url: &str,
        id: &str,
    ) -> Result<(crate::VaultRef, std::sync::Arc<pass_core::Vault>, Item), RpcError> {
        let opened = self.opened_or_locked()?;
        let Some((vault_ref, vault)) = opened.holding(id).cloned() else {
            return Err(RpcError::new(ErrorCode::NotFound, "no such item"));
        };
        vault
            .logins_of_page(url.to_string())
            .into_iter()
            .find(|i| i.id == id)
            .map(|item| (vault_ref, vault, item))
            .ok_or_else(|| {
                RpcError::new(ErrorCode::UrlMismatch, "item does not belong to this site")
            })
    }

    /// The item, but only if it really belongs to the requesting site.
    fn item_for_url(&self, url: &str, id: &str) -> Result<Item, RpcError> {
        self.item_in(url, id).map(|(_, _, item)| item)
    }

    /// [`crate::Ui::verify_user`] before a secret is handed out; `cancelled` if refused.
    /// `Ok(true)`: the user was really verified (the WebAuthn UV flag may be set).
    fn verified(&self, reason: Reason) -> Result<bool, RpcError> {
        verification_result(self.ui.verify_user(&reason))
    }

    /// [`Self::verified`] for a secret of login `item_id`.
    pub(crate) fn verified_item(
        &self,
        reason: Reason,
        item_id: &str,
        secret: ItemSecret,
    ) -> Result<bool, RpcError> {
        verification_result(self.ui.verify_item(&reason, item_id, secret))
    }

    /// [`Self::verified`] for a passkey request. With `userVerification: "required"` anything but
    /// a real verification is `not_supported`, so the extension falls back to the browser's own
    /// WebAuthn.
    fn verified_for_passkey(
        &self,
        reason: Reason,
        required: bool,
        item: Option<&str>,
    ) -> Result<bool, RpcError> {
        if !required {
            return match item {
                Some(item) => self.verified_item(reason, item, ItemSecret::Passkey),
                None => self.verified(reason),
            };
        }
        match self.ui.require_verification(&reason) {
            Verification::Verified => Ok(true),
            Verification::Required => Err(verification_required()),
            Verification::Allowed | Verification::Refused => Err(RpcError::new(
                ErrorCode::NotSupported,
                "user verification is required and Passyble could not verify the user",
            )),
        }
    }

    /// A code for the login just filled on this site continues that verified fill, so by default
    /// it doesn't ask again. Any other login's code does.
    fn verified_code(&self, url: &str, item: &Item) -> Result<(), RpcError> {
        let follows_fill = self
            .pending_otp(url)
            .is_some_and(|pending| pending.item_id == item.id);
        self.verified_item(
            Reason::UseCode {
                title: item.title.clone(),
            },
            &item.id,
            ItemSecret::Code { follows_fill },
        )
        .map(|_| ())
    }

    fn rpc_unlock(&self, p: unlock::ForParams) -> RpcResult {
        // A fill waiting on this unlock counts it as that fill's check.
        let _for = self.unlocking_for(p.item);
        if self.is_locked() && !self.ui.request_unlock() {
            return Err(RpcError::new(ErrorCode::Cancelled, "unlock cancelled"));
        }
        if self.is_locked() {
            return Err(RpcError::new(ErrorCode::Cancelled, "unlock cancelled"));
        }
        Ok(json!({ "locked": false }))
    }

    fn rpc_find(&self, p: UrlParams) -> RpcResult {
        // The extension asks on every page with a login form, so this doesn't count as activity
        // (browsing alone would keep the vault from auto-locking). Filling does. Soft-locked, the
        // list comes from the kept summaries with `locked: true`.
        let lists = self.search_lists()?;
        let listed = &lists.listed;
        let locked = listed.locked;
        // Every open vault's logins in one order, each with its vault.
        let found = pass_core::summaries_for_url_in(
            listed.groups.iter().flat_map(|(_, list)| list.iter()),
            &p.url,
        );
        let items: Vec<Value> = found
            .iter()
            .map(|i| {
                json!({
                    "id": i.id, "title": i.title, "username": i.username,
                    "has_totp": i.has_totp, "has_passkey": !i.passkeys.is_empty(),
                    "favorite": i.favorite,
                    "vault_id": listed.ref_of(&i.id).map(|r| r.id.clone()),
                })
            })
            .collect();
        let vaults = vaults_json(&listed.table(found.iter().map(|i| i.id.as_str())));
        let pending = if locked {
            None
        } else {
            self.pending_otp(&p.url).map(|pending| {
                json!({
                    "id": pending.item_id, "title": pending.title,
                    "skips_2fa": self.skips_2fa(&p.url),
                })
            })
        };
        Ok(json!({ "items": items, "pending_otp": pending, "locked": locked, "vaults": vaults }))
    }

    fn rpc_fill(&self, p: ItemParams) -> RpcResult {
        let id =
            p.id.ok_or_else(|| RpcError::new(ErrorCode::InvalidParams, "id is required"))?;
        // A fill-only member's login is filled like any other: that is what the role allows. The
        // extension never shows or keeps the password (`vault.can_reveal: false`).
        let (vault_ref, _, item) = self.item_in(&p.url, &id)?;
        self.verified_item(
            Reason::FillLogin {
                title: item.title.clone(),
            },
            &item.id,
            ItemSecret::Password,
        )?;
        crate::timing::mark("fill: verified");
        self.record_use(&item.id);
        let totp = self.totp_json(&item);
        if totp.is_some() {
            self.remember_otp(&p.url, &item.id);
        }
        let skips_2fa = totp.is_some() && self.skips_2fa(&p.url);
        Ok(json!({
            "username": item.username, "password": item.password, "totp": totp,
            "skips_2fa": skips_2fa, "vault": vault_json(&vault_ref),
        }))
    }

    fn rpc_totp_get(&self, p: ItemParams) -> RpcResult {
        self.unlocked()?;
        // A picked code is a use. The pending code (no id) belongs to the fill that just counted.
        let picked = p.id.is_some();
        let (vault_ref, _, item) = match p.id {
            Some(id) => self.item_in(&p.url, &id)?,
            None => {
                let pending = self.pending_otp(&p.url).ok_or_else(|| {
                    RpcError::new(ErrorCode::NotFound, "no pending code for this site")
                })?;
                self.item_in(&p.url, &pending.item_id)?
            }
        };
        let code = self
            .totp_json(&item)
            .ok_or_else(|| RpcError::new(ErrorCode::NotFound, "this login has no 2FA secret"))?;
        self.verified_code(&p.url, &item)?;
        if picked {
            self.record_use(&item.id);
        } else {
            // Not counted again for "most used first", but still a use.
            self.note_use();
        }
        let mut result =
            json!({ "id": item.id, "title": item.title, "vault": vault_json(&vault_ref) });
        result
            .as_object_mut()
            .unwrap()
            .extend(code.as_object().unwrap().clone());
        Ok(result)
    }

    fn rpc_totp_popup(&self, p: ItemParams) -> RpcResult {
        let id =
            p.id.ok_or_else(|| RpcError::new(ErrorCode::InvalidParams, "id is required"))?;
        let item = self.item_for_url(&p.url, &id)?;
        if !item.has_totp() {
            return Err(RpcError::new(
                ErrorCode::NotFound,
                "this login has no 2FA secret",
            ));
        }
        self.verified_code(&p.url, &item)?;
        self.ui.show_totp_popup(&item.id, &item.title);
        Ok(json!({}))
    }

    /// Hands a `pass+server://` link or a plain server address to the desktop app, which shows its
    /// pairing or sign-in dialog prefilled. Nothing is applied until the user confirms there, so
    /// this works while locked and returns as soon as the dialog is up.
    fn rpc_server_pair(&self, p: PairParams) -> RpcResult {
        let link = p.link.trim();
        if link.len() > MAX_LINK_LEN {
            return Err(RpcError::new(ErrorCode::InvalidParams, "link is too long"));
        }
        if !link.to_ascii_lowercase().starts_with("pass+server://") {
            let Some((address, host)) = normalize_server_address(link) else {
                return Err(RpcError::new(
                    ErrorCode::InvalidParams,
                    "not a pass+server:// link or a server address",
                ));
            };
            if !self.ui.show_server_pairing(&address) {
                return Err(RpcError::new(
                    ErrorCode::NotSupported,
                    "this Passyble app can't connect to Passyble Server",
                ));
            }
            return Ok(json!({
                "shown": true,
                "host": host,
                "user": null,
                "sign_in": true,
                "address": true,
            }));
        }
        let parsed = pass_core::parse_server_link(link)?;
        if !self.ui.show_server_pairing(link) {
            return Err(RpcError::new(
                ErrorCode::NotSupported,
                "this Passyble app can't connect to Passyble Server",
            ));
        }
        Ok(json!({
            "shown": true,
            "host": parsed.host,
            "user": parsed.username,
            "sign_in": parsed.pairing.is_none(),
        }))
    }

    fn rpc_save(&self, p: SaveParams) -> RpcResult {
        let opened = self.opened_or_locked()?;
        if p.password.is_empty() {
            return Err(RpcError::new(ErrorCode::InvalidParams, "empty password"));
        }
        if p.update.as_deref() == Some("username") && p.id.is_none() {
            return Err(RpcError::new(
                ErrorCode::InvalidParams,
                "id is required to update a username",
            ));
        }
        // Only a login of this page's host (or of its verified canonical host) is updated. A
        // login of another subdomain is left alone and a new one is saved for this host.
        let canonical = save::canonical_origin(&p.url, p.canonical_url.as_deref());
        let scope = save::save_scope(&opened, &p.url, canonical.as_deref());
        let own = opened.find_for_save(&p.url);
        let page_origin = url::Url::parse(&p.url)
            .map_err(|_| RpcError::new(ErrorCode::InvalidParams, "invalid url"))?
            .origin()
            .ascii_serialization();
        // A canonical-host login updated from this page also gets this page's address, so both
        // hosts share it. Returns whether that changed anything.
        let share = |item: &mut Item| {
            let add = !own.iter().any(|i| i.id == item.id) && !item.urls.contains(&page_origin);
            if add {
                item.urls.push(page_origin.clone());
            }
            add
        };
        let given = match &p.id {
            Some(id) => {
                let (vault_ref, _, item) = self.item_in(&p.url, id)?;
                if !vault_ref.can_edit {
                    return Err(read_only());
                }
                Some(item).filter(|item| scope.iter().any(|i| i.id == item.id))
            }
            None => None,
        };
        let vault_of = |item: &Item| -> Result<InVault, RpcError> {
            opened
                .holding(&item.id)
                .cloned()
                .ok_or_else(|| RpcError::new(ErrorCode::NotFound, "no such item"))
        };
        if let (Some(mut item), Some("username")) = (given.clone(), p.update.as_deref()) {
            let username = p.username.trim();
            if username.is_empty() || username.chars().any(char::is_control) {
                return Err(RpcError::new(ErrorCode::InvalidParams, "invalid username"));
            }
            let (vault_ref, vault) = vault_of(&item)?;
            let shared = share(&mut item);
            if item.username != username || shared {
                item.username = username.to_string();
                vault.upsert(item.clone())?;
                self.save()?;
                self.ui.vault_changed();
            }
            return Ok(json!({ "id": item.id, "vault": vault_json(&vault_ref) }));
        }
        let existing = match given {
            Some(item) => Some(item),
            None => {
                // Checked again here, so a banner shown while locked or a late second Save never
                // adds a duplicate.
                if let Some(item) =
                    save::already_saved(&opened, &p.url, &p.username, &p.password, None)
                {
                    let vault = opened.ref_of(&item.id).map(vault_json);
                    return Ok(json!({ "id": item.id, "unchanged": true, "vault": vault }));
                }
                scope
                    .iter()
                    .find(|i| save::same_login_name(&i.username, &p.username))
                    .cloned()
            }
        };
        // Kept so `logins.restore` can undo this update.
        let mut before = None;
        let (item, target) = match existing {
            // Nothing new: don't write (the submitted login is the saved one).
            Some(item)
                if save::same_password(&item, &p.password)
                    && (!item.username.is_empty() || p.username.is_empty()) =>
            {
                let vault = opened.ref_of(&item.id).map(vault_json);
                return Ok(json!({ "id": item.id, "unchanged": true, "vault": vault }));
            }
            Some(mut item) => {
                let target = vault_of(&item)?;
                before = Some(item.clone());
                item.password = p.password;
                if item.username.is_empty() {
                    item.username = p.username;
                }
                share(&mut item);
                (item, target)
            }
            None => {
                let page = url::Url::parse(&p.url)
                    .map_err(|_| RpcError::new(ErrorCode::InvalidParams, "invalid url"))?;
                let target = self.save_target(&opened, p.vault.as_deref(), &p.url)?;
                let host = page.host_str().unwrap_or_default().to_string();
                let title = pass_core::registrable_domain(host.clone()).unwrap_or(host);
                let urls = canonical
                    .iter()
                    .cloned()
                    .chain(std::iter::once(page_origin.clone()))
                    .collect();
                let item = Item {
                    kind: ItemKind::Login,
                    title,
                    username: p.username,
                    password: p.password,
                    urls,
                    ..Default::default()
                };
                (item, target)
            }
        };
        let (vault_ref, vault) = target;
        let saved = vault.upsert(item)?;
        self.save()?;
        self.ui.vault_changed();
        if let (Some(before), Ok(page)) = (before, edit::page(&p.url)) {
            self.remember_deleted(&vault.vault_id(), &edit::site(&page), before);
        }
        Ok(json!({ "id": saved.id, "vault": vault_json(&vault_ref) }))
    }

    /// The vault a new item goes into: `wanted` (a vault id the extension offered), or the
    /// default for `url`. `read_only` for a vault this user can't edit, `not_found` for one that
    /// isn't open.
    pub(crate) fn save_target(
        &self,
        opened: &crate::agent::Opened,
        wanted: Option<&str>,
        url: &str,
    ) -> Result<(crate::VaultRef, std::sync::Arc<pass_core::Vault>), RpcError> {
        let id = match wanted.filter(|w| !w.is_empty()) {
            Some(id) => id.to_string(),
            None => opened.default_save(Some(url)).ok_or_else(read_only)?,
        };
        let (vault_ref, vault) = opened
            .by_id(&id)
            .cloned()
            .ok_or_else(|| RpcError::new(ErrorCode::NotFound, "that vault isn't open"))?;
        if !vault_ref.can_edit {
            return Err(read_only());
        }
        Ok((vault_ref, vault))
    }

    /// `vaults.list`: the home vault and every shared vault, for the popup's vault filter and its
    /// "Shared with me" line. A background method: no prompt, no activity.
    fn rpc_vaults_list(&self) -> RpcResult {
        let teams = self.ui.teams_summary();
        let password_policy = self.ui.password_policy();
        let Some(listed) = self.listed_vaults() else {
            return Ok(json!({ "vaults": [], "teams": teams, "password_policy": password_policy }));
        };
        let mut vaults = Vec::new();
        if let Some((home, list)) = listed.groups.first() {
            let mut v = vault_json(home);
            v["items"] = json!(list.len());
            v["open"] = json!(!listed.locked);
            v["error"] = Value::Null;
            v["last_sync"] = Value::Null;
            vaults.push(v);
        }
        for status in self.linked_status() {
            let mut v = match &status.vault {
                Some(r) => vault_json(r),
                None => json!({
                    "id": null, "name": status.name, "home": false, "kind": null, "role": null,
                    "can_edit": false, "can_reveal": false,
                }),
            };
            if listed.locked {
                if let Some(r) = &status.vault {
                    if let Some((kept, list)) = listed.groups.iter().find(|(k, _)| k.id == r.id) {
                        v = vault_json(kept);
                        v["items"] = json!(list.len());
                    }
                }
            } else {
                v["items"] = json!(status.items);
            }
            if v.get("items").is_none() {
                v["items"] = json!(0);
            }
            v["open"] = json!(status.open && !listed.locked);
            v["error"] = match (&status.error, listed.locked) {
                (Some(e), false) => json!({ "code": e.code, "message": e.message }),
                _ => Value::Null,
            };
            v["last_sync"] = json!(status.last_sync_ms);
            vaults.push(v);
        }
        Ok(json!({ "vaults": vaults, "teams": teams, "password_policy": password_policy }))
    }

    /// `sync.now`: syncs every open vault that has sync set up, through the app when it can.
    /// Needs the vault unlocked and is refused in read-only mode.
    fn rpc_sync_now(&self) -> RpcResult {
        self.unlocked()?;
        let report = self.ui.sync_now().unwrap_or_else(|| self.sync_report());
        serde_json::to_value(report)
            .map_err(|e| RpcError::new(ErrorCode::Internal, format!("sync report: {e}")))
    }

    /// `app.show_teams`: the desktop app's Teams and Family screen.
    fn rpc_show_teams(&self, p: ShowTeamsParams) -> RpcResult {
        let section = p.section.unwrap_or_default();
        let section = match section.as_str() {
            "shared" | "invites" | "confirm" | "members" | "notices" => section.as_str(),
            _ => "",
        };
        if !self.ui.show_teams(section) {
            return Err(RpcError::new(
                ErrorCode::NotSupported,
                "this Passyble app has no Teams and Family screen",
            ));
        }
        Ok(json!({ "shown": true }))
    }

    /// `account.status`: the desktop app's Passyble account for the extension in app mode, signed
    /// in or not and the e-mail address; nothing else (no token, no account id). Works while
    /// locked. A background method: no prompt, no activity.
    fn rpc_account_status(&self) -> RpcResult {
        let Some(account) = self.ui.account_summary() else {
            return Err(RpcError::new(
                ErrorCode::NotSupported,
                "this Passyble app has no Passyble account",
            ));
        };
        let email = account.email.filter(|e| account.signed_in && !e.is_empty());
        Ok(json!({ "signed_in": account.signed_in, "email": email }))
    }

    /// `app.show_account`: the desktop app's Passyble account screen; with `sign_in`, the app's
    /// own account sign-in starts too (the extension's "Sign in" in app mode). Works while locked.
    fn rpc_show_account(&self, p: ShowAccountParams) -> RpcResult {
        if !self.ui.show_account(p.sign_in) {
            return Err(RpcError::new(
                ErrorCode::NotSupported,
                "this Passyble app has no Passyble account",
            ));
        }
        Ok(json!({ "shown": true }))
    }

    fn rpc_passkey_create(&self, p: CreateParams) -> RpcResult {
        let opened = self.opened_or_locked()?;
        let rp_id = effective_rp_id(p.rp.id, &p.origin)?;
        let algorithms: Vec<i64> = p.pub_key_cred_params.iter().map(|a| a.alg).collect();
        if !algorithms.is_empty() && !algorithms.contains(&-7) {
            return Err(RpcError::new(
                ErrorCode::NotSupported,
                "only ES256 passkeys are supported",
            ));
        }
        let excluded = p
            .exclude_credentials
            .iter()
            .map(|c| b64("excludeCredentials.id", &c.id))
            .collect::<Result<Vec<_>, _>>()?;
        if !excluded.is_empty()
            && opened
                .0
                .iter()
                .any(|(_, v)| !v.find_passkeys(rp_id.clone(), excluded.clone()).is_empty())
        {
            return Err(RpcError::new(
                ErrorCode::InvalidState,
                "a passkey for this account is already in Passyble",
            ));
        }
        let user_handle = b64("user.id", &p.user.id)?;
        if let Some(prf) = &p.extensions.prf {
            prf_registration_check(prf).map_err(prf_error)?;
        }
        crate::timing::mark("passkey: request checked");
        let site = format!("https://{rp_id}");
        let (item_id, wanted_vault) = match p.consent {
            // Said yes in the extension's card in the page: the login it chose must be one the
            // card could offer (`passkey.create_options`), never an unrelated item.
            Some(consent) => {
                let item_id = consent.item_id.filter(|id| !id.is_empty());
                if let Some(id) = &item_id {
                    let offered = opened.find_for_url(&site).iter().any(|i| &i.id == id);
                    if !offered {
                        return Err(RpcError::new(
                            ErrorCode::UrlMismatch,
                            "item does not belong to this site",
                        ));
                    }
                }
                crate::timing::mark("passkey: consent given in the browser");
                (item_id, consent.vault)
            }
            None => {
                let consent = self.ui.confirm_passkey_create(&rp_id, &p.user.name);
                crate::timing::mark("passkey: consent window answered");
                match consent {
                    Consent::Approve { item_id } => (item_id, None),
                    Consent::Deny => return Err(RpcError::new(ErrorCode::Cancelled, "declined")),
                }
            }
        };
        // The passkey goes with its login, in that login's vault (one this user may edit), or
        // into the chosen (or default) vault as a new login.
        let (vault_ref, vault) = match &item_id {
            Some(id) => {
                let (vault_ref, vault) = opened
                    .holding(id)
                    .cloned()
                    .ok_or_else(|| RpcError::new(ErrorCode::NotFound, "no such item"))?;
                if !vault_ref.can_edit {
                    return Err(read_only());
                }
                (vault_ref, vault)
            }
            None => self.save_target(&opened, wanted_vault.as_deref(), &site)?,
        };
        let user_verified = self.verified_for_passkey(
            Reason::SavePasskey {
                site: rp_id.clone(),
            },
            uv_required(&p.authenticator_selection.user_verification),
            None,
        )?;
        crate::timing::mark("passkey: verified");
        let challenge = b64("challenge", &p.challenge)?;
        let client_data = client_data_json(
            "webauthn.create".into(),
            challenge,
            p.origin.clone(),
            p.cross_origin,
            None,
        );
        let mut created = passkey_create(
            rp_id,
            p.rp.name,
            user_handle,
            p.user.name.clone(),
            p.user.display_name.unwrap_or(p.user.name),
            sha256(client_data.clone().into_bytes()),
            algorithms,
        )?;
        if !user_verified {
            clear_uv_flag(&mut created);
        }
        crate::timing::mark("passkey: created");
        let mut extension_results = json!({});
        if let Some(prf) = &p.extensions.prf {
            extension_results["prf"] =
                prf_registration_output(prf, &created.passkey).map_err(prf_error)?;
        }
        vault.add_passkey(item_id, created.passkey, Some(p.origin))?;
        self.save()?;
        crate::timing::mark("passkey: saved");
        self.ui.vault_changed();
        Ok(json!({
            "vault": vault_json(&vault_ref),
            "credentialId": b64url_encode(created.credential_id),
            "clientDataJSON": b64url_encode(client_data.into_bytes()),
            "attestationObject": b64url_encode(created.attestation_object),
            "authenticatorData": b64url_encode(created.authenticator_data),
            "publicKey": b64url_encode(created.public_key_spki),
            "publicKeyAlgorithm": created.public_key_algorithm,
            "transports": ["internal", "hybrid"],
            "clientExtensionResults": extension_results,
        }))
    }

    fn rpc_passkey_get(&self, p: GetParams) -> RpcResult {
        let opened = self.opened_or_locked()?;
        let rp_id = effective_rp_id(p.rp_id, &p.origin)?;
        let allowed = p
            .allow_credentials
            .iter()
            .map(|c| b64("allowCredentials.id", &c.id))
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(prf) = &p.extensions.prf {
            prf_authentication_check(prf, &allowed).map_err(prf_error)?;
        }
        // Every open vault's passkeys for the RP (fill-only members sign in with theirs too, PRF
        // included: the extension gets the PRF's output, never the secret inside the passkey).
        let mut matches: Vec<pass_core::PasskeyMatch> = opened
            .0
            .iter()
            .flat_map(|(_, v)| v.find_passkeys(rp_id.clone(), allowed.clone()))
            .collect();
        if let Some(id) = &p.id {
            matches.retain(|m| &m.item_id == id);
            if let Some(credential) = &p.credential_id {
                let credential = b64("credentialId", credential)?;
                matches.retain(|m| m.passkey.credential_id == credential);
            }
        }
        if matches.is_empty() {
            return Err(RpcError::new(
                ErrorCode::NotFound,
                "no passkey for this site in Passyble",
            ));
        }
        crate::timing::mark("passkey: matched");
        // Already picked in the extension's own UI: don't ask again in a window.
        let index = if p.id.is_some() && matches.len() == 1 {
            crate::timing::mark("passkey: picked in the browser");
            0
        } else {
            let choices: Vec<PasskeyChoice> = matches
                .iter()
                .map(|m| PasskeyChoice {
                    item_id: m.item_id.clone(),
                    title: m.item_title.clone(),
                    user_name: m.passkey.user_name.clone(),
                })
                .collect();
            let pick = self.ui.choose_passkey_for_browser(&rp_id, &choices);
            crate::timing::mark("passkey: chooser window answered");
            match pick {
                PasskeyPick::Chosen(i) if i < matches.len() => i,
                PasskeyPick::Elsewhere => {
                    return Err(RpcError::new(
                        ErrorCode::NotFound,
                        "the user chose another device or the browser's own passkeys",
                    ))
                }
                PasskeyPick::Chosen(_) | PasskeyPick::Cancelled => {
                    return Err(RpcError::new(ErrorCode::Cancelled, "cancelled"))
                }
            }
        };
        let chosen = matches[index].passkey.clone();
        let user_verified = self.verified_for_passkey(
            Reason::PasskeySignIn {
                site: rp_id.clone(),
            },
            uv_required(&p.user_verification),
            Some(&matches[index].item_id),
        )?;
        crate::timing::mark("passkey: verified");
        let challenge = b64("challenge", &p.challenge)?;
        let client_data = client_data_json(
            "webauthn.get".into(),
            challenge,
            p.origin,
            p.cross_origin,
            None,
        );
        let mut extension_results = json!({});
        if let Some(prf) = &p.extensions.prf {
            extension_results["prf"] =
                prf_authentication_output(prf, &allowed, &chosen).map_err(prf_error)?;
        }
        let assertion = passkey_assert(
            chosen,
            sha256(client_data.clone().into_bytes()),
            user_verified,
        )?;
        crate::timing::mark("passkey: signed");
        self.record_use(&matches[index].item_id);
        let vault = opened.ref_of(&matches[index].item_id).map(vault_json);
        Ok(json!({
            "vault": vault,
            "credentialId": b64url_encode(assertion.credential_id),
            "clientDataJSON": b64url_encode(client_data.into_bytes()),
            "authenticatorData": b64url_encode(assertion.authenticator_data),
            "signature": b64url_encode(assertion.signature),
            "userHandle": b64url_encode(assertion.user_handle),
            "clientExtensionResults": extension_results,
        }))
    }

    /// `passkey.find`: the passkeys for a page's pending request, with the same RP ID rules as
    /// `passkey.get`. Names and titles only, never a key or user handle.
    fn rpc_passkey_find(&self, p: FindPasskeyParams) -> RpcResult {
        let rp_id = effective_rp_id(p.rp_id, &p.origin)?;
        let allowed = p
            .allow_credentials
            .iter()
            .map(|c| b64("allowCredentials.id", &c.id))
            .collect::<Result<Vec<_>, _>>()?;
        let listed = self.listed_all()?;
        let locked = listed.locked;
        let found = pass_core::summaries_with_passkeys(listed.all(), rp_id.clone());
        let items: Vec<Value> = found
            .iter()
            .filter(|s| s.trashed_at.is_none())
            .flat_map(|s| {
                let vault_id = listed.ref_of(&s.id).map(|r| r.id.clone());
                s.passkeys
                    .iter()
                    .filter(|pk| pk.rp_id.eq_ignore_ascii_case(&rp_id))
                    .filter(|pk| allowed.is_empty() || allowed.contains(&pk.credential_id))
                    .map(move |pk| {
                        json!({
                            "id": s.id,
                            "title": s.title,
                            "user_name": pk.user_name,
                            "user_display_name": pk.user_display_name,
                            "credential_id": b64url_encode(pk.credential_id.clone()),
                            "vault_id": vault_id,
                        })
                    })
            })
            .collect();
        let vaults = vaults_json(&listed.table(found.iter().map(|s| s.id.as_str())));
        Ok(json!({ "rp_id": rp_id, "items": items, "locked": locked, "vaults": vaults }))
    }

    /// `passkey.create_options`: what the extension's "Save a passkey?" card offers: the site's
    /// logins, the one matching the user name, and whether an excluded credential is already in
    /// the vault. Titles and user names only.
    fn rpc_passkey_create_options(&self, p: CreateOptionsParams) -> RpcResult {
        let rp_id = effective_rp_id(p.rp_id, &p.origin)?;
        let excluded = p
            .exclude_credentials
            .iter()
            .map(|c| b64("excludeCredentials.id", &c.id))
            .collect::<Result<Vec<_>, _>>()?;
        let listed = self.listed_all()?;
        let locked = listed.locked;
        let list = listed.all();
        let exists = !excluded.is_empty()
            && list.iter().filter(|s| s.trashed_at.is_none()).any(|s| {
                s.passkeys.iter().any(|pk| {
                    pk.rp_id.eq_ignore_ascii_case(&rp_id) && excluded.contains(&pk.credential_id)
                })
            });
        // Only logins of vaults this user may edit can take the passkey.
        let editable: Vec<pass_core::ItemSummary> = listed
            .groups
            .iter()
            .filter(|(r, _)| r.can_edit)
            .flat_map(|(_, l)| l.iter().cloned())
            .collect();
        let site = format!("https://{rp_id}");
        let logins = pass_core::summaries_for_url(editable, site.clone());
        let user = p.user_name.trim();
        let suggested = logins
            .iter()
            .find(|i| !user.is_empty() && i.username.eq_ignore_ascii_case(user))
            .map(|i| i.id.clone());
        let candidates: Vec<Value> = logins
            .iter()
            .map(|i| {
                json!({
                    "id": i.id, "title": i.title, "username": i.username,
                    "vault_id": listed.ref_of(&i.id).map(|r| r.id.clone()),
                })
            })
            .collect();
        let vaults: Vec<crate::VaultRef> = listed
            .groups
            .iter()
            .filter(|(r, _)| r.can_edit)
            .map(|(r, _)| r.clone())
            .collect();
        // Soft-locked there is no vault to ask, so it is the home vault.
        let default_vault = self
            .default_save_vault(Some(&site))
            .or_else(|| listed.groups.first().map(|(r, _)| r.id.clone()));
        Ok(json!({
            "rp_id": rp_id,
            "locked": locked,
            "excluded": exists,
            "candidates": candidates,
            "suggested": suggested,
            "vault": self.ui.vault_name(),
            "vaults": vaults_json(&vaults),
            "default_vault": default_vault,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_server_address;

    #[test]
    fn server_addresses_follow_core() {
        let ok = |typed: &str| normalize_server_address(typed);
        assert_eq!(
            ok(" pass.example.com:8443/ "),
            Some((
                "https://pass.example.com:8443".into(),
                "pass.example.com:8443".into()
            ))
        );
        assert_eq!(
            ok("https://example.org/pass/"),
            Some(("https://example.org/pass".into(), "example.org".into()))
        );
        for bad in [
            "",
            "ftp://example.com",
            "not an address",
            "https://user:pw@example.com",
            "https://example.com/?x=1",
            "https://example.com/#x",
        ] {
            assert_eq!(ok(bad), None, "{bad}");
        }
        // Plain http:// only for this device or a private network, as in core.
        #[cfg(feature = "webdav")]
        {
            for local in [
                "http://localhost:8080",
                "http://127.0.0.1:8080",
                "http://10.0.0.5:8080",
                "http://192.168.1.20",
                "http://100.101.102.103",
                "http://nas.local:8080/pass",
                "http://[::1]:8080",
            ] {
                let (address, _) = ok(local).unwrap_or_else(|| panic!("{local} refused"));
                assert_eq!(
                    Some(address.clone()),
                    pass_core::normalize_server_url(local.into()).ok()
                );
            }
            assert_eq!(
                ok("http://10.0.0.5:8080").unwrap().1,
                "10.0.0.5:8080".to_string()
            );
        }
        for public in [
            "http://pass.example.com",
            "http://pass.example.com:8443/",
            "http://203.0.113.7:8080",
            "http://[2001:db8::1]:8080",
        ] {
            assert_eq!(ok(public), None, "{public}");
        }
    }
}
