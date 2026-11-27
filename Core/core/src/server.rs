//! Passyble Server accounts: password sign-in and password changes. Blocking; call off the UI thread.
//! The password never leaves the device: requests carry `auth_key` (Argon2id + HKDF, see
//! [`crate::server_auth_key`]), and the vault uses its own salt so the server can't unwrap it.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::Deserialize;
use serde_json::json;

use crate::encoding::b64_encode;
use crate::i18n::{tr, trn};
use crate::net;
use crate::pinning::{normalize_pins, PinVerifier};
use crate::server_auth::{auth_key, ServerKdf};
use crate::{b64url_decode, b64url_encode, PassError, Result, WebDavConfig};

/// `POST /api/v1/prelogin`: the account's password parameters. Unknown accounts get plausible
/// fake ones, so this says nothing about whether the account exists.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ServerPrelogin {
    pub kdf: ServerKdf,
    /// base64url.
    pub salt: String,
}

/// A device signed in with a password. `token` is a secret: store it like a WebDAV password.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ServerSession {
    /// Base URL as given (normalized), e.g. `https://pass.example.com:8443`.
    pub server_url: String,
    /// The account (HTTP Basic user name for sync).
    pub username: String,
    /// The device token (`pst_…`, HTTP Basic password for sync).
    pub token: String,
    pub device_id: String,
    pub device_name: String,
    /// The vault file's WebDAV URL (`None`: the account has no vault).
    pub vault_url: Option<String>,
    /// The server already has the vault file (download it; otherwise create one).
    pub vault_exists: bool,
    /// Admin-set password: call [`server_change_password`] first. Until then the token can't read
    /// or write the vault.
    pub must_change_password: bool,
    /// The current password was set by the admin and never changed by the user.
    pub password_admin_known: bool,
    /// The certificate pins used for the sign-in (keep them with the sync settings).
    pub pins: Vec<String>,
}

impl std::fmt::Debug for ServerSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerSession")
            .field("server_url", &self.server_url)
            .field("username", &self.username)
            .field("device_id", &self.device_id)
            .field("vault_url", &self.vault_url)
            .field("vault_exists", &self.vault_exists)
            .field("must_change_password", &self.must_change_password)
            .finish_non_exhaustive()
    }
}

impl ServerSession {
    /// The sync settings for the session's vault.
    pub fn webdav_config(&self) -> Result<WebDavConfig> {
        Ok(WebDavConfig {
            url: self
                .vault_url
                .clone()
                .ok_or_else(|| PassError::NotFound(tr!("server.no_vault")))?,
            username: self.username.clone(),
            password: self.token.clone(),
            pins: self.pins.clone(),
        })
    }
}

/// [`ServerSession::webdav_config`] for Kotlin.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn server_session_webdav_config(session: ServerSession) -> Result<WebDavConfig> {
    session.webdav_config()
}

/// `GET /api/v1/whoami` for a device token.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ServerAccount {
    pub username: String,
    pub device_id: String,
    pub device_name: String,
    pub vault_url: Option<String>,
    pub vault_exists: bool,
    /// `false`: a pairing-only account (no password yet).
    pub has_password: bool,
    pub must_change_password: bool,
    pub password_admin_known: bool,
    /// This device may only change the password (signed in with an admin-set password).
    pub limited: bool,
}

/// One of the account's devices (`GET /api/v1/devices`).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ServerDevice {
    /// `d_…`: pass it to [`server_revoke_device`].
    pub id: String,
    pub name: String,
    /// When it signed in or was paired (unix ms).
    pub created_at: i64,
    /// When it last talked to the server (unix ms, accurate to a few minutes), if known.
    pub last_used_at: Option<i64>,
    /// The device making the request ("This device").
    pub current: bool,
    /// Signed in with an admin-set password that was not changed yet.
    pub limited: bool,
}

/// Normalizes a server address typed by the user (`pass.example.com:8443` becomes
/// `https://pass.example.com:8443`). Rejects other schemes, credentials, queries, fragments, and
/// `http://` outside this device or a private network ([`plain_http_allowed`]).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn normalize_server_url(input: String) -> Result<String> {
    let input = input.trim();
    if input.is_empty() {
        return Err(PassError::InvalidInput(tr!("server.enter_address")));
    }
    let with_scheme = if input.contains("://") {
        input.to_string()
    } else {
        format!("https://{input}")
    };
    let url = url::Url::parse(&with_scheme)
        .map_err(|_| PassError::InvalidInput(tr!("server.invalid_address")))?;
    if !matches!(url.scheme(), "https" | "http") {
        return Err(PassError::InvalidInput(tr!("server.address_scheme")));
    }
    if url.host_str().is_none_or(str::is_empty)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(PassError::InvalidInput(tr!("server.invalid_address")));
    }
    refuse_public_plain_http(&url)?;
    Ok(url.as_str().trim_end_matches('/').to_string())
}

/// Whether `url` is a plain `http://` address outside this device and private networks
/// ([`plain_http_allowed`]), which is refused for Passyble Server and WebDAV alike. `false` for
/// `https://`, local `http://` and anything that isn't a URL.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn plain_http_refused(url: String) -> bool {
    check_plain_http(&url).is_err()
}

/// [`plain_http_refused`] as an `InvalidInput` error (`server.plain_http_refused`).
pub fn check_plain_http(url: &str) -> Result<()> {
    match url::Url::parse(url.trim()) {
        Ok(url) => refuse_public_plain_http(&url),
        Err(_) => Ok(()),
    }
}

pub(crate) fn refuse_public_plain_http(url: &url::Url) -> Result<()> {
    if url.scheme() == "http" && !plain_http_allowed(url) {
        return Err(PassError::InvalidInput(tr!(
            "server.plain_http_refused",
            host = url.host_str().unwrap_or_default()
        )));
    }
    Ok(())
}

/// Whether plain `http://` is acceptable for this host: loopback, private networks (RFC 1918,
/// fc00::/7), link-local, 100.64.0.0/10 (Tailscale and other VPNs), and `*.local`, `*.lan`,
/// `*.internal`, `*.home.arpa`.
fn plain_http_allowed(url: &url::Url) -> bool {
    fn v4_ok(ip: std::net::Ipv4Addr) -> bool {
        let [a, b, ..] = ip.octets();
        ip.is_loopback()
            || ip.is_private()
            || ip.is_link_local()
            || (a == 100 && (64..128).contains(&b))
    }
    match url.host() {
        Some(url::Host::Domain(d)) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            d == "localhost"
                || [".localhost", ".local", ".lan", ".internal", ".home.arpa"]
                    .iter()
                    .any(|suffix| d.ends_with(suffix))
        }
        Some(url::Host::Ipv4(ip)) => v4_ok(ip),
        Some(url::Host::Ipv6(ip)) => {
            let first = ip.segments()[0];
            ip.is_loopback()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
                || ip.to_ipv4_mapped().is_some_and(v4_ok)
        }
        None => false,
    }
}

fn invalid_password() -> PassError {
    PassError::InvalidPassword
}

/// Start of the `InvalidInput` message when two-factor sign-in needs a code the request lacked.
pub const TWO_FACTOR_REQUIRED: &str = "2fa_required";

/// Passyble Server's stable code of an error answer. Its message is translated, so the core
/// recognises answers by this code, never by their text.
const ERROR_CODE_HEADER: &str = "X-Pass-Error";

fn error_code_of(response: &ureq::Response) -> Option<String> {
    response
        .header(ERROR_CODE_HEADER)
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
}

/// Passyble Server's shared vault and Passyble Cloud error codes. Each becomes `Network` with the
/// catalog text `server.<code>`, so apps tell them apart with [`crate::core_message_is`] instead
/// of reading them as an authentication failure or "not found".
pub const SHARED_VAULT_ERRORS: &[&str] = &[
    "read_only_member",
    "subscription_inactive",
    "account_suspended",
    "cloud_managed",
    "no_vault_access",
    "not_vault_manager",
    "member_via_group",
    "vault_limit",
];

pub(crate) fn shared_vault_error(code: &str) -> Option<PassError> {
    let text = match code {
        "read_only_member" => tr!("server.read_only_member"),
        "subscription_inactive" => tr!("server.subscription_inactive"),
        "account_suspended" => tr!("server.account_suspended"),
        "cloud_managed" => tr!("server.cloud_managed"),
        "no_vault_access" => tr!("server.no_vault_access"),
        "not_vault_manager" => tr!("server.not_vault_manager"),
        "member_via_group" => tr!("server.member_via_group"),
        "vault_limit" => tr!("server.vault_limit"),
        _ => return None,
    };
    Some(PassError::Network(text))
}

pub(crate) fn shared_vault_error_of(response: &ureq::Response) -> Option<PassError> {
    shared_vault_error(&error_code_of(response)?)
}

/// A Passyble Server error message for the user: only when the answer has an
/// [`ERROR_CODE_HEADER`] and is a short line of plain text, never a proxy's error page.
fn server_text(response: ureq::Response) -> Option<String> {
    error_code_of(&response)?;
    net::plain_message(&response.into_string().ok()?)
}

/// Start of the `InvalidInput` message for a wrong, expired or already used two-factor code
/// (counted like a wrong password by the server's limits).
pub const TWO_FACTOR_INVALID: &str = "2fa_invalid";

/// `{ "error": <code>, "message": <text> }`, the server's JSON error shape.
fn json_error_of(body: &str) -> Option<(String, String)> {
    #[derive(Deserialize)]
    struct E {
        error: String,
        #[serde(default)]
        message: String,
    }
    let e: E = serde_json::from_str(body).ok()?;
    Some((e.error, e.message))
}

static SERVER_LANGUAGE: RwLock<Option<String>> = RwLock::new(None);

/// Sets the language sent to Passyble Server as `Accept-Language` (`de`, `zh-CN`, ...; `None` stops
/// sending one). Process-wide.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn set_server_language(language: Option<String>) {
    let language = language.map(|l| l.trim().replace('_', "-")).filter(|l| {
        !l.is_empty() && l.len() <= 35 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    });
    *SERVER_LANGUAGE.write().unwrap_or_else(|e| e.into_inner()) = language;
}

fn server_language() -> Option<String> {
    SERVER_LANGUAGE
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// Sets (or with `None` clears) the language of the signed-in account's e-mails and pages
/// (`POST /api/v1/language`). Returns the language the server stored.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn server_set_language(
    server_url: String,
    username: String,
    token: String,
    language: Option<String>,
    pins: Vec<String>,
) -> Result<Option<String>> {
    #[derive(Deserialize)]
    struct Answer {
        #[serde(default)]
        language: Option<String>,
    }
    let api = Api::new(&server_url, &pins)?;
    let user = account_name(&username)?;
    let language = language
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty());
    let a: Answer = api.post(
        &tr!("action.set_language"),
        "/api/v1/language",
        Some((&user, &token)),
        json!({ "language": language }),
    )?;
    Ok(a.language)
}

#[allow(clippy::result_large_err)] // ureq's middleware signature
fn with_language(
    request: ureq::Request,
    next: ureq::MiddlewareNext<'_>,
) -> std::result::Result<ureq::Response, ureq::Error> {
    match server_language() {
        Some(language) => next.handle(request.set("Accept-Language", &language)),
        None => next.handle(request),
    }
}

struct Api {
    agent: ureq::Agent,
    pins: Option<Arc<PinVerifier>>,
    base: String,
}

impl Api {
    fn new(server_url: &str, pins: &[String]) -> Result<Self> {
        let base = normalize_server_url(server_url.to_string())?;
        let mut builder = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .middleware(with_language);
        let pins = normalize_pins(pins)?;
        let verifier = if pins.is_empty() {
            None
        } else {
            let verifier = PinVerifier::new(pins);
            builder = builder.tls_config(verifier.client_config()?);
            Some(verifier)
        };
        Ok(Self {
            agent: builder.build(),
            pins: verifier,
            base,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// The vault URL for a `vault_path` from the server. It must be an absolute path whose URL has
    /// the base URL's origin (`@other.host/…` would give `https://this.host@other.host/…`), so the
    /// credentials and the vault never go to another host.
    fn vault_url(&self, path: Option<String>) -> Result<Option<String>> {
        match path {
            None => Ok(None),
            Some(p)
                if p.starts_with('/')
                    && !p.starts_with("//")
                    && !p.contains(['\\', '?', '#', '@']) =>
            {
                let url = self.url(&p);
                let origin = |u: &str| {
                    url::Url::parse(u).ok().map(|u| {
                        (
                            u.scheme().to_string(),
                            u.host_str().map(str::to_string),
                            u.port_or_known_default(),
                            u.username().to_string(),
                            u.password().map(str::to_string),
                        )
                    })
                };
                match (origin(&self.base), origin(&url)) {
                    (Some(a), Some(b)) if a == b => Ok(Some(url)),
                    _ => Err(PassError::Network(tr!("server.invalid_vault_path"))),
                }
            }
            Some(_) => Err(PassError::Network(tr!("server.invalid_vault_path"))),
        }
    }

    fn error(&self, action: &str, err: ureq::Error) -> PassError {
        match err {
            ureq::Error::Status(code, response) => {
                let token_rejected = response.header("WWW-Authenticate").is_some();
                let server_code = error_code_of(&response);
                let retry = response
                    .header("Retry-After")
                    .and_then(|v| v.trim().parse::<u64>().ok());
                let body = response
                    .into_string()
                    .unwrap_or_default()
                    .trim()
                    .chars()
                    .take(300)
                    .collect::<String>();
                let json = json_error_of(&body);
                if let Some(e) = server_code.as_deref().and_then(shared_vault_error) {
                    return e;
                }
                match server_code.as_deref() {
                    // A device signed in with an admin-set password may only change it.
                    Some("password_change_required") => {
                        return PassError::Network(tr!("server.password_change_required"))
                    }
                    Some("email_unavailable") => {
                        return PassError::Network(tr!("server.cant_send_email"))
                    }
                    Some("unknown_language") => {
                        let detail = json
                            .and_then(|(_, m)| net::plain_message(&m))
                            .or_else(|| net::plain_message(&body))
                            .unwrap_or_default();
                        return PassError::Network(tr!(
                            "server.unknown_language",
                            action = action,
                            detail = detail
                        ));
                    }
                    _ => {}
                }
                // Only Passyble Server's JSON errors carry a user message; a proxy's page is never shown.
                let json = json.map(|(e, m)| (e, net::plain_message(&m).unwrap_or_default()));
                match (code, json) {
                    (401, Some((e, m))) if e == TWO_FACTOR_REQUIRED || e == TWO_FACTOR_INVALID => {
                        PassError::InvalidInput(format!("{e}: {m}"))
                    }
                    (409, Some((_, m))) if !m.is_empty() => PassError::Conflict(m),
                    (_, Some((_, m))) if !m.is_empty() && code != 404 && code != 405 => {
                        PassError::Network(format!("{action}: {m}"))
                    }
                    _ => match code {
                        401 if token_rejected => {
                            PassError::Network(tr!("server.auth_failed", action = action))
                        }
                        401 => invalid_password(),
                        429 => PassError::Network(trn!(
                            "server.too_many_attempts",
                            retry.map_or(15, |s| s.div_ceil(60).max(1)),
                            action = action
                        )),
                        404 | 405 => {
                            PassError::Network(tr!("server.unsupported.sign_in", action = action))
                        }
                        _ => match server_code.and_then(|_| net::plain_message(&body)) {
                            Some(message) => PassError::Network(format!("{action}: {message}")),
                            None => net::status_error(action, code),
                        },
                    },
                }
            }
            ureq::Error::Transport(t) => match self.pins.as_ref().and_then(|v| v.rejected()) {
                Some(seen) => {
                    PassError::CertificateChanged(tr!("server.certificate_not_in_link", key = seen))
                }
                None => net::transport_error(action, &t, &self.base, || {
                    tr!("server.unexpected_answer", action = action)
                }),
            },
        }
    }

    fn post<T: serde::de::DeserializeOwned>(
        &self,
        action: &str,
        path: &str,
        basic: Option<(&str, &str)>,
        body: serde_json::Value,
    ) -> Result<T> {
        let mut request = self
            .agent
            .post(&self.url(path))
            .set("Content-Type", "application/json");
        if let Some((user, token)) = basic {
            request = request.set("Authorization", &basic_auth(user, token));
        }
        let response = request
            .send_string(&body.to_string())
            .map_err(|e| self.error(action, e))?;
        read_json(action, response)
    }

    fn get<T: serde::de::DeserializeOwned>(
        &self,
        action: &str,
        path: &str,
        user: &str,
        token: &str,
    ) -> Result<T> {
        let response = self
            .agent
            .get(&self.url(path))
            .set("Authorization", &basic_auth(user, token))
            .call()
            .map_err(|e| self.error(action, e))?;
        read_json(action, response)
    }

    fn prelogin(&self, user: &str) -> Result<ServerPrelogin> {
        let p: ServerPrelogin = self.post(
            &tr!("action.sign_in"),
            "/api/v1/prelogin",
            None,
            json!({ "user": user }),
        )?;
        p.kdf.check_offered()?;
        Ok(p)
    }

    fn auth_for(&self, user: &str, password: &str) -> Result<String> {
        let p = self.prelogin(user)?;
        let salt = salt_bytes(&p.salt)?;
        Ok(b64url_encode(auth_key(password, &salt, &p.kdf)?.to_vec()))
    }
}

fn basic_auth(user: &str, token: &str) -> String {
    format!("Basic {}", b64_encode(format!("{user}:{token}").as_bytes()))
}

fn read_json<T: serde::de::DeserializeOwned>(action: &str, response: ureq::Response) -> Result<T> {
    let unexpected = || tr!("server.unexpected_answer", action = action);
    let text = response
        .into_string()
        .map_err(|e| net::read_error(action, &e, unexpected))?;
    serde_json::from_str(&text).map_err(|_| PassError::Network(unexpected()))
}

fn salt_bytes(salt: &str) -> Result<Vec<u8>> {
    let bytes = b64url_decode(salt.to_string())
        .map_err(|_| PassError::Crypto(tr!("server.invalid_salt")))?;
    if !(16..=64).contains(&bytes.len()) {
        return Err(PassError::Crypto(tr!("server.invalid_salt")));
    }
    Ok(bytes)
}

fn account_name(user: &str) -> Result<String> {
    let user = user.trim().to_lowercase();
    if user.is_empty() {
        return Err(PassError::InvalidInput(tr!("server.enter_user")));
    }
    Ok(user)
}

fn new_password_body(new_password: &str) -> Result<serde_json::Value> {
    if new_password.chars().count() < 8 {
        return Err(PassError::InvalidInput(trn!(
            "server.new_password_too_short",
            8
        )));
    }
    let kdf = ServerKdf::default();
    let salt = crate::crypto::random_bytes::<16>();
    let auth = auth_key(new_password, &salt, &kdf)?;
    Ok(json!({
        "new_salt": b64url_encode(salt.to_vec()),
        "new_kdf": { "alg": kdf.alg, "m_kib": kdf.m_kib, "t": kdf.t, "p": kdf.p },
        "new_auth": b64url_encode(auth.to_vec()),
    }))
}

/// The account's password parameters (`POST /api/v1/prelogin`). Rejects parameters weaker than
/// what Passyble sets for a password (Argon2id, 64 MiB, t = 3) with `Crypto`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn server_prelogin(
    server_url: String,
    username: String,
    pins: Vec<String>,
) -> Result<ServerPrelogin> {
    Api::new(&server_url, &pins)?.prelogin(&account_name(&username)?)
}

/// Signs in with the account password and registers this device (`POST /api/v1/login`).
/// Wrong user or password: `InvalidPassword`. A two-factor account fails with `2fa_required`: use
/// [`server_login_2fa`].
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn server_login(
    server_url: String,
    username: String,
    password: String,
    device_name: String,
    pins: Vec<String>,
) -> Result<ServerSession> {
    server_login_2fa(server_url, username, password, device_name, None, pins)
}

fn otp_value(otp: Option<String>) -> Option<String> {
    otp.map(|o| o.trim().to_string()).filter(|o| !o.is_empty())
}

/// [`server_login`] with a two-factor `otp` (authenticator code or recovery code). Call it with
/// `None` first, then again with the code on `2fa_required`; `2fa_invalid` is a wrong or used code.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn server_login_2fa(
    server_url: String,
    username: String,
    password: String,
    device_name: String,
    otp: Option<String>,
    pins: Vec<String>,
) -> Result<ServerSession> {
    #[derive(Deserialize)]
    struct Login {
        user: String,
        token: String,
        device_id: String,
        device_name: String,
        vault_path: Option<String>,
        #[serde(default)]
        vault_exists: bool,
        #[serde(default)]
        must_change_password: bool,
        #[serde(default)]
        password_admin_known: bool,
    }
    let api = Api::new(&server_url, &pins)?;
    let user = account_name(&username)?;
    let auth = api.auth_for(&user, &password)?;
    let mut body = json!({ "user": user, "auth": auth, "device_name": device_name.trim() });
    if let Some(otp) = otp_value(otp) {
        body["otp"] = json!(otp);
    }
    let r: Login = api.post(&tr!("action.sign_in"), "/api/v1/login", None, body)?;
    Ok(ServerSession {
        vault_url: api.vault_url(r.vault_path)?,
        server_url: api.base,
        username: r.user,
        token: r.token,
        device_id: r.device_id,
        device_name: r.device_name,
        vault_exists: r.vault_exists,
        must_change_password: r.must_change_password,
        password_admin_known: r.password_admin_known,
        pins,
    })
}

/// Changes the account password (`POST /api/v1/password`), authenticated by the device token and
/// the current password (empty `old_password` for an account with no password yet). The account's
/// other devices are signed out.
///
/// This only changes the server sign-in: re-wrap the vault too (`Vault::change_password`, then
/// sync). Do the server first, so a failed vault upload leaves a password the next sign-in can fix.
/// A two-factor account needs [`server_change_password_2fa`].
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn server_change_password(
    server_url: String,
    username: String,
    token: String,
    old_password: String,
    new_password: String,
    pins: Vec<String>,
) -> Result<()> {
    server_change_password_2fa(
        server_url,
        username,
        token,
        old_password,
        new_password,
        None,
        pins,
    )
}

/// [`server_change_password`] with a two-factor `otp` (authenticator or recovery code).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn server_change_password_2fa(
    server_url: String,
    username: String,
    token: String,
    old_password: String,
    new_password: String,
    otp: Option<String>,
    pins: Vec<String>,
) -> Result<()> {
    let api = Api::new(&server_url, &pins)?;
    let user = account_name(&username)?;
    let mut body = new_password_body(&new_password)?;
    if !old_password.is_empty() {
        body["old_auth"] = json!(api.auth_for(&user, &old_password)?);
    }
    if let Some(otp) = otp_value(otp) {
        body["otp"] = json!(otp);
    }
    let _: serde_json::Value = api.post(
        &tr!("action.change_password"),
        "/api/v1/password",
        Some((&user, &token)),
        body,
    )?;
    Ok(())
}

/// Sets the account password with a one-time invite or reset `code` instead of the old password.
/// A wrong, expired or used code is `InvalidPassword`. A reset code also signs out every device,
/// and the server can't re-encrypt the vault: re-wrap it after signing in again.
///
/// A two-factor account needs a code too: [`server_set_password_with_code_2fa`].
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn server_set_password_with_code(
    server_url: String,
    username: String,
    code: String,
    new_password: String,
    pins: Vec<String>,
) -> Result<()> {
    server_set_password_with_code_2fa(server_url, username, code, new_password, None, pins)
}

/// [`server_set_password_with_code`] with a two-factor `otp`. The one-time `code` is only used up
/// when the whole request succeeds.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn server_set_password_with_code_2fa(
    server_url: String,
    username: String,
    code: String,
    new_password: String,
    otp: Option<String>,
    pins: Vec<String>,
) -> Result<()> {
    let api = Api::new(&server_url, &pins)?;
    let user = account_name(&username)?;
    let mut body = new_password_body(&new_password)?;
    body["user"] = json!(user);
    body["code"] = json!(code.trim());
    if let Some(otp) = otp_value(otp) {
        body["otp"] = json!(otp);
    }
    let _: serde_json::Value =
        api.post(&tr!("action.set_password"), "/api/v1/password", None, body)?;
    Ok(())
}

/// "Forgot password?": asks the server to e-mail a reset link (`POST /api/v1/reset/request`). The
/// answer is the same whether or not the account exists, so `Ok` only means a link may be on its way.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn server_request_reset(
    server_url: String,
    user_or_email: String,
    pins: Vec<String>,
) -> Result<()> {
    let api = Api::new(&server_url, &pins)?;
    let target = user_or_email.trim();
    if target.is_empty() {
        return Err(PassError::InvalidInput(tr!("server.enter_user_or_email")));
    }
    let body = if target.contains('@') {
        json!({ "email": target })
    } else {
        json!({ "user": target.to_lowercase() })
    };
    let response = api
        .agent
        .post(&api.url("/api/v1/reset/request"))
        .set("Content-Type", "application/json")
        .send_string(&body.to_string());
    match response {
        Ok(_) => Ok(()),
        // Servers without the error code send only their English text.
        Err(ureq::Error::Status(503, r))
            if error_code_of(&r).as_deref() == Some("email_unavailable") =>
        {
            Err(PassError::Network(tr!("server.cant_send_email")))
        }
        Err(ureq::Error::Status(503, r)) => Err(PassError::Network(
            server_text(r).unwrap_or_else(|| tr!("server.cant_send_email")),
        )),
        Err(ureq::Error::Status(404 | 405, _)) => {
            Err(PassError::Network(tr!("server.unsupported.reset")))
        }
        Err(ureq::Error::Status(429, r)) => {
            let retry = r
                .header("Retry-After")
                .and_then(|v| v.trim().parse::<u64>().ok());
            Err(PassError::Network(trn!(
                "server.too_many_resets",
                retry.map_or(60, |s| s.div_ceil(60).max(1))
            )))
        }
        Err(e) => Err(api.error(&tr!("action.password_reset"), e)),
    }
}

/// Whether `password` is the account's current password (`POST /api/v1/verify`), for a device whose
/// vault is still unlocked after the password was changed elsewhere.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn server_verify_password(
    server_url: String,
    username: String,
    token: String,
    password: String,
    pins: Vec<String>,
) -> Result<bool> {
    #[derive(Deserialize)]
    struct Verify {
        ok: bool,
    }
    let api = Api::new(&server_url, &pins)?;
    let user = account_name(&username)?;
    let auth = api.auth_for(&user, &password)?;
    let r: Verify = api.post(
        &tr!("action.check_password"),
        "/api/v1/verify",
        Some((&user, &token)),
        json!({ "auth": auth }),
    )?;
    Ok(r.ok)
}

/// The device's account (`GET /api/v1/whoami`).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn server_account(
    server_url: String,
    username: String,
    token: String,
    pins: Vec<String>,
) -> Result<ServerAccount> {
    #[derive(Deserialize)]
    struct Whoami {
        user: String,
        device_id: String,
        device_name: String,
        #[serde(default)]
        vault_path: Option<String>,
        #[serde(default)]
        vault_exists: bool,
        #[serde(default)]
        has_password: bool,
        #[serde(default)]
        must_change_password: bool,
        #[serde(default)]
        password_admin_known: bool,
        #[serde(default)]
        limited: bool,
    }
    let api = Api::new(&server_url, &pins)?;
    let user = account_name(&username)?;
    let r: Whoami = api.get(&tr!("action.account"), "/api/v1/whoami", &user, &token)?;
    Ok(ServerAccount {
        vault_url: api.vault_url(r.vault_path)?,
        username: r.user,
        device_id: r.device_id,
        device_name: r.device_name,
        vault_exists: r.vault_exists,
        has_password: r.has_password,
        must_change_password: r.must_change_password,
        password_admin_known: r.password_admin_known,
        limited: r.limited,
    })
}

/// The account's signed-in devices (`GET /api/v1/devices`), oldest first; the calling one has
/// `current: true`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn server_list_devices(
    server_url: String,
    username: String,
    token: String,
    pins: Vec<String>,
) -> Result<Vec<ServerDevice>> {
    #[derive(Deserialize)]
    struct Device {
        id: String,
        name: String,
        #[serde(default)]
        created_at: i64,
        #[serde(default)]
        last_used_at: Option<i64>,
        #[serde(default)]
        current: bool,
        #[serde(default)]
        limited: bool,
    }
    #[derive(Deserialize)]
    struct Devices {
        devices: Vec<Device>,
    }
    let api = Api::new(&server_url, &pins)?;
    let user = account_name(&username)?;
    let response = api
        .agent
        .get(&api.url("/api/v1/devices"))
        .set("Authorization", &basic_auth(&user, &token))
        .call();
    let response = match response {
        Ok(r) => r,
        Err(ureq::Error::Status(404 | 405, _)) => return Err(no_device_api()),
        Err(e) => return Err(api.error(&tr!("action.devices"), e)),
    };
    let r: Devices = read_json(&tr!("action.devices"), response)?;
    Ok(r.devices
        .into_iter()
        .map(|d| ServerDevice {
            id: d.id,
            name: d.name,
            created_at: d.created_at,
            last_used_at: d.last_used_at,
            current: d.current,
            limited: d.limited,
        })
        .collect())
}

/// Signs out one of the account's devices (`DELETE /api/v1/devices/<id>`). Unknown id, or already
/// signed out: `NotFound`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn server_revoke_device(
    server_url: String,
    username: String,
    token: String,
    device_id: String,
    pins: Vec<String>,
) -> Result<()> {
    let api = Api::new(&server_url, &pins)?;
    let user = account_name(&username)?;
    let id = device_id.trim();
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err(PassError::InvalidInput(tr!("server.invalid_device_id")));
    }
    let response = api
        .agent
        .delete(&api.url(&format!("/api/v1/devices/{id}")))
        .set("Authorization", &basic_auth(&user, &token))
        .call();
    match response {
        Ok(_) => Ok(()),
        // An unknown device, or a server without this endpoint. Servers without error codes only
        // send the English text.
        Err(ureq::Error::Status(404, r)) => {
            let no_such_device = error_code_of(&r).as_deref() == Some("no_such_device");
            if no_such_device || r.into_string().is_ok_and(|b| b.contains("no such device")) {
                Err(PassError::NotFound(tr!("server.no_such_device")))
            } else {
                Err(no_device_api())
            }
        }
        Err(ureq::Error::Status(405, _)) => Err(no_device_api()),
        Err(e) => Err(api.error(&tr!("action.sign_out_device"), e)),
    }
}

fn no_device_api() -> PassError {
    PassError::Network(tr!("server.no_devices_api"))
}

/// A user or vault name as the server accepts it.
fn server_name_ok(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_alphanumeric()
        && b
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-' || *c == b'_')
}

/// The owner and vault name of a vault's WebDAV URL on this server (`…/dav/<owner>/<name>.vault`),
/// which must have the server's origin.
fn vault_ref_of(api: &Api, vault_url: &str) -> Result<(String, String)> {
    let bad = || PassError::InvalidInput(tr!("server.invalid_vault_path"));
    let url = url::Url::parse(vault_url).map_err(|_| bad())?;
    let base = url::Url::parse(&api.base).map_err(|_| bad())?;
    if url.origin() != base.origin() || url.query().is_some() || !url.username().is_empty() {
        return Err(bad());
    }
    let segments: Vec<&str> = url.path_segments().map(|s| s.collect()).unwrap_or_default();
    let [.., dav, owner, file] = segments.as_slice() else {
        return Err(bad());
    };
    let name = file.strip_suffix(".vault").ok_or_else(bad)?;
    if *dav != "dav" || !server_name_ok(owner) || !server_name_ok(name) {
        return Err(bad());
    }
    Ok((owner.to_string(), name.to_string()))
}

/// Deletes every previous version the server keeps of the vault at `vault_url`, keeping the live
/// file (`DELETE /api/v1/vaults/<owner>/<vault>/versions`, owner only). Call it after a master
/// password change rotated the vault key and the new file is uploaded: the old versions are
/// encrypted under the old key, so cracking the old password from one would expose it.
/// `Some(n)`: `n` versions dropped; `None`: the server lacks the call.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn server_purge_versions(
    server_url: String,
    username: String,
    token: String,
    vault_url: String,
    pins: Vec<String>,
) -> Result<Option<u64>> {
    let api = Api::new(&server_url, &pins)?;
    let user = account_name(&username)?;
    let (owner, name) = vault_ref_of(&api, &vault_url)?;
    let action = tr!("action.drop_old_versions");
    let unexpected = || PassError::Network(tr!("server.unexpected_answer", action = action.as_str()));
    let response = api
        .agent
        .delete(&api.url(&format!("/api/v1/vaults/{owner}/{name}/versions")))
        .set("Authorization", &basic_auth(&user, &token))
        .set("Content-Type", "application/json")
        .call();
    match response {
        Ok(r) => {
            let body: serde_json::Value = read_json(&action, r)?;
            body.get("removed")
                .and_then(serde_json::Value::as_u64)
                .map(Some)
                .ok_or_else(unexpected)
        }
        // The versions route exists but not this method: the server predates the call.
        Err(ureq::Error::Status(405, r)) if error_code_of(&r).is_none() => Ok(None),
        Err(ureq::Error::Status(403, r))
            if error_code_of(&r).as_deref() == Some("not_vault_owner") =>
        {
            Err(PassError::InvalidInput(tr!("server.not_vault_owner")))
        }
        Err(e) => Err(api.error(&action, e)),
    }
}

/// What a Passyble Server says about itself (`GET /api/v1/info`, no account needed).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ServerInfo {
    /// The server's display name (`server.name`, default its host).
    pub name: String,
    pub version: String,
    /// The address the admin configured for devices, if any (may differ from the one typed).
    pub public_url: Option<String>,
    /// The server can send e-mail (invites, resets).
    pub email: bool,
    /// "Forgot password?" works ([`server_request_reset`]).
    pub password_reset: bool,
    /// Self sign-up ([`server_signup`]): `"closed"`, `"invite"` (by e-mail address) or `"open"`.
    pub signup: String,
    /// Sign-in accepts the account's e-mail address instead of the user name.
    pub username_or_email: bool,
}

/// `GET /api/v1/info`. With `pins` empty the certificate must be publicly trusted; for a
/// self-signed one get its key with [`crate::fetch_server_pin`] first. Not a Passyble Server: `NotFound`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn server_info(server_url: String, pins: Vec<String>) -> Result<ServerInfo> {
    #[derive(Deserialize)]
    struct Features {
        #[serde(default)]
        email: bool,
        #[serde(default)]
        password_reset: bool,
        #[serde(default)]
        signup: Option<String>,
        #[serde(default)]
        username_or_email: bool,
    }
    #[derive(Deserialize)]
    struct Info {
        #[serde(default)]
        service: String,
        #[serde(default)]
        name: String,
        #[serde(default)]
        version: String,
        #[serde(default)]
        public_url: Option<String>,
        features: Option<Features>,
    }
    let api = Api::new(&server_url, &pins)?;
    let not_pass = || PassError::NotFound(tr!("server.not_passyble"));
    let action = tr!("action.server_info");
    let response = match api.agent.get(&api.url("/api/v1/info")).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(404 | 405, _)) => return Err(not_pass()),
        Err(e) => return Err(api.error(&action, e)),
    };
    let info: Info = read_json(&action, response).map_err(|_| not_pass())?;
    if info.service != "pass-server" {
        return Err(not_pass());
    }
    let features = info.features.unwrap_or(Features {
        email: false,
        password_reset: false,
        signup: None,
        username_or_email: false,
    });
    Ok(ServerInfo {
        name: if info.name.trim().is_empty() {
            "Passyble Server".into()
        } else {
            info.name
        },
        version: info.version,
        public_url: info.public_url,
        email: features.email,
        password_reset: features.password_reset,
        signup: features.signup.unwrap_or_else(|| "closed".into()),
        username_or_email: features.username_or_email,
    })
}

/// The answer to [`server_signup`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ServerSignup {
    /// `open` sign-up: the new account's user name; sign in with it (or the e-mail address) and
    /// the password ([`server_login`]). `None` for `invite`.
    pub username: Option<String>,
    /// `invite` sign-up: an invite e-mail is on its way, if the address can get an account (the
    /// answer is the same either way).
    pub check_email: bool,
}

/// Self sign-up (`POST /api/v1/signup`), when [`ServerInfo::signup`] allows it:
/// * `"invite"`: give `email` (and optionally a wished-for `username`; `password` is ignored).
/// * `"open"`: give `username` and `password` (at least 8 characters); then [`server_login`].
///
/// Name taken: `Conflict`; invalid name or address: `InvalidInput`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn server_signup(
    server_url: String,
    username: String,
    email: String,
    password: String,
    pins: Vec<String>,
) -> Result<ServerSignup> {
    #[derive(Deserialize)]
    struct Answer {
        #[serde(default)]
        user: Option<String>,
        #[serde(default)]
        check_email: bool,
    }
    let api = Api::new(&server_url, &pins)?;
    let mut body = if password.is_empty() {
        json!({})
    } else {
        new_password_body(&password)?
    };
    let username = username.trim().to_lowercase();
    if !username.is_empty() {
        body["user"] = json!(username);
    }
    if !email.trim().is_empty() {
        body["email"] = json!(email.trim());
    }
    if username.is_empty() && email.trim().is_empty() {
        return Err(PassError::InvalidInput(tr!(
            "server.signup_enter_user_or_email"
        )));
    }
    let response = api
        .agent
        .post(&api.url("/api/v1/signup"))
        .set("Content-Type", "application/json")
        .send_string(&body.to_string());
    let message =
        |r: ureq::Response, fallback: &str| server_text(r).unwrap_or_else(|| fallback.to_string());
    match response {
        Ok(r) => {
            let a: Answer = read_json(&tr!("action.sign_up"), r)?;
            Ok(ServerSignup {
                username: a.user,
                check_email: a.check_email,
            })
        }
        Err(ureq::Error::Status(403, r)) => {
            Err(PassError::Network(message(r, &tr!("server.signup_closed"))))
        }
        Err(ureq::Error::Status(409, r)) => Err(PassError::Conflict(message(
            r,
            &tr!("server.signup_name_taken"),
        ))),
        Err(ureq::Error::Status(400, r)) => Err(PassError::InvalidInput(message(
            r,
            &tr!("server.signup_invalid"),
        ))),
        Err(ureq::Error::Status(404 | 405, _)) => {
            Err(PassError::Network(tr!("server.unsupported.sign_up")))
        }
        Err(ureq::Error::Status(429, r)) => {
            let retry = r
                .header("Retry-After")
                .and_then(|v| v.trim().parse::<u64>().ok());
            Err(PassError::Network(trn!(
                "server.too_many_sign_ups",
                retry.map_or(60, |s| s.div_ceil(60).max(1))
            )))
        }
        Err(e) => Err(api.error(&tr!("action.sign_up"), e)),
    }
}

/// The account's two-factor sign-in (`GET /api/v1/2fa`).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ServerTwoFactorStatus {
    /// On: password sign-ins and password changes need a code.
    pub enabled: bool,
    /// Set up ([`server_two_factor_setup`]) but not confirmed yet.
    pub pending: bool,
    /// When it was turned on (unix ms).
    pub enabled_at: Option<i64>,
    /// Unused recovery codes (0 when off).
    pub recovery_codes_left: u32,
    /// The server lets users turn it on (`[auth] two_factor`).
    pub available: bool,
}

/// A new authenticator secret (`POST /api/v1/2fa/setup`). `secret` is a secret: don't log or store it.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ServerTwoFactorSetup {
    /// Base32 (RFC 4648, no padding).
    pub secret: String,
    /// `otpauth://totp/<issuer>:<account>?secret=…&issuer=…&algorithm=SHA1&digits=6&period=30`.
    pub otpauth_uri: String,
    /// The name authenticator apps show (the server's name).
    pub issuer: String,
    /// The account name in the authenticator.
    pub account: String,
    pub digits: u32,
    pub period: u32,
}

impl std::fmt::Debug for ServerTwoFactorSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerTwoFactorSetup")
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

fn no_two_factor_api() -> PassError {
    PassError::Network(tr!("server.unsupported.two_factor"))
}

/// POST with the device token; 404/405 → `missing()`.
fn post_or(
    api: &Api,
    action: &str,
    path: &str,
    user: &str,
    token: &str,
    body: serde_json::Value,
    missing: fn() -> PassError,
) -> Result<serde_json::Value> {
    let response = api
        .agent
        .post(&api.url(path))
        .set("Content-Type", "application/json")
        .set("Authorization", &basic_auth(user, token))
        .send_string(&body.to_string());
    match response {
        Ok(r) => read_json(action, r),
        Err(ureq::Error::Status(404 | 405, _)) => Err(missing()),
        Err(e) => Err(api.error(action, e)),
    }
}

/// GET with the device token; 404/405 → `missing()`.
fn get_or<T: serde::de::DeserializeOwned>(
    api: &Api,
    action: &str,
    path: &str,
    user: &str,
    token: &str,
    missing: fn() -> PassError,
) -> Result<T> {
    let response = api
        .agent
        .get(&api.url(path))
        .set("Authorization", &basic_auth(user, token))
        .call();
    match response {
        Ok(r) => read_json(action, r),
        Err(ureq::Error::Status(404 | 405, _)) => Err(missing()),
        Err(e) => Err(api.error(action, e)),
    }
}

/// Whether the account has two-factor sign-in on (`GET /api/v1/2fa`).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn server_two_factor_status(
    server_url: String,
    username: String,
    token: String,
    pins: Vec<String>,
) -> Result<ServerTwoFactorStatus> {
    #[derive(Deserialize)]
    struct Status {
        #[serde(default)]
        enabled: bool,
        #[serde(default)]
        pending: bool,
        #[serde(default)]
        enabled_at: Option<i64>,
        #[serde(default)]
        recovery_codes_left: u32,
        #[serde(default)]
        available: bool,
    }
    let api = Api::new(&server_url, &pins)?;
    let user = account_name(&username)?;
    let s: Status = get_or(
        &api,
        &tr!("action.two_factor"),
        "/api/v1/2fa",
        &user,
        &token,
        no_two_factor_api,
    )?;
    Ok(ServerTwoFactorStatus {
        enabled: s.enabled,
        pending: s.pending,
        enabled_at: s.enabled_at,
        recovery_codes_left: s.recovery_codes_left,
        available: s.available,
    })
}

/// Starts turning on two-factor sign-in (`POST /api/v1/2fa/setup`) with the account password.
/// Nothing changes for sign-ins until [`server_two_factor_confirm`].
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn server_two_factor_setup(
    server_url: String,
    username: String,
    token: String,
    password: String,
    pins: Vec<String>,
) -> Result<ServerTwoFactorSetup> {
    #[derive(Deserialize)]
    struct Setup {
        secret: String,
        otpauth_uri: String,
        #[serde(default)]
        issuer: String,
        #[serde(default)]
        account: String,
        #[serde(default = "six")]
        digits: u32,
        #[serde(default = "thirty")]
        period: u32,
    }
    fn six() -> u32 {
        6
    }
    fn thirty() -> u32 {
        30
    }
    let api = Api::new(&server_url, &pins)?;
    let user = account_name(&username)?;
    let auth = api.auth_for(&user, &password)?;
    let v = post_or(
        &api,
        &tr!("action.two_factor_setup"),
        "/api/v1/2fa/setup",
        &user,
        &token,
        json!({ "auth": auth }),
        no_two_factor_api,
    )?;
    let s: Setup = serde_json::from_value(v).map_err(|_| {
        PassError::Network(tr!(
            "server.unexpected_answer",
            action = tr!("action.two_factor_setup")
        ))
    })?;
    if !s.otpauth_uri.starts_with("otpauth://totp/") {
        return Err(PassError::Network(tr!(
            "server.invalid_otpauth",
            action = tr!("action.two_factor_setup")
        )));
    }
    Ok(ServerTwoFactorSetup {
        secret: s.secret,
        otpauth_uri: s.otpauth_uri,
        issuer: s.issuer,
        account: s.account,
        digits: s.digits,
        period: s.period,
    })
}

/// Turns two-factor sign-in on with the first `code` (`POST /api/v1/2fa/confirm`). Returns the 10
/// recovery codes: show them once, never store them.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn server_two_factor_confirm(
    server_url: String,
    username: String,
    token: String,
    code: String,
    pins: Vec<String>,
) -> Result<Vec<String>> {
    #[derive(Deserialize)]
    struct Confirmed {
        recovery_codes: Vec<String>,
    }
    let api = Api::new(&server_url, &pins)?;
    let user = account_name(&username)?;
    let code = code.trim();
    if code.is_empty() {
        return Err(PassError::InvalidInput(tr!("server.enter_two_factor_code")));
    }
    let v = post_or(
        &api,
        &tr!("action.two_factor_setup"),
        "/api/v1/2fa/confirm",
        &user,
        &token,
        json!({ "code": code }),
        no_two_factor_api,
    )?;
    let c: Confirmed = serde_json::from_value(v).map_err(|_| {
        PassError::Network(tr!(
            "server.unexpected_answer",
            action = tr!("action.two_factor_setup")
        ))
    })?;
    Ok(c.recovery_codes)
}

/// Turns two-factor sign-in off (`POST /api/v1/2fa/disable`) with the account password and a
/// current `code` (may be empty to drop an unconfirmed setup).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn server_two_factor_disable(
    server_url: String,
    username: String,
    token: String,
    password: String,
    code: String,
    pins: Vec<String>,
) -> Result<()> {
    let api = Api::new(&server_url, &pins)?;
    let user = account_name(&username)?;
    let auth = api.auth_for(&user, &password)?;
    let mut body = json!({ "auth": auth });
    if let Some(code) = otp_value(Some(code)) {
        body["code"] = json!(code);
    }
    post_or(
        &api,
        &tr!("action.two_factor_disable"),
        "/api/v1/2fa/disable",
        &user,
        &token,
        body,
        no_two_factor_api,
    )?;
    Ok(())
}

/// One entry of the account's security history (`GET /api/v1/security-events`).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ServerSecurityEvent {
    /// Unix ms.
    pub at: i64,
    /// E.g. `sign_in`, `sign_in_failed`, `device_revoked`, `password_changed`, `2fa_enabled`.
    /// The list can grow: show unknown ones generically.
    pub event: String,
    /// `user`, `admin`, `server`, or `anonymous` (no valid credentials).
    pub actor: String,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub ip: Option<String>,
    /// An event qualifier, e.g. `sign_in_failed` → `password` | `2fa`.
    pub detail: Option<String>,
    /// E.g. devices signed out, failures, or recovery codes left, depending on the event.
    pub count: Option<u64>,
    /// About the device making this request.
    pub current: bool,
}

fn no_events_api() -> PassError {
    PassError::Network(tr!("server.no_security_events"))
}

/// The account's newest security events (`GET /api/v1/security-events`), newest first, at most
/// `limit` (1-200; 0 = the server's default).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn server_security_events(
    server_url: String,
    username: String,
    token: String,
    limit: u32,
    pins: Vec<String>,
) -> Result<Vec<ServerSecurityEvent>> {
    #[derive(Deserialize)]
    struct Event {
        ts: i64,
        event: String,
        #[serde(default)]
        actor: String,
        #[serde(default)]
        device_id: Option<String>,
        #[serde(default)]
        device_name: Option<String>,
        #[serde(default)]
        ip: Option<String>,
        #[serde(default)]
        detail: Option<String>,
        #[serde(default)]
        count: Option<u64>,
        #[serde(default)]
        current: bool,
    }
    #[derive(Deserialize)]
    struct Events {
        events: Vec<Event>,
    }
    let api = Api::new(&server_url, &pins)?;
    let user = account_name(&username)?;
    let path = if limit == 0 {
        "/api/v1/security-events".to_string()
    } else {
        format!("/api/v1/security-events?limit={}", limit.min(200))
    };
    let r: Events = get_or(
        &api,
        &tr!("action.security_events"),
        &path,
        &user,
        &token,
        no_events_api,
    )?;
    Ok(r.events
        .into_iter()
        .map(|e| ServerSecurityEvent {
            at: e.ts,
            event: e.event,
            actor: e.actor,
            device_id: e.device_id,
            device_name: e.device_name,
            ip: e.ip,
            detail: e.detail,
            count: e.count,
            current: e.current,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_goes_with_requests() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = stream.read(&mut buf).unwrap();
                request.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&request);
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let length = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if body.len() >= length {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            let answer = "{\"language\":\"zh-CN\"}";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                answer.len()
            )
            .unwrap();
            String::from_utf8_lossy(&request).into_owned()
        });
        set_server_language(Some("zh_Hans".into()));
        assert_eq!(server_language().as_deref(), Some("zh-Hans"));
        let stored = server_set_language(
            format!("http://127.0.0.1:{port}"),
            "Alice".into(),
            "pst_token".into(),
            Some("zh-Hans".into()),
            vec![],
        );
        set_server_language(None);
        assert_eq!(server_language(), None);
        set_server_language(Some("not a tag!".into()));
        assert_eq!(server_language(), None);
        assert_eq!(stored.unwrap().as_deref(), Some("zh-CN"));
        let request = server.join().unwrap();
        let lower = request.to_ascii_lowercase();
        assert!(lower.starts_with("post /api/v1/language "), "{request}");
        assert!(
            lower.contains("\r\naccept-language: zh-hans\r\n"),
            "{request}"
        );
        assert!(lower.contains("\r\nauthorization: basic "), "{request}");
        assert!(request.ends_with("{\"language\":\"zh-Hans\"}"), "{request}");
    }

    /// One answer from a server on 127.0.0.1: the port, and the request it got.
    fn serve_once(status: &'static str, body: &'static str) -> (u16, std::thread::JoinHandle<String>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            while !String::from_utf8_lossy(&request).contains("\r\n\r\n") {
                let n = stream.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
            }
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            String::from_utf8_lossy(&request).into_owned()
        });
        (port, server)
    }

    #[test]
    fn old_versions_are_dropped_after_a_rotation() {
        let (port, server) = serve_once("200 OK", r#"{"removed":3}"#);
        let base = format!("http://127.0.0.1:{port}");
        let removed = server_purge_versions(
            base.clone(),
            "Alice".into(),
            "pst_token".into(),
            format!("{base}/dav/alice/personal.vault"),
            vec![],
        )
        .unwrap();
        assert_eq!(removed, Some(3));
        let request = server.join().unwrap().to_ascii_lowercase();
        assert!(
            request.starts_with("delete /api/v1/vaults/alice/personal/versions "),
            "{request}"
        );
        assert!(request.contains("\r\ncontent-type: application/json\r\n"), "{request}");
        assert!(request.contains("\r\nauthorization: basic "), "{request}");
    }

    #[test]
    fn an_older_server_or_another_owner_keeps_the_versions() {
        let (port, server) = serve_once("405 Method Not Allowed", "");
        let base = format!("http://127.0.0.1:{port}");
        let vault = format!("{base}/dav/alice/personal.vault");
        let old = server_purge_versions(base.clone(), "a".into(), "t".into(), vault, vec![]);
        assert_eq!(old.unwrap(), None);
        server.join().unwrap();
        // A vault URL on another host, or not a vault file, is refused before anything is sent.
        for url in [
            "http://evil.example/dav/alice/personal.vault",
            "http://127.0.0.1:1/dav/alice/personal.vault",
            &format!("{base}/dav/alice/personal.txt"),
            &format!("{base}/dav/Alice/personal.vault"),
            &format!("{base}/files/alice/personal.vault"),
        ] {
            assert!(
                server_purge_versions(base.clone(), "a".into(), "t".into(), url.into(), vec![])
                    .is_err(),
                "{url}"
            );
        }
    }

    #[test]
    fn json_errors() {
        assert_eq!(
            json_error_of(r#"{"error":"2fa_required","message":"enter the code"}"#),
            Some(("2fa_required".into(), "enter the code".into()))
        );
        assert_eq!(json_error_of("wrong user name or password"), None);
        assert_eq!(
            otp_value(Some(" 123 456 ".into())).as_deref(),
            Some("123 456")
        );
        assert_eq!(otp_value(Some("  ".into())), None);
        assert_eq!(otp_value(None), None);
    }

    #[test]
    fn vault_paths_stay_on_the_server() {
        let api = Api::new("https://pass.example.com:8443/pass", &[]).unwrap();
        assert_eq!(api.vault_url(None).unwrap(), None);
        assert_eq!(
            api.vault_url(Some("/dav/alice/personal.vault".into()))
                .unwrap()
                .as_deref(),
            Some("https://pass.example.com:8443/pass/dav/alice/personal.vault")
        );
        for bad in [
            "@evil.example/dav/a/p.vault",
            ".evil.example/dav/a/p.vault",
            "//evil.example/dav/a/p.vault",
            "/dav/a/p.vault?x=1",
            "/\\evil.example/x",
            "/dav/a@evil.example",
            "",
        ] {
            assert!(api.vault_url(Some(bad.into())).is_err(), "{bad}");
        }
    }

    #[test]
    fn server_addresses() {
        let n = |s: &str| normalize_server_url(s.into());
        assert_eq!(
            n(" pass.example.com:8443 ").unwrap(),
            "https://pass.example.com:8443"
        );
        assert_eq!(n("https://h/pass/").unwrap(), "https://h/pass");
        assert_eq!(n("http://[::1]:8080").unwrap(), "http://[::1]:8080");
        assert_eq!(n("HTTPS://Host.Example").unwrap(), "https://host.example");
        // Plain http:// only on this device or a private network.
        for ok in [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://app.localhost",
            "http://10.1.2.3:8443",
            "http://172.16.0.5",
            "http://172.31.255.255",
            "http://192.168.1.20:8080/pass",
            "http://169.254.10.1",
            "http://100.101.102.103",
            "http://nas.local:8080",
            "http://NAS.Local.",
            "http://pass.home.arpa",
            "http://nas.lan:5005/dav",
            "http://dav.corp.internal",
            "http://[fd12:3456::1]:8080",
            "http://[fe80::1]",
            "http://[::ffff:192.168.0.1]",
        ] {
            assert!(n(ok).is_ok(), "{ok}");
        }
        for public in [
            "http://pass.example.com",
            "http://203.0.113.7:8443",
            "http://172.32.0.1",
            "http://100.128.0.1",
            "http://8.8.8.8",
            "http://[2001:db8::1]",
            "http://[::ffff:8.8.8.8]",
            "http://local",
            "http://evil.local.example.com",
            "http://localhost.example.com",
            "http://lan",
            "http://evil.lan.example.com",
        ] {
            match n(public) {
                Err(PassError::InvalidInput(m)) => {
                    assert!(m.contains("https://"), "{public}: {m}")
                }
                other => panic!("{public}: {other:?}"),
            }
        }
        assert!(n("https://pass.example.com").is_ok());
        for bad in [
            "",
            "ftp://h",
            "https://u:p@h",
            "https://h/?x=1",
            "https://h/#f",
        ] {
            assert!(matches!(n(bad), Err(PassError::InvalidInput(_))), "{bad}");
        }
    }

    /// One rule for WebDAV and Passyble Server addresses: `plain_http_refused` (what the apps ask
    /// before saving a WebDAV address) agrees with `normalize_server_url`.
    #[test]
    fn plain_http_only_on_local_networks() {
        let refused = |s: &str| plain_http_refused(s.into());
        for local in [
            "http://192.168.1.5/remote.php/dav/files/me/pass.vault",
            "http://10.0.0.2:8080/dav/pass.vault",
            "http://nas.local/dav/pass.vault",
            "http://nas.lan/dav/pass.vault",
            "http://[fd00::5]/pass.vault",
            "http://[fe80::1]/pass.vault",
            "HTTP://127.0.0.1:1234/pass.vault",
            "http://100.64.0.1/pass.vault",
            "https://cloud.example.com/remote.php/dav/files/me/pass.vault",
        ] {
            assert!(!refused(local), "{local}");
            assert!(normalize_server_url(local.into()).is_ok(), "{local}");
        }
        for public in [
            "http://cloud.example.com/remote.php/dav/files/me/pass.vault",
            " http://203.0.113.7/pass.vault ",
            "http://[2001:db8::1]/pass.vault",
            "HTTP://dav.example.org/pass.vault",
        ] {
            assert!(refused(public), "{public}");
            assert!(normalize_server_url(public.into()).is_err(), "{public}");
        }
        // Not a URL: other checks say what is wrong.
        assert!(!refused(""));
        assert!(!refused("cloud.example.com/dav"));
    }

    /// Answers one request with `status`, an `X-Pass-Error` code and a (translated) `body`.
    fn answer_once(status: &'static str, code: &'static str, body: &'static str) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = stream.read(&mut buf).unwrap();
                request.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&request);
                if let Some((head, rest)) = text.split_once("\r\n\r\n") {
                    let length = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if rest.len() >= length {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nX-Pass-Error: {code}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        format!("http://127.0.0.1:{port}")
    }

    /// Unknown answers (a proxy's error page) never show the body or status; Passyble Server's own
    /// messages (with an error code) are shown.
    #[test]
    fn unmapped_answers_never_show_the_body() {
        let devices =
            |url: String| server_list_devices(url, "alice".into(), "pst_t".into(), vec![]);
        let network = |r: Result<Vec<ServerDevice>>| match r {
            Err(PassError::Network(m)) => m,
            other => panic!("{other:?}"),
        };

        let m = network(devices(answer_once(
            "502 Bad Gateway",
            "",
            "<html><body>nginx/1.25 upstream 10.0.0.7 refused</body></html>",
        )));
        assert!(
            crate::core_message_is(m.clone(), "net.server_error".into()),
            "{m}"
        );
        assert!(
            !m.contains("nginx") && !m.contains("502") && !m.contains("HTTP"),
            "{m}"
        );

        let m = network(devices(answer_once(
            "418 I'm a teapot",
            "",
            "short and stout",
        )));
        assert!(
            crate::core_message_is(m.clone(), "net.refused".into()),
            "{m}"
        );
        assert!(!m.contains("stout") && !m.contains("418"), "{m}");

        let m = network(devices(answer_once(
            "400 Bad Request",
            "invalid_device_name",
            "Der Gerätename ist zu lang",
        )));
        assert!(m.ends_with(": Der Gerätename ist zu lang"), "{m}");

        // Not JSON where JSON was expected: no parser text.
        let m = network(devices(answer_once("200 OK", "", "not json")));
        assert!(
            crate::core_message_is(m.clone(), "server.unexpected_answer".into()),
            "{m}"
        );
        assert!(!m.contains("line 1"), "{m}");
    }

    /// Shared vault and Cloud codes get the core's own words in the API and in sync, never "wrong
    /// password".
    #[test]
    fn shared_vault_codes_have_their_own_words() {
        let is = |m: &str, key: &str| crate::core_message_is(m.into(), key.into());
        for code in SHARED_VAULT_ERRORS {
            let key = format!("server.{code}");
            let words = |r: Result<()>| match r {
                Err(PassError::Network(m)) => m,
                other => panic!("{code}: {other:?}"),
            };
            let url = answer_once("403 Forbidden", code, "Der Server sagt nein");
            let m =
                words(server_list_devices(url, "alice".into(), "pst_t".into(), vec![]).map(|_| ()));
            assert!(is(&m, &key), "{code}: {m}");
            assert!(!m.contains("Der Server"), "{m}");
            // The same in sync: never "authentication failed".
            let url = answer_once("403 Forbidden", code, "nein");
            let m = words(
                crate::webdav_download(crate::WebDavConfig {
                    url: format!("{url}/dav/acme/eng.vault"),
                    username: "alice".into(),
                    password: "pst_t".into(),
                    pins: vec![],
                })
                .map(|_| ()),
            );
            assert!(is(&m, &key), "{code}: {m}");
            assert!(!crate::core_message_is(m, "webdav.auth_failed".into()));
        }
        // Every one has words of its own, in English too.
        for code in SHARED_VAULT_ERRORS {
            let key = format!("server.{code}");
            assert_ne!(crate::i18n::text(&key, &[]), key);
        }
    }

    /// The server's error codes, not its (translated) texts, decide what the apps are told.
    #[test]
    fn server_error_codes_not_texts() {
        let url = answer_once(
            "403 Forbidden",
            "password_change_required",
            "Wähle zuerst in der Passyble-App ein neues Passwort",
        );
        match server_list_devices(url, "alice".into(), "pst_t".into(), vec![]) {
            Err(PassError::Network(m)) => {
                assert!(
                    crate::core_message_is(m.clone(), "server.password_change_required".into()),
                    "{m}"
                );
                assert!(m.starts_with("choose a new password"), "{m}");
            }
            other => panic!("{other:?}"),
        }

        let url = answer_once("404 Not Found", "no_such_device", "kein solches Gerät");
        assert!(matches!(
            server_revoke_device(url, "alice".into(), "pst_t".into(), "d_1".into(), vec![]),
            Err(PassError::NotFound(_))
        ));

        let url = answer_once(
            "503 Service Unavailable",
            "email_unavailable",
            "Dieser Server kann keine E-Mails senden",
        );
        match server_request_reset(url, "alice".into(), vec![]) {
            Err(PassError::Network(m)) => {
                assert!(
                    crate::core_message_is(m.clone(), "server.cant_send_email".into()),
                    "{m}"
                );
                assert!(m.contains("can't send e-mail"), "{m}");
            }
            other => panic!("{other:?}"),
        }

        let url = answer_once(
            "400 Bad Request",
            "unknown_language",
            "keine Sprache \"tlh\" (verfügbar: de, en)",
        );
        match server_set_language(
            url,
            "alice".into(),
            "pst_t".into(),
            Some("tlh".into()),
            vec![],
        ) {
            Err(PassError::Network(m)) => {
                assert!(
                    crate::core_message_is(m.clone(), "server.unknown_language".into()),
                    "{m}"
                );
                assert!(
                    m.contains("(verfügbar: de, en)"),
                    "the server's detail stays: {m}"
                );
            }
            other => panic!("{other:?}"),
        }
    }
}
