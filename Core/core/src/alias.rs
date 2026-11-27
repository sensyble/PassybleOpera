//! E-mail alias services (SimpleLogin, addy.io, Firefox Relay, DuckDuckGo, Fastmail, Forward Email):
//! creates a new alias in the user's own account over the service's HTTPS API. Tokens are kept in
//! the vault and never appear in logs, errors or URLs. The website's name is sent only when the
//! caller passes `website`. Requests go through a [`Transport`] so tests run without a network.

// Without `webdav` (no HTTP client) only the configs and their storage are used.
#![cfg_attr(not(feature = "webdav"), allow(dead_code))]

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::i18n::tr;
use crate::{PassError, Result, Vault};

/// An e-mail alias service.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum AliasService {
    #[default]
    #[serde(rename = "simplelogin")]
    SimpleLogin,
    #[serde(rename = "addy_io")]
    AddyIo,
    #[serde(rename = "firefox_relay")]
    FirefoxRelay,
    #[serde(rename = "duckduckgo")]
    DuckDuckGo,
    #[serde(rename = "fastmail")]
    Fastmail,
    #[serde(rename = "forwardemail")]
    ForwardEmail,
}

impl AliasService {
    pub const ALL: [AliasService; 6] = [
        AliasService::SimpleLogin,
        AliasService::AddyIo,
        AliasService::FirefoxRelay,
        AliasService::DuckDuckGo,
        AliasService::Fastmail,
        AliasService::ForwardEmail,
    ];

    /// Stable id (settings keys, JSON): `simplelogin`, `addy_io`, `firefox_relay`, `duckduckgo`,
    /// `fastmail`, `forwardemail`.
    pub fn id(self) -> &'static str {
        match self {
            AliasService::SimpleLogin => "simplelogin",
            AliasService::AddyIo => "addy_io",
            AliasService::FirefoxRelay => "firefox_relay",
            AliasService::DuckDuckGo => "duckduckgo",
            AliasService::Fastmail => "fastmail",
            AliasService::ForwardEmail => "forwardemail",
        }
    }

    pub fn from_id(id: &str) -> Option<AliasService> {
        AliasService::ALL.into_iter().find(|s| s.id() == id.trim())
    }

    /// The service's name (a brand: not translated).
    pub fn name(self) -> &'static str {
        match self {
            AliasService::SimpleLogin => "SimpleLogin",
            AliasService::AddyIo => "addy.io",
            AliasService::FirefoxRelay => "Firefox Relay",
            AliasService::DuckDuckGo => "DuckDuckGo",
            AliasService::Fastmail => "Fastmail",
            AliasService::ForwardEmail => "Forward Email",
        }
    }

    /// The API's address when [`AliasConfig::base_url`] is empty.
    pub fn default_base_url(self) -> &'static str {
        match self {
            AliasService::SimpleLogin => "https://app.simplelogin.io",
            AliasService::AddyIo => "https://app.addy.io",
            AliasService::FirefoxRelay => "https://relay.firefox.com",
            AliasService::DuckDuckGo => "https://quack.duckduckgo.com",
            AliasService::Fastmail => "https://api.fastmail.com",
            AliasService::ForwardEmail => "https://api.forwardemail.net",
        }
    }

    /// Whether the service can be self-hosted ([`AliasConfig::base_url`] is used).
    pub fn self_hostable(self) -> bool {
        matches!(self, AliasService::SimpleLogin | AliasService::AddyIo)
    }

    /// Whether [`AliasConfig::domain`] is used: addy.io (the alias domain, `anonaddy.me` when
    /// empty) and Forward Email (the user's own domain, required).
    pub fn uses_domain(self) -> bool {
        matches!(self, AliasService::AddyIo | AliasService::ForwardEmail)
    }
}

/// The name of an alias service (for the apps' lists).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn alias_service_name(service: AliasService) -> String {
    service.name().to_string()
}

/// The user's account at an alias service. Kept in the vault ([`Vault::set_alias_config`]).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AliasConfig {
    pub service: AliasService,
    /// The account's API token (Fastmail: an API token with the Masked Email scope).
    #[serde(default)]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub token: String,
    /// A self-hosted server (SimpleLogin, addy.io), `https://` only; `""`: the service's own.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub base_url: String,
    /// addy.io: the alias domain (`""`: `anonaddy.me`). Forward Email: the user's domain.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub domain: String,
}

/// The token never shows in debug output.
impl std::fmt::Debug for AliasConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AliasConfig")
            .field("service", &self.service)
            .field("base_url", &self.base_url)
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

/// addy.io's shared domain, used when no domain is set.
pub const ADDY_DEFAULT_DOMAIN: &str = "anonaddy.me";

impl AliasConfig {
    /// The config as it is stored: trimmed, a base URL only for self-hostable services and a
    /// domain only where one is used. Errors name what to fix.
    pub(crate) fn normalized(&self) -> Result<AliasConfig> {
        let token = self.token.trim();
        if token.is_empty() {
            return Err(PassError::InvalidInput(tr!(
                "alias.no_token",
                service = self.service.name()
            )));
        }
        if token.len() > 4096 || token.chars().any(|c| c.is_control() || c == ' ') {
            return Err(PassError::InvalidInput(tr!(
                "alias.bad_token_format",
                service = self.service.name()
            )));
        }
        let base_url = if self.service.self_hostable() && !self.base_url.trim().is_empty() {
            clean_base_url(&self.base_url)?
        } else {
            String::new()
        };
        let domain = if self.service.uses_domain() && !self.domain.trim().is_empty() {
            crate::generator::clean_domain(&self.domain)
                .ok_or_else(|| PassError::InvalidInput(tr!("generator.bad_domain")))?
        } else if self.service == AliasService::ForwardEmail {
            return Err(PassError::InvalidInput(tr!("alias.domain_required")));
        } else {
            String::new()
        };
        Ok(AliasConfig {
            service: self.service,
            token: token.to_string(),
            base_url,
            domain,
        })
    }

    fn base(&self) -> String {
        if self.base_url.is_empty() {
            self.service.default_base_url().to_string()
        } else {
            self.base_url.trim_end_matches('/').to_string()
        }
    }
}

/// A self-hosted server's address: `https://host[:port][/path]`, no credentials, query or
/// fragment; the trailing `/` dropped.
fn clean_base_url(input: &str) -> Result<String> {
    let bad = || PassError::InvalidInput(tr!("alias.bad_base_url"));
    let url = url::Url::parse(input.trim()).map_err(|_| bad())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(bad());
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

/// The website an alias is made for, as a host name (`github.com` for
/// `https://github.com/login`); `None` if `website` has none.
fn website_host(website: Option<&str>) -> Option<String> {
    let url = crate::matching::parse_loose(website?.trim())?;
    let host = url.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    let ok = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'));
    ok.then_some(host)
}

/// One HTTP request to a service.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct HttpRequest {
    pub method: &'static str,
    pub url: String,
    /// Header name and value; `Authorization` / `Authentication` carry the token.
    pub headers: Vec<(&'static str, String)>,
    pub body: Option<Value>,
}

impl std::fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("body", &self.body)
            .finish_non_exhaustive()
    }
}

/// A service's answer: status and body (at most [`MAX_BODY`] bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HttpResponse {
    pub status: u16,
    pub body: String,
}

/// Longest answer read.
const MAX_BODY: u64 = 256 * 1024;

/// Sends a request: the network ([`UreqTransport`]) or, in tests, canned answers. `Err` only
/// when there is no answer at all (`Network`).
pub(crate) trait Transport {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse>;
}

const JSON: &str = "application/json";

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

fn note_for(host: &Option<String>) -> Option<String> {
    host.as_ref().map(|h| format!("Website: {h}"))
}

/// The request that makes a new alias (Fastmail: the second request, after [`fastmail_session`]).
fn create_request(config: &AliasConfig, host: &Option<String>) -> HttpRequest {
    let base = config.base();
    let token = &config.token;
    match config.service {
        // POST /api/alias/random/new, `Authentication: <api key>`, `?hostname=` (SimpleLogin
        // suggests the same alias for the site again), body `{ "note" }`. 201: the alias.
        AliasService::SimpleLogin => {
            let mut url = format!("{base}/api/alias/random/new");
            if let Some(h) = host {
                url.push_str("?hostname=");
                url.push_str(&percent_encoding::utf8_percent_encode(h, QUERY).to_string());
            }
            let mut body = json!({});
            if let Some(note) = note_for(host) {
                body["note"] = note.into();
            }
            HttpRequest {
                method: "POST",
                url,
                headers: vec![
                    ("Authentication", token.clone()),
                    ("Content-Type", JSON.into()),
                    ("Accept", JSON.into()),
                ],
                body: Some(body),
            }
        }
        // POST /api/v1/aliases, Bearer, body `{ "domain", "description" }`. 201: `data.email`.
        AliasService::AddyIo => {
            let domain = if config.domain.is_empty() {
                ADDY_DEFAULT_DOMAIN
            } else {
                &config.domain
            };
            let mut body = json!({ "domain": domain });
            if let Some(note) = note_for(host) {
                body["description"] = note.into();
            }
            HttpRequest {
                method: "POST",
                url: format!("{base}/api/v1/aliases"),
                headers: addy_headers(token),
                body: Some(body),
            }
        }
        // POST /api/v1/relayaddresses/, `Authorization: Token <key>`, body `{ "enabled",
        // "generated_for", "description" }`. 201: `full_address`.
        AliasService::FirefoxRelay => {
            let mut body = json!({ "enabled": true });
            if let Some(h) = host {
                body["generated_for"] = h.clone().into();
                body["description"] = h.clone().into();
            }
            HttpRequest {
                method: "POST",
                url: format!("{base}/api/v1/relayaddresses/"),
                headers: vec![
                    ("Authorization", format!("Token {token}")),
                    ("Content-Type", JSON.into()),
                    ("Accept", JSON.into()),
                ],
                body: Some(body),
            }
        }
        // POST /api/email/addresses, Bearer, no body (the website can't be sent). 201:
        // `address`, the part before `@duck.com`.
        AliasService::DuckDuckGo => HttpRequest {
            method: "POST",
            url: format!("{base}/api/email/addresses"),
            headers: vec![("Authorization", bearer(token)), ("Accept", JSON.into())],
            body: None,
        },
        // JMAP `MaskedEmail/set` (built by `fastmail_create`, which needs the session).
        AliasService::Fastmail => unreachable!("fastmail_create"),
        // POST /v1/domains/<domain>/aliases, HTTP Basic with the token as user name, body
        // `{ "labels", "description" }` (no `name`: a random one). 200: `name` and `domain.name`.
        AliasService::ForwardEmail => {
            let mut body = json!({});
            if let Some(h) = host {
                body["labels"] = h.clone().into();
                body["description"] = format!("Website: {h}").into();
            }
            HttpRequest {
                method: "POST",
                url: format!("{base}/v1/domains/{}/aliases", config.domain),
                headers: forward_email_headers(token),
                body: Some(body),
            }
        }
    }
}

const QUERY: &percent_encoding::AsciiSet =
    &percent_encoding::NON_ALPHANUMERIC.remove(b'.').remove(b'-');

fn addy_headers(token: &str) -> Vec<(&'static str, String)> {
    vec![
        ("Authorization", bearer(token)),
        ("Content-Type", JSON.into()),
        ("Accept", JSON.into()),
        ("X-Requested-With", "XMLHttpRequest".into()),
    ]
}

fn forward_email_headers(token: &str) -> Vec<(&'static str, String)> {
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("{token}:"));
    vec![
        ("Authorization", format!("Basic {basic}")),
        ("Content-Type", JSON.into()),
        ("Accept", JSON.into()),
    ]
}

/// The request that checks a token without making an alias (DuckDuckGo has none: `None`).
fn check_request(config: &AliasConfig) -> Option<HttpRequest> {
    let base = config.base();
    let token = &config.token;
    let get = |url: String, headers| HttpRequest {
        method: "GET",
        url,
        headers,
        body: None,
    };
    match config.service {
        AliasService::SimpleLogin => Some(get(
            format!("{base}/api/user_info"),
            vec![("Authentication", token.clone()), ("Accept", JSON.into())],
        )),
        AliasService::AddyIo => Some(get(
            format!("{base}/api/v1/account-details"),
            addy_headers(token),
        )),
        AliasService::FirefoxRelay => Some(get(
            format!("{base}/api/v1/profiles/"),
            vec![
                ("Authorization", format!("Token {token}")),
                ("Accept", JSON.into()),
            ],
        )),
        AliasService::DuckDuckGo => None,
        AliasService::Fastmail => Some(fastmail_session_request(config)),
        AliasService::ForwardEmail => Some(get(
            format!("{base}/v1/domains/{}", config.domain),
            forward_email_headers(token),
        )),
    }
}

const MASKED_EMAIL: &str = "https://www.fastmail.com/dev/maskedemail";
const JMAP_CORE: &str = "urn:ietf:params:jmap:core";

fn fastmail_session_request(config: &AliasConfig) -> HttpRequest {
    HttpRequest {
        method: "GET",
        url: format!("{}/jmap/session", config.base()),
        headers: vec![
            ("Authorization", bearer(&config.token)),
            ("Accept", JSON.into()),
        ],
        body: None,
    }
}

/// From the JMAP session: the account for masked e-mail and the API URL (only one on Fastmail's
/// own API host is used, else the documented `https://api.fastmail.com/jmap/api/`).
fn fastmail_session(config: &AliasConfig, body: &str) -> Result<(String, String)> {
    let session: Value = serde_json::from_str(body).map_err(|_| unexpected(config.service))?;
    let account = session["primaryAccounts"][MASKED_EMAIL]
        .as_str()
        .filter(|a| !a.is_empty())
        .ok_or_else(|| PassError::InvalidInput(tr!("alias.fastmail_no_masked_email")))?
        .to_string();
    let default_api = format!("{}/jmap/api/", config.base());
    let api = session["apiUrl"]
        .as_str()
        .filter(|u| u.starts_with(&format!("{}/", config.base())))
        .map_or(default_api, str::to_string);
    Ok((account, api))
}

fn fastmail_create_request(
    config: &AliasConfig,
    account: &str,
    api: &str,
    host: &Option<String>,
) -> HttpRequest {
    // `forDomain` is the site's origin; `description` stays empty unless the user wrote one
    // (Fastmail's guidance for password managers).
    let mut create = json!({ "state": "enabled", "description": "" });
    if let Some(h) = host {
        create["forDomain"] = format!("https://{h}").into();
    }
    HttpRequest {
        method: "POST",
        url: api.to_string(),
        headers: vec![
            ("Authorization", bearer(&config.token)),
            ("Content-Type", JSON.into()),
            ("Accept", JSON.into()),
        ],
        body: Some(json!({
            "using": [JMAP_CORE, MASKED_EMAIL],
            "methodCalls": [[
                "MaskedEmail/set",
                { "accountId": account, "create": { "passyble": create } },
                "0"
            ]]
        })),
    }
}

fn unexpected(service: AliasService) -> PassError {
    PassError::Network(tr!("alias.unexpected_answer", service = service.name()))
}

/// A short, printable message from an error answer (`error`, `message`, `detail`, ...), only to
/// tell whether the service said why it refused. The text itself is never shown.
fn answer_message(body: &str) -> Option<String> {
    let value: Value = serde_json::from_str(body).ok()?;
    let text = ["error", "message", "detail", "description"]
        .iter()
        .find_map(|k| match &value[*k] {
            Value::String(s) => Some(s.clone()),
            Value::Object(o) => o.get("message").and_then(Value::as_str).map(str::to_string),
            _ => None,
        })
        .or_else(|| {
            // Django REST Framework: `{ "field": ["message"] }`.
            value
                .as_object()?
                .values()
                .find_map(|v| v.as_array()?.first()?.as_str().map(str::to_string))
        })?;
    let clean: String = text.chars().filter(|c| !c.is_control()).take(200).collect();
    let clean = clean.trim().to_string();
    (!clean.is_empty()).then_some(clean)
}

/// The error for a non-2xx answer.
fn status_error(service: AliasService, response: &HttpResponse) -> PassError {
    let name = service.name();
    let message = answer_message(&response.body);
    match (response.status, message) {
        (401, _) | (403, None) => PassError::InvalidInput(tr!("alias.bad_token", service = name)),
        (429, _) => PassError::Network(tr!("alias.rate_limited", service = name)),
        (404, None) => PassError::InvalidInput(tr!("alias.not_found", service = name)),
        (400..=499, Some(_)) => PassError::InvalidInput(tr!("alias.refused", service = name)),
        _ => PassError::Network(tr!("alias.server_error", service = name)),
    }
}

/// The answer's JSON when it is a success, else the matching error.
fn success_json(service: AliasService, response: &HttpResponse) -> Result<Value> {
    if !(200..300).contains(&response.status) {
        return Err(status_error(service, response));
    }
    serde_json::from_str(&response.body).map_err(|_| unexpected(service))
}

/// The new alias from the creating request's answer.
fn parse_created(config: &AliasConfig, response: &HttpResponse) -> Result<String> {
    let service = config.service;
    let value = success_json(service, response)?;
    let address = match service {
        // Depending on the server version the answer has `alias` or the alias object (`email`).
        AliasService::SimpleLogin => value["alias"]
            .as_str()
            .or_else(|| value["email"].as_str())
            .map(str::to_string),
        AliasService::AddyIo => value["data"]["email"].as_str().map(str::to_string),
        AliasService::FirefoxRelay => value["full_address"].as_str().map(str::to_string),
        AliasService::DuckDuckGo => value["address"]
            .as_str()
            .filter(|a| !a.is_empty() && !a.contains('@'))
            .map(|a| format!("{a}@duck.com")),
        AliasService::Fastmail => {
            let call = &value["methodResponses"][0];
            match call[0].as_str() {
                Some("MaskedEmail/set") => match call[1]["created"]["passyble"]["email"].as_str() {
                    Some(email) => Some(email.to_string()),
                    // `notCreated`: Fastmail's reason is for developers, not shown.
                    None => {
                        return Err(PassError::InvalidInput(tr!(
                            "alias.refused",
                            service = service.name()
                        )));
                    }
                },
                Some("error") => {
                    return Err(PassError::InvalidInput(tr!(
                        "alias.refused",
                        service = service.name()
                    )));
                }
                _ => None,
            }
        }
        AliasService::ForwardEmail => value["name"].as_str().map(|name| {
            let domain = value["domain"]["name"].as_str().unwrap_or(&config.domain);
            format!("{name}@{domain}")
        }),
    };
    address
        .map(|a| a.trim().to_string())
        .filter(|a| valid_address(a))
        .ok_or_else(|| unexpected(service))
}

/// Looks like an e-mail address: one `@`, something on both sides, no spaces or controls.
fn valid_address(a: &str) -> bool {
    a.len() <= 320
        && a.split('@').count() == 2
        && a.split('@').all(|p| !p.is_empty())
        && !a.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Makes a new alias at the user's account (`config`). `website`: a URL or host name, sent as
/// the alias's note or label; `None` sends nothing about the site.
pub(crate) fn create_alias(
    transport: &dyn Transport,
    config: &AliasConfig,
    website: Option<&str>,
) -> Result<String> {
    let config = config.normalized()?;
    let host = website_host(website);
    let request = if config.service == AliasService::Fastmail {
        let session = transport.send(&fastmail_session_request(&config))?;
        if !(200..300).contains(&session.status) {
            return Err(status_error(config.service, &session));
        }
        let (account, api) = fastmail_session(&config, &session.body)?;
        fastmail_create_request(&config, &account, &api, &host)
    } else {
        create_request(&config, &host)
    };
    let response = transport.send(&request)?;
    parse_created(&config, &response)
}

/// Checks `config` (the token, and Forward Email's domain) without making an alias, except at
/// DuckDuckGo, which has no other way: there the check makes one and returns it (`Some`).
pub(crate) fn check_alias(
    transport: &dyn Transport,
    config: &AliasConfig,
) -> Result<Option<String>> {
    let config = config.normalized()?;
    let Some(request) = check_request(&config) else {
        return create_alias(transport, &config, None).map(Some);
    };
    let response = transport.send(&request)?;
    if !(200..300).contains(&response.status) {
        return Err(status_error(config.service, &response));
    }
    if config.service == AliasService::Fastmail {
        fastmail_session(&config, &response.body)?;
    }
    Ok(None)
}

/// The network transport: ureq with rustls, 10 s to connect, 30 s per request. Errors never
/// include headers (the token).
#[cfg(feature = "webdav")]
pub(crate) struct UreqTransport {
    agent: ureq::Agent,
    service: AliasService,
}

#[cfg(feature = "webdav")]
impl UreqTransport {
    pub(crate) fn new(service: AliasService) -> Self {
        Self {
            agent: ureq::AgentBuilder::new()
                .timeout_connect(std::time::Duration::from_secs(10))
                .timeout(std::time::Duration::from_secs(30))
                .redirects(0)
                .build(),
            service,
        }
    }
}

#[cfg(feature = "webdav")]
impl Transport for UreqTransport {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse> {
        use std::io::Read;
        let mut call = self
            .agent
            .request(request.method, &request.url)
            .set("User-Agent", "Passyble");
        for (name, value) in &request.headers {
            call = call.set(name, value);
        }
        let result = match &request.body {
            Some(body) => call.send_string(&body.to_string()),
            None if request.method == "POST" => call.send_bytes(&[]),
            None => call.call(),
        };
        let response = match result {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            // Not the library's text, nor the URL (it can name the user's domain).
            Err(ureq::Error::Transport(_)) => {
                return Err(PassError::Network(tr!(
                    "alias.cant_reach",
                    service = self.service.name()
                )));
            }
        };
        let status = response.status();
        let mut body = String::new();
        response
            .into_reader()
            .take(MAX_BODY)
            .read_to_string(&mut body)
            .map_err(|_| unexpected(self.service))?;
        Ok(HttpResponse { status, body })
    }
}

/// Makes a new alias with a config that isn't saved yet (blocking). For a saved config use
/// [`Vault::generate_alias`].
#[cfg(feature = "webdav")]
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn alias_generate(config: AliasConfig, website: Option<String>) -> Result<String> {
    create_alias(
        &UreqTransport::new(config.service),
        &config,
        website.as_deref(),
    )
}

/// Checks the token (and Forward Email's domain) without making an alias. DuckDuckGo has no such
/// check, so there it makes an alias and returns it. Blocking.
#[cfg(feature = "webdav")]
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn alias_check(config: AliasConfig) -> Result<Option<String>> {
    check_alias(&UreqTransport::new(config.service), &config)
}

/// The e-mail generator's addresses, kept in the vault ([`Vault::email_generator_settings`]).
/// `""`: not set.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct EmailGeneratorSettings {
    /// The user's own address, for plus addressing (`alex@example.com`).
    #[serde(default)]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub address: String,
    /// A catch-all domain the user owns (`mydomain.com`).
    #[serde(default)]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub domain: String,
}

const EMAIL_KEY: &str = "email";
const ALIAS_PREFIX: &str = "alias.";
const ALIAS_DEFAULT_KEY: &str = "alias-default";

fn alias_key(service: AliasService) -> String {
    format!("{ALIAS_PREFIX}{}", service.id())
}

fn to_json<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|_| PassError::Crypto(tr!("error.internal")))
}

/// Settings for the username and e-mail generators, kept (encrypted) in the vault and synced with
/// it. Each change marks the vault dirty: save it like after an edit.
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Vault {
    /// The e-mail generator's addresses (empty when not set).
    pub fn email_generator_settings(&self) -> EmailGeneratorSettings {
        self.setting(EMAIL_KEY)
            .and_then(|v| serde_json::from_str(&v).ok())
            .unwrap_or_default()
    }

    /// Saves the e-mail generator's addresses, trimmed (the domain in lowercase). Each must be
    /// empty or valid: `InvalidInput` names the one that isn't.
    pub fn set_email_generator_settings(&self, settings: EmailGeneratorSettings) -> Result<()> {
        let address = settings.address.trim().to_string();
        if !address.is_empty() {
            crate::generate_email(crate::EmailOptions {
                address: address.clone(),
                ..Default::default()
            })?;
        }
        let domain = match settings.domain.trim() {
            "" => String::new(),
            d => crate::generator::clean_domain(d)
                .ok_or_else(|| PassError::InvalidInput(tr!("generator.bad_domain")))?,
        };
        let value = (!address.is_empty() || !domain.is_empty())
            .then(|| to_json(&EmailGeneratorSettings { address, domain }))
            .transpose()?;
        self.put_setting(EMAIL_KEY, value)?;
        Ok(())
    }

    /// Every alias service set up in this vault, in [`AliasService::ALL`] order. The configs hold
    /// the API tokens: show them only masked.
    pub fn alias_configs(&self) -> Vec<AliasConfig> {
        AliasService::ALL
            .into_iter()
            .filter_map(|s| self.alias_config(s))
            .collect()
    }

    /// The config of `service`, if it is set up.
    pub fn alias_config(&self, service: AliasService) -> Option<AliasConfig> {
        let config: AliasConfig = serde_json::from_str(&self.setting(&alias_key(service))?).ok()?;
        (config.service == service).then_some(config)
    }

    /// Sets up (or replaces) an alias service after normalizing it (`InvalidInput` says what to
    /// fix). The first service set up becomes the default.
    pub fn set_alias_config(&self, config: AliasConfig) -> Result<()> {
        let config = config.normalized()?;
        self.put_setting(&alias_key(config.service), Some(to_json(&config)?))?;
        if self.setting(ALIAS_DEFAULT_KEY).is_none() {
            self.put_setting(ALIAS_DEFAULT_KEY, Some(config.service.id().to_string()))?;
        }
        Ok(())
    }

    /// Removes `service`'s config (and its token) from the vault; if it was the default, another
    /// set-up service (if any) becomes the default.
    pub fn remove_alias_config(&self, service: AliasService) -> Result<()> {
        self.put_setting(&alias_key(service), None)?;
        if self.setting(ALIAS_DEFAULT_KEY).as_deref() == Some(service.id()) {
            let next = self
                .alias_configs()
                .first()
                .map(|c| c.service.id().to_string());
            self.put_setting(ALIAS_DEFAULT_KEY, next)?;
        }
        Ok(())
    }

    /// The service the generator uses: the chosen default if it is still set up, else the first
    /// set-up one; `None` when no service is set up.
    pub fn alias_default_service(&self) -> Option<AliasService> {
        let configured: Vec<AliasService> = self
            .setting_keys(ALIAS_PREFIX)
            .iter()
            .filter_map(|k| AliasService::from_id(&k[ALIAS_PREFIX.len()..]))
            .collect();
        self.setting(ALIAS_DEFAULT_KEY)
            .and_then(|id| AliasService::from_id(&id))
            .filter(|s| configured.contains(s))
            .or_else(|| {
                AliasService::ALL
                    .into_iter()
                    .find(|s| configured.contains(s))
            })
    }

    /// Chooses the default service (`None`: the first set up). `NotFound` if it isn't set up.
    pub fn set_alias_default_service(&self, service: Option<AliasService>) -> Result<()> {
        if let Some(s) = service {
            if self.alias_config(s).is_none() {
                return Err(PassError::NotFound(tr!(
                    "alias.not_set_up",
                    service = s.name()
                )));
            }
        }
        self.put_setting(ALIAS_DEFAULT_KEY, service.map(|s| s.id().to_string()))?;
        Ok(())
    }
}

/// Alias services over the network, with the config kept in the vault.
#[cfg(feature = "webdav")]
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Vault {
    /// Makes a new alias at `service` (`None`: [`Vault::alias_default_service`]) with its saved
    /// config. `website` is sent as the alias's note or label: pass it only when the user asked.
    /// Blocking; the vault isn't locked during the request. `NotFound` when not set up.
    pub fn generate_alias(
        &self,
        service: Option<AliasService>,
        website: Option<String>,
    ) -> Result<String> {
        let config = self.saved_alias_config(service)?;
        create_alias(
            &UreqTransport::new(config.service),
            &config,
            website.as_deref(),
        )
    }

    /// [`alias_check`] with `service`'s saved config (the "Test" button for a saved token).
    pub fn check_alias_service(&self, service: AliasService) -> Result<Option<String>> {
        let config = self.saved_alias_config(Some(service))?;
        check_alias(&UreqTransport::new(config.service), &config)
    }
}

#[cfg(feature = "webdav")]
impl Vault {
    fn saved_alias_config(&self, service: Option<AliasService>) -> Result<AliasConfig> {
        let service = service
            .or_else(|| self.alias_default_service())
            .ok_or_else(|| PassError::NotFound(tr!("alias.none_set_up")))?;
        self.alias_config(service)
            .ok_or_else(|| PassError::NotFound(tr!("alias.not_set_up", service = service.name())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Answers each request with the next canned response and records the requests.
    struct Canned {
        answers: RefCell<Vec<HttpResponse>>,
        sent: RefCell<Vec<HttpRequest>>,
    }

    impl Canned {
        fn new(answers: &[(u16, &str)]) -> Canned {
            Canned {
                answers: RefCell::new(
                    answers
                        .iter()
                        .rev()
                        .map(|(status, body)| HttpResponse {
                            status: *status,
                            body: body.to_string(),
                        })
                        .collect(),
                ),
                sent: RefCell::new(Vec::new()),
            }
        }
    }

    impl Transport for Canned {
        fn send(&self, request: &HttpRequest) -> Result<HttpResponse> {
            self.sent.borrow_mut().push(request.clone());
            self.answers
                .borrow_mut()
                .pop()
                .ok_or_else(|| PassError::Network("no answer".into()))
        }
    }

    fn config(service: AliasService) -> AliasConfig {
        AliasConfig {
            service,
            token: " tok-123 ".into(),
            ..Default::default()
        }
    }

    fn header<'a>(r: &'a HttpRequest, name: &str) -> Option<&'a str> {
        r.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn simplelogin() {
        let t = Canned::new(&[(
            201,
            r#"{"id":1,"email":"cool.otter@simplelogin.com","alias":"cool.otter@simplelogin.com"}"#,
        )]);
        let alias = create_alias(
            &t,
            &config(AliasService::SimpleLogin),
            Some("https://accounts.github.com/login"),
        )
        .unwrap();
        assert_eq!(alias, "cool.otter@simplelogin.com");
        let r = &t.sent.borrow()[0];
        assert_eq!(r.method, "POST");
        assert_eq!(
            r.url,
            "https://app.simplelogin.io/api/alias/random/new?hostname=accounts.github.com"
        );
        assert_eq!(header(r, "Authentication"), Some("tok-123"));
        assert_eq!(header(r, "Authorization"), None);
        assert_eq!(
            r.body,
            Some(json!({ "note": "Website: accounts.github.com" }))
        );

        // No website: nothing about it is sent; a self-hosted server; `email` only.
        let t = Canned::new(&[(201, r#"{"email":"x@sl.example.org"}"#)]);
        let mut c = config(AliasService::SimpleLogin);
        c.base_url = "https://sl.example.org/".into();
        assert_eq!(create_alias(&t, &c, None).unwrap(), "x@sl.example.org");
        let r = &t.sent.borrow()[0];
        assert_eq!(r.url, "https://sl.example.org/api/alias/random/new");
        assert_eq!(r.body, Some(json!({})));
    }

    #[test]
    fn addy_io() {
        let t = Canned::new(&[(
            201,
            r#"{"data":{"id":"x","email":"k3vq9@anonaddy.me","local_part":"k3vq9"}}"#,
        )]);
        let alias = create_alias(&t, &config(AliasService::AddyIo), None).unwrap();
        assert_eq!(alias, "k3vq9@anonaddy.me");
        let r = &t.sent.borrow()[0];
        assert_eq!(r.url, "https://app.addy.io/api/v1/aliases");
        assert_eq!(header(r, "Authorization"), Some("Bearer tok-123"));
        assert_eq!(header(r, "X-Requested-With"), Some("XMLHttpRequest"));
        assert_eq!(r.body, Some(json!({ "domain": "anonaddy.me" })));

        let t = Canned::new(&[(201, r#"{"data":{"email":"a@alex.anonaddy.com"}}"#)]);
        let mut c = config(AliasService::AddyIo);
        c.domain = "Alex.AnonAddy.com".into();
        create_alias(&t, &c, Some("shop.example")).unwrap();
        assert_eq!(
            t.sent.borrow()[0].body,
            Some(json!({ "domain": "alex.anonaddy.com", "description": "Website: shop.example" }))
        );
    }

    #[test]
    fn firefox_relay() {
        let t = Canned::new(&[(201, r#"{"id":5,"full_address":"abc123@mozmail.com"}"#)]);
        let alias =
            create_alias(&t, &config(AliasService::FirefoxRelay), Some("example.com")).unwrap();
        assert_eq!(alias, "abc123@mozmail.com");
        let r = &t.sent.borrow()[0];
        assert_eq!(r.url, "https://relay.firefox.com/api/v1/relayaddresses/");
        assert_eq!(header(r, "Authorization"), Some("Token tok-123"));
        assert_eq!(
            r.body,
            Some(
                json!({ "enabled": true, "generated_for": "example.com", "description": "example.com" })
            )
        );
        // The free plan's limit: the core's text says what to check, not the service's English.
        let t = Canned::new(&[(
            403,
            r#"{"detail":"You must be a premium subscriber to make more than 5 email masks."}"#,
        )]);
        let e = create_alias(&t, &config(AliasService::FirefoxRelay), None).unwrap_err();
        assert!(
            matches!(&e, PassError::InvalidInput(m) if m.contains("alias limit") && !m.contains("premium subscriber")),
            "{e}"
        );
    }

    #[test]
    fn duckduckgo() {
        let t = Canned::new(&[(201, r#"{"address":"quiet-otter-x1"}"#)]);
        let alias =
            create_alias(&t, &config(AliasService::DuckDuckGo), Some("example.com")).unwrap();
        assert_eq!(alias, "quiet-otter-x1@duck.com");
        let r = &t.sent.borrow()[0];
        assert_eq!(r.method, "POST");
        assert_eq!(r.url, "https://quack.duckduckgo.com/api/email/addresses");
        assert_eq!(header(r, "Authorization"), Some("Bearer tok-123"));
        // DuckDuckGo gets nothing about the site.
        assert_eq!(r.body, None);
        assert!(!r.url.contains("example"));
        // The check makes an address (no other way).
        let t = Canned::new(&[(201, r#"{"address":"abc"}"#)]);
        assert_eq!(
            check_alias(&t, &config(AliasService::DuckDuckGo)).unwrap(),
            Some("abc@duck.com".into())
        );
    }

    #[test]
    fn fastmail() {
        let session = r#"{"apiUrl":"https://api.fastmail.com/jmap/api/","primaryAccounts":{"urn:ietf:params:jmap:core":"u1","https://www.fastmail.com/dev/maskedemail":"u1"}}"#;
        let created = r#"{"methodResponses":[["MaskedEmail/set",{"accountId":"u1","created":{"passyble":{"id":"m1","email":"funny.otter1@fastmail.com","state":"enabled"}}},"0"]],"sessionState":"x"}"#;
        let t = Canned::new(&[(200, session), (200, created)]);
        let alias = create_alias(
            &t,
            &config(AliasService::Fastmail),
            Some("https://www.example.com/x"),
        )
        .unwrap();
        assert_eq!(alias, "funny.otter1@fastmail.com");
        let sent = t.sent.borrow();
        assert_eq!(sent[0].method, "GET");
        assert_eq!(sent[0].url, "https://api.fastmail.com/jmap/session");
        assert_eq!(header(&sent[0], "Authorization"), Some("Bearer tok-123"));
        assert_eq!(sent[1].url, "https://api.fastmail.com/jmap/api/");
        let body = sent[1].body.as_ref().unwrap();
        assert_eq!(body["using"], json!([JMAP_CORE, MASKED_EMAIL]));
        let call = &body["methodCalls"][0];
        assert_eq!(call[0], "MaskedEmail/set");
        assert_eq!(call[1]["accountId"], "u1");
        assert_eq!(
            call[1]["create"]["passyble"],
            json!({ "state": "enabled", "description": "", "forDomain": "https://www.example.com" })
        );
        drop(sent);

        // An apiUrl elsewhere is not followed; without a website there is no forDomain.
        let odd = r#"{"apiUrl":"https://evil.example/jmap","primaryAccounts":{"https://www.fastmail.com/dev/maskedemail":"u1"}}"#;
        let t = Canned::new(&[(200, odd), (200, created)]);
        create_alias(&t, &config(AliasService::Fastmail), None).unwrap();
        let sent = t.sent.borrow();
        assert_eq!(sent[1].url, "https://api.fastmail.com/jmap/api/");
        assert!(
            sent[1].body.as_ref().unwrap()["methodCalls"][0][1]["create"]["passyble"]
                .get("forDomain")
                .is_none()
        );
        drop(sent);

        // A token without the Masked Email scope.
        let t = Canned::new(&[(
            200,
            r#"{"apiUrl":"x","primaryAccounts":{"urn:ietf:params:jmap:core":"u1"}}"#,
        )]);
        let e = create_alias(&t, &config(AliasService::Fastmail), None).unwrap_err();
        assert!(matches!(e, PassError::InvalidInput(_)));
        assert!(check_alias(&t, &config(AliasService::Fastmail)).is_err());

        // notCreated / error answers.
        let refused = r#"{"methodResponses":[["MaskedEmail/set",{"notCreated":{"passyble":{"type":"invalidProperties","description":"bad forDomain"}}},"0"]]}"#;
        let t = Canned::new(&[(200, session), (200, refused)]);
        let e = create_alias(&t, &config(AliasService::Fastmail), None).unwrap_err();
        assert!(
            matches!(&e, PassError::InvalidInput(m) if m.contains("didn't make the alias") && !m.contains("forDomain")),
            "{e}"
        );
        let error = r#"{"methodResponses":[["error",{"type":"accountNotFound"},"0"]]}"#;
        let t = Canned::new(&[(200, session), (200, error)]);
        let e = create_alias(&t, &config(AliasService::Fastmail), None).unwrap_err();
        assert!(
            matches!(&e, PassError::InvalidInput(m) if !m.contains("accountNotFound")),
            "{e}"
        );
    }

    #[test]
    fn forward_email() {
        let mut c = config(AliasService::ForwardEmail);
        assert!(matches!(
            create_alias(&Canned::new(&[]), &c, None),
            Err(PassError::InvalidInput(_))
        ));
        c.domain = "mydomain.com".into();
        let t = Canned::new(&[(
            200,
            r#"{"name":"k3vq9tmz","domain":{"name":"mydomain.com"},"id":"x"}"#,
        )]);
        let alias = create_alias(&t, &c, Some("github.com")).unwrap();
        assert_eq!(alias, "k3vq9tmz@mydomain.com");
        let r = &t.sent.borrow()[0];
        assert_eq!(
            r.url,
            "https://api.forwardemail.net/v1/domains/mydomain.com/aliases"
        );
        // Basic auth: the token as user name, no password.
        assert_eq!(header(r, "Authorization"), Some("Basic dG9rLTEyMzo="));
        assert_eq!(
            r.body,
            Some(json!({ "labels": "github.com", "description": "Website: github.com" }))
        );
        let t = Canned::new(&[(200, r#"{"name":"abc"}"#)]);
        assert_eq!(create_alias(&t, &c, None).unwrap(), "abc@mydomain.com");
        assert_eq!(t.sent.borrow()[0].body, Some(json!({})));
        let t = Canned::new(&[(200, "{}")]);
        assert_eq!(check_alias(&t, &c).unwrap(), None);
        assert_eq!(
            t.sent.borrow()[0].url,
            "https://api.forwardemail.net/v1/domains/mydomain.com"
        );
    }

    #[test]
    fn checks_make_no_alias() {
        let expected = [
            (
                AliasService::SimpleLogin,
                "https://app.simplelogin.io/api/user_info",
            ),
            (
                AliasService::AddyIo,
                "https://app.addy.io/api/v1/account-details",
            ),
            (
                AliasService::FirefoxRelay,
                "https://relay.firefox.com/api/v1/profiles/",
            ),
        ];
        for (service, url) in expected {
            let t = Canned::new(&[(200, "{}")]);
            assert_eq!(check_alias(&t, &config(service)).unwrap(), None);
            let r = &t.sent.borrow()[0];
            assert_eq!((r.method, r.url.as_str()), ("GET", url));
        }
        let t = Canned::new(&[(
            200,
            r#"{"primaryAccounts":{"https://www.fastmail.com/dev/maskedemail":"u1"}}"#,
        )]);
        assert_eq!(
            check_alias(&t, &config(AliasService::Fastmail)).unwrap(),
            None
        );
        assert_eq!(t.sent.borrow().len(), 1);
    }

    #[test]
    fn errors() {
        let c = config(AliasService::SimpleLogin);
        let err = |status: u16, body: &str| {
            create_alias(&Canned::new(&[(status, body)]), &c, None).unwrap_err()
        };
        assert!(
            matches!(err(401, r#"{"error":"Wrong api key"}"#), PassError::InvalidInput(m) if m.contains("API token"))
        );
        assert!(matches!(err(403, ""), PassError::InvalidInput(m) if m.contains("API token")));
        assert!(matches!(err(429, ""), PassError::Network(m) if m.contains("too many")));
        // The service's own words and status codes are not shown: the core's plain text is.
        assert!(
            matches!(err(400, r#"{"error":"You have reached the limit"}"#), PassError::InvalidInput(m) if m.contains("didn't make the alias") && !m.contains("reached the limit"))
        );
        assert!(
            matches!(err(400, r#"{"note":["Too long."]}"#), PassError::InvalidInput(m) if !m.contains("Too long."))
        );
        assert!(
            matches!(err(502, "<html>"), PassError::Network(m) if !m.contains("502") && !m.contains("<html>") && m.contains("Try again later"))
        );
        assert!(matches!(err(201, "not json"), PassError::Network(_)));
        assert!(matches!(
            err(201, r#"{"alias":"no at sign"}"#),
            PassError::Network(_)
        ));
        // No answer at all.
        assert!(matches!(
            create_alias(&Canned::new(&[]), &c, None),
            Err(PassError::Network(_))
        ));
        // The token is in no error.
        for e in [err(401, ""), err(500, ""), err(400, r#"{"error":"x"}"#)] {
            assert!(!e.to_string().contains("tok-123"));
        }
    }

    #[test]
    fn config_validation() {
        let mut c = config(AliasService::SimpleLogin);
        c.token = "  ".into();
        assert!(c.normalized().is_err());
        c.token = "a b".into();
        assert!(c.normalized().is_err());
        c.token = "tok".into();
        for bad in [
            "http://sl.example.org",
            "https://u:p@x.org",
            "https://x.org/?a=1",
            "nope",
        ] {
            c.base_url = bad.into();
            assert!(c.normalized().is_err(), "{bad}");
        }
        c.base_url = "https://sl.example.org/prefix/".into();
        assert_eq!(
            c.normalized().unwrap().base_url,
            "https://sl.example.org/prefix"
        );
        // A base URL and a domain only where the service uses them.
        let mut ddg = config(AliasService::DuckDuckGo);
        ddg.base_url = "https://evil.example".into();
        ddg.domain = "x.com".into();
        let n = ddg.normalized().unwrap();
        assert_eq!(
            (n.base_url.as_str(), n.domain.as_str(), n.token.as_str()),
            ("", "", "tok-123")
        );
        assert!(!format!("{n:?}").contains("tok-123"));
        assert_eq!(AliasService::from_id("addy_io"), Some(AliasService::AddyIo));
        for s in AliasService::ALL {
            assert_eq!(AliasService::from_id(s.id()), Some(s));
            assert!(s.default_base_url().starts_with("https://"));
        }
    }
    fn vault(device: &str) -> std::sync::Arc<crate::Vault> {
        crate::Vault::create_with_kdf(
            "pw",
            device,
            crate::KdfParams {
                m_kib: 64,
                t: 1,
                p: 1,
                ..Default::default()
            },
        )
        .unwrap()
    }

    fn saved(service: AliasService, token: &str) -> AliasConfig {
        AliasConfig {
            service,
            token: token.into(),
            ..Default::default()
        }
    }

    #[test]
    fn tokens_are_kept_encrypted_in_the_vault() {
        let v = vault("laptop");
        assert!(v.alias_configs().is_empty());
        assert_eq!(v.alias_default_service(), None);
        v.set_alias_config(saved(AliasService::SimpleLogin, "sl-secret-token"))
            .unwrap();
        v.set_email_generator_settings(EmailGeneratorSettings {
            address: " alex@example.com ".into(),
            domain: "MyDomain.com".into(),
        })
        .unwrap();
        assert!(v.is_dirty());
        let file = v.serialize().unwrap();
        let text = String::from_utf8_lossy(&file);
        for secret in [
            "sl-secret-token",
            "alex@example.com",
            "mydomain.com",
            "simplelogin",
        ] {
            assert!(!text.contains(secret), "{secret} in the vault file");
        }
        let again = crate::Vault::unlock(file, "pw".into(), "laptop".into()).unwrap();
        assert_eq!(
            again.alias_config(AliasService::SimpleLogin).unwrap().token,
            "sl-secret-token"
        );
        assert_eq!(
            again.alias_default_service(),
            Some(AliasService::SimpleLogin)
        );
        assert_eq!(
            again.email_generator_settings(),
            EmailGeneratorSettings {
                address: "alex@example.com".into(),
                domain: "mydomain.com".into()
            }
        );
        // Settings don't count as items.
        assert_eq!(again.item_count(), 0);
        assert!(again.items().is_empty());
        // Bad input is refused and changes nothing.
        assert!(again
            .set_alias_config(saved(AliasService::DuckDuckGo, " "))
            .is_err());
        assert!(again
            .set_email_generator_settings(EmailGeneratorSettings {
                address: "nope".into(),
                ..Default::default()
            })
            .is_err());
        assert_eq!(again.alias_configs().len(), 1);
        assert!(again
            .set_alias_default_service(Some(AliasService::Fastmail))
            .is_err());
    }

    #[test]
    fn default_service_follows_removals() {
        let v = vault("laptop");
        v.set_alias_config(saved(AliasService::DuckDuckGo, "a"))
            .unwrap();
        v.set_alias_config(saved(AliasService::AddyIo, "b"))
            .unwrap();
        assert_eq!(v.alias_default_service(), Some(AliasService::DuckDuckGo));
        v.set_alias_default_service(Some(AliasService::AddyIo))
            .unwrap();
        assert_eq!(v.alias_default_service(), Some(AliasService::AddyIo));
        v.remove_alias_config(AliasService::AddyIo).unwrap();
        assert_eq!(v.alias_default_service(), Some(AliasService::DuckDuckGo));
        assert_eq!(
            v.alias_configs()
                .iter()
                .map(|c| c.service)
                .collect::<Vec<_>>(),
            vec![AliasService::DuckDuckGo]
        );
        v.remove_alias_config(AliasService::DuckDuckGo).unwrap();
        assert_eq!(v.alias_default_service(), None);
        assert!(v.alias_configs().is_empty());
    }

    #[test]
    fn settings_sync_per_key() {
        let laptop = vault("laptop");
        let synced = laptop.serialize().unwrap();
        let phone = crate::Vault::unlock(synced, "pw".into(), "phone".into()).unwrap();
        laptop
            .set_alias_config(saved(AliasService::SimpleLogin, "sl"))
            .unwrap();
        phone
            .set_alias_config(saved(AliasService::DuckDuckGo, "ddg"))
            .unwrap();
        phone
            .set_email_generator_settings(EmailGeneratorSettings {
                address: "alex@example.com".into(),
                ..Default::default()
            })
            .unwrap();

        laptop.merge_remote(phone.serialize().unwrap()).unwrap();
        phone.merge_remote(laptop.serialize().unwrap()).unwrap();
        for v in [&laptop, &phone] {
            assert_eq!(v.alias_configs().len(), 2);
            assert_eq!(v.email_generator_settings().address, "alex@example.com");
        }
        assert_eq!(
            laptop.lock_fingerprint_for_tests(),
            phone.lock_fingerprint_for_tests()
        );

        // A removal syncs too, and merging again changes nothing.
        phone
            .remove_alias_config(AliasService::SimpleLogin)
            .unwrap();
        laptop.merge_remote(phone.serialize().unwrap()).unwrap();
        assert!(laptop.alias_config(AliasService::SimpleLogin).is_none());
        let before = laptop.lock_fingerprint_for_tests();
        laptop.merge_remote(phone.serialize().unwrap()).unwrap();
        assert_eq!(laptop.lock_fingerprint_for_tests(), before);
        assert_eq!(phone.lock_fingerprint_for_tests(), before);
    }

    #[test]
    fn settings_survive_older_clients_and_key_rotation() {
        let laptop = vault("laptop");
        laptop
            .set_alias_config(saved(AliasService::Fastmail, "fm"))
            .unwrap();
        // An older client writes the file without the settings blob.
        let mut old: Value = serde_json::from_slice(&laptop.serialize().unwrap()).unwrap();
        assert!(old.get("settings").is_some());
        old.as_object_mut().unwrap().remove("settings");
        let old = serde_json::to_vec(&old).unwrap();
        laptop.merge_remote(old.clone()).unwrap();
        assert_eq!(
            laptop.alias_config(AliasService::Fastmail).unwrap().token,
            "fm"
        );
        #[cfg(feature = "webdav")]
        assert!(laptop.remote_is_behind(&crate::vault::parse_file(&old).unwrap()));
        // That copy opens and has no settings.
        let older = crate::Vault::unlock(old, "pw".into(), "phone".into()).unwrap();
        assert!(older.alias_configs().is_empty());

        laptop
            .change_password("pw".into(), "new".into())
            .unwrap();
        let rotated =
            crate::Vault::unlock(laptop.serialize().unwrap(), "new".into(), "laptop".into())
                .unwrap();
        assert_eq!(
            rotated.alias_config(AliasService::Fastmail).unwrap().token,
            "fm"
        );
        // A tampered blob is ignored, not fatal.
        let mut bad: Value = serde_json::from_slice(&laptop.serialize().unwrap()).unwrap();
        bad["settings"]["updated_at"] = json!(1);
        let opened =
            crate::Vault::unlock(serde_json::to_vec(&bad).unwrap(), "new".into(), "x".into())
                .unwrap();
        assert!(opened.alias_configs().is_empty());
    }
}
