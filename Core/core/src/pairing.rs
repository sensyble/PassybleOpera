//! `pass+server://` pairing and sign-in links.
//!
//! ```text
//! pairing: pass+server://<host>[:<port>]<path>?v=1&user=<user>&token=<token>[&name=<device>][&pin=sha256:<b64url>]...[&scheme=http]
//! sign-in: pass+server://<host>[:<port>][<base path>]/?v=1&user=<user>[&pin=...]...[&scheme=http]
//! ```

use percent_encoding::percent_decode_str;

use crate::i18n::tr;
use crate::{PassError, Result};

const PREFIX: &str = "pass+server://";
const VERSION: &str = "1";

/// A parsed pairing link. `token` is a secret (the device's password on the server).
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PairingLink {
    /// The vault file's WebDAV URL, e.g. `https://pass.example.com:8443/dav/alice/personal.vault`.
    pub url: String,
    /// `host`, `host:port`, `[v6]` or `[v6]:port`, exactly as in the link (for display).
    pub host: String,
    /// The account (HTTP Basic user name).
    pub username: String,
    /// The device token (HTTP Basic password), `pst_…`.
    pub token: String,
    /// The device name registered on the server (display only).
    pub device_name: Option<String>,
    /// Certificate pins (`sha256:…`). Empty: the server has a publicly trusted certificate.
    pub pins: Vec<String>,
    /// `false` for `scheme=http` (loopback / private networks only; warn the user).
    pub https: bool,
}

impl std::fmt::Debug for PairingLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingLink")
            .field("url", &self.url)
            .field("username", &self.username)
            .field("device_name", &self.device_name)
            .field("pins", &self.pins)
            .finish_non_exhaustive()
    }
}

impl PairingLink {
    /// The sync settings this link stands for.
    #[cfg(feature = "webdav")]
    pub fn webdav_config(&self) -> crate::WebDavConfig {
        crate::WebDavConfig {
            url: self.url.clone(),
            username: self.username.clone(),
            password: self.token.clone(),
            pins: self.pins.clone(),
        }
    }
}

fn invalid(msg: impl Into<String>) -> PassError {
    PassError::InvalidInput(msg.into())
}

/// Parses a `pass+server://` pairing link (with a device token). A sign-in link is rejected; use
/// [`parse_server_link`] to accept both kinds.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn parse_pairing_link(link: &str) -> Result<PairingLink> {
    let parsed = parse_server_link(link)?;
    parsed
        .pairing
        .ok_or_else(|| invalid(tr!("pairing.sign_in_link")))
}

/// Either kind of `pass+server://` link: a pairing link (`token=`, `pairing` is set) or a sign-in
/// link (no token: only the server, account and pins).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ServerLink {
    /// The server's base URL for the account API, e.g. `https://pass.example.com:8443` (with any
    /// reverse-proxy prefix). For a pairing link it is the vault path before `/dav/`.
    pub server_url: String,
    /// `host[:port]` for display.
    pub host: String,
    pub username: String,
    pub pins: Vec<String>,
    /// `false` for `scheme=http`: warn.
    pub https: bool,
    /// Set for pairing links.
    pub pairing: Option<PairingLink>,
    /// A one-time code from `invite=<code>` or `reset=<code>` that sets the account password without
    /// the old one. `code_kind` is `invite` or `reset`.
    pub code: Option<String>,
    pub code_kind: Option<String>,
}

/// Parses a pairing or sign-in link. Errors are `InvalidInput` with a user-facing message.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn parse_server_link(link: &str) -> Result<ServerLink> {
    let rest = link
        .strip_prefix(PREFIX)
        .ok_or_else(|| invalid(tr!("pairing.not_a_link")))?;
    let (before_query, query) = rest.split_once('?').unwrap_or((rest, ""));
    let before_query = before_query.split('#').next().unwrap_or_default();
    let query = query.split('#').next().unwrap_or_default();
    let (authority, path) = match before_query.find('/') {
        Some(slash) => before_query.split_at(slash),
        None => (before_query, ""),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(invalid(tr!("pairing.invalid_host")));
    }
    let mut version = None;
    let mut user = None;
    let mut token = None;
    let mut name = None;
    let mut pins = Vec::new();
    let mut https = true;
    let mut codes: Vec<(String, String)> = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = percent_decode_str(v)
            .decode_utf8()
            .map_err(|_| invalid(tr!("pairing.invalid_encoding")))?
            .into_owned();
        match k {
            "v" => version = Some(v),
            "user" => user = Some(v),
            "token" => token = Some(v),
            "name" => name = Some(v),
            "pin" => pins.push(v),
            "invite" | "reset" => codes.push((k.to_string(), v)),
            "scheme" => match v.as_str() {
                "https" => https = true,
                "http" => https = false,
                _ => return Err(invalid(tr!("pairing.unsupported_scheme"))),
            },
            _ => {} // Unknown parameters are ignored.
        }
    }
    match version.as_deref() {
        Some(VERSION) => {}
        Some(_) => return Err(invalid(tr!("pairing.unsupported_version"))),
        None => return Err(invalid(tr!("pairing.no_version"))),
    }
    for pin in &pins {
        if !pin.starts_with("sha256:") {
            return Err(invalid(tr!("pairing.unsupported_pin")));
        }
    }
    let username = user
        .filter(|u| !u.is_empty())
        .ok_or_else(|| invalid(tr!("pairing.missing_user")))?;
    let scheme = if https { "https" } else { "http" };
    match token {
        Some(token) => {
            if token.is_empty() {
                return Err(invalid(tr!("pairing.missing_token")));
            }
            if !codes.is_empty() {
                return Err(invalid(tr!("pairing.token_and_code")));
            }
            if path.len() < 2 {
                return Err(invalid(tr!("pairing.no_vault_path")));
            }
            let base_path = path.rfind("/dav/").map_or("", |i| &path[..i]);
            Ok(ServerLink {
                server_url: format!("{scheme}://{authority}{base_path}"),
                host: authority.to_string(),
                username: username.clone(),
                pins: pins.clone(),
                https,
                pairing: Some(PairingLink {
                    url: format!("{scheme}://{authority}{path}"),
                    host: authority.to_string(),
                    username,
                    token,
                    device_name: name,
                    pins,
                    https,
                }),
                code: None,
                code_kind: None,
            })
        }
        None => {
            if codes.len() > 1 || codes.iter().any(|(_, c)| c.is_empty()) {
                return Err(invalid(tr!("pairing.one_code")));
            }
            let code = codes.pop();
            Ok(ServerLink {
                server_url: format!("{scheme}://{authority}{}", path.trim_end_matches('/')),
                host: authority.to_string(),
                username,
                pins,
                https,
                pairing: None,
                code_kind: code.as_ref().map(|(k, _)| k.clone()),
                code: code.map(|(_, c)| c),
            })
        }
    }
}

/// [`PairingLink::webdav_config`] for Kotlin: the `WebDavConfig` to store and sync with.
#[cfg(feature = "webdav")]
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn pairing_webdav_config(link: PairingLink) -> crate::WebDavConfig {
    link.webdav_config()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_from_the_spec() {
        let link = parse_pairing_link(
            "pass+server://pass.example.com:8443/dav/alice/personal.vault?v=1&user=alice&token=pst_kr3RuvCRcaQ29nq0oGvtM8RWx1_YAaPvx1qy-J047Hw&name=Pixel%209&pin=sha256:novcWsacBi2IRLwBIN7QCQVpLOAGPBXRFHKFijjSE-g",
        )
        .unwrap();
        assert_eq!(
            link.url,
            "https://pass.example.com:8443/dav/alice/personal.vault"
        );
        assert_eq!(link.host, "pass.example.com:8443");
        assert_eq!(link.username, "alice");
        assert_eq!(link.device_name.as_deref(), Some("Pixel 9"));
        assert_eq!(
            link.pins,
            ["sha256:novcWsacBi2IRLwBIN7QCQVpLOAGPBXRFHKFijjSE-g"]
        );
        assert!(link.https);
        assert!(!format!("{link:?}").contains("pst_"));
    }

    #[test]
    fn sign_in_links() {
        let link = parse_server_link(
            "pass+server://pass.example.com:8443/?v=1&user=alice&pin=sha256:novcWsacBi2IRLwBIN7QCQVpLOAGPBXRFHKFijjSE-g",
        )
        .unwrap();
        assert_eq!(link.server_url, "https://pass.example.com:8443");
        assert!(link.pairing.is_none());
        assert_eq!(link.username, "alice");
        let err = parse_pairing_link("pass+server://h/?v=1&user=a").unwrap_err();
        assert!(err
            .to_string()
            .contains("sign in with your Passyble Server password"));
        let paired =
            parse_server_link("pass+server://h:1/pass/dav/a/p.vault?v=1&user=a&token=pst_t")
                .unwrap();
        assert_eq!(paired.server_url, "https://h:1/pass");
        assert_eq!(
            paired.pairing.unwrap().url,
            "https://h:1/pass/dav/a/p.vault"
        );
        let coded = parse_server_link("pass+server://h/?v=1&user=a&invite=psc_x").unwrap();
        assert_eq!(coded.code.as_deref(), Some("psc_x"));
        assert_eq!(coded.code_kind.as_deref(), Some("invite"));
    }

    #[test]
    fn errors_are_invalid_input() {
        for bad in [
            "https://x/y?v=1&user=a&token=b",
            "pass+server://x/y?v=2&user=a&token=b",
            "pass+server://x/y?v=1&user=a&token=%FF",
        ] {
            assert!(matches!(
                parse_pairing_link(bad),
                Err(PassError::InvalidInput(_))
            ));
        }
    }
}
