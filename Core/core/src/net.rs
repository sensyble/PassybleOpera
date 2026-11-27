//! Network failures in plain words for the user: what went wrong and what to do, never the
//! library's or the server's own text. Unreachable servers use the `pinning.cant_connect` text.

use std::error::Error as StdError;

use rustls::CertificateError;

use crate::i18n::tr;
use crate::PassError;

/// Why a request got no HTTP answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The certificate is from no authority this device trusts (a self-signed Passyble Server
    /// reached without a pin).
    Untrusted,
    /// The certificate has expired or isn't valid yet (or this device's clock is wrong).
    Dates,
    /// The certificate is for another name.
    WrongName,
    /// Another certificate problem (revoked, damaged, unsupported).
    Certificate,
    /// The secure connection failed for another reason (not a TLS server, a protocol error).
    Secure,
    /// No connection: the name doesn't resolve, the connection was refused, timed out or reset.
    Unreachable,
    /// The address can't be used (bad URL, unknown scheme).
    BadAddress,
    /// The server answered something that isn't HTTP as expected (bad status line or header,
    /// redirect loop).
    Unexpected,
}

/// The TLS error inside `err`'s chain of sources, if any (rustls' errors come wrapped in an
/// `io::Error`).
fn tls_error<'a>(err: &'a (dyn StdError + 'static)) -> Option<&'a rustls::Error> {
    let mut current: Option<&'a (dyn StdError + 'static)> = Some(err);
    while let Some(e) = current {
        if let Some(tls) = e.downcast_ref::<rustls::Error>() {
            return Some(tls);
        }
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            if let Some(tls) = io
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<rustls::Error>())
            {
                return Some(tls);
            }
        }
        current = e.source();
    }
    None
}

fn tls_failure(e: &rustls::Error) -> Failure {
    match e {
        rustls::Error::InvalidCertificate(c) => match c {
            CertificateError::UnknownIssuer => Failure::Untrusted,
            CertificateError::Expired
            | CertificateError::ExpiredContext { .. }
            | CertificateError::NotValidYet
            | CertificateError::NotValidYetContext { .. } => Failure::Dates,
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                Failure::WrongName
            }
            _ => Failure::Certificate,
        },
        _ => Failure::Secure,
    }
}

/// What kind of failure `t` is.
pub(crate) fn classify(t: &ureq::Transport) -> Failure {
    if let Some(tls) = tls_error(t) {
        return tls_failure(tls);
    }
    use ureq::ErrorKind as K;
    match t.kind() {
        K::InvalidUrl | K::UnknownScheme | K::InsecureRequestHttpsOnly | K::InvalidProxyUrl => {
            Failure::BadAddress
        }
        K::TooManyRedirects | K::BadStatus | K::BadHeader | K::HTTP => Failure::Unexpected,
        K::Dns | K::ConnectionFailed | K::Io | K::ProxyConnect | K::ProxyUnauthorized => {
            Failure::Unreachable
        }
    }
}

/// `host` or `host:port` (a port other than the scheme's default) of a URL.
fn host_of(url: &url::Url) -> Option<String> {
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

/// The host to name in a message: the failed request's, else the one of `url`, else `url` itself.
fn host_for(t: &ureq::Transport, url: &str) -> String {
    t.url()
        .and_then(host_of)
        .or_else(|| url::Url::parse(url).ok().as_ref().and_then(host_of))
        .unwrap_or_else(|| url.to_string())
}

/// `{action}: ` + `message`, the shape of the core's network errors.
fn with_action(action: &str, message: String) -> String {
    format!("{action}: {message}")
}

/// A request to `url` that got no HTTP answer, as `Network`. `unexpected` words a server that
/// answered something else than expected.
pub(crate) fn transport_error(
    action: &str,
    t: &ureq::Transport,
    url: &str,
    unexpected: impl FnOnce() -> String,
) -> PassError {
    PassError::Network(match classify(t) {
        Failure::Untrusted => tr!("net.untrusted_certificate", action = action),
        Failure::Dates => tr!("net.certificate_dates", action = action),
        Failure::WrongName => tr!("net.certificate_name", action = action),
        Failure::Certificate => tr!("net.certificate_invalid", action = action),
        Failure::Secure => tr!(
            "net.secure_connection",
            action = action,
            host = host_for(t, url)
        ),
        Failure::Unreachable => {
            with_action(action, tr!("pinning.cant_connect", host = host_for(t, url)))
        }
        Failure::BadAddress => with_action(action, tr!("server.invalid_address")),
        Failure::Unexpected => unexpected(),
    })
}

/// An HTTP error status the caller has no better words for, as `Network` (`{action}: …`): never
/// the status code or the answer's body.
pub(crate) fn status_error(action: &str, code: u16) -> PassError {
    PassError::Network(match code {
        404 | 410 => tr!("net.not_found", action = action),
        413 => tr!("net.too_large", action = action),
        408 | 429 => tr!("net.busy", action = action),
        500..=599 => tr!("net.server_error", action = action),
        _ => tr!("net.refused", action = action),
    })
}

/// An error while reading an answer's body, as `Network`.
pub(crate) fn read_error(
    action: &str,
    e: &std::io::Error,
    unexpected: impl FnOnce() -> String,
) -> PassError {
    PassError::Network(match e.kind() {
        std::io::ErrorKind::InvalidData => unexpected(),
        _ => tr!("net.connection_lost", action = action),
    })
}

/// The generic text for an answer the core can't read.
pub(crate) fn unexpected_answer(action: &str) -> String {
    tr!("net.unexpected_answer", action = action)
}

/// Whether a server's error text can be shown as it is: a short line of plain text (Passyble
/// Server's messages), not an error page, JSON or a long dump.
pub(crate) fn plain_message(text: &str) -> Option<String> {
    let text = text.trim();
    let plain = !text.is_empty()
        && text.chars().count() <= 300
        && !text.starts_with(['<', '{', '['])
        && !text.chars().any(|c| c.is_control() && c != '\t');
    plain.then(|| text.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(e: PassError) -> String {
        match e {
            PassError::Network(m) => m,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn statuses_are_words_not_codes() {
        for code in [
            400, 403, 404, 405, 408, 410, 413, 418, 429, 500, 502, 503, 599,
        ] {
            let m = message(status_error("upload", code));
            assert!(m.starts_with("upload: "), "{m}");
            assert!(!m.contains(&code.to_string()), "{code}: {m}");
            assert!(!m.contains("HTTP"), "{code}: {m}");
        }
        assert!(message(status_error("sync", 500)).contains("Try again later"));
    }

    #[test]
    fn unreachable_servers_name_the_host() {
        // Nothing listens on port 9 of localhost (discard): the connection is refused.
        let err = ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(5))
            .build()
            .get("http://127.0.0.1:9/x")
            .call()
            .unwrap_err();
        let ureq::Error::Transport(t) = err else {
            panic!("{err:?}")
        };
        assert_eq!(classify(&t), Failure::Unreachable);
        let m = message(transport_error(
            "sign-in",
            &t,
            "http://127.0.0.1:9",
            String::new,
        ));
        assert!(
            crate::core_message_is(m.clone(), "pinning.cant_connect".into()),
            "{m}"
        );
        assert_eq!(
            crate::core_message_arg(m.clone(), "pinning.cant_connect".into(), "host".into())
                .as_deref(),
            Some("127.0.0.1:9"),
            "{m}"
        );
        assert!(!m.to_ascii_lowercase().contains("os error"), "{m}");
    }

    #[test]
    fn certificate_errors_are_told_apart() {
        let wrap = |c: CertificateError| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                rustls::Error::InvalidCertificate(c),
            )
        };
        let of = |e: &std::io::Error| tls_error(e).map(tls_failure);
        assert_eq!(
            of(&wrap(CertificateError::UnknownIssuer)),
            Some(Failure::Untrusted)
        );
        assert_eq!(of(&wrap(CertificateError::Expired)), Some(Failure::Dates));
        assert_eq!(
            of(&wrap(CertificateError::NotValidForName)),
            Some(Failure::WrongName)
        );
        assert_eq!(
            of(&wrap(CertificateError::Revoked)),
            Some(Failure::Certificate)
        );
        assert_eq!(of(&std::io::Error::other("reset")), None);
    }

    #[test]
    fn only_plain_server_texts_are_shown() {
        assert_eq!(
            plain_message(" sign-up is closed \n").as_deref(),
            Some("sign-up is closed")
        );
        assert_eq!(
            plain_message("<html><body>502 Bad Gateway</body></html>"),
            None
        );
        assert_eq!(plain_message("{\"error\":\"x\"}"), None);
        assert_eq!(plain_message("line one\nline two"), None);
        assert_eq!(plain_message(&"x".repeat(301)), None);
        assert_eq!(plain_message("  "), None);
    }
}
