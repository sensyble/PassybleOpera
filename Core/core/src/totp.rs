use hmac::{Hmac, Mac};
use url::Url;

use crate::encoding::base32_decode;
use crate::i18n::tr;
use crate::{PassError, Result};

macro_rules! hmac {
    ($digest:ty, $key:expr, $msg:expr) => {{
        let mut mac =
            <Hmac<$digest> as Mac>::new_from_slice($key).expect("HMAC accepts any key length");
        mac.update($msg);
        mac.finalize().into_bytes().to_vec()
    }};
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgorithm {
    /// Its name in an `otpauth://` link.
    pub fn uri_name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct TotpConfig {
    pub secret: Vec<u8>,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period: u32,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

impl std::fmt::Debug for TotpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpConfig")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct TotpCode {
    pub code: String,
    pub period: u32,
    pub remaining_secs: u32,
}

/// Parses an `otpauth://totp/...` URI or a bare base32 secret.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn totp_parse(input: String) -> Result<TotpConfig> {
    let input = input.trim();
    if input.is_empty() {
        return Err(PassError::InvalidInput(tr!("totp.empty_secret")));
    }
    // `get`, not slicing: byte 10 may fall inside a multi-byte character.
    let is_uri = input
        .get(..10)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("otpauth://"));
    let config = if is_uri {
        parse_uri(input)?
    } else {
        TotpConfig {
            secret: base32_decode(input)?,
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
            issuer: None,
            account: None,
        }
    };
    if config.secret.is_empty() {
        return Err(PassError::InvalidInput(tr!("totp.empty_secret")));
    }
    Ok(config)
}

/// Why an `otpauth://` link can't be read. The values are the link's own, untrusted input.
pub(crate) enum UriError {
    Invalid,
    Hotp,
    NotTotp,
    Secret,
    Algorithm(String),
    Digits(String),
    Period(String),
}

fn parse_uri(input: &str) -> Result<TotpConfig> {
    let url = Url::parse(input).map_err(|_| PassError::InvalidInput(tr!("totp.invalid_uri")))?;
    parse_url(&url).map_err(|e| {
        PassError::InvalidInput(match e {
            UriError::Invalid => tr!("totp.invalid_uri"),
            UriError::Hotp => tr!("totp.hotp_unsupported"),
            UriError::NotTotp => tr!("totp.not_totp"),
            // Not base32's message: the character it stopped at would be part of the secret.
            UriError::Secret => tr!("totp.link_bad_secret"),
            UriError::Algorithm(algorithm) => {
                tr!("totp.unsupported_algorithm", algorithm = algorithm)
            }
            UriError::Digits(digits) => tr!("totp.invalid_digits", digits = digits),
            UriError::Period(period) => tr!("totp.invalid_period", period = period),
        })
    })
}

/// Reads a parsed `otpauth://` link. The secret may be missing (empty).
pub(crate) fn parse_url(url: &Url) -> std::result::Result<TotpConfig, UriError> {
    match url.host_str().map(str::to_ascii_lowercase).as_deref() {
        Some("totp") => {}
        Some("hotp") => return Err(UriError::Hotp),
        Some(_) => return Err(UriError::NotTotp),
        None => return Err(UriError::Invalid),
    }
    let label = percent_decode(url.path().trim_start_matches('/'));
    let (label_issuer, account) = match label.split_once(':') {
        Some((issuer, account)) => (Some(issuer.trim().to_string()), account.trim().to_string()),
        None => (None, label.trim().to_string()),
    };
    let mut config = TotpConfig {
        secret: Vec::new(),
        algorithm: TotpAlgorithm::Sha1,
        digits: 6,
        period: 30,
        issuer: label_issuer.filter(|s| !s.is_empty()),
        account: Some(account).filter(|s| !s.is_empty()),
    };
    for (key, value) in url.query_pairs() {
        match key.to_ascii_lowercase().as_str() {
            "secret" => config.secret = base32_decode(&value).map_err(|_| UriError::Secret)?,
            "issuer" if !value.is_empty() => config.issuer = Some(value.into_owned()),
            "algorithm" => {
                config.algorithm = match value.to_ascii_uppercase().as_str() {
                    "SHA1" => TotpAlgorithm::Sha1,
                    "SHA256" => TotpAlgorithm::Sha256,
                    "SHA512" => TotpAlgorithm::Sha512,
                    other => return Err(UriError::Algorithm(other.to_string())),
                }
            }
            "digits" => {
                config.digits = value
                    .parse()
                    .ok()
                    .filter(|d| (6..=10).contains(d))
                    .ok_or_else(|| UriError::Digits(value.to_string()))?
            }
            "period" => {
                config.period = value
                    .parse()
                    .ok()
                    .filter(|p| (1..=3600).contains(p))
                    .ok_or_else(|| UriError::Period(value.to_string()))?
            }
            _ => {}
        }
    }
    Ok(config)
}

fn percent_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("x={}", s.replace('+', "%2B")).as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

/// Generates the code valid at `unix_secs`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn totp_generate(input: String, unix_secs: i64) -> Result<TotpCode> {
    let config = totp_parse(input)?;
    Ok(generate(&config, unix_secs))
}

pub(crate) fn generate(config: &TotpConfig, unix_secs: i64) -> TotpCode {
    let period = config.period.max(1) as i64;
    let t = unix_secs.max(0);
    let counter = (t / period) as u64;
    let msg = counter.to_be_bytes();
    let digest = match config.algorithm {
        TotpAlgorithm::Sha1 => hmac!(sha1::Sha1, &config.secret, &msg),
        TotpAlgorithm::Sha256 => hmac!(sha2::Sha256, &config.secret, &msg),
        TotpAlgorithm::Sha512 => hmac!(sha2::Sha512, &config.secret, &msg),
    };
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        digest[offset],
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]) & 0x7fff_ffff;
    let digits = config.digits.clamp(6, 10);
    let code = (binary as u64) % 10u64.pow(digits);
    TotpCode {
        code: format!("{code:0width$}", width = digits as usize),
        period: period as u32,
        remaining_secs: (period - t % period) as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::base32_encode;

    // RFC 6238 appendix B test vectors (8 digits).
    #[test]
    fn rfc6238_vectors() {
        let cases = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        let sha1 = base32_encode(b"12345678901234567890");
        let sha256 = base32_encode(b"12345678901234567890123456789012");
        let sha512 =
            base32_encode(b"1234567890123456789012345678901234567890123456789012345678901234");
        for (t, c1, c256, c512) in cases {
            let uri = |secret: &str, alg: &str| {
                format!("otpauth://totp/Test?secret={secret}&algorithm={alg}&digits=8")
            };
            assert_eq!(totp_generate(uri(&sha1, "SHA1"), t).unwrap().code, c1);
            assert_eq!(totp_generate(uri(&sha256, "SHA256"), t).unwrap().code, c256);
            assert_eq!(totp_generate(uri(&sha512, "SHA512"), t).unwrap().code, c512);
        }
    }

    #[test]
    fn parses_uri_labels_and_bare_secrets() {
        let c = totp_parse("otpauth://totp/ACME%20Co:john.doe%40email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&period=60".into()).unwrap();
        assert_eq!(c.issuer.as_deref(), Some("ACME Co"));
        assert_eq!(c.account.as_deref(), Some("john.doe@email.com"));
        assert_eq!(c.period, 60);
        assert_eq!(c.digits, 6);

        let bare = totp_parse("hxdm vjec jjws rb3h wizr 4ifu gftm xboz".into()).unwrap();
        assert_eq!(bare.secret, c.secret);
        let code = totp_generate("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".into(), 95).unwrap();
        assert_eq!(code.code.len(), 6);
        assert_eq!(code.remaining_secs, 25);

        assert!(totp_parse("otpauth://hotp/x?secret=AAAA&counter=1".into()).is_err());
        assert!(totp_parse("".into()).is_err());
    }

    #[test]
    fn multibyte_input_is_an_error_not_a_panic() {
        // Byte 10 falls inside "é": slicing there would panic.
        for input in ["abcdefghié123", "ééééééé", "otpauth:/é/totp/x?secret=AAAA"] {
            assert!(totp_parse(input.into()).is_err(), "{input}");
        }
        assert!(totp_parse("OTPAUTH://totp/x?secret=JBSWY3DPEHPK3PXP".into()).is_ok());
    }
}
