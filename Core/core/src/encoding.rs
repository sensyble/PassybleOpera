use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;

use crate::{PassError, Result};

/// Base64url without padding, the encoding WebAuthn uses for binary values.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn b64url_encode(data: Vec<u8>) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decodes base64url, tolerating padding and the standard alphabet.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn b64url_decode(s: String) -> Result<Vec<u8>> {
    let normalized: String = s
        .trim()
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .collect();
    URL_SAFE_NO_PAD
        .decode(normalized)
        .map_err(|_| PassError::InvalidInput(crate::i18n::tr!("encoding.damaged")))
}

pub(crate) fn b64_encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub(crate) fn b64_decode(s: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(s)
        .map_err(|_| PassError::Corrupt(crate::i18n::tr!("encoding.damaged")))
}

/// RFC 4648 base32 decoding as used by TOTP secrets: case-insensitive, ignores spaces,
/// dashes and padding.
pub(crate) fn base32_decode(input: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    let mut buffer: u64 = 0;
    let mut bits = 0u32;
    for c in input.chars() {
        let value = match c.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u64 - 'A' as u64,
            c @ '2'..='7' => c as u64 - '2' as u64 + 26,
            ' ' | '-' | '=' | '\t' | '\n' | '\r' => continue,
            other => {
                return Err(PassError::InvalidInput(crate::i18n::tr!(
                    "encoding.invalid_base32",
                    character = format!("{other:?}")
                )))
            }
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

/// RFC 4648 base32 without padding (TOTP secrets in `otpauth://` URIs).
pub(crate) fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Lowercase hex without separators.
pub(crate) fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_roundtrip() {
        let data = b"12345678901234567890";
        let encoded = base32_encode(data);
        assert_eq!(encoded, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(base32_decode(&encoded).unwrap(), data);
        assert_eq!(
            base32_decode("gezd gnbv-gy3t qojq gezd gnbv gy3t qojq").unwrap(),
            data
        );
        assert!(base32_decode("1189").is_err());
    }

    #[test]
    fn b64url_accepts_variants() {
        let data = vec![0xfb, 0xff, 0x00, 0x10];
        let enc = b64url_encode(data.clone());
        assert_eq!(enc, "-_8AEA");
        assert_eq!(b64url_decode(enc).unwrap(), data);
        assert_eq!(b64url_decode("+/8AEA==".into()).unwrap(), data);
    }
}
