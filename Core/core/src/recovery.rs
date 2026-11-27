//! Recovery codes: a random secret that unlocks the vault when the master password is forgotten.
//!
//! 128 random bits plus a 22-bit checksum (the first bits of `SHA-256("pass/recovery-code/v1:" + secret)`),
//! written as 30 Crockford base32 characters in six groups, so a typo is caught before any Argon2 run.
//! Reading ignores case, spaces and dashes, and maps `O`, `I`, `L` to `0`, `1`, `1`.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::random_bytes;
use crate::i18n::{tr, trn};
use crate::{PassError, Result};

/// Bytes of randomness in a recovery code.
pub(crate) const SECRET_LEN: usize = 16;
/// Checksum bits after the secret.
const CHECK_BITS: usize = 22;
/// Characters in a code (5 bits each): 128 + 22 = 150 bits.
const CODE_CHARS: usize = (SECRET_LEN * 8 + CHECK_BITS) / 5;
/// Characters per group in the written form.
const GROUP: usize = 5;
/// Crockford's base32 alphabet.
pub(crate) const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub(crate) type Secret = Zeroizing<[u8; SECRET_LEN]>;

/// The checksum domain of recovery codes. The Secret Key (`crate::account_key`) uses the same
/// format with a domain of its own, so neither can be taken for the other.
pub(crate) const RECOVERY_DOMAIN: &[u8] = b"pass/recovery-code/v1:";

/// The checksum of `secret` in `domain`, in the low [`CHECK_BITS`] bits.
fn checksum(domain: &[u8], secret: &[u8; SECRET_LEN]) -> u32 {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(secret);
    let d = h.finalize();
    (u32::from_be_bytes([0, d[0], d[1], d[2]])) >> (24 - CHECK_BITS)
}

/// The bit at `i` (most significant first) of `secret` followed by its checksum.
fn bit(secret: &[u8; SECRET_LEN], check: u32, i: usize) -> u8 {
    if i < SECRET_LEN * 8 {
        (secret[i / 8] >> (7 - i % 8)) & 1
    } else {
        ((check >> (CHECK_BITS - 1 - (i - SECRET_LEN * 8))) & 1) as u8
    }
}

/// The written form of `secret`: `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`.
pub(crate) fn encode(secret: &[u8; SECRET_LEN]) -> Zeroizing<String> {
    encode_in(RECOVERY_DOMAIN, secret)
}

/// [`encode`] with the checksum of another `domain`.
pub(crate) fn encode_in(domain: &[u8], secret: &[u8; SECRET_LEN]) -> Zeroizing<String> {
    let check = checksum(domain, secret);
    let mut out = Zeroizing::new(String::with_capacity(CODE_CHARS + CODE_CHARS / GROUP));
    for c in 0..CODE_CHARS {
        if c > 0 && c % GROUP == 0 {
            out.push('-');
        }
        let v = (0..5).fold(0usize, |v, b| {
            (v << 1) | bit(secret, check, c * 5 + b) as usize
        });
        out.push(ALPHABET[v] as char);
    }
    out
}

/// A new random secret and its written form.
pub(crate) fn generate() -> (Secret, Zeroizing<String>) {
    let secret = Zeroizing::new(random_bytes::<SECRET_LEN>());
    let code = encode(&secret);
    (secret, code)
}

/// The value of one character of a code, `None` for a character that can't be in one.
fn value(c: char) -> Option<u8> {
    let c = match c.to_ascii_uppercase() {
        'O' => '0',
        'I' | 'L' => '1',
        c => c,
    };
    ALPHABET
        .iter()
        .position(|&a| a as char == c)
        .map(|v| v as u8)
}

/// The secret of a written code. `InvalidInput` when it isn't one: a wrong length, a character
/// that can't be in a code, or a checksum that doesn't match (a typo).
pub(crate) fn decode(code: &str) -> Result<Secret> {
    decode_in(RECOVERY_DOMAIN, code)
}

/// [`decode`] with the checksum of another `domain`.
pub(crate) fn decode_in(domain: &[u8], code: &str) -> Result<Secret> {
    let mut values = Zeroizing::new(Vec::with_capacity(CODE_CHARS));
    for c in code.chars() {
        if c.is_whitespace() || c == '-' {
            continue;
        }
        let v = value(c)
            .ok_or_else(|| PassError::InvalidInput(tr!("recovery.bad_character", character = c)))?;
        values.push(v);
    }
    if values.len() != CODE_CHARS {
        return Err(PassError::InvalidInput(trn!(
            "recovery.wrong_length",
            values.len(),
            expected = CODE_CHARS
        )));
    }
    let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
    let mut check = 0u32;
    for (i, b) in values
        .iter()
        .flat_map(|v| (0..5).rev().map(move |s| (v >> s) & 1))
        .enumerate()
    {
        if i < SECRET_LEN * 8 {
            secret[i / 8] |= b << (7 - i % 8);
        } else {
            check = (check << 1) | u32::from(b);
        }
    }
    if check != checksum(domain, &secret) {
        return Err(PassError::InvalidInput(tr!("recovery.typo")));
    }
    Ok(secret)
}

/// Whether `code` is a well-formed recovery code (length, characters, checksum), without touching
/// any vault. It can still belong to another vault.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn recovery_code_valid_format(code: String) -> bool {
    decode(&code).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip_in_six_groups_of_five() {
        for _ in 0..50 {
            let (secret, code) = generate();
            assert_eq!(code.len(), 35, "{}", code.as_str());
            assert!(code.split('-').all(|g| g.len() == 5));
            assert_eq!(code.split('-').count(), 6);
            assert!(code
                .chars()
                .all(|c| c == '-' || ALPHABET.contains(&(c as u8))));
            assert_eq!(*decode(&code).unwrap(), *secret);
        }
    }

    #[test]
    fn reading_is_forgiving_about_case_spaces_and_lookalikes() {
        let secret = [0u8; SECRET_LEN];
        let code = encode(&secret);
        // All-zero secret: zeros, then the checksum.
        assert!(code.starts_with("00000-00000-00000-00000-00000-"));
        let sloppy = format!(
            " {} ",
            code.to_lowercase().replace('0', "o").replace('-', "  ")
        );
        assert_eq!(*decode(&sloppy).unwrap(), secret);
        let mut ones = [0u8; SECRET_LEN];
        ones[1] = 0b0100_0000; // bit 9: the second character (bits 5..=9) is 1
        let code = encode(&ones);
        assert!(code.starts_with("01"));
        assert_eq!(*decode(&code.replacen('1', "l", 1)).unwrap(), ones);
        assert_eq!(*decode(&code.replacen('1', "I", 1)).unwrap(), ones);
    }

    /// The checksum catches a random typo with probability 1 - 2^-22, so this checks fixed codes:
    /// every single wrong character and every swap of neighbours is caught.
    #[test]
    fn typos_are_caught() {
        let mut counting = [0u8; SECRET_LEN];
        for (i, b) in counting.iter_mut().enumerate() {
            *b = i as u8;
        }
        for secret in [counting, [0xA5; SECRET_LEN], [0xFF; SECRET_LEN]] {
            typos_of(&encode(&secret));
        }
    }

    fn typos_of(code: &str) {
        let chars: Vec<char> = code.chars().collect();
        let positions: Vec<usize> = (0..chars.len()).filter(|&i| chars[i] != '-').collect();
        // Every single-character substitution.
        for &i in &positions {
            for &a in ALPHABET.iter() {
                let a = a as char;
                if a == chars[i] {
                    continue;
                }
                let mut typo = chars.clone();
                typo[i] = a;
                let typo: String = typo.into_iter().collect();
                assert!(!recovery_code_valid_format(typo.clone()), "{typo}");
            }
        }
        // Every swap of two neighbouring different characters.
        for w in positions.windows(2) {
            if chars[w[0]] == chars[w[1]] {
                continue;
            }
            let mut typo = chars.clone();
            typo.swap(w[0], w[1]);
            let typo: String = typo.into_iter().collect();
            assert!(!recovery_code_valid_format(typo.clone()), "{typo}");
        }
        // A character too many or too few, and characters that are never in a code.
        assert!(matches!(
            decode(&format!("{code}0")),
            Err(PassError::InvalidInput(_))
        ));
        assert!(matches!(
            decode(&code[1..]),
            Err(PassError::InvalidInput(_))
        ));
        assert!(matches!(
            decode(&code.replacen(chars[0], "U", 1)),
            Err(PassError::InvalidInput(_))
        ));
        assert!(!recovery_code_valid_format(String::new()));
        assert!(recovery_code_valid_format(code.to_string()));
    }
}
