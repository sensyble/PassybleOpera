//! Passphrase-encrypted OpenPGP messages (Proton Pass' `data.pgp`, or a `.pgp` / `.asc` export),
//! decrypted with rPGP (feature `import-pgp`). Only integrity-protected SKESK messages are accepted,
//! and an Argon2 S2K is bounded here before rPGP derives anything.

use zeroize::Zeroizing;

use crate::Result;

/// Whether `data` starts like a binary OpenPGP message encrypted with a passphrase (a
/// symmetric-key encrypted session key packet, tag 3, version 4, 5 or 6).
pub(crate) fn is_binary(data: &[u8]) -> bool {
    let Some(&first) = data.first() else {
        return false;
    };
    // New packet format with a one-octet length, or old format (tag 3) with a one- or
    // two-octet length.
    let body = match first {
        0xC3 if data.get(1).is_some_and(|&l| l < 192) => 2,
        0x8C => 2,
        0x8D => 3,
        _ => return false,
    };
    match data.get(body) {
        // v4: version, symmetric algorithm (1..=13), S2K type (0, 1, 3 or 4).
        Some(4) => {
            data.get(body + 1).is_some_and(|a| (1..=13).contains(a))
                && data
                    .get(body + 2)
                    .is_some_and(|t| matches!(t, 0 | 1 | 3 | 4))
        }
        Some(5) | Some(6) => data.get(body + 1).is_some(),
        _ => false,
    }
}

#[cfg(feature = "import-pgp")]
mod imp {
    use std::io::Read;

    use pgp::composed::{Esk, Message};
    use pgp::types::{Password, StringToKey};
    use zeroize::Zeroizing;

    use super::super::encrypted::{damaged, too_heavy, Kind};
    use super::super::{invalid, MAX_IMPORT_BYTES};
    use crate::i18n::tr;
    use crate::{PassError, Result};

    /// Most Argon2 S2K memory accepted: 2^20 KiB (1 GiB).
    const MAX_ARGON2_M_ENC: u8 = 20;

    fn check_s2k(s2k: &StringToKey) -> Result<()> {
        if let StringToKey::Argon2 { t, p, m_enc, .. } = s2k {
            let work = (1u64 << (*m_enc).min(40)).saturating_mul(u64::from(*t));
            if *m_enc > MAX_ARGON2_M_ENC
                || *t > 32
                || *p > 32
                || work > super::super::encrypted::MAX_ARGON2_WORK
            {
                return Err(too_heavy(Kind::Pgp));
            }
        }
        Ok(())
    }

    pub(crate) fn decrypt(data: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>> {
        let unreadable = |_: pgp::errors::Error| invalid(tr!("import.pgp_unreadable"));
        let trimmed = data.trim_ascii_start();
        let message = if trimmed.starts_with(b"-----BEGIN PGP") {
            Message::from_armor(trimmed)
                .map(|(m, _)| m)
                .map_err(unreadable)?
        } else {
            Message::from_bytes(data).map_err(unreadable)?
        };
        let Message::Encrypted { esk, .. } = &message else {
            return Err(invalid(tr!("import.pgp_not_encrypted")));
        };
        let mut symmetric = 0;
        for e in esk {
            if let Esk::SymKeyEncryptedSessionKey(skesk) = e {
                symmetric += 1;
                if let Some(s2k) = skesk.s2k() {
                    check_s2k(s2k)?;
                }
            }
        }
        if symmetric == 0 {
            return Err(invalid(tr!("import.pgp_not_password")));
        }
        let password = Password::from(password);
        let message = message
            .decrypt_with_password(&password)
            .map_err(|_| PassError::InvalidPassword)?;
        let mut message = if message.is_compressed() {
            message.decompress().map_err(|_| damaged(Kind::Pgp))?
        } else {
            message
        };
        let mut out = Zeroizing::new(Vec::new());
        // Never more than the import limit, whatever a compressed packet expands to. A wrong
        // password that slipped past the 2-byte quick check fails here (MDC / AEAD tag).
        (&mut message)
            .take(MAX_IMPORT_BYTES as u64 + 1)
            .read_to_end(&mut out)
            .map_err(|_| PassError::InvalidPassword)?;
        if out.len() > MAX_IMPORT_BYTES {
            return Err(invalid(tr!(
                "import.too_large",
                megabytes = MAX_IMPORT_BYTES / (1024 * 1024)
            )));
        }
        Ok(out)
    }
}

/// Decrypts a passphrase-encrypted OpenPGP message (armored or binary): its literal data.
/// `InvalidPassword` for a wrong passphrase.
#[cfg(feature = "import-pgp")]
pub(crate) fn decrypt(data: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>> {
    imp::decrypt(data, password)
}

#[cfg(not(feature = "import-pgp"))]
pub(crate) fn decrypt(_data: &[u8], _password: &str) -> Result<Zeroizing<Vec<u8>>> {
    Err(super::invalid(crate::i18n::tr!("import.encrypted_pgp")))
}
