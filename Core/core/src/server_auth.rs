//! Client side of the Passyble Server account password derivation; it must match the server's.
//!
//! ```text
//! master   = Argon2id(password, salt, m_kib, t, p)                    (32 bytes)
//! auth_key = HKDF-SHA256(ikm = master, salt = none, info = "pass-server-auth")   (32 bytes)
//! ```
//!
//! Only `auth_key` is sent to the server. The vault has its own random salt, so neither value
//! unwraps the vault key.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto;
use crate::encoding::b64url_decode;
use crate::i18n::tr;
use crate::vault::KdfParams;
use crate::{PassError, Result};

pub(crate) const AUTH_INFO: &[u8] = b"pass-server-auth";

/// Argon2id parameters of a Passyble Server account password (no salt: it travels separately).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ServerKdf {
    pub alg: String,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for ServerKdf {
    fn default() -> Self {
        let d = KdfParams::default();
        Self {
            alg: d.alg,
            m_kib: d.m_kib,
            t: d.t,
            p: d.p,
        }
    }
}

/// The weakest parameters a server's prelogin may ask for: what Passyble clients and the server's
/// admin tool set ([`ServerKdf::default`], 64 MiB, 3 passes).
const OFFERED_MIN_M_KIB: u32 = 64 * 1024;
const OFFERED_MIN_T: u32 = 3;

impl ServerKdf {
    /// Same bounds as the server, for deriving `auth_key` (the shared vectors use them). The
    /// upper bound stops a server from making the device allocate gigabytes.
    pub(crate) fn check(&self) -> Result<()> {
        let ok = self.alg == "argon2id"
            && (19 * 1024..=1024 * 1024).contains(&self.m_kib)
            && (2..=20).contains(&self.t)
            && (1..=16).contains(&self.p);
        if ok {
            Ok(())
        } else {
            Err(PassError::Crypto(tr!("server.unsafe_parameters")))
        }
    }

    /// For the parameters a server's prelogin hands out: [`ServerKdf::check`] and nothing below
    /// 64 MiB, 3 passes. A malicious server asking for cheaper parameters would get an `auth_key`
    /// that is cheaper to brute-force.
    pub(crate) fn check_offered(&self) -> Result<()> {
        self.check()?;
        if self.m_kib < OFFERED_MIN_M_KIB || self.t < OFFERED_MIN_T {
            return Err(PassError::Crypto(tr!("server.unsafe_parameters")));
        }
        Ok(())
    }
}

/// HKDF-SHA256 (RFC 5869) with an empty salt and one 32-byte output block.
pub(crate) fn hkdf_sha256(ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut extract = <Hmac<Sha256> as Mac>::new_from_slice(&[0u8; 32]).expect("any key length");
    extract.update(ikm);
    // A plain array: zeroizing a GenericArray needs generic-array's `zeroize` feature, which not
    // every build of the core turns on (the browser extension's WebAssembly does not).
    let prk: Zeroizing<[u8; 32]> = Zeroizing::new(extract.finalize().into_bytes().into());
    let mut expand = <Hmac<Sha256> as Mac>::new_from_slice(&prk[..]).expect("any key length");
    expand.update(info);
    expand.update(&[1]);
    Zeroizing::new(expand.finalize().into_bytes().into())
}

/// `auth_key` for `password` with the account's salt (raw bytes) and parameters.
pub(crate) fn auth_key(
    password: &str,
    salt: &[u8],
    kdf: &ServerKdf,
) -> Result<Zeroizing<[u8; 32]>> {
    kdf.check()?;
    if password.is_empty() {
        return Err(PassError::InvalidInput(tr!("server.empty_password")));
    }
    let params = KdfParams {
        alg: kdf.alg.clone(),
        m_kib: kdf.m_kib,
        t: kdf.t,
        p: kdf.p,
        salt: String::new(),
    };
    let master = crypto::derive_kek(password, &params, salt)?;
    Ok(hkdf_sha256(master.as_slice(), AUTH_INFO))
}

/// The base64url `auth_key` a client sends for `password`, given the account's base64url `salt`
/// and KDF parameters.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn server_auth_key(password: String, salt: String, kdf: ServerKdf) -> Result<String> {
    let salt = b64url_decode(salt)?;
    if salt.len() < 16 || salt.len() > 64 {
        return Err(PassError::Crypto(tr!("server.invalid_salt")));
    }
    Ok(crate::b64url_encode(
        auth_key(&password, &salt, &kdf)?.to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_rfc5869_case_3() {
        let okm = hkdf_sha256(&[0x0b; 22], b"");
        assert_eq!(
            crate::encoding::hex(okm.as_slice()),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        );
    }

    #[test]
    fn rejects_weak_parameters() {
        let weak = ServerKdf {
            m_kib: 1024,
            ..Default::default()
        };
        assert!(matches!(
            server_auth_key("pw".into(), "AAAAAAAAAAAAAAAAAAAAAA".into(), weak),
            Err(PassError::Crypto(_))
        ));
        assert!(server_auth_key("pw".into(), "AAAA".into(), ServerKdf::default()).is_err());
    }

    #[test]
    fn a_server_cannot_offer_cheaper_parameters_than_passyble_sets() {
        assert!(ServerKdf::default().check_offered().is_ok());
        let stronger = ServerKdf { m_kib: 256 * 1024, t: 4, p: 2, ..Default::default() };
        assert!(stronger.check_offered().is_ok());
        for weak in [
            ServerKdf { m_kib: 19 * 1024, t: 2, ..Default::default() },
            ServerKdf { m_kib: 32 * 1024, ..Default::default() },
            ServerKdf { t: 2, ..Default::default() },
        ] {
            // Fine for the shared vectors, refused from a prelogin.
            assert!(weak.check().is_ok());
            assert!(matches!(weak.check_offered(), Err(PassError::Crypto(_))));
        }
    }
}
