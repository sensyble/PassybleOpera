/// Every fallible core operation returns this error. Exposed to Kotlin as `PassException`.
///
/// The payload is user-facing text in the core's language ([`crate::set_language`]). The kind
/// prefixes (`invalid input: `, `network error: `, ...) stay English: apps strip or ignore them. To
/// tell messages of one kind apart, apps use [`crate::core_message_is`], not English words.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
#[cfg_attr(feature = "uniffi", uniffi(flat_error))]
pub enum PassError {
    #[error("wrong master password or vault key")]
    InvalidPassword,
    #[error("vault file is corrupt: {0}")]
    Corrupt(String),
    #[error("crypto failure: {0}")]
    Crypto(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("conflict: {0}")]
    Conflict(String),
    /// A pinned server presented a key that matches none of the pins: the certificate was replaced,
    /// or someone is intercepting the connection. The device must be paired again with a new link.
    #[error("server certificate changed, pair this device again: {0}")]
    CertificateChanged(String),
    /// A cloud account (Google Drive) refused the access token: expired, revoked, or missing
    /// permission. Get a new token and retry. The vault and its master password are not involved.
    #[error("sign-in required: {0}")]
    AuthRequired(String),
}

pub type Result<T, E = PassError> = std::result::Result<T, E>;
