//! Secure send: a text or small file shared through a one-time, expiring link, end-to-end
//! encrypted with XChaCha20-Poly1305. The key comes from a random link key (plus Argon2id of an
//! optional password) through HKDF-SHA256. The link key travels only in the URL fragment, which
//! browsers never send, so the service can't read the content.

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto::{self, Key, KEY_LEN, NONCE_LEN};
use crate::encoding::{b64url_decode, b64url_encode};
use crate::i18n::tr;
use crate::vault::KdfParams;
use crate::{now_ms, PassError, Result};

/// The largest content of one send: 10 MiB.
pub const SEND_MAX_BYTES: u64 = 10 * 1024 * 1024;
/// The furthest expiry a send can have: 30 days.
pub const SEND_MAX_DAYS: u32 = 30;
const DAY_MS: i64 = 24 * 60 * 60 * 1000;
const MAX_NAME: usize = 255;
const MAX_MIME: usize = 127;
const MAX_SEND_ID: usize = 64;
const SALT_LEN: usize = 16;

/// What is sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum SendKind {
    /// A text (UTF-8), shown on the page.
    Text,
    /// A file, offered for download under `name`.
    File,
}

/// The content of a send. Not wiped on drop, since the bindings move its fields out.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SendContent {
    pub kind: SendKind,
    /// The file name; `""` for a text.
    pub name: String,
    /// The file's media type (`application/pdf`); `""` when unknown or for a text.
    pub mime: String,
    pub data: Vec<u8>,
}

/// Never the content in debug output.
impl std::fmt::Debug for SendContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendContent")
            .field("kind", &self.kind)
            .field("bytes", &self.data.len())
            .finish_non_exhaustive()
    }
}

/// How a send may be opened.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SendOptions {
    /// When the service deletes it (Unix ms): in the future, at most [`SEND_MAX_DAYS`] away.
    pub expires_at: i64,
    /// How many times it can be opened (the service counts); 0 for no limit but the expiry.
    pub max_views: u32,
    /// A password the recipient must type too (told another way than the link).
    pub password: Option<String>,
}

impl std::fmt::Debug for SendOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendOptions")
            .field("expires_at", &self.expires_at)
            .field("max_views", &self.max_views)
            .field("password", &self.password.is_some())
            .finish()
    }
}

/// A sealed send, from [`send_seal`]: upload `ciphertext` and `meta`, and give the recipient
/// the link built from the service's id and `key` ([`send_link`]).
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SealedSend {
    pub ciphertext: Vec<u8>,
    /// The cleartext metadata for the service, JSON: `{"v":1, "expires_at", "max_views",
    /// "size", "kdf"?}` (`kdf` only with a password).
    pub meta: String,
    /// The link key for the link's fragment (base64url, 43 characters). Never uploaded.
    pub key: String,
    /// With a password: the proof the service asks for before a download (base64url); it
    /// stores a hash of it.
    pub password_auth: Option<String>,
}

impl std::fmt::Debug for SealedSend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedSend")
            .field("bytes", &self.ciphertext.len())
            .field("meta", &self.meta)
            .finish_non_exhaustive()
    }
}

/// What the open page shows before opening: from the metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SendInfo {
    pub expires_at: i64,
    pub max_views: u32,
    /// Size of the content in bytes.
    pub size: u64,
    /// Whether the recipient must type a password.
    pub has_password: bool,
}

/// A send link taken apart ([`send_parse_link`]).
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SendLink {
    /// The service's id of the send (the last part of the path).
    pub send_id: String,
    /// The link key (base64url), for [`send_open`].
    pub key: String,
}

impl std::fmt::Debug for SendLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendLink")
            .field("send_id", &self.send_id)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Meta {
    v: u32,
    expires_at: i64,
    max_views: u32,
    size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kdf: Option<KdfParams>,
}

#[derive(Serialize, Deserialize)]
struct Header {
    kind: SendKind,
    #[serde(default)]
    name: String,
    #[serde(default)]
    mime: String,
}

fn damaged() -> PassError {
    PassError::Corrupt(tr!("send.damaged"))
}

fn internal() -> PassError {
    PassError::Crypto(tr!("error.internal"))
}

fn aad(meta: &Meta) -> Result<Vec<u8>> {
    let mut aad = b"pass/send/v1:".to_vec();
    aad.extend(
        serde_json::to_vec(&(
            meta.v,
            meta.expires_at,
            meta.max_views,
            meta.size,
            &meta.kdf,
        ))
        .map_err(|_| internal())?,
    );
    Ok(aad)
}

fn hkdf32(salt: &[u8], ikm: &[u8], info: &[u8]) -> Key {
    let mut okm = Key::zeroed();
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut okm[..])
        .expect("32 bytes is a valid length");
    okm
}

fn content_key(link_key: &[u8; KEY_LEN], password_key: Option<&Key>) -> Key {
    let mut ikm = Zeroizing::new(link_key.to_vec());
    if let Some(p) = password_key {
        ikm.extend_from_slice(p.as_slice());
    }
    hkdf32(b"pass/send/v1", &ikm, b"content")
}

fn auth_of(password_key: &Key) -> String {
    b64url_encode(hkdf32(b"pass/send-auth/v1", password_key.as_slice(), b"auth").to_vec())
}

fn password_key(password: &str, kdf: &KdfParams) -> Result<Key> {
    kdf.check()?;
    let salt = crate::encoding::b64url_decode(kdf.salt.clone()).map_err(|_| damaged())?;
    crypto::derive_kek(password, kdf, &salt)
}

fn parse_meta(meta: &str) -> Result<Meta> {
    let meta: Meta = serde_json::from_str(meta).map_err(|_| damaged())?;
    if meta.v != 1 || meta.size > SEND_MAX_BYTES {
        return Err(damaged());
    }
    Ok(meta)
}

fn link_key_of(key: &str) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let bytes = Zeroizing::new(b64url_decode(key.to_string()).map_err(|_| bad_link())?);
    let key: [u8; KEY_LEN] = bytes.as_slice().try_into().map_err(|_| bad_link())?;
    Ok(Zeroizing::new(key))
}

fn bad_link() -> PassError {
    PassError::InvalidInput(tr!("send.bad_link"))
}

/// [`send_seal`] with every random value and the time given, for byte-exact test vectors.
#[allow(clippy::too_many_arguments)]
pub(crate) fn seal_with(
    content: &SendContent,
    options: &SendOptions,
    now: i64,
    link_key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    salt: [u8; SALT_LEN],
    mut kdf: KdfParams,
) -> Result<SealedSend> {
    let size = content.data.len() as u64;
    if size > SEND_MAX_BYTES {
        return Err(PassError::InvalidInput(tr!(
            "send.too_large",
            max = SEND_MAX_BYTES / (1024 * 1024)
        )));
    }
    if options.expires_at <= now || options.expires_at > now + SEND_MAX_DAYS as i64 * DAY_MS {
        return Err(PassError::InvalidInput(tr!(
            "send.bad_expiry",
            days = SEND_MAX_DAYS
        )));
    }
    let (name, mime) = match content.kind {
        SendKind::Text => {
            if std::str::from_utf8(&content.data).is_err() {
                return Err(PassError::InvalidInput(tr!("send.bad_text")));
            }
            (String::new(), String::new())
        }
        SendKind::File => {
            let name = content.name.trim();
            if name.is_empty()
                || name.len() > MAX_NAME
                || name
                    .chars()
                    .any(|c| c.is_control() || c == '/' || c == '\\')
            {
                return Err(PassError::InvalidInput(tr!("send.bad_name")));
            }
            let mime = content.mime.trim();
            if mime.len() > MAX_MIME || !mime.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(PassError::InvalidInput(tr!("send.bad_name")));
            }
            (name.to_string(), mime.to_string())
        }
    };
    let password_key = match options.password.as_deref() {
        Some("") => return Err(PassError::InvalidInput(tr!("send.empty_password"))),
        Some(password) => {
            kdf.alg = "argon2id".into();
            kdf.salt = b64url_encode(salt.to_vec());
            Some(password_key(password, &kdf)?)
        }
        None => None,
    };
    let meta = Meta {
        v: 1,
        expires_at: options.expires_at,
        max_views: options.max_views,
        size,
        kdf: password_key.as_ref().map(|_| kdf.clone()),
    };
    let header = serde_json::to_vec(&Header {
        kind: content.kind,
        name,
        mime,
    })
    .map_err(|_| internal())?;
    let mut plain = Zeroizing::new(Vec::with_capacity(4 + header.len() + content.data.len()));
    plain.extend_from_slice(&(header.len() as u32).to_be_bytes());
    plain.extend_from_slice(&header);
    plain.extend_from_slice(&content.data);
    let key = content_key(&link_key, password_key.as_ref());
    let ct = crypto::seal_with_nonce(&key, &nonce, &plain, &aad(&meta)?)?;
    let mut ciphertext = nonce.to_vec();
    ciphertext.extend_from_slice(&ct);
    Ok(SealedSend {
        ciphertext,
        meta: serde_json::to_string(&meta).map_err(|_| internal())?,
        key: b64url_encode(link_key.to_vec()),
        password_auth: password_key.as_ref().map(auth_of),
    })
}

/// Encrypts `content` for a send with a fresh link key (and Argon2id with the vault defaults
/// for a password). `InvalidInput` for content over [`SEND_MAX_BYTES`], an expiry in the past or
/// more than [`SEND_MAX_DAYS`] away, a text that isn't UTF-8, a file without a usable name, or
/// an empty password.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn send_seal(content: SendContent, options: SendOptions) -> Result<SealedSend> {
    seal_with(
        &content,
        &options,
        now_ms(),
        crypto::random_bytes::<KEY_LEN>(),
        crypto::random_bytes::<NONCE_LEN>(),
        crypto::random_bytes::<SALT_LEN>(),
        KdfParams::default(),
    )
}

/// What the metadata says: shown before opening ("a 2 MB file, password needed").
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn send_info(meta: String) -> Result<SendInfo> {
    let meta = parse_meta(&meta)?;
    Ok(SendInfo {
        expires_at: meta.expires_at,
        max_views: meta.max_views,
        size: meta.size,
        has_password: meta.kdf.is_some(),
    })
}

/// The proof of the password for the service, before it hands out the ciphertext (Argon2id
/// with the send's parameters). `InvalidInput` for a send without a password.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn send_password_auth(meta: String, password: String) -> Result<String> {
    let password = Zeroizing::new(password);
    let meta = parse_meta(&meta)?;
    let kdf = meta
        .kdf
        .ok_or_else(|| PassError::InvalidInput(tr!("send.no_password")))?;
    Ok(auth_of(&password_key(&password, &kdf)?))
}

/// Decrypts a send with the link key from the fragment (and the password if it has one).
/// `InvalidInput` when a password is needed and missing; `Crypto` when it doesn't open (a wrong
/// password, an incomplete link, or damaged data: they can't be told apart).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn send_open(
    ciphertext: Vec<u8>,
    meta: String,
    key: String,
    password: Option<String>,
) -> Result<SendContent> {
    let password = password.map(Zeroizing::new);
    let meta = parse_meta(&meta)?;
    let link_key = link_key_of(&key)?;
    let password_key = match (&meta.kdf, password.as_deref()) {
        (Some(_), None) => return Err(PassError::InvalidInput(tr!("send.needs_password"))),
        (Some(kdf), Some(p)) => Some(password_key(p, kdf)?),
        (None, _) => None,
    };
    if ciphertext.len() < NONCE_LEN {
        return Err(damaged());
    }
    let ckey = content_key(&link_key, password_key.as_ref());
    let plain = crypto::open(
        &ckey,
        &ciphertext[..NONCE_LEN],
        &ciphertext[NONCE_LEN..],
        &aad(&meta)?,
    )
    .ok_or_else(|| {
        PassError::Crypto(if meta.kdf.is_some() {
            tr!("send.cannot_open_password")
        } else {
            tr!("send.cannot_open")
        })
    })?;
    if plain.len() < 4 {
        return Err(damaged());
    }
    let header_len = u32::from_be_bytes(plain[..4].try_into().expect("4 bytes")) as usize;
    let header = plain.get(4..4 + header_len).ok_or_else(damaged)?;
    let header: Header = serde_json::from_slice(header).map_err(|_| damaged())?;
    let data = plain[4 + header_len..].to_vec();
    if data.len() as u64 != meta.size {
        return Err(damaged());
    }
    Ok(SendContent {
        kind: header.kind,
        name: header.name,
        mime: header.mime,
        data,
    })
}

/// The link to give the recipient: `base` (the service's send page, `https://…/s`), the
/// service's `send_id` and the link key as the fragment.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn send_link(base: &str, send_id: &str, key: &str) -> Result<String> {
    if !valid_send_id(send_id) {
        return Err(bad_link());
    }
    link_key_of(key)?;
    let base = base.trim().trim_end_matches('/');
    if !(base.starts_with("https://") || base.starts_with("http://localhost")) {
        return Err(bad_link());
    }
    Ok(format!("{base}/{send_id}#{key}"))
}

fn valid_send_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_SEND_ID
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Takes a send link apart: the id (last part of the path) and the link key (the fragment).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn send_parse_link(link: &str) -> Result<SendLink> {
    let (path, key) = link.trim().split_once('#').ok_or_else(bad_link)?;
    link_key_of(key)?;
    let path = path.split(['?']).next().unwrap_or_default();
    let send_id = path
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or_default();
    if !valid_send_id(send_id) || !path.contains("://") {
        return Err(bad_link());
    }
    Ok(SendLink {
        send_id: send_id.to_string(),
        key: key.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const NOW: i64 = 1_730_000_000_000;

    fn small_kdf() -> KdfParams {
        KdfParams {
            m_kib: 64,
            t: 1,
            p: 1,
            ..KdfParams::default()
        }
    }

    fn text(s: &str) -> SendContent {
        SendContent {
            kind: SendKind::Text,
            name: String::new(),
            mime: String::new(),
            data: s.as_bytes().to_vec(),
        }
    }

    fn opts(password: Option<&str>) -> SendOptions {
        SendOptions {
            expires_at: NOW + DAY_MS,
            max_views: 1,
            password: password.map(str::to_string),
        }
    }

    fn seal(content: &SendContent, password: Option<&str>) -> SealedSend {
        seal_with(
            content,
            &opts(password),
            NOW,
            crypto::random_bytes(),
            crypto::random_bytes(),
            crypto::random_bytes(),
            small_kdf(),
        )
        .unwrap()
    }

    #[test]
    fn a_text_and_a_file_round_trip() {
        let sealed = seal(&text("wifi: demo-pass-123"), None);
        assert!(sealed.password_auth.is_none());
        assert_eq!(sealed.key.len(), 43);
        let info = send_info(sealed.meta.clone()).unwrap();
        assert_eq!(info.size, 19);
        assert!(!info.has_password);
        let opened = send_open(
            sealed.ciphertext.clone(),
            sealed.meta.clone(),
            sealed.key.clone(),
            None,
        )
        .unwrap();
        assert_eq!(opened.data, b"wifi: demo-pass-123");
        assert_eq!(opened.kind, SendKind::Text);
        assert!(!format!("{opened:?}{sealed:?}").contains("demo-pass"));

        let file = SendContent {
            kind: SendKind::File,
            name: "contract.pdf".into(),
            mime: "application/pdf".into(),
            data: vec![7u8; 4096],
        };
        let sealed = seal(&file, Some("correct horse"));
        let info = send_info(sealed.meta.clone()).unwrap();
        assert!(info.has_password);
        let auth = send_password_auth(sealed.meta.clone(), "correct horse".into()).unwrap();
        assert_eq!(Some(auth), sealed.password_auth);
        let opened = send_open(
            sealed.ciphertext.clone(),
            sealed.meta.clone(),
            sealed.key.clone(),
            Some("correct horse".into()),
        )
        .unwrap();
        assert_eq!(opened.name, "contract.pdf");
        assert_eq!(opened.mime, "application/pdf");
        assert_eq!(opened.data.len(), 4096);
    }

    #[test]
    fn neither_the_link_nor_the_password_alone_opens_a_protected_send() {
        let sealed = seal(&text("the code is 4417"), Some("pw-one"));
        let open = |key: &str, pw: Option<&str>| {
            send_open(
                sealed.ciphertext.clone(),
                sealed.meta.clone(),
                key.to_string(),
                pw.map(str::to_string),
            )
        };
        assert!(matches!(
            open(&sealed.key, None),
            Err(PassError::InvalidInput(_))
        ));
        assert!(matches!(
            open(&sealed.key, Some("pw-two")),
            Err(PassError::Crypto(_))
        ));
        let other_key = b64url_encode(vec![1u8; 32]);
        assert!(matches!(
            open(&other_key, Some("pw-one")),
            Err(PassError::Crypto(_))
        ));
        assert!(open(&sealed.key, Some("pw-one")).is_ok());
        // The proof for the service doesn't come from a wrong password.
        assert_ne!(
            send_password_auth(sealed.meta.clone(), "pw-two".into()).ok(),
            sealed.password_auth
        );
    }

    #[test]
    fn the_service_cannot_change_the_metadata_or_the_content() {
        let sealed = seal(&text("hello"), None);
        let mut meta: Value = serde_json::from_str(&sealed.meta).unwrap();
        meta["max_views"] = 100.into();
        assert!(send_open(
            sealed.ciphertext.clone(),
            meta.to_string(),
            sealed.key.clone(),
            None
        )
        .is_err());
        let mut meta: Value = serde_json::from_str(&sealed.meta).unwrap();
        meta["expires_at"] = (NOW + 20 * DAY_MS).into();
        assert!(send_open(
            sealed.ciphertext.clone(),
            meta.to_string(),
            sealed.key.clone(),
            None
        )
        .is_err());
        let mut ct = sealed.ciphertext.clone();
        let last = ct.len() - 1;
        ct[last] ^= 1;
        assert!(send_open(ct, sealed.meta.clone(), sealed.key.clone(), None).is_err());
        // Removing the password from the metadata doesn't skip it.
        let protected = seal(&text("hello"), Some("pw"));
        let mut meta: Value = serde_json::from_str(&protected.meta).unwrap();
        meta.as_object_mut().unwrap().remove("kdf");
        assert!(send_open(
            protected.ciphertext.clone(),
            meta.to_string(),
            protected.key.clone(),
            None
        )
        .is_err());
    }

    #[test]
    fn limits_are_checked() {
        let big = SendContent {
            kind: SendKind::File,
            name: "big.bin".into(),
            mime: String::new(),
            data: vec![0u8; SEND_MAX_BYTES as usize + 1],
        };
        let rand = || crypto::random_bytes();
        let try_seal = |c: &SendContent, o: &SendOptions| {
            seal_with(
                c,
                o,
                NOW,
                rand(),
                crypto::random_bytes(),
                crypto::random_bytes(),
                small_kdf(),
            )
        };
        assert!(try_seal(&big, &opts(None)).is_err());
        let past = SendOptions {
            expires_at: NOW,
            ..opts(None)
        };
        assert!(try_seal(&text("x"), &past).is_err());
        let far = SendOptions {
            expires_at: NOW + (SEND_MAX_DAYS as i64 + 1) * DAY_MS,
            ..opts(None)
        };
        assert!(try_seal(&text("x"), &far).is_err());
        assert!(try_seal(&text("x"), &opts(Some(""))).is_err());
        let bad_text = SendContent {
            kind: SendKind::Text,
            name: String::new(),
            mime: String::new(),
            data: vec![0xff, 0xfe],
        };
        assert!(try_seal(&bad_text, &opts(None)).is_err());
        let no_name = SendContent {
            kind: SendKind::File,
            name: "../etc".into(),
            mime: String::new(),
            data: vec![1],
        };
        assert!(try_seal(&no_name, &opts(None)).is_err());
    }

    #[test]
    fn links_carry_the_key_in_the_fragment_only() {
        let key = b64url_encode(vec![3u8; 32]);
        let link = send_link("https://send.passyble.com/s/", "abc_DEF-1", &key).unwrap();
        assert_eq!(link, format!("https://send.passyble.com/s/abc_DEF-1#{key}"));
        let parsed = send_parse_link(&link).unwrap();
        assert_eq!(parsed.send_id, "abc_DEF-1");
        assert_eq!(parsed.key, key);
        assert!(!format!("{parsed:?}").contains(&key));
        assert!(send_link("https://x/s", "bad id", &key).is_err());
        assert!(send_link("ftp://x/s", "id", &key).is_err());
        assert!(send_link("https://x/s", "id", "short").is_err());
        assert!(send_parse_link("https://send.passyble.com/s/abc").is_err());
        assert!(send_parse_link("https://send.passyble.com/s/abc#short").is_err());
    }

    /// `core/tests/send_vectors.json` holds byte for byte, so the WebAssembly open page and the
    /// apps agree. `PASS_WRITE_SEND_VECTORS=1` writes the file again.
    #[test]
    fn the_test_vectors_hold() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/send_vectors.json");
        let cases = vector_cases();
        if std::env::var("PASS_WRITE_SEND_VECTORS").is_ok() {
            std::fs::write(path, serde_json::to_string_pretty(&cases).unwrap() + "\n").unwrap();
        }
        let file: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(
            file, cases,
            "core/tests/send_vectors.json no longer matches the format"
        );
        for case in file.as_array().unwrap() {
            let s = |k: &str| case[k].as_str().unwrap().to_string();
            let opened = send_open(
                b64url_decode(s("ciphertext")).unwrap(),
                s("meta"),
                s("key"),
                case["password"].as_str().map(str::to_string),
            )
            .unwrap();
            assert_eq!(opened.data, b64url_decode(s("data")).unwrap());
            assert_eq!(opened.name, s("name"));
        }
    }

    fn vector_cases() -> Value {
        let cases = [
            (
                "a text without a password",
                text("Wi-Fi: demo-network / demo-pass-2024"),
                None,
            ),
            (
                "a file with a password",
                SendContent {
                    kind: SendKind::File,
                    name: "notes.txt".into(),
                    mime: "text/plain".into(),
                    data: b"demo file contents\n".to_vec(),
                },
                Some("demo password"),
            ),
        ];
        Value::Array(
            cases
                .iter()
                .enumerate()
                .map(|(i, (what, content, password))| {
                    let n = i as u8;
                    let options = SendOptions {
                        expires_at: NOW + DAY_MS,
                        max_views: 3,
                        password: password.map(str::to_string),
                    };
                    let sealed = seal_with(
                        content,
                        &options,
                        NOW,
                        [0x10 + n; KEY_LEN],
                        [0x20 + n; NONCE_LEN],
                        [0x30 + n; SALT_LEN],
                        small_kdf(),
                    )
                    .unwrap();
                    serde_json::json!({
                        "what": what,
                        "now": NOW,
                        "link_key": b64url_encode(vec![0x10 + n; KEY_LEN]),
                        "nonce": b64url_encode(vec![0x20 + n; NONCE_LEN]),
                        "salt": b64url_encode(vec![0x30 + n; SALT_LEN]),
                        "kind": match content.kind { SendKind::Text => "text", SendKind::File => "file" },
                        "name": content.name,
                        "mime": content.mime,
                        "data": b64url_encode(content.data.clone()),
                        "password": password,
                        "expires_at": options.expires_at,
                        "max_views": options.max_views,
                        "meta": sealed.meta,
                        "key": sealed.key,
                        "ciphertext": b64url_encode(sealed.ciphertext.clone()),
                        "password_auth": sealed.password_auth,
                    })
                })
                .collect(),
        )
    }
}
