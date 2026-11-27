//! The list a soft lock keeps ([`crate::LockKind::Soft`]), also stored on disk so logins can be
//! listed before the first unlock after a start. The file holds only [`ItemSummary`] fields, never
//! a secret or the vault key, and is sealed to the OS user (DPAPI on Windows). Without a sealer
//! nothing is written.

#![cfg_attr(not(feature = "native"), allow(dead_code))]

#[cfg(feature = "native")]
use std::fs;
use std::io;
use std::path::Path;
use std::sync::Arc;

use pass_core::{
    b64url_decode, b64url_encode, AndroidApp, CardSummary, IdentitySummary, ItemKind, ItemSummary,
    PasskeySummary, UrlRule,
};
use serde::{Deserialize, Serialize};

/// Seals the file to the current OS user: DPAPI on Windows, the sealer set with
/// [`set_default_sealer`] elsewhere.
pub trait Sealer: Send + Sync {
    fn seal(&self, plain: &[u8]) -> Option<Vec<u8>>;
    /// `None`: not sealed by this user and app (or damaged).
    fn open(&self, sealed: &[u8]) -> Option<Vec<u8>>;
}

#[cfg(not(windows))]
static DEFAULT_SEALER: std::sync::OnceLock<Arc<dyn Sealer>> = std::sync::OnceLock::new();

/// Sets the sealer for platforms without a built-in one. It can be set only once, before the
/// first agent; a later call, or any call on Windows, is [`crate::AlreadySet`].
#[cfg_attr(windows, allow(unused_variables))]
pub fn set_default_sealer(sealer: Arc<dyn Sealer>) -> Result<(), crate::AlreadySet> {
    #[cfg(not(windows))]
    {
        DEFAULT_SEALER.set(sealer).map_err(|_| crate::AlreadySet)
    }
    #[cfg(windows)]
    {
        Err(crate::AlreadySet)
    }
}

/// DPAPI on Windows; elsewhere the one from [`set_default_sealer`], or `None` (the list is then
/// not kept on disk).
pub(crate) fn platform_sealer() -> Option<Arc<dyn Sealer>> {
    #[cfg(all(windows, feature = "native"))]
    {
        Some(Arc::new(dpapi::Dpapi))
    }
    #[cfg(all(windows, not(feature = "native")))]
    {
        None
    }
    #[cfg(not(windows))]
    {
        DEFAULT_SEALER.get().cloned()
    }
}

const FORMAT: &str = "passyble-kept-list";
const VERSION: u32 = 1;
/// Larger files are not read (a list of tens of thousands of items stays far below).
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct Contents {
    format: String,
    version: u32,
    /// The vault file's id: the list is only shown for that vault.
    vault_id: String,
    /// When it was written (Unix milliseconds).
    saved_at: i64,
    items: Vec<StoredItem>,
    /// A shared vault's list: what it is and what the user may do in it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vault: Option<StoredRef>,
}

/// A shared vault's kind (`org`, `direct`) and the user's role in it, kept with its list.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredRef {
    pub kind: String,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub can_edit: bool,
    #[serde(default)]
    pub can_reveal: bool,
}

/// [`ItemSummary`] as stored. Its own type, so the file format doesn't change with pass-core's
/// structs.
#[derive(Serialize, Deserialize)]
struct StoredItem {
    id: String,
    kind: ItemKind,
    title: String,
    username: String,
    #[serde(default)]
    urls: Vec<String>,
    #[serde(default)]
    android_apps: Vec<AndroidApp>,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    has_password: bool,
    #[serde(default)]
    has_totp: bool,
    #[serde(default)]
    has_notes: bool,
    #[serde(default)]
    passkeys: Vec<StoredPasskey>,
    #[serde(default)]
    favorite: bool,
    #[serde(default)]
    created_at: i64,
    #[serde(default)]
    updated_at: i64,
    #[serde(default)]
    use_count: u64,
    #[serde(default)]
    last_used: i64,
    #[serde(default)]
    rank: i64,
    // Absent from version 1 files.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    card: Option<StoredCard>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity: Option<StoredIdentity>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    has_fields: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    url_rules: Vec<UrlRule>,
}

/// [`CardSummary`] as stored: the public part of a card only (never the number, code or PIN).
#[derive(Serialize, Deserialize)]
struct StoredCard {
    #[serde(default)]
    cardholder_name: String,
    #[serde(default)]
    brand: String,
    #[serde(default)]
    last4: String,
    #[serde(default)]
    expiry_month: u32,
    #[serde(default)]
    expiry_year: u32,
}

/// [`IdentitySummary`] as stored.
#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    #[serde(default)]
    full_name: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    company: String,
}

#[derive(Serialize, Deserialize)]
struct StoredPasskey {
    rp_id: String,
    user_name: String,
    user_display_name: String,
    /// Base64url; public (the site stores it and sends it in its allow-list).
    credential_id: String,
}

impl StoredItem {
    fn of(s: &ItemSummary) -> StoredItem {
        StoredItem {
            id: s.id.clone(),
            kind: s.kind,
            title: s.title.clone(),
            username: s.username.clone(),
            urls: s.urls.clone(),
            android_apps: s.android_apps.clone(),
            domain: s.domain.clone(),
            has_password: s.has_password,
            has_totp: s.has_totp,
            has_notes: s.has_notes,
            passkeys: s
                .passkeys
                .iter()
                .map(|p| StoredPasskey {
                    rp_id: p.rp_id.clone(),
                    user_name: p.user_name.clone(),
                    user_display_name: p.user_display_name.clone(),
                    credential_id: b64url_encode(p.credential_id.clone()),
                })
                .collect(),
            favorite: s.favorite,
            created_at: s.created_at,
            updated_at: s.updated_at,
            use_count: s.use_count,
            last_used: s.last_used,
            rank: s.rank,
            tags: s.tags.clone(),
            card: s.card.as_ref().map(|c| StoredCard {
                cardholder_name: c.cardholder_name.clone(),
                brand: c.brand.clone(),
                last4: c.last4.clone(),
                expiry_month: c.expiry_month,
                expiry_year: c.expiry_year,
            }),
            identity: s.identity.as_ref().map(|i| StoredIdentity {
                full_name: i.full_name.clone(),
                email: i.email.clone(),
                company: i.company.clone(),
            }),
            has_fields: s.has_fields,
            url_rules: s.url_rules.clone(),
        }
    }

    fn into_summary(self) -> Option<ItemSummary> {
        let passkeys = self
            .passkeys
            .into_iter()
            .map(|p| {
                Some(PasskeySummary {
                    rp_id: p.rp_id,
                    user_name: p.user_name,
                    user_display_name: p.user_display_name,
                    credential_id: b64url_decode(p.credential_id).ok()?,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(ItemSummary {
            id: self.id,
            kind: self.kind,
            title: self.title,
            username: self.username,
            urls: self.urls,
            android_apps: self.android_apps,
            domain: self.domain,
            has_password: self.has_password,
            has_totp: self.has_totp,
            has_notes: self.has_notes,
            passkeys,
            favorite: self.favorite,
            created_at: self.created_at,
            updated_at: self.updated_at,
            use_count: self.use_count,
            last_used: self.last_used,
            rank: self.rank,
            tags: self.tags,
            card: self.card.map(|c| CardSummary {
                cardholder_name: c.cardholder_name,
                brand: c.brand,
                last4: c.last4,
                expiry_month: c.expiry_month,
                expiry_year: c.expiry_year,
            }),
            identity: self.identity.map(|i| IdentitySummary {
                full_name: i.full_name,
                email: i.email,
                company: i.company,
            }),
            has_fields: self.has_fields,
            // The kept list never holds the trash.
            trashed_at: None,
            url_rules: self.url_rules,
        })
    }
}

/// Writes `items` of vault `vault_id` to `path`, sealed (via a temporary file and a rename, so a
/// crash leaves the previous list or none, never half of one). `saved_at`: now, in Unix ms.
#[cfg(feature = "native")]
pub(crate) fn save(
    path: &Path,
    sealer: &dyn Sealer,
    vault_id: &str,
    items: &[ItemSummary],
    saved_at: i64,
) -> io::Result<()> {
    write(path, sealer, vault_id, items, saved_at, None)
}

/// [`save`] for a shared vault's list, with `vault` (its kind and the user's role).
#[cfg(feature = "native")]
pub(crate) fn save_shared(
    path: &Path,
    sealer: &dyn Sealer,
    vault_id: &str,
    vault: &StoredRef,
    items: &[ItemSummary],
    saved_at: i64,
) -> io::Result<()> {
    write(path, sealer, vault_id, items, saved_at, Some(vault.clone()))
}

#[cfg(feature = "native")]
fn write(
    path: &Path,
    sealer: &dyn Sealer,
    vault_id: &str,
    items: &[ItemSummary],
    saved_at: i64,
    vault: Option<StoredRef>,
) -> io::Result<()> {
    let contents = Contents {
        format: FORMAT.into(),
        version: VERSION,
        vault_id: vault_id.into(),
        saved_at,
        items: items.iter().map(StoredItem::of).collect(),
        vault,
    };
    let plain = serde_json::to_vec(&contents).map_err(io::Error::other)?;
    let sealed = sealer
        .seal(&plain)
        .ok_or_else(|| io::Error::other("the list could not be sealed"))?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &sealed)?;
    fs::rename(&tmp, path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}

/// Without the feature `native` nothing is kept on disk.
#[cfg(not(feature = "native"))]
pub(crate) fn save(_: &Path, _: &dyn Sealer, _: &str, _: &[ItemSummary], _: i64) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the list is kept in memory only",
    ))
}

#[cfg(not(feature = "native"))]
pub(crate) fn save_shared(
    _: &Path,
    _: &dyn Sealer,
    _: &str,
    _: &StoredRef,
    _: &[ItemSummary],
    _: i64,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the list is kept in memory only",
    ))
}

/// The list kept at `path` for vault `vault_id`. `None` if there is none, and also (deleting the
/// file) if it doesn't open for this user, is damaged or of an unknown format, or belongs to
/// another vault.
#[cfg(feature = "native")]
pub(crate) fn load(path: &Path, sealer: &dyn Sealer, vault_id: &str) -> Option<Vec<ItemSummary>> {
    read(path, sealer, vault_id).map(|(_, items)| items)
}

/// A shared vault's list kept at `path` ([`save_shared`]) for vault `vault_id`, with its kind
/// and role; as [`load`] otherwise (a home vault's list there is deleted too).
#[cfg(feature = "native")]
pub(crate) fn load_shared(
    path: &Path,
    sealer: &dyn Sealer,
    vault_id: &str,
) -> Option<(StoredRef, Vec<ItemSummary>)> {
    match read(path, sealer, vault_id) {
        Some((Some(vault), items)) => Some((vault, items)),
        Some((None, _)) => {
            remove(path);
            None
        }
        None => None,
    }
}

#[cfg(not(feature = "native"))]
pub(crate) fn load_shared(
    _: &Path,
    _: &dyn Sealer,
    _: &str,
) -> Option<(StoredRef, Vec<ItemSummary>)> {
    None
}

#[cfg(feature = "native")]
fn read(
    path: &Path,
    sealer: &dyn Sealer,
    vault_id: &str,
) -> Option<(Option<StoredRef>, Vec<ItemSummary>)> {
    let size = fs::metadata(path).ok()?.len();
    let loaded = (size <= MAX_FILE_BYTES)
        .then(|| fs::read(path).ok())
        .flatten()
        .and_then(|sealed| sealer.open(&sealed))
        .and_then(|plain| serde_json::from_slice::<Contents>(&plain).ok())
        .filter(|c| c.format == FORMAT && c.version == VERSION && c.vault_id == vault_id)
        .and_then(|c| {
            let items = c
                .items
                .into_iter()
                .map(StoredItem::into_summary)
                .collect::<Option<Vec<_>>>()?;
            Some((c.vault, items))
        });
    if loaded.is_none() {
        remove(path);
    }
    loaded
}

#[cfg(not(feature = "native"))]
pub(crate) fn load(_: &Path, _: &dyn Sealer, _: &str) -> Option<Vec<ItemSummary>> {
    None
}

/// Deletes the list kept at `path` (nothing if there is none).
#[cfg(feature = "native")]
pub(crate) fn remove(path: &Path) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(path.with_extension("tmp"));
}

#[cfg(not(feature = "native"))]
pub(crate) fn remove(_: &Path) {}

/// The id of the vault in a vault file (from its cleartext header), `None` if it isn't a vault.
pub(crate) fn vault_id_of(bytes: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct Header {
        vault_id: String,
    }
    serde_json::from_slice::<Header>(bytes)
        .ok()
        .map(|h| h.vault_id)
        .filter(|id| !id.is_empty())
}

#[cfg(all(windows, feature = "native"))]
mod dpapi {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    /// App-specific entropy: another program running as the same user must at least know this
    /// constant to unseal the file, and Passyble's other DPAPI blobs (the Windows Hello key) don't
    /// open as a list. Not a secret (it's in the binary).
    pub(super) const ENTROPY: &[u8] = b"com.sensyble.pass/kept-list/v1";

    pub(crate) struct Dpapi;

    impl super::Sealer for Dpapi {
        fn seal(&self, plain: &[u8]) -> Option<Vec<u8>> {
            protect(plain, ENTROPY)
        }
        fn open(&self, sealed: &[u8]) -> Option<Vec<u8>> {
            unprotect(sealed, ENTROPY)
        }
    }

    fn blob(data: &[u8]) -> Option<CRYPT_INTEGER_BLOB> {
        Some(CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(data.len()).ok()?,
            pbData: data.as_ptr() as *mut u8,
        })
    }

    fn empty() -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        }
    }

    /// Copies a blob DPAPI allocated and frees it.
    ///
    /// # Safety
    /// `out` must come from a successful `CryptProtectData` / `CryptUnprotectData`.
    unsafe fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        if out.pbData.is_null() {
            return Vec::new();
        }
        unsafe {
            let bytes = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
            LocalFree(out.pbData.cast());
            bytes
        }
    }

    pub(super) fn protect(data: &[u8], entropy: &[u8]) -> Option<Vec<u8>> {
        let input = blob(data)?;
        let entropy = blob(entropy)?;
        let mut out = empty();
        // SAFETY: the input blobs point at live slices for the call; `out` is freed by `take`.
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        (ok != 0).then(|| unsafe { take(out) })
    }

    pub(super) fn unprotect(data: &[u8], entropy: &[u8]) -> Option<Vec<u8>> {
        let input = blob(data)?;
        let entropy = blob(entropy)?;
        let mut out = empty();
        // SAFETY: as in `protect`.
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        (ok != 0).then(|| unsafe { take(out) })
    }
}

#[cfg(all(test, feature = "native"))]
pub(crate) mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use pass_core::{Item, Passkey};
    use serde_json::{json, Value};

    use crate::{Agent, AgentConfig, Consent, LockKind, PasskeyChoice, Ui};

    /// Stands for DPAPI: "sealed" for one user (`user`), opened only by that user.
    pub(crate) struct FakeSealer(pub u8);

    impl Sealer for FakeSealer {
        fn seal(&self, plain: &[u8]) -> Option<Vec<u8>> {
            let mut out = vec![self.0];
            out.extend(plain.iter().map(|b| b ^ 0x5a));
            Some(out)
        }
        fn open(&self, sealed: &[u8]) -> Option<Vec<u8>> {
            match sealed.split_first() {
                Some((user, rest)) if *user == self.0 => {
                    Some(rest.iter().map(|b| b ^ 0x5a).collect())
                }
                _ => None,
            }
        }
    }

    fn summary(id: &str, title: &str) -> ItemSummary {
        ItemSummary::of(&Item {
            id: id.into(),
            title: title.into(),
            username: "octo".into(),
            password: "hunter2-secret".into(),
            urls: vec!["https://github.com/login".into()],
            totp: Some("JBSWY3DPEHPK3PXP".into()),
            notes: "recovery codes".into(),
            passkeys: vec![Passkey {
                credential_id: vec![1, 2, 3],
                rp_id: "github.com".into(),
                user_name: "octo".into(),
                private_key_pkcs8: b"PRIVATE-KEY".to_vec(),
                ..Default::default()
            }],
            favorite: true,
            ..Default::default()
        })
        .with_usage(pass_core::ItemUsage {
            count: 3,
            last_used: 7,
            rank: 9,
        })
    }

    #[test]
    fn round_trips_and_holds_no_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kept").join("v1.bin");
        let items = vec![summary("1", "GitHub"), summary("2", "Gist")];
        save(&path, &FakeSealer(1), "vault-a", &items, 1_700_000_000_000).unwrap();
        assert_eq!(load(&path, &FakeSealer(1), "vault-a"), Some(items));
        // The plaintext under the seal: titles yes, secrets never.
        let plain = FakeSealer(1).open(&fs::read(&path).unwrap()).unwrap();
        let plain = String::from_utf8(plain).unwrap();
        assert!(plain.contains("GitHub"));
        for secret in ["hunter2", "JBSWY3DPEHPK3PXP", "recovery", "PRIVATE"] {
            assert!(!plain.contains(secret), "{secret} in {plain}");
        }
    }

    #[test]
    fn another_user_a_damaged_file_or_another_vault_is_ignored_and_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v1.bin");
        let items = vec![summary("1", "GitHub")];

        save(&path, &FakeSealer(1), "vault-a", &items, 1_700_000_000_000).unwrap();
        assert_eq!(load(&path, &FakeSealer(2), "vault-a"), None, "another user");
        assert!(!path.exists());

        save(&path, &FakeSealer(1), "vault-a", &items, 1_700_000_000_000).unwrap();
        assert_eq!(
            load(&path, &FakeSealer(1), "vault-b"),
            None,
            "another vault"
        );
        assert!(!path.exists());

        fs::write(&path, b"\x01not json").unwrap();
        assert_eq!(load(&path, &FakeSealer(1), "vault-a"), None, "damaged");
        assert!(!path.exists());

        let other = FakeSealer(1)
            .seal(json!({ "format": FORMAT, "version": 99, "vault_id": "vault-a", "saved_at": 0, "items": [] }).to_string().as_bytes())
            .unwrap();
        fs::write(&path, other).unwrap();
        assert_eq!(
            load(&path, &FakeSealer(1), "vault-a"),
            None,
            "unknown version"
        );
        assert!(!path.exists());

        assert_eq!(load(&path, &FakeSealer(1), "vault-a"), None, "missing");
    }

    fn card_and_identity() -> Vec<ItemSummary> {
        let card = ItemSummary::of(&Item {
            id: "c".into(),
            kind: pass_core::ItemKind::Card,
            title: "Visa •••• 1111".into(),
            notes: "card notes".into(),
            tags: vec!["Finance/Cards".into()],
            card: Some(pass_core::CardData {
                cardholder_name: "Ada Lovelace".into(),
                number: "4111111111111111".into(),
                expiry_month: 12,
                expiry_year: 2031,
                security_code: "737".into(),
                pin: "9876".into(),
                brand: "visa".into(),
            }),
            fields: vec![pass_core::CustomField {
                name: "Bank".into(),
                value: "hidden-field-value".into(),
                kind: pass_core::FieldKind::Hidden,
            }],
            ..Default::default()
        });
        let identity = ItemSummary::of(&Item {
            id: "i".into(),
            kind: pass_core::ItemKind::Identity,
            title: "Me".into(),
            tags: vec!["Personal".into()],
            identity: Some(pass_core::IdentityData {
                first_name: "Ada".into(),
                last_name: "Lovelace".into(),
                email: "ada@example.com".into(),
                company: "Analytical Engines".into(),
                phone: "+44 20 7946 0000".into(),
                address1: "12 Secret Street".into(),
                birth_date: "1815-12-10".into(),
                ..Default::default()
            }),
            ..Default::default()
        });
        vec![card, identity]
    }

    #[test]
    fn keeps_tags_and_card_and_identity_summaries_but_no_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v1.bin");
        let items = card_and_identity();
        save(&path, &FakeSealer(1), "vault-a", &items, 1_700_000_000_000).unwrap();
        let loaded = load(&path, &FakeSealer(1), "vault-a").unwrap();
        assert_eq!(loaded, items);
        assert_eq!(loaded[0].tags, ["Finance/Cards"]);
        let card = loaded[0].card.as_ref().unwrap();
        assert_eq!((card.brand.as_str(), card.last4.as_str()), ("visa", "1111"));
        assert_eq!((card.expiry_month, card.expiry_year), (12, 2031));
        assert!(loaded[0].has_fields);
        let identity = loaded[1].identity.as_ref().unwrap();
        assert_eq!(identity.full_name, "Ada Lovelace");
        assert_eq!(identity.email, "ada@example.com");
        // Filters on the kept list work as on the vault.
        assert_eq!(
            pass_core::summaries_with_tag(loaded.clone(), "finance".into()).len(),
            1
        );
        assert_eq!(pass_core::summaries_tags(loaded).len(), 2);
        let plain =
            String::from_utf8(FakeSealer(1).open(&fs::read(&path).unwrap()).unwrap()).unwrap();
        for secret in [
            "4111111111111111",
            "security_code",
            "\"pin\"",
            "\"number\"",
            "hidden-field-value",
            "card notes",
            "Secret Street",
            "1815-12-10",
            "+44 20 7946 0000",
        ] {
            assert!(!plain.contains(secret), "{secret} in {plain}");
        }
    }

    #[test]
    fn reads_files_from_before_tags_and_cards() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v1.bin");
        // A version 1 file: no tags, card, identity or has_fields.
        let old = json!({
            "format": FORMAT, "version": 1, "vault_id": "vault-a", "saved_at": 1,
            "items": [{
                "id": "1", "kind": "login", "title": "GitHub", "username": "octo",
                "urls": ["https://github.com"], "android_apps": [], "domain": "github.com",
                "has_password": true, "has_totp": false, "has_notes": false, "passkeys": [],
                "favorite": false, "created_at": 1, "updated_at": 2, "use_count": 0,
                "last_used": 0, "rank": 0
            }]
        });
        fs::write(
            &path,
            FakeSealer(1).seal(old.to_string().as_bytes()).unwrap(),
        )
        .unwrap();
        let loaded = load(&path, &FakeSealer(1), "vault-a").unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].title, "GitHub");
        assert!(loaded[0].tags.is_empty() && loaded[0].card.is_none());
        assert!(loaded[0].identity.is_none() && !loaded[0].has_fields);
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_round_trip_and_app_entropy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v1.bin");
        let items = vec![summary("1", "GitHub")];
        save(&path, &dpapi::Dpapi, "vault-a", &items, 1_700_000_000_000).unwrap();
        let sealed = fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&sealed).contains("GitHub"));
        assert_eq!(load(&path, &dpapi::Dpapi, "vault-a"), Some(items));
        // Sealed with other entropy (another app of the same user): doesn't open.
        assert!(dpapi::unprotect(&sealed, b"other").is_none());
        let foreign = dpapi::protect(b"{}", b"other").unwrap();
        fs::write(&path, foreign).unwrap();
        assert_eq!(load(&path, &dpapi::Dpapi, "vault-a"), None);
        assert!(!path.exists());
    }

    #[derive(Default)]
    struct QuietUi {
        lock_events: std::sync::Mutex<Vec<bool>>,
    }

    impl Ui for QuietUi {
        fn request_unlock(&self) -> bool {
            false
        }
        fn confirm_passkey_create(&self, _: &str, _: &str) -> Consent {
            Consent::Deny
        }
        fn choose_passkey(&self, _: &str, _: &[PasskeyChoice]) -> Option<usize> {
            None
        }
        fn show_totp_popup(&self, _: &str, _: &str) {}
        fn notify_lock_state(&self, locked: bool) {
            self.lock_events.lock().unwrap().push(locked);
        }
    }

    struct Setup {
        _dir: tempfile::TempDir,
        config: AgentConfig,
    }

    impl Setup {
        fn new() -> Setup {
            let dir = tempfile::tempdir().unwrap();
            let config = AgentConfig {
                vault_path: dir.path().join("pass.vault"),
                device_id: "laptop".into(),
                auto_lock: Duration::from_secs(900),
                #[cfg(feature = "webdav")]
                webdav: None,
                #[cfg(feature = "gdrive")]
                gdrive: None,
                kept_list: Some(dir.path().join("kept").join("v1.bin")),
            };
            Setup { _dir: dir, config }
        }

        fn kept(&self) -> std::path::PathBuf {
            self.config.kept_list.clone().unwrap()
        }

        /// A fresh agent (an app start) with the fake DPAPI of user 1.
        fn agent(&self) -> (Arc<Agent>, Arc<QuietUi>) {
            let ui = Arc::new(QuietUi::default());
            let agent = Agent::new(self.config.clone(), ui.clone());
            agent.set_kept_sealer(Some(Arc::new(FakeSealer(1))));
            (agent, ui)
        }
    }

    fn call(agent: &Agent, method: &str, params: Value) -> Value {
        let line = json!({ "id": 1, "method": method, "params": params }).to_string();
        serde_json::from_str(&agent.handle_line(&line)).unwrap()
    }

    fn add(agent: &Agent, title: &str) -> Item {
        agent
            .vault()
            .unwrap()
            .upsert(Item {
                title: title.into(),
                username: "octo".into(),
                password: "pw-secret".into(),
                urls: vec!["https://github.com".into()],
                ..Default::default()
            })
            .unwrap()
    }

    fn titles(found: &Value) -> Vec<String> {
        found["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["title"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn a_new_agent_starts_soft_locked_with_the_kept_list() {
        let setup = Setup::new();
        {
            let (agent, _) = setup.agent();
            agent.create_vault("master").unwrap();
            assert!(setup.kept().exists(), "written on unlock");
            add(&agent, "GitHub");
            // Quitting is a full lock: the list goes from memory, the file stays.
            agent.save_and_lock_as(LockKind::Full).unwrap();
            assert!(!agent.is_soft_locked());
        }
        let (agent, ui) = setup.agent();
        assert!(agent.restore_kept_list());
        assert!(agent.is_locked() && agent.is_soft_locked());
        assert_eq!(*ui.lock_events.lock().unwrap(), [true]);
        let status = call(&agent, "status", json!({}));
        assert_eq!(status["result"]["soft_locked"], true);
        let found = call(
            &agent,
            "logins.find",
            json!({ "url": "https://github.com/login" }),
        );
        assert_eq!(found["result"]["locked"], true);
        assert_eq!(titles(&found["result"]), ["GitHub"]);
        // Filling still needs the vault.
        let id = found["result"]["items"][0]["id"].as_str().unwrap();
        let fill = call(
            &agent,
            "logins.fill",
            json!({ "id": id, "url": "https://github.com/login" }),
        );
        assert_eq!(fill["error"]["code"], "locked");
        // Unlocking replaces it with the vault; a restore while unlocked does nothing.
        agent.unlock("master").unwrap();
        assert!(!agent.restore_kept_list());
    }

    #[test]
    fn edits_reach_the_file_on_lock_and_on_tick() {
        let setup = Setup::new();
        let (agent, _) = setup.agent();
        agent.create_vault("master").unwrap();
        add(&agent, "GitHub");
        // Throttled: right after the unlock's write, a tick doesn't write again...
        agent.tick();
        let sealer = FakeSealer(1);
        let id = kept_list_vault_id(&setup);
        assert_eq!(load(&setup.kept(), &sealer, &id).unwrap().len(), 0);
        // ...once the throttle has passed, it does.
        agent.expire_kept_throttle();
        agent.tick();
        assert_eq!(load(&setup.kept(), &sealer, &id).unwrap().len(), 1);
        // A soft lock writes the list it keeps (usage order included).
        add(&agent, "Gist");
        agent.save_and_lock().unwrap();
        assert!(agent.is_soft_locked());
        assert_eq!(load(&setup.kept(), &sealer, &id).unwrap().len(), 2);
    }

    fn kept_list_vault_id(setup: &Setup) -> String {
        vault_id_of(&fs::read(&setup.config.vault_path).unwrap()).unwrap()
    }

    #[test]
    fn wipe_triggers() {
        let setup = Setup::new();
        let (agent, ui) = setup.agent();
        agent.create_vault("master").unwrap();
        add(&agent, "GitHub");
        agent.save_and_lock().unwrap();
        assert!(setup.kept().exists());

        // "Lock completely" (or a sign-out): the file and the list in memory go.
        agent.forget_kept_list();
        assert!(!setup.kept().exists());
        assert!(agent.is_locked() && !agent.is_soft_locked());
        assert_eq!(ui.lock_events.lock().unwrap().last(), Some(&true));
        // Nothing is written again until the next unlock.
        agent.unlock("master").unwrap();
        assert!(setup.kept().exists());

        // "Keep list visible when locked" off: the file goes, and nothing is written.
        agent.set_keep_list(false);
        assert!(!setup.kept().exists());
        agent.save_and_lock().unwrap();
        assert!(!setup.kept().exists());
        let (fresh, _) = setup.agent();
        fresh.set_keep_list(false);
        assert!(!fresh.restore_kept_list());

        // On again: written at the next unlock.
        agent.set_keep_list(true);
        agent.unlock("master").unwrap();
        agent.save_and_lock_as(LockKind::Full).unwrap();
        assert!(setup.kept().exists());

        // The vault file missing (a cloud folder not synced yet): nothing shown, nothing deleted.
        let vault_bytes = fs::read(&setup.config.vault_path).unwrap();
        fs::remove_file(&setup.config.vault_path).unwrap();
        let (fresh, _) = setup.agent();
        assert!(!fresh.restore_kept_list());
        assert!(setup.kept().exists());
        fs::write(&setup.config.vault_path, &vault_bytes).unwrap();
        assert!(fresh.restore_kept_list());

        // Another vault in that file now: ignored and deleted.
        let other = pass_core::Vault::create("other".into(), "laptop".into()).unwrap();
        fs::write(&setup.config.vault_path, other.serialize().unwrap()).unwrap();
        let (fresh, _) = setup.agent();
        assert!(!fresh.restore_kept_list());
        assert!(!setup.kept().exists());
    }

    /// Another vault's config in the same folder: its own vault file and kept list.
    fn other_vault(setup: &Setup) -> AgentConfig {
        let dir = setup.config.vault_path.parent().unwrap();
        AgentConfig {
            vault_path: dir.join("other.vault"),
            kept_list: Some(dir.join("kept").join("v2.bin")),
            ..setup.config.clone()
        }
    }

    #[test]
    fn switching_vaults_keeps_each_vaults_list() {
        let setup = Setup::new();
        let other = other_vault(&setup);
        let (agent, _) = setup.agent();
        agent.create_vault("master").unwrap();
        add(&agent, "GitHub");

        // Switching away (unlocked): nothing of the first vault stays in memory, its file stays.
        assert!(agent.reconfigure(other.clone()));
        assert!(agent.is_locked() && !agent.is_soft_locked());
        assert!(setup.kept().exists());
        agent.create_vault("second").unwrap();
        let second = other.kept_list.clone().unwrap();
        assert!(second.exists());
        // Switching back with the second one soft-locked: its file stays too.
        agent.save_and_lock().unwrap();
        assert!(agent.is_soft_locked());
        agent.reconfigure(setup.config.clone());
        assert!(!agent.is_soft_locked());
        assert!(setup.kept().exists() && second.exists());

        // The next start of either vault comes back soft-locked with its own list.
        let (fresh, _) = setup.agent();
        assert!(fresh.restore_kept_list());
        let list = fresh.summaries().unwrap();
        assert_eq!(
            list.iter().map(|i| i.title.as_str()).collect::<Vec<_>>(),
            ["GitHub"]
        );
        let ui = Arc::new(QuietUi::default());
        let fresh = Agent::new(other, ui);
        fresh.set_kept_sealer(Some(Arc::new(FakeSealer(1))));
        assert!(fresh.restore_kept_list());
        assert_eq!(fresh.item_count(), Some(0));
    }

    #[test]
    fn lock_completely_then_switching_writes_the_other_vaults_list() {
        let setup = Setup::new();
        let other = other_vault(&setup);
        let (agent, _) = setup.agent();
        agent.create_vault("master").unwrap();
        agent.save_and_lock_as(LockKind::Full).unwrap();
        agent.forget_kept_list();
        assert!(!setup.kept().exists());
        agent.reconfigure(other.clone());
        agent.create_vault("second").unwrap();
        assert!(other.kept_list.unwrap().exists(), "an unlock writes again");
        assert!(!setup.kept().exists());
    }

    #[test]
    fn no_sealer_no_file() {
        let setup = Setup::new();
        let ui = Arc::new(QuietUi::default());
        let agent = Agent::new(setup.config.clone(), ui);
        agent.set_kept_sealer(None);
        agent.create_vault("master").unwrap();
        agent.save_and_lock().unwrap();
        assert!(agent.is_soft_locked());
        assert!(!setup.kept().exists());
    }
}
