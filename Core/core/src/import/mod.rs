//! Import from other password managers and authenticator apps.
//!
//! [`parse_import`] turns an export file into items plus a report of what could not be read.
//! Nothing touches the vault until [`ImportBatch::commit`]. Input is untrusted: file size, entry
//! count, ZIP members and decoded images are capped, and bad input is an error, never a panic.

mod apply;
mod archive;
mod csv_formats;
mod duplicates;
mod encrypted;
mod json_formats;
mod kdbx;
mod merge;
mod otp_formats;
pub(crate) use otp_formats::build_otpauth;
mod pair;
mod pgp;
#[cfg(feature = "import-qr")]
mod qr;
#[cfg(feature = "import-qr")]
pub use qr::{qr_decode_image, qr_decode_rgba};
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_encrypted;

pub(crate) use duplicates::duplicate_groups;
pub use duplicates::{find_duplicates, merge_items};
pub use encrypted::{import_encryption, ImportEncryption};
pub use pair::{
    merge_candidates, merge_pair, merge_preview, merge_suggestions, MergeCandidate, MergeField,
    MergeFieldPlan, MergeFieldState, MergeNotes, MergeOutcome, MergePicks, MergePlan, MergePreview,
    MergeSide, MergeSuggestion, MergeUndo,
};

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::i18n::tr;
use crate::model::{CardData, CustomField, FieldKind, IdentityData, Item, ItemKind, Passkey};
use crate::vault::Vault;
use crate::{PassError, Result};

/// Largest export file accepted (also the cap on any single decompressed ZIP member).
pub const MAX_IMPORT_BYTES: usize = 50 * 1024 * 1024;
/// Most entries read from one export; the rest are reported as skipped.
pub(crate) const MAX_ENTRIES: usize = 100_000;

/// The export format, detected from the file or chosen explicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum ImportFormat {
    /// `otpauth-migration://` links (text) or an image of the export QR code.
    GoogleAuthenticator,
    /// Plain `otpauth://` links, one per line.
    OtpauthUris,
    Aegis,
    TwoFas,
    ChromeCsv,
    FirefoxCsv,
    AppleCsv,
    /// ZIP with `Proton Pass/data.json`, or that `data.json` on its own.
    ProtonPass,
    ProtonPassCsv,
    /// `.1pux` (ZIP with `export.data`), or that `export.data` on its own.
    OnePassword,
    OnePasswordCsv,
    BitwardenJson,
    BitwardenCsv,
    KeepassxcCsv,
    LastpassCsv,
    DashlaneCsv,
    /// A CSV with recognisable columns (title / url / username / password / notes / totp).
    GenericCsv,
    /// Passyble's own JSON export (`export_json`; an encrypted one is opened with
    /// `export_decrypt` first).
    PassybleJson,
    /// A KeePass database (`.kdbx`, or KeePass 1 `.kdb`), opened with its password / key file.
    Keepass,
}

impl ImportFormat {
    pub fn display_name(self) -> &'static str {
        match self {
            Self::GoogleAuthenticator => "Google Authenticator",
            Self::OtpauthUris => "otpauth:// links",
            Self::Aegis => "Aegis",
            Self::TwoFas => "2FAS",
            Self::ChromeCsv => "Chrome / Edge / Brave (CSV)",
            Self::FirefoxCsv => "Firefox (CSV)",
            Self::AppleCsv => "Apple Passwords / Safari (CSV)",
            Self::ProtonPass => "Proton Pass",
            Self::ProtonPassCsv => "Proton Pass (CSV)",
            Self::OnePassword => "1Password (1PUX)",
            Self::OnePasswordCsv => "1Password (CSV)",
            Self::BitwardenJson => "Bitwarden (JSON)",
            Self::BitwardenCsv => "Bitwarden (CSV)",
            Self::KeepassxcCsv => "KeePassXC (CSV)",
            Self::LastpassCsv => "LastPass (CSV)",
            Self::DashlaneCsv => "Dashlane (CSV)",
            Self::GenericCsv => "CSV",
            Self::PassybleJson => "Passyble (JSON)",
            Self::Keepass => "KeePass (KDBX)",
        }
    }

    /// [`ImportFormat::display_name`] in the core's language (`crate::set_language`).
    pub(crate) fn name(self) -> String {
        match self {
            Self::GoogleAuthenticator => tr!("import.format.google_authenticator"),
            Self::OtpauthUris => tr!("import.format.otpauth_uris"),
            Self::Aegis => tr!("import.format.aegis"),
            Self::TwoFas => tr!("import.format.two_fas"),
            Self::ChromeCsv => tr!("import.format.chrome_csv"),
            Self::FirefoxCsv => tr!("import.format.firefox_csv"),
            Self::AppleCsv => tr!("import.format.apple_csv"),
            Self::ProtonPass => tr!("import.format.proton_pass"),
            Self::ProtonPassCsv => tr!("import.format.proton_pass_csv"),
            Self::OnePassword => tr!("import.format.one_password"),
            Self::OnePasswordCsv => tr!("import.format.one_password_csv"),
            Self::BitwardenJson => tr!("import.format.bitwarden_json"),
            Self::BitwardenCsv => tr!("import.format.bitwarden_csv"),
            Self::KeepassxcCsv => tr!("import.format.keepassxc_csv"),
            Self::LastpassCsv => tr!("import.format.lastpass_csv"),
            Self::DashlaneCsv => tr!("import.format.dashlane_csv"),
            Self::GenericCsv => tr!("import.format.generic_csv"),
            Self::PassybleJson => tr!("import.format.passyble_json"),
            Self::Keepass => tr!("import.format.keepass"),
        }
    }

    fn is_csv(self) -> bool {
        matches!(
            self,
            Self::ChromeCsv
                | Self::FirefoxCsv
                | Self::AppleCsv
                | Self::ProtonPassCsv
                | Self::OnePasswordCsv
                | Self::BitwardenCsv
                | Self::KeepassxcCsv
                | Self::LastpassCsv
                | Self::DashlaneCsv
                | Self::GenericCsv
        )
    }
}

/// An entry of the export that was not imported, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ImportSkip {
    /// Title of the entry, or a description such as "entry 12".
    pub entry: String,
    pub reason: String,
}

/// The parsed export. Holds secrets: keep it out of UIs (use [`ImportPreview`]).
#[derive(Clone, Debug)]
pub struct ImportReport {
    pub format: ImportFormat,
    pub items: Vec<Item>,
    pub skipped: Vec<ImportSkip>,
    pub warnings: Vec<String>,
}

/// What the import will do with one parsed entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum ImportAction {
    /// A new item.
    Add,
    /// Added to an existing item (2FA, passkeys, websites, missing password or notes).
    Merge,
    /// Matches an existing item whose password or 2FA secret differs: added as a separate item so
    /// neither is lost.
    Conflict,
    /// Already in the vault; nothing to do.
    Duplicate,
    /// Left out by a [`ImportDecision::Skip`] of its clash group although it differs.
    Skip,
}

/// One parsed entry as the preview shows it. No secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ImportEntry {
    pub kind: ItemKind,
    pub title: String,
    pub username: String,
    /// First website, if any.
    pub url: Option<String>,
    pub has_password: bool,
    pub has_totp: bool,
    pub passkeys: u32,
    pub has_notes: bool,
    pub action: ImportAction,
    /// The existing item for `Merge`, `Conflict` and `Duplicate`.
    pub target_id: Option<String>,
    pub target_title: Option<String>,
    /// For `Merge` into an existing item: what gets added, e.g. `["2FA", "passkey"]`. Empty when
    /// entries of the file are merged into one new item (`target_id` is `None`).
    pub adds: Vec<String>,
    /// Id of its [`ImportGroup`] when the entry clashes with a vault item or other entries.
    pub group: Option<String>,
}

/// Why entries are grouped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum ClashKind {
    /// The entry (or entries) match a vault item and bring nothing new (at most another title).
    /// Default: skip.
    Identical,
    /// Same account (site + username) as a vault item; something differs. Default: merge.
    Differs,
    /// Two or more entries of the file for the same account, none in the vault. Default: merge
    /// them into one item.
    InFileDuplicate,
}

/// A field that differs between the versions of a clash group (relative to the first: the vault
/// item, or the first entry).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum ClashField {
    Title,
    Password,
    Totp,
    Urls,
    Notes,
    Passkeys,
}

/// Where a version of a clash group comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum MergeSource {
    /// The vault item the import matches.
    Existing,
    /// An entry of the export file.
    Import,
    /// An item of the vault ([`find_duplicates`]).
    Vault,
}

/// One value a merge can keep (a password, a 2FA secret or a title). Never the value itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MergeChoice {
    /// What an [`ImportDecision::Merge`] names to keep it: `existing`, `import#<n>` (entry `n` of
    /// the file) or, for vault duplicates, the item id.
    pub id: String,
    pub source: MergeSource,
    /// Title of the item or entry it comes from.
    pub label: String,
    /// Last modified (Unix ms), 0 if the export doesn't say.
    pub modified_at: i64,
    /// What merging keeps unless told otherwise.
    pub is_default: bool,
}

/// What to do with a clash group (or a group of vault duplicates).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum ImportDecision {
    /// Import nothing from the group (vault duplicates: leave them).
    Skip,
    /// Merge into one item. Each `*_from` is a [`MergeChoice::id`]; `None` (or an id that isn't in
    /// the group) keeps the default. Websites, notes, passkeys are united; the password not kept
    /// goes to the item's password history.
    Merge {
        #[serde(default)]
        password_from: Option<String>,
        #[serde(default)]
        totp_from: Option<String>,
        #[serde(default)]
        title_from: Option<String>,
    },
    /// Keep them as separate items (import: add the entries as new items).
    KeepBoth,
}

impl ImportDecision {
    /// `Merge` with every default.
    pub fn default_merge() -> Self {
        Self::Merge {
            password_from: None,
            totp_from: None,
            title_from: None,
        }
    }
}

/// A decision for one group of [`ImportPreview::groups`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ImportGroupDecision {
    pub group_id: String,
    pub decision: ImportDecision,
}

/// Entries of the file that are the same account as a vault item or as each other. No secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ImportGroup {
    /// Stable for the same file and vault: pass it back in [`ImportGroupDecision`].
    pub id: String,
    pub kind: ClashKind,
    /// Of the vault item, or of the first entry.
    pub title: String,
    pub username: String,
    pub url: Option<String>,
    pub existing_id: Option<String>,
    pub existing_title: Option<String>,
    /// Indices into [`ImportPreview::entries`].
    pub entries: Vec<u32>,
    pub differs: Vec<ClashField>,
    /// Two or more when the passwords differ: which one a merge keeps.
    pub password_choices: Vec<MergeChoice>,
    pub totp_choices: Vec<MergeChoice>,
    pub title_choices: Vec<MergeChoice>,
    /// Identical: `Skip`; otherwise `Merge` with the default choices.
    pub default_decision: ImportDecision,
}

/// Items of the vault that look like the same account ([`find_duplicates`]). No secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct DuplicateGroup {
    /// The first item's id.
    pub id: String,
    /// `Identical` (merging only drops copies) or `Differs`.
    pub kind: ClashKind,
    pub title: String,
    pub username: String,
    pub url: Option<String>,
    /// Most recently changed first; [`merge_items`] keeps the first one's id.
    pub item_ids: Vec<String>,
    /// One per item (same order): its title and last change.
    pub items: Vec<MergeChoice>,
    pub differs: Vec<ClashField>,
    pub password_choices: Vec<MergeChoice>,
    pub totp_choices: Vec<MergeChoice>,
    pub title_choices: Vec<MergeChoice>,
    /// Always `Merge` with the default choices.
    pub default_decision: ImportDecision,
}

/// Dry run of an import against the current vault. No secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ImportPreview {
    pub format: ImportFormat,
    pub format_name: String,
    pub entries: Vec<ImportEntry>,
    /// New items, including `conflicts`.
    pub to_add: u32,
    pub to_merge: u32,
    pub conflicts: u32,
    pub duplicates: u32,
    /// Number of `groups`.
    pub clashes: u32,
    /// Entries that clash with a vault item or with each other; counts and actions above assume
    /// each group's default decision.
    pub groups: Vec<ImportGroup>,
    /// Entries of the file that can't be imported.
    pub skipped: Vec<ImportSkip>,
    pub warnings: Vec<String>,
}

/// Outcome of [`ImportBatch::commit`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ImportResult {
    /// New items (including `conflicts`).
    pub added: u32,
    /// Entries merged into another item (a vault item, or the first entry of their group).
    pub merged: u32,
    /// New items kept next to a matching one (Keep both).
    pub conflicts: u32,
    /// Duplicates, skipped groups and entries of the file that couldn't be imported.
    pub skipped: u32,
}

/// A parsed export waiting to be committed. Its items (with secrets) stay on the Rust side.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[derive(Debug)]
pub struct ImportBatch {
    report: ImportReport,
}

/// Parses an export file. `format: None` detects it.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn import_parse(
    data: Vec<u8>,
    file_name: String,
    format: Option<ImportFormat>,
) -> Result<Arc<ImportBatch>> {
    Ok(Arc::new(ImportBatch::new(parse_import(
        &data, &file_name, format,
    )?)))
}

/// [`import_parse`] for a file that may be password-protected ([`import_encryption`]). Returns
/// `InvalidPassword` for a wrong password and `InvalidInput` for damaged files or unusually heavy
/// key derivation settings. The password is not kept.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn import_parse_with_password(
    data: Vec<u8>,
    file_name: String,
    password: String,
) -> Result<Arc<ImportBatch>> {
    import_parse_with_key_file(data, file_name, password, None)
}

/// [`import_parse_with_password`] with a KeePass key file as well as (or, with an empty
/// `password`, instead of) the password. Other formats ignore `key_file`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn import_parse_with_key_file(
    data: Vec<u8>,
    file_name: String,
    password: String,
    key_file: Option<Vec<u8>>,
) -> Result<Arc<ImportBatch>> {
    let password = zeroize::Zeroizing::new(password);
    let key_file = key_file.map(zeroize::Zeroizing::new);
    let unlock = encrypted::Unlock {
        password: &password,
        key_file: key_file.as_ref().map(|k| k.as_slice()),
    };
    Ok(Arc::new(ImportBatch::new(parse_import_unlocked(
        &data, &file_name, &unlock,
    )?)))
}

/// [`parse_import`] of a file that may be password-protected, opened with `unlock`.
pub fn parse_import_with_password(
    data: &[u8],
    file_name: &str,
    password: &str,
    key_file: Option<&[u8]>,
) -> Result<ImportReport> {
    parse_import_unlocked(data, file_name, &encrypted::Unlock { password, key_file })
}

fn parse_import_unlocked(
    data: &[u8],
    file_name: &str,
    unlock: &encrypted::Unlock<'_>,
) -> Result<ImportReport> {
    if data.len() <= MAX_IMPORT_BYTES && crate::export::is_encrypted(data) {
        let plain = zeroize::Zeroizing::new(crate::export::export_decrypt(
            data.to_vec(),
            unlock.password.to_string(),
        )?);
        return parse_import(&plain, file_name, Some(ImportFormat::PassybleJson));
    }
    parse_import_inner(data, file_name, None, Some(unlock))
}

impl ImportBatch {
    pub fn new(report: ImportReport) -> Self {
        Self { report }
    }

    pub fn report(&self) -> &ImportReport {
        &self.report
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl ImportBatch {
    pub fn format(&self) -> ImportFormat {
        self.report.format
    }

    /// Number of importable entries.
    pub fn item_count(&self) -> u32 {
        self.report.items.len() as u32
    }

    /// What [`ImportBatch::commit`] would do with the vault as it is now.
    pub fn preview(&self, vault: Arc<Vault>) -> ImportPreview {
        let plan = apply::plan(
            &vault.items(),
            &self.report.items,
            &HashMap::new(),
            crate::now_ms(),
        );
        apply::preview(&self.report, plan)
    }

    /// Adds the items to the vault (de-duplicated against its current contents), every clash group
    /// with its default decision. The caller saves and syncs the vault afterwards.
    pub fn commit(&self, vault: Arc<Vault>) -> Result<ImportResult> {
        self.commit_with(vault, Vec::new())
    }

    /// [`ImportBatch::commit`] with a decision per clash group (by [`ImportGroup::id`]); groups
    /// without one get their default, unknown ids are ignored. The import is planned again against
    /// the vault as it is now.
    pub fn commit_with(
        &self,
        vault: Arc<Vault>,
        decisions: Vec<ImportGroupDecision>,
    ) -> Result<ImportResult> {
        let decisions: HashMap<String, ImportDecision> = decisions
            .into_iter()
            .map(|d| (d.group_id, d.decision))
            .collect();
        apply::commit(&vault, &self.report, &decisions)
    }
}

/// Parses an export file into items. `file_name` is a hint for detection (and error messages);
/// `format` skips detection.
pub fn parse_import(
    data: &[u8],
    file_name: &str,
    format: Option<ImportFormat>,
) -> Result<ImportReport> {
    parse_import_inner(data, file_name, format, None)
}

fn parse_import_inner(
    data: &[u8],
    file_name: &str,
    format: Option<ImportFormat>,
    unlock: Option<&encrypted::Unlock<'_>>,
) -> Result<ImportReport> {
    if data.len() > MAX_IMPORT_BYTES {
        return Err(invalid(tr!(
            "import.too_large",
            megabytes = MAX_IMPORT_BYTES / (1024 * 1024)
        )));
    }
    if data.iter().all(|b| b.is_ascii_whitespace()) {
        return Err(invalid(tr!("import.empty_file")));
    }
    let mut c = Collector::default();
    let format = parse_bytes(data, file_name, format, &mut c, unlock)?;
    // An export file never shares an item with AI tools (crate::ai): not even Passyble's own, so
    // a file someone hands over can't mark a login it merges into.
    for item in &mut c.items {
        item.set_ai_access(None);
    }
    let cut: Vec<String> = c
        .items
        .iter_mut()
        .enumerate()
        .filter_map(|(n, i)| {
            crate::limits::truncate_chars(&mut i.notes, crate::MAX_NOTES_CHARS).then_some((n, i))
        })
        .map(|(n, i)| match i.title.trim() {
            "" => tr!("import.entry_number", number = n + 1),
            t => t.chars().take(80).collect(),
        })
        .collect();
    if !cut.is_empty() {
        let mut entries = cut.iter().take(20).cloned().collect::<Vec<_>>().join("; ");
        if cut.len() > 20 {
            entries.push_str("; …");
        }
        c.warn(tr!("import.notes_truncated", entries = entries));
    }
    if c.items.is_empty() && c.skipped.is_empty() {
        return Err(invalid(tr!("import.no_entries", format = format.name())));
    }
    Ok(ImportReport {
        format,
        items: c.items,
        skipped: c.skipped,
        warnings: c.warnings,
    })
}

pub(crate) fn invalid(msg: impl Into<String>) -> PassError {
    PassError::InvalidInput(msg.into())
}

pub(crate) fn encrypted_error(what: &str) -> PassError {
    invalid(tr!("import.encrypted", format = what))
}

pub(crate) const ZIP_MAGIC: &[u8] = b"PK\x03\x04";
const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";
const JPEG_MAGIC: &[u8] = b"\xff\xd8\xff";
pub(crate) const KDBX_MAGIC: &[u8] = b"\x03\xd9\xa2\x9a";

fn parse_bytes(
    data: &[u8],
    file_name: &str,
    format: Option<ImportFormat>,
    c: &mut Collector,
    unlock: Option<&encrypted::Unlock<'_>>,
) -> Result<ImportFormat> {
    if data.starts_with(ZIP_MAGIC) {
        return archive::parse_zip(data, format, c, unlock);
    }
    if data.starts_with(PNG_MAGIC) || data.starts_with(JPEG_MAGIC) {
        return parse_image(data, format, c);
    }
    if data.starts_with(KDBX_MAGIC) {
        if format.is_some_and(|f| f != ImportFormat::Keepass) {
            return Err(invalid(tr!(
                "import.not_format",
                format = format.map(ImportFormat::name).unwrap_or_default()
            )));
        }
        if !cfg!(feature = "import-kdbx") {
            return Err(invalid(tr!("import.keepass_database")));
        }
        let unlock = unlock.ok_or_else(|| encrypted::password_needed(encrypted::Kind::Keepass))?;
        return kdbx::parse(data, unlock, c);
    }
    if pgp::is_binary(data) {
        return parse_pgp(data, file_name, format, c, unlock);
    }
    let text = decode_text(data, c);
    parse_text(&text, file_name, format, c, unlock)
}

/// A passphrase-encrypted OpenPGP file: decrypted, then read as the export it holds (a Proton
/// Pass ZIP or `data.json`, or any other export). What it holds is not decrypted again.
fn parse_pgp(
    data: &[u8],
    file_name: &str,
    format: Option<ImportFormat>,
    c: &mut Collector,
    unlock: Option<&encrypted::Unlock<'_>>,
) -> Result<ImportFormat> {
    if !cfg!(feature = "import-pgp") {
        return Err(invalid(tr!("import.encrypted_pgp")));
    }
    let unlock = unlock
        .filter(|u| !u.password.is_empty())
        .ok_or_else(|| encrypted::password_needed(encrypted::Kind::Pgp))?;
    let plain = pgp::decrypt(data, unlock.password)?;
    if plain.starts_with(ZIP_MAGIC) {
        // A Proton Pass ZIP; its own data.pgp (if any) takes the same passphrase.
        return archive::parse_zip(&plain, format, c, Some(unlock));
    }
    if plain.starts_with(KDBX_MAGIC) || pgp::is_binary(&plain) {
        return Err(invalid(tr!("import.unknown_file")));
    }
    let text = zeroize::Zeroizing::new(decode_text(&plain, c));
    if text.trim_start().starts_with("-----BEGIN PGP") {
        return Err(invalid(tr!("import.unknown_file")));
    }
    parse_text(&text, file_name, format, c, None)
}

#[cfg(feature = "import-qr")]
fn parse_image(
    data: &[u8],
    format: Option<ImportFormat>,
    c: &mut Collector,
) -> Result<ImportFormat> {
    if let Some(f) = format.filter(|f| {
        !matches!(
            f,
            ImportFormat::GoogleAuthenticator | ImportFormat::OtpauthUris
        )
    }) {
        return Err(invalid(tr!("import.image_wrong_format", format = f.name())));
    }
    let texts = qr::qr_decode_image(data)?;
    let joined = texts.join("\n");
    if !contains_ci(&joined, "otpauth") {
        return Err(invalid(tr!("import.qr_not_otp")));
    }
    otp_formats::parse_otp_text(&joined, c)
}

#[cfg(not(feature = "import-qr"))]
fn parse_image(
    _data: &[u8],
    _format: Option<ImportFormat>,
    _c: &mut Collector,
) -> Result<ImportFormat> {
    Err(invalid(tr!("import.no_qr_support")))
}

/// UTF-8 (with or without BOM) or UTF-16 with BOM; anything else is read as Latin-1 with a warning.
fn decode_text(data: &[u8], c: &mut Collector) -> String {
    if let Some(rest) = data.strip_prefix(b"\xef\xbb\xbf") {
        return String::from_utf8_lossy(rest).into_owned();
    }
    let utf16 = |rest: &[u8], le: bool| {
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&p| {
                if le {
                    u16::from_le_bytes(p)
                } else {
                    u16::from_be_bytes(p)
                }
            })
            .collect();
        String::from_utf16_lossy(&units)
    };
    if let Some(rest) = data.strip_prefix(b"\xff\xfe") {
        return utf16(rest, true);
    }
    if let Some(rest) = data.strip_prefix(b"\xfe\xff") {
        return utf16(rest, false);
    }
    match std::str::from_utf8(data) {
        Ok(s) => s.to_string(),
        Err(_) => {
            c.warn(tr!("import.latin1"));
            data.iter().map(|&b| b as char).collect()
        }
    }
}

pub(crate) fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

pub(crate) fn starts_with_ci(s: &str, prefix: &str) -> bool {
    s.len() >= prefix.len()
        && s.is_char_boundary(prefix.len())
        && s[..prefix.len()].eq_ignore_ascii_case(prefix)
}

fn parse_text(
    text: &str,
    file_name: &str,
    format: Option<ImportFormat>,
    c: &mut Collector,
    unlock: Option<&encrypted::Unlock<'_>>,
) -> Result<ImportFormat> {
    let trimmed = text.trim_start();
    if trimmed.starts_with("-----BEGIN PGP") {
        return parse_pgp(trimmed.as_bytes(), file_name, format, c, unlock);
    }
    // Encrypted JSON exports (Bitwarden, Aegis, 2FAS), whatever format was asked for.
    if trimmed.starts_with('{') && encrypted::has_marker(trimmed) {
        let value = parse_json(text)?;
        if let Some(kind) = encrypted::json_kind(&value) {
            return encrypted::parse_json(&value, kind, format, c, unlock);
        }
    }
    if let Some(format) = format {
        return parse_as(text, format, c);
    }
    if contains_ci(text, "otpauth-migration://") {
        return otp_formats::parse_otp_text(text, c);
    }
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        let value = parse_json(text)?;
        let format =
            json_formats::detect(&value).ok_or_else(|| invalid(tr!("import.unknown_json")))?;
        json_formats::parse(&value, format, c)?;
        return Ok(format);
    }
    let first_line = trimmed.lines().next().unwrap_or_default().trim();
    if starts_with_ci(first_line, "otpauth://") {
        return otp_formats::parse_otp_text(text, c);
    }
    if let Some(format) = csv_formats::detect(text) {
        csv_formats::parse(text, format, c)?;
        return Ok(format);
    }
    if contains_ci(text, "otpauth://") {
        return otp_formats::parse_otp_text(text, c);
    }
    let lower = file_name.to_ascii_lowercase();
    Err(invalid(if lower.ends_with(".csv") {
        tr!("import.unknown_csv")
    } else if file_name.trim().is_empty() {
        tr!("import.unknown_file")
    } else {
        tr!("import.unknown_named_file", file = file_name.trim())
    }))
}

fn parse_as(text: &str, format: ImportFormat, c: &mut Collector) -> Result<ImportFormat> {
    match format {
        ImportFormat::GoogleAuthenticator | ImportFormat::OtpauthUris => {
            otp_formats::parse_otp_text(text, c)?;
        }
        f if f.is_csv() => csv_formats::parse(text, f, c)?,
        f => {
            let value = parse_json(text)?;
            json_formats::parse(&value, f, c)?;
        }
    }
    Ok(format)
}

pub(crate) fn parse_json(text: &str) -> Result<serde_json::Value> {
    serde_json::from_str(text).map_err(|_| invalid(tr!("import.json_unreadable")))
}

/// One entry as read from an export, before clean-up.
#[derive(Default)]
pub(crate) struct Draft {
    pub kind: ItemKind,
    pub title: String,
    pub username: String,
    /// Kept as the username when there is none, otherwise added to the notes.
    pub email: String,
    pub password: String,
    pub urls: Vec<String>,
    /// `otpauth://` URI or base32 secret.
    pub totp: String,
    pub notes: String,
    /// Custom fields ([`Item::fields`]); empty values are dropped.
    pub fields: Vec<CustomField>,
    /// Folders, collections, groups, categories ([`Item::tags`]).
    pub tags: Vec<String>,
    /// For `ItemKind::Card`.
    pub card: Option<CardData>,
    /// For `ItemKind::Identity`.
    pub identity: Option<IdentityData>,
    pub favorite: bool,
    pub passkeys: Vec<Passkey>,
    /// Unix milliseconds, 0 if unknown.
    pub created_at: i64,
    /// Last modified (Unix milliseconds), 0 if unknown: picks the default password when merging.
    pub updated_at: i64,
}

impl Draft {
    /// Adds a custom field.
    pub fn field(&mut self, name: &str, value: &str, kind: FieldKind) {
        self.fields.push(CustomField {
            name: name.to_string(),
            value: value.to_string(),
            kind,
        });
    }
}

/// Display name of a card brand ([`crate::card_brand`]).
pub(crate) fn brand_name(brand: &str) -> String {
    crate::model::card_brand_name(brand.to_string())
}

/// A brand name as an export spells it (`Visa`, `MasterCard`, `American Express`) → our id.
pub(crate) fn brand_id(name: &str) -> String {
    let n: String = name
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect::<String>()
        .to_lowercase();
    match n.as_str() {
        "americanexpress" | "amex" => "amex".into(),
        "mastercard" | "mc" => "mastercard".into(),
        "dinersclub" | "diners" => "diners".into(),
        "discover" => "discover".into(),
        "visa" | "visaelectron" => "visa".into(),
        "jcb" => "jcb".into(),
        "unionpay" | "chinaunionpay" => "unionpay".into(),
        "maestro" => "maestro".into(),
        "mir" => "mir".into(),
        _ => n,
    }
}

/// Splits `MM/YY`, `MM/YYYY`, `YYYY-MM`, `YYYYMM`, `MMYY` or `Month,YYYY` into (month, year);
/// zeros for what can't be read. Two-digit years are taken as 20xx.
pub(crate) fn parse_expiry(s: &str) -> (u32, u32) {
    let s = s.trim();
    const MONTHS: [&str; 12] = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let lower = s.to_lowercase();
    if let Some(m) = MONTHS.iter().position(|m| lower.starts_with(m)) {
        let year: String = lower.chars().filter(char::is_ascii_digit).collect();
        return (m as u32 + 1, year_of(&year));
    }
    let parts: Vec<&str> = s
        .split(|c: char| !c.is_ascii_digit())
        .filter(|p| !p.is_empty())
        .collect();
    let (m, y) = match parts.as_slice() {
        [a, b] if a.len() == 4 => (*b, *a),
        [a, b] => (*a, *b),
        [one] if one.len() == 6 && one.starts_with("20") => (&one[4..], &one[..4]),
        [one] if one.len() == 6 => (&one[..2], &one[2..]),
        [one] if one.len() == 4 => (&one[..2], &one[2..]),
        _ => return (0, 0),
    };
    let month: u32 = m.parse().unwrap_or(0);
    if !(1..=12).contains(&month) {
        return (0, year_of(y));
    }
    (month, year_of(y))
}

fn year_of(y: &str) -> u32 {
    match y.parse::<u32>() {
        Ok(v) if v < 100 => 2000 + v,
        Ok(v) if (1900..=9999).contains(&v) => v,
        _ => 0,
    }
}

/// Splits a tag cell (`a, b` or `a; b`) into tags.
pub(crate) fn split_tags(cell: &str) -> Vec<String> {
    cell.split([',', ';'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

#[derive(Default)]
pub(crate) struct Collector {
    pub items: Vec<Item>,
    pub skipped: Vec<ImportSkip>,
    pub warnings: Vec<String>,
    seen: usize,
    capped: bool,
}

impl Collector {
    /// Label for an entry in messages: its title, or its position.
    pub fn label(&self, title: &str) -> String {
        let title = title.trim();
        if title.is_empty() {
            tr!("import.entry_number", number = self.seen + 1)
        } else {
            title.chars().take(80).collect()
        }
    }

    pub fn full(&self) -> bool {
        self.items.len() + self.skipped.len() >= MAX_ENTRIES
    }

    fn check_cap(&mut self) -> bool {
        if self.full() {
            if !self.capped {
                self.capped = true;
                self.warnings
                    .push(tr!("import.too_many_entries", max = MAX_ENTRIES));
            }
            return false;
        }
        true
    }

    pub fn skip(&mut self, entry: impl Into<String>, reason: impl Into<String>) {
        if !self.check_cap() {
            return;
        }
        self.seen += 1;
        self.skipped.push(ImportSkip {
            entry: entry.into(),
            reason: reason.into(),
        });
    }

    /// Takes over what another collector read (one file of a ZIP).
    pub fn merge(&mut self, other: Collector) {
        let room = MAX_ENTRIES.saturating_sub(self.items.len() + self.skipped.len());
        let skipped_room = room.saturating_sub(other.items.len().min(room));
        let (items, skipped) = (other.items.len(), other.skipped.len());
        self.items.extend(other.items.into_iter().take(room));
        self.skipped
            .extend(other.skipped.into_iter().take(skipped_room));
        self.seen += items + skipped;
        for w in other.warnings {
            self.warn(w);
        }
        if items + skipped > room {
            self.check_cap();
        }
    }

    pub fn warn(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        if self.warnings.len() < 1000 && !self.warnings.contains(&msg) {
            self.warnings.push(msg);
        }
    }

    /// Takes an item as it is (Passyble's own export, already complete and checked).
    pub fn push_item(&mut self, item: Item) {
        if !self.check_cap() {
            return;
        }
        self.seen += 1;
        self.items.push(item);
    }

    pub fn add(&mut self, d: Draft) {
        if !self.check_cap() {
            return;
        }
        let label = self.label(if d.title.trim().is_empty() {
            d.urls.first().map(String::as_str).unwrap_or_default()
        } else {
            &d.title
        });
        let mut urls: Vec<String> = Vec::new();
        for url in d.urls {
            let url = url.trim().to_string();
            if !url.is_empty() && !urls.iter().any(|u| u.eq_ignore_ascii_case(&url)) {
                urls.push(url);
            }
        }
        let totp = match normalize_totp(&d.totp) {
            Ok(t) => t,
            Err(reason) => {
                self.warn(tr!(
                    "import.totp_not_imported",
                    entry = label,
                    reason = reason
                ));
                None
            }
        };
        let mut username = d.username.trim().to_string();
        let email = d.email.trim().to_string();
        let mut fields = d.fields;
        if username.is_empty() {
            username = email;
        } else if !email.is_empty() && !email.eq_ignore_ascii_case(&username) {
            fields.insert(
                0,
                CustomField {
                    name: tr!("import.field.email"),
                    value: email,
                    kind: FieldKind::Text,
                },
            );
        }
        let notes = d.notes.trim().to_string();
        let fields: Vec<CustomField> = fields
            .into_iter()
            .map(|f| CustomField {
                name: f.name.trim().to_string(),
                value: f.value.trim().to_string(),
                kind: f.kind,
            })
            .filter(|f| !f.value.is_empty())
            .collect();
        let password = d.password;
        let empty_login = username.is_empty()
            && password.is_empty()
            && urls.is_empty()
            && totp.is_none()
            && d.passkeys.is_empty()
            && notes.is_empty()
            && fields.is_empty();
        if d.kind == ItemKind::Login && empty_login {
            self.skip(label, tr!("import.skip.empty_entry"));
            return;
        }
        if d.kind == ItemKind::Note
            && notes.is_empty()
            && fields.is_empty()
            && d.title.trim().is_empty()
        {
            self.skip(label, tr!("import.skip.empty_note"));
            return;
        }
        let card = d.card.filter(|c| *c != CardData::default());
        let identity = d.identity.filter(|i| !i.is_empty());
        if d.kind == ItemKind::Card
            && card.is_none()
            && notes.is_empty()
            && fields.is_empty()
            && d.title.trim().is_empty()
        {
            self.skip(label, tr!("import.skip.empty_card"));
            return;
        }
        if d.kind == ItemKind::Identity
            && identity.is_none()
            && notes.is_empty()
            && fields.is_empty()
            && d.title.trim().is_empty()
        {
            self.skip(label, tr!("import.skip.empty_identity"));
            return;
        }
        let mut title = d.title.trim().to_string();
        if title.is_empty() {
            title = urls
                .iter()
                .find_map(|u| crate::registrable_domain(u.clone()))
                .or_else(|| {
                    totp.as_deref()
                        .and_then(|t| crate::totp_parse(t.to_string()).ok())
                        .and_then(|c| c.issuer)
                })
                .unwrap_or_else(|| match d.kind {
                    ItemKind::Card => card
                        .as_ref()
                        .map(|c| {
                            let brand = c.brand.clone();
                            let brand = if brand.is_empty() {
                                crate::card_brand(c.number.clone())
                            } else {
                                brand
                            };
                            let last4 = c.last4();
                            match (brand.is_empty(), last4.is_empty()) {
                                (false, false) => format!("{} •••• {last4}", brand_name(&brand)),
                                (true, false) => tr!("model.card_title", last4 = last4),
                                (false, true) => brand_name(&brand),
                                (true, true) => tr!("import.title.card"),
                            }
                        })
                        .unwrap_or_else(|| tr!("import.title.card")),
                    ItemKind::Identity => identity
                        .as_ref()
                        .map(IdentityData::full_name)
                        .filter(|n| !n.is_empty())
                        .unwrap_or_else(|| tr!("import.title.identity")),
                    _ if !username.is_empty() => username.clone(),
                    ItemKind::Note => tr!("import.title.note"),
                    ItemKind::Login => tr!("import.title.login"),
                });
        }
        self.seen += 1;
        self.items.push(Item {
            kind: d.kind,
            title,
            username: if d.kind == ItemKind::Login {
                username
            } else {
                String::new()
            },
            password: if d.kind == ItemKind::Login {
                password
            } else {
                String::new()
            },
            urls: if d.kind == ItemKind::Login {
                urls
            } else {
                Vec::new()
            },
            totp: totp.filter(|_| d.kind == ItemKind::Login),
            passkeys: d.passkeys,
            notes,
            favorite: d.favorite,
            created_at: d.created_at.max(0),
            updated_at: d.updated_at.max(0),
            card: card.filter(|_| d.kind == ItemKind::Card),
            identity: identity.filter(|_| d.kind == ItemKind::Identity),
            fields,
            tags: crate::model::normalize_tags(&d.tags),
            ..Default::default()
        });
    }
}

/// Validates a TOTP value; `Ok(None)` when there is none.
pub(crate) fn normalize_totp(raw: &str) -> std::result::Result<Option<String>, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    if starts_with_ci(raw, "steam://") {
        return Err(tr!("import.steam_unsupported"));
    }
    if starts_with_ci(raw, "otpauth://") {
        return crate::totp_parse(raw.to_string())
            .map(|_| Some(raw.to_string()))
            .map_err(|e| short_error(&e));
    }
    let secret: String = raw
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_uppercase();
    crate::totp_parse(secret.clone())
        .map(|_| Some(secret))
        .map_err(|e| short_error(&e))
}

pub(crate) fn short_error(e: &PassError) -> String {
    match e {
        PassError::InvalidInput(m) | PassError::Corrupt(m) | PassError::Crypto(m) => m.clone(),
        other => other.to_string(),
    }
}

/// Seconds or milliseconds since the epoch (as exports mix both) → milliseconds.
pub(crate) fn epoch_to_ms(v: i64) -> i64 {
    if v <= 0 {
        0
    } else if v < 100_000_000_000 {
        v.saturating_mul(1000)
    } else {
        v
    }
}

/// `2024-05-01T12:34:56.789Z` (RFC 3339) → Unix milliseconds; 0 if unparsable.
pub(crate) fn iso8601_to_ms(s: &str) -> i64 {
    fn num(s: &str) -> Option<i64> {
        s.parse().ok()
    }
    let s = s.trim();
    let parse = || -> Option<i64> {
        let date = s.get(0..10)?;
        let y = num(date.get(0..4)?)?;
        let m = num(date.get(5..7)?)?;
        let d = num(date.get(8..10)?)?;
        if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
            return None;
        }
        let (mut hh, mut mm, mut ss) = (0, 0, 0);
        if let Some(time) = s.get(11..19) {
            hh = num(time.get(0..2)?)?;
            mm = num(time.get(3..5)?)?;
            ss = num(time.get(6..8)?)?;
        }
        // Days from civil (Howard Hinnant's algorithm).
        let y = if m <= 2 { y - 1 } else { y };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400;
        let mp = (m + 9) % 12;
        let doy = (153 * mp + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146_097 + doe - 719_468;
        Some(((days * 24 + hh) * 60 + mm) * 60 * 1000 + ss * 1000)
    };
    parse().filter(|v| *v > 0).unwrap_or(0)
}
