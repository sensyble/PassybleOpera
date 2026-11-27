//! ZIP exports: 1Password `.1pux`, Proton Pass and Dashlane (a ZIP of CSV files).
//! Encrypted members and Proton Pass' `data.pgp` are read with the export's password.

use std::io::{Cursor, Read};

use zeroize::Zeroizing;
use zip::ZipArchive;

use super::encrypted::{password_needed, Kind, Unlock};
use super::{invalid, json_formats, parse_json, Collector, ImportFormat, MAX_IMPORT_BYTES};
use crate::i18n::tr;
use crate::{PassError, Result};

/// Most members looked at in one archive.
const MAX_MEMBERS: usize = 10_000;

type Archive<'a> = ZipArchive<Cursor<&'a [u8]>>;

/// A member: index, name (with `/`), encrypted.
type Member = (usize, String, bool);

/// The ZIP library's reason is not for the user.
fn unreadable(_: &dyn std::fmt::Display) -> PassError {
    invalid(tr!("import.zip_unreadable"))
}

/// Reads one member, never more than `limit` bytes whatever its header claims (zip-bomb guard).
/// An encrypted member is read with `password` (`InvalidPassword` if it doesn't open).
pub(super) fn read_member(
    archive: &mut Archive<'_>,
    index: usize,
    limit: usize,
    password: Option<&str>,
) -> Result<Vec<u8>> {
    let mut file = match password {
        Some(pw) => archive
            .by_index_decrypt(index, pw.as_bytes())
            .map_err(|e| match e {
                zip::result::ZipError::InvalidPassword => PassError::InvalidPassword,
                other => unreadable(&other),
            })?,
        None => archive.by_index(index).map_err(|e| unreadable(&e))?,
    };
    let encrypted = file.encrypted();
    let mut out = Vec::new();
    (&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| {
            // ZipCrypto checks only one byte of the password up front: a wrong one that slips
            // through fails here (inflate or CRC error).
            if encrypted {
                PassError::InvalidPassword
            } else {
                unreadable(&e)
            }
        })?;
    if out.len() > limit {
        return Err(invalid(tr!("import.zip_member_too_large")));
    }
    Ok(out)
}

fn utf8(bytes: &[u8]) -> Result<String> {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    String::from_utf8(bytes.to_vec()).map_err(|_| invalid(tr!("import.zip_member_not_utf8")))
}

/// The members of an archive, without directories.
fn members(archive: &mut Archive<'_>) -> Result<Vec<Member>> {
    if archive.len() > MAX_MEMBERS {
        return Err(invalid(tr!("import.zip_too_many_files")));
    }
    let mut names = Vec::with_capacity(archive.len());
    for i in 0..archive.len() {
        let file = archive.by_index_raw(i).map_err(|e| unreadable(&e))?;
        if file.is_dir() {
            continue;
        }
        // A member name the ZIP library can't decode makes the archive unreadable.
        let name = file.name().map_err(|e| unreadable(&e))?.replace('\\', "/");
        names.push((i, name, file.encrypted()));
    }
    Ok(names)
}

fn is_pgp_member(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".pgp")
}

/// Whether a ZIP needs a password: Proton Pass' `data.pgp`, or encrypted members.
pub(crate) fn encryption(data: &[u8]) -> Option<Kind> {
    let mut archive = ZipArchive::new(Cursor::new(data)).ok()?;
    let names = members(&mut archive).ok()?;
    if names.iter().any(|(_, n, _)| is_pgp_member(n)) {
        return cfg!(feature = "import-pgp").then_some(Kind::ProtonZip);
    }
    names.iter().any(|(_, _, enc)| *enc).then_some(Kind::Zip)
}

pub(crate) fn parse_zip(
    data: &[u8],
    format: Option<ImportFormat>,
    c: &mut Collector,
    unlock: Option<&Unlock<'_>>,
) -> Result<ImportFormat> {
    let mut archive = ZipArchive::new(Cursor::new(data)).map_err(|e| unreadable(&e))?;
    let names = members(&mut archive)?;
    let find = |pred: &dyn Fn(&str) -> bool| names.iter().find(|(_, n, _)| pred(n)).cloned();
    let password = unlock.map(|u| u.password).filter(|p| !p.is_empty());
    let password_for = |entry: &Member| -> Result<Option<&str>> {
        match (entry.2, password) {
            (false, _) => Ok(None),
            (true, Some(pw)) => Ok(Some(pw)),
            (true, None) => Err(password_needed(Kind::Zip)),
        }
    };
    let member_text = |archive: &mut Archive<'_>, entry: &Member| -> Result<Zeroizing<String>> {
        let bytes = Zeroizing::new(read_member(
            archive,
            entry.0,
            MAX_IMPORT_BYTES,
            password_for(entry)?,
        )?);
        utf8(&bytes).map(Zeroizing::new)
    };

    // 1Password .1pux
    if let Some(entry) = find(&|n| n == "export.data" || n.ends_with("/export.data")) {
        if format.is_some_and(|f| f != ImportFormat::OnePassword) {
            return Err(wrong_format(format));
        }
        let value = parse_json(&member_text(&mut archive, &entry)?)?;
        json_formats::parse(&value, ImportFormat::OnePassword, c)?;
        return Ok(ImportFormat::OnePassword);
    }
    // Proton Pass: "Proton Pass/data.json", or data.pgp when passphrase-encrypted.
    if let Some(entry) = find(&|n| is_pgp_member(n)) {
        if format.is_some_and(|f| f != ImportFormat::ProtonPass) {
            return Err(wrong_format(format));
        }
        let pw = password.ok_or_else(|| password_needed(Kind::ProtonZip))?;
        let sealed = read_member(
            &mut archive,
            entry.0,
            MAX_IMPORT_BYTES,
            password_for(&entry)?,
        )?;
        let plain = super::pgp::decrypt(&sealed, pw)?;
        let value = parse_json(&Zeroizing::new(utf8(&plain)?))?;
        json_formats::parse(&value, ImportFormat::ProtonPass, c)?;
        return Ok(ImportFormat::ProtonPass);
    }
    if let Some(entry) = find(&|n| n == "data.json" || n.ends_with("/data.json")) {
        if format.is_some_and(|f| f != ImportFormat::ProtonPass) {
            return Err(wrong_format(format));
        }
        let value = parse_json(&member_text(&mut archive, &entry)?)?;
        json_formats::parse(&value, ImportFormat::ProtonPass, c)?;
        return Ok(ImportFormat::ProtonPass);
    }
    // Anything else: a ZIP of CSV / JSON exports (Dashlane, or a zipped export). Read each.
    let mut detected = None;
    let mut errors = Vec::new();
    let mut total = 0usize;
    for entry in &names {
        let lower = entry.1.to_ascii_lowercase();
        if !(lower.ends_with(".csv") || lower.ends_with(".json") || lower.ends_with(".txt")) {
            continue;
        }
        let text = member_text(&mut archive, entry)?;
        total += text.len();
        if total > MAX_IMPORT_BYTES {
            return Err(invalid(tr!("import.zip_too_large")));
        }
        let mut sub = Collector::default();
        // A member may be an encrypted export of its own (say a Bitwarden JSON with a file
        // password): it is opened with the same password.
        match super::parse_text(&text, &entry.1, format, &mut sub, unlock) {
            Ok(f) => {
                detected.get_or_insert(f);
                c.merge(sub);
            }
            // A wrong password is not a member that "couldn't be imported": ask again.
            Err(PassError::InvalidPassword) => return Err(PassError::InvalidPassword),
            Err(e) => errors.push(format!("{}: {}", entry.1, super::short_error(&e))),
        }
    }
    match detected {
        Some(f) => {
            for e in errors {
                c.warn(tr!("import.zip_not_imported", detail = e));
            }
            Ok(f)
        }
        None => Err(invalid(match errors.first() {
            Some(e) => tr!("import.zip_nothing_imported", detail = e),
            None => tr!("import.zip_unknown"),
        })),
    }
}

fn wrong_format(format: Option<ImportFormat>) -> crate::PassError {
    invalid(match format {
        Some(f) => tr!("import.zip_wrong_format", format = f.name()),
        None => tr!("import.zip_unsupported"),
    })
}
