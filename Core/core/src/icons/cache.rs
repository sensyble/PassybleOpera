//! The on-device icon cache: one file per domain, named by the hex SHA-256 of the domain + `.icon`.
//! Content: `SPI1`, a status byte (1 icon, 0 the site has none, 2 the fetch failed), the fetch time
//! (i64 Unix ms, little endian), then the PNG for status 1. Each status has its own max age, and a
//! failed refresh never discards a cached icon.

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::{fetch_with, site_icon_domain, Options};
use crate::{PassError, Result};

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
/// Refresh a cached icon after 30 days.
pub const ICON_MAX_AGE_MS: i64 = 30 * DAY_MS;
/// Ask a site with no icon again after 7 days.
pub const NONE_MAX_AGE_MS: i64 = 7 * DAY_MS;
/// Retry a site that couldn't be reached after a day.
pub const FAILED_MAX_AGE_MS: i64 = DAY_MS;

const MAGIC: &[u8; 4] = b"SPI1";
const HEADER: usize = 4 + 1 + 8;
const EXTENSION: &str = "icon";

const STATUS_NONE: u8 = 0;
const STATUS_ICON: u8 = 1;
const STATUS_FAILED: u8 = 2;

/// What the cache knows about a domain's icon.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CachedSiteIcon {
    /// The PNG to show, or `None` when the site has no usable icon (show the letter).
    pub png: Option<Vec<u8>>,
    pub fetched_at_ms: i64,
    /// Time to fetch again ([`site_icon_cache_refresh`]); `png` stays usable meanwhile.
    pub needs_refresh: bool,
}

/// The cache file name for `domain` (as returned by [`site_icon_domain`]): hex SHA-256 + `.icon`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn site_icon_cache_file_name(domain: String) -> String {
    let hash = Sha256::digest(domain.trim().to_ascii_lowercase().as_bytes());
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    format!("{hex}.{EXTENSION}")
}

fn path_for(cache_dir: &str, domain: &str) -> PathBuf {
    Path::new(cache_dir).join(site_icon_cache_file_name(domain.to_string()))
}

/// The cached entry for `domain`, or `None` if there is none (or it's unreadable): fetch it.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn site_icon_cache_read(cache_dir: String, domain: String) -> Option<CachedSiteIcon> {
    read_at(&cache_dir, &domain, crate::now_ms())
}

pub(crate) fn read_at(cache_dir: &str, domain: &str, now: i64) -> Option<CachedSiteIcon> {
    let data = fs::read(path_for(cache_dir, domain)).ok()?;
    if data.len() < HEADER || &data[..4] != MAGIC {
        return None;
    }
    let status = data[4];
    let fetched_at_ms = i64::from_le_bytes(data[5..HEADER].try_into().ok()?);
    let max_age = match status {
        STATUS_ICON if data.len() > HEADER => ICON_MAX_AGE_MS,
        STATUS_NONE => NONE_MAX_AGE_MS,
        STATUS_FAILED => FAILED_MAX_AGE_MS,
        _ => return None,
    };
    let age = now - fetched_at_ms;
    Some(CachedSiteIcon {
        png: (status == STATUS_ICON).then(|| data[HEADER..].to_vec()),
        fetched_at_ms,
        // A time in the future means the clock moved: refresh rather than trust it for years.
        needs_refresh: age >= max_age || age < -DAY_MS,
    })
}

/// Fetches `domain`'s icon now and stores the outcome. Returns the PNG to show (a previously cached
/// icon when this fetch failed), or `None`. Blocks for up to about 20 seconds.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn site_icon_cache_refresh(cache_dir: String, domain: String) -> Result<Option<Vec<u8>>> {
    let normalized = site_icon_domain(domain.clone())
        .filter(|d| *d == domain)
        .ok_or_else(|| {
            PassError::InvalidInput("not a website host; use site_icon_domain()".into())
        })?;
    refresh_with(
        &cache_dir,
        &normalized,
        &Options::default(),
        crate::now_ms(),
    )
}

pub(crate) fn refresh_with(
    cache_dir: &str,
    domain: &str,
    options: &Options,
    now: i64,
) -> Result<Option<Vec<u8>>> {
    let previous = read_at(cache_dir, domain, now).and_then(|c| c.png);
    let (status, png, fetched_at) = match fetch_with(domain, options) {
        Ok(icon) => (STATUS_ICON, Some(icon.bytes), now),
        // Keep the old icon, and try again in a day.
        Err(_) if previous.is_some() => (
            STATUS_ICON,
            previous,
            now - ICON_MAX_AGE_MS + FAILED_MAX_AGE_MS,
        ),
        Err(PassError::NotFound(_)) => (STATUS_NONE, None, now),
        Err(_) => (STATUS_FAILED, None, now),
    };
    let mut data = Vec::with_capacity(HEADER + png.as_ref().map_or(0, Vec::len));
    data.extend_from_slice(MAGIC);
    data.push(status);
    data.extend_from_slice(&fetched_at.to_le_bytes());
    if let Some(png) = &png {
        data.extend_from_slice(png);
    }
    write_atomic(cache_dir, &path_for(cache_dir, domain), &data)?;
    Ok(png)
}

fn write_atomic(dir: &str, path: &Path, data: &[u8]) -> Result<()> {
    let io = |e: std::io::Error| PassError::InvalidInput(format!("icon cache: {e}"));
    fs::create_dir_all(dir).map_err(io)?;
    let tmp = path.with_extension(format!("tmp{:08x}", rand::random::<u32>()));
    fs::write(&tmp, data).map_err(io)?;
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        io(e)
    })
}

/// Deletes every cached icon (the setting was turned off). Only this cache's own files are
/// removed; returns how many.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn site_icon_cache_clear(cache_dir: String) -> Result<u32> {
    let entries = match fs::read_dir(&cache_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(PassError::InvalidInput(format!("icon cache: {e}"))),
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some((stem, ext)) = name.split_once('.') else {
            continue;
        };
        let ours = stem.len() == 64
            && stem.bytes().all(|b| b.is_ascii_hexdigit())
            && (ext == EXTENSION || ext.starts_with("tmp"));
        if ours && fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}
