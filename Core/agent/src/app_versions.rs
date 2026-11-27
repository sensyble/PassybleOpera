//! Forced and recommended app updates, from the per-platform version document at [`ENDPOINT`].
//!
//! This module has no network code: the app fetches the document and hands the body here. A
//! missing or malformed value never blocks, and a failed fetch keeps the last good answer.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The version document's URL.
pub const ENDPOINT: &str = "https://account.passyble.com/api/app-versions";
/// The document version this code reads (`"v"`).
pub const DOCUMENT_VERSION: u64 = 1;
/// The admin's message is cut to this many characters.
pub const MESSAGE_MAX: usize = 280;
/// Answers longer than this are not version documents.
pub const MAX_BODY: usize = 64 * 1024;

/// A `MAJOR.MINOR.PATCH` version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl Version {
    /// Parses `1.2.3`, ignoring a `-prerelease` or `+build` suffix. `None` for anything else.
    pub fn parse(text: &str) -> Option<Version> {
        let text = text.trim();
        let core = text.split(['-', '+']).next().unwrap_or_default();
        // A suffix needs something after its marker ("1.2.3-" is malformed).
        if core.len() != text.len() && core.len() + 1 == text.len() {
            return None;
        }
        let mut parts = core.split('.');
        let mut number = || -> Option<u64> {
            let part = parts.next()?;
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            part.parse().ok()
        };
        let version = Version {
            major: number()?,
            minor: number()?,
            patch: number()?,
        };
        parts.next().is_none().then_some(version)
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// One platform's entry, with malformed values already dropped.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    pub minimum: Option<Version>,
    pub recommended: Option<Version>,
    /// Plain text (never HTML), at most [`MESSAGE_MAX`] characters, `None` when empty.
    pub message: Option<String>,
}

/// What the app shows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Requirement {
    /// Nothing to show (up to date, no requirement, or no data).
    None,
    /// Below the recommended version: the dismissible "Update available" banner.
    Recommended {
        version: String,
        message: Option<String>,
    },
    /// Below the minimum: the "Update required" screen and read-only mode.
    Required {
        minimum: String,
        message: Option<String>,
    },
}

impl Requirement {
    pub fn is_required(&self) -> bool {
        matches!(self, Requirement::Required { .. })
    }
}

/// The admin's message on one line, whitespace collapsed and cut to [`MESSAGE_MAX`] characters.
/// The apps show it as text, never as markup.
pub fn clean_message(text: &str) -> Option<String> {
    let spaced: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let joined = spaced.split_whitespace().collect::<Vec<_>>().join(" ");
    let cut: String = joined.chars().take(MESSAGE_MAX).collect();
    let cut = cut.trim_end().to_string();
    (!cut.is_empty()).then_some(cut)
}

/// The document, if `body` is JSON with `"v": 1` and a `platforms` object.
pub fn parse_document(body: &str) -> Option<Value> {
    if body.len() > MAX_BODY {
        return None;
    }
    let doc: Value = serde_json::from_str(body).ok()?;
    if doc.get("v").and_then(Value::as_u64) != Some(DOCUMENT_VERSION) {
        return None;
    }
    doc.get("platforms")?.as_object()?;
    Some(doc)
}

/// `platform`'s policy in a document. Missing or malformed values are no requirement.
pub fn policy_for(doc: &Value, platform: &str) -> Policy {
    let Some(entry) = doc
        .get("platforms")
        .and_then(|p| p.get(platform))
        .and_then(Value::as_object)
    else {
        return Policy::default();
    };
    let version = |key: &str| entry.get(key).and_then(Value::as_str).and_then(Version::parse);
    Policy {
        minimum: version("minimum"),
        recommended: version("recommended"),
        message: entry
            .get("message")
            .and_then(Value::as_str)
            .and_then(clean_message),
    }
}

/// What `current` (this app's version) must show under `policy`. A `current` that is not a
/// version never blocks.
pub fn evaluate(current: &str, policy: &Policy) -> Requirement {
    let Some(current) = Version::parse(current) else {
        return Requirement::None;
    };
    if let Some(minimum) = policy.minimum.filter(|m| current < *m) {
        return Requirement::Required {
            minimum: minimum.to_string(),
            message: policy.message.clone(),
        };
    }
    if let Some(recommended) = policy.recommended.filter(|r| current < *r) {
        return Requirement::Recommended {
            version: recommended.to_string(),
            message: policy.message.clone(),
        };
    }
    Requirement::None
}

/// The last good answer, kept on disk between runs, plus the recommended version whose banner
/// the user closed.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Cache {
    /// When [`Cache::document`] was fetched (Unix ms).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fetched_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document: Option<Value>,
    /// The banner was closed for this recommended version; it shows again only for a higher one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dismissed: Option<String>,
}

impl Cache {
    /// Records a fetch: `Some(body)` for an HTTP 200 answer, `None` for a failure. Only a good
    /// document replaces the cached one. Returns `true` if it was replaced.
    pub fn record(&mut self, body: Option<&str>, now_ms: i64) -> bool {
        match body.and_then(parse_document) {
            Some(doc) => {
                self.document = Some(doc);
                self.fetched_ms = Some(now_ms);
                true
            }
            None => false,
        }
    }

    /// `platform`'s policy from the cached document; none without one.
    pub fn policy(&self, platform: &str) -> Policy {
        self.document
            .as_ref()
            // A cache file edited by hand is checked like an answer.
            .filter(|doc| doc.get("v").and_then(Value::as_u64) == Some(DOCUMENT_VERSION))
            .map(|doc| policy_for(doc, platform))
            .unwrap_or_default()
    }

    /// [`evaluate`] against the cached document. Nothing cached: [`Requirement::None`].
    pub fn requirement(&self, current: &str, platform: &str) -> Requirement {
        evaluate(current, &self.policy(platform))
    }

    /// Whether the banner for recommended `version` was closed.
    pub fn is_dismissed(&self, version: &str) -> bool {
        self.dismissed.as_deref() == Some(version)
    }

    /// Reads `path`; a missing or unreadable file is an empty cache (never a block).
    #[cfg(feature = "native")]
    pub fn load(path: &std::path::Path) -> Cache {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    /// Writes `path` through a temporary file, so a crash leaves the old one.
    #[cfg(feature = "native")]
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let text = serde_json::to_string(self).map_err(std::io::Error::other)?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn v(text: &str) -> Option<Version> {
        Version::parse(text)
    }

    #[test]
    fn versions_compare_numerically() {
        assert!(v("0.10.0") > v("0.9.9"));
        assert!(v("1.0.0") > v("0.99.99"));
        assert!(v("0.1.10") > v("0.1.9"));
        assert_eq!(v("01.002.3"), v("1.2.3"));
        assert_eq!(v(" 1.2.3 "), v("1.2.3"));
        assert_eq!(
            v("18446744073709551615.0.0").map(|x| x.major),
            Some(u64::MAX)
        );
    }

    #[test]
    fn suffixes_are_ignored_on_both_sides() {
        assert_eq!(v("1.2.3-beta.1"), v("1.2.3"));
        assert_eq!(v("1.2.3+build.7"), v("1.2.3"));
        assert_eq!(v("1.2.3-rc.1+build.7"), v("1.2.3"));
        let policy = Policy {
            minimum: v("0.2.0-beta"),
            ..Default::default()
        };
        assert_eq!(evaluate("0.2.0-alpha", &policy), Requirement::None);
        assert!(evaluate("0.1.9+x", &policy).is_required());
    }

    #[test]
    fn malformed_versions_are_none() {
        for bad in [
            "", " ", "1", "1.2", "1.2.3.4", "v1.2.3", "1.2.x", "1..3", ".1.2", "1.2.", "-1.2.3",
            "1.-2.3", "1.2.3-", "1.2.3+", "+1.2.3", "1.2.3 4", "1,2,3", "１.2.3",
            "18446744073709551616.0.0",
        ] {
            assert_eq!(v(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn requirements_follow_minimum_then_recommended() {
        let policy = Policy {
            minimum: v("0.2.0"),
            recommended: v("0.3.0"),
            message: Some("Security fix".into()),
        };
        assert_eq!(
            evaluate("0.1.9", &policy),
            Requirement::Required {
                minimum: "0.2.0".into(),
                message: Some("Security fix".into())
            }
        );
        assert_eq!(
            evaluate("0.2.0", &policy),
            Requirement::Recommended {
                version: "0.3.0".into(),
                message: Some("Security fix".into())
            }
        );
        assert_eq!(evaluate("0.3.0", &policy), Requirement::None);
        assert_eq!(evaluate("1.0.0", &policy), Requirement::None);
        // This app's own version unreadable: never a block.
        assert_eq!(evaluate("dev", &policy), Requirement::None);
        // A minimum above the recommended version still blocks.
        let odd = Policy {
            minimum: v("2.0.0"),
            recommended: v("1.0.0"),
            message: None,
        };
        assert!(evaluate("1.5.0", &odd).is_required());
    }

    #[test]
    fn documents_are_checked() {
        let good = r#"{"v":1,"platforms":{"windows":{"minimum":"0.1.0","recommended":"0.1.2","message":"Hi"}}}"#;
        assert!(parse_document(good).is_some());
        for bad in [
            "",
            "<html>502</html>",
            r#"{"platforms":{}}"#,
            r#"{"v":2,"platforms":{}}"#,
            r#"{"v":"1","platforms":{}}"#,
            r#"{"v":1}"#,
            r#"{"v":1,"platforms":[]}"#,
            r#"{"v":1,"platforms":{"windows":{"minimum":"0.1.0"}"#,
            "[1]",
        ] {
            assert!(parse_document(bad).is_none(), "{bad:?}");
        }
        let huge = format!(
            r#"{{"v":1,"platforms":{{}},"pad":"{}"}}"#,
            "x".repeat(MAX_BODY)
        );
        assert!(parse_document(&huge).is_none());
    }

    #[test]
    fn missing_null_and_malformed_fields_are_no_requirement() {
        let doc = json!({ "v": 1, "platforms": {
            "windows": { "minimum": null, "recommended": "0.2" },
            "linux": { "minimum": 5, "recommended": ["1.0.0"], "message": 7 },
            "macos": "1.0.0",
            "ios": {},
        }});
        for platform in ["windows", "linux", "macos", "ios", "android", "extension-chrome"] {
            assert_eq!(
                policy_for(&doc, platform),
                Policy::default(),
                "{platform}"
            );
            assert_eq!(
                evaluate("0.0.1", &policy_for(&doc, platform)),
                Requirement::None
            );
        }
        // One malformed field doesn't hide a good one.
        let doc = json!({ "v": 1, "platforms": { "windows": { "minimum": "bad", "recommended": "0.5.0" } } });
        assert_eq!(
            evaluate("0.4.0", &policy_for(&doc, "windows")),
            Requirement::Recommended {
                version: "0.5.0".into(),
                message: None
            }
        );
    }

    #[test]
    fn messages_are_plain_one_line_text_cut_to_280() {
        assert_eq!(
            clean_message("  Update\nnow\t please \u{7}"),
            Some("Update now please".into())
        );
        assert_eq!(clean_message(" \n "), None);
        let long = "é".repeat(400);
        assert_eq!(
            clean_message(&long).map(|m| m.chars().count()),
            Some(MESSAGE_MAX)
        );
        // Markup stays text: the apps never render it.
        assert_eq!(
            clean_message("<b>Hi</b>").as_deref(),
            Some("<b>Hi</b>")
        );
    }

    #[test]
    fn the_cache_keeps_the_last_good_answer() {
        let mut cache = Cache::default();
        // Nothing ever fetched: never a block.
        assert_eq!(cache.requirement("0.0.1", "windows"), Requirement::None);
        assert!(!cache.record(None, 1));
        assert_eq!(cache.requirement("0.0.1", "windows"), Requirement::None);
        assert!(!cache.record(Some("<html>oops</html>"), 2));
        assert_eq!(cache, Cache::default());

        let doc = r#"{"v":1,"platforms":{"windows":{"minimum":"0.2.0"}}}"#;
        assert!(cache.record(Some(doc), 10));
        assert_eq!(cache.fetched_ms, Some(10));
        assert!(cache.requirement("0.1.0", "windows").is_required());
        assert_eq!(cache.requirement("0.1.0", "linux"), Requirement::None);

        // A failed fetch, or a bad answer, keeps the cached one (and its time).
        assert!(!cache.record(None, 20));
        assert!(!cache.record(Some("{}"), 30));
        assert_eq!(cache.fetched_ms, Some(10));
        assert!(cache.requirement("0.1.0", "windows").is_required());

        // A good answer without the requirement lifts it.
        assert!(cache.record(Some(r#"{"v":1,"platforms":{}}"#), 40));
        assert_eq!(cache.requirement("0.1.0", "windows"), Requirement::None);
    }

    #[test]
    fn dismissal_is_per_recommended_version() {
        let mut cache = Cache::default();
        assert!(!cache.is_dismissed("0.3.0"));
        cache.dismissed = Some("0.3.0".into());
        assert!(cache.is_dismissed("0.3.0"));
        assert!(!cache.is_dismissed("0.4.0"));
    }

    #[cfg(feature = "native")]
    #[test]
    fn the_cache_file_round_trips_and_a_bad_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("app-versions.json");
        assert_eq!(Cache::load(&path), Cache::default());
        let mut cache = Cache {
            dismissed: Some("0.3.0".into()),
            ..Default::default()
        };
        cache.record(
            Some(r#"{"v":1,"platforms":{"linux":{"minimum":"9.0.0","message":"Hi"}}}"#),
            5,
        );
        cache.save(&path).unwrap();
        let back = Cache::load(&path);
        assert_eq!(back, cache);
        assert!(back.requirement("1.0.0", "linux").is_required());

        std::fs::write(&path, "not json").unwrap();
        assert_eq!(Cache::load(&path), Cache::default());
        // A document edited into another version is ignored.
        std::fs::write(
            &path,
            r#"{"document":{"v":2,"platforms":{"linux":{"minimum":"9.0.0"}}}}"#,
        )
        .unwrap();
        assert_eq!(
            Cache::load(&path).requirement("1.0.0", "linux"),
            Requirement::None
        );
    }
}
