//! How the 2FA step went on each site after a fill, so the extension stops offering a code on
//! sites that usually don't ask for one. An attempt keeps its strongest outcome (`used` > `asked`
//! > `skipped`). Sites are keyed by a salted SHA-256 of their registrable domain and the file
//! holds nothing else. It is device-local and never synced.

use std::collections::{HashMap, VecDeque};
#[cfg(feature = "native")]
use std::fs;
#[cfg(feature = "native")]
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use crate::clock::Instant;

use pass_core::{registrable_domain, sha256};
use serde::{Deserialize, Serialize};

use crate::Agent;

/// Outcomes kept per site.
pub const HISTORY_LEN: usize = 5;
/// Sites kept in the file; the least recently updated go first.
pub const MAX_SITES: usize = 500;
/// How long after a fill its 2FA outcome is still taken.
pub const ATTEMPT_WINDOW: Duration = Duration::from_secs(300);

const FILE_VERSION: u32 = 1;
const KEY_PREFIX: &[u8] = b"senpass-otp-history\0";

/// How the 2FA step went after one fill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OtpOutcome {
    /// Signed in without being asked for a code.
    Skipped,
    /// The 2FA step showed up.
    Asked,
    /// The code was filled or copied.
    Used,
}

impl OtpOutcome {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "skipped" => Some(Self::Skipped),
            "asked" => Some(Self::Asked),
            "used" => Some(Self::Used),
            _ => None,
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Skipped => 0,
            Self::Asked => 1,
            Self::Used => 2,
        }
    }

    fn code(self) -> char {
        match self {
            Self::Skipped => 's',
            Self::Asked => 'a',
            Self::Used => 'u',
        }
    }

    fn from_code(c: char) -> Option<Self> {
        match c {
            's' => Some(Self::Skipped),
            'a' => Some(Self::Asked),
            'u' => Some(Self::Used),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Site {
    outcomes: VecDeque<OtpOutcome>,
    /// Unix seconds of the last change (eviction order).
    updated: u64,
}

struct Attempt {
    started: Instant,
    recorded: bool,
}

/// On-disk form: `{"version":1,"sites":{"<hex sha-256>":{"o":"ssau","t":1700000000}}}`.
#[derive(Serialize, Deserialize)]
struct FileData {
    version: u32,
    sites: HashMap<String, FileSite>,
}

#[derive(Serialize, Deserialize)]
struct FileSite {
    o: String,
    t: u64,
}

#[derive(Default)]
pub struct OtpHistory {
    path: Option<PathBuf>,
    loaded: bool,
    sites: HashMap<String, Site>,
    /// Open attempts by site key (memory only).
    attempts: HashMap<String, Attempt>,
}

/// The key a site is stored under: hex SHA-256 of its registrable domain. `None` for a URL without one.
pub fn site_key(url: &str) -> Option<String> {
    let domain = registrable_domain(url.to_string())?;
    let mut data = KEY_PREFIX.to_vec();
    data.extend_from_slice(domain.to_ascii_lowercase().as_bytes());
    Some(sha256(data).iter().map(|b| format!("{b:02x}")).collect())
}

impl OtpHistory {
    /// The file to keep the history in (`None` for memory only). Read on first use.
    pub fn set_path(&mut self, path: Option<PathBuf>) {
        if self.path != path {
            self.path = path;
            self.loaded = false;
            self.sites.clear();
        }
    }

    /// A login with a 2FA secret was just filled on `url`: its outcome is expected.
    #[cfg(test)]
    pub fn begin(&mut self, url: &str) {
        self.begin_at(url, Instant::now());
    }

    /// [`OtpHistory::begin`] at `now` (the agent's clock).
    pub(crate) fn begin_at(&mut self, url: &str, now: Instant) {
        let Some(key) = site_key(url) else { return };
        self.attempts
            .retain(|_, a| now.duration_since(a.started) <= ATTEMPT_WINDOW);
        self.attempts.insert(
            key,
            Attempt {
                started: now,
                recorded: false,
            },
        );
    }

    /// Takes the outcome of the open attempt on `url`'s site. Returns whether it was taken.
    #[cfg(test)]
    pub fn record(&mut self, url: &str, outcome: OtpOutcome) -> bool {
        let unix_secs = crate::clock::SystemTime::now()
            .duration_since(crate::clock::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.record_at(url, outcome, Instant::now(), unix_secs)
    }

    /// [`OtpHistory::record`] at `now` (the agent's clock), `unix_secs` being the wall clock.
    pub(crate) fn record_at(
        &mut self,
        url: &str,
        outcome: OtpOutcome,
        now: Instant,
        unix_secs: u64,
    ) -> bool {
        let Some(key) = site_key(url) else {
            return false;
        };
        let Some(attempt) = self.attempts.get_mut(&key) else {
            return false;
        };
        if now.duration_since(attempt.started) > ATTEMPT_WINDOW {
            self.attempts.remove(&key);
            return false;
        }
        let first = !attempt.recorded;
        attempt.recorded = true;
        self.load();
        let site = self.sites.entry(key).or_default();
        match site.outcomes.back_mut() {
            Some(last) if !first => {
                if outcome.rank() <= last.rank() {
                    return true; // the attempt already has this, or something stronger
                }
                *last = outcome;
            }
            _ => {
                site.outcomes.push_back(outcome);
                while site.outcomes.len() > HISTORY_LEN {
                    site.outcomes.pop_front();
                }
            }
        }
        site.updated = unix_secs;
        self.prune();
        self.save();
        true
    }

    /// The last two sign-ins on `url`'s site skipped the 2FA step.
    pub fn skips_2fa(&mut self, url: &str) -> bool {
        let Some(key) = site_key(url) else {
            return false;
        };
        self.load();
        self.sites.get(&key).is_some_and(|site| {
            site.outcomes.len() >= 2
                && site
                    .outcomes
                    .iter()
                    .rev()
                    .take(2)
                    .all(|o| *o == OtpOutcome::Skipped)
        })
    }

    /// The outcomes kept for `url`'s site, oldest first.
    pub fn outcomes(&mut self, url: &str) -> Vec<OtpOutcome> {
        let Some(key) = site_key(url) else {
            return Vec::new();
        };
        self.load();
        self.sites
            .get(&key)
            .map(|s| s.outcomes.iter().copied().collect())
            .unwrap_or_default()
    }

    fn prune(&mut self) {
        if self.sites.len() <= MAX_SITES {
            return;
        }
        let mut by_age: Vec<(u64, String)> = self
            .sites
            .iter()
            .map(|(k, s)| (s.updated, k.clone()))
            .collect();
        by_age.sort();
        let excess = self.sites.len() - MAX_SITES;
        for (_, key) in by_age.into_iter().take(excess) {
            self.sites.remove(&key);
        }
    }

    fn load(&mut self) {
        if self.loaded {
            return;
        }
        self.loaded = true;
        let Some(bytes) = self.read_file() else {
            return;
        };
        let Ok(data) = serde_json::from_slice::<FileData>(&bytes) else {
            return;
        };
        if data.version != FILE_VERSION {
            return;
        }
        for (key, site) in data.sites {
            let valid_key = key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit());
            let outcomes: Option<VecDeque<OtpOutcome>> =
                site.o.chars().map(OtpOutcome::from_code).collect();
            if let (true, Some(mut outcomes)) = (valid_key, outcomes) {
                while outcomes.len() > HISTORY_LEN {
                    outcomes.pop_front();
                }
                self.sites.insert(
                    key.to_ascii_lowercase(),
                    Site {
                        outcomes,
                        updated: site.t,
                    },
                );
            }
        }
        self.prune();
    }

    fn read_file(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "native")]
        if let Some(path) = &self.path {
            return fs::read(path).ok();
        }
        None
    }

    fn save(&self) {
        let Some(path) = &self.path else { return };
        let data = FileData {
            version: FILE_VERSION,
            sites: self
                .sites
                .iter()
                .map(|(k, s)| {
                    (
                        k.clone(),
                        FileSite {
                            o: s.outcomes.iter().map(|o| o.code()).collect(),
                            t: s.updated,
                        },
                    )
                })
                .collect(),
        };
        if let Ok(bytes) = serde_json::to_vec(&data) {
            // Best effort: losing the history only means one more proactive offer.
            #[cfg(feature = "native")]
            let _ = write_replace(path, &bytes);
            #[cfg(not(feature = "native"))]
            let _ = (path, bytes);
        }
    }
}

#[cfg(feature = "native")]
fn write_replace(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)
}

impl Agent {
    /// Where the 2FA outcome history is kept. `None` (the default) keeps it in memory only.
    pub fn set_otp_history_file(&self, path: Option<PathBuf>) {
        self.otp_history().set_path(path);
    }

    /// `otp.outcome`: how the 2FA step went after the last fill on `url`'s site.
    pub fn otp_outcome(&self, url: &str, outcome: OtpOutcome) -> bool {
        let (now, unix_secs) = (self.now(), (self.unix_ms() / 1000).max(0) as u64);
        self.otp_history().record_at(url, outcome, now, unix_secs)
    }

    /// The last two sign-ins on `url`'s site skipped the 2FA step.
    pub fn skips_2fa(&self, url: &str) -> bool {
        self.otp_history().skips_2fa(url)
    }

    /// The 2FA outcomes kept for `url`'s site, oldest first.
    pub fn otp_outcomes(&self, url: &str) -> Vec<OtpOutcome> {
        self.otp_history().outcomes(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "https://github.com/login";

    #[test]
    fn outcomes_without_a_fill_are_ignored() {
        let mut h = OtpHistory::default();
        assert!(!h.record(URL, OtpOutcome::Skipped));
        assert!(h.outcomes(URL).is_empty());
    }

    #[test]
    fn one_outcome_per_fill_the_strongest_wins() {
        let mut h = OtpHistory::default();
        h.begin(URL);
        assert!(h.record("https://www.github.com/", OtpOutcome::Skipped));
        assert!(h.record(URL, OtpOutcome::Asked));
        assert!(h.record(URL, OtpOutcome::Skipped));
        assert_eq!(h.outcomes(URL), vec![OtpOutcome::Asked]);
        assert!(h.record(URL, OtpOutcome::Used));
        assert_eq!(h.outcomes(URL), vec![OtpOutcome::Used]);
        h.begin(URL);
        h.record(URL, OtpOutcome::Skipped);
        assert_eq!(h.outcomes(URL), vec![OtpOutcome::Used, OtpOutcome::Skipped]);
    }

    #[test]
    fn an_attempt_expires() {
        let mut h = OtpHistory::default();
        let t0 = Instant::now();
        h.begin_at(URL, t0);
        assert!(!h.record_at(
            URL,
            OtpOutcome::Skipped,
            t0 + ATTEMPT_WINDOW + Duration::from_secs(1),
            1_700_000_000
        ));
        assert!(h.outcomes(URL).is_empty());
    }

    #[test]
    fn skips_after_two_skipped_sign_ins_and_keeps_five() {
        let mut h = OtpHistory::default();
        fn sign_in(h: &mut OtpHistory, o: OtpOutcome) {
            h.begin(URL);
            h.record(URL, o);
        }
        sign_in(&mut h, OtpOutcome::Used);
        sign_in(&mut h, OtpOutcome::Skipped);
        assert!(!h.skips_2fa(URL));
        sign_in(&mut h, OtpOutcome::Skipped);
        assert!(h.skips_2fa(URL));
        assert!(!h.skips_2fa("https://gitlab.com/"), "per site");
        sign_in(&mut h, OtpOutcome::Asked);
        assert!(!h.skips_2fa(URL));
        for _ in 0..4 {
            sign_in(&mut h, OtpOutcome::Skipped);
        }
        assert_eq!(
            h.outcomes(URL),
            vec![OtpOutcome::Asked]
                .into_iter()
                .chain([OtpOutcome::Skipped; 4])
                .collect::<Vec<_>>()
        );
        sign_in(&mut h, OtpOutcome::Skipped);
        assert_eq!(h.outcomes(URL).len(), HISTORY_LEN);
    }

    #[test]
    fn keys_are_hashed_domains() {
        let key = site_key("https://accounts.github.com/x").unwrap();
        assert_eq!(key.len(), 64);
        assert_eq!(Some(key.clone()), site_key("github.com"));
        assert!(!key.contains("github"));
        assert_eq!(site_key("not a url at all"), None);
    }

    #[cfg(feature = "native")]
    #[test]
    fn the_file_round_trips_and_holds_no_domain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Pass").join("otp-history.json");
        let mut h = OtpHistory::default();
        h.set_path(Some(path.clone()));
        for _ in 0..2 {
            h.begin(URL);
            h.record(URL, OtpOutcome::Skipped);
        }
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains("github"), "{text}");
        assert!(text.contains("\"o\":\"ss\""), "{text}");
        let mut again = OtpHistory::default();
        again.set_path(Some(path.clone()));
        assert!(again.skips_2fa(URL));
        // A damaged file is ignored, not fatal.
        fs::write(&path, b"{not json").unwrap();
        let mut broken = OtpHistory::default();
        broken.set_path(Some(path));
        assert!(!broken.skips_2fa(URL));
    }

    #[test]
    fn old_sites_are_dropped_beyond_the_limit() {
        let mut h = OtpHistory::default();
        let url = |i: usize| format!("https://site{i}.example/");
        for i in 0..MAX_SITES {
            h.begin(&url(i));
            h.record(&url(i), OtpOutcome::Asked);
            h.sites
                .get_mut(&site_key(&url(i)).unwrap())
                .unwrap()
                .updated = i as u64;
        }
        for i in MAX_SITES..MAX_SITES + 3 {
            h.begin(&url(i));
            h.record(&url(i), OtpOutcome::Asked);
        }
        assert_eq!(h.sites.len(), MAX_SITES);
        for i in 0..3 {
            assert!(h.outcomes(&url(i)).is_empty(), "site{i} is the oldest");
        }
        assert_eq!(h.outcomes(&url(3)).len(), 1);
        assert_eq!(h.outcomes(&url(MAX_SITES + 2)).len(), 1);
    }
}
