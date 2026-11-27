//! Several open vaults at once: the personal vault and the shared vaults of a team or family.
//! Search and page or app matching run over all of them in one order, as if they were one vault,
//! with the vault id on every result. Everything works on summaries, so the same calls serve
//! unlocked and soft-locked vaults.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::matching::MatchQuality;
use crate::model::ItemKind;
use crate::share::{MemberRole, SharedKind};
use crate::summary::ItemSummary;
use crate::Vault;

/// The list of one vault, for searching across vaults and for the soft lock. No secrets.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct VaultSummaries {
    pub vault_id: String,
    /// `None` for a personal vault.
    pub shared: Option<SharedKind>,
    /// This device's role in a shared vault; `None` for a personal vault.
    pub role: Option<MemberRole>,
    /// Whether items may be added and changed here (a new login can be saved here).
    pub can_edit: bool,
    /// Whether passwords may be shown and copied (`false` in a fill-only vault).
    pub can_reveal: bool,
    pub summaries: Vec<ItemSummary>,
}

/// One result of a search across vaults.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct VaultItemSummary {
    pub vault_id: String,
    pub summary: ItemSummary,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Vault {
    /// This vault's list with its place among the open vaults ([`VaultSummaries`]).
    pub fn vault_summaries(&self) -> VaultSummaries {
        let info = self.shared_info();
        VaultSummaries {
            vault_id: self.vault_id(),
            shared: info.as_ref().map(|i| i.kind),
            role: info.as_ref().map(|i| i.role),
            can_edit: self.can_edit(),
            can_reveal: self.can_reveal_secrets(),
            summaries: self.summaries(),
        }
    }
}

/// [`crate::Vault::vault_summaries`] of each open vault, in the order given.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn multi_vault_summaries(vaults: Vec<Arc<Vault>>) -> Vec<VaultSummaries> {
    vaults.iter().map(|v| v.vault_summaries()).collect()
}

/// Runs a single-vault query over every vault's summaries as one list (the ids tagged with the
/// vault's place), so the order across vaults is exactly the order within one, then gives each
/// result its vault id back.
fn across(
    groups: Vec<VaultSummaries>,
    query: impl FnOnce(Vec<ItemSummary>) -> Vec<ItemSummary>,
) -> Vec<VaultItemSummary> {
    let ids: Vec<String> = groups.iter().map(|g| g.vault_id.clone()).collect();
    let all: Vec<ItemSummary> = groups
        .into_iter()
        .enumerate()
        .flat_map(|(i, g)| {
            g.summaries.into_iter().map(move |mut s| {
                s.id = format!("{i}:{}", s.id);
                s
            })
        })
        .collect();
    query(all)
        .into_iter()
        .filter_map(|mut s| {
            let (i, id) = s.id.split_once(':')?;
            let vault_id = ids.get(i.parse::<usize>().ok()?)?.clone();
            s.id = id.to_string();
            Some(VaultItemSummary {
                vault_id,
                summary: s,
            })
        })
        .collect()
}

/// [`crate::summaries_search`] across vaults: best match first, whatever vault it is in.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn multi_search(groups: Vec<VaultSummaries>, query: String) -> Vec<VaultItemSummary> {
    across(groups, |all| crate::summaries_search(all, query))
}

/// [`crate::summaries_for_url`] across vaults: the logins for a web page, best first.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn multi_for_url(groups: Vec<VaultSummaries>, url: String) -> Vec<VaultItemSummary> {
    across(groups, |all| crate::summaries_for_url(all, url))
}

/// [`crate::summaries_for_android_app`] across vaults.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn multi_for_android_app(
    groups: Vec<VaultSummaries>,
    package: String,
    cert_sha256: Option<String>,
) -> Vec<VaultItemSummary> {
    across(groups, |all| {
        crate::summaries_for_android_app(all, package, cert_sha256)
    })
}

/// [`crate::summaries_with_passkeys`] across vaults.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn multi_with_passkeys(groups: Vec<VaultSummaries>, rp_id: String) -> Vec<VaultItemSummary> {
    across(groups, |all| crate::summaries_with_passkeys(all, rp_id))
}

/// The vault a new login for `url` is saved to by default (the save prompt lets the user pick
/// another): the vault that already has a login for that site, if this device may edit it;
/// else `preferred` (the user's choice in Settings) if it may be edited; else the first personal
/// vault; else the first shared vault that may be edited. `None` when no vault may be edited.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn multi_default_save_vault(
    groups: Vec<VaultSummaries>,
    url: Option<String>,
    preferred: Option<String>,
) -> Option<String> {
    let writable: Vec<&VaultSummaries> = groups.iter().filter(|g| g.can_edit).collect();
    if let Some(url) = url {
        let candidates: Vec<VaultSummaries> = writable.iter().map(|g| (*g).clone()).collect();
        if let Some(hit) = multi_for_url(candidates, url).into_iter().next() {
            return Some(hit.vault_id);
        }
    }
    if let Some(p) = preferred {
        if writable.iter().any(|g| g.vault_id == p) {
            return Some(p);
        }
    }
    writable
        .iter()
        .find(|g| g.shared.is_none())
        .or_else(|| writable.first())
        .map(|g| g.vault_id.clone())
}

/// The lists of the open vaults read once, for searching keystroke after keystroke. Rebuild it
/// when the lists change. Gives what [`multi_search`] and [`multi_for_url`] give over the same
/// lists, without normalizing every summary again or passing it across the bindings per call.
///
/// An item's place depends on it alone, so filtering the results (one vault, a tag, a kind) gives
/// the order a search over that part would give.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct SearchIndex {
    vault_ids: Vec<String>,
    entries: Vec<IndexEntry>,
    /// `entries` by title (lower case), for an empty query.
    by_title: Vec<usize>,
}

struct IndexEntry {
    vault: usize,
    summary: ItemSummary,
    doc: crate::search::SearchDoc,
    /// The title as the search orders it ([`crate::search::normalize`]).
    title_key: String,
    /// The website entries that can match a page, read once.
    urls: Box<[crate::matching::MatchUrl]>,
}

impl std::fmt::Debug for SearchIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchIndex")
            .field("items", &self.entries.len())
            .finish_non_exhaustive()
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl SearchIndex {
    /// Reads `groups` (as [`multi_search`] takes them) and the notes by item id (only while
    /// unlocked; empty when locked).
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new(groups: Vec<VaultSummaries>, notes: HashMap<String, String>) -> Arc<SearchIndex> {
        let mut vault_ids = Vec::with_capacity(groups.len());
        let mut entries = Vec::new();
        for (vault, group) in groups.into_iter().enumerate() {
            vault_ids.push(group.vault_id);
            for summary in group.summaries {
                let doc = crate::search::Doc::of_summary(
                    &summary,
                    notes.get(&summary.id).map(String::as_str),
                )
                .index();
                let urls = crate::matching::match_urls(&summary.urls, &summary.url_rules);
                entries.push(IndexEntry {
                    vault,
                    title_key: crate::search::normalize(&summary.title),
                    summary,
                    doc,
                    urls,
                });
            }
        }
        let mut by_title: Vec<usize> = (0..entries.len()).collect();
        by_title.sort_by_cached_key(|&i| entries[i].summary.title.to_lowercase());
        Arc::new(SearchIndex {
            vault_ids,
            entries,
            by_title,
        })
    }

    /// How many items the index holds.
    pub fn len(&self) -> u32 {
        self.entries.len() as u32
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// [`multi_search`] over the lists read (with their notes).
    pub fn search(&self, query: String) -> Vec<VaultItemSummary> {
        self.results(self.ranked(&query).into_iter())
    }

    /// [`SearchIndex::search`] as places in the lists given to [`SearchIndex::new`] (the
    /// summaries of all groups one after the other, from 0): what a list that keeps those
    /// summaries needs per keystroke, without copying them across the bindings.
    pub fn search_positions(&self, query: String) -> Vec<u32> {
        self.ranked(&query).into_iter().map(|i| i as u32).collect()
    }

    /// [`multi_for_url`] over the lists read: the logins for a web page, best first.
    pub fn for_url(&self, url: String) -> Vec<VaultItemSummary> {
        let Some(page) = crate::matching::parse_loose(&url) else {
            return Vec::new();
        };
        let page = crate::matching::MatchPage::of(&page);
        self.logins_where(|e| crate::matching::tier_of(&e.urls, &page))
    }

    /// [`multi_for_android_app`] over the lists read.
    pub fn for_android_app(
        &self,
        package: String,
        cert_sha256: Option<String>,
    ) -> Vec<VaultItemSummary> {
        let cert = cert_sha256
            .as_deref()
            .map(crate::matching::normalize_cert)
            .filter(|c| !c.is_empty());
        self.logins_where(|e| {
            crate::matching::android_app_match(
                &e.summary.android_apps,
                &e.summary.urls,
                &e.summary.url_rules,
                &package,
                cert.as_deref(),
            )
        })
    }
}

impl SearchIndex {
    /// The places of the results of `query`, in the order of [`crate::search::rank_by`] (best
    /// match first, then favorites and usage, then by title; ties keep the lists' order).
    fn ranked(&self, query: &str) -> Vec<usize> {
        let parsed = crate::search::Query::parse(query);
        if parsed.is_empty() {
            return self.by_title.clone();
        }
        let mut found: Vec<(u32, usize)> = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| Some((crate::search::score_indexed(&parsed, &e.doc)?, i)))
            .collect();
        let title = |i: usize| self.entries[i].title_key.as_str();
        if parsed.has_tokens() {
            let order = |i: usize| {
                let s = &self.entries[i].summary;
                (s.favorite, s.rank)
            };
            found.sort_by(|(sa, a), (sb, b)| {
                sb.cmp(sa)
                    .then(order(*b).cmp(&order(*a)))
                    .then_with(|| title(*a).cmp(title(*b)))
            });
        } else {
            // Tag filters only: by title, like an empty query.
            found.sort_by(|(_, a), (_, b)| title(*a).cmp(title(*b)));
        }
        found.into_iter().map(|(_, i)| i).collect()
    }

    fn results(&self, order: impl Iterator<Item = usize>) -> Vec<VaultItemSummary> {
        order
            .map(|i| {
                let e = &self.entries[i];
                VaultItemSummary {
                    vault_id: self.vault_ids[e.vault].clone(),
                    summary: e.summary.clone(),
                }
            })
            .collect()
    }

    /// As `summary::logins_where`: logins with a match, best first, then in suggestion order.
    fn logins_where(&self, score: impl Fn(&IndexEntry) -> MatchQuality) -> Vec<VaultItemSummary> {
        let mut found: Vec<(MatchQuality, usize)> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.summary.kind == ItemKind::Login)
            .filter_map(|(i, e)| {
                let q = score(e);
                (q > MatchQuality::None).then_some((q, i))
            })
            .collect();
        found.sort_by(|(qa, a), (qb, b)| {
            qb.cmp(qa).then_with(|| {
                crate::summary::suggested_order(
                    &self.entries[*a].summary,
                    &self.entries[*b].summary,
                )
            })
        });
        self.results(found.into_iter().map(|(_, i)| i))
    }
}

/// The soft-locked list read once for autofill and the Credential Manager: only what matching a
/// page, an app or a passkey's site needs (no usernames, titles only as sort keys). Keep it while
/// the vault stays soft-locked and drop it at a full lock. Results are places in that list, in
/// the order of [`crate::summaries_for_url`], [`crate::summaries_for_android_app`] and
/// [`crate::summaries_with_passkeys`].
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct KeptMatcher {
    entries: Vec<KeptEntry>,
}

/// A linked app: its package name and normalized certificate digest.
type LinkedApp = (Box<str>, Option<Box<str>>);

struct KeptEntry {
    place: u32,
    login: bool,
    favorite: bool,
    rank: i64,
    /// The title in lower case, as the suggestion order compares titles.
    title_key: Box<str>,
    urls: Box<[crate::matching::MatchUrl]>,
    apps: Box<[LinkedApp]>,
    /// `androidapp://<package>` entries, lower case.
    app_links: Box<[Box<str>]>,
    /// The passkeys' sites, lower case.
    passkey_sites: Box<[Box<str>]>,
}

impl std::fmt::Debug for KeptMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeptMatcher")
            .field("items", &self.entries.len())
            .finish_non_exhaustive()
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl KeptMatcher {
    /// Reads the kept list (as [`crate::summaries_for_url`] takes it).
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new(summaries: Vec<ItemSummary>) -> Arc<KeptMatcher> {
        let entries = summaries
            .iter()
            .enumerate()
            .filter(|(_, s)| s.kind == ItemKind::Login || !s.passkeys.is_empty())
            .map(|(place, s)| KeptEntry {
                place: place as u32,
                login: s.kind == ItemKind::Login,
                favorite: s.favorite,
                rank: s.rank,
                title_key: s.title.to_lowercase().into_boxed_str(),
                urls: crate::matching::match_urls(&s.urls, &s.url_rules),
                apps: s
                    .android_apps
                    .iter()
                    .filter(|a| !a.never_show)
                    .map(|a| {
                        (
                            a.package.clone().into_boxed_str(),
                            a.cert_sha256
                                .as_deref()
                                .map(|c| crate::matching::normalize_cert(c).into_boxed_str()),
                        )
                    })
                    .collect(),
                app_links: s
                    .urls
                    .iter()
                    .filter(|u| crate::url_rule_of(&s.url_rules, u) != crate::UrlMatch::Never)
                    .map(|u| u.trim().to_ascii_lowercase())
                    .filter(|u| u.starts_with("androidapp://"))
                    .map(String::into_boxed_str)
                    .collect(),
                passkey_sites: s
                    .passkeys
                    .iter()
                    .map(|p| p.rp_id.to_ascii_lowercase().into_boxed_str())
                    .collect(),
            })
            .collect();
        Arc::new(KeptMatcher { entries })
    }

    /// [`crate::summaries_for_url`]: places of the logins for a web page, best first.
    pub fn for_url(&self, url: String) -> Vec<u32> {
        let Some(page) = crate::matching::parse_loose(&url) else {
            return Vec::new();
        };
        let page = crate::matching::MatchPage::of(&page);
        self.logins_where(|e| crate::matching::tier_of(&e.urls, &page))
    }

    /// [`crate::summaries_for_android_app`]: places of the logins for an app. A stored
    /// certificate digest must match.
    pub fn for_android_app(&self, package: String, cert_sha256: Option<String>) -> Vec<u32> {
        let cert = cert_sha256
            .as_deref()
            .map(crate::matching::normalize_cert)
            .filter(|c| !c.is_empty());
        let link = format!("androidapp://{package}").to_ascii_lowercase();
        self.logins_where(|e| {
            let linked = e
                .apps
                .iter()
                .map(|(p, stored)| {
                    if **p != *package {
                        MatchQuality::None
                    } else {
                        match stored {
                            None => MatchQuality::Host,
                            Some(s) if cert.as_deref() == Some(&**s) => MatchQuality::Exact,
                            Some(_) => MatchQuality::None,
                        }
                    }
                })
                .max()
                .unwrap_or(MatchQuality::None);
            if linked > MatchQuality::None {
                linked
            } else if e.app_links.iter().any(|l| **l == *link) {
                MatchQuality::Domain
            } else {
                MatchQuality::None
            }
        })
    }

    /// [`crate::summaries_with_passkeys`]: places of the items with a passkey for `rp_id`, the
    /// most used first, then by title.
    pub fn with_passkeys(&self, rp_id: String) -> Vec<u32> {
        let rp = rp_id.to_ascii_lowercase();
        let mut found: Vec<&KeptEntry> = self
            .entries
            .iter()
            .filter(|e| e.passkey_sites.iter().any(|s| **s == *rp))
            .collect();
        found.sort_by(|a, b| {
            b.rank
                .cmp(&a.rank)
                .then_with(|| a.title_key.cmp(&b.title_key))
        });
        found.into_iter().map(|e| e.place).collect()
    }

    /// How many items it can match.
    pub fn len(&self) -> u32 {
        self.entries.len() as u32
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl KeptMatcher {
    /// As `summary::logins_where`: logins with a match, best first, then favorites, the most
    /// used and by title.
    fn logins_where(&self, score: impl Fn(&KeptEntry) -> MatchQuality) -> Vec<u32> {
        let mut found: Vec<(MatchQuality, &KeptEntry)> = self
            .entries
            .iter()
            .filter(|e| e.login)
            .filter_map(|e| {
                let q = score(e);
                (q > MatchQuality::None).then_some((q, e))
            })
            .collect();
        found.sort_by(|(qa, a), (qb, b)| {
            qb.cmp(qa)
                .then(b.favorite.cmp(&a.favorite))
                .then(b.rank.cmp(&a.rank))
                .then_with(|| a.title_key.cmp(&b.title_key))
        });
        found.into_iter().map(|(_, e)| e.place).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ItemKind;

    fn login(id: &str, title: &str, url: &str, rank: i64) -> ItemSummary {
        ItemSummary {
            id: id.into(),
            kind: ItemKind::Login,
            title: title.into(),
            username: "kim".into(),
            urls: vec![url.into()],
            rank,
            ..Default::default()
        }
    }

    fn groups() -> Vec<VaultSummaries> {
        vec![
            VaultSummaries {
                vault_id: "home".into(),
                can_edit: true,
                can_reveal: true,
                summaries: vec![
                    login("1", "GitHub", "https://github.com", 1),
                    login("2", "Bank", "https://bank.example", 0),
                ],
                ..Default::default()
            },
            VaultSummaries {
                vault_id: "eng".into(),
                shared: Some(SharedKind::Org),
                role: Some(MemberRole::Fill),
                can_edit: false,
                can_reveal: false,
                summaries: vec![login("1", "GitHub deploy bot", "https://github.com", 9)],
            },
            VaultSummaries {
                vault_id: "ops".into(),
                shared: Some(SharedKind::Org),
                role: Some(MemberRole::Edit),
                can_edit: true,
                can_reveal: true,
                summaries: vec![login("3", "Router", "https://router.example", 0)],
            },
        ]
    }

    #[test]
    fn results_across_vaults_keep_their_vault_and_one_order() {
        let found = multi_for_url(groups(), "https://github.com/login".into());
        let got: Vec<(&str, &str)> = found
            .iter()
            .map(|r| (r.vault_id.as_str(), r.summary.id.as_str()))
            .collect();
        // The same item id in two vaults stays two results; the more used first.
        assert_eq!(got, [("eng", "1"), ("home", "1")]);
        let found = multi_search(groups(), "router".into());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].vault_id, "ops");
        assert_eq!(found[0].summary.title, "Router");
        assert_eq!(multi_search(groups(), String::new()).len(), 4);
        assert!(multi_with_passkeys(groups(), "github.com".into()).is_empty());
        assert!(multi_for_android_app(groups(), "com.example".into(), None).is_empty());
    }

    #[test]
    fn the_default_save_vault_follows_the_site_then_the_choice_then_home() {
        // The router's site is in the ops vault, which may be edited.
        assert_eq!(
            multi_default_save_vault(groups(), Some("https://router.example/admin".into()), None)
                .as_deref(),
            Some("ops")
        );
        // GitHub is in eng too, but this device can't edit eng: home, where it also is.
        assert_eq!(
            multi_default_save_vault(
                groups(),
                Some("https://github.com".into()),
                Some("eng".into())
            )
            .as_deref(),
            Some("home")
        );
        // A new site: the preferred vault if editable, else the personal one.
        assert_eq!(
            multi_default_save_vault(
                groups(),
                Some("https://new.example".into()),
                Some("ops".into())
            )
            .as_deref(),
            Some("ops")
        );
        assert_eq!(
            multi_default_save_vault(groups(), None, Some("eng".into())).as_deref(),
            Some("home")
        );
        let shared_only: Vec<VaultSummaries> = groups().into_iter().skip(1).collect();
        assert_eq!(
            multi_default_save_vault(shared_only, None, None).as_deref(),
            Some("ops")
        );
        let read_only: Vec<VaultSummaries> = groups().into_iter().skip(1).take(1).collect();
        assert_eq!(multi_default_save_vault(read_only, None, None), None);
    }
}
