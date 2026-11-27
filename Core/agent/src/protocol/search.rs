//! Searching the vault from the extension popup.
//!
//! `logins.search` returns no secrets and remembers what it returned; only those logins can then
//! be copied or filled into another site. Queries need two characters, so an empty one can't list
//! the whole vault.

use std::time::Duration;

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use pass_core::{
    login_sites, similar_logins, site_name, summaries_for_url, totp_generate, ItemKind,
    ItemSummary, KnownSites, LookalikeCheck, SearchIndex, VaultSummaries,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::edit::{is_web_entry, page};
use super::{fill_only, vault_json, vaults_json, ErrorCode, ItemParams, RpcError, RpcResult};
use crate::{Agent, CrossFillRequest, ItemSecret, Reason};
#[cfg(test)]
use pass_core::Item;

const MIN_QUERY: usize = 2;
const MAX_QUERY: usize = 128;
const DEFAULT_LIMIT: i64 = 20;
const MAX_LIMIT: i64 = 50;

const SEARCHES_PER_MINUTE: usize = 120;
const SIMILAR_PER_MINUTE: usize = 60;
const DEFAULT_SIMILAR: i64 = 3;
const MAX_SIMILAR: i64 = 10;
const ADD_URLS_PER_MINUTE: usize = 10;
const COPIES_PER_MINUTE: usize = 30;
const CROSS_FILLS_PER_MINUTE: usize = 10;
const MINUTE: Duration = Duration::from_secs(60);

#[derive(Deserialize)]
pub(super) struct SearchParams {
    query: String,
    limit: Option<i64>,
    /// The page the popup is open on, if any: results whose site it looks like without being it
    /// get `lookalike` ([`pass_core::LookalikeCheck`]), so the popup warns before a fill or copy.
    #[serde(default)]
    url: Option<String>,
}

/// `lookalike` of a search result: the user's site the page looks like, the page's host and why.
pub(super) fn lookalike_json(found: &pass_core::Lookalike) -> Value {
    json!({ "domain": found.domain, "host": found.host, "reason": found.reason.as_str() })
}

#[derive(Deserialize)]
pub(super) struct SimilarParams {
    /// The page without logins of its own (http(s) only).
    url: String,
    limit: Option<i64>,
}

#[derive(Deserialize)]
pub(super) struct AddUrlParams {
    /// The login that was just filled into the page.
    id: String,
    /// The page it was filled into; its origin is added.
    url: String,
    /// The fill's `add_url_token`.
    token: String,
}

#[derive(Deserialize)]
pub(super) struct CopyParams {
    id: String,
    field: String,
    /// The page, if the login belongs to it (then it needn't come from a search).
    url: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct CrossParams {
    url: String,
    id: String,
}

fn rate_limited(message: &str) -> RpcError {
    RpcError::new(ErrorCode::RateLimited, message)
}

/// The popup's search only matches a login's websites, not app entries or Android apps.
fn searchable(item: &ItemSummary) -> ItemSummary {
    let mut item = item.clone();
    item.urls.retain(|u| is_web_entry(u));
    item.android_apps.clear();
    item
}

/// The lists of the open vaults, kept between requests while they stay the same
/// ([`crate::agent::ListStamp`]), so `logins.find` and `logins.search` don't rebuild every
/// summary each time. Holds no secret and no vault (the stamp's references are weak).
pub(crate) struct SearchLists {
    stamp: crate::agent::ListStamp,
    pub(crate) listed: crate::agent::Listed,
    searching: OnceLock<Searching>,
}

/// What `logins.search` reads of the lists: the logins as the search sees them ([`searchable`])
/// in a [`SearchIndex`], and the sites the lookalike check knows.
struct Searching {
    logins: Vec<ItemSummary>,
    index: Arc<SearchIndex>,
    known: KnownSites,
}

impl SearchLists {
    fn searching(&self) -> &Searching {
        self.searching.get_or_init(|| {
            let all = || self.listed.groups.iter().flat_map(|(_, list)| list.iter());
            let logins: Vec<ItemSummary> = all()
                .filter(|i| i.kind == ItemKind::Login)
                .map(searchable)
                .collect();
            // One list, as `summaries_search` over `logins` searched it.
            let index = SearchIndex::new(
                vec![VaultSummaries {
                    summaries: logins.clone(),
                    ..Default::default()
                }],
                HashMap::new(),
            );
            let sites: Vec<String> = all()
                .flat_map(|i| login_sites(&i.urls, &i.android_apps))
                .collect();
            Searching {
                logins,
                index,
                known: KnownSites::from_urls(sites.iter().map(String::as_str)),
            }
        })
    }
}

impl Agent {
    /// [`SearchLists`] for the lists as they are now: the kept one while they haven't changed;
    /// `locked` when fully locked.
    pub(crate) fn search_lists(&self) -> Result<Arc<SearchLists>, RpcError> {
        let sources = self
            .list_sources()
            .ok_or_else(|| RpcError::new(ErrorCode::Locked, "Vault is locked"))?;
        if let Some(kept) = self.kept_search() {
            if kept.stamp.is(&sources) {
                return Ok(kept);
            }
        }
        let fresh = Arc::new(SearchLists {
            stamp: sources.stamp(),
            listed: sources.listed(),
            searching: OnceLock::new(),
        });
        self.keep_search(fresh.clone());
        Ok(fresh)
    }
}

impl Agent {
    /// `logins.search`: logins whose title, username or website matches the query. No secrets.
    pub(super) fn rpc_search(&self, p: SearchParams) -> RpcResult {
        let lists = self.search_lists()?;
        let listed = &lists.listed;
        let locked = listed.locked;
        if !self.within_rate("search", SEARCHES_PER_MINUTE, MINUTE) {
            return Err(rate_limited(
                "Too many searches. Wait a minute and try again",
            ));
        }
        let query = p.query.trim().to_lowercase();
        let length = query.chars().count();
        if length < MIN_QUERY {
            return Err(RpcError::new(
                ErrorCode::InvalidParams,
                "type at least 2 characters",
            ));
        }
        if length > MAX_QUERY {
            return Err(RpcError::new(ErrorCode::InvalidParams, "query is too long"));
        }
        let limit = p.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT) as usize;
        // Every open vault's logins as one list, best matches first.
        let searching = lists.searching();
        let places = searching.index.search_positions(query);
        let truncated = places.len() > limit;
        let found: Vec<&ItemSummary> = places
            .into_iter()
            .take(limit)
            .map(|p| &searching.logins[p as usize])
            .collect();
        let ids: Vec<String> = found.iter().map(|i| i.id.clone()).collect();
        self.remember_search_hits(&ids);
        // A page of any of the user's sites is no lookalike. Only web pages: an extension page or
        // `chrome://` has no site.
        let check = p
            .url
            .as_deref()
            .filter(|url| page(url).is_ok())
            .and_then(|url| LookalikeCheck::new_known(url, &searching.known));
        let items: Vec<Value> = found
            .iter()
            .map(|i| {
                let mut row = json!({
                    "id": i.id, "title": i.title, "username": i.username,
                    "domain": i.domain, "has_totp": i.has_totp, "favorite": i.favorite,
                    "vault_id": listed.ref_of(&i.id).map(|r| r.id.clone()),
                });
                if let Some(like) = check
                    .as_ref()
                    .and_then(|c| c.against(i.urls.iter().map(String::as_str)))
                {
                    row["lookalike"] = lookalike_json(&like);
                }
                row
            })
            .collect();
        let vaults = vaults_json(&listed.table(found.iter().map(|i| i.id.as_str())));
        Ok(json!({ "items": items, "truncated": truncated, "locked": locked, "vaults": vaults }))
    }

    /// `logins.similar`: a few logins of sites like the page ([`similar_logins`]), never a
    /// lookalike and never one of its own. No secrets. They count as search hits, so a copy or a
    /// cross fill may follow.
    pub(super) fn rpc_similar(&self, p: SimilarParams) -> RpcResult {
        page(&p.url)?;
        let lists = self.search_lists()?;
        let listed = &lists.listed;
        if !self.within_rate("similar", SIMILAR_PER_MINUTE, MINUTE) {
            return Err(rate_limited(
                "Too many searches. Wait a minute and try again",
            ));
        }
        let limit = p.limit.unwrap_or(DEFAULT_SIMILAR).clamp(1, MAX_SIMILAR) as usize;
        let searching = lists.searching();
        let found = similar_logins(&p.url, &searching.logins, &searching.known, limit);
        let logins: Vec<&ItemSummary> = found.iter().map(|s| &searching.logins[s.index]).collect();
        let ids: Vec<String> = logins.iter().map(|i| i.id.clone()).collect();
        self.remember_search_hits(&ids);
        let items: Vec<Value> = found
            .iter()
            .zip(&logins)
            .map(|(similar, i)| {
                json!({
                    "id": i.id, "title": i.title, "username": i.username,
                    "domain": i.domain, "has_totp": i.has_totp, "favorite": i.favorite,
                    "vault_id": listed.ref_of(&i.id).map(|r| r.id.clone()),
                    "reason": similar.reason.as_str(),
                })
            })
            .collect();
        let vaults = vaults_json(&listed.table(logins.iter().map(|i| i.id.as_str())));
        Ok(json!({
            "items": items, "name": site_name(&p.url), "locked": listed.locked, "vaults": vaults,
        }))
    }

    /// `logins.add_url`: after a cross fill, adds the page's origin to the login that was filled.
    /// Needs that fill's one-use `add_url_token`, for that login and a page of that origin.
    pub(super) fn rpc_add_url(&self, p: AddUrlParams) -> RpcResult {
        let opened = self.opened_or_locked()?;
        self.unlocked()?;
        let page = page(&p.url)?;
        if !self.within_rate("add_url", ADD_URLS_PER_MINUTE, MINUTE) {
            return Err(rate_limited(
                "Too many changes. Wait a minute and try again",
            ));
        }
        let origin = page.origin().ascii_serialization();
        if !self.take_cross_fill(&p.token, &p.id, &origin) {
            return Err(RpcError::new(
                ErrorCode::NotFound,
                "nothing was filled into this page from that login",
            ));
        }
        let (vault_ref, vault) = opened
            .holding(&p.id)
            .cloned()
            .ok_or_else(|| RpcError::new(ErrorCode::NotFound, "no such item"))?;
        if !vault_ref.can_edit {
            return Err(super::read_only());
        }
        let mut item = vault
            .get(p.id.clone())
            .ok_or_else(|| RpcError::new(ErrorCode::NotFound, "no such item"))?;
        // Already a login of the page (added from another tab, or hidden by a website rule the
        // user set): nothing to change.
        let added = !vault
            .logins_of_page(p.url.clone())
            .iter()
            .any(|i| i.id == item.id);
        if added {
            item.urls.push(origin);
            item = vault.upsert(item)?;
            self.edited()?;
        }
        Ok(json!({
            "added": added, "id": item.id, "title": item.title, "vault": vault_json(&vault_ref),
        }))
    }

    /// `logins.copy`: the desktop app copies a field of a search result or a login of the page,
    /// so the value never goes to the browser. A login of the page is verified as its fill would
    /// be; another site's always goes through the per-fill policy.
    pub(super) fn rpc_copy(&self, p: CopyParams) -> RpcResult {
        let field = p.field.as_str();
        if !matches!(field, "username" | "password" | "totp") {
            return Err(RpcError::new(
                ErrorCode::InvalidParams,
                "field must be username, password or totp",
            ));
        }
        let listed = self.listed_all()?;
        let locked = listed.locked;
        let list = listed.all();
        if locked && field != "username" {
            return Err(RpcError::new(ErrorCode::Locked, "Vault is locked"));
        }
        // A fill-only member's password is filled, never copied (its codes and username may be).
        if field == "password" && listed.ref_of(&p.id).is_some_and(|r| !r.can_reveal) {
            return Err(fill_only());
        }
        if !self.within_rate("copy", COPIES_PER_MINUTE, MINUTE) {
            return Err(rate_limited("Too many copies. Wait a minute and try again"));
        }
        let summary = list
            .iter()
            .find(|i| i.id == p.id)
            .ok_or_else(|| RpcError::new(ErrorCode::NotFound, "no such item"))?;
        let of_page = p.url.as_deref().is_some_and(|url| {
            summaries_for_url(list.clone(), url.to_string())
                .iter()
                .any(|i| i.id == summary.id)
        });
        if !of_page && !self.search_hit(&summary.id) {
            return Err(RpcError::new(
                ErrorCode::UrlMismatch,
                "item does not belong to this site",
            ));
        }
        if field == "username" {
            if !self.ui.copy_to_clipboard(&summary.username) {
                return Err(RpcError::new(
                    ErrorCode::NotSupported,
                    "this Passyble app can't copy to the clipboard",
                ));
            }
            // Not counted for "most used first": no sign-in needs only the username.
            self.note_use();
            return Ok(json!({ "copied": true, "field": field }));
        }
        self.unlocked()?;
        let item = self
            .any_item(&p.id)
            .ok_or_else(|| RpcError::new(ErrorCode::NotFound, "no such item"))?;
        let value = match field {
            "password" => {
                if item.password.is_empty() {
                    return Err(RpcError::new(
                        ErrorCode::NotFound,
                        "this login has no password",
                    ));
                }
                let reason = Reason::CopyPassword {
                    title: item.title.clone(),
                };
                if of_page {
                    self.verified_item(reason, &item.id, ItemSecret::Password)?;
                } else {
                    self.verified(reason)?;
                }
                item.password.clone()
            }
            _ => {
                let secret = item
                    .totp
                    .clone()
                    .filter(|_| self.totp_json(&item).is_some())
                    .ok_or_else(|| {
                        RpcError::new(ErrorCode::NotFound, "this login has no 2FA secret")
                    })?;
                let reason = Reason::CopyCode {
                    title: item.title.clone(),
                };
                match p.url.as_deref().filter(|_| of_page) {
                    Some(url) => {
                        let follows_fill = self
                            .pending_otp(url)
                            .is_some_and(|pending| pending.item_id == item.id);
                        self.verified_item(reason, &item.id, ItemSecret::Code { follows_fill })?;
                    }
                    None => {
                        self.verified(reason)?;
                    }
                }
                // The code as of now: the verification may have taken a while.
                totp_generate(secret, self.now_secs())
                    .map_err(|_| {
                        RpcError::new(ErrorCode::NotFound, "this login has no 2FA secret")
                    })?
                    .code
            }
        };
        if !self.ui.copy_to_clipboard(&value) {
            return Err(RpcError::new(
                ErrorCode::NotSupported,
                "this Passyble app can't copy to the clipboard",
            ));
        }
        self.record_use(&item.id);
        Ok(json!({ "copied": true, "field": field }))
    }

    /// `logins.fill_cross`: fills a login into the page. Another site's login (from a search) is
    /// only filled after the user confirms, and leaves no pending 2FA code for the page.
    pub(super) fn rpc_fill_cross(&self, p: CrossParams) -> RpcResult {
        let opened = self.opened_or_locked()?;
        let page = page(&p.url)?;
        if !self.within_rate("fill_cross", CROSS_FILLS_PER_MINUTE, MINUTE) {
            return Err(rate_limited("Too many fills. Wait a minute and try again"));
        }
        let (vault_ref, vault) = opened
            .holding(&p.id)
            .cloned()
            .ok_or_else(|| RpcError::new(ErrorCode::NotFound, "no such item"))?;
        let item = vault
            .get(p.id.clone())
            .ok_or_else(|| RpcError::new(ErrorCode::NotFound, "no such item"))?;
        if vault
            .logins_of_page(p.url.clone())
            .iter()
            .any(|i| i.id == item.id)
        {
            let mut result = self.rpc_fill(ItemParams {
                url: p.url,
                id: Some(item.id),
            })?;
            result["cross"] = json!(false);
            return Ok(result);
        }
        if !self.search_hit(&item.id) {
            return Err(RpcError::new(
                ErrorCode::UrlMismatch,
                "item does not belong to this site",
            ));
        }
        let page_host = page.host_str().unwrap_or_default().to_string();
        let lookalike = vault.lookalike_for_url(p.url.clone(), item.id.clone());
        let request = CrossFillRequest {
            item_id: item.id.clone(),
            title: item.title.clone(),
            username: item.username.clone(),
            item_domain: ItemSummary::of(&item).domain,
            page_host: page_host.clone(),
            lookalike: lookalike.clone(),
        };
        match self.ui.confirm_cross_fill(&request) {
            None => {
                return Err(RpcError::new(
                    ErrorCode::NotSupported,
                    "this Passyble app can't fill a login into another site",
                ))
            }
            Some(false) => return Err(RpcError::new(ErrorCode::Cancelled, "declined")),
            Some(true) => {}
        }
        self.verified_item(
            Reason::FillLoginInto {
                title: item.title.clone(),
                host: page_host.clone(),
            },
            &item.id,
            ItemSecret::Password,
        )?;
        self.record_use(&item.id);
        // "Add <site> to this login" may follow (`logins.add_url`), for this fill only.
        let token = self.remember_cross_fill(&item.id, &page.origin().ascii_serialization());
        let mut result = json!({
            "username": item.username, "password": item.password, "totp": self.totp_json(&item),
            "skips_2fa": false, "cross": true, "vault": vault_json(&vault_ref),
            "add_url_token": token, "title": item.title, "domain": request.item_domain,
        });
        if let Some(like) = &lookalike {
            result["lookalike"] = lookalike_json(like);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::{searchable, Item};
    use pass_core::{summaries_search, ItemSummary};

    fn matches(item: &ItemSummary, query: &str) -> bool {
        !summaries_search(vec![searchable(item)], query.into()).is_empty()
    }

    #[test]
    fn only_websites_are_searched() {
        let item = Item {
            title: "Work".into(),
            username: "alice".into(),
            urls: vec!["windows:x.exe".into(), "https://mail.example.co.uk".into()],
            ..Default::default()
        };
        let item = ItemSummary::of(&item);
        assert_eq!(item.domain, "example.co.uk");
        assert!(matches(&item, "mail.ex"));
        assert!(matches(&item, "ali"));
        assert!(matches(&item, "work exmaple"));
        assert!(!matches(&item, "x.exe"));
    }
}
