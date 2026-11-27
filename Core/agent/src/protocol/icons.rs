//! `icons.get`: website icons for the popup, read from the desktop app's icon cache.
//!
//! Only icons of logins that match the page, or that a recent `logins.search` returned, are
//! answered, so the extension can't enumerate the sites in the vault. The agent never fetches an
//! icon and never asks to unlock for one.

use serde::Deserialize;

use super::RpcResult;

#[derive(Deserialize)]
#[cfg_attr(not(feature = "icons"), allow(dead_code))]
pub(super) struct IconsParams {
    url: Option<String>,
    /// Only these domains; all matching ones when missing.
    domains: Option<Vec<String>>,
    /// Instead of `url`: logins a recent `logins.search` returned (others are skipped).
    ids: Option<Vec<String>>,
}

/// One page of search results.
#[cfg_attr(not(feature = "icons"), allow(dead_code))]
const MAX_IDS: usize = 50;

#[cfg(feature = "icons")]
mod imp {
    use std::collections::BTreeMap;

    use pass_core::{
        b64url_encode, site_icon_cache_read, site_icon_domain, summaries_for_url, ItemKind,
        ItemSummary,
    };
    use serde_json::{json, Value};

    use super::{IconsParams, RpcResult, MAX_IDS};
    use crate::protocol::{ErrorCode, RpcError};
    use crate::Agent;

    const MAX_DOMAINS: usize = 32;
    /// Cached icons are small PNGs; a bigger file isn't one of ours.
    const MAX_PNG: usize = 64 * 1024;
    /// All data URLs together, well under native messaging's 1 MB message limit.
    const MAX_TOTAL: usize = 512 * 1024;
    const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

    fn icon_domain(item: &ItemSummary) -> Option<String> {
        item.urls.iter().find_map(|u| site_icon_domain(u.clone()))
    }

    /// Data URLs use standard, padded base64.
    fn data_url(png: Vec<u8>) -> String {
        let mut b64: String = b64url_encode(png)
            .chars()
            .map(|c| match c {
                '-' => '+',
                '_' => '/',
                c => c,
            })
            .collect();
        while !b64.len().is_multiple_of(4) {
            b64.push('=');
        }
        format!("data:image/png;base64,{b64}")
    }

    impl Agent {
        pub(in crate::protocol) fn rpc_icons_get(&self, p: IconsParams) -> RpcResult {
            if p.ids.is_none() && p.url.is_none() {
                return Err(RpcError::new(
                    ErrorCode::InvalidParams,
                    "url or ids is required",
                ));
            }
            if p.ids.as_ref().is_some_and(|ids| ids.len() > MAX_IDS) {
                return Err(RpcError::new(ErrorCode::InvalidParams, "too many ids"));
            }
            let empty = || Ok(json!({ "icons": {}, "items": {} }));
            let Some(dir) = self.icon_cache_dir() else {
                return empty();
            };
            // No unlock prompt for icons; soft-locked, the kept lists are used (icons hold no secret).
            let Some(list) = self.listed_vaults().map(|l| l.all()) else {
                return empty();
            };
            let wanted = p.domains.map(|d| {
                d.into_iter()
                    .map(|d| d.trim().to_ascii_lowercase())
                    .collect::<Vec<_>>()
            });
            let mut by_item: Vec<(String, String)> = Vec::new();
            let mut domains: Vec<String> = Vec::new();
            let items: Vec<ItemSummary> = match (p.ids, p.url) {
                // Only logins the popup's search just showed: no enumeration by id.
                (Some(ids), _) => ids
                    .iter()
                    .filter(|id| self.search_hit(id))
                    .filter_map(|id| list.iter().find(|i| &i.id == id).cloned())
                    .filter(|item| item.kind == ItemKind::Login)
                    .collect(),
                (None, Some(url)) => summaries_for_url(list.to_vec(), url),
                (None, None) => Vec::new(),
            };
            for item in items {
                let Some(domain) = icon_domain(&item) else {
                    continue;
                };
                if wanted.as_ref().is_some_and(|w| !w.contains(&domain)) {
                    continue;
                }
                if !domains.contains(&domain) {
                    if domains.len() == MAX_DOMAINS {
                        continue;
                    }
                    domains.push(domain.clone());
                }
                by_item.push((item.id, domain));
            }
            let dir = dir.to_string_lossy().into_owned();
            let mut icons = BTreeMap::new();
            let mut total = 0;
            for domain in domains {
                let Some(png) =
                    site_icon_cache_read(dir.clone(), domain.clone()).and_then(|c| c.png)
                else {
                    continue;
                };
                if png.len() > MAX_PNG || !png.starts_with(PNG_SIGNATURE) {
                    continue;
                }
                let url = data_url(png);
                if total + url.len() > MAX_TOTAL {
                    break;
                }
                total += url.len();
                icons.insert(domain, Value::String(url));
            }
            let items: BTreeMap<String, String> = by_item
                .into_iter()
                .filter(|(_, domain)| icons.contains_key(domain))
                .collect();
            Ok(json!({ "icons": icons, "items": items }))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::data_url;

        #[test]
        fn data_urls_use_padded_standard_base64() {
            assert_eq!(data_url(vec![0xfb, 0xff]), "data:image/png;base64,+/8=");
            assert_eq!(data_url(vec![1, 2, 3]), "data:image/png;base64,AQID");
            assert_eq!(data_url(vec![0xff]), "data:image/png;base64,/w==");
        }
    }
}

#[cfg(not(feature = "icons"))]
impl crate::Agent {
    pub(super) fn rpc_icons_get(&self, _p: IconsParams) -> RpcResult {
        Err(super::RpcError::new(
            super::ErrorCode::NotSupported,
            "this Passyble build has no website icons",
        ))
    }
}
