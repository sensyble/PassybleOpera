//! `sites.suggest` and `sites.name_for`: popular sites for the editors, from the list compiled
//! into pass-core. Nothing leaves the device and no vault is needed.

use pass_core::{site_for_domain, site_suggestions, MAX_SITE_SUGGESTIONS};
use serde::Deserialize;
use serde_json::json;

use super::{ErrorCode, RpcError, RpcResult};
use crate::Agent;

/// Suggestions when the request doesn't say how many.
const DEFAULT_LIMIT: u32 = 8;
const MAX_QUERY: usize = 256;
const MAX_URL: usize = 2048;

#[derive(Deserialize)]
pub(super) struct SuggestParams {
    query: String,
    /// At most [`MAX_SITE_SUGGESTIONS`]; more is capped.
    #[serde(default)]
    limit: Option<u32>,
}

#[derive(Deserialize)]
pub(super) struct NameForParams {
    url: String,
}

fn invalid(message: &str) -> RpcError {
    RpcError::new(ErrorCode::InvalidParams, message)
}

impl Agent {
    pub(super) fn rpc_sites_suggest(&self, p: SuggestParams) -> RpcResult {
        if p.query.len() > MAX_QUERY {
            return Err(invalid("query is too long"));
        }
        let limit = p.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_SITE_SUGGESTIONS);
        Ok(json!({ "sites": site_suggestions(p.query, limit) }))
    }

    pub(super) fn rpc_sites_name_for(&self, p: NameForParams) -> RpcResult {
        if p.url.len() > MAX_URL {
            return Err(invalid("url is too long"));
        }
        Ok(json!({ "name": site_for_domain(p.url) }))
    }
}
