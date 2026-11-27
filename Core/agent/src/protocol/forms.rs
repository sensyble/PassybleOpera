//! Payment cards and identities for web forms.
//!
//! These belong to no site, so nothing is bound to the page's URL. Instead the page must be
//! secure, lists carry no secrets, and every card fill asks the user.

use std::net::IpAddr;
use std::time::Duration;

use pass_core::{summaries_suggested, ItemKind, ItemSummary};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{fill_only, vaults_json, ErrorCode, RpcError, RpcResult};
use crate::{Agent, CardFillRequest, Reason};

const CARD_FILLS_PER_MINUTE: usize = 20;
const IDENTITY_FILLS_PER_MINUTE: usize = 60;
const MINUTE: Duration = Duration::from_secs(60);

#[derive(Deserialize)]
pub(super) struct ListParams {
    url: String,
}

#[derive(Deserialize)]
pub(super) struct CardFillParams {
    url: String,
    id: String,
    /// The tab's top page when the form is in a frame (shown in the prompt only).
    top_url: Option<String>,
    /// `"copy"`: the popup copies a value; anything else is a fill.
    purpose: Option<String>,
    /// With `purpose: "copy"`: `"number"` or `"security_code"`, which the desktop app copies
    /// itself so the value never reaches the browser.
    field: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct IdentityFillParams {
    url: String,
    id: String,
}

/// Returns the host of a page cards and identities may be filled into: `https://`, or `http://`
/// on this device. Anything else is `url_mismatch`.
pub(super) fn secure_page_host(url: &str) -> Result<String, RpcError> {
    let refused = || {
        RpcError::new(
            ErrorCode::UrlMismatch,
            "cards and addresses are only filled on secure (https) pages",
        )
    };
    let page = url::Url::parse(url).map_err(|_| refused())?;
    let host = page
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(refused)?;
    let secure = match page.scheme() {
        "https" => true,
        "http" => is_local_host(host),
        _ => false,
    };
    if !secure {
        return Err(refused());
    }
    Ok(host.to_string())
}

fn is_local_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost") {
        return true;
    }
    host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn card_json(summary: &ItemSummary) -> Option<Value> {
    let card = summary.card.as_ref()?;
    Some(json!({
        "id": summary.id, "title": summary.title, "cardholder_name": card.cardholder_name,
        "brand": card.brand, "last4": card.last4, "expiry_month": card.expiry_month,
        "expiry_year": card.expiry_year, "favorite": summary.favorite,
    }))
}

fn identity_json(summary: &ItemSummary) -> Option<Value> {
    let identity = summary.identity.as_ref()?;
    Some(json!({
        "id": summary.id, "title": summary.title, "full_name": identity.full_name,
        "email": identity.email, "company": identity.company, "favorite": summary.favorite,
    }))
}

impl Agent {
    /// The live items of `kind` without secrets, in suggestion order. Not activity.
    fn listed_kind(
        &self,
        url: &str,
        kind: ItemKind,
    ) -> Result<(Vec<ItemSummary>, crate::agent::Listed), RpcError> {
        secure_page_host(url)?;
        let listed = self.listed_all()?;
        let items = listed
            .all()
            .into_iter()
            .filter(|i| i.kind == kind && i.trashed_at.is_none())
            .collect();
        Ok((summaries_suggested(items), listed))
    }

    /// A listing answer for cards or identities: each item with its vault, and the `vaults` table.
    fn listed_kind_json(
        items: &[ItemSummary],
        listed: &crate::agent::Listed,
        to_json: fn(&ItemSummary) -> Option<Value>,
    ) -> Value {
        let json_items: Vec<Value> = items
            .iter()
            .filter_map(|i| {
                let mut v = to_json(i)?;
                v["vault_id"] = json!(listed.ref_of(&i.id).map(|r| r.id.clone()));
                Some(v)
            })
            .collect();
        let vaults = vaults_json(&listed.table(items.iter().map(|i| i.id.as_str())));
        json!({ "items": json_items, "locked": listed.locked, "vaults": vaults })
    }

    /// `cards.list`: never the number, code or PIN.
    pub(super) fn rpc_cards_list(&self, p: ListParams) -> RpcResult {
        let (cards, listed) = self.listed_kind(&p.url, ItemKind::Card)?;
        Ok(Self::listed_kind_json(&cards, &listed, card_json))
    }

    pub(super) fn rpc_identities_list(&self, p: ListParams) -> RpcResult {
        let (identities, listed) = self.listed_kind(&p.url, ItemKind::Identity)?;
        Ok(Self::listed_kind_json(&identities, &listed, identity_json))
    }

    /// `cards.fill`: only after the user confirms the fill and passes the per-fill policy.
    pub(super) fn rpc_cards_fill(&self, p: CardFillParams) -> RpcResult {
        let page_host = secure_page_host(&p.url)?;
        let opened = self.opened_or_locked()?;
        let (vault_ref, vault) = opened
            .holding(&p.id)
            .cloned()
            .ok_or_else(|| RpcError::new(ErrorCode::NotFound, "no such card"))?;
        let item = vault
            .get(p.id.clone())
            .filter(|i| !i.is_trashed())
            .ok_or_else(|| RpcError::new(ErrorCode::NotFound, "no such card"))?;
        // A fill-only member's card is filled, never copied.
        if !vault_ref.can_reveal && p.purpose.as_deref() == Some("copy") {
            return Err(fill_only());
        }
        let card = match (&item.kind, &item.card) {
            (ItemKind::Card, Some(card)) => card.clone(),
            _ => {
                return Err(RpcError::new(
                    ErrorCode::NotFound,
                    "that item is not a card",
                ))
            }
        };
        if !self.within_rate("card_fill", CARD_FILLS_PER_MINUTE, MINUTE) {
            return Err(RpcError::new(
                ErrorCode::RateLimited,
                "Too many card fills. Wait a minute and try again",
            ));
        }
        let top_host = p
            .top_url
            .as_deref()
            .and_then(|u| url::Url::parse(u).ok())
            .and_then(|u| u.host_str().map(str::to_string))
            .filter(|h| !h.eq_ignore_ascii_case(&page_host))
            .unwrap_or_default();
        let copy = p.purpose.as_deref() == Some("copy");
        let copy_field = match p.field.as_deref() {
            None => None,
            Some(f @ ("number" | "security_code")) if copy => Some(f),
            Some(_) => {
                return Err(RpcError::new(
                    ErrorCode::InvalidParams,
                    "field must be number or security_code, with purpose copy",
                ))
            }
        };
        let request = CardFillRequest {
            item_id: item.id.clone(),
            title: item.title.clone(),
            brand: card.brand.clone(),
            last4: card.last4(),
            page_host: page_host.clone(),
            top_host,
            copy,
        };
        match self.ui.confirm_card_fill(&request) {
            None => {
                return Err(RpcError::new(
                    ErrorCode::NotSupported,
                    "this Passyble app can't fill cards",
                ))
            }
            Some(false) => return Err(RpcError::new(ErrorCode::Cancelled, "declined")),
            Some(true) => {}
        }
        let title = item.title.clone();
        let reason = if copy {
            Reason::CopyCard { title }
        } else {
            Reason::FillCard {
                title,
                host: page_host,
            }
        };
        self.verified(reason)?;
        self.record_use(&item.id);
        if let Some(field) = copy_field {
            let value = if field == "number" {
                &card.number
            } else {
                &card.security_code
            };
            if value.is_empty() {
                return Ok(json!({ "copied": false, "field": field }));
            }
            // An app that can't copy falls back to answering the card.
            if self.ui.copy_to_clipboard(value) {
                return Ok(json!({ "copied": true, "field": field }));
            }
        }
        Ok(json!({
            "cardholder_name": card.cardholder_name, "number": card.number,
            "expiry_month": card.expiry_month, "expiry_year": card.expiry_year,
            "security_code": card.security_code, "brand": card.brand,
        }))
    }

    /// `identities.fill`: no prompt beyond the unlocked vault.
    pub(super) fn rpc_identities_fill(&self, p: IdentityFillParams) -> RpcResult {
        secure_page_host(&p.url)?;
        self.unlocked()?;
        let item = self
            .any_item(&p.id)
            .filter(|i| !i.is_trashed())
            .ok_or_else(|| RpcError::new(ErrorCode::NotFound, "no such identity"))?;
        let identity = match (&item.kind, &item.identity) {
            (ItemKind::Identity, Some(identity)) => identity.clone(),
            _ => {
                return Err(RpcError::new(
                    ErrorCode::NotFound,
                    "that item is not an identity",
                ))
            }
        };
        if !self.within_rate("identity_fill", IDENTITY_FILLS_PER_MINUTE, MINUTE) {
            return Err(RpcError::new(
                ErrorCode::RateLimited,
                "Too many fills. Wait a minute and try again",
            ));
        }
        self.record_use(&item.id);
        Ok(json!({
            "honorific": identity.honorific, "first_name": identity.first_name,
            "middle_name": identity.middle_name, "last_name": identity.last_name,
            "full_name": identity.full_name(), "email": identity.email, "phone": identity.phone,
            "address1": identity.address1, "address2": identity.address2,
            "address3": identity.address3, "city": identity.city, "region": identity.region,
            "postal_code": identity.postal_code, "country": identity.country,
            "company": identity.company, "birth_date": identity.birth_date,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::secure_page_host;

    #[test]
    fn only_secure_pages() {
        for ok in [
            "https://shop.example/checkout",
            "https://js.stripe.com/v3/elements-inner-card.html",
            "http://localhost:8080/pay",
            "http://shop.localhost/",
            "http://127.0.0.1:3000/",
            "http://[::1]/",
        ] {
            assert!(secure_page_host(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://shop.example/checkout",
            "http://192.168.1.5/",
            "ftp://example.com/",
            "file:///C:/form.html",
            "chrome://settings",
            "about:blank",
            "not a url",
            "",
        ] {
            assert!(secure_page_host(bad).is_err(), "{bad}");
        }
        assert_eq!(
            secure_page_host("https://Shop.Example:8443/x").unwrap(),
            "shop.example"
        );
    }
}
