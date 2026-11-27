//! `cards.save_check` and `cards.save`: the "Save card?" banner after a checkout form.
//!
//! Typed numbers are compared with saved cards here, so a saved number never goes to the browser.
//! The security code is never taken. Saving releases nothing, so it asks nothing.

use std::sync::Arc;
use std::time::Duration;

use pass_core::{card_brand, card_number_valid, secrets_equal, CardData, Item, ItemKind, Vault};
use serde::Deserialize;
use serde_json::{json, Value};

use super::forms::secure_page_host;
use super::{new_item_vault, read_only, vault_json, vaults_json, ErrorCode, RpcError, RpcResult};
use crate::agent::Opened;
use crate::{Agent, VaultRef};

/// Checks per minute (each one tells whether a typed number is a saved card: keep it slow).
const CHECKS_PER_MINUTE: usize = 30;
const MAX_TITLE: usize = 256;
const MAX_HOLDER: usize = 256;

#[derive(Deserialize)]
pub(super) struct CardSaveCheckParams {
    url: String,
    number: String,
    #[serde(default)]
    expiry_month: Option<u32>,
    #[serde(default)]
    expiry_year: Option<u32>,
}

#[derive(Deserialize)]
pub(super) struct CardSaveParams {
    url: String,
    number: String,
    #[serde(default)]
    expiry_month: Option<u32>,
    #[serde(default)]
    expiry_year: Option<u32>,
    #[serde(default)]
    cardholder_name: Option<String>,
    /// The new card's title; empty or missing: "Visa •••• 4242" (pass-core's default).
    #[serde(default)]
    title: Option<String>,
    /// The saved card `cards.save_check` answered `update_expiry` for.
    #[serde(default)]
    id: Option<String>,
    /// The vault a new card goes into (`cards.save_check`'s `vaults`); default its
    /// `default_vault` (the home vault).
    #[serde(default)]
    vault: Option<String>,
}

fn invalid(message: &str) -> RpcError {
    RpcError::new(ErrorCode::InvalidParams, message)
}

/// The digits of a valid card number (12 to 19 digits, Luhn; spaces and dashes allowed).
fn card_digits(number: &str) -> Result<String, RpcError> {
    if !card_number_valid(number.to_string()) {
        return Err(invalid("not a valid card number"));
    }
    Ok(number.chars().filter(char::is_ascii_digit).collect())
}

/// The expiry as stored (`27` is `2027`); `(0, 0)` when either part is missing.
fn expiry(month: Option<u32>, year: Option<u32>) -> Result<(u32, u32), RpcError> {
    let (month, mut year) = (month.unwrap_or(0), year.unwrap_or(0));
    if month > 12 {
        return Err(invalid("expiry_month must be 1 to 12"));
    }
    if year > 0 && year < 100 {
        year += 2000;
    }
    if year > 9999 {
        return Err(invalid("expiry_year is not a year"));
    }
    if month == 0 || year == 0 {
        return Ok((0, 0));
    }
    Ok((month, year))
}

/// A single-line text field: trimmed, no control characters, at most `max` characters.
fn line(field: &str, value: Option<&str>, max: usize) -> Result<String, RpcError> {
    let value = value.unwrap_or_default().trim();
    if value.chars().count() > max || value.chars().any(char::is_control) {
        return Err(invalid(&format!("{field} is not a single line of text")));
    }
    Ok(value.to_string())
}

/// A saved card with this number (compared in constant time), in an open vault.
struct Saved {
    vault_ref: VaultRef,
    vault: Arc<Vault>,
    item: Item,
    card: CardData,
}

impl Saved {
    fn same_expiry(&self, (month, year): (u32, u32)) -> bool {
        self.card.expiry_month == month && self.card.expiry_year == year
    }
}

/// Every live card of the open vaults (the home vault's first) whose number is `digits`.
fn saved_with_number(opened: &Opened, digits: &str) -> Vec<Saved> {
    opened
        .0
        .iter()
        .flat_map(|(vault_ref, vault)| {
            vault.items().into_iter().filter_map(move |item| {
                let card = match (&item.kind, &item.card) {
                    (ItemKind::Card, Some(card)) => card.clone(),
                    _ => return None,
                };
                let saved: String = card.number.chars().filter(char::is_ascii_digit).collect();
                secrets_equal(&saved, digits).then(|| Saved {
                    vault_ref: vault_ref.clone(),
                    vault: vault.clone(),
                    item,
                    card,
                })
            })
        })
        .collect()
}

/// What the banner should offer for `digits` with `expiry`: `none` (saved as is: the same number
/// with the same expiry, or no expiry typed, in any open vault), `update_expiry` (the same number
/// with another expiry, in a vault this user may edit) or `save_new`. A card saved only in
/// vaults this user can't edit is `none`: it is in Passyble already and fills from there.
enum Decision<'a> {
    None(Option<&'a Saved>),
    UpdateExpiry(&'a Saved),
    SaveNew,
}

fn decide(saved: &[Saved], expiry: (u32, u32)) -> Decision<'_> {
    if saved.is_empty() {
        return Decision::SaveNew;
    }
    if expiry == (0, 0) {
        return Decision::None(saved.first());
    }
    if let Some(same) = saved.iter().find(|s| s.same_expiry(expiry)) {
        return Decision::None(Some(same));
    }
    match saved.iter().find(|s| s.vault_ref.can_edit) {
        Some(editable) => Decision::UpdateExpiry(editable),
        None => Decision::None(saved.first()),
    }
}

/// The submitted card for the banner: its brand and last four digits, never more of the number.
fn shown(digits: &str) -> Value {
    json!({ "brand": card_brand(digits.to_string()), "last4": &digits[digits.len() - 4..] })
}

fn about(saved: &Saved) -> Value {
    json!({
        "id": saved.item.id, "title": saved.item.title, "vault": vault_json(&saved.vault_ref),
        "saved_expiry_month": saved.card.expiry_month, "saved_expiry_year": saved.card.expiry_year,
    })
}

fn merge(mut a: Value, b: Value) -> Value {
    if let (Some(a), Value::Object(b)) = (a.as_object_mut(), b) {
        a.extend(b);
    }
    a
}

impl Agent {
    /// `cards.save_check`: see [`decide`]. `save_new` also lists the vaults a new card can go to
    /// and the default one.
    pub(super) fn rpc_cards_save_check(&self, p: CardSaveCheckParams) -> RpcResult {
        secure_page_host(&p.url)?;
        let digits = card_digits(&p.number)?;
        let expiry = expiry(p.expiry_month, p.expiry_year)?;
        // Like `logins.save_check`: the extension asks on its own after a submit, which isn't use.
        let opened = self.opened_or_locked()?;
        if !self.within_rate(
            "card_save_check",
            CHECKS_PER_MINUTE,
            Duration::from_secs(60),
        ) {
            return Err(RpcError::new(
                ErrorCode::RateLimited,
                "Too many checks. Wait a minute",
            ));
        }
        let saved = saved_with_number(&opened, &digits);
        let answer = match decide(&saved, expiry) {
            Decision::None(Some(saved)) => merge(json!({ "action": "none" }), about(saved)),
            Decision::None(None) => json!({ "action": "none" }),
            Decision::UpdateExpiry(saved) => {
                merge(json!({ "action": "update_expiry" }), about(saved))
            }
            Decision::SaveNew => json!({
                "action": "save_new",
                "vaults": vaults_json(&opened.editable()),
                "default_vault": opened.default_save(None),
            }),
        };
        Ok(merge(answer, shown(&digits)))
    }

    /// `cards.save`: with `id`, sets the expiry of that saved card, which must have this number.
    /// Without `id`, decides again as `cards.save_check` would, so a late second Save never adds
    /// a duplicate.
    pub(super) fn rpc_cards_save(&self, p: CardSaveParams) -> RpcResult {
        secure_page_host(&p.url)?;
        let digits = card_digits(&p.number)?;
        let expiry = expiry(p.expiry_month, p.expiry_year)?;
        let holder = line("cardholder_name", p.cardholder_name.as_deref(), MAX_HOLDER)?;
        let title = line("title", p.title.as_deref(), MAX_TITLE)?;
        let opened = self.opened_or_locked()?;
        self.edit_rate()?;
        let saved = saved_with_number(&opened, &digits);
        let target = match p.id.as_deref() {
            Some(id) => {
                let found = saved
                    .iter()
                    .find(|s| s.item.id == id)
                    .ok_or_else(|| RpcError::new(ErrorCode::NotFound, "no such card"))?;
                if !found.vault_ref.can_edit {
                    return Err(read_only());
                }
                if expiry == (0, 0) || found.same_expiry(expiry) {
                    Some(Err(found))
                } else {
                    Some(Ok(found))
                }
            }
            None => match decide(&saved, expiry) {
                Decision::None(found) => found.map(Err),
                Decision::UpdateExpiry(found) => Some(Ok(found)),
                Decision::SaveNew => None,
            },
        };
        match target {
            // Saved as is: write nothing.
            Some(Err(found)) => Ok(merge(
                json!({ "id": found.item.id, "unchanged": true, "vault": vault_json(&found.vault_ref) }),
                shown(&digits),
            )),
            Some(Ok(found)) => {
                let mut item = found.item.clone();
                let card = item.card.get_or_insert_with(CardData::default);
                card.expiry_month = expiry.0;
                card.expiry_year = expiry.1;
                if card.cardholder_name.trim().is_empty() && !holder.is_empty() {
                    card.cardholder_name = holder;
                }
                let saved = found.vault.upsert(item)?;
                self.edited()?;
                Ok(merge(
                    json!({ "id": saved.id, "title": saved.title, "updated": true,
                            "vault": vault_json(&found.vault_ref) }),
                    shown(&digits),
                ))
            }
            None => {
                let (vault_ref, vault) = new_item_vault(&opened, p.vault.as_deref())?;
                let saved = vault.upsert(Item {
                    kind: ItemKind::Card,
                    title,
                    card: Some(CardData {
                        cardholder_name: holder,
                        number: digits.clone(),
                        expiry_month: expiry.0,
                        expiry_year: expiry.1,
                        ..Default::default()
                    }),
                    ..Default::default()
                })?;
                self.edited()?;
                Ok(merge(
                    json!({ "id": saved.id, "title": saved.title, "vault": vault_json(&vault_ref) }),
                    shown(&digits),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{card_digits, expiry};

    #[test]
    fn numbers_and_expiries() {
        assert_eq!(
            card_digits("4242 4242 4242 4242").unwrap(),
            "4242424242424242"
        );
        assert_eq!(
            card_digits("5555-5555-5555-4444").unwrap(),
            "5555555555554444"
        );
        for bad in ["4242 4242 4242 4241", "4242", "", "4242x4242x4242x4242"] {
            assert!(card_digits(bad).is_err(), "{bad}");
        }
        assert_eq!(expiry(Some(4), Some(29)).unwrap(), (4, 2029));
        assert_eq!(expiry(Some(4), Some(2029)).unwrap(), (4, 2029));
        assert_eq!(expiry(Some(4), None).unwrap(), (0, 0));
        assert_eq!(expiry(None, None).unwrap(), (0, 0));
        assert!(expiry(Some(13), Some(29)).is_err());
        assert!(expiry(Some(1), Some(10_000)).is_err());
    }
}
