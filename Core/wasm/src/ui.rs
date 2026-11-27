//! The browser's [`Ui`]. No call may wait for a person here: the extension asks in its own pages
//! first and the answer travels with the request ([`RequestGrants`]). Prompts only the desktop has
//! fail as they would with a desktop UI that lacks them.

use std::sync::{Mutex, MutexGuard};

use pass_agent::{
    CardFillRequest, Consent, CrossFillRequest, ItemSecret, PasskeyChoice, PasskeyPick, Reason, Ui,
    Verification,
};
use serde_json::json;
use zeroize::Zeroizing;

/// What the extension decided for the request being handled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RequestGrants {
    /// A valid grant came with this request.
    pub verified: bool,
    /// The user said yes to this fill in an extension page.
    pub confirmed: bool,
}

/// Something the extension does for the agent.
pub enum Effect {
    /// Put a secret on the clipboard.
    Copy(Zeroizing<String>),
    /// The vault was locked (`true`) or unlocked.
    LockState(bool),
    VaultChanged,
}

impl Effect {
    /// Writes the effect as JSON into `out`, which must already have room so that growing it
    /// leaves no copy of a secret behind.
    fn write_json(&self, out: &mut String) {
        match self {
            Effect::Copy(text) => {
                let quoted =
                    Zeroizing::new(serde_json::to_string(text.as_str()).unwrap_or_default());
                out.push_str(r#"{"type":"copy","text":"#);
                out.push_str(&quoted);
                out.push('}');
            }
            Effect::LockState(locked) => {
                out.push_str(&json!({ "type": "lock_state", "locked": locked }).to_string())
            }
            Effect::VaultChanged => out.push_str(r#"{"type":"vault_changed"}"#),
        }
    }

    /// Room [`Effect::write_json`] needs at most (a JSON string escapes a character to at most
    /// six bytes).
    fn json_len(&self) -> usize {
        match self {
            Effect::Copy(text) => 32 + 6 * text.len(),
            _ => 48,
        }
    }
}

#[derive(Default)]
struct UiState {
    request: RequestGrants,
    verify_each_fill: bool,
    effects: Vec<Effect>,
}

/// The [`Ui`] of the browser extension's agent.
#[derive(Default)]
pub struct BrowserUi {
    state: Mutex<UiState>,
}

impl BrowserUi {
    pub fn new(verify_each_fill: bool) -> BrowserUi {
        let ui = BrowserUi::default();
        ui.state().verify_each_fill = verify_each_fill;
        ui
    }

    fn state(&self) -> MutexGuard<'_, UiState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// "Confirm it's you before each fill".
    pub fn set_verify_each_fill(&self, on: bool) {
        self.state().verify_each_fill = on;
    }

    /// What the extension decided for the request about to be handled; reset with
    /// [`BrowserUi::end_request`].
    pub fn begin_request(&self, grants: RequestGrants) {
        self.state().request = grants;
    }

    pub fn end_request(&self) {
        self.state().request = RequestGrants::default();
    }

    /// The effects since the last call, as a JSON array (`[]` if none). The copies' texts in the
    /// returned string are the caller's to clear.
    pub fn take_effects(&self) -> Zeroizing<String> {
        let effects = std::mem::take(&mut self.state().effects);
        let room = 2 + effects.iter().map(|e| e.json_len() + 1).sum::<usize>();
        let mut out = Zeroizing::new(String::with_capacity(room));
        out.push('[');
        for (i, effect) in effects.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            effect.write_json(&mut out);
        }
        out.push(']');
        out
    }

    fn push(&self, effect: Effect) {
        self.state().effects.push(effect);
    }

    /// An effect from outside a request, such as a Drive sync.
    pub fn push_effect(&self, effect: Effect) {
        self.push(effect);
    }

    fn grants(&self) -> (RequestGrants, bool) {
        let state = self.state();
        (state.request, state.verify_each_fill)
    }
}

impl Ui for BrowserUi {
    /// The extension opens its own unlock UI; the agent never waits for an unlock here.
    fn request_unlock(&self) -> bool {
        false
    }

    /// Reached only for a request without the page card's decision (`consent`).
    fn confirm_passkey_create(&self, _rp_id: &str, _user_name: &str) -> Consent {
        Consent::Deny
    }

    fn choose_passkey(&self, _rp_id: &str, _options: &[PasskeyChoice]) -> Option<usize> {
        None
    }

    fn choose_passkey_for_browser(&self, _rp_id: &str, _options: &[PasskeyChoice]) -> PasskeyPick {
        PasskeyPick::Cancelled
    }

    /// Never reached: `totp.popup` is answered `not_supported` before the agent.
    fn show_totp_popup(&self, _item_id: &str, _title: &str) {}

    fn notify_lock_state(&self, locked: bool) {
        self.push(Effect::LockState(locked));
    }

    fn verify_user(&self, _reason: &Reason) -> Verification {
        match self.grants() {
            (grants, _) if grants.verified => Verification::Verified,
            (_, true) => Verification::Required,
            (_, false) => Verification::Allowed,
        }
    }

    fn verify_item(&self, reason: &Reason, _item_id: &str, secret: ItemSecret) -> Verification {
        let (grants, _) = self.grants();
        match secret {
            ItemSecret::Code { follows_fill: true } if !grants.verified => Verification::Allowed,
            _ => self.verify_user(reason),
        }
    }

    /// A site demands user verification (passkeys): only a grant is one.
    fn require_verification(&self, _reason: &Reason) -> Verification {
        if self.grants().0.verified {
            Verification::Verified
        } else {
            Verification::Required
        }
    }

    fn vault_changed(&self) {
        self.push(Effect::VaultChanged);
    }

    fn copy_to_clipboard(&self, text: &str) -> bool {
        self.push(Effect::Copy(Zeroizing::new(text.to_string())));
        true
    }

    fn confirm_cross_fill(&self, _request: &CrossFillRequest) -> Option<bool> {
        Some(self.grants().0.confirmed)
    }

    fn confirm_card_fill(&self, _request: &CardFillRequest) -> Option<bool> {
        Some(self.grants().0.confirmed)
    }

    fn host_features(&self) -> &'static [&'static str] {
        &["vault.browser"]
    }
}
