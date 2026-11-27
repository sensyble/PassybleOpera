//! The extension popup's vault switcher and pins: `vaults.pins`, `vaults.set_pins`, `vaults.own`
//! and `vaults.switch`.

use pass_core::MAX_PINNED_VAULTS;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{ErrorCode, RpcError, RpcResult};
use crate::Agent;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SetPinsParams {
    ids: Vec<String>,
    /// Vaults the caller lists beside the agent's: the browser vault's shared vaults, which the
    /// extension opens itself.
    #[serde(default)]
    known: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SwitchParams {
    id: String,
}

fn pins_json(pins: Vec<String>) -> Value {
    json!({ "pins": pins, "max": MAX_PINNED_VAULTS })
}

impl Agent {
    /// `vaults.pins`: the pinned vault ids, in pin order.
    pub(super) fn rpc_vaults_pins(&self) -> RpcResult {
        self.unlocked()?;
        Ok(pins_json(self.pinned_vaults()?))
    }

    /// `vaults.set_pins`: saves the pins (all of them, in order; [`Agent::set_pinned_vaults`]).
    pub(super) fn rpc_vaults_set_pins(&self, p: SetPinsParams) -> RpcResult {
        self.unlocked()?;
        self.edit_rate()?;
        Ok(pins_json(self.set_pinned_vaults_with(p.ids, p.known)?))
    }

    /// `vaults.own`: the app's own vaults on this device ([`crate::Ui::own_vaults`]).
    pub(super) fn rpc_vaults_own(&self) -> RpcResult {
        let vaults = self.ui.own_vaults().ok_or_else(no_switcher)?;
        Ok(json!({ "vaults": vaults }))
    }

    /// `vaults.switch`: the app opens own vault `id` instead ([`crate::Ui::switch_vault`]).
    /// `switching: false` when it is the open one already.
    pub(super) fn rpc_vaults_switch(&self, p: SwitchParams) -> RpcResult {
        let vaults = self.ui.own_vaults().ok_or_else(no_switcher)?;
        let target = vaults
            .iter()
            .find(|v| v.id == p.id)
            .ok_or_else(|| RpcError::new(ErrorCode::NotFound, "no such vault"))?;
        if target.active {
            return Ok(json!({ "switching": false }));
        }
        match self.ui.switch_vault(&p.id) {
            Some(true) => Ok(json!({ "switching": true })),
            Some(false) => Err(RpcError::new(ErrorCode::NotFound, "no such vault")),
            None => Err(no_switcher()),
        }
    }
}

fn no_switcher() -> RpcError {
    RpcError::new(
        ErrorCode::NotSupported,
        "this Passyble app has only the one vault",
    )
}
