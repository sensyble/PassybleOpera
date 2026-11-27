//! The browser extension's own vault: pass-agent's request handlers and pass-core compiled to
//! WebAssembly. [`BrowserHost`] keeps the vault file in memory and never waits for a person; the
//! extension stores the file, drives the timers and exchanges JSON strings with it.

pub mod account;
pub mod drive;
mod host;
pub mod teams;
pub mod ui;

#[cfg(target_arch = "wasm32")]
mod bindings;
#[cfg(target_arch = "wasm32")]
pub use bindings::{
    set_kdf, BrowserAgent, JsAccountKey, JsAccountPassword, JsApprovedKeys, JsDeviceApprovalKeys,
    JsDriveCall, JsSharedVault,
};

pub use host::{
    envelope, master_password_check_json, site_suggestions_json, BrowserConfig, BrowserHost,
    BrowserOptions, HostResult, GRANT_TTL, VAULT_PATH,
};
