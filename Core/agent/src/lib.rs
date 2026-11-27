//! The headless part of the Passyble desktop app: holds the unlocked vault, auto-locks it, keeps
//! the vault file in sync and answers browser-extension requests over local IPC. The GUI supplies
//! a [`Ui`]. Without the `native` feature the same handlers build for WebAssembly.

mod agent;
pub mod app_versions;
mod ai;
pub mod clock;
/// Process hardening of the desktop app and the native host (no crash dumps, memory closed to
/// other processes of the user).
#[cfg(feature = "native")]
pub mod harden;
#[cfg(feature = "native")]
pub mod ipc;
mod kept_list;
mod otp_history;
mod pins;
#[cfg(feature = "native")]
mod platform_passkey;
mod protocol;
mod read_only;
pub mod store;
pub mod timing;

#[cfg(feature = "gdrive")]
pub use agent::GDriveTarget;
pub use agent::{
    Agent, AgentConfig, AgentHost, LinkedError, LinkedNotice, LinkedStatus, LinkedVaultConfig,
    LockKind, PasswordPolicy, PasswordPolicyMode, PendingOtp, TeamsSummary, Timers, VaultKind,
    VaultRef, WindowMatch, DELETE_UNDO_WINDOW, USE_SAVE_DELAY,
};
pub use ai::{
    command_line as ai_command_line, AiAction, AiClient, AiDecision, AiGrant, AiLogEntry,
    AiOutcome, AiRevealRequest, AiRunRequest, AiSecretUse, MAX_LOG as AI_MAX_LOG,
};
pub use kept_list::{set_default_sealer as set_default_kept_sealer, Sealer as KeptSealer};

/// A hook that is set once at start was already set; the existing one is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlreadySet;

impl std::fmt::Display for AlreadySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("already set")
    }
}

impl std::error::Error for AlreadySet {}
pub use otp_history::OtpOutcome;
#[cfg(feature = "native")]
pub use platform_passkey::{
    PasskeyMetadata, PlatformAssertion, PlatformCreateRequest, PlatformCreated, PlatformGetRequest,
};
pub use protocol::check::check_json as password_check_json;
pub use protocol::{ErrorCode, RpcError, BACKGROUND_METHODS};
pub use read_only::{allows as read_only_allows, READ_ONLY_METHODS, UPDATE_REQUIRED_MESSAGE};

/// The user's answer to "save this passkey?".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Consent {
    /// Store it, attached to `item_id` when given.
    Approve {
        item_id: Option<String>,
    },
    Deny,
}

/// The outcome of [`Ui::verify_user`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verification {
    /// The user just verified (Windows Hello, or the unlock this request asked for). Passkey
    /// responses carry the UV flag.
    Verified,
    /// Allowed without verifying now (no per-fill policy, or within its grace period). No UV flag.
    Allowed,
    /// Declined or failed: the request is refused with `cancelled`.
    Refused,
    /// This host can't prompt during a request: it fails with `verification_required` and the
    /// host retries with its own grant. The desktop app never answers this.
    Required,
}

/// What [`Ui::verify_item`] lets out of the vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemSecret {
    /// The login's password goes to the browser (`logins.fill`, `logins.fill_cross`).
    Password,
    /// A 2FA code of the login (`totp.get`, `totp.popup`). `follows_fill`: the login was just
    /// filled on this site ([`Agent::pending_otp`]).
    Code { follows_fill: bool },
    /// A passkey of the login signs a sign-in (`passkey.get`).
    Passkey,
}

/// Result of an unlock from the extension's unlock form (`unlock.password`, `unlock.hello`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnlockAttempt {
    Unlocked,
    /// The master password didn't open the vault (`wrong_password`).
    WrongPassword,
    /// The user cancelled Windows Hello (`cancelled`).
    Cancelled,
    /// Windows Hello can't unlock now (`not_supported`, with this text).
    Unavailable(String),
    /// Anything else, as a sentence for the user (`internal`).
    Failed(String),
}

/// What the browser extension's own unlock form may offer (`unlock.options`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnlockOptions {
    /// Windows Hello can unlock the vault now.
    pub hello: bool,
}

/// One passkey the user can pick for a sign-in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeyChoice {
    pub item_id: String,
    pub title: String,
    pub user_name: String,
}

/// The user's answer to [`Ui::choose_passkey_for_browser`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasskeyPick {
    /// Sign in with this one (an index into the options).
    Chosen(usize),
    /// "Use another device": the agent answers `not_found` and the extension hands the request
    /// to the browser's own WebAuthn.
    Elsewhere,
    /// Closed or timed out: `cancelled`.
    Cancelled,
}

/// "Fill a login from another site?" (`logins.fill_cross`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossFillRequest {
    pub item_id: String,
    pub title: String,
    pub username: String,
    /// The login's site: the registrable domain (or host) of its first website, `""` if none.
    pub item_domain: String,
    /// The host of the page it would be filled into.
    pub page_host: String,
    /// The page looks like the login's site without being it (`pass_core::Vault::lookalike_for_url`:
    /// `paypa1.com` for a `paypal.com` login): the prompt warns that it may be a phishing copy.
    pub lookalike: Option<pass_core::Lookalike>,
}

/// "Fill this card?" (`cards.fill`). Cards aren't bound to a site, so every fill or copy is
/// confirmed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CardFillRequest {
    pub item_id: String,
    pub title: String,
    /// `visa`, `mastercard`, etc. (`""` if unknown).
    pub brand: String,
    /// The last four digits only (`""` without a number).
    pub last4: String,
    /// The host of the page (frame) the card would go to, as the browser reported it.
    pub page_host: String,
    /// The top page's host when the form is in a frame of another host, else `""`. Shown in the
    /// prompt only.
    pub top_host: String,
    /// The popup copies a value instead of filling a page.
    pub copy: bool,
}

/// The app's Passyble account as the browser extension sees it in app mode (`account.status`):
/// signed in or not, and as whom. Never a token, the account id or anything else.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountSummary {
    pub signed_in: bool,
    /// The account's e-mail address while signed in.
    pub email: Option<String>,
}

/// The app's Passyble account as the browser extension in browser mode sees it for the
/// same-computer sign-in handoff (`account.peer`): each side may sign the other
/// in, and a sign-out on one side may sign the other out too. Never a token or the account id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountPeer {
    pub signed_in: bool,
    /// The account's e-mail address while signed in; while signed out with
    /// [`AccountPeer::sign_out_extension`], the address the app signed out of.
    pub email: Option<String>,
    /// The extension may sign the app in (`account.handoff_begin`). `false` after the user signed
    /// out of the app and chose to keep the extension signed in, until the user signs in to the
    /// app again.
    pub accepts_handoff: bool,
    /// The user signed out of the app and asked to sign out of the browser extension too: an
    /// extension signed in to [`AccountPeer::email`] signs out, then sends
    /// `account.peer_signed_out`.
    pub sign_out_extension: bool,
}

/// A sign-in code the signed-in app got from the Passyble service for the browser extension
/// (`account.handoff_to_extension`): 60 seconds, single use, bound to the extension's challenge.
/// Never logged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandoffCode {
    pub code: String,
    /// The account's e-mail address.
    pub email: String,
}

/// What the signed-out app hands to the browser extension so the extension can get it a sign-in
/// code (`account.handoff_begin`): the S256 challenge of a verifier only the app holds, and the
/// name the device list shows for the app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandoffRequest {
    pub code_challenge: String,
    pub device_name: String,
}

/// Why one of the account handoff methods (`account.handoff_*`, `account.sign_out`,
/// `account.peer_signed_out`) did nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountError {
    /// This UI has no Passyble account (the agent answers `not_supported`).
    NotSupported,
    /// Not in the state the method needs: signed out (or in), the user turned the handoff off, no
    /// pending sign-in or it ran out (`invalid_state`, with this message).
    InvalidState(String),
    /// The Passyble service refused or could not be reached, in the user's language (`internal`).
    Failed(String),
}

/// One of the user's own vaults on this device (the desktop app's vault list), for the browser
/// extension's vault switcher (`vaults.own`). Only one of them is open at a time.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct OwnVault {
    /// The app's id for it: what `vaults.switch` takes.
    pub id: String,
    /// Its vault id (as in `vaults.list` and the pins), once it was opened on this device.
    pub vault_id: Option<String>,
    pub name: String,
    /// Where it is kept: a file path, "Google Drive · <account>" or a server's host.
    pub location: String,
    /// The vault the app has open (or would unlock next).
    pub active: bool,
}

/// What `sync.now` did: how many open vaults synced, which failed and why, and
/// whether no open vault has sync set up at all (`no_sync`: the app offers "Set up sync").
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct SyncReport {
    pub synced: u32,
    pub failed: Vec<SyncFailure>,
    pub no_sync: bool,
}

/// A vault [`SyncReport`] couldn't sync: its name and the reason, in words for the user.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SyncFailure {
    pub vault: String,
    pub reason: String,
}

/// Why a secret is about to leave the vault, or a change go in: the line under "Confirm it's you"
/// for [`Ui::verify_user`] and [`Ui::require_verification`] (and the Windows Hello dialog's
/// message). Typed rather than text so the UI can say it in the user's language; `Display` is the
/// English text, for logs and tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    /// `logins.fill`: "Fill your {title} login".
    FillLogin { title: String },
    /// `logins.fill_cross`: "Fill your {title} login into {host}" (a page of another site).
    FillLoginInto { title: String, host: String },
    /// `totp.get` / `totp.popup` for a login that wasn't just filled: "Use the 2FA code of {title}".
    UseCode { title: String },
    /// `logins.copy` of a password: "Copy the password of {title}".
    CopyPassword { title: String },
    /// `logins.copy` of a 2FA code: "Copy the 2FA code of {title}".
    CopyCode { title: String },
    /// `logins.get_for_edit`: "Edit your {title} login".
    EditLogin { title: String },
    /// `logins.update`: "Save changes to {title}".
    SaveChanges { title: String },
    /// `logins.create`: "Add a login for {site}".
    AddLogin { site: String },
    /// `logins.delete`: "Delete {title}".
    DeleteLogin { title: String },
    /// `totp.set`: "Change the 2FA code of {title}".
    ChangeCode { title: String },
    /// `cards.fill`: "Fill your {title} card on {host}".
    FillCard { title: String, host: String },
    /// `cards.fill` from the popup (a copy): "Copy from your {title} card".
    CopyCard { title: String },
    /// `notes.get`: "Show your {title} note".
    ShowNote { title: String },
    /// `notes.get` with `copy`: "Copy your {title} note".
    CopyNote { title: String },
    /// `passkey.create`: "Save a passkey for {site}" (the relying party ID).
    SavePasskey { site: String },
    /// `passkey.get`: "Sign in to {site} with a passkey" (the relying party ID).
    PasskeySignIn { site: String },
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reason::FillLogin { title } => write!(f, "Fill your {title} login"),
            Reason::FillLoginInto { title, host } => {
                write!(f, "Fill your {title} login into {host}")
            }
            Reason::UseCode { title } => write!(f, "Use the 2FA code of {title}"),
            Reason::CopyPassword { title } => write!(f, "Copy the password of {title}"),
            Reason::CopyCode { title } => write!(f, "Copy the 2FA code of {title}"),
            Reason::EditLogin { title } => write!(f, "Edit your {title} login"),
            Reason::SaveChanges { title } => write!(f, "Save changes to {title}"),
            Reason::AddLogin { site } => write!(f, "Add a login for {site}"),
            Reason::DeleteLogin { title } => write!(f, "Delete {title}"),
            Reason::ChangeCode { title } => write!(f, "Change the 2FA code of {title}"),
            Reason::FillCard { title, host } => write!(f, "Fill your {title} card on {host}"),
            Reason::CopyCard { title } => write!(f, "Copy from your {title} card"),
            Reason::ShowNote { title } => write!(f, "Show your {title} note"),
            Reason::CopyNote { title } => write!(f, "Copy your {title} note"),
            Reason::SavePasskey { site } => write!(f, "Save a passkey for {site}"),
            Reason::PasskeySignIn { site } => write!(f, "Sign in to {site} with a passkey"),
        }
    }
}

/// Everything the agent needs from the user. Calls may block (they run on IPC threads).
pub trait Ui: Send + Sync {
    /// Shows the unlock window and blocks until the vault is unlocked (`true`) or the user gives up.
    fn request_unlock(&self) -> bool;
    /// What the extension's unlock form may offer (`unlock.options`). Default: password only.
    fn unlock_options(&self) -> UnlockOptions {
        UnlockOptions::default()
    }
    /// `unlock.password` from the extension's unlock form. Blocks. `None` (the default) makes the
    /// agent call [`Agent::unlock`] itself. The password must never be logged or kept.
    fn unlock_with_password(&self, password: &str) -> Option<UnlockAttempt> {
        let _ = password;
        None
    }
    /// `unlock.hello` from the extension's unlock form. Blocks while the prompt is up.
    /// Default: unavailable.
    fn unlock_with_hello(&self) -> UnlockAttempt {
        UnlockAttempt::Unavailable("Windows Hello isn't available here".into())
    }
    /// `unlock.cancel`: cancels a pending [`Ui::unlock_with_hello`] (which then answers
    /// `cancelled`). Returns `true` if one was pending. Never prompts.
    fn cancel_unlock(&self) -> bool {
        false
    }
    /// Features this host adds to `status.features`. Default: none.
    fn host_features(&self) -> &'static [&'static str] {
        &[]
    }
    /// Whether [`Ui::unlock_with_hello`] prompts over the browser window and
    /// [`Ui::cancel_unlock`] can cancel it (advertised as `unlock.hello_browser`).
    fn hello_in_browser(&self) -> bool {
        false
    }
    /// The browser extension asked for logins (`logins.find` for a page, `logins.search` from
    /// its popup): a hint that the vault is about to be used, so a host with a sync schedule can
    /// check for other devices' changes. Must return at once; the answer never waits for a sync.
    /// Default: nothing.
    fn logins_requested(&self) {}
    /// "Save a passkey for {user} on {site}?" for a request that wasn't answered in the browser
    /// already (`passkey.create` without `consent`; the Windows passkey provider). Blocks.
    fn confirm_passkey_create(&self, rp_id: &str, user_name: &str) -> Consent;
    /// Returns the index of the chosen passkey, or `None` if the user cancelled.
    fn choose_passkey(&self, rp_id: &str, options: &[PasskeyChoice]) -> Option<usize>;
    /// [`Ui::choose_passkey`] for `passkey.get` from the extension, which can also answer
    /// [`PasskeyPick::Elsewhere`]. Default: [`Ui::choose_passkey`].
    fn choose_passkey_for_browser(&self, rp_id: &str, options: &[PasskeyChoice]) -> PasskeyPick {
        self.choose_passkey(rp_id, options)
            .map_or(PasskeyPick::Cancelled, PasskeyPick::Chosen)
    }
    /// Windows fallback when a code can't be filled: an always-on-top popup with the live code.
    fn show_totp_popup(&self, item_id: &str, title: &str);
    fn notify_lock_state(&self, locked: bool);
    /// Asked right before a secret leaves the vault for the browser. Blocks.
    /// [`Verification::Refused`] fails the request with `cancelled`, and only
    /// [`Verification::Verified`] sets the WebAuthn UV flag. Default: allowed.
    fn verify_user(&self, reason: &Reason) -> Verification {
        let _ = reason;
        Verification::Allowed
    }
    /// [`Ui::verify_user`] for a secret of login `item_id`, so the UI can tie the answer to that
    /// login. Default: a code that follows its login's fill is allowed, anything else asks
    /// [`Ui::verify_user`].
    fn verify_item(&self, reason: &Reason, item_id: &str, secret: ItemSecret) -> Verification {
        let _ = item_id;
        match secret {
            ItemSecret::Code { follows_fill: true } => Verification::Allowed,
            _ => self.verify_user(reason),
        }
    }
    /// Like [`Ui::verify_user`] for WebAuthn `userVerification: "required"`: only
    /// [`Verification::Verified`] succeeds; anything else answers `not_supported` so the extension
    /// falls back to the browser's WebAuthn.
    fn require_verification(&self, reason: &Reason) -> Verification {
        match self.verify_user(reason) {
            Verification::Verified => Verification::Verified,
            Verification::Required => Verification::Required,
            Verification::Allowed | Verification::Refused => Verification::Refused,
        }
    }
    /// `server.pair`: show the pairing dialog prefilled with `link` and return right away. The
    /// link must never be applied without the user confirming it. `false` if there is no dialog.
    fn show_server_pairing(&self, link: &str) -> bool {
        let _ = link;
        false
    }
    /// The extension changed the vault; open windows should reload.
    fn vault_changed(&self) {}
    /// The open vault's name when the user has several, for `passkey.create_options`.
    fn vault_name(&self) -> Option<String> {
        None
    }
    /// A credential was just used ([`Agent::note_use`]). Must not block.
    fn credential_used(&self) {}
    /// `app.show_item`: bring up the main window on that item. `false` if this UI can't.
    fn show_item(&self, item_id: &str) -> bool {
        let _ = item_id;
        false
    }
    /// `logins.copy` or `generate.copy`: put `text` on the clipboard as a secret. `false` if this
    /// UI can't.
    fn copy_to_clipboard(&self, text: &str) -> bool {
        let _ = text;
        false
    }
    /// Asks before a login is filled into another site's page. Blocks. `None` if this UI has no
    /// such prompt.
    fn confirm_cross_fill(&self, request: &CrossFillRequest) -> Option<bool> {
        let _ = request;
        None
    }
    /// Asks before a payment card leaves the vault (`cards.fill`), every time. Blocks. `None` if
    /// this UI has no such prompt. [`Ui::verify_user`] follows a yes.
    fn confirm_card_fill(&self, request: &CardFillRequest) -> Option<bool> {
        let _ = request;
        None
    }
    /// What waits for the user in the app's Teams and Family screen (`vaults.list` `teams`):
    /// invitations, people to confirm, unseen notices. `None` (the default): no Passyble account,
    /// or this UI has no such screen.
    fn teams_summary(&self) -> Option<TeamsSummary> {
        None
    }
    /// A Team's password rule for this device (`vaults.list` `password_policy`). `None` (the
    /// default): no Team, the Team leaves it to the member, or this UI has no Teams screen. While a
    /// `second_password` rule isn't met the app also hands over the team's shared vaults as not
    /// writable ([`LinkedVaultConfig::writable`]), so they are read here and changed nowhere.
    fn password_policy(&self) -> Option<PasswordPolicy> {
        None
    }
    /// `app.show_teams`: bring up the Teams and Family screen on `section` (`shared`, `invites`,
    /// `confirm`, `members`, `notices`, or anything else for the overview). `false` if this UI
    /// can't (the default; the agent answers `not_supported`).
    fn show_teams(&self, section: &str) -> bool {
        let _ = section;
        false
    }
    /// `account.status`: the app's Passyble account for the browser extension in app mode (signed
    /// in or not, the e-mail address; no token). Must not block or prompt. `None` (the default):
    /// this UI has no Passyble account (the agent answers `not_supported`).
    fn account_summary(&self) -> Option<AccountSummary> {
        None
    }
    /// `app.show_account`: bring up the app's Passyble account (Settings, its account row); with
    /// `sign_in`, start the app's own account sign-in in the system browser too, as that row's
    /// Sign in button does. Returns at once (the sign-in goes on in the app). `false` if this UI
    /// can't (the default; the agent answers `not_supported`).
    fn show_account(&self, sign_in: bool) -> bool {
        let _ = sign_in;
        false
    }
    /// `account.peer`: the app's Passyble account for the browser extension in browser mode, for
    /// the same-computer sign-in handoff. Must not block or prompt (the extension asks on its own,
    /// every half minute at most). `None` (the default): this UI has no Passyble account (the agent
    /// answers `not_supported`).
    fn account_peer(&self) -> Option<AccountPeer> {
        None
    }
    /// `account.handoff_to_extension`: the app is signed in and the extension isn't. Ask the
    /// Passyble service (with the app's own access token) for a sign-in code for the extension,
    /// bound to `code_challenge` (43 base64url characters, checked by the agent); `device_name` is
    /// the extension's name for the device list. Blocks for the request. Default:
    /// [`AccountError::NotSupported`].
    fn handoff_to_extension(
        &self,
        code_challenge: &str,
        device_name: &str,
    ) -> Result<HandoffCode, AccountError> {
        let _ = (code_challenge, device_name);
        Err(AccountError::NotSupported)
    }
    /// `account.handoff_begin`: the app is signed out and takes a sign-in from the extension.
    /// Make a fresh PKCE verifier, keep it in memory only for 60 seconds (a new begin replaces
    /// it) and answer its challenge. Default: [`AccountError::NotSupported`].
    fn handoff_begin(&self) -> Result<HandoffRequest, AccountError> {
        Err(AccountError::NotSupported)
    }
    /// `account.handoff_finish`: redeem the code the extension got for the pending verifier
    /// (single use) and keep the new session as any sign-in. Blocks for the request. Answers the
    /// account's e-mail address. Default: [`AccountError::NotSupported`].
    fn handoff_finish(&self, code: &str) -> Result<String, AccountError> {
        let _ = code;
        Err(AccountError::NotSupported)
    }
    /// `account.sign_out`: the user signed out of the extension and ticked "also sign out of the
    /// Passyble app". Sign out as the app's own Sign out does, without asking again (the user
    /// confirmed in the extension). Blocks for the request. Default:
    /// [`AccountError::NotSupported`].
    fn sign_out_from_extension(&self) -> Result<(), AccountError> {
        Err(AccountError::NotSupported)
    }
    /// `account.peer_signed_out`: the extension signed itself out because the app asked it to
    /// ([`AccountPeer::sign_out_extension`]); forget that request. Default:
    /// [`AccountError::NotSupported`].
    fn peer_signed_out(&self) -> Result<(), AccountError> {
        Err(AccountError::NotSupported)
    }
    /// `sync.now`: sync every open vault that has sync set up and say how it went. Blocks until
    /// done; the vault is unlocked. `None` (the default): the agent syncs what it can itself
    /// ([`Agent::sync_report`]).
    fn sync_now(&self) -> Option<SyncReport> {
        None
    }
    /// `vaults.own`: the user's own vaults on this device, for the browser extension's vault
    /// switcher. Must not block or prompt. `None` (the default): this host has only the one vault.
    fn own_vaults(&self) -> Option<Vec<OwnVault>> {
        None
    }
    /// `vaults.switch`: bring up the app with the unlock of own vault `id`; the open vault stays
    /// open until the other one is unlocked. Returns at once. `Some(false)`: no such vault; `None`
    /// (the default): this UI can't (the agent answers `not_supported`).
    fn switch_vault(&self, id: &str) -> Option<bool> {
        let _ = id;
        None
    }
    /// An AI tool (through `passyble-mcp`) wants to run a command with item secrets in its
    /// environment, and at least one item is "Ask every time" with no grant for this client. Show
    /// the client, items, fields, command and working directory with Deny, Allow once and "Allow
    /// until the vault locks". Blocks; no answer within about 2 minutes is [`AiDecision::Deny`].
    /// `None` (the default): no such prompt, the agent answers `not_supported`.
    fn confirm_ai_run(&self, request: &AiRunRequest) -> Option<AiDecision> {
        let _ = request;
        None
    }
    /// An AI tool asks for the raw value of a field (`reveal_secret`), which then goes into the AI
    /// chat and to the AI provider, so the prompt must say so. Asked every time, even with a grant.
    /// Blocks; `Some(true)` only for an explicit yes. `None` (the default): no such prompt, the
    /// agent answers `not_supported`.
    fn confirm_ai_reveal(&self, request: &AiRevealRequest) -> Option<bool> {
        let _ = request;
        None
    }
    /// The log of AI requests or the grants changed (an AI tools page may refresh). Must not block.
    /// Default: nothing.
    fn ai_activity(&self) {}
    /// Whether AI tools may use the marked items of shared vault `vault` (never asked for the home
    /// vault). The desktop app says no when the organisation disallows export, since a secret an
    /// AI tool gets leaves Passyble just as an export does. Must not block. Default: yes.
    fn ai_allows_vault(&self, vault: &VaultRef) -> bool {
        let _ = vault;
        true
    }
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
