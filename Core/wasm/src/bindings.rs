//! The JavaScript API: `BrowserAgent`, `DriveCall` and `setKdf`. Everything but bytes crosses as
//! JSON strings. Strings that can hold a secret are cleared in WebAssembly memory once JavaScript
//! has its copy.

use std::cell::RefCell;

use js_sys::{Array, Function, JsString, Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::host::{envelope, BrowserHost};
use crate::teams;

thread_local! {
    /// The host's Argon2id function (`setKdf`).
    static KDF: RefCell<Option<Function>> = const { RefCell::new(None) };
}

/// Hands every Argon2id run to `kdf(secret, salt, mKib, t, p) -> Uint8Array(32)`, or back to
/// this module with `undefined`. Call once before creating or unlocking a vault.
#[wasm_bindgen(js_name = setKdf)]
pub fn set_kdf(kdf: Option<Function>) {
    let runner = kdf
        .as_ref()
        .map(|_| host_argon2id as pass_core::Argon2idRunner);
    KDF.with(|slot| *slot.borrow_mut() = kdf);
    pass_core::set_argon2id_runner(runner);
}

/// `pass_core::Argon2idRunner` over the host's function. The copies of the secret and the key in
/// JavaScript are zeroed as soon as the call returns.
fn host_argon2id(secret: &[u8], salt: &[u8], m_kib: u32, t: u32, p: u32) -> Option<[u8; 32]> {
    let kdf = KDF.with(|slot| slot.borrow().clone())?;
    let secret = Uint8Array::from(secret);
    let args = Array::new();
    args.push(&secret);
    args.push(&Uint8Array::from(salt));
    args.push(&JsValue::from(m_kib));
    args.push(&JsValue::from(t));
    args.push(&JsValue::from(p));
    let out = kdf.apply(&JsValue::NULL, &args);
    secret.fill(0, 0, secret.length());
    let out: Uint8Array = out.ok()?.dyn_into().ok()?;
    let mut key = [0u8; 32];
    let ok = out.length() == 32;
    if ok {
        out.copy_to(&mut key);
    }
    out.fill(0, 0, out.length());
    ok.then_some(key)
}

/// The master password rule as a new master password is typed: `names` a JSON array of strings
/// (e-mail address, vault name). Answers the check as JSON (`host::master_password_check_json`).
/// Needs no `BrowserAgent`; the password is cleared here once checked.
#[wasm_bindgen(js_name = checkMasterPassword)]
pub fn check_master_password(password: String, names: &str) -> String {
    let password = Zeroizing::new(password);
    crate::host::master_password_check_json(&password, names)
}

/// Popular sites for a name or website being typed in an editor: a JSON array of
/// `{"name", "domain"}` (`host::site_suggestions_json`), plain JSON, no envelope. Needs no
/// `BrowserAgent`; nothing leaves the device.
#[wasm_bindgen(js_name = siteSuggestions)]
pub fn site_suggestions(query: &str, limit: u32) -> String {
    crate::host::site_suggestions_json(query, limit)
}

/// The name of the popular site of a website (a URL or host; `pass_core::site_for_domain`),
/// `undefined` for one not in the list. Needs no `BrowserAgent`.
#[wasm_bindgen(js_name = siteNameFor)]
pub fn site_name_for(url: &str) -> Option<String> {
    pass_core::site_for_domain(url.to_string())
}

/// A string for JavaScript, cleared here once copied out.
fn secret_out(text: Zeroizing<String>) -> JsString {
    JsString::from(text.as_str())
}

/// The browser extension's vault.
#[wasm_bindgen]
pub struct BrowserAgent {
    host: BrowserHost,
}

#[wasm_bindgen]
impl BrowserAgent {
    /// `config`: `{"device_id": "…", "auto_lock_secs": 900, "keep_list": true,
    /// "verify_each_fill": false}` (all but `device_id` optional). Throws on a bad config.
    #[wasm_bindgen(constructor)]
    pub fn new(config: &str) -> Result<BrowserAgent, JsError> {
        BrowserHost::from_json(config)
            .map(|host| BrowserAgent { host })
            .map_err(|e| JsError::new(&e.message))
    }

    /// Whether this browser has a vault.
    #[wasm_bindgen(js_name = hasVault)]
    pub fn has_vault(&self) -> bool {
        self.host.has_vault()
    }

    /// Loads a vault file. Locked only. `{"result": {"vault_id"}}`.
    pub fn load(&self, file: Vec<u8>) -> String {
        envelope(self.host.load(file))
    }

    /// A new vault with this master password, opened. `{"result": {"vault_id", "grant"}}`; then
    /// store `takeSave()`.
    pub fn create(&self, password: String) -> String {
        let password = Zeroizing::new(password);
        envelope(self.host.create(&password))
    }

    /// `{"result": {"locked": false, "grant"}}`, or `wrong_password`, `rate_limited`, `no_vault`.
    pub fn unlock(&self, password: String) -> String {
        let password = Zeroizing::new(password);
        envelope(self.host.unlock(&password))
    }

    /// Unlocks with the kept key after a service-worker restart. `{"result": {"locked": false}}`.
    #[wasm_bindgen(js_name = unlockWithKey)]
    pub fn unlock_with_key(&self, key: Vec<u8>, idle_ms: f64) -> String {
        let key = Zeroizing::new(key);
        envelope(self.host.unlock_with_key(&key, idle_ms.max(0.0) as u64))
    }

    /// The master password checked while unlocked: `{"result": {"grant"}}` for one request.
    #[wasm_bindgen(js_name = verifyPassword)]
    pub fn verify_password(&self, password: String) -> String {
        let password = Zeroizing::new(password);
        envelope(self.host.verify_password(&password))
    }

    /// Saves and locks (`completely`: also drops the login list kept for the menus). Store
    /// `takeSave()` afterwards.
    pub fn lock(&self, completely: bool) -> String {
        envelope(self.host.lock(completely))
    }

    /// `{"auto_lock_secs"?, "keep_list"?, "verify_each_fill"?}`. `{"result": {}}`.
    #[wasm_bindgen(js_name = setOptions)]
    pub fn set_options(&self, options: &str) -> String {
        envelope(self.host.set_options(options))
    }

    /// One protocol request line, optionally with `"grant"` and `"confirmed"` next to `params`.
    /// Returns the response line.
    pub fn handle(&self, line: String) -> JsString {
        let line = Zeroizing::new(line);
        secret_out(self.host.handle(&line))
    }

    /// Runs the agent's timers: call at `nextTickMs()` and after each request.
    pub fn tick(&self) {
        self.host.tick();
    }

    /// Milliseconds until `tick` has something to do; `undefined`: nothing to wait for.
    #[wasm_bindgen(js_name = nextTickMs)]
    pub fn next_tick_ms(&self) -> Option<f64> {
        self.host.next_tick().map(|d| d.as_millis() as f64)
    }

    /// Milliseconds since the vault was last used.
    #[wasm_bindgen(js_name = idleMs)]
    pub fn idle_ms(&self) -> f64 {
        self.host.idle().as_millis() as f64
    }

    /// A JSON array of `{"type": "copy", "text"}`, `{"type": "lock_state", "locked"}`,
    /// `{"type": "vault_changed"}` since the last call.
    #[wasm_bindgen(js_name = takeEffects)]
    pub fn take_effects(&self) -> JsString {
        secret_out(self.host.take_effects())
    }

    /// The encrypted vault file if the agent wrote it since the last call.
    #[wasm_bindgen(js_name = takeSave)]
    pub fn take_save(&self) -> Option<Vec<u8>> {
        self.host.take_save()
    }

    /// The encrypted vault file now (saved first while unlocked), `undefined` without a vault.
    #[wasm_bindgen(js_name = exportVault)]
    pub fn export_vault(&self) -> Option<Vec<u8>> {
        self.host.export().ok()
    }

    /// The unlocked vault's 32-byte key, `undefined` while locked.
    #[wasm_bindgen(js_name = vaultKey)]
    pub fn vault_key(&self) -> Option<Uint8Array> {
        self.host
            .vault_key()
            .map(|key| Uint8Array::from(key.as_slice()))
    }
}

/// One Google Drive operation, one HTTP request at a time. `begin()` gives the first step; send
/// each `{"send": ...}` request (body from `takeBody()`) and pass the answer to
/// `respond(status, headersJson, body)`, or call `fail(kind)`, until `{"done": ...}`. Then `free()`.
#[wasm_bindgen(js_name = DriveCall)]
pub struct JsDriveCall {
    call: crate::drive::DriveCall,
}

#[wasm_bindgen(js_class = DriveCall)]
impl JsDriveCall {
    /// The vaults in the account's Passyble folder (`[{file_id, vault_id, name, modified, size}]`).
    pub fn list(token: &str) -> JsDriveCall {
        JsDriveCall {
            call: crate::drive::DriveCall::list(token),
        }
    }

    /// One vault file; the bytes with `takeBytes()` once done.
    pub fn download(token: &str, file_id: &str) -> JsDriveCall {
        JsDriveCall {
            call: crate::drive::DriveCall::download(token, file_id),
        }
    }

    /// The token's Google account: `{email, display_name}`.
    pub fn account(token: &str) -> JsDriveCall {
        JsDriveCall {
            call: crate::drive::DriveCall::account(token),
        }
    }

    pub fn begin(&mut self) -> String {
        self.call.begin()
    }

    pub fn respond(&mut self, status: u16, headers: &str, body: Vec<u8>) -> String {
        self.call.respond(status, headers, body)
    }

    pub fn fail(&mut self, kind: &str) -> String {
        self.call.fail(kind)
    }

    #[wasm_bindgen(js_name = takeBody)]
    pub fn take_body(&mut self) -> Option<Vec<u8>> {
        self.call.take_body()
    }

    #[wasm_bindgen(js_name = takeBytes)]
    pub fn take_bytes(&mut self) -> Option<Vec<u8>> {
        self.call.take_bytes()
    }
}

#[wasm_bindgen]
impl BrowserAgent {
    /// Syncs the open vault with Google Drive; throws while locked. Once done, store `takeSave()`
    /// and apply `takeEffects()`.
    #[wasm_bindgen(js_name = driveSync)]
    pub fn drive_sync(&self, token: &str, vault_name: &str) -> Result<JsDriveCall, JsError> {
        crate::drive::DriveCall::sync(&self.host, token, vault_name)
            .map(|call| JsDriveCall { call })
            .map_err(|e| JsError::new(&e.message))
    }
}

// Teams and Family, secure send. Functions answer with the usual envelope; those that hand over
// bytes return an object and throw on errors.

fn js_error(e: pass_agent::RpcError) -> JsError {
    JsError::new(&e.message)
}

fn set(target: &Object, key: &str, value: &JsValue) {
    // Setting a property of a plain object can't fail.
    let _ = Reflect::set(target, &JsValue::from_str(key), value);
}

/// Encrypts a send. `options`: `{"kind": "text" | "file", "name"?, "mime"?, "expires_at",
/// "max_views"?, "password"?}`. Returns `{ciphertext: Uint8Array, meta, key, password_auth}`:
/// upload `ciphertext` and `meta`, put `key` in the link's fragment only. Throws on bad input.
#[wasm_bindgen(js_name = sendSeal)]
pub fn send_seal(data: Vec<u8>, options: String) -> Result<Object, JsError> {
    let options = Zeroizing::new(options);
    let (ciphertext, info) = teams::send_seal(data, &options).map_err(js_error)?;
    let out = Object::new();
    set(&out, "ciphertext", &Uint8Array::from(ciphertext.as_slice()));
    for key in ["meta", "key", "password_auth"] {
        let value = info[key]
            .as_str()
            .map(JsValue::from_str)
            .unwrap_or(JsValue::NULL);
        set(&out, key, &value);
    }
    Ok(out)
}

/// Opens a send with the link key (the fragment) and the password, if it has one. Returns
/// `{kind, name, mime, data: Uint8Array}`; throws when it doesn't open.
#[wasm_bindgen(js_name = sendOpen)]
pub fn send_open(
    ciphertext: Vec<u8>,
    meta: &str,
    key: &str,
    password: Option<String>,
) -> Result<Object, JsError> {
    let password = password.map(Zeroizing::new);
    let (header, data) =
        teams::send_open(ciphertext, meta, key, password.as_deref().cloned()).map_err(js_error)?;
    let out = Object::new();
    for field in ["kind", "name", "mime"] {
        set(
            &out,
            field,
            &JsValue::from_str(header[field].as_str().unwrap_or("")),
        );
    }
    set(&out, "data", &Uint8Array::from(data.as_slice()));
    Ok(out)
}

/// `{"result": {expires_at, max_views, size, has_password}}` from a send's metadata.
#[wasm_bindgen(js_name = sendInfo)]
pub fn send_info(meta: &str) -> String {
    envelope(teams::send_info(meta))
}

/// `{"result": {"auth"}}`: the password proof the service asks for before a download.
#[wasm_bindgen(js_name = sendPasswordAuth)]
pub fn send_password_auth(meta: &str, password: String) -> String {
    let password = Zeroizing::new(password);
    envelope(teams::send_password_auth(meta, password.to_string()))
}

/// `{"result": {"link"}}`.
#[wasm_bindgen(js_name = sendLink)]
pub fn send_link(base: &str, send_id: &str, key: &str) -> String {
    envelope(teams::send_link(base, send_id, key))
}

/// `{"result": {"send_id", "key"}}` from the page's own address.
#[wasm_bindgen(js_name = sendParseLink)]
pub fn send_parse_link(link: &str) -> String {
    envelope(teams::send_parse_link(link))
}

/// `{"result": [{"rule", "message"}]}`: what this device's settings break of the policy.
#[wasm_bindgen(js_name = policyCheck)]
pub fn policy_check(policy: &str, local: &str) -> String {
    envelope(teams::policy_check(policy, local))
}

/// `{"result": {"export", "sharing_outside", "auto_lock_secs"}}` under a policy (`undefined`:
/// no organisation) for the user's chosen auto-lock.
#[wasm_bindgen(js_name = policyAllows)]
pub fn policy_allows(policy: Option<String>, chosen_auto_lock_secs: Option<f64>) -> String {
    envelope(teams::policy_allows(
        policy.as_deref(),
        chosen_auto_lock_secs.map(|s| s.max(0.0) as u64),
    ))
}

/// Search across vaults: `groups` is a JSON array of `summaries()` results.
#[wasm_bindgen(js_name = multiSearch)]
pub fn multi_search(groups: &str, query: &str) -> String {
    envelope(teams::multi_search_json(groups, query))
}

/// The logins for a page across vaults, each with its `vault_id`.
#[wasm_bindgen(js_name = multiForUrl)]
pub fn multi_for_url(groups: &str, url: &str) -> String {
    envelope(teams::multi_for_url_json(groups, url))
}

/// `multiSearch` and `multiForUrl` over lists read once: build it when the lists change and
/// keep it while the user types (`free()` it when replaced). The same answers, without parsing
/// and reading every summary again per call.
#[wasm_bindgen(js_name = SearchIndex)]
pub struct JsSearchIndex {
    inner: std::sync::Arc<pass_core::SearchIndex>,
}

#[wasm_bindgen(js_class = SearchIndex)]
impl JsSearchIndex {
    /// `groups`: a JSON array of `summaries()` results, as `multiSearch` takes it.
    #[wasm_bindgen(constructor)]
    pub fn new(groups: &str) -> Result<JsSearchIndex, JsError> {
        teams::search_index(groups)
            .map(|inner| JsSearchIndex { inner })
            .map_err(js_error)
    }

    /// `multiSearch` over the lists read.
    pub fn search(&self, query: &str) -> String {
        envelope(teams::index_search_json(&self.inner, query))
    }

    /// `search` as places in the lists given (every group's summaries one after the other, from
    /// 0): what a caller that keeps those lists needs per keystroke, with no JSON either way.
    #[wasm_bindgen(js_name = searchPositions)]
    pub fn search_positions(&self, query: &str) -> Vec<u32> {
        self.inner.search_positions(query.into())
    }

    /// `multiForUrl` over the lists read.
    #[wasm_bindgen(js_name = forUrl)]
    pub fn for_url(&self, url: &str) -> String {
        envelope(teams::index_for_url_json(&self.inner, url))
    }
}

/// `{"result": {"vault_id"}}`: the save banner's default vault.
#[wasm_bindgen(js_name = multiDefaultSaveVault)]
pub fn multi_default_save_vault(
    groups: &str,
    url: Option<String>,
    preferred: Option<String>,
) -> String {
    envelope(teams::multi_default_save_vault_json(groups, url, preferred))
}

/// `{"result": {"valid", "fingerprint"}}` of public keys from the account service.
#[wasm_bindgen(js_name = publicKeysCheck)]
pub fn public_keys_check(keys: &str) -> String {
    envelope(teams::public_keys_check(keys))
}

#[wasm_bindgen]
impl BrowserAgent {
    /// `{"result": {"public_keys", "fingerprint"}}`: this account's keyset, made in this
    /// browser's vault if missing. Then store `takeSave()`.
    #[wasm_bindgen(js_name = ensureKeyset)]
    pub fn ensure_keyset(&self, account: &str) -> String {
        envelope(self.host.ensure_keyset(account))
    }

    /// `{"result": VaultSummaries}` of this browser's vault, for `multiSearch` and friends.
    #[wasm_bindgen(js_name = homeSummaries)]
    pub fn home_summaries(&self) -> String {
        envelope(self.host.home_summaries())
    }

    /// The same string while `homeSummaries()` would give the same list; `undefined` while
    /// locked. Keep the list (and a `SearchIndex` of it) while this doesn't change.
    #[wasm_bindgen(js_name = homeStamp)]
    pub fn home_stamp(&self) -> Option<String> {
        self.host.home_stamp()
    }

    /// `{"result": [ContactPin]}`: the contact keys this user verified.
    #[wasm_bindgen(js_name = contactPins)]
    pub fn contact_pins(&self) -> String {
        envelope(self.host.contact_pins())
    }

    /// `{"result": {"status": "pinned" | "not_pinned" | "changed", "pinned_fingerprint"?}}` for
    /// public keys (JSON) in `scope` (`"personal"`).
    #[wasm_bindgen(js_name = contactPinStatus)]
    pub fn contact_pin_status(&self, keys: &str, scope: &str) -> String {
        envelope(self.host.contact_pin_status(keys, scope))
    }

    /// `{"result": ContactPin}` after the user compared `compared` with the person; an error when
    /// it isn't their fingerprint. This browser's vault is saved (store `takeSave()`).
    #[wasm_bindgen(js_name = pinContact)]
    pub fn pin_contact(&self, keys: &str, scope: &str, compared: &str) -> String {
        envelope(self.host.pin_contact(keys, scope, compared))
    }

    /// `{"result": [{"account", "fingerprint", "status", "pinned_fingerprint"?}]}`: the member
    /// changes (JSON) whose keys this user hasn't verified.
    #[wasm_bindgen(js_name = unpinnedChanges)]
    pub fn unpinned_changes(&self, changes: &str) -> String {
        envelope(self.host.unpinned_changes(changes))
    }

    /// Opens a shared vault's file with `account`'s keyset from this browser's vault (unlocked).
    /// Throws when it doesn't open (not a member, a list that doesn't verify, a rollback). Then
    /// store `takeSave()`: the accepted members list is remembered.
    #[wasm_bindgen(js_name = openShared)]
    pub fn open_shared(&self, file: Vec<u8>, account: &str) -> Result<JsSharedVault, JsError> {
        self.host
            .open_shared(file, account)
            .map(|inner| JsSharedVault { inner })
            .map_err(js_error)
    }
}

/// One open shared vault (`BrowserAgent.openShared`). Free it with `free()` when it locks.
#[wasm_bindgen(js_name = SharedVault)]
pub struct JsSharedVault {
    inner: teams::SharedVault,
}

#[wasm_bindgen(js_class = SharedVault)]
impl JsSharedVault {
    /// `{"result": SharedInfo}`.
    pub fn info(&self) -> String {
        envelope(self.inner.info())
    }

    /// `{"result": VaultSummaries}`.
    pub fn summaries(&self) -> String {
        envelope(self.inner.summaries())
    }

    /// The item with its secrets as JSON, `null` if there is none.
    pub fn item(&self, id: &str) -> JsString {
        secret_out(self.inner.item(id))
    }

    /// `{"result": {"id"}}`.
    pub fn upsert(&self, item: String) -> String {
        let item = Zeroizing::new(item);
        envelope(self.inner.upsert(&item))
    }

    pub fn delete(&self, id: &str) -> String {
        envelope(self.inner.delete(id))
    }

    /// Merges a downloaded copy: `{"result": {"added", "updated", "deleted", "unchanged",
    /// "dirty", "notice"}}`.
    pub fn merge(&self, file: Vec<u8>) -> String {
        envelope(self.inner.merge(file))
    }

    /// The encrypted file to store and upload.
    pub fn save(&self) -> Result<Vec<u8>, JsError> {
        self.inner.save().map_err(js_error)
    }

    /// `changes`: a JSON array of `{"op": "add" | "set_role" | "set_group" | "replace_keys" |
    /// "remove", …}`. Keys added or replaced must be pinned (`BrowserAgent.pinContact`).
    /// `{"result": SharedInfo}`.
    #[wasm_bindgen(js_name = changeMembers)]
    pub fn change_members(&self, changes: &str) -> String {
        envelope(self.inner.change_members(changes))
    }

    /// `{"result": {"status", "pinned_fingerprint"?} | null}`: whether this user verified the
    /// manager who signed the members list.
    #[wasm_bindgen(js_name = signerStatus)]
    pub fn signer_status(&self) -> String {
        envelope(self.inner.signer_status())
    }

    pub fn leave(&self) -> String {
        envelope(self.inner.leave())
    }

    /// `{"result": MembersNotice | null}`.
    #[wasm_bindgen(js_name = takeNotice)]
    pub fn take_notice(&self) -> String {
        envelope(self.inner.take_notice())
    }

    /// Copies (`remove` false) or moves an item to (`"to_home"`) or from (`"from_home"`) this
    /// browser's vault: `{"result": {"id"}}`.
    pub fn transfer(&self, id: &str, direction: &str, remove: bool) -> String {
        envelope(self.inner.transfer(id, direction, remove))
    }
}

// Passyble account keys. They stay in WebAssembly memory as objects (free them once used); only
// the account key's bytes (`toBytes`), a Secret Key's text and the account service's blobs cross.

/// An error as `"<code>: <message>"`, so the extension can tell `wrong_password` from the rest.
fn rpc_error(e: pass_agent::RpcError) -> JsError {
    JsError::new(&format!("{}: {}", e.code.as_str(), e.message))
}

fn key_js_error(e: pass_core::PassError) -> JsError {
    rpc_error(crate::account::key_error(e))
}

/// `{"result": {"kind", "account", "ak_id", "account_recovery"}}`: what a vault file opens with
/// (`"password"`, `"account"`: linked to a Passyble account, `"members"`), without opening it.
#[wasm_bindgen(js_name = vaultFileAccess)]
pub fn vault_file_access(file: Vec<u8>) -> String {
    envelope(crate::account::vault_access(&file))
}

/// `{"result": {"text"}}`: a typed or pasted Secret Key written the one way it is kept, or an
/// `invalid_params` error with the reason (a recovery code typed here is named as such).
#[wasm_bindgen(js_name = secretKeyText)]
pub fn secret_key_text(text: String) -> JsString {
    let text = Zeroizing::new(text);
    secret_out(Zeroizing::new(envelope(crate::account::secret_key_text(
        &text,
    ))))
}

/// `{"result": {"email", "account", "secret_key"}}` from the Emergency Kit's setup QR.
#[wasm_bindgen(js_name = parseKitQr)]
pub fn parse_kit_qr(text: String) -> JsString {
    let text = Zeroizing::new(text);
    secret_out(Zeroizing::new(envelope(crate::account::kit_qr(&text))))
}

/// `{"result": {"size", "path"}}`: a QR code of `text` as one SVG path (`<svg viewBox="0 0 size
/// size"><path d="path"/></svg>`), the quiet zone included.
#[wasm_bindgen(js_name = qrSvgPath)]
pub fn qr_svg_path(text: &str) -> String {
    envelope(crate::account::qr_svg(text))
}

/// What the Passyble password and the Secret Key derive for one account (one Argon2id run, through
/// `setKdf`'s runner): the sign-in key and the key of the password wrap. Free it once used.
#[wasm_bindgen(js_name = AccountPassword)]
pub struct JsAccountPassword {
    inner: std::sync::Arc<pass_core::AccountPassword>,
}

#[wasm_bindgen(js_class = AccountPassword)]
impl JsAccountPassword {
    /// `salt` and `kdf` (`{"alg", "m_kib", "t", "p"}`) from the account service's prelogin.
    /// Throws for a Secret Key that doesn't read, or parameters below the apps' minimum.
    #[wasm_bindgen(constructor)]
    pub fn new(
        password: String,
        secret_key: String,
        salt: String,
        kdf: &str,
    ) -> Result<JsAccountPassword, JsError> {
        let password = Zeroizing::new(password);
        let secret_key = Zeroizing::new(secret_key);
        let sk = crate::account::secret_key(&secret_key).map_err(rpc_error)?;
        let kdf = crate::account::parse_kdf(kdf).map_err(rpc_error)?;
        let inner = pass_core::AccountPassword::new(password.to_string(), &sk, salt, kdf)
            .map_err(key_js_error)?;
        Ok(JsAccountPassword { inner })
    }

    /// The sign-in key's public half (base64url), what the account service keeps.
    #[wasm_bindgen(js_name = authPub)]
    pub fn auth_pub(&self) -> String {
        self.inner.auth_pub()
    }

    /// The sign-in signature over the account service's `nonce`: sign exactly the e-mail address
    /// and device name as the service normalizes them.
    #[wasm_bindgen(js_name = signIn)]
    pub fn sign_in(
        &self,
        email: String,
        nonce: String,
        device_name: String,
        platform: String,
    ) -> Result<String, JsError> {
        self.inner
            .sign_in(email, nonce, device_name, platform)
            .map_err(key_js_error)
    }

    pub fn salt(&self) -> String {
        self.inner.salt()
    }

    /// `{"alg", "m_kib", "t", "p"}`.
    pub fn kdf(&self) -> String {
        crate::account::kdf_json(&self.inner.kdf())
    }

    /// Opens the account's password wrap (`{"nonce", "ct"}`): the account key. Throws
    /// `wrong_password: ...` when the password and Secret Key don't open it.
    #[wasm_bindgen(js_name = openAccountKey)]
    pub fn open_account_key(
        &self,
        account: String,
        ak_id: String,
        wrap: &str,
    ) -> Result<JsAccountKey, JsError> {
        let wrap = crate::account::parse_wrap(wrap).map_err(rpc_error)?;
        self.inner
            .open_account_key(account, ak_id, wrap)
            .map(|inner| JsAccountKey { inner })
            .map_err(key_js_error)
    }
}

/// The account key, open in this browser. Free it once used; `toBytes()` is what
/// `chrome.storage.session` may keep while a linked vault is unlocked.
#[wasm_bindgen(js_name = AccountKey)]
pub struct JsAccountKey {
    inner: std::sync::Arc<pass_core::AccountKey>,
}

#[wasm_bindgen(js_class = AccountKey)]
impl JsAccountKey {
    /// The key kept with `toBytes()`, refused unless it is the account's `akId`.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(
        account: String,
        key: Vec<u8>,
        ak_id: String,
    ) -> Result<JsAccountKey, JsError> {
        let key = Zeroizing::new(key);
        pass_core::AccountKey::from_bytes(account, key.to_vec(), ak_id)
            .map(|inner| JsAccountKey { inner })
            .map_err(key_js_error)
    }

    /// Opens a passkey's PRF wrap (`{"nonce", "ct"}`) with the 32-byte PRF output of a verified
    /// assertion by `credentialId`. Throws `wrong_password: ...` when it doesn't open.
    #[wasm_bindgen(js_name = openPrf)]
    pub fn open_prf(
        account: String,
        ak_id: String,
        prf_output: Vec<u8>,
        credential_id: String,
        wrap: &str,
    ) -> Result<JsAccountKey, JsError> {
        let prf_output = Zeroizing::new(prf_output);
        let wrap = crate::account::parse_wrap(wrap).map_err(rpc_error)?;
        pass_core::account_key_open_prf(account, ak_id, prf_output.to_vec(), credential_id, wrap)
            .map(|inner| JsAccountKey { inner })
            .map_err(key_js_error)
    }

    pub fn account(&self) -> String {
        self.inner.account()
    }

    #[wasm_bindgen(js_name = akId)]
    pub fn ak_id(&self) -> String {
        self.inner.ak_id()
    }

    pub fn fingerprint(&self) -> String {
        self.inner.fingerprint()
    }

    /// The raw key (32 bytes), for `chrome.storage.session` only. Never upload it.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Uint8Array {
        let raw = Zeroizing::new(self.inner.to_bytes());
        Uint8Array::from(raw.as_slice())
    }

    #[wasm_bindgen(js_name = akSignPub)]
    pub fn ak_sign_pub(&self) -> String {
        self.inner.ak_sign_pub()
    }

    /// `ak_sign`'s signature of a key-changing request (`X-Pass-Key-Sig`): the service's fresh
    /// nonce, the method, the path and the exact body bytes sent.
    #[wasm_bindgen(js_name = signRequest)]
    pub fn sign_request(
        &self,
        nonce: String,
        method: String,
        path: String,
        body: Vec<u8>,
    ) -> Result<String, JsError> {
        self.inner
            .sign_request(nonce, method, path, body)
            .map_err(key_js_error)
    }

    /// This key wrapped by the password's wrap key: `{"nonce", "ct"}`.
    #[wasm_bindgen(js_name = passwordWrap)]
    pub fn password_wrap(&self, password: &JsAccountPassword) -> Result<String, JsError> {
        self.inner
            .password_wrap(&password.inner)
            .map(|w| crate::account::wrap_json(&w))
            .map_err(key_js_error)
    }

    /// The Secret Key under this key (`sk_wrap`): `{"nonce", "ct"}`.
    #[wasm_bindgen(js_name = secretKeyWrap)]
    pub fn secret_key_wrap(&self, secret_key: String) -> Result<String, JsError> {
        let secret_key = Zeroizing::new(secret_key);
        let sk = crate::account::secret_key(&secret_key).map_err(rpc_error)?;
        self.inner
            .secret_key_wrap(&sk)
            .map(|w| crate::account::wrap_json(&w))
            .map_err(key_js_error)
    }

    /// Opens `sk_wrap` (`{"nonce", "ct"}`): the account's Secret Key, written `P1-...`.
    #[wasm_bindgen(js_name = openSecretKey)]
    pub fn open_secret_key(&self, wrap: &str) -> Result<JsString, JsError> {
        let wrap = crate::account::parse_wrap(wrap).map_err(rpc_error)?;
        let sk = self.inner.open_secret_key(wrap).map_err(key_js_error)?;
        Ok(secret_out(Zeroizing::new(sk.text())))
    }

    /// This key wrapped by a passkey's 32-byte PRF output, for the account service:
    /// `{"nonce", "ct"}`.
    #[wasm_bindgen(js_name = prfWrap)]
    pub fn prf_wrap(&self, prf_output: Vec<u8>, credential_id: String) -> Result<String, JsError> {
        let prf_output = Zeroizing::new(prf_output);
        self.inner
            .prf_wrap(prf_output.to_vec(), credential_id)
            .map(|w| crate::account::wrap_json(&w))
            .map_err(key_js_error)
    }
}

/// This browser as a new device of the account: a one-time X25519 key pair and a random `r_n`.
/// Keep `secret()` in `chrome.storage.session` while the request waits (the service worker may
/// stop), `restore` it, and free it once the request ended.
#[wasm_bindgen(js_name = DeviceApprovalKeys)]
pub struct JsDeviceApprovalKeys {
    inner: std::sync::Arc<pass_core::DeviceApprovalKeys>,
}

#[wasm_bindgen(js_class = DeviceApprovalKeys)]
impl JsDeviceApprovalKeys {
    #[wasm_bindgen(constructor)]
    #[allow(clippy::new_without_default)]
    pub fn new() -> JsDeviceApprovalKeys {
        JsDeviceApprovalKeys {
            inner: pass_core::DeviceApprovalKeys::new(),
        }
    }

    pub fn restore(secret: String) -> Result<JsDeviceApprovalKeys, JsError> {
        let secret = Zeroizing::new(secret);
        pass_core::DeviceApprovalKeys::restore(secret.to_string())
            .map(|inner| JsDeviceApprovalKeys { inner })
            .map_err(key_js_error)
    }

    /// The private half (base64url), for `chrome.storage.session` only.
    pub fn secret(&self) -> JsString {
        secret_out(Zeroizing::new(self.inner.secret()))
    }

    #[wasm_bindgen(js_name = encPub)]
    pub fn enc_pub(&self) -> String {
        self.inner.enc_pub()
    }

    pub fn commitment(&self) -> String {
        self.inner.commitment()
    }

    /// `r_n`: revealed once the approving device's `r_a` arrived (the code variant).
    pub fn reveal(&self) -> String {
        self.inner.reveal()
    }

    /// The QR this browser shows: `passyble:approve/v1?id=<request>&k=<enc_pub>&r=<r_n>`.
    #[wasm_bindgen(js_name = approvalQr)]
    pub fn approval_qr(&self, request_id: String) -> String {
        self.inner.approval_qr(request_id)
    }

    /// The 6 digits to compare with the approving device's.
    pub fn code(
        &self,
        request_id: String,
        account: String,
        r_a: String,
    ) -> Result<String, JsError> {
        self.inner
            .code(request_id, account, r_a)
            .map_err(key_js_error)
    }

    /// Opens the keys the approving device sealed (`{"enc", "ct"}`), checked against the
    /// account's `akId`.
    pub fn open(
        &self,
        request_id: String,
        account: String,
        ak_id: String,
        r_a: String,
        sealed: &str,
    ) -> Result<JsApprovedKeys, JsError> {
        let sealed = crate::account::parse_sealed(sealed).map_err(rpc_error)?;
        self.inner
            .open(request_id, account, ak_id, r_a, sealed)
            .map(|inner| JsApprovedKeys { inner })
            .map_err(key_js_error)
    }

    /// The MAC to send with this browser's key after reading an invitation QR
    /// (`passyble:add/v1?...`).
    #[wasm_bindgen(js_name = invitationMac)]
    pub fn invitation_mac(&self, qr: String) -> Result<String, JsError> {
        let qr = Zeroizing::new(qr);
        let parsed = pass_core::parse_invitation_qr(qr.to_string()).map_err(key_js_error)?;
        self.inner.invitation_mac(parsed).map_err(key_js_error)
    }

    /// Opens the keys sealed through an invitation QR.
    #[wasm_bindgen(js_name = openInvitation)]
    pub fn open_invitation(
        &self,
        invitation_id: String,
        account: String,
        ak_id: String,
        sealed: &str,
    ) -> Result<JsApprovedKeys, JsError> {
        let sealed = crate::account::parse_sealed(sealed).map_err(rpc_error)?;
        self.inner
            .open_invitation(invitation_id, account, ak_id, sealed)
            .map(|inner| JsApprovedKeys { inner })
            .map_err(key_js_error)
    }
}

/// What an approval brought: the account key and the Secret Key. Free it once used.
#[wasm_bindgen(js_name = ApprovedKeys)]
pub struct JsApprovedKeys {
    inner: std::sync::Arc<pass_core::ApprovedKeys>,
}

#[wasm_bindgen(js_class = ApprovedKeys)]
impl JsApprovedKeys {
    /// The arrived account key's fingerprint (`ABCD-…`, as Settings shows it on the approving
    /// device). Show it and keep the keys only when the user says it matches.
    pub fn fingerprint(&self) -> String {
        self.inner.fingerprint()
    }

    #[wasm_bindgen(js_name = accountKey)]
    pub fn account_key(&self) -> JsAccountKey {
        JsAccountKey {
            inner: self.inner.account_key(),
        }
    }

    /// The Secret Key, written `P1-...`.
    #[wasm_bindgen(js_name = secretKey)]
    pub fn secret_key(&self) -> JsString {
        secret_out(Zeroizing::new(self.inner.secret_key().text()))
    }
}

#[wasm_bindgen]
impl BrowserAgent {
    /// `{"result": {"kind", "account", "ak_id", "account_recovery"}}` of this browser's vault file;
    /// `no_vault` without one.
    #[wasm_bindgen(js_name = vaultAccess)]
    pub fn vault_access(&self) -> String {
        envelope(self.host.vault_access())
    }

    /// Opens this browser's vault, linked to a Passyble account, with the account key:
    /// `{"result": {"locked": false, "grant"}}`, or `wrong_password`, `invalid_params` (another
    /// account or another key of it), `no_vault`.
    #[wasm_bindgen(js_name = unlockWithAccountKey)]
    pub fn unlock_with_account_key(&self, account_key: &JsAccountKey) -> String {
        envelope(self.host.unlock_with_account_key(&account_key.inner))
    }

    /// The Passyble password checked while the linked vault is unlocked (through the account key it
    /// opened): `{"result": {"grant"}}` for one request.
    #[wasm_bindgen(js_name = verifyAccountKey)]
    pub fn verify_account_key(&self, account_key: &JsAccountKey) -> String {
        envelope(self.host.verify_account_key(&account_key.inner))
    }
}
