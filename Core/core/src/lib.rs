//! Shared core for every Pass client: the encrypted vault, TOTP, a software WebAuthn
//! authenticator for passkeys, URL / Android-app matching and sync.

// The import tests' JSON fixtures nest deeper than `json!`'s default limit allows.
#![cfg_attr(test, recursion_limit = "256")]

mod account_key;
mod ai;
mod alias;
mod clock;
mod crypto;
mod encoding;
mod error;
mod export;
#[cfg(feature = "gdrive-core")]
mod gdrive;
mod generator;
mod health;
#[cfg(feature = "gdrive-core")]
mod http;
mod i18n;
#[cfg(test)]
mod i18n_tests;
#[cfg(feature = "icons")]
mod icons;
mod import;
mod limits;
mod lookalike;
mod matching;
mod model;
mod multi;
#[cfg(feature = "webdav")]
mod net;
mod otpauth;
mod pairing;
mod passkey;
mod password_check;
#[cfg(test)]
mod perf_tests;
#[cfg(feature = "webdav")]
mod pinning;
mod policy;
mod popular_sites;
mod prf;
mod recovery;
mod search;
mod secmem;
mod send;
#[cfg(feature = "webdav")]
mod server;
mod server_auth;
mod settings;
mod share;
mod similar;
mod sites;
mod summary;
mod totp;
mod usage;
mod vault;
#[cfg(feature = "webdav")]
mod webdav;
mod words;

pub use ai::{is_ai_access_field, item_ai_access, item_with_ai_access, AiAccess, AI_ACCESS_FIELD};
// Where Argon2id runs: the browser extension's WebAssembly hands it to a separate, short-lived
// module. Unset everywhere else.
pub use crypto::{random_token, set_argon2id_runner, Argon2idRunner};
pub use encoding::{b64url_decode, b64url_encode};
pub use error::{PassError, Result};
// Whether the vault keys are locked in RAM (out of swap and crash dumps); the desktop app logs it.
pub use secmem::key_memory_locked;
#[cfg(feature = "gdrive")]
pub use gdrive::{
    gdrive_account, gdrive_delete, gdrive_delete_old_versions, gdrive_download, gdrive_list_vaults,
    gdrive_remove_vault, gdrive_sync,
};
// The same Google Drive sync, driven request by request by the browser extension.
#[cfg(feature = "gdrive-core")]
pub use gdrive::{
    gdrive_account_exchange, gdrive_download_exchange, gdrive_list_exchange, gdrive_sync_exchange,
    GDriveAccount, GDriveConfig, GDriveOldVersions, GDriveVault,
};
pub use generator::{
    generate_email, generate_passphrase, generate_password, generate_username, EmailKind,
    EmailOptions, PasswordOptions, UsernameKind, UsernameOptions, PASSPHRASE_DEFAULT_WORDS,
    PASSPHRASE_MAX_WORDS, PASSPHRASE_MIN_WORDS, USERNAME_SEPARATORS,
};
#[cfg(feature = "gdrive-core")]
pub use http::{Exchange, FetchFailure, HttpRequest, HttpResponse, Step};
// E-mail alias services; their configs are kept in the vault.
#[cfg(feature = "webdav")]
pub use alias::{alias_check, alias_generate};
pub use alias::{
    alias_service_name, AliasConfig, AliasService, EmailGeneratorSettings, ADDY_DEFAULT_DOMAIN,
};
pub use i18n::{core_message_arg, core_message_is, set_language};
#[cfg(feature = "icons")]
pub use icons::cache::{
    site_icon_cache_clear, site_icon_cache_file_name, site_icon_cache_read,
    site_icon_cache_refresh, CachedSiteIcon, FAILED_MAX_AGE_MS, ICON_MAX_AGE_MS, NONE_MAX_AGE_MS,
};
#[cfg(feature = "icons")]
pub use icons::{fetch_site_icon, site_icon_domain, SiteIcon, ICON_SIDE};
pub use import::{
    find_duplicates, import_parse, merge_candidates, merge_items, merge_pair, merge_preview,
    merge_suggestions, parse_import, ClashField, ClashKind, DuplicateGroup, ImportAction,
    ImportBatch, ImportDecision, ImportEntry, ImportFormat, ImportGroup, ImportGroupDecision,
    ImportPreview, ImportReport, ImportResult, ImportSkip, MergeCandidate, MergeChoice, MergeField,
    MergeFieldPlan, MergeFieldState, MergeNotes, MergeOutcome, MergePicks, MergePlan, MergePreview,
    MergeSide, MergeSource, MergeSuggestion, MergeUndo, MAX_IMPORT_BYTES,
};
#[cfg(feature = "import-qr")]
pub use import::{qr_decode_image, qr_decode_rgba};
// Lookalike sites: a warning before a login is filled, copied or saved by hand on a page that
// imitates one of the user's sites.
pub use lookalike::{
    login_sites, lookalike_of, KnownSites, Lookalike, LookalikeCheck, LookalikeReason,
};
pub use matching::{
    canonical_save_origin, registrable_domain, url_suggests_host_only, MatchQuality,
};
// Similar sites: another site's logins offered on a page without its own.
pub use similar::{similar_logins, site_name, SimilarLogin, SimilarReason};
pub use model::{AndroidApp, Item, ItemKind, Passkey, PasswordHistoryEntry, MAX_PASSWORD_HISTORY};
pub use limits::{
    check_notes_length, MAX_FIELD_NAME_CHARS, MAX_FIELD_VALUE_CHARS, MAX_ITEM_FIELDS, MAX_ITEM_URLS,
    MAX_NOTES_CHARS,
};
pub use otpauth::{
    otpauth_matches, otpauth_parse_link, OtpauthLink, OtpauthMatch, MAX_OTPAUTH_LINK,
};
#[cfg(feature = "webdav")]
pub use pairing::pairing_webdav_config;
pub use pairing::{parse_pairing_link, parse_server_link, PairingLink, ServerLink};
pub use passkey::{
    android_origin, assetlinks_allows, client_data_json, passkey_assert, passkey_create,
    rp_id_valid_for_origin, sha256, PasskeyAssertion, PasskeyCreation, AAGUID,
};
// The WebAuthn PRF extension.
#[cfg(feature = "webdav")]
pub use pinning::{fetch_server_pin, spki_pin};
pub use prf::{
    passkey_hmac_secret, passkey_prf_available, passkey_prf_eval, prf_authentication_check,
    prf_authentication_output, prf_registration_check, prf_registration_output, prf_salt,
    webauthn_prf_create_error, webauthn_prf_create_output, webauthn_prf_get_error,
    webauthn_prf_get_output, PrfRequestError, PrfValues, PRF_LEN, PRF_SECRET_OID,
};
pub use search::{items_search, summaries_search_with_notes};
#[cfg(feature = "webdav")]
pub use server::{
    check_plain_http, normalize_server_url, plain_http_refused, server_account,
    server_change_password, server_info, server_list_devices, server_login, server_prelogin,
    server_purge_versions, server_request_reset, server_revoke_device,
    server_session_webdav_config, server_set_password_with_code, server_signup, server_verify_password, ServerAccount,
    ServerDevice, ServerInfo, ServerPrelogin, ServerSession, ServerSignup,
};
#[cfg(feature = "webdav")]
pub use server::{
    server_change_password_2fa, server_login_2fa, server_security_events,
    server_set_password_with_code_2fa, server_two_factor_confirm, server_two_factor_disable,
    server_two_factor_setup, server_two_factor_status, ServerSecurityEvent, ServerTwoFactorSetup,
    ServerTwoFactorStatus, TWO_FACTOR_INVALID, TWO_FACTOR_REQUIRED,
};
#[cfg(feature = "webdav")]
pub use server::{server_set_language, set_server_language, SHARED_VAULT_ERRORS};
pub use server_auth::{server_auth_key, ServerKdf};
pub use summary::{
    summaries_for_android_app, summaries_for_url, summaries_for_url_in, summaries_most_used,
    summaries_search, summaries_suggested, summaries_with_passkeys, ItemSummary, PasskeySummary,
};
pub use totp::{totp_generate, totp_parse, TotpAlgorithm, TotpCode, TotpConfig};
pub use usage::{
    usage_frecency, ItemUsage, MAX_USAGE_DEVICES, USAGE_HALF_LIFE_MS, USAGE_SYNC_INTERVAL_MS,
    USE_DEDUPE_MS,
};
#[cfg(feature = "sync-core")]
pub use vault::SyncResult;
pub use vault::{KdfParams, MergeStats, PasskeyMatch, SaveSnapshot, Vault};
// One Passyble password for the account and its vaults.
pub use account_key::{
    account_key_from_admin_recovery, account_key_open_prf, account_key_open_recovery,
    account_recovery_sign, account_recovery_verify, account_recovery_verify_pub,
    account_request_verify, account_sign_in_verify, device_approval_code, device_approval_nonce,
    emergency_kit, parse_approval_qr, parse_invitation_qr, parse_kit_qr, secret_key_valid_format,
    AccountKdf, AccountKey, AccountPassword, AccountRecovery, AccountWrap, ApprovalQr,
    ApprovedKeys, DeviceApprovalKeys, DeviceInvitation, EmergencyKit, InvitationQr, KitQr,
    SealedAccountKey, SecretKey, ACCOUNT_PASSWORD_MAX_CHARS,
};
pub use vault::{
    account_key_from_vault_file, vault_file_access, AccountRecoveryWrap, VaultAccess, VaultAccountLink,
};
// Shared vaults: Family and Teams vaults, department vaults and direct shares, with emergency
// access and admin-assisted recovery.
pub use share::emergency::EMERGENCY_MAX_WAIT_HOURS;
pub use share::{
    admin_recovery_approve, admin_recovery_request, org_recovery_create, org_recovery_rewrap,
    org_recovery_verify, public_keys_fingerprint, public_keys_verify, recovery_request_code,
    AdminRecoveryUse, AdminWrap,
    ContactPin, PinProblem, PinSource, PinStatus, ORG_SCOPE_PREFIX, PERSONAL_SCOPE,
    EmergencyAccess, EmergencyGrant, EmergencyGrantCreated, GroupMember, MemberChange,
    MemberInfo, MemberRole, MembersNotice, OrgKind, OrgRecoveryKey, PublicKeys,
    RecoveryApproval, RecoveryEnrollment, RecoveryRequest, RecoveryRequestPublic, ShareTrust,
    SharedInfo, SharedKind, UserKeyset,
};
pub use vault::{AdminRecoveryStatus, MAX_PINNED_VAULTS};
// Several open vaults at once, secure send and organisation policies.
pub use multi::{
    multi_default_save_vault, multi_for_android_app, multi_for_url, multi_search,
    multi_vault_summaries, multi_with_passkeys, KeptMatcher, SearchIndex, VaultItemSummary,
    VaultSummaries,
};
pub use policy::{
    policy_allows_export, policy_allows_share, policy_auto_lock_secs, policy_blocked_message,
    policy_check_master_password, policy_parse, policy_strictest, policy_violations,
    LocalSecurity, OrgPolicy, PolicyBlock, PolicyRule, PolicyViolation,
};
pub use send::{
    send_info, send_link, send_open, send_parse_link, send_password_auth, send_seal,
    SealedSend, SendContent, SendInfo, SendKind, SendLink, SendOptions, SEND_MAX_BYTES,
    SEND_MAX_DAYS,
};
#[cfg(feature = "webdav")]
pub use webdav::{webdav_download, webdav_exists, webdav_replace, webdav_sync, WebDavConfig};

pub use export::{
    export_csv, export_decrypt, export_encrypted_json, export_is_encrypted, export_json,
};
#[cfg(feature = "webdav")]
pub use health::{hibp_check, hibp_range};
pub use health::{
    health_report, health_use_https, hibp_match, hibp_prefix, password_health, password_strength,
    DuplicateSet, HealthItem, HealthReport, HibpQuery, InsecureItem, PasswordStrength, ReusedGroup,
    SiteItem, OLD_PASSWORD_MS,
};
pub use import::{
    import_encryption, import_parse_with_key_file, import_parse_with_password,
    parse_import_with_password, ImportEncryption,
};
pub use model::{
    card_brand, card_brand_name, card_number_valid, url_rule_of, CardData, CustomField, FieldKind,
    IdentityData, UrlMatch, UrlRule, TRASH_RETENTION_MS,
};
pub use password_check::{
    check_master_password, master_password_check, password_issues, password_issues_in,
    require_master_password, strength_label, IssueSeverity, MasterPasswordCheck,
    MasterPasswordContext, MasterPasswordIssue, PasswordCheck, PasswordContext, PasswordIssue,
    PasswordIssueKind, MASTER_PASSWORD_MIN_LENGTH, MASTER_PASSWORD_MIN_SCORE, PASSWORD_MIN_LENGTH,
};
pub use sites::{site_security, SiteSecurity};
// Popular sites: a new login's name and website suggested from each other.
pub use popular_sites::{
    site_for_android_app, site_for_domain, site_suggestions, SiteSuggestion, MAX_SITE_SUGGESTIONS,
};
pub use summary::{app_pin, APP_PIN_PREFIXES};
pub use summary::{summaries_tags, summaries_with_tag, CardSummary, IdentitySummary, TagCount};
pub use recovery::recovery_code_valid_format;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

/// Whether two secrets are equal, in constant time (their lengths are not secret). Rust only.
pub fn secrets_equal(a: &str, b: &str) -> bool {
    crypto::ct_eq(a.as_bytes(), b.as_bytes())
}

/// Current time in Unix milliseconds (`Date.now()` in the browser's WebAssembly).
pub(crate) use clock::now_ms;
