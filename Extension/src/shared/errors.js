// Error codes of the agent protocol. The extension uses the same vocabulary internally.
export const ErrorCode = Object.freeze({
  LOCKED: 'locked',
  NOT_FOUND: 'not_found',
  URL_MISMATCH: 'url_mismatch',
  CANCELLED: 'cancelled',
  INVALID_PARAMS: 'invalid_params',
  NOT_SUPPORTED: 'not_supported',
  AGENT_UNAVAILABLE: 'agent_unavailable',
  INTERNAL: 'internal',
  RATE_LIMITED: 'rate_limited',
  WRONG_PASSWORD: 'wrong_password',
  // Not in the protocol's list of error codes; accepted from the agent and mapped to InvalidStateError.
  INVALID_STATE: 'invalid_state',
  // Extension-internal: no answer within the method's timeout (a Passyble window may still be waiting). Not "not running".
  TIMEOUT: 'timeout',
  EXTENSION_RELOADED: 'extension_reloaded',
  // Extension-internal; the English `message` is for logs and tests only, never shown.
  CANT_READ_PAGE: 'cant_read_page',
  OPEN_QR_PAGE_FIRST: 'open_qr_page_first',
  PAGE_TOO_LARGE: 'page_too_large',
  CANNOT_RUN_HERE: 'cannot_run_here',
  NEEDS_SECURE_PAGE: 'needs_secure_page',
  NO_VAULT: 'no_vault',
  VERIFICATION_REQUIRED: 'verification_required',
  // Below the minimum version an app is read-only; this extension also raises it itself (reason `extension_update`).
  UPDATE_REQUIRED: 'update_required',
  READ_ONLY: 'read_only',
  FILL_ONLY: 'fill_only',
});

// A finer cause than the protocol code, set by the background; friendlyError picks the text by `reason` first.
export const Reason = Object.freeze({
  NEEDS_UPDATE: 'needs_update',
  FORMS_OFF: 'forms_off',
  WEB_PAGES_ONLY: 'web_pages_only',
  PICK_IN_POPUP: 'pick_in_popup',
  NOTHING_TO_SAVE: 'nothing_to_save',
  NOTHING_TO_UNDO: 'nothing_to_undo',
  BAD_REQUEST: 'bad_request',
  UNEXPECTED: 'unexpected',
  PASSKEYS_NEED_APP: 'passkeys_need_app',
  BACKUP_FIRST: 'backup_first',
  COPY_FAILED: 'copy_failed',
  EXTENSION_UPDATE: 'extension_update',
  WRONG_ACCOUNT_PASSWORD: 'wrong_account_password',
  PASSWORD_LIMITED: 'password_limited',
  ACCOUNT_KEYS_OFF: 'account_keys_off',
  NO_ACCOUNT_PASSWORD: 'no_account_password',
  ACCOUNT_SERVICE: 'account_service',
  ACCOUNT_OFFLINE: 'account_offline',
  ACCOUNT_SIGNED_OUT: 'account_signed_out',
  BAD_SECRET_KEY: 'bad_secret_key',
  SECRET_KEY_NEEDED: 'secret_key_needed',
  EMAIL_NEEDED: 'email_needed',
  OTHER_ACCOUNT: 'other_account',
  OTHER_ACCOUNT_KEY: 'other_account_key',
  APPROVAL_MISMATCH: 'approval_mismatch',
});

export class PassError extends Error {
  /** `message` is English detail for logs and tests, never shown; `reason` picks the user-facing text. */
  constructor(code, message, reason) {
    super(message || code);
    this.name = 'PassError';
    this.code = code;
    if (reason) this.reason = reason;
  }

  toJSON() {
    return this.reason ? { code: this.code, message: this.message, reason: this.reason } : { code: this.code, message: this.message };
  }

  /** Normalises anything thrown into a PassError. */
  static from(err) {
    if (err instanceof PassError) return err;
    if (err && typeof err === 'object' && typeof err.code === 'string') {
      return new PassError(err.code, err.message, typeof err.reason === 'string' ? err.reason : undefined);
    }
    return new PassError(ErrorCode.INTERNAL, err?.message || String(err), Reason.UNEXPECTED);
  }
}
