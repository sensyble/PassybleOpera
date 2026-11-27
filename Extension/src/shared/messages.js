// The raw message of the agent or of a JS exception is never shown (it goes to the console). The desktop app's own
// translated texts are shown only for `not_supported` in `unlock` and `invalid_params` / `internal` in `generate`.

import { t } from './i18n.js';

const NO_DETAIL_RE = /^(?:internal|no response|undefined|null|\[object \w+\])$/i;

// The desktop app's English answers to requests this extension doesn't send: not the core's translated sentence.
const AGENT_ENGLISH_RE = /^(?:unknown (?:service|kind|method)\b|no alias requested|not a web page)/i;

export const MSG = Object.freeze({
  agentUnavailable: t('errAgentUnavailable'),
  timeout: t('errTimeout'),
  extensionReloaded: t('errExtensionReloaded'),
  hostMissing: t('errHostMissing'),
  locked: t('errLocked'),
  urlMismatch: t('errUrlMismatch'),
  cancelled: t('errCancelled'),
  notFound: t('errNotFound'),
  notSupported: t('errNotSupported'),
  badServerInput: t('errBadServerInput'),
  addressNeedsUpdate: t('errAddressNeedsUpdate'),
  startFailed: t('errStartFailed'),
  editNeedsUpdate: t('errEditNeedsUpdate'),
  rateLimited: t('errRateLimited'),
  wrongPassword: t('errWrongPassword'),
  tooManyAttempts: t('errTooManyAttempts'),
  unlockNeedsUpdate: t('errUnlockNeedsUpdate'),
  unlockFailed: t('errUnlockFailed'),
  unlockEmpty: t('popupUnlockEmpty'),
  generateNotSetUp: t('errGenerateNotSetUp'),
  aliasRateLimited: t('errAliasRateLimited'),
  aliasNotSupported: t('errAliasNotSupported'),
  formsOff: t('errFormsOff'),
  webPagesOnly: t('errWebPagesOnly'),
  pickInPopup: t('errPickInPopup'),
  nothingToSave: t('errNothingToSave'),
  nothingToUndo: t('errNothingToUndo'),
  generic: t('errGeneric'),
  cantReadPage: t('editorCantReadPage'),
  openQrPageFirst: t('editorOpenQrPageFirst'),
  pageTooLarge: sentence(t('bgPageTooLarge')),
  cannotRunHere: sentence(t('bgCannotRunHere')),
  needsSecurePage: sentence(t('bgFormsNeedHttps')),
  noVault: t('errNoVault'),
  verificationRequired: t('errVerificationRequired'),
  passkeysNeedApp: t('errPasskeysNeedApp'),
  backupFirst: t('errBackupFirst'),
  copyFailed: t('popupCopyFailed'),
  appUpdateRequired: t('errAppUpdateRequired'),
  extensionUpdateRequired: t('errExtensionUpdateRequired'),
  readOnly: t('errReadOnly'),
  fillOnly: t('errFillOnly'),
  wrongAccountPassword: t('errWrongAccountPassword'),
  passwordLimited: t('errPasswordLimited'),
  accountKeysOff: t('errAccountKeysOff'),
  noAccountPassword: t('errNoAccountPassword'),
  accountService: t('errAccountService'),
  accountOffline: t('errAccountOffline'),
  accountSignedOut: t('errAccountSignedOut'),
  badSecretKey: t('errBadSecretKey'),
  secretKeyNeeded: t('errSecretKeyNeeded'),
  emailNeeded: t('errEmailNeeded'),
  otherAccount: t('errOtherAccount'),
  otherAccountKey: t('errOtherAccountKey'),
  approvalMismatch: t('errApprovalMismatch'),
});

// Browsers' wording when the native host is not registered, not allowed for this extension, or cannot start.
const HOST_MISSING_RE = /native messaging host not found|no such native application|access to the specified native messaging host is forbidden|failed to start native messaging host/i;

export function isHostMissing(err) {
  if (!err) return false;
  const code = typeof err === 'object' ? err.code : undefined;
  if (code && code !== 'agent_unavailable') return false;
  const text = messageOf(err);
  return HOST_MISSING_RE.test(text) || (code === 'agent_unavailable' && /not found/i.test(text));
}

function messageOf(err) {
  if (typeof err === 'string') return err;
  return typeof err?.message === 'string' ? err.message : '';
}

function cleanMessage(text) {
  return String(text || '').split(/\r?\n/)[0].replace(/^(?:[A-Z]\w*)?Error:\s*/, '').trim();
}

function sentence(text) {
  if (!text || NO_DETAIL_RE.test(text)) return '';
  const s = text.charAt(0).toUpperCase() + text.slice(1);
  // Sentence-final punctuation of Latin, CJK and Devanagari text.
  return /[.!?…。！？।]$/.test(s) ? s : `${s}.`;
}

function ownText(err, code) {
  // A `reason` means the extension raised it: its message is English for logs, not the desktop app's.
  if (typeof err === 'object' && err?.reason) return '';
  const text = cleanMessage(messageOf(err));
  if (!text || text === code || AGENT_ENGLISH_RE.test(text)) return '';
  return sentence(text);
}

function needsUpdate(context) {
  switch (context) {
    case 'edit': return MSG.editNeedsUpdate;
    case 'unlock': return MSG.unlockNeedsUpdate;
    case 'server-address': return MSG.addressNeedsUpdate;
    default: return MSG.notSupported;
  }
}

function reasonText(reason, context) {
  switch (reason) {
    case 'needs_update': return needsUpdate(context);
    case 'forms_off': return MSG.formsOff;
    case 'web_pages_only': return MSG.webPagesOnly;
    case 'pick_in_popup': return MSG.pickInPopup;
    case 'nothing_to_save': return MSG.nothingToSave;
    case 'nothing_to_undo': return MSG.nothingToUndo;
    case 'passkeys_need_app': return MSG.passkeysNeedApp;
    case 'backup_first': return MSG.backupFirst;
    case 'copy_failed': return MSG.copyFailed;
    case 'extension_update': return MSG.extensionUpdateRequired;
    case 'wrong_account_password': return MSG.wrongAccountPassword;
    case 'password_limited': return MSG.passwordLimited;
    case 'account_keys_off': return MSG.accountKeysOff;
    case 'no_account_password': return MSG.noAccountPassword;
    case 'account_service': return MSG.accountService;
    case 'account_offline': return MSG.accountOffline;
    case 'account_signed_out': return MSG.accountSignedOut;
    case 'bad_secret_key': return MSG.badSecretKey;
    case 'secret_key_needed': return MSG.secretKeyNeeded;
    case 'email_needed': return MSG.emailNeeded;
    case 'other_account': return MSG.otherAccount;
    case 'other_account_key': return MSG.otherAccountKey;
    case 'approval_mismatch': return MSG.approvalMismatch;
    case 'bad_request':
    case 'unexpected': return MSG.generic;
    default: return '';
  }
}

function generateText(err, code) {
  switch (code) {
    case 'not_found': return MSG.generateNotSetUp;
    case 'rate_limited': return MSG.aliasRateLimited;
    case 'not_supported':
      return /unknown method/i.test(messageOf(err)) ? MSG.notSupported : MSG.aliasNotSupported;
    case 'invalid_params':
    case 'internal':
      return ownText(err, code) || MSG.generic;
    default:
      return '';
  }
}

function pick(err, context) {
  if (isHostMissing(err)) return MSG.hostMissing;
  const code = typeof err === 'object' && err ? err.code : undefined;
  const byReason = reasonText(typeof err === 'object' && err ? err.reason : undefined, context);
  if (byReason) return byReason;
  if (context === 'generate') {
    const text = generateText(err, code);
    if (text) return text;
  }
  switch (code) {
    case 'agent_unavailable': return MSG.agentUnavailable;
    case 'timeout': return MSG.timeout;
    case 'extension_reloaded': return MSG.extensionReloaded;
    case 'locked': return MSG.locked;
    case 'url_mismatch': return MSG.urlMismatch;
    case 'cancelled': return MSG.cancelled;
    case 'not_found': return MSG.notFound;
    case 'cant_read_page': return MSG.cantReadPage;
    case 'open_qr_page_first': return MSG.openQrPageFirst;
    case 'page_too_large': return MSG.pageTooLarge;
    case 'cannot_run_here': return MSG.cannotRunHere;
    case 'needs_secure_page': return MSG.needsSecurePage;
    case 'wrong_password': return MSG.wrongPassword;
    case 'no_vault': return MSG.noVault;
    case 'verification_required': return MSG.verificationRequired;
    case 'update_required': return MSG.appUpdateRequired;
    case 'read_only': return MSG.readOnly;
    case 'fill_only': return MSG.fillOnly;
    case 'rate_limited': return context === 'unlock' ? MSG.tooManyAttempts : MSG.rateLimited;
    case 'not_supported':
      if (/unknown method/i.test(messageOf(err))) return needsUpdate(context);
      if (context === 'unlock') return ownText(err, code) || MSG.unlockFailed;
      return needsUpdate(context);
    case 'invalid_params':
      if (context === 'server-address') return MSG.addressNeedsUpdate; // desktop apps that only take links
      if (context === 'server-pair') return MSG.badServerInput;
      if (context === 'unlock') return MSG.unlockEmpty; // an empty or over-long master password
      return MSG.generic;
    case 'internal':
      return context === 'unlock' ? MSG.unlockFailed : MSG.generic;
    default:
      return MSG.generic;
  }
}

/** Raw detail for support: the console only, never the UI. */
function logDetail(err, context) {
  try {
    const code = typeof err === 'object' && err ? err.code : undefined;
    const detail = cleanMessage(messageOf(err));
    if (detail && !NO_DETAIL_RE.test(detail)) globalThis.console?.debug?.('Passyble error', code ?? '', context ?? '', detail);
  } catch { /* no console */ }
}

/** User-facing, translated text for an error; never a raw English message or a stack. */
export function friendlyError(err, { context } = {}) {
  const text = pick(err, context);
  if (text === MSG.generic || text === MSG.unlockFailed) logDetail(err, context);
  return text;
}
