// Passyble content script (isolated world, every frame), loaded as a module by loader.js.
// Finds login, OTP, card and address fields, runs the inline menu, fills, and offers to save.
import { ext } from '../shared/api.js';
import {
  detectFields, detectFormFields, isVisible, FieldKind, isWebauthnField, couldBeCodeField, adoptableCodeField,
  contextLooksLike2fa, nearText, collectInputs, isFillableInput, usernameScore, SHORT_PAGE_TEXT,
} from './detect.js';
import { fillInput, fillLoginGroup, fillOtpEntry, fillNewPasswords, wasFilledByPass } from './fill.js';
import { fillCardGroup, fillIdentityGroup } from './autofill.js';
import { captureCardFrom, PAY_TEXT_RE } from './card-capture.js';
import { brandBadge, cardSummary, identitySummary, isSecureFormUrl } from '../shared/cards.js';
import { InlineMenu } from './menu.js';
import { showOtpToast, showNotice, showActionToast } from './toast.js';
import { showPasskeyPrompt, showPasskeyNone, passkeyAccount } from './passkey-prompt.js';
import { createPasskeyFlow } from './passkey-flow.js';
import { isOwnNode } from './ui-common.js';
import {
  decideOtpAction, decideShortcutAction, looksLike2faPage, looksLikeLoginPath, looksSignedIn,
  TOAST_DELAY_MS, SKIP_DETECT_MS, PENDING_OTP_WINDOW_MS,
} from '../shared/otp-logic.js';
import { DEFAULT_SETTINGS, getSettings, onSettingsChanged } from '../shared/settings.js';
import { isPlainPassword, wordsOf } from '../shared/generator.js';
import { prefersNoSymbols, generatorOptions } from '../shared/generate-prefs.js';
import { passwordRulesOf, passwordLimitsOf } from './password-rules.js';
import { planFor, agentCanMake, makeLocally, strengthOf } from './generate-plan.js';
import { friendlyError, isHostMissing } from '../shared/messages.js';
import { matchLogins } from './suggest.js';
import { t } from '../shared/i18n.js';
import { canReveal, vaultLabel, vaultTable } from '../shared/vaults.js';
import { extensionBlocked, onExtensionBlockedChange } from '../shared/app-versions.js';

const isTop = window === window.top;
const BADGE_2FA = () => ({ text: t('commonBadge2fa'), otp: true });
const BADGE_PASSKEY = () => t('commonPasskey');
const SUBMIT_TEXT_RE = /(log ?in|sign ?in|log ?on|continue|next|submit|sign ?up|register|create|save|change|update|confirm|verify|weiter|anmelden|einloggen|speichern|connexion|se connecter|suivant|continuer|entrar|siguiente|iniciar|accedi|avanti|inloggen|volgende|zaloguj|dalej|войти|далее|ログイン|次へ|登录|下一步|로그인|다음)/i;

let settings = { ...DEFAULT_SETTINGS };
let scan = { groups: [], fields: new Map() };
const NO_FORMS = Object.freeze({ cards: [], identities: [], fields: new Map() });
let forms = NO_FORMS;              // card and identity fields (detectFormFields), when offered
let formSupport = null;            // { cards, identities }, asked once per page
const formsAutoOffered = new WeakSet(); // card / address fields the menu already auto-opened for
let menu = null;
let toast = null;
let navStartedAt = Date.now();
let lastHref = location.href;
let otpCtx = null;          // from background: { pending, offer, autoFillOtp, otpFieldElsewhere }
let otpHandled = false;     // pending OTP already offered / filled on this page
let otpFilled = false;      // the code went into a field on this page
let otpFieldReported = false;
let otpTimer = 0;
let observer = null;
let lastFocusReport = 0;
let otpCtxRequested = false;
let otpAutoTries = 0;       // failed automatic fills of the pending code on this page
let signInField = null;     // password field just filled; while it is on screen the 2FA step hasn't come yet
let otpSkipped = false;     // signed in without a 2FA step (only a late code field gets the code)
let otpAskReported = false; // otp.outcome "asked" already sent for this page
let lastSubmitAt = 0;       // last form submission: the skip check restarts from it
const adHocOtp = new WeakMap(); // undetected fields used as the code field (see fieldInfo)
let started = false;
let quiet = false;                 // forced update: this page's script has stopped
let awaitingUnblock = false;       // started while blocked: starts once the block is lifted
let appUpdateShown = false;        // the app update notice already auto-opened on this page
const autoOffered = new WeakSet(); // new-password fields the generator already opened for
const autoSuggested = new WeakSet(); // sign-in fields the suggestions already opened for
let menuAutoField = null;          // field the menu auto-opened for (typing closes or filters it)
let menuModel = null;              // { field, info, data, preview, view: 'logins' | 'unlock', opts, showAll }
let pendingUnlock = null;          // { field, run, at, needsFocus }: runs once Passyble is unlocked
const PENDING_UNLOCK_TTL_MS = 2 * 60_000;
let helloRun = 0;                  // the Windows Hello unlock the menu waits for (a newer one wins)
// Windows Hello only starts on its own this soon after the user gesture that asked for it.
const HELLO_GESTURE_MS = 5000;
let unlockFrame = null;            // { el, field, ready, timer, watch }: the master password frame
let frameBlocked = false;          // frame didn't load or the page covered the menu: use the popup
const FRAME_PATH = 'src/unlock/frame.html';
const FRAME_READY_MS = 3000;
// The page's first sign-in field focus per step counts as the user's (pageFocusInitial).
const PAGE_FOCUS_WINDOW_MS = 10_000;
let stepStartedAt = Date.now();
let stepFocusSeen = false;         // a sign-in field had focus in this step already (only the first is the page's)
let lastInteractionAt = 0;         // the last trusted pointer press or key in this frame
let hiddenSeenAt = 0;              // when this document was last seen hidden (a background tab)
let shownAt = 0;                   // when it became visible after that (0: visible since it loaded)
let suggestWait = null;            // { field, info, at, why, left, timer }: suggestions waiting to open (suggestLogins)
let undetectedFocus = null;        // { field, at, initial }: focused before detect.js knew the field (recheckFocusedField)
let menuPassive = false;           // the open menu came from the page (script focus, passkey request): nothing preselected
let lastGesture = { at: 0, kind: '', target: null };
// Kept until submit (or 10 min): the save banner offers it even if the page clears the field.
let generated = null;              // { password, fields: HTMLInputElement[], at }
// Lazy-loaded: this script runs in every frame and most never show the banner or generate.
let bannerModule = null;
let revealModule = null;
const loadBanner = () => (bannerModule ??= import('./banner.js').catch((err) => { bannerModule = null; throw err; }));
const loadReveal = () => (revealModule ??= import('./reveal.js').catch((err) => { revealModule = null; throw err; }));
// Also lazy: the options card and the passphrase word list (62 KB).
let genOptionsModule = null;
let passphraseWords = null;
const loadGenOptions = () => (genOptionsModule ??= import('./gen-options.js').catch((err) => { genOptionsModule = null; throw err; }));
const loadPassphraseWords = () => (passphraseWords ??= import('../shared/passphrase-words.js')
  .then((m) => wordsOf(m.PASSPHRASE_WORDS)).catch((err) => { passphraseWords = null; throw err; }));

/** A UI still loading: `close()` before it loaded means it never shows. */
function pendingUi() {
  return { closed: false, close() { this.closed = true; } };
}

let generatedReveal = null;        // the generated password shown once beside its field (reveal.js), while it has the focus
const GENERATED_TTL_MS = 10 * 60_000;
let draft = null;                  // { id } of the login the generated password was auto-saved as (background has the rest)
let genOptions = null;             // the generator's options card (gen-options.js) while it is open
let draftToast = null;
let lastContext = { at: 0, target: null }; // last right-clicked element
const CONTEXT_TTL_MS = 60_000;
const USER_FOCUS_WINDOW_MS = 1000;
const AGENT_GENERATE_TIMEOUT_MS = 1500;
const AGENT_COPY_TIMEOUT_MS = 1500; // much later, the browser may no longer treat the copy as part of the click

class BgError extends Error {
  constructor(code, message, reason) {
    super(message || code);
    this.code = code;
    if (reason) this.reason = reason; // picks the text in friendlyError
  }
}

function contextAlive() {
  try { return !!ext.runtime?.id; } catch { return false; }
}

// Resent while a still-starting service worker never got it (Brave's can take ~2 s); nothing else is resent.
const BG_RETRY_MS = [250, 500, 1000];
const NOT_DELIVERED_RE = /receiving end does not exist|could not establish connection/i;

/** Extension updated or reloaded: this script is cut off until the page reloads. */
function reloaded() {
  teardown();
  return new BgError('extension_reloaded', 'Extension was reloaded');
}

async function bg(type, payload = {}) {
  let res;
  for (let attempt = 0; ; attempt++) {
    if (!contextAlive()) throw reloaded();
    try {
      res = await ext.runtime.sendMessage({ type, ...payload });
      break;
    } catch (err) {
      if (!contextAlive()) throw reloaded();
      const message = String(err?.message || err);
      if (attempt >= BG_RETRY_MS.length || !NOT_DELIVERED_RE.test(message)) throw new BgError('agent_unavailable', message);
      await new Promise((resolve) => setTimeout(resolve, BG_RETRY_MS[attempt]));
    }
  }
  if (!res) throw new BgError('agent_unavailable', 'No response');
  if (res.ok) return res.result;
  throw new BgError(res.error?.code || 'internal', res.error?.message, res.error?.reason);
}

/** Visible page text, read lazily at most once per scan (innerText needs layout; jsdom: textContent). */
let textGen = 0;
let pageTextCache = { gen: -1, text: '' };
function pageText() {
  if (pageTextCache.gen === textGen) return pageTextCache.text;
  const body = document.body;
  const text = body ? (typeof body.innerText === 'string' ? body.innerText : body.textContent) || '' : '';
  pageTextCache = { gen: textGen, text: text.slice(0, 20_000) };
  return pageTextCache.text;
}

function rescanNow() {
  textGen++;
  scan = detectFields(document, { isVisible, pageText });
  forms = formsWanted() ? detectFormFields(document, { isVisible }) : NO_FORMS;
  if (menu?.iconField && !fieldInfo(menu.iconField) && !formInfo(menu.iconField)) menu.hideIcon();
  // Sub-frames (often ads) ask the agent only once they contain a login / OTP field.
  if (!otpCtxRequested && started && (isTop || scan.groups.length)) loadOtpContext(isTop);
  evaluateOtp();
  return scan;
}

let scanTimer = 0;
let lastScan = 0;
function scheduleScan() {
  if (scanTimer) return;
  const wait = Math.max(0, 250 - (Date.now() - lastScan));
  scanTimer = setTimeout(() => {
    scanTimer = 0;
    lastScan = Date.now();
    checkSpaNavigation();
    rescanNow();
    recheckFocusedField();
  }, wait);
}

function startObserver() {
  observer = new MutationObserver((records) => {
    for (const r of records) {
      if (!isOwnNode(r.target)) { scheduleScan(); return; }
    }
  });
  observer.observe(document.documentElement, {
    childList: true, subtree: true, attributes: true,
    attributeFilter: ['type', 'hidden', 'style', 'class', 'autocomplete', 'disabled', 'readonly'],
  });
}

function checkSpaNavigation() {
  if (location.href === lastHref) return;
  lastHref = location.href;
  navStartedAt = Date.now();
  newStep();
  otpHandled = false;
  otpFilled = false;
  otpFieldReported = false;
  otpAutoTries = 0;
  signInField = null;
  otpSkipped = false;
  otpAskReported = false;
  loadOtpContext(isTop);
  if (isTop) checkSaveBanner(true);
  if (isTop) checkCardBanner();
}

function deepActiveElement() {
  let a = document.activeElement;
  while (a?.shadowRoot?.activeElement) a = a.shadowRoot.activeElement;
  return a;
}

function eventField(e) {
  const target = e.composedPath ? e.composedPath()[0] : e.target;
  return target && target.tagName === 'INPUT' ? target : null;
}

function fieldInfo(field) {
  return scan.fields.get(field) || adHocOtp.get(field) || null;
}

function groupOf(field) {
  return fieldInfo(field)?.group || null;
}

function formsWanted() {
  return settings.formFill !== false && settings.inlineMenu && isSecureFormUrl(location.href);
}

/** The card or identity info of `field`; login fields keep the login menu. */
function formInfo(field) {
  if (!field || scan.fields.has(field) || adHocOtp.has(field)) return null;
  return forms.fields.get(field) || null;
}

const FORM_METHODS = {
  card: { list: 'cards.list', fill: 'cards.fill', feature: 'cards', heading: t('menuHeadingCards'), lockedHeading: t('menuHeadingCardsLocked'), empty: t('menuNoCards') },
  identity: { list: 'identities.list', fill: 'identities.fill', feature: 'identities', heading: t('menuHeadingAddresses'), lockedHeading: t('menuHeadingAddressesLocked'), empty: t('menuNoAddresses') },
};

async function formFeatures() {
  if (formSupport) return formSupport;
  try {
    const res = await bg('forms.features');
    formSupport = { cards: res?.cards === true, identities: res?.identities === true };
  } catch {
    return { cards: false, identities: false }; // not running: asked again next time
  }
  return formSupport;
}

async function onFormFieldFocus(field, form) {
  reportFocus(form.type);
  if (!formsWanted()) return;
  const fromUser = focusFromUser(field);
  const support = await formFeatures();
  if (!support[FORM_METHODS[form.type].feature]) return;
  if (deepActiveElement() !== field || !formInfo(field)) return;
  const m = ensureMenu();
  m.showIcon(field);
  if (m.isOpen && m.field !== field) m.close();
  if (!settings.autoSuggest || !fromUser || field.value || formsAutoOffered.has(field) || m.isOpen) return;
  formsAutoOffered.add(field);
  let data;
  try { data = await bg(FORM_METHODS[form.type].list, { automatic: true }); } catch { return; }
  if (!data?.items?.length) return;
  if (deepActiveElement() !== field || field.value || menu?.isOpen) return;
  openFormMenu(field, form, { auto: true, passive: true, data });
}

// An "isn't running" menu re-asks quietly every 2 s for up to 30 s and fills in once Passyble answers.
const RECHECK_MS = 2000;
const RECHECKS = 15;
let recheckTimer = 0;

/** Re-sends side-effect free `method` until Passyble answers, while that menu stays as it is. */
function recheckWhileUnavailable(field, method, reopen) {
  clearTimeout(recheckTimer);
  const model = menuModel;
  const shown = () => !!menu?.isOpen && menu.field === field && menuModel === model;
  let left = RECHECKS;
  const check = async () => {
    recheckTimer = 0;
    if (!shown()) return;
    let data;
    try {
      data = await bg(method);
    } catch (err) {
      if (err.code === 'extension_reloaded' || !shown()) return;
      if (err.code === 'agent_unavailable') {
        if (--left > 0) recheckTimer = setTimeout(check, RECHECK_MS);
        return;
      }
      reopen(null, err);
      return;
    }
    if (shown()) reopen(data, null);
  };
  recheckTimer = setTimeout(check, RECHECK_MS);
}

async function openFormMenu(field, form, { auto = false, passive = false, data: found = null, refresh = false, failed = null, user = '' } = {}) {
  const gesture = user ? Date.now() : 0;
  const methods = FORM_METHODS[form.type];
  const m = ensureMenu();
  menuAutoField = auto ? field : null;
  menuPassive = passive;
  menuModel = { field, info: form, data: null, preview: null, view: form.type };
  if (!refresh) m.open(field, { status: 'loading', heading: methods.heading });
  const show = (model) => m.update({ heading: methods.heading, ...model, preselect: !passive });
  let data = found;
  try {
    if (failed) throw failed;
    if (!data) data = await bg(methods.list);
  } catch (err) {
    if (m.field !== field) return;
    if (err.code === 'not_supported') {
      // An older desktop app, or the setting turned off meanwhile.
      formSupport = { ...(formSupport || { cards: false, identities: false }), [methods.feature]: false };
      m.close();
      if (m.iconField === field) m.hideIcon();
      return;
    }
    if (err.code === 'locked') {
      if (await offerUnlock(reopenAfterUnlock(field), { quiet: true, ...unlockStart(user, gesture) })) return;
      if (m.field !== field) return;
      show({ status: 'ok', message: t('menuLocked'), entries: [{ kind: 'unlock', title: t('menuUnlock'), icon: 'lock' }] });
    } else if (err.code === 'agent_unavailable') {
      show({ status: 'unavailable', message: errorMessage(err) });
      if (!isHostMissing(err)) {
        recheckWhileUnavailable(field, methods.list, (again, error) =>
          openFormMenu(field, form, { auto, passive, data: again, refresh: true, failed: error }));
      }
    } else {
      show({ status: 'message', message: errorMessage(err), entries: [] });
    }
    return;
  }
  if (m.field !== field) return;
  menuModel = { field, info: form, data, preview: null, view: form.type };
  show({ status: 'ok', ...buildFormMenuModel(form.type, data) });
}

function buildFormMenuModel(type, data) {
  const items = Array.isArray(data?.items) ? data.items : [];
  const methods = FORM_METHODS[type];
  // `guarded`: Enter needs the same checks as a click (visible for a moment, not covered).
  const entries = type === 'card'
    ? items.map((c) => ({ kind: 'card', id: String(c.id), title: c.title || cardSummary(c), subtitle: cardSummary(c),
      avatar: brandBadge(c.brand), avatarClass: 'brand', guarded: true }))
    : items.map((i) => ({ kind: 'identity', id: String(i.id), title: i.title || i.full_name || t('commonIdentity'),
      subtitle: identitySummary(i) || t('commonNameAndAddress'), icon: 'idCard', guarded: true }));
  return { heading: data?.locked ? methods.lockedHeading : methods.heading, entries, message: methods.empty };
}

// This frame only: the background asks the agent with this frame's own URL.
async function fillForm(entry, field) {
  const type = entry.kind === 'card' ? 'card' : 'identity';
  const values = await bg(FORM_METHODS[type].fill, { id: entry.id });
  rescanNow();
  const group = forms.fields.get(field)?.group;
  if (!group || !field.isConnected) { showNotice(t('menuFormChanged')); return false; }
  const filled = type === 'card' ? fillCardGroup(group, values, { isVisible }) : fillIdentityGroup(group, values, { isVisible });
  return filled > 0;
}

function firstOtpEntry() {
  return scan.groups.find((g) => g.otp)?.otp || null;
}

function otpOfferActive() {
  return !!otpCtx?.offer && !otpFilled && !otpSkipped;
}

function adoptAsOtpField(field) {
  const group = { form: field.form || null, container: null, username: null, currentPassword: null,
    newPasswords: [], passwords: [], otp: { kind: 'single', fields: [field] }, inputs: [field], text: '', intent: null };
  const info = { kind: FieldKind.OTP, group };
  adHocOtp.set(field, info);
  return info;
}

function otpEntryForCommand() {
  const active = deepActiveElement();
  if (active?.tagName === 'INPUT') {
    const info = fieldInfo(active);
    if (info?.kind === FieldKind.OTP) return info.group.otp;
    const loneUsername = info?.kind === FieldKind.USERNAME && !info.group.passwords.length && !firstOtpEntry();
    if ((!info || loneUsername) && couldBeCodeField(active)) return { kind: 'single', fields: [active] };
  }
  return firstOtpEntry();
}

/** The focused field's group, else the most login-like one. A `quiet` group only when focused. */
function targetGroup() {
  const active = deepActiveElement();
  const g = active && groupOf(active);
  if (g) return { group: g, field: active, focused: true };
  const groups = scan.groups.filter((x) => !x.quiet);
  const best = groups.find((x) => x.currentPassword) || groups.find((x) => x.username) ||
    groups.find((x) => x.passwords.length) || groups[0];
  if (!best) return null;
  return { group: best, field: best.username || best.currentPassword || best.passwords[0]?.el || best.otp?.fields[0] };
}

// Sandboxed documents have an opaque origin (`document.domain` is "", unfakeable from the isolated
// world): their URL names a site they are not, so nothing fills or saves.
export function opaqueOrigin() {
  try { return document.domain === ''; } catch { return true; }
}

function sameOriginAsTop() {
  if (isTop) return true;
  try { return window.top.location.origin === location.origin; } catch { return false; }
}

function errorMessage(err) {
  return friendlyError(err);
}

function ensureMenu() {
  if (!menu) {
    menu = new InlineMenu({
      onIconClick: (field) => (menu.isOpen && menu.field === field ? menu.close() : openMenu(field, { user: 'icon' })),
      onSelect: (entry, field) => onMenuSelect(entry, field),
      onGenerateClick: (field) => { generateAndSave(field).catch(() => {}); },
      onGenerateOptions: (field) => { openGeneratorOptions(field).catch(() => {}); },
    });
  }
  return menu;
}

/** Tells the background which frame has the focused field, so shortcuts go there. */
function reportFocus(kind) {
  if (Date.now() - lastFocusReport > 2000) {
    lastFocusReport = Date.now();
    bg('focus', { kind }).catch(() => {});
  }
}

/** `initial`: the page focused the field as it loaded; suggestions then open as for a click. */
function onFieldFocus(field, { initial = false } = {}) {
  let info = fieldInfo(field);
  if (!info) {
    const form = formInfo(field);
    if (form) { onFormFieldFocus(field, form); return; }
    if (!couldBeCodeField(field)) return;
    // A pending 2FA code is on offer: adopt a field that could be the step's code box, never a search or chat.
    if (!otpOfferActive() || !isVisible(field) || !adoptableCodeField(field, {
      pageText, inputCount: visibleInputCount, loginPath: looksLikeLoginPath(location.href),
    })) { reportFocus('other'); return; }
    info = adoptAsOtpField(field);
  }
  reportFocus(info.kind);
  if (!settings.inlineMenu) return;
  const m = ensureMenu();
  m.showIcon(field, iconOptions(info));
  if (m.isOpen && m.field !== field) m.close();
  const conditional = globalThis.__passBridge?.hasConditional();
  if (info.kind === FieldKind.OTP && !m.isOpen && wantsOtpMenu(field)) openMenu(field, { auto: true });
  // Opened for the page's passkey request: nothing preselected, so the Enter submitting a username picks nothing.
  else if (conditional && (isWebauthnField(field) || info.kind === FieldKind.USERNAME) && !m.isOpen) openMenu(field, { passive: true });
  else if (!maybeAutoGenerate(field, info)) maybeAutoSuggest(field, info, { initial });
}

function wantsOtpMenu(field) {
  if (otpFilled || field.value) return false;
  if (otpOfferActive()) return true;
  return focusFromUser(field) && !!otpCtx?.items?.some((it) => it.has_totp);
}

/** Remembers the last trusted pointer press / key, to tell user focus from script focus. */
function recordGesture(e) {
  if (!e.isTrusted) return;
  const kind = e.type === 'keydown' ? 'key' : 'pointer';
  lastGesture = { at: Date.now(), kind, target: e.composedPath ? e.composedPath()[0] : e.target };
  lastInteractionAt = lastGesture.at;
  if (kind !== 'pointer') return;
  // A press on a new-password field that already has focus (autofocus) counts as focusing it.
  const field = eventField(e);
  if (field && field === deepActiveElement()) {
    const info = scan.fields.get(field);
    if (info && !maybeAutoGenerate(field, info)) maybeAutoSuggest(field, info);
  }
}

function focusFromUser(field) {
  if (Date.now() - lastGesture.at > USER_FOCUS_WINDOW_MS) return false;
  if (lastGesture.kind === 'key') return true;
  const target = lastGesture.target;
  if (!target) return false;
  if (target === field) return true;
  const label = target.closest?.('label');
  return !!label && (label.control === field || label.contains(field));
}

function maybeAutoGenerate(field, info) {
  if (!settings.inlineMenu || !settings.autoGenerate) return false;
  if (info.kind !== FieldKind.NEW_PASSWORD || info.group?.quiet) return false;
  if (autoOffered.has(field) || field.value) return false;
  if (menu?.isOpen || !focusFromUser(field)) return false;
  // Once per form: if the user dismisses it on "password", "confirm password" doesn't ask again.
  for (const el of info.group?.newPasswords || []) autoOffered.add(el);
  autoOffered.add(field);
  ensureMenu().showIcon(field, iconOptions(info));
  openMenu(field, { auto: true });
  return true;
}

const isSignInInfo = (info) => info?.kind === FieldKind.USERNAME || info?.kind === FieldKind.CURRENT_PASSWORD;

function newStep() {
  stepStartedAt = Date.now();
  stepFocusSeen = false;
}

/** When this document became visible (now while it is hidden: a background tab hasn't been seen yet). */
function visibleSince() {
  if (document.visibilityState === 'hidden') {
    hiddenSeenAt = Date.now();
    return hiddenSeenAt;
  }
  if (hiddenSeenAt > shownAt) shownAt = Date.now(); // shown, before its visibilitychange came here
  return shownAt;
}

/** The page's initial sign-in focus for this step: first, no user input since, within PAGE_FOCUS_WINDOW_MS. */
function pageFocusInitial() {
  if (stepFocusSeen || lastInteractionAt > stepStartedAt) return false;
  return Date.now() - Math.max(stepStartedAt, visibleSince()) <= PAGE_FOCUS_WINDOW_MS;
}

function onFocusIn(field) {
  if (suggestWait && suggestWait.field !== field) clearSuggestWait();
  const info = scan.fields.get(field);
  let initial = false;
  if (isSignInInfo(info)) {
    initial = pageFocusInitial();
    stepFocusSeen = true;
  }
  // Nothing knows the field yet (its form is still rendering): looked at again after the next scan.
  undetectedFocus = !fieldInfo(field) && !formInfo(field)
    ? { field, at: Date.now(), initial: focusFromUser(field) || pageFocusInitial() }
    : null;
  onFieldFocus(field, { initial });
}

function recheckFocusedField() {
  const u = undetectedFocus;
  if (!u) return;
  if (deepActiveElement() !== u.field) { undetectedFocus = null; return; }
  const info = scan.fields.get(u.field);
  if (!info) return;
  undetectedFocus = null;
  const initial = u.initial && isSignInInfo(info) && !stepFocusSeen && lastInteractionAt <= u.at;
  if (isSignInInfo(info)) stepFocusSeen = true;
  onFieldFocus(u.field, { initial });
}

function pageAskedPasskey() {
  return !!globalThis.__passBridge?.hasConditional();
}

/** Auto-opens the site's logins for an empty sign-in field, once per field and page load; never fills. */
async function maybeAutoSuggest(field, info, { initial = false } = {}) {
  if (!settings.inlineMenu || !settings.autoSuggest) return false;
  if (!isSignInInfo(info) || info.group?.quiet) return false;
  if (autoSuggested.has(field) || field.value) return false;
  if (menu?.isOpen || !(initial || focusFromUser(field))) return false;
  autoSuggested.add(field);
  return suggestLogins(field, info, Date.now());
}

// Waits while the tab is hidden, while fully locked (Windows Hello never comes from the page) and while
// Passyble isn't running; opens only if the field is still focused, empty and untouched since `at`.
async function suggestLogins(field, info, at, left = RECHECKS) {
  clearSuggestWait();
  if (document.visibilityState === 'hidden') { waitToSuggest(field, info, at, 'visible', left); return false; }
  let data;
  try {
    data = await bg('logins.find');
  } catch (err) {
    if (err?.code === 'update_required') return showAppUpdateLine(field, info);
    if (err?.code === 'locked') waitToSuggest(field, info, at, 'unlock', left);
    else if ((err?.code === 'agent_unavailable' && !isHostMissing(err)) || err?.code === 'timeout') {
      waitToSuggest(field, info, at, 'retry', left - 1);
    }
    return false;
  }
  if (!data?.items?.length) return false;
  if (deepActiveElement() !== field || field.value || menu?.isOpen || !settings.inlineMenu || !settings.autoSuggest) return false;
  if (document.visibilityState === 'hidden') { waitToSuggest(field, info, at, 'visible', left); return false; }
  ensureMenu().showIcon(field, iconOptions(info));
  openMenu(field, { auto: true, passive: pageAskedPasskey(), data });
  return true;
}

function waitToSuggest(field, info, at, why, left) {
  if (left <= 0 || deepActiveElement() !== field) return;
  clearSuggestWait();
  const wait = { field, info, at, why, left, timer: 0 };
  if (why === 'retry') wait.timer = setTimeout(() => resumeSuggest('retry'), RECHECK_MS);
  suggestWait = wait;
}

function clearSuggestWait() {
  if (suggestWait) clearTimeout(suggestWait.timer);
  suggestWait = null;
}

function resumeSuggest(why) {
  const w = suggestWait;
  if (!w || (w.why !== why && !(why === 'unlock' && w.why === 'retry'))) return false;
  clearSuggestWait();
  if (deepActiveElement() !== w.field || w.field.value || lastInteractionAt > w.at || menu?.isOpen) return false;
  if (!settings.inlineMenu || !settings.autoSuggest) return false;
  suggestLogins(w.field, w.info, w.at, w.left);
  return true;
}

// Firefox: a sign-in field the page focused in a hidden tab gets no focus event, so it counts as the
// page's initial focus once the tab shows.
function onVisibilityChange() {
  visibleSince();
  if (document.visibilityState === 'hidden' || resumeSuggest('visible')) return;
  const active = deepActiveElement();
  if (active?.tagName === 'INPUT' && !stepFocusSeen && isSignInInfo(scan.fields.get(active))) onFocusIn(active);
}

function showAppUpdateLine(field, info, { user = '' } = {}) {
  if (!user && appUpdateShown) return false;
  if (deepActiveElement() !== field || menu?.isOpen || !settings.inlineMenu) return false;
  appUpdateShown = true;
  ensureMenu().showIcon(field, iconOptions(info));
  openMenu(field, { auto: !user, passive: true, failed: new BgError('update_required'), user });
  return true;
}

function iconOptions(info) {
  return { generate: info?.kind === FieldKind.NEW_PASSWORD };
}

function closeAutoMenu() {
  if (menu?.isOpen && menuAutoField && menu.field === menuAutoField) menu.close();
  menuAutoField = null;
}

/** True when the click that ends here selected text in `field` (a drag, a double-click). */
function selectsText(field) {
  try {
    if (typeof field.selectionStart === 'number' && field.selectionStart !== field.selectionEnd) return true;
  } catch { /* e-mail fields have no selection range */ }
  try { return !!window.getSelection?.()?.toString(); } catch { return false; }
}

// A click or tap reopens the field's menu every time (the focus opening is once per field), even on a
// filled sign-in field, to switch accounts.
async function onFieldClick(e) {
  if (!e.isTrusted || e.button !== 0 || !settings.inlineMenu) return;
  const field = eventField(e);
  if (!field || field !== deepActiveElement() || selectsText(field)) return;
  if (menu?.isOpen && menu.field === field) return;
  const info = fieldInfo(field);
  if (!info) {
    const form = formInfo(field);
    if (form) reopenFormMenu(field, form);
    return;
  }
  if (info.kind === FieldKind.NEW_PASSWORD) {
    if (!settings.autoGenerate || field.value) return;
    ensureMenu().showIcon(field, iconOptions(info));
    openMenu(field, { auto: true });
    return;
  }
  if (!settings.autoSuggest || (info.kind !== FieldKind.USERNAME && info.kind !== FieldKind.CURRENT_PASSWORD)) return;
  let data = null;
  try {
    data = await bg('logins.find');
  } catch (err) {
    if (err.code === 'update_required') { showAppUpdateLine(field, info, { user: 'click' }); return; }
    // Locked: show how to unlock, except on a `quiet` field (a post password is not worth a prompt).
    if (err.code !== 'locked' || info.group?.quiet) return;
  }
  if (data && !data.items?.length) return;
  if (deepActiveElement() !== field || menu?.isOpen || !settings.inlineMenu) return;
  ensureMenu().showIcon(field, iconOptions(info));
  openMenu(field, { auto: true, passive: pageAskedPasskey(), showAll: true, data, user: 'click' });
}

async function reopenFormMenu(field, form) {
  if (!settings.autoSuggest || !formsWanted() || menu?.iconField !== field) return;
  let data;
  try { data = await bg(FORM_METHODS[form.type].list, { automatic: true }); } catch { return; }
  if (!data?.items?.length) return;
  if (deepActiveElement() !== field || menu?.isOpen) return;
  openFormMenu(field, form, { auto: true, passive: true, data });
}

/** No special characters by default when the field forbids them or the site's last password had none. */
async function defaultSymbols(field) {
  if (passwordRulesOf(field).symbols === false) return false;
  try { return !(await prefersNoSymbols(location.href)); } catch { return true; }
}

// From the agent when it can make the plan, else made here. An explicit `symbols: true` overrides a
// field that seems to forbid them.
async function preparePassword(field, { symbols, options } = {}) {
  const explicit = typeof symbols === 'boolean';
  if (!explicit) symbols = await defaultSymbols(field);
  options ??= await generatorOptions();
  const limits = passwordLimitsOf(field);
  if (explicit && symbols) delete limits.symbols;
  const plan = planFor(options, limits, symbols);
  let result = null;
  if (agentCanMake(plan)) {
    let timer = 0;
    try {
      const res = await Promise.race([
        bg('generate', { length: plan.length, automatic: true, ...(plan.symbols ? {} : { symbols: false }) }),
        new Promise((resolve) => { timer = setTimeout(resolve, AGENT_GENERATE_TIMEOUT_MS, null); }),
      ]);
      const pw = res?.password;
      if (typeof pw === 'string' && pw.length >= 8 && (plan.symbols || isPlainPassword(pw))) result = { password: pw, mode: 'password', notes: plan.notes };
    } catch { /* desktop app not running: generate here */ }
    clearTimeout(timer);
  }
  if (!result) {
    let words = null;
    if (plan.mode === 'passphrase') {
      try { words = await loadPassphraseWords(); } catch { /* a password instead */ }
    }
    result = makeLocally(plan, limits, { words });
  }
  return { ...result, symbols: plan.symbols, ...strengthOf(result) };
}

function wantsNewPassword(info) {
  const group = info.group;
  return info.kind === FieldKind.NEW_PASSWORD ||
    !!(group && group.newPasswords.length && !group.currentPassword && info.kind !== FieldKind.USERNAME && info.kind !== FieldKind.OTP);
}

function generateEntries(preview) {
  const plain = preview.symbols === false;
  const strong = preview.mode === 'passphrase' ? t('genPassphraseEntry') : t('menuGenerateEntry');
  const title = (symbols) => (symbols ? strong : t('commonNoSymbols'));
  return [
    { kind: 'generate', symbols: !plain, title: title(!plain), icon: 'dice', preview },
    { kind: 'generate', symbols: plain, title: title(plain), subtitle: plain ? t('menuGenerateSymbolsSub') : t('menuGenerateNoSymbolsSub'), icon: 'dice' },
    { kind: 'generate-options', title: t('genOptionsEntry'), subtitle: t('genOptionsEntrySub'), icon: 'gear' },
  ];
}

function activeGenerated() {
  if (generated && Date.now() - generated.at > GENERATED_TTL_MS) generated = null;
  return generated;
}

// `auto`: opened on its own (typing or Esc closes it). `passive`: opened for something the page did, so
// nothing is preselected and Enter keeps its meaning. `user`: the user's own action, so a fully locked
// vault starts Windows Hello at once.
async function openMenu(field, { force = false, auto = false, passive = false, showAll = false, data: found = null,
  refresh = false, preview: kept = null, failed = null, user = '' } = {}) {
  if (!settings.inlineMenu && !force) return;
  generatedReveal?.close(); // both sit in the same spot
  const gesture = user ? Date.now() : 0;
  const form = !fieldInfo(field) && formInfo(field);
  if (form) { await openFormMenu(field, form, { auto, passive, data: found, refresh, failed, user }); return; }
  const info = fieldInfo(field) || { kind: FieldKind.USERNAME, group: null };
  const m = ensureMenu();
  menuAutoField = auto ? field : null;
  menuPassive = passive;
  menuModel = { field, info, data: null, preview: null, view: 'logins', showAll };
  if (!refresh) m.open(field, { status: 'loading' });
  const show = (model) => m.update({ ...model, preselect: !passive });
  const genPromise = wantsNewPassword(info) ? (kept ? Promise.resolve(kept) : preparePassword(field)) : null;
  let data = found;
  try {
    if (failed) throw failed;
    if (!data) data = await bg('logins.find');
  } catch (err) {
    const preview = genPromise ? await genPromise : null;
    if (m.field !== field) return;
    const gen = preview ? generateEntries(preview) : [];
    if (err.code === 'locked') {
      // Generating needs no unlocked vault; saving later asks to unlock.
      if (!gen.length && await offerUnlock(reopenAfterUnlock(field, { showAll }), { quiet: true, ...unlockStart(user, gesture) })) return;
      if (m.field !== field) return;
      show({ status: 'ok', message: t('menuLocked'), entries: [...gen, { kind: 'unlock', title: t('menuUnlock'), icon: 'lock', separatorBefore: gen.length > 0 }] });
    } else if (err.code === 'agent_unavailable') {
      if (gen.length && !isHostMissing(err)) show({ status: 'message', message: t('menuNotRunningGenerate'), entries: gen });
      else if (gen.length) show({ status: 'message', message: errorMessage(err), entries: gen });
      else show({ status: 'unavailable', message: errorMessage(err) });
      if (!isHostMissing(err)) {
        recheckWhileUnavailable(field, 'logins.find', (again, error) =>
          openMenu(field, { force: true, auto, passive, showAll, data: again, refresh: true, preview, failed: error }));
      }
    } else {
      show({ status: 'message', message: errorMessage(err), entries: gen });
    }
    return;
  }
  const preview = genPromise ? await genPromise : null;
  if (m.field !== field) return;
  if (!data.items?.length && !data.locked && isSignInInfo(info) && !data.similar) {
    // No login of this site: logins of similar sites and the vault search (`menu.similar`).
    data = { ...data, similar: await bg('menu.similar').catch(() => null) };
    if (m.field !== field) return;
  }
  menuModel = { field, info, data, preview, view: 'logins', showAll };
  show({ status: 'ok', ...buildMenuModel(info, field, data, preview, { showAll }) });
}

function typedFilter(info, field) {
  if (info?.kind !== FieldKind.USERNAME) return '';
  return String(field?.value || '').trim();
}

function refilterMenu(field) {
  if (!menu?.isOpen || menu.field !== field || menuModel?.field !== field) return false;
  if (menuModel.view !== 'logins' || !menuModel.data || menuModel.info?.kind !== FieldKind.USERNAME) return false;
  menuModel.showAll = false;
  menu.update({ status: 'ok', ...buildMenuModel(menuModel.info, field, menuModel.data, menuModel.preview), preselect: !menuPassive });
  return true;
}

function buildMenuModel(info, field, data, preview = null, { showAll = false } = {}) {
  const items = data.items || [];
  const pending = data.pending_otp || null;
  const entries = [];
  const group = info.group;

  if (info.kind === FieldKind.OTP) {
    if (pending) {
      entries.push({ kind: 'otp', id: pending.id, title: pending.title, subtitle: t('menuFillOtp'), icon: 'clock', avatarClass: 'otp', badges: [BADGE_2FA()] });
    }
    for (const it of items) {
      if (it.has_totp && it.id !== pending?.id) {
        entries.push({ kind: 'otp', id: it.id, title: it.title, subtitle: t('menuOtpCodeFor', it.username || ''), icon: 'clock', avatarClass: 'otp' });
      }
    }
    return { heading: data.locked ? t('menuHeadingOtpLocked') : t('menuHeadingOtp'), entries, message: t('menuNoOtp') };
  }

  const typed = showAll ? '' : typedFilter(info, field);
  const shown = typed ? matchLogins(items, typed) : items;
  const bridge = globalThis.__passBridge;
  if (bridge?.hasConditional() && (isWebauthnField(field) || info.kind === FieldKind.USERNAME)) {
    // Passkeys for the page's request, else logins that have one (older desktop apps).
    const offered = offeredPasskeys();
    if (offered) {
      const named = offered.map((pk) => ({ ...pk, username: pk.user_name || pk.user_display_name || '' }));
      for (const pk of typed ? matchLogins(named, typed) : named) {
        entries.push({ kind: 'passkey', id: pk.id, credentialId: pk.credential_id, account: passkeyAccount(pk), title: pk.title, subtitle: t('menuPasskeyFor', passkeyAccount(pk)), icon: 'key', badges: [BADGE_PASSKEY()] });
      }
    } else {
      for (const it of shown) {
        if (it.has_passkey) {
          entries.push({ kind: 'passkey', id: it.id, account: it.username || '', title: it.title, subtitle: t('menuPasskeyFor', it.username || ''), icon: 'key', badges: [BADGE_PASSKEY()] });
        }
      }
    }
  }
  const firstLogin = entries.length;
  // Linked vaults (Teams, Family): each login says which vault it is in once there are several.
  const vaults = vaultTable(data.vaults);
  for (const it of shown) {
    const badges = [];
    if (it.has_totp) badges.push(BADGE_2FA());
    if (it.has_passkey) badges.push(BADGE_PASSKEY());
    const vault = vaultLabel(it, vaults);
    if (vault) badges.push(vault);
    if (!canReveal(it, vaults)) badges.push(t('teamsFillOnly'));
    entries.push({ kind: 'login', id: it.id, title: it.title, subtitle: it.username || t('commonNoUsername'), badges, separatorBefore: entries.length === firstLogin && firstLogin > 0 });
  }
  const similar = !items.length && !data.locked && isSignInInfo(info) ? data.similar : null;
  if (similar && !entries.length) return similarModel(similar, vaults);
  if (wantsNewPassword(info)) {
    // Generator first; picking a saved login still fills its password here.
    if (entries.length) entries[0].separatorBefore = true;
    entries.unshift(...generateEntries(preview));
  }
  if (pending && group?.otp) {
    entries.unshift({ kind: 'otp', id: pending.id, title: pending.title, subtitle: t('menuFillOtp'), icon: 'clock', avatarClass: 'otp', badges: [BADGE_2FA()] });
  }
  // Soft-locked: the app kept the list, so logins show and picking one unlocks first.
  const model = data.locked ? { heading: t('menuHeadingLocked'), entries } : { entries };
  if (typed && items.length && !shown.length) Object.assign(model, { status: 'message', message: t('menuNoMatches') });
  return model;
}

// Nothing preselected, so Enter never picks another site's login.
function similarModel(similar, vaults) {
  const entries = [];
  const found = Array.isArray(similar.items) ? similar.items.slice(0, 3) : [];
  const table = vaultTable(similar.vaults, [...vaults.values()]);
  found.forEach((it, i) => {
    const badges = [];
    if (it.has_totp) badges.push(BADGE_2FA());
    const vault = vaultLabel(it, table);
    if (vault) badges.push(vault);
    entries.push({ kind: 'similar', id: String(it.id), title: it.title || it.domain || '?',
      subtitle: [it.username || t('commonNoUsername'), it.domain].filter(Boolean).join(' · '),
      badges, section: i === 0 ? t('menuSimilarSites') : '' });
  });
  if (similar.search) entries.push({ kind: 'search', title: t('menuSearchPassyble'), icon: 'search', separatorBefore: entries.length > 0 });
  const site = location.hostname.replace(/^www\./, '');
  return { status: 'message', message: site ? t('commonNoLoginsFor', site) : t('menuNoLogins'), entries, neverPreselect: true };
}

/** A "Similar sites" pick: the agent fills it only after the user confirms in the desktop app. */
async function fillSimilar(id, group, field) {
  let creds;
  try {
    creds = await bg('logins.fill_cross', { id, similar: true });
  } catch (err) {
    if (err.code !== 'cancelled') showNotice(errorMessage(err));
    return false;
  }
  const target = group || groupOf(field);
  const result = target
    ? fillLoginGroup(target, creds, { field })
    : { username: !!field && usernameScore(field) > 0 && fillInput(field, creds.username), password: false };
  if (!creds.cross) bg('fill.done', { id, otp: !!result.otp }).catch(() => {});
  return !!(result.username || result.password);
}

// Shows how to unlock and runs `pending.run` once unlocked, however that happens. Desktop apps without
// `unlock.inline`: `run` right away (their own prompt). `gesture` (the user's click, tap or key) lets
// Windows Hello start at once unless declined moments ago (`hello_auto`). False when nothing was shown.
async function offerUnlock(pending, { prompt = '', quiet = false, gesture = 0, focusFrame = false } = {}) {
  const m = ensureMenu();
  const { field } = pending;
  if (!quiet) m.update({ status: 'loading' });
  let opts = null;
  try {
    opts = await bg('unlock.options', pending.itemId ? { for: pending.itemId } : {});
  } catch (err) {
    if (err.code === 'agent_unavailable' && m.field === field) {
      m.update({ status: 'unavailable', message: errorMessage(err) });
      return true;
    }
    if ((err.code === 'timeout' || err.code === 'extension_reloaded') && m.field === field) {
      m.update({ status: 'message', message: errorMessage(err), entries: [] });
      return true;
    }
  }
  if (m.field !== field) return true;
  if (!opts?.inline || !opts.locked) {
    if (quiet) return false;
    m.close();
    await pending.run();
    return true;
  }
  pendingUnlock = { ...pending, at: Date.now() };
  if (helloStartsNow(opts, gesture)) startHello(field, opts, prompt);
  else showUnlockChoices(field, opts, { prompt, focusFrame });
  return true;
}

function helloStartsNow(opts, gesture) {
  if (!gesture || Date.now() - gesture > HELLO_GESTURE_MS || !opts?.hello) return false;
  return opts.hello_auto !== false || !!opts.hello_pending;
}

// Focus the password frame when the user went for Passyble itself, not on a plain click into the field.
function unlockStart(user, gesture) {
  return user ? { gesture, focusFrame: user !== 'click' } : {};
}

// Without `unlocked` (older desktop apps) `unlock` shows the desktop app's own prompt first.
function reopenAfterUnlock(field, { showAll = false } = {}) {
  return { field, needsFocus: true, run: async ({ unlocked = false } = {}) => {
    if (!unlocked) await bg('unlock');
    await openMenu(field, { force: true, showAll });
  } };
}

/** `prompt`: what unlocking is for; `message` replaces it with an outcome. */
function showUnlockChoices(field, opts, { prompt = '', message = '', focusFrame = false } = {}) {
  const frame = unlockFrameFor(field, { focus: focusFrame, hello: !!opts.hello });
  const entries = [];
  if (opts.hello) entries.push({ kind: 'unlock-hello', title: t('menuUnlockHello'), icon: 'hello', separatorBefore: !!frame });
  if (!frame) entries.push({ kind: 'unlock-password', title: t('menuUnlockPassword'), icon: 'lock' });
  // Browser-only vault: there is no app to open.
  if (!opts.browser) entries.push({ kind: 'unlock-app', title: t('commonOpenPassyble'), subtitle: t('commonUnlockInApp'), icon: 'external', separatorBefore: true });
  menuModel = { ...(menuModel || {}), field, view: 'unlock', opts, prompt };
  ensureMenu().update({ status: 'message', heading: t('menuHeadingLocked'), entries, preselect: true, frame,
    message: message || prompt || t('menuUnlockToSee') });
}

async function startHello(field, opts, prompt = '') {
  const run = ++helloRun;
  const m = ensureMenu();
  menuModel = { ...(menuModel || {}), field, view: 'unlock', opts, prompt };
  m.update({ status: 'message', heading: t('menuHeadingLocked'), preselect: false,
    message: [prompt || t('menuUnlockToSee'), t('commonConfirmHello')].join(' '),
    entries: [{ kind: 'unlock-use-password', title: t('menuUsePassword'), icon: 'lock' }] });
  try {
    await bg('unlock.hello');
  } catch (err) {
    // The user moved on to the password (or another Hello) meanwhile.
    if (run !== helloRun || m.field !== field) return;
    const again = (message, extra = {}) => showUnlockChoices(field, { ...opts, ...extra }, { prompt, message, focusFrame: true });
    if (err.code === 'agent_unavailable') m.update({ status: 'unavailable', message: errorMessage(err) });
    else if (err.code === 'cancelled') again(t('menuHelloCancelledPassword'));
    // Hello turned off, or the master password is due.
    else if (err.code === 'not_supported') again(friendlyError(err, { context: 'unlock' }), { hello: false });
    else again(errorMessage(err));
    return;
  }
  await completePendingUnlock();
}

function usePasswordInstead(field) {
  helloRun++;
  bg('unlock.cancel').catch(() => {});
  const opts = menuModel?.opts || { inline: true, locked: true, hello: false };
  showUnlockChoices(field, opts, { prompt: menuModel?.prompt || '', focusFrame: true });
}

/** "chrome-extension://<id>" / "moz-extension://<uuid>" ('' where the runtime can't say). */
function extensionOrigin() {
  try { return String(ext.runtime.getURL('') || '').replace(/\/+$/, ''); } catch { return ''; }
}

// Reused while on screen so nothing typed is lost; null where it can't be used (the popup then).
function unlockFrameFor(field, { focus = false, hello = false } = {}) {
  if (frameBlocked || !extensionOrigin()) return null;
  if (unlockFrame?.field === field && unlockFrame.el.isConnected) {
    if (unlockFrame.hello !== hello) {
      unlockFrame.hello = hello;
      postFrameHello(unlockFrame);
    }
    if (focus) focusUnlockFrame();
    return unlockFrame.el;
  }
  dropUnlockFrame();
  const el = document.createElement('iframe');
  el.className = 'unlock-frame';
  el.title = t('unlockFrameTitle');
  const query = [focus ? 'focus=1' : '', hello ? 'hello=1' : ''].filter(Boolean).join('&');
  el.src = ext.runtime.getURL(FRAME_PATH) + (query ? `?${query}` : '');
  const frame = { el, field, ready: false, wantFocus: focus, timer: 0, watch: 0, hello };
  // Some pages block extension frames: fall back to the popup.
  frame.timer = setTimeout(() => { if (unlockFrame === frame && !frame.ready) unlockFrameFailed(); }, FRAME_READY_MS);
  // The page must not draw over the menu or make it see-through while a password goes in.
  frame.watch = setInterval(() => {
    if (unlockFrame !== frame) return;
    if (!el.isConnected) { dropUnlockFrame(); return; }
    if (menu?.isOpen && !menu.intact()) unlockFrameFailed();
  }, 250);
  unlockFrame = frame;
  return el;
}

function postFrameHello(frame) {
  if (!frame?.ready) return; // sent on 'ready'
  try { frame.el.contentWindow?.postMessage({ passybleUnlock: 'hello', on: !!frame.hello }, extensionOrigin()); } catch { /* gone */ }
}

function dropUnlockFrame() {
  if (!unlockFrame) return;
  clearTimeout(unlockFrame.timer);
  clearInterval(unlockFrame.watch);
  unlockFrame = null;
}

// Focus the iframe element first: a cross-origin frame may not take focus by itself.
function focusUnlockFrame() {
  const frame = unlockFrame;
  if (!frame) return;
  if (!frame.ready) { frame.wantFocus = true; return; }
  frame.wantFocus = false;
  try { frame.el.focus({ preventScroll: true }); } catch { /* gone */ }
  try { frame.el.contentWindow?.postMessage({ passybleUnlock: 'focus' }, extensionOrigin()); } catch { /* gone */ }
}

function unlockFrameFailed() {
  const field = unlockFrame?.field;
  frameBlocked = true;
  dropUnlockFrame();
  if (field && menu?.isOpen && menu.field === field && menuModel?.view === 'unlock') {
    showUnlockChoices(field, menuModel.opts || { inline: true, locked: true, hello: false }, { prompt: menuModel.prompt || '' });
  }
}

/** Status messages from the master password frame. They never carry a secret. */
function onFrameMessage(e) {
  const frame = unlockFrame;
  if (!frame || e.source !== frame.el.contentWindow || e.origin !== extensionOrigin()) return;
  const what = e.data?.passybleUnlock;
  if (what === 'ready') {
    frame.ready = true;
    clearTimeout(frame.timer);
    const height = Number(e.data.height);
    if (height > 0) frame.el.style.height = `${Math.min(160, Math.max(40, Math.ceil(height)))}px`;
    postFrameHello(frame);
    if (frame.wantFocus) focusUnlockFrame();
  } else if (what === 'unlocked') {
    completePendingUnlock().catch(() => {});
  } else if (what === 'escape') {
    const field = frame.field;
    menu?.close();
    if (field?.isConnected) field.focus({ preventScroll: true });
  }
}

// Runs the waiting pick once; whichever comes first calls it: the unlock's answer, the frame, or `lock_state`.
async function completePendingUnlock() {
  const p = pendingUnlock;
  pendingUnlock = null;
  if (!p || Date.now() - p.at > PENDING_UNLOCK_TTL_MS || !p.field.isConnected) return false;
  if (menu?.hasFocus()) p.field.focus({ preventScroll: true });
  if (p.needsFocus && deepActiveElement() !== p.field) return false;
  if (menu?.isOpen && menu.field === p.field) menu.close();
  try {
    await p.run({ unlocked: true });
  } catch (err) {
    showNotice(errorMessage(err));
  }
  return true;
}

async function onUnlockSelect(entry, field) {
  const m = ensureMenu();
  const opts = menuModel?.opts || { inline: true, locked: true, hello: false };
  const prompt = menuModel?.prompt || '';
  const again = (message, extra = {}) => { if (m.field === field) showUnlockChoices(field, { ...opts, ...extra }, { prompt, message }); };
  try {
    switch (entry.kind) {
      case 'unlock-hello':
        await startHello(field, opts, prompt);
        return;
      case 'unlock-use-password':
        usePasswordInstead(field);
        return;
      case 'unlock-password':
        // An extension page takes the password, so this page never sees it.
        await bg('unlock.open-form');
        again(t('commonUnlockInApp'));
        return;
      case 'unlock-app':
        m.update({ status: 'message', heading: t('menuHeadingLocked'), message: t('menuUnlockingInApp'), entries: [] });
        await bg('unlock');
        break;
      default:
        return;
    }
  } catch (err) {
    if (err.code === 'agent_unavailable') { m.update({ status: 'unavailable', message: errorMessage(err) }); return; }
    if (err.code === 'cancelled') { again(entry.kind === 'unlock-hello' ? t('menuHelloCancelled') : t('errCancelled')); return; }
    if (err.code === 'not_supported') { again(friendlyError(err, { context: 'unlock' }), { hello: false }); return; }
    again(errorMessage(err));
    return;
  }
  await completePendingUnlock();
}

async function onMenuSelect(entry, field) {
  const m = ensureMenu();
  const group = groupOf(field) || targetGroup()?.group;
  try {
    switch (entry.kind) {
      case 'unlock':
        await offerUnlock(reopenAfterUnlock(field), { gesture: Date.now(), focusFrame: true });
        return;
      case 'unlock-hello':
      case 'unlock-use-password':
      case 'unlock-password':
      case 'unlock-app':
        await onUnlockSelect(entry, field);
        return;
      case 'card':
      case 'identity':
        // Picked from a soft-locked list: unlock first, then fill.
        if (menuModel?.data?.locked) {
          await offerUnlock({ field, run: () => fillForm(entry, field) }, { prompt: entry.title ? t('menuUnlockToFill', entry.title) : '', gesture: Date.now(), focusFrame: true });
          return;
        }
        m.close();
        menuAutoField = null;
        await fillForm(entry, field);
        return;
      case 'login':
        if (menuModel?.data?.locked) {
          await offerUnlock({ field, itemId: entry.id, run: () => fillLogin(entry.id, group, field, { picked: true }) }, { prompt: entry.title ? t('menuUnlockToFill', entry.title) : '', gesture: Date.now(), focusFrame: true });
          return;
        }
        m.close();
        await fillLogin(entry.id, group, field, { picked: true });
        return;
      case 'otp':
        if (menuModel?.data?.locked) {
          await offerUnlock({ field, itemId: entry.id, run: () => fillOtp(entry.id, group?.otp || firstOtpEntry()) }, { prompt: t('menuUnlockToFillOtp', entry.title), gesture: Date.now(), focusFrame: true });
          return;
        }
        m.close();
        await fillOtp(entry.id, group?.otp || firstOtpEntry());
        return;
      case 'passkey': {
        const pk = { id: entry.id, credential_id: entry.credentialId, title: entry.title };
        if (menuModel?.data?.locked) {
          await offerUnlock({ field, itemId: entry.id, run: () => completePasskey(pk) }, { prompt: t('menuUnlockToSignIn', entry.account || entry.title || ''), gesture: Date.now(), focusFrame: true });
          return;
        }
        m.update({ status: 'loading' });
        const res = await globalThis.__passBridge.completeConditional(entry.id, entry.credentialId);
        if (res.ok) m.close();
        else m.update({ status: 'message', message: errorMessage(res.error), entries: [] });
        return;
      }
      case 'similar':
        m.close();
        menuAutoField = null;
        await fillSimilar(entry.id, group, field);
        return;
      case 'search': {
        m.close();
        menuAutoField = null;
        const res = await bg('menu.search');
        if (!res?.opened) showNotice(t('menuSearchUseToolbar'));
        return;
      }
      case 'generate': {
        m.close();
        menuAutoField = null;
        const symbols = entry.symbols !== false;
        const made = entry.preview?.password ? entry.preview : await preparePassword(field, { symbols });
        fillGenerated(made.password, group, field, { symbols, made });
        return;
      }
      case 'generate-options': {
        // The password the menu shows in its first row: that one goes into the field.
        const preview = m.entries.find((e) => e.kind === 'generate' && e.preview)?.preview || null;
        m.close();
        menuAutoField = null;
        await openGeneratorOptions(field, { keyboard: true, preview });
        return;
      }
      default:
    }
  } catch (err) {
    if (err.code === 'locked') {
      openMenu(field, { force: true, user: 'pick' });
    } else if (m.isOpen) {
      m.update({ status: 'message', message: errorMessage(err), entries: [] });
    } else {
      showNotice(errorMessage(err));
    }
  }
}

// Passkey sign-in offered on its own: a pending conditional request (parked in bridge.js) is looked up
// with `passkey.find` (no prompt; the origin comes from the browser) and offered in passkey-prompt.js's
// card. With none for the request Passyble steps out, leaving it to the browser's own WebAuthn.

let passkeyOffer = null;             // { rid, site, items, locked, prompt, busy }: for the pending request
const passkeyDismissed = new Set();  // sites the user said "Not now" to on this page
const passkeyNoneShown = new Set();  // sites the "no passkey" notice was shown for on this page
// The page's own get() / create() card (passkey-flow.js); the conditional card makes room for it.
let passkeyFlow = null;

function conditionalRequest() {
  try {
    return globalThis.__passBridge?.conditionalRequest?.() || null;
  } catch {
    return null;
  }
}

/** Null when unknown (older app, locked, not running): the menu then uses `has_passkey`. */
function offeredPasskeys() {
  const req = conditionalRequest();
  return req && passkeyOffer?.rid === req.rid && !passkeyOffer.full && Array.isArray(passkeyOffer.items) ? passkeyOffer.items : null;
}

async function refreshPasskeyOffer() {
  const req = conditionalRequest();
  if (!req) { dropPasskeyOffer(); return; }
  if (passkeyOffer?.rid === req.rid) return;
  dropPasskeyOffer();
  if (!settings.passkeys) return;
  const offer = { rid: req.rid, site: req.rpId || location.hostname, items: null, locked: false, prompt: null };
  passkeyOffer = offer;
  let found;
  try {
    found = await bg('passkey.find', { options: { rpId: req.rpId, allowCredentials: req.allowCredentials } });
  } catch (err) {
    if (err?.code === 'update_required' && passkeyOffer === offer) {
      try { globalThis.__passBridge?.endConditional?.(offer.rid); } catch { /* an older bridge */ }
      dropPasskeyOffer();
      return;
    }
    // Fully locked: the card offers to unlock (nothing of the vault on it).
    if (err?.code === 'locked' && passkeyOffer === offer) {
      offer.items = [];
      offer.locked = true;
      offer.full = true;
      showPasskeyOffer(offer);
    }
    return;
  }
  if (passkeyOffer !== offer) return;
  offer.items = (Array.isArray(found?.items) ? found.items : []).filter((pk) => pk && typeof pk.id === 'string' && pk.id);
  offer.locked = found?.locked === true;
  if (typeof found?.rp_id === 'string' && found.rp_id) offer.site = found.rp_id;
  const none = !offer.items.length && stepOutOfConditional(offer.rid, offer.site);
  if (menu?.isOpen && menuModel?.view === 'logins' && menuModel.data && menuModel.field === menu.field) {
    menu.update({ status: 'ok', ...buildMenuModel(menuModel.info, menuModel.field, menuModel.data, menuModel.preview, { showAll: !!menuModel.showAll }), preselect: !menuPassive });
  }
  if (!none) showPasskeyOffer(offer);
}

// No passkey for `rid`: hand it to the browser's own conditional request (endConditional) and say so
// briefly (once per site, not after "Not now"). False when it can't.
function stepOutOfConditional(rid, site, { clicked = false } = {}) {
  const bridge = globalThis.__passBridge;
  let ended = false;
  try { ended = typeof bridge?.endConditional === 'function' && bridge.endConditional(rid) === true; } catch { ended = false; }
  if (!ended) return false;
  if (passkeyOffer?.rid === rid) dropPasskeyOffer();
  if (clicked || (settings.autoPasskey && !passkeyDismissed.has(site) && !passkeyNoneShown.has(site))) {
    passkeyNoneShown.add(site);
    showPasskeyNone(site);
  }
  return true;
}

function showPasskeyOffer(offer) {
  if (!settings.passkeys || !settings.autoPasskey || !(offer.items?.length || offer.full) || passkeyDismissed.has(offer.site)) return;
  if (passkeyFlow?.active) return;
  offer.prompt = showPasskeyPrompt({
    site: offer.site,
    passkeys: offer.items,
    locked: offer.locked,
    onPick: (pk, card) => signInWithPasskey(pk, { locked: offer.locked, card, offer }),
    onDismiss: () => {
      passkeyDismissed.add(offer.site);
      offer.prompt = null;
    },
  });
}

function dropPasskeyOffer() {
  passkeyOffer?.prompt?.close();
  passkeyOffer = null;
}

function passkeyOfferLockChanged() {
  // `busy`: the card itself is unlocking and carries on from there.
  if (!passkeyOffer?.prompt || passkeyOffer.prompt.closed || passkeyOffer.busy) return;
  dropPasskeyOffer();
  refreshPasskeyOffer().catch(() => {});
}

/** After the card's "Unlock": one passkey `{ pk }`, several a pick card (`{ done }`), none `{ message }`. */
async function passkeysAfterUnlock(offer) {
  const req = conditionalRequest();
  if (!req) return { done: true };
  const found = await bg('passkey.find', { options: { rpId: req.rpId, allowCredentials: req.allowCredentials }, automatic: false });
  const items = (Array.isArray(found?.items) ? found.items : []).filter((p) => p && typeof p.id === 'string' && p.id);
  const current = offer && passkeyOffer === offer && offer.rid === req.rid;
  if (current) Object.assign(offer, { items, locked: found?.locked === true, full: false });
  if (!items.length) {
    const site = typeof found?.rp_id === 'string' && found.rp_id ? found.rp_id : (req.rpId || location.hostname);
    if (stepOutOfConditional(req.rid, site, { clicked: true })) return { done: true };
    return { message: t('passkeyNoneTitle') }; // an older bridge.js can't step out
  }
  if (items.length > 1 && current) {
    offer.prompt = null; // closed on `done`
    showPasskeyOffer(offer);
    return { done: true };
  }
  return { pk: items[0] };
}

async function completePasskey(pk) {
  const res = await globalThis.__passBridge?.completeConditional(pk.id, pk.credential_id);
  if (!res) throw new BgError('not_found', 'No passkey request on this page');
  if (!res.ok) throw new BgError(res.error?.code || 'internal', res.error?.message, res.error?.reason);
}

// Locked (the kept list): unlock in the card first, never in a desktop window. `{ done }` closes the
// card, `{ message }` keeps it with that line.
async function signInWithPasskey(pk, { locked = false, card = null, offer = null } = {}) {
  if (!globalThis.__passBridge?.hasConditional()) return { done: true }; // the page moved on
  if (offer) offer.busy = true;
  try {
    if (locked && card && passkeyFlow) {
      const unlocked = await passkeyFlow.unlockInCard(card, { itemId: pk?.id || null });
      if (unlocked !== true) return { message: unlocked };
      if (!globalThis.__passBridge?.hasConditional()) return { done: true };
      card.setStatus(t('passkeyPromptSigningIn'));
    }
    if (!pk) {
      const next = await passkeysAfterUnlock(offer);
      if (next.message !== undefined || next.done) return next;
      pk = next.pk;
    }
    await completePasskey(pk);
    return { done: true };
  } catch (err) {
    return { message: errorMessage(err) };
  } finally {
    if (offer) offer.busy = false;
  }
}

function fillGenerated(password, group, field, { onlyField = false, symbols, options = null, reveal = true, made = null } = {}) {
  // `onlyField` (context menu): the clicked field, plus its confirmation only if it is a new-password field.
  const intoGroup = !!group?.newPasswords.length && (!onlyField || group.newPasswords.includes(field));
  const fields = intoGroup ? [...group.newPasswords] : (field ? [field] : []);
  if (intoGroup) fillNewPasswords(group, password);
  else if (field) fillInput(field, password);
  for (const el of fields) autoOffered.add(el);
  generated = { password, fields, at: Date.now(), mode: made?.mode || 'password', words: made?.words, symbols };
  // The background keeps a hash of it for this tab and origin: the submit is saved without asking.
  if (fields.length) {
    bg('generate.filled', { password, ...(typeof symbols === 'boolean' ? { symbols } : {}), ...(options ? { options } : {}) }).catch(() => {});
  }
  if (reveal) revealGenerated(fields.find((el) => el === deepActiveElement()), password);
  return fields;
}

// Shown once beside the focused field, never with the menu open; filled logins never show theirs.
function revealGenerated(field, password) {
  generatedReveal?.close();
  generatedReveal = null;
  if (!field || !password) return;
  menu?.close();
  menuAutoField = null;
  const pending = pendingUi();
  generatedReveal = pending;
  loadReveal().then(({ showGeneratedPassword }) => {
    if (pending.closed || generatedReveal !== pending) return;
    const shown = showGeneratedPassword(field, password, {
      copyByApp: copyGeneratedByApp,
      // Copied here (an older desktop app, or none running): cleared after 45 s. The desktop app clears its own copy.
      onCopy: (value) => { bg('clipboard.copied', { value }).catch(() => {}); },
      onClose: () => { if (generatedReveal === shown) generatedReveal = null; },
    });
    generatedReveal = shown?.closed ? null : shown;
  }).catch(() => { if (generatedReveal === pending) generatedReveal = null; });
}

// Kept out of clipboard history and cleared after 45 s; rejects when it can't (the callout copies then).
function copyGeneratedByApp(password) {
  let timer = 0;
  return Promise.race([
    bg('generate.copy', { password }),
    new Promise((_, reject) => { timer = setTimeout(reject, AGENT_COPY_TIMEOUT_MS, new Error('timeout')); }),
  ]).finally(() => clearTimeout(timer));
}

async function generateAndSave(field) {
  rescanNow();
  const group = groupOf(field);
  menu?.close();
  menuAutoField = null;
  genOptions?.close('regenerated');
  const made = await preparePassword(field);
  const { password, symbols } = made;
  fillGenerated(password, group, field, { symbols, made });
  await saveDraft(password, group);
}

// Every change fills a new password and is remembered as the options. Opened from the button, the
// result is saved as a draft; from the menu only when a draft exists.
async function openGeneratorOptions(field, { keyboard = false, preview = null } = {}) {
  rescanNow();
  if (genOptions && !genOptions.closed) {
    const same = genOptions.field === field;
    genOptions.close('reopened');
    if (same && !keyboard) return;
  }
  menu?.close();
  menuAutoField = null;
  generatedReveal?.close();
  const pending = { ...pendingUi(), field };
  genOptions = pending;
  const group = groupOf(field);
  const [{ showGeneratorOptions }, options, symbols] = await Promise.all([loadGenOptions(), generatorOptions(), defaultSymbols(field)]);
  if (pending.closed || genOptions !== pending || !field.isConnected) return;
  const limits = passwordLimitsOf(field);
  const fill = (result, changed) => {
    fillGenerated(result.password, group, field, { symbols: result.symbols, options: changed, reveal: false, made: result });
    return result;
  };
  const kept = activeGenerated();
  const keptHere = !!kept?.fields.includes(field) && field.value === kept.password;
  const current = keptHere
    ? planned(field, kept, options, symbols)
    : fill(preview?.password ? preview : await preparePassword(field, { symbols, options }), null);
  if (pending.closed || genOptions !== pending) return;
  const fromButton = !keyboard;
  const startPassword = field.value;
  const card = showGeneratorOptions(field, {
    options,
    symbols: current.symbols,
    limits,
    current,
    focus: keyboard,
    generate: async (next, nextSymbols) => fill(await preparePassword(field, { symbols: nextSymbols, options: next }), next),
    onClose: ({ reason, password }) => {
      if (genOptions?.card === card) genOptions = null;
      menu?.setOptionsOpen(false);
      if (reason === 'gone' || reason === 'typed' || reason === 'reopened' || reason === 'regenerated') return;
      // Saved like the button's own: one filled or changed here (a draft saved before gets the change).
      const changed = password !== startPassword;
      const save = changed ? fromButton || !!draft : fromButton && !keptHere;
      if (password && field.value === password && save) saveDraft(password, group).catch(() => {});
      if (reason === 'outside') return;
      try { field.focus({ preventScroll: true }); } catch { /* gone */ }
      if (deepActiveElement() === field) revealGenerated(field, password);
    },
  });
  genOptions = { field, card, close: (reason) => card.close(reason), get closed() { return card.closed; } };
  menu?.setOptionsOpen(true);
}

function planned(field, kept, options, symbols) {
  const plan = planFor(options, passwordLimitsOf(field), symbols);
  const result = { password: kept.password, mode: kept.mode || 'password', words: kept.words };
  return { ...result, symbols: kept.symbols ?? plan.symbols, notes: plan.notes, ...strengthOf(result) };
}

// Saved right away so a sign-up that fails half-way never loses it; the form's submit updates it.
async function saveDraft(password, group) {
  const username = group?.username?.value?.trim() || '';
  const kind = group?.currentPassword ? 'change' : 'signup';
  let res;
  try {
    res = await bg('draft.save', { username, password, kind });
  } catch (err) {
    if (err.code === 'cancelled') return null;
    const later = t('toastFilledSaveLater');
    showNotice(err.code === 'not_supported' || err.code === 'agent_unavailable' ? later : t('toastFilledNotSaved', errorMessage(err)));
    return null;
  }
  draft = { id: res.id };
  draftToast?.close();
  draftToast = showActionToast({
    text: res.created ? t('toastDraftSaved') : t('toastDraftUpdated'),
    detail: kind === 'change' ? t('toastDraftChangeDetail') : null,
    action: t('commonUndo'),
    onAction: async (toastUi) => {
      try {
        await bg('draft.undo', { id: draft?.id });
        draft = null;
        toastUi.done(t('toastDraftRemoved'));
      } catch (err) {
        toastUi.done(errorMessage(err));
      }
    },
    onClose: () => { draftToast = null; },
  });
  return res;
}

function onContextMenu(e) {
  if (!e.isTrusted) return;
  const target = e.composedPath ? e.composedPath()[0] : e.target;
  lastContext = { at: Date.now(), target };
  reportMenuTarget(target);
}

// Report on press, before the browser builds its context menu.
function onRightPress(e) {
  if (!e.isTrusted || e.button !== 2) return;
  reportMenuTarget(e.composedPath ? e.composedPath()[0] : e.target);
}

function reportMenuTarget(target) {
  if (!contextAlive()) return;
  bg('menu.target', { password: isPasswordField(target), username: isUsernameField(target) }).catch(() => {});
}

function isUsernameField(el) {
  if (!el || el.tagName !== 'INPUT' || !isFillableInput(el) || isPasswordField(el)) return false;
  if (fieldInfo(el)?.kind === FieldKind.USERNAME) return true;
  if ((el.getAttribute('type') || '').toLowerCase() === 'email') return true;
  return /\b(?:username|email)\b/i.test(el.getAttribute('autocomplete') || '');
}

function isPasswordField(el) {
  if (!el || el.tagName !== 'INPUT' || !isFillableInput(el)) return false;
  if ((el.getAttribute('type') || '').toLowerCase() === 'password') return true;
  const kind = fieldInfo(el)?.kind;
  return kind === FieldKind.NEW_PASSWORD || kind === FieldKind.CURRENT_PASSWORD;
}

function contextTarget(accept) {
  let el = Date.now() - lastContext.at < CONTEXT_TTL_MS ? lastContext.target : null;
  if (!el?.isConnected) el = deepActiveElement();
  return accept(el) ? el : null;
}

function passwordTarget() {
  return contextTarget(isPasswordField);
}

/** `kind`: 'username' | 'alias'. An alias service can be slow. Nothing is saved here. */
async function commandGenerateUsernameHere(kind) {
  rescanNow();
  const target = contextTarget(isUsernameField);
  if (!target) return false;
  const busy = kind === 'alias' ? showNotice(t('commonCreatingAlias'), 90_000) : null;
  let value;
  try {
    value = kind === 'alias' ? (await bg('generate.email', { kind: 'alias' }))?.email : (await bg('generate.username'))?.username;
  } catch (err) {
    busy?.close();
    if (err.code !== 'cancelled') showNotice(friendlyError(err, { context: 'generate' }));
    return false;
  }
  busy?.close();
  if (typeof value !== 'string' || !value) return false;
  return fillInput(target, value);
}

// Context menu (`symbols` false: letters and numbers only) or shortcut (`focused`). With no password
// field it answers false and the background copies a password instead.
async function commandGenerateHere(symbols, { focused = false } = {}) {
  rescanNow();
  const active = focused ? deepActiveElement() : null;
  const target = focused ? (isPasswordField(active) ? active : null) : passwordTarget();
  if (!target) return false;
  const made = await preparePassword(target, { symbols });
  const { password } = made;
  const group = groupOf(target);
  // Only a choice the user made becomes the site's default (the shortcut follows it).
  fillGenerated(password, group, target, { onlyField: true, symbols, made });
  await saveDraft(password, group);
  return true;
}

/** "Fill on this page" for another site's login: the desktop app asks first, showing this frame's URL. */
async function commandFillCross(id) {
  rescanNow();
  const target = targetGroup();
  if (!target?.field) { showNotice(t('commonNoLoginForm')); return false; }
  let creds;
  try {
    creds = await bg('logins.fill_cross', { id });
  } catch (err) {
    if (err.code !== 'cancelled') showNotice(errorMessage(err));
    return false;
  }
  let result;
  if (target.group) result = fillLoginGroup(target.group, creds, { field: target.focused ? target.field : null });
  else result = { username: usernameScore(target.field) > 0 && fillInput(target.field, creds.username), password: false };
  if (!creds.cross) bg('fill.done', { id, otp: !!result.otp }).catch(() => {});
  return !!(result.username || result.password);
}

// `picked`: the user chose it for `field`, so even a new-password field gets the password; automatic
// fills never put a stored password into a sign-up form.
async function fillLogin(id, group, field, { picked = false } = {}) {
  const creds = await bg('logins.fill', { id });
  let result;
  if (group) {
    result = fillLoginGroup(group, creds, { field: picked ? field : null });
  } else {
    // The page changed under the menu: fill only a field that still looks like a username.
    result = { username: false, password: false, otp: false };
    if (field && usernameScore(field) > 0) result.username = fillInput(field, creds.username);
  }
  bg('fill.done', { id, otp: !!result.otp }).catch(() => {});
  if (result.otp) { otpHandled = true; otpFilled = true; } else if (creds.totp?.code) expectOtpStep(id, group, !!creds.skips_2fa);
  return result;
}

// Many sites show the 2FA step in the same document without a navigation, so after a fill whose code
// had nowhere to go the pending code is offered from here on. `quiet`: the site usually skips 2FA
// (`skips_2fa`), so only a code field that shows up gets it.
function expectOtpStep(id, group, quiet = false) {
  otpCtx = { ...(otpCtx || {}), pending: { id, title: otpCtx?.pending?.title || '' }, offer: true, late: false, quiet };
  otpHandled = false;
  otpFilled = false;
  otpAutoTries = 0;
  otpSkipped = false;
  otpAskReported = false;
  navStartedAt = Date.now();
  signInField = group?.currentPassword || group?.passwords?.[0]?.el || null;
}

function signInStillShown() {
  return !!signInField && signInField.isConnected && isVisible(signInField);
}

async function fillOtp(id, entry) {
  const code = await bg('totp.get', id ? { id } : {});
  if (entry && fillOtpEntry(entry, code.code)) {
    otpHandled = true;
    otpFilled = true;
    toast?.close();
    bg('otp.consumed', { id: code.id || id }).catch(() => {});
    return true;
  }
  showToastFor(code);
  return false;
}

async function loadOtpContext(navigation) {
  otpCtxRequested = true;
  try {
    otpCtx = await bg('otp.context', { navigation });
  } catch {
    otpCtx = null;
  }
  evaluateOtp();
}

function evaluateOtp() {
  if (!otpCtx) return;
  const entry = firstOtpEntry();
  if (entry && !otpFieldReported) {
    otpFieldReported = true;
    bg('otp.field-seen').catch(() => {});
  }
  const now = Date.now();
  const elapsed = now - navStartedAt;
  const settled = now - Math.max(navStartedAt, lastSubmitAt);
  const offer = !!otpCtx.offer && !otpHandled;
  // Only read while a code is on offer: innerText forces layout.
  const wording = offer && !entry ? stepWording() : false;
  const loginPath = offer && !entry ? looksLikeLoginPath(location.href) : false;
  // Off a sign-in URL the wording must be near an input or frame: an inbox or help page is no 2FA step.
  const pageLooks2fa = wording && !signInStillShown() && (loginPath || wordingNearInput());
  if (offer && (entry || pageLooks2fa) && !otpAskReported) {
    otpAskReported = true;
    bg('otp.outcome', { outcome: 'asked' }).catch(() => {});
  }
  const action = decideOtpAction({
    offer,
    hasOtpField: !!entry,
    autoFillOtp: !!settings.autoFillOtp,
    canAutoFill: sameOriginAsTop(),
    elapsedMs: elapsed,
    settledMs: settled,
    pageLooks2fa,
    signedIn: offer && !entry && looksSignedIn({ hasOtpField: false, wording, passwordShown: passwordShown(), loginPath }),
    isTopFrame: isTop,
    otpFieldElsewhere: !!otpCtx.otpFieldElsewhere,
    toastShown: !!toast,
    quiet: !!otpCtx.quiet,
    skipped: otpSkipped,
    late: !!otpCtx.late,
  });
  switch (action) {
    case 'autofill':
      otpHandled = true;
      // Retried on later scans (the agent may have been busy), but not forever.
      fillOtp(null, entry).catch(() => { if (++otpAutoTries < 3) otpHandled = false; });
      break;
    case 'skipped':
      // Signed in without a 2FA step. A code field that still shows up gets the code.
      otpSkipped = true;
      clearTimeout(otpTimer);
      otpTimer = 0;
      bg('otp.outcome', { outcome: 'skipped' }).catch(() => {});
      break;
    case 'offer': {
      otpHandled = true;
      const field = entry.fields[0];
      if (!settings.inlineMenu) {
        // After the agent's window (`late`) ask by item; `automatic`: never an unlock prompt on page load.
        bg('totp.get', otpCtx.late && otpCtx.pending?.id ? { id: otpCtx.pending.id, automatic: true } : {}).then(showToastFor, () => {});
        break;
      }
      const active = deepActiveElement();
      if (!active || active === document.body || active === document.documentElement) {
        try { field.focus({ preventScroll: false }); } catch { /* ignore */ }
      }
      ensureMenu().showIcon(field);
      openMenu(field, { auto: true });
      break;
    }
    case 'toast':
      otpHandled = true;
      bg('totp.get').then(showToastFor, () => {});
      break;
    case 'wait':
      if (!otpTimer) {
        // Re-check when the toast delay or skip check is due, else every 2 s.
        let next = 2000;
        if (elapsed < TOAST_DELAY_MS) next = TOAST_DELAY_MS - elapsed + 50;
        else if (settled < SKIP_DETECT_MS) next = Math.min(next, SKIP_DETECT_MS - settled + 50);
        otpTimer = setTimeout(() => { otpTimer = 0; textGen++; evaluateOtp(); }, next);
      }
      break;
    default:
  }
}

function visibleInputCount() {
  let n = 0;
  for (const el of collectInputs(document)) if (isFillableInput(el) && !isOwnNode(el) && isVisible(el)) n++;
  return n;
}

// On a long page (inbox, chat, forum, help article) the wording only counts next to an input or frame.
function stepWording() {
  const text = pageText();
  if (!looksLike2faPage(text)) return false;
  return text.length <= SHORT_PAGE_TEXT || wordingNearInput();
}

// Cached per scan.
let nearWordingCache = { gen: -1, value: false };
function wordingNearInput() {
  if (nearWordingCache.gen === textGen) return nearWordingCache.value;
  let value = false;
  let checked = 0;
  for (const el of [...collectInputs(document), ...document.querySelectorAll('textarea, iframe')]) {
    if (checked >= 30) break;
    if ((el.tagName === 'INPUT' && !isFillableInput(el)) || isOwnNode(el) || !isVisible(el)) continue;
    checked++;
    if (contextLooksLike2fa(nearText(el))) { value = true; break; }
  }
  nearWordingCache = { gen: textGen, value };
  return value;
}

function passwordShown() {
  return scan.groups.some((g) => !g.quiet && g.passwords.some((p) => p.el && isVisible(p.el)));
}

function showToastFor(code) {
  if (!code?.code) return;
  toast?.close();
  toast = showOtpToast({
    title: code.title,
    initial: code,
    // Next code when the period rolls over. `automatic`: never an unlock prompt for it.
    refresh: () => bg('totp.get', { id: code.id, automatic: true }),
    onShowDesktop: () => bg('totp.popup', { id: code.id }),
    // The desktop app keeps its copy out of clipboard history and the cloud clipboard.
    copyByApp: () => bg('totp.copy', { id: code.id }),
    onCopy: (copied) => {
      bg('otp.consumed', { id: code.id }).catch(() => {});
      // Copied by the extension (older desktop app): cleared after 45 s.
      if (copied) bg('clipboard.copied', { value: copied }).catch(() => {});
    },
    onClose: () => { toast = null; },
    ttlMs: PENDING_OTP_WINDOW_MS,
  });
}

async function commandFillLogin() {
  rescanNow();
  // Card or address field: open its menu, never fill on its own.
  const active = deepActiveElement();
  const form = active?.tagName === 'INPUT' ? formInfo(active) : null;
  if (form) {
    if (!(await formFeatures())[FORM_METHODS[form.type].feature]) { showNotice(t('menuFormsNeedUpdate')); return; }
    ensureMenu().showIcon(active);
    openMenu(active, { force: true, user: 'command' });
    return;
  }
  const target = targetGroup();
  const field = target?.field;
  let data;
  try {
    data = await bg('logins.find');
  } catch (err) {
    if (field && err.code === 'locked') { openMenu(field, { force: true, user: 'command' }); return; }
    showNotice(errorMessage(err));
    return;
  }
  const items = data.items || [];
  if (!field) {
    showNotice(items.length ? t('commonNoLoginForm') : t('errNotFound'));
    return;
  }
  if (target.group?.otp && !target.group.username && !target.group.passwords.length) {
    await commandFillOtp();
    return;
  }
  if (items.length === 1) {
    await fillLogin(items[0].id, target.group, field, { picked: !!target.focused });
  } else {
    ensureMenu().showIcon(field);
    openMenu(field, { force: true, user: 'command' });
  }
}

async function commandFillOtp() {
  rescanNow();
  const entry = otpEntryForCommand();
  let data;
  try {
    data = await bg('logins.find');
  } catch (err) {
    showNotice(errorMessage(err));
    return;
  }
  const decision = decideShortcutAction({ hasOtpField: !!entry, pending: data.pending_otp, items: data.items });
  if (!decision) { showNotice(t('noticeNoOtp')); return; }
  try {
    if (decision.action === 'fill') await fillOtp(decision.id, entry);
    else showToastFor(await bg('totp.get', { id: decision.id }));
  } catch (err) {
    showNotice(errorMessage(err));
  }
}

async function commandFillItem(id) {
  rescanNow();
  const target = targetGroup();
  if (!target) return false;
  const r = await fillLogin(id, target.group, target.field, { picked: !!target.focused });
  return r.username || r.password;
}

function onRuntimeMessage(msg, sender, sendResponse) {
  if (quiet || sender.id !== ext.runtime.id || !msg || typeof msg.type !== 'string') return false;
  const run = {
    'cmd.fill-login': () => commandFillLogin(),
    'cmd.fill-otp': () => commandFillOtp(),
    'cmd.fill-item': () => commandFillItem(String(msg.id)),
    // The keyboard shortcut (`focused`): the focused field and the site's choice; the context menu: its item's.
    'cmd.generate-here': () => (msg.focused === true ? commandGenerateHere(undefined, { focused: true }) : commandGenerateHere(msg.symbols !== false)),
    'cmd.generate-username-here': () => commandGenerateUsernameHere(msg.kind === 'alias' ? 'alias' : 'username'),
    'cmd.fill-cross': () => commandFillCross(String(msg.id)),
    'save.recheck': () => recheckSaveBanner(),
    'cross.offer': () => checkCrossBanner(),
    // A card was submitted in this tab, or the vault was just unlocked for one (background/card-save.js).
    'card.offer': () => checkCardBanner(msg.recheck === true),
    // A copy's outcome after Windows Hello or the app's prompt closed the popup: plain text, top frame only.
    'cmd.notice': () => {
      if (window !== window.top || typeof msg.text !== 'string' || !msg.text) return false;
      showNotice(msg.text.slice(0, 300));
    },
    lock_state: async () => {
      formSupport = null;
      // Locked: no 2FA code or password stays on screen.
      if (msg.locked === true) { toast?.close(); generatedReveal?.close(); }
      passkeyFlow?.lockChanged(msg.locked === true);
      passkeyOfferLockChanged();
      if (msg.locked === false && pendingUnlock && await completePendingUnlock()) return;
      if (msg.locked === false && resumeSuggest('unlock')) return;
      if (menu?.isOpen && menu.field) openMenu(menu.field, { force: true, passive: menuPassive, showAll: !!menuModel?.showAll });
    },
  }[msg.type];
  if (!run) return false;
  Promise.resolve().then(run).then((v) => sendResponse({ ok: v !== false }), (err) => sendResponse({ ok: false, error: { code: err.code || 'internal', message: err.message, reason: err.reason ?? (err.code ? undefined : 'unexpected') } }));
  return true;
}

function groupNear(el) {
  const form = el.closest?.('form');
  const inForm = form && scan.groups.find((g) => g.form === form);
  if (inForm) return inForm;
  const containing = scan.groups.find((g) => g.container?.contains(el) && (g.passwords.length || g.username));
  if (containing) return containing;
  const withPw = scan.groups.filter((g) => g.passwords.length);
  return withPw.length === 1 ? withPw[0] : null;
}

let lastCapture = { at: 0, sig: '' };
let goneTimer = 0;
// Same-document (fetch/XHR) sign-ins: the banner shows once the form is gone; slow back ends take seconds.
const GONE_CHECKS_MS = [800, 1700, 3000, 5000, 8000, 12000];

function captureGroup(group) {
  if (!settings.saveBanner || !group) return;
  const pwEl = group.newPasswords[0] || group.currentPassword || group.passwords[0]?.el;
  const username = group.username?.value?.trim() || '';
  if (!pwEl) {
    if (username && !group.otp) bg('save.capture', { username }).catch(() => {});
    return;
  }
  const gen = activeGenerated();
  const genHere = !!gen && gen.fields.some((el) => el === pwEl || group.newPasswords.includes(el));
  // A post or page password is not a login, unless Passyble generated it.
  if (group.quiet && !genHere) return;
  let password = pwEl.value;
  // Some sign-up scripts clear or re-render the field before submitting: use the generated password.
  if (!password && genHere) password = gen.password;
  if (!password) return;
  const usedGenerated = genHere && password === gen.password;
  if (!group.newPasswords.length && !usedGenerated && wasFilledByPass(pwEl)) return; // unchanged Passyble fill
  let kind = group.newPasswords.length ? (group.currentPassword ? 'change' : 'signup') : 'login';
  if (usedGenerated && kind === 'login') kind = 'signup';
  const sig = `${username}\u0000${password.length}\u0000${kind}`;
  if (sig === lastCapture.sig && Date.now() - lastCapture.at < 1500) return; // click + submit duplicates
  lastCapture = { at: Date.now(), sig };
  if (usedGenerated) generated = null; // the background has it now
  const capture = { username, password, kind };
  const canonical = canonicalUrl();
  if (canonical) capture.canonical = canonical;
  bg('save.capture', capture).catch(() => {});
  if (isTop) watchFormGone(pwEl);
}

/** Canonical URL, top frame of an https page only; the agent decides whether that host may share the login. */
function canonicalUrl() {
  if (!isTop || location.protocol !== 'https:') return '';
  for (const link of document.head?.querySelectorAll('link[rel][href]') || []) {
    if (!String(link.getAttribute('rel')).toLowerCase().split(/\s+/).includes('canonical')) continue;
    const href = link.href;
    return typeof href === 'string' && href.startsWith('https://') && href.length <= 2048 ? href : '';
  }
  return '';
}

function watchFormGone(pwEl) {
  clearTimeout(goneTimer);
  const since = Date.now();
  let i = 0;
  const check = () => {
    goneTimer = 0;
    if (!pwEl.isConnected || !isVisible(pwEl)) { checkSaveBanner(true); return; }
    if (++i < GONE_CHECKS_MS.length) goneTimer = setTimeout(check, Math.max(0, GONE_CHECKS_MS[i] - (Date.now() - since)));
  };
  goneTimer = setTimeout(check, GONE_CHECKS_MS[0]);
}

function onSubmit(e) {
  if (!e.isTrusted) return;
  lastSubmitAt = Date.now();
  newStep();
  const form = e.composedPath()[0];
  rescanNow();
  captureGroup(scan.groups.find((g) => g.form === form) || groupNear(form));
  captureCard(form);
}

function onClick(e) {
  if (!e.isTrusted || e.button !== 0) return;
  const el = e.composedPath()[0];
  const btn = el?.closest?.('button, input[type=submit], input[type=image], input[type=button], [role=button], a');
  if (!btn) return;
  const type = (btn.getAttribute('type') || '').toLowerCase();
  const text = `${btn.textContent || ''} ${btn.getAttribute('value') || ''} ${btn.getAttribute('aria-label') || ''} ${btn.id || ''} ${btn.getAttribute('name') || ''}`;
  const submits = type === 'submit' || SUBMIT_TEXT_RE.test(text);
  // A card form's "Pay" / "Place order" button (often not a submit button): offer to save the card.
  if (submits || PAY_TEXT_RE.test(text)) captureCard(btn);
  if (!submits) return;
  lastSubmitAt = Date.now();
  // "Next" on an identifier-first sign-in: the password step's own focus is that step's initial one.
  if (!isOwnNode(e.target)) newStep();
  rescanNow();
  captureGroup(groupNear(btn));
}

function onKeyDown(e) {
  if (!e.isTrusted) return;
  lastInteractionAt = Date.now();
  if (e.key === 'Tab') recordGesture(e);
  const field = eventField(e);
  if (menu?.isOpen && field === menu.field) {
    // Typing means "no thanks" to a menu that opened on its own; a username field's menu filters instead.
    if (menuAutoField === field && !e.ctrlKey && !e.metaKey && !e.altKey &&
        (e.key.length === 1 || e.key === 'Backspace' || e.key === 'Delete')) {
      if (fieldInfo(field)?.kind !== FieldKind.USERNAME) closeAutoMenu();
      return;
    }
    if (menu.handleKey(e)) { e.preventDefault(); e.stopPropagation(); return; }
  }
  if (!field) return;
  const info = fieldInfo(field);
  if (!info) {
    if (e.key === 'Enter') captureCard(field);
    // A card or address field with the Passyble icon: ↓ opens its menu too.
    if (e.key === 'ArrowDown' && settings.inlineMenu && !menu?.isOpen && menu?.iconField === field &&
        (e.altKey || !field.value) && formInfo(field)) {
      e.preventDefault();
      openMenu(field, { user: 'key' });
    }
    return;
  }
  if (e.key === 'Enter') {
    lastSubmitAt = Date.now();
    newStep();
    captureGroup(info.group);
  } else if (e.key === 'ArrowDown' && settings.inlineMenu && !menu?.isOpen && (e.altKey || !field.value)) {
    e.preventDefault();
    openMenu(field, { user: 'key' });
  }
}

async function checkSaveBanner(sameDocument) {
  if (!isTop || !settings.saveBanner) return;
  // A login form still shown after load usually means a failed sign-in (sign-ups are still offered).
  const loginFormVisible = !sameDocument && scan.groups.some((g) => !g.quiet && g.currentPassword && !g.newPasswords.length && isVisible(g.currentPassword));
  let info;
  try { info = await bg('save.query', loginFormVisible ? { sameDocument, loginFormVisible } : { sameDocument }); } catch { return; }
  if (info?.cross) openCrossBanner(info.cross);
  else if (info?.changed) openChangedBanner(info.changed);
  else if (info?.autosaved) showAutoSaved(info);
  else if (info) openSaveBanner(info);
}

/** "Update this login?" after the user changed a Passyble fill; by the card's one-time token only. */
function openChangedBanner(info) {
  if (!info || typeof info.token !== 'string') return;
  crossBanner?.close();
  crossBanner = null;
  saveBanner?.close();
  const pending = pendingUi();
  saveBanner = pending;
  loadBanner().then(({ showChangedBanner }) => {
    if (pending.closed || saveBanner !== pending) return;
    saveBanner = showChangedBanner({
      ...info,
      onUpdate: () => bg('changed.update', { token: info.token }),
      onSaveNew: () => bg('changed.save', { token: info.token }),
      onDismiss: () => { bg('changed.dismiss', { token: info.token }).catch(() => {}); },
    });
  }).catch(() => { if (saveBanner === pending) saveBanner = null; });
}

let crossBanner = null; // { close } of the card on screen

async function checkCrossBanner() {
  if (!isTop || !settings.saveBanner) return;
  let info;
  try { info = await bg('cross.query'); } catch { return; }
  if (info) openCrossBanner(info);
}

/** The card after a cross fill; it holds only its one-time token, the background has the rest. */
function openCrossBanner(info) {
  if (!info || typeof info.token !== 'string') return;
  saveBanner?.close();
  saveBanner = null;
  crossBanner?.close();
  const pending = pendingUi();
  crossBanner = pending;
  loadBanner().then(({ showCrossBanner }) => {
    if (pending.closed || crossBanner !== pending) return;
    crossBanner = showCrossBanner({
      ...info,
      onAdd: () => bg('cross.add', { token: info.token }),
      onCopy: () => bg('cross.copy', { token: info.token }),
      onDismiss: () => { bg('cross.dismiss', { token: info.token }).catch(() => {}); },
    });
  }).catch(() => { if (crossBanner === pending) crossBanner = null; });
}

/** After an unlock (`save.recheck`): the banner held back while locked, or closing one already saved. */
async function recheckSaveBanner() {
  if (!isTop || !settings.saveBanner) return;
  let info;
  try { info = await bg('save.query', { recheck: true }); } catch { return; }
  if (!info) return;
  if (info.cross) { openCrossBanner(info.cross); return; }
  if (info.close) {
    saveBanner?.close();
    saveBanner = null;
    if (info.autosaved) showAutoSaved(info);
    return;
  }
  if (info.autosaved) showAutoSaved(info);
  else openSaveBanner(info);
}

function showAutoSaved(info) {
  const updated = info.autosaved === 'updated';
  draftToast?.close();
  draftToast = showActionToast({
    text: updated ? t('toastAutoUpdated') : t('toastDraftSaved'),
    action: t('commonUndo'),
    onAction: async (toastUi) => {
      try {
        await bg('save.undo', { token: info.token });
        toastUi.done(updated ? t('toastAutoRestored') : t('toastDraftRemoved'));
      } catch (err) {
        toastUi.done(errorMessage(err));
      }
    },
    onClose: () => { draftToast = null; },
  });
}

let saveBanner = null; // { close }

function openSaveBanner(info) {
  saveBanner?.close();
  const pending = pendingUi();
  saveBanner = pending;
  loadBanner().then(({ showSaveBanner }) => {
    if (pending.closed || saveBanner !== pending) return;
    saveBanner = showSaveBanner({
      ...info,
      // The token only: the edit frame handed the edits to the background; no password passes through here.
      onSave: (vault) => bg('save.commit', { token: info.token, ...(typeof vault === 'string' && vault ? { vault } : {}) }),
      // The password check of what Save would save now (edits included), through the background (codes only).
      onCheck: () => bg('save.check', { token: info.token }),
      onDismiss: () => { bg('save.dismiss').catch(() => {}); },
      // The background stores the site of the form's frame from the browser's sender info.
      onNever: () => bg('save.never', { token: info.token }),
    });
  }).catch(() => { if (saveBanner === pending) saveBanner = null; });
}

let lastCardCapture = { at: 0, sig: '' };
let cardBanner = null; // { close } of the card banner on screen

// Number, expiry and holder go to the background, never the security code; only in the top frame or a
// frame of the top page's origin, on secure pages.
function captureCard(el) {
  if (settings.cardSave === false) return;
  const card = captureCardFrom(el, { root: document, win: window, isVisible });
  if (!card) return;
  const sig = `${card.number.slice(-4)}\u0000${card.expiry_month}\u0000${card.expiry_year}`;
  if (sig === lastCardCapture.sig && Date.now() - lastCardCapture.at < 1500) return; // click + submit
  lastCardCapture = { at: Date.now(), sig };
  bg('card.capture', card).catch(() => {});
}

async function checkCardBanner(recheck = false) {
  if (!isTop || settings.cardSave === false) return;
  let info;
  try { info = await bg('card.query', recheck ? { recheck: true } : {}); } catch { return; }
  if (info?.close === true) { cardBanner?.close(); cardBanner = null; return; }
  if (typeof info?.token !== 'string' || !info.token || !/^\d{4}$/.test(String(info.last4 ?? ''))) return;
  openCardBanner(info);
}

function openCardBanner(info) {
  cardBanner?.close();
  const pending = pendingUi();
  cardBanner = pending;
  const exp = { expiry_month: info.expiry_month, expiry_year: info.expiry_year };
  const label = cardSummary({ brand: info.brand, last4: info.last4, ...exp });
  const update = info.mode === 'update';
  loadBanner().then(({ showSaveBanner }) => {
    if (pending.closed || cardBanner !== pending) return;
    cardBanner = showSaveBanner({
      mode: update ? 'update' : 'save',
      host: info.host,
      username: '',
      token: info.token,
      editable: info.editable === true,
      title: info.title ?? null,
      vaults: info.vaults ?? null,
      vault_name: info.vault_name ?? null,
      editPath: 'src/save/card-edit.html',
      labels: {
        heading: t(update ? 'cardBannerUpdate' : 'cardBannerSave'),
        done: t(update ? 'cardBannerUpdated' : 'cardBannerSaved'),
        who: update && info.title ? `${info.title} · ${label.split(' · ').slice(1).join(' · ') || label}` : label,
        // The security code is never saved: the user can add it to the card in Passyble.
        note: update ? '' : t('cardBannerNoCode'),
        neverDone: t('cardBannerNeverDone'),
        results: { update_expiry: t('cardBannerUpdated'), save_new: t('cardBannerSaved') },
        frameTitle: t('cardBannerEditFrameTitle'),
      },
      onSave: (vault) => bg('card.commit', { token: info.token, ...(typeof vault === 'string' && vault ? { vault } : {}) }),
      onDismiss: () => { bg('card.dismiss', { token: info.token }).catch(() => {}); },
      onNever: () => bg('card.never', { token: info.token }),
    });
  }).catch(() => { if (cardBanner === pending) cardBanner = null; });
}

const listeners = [];
function listen(target, type, fn, opts) {
  target.addEventListener(type, fn, opts);
  listeners.push(() => target.removeEventListener(type, fn, opts));
}

export function stop() {
  teardown();
}

function teardown() {
  observer?.disconnect();
  dropUnlockFrame();
  listeners.splice(0).forEach((off) => off());
  menu?.destroy();
  toast?.close();
  generatedReveal?.close();
  genOptions?.close('gone');
  genOptions = null;
  draftToast?.close();
  saveBanner?.close();
  saveBanner = null;
  cardBanner?.close();
  cardBanner = null;
  dropPasskeyOffer();
  passkeyFlow?.stop();
  clearTimeout(otpTimer);
  clearTimeout(scanTimer);
  clearTimeout(goneTimer);
  clearTimeout(recheckTimer);
  clearSuggestWait();
  undetectedFocus = null;
  generated = null;
  draft = null;
}

export async function start() {
  if (started || quiet) return;
  started = true;
  if (!/^https?:$/.test(location.protocol) || opaqueOrigin()) return;
  // Below the minimum extension version: do nothing until the block is lifted.
  if (await extensionBlocked(ext)) {
    started = false;
    if (!awaitingUnblock) {
      awaitingUnblock = true;
      const off = onExtensionBlockedChange((blocked) => {
        if (blocked) return;
        off();
        awaitingUnblock = false;
        start();
      }, ext);
    }
    return;
  }
  settings = await getSettings();
  // A block while the page is open stops everything until reload.
  listeners.push(onExtensionBlockedChange((blocked) => {
    if (!blocked || quiet) return;
    quiet = true;
    teardown();
  }, ext));
  onSettingsChanged((s) => {
    if (quiet) return;
    settings = s;
    formSupport = null;
    if (!s.inlineMenu) menu?.destroy();
    if (!s.autoGenerate) closeAutoMenu();
    if (!s.passkeys) dropPasskeyOffer();
    else if (!s.autoPasskey) passkeyOffer?.prompt?.close();
    else if (passkeyOffer?.items && (!passkeyOffer.prompt || passkeyOffer.prompt.closed)) showPasskeyOffer(passkeyOffer);
    else refreshPasskeyOffer().catch(() => {});
    if (!formsWanted()) {
      forms = NO_FORMS;
      if (menu?.isOpen && (menuModel?.view === 'card' || menuModel?.view === 'identity')) menu.close();
      if (menu?.iconField && !fieldInfo(menu.iconField)) menu.hideIcon();
    }
  });
  ext.runtime.onMessage.addListener(onRuntimeMessage);

  listen(document, 'focusin', (e) => {
    const field = eventField(e);
    if (!field) return;
    // An SPA navigation (pushState) the scan hasn't seen yet starts a new step before this focus.
    checkSpaNavigation();
    if (!scan.fields.has(field)) rescanNow();
    onFocusIn(field);
  }, true);
  listen(window, 'popstate', () => checkSpaNavigation());
  listen(window, 'hashchange', () => checkSpaNavigation());
  listen(document, 'visibilitychange', onVisibilityChange);
  listen(document, 'keydown', onKeyDown, true);
  for (const type of ['pointerdown', 'mousedown', 'touchstart']) listen(window, type, recordGesture, { capture: true, passive: true });
  listen(document, 'input', (e) => {
    if (!e.isTrusted) return;
    const field = eventField(e);
    if (field && refilterMenu(field)) return;
    if (menuAutoField && field === menuAutoField) closeAutoMenu();
  }, true);
  listen(document, 'submit', onSubmit, true);
  listen(document, 'click', onClick, true);
  listen(document, 'click', onFieldClick, true);
  listen(document, 'contextmenu', onContextMenu, true);
  listen(window, 'mousedown', onRightPress, { capture: true, passive: true });
  listen(window, 'pagehide', () => { menu?.close(); });
  listen(window, 'message', onFrameMessage);

  const offConditional = globalThis.__passBridge?.onConditionalChange((pending) => {
    const active = deepActiveElement();
    if (pending && active && scan.fields.has(active)) onFieldFocus(active);
    refreshPasskeyOffer().catch(() => {});
  });
  if (offConditional) listeners.push(offConditional);
  passkeyFlow = createPasskeyFlow({
    bg,
    bridge: () => globalThis.__passBridge,
    onCardShown: () => {
      if (passkeyOffer?.prompt && !passkeyOffer.busy) {
        passkeyOffer.prompt.close();
        passkeyOffer.prompt = null;
      }
    },
  });
  const bridge = globalThis.__passBridge;
  if (typeof bridge?.onModalRequest === 'function') {
    listeners.push(bridge.onModalRequest((info) => (settings.passkeys ? passkeyFlow.handle(info) : false)));
    listeners.push(bridge.onModalChange(() => passkeyFlow.changed()));
  }

  rescanNow();
  startObserver();
  // A field focused before Passyble started gets no focus event; its focus counts as the page's.
  visibleSince();
  const active = deepActiveElement();
  if (active?.tagName === 'INPUT' && isSignInInfo(scan.fields.get(active))) stepFocusSeen = true;
  if (active && scan.fields.has(active)) onFieldFocus(active, { initial: true });
  if (isTop) checkSaveBanner(false);
  if (isTop) checkCardBanner();
  refreshPasskeyOffer().catch(() => {});
}
