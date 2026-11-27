// Popup login editor: edit, add or delete a login of the current site, or open it in Passyble.
// Requests go through the background (`popup.edit-*`), which takes the page from the tab. The password and
// any scanned 2FA secret live only in this page and the form, and are cleared when the editor closes.
import { icon } from '../shared/svg-icon.js';
import { openMenu, closeMenu, menuIsOpen } from '../ui/popover.js';
import { friendlyError } from '../shared/messages.js';
import { isPlainPassword, MIN_LENGTH, PASSPHRASE_MIN_WORDS, wordsOf } from '../shared/generator.js';
import { cleanOptions, generatorOptions, prefersNoSymbols, rememberOptions, rememberSymbols } from '../shared/generate-prefs.js';
import { agentCanMake, makeLocally, planFor } from '../content/generate-plan.js';
import { LENGTH_MAX, WORDS_MAX } from '../content/gen-options.js';
import { formatCode } from '../shared/otp-logic.js';
import { getSettings, setSettings } from '../shared/settings.js';
import { t } from '../shared/i18n.js';
import { CHECK_DEBOUNCE_MS, issueTexts, looksStrong, wantsStrongPassword } from '../shared/password-issues.js';
import { vaultName } from './vault-filter.js';
import { notesCounter } from './notes-counter.js';

/** A website's rule (Item.url_rules): `subdomains` is the default and is never sent as a rule. */
const RULES = ['subdomains', 'host', 'never'];
const RULE_BADGE = { host: 'editorRuleBadgeHost', never: 'editorRuleBadgeNever' };

const CHAR_TYPES = [['uppercase', 'A-Z', 'genUppercase'], ['lowercase', 'a-z', 'genLowercase'], ['digits', '0-9', 'genDigits'],
  ['symbols', '!@#', 'genSymbols']];

let wordList = null;
/** The passphrase wordlist (62 KB), loaded the first time a passphrase is made here; null if it can't be. */
function passphraseWords() {
  wordList ??= import('../shared/passphrase-words.js').then((m) => wordsOf(m.PASSPHRASE_WORDS), () => { wordList = null; return null; });
  return wordList;
}

const SITE_DEBOUNCE_MS = 150;

function siteQuery(text) {
  return String(text || '').trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/^www\./i, '').split(/[/?#]/)[0].toLowerCase();
}

/** A saved login with a second website or a non-default website rule (the vault alone doesn't count). */
export function hasDetails(data) {
  if (!data?.id) return false;
  const urls = Array.isArray(data.urls) ? data.urls.filter((u) => String(u || '').trim()) : [];
  const rules = Array.isArray(data.url_rules) ? data.url_rules : [];
  return urls.length > 1 || rules.some((r) => RULES.includes(r?.rule) && r.rule !== 'subdomains');
}

function ruleOf(rules, url) {
  const rule = (Array.isArray(rules) ? rules : []).find((r) => r?.url === url)?.rule;
  return RULES.includes(rule) ? rule : 'subdomains';
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) node.append(c instanceof Node ? c : String(c));
  return node;
}

function iconButton(name, label, onclick, extra = {}) {
  return el('button', { class: 'icon-btn', type: 'button', title: label, 'aria-label': label, onclick, ...extra }, icon(name));
}

function textButton(name, label, onclick, extra = {}) {
  const { class: cls = 'ghost', ...rest } = extra;
  return el('button', { class: `btn ${cls}`.trim(), type: 'button', onclick, ...rest }, icon(name), el('span', {}, label));
}

function box(input, ...buttons) {
  input.classList.remove('input');
  return el('div', { class: 'ed-box' }, input, ...buttons);
}

function field(label, input, ...after) {
  if (!input.hasAttribute('aria-label')) input.setAttribute('aria-label', label);
  const control = input.tagName === 'TEXTAREA' ? input : box(input, ...after);
  return el('div', { class: 'ed-field' }, el('span', { class: 'ed-label', 'aria-hidden': 'true' }, label), control);
}

function hostOf(url) {
  try { return new URL(url).hostname; } catch { return ''; }
}

function originOf(url) {
  try { return new URL(url).origin; } catch { return ''; }
}

export function mountEditor(root, { send, request = send, tab, state, snack, onClose, setHeading = () => {}, tools = null, vaults = () => [] }) {
  let current = null; // { id|null, totp: {kind, info, value}, vault, targets } while open
  let timer = 0;
  let checkTimer = 0;
  let checkSeq = 0; // a check answered after a newer one started (or the editor closed) is dropped
  const inputs = {};
  const hints = new Map(); // website -> Promise of its sites.rule_hint
  let confirming = null; // "Move to a shared vault?" is up: its answer (Esc says no)
  let listSeq = 0;
  let nameTimer = 0;
  let nameSeq = 0; // a name answered after a newer website was typed is dropped
  const layers = []; // open over the form (the generator's options, a suggestion list): Esc closes the last first

  function drop(layer) {
    const at = layers.indexOf(layer);
    if (at >= 0) layers.splice(at, 1);
  }

  function clear() {
    clearInterval(timer);
    timer = 0;
    clearTimeout(checkTimer);
    checkSeq++;
    clearTimeout(nameTimer);
    nameSeq++;
    hints.clear();
    confirming = null;
    layers.length = 0;
    for (const input of root.querySelectorAll('input, textarea')) input.value = '';
    root.replaceChildren();
    closeMenu();
    tools?.replaceChildren();
    current = null;
    for (const k of Object.keys(inputs)) delete inputs[k];
  }

  function close(changed, info) {
    clear();
    onClose(changed, info);
  }

  /** `totp.kind`: 'none' | 'saved' (on the login, unchanged) | 'new' (scanned / pasted, saved on Save) | 'removed'. */
  function renderTotp() {
    const box = inputs.totpBox;
    clearInterval(timer);
    timer = 0;
    const totp = current.totp;
    const label = box.previousElementSibling;
    if (label?.classList.contains('ed-label')) label.hidden = !(totp.kind === 'saved' || totp.kind === 'new');
    if (totp.kind === 'saved' || totp.kind === 'new') {
      const info = totp.info || {};
      const name = [info.issuer, info.account].filter(Boolean).join(' · ');
      const codeEl = el('span', { class: 'ed-code' }, info.code ? formatCode(info.code) : '••• •••');
      const period = Number(info.period) || 30;
      const R = 5.5;
      const CIRC = 2 * Math.PI * R;
      const NS = 'http://www.w3.org/2000/svg';
      const ring = document.createElementNS(NS, 'svg');
      for (const [k, v] of Object.entries({ class: 'ring ed-ring', viewBox: '0 0 14 14', width: 14, height: 14 })) ring.setAttribute(k, String(v));
      const circle = (cls) => {
        const c = document.createElementNS(NS, 'circle');
        for (const [k, v] of Object.entries({ class: cls, cx: 7, cy: 7, r: R, fill: 'none', 'stroke-width': 2.2, 'stroke-linecap': 'round' })) c.setAttribute(k, String(v));
        return c;
      };
      const bar = circle('bar');
      bar.setAttribute('stroke-dasharray', CIRC.toFixed(2));
      ring.append(circle('track'), bar);
      const secs = el('span', { class: 'ed-secs', role: 'img' }, ring);
      secs.hidden = true;
      const refresh = iconButton('sync', t('editorShowCode'), () => refreshCode(), { hidden: true });
      let left = Number(info.remaining_secs) || 0;
      const tick = () => {
        if (left > 0) {
          const label = t('editorSecondsLeft', left);
          secs.title = label;
          secs.setAttribute('aria-label', label);
          secs.hidden = false;
          bar.setAttribute('stroke-dashoffset', (CIRC * (1 - left / period)).toFixed(2));
          bar.classList.toggle('low', left <= 5);
          left -= 1;
          return;
        }
        secs.hidden = true;
        codeEl.textContent = '••• •••';
        refresh.hidden = false;
        clearInterval(timer);
      };
      if (info.code) { tick(); timer = setInterval(tick, 1000); } else refresh.hidden = false;
      box.replaceChildren(el('div', { class: 'ed-totp' },
        el('div', { class: 'ed-totp-main' },
          el('div', { class: 'ed-row' }, codeEl, secs, refresh),
          el('div', { class: 'muted' }, totp.kind === 'new' ? (name ? t('editorTotpNewNamed', name) : t('editorTotpNew')) : name || t('editorTotpOn'))),
        iconButton('trash', t('editorRemoveTotp'), () => { current.totp = { kind: 'removed' }; renderTotp(); })));
      return;
    }
    const removed = totp.kind === 'removed';
    const add = textButton('plus', t('editorAddTotp'), () => showAdd(), { id: 'ed-totp-add' });
    box.replaceChildren(el('div', { class: 'ed-row' }, add,
      removed ? el('span', { class: 'ed-note' }, t('editorTotpRemoved')) : null));
  }

  async function refreshCode() {
    const totp = current?.totp;
    if (!totp) return;
    try {
      if (totp.kind === 'new') {
        totp.info = { ...totp.info, ...(await send('popup.totp-check', { tabId: tab().id, totp: totp.value })) };
      } else if (totp.kind === 'saved' && current.id) {
        const res = await send('popup.totp', { tabId: tab().id, id: current.id });
        totp.info = { ...totp.info, code: res.code, remaining_secs: res.remaining_secs };
      }
      renderTotp();
    } catch (err) {
      snack(friendlyError(err, { context: 'edit' }));
    }
  }

  function showAdd() {
    const box = inputs.totpBox;
    const secret = el('input', { id: 'ed-totp-secret', type: 'text', placeholder: t('editorSecretPlaceholder'), autocomplete: 'off', spellcheck: 'false',
      'aria-label': t('editorSecretLabel') });
    const addSecret = async () => {
      const value = secret.value.trim();
      if (!value) { secret.focus(); return; }
      try {
        const info = await send('popup.totp-check', { tabId: tab().id, totp: value });
        secret.value = '';
        current.totp = { kind: 'new', value, info };
        renderTotp();
      } catch (err) {
        snack(err.code === 'invalid_params' ? t('editorTotpInvalid') : friendlyError(err, { context: 'edit' }));
      }
    };
    secret.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); addSecret(); } });
    const scan = state()?.can_scan ? textButton('qr', t('editorScanQr'), () => scanQr(scan), { id: 'ed-totp-scan', class: '' }) : null;
    box.replaceChildren(el('div', { class: 'ed-totp-add' },
      scan,
      el('div', { class: 'ed-row' }, el('div', { class: 'ed-box' }, secret, iconButton('check', t('editorAdd'), addSecret, { id: 'ed-totp-ok' }),
        iconButton('close', t('commonCancel'), () => { secret.value = ''; renderTotp(); })))));
    (scan || secret).focus();
  }

  async function scanQr(button) {
    button.disabled = true;
    try {
      const res = await send('popup.totp-scan', { tabId: tab().id });
      const { totp, ...info } = res || {};
      if (!totp) throw Object.assign(new Error('No 2FA QR code found on this page.'), { code: 'not_found' });
      current.totp = { kind: 'new', value: totp, info };
      renderTotp();
    } catch (err) {
      snack(err.code === 'not_found' ? t('editorNoQr') : friendlyError(err, { context: 'edit' }));
      button.disabled = false;
    }
  }

  function urlRow(value = '', rule = 'subdomains') {
    const input = el('input', { type: 'text', class: 'ed-url', placeholder: 'example.com', autocomplete: 'off', spellcheck: 'false', 'aria-label': t('editorWebsite') });
    input.value = value;
    const badge = el('span', { class: 'ed-badge', hidden: true });
    const gear = current.rules
      ? iconButton('gear', t('editorRuleMenu'), () => ruleMenu(row, gear), { class: 'icon-btn ed-rule', 'aria-haspopup': 'menu', 'aria-expanded': 'false' })
      : null;
    const row = el('div', { class: 'ed-box ed-url-row' }, input, badge, gear, iconButton('close', t('editorRemoveWebsite'), () => removeRow(row)));
    setRule(row, rule);
    if (current.sites) {
      const first = () => row === inputs.urls?.firstElementChild;
      row.append(siteList(input, { queryOf: siteQuery, pick: (site) => {
        input.value = `https://${site.domain}`;
        if (!first() || !current.titleAuto) return;
        clearTimeout(nameTimer);
        nameSeq++;
        inputs.title.value = site.name;
      } }));
      input.addEventListener('input', () => { if (first()) scheduleName(input.value); });
    }
    return row;
  }

  function setRule(row, rule) {
    row.dataset.rule = rule;
    const badge = row.querySelector('.ed-badge');
    badge.textContent = RULE_BADGE[rule] ? t(RULE_BADGE[rule]) : '';
    badge.hidden = !RULE_BADGE[rule];
  }

  function removeRow(row) {
    const next = row.nextElementSibling || row.previousElementSibling;
    row.remove();
    inputs.showDetails?.();
    (next?.querySelector('input') || root.querySelector('#ed-url-add:not([hidden])') || root.querySelector('#ed-details-toggle'))?.focus();
  }

  async function ruleMenu(row, gear) {
    const opened = current;
    const url = row.querySelector('input').value.trim();
    const suggested = url ? await ruleHint(url) : null;
    if (current !== opened || !gear.isConnected) return;
    const choice = (rule, label, detail) => ({ id: `ed-rule-${rule}`, label: t(label), detail: t(detail), selected: row.dataset.rule === rule,
      tag: suggested === rule ? t('editorRuleSuggested') : undefined, onSelect: () => setRule(row, rule) });
    openMenu(gear, [
      choice('subdomains', 'editorRuleSubdomains', 'editorRuleSubdomainsDetail'),
      choice('host', 'editorRuleHost', 'editorRuleHostDetail'),
      choice('never', 'editorRuleNever', 'editorRuleNeverDetail'),
    ], { label: t('editorRuleMenu') });
  }

  function ruleHint(url) {
    if (!hints.has(url)) {
      hints.set(url, request('popup.rule-hint', { url }).then((res) => (RULES.includes(res?.suggested) ? res.suggested : null), () => null));
    }
    return hints.get(url);
  }

  async function usernameMenu(button) {
    if (button.disabled) return;
    const opened = current;
    const st = state() || {};
    let opts = null;
    if (st.can_generate_email) {
      try { opts = await request('popup.generate-options', { tabId: tab().id }); } catch { /* locked, or older: usernames only */ }
    }
    const website = { on: opts ? await mentionWebsite() : false };
    const aliases = Array.isArray(opts?.aliases) ? [...opts.aliases].sort((a, b) => Number(!!b.default) - Number(!!a.default)) : [];
    const email = [
      opts?.plus ? { id: 'ed-gen-plus', icon: 'mail', label: t('editorGenPlus'), onSelect: () => fillUsername(button, 'plus', null, website.on) } : null,
      opts?.catch_all ? { id: 'ed-gen-catchall', icon: 'mail', label: t('editorGenCatchAll'), onSelect: () => fillUsername(button, 'catch_all', null, website.on) } : null,
      ...aliases.map((a) => ({ id: `ed-gen-alias-${a.id}`, icon: 'shield', label: t('editorGenAlias', String(a.name || a.id)),
        onSelect: () => fillUsername(button, 'alias', String(a.id), website.on) })),
    ].filter(Boolean);
    if (current !== opened || !button.isConnected) return;
    const items = [st.can_generate_username
      ? { id: 'ed-gen-username', icon: 'user', label: t('editorGenRandomUsername'), onSelect: () => fillUsername(button, 'username') } : null];
    if (email.length) {
      items.push(...email, 'sep', { id: 'ed-gen-website', label: t('editorGenMentionWebsite'), checked: website.on,
        onToggle: (on) => { website.on = on; setSettings({ mentionWebsite: on }).catch(() => {}); } });
    }
    if (!items.some(Boolean)) return;
    openMenu(button, items, { label: t('editorGenerateUsername') });
  }

  async function mentionWebsite() {
    try { return (await getSettings()).mentionWebsite === true; } catch { return false; }
  }

  async function fillUsername(button, kind, service = null, website = false) {
    const opened = current;
    const input = inputs.username;
    button.disabled = true;
    button.classList.add('busy');
    button.setAttribute('aria-busy', 'true');
    if (kind === 'alias') snack(t('commonCreatingAlias'));
    try {
      let value;
      if (kind === 'username') {
        ({ username: value } = await send('popup.generate-username', {}));
      } else {
        const payload = { tabId: tab().id, kind };
        if (service) payload.service = service;
        if (website) payload.website = true;
        ({ email: value } = await send('popup.generate-email', payload));
      }
      if (current !== opened || typeof value !== 'string' || !value) return;
      input.value = value;
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.focus();
    } catch (err) {
      if (current === opened) snack(friendlyError(err, { context: 'generate' }));
    } finally {
      button.disabled = false;
      button.classList.remove('busy');
      button.removeAttribute('aria-busy');
    }
  }

  function scheduleCheck(now = false) {
    clearTimeout(checkTimer);
    const opened = current;
    if (!opened || !inputs.password?.value) { checkSeq++; renderCheck(null); return; }
    checkTimer = setTimeout(() => runCheck(opened), now ? 0 : CHECK_DEBOUNCE_MS);
  }

  async function runCheck(opened) {
    const seq = ++checkSeq;
    const password = inputs.password?.value;
    if (!password || current !== opened) return;
    let result = null;
    try {
      // `request`: never asks to unlock (locked, the desktop app checks the password alone).
      result = await request('popup.password-check', { tabId: tab().id, password, username: inputs.username.value.trim(),
        title: inputs.title.value.trim(), id: opened.id || undefined });
    } catch { result = null; /* an older desktop app, or none: say nothing */ }
    if (seq === checkSeq && current === opened) renderCheck(result);
  }

  function renderCheck(result) {
    const box = inputs.checkBox;
    if (!box) return;
    const list = issueTexts(result);
    if (list.length) {
      box.replaceChildren(
        el('ul', { class: 'ed-issues', 'aria-label': t('issueListLabel') },
          list.map((i) => el('li', { class: i.severity }, icon('alert', { size: 14 }), el('span', {}, i.text)))),
        wantsStrongPassword(result) ? textButton('dice', t('issueUseStrong'), () => inputs.generate?.(), { id: 'ed-use-strong' }) : null);
    } else if (looksStrong(result)) {
      box.replaceChildren(el('span', { class: 'ed-strong' }, icon('check', { size: 14 }), el('span', {}, t('issueStrong'))));
    } else {
      box.replaceChildren();
    }
  }

  /** Passwords with every letter and digit type come from the desktop app's `generate` when it answers; the rest is made here. */
  function passwordGenerator(onFill, isEmpty) {
    const opened = current;
    const site = tab()?.url || '';
    let prefs = null; // { options, symbols }, read before the first password here
    let seq = 0;
    const id = (name) => `ed-gen-${name}`;
    const panel = el('div', { class: 'ed-gen', id: id('panel'), role: 'group', 'aria-label': t('genOptionsButton'), hidden: true });
    const toggle = el('button', { class: 'icon-btn ed-gen-toggle', type: 'button', id: id('toggle'), title: t('genOptionsButton'),
      'aria-label': t('genOptionsButton'), 'aria-expanded': 'false', 'aria-controls': id('panel') }, icon('chevronDown', { size: 16 }));
    toggle.addEventListener('click', () => (panel.hidden ? open() : hide()));

    async function readPrefs() {
      prefs ??= { options: await generatorOptions(), symbols: !(await prefersNoSymbols(site).catch(() => false)) };
      return prefs;
    }

    async function fill() {
      const mine = ++seq;
      const { options, symbols } = await readPrefs();
      const plan = planFor(options, {}, symbols);
      let value = '';
      if (agentCanMake(plan)) {
        try {
          ({ password: value } = await send('popup.generate', { length: plan.length, ...(plan.symbols ? {} : { symbols: false }) }));
        } catch (err) {
          if (err.code !== 'agent_unavailable' && err.code !== 'timeout') { snack(friendlyError(err)); return; }
        }
        if (typeof value !== 'string' || (!plan.symbols && !isPlainPassword(value))) value = '';
      }
      if (!value) value = makeLocally(plan, {}, { words: plan.mode === 'passphrase' ? await passphraseWords() : null }).password;
      if (current !== opened || mine !== seq) return;
      onFill(value);
    }

    const mode = (value, label) => el('label', {}, el('input', { type: 'radio', name: id('mode'), value, id: id(value) }), el('span', {}, label));
    const modes = el('div', { class: 'ed-gen-modes', role: 'radiogroup', 'aria-label': t('genModeLabel') },
      mode('password', t('genModePassword')), mode('passphrase', t('genModePassphrase')));
    const slider = (name, label, min, max) => {
      const input = el('input', { type: 'range', id: id(name), min, max, step: 1 });
      const out = el('output', { for: id(name) });
      return { input, out, nodes: [el('div', { class: 'ed-gen-row' }, el('label', { for: id(name) }, label), out), input] };
    };
    const length = slider('length', t('genLength'), MIN_LENGTH, LENGTH_MAX);
    const words = slider('words', t('genWords'), PASSPHRASE_MIN_WORDS, WORDS_MAX);
    const chip = (name, text, label) => el('label', { class: 'ed-gen-chip', title: label },
      el('input', { type: 'checkbox', id: id(name), 'aria-label': label }), el('span', { 'aria-hidden': 'true' }, text));
    const passwordPart = el('div', { class: 'ed-gen-part' }, ...length.nodes,
      el('div', { class: 'ed-gen-types', role: 'group', 'aria-label': t('genTypes') }, CHAR_TYPES.map(([name, text, label]) => chip(name, text, t(label)))));
    const passphrasePart = el('div', { class: 'ed-gen-part' }, ...words.nodes,
      el('div', { class: 'ed-gen-types' }, chip('hyphens', t('genHyphensChip'), t('genHyphens'))));
    panel.append(modes, passwordPart, passphrasePart,
      el('div', { class: 'ed-gen-actions' }, textButton('retry', t('genRegenerate'), () => fill(), { id: id('regenerate') })));
    const box = (name) => panel.querySelector(`#${id(name)}`);

    function sync() {
      const { options, symbols } = prefs;
      for (const radio of modes.querySelectorAll('input')) radio.checked = radio.value === options.mode;
      passwordPart.hidden = options.mode === 'passphrase';
      passphrasePart.hidden = !passwordPart.hidden;
      length.input.value = String(Math.min(LENGTH_MAX, options.length));
      length.out.textContent = length.input.value;
      words.input.value = String(Math.min(WORDS_MAX, options.words));
      words.out.textContent = words.input.value;
      const on = { ...options, symbols };
      const count = CHAR_TYPES.filter(([name]) => on[name]).length;
      for (const [name] of CHAR_TYPES) {
        box(name).checked = !!on[name];
        box(name).disabled = on[name] && count === 1;
      }
      box('hyphens').checked = symbols;
    }

    function change(next, symbols = prefs.symbols) {
      if (symbols !== prefs.symbols) rememberSymbols(site, symbols).catch(() => {});
      prefs = { options: cleanOptions({ ...prefs.options, ...next }), symbols };
      sync();
      rememberOptions(prefs.options).catch(() => {});
      fill();
    }

    for (const radio of modes.querySelectorAll('input')) radio.addEventListener('change', () => change({ mode: radio.value }));
    length.input.addEventListener('input', () => change({ length: Number(length.input.value) }));
    words.input.addEventListener('input', () => change({ words: Number(words.input.value) }));
    for (const [name] of CHAR_TYPES) {
      box(name).addEventListener('change', () => (name === 'symbols' ? change({}, box(name).checked) : change({ [name]: box(name).checked })));
    }
    box('hyphens').addEventListener('change', () => change({}, box('hyphens').checked));

    const layer = { close: () => hide(true) };

    async function open() {
      await readPrefs();
      if (current !== opened) return;
      sync();
      panel.hidden = false;
      toggle.setAttribute('aria-expanded', 'true');
      layers.push(layer);
      panel.querySelector('input:checked').focus();
      if (isEmpty()) fill();
    }

    function hide(focusToggle = false) {
      panel.hidden = true;
      toggle.setAttribute('aria-expanded', 'false');
      drop(layer);
      if (focusToggle) toggle.focus();
    }

    return { fill, toggle, panel };
  }

  function siteList(input, { queryOf, pick }) {
    const opened = current;
    const listId = `${input.id || `ed-url-${++listSeq}`}-sites`;
    const list = el('ul', { class: 'ed-sites', id: listId, role: 'listbox', 'aria-label': t('editorPopularSites'), hidden: true });
    Object.entries({ role: 'combobox', 'aria-autocomplete': 'list', 'aria-expanded': 'false', 'aria-controls': listId })
      .forEach(([k, v]) => input.setAttribute(k, v));
    let sites = [];
    let active = -1;
    let timer = 0;
    let seq = 0;
    const layer = { close: () => hide() };

    function hide() {
      list.hidden = true;
      input.setAttribute('aria-expanded', 'false');
      input.removeAttribute('aria-activedescendant');
      drop(layer);
    }

    function show(found) {
      sites = found;
      active = -1;
      list.replaceChildren(...sites.map((s, i) => el('li', { id: `${listId}-${i}`, class: 'ed-site', role: 'option', 'aria-selected': 'false',
        onmousedown: (e) => e.preventDefault(), onclick: () => choose(i) },
      el('span', { class: 'ed-site-letter', 'aria-hidden': 'true' }, [...s.name][0]?.toUpperCase() || '?'),
      el('span', { class: 'ed-site-name' }, s.name), el('span', { class: 'ed-site-domain' }, s.domain))));
      if (!sites.length) { hide(); return; }
      list.hidden = false;
      input.setAttribute('aria-expanded', 'true');
      if (!layers.includes(layer)) layers.push(layer);
    }

    function move(by) {
      active = (active + by + sites.length) % sites.length;
      list.querySelectorAll('[role="option"]').forEach((li, i) => li.setAttribute('aria-selected', String(i === active)));
      input.setAttribute('aria-activedescendant', `${listId}-${active}`);
      list.children[active]?.scrollIntoView?.({ block: 'nearest' });
    }

    function choose(i) {
      const site = sites[i];
      hide();
      if (site) pick(site);
    }

    async function ask() {
      const mine = ++seq;
      const query = queryOf(input.value);
      const found = query ? await popularSites(query) : [];
      if (current === opened && mine === seq && root.contains(input) && root.ownerDocument.activeElement === input) show(found);
    }

    input.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(ask, SITE_DEBOUNCE_MS); });
    input.addEventListener('blur', () => { clearTimeout(timer); seq++; hide(); });
    input.addEventListener('keydown', (e) => {
      if (list.hidden) return;
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); move(e.key === 'ArrowDown' ? 1 : -1); }
      else if (e.key === 'Enter' && active >= 0) { e.preventDefault(); choose(active); }
      else if (e.key === 'Escape') { e.preventDefault(); hide(); }
      else if (e.key === 'Tab') hide();
    });
    return list;
  }

  async function popularSites(query) {
    try {
      const res = await request('popup.site-suggest', { query });
      return (Array.isArray(res?.sites) ? res.sites : [])
        .filter((s) => typeof s?.name === 'string' && s.name && typeof s.domain === 'string' && s.domain);
    } catch {
      return [];
    }
  }

  async function siteName(url) {
    try {
      const res = await request('popup.site-name', { url });
      return typeof res?.name === 'string' && res.name ? res.name : null;
    } catch {
      return null;
    }
  }

  /** A Name the user typed stays; an empty one, or one filled this way, follows the first website. */
  async function nameFromWebsite(url) {
    const opened = current;
    const mine = ++nameSeq;
    const host = siteQuery(url);
    if (!host || !current.titleAuto) return;
    const name = (await siteName(url)) || (/\.[a-z]{2,}$/.test(host) ? host : null);
    if (name && current === opened && mine === nameSeq && current.titleAuto) inputs.title.value = name;
  }

  function scheduleName(url) {
    clearTimeout(nameTimer);
    nameTimer = setTimeout(() => nameFromWebsite(url), SITE_DEBOUNCE_MS);
  }

  function render(data) {
    const isNew = !data.id;
    setHeading(isNew ? t('editorAddLogin') : t('editorEditLogin'));
    const title = el('input', { id: 'ed-title', type: 'text', autocomplete: 'off', spellcheck: 'false', maxlength: 256 });
    const username = el('input', { id: 'ed-username', type: 'text', autocomplete: 'off', spellcheck: 'false', maxlength: 512 });
    const password = el('input', { id: 'ed-password', type: 'password', autocomplete: 'new-password', spellcheck: 'false', maxlength: 4096 });
    const notes = el('textarea', { id: 'ed-notes', rows: 3, spellcheck: 'false', maxlength: 20000 });
    title.value = data.title || '';
    username.value = data.username || '';
    password.value = data.password || '';
    notes.value = data.notes || '';
    const reveal = iconButton('eye', t('commonShowPassword'), () => togglePassword(), { id: 'ed-reveal' });
    const togglePassword = (show = password.type === 'password') => {
      password.type = show ? 'text' : 'password';
      reveal.replaceChildren(icon(show ? 'eyeOff' : 'eye'));
      reveal.title = show ? t('commonHidePassword') : t('commonShowPassword');
      reveal.setAttribute('aria-label', reveal.title);
    };
    const generator = passwordGenerator((value) => {
      password.value = value;
      reveal.hidden = false;
      togglePassword(true);
      scheduleCheck(true);
    }, () => !password.value);
    const fillGenerated = generator.fill;
    const gen = iconButton('dice', t('editorGenerate'), fillGenerated, { id: 'ed-generate' });
    const st = state() || {};
    const userGen = st.can_generate_username || st.can_generate_email
      ? iconButton('dice', t('editorGenerateUsername'), () => usernameMenu(userGen), { id: 'ed-username-generate', 'aria-haspopup': 'menu', 'aria-expanded': 'false' })
      : null;
    const urls = el('div', { class: 'ed-urls', id: 'ed-urls' }, (data.urls || []).map((u) => urlRow(u, ruleOf(data.url_rules, u))));
    const vault = current.targets.length > 1
      ? el('select', { id: 'ed-vault' }, current.targets.map((v) => el('option', { value: v.id }, vaultName(v))))
      : null;
    if (vault) vault.value = current.vault;
    const totpBox = el('div', { id: 'ed-totp' });
    const checkBox = el('div', { class: 'ed-check', id: 'ed-check', 'aria-live': 'polite' });
    Object.assign(inputs, { title, username, password, notes, urls, totpBox, checkBox, vault, generate: fillGenerated });
    password.addEventListener('input', () => scheduleCheck());
    for (const input of [username, title]) input.addEventListener('input', () => { if (password.value) scheduleCheck(); });
    const passwordField = field(t('commonPassword'), password, reveal, gen, generator.toggle);
    passwordField.append(generator.panel);
    const eyeState = () => { reveal.hidden = !password.value; };
    password.addEventListener('input', eyeState);
    eyeState();
    passwordField.append(checkBox);

    const save = el('button', { class: 'btn primary', type: 'button', id: 'ed-save', onclick: () => submit(save) }, t('commonSave'));
    const footer = el('div', { class: 'ed-actions' },
      el('button', { class: 'btn', type: 'button', id: 'ed-cancel', onclick: () => close(false) }, t('commonCancel')),
      save);
    if (!isNew && tools) {
      const more = el('button', { class: 'icon-btn', type: 'button', id: 'ed-more', title: t('commonMore'), 'aria-label': t('editorMoreActions'),
        'aria-haspopup': 'menu', 'aria-expanded': 'false' }, icon('more', { size: 18 }));
      // The vault in this browser (`browser`): there is no Passyble app to open it in.
      more.addEventListener('click', () => openMenu(more, [
        ...(state()?.browser ? [] : [{ id: 'ed-open', icon: 'external', label: t('commonOpenInPassyble'), onSelect: () => showInPass() }, 'sep']),
        { id: 'ed-delete', icon: 'trash', label: t('editorDelete'), danger: true, onSelect: () => remove() },
      ], { label: t('editorLoginActions') }));
      tools.replaceChildren(more);
    }

    const titleField = field(t('editorTitle'), title);
    if (current.sites) {
      title.addEventListener('input', () => { current.titleAuto = !title.value.trim(); });
      titleField.querySelector('.ed-box').append(siteList(title, { queryOf: (text) => text.trim(), pick: (site) => {
        title.value = site.name;
        current.titleAuto = false;
        let first = urls.querySelector('.ed-url-row input');
        if (!first) { urls.append(urlRow()); first = urls.querySelector('.ed-url-row input'); }
        if (!first.value.trim()) first.value = `https://${site.domain}`;
      } }));
    }
    // A new login always has a website row up front (an empty one is not saved).
    if (!urls.firstElementChild) urls.append(urlRow());
    const addUrl = textButton('plus', t('editorAddWebsite'), () => { const row = urlRow(); urls.append(row); row.querySelector('input').focus(); }, { id: 'ed-url-add' });
    const details = el('div', { class: 'ed-details', id: 'ed-details' }, addUrl, vault ? field(t('editorVault'), vault) : null);
    const toggle = el('button', { class: 'ed-details-toggle', type: 'button', id: 'ed-details-toggle', 'aria-controls': 'ed-details' },
      el('span', {}, t('editorMoreDetails')), icon('chevronDown', { size: 16 }));
    const urlsLabel = el('span', { class: 'ed-label' });
    let open = hasDetails(data);
    const showDetails = () => {
      urlsLabel.textContent = t(open ? 'editorWebsites' : 'editorWebsite');
      details.hidden = !open;
      toggle.setAttribute('aria-expanded', String(open));
      toggle.classList.toggle('open', open);
      [...urls.children].forEach((row, i) => { row.hidden = !open && i > 0; });
    };
    toggle.addEventListener('click', () => { open = !open; showDetails(); });
    inputs.showDetails = showDetails;
    showDetails();
    const notesField = field(t('editorNotes'), notes);
    notesField.append(notesCounter(notes));
    const body = el('div', { class: 'ed-body' },
      titleField,
      el('div', { class: 'ed-field' }, urlsLabel, urls),
      field(t('commonUsername'), username, userGen),
      passwordField,
      el('div', { class: 'ed-field' }, el('span', { class: 'ed-label' }, t('editorTotp')), totpBox),
      notesField,
      toggle,
      details);
    // The card scrolls inside a plain scroller; hairlines show only while content is under an edge.
    const scroller = el('div', { class: 'ed-scroll' }, body);
    const edge = () => {
      scroller.classList.toggle('under-top', scroller.scrollTop > 0);
      footer.classList.toggle('edge', scroller.scrollTop + scroller.clientHeight < scroller.scrollHeight - 1);
    };
    scroller.addEventListener('scroll', edge, { passive: true });
    root.replaceChildren(el('form', { class: 'ed', autocomplete: 'off', onsubmit: (e) => { e.preventDefault(); submit(save); } }, scroller, footer));
    globalThis.requestAnimationFrame?.(edge);
    renderTotp();
    if (password.value) scheduleCheck(true);
    (isNew ? username : password).focus();
  }

  function collect() {
    const sites = [...inputs.urls.querySelectorAll('.ed-url-row')]
      .map((row) => ({ url: row.querySelector('input').value.trim(), rule: row.dataset.rule }))
      .filter((s) => s.url);
    const fields = {
      title: inputs.title.value.trim(),
      username: inputs.username.value.trim(),
      password: inputs.password.value,
      notes: inputs.notes.value,
      urls: sites.map((s) => s.url),
    };
    // The same address string as in `urls` (an older agent refuses the field).
    if (current.rules) fields.url_rules = sites.filter((s) => s.rule !== 'subdomains').map(({ url, rule }) => ({ url, rule }));
    const totp = current.totp;
    if (totp.kind === 'new') fields.totp = totp.value;
    else if (totp.kind === 'removed' && current.hadTotp) fields.totp = null;
    return fields;
  }

  async function submit(button) {
    if (!current || button.disabled) return;
    const opened = current;
    const isNew = !current.id;
    const target = current.targets.find((v) => v.id === inputs.vault?.value && (isNew || v.id !== current.vault)) || null;
    button.disabled = true;
    // Into a shared vault its members see the login: the user says yes first.
    if (target && !target.home && !(await confirmMove(button, inputs.title.value.trim() || t('editorLoginFallback'), vaultName(target)))) {
      button.disabled = false;
      return;
    }
    if (current !== opened) return;
    try {
      await send('popup.edit-save', { tabId: tab().id, id: current.id || undefined, fields: collect(), ...(isNew && target ? { vault: target.id } : {}) });
    } catch (err) {
      snack(friendlyError(err, { context: 'edit' }));
      button.disabled = false;
      return;
    }
    if (!target || isNew) {
      snack(t('editorSaved'));
      close(true);
      return;
    }
    // The fields are saved either way; a move that didn't happen says why.
    try {
      const moved = await send('popup.edit-move', { tabId: tab().id, id: current.id, vault: target.id });
      close(true, { moved: { id: typeof moved?.id === 'string' ? moved.id : current.id, vault: target } });
    } catch (err) {
      snack(friendlyError(err, { context: 'edit' }));
      close(true);
    }
  }

  function confirmMove(button, title, vault) {
    const footer = button.closest('.ed-actions');
    return new Promise((resolve) => {
      const done = (yes) => { confirming = null; box.remove(); footer.hidden = false; resolve(yes); };
      confirming = done;
      const move = el('button', { class: 'btn primary', type: 'button', id: 'ed-move-ok', onclick: () => done(true) }, t('editorMove'));
      const box = el('div', { class: 'ed-confirm', role: 'alertdialog', 'aria-labelledby': 'ed-move-text' },
        el('p', { id: 'ed-move-text' }, t('editorMoveConfirm', title, vault)),
        el('div', { class: 'ed-actions' },
          el('button', { class: 'btn', type: 'button', id: 'ed-move-cancel', onclick: () => done(false) }, t('commonCancel')),
          move));
      footer.hidden = true;
      footer.after(box);
      move.focus();
    });
  }

  async function remove() {
    if (!current?.id) return;
    const { id } = current;
    const title = inputs.title.value || t('editorLoginFallback');
    try {
      await send('popup.edit-delete', { tabId: tab().id, id });
      close(true, { deleted: { id, title } });
    } catch (err) {
      snack(friendlyError(err, { context: 'edit' }));
    }
  }

  async function showInPass() {
    try {
      await send('popup.show-item', { tabId: tab().id, id: current.id });
      snack(t('commonOpenedInPassyble'));
    } catch (err) {
      snack(friendlyError(err, { context: 'edit' }));
    }
  }

  /** An open menu or list takes the keys first; Esc during "Move to a shared vault?" answers no. */
  function onKey(e) {
    if (!current || e.defaultPrevented) return;
    const save = (e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === 's';
    if (e.key !== 'Escape' && !save) return;
    e.preventDefault();
    if (menuIsOpen()) return;
    if (layers.length) {
      if (!save) layers.at(-1).close();
      return;
    }
    if (save) {
      const button = root.querySelector('#ed-save');
      if (button) submit(button);
    } else if (confirming) {
      confirming(false);
    } else {
      close(false);
    }
  }
  root.ownerDocument.addEventListener('keydown', onKey);

  // Never leave the form's contents behind (popup closed, navigated, or put in the back/forward cache).
  document.defaultView?.addEventListener('pagehide', clear);

  return {
    get isOpen() { return !!current; },
    async open(item) {
      clear();
      if (!item) {
        const url = tab().url || '';
        // `sites`: popular sites suggest the Name and websites; `titleAuto`: the Name is still the one given here.
        // A new login goes to the home vault unless the picker (shown with several editable vaults) says otherwise.
        const targets = state()?.can_move ? vaults() : [];
        const home = targets.find((v) => v.home) || targets[0];
        current = { id: null, hadTotp: false, totp: { kind: 'none' }, vault: home?.id ?? null, targets, rules: !!state()?.can_url_rules,
          sites: !!state()?.can_sites, titleAuto: true };
        render({ id: null, title: hostOf(url).replace(/^www\./, ''), urls: originOf(url) ? [originOf(url)] : [] });
        if (current.sites && originOf(url)) nameFromWebsite(originOf(url));
        return true;
      }
      try {
        const data = await send('popup.edit-get', { tabId: tab().id, id: item.id });
        const vault = typeof data.vault?.id === 'string' ? data.vault.id : item.vault_id;
        const targets = state()?.can_move && !data.read_only ? vaults() : [];
        current = { id: data.id || item.id, hadTotp: !!data.totp,
          totp: data.totp ? { kind: 'saved', info: data.totp.invalid ? null : data.totp } : { kind: 'none' },
          vault, targets: targets.some((v) => v.id === vault) ? targets : [], rules: !!state()?.can_url_rules };
        render({ ...data, id: current.id });
        return true;
      } catch (err) {
        snack(friendlyError(err, { context: 'edit' }));
        return false;
      }
    },
    close: () => close(false),
    clear,
  };
}
