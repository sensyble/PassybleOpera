// "Add Passyble Server" form, shared by the popup and the options page.
// The input may hold a pairing token: it is sent once to the background, never logged or stored, and
// the field is cleared after sending.
import { checkServerInput, KIND_INVITE } from '../shared/pairing.js';
import { friendlyError } from '../shared/messages.js';
import { t } from '../shared/i18n.js';

const KIND_LABELS = Object.freeze({
  pairing: t('serverKindPairing'),
  invite: t('serverKindInvite'),
  address: t('serverKindAddress'),
});

export const HINT = t('serverHint');
export const SIGN_IN_OPENED = t('serverSignInOpened');

export function pairErrorText(err, { address = false } = {}) {
  return friendlyError(err, { context: address ? 'server-address' : 'server-pair' });
}

export function mountServerPair(root, { send }) {
  const doc = root.ownerDocument;
  root.classList.add('sp');
  const h = (tag, attrs = {}, ...children) => {
    const node = doc.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') node.className = v;
      else node.setAttribute(k, v === true ? '' : String(v));
    }
    node.append(...children);
    return node;
  };

  const uid = Math.random().toString(36).slice(2, 8);
  const hintId = `sp-hint-${uid}`;
  const input = h('input', {
    class: 'sp-input', id: `sp-input-${uid}`, type: 'text', placeholder: 'pass.example.com',
    'aria-label': t('serverInputLabel'), 'aria-describedby': hintId,
    // No name (no form history), no autocomplete, and no spellcheck: Chrome's enhanced spellcheck
    // sends field text to a web service, and a pairing link carries the account's token.
    autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', autocorrect: 'off', enterkeyhint: 'go',
  });
  const send_ = h('button', { class: 'btn primary sp-send', type: 'button', disabled: true, title: t('serverContinueTitle') },
    h('span', {}, t('serverContinue')));
  const hint = h('p', { class: 'sp-hint', id: hintId }, HINT);
  const preview = h('dl', { class: 'sp-preview', hidden: true });
  const warn = h('p', { class: 'sp-warn', hidden: true });
  const error = h('p', { class: 'sp-error', role: 'alert', hidden: true });
  const result = h('p', { class: 'sp-result', role: 'status', 'aria-live': 'polite', hidden: true });
  const drop = h('div', { class: 'sp-drop' }, input, send_);

  const label = h('label', { class: 'sp-label', for: `sp-input-${uid}` }, t('serverAddressLabel'));
  root.replaceChildren(label, drop, hint, error, preview, warn, result);

  let current = null; // checkServerInput(...).value for the field's current value (no token)
  let busy = false;
  let errorTimer = 0;

  function setMessage(node, text, kind) {
    node.hidden = !text;
    node.textContent = text || '';
    if (kind) node.dataset.kind = kind; else delete node.dataset.kind;
  }

  function row(label, value) {
    return [h('dt', {}, label), h('dd', {}, value)];
  }

  function showPreview(value) {
    if (value.type === 'address') {
      preview.append(
        ...row(t('serverRowServer'), value.host),
        ...row(t('serverRowAddress'), value.address),
        ...row(t('serverRowNext'), t('serverNextSignIn')),
      );
      return;
    }
    const info = value.info;
    const pins = info.pins.length;
    const invite = info.kind === KIND_INVITE;
    preview.append(
      ...row(t('serverRowLink'), KIND_LABELS[info.kind]),
      ...row(t('serverRowServer'), info.host),
      ...row(t('serverRowAccount'), info.username),
      ...(invite && !info.deviceName ? [] : row(t('serverRowDevice'), info.deviceName || t('serverDeviceUnnamed'))),
      ...row(t('serverRowCertificate'), pins
        ? t('serverCertLinked')
        : info.https ? t('serverCertPublic') : t('serverCertNone')),
      ...(invite ? row(t('serverRowPassword'), t('serverPasswordAsked')) : row(t('serverRowToken'), t('serverTokenIncluded'))),
    );
  }

  function validate({ live = false } = {}) {
    const value = input.value;
    current = null;
    clearTimeout(errorTimer);
    preview.hidden = true;
    preview.replaceChildren();
    setMessage(warn, '');
    if (!value.trim()) {
      setMessage(error, '');
      hint.hidden = false;
      send_.disabled = true;
      return;
    }
    const check = checkServerInput(value);
    if (!check.ok) {
      send_.disabled = true;
      if (live) {
        setMessage(error, '');
        errorTimer = setTimeout(() => { setMessage(error, check.message); hint.hidden = true; }, 700);
        errorTimer?.unref?.(); // Node (tests) only
      } else {
        setMessage(error, check.message);
        hint.hidden = true;
      }
      return;
    }
    setMessage(error, '');
    hint.hidden = false;
    setMessage(result, '');
    current = check.value;
    showPreview(current);
    preview.hidden = false;
    const https = current.type === 'address' ? current.https : current.info.https;
    if (!https) {
      setMessage(warn, t('serverHttpWarning'));
    }
    send_.disabled = busy;
  }

  function reset() {
    input.value = '';
    current = null;
    setMessage(result, '');
    validate();
  }

  async function submit() {
    if (busy) return;
    validate();
    if (!current) return;
    const value = current;
    const isAddress = value.type === 'address';
    const payload = { link: isAddress ? value.address : value.link };
    busy = true;
    send_.disabled = true;
    input.disabled = true;
    setMessage(result, t('serverOpening'));
    try {
      const res = await send('popup.server-pair', payload);
      const signIn = isAddress || res?.sign_in || value.info?.kind === KIND_INVITE;
      setMessage(result, signIn
        ? SIGN_IN_OPENED
        : t('serverCheckWindow', res?.host || value.info.host, res?.user || value.info.username), 'ok');
    } catch (err) {
      setMessage(result, pairErrorText(err, { address: isAddress }), 'error');
    } finally {
      busy = false;
      input.disabled = false;
      // Clear the link (and its token) once it has been handed over, whatever the outcome.
      input.value = '';
      current = null;
      preview.hidden = true;
      preview.replaceChildren();
      setMessage(warn, '');
      setMessage(error, '');
      hint.hidden = false;
      send_.disabled = true;
    }
  }

  input.addEventListener('input', (e) => {
    setMessage(result, '');
    validate({ live: /^(?:insertText|insertCompositionText|deleteContent)/.test(e.inputType || '') });
  });
  input.addEventListener('blur', () => { if (!busy && input.value.trim()) validate(); });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); submit(); }
  });
  send_.addEventListener('click', submit);

  const hasText = (e) => [...(e.dataTransfer?.types || [])].some((t) => t === 'text/plain' || t === 'text/uri-list');
  root.addEventListener('dragover', (e) => {
    if (!hasText(e)) return;
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
    drop.classList.add('over');
  });
  root.addEventListener('dragleave', (e) => {
    if (!root.contains(e.relatedTarget)) drop.classList.remove('over');
  });
  root.addEventListener('drop', (e) => {
    drop.classList.remove('over');
    const text = e.dataTransfer?.getData('text/plain') || e.dataTransfer?.getData('text/uri-list') || '';
    if (!text) return;
    e.preventDefault();
    if (busy) return;
    const check = checkServerInput(text);
    input.value = check.ok ? (check.value.type === 'link' ? check.value.link : check.value.address) : text.trim();
    setMessage(result, '');
    validate();
    input.focus();
  });

  return { input, focus: () => input.focus(), reset };
}
