// Passyble Server pairing links (`pass+server://`). The extension never connects to the server: it
// checks the link and hands it to the desktop app (`server.pair`). Mirrors pass-core's `parse_pairing_link` and is
// tested against the same vectors; `token` may be omitted (an invite). The token is never returned.
import { ErrorCode, PassError } from './errors.js';
import { t } from './i18n.js';

const PAIRING_PREFIX = 'pass+server://';
/** `server.pair` rejects longer links (bytes after trimming). */
export const MAX_LINK_LEN = 4096;

const encoder = new TextEncoder();

function invalid(message) {
  return new PassError(ErrorCode.INVALID_PARAMS, message);
}

const isHex = (b) => (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x46) || (b >= 0x61 && b <= 0x66);

/** Percent-decodes like Rust's `percent_decode_str(..).decode_utf8()`: a stray `%` stays literal, `+` stays `+`. */
function percentDecode(value) {
  const src = encoder.encode(value);
  const out = new Uint8Array(src.length);
  let n = 0;
  for (let i = 0; i < src.length; i++) {
    if (src[i] === 0x25 && i + 2 < src.length && isHex(src[i + 1]) && isHex(src[i + 2])) {
      out[n++] = parseInt(String.fromCharCode(src[i + 1], src[i + 2]), 16);
      i += 2;
    } else {
      out[n++] = src[i];
    }
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(out.subarray(0, n));
  } catch {
    throw invalid(t('pairBadPercent'));
  }
}

/** Picks the first `pass+server://` token out of pasted text, else returns the trimmed text for the parser to explain. */
export function extractPairingLink(text) {
  const s = typeof text === 'string' ? text : '';
  const m = s.match(/pass\+server:\/\/[^\s"'<>`]+/i);
  if (!m) return s.trim();
  const link = m[0].replace(/[.,;:!)\]}]+$/, '');
  // The scheme is case-insensitive for people, not for the parser (and the desktop app).
  return PAIRING_PREFIX + link.slice(PAIRING_PREFIX.length);
}

/** Normalizes a plain server address like pass-core's `normalize_server_url`; throws PassError `invalid_params`. */
export function normalizeServerAddress(input) {
  const text = typeof input === 'string' ? input.trim() : '';
  if (!text) throw invalid(t('pairAddressEmpty'));
  if (text.length > MAX_LINK_LEN) throw invalid(t('pairAddressTooLong'));
  if (/\s/.test(text)) throw invalid(t('pairAddressSpaces'));
  const schemeMatch = text.match(/^([a-z][a-z0-9+.-]*):\/\//i);
  if (schemeMatch && !/^https?$/i.test(schemeMatch[1])) {
    throw invalid(t('pairAddressScheme'));
  }
  const withScheme = schemeMatch ? text : `https://${text}`;
  const authority = withScheme.slice(withScheme.indexOf('://') + 3).split(/[/?#]/)[0];
  if (authority.includes('@')) {
    throw invalid(text.includes('/') || !text.includes('.')
      ? t('pairAddressCredentials')
      : t('pairAddressEmail'));
  }
  if (/[?#]/.test(withScheme)) {
    throw invalid(t('pairAddressQuery'));
  }
  let url;
  try {
    url = new URL(withScheme);
  } catch {
    throw invalid(t('pairAddressInvalid'));
  }
  if (!url.hostname || url.username || url.password || /^https?$/i.test(url.hostname)) {
    throw invalid(t('pairAddressInvalid'));
  }
  return { url: url.href.replace(/\/+$/, ''), host: url.host, https: url.protocol === 'https:' };
}

export function parseServerInput(text) {
  const s = typeof text === 'string' ? text : '';
  if (/pass\+server:\/\//i.test(s)) {
    const link = extractPairingLink(s);
    return { type: 'link', link, info: parsePairingLink(link) };
  }
  if (!s.trim()) throw invalid(t('pairInputEmpty'));
  // "Server: https://pass.example.com/" pasted from an e-mail: take the web address out of the text.
  const inText = /\s/.test(s.trim()) ? s.match(/https?:\/\/[^\s"'<>`]+/i) : null;
  const { url, host, https } = normalizeServerAddress(inText ? inText[0].replace(/[.,;:!)\]}]+$/, '') : s);
  return { type: 'address', address: url, host, https };
}

export function checkServerInput(text) {
  try {
    return { ok: true, value: parseServerInput(text) };
  } catch (err) {
    return { ok: false, message: PassError.from(err).message };
  }
}

const KIND_PAIRING = 'pairing';
export const KIND_INVITE = 'invite';

/** Parses and validates a pairing link; returns what can be shown, never the token. */
export function parsePairingLink(input) {
  const link = typeof input === 'string' ? input.trim() : '';
  if (!link) throw invalid(t('pairLinkEmpty'));
  if (encoder.encode(link).length > MAX_LINK_LEN) throw invalid(t('pairLinkTooLong'));
  if (!link.startsWith(PAIRING_PREFIX)) {
    throw invalid(t('pairLinkPrefix'));
  }
  const rest = link.slice(PAIRING_PREFIX.length);
  const q = rest.indexOf('?');
  let beforeQuery = q >= 0 ? rest.slice(0, q) : rest;
  let query = q >= 0 ? rest.slice(q + 1) : '';
  beforeQuery = beforeQuery.split('#')[0];
  query = query.split('#')[0];

  // A sign-in link may have no path (server base path).
  const slash = beforeQuery.indexOf('/');
  const authority = slash < 0 ? beforeQuery : beforeQuery.slice(0, slash);
  const path = slash < 0 ? '' : beforeQuery.slice(slash);
  if (!authority || authority.includes('@')) throw invalid(t('pairLinkAddress'));

  let version = null;
  let user = null;
  let token = null;
  let name = null;
  const pins = [];
  const codes = [];
  let https = true;
  for (const pair of query.split('&')) {
    if (!pair) continue;
    const eq = pair.indexOf('=');
    const key = eq >= 0 ? pair.slice(0, eq) : pair;
    const value = percentDecode(eq >= 0 ? pair.slice(eq + 1) : '');
    switch (key) {
      case 'v': version = value; break;
      case 'user': user = value; break;
      case 'token': token = value; break;
      case 'name': name = value; break;
      case 'pin': pins.push(value); break;
      case 'invite': case 'reset': codes.push({ kind: key, value }); break;
      case 'scheme':
        if (value === 'https') https = true;
        else if (value === 'http') https = false;
        else throw invalid(t('pairLinkScheme'));
        break;
      default: break; // unknown parameters are ignored (newer link versions may add optional ones)
    }
  }
  if (version === null) throw invalid(t('pairLinkNoVersion'));
  if (version !== '1') throw invalid(t('pairLinkVersion'));
  for (const pin of pins) {
    if (!pin.startsWith('sha256:')) throw invalid(t('pairLinkPin'));
  }
  if (!user) throw invalid(t('pairLinkNoUser'));
  if (token !== null) {
    if (!token) throw invalid(t('pairLinkEmptyToken'));
    if (codes.length) throw invalid(t('pairLinkTokenAndCode'));
    if (path.length < 2) throw invalid(t('pairLinkNoPath'));
  } else if (codes.length > 1 || codes.some((c) => !c.value)) {
    throw invalid(t('pairLinkCodes'));
  }
  return { // no token: the caller sends the link it already holds
    kind: token ? KIND_PAIRING : KIND_INVITE,
    codeKind: token ? null : (codes[0]?.kind ?? null), // 'invite' | 'reset' | null; the code itself is not returned
    url: `${https ? 'https' : 'http'}://${authority}${token ? path : path.replace(/\/+$/, '')}`,
    host: authority,
    username: user,
    deviceName: name,
    pins,
    https,
  };
}
