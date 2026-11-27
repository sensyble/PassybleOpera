// Only the otpauth link itself goes on to the vault, where the agent checks it again; the secret is never pulled out.
// `otpauth-migration://` is recognised but not read: only the Passyble app's import reads it.

/** A base32 secret shorter than this (80 bits) is refused, as the agent does (MIN_TOTP_SECRET). */
const MIN_SECRET_CHARS = 16;
const MAX_LINK = 2048;
const ALGORITHMS = new Set(['SHA1', 'SHA256', 'SHA512']);

export function parseOtpauth(text) {
  const raw = String(text ?? '').trim();
  if (/^otpauth-migration:/i.test(raw)) return { kind: 'migration' };
  if (!/^otpauth:\/\//i.test(raw)) return null;
  if (raw.length > MAX_LINK) return { kind: 'invalid' };
  let url;
  try { url = new URL(raw); } catch { return { kind: 'invalid' }; }
  const type = url.host.toLowerCase();
  if (type === 'hotp') return { kind: 'hotp' };
  if (type !== 'totp') return { kind: 'invalid' };
  const q = url.searchParams;
  const secret = (q.get('secret') || '').replace(/[\s-]/g, '').toUpperCase();
  if (!/^[A-Z2-7]+=*$/.test(secret) || secret.replace(/=+$/, '').length < MIN_SECRET_CHARS) return { kind: 'invalid' };
  const digits = Number(q.get('digits') || 6);
  const period = Number(q.get('period') || 30);
  const algorithm = String(q.get('algorithm') || 'SHA1').toUpperCase().replace('-', '');
  if (![6, 7, 8].includes(digits) || !Number.isInteger(period) || period < 1 || period > 300 || !ALGORITHMS.has(algorithm)) {
    return { kind: 'invalid' };
  }
  let label = '';
  try { label = decodeURIComponent(url.pathname.replace(/^\/+/, '')); } catch { label = ''; }
  const cut = label.indexOf(':');
  const labelIssuer = cut >= 0 ? label.slice(0, cut).trim() : '';
  const account = (cut >= 0 ? label.slice(cut + 1) : label).trim();
  const issuer = (q.get('issuer') || labelIssuer).trim();
  return { kind: 'totp', uri: raw, issuer, account, digits, period, algorithm };
}

const PROBLEM_ORDER = ['migration', 'hotp', 'invalid'];

export function pickAuthenticator(texts) {
  const list = Array.isArray(texts) ? texts.filter((t) => typeof t === 'string') : [];
  if (!list.length) return { problem: 'none' };
  const parsed = list.map(parseOtpauth);
  const totp = parsed.find((p) => p?.kind === 'totp');
  if (totp) return { totp };
  for (const kind of PROBLEM_ORDER) if (parsed.some((p) => p?.kind === kind)) return { problem: kind };
  return { problem: 'not_otp' };
}

const norm = (s) => String(s ?? '').trim().toLowerCase();

/** The site's logins the scanned code can go to, and the one chosen at first (only when unambiguous). */
export function matchLogins(items, info) {
  const logins = (Array.isArray(items) ? items : []).filter((i) => i && typeof i.id === 'string' && i.id);
  if (logins.length === 1) return { candidates: logins, preselect: logins[0].id };
  const account = norm(info?.account);
  const same = account ? logins.filter((i) => norm(i.username) === account) : [];
  const rest = logins.filter((i) => !same.includes(i));
  return { candidates: [...same, ...rest], preselect: same.length === 1 ? same[0].id : null };
}

export function newLoginFields(info, site = '') {
  const title = (info?.issuer || site || '').slice(0, 256);
  const account = String(info?.account || '');
  const fields = { title, totp: info.uri };
  if (account && norm(account) !== norm(info?.issuer)) fields.username = account.slice(0, 512);
  return fields;
}
