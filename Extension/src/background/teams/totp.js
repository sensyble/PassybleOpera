// 2FA codes (RFC 6238) for the logins of shared vaults, made the same way pass-core makes them. The secret
// stays in the function's locals; only the code and its timing come out.

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const ALGORITHMS = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };

export function base32Decode(text) {
  const clean = String(text || '').toUpperCase().replace(/[\s=-]/g, '');
  if (!clean || /[^A-Z2-7]/.test(clean)) return null;
  const out = [];
  let bits = 0;
  let value = 0;
  for (const c of clean) {
    value = (value << 5) | B32.indexOf(c);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return out.length ? new Uint8Array(out) : null;
}

function totpParse(value) {
  const text = String(value || '').trim();
  if (!text) return null;
  if (!/^otpauth:/i.test(text)) {
    const secret = base32Decode(text);
    return secret ? { secret, digits: 6, period: 30, algorithm: 'SHA1', issuer: '', account: '' } : null;
  }
  let url;
  try { url = new URL(text); } catch { return null; }
  if (url.host.toLowerCase() !== 'totp') return null;
  const q = url.searchParams;
  const secret = base32Decode(q.get('secret'));
  if (!secret) return null;
  const digits = Number(q.get('digits') || 6);
  const period = Number(q.get('period') || 30);
  const algorithm = String(q.get('algorithm') || 'SHA1').toUpperCase();
  if (![6, 7, 8].includes(digits) || !Number.isInteger(period) || period < 1 || period > 300 || !ALGORITHMS[algorithm]) return null;
  let label = '';
  try { label = decodeURIComponent(url.pathname.replace(/^\/+/, '')); } catch { label = ''; }
  const [labelIssuer, labelAccount] = label.includes(':') ? label.split(/:(.*)/s) : ['', label];
  return { secret, digits, period, algorithm, issuer: q.get('issuer') || labelIssuer || '', account: (labelAccount || '').trim() };
}

/** The code at `nowMs` in the shape of the agent's `totp.get`, or null. */
export async function totpCode(value, nowMs = Date.now(), subtle = globalThis.crypto?.subtle) {
  const cfg = totpParse(value);
  if (!cfg || !subtle) return null;
  const secs = Math.floor(nowMs / 1000);
  const counter = Math.floor(secs / cfg.period);
  const msg = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    msg[i] = c & 0xff;
    c = Math.floor(c / 256);
  }
  const key = await subtle.importKey('raw', cfg.secret, { name: 'HMAC', hash: ALGORITHMS[cfg.algorithm] }, false, ['sign']);
  cfg.secret.fill(0);
  const mac = new Uint8Array(await subtle.sign('HMAC', key, msg));
  const offset = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  const code = String(bin % 10 ** cfg.digits).padStart(cfg.digits, '0');
  return { code, period: cfg.period, remaining_secs: cfg.period - (secs % cfg.period) };
}

export async function totpInfo(value, nowMs = Date.now(), subtle = globalThis.crypto?.subtle) {
  const cfg = totpParse(value);
  if (!cfg) return { invalid: true };
  const now = await totpCode(value, nowMs, subtle);
  return { issuer: cfg.issuer, account: cfg.account, digits: cfg.digits, period: cfg.period, algorithm: cfg.algorithm,
    code: now?.code ?? '', remaining_secs: now?.remaining_secs ?? cfg.period };
}
