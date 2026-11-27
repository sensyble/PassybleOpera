// Labels for cards and identities (no secrets). Brand names are not translated.
import { t } from './i18n.js';

const BRANDS = Object.freeze({
  visa: { name: 'Visa', badge: 'VISA' },
  mastercard: { name: 'Mastercard', badge: 'MC' },
  amex: { name: 'American Express', badge: 'AMEX' },
  discover: { name: 'Discover', badge: 'DISC' },
  diners: { name: 'Diners Club', badge: 'DC' },
  jcb: { name: 'JCB', badge: 'JCB' },
  unionpay: { name: 'UnionPay', badge: 'UP' },
  maestro: { name: 'Maestro', badge: 'MAES' },
  mir: { name: 'Mir', badge: 'MIR' },
});

export function brandName(brand) {
  const key = String(brand || '').toLowerCase();
  return BRANDS[key]?.name || (key ? key.charAt(0).toUpperCase() + key.slice(1) : t('cardsCard'));
}

export function brandBadge(brand) {
  return BRANDS[String(brand || '').toLowerCase()]?.badge || t('cardsBadge');
}

/** "04/29" (MM/YY), or "" when the month or year is unknown. */
export function shortExpiry(month, year) {
  const m = Number(month);
  const y = Number(year);
  if (!Number.isInteger(m) || m < 1 || m > 12 || !Number.isInteger(y) || y <= 0) return '';
  return `${String(m).padStart(2, '0')}/${String(y % 100).padStart(2, '0')}`;
}

export function cardSummary(card) {
  const parts = [card?.last4 ? `${brandName(card.brand)} •••• ${card.last4}` : brandName(card?.brand)];
  const exp = shortExpiry(card?.expiry_month, card?.expiry_year);
  if (exp) parts.push(exp);
  return parts.join(' · ');
}

export function identitySummary(identity) {
  return [identity?.full_name, identity?.email || identity?.company].filter(Boolean).join(' · ');
}

/** The page may get cards and addresses: https, or http on this device (as the agent checks). */
export function isSecureFormUrl(url) {
  let u;
  try { u = new URL(url); } catch { return false; }
  if (u.protocol === 'https:') return true;
  if (u.protocol !== 'http:') return false;
  const host = u.hostname.toLowerCase();
  return host === 'localhost' || host.endsWith('.localhost') || /^127\.\d+\.\d+\.\d+$/.test(host) || host === '[::1]';
}
