// Firefox's built-in data consent (Firefox 140+): the manifest declares `required: ["none"]` plus optional categories.
// Other browsers have no such consent, so askDataConsent() resolves true at once.
// In Firefox the request must come from the click: call it first in the handler, before any `await`.
import { ext } from './api.js';

export const ACCOUNT_DATA = Object.freeze(['authenticationInfo', 'personallyIdentifyingInfo']);
export const SYNC_DATA = Object.freeze(['authenticationInfo', 'personallyIdentifyingInfo', 'financialAndPaymentInfo']);

export function optionalDataCategories(api = ext) {
  try {
    const declared = api?.runtime?.getManifest?.()?.browser_specific_settings?.gecko?.data_collection_permissions?.optional;
    return Array.isArray(declared) ? declared : [];
  } catch {
    return [];
  }
}

export function askDataConsent(categories, api = ext) {
  const declared = optionalDataCategories(api);
  const wanted = categories.filter((c) => declared.includes(c));
  if (!wanted.length || typeof api?.permissions?.request !== 'function') return Promise.resolve(true);
  try {
    return Promise.resolve(api.permissions.request({ data_collection: wanted })).then((ok) => ok === true, () => false);
  } catch {
    return Promise.resolve(false);
  }
}

export async function hasDataConsent(categories, api = ext) {
  const declared = optionalDataCategories(api);
  const wanted = categories.filter((c) => declared.includes(c));
  if (!wanted.length || typeof api?.permissions?.contains !== 'function') return true;
  try {
    return (await api.permissions.contains({ data_collection: wanted })) === true;
  } catch {
    return false;
  }
}
