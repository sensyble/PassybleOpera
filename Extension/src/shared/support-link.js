// The desktop app has its own support screen (`passyble://support`, once `status.features` lists `support.link`); otherwise the web form opens.

const SUPPORT_FEATURE = 'support.link';
export const APP_SUPPORT_URL = 'passyble://support';
export const WEB_SUPPORT_BASE = 'https://account.passyble.com';

function webSupportUrl(base) {
  const origin = typeof base === 'string' && /^https?:\/\/[^/?#]+$/.test(base) ? base : WEB_SUPPORT_BASE;
  return `${origin}/support`;
}

export function chooseSupportLink({ browserMode, features, base } = {}) {
  if (!browserMode && Array.isArray(features) && features.includes(SUPPORT_FEATURE)) return { via: 'app', url: APP_SUPPORT_URL };
  return { via: 'web', url: webSupportUrl(base) };
}

/** Opens the support page; any failure of the app route falls back to the web form. An external-protocol navigation does not unload the page. */
export async function openSupport({ browserMode, getStatus, navigate, openWeb, getBase }) {
  let base;
  try { base = await getBase?.(); } catch { base = undefined; }
  let features = [];
  if (!browserMode) {
    try {
      const status = await getStatus();
      features = Array.isArray(status?.features) ? status.features : [];
    } catch { features = []; }
  }
  const choice = chooseSupportLink({ browserMode, features, base });
  if (choice.via === 'app') {
    try {
      await navigate(choice.url);
      return choice;
    } catch { /* the web form */ }
  }
  const web = { via: 'web', url: webSupportUrl(base) };
  await openWeb(web.url);
  return web;
}
