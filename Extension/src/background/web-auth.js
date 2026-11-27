// The redirect URL `identity.launchWebAuthFlow` catches for the account sign-in, derived from the extension's
// ID: https://<id>.chromiumapp.org/ in Chromium browsers, https://<sha1>.extensions.allizom.org/ in Firefox.
// Safari has no identity API, so there is no redirect there.

const CHROMIUM_REDIRECT_RE = /^https:\/\/[a-p]{32}\.chromiumapp\.org\/$/;
const FIREFOX_REDIRECT_RE = /^https:\/\/([0-9a-f]{40})\.extensions\.allizom\.org\/$/;

/** The redirect URL for launchWebAuthFlow, or null when there is no identity API or an unknown form. */
export function webAuthRedirect(ext) {
  let uri;
  try { uri = ext?.identity?.getRedirectURL?.(); } catch { return null; }
  // Opera has no getRedirectURL: a Chromium extension ID gives the same chromiumapp.org URL.
  if (typeof ext?.identity?.getRedirectURL !== 'function' && /^[a-p]{32}$/.test(String(ext?.runtime?.id))) {
    uri = `https://${ext.runtime.id}.chromiumapp.org/`;
  }
  if (typeof uri !== 'string' || typeof ext.identity?.launchWebAuthFlow !== 'function') return null;
  if (CHROMIUM_REDIRECT_RE.test(uri) || FIREFOX_REDIRECT_RE.test(uri)) return uri;
  return null;
}

export function cameBackTo(answer, redirect) {
  let back;
  try { back = new URL(answer); } catch { return false; }
  return redirect.endsWith('/') ? `${back.origin}/` === redirect : `${back.origin}${back.pathname}` === redirect;
}
