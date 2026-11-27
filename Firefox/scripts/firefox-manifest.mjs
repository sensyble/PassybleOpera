// Turns the Chromium manifest into the Firefox one, using the data in manifest.overrides.json:
// background as an event page, no Chrome-only keys or permissions, the gecko ID and data consent,
// and _execute_action instead of the MV2 command name.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export const FIREFOX_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const OVERRIDES_FILE = path.join(FIREFOX_DIR, 'manifest.overrides.json');

/** Firefox/manifest.overrides.json, parsed. */
export const OVERRIDES = Object.freeze(JSON.parse(readFileSync(OVERRIDES_FILE, 'utf8')));

export const GECKO_ID = OVERRIDES.browser_specific_settings.gecko.id;
export const GECKO_MIN_VERSION = OVERRIDES.browser_specific_settings.gecko.strict_min_version;
/** Permissions Firefox does not know (it warns about them when loading the add-on). */
export const CHROME_ONLY_PERMISSIONS = Object.freeze([...OVERRIDES.remove_permissions]);
/** Firefox's built-in data consent (AMO requirement). */
export const DATA_COLLECTION = Object.freeze(structuredClone(OVERRIDES.browser_specific_settings.gecko.data_collection_permissions));

/** Redirect URLs identity.launchWebAuthFlow accepts for an add-on ID (lower-case hex SHA-1 of the ID). */
export function firefoxRedirectUrls(id = GECKO_ID) {
  const hash = createHash('sha1').update(id, 'utf8').digest('hex');
  return { web: `https://${hash}.extensions.allizom.org/`, loopback: `http://127.0.0.1/mozoauth2/${hash}` };
}

export function toFirefoxManifest(chrome, overrides = OVERRIDES) {
  const m = structuredClone(chrome);
  const worker = m.background?.service_worker;
  if (worker) {
    m.background = { scripts: [worker], type: m.background.type || 'module' };
  }
  if (m.commands?._execute_browser_action) {
    m.commands._execute_action ??= m.commands._execute_browser_action;
    delete m.commands._execute_browser_action;
  }
  for (const key of overrides.remove_keys || []) delete m[key];
  if (m.permissions) m.permissions = m.permissions.filter((p) => !(overrides.remove_permissions || []).includes(p));
  m.browser_specific_settings = structuredClone(overrides.browser_specific_settings);
  for (const war of m.web_accessible_resources || []) delete war.use_dynamic_url;
  return m;
}
