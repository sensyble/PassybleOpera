// "Help and support": the app's support screen when the desktop app advertises `support.link`, else the web form.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { chooseSupportLink, openSupport, APP_SUPPORT_URL, WEB_SUPPORT_BASE } from '../src/shared/support-link.js';

const WEB = `${WEB_SUPPORT_BASE}/support`;

test('chooseSupportLink: app with the feature goes to passyble://support', () => {
  assert.deepEqual(chooseSupportLink({ browserMode: false, features: ['vaults', 'support.link'] }), { via: 'app', url: APP_SUPPORT_URL });
  assert.equal(APP_SUPPORT_URL, 'passyble://support');
});

test('chooseSupportLink: browser mode, no feature or no features: the web form', () => {
  assert.deepEqual(chooseSupportLink({ browserMode: true, features: ['support.link'] }), { via: 'web', url: WEB });
  assert.deepEqual(chooseSupportLink({ browserMode: false, features: ['vaults'] }), { via: 'web', url: WEB });
  assert.deepEqual(chooseSupportLink({ browserMode: false }), { via: 'web', url: WEB });
});

test('chooseSupportLink: a dev account base is used, a bad one is not', () => {
  assert.equal(chooseSupportLink({ features: [], base: 'http://localhost:8787' }).url, 'http://localhost:8787/support');
  assert.equal(chooseSupportLink({ features: [], base: 'javascript:alert(1)' }).url, WEB);
});

function harness({ browserMode = false, status, navigateThrows = false }) {
  const calls = { navigate: [], web: [] };
  return {
    calls,
    run: () => openSupport({
      browserMode,
      getStatus: async () => { if (status instanceof Error) throw status; return status; },
      navigate: async (u) => { if (navigateThrows) throw new Error('no tab'); calls.navigate.push(u); },
      openWeb: async (u) => { calls.web.push(u); },
      getBase: async () => WEB_SUPPORT_BASE,
    }),
  };
}

test('openSupport: app connected with the feature navigates the tab', async () => {
  const h = harness({ status: { features: ['support.link'] } });
  assert.equal((await h.run()).via, 'app');
  assert.deepEqual(h.calls, { navigate: [APP_SUPPORT_URL], web: [] });
});

test('openSupport: browser mode opens the web form and never asks the app', async () => {
  const h = harness({ browserMode: true, status: new Error('must not be asked') });
  assert.equal((await h.run()).via, 'web');
  assert.deepEqual(h.calls, { navigate: [], web: [WEB] });
});

test('openSupport: no feature, status error, or failed navigation fall back to the web form', async () => {
  for (const h of [harness({ status: { features: [] } }), harness({ status: new Error('timeout') }),
    harness({ status: { features: ['support.link'] }, navigateThrows: true })]) {
    assert.equal((await h.run()).via, 'web');
    assert.deepEqual(h.calls.web, [WEB]);
  }
});

test('the background has the support.open handler and both pages send it', () => {
  assert.match(readFileSync(new URL('../src/background.js', import.meta.url), 'utf8'), /async 'support\.open'\(/);
  assert.match(readFileSync(new URL('../src/popup/popup.js', import.meta.url), 'utf8'), /send\('support\.open'\)/);
  assert.match(readFileSync(new URL('../src/options/options.js', import.meta.url), 'utf8'), /send\('support\.open'\)/);
});
