import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  BROWSER_AUTOFILL_KEY,
  restoreBrowserAutofill,
  turnOffBrowserAutofill,
  turnOffOnFirstPopup,
} from '../src/shared/browser-autofill.js';

/** A `privacy.services` setting (chrome.types.ChromeSetting) with a value and a level of control. */
function fakeSetting(value, levelOfControl = 'controllable_by_this_extension') {
  const s = {
    value,
    levelOfControl,
    sets: [],
    cleared: 0,
    async get() { return { value: s.value, levelOfControl: s.levelOfControl }; },
    async set({ value: v }) { s.sets.push(v); s.value = v; s.levelOfControl = 'controlled_by_this_extension'; },
    async clear() { s.cleared++; s.value = true; s.levelOfControl = 'controllable_by_this_extension'; },
  };
  return s;
}

function fakeApi(services) {
  const store = {};
  return {
    store,
    privacy: { services },
    storage: {
      local: {
        async get(key) { return key in store ? { [key]: store[key] } : {}; },
        async set(obj) { Object.assign(store, obj); },
      },
    },
  };
}

test('turns off what is on and controllable; skips policy-controlled, already-off and missing settings', async () => {
  const services = {
    passwordSavingEnabled: fakeSetting(true),
    autofillAddressEnabled: fakeSetting(true, 'controlled_by_other_extensions'),
    autofillCreditCardEnabled: fakeSetting(false),
  };
  assert.deepEqual(await turnOffBrowserAutofill(fakeApi(services)), ['passwordSavingEnabled']);
  assert.deepEqual(services.passwordSavingEnabled.sets, [false]);
  assert.deepEqual(services.autofillAddressEnabled.sets, []);
  assert.deepEqual(services.autofillCreditCardEnabled.sets, []);
  // Firefox: only passwordSavingEnabled exists; no privacy API at all changes nothing.
  assert.deepEqual(await turnOffBrowserAutofill(fakeApi({ passwordSavingEnabled: fakeSetting(true) })), ['passwordSavingEnabled']);
  assert.deepEqual(await turnOffBrowserAutofill({}), []);
});

test('only the first popup changes anything, and it remembers that it did', async () => {
  const services = { passwordSavingEnabled: fakeSetting(true), autofillAddressEnabled: fakeSetting(true) };
  const api = fakeApi(services);
  assert.deepEqual(await turnOffOnFirstPopup(api), ['passwordSavingEnabled', 'autofillAddressEnabled']);
  assert.deepEqual(api.store[BROWSER_AUTOFILL_KEY].changed, ['passwordSavingEnabled', 'autofillAddressEnabled']);
  // The user turns password saving back on in the browser: later popups leave it alone.
  services.passwordSavingEnabled.value = true;
  assert.equal(await turnOffOnFirstPopup(api), null);
  assert.deepEqual(services.passwordSavingEnabled.sets, [false]);
});

test('undo hands the changed settings back to the browser', async () => {
  const services = { passwordSavingEnabled: fakeSetting(true), autofillAddressEnabled: fakeSetting(true) };
  const api = fakeApi(services);
  const changed = await turnOffOnFirstPopup(api);
  await restoreBrowserAutofill(changed, api);
  assert.equal(services.passwordSavingEnabled.cleared, 1);
  assert.equal(services.autofillAddressEnabled.cleared, 1);
  assert.equal(services.passwordSavingEnabled.value, true);
});
