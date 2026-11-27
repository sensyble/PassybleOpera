// The background side of "Save card to Passyble?" (src/background/card-save.js) with a fake agent: never a
// security code kept, never the number in the banner. Test card numbers only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CARD_EDIT_PATH, CARD_KEEP_MS, CARD_SHOW_MS, createCardSave } from '../src/background/card-save.js';

const SHOP = 'https://shop.example/checkout';
const VISA = '4242424242424242';
const EXT = 'chrome-extension://pass-ext/';

function harness({ features = ['cards', 'cards.save'], settings = {}, decide = null, locked = false, kept = null } = {}) {
  const tabs = new Map();
  const calls = [];
  const sentToTop = [];
  const never = new Set();
  let clock = 1_000_000;
  const state = { locked, unlocks: 0 };
  const agent = async (method, params = {}) => {
    calls.push({ method, params });
    if (method === 'cards.list') return { locked: true, items: kept || [] };
    if (state.locked) throw Object.assign(new Error('Vault is locked'), { code: 'locked' });
    if (method === 'cards.save_check') {
      return decide ? decide(params) : { action: 'save_new', brand: 'visa', last4: params.number.slice(-4), vaults: [], default_vault: 'home' };
    }
    if (method === 'cards.save') return params.id ? { id: params.id, title: 'Visa •••• 4242', updated: true } : { id: 'new-card', title: params.title || 'Visa •••• 4242' };
    throw new Error(`unexpected ${method}`);
  };
  const cs = createCardSave({
    agent,
    withUnlock: async (fn) => {
      try { return await fn(); } catch (err) {
        if (err.code !== 'locked') throw err;
        state.unlocks++;
        state.locked = false;
        return fn();
      }
    },
    getSettings: async () => ({ cardSave: true, ...settings }),
    agentFeatures: async () => features,
    tabState: (id) => { if (!tabs.has(id)) tabs.set(id, {}); return tabs.get(id); },
    tabs,
    frameUrl: (sender) => sender.url,
    isNeverSave: async (url) => never.has(new URL(url).origin),
    addNeverSave: async (url) => { never.add(new URL(url).origin); return new URL(url).origin; },
    sendToTop: async (tabId, message) => { sentToTop.push({ tabId, message }); },
    extensionUrl: (path) => `${EXT}${path}`,
    now: () => clock,
  });
  const top = { tab: { id: 7, url: SHOP }, frameId: 0, url: SHOP };
  const call = (type, msg = {}, sender = top) => {
    const fn = cs.contentHandlers[type] || cs.pageHandlers[type];
    return fn({ type, ...msg }, sender);
  };
  const capture = (msg = {}, sender = top) => call('card.capture', {
    number: '4242 4242 4242 4242', expiry_month: 4, expiry_year: 2029, cardholder_name: 'Ada Lovelace', ...msg,
  }, sender);
  return { cs, tabs, calls, sentToTop, never, state, call, capture, top, tick: (ms) => { clock += ms; } };
}

const editSender = () => ({ tab: { id: 7, url: SHOP }, frameId: 3, url: `${EXT}${CARD_EDIT_PATH}` });

test('capture keeps number, expiry and holder in memory, never a security code; the top frame is told', async () => {
  const h = harness();
  await h.capture({ security_code: '737', cvc: '737' });
  const card = h.tabs.get(7).card;
  assert.equal(card.number, VISA);
  assert.deepEqual([card.month, card.year, card.holder, card.brand], [4, 2029, 'Ada Lovelace', 'visa']);
  assert.ok(!JSON.stringify(card).includes('737'), 'no security code kept');
  assert.deepEqual(h.sentToTop, [{ tabId: 7, message: { type: 'card.offer' } }]);
});

test('capture rules: secure pages, top or same-origin frames, valid numbers, the setting', async () => {
  const cases = [
    ['a cross-origin payment iframe', {}, { tab: { id: 7, url: SHOP }, frameId: 5, url: 'https://js.stripe.example/elements' }],
    ['an opaque frame', {}, { tab: { id: 7, url: SHOP }, frameId: 5, url: '' }],
    ['plain http', {}, { tab: { id: 7, url: 'http://shop.example/' }, frameId: 0, url: 'http://shop.example/' }],
    ['not Luhn-valid', { number: '4242424242424241' }],
    ['too short', { number: '42424242424' }],
    ['letters', { number: '4242abcd42424242' }],
  ];
  for (const [what, msg, sender] of cases) {
    const h = harness();
    await h.capture(msg, sender);
    assert.equal(h.tabs.get(7)?.card ?? null, null, what);
  }
  const off = harness({ settings: { cardSave: false } });
  await off.capture();
  assert.equal(off.tabs.get(7)?.card ?? null, null, 'Offer to save cards: off');
  const sameOrigin = harness();
  await sameOrigin.capture({}, { tab: { id: 7, url: SHOP }, frameId: 2, url: 'https://shop.example/pay-frame' });
  assert.equal(sameOrigin.tabs.get(7).card.number, VISA, 'a frame of the shop itself');
});

test('the agent decides: saved as is is nothing; the banner gets the last four digits, never the number', async () => {
  const none = harness({ decide: () => ({ action: 'none', id: 'c1', brand: 'visa', last4: '4242' }) });
  await none.capture();
  assert.equal(await none.call('card.query'), null);
  assert.equal(none.tabs.get(7).card, null, 'dropped');
  assert.deepEqual(none.calls.find((c) => c.method === 'cards.save_check').params,
    { url: SHOP, number: VISA, expiry_month: 4, expiry_year: 2029 });

  const fresh = harness();
  await fresh.capture();
  const info = await fresh.call('card.query');
  assert.equal(info.mode, 'save');
  assert.deepEqual([info.brand, info.last4, info.expiry_month, info.expiry_year, info.host], ['visa', '4242', 4, 2029, 'shop.example']);
  assert.ok(!JSON.stringify(info).includes(VISA), 'never the number');
  assert.equal(await fresh.call('card.query'), null, 'shown once');
  assert.equal(await fresh.call('card.query', {}, { ...fresh.top, frameId: 2 }), null, 'top frame only');
});

test('Update card expiry?: the saved card, then cards.save with its id', async () => {
  const h = harness({ decide: () => ({ action: 'update_expiry', id: 'c1', title: 'Visa •••• 4242', brand: 'visa', last4: '4242',
    vault: { id: 'v-team', name: 'Engineering', home: false } }) });
  await h.capture({ expiry_month: 5, expiry_year: 31 });
  const info = await h.call('card.query');
  assert.equal(info.mode, 'update');
  assert.equal(info.title, 'Visa •••• 4242');
  assert.equal(info.vault_name, 'Engineering');
  const res = await h.call('card.commit', { token: info.token });
  assert.equal(res.action, 'update_expiry');
  assert.deepEqual(h.calls.at(-1), { method: 'cards.save',
    params: { url: SHOP, number: VISA, expiry_month: 5, expiry_year: 2031, cardholder_name: 'Ada Lovelace', id: 'c1' } });
  assert.equal(h.tabs.get(7).card, null, 'the number leaves memory');
  await assert.rejects(h.call('card.commit', { token: info.token }), /Nothing to save/);
});

test('Save card: a vault offered by the agent, the edit frame\'s holder / expiry / title, no security code', async () => {
  const h = harness({ decide: () => ({ action: 'save_new', brand: 'visa', last4: '4242',
    vaults: [{ id: 'home', name: 'Mine', home: true, can_edit: true }, { id: 'v-team', name: 'Team', can_edit: true }],
    default_vault: 'home' }) });
  await h.capture();
  const info = await h.call('card.query');
  assert.deepEqual(info.vaults, { vaults: [{ id: 'home', name: 'Mine' }, { id: 'v-team', name: 'Team' }], selected: 'home' });
  // The edit frame: only that extension page in a frame of the tab, with the banner's token.
  await assert.rejects(h.call('card.edit-get', { token: info.token }, { ...editSender(), url: `${EXT}src/save/edit.html` }));
  await assert.rejects(h.call('card.edit-get', { token: info.token }, { ...editSender(), frameId: 0 }));
  await assert.rejects(h.call('card.edit-get', { token: 'guess' }, editSender()));
  const got = await h.call('card.edit-get', { token: info.token }, editSender());
  assert.deepEqual(got, { mode: 'save', holder: 'Ada Lovelace', expiry_month: 4, expiry_year: 2029, brand: 'visa', last4: '4242' });
  await assert.rejects(h.call('card.edit-set', { token: info.token, holder: 'A', expiry: '13/29', title: '' }, editSender()), /expiry/);
  await assert.rejects(h.call('card.edit-set', { token: info.token, holder: 'A', expiry: '04/29', title: 'a\nb' }, editSender()), /title/);
  await h.call('card.edit-set', { token: info.token, holder: ' Ada King ', expiry: '05/30', title: 'Travel' }, editSender());
  const res = await h.call('card.commit', { token: info.token, vault: 'v-team' });
  assert.equal(res.id, 'new-card');
  const saved = h.calls.at(-1);
  assert.equal(saved.method, 'cards.save');
  assert.deepEqual(saved.params, { url: SHOP, number: VISA, expiry_month: 5, expiry_year: 2030, cardholder_name: 'Ada King',
    title: 'Travel', vault: 'v-team' });
  assert.equal(h.calls.filter((c) => c.method === 'cards.save_check').length, 2, 'another expiry typed: checked again');
  assert.ok(!JSON.stringify(h.calls).includes('737'));
});

test('a vault the agent did not offer is not passed on', async () => {
  const h = harness();
  await h.capture();
  const info = await h.call('card.query');
  await h.call('card.commit', { token: info.token, vault: 'someone-elses' });
  assert.equal(h.calls.at(-1).params.vault, undefined);
});

test('Never for this site, Not now, and the time limits', async () => {
  const h = harness();
  await h.capture();
  let info = await h.call('card.query');
  await assert.rejects(h.call('card.never', { token: 'other' }), /Nothing to save/);
  assert.deepEqual(await h.call('card.never', { token: info.token }), { site: 'https://shop.example' });
  assert.equal(h.tabs.get(7).card, null);
  await h.capture({ number: '5555555555554444' });
  assert.equal(await h.call('card.query'), null, 'never asked again on that site');
  assert.equal(h.calls.filter((c) => c.method === 'cards.save_check').length, 1, 'the agent is not even asked');

  const later = harness();
  await later.capture();
  later.tick(CARD_SHOW_MS + 1);
  assert.equal(await later.call('card.query'), null, 'too late to show');
  const dismissed = harness();
  await dismissed.capture();
  info = await dismissed.call('card.query');
  await dismissed.call('card.dismiss', { token: info.token });
  assert.equal(dismissed.tabs.get(7).card, null);
  const expired = harness();
  await expired.capture();
  info = await expired.call('card.query');
  expired.tick(CARD_KEEP_MS + 1);
  await assert.rejects(expired.call('card.commit', { token: info.token }), /Nothing to save/);
});

test('an agent without cards.save offers nothing', async () => {
  const h = harness({ features: ['cards'] });
  await h.capture();
  assert.equal(await h.call('card.query'), null);
  assert.equal(h.calls.length, 0);
  assert.equal(h.tabs.get(7).card, null);
});

test('locked: the banner shows; Save unlocks, checks again and writes nothing for a card saved as is', async () => {
  const h = harness({ locked: true, decide: () => ({ action: 'none', id: 'c1' }) });
  await h.capture();
  const info = await h.call('card.query');
  assert.equal(info.mode, 'save', 'shown while locked');
  assert.equal(info.brand, 'visa', 'the brand from the number while locked');
  const res = await h.call('card.commit', { token: info.token });
  assert.equal(h.state.unlocks, 1);
  assert.deepEqual(res, { id: 'c1', unchanged: true, action: 'none' });
  assert.ok(!h.calls.some((c) => c.method === 'cards.save'), 'nothing written');
});

test('soft-locked with what may be this card: held until the unlock, then shown only if there is something to offer', async () => {
  const kept = [{ last4: '4242', expiry_month: 4, expiry_year: 2029, brand: 'visa' }];
  const h = harness({ locked: true, kept, decide: () => ({ action: 'update_expiry', id: 'c1', title: 'Visa •••• 4242' }) });
  await h.capture();
  assert.equal(await h.call('card.query'), null, 'held');
  h.state.locked = false;
  h.sentToTop.length = 0;
  h.cs.recheckAll();
  assert.deepEqual(h.sentToTop, [{ tabId: 7, message: { type: 'card.offer', recheck: true } }]);
  const info = await h.call('card.query', { recheck: true });
  assert.equal(info.mode, 'update');

  const saved = harness({ locked: true, kept, decide: () => ({ action: 'none', id: 'c1' }) });
  await saved.capture();
  assert.equal(await saved.call('card.query'), null);
  saved.state.locked = false;
  assert.equal(await saved.call('card.query', { recheck: true }), null, 'saved as is: nothing');
  assert.equal(saved.tabs.get(7).card, null);
});

test('a banner shown while locked goes away when the unlock shows the card is saved', async () => {
  const h = harness({ locked: true, decide: () => ({ action: 'none', id: 'c1' }) });
  await h.capture();
  assert.ok(await h.call('card.query'), 'shown (fully locked: no list to look at)');
  h.state.locked = false;
  assert.deepEqual(await h.call('card.query', { recheck: true }), { close: true });
  assert.equal(h.tabs.get(7).card, null);
});
