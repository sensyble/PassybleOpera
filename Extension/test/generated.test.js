import { test } from 'node:test';
import assert from 'node:assert/strict';
import { GENERATED_TTL_MS, autoSavePlan, createGeneratedPasswords } from '../src/background/generated.js';

test('a generated password matches only for the origin it was filled into, and exactly', async () => {
  const g = createGeneratedPasswords();
  await g.remember('https://shop.example', 'Gen-Pass-1');
  assert.equal(await g.matches('https://shop.example', 'Gen-Pass-1'), true);
  assert.equal(await g.matches('https://evil.example', 'Gen-Pass-1'), false, 'another origin');
  assert.equal(await g.matches('https://shop.example', 'gen-pass-1'), false, 'case counts');
  assert.equal(await g.matches('https://shop.example', 'Gen-Pass-1 '), false, 'no trimming');
  assert.equal(await g.matches('https://shop.example', ''), false);
  // Nothing for an opaque origin or an empty password.
  await g.remember('null', 'Gen-Pass-2');
  await g.remember('https://shop.example', '');
  assert.equal(g.size, 1);
});

test('generated passwords expire after 30 minutes', async () => {
  let now = 1_000_000;
  const g = createGeneratedPasswords({ now: () => now });
  await g.remember('https://shop.example', 'Gen-Pass-1');
  now += GENERATED_TTL_MS - 1;
  assert.equal(await g.matches('https://shop.example', 'Gen-Pass-1'), true, 'just before');
  now += 1;
  assert.equal(await g.matches('https://shop.example', 'Gen-Pass-1'), false, 'expired');
  assert.equal(g.size, 0, 'and forgotten');
  assert.equal(GENERATED_TTL_MS, 30 * 60_000);
});

test('generated passwords: generating again keeps the newest few; the same one again is refreshed', async () => {
  let now = 0;
  const g = createGeneratedPasswords({ now: () => now });
  for (let i = 0; i < 12; i++) { now += 1000; await g.remember('https://shop.example', `Gen-${i}`); }
  assert.equal(g.size, 8);
  assert.equal(await g.matches('https://shop.example', 'Gen-0'), false, 'the oldest is dropped');
  assert.equal(await g.matches('https://shop.example', 'Gen-11'), true);
  now += GENERATED_TTL_MS - 500;
  await g.remember('https://shop.example', 'Gen-11');
  now += 1000;
  assert.equal(await g.matches('https://shop.example', 'Gen-11'), true, 'refreshed');
  assert.equal(await g.matches('https://shop.example', 'Gen-10'), false);
});

test('autoSavePlan: create, update or ask', () => {
  // A login of the site with this username (or the one a change form changes): its password is updated.
  assert.equal(autoSavePlan({ action: 'update_password', id: 'gh' }, { username: 'octo' }), 'update');
  assert.equal(autoSavePlan({ action: 'update_password', id: 'gh' }, { username: '' }), 'update');
  assert.equal(autoSavePlan({ action: 'update_password' }, { username: 'octo' }), 'prompt', 'no id: ask');
  // No login of the site yet, or a new account (another username): a new login.
  assert.equal(autoSavePlan({ action: 'save_new' }, { username: 'me@x.test' }), 'create');
  assert.equal(autoSavePlan({ action: 'save_new' }, { username: '', siteLogins: 0 }), 'create');
  // No username and logins of the site already (several, or unknown): which one? Ask.
  assert.equal(autoSavePlan({ action: 'save_new' }, { username: '  ', siteLogins: 2 }), 'prompt');
  assert.equal(autoSavePlan({ action: 'save_new' }, { username: '', siteLogins: 1 }), 'prompt');
  assert.equal(autoSavePlan({ action: 'save_new' }, { username: '', siteLogins: null }), 'prompt');
  // A username change, locked (unknown), anything else: ask.
  assert.equal(autoSavePlan({ action: 'update_username', id: 'x' }, { username: 'new' }), 'prompt');
  assert.equal(autoSavePlan(null, { username: 'me' }), 'prompt');
  assert.equal(autoSavePlan({ action: 'something_new' }, { username: 'me' }), 'prompt');
});
