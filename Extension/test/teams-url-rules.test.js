// Website rules (Item.url_rules) in the browser vault's shared vaults (background/teams/multi.js): what the
// editor gets and saves, and the rule-free summaries a pick by hand and the save banner go by.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyFields, urlRulesOf, withoutRules } from '../src/background/teams/multi.js';

const ITEM = { id: 'demo', kind: 'login', urls: ['https://example.com', 'https://shop.example.com'],
  url_rules: [{ url: 'https://shop.example.com', rule: 'never' }] };

test('urlRulesOf: only rules that are not the default, of websites the item has', () => {
  assert.deepEqual(urlRulesOf({ urls: ['https://a.example'], url_rules: [
    { url: 'https://a.example', rule: 'host', note: 'x' }, { url: 'https://a.example', rule: 'subdomains' },
    { url: 'https://gone.example', rule: 'never' }, { url: 'https://a.example', rule: 'sometimes' }, null] }),
  [{ url: 'https://a.example', rule: 'host' }]);
  assert.deepEqual(urlRulesOf({ urls: ['https://a.example'] }), []);
});

test('applyFields: url_rules replaces every rule; without it the item keeps its rules', () => {
  const kept = applyFields(ITEM, { title: 'Demo' });
  assert.deepEqual(kept.url_rules, ITEM.url_rules);
  const changed = applyFields(ITEM, { urls: ['https://example.com'], url_rules: [{ url: 'https://example.com', rule: 'host' },
    { url: 'https://shop.example.com', rule: 'never' }] });
  assert.deepEqual(changed.url_rules, [{ url: 'https://example.com', rule: 'host' }], 'a removed website loses its rule');
  assert.deepEqual(applyFields(ITEM, { url_rules: [] }).url_rules, []);
});

test('withoutRules: the summaries match as if no website had a rule; nothing else changes', () => {
  const summaries = { vault_id: 'v1', can_edit: true, summaries: [{ id: 'demo', title: 'Demo', urls: ITEM.urls, url_rules: ITEM.url_rules }] };
  assert.deepEqual(withoutRules(summaries), { vault_id: 'v1', can_edit: true, summaries: [{ id: 'demo', title: 'Demo', urls: ITEM.urls }] });
  assert.equal(summaries.summaries[0].url_rules, ITEM.url_rules, 'the original is left as it was');
  assert.equal(withoutRules(undefined), undefined);
});
