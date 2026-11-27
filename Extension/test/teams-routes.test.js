// The account service routes the browser vault calls, with a fake fetch. Demo accounts and tokens only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createOrgApi, ORG_ROUTES } from '../src/background/teams/org-api.js';
import { base64Encode, createBody, createSendClient, linkBaseOf, sendView } from '../src/background/teams/send-client.js';

const BASE = 'https://account.example.test';

function fakeFetch(answers = {}) {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, method: init.method, body: init.body ? JSON.parse(init.body) : undefined });
    const a = answers[`${init.method} ${url.slice(BASE.length)}`] || { status: 200, body: {} };
    return {
      ok: a.status >= 200 && a.status < 300,
      status: a.status,
      headers: { get: (h) => (h === 'X-Pass-Error' ? a.code || null : null) },
      json: async () => a.body,
    };
  };
  return { fn, calls };
}

const account = { accessToken: async () => 'demo-token', base: async () => BASE };

test('member actions use the documented routes', async () => {
  const f = fakeFetch();
  const api = createOrgApi({ account, fetch: f.fn });
  await api.invites();
  await api.answerInvite('mem_1', true);
  await api.answerInvite('mem_2', false);
  await api.leaveOrg('org_acme');
  await api.leaveVault('org_acme', 'v/1');
  await api.deviceApprovals();
  await api.answerDevice('ap_1', true);
  await api.answerDevice('ap_2', false);
  await api.deviceApprovalEmail();
  assert.deepEqual(f.calls.map((c) => `${c.method} ${c.url.slice(BASE.length)}`), [
    'GET /v1/invites',
    'POST /v1/invites/mem_1/accept',
    'POST /v1/invites/mem_2/decline',
    'POST /v1/orgs/org_acme/leave',
    'POST /v1/orgs/org_acme/vaults/v%2F1/leave',
    'GET /v1/device-approvals',
    'POST /v1/device-approvals/ap_1/approve',
    'POST /v1/device-approvals/ap_2/deny',
    'POST /v1/device-approvals/email',
  ]);
  assert.ok(!JSON.stringify(ORG_ROUTES).includes('ASSUMED'));
});

test('a device waiting for approval carries the service answer', async () => {
  const approval = { id: 'ap_1', status: 'pending', expires_at: 1, email_sent_at: null };
  const f = fakeFetch({ 'POST /v1/cloud/devices': { status: 403, code: 'device_approval_required', body: { error: 'device_approval_required', approval } } });
  const api = createOrgApi({ account, fetch: f.fn });
  await assert.rejects(api.cloudDevice('Firefox'), (err) => err.serviceCode === 'device_approval_required' && err.data.approval.id === 'ap_1');
});

test('a send uploads the core metadata as it is, with a base64 ciphertext', async () => {
  const body = createBody({ ciphertext: new Uint8Array([1, 2, 3]), meta: '{"v":1}', key: 'secret-link-key', password_auth: '' });
  assert.deepEqual(body, { meta: '{"v":1}', ciphertext: 'AQID' });
  assert.ok(!JSON.stringify(body).includes('secret-link-key'));
  assert.equal(createBody({ ciphertext: new Uint8Array([255]), meta: 'm', password_auth: 'proof' }).password_auth, 'proof');
  assert.equal(base64Encode(new Uint8Array([251, 255])), '+/8=');
  assert.equal(linkBaseOf({ link_base: 'https://account.passyble.com/send/' }, 'x'), 'https://account.passyble.com/send');
  assert.equal(linkBaseOf({ link_base: 'javascript:alert(1)' }, `${BASE}/send`), `${BASE}/send`);
  assert.equal(linkBaseOf(null, `${BASE}/send`), `${BASE}/send`);
  const f = fakeFetch();
  const client = createSendClient({ account, fetch: f.fn });
  await client.create(body);
  await client.list();
  await client.revoke('s 1');
  assert.deepEqual(f.calls.map((c) => `${c.method} ${c.url.slice(BASE.length)}`), ['POST /v1/sends', 'GET /v1/sends', 'DELETE /v1/sends/s%201']);
});

test('a listed send follows the service state', () => {
  const now = 1_000_000;
  assert.equal(sendView({ id: 'a', state: 'active', expires_at: now + 10 }, now).expired, false);
  assert.equal(sendView({ id: 'b', state: 'viewed', expires_at: now + 10 }, now).expired, true);
  assert.equal(sendView({ id: 'c', expires_at: now - 1 }, now).state, 'expired');
});
