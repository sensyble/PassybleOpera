import { test } from 'node:test';
import assert from 'node:assert/strict';
import { NativeClient, HOST_NAME } from '../src/background/native-client.js';
import { PassError } from '../src/shared/errors.js';

function event() {
  const fns = new Set();
  return { addListener: (f) => fns.add(f), removeListener: (f) => fns.delete(f), fire: (...a) => [...fns].forEach((f) => f(...a)), get size() { return fns.size; } };
}

function fakePort() {
  return {
    sent: [],
    onMessage: event(),
    onDisconnect: event(),
    closed: false,
    postMessage(m) { if (this.closed) throw new Error('Attempting to use a disconnected port object'); this.sent.push(m); },
    disconnect() { this.closed = true; },
    reply(msg) { this.onMessage.fire(msg); },
  };
}

function fakeTimers() {
  let next = 1;
  const timers = new Map();
  return {
    setTimeout: (fn, ms) => { const id = next++; timers.set(id, { fn, ms }); return id; },
    clearTimeout: (id) => timers.delete(id),
    fireAll: () => { const all = [...timers.values()]; timers.clear(); all.forEach((t) => t.fn()); },
    get count() { return timers.size; },
  };
}

function setup() {
  const ports = [];
  const names = [];
  const timers = fakeTimers();
  const client = new NativeClient({
    connect: (name) => { names.push(name); const p = fakePort(); ports.push(p); return p; },
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout,
  });
  return { client, ports, names, timers };
}

test('connects lazily to com.sensyble.pass and sends the request envelope', async () => {
  const { client, ports, names } = setup();
  assert.equal(client.connected, false);
  const p = client.request('logins.find', { url: 'https://github.com/login' });
  assert.deepEqual(names, [HOST_NAME]);
  assert.equal(HOST_NAME, 'com.sensyble.pass');
  assert.deepEqual(ports[0].sent, [{ id: 1, method: 'logins.find', params: { url: 'https://github.com/login' } }]);
  ports[0].reply({ id: 1, result: { items: [], pending_otp: null } });
  assert.deepEqual(await p, { items: [], pending_otp: null });
});

test('matches out-of-order responses by id and reuses the port', async () => {
  const { client, ports } = setup();
  const a = client.request('status');
  const b = client.request('generate', { length: 20 });
  const c = client.request('totp.get', { url: 'https://x.test' });
  assert.equal(ports.length, 1);
  assert.deepEqual(ports[0].sent.map((m) => m.id), [1, 2, 3]);
  ports[0].reply({ id: 3, result: { code: '123456' } });
  ports[0].reply({ id: 1, result: { locked: false, version: '0.1.0' } });
  ports[0].reply({ id: '2', result: { password: 'pw' } }); // string ids tolerated
  assert.deepEqual(await a, { locked: false, version: '0.1.0' });
  assert.deepEqual(await b, { password: 'pw' });
  assert.deepEqual(await c, { code: '123456' });
  assert.equal(client.pendingCount, 0);
});

test('error responses reject with a PassError carrying the protocol code', async () => {
  const { client, ports } = setup();
  const p = client.request('logins.fill', { url: 'https://a.test', id: 'x' });
  ports[0].reply({ id: 1, error: { code: 'url_mismatch', message: 'Item does not match' } });
  await assert.rejects(p, (err) => err instanceof PassError && err.code === 'url_mismatch' && err.message === 'Item does not match');
});

test('a result-less success resolves to an empty object', async () => {
  const { client, ports } = setup();
  const p = client.request('totp.popup', { url: 'https://a.test', id: '1' });
  ports[0].reply({ id: 1 });
  assert.deepEqual(await p, {});
});

test('unsolicited events go to listeners; replies for unknown ids are ignored', () => {
  const { client, ports } = setup();
  client.request('status');
  const seen = [];
  const off = client.on('lock_state', (d) => seen.push(d));
  ports[0].reply({ event: 'lock_state', data: { locked: true } });
  ports[0].reply({ event: 'something_else', data: {} });
  ports[0].reply({ id: 999, result: {} });
  ports[0].reply(null);
  off();
  ports[0].reply({ event: 'lock_state', data: { locked: false } });
  assert.deepEqual(seen, [{ locked: true }]);
  assert.equal(client.pendingCount, 1);
});

test('disconnect rejects everything pending with agent_unavailable and reconnects lazily', async () => {
  const { client, ports, names } = setup();
  const disconnects = [];
  client.on('disconnect', (d) => disconnects.push(d));
  const a = client.request('status');
  const b = client.request('unlock');
  ports[0].onDisconnect.fire({ error: { message: 'Native host has exited.' } });
  await assert.rejects(a, (e) => e.code === 'agent_unavailable' && /exited/.test(e.message));
  await assert.rejects(b, (e) => e.code === 'agent_unavailable');
  assert.equal(client.connected, false);
  assert.deepEqual(disconnects, [{ reason: 'Native host has exited.' }]);

  const c = client.request('status');
  assert.equal(names.length, 2);
  assert.equal(ports[1].sent[0].method, 'status');
  ports[1].reply({ id: ports[1].sent[0].id, result: { locked: true } });
  assert.deepEqual(await c, { locked: true });
});

test('a request lost with its port is marked portClosed; the host\'s own "not running" answer is not', async () => {
  const { client, ports } = setup();
  const answered = client.request('status');
  ports[0].reply({ id: 1, error: { code: 'agent_unavailable', message: 'The Passyble desktop app is not running' } });
  await assert.rejects(answered, (e) => e.code === 'agent_unavailable' && e.portClosed === undefined);
  const lost = client.request('logins.find', { url: 'https://a.test' });
  ports[0].onDisconnect.fire({ error: { message: 'Native host has exited.' } });
  await assert.rejects(lost, (e) => e.code === 'agent_unavailable' && e.portClosed === true);
  // The port died before the message went out (postMessage throws), and an explicit disconnect().
  client.request('status').catch(() => {});
  ports[1].closed = true;
  await assert.rejects(client.request('status'), (e) => e.portClosed === true);
  const pending = client.request('status');
  client.disconnect();
  await assert.rejects(pending, (e) => e.portClosed === true);
  // Not even a port: nothing was lost with one.
  const none = new NativeClient({ connect: () => { throw new Error('nativeMessaging permission missing'); } });
  await assert.rejects(none.request('status'), (e) => e.code === 'agent_unavailable' && e.portClosed === undefined);
});

test('a disconnect of a stale port does not affect the current one', async () => {
  const { client, ports } = setup();
  client.request('status').catch(() => {});
  ports[0].onDisconnect.fire({});
  const p = client.request('status');
  ports[0].onDisconnect.fire({}); // late event from the old port
  assert.equal(client.connected, true);
  ports[1].reply({ id: ports[1].sent[0].id, result: { ok: 1 } });
  assert.deepEqual(await p, { ok: 1 });
});

test('host-not-found surfaces as agent_unavailable via runtime.lastError', async () => {
  const port = fakePort();
  const client = new NativeClient({ connect: () => port, lastError: () => ({ message: 'Specified native messaging host not found.' }) });
  const p = client.request('status');
  port.onDisconnect.fire(undefined);
  await assert.rejects(p, (e) => e.code === 'agent_unavailable' && /not found/.test(e.message));
});

test('connect throwing rejects with agent_unavailable', async () => {
  const client = new NativeClient({ connect: () => { throw new Error('nativeMessaging permission missing'); } });
  await assert.rejects(client.request('status'), (e) => e.code === 'agent_unavailable' && /permission/.test(e.message));
});

test('postMessage failure rejects and drops the port', async () => {
  const { client, ports } = setup();
  client.request('status').catch(() => {});
  ports[0].closed = true;
  await assert.rejects(client.request('status'), (e) => e.code === 'agent_unavailable');
  assert.equal(client.connected, false);
});

test('timeouts reject with timeout (not agent_unavailable) and late replies are ignored', async () => {
  const { client, ports, timers } = setup();
  const p = client.request('status');
  assert.equal(timers.count, 1);
  timers.fireAll();
  await assert.rejects(p, (e) => e.code === 'timeout' && /in time/.test(e.message));
  assert.equal(client.connected, true, 'a timeout keeps the port: Passyble is running');
  ports[0].reply({ id: 1, result: {} });
  assert.equal(client.pendingCount, 0);
});

test('methods that can wait for Windows Hello or a confirmation get long timeouts', () => {
  const { client, timers } = setup();
  const seen = [];
  const st = timers.setTimeout;
  client._setTimeout = (fn, ms) => { seen.push(ms); return st(fn, ms); };
  const long = { 'logins.fill': 3, 'logins.fill_cross': 3, 'logins.copy': 3, 'totp.get': 3, 'totp.popup': 3, 'cards.fill': 3, 'server.pair': 10, unlock: 10 };
  for (const method of Object.keys(long)) client.request(method).catch(() => {});
  client.request('status').catch(() => {});
  assert.deepEqual(seen, [...Object.values(long).map((min) => min * 60_000), 30_000]);
  timers.fireAll();
});

test('settling a request clears its timer', async () => {
  const { client, ports, timers } = setup();
  const p = client.request('status');
  ports[0].reply({ id: 1, result: {} });
  await p;
  assert.equal(timers.count, 0);
});

test('explicit disconnect() closes the port and rejects pending', async () => {
  const { client, ports } = setup();
  const p = client.request('status');
  client.disconnect();
  assert.equal(ports[0].closed, true);
  await assert.rejects(p, (e) => e.code === 'agent_unavailable');
});
