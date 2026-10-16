import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { SealedClient, pair, pairingCode, resolvePairingCode } from '../src/client.mjs';
import { respondOnce } from '../src/respond.mjs';
import { b64url, openRequest, parseAddress, privateKeyFromRaw, rawPublicKey, safetyCode, sealRequest } from '../src/sealed.mjs';

const devicePrivate = Buffer.alloc(32, 3);
const address = `https://relay.example/t/${'a'.repeat(32)}#k=${b64url(rawPublicKey(privateKeyFromRaw(devicePrivate)))}`;

/// A relay plus device in one fake fetch: records what the relay saw, opens the
/// sealed request as the device would, and answers with `device(request)`.
function fakeRelay(device, { online = true } = {}) {
  const seen = [];
  const fetchImpl = async (url, init) => {
    seen.push({ url, headers: init.headers, body: init.body });
    if (!online) {
      if (init.headers['x-marginalia-queue'] === '1') return new Response(JSON.stringify({ queued: 'q1' }), { status: 202 });
      return new Response(JSON.stringify({ error: { code: 'device_offline', message: 'offline' } }), { status: 503 });
    }
    const opened = openRequest(devicePrivate, init.body);
    const reply = await device(opened.request);
    return new Response(opened.sealReply({ status: reply.status ?? 200, body: JSON.stringify(reply.json) }), { status: 200 });
  };
  return { seen, fetchImpl };
}

test('the relay sees only sealed bytes: no key, path or content', async () => {
  const relay = fakeRelay(request => {
    assert.equal(request.path, '/api/v1/items/secret-item');
    assert.equal(request.headers.authorization, 'Bearer mrg_secret');
    return { json: { title: 'A private title' } };
  });
  const client = new SealedClient({ address, token: 'mrg_secret', fetchImpl: relay.fetchImpl });
  const result = await client.call('GET', '/api/v1/items/secret-item');
  assert.equal(result.json.title, 'A private title');
  const outer = JSON.stringify(relay.seen);
  assert.ok(relay.seen[0].url.endsWith('/sealed'));
  for (const secret of ['mrg_secret', 'secret-item', 'A private title']) assert.ok(!outer.includes(secret), secret);
});

test('a sealed request opens only with the device key, and replies only with the request key', () => {
  const sealed = sealRequest(rawPublicKey(privateKeyFromRaw(devicePrivate)), { method: 'GET', path: '/health' });
  assert.throws(() => openRequest(Buffer.alloc(32, 4), sealed.body));
  const opened = openRequest(devicePrivate, sealed.body);
  const other = sealRequest(rawPublicKey(privateKeyFromRaw(devicePrivate)), { method: 'GET', path: '/health' });
  assert.throws(() => other.openReply(opened.sealReply({ status: 200, body: '{}' })));
  assert.equal(sealed.openReply(opened.sealReply({ status: 200, body: '{"ok":true}' })).body, '{"ok":true}');
});

test('writes to an offline device are queued with a command id; reads say it is offline', async () => {
  const relay = fakeRelay(() => { throw new Error('unreachable'); }, { online: false });
  const client = new SealedClient({ address, token: 'mrg_x', fetchImpl: relay.fetchImpl });
  const reply = await client.mcp({ jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'add_note', arguments: { title: 't', text: 'x' } } });
  assert.match(reply.result.content[0].text, /Queued, not yet applied/);
  assert.match(reply.result.content[0].text, /command_id mc-[0-9a-f-]{36}/);
  const retry = await client.mcp({ jsonrpc: '2.0', id: 8, method: 'tools/call', params: { name: 'add_note', arguments: { text: 'x', title: 't' } } });
  assert.notEqual(/command_id (mc-[0-9a-f-]+)/.exec(retry.result.content[0].text)[1], /command_id (mc-[0-9a-f-]+)/.exec(reply.result.content[0].text)[1], 'separate identical calls remain distinct');
  assert.equal(relay.seen[0].headers['x-marginalia-queue'], '1');
  await assert.rejects(client.tool('get_item', { id: 'x' }), error => error.code === 'device_offline');
  assert.equal(relay.seen.at(-1).headers['x-marginalia-queue'], undefined);
});

test('suggest_notes is a sealed queued write with a per-call receipt id', async () => {
  const relay = fakeRelay(() => { throw new Error('unreachable'); }, { online: false });
  const client = new SealedClient({ address, token: 'mrg_x', fetchImpl: relay.fetchImpl });
  const message = { jsonrpc: '2.0', id: 11, method: 'tools/call',
    params: { name: 'suggest_notes', arguments: { notes: [], links: [] } } };
  const reply = await client.mcp(message);
  assert.match(reply.result.content[0].text, /Queued, not yet applied/);
  assert.match(reply.result.content[0].text, /command_id mc-[0-9a-f-]{36}/);
  assert.equal(relay.seen[0].headers['x-marginalia-queue'], '1');
  const opened = openRequest(devicePrivate, relay.seen[0].body);
  assert.equal(opened.request.queued, true);
  assert.equal(JSON.parse(opened.request.body).params.name, 'suggest_notes');
  assert.match(JSON.parse(opened.request.body).params.arguments.command_id, /^mc-[0-9a-f-]{36}$/);
});

test('book highlights and history pages are queued writes too', async () => {
  const relay = fakeRelay(() => { throw new Error('unreachable'); }, { online: false });
  const client = new SealedClient({ address, token: 'mrg_x', fetchImpl: relay.fetchImpl });
  for (const [name, args] of [['add_highlight', { item: 'b', quote: 'q' }],
    ['import_book_history', { source: 'Notion', books: [{ key: 'k', title: 'T' }] }]]) {
    const reply = await client.mcp({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } });
    assert.match(reply.result.content[0].text, /Queued, not yet applied/, name);
    const opened = openRequest(devicePrivate, relay.seen.at(-1).body);
    assert.equal(opened.request.queued, true, name);
  }
});

test('pairing goes through the sealed channel and saves the key privately', async () => {
  let polls = 0;
  const relay = fakeRelay(request => {
    if (request.method === 'POST') return { json: { id: 'p1', code: '123-456', secret: 's3cret' } };
    assert.equal(request.headers['x-pairing-secret'], 's3cret');
    return { json: ++polls < 2 ? { state: 'pending' } : { state: 'approved', token: 'mrg_new', scopes: ['library.read'] } };
  });
  const configPath = join(mkdtempSync(join(tmpdir(), 'mc-')), 'agent.json');
  let code;
  const config = await pair({ address, name: 'Test agent', configPath, fetchImpl: relay.fetchImpl, pollMs: 1, onCode: value => { code = value; } });
  assert.equal(code, '123-456');
  assert.equal(config.token, 'mrg_new');
  assert.equal(JSON.parse(readFileSync(configPath, 'utf8')).token, 'mrg_new');
  assert.equal(statSync(configPath).mode & 0o777, 0o600);
  assert.ok(!JSON.stringify(relay.seen).includes('mrg_new'));
});

test('respond answers each open request with the chosen agent and names the request', async () => {
  const written = [];
  const relay = fakeRelay(request => {
    const message = JSON.parse(request.body);
    const { name, arguments: args } = message.params;
    const reply = text => ({ json: { jsonrpc: '2.0', id: message.id, result: { isError: false, content: [{ type: 'text', text: JSON.stringify(text) }] } } });
    if (name === 'pending_requests') return reply({ requests: [{ id: 'R-1', item: 'i1', kind: 'question', instruction: 'Why?', title: 'Essay' },
      { id: 'R-2', item: 'i1', kind: 'question', instruction: 'Transcribe this page.', hasPhoto: true }] });
    if (name === 'get_item') return reply({ id: 'i1', title: 'Essay', text: 'Because of reasons.' });
    if (name === 'add_insight') { written.push(args); return reply({ state: 'applied' }); }
    throw new Error(name);
  });
  const client = new SealedClient({ address, token: 'mrg_x', fetchImpl: relay.fetchImpl });
  const prompts = [];
  const results = await respondOnce({ client, model: 'test-model', run: async prompt => { prompts.push(prompt); return 'Because of reasons.'; } });
  assert.deepEqual(results, [{ id: 'R-1', answered: true }]);
  assert.match(prompts[0], /Question: Why\?/);
  assert.match(prompts[0], /Because of reasons\./);
  assert.equal(written[0].request, 'R-1');
  assert.equal(written[0].command_id, 'respond-R-1');
  assert.equal(written[0].model, 'test-model');
});

test('the safety code matches the one the app computes for the same key', () => {
  assert.equal(safetyCode(rawPublicKey(privateKeyFromRaw(Buffer.alloc(32, 7)))), '03949 09555 65292 03908 31458');
});

test('a pairing code is recognised however it is typed, and an address is not a code', () => {
  assert.equal(pairingCode('k7q-2mf'), 'K7Q2MF');
  assert.equal(pairingCode('K7Q 2MF'), 'K7Q2MF');
  assert.equal(pairingCode(address), null);
  assert.equal(pairingCode('K7Q2M0'), null);
});

test('spending a pairing code at the relay returns the library address', async () => {
  const seen = [];
  const fetchImpl = async (url, init) => {
    seen.push({ url, method: init.method });
    return new Response(JSON.stringify({ address }), { status: 200 });
  };
  assert.equal(await resolvePairingCode('K7Q2MF', { relay: 'https://relay.example/', fetchImpl }), address);
  assert.deepEqual(seen, [{ url: 'https://relay.example/v1/codes/K7Q2MF', method: 'POST' }]);
});

test('a pairing code cannot redirect a sealed pairing to another relay', async () => {
  const fetchImpl = async () => new Response(JSON.stringify({ address }), { status: 200 });
  await assert.rejects(resolvePairingCode('K7Q2MF', { relay: 'https://other.example', fetchImpl }),
    /different server/);
});

test('an unknown or spent code says where to get a new one', async () => {
  const fetchImpl = async () => new Response(JSON.stringify({ error: { code: 'code_unknown', message: 'That code is not valid. Marginalia shows a new one in Agents.' } }), { status: 404 });
  await assert.rejects(resolvePairingCode('K7Q2MF', { fetchImpl }), /Marginalia shows a new one in Agents/);
});

test('library addresses accept HTTPS and local HTTP, without credentials or query strings', () => {
  const path = `/t/${'a'.repeat(32)}#k=${b64url(rawPublicKey(privateKeyFromRaw(devicePrivate)))}`;
  assert.equal(parseAddress(`https://relay.example${path}`).base, `https://relay.example/t/${'a'.repeat(32)}`);
  assert.equal(parseAddress(`http://127.0.0.1:8787${path}`).base, `http://127.0.0.1:8787/t/${'a'.repeat(32)}`);
  assert.equal(parseAddress(`http://[::1]:8787${path}`).base, `http://[::1]:8787/t/${'a'.repeat(32)}`);
  for (const invalid of [
    `ftp://localhost${path}`,
    `http://relay.example${path}`,
    `https://user:pass@relay.example${path}`,
    `https://relay.example/t/${'a'.repeat(32)}?tracking=1#k=${b64url(rawPublicKey(privateKeyFromRaw(devicePrivate)))}`,
  ]) assert.throws(() => parseAddress(invalid), invalid);
});

test('pairing-code resolution rejects non-HTTP loopback origins', async () => {
  await assert.rejects(resolvePairingCode('K7Q2MF', { relay: 'ftp://localhost/' }), /HTTPS origin/);
});
