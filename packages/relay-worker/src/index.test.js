import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';

globalThis.WebSocketRequestResponsePair = class {
  constructor(request, response) { this.request = request; this.response = response; }
};

// The production module's only Cloudflare import is its Durable Object base.
// Substitute that base so the actual routing and forwarding code runs in Node.
const source = await readFile(new URL('./index.ts', import.meta.url), 'utf8');
const moduleSource = ts.transpile(source.replace(
  "import { DurableObject } from 'cloudflare:workers';",
  'class DurableObject { constructor(ctx, env) { this.ctx = ctx; this.env = env; } }',
), { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 });
const relay = await import(`data:text/javascript;base64,${Buffer.from(moduleSource).toString('base64')}`);
const { Tunnel } = relay;

function fixture(sockets = []) {
  const writes = [];
  let heartbeat;
  const ctx = {
    getWebSockets: () => sockets,
    setWebSocketAutoResponse: pair => { heartbeat = pair; },
    storage: {
      get: async () => undefined,
      put: async (...args) => { writes.push(args); },
    },
  };
  return { tunnel: new Tunnel(ctx, { RELAY_ORIGIN: 'https://relay.example' }), writes, heartbeat };
}

function socket() {
  return { sent: [], send(message) { this.sent.push(JSON.parse(message)); } };
}

const id = 'a'.repeat(32);
const url = `https://relay.example/t/${id}/mcp`;

test('device heartbeat is answered without waking the object', () => {
  const { heartbeat } = fixture();
  assert.equal(heartbeat.request, '{"type":"ping"}');
  assert.equal(heartbeat.response, '{"type":"pong"}');
});

test('an unclaimed tunnel rejects a secret unrelated to its public id', async () => {
  const { tunnel, writes } = fixture();
  const secret = 'x'.repeat(64);
  const requestedID = createHash('sha256').update('some other secret').digest('hex').slice(0, 32);
  const response = await tunnel.fetch(new Request(
    `https://relay.example/v1/tunnels/${requestedID}/connect`,
    { headers: { upgrade: 'websocket', authorization: `Bearer ${secret}` } },
  ));
  assert.equal(response.status, 401);
  assert.deepEqual(writes, []);
});

test('the secret-derived id lets the device claim its tunnel', async () => {
  const secret = 'x'.repeat(64);
  const digest = createHash('sha256').update(secret).digest('hex');
  const { tunnel, writes } = fixture();
  tunnel.ctx.acceptWebSocket = () => {};
  const NativeResponse = globalThis.Response;
  const NativePair = globalThis.WebSocketPair;
  globalThis.Response = function (body, options) {
    if (options?.status === 101) return { status: 101, webSocket: options.webSocket };
    return new NativeResponse(body, options);
  };
  globalThis.WebSocketPair = class { constructor() { return { client: {}, server: socket() }; } };
  try {
    const response = await tunnel.fetch(new Request(
      `https://relay.example/v1/tunnels/${digest.slice(0, 32)}/connect`,
      { headers: { upgrade: 'websocket', authorization: `Bearer ${secret}` } },
    ));
    assert.equal(response.status, 101);
    // The tunnel also remembers its own id, so it can mint pairing codes for this library.
    assert.deepEqual(writes, [['secret', digest], ['tunnel', digest.slice(0, 32)]]);
    assert.ok(tunnel.activeSocket);
  } finally {
    globalThis.Response = NativeResponse;
    globalThis.WebSocketPair = NativePair;
  }
});

test('an agent path ending in connect cannot enter the tunnel ownership handler', async () => {
  const { tunnel, writes } = fixture();
  const response = await tunnel.fetch(new Request(`https://relay.example/t/${id}/anything/connect`));
  assert.equal(response.status, 503);
  assert.deepEqual(writes.filter(([key]) => key === 'secret'), []);
});

test('a body without Content-Length is rejected before reading beyond the limit', async () => {
  const current = socket();
  const { tunnel } = fixture([current]);
  let reads = 0;
  let cancelled = false;
  const request = {
    method: 'POST', headers: new Headers(),
    body: { getReader: () => ({
      read: async () => {
        reads++;
        if (reads > 2) throw new Error('Read beyond the limit');
        return { done: false, value: new Uint8Array(1_100_000) };
      },
      cancel: async () => { cancelled = true; },
    }) },
  };
  const response = await tunnel.forward(request, new URL(url));
  assert.equal(response.status, 413);
  assert.equal(reads, 2);
  assert.equal(cancelled, true);
  assert.deepEqual(current.sent, []);
});

test('a stalled forwarded body times out and releases its reader slot', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { tunnel } = fixture([socket()]);
  let finish;
  let cancelled = false;
  const request = { headers: new Headers(), body: { getReader: () => ({
    read: () => new Promise(resolve => { finish = resolve; }),
    cancel: async () => { cancelled = true; finish({ done: true }); },
  }) } };
  const response = tunnel.forward(request, new URL(url));
  await Promise.resolve();
  t.mock.timers.tick(30_000);
  assert.equal((await response).status, 408);
  assert.equal(cancelled, true);
  assert.equal(tunnel.reading, 0);
});

test('a full pending queue refuses another request before reading its body', async () => {
  const current = socket();
  const { tunnel } = fixture([current]);
  for (let index = 0; index < 32; index++) tunnel.pending.set(index, { socket: current });
  const response = await tunnel.forward({
    headers: new Headers(),
    get body() { throw new Error('The request body should not be read'); },
  }, new URL(url));
  assert.equal(response.status, 429);
  assert.deepEqual(current.sent, []);
});

test('a bounded request reaches the current device and returns its matching reply', async () => {
  let sent;
  const delivered = new Promise(resolve => { sent = resolve; });
  const current = socket();
  current.send = message => sent(JSON.parse(message));
  const { tunnel } = fixture([current]);
  const request = new Request(url, {
    method: 'POST',
    headers: { authorization: 'Bearer agent-key', 'content-type': 'application/json' },
    body: '{"method":"tools/list"}',
  });
  const result = tunnel.forward(request, new URL(url));
  const envelope = await delivered;
  assert.equal(envelope.path, `/mcp`);
  assert.equal(envelope.headers.authorization, 'Bearer agent-key');
  assert.equal(Buffer.from(envelope.body, 'base64').toString(), '{"method":"tools/list"}');
  await tunnel.webSocketMessage(current, JSON.stringify({
    id: envelope.id, status: 200, contentType: 'application/json',
    body: Buffer.from('{"ok":true}').toString('base64'),
  }));
  const response = await result;
  assert.equal(response.status, 200);
  assert.equal(await response.text(), '{"ok":true}');
});

test('an old socket closing cannot fail or answer a new socket request', async () => {
  const oldSocket = socket();
  const newSocket = socket();
  const { tunnel } = fixture([oldSocket]);
  const resolved = new Map();
  const oldTimer = setTimeout(() => {}, 60_000);
  const newTimer = setTimeout(() => {}, 60_000);
  tunnel.pending.set(1, { socket: oldSocket, timer: oldTimer, resolve: response => resolved.set(1, response) });
  tunnel.pending.set(2, { socket: newSocket, timer: newTimer, resolve: response => resolved.set(2, response) });
  tunnel.activeSocket = newSocket;

  await tunnel.webSocketClose(oldSocket);
  assert.equal(resolved.get(1).status, 503);
  assert.equal(resolved.has(2), false);
  assert.equal(tunnel.pending.has(2), true);
  assert.equal(tunnel.activeSocket, newSocket);

  await tunnel.webSocketMessage(oldSocket, JSON.stringify({ id: 2, status: 200, body: '' }));
  assert.equal(resolved.has(2), false);
  await tunnel.webSocketMessage(newSocket, JSON.stringify({ id: 2, status: 200, body: '' }));
  assert.equal(resolved.get(2).status, 200);
});

// MARK: One library address, held writes, rate limits and the hosted agent

import { openRequest, privateKeyFromRaw, rawPublicKey, b64url } from '../../marginalia-connect/src/sealed.mjs';

function library(sockets = [], env = {}) {
  const store = new Map();
  let transaction = Promise.resolve();
  const ctx = {
    getWebSockets: () => sockets,
    setWebSocketAutoResponse: () => {},
    storage: {
      get: async key => store.get(key),
      put: async (key, value) => { store.set(key, value); },
      delete: async keys => { for (const key of [keys].flat()) store.delete(key); },
      list: async ({ prefix }) => new Map([...store].filter(([key]) => key.startsWith(prefix)).sort()),
      transaction: callback => {
        const result = transaction.then(() => callback(ctx.storage));
        transaction = result.catch(() => {});
        return result;
      },
    },
  };
  return { tunnel: new Tunnel(ctx, { RELAY_ORIGIN: 'https://relay.example', ...env }), store };
}

/// A device socket that answers every envelope through `answer(envelope)`.
function device(platform, at, answer = () => ({ status: 200, body: '' })) {
  const current = {
    platform, sent: [], tunnel: null,
    deserializeAttachment: () => ({ device: platform + at, platform, at }),
    send(message) {
      const envelope = JSON.parse(message);
      this.sent.push(envelope);
      if (typeof envelope.id !== 'number') return;
      queueMicrotask(async () => {
        const reply = await answer(envelope);
        await this.tunnel.webSocketMessage(this, JSON.stringify({ id: envelope.id, status: reply.status, body: Buffer.from(reply.body).toString('base64') }));
      });
    },
  };
  return current;
}

test('one library address routes to a Mac when one is online, else the newest device', async () => {
  const iPad = device('iPadOS', 3), mac = device('macOS', 1), iPhone = device('iOS', 2);
  const sockets = [iPhone, mac, iPad];
  const { tunnel } = library(sockets);
  tunnel.activeSocket = null;
  for (const socket of sockets) socket.tunnel = tunnel;
  await tunnel.forward(new Request(`${url}`, { method: 'POST', body: '{}' }), new URL(url));
  assert.equal(mac.sent.length, 1);
  sockets.splice(sockets.indexOf(mac), 1);
  await tunnel.forward(new Request(`${url}`, { method: 'POST', body: '{}' }), new URL(url));
  assert.equal(iPad.sent.length, 1);
  assert.equal(iPhone.sent.length, 0);
});

test('a sealed write waits for an offline library and is delivered once a device is ready', async () => {
  const sockets = [];
  const { tunnel, store } = library(sockets);
  const sealedURL = `https://relay.example/t/${id}/sealed`;
  const held = await tunnel.forward(new Request(sealedURL, { method: 'POST', headers: { 'x-marginalia-queue': '1' }, body: '{"v":1}' }), new URL(sealedURL));
  assert.equal(held.status, 202);
  const read = await tunnel.forward(new Request(sealedURL, { method: 'POST', body: '{"v":1}' }), new URL(sealedURL));
  assert.equal(read.status, 503, 'only writes marked safe to hold are held');
  assert.equal([...store.keys()].filter(key => key.startsWith('queue:')).length, 1);
  const phone = device('iOS', 1);
  phone.tunnel = tunnel;
  sockets.push(phone);
  await tunnel.webSocketMessage(phone, '{"type":"ready"}');
  assert.equal(phone.sent.length, 1);
  assert.equal(phone.sent[0].path, '/sealed');
  assert.equal(Buffer.from(phone.sent[0].body, 'base64').toString(), '{"v":1}');
  assert.equal([...store.keys()].filter(key => key.startsWith('queue:')).length, 0);
});

test('one caller cannot flood a library', async () => {
  const phone = device('iOS', 1);
  const { tunnel } = library([phone]);
  phone.tunnel = tunnel;
  let limited = 0;
  for (let index = 0; index < 125; index++) {
    const response = await tunnel.forward(new Request(url, { method: 'POST', headers: { 'cf-connecting-ip': '203.0.113.9' }, body: '{}' }), new URL(url));
    if (response.status === 429) limited++;
  }
  assert.equal(limited, 5);
});

test('a hosted-agent setting cannot run without an AI binding', async () => {
  const phone = device('iOS', 1);
  const { tunnel, store } = library([phone]);
  store.set('hosted', { token: 'mrg_hosted', key: 'unused', enabled: Date.now() });
  assert.equal(await tunnel.maybeRunHostedAgent(), 0);
  assert.deepEqual(phone.sent, []);
});

test('the hosted agent answers an open request through the sealed channel with Workers AI', async () => {
  const devicePrivate = Buffer.alloc(32, 5);
  const devicePublic = b64url(rawPublicKey(privateKeyFromRaw(devicePrivate)));
  const calls = [];
  const phone = device('iOS', 1, envelope => {
    assert.equal(envelope.path, '/sealed');
    const opened = openRequest(devicePrivate, Buffer.from(envelope.body, 'base64').toString());
    assert.equal(opened.request.headers.authorization, 'Bearer mrg_hosted');
    const { name, arguments: args } = JSON.parse(opened.request.body).params;
    calls.push({ name, args });
    const result = name === 'pending_requests' ? { requests: [{ id: 'R1', item: 'i1', kind: 'summarize', instruction: 'Summarize this item for the user.' }] }
      : name === 'get_item' ? { id: 'i1', title: 'Essay', text: 'A long essay about attention.' }
      : { state: 'applied' };
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, result: { isError: false, content: [{ type: 'text', text: JSON.stringify(result) }] } });
    return { status: 200, body: opened.sealReply({ status: 200, body }) };
  });
  const prompts = [];
  const { tunnel, store } = library([phone], { AI: { run: async (model, input) => { prompts.push({ model, input }); return { response: 'It is about attention.' }; } } });
  phone.tunnel = tunnel;
  await tunnel.webSocketMessage(phone, JSON.stringify({ type: 'hosted-agent', enabled: true, token: 'mrg_hosted', key: devicePublic }));
  assert.ok(store.get('hosted'));
  assert.deepEqual(calls.map(call => call.name), ['pending_requests', 'get_item', 'add_insight']);
  assert.equal(calls[2].args.request, 'R1');
  assert.equal(calls[2].args.text, 'It is about attention.');
  assert.match(prompts[0].input.messages[1].content, /A long essay about attention/);
  // The relay only ever carried sealed bytes, and turning it off forgets the key.
  assert.ok(!JSON.stringify(phone.sent).includes('attention'));
  await tunnel.webSocketMessage(phone, JSON.stringify({ type: 'hosted-agent', enabled: false }));
  assert.equal(store.get('hosted'), undefined);
});


for (const scenario of ['mixed', 'all-photo']) {
  test(`the hosted agent leaves photo requests pending (${scenario})`, async () => {
    const devicePrivate = Buffer.alloc(32, 7);
    const devicePublic = b64url(rawPublicKey(privateKeyFromRaw(devicePrivate)));
    // More than five photos must not consume the ordinary-request batch allowance.
    const photos = Array.from({ length: 6 }, (_, n) => ({
      id: `P${n}`, item: `photo${n}`, kind: 'question', instruction: 'Read my page.', hasPhoto: true,
    }));
    const ordinary = scenario === 'mixed' ? Array.from({ length: 6 }, (_, n) => ({
      id: `R${n}`, item: `text${n}`, kind: 'summarize', instruction: 'Summarize.',
    })) : [];
    const pending = [...photos, ...ordinary];
    const originalPhotos = structuredClone(photos);
    const calls = [];
    const phone = device('iOS', 1, envelope => {
      const opened = openRequest(devicePrivate, Buffer.from(envelope.body, 'base64').toString());
      const { name, arguments: args } = JSON.parse(opened.request.body).params;
      calls.push({ name, args });
      let result;
      if (name === 'pending_requests') result = { requests: pending };
      else if (name === 'get_item') {
        assert.ok(args.id.startsWith('text'), 'Photo content must never be fetched by the text-only agent.');
        result = { id: args.id, title: 'Synthetic essay', text: 'Synthetic ordinary text.' };
      } else if (name === 'add_insight') {
        const position = pending.findIndex(request => request.id === args.request);
        assert.ok(position >= 0 && !pending[position].hasPhoto);
        pending.splice(position, 1);
        result = { state: 'applied' };
      } else assert.fail(`Unexpected tool ${name}`);
      const body = JSON.stringify({ jsonrpc: '2.0', id: 1,
        result: { isError: false, content: [{ type: 'text', text: JSON.stringify(result) }] } });
      return { status: 200, body: opened.sealReply({ status: 200, body }) };
    });
    const prompts = [];
    const { tunnel, store } = library([phone], { AI: { run: async (model, input) => {
      prompts.push(input); return { response: 'Synthetic summary.' };
    } } });
    phone.tunnel = tunnel;
    try {
      await tunnel.webSocketMessage(phone, JSON.stringify({ type: 'hosted-agent', enabled: true,
        token: 'mrg_synthetic_hosted', key: devicePublic }));
      const expected = scenario === 'mixed' ? 5 : 0;
      assert.equal(prompts.length, expected);
      assert.equal(calls.filter(call => call.name === 'get_item').length, expected);
      assert.deepEqual(calls.filter(call => call.name === 'add_insight').map(call => call.args.request),
        ordinary.slice(0, expected).map(request => request.id));
      assert.deepEqual(pending.filter(request => request.hasPhoto), originalPhotos);
      assert.equal(pending.filter(request => !request.hasPhoto).length, ordinary.length - expected);
      const usage = [...store].filter(([key]) => key.startsWith('usage:'));
      assert.equal(usage.reduce((sum, [, value]) => sum + (value.hosted ?? 0), 0), expected);
      if (expected === 0) assert.equal(usage.length, 0);
    } finally {
      await tunnel.webSocketMessage(phone, JSON.stringify({ type: 'hosted-agent', enabled: false }));
      assert.equal(store.get('hosted'), undefined);
    }
  });
}

// MARK: Chat apps by OAuth, waking a phone, and usage

import { generateKeyPairSync } from 'node:crypto';

/// A device that serves pairing and MCP through the sealed channel, like the app.
function servingDevice(devicePrivate, state) {
  return device('iOS', 1, envelope => {
    if (envelope.path !== '/sealed') {
      state.plainCalls = (state.plainCalls ?? 0) + 1;
      return { status: 403, body: '{"error":"plain_requests_disabled"}' };
    }
    const opened = openRequest(devicePrivate, Buffer.from(envelope.body, 'base64').toString());
    const { method, path, headers, body } = opened.request;
    let reply;
    if (method === 'POST' && path === '/api/v1/pairings') {
      state.pairing = JSON.parse(body);
      state.pairingHeaders = headers;
      state.pairingBody = body;
      if (state.pairingTokens) {
        state.pairingTokens.push('mrg_' + createHash('sha256').update(`${state.token}:${state.pairingTokens.length}`).digest('hex'));
      }
      reply = { status: 200, body: JSON.stringify({ id: 'p1', code: '481-902', secret: 'pair-secret' }) };
    } else if (method === 'GET' && path === '/api/v1/pairings/p1') {
      assert.equal(headers['x-pairing-secret'], 'pair-secret');
      reply = { status: 200, body: JSON.stringify(state.approved ? { state: 'approved', token: state.pairingTokens?.at(-1) ?? state.token ?? 'mrg_chat' } : { state: state.denied ? 'denied' : 'pending' }) };
    } else if (path === '/mcp') {
      state.mcp.push({ authorization: headers.authorization, body: JSON.parse(body) });
      reply = state.reply ? state.reply(JSON.parse(body), headers) : state.revoked ? { status: 401, body: '{"error":{"code":"unauthorized"}}' }
        : { status: 200, body: JSON.stringify({ jsonrpc: '2.0', id: 1, result: { tools: [] } }) };
    } else reply = { status: 404, body: '{}' };
    return { status: 200, body: opened.sealReply(reply) };
  });
}

test('a chat app connects by OAuth: the user approves on a device, calls are sealed with that key, revocation ends it', async () => {
  const devicePrivate = Buffer.alloc(32, 6);
  const state = { approved: false, revoked: false, mcp: [] };
  const phone = servingDevice(devicePrivate, state);
  const { tunnel, store } = library([phone]);
  const tunnelSecret = 'synthetic-private-tunnel-secret';
  const secretHash = createHash('sha256').update(tunnelSecret).digest('hex');
  store.set('secret', secretHash);
  phone.tunnel = tunnel;
  await tunnel.webSocketMessage(phone, JSON.stringify({ type: 'ready', key: b64url(rawPublicKey(privateKeyFromRaw(devicePrivate))) }));
  const base = `https://relay.example/t/${id}`;
  const call = (path, init) => tunnel.fetch(new Request(base + path, init));

  const anonymous = await call('/mcp', { method: 'POST', body: '{}' });
  assert.equal(anonymous.status, 401);
  assert.match(anonymous.headers.get('www-authenticate'), /resource_metadata="https:\/\/relay\.example\/\.well-known\/oauth-protected-resource\/t\/a{32}\/mcp"/);
  const discovered = await relay.default.fetch(new Request(`https://relay.example/.well-known/oauth-authorization-server/t/${id}`), { RELAY_ORIGIN: 'https://relay.example' });
  const metadata = await discovered.json();
  assert.equal(metadata.token_endpoint, `${base}/oauth/token`);
  assert.equal(metadata.authorization_response_iss_parameter_supported, true);

  const registered = await (await call('/oauth/register', { method: 'POST', body: JSON.stringify({ client_name: 'Claude', redirect_uris: ['https://claude.ai/api/mcp/auth_callback'] }) })).json();
  assert.ok(registered.client_id.startsWith('mcc_'));
  const evil = await call('/oauth/register', { method: 'POST', body: JSON.stringify({ client_name: 'x', redirect_uris: ['javascript:alert(1)'] }) });
  assert.equal(evil.status, 400);

  const verifier = 'v'.repeat(64);
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const deniedScope = await call(`/oauth/authorize?response_type=code&client_id=${registered.client_id}&redirect_uri=${encodeURIComponent('https://claude.ai/api/mcp/auth_callback')}&code_challenge=${challenge}&code_challenge_method=S256&scope=admin&state=xyz`);
  const deniedTarget = new URL(deniedScope.headers.get('location'));
  assert.equal(deniedTarget.searchParams.get('error'), 'invalid_scope');
  assert.equal(deniedTarget.searchParams.get('iss'), base);
  assert.equal(deniedTarget.searchParams.get('state'), 'xyz');
  const authorize = await call(`/oauth/authorize?response_type=code&client_id=${registered.client_id}&redirect_uri=${encodeURIComponent('https://claude.ai/api/mcp/auth_callback')}&code_challenge=${challenge}&code_challenge_method=S256&state=xyz`);
  const page = await authorize.text();
  assert.equal(authorize.status, 200);
  assert.match(page, /481-902/);
  assert.equal(state.pairing.name, 'Claude');
  assert.match(state.pairing.client, /relay can read/);
  const expectedProof = createHmac('sha256', Buffer.from(secretHash, 'hex'))
    .update(`marginalia-oauth-pairing-v1\n${state.pairingBody}`).digest('base64url');
  assert.equal(state.pairingHeaders['x-marginalia-chat-proof'], expectedProof);
  const requestID = /request=([^"&]+)/.exec(page)[1];
  const waiting = await (await call(`/oauth/authorize/status?request=${requestID}`)).json();
  assert.match(waiting.message, /Waiting/);
  state.approved = true;
  const approved = await (await call(`/oauth/authorize/status?request=${decodeURIComponent(requestID)}`)).json();
  const redirect = new URL(approved.redirect);
  assert.equal(redirect.searchParams.get('state'), 'xyz');
  assert.equal(redirect.searchParams.get('iss'), base);
  const code = redirect.searchParams.get('code');

  const form = params => ({ method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(params).toString() });
  const wrong = await call('/oauth/token', form({ grant_type: 'authorization_code', code, client_id: registered.client_id, redirect_uri: 'https://claude.ai/api/mcp/auth_callback', code_verifier: 'w'.repeat(64) }));
  assert.equal(wrong.status, 400, 'PKCE is enforced');
  const again = await call(`/oauth/authorize/status?request=${requestID}`);
  assert.match((await again.json()).message, /expired/);

  // Start over and exchange properly.
  state.approved = false;
  const second = await (await call(`/oauth/authorize?response_type=code&client_id=${registered.client_id}&redirect_uri=${encodeURIComponent('https://claude.ai/api/mcp/auth_callback')}&code_challenge=${challenge}&code_challenge_method=S256`)).text();
  state.approved = true;
  const secondID = /request=([^"&]+)/.exec(second)[1];
  const secondCode = new URL((await (await call(`/oauth/authorize/status?request=${secondID}`)).json()).redirect).searchParams.get('code');
  const tokens = await (await call('/oauth/token', form({ grant_type: 'authorization_code', code: secondCode, client_id: registered.client_id, redirect_uri: 'https://claude.ai/api/mcp/auth_callback', code_verifier: verifier }))).json();
  assert.ok(tokens.access_token.startsWith('mca_'));
  assert.ok(!JSON.stringify(tokens).includes('mrg_chat'), 'the app never sees the device key');

  const listed = await call('/mcp', { method: 'POST', headers: { authorization: `Bearer ${tokens.access_token}`, 'content-type': 'application/json' }, body: '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' });
  assert.equal(listed.status, 200);
  assert.deepEqual((await listed.json()).result, { tools: [] });
  assert.equal(state.mcp[0].authorization, 'Bearer mrg_chat');
  assert.ok(!JSON.stringify(phone.sent).includes('tools/list'), 'the call reached the device sealed');

  const refreshed = await (await call('/oauth/token', form({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: registered.client_id }))).json();
  assert.ok(refreshed.access_token.startsWith('mca_'));
  const reused = await call('/oauth/token', form({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: registered.client_id }));
  assert.equal(reused.status, 400, 'refresh tokens rotate');

  state.revoked = true;
  const revoked = await call('/mcp', { method: 'POST', headers: { authorization: `Bearer ${refreshed.access_token}` }, body: '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' });
  assert.equal(revoked.status, 401);
  assert.equal([...store.keys()].filter(key => key.startsWith('grant:')).length, 0);
  assert.equal((await tunnel.count('requests', 0)).chat, 2);
});

test('a silent push is signed for APNs and asks only for background time', async () => {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const settings = { APNS_KEY_P8: privateKey.export({ format: 'pem', type: 'pkcs8' }), APNS_KEY_ID: 'KEY1234567', APNS_TEAM_ID: 'DEMO123456', APNS_TOPIC: 'com.example.synthetic-device' };
  let sent;
  const status = await relay.sendBackgroundPush(settings, { token: 'ab'.repeat(32), environment: 'development' }, async (url, init) => {
    sent = { url, init };
    return new Response(null, { status: 200 });
  });
  assert.equal(status, 200);
  assert.equal(sent.url, `https://api.sandbox.push.apple.com/3/device/${'ab'.repeat(32)}`);
  assert.equal(sent.init.headers['apns-push-type'], 'background');
  assert.equal(sent.init.headers['apns-priority'], '5');
  assert.equal(sent.init.headers['apns-topic'], 'com.example.synthetic-device');
  assert.deepEqual(JSON.parse(sent.init.body), { aps: { 'content-available': 1 }, marginalia: 'relay' });
  const [header, claims] = sent.init.headers.authorization.replace('bearer ', '').split('.').slice(0, 2).map(part => JSON.parse(Buffer.from(part, 'base64url')));
  assert.deepEqual(header, { alg: 'ES256', kid: 'KEY1234567' });
  assert.equal(claims.iss, 'DEMO123456');
});

test('a phone registers for wake-ups, and the device can read this month’s usage and allowance', async () => {
  const phone = device('iOS', 1);
  const { tunnel, store } = library([phone], { HOSTED_ANSWERS_PER_MONTH: '2' });
  phone.tunnel = tunnel;
  await tunnel.webSocketMessage(phone, JSON.stringify({ type: 'push-token', token: 'cd'.repeat(32), environment: 'development' }));
  assert.equal(store.get('push:iOS1').token, 'cd'.repeat(32));
  await tunnel.forward(new Request(url, { method: 'POST', body: '{}' }), new URL(url));
  await tunnel.webSocketMessage(phone, '{"type":"usage"}');
  const usage = phone.sent.find(message => message.type === 'usage');
  assert.equal(usage.requests, 1);
  assert.equal(usage.hostedAllowance, 2);
  assert.equal(usage.wake, false, 'no APNs key is configured in tests');
});

test('the wake-up check in Settings pushes only to the device that asked, and says why when it cannot', async () => {
  const phone = device('iOS', 1);
  const { tunnel } = library([phone]);
  phone.tunnel = tunnel;
  await tunnel.webSocketMessage(phone, '{"type":"push-test"}');
  assert.match(phone.sent.at(-1).reason, /not set up/);
});

// The universal front door runs the production Gateway, Tunnel and sealed crypto.
// Only Durable Object storage and the paired devices are synthetic.
const origin = 'https://relay.example';
const rootResource = `${origin}/mcp`;
const redirectUri = 'https://chat.example/callback';
const verifier = 'p'.repeat(64);
const challenge = createHash('sha256').update(verifier).digest('base64url');
const formRequest = values => ({ method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(values).toString() });

async function universalFixture({ distinctPairingKeys = false, relayAddress = origin } = {}) {
  const libraries = new Map();
  for (const [index, tunnelId] of [id, 'b'.repeat(32)].entries()) {
    const key = Buffer.alloc(32, index + 10);
    const state = { approved: false, revoked: false, mcp: [], token: `mrg_library_${index}` };
    if (distinctPairingKeys) state.pairingTokens = [];
    const phone = servingDevice(key, state);
    const sockets = [phone];
    const entry = library(sockets, { RELAY_ORIGIN: relayAddress });
    phone.tunnel = entry.tunnel;
    await entry.tunnel.webSocketMessage(phone, JSON.stringify({ type: 'ready', key: b64url(rawPublicKey(privateKeyFromRaw(key))) }));
    libraries.set(tunnelId, { ...entry, key, state, phone, sockets });
  }
  const env = { RELAY_ORIGIN: relayAddress, TUNNELS: { idFromName: name => name, get: name => libraries.get(name)?.tunnel } };
  const storage = library();
  const gateway = new relay.Gateway(storage.tunnel.ctx, env);
  env.GATEWAY = { idFromName: name => name, get: () => gateway };
  const call = (path, init) => relay.default.fetch(new Request(relayAddress + path, init), env);
  const registered = await (await call('/oauth/register', { method: 'POST', body: JSON.stringify({ client_name: 'Synthetic chat', redirect_uris: [redirectUri] }) })).json();
  return { call, gateway, store: storage.store, env, libraries, clientId: registered.client_id, origin: relayAddress };
}

async function selection(harness, overrides = {}) {
  const query = new URLSearchParams({ response_type: 'code', client_id: harness.clientId, redirect_uri: redirectUri, code_challenge: challenge,
    code_challenge_method: 'S256', resource: `${harness.origin}/mcp`, scope: 'library', state: 'synthetic-state', ...overrides });
  const path = `/oauth/authorize?${query}`;
  const response = await harness.call(path);
  const html = await response.text();
  return { response, html, path, nonce: /name="request" value="([^"]+)"/.exec(html)?.[1] };
}

async function approvedCode(harness, tunnelId = id) {
  const chosen = await selection(harness);
  const response = await harness.call('/oauth/authorize', formRequest({ request: chosen.nonce, connector: `${harness.origin}/t/${tunnelId}/mcp` }));
  assert.equal(response.status, 200);
  const html = await response.text();
  const requestId = /request=([^"&]+)/.exec(html)[1];
  const entry = harness.libraries.get(tunnelId);
  assert.equal(entry.state.approved, false);
  const pending = await (await harness.call(`/oauth/authorize/status?request=${requestId}`)).json();
  assert.match(pending.message, /Waiting for you to allow it/);
  entry.state.approved = true;
  const approved = await (await harness.call(`/oauth/authorize/status?request=${requestId}`)).json();
  const target = new URL(approved.redirect);
  assert.equal(target.origin + target.pathname, redirectUri);
  assert.equal(target.searchParams.get('state'), 'synthetic-state');
  assert.equal(target.searchParams.get('iss'), harness.origin);
  entry.state.approved = false;
  return target.searchParams.get('code');
}

const exchangeForm = (harness, code, overrides = {}) => formRequest({ grant_type: 'authorization_code', client_id: harness.clientId,
  redirect_uri: redirectUri, code_verifier: verifier, code, resource: `${harness.origin}/mcp`, ...overrides });
async function access(harness, tunnelId = id) {
  const code = await approvedCode(harness, tunnelId);
  const response = await harness.call('/oauth/token', exchangeForm(harness, code));
  assert.equal(response.status, 200);
  return response.json();
}
const mcpRequest = (token, method, params) => ({ method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
  body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, ...(params ? { params } : {}) }) });

test('synthetic OAuth clients forward distinct device keys and accepted provenance unchanged', async () => {
  // This exercises the actual OAuth/relay adapter with a simulated Core-shaped
  // device response. Core authorization and persistence have separate Swift tests.
  const h = await universalFixture({ distinctPairingKeys: true });
  const clientB = await (await h.call('/oauth/register', { method: 'POST', body: JSON.stringify({
    client_name: 'Second synthetic reader', redirect_uris: [redirectUri],
  }) })).json();
  const a = await access(h);
  const b = await access({ ...h, clientId: clientB.client_id });
  const state = h.libraries.get(id).state;
  const [deviceA, deviceB] = state.pairingTokens;
  assert.equal(state.pairingTokens.length, 2);
  assert.notEqual(deviceA, deviceB);
  const provenance = {
    id: 'suggestion-a', open: false, proposed_by: { key: 'device-key-a', name: 'Synthetic client A' },
    notes: [{ id: 'n', state: 'kept', edited: true, note_item: 'kept-note', connection: null,
      note_pointer: { item: 'kept-note', anchor: 'p0', textVersion: 'edited-version' },
      basis: [{ item: 'source', anchor: 'p1', textVersion: 'source-version', changed: false }], basis_complete: true }],
    links: [{ id: 'l', state: 'kept', edited: false, note_item: null, connection: 'connection-a',
      basis: [{ item: 'source', changed: false }], basis_complete: true,
      connection_detail: { id: 'connection-a', state: 'active', revision: 'revision-a', relation: 'expands',
        source: { item: 'kept-note', textVersion: 'edited-version', changed: false },
        target: { item: 'source', textVersion: 'source-version', changed: false }, reason: 'A user-reviewed connection.' } }],
  };
  const schema = { type: 'object', properties: { id: { type: 'string' } }, required: ['id'], additionalProperties: false };
  const revoked = new Set();
  state.reply = (message, headers) => {
    const deviceKey = headers.authorization?.replace(/^Bearer /, '');
    assert.ok(state.pairingTokens.includes(deviceKey));
    if (revoked.has(deviceKey)) return { status: 401, body: '{"error":{"code":"unauthorized"}}' };
    if (message.method === 'tools/list') return { status: 200, body: JSON.stringify({ jsonrpc: '2.0', id: message.id,
      result: { tools: [{ name: 'get_suggestion', inputSchema: schema }] } }) };
    let value;
    switch (message.params.name) {
      case 'knowledge_search': value = { pointers: [{ item: 'kept-note', title: 'Edited thought', kind: 'note',
        origin: { suggestion: 'suggestion-a', part: 'n' }, anchor: 'p0', textVersion: 'edited-version' }], total: 1 }; break;
      case 'knowledge_open': value = { item: 'kept-note', textVersion: 'edited-version', changed: false,
        passages: [{ anchor: 'p0', text: 'The exact edited and accepted thought.' }] }; break;
      case 'get_suggestion': value = provenance; break;
      default: throw new Error('Unexpected synthetic knowledge tool.');
    }
    return { status: 200, body: JSON.stringify({ jsonrpc: '2.0', id: message.id,
      result: { isError: false, content: [{ type: 'text', text: JSON.stringify(value) }] } }) };
  };
  const list = await (await h.call('/mcp', mcpRequest(b.access_token, 'tools/list'))).json();
  assert.deepEqual(list.result.tools[0].inputSchema, schema);
  const read = async (token, name, args) => {
    const request = mcpRequest(token, 'tools/call', { name, arguments: args });
    const response = await h.call('/mcp', request);
    assert.equal(response.status, 200);
    assert.deepEqual(state.mcp.at(-1).body, JSON.parse(request.body), 'the adapter preserves the device request');
    const rpc = await response.json();
    assert.equal(rpc.result.isError, false);
    return JSON.parse(rpc.result.content[0].text);
  };
  const found = await read(b.access_token, 'knowledge_search', { query: 'edited thought', limit: 2 });
  const outcome = await read(b.access_token, 'get_suggestion', { id: found.pointers[0].origin.suggestion });
  assert.deepEqual(outcome, provenance, 'accepted context is not rewritten by the OAuth adapter');
  const opened = await read(b.access_token, 'knowledge_open', { item: outcome.notes[0].note_pointer.item, anchor: 'p0',
    text_version: outcome.notes[0].note_pointer.textVersion });
  assert.equal(opened.passages[0].text, 'The exact edited and accepted thought.');
  assert.equal(state.mcp.at(-1).authorization, `Bearer ${deviceB}`);
  await read(a.access_token, 'get_suggestion', { id: provenance.id });
  assert.equal(state.mcp.at(-1).authorization, `Bearer ${deviceA}`);
  revoked.add(deviceA);
  assert.equal((await h.call('/mcp', mcpRequest(a.access_token, 'tools/call', {
    name: 'get_suggestion', arguments: { id: provenance.id },
  }))).status, 401);
  assert.deepEqual(await read(b.access_token, 'get_suggestion', { id: provenance.id }), provenance);
  assert.equal(state.mcp.at(-1).authorization, `Bearer ${deviceB}`);
  assert.equal(state.plainCalls ?? 0, 0);
});

test('universal discovery advertises the root audience, OAuth routes and a bearer challenge', async () => {
  const h = await universalFixture();
  const protectedMetadata = await (await h.call('/.well-known/oauth-protected-resource/mcp')).json();
  assert.equal(protectedMetadata.resource, rootResource);
  assert.deepEqual(protectedMetadata.authorization_servers, [origin]);
  const authMetadata = await (await h.call('/.well-known/oauth-authorization-server')).json();
  assert.equal(authMetadata.issuer, origin);
  assert.equal(authMetadata.token_endpoint, `${origin}/oauth/token`);
  assert.equal(authMetadata.revocation_endpoint, `${origin}/oauth/revoke`);
  assert.equal(authMetadata.authorization_response_iss_parameter_supported, true);
  const anonymous = await h.call('/mcp', { method: 'POST', body: '{}' });
  assert.equal(anonymous.status, 401);
  assert.match(anonymous.headers.get('www-authenticate'), /oauth-protected-resource\/mcp/);
  assert.equal(anonymous.headers.get('access-control-expose-headers'), 'www-authenticate, mcp-session-id');
  const preflight = await h.call('/mcp', { method: 'OPTIONS' });
  assert.equal(preflight.status, 204);
});

test('a configured local origin binds discovery, authorization, selection and token audience despite a forged Host', async () => {
  const local = 'http://localhost:8787';
  const h = await universalFixture({ relayAddress: local });
  const discovery = await relay.default.fetch(new Request(`${local}/.well-known/oauth-authorization-server`, {
    headers: { host: 'attacker.example' },
  }), h.env);
  assert.equal((await discovery.json()).issuer, local);
  assert.equal((await (await h.call('/.well-known/oauth-protected-resource/mcp')).json()).resource, `${local}/mcp`);
  const token = await access(h);
  assert.ok(token.access_token.startsWith('mca_'));
  const wrong = await h.call('/oauth/token', formRequest({ grant_type: 'refresh_token', refresh_token: token.refresh_token,
    client_id: h.clientId, resource: rootResource }));
  assert.equal(wrong.status, 400);
});

test('missing or invalid relay origins fail closed at the network and Durable Object auth entries', async () => {
  const h = await universalFixture();
  for (const value of [undefined, '', 'https://user:pass@relay.example', 'https://relay.example/path',
    'https://relay.example?x=1', 'https://relay.example#part', 'http://relay.example', 'javascript:alert(1)']) {
    h.env.RELAY_ORIGIN = value;
    assert.equal((await h.call('/health')).status, 503);
    assert.equal((await h.call('/.well-known/oauth-authorization-server')).status, 503);
    assert.equal((await h.gateway.fetch(new Request(`${origin}/oauth/register`))).status, 503);
    assert.equal((await h.gateway.admitChat('', '127.0.0.1')).status, 503);
  }
});

test('concurrent approval polls issue only one authorization code', async () => {
  const h = await universalFixture();
  const chosen = await selection(h);
  const page = await (await h.call('/oauth/authorize', formRequest({ request: chosen.nonce,
    connector: `${origin}/t/${id}/mcp` }))).text();
  const requestId = /request=([^"&]+)/.exec(page)[1];
  h.libraries.get(id).state.approved = true;
  const replies = await Promise.all([1, 2].map(async () => (await h.call(`/oauth/authorize/status?request=${requestId}`)).json()));
  assert.equal(replies.filter(reply => reply.redirect).length, 1);
  assert.equal([...h.store.keys()].filter(key => key.startsWith('code:')).length, 1);
});

test('universal authorization requires exact resource, registered redirect, S256 and supported scope before asking a device', async () => {
  const h = await universalFixture();
  for (const overrides of [{ resource: `${origin}/t/${id}/mcp` }, { resource: '' }, { code_challenge_method: 'plain' }, { code_challenge: 'bad' }, { scope: 'admin' }]) {
    const { response, nonce } = await selection(h, overrides);
    assert.equal(response.status, 302);
    assert.equal(nonce, undefined);
    const target = new URL(response.headers.get('location'));
    assert.ok(target.searchParams.get('error'));
    assert.equal(target.searchParams.get('iss'), origin);
    assert.equal(target.searchParams.get('state'), 'synthetic-state');
  }
  const unregistered = await selection(h, { redirect_uri: 'https://evil.example/callback' });
  assert.equal(unregistered.response.status, 400);
  assert.equal(unregistered.response.headers.get('location'), null);
  assert.equal(h.libraries.get(id).state.pairing, undefined);
});

test('connector selection rejects foreign addresses and cross-origin form posts; its nonce is one use', async () => {
  const h = await universalFixture();
  const { response: selectionPage, nonce, html } = await selection(h);
  assert.match(html, /Relay can read/);
  assert.match(html, /Your pairing code/);
  assert.doesNotMatch(html, /Advanced/, 'the sign-in page no longer sends people to a buried setting');
  assert.equal(selectionPage.headers.get('referrer-policy'), 'same-origin',
    'same-origin forms need their own Origin, while cross-origin OAuth redirects keep no Referrer');
  for (const connector of [`https://evil.example/t/${id}/mcp`, `${origin}/t/${id}/mcp?secret=x`, `${origin}/t/${id}/mcp#x`, `https://user@${new URL(origin).host}/t/${id}/mcp`, `${origin}/t/${id}/sealed`]) {
    assert.equal((await h.call('/oauth/authorize', formRequest({ request: nonce, connector }))).status, 400);
  }
  const init = formRequest({ request: nonce, connector: `${origin}/t/${id}/mcp` });
  init.headers.origin = 'https://evil.example';
  assert.equal((await h.call('/oauth/authorize', init)).status, 403);
  const nullOrigin = formRequest({ request: nonce, connector: `${origin}/t/${id}/mcp` });
  nullOrigin.headers.origin = 'null';
  assert.equal((await h.call('/oauth/authorize', nullOrigin)).status, 403);
  const selected = await Promise.all([1, 2].map(() => {
    const sameOrigin = formRequest({ request: nonce, connector: `${origin}/t/${id}/mcp` });
    sameOrigin.headers.origin = origin;
    return h.call('/oauth/authorize', sameOrigin);
  }));
  assert.deepEqual(selected.map(response => response.status).sort(), [200, 400]);
  assert.equal(selected.find(response => response.status === 200).headers.get('referrer-policy'), 'no-referrer');
  assert.equal(h.libraries.get('b'.repeat(32)).state.pairing, undefined);
});

test('an offline OAuth selector links to a fresh authorization GET and preserves client state after reconnection', async () => {
  const h = await universalFixture();
  const entry = h.libraries.get(id);
  entry.sockets.length = 0;
  const first = await selection(h);
  const form = () => formRequest({ request: first.nonce, connector: `${origin}/t/${id}/mcp` });
  const offline = await h.call('/oauth/authorize', form());
  assert.equal(offline.status, 503);
  const offlinePage = await offline.text();
  const retryHref = /<a href="([^"]+)">Try again<\/a>/.exec(offlinePage)?.[1].replaceAll('&#38;', '&');
  assert.equal(retryHref, first.path, 'retry returns to the original same-origin OAuth GET, not its spent POST');
  assert.equal((await h.call('/oauth/authorize', form())).status, 400, 'the original selection nonce remains one-use');
  assert.equal(entry.state.pairing, undefined, 'no approval was requested while iOS was offline');
  assert.equal([...entry.store.keys()].filter(key => key.startsWith('queue:')).length, 0);

  entry.sockets.push(entry.phone);
  await entry.tunnel.webSocketMessage(entry.phone, JSON.stringify({ type: 'ready',
    key: b64url(rawPublicKey(privateKeyFromRaw(entry.key))) }));
  const retried = await h.call(retryHref);
  assert.equal(retried.status, 200);
  const freshNonce = /name="request" value="([^"]+)"/.exec(await retried.text())?.[1];
  assert.ok(freshNonce && freshNonce !== first.nonce);
  const pending = await h.call('/oauth/authorize', formRequest({ request: freshNonce, connector: `${origin}/t/${id}/mcp` }));
  assert.equal(pending.status, 200);
  const requestId = /request=([^"&]+)/.exec(await pending.text())?.[1];
  assert.ok(requestId);
  entry.state.approved = true;
  const approved = await (await h.call(`/oauth/authorize/status?request=${requestId}`)).json();
  const callback = new URL(approved.redirect);
  assert.equal(callback.searchParams.get('state'), 'synthetic-state');
  assert.equal(callback.searchParams.get('iss'), origin);
  const exchanged = await h.call('/oauth/token', exchangeForm(h, callback.searchParams.get('code')));
  assert.equal(exchanged.status, 200);
  const tokens = await exchanged.json();
  assert.equal((await h.call('/mcp', mcpRequest(tokens.access_token, 'tools/list'))).status, 200);
});

test('root codes validate resource, PKCE and client binding; concurrent redemption succeeds only once', async () => {
  const h = await universalFixture();
  const code = await approvedCode(h);
  for (const overrides of [{ resource: `${origin}/t/${id}/mcp` }, { resource: '' }, { code_verifier: 'w'.repeat(64) }, { client_id: 'unregistered' }, { redirect_uri: 'https://evil.example' }]) {
    assert.equal((await h.call('/oauth/token', exchangeForm(h, code, overrides))).status, 400);
  }
  const responses = await Promise.all([1, 2].map(() => h.call('/oauth/token', exchangeForm(h, code))));
  assert.deepEqual(responses.map(response => response.status).sort(), [200, 400]);
  const tokens = await responses.find(response => response.status === 200).json();
  assert.ok(tokens.access_token.startsWith('mca_'));
  assert.ok(!JSON.stringify(tokens).includes('mrg_'));
  assert.equal([...h.store].filter(([key]) => key.startsWith('grant:')).length, 1);
});

test('root MCP grants route only to their approved library; root and tunnel tokens cannot cross audiences', async () => {
  const h = await universalFixture();
  const first = await access(h);
  const second = await access(h, 'b'.repeat(32));
  assert.equal((await h.call('/mcp', mcpRequest(first.access_token, 'tools/call', { name: 'get_item', arguments: { id: 'synthetic' } }))).status, 200);
  assert.equal(h.libraries.get(id).state.mcp.at(-1).authorization, 'Bearer mrg_library_0');
  assert.equal(h.libraries.get('b'.repeat(32)).state.mcp.length, 0);
  assert.equal((await h.call('/mcp', mcpRequest(second.access_token, 'tools/list'))).status, 200);
  assert.equal(h.libraries.get('b'.repeat(32)).state.mcp.at(-1).authorization, 'Bearer mrg_library_1');
  assert.equal((await h.call(`/t/${id}/mcp`, mcpRequest(first.access_token, 'tools/list'))).status, 401);
  const grant = [...h.store].find(([key]) => key.startsWith('grant:'));
  // Defense in depth: even a misrouted/copied session cannot authorize a resource.
  const entry = h.libraries.get(id);
  for (const [key, value] of h.store) if (key.startsWith('access:') || key === grant[0]) entry.store.set(key, value);
  assert.equal((await h.call(`/t/${id}/mcp`, mcpRequest(first.access_token, 'tools/list'))).status, 401);
  grant[1].resource = `${origin}/t/${id}/mcp`;
  assert.equal((await h.call('/mcp', mcpRequest(first.access_token, 'tools/list'))).status, 401);
});

test('root catalog curates device-authorized tools and annotates honest read/write behavior; hidden tools cannot be called', async () => {
  const h = await universalFixture();
  const tokens = await access(h);
  const entry = h.libraries.get(id);
  assert.deepEqual(entry.state.pairing.scopes, ['library.read', 'library.text', 'library.add', 'insights.write', 'suggestions.write']);
  entry.state.reply = message => ({ status: 200, body: JSON.stringify({ jsonrpc: '2.0', id: message.id, result: { tools: [
    { name: 'search_library', inputSchema: { type: 'object' } }, { name: 'collect_link' }, { name: 'add_note' }, { name: 'get_suggestion' }, { name: 'delete_item' },
  ] } }) });
  const listed = await (await h.call('/mcp', mcpRequest(tokens.access_token, 'tools/list'))).json();
  assert.deepEqual(listed.result.tools.map(tool => tool.name), ['search_library', 'add_note', 'get_suggestion']);
  for (const tool of listed.result.tools) {
    assert.equal(tool.annotations.destructiveHint, false);
    assert.deepEqual(tool.securitySchemes, [{ type: 'oauth2', scopes: ['library'] }]);
  }
  assert.equal(listed.result.tools[0].annotations.readOnlyHint, true);
  assert.equal(listed.result.tools[1].annotations.openWorldHint, false);
  assert.equal(listed.result.tools[1].annotations.idempotentHint, false);
  assert.equal(listed.result.tools[2].annotations.readOnlyHint, true);
  const before = entry.state.mcp.length;
  for (const method of ['tools/call', 'resources/list']) {
    const response = await (await h.call('/mcp', mcpRequest(tokens.access_token, method, { name: 'delete_item' }))).json();
    assert.equal(response.error.code, -32601);
  }
  assert.equal(entry.state.mcp.length, before, 'unavailable requests never reach the device');
  const collect = await (await h.call('/mcp', mcpRequest(tokens.access_token, 'tools/call', { name: 'collect_link', arguments: { url: 'https://public.example' } }))).json();
  assert.equal(collect.error.code, -32601, 'collect_link stays unavailable until the native URL-fetch boundary is hardened');
  assert.equal(entry.state.mcp.length, before);
  const malformed = await (await h.call('/mcp', mcpRequest(tokens.access_token, 'tools/call', { name: { toString: null } }))).json();
  assert.equal(malformed.error.code, -32601);
  entry.state.reply = () => ({ status: 403, body: '{"error":"insufficient_scope"}' });
  assert.equal((await h.call('/mcp', mcpRequest(tokens.access_token, 'tools/call', { name: 'add_note' }))).status, 403, 'device authorization remains authoritative');
});

test('refresh requires matching client/resource and rotates once under concurrent use; revocation invalidates all grant sessions', async () => {
  const h = await universalFixture();
  const tokens = await access(h);
  const other = await (await h.call('/oauth/register', { method: 'POST', body: JSON.stringify({ redirect_uris: [redirectUri] }) })).json();
  const refresh = overrides => formRequest({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: h.clientId, resource: rootResource, ...overrides });
  for (const overrides of [{ client_id: other.client_id }, { client_id: '' }, { resource: `${origin}/t/${id}/mcp` }]) {
    assert.equal((await h.call('/oauth/token', refresh(overrides))).status, 400);
  }
  const refreshed = await Promise.all([1, 2].map(() => h.call('/oauth/token', refresh({}))));
  assert.deepEqual(refreshed.map(response => response.status).sort(), [200, 400]);
  const next = await refreshed.find(response => response.status === 200).json();
  await h.call('/oauth/revoke', formRequest({ client_id: other.client_id, token: next.refresh_token }));
  assert.equal((await h.call('/mcp', mcpRequest(next.access_token, 'tools/list'))).status, 200);
  assert.equal((await h.call('/oauth/revoke', formRequest({ client_id: h.clientId, token: next.refresh_token }))).status, 200);
  for (const token of [tokens.access_token, next.access_token]) {
    assert.equal((await h.call('/mcp', mcpRequest(token, 'tools/list'))).status, 401);
  }
  assert.equal((await h.call('/oauth/token', formRequest({ grant_type: 'refresh_token', client_id: h.clientId, resource: rootResource, refresh_token: next.refresh_token }))).status, 400);
});

test('two chat clients work through a sealed-only device, keep separate grants and cannot retarget another library', async () => {
  const h = await universalFixture();
  const registeredB = await (await h.call('/oauth/register', { method: 'POST', body: JSON.stringify({
    client_name: 'Second synthetic chat', redirect_uris: [redirectUri],
  }) })).json();
  const clientB = { ...h, clientId: registeredB.client_id };
  const firstA = await access(h);
  const firstB = await access(clientB);
  const otherLibrary = 'b'.repeat(32);
  const firstLibrary = h.libraries.get(id).state;
  const secondLibrary = h.libraries.get(otherLibrary).state;

  const plain = await h.call(`/t/${id}/mcp`, mcpRequest(firstLibrary.token, 'tools/list'));
  assert.equal(plain.status, 403, 'the simulated device refuses direct plaintext MCP');
  assert.equal(firstLibrary.plainCalls, 1);

  for (const token of [firstA.access_token, firstB.access_token]) {
    assert.equal((await h.call(`/mcp?library=${otherLibrary}`, mcpRequest(token, 'tools/list'))).status, 200);
    assert.equal((await h.call(`/t/${otherLibrary}/mcp`, mcpRequest(token, 'tools/list'))).status, 401);
  }
  assert.equal(firstLibrary.mcp.length, 2, 'both clients reach only their approved library');
  assert.equal(firstLibrary.plainCalls, 1, 'both OAuth calls reached the device sealed');
  assert.equal(secondLibrary.mcp.length, 0);

  const refresh = (token, clientId) => formRequest({ grant_type: 'refresh_token', refresh_token: token, client_id: clientId, resource: rootResource });
  assert.equal((await h.call('/oauth/token', refresh(firstA.refresh_token, clientB.clientId))).status, 400,
    'client B cannot exchange client A’s refresh token');
  const renewedAResponse = await h.call('/oauth/token', refresh(firstA.refresh_token, h.clientId));
  assert.equal(renewedAResponse.status, 200);
  const renewedA = await renewedAResponse.json();

  assert.equal((await h.call('/oauth/revoke', formRequest({ client_id: h.clientId, token: firstA.access_token }))).status, 200);
  for (const token of [firstA.access_token, renewedA.access_token]) {
    assert.equal((await h.call('/mcp', mcpRequest(token, 'tools/list'))).status, 401);
  }
  assert.equal((await h.call('/oauth/token', refresh(renewedA.refresh_token, h.clientId))).status, 400);

  assert.equal((await h.call('/mcp', mcpRequest(firstB.access_token, 'tools/list'))).status, 200,
    'revoking client A does not revoke client B');
  const renewedBResponse = await h.call('/oauth/token', refresh(firstB.refresh_token, clientB.clientId));
  assert.equal(renewedBResponse.status, 200);
  const renewedB = await renewedBResponse.json();
  assert.equal((await h.call('/mcp', mcpRequest(renewedB.access_token, 'tools/list'))).status, 200);
  assert.equal(firstLibrary.plainCalls, 1, 'refresh and revocation did not need plaintext access');
  assert.equal(secondLibrary.mcp.length, 0);
});

test('an iOS-only library grants access online, refuses offline reads, then resumes after reconnect without sharing revocation', async () => {
  const h = await universalFixture();
  const entry = h.libraries.get(id);
  assert.equal(entry.phone.platform, 'iOS');
  const clientB = await (await h.call('/oauth/register', { method: 'POST', body: JSON.stringify({
    client_name: 'Second iOS client', redirect_uris: [redirectUri],
  }) })).json();
  const firstA = await access(h);
  const firstB = await access({ ...h, clientId: clientB.client_id });
  assert.equal((await h.call('/mcp', mcpRequest(firstA.access_token, 'tools/list'))).status, 200);

  entry.sockets.length = 0;
  const offline = await h.call('/mcp', mcpRequest(firstA.access_token, 'tools/list'));
  assert.equal(offline.status, 503);
  assert.equal((await offline.json()).error.code, 'device_offline');
  assert.equal(entry.state.mcp.length, 1, 'offline calls do not reach the device');
  const renewedAResponse = await h.call('/oauth/token', formRequest({ grant_type: 'refresh_token', client_id: h.clientId,
    refresh_token: firstA.refresh_token, resource: rootResource }));
  assert.equal(renewedAResponse.status, 200, 'OAuth refresh does not require an awake device');
  const renewedA = await renewedAResponse.json();

  entry.sockets.push(entry.phone);
  await entry.tunnel.webSocketMessage(entry.phone, JSON.stringify({ type: 'ready',
    key: b64url(rawPublicKey(privateKeyFromRaw(entry.key))) }));
  assert.equal((await h.call('/mcp', mcpRequest(renewedA.access_token, 'tools/list'))).status, 200);
  assert.equal((await h.call('/mcp', mcpRequest(firstB.access_token, 'tools/list'))).status, 200);
  assert.equal((await h.call('/oauth/revoke', formRequest({ client_id: h.clientId, token: renewedA.refresh_token }))).status, 200);
  assert.equal((await h.call('/mcp', mcpRequest(renewedA.access_token, 'tools/list'))).status, 401);
  assert.equal((await h.call('/mcp', mcpRequest(firstB.access_token, 'tools/list'))).status, 200,
    'client B remains authorized on the same iOS device');
  assert.equal(entry.state.plainCalls ?? 0, 0);
});

test('revocation on a device clears its root grant; offline or lost writes are never queued or retried', async () => {
  const h = await universalFixture();
  const tokens = await access(h);
  const entry = h.libraries.get(id);
  entry.sockets.length = 0;
  const offline = await h.call('/mcp', mcpRequest(tokens.access_token, 'tools/call', { name: 'add_note' }));
  assert.equal(offline.status, 503);
  assert.equal((await offline.json()).error.code, 'device_offline');
  assert.equal(entry.state.mcp.length, 0);
  assert.equal([...entry.store.keys()].filter(key => key.startsWith('queue:')).length, 0);
  entry.sockets.push(entry.phone);
  const sent = [];
  entry.phone.send = message => { const envelope = JSON.parse(message); sent.push(envelope); queueMicrotask(() => entry.tunnel.webSocketClose(entry.phone)); };
  const lost = await h.call('/mcp', mcpRequest(tokens.access_token, 'tools/call', { name: 'add_note', arguments: { command_id: 'synthetic-command' } }));
  assert.equal(lost.status, 503);
  assert.equal(sent.length, 1);
  assert.equal([...entry.store.keys()].filter(key => key.startsWith('queue:')).length, 0);
});

test('a denied pairing issues no code; on-device revocation and expired access tokens reject root requests', async () => {
  const h = await universalFixture();
  const chosen = await selection(h);
  const page = await (await h.call('/oauth/authorize', formRequest({ request: chosen.nonce, connector: `${origin}/t/${id}/mcp` }))).text();
  const requestId = /request=([^"&]+)/.exec(page)[1];
  h.libraries.get(id).state.denied = true;
  const denied = new URL((await (await h.call(`/oauth/authorize/status?request=${requestId}`)).json()).redirect);
  assert.equal(denied.searchParams.get('error'), 'access_denied');
  assert.equal(denied.searchParams.get('code'), null);
  assert.equal(denied.searchParams.get('iss'), origin);
  h.libraries.get(id).state.denied = false;
  const tokens = await access(h);
  h.libraries.get(id).state.revoked = true;
  assert.equal((await h.call('/mcp', mcpRequest(tokens.access_token, 'tools/list'))).status, 401);
  assert.equal([...h.store.keys()].filter(key => key.startsWith('grant:')).length, 0);
  h.libraries.get(id).state.revoked = false;
  const next = await access(h);
  for (const [key, session] of h.store) if (key.startsWith('access:')) session.expires = Date.now() - 1;
  assert.equal((await h.call('/mcp', mcpRequest(next.access_token, 'tools/list'))).status, 401);
});

test('root OAuth validates client metadata, bounds bodies and rate limits callers without exposing internal RPC', async () => {
  const h = await universalFixture();
  for (const body of [null, { redirect_uris: 'https://chat.example' }, { redirect_uris: [123] }, { redirect_uris: ['https://chat.example/#fragment'] },
    { redirect_uris: [redirectUri], token_endpoint_auth_method: 'client_secret_basic' }, { redirect_uris: [redirectUri], grant_types: ['password'] },
    { redirect_uris: [redirectUri], client_name: { toString: null } }]) {
    assert.equal((await h.call('/oauth/register', { method: 'POST', body: JSON.stringify(body) })).status, 400);
  }
  assert.equal((await h.call('/oauth/register', { method: 'POST', body: 'x'.repeat(2_000_001) })).status, 413);
  assert.equal((await h.call('/oauth/chatDeviceCall', { method: 'POST', body: '{}' })).status, 404);
  assert.equal((await h.call('/mcp', { method: 'GET' })).status, 405);
  const responses = [];
  for (let index = 0; index < 125; index++) responses.push(await h.call('/mcp', { method: 'POST', body: '{}' }));
  assert.ok(responses.some(response => response.status === 429));
});

test('unauthenticated traffic cannot consume another library grant budget; a full DCR registry recycles unused clients', async () => {
  const h = await universalFixture();
  const tokens = await access(h);
  for (const address of ['192.0.2.1', '192.0.2.2']) {
    for (let count = 0; count < 120; count++) {
      assert.equal((await h.call('/mcp', { method: 'POST', headers: { 'cf-connecting-ip': address }, body: '{}' })).status, 401);
    }
  }
  assert.equal((await h.call('/mcp', mcpRequest(tokens.access_token, 'tools/list'))).status, 200);
  for (let index = 0; index < 499; index++) h.store.set(`client:mcc_unused_${index}`, { name: 'Unused', redirectUris: [redirectUri], created: index });
  const registered = await h.call('/oauth/register', { method: 'POST', body: JSON.stringify({ redirect_uris: [redirectUri] }) });
  assert.equal(registered.status, 201);
  assert.ok(h.store.has(`client:${h.clientId}`), 'a granted client is not evicted');
  assert.equal(h.store.has('client:mcc_unused_0'), false);
  assert.equal([...h.store.keys()].filter(key => key.startsWith('client:')).length, 500);
});

test('anonymous MCP slow streams are rejected before they reserve a body reader', async () => {
  const h = await universalFixture();
  const tokens = await access(h);
  let pulls = 0;
  let cancelled = 0;
  for (let index = 0; index < 32; index++) {
    const body = new ReadableStream({ pull() { pulls++; }, cancel() { cancelled++; return new Promise(() => {}); } }, { highWaterMark: 0 });
    const request = new Request(rootResource, { method: 'POST', body, duplex: 'half' });
    assert.equal((await relay.default.fetch(request, h.env)).status, 401);
  }
  assert.equal(pulls, 0);
  assert.equal(cancelled, 32, 'early rejection cancels without awaiting a slow cancellation promise');
  assert.equal(h.gateway.reading, 0);
  assert.equal((await h.call('/mcp', mcpRequest(tokens.access_token, 'tools/list'))).status, 200);
});

test('network admission rejects unknown root bearer tokens without forwarding a body stream to the Durable Object', async () => {
  const h = await universalFixture();
  h.env.GATEWAY.get = () => ({ admitChat: h.gateway.admitChat.bind(h.gateway), fetch() { throw new Error('An unauthorized body must not enter the DO fetch pipeline'); } });
  for (const authorization of ['', 'Bearer mca_unknown', 'Bearer mrg_device_token']) {
    const response = await h.call('/mcp', { method: 'POST', headers: { authorization }, body: '{}' });
    assert.equal(response.status, 401);
    assert.match(response.headers.get('www-authenticate'), /oauth-protected-resource\/mcp/);
  }
});

test('public OAuth slow bodies have a separate reader pool from authenticated MCP', async () => {
  const h = await universalFixture();
  const tokens = await access(h);
  const streams = [];
  const pending = [];
  for (let index = 0; index < 32; index++) {
    let entered;
    const signal = new Promise(resolve => { entered = resolve; });
    const stream = new ReadableStream({ start(controller) { streams.push(controller); }, pull() { entered(); } }, { highWaterMark: 0 });
    pending.push(relay.default.fetch(new Request(`${origin}/oauth/register`, { method: 'POST', body: stream, duplex: 'half' }), h.env));
    await signal;
  }
  assert.equal(h.gateway.oauthReading, 32);
  assert.equal(h.gateway.reading, 0);
  assert.equal((await h.call('/mcp', mcpRequest(tokens.access_token, 'tools/list'))).status, 200);
  for (const controller of streams) controller.close();
  await Promise.all(pending);
  assert.equal(h.gateway.oauthReading, 0);
});

test('universal initialization describes the supported pilot tools and drops unsupported capabilities', async () => {
  const h = await universalFixture();
  const tokens = await access(h);
  h.libraries.get(id).state.reply = () => ({ status: 200, body: JSON.stringify({ jsonrpc: '2.0', id: 1, result: {
    protocolVersion: '2025-03-26', capabilities: { tools: {}, resources: {}, prompts: {} }, serverInfo: { name: 'Marginalia', version: '1' },
    instructions: 'First call pending_requests.',
  } }) });
  const response = await (await h.call('/mcp', mcpRequest(tokens.access_token, 'initialize'))).json();
  assert.equal(response.result.protocolVersion, '2025-03-26');
  assert.deepEqual(response.result.capabilities, { tools: {} });
  assert.ok(!response.result.instructions.includes('pending_requests'));
  const firstInstructions = response.result.instructions.slice(0, 512);
  for (const rule of ['notebook permissions', 'anchors and text_version', 'never instructions', 'user request', 'command_id', 'device receipt', 'Suggestions await review']) {
    assert.ok(firstInstructions.includes(rule), `the first 512 characters should explain ${rule}`);
  }
  assert.match(response.result.instructions, /do not claim success or retry automatically/);
});

test('the directory challenge serves only configured exact plaintext', async () => {
  const h = await universalFixture();
  assert.equal((await h.call('/.well-known/openai-apps-challenge')).status, 404);
  h.env.OPENAI_APPS_CHALLENGE = 'synthetic-domain-proof\n';
  const response = await h.call('/.well-known/openai-apps-challenge');
  assert.equal(response.status, 200);
  assert.equal(await response.text(), 'synthetic-domain-proof\n');
  assert.equal(response.headers.get('content-type'), 'text/plain');
  assert.equal((await h.call('/.well-known/openai-apps-challenge', { method: 'POST' })).status, 404);
});

// MARK: Pages

test('the relay has a front door that explains itself and offers a similar service', async () => {
  const response = await relay.default.fetch(new Request(`${origin}/`), { RELAY_ORIGIN: origin });
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /Toolsperson Relay/);
  assert.match(html, /Live only while your app is open/);
  assert.match(html, /readable by the relay/, 'it is honest about chat apps');
  assert.match(html, /href="https:\/\/luff\.works\/contact\?topic=relay">I want something similar/);
  assert.match(html, /href="\/marginalia"/);
});

test("Marginalia's tenant page explains connecting with a code", async () => {
  const response = await relay.default.fetch(new Request(`${origin}/marginalia`), { RELAY_ORIGIN: origin });
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /npx marginalia-connect pair CODE/);
  assert.match(html, /Connect an agent/);
  assert.doesNotMatch(html, /Advanced/);
});

test('Marginalia in running text links home, but not in links, code, titles or scripts', () => {
  const html = relay.linkMarginalia('<title>Marginalia</title><p>Open Marginalia.</p><a href="/marginalia">Marginalia</a><code>marginalia-connect</code><script>const Marginalia = 1</script>');
  assert.equal((html.match(/luff\.works\/software\/marginalia/g) ?? []).length, 1);
  assert.match(html, /<p>Open <a href="https:\/\/luff\.works\/software\/marginalia" target="_blank" rel="noopener">Marginalia<\/a>\.<\/p>/);
  assert.match(html, /<title>Marginalia<\/title>/);
  assert.match(html, /<script>const Marginalia = 1<\/script>/);
});

test('chat sign-in shows where it stands: enter the code, then allow it in Marginalia', async () => {
  const h = await universalFixture();
  const chosen = await selection(h);
  assert.match(chosen.html, /<li class="current" data-n="1" aria-current="step">Enter your code<\/li>/);
  assert.match(chosen.html, /Back to Synthetic chat/);
  assert.match(chosen.html, /href="https:\/\/luff\.works\/software\/toolsperson"/);
});

// MARK: Pairing codes

function codesFixture() {
  const store = new Map();
  let transaction = Promise.resolve();
  const ctx = { storage: {
    get: async key => store.get(key),
    put: async (key, value) => { store.set(key, value); },
    delete: async keys => { for (const key of [keys].flat()) store.delete(key); },
    transaction: callback => {
      const result = transaction.then(() => callback(ctx.storage));
      transaction = result.catch(() => {});
      return result;
    },
  } };
  return { codes: new relay.Codes(ctx, {}), store };
}

test('pairing codes are short, unambiguous and normalized from what people type', () => {
  assert.equal(relay.normalizeCode('k7q-2mf'), 'K7Q2MF');
  assert.equal(relay.normalizeCode(' K7Q 2MF '), 'K7Q2MF');
  assert.equal(relay.normalizeCode('K7Q2M0'), null, 'zero is not in the alphabet');
  assert.equal(relay.normalizeCode('K7Q2'), null);
});

test('a minted code finds its library once, and a new code replaces the old', async () => {
  const { codes } = codesFixture();
  const first = await codes.mint(id, 'device-key');
  assert.match(first.code, /^[23456789ABCDEFGHJKMNPQRSTUVWXYZ]{6}$/);
  const second = await codes.mint(id, 'device-key');
  assert.equal(await codes.spend(first.code, 'a'), null, 'the replaced code no longer works');
  assert.deepEqual(await codes.spend(second.code.toLowerCase(), 'a'), { tunnel: id, key: 'device-key' });
  assert.equal(await codes.spend(second.code, 'a'), null, 'a code works once');
});

test('concurrent code spends yield only one address', async () => {
  const { codes } = codesFixture();
  const minted = await codes.mint(id, 'device-key');
  const results = await Promise.all([codes.spend(minted.code, 'a'), codes.spend(minted.code, 'b')]);
  assert.equal(results.filter(Boolean).length, 1);
});

test('an expired code finds nothing', async () => {
  const { codes, store } = codesFixture();
  const minted = await codes.mint(id, 'device-key');
  store.get(`code:${minted.code}`).expires = Date.now() - 1;
  assert.equal(await codes.spend(minted.code, 'a'), null);
});

test('guessing codes is rate limited per address', async () => {
  const { codes } = codesFixture();
  for (let attempt = 0; attempt < 10; attempt++) assert.equal(await codes.spend('ABCDEF', 'guesser'), null);
  assert.equal(await codes.spend('ABCDEF', 'guesser'), 'limited');
  assert.equal(await codes.spend('ABCDEF', 'someone-else'), null);
});

test('a device asks for a code over its socket and gets one for its library', async () => {
  const { codes } = codesFixture();
  const entry = library([]);
  entry.tunnel.env.CODES = { idFromName: name => name, get: () => codes };
  entry.store.set('tunnel', id);
  entry.store.set('deviceKey', 'device-key');
  const phone = socket();
  await entry.tunnel.webSocketMessage(phone, JSON.stringify({ type: 'pairing-code' }));
  const reply = phone.sent.at(-1);
  assert.equal(reply.type, 'pairing-code');
  assert.deepEqual(await codes.spend(reply.code, 'a'), { tunnel: id, key: 'device-key' });
});

test('marginalia-connect spends a code to learn the library address', async () => {
  const { codes } = codesFixture();
  const minted = await codes.mint(id, 'device-key');
  const env = { RELAY_ORIGIN: origin, CODES: { idFromName: name => name, get: () => codes } };
  const response = await relay.default.fetch(new Request(`${origin}/v1/codes/${minted.code}`, { method: 'POST' }), env);
  assert.equal(response.status, 200);
  assert.equal((await response.json()).address, `https://relay.example/t/${id}#k=device-key`);
  assert.equal((await relay.default.fetch(new Request(`${origin}/v1/codes/${minted.code}`, { method: 'POST' }), env)).status, 404);
});

test('a chat app signs in with the code Marginalia shows instead of the library address', async () => {
  const h = await universalFixture();
  const { codes } = codesFixture();
  h.env.CODES = { idFromName: name => name, get: () => codes };
  const minted = await codes.mint(id, 'device-key');
  const invalidNonce = await h.call('/oauth/authorize', formRequest({ request: 'invalid', connector: minted.code }));
  assert.equal(invalidNonce.status, 400);
  assert.match(await invalidNonce.text(), /Connection expired/);
  const chosen = await selection(h);
  assert.match(chosen.html, /Your pairing code/);
  assert.doesNotMatch(chosen.html, /Advanced/);
  const wrongCode = minted.code === 'ABCDEF' ? 'BCDEFG' : 'ABCDEF';
  assert.equal((await h.call('/oauth/authorize', formRequest({ request: chosen.nonce, connector: wrongCode }))).status, 400);
  const response = await h.call('/oauth/authorize', formRequest({ request: chosen.nonce, connector: minted.code.slice(0, 3) + '-' + minted.code.slice(3) }));
  assert.equal(response.status, 200);
  assert.match(await response.text(), /Allow Synthetic chat in <a [^>]*>Marginalia<\/a>/);
});

test('racing one selector cannot spend a second pairing code', async () => {
  const h = await universalFixture();
  const { codes } = codesFixture();
  const minted = await codes.mint(id, 'device-key');
  let spends = 0;
  h.env.CODES = { idFromName: name => name, get: () => ({ spend: (...args) => { spends++; return codes.spend(...args); } }) };
  const chosen = await selection(h);
  const replies = await Promise.all([1, 2].map(() => h.call('/oauth/authorize',
    formRequest({ request: chosen.nonce, connector: minted.code }))));
  assert.deepEqual(replies.map(reply => reply.status).sort(), [200, 400]);
  assert.equal(spends, 1);
});

test('APNs requires an explicit operator topic before any provider request', async () => {
  const status = await relay.sendBackgroundPush({ APNS_KEY_P8: 'fixture', APNS_KEY_ID: 'fixture', APNS_TEAM_ID: 'DEMO123456' },
    { token: 'ab'.repeat(32), environment: 'development' }, async () => { throw new Error('No provider call allowed'); });
  assert.equal(status, 0);
});
