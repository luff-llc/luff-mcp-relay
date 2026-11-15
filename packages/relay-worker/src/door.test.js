import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';

globalThis.WebSocketRequestResponsePair = class {
  constructor(request, response) { this.request = request; this.response = response; }
};

// Same harness as index.test.js: the real module, with only its Durable Object base substituted.
const source = await readFile(new URL('./index.ts', import.meta.url), 'utf8');
const moduleSource = ts.transpile(source.replace(
  "import { DurableObject } from 'cloudflare:workers';",
  'class DurableObject { constructor(ctx, env) { this.ctx = ctx; this.env = env; } }',
), { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 });
const relay = await import(`data:text/javascript;base64,${Buffer.from(moduleSource).toString('base64')}`);

const ORIGIN = 'https://relay.example';
const AUDIENCE = `${ORIGIN}/door/mcp`;
const JWKS = 'https://id.example/oauth/jwks';
const UPSTREAM = 'https://galley.example/mcp';
const METADATA = `${ORIGIN}/.well-known/oauth-protected-resource/door/mcp`;
const DOOR_ENV = { DOOR_ISSUER: 'https://id.example', DOOR_JWKS_URL: JWKS, DOOR_UPSTREAM_MCP: UPSTREAM };
const encoder = new TextEncoder();
const b64u = bytes => Buffer.from(bytes).toString('base64url');
const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const publicJWK = await crypto.subtle.exportKey('jwk', pair.publicKey);
const goodKey = { kty: 'EC', crv: 'P-256', x: publicJWK.x, y: publicJWK.y, kid: 'k1', alg: 'ES256', use: 'sig' };
const jsonReply = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

/// A Gateway whose storage records any touch at all, so tests can prove the door never stores.
function makeRig(extraEnv = {}, { door = true } = {}) {
  relay.resetDoorKeys();
  const touched = [];
  const names = [];
  const instances = {};
  const ctx = {
    getWebSockets: () => [],
    setWebSocketAutoResponse: () => {},
    storage: new Proxy({}, { get: (_, name) => { touched.push(name); return async () => undefined; } }),
  };
  const env = { RELAY_ORIGIN: ORIGIN, ...(door ? DOOR_ENV : {}), ...extraEnv };
  env.GATEWAY = {
    idFromName: name => { names.push(name); return name; },
    get: id => (instances[id] ??= new relay.Gateway(ctx, env)),
  };
  const clock = { t: Date.now() };
  const calls = { jwks: [], upstream: [] };
  const state = {
    jwks: () => jsonReply({ keys: [goodKey] }),
    upstream: () => jsonReply({ jsonrpc: '2.0', id: 1, result: {} }),
  };
  const fetchImpl = async (url, init) => {
    if (url === JWKS || String(url).includes('/jwks')) { calls.jwks.push({ url, init }); return state.jwks(); }
    calls.upstream.push({ url, init });
    return state.upstream(init);
  };
  const seams = { fetchImpl, now: () => clock.t };
  return { env, touched, names, clock, calls, state, seams };
}

async function sign(claims = {}, { header = {}, key = pair.privateKey, mutate } = {}, rig) {
  const now = Math.floor((rig?.clock.t ?? Date.now()) / 1000);
  const body = {
    iss: 'https://id.example', aud: AUDIENCE, sub: 'person-1', act: { sub: 'app-1' }, amr: ['hosted_oauth'],
    iat: now, exp: now + 300, ...claims,
  };
  for (const [name, value] of Object.entries(body)) if (value === undefined) delete body[name];
  const head = { alg: 'ES256', typ: 'at+jwt', kid: 'k1', ...header };
  for (const [name, value] of Object.entries(head)) if (value === undefined) delete head[name];
  const input = `${b64u(encoder.encode(JSON.stringify(head)))}.${b64u(encoder.encode(JSON.stringify(body)))}`;
  const signature = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, encoder.encode(input)));
  if (mutate) mutate(signature);
  return `${input}.${b64u(signature)}`;
}

const RPC = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'anything', arguments: {} } };
async function door(rig, { token, body = JSON.stringify(RPC), headers = {}, method = 'POST', authorization } = {}) {
  const sent = { ...headers };
  const auth = authorization ?? (token === undefined ? undefined : `Bearer ${token}`);
  if (auth !== undefined) sent.authorization = auth;
  if (method === 'POST') sent['content-type'] ??= 'application/json';
  const request = new Request(`${ORIGIN}/door/mcp`, { method, headers: sent, body: method === 'POST' ? body : undefined });
  return relay.handleDoor(request, rig.env, ORIGIN, relay.doorConfig(rig.env), rig.seams);
}
const goodToken = (rig, claims = {}) => sign(claims, {}, rig);
const route = (env, path, init) => relay.default.fetch(new Request(`${ORIGIN}${path}`, init), env);

// MARK: off

test('door off: the door paths answer exactly the unknown-route response, and OPTIONS still 204', async () => {
  const { env } = makeRig({}, { door: false });
  const unknown = await route(env, '/nowhere', { method: 'POST', body: '{}' });
  assert.equal(unknown.status, 404);
  const expected = { status: 404, headers: [...unknown.headers], body: await unknown.text() };
  assert.equal(expected.body, '{"error":{"code":"not_found","message":"Unknown route."}}');
  for (const [path, method] of [['/door/mcp', 'POST'], ['/door/mcp', 'GET'], ['/door/', 'POST'], ['/door/other', 'GET'], ['/.well-known/oauth-protected-resource/door/mcp', 'GET']]) {
    const reply = await route(env, path, { method, body: method === 'POST' ? '{}' : undefined });
    assert.deepEqual({ status: reply.status, headers: [...reply.headers], body: await reply.text() }, expected, `${method} ${path}`);
  }
  for (const path of ['/door/mcp', '/.well-known/oauth-protected-resource/door/mcp']) {
    assert.equal((await route(env, path, { method: 'OPTIONS' })).status, 204);
  }
});

const offCases = {
  'no issuer': { DOOR_ISSUER: undefined },
  'no jwks': { DOOR_JWKS_URL: undefined },
  'no upstream': { DOOR_UPSTREAM_MCP: undefined },
  'issuer with a path': { DOOR_ISSUER: 'https://id.example/x' },
  'issuer with a trailing slash': { DOOR_ISSUER: 'https://id.example/' },
  'issuer over plain http': { DOOR_ISSUER: 'http://id.example', DOOR_JWKS_URL: 'http://id.example/oauth/jwks' },
  'jwks on another origin': { DOOR_JWKS_URL: 'https://keys.example/oauth/jwks' },
  'jwks with a query': { DOOR_JWKS_URL: `${JWKS}?a=1` },
  'jwks with credentials': { DOOR_JWKS_URL: 'https://u:p@id.example/oauth/jwks' },
  'jwks with a fragment': { DOOR_JWKS_URL: `${JWKS}#x` },
  'upstream over plain http': { DOOR_UPSTREAM_MCP: 'http://galley.example/mcp' },
  'upstream with a fragment': { DOOR_UPSTREAM_MCP: `${UPSTREAM}#x` },
  'upstream with credentials': { DOOR_UPSTREAM_MCP: 'https://u:p@galley.example/mcp' },
  'upstream not a url': { DOOR_UPSTREAM_MCP: 'galley' },
  'a bad scope': { DOOR_SCOPES: 'ok bad/scope' },
  'too many scopes': { DOOR_SCOPES: 'a b c d e f g h i' },
};
for (const [name, change] of Object.entries(offCases)) {
  test(`door off: ${name}`, async () => {
    const { env } = makeRig(change);
    for (const [path, method] of [['/door/mcp', 'POST'], ['/.well-known/oauth-protected-resource/door/mcp', 'GET']]) {
      const reply = await route(env, path, { method, body: method === 'POST' ? '{}' : undefined });
      assert.equal(reply.status, 404);
      assert.equal(await reply.text(), '{"error":{"code":"not_found","message":"Unknown route."}}');
    }
  });
}

test('door on: loopback http is allowed for all three addresses', async () => {
  const { env } = makeRig({ DOOR_ISSUER: 'http://localhost:9000', DOOR_JWKS_URL: 'http://localhost:9000/jwks', DOOR_UPSTREAM_MCP: 'http://127.0.0.1:9100/mcp' });
  assert.equal((await route(env, '/.well-known/oauth-protected-resource/door/mcp')).status, 200);
});

// MARK: metadata

test('metadata without scopes, built from configuration and ignoring Host', async () => {
  const { env } = makeRig();
  const reply = await route(env, '/.well-known/oauth-protected-resource/door/mcp', { headers: { host: 'evil.example', 'x-forwarded-host': 'evil.example' } });
  assert.equal(reply.status, 200);
  assert.equal(reply.headers.get('access-control-allow-origin'), '*');
  assert.deepEqual(await reply.json(), {
    resource: AUDIENCE, authorization_servers: ['https://id.example'], bearer_methods_supported: ['header'], resource_name: 'The door',
  });
  const foreign = await relay.default.fetch(new Request('https://evil.example/.well-known/oauth-protected-resource/door/mcp'), env);
  assert.equal((await foreign.json()).resource, AUDIENCE);
});

test('metadata with scopes', async () => {
  const { env } = makeRig({ DOOR_SCOPES: 'projects:read projects.write' });
  const body = await (await route(env, '/.well-known/oauth-protected-resource/door/mcp')).json();
  assert.deepEqual(body.scopes_supported, ['projects:read', 'projects.write']);
});

// MARK: tokens

test('no token: 401 with a challenge without error=, and nothing contacted', async () => {
  const rig = makeRig();
  const reply = await door(rig);
  assert.equal(reply.status, 401);
  assert.equal(reply.headers.get('www-authenticate'), `Bearer resource_metadata="${METADATA}"`);
  assert.equal(reply.headers.get('access-control-allow-origin'), '*');
  assert.deepEqual(await reply.json(), { error: 'invalid_token', error_description: 'Sign in again to use this connection.' });
  assert.equal(rig.calls.upstream.length, 0);
  assert.equal(rig.calls.jwks.length, 0);
});

test('the challenge carries the scopes, and error= once a token was presented', async () => {
  const rig = makeRig({ DOOR_SCOPES: 'a b' });
  assert.equal((await door(rig)).headers.get('www-authenticate'), `Bearer resource_metadata="${METADATA}", scope="a b"`);
  assert.equal((await door(rig, { authorization: 'Basic abc' })).headers.get('www-authenticate'),
    `Bearer resource_metadata="${METADATA}", scope="a b", error="invalid_token"`);
});

test('a good token: body, Authorization and headers pass through exactly, and the reply comes back unchanged', async () => {
  const rig = makeRig();
  const token = await goodToken(rig);
  const bytes = Buffer.from('{ "jsonrpc" : "2.0",\n  "id":7, "method":"tools/call",\t"params":{"name":"find","arguments":{"q":"café ✓ 日本"}}  }\n');
  rig.state.upstream = () => new Response('{"ok":true}', { status: 201, headers: {
    'content-type': 'application/json', 'mcp-session-id': 'sess-1', 'cache-control': 'no-store', 'retry-after': '3', 'set-cookie': 'a=b', 'x-internal': '1',
  } });
  const reply = await door(rig, { token, body: bytes, headers: {
    accept: 'application/json, text/event-stream', 'mcp-session-id': 'sess-0', 'mcp-protocol-version': '2025-06-18',
    cookie: 'c=1', origin: 'https://chat.example', 'user-agent': 'chat', 'x-forwarded-for': '9.9.9.9', 'cf-connecting-ip': '9.9.9.9', 'x-pairing-secret': 's',
  } });
  assert.equal(rig.calls.upstream.length, 1);
  const { url, init } = rig.calls.upstream[0];
  assert.equal(url, UPSTREAM);
  assert.equal(init.method, 'POST');
  assert.equal(init.redirect, 'manual');
  assert.ok(init.signal instanceof AbortSignal);
  assert.ok(Buffer.from(init.body).equals(bytes));
  assert.equal(init.headers.get('authorization'), `Bearer ${token}`);
  assert.deepEqual([...init.headers.keys()].sort(), ['accept', 'authorization', 'content-type', 'mcp-protocol-version', 'mcp-session-id']);
  assert.equal(reply.status, 201);
  assert.equal(await reply.text(), '{"ok":true}');
  for (const [name, value] of [['content-type', 'application/json'], ['mcp-session-id', 'sess-1'], ['cache-control', 'no-store'], ['retry-after', '3'], ['access-control-allow-origin', '*']]) {
    assert.equal(reply.headers.get(name), value, name);
  }
  assert.equal(reply.headers.get('set-cookie'), null);
  assert.equal(reply.headers.get('x-internal'), null);
});

test('an event-stream reply is streamed, not buffered', async () => {
  const rig = makeRig();
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  rig.state.upstream = () => new Response(new ReadableStream({
    async start(controller) {
      controller.enqueue(encoder.encode('event: message\ndata: {"a":1}\n\n'));
      await gate;
      controller.enqueue(encoder.encode('data: {"b":2}\n\n'));
      controller.close();
    },
  }), { headers: { 'content-type': 'text/event-stream' } });
  const reply = await door(rig, { token: await goodToken(rig), headers: { accept: 'text/event-stream' } });
  assert.equal(reply.headers.get('content-type'), 'text/event-stream');
  const reader = reply.body.getReader();
  assert.equal(new TextDecoder().decode((await reader.read()).value), 'event: message\ndata: {"a":1}\n\n');
  release();
  assert.equal(new TextDecoder().decode((await reader.read()).value), 'data: {"b":2}\n\n');
});

test("the upstream's tool error passes through unchanged", async () => {
  const rig = makeRig();
  const error = '{"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[{"type":"text","text":"No such project."}]}}';
  rig.state.upstream = () => new Response(error, { headers: { 'content-type': 'application/json' } });
  const reply = await door(rig, { token: await goodToken(rig) });
  assert.equal(reply.status, 200);
  assert.equal(await reply.text(), error);
});

test("the upstream's own 401 and its challenge pass through as they are", async () => {
  const rig = makeRig();
  const challenge = 'Bearer resource_metadata="https://galley.example/.well-known/oauth-protected-resource", error="invalid_token"';
  rig.state.upstream = () => new Response('{"error":"invalid_token"}', { status: 401, headers: { 'content-type': 'application/json', 'www-authenticate': challenge } });
  const reply = await door(rig, { token: await goodToken(rig) });
  assert.equal(reply.status, 401);
  assert.equal(reply.headers.get('www-authenticate'), challenge);
  assert.equal(await reply.text(), '{"error":"invalid_token"}');
});

const badTokens = {
  'a bad signature': rig => sign({}, { mutate: signature => { signature[0] ^= 1; } }, rig),
  'a signature of the wrong length': async rig => `${(await goodToken(rig)).split('.').slice(0, 2).join('.')}.${b64u(new Uint8Array(63))}`,
  'an unknown kid': rig => sign({}, { header: { kid: 'other' } }, rig),
  'the wrong alg': rig => sign({}, { header: { alg: 'ES384' } }, rig),
  'alg none': rig => sign({}, { header: { alg: 'none' } }, rig),
  'the wrong typ': rig => sign({}, { header: { typ: 'JWT' } }, rig),
  'an extra header member': rig => sign({}, { header: { jku: 'https://evil.example/jwks' } }, rig),
  'an empty kid': rig => sign({}, { header: { kid: '' } }, rig),
  'a kid over 128 characters': rig => sign({}, { header: { kid: 'k'.repeat(129) } }, rig),
  'the wrong iss': rig => sign({ iss: 'https://evil.example' }, {}, rig),
  'the wrong aud': rig => sign({ aud: `${ORIGIN}/mcp` }, {}, rig),
  'aud as an array': rig => sign({ aud: [AUDIENCE] }, {}, rig),
  'an expired token': rig => sign({ exp: Math.floor(rig.clock.t / 1000) - 1 }, {}, rig),
  'an iat in the future': rig => sign({ iat: Math.floor(rig.clock.t / 1000) + 3600 }, {}, rig),
  'a fractional exp': rig => sign({ exp: Math.floor(rig.clock.t / 1000) + 10.5 }, {}, rig),
  'an nbf in the future': rig => sign({ nbf: Math.floor(rig.clock.t / 1000) + 3600 }, {}, rig),
  'no amr': rig => sign({ amr: undefined }, {}, rig),
  'amr webauthn': rig => sign({ amr: ['webauthn'] }, {}, rig),
  'amr with two entries': rig => sign({ amr: ['hosted_oauth', 'webauthn'] }, {}, rig),
  'no act': rig => sign({ act: undefined }, {}, rig),
  'act with an extra member': rig => sign({ act: { sub: 'app-1', act: { sub: 'x' } } }, {}, rig),
  'act as a string': rig => sign({ act: 'app-1' }, {}, rig),
  'cnf present': rig => sign({ cnf: { jkt: 'abc' } }, {}, rig),
  'luff_binding other than hosted_bearer': rig => sign({ luff_binding: 'device' }, {}, rig),
  'no sub': rig => sign({ sub: undefined }, {}, rig),
  'four parts': async rig => `${await goodToken(rig)}.x`,
  'an empty part': async rig => `${(await goodToken(rig)).split('.')[0]}..${b64u(new Uint8Array(64))}`,
  'an oversize token': async () => `${'a'.repeat(16_385)}.b.c`,
};
for (const [name, make] of Object.entries(badTokens)) {
  test(`refused without contacting the upstream: ${name}`, async () => {
    const rig = makeRig();
    const reply = await door(rig, { token: await make(rig) });
    assert.equal(reply.status, 401);
    assert.match(reply.headers.get('www-authenticate'), /error="invalid_token"$/);
    assert.equal((await reply.json()).error, 'invalid_token');
    assert.equal(rig.calls.upstream.length, 0);
  });
}

test('refused: a DPoP header is present', async () => {
  const rig = makeRig();
  const reply = await door(rig, { token: await goodToken(rig), headers: { dpop: 'proof' } });
  assert.equal(reply.status, 401);
  assert.equal(rig.calls.upstream.length, 0);
});

test('refused: a non-Bearer scheme, even with a good token', async () => {
  const rig = makeRig();
  for (const authorization of [`Token ${await goodToken(rig)}`, `bearer ${await goodToken(rig)}`, 'Bearer', 'Bearer ']) {
    assert.equal((await door(rig, { authorization })).status, 401, authorization);
  }
  assert.equal(rig.calls.upstream.length, 0);
});

// MARK: keys

test('the key set is fetched once across several calls, and with the safe options', async () => {
  const rig = makeRig();
  for (let index = 0; index < 4; index++) assert.equal((await door(rig, { token: await goodToken(rig) })).status, 200);
  assert.equal(rig.calls.jwks.length, 1);
  assert.equal(rig.calls.jwks[0].init.redirect, 'error');
  assert.ok(rig.calls.jwks[0].init.signal instanceof AbortSignal);
});

test('an unknown kid refetches at most once a minute', async () => {
  const rig = makeRig();
  await door(rig, { token: await goodToken(rig) });
  const stranger = await sign({}, { header: { kid: 'other' } }, rig);
  assert.equal((await door(rig, { token: stranger })).status, 401);
  assert.equal(rig.calls.jwks.length, 1);
  rig.clock.t += 61_000;
  assert.equal((await door(rig, { token: await sign({}, { header: { kid: 'other' } }, rig) })).status, 401);
  assert.equal(rig.calls.jwks.length, 2);
  assert.equal((await door(rig, { token: await sign({}, { header: { kid: 'other' } }, rig) })).status, 401);
  assert.equal(rig.calls.jwks.length, 2);
});

test('a rotated-in key is picked up on the refetch', async () => {
  const rig = makeRig();
  await door(rig, { token: await goodToken(rig) });
  rig.state.jwks = () => jsonReply({ keys: [goodKey, { ...goodKey, kid: 'k2' }] });
  rig.clock.t += 61_000;
  assert.equal((await door(rig, { token: await sign({}, { header: { kid: 'k2' } }, rig) })).status, 200);
});

test('keys are refreshed after ten minutes; a failed refresh keeps the previous keys for an hour more', async () => {
  const rig = makeRig();
  const long = () => sign({ exp: Math.floor(rig.clock.t / 1000) + 100_000 }, {}, rig);
  assert.equal((await door(rig, { token: await long() })).status, 200);
  rig.state.jwks = () => { throw new Error('down'); };
  rig.clock.t += 11 * 60_000;
  assert.equal((await door(rig, { token: await long() })).status, 200);
  assert.equal(rig.calls.jwks.length, 2);
  rig.clock.t += 30 * 60_000;
  assert.equal((await door(rig, { token: await long() })).status, 200);
  rig.clock.t += 40 * 60_000;
  const reply = await door(rig, { token: await long() });
  assert.equal(reply.status, 503);
  assert.equal((await reply.json()).error.code, 'door_unavailable');
});

const noKeys = {
  'the fetch fails': () => { throw new Error('down'); },
  'a non-200 answer': () => new Response('{}', { status: 500, headers: { 'content-type': 'application/json' } }),
  'a non-JSON content type': () => new Response('{"keys":[]}', { headers: { 'content-type': 'text/html' } }),
  'text that is not JSON': () => new Response('nope', { headers: { 'content-type': 'application/json' } }),
  'an oversize set': () => new Response(JSON.stringify({ keys: [goodKey], pad: 'x'.repeat(70_000) }), { headers: { 'content-type': 'application/json' } }),
  'no keys': () => jsonReply({ keys: [] }),
  'nine keys': () => jsonReply({ keys: Array.from({ length: 9 }, (_, index) => ({ ...goodKey, kid: `k${index}` })) }),
  'only unusable keys': () => jsonReply({ keys: [{ ...goodKey, d: 'secret' }, { ...goodKey, crv: 'P-384' }, { ...goodKey, alg: 'RS256' }, { ...goodKey, use: 'enc' }, { ...goodKey, kty: 'RSA' }] }),
};
for (const [name, jwks] of Object.entries(noKeys)) {
  test(`no usable keys gives 503, not 401: ${name}`, async () => {
    const rig = makeRig();
    rig.state.jwks = jwks;
    const reply = await door(rig, { token: await goodToken(rig) });
    assert.equal(reply.status, 503);
    assert.equal((await reply.json()).error.code, 'door_unavailable');
    assert.equal(reply.headers.get('www-authenticate'), null);
    assert.equal(rig.calls.upstream.length, 0);
  });
}

test('keys that break the rules are ignored, the rest still work', async () => {
  const rig = makeRig();
  rig.state.jwks = () => jsonReply({ keys: [{ ...goodKey, kid: 'with-d', d: 'x' }, goodKey] });
  assert.equal((await door(rig, { token: await sign({}, { header: { kid: 'with-d' } }, rig) })).status, 401);
  assert.equal((await door(rig, { token: await goodToken(rig) })).status, 200);
});

test('the key cache is keyed by the JWKS address', async () => {
  const rig = makeRig();
  await door(rig, { token: await goodToken(rig) });
  rig.env.DOOR_JWKS_URL = 'https://id.example/other/jwks';
  rig.state.jwks = () => jsonReply({ keys: [{ ...goodKey, kid: 'other-only' }] });
  assert.equal((await door(rig, { token: await goodToken(rig) })).status, 401);
  assert.equal(rig.calls.jwks.length, 2);
  assert.equal(rig.calls.jwks[1].url, 'https://id.example/other/jwks');
});

// MARK: door refusals

const refusalCases = {
  'subscription': { seams: { subscription: async () => ({ ok: false, message: 'A subscription is needed.' }) }, code: 'subscription', text: 'A subscription is needed.' },
  'not_reachable': { upstream: () => { throw new TypeError('network'); }, code: 'not_reachable', text: /./ },
};
for (const [name, { seams, upstream, code, text }] of Object.entries(refusalCases)) {
  test(`${name}: the shape for tools/call, tools/list and a notification`, async () => {
    const rig = makeRig();
    if (upstream) rig.state.upstream = upstream;
    Object.assign(rig.seams, seams);
    const token = await goodToken(rig);
    const expectedText = message => typeof text === 'string' ? assert.equal(message, text) : assert.match(message, text);
    let reply = await door(rig, { token, body: JSON.stringify({ jsonrpc: '2.0', id: 'a', method: 'tools/call', params: { name: 't' } }) });
    assert.equal(reply.status, 200);
    assert.equal(reply.headers.get('access-control-allow-origin'), '*');
    let body = await reply.json();
    assert.equal(body.id, 'a');
    assert.equal(body.result.isError, true);
    assert.equal(body.result.content.length, 1);
    assert.equal(body.result.content[0].type, 'text');
    expectedText(body.result.content[0].text);
    assert.deepEqual(body.result.structuredContent, { code, message: body.result.content[0].text });
    reply = await door(rig, { token, body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }) });
    assert.equal(reply.status, 200);
    body = await reply.json();
    assert.equal(body.id, 2);
    assert.equal(body.error.code, -32000);
    assert.deepEqual(body.error.data, { code });
    expectedText(body.error.message);
    reply = await door(rig, { token, body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) });
    assert.equal(reply.status, 202);
    assert.equal(await reply.text(), '');
    if (seams) assert.equal(rig.calls.upstream.length, 0);
  });
}

test('the subscription seam is consulted with the verified claims; the default passes everyone', async () => {
  assert.deepEqual(await relay.doorSubscription({}), { ok: true });
  const rig = makeRig();
  let seen;
  rig.seams.subscription = async claims => { seen = claims; return { ok: true }; };
  assert.equal((await door(rig, { token: await goodToken(rig) })).status, 200);
  assert.equal(seen.sub, 'person-1');
  assert.equal(seen.act.sub, 'app-1');
});

test('an upstream timeout is not_reachable, and the call carried a timeout signal', async () => {
  const rig = makeRig();
  rig.state.upstream = init => { assert.ok(init.signal instanceof AbortSignal); throw new DOMException('The operation timed out.', 'TimeoutError'); };
  const body = await (await door(rig, { token: await goodToken(rig) })).json();
  assert.equal(body.result.structuredContent.code, 'not_reachable');
});

test('a redirect is not followed and is not_reachable', async () => {
  const rig = makeRig();
  rig.state.upstream = () => new Response(null, { status: 302, headers: { location: 'https://evil.example/steal' } });
  const reply = await door(rig, { token: await goodToken(rig) });
  assert.equal(reply.status, 200);
  assert.equal((await reply.json()).result.structuredContent.code, 'not_reachable');
  assert.equal(rig.calls.upstream.length, 1);
  assert.equal(rig.calls.upstream[0].init.redirect, 'manual');
});

// MARK: methods and bodies

test('a method outside the allowlist answers -32601 and is not forwarded', async () => {
  const rig = makeRig();
  const reply = await door(rig, { token: await goodToken(rig), body: JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'resources/list' }) });
  assert.equal(reply.status, 200);
  assert.deepEqual(await reply.json(), { jsonrpc: '2.0', id: 9, error: { code: -32601, message: 'This method is not available through the door.' } });
  assert.equal(rig.calls.upstream.length, 0);
});

test('every allowed method is forwarded', async () => {
  const rig = makeRig();
  const token = await goodToken(rig);
  for (const method of ['initialize', 'ping', 'notifications/initialized', 'tools/list', 'tools/call']) {
    assert.equal((await door(rig, { token, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method }) })).status, 200, method);
  }
  assert.equal(rig.calls.upstream.length, 5);
});

test('any tool name passes: the source decides', async () => {
  const rig = makeRig();
  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'delete_everything', arguments: {} } });
  assert.equal((await door(rig, { token: await goodToken(rig), body })).status, 200);
  assert.equal(rig.calls.upstream.length, 1);
});

for (const [name, body] of [['a batch', '[{"jsonrpc":"2.0","id":1,"method":"ping"}]'], ['malformed JSON', '{"jsonrpc":'], ['a non-object', '"ping"'],
  ['a missing method', '{"jsonrpc":"2.0","id":1}'], ['a non-string method', '{"jsonrpc":"2.0","id":1,"method":4}'], ['the wrong version', '{"jsonrpc":"1.0","id":1,"method":"ping"}']]) {
  test(`${name} is a 400 invalid_request`, async () => {
    const rig = makeRig();
    const reply = await door(rig, { token: await goodToken(rig), body });
    assert.equal(reply.status, 400);
    assert.deepEqual(await reply.json(), { error: 'invalid_request' });
    assert.equal(rig.calls.upstream.length, 0);
  });
}

// MARK: limits

test('a body over 2 MB is a 413 and is not forwarded', async () => {
  const rig = makeRig();
  const reply = await door(rig, { token: await goodToken(rig), body: Buffer.alloc(2_000_001, 97) });
  assert.equal(reply.status, 413);
  assert.equal((await reply.json()).error.code, 'payload_too_large');
  assert.equal(rig.calls.upstream.length, 0);
});

test('a declared length over 2 MB is a 413 before reading', async () => {
  const rig = makeRig();
  const reply = await door(rig, { token: await goodToken(rig), headers: { 'content-length': '2000001' } });
  assert.equal(reply.status, 413);
  assert.equal(rig.calls.upstream.length, 0);
});

test('the per-address limit answers 429 before any key fetch or upstream contact', async () => {
  const rig = makeRig();
  const headers = { 'cf-connecting-ip': '203.0.113.5' };
  for (let index = 0; index < 120; index++) assert.equal((await door(rig, { headers })).status, 401);
  const reply = await door(rig, { token: await goodToken(rig), headers });
  assert.equal(reply.status, 429);
  assert.equal((await reply.json()).error.code, 'rate_limited');
  assert.equal(reply.headers.get('access-control-allow-origin'), '*');
  assert.equal(rig.calls.jwks.length, 0);
  assert.equal(rig.calls.upstream.length, 0);
  assert.equal((await door(rig, { headers: { 'cf-connecting-ip': '203.0.113.6' } })).status, 401);
});

test('the per-caller limit answers 429 after the token verifies, whatever the address', async () => {
  const rig = makeRig();
  const token = await goodToken(rig);
  for (let index = 0; index < 240; index++) {
    assert.equal((await door(rig, { token, headers: { 'cf-connecting-ip': `10.0.${index >> 8}.${index & 255}` } })).status, 200, `call ${index}`);
  }
  const reply = await door(rig, { token, headers: { 'cf-connecting-ip': '10.9.9.9' } });
  assert.equal(reply.status, 429);
  assert.equal(rig.calls.upstream.length, 240);
  const other = await sign({ sub: 'person-2' }, {}, rig);
  assert.equal((await door(rig, { token: other, headers: { 'cf-connecting-ip': '10.9.9.9' } })).status, 200);
});

test('anything but POST is a 405 with Allow, and CORS', async () => {
  const rig = makeRig();
  for (const method of ['GET', 'PUT', 'DELETE']) {
    const reply = await door(rig, { method, token: await goodToken(rig) });
    assert.equal(reply.status, 405, method);
    assert.equal(reply.headers.get('allow'), 'POST, OPTIONS');
    assert.equal(reply.headers.get('access-control-allow-origin'), '*');
  }
  assert.equal(rig.calls.upstream.length, 0);
  const options = await route(rig.env, '/door/mcp', { method: 'OPTIONS' });
  assert.equal(options.status, 204);
});

// MARK: nothing kept

test('nothing is logged and nothing is stored, on a good call and a refused one', async () => {
  const rig = makeRig();
  const calls = [];
  const original = {};
  for (const name of Object.keys(console)) {
    if (typeof console[name] !== 'function') continue;
    original[name] = console[name];
    console[name] = (...args) => { calls.push([name, ...args]); };
  }
  try {
    const token = await goodToken(rig);
    assert.equal((await door(rig, { token })).status, 200);
    assert.equal((await door(rig)).status, 401);
    assert.equal((await door(rig, { token: await sign({ iss: 'x' }, {}, rig) })).status, 401);
    rig.state.upstream = () => { throw new Error('down'); };
    assert.equal((await door(rig, { token })).status, 200);
  } finally {
    Object.assign(console, original);
  }
  assert.deepEqual(calls, []);
  assert.deepEqual(rig.touched, []);
});

test('door traffic uses its own rate-limit instance, never the library one', async () => {
  const rig = makeRig();
  await door(rig, { token: await goodToken(rig) });
  assert.ok(rig.names.length >= 1);
  assert.deepEqual([...new Set(rig.names)], ['door']);
});

// MARK: the library address

test('with the door on, /mcp and its metadata are exactly what they are with the door off', async () => {
  const on = makeRig();
  const off = makeRig({}, { door: false });
  for (const [path, init] of [['/mcp', { method: 'POST', body: '{}' }], ['/.well-known/oauth-protected-resource/mcp', {}], ['/.well-known/oauth-protected-resource', {}], ['/health', {}]]) {
    const a = await route(on.env, path, init);
    const b = await route(off.env, path, init);
    assert.deepEqual({ status: a.status, headers: [...a.headers], body: await a.text() }, { status: b.status, headers: [...b.headers], body: await b.text() }, path);
  }
  const library = await route(on.env, '/mcp', { method: 'POST', body: '{}' });
  assert.equal(library.status, 401);
  assert.match(library.headers.get('www-authenticate'), /resource_metadata="https:\/\/relay\.example\/\.well-known\/oauth-protected-resource\/mcp"/);
  assert.equal((await (await route(on.env, '/.well-known/oauth-protected-resource/mcp')).json()).resource, `${ORIGIN}/mcp`);
});
