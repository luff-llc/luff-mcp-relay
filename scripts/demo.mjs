#!/usr/bin/env node
// Exercise the packaged relay through a real local Workers runtime and a synthetic device.
import assert from 'node:assert/strict';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import WebSocket from 'ws';
import { b64url, openRequest, privateKeyFromRaw, rawPublicKey } from '../packages/marginalia-connect/src/sealed.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const worker = join(root, 'packages/relay-worker');
const port = 18000 + randomBytes(2).readUInt16BE() % 10000;
const origin = `http://localhost:${port}`;
const network = `http://127.0.0.1:${port}`;
const resource = `${origin}/mcp`;
const redirectUri = 'https://synthetic-client.example/callback';
const deviceSecret = randomBytes(48).toString('base64url');
const tunnel = createHash('sha256').update(deviceSecret).digest('hex').slice(0, 32);
const devicePrivate = randomBytes(32);
const devicePublic = b64url(rawPublicKey(privateKeyFromRaw(devicePrivate)));
const deviceToken = `mrg_demo_${randomBytes(24).toString('base64url')}`;
const verifier = randomBytes(48).toString('base64url');
const challenge = createHash('sha256').update(verifier).digest('base64url');
let approved = false;
let revoked = false;
let sealedCalls = 0;
let deviceFailure;
let child;
let socket;
let output = '';
const codeWaiters = [];

function record(chunk) { output = (output + chunk.toString()).slice(-12_000); }
function checkDevice() { if (deviceFailure) throw deviceFailure; }
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const form = values => ({ method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(values) });
async function call(path, init = {}) {
  checkDevice();
  return fetch(network + path, { ...init, redirect: 'manual', signal: AbortSignal.timeout(15_000) });
}
async function expectJSON(path, init, status) {
  const response = await call(path, init);
  const body = await response.json();
  assert.equal(response.status, status, `${path}: ${JSON.stringify(body)}`);
  return body;
}

async function ready() {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (child.exitCode !== null) throw new Error(`Wrangler exited (${child.exitCode}).\n${output}`);
    try {
      const response = await fetch(network + '/health', { signal: AbortSignal.timeout(300) });
      if (response.ok) return;
    } catch { /* The local runtime is still starting. */ }
    await pause(200);
  }
  throw new Error(`Wrangler did not start on ${network}.\n${output}`);
}

function handleDeviceMessage(message) {
  if (message.type === 'pairing-code') {
    const waiter = codeWaiters.shift();
    if (waiter) waiter(message);
    return;
  }
  if (typeof message.id !== 'number') return;
  assert.equal(message.path, '/sealed', 'OAuth calls must be sealed to the device');
  sealedCalls++;
  const opened = openRequest(devicePrivate, Buffer.from(message.body, 'base64').toString());
  const { method, path, headers, body } = opened.request;
  let answer;
  if (method === 'POST' && path === '/api/v1/pairings') {
    const proof = createHmac('sha256', createHash('sha256').update(deviceSecret).digest())
      .update(`marginalia-oauth-pairing-v1\n${body}`).digest('base64url');
    assert.equal(headers['x-marginalia-chat-proof'], proof);
    answer = { status: 200, body: JSON.stringify({ id: 'demo-pairing', code: '481-902', secret: 'demo-pairing-secret' }) };
  } else if (method === 'GET' && path === '/api/v1/pairings/demo-pairing') {
    assert.equal(headers['x-pairing-secret'], 'demo-pairing-secret');
    answer = { status: 200, body: JSON.stringify(approved ? { state: 'approved', token: deviceToken } : { state: 'pending' }) };
  } else if (method === 'POST' && path === '/mcp') {
    assert.equal(headers.authorization, `Bearer ${deviceToken}`);
    const rpc = JSON.parse(body);
    assert.equal(rpc.method, 'tools/call');
    assert.equal(rpc.params.name, 'knowledge_search');
    answer = revoked ? { status: 401, body: '{"error":{"code":"unauthorized"}}' }
      : { status: 200, body: JSON.stringify({ jsonrpc: '2.0', id: rpc.id, result: {
        isError: false, content: [{ type: 'text', text: JSON.stringify({ pointers: [{ item: 'synthetic-note', title: 'Demo note' }] }) }],
      } }) };
  } else {
    throw new Error(`Unexpected device request ${method} ${path}`);
  }
  socket.send(JSON.stringify({ id: message.id, status: 200, contentType: 'application/json',
    body: Buffer.from(opened.sealReply(answer)).toString('base64') }));
}

async function pairingCode() {
  const reply = new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Device did not receive a pairing code')), 10_000);
    codeWaiters.push(value => { clearTimeout(timeout); resolve(value); });
  });
  socket.send(JSON.stringify({ type: 'pairing-code' }));
  const value = await reply;
  assert.match(value.code, /^[A-HJ-NP-Z2-9]{6}$/);
  return value.code;
}

async function main() {
  const scratch = await mkdtemp(join(tmpdir(), 'luff-relay-demo-'));
  try {
    child = spawn(join(root, 'node_modules/.bin/wrangler'), [
      'dev', '--local', '--ip', '127.0.0.1', '--port', String(port), '--inspector-port', String(port + 1),
      '--persist-to', join(scratch, 'state'), '--var', `RELAY_ORIGIN:${origin}`, '--show-interactive-dev-session=false',
    ], { cwd: worker, detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'], env: {
      ...process.env, WRANGLER_SEND_METRICS: 'false', XDG_CONFIG_HOME: join(scratch, 'config'),
      WRANGLER_LOG_PATH: join(scratch, 'wrangler.log'),
    } });
    child.stdout.on('data', record);
    child.stderr.on('data', record);
    await ready();

    const metadata = await expectJSON('/.well-known/oauth-protected-resource/mcp', {}, 200);
    assert.equal(metadata.resource, resource, 'the command-line origin must reach the runtime');
    const issuer = await expectJSON('/.well-known/oauth-authorization-server', {}, 200);
    assert.equal(issuer.issuer, origin);
    console.log('✓ local Workers runtime and configured origin');

    socket = new WebSocket(`ws://127.0.0.1:${port}/v1/tunnels/${tunnel}/connect`, {
      headers: { authorization: `Bearer ${deviceSecret}`, 'x-marginalia-device': 'synthetic-demo', 'x-marginalia-platform': 'macOS' },
    });
    socket.on('message', raw => {
      try { handleDeviceMessage(JSON.parse(raw.toString())); }
      catch (cause) { deviceFailure = cause; socket.close(); }
    });
    await new Promise((resolve, reject) => {
      socket.once('open', resolve);
      socket.once('error', reject);
    });
    socket.send(JSON.stringify({ type: 'ready', key: devicePublic }));
    const discoveryCode = await pairingCode();
    const discovered = await expectJSON(`/v1/codes/${discoveryCode}`, { method: 'POST' }, 200);
    assert.equal(discovered.address, `${origin}/t/${tunnel}#k=${devicePublic}`);
    assert.equal((await call(`/v1/codes/${discoveryCode}`, { method: 'POST' })).status, 404);
    console.log('✓ authenticated device and one-use code discovery');

    const client = await expectJSON('/oauth/register', { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_name: 'Synthetic demo', redirect_uris: [redirectUri] }) }, 201);
    const authorization = new URLSearchParams({ response_type: 'code', client_id: client.client_id, redirect_uri: redirectUri,
      code_challenge: challenge, code_challenge_method: 'S256', resource, scope: 'library', state: 'demo-state' });
    const selection = await call(`/oauth/authorize?${authorization}`);
    assert.equal(selection.status, 200);
    const nonce = /name="request" value="([^"]+)"/.exec(await selection.text())?.[1];
    assert.ok(nonce, 'authorization selector nonce');
    const connectCode = await pairingCode();
    const selected = await call('/oauth/authorize', { ...form({ request: nonce, connector: connectCode }), headers: {
      'content-type': 'application/x-www-form-urlencoded', origin,
    } });
    const selectedPage = await selected.text();
    assert.equal(selected.status, 200, selectedPage);
    const requestId = /request=([^"&]+)/.exec(selectedPage)?.[1];
    assert.ok(requestId, 'device approval request');
    const pending = await expectJSON(`/oauth/authorize/status?request=${requestId}`, {}, 200);
    assert.match(pending.message, /Waiting/);
    approved = true;
    const decision = await expectJSON(`/oauth/authorize/status?request=${requestId}`, {}, 200);
    const callback = new URL(decision.redirect);
    assert.equal(callback.searchParams.get('iss'), origin);
    assert.equal(callback.searchParams.get('state'), 'demo-state');
    const code = callback.searchParams.get('code');
    assert.ok(code);
    const tokens = await expectJSON('/oauth/token', form({ grant_type: 'authorization_code', client_id: client.client_id,
      redirect_uri: redirectUri, code_verifier: verifier, code, resource }), 200);
    assert.ok(tokens.access_token.startsWith('mca_'));
    console.log('✓ OAuth registration, device approval and PKCE exchange');

    const request = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'knowledge_search', arguments: { query: 'demo' } } };
    const read = () => call('/mcp', { method: 'POST', headers: { authorization: `Bearer ${tokens.access_token}`,
      'content-type': 'application/json' }, body: JSON.stringify(request) });
    const allowed = await read();
    assert.equal(allowed.status, 200);
    const rpc = await allowed.json();
    assert.equal(JSON.parse(rpc.result.content[0].text).pointers[0].item, 'synthetic-note');
    const wrongAudience = await call('/oauth/token', form({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token,
      client_id: client.client_id, resource: `${origin}/t/${tunnel}/mcp` }));
    assert.equal(wrongAudience.status, 400);
    assert.ok(sealedCalls >= 3);
    console.log('✓ sealed read and wrong-audience rejection');

    revoked = true;
    assert.equal((await read()).status, 401);
    assert.equal((await read()).status, 401);
    checkDevice();
    console.log('✓ device revocation invalidates the grant');
  } finally {
    socket?.close();
    if (child?.pid) {
      try { process.kill(process.platform === 'win32' ? child.pid : -child.pid, 'SIGTERM'); } catch { child.kill(); }
      await Promise.race([new Promise(resolve => child.once('exit', resolve)), pause(2_000)]);
      if (child.exitCode === null) {
        try { process.kill(process.platform === 'win32' ? child.pid : -child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); }
      }
    }
    await rm(scratch, { recursive: true, force: true });
  }
}

main().catch(error => { console.error(error.stack ?? error, output ? `\nWrangler output:\n${output}` : ''); process.exitCode = 1; });
