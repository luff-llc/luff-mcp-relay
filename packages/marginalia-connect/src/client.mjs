// A client for one Marginalia library reached through Marginalia Relay. Every call
// is sealed to the device, so the relay sees neither the agent key nor the library.
import { randomUUID } from 'node:crypto';
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { parseAddress, safetyCode, sealRequest } from './sealed.mjs';

export const WRITE_TOOLS = new Set(['collect_link', 'add_note', 'add_book', 'add_highlight', 'add_insight',
  'set_reading_state', 'set_book_plan', 'suggest_notes', 'import_book_history']);

export class RelayError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}

export class SealedClient {
  constructor({ address, token = null, fetchImpl = fetch }) {
    this.address = address;
    this.target = parseAddress(address);
    this.safetyCode = safetyCode(this.target.devicePublicKey);
    this.token = token;
    this.fetch = fetchImpl;
  }

  /// One gateway call. Returns {status, json} from the device, or {queued} when the
  /// relay held a write for an offline device.
  async call(method, path, { body, headers = {}, queued = false } = {}) {
    const inner = { ...headers };
    if (this.token) inner.authorization = `Bearer ${this.token}`;
    if (body !== undefined) inner['content-type'] = 'application/json';
    const sealed = sealRequest(this.target.devicePublicKey, {
      method, path, headers: inner, body: body === undefined ? '' : JSON.stringify(body), queued,
    });
    const outer = { 'content-type': 'application/json' };
    if (queued) outer['x-marginalia-queue'] = '1';
    const response = await this.fetch(`${this.target.base}/sealed`, { method: 'POST', headers: outer, body: sealed.body });
    const text = await response.text();
    if (response.status === 202 && queued) return { queued: JSON.parse(text) };
    if (response.status !== 200) {
      let error = {};
      try { error = JSON.parse(text).error ?? {}; } catch { /* not JSON */ }
      throw new RelayError(response.status, error.code ?? 'relay_error', error.message ?? `Relay answered ${response.status}.`);
    }
    let reply;
    try { reply = sealed.openReply(text); } catch {
      let error = {};
      try { error = JSON.parse(text).error ?? {}; } catch { /* not JSON */ }
      throw new RelayError(400, error.code ?? 'sealed_reply', error.message ?? 'The device reply could not be opened.');
    }
    return { status: reply.status, json: reply.body ? JSON.parse(reply.body) : null };
  }

  /// MCP JSON-RPC over the sealed channel. Writes carry a command id so that the
  /// relay may hold them for an offline device and a retry never duplicates.
  async mcp(message) {
    let queued = false;
    if (message.method === 'tools/call' && WRITE_TOOLS.has(message.params?.name)) {
      message = structuredClone(message);
      message.params.arguments ??= {};
      // Separate user requests with identical arguments are distinct writes. Callers
      // retrying an uncertain result should pass their own stable command_id.
      message.params.arguments.command_id ??= `mc-${randomUUID()}`;
      queued = true;
    }
    const result = await this.call('POST', '/mcp', { body: message, queued });
    if (result.queued) {
      const commandId = message.params.arguments.command_id;
      return {
        jsonrpc: '2.0', id: message.id, result: {
          isError: false,
          content: [{ type: 'text', text: `Queued, not yet applied: the user's device is offline. Marginalia Relay holds this sealed write and delivers it when Marginalia next connects. command_id ${commandId}; check later with get_item or library_changes before telling the user it is saved.` }],
        },
      };
    }
    if (result.status === 202 || result.json === null) return null;
    return result.json;
  }

  async tool(name, args = {}) {
    const reply = await this.mcp({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } });
    const text = reply?.result?.content?.[0]?.text ?? '';
    let value;
    try { value = JSON.parse(text); } catch { value = { message: text }; }
    if (reply?.error || reply?.result?.isError) throw new RelayError(400, 'tool_error', value.message ?? value.reason ?? text);
    return value;
  }
}

export const DEFAULT_RELAY = 'https://relay.toolsperson.com';

/// What a pairing asks for unless --scopes says otherwise: enough for either choice in
/// Marginalia ("only what you ask about" or "everything you've kept"), and adding things.
/// The person narrows it on their device; approval never grants more than this.
export const DEFAULT_SCOPES = ['library.read', 'library.text', 'library.add', 'requests.answer', 'insights.write', 'suggestions.write'];

/// A pairing code as people type it ("k7q-2mf"), or null when the argument is not one.
export function pairingCode(value) {
  const code = String(value ?? '').toUpperCase().replace(/[\s-]/g, '');
  return /^[23456789ABCDEFGHJKMNPQRSTUVWXYZ]{6}$/.test(code) ? code : null;
}

/// Spend a pairing code at the relay to learn the library's address. The relay supplies the
/// device key, so the person must check that the safety code printed here matches the one
/// Marginalia shows before allowing: that check is what keeps the bridge end-to-end.
export async function resolvePairingCode(code, { relay = DEFAULT_RELAY, fetchImpl = fetch } = {}) {
  const relayURL = new URL(relay);
  const local = ['127.0.0.1', 'localhost', '[::1]'].includes(relayURL.hostname);
  if ((relayURL.protocol !== 'https:' && !(relayURL.protocol === 'http:' && local))
    || relayURL.username || relayURL.password || relayURL.pathname !== '/' || relayURL.search || relayURL.hash) {
    throw new Error('The relay must be an HTTPS origin, or an HTTP origin on loopback.');
  }
  const response = await fetchImpl(`${relayURL.origin}/v1/codes/${code}`, { method: 'POST' });
  let json = null;
  try { json = await response.json(); } catch { /* reported below */ }
  if (response.status !== 200 || typeof json?.address !== 'string') {
    throw new RelayError(response.status, json?.error?.code ?? 'code_unknown',
      json?.error?.message ?? 'That code is not valid. Marginalia shows a new one in Agents.');
  }
  // A code resolved at one relay must not move the private pairing exchange to
  // another server. The safety code still protects the device key itself.
  const target = parseAddress(json.address);
  if (new URL(target.base).origin !== relayURL.origin) {
    throw new Error('The relay returned an address on a different server.');
  }
  return json.address;
}

/// Ask the device for a key. The user approves it in Marginalia; the key is saved to `configPath`.
export async function pair({ address, name, scopes, configPath, fetchImpl = fetch, onCode = () => {}, pollMs = 2000, timeoutMs = 300_000 }) {
  const client = new SealedClient({ address, fetchImpl });
  const opened = await client.call('POST', '/api/v1/pairings', { body: { name, client: 'marginalia-connect', scopes: scopes ?? DEFAULT_SCOPES } });
  if (opened.status !== 200) throw new RelayError(opened.status, opened.json?.error?.code, opened.json?.error?.message ?? 'Pairing was refused.');
  onCode(opened.json.code, client.safetyCode);
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const polled = await client.call('GET', `/api/v1/pairings/${opened.json.id}`, { headers: { 'x-pairing-secret': opened.json.secret } });
    const state = polled.json?.state;
    if (state === 'approved') {
      const config = { address, token: polled.json.token, scopes: polled.json.scopes, name, safetyCode: client.safetyCode };
      saveConfig(configPath, config);
      return config;
    }
    if (state && state !== 'pending') throw new RelayError(403, `pairing_${state}`, `The pairing request was ${state}.`);
    await new Promise(resolve => setTimeout(resolve, pollMs));
  }
  throw new RelayError(408, 'pairing_timeout', 'Nobody approved the request in time.');
}

export function saveConfig(path, config) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
  chmodSync(path, 0o600);
}

export function loadConfig(path) {
  const config = JSON.parse(readFileSync(path, 'utf8'));
  if (!config.address || !config.token) throw new Error(`${path} is not a marginalia-connect configuration.`);
  return config;
}
