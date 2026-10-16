// Sealed channel v1: an agent encrypts each request to the device's public key so
// Marginalia Relay forwards bytes it cannot read. Mirrors AgentSealedChannel.swift;
// the format is in docs/colophon/relay-sealed-channel.md.
import {
  createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey, diffieHellman,
  generateKeyPairSync, hkdfSync, randomBytes,
} from 'node:crypto';

const INFO = Buffer.from('marginalia-sealed-v1');
const REQUEST_AAD = Buffer.from('marginalia-sealed-v1 request');
const REPLY_AAD = Buffer.from('marginalia-sealed-v1 reply');
const PKCS8_X25519 = Buffer.from('302e020100300506032b656e04220420', 'hex');

export const b64url = bytes => Buffer.from(bytes).toString('base64url');
export const fromB64url = text => Buffer.from(text, 'base64url');

export function privateKeyFromRaw(raw) {
  return createPrivateKey({ key: Buffer.concat([PKCS8_X25519, Buffer.from(raw)]), format: 'der', type: 'pkcs8' });
}
export function rawPublicKey(key) {
  return fromB64url(createPublicKey(key).export({ format: 'jwk' }).x);
}
function publicKeyFromRaw(raw) {
  return createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: b64url(raw) }, format: 'jwk' });
}

function derive(ephemeralPrivate, ephemeralPublic, devicePublic) {
  const shared = diffieHellman({ privateKey: ephemeralPrivate, publicKey: publicKeyFromRaw(devicePublic) });
  const material = Buffer.from(hkdfSync('sha256', shared, Buffer.concat([ephemeralPublic, devicePublic]), INFO, 64));
  return { request: material.subarray(0, 32), reply: material.subarray(32) };
}

/// Seal one request. Returns the JSON body to POST to /t/<tunnel>/sealed and the
/// function that opens the device's reply. `fixed` pins keys for test vectors only.
export function sealRequest(devicePublicKey, { method, path, headers = {}, body = '', queued = false, ts = Date.now() / 1000 }, fixed = {}) {
  const device = Buffer.from(devicePublicKey);
  if (device.length !== 32) throw new Error('The device key must be 32 bytes.');
  const ephemeral = fixed.ephemeralPrivate ? privateKeyFromRaw(fixed.ephemeralPrivate) : generateKeyPairSync('x25519').privateKey;
  const epk = rawPublicKey(ephemeral);
  const keys = derive(ephemeral, epk, device);
  const iv = fixed.iv ?? randomBytes(12);
  const inner = JSON.stringify({ method, path, headers, body: Buffer.from(body).toString('base64'), ts, queued });
  const cipher = createCipheriv('aes-256-gcm', keys.request, iv);
  cipher.setAAD(REQUEST_AAD);
  const ct = Buffer.concat([cipher.update(inner), cipher.final(), cipher.getAuthTag()]);
  const sealed = JSON.stringify({ v: 1, epk: b64url(epk), iv: b64url(iv), ct: b64url(ct) });
  return {
    body: sealed,
    openReply(text) {
      const outer = JSON.parse(text);
      const bytes = fromB64url(outer.ct);
      const decipher = createDecipheriv('aes-256-gcm', keys.reply, fromB64url(outer.iv));
      decipher.setAAD(REPLY_AAD);
      decipher.setAuthTag(bytes.subarray(bytes.length - 16));
      const plain = Buffer.concat([decipher.update(bytes.subarray(0, bytes.length - 16)), decipher.final()]);
      const reply = JSON.parse(plain.toString('utf8'));
      return { status: reply.status, contentType: reply.contentType, body: Buffer.from(reply.body ?? '', 'base64').toString('utf8') };
    },
  };
}

/// The device side, for tests: open a sealed request and seal a reply.
export function openRequest(devicePrivateRaw, text) {
  const device = privateKeyFromRaw(devicePrivateRaw);
  const devicePublic = rawPublicKey(device);
  const outer = JSON.parse(text);
  const epk = fromB64url(outer.epk);
  const shared = diffieHellman({ privateKey: device, publicKey: publicKeyFromRaw(epk) });
  const material = Buffer.from(hkdfSync('sha256', shared, Buffer.concat([epk, devicePublic]), INFO, 64));
  const bytes = fromB64url(outer.ct);
  const decipher = createDecipheriv('aes-256-gcm', material.subarray(0, 32), fromB64url(outer.iv));
  decipher.setAAD(REQUEST_AAD);
  decipher.setAuthTag(bytes.subarray(bytes.length - 16));
  const inner = JSON.parse(Buffer.concat([decipher.update(bytes.subarray(0, bytes.length - 16)), decipher.final()]).toString('utf8'));
  return {
    request: { ...inner, body: Buffer.from(inner.body ?? '', 'base64').toString('utf8') },
    sealReply({ status, contentType = 'application/json', body = '' }) {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', material.subarray(32), iv);
      cipher.setAAD(REPLY_AAD);
      const plain = JSON.stringify({ status, contentType, body: Buffer.from(body).toString('base64') });
      const ct = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
      return JSON.stringify({ v: 1, iv: b64url(iv), ct: b64url(ct) });
    },
  };
}

/// Five groups of five digits from the library's key; the app shows the same code.
export function safetyCode(publicKey) {
  const digest = createHash('sha256').update(Buffer.from(publicKey)).digest();
  return [0, 1, 2, 3, 4].map(group => String(digest.readUInt16BE(group * 2)).padStart(5, '0')).join(' ');
}

/// `https://relay.toolsperson.com/t/<tunnel>#k=<device key>` → its parts.
export function parseAddress(address) {
  const url = new URL(address);
  const local = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) {
    throw new Error('The relay address must use HTTPS, or HTTP on loopback.');
  }
  if (url.username || url.password || url.search) {
    throw new Error('The relay address must not contain credentials or a query string.');
  }
  const match = /^\/t\/([a-f0-9]{32})\/?$/.exec(url.pathname);
  const key = new URLSearchParams(url.hash.slice(1)).get('k');
  if (!match || !key || fromB64url(key).length !== 32) {
    throw new Error('Use the address from Marginalia → Settings → Agents, including #k=… (the device key).');
  }
  return { base: `${url.origin}/t/${match[1]}`, tunnel: match[1], devicePublicKey: fromB64url(key) };
}
