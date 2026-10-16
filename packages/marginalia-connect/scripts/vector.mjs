// Prints a fixed sealed request so the Swift tests can pin the wire format:
//   node scripts/vector.mjs
import { b64url, privateKeyFromRaw, rawPublicKey, sealRequest } from '../src/sealed.mjs';

export const devicePrivate = Buffer.alloc(32, 7);
export const vector = sealRequest(rawPublicKey(privateKeyFromRaw(devicePrivate)), {
  method: 'POST', path: '/mcp', headers: { authorization: 'Bearer mrg_test' },
  body: '{"jsonrpc":"2.0","id":1,"method":"ping"}', ts: 1_790_000_000,
}, { ephemeralPrivate: Buffer.alloc(32, 9), iv: Buffer.from('000102030405060708090a0b', 'hex') });

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log(JSON.stringify({ devicePrivateKey: b64url(devicePrivate), timestamp: 1_790_000_000, body: vector.body }, null, 2));
}
