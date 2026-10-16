# Device integration contract

The wire names stay Marginalia-compatible. There is no native app or arbitrary
upstream adapter bundled. The synthetic demo is not a production device server.

1. Generate a high-entropy library secret and X25519 device/library key pair.
   Tunnel ID is the first 16 bytes of SHA-256(UTF-8(secret)), hex encoded.
2. Open `GET /v1/tunnels/<32-hex>/connect` as WebSocket, with
   `Authorization: Bearer <secret>`, `X-Marginalia-Device` (stable ID) and
   `X-Marginalia-Platform` (`macOS`, `iOS` etc.). The relay keeps a secret hash.
3. Send `{"type":"ready","key":"<base64url X25519 public key>"}`. Heartbeats
   are `{"type":"ping"}` / `{"type":"pong"}`. See source for pairing-code messages.
4. Receive `{id, method, path, headers, body}` envelopes. `body` is base64 bytes.
   Reply with matching `id`, HTTP `status`, `contentType` and base64 `body`.
5. `/sealed` uses X25519 and HKDF-SHA256, salt `ephemeralPublic || devicePublic`,
   info `marginalia-sealed-v1`, producing two 32-byte AES-GCM keys. Request/reply
   AAD is `marginalia-sealed-v1 request` / `marginalia-sealed-v1 reply`.
   See [sealed client](../packages/marginalia-connect/src/sealed.mjs).

The decrypted request contains `method`, `path`, `headers`, base64 `body`, `ts` and
`queued`. A real device must validate version, key/nonce lengths, authentication
tags, timestamps/replay rules, authentication and scopes before execution. The
exported `openRequest` is a fixture primitive; it supplies no authorization or
replay persistence.

OAuth pairing uses `POST /api/v1/pairings` with name/client/scopes, followed by
`GET /api/v1/pairings/<id>` carrying `x-pairing-secret`. The device must show
explicit consent, verify `x-marginalia-chat-proof` against its library secret and
return a separately scoped agent key only after approval. Results include `id`,
`secret`, human verification `code`, `state`, `token`, `scopes`. Never return the
library secret. OAuth and Node pairing have different provenance. Read the
[Worker](../packages/relay-worker/src/index.ts) and synthetic tests before
implementing compatibility.

Root MCP permits `search_library`, `knowledge_search`, `knowledge_open`, `get_item`,
`add_note`, `add_insight`, `suggest_notes`, `get_suggestion`, plus
initialize/ping/initialized/list/call. `collect_link` is excluded until the device
enforces URL-fetch SSRF protection. A different product must review this allowlist,
annotations, scopes, initialization instructions and consent pages together.
Per-tunnel/device surfaces have different policy and still require device checks.

Queued writes need durable device command-ID deduplication, including across
restarts. Lost replies do not prove execution failed.
