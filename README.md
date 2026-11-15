# Ligature

Ligature is an OAuth MCP server for software that runs on a user's device. Extracted
from Marginalia and developed in public by [LUFF](https://luff.works).

Ligature has two addresses. The library relay (`/mcp`) passes requests to a device,
which answers them. The door (`/door/mcp`) passes requests through to an MCP source,
with sign-in by an outside identity service; it is staging only today.

Connect a chat app through OAuth, or run a Node bridge that seals requests directly
to a device. The device connects outward over WebSocket and remains responsible for
approving access, enforcing scopes and serving its tools.

**Status: developer preview.** The implementation and regression suite come from
Marginalia. The device contract, consent copy and root tool catalog are currently
Marginalia-specific. This is a reference deployment and integration starting point;
a company must implement the device contract and its own consent and tool policy.
It does not wrap an arbitrary existing MCP endpoint.

## Start locally

Requires Node 22.13+ and npm. Local development needs no Cloudflare account or
production credentials.

```sh
git clone https://github.com/luff-llc/luff-mcp-relay.git
cd luff-mcp-relay
npm ci
npm test
npm run dev
```

In another terminal:

```sh
curl http://localhost:8787/health
curl http://localhost:8787/.well-known/oauth-protected-resource/mcp
```

Health and discovery work immediately; tool calls require a connected device.
Local state lives under `.wrangler/`. Run `npm run demo` for a local synthetic
device and OAuth client journey.

## Two packages

| Package | Purpose | Runtime |
| --- | --- | --- |
| [`@luff-llc/ligature`](packages/relay-worker) | Worker handler, Tunnel, Gateway and Codes Durable Objects; deployment template | Cloudflare Workers |
| [`marginalia-connect`](packages/marginalia-connect) | Sealed Node API and CLI: pairing, stdio MCP, loopback proxy | Node 22.13+ |

This repository prepares unpublished development versions: Worker `0.1.0-dev.0`
and client `0.4.0-dev.0`. The existing `marginalia-connect@0.3.1` is a separate
release. **No new npm release has been published from this repository.**

```sh
npm run build
npm run verify:packages
# Tarballs and verification reports are written to artifacts/.
npm install ./artifacts/marginalia-connect-0.4.0-dev.0.tgz
npx marginalia-connect --help
```

The client API is importable from Node:

```js
import { SealedClient } from 'marginalia-connect';
const client = new SealedClient({
  address: process.env.DEVICE_ADDRESS,
  token: process.env.DEVICE_AGENT_KEY,
});
const result = await client.call('POST', '/mcp', {
  body: { jsonrpc: '2.0', id: 1, method: 'tools/list' },
});
```

A device address includes its public key fragment. Short-code pairing also
requires comparing the safety code on the device. Worker exports run in Workers,
not Node. See the [client guide](packages/marginalia-connect/README.md).

## What runs here

- OAuth authorization code with S256 PKCE, dynamic registration, resource-bound
  opaque access tokens, rotating refresh tokens and grant revocation.
- Stable `/mcp` and per-library `/t/<id>/mcp` endpoints.
- Outbound device tunnels, reconnect handling and bounded request forwarding.
- Opaque sealed transport for the Node bridge. Explicitly marked sealed writes can
  wait offline; OAuth calls are attempted once and never queued or retried.
- Optional Apple push and legacy hosted-agent hooks. Neither is configured by
  default. The legacy hosted-agent path is not an offered hosted product.

OAuth traffic is readable by the relay. It holds approved device agent keys and
OAuth grants. Only the sealed Node bridge path hides request and response content
from it, provided the device key is independently verified. Devices must be online
for OAuth and read requests. See [architecture and trust boundaries](docs/architecture.md).

## Adapt, deploy, contribute

- [Device integration and wire protocol](docs/device-contract.md)
- [Deployment and upgrades](docs/deployment.md)
- [Supported clients and acceptance evidence](docs/compatibility.md)
- [Development and release process](CONTRIBUTING.md)
- [Security policy and operational limits](SECURITY.md)
- [Source provenance and licensing](NOTICE.md)
- [Roadmap](docs/roadmap.md)

MIT licensed. LUFF offers integration design and managed hosting work through
[its contact page](https://luff.works/contact?topic=relay). Public source does not
include a hosting subscription, SLA or deployed service.
