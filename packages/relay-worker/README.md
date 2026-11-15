# @luff-llc/ligature

Cloudflare Workers deployment of Ligature (the library relay and the door), extracted from
Marginalia. Developer preview `0.1.0-dev.0`; no npm release from this repository yet.

Exports the default Worker handler and `Tunnel`, `Gateway`, `Codes` Durable Object
classes, plus metadata and sealed-channel helpers. `RelayEnv` describes the host
bindings. Import only in a Workers runtime. Node applications use `marginalia-connect`.

```ts
export { default, Tunnel, Gateway, Codes } from '@luff-llc/ligature';
```

Build and test from the repository root:

```sh
npm ci
npm test
npm run build
npm run dev
```

Install a verified tarball into a Worker project, then copy `wrangler.example.toml`
from the installed package. Choose a new Worker name and set `RELAY_ORIGIN` to its
exact public HTTPS origin. No production account, route, Apple team or secret is
included. [Deployment](https://github.com/luff-llc/luff-mcp-relay/blob/main/docs/deployment.md) explains bindings and migrations.

This retains Marginalia's device approval endpoints, protocol and root tool policy.
An online compatible device is required. [Device contract](https://github.com/luff-llc/luff-mcp-relay/blob/main/docs/device-contract.md)
and [trust boundaries](https://github.com/luff-llc/luff-mcp-relay/blob/main/docs/architecture.md) describe the integration work.
