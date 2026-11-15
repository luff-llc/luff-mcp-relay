# Deploy your own Ligature

Local work needs no Cloudflare login. Production needs your own Workers account
and Durable Objects support. This cut has no Node server or Docker adapter.

## From source

```sh
npm ci
npm test
npm run build
cp packages/relay-worker/wrangler.toml packages/relay-worker/wrangler.production.toml
```

Edit that copy: choose an unused Worker name, set `RELAY_ORIGIN` to its exact public
HTTPS origin and optionally add your own custom-domain route. Keep all three
bindings and migrations. Never deploy the localhost config to production.
Account-specific configuration belongs outside public Git.

```sh
# Explicit operator actions after reviewing configuration:
npx wrangler login
npx wrangler deploy --config packages/relay-worker/wrangler.production.toml
```

Source `main` is `src/index.ts`, relative to its config. Migrations `v1`, `v2`,
`v3` create SQLite objects `Tunnel`, `Gateway`, `Codes`. Preserve binding names
and migration tags on upgrades; changes can orphan access state. Test upgrades and
rollback on a separate staging Worker with synthetic devices.

## From a tarball

Repository versions are currently unpublished. Build verified artifacts first:

```sh
npm run verify:packages
# In a separate Worker project:
npm init -y
npm install /path/to/luff-llc-ligature-0.1.0-dev.0.tgz
cp node_modules/@luff-llc/ligature/wrangler.example.toml wrangler.toml
```

Install compatible Wrangler locally (this repository pins `4.151.0`), update
the sample name/origin and run `npx wrangler deploy --dry-run`. The template loads
`node_modules/@luff-llc/ligature/dist/index.js`. You may instead re-export the
handler/classes from your Worker module. No private checkout is required.

## Optional adapters

Default configuration includes neither Workers AI nor APNs credentials. Legacy
hosted-agent code is Marginalia-specific and opt-in; enabling it changes what
content the operator processes. Review consent, model and limits before adding an
`AI` binding. It is unnecessary for OAuth.

Apple wake needs your own `APNS_TEAM_ID`, `APNS_TOPIC`, `APNS_KEY_ID` and
`APNS_KEY_P8`. Store key material with `wrangler secret put`, never source files.
No Apple production identity is supplied. Optional Directory verification uses
the `OPENAI_APPS_CHALLENGE` secret; it is unrelated to OAuth.

## The door (staging only)

The door is a pass-through MCP address at `/door/mcp`. A chat app holds a token
issued by an external identity service; the door checks it and forwards the call
to one upstream MCP address. It is off unless these public vars are all set and
valid:

- `DOOR_ISSUER`: the identity service origin, for example `https://id.example.com`.
- `DOOR_JWKS_URL`: its published keys address, on the same origin.
- `DOOR_UPSTREAM_MCP`: the one upstream MCP address.
- `DOOR_SCOPES` (optional): up to eight space-separated scope names to publish.

It needs no secret and no storage. Keep the vars out of production config and out
of `wrangler.toml`; the sample lists them commented out. Metadata is at
`/.well-known/oauth-protected-resource/door/mcp`.

## A staging Worker from this repository

Keep staging as its own Worker with its own name, origin and Durable Objects.
Copy `packages/relay-worker/wrangler.toml` to `wrangler.staging.toml` beside it
(ignored by Git), then set the Worker name, `RELAY_ORIGIN`, the route and, to turn
the door on, the `DOOR_*` vars.

When the Worker already exists and was deployed from another checkout, the new
config must repeat its name, its three bindings and its migration tags exactly,
and list every var and binding the old config had. A deploy replaces vars and
bindings with what the config lists; secrets set with `wrangler secret put` stay.
Compare first, without deploying:

```sh
npx wrangler deploy --dry-run --config packages/relay-worker/wrangler.staging.toml
```

## Acceptance and operation

Verify health/discovery at your origin, approve a synthetic device, connect the
actual intended client and verify scope denial, revocation and isolation. See
[compatibility](compatibility.md). Continuous availability needs a persistent
compatible backend; this relay has no cloud library replica.

Restrict account access. Monitor latency, failures, pools, rate limits and storage.
Redact bodies, bearers and keys from logs. Establish deletion, restore and incident
procedures before paid hosting. No billing, SLA or deployed service is included.
