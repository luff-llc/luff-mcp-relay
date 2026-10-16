# Provenance and attribution

The initial source is extracted from Marginalia, not recreated as a new gateway.

- Source snapshot: `39248719908976354038e87819473da60f442b2f`.
- Relay latest source commit: `8790a393dbf65e75a1d9d382c7db6568c470b84b`.
- Client latest source commit: `24cb29a0688c0791791f5f8ca11c64e566d8d371`.
- Paths: `packages/relay-worker/src/index.ts`, its synthetic tests, and
  `packages/marginalia-connect` source, CLI, tests and crypto-vector script.

The source checkout is private. This repository starts a minimal new history and
includes no private Git history, native app, personal records, production config,
runtime storage or credentials. Source authorship records attribute implementation
to Xinchen Liu with Claude Code and Codex assistance. The relay had no declared
license and the client declared `UNLICENSED`. The owner explicitly approved MIT
for this extraction on 2026-10-16.

Marginalia wire names, crypto domain separators and product policy stay for
compatibility. MIT does not grant trademark rights or imply vendor endorsement.

The Node client bundles no third-party runtime dependency. The Worker imports
Cloudflare's platform API. Development tools and transitive dependencies retain
their own licenses under npm and are recorded in the lockfile. Package artifacts
contain project code, MIT license, docs and generated Worker type support.
Do not copy node_modules into source releases.

Generated Worker runtime declarations retain Cloudflare/Microsoft Apache-2.0 notices
and include the Apache license in the Worker package. See its THIRD_PARTY_NOTICES.md.
