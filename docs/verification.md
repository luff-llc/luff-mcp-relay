# Initial extraction verification

Executed on 2026-10-16, macOS 27.0.1 arm64, Node 24.12.0 and npm 11.6.2.
The full candidate source was copied to a separate temporary directory; `npm ci`
installed the lockfile without using the private checkout.

- 18 Node client tests and 57 Worker regressions passed (75 total).
- Workers type generation and TypeScript build passed with Wrangler 4.151.0.
- Both npm archives passed exact file allowlists and packed-content checks.
- Both archives installed in a fresh consumer outside the source directory.
  That consumer installed its own public TypeScript/Node type dependencies.
- Client ESM and sealed-subpath imports, installed CLI help/version, strict NodeNext
  client declarations and strict Workers/Bundler declarations passed. No platform
  stub or disabled library checking was used for package declaration checks.
- Local Wrangler runtime demo passed configured-origin discovery, authenticated
  device connection, one-use pairing code, OAuth device approval/PKCE exchange,
  permitted sealed call, wrong-resource denial and device revocation.
- A publication-file text/path/credential-pattern/link audit passed. Focused source
  review checked OAuth audience/isolation, credential use, approval/code/refresh
  transactions, origin handling, bounded readers, retry/reconnect and package scope.
- `npm audit` reported zero known dependency advisories after development-tool
  updates. This is a registry snapshot, not an independent security certification.

Fixed during extraction: hardcoded relay origin, concurrent approval code issuance,
selector nonce ordering, unbounded tunnel body-read time, non-HTTP loopback client
URLs and inherited Apple identity/default configuration. The original private
checkout and its unrelated dirty work were left unchanged.

Artifacts (not committed): `artifacts/luff-llc-ligature-0.1.0-dev.0.tgz`,
`artifacts/marginalia-connect-0.4.0-dev.0.tgz`, JSON verification/audit reports,
and `artifacts/SHA256SUMS`. npm publication has not occurred. The existing npm
owner of `marginalia-connect` was verified as `mikelxc`; new versions still need
an explicit release decision.

Real ChatGPT/Claude/Grok installations, native device acceptance, hosted staging,
load, durable migration and restore tests remain outstanding. Device revocation
while offline and queued-write deduplication limits are documented in
[architecture](architecture.md). No provider enrollment, persistent credential,
production traffic, hosting deployment, billing or website change was performed.
