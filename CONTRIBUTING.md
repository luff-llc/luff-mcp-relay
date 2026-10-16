# Contributing

Use Node 22.13+ and npm. Install with `npm ci`; run `npm test` for focused feedback,
then `npm run check` and `npm run demo` before release. Add regressions for changed
authorization, routing and persistence. Keep protocol compatibility unless an
explicit version change is documented.

Issues should explain the user problem, client/device versions and a synthetic
reproduction. Keep keys, token URLs, personal records and production logs out.
Vulnerabilities follow [SECURITY.md](SECURITY.md).

Keep this small: one Cloudflare host adapter and one Node client. Customer identity,
provider OAuth and tool policy stay separate. A new abstraction needs a second
concrete integration. Tests need no production traffic or persistent credentials.

## Release

1. Review all tracked files and exact public history. Inspect pack manifests and
   run content audit.
2. Run clean install, tests, build, local demo and external tarball consumer checks.
   Record commit/evidence in release notes.
3. Confirm npm names, maintainers, MIT attribution, version and runtime.
   `marginalia-connect` already exists; verify its npm owner before release.
   `luff-mcp-relay` is a proposed package name.
4. Inspect `artifacts/*.tgz`. A registry dry run is another preview; actual
   publishing needs separate release authorization.
5. Tag a reviewed commit and publish manually or through a separately approved
   trusted-publisher setup. No workflow publishes packages or deploys infrastructure.

[NOTICE.md](NOTICE.md) records provenance. Standalone changes do not automatically
update the private native app or production relay.
