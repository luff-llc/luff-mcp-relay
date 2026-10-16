# Compatibility and evidence

| Surface | Evidence here | Live acceptance |
| --- | --- | --- |
| OAuth MCP, Streamable HTTP JSON | Synthetic discovery, registration, PKCE, approval, calls, refresh, revoke | Actual client installation required |
| ChatGPT custom connector | Protocol-shaped synthetic client | Not verified for this extraction |
| Claude custom connector | Protocol-shaped synthetic client | Not verified for this extraction |
| Grok custom connector | Protocol-shaped synthetic client | Not verified for this extraction |
| Node API / stdio bridge | Source tests and installed-tarball checks | Real native-device journey required |
| Cloudflare Workers | Types/build and local runtime demo | Staging deployment and durable upgrade acceptance required |
| SSE, resources, prompts, subscriptions | Not implemented on root MCP | Unsupported |
| Downstream provider OAuth | No adapter | Unsupported |

`npm test` runs actual Worker routing/authentication code transpiled in Node with
an in-memory Durable Object substitute and synthetic sealed devices. It covers
permitted/denied calls, audience/library isolation, wrong client, code/refresh reuse,
expiry, revocation, device denial, reconnect, stale sockets, queues, body limits
and uncertain writes. It does not establish real native-device persistence or
vendor interoperability.

`npm run demo` exercises a local Workers runtime with a synthetic device/client.
`npm run verify:packages` packs allowlisted files, installs tarballs in a separate
consumer and checks exports/types/CLI. `npm run verify:public` checks publication
content and local Markdown links. Fixture client names do not mean vendor
certification. See [release notes](../CHANGELOG.md).
