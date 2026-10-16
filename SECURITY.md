# Security

This developer preview has no external security audit or enterprise assurance.
Report vulnerabilities privately through GitHub **Report a vulnerability** when
available, or [LUFF contact](https://luff.works/contact?topic=relay) to establish a
private channel. Avoid public exploit details, tokens or customer data.

Review scope includes OAuth client/redirect/PKCE/resource binding, grant isolation,
one-use codes and refresh tokens, revocation, tunnel ownership/reply binding,
body/queue limits, origins and npm artifacts. Tests use synthetic material only.

Required properties:

- Bearers authorize only their grant's resource and library.
- Client bearers never become unrelated upstream API credentials.
- Device keys require explicit approval and remain scoped at the device.
- OAuth calls never silently queue or retry uncertain writes.
- Anonymous bodies cannot consume another grant's reader budget.
- Samples contain no production route, Apple identity or secret.

[Architecture](docs/architecture.md) documents visibility, availability, delayed
device revocation, replay responsibilities, registry capacity and infrastructure
safeguards. Native devices, provider APIs and production setup are outside these
tests. The fixture decrypt helper is not a production device server. Review scopes,
consent and URL-fetch SSRF protection for every adapter. Recheck dependency
advisories and licenses for each release.
