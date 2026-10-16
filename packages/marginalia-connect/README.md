# marginalia-connect

`marginalia-connect` connects an agent to one Marginalia library through a Marginalia Relay. The CLI can pair an agent, serve Marginalia's tools over stdio MCP, run a local HTTP proxy, answer reading requests with a chosen command, and import reading history. Requests and replies are encrypted for the library device; the relay forwards sealed bytes.

Requires Node.js **22.13 or newer**. This package is a Marginalia-specific adapter. It understands Marginalia's pairing, tool names, history format, and offline-write behavior; it is not a generic MCP relay client. The device must be online for reads and pairing approval. Supported writes can be held, still encrypted, until the device reconnects. A queued receipt means the write has **not yet been applied**.

## Run the CLI

For a development checkout, run `node bin/marginalia-connect.mjs --help` from this directory. To test the exact package artifact before publishing:

```sh
npm pack
npm exec --yes --package ./marginalia-connect-0.4.0-dev.0.tgz -- marginalia-connect --help
```

`npx marginalia-connect` without a local install resolves a version from the npm registry. It will not run this checkout or its newly built tarball unless that version has actually been published. This extraction is MIT licensed; no new npm release has been published.

## Pair with a local relay

Start a self-hosted relay and attach a compatible device implementing [the device contract](https://github.com/luff-llc/luff-mcp-relay/blob/main/docs/device-contract.md). This repository does not include a native app or a UI setting that retargets an installed Marginalia app; that integration is separate. With a compatible device showing its six-character pairing code, run:

```sh
node bin/marginalia-connect.mjs pair K7Q-2MF \
  --relay http://localhost:8787 \
  --name "Local agent" \
  --config ./local-agent.json
```

The code is illustrative. The CLI prints a request code and a safety code. Compare both with Marginalia before approving on the device. It saves the granted agent key in the config file with mode `0600`; keep that file private. A full library address ending in `#k=…` can be used in place of a pairing code. In that case, its embedded relay origin is used and `--relay` has no effect. Relay addresses require HTTPS, except HTTP on loopback for local development.

After pairing, expose the library's tools to an MCP host:

```sh
node bin/marginalia-connect.mjs mcp --config ./local-agent.json
```

For a local HTTP caller, use `proxy --config ./local-agent.json --port 18900`. The proxy listens on `127.0.0.1` and forwards each call through the sealed channel. `call --config ./local-agent.json GET /api/v1/items` makes a direct gateway call. `respond --config ./local-agent.json --run "claude -p" --once` answers currently pending text requests with the named local command; the command must already be installed and suitable for your data. See `--help` for every command and option.

## Import reading history

`import-books` accepts a JSON file shaped for Marginalia's `import_book_history` tool. Each source record needs a stable key so rerunning a page does not duplicate it:

```json
{
  "source": "My reading list",
  "books": [
    {
      "key": "book-1",
      "title": "Example book",
      "readings": [{ "key": "read-1", "finished": "2025-01-01" }],
      "highlights": [{ "key": "quote-1", "quote": "Example passage" }]
    }
  ]
}
```

```sh
node bin/marginalia-connect.mjs import-books ./history.json \
  --config ./local-agent.json --report ./import-report.json
# After reviewing the dry-run totals and problems:
node bin/marginalia-connect.mjs import-books ./history.json \
  --config ./local-agent.json --apply --report ./applied-report.json
```

Import defaults to a dry run and sends pages directly, one receipt at a time. Source systems need their own mapping into this format; the package does not read a Notion, Kindle, or other service export automatically. Ambiguous matches and rejected records appear in the report.

## Node API

The package exports `SealedClient`, `pair`, `resolvePairingCode`, `loadConfig`, `pages`, `importHistory`, and responder helpers as ESM with TypeScript declarations. Cryptographic protocol helpers are available separately from `marginalia-connect/sealed` for integrations and testing. Preserve the sealed-channel framing and domain separators when implementing another client; the [protocol documentation](https://github.com/luff-llc/luff-mcp-relay/blob/main/docs/device-contract.md) describes the wire format.

```js
import { SealedClient, loadConfig } from 'marginalia-connect';

const client = new SealedClient(loadConfig('./local-agent.json'));
const result = await client.tool('get_item', { id: 'example-item' });
console.log(result);
```
