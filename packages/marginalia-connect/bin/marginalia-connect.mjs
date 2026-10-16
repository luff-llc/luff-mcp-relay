#!/usr/bin/env node
// Connect any agent harness to a Marginalia library through Marginalia Relay,
// end-to-end encrypted: the relay forwards sealed bytes it cannot read.
//
//   marginalia-connect pair CODE [--name "Claude Code"] [--scopes a,b] [--config FILE]   CODE from Marginalia → Agents
//   marginalia-connect mcp [--config FILE]            stdio MCP server for Claude Code, Codex, OpenClaw…
//   marginalia-connect proxy [--config FILE] [--port 18900] [--pass-auth]   plain HTTP on 127.0.0.1, sealed onward
//   marginalia-connect respond [--config FILE] --run "claude -p" [--model NAME] [--once] [--interval 30]
//   marginalia-connect call [--config FILE] METHOD PATH [JSON]
//   marginalia-connect import-books [--config FILE] FILE [--apply] [--report OUT.json]   reading history, dry run unless --apply
//
// CODE is the six-character pairing code Marginalia shows; a full library address ending in #k=… (the
// device's key) still works. The agent key is saved in the config file (mode 600) and never printed.
import { createServer } from 'node:http';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { readFileSync, writeFileSync } from 'node:fs';
import { SealedClient, loadConfig, pair, pairingCode, resolvePairingCode } from '../src/client.mjs';
import { importHistory } from '../src/import.mjs';
import { commandRunner, respondOnce } from '../src/respond.mjs';

const say = text => process.stderr.write(text + '\n');
const help = `marginalia-connect — connect an agent to a Marginalia library

Usage:
  marginalia-connect pair CODE|ADDRESS [--name NAME] [--scopes a,b] [--config FILE] [--relay URL]
  marginalia-connect mcp [--config FILE]
  marginalia-connect proxy [--config FILE] [--port 18900] [--pass-auth]
  marginalia-connect respond --run "claude -p" [--config FILE] [--model NAME] [--once] [--interval 30]
  marginalia-connect call [--config FILE] METHOD PATH [JSON]
  marginalia-connect import-books FILE [--config FILE] [--apply] [--report OUT.json]

Pairing codes appear in Marginalia → Agents. A full library address also works.
Importing is a dry run unless --apply is given. For a self-hosted relay,
pass --relay http://127.0.0.1:8787 when pairing with a code.
`;

function parse(argv) {
  const [command, ...rest] = argv;
  const flags = {}, positional = [];
  for (let index = 0; index < rest.length; index++) {
    const value = rest[index];
    if (value.startsWith('--')) {
      const name = value.slice(2);
      if (['once', 'pass-auth', 'apply'].includes(name)) flags[name] = true;
      else flags[name] = rest[++index];
    } else positional.push(value);
  }
  return { command, flags, positional };
}

const defaultConfig = name => join(homedir(), '.config', 'marginalia', `${(name ?? 'agent').toLowerCase().replace(/[^a-z0-9]+/g, '-')}.json`);

async function main() {
  const argv = process.argv.slice(2);
  if (argv.includes('--help') || argv.includes('-h') || argv.length === 0) {
    process.stdout.write(help);
    return;
  }
  if (argv.includes('--version') || argv.includes('-v')) {
    const metadata = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    process.stdout.write(`${metadata.version}\n`);
    return;
  }
  const { command, flags, positional } = parse(argv);
  const configPath = flags.config ?? defaultConfig(flags.name);
  switch (command) {
    case 'pair': {
      const given = positional[0];
      if (!given) throw new Error('usage: marginalia-connect pair CODE|ADDRESS [--name NAME] [--scopes a,b] [--config FILE] [--relay URL]');
      const code = pairingCode(given);
      const address = code ? await resolvePairingCode(code, { relay: flags.relay }) : given;
      const name = flags.name ?? 'Agent';
      await pair({
        address, name, configPath, scopes: flags.scopes?.split(','),
        onCode: (request, safety) => say([
          `Marginalia is asking you to allow “${name}”. Check it shows both:`,
          `  request code  ${request}`,
          `  safety code   ${safety}`,
          code ? 'If the safety code differs, choose Deny: something is between you and your library.' : '',
          'Waiting…',
        ].filter(Boolean).join('\n')),
      });
      say(`Connected. Saved to ${configPath}.`);
      say(`Claude Code: claude mcp add marginalia -- npx marginalia-connect mcp --config ${configPath}`);
      return;
    }
    case 'mcp': {
      const client = new SealedClient(loadConfig(configPath));
      const lines = createInterface({ input: process.stdin });
      for await (const line of lines) {
        if (!line.trim()) continue;
        let message;
        try { message = JSON.parse(line); } catch {
          process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }) + '\n');
          continue;
        }
        try {
          const reply = await client.mcp(message);
          if (reply && message.id !== undefined) process.stdout.write(JSON.stringify(reply) + '\n');
        } catch (error) {
          if (message.id === undefined) continue;
          const text = error.code === 'device_offline'
            ? 'The device holding the library is offline (asleep, or Marginalia is closed or in the background on iPhone/iPad). Reads need it online; writes are held by the relay until it reconnects.'
            : error.message;
          process.stdout.write(JSON.stringify(message.method === 'tools/call'
            ? { jsonrpc: '2.0', id: message.id, result: { isError: true, content: [{ type: 'text', text }] } }
            : { jsonrpc: '2.0', id: message.id, error: { code: -32000, message: text } }) + '\n');
        }
      }
      return;
    }
    case 'proxy': {
      const config = loadConfig(configPath);
      // --pass-auth forwards the caller's own key instead of this connection's (for test suites).
      const passAuth = flags['pass-auth'] === true;
      const client = new SealedClient({ ...config, token: passAuth ? null : config.token });
      const port = Number(flags.port ?? 18900);
      const server = createServer(async (request, response) => {
        // This proxy holds a key: a web page must never be able to use it.
        if (request.headers.origin || request.headers['sec-fetch-site']) {
          response.writeHead(403, { 'content-type': 'application/json' });
          response.end(JSON.stringify({ error: { code: 'origin_refused', message: 'Browser requests are not accepted.' } }));
          return;
        }
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const text = Buffer.concat(chunks).toString('utf8');
        try {
          // The proxy's own key replaces whatever the local caller sent.
          const headers = passAuth && request.headers.authorization ? { authorization: request.headers.authorization } : {};
          const result = await client.call(request.method, request.url, { body: text ? JSON.parse(text) : undefined, headers });
          response.writeHead(result.status, { 'content-type': 'application/json' });
          response.end(result.json === null ? '' : JSON.stringify(result.json));
        } catch (error) {
          response.writeHead(error.status ?? 502, { 'content-type': 'application/json' });
          response.end(JSON.stringify({ error: { code: error.code ?? 'proxy_error', message: error.message } }));
        }
      });
      server.listen(port, '127.0.0.1', () => say(`Sealed proxy on http://127.0.0.1:${port} → ${client.target.base}`));
      return;
    }
    case 'import-books': {
      const file = positional[0];
      if (!file) throw new Error('usage: marginalia-connect import-books FILE [--apply] [--report OUT.json] [--config FILE]');
      const client = new SealedClient(loadConfig(configPath));
      const history = JSON.parse(readFileSync(file, 'utf8'));
      const result = await importHistory({ client, history, dryRun: flags.apply !== true, log: say });
      if (flags.report) writeFileSync(flags.report, JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });
      process.stdout.write(JSON.stringify({ dryRun: result.dryRun, pages: result.pages, totals: result.totals,
        problems: result.problems.length }, null, 2) + '\n');
      if (result.dryRun) say('Dry run: nothing was saved. Review the totals and problems, then run again with --apply.');
      return;
    }
    case 'respond': {
      if (!flags.run) throw new Error('usage: marginalia-connect respond --run "claude -p" [--model NAME] [--once] [--interval 30]');
      const client = new SealedClient(loadConfig(configPath));
      const run = commandRunner(flags.run);
      const model = flags.model ?? flags.run.split(/\s+/)[0];
      do {
        try { await respondOnce({ client, run, model, log: say }); } catch (error) { say(`Waiting for the device: ${error.message}`); }
        if (flags.once) break;
        await new Promise(resolve => setTimeout(resolve, Number(flags.interval ?? 30) * 1000));
      } while (true);
      return;
    }
    case 'call': {
      const [method, path, body] = positional;
      const client = new SealedClient(loadConfig(configPath));
      const result = await client.call(method, path, { body: body ? JSON.parse(body) : undefined });
      process.stdout.write(JSON.stringify(result.json ?? result, null, 2) + '\n');
      return;
    }
    default:
      throw new Error('usage: marginalia-connect pair | mcp | proxy | respond | call  (see the header of this file)');
  }
}

main().catch(error => { say(error.message); process.exitCode = 1; });
