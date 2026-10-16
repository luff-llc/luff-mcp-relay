import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import * as api from '../index.mjs';

const cli = fileURLToPath(new URL('../bin/marginalia-connect.mjs', import.meta.url));
const metadata = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

test('public ESM entry exposes the client and workflows', () => {
  for (const name of ['SealedClient', 'pair', 'loadConfig', 'resolvePairingCode', 'importHistory', 'pages', 'respondOnce']) {
    assert.equal(typeof api[name], 'function', name);
  }
  assert.equal(api.DEFAULT_RELAY.startsWith('https://'), true);
});

test('help and version exit cleanly without loading a configuration', () => {
  for (const args of [['--help'], ['pair', '--help'], ['--version'], ['pair', '--version']]) {
    const result = spawnSync(process.execPath, [cli, ...args, '--config', '/missing/marginalia.json'], { encoding: 'utf8' });
    assert.equal(result.status, 0, `${args.join(' ')}: ${result.stderr}`);
    assert.equal(result.stderr, '');
    if (args.includes('--help')) {
      assert.match(result.stdout, /marginalia-connect pair CODE\|ADDRESS/);
      assert.match(result.stdout, /marginalia-connect import-books FILE/);
    } else assert.equal(result.stdout, `${metadata.version}\n`);
  }
});
