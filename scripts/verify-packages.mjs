import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const artifacts = path.join(root, 'artifacts');
const packages = [
  {
    name: 'marginalia-connect',
    directory: path.join(root, 'packages/marginalia-connect'),
    allowed: new Set([
      'package.json', 'LICENSE', 'README.md', 'bin/marginalia-connect.mjs',
      'index.mjs', 'index.d.mts', 'src/client.mjs', 'src/import.mjs', 'src/respond.mjs',
      'src/sealed.mjs', 'src/sealed.d.mts',
    ]),
    required: ['package.json', 'LICENSE', 'README.md', 'bin/marginalia-connect.mjs', 'index.mjs', 'index.d.mts', 'src/sealed.mjs', 'src/sealed.d.mts'],
  },
  {
    name: 'luff-mcp-relay',
    directory: path.join(root, 'packages/relay-worker'),
    allowed: new Set([
      'package.json', 'LICENSE', 'LICENSE-APACHE-2.0.txt', 'THIRD_PARTY_NOTICES.md', 'README.md',
      'wrangler.example.toml', 'dist/index.js', 'dist/index.d.ts', 'dist/worker-runtime.d.cts',
    ]),
    required: [
      'package.json', 'LICENSE', 'LICENSE-APACHE-2.0.txt', 'THIRD_PARTY_NOTICES.md', 'README.md',
      'wrangler.example.toml', 'dist/index.js', 'dist/index.d.ts', 'dist/worker-runtime.d.cts',
    ],
  },
];

const findings = [];
const secretPatterns = [
  ['AWS access key', /\bAKIA[0-9A-Z]{16}\b/g],
  ['GitHub token', /\b(?:gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{30,})\b/g],
  ['Stripe live secret', /\bsk_live_[A-Za-z0-9]{20,}\b/g],
  ['private key material', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g],
  ['absolute user path', /(?:^|[\s"'=(])\/(?:Users|home)\/[^\s"'`]+/g],
];

function allowedPath(item, list) {
  return list.allowed.has(item);
}

async function run(command, args, options = {}) {
  try {
    const result = await execFileAsync(command, args, { cwd: root, maxBuffer: 16 * 1024 * 1024, ...options });
    return { stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    const details = [error.stdout, error.stderr, error.message].filter(Boolean).join('\n');
    throw new Error(`${command} ${args.join(' ')} failed:\n${details}`, { cause: error });
  }
}

function scanText(label, text) {
  for (const [name, pattern] of secretPatterns) {
    pattern.lastIndex = 0;
    if (pattern.test(text)) findings.push(`${label}: possible ${name}`);
  }
}

async function pack(list, cache) {
  const result = await run('npm', ['pack', '--json', '--pack-destination', artifacts], {
    cwd: list.directory,
    env: {
      ...process.env,
      npm_config_cache: cache,
      npm_config_update_notifier: 'false',
      npm_config_fund: 'false',
      npm_config_audit: 'false',
      WRANGLER_LOG_PATH: path.join(cache, 'wrangler-logs'),
      WRANGLER_WRITE_LOGS: 'false',
    },
  });
  let info;
  try {
    const jsonStart = result.stdout.search(/^\[\s*$/m);
    if (jsonStart < 0) throw new Error('npm pack did not print its JSON file listing');
    [info] = JSON.parse(result.stdout.slice(jsonStart));
  } catch (error) {
    throw new Error(`Could not parse npm pack output for ${list.name}: ${result.stdout}`, { cause: error });
  }
  assert.equal(info.name, list.name, `unexpected package name for ${list.name}`);
  const included = info.files.map(file => file.path).sort();
  const unexpected = included.filter(file => !allowedPath(file, list));
  const missing = list.required.filter(file => !included.includes(file));
  assert.deepEqual(unexpected, [], `${list.name} archive contains files outside its allowlist`);
  assert.deepEqual(missing, [], `${list.name} archive is missing required files`);
  const tarball = path.join(artifacts, info.filename);
  // Scan each archive member separately so a binary or unrelated file cannot mask findings.
  for (const file of included) {
    const extracted = await run('tar', ['-xOf', tarball, `package/${file}`], { maxBuffer: 32 * 1024 * 1024 });
    scanText(`${list.name}/${file}`, extracted.stdout);
  }
  return { name: info.name, version: info.version, filename: info.filename, fileCount: included.length, files: included, tarball };
}

async function smokeInstall(consumer, cache, tarballs) {
  await writeFile(path.join(consumer, 'package.json'), JSON.stringify({ name: 'luff-package-consumer-check', private: true, type: 'module' }, null, 2));
  await run('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', ...tarballs], {
    cwd: consumer,
    env: { ...process.env, npm_config_cache: cache, npm_config_update_notifier: 'false' },
  });
  await run('npm', ['install', '--save-dev', '--ignore-scripts', '--no-audit', '--no-fund',
    'typescript@5.8.3', '@types/node@22.19.11'], {
    cwd: consumer,
    env: { ...process.env, npm_config_cache: cache, npm_config_update_notifier: 'false' },
  });
  const smoke = `import * as api from 'marginalia-connect';
import * as sealed from 'marginalia-connect/sealed';
const apiNames = ['SealedClient','RelayError','DEFAULT_RELAY','DEFAULT_SCOPES','WRITE_TOOLS','pair','pairingCode','resolvePairingCode','loadConfig','saveConfig','pages','importHistory','LIMITS','commandRunner','promptFor','respondOnce'];
const sealedNames = ['b64url','fromB64url','privateKeyFromRaw','rawPublicKey','sealRequest','openRequest','safetyCode','parseAddress'];
for (const name of apiNames) if (!(name in api)) throw new Error('Missing public API export: ' + name);
for (const name of sealedNames) if (!(name in sealed)) throw new Error('Missing sealed API export: ' + name);
console.log('consumer import smoke check passed');
`;
  const smokePath = path.join(consumer, 'smoke.mjs');
  await writeFile(smokePath, smoke);
  await run(process.execPath, [smokePath], { cwd: consumer });
  const bin = path.join(consumer, 'node_modules/.bin/marginalia-connect');
  const help = await run(bin, ['--help'], { cwd: consumer });
  const version = await run(bin, ['--version'], { cwd: consumer });
  assert.match(help.stdout + help.stderr, /marginalia-connect/i, 'installed CLI --help should identify the command');
  assert.match(version.stdout + version.stderr, /\d+\.\d+\.\d+/, 'installed CLI --version should report its package version');
}

async function typecheckConsumer(consumer) {
  const clientTypes = `import * as client from 'marginalia-connect';
import * as sealed from 'marginalia-connect/sealed';

const clientCtor: typeof client.SealedClient = client.SealedClient;
const seal: typeof sealed.sealRequest = sealed.sealRequest;
void [clientCtor, seal];
`;
  const workerTypes = `import type relay from 'luff-mcp-relay';
import type { Tunnel, Gateway, Codes, normalizeCode } from 'luff-mcp-relay';
import type { RelayEnv } from 'luff-mcp-relay';

type Worker = typeof relay;
type DurableClasses = [typeof Tunnel, typeof Gateway, typeof Codes];
type NormalizeCode = typeof normalizeCode;
declare const normalize: NormalizeCode;
const code: string | null = normalize('abc');
declare function checkEnv(env: RelayEnv): [string, RelayEnv['TUNNELS'], RelayEnv['GATEWAY'], RelayEnv['CODES']];
declare const worker: Worker;
declare const classes: DurableClasses;
void [code, worker, classes, checkEnv];
`;
  await writeFile(path.join(consumer, 'client-types.mts'), clientTypes);
  await writeFile(path.join(consumer, 'worker-types.mts'), workerTypes);
  await writeFile(path.join(consumer, 'tsconfig.client.json'), JSON.stringify({
    compilerOptions: {
      target: 'ES2022', module: 'NodeNext', moduleResolution: 'NodeNext', lib: ['ES2022', 'DOM'], strict: true,
      skipLibCheck: false, noEmit: true, types: ['node'],
    },
    files: [path.join(consumer, 'client-types.mts')],
  }, null, 2));
  await writeFile(path.join(consumer, 'tsconfig.worker.json'), JSON.stringify({
    compilerOptions: { target: 'ES2022', module: 'ESNext', moduleResolution: 'Bundler', lib: ['ES2022'], strict: true, skipLibCheck: false, noEmit: true, types: [] },
    files: [path.join(consumer, 'worker-types.mts')],
  }, null, 2));
  const tsc = path.join(consumer, 'node_modules/.bin/tsc');
  await run(tsc, ['--project', path.join(consumer, 'tsconfig.client.json')], { cwd: consumer });
  await run(tsc, ['--project', path.join(consumer, 'tsconfig.worker.json')], { cwd: consumer });
}

async function main() {
  await mkdir(artifacts, { recursive: true });
  const temp = await mkdtemp(path.join(os.tmpdir(), 'luff-package-verify-'));
  const cache = path.join(temp, 'npm-cache');
  const consumer = path.join(temp, 'consumer');
  await mkdir(consumer, { recursive: true });
  try {
    const reports = [];
    for (const list of packages) reports.push(await pack(list, cache));
    if (findings.length) throw new Error(`Package content audit failed:\n${findings.join('\n')}`);
    await smokeInstall(consumer, cache, reports.map(item => item.tarball));
    await typecheckConsumer(consumer);
    const report = {
      generatedAt: new Date().toISOString(),
      result: 'passed',
      checks: ['npm pack file allowlists', 'packed text private-path and secret scan', 'fresh consumer install with lifecycle scripts disabled', 'Node client and sealed API runtime import smoke check', 'installed CLI help/version', 'strict NodeNext client declaration check', 'strict ES2022 worker declaration and export check'],
      packages: reports,
    };
    await writeFile(path.join(artifacts, 'verify-packages.json'), `${JSON.stringify(report, null, 2)}\n`);
    console.log(`Package verification passed; report saved to ${path.relative(root, path.join(artifacts, 'verify-packages.json'))}.`);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
}

main().catch(async error => {
  try {
    await mkdir(artifacts, { recursive: true });
    await writeFile(path.join(artifacts, 'verify-packages.json'), `${JSON.stringify({ generatedAt: new Date().toISOString(), result: 'failed', error: error.message }, null, 2)}\n`);
  } catch (reportError) {
    console.error(`Could not write verification report: ${reportError.message}`);
  }
  console.error(error.stack ?? error);
  process.exitCode = 1;
});
