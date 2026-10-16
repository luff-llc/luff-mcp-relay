import { readFileSync, writeFileSync, rmSync } from 'node:fs';
const path = new URL('../packages/relay-worker/dist/index.d.ts', import.meta.url);
const declarations = readFileSync(path, 'utf8').replace(/\bEnv\b/g, 'RelayEnv');
const generated = readFileSync(new URL('../packages/relay-worker/worker-configuration.d.ts', import.meta.url), 'utf8');
const marker = '// Begin runtime types';
if (!generated.includes(marker)) throw new Error('Generated Worker runtime types marker missing');
writeFileSync(new URL('../packages/relay-worker/dist/worker-runtime.d.cts', import.meta.url), generated.slice(generated.indexOf(marker)));
writeFileSync(path, `/// <reference path="./worker-runtime.d.cts" />\nexport interface RelayEnv {\n  RELAY_ORIGIN: string;\n  TUNNELS: DurableObjectNamespace<Tunnel>;\n  GATEWAY: DurableObjectNamespace<Gateway>;\n  CODES: DurableObjectNamespace<Codes>;\n  AI?: { run(model: string, input: unknown): Promise<unknown> };\n}\n` + declarations);
rmSync(new URL('../packages/relay-worker/dist/worker-runtime.d.ts', import.meta.url), { force: true });
