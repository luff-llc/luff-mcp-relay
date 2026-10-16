import { execFile } from 'node:child_process';
import { mkdir, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ignoreDirs = new Set(['.git', 'node_modules', 'artifacts', 'dist', '.wrangler']);
const findings = [];
const secretRules = [
  ['AWS access key', /\bAKIA[0-9A-Z]{16}\b/g],
  ['GitHub token', /\b(?:gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{30,})\b/g],
  ['Stripe live secret', /\bsk_live_[A-Za-z0-9]{20,}\b/g],
  ['private key material', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g],
];
const privatePathRules = [
  /(?:^|[\s"'=(])\/(?:Users|home)\/[^\s"'`]+/g,
  /(?:^|[\s"'=(])\/private\/var\/[^\s"'`]+/g,
];

async function trackedFiles() {
  try {
    const { stdout } = await execFileAsync('git', ['ls-files', '-z'], { cwd: root, maxBuffer: 16 * 1024 * 1024 });
    const tracked = stdout.split('\0').filter(Boolean);
    if (tracked.length) return tracked;
  } catch {
    // A new repository may not have any staged or committed files yet.
  }
  const files = [];
  async function walk(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (entry.isDirectory() && ignoreDirs.has(entry.name)) continue;
      const full = path.join(directory, entry.name);
      if (entry.isDirectory()) await walk(full);
      else if (entry.isFile()) files.push(path.relative(root, full).split(path.sep).join('/'));
    }
  }
  await walk(root);
  return files;
}

function report(file, line, message) {
  findings.push(`${file}:${line}: ${message}`);
}

function inspectLinks(file, text, knownFiles) {
  if (!file.toLowerCase().endsWith('.md') && !file.toLowerCase().endsWith('.mdx')) return;
  const lines = text.split(/\r?\n/);
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex];
    const regex = /!?\[[^\]]*\]\(\s*(?:<([^>]+)>|([^\s)]+))(?:\s+[^)]*)?\)/g;
    for (const match of line.matchAll(regex)) {
      const target = (match[1] ?? match[2] ?? '').replace(/&amp;/g, '&');
      if (!target || /^(?:[a-z][a-z0-9+.-]*:|\/\/|#)/i.test(target)) continue;
      let pathname;
      try { pathname = decodeURIComponent(target.split(/[?#]/, 1)[0]); } catch { pathname = target.split(/[?#]/, 1)[0]; }
      if (!pathname) continue;
      const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(file), pathname)).replace(/\/$/, '');
      if (resolved.startsWith('../') || resolved === '..') {
        report(file, lineIndex + 1, `local Markdown link escapes the repository: ${target}`);
        continue;
      }
      if (!knownFiles.has(resolved)) report(file, lineIndex + 1, `broken local Markdown link: ${target}`);
    }
  }
}

async function main() {
  const files = await trackedFiles();
  const knownFiles = new Set(files);
  for (const file of files) {
    let parent = path.posix.dirname(file);
    while (parent && parent !== '.') {
      knownFiles.add(parent);
      parent = path.posix.dirname(parent);
    }
  }
  let scanned = 0;
  for (const file of files) {
    const full = path.join(root, file);
    const metadata = await stat(full).catch(() => null);
    if (!metadata?.isFile()) {
      report(file, 1, 'candidate is not a regular file and could not be audited');
      continue;
    }
    if (metadata.size > 2 * 1024 * 1024) {
      report(file, 1, `file is too large to audit (${metadata.size} bytes)`);
      continue;
    }
    const bytes = await readFile(full).catch(() => null);
    if (bytes === null) {
      report(file, 1, 'file could not be read');
      continue;
    }
    if (bytes.includes(0)) {
      report(file, 1, 'binary or NUL-containing file could not be text-audited');
      continue;
    }
    let text;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
    catch {
      report(file, 1, 'file is not valid UTF-8 text and could not be audited');
      continue;
    }
    scanned++;
    const lines = text.split(/\r?\n/);
    lines.forEach((line, index) => {
      for (const [name, regex] of secretRules) {
        regex.lastIndex = 0;
        if (regex.test(line)) report(file, index + 1, `possible ${name}`);
      }
      for (const regex of privatePathRules) {
        regex.lastIndex = 0;
        if (regex.test(line)) report(file, index + 1, 'absolute private machine path');
      }
    });
    inspectLinks(file, text, knownFiles);
  }
  const reportData = { generatedAt: new Date().toISOString(), result: findings.length ? 'failed' : 'passed', filesConsidered: files.length, textFilesScanned: scanned, findings };
  const artifacts = path.join(root, 'artifacts');
  await mkdir(artifacts, { recursive: true });
  await writeFile(path.join(artifacts, 'audit-public.json'), `${JSON.stringify(reportData, null, 2)}\n`);
  if (findings.length) {
    console.error(`Public source audit found ${findings.length} issue(s):\n${findings.join('\n')}`);
    process.exitCode = 1;
    return;
  }
  console.log(`Public source audit passed (${scanned} text files scanned).`);
}

main().catch(error => {
  console.error(error.stack ?? error);
  process.exitCode = 1;
});
