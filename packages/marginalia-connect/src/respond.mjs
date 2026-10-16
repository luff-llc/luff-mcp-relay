// Answers what the user asks from their phone ("Summarize", "Ask a question") by
// running an agent they choose — `claude -p`, `codex exec`, a local model — and
// attaching its answer to the item, attributed to this connection.
import { spawn } from 'node:child_process';

const MAX_TEXT = 60_000;

export function promptFor(request, item) {
  const text = String(item.text ?? '').slice(0, MAX_TEXT);
  return [
    request.kind === 'summarize'
      ? 'Summarize this item for the reader in a few short paragraphs. Be faithful to the text; do not invent.'
      : `Answer the reader's question about this item, using the text. Say so if the text does not answer it.\n\nQuestion: ${request.instruction}`,
    '',
    `Title: ${item.title}`,
    item.author ? `Author: ${item.author}` : '',
    item.url ? `Link: ${item.url}` : '',
    '',
    text + (String(item.text ?? '').length > MAX_TEXT ? '\n\n[The text continues; this is the first part.]' : ''),
  ].filter(line => line !== null).join('\n');
}

/// Run a shell command with the prompt on stdin; its stdout is the answer.
export function commandRunner(command, { timeoutMs = 600_000 } = {}) {
  return prompt => new Promise((resolve, reject) => {
    const child = spawn(command, { shell: true, stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '', err = '';
    const timer = setTimeout(() => { child.kill('SIGTERM'); reject(new Error(`${command} took too long.`)); }, timeoutMs);
    child.stdout.on('data', chunk => { out += chunk; });
    child.stderr.on('data', chunk => { err += chunk; });
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', code => {
      clearTimeout(timer);
      if (code === 0 && out.trim()) resolve(out.trim());
      else reject(new Error(`${command} exited ${code}: ${(err.trim() || out.trim()).slice(0, 500)}`));
    });
    child.stdin.end(prompt);
  });
}

/// Answer every open request once. Returns what happened to each.
export async function respondOnce({ client, run, model = null, log = () => {} }) {
  const pending = await client.tool('pending_requests');
  const results = [];
  // A page photo needs an agent that can see it (request_photo), not the item's text.
  for (const request of (pending.requests ?? []).filter(request => !request.hasPhoto).slice(0, 10)) {
    try {
      const item = await client.tool('get_item', { id: request.item });
      const answer = await run(promptFor(request, item), { request, item });
      await client.tool('add_insight', {
        item: request.item, request: request.id, text: answer.slice(0, 100_000),
        command_id: `respond-${request.id}`.replace(/[^A-Za-z0-9_-]/g, '-').slice(0, 128),
        ...(model ? { model } : {}),
      });
      log(`Answered ${request.kind} for “${request.title ?? request.item}”.`);
      results.push({ id: request.id, answered: true });
    } catch (error) {
      log(`Could not answer ${request.id}: ${error.message}`);
      results.push({ id: request.id, answered: false, error: error.message });
    }
  }
  return results;
}
