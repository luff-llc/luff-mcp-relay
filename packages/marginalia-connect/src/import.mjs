// Bring a whole reading history into Marginalia a page at a time with import_book_history.
// The file has the tool's own shape: {"source": "Notion · Reading List", "books": [...]}.
// Every element carries a key from the source, so a page sent twice changes nothing and an
// interrupted run can simply be started again.

export const LIMITS = { books: 25, highlights: 500, bytes: 800_000 };

/// Split a history into pages under the gateway's limits. A book with more highlights than
/// fit is sent again on later pages with the rest; its readings go only on the first.
export function pages(history, limits = LIMITS) {
  if (!history || typeof history.source !== 'string' || !Array.isArray(history.books)) {
    throw new Error('The file needs {"source": "...", "books": [...]}.');
  }
  const result = [];
  let page = [], highlights = 0, bytes = 0;
  const flush = () => { if (page.length) result.push({ source: history.source, books: page }); page = []; highlights = 0; bytes = 0; };
  for (const book of history.books) {
    const all = book.highlights ?? [];
    let start = 0;
    for (;;) {
      const room = Math.max(1, limits.highlights - highlights);
      const chunk = { ...book, readings: start === 0 ? book.readings ?? [] : [], highlights: all.slice(start, start + room) };
      const size = Buffer.byteLength(JSON.stringify(chunk));
      if (page.length && (page.length >= limits.books || highlights + chunk.highlights.length > limits.highlights
        || bytes + size > limits.bytes || page.some(other => other.key === book.key))) {
        flush();
        continue; // the same chunk again, on a fresh page
      }
      page.push(chunk);
      highlights += chunk.highlights.length;
      bytes += size;
      start += chunk.highlights.length;
      if (start >= all.length) break;
    }
  }
  flush();
  return result;
}

/// Send every page. A dry run saves nothing and reports what would happen. Calls are never
/// queued by the relay: each page needs its receipt before the next one is sent.
export async function importHistory({ client, history, dryRun = true, limits = LIMITS, log = () => {} }) {
  const all = pages(history, limits);
  const totals = {};
  const problems = [];
  for (const [index, books] of all.entries()) {
    const message = { jsonrpc: '2.0', id: index + 1, method: 'tools/call',
      params: { name: 'import_book_history', arguments: { ...books, dry_run: dryRun } } };
    const reply = await client.call('POST', '/mcp', { body: message });
    const text = reply.json?.result?.content?.[0]?.text ?? reply.json?.error?.message ?? '';
    let receipt;
    try { receipt = JSON.parse(text); } catch { throw new Error(`Page ${index + 1} failed: ${text || `status ${reply.status}`}`); }
    if (!receipt.summary) throw new Error(`Page ${index + 1} failed: ${text}`);
    for (const [name, value] of Object.entries(receipt.summary)) totals[name] = (totals[name] ?? 0) + value;
    for (const book of receipt.books) {
      if (book.state === 'ambiguous' || book.state === 'rejected') {
        problems.push({ book: book.key, state: book.state, reason: book.reason, candidates: book.candidates });
      }
      for (const kind of ['readings', 'highlights']) {
        for (const element of book[kind]) {
          if (element.state === 'rejected') problems.push({ book: book.key, [kind.slice(0, -1)]: element.key, reason: element.reason });
        }
      }
    }
    log(`Page ${index + 1} of ${all.length}: ${receipt.summary.highlightsAdded} highlights and ${receipt.summary.readingsAdded + receipt.summary.readingsUpdated} readings ${dryRun ? 'would be saved' : 'saved'}.`);
  }
  return { dryRun, pages: all.length, totals, problems };
}
