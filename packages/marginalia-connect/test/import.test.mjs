import assert from 'node:assert/strict';
import { test } from 'node:test';
import { importHistory, pages } from '../src/import.mjs';

// Synthetic history only: no real titles or reading data.
const history = {
  source: 'Notion · Reading List',
  books: Array.from({ length: 30 }, (_, index) => ({
    key: `row-${index}`, title: `Book ${index}`,
    readings: [{ key: 'r1', finished: '2020-01-01' }],
    highlights: Array.from({ length: index === 0 ? 1_200 : 3 }, (__, n) => ({ key: `h${n}`, quote: `Line ${n}` })),
  })),
};

test('a history is paged under the limits, a long book across pages, its readings once', () => {
  const result = pages(history);
  for (const page of result) {
    assert.ok(page.books.length <= 25);
    assert.ok(page.books.reduce((sum, book) => sum + book.highlights.length, 0) <= 500);
    assert.ok(Buffer.byteLength(JSON.stringify(page)) <= 800_000);
    assert.equal(new Set(page.books.map(book => book.key)).size, page.books.length);
    assert.equal(page.source, 'Notion · Reading List');
  }
  const first = result.flatMap(page => page.books).filter(book => book.key === 'row-0');
  assert.equal(first.length, 3);
  assert.equal(first.reduce((sum, book) => sum + book.highlights.length, 0), 1_200);
  assert.equal(first.filter(book => book.readings.length > 0).length, 1);
  const keys = new Set(result.flatMap(page => page.books.flatMap(book => book.highlights.map(h => `${book.key}/${h.key}`))));
  assert.equal(keys.size, 1_200 + 29 * 3);
  assert.throws(() => pages({ books: [] }));
});

test('every page is sent live as a dry run by default, and problems are collected', async () => {
  const sent = [];
  const client = {
    async call(method, path, { body }) {
      assert.equal(method, 'POST');
      assert.equal(path, '/mcp');
      sent.push(body.params.arguments);
      const books = body.params.arguments.books.map(book => ({
        key: book.key, state: book.key === 'row-1' ? 'ambiguous' : 'matched', reason: null, candidates: [],
        readings: book.readings.map(r => ({ key: r.key, state: 'added' })),
        highlights: book.highlights.map(h => ({ key: h.key, state: 'added' })),
      }));
      const summary = { highlightsAdded: books.reduce((n, b) => n + b.highlights.length, 0),
        readingsAdded: books.reduce((n, b) => n + b.readings.length, 0), readingsUpdated: 0 };
      return { status: 200, json: { result: { content: [{ type: 'text', text: JSON.stringify({ summary, books }) }] } } };
    },
  };
  const result = await importHistory({ client, history });
  assert.equal(result.dryRun, true);
  assert.ok(sent.every(args => args.dry_run === true));
  assert.equal(result.totals.highlightsAdded, 1_200 + 29 * 3);
  assert.equal(result.totals.readingsAdded, 30);
  assert.deepEqual(result.problems.map(problem => problem.book), ['row-1']);
  const applied = await importHistory({ client, history, dryRun: false });
  assert.equal(applied.dryRun, false);
  assert.ok(sent.slice(-applied.pages).every(args => args.dry_run === false));
});
