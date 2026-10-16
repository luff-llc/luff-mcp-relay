import type { Buffer } from 'node:buffer';

export interface ConnectionConfig {
  address: string;
  token: string;
  scopes?: string[];
  name?: string;
  safetyCode?: string;
}

export interface McpMessage {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: { name?: string; arguments?: Record<string, unknown>; [key: string]: unknown };
  [key: string]: unknown;
}

export interface McpReply {
  jsonrpc: '2.0';
  id?: string | number | null;
  result?: { isError?: boolean; content?: Array<{ type: string; text?: string }>; [key: string]: unknown };
  error?: { code: number; message: string; [key: string]: unknown };
  [key: string]: unknown;
}

export interface CallOptions {
  body?: unknown;
  headers?: Record<string, string>;
  queued?: boolean;
}

export type CallResult = { status: number; json: unknown } | { queued: unknown };
export type FetchImpl = (input: string, init: RequestInit) => Promise<Response>;

export declare class RelayError extends Error {
  constructor(status: number, code: string, message: string);
  status: number;
  code: string;
}

export declare class SealedClient {
  constructor(options: { address: string; token?: string | null; fetchImpl?: FetchImpl });
  address: string;
  target: { base: string; tunnel: string; devicePublicKey: Buffer };
  safetyCode: string;
  token: string | null;
  fetch: FetchImpl;
  call(method: string, path: string, options?: CallOptions): Promise<CallResult>;
  mcp(message: McpMessage): Promise<McpReply | null>;
  tool(name: string, args?: Record<string, unknown>): Promise<Record<string, unknown>>;
}

export declare const WRITE_TOOLS: Set<string>;
export declare const DEFAULT_RELAY: string;
export declare const DEFAULT_SCOPES: string[];
export declare function pairingCode(value: unknown): string | null;
export declare function resolvePairingCode(code: string, options?: { relay?: string; fetchImpl?: FetchImpl }): Promise<string>;
export declare function pair(options: {
  address: string;
  name: string;
  configPath: string;
  scopes?: string[];
  fetchImpl?: FetchImpl;
  onCode?: (requestCode: string, safetyCode: string) => void;
  pollMs?: number;
  timeoutMs?: number;
}): Promise<ConnectionConfig>;
export declare function saveConfig(path: string, config: ConnectionConfig): void;
export declare function loadConfig(path: string): ConnectionConfig;

export interface HistoryBook {
  key: string;
  highlights?: Array<Record<string, unknown>>;
  readings?: Array<Record<string, unknown>>;
  [key: string]: unknown;
}
export interface History { source: string; books: HistoryBook[] }
export interface PageLimits { books: number; highlights: number; bytes: number }
export interface ImportProblem {
  book: string;
  state?: string;
  reason?: string | null;
  candidates?: unknown[];
  reading?: string;
  highlight?: string;
}
export interface ImportResult {
  dryRun: boolean;
  pages: number;
  totals: Record<string, number>;
  problems: ImportProblem[];
}
export declare const LIMITS: PageLimits;
export declare function pages(history: History, limits?: PageLimits): History[];
export declare function importHistory(options: {
  client: Pick<SealedClient, 'call'>;
  history: History;
  dryRun?: boolean;
  limits?: PageLimits;
  log?: (message: string) => void;
}): Promise<ImportResult>;

export interface PendingRequest {
  id: string;
  item: string;
  kind: string;
  instruction?: string;
  title?: string;
  hasPhoto?: boolean;
  [key: string]: unknown;
}
export interface LibraryItem {
  title?: string;
  author?: string;
  url?: string;
  text?: string;
  [key: string]: unknown;
}
export declare function promptFor(request: PendingRequest, item: LibraryItem): string;
export declare function commandRunner(command: string, options?: { timeoutMs?: number }): (prompt: string) => Promise<string>;
export declare function respondOnce(options: {
  client: Pick<SealedClient, 'tool'>;
  run: (prompt: string, context: { request: PendingRequest; item: LibraryItem }) => Promise<string>;
  model?: string | null;
  log?: (message: string) => void;
}): Promise<Array<{ id: string; answered: boolean; error?: string }>>;
