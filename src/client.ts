// HTTP client for the Custodian Data Vault API: API key, idempotency keys, typed errors.
// Endpoint methods (customers, sessions, records, ...) are added with the API in Phase 1.
import crypto from 'node:crypto';

export const DEFAULT_BASE_URL = 'https://api.thecustodian.io/vault/v1';

const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_RESPONSE_BYTES = 32 << 20;
const MAX_ERROR_BYTES = 64 << 10;

export interface ClientOptions {
  baseUrl?: string;
  fetch?: typeof fetch;
  /**
   * How long to wait for the vault to answer, in milliseconds. The default is 30000. 0 turns the limit off.
   * For a download it limits the wait for the answer to start, not the time to read the file. When the limit
   * is reached the call rejects with a `TimeoutError` (`error.name === 'TimeoutError'`).
   */
  timeoutMs?: number;
}

export class APIError extends Error {
  constructor(
    readonly status: number,
    readonly type: string,
    readonly code: string,
    message: string,
    readonly requestId: string = '',
    readonly param: string = '',
  ) {
    super(message);
    this.name = 'APIError';
  }
}

export interface RequestOptions {
  idempotencyKey?: string;
  signal?: AbortSignal;
}

export class Client {
  readonly #apiKey: string;
  readonly #baseUrl: string;
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;

  constructor(apiKey: string, options: ClientOptions = {}) {
    if (apiKey.trim() === '') throw new Error('custodian: an API key is required');
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (!Number.isFinite(timeoutMs) || timeoutMs < 0) throw new Error('custodian: timeoutMs must be 0 or more');
    this.#apiKey = apiKey;
    this.#baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, '');
    this.#fetch = options.fetch ?? fetch;
    this.#timeoutMs = timeoutMs;
  }

  /** Sends a request. A POST gets an Idempotency-Key, so a retry cannot repeat the action. */
  async request<T>(method: string, path: string, body?: unknown, options: RequestOptions = {}): Promise<T> {
    const headers: Record<string, string> = { Authorization: `Bearer ${this.#apiKey}`, Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (method === 'POST') headers['Idempotency-Key'] = options.idempotencyKey ?? crypto.randomBytes(16).toString('hex');

    const init: RequestInit = { method, headers };
    if (body !== undefined) init.body = JSON.stringify(body);
    const limit = withTimeout(options.signal, this.#timeoutMs);
    if (limit.signal) init.signal = limit.signal;
    try {
      const response = await this.#fetch(this.#baseUrl + path, init);
      if (!response.ok) throw parseError(response.status, (await readBody(response, MAX_ERROR_BYTES)).text);
      const { text, truncated } = await readBody(response, MAX_RESPONSE_BYTES);
      if (truncated) throw new APIError(response.status, 'api_error', 'response_too_large', 'the answer is larger than 32 MiB');
      if (text === '') return undefined as T;
      try {
        return JSON.parse(text) as T;
      } catch {
        throw new APIError(response.status, 'api_error', 'unparsed_response', 'the answer is not JSON');
      }
    } finally {
      limit.stop();
    }
  }

  /** Sends a GET and gives back the answer without reading its body, for a download. An error answer is read and thrown. */
  async stream(path: string, headers: Record<string, string> = {}, options: RequestOptions = {}): Promise<Response> {
    const init: RequestInit = { method: 'GET', headers: { ...headers, Authorization: `Bearer ${this.#apiKey}`, Accept: 'application/octet-stream, application/json' } };
    const limit = withTimeout(options.signal, this.#timeoutMs);
    if (limit.signal) init.signal = limit.signal;
    let response: Response;
    try {
      response = await this.#fetch(this.#baseUrl + path, init);
      if (!response.ok) throw parseError(response.status, (await readBody(response, MAX_ERROR_BYTES)).text);
    } finally {
      // The time limit covers the wait for the answer only, so a large file can take as long as it needs.
      limit.stop();
    }
    return response;
  }
}

function withTimeout(caller: AbortSignal | undefined, ms: number): { signal: AbortSignal | undefined; stop: () => void } {
  if (ms === 0) return { signal: caller, stop: () => undefined };
  const timer = new AbortController();
  const id = setTimeout(() => timer.abort(new DOMException(`the vault did not answer within ${ms} ms`, 'TimeoutError')), ms);
  return { signal: caller ? AbortSignal.any([caller, timer.signal]) : timer.signal, stop: () => clearTimeout(id) };
}

/** Reads at most `limit` bytes. If the body is longer, it stops reading, cancels it and says so. */
async function readBody(response: Response, limit: number): Promise<{ text: string; truncated: boolean }> {
  if (!response.body) return { text: '', truncated: false };
  const reader = response.body.getReader();
  const parts: Uint8Array[] = [];
  let size = 0;
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (size + value.length > limit) {
      parts.push(value.subarray(0, limit - size));
      truncated = true;
      await reader.cancel().catch(() => undefined);
      break;
    }
    parts.push(value);
    size += value.length;
  }
  return { text: Buffer.concat(parts).toString('utf8'), truncated };
}

function parseError(status: number, text: string): APIError {
  try {
    const parsed = JSON.parse(text) as { error?: { type?: string; code?: string; message?: string; request_id?: string; param?: string } };
    const e = parsed.error;
    if (e?.code) return new APIError(status, e.type ?? 'api_error', e.code, e.message ?? '', e.request_id, e.param);
  } catch {
    // not JSON: fall through
  }
  return new APIError(status, 'api_error', 'unparsed_error', text.trim());
}
