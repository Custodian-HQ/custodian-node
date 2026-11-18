// HTTP client for the Custodian Data Vault API: API key, idempotency keys, typed errors.
import crypto from 'node:crypto';

export const DEFAULT_BASE_URL = 'https://api.thecustodian.io/vault/v1';

const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_RESPONSE_BYTES = 32 << 20;
const MAX_ERROR_BYTES = 64 << 10;
const MAX_RAW_MESSAGE = 200;
/** The `type` of an error the SDK makes itself. Not exported from the package. */
export const API_ERROR_TYPE = 'api_error';

export interface ClientOptions {
  baseUrl?: string;
  fetch?: typeof fetch;
  /**
   * How long to wait for the vault to answer, in milliseconds. The default is 30000. 0 turns the limit off.
   * For a download it limits the wait for the answer to start, not the time to read the file. When the limit
   * is reached the call rejects with a `TimeoutError` (`error.name === 'TimeoutError'`).
   */
  timeoutMs?: number;
  /** Lets `baseUrl` use plain http for a host that is not local. The API key then travels in clear text. */
  allowInsecureHttp?: boolean;
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
    if (apiKey.trim() === '') throw new Error('custodian: no API key was given. Pass your API key to the client');
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (!Number.isFinite(timeoutMs) || timeoutMs < 0) throw new Error('custodian: timeoutMs must be 0 or more');
    this.#apiKey = apiKey;
    this.#baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, '');
    checkBaseUrl(this.#baseUrl, options.allowInsecureHttp === true);
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
    return this.#send(path, init, options.signal, async (response) => {
      const { text, truncated } = await readBody(response, MAX_RESPONSE_BYTES);
      if (truncated) throw new APIError(response.status, API_ERROR_TYPE, 'response_too_large', 'the answer is larger than 32 MiB, so it was not read');
      if (text === '') return undefined as T;
      try {
        return JSON.parse(text) as T;
      } catch {
        throw new APIError(response.status, API_ERROR_TYPE, 'unparsed_response', 'the vault sent an answer that is not JSON. A proxy between you and the vault may have changed it');
      }
    });
  }

  /** Sends a GET and gives back the answer without reading its body, for a download. An error answer is read and thrown. */
  async stream(path: string, headers: Record<string, string> = {}, options: RequestOptions = {}): Promise<Response> {
    const init: RequestInit = { method: 'GET', headers: { ...headers, Authorization: `Bearer ${this.#apiKey}`, Accept: 'application/octet-stream, application/json' } };
    // The time limit covers the wait for the answer only, so a large file can take as long as it needs.
    return this.#send(path, init, options.signal, async (response) => response);
  }

  /** Runs one fetch under the time limit. Redirects are never followed, so the API key cannot go to another host. */
  async #send<T>(path: string, init: RequestInit, signal: AbortSignal | undefined, handle: (response: Response) => Promise<T>): Promise<T> {
    const limit = withTimeout(signal, this.#timeoutMs);
    if (limit.signal) init.signal = limit.signal;
    try {
      const response = await this.#fetch(this.#baseUrl + path, { ...init, redirect: 'manual' });
      if (!response.ok) throw parseError(response.status, (await readBody(response, MAX_ERROR_BYTES)).text);
      return await handle(response);
    } finally {
      limit.stop();
    }
  }
}

function checkBaseUrl(baseUrl: string, allowInsecureHttp: boolean): void {
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new Error('custodian: the base URL is not valid');
  }
  const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
  if (url.protocol === 'https:' || (url.protocol === 'http:' && (local || allowInsecureHttp))) return;
  throw new Error('custodian: the base URL must use https. Plain http works only for localhost, or when you set allowInsecureHttp');
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
    if (e?.code) return new APIError(status, e.type ?? API_ERROR_TYPE, e.code, e.message ?? '', e.request_id, e.param);
  } catch {
    // not JSON: fall through
  }
  const message = text.trim();
  return new APIError(status, API_ERROR_TYPE, 'unparsed_error', message.length > MAX_RAW_MESSAGE ? `${message.slice(0, MAX_RAW_MESSAGE)}...` : message);
}
