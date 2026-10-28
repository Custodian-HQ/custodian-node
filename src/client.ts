// HTTP client for the Custodian Data Vault API: API key, idempotency keys, typed errors.
// Endpoint methods (customers, sessions, records, ...) are added with the API in Phase 1.
import crypto from 'node:crypto';

export const DEFAULT_BASE_URL = 'https://api.thecustodian.io/vault/v1';

export interface ClientOptions {
  baseUrl?: string;
  fetch?: typeof fetch;
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

  constructor(apiKey: string, options: ClientOptions = {}) {
    if (apiKey.trim() === '') throw new Error('custodian: an API key is required');
    this.#apiKey = apiKey;
    this.#baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, '');
    this.#fetch = options.fetch ?? fetch;
  }

  /** Sends a request. A POST gets an Idempotency-Key, so a retry cannot repeat the action. */
  async request<T>(method: string, path: string, body?: unknown, options: RequestOptions = {}): Promise<T> {
    const headers: Record<string, string> = { Authorization: `Bearer ${this.#apiKey}`, Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (method === 'POST') headers['Idempotency-Key'] = options.idempotencyKey ?? crypto.randomBytes(16).toString('hex');

    const init: RequestInit = { method, headers };
    if (body !== undefined) init.body = JSON.stringify(body);
    if (options.signal) init.signal = options.signal;
    const response = await this.#fetch(this.#baseUrl + path, init);
    const text = await response.text();
    if (!response.ok) throw parseError(response.status, text);
    return (text === '' ? undefined : JSON.parse(text)) as T;
  }
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
