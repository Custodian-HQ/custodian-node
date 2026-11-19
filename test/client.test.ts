import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { APIError, Client } from '../src/client.js';

let server: http.Server | undefined;
let other: http.Server | undefined;
afterEach(async () => {
  for (const s of [server, other]) {
    s?.closeAllConnections();
    await new Promise<void>((done) => (s ? s.close(() => done()) : done()));
  }
  server = other = undefined;
});

async function listen(handler: http.RequestListener): Promise<{ server: http.Server; url: string }> {
  const s = http.createServer(handler);
  await new Promise<void>((ok) => s.listen(0, '127.0.0.1', ok));
  return { server: s, url: `http://127.0.0.1:${(s.address() as AddressInfo).port}` };
}

const nameOf = (error: unknown): string => (error instanceof Error ? error.name : String(error));

async function serve(handler: http.RequestListener): Promise<string> {
  const started = await listen(handler);
  server = started.server;
  return started.url;
}

describe('Client', () => {
  it('sends the key, and an idempotency key on POST only', async () => {
    const seen: http.IncomingHttpHeaders[] = [];
    const baseUrl = await serve((req, res) => { seen.push(req.headers); res.end('{"ok":true}'); });
    const client = new Client('cdv_test_key', { baseUrl: baseUrl + '/' });

    await expect(client.request('POST', '/customers', { external_ref: 'u1' })).resolves.toEqual({ ok: true });
    await client.request('POST', '/customers', undefined, { idempotencyKey: 'mine' });
    await client.request('GET', '/customers');

    expect(seen[0]?.authorization).toBe('Bearer cdv_test_key');
    expect(seen[0]?.['idempotency-key']).toHaveLength(32);
    expect(seen[1]?.['idempotency-key']).toBe('mine');
    expect(seen[2]?.['idempotency-key']).toBeUndefined();
  });

  it('turns an error body into an APIError', async () => {
    const baseUrl = await serve((_req, res) => {
      res.writeHead(404).end('{"error":{"type":"not_found_error","code":"customer_not_found","message":"No such customer","request_id":"abc"}}');
    });
    const error = await new Client('k', { baseUrl }).request('GET', '/customers/x').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(APIError);
    expect(error).toMatchObject({ status: 404, code: 'customer_not_found', requestId: 'abc' });
  });

  it('still gives an APIError when the body is not JSON', async () => {
    const baseUrl = await serve((_req, res) => { res.writeHead(502).end('bad gateway'); });
    await expect(new Client('k', { baseUrl }).request('GET', '/x')).rejects.toMatchObject({ status: 502, code: 'unparsed_error' });
  });

  it('refuses an empty API key', () => {
    expect(() => new Client('  ')).toThrow('API key');
  });

  it('gives an APIError when a good answer is not JSON', async () => {
    const baseUrl = await serve((_req, res) => { res.writeHead(200, { 'content-type': 'text/html' }).end('<html>captive portal</html>'); });
    await expect(new Client('k', { baseUrl }).request('GET', '/x')).rejects.toMatchObject({ name: 'APIError', status: 200, code: 'unparsed_response' });
  });
});

describe('Client time limit', () => {
  it('stops a call that gets no answer, with a TimeoutError', async () => {
    const baseUrl = await serve(() => undefined);
    const error = await new Client('k', { baseUrl, timeoutMs: 50 }).request('GET', '/x').catch((e: unknown) => e);
    expect(nameOf(error)).toBe('TimeoutError');
  });

  it('stops a call whose body stalls', async () => {
    const baseUrl = await serve((_req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.write('{"a":'); });
    const error = await new Client('k', { baseUrl, timeoutMs: 50 }).request('GET', '/x').catch((e: unknown) => e);
    expect(nameOf(error)).toBe('TimeoutError');
  });

  it('waits as long as needed when the limit is 0, and refuses a limit that is not a number of 0 or more', async () => {
    const baseUrl = await serve((_req, res) => { setTimeout(() => res.end('{"ok":true}'), 120); });
    await expect(new Client('k', { baseUrl, timeoutMs: 0 }).request('GET', '/x')).resolves.toEqual({ ok: true });
    for (const bad of [-1, Number.NaN, Number.POSITIVE_INFINITY]) expect(() => new Client('k', { timeoutMs: bad })).toThrow('timeoutMs');
  });

  it('stops when the caller aborts, with its own signal', async () => {
    const baseUrl = await serve(() => undefined);
    const controller = new AbortController();
    const call = new Client('k', { baseUrl }).request('GET', '/x', undefined, { signal: controller.signal }).catch((e: unknown) => e);
    setTimeout(() => controller.abort(), 30);
    expect(nameOf(await call)).toBe('AbortError');
  });

  it('limits the wait for a download to start, and then lets the body take its time', async () => {
    const baseUrl = await serve((req, res) => {
      if (req.url === '/silent') return;
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.write('first');
      setTimeout(() => res.end('second'), 150);
    });
    const client = new Client('k', { baseUrl, timeoutMs: 50 });
    expect(nameOf(await client.stream('/silent').catch((e: unknown) => e))).toBe('TimeoutError');
    const response = await client.stream('/slow');
    expect(await response.text()).toBe('firstsecond');
  });

  it('also limits the read of an error answer to a download', async () => {
    const baseUrl = await serve((_req, res) => { res.writeHead(502, { 'content-type': 'text/plain' }); res.write('bad'); });
    const error = await new Client('k', { baseUrl, timeoutMs: 50 }).stream('/x').catch((e: unknown) => e);
    expect(nameOf(error)).toBe('TimeoutError');
  });
});

describe('Client body limits', () => {
  /** A body of `chunks` pieces of `size` bytes that counts what was asked for and whether it was cancelled. */
  function body(chunks: number, size: number): { stream: ReadableStream<Uint8Array>; state: { pulled: number; cancelled: boolean } } {
    const state = { pulled: 0, cancelled: false };
    const stream = new ReadableStream<Uint8Array>(
      {
        pull(controller) {
          if (state.pulled >= chunks) return controller.close();
          state.pulled++;
          controller.enqueue(new Uint8Array(size).fill(0x20));
        },
        cancel() {
          state.cancelled = true;
        },
      },
      { highWaterMark: 0 },
    );
    return { stream, state };
  }

  it('refuses an answer larger than 32 MiB and stops reading it', async () => {
    const { stream, state } = body(100, 1 << 20);
    const client = new Client('k', { fetch: async () => new Response(stream, { status: 200 }) });
    await expect(client.request('GET', '/x')).rejects.toMatchObject({ code: 'response_too_large' });
    expect(state.cancelled).toBe(true);
    expect(state.pulled).toBeLessThanOrEqual(34);
  });

  it('does not call a 1 MiB answer too large', async () => {
    const { stream } = body(1, 1 << 20);
    const client = new Client('k', { fetch: async () => new Response(stream, { status: 200, headers: { 'content-type': 'application/json' } }) });
    await expect(client.request('GET', '/x')).rejects.toMatchObject({ code: 'unparsed_response' });
  });

  it('reads at most 64 KiB of an error answer, in request and in stream', async () => {
    for (const call of [(c: Client) => c.request('GET', '/x'), (c: Client) => c.stream('/x')]) {
      const { stream, state } = body(1 << 20, 1024);
      const client = new Client('k', { fetch: async () => new Response(stream, { status: 502 }) });
      const error = await call(client).catch((e: unknown) => e);
      expect(error).toMatchObject({ name: 'APIError', status: 502, code: 'unparsed_error' });
      expect(state.cancelled).toBe(true);
      expect(state.pulled).toBeLessThanOrEqual(66);
    }
  });
});

describe('Client redirects', () => {
  it('does not follow a redirect to another host', async () => {
    const seen: { a?: string | undefined; b?: string | undefined } = {};
    const b = await listen((req, res) => { seen.b = req.headers.authorization; res.end('{"landed":true}'); });
    other = b.server;
    const baseUrl = await serve((req, res) => { seen.a = req.headers.authorization; res.writeHead(302, { location: `${b.url}/stolen` }).end(); });
    await expect(new Client('cdv_test_secret', { baseUrl }).request('POST', '/x', { a: 1 })).rejects.toMatchObject({ status: 302 });
    expect(seen.a).toBe('Bearer cdv_test_secret');
    expect(seen.b).toBeUndefined();
  });

  it('does not follow a redirect on a download either', async () => {
    let leaked: string | undefined;
    const b = await listen((req, res) => { leaked = req.headers.authorization; res.end('file'); });
    other = b.server;
    const baseUrl = await serve((_req, res) => { res.writeHead(302, { location: b.url }).end(); });
    await expect(new Client('cdv_test_secret', { baseUrl }).stream('/file')).rejects.toMatchObject({ status: 302 });
    expect(leaked).toBeUndefined();
  });
});

describe('Client base URL', () => {
  it('refuses plain http to a remote host unless the option allows it', () => {
    expect(() => new Client('k', { baseUrl: 'http://api.example.com/vault/v1' })).toThrow(/https/);
    expect(() => new Client('k', { baseUrl: 'http://api.example.com/vault/v1', allowInsecureHttp: true })).not.toThrow();
    for (const baseUrl of ['http://localhost:8080', 'http://127.0.0.1:1', 'http://[::1]:1', 'https://api.example.com']) {
      expect(() => new Client('k', { baseUrl })).not.toThrow();
    }
  });
});
