import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { APIError, Client } from '../src/client.js';

let server: http.Server | undefined;
afterEach(() => new Promise<void>((done) => (server ? server.close(() => done()) : done())));

async function serve(handler: http.RequestListener): Promise<string> {
  server = http.createServer(handler);
  await new Promise<void>((ok) => server!.listen(0, '127.0.0.1', ok));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
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
});
