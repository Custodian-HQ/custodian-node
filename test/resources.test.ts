import crypto from 'node:crypto';
import fs from 'node:fs';
import { describe, expect, it } from 'vitest';
import { Custodian } from '../src/custodian.js';
import { Purpose } from '../src/enums.js';

/** "METHOD /path" for every operation in the vendored business API spec, as a pattern. */
function specOperations(): Map<string, RegExp> {
  const text = fs.readFileSync('test/spec/openapi-vault.yaml', 'utf8');
  const pinned = fs.readFileSync('test/spec/openapi-vault.lock', 'utf8').trim();
  if (crypto.createHash('sha256').update(text).digest('hex') !== pinned) {
    throw new Error('test/spec/openapi-vault.yaml is not the pinned spec: run scripts/vendor-spec.mjs and review the diff');
  }
  const operations = new Map<string, RegExp>();
  let inPaths = false;
  let path = '';
  for (const line of text.split('\n')) {
    if (line === 'paths:') inPaths = true;
    else if (inPaths && line !== '' && !line.startsWith(' ')) inPaths = false;
    else if (inPaths && /^ {2}\/.*:$/.test(line)) path = line.trim().slice(0, -1);
    else if (inPaths && /^ {4}(get|post|put|patch|delete):$/.test(line)) {
      const method = line.trim().slice(0, -1).toUpperCase();
      const pattern = path.replace(/[.*+?^$()|[\]\\]/g, '\\$&').replace(/\{[^}]+\}/g, '[^/]+');
      operations.set(`${method} ${path}`, new RegExp(`^${pattern}$`));
    }
  }
  expect(operations.size).toBeGreaterThan(20);
  return operations;
}

describe('the SDK and the API spec', () => {
  it('call exactly the same operations', async () => {
    const seen: string[] = [];
    const fetchStub: typeof fetch = async (input, init) => {
      const url = new URL(String(input));
      const method = init?.method ?? 'GET';
      seen.push(`${method} ${url.pathname}`);
      const empty = method === 'DELETE' || url.pathname.endsWith('/retry');
      return new Response(empty ? null : '{"data":[]}', { status: empty ? 204 : 200 });
    };
    const c = new Custodian('k', { baseUrl: 'https://api.test/vault/v1', fetch: fetchStub });

    await c.me();
    await c.customers.create('ref');
    await c.customers.get('cus_1');
    await c.customers.delete('cus_1');
    await c.customers.reset('cus_1', { return_url: 'https://a.example/x', state: 's' });
    await c.customers.list({ limit: 5, starting_after: 'cus_1', external_ref: 'x', state: 'reset: enrolment needed' });
    await c.resetContactText.get();
    await c.resetContactText.set('Call us');
    await c.sessions.create({ customer: 'cus_1', purpose: Purpose.Enrol, return_url: 'https://a.example/x', state: 's' });
    await c.sessions.retrieve('ses_1');
    await c.records.list({ customer: 'cus_1', limit: 5, starting_after: 'rec_1' });
    await c.records.get('rec_1');
    await c.disclosures.envelope('dsc_1');
    await c.disclosures.acknowledge('dsc_1');
    await c.disclosures.downloadFile('dsc_1', 'passport');
    await c.templates.list();
    await c.templates.create({ name: 'kyc', keys: [{ name: 'a' }] });
    await c.templates.get('kyc');
    await c.templates.replace('kyc', [{ name: 'b' }]);
    await c.templates.delete('kyc');
    await c.disclosureKeys.list();
    await c.disclosures.create({ record: 'rec_1', keys: ['a'], reason: 'r', disclosure_key_fingerprint: 'f' });
    await c.disclosures.get('dsc_1');
    await c.disclosures.list({ status: 'pending', limit: 5, starting_after: 'dsc_1' });
    await c.disclosures.cancel('dsc_1');
    await c.recoveryPolicy.get();
    await c.recoveryPolicy.set(3);
    await c.webhookEndpoints.list();
    await c.webhookDeliveries.list({ endpoint: 'we_1', limit: 5, starting_after: 9 });
    await c.webhookDeliveries.retry(7);
    await c.usage();
    await c.auditEvents({ limit: 5, starting_after: 9 });

    const operations = specOperations();
    const covered = new Set<string>();
    for (const call of seen) {
      const [method, path] = call.split(' ') as [string, string];
      const route = path.replace('/vault/v1', '');
      const hit = [...operations].filter(([key, pattern]) => key.startsWith(`${method} `) && pattern.test(route));
      expect(hit.length, `the SDK calls ${call}, which the spec does not have`).toBeGreaterThan(0);
      for (const [key] of hit) covered.add(key);
    }
    const missing = [...operations.keys()].filter((key) => !covered.has(key)).sort();
    expect(missing, 'the spec has operations with no SDK method').toEqual([]);
  });

  it('sends the right shapes and reads the answers', async () => {
    let seen: { url: string; method: string; body: string | undefined } | undefined;
    const fetchStub: typeof fetch = async (input, init) => {
      seen = { url: String(input), method: init?.method ?? 'GET', body: init?.body as string | undefined };
      return new Response('{"id":"ses_1","status":"created","url":"https://vault.example/b/org_x/enrol#st=tok"}', { status: 201 });
    };
    const c = new Custodian('k', { baseUrl: 'https://api.test/vault/v1', fetch: fetchStub });
    const session = await c.sessions.create({ customer: 'cus_1', purpose: 'entry', return_url: 'https://a.example/x', state: 's', keys: [{ name: 'id_document', type: 'file' }] });
    expect(session.url).toContain('#st=');
    expect(seen?.method).toBe('POST');
    expect(JSON.parse(seen!.body!)).toMatchObject({ return_url: 'https://a.example/x', keys: [{ name: 'id_document', type: 'file' }] });
    await c.customers.list({ limit: 5, external_ref: 'a b' });
    expect(seen?.url).toBe('https://api.test/vault/v1/customers?limit=5&external_ref=a+b');
  });

  it('lists and gets records, and sends the record and the size limit of a key', async () => {
    const seen: { url: string; method: string; body: string | undefined }[] = [];
    const fetchStub: typeof fetch = async (input, init) => {
      seen.push({ url: String(input), method: init?.method ?? 'GET', body: init?.body as string | undefined });
      const url = String(input);
      if (url.includes('/records?')) {
        return new Response('{"data":[{"token":"rec_1","customer":"cus_1","version":2,"keys":[{"name":"income","type":"number","version":2,"updated_at":"2026-10-27T10:00:00Z"}],"created_at":"2026-10-27T09:00:00Z","updated_at":"2026-10-27T10:00:00Z"}],"has_more":true}', { status: 200 });
      }
      if (url.endsWith('/sessions')) return new Response('{"id":"ses_1","record":"rec_1","status":"created"}', { status: 201 });
      return new Response('{"token":"rec_1","customer":"cus_1","version":2,"keys":[],"created_at":"x","updated_at":"x"}', { status: 200 });
    };
    const c = new Custodian('k', { baseUrl: 'https://api.test/vault/v1', fetch: fetchStub });
    const page = await c.records.list({ customer: 'cus_1', limit: 5, starting_after: 'rec_0' });
    expect(page.has_more).toBe(true);
    expect(page.data[0]?.keys[0]?.name).toBe('income');
    expect(seen[0]?.url).toBe('https://api.test/vault/v1/records?customer=cus_1&limit=5&starting_after=rec_0');
    expect((await c.records.get('rec_1')).token).toBe('rec_1');
    expect(seen[1]?.url).toBe('https://api.test/vault/v1/records/rec_1');
    const session = await c.sessions.create({ customer: 'cus_1', purpose: 'view', return_url: 'https://a.example/x', state: 's', record: 'rec_1', keys: [{ name: 'note', max_size: 2048 }] });
    expect(session.record).toBe('rec_1');
    expect(JSON.parse(seen[2]!.body!)).toMatchObject({ record: 'rec_1', keys: [{ name: 'note', max_size: 2048 }] });
  });
});

describe('customers.createNamed', () => {
  it('sends the name that is offered', async () => {
    let sent: unknown;
    const fetchStub: typeof fetch = async (_input, init) => {
      sent = JSON.parse(String(init?.body));
      return new Response('{"id":"cus_1","external_ref":"ref","first_name":"Amina","last_name":"Okafor","name_confirmed":false}', { status: 201 });
    };
    const c = new Custodian('k', { baseUrl: 'https://api.test/vault/v1', fetch: fetchStub });
    const made = await c.customers.createNamed('ref', { first_name: 'Amina', last_name: 'Okafor' });
    expect(made).toMatchObject({ first_name: 'Amina', last_name: 'Okafor', name_confirmed: false });
    expect(sent).toEqual({ external_ref: 'ref', first_name: 'Amina', last_name: 'Okafor' });
  });
});

describe('audit events', () => {
  it('carry every field of the spec', async () => {
    const body = { data: [{ id: 7, type: 'business.suspended', occurred_at: '2026-10-29T10:00:00Z', staff: true }, { id: 8, type: 'api_key.created', occurred_at: '2026-10-29T11:00:00Z', user: 'usr_1', user_email: 'a@example.com', api_key_label: 'cdv_test_Qa7x…m2Lp', livemode: false, api_key: 'key_1' }], total: 2 };
    const fetchStub: typeof fetch = async () => new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
    const c = new Custodian('k', { baseUrl: 'https://api.test/vault/v1', fetch: fetchStub });
    const [staff, api] = await c.auditEvents();
    expect(staff?.staff).toBe(true);
    expect(staff?.user_email).toBeUndefined();
    expect(api?.user_email).toBe('a@example.com');
    expect(api?.api_key_label).toBe('cdv_test_Qa7x…m2Lp');
    expect(api?.livemode).toBe(false);
  });
});
