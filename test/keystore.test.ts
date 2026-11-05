import fs from 'node:fs';
import { describe, expect, it } from 'vitest';
import { EnvelopeError, hybridSupported, KeyStoreError, MemoryKeyStore, observe, openEnvelopeFor, SUITE_HYBRID, type Expected } from '../src/index.js';

interface Case {
  suite: string;
  business_private_key_hex: string;
  kid: string;
  business_id: string;
  customer_id: string;
  request_id: string;
  vault_sign_public_key_hex: string;
  keys: string[] | null;
  files?: string[];
  envelope: Record<string, unknown>;
}
const cases = (JSON.parse(fs.readFileSync('test/fixtures/v1/disclosure-envelope.json', 'utf8')) as { cases: Case[] }).cases;
const want = (c: Case): Omit<Expected, 'signKey'> => ({
  requestId: c.request_id, businessId: c.business_id, customerId: c.customer_id, kid: c.kid, keys: c.keys ?? [], files: c.files ?? [], suite: c.suite as Expected['suite'], privateKey: Buffer.from(c.business_private_key_hex, 'hex'),
});
const enrolled = (id: string, key: Buffer) => ({ type: 'customer.enrolled', data: { object: { id, livemode: true, vault_sign_key: key.toString('base64url'), mk_epoch: 1 } } });
const codeOf = async (run: () => Promise<unknown>): Promise<string> => {
  try {
    await run();
  } catch (error) {
    return error instanceof KeyStoreError || error instanceof EnvelopeError ? error.code : `other: ${String(error)}`;
  }
  return 'ok';
};

describe('the key store', () => {
  it.each(cases)('opens the envelope for $suite with the key the webhook gave, and refuses without it', async (c) => {
    if (c.suite === SUITE_HYBRID && !hybridSupported) return;
    const store = new MemoryKeyStore();
    expect(await codeOf(() => openEnvelopeFor(store, c.envelope, want(c)))).toBe('no_key');
    await observe(store, enrolled(c.customer_id, Buffer.from(c.vault_sign_public_key_hex, 'hex')));
    const opened = await openEnvelopeFor(store, c.envelope, want(c));
    expect(Object.keys(opened.fields).sort()).toEqual([...(c.keys ?? [])].sort());
    expect(Object.keys(opened.files).sort()).toEqual([...(c.files ?? [])].sort());
  });

  it('refuses another key for a known customer until a reset or a deletion', async () => {
    const a = Buffer.alloc(32);
    const b = Buffer.alloc(32, 1);
    for (const kind of ['customer.reset', 'customer.deleted']) {
      const store = new MemoryKeyStore();
      await observe(store, enrolled('cus_1', a));
      await observe(store, enrolled('cus_1', a));
      expect(await codeOf(() => observe(store, enrolled('cus_1', b)))).toBe('key_changed');
      expect(store.get('cus_1')?.equals(a)).toBe(true);
      await observe(store, { type: kind, data: { object: { id: 'cus_1' } } });
      await observe(store, enrolled('cus_1', b));
      expect(store.get('cus_1')?.equals(b)).toBe(true);
    }
  });

  it('keeps the pinned key after a request for a reset', async () => {
    const a = Buffer.alloc(32);
    const b = Buffer.alloc(32, 1);
    const store = new MemoryKeyStore();
    await observe(store, enrolled('cus_1', a));
    await observe(store, { type: 'customer.reset_requested', data: { object: { id: 'cus_1' } } });
    expect(await codeOf(() => observe(store, enrolled('cus_1', b)))).toBe('key_changed');
    expect(store.get('cus_1')?.equals(a)).toBe(true);
  });

  it('refuses a bad event and ignores other types', async () => {
    const store = new MemoryKeyStore();
    for (const object of [{ vault_sign_key: 'AAAA' }, { id: 'cus_1', vault_sign_key: Buffer.alloc(31).toString('base64url') }, { id: 'cus_1', vault_sign_key: '!!' }, null]) {
      expect(await codeOf(() => observe(store, { type: 'customer.enrolled', data: { object } }))).toBe('format');
    }
    await observe(store, { type: 'record.created', data: { object: {} } });
    expect(store.get('cus_1')).toBeUndefined();
  });

  it('refuses an envelope signed by another key', async () => {
    const c = cases[0]!;
    const store = new MemoryKeyStore();
    await observe(store, enrolled(c.customer_id, Buffer.alloc(32)));
    expect(await codeOf(() => openEnvelopeFor(store, c.envelope, want(c)))).toBe('signature');
  });
});
