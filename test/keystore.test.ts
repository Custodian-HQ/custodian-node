import fs from 'node:fs';
import { describe, expect, it } from 'vitest';
import { EnvelopeError, hybridSupported, KeyStoreError, MemoryKeyStore, observe, observeEvent, openEnvelopeFor, SUITE_HYBRID, type Expected, type KeyStore } from '../src/index.js';
import { nonCanonical } from './envelope-builder.js';

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
  const opensWithTheWebhookKey = async (c: Case): Promise<void> => {
    const store = new MemoryKeyStore();
    expect(await codeOf(() => openEnvelopeFor(store, c.envelope, want(c)))).toBe('no_key');
    await observe(store, enrolled(c.customer_id, Buffer.from(c.vault_sign_public_key_hex, 'hex')));
    const opened = await openEnvelopeFor(store, c.envelope, want(c));
    expect(Object.keys(opened.fields).sort()).toEqual([...(c.keys ?? [])].sort());
    expect(Object.keys(opened.files).sort()).toEqual([...(c.files ?? [])].sort());
  };
  const name = 'opens the envelope for $suite with the key the webhook gave, and refuses without it';
  const supported = cases.filter((c) => c.suite !== SUITE_HYBRID || hybridSupported);
  const unsupported = cases.filter((c) => !supported.includes(c));
  it.each(supported)(name, opensWithTheWebhookKey);
  if (unsupported.length > 0) it.skip.each(unsupported)(name, opensWithTheWebhookKey);

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
    const canonical = Buffer.alloc(32).toString('base64url');
    for (const object of [{ vault_sign_key: 'AAAA' }, { id: 'cus_1', vault_sign_key: Buffer.alloc(31).toString('base64url') }, { id: 'cus_1', vault_sign_key: '!!' }, { id: 'cus_1', vault_sign_key: nonCanonical(canonical) }, { id: 'cus_1', vault_sign_key: '' }, null]) {
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

describe('two events at once for one customer', () => {
  const a = Buffer.alloc(32, 1);
  const b = Buffer.alloc(32, 2);
  const pause = (): Promise<void> => new Promise((done) => setTimeout(done, 5));

  /** A store that waits on every call, as a database does. `putIfAbsent` is atomic, as it must be. */
  class SlowStore implements KeyStore {
    readonly inner = new MemoryKeyStore();
    async get(id: string): Promise<Buffer | undefined> {
      await pause();
      return this.inner.get(id);
    }
    async put(id: string, key: Buffer): Promise<void> {
      await pause();
      this.inner.put(id, key);
    }
    async putIfAbsent(id: string, key: Buffer): Promise<boolean> {
      await pause();
      return this.inner.putIfAbsent(id, key);
    }
    async delete(id: string): Promise<void> {
      await pause();
      this.inner.delete(id);
    }
  }

  const oneWins = (results: PromiseSettledResult<void>[]): void => {
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    const lost = results.find((r) => r.status === 'rejected') as PromiseRejectedResult;
    expect(lost.reason).toBeInstanceOf(KeyStoreError);
    expect((lost.reason as KeyStoreError).code).toBe('key_changed');
  };

  it('lets one key win and refuses the other, in memory', async () => {
    const store = new MemoryKeyStore();
    oneWins(await Promise.allSettled([observe(store, enrolled('cus_1', a)), observe(store, enrolled('cus_1', b))]));
    expect([a, b].filter((k) => store.get('cus_1')?.equals(k))).toHaveLength(1);
  });

  it('lets one key win and refuses the other, with a store that waits', async () => {
    const store = new SlowStore();
    oneWins(await Promise.allSettled([observe(store, enrolled('cus_1', a)), observe(store, enrolled('cus_1', b))]));
    expect([a, b].filter((k) => store.inner.get('cus_1')?.equals(k))).toHaveLength(1);
  });

  it('accepts the same key twice at once', async () => {
    const store = new SlowStore();
    const results = await Promise.allSettled([observe(store, enrolled('cus_1', a)), observe(store, enrolled('cus_1', a))]);
    expect(results.map((r) => r.status)).toEqual(['fulfilled', 'fulfilled']);
  });

  it('stays correct with a store that has no putIfAbsent, when the events come one after the other', async () => {
    const store: KeyStore = { get: (id) => inner.get(id), put: (id, key) => inner.put(id, key), delete: (id) => inner.delete(id) };
    const inner = new MemoryKeyStore();
    await observe(store, enrolled('cus_1', a));
    expect(await codeOf(() => observe(store, enrolled('cus_1', b)))).toBe('key_changed');
  });

  it('gives up with an error when a store keeps saying no and holds nothing', async () => {
    const store: KeyStore = { get: () => undefined, put: () => undefined, putIfAbsent: () => false, delete: () => undefined };
    await expect(observe(store, enrolled('cus_1', a))).rejects.toThrow(/did not keep/);
  });
});

describe('observeEvent', () => {
  const A = Buffer.alloc(32);
  const B = Buffer.alloc(32, 1);
  const enrol = (key: Buffer, created: number) => ({ ...enrolled('cus_1', key), created });
  const gone = (type: string, created: number) => ({ type, created, data: { object: { id: 'cus_1' } } });
  const yes = { approveReset: () => true };

  it('refuses a reset with no callback, with a callback that says no, and with one that throws; the key stays', async () => {
    for (const type of ['customer.reset', 'customer.deleted']) {
      for (const [name, options] of Object.entries({ none: {}, no: { approveReset: () => false }, throws: { approveReset: () => { throw new Error('lookup failed'); } } })) {
        const store = new MemoryKeyStore();
        await observeEvent(store, enrol(A, 1), options);
        const code = await codeOf(() => observeEvent(store, gone(type, 2), options));
        expect(code, `${type} ${name}`).toBe(name === 'throws' ? 'other: Error: lookup failed' : 'reset_not_approved');
        expect(store.get('cus_1')?.equals(A)).toBe(true);
        expect(await codeOf(() => observeEvent(store, enrol(B, 3), options))).toBe('key_changed');
      }
    }
  });

  it('forgets the key after an approved reset and pins the next one', async () => {
    for (const type of ['customer.reset', 'customer.deleted']) {
      const store = new MemoryKeyStore();
      await observeEvent(store, enrol(A, 1), yes);
      await observeEvent(store, gone(type, 2), yes);
      expect(store.get('cus_1')).toBeUndefined();
      await observeEvent(store, enrol(B, 3), yes);
      expect(store.get('cus_1')?.equals(B)).toBe(true);
    }
  });

  it('refuses an event with no time, and keeps the clock', async () => {
    const store = new MemoryKeyStore();
    await observeEvent(store, enrol(A, 10), yes);
    const noTime = { ...enrol(B, 11), created: undefined as unknown as number };
    expect(await codeOf(() => observeEvent(store, noTime, yes))).toBe('format');
    expect(store.lastEvent('cus_1')).toBe(10);
  });

  it('ignores an old enrolled event that arrives after a newer reset', async () => {
    const store = new MemoryKeyStore();
    await observeEvent(store, enrol(A, 10), yes);
    await observeEvent(store, gone('customer.reset', 20), yes);
    expect(await codeOf(() => observeEvent(store, enrol(A, 10), yes))).toBe('stale_event');
    expect(store.get('cus_1')).toBeUndefined();
  });

  it('ignores an old reset that arrives after a newer enrolled event, and handles events of the same second', async () => {
    const store = new MemoryKeyStore();
    await observeEvent(store, enrol(A, 10), yes);
    await observeEvent(store, gone('customer.reset', 20), yes);
    await observeEvent(store, enrol(B, 30), yes);
    expect(await codeOf(() => observeEvent(store, gone('customer.reset', 20), yes))).toBe('stale_event');
    expect(store.get('cus_1')?.equals(B)).toBe(true);
    expect(store.lastEvent('cus_1')).toBe(30);
    await observeEvent(store, gone('customer.reset', 30), yes);
    expect(store.get('cus_1')).toBeUndefined();
  });

  it('skips the order check when the store has no clock', async () => {
    const inner = new MemoryKeyStore();
    const plain: KeyStore = { get: (id) => inner.get(id), put: (id, k) => inner.put(id, k), delete: (id) => inner.delete(id) };
    await observeEvent(plain, enrol(A, 20));
    await observeEvent(plain, enrol(A, 10));
    expect(inner.get('cus_1')?.equals(A)).toBe(true);
  });
});
