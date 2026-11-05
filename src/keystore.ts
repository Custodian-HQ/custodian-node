// Keeps each customer's vault-sign public key from the customer.enrolled webhook, and opens envelopes against it.
import { decodeBase64Url } from './base64url.js';
import { openEnvelope, type Expected, type Opened } from './envelope.js';

export type KeyStoreErrorCode = 'no_key' | 'key_changed' | 'format';

export class KeyStoreError extends Error {
  constructor(readonly code: KeyStoreErrorCode, message: string) {
    super(message);
    this.name = 'KeyStoreError';
  }
}

/** Keeps each customer's vault-sign public key. Back it with your own database. The methods may be asynchronous. */
export interface KeyStore {
  get(customerId: string): Buffer | undefined | Promise<Buffer | undefined>;
  put(customerId: string, key: Buffer): void | Promise<void>;
  /**
   * Keeps the key only if the customer has none, and says whether it did. It must be atomic, for example `INSERT ... ON CONFLICT DO NOTHING`.
   * `observe` uses it when you provide it, so two events at once cannot replace each other's key.
   */
  putIfAbsent?(customerId: string, key: Buffer): boolean | Promise<boolean>;
  delete(customerId: string): void | Promise<void>;
}

/** A KeyStore in memory, for tests and for programs that do not restart. */
export class MemoryKeyStore implements KeyStore {
  readonly #keys = new Map<string, Buffer>();
  get(customerId: string): Buffer | undefined {
    return this.#keys.get(customerId);
  }
  put(customerId: string, key: Buffer): void {
    this.#keys.set(customerId, Buffer.from(key));
  }
  putIfAbsent(customerId: string, key: Buffer): boolean {
    if (this.#keys.has(customerId)) return false;
    this.#keys.set(customerId, Buffer.from(key));
    return true;
  }
  delete(customerId: string): void {
    this.#keys.delete(customerId);
  }
}

/**
 * Keeps the signing key that a verified webhook event names. Call it for every event, after constructEvent. It acts on:
 * - customer.enrolled: keeps the key. If you already hold another key for the customer it throws key_changed and keeps the old one.
 * - customer.reset and customer.deleted: forgets the key, so the next enrolment can set a new one.
 * Other types are ignored. The same event may arrive twice; that is harmless.
 */
export async function observe(store: KeyStore, event: { type: string; data: { object: unknown } }): Promise<void> {
  const object = event.data.object as { id?: unknown; vault_sign_key?: unknown } | null;
  if (event.type === 'customer.enrolled') {
    const key = object && typeof object.id === 'string' && object.id !== '' && typeof object.vault_sign_key === 'string' && object.vault_sign_key !== '' ? decodeBase64Url(object.vault_sign_key) : undefined;
    if (!object || typeof object.id !== 'string' || !key) throw new KeyStoreError('format', 'the customer.enrolled event does not hold an id and a key');
    if (key.length !== 32) throw new KeyStoreError('format', 'the signing key is not 32 bytes');
    // A second event can store a key between our read and our write. With `putIfAbsent` we read again and compare.
    for (let attempt = 0; attempt < 3; attempt++) {
      const held = await store.get(object.id);
      if (held !== undefined) {
        if (!held.equals(key)) throw new KeyStoreError('key_changed', 'the customer signing key changed without a reset');
        return;
      }
      if (!store.putIfAbsent) return void (await store.put(object.id, key));
      if (await store.putIfAbsent(object.id, key)) return;
    }
    throw new Error('custodian: the key store did not keep the signing key');
  } else if (event.type === 'customer.reset' || event.type === 'customer.deleted') {
    if (!object || typeof object.id !== 'string' || object.id === '') throw new KeyStoreError('format', `the ${event.type} event does not hold an id`);
    await store.delete(object.id);
  }
}

/**
 * openEnvelope with the customer's signing key taken from your store. It ignores `signKey` in `want`. If the store holds no key for the
 * customer it throws no_key and opens nothing. The key is never fetched from Custodian: the key you check against must not come from the
 * party you are checking.
 */
export async function openEnvelopeFor(store: KeyStore, raw: string | Buffer | Record<string, unknown>, want: Omit<Expected, 'signKey'>): Promise<Opened> {
  const signKey = await store.get(want.customerId);
  if (signKey === undefined) throw new KeyStoreError('no_key', 'no signing key is kept for this customer');
  return openEnvelope(raw, { ...want, signKey });
}
