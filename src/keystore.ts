// Keeps each customer's vault-sign public key from the customer.enrolled webhook, and opens envelopes against it.
import { decodeBase64Url } from './base64url.js';
import { openEnvelope, type Expected, type Opened } from './envelope.js';
import { EVENT_CUSTOMER_DELETED, EVENT_CUSTOMER_ENROLLED, EVENT_CUSTOMER_RESET } from './webhook.js';

export type KeyStoreErrorCode = 'no_key' | 'key_changed' | 'format' | 'reset_not_approved' | 'stale_event';

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
  /** The `created` time of the last event handled for the customer, or 0 if none. Give both clock methods to turn on the order check of `observeEvent`. */
  lastEvent?(customerId: string): number | Promise<number>;
  setLastEvent?(customerId: string, created: number): void | Promise<void>;
}

/** A KeyStore in memory, for tests and for programs that do not restart. */
export class MemoryKeyStore implements KeyStore {
  readonly #keys = new Map<string, Buffer>();
  readonly #clock = new Map<string, number>();
  lastEvent(customerId: string): number {
    return this.#clock.get(customerId) ?? 0;
  }
  setLastEvent(customerId: string, created: number): void {
    this.#clock.set(customerId, created);
  }
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

function customerIdOf(event: { type: string; data: { object: unknown } }): string {
  const id = (event.data.object as { id?: unknown } | null)?.id;
  if (typeof id !== 'string' || id === '') throw new KeyStoreError('format', `the ${event.type} event does not hold an id`);
  return id;
}

/** How `observeEvent` treats an event that erases a key. */
export interface ObserveOptions {
  /**
   * Called before a customer.reset or customer.deleted event erases the kept key. Return true only if you started the reset or confirmed it with your
   * own customer. The webhook is signed with a secret Custodian also holds, so the signature alone does not show that a reset is real. If it is
   * missing, resets are refused. If it throws, the error goes to the caller and the key stays.
   */
  approveReset?: (customerId: string, eventType: string) => boolean | Promise<boolean>;
}

/**
 * `observe` with two more checks. Use it for every verified event.
 * - customer.reset and customer.deleted erase the kept key only if `approveReset` says yes. Without it they throw reset_not_approved and the key stays.
 * - If the store has `lastEvent` and `setLastEvent`, an event older than the last one handled for the customer throws stale_event and changes
 *   nothing: a retried old event cannot pin an old key or erase a new one. Treat stale_event as handled and acknowledge the webhook. Events with the
 *   same `created` second cannot be put in order, so all are handled. A store without the clock methods skips this check.
 */
export async function observeEvent(store: KeyStore, event: { type: string; created: number; data: { object: unknown } }, options: ObserveOptions = {}): Promise<void> {
  if (event.type !== EVENT_CUSTOMER_ENROLLED && event.type !== EVENT_CUSTOMER_RESET && event.type !== EVENT_CUSTOMER_DELETED) return;
  const id = customerIdOf(event);
  const clock = store.lastEvent && store.setLastEvent ? { last: store.lastEvent.bind(store), set: store.setLastEvent.bind(store) } : undefined;
  if (clock && !Number.isFinite(event.created)) throw new KeyStoreError('format', `the ${event.type} event does not hold a time`);
  const last = clock ? await clock.last(id) : 0;
  if (clock && event.created < last) throw new KeyStoreError('stale_event', 'the event is older than one already handled for this customer');
  if (event.type !== EVENT_CUSTOMER_ENROLLED && !(options.approveReset && (await options.approveReset(id, event.type)))) {
    throw new KeyStoreError('reset_not_approved', 'the reset was not approved, so the signing key stays. Set approveReset to approve a reset');
  }
  await observe(store, event);
  if (clock && event.created > last) await clock.set(id, event.created);
}

/**
 * Keeps the signing key that a verified webhook event names. It trusts the vault: it asks no approval before a reset erases a key and does not
 * check the order of events. Use `observeEvent` instead. Call it for every event, after constructEvent. It acts on:
 * - customer.enrolled: keeps the key. If you already hold another key for the customer it throws key_changed and keeps the old one.
 * - customer.reset and customer.deleted: forgets the key, so the next enrolment can set a new one.
 * Other types are ignored. The same event may arrive twice; that is harmless.
 */
export async function observe(store: KeyStore, event: { type: string; data: { object: unknown } }): Promise<void> {
  const object = event.data.object as { id?: unknown; vault_sign_key?: unknown } | null;
  if (event.type === EVENT_CUSTOMER_ENROLLED) {
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
  } else if (event.type === EVENT_CUSTOMER_RESET || event.type === EVENT_CUSTOMER_DELETED) {
    await store.delete(customerIdOf(event));
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
