// Opens a disclosure envelope, receiver side. Written separately from custodian-device-crypto and checked against the same fixtures.
//
// It checks the shape, the request, the business, the customer, the key and the suite; then the customer's signature over everything; then
// the key commitment; then that the sealed content names the same request and holds exactly the keys that were asked for.
import crypto from 'node:crypto';
import { decodeBase64Url } from './base64url.js';
import { open as openSealed, SUITE_CLASSIC, SUITE_HYBRID, type Suite } from './disclosure.js';

export type EnvelopeErrorCode = 'format' | 'request' | 'business' | 'customer' | 'key' | 'signature' | 'payload';

/** The reason an envelope was refused. Read `code`. */
export class EnvelopeError extends Error {
  constructor(readonly code: EnvelopeErrorCode, message: string) {
    super(message);
    this.name = 'EnvelopeError';
  }
}

/** What you know before you open an envelope. Every field is checked. */
export interface Expected {
  /** The disclosure request (dsc_...). */
  requestId: string;
  /** Your organization's public id (org_...). */
  businessId: string;
  /** The customer (cus_...). */
  customerId: string;
  /** The id of your disclosure key that the request was made with. */
  kid: string;
  /** The value key names you asked for. The envelope must hold exactly these. */
  keys: string[];
  /** The file key names you asked for. The envelope must hold exactly these. Leave it out if you asked for no file. */
  files?: string[];
  /** The customer's public vault-sign key, 32 bytes. Use the one you kept from the customer.enrolled webhook. */
  signKey: Buffer;
  suite: Suite;
  /** Your disclosure private key. */
  privateKey: Buffer;
}

/** The key of one approved file. It opens that file only. Use the file, then discard the key: the customer cannot take it back. */
export interface FileGrant {
  fileId: string;
  key: Buffer;
}

export interface Opened {
  requestId: string;
  businessId: string;
  customerId: string;
  /** The token of the record the values came from. */
  record: string;
  approvedAt: number;
  /** The approved values by key name. The object has no prototype, so a key may have any name. */
  fields: Record<string, string>;
  /** One grant for each file you asked for. Download and open a file with `receiveFile`. The object has no prototype. */
  files: Record<string, FileGrant>;
}

const ENVELOPE_FIELDS = ['v', 'suite', 'request_id', 'business_id', 'customer_id', 'kid', 'enc', 'commit', 'ct', 'sig'];
const SIGNATURE_LABEL = Buffer.from('cdv/v1/sig-disclosure');
const INFO_LABEL = Buffer.from('cdv/v1/disclosure');
const SPKI_ED25519 = Buffer.from('302a300506032b6570032100', 'hex');
/** The key id of every file key: the first 8 bytes of SHA-256("cdv/v1/file-key"). Not exported from the package. */
export const FILE_KEY_ID = crypto.createHash('sha256').update('cdv/v1/file-key').digest().subarray(0, 8);

// ---- A small deterministic CBOR: what an envelope needs, and nothing else. -------------------------------------------------------------

function head(major: number, n: number): Buffer {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n <= 0xff) return Buffer.from([(major << 5) | 24, n]);
  if (n <= 0xffff) return Buffer.from([(major << 5) | 25, n >> 8, n & 0xff]);
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(n, 1);
  return b;
}
const text = (s: string): Buffer => {
  const raw = Buffer.from(s, 'utf8');
  return Buffer.concat([head(3, raw.length), raw]);
};
const bytes = (b: Buffer): Buffer => Buffer.concat([head(2, b.length), b]);

function encodeMap(pairs: [Buffer, Buffer][]): Buffer {
  const sorted = [...pairs].sort((a, b) => Buffer.compare(a[0], b[0]));
  return Buffer.concat([head(5, sorted.length), ...sorted.flatMap(([k, v]) => [k, v])]);
}

type Item = { kind: 'n'; n: number } | { kind: 's'; s: string } | { kind: 'b'; b: Buffer } | { kind: 'm'; m: [string, Item][] };

class Reader {
  #at = 0;
  /** Every byte string the reader copied out, so a failure can wipe them. */
  readonly copies: Buffer[] = [];
  constructor(private readonly b: Buffer) {}
  #fail(): never {
    throw new EnvelopeError('payload', 'the sealed content is not deterministic CBOR');
  }
  #take(n: number): Buffer {
    if (n > this.b.length - this.#at) this.#fail();
    const out = this.b.subarray(this.#at, this.#at + n);
    this.#at += n;
    return out;
  }
  #argument(info: number): number {
    if (info < 24) return info;
    const size = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : 0;
    if (size === 0) this.#fail();
    const raw = this.#take(size);
    const n = size === 1 ? raw[0]! : size === 2 ? raw.readUInt16BE(0) : raw.readUInt32BE(0);
    if ((size === 1 && n < 24) || (size === 2 && n <= 0xff) || (size === 4 && n <= 0xffff)) this.#fail();
    return n;
  }
  item(depth = 0): Item {
    if (depth > 8 || this.#at >= this.b.length) this.#fail();
    const first = this.b[this.#at++]!;
    const major = first >> 5;
    const n = this.#argument(first & 31);
    if (major === 0) return { kind: 'n', n };
    if (major === 2) {
      const copy = Buffer.from(this.#take(n));
      this.copies.push(copy);
      return { kind: 'b', b: copy };
    }
    if (major === 3) {
      const raw = this.#take(n);
      try {
        return { kind: 's', s: new TextDecoder('utf-8', { fatal: true }).decode(raw) };
      } catch {
        return this.#fail();
      }
    }
    if (major === 5) {
      if (n > 1000) this.#fail();
      const out: [string, Item][] = [];
      let last: Buffer | undefined;
      for (let i = 0; i < n; i++) {
        const start = this.#at;
        const key = this.item(depth + 1);
        if (key.kind !== 's') this.#fail();
        const encoded = this.b.subarray(start, this.#at);
        if (last && Buffer.compare(last, encoded) >= 0) this.#fail();
        last = encoded;
        out.push([key.s, this.item(depth + 1)]);
      }
      return { kind: 'm', m: out };
    }
    return this.#fail();
  }
  done(): boolean {
    return this.#at === this.b.length;
  }
}

/** Reads one item of deterministic CBOR from `plain`. Exported for the tests, not from the package. */
export function decodePayload(plain: Buffer, reader = new Reader(plain)): Item {
  const item = reader.item();
  if (!reader.done()) throw new EnvelopeError('payload', 'the sealed content has bytes after the item');
  return item;
}

// ---------------------------------------------------------------------------------------------------------------------------------------

const strictBase64Url = (value: unknown): Buffer => {
  const bytes = typeof value === 'string' ? decodeBase64Url(value) : undefined;
  if (!bytes) throw new EnvelopeError('format', 'a field is not base64url');
  return bytes;
};

/**
 * Checks and opens an envelope from `GET /disclosures/{id}/envelope`. Nothing is opened unless the customer's signature is good. Call
 * `acknowledge` on the request afterwards.
 */
export function openEnvelope(raw: string | Buffer | Record<string, unknown>, want: Expected): Opened {
  let w: Record<string, unknown>;
  try {
    w = typeof raw === 'string' || Buffer.isBuffer(raw) ? (JSON.parse(raw.toString()) as Record<string, unknown>) : raw;
  } catch {
    throw new EnvelopeError('format', 'the envelope is not JSON');
  }
  if (typeof w !== 'object' || w === null || Array.isArray(w)) throw new EnvelopeError('format', 'the envelope is not an object');
  const keys = Object.keys(w);
  if (keys.length !== ENVELOPE_FIELDS.length || !ENVELOPE_FIELDS.every((k) => k in w) || w['v'] !== 1) throw new EnvelopeError('format', 'the envelope has the wrong fields');
  for (const k of ['suite', 'request_id', 'business_id', 'customer_id', 'kid']) {
    if (typeof w[k] !== 'string') throw new EnvelopeError('format', `${k} is not text`);
  }
  const enc = strictBase64Url(w['enc']);
  const commit = strictBase64Url(w['commit']);
  const ct = strictBase64Url(w['ct']);
  const sig = strictBase64Url(w['sig']);

  if (w['request_id'] !== want.requestId) throw new EnvelopeError('request', 'the envelope is for another request');
  if (w['business_id'] !== want.businessId) throw new EnvelopeError('business', 'the envelope is for another business');
  if (w['customer_id'] !== want.customerId) throw new EnvelopeError('customer', 'the envelope is for another customer');
  if (w['kid'] !== want.kid || w['suite'] !== want.suite || (want.suite !== SUITE_HYBRID && want.suite !== SUITE_CLASSIC)) throw new EnvelopeError('key', 'the envelope was sealed to another key');

  const t = (name: string): [Buffer, Buffer] => [text(name), text(w[name] as string)];
  const statement = encodeMap([[text('v'), head(0, 1)], t('suite'), t('request_id'), t('business_id'), t('customer_id'), t('kid'), [text('enc'), bytes(enc)], [text('commit'), bytes(commit)], [text('ct'), bytes(ct)]]);
  let signed = false;
  if (want.signKey.length === 32 && sig.length === 64) {
    const publicKey = crypto.createPublicKey({ key: Buffer.concat([SPKI_ED25519, want.signKey]), format: 'der', type: 'spki' });
    signed = crypto.verify(null, Buffer.concat([SIGNATURE_LABEL, Buffer.from([0]), statement]), publicKey, sig);
  }
  if (!signed) throw new EnvelopeError('signature', 'the signature does not check');

  // Key names are ASCII, so sorting the strings sorts their bytes.
  const names = [...want.keys, ...(want.files ?? [])].sort();
  const aad = Buffer.concat([head(4, names.length), ...names.map(text)]);
  const info = Buffer.concat([INFO_LABEL, Buffer.from([0]), Buffer.from(w['business_id'] as string), Buffer.from([0]), Buffer.from(w['request_id'] as string)]);
  let plain: Buffer;
  try {
    plain = openSealed(want.suite, want.privateKey, { enc, info, aad, ciphertext: ct, commit });
  } catch (error) {
    throw new EnvelopeError('payload', error instanceof Error ? error.message : 'the sealed content cannot be opened');
  }
  try {
    return readPayload(plain, want);
  } finally {
    plain.fill(0);
  }
}

/** Reads the sealed content. If it is refused, every file key it copied is cleared first. */
export function readPayload(plain: Buffer, want: Expected): Opened {
  const reader = new Reader(plain);
  try {
    return parsePayload(plain, want, reader);
  } catch (error) {
    for (const copy of reader.copies) copy.fill(0);
    throw error;
  }
}

function parsePayload(plain: Buffer, want: Expected, reader: Reader): Opened {
  const bad = (m: string): never => {
    throw new EnvelopeError('payload', m);
  };
  const root = decodePayload(plain, reader);
  if (root.kind !== 'm') return bad('the sealed content is not a map');
  // No prototype: a name such as `__proto__` is then an ordinary key that is counted, as in Go.
  const out: Opened = { requestId: want.requestId, businessId: want.businessId, customerId: want.customerId, record: '', approvedAt: -1, fields: Object.create(null) as Record<string, string>, files: Object.create(null) as Record<string, FileGrant> };
  const askedFiles = want.files ?? [];
  const seen = new Set<string>();
  for (const [key, value] of root.m) {
    seen.add(key);
    if (key === 'request_id') {
      if (value.kind !== 's' || value.s !== want.requestId) bad('the sealed content is for another request');
    } else if (key === 'record') {
      if (value.kind !== 's' || value.s === '') bad('no record');
      else out.record = value.s;
    } else if (key === 'approved_at') {
      if (value.kind !== 'n') bad('no approval time');
      else out.approvedAt = value.n;
    } else if (key === 'fields') {
      if (value.kind !== 'm') bad('no fields');
      else
        for (const [name, field] of value.m) {
          if (field.kind !== 's') bad('a value is not text');
          else out.fields[name] = field.s;
        }
    } else if (key === 'files') {
      if (value.kind !== 'm' || askedFiles.length === 0) bad('files that were not asked for');
      else for (const [name, grant] of value.m) out.files[name] = readGrant(grant);
    } else bad('an unknown field in the sealed content');
  }
  if (!['request_id', 'record', 'approved_at', 'fields'].every((k) => seen.has(k))) bad('a field is missing');
  if (!sameNames(Object.keys(out.fields), want.keys) || !sameNames(Object.keys(out.files), askedFiles) || want.keys.some((k) => askedFiles.includes(k))) {
    bad('the sealed content does not hold the keys that were asked for');
  }
  return out;
}

const sameNames = (got: string[], asked: string[]): boolean => got.length === asked.length && [...got].sort().join('\0') === [...asked].sort().join('\0');

function readGrant(item: Item): FileGrant {
  const bad = (): never => {
    throw new EnvelopeError('payload', 'a file grant is not valid');
  };
  if (item.kind !== 'm' || item.m.length !== 3) return bad();
  const got = Object.fromEntries(item.m);
  const [id, key, keyId] = [got['file_id'], got['key'], got['key_id']];
  if (id?.kind !== 's' || id.s === '' || key?.kind !== 'b' || key.b.length !== 32 || keyId?.kind !== 'b' || !keyId.b.equals(FILE_KEY_ID)) return bad();
  return { fileId: id.s, key: key.b };
}
