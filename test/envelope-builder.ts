// Builds a signed envelope in test code (classic suite), so a test can change one part and keep the signature good.
import crypto from 'node:crypto';
import { fingerprint, SUITE_CLASSIC, type Sealed } from '../src/disclosure.js';
import type { Expected } from '../src/envelope.js';
import { dhkemX25519, setupReceiver, x25519PublicKey } from '../src/hpke.js';

export const head = (major: number, n: number): Buffer => {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n <= 0xff) return Buffer.from([(major << 5) | 24, n]);
  if (n <= 0xffff) return Buffer.from([(major << 5) | 25, n >> 8, n & 0xff]);
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(n, 1);
  return b;
};
export const text = (s: string): Buffer => {
  const raw = Buffer.from(s, 'utf8');
  return Buffer.concat([head(3, raw.length), raw]);
};
export const bytes = (b: Buffer): Buffer => Buffer.concat([head(2, b.length), b]);
export const uint = (n: number): Buffer => head(0, n);
/** A deterministic map: the pairs are sorted by the encoded key. */
export const map = (pairs: [string, Buffer][]): Buffer => {
  const sorted = pairs.map(([k, v]) => [text(k), v] as const).sort((a, b) => Buffer.compare(a[0], b[0]));
  return Buffer.concat([head(5, sorted.length), ...sorted.flatMap(([k, v]) => [k, v])]);
};

const FILE_KEY_ID = crypto.createHash('sha256').update('cdv/v1/file-key').digest().subarray(0, 8);
export const grant = (fileId: string, key: Buffer): Buffer => map([['file_id', text(fileId)], ['key', bytes(key)], ['key_id', bytes(FILE_KEY_ID)]]);

export interface Built {
  /** The envelope as the vault sends it. */
  envelope: Record<string, string | number>;
  want: Expected;
  /** The sealed message alone, for tests of `open`. */
  sealed: Sealed;
}

export interface BuildOptions {
  keys?: Record<string, string>;
  /** The files asked for, and the key of each. */
  files?: Record<string, Buffer>;
  /** Replaces the sealed content. Build it with `map`, `text`, `bytes` and `grant`. */
  payload?: Buffer;
  /** Changes a part after the seal and before the signature, so the signature stays good. */
  tamper?: { enc?: (b: Buffer) => Buffer; commit?: (b: Buffer) => Buffer; ct?: (b: Buffer) => Buffer };
}

const ids = { requestId: 'dsc_1', businessId: 'org_1', customerId: 'cus_1', kid: 'dk_1', record: 'rec_1' };

export function build(options: BuildOptions = {}): Built {
  const keys = options.keys ?? { name: 'Amina' };
  const files = options.files ?? {};
  const receiver = crypto.randomBytes(32);
  const sender = crypto.randomBytes(32);
  const signing = crypto.generateKeyPairSync('ed25519');
  const signKey = signing.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);

  const names = [...Object.keys(keys), ...Object.keys(files)].sort();
  const aad = Buffer.concat([head(4, names.length), ...names.map(text)]);
  const rk = fingerprint(SUITE_CLASSIC, x25519PublicKey(receiver));
  const info = Buffer.concat([Buffer.from('cdv/v1/disclosure'), Buffer.from([0]), Buffer.from(ids.businessId), Buffer.from([0]), Buffer.from(ids.requestId), Buffer.from([0]), Buffer.from(rk)]);
  const enc = x25519PublicKey(sender);
  // The receiver's shared secret is the sender's: the DH is symmetric. So the receiver code gives the key schedule for the seal.
  const hpke = setupReceiver(dhkemX25519, 2, receiver, enc, info);

  const fileMap: [string, Buffer][] = Object.entries(files).map(([name, key]) => [name, grant(`fil_${name}`, key)]);
  const pairs: [string, Buffer][] = [
    ['request_id', text(ids.requestId)],
    ['record', text(ids.record)],
    ['approved_at', uint(1700000000)],
    ['fields', map(Object.entries(keys).map(([k, v]) => [k, text(v)] as [string, Buffer]))],
  ];
  if (fileMap.length > 0) pairs.push(['files', map(fileMap)]);
  const plain = options.payload ?? map(pairs);
  const cipher = crypto.createCipheriv('aes-256-gcm', hpke.key, hpke.baseNonce);
  cipher.setAAD(aad);
  let ct: Buffer = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
  let commit: Buffer = hpke.export(Buffer.from('cdv/v1/commit'), 32);
  let encOut: Buffer = enc;
  if (options.tamper?.enc) encOut = options.tamper.enc(Buffer.from(encOut));
  if (options.tamper?.commit) commit = options.tamper.commit(Buffer.from(commit));
  if (options.tamper?.ct) ct = options.tamper.ct(Buffer.from(ct));

  const statement = map([
    ['v', uint(2)],
    ['suite', text(SUITE_CLASSIC)],
    ['request_id', text(ids.requestId)],
    ['business_id', text(ids.businessId)],
    ['customer_id', text(ids.customerId)],
    ['kid', text(ids.kid)],
    ['rk', text(rk)],
    ['enc', bytes(encOut)],
    ['commit', bytes(commit)],
    ['ct', bytes(ct)],
  ]);
  const sig = crypto.sign(null, Buffer.concat([Buffer.from('cdv/v1/sig-disclosure'), Buffer.from([0]), statement]), signing.privateKey);
  const envelope = {
    v: 2,
    suite: SUITE_CLASSIC,
    request_id: ids.requestId,
    business_id: ids.businessId,
    customer_id: ids.customerId,
    kid: ids.kid,
    enc: encOut.toString('base64url'),
    commit: commit.toString('base64url'),
    ct: ct.toString('base64url'),
    sig: sig.toString('base64url'),
  };
  const want: Expected = { ...ids, keys: Object.keys(keys), files: Object.keys(files), signKey, suite: SUITE_CLASSIC, privateKey: receiver };
  return { envelope, want, sealed: { enc: encOut, info, aad, ciphertext: ct, commit } };
}

/** Writes the same bytes with other trailing bits in the last character: base64url that is not the one canonical text. */
export function nonCanonical(value: string): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const last = alphabet.indexOf(value.at(-1)!);
  return value.slice(0, -1) + alphabet[last ^ 1];
}
