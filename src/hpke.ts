// HPKE (RFC 9180, base mode), receiver side only, built on node:crypto and nothing else.
// Two KEMs: DHKEM(X25519, HKDF-SHA256), id 0x0020, and X-Wing (ML-KEM-768 with X25519), id 0x647a, from
// draft-ietf-hpke-pq. X-Wing needs Node 24.15 or later, which has ML-KEM and importing a key from its seed.
// The key commitment is checked in disclosure.ts. It is checked against the shared fixtures in test/.
import crypto from 'node:crypto';

const X25519_PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI = Buffer.from('302a300506032b656e032100', 'hex');
const XWING_LABEL = Buffer.from('5c2e2f2f5e5c', 'hex'); // \.//^\
const XWING_CT_ML_KEM = 1088;

const KEM_X25519 = 0x0020;
const KEM_XWING = 0x647a;

/** Whether this Node can do ML-KEM, so the hybrid suite works. */
export const hybridSupported: boolean = typeof crypto.encapsulate === 'function';

export interface Kem {
  readonly id: number;
  /** The shared secret, from the receiver's private key and the sender's `enc`. */
  decapsulate(privateKey: Buffer, enc: Buffer): Buffer;
}

const u16 = (n: number): Buffer => Buffer.from([n >> 8, n & 255]);

function hkdfExtract(salt: Buffer, ikm: Buffer): Buffer {
  return crypto.createHmac('sha256', salt.length ? salt : Buffer.alloc(32)).update(ikm).digest();
}

function hkdfExpand(prk: Buffer, info: Buffer, length: number): Buffer {
  const blocks: Buffer[] = [];
  let previous: Buffer = Buffer.alloc(0);
  for (let i = 1; Buffer.concat(blocks).length < length; i++) {
    previous = crypto.createHmac('sha256', prk).update(Buffer.concat([previous, info, Buffer.from([i])])).digest();
    blocks.push(previous);
  }
  return Buffer.concat(blocks).subarray(0, length);
}

const labeledExtract = (suite: Buffer, salt: Buffer, label: string, ikm: Buffer): Buffer =>
  hkdfExtract(salt, Buffer.concat([Buffer.from('HPKE-v1'), suite, Buffer.from(label), ikm]));

const labeledExpand = (suite: Buffer, prk: Buffer, label: string, info: Buffer, length: number): Buffer =>
  hkdfExpand(prk, Buffer.concat([u16(length), Buffer.from('HPKE-v1'), suite, Buffer.from(label), info]), length);

function x25519PrivateKey(secret: Buffer): crypto.KeyObject {
  return crypto.createPrivateKey({ key: Buffer.concat([X25519_PKCS8, secret]), format: 'der', type: 'pkcs8' });
}

function x25519(secret: Buffer, peerPublic: Buffer): Buffer {
  const privateKey = x25519PrivateKey(secret);
  const publicKey = crypto.createPublicKey({ key: Buffer.concat([X25519_SPKI, peerPublic]), format: 'der', type: 'spki' });
  return crypto.diffieHellman({ privateKey, publicKey });
}

export function x25519PublicKey(secret: Buffer): Buffer {
  return crypto.createPublicKey(x25519PrivateKey(secret)).export({ format: 'der', type: 'spki' }).subarray(-32);
}

export const dhkemX25519: Kem = {
  id: KEM_X25519,
  decapsulate(privateKey, enc) {
    const suite = Buffer.concat([Buffer.from('KEM'), u16(KEM_X25519)]);
    const dh = x25519(privateKey, enc);
    const context = Buffer.concat([enc, x25519PublicKey(privateKey)]);
    return labeledExpand(suite, labeledExtract(suite, Buffer.alloc(0), 'eae_prk', dh), 'shared_secret', context, 32);
  },
};

/** The X-Wing private key is a 32-byte seed. SHAKE256 expands it to the ML-KEM seed and the X25519 key. */
function expandXWingSeed(seed: Buffer): { mlkemSeed: Buffer; x25519Secret: Buffer } {
  const expanded = crypto.createHash('shake256', { outputLength: 96 }).update(seed).digest();
  return { mlkemSeed: expanded.subarray(0, 64), x25519Secret: expanded.subarray(64, 96) };
}

function mlkemKey(mlkemSeed: Buffer): crypto.KeyObject {
  return crypto.createPrivateKey({ key: mlkemSeed, format: 'raw-seed', asymmetricKeyType: 'ml-kem-768' });
}

export const xwing: Kem & { publicKey(seed: Buffer): Buffer; generateSeed(): Buffer } = {
  id: KEM_XWING,
  generateSeed: () => crypto.randomBytes(32),
  publicKey(seed) {
    const { mlkemSeed, x25519Secret } = expandXWingSeed(seed);
    const mlkemPublic = crypto.createPublicKey(mlkemKey(mlkemSeed)).export({ format: 'raw-public' });
    return Buffer.concat([mlkemPublic, x25519PublicKey(x25519Secret)]);
  },
  decapsulate(seed, enc) {
    if (enc.length !== XWING_CT_ML_KEM + 32) throw new Error('hpke: the X-Wing encapsulated key has the wrong length');
    const { mlkemSeed, x25519Secret } = expandXWingSeed(seed);
    const ctX25519 = enc.subarray(XWING_CT_ML_KEM, XWING_CT_ML_KEM + 32);
    const ssMlkem = crypto.decapsulate(mlkemKey(mlkemSeed), enc.subarray(0, XWING_CT_ML_KEM));
    const ssX25519 = x25519(x25519Secret, ctX25519);
    return crypto
      .createHash('sha3-256')
      .update(Buffer.concat([ssMlkem, ssX25519, ctX25519, x25519PublicKey(x25519Secret), XWING_LABEL]))
      .digest();
  },
};

export type AeadId = 1 | 2 | 3; // AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
const AEADS: Record<AeadId, { cipher: 'aes-128-gcm' | 'aes-256-gcm' | 'chacha20-poly1305'; keyLength: number }> = {
  1: { cipher: 'aes-128-gcm', keyLength: 16 },
  2: { cipher: 'aes-256-gcm', keyLength: 32 },
  3: { cipher: 'chacha20-poly1305', keyLength: 32 },
};
const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;
const KDF_HKDF_SHA256 = 1;

interface Receiver {
  readonly sharedSecret: Buffer;
  readonly key: Buffer;
  readonly baseNonce: Buffer;
  open(aad: Buffer, ciphertext: Buffer): Buffer;
  export(exporterContext: Buffer, length: number): Buffer;
  /** Zeroes the secrets the receiver holds. Call it when done. */
  wipe(): void;
}

/** Sets up an HPKE receiver (base mode, HKDF-SHA256). */
export function setupReceiver(kem: Kem, aeadId: AeadId, privateKey: Buffer, enc: Buffer, info: Buffer): Receiver {
  const { cipher, keyLength } = AEADS[aeadId];
  const suite = Buffer.concat([Buffer.from('HPKE'), u16(kem.id), u16(KDF_HKDF_SHA256), u16(aeadId)]);
  const sharedSecret = kem.decapsulate(privateKey, enc);

  const none = Buffer.alloc(0);
  const pskIdHash = labeledExtract(suite, none, 'psk_id_hash', none);
  const infoHash = labeledExtract(suite, none, 'info_hash', info);
  const context = Buffer.concat([Buffer.from([0]), pskIdHash, infoHash]);
  const secret = labeledExtract(suite, sharedSecret, 'secret', none);
  const key = labeledExpand(suite, secret, 'key', context, keyLength);
  const baseNonce = labeledExpand(suite, secret, 'base_nonce', context, NONCE_LENGTH);
  const exporterSecret = labeledExpand(suite, secret, 'exp', context, 32);

  let sequence = 0n;
  return {
    sharedSecret,
    key,
    baseNonce,
    open(aad, ciphertext) {
      const nonce = Buffer.from(baseNonce);
      for (let i = 0; i < NONCE_LENGTH; i++) nonce[NONCE_LENGTH - 1 - i]! ^= Number((sequence >> BigInt(8 * i)) & 0xffn);
      // Node types the two cipher families separately, so each branch names its own literal.
      const decipher =
        cipher === 'chacha20-poly1305'
          ? crypto.createDecipheriv(cipher, key, nonce, { authTagLength: TAG_LENGTH })
          : crypto.createDecipheriv(cipher, key, nonce, { authTagLength: TAG_LENGTH });
      decipher.setAAD(aad, { plaintextLength: ciphertext.length - TAG_LENGTH });
      decipher.setAuthTag(ciphertext.subarray(-TAG_LENGTH));
      const plaintext = Buffer.concat([decipher.update(ciphertext.subarray(0, -TAG_LENGTH)), decipher.final()]);
      sequence += 1n;
      return plaintext;
    },
    export: (exporterContext, length) => labeledExpand(suite, exporterSecret, 'sec', exporterContext, length),
    wipe() {
      for (const secret of [sharedSecret, key, baseNonce, exporterSecret]) secret.fill(0);
    },
  };
}
