// Disclosure keys and opening, receiver side. The browser seals; the business opens.
import crypto from 'node:crypto';
import { dhkemX25519, hybridSupported, setupReceiver, x25519PublicKey, xwing, type Kem } from './hpke.js';

export const SUITE_HYBRID = 'cdv1-xwing-hkdf256-aes256gcm';
export const SUITE_CLASSIC = 'cdv1-x25519-hkdf256-aes256gcm';
export type Suite = typeof SUITE_HYBRID | typeof SUITE_CLASSIC;

const AES_256_GCM = 2;
const COMMIT_LABEL = Buffer.from('cdv/v1/commit');
const COMMIT_SIZE = 32;

/** The hybrid suite when this Node can do ML-KEM (24.15 or later), the classic one otherwise. */
export function defaultSuite(): Suite {
  return hybridSupported ? SUITE_HYBRID : SUITE_CLASSIC;
}

function kemFor(suite: Suite): Kem {
  if (suite === SUITE_HYBRID) {
    if (!hybridSupported) throw new Error(`${SUITE_HYBRID} needs Node 24.15 or later`);
    return xwing;
  }
  if (suite === SUITE_CLASSIC) return dhkemX25519;
  throw new Error(`unknown suite ${String(suite)}`);
}

export interface DisclosureKey {
  suite: Suite;
  /** For the hybrid suite this is the 32-byte seed. Keep it secret. */
  privateKey: Buffer;
  publicKey: Buffer;
}

export function generateKey(suite: Suite = defaultSuite()): DisclosureKey {
  kemFor(suite);
  if (suite === SUITE_HYBRID) {
    const privateKey = xwing.generateSeed();
    return { suite, privateKey, publicKey: xwing.publicKey(privateKey) };
  }
  const privateKey = crypto.randomBytes(32);
  return { suite, privateKey, publicKey: x25519PublicKey(privateKey) };
}

export interface Sealed {
  enc: Buffer;
  info: Buffer;
  aad: Buffer;
  ciphertext: Buffer;
  commit: Buffer;
}

/** Opens one sealed message. The key commitment is compared in constant time before anything is decrypted. */
export function open(suite: Suite, privateKey: Buffer, sealed: Sealed): Buffer {
  const receiver = setupReceiver(kemFor(suite), AES_256_GCM, privateKey, sealed.enc, sealed.info);
  const expected = receiver.export(COMMIT_LABEL, COMMIT_SIZE);
  if (sealed.commit.length !== COMMIT_SIZE || !crypto.timingSafeEqual(expected, sealed.commit)) {
    throw new Error('key commitment does not match');
  }
  return receiver.open(sealed.aad, sealed.ciphertext);
}

/**
 * The fingerprint of a disclosure public key: SHA-256 over the label "cdv/v1/dkfp", the suite name and the raw public key, each
 * followed by a zero byte, as 64 lowercase hexadecimal characters. Keep it in your app config and send it as
 * `disclosure_key_fingerprint`. It is not a secret.
 */
export function fingerprint(suite: Suite, publicKey: Buffer): string {
  return crypto
    .createHash('sha256')
    .update(Buffer.concat([Buffer.from('cdv/v1/dkfp'), Buffer.from([0]), Buffer.from(suite), Buffer.from([0]), publicKey]))
    .digest('hex');
}
