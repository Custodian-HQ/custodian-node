import { describe, expect, it } from 'vitest';
import { SUITE_CLASSIC, SUITE_HYBRID, defaultSuite, fingerprint, generateKey, open, type Sealed, type Suite } from '../src/disclosure.js';
import { hybridSupported, setupReceiver, xwing, type AeadId } from '../src/hpke.js';
import { build } from './envelope-builder.js';
import { fixture } from './fixture.js';

const hex = (s: string): Buffer => Buffer.from(s, 'hex');
const hybrid = hybridSupported ? it : it.skip;
const AUTHENTICATION = /authenticate/;

describe('X-Wing against the published vector', () => {
  interface Vector {
    skRm: string; pkRm: string; enc: string; info: string; aead_id: number; shared_secret: string; key: string;
    encryptions: { aad: string; ct: string; pt: string }[];
    exports: { exporter_context: string; L: number; exported_value: string }[];
  }
  hybrid('derives the public key, the secret, the key, every message and every export', () => {
    const v = fixture<Vector>('hpke-xwing-vector.json');
    expect(xwing.publicKey(hex(v.skRm)).equals(hex(v.pkRm))).toBe(true);
    const receiver = setupReceiver(xwing, v.aead_id as AeadId, hex(v.skRm), hex(v.enc), hex(v.info));
    expect(receiver.sharedSecret.equals(hex(v.shared_secret))).toBe(true);
    expect(receiver.key.equals(hex(v.key))).toBe(true);
    for (const e of v.encryptions) expect(receiver.open(hex(e.aad), hex(e.ct)).equals(hex(e.pt))).toBe(true);
    for (const e of v.exports) expect(receiver.export(hex(e.exporter_context), e.L).equals(hex(e.exported_value))).toBe(true);
  });
});

describe('disclosures sealed by custodian-device-crypto', () => {
  interface Sample { suite: typeof SUITE_HYBRID; SkR: string; Info: string; Aad: string; Enc: string; Ct: string; Commit: string; Pt: string }
  const sample = fixture<Sample>('hpke-xwing-aes256gcm-sample.json');
  const sealed = (): Sealed => ({ enc: hex(sample.Enc), info: hex(sample.Info), aad: hex(sample.Aad), ciphertext: hex(sample.Ct), commit: hex(sample.Commit) });

  hybrid('opens', () => {
    expect(open(sample.suite, hex(sample.SkR), sealed()).equals(hex(sample.Pt))).toBe(true);
  });

  hybrid('refuses a wrong commitment, a changed ciphertext and a wrong aad', () => {
    const wrongCommit = sealed();
    wrongCommit.commit = Buffer.from(wrongCommit.commit);
    wrongCommit.commit[0]! ^= 1;
    expect(() => open(sample.suite, hex(sample.SkR), wrongCommit)).toThrow('commitment');

    const changed = sealed();
    changed.ciphertext = Buffer.from(changed.ciphertext);
    changed.ciphertext[0]! ^= 1;
    expect(() => open(sample.suite, hex(sample.SkR), changed)).toThrow(AUTHENTICATION);

    expect(() => open(sample.suite, hex(sample.SkR), { ...sealed(), aad: Buffer.from('other') })).toThrow(AUTHENTICATION);

    expect(() => open(sample.suite, xwing.generateSeed(), sealed())).toThrow('key commitment does not match');
    const changedEnc = sealed();
    changedEnc.enc = Buffer.from(changedEnc.enc);
    changedEnc.enc[0]! ^= 1;
    expect(() => open(sample.suite, hex(sample.SkR), changedEnc)).toThrow('key commitment does not match');
  });
});

// The classic suite works on every supported Node, so these always run.
describe('opening with the classic suite', () => {
  const { sealed, want } = build();
  const copy = (): Sealed => ({ enc: Buffer.from(sealed.enc), info: Buffer.from(sealed.info), aad: Buffer.from(sealed.aad), ciphertext: Buffer.from(sealed.ciphertext), commit: Buffer.from(sealed.commit) });

  it('opens a message that is not changed', () => {
    expect(open(SUITE_CLASSIC, want.privateKey, copy()).length).toBeGreaterThan(0);
  });

  it('refuses a changed ciphertext, a cut ciphertext and another aad, with an authentication error', () => {
    const changed = copy();
    changed.ciphertext[0]! ^= 1;
    expect(() => open(SUITE_CLASSIC, want.privateKey, changed)).toThrow(AUTHENTICATION);
    const cut = copy();
    cut.ciphertext = cut.ciphertext.subarray(0, -1);
    expect(() => open(SUITE_CLASSIC, want.privateKey, cut)).toThrow(AUTHENTICATION);
    expect(() => open(SUITE_CLASSIC, want.privateKey, { ...copy(), aad: Buffer.from('other') })).toThrow(AUTHENTICATION);
  });

  it('refuses a changed enc, another private key and a changed commitment, with a commitment error', () => {
    const enc = copy();
    enc.enc[0]! ^= 1;
    expect(() => open(SUITE_CLASSIC, want.privateKey, enc)).toThrow('key commitment does not match');
    expect(() => open(SUITE_CLASSIC, generateKey(SUITE_CLASSIC).privateKey, copy())).toThrow('key commitment does not match');
    const commit = copy();
    commit.commit[0]! ^= 1;
    expect(() => open(SUITE_CLASSIC, want.privateKey, commit)).toThrow('key commitment does not match');
    expect(() => open(SUITE_CLASSIC, want.privateKey, { ...copy(), commit: Buffer.alloc(31) })).toThrow('key commitment does not match');
  });
});

describe('keys', () => {
  it('picks the suite this Node can do', () => {
    expect(defaultSuite()).toBe(hybridSupported ? SUITE_HYBRID : SUITE_CLASSIC);
  });

  it('makes classic keys with a 32-byte public key', () => {
    const key = generateKey(SUITE_CLASSIC);
    expect(key.publicKey).toHaveLength(32);
  });

  hybrid('makes hybrid keys with a 1,216-byte public key', () => {
    const key = generateKey(SUITE_HYBRID);
    expect(key.privateKey).toHaveLength(32);
    expect(key.publicKey).toHaveLength(1216);
  });
});

describe('fingerprint', () => {
  interface FingerprintFixture {
    label: string;
    cases: { name: string; suite: Suite; public_key_hex: string; fingerprint: string }[];
  }
  const shared = fixture<FingerprintFixture>('disclosure-key-fingerprint.json');

  it('gives the answers of the shared fixture', () => {
    expect(shared.label).toBe('cdv/v1/dkfp');
    expect(shared.cases.length).toBeGreaterThanOrEqual(4);
    for (const c of shared.cases) expect(fingerprint(c.suite, hex(c.public_key_hex)), c.name).toBe(c.fingerprint);
  });
});
