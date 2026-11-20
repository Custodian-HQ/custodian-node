import { describe, expect, it } from 'vitest';
import { fixture } from './fixture.js';
import { EnvelopeError, fingerprint, generateKey, hybridSupported, openEnvelope, SUITE_CLASSIC, SUITE_HYBRID, type Expected } from '../src/index.js';

interface Case {
  name: string;
  suite: typeof SUITE_CLASSIC | typeof SUITE_HYBRID;
  business_private_key_hex: string;
  business_public_key_hex: string;
  rk: string;
  kid: string;
  business_id: string;
  customer_id: string;
  request_id: string;
  record: string;
  approved_at: number;
  vault_sign_public_key_hex: string;
  keys: string[] | null;
  files?: string[];
  fields: Record<string, string>;
  file_grants?: Record<string, { file_id: string; key_hex: string }>;
  envelope: Record<string, unknown>;
  refuse: { name: string; envelope: Record<string, unknown>; expected_override?: Record<string, unknown>; error: string }[];
}
const cases = fixture<{ cases: Case[] }>('disclosure-envelope.json').cases;

const expected = (c: Case): Expected => ({
  requestId: c.request_id, businessId: c.business_id, customerId: c.customer_id, kid: c.kid, keys: c.keys ?? [], files: c.files ?? [],
  signKey: Buffer.from(c.vault_sign_public_key_hex, 'hex'), suite: c.suite, privateKey: Buffer.from(c.business_private_key_hex, 'hex'),
});

function codeOf(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    return error instanceof EnvelopeError ? error.code : `other: ${String(error)}`;
  }
  return 'opened';
}

// The fixture comes from custodian-device-crypto, where the browser code made it. This reader was written separately.
describe.each(cases)('the envelope the browser sealed for $suite', (c) => {
  const supported = c.suite !== SUITE_HYBRID || hybridSupported;
  const it_ = supported ? it : it.skip;

  it_('opens, and gives back exactly the approved values', () => {
    const got = openEnvelope(c.envelope, expected(c));
    const files = Object.fromEntries(Object.entries(c.file_grants ?? {}).map(([name, g]) => [name, { fileId: g.file_id, key: Buffer.from(g.key_hex, 'hex') }]));
    expect(got).toEqual({ requestId: c.request_id, businessId: c.business_id, customerId: c.customer_id, record: c.record, approvedAt: c.approved_at, fields: c.fields, files });
  });

  it_('refuses every change in the fixture for the right reason', () => {
    expect(c.refuse.length).toBeGreaterThanOrEqual(10);
    for (const r of c.refuse) {
      const want = expected(c);
      const o = r.expected_override ?? {};
      if (typeof o['business_id'] === 'string') want.businessId = o['business_id'];
      if (typeof o['customer_id'] === 'string') want.customerId = o['customer_id'];
      if (typeof o['kid'] === 'string') want.kid = o['kid'];
      if (typeof o['vault_sign_public_key_hex'] === 'string') want.signKey = Buffer.from(o['vault_sign_public_key_hex'], 'hex');
      if (Array.isArray(o['keys'])) want.keys = o['keys'] as string[];
      if (Array.isArray(o['files'])) want.files = o['files'] as string[];
      expect(codeOf(() => openEnvelope(r.envelope, want)), `${c.name} / ${r.name}`).toBe(r.error);
    }
  });

  it_('names the business key and refuses a seal to a substituted key or an old version', () => {
    const own = generateKey(c.suite);
    expect(fingerprint(c.suite, Buffer.from(c.business_public_key_hex, 'hex'))).toBe(c.rk);
    const swapped = c.refuse.find((r) => r.name === 'sealed to a key that is not the business key');
    const old = c.refuse.find((r) => r.name === 'a version that is not 2');
    expect(codeOf(() => openEnvelope(swapped!.envelope, expected(c)))).toBe('signature');
    expect(codeOf(() => openEnvelope(old!.envelope, expected(c)))).toBe('format');
    expect(codeOf(() => openEnvelope(c.envelope, { ...expected(c), privateKey: own.privateKey }))).toBe('signature');
  });

  it_('refuses another private key and text that is not an envelope', () => {
    const other = generateKey(c.suite);
    expect(codeOf(() => openEnvelope(c.envelope, { ...expected(c), privateKey: other.privateKey }))).toBe('signature');
    expect(codeOf(() => openEnvelope('{', expected(c)))).toBe('format');
    expect(codeOf(() => openEnvelope('[]', expected(c)))).toBe('format');
    expect(codeOf(() => openEnvelope(JSON.stringify(c.envelope), expected(c)))).toBe('opened');
  });
});

describe('the fixture', () => {
  it('has a mixed case and a file-only case', () => {
    expect(cases.map((c) => c.name)).toEqual(expect.arrayContaining(['xwing-mixed', 'x25519-files-only']));
  });

  it('refuses files when none were asked for', () => {
    const c = cases.find((x) => x.name === 'x25519-files-only')!;
    // With no file names the AAD changes, so the seal itself refuses: still a payload error.
    expect(codeOf(() => openEnvelope(c.envelope, { ...expected(c), files: [] }))).toBe('payload');
  });
});
