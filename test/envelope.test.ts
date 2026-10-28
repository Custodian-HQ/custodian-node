import fs from 'node:fs';
import { describe, expect, it } from 'vitest';
import { approveUrl, EnvelopeError, generateKey, hybridSupported, openEnvelope, SUITE_CLASSIC, SUITE_HYBRID, type Expected } from '../src/index.js';

interface Case {
  name: string;
  suite: typeof SUITE_CLASSIC | typeof SUITE_HYBRID;
  business_private_key_hex: string;
  kid: string;
  business_id: string;
  customer_id: string;
  request_id: string;
  record: string;
  approved_at: number;
  vault_sign_public_key_hex: string;
  keys: string[];
  fields: Record<string, string>;
  envelope: Record<string, unknown>;
  refuse: { name: string; envelope: Record<string, unknown>; expected_override?: Record<string, unknown>; error: string }[];
}
const cases = (JSON.parse(fs.readFileSync('test/fixtures/v1/disclosure-envelope.json', 'utf8')) as { cases: Case[] }).cases;

const expected = (c: Case): Expected => ({
  requestId: c.request_id, businessId: c.business_id, customerId: c.customer_id, kid: c.kid, keys: c.keys,
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
    expect(got).toEqual({ record: c.record, approvedAt: c.approved_at, fields: c.fields });
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
      expect(codeOf(() => openEnvelope(r.envelope, want)), `${c.name} / ${r.name}`).toBe(r.error);
    }
  });

  it_('refuses another private key and text that is not an envelope', () => {
    const other = generateKey(c.suite);
    expect(codeOf(() => openEnvelope(c.envelope, { ...expected(c), privateKey: other.privateKey }))).toBe('payload');
    expect(codeOf(() => openEnvelope('{', expected(c)))).toBe('format');
    expect(codeOf(() => openEnvelope('[]', expected(c)))).toBe('format');
    expect(codeOf(() => openEnvelope(JSON.stringify(c.envelope), expected(c)))).toBe('opened');
  });
});

describe('the link of an approve session', () => {
  it('gets the fingerprint in the fragment only', () => {
    const fp = 'AB'.repeat(32);
    expect(approveUrl('https://vault.thecustodian.io/b/org_x/approve#st=cdvs_live_org_x_tok', fp)).toBe(`https://vault.thecustodian.io/b/org_x/approve#st=cdvs_live_org_x_tok&fp=${fp.toLowerCase()}`);
  });

  it('refuses a bad fingerprint or a link that cannot carry it', () => {
    const ok = 'https://vault.example/b/o/approve#st=t';
    expect(() => approveUrl(ok, 'abcd')).toThrow(/64 hexadecimal/);
    expect(() => approveUrl(ok, 'g'.repeat(64))).toThrow(/64 hexadecimal/);
    expect(() => approveUrl('https://vault.example/b/o/approve', 'a'.repeat(64))).toThrow(/not valid/);
    expect(() => approveUrl('http://vault.example/b/o/approve#st=t', 'a'.repeat(64))).toThrow(/not valid/);
    expect(() => approveUrl('not a url', 'a'.repeat(64))).toThrow(/not valid/);
  });
});
