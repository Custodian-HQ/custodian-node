import { describe, expect, it } from 'vitest';
import { approveUrl, parseReturn } from '../src/return.js';

describe('parseReturn', () => {
  it('returns the session id for a good return, and ignores a status someone added', () => {
    expect(parseReturn('https://shop.example.com/done?session=ses_1&state=abc', 'abc')).toBe('ses_1');
    expect(parseReturn('https://shop.example.com/done?session=ses_1&state=abc&status=completed', 'abc')).toBe('ses_1');
  });

  it('refuses a status alone, an unknown state, no expected state, a missing session and repeated parameters', () => {
    for (const [url, state] of [
      ['https://shop.example.com/done?status=completed', 'abc'],
      ['https://shop.example.com/done?session=ses_1&state=zzz', 'abc'],
      ['https://shop.example.com/done?session=ses_1&state=', ''],
      ['https://shop.example.com/done?state=abc', 'abc'],
      ['https://shop.example.com/done?session=ses_1&session=ses_2&state=abc', 'abc'],
      ['https://shop.example.com/done?session=ses_1&state=abc&state=abc', 'abc'],
    ] as const) expect(() => parseReturn(url, state), url).toThrow('not valid');
  });
});

describe('approveUrl', () => {
  const fp = 'a'.repeat(64);

  it('takes https, and http for localhost only', () => {
    expect(approveUrl('https://vault.example/b/o/approve#st=t', fp)).toBe(`https://vault.example/b/o/approve#st=t&fp=${fp}`);
    expect(approveUrl('http://localhost:3000/b/o/approve#st=t', fp)).toBe(`http://localhost:3000/b/o/approve#st=t&fp=${fp}`);
    expect(approveUrl('https://localhost/b/o/approve#st=t', fp)).toContain('&fp=');
  });

  it('puts the fingerprint in lower case, and replaces an fp that is already in the fragment', () => {
    expect(approveUrl('https://vault.thecustodian.io/b/org_x/approve#st=tok', 'AB'.repeat(32))).toBe(`https://vault.thecustodian.io/b/org_x/approve#st=tok&fp=${'ab'.repeat(32)}`);
    expect(approveUrl(`https://v.example/b/o/approve#st=t&fp=${'cd'.repeat(32)}&x=1&fp=1`, fp)).toBe(`https://v.example/b/o/approve#st=t&x=1&fp=${fp}`);
  });

  it('refuses a fingerprint that is not 64 hexadecimal characters', () => {
    for (const bad of ['abcd', 'g'.repeat(64)]) expect(() => approveUrl('https://vault.example/b/o/approve#st=t', bad)).toThrow(/64 hexadecimal/);
  });

  it('refuses every other scheme, even for localhost', () => {
    for (const url of [
      'javascript://localhost/%0Aalert(1)#x',
      'ftp://localhost/file#st=t',
      'file://localhost/etc/passwd#st=t',
      'data://localhost/#st=t',
      'ws://localhost/#st=t',
      'http://vault.example/b/o/approve#st=t',
      'http://localhost.evil.example/b/o/approve#st=t',
      'https://vault.example/b/o/approve',
      'https://vault.example/b/o/approve#',
      'not a url',
    ]) expect(() => approveUrl(url, fp), url).toThrow(/not valid/);
  });
});
