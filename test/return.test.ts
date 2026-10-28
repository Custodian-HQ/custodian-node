import { describe, expect, it } from 'vitest';
import { parseReturn } from '../src/return.js';

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
