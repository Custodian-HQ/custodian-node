import { describe, expect, it, vi } from 'vitest';
import { decodePayload, EnvelopeError, openEnvelope } from '../src/envelope.js';
import { fixture } from './fixture.js';
import { build, bytes, grant, head, map, nonCanonical, text, uint } from './envelope-builder.js';

function codeOf(run: () => unknown): { code: string; message: string } {
  try {
    run();
  } catch (error) {
    if (error instanceof EnvelopeError) return { code: error.code, message: error.message };
    throw error;
  }
  return { code: 'opened', message: '' };
}

describe('an envelope that is signed and then changed', () => {
  it('opens when nothing is changed', () => {
    const { envelope, want } = build({ keys: { name: 'Amina' }, files: { passport: Buffer.alloc(32, 7) } });
    const opened = openEnvelope(envelope, want);
    expect(opened.fields).toEqual({ name: 'Amina' });
    expect(opened.files['passport']?.fileId).toBe('fil_passport');
  });

  it('refuses a changed enc and a changed commitment, because the key commitment fails', () => {
    for (const part of ['enc', 'commit'] as const) {
      const { envelope, want } = build({ tamper: { [part]: (b: Buffer) => Buffer.from(b.map((x, i) => (i === 0 ? x ^ 1 : x))) } });
      const got = codeOf(() => openEnvelope(envelope, want));
      expect(got.code, part).toBe('payload');
      expect(got.message, part).toMatch(/commitment/);
    }
  });

  it('refuses a changed ciphertext, because the authentication tag fails and not the commitment', () => {
    const { envelope, want } = build({ tamper: { ct: (b) => Buffer.from(b.map((x, i) => (i === 0 ? x ^ 1 : x))) } });
    const got = codeOf(() => openEnvelope(envelope, want));
    expect(got.code).toBe('payload');
    expect(got.message).not.toMatch(/commitment/);
  });
});

describe('the names in the sealed content', () => {
  it('refuses a file grant named __proto__ that was not asked for', () => {
    const key = Buffer.alloc(32, 9);
    const payload = map([
      ['request_id', text('dsc_1')],
      ['record', text('rec_1')],
      ['approved_at', uint(1)],
      ['fields', map([['name', text('Amina')]])],
      ['files', map([['a', grant('fil_a', key)], ['__proto__', grant('fil_x', Buffer.alloc(32, 8))]])],
    ]);
    const { envelope, want } = build({ payload, keys: { name: 'Amina' }, files: { a: key } });
    expect(codeOf(() => openEnvelope(envelope, want))).toMatchObject({ code: 'payload', message: expect.stringMatching(/keys that were asked for/) });
  });

  it('keeps a key named constructor or __proto__ as an ordinary name', () => {
    const { envelope, want } = build({ keys: { constructor: 'one', toString: 'two' }, files: { hasOwnProperty: Buffer.alloc(32, 3) } });
    const opened = openEnvelope(envelope, want);
    expect(Object.keys(opened.fields).sort()).toEqual(['constructor', 'toString']);
    expect(opened.fields['constructor']).toBe('one');
    expect(Object.keys(opened.files)).toEqual(['hasOwnProperty']);
    expect(Object.getPrototypeOf(opened.fields)).toBeNull();
    expect(Object.getPrototypeOf(opened.files)).toBeNull();
  });

  it('clears every file key it copied when the sealed content is refused', () => {
    const keys = [Buffer.alloc(32, 1), Buffer.alloc(32, 2), Buffer.alloc(32, 3)];
    const payload = map([
      ['request_id', text('dsc_1')],
      ['record', text('rec_1')],
      ['approved_at', uint(1)],
      ['fields', map([['name', text('Amina')]])],
      ['files', map([['a', grant('fil_a', keys[0]!)], ['b', grant('fil_b', keys[1]!)], ['c', grant('fil_c', keys[2]!)]])],
    ]);
    // The seal is good, but only a and b were asked for, so the check on the names fails after all three grants were read.
    const { envelope, want } = build({ payload, keys: { name: 'Amina' }, files: { a: keys[0]!, b: keys[1]! } });
    const original = Buffer.from.bind(Buffer) as (...args: unknown[]) => Buffer;
    const copies: Buffer[] = [];
    const spy = vi.spyOn(Buffer, 'from').mockImplementation(((...args: unknown[]) => {
      const out = original(...args);
      if (out.length === 32 && keys.some((k) => k.equals(out))) copies.push(out);
      return out;
    }) as never);
    let got: { code: string };
    try {
      got = codeOf(() => openEnvelope(envelope, want));
    } finally {
      spy.mockRestore();
    }
    expect(got.code).toBe('payload');
    expect(copies.length).toBeGreaterThanOrEqual(3);
    for (const copy of copies) expect(copy.equals(Buffer.alloc(32))).toBe(true);
  });
});

describe('base64url that is not the one canonical text', () => {
  it('is refused in every field, though the bytes are the same', () => {
    const { envelope, want } = build();
    expect(codeOf(() => openEnvelope(envelope, want)).code).toBe('opened');
    for (const field of ['sig', 'enc', 'commit', 'ct'] as const) {
      const changed = { ...envelope, [field]: nonCanonical(String(envelope[field])) };
      expect(Buffer.from(String(changed[field]), 'base64url').equals(Buffer.from(String(envelope[field]), 'base64url'))).toBe(true);
      expect(codeOf(() => openEnvelope(changed, want)).code, field).toBe('format');
    }
  });
});

describe('the CBOR reader', () => {
  const refused = (hex: string): boolean => {
    try {
      decodePayload(Buffer.from(hex, 'hex'));
    } catch (error) {
      return error instanceof EnvelopeError && error.code === 'payload';
    }
    return false;
  };

  it('reads a good map', () => {
    expect(decodePayload(map([['a', uint(1)], ['b', bytes(Buffer.from('xy'))]]))).toEqual({ kind: 'm', m: [['a', { kind: 'n', n: 1 }], ['b', { kind: 'b', b: Buffer.from('xy') }]] });
  });

  it('refuses a number that is not the shortest, out-of-order keys, repeated keys, bytes after the item and bad UTF-8', () => {
    expect(refused('1805')).toBe(true); // 5 in two bytes
    expect(refused('190005')).toBe(true); // 5 in three bytes
    expect(refused('1a000000ff')).toBe(true); // 255 in five bytes
    expect(refused('a2616201616102')).toBe(true); // keys b, a
    expect(refused('a2616101616102')).toBe(true); // key a twice
    expect(refused('0100')).toBe(true);
    expect(refused('62fffe')).toBe(true);
    expect(refused('')).toBe(true);
    expect(refused('62')).toBe(true);
  });

  it('refuses a map that is nested deeper than 8 levels', () => {
    const nest = (levels: number): Buffer => (levels === 0 ? uint(0) : Buffer.concat([head(5, 1), text('a'), nest(levels - 1)]));
    expect(() => decodePayload(nest(3))).not.toThrow();
    expect(() => decodePayload(nest(5))).not.toThrow();
    expect(() => decodePayload(nest(9))).toThrow(EnvelopeError);
  });

  it('refuses everything in the shared list of invalid items', () => {
    const shared = fixture<{ invalid: { name: string; hex: string }[] }>('cbor.json');
    expect(shared.invalid.length).toBeGreaterThanOrEqual(20);
    for (const item of shared.invalid) expect(refused(item.hex), item.name).toBe(true);
  });
});
