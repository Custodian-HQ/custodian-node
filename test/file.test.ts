import crypto from 'node:crypto';
import fs from 'node:fs';
import { describe, expect, it } from 'vitest';
import { Custodian } from '../src/custodian.js';
import { decodeRecords, FileError, fileAAD, openFile, openStream, receiveFile } from '../src/file.js';
import { FILE_KEY_ID, type Opened } from '../src/envelope.js';

interface StreamCase {
  name: string;
  flags: number;
  chunk_size: number;
  salt_hex: string;
  prefix_hex: string;
  plaintext_seed: string;
  plaintext_bytes: number;
  chunks: number;
  header_hex: string;
  stream_sha256: string;
  stream_hex?: string;
}
const fs_ = JSON.parse(fs.readFileSync('test/fixtures/v1/file-stream.json', 'utf8')) as {
  key_hex: string; key_id_hex: string; other_key_hex: string; aad_hex: string; cases: StreamCase[]; refusal_stream: StreamCase; must_fail: { name: string; stream_hex: string; error: string }[];
};
const zs = JSON.parse(fs.readFileSync('test/fixtures/v1/zstd-records.json', 'utf8')) as {
  max_frame: number; cases: { name: string; plaintext_bytes: number; records_hex: string }[]; must_fail: { name: string; records_hex: string; error: string }[];
};

const key = Buffer.from(fs_.key_hex, 'hex');
const aad = Buffer.from(fs_.aad_hex, 'hex');
const sha = (b: Buffer): string => crypto.createHash('sha256').update(b).digest('hex');

function streamPlaintext(seed: string, size: number): Buffer {
  const parts: Buffer[] = [];
  for (let n = 0, have = 0; have < size; n++, have += 32) parts.push(crypto.createHash('sha256').update(`${seed}/${n}`).digest());
  return Buffer.concat(parts).subarray(0, size);
}

function zstdPlaintext(size: number): Buffer {
  const unit = Buffer.from('a value the server must never read. ');
  return Buffer.alloc(size, unit);
}

/** A sealer for tests only, as in the wire format; it lets the large fixture cases be checked by their hash. */
function seal(fileKey: Buffer, callerAad: Buffer, plain: Buffer, o: { flags: number; size: number; salt: Buffer; prefix: Buffer; keyId: Buffer }): Buffer {
  const info = (label: string): Buffer => Buffer.concat([Buffer.from(label), o.salt]);
  const enc = Buffer.from(crypto.hkdfSync('sha256', fileKey, Buffer.alloc(0), info('cdv/v1/file-enc'), 32));
  const commit = Buffer.from(crypto.hkdfSync('sha256', fileKey, Buffer.alloc(0), info('cdv/v1/file-commit'), 32));
  const size = Buffer.alloc(4);
  size.writeUInt32BE(o.size);
  const header = Buffer.concat([Buffer.from([1, 1, o.flags]), o.keyId, size, o.salt, o.prefix, commit]);
  const out = [header];
  const count = Math.max(1, Math.ceil(plain.length / o.size));
  for (let i = 0; i < count; i++) {
    const last = i === count - 1;
    const iv = Buffer.alloc(12);
    o.prefix.copy(iv);
    iv.writeUInt32BE(i, 7);
    iv[11] = last ? 1 : 0;
    const c = crypto.createCipheriv('aes-256-gcm', enc, iv);
    c.setAAD(i === 0 ? Buffer.concat([header, callerAad]) : callerAad);
    out.push(c.update(plain.subarray(i * o.size, (i + 1) * o.size)), c.final(), c.getAuthTag());
  }
  return Buffer.concat(out);
}

const sealCase = (c: StreamCase, plain: Buffer): Buffer =>
  seal(key, aad, plain, { flags: c.flags, size: c.chunk_size, salt: Buffer.from(c.salt_hex, 'hex'), prefix: Buffer.from(c.prefix_hex, 'hex'), keyId: Buffer.from(fs_.key_id_hex, 'hex') });

/** Feeds the input in small, uneven pieces, as a network would. */
async function* pieces(b: Buffer, size = 7777): AsyncGenerator<Uint8Array> {
  for (let at = 0; at < b.length; at += size) yield b.subarray(at, at + size);
}

async function readStream(fileKey: Buffer, callerAad: Buffer, input: AsyncIterable<Uint8Array> | Uint8Array): Promise<{ flags: number; plain: Buffer; biggest: number }> {
  let flags = -1;
  let biggest = 0;
  const parts: Buffer[] = [];
  for await (const part of openStream(fileKey, callerAad, input)) {
    if (typeof part === 'number') flags = part;
    else {
      parts.push(part);
      biggest = Math.max(biggest, part.length);
    }
  }
  return { flags, plain: Buffer.concat(parts), biggest };
}

async function codeOf(run: () => Promise<unknown>): Promise<string> {
  try {
    await run();
  } catch (error) {
    return error instanceof FileError ? error.code : `other: ${String(error)}`;
  }
  return 'opened';
}

async function collect(stream: ReadableStream<Uint8Array> | AsyncIterable<Uint8Array>): Promise<Buffer> {
  const parts: Uint8Array[] = [];
  for await (const part of stream) parts.push(part);
  return Buffer.concat(parts);
}

describe('the file stream fixture', () => {
  it.each(fs_.cases)('opens $name', async (c) => {
    const plain = streamPlaintext(c.plaintext_seed, c.plaintext_bytes);
    const stream = c.stream_hex ? Buffer.from(c.stream_hex, 'hex') : sealCase(c, plain);
    expect(sha(stream)).toBe(c.stream_sha256);
    expect(stream.subarray(0, 70).toString('hex')).toBe(c.header_hex);
    const got = await readStream(key, aad, pieces(stream));
    expect(got.flags).toBe(c.flags);
    expect(got.plain.equals(plain)).toBe(true);
    expect(got.biggest).toBeLessThanOrEqual(c.chunk_size);
  });

  it('refuses every change in the fixture for the right reason', async () => {
    expect(fs_.must_fail.length).toBeGreaterThanOrEqual(20);
    for (const f of fs_.must_fail) {
      // These two are a good stream opened with the other key, or with an "x" added to the AAD.
      const k = f.name === 'another key' ? Buffer.from(fs_.other_key_hex, 'hex') : key;
      const a = f.name === 'another AAD' ? Buffer.concat([aad, Buffer.from('x')]) : aad;
      expect(await codeOf(() => readStream(k, a, Buffer.from(f.stream_hex, 'hex'))), f.name).toBe(f.error);
    }
  });

  it('refuses another key and a wrong key name in the context', async () => {
    const stream = Buffer.from(fs_.refusal_stream.stream_hex!, 'hex');
    expect(await codeOf(() => readStream(Buffer.from(fs_.other_key_hex, 'hex'), aad, stream))).toBe('commitment');
    const context = { businessId: 'org_0123', customerId: 'cus_0123', record: 'rec_0123', key: 'id_document' };
    expect(fileAAD(context, 'file_0123').equals(aad)).toBe(true);
    expect(await codeOf(() => readStream(key, fileAAD({ ...context, key: 'passport' }, 'file_0123'), stream))).toBe('open');
  });

  it('gives out nothing before chunk 0 is proven', async () => {
    const stream = Buffer.from(fs_.refusal_stream.stream_hex!, 'hex');
    stream[70] = stream[70]! ^ 1;
    const out: unknown[] = [];
    const code = await codeOf(async () => {
      for await (const part of openStream(key, aad, stream)) out.push(part);
    });
    expect(code).toBe('open');
    expect(out).toEqual([fs_.refusal_stream.flags]);
  });
});

describe('the zstd fixture', () => {
  it('has the frame limit this reader uses', () => {
    expect(zs.max_frame).toBe(1064960);
  });

  it.each(zs.cases)('decodes $name', async (c) => {
    const plain = await collect(decodeRecords(pieces(Buffer.from(c.records_hex, 'hex'), 13)));
    expect(plain.equals(zstdPlaintext(c.plaintext_bytes))).toBe(true);
  });

  it('refuses every hostile record for the right reason', async () => {
    const map: Record<string, string> = { format: 'records', frame: 'frame' };
    for (const f of zs.must_fail) {
      expect(await codeOf(() => collect(decodeRecords(Buffer.from(f.records_hex, 'hex')))), f.name).toBe(map[f.error]);
    }
  });
});

describe('openFile', () => {
  const context = { businessId: 'org_1', customerId: 'cus_1', record: 'rec_1', key: 'passport' };
  const grant = { fileId: 'fil_1', key: crypto.randomBytes(32) };
  const opts = { size: 1 << 20, salt: crypto.randomBytes(16), prefix: crypto.randomBytes(7), keyId: FILE_KEY_ID };
  const twoBlocks = zs.cases.find((c) => c.name === 'a full block and a short one')!;
  const records = Buffer.from(twoBlocks.records_hex, 'hex');

  it('opens a zstd file and a plain file', async () => {
    const zipped = seal(grant.key, fileAAD(context, grant.fileId), records, { ...opts, flags: 1 });
    expect((await collect(openFile(grant, pieces(zipped), context))).equals(zstdPlaintext(twoBlocks.plaintext_bytes))).toBe(true);
    const plain = crypto.randomBytes(3 * 1024 + 5);
    const sealed = seal(grant.key, fileAAD(context, grant.fileId), plain, { ...opts, size: 1024, flags: 0 });
    expect((await collect(openFile(grant, sealed, context))).equals(plain)).toBe(true);
  });

  it('refuses a cut file, a moved chunk, a wrong key name, a bad commitment and a hostile frame', async () => {
    const plain = crypto.randomBytes(3 * 1024 + 5);
    const sealed = seal(grant.key, fileAAD(context, grant.fileId), plain, { ...opts, size: 1024, flags: 0 });
    const chunk = (i: number): Buffer => sealed.subarray(70 + i * 1040, 70 + (i + 1) * 1040);
    const open = (b: Buffer, ctx = context): Promise<Buffer> => collect(openFile(grant, b, ctx));
    expect(await codeOf(() => open(sealed.subarray(0, 70 + 3 * 1040)))).toBe('truncated');
    expect(await codeOf(() => open(Buffer.concat([sealed.subarray(0, 70), chunk(0), chunk(2), chunk(1), sealed.subarray(70 + 3 * 1040)])))).toBe('open');
    expect(await codeOf(() => open(sealed, { ...context, key: 'utility_bill' }))).toBe('open');
    const badCommit = Buffer.from(sealed);
    badCommit[69] = badCommit[69]! ^ 1;
    expect(await codeOf(() => open(badCommit))).toBe('commitment');
    const hostile = Buffer.from(zs.must_fail.find((f) => f.name === 'a frame of 64 MiB')!.records_hex, 'hex');
    expect(await codeOf(() => open(seal(grant.key, fileAAD(context, grant.fileId), hostile, { ...opts, flags: 1 })))).toBe('frame');
    const long = Buffer.from(zs.must_fail.find((f) => f.name === 'a record longer than the limit')!.records_hex, 'hex');
    expect(await codeOf(() => open(seal(grant.key, fileAAD(context, grant.fileId), long, { ...opts, flags: 1 })))).toBe('records');
  });

  it('refuses a stream with more chunks than the limit', async () => {
    const sealed = seal(grant.key, fileAAD(context, grant.fileId), crypto.randomBytes(3 * 1024), { ...opts, size: 1024, flags: 0 });
    const run = async (max: number): Promise<number> => {
      let n = 0;
      for await (const part of openStream(grant.key, fileAAD(context, grant.fileId), sealed, max)) if (typeof part !== 'number') n++;
      return n;
    };
    expect(await run(3)).toBe(3);
    await expect(run(2)).rejects.toMatchObject({ code: 'too_long' });
  });

  it('refuses a compressed file that is cut at the border of a chunk', async () => {
    // Several good records in a row, so the records layer is more than two chunks long.
    const many = Buffer.concat(Array.from({ length: 6 }, () => Buffer.concat(zs.cases.map((c) => Buffer.from(c.records_hex, 'hex')))));
    expect(many.length).toBeGreaterThan(2 * 1024);
    const sealed = seal(grant.key, fileAAD(context, grant.fileId), many, { ...opts, size: 1024, flags: 1 });
    const chunks = Math.ceil(many.length / 1024);
    expect((await collect(openFile(grant, sealed, context))).length).toBeGreaterThan(0);
    for (let keep = 1; keep < chunks; keep++) {
      const cut = sealed.subarray(0, 70 + keep * (1024 + 16));
      expect(await codeOf(() => collect(openFile(grant, cut, context))), `${keep} chunks kept`).toBe('truncated');
    }
  });

  it('refuses a key that was cleared, with its own error', async () => {
    const sealed = seal(grant.key, fileAAD(context, grant.fileId), crypto.randomBytes(2000), { ...opts, size: 1024, flags: 0 });
    const cleared = { fileId: grant.fileId, key: Buffer.alloc(32) };
    expect(await codeOf(() => collect(openFile(cleared, sealed, context)))).toBe('key_cleared');
    expect(await codeOf(() => readStream(Buffer.alloc(32), aad, sealed))).toBe('key_cleared');
    expect(await codeOf(() => readStream(Buffer.alloc(31), aad, sealed))).toBe('format');
  });
});

describe('downloadFile and receiveFile', () => {
  const plain = crypto.randomBytes(2500);
  const grantKey = crypto.randomBytes(32);
  const context = { businessId: 'org_1', customerId: 'cus_1', record: 'rec_1', key: 'passport' };
  const sealed = seal(grantKey, fileAAD(context, 'fil_1'), plain, { flags: 0, size: 1024, salt: crypto.randomBytes(16), prefix: crypto.randomBytes(7), keyId: FILE_KEY_ID });
  const opened = (): Opened => ({ requestId: 'dsc_1', businessId: 'org_1', customerId: 'cus_1', record: 'rec_1', approvedAt: 1, fields: {}, files: { passport: { fileId: 'fil_1', key: Buffer.from(grantKey) } } });

  it('downloads, opens, then clears and forgets the key', async () => {
    const seen: { url: string; headers: Record<string, string> }[] = [];
    const fetchStub: typeof fetch = async (input, init) => {
      seen.push({ url: String(input), headers: init?.headers as Record<string, string> });
      return new Response(new Blob([sealed]).stream(), { status: 200 });
    };
    const c = new Custodian('k', { baseUrl: 'https://api.test/vault/v1', fetch: fetchStub });
    const o = opened();
    const key = o.files['passport']!.key;
    expect((await collect(await receiveFile(c, o, 'passport'))).equals(plain)).toBe(true);
    expect(seen[0]?.url).toBe('https://api.test/vault/v1/disclosures/dsc_1/files/passport');
    expect(seen[0]?.headers['Accept']).toContain('application/octet-stream');
    expect(key.equals(Buffer.alloc(32))).toBe(true);
    expect(o.files).toEqual({});
    await expect(receiveFile(c, o, 'passport')).rejects.toThrow(/no file named passport/);
  });

  it('clears the key and cancels the download when the stream is cancelled before any read', async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({ pull: (c) => c.enqueue(sealed), cancel: () => void (cancelled = true) });
    const c = new Custodian('k', { fetch: async () => new Response(body, { status: 200 }) });
    const o = opened();
    const key = o.files['passport']!.key;
    await (await receiveFile(c, o, 'passport')).cancel();
    expect(key.equals(Buffer.alloc(32))).toBe(true);
    expect(o.files).toEqual({});
    expect(cancelled).toBe(true);
  });

  it('clears the key when the file is refused', async () => {
    const bad = Buffer.from(sealed);
    bad[100] = bad[100]! ^ 1;
    const c = new Custodian('k', { fetch: async () => new Response(bad, { status: 200 }) });
    const o = opened();
    const key = o.files['passport']!.key;
    const stream = await receiveFile(c, o, 'passport');
    expect(await codeOf(() => collect(stream))).toBe('open');
    expect(key.equals(Buffer.alloc(32))).toBe(true);
    expect(o.files).toEqual({});
  });

  it('keeps the key when the download is refused before it starts', async () => {
    const fetchStub: typeof fetch = async () => new Response('{"error":{"type":"rate_limit_error","code":"busy","message":"busy"}}', { status: 429 });
    const o = opened();
    await expect(receiveFile(new Custodian('k', { fetch: fetchStub }), o, 'passport')).rejects.toMatchObject({ status: 429, code: 'busy' });
    expect(o.files['passport']?.key.equals(grantKey)).toBe(true);
  });

  it('sends a range, wants 206 for it, and says clearly when the file was replaced', async () => {
    let status = 206;
    let range: string | undefined;
    const fetchStub: typeof fetch = async (_input, init) => {
      range = (init?.headers as Record<string, string>)['Range'];
      if (status === 410) return new Response('{"error":{"type":"invalid_request_error","code":"file_replaced","message":"gone"}}', { status });
      return new Response(new Uint8Array([1, 2, 3]), { status });
    };
    const c = new Custodian('k', { fetch: fetchStub });
    expect([...(await collect(await c.disclosures.downloadFile('dsc_1', 'passport', { range: { start: 0, end: 1023 } })))]).toEqual([1, 2, 3]);
    expect(range).toBe('bytes=0-1023');
    await c.disclosures.downloadFile('dsc_1', 'passport', { range: { start: 1024 } });
    expect(range).toBe('bytes=1024-');
    status = 200;
    await expect(c.disclosures.downloadFile('dsc_1', 'passport', { range: { start: 5 } })).rejects.toMatchObject({ status: 200, code: 'unexpected_status' });
    await expect(c.disclosures.downloadFile('dsc_1', 'passport', { range: { start: -1 } })).rejects.toThrow(/byte range/);
    status = 410;
    await expect(c.disclosures.downloadFile('dsc_1', 'passport')).rejects.toMatchObject({ status: 410, code: 'file_replaced', message: expect.stringMatching(/replaced or removed/) });
  });

  it('wants exactly 200 for a whole file and exactly 206 for a range, and refuses any other success', async () => {
    let status = 200;
    const fetchStub: typeof fetch = async () => new Response(status === 204 ? null : new Uint8Array([1]), { status });
    const c = new Custodian('k', { fetch: fetchStub });
    status = 206;
    await expect(c.disclosures.downloadFile('dsc_1', 'passport')).rejects.toMatchObject({ status: 206, code: 'unexpected_status' });
    status = 204;
    await expect(c.disclosures.downloadFile('dsc_1', 'passport')).rejects.toMatchObject({ status: 204, code: 'unexpected_status' });
    await expect(c.disclosures.downloadFile('dsc_1', 'passport', { range: { start: 0 } })).rejects.toMatchObject({ status: 204, code: 'unexpected_status' });
    status = 200;
    expect([...(await collect(await c.disclosures.downloadFile('dsc_1', 'passport')))]).toEqual([1]);
  });

  it('says no file named for a name that only the prototype has', async () => {
    let called = false;
    const c = new Custodian('k', { fetch: async () => { called = true; return new Response(sealed, { status: 200 }); } });
    for (const name of ['constructor', '__proto__', 'toString', 'hasOwnProperty']) {
      await expect(receiveFile(c, opened(), name)).rejects.toThrow(/no file named/);
    }
    expect(called).toBe(false);
  });

  it('settles a cancel that comes while a read waits on a stalled download, and clears the key', async () => {
    let signal: AbortSignal | undefined;
    let bodyCancelled = false;
    // The first bytes arrive and then nothing does: the read inside the file layer waits for more.
    const body = new ReadableStream<Uint8Array>({
      start: (controller) => controller.enqueue(sealed.subarray(0, 10)),
      pull: () => new Promise<void>(() => undefined),
      cancel: () => void (bodyCancelled = true),
    });
    const c = new Custodian('k', { fetch: async (_input, init) => { signal = init?.signal ?? undefined; return new Response(body, { status: 200 }); } });
    const o = opened();
    const key = o.files['passport']!.key;
    const stream = await receiveFile(c, o, 'passport');
    const reader = stream.getReader();
    const read = reader.read().catch((e: unknown) => e);
    await new Promise((done) => setTimeout(done, 50));
    const outcome = await Promise.race([reader.cancel().then(() => 'settled'), new Promise((done) => setTimeout(() => done('hung'), 1000))]);
    expect(outcome).toBe('settled');
    expect(signal?.aborted).toBe(true);
    expect(bodyCancelled).toBe(true);
    expect(key.equals(Buffer.alloc(32))).toBe(true);
    expect(o.files).toEqual({});
    expect(await Promise.race([read, new Promise((done) => setTimeout(() => done('pending'), 1000))])).not.toBe('pending');
  });

  it('also aborts the download when the caller aborts', async () => {
    let signal: AbortSignal | undefined;
    const c = new Custodian('k', { fetch: async (_input, init) => { signal = init?.signal ?? undefined; return new Response(sealed, { status: 200 }); } });
    const caller = new AbortController();
    await receiveFile(c, opened(), 'passport', { signal: caller.signal });
    expect(signal?.aborted).toBe(false);
    caller.abort();
    expect(signal?.aborted).toBe(true);
  });
});
