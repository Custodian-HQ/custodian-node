// Opens a disclosed file, receiver side: the file stream and its zstd layer, as in the wire format of custodian-device-crypto.
// It holds at most one chunk (1 MiB and a tag) and one zstd frame in memory, and gives out no plaintext before chunk 0 is proven.
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import type { Custodian } from './custodian.js';
import type { FileGrant, Opened } from './envelope.js';

export type FileErrorCode = 'format' | 'commitment' | 'open' | 'truncated' | 'too_long' | 'records' | 'frame' | 'key_cleared';

/** The reason a file was refused. Read `code`. Any refusal means you must not use the bytes you already read. */
export class FileError extends Error {
  constructor(readonly code: FileErrorCode, message: string) {
    super(message);
    this.name = 'FileError';
  }
}

/** Where the file comes from. Take every field from the opened envelope; `receiveFile` does this for you. */
export interface FileContext {
  businessId: string;
  customerId: string;
  /** The record token. */
  record: string;
  /** The file key name, as in the request. */
  key: string;
}

const HEADER_SIZE = 70;
const TAG_SIZE = 16;
const MIN_CHUNK = 1024;
const MAX_CHUNK = 1 << 20;
// A stream has at most 2^32 - 1 chunks, so the counters run from 0 to 2^32 - 2.
const MAX_CHUNKS = 2 ** 32 - 1;
const FLAG_ZSTD = 0x01;
const BLOCK_SIZE = 1 << 20;
const MAX_FRAME = BLOCK_SIZE + BLOCK_SIZE / 64;

/** A byte queue over an input that arrives in pieces. */
class Input {
  readonly #parts: Buffer[] = [];
  readonly #source: AsyncIterator<Uint8Array>;
  #ended = false;
  length = 0;

  constructor(source: AsyncIterable<Uint8Array> | Uint8Array) {
    this.#source = source instanceof Uint8Array ? (async function* () { yield source; })() : source[Symbol.asyncIterator]();
  }
  /** Reads until it holds at least n bytes or the input ends. */
  async fill(n: number): Promise<void> {
    while (this.length < n && !this.#ended) {
      const next = await this.#source.next();
      if (next.done) this.#ended = true;
      else if (next.value.length > 0) {
        this.#parts.push(Buffer.from(next.value.buffer, next.value.byteOffset, next.value.byteLength));
        this.length += next.value.length;
      }
    }
  }
  take(n: number): Buffer {
    const out = Buffer.allocUnsafe(n);
    let at = 0;
    while (at < n) {
      const part = this.#parts[0]!;
      const used = Math.min(part.length, n - at);
      part.copy(out, at, 0, used);
      at += used;
      if (used === part.length) this.#parts.shift();
      else this.#parts[0] = part.subarray(used);
    }
    this.length -= n;
    return out;
  }
  async close(): Promise<void> {
    if (!this.#ended) await this.#source.return?.();
  }
}

/** The caller AAD of a file: label, business, customer, record, key name and file id, each after a zero byte. */
export function fileAAD(context: FileContext, fileId: string): Buffer {
  return Buffer.from(['cdv/v1/file-value', context.businessId, context.customerId, context.record, context.key, fileId].join('\0'));
}

function nonce(prefix: Buffer, counter: number, last: boolean): Buffer {
  const out = Buffer.alloc(12);
  prefix.copy(out);
  out.writeUInt32BE(counter, 7);
  out[11] = last ? 1 : 0;
  return out;
}

function gcmOpen(key: crypto.KeyObject, iv: Buffer, aad: Buffer, chunk: Buffer): Buffer | undefined {
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAAD(aad);
  d.setAuthTag(chunk.subarray(chunk.length - TAG_SIZE));
  const out = d.update(chunk.subarray(0, chunk.length - TAG_SIZE));
  try {
    d.final();
    return out;
  } catch {
    out.fill(0);
    return undefined;
  }
}

const hkdf = (key: Buffer, label: string, salt: Buffer): Buffer => Buffer.from(crypto.hkdfSync('sha256', key, Buffer.alloc(0), Buffer.concat([Buffer.from(label), salt]), 32));

/**
 * The stream layer alone: checks the header and gives out the plaintext of each chunk once its tag is good. The first value is the
 * header flags. Use `openFile` unless you test the layers apart.
 */
export async function* openStream(fileKey: Buffer, aad: Buffer, ciphertext: AsyncIterable<Uint8Array> | Uint8Array): AsyncGenerator<number | Buffer> {
  if (fileKey.length !== 32) throw new FileError('format', 'a file key is 32 bytes');
  if (fileKey.every((byte) => byte === 0)) throw new FileError('key_cleared', 'the file key was cleared');
  const input = new Input(ciphertext);
  try {
    await input.fill(HEADER_SIZE);
    if (input.length < HEADER_SIZE) throw new FileError('format', 'the file is shorter than its header');
    const header = input.take(HEADER_SIZE);
    const size = header.readUInt32BE(11);
    if (header[0] !== 0x01 || header[1] !== 0x01 || (header[2]! & ~FLAG_ZSTD) !== 0 || size < MIN_CHUNK || size > MAX_CHUNK) {
      throw new FileError('format', 'the file is not a stream of version 1');
    }
    const salt = header.subarray(15, 31);
    const prefix = header.subarray(31, 38);
    const commit = hkdf(fileKey, 'cdv/v1/file-commit', salt);
    if (!crypto.timingSafeEqual(commit, header.subarray(38))) throw new FileError('commitment', 'the file was not made with this key');
    const raw = hkdf(fileKey, 'cdv/v1/file-enc', salt);
    const key = crypto.createSecretKey(raw);
    raw.fill(0);
    yield header[2]!;

    const full = size + TAG_SIZE;
    for (let counter = 0; ; counter++) {
      if (counter >= MAX_CHUNKS) throw new FileError('too_long', 'the file has too many chunks');
      // A full chunk is the last one only if nothing follows it.
      await input.fill(full + 1);
      const last = input.length <= full;
      if (last && input.length < TAG_SIZE) throw new FileError('truncated', 'the file ended early');
      const chunk = input.take(last ? input.length : full);
      const aadFor = counter === 0 ? Buffer.concat([header, aad]) : aad;
      const plain = gcmOpen(key, nonce(prefix, counter, last), aadFor, chunk);
      if (!plain) {
        if (last && gcmOpen(key, nonce(prefix, counter, false), aadFor, chunk)?.fill(0)) throw new FileError('truncated', 'the file ended early');
        throw new FileError('open', 'a chunk of the file does not open');
      }
      yield plain;
      if (last) return;
    }
  } finally {
    await input.close();
  }
}

/** Reads a zstd frame header and checks that the input is exactly one frame. Gives the content size, or 0 to refuse. */
function frameContentSize(f: Buffer): number {
  if (f.length < 6 || f.readUInt32LE(0) !== 0xfd2fb528) return 0;
  const fhd = f[4]!;
  const single = (fhd & 0x20) !== 0;
  if ((fhd & 0x08) !== 0) return 0;
  let pos = 5;
  let window = 0;
  if (!single) {
    const wd = f[pos++]!;
    const base = 2 ** (10 + (wd >> 3));
    window = base + (base / 8) * (wd & 7);
  }
  pos += [0, 1, 2, 4][fhd & 3]!;
  const fcsFlag = fhd >> 6;
  const fcsSize = fcsFlag === 0 ? (single ? 1 : 0) : [0, 2, 4, 8][fcsFlag]!;
  if (fcsSize === 0 || pos + fcsSize > f.length) return 0;
  let fcs: number;
  if (fcsSize === 1) fcs = f[pos]!;
  else if (fcsSize === 2) fcs = f.readUInt16LE(pos) + 256;
  else if (fcsSize === 4) fcs = f.readUInt32LE(pos);
  else {
    const big = f.readBigUInt64LE(pos);
    fcs = big > BigInt(BLOCK_SIZE) ? BLOCK_SIZE + 1 : Number(big);
  }
  pos += fcsSize;
  if (single) window = fcs;
  if (fcs === 0 || fcs > BLOCK_SIZE || window > BLOCK_SIZE) return 0;
  // Walk the blocks: the decoder alone would accept more frames after this one, such as an empty or a skippable one.
  for (;;) {
    if (f.length - pos < 3) return 0;
    const bh = f[pos]! | (f[pos + 1]! << 8) | (f[pos + 2]! << 16);
    const type = (bh >> 1) & 3;
    if (type === 3) return 0;
    pos += 3 + (type === 1 ? 1 : bh >>> 3);
    if (bh & 1) break;
  }
  if (fhd & 0x04) pos += 4;
  return pos === f.length ? fcs : 0;
}

/** Decodes one zstd frame of at most one block. Refuses a frame that says no size, a wrong size, or holds more than one frame. */
export function decodeFrame(frame: Buffer): Buffer {
  const size = frameContentSize(frame);
  if (size === 0) throw new FileError('frame', 'a zstd frame is refused');
  let out: Buffer;
  try {
    out = zlib.zstdDecompressSync(frame, { maxOutputLength: size, params: { [zlib.constants.ZSTD_d_windowLogMax]: 20 } });
  } catch {
    throw new FileError('frame', 'a zstd frame does not decode');
  }
  if (out.length !== size) throw new FileError('frame', 'a zstd frame does not decode to the size it says');
  return out;
}

/** The zstd layer alone: reads the length-prefixed frames and gives out each decoded block. */
export async function* decodeRecords(plaintext: AsyncIterable<Uint8Array> | Uint8Array): AsyncGenerator<Buffer> {
  const input = new Input(plaintext);
  try {
    for (;;) {
      await input.fill(4);
      if (input.length === 0) return;
      if (input.length < 4) throw new FileError('records', 'a record length is cut short');
      const size = input.take(4).readUInt32BE(0);
      if (size === 0 || size > MAX_FRAME) throw new FileError('records', 'a record has a length that is not allowed');
      await input.fill(size);
      if (input.length < size) throw new FileError('records', 'a record is cut short');
      yield decodeFrame(input.take(size));
    }
  } finally {
    await input.close();
  }
}

async function* chunksAfterFlags(stream: AsyncGenerator<number | Buffer>): AsyncGenerator<Buffer> {
  for await (const part of stream) yield part as Buffer;
}

async function* fileBytes(grant: FileGrant, ciphertext: AsyncIterable<Uint8Array> | Uint8Array, context: FileContext): AsyncGenerator<Buffer> {
  const stream = openStream(grant.key, fileAAD(context, grant.fileId), ciphertext);
  const first = await stream.next();
  const flags = first.value as number;
  yield* flags & FLAG_ZSTD ? decodeRecords(chunksAfterFlags(stream)) : chunksAfterFlags(stream);
}

/**
 * Opens a disclosed file as a stream of plaintext. `ciphertext` is the download from `disclosures.downloadFile`. A refusal ends the
 * stream with a FileError; drop what you read then. Check the file type again yourself: the customer chose the file.
 */
export function openFile(grant: FileGrant, ciphertext: AsyncIterable<Uint8Array> | Uint8Array, context: FileContext): ReadableStream<Uint8Array> {
  return ReadableStream.from(fileBytes(grant, ciphertext, context));
}

/**
 * Downloads one approved file and opens it. The key is cleared, and removed from `opened.files`, once the stream ends, fails or is
 * cancelled. If the download is refused before it starts (such as `429 busy`), the key is kept, so you can try again.
 */
export async function receiveFile(custodian: Custodian, opened: Opened, name: string, options: { signal?: AbortSignal } = {}): Promise<ReadableStream<Uint8Array>> {
  if (!Object.hasOwn(opened.files, name)) throw new Error(`custodian: the envelope holds no file named ${name}, or it was already received`);
  const grant = opened.files[name]!;
  // Aborted by `cancel`, so a download that has stalled is dropped at once.
  const abort = new AbortController();
  const signal = options.signal ? AbortSignal.any([options.signal, abort.signal]) : abort.signal;
  const ciphertext = await custodian.disclosures.downloadFile(opened.requestId, name, { signal });
  const context = { businessId: opened.businessId, customerId: opened.customerId, record: opened.record, key: name };
  const reader = ciphertext.getReader();
  const body: AsyncIterable<Uint8Array> = {
    async *[Symbol.asyncIterator]() {
      try {
        for (;;) {
          const next = await reader.read();
          if (next.done) return;
          yield next.value;
        }
      } finally {
        await reader.cancel().catch(() => undefined);
      }
    },
  };
  const parts = fileBytes(grant, body, context);
  let cancelled = false;
  const discard = (): void => {
    grant.key.fill(0);
    delete opened.files[name];
  };
  // Built by hand so a cancel, even one while a read waits on the network, clears the key and frees the download.
  return new ReadableStream<Uint8Array>(
    {
      async pull(controller) {
        try {
          const next = await parts.next();
          if (cancelled) return;
          if (next.done) {
            discard();
            controller.close();
          } else controller.enqueue(next.value);
        } catch (error) {
          discard();
          if (!cancelled) controller.error(error);
        }
      },
      async cancel() {
        cancelled = true;
        discard();
        abort.abort();
        // Cancelling the reader ends a read that waits on the network, so `return` does not queue behind it.
        await reader.cancel().catch(() => undefined);
        await parts.return(undefined).catch(() => undefined);
      },
    },
    { highWaterMark: 0 },
  );
}
