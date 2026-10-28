// The fixtures are vendored from custodian-device-crypto. Two checks keep them honest: every file must match the
// manifest, and the manifest must match the hash pinned in test/fixtures.lock.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const dir = path.resolve('test/fixtures/v1');
const sha = (file: string): string => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');

describe('vendored fixtures', () => {
  it('has the manifest that is pinned', () => {
    const pinned = fs.readFileSync('test/fixtures.lock', 'utf8').trim();
    expect(sha(path.join(dir, 'MANIFEST.json'))).toBe(pinned);
  });

  it('has every file the manifest lists, unchanged, and no others', () => {
    const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'MANIFEST.json'), 'utf8')) as { files: Record<string, string> };
    const present = fs.readdirSync(dir).filter((n) => n !== 'MANIFEST.json').sort();
    expect(present).toEqual(Object.keys(manifest.files).sort());
    for (const [name, hash] of Object.entries(manifest.files)) expect(sha(path.join(dir, name)), name).toBe(hash);
  });
});
