// Founder rule: this SDK never carries Custodian Personal code. The needles are built in pieces so this file does not match itself.
import fs from 'node:fs';
import path from 'node:path';
import { expect, it } from 'vitest';

const needles = ['cdv/v1/' + 'personal/', 'fixtures/' + 'personal', 'personal-' + 'sign.json'];
const skip = new Set(['node_modules', '.git', 'dist']);

function* files(dir: string): Generator<string> {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (skip.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* files(full);
    else yield full;
  }
}

it('holds no Personal label, fixture or file name', () => {
  const found: string[] = [];
  for (const file of files('.')) {
    if (path.basename(file).toLowerCase().includes('personal') && !file.endsWith('personal-guard.test.ts')) found.push(`${file}: name`);
    const text = fs.readFileSync(file, 'utf8');
    for (const n of needles) if (text.includes(n)) found.push(`${file}: ${n}`);
  }
  expect(found).toEqual([]);
});
