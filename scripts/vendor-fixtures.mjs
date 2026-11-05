// Copies the fixtures from a checkout of the reference implementation and pins the manifest.
// Usage: node scripts/vendor-fixtures.mjs <path to source checkout>
// Review the diff before committing: it shows exactly what the wire format changed.
// PROVENANCE.md belongs to this repository: the copy keeps it.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const source = process.argv[2];
if (!source) throw new Error('usage: vendor-fixtures.mjs <path to source checkout>');
const from = path.join(source, 'fixtures/v1');
const to = path.resolve('test/fixtures/v1');
const sha = (data) => crypto.createHash('sha256').update(data).digest('hex');

const provenance = fs.readFileSync(path.join(to, 'PROVENANCE.md'));
fs.rmSync(to, { recursive: true, force: true });
fs.mkdirSync(to, { recursive: true });
for (const name of fs.readdirSync(from)) fs.copyFileSync(path.join(from, name), path.join(to, name));
fs.writeFileSync(path.join(to, 'PROVENANCE.md'), provenance);

const pin = sha(fs.readFileSync(path.join(to, 'MANIFEST.json')));
fs.writeFileSync(path.resolve('test/fixtures.lock'), pin + '\n');
console.log(`vendored ${fs.readdirSync(to).length} files; pinned manifest ${pin}`);
