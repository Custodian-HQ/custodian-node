// Copies the fixtures from a checkout of custodian-device-crypto and pins the manifest.
// Usage: node scripts/vendor-fixtures.mjs ../../go/custodian-device-crypto
// Review the diff before committing: it shows exactly what the wire format changed.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const source = process.argv[2];
if (!source) throw new Error('usage: vendor-fixtures.mjs <path to custodian-device-crypto>');
const from = path.join(source, 'fixtures/v1');
const to = path.resolve('test/fixtures/v1');
fs.rmSync(to, { recursive: true, force: true });
fs.mkdirSync(to, { recursive: true });
for (const name of fs.readdirSync(from)) fs.copyFileSync(path.join(from, name), path.join(to, name));
const pin = crypto.createHash('sha256').update(fs.readFileSync(path.join(to, 'MANIFEST.json'))).digest('hex');
fs.writeFileSync(path.resolve('test/fixtures.lock'), pin + '\n');
console.log(`vendored ${fs.readdirSync(to).length} files; pinned manifest ${pin}`);
