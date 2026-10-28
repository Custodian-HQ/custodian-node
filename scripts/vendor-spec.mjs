// Copies the business API spec from a checkout of custodian-api and pins it. A test checks that the SDK calls exactly the
// operations the spec lists. Review the diff before committing: it shows what the API changed.
// Usage: node scripts/vendor-spec.mjs ../../go/Custodian
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const source = process.argv[2];
if (!source) throw new Error('usage: vendor-spec.mjs <path to custodian-api>');
const text = fs.readFileSync(path.join(source, 'docs/openapi-vault.yaml'));
fs.mkdirSync('test/spec', { recursive: true });
fs.writeFileSync('test/spec/openapi-vault.yaml', text);
const pin = crypto.createHash('sha256').update(text).digest('hex');
fs.writeFileSync('test/spec/openapi-vault.lock', pin + '\n');
console.log(`vendored the spec; pinned ${pin}`);
