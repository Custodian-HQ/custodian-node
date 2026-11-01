// The SDK version is the API spec version. With a tag (v0.1.0) the tag must match too.
import { readFileSync } from 'node:fs';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const spec = readFileSync(new URL('../test/spec/openapi-vault.yaml', import.meta.url), 'utf8');
const specVersion = /^info:[\s\S]*?^ {2}version:\s*(\S+)/m.exec(spec)?.[1];
const tag = process.argv[2];

const problems = [];
if (!specVersion) problems.push('no version in test/spec/openapi-vault.yaml');
else if (pkg.version !== specVersion) problems.push(`package.json version ${pkg.version} does not match the API spec version ${specVersion}`);
if (tag && tag.replace(/^v/, '') !== pkg.version) problems.push(`tag ${tag} does not match package.json version ${pkg.version}`);
if (problems.length) {
  console.error(problems.join('\n'));
  process.exit(1);
}
console.log(`version ${pkg.version} ok`);
