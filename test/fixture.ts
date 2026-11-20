import fs from 'node:fs';

/** Reads a JSON file of the vendored fixtures. */
export const fixture = <T>(name: string): T => JSON.parse(fs.readFileSync(`test/fixtures/v1/${name}`, 'utf8')) as T;
