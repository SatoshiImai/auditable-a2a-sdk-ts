/** Refuse to publish while a dependency is a `file:` or `link:` range. */

import { readFileSync } from 'node:fs';

const LOCAL_RANGE = /^(?:file|link):/;

const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as Record<
  string,
  unknown
>;
const local = ['dependencies', 'peerDependencies', 'optionalDependencies'].flatMap((field) =>
  Object.entries((manifest[field] ?? {}) as Record<string, string>)
    .filter(([, range]) => LOCAL_RANGE.test(range))
    .map(([name, range]) => `${field}.${name}: ${range}`),
);
if (local.length > 0) {
  process.stderr.write(`refusing to publish with local dependencies:\n  ${local.join('\n  ')}\n`);
  process.exit(1);
}
