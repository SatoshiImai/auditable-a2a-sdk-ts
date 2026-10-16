/** Load the vendored conformance vectors. */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const SPEC_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'spec');

export function loadVector<T>(name: string): T {
  return JSON.parse(readFileSync(join(SPEC_DIR, 'vectors', name), 'utf-8')) as T;
}

export function loadSchema(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(SPEC_DIR, 'schema', name), 'utf-8')) as Record<string, unknown>;
}
