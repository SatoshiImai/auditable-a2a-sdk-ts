/**
 * Vendor the spec's `schema/` and `vectors/` from the `auditable-a2a` repository into `spec/`, byte for byte.
 *
 * Usage:
 *   tsx scripts/sync-spec.ts            # copy source -> vendored spec/
 *   tsx scripts/sync-spec.ts --check    # verify vendored == source (CI drift gate); no writes
 *
 * The source resolves in this order: `--source` argument, `AA2A_SPEC_SRC` env var, then the default
 * sibling checkout `../auditable-a2a/spec`.
 */

import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const VENDORED_SUBDIRS = ['schema', 'vectors'] as const;

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const VENDORED_SPEC_DIR = join(REPO_ROOT, 'spec');

function roots(source: string): { src: string; dst: string }[] {
  return VENDORED_SUBDIRS.map((subdir) => ({ src: join(source, subdir), dst: join(VENDORED_SPEC_DIR, subdir) }));
}

function pairs(source: string): { src: string; dst: string }[] {
  const found: { src: string; dst: string }[] = [];
  for (const { src, dst } of roots(source)) {
    for (const srcPath of walkJson(src).sort()) {
      found.push({ src: srcPath, dst: join(dst, relative(src, srcPath)) });
    }
  }
  return found;
}
const DEFAULT_SOURCE = join(REPO_ROOT, '..', 'auditable-a2a', 'spec');

function resolveSource(cliSource: string | undefined): string {
  const raw = cliSource ?? process.env.AA2A_SPEC_SRC ?? DEFAULT_SOURCE;
  const source = resolve(raw);
  if (!existsSync(source) || !statSync(source).isDirectory()) {
    throw new Error(`spec source directory not found: ${source}`);
  }
  return source;
}

function walkJson(root: string): string[] {
  if (!existsSync(root) || !statSync(root).isDirectory()) {
    return [];
  }
  const out: string[] = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const full = join(root, entry.name);
    if (entry.isDirectory()) {
      out.push(...walkJson(full));
    } else if (entry.isFile() && entry.name.endsWith('.json')) {
      out.push(full);
    }
  }
  return out;
}

function check(source: string): boolean {
  const expected = pairs(source);
  const known = new Set(expected.map(({ dst }) => dst));
  let ok = true;

  for (const { src, dst } of expected) {
    if (!existsSync(dst)) {
      console.error(`missing in vendored copy: ${relative(REPO_ROOT, dst)}`);
      ok = false;
    } else if (!readFileSync(src).equals(readFileSync(dst))) {
      console.error(`content drift: ${relative(REPO_ROOT, dst)}`);
      ok = false;
    }
  }
  for (const { dst } of roots(source)) {
    for (const stale of walkJson(dst)) {
      if (!known.has(stale)) {
        console.error(`stale file in vendored copy (not in source): ${relative(REPO_ROOT, stale)}`);
        ok = false;
      }
    }
  }

  if (ok) {
    console.log(`vendored copies are in sync (${expected.length} files)`);
  }
  return ok;
}

function sync(source: string): number {
  for (const { dst } of roots(source)) {
    if (existsSync(dst)) {
      rmSync(dst, { recursive: true, force: true });
    }
  }
  let copied = 0;
  for (const { src, dst } of pairs(source)) {
    mkdirSync(dirname(dst), { recursive: true });
    writeFileSync(dst, readFileSync(src));
    copied += 1;
  }
  console.log(`vendored ${copied} files from ${source}`);
  return copied;
}

function main(argv: string[]): number {
  const checkOnly = argv.includes('--check');
  const sourceIdx = argv.indexOf('--source');
  const cliSource = sourceIdx >= 0 ? argv[sourceIdx + 1] : undefined;

  const source = resolveSource(cliSource);
  if (checkOnly) {
    return check(source) ? 0 : 1;
  }
  sync(source);
  return 0;
}

process.exit(main(process.argv.slice(2)));
