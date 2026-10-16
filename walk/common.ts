/**
 * Shared by the walk's processes. Each prints `WALK_URL=<url>` once it listens, and binds `WALK_PORT` when given,
 * so a restarted Server Agent keeps its URL and key ids (§5.2, §10.2).
 */

import { appendFileSync, closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync } from 'node:fs';
import { createServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { type KeyRole, type LedgerRepository, publicJwk, RepositoryError, type SealedRecord } from 'auditable-mcp-sdk';
import { toNodeListener } from 'auditable-mcp-sdk/node';

/** A `LedgerRepository` keeping each partition as a JSON-lines file. */
export class FileLedgerRepository implements LedgerRepository {
  readonly #directory: string;

  constructor(directory: string) {
    this.#directory = directory;
    mkdirSync(directory, { recursive: true });
  }

  #path(partition: string): string {
    return join(this.#directory, `${partition.replaceAll('/', '_')}.jsonl`);
  }

  async append(partition: string, record: SealedRecord): Promise<void> {
    const records = await this.readAll(partition);
    const expected = records.length === 0 ? 0 : (records.at(-1) as SealedRecord).seq + 1;
    if (record.seq !== expected) {
      throw new RepositoryError(`seq ${record.seq} is not the next position ${expected} of ${partition}`);
    }
    const fd = openSync(this.#path(partition), 'a');
    try {
      appendFileSync(fd, `${JSON.stringify(record)}\n`);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  }

  async loadTail(partition: string): Promise<SealedRecord | null> {
    return (await this.readAll(partition)).at(-1) ?? null;
  }

  async readAll(partition: string): Promise<SealedRecord[]> {
    const path = this.#path(partition);
    if (!existsSync(path)) return [];
    return readFileSync(path, 'utf8')
      .split('\n')
      .filter((line) => line !== '')
      .map((line) => JSON.parse(line) as SealedRecord);
  }
}

/** Publish a key as a JWK (§10.2). */
export function ordinaryJwk(kid: string, publicKey: Uint8Array, role: (typeof KeyRole)[keyof typeof KeyRole]) {
  const { amcp_role: _role, ...jwk } = publicJwk(kid, publicKey, 'Ed25519', role);
  return jwk;
}

/** Listen over HTTPS and announce the URL only after `route` is built, so a resumption finishes first. */
export async function serve(
  route: (base: string) => Promise<(request: Request) => Promise<Response>>,
): Promise<void> {
  let handler: (request: Request) => Promise<Response> = async () => new Response(null, { status: 503 });
  const server = createServer(
    { key: readFileSync(process.env.WALK_TLS_KEY as string), cert: readFileSync(process.env.WALK_TLS_CERT as string) },
    toNodeListener({ fetch: (request) => handler(request) }),
  );
  await new Promise<void>((resolve) => server.listen(Number(process.env.WALK_PORT ?? 0), '127.0.0.1', resolve));
  const base = `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
  handler = await route(base);
  process.stdout.write(`WALK_URL=${base}\n`);
}

export const json = (body: unknown, init: ResponseInit = {}): Response =>
  new Response(JSON.stringify(body), { ...init, headers: { 'content-type': 'application/json', ...init.headers } });
