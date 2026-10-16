/**
 * The audit host's countersignature keys on the Server Agent (§10.2). A failed refetch answers `'unavailable'`
 * (a failure to record, `host-unavailable`), not a failed countersignature.
 */

import { CountersignatureRegistryVerifier, type CountersignatureVerifier, KeyRole } from 'auditable-mcp-sdk';
import { keyIdOf, registryFromJwks } from './keys';

export interface HostKeySet {
  keys: Record<string, unknown>[];
}

/** Fetches the JWKS at `url`; it throws when it could not. */
export type FetchHostKeys = (url: string) => Promise<HostKeySet>;

/** Fetch a JWKS: one GET, no redirect, bounded to `timeoutMs` (§6.8, §13.1); throws unless `200` with a JWK Set. */
export function fetchHostKeysWith(fetchImpl: typeof fetch = fetch, timeoutMs = 10_000): FetchHostKeys {
  return async (url) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetchImpl(url, { redirect: 'manual', signal: controller.signal });
      if (response.status !== 200) throw new Error(`hostKeys answered ${response.status}`);
      const body = (await response.json()) as unknown;
      if (typeof body !== 'object' || body === null || !Array.isArray((body as { keys?: unknown }).keys)) {
        throw new Error('hostKeys is not a JWK Set');
      }
      return body as HostKeySet;
    } finally {
      clearTimeout(timer);
    }
  };
}

/** Verifies countersignatures against the host's keys, fetching them again for a `kid` it does not hold. */
export class HostKeysVerifier implements CountersignatureVerifier {
  readonly #url: string;
  readonly #fetch: FetchHostKeys | undefined;
  #snapshot: HostKeySet;
  #verifier: CountersignatureRegistryVerifier;

  /**
   * @param url The `hostKeys` URL.
   * @param snapshot The JWKS fetched from it.
   * @param fetchKeys Fetches it again; without it, a `kid` not in `snapshot` does not verify.
   */
  constructor(url: string, snapshot: HostKeySet, fetchKeys?: FetchHostKeys) {
    this.#url = url;
    this.#snapshot = snapshot;
    this.#fetch = fetchKeys;
    this.#verifier = new CountersignatureRegistryVerifier(registryFromJwks(url, snapshot, KeyRole.HOST));
  }

  /** The key set the verifier holds now, for the Server Agent's own ledger. */
  get snapshot(): HostKeySet {
    return this.#snapshot;
  }

  async verify(hostKeyId: string, signature: string, payload: Uint8Array): Promise<boolean | 'unavailable'> {
    if (!this.#holds(hostKeyId) && this.#fetch !== undefined) {
      try {
        const fetched = await this.#fetch(this.#url);
        // A set with a non-conforming JWK is refused (§10.2), as a failed fetch is.
        this.#verifier = new CountersignatureRegistryVerifier(registryFromJwks(this.#url, fetched, KeyRole.HOST));
        this.#snapshot = fetched;
      } catch {
        return 'unavailable';
      }
    }
    return this.#verifier.verify(hostKeyId, signature, payload);
  }

  #holds(hostKeyId: string): boolean {
    return this.#snapshot.keys.some((jwk) => typeof jwk.kid === 'string' && keyIdOf(this.#url, jwk.kid) === hostKeyId);
  }
}
