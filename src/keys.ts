/** §10.2: JWKS-published keys as a-MCP key registries; a set's role comes from where it was named. */

import { type JwkSet, KeyRegistry, type KeyRole, publicKeyOf, ROLE_MEMBER } from 'auditable-mcp-sdk';

/**
 * Return a key's a-MCP identifier (`key_id` or `host_key_id`): the JWKS URL, `#`, and the JWK's `kid`.
 *
 * @throws {Error} The URL carries a fragment, so the first `#` would not separate URL from `kid` (§3.1, §7.1).
 */
export function keyIdOf(jwksUrl: string, kid: string): string {
  if (jwksUrl.includes('#')) {
    throw new Error(`a JWKS URL carries no fragment (§10.2): ${jwksUrl}`);
  }
  return `${jwksUrl}#${kid}`;
}

/**
 * Load the JWK Set fetched from `jwksUrl` into a registry of `role`, keyed by `keyIdOf(jwksUrl, kid)` (§10.2).
 *
 * @throws {Error} Any JWK is not conforming; the whole set is refused (a-MCP §5.1).
 */
export function registryFromJwks(jwksUrl: string, document: JwkSet, role: KeyRole): KeyRegistry {
  if (!Array.isArray(document?.keys)) {
    throw new Error('a JWK Set carries its keys under `keys` (RFC 7517)');
  }
  const seen = new Set<string>();
  const registry = new KeyRegistry(role);
  for (const jwk of document.keys) {
    if (typeof jwk !== 'object' || jwk === null || Array.isArray(jwk)) {
      throw new Error("every member of a JWK Set's `keys` is a JWK object (RFC 7517)");
    }
    if (typeof jwk.kid !== 'string' || jwk.kid === '') {
      throw new Error('every JWK carries a `kid` (§10.2)');
    }
    if (seen.has(jwk.kid)) {
      throw new Error(`kid "${jwk.kid}" appears twice in ${jwksUrl}; a kid is unique within its set (§10.2)`);
    }
    seen.add(jwk.kid);
    if (typeof jwk.alg !== 'string') {
      throw new Error(`the JWK "${jwk.kid}" carries no \`alg\` (§10.2)`);
    }
    // The role comes from where the set was named, not from the JWK.
    const entry = publicKeyOf({ ...jwk, kid: keyIdOf(jwksUrl, jwk.kid), [ROLE_MEMBER]: role });
    registry.register(entry.keyId, entry.publicKey, entry.algorithm);
    if (entry.revoked) {
      registry.revoke(entry.keyId);
    }
  }
  return registry;
}
