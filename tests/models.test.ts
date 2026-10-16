/** The schemas' patterns: RFC 3339 timestamps (§7) and `Authorization` credentials (§6.1). */

import { describe, expect, it } from 'vitest';
import { auditRequestSchema, authenticationInfoSchema } from '../src/models';

const REQUEST = {
  auditEndpoint: { url: 'https://audit.example/a2a', authentication: { scheme: 'Bearer', credentials: 'abc' } },
  sessionId: '0199a3e1-0000-7000-8000-000000000001',
  level: 'L1',
  countersign: 'none',
  expiresAt: '2026-11-15T00:00:00Z',
};

describe('expiresAt (§7.1)', () => {
  it('requires seconds, as RFC 3339 does', () => {
    expect(auditRequestSchema.safeParse(REQUEST).success).toBe(true);
    expect(auditRequestSchema.safeParse({ ...REQUEST, expiresAt: '2026-11-15T00:00Z' }).success).toBe(false);
  });
});

describe('the endpoint credentials (§6.1)', () => {
  it('take a token for the scheme and visible ASCII for the credentials', () => {
    expect(authenticationInfoSchema.safeParse({ scheme: 'Bearer', credentials: 'a b' }).success).toBe(true);
    expect(authenticationInfoSchema.safeParse({ scheme: 'Bear er', credentials: 'abc' }).success).toBe(false);
    expect(authenticationInfoSchema.safeParse({ scheme: 'Bearer', credentials: 'ä' }).success).toBe(false);
    expect(authenticationInfoSchema.safeParse({ scheme: 'Bearer', credentials: ' abc' }).success).toBe(false);
  });
});
