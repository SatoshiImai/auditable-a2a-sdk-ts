/**
 * The Zod models and the vendored JSON Schemas agree on every mutation of each valid sample (a field dropped,
 * replaced by a wrong value, or added).
 */

import { Ajv2020 } from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';
import type { z } from 'zod';
import {
  agentCardParamsSchema,
  auditCredentialsSchema,
  auditRequestSchema,
  auditSessionSchema,
  auditStatusSchema,
  auditSubmissionSchema,
  sessionPositionSchema,
} from '../../src/models';
import { loadSchema } from '../vectors';

const SESSION = '0199a3e0-7c1f-7a4e-9b1d-5f2f7e0c4a11';
const WRONG: unknown[] = [
  '',
  'X',
  'http://a.example',
  'https://a.example',
  'https://a.example/k#f',
  'a\r\nb',
  'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA',
  '00000000-0000-0000-0000-000000000000',
  '2026-02-30T00:00:00Z',
  '2026-10-15T00:00:00+09:00',
  -1,
  99,
  600,
  1.5,
  0,
  true,
  false,
  null,
  {},
  [],
  'L1',
  'L2',
  'host',
  'none',
  'host-unavailable',
  'unknown-key',
];

function mutations(base: Record<string, unknown>): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [base, { ...base, extra: 1 }];
  for (const key of Object.keys(base)) {
    const { [key]: _dropped, ...rest } = base;
    out.push(rest);
    for (const value of WRONG) {
      out.push({ ...base, [key]: value });
    }
  }
  return out;
}

const endpoint = { url: 'https://a.example', authentication: { scheme: 'Bearer', credentials: 'c' }, token: 't' };
const request = {
  auditEndpoint: endpoint,
  sessionId: SESSION,
  level: 'L2',
  countersign: 'host',
  hostKeys: 'https://a.example/k',
  expiresAt: '2026-11-15T00:00:00Z',
};
const last = {
  seq: 1,
  host_ts: '2026-10-15T00:00:00Z',
  previous_hash: '0'.repeat(64),
  record_hash: '1'.repeat(64),
  log_id: 'l',
  host_signature: 'c2ln',
  host_key_id: 'h',
};

const CASES: Array<[string, z.ZodType, Record<string, unknown>[]]> = [
  [
    'agent-card-params.schema.json',
    agentCardParamsSchema,
    mutations({ level: 'L2', countersign: 'host', selfChain: true, attestationKeys: 'https://a.example/j' }),
  ],
  [
    'audit-request.schema.json',
    auditRequestSchema,
    [...mutations(request), ...mutations(endpoint).map((auditEndpoint) => ({ ...request, auditEndpoint }))],
  ],
  [
    'audit-session.schema.json',
    auditSessionSchema,
    mutations({ sessionId: SESSION, level: 'L1', countersign: 'none' }),
  ],
  [
    'audit-status.schema.json',
    auditStatusSchema,
    mutations({ reason: 'host-rejected', hostReason: 'unknown-key', httpStatus: 401, attemptId: SESSION }),
  ],
  [
    'audit-credentials.schema.json',
    auditCredentialsSchema,
    mutations({ authentication: { scheme: 'Bearer', credentials: 'c' }, token: 't' }),
  ],
  [
    'audit-submission.schema.json',
    auditSubmissionSchema,
    [
      ...mutations({ taskId: 't', token: 'x', event: {} }),
      ...mutations({ taskId: 't', position: true }),
      ...mutations({ taskId: 't', close: true }),
    ],
  ],
  [
    'session-position.schema.json',
    sessionPositionSchema,
    [...mutations({ last }), ...mutations(last).map((position) => ({ last: position })), { last: null }],
  ],
];

const ajv = new Ajv2020({ strict: false, allErrors: true, logger: false });

describe('the Zod models agree with the vendored JSON Schemas', () => {
  for (const [file, schema, samples] of CASES) {
    it(file, () => {
      const validate = ajv.compile(loadSchema(file));
      const disagreements = samples.filter((sample) => schema.safeParse(sample).success !== validate(sample));
      expect(disagreements).toEqual([]);
    });
  }
});
