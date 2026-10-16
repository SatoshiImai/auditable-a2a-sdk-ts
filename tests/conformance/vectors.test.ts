import { auditEventSchema, canonicalize, sha256Hex } from 'auditable-mcp-sdk';
import { describe, expect, it } from 'vitest';
import { type ExecutionReportInput, executionReport } from '../../src/execution-report';
import { keyIdOf } from '../../src/keys';
import type { AgentCardParams, AuditRequest, SessionPosition } from '../../src/models';
import { negotiate } from '../../src/negotiate';
import { checkPosition, type HeldState } from '../../src/position';
import { loadVector } from '../vectors';

interface NegotiationVector {
  name: string;
  params: AgentCardParams;
  request: Pick<AuditRequest, 'level' | 'countersign'>;
  expected: unknown;
}

interface ExecutionReportVector {
  name: string;
  input: ExecutionReportInput;
  outcome: 'attempted' | 'success';
  event: unknown;
  canonical: string;
  sha256: string;
}

describe('negotiation (§4.3)', () => {
  for (const vector of loadVector<NegotiationVector[]>('negotiation.json')) {
    it(vector.name, () => {
      expect(negotiate(vector.params, vector.request)).toEqual(vector.expected);
    });
  }
});

describe('key ids (§10.2)', () => {
  for (const vector of loadVector<Array<{ jwks: string; kid: string; key_id: string }>>('key-id.json')) {
    it(vector.key_id, () => {
      expect(keyIdOf(vector.jwks, vector.kid)).toBe(vector.key_id);
    });
  }

  it('refuses a JWKS URL that carries a fragment', () => {
    expect(() => keyIdOf('https://agent.example.com/jwks.json#x', 'k1')).toThrow(/§10.2/);
  });
});

describe('execution reports (§8.6)', () => {
  for (const vector of loadVector<ExecutionReportVector[]>('execution-report.json')) {
    it(vector.name, () => {
      const event = executionReport(vector.input, vector.outcome);
      expect(event).toEqual(vector.event);
      expect(auditEventSchema.safeParse(event).success).toBe(true);
      expect(canonicalize(event)).toBe(vector.canonical);
      expect(sha256Hex(vector.canonical)).toBe(vector.sha256);
    });
  }
});

describe('the position check on resumption (§5.5)', () => {
  type Vector = { name: string; position: SessionPosition; held: HeldState; expected: unknown };
  for (const vector of loadVector<Vector[]>('position-check.json')) {
    it(vector.name, () => {
      expect(checkPosition(vector.position, vector.held)).toEqual(vector.expected);
    });
  }
});
