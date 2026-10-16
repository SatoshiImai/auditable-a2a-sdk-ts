/** The verifier (§11). */

import { Ed25519Signer, generateToolKey, KeyRole, publicJwk, SPEC_VERSION } from 'auditable-mcp-sdk';
import { describe, expect, it } from 'vitest';
import { A2aAuditHost, type IssuedAuthentication } from '../src/audit-host';
import { createAuditEndpointHandler } from '../src/endpoint-handler';
import { executionReport } from '../src/execution-report';
import { keyIdOf } from '../src/keys';
import { Countersign, Level } from '../src/models';
import { InMemorySessionStore, type SessionState } from '../src/session-store';
import { A2aFinding, verifyA2aLedger } from '../src/verify';

const TASK = 'task-1';
const AGENT_KEYS = 'https://agent.example/.well-known/jwks.json';

class Clock {
  #n = 0;
  now(): string {
    this.#n += 1;
    return new Date(Date.UTC(2026, 9, 15, 0, 0, this.#n)).toISOString();
  }
}

function id(n: number): string {
  return `0199a3e1-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;
}

function event(sessionId: string, n: number, outcome = 'attempted') {
  return {
    id: id(n),
    spec_version: SPEC_VERSION,
    ts: '2026-10-15T00:00:00.000Z',
    session_id: sessionId,
    action_type: 'db.read',
    mutates: false,
    egress: false,
    target_resource: { kind: 'table', ref: 'customers' },
    outcome,
  };
}

function report(sessionId: string, n: number, attemptId: string) {
  return executionReport(
    { id: id(n), ts: '2026-10-15T00:00:00.000Z', sessionId, attemptId, execution: 'not-performed' },
    'attempted',
  );
}

async function l1() {
  const host = A2aAuditHost.create('client-a', Level.L1, Countersign.NONE, {
    store: new InMemorySessionStore(),
    clock: new Clock(),
  });
  const { sessionId, authentication } = await host.openSession({
    delegate: 'https://agent.example',
    expiresAt: '2026-11-15T00:00:00Z',
  });
  const handler = createAuditEndpointHandler(host);
  const send = async (body: unknown, auth: IssuedAuthentication = authentication) => {
    const response = await handler(
      new Request('https://audit.example/a2a', {
        method: 'POST',
        headers: { authorization: `${auth.scheme} ${auth.credentials}` },
        body: JSON.stringify(body),
      }),
    );
    return response.status;
  };
  return { host, sessionId, send };
}

function evidence(host: A2aAuditHost, sessionId: string): SessionState {
  return host.session(sessionId) as SessionState;
}

describe('a clean session', () => {
  it('verifies complete once it has ended', async () => {
    const { host, sessionId, send } = await l1();
    await send({ taskId: TASK, event: event(sessionId, 1) });
    await send({ taskId: TASK, event: event(sessionId, 1, 'success') });
    await send({ taskId: TASK, close: true });
    const result = verifyA2aLedger(host.records(), [evidence(host, sessionId)], { anchoredDigest: host.digest() });
    expect(result.findings).toEqual([]);
    expect(result.complete).toBe(true);
  });

  it('reports the end it could not check while the session is open (§11 Inputs)', async () => {
    const { host, sessionId, send } = await l1();
    await send({ taskId: TASK, event: event(sessionId, 1) });
    const result = verifyA2aLedger(host.records(), [evidence(host, sessionId)]);
    expect(result.unchecked).toEqual([`end of session ${sessionId}: not recorded`]);
    expect(result.complete).toBe(false);
  });
});

describe('check 2: after the end (§11)', () => {
  it('lists a record sealed after a close, to be read against its reason (§13.7)', async () => {
    const { host, sessionId, send } = await l1();
    await send({ taskId: TASK, event: event(sessionId, 1) });
    await send({ taskId: TASK, close: true });
    await send({ taskId: TASK, event: event(sessionId, 1, 'success') });
    const result = verifyA2aLedger(host.records(), [evidence(host, sessionId)]);
    expect(result.findings).toEqual([]);
    expect(result.recordsAfterClose).toEqual([{ sessionId, seq: 1, id: host.records()[1]?.event.id }]);
    expect(result.complete).toBe(true);
  });

  it('finds an attempt sealed after the end the evidence records', async () => {
    const { host, sessionId, send } = await l1();
    await send({ taskId: TASK, event: event(sessionId, 1) });
    await send({ taskId: TASK, event: event(sessionId, 2) });
    const state = evidence(host, sessionId);
    const ended = { ...state, end: { cause: 'client-notice' as const, at: '2026-10-15T00:00:01Z', lastSeq: 0 } };
    const result = verifyA2aLedger(host.records(), [ended]);
    expect(result.findings.map((finding) => [finding.code, finding.tier1, finding.seq])).toEqual([
      [A2aFinding.ATTEMPT_AFTER_END, 'replay-detected', 1],
    ]);
  });
});

describe('check 3: execution reports (§8.6, §11)', () => {
  it('finds a report naming no accepted attempt, and a second report on one attempt', async () => {
    const { host, sessionId, send } = await l1();
    await send({ taskId: TASK, event: event(sessionId, 1) });
    await send({ taskId: TASK, event: report(sessionId, 2, id(99)) });
    await send({ taskId: TASK, event: report(sessionId, 3, id(1)) });
    await send({ taskId: TASK, event: report(sessionId, 4, id(1)) });
    await send({ taskId: TASK, close: true });
    const result = verifyA2aLedger(host.records(), [evidence(host, sessionId)]);
    expect(result.findings.map((finding) => [finding.code, finding.tier1, finding.id])).toEqual([
      [A2aFinding.REPORT_UNMATCHED, 'orphaned-outcome', id(2)],
      [A2aFinding.REPORT_DUPLICATED, 'replay-detected', id(4)],
    ]);
  });
});

describe('check 4: resolved after the end (§5.4, §11)', () => {
  it('reads an unresolved attempt resolved by a late outcome or report as resolved', async () => {
    const { host, sessionId, send } = await l1();
    await send({ taskId: TASK, event: event(sessionId, 1) });
    await send({ taskId: TASK, event: event(sessionId, 2) });
    await host.endSession(sessionId);
    await send({ taskId: TASK, event: event(sessionId, 1, 'success') });
    await send({ taskId: TASK, event: report(sessionId, 3, id(2)) });
    const result = verifyA2aLedger(host.records(), [evidence(host, sessionId)]);
    expect(result.resolvedAfterEnd.sort()).toEqual([id(1), id(2)]);
    expect(result.findings).toEqual([]);
  });
});

describe('check 1: one key per session (§5.1, §11)', () => {
  it('verifies signatures against the snapshot, and finds a record under another key than the bound one', async () => {
    const key = generateToolKey(keyIdOf(AGENT_KEYS, 'a1'));
    const { amcp_role: _role, ...jwk } = publicJwk('a1', key.publicKey, 'Ed25519', KeyRole.TOOL);
    const host = A2aAuditHost.create('client-a', Level.L2, Countersign.NONE, {
      store: new InMemorySessionStore(),
      clock: new Clock(),
    });
    const opened = await host.openSession({
      delegate: 'https://agent.example',
      expiresAt: '2026-11-15T00:00:00Z',
      attestationKeys: AGENT_KEYS,
      keySnapshot: { keys: [jwk] },
    });
    const handler = createAuditEndpointHandler(host);
    const signer = Ed25519Signer.fromToolKey(key);
    await handler(
      new Request('https://audit.example/a2a', {
        method: 'POST',
        headers: { authorization: `${opened.authentication.scheme} ${opened.authentication.credentials}` },
        body: JSON.stringify({ taskId: TASK, event: await signer.sign(event(opened.sessionId, 1), 0) }),
      }),
    );
    await host.endSession(opened.sessionId);
    const state = evidence(host, opened.sessionId);
    expect(verifyA2aLedger(host.records(), [state]).amcp.unchecked).toEqual([]);
    const tampered = { ...state, boundKeyId: keyIdOf(AGENT_KEYS, 'other') };
    expect(verifyA2aLedger(host.records(), [tampered]).findings.map((finding) => finding.code)).toEqual([
      'signature-invalid',
    ]);
    const noSnapshot = { ...state, keySnapshot: undefined };
    expect(verifyA2aLedger(host.records(), [noSnapshot]).unchecked).toContain(
      `signatures of session ${opened.sessionId}: no key snapshot`,
    );
  });
});

describe('the version a session was opened for (§4.1, §11 Inputs)', () => {
  it('reports a session of another version, or of none recorded, as not checked', async () => {
    const { host, sessionId, send } = await l1();
    await send({ taskId: TASK, event: event(sessionId, 1) });
    await send({ taskId: TASK, close: true });
    const state = evidence(host, sessionId);
    const later = { ...state, version: 'https://timberlandchapel.com/a2a/extensions/auditable-a2a/0.2' };
    const result = verifyA2aLedger(host.records(), [later]);
    expect(result.unchecked).toEqual([`session ${sessionId}: version ${later.version} is not implemented`]);
    expect(result.amcp.issues).toEqual([]);
    expect(result.complete).toBe(false);
    const { version: _version, ...unversioned } = state;
    expect(verifyA2aLedger(host.records(), [unversioned]).unchecked).toEqual([
      `version of session ${sessionId}: not recorded`,
    ]);
  });
});

describe('an execution report that names an execution report (§8.6)', () => {
  it('is unmatched', async () => {
    const { host, sessionId, send } = await l1();
    await send({ taskId: TASK, event: event(sessionId, 1) });
    const report = (n: number, attemptId: string) =>
      executionReport(
        { id: id(n), ts: '2026-10-15T00:00:00.000Z', sessionId, attemptId, execution: 'not-performed' },
        'attempted',
      );
    await send({ taskId: TASK, event: report(2, id(1)) });
    await send({ taskId: TASK, event: report(3, id(2)) });
    const result = verifyA2aLedger(host.records(), [evidence(host, sessionId)]);
    expect(result.findings.map((finding) => [finding.code, finding.id])).toEqual([
      [A2aFinding.REPORT_UNMATCHED, id(3)],
    ]);
  });
});

describe('a key snapshot that is not a conforming key set (§11 Inputs)', () => {
  it("leaves the session's signatures unchecked rather than throw", async () => {
    const { host, sessionId, send } = await l1();
    await send({ taskId: TASK, event: event(sessionId, 1) });
    await send({ taskId: TASK, close: true });
    const broken = {
      ...evidence(host, sessionId),
      level: Level.L2,
      attestationKeys: 'https://agent.example/.well-known/jwks.json',
      keySnapshot: { keys: [{ kty: 'OKP' }] },
    };
    expect(verifyA2aLedger(host.records(), [broken]).unchecked).toContain(
      `signatures of session ${sessionId}: the key snapshot is not a conforming key set`,
    );
  });
});

describe('an execution report the Server Agent aborted (§8.6)', () => {
  it('is not counted, so the report that follows it is not a duplicate', async () => {
    const { host, sessionId, send } = await l1();
    await send({ taskId: TASK, event: event(sessionId, 1) });
    await send({ taskId: TASK, event: report(sessionId, 2, id(1)) });
    await send({
      taskId: TASK,
      event: { ...report(sessionId, 2, id(1)), outcome: 'aborted', reason: 'host-signature-invalid' },
    });
    await send({ taskId: TASK, event: report(sessionId, 3, id(1)) });
    await send({ taskId: TASK, event: { ...report(sessionId, 3, id(1)), outcome: 'success' } });
    await send({ taskId: TASK, close: true });
    expect(verifyA2aLedger(host.records(), [evidence(host, sessionId)]).findings).toEqual([]);
  });
});

describe('a report that names the type without its shape (§8.6, §11 check 3)', () => {
  it('is unmatched', async () => {
    const { host, sessionId, send } = await l1();
    await send({ taskId: TASK, event: event(sessionId, 1) });
    await send({ taskId: TASK, event: { ...report(sessionId, 2, id(1)), egress: true } });
    const result = verifyA2aLedger(host.records(), [evidence(host, sessionId)]);
    expect(result.findings.map((finding) => [finding.code, finding.id])).toEqual([
      [A2aFinding.REPORT_UNMATCHED, id(2)],
    ]);
  });
});
