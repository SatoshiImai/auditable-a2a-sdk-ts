/** The audit host and its HTTP endpoint (§5, §6). */

import {
  Ed25519Signer,
  generateToolKey,
  InMemoryLedgerRepository,
  KeyRole,
  publicJwk,
  RepositoryError,
  SPEC_VERSION,
} from 'auditable-mcp-sdk';
import { describe, expect, it } from 'vitest';
import { A2aAuditHost, type IssuedAuthentication } from '../src/audit-host';
import { createAuditEndpointHandler } from '../src/endpoint-handler';
import { executionReport } from '../src/execution-report';
import { keyIdOf } from '../src/keys';
import { Countersign, EXTENSION_URI, Level } from '../src/models';
import { InMemorySessionStore } from '../src/session-store';

const ENDPOINT = 'https://audit.client.example/a2a';
const JWKS_URL = 'https://agent.example/.well-known/jwks.json';
const TASK = 'task-1';

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

function event(sessionId: string, n: number, outcome = 'attempted', extra: Record<string, unknown> = {}) {
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
    ...extra,
  };
}

async function post(
  handler: (request: Request) => Promise<Response>,
  authentication: IssuedAuthentication,
  body: unknown,
): Promise<{ status: number; body: unknown }> {
  const response = await handler(
    new Request(ENDPOINT, {
      method: 'POST',
      headers: {
        authorization: `${authentication.scheme} ${authentication.credentials}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(body),
    }),
  );
  const text = await response.text();
  return { status: response.status, body: text === '' ? undefined : JSON.parse(text) };
}

async function l1(expiresAt = '2026-11-15T00:00:00Z') {
  const store = new InMemorySessionStore();
  const repository = new InMemoryLedgerRepository();
  const host = A2aAuditHost.create('client-a', Level.L1, Countersign.NONE, { store, repository, clock: new Clock() });
  const { sessionId, authentication } = await host.openSession({ delegate: 'https://agent.example', expiresAt });
  return { host, store, repository, sessionId, authentication, handler: createAuditEndpointHandler(host) };
}

describe('one session from first attempt to close (§5, §6)', () => {
  it('binds the Task, seals, answers the position, and refuses attempts after the close', async () => {
    const { host, sessionId, authentication, handler } = await l1();
    const attempt = await post(handler, authentication, { taskId: TASK, event: event(sessionId, 1) });
    expect(attempt.status).toBe(200);
    expect((attempt.body as { status: string }).status).toBe('accept');
    expect(host.session(sessionId)?.boundTaskId).toBe(TASK);

    const outcome = await post(handler, authentication, { taskId: TASK, event: event(sessionId, 1, 'success') });
    expect(outcome.status).toBe(204);

    const position = await post(handler, authentication, { taskId: TASK, position: true });
    expect(position.status).toBe(200);
    expect((position.body as { last: { seq: number } }).last.seq).toBe(1);

    expect((await post(handler, authentication, { taskId: TASK, close: true })).status).toBe(204);
    const after = await post(handler, authentication, { taskId: TASK, event: event(sessionId, 2) });
    expect(after.body).toEqual({ status: 'reject', reason: 'replay-detected' });
    expect(host.session(sessionId)?.end?.cause).toBe('close');
  });

  it('answers a byte-identical resend from the ledger, even after the end (§6.6)', async () => {
    const { authentication, sessionId, handler, host } = await l1();
    const first = await post(handler, authentication, { taskId: TASK, event: event(sessionId, 1) });
    await host.endSession(sessionId);
    const again = await post(handler, authentication, { taskId: TASK, event: event(sessionId, 1) });
    expect(again.body).toEqual(first.body);
  });
});

describe('the position of a session with no record (§6.5)', () => {
  it('is null', async () => {
    const { authentication, handler } = await l1();
    expect(await post(handler, authentication, { taskId: TASK, position: true })).toEqual({
      status: 200,
      body: { last: null },
    });
  });
});

describe('after the session ends (§5.4)', () => {
  it('seals an outcome owed and admits an execution report, and records the unresolved attempt', async () => {
    const { host, sessionId, authentication, handler } = await l1();
    await post(handler, authentication, { taskId: TASK, event: event(sessionId, 1) });
    await post(handler, authentication, { taskId: TASK, event: event(sessionId, 2) });
    await host.endSession(sessionId);
    expect(host.anomalies().map((anomaly) => anomaly.kind)).toEqual(['unresolved-attempt', 'unresolved-attempt']);

    expect((await post(handler, authentication, { taskId: TASK, event: event(sessionId, 1, 'success') })).status).toBe(
      204,
    );
    const report = executionReport(
      { id: id(3), ts: '2026-10-15T00:00:00.000Z', sessionId, attemptId: id(2), execution: 'not-performed' },
      'attempted',
    );
    const admitted = await post(handler, authentication, { taskId: TASK, event: report });
    expect((admitted.body as { status: string }).status).toBe('accept');
    expect(host.records().filter((record) => record.event.session_id === sessionId)).toHaveLength(4);
  });

  it('ends at expiresAt and refuses the next attempt', async () => {
    const { host, sessionId, authentication, handler } = await l1('2026-10-15T00:00:01Z');
    const late = await post(handler, authentication, { taskId: TASK, event: event(sessionId, 1) });
    expect(late.body).toEqual({ status: 'reject', reason: 'replay-detected' });
    expect(host.session(sessionId)?.end?.cause).toBe('expiry');
  });
});

describe('the session check (§6.6)', () => {
  it('refuses another Task on a bound session, by submission kind', async () => {
    const { host, sessionId, authentication, handler } = await l1();
    await post(handler, authentication, { taskId: TASK, event: event(sessionId, 1) });
    const other = 'task-2';
    expect((await post(handler, authentication, { taskId: other, event: event(sessionId, 2) })).body).toEqual({
      status: 'reject',
      reason: 'replay-detected',
    });
    expect((await post(handler, authentication, { taskId: other, event: event(sessionId, 1, 'success') })).status).toBe(
      204,
    );
    expect(host.anomalies().map((anomaly) => anomaly.kind)).toEqual(['replay-detected']);
    expect((await post(handler, authentication, { taskId: other, position: true })).status).toBe(403);
    expect((await post(handler, authentication, { taskId: other, close: true })).status).toBe(403);
  });

  it('answers 401 to credentials it did not issue', async () => {
    const { sessionId, handler } = await l1();
    const forged = { scheme: 'Bearer', credentials: 'not-issued' };
    expect((await post(handler, forged, { taskId: TASK, event: event(sessionId, 1) })).status).toBe(401);
  });

  it('answers 400 to a body that is not a submission, and 405 to another method', async () => {
    const { authentication, handler } = await l1();
    expect((await post(handler, authentication, { taskId: TASK, position: true, close: true })).status).toBe(400);
    expect((await handler(new Request(ENDPOINT, { method: 'GET' }))).status).toBe(405);
  });
});

describe('credentials over a long Task (§5.7)', () => {
  it('retires the old credential for attempts once the new one is used, but keeps it for records owed', async () => {
    const { host, sessionId, authentication, handler } = await l1();
    await post(handler, authentication, { taskId: TASK, event: event(sessionId, 1) });
    const renewed = await host.issueCredentials(sessionId);
    expect((await post(handler, renewed, { taskId: TASK, event: event(sessionId, 2) })).status).toBe(200);
    expect((await post(handler, authentication, { taskId: TASK, event: event(sessionId, 3) })).status).toBe(401);
    expect((await post(handler, authentication, { taskId: TASK, event: event(sessionId, 1, 'success') })).status).toBe(
      204,
    );
  });
});

describe('a refused outcome is acknowledged only once recorded (§6.3)', () => {
  it('answers 503 when the outcome could not be recorded', async () => {
    const repository = new InMemoryLedgerRepository();
    repository.append = async () => {
      throw new RepositoryError('storage down');
    };
    const failing = A2aAuditHost.create('client-b', Level.L1, Countersign.NONE, {
      store: new InMemorySessionStore(),
      repository,
      clock: new Clock(),
    });
    const opened = await failing.openSession({ delegate: 'https://agent.example', expiresAt: '2026-11-15T00:00:00Z' });
    const failingHandler = createAuditEndpointHandler(failing);
    const answer = await post(failingHandler, opened.authentication, {
      taskId: TASK,
      event: event(opened.sessionId, 1, 'aborted', { reason: 'host-unavailable' }),
    });
    expect(answer.status).toBe(503);
  });
});

describe('Level 2 (§5.1, §10.2)', () => {
  async function l2() {
    const toolKey = generateToolKey(keyIdOf(JWKS_URL, 'k1'));
    const otherKey = generateToolKey(keyIdOf(JWKS_URL, 'k2'));
    const jwk = (key: typeof toolKey, kid: string) => {
      const { amcp_role: _role, ...published } = publicJwk(kid, key.publicKey, 'Ed25519', KeyRole.TOOL);
      return published;
    };
    const host = A2aAuditHost.create('client-a', Level.L2, Countersign.NONE, {
      store: new InMemorySessionStore(),
      clock: new Clock(),
    });
    const opened = await host.openSession({
      delegate: 'https://agent.example',
      expiresAt: '2026-11-15T00:00:00Z',
      attestationKeys: JWKS_URL,
      keySnapshot: { keys: [jwk(toolKey, 'k1'), jwk(otherKey, 'k2')] },
    });
    return {
      host,
      ...opened,
      handler: createAuditEndpointHandler(host),
      signer: Ed25519Signer.fromToolKey(toolKey),
      other: Ed25519Signer.fromToolKey(otherKey),
    };
  }

  it('verifies against the snapshot and binds the first key', async () => {
    const { host, sessionId, authentication, handler, signer, other } = await l2();
    const first = await post(handler, authentication, {
      taskId: TASK,
      event: await signer.sign(event(sessionId, 1), 0),
    });
    expect((first.body as { status: string }).status).toBe('accept');
    expect(host.session(sessionId)?.boundKeyId).toBe(keyIdOf(JWKS_URL, 'k1'));
    const switched = await post(handler, authentication, {
      taskId: TASK,
      event: await other.sign(event(sessionId, 2), 0),
    });
    expect(switched.body).toEqual({ status: 'reject', reason: 'unknown-key' });
  });

  it('refuses a JWKS whose key carries no alg', async () => {
    const host = A2aAuditHost.create('client-a', Level.L2, Countersign.NONE, { store: new InMemorySessionStore() });
    const key = generateToolKey('k1');
    const { alg: _alg, amcp_role: _role, ...noAlg } = publicJwk('k1', key.publicKey, 'Ed25519', KeyRole.TOOL);
    await expect(
      host.openSession({
        delegate: 'https://agent.example',
        expiresAt: '2026-11-15T00:00:00Z',
        attestationKeys: JWKS_URL,
        keySnapshot: { keys: [noAlg] },
      }),
    ).rejects.toThrow(/alg/);
  });
});

describe('a restart of the audit host (§5.6)', () => {
  it('keeps every session open, seals outcomes owed, and keeps an ended session ended', async () => {
    const { host, store, repository, sessionId, authentication, handler } = await l1();
    await post(handler, authentication, { taskId: TASK, event: event(sessionId, 1) });
    const second = await host.openSession({ delegate: 'https://agent.example', expiresAt: '2026-11-15T00:00:00Z' });
    await host.endSession(second.sessionId);

    const resumed = await A2aAuditHost.resume('client-a', Level.L1, Countersign.NONE, {
      store,
      repository,
      clock: new Clock(),
    });
    const resumedHandler = createAuditEndpointHandler(resumed);
    expect(
      (await post(resumedHandler, authentication, { taskId: TASK, event: event(sessionId, 1, 'success') })).status,
    ).toBe(204);
    expect(
      (
        (await post(resumedHandler, authentication, { taskId: TASK, event: event(sessionId, 2) })).body as {
          status: string;
        }
      ).status,
    ).toBe('accept');
    expect(resumed.session(second.sessionId)?.end?.cause).toBe('client-notice');
    const ended = await post(resumedHandler, second.authentication, {
      taskId: TASK,
      event: event(second.sessionId, 9),
    });
    expect(ended.body).toEqual({ status: 'reject', reason: 'replay-detected' });
  });
});

describe('after a restart, the records sealed before it (§5.6)', () => {
  it('answer the position, are resolved at the end, and admit a report after it', async () => {
    const { store, repository, sessionId, authentication, handler } = await l1();
    const first = await post(handler, authentication, { taskId: TASK, event: event(sessionId, 1) });
    const accepted = first.body as { seq: number; record_hash: string };

    const resumed = await A2aAuditHost.resume('client-a', Level.L1, Countersign.NONE, {
      store,
      repository,
      clock: new Clock(),
    });
    const after = createAuditEndpointHandler(resumed);
    const position = await post(after, authentication, { taskId: TASK, position: true });
    expect(position.body).toMatchObject({ last: { seq: accepted.seq, record_hash: accepted.record_hash } });

    await resumed.endSession(sessionId);
    expect(resumed.session(sessionId)?.anomalies.map((a) => [a.kind, a.id])).toEqual([['unresolved-attempt', id(1)]]);
    expect(resumed.session(sessionId)?.end?.lastSeq).toBe(accepted.seq);
    const report = executionReport(
      { id: id(2), ts: '2026-10-15T00:00:00.000Z', sessionId, attemptId: id(1), execution: 'not-performed' },
      'attempted',
    );
    expect(
      ((await post(after, authentication, { taskId: TASK, event: report })).body as { status: string }).status,
    ).toBe('accept');
  });
});

describe('the version a session is opened for (§4.1, §5.1)', () => {
  it('is recorded, and a version this host does not implement is refused', async () => {
    const { host, sessionId } = await l1();
    expect(host.session(sessionId)?.version).toBe(EXTENSION_URI);
    await expect(
      host.openSession({
        version: 'https://timberlandchapel.com/a2a/extensions/auditable-a2a/0.2',
        delegate: 'https://agent.example',
        expiresAt: '2026-11-15T00:00:00Z',
      }),
    ).rejects.toThrow(/0\.2/);
  });
});

describe('expiry and purge (§5.3, §5.4)', () => {
  it('ends an expired session at its expiry, on a sweep', async () => {
    const { host, sessionId } = await l1('2026-10-15T00:00:00Z');
    expect(await host.sweep()).toEqual([sessionId]);
    expect(host.session(sessionId)?.end).toMatchObject({ cause: 'expiry', at: '2026-10-15T00:00:00Z' });
    expect(await host.sweep()).toEqual([]);
  });

  it('purges only an ended session, after which its credentials are not recognised', async () => {
    const { host, store, sessionId, authentication, handler } = await l1();
    await expect(host.purge(sessionId)).rejects.toThrow(/not ended/);
    await host.endSession(sessionId);
    await host.purge(sessionId);
    expect(host.session(sessionId)).toBeUndefined();
    expect(await store.all()).toEqual([]);
    expect((await post(handler, authentication, { taskId: TASK, position: true })).status).toBe(401);
  });
});

describe('a session store that fails (§5.1, §5.6)', () => {
  it('leaves the session unbound, and the attempt unrecorded', async () => {
    const store = new InMemorySessionStore();
    let failing = false;
    const flaky = {
      put: async (state: Parameters<typeof store.put>[0]) => {
        if (failing) throw new Error('store down');
        await store.put(state);
      },
      all: () => store.all(),
      delete: (sessionId: string) => store.delete(sessionId),
    };
    const host = A2aAuditHost.create('client-a', Level.L1, Countersign.NONE, { store: flaky, clock: new Clock() });
    const { sessionId, authentication } = await host.openSession({
      delegate: 'https://agent.example',
      expiresAt: '2026-11-15T00:00:00Z',
    });
    const handler = createAuditEndpointHandler(host);
    failing = true;
    const refused = await post(handler, authentication, { taskId: TASK, event: event(sessionId, 1) });
    expect(refused.body).toMatchObject({ status: 'unavailable' });
    expect(host.session(sessionId)?.boundTaskId).toBeUndefined();
    expect(host.records()).toEqual([]);
    failing = false;
    const accepted = await post(handler, authentication, { taskId: TASK, event: event(sessionId, 1) });
    expect(accepted.body).toMatchObject({ status: 'accept' });
    expect(host.session(sessionId)?.boundTaskId).toBe(TASK);
  });
});

describe('a signer_seq decided by a refusal, across a restart (§5.6)', () => {
  it('is refused again after the audit host restarts', async () => {
    const toolKey = generateToolKey(keyIdOf(JWKS_URL, 'k1'));
    const { amcp_role: _role, ...jwk } = publicJwk('k1', toolKey.publicKey, 'Ed25519', KeyRole.TOOL);
    const store = new InMemorySessionStore();
    const repository = new InMemoryLedgerRepository();
    const host = A2aAuditHost.create('client-a', Level.L2, Countersign.NONE, { store, repository, clock: new Clock() });
    const { sessionId, authentication } = await host.openSession({
      delegate: 'https://agent.example',
      expiresAt: '2026-11-15T00:00:00Z',
      attestationKeys: JWKS_URL,
      keySnapshot: { keys: [jwk] },
    });
    const signer = Ed25519Signer.fromToolKey(toolKey);
    const handler = createAuditEndpointHandler(host);
    await post(handler, authentication, { taskId: TASK, event: await signer.sign(event(sessionId, 1), 0) });
    const refused = await post(handler, authentication, {
      taskId: TASK,
      event: await signer.sign(event(sessionId, 1, 'attempted', { action_type: 'db.write' }), 1),
    });
    expect(refused.body).toEqual({ status: 'reject', reason: 'replay-detected' });

    const resumed = await A2aAuditHost.resume('client-a', Level.L2, Countersign.NONE, {
      store,
      repository,
      clock: new Clock(),
    });
    const again = await post(createAuditEndpointHandler(resumed), authentication, {
      taskId: TASK,
      event: await signer.sign(event(sessionId, 2), 1),
    });
    expect(again.body).toEqual({ status: 'reject', reason: 'replay-detected' });
  });
});

describe('an anomaly the session store could not keep (§6.3)', () => {
  it("goes with the session's next stored change", async () => {
    const toolKey = generateToolKey(keyIdOf(JWKS_URL, 'k1'));
    const { amcp_role: _role, ...jwk } = publicJwk('k1', toolKey.publicKey, 'Ed25519', KeyRole.TOOL);
    const store = new InMemorySessionStore();
    let failing = false;
    const flaky = {
      put: async (state: Parameters<typeof store.put>[0]) => {
        if (failing) throw new Error('store down');
        await store.put(state);
      },
      all: () => store.all(),
      delete: (sessionId: string) => store.delete(sessionId),
    };
    const host = A2aAuditHost.create('client-a', Level.L2, Countersign.NONE, { store: flaky, clock: new Clock() });
    const { sessionId, authentication } = await host.openSession({
      delegate: 'https://agent.example',
      expiresAt: '2026-11-15T00:00:00Z',
      attestationKeys: JWKS_URL,
      keySnapshot: { keys: [jwk] },
    });
    const signer = Ed25519Signer.fromToolKey(toolKey);
    const handler = createAuditEndpointHandler(host);
    await post(handler, authentication, { taskId: TASK, event: await signer.sign(event(sessionId, 1), 0) });
    // Under Level 2 the resend is a signer_seq replay, so only the first answer records it.
    const orphan = await signer.sign(event(sessionId, 7, 'success'), 1);
    failing = true;
    expect((await post(handler, authentication, { taskId: TASK, event: orphan })).status).toBe(503);
    failing = false;
    await post(handler, authentication, { taskId: TASK, event: orphan });
    expect(host.session(sessionId)?.anomalies.map((a) => [a.kind, a.id])).toContainEqual(['orphaned-outcome', id(7)]);
  });
});

describe('a token the audit host did not issue (§6.6)', () => {
  it('is answered 401', async () => {
    const { sessionId, authentication, handler } = await l1();
    const answer = await post(handler, authentication, { taskId: TASK, token: 'guess', event: event(sessionId, 1) });
    expect(answer.status).toBe(401);
  });
});

describe('the answers that carry more than a status (§6.6, §5.4)', () => {
  it('names the scheme in WWW-Authenticate on a 401', async () => {
    const { sessionId, handler } = await l1();
    const response = await handler(
      new Request(ENDPOINT, {
        method: 'POST',
        headers: { authorization: 'Bearer not-issued', 'content-type': 'application/json' },
        body: JSON.stringify({ taskId: TASK, event: event(sessionId, 1) }),
      }),
    );
    expect(response.status).toBe(401);
    expect(response.headers.get('www-authenticate')).toBe('Bearer');
  });

  it('admits a retired credential for the resend of an attempt it sealed', async () => {
    const { host, sessionId, authentication, handler } = await l1();
    const first = await post(handler, authentication, { taskId: TASK, event: event(sessionId, 1) });
    const newer = await host.issueCredentials(sessionId);
    await post(handler, newer, { taskId: TASK, position: true });
    expect((await post(handler, authentication, { taskId: TASK, event: event(sessionId, 2) })).status).toBe(401);
    expect(await post(handler, authentication, { taskId: TASK, event: event(sessionId, 1) })).toEqual(first);
    expect((await post(handler, authentication, { taskId: TASK, position: true })).status).toBe(200);
  });
});

describe('a credential a newer one replaced (§5.4, §5.7)', () => {
  it('admits only the records of attempts sealed while it was the newest', async () => {
    const { host, sessionId, authentication, handler } = await l1();
    await post(handler, authentication, { taskId: TASK, event: event(sessionId, 1) });
    const newer = await host.issueCredentials(sessionId);
    await post(handler, newer, { taskId: TASK, event: event(sessionId, 2) });
    expect((await post(handler, authentication, { taskId: TASK, event: event(sessionId, 1, 'success') })).status).toBe(
      204,
    );
    expect((await post(handler, authentication, { taskId: TASK, event: event(sessionId, 2, 'success') })).status).toBe(
      401,
    );
    const reportOn = (n: number, attemptId: string) =>
      executionReport(
        { id: id(n), ts: '2026-10-15T00:00:00.000Z', sessionId, attemptId, execution: 'not-performed' },
        'attempted',
      );
    expect((await post(handler, authentication, { taskId: TASK, event: reportOn(3, id(2)) })).status).toBe(401);
  });
});

describe('an attempt that names the execution report type without its shape (§8.6)', () => {
  it('is not admitted after the end', async () => {
    const { host, sessionId, authentication, handler } = await l1();
    await post(handler, authentication, { taskId: TASK, event: event(sessionId, 1) });
    await host.endSession(sessionId);
    const disguised = {
      ...executionReport(
        { id: id(2), ts: '2026-10-15T00:00:00.000Z', sessionId, attemptId: id(1), execution: 'not-performed' },
        'attempted',
      ),
      mutates: true,
    };
    expect((await post(handler, authentication, { taskId: TASK, event: disguised })).body).toEqual({
      status: 'reject',
      reason: 'replay-detected',
    });
  });
});
