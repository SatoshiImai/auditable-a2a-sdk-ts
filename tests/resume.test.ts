/** Resumption after a Server Agent restart (§5.5): nothing left unrecorded, nothing performed twice. */

import { randomUUID } from 'node:crypto';
import {
  AmcpAbortedError,
  CountersignatureRegistryVerifier,
  type Deps,
  Ed25519Countersigner,
  Ed25519Signer,
  generateToolKey,
  InMemoryLedgerRepository,
  KeyRole,
  type LedgerRepository,
  publicJwk,
  RepositoryError,
  type SealedRecord,
} from 'auditable-mcp-sdk';
import { describe, expect, it } from 'vitest';
import { A2aAuditHost } from '../src/audit-host';
import { AuditedTask } from '../src/audited-task';
import { createAuditEndpointHandler } from '../src/endpoint-handler';
import { EXECUTION_REPORT_ACTION_TYPE } from '../src/execution-report';
import { keyIdOf, registryFromJwks } from '../src/keys';
import { type AuditRequest, Countersign, Level } from '../src/models';
import { resumeTask } from '../src/resume';
import { SelfLedger } from '../src/self-ledger';
import { InMemorySessionStore } from '../src/session-store';
import { verifyA2aLedger } from '../src/verify';

const ENDPOINT = 'https://audit.client.example/a2a';
const HOST_KEYS = 'https://audit.client.example/keys.json';
const AGENT_KEYS = 'https://agent.example/.well-known/jwks.json';
const TASK = 'task-1';
const PARTITION = 'tasks/task-1';
const TABLE = { kind: 'table', ref: 'customers' };
const READ = { mutates: false, egress: false };

class Clock implements Deps {
  #n = 0;
  now(): string {
    this.#n += 1;
    return new Date(Date.UTC(2026, 9, 15, 0, 0, this.#n)).toISOString();
  }
  newId(): string {
    return randomUUID();
  }
}

/** A repository whose appends can be made to fail, as a full disk or a lost connection does. */
class FlakyRepository implements LedgerRepository {
  readonly inner = new InMemoryLedgerRepository();
  failWhen: ((record: SealedRecord) => boolean) | undefined;

  async append(partition: string, record: SealedRecord): Promise<void> {
    if (this.failWhen?.(record)) throw new RepositoryError('disk full');
    await this.inner.append(partition, record);
  }
  loadTail(partition: string): Promise<SealedRecord | null> {
    return this.inner.loadTail(partition);
  }
  readAll(partition: string): Promise<SealedRecord[]> {
    return this.inner.readAll(partition);
  }
}

type Mode = 'serve' | 'down' | 'lose-answer' | 'hang' | { status: number } | { body: unknown };

/** A fetch to the audit host's handler; `next` shapes the coming calls, one mode per call. */
function fetchTo(handler: (request: Request) => Promise<Response>) {
  const next: Mode[] = [];
  const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
    const mode = next.shift() ?? 'serve';
    if (mode === 'down') throw new TypeError('connection refused');
    if (mode === 'hang') {
      await handler(new Request(url, init));
      return new Promise<Response>(() => undefined);
    }
    if (mode === 'lose-answer') {
      await handler(new Request(url, init));
      throw new TypeError('connection reset');
    }
    if (typeof mode === 'object' && 'status' in mode) return new Response(null, { status: mode.status });
    if (typeof mode === 'object' && 'body' in mode) return Response.json(mode.body);
    return handler(new Request(url, init));
  }) as typeof fetch;
  return { fetchImpl, next };
}

function ordinaryJwk(kid: string, publicKey: Uint8Array, role: (typeof KeyRole)[keyof typeof KeyRole]) {
  const { amcp_role: _role, ...jwk } = publicJwk(kid, publicKey, 'Ed25519', role);
  return jwk;
}

async function setup(level: Level = Level.L2, countersign: Countersign = Countersign.HOST) {
  const agentKey = generateToolKey(keyIdOf(AGENT_KEYS, 'a1'));
  const hostKey = generateToolKey(keyIdOf(HOST_KEYS, 'h1'));
  const host = A2aAuditHost.create('client-a', level, countersign, {
    store: new InMemorySessionStore(),
    clock: new Clock(),
    ...(countersign === Countersign.HOST
      ? { countersigner: new Ed25519Countersigner(hostKey.keyId, hostKey.privateKey) }
      : {}),
  });
  const opened = await host.openSession({
    delegate: 'https://agent.example',
    expiresAt: '2026-11-15T00:00:00Z',
    ...(level === Level.L2
      ? { attestationKeys: AGENT_KEYS, keySnapshot: { keys: [ordinaryJwk('a1', agentKey.publicKey, KeyRole.TOOL)] } }
      : {}),
    ...(countersign === Countersign.HOST ? { hostKeys: HOST_KEYS } : {}),
  });
  const request: AuditRequest = {
    auditEndpoint: { url: ENDPOINT, authentication: opened.authentication },
    sessionId: opened.sessionId,
    level,
    countersign,
    expiresAt: '2026-11-15T00:00:00Z',
    ...(countersign === Countersign.HOST ? { hostKeys: HOST_KEYS } : {}),
  };
  const repository = new FlakyRepository();
  const deps = new Clock();
  const signer = level === Level.L2 ? Ed25519Signer.fromToolKey(agentKey) : undefined;
  const { fetchImpl, next } = fetchTo(createAuditEndpointHandler(host));
  const task = new AuditedTask({
    taskId: TASK,
    request,
    fetch: fetchImpl,
    deps,
    selfLedger: await SelfLedger.open(repository, PARTITION, () => deps.now()),
    ...(signer === undefined ? {} : { signer }),
    ...(countersign === Countersign.HOST
      ? { hostKeySnapshot: { keys: [ordinaryJwk('h1', hostKey.publicKey, KeyRole.HOST)] } }
      : {}),
  });
  /** A new process: the same own ledger and the same audit host, nothing else of the old one. */
  const restart = async (options: { signer?: Ed25519Signer; terminal?: boolean; modes?: Mode[] } = {}) => {
    const chosen = options.signer ?? signer;
    const after = fetchTo(createAuditEndpointHandler(host));
    after.next.push(...(options.modes ?? []));
    const resumed = await resumeTask({
      selfLedger: await SelfLedger.open(repository, PARTITION, () => deps.now()),
      credentials: { authentication: opened.authentication },
      deps,
      fetch: after.fetchImpl,
      timeoutMs: 50,
      ...(chosen === undefined ? {} : { signer: chosen }),
      ...(options.terminal === undefined ? {} : { terminal: options.terminal }),
    });
    return { resumed, next: after.next };
  };
  const hostKeySnapshot = { keys: [ordinaryJwk('h1', hostKey.publicKey, KeyRole.HOST)] };
  return { host, task, next, repository, restart, hostKeySnapshot, sessionId: opened.sessionId };
}

const outcomesOf = (host: A2aAuditHost, id: string) =>
  host.records().filter((record) => record.event.id === id && record.event.outcome !== 'attempted');
const reportsOn = (host: A2aAuditHost, id: string) =>
  host
    .records()
    .filter(
      (record) =>
        record.event.action_type === EXECUTION_REPORT_ACTION_TYPE &&
        record.event.outcome === 'attempted' &&
        (record.event.action_context as { attemptId?: string }).attemptId === id,
    );

describe('a restart after the access resolved (§5.5 steps 2 and 4)', () => {
  it('delivers the outcome it owed, and numbers the next event after the last one it used', async () => {
    const { host, task, next, restart } = await setup();
    let id = '';
    await (async () => {
      await using action = await task.action('db.read', TABLE, READ);
      id = action.id;
      action.succeeded();
      next.push('down');
    })();
    expect(task.client.owed).toHaveLength(1);

    const { resumed } = await restart();
    expect(resumed.state).toBe('continue');
    expect(outcomesOf(host, id).map((record) => record.event.outcome)).toEqual(['success']);
    if (resumed.state !== 'continue') return;
    await (async () => {
      await using again = await resumed.task.action('db.read', TABLE, READ);
      again.succeeded();
    })();
    expect(host.records().map((record) => record.event.signer_seq)).toEqual([0, 1, 2, 3]);
  });

  it('writes the outcome from how the access resolved when the outcome itself was never written', async () => {
    const { host, task, repository, restart } = await setup();
    let id = '';
    repository.failWhen = (record) =>
      record.event.entry === 'sent' && record.event.event !== undefined
        ? (record.event.event as { outcome?: string }).outcome === 'failed'
        : false;
    await (async () => {
      await using action = await task.action('db.write', TABLE, { mutates: true, egress: false });
      id = action.id;
      action.failed();
    })();
    repository.failWhen = undefined;
    expect(outcomesOf(host, id)).toHaveLength(0);

    const { resumed } = await restart();
    expect(resumed.state).toBe('continue');
    expect(outcomesOf(host, id).map((record) => record.event.outcome)).toEqual(['failed']);
    expect(reportsOn(host, id)).toHaveLength(0);
  });
});

describe('a restart before the access resolved is never performed again (§5.5 step 4)', () => {
  it('reports not-performed an accept it had not started on', async () => {
    const { host, task, repository, restart } = await setup();
    repository.failWhen = (record) => record.event.entry === 'performing';
    await expect(task.action('db.write', TABLE, { mutates: true, egress: false })).rejects.toThrow(/performing/);
    repository.failWhen = undefined;
    const id = String(host.records()[0]?.event.id);

    const { resumed } = await restart();
    expect(resumed).toMatchObject({ state: 'continue', notPerformed: [id], indeterminate: [] });
    expect(reportsOn(host, id)).toHaveLength(1);
    expect(outcomesOf(host, id)).toHaveLength(0);
  });

  it('reports indeterminate an accept it was performing', async () => {
    const { host, task, restart } = await setup();
    const action = await task.action('db.write', TABLE, { mutates: true, egress: false });

    const { resumed } = await restart();
    expect(resumed).toMatchObject({ state: 'continue', notPerformed: [], indeterminate: [action.id] });
    const report = reportsOn(host, action.id)[0];
    expect((report?.event.action_context as { execution?: string }).execution).toBe('indeterminate');
  });

  it('reports not-performed an accept that first reaches it on a resend', async () => {
    const { host, task, next, restart } = await setup();
    next.push('hang');
    void task.action('db.write', TABLE, { mutates: true, egress: false });
    await expect.poll(() => host.records().length).toBe(1);
    const id = String(host.records()[0]?.event.id);

    const { resumed } = await restart();
    expect(resumed).toMatchObject({ state: 'continue', notPerformed: [id] });
    expect(
      host.records().filter((record) => record.event.id === id && record.event.outcome === 'attempted'),
    ).toHaveLength(1);
    expect(reportsOn(host, id)).toHaveLength(1);
  });

  it('completes a report whose own outcome was never written, rather than reporting again', async () => {
    const { host, task, repository, restart } = await setup();
    repository.failWhen = (record) => record.event.entry === 'performing';
    await expect(task.action('db.write', TABLE, { mutates: true, egress: false })).rejects.toThrow();
    const id = String(host.records()[0]?.event.id);
    repository.failWhen = (record) => {
      const event = record.event.event as { action_type?: string; outcome?: string } | undefined;
      return event?.action_type === EXECUTION_REPORT_ACTION_TYPE && event.outcome === 'success';
    };
    expect((await restart()).resumed.state).toBe('continue');
    repository.failWhen = undefined;
    const reportId = String(reportsOn(host, id)[0]?.event.id);
    expect(outcomesOf(host, reportId)).toHaveLength(0);

    expect((await restart()).resumed.state).toBe('continue');
    expect(reportsOn(host, id)).toHaveLength(1);
    expect(outcomesOf(host, reportId).map((record) => record.event.outcome)).toEqual(['success']);
  });

  it('resends a report outcome that was written but not acknowledged', async () => {
    const { host, task, repository, restart } = await setup();
    repository.failWhen = (record) => record.event.entry === 'performing';
    await expect(task.action('db.write', TABLE, { mutates: true, egress: false })).rejects.toThrow();
    repository.failWhen = undefined;
    const id = String(host.records()[0]?.event.id);
    // Position, report attempt, then the report's outcome is lost.
    expect((await restart({ modes: ['serve', 'serve', 'down'] })).resumed.state).toBe('continue');
    const reportId = String(reportsOn(host, id)[0]?.event.id);
    expect(outcomesOf(host, reportId)).toHaveLength(0);

    expect((await restart()).resumed.state).toBe('continue');
    expect(reportsOn(host, id)).toHaveLength(1);
    expect(outcomesOf(host, reportId).map((record) => record.event.outcome)).toEqual(['success']);
  });
});

describe('a refusal the restart interrupted (§5.5 step 2)', () => {
  it('sends the aborted outcome of a reject it recorded but had not answered', async () => {
    const { host, task, sessionId, repository, restart } = await setup();
    await host.endSession(sessionId);
    repository.failWhen = (record) => (record.event.event as { outcome?: string } | undefined)?.outcome === 'aborted';
    await expect(task.action('db.read', TABLE, READ)).rejects.toThrow(/host-rejected/);
    repository.failWhen = undefined;
    const sent = (await repository.readAll(PARTITION)).find((record) => record.event.entry === 'sent');
    const id = String((sent?.event.event as { id?: string }).id);
    expect(outcomesOf(host, id)).toHaveLength(0);

    await restart();
    expect(outcomesOf(host, id).map((record) => [record.event.outcome, record.event.reason])).toEqual([
      ['aborted', 'host-rejected'],
    ]);
  });
});

describe('an attempt answered unavailable before the restart (§5.5 step 2)', () => {
  it('is resent, and an accept that first arrives then is reported not-performed', async () => {
    const { host, task, next, repository, restart } = await setup(Level.L1, Countersign.NONE);
    next.push({ body: { status: 'unavailable', reason: 'internal-error' } });
    repository.failWhen = (record) => (record.event.event as { outcome?: string } | undefined)?.outcome === 'aborted';
    await expect(task.action('db.read', TABLE, READ)).rejects.toBeInstanceOf(AmcpAbortedError);
    repository.failWhen = undefined;
    expect(host.records()).toEqual([]);
    const sent = (await repository.readAll(PARTITION)).find((record) => record.event.entry === 'sent');
    const id = String((sent?.event.event as { id?: string }).id);

    const { resumed } = await restart();
    expect(resumed).toMatchObject({ state: 'continue', notPerformed: [id] });
    expect(
      host
        .records()
        .filter((r) => r.event.id === id)
        .map((r) => r.event.outcome),
    ).toEqual(['attempted']);
    expect(reportsOn(host, id)).toHaveLength(1);
  });
});

describe('resuming again is idempotent', () => {
  it('neither reports nor seals twice across repeated restarts, and the Client ledger verifies', async () => {
    const { host, task, sessionId, restart, hostKeySnapshot } = await setup();
    const action = await task.action('db.write', TABLE, { mutates: true, egress: false });
    await restart();
    const sealed = host.records().length;
    const again = await restart();
    expect(again.resumed).toMatchObject({ state: 'continue', notPerformed: [], indeterminate: [] });
    expect(host.records()).toHaveLength(sealed);
    expect(reportsOn(host, action.id)).toHaveLength(1);

    await host.endSession(sessionId);
    const state = host.session(sessionId);
    const report = verifyA2aLedger(host.records(), state === undefined ? [] : [state], {
      countersignatureChecker: new CountersignatureRegistryVerifier(
        registryFromJwks(HOST_KEYS, hostKeySnapshot, KeyRole.HOST),
      ).check,
    });
    expect(report.findings).toEqual([]);
    expect(report.amcp.complete).toBe(true);
  });
});

describe('a step that cannot reach the audit host holds the Task (§5.5)', () => {
  it('holds at step 3 while the position is unanswered, and continues when resumed again', async () => {
    const { task, restart } = await setup(Level.L1, Countersign.NONE);
    await (async () => {
      await using action = await task.action('db.read', TABLE, READ);
      action.succeeded();
    })();
    expect((await restart({ modes: ['down'] })).resumed).toEqual({
      state: 'held',
      step: 3,
      status: { reason: 'host-unavailable' },
    });
    expect((await restart()).resumed.state).toBe('continue');
  });

  it('holds at step 2 on 401, with the status that asks for new credentials (§5.7)', async () => {
    const { host, task, next, restart } = await setup(Level.L1, Countersign.NONE);
    next.push('hang');
    void task.action('db.read', TABLE, READ);
    await expect.poll(() => host.records().length).toBe(1);
    expect((await restart({ modes: [{ status: 401 }] })).resumed).toEqual({
      state: 'held',
      step: 2,
      status: { reason: 'host-unavailable', httpStatus: 401, attemptId: expect.any(String) },
    });
    expect((await restart()).resumed.state).toBe('continue');
  });
});

describe('a check that fails fails the Task (§5.5)', () => {
  it('fails when the own ledger does not recompute', async () => {
    const { task, repository } = await setup();
    await (async () => {
      await using action = await task.action('db.read', TABLE, READ);
      action.succeeded();
    })();
    const records = await repository.inner.readAll(PARTITION);
    (records[1] as { event: Record<string, unknown> }).event = { entry: 'performing', id: 'forged' };
    const tampered = new InMemoryLedgerRepository();
    for (const record of records) await tampered.append(PARTITION, record);
    const resumed = await resumeTask({
      selfLedger: await SelfLedger.open(tampered, PARTITION),
      credentials: { authentication: { scheme: 'Bearer', credentials: 'x' } },
    });
    expect(resumed).toEqual({ state: 'failed', reason: 'own-ledger' });
  });

  it('fails when a well-chained entry is not one the SDK writes', async () => {
    const { task, repository } = await setup();
    await (async () => {
      await using action = await task.action('db.read', TABLE, READ);
      action.succeeded();
    })();
    const reopened = await SelfLedger.open(repository.inner, PARTITION);
    await reopened.write({ entry: 'resolved', id: 'x', outcome: 'maybe' } as never);
    const resumed = await resumeTask({
      selfLedger: reopened,
      credentials: { authentication: { scheme: 'Bearer', credentials: 'x' } },
    });
    expect(resumed).toEqual({ state: 'failed', reason: 'own-ledger' });
  });

  it('fails when the signer is not the key the session is bound to (§5.2)', async () => {
    const { task, restart } = await setup();
    await (async () => {
      await using action = await task.action('db.read', TABLE, READ);
      action.succeeded();
    })();
    const other = Ed25519Signer.fromToolKey(generateToolKey(keyIdOf(AGENT_KEYS, 'a2')));
    expect((await restart({ signer: other })).resumed).toEqual({ state: 'failed', reason: 'key-changed' });
  });

  it('fails when the position does not recompute from an event of the own ledger', async () => {
    const { host, task, restart } = await setup(Level.L1, Countersign.NONE);
    await (async () => {
      await using action = await task.action('db.read', TABLE, READ);
      action.succeeded();
    })();
    const [first, second] = host.records() as [SealedRecord, SealedRecord];
    const forged = {
      seq: second.seq,
      host_ts: second.host_ts,
      previous_hash: second.previous_hash,
      record_hash: first.record_hash,
    };
    expect((await restart({ modes: [{ body: { last: forged } }] })).resumed).toEqual({
      state: 'failed',
      reason: 'no-matching-event',
    });
  });

  it('fails when the position is empty while the own ledger holds an accept (a cut-off tail)', async () => {
    const { task, restart } = await setup(Level.L1, Countersign.NONE);
    await task.action('db.read', TABLE, READ);
    expect((await restart({ modes: [{ body: { last: null } }] })).resumed).toEqual({
      state: 'failed',
      reason: 'empty-with-accepts',
    });
  });

  it('fails when the position request is refused (§6.6)', async () => {
    const { task, restart } = await setup(Level.L1, Countersign.NONE);
    await task.action('db.read', TABLE, READ);
    expect((await restart({ modes: [{ status: 403 }] })).resumed).toEqual({
      state: 'failed',
      reason: 'position-refused',
    });
  });

  it('fails when the position is not countersigned under countersign "host"', async () => {
    const { host, task, restart } = await setup();
    await task.action('db.read', TABLE, READ);
    const { seq, host_ts, previous_hash, record_hash } = host.records()[0] as SealedRecord;
    expect(
      (await restart({ modes: [{ body: { last: { seq, host_ts, previous_hash, record_hash } } }] })).resumed,
    ).toEqual({ state: 'failed', reason: 'position-uncountersigned' });
  });
});

describe('a closed session completes the move to the terminal state (§5.5 step 6)', () => {
  it('delivers only, for a Task already terminal at the restart', async () => {
    const { host, task, restart } = await setup();
    const action = await task.action('db.write', TABLE, { mutates: true, egress: false });
    expect((await restart({ terminal: true })).resumed).toMatchObject({
      state: 'delivered',
      indeterminate: [action.id],
    });
    expect(reportsOn(host, action.id)).toHaveLength(1);
  });

  it('reports closed when the own ledger shows the close', async () => {
    const { host, task, sessionId, restart } = await setup();
    await (async () => {
      await using action = await task.action('db.read', TABLE, READ);
      action.succeeded();
    })();
    expect(await task.finish()).toBe(true);
    const { resumed } = await restart();
    expect(resumed.state).toBe('closed');
    expect(host.session(sessionId)?.end?.cause).toBe('close');
  });
});
