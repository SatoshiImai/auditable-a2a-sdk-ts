/** What an AuditedTask holds as outstanding (§5.4), and the auditStatus of a hold (§7.3, §8.4). */

import {
  AmcpAbortedError,
  Ed25519Countersigner,
  generateToolKey,
  InMemoryLedgerRepository,
  KeyRole,
  publicJwk,
  RepositoryError,
  type SealedRecord,
} from 'auditable-mcp-sdk';
import { describe, expect, it } from 'vitest';
import { A2aAuditHost } from '../src/audit-host';
import { AuditedTask, SessionExpiredError } from '../src/audited-task';
import { createAuditEndpointHandler } from '../src/endpoint-handler';
import { keyIdOf } from '../src/keys';
import { type AuditRequest, Countersign, Level } from '../src/models';
import { resumeTask } from '../src/resume';
import { SelfLedger, SelfLedgerError } from '../src/self-ledger';
import { InMemorySessionStore } from '../src/session-store';

const ENDPOINT = 'https://audit.client.example/a2a';
const HOST_KEYS = 'https://audit.client.example/keys.json';
const TASK = 'task-1';
const TABLE = { kind: 'table', ref: 'customers' };
const READ = { mutates: false, egress: false };

class Clock {
  #n = 0;
  constructor(readonly start = Date.UTC(2026, 9, 15)) {}
  now(): string {
    this.#n += 1;
    return new Date(this.start + this.#n * 1000).toISOString();
  }
  newId(): string {
    return crypto.randomUUID();
  }
}

type Rule = (body: {
  event?: { outcome?: string; action_type?: string };
}) => Promise<number | undefined> | number | undefined;

/** A fetch to the handler; each rule may hold a submission back, or answer it with a status instead. */
function fetchTo(handler: (request: Request) => Promise<Response>) {
  const rules: Rule[] = [];
  const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
    const request = new Request(url, init);
    const body = JSON.parse(await request.clone().text());
    for (const rule of rules) {
      const status = await rule(body);
      if (status !== undefined) return new Response(null, { status });
    }
    return handler(request);
  }) as typeof fetch;
  return { fetchImpl, rules };
}

function gate() {
  let open!: () => void;
  const opened = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { open, opened };
}

async function setup(
  options: {
    expiresAt?: string;
    countersign?: Countersign;
    selfLedger?: boolean;
    keyServerFailsAfter?: number | null;
  } = {},
) {
  const countersign = options.countersign ?? Countersign.NONE;
  const expiresAt = options.expiresAt ?? '2026-11-15T00:00:00Z';
  let hostKey = generateToolKey(keyIdOf(HOST_KEYS, 'h1'));
  const jwks = () => {
    const { amcp_role: _role, ...jwk } = publicJwk(
      hostKey.keyId.split('#')[1] as string,
      hostKey.publicKey,
      'Ed25519',
      KeyRole.HOST,
    );
    return { keys: [jwk] };
  };
  const host = A2aAuditHost.create('client-a', Level.L1, countersign, {
    store: new InMemorySessionStore(),
    clock: new Clock(),
    ...(countersign === Countersign.HOST
      ? {
          // A countersigner whose key the test rotates.
          countersigner: {
            get keyId() {
              return hostKey.keyId;
            },
            sign: (payload: Uint8Array) => new Ed25519Countersigner(hostKey.keyId, hostKey.privateKey).sign(payload),
          },
        }
      : {}),
  });
  const opened = await host.openSession({
    delegate: 'https://agent.example',
    expiresAt,
    ...(countersign === Countersign.HOST ? { hostKeys: HOST_KEYS } : {}),
  });
  const request: AuditRequest = {
    auditEndpoint: { url: ENDPOINT, authentication: opened.authentication },
    sessionId: opened.sessionId,
    level: Level.L1,
    countersign,
    expiresAt,
    ...(countersign === Countersign.HOST ? { hostKeys: HOST_KEYS } : {}),
  };
  const { fetchImpl, rules } = fetchTo(createAuditEndpointHandler(host));
  const repository = new InMemoryLedgerRepository();
  let failJournal: ((record: SealedRecord) => boolean) | undefined;
  const flaky = {
    append: async (partition: string, record: SealedRecord) => {
      if (failJournal?.(record)) throw new RepositoryError('disk full');
      await repository.append(partition, record);
    },
    loadTail: (partition: string) => repository.loadTail(partition),
    readAll: (partition: string) => repository.readAll(partition),
  };
  const keyFetches: string[] = [];
  const failsAfter = options.keyServerFailsAfter === undefined ? 1 : options.keyServerFailsAfter;
  const fetchHostKeys = async (url: string) => {
    keyFetches.push(url);
    if (failsAfter !== null && keyFetches.length > failsAfter) throw new Error('key server down');
    return jwks();
  };
  const task = new AuditedTask({
    taskId: TASK,
    request,
    fetch: fetchImpl,
    deps: new Clock(),
    ...(countersign === Countersign.HOST
      ? {
          hostKeySnapshot: jwks(),
          fetchHostKeys,
        }
      : {}),
    ...(options.selfLedger === true ? { selfLedger: await SelfLedger.open(flaky, TASK) } : {}),
  });
  return {
    host,
    task,
    request,
    flaky,
    fetchImpl,
    fetchHostKeys,
    rules,
    sessionId: opened.sessionId,
    rotateHostKey: (kid: string) => {
      hostKey = generateToolKey(keyIdOf(HOST_KEYS, kid));
    },
    keyFetches,
    failJournalWhen: (predicate: ((record: SealedRecord) => boolean) | undefined) => {
      failJournal = predicate;
    },
  };
}

describe('nothing outstanding means nothing outstanding (§5.4)', () => {
  it('does not close the session under an attempt still on its way', async () => {
    const { host, task, rules, sessionId } = await setup();
    const held = gate();
    const reached = gate();
    rules.push(async (body) => {
      if (body.event?.outcome === 'attempted') {
        reached.open();
        await held.opened;
      }
      return undefined;
    });
    const acting = (async () => {
      await using action = await task.action('db.read', TABLE, READ);
      action.succeeded();
    })();
    await reached.opened;
    expect(task.mayEnd()).toBe(false);
    expect(await task.finish()).toBe(false);
    held.open();
    await acting;
    expect(await task.finish()).toBe(true);
    expect(host.session(sessionId)?.anomalies).toEqual([]);
  });

  it('keeps an accept whose performing could not be written until an execution report resolves it', async () => {
    const { host, task, failJournalWhen } = await setup({ selfLedger: true });
    failJournalWhen((record) => record.event.entry === 'performing');
    await expect(task.action('db.write', TABLE, { mutates: true, egress: false })).rejects.toBeInstanceOf(
      SelfLedgerError,
    );
    failJournalWhen(undefined);
    expect(task.mayEnd()).toBe(false);
    const attemptId = String(host.records()[0]?.event.id);
    await task.reportExecution(attemptId, 'not-performed');
    expect(task.mayEnd()).toBe(true);
  });

  it('sends no outcome for an action resolved by an execution report, and counts a double dispose once', async () => {
    const { host, task } = await setup();
    const action = await task.action('db.write', TABLE, { mutates: true, egress: false });
    await task.reportExecution(action.id, 'not-performed');
    await action[Symbol.asyncDispose]();
    await action[Symbol.asyncDispose]();
    expect(
      host
        .records()
        .filter((record) => record.event.id === action.id)
        .map((r) => r.event.outcome),
    ).toEqual(['attempted']);
    expect(task.mayEnd()).toBe(true);
  });
});

describe('the auditStatus of a hold (§7.3, §8.4)', () => {
  it('names the failure of the attempt it is about, whatever was recorded since', async () => {
    const { task, rules } = await setup();
    rules.push((body) =>
      body.event?.action_type === 'db.write' && body.event.outcome === 'attempted' ? 401 : undefined,
    );
    const refused = await task.action('db.write', TABLE, { mutates: true, egress: false }).catch((e: unknown) => e);
    await (async () => {
      await using action = await task.action('db.read', TABLE, READ);
      action.succeeded();
    })();
    expect(task.statusOf(refused as AmcpAbortedError)).toMatchObject({ reason: 'host-unavailable', httpStatus: 401 });
  });

  it('names an outcome it could not deliver, with the status that asks for new credentials (§5.7)', async () => {
    const { task, rules } = await setup();
    rules.push((body) => (body.event?.outcome === 'success' ? 401 : undefined));
    let id = '';
    await (async () => {
      await using action = await task.action('db.read', TABLE, READ);
      id = action.id;
      action.succeeded();
    })();
    expect(task.heldStatus()).toEqual({ reason: 'host-unavailable', httpStatus: 401, attemptId: id });
  });
});

describe('the session expiry (§5.3)', () => {
  it('refuses an access after it', async () => {
    const { task } = await setup({ expiresAt: '2026-10-15T00:00:00Z' });
    await expect(task.action('db.read', TABLE, READ)).rejects.toBeInstanceOf(SessionExpiredError);
    expect(task.mayEnd()).toBe(true);
  });
});

describe('the audit host keys (§10.2)', () => {
  it('fetches them again for a kid it does not hold, and reads a fetch that fails as a failure to record', async () => {
    const { task, rotateHostKey, keyFetches } = await setup({ countersign: Countersign.HOST });
    rotateHostKey('h2');
    await (async () => {
      await using action = await task.action('db.read', TABLE, READ);
      action.succeeded();
    })();
    expect(keyFetches).toEqual([HOST_KEYS]);
    rotateHostKey('h3');
    const error = await task.action('db.read', TABLE, READ).catch((e: unknown) => e);
    expect((error as AmcpAbortedError).reason).toBe('host-unavailable');
  });
});

describe('an access written as performing, across a restart after the host keys rotate (§5.5 step 4)', () => {
  it('is resolved with its outcome, not recorded as aborted', async () => {
    const { host, task, request, flaky, fetchImpl, fetchHostKeys, rotateHostKey, failJournalWhen } = await setup({
      countersign: Countersign.HOST,
      selfLedger: true,
      keyServerFailsAfter: null,
    });
    rotateHostKey('h2');
    failJournalWhen(
      (record) => record.event.entry === 'sent' && (record.event.event as { outcome?: string }).outcome === 'success',
    );
    let id = '';
    await (async () => {
      await using action = await task.action('db.write', TABLE, { mutates: true, egress: false });
      id = action.id;
      action.succeeded();
    })();
    failJournalWhen(undefined);
    // From here the host publishes only its newest key, and countersigns under it.
    rotateHostKey('h3');
    await (async () => {
      await using action = await task.action('db.read', TABLE, READ);
      action.succeeded();
    })();

    const resumed = await resumeTask({
      selfLedger: await SelfLedger.open(flaky, TASK),
      credentials: { authentication: request.auditEndpoint.authentication },
      fetch: fetchImpl,
      fetchHostKeys,
    });
    expect(resumed.state).toBe('continue');
    expect(
      host
        .records()
        .filter((record) => record.event.id === id)
        .map((record) => record.event.outcome),
    ).toEqual(['attempted', 'success']);
  });
});

describe('the own ledger when its tail cannot be read back (§5.5)', () => {
  it('raises its own error, and reads the tail before the next write', async () => {
    const inner = new InMemoryLedgerRepository();
    let appendDown = false;
    let tailDown = false;
    const repository = {
      append: async (partition: string, record: SealedRecord) => {
        if (appendDown) throw new RepositoryError('disk full');
        await inner.append(partition, record);
      },
      loadTail: async (partition: string) => {
        if (tailDown) throw new RepositoryError('store down');
        return inner.loadTail(partition);
      },
      readAll: (partition: string) => inner.readAll(partition),
    };
    const ledger = await SelfLedger.open(repository, TASK);
    appendDown = true;
    tailDown = true;
    await expect(ledger.write({ entry: 'close' })).rejects.toBeInstanceOf(SelfLedgerError);
    await expect(ledger.write({ entry: 'close' })).rejects.toBeInstanceOf(SelfLedgerError);
    appendDown = false;
    tailDown = false;
    await ledger.write({ entry: 'close' });
    expect((await ledger.entries()).map((entry) => entry.entry)).toEqual(['close']);
  });
});

describe('a session entry whose acknowledgement was lost (§5.5)', () => {
  it('is not written twice, and the Task resumes', async () => {
    const { request, fetchImpl } = await setup();
    const inner = new InMemoryLedgerRepository();
    let lost = false;
    const repository = {
      append: async (partition: string, record: SealedRecord) => {
        await inner.append(partition, record);
        if (record.event.entry === 'session' && !lost) {
          lost = true;
          throw new RepositoryError('acknowledgement lost');
        }
      },
      loadTail: (partition: string) => inner.loadTail(partition),
      readAll: (partition: string) => inner.readAll(partition),
    };
    const task = new AuditedTask({
      taskId: TASK,
      request,
      fetch: fetchImpl,
      deps: new Clock(),
      selfLedger: await SelfLedger.open(repository, TASK),
    });
    await (async () => {
      await using action = await task.action('db.read', TABLE, READ);
      action.succeeded();
    })();
    const entries = await (await SelfLedger.open(repository, TASK)).entries();
    expect(entries.filter((entry) => entry.entry === 'session')).toHaveLength(1);
    const resumed = await resumeTask({
      selfLedger: await SelfLedger.open(repository, TASK),
      credentials: { authentication: request.auditEndpoint.authentication },
      fetch: fetchImpl,
    });
    expect(resumed.state).toBe('continue');
  });
});

describe('execution reports (§8.6)', () => {
  it('refuses a second report, and one on an attempt the Task never had accepted', async () => {
    const { task } = await setup();
    const action = await task.action('db.write', TABLE, { mutates: true, egress: false });
    await task.reportExecution(action.id, 'not-performed');
    await expect(task.reportExecution(action.id, 'not-performed')).rejects.toThrow(/already accepted/);
    await expect(task.reportExecution('0199a3e1-0000-7000-8000-0000000000ff', 'not-performed')).rejects.toThrow(
      /not an access/,
    );
    await action[Symbol.asyncDispose]();
  });

  it('lets an action whose report was not recorded send its outcome', async () => {
    const { host, task, rules } = await setup();
    const action = await task.action('db.write', TABLE, { mutates: true, egress: false });
    const refuseReports: Rule = (body) => (body.event?.action_type === 'a2a.execution-report' ? 503 : undefined);
    rules.push(refuseReports);
    await expect(task.reportExecution(action.id, 'not-performed')).rejects.toBeInstanceOf(AmcpAbortedError);
    rules.length = 0;
    action.succeeded();
    await action[Symbol.asyncDispose]();
    expect(await task.finish()).toBe(true);
    expect(
      host
        .records()
        .filter((record) => record.event.id === action.id)
        .map((record) => record.event.outcome),
    ).toEqual(['attempted', 'success']);
  });
});

describe('one resolution per attempt (§8.6)', () => {
  it("seals one report when the own ledger fails what would be the report's performing entry", async () => {
    const { host, task, failJournalWhen } = await setup({ selfLedger: true });
    const action = await task.action('db.write', TABLE, { mutates: true, egress: false });
    failJournalWhen((record) => record.event.entry === 'performing');
    await task.reportExecution(action.id, 'not-performed');
    failJournalWhen(undefined);
    await action[Symbol.asyncDispose]();
    const reports = host.records().filter((record) => record.event.action_type === 'a2a.execution-report');
    expect(reports.map((record) => record.event.outcome)).toEqual(['attempted', 'success']);
    expect(task.mayEnd()).toBe(true);
  });

  it('refuses a report while another on the same attempt is on its way', async () => {
    const { task, rules } = await setup();
    const action = await task.action('db.write', TABLE, { mutates: true, egress: false });
    const held = gate();
    const reached = gate();
    rules.push(async (body) => {
      if (body.event?.action_type === 'a2a.execution-report' && body.event.outcome === 'attempted') {
        reached.open();
        await held.opened;
      }
      return undefined;
    });
    const first = task.reportExecution(action.id, 'not-performed');
    await reached.opened;
    await expect(task.reportExecution(action.id, 'not-performed')).rejects.toThrow(/on its way/);
    held.open();
    await first;
    await action[Symbol.asyncDispose]();
  });

  it('refuses a report on an attempt whose outcome was sent', async () => {
    const { task } = await setup();
    let id = '';
    await (async () => {
      await using action = await task.action('db.read', TABLE, READ);
      id = action.id;
      action.succeeded();
    })();
    await expect(task.reportExecution(id, 'not-performed')).rejects.toThrow(/has its outcome/);
  });
});
