/** The Server Agent's side (§6, §8), against this SDK's audit host. */

import {
  AmcpAbortedError,
  Ed25519Countersigner,
  Ed25519Signer,
  generateToolKey,
  KeyRole,
  publicJwk,
} from 'auditable-mcp-sdk';
import { describe, expect, it } from 'vitest';
import { A2aAuditHost } from '../src/audit-host';
import { AuditedTask } from '../src/audited-task';
import { createAuditEndpointHandler } from '../src/endpoint-handler';
import { keyIdOf } from '../src/keys';
import { type AuditRequest, Countersign, Level } from '../src/models';
import { InMemorySessionStore } from '../src/session-store';

const ENDPOINT = 'https://audit.client.example/a2a';
const HOST_KEYS = 'https://audit.client.example/keys.json';
const AGENT_KEYS = 'https://agent.example/.well-known/jwks.json';
const TASK = 'task-1';
const TABLE = { kind: 'table', ref: 'customers' };

class Clock {
  #n = 0;
  now(): string {
    this.#n += 1;
    return new Date(Date.UTC(2026, 9, 15, 0, 0, this.#n)).toISOString();
  }
}

/** A fetch that serves `handler`, optionally failing the next calls in a given way. */
function fetchTo(handler: (request: Request) => Promise<Response>) {
  const failures: Array<'down' | number> = [];
  const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
    const next = failures.shift();
    if (next === 'down') throw new TypeError('connection refused');
    if (typeof next === 'number')
      return new Response(null, { status: next, headers: { location: 'https://elsewhere.example' } });
    return handler(new Request(url, init));
  }) as typeof fetch;
  return { fetchImpl, failures };
}

function ordinaryJwk(kid: string, publicKey: Uint8Array, role: (typeof KeyRole)[keyof typeof KeyRole]) {
  const { amcp_role: _role, ...jwk } = publicJwk(kid, publicKey, 'Ed25519', role);
  return jwk;
}

async function setup(level: Level = Level.L1, countersign: Countersign = Countersign.NONE) {
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
  const { fetchImpl, failures } = fetchTo(createAuditEndpointHandler(host));
  const task = new AuditedTask({
    taskId: TASK,
    request,
    fetch: fetchImpl,
    ...(level === Level.L2 ? { signer: Ed25519Signer.fromToolKey(agentKey) } : {}),
    ...(countersign === Countersign.HOST
      ? { hostKeySnapshot: { keys: [ordinaryJwk('h1', hostKey.publicKey, KeyRole.HOST)] } }
      : {}),
  });
  return { host, task, failures, sessionId: opened.sessionId };
}

describe('an access recorded before it is performed (§8.1, §8.3)', () => {
  it('seals the attempt and the outcome in the Client ledger, and closes the session at the end', async () => {
    const { host, task, sessionId } = await setup();
    await (async () => {
      await using action = await task.action('db.read', TABLE, { mutates: false, egress: false });
      action.succeeded();
    })();
    expect(host.records().map((record) => record.event.outcome)).toEqual(['attempted', 'success']);
    expect(task.mayEnd()).toBe(true);
    expect(await task.finish()).toBe(true);
    expect(host.session(sessionId)?.end?.cause).toBe('close');
  });

  it('works signed and countersigned: Level 2 with countersign "host"', async () => {
    const { host, task } = await setup(Level.L2, Countersign.HOST);
    await (async () => {
      await using action = await task.action('db.read', TABLE, { mutates: false, egress: false });
      action.succeeded();
    })();
    expect(host.records()).toHaveLength(2);
    expect(host.records()[0]?.host_signature).toBeDefined();
  });
});

describe('a record that cannot be made holds the Task (§8.4)', () => {
  it('reads a refused connection as unavailable, and gives the auditStatus', async () => {
    const { task, failures } = await setup();
    failures.push('down', 'down');
    const error = await task.action('db.read', TABLE, { mutates: false, egress: false }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AmcpAbortedError);
    expect(task.statusOf(error as AmcpAbortedError)).toEqual({
      reason: 'host-unavailable',
      attemptId: expect.any(String),
    });
  });

  it('does not follow a redirect, and names the status (§6.8, §7.3)', async () => {
    const { task, failures } = await setup();
    failures.push(302);
    const error = await task.action('db.read', TABLE, { mutates: false, egress: false }).catch((e: unknown) => e);
    expect(task.statusOf(error as AmcpAbortedError)).toEqual({
      reason: 'host-unavailable',
      httpStatus: 302,
      attemptId: expect.any(String),
    });
  });

  it('names the host reason of a reject (§7.3)', async () => {
    const { host, task, sessionId } = await setup();
    await host.endSession(sessionId);
    const error = await task.action('db.read', TABLE, { mutates: false, egress: false }).catch((e: unknown) => e);
    expect(task.statusOf(error as AmcpAbortedError)).toEqual({
      reason: 'host-rejected',
      hostReason: 'replay-detected',
      attemptId: expect.any(String),
    });
  });

  it('asks for new credentials on 401, and records again once they are replaced (§5.7)', async () => {
    const { host, task, sessionId } = await setup();
    task.replaceCredentials({ scheme: 'Bearer', credentials: 'stale' });
    const error = await task.action('db.read', TABLE, { mutates: false, egress: false }).catch((e: unknown) => e);
    expect(task.statusOf(error as AmcpAbortedError)).toEqual({
      reason: 'host-unavailable',
      httpStatus: 401,
      attemptId: expect.any(String),
    });
    task.replaceCredentials(await host.issueCredentials(sessionId));
    await (async () => {
      await using action = await task.action('db.read', TABLE, { mutates: false, egress: false });
      action.succeeded();
    })();
    expect(host.records().filter((record) => record.event.outcome === 'success')).toHaveLength(1);
  });
});

describe('an outcome is delivered until acknowledged (§5.4, §6.4)', () => {
  it('keeps an unacknowledged outcome owed, holds the end, and delivers it on flush', async () => {
    const { host, task, failures } = await setup();
    await (async () => {
      await using action = await task.action('db.read', TABLE, { mutates: false, egress: false });
      failures.push(503);
      action.succeeded();
    })();
    expect(task.client.owed).toHaveLength(1);
    expect(task.mayEnd()).toBe(false);
    expect(task.mayEnd('cancel')).toBe(true);
    expect(await task.client.flush()).toBe(0);
    expect(host.records().map((record) => record.event.outcome)).toEqual(['attempted', 'success']);
  });
});

describe('the execution report (§8.6)', () => {
  it('records that an accepted access was not performed', async () => {
    const { host, task } = await setup();
    const action = await task.action('payment.send', TABLE, { mutates: true, egress: true });
    const attemptId = String(host.records()[0]?.event.id);
    await task.reportExecution(attemptId, 'not-performed');
    const report = host.records().find((record) => record.event.action_type === 'a2a.execution-report');
    expect(report?.event.action_context).toEqual({ attemptId, execution: 'not-performed' });
    expect(action).toBeDefined();
  });
});
