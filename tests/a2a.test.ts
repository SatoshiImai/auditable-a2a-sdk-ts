/** The `@a2a-js/sdk` binding: Client and Server Agent over in-process JSON-RPC. */

import { AgentCard, Extensions, Message, Task, TaskState, TaskStatusUpdateEvent } from '@a2a-js/sdk';
import { ClientFactory, ClientFactoryOptions, JsonRpcTransportFactory } from '@a2a-js/sdk/client';
import {
  type A2ARequestHandler,
  DefaultRequestHandler,
  InMemoryTaskStore,
  JsonRpcTransportHandler,
  ServerCallContext,
} from '@a2a-js/sdk/server';
import { AmcpAbortedError } from 'auditable-mcp-sdk';
import { describe, expect, it } from 'vitest';
import {
  type AuditedAgentExecutor,
  auditedExecutor,
  auditedRequestHandler,
  heldForAudit,
  readRejection,
  sendAudited,
} from '../src/a2a';
import { agentCardExtension, auditCredentialsMetadata, HoldRemedy, readAuditStatus } from '../src/admission';
import { A2aAuditHost } from '../src/audit-host';
import { AuditedTask } from '../src/audited-task';
import { createAuditEndpointHandler } from '../src/endpoint-handler';
import { type AuditCredentials, type AuditRequest, Countersign, EXTENSION_URI, Level } from '../src/models';
import { InMemorySessionStore } from '../src/session-store';
import { verifyA2aLedger } from '../src/verify';

const AGENT = 'https://agent.example/a2a';
const AUDIT = 'https://audit.client.example/a2a';
const TABLE = { kind: 'table', ref: 'customers' };

class Clock {
  #n = 0;
  now(): string {
    this.#n += 1;
    return new Date(Date.UTC(2026, 9, 15, 0, 0, this.#n)).toISOString();
  }
}

/** A `fetch` that serves the agent's JSON-RPC as the SDK's express adapter does, without a network. */
function servingFetch(
  handler: A2ARequestHandler,
  audit: (request: Request) => Promise<Response>,
  activated: string[][],
): typeof fetch {
  const transport = new JsonRpcTransportHandler(handler);
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const request = new Request(input, init);
    if (request.url.startsWith(AUDIT)) return audit(request);
    const context = new ServerCallContext({
      requestedExtensions: Extensions.parseServiceParameter(request.headers.get('A2A-Extensions') ?? undefined),
      requestedVersion: request.headers.get('A2A-Version') ?? '1.0',
    });
    const answer = await transport.handle(await request.text(), context);
    activated.push([...(context.activatedExtensions ?? [])]);
    return new Response(JSON.stringify(answer), {
      headers: {
        'content-type': 'application/json',
        'A2A-Extensions': Extensions.toServiceParameter(context.activatedExtensions ?? []),
      },
    });
  }) as typeof fetch;
}

interface World {
  host: A2aAuditHost;
  send: (request?: AuditRequest, metadata?: Record<string, unknown>) => Promise<{ result: unknown; audited: boolean }>;
  sendPlain: (taskId?: string, metadata?: Record<string, unknown>, extensions?: string[]) => Promise<unknown>;
  open: () => Promise<AuditRequest>;
  saved: string[];
  /** The extensions each response listed in `A2A-Extensions`, in order. */
  activated: string[][];
  credentialsReplaced: Array<{ taskId: string; credentials: AuditCredentials }>;
  setAuditDown: (down: boolean) => void;
  /** The audit context the executor received for each request, in order. */
  audits: Array<{ sessionId: string } | undefined>;
  getTask: (taskId: string, extensions?: string[]) => Promise<unknown>;
}

async function setup(options: { required?: boolean; level?: Level; answerWithMessage?: boolean } = {}): Promise<World> {
  const level = options.level ?? Level.L1;
  const host = A2aAuditHost.create('client-a', Level.L1, Countersign.NONE, {
    store: new InMemorySessionStore(),
    clock: new Clock(),
  });
  const auditHandler = createAuditEndpointHandler(host);
  let auditDown = false;
  const auditFetch = (async (input: string | URL | Request, init?: RequestInit) => {
    if (auditDown) throw new TypeError('connection refused');
    return auditHandler(new Request(input, init));
  }) as typeof fetch;

  const params = {
    level,
    countersign: Countersign.NONE,
    ...(level === Level.L2 ? { attestationKeys: 'https://agent.example/jwks.json' } : {}),
  };
  const declaration = { required: options.required ?? false, params };
  const card = AgentCard.fromJSON({
    name: 'ledger agent',
    description: 'reads the customers table',
    version: '1.0.0',
    supportedInterfaces: [{ url: AGENT, protocolBinding: 'JSONRPC', protocolVersion: '1.0' }],
    capabilities: { extensions: [agentCardExtension(params, { required: declaration.required })] },
    defaultInputModes: ['text/plain'],
    defaultOutputModes: ['text/plain'],
    skills: [],
  });

  const sessions = new Map<string, string>();
  const credentialsReplaced: World['credentialsReplaced'] = [];
  const audits: World['audits'] = [];
  const executor: AuditedAgentExecutor = {
    async execute(requestContext, eventBus, audit) {
      audits.push(audit === undefined ? undefined : { sessionId: audit.auditSession.sessionId });
      const { taskId, contextId } = requestContext;
      if (options.answerWithMessage === true) {
        // No recorded access, so no Task (§4.3).
        eventBus.publish({
          kind: 'message',
          data: Message.fromJSON({
            messageId: crypto.randomUUID(),
            contextId,
            role: 'ROLE_AGENT',
            parts: [{ text: '42' }],
          }),
        });
        eventBus.finished();
        return;
      }
      if (requestContext.task === undefined) {
        eventBus.publish({
          kind: 'task',
          data: Task.fromJSON({ id: taskId, contextId, status: { state: 'TASK_STATE_WORKING' } }),
        });
      }
      if (audit?.request !== undefined) {
        sessions.set(audit.request.sessionId, taskId);
        const task = new AuditedTask({ taskId, request: audit.request, fetch: auditFetch, timeoutMs: 100 });
        try {
          await using action = await task.action('db.read', TABLE, { mutates: false, egress: false });
          action.succeeded();
        } catch (error) {
          if (!(error instanceof AmcpAbortedError)) throw error;
          eventBus.publish({ kind: 'statusUpdate', data: heldForAudit({ taskId, contextId }, task.statusOf(error)) });
          eventBus.finished();
          return;
        }
        await task.finish();
      }
      eventBus.publish({
        kind: 'statusUpdate',
        data: TaskStatusUpdateEvent.fromJSON({ taskId, contextId, status: { state: 'TASK_STATE_COMPLETED' } }),
      });
      eventBus.finished();
    },
    async cancelTask() {},
  };
  const taskStore = new InMemoryTaskStore();
  const saved: string[] = [];
  const save = taskStore.save.bind(taskStore);
  taskStore.save = async (task, context) => {
    saved.push(task.id);
    await save(task, context);
  };
  const handler = auditedRequestHandler(new DefaultRequestHandler(card, taskStore, auditedExecutor(executor)), {
    declaration,
    sessionInUse: async (sessionId) => {
      const taskId = sessions.get(sessionId);
      return taskId === undefined ? undefined : { taskId, sameClient: true };
    },
    onCredentials: async (taskId, credentials) => {
      credentialsReplaced.push({ taskId, credentials });
    },
  });

  const activated: string[][] = [];
  const serving = servingFetch(handler, auditHandler, activated);
  const client = await new ClientFactory(
    ClientFactoryOptions.createFrom(ClientFactoryOptions.default, {
      transports: [new JsonRpcTransportFactory({ fetchImpl: serving })],
    }),
  ).createFromAgentCard(card);
  const message = (taskId?: string) => ({
    messageId: crypto.randomUUID(),
    role: 'ROLE_USER',
    parts: [{ text: 'Count the customers.' }],
    ...(taskId === undefined ? {} : { taskId }),
  });

  return {
    host,
    saved,
    activated,
    credentialsReplaced,
    audits,
    getTask: async (taskId, extensions = []) =>
      client.getTask({ tenant: '', id: taskId, historyLength: undefined } as never, {
        serviceParameters: { 'A2A-Extensions': extensions.join(',') },
      }),
    setAuditDown: (down) => {
      auditDown = down;
    },
    open: async () => {
      const opened = await host.openSession({ delegate: AGENT, expiresAt: '2026-11-15T00:00:00Z' });
      return {
        auditEndpoint: { url: AUDIT, authentication: opened.authentication },
        sessionId: opened.sessionId,
        level: Level.L1,
        countersign: Countersign.NONE,
        expiresAt: '2026-11-15T00:00:00Z',
      };
    },
    send: async (request, metadata) => {
      const params = { message: message() as never, metadata, tenant: '', configuration: undefined };
      return sendAudited(client, params as never, request as AuditRequest);
    },
    sendPlain: async (taskId, metadata, extensions = []) =>
      client.sendMessage(
        { message: message(taskId) as never, metadata, tenant: '', configuration: undefined } as never,
        {
          serviceParameters: { 'A2A-Extensions': extensions.join(',') },
        },
      ),
  };
}

const stateOf = (result: unknown) => (result as { status?: { state?: TaskState } }).status?.state;

describe('an audit-negotiated Task over the official SDK (§4.3)', () => {
  it('lists the URI, carries auditSession, and records the access in the Client ledger', async () => {
    const world = await setup();
    const request = await world.open();
    const { result, audited } = await world.send(request);

    expect(audited).toBe(true);
    expect(world.activated.at(-1)).toEqual([EXTENSION_URI]);
    expect(stateOf(result)).toBe(TaskState.TASK_STATE_COMPLETED);
    expect(world.host.records().map((record) => record.event.outcome)).toEqual(['attempted', 'success']);
    const session = world.host.session(request.sessionId);
    expect(session?.end?.cause).toBe('close');
    expect(verifyA2aLedger(world.host.records(), session === undefined ? [] : [session]).complete).toBe(true);
  });
});

describe('a negotiated request answered with a direct Message (§4.3)', () => {
  it('carries auditSession in the Message, and nothing is recorded', async () => {
    const world = await setup({ answerWithMessage: true });
    const { result, audited } = await world.send(await world.open());

    expect(audited).toBe(true);
    expect('messageId' in (result as object)).toBe(true);
    expect(world.host.records()).toEqual([]);
  });
});

describe('a request that is not audit-negotiated', () => {
  it('serves an unactivated request as an ordinary Task, with none of this extension (§4.5)', async () => {
    const world = await setup();
    const result = await world.sendPlain();
    expect(stateOf(result)).toBe(TaskState.TASK_STATE_COMPLETED);
    expect((result as { metadata?: Record<string, unknown> }).metadata?.[EXTENSION_URI]).toBeUndefined();
    expect(world.host.records()).toEqual([]);
  });

  it('refuses an unactivated request under the mandatory posture (§4.5)', async () => {
    const world = await setup({ required: true });
    await expect(world.sendPlain()).rejects.toMatchObject({ reason: 'EXTENSION_SUPPORT_REQUIRED' });
    expect(world.saved).toEqual([]);
  });

  it('rejects a level the agent does not meet, naming the field, and creates no Task (§4.4)', async () => {
    const world = await setup();
    const request = { ...(await world.open()), level: Level.L2 };
    const error = await world.send(request).catch((caught: unknown) => caught);
    expect(readRejection(error)?.field).toBe(`metadata[${JSON.stringify(EXTENSION_URI)}].auditRequest.level`);
    expect(world.saved).toEqual([]);
  });

  it('names the Task of a reused sessionId to the same Client (§4.4)', async () => {
    const world = await setup();
    const request = await world.open();
    const first = await world.send(request);
    const error = await world.send(request).catch((caught: unknown) => caught);
    expect(readRejection(error)?.sessionInUse).toEqual({ taskId: (first.result as { id: string }).id });
  });
});

describe('a Task held for audit (§8.4, §8.5)', () => {
  it('is held in TASK_STATE_AUTH_REQUIRED with an auditStatus the Client reads', async () => {
    const world = await setup();
    const request = await world.open();
    world.setAuditDown(true);
    const { result, audited } = await world.send(request);

    expect(audited).toBe(true);
    const status = (result as { status: { state: TaskState; message: { metadata: unknown } } }).status;
    expect(status.state).toBe(TaskState.TASK_STATE_AUTH_REQUIRED);
    expect(readAuditStatus(status.message.metadata)?.remedy).toBe(HoldRemedy.RESTORE_HOST);
  });
});

describe('a later request on the Task (§4.6, §5.7)', () => {
  it('hands auditCredentials to the running Task and rejects an auditRequest', async () => {
    const world = await setup();
    const request = await world.open();
    world.setAuditDown(true);
    const { result } = await world.send(request);
    const taskId = (result as { id: string }).id;
    const credentials = { authentication: { scheme: 'Bearer', credentials: 'renewed' } };

    await world.sendPlain(taskId, auditCredentialsMetadata(credentials), [EXTENSION_URI]);
    expect(world.credentialsReplaced).toEqual([{ taskId, credentials }]);

    const error = await world
      .sendPlain(taskId, { [EXTENSION_URI]: { auditRequest: request } }, [EXTENSION_URI])
      .catch((caught: unknown) => caught);
    expect(readRejection(error)?.field).toBe(`metadata[${JSON.stringify(EXTENSION_URI)}].auditRequest`);
  });
});

describe('a later request on an audit-negotiated Task that does not list the URI (§4.3, §8.1)', () => {
  it("still hands the executor the Task's audit", async () => {
    const world = await setup();
    const request = await world.open();
    world.setAuditDown(true);
    const { result } = await world.send(request);
    const taskId = (result as { id: string }).id;
    world.setAuditDown(false);
    await world.sendPlain(taskId, undefined, []);
    expect(world.audits.at(-1)).toEqual({ sessionId: request.sessionId });
  });
});

describe('the mandatory posture on a later request (§4.6, A2A §3.3.4)', () => {
  it('refuses a GetTask that does not list the URI', async () => {
    const world = await setup({ required: true });
    const request = await world.open();
    const { result } = await world.send(request);
    const taskId = (result as { id: string }).id;
    await expect(world.getTask(taskId)).rejects.toMatchObject({ reason: 'EXTENSION_SUPPORT_REQUIRED' });
    await expect(world.getTask(taskId, [EXTENSION_URI])).resolves.toMatchObject({ id: taskId });
  });
});
