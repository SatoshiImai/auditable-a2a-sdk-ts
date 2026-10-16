/**
 * The walk's Server Agent process; same routes as the Python SDK's `agent.py`:
 * - `GET /.well-known/agent-card.json`: the Agent Card, Level 2 with countersignatures.
 * - `GET /jwks.json`: the attestation keys (§10.2), kept in `WALK_STATE_DIR` across restarts (§5.2).
 * - `GET /card-keys.json`: the Agent Card signing key (§3.1, A2A §8.4), named by the signature's `jku`.
 * - `POST /`: A2A over JSON-RPC.
 *
 * With `WALK_RESUME=1` it resumes every Task in its own ledger before serving and prints
 * `WALK_RESUMED=<taskId> <state>` for each.
 */

import { createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { AgentCard, Extensions, generateAgentCardSignature, Task, TaskStatusUpdateEvent } from '@a2a-js/sdk';
import {
  DefaultRequestHandler,
  type ExecutionEventBus,
  InMemoryTaskStore,
  JsonRpcTransportHandler,
  ServerCallContext,
} from '@a2a-js/sdk/server';
import { AmcpAbortedError, Ed25519Signer, generateToolKey, KeyRole, loadToolKey, toolKeyPkcs8 } from 'auditable-mcp-sdk';
import {
  type AuditedAgentExecutor,
  auditedExecutor,
  auditedRequestHandler,
  heldForAudit,
  resumedFromHold,
} from '../src/a2a';
import { agentCardExtension } from '../src/admission';
import { AuditedTask } from '../src/audited-task';
import { keyIdOf } from '../src/keys';
import { type AuditRequest, Countersign, Level } from '../src/models';
import { resumeTask } from '../src/resume';
import { SelfLedger } from '../src/self-ledger';
import { FileLedgerRepository, json, ordinaryJwk, serve } from './common';

const TABLE = { kind: 'table', ref: 'customers' };
const LEDGER = { kind: 'ledger', ref: 'general-ledger/2026-09' };
const REPORT = { kind: 'document', ref: 'settlement-report/2026-09' };
const state = process.env.WALK_STATE_DIR as string;
mkdirSync(state, { recursive: true });
const repository = new FileLedgerRepository(join(state, 'ledger'));
const secrets = (taskId: string) => join(state, `${taskId}.credentials.json`);

function signerFor(attestationKeys: string) {
  const keyId = keyIdOf(attestationKeys, 'a1');
  const path = join(state, 'agent-key.der');
  const key = existsSync(path) ? loadToolKey(keyId, readFileSync(path)) : generateToolKey(keyId);
  if (!existsSync(path)) writeFileSync(path, toolKeyPkcs8(key));
  return { signer: Ed25519Signer.fromToolKey(key), jwks: { keys: [ordinaryJwk('a1', key.publicKey, KeyRole.TOOL)] } };
}

function cardKey(): KeyObject {
  const path = join(state, 'card-key.der');
  if (!existsSync(path)) {
    const { privateKey } = generateKeyPairSync('ed25519');
    writeFileSync(path, privateKey.export({ format: 'der', type: 'pkcs8' }));
  }
  return createPrivateKey({ key: readFileSync(path), format: 'der', type: 'pkcs8' });
}

await serve(async (base) => {
  const attestationKeys = `${base}/jwks.json`;
  const { signer, jwks } = signerFor(attestationKeys);

  if (process.env.WALK_RESUME === '1') {
    for (const file of readdirSync(join(state, 'ledger')).filter((name) => name.endsWith('.jsonl')).sort()) {
      const taskId = file.slice(0, -'.jsonl'.length);
      const endpoint = JSON.parse(readFileSync(secrets(taskId), 'utf8')) as AuditRequest['auditEndpoint'];
      const result = await resumeTask({
        selfLedger: await SelfLedger.open(repository, taskId),
        credentials: {
          authentication: endpoint.authentication,
          ...(endpoint.token === undefined ? {} : { token: endpoint.token }),
        },
        signer,
      });
      const closed = result.state === 'continue' && (await result.task.finish());
      process.stdout.write(`WALK_RESUMED=${taskId} ${result.state}${closed ? ' closed' : ''}\n`);
    }
  }

  const params = { level: Level.L2, countersign: Countersign.HOST, selfChain: true, attestationKeys };
  const card = AgentCard.fromJSON({
    name: 'ledger agent (TypeScript)',
    description: 'reads the customers table',
    version: '1.0.0',
    supportedInterfaces: [{ url: `${base}/`, protocolBinding: 'JSONRPC', protocolVersion: '1.0' }],
    capabilities: { streaming: false, extensions: [agentCardExtension(params, { required: false })] },
    defaultInputModes: ['text/plain'],
    defaultOutputModes: ['text/plain'],
    skills: [],
  });

  const signingKey = cardKey();
  const cardJwks = { keys: [{ ...createPublicKey(signingKey).export({ format: 'jwk' }), kid: 'c1', alg: 'EdDSA' }] };
  const signed = await generateAgentCardSignature(signingKey, {
    alg: 'EdDSA',
    kid: 'c1',
    jku: `${base}/card-keys.json`,
    typ: 'JOSE',
  })(card);

  const sessions = new Map<string, string>();
  /** The audited Tasks held for a record, by id, which a later message takes up again (§8.5). */
  const held = new Map<string, AuditedTask>();
  const complete = (bus: ExecutionEventBus, taskId: string, contextId: string, text: string) => {
    bus.publish({
      kind: 'statusUpdate',
      data: TaskStatusUpdateEvent.fromJSON({
        taskId,
        contextId,
        status: {
          state: 'TASK_STATE_COMPLETED',
          message: { messageId: crypto.randomUUID(), contextId, taskId, role: 'ROLE_AGENT', parts: [{ text }] },
        },
      }),
    });
    bus.finished();
  };
  const audited = async (taskId: string, request: AuditRequest) => {
    sessions.set(request.sessionId, taskId);
    writeFileSync(secrets(taskId), JSON.stringify(request.auditEndpoint));
    const hostKeySnapshot = (await (await fetch(request.hostKeys as string)).json()) as {
      keys: Record<string, unknown>[];
    };
    return new AuditedTask({ taskId, request, signer, hostKeySnapshot, selfLedger: await SelfLedger.open(repository, taskId) });
  };
  /** Record and fetch the settlement report; hold the Task while it cannot be recorded (§8.4). */
  const fetchReport = async (task: AuditedTask, bus: ExecutionEventBus, taskId: string, contextId: string, resumed: boolean) => {
    try {
      await using action = await task.action('report.fetch', REPORT, {
        mutates: false,
        egress: false,
        commitSalted: { path: '/settlement/2026-09.csv' },
      });
      action.succeeded();
    } catch (error) {
      if (!(error instanceof AmcpAbortedError)) throw error;
      bus.publish({ kind: 'statusUpdate', data: heldForAudit({ taskId, contextId }, task.statusOf(error)) });
      bus.finished();
      return;
    }
    if (resumed) bus.publish({ kind: 'statusUpdate', data: resumedFromHold({ taskId, contextId }) });
    held.delete(taskId);
    await task.finish();
    complete(bus, taskId, contextId, 'Reconciled: 3 entries differ.');
  };

  const executor: AuditedAgentExecutor = {
    async execute(requestContext, eventBus, audit) {
      const { taskId, contextId } = requestContext;
      // A later message on an audited Task is taken up whatever it lists in A2A-Extensions (§4.3, §8.1).
      const holding = held.get(taskId);
      if (holding !== undefined) {
        await fetchReport(holding, eventBus, taskId, contextId, true);
        return;
      }
      if (requestContext.task === undefined) {
        eventBus.publish({
          kind: 'task',
          data: Task.fromJSON({ id: taskId, contextId, status: { state: 'TASK_STATE_WORKING' } }),
        });
      }
      if (audit?.request === undefined) {
        complete(eventBus, taskId, contextId, 'Done.');
        return;
      }
      const task = await audited(taskId, audit.request);
      const first = requestContext.userMessage.parts[0]?.content;
      if (first?.$case === 'text' && first.value.startsWith('Reconcile')) {
        held.set(taskId, task);
        {
          await using action = await task.action('ledger.read', LEDGER, {
            mutates: false,
            egress: false,
            disclose: { period: '2026-09' },
          });
          action.succeeded();
        }
        await fetchReport(task, eventBus, taskId, contextId, false);
        return;
      }
      let attemptId = '';
      {
        await using action = await task.action('db.read', TABLE, { mutates: false, egress: false });
        attemptId = action.id;
        action.succeeded();
      }
      if (!(await task.finish())) {
        eventBus.publish({
          kind: 'statusUpdate',
          data: heldForAudit({ taskId, contextId }, { reason: 'host-unavailable', attemptId }),
        });
        eventBus.finished();
        return;
      }
      complete(eventBus, taskId, contextId, 'Done.');
    },
    async cancelTask() {},
  };
  const handler = auditedRequestHandler(
    new DefaultRequestHandler(signed, new InMemoryTaskStore(), auditedExecutor(executor)),
    {
      declaration: { required: false, params },
      sessionInUse: async (sessionId) => {
        const taskId = sessions.get(sessionId);
        return taskId === undefined ? undefined : { taskId, sameClient: true };
      },
      onCredentials: async (taskId, credentials) => {
        writeFileSync(secrets(taskId), JSON.stringify(credentials));
      },
    },
  );
  const transport = new JsonRpcTransportHandler(handler);

  return async (request) => {
    const path = new URL(request.url).pathname;
    if (path === '/.well-known/agent-card.json') return json(AgentCard.toJSON(signed));
    if (path === '/jwks.json') return json(jwks);
    if (path === '/card-keys.json') return json(cardJwks);
    if (path === '/' && request.method === 'POST') {
      const context = new ServerCallContext({
        requestedExtensions: Extensions.parseServiceParameter(request.headers.get('A2A-Extensions') ?? undefined),
        requestedVersion: request.headers.get('A2A-Version') ?? '0.3',
      });
      const answer = await transport.handle(await request.text(), context);
      const activated = context.activatedExtensions ?? [];
      return json(answer, {
        headers: activated.length === 0 ? {} : { 'A2A-Extensions': Extensions.toServiceParameter(activated) },
      });
    }
    return new Response(null, { status: 404 });
  };
});
