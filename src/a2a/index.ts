/**
 * The binding to `@a2a-js/sdk`. Requests are decided in a request-handler wrapper, since an executor that throws
 * still leaves a stored failed Task and §4.4 creates none.
 */

import { Message, type SendMessageRequest, type StreamResponse, type Task, TaskStatusUpdateEvent } from '@a2a-js/sdk';
import { type Client, ServiceParameters, withA2AExtensions } from '@a2a-js/sdk/client';
import { ExtensionSupportRequiredError, RequestMalformedError } from '@a2a-js/sdk/errors';
import type {
  A2ARequestHandler,
  AgentExecutionEvent,
  AgentExecutor,
  ExecutionEventBus,
  RequestContext,
  ServerCallContext,
} from '@a2a-js/sdk/server';
import {
  type AgentExtensionDeclaration,
  AUDIT_SESSION_IN_USE,
  admitLaterRequest,
  admitNewTask,
  auditRequestMetadata,
  auditSessionMetadata,
  auditStatusMetadata,
  isAudited,
  type Rejection,
  type SessionUse,
} from '../admission';
import {
  type AuditCredentials,
  type AuditRequest,
  type AuditSession,
  type AuditStatus,
  auditRequestSchema,
  auditSessionSchema,
  EXTENSION_URI,
} from '../models';

/** The validation error of §4.4, carried in the A2A `ErrorInfo`'s `metadata`, which both official SDKs deliver. */
export function rejectionError(rejection: Rejection): Error {
  return new RequestMalformedError({
    message: `${rejection.field} ${rejection.description}`,
    metadata: {
      auditField: rejection.field,
      ...(rejection.sessionInUse === undefined
        ? {}
        : { auditReason: AUDIT_SESSION_IN_USE, auditTaskId: rejection.sessionInUse.taskId }),
    },
  });
}

function auditSessionOf(task: Pick<Task, 'metadata'> | undefined): AuditSession | undefined {
  const own = task?.metadata?.[EXTENSION_URI] as Record<string, unknown> | undefined;
  const parsed = auditSessionSchema.safeParse(own?.auditSession);
  return parsed.success ? parsed.data : undefined;
}

export interface AuditedRequestHandlerOptions {
  /** What the Server Agent declares (§3); the same entry must be in its Agent Card. */
  declaration: Pick<AgentExtensionDeclaration, 'required' | 'params'>;
  /**
   * Who already uses a `sessionId` (§4.3 condition 5). Look up and reserve it in one atomic step, or two
   * concurrent requests bind one session to two Tasks.
   */
  sessionInUse: (sessionId: string, context: ServerCallContext) => Promise<SessionUse | undefined>;
  /** Replace the running Task's endpoint credentials (§5.7); the request's Message is then processed as usual. */
  onCredentials: (taskId: string, credentials: AuditCredentials) => Promise<void>;
}

/**
 * Wrap the SDK's request handler so that each request is decided as §4.3 - §4.6 direct before the SDK takes it.
 *
 * @throws {A2AError} From `sendMessage` and `sendMessageStream`: `RequestMalformedError` for a request §4.4 or
 *   §4.6 rejects, and `ExtensionSupportRequiredError` under the mandatory posture (§4.5).
 */
export function auditedRequestHandler(
  inner: A2ARequestHandler,
  options: AuditedRequestHandlerOptions,
): A2ARequestHandler {
  const requested = (context: ServerCallContext) => context.requestedExtensions ?? [];
  // Under the mandatory posture, every request lists this extension, or A2A refuses it (§4.6, A2A §3.3.4).
  const requireActivation = (context: ServerCallContext) => {
    if (options.declaration.required && !requested(context).includes(EXTENSION_URI)) {
      throw new ExtensionSupportRequiredError(`this agent requires the extension ${EXTENSION_URI}`);
    }
  };
  const activateFor = async (taskId: string, context: ServerCallContext, tenant: string): Promise<void> => {
    if (!requested(context).includes(EXTENSION_URI)) return;
    if (auditSessionOf(await inner.getTask({ tenant, id: taskId }, context)) !== undefined) {
      context.addActivatedExtension(EXTENSION_URI);
    }
  };

  const admit = async (params: SendMessageRequest, context: ServerCallContext): Promise<void> => {
    const taskId = params.message?.taskId;
    if (taskId === undefined || taskId === '') {
      const admission = await admitNewTask({
        declaration: options.declaration,
        requestedExtensions: requested(context),
        metadata: params.metadata,
        sessionInUse: (sessionId) => options.sessionInUse(sessionId, context),
      });
      switch (admission.kind) {
        case 'ordinary':
          return;
        case 'unsupported':
          throw new ExtensionSupportRequiredError(`this agent requires the extension ${EXTENSION_URI}`);
        case 'invalid':
          throw rejectionError(admission.rejection);
        case 'negotiated':
          context.addActivatedExtension(EXTENSION_URI);
          return;
      }
    }
    requireActivation(context);
    const task = await inner.getTask({ tenant: params.tenant, id: taskId }, context);
    const admission = admitLaterRequest({
      requestedExtensions: requested(context),
      metadata: params.metadata,
      auditNegotiated: auditSessionOf(task) !== undefined,
    });
    switch (admission.kind) {
      case 'invalid':
        throw rejectionError(admission.rejection);
      case 'credentials':
        await options.onCredentials(taskId, admission.credentials);
        context.addActivatedExtension(EXTENSION_URI);
        return;
      case 'continue':
        if (admission.activate) context.addActivatedExtension(EXTENSION_URI);
        return;
    }
  };

  return {
    getAgentCard: () => inner.getAgentCard(),
    getAuthenticatedExtendedAgentCard: (params, context) => inner.getAuthenticatedExtendedAgentCard(params, context),
    sendMessage: async (params, context) => {
      await admit(params, context);
      return inner.sendMessage(params, context);
    },
    // The SDK writes `A2A-Extensions` when this returns, so activation must be synchronous; the decision runs
    // first in the stream. A later request on a Task cannot be activated here: that needs the stored Task (§4.3).
    sendMessageStream: (params, context) => {
      const own = params.metadata?.[EXTENSION_URI] as Record<string, unknown> | undefined;
      const creates = params.message?.taskId === undefined || params.message.taskId === '';
      if (creates && requested(context).includes(EXTENSION_URI) && own?.auditRequest !== undefined) {
        context.addActivatedExtension(EXTENSION_URI);
      }
      return (async function* (): AsyncGenerator<StreamResponse, void, undefined> {
        await admit(params, context);
        yield* inner.sendMessageStream(params, context);
      })();
    },
    getTask: async (params, context) => {
      requireActivation(context);
      const task = await inner.getTask(params, context);
      if (requested(context).includes(EXTENSION_URI) && auditSessionOf(task) !== undefined) {
        context.addActivatedExtension(EXTENSION_URI);
      }
      return task;
    },
    cancelTask: async (params, context) => {
      requireActivation(context);
      await activateFor(params.id, context, params.tenant);
      return inner.cancelTask(params, context);
    },
    createTaskPushNotificationConfig: async (params, context) => {
      requireActivation(context);
      return inner.createTaskPushNotificationConfig(params, context);
    },
    getTaskPushNotificationConfig: async (params, context) => {
      requireActivation(context);
      return inner.getTaskPushNotificationConfig(params, context);
    },
    listTaskPushNotificationConfigs: async (params, context) => {
      requireActivation(context);
      return inner.listTaskPushNotificationConfigs(params, context);
    },
    deleteTaskPushNotificationConfig: async (params, context) => {
      requireActivation(context);
      return inner.deleteTaskPushNotificationConfig(params, context);
    },
    resubscribe: (params, context) => {
      requireActivation(context);
      return inner.resubscribe(params, context);
    },
    listTasks: async (params, context) => {
      requireActivation(context);
      return inner.listTasks(params, context);
    },
  };
}

/** What an executor receives of this extension for the request it runs. */
export interface AuditContext {
  auditSession: AuditSession;
  /** The validated `auditRequest`, on the request that created the Task only; the credentials are in it. */
  request?: AuditRequest;
}

/** An executor that runs an audit-negotiated Task; `audit` is undefined for an ordinary one (§4.5). */
export interface AuditedAgentExecutor {
  execute(requestContext: RequestContext, eventBus: ExecutionEventBus, audit: AuditContext | undefined): Promise<void>;
  cancelTask(taskId: string, eventBus: ExecutionEventBus): Promise<void>;
}

function auditContextOf(requestContext: RequestContext): AuditContext | undefined {
  // An audit-negotiated Task stays audited whatever a later request lists (§4.3, §8.1).
  const existing = auditSessionOf(requestContext.task);
  if (existing !== undefined) return { auditSession: existing };
  if (!(requestContext.context.activatedExtensions ?? []).includes(EXTENSION_URI)) return undefined;
  const own = requestContext.request.metadata?.[EXTENSION_URI] as Record<string, unknown> | undefined;
  const parsed = auditRequestSchema.safeParse(own?.auditRequest);
  if (!parsed.success) return undefined;
  const request = parsed.data;
  return {
    auditSession: { sessionId: request.sessionId, level: request.level, countersign: request.countersign },
    request,
  };
}

/**
 * Wrap an executor so that every Task it publishes for an audit-negotiated request, and a direct `Message` it
 * answers one with, carries `auditSession` (§4.3).
 */
export function auditedExecutor(inner: AuditedAgentExecutor): AgentExecutor {
  return {
    execute: async (requestContext, eventBus) => {
      const audit = auditContextOf(requestContext);
      if (audit === undefined) {
        await inner.execute(requestContext, eventBus, undefined);
        return;
      }
      const metadata = auditSessionMetadata(audit.auditSession);
      const bus = Object.create(eventBus) as ExecutionEventBus;
      bus.publish = (event: AgentExecutionEvent) => {
        if (event.kind === 'task' || event.kind === 'message') {
          event.data.metadata = { ...event.data.metadata, ...metadata };
        }
        eventBus.publish(event);
      };
      await inner.execute(requestContext, bus, audit);
    },
    cancelTask: (taskId, eventBus) => inner.cancelTask(taskId, eventBus),
  };
}

/** The status update that holds a Task for audit (§8.4): `TASK_STATE_AUTH_REQUIRED`, annotated with `auditStatus`. */
export function heldForAudit(
  task: { taskId: string; contextId: string },
  status: AuditStatus,
  text = 'The next step cannot be recorded in your audit ledger, so it has not been taken.',
): TaskStatusUpdateEvent {
  return TaskStatusUpdateEvent.fromJSON({
    taskId: task.taskId,
    contextId: task.contextId,
    status: {
      state: 'TASK_STATE_AUTH_REQUIRED',
      timestamp: new Date().toISOString(),
      message: Message.toJSON(
        Message.fromJSON({
          messageId: crypto.randomUUID(),
          contextId: task.contextId,
          taskId: task.taskId,
          role: 'ROLE_AGENT',
          parts: [{ text }],
          metadata: auditStatusMetadata(status),
        }),
      ),
    },
  });
}

/** The status update that resumes a Task once nothing is held (§8.4). */
export function resumedFromHold(task: { taskId: string; contextId: string }): TaskStatusUpdateEvent {
  return TaskStatusUpdateEvent.fromJSON({
    taskId: task.taskId,
    contextId: task.contextId,
    status: { state: 'TASK_STATE_WORKING', timestamp: new Date().toISOString() },
  });
}

/** What a Client reads of a §4.4 rejection: the field, and the Task a reused `sessionId` belongs to. */
export interface ReadRejection {
  field: string;
  /** Present only when the Server Agent named the Task as the same Client's (§4.4). */
  sessionInUse?: { taskId: string };
}

/**
 * Read a §4.4 rejection from an error the SDK's client threw: the `ErrorInfo` `metadata` is on the error itself
 * over HTTP+JSON, and in its `data` details over JSON-RPC.
 */
export function readRejection(error: unknown): ReadRejection | undefined {
  if (typeof error !== 'object' || error === null) return undefined;
  const carrier = error as { metadata?: unknown; data?: unknown };
  const fromData = Array.isArray(carrier.data)
    ? (carrier.data as Array<Record<string, unknown>>).find((detail) =>
        String(detail['@type'] ?? '').endsWith('google.rpc.ErrorInfo'),
      )?.metadata
    : undefined;
  const metadata = (carrier.metadata ?? fromData) as Record<string, unknown> | undefined;
  if (typeof metadata?.auditField !== 'string') return undefined;
  return {
    field: metadata.auditField,
    ...(metadata.auditReason === AUDIT_SESSION_IN_USE && typeof metadata.auditTaskId === 'string'
      ? { sessionInUse: { taskId: metadata.auditTaskId } }
      : {}),
  };
}

/** Delegate with this extension activated and `request` attached, and say whether the answer is audited (§4.3). */
export async function sendAudited(
  client: Client,
  params: SendMessageRequest,
  request: AuditRequest,
): Promise<{ result: Message | Task; audited: boolean }> {
  const result = await client.sendMessage(
    { ...params, metadata: { ...params.metadata, ...auditRequestMetadata(request) } },
    { serviceParameters: ServiceParameters.create(withA2AExtensions(EXTENSION_URI)) },
  );
  const audited = isAudited(request, result.metadata);
  return { result, audited };
}
