/** The decisions on the A2A messages (§3, §4, §7), on plain JSON; `auditable-a2a-sdk/a2a` binds them to an SDK. */

import type { z } from 'zod';
import {
  type AgentCardParams,
  type AuditCredentials,
  type AuditRequest,
  type AuditSession,
  type AuditStatus,
  agentCardParamsSchema,
  auditCredentialsSchema,
  auditRequestSchema,
  auditSessionSchema,
  auditStatusSchema,
  EXTENSION_URI,
} from './models';
import { negotiate } from './negotiate';

/** The `auditReason` naming the Task a reused `sessionId` belongs to (§4.4). */
export const AUDIT_SESSION_IN_USE = 'AUDIT_SESSION_IN_USE';

/**
 * A validation error's details (§4.4): the field that failed, and, for a `sessionId` the same Client already used,
 * the Task that used it. A binding carries them in the `metadata` of A2A's own `ErrorInfo`.
 */
export interface Rejection {
  field: string;
  description: string;
  sessionInUse?: { taskId: string };
}

/** The Agent Card entry declaring this extension (§3). */
export interface AgentExtensionDeclaration {
  uri: string;
  description?: string;
  required: boolean;
  params: AgentCardParams;
}

/** What the Server Agent declares in `capabilities.extensions` (§3); `required` is the mandatory posture (§4.5). */
export function agentCardExtension(
  params: AgentCardParams,
  options: { required: boolean; description?: string },
): AgentExtensionDeclaration {
  return {
    uri: EXTENSION_URI,
    ...(options.description === undefined ? {} : { description: options.description }),
    required: options.required,
    params: agentCardParamsSchema.parse(params),
  };
}

/** Who already uses a `sessionId`, as the Server Agent's Task store answers (§4.3 condition 5, §4.4). */
export interface SessionUse {
  taskId: string;
  /** The Task was created by the same authenticated Client as this request. */
  sameClient: boolean;
}

export type NewTaskAdmission =
  /** Not activated: serve as an ordinary A2A agent (§4.5). */
  | { kind: 'ordinary' }
  /** Not activated under the mandatory posture: `ExtensionSupportRequiredError` (§4.5). */
  | { kind: 'unsupported' }
  /** Activated and not negotiated: a validation error, and no Task (§4.4). */
  | { kind: 'invalid'; rejection: Rejection }
  /** Audit-negotiated (§4.3): list the URI in the response and place `auditSession` in every Task returned. */
  | { kind: 'negotiated'; request: AuditRequest; auditSession: AuditSession };

export type LaterRequestAdmission =
  /** Nothing of this extension to act on; `activate` says whether to list the URI in the response (§4.3). */
  | { kind: 'continue'; activate: boolean }
  /** Replace the endpoint's credentials and nothing else (§4.6, §5.7). */
  | { kind: 'credentials'; credentials: AuditCredentials }
  | { kind: 'invalid'; rejection: Rejection };

const fieldOf = (member: string, path: readonly PropertyKey[] = []): string =>
  [`metadata[${JSON.stringify(EXTENSION_URI)}]`, member, ...path.map(String)].filter((part) => part !== '').join('.');

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

type Own =
  | { present: false }
  | { present: true; own: Record<string, unknown> }
  | { present: true; rejection: Rejection };

/** This extension's member of a request's `metadata`: absent, an object, or something to reject. */
function extensionMetadata(metadata: unknown): Own {
  if (!isObject(metadata) || !(EXTENSION_URI in metadata)) return { present: false };
  const own = metadata[EXTENSION_URI];
  return isObject(own)
    ? { present: true, own }
    : { present: true, rejection: { field: fieldOf(''), description: 'must be an object' } };
}

function rejectionOf(member: string, error: z.ZodError): Rejection {
  const issue = error.issues[0];
  return { field: fieldOf(member, issue?.path ?? []), description: issue?.message ?? 'is not valid' };
}

export interface NewTaskInput {
  /** What the Server Agent declares (§3). */
  declaration: Pick<AgentExtensionDeclaration, 'required' | 'params'>;
  /** The URIs the request lists in `A2A-Extensions` (§4.2). */
  requestedExtensions: readonly string[];
  /** The request's `SendMessageRequest.metadata`. */
  metadata: unknown;
  /** Who already uses a `sessionId`, if anyone (§4.3 condition 5). */
  sessionInUse: (sessionId: string) => SessionUse | undefined | Promise<SessionUse | undefined>;
}

/** Decide a request that creates a Task (§4.3 - §4.5). */
export async function admitNewTask(input: NewTaskInput): Promise<NewTaskAdmission> {
  const found = extensionMetadata(input.metadata);
  if (!input.requestedExtensions.includes(EXTENSION_URI)) {
    // §4.4: the extension's metadata without the activation means the activation was lost.
    const carried =
      found.present && 'own' in found
        ? (['auditRequest', 'auditCredentials'] as const).find((member) => member in found.own)
        : undefined;
    if (carried !== undefined) {
      return {
        kind: 'invalid',
        rejection: { field: fieldOf(carried), description: 'requires this extension in A2A-Extensions' },
      };
    }
    return input.declaration.required ? { kind: 'unsupported' } : { kind: 'ordinary' };
  }
  if (!found.present) {
    return { kind: 'invalid', rejection: { field: fieldOf('auditRequest'), description: 'is required' } };
  }
  if ('rejection' in found) return { kind: 'invalid', rejection: found.rejection };
  const { own } = found;
  if ('auditCredentials' in own) {
    return {
      kind: 'invalid',
      rejection: { field: fieldOf('auditCredentials'), description: 'replaces credentials of an existing Task only' },
    };
  }
  const parsed = auditRequestSchema.safeParse(own.auditRequest);
  if (!parsed.success) {
    return own.auditRequest === undefined
      ? { kind: 'invalid', rejection: { field: fieldOf('auditRequest'), description: 'is required' } }
      : { kind: 'invalid', rejection: rejectionOf('auditRequest', parsed.error) };
  }
  const request = parsed.data;
  const fit = negotiate(input.declaration.params, request);
  if (!fit.negotiated) {
    return {
      kind: 'invalid',
      rejection: {
        field: fieldOf('auditRequest', [fit.field]),
        description:
          fit.field === 'level'
            ? `the Server Agent attests at ${input.declaration.params.level}`
            : 'the Server Agent requires countersign "host"',
      },
    };
  }
  const use = await input.sessionInUse(request.sessionId);
  if (use !== undefined) {
    return {
      kind: 'invalid',
      rejection: {
        field: fieldOf('auditRequest', ['sessionId']),
        description: 'is already used for another Task',
        // Another Client's Task is never named (A2A §3.3.2).
        ...(use.sameClient ? { sessionInUse: { taskId: use.taskId } } : {}),
      },
    };
  }
  return {
    kind: 'negotiated',
    request,
    auditSession: { sessionId: request.sessionId, level: request.level, countersign: request.countersign },
  };
}

export interface LaterRequestInput {
  requestedExtensions: readonly string[];
  metadata: unknown;
  /** Whether the Task the request is on is audit-negotiated. */
  auditNegotiated: boolean;
}

/** Decide a request on an existing Task (§4.6). */
export function admitLaterRequest(input: LaterRequestInput): LaterRequestAdmission {
  const activated = input.requestedExtensions.includes(EXTENSION_URI);
  const found = extensionMetadata(input.metadata);
  if (!found.present) return { kind: 'continue', activate: activated && input.auditNegotiated };
  if ('rejection' in found) return { kind: 'invalid', rejection: found.rejection };
  const { own } = found;
  if ('auditRequest' in own) {
    return {
      kind: 'invalid',
      rejection: { field: fieldOf('auditRequest'), description: 'negotiates a new Task only' },
    };
  }
  if (!('auditCredentials' in own)) return { kind: 'continue', activate: activated && input.auditNegotiated };
  if (!activated || !input.auditNegotiated) {
    return {
      kind: 'invalid',
      rejection: {
        field: fieldOf('auditCredentials'),
        description: activated ? 'the Task is not audit-negotiated' : 'requires this extension in A2A-Extensions',
      },
    };
  }
  const parsed = auditCredentialsSchema.safeParse(own.auditCredentials);
  return parsed.success
    ? { kind: 'credentials', credentials: parsed.data }
    : { kind: 'invalid', rejection: rejectionOf('auditCredentials', parsed.error) };
}

/** `metadata` carrying `member` keyed by the extension URI (§7). */
const keyed = (member: string, value: unknown): Record<string, unknown> => ({ [EXTENSION_URI]: { [member]: value } });

/** The Task's `metadata` for an audit-negotiated Task (§7.2). */
export const auditSessionMetadata = (session: AuditSession): Record<string, unknown> => keyed('auditSession', session);
/** The held Task's status message `metadata` (§7.3). */
export const auditStatusMetadata = (status: AuditStatus): Record<string, unknown> => keyed('auditStatus', status);
/** The Client's request `metadata` that negotiates a Task (§4.2, §7.1). */
export const auditRequestMetadata = (request: AuditRequest): Record<string, unknown> =>
  keyed('auditRequest', auditRequestSchema.parse(request));
/** The Client's request `metadata` that replaces the endpoint's credentials (§5.7, §7.4). */
export const auditCredentialsMetadata = (credentials: AuditCredentials): Record<string, unknown> =>
  keyed('auditCredentials', auditCredentialsSchema.parse(credentials));

function member<T>(metadata: unknown, name: string, schema: z.ZodType<T>): T | undefined {
  if (!isObject(metadata)) return undefined;
  const own = metadata[EXTENSION_URI];
  if (!isObject(own)) return undefined;
  const parsed = schema.safeParse(own[name]);
  return parsed.success ? parsed.data : undefined;
}

/** What the Client does about a held Task (§8.5). */
export const HoldRemedy = {
  REPLACE_CREDENTIALS: 'replace-credentials',
  RESTORE_HOST: 'restore-host',
  DELEGATE_AGAIN: 'delegate-again',
  NOTHING_RESTORES: 'nothing-restores',
  NONE: 'none',
  INVESTIGATE_HOST: 'investigate-host',
} as const;
export type HoldRemedy = (typeof HoldRemedy)[keyof typeof HoldRemedy];

/** The row of §8.5's table an `auditStatus` falls in. */
export function holdRemedy(status: AuditStatus): HoldRemedy {
  switch (status.reason) {
    case 'host-unavailable':
      return status.httpStatus === 401 ? HoldRemedy.REPLACE_CREDENTIALS : HoldRemedy.RESTORE_HOST;
    case 'host-rejected':
      if (status.hostReason === 'unknown-key') return HoldRemedy.DELEGATE_AGAIN;
      if (status.hostReason === 'replay-detected') return HoldRemedy.NOTHING_RESTORES;
      return HoldRemedy.NONE;
    default:
      return HoldRemedy.INVESTIGATE_HOST;
  }
}

/** The Client's reading of a held Task's status message `metadata` (§7.3), with what to do about it (§8.5). */
export function readAuditStatus(metadata: unknown): { status: AuditStatus; remedy: HoldRemedy } | undefined {
  const status = member(metadata, 'auditStatus', auditStatusSchema);
  return status === undefined ? undefined : { status, remedy: holdRemedy(status) };
}

/**
 * Whether the Task or direct `Message` returned for a request that activated this extension is audited under
 * `request` (§4.3): its `metadata` carries an `auditSession` naming the session, level, and countersignature
 * setting of the request. A Client that requires audit treats any other answer as not audited.
 */
export function isAudited(
  request: Pick<AuditRequest, 'sessionId' | 'level' | 'countersign'>,
  taskMetadata: unknown,
): boolean {
  const session = member(taskMetadata, 'auditSession', auditSessionSchema);
  return (
    session !== undefined &&
    session.sessionId === request.sessionId &&
    session.level === request.level &&
    session.countersign === request.countersign
  );
}
