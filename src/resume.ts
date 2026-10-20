/**
 * Resumption of a Task after a Server Agent restart (§5.5), steps 1 - 4 and 6; step 5 is the caller's. An accept
 * first received on a step-2 resend is reported `not-performed`.
 */

import {
  type AcceptResponse,
  AmcpAbortedError,
  type AttemptResponse,
  computeRecordHash,
  countersignaturePayload,
  type Deps,
  type EventSigner,
  SystemDeps,
} from 'auditable-mcp-sdk';
import { AuditedTask, RESTORE_ACCEPTS } from './audited-task';
import { EXECUTION_REPORT_ACTION_TYPE, Execution } from './execution-report';
import { type FetchHostKeys, fetchHostKeysWith, HostKeysVerifier } from './host-keys';
import { type AuditRequest, type AuditStatus, type AuthenticationInfo, Countersign, Level } from './models';
import { checkPosition } from './position';
import { type JournalEntry, type SelfLedger, SelfLedgerError } from './self-ledger';

export interface ResumeOptions {
  /** The Task's partition of the Server Agent's own ledger. */
  selfLedger: SelfLedger;
  /** The endpoint's credentials, from where the Server Agent holds them as secrets (§13.2). */
  credentials: { authentication: AuthenticationInfo; token?: string };
  /** Under Level 2, the signer of the key the session is bound to (§5.2). */
  signer?: EventSigner;
  /** The Task was in a terminal state at the restart: resumption only delivers (§5.5). */
  terminal?: boolean;
  deps?: Deps;
  timeoutMs?: number;
  fetch?: typeof fetch;
  /** Fetches `hostKeys` again for a `kid` the Task's own ledger does not hold (§10.2); see `AuditedTaskOptions`. */
  fetchHostKeys?: FetchHostKeys;
}

/** What the caller does next (§5.5). */
export type ResumeResult =
  | {
      /** Continue the Task (step 6); or, for a Task already terminal, delivery is done. */
      state: 'continue' | 'delivered';
      task: AuditedTask;
      /** Accesses reported `not-performed`, which may be attempted again (step 5). */
      notPerformed: string[];
      /** Accesses reported `indeterminate`, to settle before any new attempt (§8.6). */
      indeterminate: string[];
    }
  /** The own ledger shows the close: complete the move to the terminal state (step 6). */
  | { state: 'closed'; task: AuditedTask }
  /** The audit host could not be reached: hold the Task with `status` and resume again later. */
  | { state: 'held'; step: 2 | 3 | 4 | 6; status: AuditStatus }
  /** A check failed: move the Task to `TASK_STATE_FAILED`. */
  | { state: 'failed'; reason: ResumeFailure };

export type ResumeFailure =
  | 'own-ledger'
  | 'key-changed'
  | 'position-refused'
  | 'no-matching-event'
  | 'later-accept'
  | 'empty-with-accepts'
  | 'position-uncountersigned'
  | 'position-signature-invalid'
  | 'session-expired';

const SIGNATURE_FIELDS = ['signature', 'key_id', 'signer_seq'] as const;

interface Restored {
  taskId: string;
  request: AuditRequest;
  keyId: string | undefined;
  hostKeySnapshot: { keys: Record<string, unknown>[] } | undefined;
  sent: Record<string, unknown>[];
  attempts: Map<string, Record<string, unknown>>;
  outcomes: Map<string, Record<string, unknown>>;
  responses: Map<string, Record<string, unknown>>;
  performing: Set<string>;
  records: Set<string>;
  resolved: Map<string, 'success' | 'failed'>;
  acked: Set<string>;
  closed: boolean;
  nextSignerSeq: number;
}

function restore(entries: JournalEntry[], credentials: ResumeOptions['credentials']): Restored {
  const [first, ...rest] = entries;
  if (first?.entry !== 'session') {
    throw new SelfLedgerError('the own ledger does not begin with the session');
  }
  const restored: Restored = {
    taskId: first.taskId,
    request: {
      ...first.request,
      auditEndpoint: {
        url: first.request.auditEndpoint.url,
        authentication: credentials.authentication,
        ...(credentials.token === undefined ? {} : { token: credentials.token }),
      },
    },
    keyId: first.keyId,
    hostKeySnapshot: first.hostKeySnapshot,
    sent: [],
    attempts: new Map(),
    outcomes: new Map(),
    responses: new Map(),
    performing: new Set(),
    records: new Set(),
    resolved: new Map(),
    acked: new Set(),
    closed: false,
    nextSignerSeq: 0,
  };
  for (const entry of rest) {
    switch (entry.entry) {
      case 'session':
        throw new SelfLedgerError('the own ledger holds a second session');
      case 'sent': {
        const event = entry.event;
        restored.sent.push(event);
        (event.outcome === 'attempted' ? restored.attempts : restored.outcomes).set(String(event.id), event);
        if (typeof event.signer_seq === 'number') {
          restored.nextSignerSeq = Math.max(restored.nextSignerSeq, event.signer_seq + 1);
        }
        break;
      }
      case 'response':
        restored.responses.set(entry.id, entry.response);
        break;
      case 'performing':
        restored.performing.add(entry.id);
        break;
      case 'record':
        restored.records.add(entry.id);
        break;
      case 'resolved':
        restored.resolved.set(entry.id, entry.outcome);
        break;
      case 'acked':
        restored.acked.add(entry.id);
        break;
      case 'close':
        restored.closed = true;
        break;
    }
  }
  return restored;
}

function isAccept(response: unknown): response is AcceptResponse {
  return typeof response === 'object' && response !== null && (response as { status?: unknown }).status === 'accept';
}

function reportedAttemptOf(event: Record<string, unknown>): string | undefined {
  if (event.action_type !== EXECUTION_REPORT_ACTION_TYPE) return undefined;
  const context = event.action_context as { attemptId?: unknown } | undefined;
  return typeof context?.attemptId === 'string' ? context.attemptId : undefined;
}

/**
 * Resume a Task from its own ledger after a Server Agent restart (§5.5).
 *
 * @throws {SelfLedgerError} An entry could not be written while resuming. Nothing it would have preceded was done;
 *   resume again, which repeats no step whose effect the ledger holds.
 */
export async function resumeTask(options: ResumeOptions): Promise<ResumeResult> {
  const deps = options.deps ?? new SystemDeps();

  // Step 1.
  let restored: Restored;
  try {
    restored = restore(await options.selfLedger.entries(), options.credentials);
  } catch (error) {
    if (error instanceof SelfLedgerError) return { state: 'failed', reason: 'own-ledger' };
    throw error;
  }
  const { request } = restored;
  if (restored.keyId !== options.signer?.keyId || (request.level === Level.L2) !== (options.signer !== undefined)) {
    return { state: 'failed', reason: 'key-changed' };
  }
  const task = new AuditedTask({
    taskId: restored.taskId,
    request,
    selfLedger: options.selfLedger,
    resumed: { nextSignerSeq: restored.nextSignerSeq },
    ...(options.signer === undefined ? {} : { signer: options.signer }),
    ...(restored.hostKeySnapshot === undefined ? {} : { hostKeySnapshot: restored.hostKeySnapshot }),
    ...(options.deps === undefined ? {} : { deps: options.deps }),
    ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
    ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
    ...(options.fetchHostKeys === undefined ? {} : { fetchHostKeys: options.fetchHostKeys }),
  });
  const client = task.client;
  const countersignatures =
    request.countersign === Countersign.HOST && restored.hostKeySnapshot !== undefined
      ? new HostKeysVerifier(
          request.hostKeys as string,
          restored.hostKeySnapshot,
          options.fetchHostKeys ?? fetchHostKeysWith(options.fetch, options.timeoutMs),
        )
      : undefined;
  const held = (step: 2 | 3 | 4 | 6, about?: { attempt?: string; outcome?: string }): ResumeResult => {
    const failure =
      about?.attempt !== undefined
        ? client.attemptFailureOf(about.attempt)
        : about?.outcome !== undefined
          ? client.outcomeFailureOf(about.outcome)
          : client.lastFailure;
    const attemptId = about?.attempt ?? about?.outcome;
    return {
      state: 'held',
      step,
      status: {
        reason: 'host-unavailable',
        ...(failure?.httpStatus === undefined || failure.httpStatus === 200 ? {} : { httpStatus: failure.httpStatus }),
        ...(attemptId === undefined ? {} : { attemptId }),
      },
    };
  };

  // Step 2. An attempt answered by an aborted outcome was given up before the restart; one answered `unavailable`
  // was decided by nothing, and is resent as one never answered is (a-MCP §7.1).
  const acceptedBefore = new Set(
    [...restored.responses].filter(([, response]) => isAccept(response)).map(([id]) => id),
  );
  const answered = (id: string) => restored.responses.has(id) && restored.responses.get(id)?.status !== 'unavailable';
  const acceptedOnResend = new Map<string, AcceptResponse>();
  // A reject the ledger holds whose aborted outcome was not written before the restart.
  const refused = new Map<string, string>(
    [...restored.responses]
      .filter(([id, response]) => response.status === 'reject' && !restored.outcomes.has(id))
      .map(([id]) => [id, 'host-rejected']),
  );
  for (const event of restored.sent) {
    const id = String(event.id);
    if (event.outcome === 'attempted') {
      if (answered(id) || restored.outcomes.has(id)) continue;
      const response: AttemptResponse = await client.resendAttempt(event);
      if (response.status === 'unavailable') return held(2, { attempt: id });
      if (response.status === 'reject') refused.set(id, 'host-rejected');
      else acceptedOnResend.set(id, response);
    } else if (!restored.acked.has(id)) {
      await client.resendOutcome(event);
      if (client.owed.length > 0) return held(2, { outcome: id });
    }
  }

  // Step 3.
  const position = await client.position();
  if (position === 'refused') return { state: 'failed', reason: 'position-refused' };
  if (position === undefined) return held(3);
  const acceptedSeqs = [
    ...[...acceptedBefore].map((id) => (restored.responses.get(id) as AcceptResponse).seq),
    ...[...acceptedOnResend.values()].map((response) => response.seq),
  ];
  const check = checkPosition(position, { events: restored.sent, acceptedSeqs });
  if (!check.ok) return { state: 'failed', reason: check.reason };
  if (request.countersign === Countersign.HOST && position.last !== null) {
    const last = position.last;
    if (last.host_signature === undefined || countersignatures === undefined) {
      return { state: 'failed', reason: 'position-uncountersigned' };
    }
    const payload = countersignaturePayload(
      last.seq,
      last.host_ts,
      last.log_id as string,
      last.previous_hash,
      last.record_hash,
    );
    const verdict = await countersignatures.verify(last.host_key_id as string, last.host_signature, payload);
    if (verdict === 'unavailable') return held(3);
    if (!verdict) return { state: 'failed', reason: 'position-signature-invalid' };
  }

  // a-MCP §7.2: check an accept received on a resend, and one held without an outcome (the restart may have
  // fallen between its arrival and the abort of a failed check).
  const unchecked = new Map<string, AcceptResponse>([
    // A `performing` access passed the check and may have happened; rechecking under changed keys would abort it.
    ...[...acceptedBefore]
      .filter((id) => !restored.outcomes.has(id) && !restored.performing.has(id))
      .map((id): [string, AcceptResponse] => [id, restored.responses.get(id) as AcceptResponse]),
    ...acceptedOnResend,
  ]);
  for (const [id, response] of unchecked) {
    const attempt = restored.attempts.get(id) as Record<string, unknown>;
    let refusal: string | undefined;
    if (request.countersign === Countersign.HOST) {
      if (response.host_signature === undefined || countersignatures === undefined) {
        refusal = 'host-uncountersigned';
      } else {
        const payload = countersignaturePayload(
          response.seq,
          response.host_ts,
          response.log_id as string,
          response.previous_hash,
          response.record_hash,
        );
        const verdict = await countersignatures.verify(
          response.host_key_id as string,
          response.host_signature,
          payload,
        );
        if (verdict === 'unavailable') return held(2, { attempt: id });
        if (!verdict) refusal = 'host-signature-invalid';
      }
    }
    if (
      refusal === undefined &&
      computeRecordHash(attempt, response.seq, response.host_ts, response.previous_hash) !== response.record_hash
    ) {
      refusal = 'hash-mismatch';
    }
    if (refusal !== undefined) {
      acceptedOnResend.delete(id);
      acceptedBefore.delete(id);
      refused.set(id, refusal);
    }
  }

  // Step 4.
  const sendOutcome = async (attempt: Record<string, unknown>, outcome: string, reason?: string): Promise<boolean> => {
    const event: Record<string, unknown> = { ...attempt, ts: deps.now(), outcome };
    for (const field of SIGNATURE_FIELDS) delete event[field];
    if (reason !== undefined) event.reason = reason;
    const signer = options.signer;
    const numbering = client.numbering;
    if (signer !== undefined && numbering !== undefined) {
      await numbering.run(async (signerSeq) => client.sendOutcome(await signer.sign(event, signerSeq)));
    } else {
      await client.sendOutcome(event);
    }
    return client.owed.length === 0;
  };
  const reported = new Set(
    [...restored.attempts.values()]
      .filter((event) => {
        const id = String(event.id);
        return (acceptedBefore.has(id) || acceptedOnResend.has(id)) && restored.outcomes.get(id)?.outcome !== 'aborted';
      })
      .map(reportedAttemptOf)
      .filter((id): id is string => id !== undefined),
  );
  task[RESTORE_ACCEPTS](
    [...acceptedBefore, ...acceptedOnResend.keys()].filter(
      (id) =>
        reportedAttemptOf(restored.attempts.get(id) ?? {}) === undefined &&
        !restored.outcomes.has(id) &&
        !restored.records.has(id),
    ),
    reported,
  );
  const notPerformed: string[] = [];
  const indeterminate: string[] = [];
  for (const [id, reason] of refused) {
    if (!(await sendOutcome(restored.attempts.get(id) as Record<string, unknown>, 'aborted', reason))) {
      return held(4, { outcome: id });
    }
  }
  for (const id of [...acceptedBefore, ...acceptedOnResend.keys()]) {
    if (restored.outcomes.has(id)) continue;
    const attempt = restored.attempts.get(id);
    if (attempt === undefined) continue;
    // A report, and a record that is not an access (§8.1), is completed with its `success` outcome, not reported on.
    if (attempt.action_type === EXECUTION_REPORT_ACTION_TYPE || restored.records.has(id)) {
      if (!(await sendOutcome(attempt, 'success'))) return held(4, { outcome: id });
      continue;
    }
    if (reported.has(id)) continue;
    const resolved = restored.resolved.get(id);
    if (resolved !== undefined && acceptedBefore.has(id)) {
      if (!(await sendOutcome(attempt, resolved))) return held(4, { outcome: id });
      continue;
    }
    const execution =
      acceptedBefore.has(id) && restored.performing.has(id) ? Execution.INDETERMINATE : Execution.NOT_PERFORMED;
    try {
      await task.reportExecution(id, execution);
    } catch (error) {
      if (error instanceof AmcpAbortedError) return { state: 'held', step: 4, status: task.statusOf(error, id) };
      throw error;
    }
    (execution === Execution.INDETERMINATE ? indeterminate : notPerformed).push(id);
  }

  // Step 6.
  if (restored.closed) {
    return (await client.close()) ? { state: 'closed', task } : held(6);
  }
  if (options.terminal === true) {
    return { state: 'delivered', task, notPerformed, indeterminate };
  }
  if (Date.parse(deps.now()) >= Date.parse(request.expiresAt)) {
    return { state: 'failed', reason: 'session-expired' };
  }
  return { state: 'continue', task, notPerformed, indeterminate };
}
