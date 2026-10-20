/**
 * One audit-negotiated Task on the Server Agent (§5, §8): an a-MCP `AmcpSession` over the Task's audit endpoint,
 * with Polluted Stop (§8.3), `auditStatus` (§7.3, §8.4), execution reports (§8.6), the terminal-state check
 * (§5.4), and the write-ahead of §5.5.
 */

import {
  AmcpAbortedError,
  AmcpSession,
  type AuditedAction,
  type Deps,
  type EventSigner,
  SessionNumbering,
  SystemDeps,
  type TargetResource,
} from 'auditable-mcp-sdk';
import { AuditEndpointClient, type AuditEndpointClientOptions, type RecordFailure } from './endpoint-client';
import { AUDIT_SESSION_KIND, EXECUTION_REPORT_ACTION_TYPE, type Execution } from './execution-report';
import { type FetchHostKeys, fetchHostKeysWith, type HostKeySet, HostKeysVerifier } from './host-keys';
import {
  ABORT_REASONS,
  type AuditRequest,
  type AuditSession,
  type AuditStatus,
  Countersign,
  HOST_REASONS,
} from './models';
import { type JournalEntry, type SelfLedger, SelfLedgerError } from './self-ledger';

export interface AuditedTaskOptions {
  /** The Task's id, which every submission carries (§6.1). */
  taskId: string;
  /** The validated `auditRequest` the Task was negotiated with (§4.3, §7.1). */
  request: AuditRequest;
  /** Under Level 2, the signer of the Server Agent's attestation key (§10.2). */
  signer?: EventSigner;
  /** Under `countersign: "host"`, the JWKS fetched from `request.hostKeys` (§10.2). */
  hostKeySnapshot?: { keys: Record<string, unknown>[] };
  /** Fetches `request.hostKeys` again for a `kid` the snapshot does not hold (§10.2); default `fetchHostKeysWith`. */
  fetchHostKeys?: FetchHostKeys;
  deps?: Deps;
  /** The bound on each submission's wait (§6.8). */
  timeoutMs?: number;
  /** The `fetch` submissions go through; it must honour `signal`, or the bounded wait (§6.8) does not hold. */
  fetch?: typeof fetch;
  /** The Task's partition of the Server Agent's own ledger, for a Task it may resume (§5.5). */
  selfLedger?: SelfLedger;
  /** Set by `resumeTask`: the session entry is written, and the next event takes `nextSignerSeq` (a-MCP §7.4). */
  resumed?: { nextSignerSeq: number };
}

/** Internal: how `resumeTask` passes the restored accepts to a Task. */
export const RESTORE_ACCEPTS = Symbol('restoreAccepts');

/** The ends a Task's terminal state may be reached by with records still owed (§5.4). */
export const TerminalBound = {
  CANCEL: 'cancel',
  HOLD_TIMEOUT: 'hold-timeout',
  EXPIRY: 'expiry',
  NOT_RESUMING: 'not-resuming',
  KEY_REVOKED: 'key-revoked',
} as const;
export type TerminalBound = (typeof TerminalBound)[keyof typeof TerminalBound];

/** The session has expired (§5.3): the Server Agent does not continue the Task, and moves it to `TASK_STATE_FAILED`. */
export class SessionExpiredError extends Error {
  constructor(expiresAt: string) {
    super(`the audit session expired at ${expiresAt}; the Task is not continued (§5.3)`);
    this.name = 'SessionExpiredError';
  }
}

async function beginsWithSession(selfLedger: SelfLedger): Promise<boolean> {
  try {
    return (await selfLedger.entries())[0]?.entry === 'session';
  } catch (error) {
    if (error instanceof SelfLedgerError) return false;
    throw error;
  }
}

interface Unresolved {
  disposed: boolean;
  reported: boolean;
}

/** The audit of one Task on the Server Agent (§5, §8). */
export class AuditedTask {
  readonly #client: AuditEndpointClient;
  readonly #session: AmcpSession;
  readonly #request: AuditRequest;
  readonly #selfLedger: SelfLedger | undefined;
  readonly #deps: Deps;
  // Attempts awaiting an answer; `finish` must not close under them.
  #pending = 0;
  // Accepted attempts whose outcome is not sent and for which no execution report was accepted (§5.4).
  readonly #unresolved = new Map<string, Unresolved>();
  // §8.6: the accesses accepted, and those with an accepted execution report.
  readonly #accepted = new Set<string>();
  readonly #reported = new Set<string>();
  readonly #reporting = new Set<string>();
  readonly #abortedAttempts = new WeakMap<AmcpAbortedError, string>();
  #lastId: string | undefined;
  // The id a record's attempt is minted with: written ahead before a-MCP sends the attempt (§8.1, §5.5).
  #presetId: string | undefined;
  #journal: ((entry: JournalEntry) => Promise<void>) | undefined;

  /**
   * @throws {Error} `countersign: "host"` without the host's key snapshot, which §8.3 needs to verify
   *   each accept's countersignature.
   */
  constructor(options: AuditedTaskOptions) {
    const { request } = options;
    if (
      request.countersign === Countersign.HOST &&
      (request.hostKeys === undefined || options.hostKeySnapshot === undefined)
    ) {
      throw new Error("a countersigned session verifies against the audit host's keys (§8.3, §10.2)");
    }
    const clientOptions: AuditEndpointClientOptions = {
      url: request.auditEndpoint.url,
      authentication: request.auditEndpoint.authentication,
      taskId: options.taskId,
      level: request.level,
      countersign: request.countersign,
      ...(request.auditEndpoint.token === undefined ? {} : { token: request.auditEndpoint.token }),
      ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
      ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
      ...(options.resumed === undefined ? {} : { numbering: new SessionNumbering(options.resumed.nextSignerSeq) }),
    };
    if (options.selfLedger !== undefined) {
      this.#journal = this.#journalOf(options.selfLedger, options, options.resumed !== undefined);
      clientOptions.journal = this.#journal;
    }
    this.#client = new AuditEndpointClient(clientOptions);
    this.#request = request;
    this.#selfLedger = options.selfLedger;
    const deps = options.deps ?? new SystemDeps();
    this.#deps = deps;
    // a-MCP mints an action's id before its first await, so the attempt id is known even when the call throws.
    const recording: Deps = {
      now: () => deps.now(),
      newId: () => {
        this.#lastId = this.#presetId ?? deps.newId();
        this.#presetId = undefined;
        return this.#lastId;
      },
    };
    const countersigned = request.countersign === Countersign.HOST;
    this.#session = new AmcpSession(this.#client, request.sessionId, {
      // Polluted Stop is REQUIRED at both levels (§8.3).
      pollutedStop: true,
      deps: recording,
      ...(options.signer === undefined ? {} : { signer: options.signer }),
      ...(countersigned
        ? {
            requireCountersign: true,
            countersignatureVerifier: new HostKeysVerifier(
              request.hostKeys as string,
              options.hostKeySnapshot as HostKeySet,
              options.fetchHostKeys ?? fetchHostKeysWith(options.fetch, options.timeoutMs),
            ),
          }
        : {}),
    });
  }

  // §5.5 step 1: the session entry goes first, once.
  #journalOf(
    selfLedger: SelfLedger,
    options: AuditedTaskOptions,
    sessionWritten: boolean,
  ): (entry: JournalEntry) => Promise<void> {
    let session: Promise<void> | undefined = sessionWritten ? Promise.resolve() : undefined;
    return async (entry) => {
      if (session === undefined) {
        const { authentication: _authentication, token: _token, ...endpoint } = options.request.auditEndpoint;
        session = selfLedger
          .write({
            entry: 'session',
            taskId: options.taskId,
            request: { ...options.request, auditEndpoint: endpoint },
            ...(options.signer === undefined ? {} : { keyId: options.signer.keyId }),
            ...(options.hostKeySnapshot === undefined ? {} : { hostKeySnapshot: options.hostKeySnapshot }),
          })
          .catch(async (error: unknown) => {
            // The append may have landed; a second session entry would make the ledger unrestorable (§5.5).
            if (!(await beginsWithSession(selfLedger))) throw error;
          });
        // Retried by the next entry.
        session.catch(() => {
          session = undefined;
        });
      }
      await session;
      await selfLedger.write(entry);
    };
  }

  /** The endpoint client, for the position check and the close (§5.5, §6.5, §6.7). */
  get client(): AuditEndpointClient {
    return this.#client;
  }

  /** What the Server Agent places in `Task.metadata[URI].auditSession` (§7.2). */
  get auditSession(): AuditSession {
    return { sessionId: this.#request.sessionId, level: this.#request.level, countersign: this.#request.countersign };
  }

  /**
   * Record an access before performing it (§8.1, §8.3). Disposal sends `success` only if `succeeded()` was
   * called, `failed` otherwise; an action resolved by {@link AuditedTask.reportExecution} sends nothing.
   *
   * @throws {AmcpAbortedError} Not recorded: do not perform it; hold the Task with {@link AuditedTask.statusOf} (§8.4).
   * @throws {SessionExpiredError} The session has expired (§5.3).
   * @throws {SelfLedgerError} The `performing` entry was not written (§5.5): do not perform it; resolve the accept
   *   with `reportExecution(id, 'not-performed')`, or let a resumption report it.
   */
  async action(
    actionType: string,
    targetResource: TargetResource,
    options: Parameters<AmcpSession['action']>[2],
  ): Promise<AuditedAction> {
    this.#refuseAfterExpiry();
    return this.#record(actionType, targetResource, options);
  }

  /**
   * Record a transition, a question or an answer: a record that is not an access (§8.1). Its attempt has `mutates`
   * and `egress` both `false`; resolving waits for the accept, so do not go past what it describes before it does.
   * Disposal sends `success` whatever the body did, and a resumption completes an accepted one with `success`
   * rather than reporting on it (§5.5).
   *
   * @throws {Error} `actionType` is the execution report's, which a record is not (§8.1).
   * @throws {AmcpAbortedError} Not recorded: do not go past it; hold the Task with {@link AuditedTask.statusOf} (§8.4).
   * @throws {SessionExpiredError} The session has expired (§5.3).
   * @throws {SelfLedgerError} It could not be written that this is a record; nothing was sent.
   */
  async record(
    actionType: string,
    targetResource: TargetResource,
    options: Omit<Parameters<AmcpSession['action']>[2], 'mutates' | 'egress'> = {},
  ): Promise<AuditedAction> {
    if (actionType === EXECUTION_REPORT_ACTION_TYPE) {
      throw new Error(`a record that is not an access does not use the action_type ${actionType}`);
    }
    this.#refuseAfterExpiry();
    // Counted from before the entry is written, so `finish` does not close while the record is on its way (§6.7).
    this.#pending += 1;
    try {
      if (this.#journal !== undefined) {
        const id = this.#deps.newId();
        await this.#journal({ entry: 'record', id });
        this.#presetId = id;
      }
      return await this.#record(actionType, targetResource, { ...options, mutates: false, egress: false }, true);
    } finally {
      this.#pending -= 1;
      // An attempt refused before a-MCP minted its id must not lend that id to the next action.
      this.#presetId = undefined;
    }
  }

  async #record(
    actionType: string,
    targetResource: TargetResource,
    options: Parameters<AmcpSession['action']>[2],
    isRecord = false,
  ): Promise<AuditedAction> {
    this.#pending += 1;
    let action: AuditedAction;
    try {
      const acquiring = this.#session.action(actionType, targetResource, options);
      const attemptId = this.#lastId;
      try {
        action = await acquiring;
      } catch (error) {
        if (error instanceof AmcpAbortedError && attemptId !== undefined) this.#abortedAttempts.set(error, attemptId);
        throw error;
      }
    } finally {
      this.#pending -= 1;
    }
    const id = action.id;
    const state: Unresolved = { disposed: false, reported: false };
    this.#unresolved.set(id, state);
    // A report or a record performs nothing (§8.1, §8.6).
    const performs = actionType !== EXECUTION_REPORT_ACTION_TYPE && !isRecord;
    if (performs) this.#accepted.add(id);
    // §5.5: not performed unless written as about to be.
    if (performs) await this.#selfLedger?.write({ entry: 'performing', id });
    // As a-MCP reads the two calls: `failed` wins, and neither means `failed`.
    let resolved: 'success' | 'failed' | undefined;
    const succeeded = action.succeeded.bind(action);
    const failed = action.failed.bind(action);
    action.succeeded = () => {
      succeeded();
      resolved ??= 'success';
    };
    // §8.1: a record describes what already happened, so it ends `success` whatever its body did.
    action.failed = isRecord
      ? () => undefined
      : () => {
          failed();
          resolved = 'failed';
        };
    const dispose = action[Symbol.asyncDispose].bind(action);
    action[Symbol.asyncDispose] = async () => {
      if (state.disposed) return;
      state.disposed = true;
      // §8.6: resolved by an execution report, so no outcome.
      if (state.reported) return;
      if (isRecord) action.succeeded();
      try {
        await this.#selfLedger?.write({ entry: 'resolved', id, outcome: resolved ?? 'failed' });
      } catch (error) {
        // Not rethrown: it would replace the body's error, and the outcome's `sent` entry says the same.
        console.error('auditable-a2a: how an access resolved was not written to the own ledger', error);
      }
      await dispose();
      if (this.#client.hasOutcome(id)) {
        this.#unresolved.delete(id);
      } else {
        // Stays unresolved, so the Task cannot end without it (§5.4).
        console.error(`auditable-a2a: the outcome of ${id} was not sent; the access stays unresolved`);
      }
    };
    return action;
  }

  /**
   * Send an execution report for an accepted attempt this Task will not resolve with an outcome (§8.6).
   *
   * @throws {Error} `attemptId` was not accepted, has an outcome, or already has a report (a finding, §11).
   * @throws {AmcpAbortedError} The report could not be recorded; send it again later.
   */
  async reportExecution(attemptId: string, execution: Execution): Promise<void> {
    if (this.#reported.has(attemptId) || this.#reporting.has(attemptId)) {
      throw new Error(`an execution report on ${attemptId} was already accepted or is on its way (§8.6)`);
    }
    if (!this.#accepted.has(attemptId)) throw new Error(`${attemptId} is not an access this Task had accepted (§8.6)`);
    if (this.#client.hasOutcome(attemptId))
      throw new Error(`${attemptId} has its outcome, so it is not reported on (§8.6)`);
    this.#reporting.add(attemptId);
    const state = this.#unresolved.get(attemptId);
    // Set before sending, so an action disposed meanwhile sends no outcome.
    if (state !== undefined) state.reported = true;
    let report: AuditedAction;
    try {
      // §5.4: admitted after the end or expiry, so no expiry check.
      report = await this.#record(
        EXECUTION_REPORT_ACTION_TYPE,
        { kind: AUDIT_SESSION_KIND, ref: this.#request.sessionId },
        { mutates: false, egress: false, disclose: { attemptId, execution } },
      );
    } catch (error) {
      if (state !== undefined) state.reported = false;
      throw error;
    } finally {
      this.#reporting.delete(attemptId);
    }
    this.#reported.add(attemptId);
    this.#unresolved.delete(attemptId);
    report.succeeded();
    await report[Symbol.asyncDispose]();
  }

  [RESTORE_ACCEPTS](accepted: Iterable<string>, reported: Iterable<string>): void {
    for (const id of accepted) this.#accepted.add(id);
    for (const id of reported) this.#reported.add(id);
  }

  /**
   * The `auditStatus` of a Task held because an access could not be recorded (§7.3, §8.4): of the attempt `error`
   * aborted, or of `attemptId`.
   */
  statusOf(error: AmcpAbortedError, attemptId?: string): AuditStatus {
    const reason = (ABORT_REASONS as readonly string[]).includes(error.reason)
      ? (error.reason as AuditStatus['reason'])
      : 'host-unavailable';
    const id = attemptId ?? this.#abortedAttempts.get(error);
    return this.#status(reason, id === undefined ? undefined : this.#client.attemptFailureOf(id), id);
  }

  /**
   * The `auditStatus` of a Task held for an outcome it could not deliver (§7.3, §8.4): of the earliest one owed,
   * or undefined when none is.
   */
  heldStatus(): AuditStatus | undefined {
    const earliest = this.#client.owed[0];
    if (earliest === undefined) return undefined;
    const id = String(earliest.id);
    return this.#status('host-unavailable', this.#client.outcomeFailureOf(id), id);
  }

  #status(
    reason: AuditStatus['reason'],
    failure: RecordFailure | undefined,
    attemptId: string | undefined,
  ): AuditStatus {
    const hostReason = failure?.hostReason;
    return {
      reason,
      ...(hostReason !== undefined && (HOST_REASONS as readonly string[]).includes(hostReason)
        ? { hostReason: hostReason as NonNullable<AuditStatus['hostReason']> }
        : {}),
      ...(failure?.httpStatus === undefined || failure.httpStatus === 200 ? {} : { httpStatus: failure.httpStatus }),
      ...(attemptId === undefined ? {} : { attemptId }),
    };
  }

  #refuseAfterExpiry(): void {
    if (Date.parse(this.#deps.now()) >= Date.parse(this.#request.expiresAt)) {
      throw new SessionExpiredError(this.#request.expiresAt);
    }
  }

  /** Replace the endpoint's credentials from an `auditCredentials` the Client sent (§5.7). */
  replaceCredentials(authentication: AuditRequest['auditEndpoint']['authentication'], token?: string): void {
    this.#client.replaceCredentials(authentication, token);
  }

  /**
   * Whether the Task may move to a terminal state (§5.4): nothing in flight, unresolved, or unacknowledged.
   *
   * @param bound The caller asserts that this §5.4 bound has passed; it is not checked.
   */
  mayEnd(bound?: TerminalBound): boolean {
    return bound !== undefined || this.#nothingOutstanding();
  }

  /** Resend owed outcomes, then close when nothing is outstanding (§5.4, §6.7); true once the close is acknowledged. */
  async finish(): Promise<boolean> {
    // Checked before the flush, which would queue behind an attempt in flight.
    if (!this.#nothingUnresolved()) return false;
    await this.#client.flush();
    if (!this.#nothingOutstanding()) return false;
    return this.#client.close();
  }

  #nothingUnresolved(): boolean {
    return this.#pending === 0 && this.#unresolved.size === 0;
  }

  #nothingOutstanding(): boolean {
    return this.#nothingUnresolved() && this.#client.owed.length === 0;
  }
}
