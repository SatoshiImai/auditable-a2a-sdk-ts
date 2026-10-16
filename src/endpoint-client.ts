/**
 * The Server Agent's side of the audit endpoint (§6), as an a-MCP `AuditTransport`: one submission at a time,
 * bounded, never redirected (§6.8); non-`200` attempts read as `unavailable` (§6.2); outcomes owed until a `2xx`
 * (§6.4); journal entries written before what they precede (§5.5).
 */

import {
  type AttemptResponse,
  type AuditCapability,
  type AuditTransport,
  attemptResponseSchema,
  type NegotiationResult,
  negotiate as negotiateCapability,
  type SessionNumbering,
  SPEC_VERSION,
  unavailable,
} from 'auditable-mcp-sdk';
import type { AuthenticationInfo, Countersign, Level, SessionPosition } from './models';
import { sessionPositionSchema } from './models';
import type { JournalEntry } from './self-ledger';

/** Why the last submission was not answered as it should have been, for `auditStatus` (§7.3). */
export interface RecordFailure {
  /** The HTTP status the endpoint answered with, when it answered (§7.3 `httpStatus`). */
  httpStatus?: number;
  /** The `reason` the audit host gave with a `reject` or `unavailable`, when it gave one. */
  hostReason?: string;
  /** The `id` of the attempt the failure is about (§7.3 `attemptId`); absent for a position request. */
  attemptId?: string;
}

export interface AuditEndpointClientOptions {
  url: string;
  authentication: AuthenticationInfo;
  token?: string;
  taskId: string;
  /** The level and countersignature setting of the session (§4.3), for `negotiate`. */
  level: Level;
  countersign: Countersign;
  /** The bound on each POST, in milliseconds (§6.8). */
  timeoutMs?: number;
  fetch?: typeof fetch;
  /** Writes an entry to the Server Agent's own ledger (§5.5); it throws when the entry was not written. */
  journal?: (entry: JournalEntry) => Promise<void>;
  /** The session's `signer_seq` numbering, for a session resumed after a restart (a-MCP §7.4). */
  numbering?: SessionNumbering;
}

export const DEFAULT_TIMEOUT_MS = 10_000;

/** The Server Agent's client of one session's audit endpoint (§6). */
export class AuditEndpointClient implements AuditTransport {
  readonly #url: string;
  #authentication: AuthenticationInfo;
  #token: string | undefined;
  readonly #taskId: string;
  readonly #host: AuditCapability;
  readonly #timeoutMs: number;
  readonly #fetch: typeof fetch;
  readonly #journal: ((entry: JournalEntry) => Promise<void>) | undefined;
  /** Read by a-MCP's `AmcpSession`, which numbers with it when present (a-MCP §7.4). */
  readonly numbering?: SessionNumbering;
  #queue: Promise<unknown> = Promise.resolve();
  readonly #owed: Record<string, unknown>[] = [];
  #lastFailure: RecordFailure | undefined;
  // Per event id, so a hold names its own submission's failure (§7.3); an attempt and its outcome share an id.
  readonly #attemptFailures = new Map<string, RecordFailure>();
  readonly #outcomeFailures = new Map<string, RecordFailure>();
  readonly #outcomes = new Set<string>();

  constructor(options: AuditEndpointClientOptions) {
    this.#url = options.url;
    this.#authentication = options.authentication;
    this.#token = options.token;
    this.#taskId = options.taskId;
    this.#host = {
      spec_version: SPEC_VERSION,
      level: options.level,
      attempt: 'request',
      countersign: options.countersign,
    };
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.#fetch = options.fetch ?? fetch;
    this.#journal = options.journal;
    if (options.numbering !== undefined) this.numbering = options.numbering;
  }

  /** The comparison a-MCP's tool side makes, against the session negotiated in A2A (§4.3). */
  negotiate(offered: AuditCapability): NegotiationResult {
    return negotiateCapability(this.#host, offered);
  }

  /** Why the last attempt or position request failed, or undefined after one that succeeded (§7.3). */
  get lastFailure(): RecordFailure | undefined {
    return this.#lastFailure;
  }

  /** Why the attempt `id` was not recorded, or undefined once it was accepted. */
  attemptFailureOf(id: string): RecordFailure | undefined {
    return this.#attemptFailures.get(id);
  }

  /** Why the outcome of `id` was last not acknowledged, or undefined once it was. */
  outcomeFailureOf(id: string): RecordFailure | undefined {
    return this.#outcomeFailures.get(id);
  }

  /** Whether the outcome of `id` was sent, and is acknowledged or owed (§6.4). */
  hasOutcome(id: string): boolean {
    return this.#outcomes.has(id);
  }

  /** The outcomes not yet acknowledged, in the order they were emitted (§6.4). */
  get owed(): readonly Record<string, unknown>[] {
    return [...this.#owed];
  }

  /** Replace the endpoint's credentials, as `auditCredentials` or a renewal does (§5.7). */
  replaceCredentials(authentication: AuthenticationInfo, token?: string): void {
    this.#authentication = authentication;
    this.#token = token;
  }

  async sendAttempt(event: Record<string, unknown>): Promise<AttemptResponse> {
    return this.#serialized(async () => {
      await this.#journal?.({ entry: 'sent', event });
      return this.#attempt(event);
    });
  }

  /** Send an outcome; one not acknowledged is kept owed and resent by `flush` (§6.4). */
  async sendOutcome(event: Record<string, unknown>): Promise<void> {
    await this.#serialized(async () => {
      await this.#journal?.({ entry: 'sent', event });
      this.#outcomes.add(String(event.id));
      await this.#outcome(event);
    });
  }

  /** Resend, byte for byte, an attempt the own ledger already holds as sent (§5.5 step 2). */
  async resendAttempt(event: Record<string, unknown>): Promise<AttemptResponse> {
    return this.#serialized(() => this.#attempt(event));
  }

  /** Resend, byte for byte, an outcome the own ledger already holds as sent (§5.5 step 2). */
  async resendOutcome(event: Record<string, unknown>): Promise<void> {
    await this.#serialized(() => this.#outcome(event));
  }

  /** Resend every owed outcome, byte for byte; return how many are still owed (§6.4). */
  async flush(): Promise<number> {
    return this.#serialized(async () => {
      while (this.#owed.length > 0) {
        const event = this.#owed[0] as Record<string, unknown>;
        if (!(await this.#deliver(event))) break;
        this.#owed.shift();
        await this.#acknowledged(event);
      }
      return this.#owed.length;
    });
  }

  /**
   * Ask for the session's last position (§6.5): the position, `'refused'` when the endpoint answered `403` (§6.6),
   * or undefined when it did not answer one.
   */
  async position(): Promise<SessionPosition | 'refused' | undefined> {
    return this.#serialized(async () => {
      const answer = await this.#post({ position: true });
      if (answer.status === 403) return 'refused';
      if (answer.status !== 200) {
        this.#lastFailure = answer.status === undefined ? {} : { httpStatus: answer.status };
        return undefined;
      }
      const parsed = sessionPositionSchema.safeParse(answer.body);
      return parsed.success ? parsed.data : undefined;
    });
  }

  /** Close the session (§6.7); true once the endpoint acknowledged it. */
  async close(): Promise<boolean> {
    return this.#serialized(async () => {
      await this.#journal?.({ entry: 'close' });
      const answer = await this.#post({ close: true });
      return answer.status !== undefined && answer.status >= 200 && answer.status < 300;
    });
  }

  async #attempt(event: Record<string, unknown>): Promise<AttemptResponse> {
    const answer = await this.#post({ event });
    const attemptId = String(event.id);
    if (answer.status !== 200) {
      this.#fail(attemptId, answer.status === undefined ? { attemptId } : { httpStatus: answer.status, attemptId });
      return unavailable();
    }
    const parsed = attemptResponseSchema.safeParse(answer.body);
    if (!parsed.success) {
      this.#fail(attemptId, { httpStatus: 200, attemptId });
      return unavailable();
    }
    const response = parsed.data;
    // A failed write throws, which a-MCP turns into an abort.
    await this.#journal?.({ entry: 'response', id: String(event.id), response });
    if (response.status === 'accept') {
      this.#lastFailure = undefined;
      this.#attemptFailures.delete(attemptId);
    } else {
      this.#fail(attemptId, { hostReason: response.reason, attemptId });
    }
    return response;
  }

  async #outcome(event: Record<string, unknown>): Promise<void> {
    if (await this.#deliver(event)) {
      await this.#acknowledged(event);
    } else {
      this.#owed.push(event);
    }
  }

  async #acknowledged(event: Record<string, unknown>): Promise<void> {
    try {
      await this.#journal?.({ entry: 'acked', id: String(event.id) });
    } catch (error) {
      // Delivered anyway; a resumption resends it, and the host treats a byte-identical repeat as one (§6.4).
      console.error('auditable-a2a: an acknowledged outcome was not written to the own ledger', error);
    }
  }

  async #deliver(event: Record<string, unknown>): Promise<boolean> {
    const answer = await this.#post({ event });
    const id = String(event.id);
    const delivered = answer.status !== undefined && answer.status >= 200 && answer.status < 300;
    // `lastFailure` is about attempts only.
    if (delivered) {
      this.#outcomeFailures.delete(id);
    } else {
      this.#outcomeFailures.set(
        id,
        answer.status === undefined ? { attemptId: id } : { httpStatus: answer.status, attemptId: id },
      );
    }
    return delivered;
  }

  #fail(id: string, failure: RecordFailure): void {
    this.#lastFailure = failure;
    this.#attemptFailures.set(id, failure);
  }

  #serialized<T>(work: () => Promise<T>): Promise<T> {
    const run = this.#queue.then(work, work);
    this.#queue = run.catch(() => undefined);
    return run;
  }

  // `status` is undefined when nothing was answered in time.
  async #post(kind: Record<string, unknown>): Promise<{ status?: number; body?: unknown }> {
    const body = { taskId: this.#taskId, ...(this.#token === undefined ? {} : { token: this.#token }), ...kind };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.#timeoutMs);
    try {
      const response = await this.#fetch(this.#url, {
        method: 'POST',
        headers: {
          authorization: `${this.#authentication.scheme} ${this.#authentication.credentials}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify(body),
        redirect: 'manual',
        signal: controller.signal,
      });
      const text = await response.text();
      let parsed: unknown;
      try {
        parsed = text === '' ? undefined : JSON.parse(text);
      } catch {
        parsed = undefined;
      }
      return { status: response.status, body: parsed };
    } catch {
      return {};
    } finally {
      clearTimeout(timer);
    }
  }
}
