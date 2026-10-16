/**
 * The Client's audit host (§5, §6): a-MCP's `AuditHost`, unchanged, plus the session record (§5.1), the end
 * (§5.4), restart (§5.6), and credential rotation (§5.7). The a-MCP session is never closed; this layer refuses
 * what the end refuses before a-MCP sees it, so owed outcomes and execution reports are still sealed.
 *
 * A session's state changes only once its new state is stored. One host validates at one level and one
 * countersign setting, as one a-MCP partition does.
 */

import {
  type AttemptResponse,
  AuditHost,
  type Clock,
  type Countersigner,
  canonicalize,
  KeyRegistryVerifier,
  KeyRole,
  type LedgerRepository,
  type OpenSession,
  OutcomeDisposition,
  reject,
  type SealedRecord,
  type SignatureVerifier,
  SPEC_VERSION,
  SystemClock,
  unavailable,
} from 'auditable-mcp-sdk';
import { EXECUTION_REPORT_ACTION_TYPE, isExecutionReport } from './execution-report';
import { registryFromJwks } from './keys';
import {
  type AuditSubmission,
  auditSubmissionSchema,
  Countersign,
  EXTENSION_URI,
  Level,
  type SessionPosition,
} from './models';
import {
  EndCause,
  type IssuedCredential,
  type SessionAnomaly,
  type SessionState,
  type SessionStore,
} from './session-store';

/** What `openSession` needs to record (§5.1). */
export interface OpenSessionInput {
  /** The version the session is opened for (§4.1): this specification's URI. This host implements only its own. */
  version?: string;
  delegate: string;
  expiresAt: string;
  /** Under Level 2: the delegate's `attestationKeys` URL and the JWKS fetched from it, after the Client
   *  verified the delegate's Agent Card signature (§5.1). */
  attestationKeys?: string;
  keySnapshot?: { keys: Record<string, unknown>[] };
  /** Under `countersign: "host"`: the URL this host publishes its countersignature keys at (§7.1). */
  hostKeys?: string;
}

/** A credential this host issued for a session, to place in `auditRequest` (§7.1) or `auditCredentials` (§7.4). */
export interface IssuedAuthentication {
  scheme: string;
  credentials: string;
}

/** The answer to one submission, for a binding to write as an HTTP response (§6). */
export interface SubmissionAnswer {
  status: number;
  body?: unknown;
}

export interface A2aAuditHostOptions {
  store: SessionStore;
  repository?: LedgerRepository;
  countersigner?: Countersigner;
  logId?: string;
  clock?: Clock;
  /** Random bytes for session credentials; Web Crypto by default. */
  random?: (bytes: number) => Uint8Array;
}

const BEARER = 'Bearer';
const CREDENTIAL_BYTES = 32;

function randomBytes(bytes: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(bytes));
}

function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** The Client's audit host for one partition (§5, §6). */
export class A2aAuditHost {
  readonly #host: AuditHost;
  readonly #store: SessionStore;
  readonly #clock: Clock;
  readonly #random: (bytes: number) => Uint8Array;
  readonly #level: Level;
  readonly #countersign: Countersign;
  readonly #states = new Map<string, SessionState>();
  readonly #verifiers = new Map<string, KeyRegistryVerifier>();
  readonly #credentials = new Map<string, string>();
  readonly #records = new Map<string, SealedRecord[]>();
  // Anomalies a-MCP recorded and no stored state carries yet (§6.3); kept for the session's next change.
  readonly #unstoredAnomalies = new Map<string, SessionAnomaly[]>();
  #indexed = 0;
  // One submission at a time, so a-MCP's in-memory anomalies reach the session's stored state before the answer.
  #queue: Promise<unknown> = Promise.resolve();

  private constructor(host: AuditHost, level: Level, countersign: Countersign, options: A2aAuditHostOptions) {
    this.#host = host;
    this.#level = level;
    this.#countersign = countersign;
    this.#store = options.store;
    this.#clock = options.clock ?? new SystemClock();
    this.#random = options.random ?? randomBytes;
  }

  /** Start a host for `partition` with no sessions yet. */
  static create(partition: string, level: Level, countersign: Countersign, options: A2aAuditHostOptions): A2aAuditHost {
    let self: A2aAuditHost | undefined;
    const verifier: SignatureVerifier = { verify: (event) => (self as A2aAuditHost).#verify(event) };
    const host = new AuditHost(
      partition,
      { spec_version: SPEC_VERSION, level, attempt: 'request', countersign },
      {
        ...(level === Level.L2 ? { verifier } : {}),
        ...(options.countersigner === undefined ? {} : { countersigner: options.countersigner }),
        ...(options.logId === undefined ? {} : { logId: options.logId }),
        ...(options.repository === undefined ? {} : { repository: options.repository }),
        ...(options.clock === undefined ? {} : { clock: options.clock }),
      },
    );
    self = new A2aAuditHost(host, level, countersign, options);
    return self;
  }

  /** Restart a host from its ledger and its session store (§5.6); ended sessions still seal what is owed (§5.4). */
  static async resume(
    partition: string,
    level: Level,
    countersign: Countersign,
    options: A2aAuditHostOptions & { repository: LedgerRepository },
  ): Promise<A2aAuditHost> {
    const states = await options.store.all();
    let self: A2aAuditHost | undefined;
    const verifier: SignatureVerifier = { verify: (event) => (self as A2aAuditHost).#verify(event) };
    const host = await AuditHost.resume(
      partition,
      { spec_version: SPEC_VERSION, level, attempt: 'request', countersign },
      {
        repository: options.repository,
        openSessions: states.map(
          (state): OpenSession => ({
            sessionId: state.sessionId,
            ...(state.signers === undefined ? {} : { signers: state.signers }),
          }),
        ),
        ...(level === Level.L2 ? { verifier } : {}),
        ...(options.countersigner === undefined ? {} : { countersigner: options.countersigner }),
        ...(options.logId === undefined ? {} : { logId: options.logId }),
        ...(options.clock === undefined ? {} : { clock: options.clock }),
      },
    );
    self = new A2aAuditHost(host, level, countersign, options);
    for (const state of states) {
      self.#remember(state);
    }
    for (const record of await options.repository.readAll(partition)) {
      self.#index(record);
    }
    return self;
  }

  /**
   * Open a session for a delegation and issue its first credential (§5.1).
   *
   * @throws {Error} A version this host does not implement, Level 2 without a key snapshot, `countersign: "host"`
   *   without `hostKeys`, or a key snapshot that is not a conforming registry (§10.2).
   */
  async openSession(input: OpenSessionInput): Promise<{ sessionId: string; authentication: IssuedAuthentication }> {
    return this.#serialized(() => this.#openSession(input));
  }

  async #openSession(input: OpenSessionInput): Promise<{ sessionId: string; authentication: IssuedAuthentication }> {
    const version = input.version ?? EXTENSION_URI;
    if (version !== EXTENSION_URI) {
      throw new Error(`this audit host implements ${EXTENSION_URI}, not ${version} (§4.1)`);
    }
    if (this.#level === Level.L2 && (input.attestationKeys === undefined || input.keySnapshot === undefined)) {
      throw new Error("a Level-2 session records the delegate's attestationKeys and their snapshot (§5.1)");
    }
    if (this.#countersign === Countersign.HOST && input.hostKeys === undefined) {
      throw new Error('a countersigning audit host names its keys in hostKeys (§7.1)');
    }
    const state: SessionState = {
      sessionId: this.#host.openSession(),
      version,
      delegate: input.delegate,
      level: this.#level,
      countersign: this.#countersign,
      hostKeys: input.hostKeys,
      expiresAt: input.expiresAt,
      attestationKeys: input.attestationKeys,
      keySnapshot: input.keySnapshot,
      credentials: [],
      anomalies: [],
    };
    if (state.attestationKeys !== undefined && state.keySnapshot !== undefined) {
      this.#verifiers.set(
        state.sessionId,
        new KeyRegistryVerifier(registryFromJwks(state.attestationKeys, state.keySnapshot, KeyRole.TOOL)),
      );
    }
    const authentication = this.#newCredential();
    state.credentials.push({ ...authentication, retiredForAttempts: false });
    await this.#store.put(state);
    this.#remember(state);
    return { sessionId: state.sessionId, authentication };
  }

  /** Issue a further credential for the session, for rotation or replacement (§5.7). */
  async issueCredentials(sessionId: string): Promise<IssuedAuthentication> {
    return this.#serialized(async () => {
      const authentication = this.#newCredential();
      await this.#update(sessionId, (draft) => {
        draft.credentials.push({ ...authentication, retiredForAttempts: false });
      });
      return authentication;
    });
  }

  /**
   * End the session on the Client's notice that its Task reached a terminal state, or that its
   * cancellation succeeded (§5.4 item 2). A session already ended keeps its first end.
   */
  async endSession(sessionId: string): Promise<void> {
    await this.#serialized(() => this.#end(sessionId, EndCause.CLIENT_NOTICE));
  }

  /** End every session whose expiry has passed (§5.3) and return their ids; call it periodically. */
  async sweep(): Promise<string[]> {
    return this.#serialized(async () => {
      const ended: string[] = [];
      for (const state of [...this.#states.values()]) {
        if (await this.#endIfExpired(state.sessionId)) ended.push(state.sessionId);
      }
      return ended;
    });
  }

  /**
   * Forget an ended session (§5.4); its records stay in the ledger.
   *
   * @throws {Error} The session has not ended.
   */
  async purge(sessionId: string): Promise<void> {
    await this.#serialized(async () => {
      const state = this.#state(sessionId);
      if (state.end === undefined) throw new Error(`session ${sessionId} has not ended, so it is not purged (§5.4)`);
      await this.#store.delete(sessionId);
      for (const credential of state.credentials) this.#credentials.delete(credential.credentials);
      this.#states.delete(sessionId);
      this.#verifiers.delete(sessionId);
      this.#records.delete(sessionId);
      this.#unstoredAnomalies.delete(sessionId);
    });
  }

  /** The session's state as this host keeps it, or undefined. */
  session(sessionId: string): SessionState | undefined {
    const state = this.#states.get(sessionId);
    return state === undefined ? undefined : structuredClone(state);
  }

  /** The records sealed in this process; after `resume`, the earlier ones are in the repository. */
  records(): SealedRecord[] {
    return this.#host.records();
  }

  /** The partition's tail digest. */
  digest(): string {
    return this.#host.digest();
  }

  /** The anomaly set, as each session keeps it durably: a-MCP's records and this layer's (§5.4, §6.6). */
  anomalies(): SessionAnomaly[] {
    return [...this.#states.values()].flatMap((state) => state.anomalies);
  }

  /**
   * Answer one submission received at the audit endpoint (§6).
   *
   * @param body The parsed JSON body.
   * @param authorization The `Authorization` header, or null.
   */
  async handle(body: unknown, authorization: string | null): Promise<SubmissionAnswer> {
    return this.#serialized(async () => {
      const before = this.#host.anomalies().length;
      const { answer, sessionId } = await this.#answer(body, authorization);
      this.#sync();
      if (sessionId === undefined) return answer;
      const recorded = this.#host
        .anomalies()
        .slice(before)
        .map(({ id, kind, detail }) => ({ id, kind, detail }));
      const held = this.#unstoredAnomalies.get(sessionId) ?? [];
      // A resend after a 503 records its anomaly again; keep it once.
      const unstored = [
        ...held,
        ...recorded.filter((anomaly) => !held.some((kept) => kept.id === anomaly.id && kept.kind === anomaly.kind)),
      ];
      this.#unstoredAnomalies.set(sessionId, unstored);
      const signers = this.#level === Level.L2 ? this.#host.signerTracker(sessionId) : undefined;
      const state = this.#state(sessionId);
      const signersChanged = JSON.stringify(signers) !== JSON.stringify(state.signers);
      if (unstored.length === 0 && !signersChanged) return answer;
      try {
        // §6.3: a refused outcome is acknowledged only once it is durably recorded; §5.6: so is a decision.
        await this.#update(sessionId, (draft) => {
          if (signers !== undefined) draft.signers = signers;
        });
      } catch {
        // §6.2: an attempt is answered with an Attempt Response; one sealed is then aborted, as unanswered.
        if (isRecord(body) && isRecord(body.event) && body.event.outcome === 'attempted') {
          return { status: 200, body: unavailable() };
        }
        return { status: 503, body: { error: 'the session state could not be stored; send it again (§6.3)' } };
      }
      return answer;
    });
  }

  #serialized<T>(work: () => Promise<T>): Promise<T> {
    const run = this.#queue.then(work, work);
    this.#queue = run.catch(() => undefined);
    return run;
  }

  async #answer(
    body: unknown,
    authorization: string | null,
  ): Promise<{ answer: SubmissionAnswer; sessionId?: string }> {
    const answer = (status: number, payload?: unknown) => ({
      answer: payload === undefined ? { status } : { status, body: payload },
    });
    const parsed = auditSubmissionSchema.safeParse(body);
    if (!parsed.success) {
      return answer(400, { error: 'not an AuditSubmission (§6.1)' });
    }
    const submission = parsed.data;
    const sessionId = await this.#authenticate(authorization, submission);
    if (sessionId === undefined) {
      return answer(401, { error: 'credentials not recognised (§6.6)' });
    }
    await this.#endIfExpired(sessionId);
    let result: SubmissionAnswer;
    if (submission.position === true) {
      result = this.#answerPosition(this.#state(sessionId), submission);
    } else if (submission.close === true) {
      result = await this.#answerClose(sessionId, submission);
    } else {
      const event = submission.event as Record<string, unknown>;
      result =
        event.outcome === 'attempted'
          ? await this.#answerAttempt(sessionId, submission, event)
          : await this.#answerOutcome(sessionId, submission, event);
    }
    return { answer: result, sessionId };
  }

  // §6.6: the session a submission arrives on is the one its credentials were issued for.
  async #authenticate(authorization: string | null, submission: AuditSubmission): Promise<string | undefined> {
    if (authorization === null) return undefined;
    // This host issues no token, so any token is one it does not recognise.
    if (submission.token !== undefined) return undefined;
    const space = authorization.indexOf(' ');
    if (space <= 0) return undefined;
    const scheme = authorization.slice(0, space);
    const credentials = authorization.slice(space + 1);
    const sessionId = this.#credentials.get(credentials);
    const state = sessionId === undefined ? undefined : this.#states.get(sessionId);
    const issued = state?.credentials.find(
      (entry) => entry.scheme.toLowerCase() === scheme.toLowerCase() && entry.credentials === credentials,
    );
    if (state === undefined || issued === undefined) return undefined;
    if (issued.retiredForAttempts && !this.#admitsRetired(state, issued, submission)) return undefined;
    // §5.7: once a newer credential is used, the older ones admit only records owed.
    const index = state.credentials.indexOf(issued);
    if (state.credentials.slice(0, index).some((entry) => !entry.retiredForAttempts)) {
      const own = this.#recordsOf(state.sessionId);
      const lastSeq = own.length === 0 ? -1 : (own[own.length - 1] as SealedRecord).seq;
      await this.#update(state.sessionId, (draft) => {
        for (const entry of draft.credentials.slice(0, index)) {
          if (!entry.retiredForAttempts) entry.newestUntilSeq = lastSeq;
          entry.retiredForAttempts = true;
        }
      });
    }
    return state.sessionId;
  }

  // §5.4, §5.7: a credential a newer one replaced admits the position, a resend of an attempt it sealed, and the
  // outcomes and execution reports of attempts sealed while it was the newest; nothing else.
  #admitsRetired(state: SessionState, issued: IssuedCredential, submission: AuditSubmission): boolean {
    if (submission.position === true) return true;
    const event = submission.event;
    if (!isRecord(event)) return false;
    const limit = issued.newestUntilSeq ?? -1;
    const sealedUpTo = (attemptId: unknown) =>
      this.#recordsOf(state.sessionId).some(
        (record) => record.event.id === attemptId && record.event.outcome === 'attempted' && record.seq <= limit,
      );
    if (event.outcome !== 'attempted') return sealedUpTo(event.id);
    if (this.#sealedRepeat(state, event) !== undefined) return true;
    return (
      event.action_type === EXECUTION_REPORT_ACTION_TYPE &&
      isRecord(event.action_context) &&
      sealedUpTo(event.action_context.attemptId)
    );
  }

  async #answerAttempt(
    sessionId: string,
    submission: AuditSubmission,
    event: Record<string, unknown>,
  ): Promise<SubmissionAnswer> {
    const state = this.#state(sessionId);
    // §6.6: a byte-identical repeat of a sealed attempt is answered from the ledger first.
    const repeat = this.#sealedRepeat(state, event);
    if (repeat !== undefined) {
      return { status: 200, body: repeat };
    }
    if (state.boundTaskId !== undefined && submission.taskId !== state.boundTaskId) {
      return { status: 200, body: reject('replay-detected') };
    }
    if (state.end !== undefined && !this.#isReportForAccepted(state, event)) {
      return { status: 200, body: reject('replay-detected') };
    }
    if (state.boundTaskId === undefined) {
      // §5.1: stored before the attempt is sealed, so no restart loses it; a refused attempt unbinds it.
      const keyId = this.#level === Level.L2 && typeof event.key_id === 'string' ? event.key_id : undefined;
      try {
        await this.#update(sessionId, (draft) => {
          draft.boundTaskId = submission.taskId;
          if (keyId !== undefined) draft.boundKeyId = keyId;
        });
      } catch {
        return { status: 200, body: unavailable() };
      }
      const response: AttemptResponse = await this.#host.handleAttempt(event, sessionId);
      if (response.status !== 'accept') {
        await this.#update(sessionId, (draft) => {
          draft.boundTaskId = undefined;
          draft.boundKeyId = undefined;
        }).catch((error: unknown) => {
          // Still bound to this Task, so another Task is refused the session: the safe side of §5.1.
          console.error(
            `auditable-a2a: the session ${sessionId} stayed bound after its first attempt was refused`,
            error,
          );
        });
      }
      return { status: 200, body: response };
    }
    const response: AttemptResponse = await this.#host.handleAttempt(event, sessionId);
    return { status: 200, body: response };
  }

  async #answerOutcome(
    sessionId: string,
    submission: AuditSubmission,
    event: Record<string, unknown>,
  ): Promise<SubmissionAnswer> {
    const state = this.#state(sessionId);
    if (state.boundTaskId !== undefined && submission.taskId !== state.boundTaskId) {
      const boundTaskId = state.boundTaskId;
      try {
        await this.#update(sessionId, (draft) => {
          draft.anomalies.push({
            id: String(event.id),
            kind: 'replay-detected',
            detail: `an outcome for task ${submission.taskId} arrived on the session bound to ${boundTaskId} (§6.6)`,
          });
        });
      } catch {
        return { status: 503, body: { error: 'the outcome could not be recorded; send it again (§6.3)' } };
      }
      return { status: 204 };
    }
    const disposition = await this.#host.recordOutcome(event, sessionId);
    // §6.3: acknowledged only once durably sealed or recorded; otherwise the Server Agent resends.
    return disposition === OutcomeDisposition.NOT_RECORDED
      ? { status: 503, body: { error: 'the outcome could not be recorded; send it again (§6.3)' } }
      : { status: 204 };
  }

  #answerPosition(state: SessionState, submission: AuditSubmission): SubmissionAnswer {
    if (state.boundTaskId !== undefined && submission.taskId !== state.boundTaskId) {
      return { status: 403, body: { error: 'the session is bound to another Task (§6.6)' } };
    }
    const position: SessionPosition = { last: this.#lastOf(state.sessionId) };
    return { status: 200, body: position };
  }

  async #answerClose(sessionId: string, submission: AuditSubmission): Promise<SubmissionAnswer> {
    const state = this.#state(sessionId);
    if (state.boundTaskId !== undefined && submission.taskId !== state.boundTaskId) {
      return { status: 403, body: { error: 'the session is bound to another Task (§6.6)' } };
    }
    try {
      await this.#end(sessionId, EndCause.CLOSE);
    } catch {
      return { status: 503, body: { error: 'the close could not be recorded; send it again (§6.7)' } };
    }
    return { status: 204 };
  }

  // §8.6, §5.4: after the end, an execution report for an attempt this session accepted is admitted.
  #isReportForAccepted(state: SessionState, event: Record<string, unknown>): boolean {
    if (!isExecutionReport(event) || !isRecord(event.action_context)) {
      return false;
    }
    const attemptId = event.action_context.attemptId;
    return this.#recordsOf(state.sessionId).some(
      (record) =>
        record.event.session_id === state.sessionId &&
        record.event.id === attemptId &&
        record.event.outcome === 'attempted',
    );
  }

  #sealedRepeat(state: SessionState, event: Record<string, unknown>): AttemptResponse | undefined {
    let canonical: string;
    try {
      canonical = canonicalize(event);
    } catch {
      return undefined;
    }
    const record = this.#recordsOf(state.sessionId).find(
      (candidate) =>
        candidate.event.id === event.id &&
        candidate.event.outcome === 'attempted' &&
        canonicalize(candidate.event) === canonical,
    );
    if (record === undefined) return undefined;
    return {
      status: 'accept',
      seq: record.seq,
      record_hash: record.record_hash,
      host_ts: record.host_ts,
      previous_hash: record.previous_hash,
      ...(record.host_signature === undefined
        ? {}
        : { host_signature: record.host_signature, host_key_id: record.host_key_id, log_id: record.log_id }),
    } as AttemptResponse;
  }

  #lastOf(sessionId: string): SessionPosition['last'] {
    const records = this.#recordsOf(sessionId);
    const last = records[records.length - 1];
    if (last === undefined) return null;
    return {
      seq: last.seq,
      host_ts: last.host_ts,
      previous_hash: last.previous_hash,
      record_hash: last.record_hash,
      ...(last.host_signature === undefined
        ? {}
        : {
            host_signature: last.host_signature,
            host_key_id: last.host_key_id as string,
            log_id: last.log_id as string,
          }),
    };
  }

  // §5.3: the session ends at its expiry, which is the time of the end whenever the host notices it.
  async #endIfExpired(sessionId: string): Promise<boolean> {
    const state = this.#state(sessionId);
    if (state.end !== undefined || Date.parse(this.#clock.now()) < Date.parse(state.expiresAt)) return false;
    await this.#end(sessionId, EndCause.EXPIRY, state.expiresAt);
    return true;
  }

  // §5.4: record the cause, the time, the last seq of the partition before the end, and every unresolved attempt.
  async #end(sessionId: string, cause: EndCause, at: string = this.#clock.now()): Promise<void> {
    if (this.#state(sessionId).end !== undefined) return;
    this.#sync();
    const lastSeq = this.#lastSeqIndexed();
    const own = this.#recordsOf(sessionId);
    const resolved = new Set(
      own.filter((record) => record.event.outcome !== 'attempted').map((r) => String(r.event.id)),
    );
    await this.#update(sessionId, (draft) => {
      draft.end = { cause, at, lastSeq };
      for (const record of own) {
        const id = String(record.event.id);
        if (record.event.outcome === 'attempted' && !resolved.has(id)) {
          draft.anomalies.push({
            id,
            kind: 'unresolved-attempt',
            detail: `session ended (${cause}) with attempt ${id} unresolved (§5.4)`,
          });
        }
      }
    });
  }

  // §5.1, §10.2: under Level 2 every event verifies against the session's snapshot, under its bound key.
  async #verify(event: Record<string, unknown>) {
    const sessionId = typeof event.session_id === 'string' ? event.session_id : undefined;
    const state = sessionId === undefined ? undefined : this.#states.get(sessionId);
    if (state === undefined) return 'unknown-key' as const;
    if (state.boundKeyId !== undefined && event.key_id !== state.boundKeyId) return 'unknown-key' as const;
    let verifier = this.#verifiers.get(state.sessionId);
    if (verifier === undefined && state.attestationKeys !== undefined && state.keySnapshot !== undefined) {
      verifier = new KeyRegistryVerifier(registryFromJwks(state.attestationKeys, state.keySnapshot, KeyRole.TOOL));
      this.#verifiers.set(state.sessionId, verifier);
    }
    return verifier === undefined ? ('unknown-key' as const) : verifier.verify(event);
  }

  #newCredential(): IssuedAuthentication {
    return { scheme: BEARER, credentials: base64url(this.#random(CREDENTIAL_BYTES)) };
  }

  #state(sessionId: string): SessionState {
    const state = this.#states.get(sessionId);
    if (state === undefined) {
      throw new Error(`no session ${sessionId} at this audit host`);
    }
    return state;
  }

  // Stored first, so a failed store leaves the session as it was; unstored anomalies go with the change.
  async #update(sessionId: string, change: (draft: SessionState) => void): Promise<SessionState> {
    const draft = structuredClone(this.#state(sessionId));
    draft.anomalies.push(...(this.#unstoredAnomalies.get(sessionId) ?? []));
    change(draft);
    await this.#store.put(draft);
    this.#remember(draft);
    this.#unstoredAnomalies.delete(sessionId);
    return draft;
  }

  #remember(state: SessionState): void {
    this.#states.set(state.sessionId, state);
    for (const credential of state.credentials) this.#credentials.set(credential.credentials, state.sessionId);
  }

  // a-MCP's records() holds only this process's seals; the index also holds the ledger read on resume.
  #sync(): void {
    const records = this.#host.records();
    for (const record of records.slice(this.#indexed)) this.#index(record);
    this.#indexed = records.length;
  }

  #index(record: SealedRecord): void {
    const sessionId = record.event.session_id;
    if (typeof sessionId !== 'string') return;
    const records = this.#records.get(sessionId) ?? [];
    records.push(record);
    this.#records.set(sessionId, records);
    this.#lastIndexedSeq = Math.max(this.#lastIndexedSeq, record.seq);
  }

  #lastIndexedSeq = -1;

  #lastSeqIndexed(): number | null {
    return this.#lastIndexedSeq < 0 ? null : this.#lastIndexedSeq;
  }

  #recordsOf(sessionId: string): SealedRecord[] {
    this.#sync();
    return this.#records.get(sessionId) ?? [];
  }
}
