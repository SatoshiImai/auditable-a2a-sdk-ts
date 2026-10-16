/**
 * Verification of a Client's ledger (§11): a-MCP's verification (a-MCP §11.4) with per-session key snapshots,
 * then §11's checks per session. A session of an unimplemented or unrecorded version is reported unchecked.
 */

import {
  type CountersignatureChecker,
  type ExpectedIdentity,
  KeyRegistryVerifier,
  KeyRole,
  type SealedRecord,
  type SignatureChecker,
  type VerifyReport,
  verifyLedger,
} from 'auditable-mcp-sdk';
import { EXECUTION_REPORT_ACTION_TYPE, isExecutionReport } from './execution-report';
import { registryFromJwks } from './keys';
import { Countersign, EXTENSION_URI, Level } from './models';
import type { SessionState } from './session-store';

/** This extension's findings (§11), each with the a-MCP Tier-1 code a consumer that knows only a-MCP reads. */
export const A2aFinding = {
  ATTEMPT_AFTER_END: 'timberlandchapel.com/a2a-attempt-after-end',
  REPORT_UNMATCHED: 'timberlandchapel.com/a2a-report-unmatched',
  REPORT_DUPLICATED: 'timberlandchapel.com/a2a-report-duplicated',
} as const;
export type A2aFinding = (typeof A2aFinding)[keyof typeof A2aFinding];

export const TIER1_FALLBACK: Record<A2aFinding, string> = {
  [A2aFinding.ATTEMPT_AFTER_END]: 'replay-detected',
  [A2aFinding.REPORT_UNMATCHED]: 'orphaned-outcome',
  [A2aFinding.REPORT_DUPLICATED]: 'replay-detected',
};

export interface Finding {
  code: A2aFinding | 'signature-invalid';
  /** The Tier-1 code to read it as (a-MCP §7.6); `signature-invalid` is one itself. */
  tier1: string;
  sessionId: string;
  seq: number;
  id: string;
  detail: string;
}

/** What the verifier needs of a session from outside the chain (§11 Inputs). */
export type SessionEvidence = Pick<SessionState, 'sessionId' | 'level'> &
  Partial<
    Pick<
      SessionState,
      'version' | 'countersign' | 'attestationKeys' | 'keySnapshot' | 'boundKeyId' | 'end' | 'anomalies'
    >
  >;

/** A record sealed in a session after the Server Agent closed it, to be read against the reason for the close. */
export interface RecordAfterClose {
  sessionId: string;
  seq: number;
  id: string;
}

export interface A2aVerifyReport {
  /** a-MCP's verification of the partition (a-MCP §11.4). */
  amcp: VerifyReport;
  /** This extension's findings (§11 Checks). */
  findings: Finding[];
  /** Accepted attempts the audit host recorded `unresolved-attempt` and that were resolved after the end (§5.4, §11 check 4). */
  resolvedAfterEnd: string[];
  /** Records sealed after an end caused by a close, listed apart from the findings (§11 check 2, §13.7). */
  recordsAfterClose: RecordAfterClose[];
  /** Checks that applied and could not run, for lack of an input (§11 Inputs). */
  unchecked: string[];
  /** True when neither a-MCP nor this extension found anything and nothing was left unchecked. */
  complete: boolean;
}

export interface VerifyA2aOptions {
  anchoredDigest?: string;
  countersignatureChecker?: CountersignatureChecker;
  /** Whether every record must be countersigned; by default, whether any session was opened with `countersign: "host"`. */
  countersignatureRequired?: boolean;
  /** The identity the partition is expected to hold, passed to a-MCP's verification (a-MCP §10.10). */
  expectedIdentity?: ExpectedIdentity;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Verify a partition of a Client's ledger and the sessions sealed in it (§11).
 *
 * @param records The partition's sealed records, in order.
 * @param sessions What the audit host keeps for each session (§5.1, §5.4).
 */
export function verifyA2aLedger(
  records: SealedRecord[],
  sessions: readonly SessionEvidence[],
  options: VerifyA2aOptions = {},
): A2aVerifyReport {
  const unchecked: string[] = [];
  const bySession = new Map(sessions.map((session) => [session.sessionId, session]));
  const known = sessions.filter((session) => {
    if (session.version === undefined) {
      unchecked.push(`version of session ${session.sessionId}: not recorded`);
      return false;
    }
    if (session.version !== EXTENSION_URI) {
      unchecked.push(`session ${session.sessionId}: version ${session.version} is not implemented`);
      return false;
    }
    return true;
  });

  // §5.1: each Level-2 record verifies against the snapshot of its own session.
  const checkers = new Map<string, SignatureChecker>();
  for (const session of known) {
    if (session.level !== Level.L2) continue;
    if (session.attestationKeys === undefined || session.keySnapshot === undefined) {
      unchecked.push(`signatures of session ${session.sessionId}: no key snapshot`);
      continue;
    }
    let verifier: KeyRegistryVerifier;
    try {
      verifier = new KeyRegistryVerifier(registryFromJwks(session.attestationKeys, session.keySnapshot, KeyRole.TOOL));
    } catch {
      unchecked.push(`signatures of session ${session.sessionId}: the key snapshot is not a conforming key set`);
      continue;
    }
    checkers.set(session.sessionId, verifier.check);
  }
  const anyLevel2 = sessions.some((session) => session.level === Level.L2);
  // A session without a checker is reported unchecked above, not judged invalid.
  const signatureChecker: SignatureChecker | undefined = anyLevel2
    ? (event) => {
        const checker = checkers.get(String(event.session_id));
        return checker === undefined ? true : checker(event);
      }
    : undefined;
  const countersignatureRequired =
    options.countersignatureRequired ?? sessions.some((session) => session.countersign === Countersign.HOST);

  const amcp = verifyLedger(records, {
    ...(options.anchoredDigest === undefined ? {} : { anchoredDigest: options.anchoredDigest }),
    ...(options.countersignatureChecker === undefined
      ? {}
      : { countersignatureChecker: options.countersignatureChecker }),
    countersignatureRequired,
    ...(options.expectedIdentity === undefined ? {} : { expectedIdentity: options.expectedIdentity }),
    ...(signatureChecker === undefined ? {} : { signatureChecker }),
  });

  const findings: Finding[] = [];
  const resolvedAfterEnd: string[] = [];
  const recordsAfterClose: RecordAfterClose[] = [];
  const add = (code: A2aFinding, session: SessionEvidence, record: SealedRecord, detail: string) =>
    findings.push({
      code,
      tier1: TIER1_FALLBACK[code],
      sessionId: session.sessionId,
      seq: record.seq,
      id: String(record.event.id),
      detail,
    });

  const sealedIn = (sessionId: string) => records.filter((record) => record.event.session_id === sessionId);

  for (const session of known) {
    const own = sealedIn(session.sessionId);

    // Check 1: under Level 2, every record of the session is under the bound key.
    if (session.level === Level.L2) {
      if (session.boundKeyId === undefined) {
        if (own.length > 0) unchecked.push(`bound key of session ${session.sessionId}: not recorded`);
      } else {
        for (const record of own) {
          if (record.event.key_id !== session.boundKeyId) {
            findings.push({
              code: 'signature-invalid',
              tier1: 'signature-invalid',
              sessionId: session.sessionId,
              seq: record.seq,
              id: String(record.event.id),
              detail: `under key ${String(record.event.key_id)}, not the session's bound key (§5.1)`,
            });
          }
        }
      }
    }

    // Check 2: nothing sealed after the end that the end refuses.
    if (session.end === undefined) {
      if (own.length > 0) unchecked.push(`end of session ${session.sessionId}: not recorded`);
    } else {
      const lastSeq = session.end.lastSeq ?? -1;
      for (const record of own.filter((candidate) => candidate.seq > lastSeq)) {
        const isReport = record.event.action_type === EXECUTION_REPORT_ACTION_TYPE;
        if (record.event.outcome === 'attempted' && !isReport) {
          add(
            A2aFinding.ATTEMPT_AFTER_END,
            session,
            record,
            `attempt sealed after the session ended at seq ${lastSeq}`,
          );
        }
        if (session.end.cause === 'close') {
          recordsAfterClose.push({ sessionId: session.sessionId, seq: record.seq, id: String(record.event.id) });
        }
      }
    }

    // Check 3: each execution report names an accepted attempt of the session, once.
    const reported = new Map<string, number>();
    for (const record of own) {
      const event = record.event;
      if (event.action_type !== EXECUTION_REPORT_ACTION_TYPE || event.outcome !== 'attempted') continue;
      // A report the Server Agent aborted was not accepted, and a new one may follow it (§8.6).
      if (own.some((candidate) => candidate.event.id === event.id && candidate.event.outcome === 'aborted')) continue;
      const context = isRecord(event.action_context) ? event.action_context : {};
      const attemptId = context.attemptId;
      // An execution report is never itself the subject of one (§8.6).
      const attempt = own.find(
        (candidate) =>
          candidate.event.id === attemptId &&
          candidate.event.outcome === 'attempted' &&
          candidate.event.action_type !== EXECUTION_REPORT_ACTION_TYPE &&
          candidate.seq < record.seq,
      );
      const resolvedByOutcome = own.some(
        (candidate) => candidate.event.id === attemptId && candidate.event.outcome !== 'attempted',
      );
      if (
        attempt === undefined ||
        resolvedByOutcome ||
        !isExecutionReport(event) ||
        event.session_id !== session.sessionId
      ) {
        add(
          A2aFinding.REPORT_UNMATCHED,
          session,
          record,
          `reports on ${String(attemptId)}, no accepted unresolved attempt of this session`,
        );
        continue;
      }
      const count = (reported.get(String(attemptId)) ?? 0) + 1;
      reported.set(String(attemptId), count);
      if (count > 1) {
        add(A2aFinding.REPORT_DUPLICATED, session, record, `a second accepted report on ${String(attemptId)}`);
      }
    }

    // Check 4: an unresolved attempt resolved after the end is resolved, not a contradiction.
    if (session.anomalies === undefined && session.end !== undefined) {
      unchecked.push(`anomaly set of session ${session.sessionId}: not recorded`);
    }
    for (const anomaly of session.anomalies ?? []) {
      if (anomaly.kind !== 'unresolved-attempt') continue;
      const resolved = own.some(
        (record) =>
          (record.event.id === anomaly.id && record.event.outcome !== 'attempted') ||
          (record.event.action_type === EXECUTION_REPORT_ACTION_TYPE &&
            isRecord(record.event.action_context) &&
            record.event.action_context.attemptId === anomaly.id),
      );
      if (resolved) resolvedAfterEnd.push(anomaly.id);
    }
  }

  for (const record of records) {
    const sessionId = record.event.session_id;
    if (typeof sessionId === 'string' && !bySession.has(sessionId)) {
      unchecked.push(`session ${sessionId}: no session record`);
    }
  }

  return {
    amcp,
    findings,
    resolvedAfterEnd,
    recordsAfterClose,
    unchecked: [...new Set(unchecked)],
    complete: amcp.complete && findings.length === 0 && unchecked.length === 0,
  };
}
