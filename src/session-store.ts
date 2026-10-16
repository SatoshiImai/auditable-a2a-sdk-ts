/** §5.1, §5.6: the durable state an audit host keeps for each session until it purges it. */

import type { JwkSet, SignerTracker } from 'auditable-mcp-sdk';
import type { Countersign, Level } from './models';

/** How a session ended (§5.4): the first of these to happen. */
export const EndCause = { CLOSE: 'close', CLIENT_NOTICE: 'client-notice', EXPIRY: 'expiry' } as const;
export type EndCause = (typeof EndCause)[keyof typeof EndCause];

/** One credential the audit host issued for a session (§5.7, §6.1). */
export interface IssuedCredential {
  scheme: string;
  credentials: string;
  /** Set once a newer credential has been used: from then on it admits only records owed (§5.7). */
  retiredForAttempts: boolean;
  /** The session's last `seq` when retired; it admits only records of attempts sealed up to it (§5.4, §5.7). */
  newestUntilSeq?: number | undefined;
}

/** An entry of the session's anomaly set this layer records itself (§5.4, §6.6). */
export interface SessionAnomaly {
  id: string;
  kind: string;
  detail: string;
}

/** Everything §5.1 and §5.6 require an audit host to keep for one session. */
export interface SessionState {
  sessionId: string;
  /** The version the session was opened for: the URI of the specification (§4.1, §5.1). */
  version: string;
  /** The URL of the Agent Card the Client delegated to (§5.1). */
  delegate: string;
  level: Level;
  countersign: Countersign;
  hostKeys?: string | undefined;
  expiresAt: string;
  /** Under Level 2: the `attestationKeys` URL and the JWKS fetched from it when the session opened. */
  attestationKeys?: string | undefined;
  keySnapshot?: JwkSet | undefined;
  credentials: IssuedCredential[];
  /** Bound by the first attempt that passes validation (§5.1). */
  boundTaskId?: string | undefined;
  boundKeyId?: string | undefined;
  /** The end, once the session has ended (§5.4). */
  end?: { cause: EndCause; at: string; lastSeq: number | null } | undefined;
  anomalies: SessionAnomaly[];
  /** Under Level 2, the `signer_seq` tracker per key (§5.6, a-MCP §7.4); refusals are not in the ledger. */
  signers?: SignerTracker | undefined;
}

/** The durable store of session states (§5.6). */
export interface SessionStore {
  /** Store the session's state durably; it throws when the state was not stored. */
  put(state: SessionState): Promise<void>;
  /** Every session the store holds, ended or not, until the audit host purges it. */
  all(): Promise<SessionState[]>;
  /** Forget a purged session. */
  delete(sessionId: string): Promise<void>;
}

/** A process-local `SessionStore`; it does not survive the process, so it does not meet §5.6 alone. */
export class InMemorySessionStore implements SessionStore {
  readonly #states = new Map<string, SessionState>();

  async put(state: SessionState): Promise<void> {
    this.#states.set(state.sessionId, structuredClone(state));
  }

  async all(): Promise<SessionState[]> {
    return [...this.#states.values()].map((state) => structuredClone(state));
  }

  async delete(sessionId: string): Promise<void> {
    this.#states.delete(sessionId);
  }
}
