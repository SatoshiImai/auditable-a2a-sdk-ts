/** §5.5 step 3: the audit host's last position against the Server Agent's own ledger. */

import { computeRecordHash } from 'auditable-mcp-sdk';
import type { SessionPosition } from './models';

export interface HeldState {
  /** Every event the Server Agent holds for the session, in the order it emitted them. */
  events: readonly Record<string, unknown>[];
  /** The `seq` of every accept it holds. */
  acceptedSeqs: readonly number[];
}

export type PositionCheck =
  | { ok: true; matched: { id: string; outcome: string } | null }
  | { ok: false; reason: 'no-matching-event' | 'later-accept' | 'empty-with-accepts' };

/** Check the audit host's last position against the Server Agent's own ledger (§5.5 step 3). */
export function checkPosition(position: SessionPosition, held: HeldState): PositionCheck {
  const last = position.last;
  if (last === null) {
    return held.acceptedSeqs.length > 0 ? { ok: false, reason: 'empty-with-accepts' } : { ok: true, matched: null };
  }
  if (held.acceptedSeqs.some((seq) => seq > last.seq)) {
    return { ok: false, reason: 'later-accept' };
  }
  const matched = held.events.find(
    (event) => computeRecordHash(event, last.seq, last.host_ts, last.previous_hash) === last.record_hash,
  );
  return matched === undefined
    ? { ok: false, reason: 'no-matching-event' }
    : { ok: true, matched: { id: String(matched.id), outcome: String(matched.outcome) } };
}
