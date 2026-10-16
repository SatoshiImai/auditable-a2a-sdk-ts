/** §4.3 conditions 3 and 4; conditions 1, 2 and 5 are checked before this. */

import { type AgentCardParams, type AuditRequest, Countersign, Level } from './models';

export type Negotiation = { negotiated: true } | { negotiated: false; field: 'level' | 'countersign' };

/** Compare the Server Agent's `params` with the Client's `auditRequest` (§4.3, §4.4). */
export function negotiate(
  params: Pick<AgentCardParams, 'level' | 'countersign'>,
  request: Pick<AuditRequest, 'level' | 'countersign'>,
): Negotiation {
  // Level 2 meets both levels; Level 1 meets only Level 1 (a-MCP §6.1).
  if (request.level === Level.L2 && params.level !== Level.L2) {
    return { negotiated: false, field: 'level' };
  }
  // The countersignature axis runs the other way: the Server Agent requires, the audit host offers.
  if (params.countersign === Countersign.HOST && request.countersign !== Countersign.HOST) {
    return { negotiated: false, field: 'countersign' };
  }
  return { negotiated: true };
}
