/** §8.6: the execution report, an a-MCP attempt and its `success` outcome in a fixed shape. */

import { SPEC_VERSION } from 'auditable-mcp-sdk';

export const EXECUTION_REPORT_ACTION_TYPE = 'a2a.execution-report';
export const AUDIT_SESSION_KIND = 'a2a.audit-session';

/** What the Server Agent knows of an accepted access it did not resolve with an outcome (§8.6). */
export const Execution = { NOT_PERFORMED: 'not-performed', INDETERMINATE: 'indeterminate' } as const;
export type Execution = (typeof Execution)[keyof typeof Execution];

export interface ExecutionReportInput {
  /** The report's own event id, shared by its attempt and outcome. */
  id: string;
  ts: string;
  sessionId: string;
  /** The `id` of the accepted attempt the report is about. */
  attemptId: string;
  execution: Execution;
}

/** Build the execution report's attempt (`attempted`) or outcome (`success`) event (§8.6). */
export function executionReport(
  input: ExecutionReportInput,
  outcome: 'attempted' | 'success',
): Record<string, unknown> {
  return {
    id: input.id,
    spec_version: SPEC_VERSION,
    ts: input.ts,
    session_id: input.sessionId,
    action_type: EXECUTION_REPORT_ACTION_TYPE,
    mutates: false,
    egress: false,
    target_resource: { kind: AUDIT_SESSION_KIND, ref: input.sessionId },
    outcome,
    // In the clear, not committed: the Client reads it (§8.6).
    action_context: { attemptId: input.attemptId, execution: input.execution },
  };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Whether `event` has every member §8.6 gives an execution report, not its `action_type` alone (§11). */
export function isExecutionReport(event: Record<string, unknown>): boolean {
  const target = event.target_resource;
  const context = event.action_context;
  return (
    event.action_type === EXECUTION_REPORT_ACTION_TYPE &&
    event.mutates === false &&
    event.egress === false &&
    isObject(target) &&
    Object.keys(target).length === 2 &&
    target.kind === AUDIT_SESSION_KIND &&
    target.ref === event.session_id &&
    isObject(context) &&
    Object.keys(context).length === 2 &&
    typeof context.attemptId === 'string' &&
    (context.execution === Execution.NOT_PERFORMED || context.execution === Execution.INDETERMINATE)
  );
}
