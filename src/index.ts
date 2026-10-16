/** Auditable A2A SDK: `auditable-a2a/0.1` over `auditable-mcp/0.4`. */

export {
  type AgentExtensionDeclaration,
  AUDIT_SESSION_IN_USE,
  admitLaterRequest,
  admitNewTask,
  agentCardExtension,
  auditCredentialsMetadata,
  auditRequestMetadata,
  auditSessionMetadata,
  auditStatusMetadata,
  HoldRemedy,
  holdRemedy,
  isAudited,
  type LaterRequestAdmission,
  type LaterRequestInput,
  type NewTaskAdmission,
  type NewTaskInput,
  type Rejection,
  readAuditStatus,
  type SessionUse,
} from './admission';
export {
  A2aAuditHost,
  type A2aAuditHostOptions,
  type IssuedAuthentication,
  type OpenSessionInput,
  type SubmissionAnswer,
} from './audit-host';
export { AuditedTask, type AuditedTaskOptions, SessionExpiredError, TerminalBound } from './audited-task';
export {
  AuditEndpointClient,
  type AuditEndpointClientOptions,
  DEFAULT_TIMEOUT_MS,
  type RecordFailure,
} from './endpoint-client';
export {
  type AuditEndpointHandlerOptions,
  createAuditEndpointHandler,
  DEFAULT_MAX_BODY_BYTES,
} from './endpoint-handler';
export {
  AUDIT_SESSION_KIND,
  EXECUTION_REPORT_ACTION_TYPE,
  Execution,
  type ExecutionReportInput,
  executionReport,
  isExecutionReport,
} from './execution-report';
export { type FetchHostKeys, fetchHostKeysWith, type HostKeySet, HostKeysVerifier } from './host-keys';
export { keyIdOf, registryFromJwks } from './keys';
export {
  ABORT_REASONS,
  type AgentCardParams,
  AUTH_CREDENTIALS_PATTERN,
  AUTH_SCHEME_PATTERN,
  type AuditCredentials,
  type AuditRequest,
  type AuditSession,
  type AuditStatus,
  type AuditSubmission,
  type AuthenticationInfo,
  agentCardParamsSchema,
  auditCredentialsSchema,
  auditRequestSchema,
  auditSessionSchema,
  auditStatusSchema,
  auditSubmissionSchema,
  authenticationInfoSchema,
  Countersign,
  DATETIME_PATTERN,
  EVENT_ID_PATTERN,
  EXTENSION_URI,
  HEADER_VALUE_PATTERN,
  HOST_REASONS,
  HTTPS_NO_FRAGMENT_PATTERN,
  HTTPS_PATTERN,
  Level,
  SESSION_ID_PATTERN,
  type SealedPosition,
  type SessionPosition,
  sealedPositionSchema,
  sessionPositionSchema,
} from './models';
export { type Negotiation, negotiate } from './negotiate';
export { checkPosition, type HeldState, type PositionCheck } from './position';
export { type ResumeFailure, type ResumeOptions, type ResumeResult, resumeTask } from './resume';
export { type JournalEntry, type JournaledRequest, SelfLedger, SelfLedgerError } from './self-ledger';
export {
  EndCause,
  InMemorySessionStore,
  type IssuedCredential,
  type SessionAnomaly,
  type SessionState,
  type SessionStore,
} from './session-store';

export {
  A2aFinding,
  type A2aVerifyReport,
  type Finding,
  type RecordAfterClose,
  type SessionEvidence,
  TIER1_FALLBACK,
  type VerifyA2aOptions,
  verifyA2aLedger,
} from './verify';

export const VERSION = '0.1.0';
