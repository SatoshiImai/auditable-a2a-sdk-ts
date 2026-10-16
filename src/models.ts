/** Zod schemas for the wire structures (§3.1, §6, §7), held to `spec/schema/` by the schema-drift test. */

import { z } from 'zod';

/** This version's extension URI (§4.1). */
export const EXTENSION_URI = 'https://timberlandchapel.com/a2a/extensions/auditable-a2a/0.1';

/** A lowercase RFC 9562 UUID of versions 1-8, never nil: an a-MCP audit session id (a-MCP §6.3). */
export const SESSION_ID_PATTERN = '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
/** The same, or the nil UUID: an a-MCP event id (a-MCP §4). */
export const EVENT_ID_PATTERN =
  '^([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$';
/** An RFC 3339 date-time in UTC with a `Z` suffix, seconds required, as a-MCP writes `host_ts`. */
export const DATETIME_PATTERN = String.raw`^(?:(?:\d\d[2468][048]|\d\d[13579][26]|\d\d0[48]|[02468][048]00|[13579][26]00)-02-29|\d{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12]\d|3[01])|(?:0[469]|11)-(?:0[1-9]|[12]\d|30)|(?:02)-(?:0[1-9]|1\d|2[0-8])))T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?Z$`;
/** An https URL; and one without a fragment, which a key id joins to a `kid` with `#` (§10.2). */
export const HTTPS_PATTERN = '^https://';
export const HTTPS_NO_FRAGMENT_PATTERN = '^https://[^#]+$';
/** No control characters (§7.1). */
export const HEADER_VALUE_PATTERN = '^[^\\u0000-\\u001f\\u007f]+$';
/** What `Authorization: {scheme} {credentials}` carries (§6.1, RFC 9110 §11.4): a token, and visible ASCII. */
export const AUTH_SCHEME_PATTERN = "^[!#$%&'*+.^_`|~0-9A-Za-z-]+$";
export const AUTH_CREDENTIALS_PATTERN = '^[\\x21-\\x7e](?:[\\x20-\\x7e]*[\\x21-\\x7e])?$';

const sessionIdRegex = new RegExp(SESSION_ID_PATTERN);
const eventIdRegex = new RegExp(EVENT_ID_PATTERN);
const datetimeRegex = new RegExp(DATETIME_PATTERN);
const httpsRegex = new RegExp(HTTPS_PATTERN);
const httpsNoFragmentRegex = new RegExp(HTTPS_NO_FRAGMENT_PATTERN);
const headerValueRegex = new RegExp(HEADER_VALUE_PATTERN);
const chainHashRegex = /^[0-9a-f]{64}$/;
const base64urlRegex = /^[A-Za-z0-9_-]+$/;

/** The a-MCP conformance levels (a-MCP §5). */
export const Level = { L1: 'L1', L2: 'L2' } as const;
export type Level = (typeof Level)[keyof typeof Level];

/** The a-MCP countersignature axis (a-MCP §5.2). */
export const Countersign = { NONE: 'none', HOST: 'host' } as const;
export type Countersign = (typeof Countersign)[keyof typeof Countersign];

/** a-MCP Tier-1 abort codes (a-MCP §7.2, §7.6): why a Task is held (§7.3). */
export const ABORT_REASONS = [
  'host-unavailable',
  'host-rejected',
  'host-uncountersigned',
  'host-signature-invalid',
  'hash-mismatch',
] as const;
/** a-MCP Tier-1 host reject and unavailable codes (a-MCP §7.6): what the audit host answered (§7.3). */
export const HOST_REASONS = [
  'schema-invalid',
  'replay-detected',
  'signature-invalid',
  'l2-unsigned',
  'unknown-key',
  'internal-error',
] as const;

const levelSchema = z.enum([Level.L1, Level.L2]);
const countersignSchema = z.enum([Countersign.NONE, Countersign.HOST]);
const httpsUrlNoFragment = z.string().regex(httpsNoFragmentRegex);
const headerValue = z.string().regex(headerValueRegex);

/** §3.1: the Agent Card's `params`. A Level-2 Server Agent names its keys. */
export const agentCardParamsSchema = z
  .strictObject({
    level: levelSchema,
    countersign: countersignSchema,
    selfChain: z.boolean().optional(),
    attestationKeys: httpsUrlNoFragment.optional(),
  })
  .refine((params) => params.level !== Level.L2 || params.attestationKeys !== undefined, {
    message: 'a Level-2 Server Agent names its keys (§3.1)',
    path: ['attestationKeys'],
  });
export type AgentCardParams = z.infer<typeof agentCardParamsSchema>;

/** A2A's AuthenticationInfo (A2A §4.3.2), with both members required and free of control characters. */
export const authenticationInfoSchema = z.strictObject({
  scheme: z.string().regex(new RegExp(AUTH_SCHEME_PATTERN)),
  credentials: z.string().regex(new RegExp(AUTH_CREDENTIALS_PATTERN)),
});
export type AuthenticationInfo = z.infer<typeof authenticationInfoSchema>;

/** §7.1: `SendMessageRequest.metadata[URI].auditRequest`. A countersigning audit host names its keys. */
const auditRequestObject = z.strictObject({
  auditEndpoint: z.strictObject({
    url: z.string().regex(httpsRegex),
    authentication: authenticationInfoSchema,
    token: headerValue.optional(),
  }),
  sessionId: z.string().regex(sessionIdRegex),
  level: levelSchema,
  countersign: countersignSchema,
  hostKeys: httpsUrlNoFragment.optional(),
  expiresAt: z.string().regex(datetimeRegex),
});
const namesHostKeys = (request: { countersign: Countersign; hostKeys?: string | undefined }): boolean =>
  request.countersign !== Countersign.HOST || request.hostKeys !== undefined;
const namesHostKeysError = { message: 'a countersigning audit host names its keys (§7.1)', path: ['hostKeys'] };
export const auditRequestSchema = auditRequestObject.refine(namesHostKeys, namesHostKeysError);
export type AuditRequest = z.infer<typeof auditRequestSchema>;

/** The `auditRequest` as the Server Agent's own ledger keeps it: without the endpoint's credentials (§13.2). */
export const journaledRequestSchema = auditRequestObject
  .extend({ auditEndpoint: z.strictObject({ url: z.string().regex(httpsRegex) }) })
  .refine(namesHostKeys, namesHostKeysError);

/** §7.2: `Task.metadata[URI].auditSession`. */
export const auditSessionSchema = z.strictObject({
  sessionId: z.string().regex(sessionIdRegex),
  level: levelSchema,
  countersign: countersignSchema,
});
export type AuditSession = z.infer<typeof auditSessionSchema>;

/** §7.3: the annotation on a held Task's status message. */
export const auditStatusSchema = z.strictObject({
  reason: z.enum(ABORT_REASONS),
  hostReason: z.enum(HOST_REASONS).optional(),
  httpStatus: z.int().min(100).max(599).optional(),
  attemptId: z.string().regex(eventIdRegex).optional(),
});
export type AuditStatus = z.infer<typeof auditStatusSchema>;

/** §7.4: a replacement of the endpoint's credentials. */
export const auditCredentialsSchema = z.strictObject({
  authentication: authenticationInfoSchema,
  token: headerValue.optional(),
});
export type AuditCredentials = z.infer<typeof auditCredentialsSchema>;

/** §6.1: the body of one POST to the audit endpoint, carrying exactly one of event, position, close. */
export const auditSubmissionSchema = z
  .strictObject({
    taskId: z.string().min(1),
    token: headerValue.optional(),
    event: z.record(z.string(), z.unknown()).optional(),
    position: z.literal(true).optional(),
    close: z.literal(true).optional(),
  })
  .refine(
    (submission) =>
      [submission.event, submission.position, submission.close].filter((value) => value !== undefined).length === 1,
    { message: 'a submission carries exactly one of event, position, or close (§6.1)' },
  );
export type AuditSubmission = z.infer<typeof auditSubmissionSchema>;

/** §6.5: a session's last sealed record, in the host-assigned fields of an a-MCP accept (a-MCP §7.1). */
export const sealedPositionSchema = z
  .strictObject({
    seq: z.int().min(0).max(Number.MAX_SAFE_INTEGER),
    host_ts: z.string().regex(datetimeRegex),
    previous_hash: z.string().regex(chainHashRegex),
    record_hash: z.string().regex(chainHashRegex),
    log_id: z.string().min(1).optional(),
    host_signature: z.string().regex(base64urlRegex).optional(),
    host_key_id: z.string().min(1).optional(),
  })
  .refine(
    (position) => {
      const present = [position.log_id, position.host_signature, position.host_key_id].filter((v) => v !== undefined);
      return present.length === 0 || present.length === 3;
    },
    { message: 'log_id, host_signature, and host_key_id appear together or not at all (a-MCP §7.1)' },
  );
export type SealedPosition = z.infer<typeof sealedPositionSchema>;

export const sessionPositionSchema = z.strictObject({ last: sealedPositionSchema.nullable() });
export type SessionPosition = z.infer<typeof sessionPositionSchema>;
