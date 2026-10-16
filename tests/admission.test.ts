/** The decisions on the A2A messages (§3, §4, §7). */

import { describe, expect, it } from 'vitest';
import {
  admitLaterRequest,
  admitNewTask,
  agentCardExtension,
  auditCredentialsMetadata,
  auditRequestMetadata,
  auditSessionMetadata,
  auditStatusMetadata,
  HoldRemedy,
  isAudited,
  readAuditStatus,
} from '../src/admission';
import { type AuditRequest, Countersign, EXTENSION_URI, Level } from '../src/models';

const REQUEST: AuditRequest = {
  auditEndpoint: { url: 'https://audit.client.example/a2a', authentication: { scheme: 'Bearer', credentials: 't' } },
  sessionId: '0199a3e0-7c1f-7a4e-9b1d-5f2f7e0c4a11',
  level: Level.L2,
  countersign: Countersign.HOST,
  hostKeys: 'https://audit.client.example/keys.json',
  expiresAt: '2026-11-15T00:00:00Z',
};
const DECLARATION = {
  required: false,
  params: { level: Level.L2, countersign: Countersign.HOST, attestationKeys: 'https://agent.example/jwks.json' },
};
const FIELD = `metadata[${JSON.stringify(EXTENSION_URI)}]`;
const unused = () => undefined;

describe('the Agent Card declaration (§3)', () => {
  it('declares the URI, the posture, and validated params', () => {
    expect(agentCardExtension(DECLARATION.params, { required: true })).toEqual({
      uri: EXTENSION_URI,
      required: true,
      params: DECLARATION.params,
    });
    expect(() => agentCardExtension({ level: Level.L2, countersign: Countersign.NONE }, { required: false })).toThrow();
  });
});

describe('a request that creates a Task (§4.3 - §4.5)', () => {
  const admit = (overrides: Partial<Parameters<typeof admitNewTask>[0]>) =>
    admitNewTask({
      declaration: DECLARATION,
      requestedExtensions: [EXTENSION_URI],
      metadata: auditRequestMetadata(REQUEST),
      sessionInUse: unused,
      ...overrides,
    });

  it('negotiates, and gives the auditSession to place in every Task', async () => {
    expect(await admit({})).toEqual({
      kind: 'negotiated',
      request: REQUEST,
      auditSession: { sessionId: REQUEST.sessionId, level: Level.L2, countersign: Countersign.HOST },
    });
  });

  it('serves an unactivated request as ordinary, or refuses it under the mandatory posture', async () => {
    expect(await admit({ requestedExtensions: ['https://other.example/ext'], metadata: {} })).toEqual({
      kind: 'ordinary',
    });
    expect(
      await admit({ requestedExtensions: [], metadata: {}, declaration: { ...DECLARATION, required: true } }),
    ).toEqual({ kind: 'unsupported' });
  });

  it('rejects an auditRequest that arrives without the activation, which was lost on the way (§4.4)', async () => {
    expect(await admit({ requestedExtensions: [] })).toEqual({
      kind: 'invalid',
      rejection: { field: `${FIELD}.auditRequest`, description: 'requires this extension in A2A-Extensions' },
    });
  });

  it('rejects an activated request without an auditRequest, naming the field', async () => {
    expect(await admit({ metadata: {} })).toEqual({
      kind: 'invalid',
      rejection: { field: `${FIELD}.auditRequest`, description: 'is required' },
    });
    expect(await admit({ metadata: { [EXTENSION_URI]: 'x' } })).toMatchObject({
      kind: 'invalid',
      rejection: { field: FIELD },
    });
  });

  it('rejects a schema-invalid auditRequest at the field that failed', async () => {
    const metadata = { [EXTENSION_URI]: { auditRequest: { ...REQUEST, expiresAt: '2026-11-15' } } };
    expect(await admit({ metadata })).toMatchObject({
      kind: 'invalid',
      rejection: { field: `${FIELD}.auditRequest.expiresAt` },
    });
  });

  it('rejects a level or countersign the declaration does not meet', async () => {
    const l1 = { ...DECLARATION, params: { level: Level.L1, countersign: Countersign.NONE } };
    expect(await admit({ declaration: l1 })).toMatchObject({ rejection: { field: `${FIELD}.auditRequest.level` } });
    const { hostKeys: _hostKeys, ...uncountersigned } = REQUEST;
    expect(
      await admit({ metadata: auditRequestMetadata({ ...uncountersigned, countersign: Countersign.NONE }) }),
    ).toMatchObject({ rejection: { field: `${FIELD}.auditRequest.countersign` } });
  });

  it('names the Task of a reused sessionId to the same Client only (§4.4)', async () => {
    const same = await admit({ sessionInUse: () => ({ taskId: 'task-9', sameClient: true }) });
    expect(same).toEqual({
      kind: 'invalid',
      rejection: {
        field: `${FIELD}.auditRequest.sessionId`,
        description: 'is already used for another Task',
        sessionInUse: { taskId: 'task-9' },
      },
    });
    const other = await admit({ sessionInUse: () => ({ taskId: 'task-9', sameClient: false }) });
    expect(other).toMatchObject({ kind: 'invalid' });
    expect(JSON.stringify(other)).not.toContain('task-9');
  });

  it('rejects auditCredentials on a request that creates a Task', async () => {
    const metadata = {
      [EXTENSION_URI]: {
        auditRequest: REQUEST,
        auditCredentials: { authentication: { scheme: 'Bearer', credentials: 'u' } },
      },
    };
    expect(await admit({ metadata })).toMatchObject({ rejection: { field: `${FIELD}.auditCredentials` } });
  });
});

describe('a request on an existing Task (§4.6)', () => {
  const credentials = { authentication: { scheme: 'Bearer', credentials: 'u' } };

  it('continues, listing the URI only for an audit-negotiated Task that the request activates', () => {
    expect(
      admitLaterRequest({ requestedExtensions: [EXTENSION_URI], metadata: undefined, auditNegotiated: true }),
    ).toEqual({ kind: 'continue', activate: true });
    expect(admitLaterRequest({ requestedExtensions: [], metadata: undefined, auditNegotiated: true })).toEqual({
      kind: 'continue',
      activate: false,
    });
  });

  it('rejects an auditRequest', () => {
    expect(
      admitLaterRequest({
        requestedExtensions: [EXTENSION_URI],
        metadata: auditRequestMetadata(REQUEST),
        auditNegotiated: true,
      }),
    ).toMatchObject({ kind: 'invalid', rejection: { field: `${FIELD}.auditRequest` } });
  });

  it('takes auditCredentials only when activated on an audit-negotiated Task', () => {
    const metadata = auditCredentialsMetadata(credentials);
    expect(admitLaterRequest({ requestedExtensions: [EXTENSION_URI], metadata, auditNegotiated: true })).toEqual({
      kind: 'credentials',
      credentials,
    });
    expect(admitLaterRequest({ requestedExtensions: [], metadata, auditNegotiated: true })).toMatchObject({
      kind: 'invalid',
    });
    expect(admitLaterRequest({ requestedExtensions: [EXTENSION_URI], metadata, auditNegotiated: false })).toMatchObject(
      {
        kind: 'invalid',
      },
    );
    const control = {
      [EXTENSION_URI]: { auditCredentials: { authentication: { scheme: 'Bearer', credentials: 'a\nb' } } },
    };
    expect(
      admitLaterRequest({ requestedExtensions: [EXTENSION_URI], metadata: control, auditNegotiated: true }),
    ).toMatchObject({ rejection: { field: `${FIELD}.auditCredentials.authentication.credentials` } });
  });
});

describe('the Client reading a response (§4.3, §7.3, §8.5)', () => {
  const session = { sessionId: REQUEST.sessionId, level: REQUEST.level, countersign: REQUEST.countersign };

  it('takes a Task as audited only with an auditSession matching the request', () => {
    const taskMetadata = auditSessionMetadata(session);
    expect(isAudited(REQUEST, taskMetadata)).toBe(true);
    expect(isAudited(REQUEST, {})).toBe(false);
    expect(isAudited({ ...REQUEST, level: Level.L1 }, taskMetadata)).toBe(false);
    const other = auditSessionMetadata({ ...session, sessionId: '0199a3e0-7c1f-7a4e-9b1d-5f2f7e0c4a12' });
    expect(isAudited(REQUEST, other)).toBe(false);
  });

  it('reads a hold and the row of §8.5 it falls in', () => {
    const read = (status: Parameters<typeof auditStatusMetadata>[0]) =>
      readAuditStatus(auditStatusMetadata(status))?.remedy;
    expect(read({ reason: 'host-unavailable', httpStatus: 401 })).toBe(HoldRemedy.REPLACE_CREDENTIALS);
    expect(read({ reason: 'host-unavailable' })).toBe(HoldRemedy.RESTORE_HOST);
    expect(read({ reason: 'host-rejected', hostReason: 'unknown-key' })).toBe(HoldRemedy.DELEGATE_AGAIN);
    expect(read({ reason: 'host-rejected', hostReason: 'replay-detected' })).toBe(HoldRemedy.NOTHING_RESTORES);
    expect(read({ reason: 'host-rejected', hostReason: 'signature-invalid' })).toBe(HoldRemedy.NONE);
    expect(read({ reason: 'hash-mismatch' })).toBe(HoldRemedy.INVESTIGATE_HOST);
    expect(readAuditStatus({})).toBeUndefined();
  });
});
