/**
 * The walk's audit host process (Level 2, countersigning); same routes as the Python SDK's `audit_host.py`:
 * - `POST /a2a`: the audit endpoint.
 * - `GET /keys.json`: the countersignature keys, as `hostKeys` names them (§10.2).
 * - `POST /admin/sessions`: open a session for a delegation (§5.1), as the Client asks its own audit host.
 * - `GET /admin/ledger`: the partition's records and each session's evidence, for the verifiers (§11).
 * - `POST /admin/outcomes`: `{"refuse": true}` answers outcomes `503` until set back.
 * - `POST /admin/attempts`: `{"refuse": "<action_type>"}` answers attempts of that kind `503` until set back with
 *   `null`.
 * - `GET /admin/exchanges`: every submission and its answer, in order, for the end-to-end example (§16).
 */

import { Ed25519Countersigner, generateToolKey, KeyRole } from 'auditable-mcp-sdk';
import { A2aAuditHost } from '../src/audit-host';
import { createAuditEndpointHandler } from '../src/endpoint-handler';
import { keyIdOf } from '../src/keys';
import { Countersign, Level } from '../src/models';
import { InMemorySessionStore } from '../src/session-store';
import { json, ordinaryJwk, serve } from './common';

await serve(async (base) => {
  const hostKeys = `${base}/keys.json`;
  const hostKey = generateToolKey(keyIdOf(hostKeys, 'h1'));
  const store = new InMemorySessionStore();
  const host = A2aAuditHost.create('walk-client', Level.L2, Countersign.HOST, {
    store,
    countersigner: new Ed25519Countersigner(hostKey.keyId, hostKey.privateKey),
  });
  const endpoint = createAuditEndpointHandler(host);
  let refuseOutcomes = false;
  let refuseAttempts: string | null = null;
  const exchanges: Array<{ submission: unknown; status: number; answer: unknown }> = [];

  return async (request) => {
    const path = new URL(request.url).pathname;
    if (path === '/a2a') {
      const body = await request.text();
      let submission: { event?: { outcome?: unknown; action_type?: unknown } } = {};
      try {
        submission = JSON.parse(body) as typeof submission;
      } catch {
        // Not JSON: the endpoint answers it as such.
      }
      const event = submission.event ?? {};
      const refused =
        (refuseOutcomes && event.outcome !== undefined && event.outcome !== 'attempted') ||
        (refuseAttempts !== null && event.outcome === 'attempted' && event.action_type === refuseAttempts);
      if (refused) {
        exchanges.push({ submission, status: 503, answer: null });
        return new Response(null, { status: 503 });
      }
      const answer = await endpoint(new Request(request.url, { method: 'POST', headers: request.headers, body }));
      const text = await answer.clone().text();
      let parsed: unknown = null;
      try {
        parsed = text === '' ? null : JSON.parse(text);
      } catch {
        parsed = null;
      }
      exchanges.push({ submission, status: answer.status, answer: parsed });
      return answer;
    }
    if (path === '/keys.json') return json({ keys: [ordinaryJwk('h1', hostKey.publicKey, KeyRole.HOST)] });
    if (path === '/admin/sessions') {
      const input = (await request.json()) as {
        delegate: string;
        expiresAt: string;
        attestationKeys: string;
        keySnapshot: { keys: Record<string, unknown>[] };
      };
      const opened = await host.openSession({ ...input, hostKeys });
      return json({ sessionId: opened.sessionId, authentication: opened.authentication, hostKeys });
    }
    if (path === '/admin/ledger') {
      const sessions = (await store.all()).map((state) => ({
        sessionId: state.sessionId,
        version: state.version,
        level: state.level,
        countersign: state.countersign,
        ...(state.attestationKeys === undefined ? {} : { attestationKeys: state.attestationKeys }),
        ...(state.keySnapshot === undefined ? {} : { keySnapshot: state.keySnapshot }),
        ...(state.boundKeyId === undefined ? {} : { boundKeyId: state.boundKeyId }),
        ...(state.end === undefined ? {} : { end: state.end }),
        anomalies: state.anomalies,
      }));
      return json({ records: host.records(), sessions });
    }
    if (path === '/admin/attempts') {
      refuseAttempts = ((await request.json()) as { refuse: string | null }).refuse;
      return json({ refuse: refuseAttempts });
    }
    if (path === '/admin/exchanges') return json({ exchanges });
    if (path === '/admin/outcomes') {
      refuseOutcomes = ((await request.json()) as { refuse: boolean }).refuse;
      return json({ refuse: refuseOutcomes });
    }
    return new Response(null, { status: 404 });
  };
});
