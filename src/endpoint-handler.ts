/** The audit endpoint over HTTP (§6), as a Fetch-API `Request` -> `Response` handler. */

import type { A2aAuditHost, SubmissionAnswer } from './audit-host';

/** Default cap on a request body; a submission is one a-MCP event or marker (§6.1). */
export const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;

export interface AuditEndpointHandlerOptions {
  /** The largest request body read; a larger one is refused with `413` before it is parsed. */
  maxBodyBytes?: number;
}

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
}

// The scheme of the credentials the audit host issues, which a 401 names (§6.6, RFC 9110 §15.5.2).
const CHALLENGE = { 'www-authenticate': 'Bearer' };

async function readCapped(request: Request, maxBytes: number): Promise<Uint8Array | null> {
  if (request.body === null) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

/** Return a handler answering `POST` submissions at the audit endpoint (§6.1 - §6.7). */
export function createAuditEndpointHandler(
  host: A2aAuditHost,
  options: AuditEndpointHandlerOptions = {},
): (request: Request) => Promise<Response> {
  const maxBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  return async (request) => {
    if (request.method !== 'POST') {
      return new Response(null, { status: 405, headers: { allow: 'POST' } });
    }
    const bytes = await readCapped(request, maxBytes);
    if (bytes === null) {
      return json(413, { error: `a submission is at most ${maxBytes} bytes` });
    }
    let body: unknown;
    try {
      body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    } catch {
      return json(400, { error: 'the body is not JSON (§6.1)' });
    }
    let answer: SubmissionAnswer;
    try {
      answer = await host.handle(body, request.headers.get('authorization'));
    } catch (error) {
      // §6.2, §6.3: a 503 is read as not recorded.
      console.error('auditable-a2a: the audit host failed to answer a submission', error);
      return json(503, { error: 'the submission could not be recorded; send it again (§6.3)' });
    }
    const headers = answer.status === 401 ? CHALLENGE : {};
    return answer.body === undefined
      ? new Response(null, { status: answer.status, headers })
      : json(answer.status, answer.body, headers);
  };
}
