/**
 * The walk's Client process: delegates one Task after verifying the Agent Card signature (§3.1, §5.1).
 *
 * stdin: `{ agentUrl, auditRequest, text }`. stdout: `{ state, audited, taskId, contextId, auditStatus }`, or
 * `{ rejected: { field, sessionInUse? } }` (§4.4).
 */

import { AgentCard, Message, taskStateToJSON, verifyAgentCardSignature } from '@a2a-js/sdk';
import { ClientFactory } from '@a2a-js/sdk/client';
import { readRejection, sendAudited } from '../src/a2a';
import { readAuditStatus } from '../src/admission';
import type { AuditRequest } from '../src/models';

const chunks: Buffer[] = [];
for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
const { agentUrl, auditRequest, text } = JSON.parse(Buffer.concat(chunks).toString('utf8')) as {
  agentUrl: string;
  auditRequest: AuditRequest;
  text: string;
};

const card = AgentCard.fromJSON(await (await fetch(`${agentUrl}/.well-known/agent-card.json`)).json());
await verifyAgentCardSignature(async (kid, jku) => {
  const jwks = (await (await fetch(jku as string)).json()) as { keys: Array<Record<string, unknown>> };
  const jwk = jwks.keys.find((key) => key.kid === kid);
  if (jwk === undefined) throw new Error(`no key ${String(kid)} at ${String(jku)}`);
  return jwk;
})(card);

const client = await new ClientFactory().createFromAgentCard(card);
const params = {
  tenant: '',
  configuration: undefined,
  metadata: undefined,
  message: Message.fromJSON({ messageId: crypto.randomUUID(), role: 'ROLE_USER', parts: [{ text }] }),
};
try {
  const { result, audited } = await sendAudited(client, params, auditRequest);
  const state = 'status' in result ? taskStateToJSON(result.status?.state ?? 0) : 'message';
  const taskId = 'status' in result ? result.id : null;
  const auditStatus = 'status' in result ? readAuditStatus(result.status?.message?.metadata)?.status : undefined;
  const contextId = 'status' in result ? result.contextId : null;
  process.stdout.write(`${JSON.stringify({ state, audited, taskId, contextId, auditStatus })}\n`);
} catch (error) {
  const rejection = readRejection(error);
  if (rejection === undefined) throw error;
  process.stdout.write(`${JSON.stringify({ rejected: rejection })}\n`);
}
