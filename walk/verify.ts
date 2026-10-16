/**
 * The walk's verifier (§11). stdin: `{ records, sessions, hostKeys, hostKeySnapshot }`; stdout:
 * `{ complete, findings, unchecked, amcpIssues }`.
 */

import { CountersignatureRegistryVerifier, KeyRole, type SealedRecord } from 'auditable-mcp-sdk';
import { registryFromJwks } from '../src/keys';
import { type SessionEvidence, verifyA2aLedger } from '../src/verify';

interface Input {
  records: SealedRecord[];
  sessions: SessionEvidence[];
  hostKeys: string;
  hostKeySnapshot: { keys: Record<string, unknown>[] };
}

const chunks: Buffer[] = [];
for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
const input = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Input;
const checker = new CountersignatureRegistryVerifier(
  registryFromJwks(input.hostKeys, input.hostKeySnapshot, KeyRole.HOST),
).check;
const report = verifyA2aLedger(input.records, input.sessions, { countersignatureChecker: checker });
process.stdout.write(
  `${JSON.stringify({
    complete: report.complete,
    findings: report.findings.map((finding) => finding.code),
    unchecked: report.unchecked,
    amcpIssues: report.amcp.issues,
  })}\n`,
);
