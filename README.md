# Auditable A2A SDK (TypeScript)

A protocol machine for [Auditable A2A](https://github.com/SatoshiImai/auditable-a2a) (`auditable-a2a/0.1`), the
[A2A](https://a2a-protocol.org/) extension under which **no act a Server Agent records on a Client's behalf proceeds
unless it was first recorded in the Client's audit ledger**. It gives each party its part: the Client's audit host
that seals the records, the Server Agent that records before it acts, the Client that delegates and reads the
answer, and the verifier that checks the Client's ledger.

It builds on [`auditable-mcp-sdk`](https://github.com/SatoshiImai/auditable-mcp-sdk-ts), whose event,
canonicalization, ledger, signatures, and verifier it uses unchanged, and binds to the official
[A2A JavaScript SDK](https://github.com/a2aproject/a2a-js) (`@a2a-js/sdk`). It is the TypeScript counterpart of the
[Python SDK](https://github.com/SatoshiImai/auditable-a2a-sdk-python) and shares its vendored schemas and vectors, so
both reproduce the same bytes, and each one's parties work with the other's.

**The specification is the source of truth.** For what is on the wire, when a Task is held, and what a verifier
reports, read [`spec/auditable-a2a.md`](https://github.com/SatoshiImai/auditable-a2a/blob/master/spec/auditable-a2a.md);
this SDK implements it, and section numbers below (§) are its.

## Scope

What this SDK does:

- **The audit host** (§5, §6): `A2aAuditHost` wraps the Auditable MCP host for a session as long as a Task. It keeps
  what §5.1 asks of each session, binds the session to a Task and a key, takes the end from a message and still
  seals outcomes and execution reports after it, survives its own restart through a `SessionStore` (§5.6), and
  rotates credentials (§5.7). `createAuditEndpointHandler` serves it as a Fetch-API `Request` -> `Response`
  handler.
- **The Server Agent** (§6, §8): `AuditedTask` records each access before it over the HTTPS binding - one submission
  at a time, a bounded wait, no redirects, outcomes owed until acknowledged - with Polluted Stop at both levels and
  countersignatures verified against the host's key snapshot. It gives the `auditStatus` of a hold, sends execution
  reports, and says whether the Task may end.
- **Resumption** (§5.5): given a `SelfLedger`, its own ledger, `AuditedTask` writes ahead what §5.5 lists, and
  `resumeTask` restores the Task from that ledger alone after a restart, without performing any access again.
- **The decisions on the A2A messages** (§3, §4, §7), on plain JSON: the Agent Card declaration, whether a request
  is audit-negotiated, ordinary, or rejected at a named field, `auditCredentials`, the extension's `metadata`, and
  what a Client does about a hold (§8.5).
- **The binding to the official A2A SDK** (`auditable-a2a-sdk/a2a`): a request handler that decides each request
  before the SDK takes it, an executor that places `auditSession` in every Task, and a Client's delegation.
- **The verifier** (§11): a-MCP's verification of the partition, with each Level-2 record checked against its own
  session's key snapshot, and this extension's checks per session.

What it does not do (your concern, behind interfaces):

- No storage backend. `SessionStore` and `LedgerRepository` are interfaces; in-memory implementations are included
  for tests.
- No HTTP server. The audit endpoint is a Fetch-API handler; serve it with whatever serves `Request` ->
  `Response`.
- No agent logic, and no in-process private keys in production: sign through a KMS or HSM, as
  `auditable-mcp-sdk` provides.

## Status

Alpha, tracking `auditable-a2a/0.1`. The public API is unstable while the specification is a draft.

## Compatibility

| | Version |
| :-- | :-- |
| Auditable A2A | `auditable-a2a/0.1` |
| A2A Protocol | [v1.0.0](https://a2a-protocol.org/v1.0.0/specification/) |
| Auditable MCP | `auditable-mcp/0.4`, through `auditable-mcp-sdk` 0.4 |
| `@a2a-js/sdk` (optional) | 1.3.x |

| A2A binding | Client | Server Agent |
| :-- | :--: | :--: |
| **JSON-RPC** | ✅ | ✅ |
| **HTTP+JSON/REST** | not yet tested | not yet tested |
| **gRPC** | not yet tested | not yet tested |

The extension's `metadata` is the same JSON object on every binding (§7), and the request handler and executor this
SDK wraps are the ones the SDK serves every binding with. The tests and the walk run over JSON-RPC.

## Install

Releases are published as tags of this repository, not to the npm registry:

```bash
npm install git+https://github.com/SatoshiImai/auditable-a2a-sdk-ts.git#v0.1.1
npm install @a2a-js/sdk   # for auditable-a2a-sdk/a2a
```

It depends on [`auditable-mcp-sdk`](https://github.com/SatoshiImai/auditable-mcp-sdk-ts) `v0.4.0`, installed the
same way. ESM-only. Requires Node.js 20+; the core runs wherever Web Crypto and `fetch` do.

| Import | Contents |
| :-- | :-- |
| `auditable-a2a-sdk` | The core: the audit host and its endpoint handler, `AuditedTask`, resumption, the decisions on the A2A messages, the verifier. Imports no A2A SDK. |
| `auditable-a2a-sdk/a2a` | The binding to `@a2a-js/sdk`, an optional peer dependency. |

## Concepts

- **Audit session.** The Client's audit host opens one per delegation and issues its `sessionId` and the endpoint's
  credentials (§5.1). The first attempt binds it to the Task and, under Level 2, to the Server Agent's key. It lasts
  as long as the Task, through restarts of either side (§5.2).
- **Write-ahead.** Before each access it records, the Server Agent sends an attempt and acts only on an accept it
  has verified (§8.1, §8.3). `task.action(...)` does both: it throws `AmcpAbortedError` before the body runs when
  the access cannot be recorded, and the disposer sends the outcome.
- **A hold, not a failure.** An access that cannot be recorded is not performed, and the Task is held in
  `TASK_STATE_AUTH_REQUIRED` with an `auditStatus` (§8.4). `task.statusOf(error)` gives it, and `holdRemedy` tells
  the Client which row of §8.5 it is in.
- **The answer is in the Task.** A Client takes an answer as audited only when its Task, or direct `Message`,
  carries an `auditSession` matching its `auditRequest` (§4.3). Its assurance is its own ledger.
- **Levels and countersignatures.** Level 1 is self-reporting; Level 2 adds the Server Agent's signature and a
  per-session sequence. A countersigning audit host signs every record it seals. These are a-MCP's, unchanged.

## Quickstart

### 1. The audit host

```ts
import { A2aAuditHost, Countersign, createAuditEndpointHandler, InMemorySessionStore, Level } from 'auditable-a2a-sdk';
import { Ed25519Countersigner, generateToolKey, InMemoryLedgerRepository } from 'auditable-mcp-sdk';

const hostKey = generateToolKey('https://audit.client.example/keys.json#h1');
const host = A2aAuditHost.create('client-a', Level.L2, Countersign.HOST, {
  store: new InMemorySessionStore(), // implement SessionStore over your store (§5.6)
  repository: new InMemoryLedgerRepository(), // and LedgerRepository for the ledger itself
  countersigner: new Ed25519Countersigner(hostKey.keyId, hostKey.privateKey),
});

// Before delegating: one session per delegation, with the delegate's key snapshot (§5.1).
const { sessionId, authentication } = await host.openSession({
  delegate: 'https://agent.example/.well-known/agent-card.json',
  expiresAt: '2026-11-15T00:00:00Z',
  attestationKeys: 'https://agent.example/.well-known/jwks.json',
  keySnapshot: delegateJwks, // fetched after verifying the delegate's Agent Card signature
  hostKeys: 'https://audit.client.example/keys.json',
});

// The audit endpoint (§6), as a Request -> Response handler.
const auditEndpoint = createAuditEndpointHandler(host);
```

`A2aAuditHost.resume(...)` brings the host back after a restart, with every session that has not ended open again
(§5.6). A `SessionStore` implements `put`, `all`, and `delete`; `put` must be durable before it returns, since the
host stores a change before it acts on it.

Each session is opened for one version of this extension (§4.1), `version` in `openSession`, defaulting to the one
this SDK implements, and the host records it. A Client that lists several versions of the URI puts an `auditRequest`
under each, with a session of each. Call `host.sweep()` periodically to end the sessions whose expiry has passed and
that receive nothing more (§5.3), and `host.purge(sessionId)` to forget an ended one under your retention policy; its
records stay in the ledger.

### 2. The Server Agent: record, then act

```ts
import { AuditedTask } from 'auditable-a2a-sdk';
import { AmcpAbortedError, Ed25519Signer } from 'auditable-mcp-sdk';

const task = new AuditedTask({
  taskId,
  request, // the validated auditRequest the Task was negotiated with
  signer: Ed25519Signer.fromToolKey(agentKey), // Level 2
  hostKeySnapshot, // fetched from request.hostKeys, under countersign: "host"
});

try {
  await using action = await task.action(
    'ledger.read',
    { kind: 'ledger', ref: 'general-ledger/2026-09' },
    { mutates: false, egress: false, disclose: { period: '2026-09' } },
  );
  await readTheLedger();
  action.succeeded();
} catch (error) {
  if (!(error instanceof AmcpAbortedError)) throw error;
  // Not recorded, so not performed: hold the Task with this as its auditStatus (§7.3, §8.4).
  const auditStatus = task.statusOf(error);
}

// Nothing in flight and every outcome acknowledged: close, then move the Task to its terminal state (§5.4).
if (await task.finish()) {
  // TASK_STATE_COMPLETED
}
```

The outcome is `success` only when `succeeded()` was called before the action is disposed, and `failed` otherwise:
a disposer cannot see whether the body threw. (The Python SDK's `async with` can, and records `failed` when the
body raised.) An access after the session's expiry throws `SessionExpiredError` without sending anything; the Task
is not continued (§5.3).

`task.mayEnd()` is true when nothing is outstanding: no attempt on its way, no accept without its outcome or an
execution report, no outcome unacknowledged. `task.mayEnd(bound)` states that one of §5.4's bounds has passed - a
cancel, the hold's timeout, the expiry, a decision not to resume, a revoked key - and the Task may end with records
still outstanding; the method takes the caller's word for it. While an outcome cannot be delivered, `task.heldStatus()`
gives the `auditStatus` of the hold, of the earliest one owed.

Under `countersign: "host"`, an accept or a position that names a `kid` the snapshot does not hold fetches
`request.hostKeys` again (§10.2); pass `fetchHostKeys` to fetch through your own client. A fetch that fails is a
failure to record, and the access is not performed. A `fetch` you pass must give up when its `signal` aborts, or the
bounded wait (§6.8) does not hold.

`disclose` records context in the clear; `commitSalted` commits to it by its salted hash instead, for what the
Client may see only that it was there (§10.3). An access the Server Agent decides not to perform, or cannot say it
performed, is stated with an execution report (§8.6):

```ts
await task.reportExecution(attemptId, 'not-performed');
```

### 3. Resuming after a restart

Give the Task its own ledger and it writes ahead what §5.5 lists. The `LedgerRepository` behind a `SelfLedger` must
commit each append durably before it returns: resumption trusts an entry as written, and the audit host's position
reveals only what it received, not an entry the Server Agent's own storage lost (§5.5). After a restart, `resumeTask`
restores it from that ledger alone: it resends what was not acknowledged, checks the audit host's last position, and
resolves every accept it holds without performing any again.

```ts
import { AuditedTask, resumeTask, SelfLedger } from 'auditable-a2a-sdk';

const task = new AuditedTask({ taskId, request, signer, hostKeySnapshot, selfLedger: await SelfLedger.open(own, taskId) });

// After a restart:
const resumed = await resumeTask({
  selfLedger: await SelfLedger.open(own, taskId),
  credentials, // the endpoint's credentials, kept as secrets and never in the ledger (§13.2)
  signer,
});
switch (resumed.state) {
  case 'continue': // carry on with resumed.task; what resumed.notPerformed names may be attempted again
  case 'delivered': // the Task was already terminal; its records are delivered
  case 'closed': // the ledger shows the close: complete the move to the terminal state
  case 'held': // hold the Task with resumed.status, and resume again later
  case 'failed': // a check failed: TASK_STATE_FAILED
}
```

### 4. On the official A2A SDK

```ts
import { AgentCard } from '@a2a-js/sdk';
import { DefaultRequestHandler, InMemoryTaskStore } from '@a2a-js/sdk/server';
import { AuditedTask, agentCardExtension, Countersign, Level } from 'auditable-a2a-sdk';
import { type AuditedAgentExecutor, auditedExecutor, auditedRequestHandler, heldForAudit } from 'auditable-a2a-sdk/a2a';

const params = { level: Level.L2, countersign: Countersign.HOST, selfChain: true, attestationKeys };
const card = AgentCard.fromJSON({
  // ...
  capabilities: { extensions: [agentCardExtension(params, { required: true })] },
});

const executor: AuditedAgentExecutor = {
  async execute(requestContext, eventBus, audit) {
    // audit is undefined for an ordinary request; audit.request is there on the one that created the Task.
    // Record each access with an AuditedTask, and publish heldForAudit(...) when one cannot be recorded.
  },
  async cancelTask() {},
};

const handler = auditedRequestHandler(
  new DefaultRequestHandler(card, new InMemoryTaskStore(), auditedExecutor(executor)),
  {
    declaration: { required: true, params },
    sessionInUse: async (sessionId) => undefined, // look up and reserve the sessionId in one step (§4.3)
    onCredentials: async (taskId, credentials) => {}, // hand them to the running AuditedTask (§5.7)
  },
);
```

`auditedRequestHandler` decides each request before the SDK takes it - an executor that throws still leaves a
stored failed Task, and a rejected request must create none (§4.4) - and lists this extension's URI in the response.
Under `required: true` it refuses every request that does not list the URI, not only the first (§4.6). A later
request on an audited Task reaches the executor with that Task's audit even when it does not list the URI.
`auditedExecutor` places `auditSession` in every Task the executor publishes, and in a direct `Message`.

`sessionInUse` must look up and reserve the `sessionId` in one atomic step - a conditional write in your Task store,
or the requests that carry one serialized: two requests that both read "unused" would bind one session to two Tasks.
When the executor answers without creating a Task, discard the `auditRequest`'s credentials with that answer
(§13.2).

On the Client:

```ts
import { readRejection, sendAudited } from 'auditable-a2a-sdk/a2a';

try {
  const { result, audited } = await sendAudited(client, params, auditRequest);
  if (!audited) {
    // Not audited (§4.3).
  }
} catch (error) {
  const rejection = readRejection(error); // §4.4: the field, and the Task a reused sessionId belongs to
}
```

`readAuditStatus(task.status.message.metadata)` reads a hold and the remedy §8.5 gives for it.

### 5. Verifying the Client's ledger

```ts
import { verifyA2aLedger } from 'auditable-a2a-sdk';

const report = verifyA2aLedger(await repository.readAll('client-a'), sessions, { countersignatureChecker });
report.complete; // a-MCP's verification and this extension's checks, with nothing left unchecked
report.findings; // each with the Tier-1 code a consumer that knows only a-MCP reads it as
report.recordsAfterClose; // records the host sealed after a session's close: listed, not findings (§11)
report.unchecked; // what could not be checked: a session of a version not implemented, an input missing
```

Pass the sessions as the audit host stores them (`SessionState`): each is read by the rules of the version it was
opened for, and whether its records must be countersigned comes from its own `countersign`. A session of a version
this verifier does not implement is reported as unchecked, not as a finding.

### Notes

- The JS SDK writes a streaming response's `A2A-Extensions` before the stored Task can be read, so a later request
  on a Task over a streaming call does not list the URI. It is a SHOULD (§4.3); the Client's judgment rests on
  `auditSession`.
- A request carrying this extension's `auditRequest` or `auditCredentials` without listing the URI is rejected: the
  activation was lost on the way, and serving it would act outside the Client's ledger (§4.4).
- A rejection's details are in the `metadata` of an `ErrorInfo` (`INVALID_PARAMS`, `a2a-protocol.org`), which the
  official SDKs carry over JSON-RPC and HTTP+JSON; a Client on a binding or SDK that drops it learns only that the
  request was refused.
- The SDK's client does not show a rejection's details; `readRejection` reads them from the error, where both
  transports put A2A's `ErrorInfo` `metadata` (§4.4).

## The walk

The suite runs every party in one process. The walk, in the Python SDK's checkout, runs the Client, the audit host,
and the Server Agent as **separate processes** over HTTPS, each this SDK's or the Python SDK's, on the official A2A
SDK of its language: every pairing, at Level 2 with countersignatures, with signed Agent Cards. The processes here
are under [`walk/`](walk/); the Python SDK's `make walk` drives them, and both SDKs' verifiers check every ledger it
produces. The specification's end-to-end example (§16) is one of its runs.

## Conformance

The normative JSON Schema and conformance vectors are vendored under [`spec/`](spec/) from the
[specification repository](https://github.com/SatoshiImai/auditable-a2a), byte-identical to the Python SDK's copy.
A conforming implementation reproduces every vector.

```bash
make spec/check    # fail if the vendored spec drifted from its source
make test          # includes the conformance vectors
```

## Development

```bash
make env/init      # install dependencies
make test          # Vitest
make lint          # biome check + tsc --noEmit
make build         # bundle ESM + type declarations to dist/
```

## Note on AI Assistance

The core architecture, design decisions, and core implementations in this project are entirely my own. I used AI tools (Claude, Gemini) strictly under my explicit direction for code generation, text formatting, edge-case verification, and polishing my English prose. All outputs were heavily reviewed, corrected, and finalized by me.

## License

Apache-2.0 (c) Satoshi Imai
