/**
 * The Server Agent's own ledger (§5.5, §9.3): §5.5's write-ahead entries, chained as a-MCP §8 seals records, one
 * Task per partition. The entry format is this SDK's; credentials are never written (§13.2).
 */

import { computeRecordHash, GENESIS_HASH, Ledger, type LedgerRepository, type SealedRecord } from 'auditable-mcp-sdk';
import { z } from 'zod';
import { journaledRequestSchema } from './models';

const jsonObject = z.record(z.string(), z.unknown());
const id = z.string().min(1);

const journalEntrySchema = z.discriminatedUnion('entry', [
  z.strictObject({
    entry: z.literal('session'),
    taskId: z.string().min(1),
    request: journaledRequestSchema,
    /** Under Level 2, the `key_id` the Server Agent signs the session's events with (§5.2). */
    keyId: z.string().min(1).optional(),
    /** Under `countersign: "host"`, the audit host's JWKS the countersignatures verify against (§10.2). */
    hostKeySnapshot: z.strictObject({ keys: z.array(jsonObject) }).optional(),
  }),
  z.strictObject({ entry: z.literal('sent'), event: jsonObject }),
  z.strictObject({ entry: z.literal('response'), id, response: jsonObject }),
  z.strictObject({ entry: z.literal('performing'), id }),
  z.strictObject({ entry: z.literal('resolved'), id, outcome: z.enum(['success', 'failed']) }),
  z.strictObject({ entry: z.literal('acked'), id }),
  z.strictObject({ entry: z.literal('close') }),
]);

/** The `auditRequest` as the session entry keeps it: without the endpoint's credentials (§13.2). */
export type JournaledRequest = z.infer<typeof journaledRequestSchema>;

export type JournalEntry = z.infer<typeof journalEntrySchema>;

/** The Server Agent's own ledger could not be written, or could not be restored as written (§5.5). */
export class SelfLedgerError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'SelfLedgerError';
  }
}

/** One Task's partition of the Server Agent's own ledger (§5.5). */
export class SelfLedger {
  readonly #repository: LedgerRepository;
  readonly #ledger: Ledger;
  readonly #now: () => string;
  #queue: Promise<unknown> = Promise.resolve();
  // Set while a failed append's fate is unknown; the next write rereads the tail first.
  #tailUncertain = false;

  private constructor(repository: LedgerRepository, partition: string, now: () => string) {
    this.#repository = repository;
    this.#ledger = new Ledger(partition);
    this.#now = now;
  }

  /**
   * Open the partition, continuing the chain from its persisted tail.
   *
   * @throws {SelfLedgerError} The partition's tail could not be read.
   */
  static async open(
    repository: LedgerRepository,
    partition: string,
    now: () => string = () => new Date().toISOString(),
  ): Promise<SelfLedger> {
    const ledger = new SelfLedger(repository, partition, now);
    await ledger.#reload();
    return ledger;
  }

  get partition(): string {
    return this.#ledger.partition;
  }

  /**
   * Durably append one entry, after every earlier one.
   *
   * @throws {SelfLedgerError} The entry was not written; what it would have preceded must not happen.
   */
  async write(entry: JournalEntry): Promise<void> {
    const run = this.#queue.then(async () => {
      if (this.#tailUncertain) await this.#reload();
      const record = this.#ledger.seal(entry as Record<string, unknown>, this.#now());
      this.#tailUncertain = true;
      try {
        await this.#repository.append(this.partition, record);
      } catch (error) {
        // The append may have landed; the tail decides.
        await this.#reload().catch((reload: unknown) => {
          console.error('auditable-a2a: the own ledger tail could not be read back after a failed append', reload);
        });
        throw new SelfLedgerError(`the own ledger did not take a ${entry.entry} entry`, { cause: error });
      }
      this.#ledger.commit(record);
      this.#tailUncertain = false;
    });
    this.#queue = run.catch(() => undefined);
    return run;
  }

  /**
   * Every entry of the partition, after recomputing its chain (a-MCP §8.2).
   *
   * @throws {SelfLedgerError} The chain does not recompute, or an entry is not one this SDK writes: the ledger
   *   cannot be restored (§5.5).
   */
  async entries(): Promise<JournalEntry[]> {
    let records: SealedRecord[];
    try {
      records = await this.#repository.readAll(this.partition);
    } catch (error) {
      throw new SelfLedgerError(`the own ledger ${this.partition} could not be read`, { cause: error });
    }
    let previous = GENESIS_HASH;
    for (const [index, record] of records.entries()) {
      if (
        record.seq !== index ||
        record.previous_hash !== previous ||
        record.record_hash !== computeRecordHash(record.event, record.seq, record.host_ts, record.previous_hash)
      ) {
        throw new SelfLedgerError(`the own ledger's chain breaks at seq ${index} of ${this.partition}`);
      }
      previous = record.record_hash;
    }
    return records.map((record) => {
      const parsed = journalEntrySchema.safeParse(record.event);
      if (!parsed.success) {
        throw new SelfLedgerError(
          `the own ledger holds an entry it did not write at seq ${record.seq} of ${this.partition}`,
          {
            cause: parsed.error,
          },
        );
      }
      return parsed.data;
    });
  }

  async #reload(): Promise<void> {
    let tail: SealedRecord | null;
    try {
      tail = await this.#repository.loadTail(this.partition);
    } catch (error) {
      this.#tailUncertain = true;
      throw new SelfLedgerError(`the own ledger tail of ${this.partition} could not be read`, { cause: error });
    }
    this.#ledger.resumeFrom(tail);
    this.#tailUncertain = false;
  }
}
