import type { D1Database } from "@cloudflare/workers-types";
import { z } from "zod";

import { LEDGER_HISTORY_SQL } from "./ledger-history-sql.ts";

const MAX_PAGES_PER_BATCH = 20;
const TimestampSchema = z.string().regex(/^\d{1,12}\.\d{6}$/u);
const ScopeSchema = z.strictObject({
  teamId: z.string().min(1).max(100),
  channelId: z.string().min(1).max(100),
  botId: z.string().min(1).max(100),
});
const EntrySchema = z.strictObject({
  changeKey: z.string().min(1).max(200),
  timestamp: TimestampSchema,
});
const PageSchema = z.strictObject({
  timestamps: z.array(TimestampSchema).max(200),
  entries: z.array(EntrySchema).max(200),
  hasMore: z.boolean(),
});
const CheckpointSchema = z.strictObject({
  revision: z.number().int().nonnegative(),
  syncedThrough: TimestampSchema.nullable(),
  scanNewest: TimestampSchema.nullable(),
  scanBefore: TimestampSchema.nullable(),
});
const DUPLICATE_KEY = "workspace_directory_ledger_duplicate_change_key";
const PAGE_INVALID = "workspace_directory_ledger_history_page_invalid";

export type WorkspaceLedgerHistoryScope = z.output<typeof ScopeSchema>;
export type WorkspaceLedgerHistoryEntry = z.output<typeof EntrySchema>;
export type WorkspaceLedgerHistoryPage = z.output<typeof PageSchema>;
export interface WorkspaceLedgerHistoryBounds {
  latest: null | string;
  oldest: null | string;
}

export interface WorkspaceLedgerHistoryIndex {
  findTimestamp(
    scope: WorkspaceLedgerHistoryScope,
    changeKey: string,
  ): Promise<null | string>;
  record(
    scope: WorkspaceLedgerHistoryScope,
    entry: WorkspaceLedgerHistoryEntry,
  ): Promise<void>;
  synchronize(
    scope: WorkspaceLedgerHistoryScope,
    read: (
      bounds: WorkspaceLedgerHistoryBounds,
    ) => Promise<WorkspaceLedgerHistoryPage>,
  ): Promise<boolean>;
}

export class D1WorkspaceLedgerHistoryIndex implements WorkspaceLedgerHistoryIndex {
  readonly #db: D1Database;
  readonly #sql: (typeof LEDGER_HISTORY_SQL)[keyof typeof LEDGER_HISTORY_SQL];

  constructor(
    db: D1Database,
    ledger: keyof typeof LEDGER_HISTORY_SQL = "workspace-directory",
  ) {
    this.#db = db;
    this.#sql = LEDGER_HISTORY_SQL[ledger];
  }

  async synchronize(
    input: WorkspaceLedgerHistoryScope,
    read: (
      bounds: WorkspaceLedgerHistoryBounds,
    ) => Promise<WorkspaceLedgerHistoryPage>,
  ): Promise<boolean> {
    const scope = ScopeSchema.parse(input);
    await this.#db
      .prepare(this.#sql.start)
      .bind(scope.teamId, scope.channelId, scope.botId)
      .run();
    for (
      let pageNumber = 0;
      pageNumber < MAX_PAGES_PER_BATCH;
      pageNumber += 1
    ) {
      // eslint-disable-next-line no-await-in-loop -- Each committed page fences the next provider boundary.
      const checkpoint = await this.#readCheckpoint(scope);

      const page = PageSchema.parse(
        // eslint-disable-next-line no-await-in-loop -- Timestamp pagination resumes from the last durable page.
        await read({
          latest: checkpoint.scanBefore,
          oldest: checkpoint.syncedThrough,
        }),
      );
      validatePage(page, checkpoint);
      const newest =
        checkpoint.scanNewest ??
        page.timestamps[0] ??
        checkpoint.syncedThrough ??
        "0.000000";
      const before = page.hasMore ? (page.timestamps.at(-1) ?? null) : null;
      // eslint-disable-next-line no-await-in-loop -- References and the page checkpoint commit in one transaction.
      const results = await this.#db.batch([
        this.#db
          .prepare(this.#sql.insertPage)
          .bind(
            scope.teamId,
            scope.channelId,
            scope.botId,
            JSON.stringify(page.entries),
            checkpoint.revision,
          ),
        this.#db
          .prepare(this.#sql.advance)
          .bind(
            scope.teamId,
            scope.channelId,
            scope.botId,
            page.hasMore ? checkpoint.syncedThrough : newest,
            page.hasMore ? newest : null,
            before,
            checkpoint.revision,
          ),
      ]);
      if (results[1]?.meta.changes !== 1)
        throw new Error("workspace_directory_ledger_history_index_fenced");
      if (!page.hasMore) {
        // eslint-disable-next-line no-await-in-loop -- A complete range must be free of duplicate change keys.
        await this.#assertNoDuplicates(scope);
        return true;
      }
    }
    return false;
  }

  async findTimestamp(
    input: WorkspaceLedgerHistoryScope,
    changeKey: string,
  ): Promise<null | string> {
    const scope = ScopeSchema.parse(input);
    const key = EntrySchema.shape.changeKey.parse(changeKey);
    const checkpoint = await this.#readCheckpoint(scope);
    if (checkpoint.syncedThrough === null || checkpoint.scanBefore !== null)
      throw new Error("workspace_directory_ledger_history_index_incomplete");
    const rows = await this.#db
      .prepare(this.#sql.find)
      .bind(scope.teamId, scope.channelId, scope.botId, key)
      .all();
    if (rows.results.length > 1) throw new Error(DUPLICATE_KEY);
    const row = rows.results[0];
    return row === undefined
      ? null
      : EntrySchema.pick({ timestamp: true }).parse(row).timestamp;
  }

  async record(
    input: WorkspaceLedgerHistoryScope,
    rawEntry: WorkspaceLedgerHistoryEntry,
  ): Promise<void> {
    const scope = ScopeSchema.parse(input);
    const entry = EntrySchema.parse(rawEntry);
    await this.#db
      .prepare(this.#sql.record)
      .bind(
        scope.teamId,
        scope.channelId,
        scope.botId,
        entry.changeKey,
        entry.timestamp,
      )
      .run();
    await this.findTimestamp(scope, entry.changeKey);
  }

  async #readCheckpoint(scope: WorkspaceLedgerHistoryScope) {
    return CheckpointSchema.parse(
      await this.#db
        .prepare(this.#sql.checkpoint)
        .bind(scope.teamId, scope.channelId, scope.botId)
        .first(),
    );
  }

  async #assertNoDuplicates(scope: WorkspaceLedgerHistoryScope): Promise<void> {
    const duplicate = await this.#db
      .prepare(this.#sql.duplicate)
      .bind(scope.teamId, scope.channelId, scope.botId)
      .first();
    if (duplicate !== null) throw new Error(DUPLICATE_KEY);
  }
}

function validatePage(
  page: WorkspaceLedgerHistoryPage,
  checkpoint: z.output<typeof CheckpointSchema>,
): void {
  let previous = checkpoint.scanBefore;
  for (const timestamp of page.timestamps) {
    if (
      (previous !== null &&
        timestampValue(timestamp) >= timestampValue(previous)) ||
      (checkpoint.syncedThrough !== null &&
        timestampValue(timestamp) <= timestampValue(checkpoint.syncedThrough))
    )
      throw new Error(PAGE_INVALID);
    previous = timestamp;
  }
  if (page.hasMore && page.timestamps.length === 0)
    throw new Error(PAGE_INVALID);
  const timestamps = new Set(page.timestamps);
  if (page.entries.some((entry) => !timestamps.has(entry.timestamp)))
    throw new Error(PAGE_INVALID);
}

function timestampValue(timestamp: string): bigint {
  return BigInt(timestamp.replace(".", ""));
}
