import { z } from "zod";

import { runtimeFetch } from "../clients/runtime-fetch.ts";
import { defaultSleep, type Sleep } from "../org-sync/http.ts";
import { waitForSlackRateLimit } from "../org-sync/slack-rate-limit.ts";
import type { WorkspaceLedgerHistoryIndex } from "../workspace-directory/d1-workspace-ledger-history-index.ts";
import {
  workspaceChangeLedgerChannelId,
  workspaceChangeLedgerChannelName,
  type WorkspaceDirectoryLedgerMessage,
} from "./change-ledger-contracts.ts";

const SLACK_API = "https://slack.com/api";
const MAX_HISTORY_PAGES = 20;
const MAX_MESSAGES_PER_PAGE = 200;
const MAX_SLACK_RATE_LIMIT_ATTEMPTS = 4;
const SLACK_RATE_LIMIT_RETRY_BUDGET_MS = 60_000;
const HANDLE_CHANNEL_MISMATCH =
  "workspace_directory_ledger_handle_channel_mismatch";
const REPAIR_SOURCE_MISMATCH =
  "workspace_directory_ledger_repair_source_mismatch";
const READBACK_MISSING = "workspace_directory_ledger_readback_missing";
const JsonObjectSchema = z.record(z.string(), z.unknown());
const JsonStringSchema = z.string();

const LedgerStateSchema = z.enum(["announced", "completed", "failed"]);
type LedgerState = z.output<typeof LedgerStateSchema>;
const TerminalStateSchema = LedgerStateSchema.exclude(["announced"]);
type TerminalState = z.output<typeof TerminalStateSchema>;
export type WorkspaceDirectoryLedgerStage =
  | "destination"
  | "digest"
  | "history"
  | "message"
  | "readback"
  | "write";

export class WorkspaceDirectoryLedgerStageError extends Error {
  readonly diagnosticStage: string;
  readonly stage: WorkspaceDirectoryLedgerStage;

  constructor(stage: WorkspaceDirectoryLedgerStage, options?: ErrorOptions) {
    super(
      options?.cause instanceof Error
        ? options.cause.message
        : `Workspace Directory ledger failed at ${stage}.`,
      options,
    );
    this.name = "WorkspaceDirectoryLedgerStageError";
    this.diagnosticStage =
      stage === "readback" &&
      options?.cause instanceof WorkspaceDirectoryLedgerReadbackError
        ? `${stage}-${options.cause.reason}`
        : stage;
    this.stage = stage;
  }
}

type WorkspaceDirectoryLedgerReadbackReason =
  | "block-shape"
  | "block-value-block-id"
  | "block-value-mrkdwn-text"
  | "block-value-mrkdwn-type"
  | "block-value-mrkdwn-verbatim"
  | "block-value-other"
  | "block-value-plain-text"
  | "block-value-table-cell"
  | "block-value-table-setting"
  | "bot"
  | "metadata"
  | "text";

class WorkspaceDirectoryLedgerReadbackError extends Error {
  readonly reason: WorkspaceDirectoryLedgerReadbackReason;

  constructor(
    reason: WorkspaceDirectoryLedgerReadbackReason,
    options?: ErrorOptions,
  ) {
    super("workspace_directory_ledger_readback_mismatch", options);
    this.name = "WorkspaceDirectoryLedgerReadbackError";
    this.reason = reason;
  }
}

const MetadataSchema = z.strictObject({
  "event_payload": z.strictObject({
    announcementDigest: z.string().regex(/^[a-f0-9]{64}$/u),
    changeKey: z.string().min(1).max(200),
    state: LedgerStateSchema,
    version: z.literal(1),
  }),
  "event_type": z.literal("sarj_workspace_directory_change"),
});

const AuthSchema = z.object({
  "bot_id": z.string().min(1),
  ok: z.literal(true),
  "team_id": z.string().min(1),
});

const ChannelInfoSchema = z.object({
  channel: z.object({
    id: z.string().min(1),
    "is_archived": z.literal(false),
    "is_ext_shared": z.literal(false),
    "is_member": z.literal(true),
    "is_pending_ext_shared": z.boolean().optional(),
    "is_private": z.literal(true),
    name: z.string().min(1),
  }),
  ok: z.literal(true),
});

const MessageSchema = z.object({
  blocks: z.array(z.unknown()).optional(),
  "bot_id": z.string().optional(),
  metadata: z.unknown().optional(),
  text: z.string().optional(),
  ts: z.string().min(1),
});

const SlackSynthesizedRichTextBlocksSchema = z.tuple([
  z.strictObject({
    "block_id": z.string().min(1).optional(),
    elements: z.tuple([
      z.strictObject({
        elements: z.array(
          z.union([
            z.strictObject({ text: z.string(), type: z.literal("text") }),
            z.strictObject({
              text: z.string(),
              type: z.literal("link"),
              url: z.string(),
            }),
          ]),
        ),
        type: z.literal("rich_text_section"),
      }),
    ]),
    type: z.literal("rich_text"),
  }),
]);

const HistorySchema = z.object({
  messages: z.array(MessageSchema).max(MAX_MESSAGES_PER_PAGE),
  ok: z.literal(true),
  "response_metadata": z
    .object({ "next_cursor": z.string().optional() })
    .optional(),
});

const IndexedHistoryPageSchema = HistorySchema.extend({
  "has_more": z.boolean(),
});
const WriteSchema = z.object({ ok: z.literal(true), ts: z.string().min(1) });
const SlackErrorSchema = z.object({
  error: z.string().optional(),
  ok: z.literal(false),
});
const SlackTimestampSchema = z.string().regex(/^\d+\.\d{6}$/u);

export const WorkspaceDirectoryTerminalReceiptSchema = z.strictObject({
  channelId: z
    .string()
    .refine((value) => value === workspaceChangeLedgerChannelId()),
  contentHash: z.string().regex(/^[a-f0-9]{64}$/u),
  timestamp: SlackTimestampSchema,
  verifiedAtMs: z.number().int().nonnegative(),
});
export type WorkspaceDirectoryTerminalReceipt = z.output<
  typeof WorkspaceDirectoryTerminalReceiptSchema
>;

export interface WorkspaceDirectoryChangeLedgerOptions {
  botToken: string;
  channelId: string;
  expectedChannelName: string;
  expectedTeamId: string;
  fetchImpl?: typeof fetch;
  historyIndex?: WorkspaceLedgerHistoryIndex;
  sleep?: Sleep;
}

export interface WorkspaceDirectoryChangeAnnouncement extends WorkspaceDirectoryLedgerMessage {
  /** Stable across retries and unique to the reviewed provider change. */
  changeKey: string;
  /**
   * Optional lower Slack timestamp bound for short-lived summary receipts.
   * Permanent per-change ledgers deliberately omit this and retain the full,
   * fail-closed history scan.
   */
  historyOldest?: string;
  retryFailed?: boolean;
}

export interface WorkspaceDirectoryChangeLedgerHandle {
  announcementDigest: string;
  changeKey: string;
  channelId: string;
  state: LedgerState;
  timestamp: string;
}

export interface IWorkspaceDirectoryChangeLedger {
  complete(
    handle: WorkspaceDirectoryChangeLedgerHandle,
    message: WorkspaceDirectoryLedgerMessage,
  ): Promise<void>;
  fail(
    handle: WorkspaceDirectoryChangeLedgerHandle,
    message: WorkspaceDirectoryLedgerMessage,
  ): Promise<void>;
  preannounce(
    input: WorkspaceDirectoryChangeAnnouncement,
  ): Promise<WorkspaceDirectoryChangeLedgerHandle>;
  recover?(
    input: WorkspaceDirectoryChangeAnnouncement,
  ): Promise<null | WorkspaceDirectoryChangeLedgerHandle>;
  repairCompleted?(
    handle: WorkspaceDirectoryChangeLedgerHandle,
    announcement: WorkspaceDirectoryLedgerMessage,
    completed: WorkspaceDirectoryLedgerMessage,
  ): Promise<WorkspaceDirectoryTerminalReceipt>;
  repairFailed?(
    handle: WorkspaceDirectoryChangeLedgerHandle,
    announcement: WorkspaceDirectoryLedgerMessage,
    failed: WorkspaceDirectoryLedgerMessage,
  ): Promise<WorkspaceDirectoryTerminalReceipt>;
  synchronizeHistory?(): Promise<boolean>;
  verifyTerminal?(
    handle: WorkspaceDirectoryChangeLedgerHandle,
    state: TerminalState,
    message: WorkspaceDirectoryLedgerMessage,
  ): Promise<WorkspaceDirectoryTerminalReceipt>;
}

/**
 * Fail-closed Slack ledger for Workspace Directory mutations.
 *
 * A provider mutation must not begin until `preannounce` resolves. Completion
 * and failure update the verified announcement in place, keeping one durable
 * audit entry per stable change key.
 */
export class WorkspaceDirectoryChangeLedger implements IWorkspaceDirectoryChangeLedger {
  #durableHistoryReady = false;
  #historyIndex: null | Promise<Map<string, z.output<typeof MessageSchema>>> =
    null;
  readonly #options: WorkspaceDirectoryChangeLedgerOptions;
  #validatedBotId: null | Promise<string> = null;

  constructor(options: WorkspaceDirectoryChangeLedgerOptions) {
    if (options.channelId !== workspaceChangeLedgerChannelId())
      throw new Error("workspace_directory_ledger_unexpected_channel_config");
    if (options.expectedChannelName !== workspaceChangeLedgerChannelName())
      throw new Error(
        "workspace_directory_ledger_unexpected_channel_name_config",
      );
    if (!options.expectedTeamId.trim())
      throw new Error("workspace_directory_ledger_missing_expected_team");
    if (!options.botToken.trim())
      throw new Error("workspace_directory_ledger_missing_bot_token");
    this.#options = options;
  }

  async synchronizeHistory(): Promise<boolean> {
    const index = this.#options.historyIndex;
    if (index === undefined || this.#durableHistoryReady) return true;
    const botId = await this.#validateDestination();
    const complete = await index.synchronize(
      this.#historyScope(botId),
      async (bounds) => {
        const query = new URLSearchParams({
          channel: this.#options.channelId,
          "include_all_metadata": "true",
          limit: String(MAX_MESSAGES_PER_PAGE),
          ...(bounds.latest !== null && { latest: bounds.latest }),
          ...(bounds.oldest !== null && { oldest: bounds.oldest }),
        });
        const result = IndexedHistoryPageSchema.parse(
          await this.#get(`conversations.history?${query.toString()}`),
        );
        const messages = new Map<string, z.output<typeof MessageSchema>>();
        indexLedgerMessages(messages, result.messages, botId);
        return {
          timestamps: result.messages.map((message) => message.ts),
          entries: [...messages].map(([changeKey, message]) => ({
            changeKey,
            timestamp: message.ts,
          })),
          hasMore:
            result["has_more"] ||
            Boolean(result["response_metadata"]?.["next_cursor"]?.trim()),
        };
      },
    );
    this.#durableHistoryReady = complete;
    return complete;
  }

  async preannounce(
    input: WorkspaceDirectoryChangeAnnouncement,
  ): Promise<WorkspaceDirectoryChangeLedgerHandle> {
    const message = captureLedgerStage(() => normalizeMessage(input));
    const botId = await captureLedgerStageAsync("destination", () =>
      this.#validateDestination(),
    );
    async function createDigest() {
      return messageDigest(message);
    }
    function createMetadata() {
      return ledgerMetadata(input.changeKey, announcementDigest, "announced");
    }
    const announcementDigest = await captureLedgerStageAsync(
      "digest",
      createDigest,
    );
    const metadata = captureLedgerStage(createMetadata);
    const recoverAnnouncement = this.#recoverValidated.bind(
      this,
      input,
      message,
      botId,
      announcementDigest,
    );
    const recovered = await captureLedgerStageAsync(
      "history",
      recoverAnnouncement,
    );
    if (recovered !== null) {
      const recoveredState = recovered.state;
      if (recoveredState === "completed") {
        return recovered;
      }
      if (recoveredState === "failed") {
        if (input.retryFailed === false)
          throw new Error(
            "workspace_directory_ledger_failed_announcement_not_retryable",
          );
        await this.#writeUpdate(recovered.timestamp, metadata, message);
        await this.#verifyExact(recovered.timestamp, botId, metadata, message);
        return this.#handle(
          input.changeKey,
          announcementDigest,
          recovered.timestamp,
          "announced",
        );
      }
      return recovered;
    }

    const postAnnouncement = this.#post.bind(this, "chat.postMessage", {
      ...(message.blocks && { blocks: message.blocks }),
      channel: this.#options.channelId,
      "client_msg_id": await stableClientMessageId(input.changeKey),
      metadata,
      mrkdwn: false,
      text: message.text,
      "unfurl_links": false,
    });
    async function writeAnnouncement() {
      return WriteSchema.parse(await postAnnouncement());
    }
    const written = await captureLedgerStageAsync("write", writeAnnouncement);
    const verifyAnnouncement = this.#verifyNewAnnouncement.bind(
      this,
      written.ts,
      botId,
      metadata,
      message,
    );
    await captureLedgerStageAsync("readback", verifyAnnouncement);
    return this.#handle(
      input.changeKey,
      announcementDigest,
      written.ts,
      "announced",
    );
  }

  async recover(
    input: WorkspaceDirectoryChangeAnnouncement,
  ): Promise<null | WorkspaceDirectoryChangeLedgerHandle> {
    const message = normalizeMessage(input);
    const botId = await this.#validateDestination();
    const announcementDigest = await messageDigest(message);
    return this.#recoverValidated(input, message, botId, announcementDigest);
  }

  async complete(
    handle: WorkspaceDirectoryChangeLedgerHandle,
    message: WorkspaceDirectoryLedgerMessage,
  ): Promise<void> {
    await this.#updateAndVerify(handle, "completed", message);
  }

  async fail(
    handle: WorkspaceDirectoryChangeLedgerHandle,
    message: WorkspaceDirectoryLedgerMessage,
  ): Promise<void> {
    await this.#updateAndVerify(handle, "failed", message);
  }

  async verifyTerminal(
    handle: WorkspaceDirectoryChangeLedgerHandle,
    state: TerminalState,
    rawMessage: WorkspaceDirectoryLedgerMessage,
  ): Promise<WorkspaceDirectoryTerminalReceipt> {
    if (handle.channelId !== this.#options.channelId) {
      throw new Error(HANDLE_CHANNEL_MISMATCH);
    }
    const timestamp = SlackTimestampSchema.parse(handle.timestamp);
    const message = normalizeMessage(rawMessage);
    const metadata = ledgerMetadata(
      handle.changeKey,
      handle.announcementDigest,
      TerminalStateSchema.parse(state),
    );
    // Terminal attestations require fresh destination evidence, not the instance cache.
    const botId = await this.#loadValidatedBotId();
    await this.#verifyExact(timestamp, botId, metadata, message);
    return WorkspaceDirectoryTerminalReceiptSchema.parse({
      channelId: this.#options.channelId,
      contentHash: await messageDigest(message),
      timestamp,
      verifiedAtMs: Date.now(),
    });
  }

  async repairCompleted(
    handle: WorkspaceDirectoryChangeLedgerHandle,
    rawAnnouncement: WorkspaceDirectoryLedgerMessage,
    rawCompleted: WorkspaceDirectoryLedgerMessage,
  ): Promise<WorkspaceDirectoryTerminalReceipt> {
    return this.#repairTerminal(
      handle,
      rawAnnouncement,
      rawCompleted,
      "completed",
    );
  }

  async repairFailed(
    handle: WorkspaceDirectoryChangeLedgerHandle,
    announcement: WorkspaceDirectoryLedgerMessage,
    failed: WorkspaceDirectoryLedgerMessage,
  ): Promise<WorkspaceDirectoryTerminalReceipt> {
    return this.#repairTerminal(handle, announcement, failed, "failed");
  }

  async #repairTerminal(
    handle: WorkspaceDirectoryChangeLedgerHandle,
    rawAnnouncement: WorkspaceDirectoryLedgerMessage,
    rawCompleted: WorkspaceDirectoryLedgerMessage,
    state: TerminalState,
  ): Promise<WorkspaceDirectoryTerminalReceipt> {
    if (handle.channelId !== this.#options.channelId)
      throw new Error(HANDLE_CHANNEL_MISMATCH);
    const announcement = normalizeMessage(rawAnnouncement);
    const completed = normalizeMessage(rawCompleted);
    if (
      (handle.state !== "announced" && handle.state !== state) ||
      (await messageDigest(announcement)) !== handle.announcementDigest
    ) {
      throw new Error(REPAIR_SOURCE_MISMATCH);
    }
    const timestamp = SlackTimestampSchema.parse(handle.timestamp);
    const botId = await this.#loadValidatedBotId();
    const current = await this.#readTimestamp(timestamp);
    if (current === null) throw new Error(REPAIR_SOURCE_MISMATCH);
    const completedMetadata = ledgerMetadata(
      handle.changeKey,
      handle.announcementDigest,
      state,
    );
    if (!messageMatches(current, botId, completedMetadata, completed)) {
      const announcedMetadata = ledgerMetadata(
        handle.changeKey,
        handle.announcementDigest,
        "announced",
      );
      if (!messageMatches(current, botId, announcedMetadata, announcement)) {
        throw new Error(REPAIR_SOURCE_MISMATCH);
      }
      await this.#writeUpdate(timestamp, completedMetadata, completed);
    }
    return this.verifyTerminal(handle, state, completed);
  }

  async #recoverValidated(
    input: WorkspaceDirectoryChangeAnnouncement,
    message: WorkspaceDirectoryLedgerMessage,
    botId: string,
    announcementDigest: string,
  ): Promise<null | WorkspaceDirectoryChangeLedgerHandle> {
    const recovered = await this.#findByChangeKey(
      botId,
      input.changeKey,
      input.historyOldest,
    );
    if (recovered === null) return null;
    const recoveredMetadata = MetadataSchema.safeParse(recovered.metadata);
    if (
      !recoveredMetadata.success ||
      recoveredMetadata.data["event_payload"].announcementDigest !==
        announcementDigest
    ) {
      throw new Error("workspace_directory_ledger_change_key_conflict");
    }
    const recoveredState = recoveredMetadata.data["event_payload"].state;
    const expectedMetadata = ledgerMetadata(
      input.changeKey,
      announcementDigest,
      "announced",
    );
    if (
      recoveredState === "announced" &&
      messageMismatchReason(recovered, botId, expectedMetadata, message) !==
        null
    ) {
      throw new Error("workspace_directory_ledger_change_key_conflict");
    }
    return this.#handle(
      input.changeKey,
      announcementDigest,
      recovered.ts,
      recoveredState,
    );
  }

  async #updateAndVerify(
    handle: WorkspaceDirectoryChangeLedgerHandle,
    state: Exclude<LedgerState, "announced">,
    rawMessage: WorkspaceDirectoryLedgerMessage,
  ): Promise<void> {
    if (handle.channelId !== this.#options.channelId)
      throw new Error(HANDLE_CHANNEL_MISMATCH);
    const message = normalizeMessage(rawMessage);
    const botId = await this.#validateDestination();
    const metadata = ledgerMetadata(
      handle.changeKey,
      handle.announcementDigest,
      state,
    );
    const current = await this.#readTimestamp(handle.timestamp);
    if (current && messageMatches(current, botId, metadata, message)) return;
    if (!current)
      throw new Error("workspace_directory_ledger_announcement_missing");
    const currentMetadata = MetadataSchema.safeParse(current.metadata);
    if (
      current["bot_id"] !== botId ||
      !currentMetadata.success ||
      currentMetadata.data["event_payload"].changeKey !== handle.changeKey ||
      currentMetadata.data["event_payload"].announcementDigest !==
        handle.announcementDigest
    ) {
      throw new Error("workspace_directory_ledger_announcement_mismatch");
    }

    if (
      state === "failed" &&
      currentMetadata.data["event_payload"].state === "completed"
    )
      return;
    await this.#writeUpdate(handle.timestamp, metadata, message);
    await this.#verifyExact(handle.timestamp, botId, metadata, message);
  }

  async #writeUpdate(
    timestamp: string,
    metadata: z.output<typeof MetadataSchema>,
    message: WorkspaceDirectoryLedgerMessage,
  ): Promise<void> {
    const written = WriteSchema.parse(
      await this.#post("chat.update", {
        blocks: message.blocks ?? [],
        channel: this.#options.channelId,
        metadata,
        mrkdwn: false,
        text: message.text,
        ts: timestamp,
      }),
    );
    if (written.ts !== timestamp)
      throw new Error("workspace_directory_ledger_update_timestamp_mismatch");
  }

  async #validateDestination(): Promise<string> {
    this.#validatedBotId ??= this.#loadValidatedBotId();
    return this.#validatedBotId;
  }

  async #loadValidatedBotId(): Promise<string> {
    const auth = AuthSchema.parse(await this.#get("auth.test"));
    if (auth["team_id"] !== this.#options.expectedTeamId)
      throw new Error("workspace_directory_ledger_unexpected_team");
    const query = new URLSearchParams({ channel: this.#options.channelId });
    const result = ChannelInfoSchema.parse(
      await this.#get(`conversations.info?${query.toString()}`),
    );
    if (
      result.channel.id !== this.#options.channelId ||
      result.channel.name !== this.#options.expectedChannelName ||
      result.channel["is_pending_ext_shared"] === true
    ) {
      throw new Error("workspace_directory_ledger_unsafe_destination");
    }
    return auth["bot_id"];
  }

  async #findByChangeKey(
    botId: string,
    changeKey: string,
    historyOldest?: string,
  ) {
    const parsedOldest =
      historyOldest === undefined
        ? undefined
        : SlackTimestampSchema.parse(historyOldest);
    if (parsedOldest) {
      const scopedHistoryIndex = await this.#loadHistoryIndex(
        botId,
        parsedOldest,
      );
      return scopedHistoryIndex.get(changeKey) ?? null;
    }
    if (this.#options.historyIndex !== undefined) {
      if (!(await this.synchronizeHistory()))
        throw new Error("workspace_directory_ledger_history_index_incomplete");
      let timestamp: null | string;
      try {
        timestamp = await this.#options.historyIndex.findTimestamp(
          this.#historyScope(botId),
          changeKey,
        );
      } catch (error) {
        this.#durableHistoryReady = false;
        throw error;
      }
      if (timestamp === null) return null;
      const current = await this.#readTimestamp(timestamp);
      const metadata = MetadataSchema.safeParse(current?.metadata);
      if (
        current?.["bot_id"] !== botId ||
        !metadata.success ||
        metadata.data["event_payload"].changeKey !== changeKey
      )
        throw new Error(
          "workspace_directory_ledger_history_index_message_mismatch",
        );
      return current;
    }
    this.#historyIndex ??= this.#loadHistoryIndex(botId);
    const historyIndex = await this.#historyIndex;
    return historyIndex.get(changeKey) ?? null;
  }

  #historyScope(botId: string) {
    return {
      botId,
      channelId: this.#options.channelId,
      teamId: this.#options.expectedTeamId,
    };
  }

  async #rememberMessage(
    botId: string,
    metadata: z.output<typeof MetadataSchema>,
    observed: z.output<typeof MessageSchema>,
  ): Promise<void> {
    if (this.#historyIndex !== null) {
      const historyIndex = await this.#historyIndex;
      historyIndex.set(metadata["event_payload"].changeKey, observed);
    }
    if (this.#durableHistoryReady && this.#options.historyIndex !== undefined) {
      await this.#options.historyIndex.record(this.#historyScope(botId), {
        changeKey: metadata["event_payload"].changeKey,
        timestamp: observed.ts,
      });
    }
  }

  async #loadHistoryIndex(
    botId: string,
    historyOldest?: string,
  ): Promise<Map<string, z.output<typeof MessageSchema>>> {
    const messagesByChangeKey = new Map<
      string,
      z.output<typeof MessageSchema>
    >();
    let cursor = "";
    const seenCursors = new Set<string>();
    for (let page = 0; page < MAX_HISTORY_PAGES; page += 1) {
      if (seenCursors.has(cursor))
        throw new Error("workspace_directory_ledger_cursor_cycle");
      seenCursors.add(cursor);
      const query = new URLSearchParams({
        channel: this.#options.channelId,
        "include_all_metadata": "true",
        limit: String(MAX_MESSAGES_PER_PAGE),
        ...(historyOldest && { inclusive: "true", oldest: historyOldest }),
      });
      if (cursor) query.set("cursor", cursor);
      const pageResult = HistorySchema.parse(
        // eslint-disable-next-line no-await-in-loop -- Slack cursor pages are provider-ordered and bounded.
        await this.#get(`conversations.history?${query.toString()}`),
      );
      indexLedgerMessages(messagesByChangeKey, pageResult.messages, botId);
      cursor = pageResult["response_metadata"]?.["next_cursor"]?.trim() ?? "";
      if (!cursor) return messagesByChangeKey;
    }
    throw new Error("workspace_directory_ledger_history_page_limit");
  }

  async #readTimestamp(timestamp: string) {
    const query = new URLSearchParams({
      channel: this.#options.channelId,
      "include_all_metadata": "true",
      inclusive: "true",
      latest: timestamp,
      limit: "1",
      oldest: timestamp,
    });
    const result = HistorySchema.parse(
      await this.#get(`conversations.history?${query.toString()}`),
    );
    return result.messages.find(({ ts }) => ts === timestamp) ?? null;
  }

  async #verifyExact(
    timestamp: string,
    botId: string,
    metadata: z.output<typeof MetadataSchema>,
    message: WorkspaceDirectoryLedgerMessage,
  ): Promise<void> {
    const observed = await this.#readTimestamp(timestamp);
    if (!observed) throw new Error(READBACK_MISSING);
    // Slack owns and may regenerate the top-level accessibility fallback for
    // Block Kit messages after both create and update. Exact blocks, metadata,
    // bot provenance, and timestamp remain authoritative for terminal receipts.
    const mismatch = messageMismatchReason(observed, botId, metadata, message);
    if (mismatch !== null)
      throw new WorkspaceDirectoryLedgerReadbackError(mismatch);
    await this.#rememberMessage(botId, metadata, observed);
  }

  async #verifyNewAnnouncement(
    timestamp: string,
    botId: string,
    metadata: z.output<typeof MetadataSchema>,
    message: WorkspaceDirectoryLedgerMessage,
  ): Promise<void> {
    const observed = await this.#readTimestamp(timestamp);
    if (observed === null) throw new Error(READBACK_MISSING);
    const mismatch = messageMismatchReason(observed, botId, metadata, message);
    if (mismatch === null) {
      await this.#rememberMessage(botId, metadata, observed);
      return;
    }
    if (
      mismatch === "text" &&
      observed["bot_id"] === botId &&
      metadataMatches(observed.metadata, metadata) &&
      blocksMatch(observed.blocks, message)
    ) {
      // Slack can replace the top-level accessibility fallback while accepting
      // an otherwise exact Block Kit post. Repair only that freshly-created,
      // provenance-pinned message, then require a second independent exact
      // readback before allowing any provider mutation to proceed.
      await this.#writeUpdate(timestamp, metadata, message);
      await this.#verifyExact(timestamp, botId, metadata, message);
      return;
    }
    throw new WorkspaceDirectoryLedgerReadbackError(mismatch);
  }

  #handle(
    changeKey: string,
    announcementDigest: string,
    timestamp: string,
    state: LedgerState,
  ): WorkspaceDirectoryChangeLedgerHandle {
    return {
      announcementDigest,
      changeKey,
      channelId: workspaceChangeLedgerChannelId(),
      state,
      timestamp,
    };
  }

  async #get(path: string): Promise<unknown> {
    return this.#request(path, { headers: this.#headers() });
  }

  async #post(path: string, body: Record<string, unknown>): Promise<unknown> {
    return this.#request(path, {
      body: JSON.stringify(body),
      headers: this.#headers(true),
      method: "POST",
    });
  }

  async #request(path: string, init: RequestInit): Promise<unknown> {
    const deadlineAt = Date.now() + SLACK_RATE_LIMIT_RETRY_BUDGET_MS;
    for (let attempt = 1; attempt <= MAX_SLACK_RATE_LIMIT_ATTEMPTS; attempt++) {
      // eslint-disable-next-line no-await-in-loop -- Slack's Retry-After must elapse before retrying a rejected request.
      const response = await (this.#options.fetchImpl ?? runtimeFetch)(
        `${SLACK_API}/${path}`,
        {
          ...init,
          redirect: "manual",
        },
      );
      if (response.status === 429 && attempt < MAX_SLACK_RATE_LIMIT_ATTEMPTS) {
        // eslint-disable-next-line no-await-in-loop -- The rejected response body must be released before retrying.
        await response.body?.cancel();
        // eslint-disable-next-line no-await-in-loop -- A 429 is a definitive rejection and is safe to retry after Slack's delay.
        await waitForSlackRateLimit({
          deadlineAt,
          label: "Workspace Directory Slack ledger",
          response,
          sleep: this.#options.sleep ?? defaultSleep,
        });
        continue;
      }
      if (!response.ok) {
        // eslint-disable-next-line no-await-in-loop -- Every rejected response body is released before failing closed.
        await response.body?.cancel();
        throw new Error(
          `workspace_directory_ledger_slack_http_${String(response.status)}`,
        );
      }
      // eslint-disable-next-line no-await-in-loop -- Only the accepted response from the current attempt is decoded.
      const body: unknown = await response.json();
      const slackError = SlackErrorSchema.safeParse(body);
      if (slackError.success)
        throw new Error(
          `workspace_directory_ledger_slack_${slackError.data.error ?? "unknown_error"}`,
        );
      return body;
    }
    throw new Error("workspace_directory_ledger_slack_rate_limit_exhausted");
  }

  #headers(json = false): HeadersInit {
    return {
      authorization: `Bearer ${this.#options.botToken}`,
      ...(json && { "content-type": "application/json; charset=utf-8" }),
    };
  }
}

function captureLedgerStage<Result>(run: () => Result): Result {
  try {
    return run();
  } catch (error) {
    if (error instanceof WorkspaceDirectoryLedgerStageError) throw error;
    throw new WorkspaceDirectoryLedgerStageError("message", { cause: error });
  }
}

async function captureLedgerStageAsync<Result>(
  stage: WorkspaceDirectoryLedgerStage,
  run: () => Promise<Result>,
): Promise<Result> {
  try {
    return await run();
  } catch (error) {
    if (error instanceof WorkspaceDirectoryLedgerStageError) throw error;
    throw new WorkspaceDirectoryLedgerStageError(stage, { cause: error });
  }
}

function indexLedgerMessages(
  messagesByChangeKey: Map<string, z.output<typeof MessageSchema>>,
  messages: readonly z.output<typeof MessageSchema>[],
  botId: string,
): void {
  for (const candidate of messages) {
    if (candidate["bot_id"] !== botId) continue;
    const parsed = MetadataSchema.safeParse(candidate.metadata);
    if (!parsed.success) continue;
    const changeKey = parsed.data["event_payload"].changeKey;
    if (messagesByChangeKey.has(changeKey)) {
      throw new Error("workspace_directory_ledger_duplicate_change_key");
    }
    messagesByChangeKey.set(changeKey, candidate);
  }
}

function normalizeMessage(
  message: WorkspaceDirectoryLedgerMessage,
): WorkspaceDirectoryLedgerMessage {
  const text = message.text.trim();
  if (!text) throw new Error("workspace_directory_ledger_empty_message");
  return { ...(message.blocks && { blocks: [...message.blocks] }), text };
}

function ledgerMetadata(
  changeKey: string,
  announcementDigest: string,
  state: LedgerState,
): z.output<typeof MetadataSchema> {
  return MetadataSchema.parse({
    "event_payload": { announcementDigest, changeKey, state, version: 1 },
    "event_type": "sarj_workspace_directory_change",
  });
}

async function messageDigest(
  message: WorkspaceDirectoryLedgerMessage,
): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(
      JSON.stringify({ blocks: message.blocks ?? [], text: message.text }),
    ),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function messageMatches(
  observed: z.output<typeof MessageSchema>,
  botId: string,
  metadata: z.output<typeof MetadataSchema>,
  message: WorkspaceDirectoryLedgerMessage,
): boolean {
  return messageMismatchReason(observed, botId, metadata, message) === null;
}

function messageMismatchReason(
  observed: z.output<typeof MessageSchema>,
  botId: string,
  metadata: z.output<typeof MetadataSchema>,
  message: WorkspaceDirectoryLedgerMessage,
): null | WorkspaceDirectoryLedgerReadbackReason {
  if (observed["bot_id"] !== botId) return "bot";
  if (!metadataMatches(observed.metadata, metadata)) return "metadata";
  const exactBlocks = blocksMatch(observed.blocks, message);
  if (!exactBlocks) {
    if (!sameJsonShape(message.blocks ?? [], observed.blocks ?? []))
      return "block-shape";
    return blockValueMismatchReason(
      message.blocks ?? [],
      observed.blocks ?? [],
    );
  }
  if (
    observed.text === undefined ||
    canonicalSlackText(observed.text) !== canonicalSlackText(message.text)
  ) {
    // For Block Kit messages Slack owns the top-level accessibility fallback and
    // may regenerate it after both chat.postMessage and chat.update. The signed
    // digest remains bound to our expected fallback and exact blocks; require bot
    // provenance, exact metadata, and exact visible blocks above, while treating
    // the provider-generated fallback as non-authoritative presentation data.
    return message.blocks !== undefined ? null : "text";
  }
  return null;
}

function metadataMatches(
  observedMetadata: unknown,
  expectedMetadata: z.output<typeof MetadataSchema>,
): boolean {
  const observed = MetadataSchema.safeParse(observedMetadata);
  if (!observed.success) return false;
  return (
    observed.data["event_payload"].announcementDigest ===
      expectedMetadata["event_payload"].announcementDigest &&
    observed.data["event_payload"].changeKey ===
      expectedMetadata["event_payload"].changeKey &&
    observed.data["event_payload"].state ===
      expectedMetadata["event_payload"].state
  );
}

function blocksMatch(
  observedBlocks: readonly unknown[] | undefined,
  message: WorkspaceDirectoryLedgerMessage,
): boolean {
  if (message.blocks !== undefined) {
    return jsonValuesEqual(message.blocks, observedBlocks ?? []);
  }
  if (observedBlocks === undefined || observedBlocks.length === 0) return true;
  const parsed = SlackSynthesizedRichTextBlocksSchema.safeParse(observedBlocks);
  if (!parsed.success) return false;
  const renderedParts: string[] = [];
  for (const element of parsed.data[0].elements[0].elements) {
    if (
      element.type === "link" &&
      (element.url !== `mailto:${element.text}` ||
        !EMAIL_ADDRESS_PATTERN.test(element.text))
    ) {
      return false;
    }
    renderedParts.push(element.text);
  }
  return renderedParts.join("") === canonicalSlackText(message.text);
}

/*
 * Slack parses submitted Block Kit and can reorder JSON object properties in the returned
 * message. Keep the content attestation exact while treating object property order as irrelevant.
 */
function jsonValuesEqual(expected: unknown, observed: unknown): boolean {
  if (Array.isArray(expected)) {
    if (!Array.isArray(observed) || observed.length !== expected.length)
      return false;
    return expected.every((value, index) =>
      jsonValuesEqual(value, observed[index]),
    );
  }
  const expectedObject = JsonObjectSchema.safeParse(expected);
  if (expectedObject.success) {
    const observedObject = JsonObjectSchema.safeParse(observed);
    if (!observedObject.success) return false;
    return jsonObjectsEqual(expectedObject.data, observedObject.data);
  }
  return Object.is(expected, observed);
}

function jsonObjectsEqual(expected: object, observed: object): boolean {
  const expectedEntries = Object.entries(expected);
  const observedEntries = new Map(Object.entries(observed));
  const canonicalMrkdwn =
    Reflect.get(expected, "type") === "mrkdwn" &&
    Reflect.get(observed, "type") === "mrkdwn";
  if (
    canonicalMrkdwn &&
    !expectedEntries.some(([key]) => key === "verbatim") &&
    z.unknown().parse(observedEntries.get("verbatim")) === false
  ) {
    observedEntries.delete("verbatim");
  }
  if (observedEntries.size !== expectedEntries.length) return false;
  for (const [key, rawValue] of expectedEntries) {
    if (!observedEntries.has(key)) return false;
    const value = z.unknown().parse(rawValue);
    const observedValue = z.unknown().parse(observedEntries.get(key));
    const textValue = JsonStringSchema.safeParse(value);
    const observedText = JsonStringSchema.safeParse(observedValue);
    if (
      key === "text" &&
      canonicalMrkdwn &&
      textValue.success &&
      observedText.success
    ) {
      if (
        canonicalSlackText(textValue.data) !==
        canonicalSlackText(observedText.data)
      )
        return false;
    } else if (!jsonValuesEqual(value, observedValue)) return false;
  }
  return true;
}

function sameJsonShape(expected: unknown, observed: unknown): boolean {
  if (Array.isArray(expected)) {
    return (
      Array.isArray(observed) &&
      expected.length === observed.length &&
      expected.every((value, index) => sameJsonShape(value, observed[index]))
    );
  }
  const expectedObject = JsonObjectSchema.safeParse(expected);
  if (!expectedObject.success)
    return (
      Object.prototype.toString.call(expected) ===
      Object.prototype.toString.call(observed)
    );
  const observedObject = JsonObjectSchema.safeParse(observed);
  if (!observedObject.success) return false;
  const expectedKeys = Object.keys(expectedObject.data);
  const observedKeys = Object.keys(observedObject.data).filter(
    (key) =>
      !(
        key === "verbatim" &&
        Reflect.get(expectedObject.data, "type") === "mrkdwn" &&
        Reflect.get(observedObject.data, "type") === "mrkdwn" &&
        Reflect.get(observedObject.data, key) === false
      ),
  );
  return (
    expectedKeys.length === observedKeys.length &&
    expectedKeys.every(
      (key) =>
        observedKeys.includes(key) &&
        sameJsonShape(
          Reflect.get(expectedObject.data, key),
          Reflect.get(observedObject.data, key),
        ),
    )
  );
}

function blockValueMismatchReason(
  expected: unknown,
  observed: unknown,
): WorkspaceDirectoryLedgerReadbackReason {
  if (Array.isArray(expected) && Array.isArray(observed))
    return arrayValueMismatchReason(expected, observed);
  const expectedObject = JsonObjectSchema.safeParse(expected);
  if (expectedObject.success)
    return objectValueMismatchReason(expectedObject.data, observed);
  return "block-value-other";
}

function arrayValueMismatchReason(
  expected: readonly unknown[],
  observed: readonly unknown[],
): WorkspaceDirectoryLedgerReadbackReason {
  for (const [index, value] of expected.entries()) {
    if (!jsonValuesEqual(value, observed[index])) {
      return blockValueMismatchReason(value, observed[index]);
    }
  }
  return "block-value-other";
}

function objectValueMismatchReason(
  expected: object,
  observed: unknown,
): WorkspaceDirectoryLedgerReadbackReason {
  const parsedObserved = JsonObjectSchema.safeParse(observed);
  const observedObject = parsedObserved.success ? parsedObserved.data : {};
  const expectedType: unknown = z
    .unknown()
    .parse(Reflect.get(expected, "type"));
  for (const [key, value] of Object.entries(expected)) {
    const observedValue: unknown = z
      .unknown()
      .parse(Reflect.get(observedObject, key));
    if (jsonValuesEqual(value, observedValue)) continue;
    const classified = classifiedObjectValueMismatch(expectedType, key);
    return classified ?? blockValueMismatchReason(value, observedValue);
  }
  return "block-value-other";
}

function classifiedObjectValueMismatch(
  expectedType: unknown,
  key: string,
): null | WorkspaceDirectoryLedgerReadbackReason {
  if (key === "block_id") return "block-value-block-id";
  if (expectedType === "raw_text") return "block-value-table-cell";
  if (expectedType === "plain_text") return "block-value-plain-text";
  if (expectedType === "mrkdwn") {
    if (key === "text") return "block-value-mrkdwn-text";
    if (key === "type") return "block-value-mrkdwn-type";
    if (key === "verbatim") return "block-value-mrkdwn-verbatim";
  }
  if (key === "align" || key === "is_wrapped")
    return "block-value-table-setting";
  return null;
}

const SLACK_MAILTO_LINK_PATTERN = /<mailto:([^<>|]+)\|([^<>]+)>/gu;
const EMAIL_ADDRESS_PATTERN = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/u;

function canonicalSlackText(text: string): string {
  return text.replaceAll(
    SLACK_MAILTO_LINK_PATTERN,
    (link, address: string, label: string) =>
      address === label && EMAIL_ADDRESS_PATTERN.test(address) ? address : link,
  );
}

async function stableClientMessageId(changeKey: string): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(`workspace-directory-change:${changeKey}`),
    ),
  );
  digest[6] = ((digest[6] ?? 0) & 0x0f) | 0x50;
  digest[8] = ((digest[8] ?? 0) & 0x3f) | 0x80;
  const hex = Array.from(digest.slice(0, 16), (byte) =>
    byte.toString(16).padStart(2, "0"),
  );
  return `${hex.slice(0, 4).join("")}-${hex.slice(4, 6).join("")}-${hex.slice(6, 8).join("")}-${hex.slice(8, 10).join("")}-${hex.slice(10).join("")}`;
}
