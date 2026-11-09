import { z } from "zod";

import { runtimeFetch } from "../clients/runtime-fetch.ts";
import { fetchPort } from "../runtime/fetch-port.ts";
import { escapeSlackMrkdwn as escapeMrkdwn } from "../shared/escape-slack-mrkdwn.ts";
import type { WorkspaceLedgerHistoryIndex } from "../workspace-directory/d1-workspace-ledger-history-index.ts";
import { AccessGuardSlackMetadataSchema } from "./issue-set.ts";
import type { AccessIssue, DownstreamAccount } from "./model.ts";
import type { EmailAccessAuditProvider } from "./provider.ts";
import type {
  AccessGuardSlackAnchorStore,
  SlackAnchorLookup,
} from "./read-access-guard-anchor.ts";

const SLACK_API = "https://slack.com/api";
const MAX_HISTORY_PAGES = 20;
const ANCHOR_EVENT_TYPE = "sarj_access_guard_state";
const DELIVERY_EVENT_TYPE = "sarj_access_guard_delivery";
const ANCHOR_TEXT =
  "IT access guard ledger — critical findings are posted in this thread.";
const ANCHOR_CLIENT_MESSAGE_ID = "6f72672d-6775-4172-a42d-616e63686f72";
const SLACKBOT_USER_ID = "USLACKBOT";

const SlackErrorSchema = z.object({
  error: z.string().optional(),
  ok: z.literal(false),
});
const AuthSchema = z.object({
  "bot_id": z.string().min(1),
  ok: z.literal(true),
  "team_id": z.string().min(1),
});
const UserAuthSchema = z.object({
  ok: z.literal(true),
  "team_id": z.string().min(1),
});
const ChannelInfoSchema = z.object({
  channel: z.object({
    id: z.string().min(1),
    "is_archived": z.literal(false),
    "is_ext_shared": z.literal(false),
    "is_member": z.literal(true),
    "is_private": z.literal(true),
  }),
  ok: z.literal(true),
});
const MetadataSchema = z.object({
  "event_payload": z.unknown(),
  "event_type": z.string(),
});
const HistorySchema = z.object({
  messages: z.array(
    z.object({
      "bot_id": z.string().optional(),
      metadata: MetadataSchema.optional(),
      ts: z.string().min(1),
    }),
  ),
  ok: z.literal(true),
  "response_metadata": z
    .object({ "next_cursor": z.string().optional() })
    .optional(),
});
const IndexedHistorySchema = HistorySchema.extend({ "has_more": z.boolean() });
const WriteSchema = z.object({
  ok: z.literal(true),
  ts: z.string().min(1).optional(),
});
const MembersSchema = z.object({
  members: z.array(
    z.object({
      deleted: z.boolean().optional(),
      id: z.string().min(1),
      "is_app_user": z.boolean().optional(),
      "is_bot": z.boolean().optional(),
      profile: z.object({
        email: z.string().optional(),
        "real_name": z.string().optional(),
      }),
    }),
  ),
  ok: z.literal(true),
  "response_metadata": z
    .object({ "next_cursor": z.string().optional() })
    .optional(),
});

export interface AccessGuardIssuePostingPort {
  postNewIssues(
    issues: readonly AccessIssue[],
    runId: string,
    occurrence: string,
  ): Promise<void>;
}

export class SlackAccessClient
  implements
    AccessGuardSlackAnchorStore,
    EmailAccessAuditProvider,
    AccessGuardIssuePostingPort
{
  readonly name = "slack";
  #anchorTs: null | string = null;
  #botId: null | string = null;
  readonly #botToken: string;
  readonly #channelId: string;
  readonly #expectedTeamId: string;
  readonly #fetchImpl: typeof fetch;
  readonly #historyIndex: undefined | WorkspaceLedgerHistoryIndex;
  readonly #userToken: string;

  constructor(options: SlackAccessClientOptions) {
    this.#botToken = options.botToken;
    this.#channelId = options.channelId;
    this.#expectedTeamId = options.expectedTeamId;
    this.#fetchImpl = fetchPort(options.fetchImpl ?? runtimeFetch);
    this.#historyIndex = options.historyIndex;
    this.#userToken = options.userToken;
  }

  async findUniqueAnchor(_options: {
    includeAllMetadata: true;
    pagination: "all";
    runId: string;
  }): Promise<SlackAnchorLookup> {
    const botId = await this.#validateDestination();
    this.#botId = botId;
    const matches = await this.#findAnchorMatches(botId);
    if (matches.length > 1) throw new Error("access_guard_duplicate_anchors");
    const match = matches[0];
    this.#anchorTs = match?.ts ?? null;
    return match
      ? { kind: "found", metadata: match.metadata }
      : { kind: "missing" };
  }

  async listAccounts(_runId: string): Promise<readonly DownstreamAccount[]> {
    const auth = UserAuthSchema.parse(
      await this.#get("auth.test", this.#userToken),
    );
    if (auth["team_id"] !== this.#expectedTeamId)
      throw new Error("access_guard_unexpected_user_token_team");
    const accounts: SlackAccount[] = [];
    let cursor = "";
    const seen = new Set<string>();
    for (let page = 0; page < MAX_HISTORY_PAGES; page++) {
      assertFreshCursor(cursor, seen, "slack_users_repeated_cursor");
      // eslint-disable-next-line no-await-in-loop -- Slack pagination is cursor-ordered and bounded.
      const parsed = await this.#listMembersPage(cursor);
      for (const member of parsed.members) {
        const account = accountFromMember(member);
        if (account) accounts.push(account);
      }
      cursor = parsed["response_metadata"]?.["next_cursor"]?.trim() ?? "";
      if (!cursor) return accounts;
    }
    throw new Error("slack_users_page_limit_exceeded");
  }

  async postNewIssues(
    issues: readonly AccessIssue[],
    _runId: string,
    occurrence: string,
  ): Promise<void> {
    if (issues.length === 0) return;
    if (!this.#anchorTs)
      throw new Error("access_guard_anchor_missing_before_alert");
    const visible = issues.slice(0, 25);
    const lines = visible.map((issue) => `• ${escapeMrkdwn(issue.summary)}`);
    const omitted = issues.length - visible.length;
    const text = [
      "🚨 *IT access guard — new critical findings*",
      ...lines,
      ...(omitted > 0
        ? [
            `• …and ${String(omitted)} more; use the private audit endpoint for full details.`,
          ]
        : []),
    ]
      .join("\n")
      .slice(0, 3_500);
    const deliveryKey = `access-${fnv1a64(
      `${occurrence}|${issues
        .map((issue) => issue.id)
        .toSorted()
        .join("|")}`,
    )}`;
    if (await this.#hasDelivery(deliveryKey)) return;
    try {
      await this.#post("chat.postMessage", this.#botToken, {
        channel: this.#channelId,
        "client_msg_id": deliveryKey,
        metadata: {
          "event_payload": { "delivery_key": deliveryKey },
          "event_type": DELIVERY_EVENT_TYPE,
        },
        text,
        "thread_ts": this.#anchorTs,
        "unfurl_links": false,
      });
    } catch (error) {
      if (!(await this.#hasDelivery(deliveryKey))) throw error;
      return;
    }
    if (!(await this.#hasDelivery(deliveryKey))) {
      throw new Error("access_guard_alert_readback_missing");
    }
  }

  async upsertUniqueAnchor(input: {
    metadata: z.output<typeof AccessGuardSlackMetadataSchema>;
    runId: string;
  }): Promise<void> {
    const metadata = AccessGuardSlackMetadataSchema.parse(input.metadata);
    if (this.#anchorTs) {
      await this.#post("chat.update", this.#botToken, {
        channel: this.#channelId,
        metadata,
        text: ANCHOR_TEXT,
        ts: this.#anchorTs,
      });
      return;
    }
    try {
      await this.#post("chat.postMessage", this.#botToken, {
        channel: this.#channelId,
        "client_msg_id": ANCHOR_CLIENT_MESSAGE_ID,
        metadata,
        text: ANCHOR_TEXT,
        "unfurl_links": false,
      });
    } catch (error) {
      const recovered = await this.findUniqueAnchor({
        includeAllMetadata: true,
        pagination: "all",
        runId: input.runId,
      });
      if (recovered.kind === "missing") throw error;
      return;
    }
    const verified = await this.findUniqueAnchor({
      includeAllMetadata: true,
      pagination: "all",
      runId: input.runId,
    });
    if (verified.kind === "missing")
      throw new Error("access_guard_anchor_readback_missing");
  }

  async #findAnchorMatches(
    botId: string,
  ): Promise<{ metadata: unknown; ts: string }[]> {
    if (this.#historyIndex !== undefined) return this.#findIndexedAnchor(botId);
    const matches: { metadata: unknown; ts: string }[] = [];
    let cursor = "";
    const seen = new Set<string>();
    for (let page = 0; page < MAX_HISTORY_PAGES; page++) {
      assertFreshCursor(cursor, seen, "slack_history_repeated_cursor");
      const query = new URLSearchParams({
        channel: this.#channelId,
        "include_all_metadata": "true",
        limit: "200",
      });
      if (cursor) query.set("cursor", cursor);
      const history = HistorySchema.parse(
        // eslint-disable-next-line no-await-in-loop -- Slack pagination is cursor-ordered and bounded.
        await this.#get(
          `conversations.history?${query.toString()}`,
          this.#botToken,
        ),
      );
      for (const message of history.messages) {
        if (
          message["bot_id"] === botId &&
          message.metadata?.["event_type"] === ANCHOR_EVENT_TYPE
        ) {
          matches.push({ metadata: message.metadata, ts: message.ts });
        }
      }
      cursor = history["response_metadata"]?.["next_cursor"]?.trim() ?? "";
      if (!cursor) return matches;
    }
    throw new Error("slack_history_page_limit_exceeded");
  }

  async #findIndexedAnchor(
    botId: string,
  ): Promise<{ metadata: unknown; ts: string }[]> {
    const index = this.#historyIndex;
    if (index === undefined)
      throw new Error("access_guard_anchor_history_index_required");
    const scope = {
      teamId: this.#expectedTeamId,
      channelId: this.#channelId,
      botId,
    };
    const complete = await index.synchronize(
      scope,
      async ({ latest, oldest }) => {
        const query = new URLSearchParams({
          channel: this.#channelId,
          "include_all_metadata": "true",
          limit: "200",
          ...(latest !== null && { latest }),
          ...(oldest !== null && { oldest }),
        });
        const history = IndexedHistorySchema.parse(
          await this.#get(
            `conversations.history?${query.toString()}`,
            this.#botToken,
          ),
        );
        return {
          timestamps: history.messages.map(({ ts }) => ts),
          entries: history.messages
            .filter(
              (message) =>
                message["bot_id"] === botId &&
                message.metadata?.["event_type"] === ANCHOR_EVENT_TYPE,
            )
            .map(({ ts }) => ({ changeKey: ANCHOR_EVENT_TYPE, timestamp: ts })),
          hasMore:
            history["has_more"] ||
            Boolean(history["response_metadata"]?.["next_cursor"]?.trim()),
        };
      },
    );
    if (!complete) throw new Error("access_guard_anchor_history_incomplete");
    const timestamp = await index.findTimestamp(scope, ANCHOR_EVENT_TYPE);
    if (timestamp === null) return [];
    return [await this.#readIndexedAnchor(botId, timestamp)];
  }

  async #readIndexedAnchor(botId: string, timestamp: string) {
    const query = new URLSearchParams({
      channel: this.#channelId,
      "include_all_metadata": "true",
      inclusive: "true",
      latest: timestamp,
      oldest: timestamp,
      limit: "1",
    });
    const history = HistorySchema.parse(
      await this.#get(
        `conversations.history?${query.toString()}`,
        this.#botToken,
      ),
    );
    const message = history.messages.find(({ ts }) => ts === timestamp);
    if (
      message?.["bot_id"] !== botId ||
      message.metadata?.["event_type"] !== ANCHOR_EVENT_TYPE
    )
      throw new Error("access_guard_anchor_history_message_mismatch");
    return { metadata: message.metadata, ts: timestamp };
  }

  async #get(path: string, token: string): Promise<unknown> {
    const response = await this.#fetchImpl(`${SLACK_API}/${path}`, {
      headers: { authorization: `Bearer ${token}` },
    });
    if (!response.ok) throw new Error(`slack_http_${String(response.status)}`);
    const raw: unknown = await response.json();
    const error = SlackErrorSchema.safeParse(raw);
    if (error.success)
      throw new Error(`slack_${error.data.error ?? "unknown_error"}`);
    return raw;
  }

  async #hasDelivery(deliveryKey: string): Promise<boolean> {
    if (!this.#anchorTs || !this.#botId)
      throw new Error("access_guard_delivery_context_missing");
    const botId = this.#botId;
    let cursor = "";
    const seen = new Set<string>();
    for (let page = 1; page <= MAX_HISTORY_PAGES; page++) {
      if (cursor && seen.has(cursor))
        throw new Error("slack_replies_repeated_cursor");
      if (cursor) seen.add(cursor);
      const query = new URLSearchParams({
        channel: this.#channelId,
        "include_all_metadata": "true",
        limit: "200",
        ts: this.#anchorTs,
      });
      if (cursor) query.set("cursor", cursor);
      const replies = HistorySchema.parse(
        // eslint-disable-next-line no-await-in-loop -- Slack pagination is cursor-ordered and bounded.
        await this.#get(
          `conversations.replies?${query.toString()}`,
          this.#botToken,
        ),
      );
      if (
        replies.messages.some(
          (message) =>
            message["bot_id"] === botId &&
            message.metadata?.["event_type"] === DELIVERY_EVENT_TYPE &&
            z
              .object({ "delivery_key": z.string() })
              .safeParse(message.metadata["event_payload"]).data?.[
              "delivery_key"
            ] === deliveryKey,
        )
      ) {
        return true;
      }
      cursor = replies["response_metadata"]?.["next_cursor"]?.trim() ?? "";
      if (!cursor) return false;
    }
    throw new Error("slack_replies_page_limit_exceeded");
  }

  async #listMembersPage(
    cursor: string,
  ): Promise<z.output<typeof MembersSchema>> {
    const query = new URLSearchParams({ limit: "200" });
    if (cursor) query.set("cursor", cursor);
    return MembersSchema.parse(
      await this.#get(`users.list?${query.toString()}`, this.#userToken),
    );
  }

  async #post(
    path: string,
    token: string,
    body: Record<string, unknown>,
  ): Promise<unknown> {
    const response = await this.#fetchImpl(`${SLACK_API}/${path}`, {
      body: JSON.stringify(body),
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json; charset=utf-8",
      },
      method: "POST",
    });
    if (!response.ok) throw new Error(`slack_http_${String(response.status)}`);
    const raw: unknown = await response.json();
    const error = SlackErrorSchema.safeParse(raw);
    if (error.success)
      throw new Error(`slack_${error.data.error ?? "unknown_error"}`);
    WriteSchema.parse(raw);
    return raw;
  }

  async #validateDestination(): Promise<string> {
    const auth = AuthSchema.parse(await this.#get("auth.test", this.#botToken));
    if (auth["team_id"] !== this.#expectedTeamId)
      throw new Error("access_guard_unexpected_slack_team");
    const query = new URLSearchParams({ channel: this.#channelId });
    const channel = ChannelInfoSchema.parse(
      await this.#get(`conversations.info?${query.toString()}`, this.#botToken),
    );
    if (channel.channel.id !== this.#channelId)
      throw new Error("access_guard_unexpected_channel");
    return auth["bot_id"];
  }
}
type SlackMember = z.output<typeof MembersSchema>["members"][number];

interface SlackAccount {
  active: boolean;
  displayName?: string;
  email: string;
  id: string;
}

function accountFromMember(member: SlackMember): null | SlackAccount {
  if (
    member.id === SLACKBOT_USER_ID ||
    member["is_bot"] === true ||
    member["is_app_user"] === true
  )
    return null;
  const email = member.profile.email?.trim();
  if (!email) throw new Error(`slack_human_missing_email:${member.id}`);
  return {
    active: member.deleted !== true,
    ...(member.profile["real_name"] && {
      displayName: member.profile["real_name"],
    }),
    email,
    id: member.id,
  };
}

function assertFreshCursor(
  cursor: string,
  seen: Set<string>,
  errorCode: string,
): void {
  if (!cursor) return;
  if (seen.has(cursor)) throw new Error(errorCode);
  seen.add(cursor);
}

interface SlackAccessClientOptions {
  botToken: string;
  channelId: string;
  expectedTeamId: string;
  fetchImpl?: typeof fetch;
  historyIndex?: WorkspaceLedgerHistoryIndex;
  userToken: string;
}

function fnv1a64(value: string): string {
  let hash = 0xcbf29ce484222325n;
  for (const character of value) {
    hash ^= BigInt(character.codePointAt(0) ?? 0);
    hash = BigInt.asUintN(64, hash * 0x100000001b3n);
  }
  return hash.toString(16).padStart(16, "0");
}
