import type { D1Database } from "@cloudflare/workers-types";
import { z } from "zod";

import { logErrorEvent } from "../shared/log-event.ts";
import { stableSlackClientMessageId } from "../shared/stable-slack-client-message-id.ts";
import { TRYCOMP_SCHEDULE_ATTEMPT_ABANDONED_AFTER_MS } from "../trycomp/config.ts";
import type { TrycompRunReport } from "../trycomp/model.ts";
import { getWorkspaceExecutionPolicy } from "./get-workspace-execution-policy.ts";

const NotificationKindSchema = z.enum([
  "audit_drift",
  "blocked",
  "failed",
  "breaker_review_required",
  "prechange",
  "completed",
]);

const AttemptKeySchema = z.string().regex(/^[a-f0-9]{64}$/u);
const NotificationBlocksSchema = z.array(z.unknown()).min(1).max(50);
const SlackTimestampSchema = z.string().trim().min(1);
const SlackJsonObjectSchema = z.record(z.string(), z.unknown());
const SlackJsonStringSchema = z.string();
const SlackBlockIdSchema = z.string().min(1);
const SlackAuthSchema = z.object({
  "bot_id": z.string().min(1),
  ok: z.literal(true),
  "team_id": z.string().min(1),
});
const CLAIM_DURATION_MS = 60_000;
const DEDUP_WINDOW_MS = 48 * 60 * 60 * 1_000;
const MAX_DRAIN_BATCH = 10;
const DrainLimitSchema = z.number().int().min(1).max(MAX_DRAIN_BATCH);
const MAX_HISTORY_PAGES = 20;
const MAX_LAST_ERROR_LENGTH = 500;
const RECOVERY_CLOCK_SKEW_MS = 5 * 60 * 1_000;
const REQUIRED_SLACK_SCOPES = [
  "chat:write",
  "groups:history",
  "groups:read",
  "metadata.message:read",
] as const;

class TrycompHistoryScanIncompleteError extends Error {
  readonly recoveryLatestTimestamp: string;

  constructor(recoveryLatestTimestamp: string, options?: ErrorOptions) {
    super("trycomp_notification_history_scan_incomplete", options);
    this.name = "TrycompHistoryScanIncompleteError";
    this.recoveryLatestTimestamp = recoveryLatestTimestamp;
  }
}

class TrycompNotificationReadbackIncompleteError extends Error {
  readonly acceptedSlackTimestamp: string;

  constructor(acceptedSlackTimestamp: string, options?: ErrorOptions) {
    super("trycomp_notification_readback_incomplete", options);
    this.name = "TrycompNotificationReadbackIncompleteError";
    this.acceptedSlackTimestamp = acceptedSlackTimestamp;
  }
}

export type TrycompNotificationKind =
  | "audit_drift"
  | "blocked"
  | "breaker_review_required"
  | "completed"
  | "failed"
  | "prechange";

export interface TrycompNotificationPayload {
  readonly blocks: readonly unknown[];
  readonly clientMessageId: string;
  readonly destinationId: string;
  readonly fallbackText: string;
  readonly intentKey: string;
  readonly kind: TrycompNotificationKind;
  readonly payloadHash: string;
}

interface TrycompScheduleFinishInput {
  attemptKey: string;
  errorCode?: string;
  notification?: TrycompNotificationPayload;
  report?: TrycompRunReport;
  state: "completed" | "failed" | "lease_busy";
}

export interface TrycompScheduleRecoveryStore {
  finish(input: TrycompScheduleFinishInput): Promise<void>;
  recoverAbandoned(destinationId: string): Promise<boolean>;
}

export interface TrycompNotificationClaim extends TrycompNotificationPayload {
  readonly acceptedSlackTimestamp: null | string;
  readonly attemptCount: number;
  readonly claimGeneration: number;
  readonly claimOwner: string;
  readonly createdAtMs: number;
  readonly recoveryLatestTimestamp: null | string;
}

export interface TrycompNotificationOutbox {
  assertDestinationConsistent(destinationId: string): Promise<void>;
  claimNext(
    expectedDestinationId: string,
  ): Promise<null | TrycompNotificationClaim>;
  complete(
    claim: TrycompNotificationClaim,
    slackTimestamp: string,
  ): Promise<void>;
  defer(
    claim: TrycompNotificationClaim,
    errorCode: string,
    recoveryLatestTimestamp?: null | string,
    acceptedSlackTimestamp?: null | string,
  ): Promise<void>;
  expediteAcceptedReceiptRecovery(): Promise<number>;
  renew(claim: TrycompNotificationClaim): Promise<void>;
}

const AttemptEvidenceRowSchema = z.strictObject({
  "error_code": z.string().nullable(),
  "plan_hash": z.string().nullable(),
  "planned_count": z.number().int().nonnegative(),
  "report_status": z.string().nullable(),
  "run_id": z.string().nullable(),
  state: z.string().min(1),
});
const AttemptNotificationLinkRowSchema = z.strictObject({
  "expected_kind": z.string().min(1),
  "intent_key": AttemptKeySchema,
});
const StoredNotificationEvidenceRowSchema = z.strictObject({
  "blocks_json": z.string().min(2),
  "client_msg_id": z.uuid(),
  "destination_id": z.string(),
  "fallback_text": z.string().min(1).max(1000),
  kind: NotificationKindSchema,
  "payload_hash": AttemptKeySchema,
});
const AbandonedAttemptRowSchema = z.strictObject({
  "attempt_key": AttemptKeySchema,
  "scheduled_at_ms": z.number().int().nonnegative(),
});
const NotificationClaimRowSchema = z.strictObject({
  "accepted_slack_ts": z.string().min(1).nullable(),
  "attempt_count": z.number().int().positive(),
  "blocks_json": z.string().min(2),
  "claim_generation": z.number().int().positive(),
  "claim_owner": z.uuid(),
  "client_msg_id": z.uuid(),
  "created_at_ms": z.number().int().nonnegative(),
  "destination_id": z.string(),
  "fallback_text": z.string().min(1).max(1000),
  "intent_key": AttemptKeySchema,
  kind: NotificationKindSchema,
  "payload_hash": AttemptKeySchema,
  "recovery_latest_ts": z.string().min(1).nullable(),
});
const DestinationMismatchRowSchema = z.strictObject({
  count: z.number().int().nonnegative(),
});

function notificationClaimFromRaw(raw: unknown): TrycompNotificationClaim {
  const row = NotificationClaimRowSchema.parse(raw);
  return {
    acceptedSlackTimestamp: row["accepted_slack_ts"],
    attemptCount: row["attempt_count"],
    blocks: NotificationBlocksSchema.parse(JSON.parse(row["blocks_json"])),
    claimGeneration: row["claim_generation"],
    claimOwner: row["claim_owner"],
    clientMessageId: row["client_msg_id"],
    createdAtMs: row["created_at_ms"],
    destinationId: row["destination_id"],
    fallbackText: row["fallback_text"],
    intentKey: row["intent_key"],
    kind: row.kind,
    payloadHash: row["payload_hash"],
    recoveryLatestTimestamp: row["recovery_latest_ts"],
  };
}
const NotificationOwnerSchema = z.uuid();

const DestinationIdSchema = z.string().regex(/^C[A-Z0-9]+$/u);

const NumericSlackTimestampSchema = z.string().regex(/^\d+(?:\.\d+)?$/u);

const TimestampMsSchema = z.number().int().nonnegative();

export class D1TrycompScheduledDeliveryStore
  implements TrycompNotificationOutbox, TrycompScheduleRecoveryStore
{
  readonly #clock: () => number;
  readonly #db: D1Database;
  readonly #ownerIdFactory: () => string;

  constructor(
    db: D1Database,
    options: {
      readonly clock?: () => number;
      readonly ownerIdFactory?: () => string;
    } = {},
  ) {
    this.#clock = options.clock ?? Date.now;
    this.#db = db;
    this.#ownerIdFactory =
      options.ownerIdFactory ?? (() => crypto.randomUUID());
  }

  async expediteAcceptedReceiptRecovery(): Promise<number> {
    const now = this.#now();
    const result = await this.#db
      .prepare(
        `UPDATE trycomp_sync_notification
         SET next_attempt_at_ms = ?1
         WHERE state = 'pending'
           AND accepted_slack_ts IS NOT NULL
           AND last_error = 'trycomp_notification_readback_content_mismatch'
           AND next_attempt_at_ms > ?1`,
      )
      .bind(now)
      .run();
    return result.meta.changes;
  }

  async finish(input: TrycompScheduleFinishInput): Promise<void> {
    const attemptKey = AttemptKeySchema.parse(input.attemptKey);
    await assertValidFinishInput(input);
    const now = this.#now();
    const finishStatement = this.#db
      .prepare(
        `UPDATE trycomp_sync_schedule_attempt
           SET state = ?2, run_id = ?3, report_status = ?4, plan_hash = ?5,
               planned_count = ?6, error_code = ?7, completed_at_ms = ?8
           WHERE attempt_key = ?1 AND state = 'started'`,
      )
      .bind(
        attemptKey,
        input.state,
        input.report?.runId ?? null,
        input.report?.status ?? null,
        input.report?.planHash ?? null,
        input.report?.planned.length ?? 0,
        input.errorCode ?? null,
        now,
      );
    const statements = input.notification
      ? [
          this.#notificationInsert(attemptKey, input.notification, now),
          this.#notificationLink(attemptKey, input.notification, now),
          finishStatement,
        ]
      : [finishStatement];
    const results = await this.#db.batch(statements);
    const finishResult = results[input.notification ? 2 : 0];
    if (finishResult?.meta.changes !== 1) {
      await this.#assertExactFinishedAttempt(attemptKey, input);
      return;
    }
    if (
      input.notification &&
      (results[0]?.meta.changes !== 1 || results[1]?.meta.changes !== 1)
    ) {
      throw new Error("trycomp_notification_enqueue_failed");
    }
  }

  async claimNext(
    expectedDestinationId: string,
  ): Promise<null | TrycompNotificationClaim> {
    const now = this.#now();
    const owner = NotificationOwnerSchema.parse(this.#ownerIdFactory());
    const destination = DestinationIdSchema.parse(expectedDestinationId);
    const raw = await this.#db
      .prepare(
        `UPDATE trycomp_sync_notification
         SET state = 'claimed', claim_owner = ?1,
             claim_generation = claim_generation + 1,
             claim_expires_at_ms = ?2, attempt_count = attempt_count + 1,
             last_attempt_at_ms = ?3, updated_at_ms = ?3
         WHERE intent_key = (
           SELECT intent_key FROM trycomp_sync_notification
           WHERE destination_id = ?4 AND (
             (state = 'pending' AND next_attempt_at_ms <= ?3)
             OR (state = 'claimed' AND claim_expires_at_ms <= ?3)
           )
           ORDER BY created_at_ms ASC, intent_key ASC LIMIT 1
         )
           AND destination_id = ?4
           AND ((state = 'pending' AND next_attempt_at_ms <= ?3)
             OR (state = 'claimed' AND claim_expires_at_ms <= ?3))
         RETURNING intent_key, kind, destination_id, fallback_text, blocks_json,
                   payload_hash, client_msg_id, claim_owner, claim_generation, attempt_count,
                   created_at_ms, recovery_latest_ts, accepted_slack_ts`,
      )
      .bind(owner, now + CLAIM_DURATION_MS, now, destination)
      .first();
    if (!raw) return null;
    return notificationClaimFromRaw(raw);
  }

  async assertDestinationConsistent(destinationId: string): Promise<void> {
    const destination = DestinationIdSchema.parse(destinationId);
    const row = DestinationMismatchRowSchema.parse(
      await this.#db
        .prepare(
          `SELECT COUNT(*) AS count
         FROM trycomp_sync_notification notification
         WHERE notification.destination_id != ?1
           AND notification.state != 'delivered'
        `,
        )
        .bind(destination)
        .first(),
    );
    if (row.count > 0)
      throw new Error("trycomp_notification_destination_mismatch");
  }

  async recoverAbandoned(destinationId: string): Promise<boolean> {
    const now = this.#now();
    const raw = await this.#db
      .prepare(
        `SELECT attempt_key, scheduled_at_ms
         FROM trycomp_sync_schedule_attempt
         WHERE state = 'started' AND started_at_ms <= ?1
         ORDER BY started_at_ms ASC, attempt_key ASC LIMIT 1`,
      )
      .bind(Math.max(0, now - TRYCOMP_SCHEDULE_ATTEMPT_ABANDONED_AFTER_MS))
      .first();
    if (!raw) return false;
    const abandoned = AbandonedAttemptRowSchema.parse(raw);
    const errorCode = "trycomp_schedule_attempt_abandoned";
    const notification = await buildTrycompNotification({
      attemptKey: abandoned["attempt_key"],
      destinationId,
      errorCode,
      kind: "failed",
      observedAtMs: abandoned["scheduled_at_ms"],
    });
    await this.finish({
      attemptKey: abandoned["attempt_key"],
      errorCode,
      notification,
      state: "failed",
    });
    return true;
  }

  async complete(
    claim: TrycompNotificationClaim,
    slackTimestamp: string,
  ): Promise<void> {
    const result = await this.#db
      .prepare(
        `UPDATE trycomp_sync_notification
         SET state = 'delivered', claim_owner = NULL, claim_expires_at_ms = NULL,
             recovery_latest_ts = NULL, accepted_slack_ts = NULL,
             slack_ts = ?4, delivered_at_ms = ?5,
             last_error = NULL, updated_at_ms = ?5
         WHERE intent_key = ?1 AND state = 'claimed'
           AND claim_owner = ?2 AND claim_generation = ?3`,
      )
      .bind(
        claim.intentKey,
        claim.claimOwner,
        claim.claimGeneration,
        SlackTimestampSchema.parse(slackTimestamp),
        this.#now(),
      )
      .run();
    if (result.meta.changes !== 1)
      throw new Error("trycomp_notification_claim_lost");
  }

  async defer(
    claim: TrycompNotificationClaim,
    errorCode: string,
    recoveryLatestTimestamp: null | string = null,
    acceptedSlackTimestamp: null | string = claim.acceptedSlackTimestamp,
  ): Promise<void> {
    const now = this.#now();
    const backoffMs = Math.min(
      6 * 60 * 60 * 1_000,
      5 * 60 * 1_000 * 2 ** (claim.attemptCount - 1),
    );
    const result = await this.#db
      .prepare(
        `UPDATE trycomp_sync_notification
         SET state = 'pending', claim_owner = NULL, claim_expires_at_ms = NULL,
             next_attempt_at_ms = ?4, last_error = ?5, recovery_latest_ts = ?6,
             accepted_slack_ts = ?7, updated_at_ms = ?8
         WHERE intent_key = ?1 AND state = 'claimed'
           AND claim_owner = ?2 AND claim_generation = ?3`,
      )
      .bind(
        claim.intentKey,
        claim.claimOwner,
        claim.claimGeneration,
        now + backoffMs,
        boundedError(errorCode),
        recoveryLatestTimestamp
          ? NumericSlackTimestampSchema.parse(recoveryLatestTimestamp)
          : null,
        acceptedSlackTimestamp
          ? NumericSlackTimestampSchema.parse(acceptedSlackTimestamp)
          : null,
        now,
      )
      .run();
    if (result.meta.changes !== 1)
      throw new Error("trycomp_notification_claim_lost");
  }

  async renew(claim: TrycompNotificationClaim): Promise<void> {
    const now = this.#now();
    const result = await this.#db
      .prepare(
        `UPDATE trycomp_sync_notification
         SET claim_expires_at_ms = ?4, updated_at_ms = ?5
         WHERE intent_key = ?1 AND state = 'claimed'
           AND claim_owner = ?2 AND claim_generation = ?3
           AND claim_expires_at_ms > ?5`,
      )
      .bind(
        claim.intentKey,
        claim.claimOwner,
        claim.claimGeneration,
        now + CLAIM_DURATION_MS,
        now,
      )
      .run();
    if (result.meta.changes !== 1)
      throw new Error("trycomp_notification_claim_lost");
  }

  async #assertExactFinishedAttempt(
    attemptKey: string,
    input: {
      errorCode?: string;
      notification?: TrycompNotificationPayload;
      report?: TrycompRunReport;
      state: "completed" | "failed" | "lease_busy";
    },
  ): Promise<void> {
    const existing = AttemptEvidenceRowSchema.parse(
      await this.#db
        .prepare(
          `SELECT state, run_id, report_status, plan_hash, planned_count, error_code
           FROM trycomp_sync_schedule_attempt WHERE attempt_key = ?1`,
        )
        .bind(attemptKey)
        .first(),
    );
    const expected = {
      "error_code": input.errorCode ?? null,
      "plan_hash": input.report?.planHash ?? null,
      "planned_count": input.report?.planned.length ?? 0,
      "report_status": input.report?.status ?? null,
      "run_id": input.report?.runId ?? null,
      state: input.state,
    };
    if (!sameJson(existing, expected))
      throw new Error("trycomp_schedule_attempt_finish_conflict");
    const linkRaw = await this.#db
      .prepare(
        `SELECT intent_key, expected_kind FROM trycomp_sync_attempt_notification
           WHERE attempt_key = ?1 AND phase = 'terminal'`,
      )
      .bind(attemptKey)
      .first();
    if (!input.notification) {
      if (linkRaw) throw new Error("trycomp_schedule_attempt_finish_conflict");
      return;
    }
    const link = AttemptNotificationLinkRowSchema.parse(linkRaw);
    if (
      link["intent_key"] !== input.notification.intentKey ||
      link["expected_kind"] !== input.notification.kind
    ) {
      throw new Error("trycomp_schedule_attempt_finish_conflict");
    }
    const stored = StoredNotificationEvidenceRowSchema.parse(
      await this.#db
        .prepare(
          `SELECT kind, destination_id, fallback_text, blocks_json, payload_hash, client_msg_id
           FROM trycomp_sync_notification WHERE intent_key = ?1`,
        )
        .bind(input.notification.intentKey)
        .first(),
    );
    if (
      stored.kind !== input.notification.kind ||
      stored["destination_id"] !== input.notification.destinationId ||
      stored["fallback_text"] !== input.notification.fallbackText ||
      stored["payload_hash"] !== input.notification.payloadHash ||
      stored["client_msg_id"] !== input.notification.clientMessageId ||
      !sameJson(JSON.parse(stored["blocks_json"]), input.notification.blocks)
    ) {
      throw new Error("trycomp_schedule_attempt_finish_conflict");
    }
  }

  #notificationInsert(
    attemptKey: string,
    notification: TrycompNotificationPayload,
    now: number,
  ) {
    return this.#db
      .prepare(
        `INSERT INTO trycomp_sync_notification
           (intent_key, attempt_key, kind, payload_version, destination_id, fallback_text,
            blocks_json, payload_hash, client_msg_id, state, next_attempt_at_ms,
            created_at_ms, last_seen_at_ms, updated_at_ms)
         SELECT ?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?8, 'pending', ?9, ?9, ?9, ?9
         FROM trycomp_sync_schedule_attempt
         WHERE attempt_key = ?2 AND state = 'started'
         ON CONFLICT (intent_key) DO UPDATE SET
           payload_hash = CASE
             WHEN trycomp_sync_notification.payload_hash = excluded.payload_hash
              AND trycomp_sync_notification.destination_id = excluded.destination_id
              AND trycomp_sync_notification.client_msg_id = excluded.client_msg_id
             THEN trycomp_sync_notification.payload_hash
             ELSE NULL
           END,
           occurrence_count = trycomp_sync_notification.occurrence_count
             + CASE WHEN trycomp_sync_notification.attempt_key = excluded.attempt_key THEN 0 ELSE 1 END,
           last_seen_at_ms = excluded.last_seen_at_ms,
           updated_at_ms = excluded.updated_at_ms`,
      )
      .bind(
        AttemptKeySchema.parse(notification.intentKey),
        attemptKey,
        notification.kind,
        notification.destinationId,
        notification.fallbackText,
        JSON.stringify(notification.blocks),
        AttemptKeySchema.parse(notification.payloadHash),
        NotificationOwnerSchema.parse(notification.clientMessageId),
        now,
      );
  }

  #notificationLink(
    attemptKey: string,
    notification: TrycompNotificationPayload,
    now: number,
  ) {
    return this.#db
      .prepare(
        `INSERT INTO trycomp_sync_attempt_notification
           (attempt_key, phase, intent_key, expected_kind, linked_at_ms)
         SELECT ?1, 'terminal', ?2, ?3, ?4
         FROM trycomp_sync_schedule_attempt
         WHERE attempt_key = ?1 AND state = 'started'
         ON CONFLICT (attempt_key, phase) DO NOTHING`,
      )
      .bind(attemptKey, notification.intentKey, notification.kind, now);
  }

  #now(): number {
    return TimestampMsSchema.parse(this.#clock());
  }
}

export interface TrycompSlackNotificationTransport {
  publishAndVerify(
    claim: TrycompNotificationClaim,
    renew: () => Promise<void>,
  ): Promise<string>;
}
export interface SlackHistoryResult {
  readonly dropped: number;
  readonly nextCursor: string | undefined;
  readonly messages: readonly {
    readonly ts: string;
    readonly botId: string | undefined;
    readonly metadata?: {
      readonly "event_type": string;
      readonly "event_payload"?: Record<string, unknown> | undefined;
    };
    readonly text: string;
    readonly blocks?: readonly unknown[];
  }[];
}
export interface NotificationAuthResult {
  status: number;
  scopes: null | string;
  body: unknown;
}
export interface NotificationChannelInfo {
  name?: string;
  isArchived?: boolean;
  isExtShared?: boolean;
  isExtSharedKnown?: true;
  isMember: boolean;
  isPendingExtShared?: boolean;
  isPrivate?: boolean;
}
export interface TrycompNotificationSlackPort {
  authTest(): Promise<NotificationAuthResult>;
  getChannelInfo(channelId: string): Promise<NotificationChannelInfo>;
  fetchHistoryStrict(
    channel: string,
    options: {
      cursor?: string;
      inclusive?: boolean;
      latestTs?: string;
      limit?: number;
      oldestTs: string;
      requireComplete?: boolean;
      retry?: boolean;
    },
  ): Promise<SlackHistoryResult>;
  postMessageWithMetadata(
    channel: string,
    text: string,
    blocks: unknown[],
    metadata: { "event_type": string; "event_payload": Record<string, string> },
    clientMsgId?: string,
    retry?: boolean,
  ): Promise<string>;
}
const ExpectedTeamIdSchema = z.string().min(1);

const NonEmptyTimestampSchema = z.string().min(1);

export class TrycompSlackNotificationClient implements TrycompSlackNotificationTransport {
  readonly #expectedTeamId: string;
  readonly #slack: TrycompNotificationSlackPort;

  constructor(slack: TrycompNotificationSlackPort, expectedTeamId: string) {
    this.#slack = slack;
    this.#expectedTeamId = ExpectedTeamIdSchema.parse(expectedTeamId);
  }

  async publishAndVerify(
    claim: TrycompNotificationClaim,
    renew: () => Promise<void>,
  ): Promise<string> {
    if (!claim.destinationId)
      throw new Error("trycomp_notification_destination_missing");
    const botId = await this.#validateDestination(claim.destinationId, renew);
    if (claim.acceptedSlackTimestamp) {
      const recoveredAccepted = await this.#find(
        claim,
        botId,
        renew,
        claim.acceptedSlackTimestamp,
      );
      if (recoveredAccepted === claim.acceptedSlackTimestamp)
        return recoveredAccepted;
      throw new TrycompNotificationReadbackIncompleteError(
        claim.acceptedSlackTimestamp,
      );
    }
    const recovered = await this.#find(claim, botId, renew);
    if (recovered) return recovered;
    await renew();
    const timestamp = NonEmptyTimestampSchema.parse(
      await this.#slack.postMessageWithMetadata(
        claim.destinationId,
        claim.fallbackText,
        [...claim.blocks],
        notificationMetadata(claim),
        claim.clientMessageId,
        false,
      ),
    );
    let verified: null | string;
    try {
      await renew();
      verified = await this.#find(claim, botId, renew, timestamp);
    } catch (error) {
      throw new TrycompNotificationReadbackIncompleteError(timestamp, {
        cause: error,
      });
    }
    if (verified !== timestamp)
      throw new TrycompNotificationReadbackIncompleteError(timestamp);
    return timestamp;
  }

  async #validateDestination(
    destinationId: string,
    renew: () => Promise<void>,
  ): Promise<string> {
    await renew();
    const authResult = await this.#slack.authTest();
    if (authResult.status !== 200)
      throw new Error("trycomp_notification_slack_auth_failed");
    const auth = SlackAuthSchema.parse(authResult.body);
    if (auth["team_id"] !== this.#expectedTeamId)
      throw new Error("trycomp_notification_wrong_team");
    const scopes = new Set(
      authResult.scopes
        ? authResult.scopes
            .split(",")
            .map((scope) => scope.trim())
            .filter(Boolean)
        : [],
    );
    if (REQUIRED_SLACK_SCOPES.some((scope) => !scopes.has(scope))) {
      throw new Error("trycomp_notification_missing_slack_scope");
    }
    await renew();
    const channel = await this.#slack.getChannelInfo(destinationId);
    if (
      channel.isArchived !== false ||
      channel.isExtShared !== false ||
      channel.isExtSharedKnown !== true ||
      !channel.isMember ||
      channel.isPendingExtShared === true
    ) {
      throw new Error("trycomp_notification_unsafe_destination");
    }
    return auth["bot_id"];
  }

  async #find(
    claim: TrycompNotificationClaim,
    botId: string,
    renew: () => Promise<void>,
    expectedTimestamp?: string,
  ): Promise<null | string> {
    const oldestTs = slackTimestampFromMilliseconds(
      Math.max(0, claim.createdAtMs - RECOVERY_CLOCK_SKEW_MS),
    );
    if (expectedTimestamp)
      return this.#findExact(claim, botId, renew, expectedTimestamp);
    return this.#scanHistory(claim, botId, renew, oldestTs);
  }

  async #findExact(
    claim: TrycompNotificationClaim,
    botId: string,
    renew: () => Promise<void>,
    expectedTimestamp: string,
  ): Promise<null | string> {
    await renew();
    const history = await this.#slack.fetchHistoryStrict(claim.destinationId, {
      inclusive: true,
      latestTs: expectedTimestamp,
      limit: 1,
      oldestTs: expectedTimestamp,
      retry: false,
    });
    assertCompleteHistory(history);
    return matchingNotification(history, claim, botId, expectedTimestamp);
  }

  async #scanHistory(
    claim: TrycompNotificationClaim,
    botId: string,
    renew: () => Promise<void>,
    oldestTs: string,
  ): Promise<null | string> {
    let cursor: string | undefined;
    let recoveryLatestTimestamp: string | undefined;
    const seen = new Set<string>();
    for (let page = 0; page < MAX_HISTORY_PAGES; page += 1) {
      const cursorKey = cursor ?? "";
      if (seen.has(cursorKey))
        throw new Error("trycomp_notification_history_cursor_cycle");
      seen.add(cursorKey);
      // eslint-disable-next-line no-await-in-loop -- The fenced claim is renewed before every provider read.
      await renew();
      // eslint-disable-next-line no-await-in-loop -- Slack history is cursor ordered and bounded.
      const history = await this.#slack.fetchHistoryStrict(
        claim.destinationId,
        {
          ...(cursor && { cursor }),
          ...(claim.recoveryLatestTimestamp && {
            latestTs: claim.recoveryLatestTimestamp,
          }),
          oldestTs,
          retry: false,
        },
      );
      assertCompleteHistory(history);
      const match = matchingNotification(history, claim, botId);
      if (match) return match;
      recoveryLatestTimestamp = oldestSlackTimestamp(
        recoveryLatestTimestamp,
        ...history.messages.map((message) => message.ts),
      );
      cursor = history.nextCursor;
      if (!cursor) return null;
    }
    if (recoveryLatestTimestamp) {
      throw new TrycompHistoryScanIncompleteError(recoveryLatestTimestamp);
    }
    throw new Error("trycomp_notification_history_page_limit");
  }
}

function assertCompleteHistory(history: SlackHistoryResult): void {
  if (history.dropped > 0)
    throw new Error("trycomp_notification_history_incomplete");
}

export interface TrycompNotificationDeliveryPort {
  drain(limit?: number): Promise<{ delivered: number; deferred: number }>;
}

export class TrycompNotificationDeliveryService implements TrycompNotificationDeliveryPort {
  readonly #expectedDestinationId: string;
  readonly #outbox: TrycompNotificationOutbox;
  readonly #transport: TrycompSlackNotificationTransport;

  constructor(
    outbox: TrycompNotificationOutbox,
    transport: TrycompSlackNotificationTransport,
    expectedDestinationId: string,
  ) {
    this.#expectedDestinationId = DestinationIdSchema.parse(
      expectedDestinationId,
    );
    this.#outbox = outbox;
    this.#transport = transport;
  }

  async drain(
    limit = MAX_DRAIN_BATCH,
  ): Promise<{ delivered: number; deferred: number }> {
    const boundedLimit = DrainLimitSchema.parse(limit);
    let delivered = 0;
    let deferred = 0;
    for (let index = 0; index < boundedLimit; index += 1) {
      // eslint-disable-next-line no-await-in-loop -- Claims and Slack receipts are intentionally serialized.
      const claim = await this.#outbox.claimNext(this.#expectedDestinationId);
      if (!claim) break;
      try {
        // eslint-disable-next-line no-await-in-loop -- A claim must finish before another delivery starts.
        const timestamp = await this.#transport.publishAndVerify(claim, () =>
          this.#outbox.renew(claim),
        );
        // eslint-disable-next-line no-await-in-loop -- Persist the exact receipt before claiming another row.
        await this.#outbox.complete(claim, timestamp);
        delivered += 1;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        // eslint-disable-next-line no-await-in-loop -- A failed claim must be durably deferred before continuing.
        await this.#outbox.defer(
          claim,
          sanitizeOutcomeCode(error),
          error instanceof TrycompHistoryScanIncompleteError
            ? oldestSlackTimestamp(
                claim.recoveryLatestTimestamp ?? undefined,
                error.recoveryLatestTimestamp,
              )
            : claim.recoveryLatestTimestamp,
          error instanceof TrycompNotificationReadbackIncompleteError
            ? error.acceptedSlackTimestamp
            : claim.acceptedSlackTimestamp,
        );
        deferred += 1;
        logErrorEvent("trycomp_notification.delivery_deferred", {
          error: message,
          "intent_key": claim.intentKey,
        });
      }
    }
    return { deferred, delivered };
  }
}

export async function buildTrycompNotification(input: {
  attemptKey?: string;
  destinationId: string;
  errorCode?: string;
  kind: Exclude<TrycompNotificationKind, "prechange">;
  observedAtMs?: number;
  report?: TrycompRunReport;
}): Promise<TrycompNotificationPayload> {
  const plannedCount = input.report?.planned.length ?? 0;
  const planHash = input.report?.planHash ?? null;
  const safeErrorCode = input.errorCode
    ? sanitizeOutcomeCode(input.errorCode)
    : null;
  const title = notificationTitle(input.kind);
  const verifiedChanges =
    input.kind === "completed" && input.report
      ? trycompActionLines(input.report.applied)
      : [];
  const facts = [
    `*Status:* ${input.report?.status ?? "failed before plan"}`,
    `*Planned changes:* ${String(plannedCount)}`,
    ...(planHash ? [`*Plan:* \`${planHash}\``] : []),
    ...(safeErrorCode ? [`*Outcome:* \`${safeErrorCode}\``] : []),
    ...(verifiedChanges.length > 0
      ? ["*Verified changes:*", ...verifiedChanges]
      : []),
  ];
  const blocks = [
    { text: { emoji: true, text: title, type: "plain_text" }, type: "header" },
    { text: { text: facts.join("\n"), type: "mrkdwn" }, type: "section" },
    {
      elements: [
        {
          text: `Review durable status: ${getWorkspaceExecutionPolicy().notificationStatusUrl}`,
          type: "mrkdwn",
        },
      ],
      type: "context",
    },
  ] as const;
  const fallbackText = `${input.kind === "completed" ? ":white_check_mark:" : ":warning:"} ${title} — ${String(plannedCount)} change(s)`;
  const payloadHash = await notificationPayloadHash({
    blocks,
    destinationId: input.destinationId,
    fallbackText,
  });
  const observedAtMs = TimestampMsSchema.parse(
    input.observedAtMs ?? Date.now(),
  );
  const windowStartMs =
    Math.floor(observedAtMs / DEDUP_WINDOW_MS) * DEDUP_WINDOW_MS;
  const intentKey = await sha256(
    JSON.stringify({
      attemptKey: input.attemptKey ?? null,
      errorCode: safeErrorCode,
      kind: input.kind,
      payloadHash,
      planHash,
      plannedCount,
      windowStartMs,
    }),
  );
  return {
    blocks,
    clientMessageId: await stableSlackClientMessageId(
      `trycomp-alert:${intentKey}`,
    ),
    destinationId: input.destinationId,
    fallbackText,
    intentKey,
    kind: input.kind,
    payloadHash,
  };
}

function trycompActionLines(actions: TrycompRunReport["planned"]): string[] {
  return actions.map((action) => {
    const label = trycompActionLabel(action.type);
    const authority =
      action.type === "deactivate" && action.deactivationAuthority
        ? `; authority \`${action.deactivationAuthority}\``
        : "";
    const member =
      "memberId" in action ? `; member \`${action.memberId}\`` : "";
    return `• ${label} \`${action.email}\`${authority}${member}`;
  });
}

function trycompActionLabel(
  type: TrycompRunReport["planned"][number]["type"],
): string {
  switch (type) {
    case "deactivate":
      return "Deactivate";
    case "invite":
      return "Invite";
    case "reactivate":
      return "Reactivate";
  }
}

function matchingNotification(
  history: SlackHistoryResult,
  claim: TrycompNotificationClaim,
  botId: string,
  expectedTimestamp?: string,
): null | string {
  const metadata = notificationMetadata(claim);
  for (const message of history.messages) {
    if (expectedTimestamp && message.ts !== expectedTimestamp) continue;
    if (message.botId !== botId || !sameJson(message.metadata, metadata))
      continue;
    if (
      message.text !== claim.fallbackText ||
      !sameSlackContent(claim.blocks, message.blocks ?? [])
    ) {
      throw new Error("trycomp_notification_readback_content_mismatch");
    }
    return message.ts;
  }
  return null;
}

function notificationMetadata(claim: TrycompNotificationClaim) {
  return {
    "event_payload": {
      intentKey: claim.intentKey,
      payloadHash: claim.payloadHash,
      version: "1",
    },
    "event_type": "sarj_trycomp_sync_alert",
  };
}

function notificationTitle(
  kind: Exclude<TrycompNotificationKind, "prechange">,
): string {
  switch (kind) {
    case "audit_drift":
      return "Trycomp audit found lifecycle drift";
    case "blocked":
      return "Trycomp synchronization is blocked";
    case "breaker_review_required":
      return "Trycomp safety breaker requires review";
    case "completed":
      return "Trycomp changes verified";
    case "failed":
      return "Trycomp scheduled synchronization failed";
  }
}

export function sanitizeOutcomeCode(error: unknown): string {
  const message = (
    error instanceof Error ? error.message : String(error)
  ).trim();
  if (
    /^[a-z0-9]+(?:[a-z0-9:_-]*[a-z0-9])?$/u.test(message) &&
    message.length <= 120
  ) {
    return message.toLocaleLowerCase("en-US");
  }
  return "trycomp_scheduled_failure";
}

function boundedError(value: string): string {
  return value.slice(0, MAX_LAST_ERROR_LENGTH);
}

function slackTimestampFromMilliseconds(value: number): string {
  return (TimestampMsSchema.parse(value) / 1_000).toFixed(3);
}

async function notificationPayloadHash(
  notification: Pick<
    TrycompNotificationPayload,
    "blocks" | "destinationId" | "fallbackText"
  >,
): Promise<string> {
  return sha256(
    JSON.stringify({
      blocks: notification.blocks,
      destinationId: notification.destinationId,
      fallbackText: notification.fallbackText,
    }),
  );
}

async function assertValidFinishInput(
  input: TrycompScheduleFinishInput,
): Promise<void> {
  if (input.state === "failed" && !input.errorCode) {
    throw new Error("trycomp_failed_attempt_notification_required");
  }
  const expectedKind = expectedFinishNotificationKind(input);
  if (expectedKind && !input.notification) {
    throw new Error("trycomp_failed_attempt_notification_required");
  }
  if (!expectedKind && input.notification) {
    throw new Error("trycomp_unexpected_attempt_notification");
  }
  if (!input.notification) return;
  if (input.notification.kind !== expectedKind) {
    throw new Error("trycomp_attempt_notification_kind_mismatch");
  }
  const expectedPayloadHash = await notificationPayloadHash(input.notification);
  if (input.notification.payloadHash !== expectedPayloadHash) {
    throw new Error("trycomp_notification_payload_hash_mismatch");
  }
}

function expectedFinishNotificationKind(
  input: TrycompScheduleFinishInput,
): null | TrycompNotificationKind {
  if (input.state === "failed")
    return input.report?.status === "blocked" ? "blocked" : "failed";
  if (
    input.state === "completed" &&
    input.report?.status === "audit" &&
    input.report.planned.length > 0
  ) {
    return "audit_drift";
  }
  if (
    input.state === "completed" &&
    input.report?.status === "converged" &&
    input.report.applied.length > 0
  ) {
    return "completed";
  }
  return null;
}

function oldestSlackTimestamp(
  ...timestamps: (string | undefined)[]
): string | undefined {
  return timestamps
    .filter((timestamp): timestamp is string => timestamp !== undefined)
    .reduce<string | undefined>((oldest, timestamp) => {
      const parsed = NumericSlackTimestampSchema.parse(timestamp);
      if (!oldest || Number(parsed) < Number(oldest)) return parsed;
      return oldest;
    }, undefined);
}

async function sha256(value: string): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
  );
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function sameJson(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (Array.isArray(left))
    return (
      Array.isArray(right) &&
      left.length === right.length &&
      left.every((value, index) => sameJson(value, right[index]))
    );
  if (!isRecord(left) || !isRecord(right)) return false;
  const leftKeys = Object.keys(left);
  const rightKeys = Object.keys(right);
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every(
      (key) => Object.hasOwn(right, key) && sameJson(left[key], right[key]),
    )
  );
}

function sameSlackContent(expected: unknown, observed: unknown): boolean {
  if (Object.is(expected, observed)) return true;
  const expectedString = SlackJsonStringSchema.safeParse(expected);
  const observedString = SlackJsonStringSchema.safeParse(observed);
  if (expectedString.success && observedString.success) {
    return (
      expectedString.data.replaceAll(
        getWorkspaceExecutionPolicy().notificationStatusUrl,
        () => `<${getWorkspaceExecutionPolicy().notificationStatusUrl}>`,
      ) === observedString.data
    );
  }
  if (Array.isArray(expected)) {
    if (!Array.isArray(observed) || expected.length !== observed.length)
      return false;
    return expected.every((value, index) =>
      sameSlackContent(value, observed[index]),
    );
  }
  if (!isRecord(expected) || !isRecord(observed)) return false;
  const expectedKeys = Object.keys(expected);
  const observedKeys = Object.keys(observed).filter(
    (key) => !isSlackGeneratedDefault(key, expected, observed),
  );
  return (
    expectedKeys.length === observedKeys.length &&
    expectedKeys.every(
      (key) =>
        Object.hasOwn(observed, key) &&
        sameSlackContent(expected[key], observed[key]),
    )
  );
}

function isSlackGeneratedDefault(
  key: string,
  expected: Record<string, unknown>,
  observed: Record<string, unknown>,
): boolean {
  if (Object.hasOwn(expected, key)) return false;
  if (key === "block_id")
    return SlackBlockIdSchema.safeParse(observed[key]).success;
  return (
    (key === "emoji" && observed[key] === true) ||
    (key === "verbatim" && observed[key] === false)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return SlackJsonObjectSchema.safeParse(value).success;
}
