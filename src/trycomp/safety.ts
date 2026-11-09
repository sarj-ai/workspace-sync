import type { D1Database } from "@cloudflare/workers-types";
import { z } from "zod";

import type { ActiveResourceLease } from "../identity-sync/resource-lease.ts";
import {
  TRYCOMP_SCHEDULE_ATTEMPT_ABANDONED_AFTER_MS,
  TRYCOMP_SCHEDULE_MAX_AGE_MS,
  TRYCOMP_SYNC_MINIMUM_LEASE_HEADROOM_MS,
  TRYCOMP_SYNC_RESOURCE_LEASE_KEY,
} from "./config.ts";
import type { TrycompAction } from "./model.ts";

const BREAKER_KEY = "org-sync/trycomp-people";
const DeactivationAuthoritySchema = z.enum([
  "contractor_group",
  "inactive_google",
]);
const RunModeSchema = z.enum(["audit", "live"]);
const RunStateSchema = z.enum([
  "planned",
  "applying",
  "completed",
  "failed",
  "ambiguous",
]);
const RunTriggerKindSchema = z.enum(["cron", "http"]);
const ActionTypeSchema = z.enum(["invite", "reactivate", "deactivate"]);
const ActionStateSchema = z.enum([
  "planned",
  "attempted",
  "provider_accepted",
  "verified",
  "ambiguous",
]);
const NotificationKindSchema = z.enum([
  "audit_drift",
  "blocked",
  "failed",
  "breaker_review_required",
  "prechange",
  "completed",
]);
const NotificationStateSchema = z.enum(["pending", "claimed", "delivered"]);
const ReportStatusSchema = z.enum(["audit", "blocked", "failed", "converged"]);
const ScheduledAttemptStateSchema = z.enum([
  "started",
  "lease_busy",
  "completed",
  "failed",
]);
const PreannouncementIntentKeySchema = z.string().regex(/^[a-f0-9]{64}$/u);
const SlackTimestampSchema = z
  .string()
  .trim()
  .regex(/^\d+(?:\.\d+)?$/u);
const BREAKER_SELECT_SQL = `SELECT state, opened_run_id, opened_action_index, reason, opened_at_ms, updated_at_ms
  FROM trycomp_sync_breaker WHERE breaker_key = ?1`;

export const TrycompDeploymentEvidenceSchema = z.strictObject({
  id: z.string().min(1),
  tag: z.string().regex(/^[a-f0-9]{40}$/u),
  timestamp: z.iso.datetime(),
});
export type TrycompDeploymentEvidence = z.output<
  typeof TrycompDeploymentEvidenceSchema
>;

const BreakerRowSchema = z.strictObject({
  "opened_action_index": z.number().int().nonnegative().nullable(),
  "opened_at_ms": z.number().int().nonnegative().nullable(),
  "opened_run_id": z.string().nullable(),
  reason: z.string().nullable(),
  state: z.enum(["closed", "review_required"]),
  "updated_at_ms": z.number().int().nonnegative(),
});

export type TrycompBreakerStatus = z.output<typeof BreakerRowSchema>;
const RunRowSchema = z.strictObject({
  "ambiguous_count": z.number().int().nonnegative(),
  "attempted_count": z.number().int().nonnegative(),
  "completed_at_ms": z.number().int().nonnegative().nullable(),
  "created_at_ms": z.number().int().nonnegative(),
  "error_code": z.string().nullable(),
  mode: RunModeSchema,
  "plan_hash": z.string().regex(/^[a-f0-9]{64}$/u),
  "planned_count": z.number().int().nonnegative(),
  "provider_accepted_count": z.number().int().nonnegative(),
  "run_id": z.uuid(),
  state: RunStateSchema,
  "trigger_kind": RunTriggerKindSchema,
  "verified_count": z.number().int().nonnegative(),
  "worker_version_id": z.string().min(1),
  "worker_version_tag": z.string().regex(/^[a-f0-9]{40}$/u),
  "worker_version_timestamp": z.iso.datetime(),
});
const ActionRowSchema = z.strictObject({
  "action_index": z.number().int().nonnegative(),
  "action_type": ActionTypeSchema,
  "authority_group_id": z.string().nullable(),
  "deactivation_authority": DeactivationAuthoritySchema.nullable(),
  email: z.email(),
  "error_code": z.string().nullable(),
  "google_user_id": z.string().nullable(),
  "member_id": z.string().nullable(),
  "run_id": z.uuid(),
  state: ActionStateSchema,
});
const ScheduledAttemptRowSchema = z.strictObject({
  "attempt_key": z.string().regex(/^[a-f0-9]{64}$/u),
  "completed_at_ms": z.number().int().nonnegative().nullable(),
  "error_code": z.string().nullable(),
  "notification_intent_key": z
    .string()
    .regex(/^[a-f0-9]{64}$/u)
    .nullable(),
  "notification_root_intent_key": z
    .string()
    .regex(/^[a-f0-9]{64}$/u)
    .nullable(),
  "notification_attempt_count": z.number().int().nonnegative().nullable(),
  "notification_accepted_slack_ts": z.string().nullable(),
  "notification_delivered_at_ms": z.number().int().nonnegative().nullable(),
  "notification_kind": NotificationKindSchema.nullable(),
  "notification_slack_ts": z.string().nullable(),
  "notification_state": NotificationStateSchema.nullable(),
  "plan_hash": z
    .string()
    .regex(/^[a-f0-9]{64}$/u)
    .nullable(),
  "planned_count": z.number().int().nonnegative(),
  "report_status": ReportStatusSchema.nullable(),
  "run_id": z.string().nullable(),
  "scheduled_at_ms": z.number().int().nonnegative(),
  "started_at_ms": z.number().int().nonnegative(),
  state: ScheduledAttemptStateSchema,
  "worker_version_id": z.string().min(1),
  "worker_version_tag": z.string().regex(/^[a-f0-9]{40}$/u),
  "worker_version_timestamp": z.iso.datetime(),
});
const NotificationSummaryRowSchema = z.strictObject({
  "accepted_count": z.number().int().nonnegative(),
  "claimed_count": z.number().int().nonnegative(),
  "delivered_count": z.number().int().nonnegative(),
  "latest_delivered_at_ms": z.number().int().nonnegative().nullable(),
  "max_attempt_count": z.number().int().nonnegative(),
  "oldest_undelivered_at_ms": z.number().int().nonnegative().nullable(),
  "pending_count": z.number().int().nonnegative(),
});
const ScheduleHealthRowSchema = z.strictObject({
  "attempt_count": z.number().int().nonnegative(),
  "missing_notification_evidence_count": z.number().int().nonnegative(),
  "stale_attempt_count": z.number().int().nonnegative(),
});
const NotificationRowSchema = z.strictObject({
  "accepted_slack_ts": z.string().nullable(),
  "attempt_key": z.string().regex(/^[a-f0-9]{64}$/u),
  "attempt_count": z.number().int().nonnegative(),
  "delivered_at_ms": z.number().int().nonnegative().nullable(),
  "intent_key": z.string().regex(/^[a-f0-9]{64}$/u),
  kind: NotificationKindSchema,
  "last_error": z.string().nullable(),
  "last_seen_at_ms": z.number().int().nonnegative(),
  "occurrence_count": z.number().int().positive(),
  "slack_ts": z.string().nullable(),
  state: NotificationStateSchema,
  "updated_at_ms": z.number().int().nonnegative(),
});

function linkedNotificationEvidence(
  row: z.infer<typeof ScheduledAttemptRowSchema>,
) {
  if (!row["notification_root_intent_key"]) return null;
  if (
    row["notification_intent_key"] === null ||
    row["notification_attempt_count"] === null ||
    row["notification_kind"] === null ||
    row["notification_state"] === null
  ) {
    throw new Error("trycomp_schedule_notification_evidence_incomplete");
  }
  const delivered = row["notification_state"] === "delivered";
  if (
    delivered !==
    (row["notification_delivered_at_ms"] !== null &&
      row["notification_slack_ts"] !== null &&
      row["notification_slack_ts"].length > 0)
  ) {
    throw new Error("trycomp_schedule_notification_receipt_inconsistent");
  }
  return {
    attemptCount: row["notification_attempt_count"],
    acceptedSlackTimestamp: row["notification_accepted_slack_ts"],
    deliveredAtMs: row["notification_delivered_at_ms"],
    intentKey: row["notification_intent_key"],
    kind: row["notification_kind"],
    rootIntentKey: row["notification_root_intent_key"],
    slackTimestamp: row["notification_slack_ts"],
    state: row["notification_state"],
  };
}

// This is a resolution of one historical attempt, not a rewrite of its provider outcome.
export const TrycompVerifiedIncidentResolutionSchema = z
  .strictObject({
    tickId: z.literal(
      "e42a58d91d7c68dc96602c470cb5a9de7ed91b78c3b621fdfe2b47cac6ed1275",
    ),
    runId: z.literal("94d0feb3-92f2-4f10-83fd-dbcc00fdaf31"),
    actionIndex: z.literal(0),
    kind: z.literal("observed-after"),
    sourceHash: z.string().regex(/^[a-f0-9]{64}$/u),
    observedAtMs: z.number().int().nonnegative(),
    recordedAtMs: z.number().int().nonnegative(),
  })
  .refine(
    (value) =>
      value.observedAtMs <= value.recordedAtMs &&
      value.observedAtMs >= value.recordedAtMs - 60_000,
  );
export const TrycompVerifiedIncidentResolutionsSchema = z
  .array(TrycompVerifiedIncidentResolutionSchema)
  .max(1);

export const TrycompSafetyReadModelSchema = z.strictObject({
  breaker: BreakerRowSchema,
  effectiveBreaker: z.boolean(),
  verifiedIncidentResolutions:
    TrycompVerifiedIncidentResolutionsSchema.optional(),
  latestActions: z.array(
    z.strictObject({
      actionIndex: z.number().int().nonnegative(),
      actionType: ActionTypeSchema,
      authorityGroupId: z.string().nullable(),
      deactivationAuthority: DeactivationAuthoritySchema.nullable(),
      email: z.email(),
      errorCode: z.string().nullable(),
      googleUserId: z.string().nullable(),
      memberId: z.string().nullable(),
      runId: z.uuid(),
      state: ActionStateSchema,
    }),
  ),
  latestNotification: z
    .strictObject({
      attemptCount: z.number().int().nonnegative(),
      acceptedSlackTimestamp: z.string().nullable(),
      attemptKey: z.string().regex(/^[a-f0-9]{64}$/u),
      deliveredAtMs: z.number().int().nonnegative().nullable(),
      intentKey: z.string().regex(/^[a-f0-9]{64}$/u),
      kind: NotificationKindSchema,
      lastError: z.string().nullable(),
      lastSeenAtMs: z.number().int().nonnegative(),
      occurrenceCount: z.number().int().positive(),
      slackTimestamp: z.string().nullable(),
      state: NotificationStateSchema,
      updatedAtMs: z.number().int().nonnegative(),
    })
    .nullable(),
  latestRuns: z.array(
    z.strictObject({
      ambiguousCount: z.number().int().nonnegative(),
      attemptedCount: z.number().int().nonnegative(),
      completedAtMs: z.number().int().nonnegative().nullable(),
      createdAtMs: z.number().int().nonnegative(),
      errorCode: z.string().nullable(),
      mode: RunModeSchema,
      planHash: z.string().regex(/^[a-f0-9]{64}$/u),
      plannedCount: z.number().int().nonnegative(),
      providerAcceptedCount: z.number().int().nonnegative(),
      runId: z.uuid(),
      state: RunStateSchema,
      trigger: RunTriggerKindSchema,
      verifiedCount: z.number().int().nonnegative(),
      workerVersionId: z.string().min(1),
      workerVersionTag: z.string().regex(/^[a-f0-9]{40}$/u),
      workerVersionTimestamp: z.iso.datetime(),
    }),
  ),
  latestScheduledAttempt: z
    .strictObject({
      attemptKey: z.string().regex(/^[a-f0-9]{64}$/u),
      completedAtMs: z.number().int().nonnegative().nullable(),
      errorCode: z.string().nullable(),
      notificationIntentKey: z
        .string()
        .regex(/^[a-f0-9]{64}$/u)
        .nullable(),
      notification: z
        .strictObject({
          attemptCount: z.number().int().nonnegative(),
          acceptedSlackTimestamp: z.string().nullable(),
          deliveredAtMs: z.number().int().nonnegative().nullable(),
          intentKey: z.string().regex(/^[a-f0-9]{64}$/u),
          kind: NotificationKindSchema,
          rootIntentKey: z.string().regex(/^[a-f0-9]{64}$/u),
          slackTimestamp: z.string().nullable(),
          state: NotificationStateSchema,
        })
        .nullable(),
      planHash: z
        .string()
        .regex(/^[a-f0-9]{64}$/u)
        .nullable(),
      plannedCount: z.number().int().nonnegative(),
      reportStatus: ReportStatusSchema.nullable(),
      runId: z.string().nullable(),
      scheduledAtMs: z.number().int().nonnegative(),
      startedAtMs: z.number().int().nonnegative(),
      state: ScheduledAttemptStateSchema,
      workerVersionId: z.string().min(1),
      workerVersionTag: z.string().regex(/^[a-f0-9]{40}$/u),
      workerVersionTimestamp: z.iso.datetime(),
    })
    .nullable(),
  notificationHealth: z.strictObject({
    acceptedCount: z.number().int().nonnegative(),
    claimedCount: z.number().int().nonnegative(),
    deliveredCount: z.number().int().nonnegative(),
    healthy: z.boolean(),
    latestDeliveredAtMs: z.number().int().nonnegative().nullable(),
    maxAttemptCount: z.number().int().nonnegative(),
    missingEvidenceCount: z.number().int().nonnegative(),
    oldestUndeliveredAtMs: z.number().int().nonnegative().nullable(),
    pendingCount: z.number().int().nonnegative(),
  }),
  scheduleHealth: z.strictObject({
    healthy: z.boolean(),
    missingNotificationEvidenceCount: z.number().int().nonnegative(),
    observed: z.boolean(),
    staleAttemptCount: z.number().int().nonnegative(),
  }),
  scheduleHealthy: z.boolean(),
  unresolvedMutations: z.number().int().nonnegative(),
});
export type TrycompSafetyReadModel = z.output<
  typeof TrycompSafetyReadModelSchema
>;

export interface TrycompSafetyStore {
  assertClosed(): Promise<void>;
  readModel(): Promise<TrycompSafetyReadModel>;
  status(): Promise<TrycompBreakerStatus>;
}

export interface TrycompMutationStore {
  beginRun(input: {
    actionAuthority?: readonly TrycompActionAuthorityEvidence[];
    actions: readonly TrycompAction[];
    deployment: TrycompDeploymentEvidence;
    mode: "audit" | "live";
    planHash: string;
    providerOperationKeys: readonly string[];
    runId: string;
    trigger: "cron" | "http";
  }): Promise<void>;
  completeRun(runId: string): Promise<void>;
  failRun(runId: string, errorCode: string): Promise<void>;
  markAttempted(input: {
    actionIndex: number;
    lease: ActiveResourceLease;
    runId: string;
  }): Promise<void>;
  markProviderAccepted(runId: string, actionIndex: number): Promise<void>;
  markVerified(
    correlationId: string,
    actionIndex: number,
    verifiedMemberId: string,
  ): Promise<void>;
  openForAmbiguous(
    runId: string,
    actionIndex: number,
    errorCode: string,
  ): Promise<void>;
  recordPreannouncement(input: {
    runId: string;
    lease: ActiveResourceLease;
    intentKey: string;
    slackTimestamp: string;
  }): Promise<void>;
}

export interface TrycompActionAuthorityEvidence {
  authorityGroupId: null | string;
  deactivationAuthority: "contractor_group" | "inactive_google" | null;
  googleUserId: null | string;
}

function assertActionAuthorityEvidence(
  action: TrycompAction,
  evidence: TrycompActionAuthorityEvidence,
): void {
  if (action.type !== "deactivate") {
    if (
      evidence.deactivationAuthority !== null ||
      evidence.authorityGroupId !== null
    ) {
      throw new Error("trycomp_journal_authority_action_mismatch");
    }
    return;
  }
  if (
    evidence.googleUserId === null ||
    evidence.deactivationAuthority !== action.deactivationAuthority
  ) {
    throw new Error("trycomp_journal_authority_action_mismatch");
  }
  const expectedGroupEvidence =
    action.deactivationAuthority === "contractor_group"
      ? evidence.authorityGroupId !== null
      : evidence.authorityGroupId === null;
  if (!expectedGroupEvidence)
    throw new Error("trycomp_journal_authority_action_mismatch");
}
const VerifiedMemberIdSchema = z.string().min(1);

const TimestampMsSchema = z.number().int().nonnegative();

export class D1TrycompMutationStore implements TrycompMutationStore {
  readonly #clock: () => number;
  readonly #db: D1Database;

  constructor(db: D1Database, options: { readonly clock?: () => number } = {}) {
    this.#clock = options.clock ?? Date.now;
    this.#db = db;
  }

  async beginRun(input: {
    actionAuthority?: readonly TrycompActionAuthorityEvidence[];
    actions: readonly TrycompAction[];
    deployment: TrycompDeploymentEvidence;
    mode: "audit" | "live";
    planHash: string;
    providerOperationKeys: readonly string[];
    runId: string;
    trigger: "cron" | "http";
  }): Promise<void> {
    if (input.providerOperationKeys.length !== input.actions.length) {
      throw new Error("trycomp_journal_operation_key_count_mismatch");
    }
    const actionAuthority =
      input.actionAuthority ??
      input.actions.map(() => ({
        authorityGroupId: null,
        deactivationAuthority: null,
        googleUserId: null,
      }));
    if (actionAuthority.length !== input.actions.length) {
      throw new Error("trycomp_journal_authority_count_mismatch");
    }
    for (const [index, action] of input.actions.entries()) {
      const evidence = actionAuthority[index];
      if (evidence === undefined)
        throw new Error("trycomp_journal_authority_count_mismatch");
      assertActionAuthorityEvidence(action, evidence);
    }
    const now = this.#now();
    const deployment = TrycompDeploymentEvidenceSchema.parse(input.deployment);
    const statements = [
      this.#db
        .prepare(
          `INSERT INTO trycomp_sync_run
             (run_id, plan_hash, trigger_kind, mode, worker_version_id, worker_version_tag,
              worker_version_timestamp, state, planned_count, created_at_ms)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'planned', ?8, ?9)`,
        )
        .bind(
          input.runId,
          input.planHash,
          input.trigger,
          input.mode,
          deployment.id,
          deployment.tag,
          deployment.timestamp,
          input.actions.length,
          now,
        ),
      ...input.actions.map((action, index) =>
        this.#db
          .prepare(
            `INSERT INTO trycomp_sync_action
               (run_id, action_index, action_type, email, member_id, provider_operation_key, state,
                deactivation_authority, google_user_id, authority_group_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'planned', ?7, ?8, ?9)`,
          )
          .bind(
            input.runId,
            index,
            action.type,
            action.email,
            "memberId" in action ? action.memberId : null,
            input.mode === "live" ? input.providerOperationKeys[index] : null,
            actionAuthority[index]?.deactivationAuthority ?? null,
            actionAuthority[index]?.googleUserId ?? null,
            actionAuthority[index]?.authorityGroupId ?? null,
          ),
      ),
    ];
    const results = await this.#db.batch(statements);
    if (results.length !== statements.length)
      throw new Error("trycomp_journal_begin_failed");
  }

  async markAttempted(input: {
    actionIndex: number;
    lease: ActiveResourceLease;
    runId: string;
  }): Promise<void> {
    const now = this.#now();
    if (input.lease.resourceKey !== TRYCOMP_SYNC_RESOURCE_LEASE_KEY) {
      throw new Error("trycomp_journal_wrong_resource_lease");
    }
    const requiredUntil = now + TRYCOMP_SYNC_MINIMUM_LEASE_HEADROOM_MS;
    const results = await this.#db.batch([
      this.#db
        .prepare(
          `UPDATE trycomp_sync_action
           SET state = 'attempted', attempted_at_ms = ?3
           WHERE run_id = ?1 AND action_index = ?2 AND state = 'planned'
             AND EXISTS (
               SELECT 1 FROM trycomp_sync_run
               WHERE run_id = ?1 AND mode = 'live' AND trigger_kind = 'cron'
                 AND state IN ('planned', 'applying')
                 AND preannouncement_intent_key IS NOT NULL
                 AND preannouncement_slack_ts IS NOT NULL
                 AND preannounced_at_ms IS NOT NULL
             )
             AND EXISTS (
               SELECT 1 FROM trycomp_sync_breaker
               WHERE breaker_key = ?4 AND state = 'closed'
             )
             AND NOT EXISTS (
               SELECT 1 FROM trycomp_unresolved_mutation
             )
             AND EXISTS (
               SELECT 1 FROM automation_singleton_lease
               WHERE lease_key = ?5 AND owner_id = ?6 AND generation = ?7
                 AND expires_at_ms > ?8
             )`,
        )
        .bind(
          input.runId,
          input.actionIndex,
          now,
          BREAKER_KEY,
          TRYCOMP_SYNC_RESOURCE_LEASE_KEY,
          input.lease.ownerId,
          input.lease.generation,
          requiredUntil,
        ),
      this.#db
        .prepare(
          `UPDATE trycomp_sync_run
           SET state = 'applying',
               attempted_count = (SELECT COUNT(*) FROM trycomp_sync_action
                                  WHERE run_id = ?1 AND attempted_at_ms IS NOT NULL)
           WHERE run_id = ?1
             AND attempted_count != (SELECT COUNT(*) FROM trycomp_sync_action
                                     WHERE run_id = ?1 AND attempted_at_ms IS NOT NULL)`,
        )
        .bind(input.runId),
    ]);
    if (results[0]?.meta.changes !== 1 || results[1]?.meta.changes !== 1) {
      throw new Error("trycomp_journal_attempted_failed");
    }
  }

  async markProviderAccepted(
    runId: string,
    actionIndex: number,
  ): Promise<void> {
    const results = await this.#db.batch([
      this.#db
        .prepare(
          `UPDATE trycomp_sync_action
           SET state = 'provider_accepted', provider_accepted_at_ms = ?3
           WHERE run_id = ?1 AND action_index = ?2 AND state = 'attempted'`,
        )
        .bind(runId, actionIndex, this.#now()),
      this.#db
        .prepare(
          `UPDATE trycomp_sync_run
           SET provider_accepted_count = (SELECT COUNT(*) FROM trycomp_sync_action
                                         WHERE run_id = ?1
                                           AND provider_accepted_at_ms IS NOT NULL)
           WHERE run_id = ?1
             AND provider_accepted_count != (SELECT COUNT(*) FROM trycomp_sync_action
                                             WHERE run_id = ?1
                                               AND provider_accepted_at_ms IS NOT NULL)`,
        )
        .bind(runId),
    ]);
    this.#assertBatchTransition(results, "provider_accepted");
  }

  async markVerified(
    correlationId: string,
    actionIndex: number,
    verifiedMemberId: string,
  ): Promise<void> {
    const results = await this.#db.batch([
      this.#db
        .prepare(
          `UPDATE trycomp_sync_action
           SET state = 'verified', verified_at_ms = ?3, member_id = COALESCE(?4, member_id)
           WHERE run_id = ?1 AND action_index = ?2 AND state = 'provider_accepted'`,
        )
        .bind(
          correlationId,
          actionIndex,
          this.#now(),
          VerifiedMemberIdSchema.parse(verifiedMemberId),
        ),
      this.#db
        .prepare(
          `UPDATE trycomp_sync_run
           SET verified_count = (SELECT COUNT(*) FROM trycomp_sync_action
                                 WHERE run_id = ?1 AND verified_at_ms IS NOT NULL)
           WHERE run_id = ?1
             AND verified_count != (SELECT COUNT(*) FROM trycomp_sync_action
                                    WHERE run_id = ?1 AND verified_at_ms IS NOT NULL)`,
        )
        .bind(correlationId),
    ]);
    this.#assertBatchTransition(results, "verified");
  }

  async recordPreannouncement(input: {
    runId: string;
    lease: ActiveResourceLease;
    intentKey: string;
    slackTimestamp: string;
  }): Promise<void> {
    if (input.lease.resourceKey !== TRYCOMP_SYNC_RESOURCE_LEASE_KEY) {
      throw new Error("trycomp_journal_wrong_resource_lease");
    }
    const now = this.#now();
    const requiredUntil = now + TRYCOMP_SYNC_MINIMUM_LEASE_HEADROOM_MS;
    const intentKey = PreannouncementIntentKeySchema.parse(input.intentKey);
    const slackTimestamp = SlackTimestampSchema.parse(input.slackTimestamp);
    const result = await this.#db
      .prepare(
        `UPDATE trycomp_sync_run
         SET preannouncement_intent_key = ?2, preannouncement_slack_ts = ?3,
             preannounced_at_ms = ?4
         WHERE run_id = ?1 AND mode = 'live' AND trigger_kind = 'cron'
           AND state = 'planned' AND planned_count > 0
           AND attempted_count = 0 AND provider_accepted_count = 0
           AND verified_count = 0 AND ambiguous_count = 0
           AND preannouncement_intent_key IS NULL
           AND preannouncement_slack_ts IS NULL
           AND preannounced_at_ms IS NULL
           AND EXISTS (
             SELECT 1 FROM trycomp_sync_notification notification
             JOIN trycomp_sync_attempt_notification evidence
               ON evidence.intent_key = notification.intent_key
              AND evidence.expected_kind = notification.kind
             WHERE notification.intent_key = ?2 AND notification.kind = 'prechange'
               AND notification.state = 'delivered' AND notification.slack_ts = ?3
               AND evidence.phase = 'prechange'
           )
           AND EXISTS (
             SELECT 1 FROM trycomp_sync_breaker
             WHERE breaker_key = ?5 AND state = 'closed'
           )
           AND EXISTS (
             SELECT 1 FROM automation_singleton_lease
             WHERE lease_key = ?6 AND owner_id = ?7 AND generation = ?8
               AND expires_at_ms > ?9
           )`,
      )
      .bind(
        input.runId,
        intentKey,
        slackTimestamp,
        now,
        BREAKER_KEY,
        TRYCOMP_SYNC_RESOURCE_LEASE_KEY,
        input.lease.ownerId,
        input.lease.generation,
        requiredUntil,
      )
      .run();
    if (result.meta.changes !== 1)
      throw new Error("trycomp_journal_preannouncement_failed");
  }

  async openForAmbiguous(
    runId: string,
    actionIndex: number,
    errorCode: string,
  ): Promise<void> {
    const now = this.#now();
    const results = await this.#db.batch([
      this.#db
        .prepare(
          `UPDATE trycomp_sync_action
           SET state = 'ambiguous', ambiguous_at_ms = ?3, error_code = ?4
           WHERE run_id = ?1 AND action_index = ?2
             AND state IN ('attempted', 'provider_accepted')`,
        )
        .bind(runId, actionIndex, now, errorCode),
      this.#db
        .prepare(
          `UPDATE trycomp_sync_run
           SET state = 'ambiguous', ambiguous_count = ambiguous_count + 1,
               completed_at_ms = ?2, error_code = ?3
           WHERE run_id = ?1 AND state IN ('planned', 'applying')`,
        )
        .bind(runId, now, errorCode),
      this.#db
        .prepare(
          `UPDATE trycomp_sync_breaker
           SET state = 'review_required', opened_run_id = ?2, opened_action_index = ?3,
               reason = ?4, opened_at_ms = ?5, updated_at_ms = ?5
           WHERE breaker_key = ?1 AND state = 'closed'`,
        )
        .bind(BREAKER_KEY, runId, actionIndex, errorCode, now),
    ]);
    if (results.length !== 3 || results[0]?.meta.changes !== 1) {
      throw new Error("trycomp_breaker_open_failed");
    }
    const status = await this.#status();
    if (status.state !== "review_required")
      throw new Error("trycomp_breaker_open_failed");
  }

  async completeRun(runId: string): Promise<void> {
    await this.#finishRun(runId, "completed", null);
  }

  async failRun(runId: string, errorCode: string): Promise<void> {
    await this.#finishRun(runId, "failed", errorCode);
  }

  async #status(): Promise<TrycompBreakerStatus> {
    const raw = await this.#db
      .prepare(BREAKER_SELECT_SQL)
      .bind(BREAKER_KEY)
      .first();
    if (!raw) throw new Error("trycomp_breaker_missing");
    return BreakerRowSchema.parse(raw);
  }

  async #finishRun(
    runId: string,
    state: "completed" | "failed",
    errorCode: null | string,
  ): Promise<void> {
    const now = this.#now();
    if (state === "failed") {
      const results = await this.#db.batch([
        this.#db
          .prepare(
            `UPDATE trycomp_sync_run SET state = 'failed', completed_at_ms = ?2, error_code = ?3
             WHERE run_id = ?1 AND state IN ('planned', 'applying')`,
          )
          .bind(runId, now, errorCode),
        this.#db
          .prepare(
            `UPDATE trycomp_sync_action
             SET released_provider_operation_key = provider_operation_key,
                 provider_operation_key = NULL,
                 operation_key_released_at_ms = ?2
             WHERE run_id = ?1
               AND provider_operation_key IS NOT NULL
               AND state = 'planned'
               AND attempted_at_ms IS NULL
               AND provider_accepted_at_ms IS NULL
               AND verified_at_ms IS NULL
               AND ambiguous_at_ms IS NULL
               AND EXISTS (
                 SELECT 1 FROM trycomp_sync_run
                 WHERE run_id = ?1
                   AND state = 'failed'
                   AND completed_at_ms = ?2
                   AND attempted_count = 0
                   AND provider_accepted_count = 0
                   AND verified_count = 0
                   AND ambiguous_count = 0
               )
               AND NOT EXISTS (
                 SELECT 1 FROM trycomp_sync_action AS sibling
                 WHERE sibling.run_id = ?1
                   AND (
                     sibling.state != 'planned'
                     OR sibling.attempted_at_ms IS NOT NULL
                     OR sibling.provider_accepted_at_ms IS NOT NULL
                     OR sibling.verified_at_ms IS NOT NULL
                     OR sibling.ambiguous_at_ms IS NOT NULL
                   )
               )`,
          )
          .bind(runId, now),
      ]);
      if (
        results.length !== 2 ||
        results[0]?.success !== true ||
        results[0].meta.changes !== 1 ||
        results[1]?.success !== true
      ) {
        throw new Error("trycomp_journal_finish_failed");
      }
      return;
    }
    const result = await this.#db
      .prepare(
        `UPDATE trycomp_sync_run SET state = ?2, completed_at_ms = ?3, error_code = ?4
         WHERE run_id = ?1 AND state IN ('planned', 'applying')`,
      )
      .bind(runId, state, now, errorCode)
      .run();
    if (result.meta.changes !== 1)
      throw new Error("trycomp_journal_finish_failed");
  }

  #assertBatchTransition(
    results: readonly {
      readonly meta: { readonly changes: number };
      readonly success: boolean;
    }[],
    transition: "provider_accepted" | "verified",
  ): void {
    if (results[0]?.meta.changes !== 1 || results[1]?.meta.changes !== 1) {
      throw new Error(`trycomp_journal_${transition}_failed`);
    }
  }

  #now(): number {
    return TimestampMsSchema.parse(this.#clock());
  }
}
const RunRowsSchema = z.array(RunRowSchema);

const ActionRowsSchema = z.array(ActionRowSchema);

export class D1TrycompSafetyStore implements TrycompSafetyStore {
  readonly #clock: () => number;
  readonly #db: D1Database;

  constructor(db: D1Database, options: { readonly clock?: () => number } = {}) {
    this.#clock = options.clock ?? Date.now;
    this.#db = db;
  }

  async assertClosed(): Promise<void> {
    const now = TimestampMsSchema.parse(this.#clock());
    await this.#db
      .prepare(
        `UPDATE trycomp_sync_breaker
         SET state = 'review_required',
             opened_run_id = (SELECT run_id FROM trycomp_unresolved_mutation
                              ORDER BY run_id, action_index LIMIT 1),
             opened_action_index = (SELECT action_index FROM trycomp_unresolved_mutation
                                     ORDER BY run_id, action_index LIMIT 1),
             reason = 'unresolved_mutation', opened_at_ms = ?2, updated_at_ms = ?2
         WHERE breaker_key = ?1 AND state = 'closed'
           AND EXISTS (SELECT 1 FROM trycomp_unresolved_mutation)`,
      )
      .bind(BREAKER_KEY, now)
      .run();
    const breaker = await this.status();
    if (breaker.state !== "closed")
      throw new Error("trycomp_sync_review_required");
  }

  async status(): Promise<TrycompBreakerStatus> {
    const raw = await this.#db
      .prepare(BREAKER_SELECT_SQL)
      .bind(BREAKER_KEY)
      .first();
    if (!raw) throw new Error("trycomp_breaker_missing");
    return BreakerRowSchema.parse(raw);
  }

  async readModel(): Promise<TrycompSafetyReadModel> {
    const now = TimestampMsSchema.parse(this.#clock());
    const [
      breakerResult,
      unresolvedResult,
      runsResult,
      actionsResult,
      attemptResult,
      notificationSummaryResult,
      notificationResult,
      scheduleHealthResult,
      incidentResolutionsResult,
    ] = await this.#db.batch([
      this.#db.prepare(BREAKER_SELECT_SQL).bind(BREAKER_KEY),
      this.#db.prepare(
        "SELECT COUNT(*) AS count FROM trycomp_unresolved_mutation",
      ),
      this.#db.prepare(
        `SELECT run_id, plan_hash, trigger_kind, mode, state, planned_count,
                  attempted_count, provider_accepted_count, verified_count, ambiguous_count,
                  created_at_ms, completed_at_ms, error_code, worker_version_id,
                  worker_version_tag, worker_version_timestamp
           FROM trycomp_sync_run ORDER BY created_at_ms DESC, run_id DESC LIMIT 20`,
      ),
      this.#db.prepare(
        `SELECT action.run_id, action.action_index, action.action_type, action.email,
                  action.member_id, action.state, action.error_code, action.deactivation_authority,
                  action.google_user_id, action.authority_group_id
           FROM trycomp_sync_action AS action
           JOIN trycomp_sync_run AS run ON run.run_id = action.run_id
           WHERE action.run_id IN (
             SELECT run_id FROM trycomp_sync_run ORDER BY created_at_ms DESC, run_id DESC LIMIT 20
           )
           ORDER BY run.created_at_ms DESC, run.run_id DESC, action.action_index ASC`,
      ),
      this.#db.prepare(
        `SELECT attempt.attempt_key, attempt.scheduled_at_ms, attempt.worker_version_id,
                attempt.worker_version_tag, attempt.worker_version_timestamp,
                attempt.state, attempt.run_id, attempt.report_status, attempt.plan_hash,
                attempt.planned_count, attempt.error_code, attempt.started_at_ms,
                attempt.completed_at_ms,
                evidence.intent_key AS notification_root_intent_key,
                linked.intent_key AS notification_intent_key,
                linked.kind AS notification_kind, linked.state AS notification_state,
                linked.attempt_count AS notification_attempt_count,
                linked.accepted_slack_ts AS notification_accepted_slack_ts,
                linked.slack_ts AS notification_slack_ts,
                linked.delivered_at_ms AS notification_delivered_at_ms
         FROM trycomp_sync_schedule_attempt attempt
         LEFT JOIN trycomp_sync_attempt_notification evidence
           ON evidence.attempt_key = attempt.attempt_key AND evidence.phase = 'terminal'
         LEFT JOIN trycomp_sync_notification linked
           ON linked.intent_key = evidence.intent_key
         ORDER BY attempt.started_at_ms DESC, attempt.attempt_key DESC LIMIT 1`,
      ),
      this.#db.prepare(
        `SELECT
           COALESCE(SUM(CASE WHEN state = 'pending' THEN 1 ELSE 0 END), 0) AS pending_count,
           COALESCE(SUM(CASE WHEN state = 'claimed' THEN 1 ELSE 0 END), 0) AS claimed_count,
           COALESCE(SUM(CASE WHEN state = 'delivered' THEN 1 ELSE 0 END), 0) AS delivered_count,
           COALESCE(SUM(CASE WHEN accepted_slack_ts IS NOT NULL THEN 1 ELSE 0 END), 0)
             AS accepted_count,
           MIN(CASE WHEN state != 'delivered' THEN created_at_ms END) AS oldest_undelivered_at_ms,
           MAX(delivered_at_ms) AS latest_delivered_at_ms,
           COALESCE(MAX(attempt_count), 0) AS max_attempt_count
         FROM trycomp_sync_notification notification`,
      ),
      this.#db.prepare(
        `SELECT intent_key, attempt_key, kind, state, attempt_count, occurrence_count,
                accepted_slack_ts,
                last_error, slack_ts, delivered_at_ms, last_seen_at_ms, updated_at_ms
         FROM trycomp_sync_notification
         ORDER BY updated_at_ms DESC, intent_key DESC LIMIT 1`,
      ),
      this.#db
        .prepare(
          `SELECT
             COUNT(*) AS attempt_count,
             COALESCE(SUM(CASE
               WHEN state = 'started' AND started_at_ms <= ?1 THEN 1 ELSE 0 END), 0)
               AS stale_attempt_count,
             COALESCE(SUM(CASE
               WHEN (
                 state = 'failed'
                 OR (state = 'completed' AND report_status = 'audit' AND planned_count > 0)
                 OR (
                   state = 'completed'
                   AND report_status = 'converged'
                   AND planned_count > 0
                   AND EXISTS (
                     SELECT 1 FROM trycomp_sync_attempt_notification prechange_evidence
                     WHERE prechange_evidence.attempt_key = attempt.attempt_key
                       AND prechange_evidence.phase = 'prechange'
                   )
                 )
               ) AND NOT EXISTS (
                 SELECT 1 FROM trycomp_sync_attempt_notification evidence
                 WHERE evidence.attempt_key = attempt.attempt_key
                   AND evidence.phase = 'terminal'
               ) THEN 1 ELSE 0 END), 0) AS missing_notification_evidence_count
           FROM trycomp_sync_schedule_attempt attempt`,
        )
        .bind(Math.max(0, now - TRYCOMP_SCHEDULE_ATTEMPT_ABANDONED_AFTER_MS)),
      this.#db
        .prepare(`SELECT verified.tick_id AS tickId, verified.run_id AS runId,
        verified.action_index AS actionIndex, verified.source_hash AS sourceHash,
        'observed-after' AS kind, resolution.recorded_at_ms AS recordedAtMs,
        json_extract(resolution.proof_json,'$.observedAtMs') AS observedAtMs
        FROM workspace_verified_comp_incident_resolution verified
        JOIN comp_incident_recovery_resolution resolution
        ON resolution.tick_id=verified.tick_id AND resolution.source_hash=verified.source_hash`),
    ]);
    const verifiedIncidentResolutions =
      TrycompVerifiedIncidentResolutionsSchema.parse(
        incidentResolutionsResult?.results ?? [],
      );
    if (
      verifiedIncidentResolutions.some(
        (resolution) => resolution.recordedAtMs > now,
      )
    )
      throw new Error("trycomp_incident_resolution_time_invalid");
    const breakerRaw = breakerResult?.results[0];
    const unresolvedRaw = unresolvedResult?.results[0];
    if (!breakerRaw) throw new Error("trycomp_breaker_missing");
    const breaker = BreakerRowSchema.parse(breakerRaw);
    const unresolvedMutations = z
      .strictObject({ count: z.number().int().nonnegative() })
      .parse(unresolvedRaw).count;
    const latestRuns = RunRowsSchema.parse(runsResult?.results ?? []).map(
      (row) => ({
        ambiguousCount: row["ambiguous_count"],
        attemptedCount: row["attempted_count"],
        completedAtMs: row["completed_at_ms"],
        createdAtMs: row["created_at_ms"],
        errorCode: row["error_code"],
        mode: row.mode,
        planHash: row["plan_hash"],
        plannedCount: row["planned_count"],
        providerAcceptedCount: row["provider_accepted_count"],
        runId: row["run_id"],
        state: row.state,
        trigger: row["trigger_kind"],
        verifiedCount: row["verified_count"],
        workerVersionId: row["worker_version_id"],
        workerVersionTag: row["worker_version_tag"],
        workerVersionTimestamp: row["worker_version_timestamp"],
      }),
    );
    const latestActions = ActionRowsSchema.parse(
      actionsResult?.results ?? [],
    ).map((row) => ({
      actionIndex: row["action_index"],
      actionType: row["action_type"],
      authorityGroupId: row["authority_group_id"],
      deactivationAuthority: row["deactivation_authority"],
      email: row.email,
      errorCode: row["error_code"],
      googleUserId: row["google_user_id"],
      memberId: row["member_id"],
      runId: row["run_id"],
      state: row.state,
    }));
    const scheduledAttemptRaw = attemptResult?.results[0];
    const scheduledAttempt = scheduledAttemptRaw
      ? ScheduledAttemptRowSchema.parse(scheduledAttemptRaw)
      : null;
    const latestScheduledAttempt = scheduledAttempt
      ? {
          attemptKey: scheduledAttempt["attempt_key"],
          completedAtMs: scheduledAttempt["completed_at_ms"],
          errorCode: scheduledAttempt["error_code"],
          notification: linkedNotificationEvidence(scheduledAttempt),
          notificationIntentKey:
            scheduledAttempt["notification_root_intent_key"],
          planHash: scheduledAttempt["plan_hash"],
          plannedCount: scheduledAttempt["planned_count"],
          reportStatus: scheduledAttempt["report_status"],
          runId: scheduledAttempt["run_id"],
          scheduledAtMs: scheduledAttempt["scheduled_at_ms"],
          startedAtMs: scheduledAttempt["started_at_ms"],
          state: scheduledAttempt.state,
          workerVersionId: scheduledAttempt["worker_version_id"],
          workerVersionTag: scheduledAttempt["worker_version_tag"],
          workerVersionTimestamp: scheduledAttempt["worker_version_timestamp"],
        }
      : null;
    const notificationSummary = NotificationSummaryRowSchema.parse(
      notificationSummaryResult?.results[0],
    );
    const notificationRaw = notificationResult?.results[0];
    const notification = notificationRaw
      ? NotificationRowSchema.parse(notificationRaw)
      : null;
    const latestNotification = notification
      ? {
          acceptedSlackTimestamp: notification["accepted_slack_ts"],
          attemptCount: notification["attempt_count"],
          attemptKey: notification["attempt_key"],
          deliveredAtMs: notification["delivered_at_ms"],
          intentKey: notification["intent_key"],
          kind: notification.kind,
          lastError: notification["last_error"],
          lastSeenAtMs: notification["last_seen_at_ms"],
          occurrenceCount: notification["occurrence_count"],
          slackTimestamp: notification["slack_ts"],
          state: notification.state,
          updatedAtMs: notification["updated_at_ms"],
        }
      : null;
    const scheduleHealth = ScheduleHealthRowSchema.parse(
      scheduleHealthResult?.results[0],
    );
    const scheduleHealthy =
      scheduleHealth["attempt_count"] > 0 &&
      scheduleHealth["stale_attempt_count"] === 0 &&
      scheduleHealth["missing_notification_evidence_count"] === 0 &&
      scheduledAttempt !== null &&
      scheduledAttempt["scheduled_at_ms"] >=
        Math.max(0, now - TRYCOMP_SCHEDULE_MAX_AGE_MS) &&
      scheduledAttempt.state === "completed" &&
      (scheduledAttempt["report_status"] === "audit" ||
        scheduledAttempt["report_status"] === "converged");
    return TrycompSafetyReadModelSchema.parse({
      breaker,
      effectiveBreaker: breaker.state !== "closed" || unresolvedMutations > 0,
      latestActions,
      verifiedIncidentResolutions,
      latestNotification,
      latestRuns,
      latestScheduledAttempt,
      notificationHealth: {
        acceptedCount: notificationSummary["accepted_count"],
        claimedCount: notificationSummary["claimed_count"],
        deliveredCount: notificationSummary["delivered_count"],
        healthy:
          notificationSummary["pending_count"] +
            notificationSummary["claimed_count"] ===
            0 && scheduleHealth["missing_notification_evidence_count"] === 0,
        latestDeliveredAtMs: notificationSummary["latest_delivered_at_ms"],
        maxAttemptCount: notificationSummary["max_attempt_count"],
        missingEvidenceCount:
          scheduleHealth["missing_notification_evidence_count"],
        oldestUndeliveredAtMs: notificationSummary["oldest_undelivered_at_ms"],
        pendingCount: notificationSummary["pending_count"],
      },
      scheduleHealth: {
        healthy: scheduleHealthy,
        missingNotificationEvidenceCount:
          scheduleHealth["missing_notification_evidence_count"],
        observed: scheduleHealth["attempt_count"] > 0,
        staleAttemptCount: scheduleHealth["stale_attempt_count"],
      },
      scheduleHealthy,
      unresolvedMutations,
    });
  }
}
