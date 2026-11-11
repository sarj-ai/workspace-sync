import type { D1Database } from "@cloudflare/workers-types";
import { z } from "zod";

import {
  type IdentityWriteBudget,
  reserveIdentityWriteBudget,
} from "../identity-provisioning/identity-budget-contracts.ts";
import type { ActiveResourceLease } from "../identity-sync/resource-lease.ts";
import {
  TRYCOMP_SYNC_MINIMUM_LEASE_HEADROOM_MS,
  TRYCOMP_SYNC_RESOURCE_LEASE_KEY,
} from "../trycomp/config.ts";
import { TrycompReviewedPlanSchema } from "../trycomp/model.ts";
import {
  D1TrycompMutationStore,
  type TrycompMutationStore,
} from "../trycomp/safety.ts";
import { workspaceChangeLedgerChannelId } from "./change-ledger-contracts.ts";

export const WorkspaceTrycompReceiptSchema = z.strictObject({
  announcementDigest: z.string().regex(/^[a-f0-9]{64}$/u),
  changeKey: z.string().min(1),
  channelId: z
    .string()
    .refine((value) => value === workspaceChangeLedgerChannelId()),
  parentPlanHash: z.string().regex(/^[a-f0-9]{64}$/u),
  requestedBy: z.literal("scheduled:workspace-directory"),
  reviewedPlan: TrycompReviewedPlanSchema,
  timestamp: z.string().regex(/^\d+\.\d{6}$/u),
});
export type WorkspaceTrycompReceipt = z.output<
  typeof WorkspaceTrycompReceiptSchema
>;

/** Consumes a freshly verified Workspace ledger receipt; never creates a Slack notification. */
export class D1WorkspaceTrycompMutationStore
  extends D1TrycompMutationStore
  implements TrycompMutationStore
{
  readonly #db: D1Database;
  readonly #receipt: WorkspaceTrycompReceipt;
  readonly #clock: () => number;
  readonly #identityBudget: IdentityWriteBudget | undefined;

  constructor(
    db: D1Database,
    receipt: WorkspaceTrycompReceipt,
    clock: () => number = Date.now,
    identityBudget?: IdentityWriteBudget,
  ) {
    super(db, { clock });
    this.#db = db;
    this.#receipt = WorkspaceTrycompReceiptSchema.parse(receipt);
    this.#clock = clock;
    this.#identityBudget = identityBudget;
  }

  override async markAttempted(input: {
    actionIndex: number;
    lease: ActiveResourceLease;
    runId: string;
  }): Promise<void> {
    if (this.#identityBudget?.required) {
      const statement = this.#db
        .prepare(`SELECT action.google_user_id
        FROM trycomp_sync_action action
        JOIN trycomp_sync_run run ON run.run_id = action.run_id
        JOIN trycomp_sync_workspace_receipt receipt ON receipt.run_id = run.run_id
        WHERE action.run_id = ?1 AND action.action_index = ?2 AND action.state = 'planned'
          AND run.plan_hash = ?3 AND receipt.child_plan_hash = ?3
          AND receipt.source_fingerprint = ?4 AND receipt.parent_plan_hash = ?5`)
        .bind(
          input.runId,
          input.actionIndex,
          this.#receipt.reviewedPlan.plan.planHash,
          this.#receipt.reviewedPlan.sourceFingerprint,
          this.#receipt.parentPlanHash,
        );
      const action = await statement.first();
      const parsed = z
        .strictObject({ "google_user_id": z.string().min(1) })
        .parse(action);
      await reserveIdentityWriteBudget(
        this.#identityBudget,
        parsed["google_user_id"],
      );
      const refreshed = z
        .strictObject({ "google_user_id": z.string().min(1) })
        .parse(await statement.first());
      if (refreshed["google_user_id"] !== parsed["google_user_id"])
        throw new Error("trycomp_workspace_budget_identity_changed");
    }
    await super.markAttempted(input);
  }

  override async recordPreannouncement(input: {
    runId: string;
    lease: ActiveResourceLease;
    intentKey: string;
    slackTimestamp: string;
  }): Promise<void> {
    const receipt = this.#receipt;
    const reviewed = receipt.reviewedPlan;
    const action = reviewed.plan.actions[0];
    if (
      input.lease.resourceKey !== TRYCOMP_SYNC_RESOURCE_LEASE_KEY ||
      input.intentKey !== receipt.announcementDigest ||
      input.slackTimestamp !== receipt.timestamp ||
      action === undefined ||
      reviewed.plan.actions.length !== 1 ||
      receipt.changeKey !==
        `${receipt.parentPlanHash}:trycomp-people:${action.type}:${action.email}`
    )
      throw new Error("trycomp_workspace_receipt_mismatch");
    const now = this.#clock();
    const results = await this.#db.batch([
      this.#db
        .prepare(`INSERT INTO trycomp_sync_workspace_receipt
        (run_id, parent_plan_hash, child_plan_hash, source_fingerprint, reviewed_plan_json,
         change_key, announcement_digest, channel_id, slack_ts, requested_by, verified_at_ms)
        SELECT run.run_id, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11
        FROM trycomp_sync_run run
        WHERE run.run_id = ?1 AND run.plan_hash = ?3 AND run.mode = 'live'
          AND run.trigger_kind = 'cron' AND run.state = 'planned' AND run.planned_count = 1
          AND run.attempted_count = 0 AND run.provider_accepted_count = 0
          AND run.verified_count = 0 AND run.ambiguous_count = 0
          AND run.preannounced_at_ms IS NULL
          AND EXISTS (SELECT 1 FROM trycomp_sync_action action
            WHERE action.run_id = run.run_id AND action.action_index = 0
              AND action.state = 'planned' AND action.action_type = ?12
              AND action.email = ?13 AND action.member_id IS ?14)
          AND EXISTS (SELECT 1 FROM trycomp_sync_breaker
            WHERE breaker_key = ?15 AND state = 'closed')
          AND EXISTS (SELECT 1 FROM automation_singleton_lease
            WHERE lease_key = ?15 AND owner_id = ?16 AND generation = ?17
              AND expires_at_ms > ?18)`)
        .bind(
          input.runId,
          receipt.parentPlanHash,
          reviewed.plan.planHash,
          reviewed.sourceFingerprint,
          JSON.stringify(reviewed),
          receipt.changeKey,
          receipt.announcementDigest,
          receipt.channelId,
          receipt.timestamp,
          receipt.requestedBy,
          now,
          action.type,
          action.email,
          action.type === "invite" ? null : action.memberId,
          TRYCOMP_SYNC_RESOURCE_LEASE_KEY,
          input.lease.ownerId,
          input.lease.generation,
          now + TRYCOMP_SYNC_MINIMUM_LEASE_HEADROOM_MS,
        ),
      this.#db
        .prepare(`UPDATE trycomp_sync_run
        SET preannouncement_intent_key = ?2, preannouncement_slack_ts = ?3,
          preannounced_at_ms = ?4
        WHERE run_id = ?1 AND preannounced_at_ms IS NULL
          AND EXISTS (SELECT 1 FROM trycomp_sync_workspace_receipt receipt
            WHERE receipt.run_id = ?1 AND receipt.announcement_digest = ?2
              AND receipt.slack_ts = ?3 AND receipt.child_plan_hash = trycomp_sync_run.plan_hash)`)
        .bind(input.runId, receipt.announcementDigest, receipt.timestamp, now),
    ]);
    if (results[0]?.meta.changes !== 1 || results[1]?.meta.changes !== 1) {
      throw new Error("trycomp_workspace_receipt_not_authorized");
    }
  }
}
