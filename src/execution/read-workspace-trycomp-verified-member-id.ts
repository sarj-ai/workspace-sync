import type { D1Database } from "@cloudflare/workers-types";
import { z } from "zod";

import {
  type WorkspaceTrycompReceipt,
  WorkspaceTrycompReceiptSchema,
} from "./workspace-receipt.ts";

/* Reads the original provider journal; never sends an invitation or a message. */
export async function readWorkspaceTrycompVerifiedMemberId(
  database: D1Database,
  rawReceipt: WorkspaceTrycompReceipt,
): Promise<null | string> {
  const receipt = WorkspaceTrycompReceiptSchema.parse(rawReceipt);
  const reviewed = receipt.reviewedPlan;
  const action = reviewed.plan.actions[0];
  if (action === undefined || reviewed.selectedIdentity === undefined)
    throw new Error("trycomp_verified_member_identity_required");
  const rows = await database
    .withSession("first-primary")
    .prepare(`
    SELECT action.member_id FROM trycomp_sync_workspace_receipt receipt
    JOIN trycomp_sync_run run ON run.run_id = receipt.run_id
    JOIN trycomp_sync_action action ON action.run_id = run.run_id
    WHERE receipt.parent_plan_hash = ?1 AND receipt.child_plan_hash = ?2
      AND receipt.source_fingerprint = ?3 AND receipt.reviewed_plan_json = ?4
      AND receipt.change_key = ?5 AND receipt.announcement_digest = ?6
      AND receipt.channel_id = ?7 AND receipt.slack_ts = ?8 AND receipt.requested_by = ?9
      AND run.plan_hash = ?2 AND run.state = 'completed' AND run.planned_count = 1
      AND run.verified_count = 1 AND run.ambiguous_count = 0
      AND action.action_index = 0 AND action.action_type = ?10 AND action.email = ?11
      AND action.google_user_id = ?12 AND action.state = 'verified' AND action.verified_at_ms IS NOT NULL
    LIMIT 2`)
    .bind(
      receipt.parentPlanHash,
      reviewed.plan.planHash,
      reviewed.sourceFingerprint,
      JSON.stringify(reviewed),
      receipt.changeKey,
      receipt.announcementDigest,
      receipt.channelId,
      receipt.timestamp,
      receipt.requestedBy,
      action.type,
      action.email,
      reviewed.selectedIdentity.googleUserId,
    )
    .all();
  if (rows.results.length === 0) return null;
  if (rows.results.length !== 1)
    throw new Error("trycomp_verified_member_ambiguous");
  return z
    .strictObject({ "member_id": z.string().min(1) })
    .parse(rows.results[0])["member_id"];
}
