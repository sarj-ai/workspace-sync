import { sameJson, sha256Hex } from "../operations/canonical.ts";
import type { PreparedOperationApply } from "../operations/kernel.ts";
import {
  JsonValueSchema,
  type OperationPlanEnvelope,
} from "../operations/schemas.ts";
import {
  WORKSPACE_DIRECTORY_ACTION_IDS,
  WorkspaceDirectoryChangeDetailsSchema,
  WorkspaceDirectoryOperationInputSchema,
} from "./contracts.ts";
import {
  type ReviewedSlackLifecycleIntentProof,
  ReviewedSlackLifecycleIntentProofSchema,
} from "./reviewed-slack-lifecycle-intent.ts";

const ACTION = WORKSPACE_DIRECTORY_ACTION_IDS.slackGroupsChannels;
const ORIGINAL_REQUIRED = "workspace_reviewed_lifecycle_original_plan_required";

export async function reviewedSlackLifecycleAdmissionProof(
  prepared: Pick<
    Extract<PreparedOperationApply, { ok: true }>,
    "pending" | "plan"
  >,
): Promise<ReviewedSlackLifecycleIntentProof> {
  if (
    prepared.pending.length !== 1 ||
    !sameJson(
      JsonValueSchema.parse(prepared.pending),
      JsonValueSchema.parse(prepared.plan.changes),
    )
  )
    throw new Error(ORIGINAL_REQUIRED);
  const evidence = await reviewedPlanEvidence(prepared.plan);
  return ReviewedSlackLifecycleIntentProofSchema.parse({
    ...evidence,
    actorHash: await sha256Hex(JsonValueSchema.parse(prepared.plan.actor)),
    originalPlanHash: prepared.plan.planHash,
    generatedAtMs: Date.parse(prepared.plan.generatedAt),
    expiresAtMs: Math.min(
      Date.parse(prepared.plan.expiresAt),
      Date.parse(prepared.plan.generatedAt) + 600_000,
    ),
  });
}

export async function assertReviewedSlackLifecyclePlanMatches(
  proof: ReviewedSlackLifecycleIntentProof,
  plan: OperationPlanEnvelope,
): Promise<void> {
  const evidence = await reviewedPlanEvidence(plan);
  if (
    !sameJson(
      JsonValueSchema.parse(evidence),
      JsonValueSchema.parse({
        branchHash: proof.branchHash,
        leafPlanHash: proof.leafPlanHash,
        reviewed: proof.reviewed,
        sourceHash: proof.sourceHash,
      }),
    )
  )
    throw new Error("workspace_reviewed_lifecycle_approved_authority_changed");
}

async function reviewedPlanEvidence(plan: OperationPlanEnvelope) {
  const input = WorkspaceDirectoryOperationInputSchema.parse(plan.input);
  const reviewed =
    "reviewedSlackLifecycleRemoval" in input
      ? input.reviewedSlackLifecycleRemoval
      : undefined;
  const change = plan.changes.length === 1 ? plan.changes[0] : undefined;
  if (
    !plan.applicable ||
    !plan.applyAuthorized ||
    plan.operation !== "workspace-directory.reconcile" ||
    reviewed === undefined ||
    change?.actionId !== ACTION ||
    change.kind !== "remove" ||
    change.risk !== "high" ||
    change.resource.type !== "slack-access" ||
    change.resource.id !== reviewed.slackUserId
  )
    throw new Error(ORIGINAL_REQUIRED);
  const details = WorkspaceDirectoryChangeDetailsSchema.parse(change.details);
  if (details.kind !== "slack-groups-channels")
    throw new Error(ORIGINAL_REQUIRED);
  const branch = details.plan.branches[2];
  if (
    branch.execution !== "managed" ||
    branch.selectedIdentity?.googleUserId !== reviewed.googleUserId ||
    branch.selectedIdentity.slackUserId !== reviewed.slackUserId ||
    !sameJson(
      JsonValueSchema.parse(branch.reviewedLifecycleRemoval),
      JsonValueSchema.parse(reviewed),
    )
  )
    throw new Error(ORIGINAL_REQUIRED);
  return {
    branchHash: await sha256Hex(JsonValueSchema.parse(branch)),
    leafPlanHash: branch.planHash,
    reviewed,
    sourceHash: await sha256Hex(JsonValueSchema.parse(plan.sourceFingerprints)),
  };
}
