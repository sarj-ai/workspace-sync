import type { OperationKernel } from "../operations/kernel.ts";
import { preflightDiagnostic } from "../operations/preflight-diagnostic.ts";
import {
  JsonValueSchema,
  type SignedOperationPlan,
} from "../operations/schemas.ts";
import { logErrorEvent } from "../shared/log-event.ts";
import {
  WorkspaceDirectoryChangeDetailsSchema,
  type WorkspaceDirectoryWorkflowParams,
  WorkspaceDirectoryWorkflowParamsSchema,
} from "./contracts.ts";
import {
  assertReviewedProviderPlanMatches,
  reviewedProviderAdmissionProof,
  reviewedProviderSelection,
} from "./reviewed-provider-admission.ts";
import {
  ClaimedReviewedProviderIntentSchema,
  type IReviewedSlackLifecycleIntentClaims,
} from "./reviewed-slack-lifecycle-intent.ts";

const ACTOR = {
  authorizationScope: "workspace-directory:apply",
  id: "scheduled:workspace-directory",
} as const;

export async function runReviewedSlackLifecycleIntent(input: {
  announcePlan(plan: SignedOperationPlan): Promise<void>;
  intents: IReviewedSlackLifecycleIntentClaims;
  kernel: Pick<OperationKernel, "plan" | "prepareApply">;
  launch(
    params: WorkspaceDirectoryWorkflowParams,
  ): Promise<{ instanceId: string }>;
  observePlan(plan: SignedOperationPlan): Promise<void>;
  tickId: string;
}): Promise<{ kind: "launched"; instanceId: string; planHash: string } | null> {
  const claimed = await input.intents.claim(input.tickId);
  if (claimed === null) return null;
  const intent = ClaimedReviewedProviderIntentSchema.parse(claimed);
  const selection = reviewedProviderSelection(intent.proof);
  const assertOriginal = () =>
    input.intents.assertClaimed(intent, input.tickId);
  await assertOriginal();
  const signed = await input.kernel.plan({
    actor: ACTOR,
    environment: "production",
    operation: "workspace-directory.reconcile",
    input: JsonValueSchema.parse(selection.input),
  });
  await assertReviewedProviderPlanMatches(intent.proof, signed.plan);
  await assertOriginal();
  await input.observePlan(signed);
  await assertOriginal();
  await input.announcePlan(signed);
  await assertOriginal();
  const prepared = await input.kernel.prepareApply(
    {
      confirmPlanHash: signed.plan.planHash,
      expectedActionIds: [selection.actionId],
      confirmations: selection.confirmations,
      riskAcknowledged: true,
      signedPlan: signed,
    },
    { actor: ACTOR, environment: "production" },
  );
  if (!prepared.ok) {
    logErrorEvent(
      "workspace_directory.scheduled_preflight_rejected",
      preflightDiagnostic(prepared),
    );
    throw new Error("workspace_reviewed_lifecycle_scheduled_apply_rejected");
  }
  await reviewedProviderAdmissionProof(prepared);
  await assertReviewedProviderPlanMatches(intent.proof, prepared.plan);
  await assertOriginal();
  const change = prepared.pending[0];
  if (change === undefined)
    throw new Error("workspace_reviewed_lifecycle_scheduled_action_missing");
  const details = WorkspaceDirectoryChangeDetailsSchema.parse(change.details);
  if (
    (details.kind !== "slack-groups-channels" &&
      details.kind !== "linear-suspensions" &&
      details.kind !== "google-group-cleanup") ||
    details.plan === undefined
  )
    throw new Error("workspace_reviewed_lifecycle_scheduled_action_missing");
  const params = WorkspaceDirectoryWorkflowParamsSchema.parse({
    authorizedActionIds: [selection.actionId],
    plan: details.plan,
    planGeneratedAt: signed.plan.generatedAt,
    planHash: signed.plan.planHash,
    requestedBy: ACTOR.id,
    ...("provider" in intent.proof
      ? { reviewedProviderIntent: intent }
      : { reviewedSlackLifecycleIntent: intent }),
    scheduledTickId: input.tickId,
  });
  await assertOriginal();
  const accepted = await input.launch(params);
  return {
    kind: "launched",
    instanceId: accepted.instanceId,
    planHash: signed.plan.planHash,
  };
}
