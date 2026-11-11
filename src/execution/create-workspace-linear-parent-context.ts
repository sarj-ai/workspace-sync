import type { LinearSuspensionParentContext } from "../access-guard/provider.ts";
import type { IdentityWriteBudget } from "../identity-provisioning/identity-budget-contracts.ts";
import { sameJson } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import type { WorkspaceDirectoryPlan } from "./contracts.ts";
import {
  createWorkspaceIdentityParentContext,
  type WorkspaceIdentityParentInput,
} from "./create-workspace-identity-parent-context.ts";
import { assertReviewedLinearIntentPlan } from "./reviewed-provider-admission.ts";
import {
  ClaimedReviewedProviderIntentSchema,
  type IReviewedProviderIntentClaims,
  isReviewedPlanWithinOriginalApproval,
} from "./reviewed-slack-lifecycle-intent.ts";

type Input = Omit<WorkspaceIdentityParentInput, "identityBudget"> & {
  linearIdentityBudget?: IdentityWriteBudget;
  intents?: Pick<IReviewedProviderIntentClaims, "assertClaimed">;
};
const ORIGINAL_INTENT_REQUIRED = "workspace_linear_original_intent_required";

export function createWorkspaceLinearParentContext(
  input: Input,
): (plan: WorkspaceDirectoryPlan) => LinearSuspensionParentContext {
  return (plan) => {
    const branch = input.params.plan.branches[4];
    if (branch.execution !== "managed" || branch.plan.actions.length !== 1)
      throw new Error("workspace_linear_signed_parent_required");
    const reviewed = branch.plan.actions[0];
    if (reviewed === undefined)
      throw new Error("workspace_linear_signed_target_required");
    const parent = createWorkspaceIdentityParentContext(
      {
        ...input,
        ...(!(input.linearIdentityBudget === undefined) && {
          identityBudget: input.linearIdentityBudget,
        }),
        now: () => input.now?.() ?? Date.now(),
      },
      plan,
      "access-guard",
    );
    const intent =
      branch.reviewedLinearSuspension === undefined
        ? undefined
        : ClaimedReviewedProviderIntentSchema.parse(
            input.params.reviewedProviderIntent,
          );
    if (
      (branch.reviewedLinearSuspension === undefined) !==
      (input.params.reviewedProviderIntent === undefined)
    )
      throw new Error(ORIGINAL_INTENT_REQUIRED);
    if (
      intent !== undefined &&
      (!("provider" in intent.proof) ||
        input.intents === undefined ||
        input.params.authorizedActionIds.length !== 1 ||
        intent.claimedTickId !== input.params.scheduledTickId ||
        !isReviewedPlanWithinOriginalApproval(
          intent.proof,
          input.params.planGeneratedAt,
        ))
    )
      throw new Error(ORIGINAL_INTENT_REQUIRED);
    const assertFreshPlan = () => {
      parent.assertFreshPlan();
      if (intent === undefined) return;
      const now = input.now?.() ?? Date.now();
      if (now < intent.proof.generatedAtMs || now >= intent.proof.expiresAtMs)
        throw new Error("workspace_reviewed_lifecycle_intent_expired");
    };
    return {
      assertFreshPlan,
      assertWriteAuthority: async (actual) => {
        if (
          !sameJson(
            JsonValueSchema.parse(target(actual)),
            JsonValueSchema.parse(target(reviewed)),
          )
        )
          throw new Error("workspace_linear_signed_target_mismatch");
        assertFreshPlan();
        if (intent !== undefined)
          await assertReviewedLinearIntentPlan(intent.proof, plan);
        await parent.assertWriteAuthority();
        if (intent !== undefined) {
          if (input.intents === undefined)
            throw new Error(ORIGINAL_INTENT_REQUIRED);
          await input.intents.assertClaimed(intent, intent.claimedTickId);
        }
        assertFreshPlan();
      },
    };
  };
}

function target(
  action: Parameters<LinearSuspensionParentContext["assertWriteAuthority"]>[0],
) {
  return {
    accountId: action.accountId,
    email: action.email,
    googleUserId: action.googleUserId,
  };
}
