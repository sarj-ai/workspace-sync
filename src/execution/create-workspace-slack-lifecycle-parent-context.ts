import { sameJson, sha256Hex } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import type { ReviewedSlackLifecycleDurableParent } from "../org-sync/reviewed-lifecycle-removal.ts";
import {
  WORKSPACE_DIRECTORY_ACTION_IDS,
  type WorkspaceDirectoryPlan,
} from "./contracts.ts";
import {
  createWorkspaceIdentityParentContext,
  type WorkspaceIdentityParentInput,
} from "./create-workspace-identity-parent-context.ts";
import { workspaceDirectorySourceFingerprints } from "./operation.ts";
import {
  ClaimedReviewedSlackLifecycleIntentSchema,
  type IReviewedSlackLifecycleIntentClaims,
  isReviewedPlanWithinOriginalApproval,
} from "./reviewed-slack-lifecycle-intent.ts";

type Input = WorkspaceIdentityParentInput & {
  slackIdentityBudget?: WorkspaceIdentityParentInput["identityBudget"];
  intents: Pick<IReviewedSlackLifecycleIntentClaims, "assertClaimed">;
};

export function createWorkspaceSlackLifecycleParentContext(
  input: Input,
): (plan: WorkspaceDirectoryPlan) => ReviewedSlackLifecycleDurableParent {
  return (plan) => {
    const intent = ClaimedReviewedSlackLifecycleIntentSchema.parse(
      input.params.reviewedSlackLifecycleIntent,
    );
    const branch = plan.branches[2];
    if (
      branch.execution !== "managed" ||
      branch.reviewedLifecycleRemoval === undefined ||
      input.params.scheduledTickId !== intent.claimedTickId ||
      input.params.authorizedActionIds.length !== 1 ||
      !isReviewedPlanWithinOriginalApproval(
        intent.proof,
        input.params.planGeneratedAt,
      ) ||
      !equal(branch.reviewedLifecycleRemoval, intent.proof.reviewed)
    )
      throw new Error("workspace_slack_lifecycle_original_intent_required");
    const parent = createWorkspaceIdentityParentContext(
      {
        ...input,
        ...(!(input.slackIdentityBudget === undefined) && {
          identityBudget: input.slackIdentityBudget,
        }),
      },
      plan,
      "slack-groups-channels",
    );
    const expected = branch.selectedUserGroups[0];
    if (expected === undefined)
      throw new Error("workspace_slack_lifecycle_exact_target_required");
    const assertFreshPlan = () => {
      parent.assertFreshPlan();
      const now = input.now?.() ?? Date.now();
      if (now < intent.proof.generatedAtMs || now >= intent.proof.expiresAtMs)
        throw new Error("workspace_reviewed_lifecycle_intent_expired");
    };
    return {
      assertFreshPlan,
      assertWriteAuthority: async (actual) => {
        assertFreshPlan();
        const withChannelIds = {
          ...actual,
          channelAdditionIds: actual.channelAdditions.map(({ id }) => id),
          channelRemovalIds: actual.channelRemovals.map(({ id }) => id),
        };
        if (
          !equal(
            Object.fromEntries(
              Object.keys(expected).map((key) => [
                key,
                Reflect.get(withChannelIds, key),
              ]),
            ),
            expected,
          )
        )
          throw new Error("workspace_slack_lifecycle_exact_target_changed");
        if (
          (await sha256Hex(JsonValueSchema.parse(branch))) !==
            intent.proof.branchHash ||
          branch.planHash !== intent.proof.leafPlanHash ||
          (await sha256Hex(
            JsonValueSchema.parse(
              workspaceDirectorySourceFingerprints(
                plan,
                new Set([WORKSPACE_DIRECTORY_ACTION_IDS.slackGroupsChannels]),
              ),
            ),
          )) !== intent.proof.sourceHash
        )
          throw new Error(
            "workspace_slack_lifecycle_approved_authority_changed",
          );
        await parent.assertWriteAuthority();
        await input.intents.assertClaimed(intent, intent.claimedTickId);
        assertFreshPlan();
      },
    };
  };
}

function equal(left: unknown, right: unknown) {
  return sameJson(JsonValueSchema.parse(left), JsonValueSchema.parse(right));
}
