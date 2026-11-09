import { z } from "zod";

import { GoogleUserIdSchema } from "../catalog/identity-authority.ts";
import type { IdentityWriteBudget } from "../identity-provisioning/identity-budget-contracts.ts";
import { sameJson } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import {
  assertReviewedLifecycleRemoval,
  type LifecycleRemovalEvidence,
} from "./assert-reviewed-lifecycle-removal.ts";
import type { SlackUserGroupReconciliation } from "./channel-model.ts";
import type { GoogleDirectoryUser } from "./model.ts";

export const ReviewedSlackLifecycleRemovalSchema = z.strictObject({
  googleUserId: GoogleUserIdSchema,
  slackUserGroupId: z.string().regex(/^S[A-Z0-9]+$/u),
  slackUserId: z.string().regex(/^U[A-Z0-9]+$/u),
});
export type ReviewedSlackLifecycleRemoval = z.output<
  typeof ReviewedSlackLifecycleRemovalSchema
>;

export interface ReviewedSlackLifecycleParentContext {
  assertFinalGoogleAuthority(
    users: readonly GoogleDirectoryUser[],
  ): Promise<void>;
  assertFreshPlan(): void;
  assertWriteAuthority(group: SlackUserGroupReconciliation): Promise<void>;
}

export type ReviewedSlackLifecycleDurableParent = Omit<
  ReviewedSlackLifecycleParentContext,
  "assertFinalGoogleAuthority"
>;

export function selectReviewedSlackLifecycleRemoval(
  groups: readonly SlackUserGroupReconciliation[],
  rawReview: ReviewedSlackLifecycleRemoval,
  evidence: LifecycleRemovalEvidence,
): SlackUserGroupReconciliation {
  const reviewed = ReviewedSlackLifecycleRemovalSchema.parse(rawReview);
  const matches = groups.filter(
    ({ slackUserGroupId }) => slackUserGroupId === reviewed.slackUserGroupId,
  );
  const group = matches.length === 1 ? matches[0] : undefined;
  if (group === undefined)
    throw new Error("reviewed_lifecycle_unique_group_required");
  assertReviewedLifecycleRemoval(group, reviewed, evidence);
  const user = evidence.directoryUsers.find(
    ({ id }) => id === reviewed.googleUserId,
  );
  if (
    user?.suspended !== true ||
    user.archived === true ||
    user.deletionTime !== undefined
  )
    throw new Error("reviewed_lifecycle_suspended_authority_required");
  return group;
}

export function createReviewedSlackLifecycleFinalGuard(input: {
  budget: IdentityWriteBudget | undefined;
  capture(): Promise<{
    evidence: LifecycleRemovalEvidence;
    groups: readonly SlackUserGroupReconciliation[];
  }>;
  expected: SlackUserGroupReconciliation;
  parent: ReviewedSlackLifecycleParentContext | undefined;
  reviewed: ReviewedSlackLifecycleRemoval;
}): () => Promise<void> {
  const parent = input.parent;
  if (input.budget?.required !== true || parent === undefined)
    throw new Error("reviewed_lifecycle_signed_parent_required");
  const expected = JsonValueSchema.parse(input.expected);
  const reviewed = ReviewedSlackLifecycleRemovalSchema.parse(input.reviewed);
  return async () => {
    parent.assertFreshPlan();
    await parent.assertWriteAuthority(input.expected);
    const current = await input.capture();
    const selected = selectReviewedSlackLifecycleRemoval(
      current.groups,
      reviewed,
      current.evidence,
    );
    if (!sameJson(expected, JsonValueSchema.parse(selected)))
      throw new Error("reviewed_lifecycle_original_group_changed");
    await parent.assertFinalGoogleAuthority(current.evidence.directoryUsers);
    parent.assertFreshPlan();
  };
}
