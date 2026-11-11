import { z } from "zod";

import type { AccessGuardPlan } from "../access-guard/model.ts";
import { GoogleUserIdSchema } from "../catalog/identity-authority.ts";
import { getWorkspaceExecutionPolicy } from "./get-workspace-execution-policy.ts";

export const ReviewedLinearSuspensionSchema = z.strictObject({
  accountId: z.string().trim().min(1),
  email: z.email().toLowerCase(),
  googleUserId: GoogleUserIdSchema,
  organizationId: z.uuid(),
  organizationUrlKey: z.string().trim().min(1),
});
export type ReviewedLinearSuspension = z.output<
  typeof ReviewedLinearSuspensionSchema
>;

export function selectReviewedLinearSuspension(
  plan: AccessGuardPlan,
  raw: ReviewedLinearSuspension,
): AccessGuardPlan {
  const reviewed = ReviewedLinearSuspensionSchema.parse(raw);
  if (
    reviewed.organizationId !==
      getWorkspaceExecutionPolicy().accessGuard.expectedLinearOrganizationId ||
    reviewed.organizationUrlKey !==
      getWorkspaceExecutionPolicy().accessGuard.expectedLinearOrganizationUrlKey
  )
    throw new Error("reviewed_linear_tenant_changed");
  const selected = plan.actions.filter(
    (action) =>
      action.googleUserId === reviewed.googleUserId &&
      action.accountId === reviewed.accountId &&
      action.email === reviewed.email,
  );
  if (selected.length !== 1)
    throw new Error("reviewed_linear_exact_action_required");
  return { ...plan, actions: selected };
}
