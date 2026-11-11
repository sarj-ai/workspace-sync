import { z } from "zod";

import { JsonValueSchema } from "../operations/schemas.ts";
import { PagerDutyTeamWritableActionSchema } from "../workspace-directory/pagerduty-team-sync.ts";

export const ReviewedPagerDutyTeamSchema = z.strictObject({
  action: PagerDutyTeamWritableActionSchema,
  expectedPlanHash: z.string().regex(/^[a-f0-9]{64}$/u),
  reviewId: z.uuid(),
});
export type ReviewedPagerDutyTeam = z.output<
  typeof ReviewedPagerDutyTeamSchema
>;

export function pagerDutyTeamManagedSlice(
  reviewed: ReviewedPagerDutyTeam,
  state: "converged" | "pending",
) {
  const { action } = ReviewedPagerDutyTeamSchema.parse(reviewed);
  return JsonValueSchema.parse({
    googleGroupId: action.googleGroupId,
    googleUserId: action.googleUserId,
    email: action.email,
    pagerDutyTeamId: action.pagerDutyTeamId,
    pagerDutyUserId: action.pagerDutyUserId,
    role:
      state === "converged"
        ? action.desiredPagerDutyRole
        : action.type === "add"
          ? null
          : action.currentPagerDutyRole,
  });
}

export function pagerDutyTeamSourceIdentity(reviewed: ReviewedPagerDutyTeam) {
  const { action } = ReviewedPagerDutyTeamSchema.parse(reviewed);
  return {
    kind: "identity" as const,
    systemId: "pagerduty" as const,
    googleUserId: action.googleUserId,
    providerAccountId: action.pagerDutyUserId,
  };
}

export function pagerDutyTeamResourceId(
  reviewed: ReviewedPagerDutyTeam,
): string {
  const { action } = ReviewedPagerDutyTeamSchema.parse(reviewed);
  return `${action.pagerDutyTeamId}:${action.pagerDutyUserId}`;
}
