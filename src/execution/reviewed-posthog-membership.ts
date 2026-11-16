import { z } from "zod";

import { JsonValueSchema } from "../operations/schemas.ts";
import { PosthogIdSchema } from "../workspace-directory/posthog-membership-client.ts";
import { PosthogMembershipActionSchema } from "../workspace-directory/posthog-membership-plan.ts";

const DigestSchema = z.string().regex(/^[a-f0-9]{64}$/u);
export const ReviewedPosthogMembershipSchema = z.strictObject({
  action: PosthogMembershipActionSchema,
  expectedPlanHash: DigestSchema,
  sourceAuthorityFingerprint: DigestSchema,
  organizationId: PosthogIdSchema,
});
export type ReviewedPosthogMembership = z.output<
  typeof ReviewedPosthogMembershipSchema
>;

export function posthogMembershipSourceIdentity(
  raw: ReviewedPosthogMembership,
) {
  const { action } = ReviewedPosthogMembershipSchema.parse(raw);
  return {
    kind: "identity" as const,
    systemId: "posthog" as const,
    googleUserId: action.googleUserId,
    providerAccountId:
      action.type === "remove-member" || action.type === "bind-member"
        ? action.userUuid
        : action.type === "cancel-invite"
          ? action.inviteId
          : action.email,
  };
}
export function posthogMembershipResourceId(
  raw: ReviewedPosthogMembership,
): string {
  const reviewed = ReviewedPosthogMembershipSchema.parse(raw);
  return `${reviewed.organizationId}:${reviewed.action.googleUserId}`;
}
export function posthogMembershipManagedSlice(
  raw: ReviewedPosthogMembership,
  state: "converged" | "pending",
) {
  const reviewed = ReviewedPosthogMembershipSchema.parse(raw);
  return JsonValueSchema.parse({
    ...posthogMembershipSourceIdentity(reviewed),
    organizationId: reviewed.organizationId,
    actionType: reviewed.action.type,
    state,
  });
}
