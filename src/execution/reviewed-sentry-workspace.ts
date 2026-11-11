import { z } from "zod";

import { GoogleUserIdSchema } from "../catalog/identity-authority.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import { SentryWorkspaceActionSchema } from "../workspace-directory/sentry-workspace-sync.ts";
import { SentryWorkspaceAuthorityPinsSchema } from "./sentry-workspace-authority-pins.ts";

const Sha256Schema = z.string().regex(/^[a-f0-9]{64}$/u);
export const ReviewedSentryWorkspaceSchema = z.strictObject({
  action: SentryWorkspaceActionSchema,
  authorityPins: SentryWorkspaceAuthorityPinsSchema,
  expectedPlanHash: Sha256Schema,
  googleUserId: GoogleUserIdSchema,
  sourceAuthorityFingerprint: Sha256Schema,
});
export type ReviewedSentryWorkspace = z.output<
  typeof ReviewedSentryWorkspaceSchema
>;

export function sentryWorkspaceSourceIdentity(raw: ReviewedSentryWorkspace) {
  const reviewed = ReviewedSentryWorkspaceSchema.parse(raw);
  return {
    googleUserId: reviewed.googleUserId,
    kind: "identity" as const,
    providerAccountId: sentryProviderIdentity(reviewed.action),
    systemId: "sentry" as const,
  };
}

export function sentryWorkspaceManagedSlice(
  raw: ReviewedSentryWorkspace,
  state: "converged" | "pending",
) {
  const reviewed = ReviewedSentryWorkspaceSchema.parse(raw);
  return JsonValueSchema.parse({
    ...sentryWorkspaceSourceIdentity(reviewed),
    actionType: reviewed.action.type,
    organizationId: reviewed.authorityPins.organization.id,
    projectId: reviewed.authorityPins.project.id,
    state,
    teamId: reviewed.authorityPins.team.id,
  });
}

export function sentryWorkspaceResourceId(
  raw: ReviewedSentryWorkspace,
): string {
  const reviewed = ReviewedSentryWorkspaceSchema.parse(raw);
  return `${reviewed.authorityPins.organization.id}:${reviewed.authorityPins.team.id}:${sentryProviderIdentity(reviewed.action)}`;
}

function sentryProviderIdentity(
  action: z.output<typeof SentryWorkspaceActionSchema>,
): string {
  return "memberId" in action ? action.memberId : action.email;
}
