import { z } from "zod";

import { JsonValueSchema } from "../operations/schemas.ts";
import { GoogleGroupCleanupActionSchema } from "../workspace-directory/google-group-cleanup-sync.ts";

export const ReviewedGoogleGroupCleanupSchema = z
  .strictObject({
    action: GoogleGroupCleanupActionSchema,
    expectedPlanHash: z.string().regex(/^[a-f0-9]{64}$/u),
  })
  .refine(
    ({ action }) => action.googleUserId === action.memberId,
    "original Google identity must equal direct member identity",
  );
export type ReviewedGoogleGroupCleanup = z.output<
  typeof ReviewedGoogleGroupCleanupSchema
>;

/** Reviewed intents pin an explicit, JSON-safe authority identity. */
export const ReviewedGoogleGroupCleanupIntentSchema =
  ReviewedGoogleGroupCleanupSchema.transform((reviewed) => {
    const { role, ...action } = reviewed.action;
    const identity = {
      ...action,
      authorityEmail: action.authorityEmail ?? action.memberEmail,
    };
    return {
      ...reviewed,
      action: role === undefined ? identity : { ...identity, role },
    };
  });
export type ReviewedGoogleGroupCleanupIntent = z.output<
  typeof ReviewedGoogleGroupCleanupIntentSchema
>;

export function googleGroupCleanupManagedSlice(
  reviewed: ReviewedGoogleGroupCleanup,
  state: "converged" | "pending",
) {
  const { action } = ReviewedGoogleGroupCleanupSchema.parse(reviewed);
  return JsonValueSchema.parse({
    googleGroupId: action.googleGroupId,
    googleGroupEmail: action.googleGroupEmail,
    googleUserId: action.googleUserId,
    memberId: action.memberId,
    memberEmail: action.memberEmail,
    lifecycle: action.lifecycle,
    authorityEmail: action.authorityEmail ?? null,
    membership:
      state === "pending"
        ? { type: "USER", role: action.role ?? "MEMBER" }
        : null,
  });
}

export function googleGroupCleanupSourceIdentity(
  reviewed: ReviewedGoogleGroupCleanup,
) {
  const { action } = ReviewedGoogleGroupCleanupSchema.parse(reviewed);
  return {
    kind: "identity" as const,
    systemId: "google-workspace" as const,
    googleUserId: action.googleUserId,
    providerAccountId: action.memberId,
  };
}

export function googleGroupCleanupResourceId(
  reviewed: ReviewedGoogleGroupCleanup,
): string {
  const { action } = ReviewedGoogleGroupCleanupSchema.parse(reviewed);
  return `${action.googleGroupId}:${action.memberId}`;
}
