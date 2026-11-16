import { z } from "zod";

import { GoogleUserIdSchema } from "../catalog/identity-authority.ts";
import { PosthogIdSchema } from "./posthog-membership-client.ts";

export const PosthogInvitationIdSchema =
  PosthogIdSchema.brand<"PosthogInvitationId">();
export const PosthogUserUuidSchema = PosthogIdSchema.brand<"PosthogUserUuid">();
export const PosthogGrantEvidenceSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("invitation"),
    inviteId: PosthogInvitationIdSchema,
  }),
  z.strictObject({
    kind: z.literal("membership"),
    userUuid: PosthogUserUuidSchema,
  }),
  z.strictObject({
    kind: z.literal("accepted-invitation"),
    inviteId: PosthogInvitationIdSchema,
    userUuid: PosthogUserUuidSchema,
  }),
]);
const Fields = {
  googleUserId: GoogleUserIdSchema,
  email: z.email().toLowerCase(),
  evidence: PosthogGrantEvidenceSchema,
};
/** Current ownership and retained provider evidence; retired evidence never grants removal authority. */
export const PosthogManagedGrantSchema = z.discriminatedUnion("state", [
  z.strictObject({ ...Fields, state: z.literal("managed") }),
  z.strictObject({ ...Fields, state: z.literal("retired") }),
]);
export type PosthogManagedGrant = z.output<typeof PosthogManagedGrantSchema>;
export type PosthogGrantEvidence = z.output<typeof PosthogGrantEvidenceSchema>;
export type PosthogGrantEventFor<G extends PosthogManagedGrant> = G extends {
  state: "managed";
}
  ?
      | { kind: "retire" }
      | (G["evidence"] extends { kind: "membership" | "accepted-invitation" }
          ? never
          : {
              kind: "bind-member";
              userUuid: z.output<typeof PosthogUserUuidSchema>;
            })
  : never;

// Provider mutations/readback and lease checks remain outside this transition.
export function posthogGrantTransition<G extends PosthogManagedGrant>(
  grant: G,
  event: PosthogGrantEventFor<G>,
): PosthogManagedGrant {
  if (grant.state !== "managed")
    throw new Error("posthog_retired_grant_transition");
  switch (event.kind) {
    case "retire":
      return { ...grant, state: "retired" };
    case "bind-member":
      if (grant.evidence.kind !== "invitation")
        throw new Error("posthog_grant_already_bound");
      return PosthogManagedGrantSchema.parse({
        ...grant,
        evidence: {
          kind: "accepted-invitation",
          inviteId: grant.evidence.inviteId,
          userUuid: event.userUuid,
        },
      });
    default:
      return impossiblePosthogState(event);
  }
}

export function posthogInvitationId(
  evidence: PosthogGrantEvidence,
): z.output<typeof PosthogInvitationIdSchema> | null {
  switch (evidence.kind) {
    case "invitation":
    case "accepted-invitation":
      return evidence.inviteId;
    case "membership":
      return null;
    default:
      return impossiblePosthogState(evidence);
  }
}
export function posthogUserUuid(
  evidence: PosthogGrantEvidence,
): z.output<typeof PosthogUserUuidSchema> | null {
  switch (evidence.kind) {
    case "membership":
    case "accepted-invitation":
      return evidence.userUuid;
    case "invitation":
      return null;
    default:
      return impossiblePosthogState(evidence);
  }
}

function impossiblePosthogState(value: never): never {
  throw new Error(`Unexpected PostHog state: ${String(value)}`);
}
