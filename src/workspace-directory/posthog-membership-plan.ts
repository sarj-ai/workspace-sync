import { z } from "zod";

import { GoogleUserIdSchema } from "../catalog/identity-authority.ts";
import { contentHash } from "../github-access-audit/content-hash.ts";
import type { ActiveResourceLease } from "../identity-sync/resource-lease.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import {
  PosthogIdSchema,
  PosthogOriginSchema,
  type PosthogMembershipSnapshot,
} from "./posthog-membership-client.ts";

const EmailSchema = z.email().transform((email) => email.toLowerCase());
export const PosthogManagedGrantSchema = z
  .strictObject({
    googleUserId: GoogleUserIdSchema,
    email: EmailSchema,
    inviteId: PosthogIdSchema.nullable(),
    userUuid: PosthogIdSchema.nullable(),
    state: z.enum(["managed", "retired"]).default("managed"),
  })
  .refine(
    (grant) => grant.inviteId !== null || grant.userUuid !== null,
    "A managed grant requires provider evidence",
  );
export type PosthogManagedGrant = z.output<typeof PosthogManagedGrantSchema>;
export const PosthogMembershipPolicySchema = z.strictObject({
  origin: PosthogOriginSchema,
  organizationId: PosthogIdSchema,
  actorUuid: PosthogIdSchema,
  authorityGroupEmail: EmailSchema,
  authorityGroupId: z.string().min(1),
  minimumGoogleUsers: z.number().int().positive(),
  adoptedGrants: z.array(PosthogManagedGrantSchema).default([]),
});
export type PosthogMembershipPolicy = z.output<
  typeof PosthogMembershipPolicySchema
>;
const ActionBase = { googleUserId: GoogleUserIdSchema, email: EmailSchema };
export const PosthogMembershipActionSchema = z.discriminatedUnion("type", [
  z.strictObject({ ...ActionBase, type: z.literal("invite") }),
  z.strictObject({
    ...ActionBase,
    type: z.literal("cancel-invite"),
    inviteId: PosthogIdSchema,
  }),
  z.strictObject({
    ...ActionBase,
    type: z.literal("remove-member"),
    userUuid: PosthogIdSchema,
  }),
  z.strictObject({ ...ActionBase, type: z.literal("retire-grant") }),
  z.strictObject({
    ...ActionBase,
    type: z.literal("bind-member"),
    userUuid: PosthogIdSchema,
  }),
]);
export type PosthogMembershipAction = z.output<
  typeof PosthogMembershipActionSchema
>;
export interface IPosthogManagedGrantRepository {
  list(organizationId: string): Promise<PosthogManagedGrant[]>;
  record(
    organizationId: string,
    grant: PosthogManagedGrant,
    lease: ActiveResourceLease,
  ): Promise<void>;
}
export interface PosthogMembershipPlan {
  actions: PosthogMembershipAction[];
  blockers: string[];
  planHash: string;
}

// Foreign grants and elevated roles never become removal authority.
interface PosthogMembershipPlanInput {
  policy: PosthogMembershipPolicy;
  desired: readonly { googleUserId: string; email: string }[];
  googleUsers: readonly GoogleDirectoryUser[];
  grants: readonly PosthogManagedGrant[];
  provider: PosthogMembershipSnapshot;
}
type GrantFinding =
  | { kind: "action"; action: PosthogMembershipAction }
  | { kind: "blocker"; code: string }
  | { kind: "none" };
export async function planPosthogMemberships(
  input: PosthogMembershipPlanInput,
): Promise<PosthogMembershipPlan> {
  const { policy, provider } = input;
  if (provider.organizationId !== policy.organizationId)
    throw new Error("posthog_plan_organization_mismatch");
  if (
    new Set(provider.members.map((member) => member.user.email)).size !==
      provider.members.length ||
    new Set(provider.members.map((member) => member.user.uuid)).size !==
      provider.members.length ||
    new Set(provider.invites.map((invite) => invite["target_email"])).size !==
      provider.invites.length ||
    new Set(input.desired.map((person) => person.googleUserId)).size !==
      input.desired.length ||
    new Set(input.desired.map((person) => person.email)).size !==
      input.desired.length
  )
    throw new Error("posthog_identity_collision");
  if (
    provider.invites.some((invite) =>
      provider.members.some(
        (member) => member.user.email === invite["target_email"],
      ),
    )
  )
    throw new Error("posthog_member_invitation_collision");
  const grants = managedGrants(input);
  const findings = [
    ...grants.values().map((grant) => ownedFinding(grant, input)),
    ...desiredFindings(input, grants),
  ];
  const actions = findings
    .flatMap((finding) => (finding.kind === "action" ? [finding.action] : []))
    .toSorted(
      (a, b) => a.email.localeCompare(b.email) || a.type.localeCompare(b.type),
    );
  const blockers = [
    ...new Set(
      findings.flatMap((finding) =>
        finding.kind === "blocker" ? [finding.code] : [],
      ),
    ),
  ].toSorted();
  return {
    actions,
    blockers,
    planHash: await contentHash({
      organizationId: policy.organizationId,
      actions,
      blockers,
    }),
  };
}
function ownedFinding(
  grant: PosthogManagedGrant,
  input: PosthogMembershipPlanInput,
): GrantFinding {
  if (grant.state === "retired") return { kind: "none" };
  const blocker = identityBlocker(grant, input);
  if (blocker !== undefined) return { kind: "blocker", code: blocker };
  const eligible = input.desired.some(
    (person) => person.googleUserId === grant.googleUserId,
  );
  const member = input.provider.members.find(
    (item) => item.user.email === grant.email,
  );
  if (member !== undefined)
    return memberFinding(grant, member, eligible, input.policy.actorUuid);
  const invite = input.provider.invites.find(
    (item) => item["target_email"] === grant.email,
  );
  if (invite !== undefined)
    return inviteFinding(grant, invite, eligible, input.policy.actorUuid);
  return eligible
    ? { kind: "none" }
    : {
        kind: "action",
        action: {
          type: "retire-grant",
          googleUserId: grant.googleUserId,
          email: grant.email,
        },
      };
}
function identityBlocker(
  grant: PosthogManagedGrant,
  input: PosthogMembershipPlanInput,
) {
  const google = input.googleUsers.find(
    (user) => user.id === grant.googleUserId,
  );
  const reassigned = input.googleUsers.some(
    (user) =>
      user.id !== grant.googleUserId &&
      [user.primaryEmail, ...(user.aliases ?? [])].some(
        (email) => email.toLowerCase() === grant.email,
      ),
  );
  if (
    reassigned ||
    (google !== undefined && google.primaryEmail.toLowerCase() !== grant.email)
  )
    return "posthog_managed_identity_changed";
  const member = input.provider.members.find(
    (item) => item.user.email === grant.email,
  );
  const invite = input.provider.invites.find(
    (item) => item["target_email"] === grant.email,
  );
  if (
    member !== undefined &&
    grant.userUuid !== null &&
    member.user.uuid !== grant.userUuid
  )
    return "posthog_managed_provider_identity_changed";
  if (
    invite !== undefined &&
    grant.inviteId !== null &&
    invite.id !== grant.inviteId
  )
    return "posthog_managed_invitation_changed";
  return undefined;
}
function memberFinding(
  grant: PosthogManagedGrant,
  member: PosthogMembershipSnapshot["members"][number],
  eligible: boolean,
  actorUuid: string,
): GrantFinding {
  const identity = {
    googleUserId: grant.googleUserId,
    email: grant.email,
    userUuid: member.user.uuid,
  };
  if (grant.userUuid === null)
    return eligible
      ? { kind: "action", action: { ...identity, type: "bind-member" } }
      : { kind: "blocker", code: "posthog_unbound_member_requires_review" };
  if (eligible) return { kind: "none" };
  if (member.level !== 1 || member.user.uuid === actorUuid)
    return { kind: "blocker", code: "posthog_managed_role_requires_review" };
  return { kind: "action", action: { ...identity, type: "remove-member" } };
}
function inviteFinding(
  grant: PosthogManagedGrant,
  invite: PosthogMembershipSnapshot["invites"][number],
  eligible: boolean,
  actorUuid: string,
): GrantFinding {
  if (eligible && !invite["is_expired"]) return { kind: "none" };
  if (
    invite.level !== 1 ||
    invite["created_by"].uuid !== actorUuid ||
    grant.inviteId !== invite.id
  )
    return {
      kind: "blocker",
      code: "posthog_managed_invitation_requires_review",
    };
  return {
    kind: "action",
    action: {
      type: "cancel-invite",
      googleUserId: grant.googleUserId,
      email: grant.email,
      inviteId: invite.id,
    },
  };
}
function desiredFindings(
  input: PosthogMembershipPlanInput,
  grants: Map<string, PosthogManagedGrant>,
): GrantFinding[] {
  return input.desired.map((person) => {
    const member = input.provider.members.find(
      (item) => item.user.email === person.email,
    );
    if (member !== undefined)
      return member.level < 1
        ? { kind: "blocker", code: "posthog_existing_role_below_required" }
        : { kind: "none" };
    const invite = input.provider.invites.find(
      (item) => item["target_email"] === person.email,
    );
    if (invite === undefined)
      return {
        kind: "action",
        action: PosthogMembershipActionSchema.parse({
          ...person,
          type: "invite",
        }),
      };
    if (
      invite["is_expired"] &&
      grants.get(person.googleUserId)?.state !== "managed"
    )
      return {
        kind: "blocker",
        code: "posthog_foreign_expired_invitation_requires_review",
      };
    return { kind: "none" };
  });
}
function managedGrants(input: PosthogMembershipPlanInput) {
  const grants = new Map<string, PosthogManagedGrant>();
  for (const raw of [...input.policy.adoptedGrants, ...input.grants]) {
    const grant = PosthogManagedGrantSchema.parse(raw);
    const previous = grants.get(grant.googleUserId);
    if (previous !== undefined && previous.email !== grant.email)
      throw new Error("posthog_grant_identity_collision");
    grants.set(grant.googleUserId, grant);
  }
  if (new Set(grants.values().map((grant) => grant.email)).size !== grants.size)
    throw new Error("posthog_grant_email_collision");
  return grants;
}
