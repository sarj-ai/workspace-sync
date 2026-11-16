import type { z } from "zod";

import type { EmployeeEntitlementAuthority } from "../identity-provisioning/employee-entitlement-policy.ts";
import { reserveIdentityWriteBudget } from "../identity-provisioning/identity-budget-contracts.ts";
import {
  resourceLeaseKey,
  withResourceLease,
  type ResourceLeaseRepository,
  type ActiveResourceLease,
} from "../identity-sync/resource-lease.ts";
import { sameJson } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import type { IGoogleDirectoryClient } from "../org-sync/google-directory-client.ts";
import type { IGoogleGroupsClient } from "../org-sync/google-groups-client.ts";
import {
  PosthogManagedGrantSchema,
  posthogGrantTransition,
  posthogInvitationId,
  posthogUserUuid,
  PosthogUserUuidSchema,
} from "../workspace-directory/posthog-managed-grant.ts";
import type {
  IPosthogMembershipClient,
  PosthogMembershipSnapshot,
} from "../workspace-directory/posthog-membership-client.ts";
import {
  planPosthogMemberships,
  PosthogMembershipPolicySchema,
  type IPosthogManagedGrantRepository,
  type PosthogManagedGrant,
  type PosthogMembershipAction,
  type PosthogMembershipPlan,
} from "../workspace-directory/posthog-membership-plan.ts";
import { capturePosthogGoogleAuthority } from "./capture-posthog-google-authority.ts";
import type {
  ReviewedActionContext,
  ReviewedActionState,
} from "./reviewed-action-context.ts";
import {
  ReviewedPosthogMembershipSchema,
  type ReviewedPosthogMembership,
} from "./reviewed-posthog-membership.ts";

export interface PosthogMembershipParent extends ReviewedActionContext<PosthogMembershipAction> {
  assertFinalSourceAuthority(): Promise<void>;
}
export interface PosthogMembershipServiceDependencies {
  directory: Pick<IGoogleDirectoryClient, "listAllUsers">;
  groups: Pick<IGoogleGroupsClient, "listGroups">;
  employeeAuthority(): Promise<EmployeeEntitlementAuthority>;
  provider: IPosthogMembershipClient;
  grants: IPosthogManagedGrantRepository;
  leases: ResourceLeaseRepository;
}
const LEASE_MS = 10 * 60 * 1000;
const MIN_HEADROOM_MS = 60 * 1000;

/** One selected membership change per signed parent, with fresh source and target evidence. */
export interface PosthogMembershipAudit {
  plan: PosthogMembershipPlan;
  sourceAuthorityFingerprint: string;
  provider: PosthogMembershipSnapshot;
  storedGrants: PosthogManagedGrant[];
  desired: { googleUserId: string; email: string }[];
}
export interface PosthogMembershipExecutionPort {
  capture(): Promise<PosthogMembershipAudit>;
  readReviewed(
    reviewed: ReviewedPosthogMembership,
  ): Promise<ReviewedActionState>;
  applyReviewed(
    reviewed: ReviewedPosthogMembership,
    parent: PosthogMembershipParent,
  ): Promise<"busy" | "completed">;
}
export class PosthogMembershipService implements PosthogMembershipExecutionPort {
  readonly #policy: z.output<typeof PosthogMembershipPolicySchema>;
  readonly #executionMode: "audit-only" | "parent";
  readonly #ports: PosthogMembershipServiceDependencies;

  constructor(
    policy: z.input<typeof PosthogMembershipPolicySchema>,
    dependencies: PosthogMembershipServiceDependencies,
    executionMode: "audit-only" | "parent" = "audit-only",
  ) {
    this.#executionMode = executionMode;
    this.#policy = PosthogMembershipPolicySchema.parse(policy);
    this.#ports = dependencies;
  }

  async capture() {
    const runId = crypto.randomUUID();
    const deadlineAt = Date.now() + 60_000;
    const [users, groups, employeeAuthority, provider, storedGrants] =
      await Promise.all([
        this.#ports.directory.listAllUsers(runId, deadlineAt),
        this.#ports.groups.listGroups(
          [this.#policy.authorityGroupEmail],
          runId,
          deadlineAt,
          true,
          true,
        ),
        this.#ports.employeeAuthority(),
        this.#ports.provider.read(),
        this.#ports.grants.list(this.#policy.organizationId),
      ]);
    if (
      provider.actorUuid !== this.#policy.actorUuid ||
      !provider.members.some(
        (member) =>
          member.user.uuid === this.#policy.actorUuid &&
          (member.level === 8 || member.level === 15),
      )
    )
      throw new Error("posthog_actor_authority_mismatch");
    const { desired, sourceAuthorityFingerprint } =
      await capturePosthogGoogleAuthority(
        this.#policy,
        users,
        groups,
        employeeAuthority,
      );
    const plan = await planPosthogMemberships({
      policy: this.#policy,
      desired,
      googleUsers: users,
      grants: storedGrants,
      provider,
    });
    return {
      plan,
      sourceAuthorityFingerprint,
      provider,
      storedGrants,
      desired,
    };
  }

  async readReviewed(
    raw: ReviewedPosthogMembership,
  ): Promise<ReviewedActionState> {
    const reviewed = ReviewedPosthogMembershipSchema.parse(raw);
    if (reviewed.organizationId !== this.#policy.organizationId)
      return "drifted";
    const current = await this.capture();
    if (
      current.sourceAuthorityFingerprint !== reviewed.sourceAuthorityFingerprint
    )
      return "drifted";
    return this.#converged(reviewed.action, current) ? "converged" : "pending";
  }

  async applyReviewed(
    raw: ReviewedPosthogMembership,
    parent: PosthogMembershipParent,
  ): Promise<"busy" | "completed"> {
    const reviewed = ReviewedPosthogMembershipSchema.parse(raw);
    if (
      this.#executionMode !== "parent" ||
      !parent.identityBudget.required ||
      reviewed.organizationId !== this.#policy.organizationId
    )
      throw new Error("posthog_signed_parent_required");
    await parent.verifyPreannouncement({
      action: reviewed.action,
      expectedPlanHash: reviewed.expectedPlanHash,
    });
    const result = await withResourceLease(
      this.#ports.leases,
      resourceLeaseKey(
        `workspace-directory/posthog/${this.#policy.organizationId}`,
      ),
      LEASE_MS,
      async (lease) => {
        const current = await this.capture();
        if (
          current.sourceAuthorityFingerprint ===
            reviewed.sourceAuthorityFingerprint &&
          this.#converged(reviewed.action, current)
        )
          return;
        this.#assertOriginal(reviewed, current);
        await reserveIdentityWriteBudget(
          parent.identityBudget,
          reviewed.action.googleUserId,
        );
        await this.#ports.leases.assertActive(lease, MIN_HEADROOM_MS);
        await parent.assertWriteAuthority();
        await parent.assertFinalSourceAuthority();
        const final = await this.capture();
        this.#assertOriginal(reviewed, final);
        await this.#ports.leases.assertActive(lease, MIN_HEADROOM_MS);
        parent.assertFreshPlan();
        const action = reviewed.action;
        if (action.type === "invite") {
          const invite = await this.#ports.provider.invite(action.email);
          if (invite["created_by"].uuid !== this.#policy.actorUuid)
            throw new Error("posthog_inviter_authority_mismatch");
          await this.#ports.leases.assertActive(lease);
          await this.#ports.grants.record(
            this.#policy.organizationId,
            PosthogManagedGrantSchema.parse({
              googleUserId: action.googleUserId,
              email: action.email,
              evidence: { kind: "invitation", inviteId: invite.id },
              state: "managed",
            }),
            lease,
          );
        } else {
          await this.#applyOwnedAction(action, final.storedGrants, lease);
        }
        const observed = await this.capture();
        if (
          observed.sourceAuthorityFingerprint !==
            reviewed.sourceAuthorityFingerprint ||
          !this.#converged(action, observed)
        )
          throw new Error("posthog_membership_readback_failed");
        await this.#ports.leases.assertActive(lease);
      },
    );
    return result.kind === "busy" ? "busy" : "completed";
  }

  async #applyOwnedAction(
    action: Exclude<PosthogMembershipAction, { type: "invite" }>,
    stored: PosthogManagedGrant[],
    lease: ActiveResourceLease,
  ): Promise<void> {
    if (action.type === "cancel-invite")
      await this.#ports.provider.cancelInvite(action.inviteId);
    if (action.type === "remove-member")
      await this.#ports.provider.removeMember(action.userUuid);
    const readback = await this.#ports.provider.read();
    if (!ownedMutationObserved(action, readback))
      throw new Error("posthog_membership_readback_failed");
    await this.#ports.leases.assertActive(lease);
    const grant = this.#ownedGrant(action.googleUserId, stored);
    if (grant === undefined) throw new Error("posthog_managed_grant_missing");
    if (grant.state !== "managed")
      throw new Error("posthog_retired_grant_transition");
    const updated =
      action.type === "bind-member"
        ? posthogGrantTransition(grant, {
            kind: "bind-member",
            userUuid: PosthogUserUuidSchema.parse(action.userUuid),
          })
        : posthogGrantTransition(grant, { kind: "retire" });
    await this.#ports.grants.record(
      this.#policy.organizationId,
      updated,
      lease,
    );
  }

  #assertOriginal(
    reviewed: ReviewedPosthogMembership,
    current: Awaited<ReturnType<PosthogMembershipService["capture"]>>,
  ): void {
    if (
      current.plan.blockers.length > 0 ||
      current.sourceAuthorityFingerprint !==
        reviewed.sourceAuthorityFingerprint ||
      current.plan.planHash !== reviewed.expectedPlanHash ||
      !current.plan.actions.some((action) =>
        sameJson(
          JsonValueSchema.parse(action),
          JsonValueSchema.parse(reviewed.action),
        ),
      )
    )
      throw new Error("posthog_reviewed_plan_drifted");
  }

  #ownedGrant(
    googleUserId: string,
    stored: PosthogManagedGrant[],
  ): PosthogManagedGrant | undefined {
    return (
      stored.find((grant) => grant.googleUserId === googleUserId) ??
      this.#policy.adoptedGrants.find(
        (grant) => grant.googleUserId === googleUserId,
      )
    );
  }

  #converged(
    action: PosthogMembershipAction,
    current: Awaited<ReturnType<PosthogMembershipService["capture"]>>,
  ): boolean {
    const grant = this.#ownedGrant(action.googleUserId, current.storedGrants);
    const member = current.provider.members.find(
      (item) => item.user.email === action.email,
    );
    const invite = current.provider.invites.find(
      (item) => item["target_email"] === action.email,
    );
    switch (action.type) {
      case "bind-member":
        return (
          grant?.state === "managed" &&
          posthogUserUuid(grant.evidence) === action.userUuid &&
          member?.user.uuid === action.userUuid
        );
      case "invite":
        return (
          grant?.state === "managed" &&
          ((member !== undefined && member.level >= 1) ||
            (invite !== undefined &&
              !invite["is_expired"] &&
              invite.level === 1 &&
              invite.id === posthogInvitationId(grant.evidence)))
        );
      case "remove-member":
        return grant?.state === "retired" && member === undefined;
      case "cancel-invite":
        return grant?.state === "retired" && invite === undefined;
      case "retire-grant":
        return (
          grant?.state === "retired" &&
          member === undefined &&
          invite === undefined
        );
      default:
        return impossiblePosthogAction(action);
    }
  }
}

function ownedMutationObserved(
  action: Exclude<PosthogMembershipAction, { type: "invite" }>,
  provider: PosthogMembershipSnapshot,
) {
  const member = provider.members.find(
    (item) => item.user.email === action.email,
  );
  const invite = provider.invites.find(
    (item) => item["target_email"] === action.email,
  );
  switch (action.type) {
    case "remove-member":
      return (
        member === undefined &&
        !provider.members.some((item) => item.user.uuid === action.userUuid)
      );
    case "cancel-invite":
      return (
        invite === undefined &&
        !provider.invites.some((item) => item.id === action.inviteId)
      );
    case "retire-grant":
      return member === undefined && invite === undefined;
    case "bind-member":
      return (
        member?.user.uuid === action.userUuid &&
        member.level >= 1 &&
        invite === undefined
      );
  }
}

function impossiblePosthogAction(value: never): never {
  throw new Error(`Unexpected PostHog action: ${String(value)}`);
}
