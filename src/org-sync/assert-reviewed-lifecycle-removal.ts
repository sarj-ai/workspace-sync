import {
  type EmployeeEntitlementAuthority,
  hasCompleteEmployeeEntitlementAuthority,
  isEmployeeEntitlementExcluded,
} from "../identity-provisioning/employee-entitlement-policy.ts";
import { normalizeIdentityEmail } from "../identity-sync/normalize-identity-email.ts";
import type { SlackUserGroupReconciliation } from "./channel-model.ts";
import { orgSyncSettings } from "./config.ts";
import { assertUnprivilegedSlackMembershipIdentities } from "./create-slack-membership-budget-guard.ts";
import type { GoogleDirectoryUser, SlackMember } from "./model.ts";

export interface ReviewedLifecycleRemoval {
  readonly googleUserId: string;
  readonly slackUserGroupId: string;
  readonly slackUserId: string;
}

export interface LifecycleRemovalEvidence {
  readonly contractorAuthority: EmployeeEntitlementAuthority;
  readonly directoryUsers: readonly GoogleDirectoryUser[];
  readonly protectedSlackUserIds: readonly string[];
  readonly slackMembers: readonly SlackMember[];
}

export function assertReviewedLifecycleRemoval(
  group: SlackUserGroupReconciliation,
  reviewed: ReviewedLifecycleRemoval,
  evidence: LifecycleRemovalEvidence,
): void {
  assertExactRemoval(group, reviewed);
  assertAdoptedGroup(group);
  const user = assertReviewedLifecycleIdentity(reviewed, evidence);
  if (
    ![
      user.primaryEmail,
      ...(user.aliases ?? []),
      ...(user.nonEditableAliases ?? []),
    ]
      .map(normalizeIdentityEmail)
      .includes(normalizeIdentityEmail(group.memberRemovals[0]?.identity ?? ""))
  )
    throw new Error("reviewed_lifecycle_identity_changed");
}

export function assertReviewedLifecycleIdentity(
  reviewed: ReviewedLifecycleRemoval,
  evidence: LifecycleRemovalEvidence,
): GoogleDirectoryUser {
  const identities = assertUnprivilegedSlackMembershipIdentities(
    evidence,
    [reviewed.slackUserId],
    evidence.protectedSlackUserIds,
  );
  if (identities.get(reviewed.slackUserId) !== reviewed.googleUserId)
    throw new Error("reviewed_lifecycle_identity_changed");
  const user = evidence.directoryUsers.find(
    ({ id }) => id === reviewed.googleUserId,
  );
  if (
    user === undefined ||
    orgSyncSettings().protectedDepartedGoogleUserIds.includes(user.id) ||
    (user.suspended !== true &&
      user.archived !== true &&
      user.deletionTime === undefined)
  )
    throw new Error("reviewed_lifecycle_inactive_authority_required");
  if (
    !hasCompleteEmployeeEntitlementAuthority(evidence.contractorAuthority) ||
    isEmployeeEntitlementExcluded(
      user.primaryEmail,
      user.id,
      evidence.contractorAuthority,
      [...(user.aliases ?? []), ...(user.nonEditableAliases ?? [])],
    )
  )
    throw new Error("reviewed_lifecycle_noncontractor_authority_required");
  return user;
}

function assertExactRemoval(
  group: SlackUserGroupReconciliation,
  reviewed: ReviewedLifecycleRemoval,
): void {
  if (
    group.status !== "update" ||
    group.memberRemovalAuthority !== "explicit_google_lifecycle" ||
    group.slackUserGroupId !== reviewed.slackUserGroupId ||
    !/^S[A-Z0-9]+$/u.test(reviewed.slackUserGroupId) ||
    !/^U[A-Z0-9]+$/u.test(reviewed.slackUserId) ||
    group.memberRemovals.length !== 1 ||
    group.memberRemovals[0]?.slackUserId !== reviewed.slackUserId ||
    group.desiredUserIds.length === 0 ||
    group.desiredUserIds.includes(reviewed.slackUserId) ||
    group.memberAdditions.length !== 0 ||
    group.effectiveAccessAdditions.length !== 0 ||
    group.channelAdditions.length !== 0 ||
    group.channelRemovals.length !== 0
  )
    throw new Error("reviewed_lifecycle_exact_removal_required");
}

function assertAdoptedGroup(group: SlackUserGroupReconciliation): void {
  const ownership = group.automationOwnership;
  if (
    ownership.kind !== "automation_created" &&
    ownership.kind !== "explicitly_adopted"
  )
    throw new Error("reviewed_lifecycle_existing_ownership_required");
  const sourceIds =
    group.authority.kind === "google_group"
      ? [group.authority.id]
      : group.authority.ids;
  const excludedIds = group.authority.excludedIds ?? [];
  if (
    group.expectedSlackUserGroupId !== group.slackUserGroupId ||
    group.currentHandle !== group.handle ||
    group.currentName !== group.desiredName ||
    !/^[a-f0-9]{40}$/u.test(ownership.cutoverRevision) ||
    !/^[a-f0-9]{64}$/u.test(ownership.evidenceDigest) ||
    sourceIds.length === 0 ||
    [...sourceIds, ...excludedIds].some((id) => !/^[a-z0-9]+$/u.test(id)) ||
    !sameIds(sourceIds, ownership.sourceGoogleGroupIds) ||
    !sameIds(excludedIds, ownership.excludedGoogleGroupIds) ||
    !sameIds(group.desiredChannelIds, ownership.allowedChannelIds) ||
    group.requiredChannelIds.some(
      (id) => !ownership.allowedChannelIds.includes(id),
    )
  )
    throw new Error("reviewed_lifecycle_ownership_changed");
}

function sameIds(left: readonly string[], right: readonly string[]): boolean {
  return (
    left.length === right.length &&
    new Set(left).size === left.length &&
    new Set(right).size === right.length &&
    left.every((id) => right.includes(id))
  );
}
