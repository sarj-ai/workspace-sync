import { contentHash } from "../github-access-audit/content-hash.ts";
import {
  hasCompleteEmployeeEntitlementAuthority,
  isEmployeeEntitlementExcluded,
  type EmployeeEntitlementAuthority,
} from "../identity-provisioning/employee-entitlement-policy.ts";
import type { GoogleGroupSnapshot } from "../org-sync/channel-model.ts";
import {
  isActiveGoogleDirectoryUser,
  type GoogleDirectoryUser,
} from "../org-sync/model.ts";
import type { PosthogMembershipPolicy } from "../workspace-directory/posthog-membership-plan.ts";

export async function capturePosthogGoogleAuthority(
  policy: PosthogMembershipPolicy,
  users: GoogleDirectoryUser[],
  groups: GoogleGroupSnapshot[],
  authority: EmployeeEntitlementAuthority,
) {
  if (
    !hasCompleteEmployeeEntitlementAuthority(authority) ||
    users.length < policy.minimumGoogleUsers
  )
    throw new Error("posthog_employee_authority_incomplete");
  const desired = desiredPeople(
    reachableGroups(policy, groups),
    users,
    authority,
  );
  const sourceAuthorityFingerprint = await contentHash({
    policy,
    groups,
    employeeAuthority: authority.fingerprint,
    users: users.map((user) => ({
      id: user.id,
      email: user.primaryEmail,
      aliases: user.aliases ?? [],
      active: isActiveGoogleDirectoryUser(user),
    })),
  });
  return { desired, sourceAuthorityFingerprint };
}
function reachableGroups(
  policy: PosthogMembershipPolicy,
  groups: GoogleGroupSnapshot[],
) {
  const root = groups.find((group) => group.id === policy.authorityGroupId);
  if (
    root?.email.toLowerCase() !== policy.authorityGroupEmail ||
    root.members.length === 0
  )
    throw new Error("posthog_google_group_authority_mismatch");
  const reachable = new Map<string, GoogleGroupSnapshot>();
  const pending = [root];
  while (pending.length > 0) {
    const group = pending.pop();
    if (group === undefined || reachable.has(group.id)) continue;
    reachable.set(group.id, group);
    for (const member of group.members) {
      if (member.type !== "GROUP") continue;
      const nested = groups.find((candidate) => candidate.id === member.id);
      if (
        nested === undefined ||
        nested.email.toLowerCase() !== member.email.toLowerCase()
      )
        throw new Error("posthog_nested_group_unresolved");
      pending.push(nested);
    }
  }
  if (
    new Set(groups.map((group) => group.id)).size !== groups.length ||
    reachable.size !== groups.length
  )
    throw new Error("posthog_group_authority_collision");
  return reachable.values().toArray();
}
function desiredPeople(
  groups: GoogleGroupSnapshot[],
  users: GoogleDirectoryUser[],
  authority: EmployeeEntitlementAuthority,
) {
  const byId = new Map(users.map((user) => [user.id, user]));
  if (
    byId.size !== users.length ||
    new Set(users.map((user) => user.primaryEmail.toLowerCase())).size !==
      users.length
  )
    throw new Error("posthog_google_identity_collision");
  const desired = new Map<string, { googleUserId: string; email: string }>();
  for (const group of groups) {
    for (const member of group.members) {
      if (member.type === "GROUP") continue;
      if (member.type !== "USER")
        throw new Error("posthog_group_member_type_unsupported");
      const user = byId.get(member.id);
      if (
        user === undefined ||
        ![user.primaryEmail, ...(user.aliases ?? [])].some(
          (email) => email.toLowerCase() === member.email.toLowerCase(),
        )
      )
        throw new Error("posthog_google_member_unresolved");
      if (
        !isActiveGoogleDirectoryUser(user) ||
        isEmployeeEntitlementExcluded(
          user.primaryEmail,
          user.id,
          authority,
          user.aliases,
        )
      )
        continue;
      desired.set(user.id, {
        googleUserId: user.id,
        email: user.primaryEmail.toLowerCase(),
      });
    }
  }
  return desired.values().toArray();
}
