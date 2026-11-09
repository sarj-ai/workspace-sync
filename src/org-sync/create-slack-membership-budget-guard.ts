import { dequal } from "dequal";

import {
  GoogleUserIdSchema,
  type GoogleUserId,
} from "../catalog/identity-authority.ts";
import {
  type IdentityWriteBudget,
  reserveIdentityWriteBudget,
} from "../identity-provisioning/identity-budget-contracts.ts";
import { protectedIdentityBlocker } from "../identity-provisioning/protected-identity-blocker.ts";
import { normalizeIdentityEmail } from "../identity-sync/normalize-identity-email.ts";
import type { GoogleDirectoryUser, SlackMember } from "./model.ts";

interface Authority {
  directoryUsers: readonly GoogleDirectoryUser[];
  slackMembers: readonly SlackMember[];
}

export function resolveSlackMembershipIdentities(
  authority: Authority,
  slackIds: readonly string[],
  multipleIdentitiesError = "slack_budget_multiple_google_identities",
): Map<string, GoogleUserId> {
  const emails = new Map<string, Set<string>>();
  const googleIds = new Set<string>();
  for (const user of authority.directoryUsers) {
    if (googleIds.has(user.id))
      throw new Error("slack_budget_duplicate_google_identity");
    googleIds.add(user.id);
    for (const email of [
      user.primaryEmail,
      ...(user.aliases ?? []),
      ...(user.nonEditableAliases ?? []),
    ]) {
      const normalized = normalizeIdentityEmail(email);
      const ids = emails.get(normalized) ?? new Set<string>();
      ids.add(user.id);
      emails.set(normalized, ids);
    }
  }
  const result = new Map<string, GoogleUserId>();
  for (const slackId of new Set(slackIds)) {
    const matches = authority.slackMembers.filter(
      (candidate) => candidate.id === slackId,
    );
    const member = matches[0];
    const ids = emails.get(normalizeIdentityEmail(member?.profile.email ?? ""));
    const googleId = ids?.values().next().value;
    if (matches.length !== 1 || ids?.size !== 1 || googleId === undefined)
      throw new Error("slack_budget_identity_mapping_missing_or_ambiguous");
    result.set(slackId, GoogleUserIdSchema.parse(googleId));
  }
  if (new Set(result.values()).size > 1)
    throw new Error(multipleIdentitiesError);
  return result;
}

export function createSlackMembershipBudgetGuard(input: {
  authority: Authority;
  budget: IdentityWriteBudget | undefined;
  refreshAuthority(): Promise<Authority>;
  slackUserIds: readonly string[];
  requireUnprivilegedIdentity?: boolean;
  protectedSlackUserIds?: readonly string[];
}): ((slackUserIds: readonly string[]) => Promise<void>) | undefined {
  if (input.requireUnprivilegedIdentity && input.budget?.required !== true)
    throw new Error("slack_membership_parent_budget_required");
  if (input.budget?.required !== true) return undefined;
  const pinned = resolveSlackMembershipIdentities(
    input.authority,
    input.slackUserIds,
    "slack_budget_plan_multiple_google_identities",
  );
  if (input.requireUnprivilegedIdentity)
    assertUnprivilegedSlackMembershipIdentities(
      input.authority,
      input.slackUserIds,
      input.protectedSlackUserIds,
    );
  const assertFresh = async (slackUserIds: readonly string[]) => {
    const authority = await input.refreshAuthority();
    const refreshed = resolveSlackMembershipIdentities(
      authority,
      slackUserIds,
      "slack_budget_write_multiple_google_identities",
    );
    if (input.requireUnprivilegedIdentity)
      assertUnprivilegedSlackMembershipIdentities(
        authority,
        slackUserIds,
        input.protectedSlackUserIds,
      );
    for (const [slackId, googleId] of refreshed) {
      if (
        pinned.get(slackId) !== googleId ||
        !dequal(
          identitySafety(input.authority, slackId, googleId),
          identitySafety(authority, slackId, googleId),
        )
      )
        throw new Error("slack_budget_identity_changed");
    }
    return refreshed;
  };
  return async (slackUserIds) => {
    if (slackUserIds.length === 0) return;
    const refreshed = await assertFresh(slackUserIds);
    await reserveIdentityWriteBudget(
      input.budget,
      refreshed.values().next().value,
    );
    await assertFresh(slackUserIds);
  };
}

export function assertUnprivilegedSlackMembershipIdentities(
  authority: Authority,
  slackUserIds: readonly string[],
  // eslint-disable-next-line @sarj/prefer-nominal-id-types -- Both collections contain Slack user IDs; their qualifiers describe states of the same identity role.
  protectedSlackUserIds: readonly string[] = [],
): Map<string, string> {
  const identities = resolveSlackMembershipIdentities(authority, slackUserIds);
  for (const [slackUserId, googleUserId] of identities) {
    const user = authority.directoryUsers.find(({ id }) => id === googleUserId);
    const member = authority.slackMembers.find(({ id }) => id === slackUserId);
    if (
      user === undefined ||
      member === undefined ||
      protectedSlackUserIds.includes(slackUserId) ||
      protectedIdentityBlocker({
        ...user,
        googleUserId,
        aliases: [...(user.aliases ?? []), ...(user.nonEditableAliases ?? [])],
      }) !== undefined ||
      [
        member.deleted,
        member["is_admin"],
        member["is_owner"],
        member["is_primary_owner"],
        member["is_bot"],
        member["is_app_user"],
        member["is_restricted"],
        member["is_ultra_restricted"],
      ].some((flag) => flag !== false) ||
      (member["enterprise_user"] !== undefined &&
        [
          member["enterprise_user"]["is_admin"],
          member["enterprise_user"]["is_owner"],
          member["enterprise_user"]["is_primary_owner"],
        ].some((flag) => flag !== false))
    )
      throw new Error("slack_membership_privileged_or_unknown_identity");
  }
  return identities;
}

function identitySafety(
  authority: Authority,
  slackId: string,
  googleId: GoogleUserId,
) {
  const user = authority.directoryUsers.find(({ id }) => id === googleId);
  const member = authority.slackMembers.find(({ id }) => id === slackId);
  return {
    user: {
      isAdmin: user?.isAdmin,
      isDelegatedAdmin: user?.isDelegatedAdmin,
      primaryEmail: user?.primaryEmail,
      aliases: user?.aliases,
      nonEditableAliases: user?.nonEditableAliases,
      suspended: user?.suspended,
      archived: user?.archived,
      deletionTime: user?.deletionTime,
    },
    member: {
      deleted: member?.deleted,
      "is_admin": member?.["is_admin"],
      "is_owner": member?.["is_owner"],
      "is_primary_owner": member?.["is_primary_owner"],
      "is_bot": member?.["is_bot"],
      "is_app_user": member?.["is_app_user"],
      "is_restricted": member?.["is_restricted"],
      "is_ultra_restricted": member?.["is_ultra_restricted"],
    },
  };
}
