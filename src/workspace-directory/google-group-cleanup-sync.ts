import { z } from "zod";

import { contentHash } from "../github-access-audit/content-hash.ts";
import {
  authoritativeGoogleDirectoryUserState,
  GoogleDirectoryUserIdSchema,
} from "../identity-lifecycle/contracts.ts";
import { protectedIdentityBlocker } from "../identity-provisioning/protected-identity-blocker.ts";
import {
  type GoogleGroupMember,
  type GoogleGroupSnapshot,
  GoogleGroupSnapshotSchema,
} from "../org-sync/channel-model.ts";
import { orgSyncSettings } from "../org-sync/config.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";

const DeletionTimeSchema = z.iso.datetime();

export function isProtectedGoogleCleanupUser(
  user: GoogleDirectoryUser,
): boolean {
  // Deleted Directory records omit administrator flags. A validated deletion is
  // sufficient lifecycle authority; immutable roots and explicit admin flags
  // remain protected independently of those omitted fields.
  const deleted =
    user.deletionTime !== undefined &&
    DeletionTimeSchema.safeParse(user.deletionTime).success;
  return (
    orgSyncSettings().protectedDepartedGoogleUserIds.includes(user.id) ||
    protectedIdentityBlocker({
      ...user,
      googleUserId: user.id,
      isAdmin: user.isAdmin ?? (deleted ? false : undefined),
      isDelegatedAdmin: user.isDelegatedAdmin ?? (deleted ? false : undefined),
      aliases: [...(user.aliases ?? []), ...(user.nonEditableAliases ?? [])],
    }) !== undefined
  );
}

const EmailSchema = z.email().transform((value) => value.toLowerCase());
const Sha256Schema = z.string().regex(/^[a-f0-9]{64}$/u);
const InactiveLifecycleSchema = z.enum(["archived", "deleted", "suspended"]);
const PrivilegedGoogleGroupRoleSchema = z.enum(["MANAGER", "OWNER"]);

export const GoogleGroupCleanupActionSchema = z.strictObject({
  authorityEmail: EmailSchema.optional(),
  googleGroupEmail: EmailSchema,
  googleGroupId: z.string().min(1),
  googleUserId: GoogleDirectoryUserIdSchema,
  lifecycle: InactiveLifecycleSchema,
  memberEmail: EmailSchema,
  memberId: GoogleDirectoryUserIdSchema,
  role: PrivilegedGoogleGroupRoleSchema.optional(),
  type: z.literal("remove-inactive-google-group-member"),
});
export type GoogleGroupCleanupAction = z.output<
  typeof GoogleGroupCleanupActionSchema
>;

export const GoogleGroupCleanupWarningSchema = z.strictObject({
  googleGroupEmail: EmailSchema,
  googleGroupId: z.string().min(1),
  googleUserId: GoogleDirectoryUserIdSchema,
  lifecycle: InactiveLifecycleSchema,
  memberEmail: EmailSchema,
  memberId: GoogleDirectoryUserIdSchema,
  role: PrivilegedGoogleGroupRoleSchema,
  type: z.literal("inactive-privileged-member-manual-review"),
});
export type GoogleGroupCleanupWarning = z.output<
  typeof GoogleGroupCleanupWarningSchema
>;

const ManagedGoogleGroupPinSchema = z.strictObject({
  email: EmailSchema,
  id: z.string().min(1),
});

export const GoogleGroupCleanupPlanSchema = z.strictObject({
  actions: z.array(GoogleGroupCleanupActionSchema),
  excludedGoogleGroupIds: z.array(z.string().min(1)),
  excludedGoogleUserIds: z.array(GoogleDirectoryUserIdSchema),
  managedGoogleGroups: z.array(ManagedGoogleGroupPinSchema),
  planHash: Sha256Schema,
  warnings: z.array(GoogleGroupCleanupWarningSchema),
});
export type GoogleGroupCleanupPlan = z.output<
  typeof GoogleGroupCleanupPlanSchema
>;

/*
 * Plans removals only from the exact managed group snapshots supplied by the
 * caller. Membership is joined to Directory authority by immutable Google user
 * ID; email similarity and a member's provider status never grant authority.
 */
export async function planGoogleGroupCleanup(input: {
  readonly directoryUsers: readonly GoogleDirectoryUser[];
  readonly excludedGoogleGroupIds?: readonly string[];
  readonly excludedGoogleUserIds?: readonly string[];
  readonly managedGoogleGroupPins: readonly z.input<
    typeof ManagedGoogleGroupPinSchema
  >[];
  readonly managedGoogleGroups: readonly GoogleGroupSnapshot[];
}): Promise<GoogleGroupCleanupPlan> {
  const excludedGoogleGroupIds = [
    ...new Set(input.excludedGoogleGroupIds),
  ].toSorted(
    (sortLeft, sortRight) =>
      Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
  );
  const excludedIds = new Set(excludedGoogleGroupIds);
  const excludedGoogleUserIds = [
    ...new Set(
      [
        ...(input.excludedGoogleUserIds ?? []),
        ...input.directoryUsers
          .filter(isProtectedGoogleCleanupUser)
          .map(({ id }) => id),
      ].map((id) => GoogleDirectoryUserIdSchema.parse(id)),
    ),
  ].toSorted(
    (sortLeft, sortRight) =>
      Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
  );
  const excludedUserIds: ReadonlySet<string> = new Set(excludedGoogleUserIds);
  const expectedPins = canonicalManagedPins(input.managedGoogleGroupPins);
  const groups = canonicalManagedGroups(
    input.managedGoogleGroups,
    expectedPins,
  );
  const { emailOwners, usersById } = authoritativeUsersById(
    input.directoryUsers,
  );
  const actions: GoogleGroupCleanupAction[] = [];
  const warnings: GoogleGroupCleanupWarning[] = [];

  for (const group of groups) {
    if (excludedIds.has(group.id)) continue;
    assertUniqueDirectUserMemberIds(group);
    for (const member of group.members) {
      if (member.type === "USER" && excludedUserIds.has(member.id)) continue;
      const memberEmailOwner = emailOwners.get(member.email.toLowerCase());
      if (memberEmailOwner !== undefined && memberEmailOwner !== member.id) {
        throw new Error(
          `google_group_cleanup_member_email_identity_mismatch:${group.id}:${member.id}`,
        );
      }
      collectMemberChange(group, member, usersById.get(member.id), actions);
    }
  }

  actions.sort(compareAction);
  warnings.sort(compareWarning);
  const body = {
    actions,
    excludedGoogleGroupIds,
    excludedGoogleUserIds,
    managedGoogleGroups: expectedPins,
    warnings,
  };
  return GoogleGroupCleanupPlanSchema.parse({
    ...body,
    planHash: await contentHash(body),
  });
}

function collectMemberChange(
  group: GoogleGroupSnapshot,
  member: GoogleGroupMember,
  user: ReturnType<typeof authoritativeGoogleDirectoryUserState> | undefined,
  actions: GoogleGroupCleanupAction[],
): void {
  if (
    member.type !== "USER" ||
    user === undefined ||
    (user.state !== "archived" &&
      user.state !== "suspended" &&
      user.state !== "deleted")
  ) {
    return;
  }
  const common = {
    googleGroupEmail: group.email,
    googleGroupId: group.id,
    googleUserId: user.googleUserId,
    lifecycle: user.state,
    memberEmail: member.email,
    memberId: GoogleDirectoryUserIdSchema.parse(member.id),
  } as const;
  actions.push(
    GoogleGroupCleanupActionSchema.parse({
      ...common,
      ...(member.role !== "MEMBER" && { role: member.role }),
      authorityEmail:
        user.state === "deleted"
          ? user.lastKnownPrimaryEmail
          : user.primaryEmail,
      type: "remove-inactive-google-group-member",
    }),
  );
}

function authoritativeUsersById(users: readonly GoogleDirectoryUser[]): {
  emailOwners: Map<string, string>;
  usersById: Map<
    string,
    ReturnType<typeof authoritativeGoogleDirectoryUserState>
  >;
} {
  const result = new Map<
    string,
    ReturnType<typeof authoritativeGoogleDirectoryUserState>
  >();
  const emailOwners = new Map<string, string>();
  for (const user of users) {
    const authority = authoritativeGoogleDirectoryUserState(user);
    if (result.has(authority.googleUserId)) {
      throw new Error(
        `google_group_cleanup_duplicate_directory_user_id:${authority.googleUserId}`,
      );
    }
    result.set(authority.googleUserId, authority);
    for (const email of [
      user.primaryEmail,
      ...(user.aliases ?? []),
      ...(user.nonEditableAliases ?? []),
    ]) {
      const normalized = email.toLowerCase();
      const existingOwner = emailOwners.get(normalized);
      if (
        existingOwner !== undefined &&
        existingOwner !== authority.googleUserId
      ) {
        throw new Error(
          `google_group_cleanup_duplicate_directory_email:${normalized}`,
        );
      }
      emailOwners.set(normalized, authority.googleUserId);
    }
  }
  return { emailOwners, usersById: result };
}

function canonicalManagedPins(
  pins: readonly z.input<typeof ManagedGoogleGroupPinSchema>[],
): z.output<typeof ManagedGoogleGroupPinSchema>[] {
  const parsed = pins.map((pin) => ManagedGoogleGroupPinSchema.parse(pin));
  const ids = new Set<string>();
  const emails = new Set<string>();
  for (const pin of parsed) {
    if (ids.has(pin.id))
      throw new Error(`google_group_cleanup_duplicate_pin_id:${pin.id}`);
    if (emails.has(pin.email))
      throw new Error(`google_group_cleanup_duplicate_pin_email:${pin.email}`);
    ids.add(pin.id);
    emails.add(pin.email);
  }
  return parsed.toSorted(
    (left, right) =>
      left.email.localeCompare(right.email) || left.id.localeCompare(right.id),
  );
}

function canonicalManagedGroups(
  groups: readonly GoogleGroupSnapshot[],
  expectedPins: readonly z.output<typeof ManagedGoogleGroupPinSchema>[],
): GoogleGroupSnapshot[] {
  const ids = new Set<string>();
  const emails = new Set<string>();
  const parsed = groups.map((group) => GoogleGroupSnapshotSchema.parse(group));
  for (const group of parsed) {
    const email = group.email.toLowerCase();
    if (ids.has(group.id))
      throw new Error(`google_group_cleanup_duplicate_group_id:${group.id}`);
    if (emails.has(email))
      throw new Error(`google_group_cleanup_duplicate_group_email:${email}`);
    ids.add(group.id);
    emails.add(email);
  }
  if (parsed.length !== expectedPins.length) {
    throw new Error("google_group_cleanup_managed_group_snapshot_incomplete");
  }
  const expectedByEmail = new Map(
    expectedPins.map((pin) => [pin.email, pin.id]),
  );
  for (const group of parsed) {
    if (expectedByEmail.get(group.email.toLowerCase()) !== group.id) {
      throw new Error(
        `google_group_cleanup_group_pin_mismatch:${group.email}:${group.id}`,
      );
    }
  }
  return parsed.toSorted(
    (left, right) =>
      left.email.localeCompare(right.email) || left.id.localeCompare(right.id),
  );
}

function assertUniqueDirectUserMemberIds(group: GoogleGroupSnapshot): void {
  const ids = new Set<string>();
  for (const member of group.members) {
    if (member.type !== "USER") continue;
    if (ids.has(member.id)) {
      throw new Error(
        `google_group_cleanup_duplicate_member_id:${group.id}:${member.id}`,
      );
    }
    ids.add(member.id);
  }
}

function compareAction(
  left: GoogleGroupCleanupAction,
  right: GoogleGroupCleanupAction,
): number {
  return (
    left.googleGroupEmail.localeCompare(right.googleGroupEmail) ||
    left.googleGroupId.localeCompare(right.googleGroupId) ||
    left.memberEmail.localeCompare(right.memberEmail) ||
    left.memberId.localeCompare(right.memberId)
  );
}

function compareWarning(
  left: GoogleGroupCleanupWarning,
  right: GoogleGroupCleanupWarning,
): number {
  return (
    left.googleGroupEmail.localeCompare(right.googleGroupEmail) ||
    left.googleGroupId.localeCompare(right.googleGroupId) ||
    left.memberEmail.localeCompare(right.memberEmail) ||
    left.memberId.localeCompare(right.memberId) ||
    left.role.localeCompare(right.role)
  );
}
