import { z } from "zod";

import { isInactiveGoogleUser } from "../google-workspace/user-lifecycle.ts";
import {
  contractorAuthorityGroup,
  employeeEntitlementExcludedEmails,
} from "../identity-provisioning/employee-entitlement-policy.ts";
import { normalizeIdentityEmail as normalizeEmail } from "../identity-sync/normalize-identity-email.ts";
import type { GoogleDirectoryUser, SlackMember } from "./model.ts";

interface ResolveManagedChannelsResult {
  asksChannel: null | SlackChannelSnapshot;
  channelRenames: ChannelRenameChange[];
  privateChannel: null | SlackChannelSnapshot;
}
interface ResolveSlackUserGroupChannelIdsResult {
  currentChannelIds: Set<string>;
  desiredChannelIds: string[];
  requiredChannelIds: string[];
}
interface ResolveSlackUserGroupMemberChangesResult {
  desiredUserIds: string[];
  memberAdditions: SlackUserGroupMemberChange[];
  memberRemovals: SlackUserGroupMemberChange[];
}

const GoogleGroupMemberFields = {
  id: z.string().min(1),
  role: z.enum(["MANAGER", "MEMBER", "OWNER"]),
  status: z
    .enum(["ACTIVE", "ARCHIVED", "SUSPENDED", "UNKNOWN"])
    .optional()
    .default("UNKNOWN"),
} as const;
export const GoogleGroupMemberSchema = z.discriminatedUnion("type", [
  z.object({
    ...GoogleGroupMemberFields,
    email: z.email(),
    type: z.literal("USER"),
  }),
  z.object({
    ...GoogleGroupMemberFields,
    email: z.email(),
    type: z.literal("GROUP"),
  }),
  z.object({
    ...GoogleGroupMemberFields,
    email: z.string().optional().default(""),
    type: z.literal("CUSTOMER"),
  }),
]);
export const GoogleGroupSnapshotSchema = z.object({
  email: z.email(),
  id: z.string().min(1),
  members: z.array(GoogleGroupMemberSchema),
});
export const GoogleGroupIdentitySchema = z.object({
  email: z.email(),
  id: z.string().min(1),
});

export type GoogleGroupMember = z.output<typeof GoogleGroupMemberSchema>;
export type GoogleGroupSnapshot = z.output<typeof GoogleGroupSnapshotSchema>;
export type GoogleGroupIdentity = z.output<typeof GoogleGroupIdentitySchema>;

export interface SlackChannelSnapshot {
  id: string;
  isArchived: boolean;
  isPrivate: boolean;
  memberIds: string[];
  name: string;
}

export interface SlackChannelSyncSnapshot {
  channels: SlackChannelSnapshot[];
  inventory: SlackChannelIdentity[];
  members: SlackMember[];
  scopes: string[];
  teamId: string;
  userGroups: SlackUserGroupSnapshot[];
}

export interface SlackUserGroupSnapshot {
  channelIds: string[];
  handle: string;
  id: string;
  isDisabled: boolean;
  name: string;
  userIds: string[];
}

export interface SlackChannelIdentity {
  id: string;
  isArchived: boolean;
  isPrivate: boolean;
  name: string;
}

export interface SlackChannelRemovalSafety extends SlackChannelIdentity {
  isExternallyShared: boolean;
}

export interface ChannelMembershipChange {
  channelId: string;
  channelName: string;
  identity: string;
  isPrivate: boolean;
  removalAuthority?: "contractor_group_authoritative" | undefined;
  slackUserId: string;
}

export interface ManualManagerTarget {
  channelId: string;
  channelName: string;
  googleRole: "MANAGER" | "OWNER";
  identity: string;
  slackUserId: string;
  verification: "manual_required";
}

export interface OrgChannelPlan {
  additions: ChannelMembershipChange[];
  channelRenames: ChannelRenameChange[];
  errors: string[];
  lifecycle: OrgChannelLifecycleAudit;
  managerTargets: ManualManagerTarget[];
  removals: ChannelMembershipChange[];
  userGroups: SlackUserGroupReconciliation[];
  warnings: string[];
}

export interface SlackUserGroupMemberChange {
  identity: string;
  slackUserId: string;
}

export interface SlackUserGroupReconciliation {
  authority: SlackUserGroupAuthority;
  automationOwnership: SlackUserGroupAutomationOwnership;
  channelAdditions: SlackChannelIdentity[];
  channelMembershipMode: "additive" | "authoritative";
  channelRemovals: SlackChannelIdentity[];
  currentHandle: null | string;
  currentName: null | string;
  desiredChannelIds: string[];
  desiredName: string;
  desiredUserIds: string[];
  effectiveAccessAdditions: ChannelMembershipChange[];
  expectedSlackUserGroupId: null | string;
  handle: string;
  memberAdditions: SlackUserGroupMemberChange[];
  memberRemovalAuthority:
    | "contractor_group_authoritative"
    | "explicit_google_lifecycle"
    | "google_group_authoritative";
  memberRemovals: SlackUserGroupMemberChange[];
  membershipMode: ManagedTeamPolicy["membershipMode"];
  requiredChannelIds: string[];
  rolloutPriority: "canonical_team" | "workspace_union";
  slackUserGroupId: null | string;
  status: "create" | "in_sync" | "update";
}

export type SlackUserGroupAuthority =
  | {
      email: string;
      excludedEmails?: string[] | undefined;
      excludedIds?: string[] | undefined;
      id: string;
      kind: "google_group";
    }
  | {
      emails: string[];
      excludedEmails: string[];
      excludedIds: string[];
      ids: string[];
      kind: "google_group_union";
    };

export type SlackUserGroupAutomationOwnership =
  | {
      allowedChannelIds: readonly string[];
      cutoverRevision: string;
      evidenceDigest: string;
      excludedGoogleGroupIds: readonly string[];
      kind: "automation_created" | "explicitly_adopted";
      sourceGoogleGroupIds: readonly string[];
    }
  | {
      allowedChannelIds: readonly string[];
      evidenceDigest: string;
      excludedGoogleGroupIds: readonly string[];
      kind: "automation_bootstrap";
      sourceGoogleGroupIds: readonly string[];
    }
  | { kind: "legacy_unmanaged" };

export interface ChannelRenameChange {
  channelId: string;
  currentName: string;
  expectedName: string;
  isPrivate: boolean;
}

export interface OrgChannelLifecycleAudit {
  allTeamProjection?: AllTeamProjectionAudit;
  canonicalAsksPrivacy?: CanonicalAsksPrivacyAudit[];
  googleTeamGroupsOutsideAssignmentAllowlist: GoogleGroupIdentity[];
  inventoryVisibility: "token_visible_only";
  legacyUserGroupRenameCandidates?: LegacyUserGroupRenameCandidate[];
  nonstandardPublicChannels: SlackChannelIdentity[];
  privateChannelRenameCandidates: PrivateChannelRenameCandidate[];
  slackTeamChannelCollisions: SlackChannelIdentity[];
  slackUsersWithoutTeamAssignment: SlackTeamAssignmentGap[];
  verticalRetirementCandidates: SlackChannelIdentity[];
}

export interface AllTeamProjectionAudit {
  excludedFromSourceMembers: SlackUserGroupMemberChange[];
  excludedGoogleGroupEmails: string[];
  handle: string;
  includedViaAnotherSourceMembers: SlackUserGroupMemberChange[];
  preservedSlackOnlyMembers: SlackUserGroupMemberChange[];
  removalMode: "deferred";
  requiredChannels: SlackChannelIdentity[];
  requiredMembers: SlackUserGroupMemberChange[];
  sourceGoogleGroupEmails: string[];
}

export interface CanonicalAsksPrivacyAudit {
  channelId: null | string;
  expectedName: string;
  googleGroupEmail: string;
  observed: "ambiguous" | "archived" | "missing" | "private" | "public";
}

export interface LegacyUserGroupRenameCandidate {
  currentHandle: string;
  expectedHandle: string;
  slackUserGroupId: string;
}

export interface SlackTeamAssignmentGap {
  identity: null | string;
  slackUserId: string;
}

export interface PrivateChannelRenameCandidate {
  channelId: string;
  currentName: string;
  expectedName: string;
}

export interface ManagedTeamPolicy {
  accessMode: "direct" | "user_group";
  additionalChannels?: readonly { name: string }[];
  additionalLegacyPrivateChannels?: readonly { name: string }[];
  asksChannel: { name: string };
  asksMembershipMode: "additive" | "authoritative";
  channelMode: "existing" | "none" | "required";
  excludedGoogleGroupEmails?: readonly string[];
  googleGroupEmail: string;
  legacyAsksChannels?: readonly { name: string }[];
  legacyPrivateChannel: { name: string };
  membershipMode: "additive" | "authoritative";
  privateChannel: { name: string };
  projectionMode?: "assignment_only" | "slack_user_group";
  slackUserGroup: {
    automationOwnership?: SlackUserGroupAutomationOwnership;
    expectedId?: string;
    handle: string;
    legacyHandles: readonly string[];
  };
  userGroupChannelMembershipMode?: "additive" | "authoritative";
}

export interface AllTeamPolicy {
  channelMembershipMode?: "additive" | "authoritative";
  excludedGoogleGroupEmails: readonly string[];
  expectedExcludedGoogleGroupIds?: Readonly<Record<string, string>>;
  googleGroupEmails: readonly string[];
  membershipMode: "additive" | "authoritative";
  protectedGoogleUserIds?: readonly string[];
  slackUserGroup: {
    automationOwnership?: SlackUserGroupAutomationOwnership;
    expectedId?: string;
    handle: string;
    legacyHandles: readonly string[];
  };
}

export function deriveExcludedGoogleGroupEmails(
  managedTeams: readonly ManagedTeamPolicy[],
  allTeam?: AllTeamPolicy,
): string[] {
  return uniqueSorted(
    [
      ...(allTeam?.excludedGoogleGroupEmails ?? []),
      ...managedTeams.flatMap((team) => team.excludedGoogleGroupEmails ?? []),
    ].map(normalizeEmail),
  );
}

export function buildOrgChannelPlan(input: {
  activeGoogleUsers: readonly GoogleDirectoryUser[];
  inactiveGoogleUsers?: readonly GoogleDirectoryUser[];
  allTeam?: AllTeamPolicy;
  allowedPublicChannelNames: readonly string[];
  allowedPublicChannelPrefixes: readonly string[];
  assignmentGroupEmails: readonly string[];
  assignmentGroups: readonly GoogleGroupSnapshot[];
  googleGroupInventory: readonly GoogleGroupIdentity[];
  managedGroups: readonly GoogleGroupSnapshot[];
  managedTeams: readonly ManagedTeamPolicy[];
  protectedSlackUserIds?: readonly string[];
  requiredPrivateChannelNames?: readonly string[];
  slack: SlackChannelSyncSnapshot;
}): OrgChannelPlan {
  const errors: string[] = [];
  const warnings: string[] = [];
  const googleByEmail = buildGoogleEmailIndex(input.activeGoogleUsers, errors);
  const googleUserByEmail = buildGoogleUserEmailIndex(
    [...input.activeGoogleUsers, ...(input.inactiveGoogleUsers ?? [])],
    errors,
  );
  const slackByEmail = buildSlackEmailIndex(input.slack.members, errors);
  const protectedSlackIds = resolveProtectedSlackIds(
    [...input.activeGoogleUsers, ...(input.inactiveGoogleUsers ?? [])],
    input.allTeam?.protectedGoogleUserIds ?? [],
    input.slack.members,
    slackByEmail,
    errors,
    input.protectedSlackUserIds ?? [],
  );
  const inactiveSlackIds = resolveInactiveSlackIds(
    input.inactiveGoogleUsers ?? [],
    googleByEmail,
    slackByEmail,
    errors,
  );
  const channelsByName = Map.groupBy(
    input.slack.channels,
    (channel) => channel.name,
  );
  const groupsByEmail = new Map(
    input.managedGroups.map((group) => [normalizeEmail(group.email), group]),
  );
  if (input.allTeam)
    recordNestedAssignmentGroups(input.assignmentGroups, errors);
  const assignedSlackIds = resolveSlackIds(
    assignedUserEmails(input.assignmentGroups, warnings),
    googleByEmail,
    slackByEmail,
    input.allTeam ? errors : warnings,
    "assigned Google user has no active Slack identity",
  );
  const excludedCandidateSlackIds = resolveExcludedSlackIds(
    deriveExcludedGoogleGroupEmails(input.managedTeams, input.allTeam),
    input.managedGroups,
    googleUserByEmail,
    slackByEmail,
    input.slack.members,
    input.allTeam?.expectedExcludedGoogleGroupIds ?? {},
    new Set(input.allTeam?.protectedGoogleUserIds),
    errors,
    warnings,
  );
  const bootstrapExcludedSlackIds = resolveSlackIds(
    new Set(employeeEntitlementExcludedEmails()),
    googleByEmail,
    slackByEmail,
    warnings,
    "employee-entitlement exclusion has no active Slack identity",
  );
  for (const [slackUserId, identity] of bootstrapExcludedSlackIds) {
    excludedCandidateSlackIds.set(slackUserId, identity);
  }
  for (const slackUserId of excludedCandidateSlackIds.keys())
    assignedSlackIds.delete(slackUserId);
  const context: TeamPlanningContext = {
    assignedSlackIds,
    channelInventoryById: new Map(
      input.slack.inventory.map((channel) => [channel.id, channel]),
    ),
    channelsByName,
    channelSnapshotsById: new Map(
      input.slack.channels.map((channel) => [channel.id, channel]),
    ),
    errors,
    excludedSlackIds: excludedCandidateSlackIds,
    googleByEmail,
    groupsByEmail,
    inactiveSlackIds,
    protectedSlackIds,
    slackByEmail,
    slackMembersById: new Map(
      input.slack.members.map((member) => [member.id, member]),
    ),
    slackUserGroupsByHandle: Map.groupBy(
      input.slack.userGroups,
      (group) => group.handle,
    ),
    warnings,
  };
  const teamPlans = input.managedTeams.map((team) =>
    planManagedTeam(team, context),
  );
  const canonicalAsksChannels = uniqueChannels(
    teamPlans.flatMap((plan) => (plan.asksChannel ? [plan.asksChannel] : [])),
  );
  const publicAsksChannels = canonicalAsksChannels.filter(
    (channel) => !channel.isPrivate,
  );
  const nonExcludedAssignmentSlackIds = input.allTeam
    ? resolveSlackIds(
        assignedUserEmails(
          input.assignmentGroups.filter(
            (group) =>
              !input.allTeam?.excludedGoogleGroupEmails
                .map(normalizeEmail)
                .includes(normalizeEmail(group.email)),
          ),
          warnings,
        ),
        googleByEmail,
        slackByEmail,
        errors,
        "assigned Google user has no active Slack identity",
      )
    : new Map<string, string>();
  const excludedSlackIds = new Map(excludedCandidateSlackIds);
  const includedViaAnotherSourceSlackIds = new Map(
    excludedCandidateSlackIds
      .entries()
      .filter(([slackUserId]) =>
        nonExcludedAssignmentSlackIds.has(slackUserId),
      ),
  );
  const allTeamSlackIds = new Map(assignedSlackIds);
  for (const slackUserId of excludedSlackIds.keys())
    allTeamSlackIds.delete(slackUserId);
  const allTeamChannels = resolveAllTeamChannels(
    input.allTeam,
    publicAsksChannels,
  );
  const allTeamUserGroup = planAllTeamUserGroup(
    input.allTeam,
    allTeamChannels,
    allTeamSlackIds,
    groupsByEmail,
    context,
  );
  const channelRenames = teamPlans
    .flatMap((plan) => plan.channelRenames)
    .toSorted((left, right) => left.channelId.localeCompare(right.channelId));
  const userGroups = [
    ...(allTeamUserGroup ? [allTeamUserGroup] : []),
    ...teamPlans.flatMap((plan) => plan.userGroups),
  ].toSorted(compareUserGroupHandle);
  const lifecycle = buildLifecycleAudit(
    input,
    assignedSlackIds,
    allTeamSlackIds,
    excludedSlackIds,
    includedViaAnotherSourceSlackIds,
    allTeamChannels,
    channelRenames,
    userGroups,
  );
  return {
    additions: sortChanges(teamPlans.flatMap((plan) => plan.additions)),
    channelRenames,
    errors: uniqueSorted(errors),
    lifecycle,
    managerTargets: teamPlans
      .flatMap((plan) => plan.managerTargets)
      .toSorted(compareChannelIdentity),
    removals: sortChanges(teamPlans.flatMap((plan) => plan.removals)),
    userGroups,
    warnings: uniqueSorted(warnings),
  };
}

function resolveAllTeamChannels(
  policy: AllTeamPolicy | undefined,
  channels: readonly SlackChannelSnapshot[],
): SlackChannelSnapshot[] {
  if (!policy) return [];
  const ownership = policy.slackUserGroup.automationOwnership;
  if (ownership === undefined || ownership.kind === "legacy_unmanaged")
    return [...channels];
  return channels.filter((channel) =>
    ownership.allowedChannelIds.includes(channel.id),
  );
}

function planAllTeamUserGroup(
  policy: AllTeamPolicy | undefined,
  channels: readonly SlackChannelSnapshot[],
  desiredMembers: ReadonlyMap<string, string>,
  groupsByEmail: ReadonlyMap<string, GoogleGroupSnapshot>,
  context: TeamPlanningContext,
): null | SlackUserGroupReconciliation {
  if (!policy) return null;
  return planSlackUserGroup(
    {
      authority: {
        emails: policy.googleGroupEmails.map(normalizeEmail).toSorted(),
        excludedEmails: policy.excludedGoogleGroupEmails
          .map(normalizeEmail)
          .toSorted(),
        excludedIds: authorityGroupIds(
          policy.excludedGoogleGroupEmails,
          groupsByEmail,
        ),
        ids: authorityGroupIds(policy.googleGroupEmails, groupsByEmail),
        kind: "google_group_union",
      },
      channelMembershipMode: policy.channelMembershipMode ?? "additive",
      explicitlyExcludedSlackIds: new Map(),
      membershipExcludedSlackIds: context.excludedSlackIds,
      membershipMode: policy.membershipMode,
      slackUserGroup: policy.slackUserGroup,
    },
    channels,
    desiredMembers,
    context,
  );
}

function buildLifecycleAudit(
  input: {
    allTeam?: AllTeamPolicy;
    allowedPublicChannelNames: readonly string[];
    allowedPublicChannelPrefixes: readonly string[];
    assignmentGroupEmails: readonly string[];
    googleGroupInventory: readonly GoogleGroupIdentity[];
    managedTeams: readonly ManagedTeamPolicy[];
    requiredPrivateChannelNames?: readonly string[];
    slack: SlackChannelSyncSnapshot;
  },
  assignedSlackIds: ReadonlyMap<string, string>,
  allTeamSlackIds: ReadonlyMap<string, string>,
  excludedSlackIds: ReadonlyMap<string, string>,
  includedViaAnotherSourceSlackIds: ReadonlyMap<string, string>,
  allTeamChannels: readonly SlackChannelSnapshot[],
  channelRenames: readonly ChannelRenameChange[],
  userGroups: readonly SlackUserGroupReconciliation[],
): OrgChannelLifecycleAudit {
  const assignmentGroups = new Set(
    input.assignmentGroupEmails.map(normalizeEmail),
  );
  const managedChannelNames = new Set(
    input.managedTeams.flatMap((team) => [
      team.privateChannel.name,
      team.legacyPrivateChannel.name,
      ...(team.additionalLegacyPrivateChannels ?? []).map(
        (channel) => channel.name,
      ),
      team.asksChannel.name,
      ...(team.legacyAsksChannels ?? []).map((channel) => channel.name),
      ...(team.additionalChannels ?? []).map((channel) => channel.name),
    ]),
  );
  const allowedPublicNames = new Set(input.allowedPublicChannelNames);
  const requiredPrivateNames = new Set(input.requiredPrivateChannelNames);
  const activeChannels = input.slack.inventory.filter(
    (channel) => !channel.isArchived,
  );
  const allTeamGroup = input.allTeam
    ? userGroups.find(
        (group) => group.handle === input.allTeam?.slackUserGroup.handle,
      )
    : undefined;
  return {
    ...(input.allTeam && {
      allTeamProjection: {
        excludedFromSourceMembers: memberChanges(excludedSlackIds),
        excludedGoogleGroupEmails: input.allTeam.excludedGoogleGroupEmails
          .map(normalizeEmail)
          .toSorted(),
        handle: input.allTeam.slackUserGroup.handle,
        includedViaAnotherSourceMembers: memberChanges(
          includedViaAnotherSourceSlackIds,
        ),
        preservedSlackOnlyMembers: memberChangesFromSlackIds(
          (allTeamGroup?.desiredUserIds ?? []).filter(
            (slackUserId) => !allTeamSlackIds.has(slackUserId),
          ),
          input.slack.members,
        ),
        removalMode: "deferred" as const,
        requiredChannels: allTeamChannels
          .map(channelIdentity)
          .toSorted(compareChannelName),
        requiredMembers: memberChanges(allTeamSlackIds),
        sourceGoogleGroupEmails: input.allTeam.googleGroupEmails
          .map(normalizeEmail)
          .toSorted(),
      },
    }),
    canonicalAsksPrivacy: input.managedTeams
      .filter((team) => team.channelMode !== "none")
      .map((team) => canonicalAsksPrivacy(team, input.slack.inventory))
      .toSorted((left, right) =>
        left.googleGroupEmail.localeCompare(right.googleGroupEmail),
      ),
    googleTeamGroupsOutsideAssignmentAllowlist: input.googleGroupInventory
      .filter(
        (group) =>
          normalizeEmail(group.email).startsWith("team-") &&
          !assignmentGroups.has(normalizeEmail(group.email)),
      )
      .toSorted((left, right) => left.email.localeCompare(right.email)),
    inventoryVisibility: "token_visible_only",
    legacyUserGroupRenameCandidates: userGroups
      .flatMap((group) => {
        if (
          !group.slackUserGroupId ||
          !group.currentHandle ||
          group.currentHandle === group.handle
        )
          return [];
        return {
          currentHandle: group.currentHandle,
          expectedHandle: group.handle,
          slackUserGroupId: group.slackUserGroupId,
        };
      })
      .toSorted((left, right) =>
        left.expectedHandle.localeCompare(right.expectedHandle),
      ),
    nonstandardPublicChannels: activeChannels
      .filter(
        (channel) =>
          !channel.isPrivate &&
          (requiredPrivateNames.has(channel.name) ||
            (!allowedPublicNames.has(channel.name) &&
              !input.allowedPublicChannelPrefixes.some((prefix) =>
                channel.name.startsWith(prefix),
              ))),
      )
      .toSorted(compareChannelName),
    privateChannelRenameCandidates: channelRenames
      .filter((rename) => rename.isPrivate)
      .map(({ channelId, currentName, expectedName }) => ({
        channelId,
        currentName,
        expectedName,
      })),
    slackTeamChannelCollisions: activeChannels
      .filter(
        (channel) =>
          channel.name.startsWith("team-") &&
          !managedChannelNames.has(channel.name),
      )
      .toSorted(compareChannelName),
    slackUsersWithoutTeamAssignment: input.slack.members
      .filter(
        (member) =>
          activeSlackHuman(member) && !assignedSlackIds.has(member.id),
      )
      .map((member) => ({
        identity: normalizeEmail(member.profile.email ?? "") || null,
        slackUserId: member.id,
      }))
      .toSorted((left, right) =>
        (left.identity ?? left.slackUserId).localeCompare(
          right.identity ?? right.slackUserId,
        ),
      ),
    verticalRetirementCandidates: activeChannels
      .filter((channel) => channel.name.startsWith("vert-"))
      .toSorted(compareChannelName),
  };
}

interface TeamPlanningContext {
  assignedSlackIds: ReadonlyMap<string, string>;
  channelInventoryById: ReadonlyMap<string, SlackChannelIdentity>;
  channelsByName: ReadonlyMap<string, SlackChannelSnapshot[]>;
  channelSnapshotsById: ReadonlyMap<string, SlackChannelSnapshot>;
  errors: string[];
  excludedSlackIds: ReadonlyMap<string, string>;
  googleByEmail: ReadonlyMap<string, string>;
  groupsByEmail: ReadonlyMap<string, GoogleGroupSnapshot>;
  inactiveSlackIds: ReadonlyMap<string, string>;
  protectedSlackIds: ReadonlyMap<string, string>;
  slackByEmail: ReadonlyMap<string, string>;
  slackMembersById: ReadonlyMap<string, SlackMember>;
  slackUserGroupsByHandle: ReadonlyMap<string, SlackUserGroupSnapshot[]>;
  warnings: string[];
}

interface TeamPlan {
  additions: ChannelMembershipChange[];
  asksChannel: null | SlackChannelSnapshot;
  channelRenames: ChannelRenameChange[];
  managerTargets: ManualManagerTarget[];
  removals: ChannelMembershipChange[];
  userGroups: SlackUserGroupReconciliation[];
}

function planManagedTeam(
  team: ManagedTeamPolicy,
  context: TeamPlanningContext,
): TeamPlan {
  const empty: TeamPlan = {
    additions: [],
    asksChannel: null,
    channelRenames: [],
    managerTargets: [],
    removals: [],
    userGroups: [],
  };
  const group = context.groupsByEmail.get(
    normalizeEmail(team.googleGroupEmail),
  );
  if (!group) {
    context.errors.push(
      `Managed Google group ${normalizeEmail(team.googleGroupEmail)} is missing`,
    );
    return empty;
  }
  const { asksChannel, channelRenames, privateChannel } =
    resolveManagedChannels(team, context);
  if (team.channelMode === "required" && (!privateChannel || !asksChannel)) {
    return { ...empty, asksChannel, channelRenames };
  }
  if (team.projectionMode === "assignment_only") {
    return { ...empty, asksChannel, channelRenames };
  }
  const managerChannels = [privateChannel, asksChannel].filter(
    (channel): channel is SlackChannelSnapshot => channel !== null,
  );
  const discoveredUserGroupChannels = uniqueChannels([
    ...(privateChannel ? [privateChannel] : []),
    ...(asksChannel ? [asksChannel] : []),
    ...resolveAdditionalChannels(team, context),
  ]);
  const userGroupChannels = resolveUserGroupChannels(
    team,
    discoveredUserGroupChannels,
  );
  const desired = resolveTeamMembership(
    group,
    managerChannels,
    context,
    team.accessMode === "user_group" ? "error" : "warning",
  );
  const explicitlyExcludedSlackIds = contractorAdministrativeSlackIds(
    group,
    context,
  );
  const membershipExcludedSlackIds = isContractorAuthorityGroup(group)
    ? new Map<string, string>()
    : context.excludedSlackIds;
  removeSlackIds(desired.memberIds, explicitlyExcludedSlackIds);
  removeSlackIds(desired.memberIds, membershipExcludedSlackIds);
  const { additions: asksAdditions, removals: asksRemovals } =
    planDirectAsksMembership(team, asksChannel, desired.memberIds, context);
  if (team.accessMode === "user_group") {
    return {
      ...empty,
      additions: asksAdditions,
      asksChannel,
      channelRenames,
      managerTargets: desired.managerTargets,
      removals: asksRemovals,
      userGroups: [
        planSlackUserGroup(
          {
            authority: {
              email: normalizeEmail(group.email),
              excludedEmails: (team.excludedGoogleGroupEmails ?? [])
                .map(normalizeEmail)
                .toSorted(),
              excludedIds: authorityGroupIds(
                team.excludedGoogleGroupEmails ?? [],
                context.groupsByEmail,
              ),
              id: group.id,
              kind: "google_group",
            },
            channelMembershipMode:
              team.userGroupChannelMembershipMode ?? "additive",
            membershipMode: team.membershipMode,
            explicitlyExcludedSlackIds,
            membershipExcludedSlackIds,
            slackUserGroup: team.slackUserGroup,
          },
          userGroupChannels,
          desired.memberIds,
          context,
        ),
      ],
    };
  }
  if (!privateChannel) return empty;
  const additions: ChannelMembershipChange[] = [];
  appendMissing(additions, privateChannel, desired.memberIds);
  additions.push(...asksAdditions);
  return {
    additions,
    asksChannel,
    channelRenames,
    managerTargets: desired.managerTargets,
    removals: [
      ...(team.membershipMode === "authoritative"
        ? channelRemovalCandidates(
            privateChannel,
            desired.memberIds,
            context,
            true,
          )
        : []),
      ...asksRemovals,
    ],
    userGroups: [],
  };
}

function contractorAdministrativeSlackIds(
  group: GoogleGroupSnapshot,
  context: TeamPlanningContext,
): ReadonlyMap<string, string> {
  if (normalizeEmail(group.email) !== contractorAuthorityGroup().email)
    return new Map();
  if (group.id !== contractorAuthorityGroup().id) {
    context.errors.push(
      "Contractor authority group has unexpected immutable Google ID",
    );
    return new Map();
  }
  const exclusions = new Map<string, string>();
  for (const member of group.members) {
    if (
      member.type !== "USER" ||
      member.status !== "ACTIVE" ||
      member.role === "MEMBER"
    )
      continue;
    const identity = canonicalGoogleIdentity(
      member.email,
      context.googleByEmail,
    );
    const slackUserId = identity
      ? context.slackByEmail.get(identity)
      : undefined;
    if (identity && slackUserId) exclusions.set(slackUserId, identity);
  }
  return exclusions;
}

function isContractorAuthorityGroup(group: GoogleGroupSnapshot): boolean {
  return (
    normalizeEmail(group.email) === contractorAuthorityGroup().email &&
    group.id === contractorAuthorityGroup().id
  );
}

function removeSlackIds(
  members: Map<string, string>,
  excluded: ReadonlyMap<string, string>,
): void {
  for (const slackUserId of excluded.keys()) members.delete(slackUserId);
}

function resolveUserGroupChannels(
  team: ManagedTeamPolicy,
  channels: readonly SlackChannelSnapshot[],
): SlackChannelSnapshot[] {
  const ownership = team.slackUserGroup.automationOwnership;
  if (ownership === undefined || ownership.kind === "legacy_unmanaged")
    return [...channels];
  return channels.filter((channel) =>
    ownership.allowedChannelIds.includes(channel.id),
  );
}

function resolveAdditionalChannels(
  team: ManagedTeamPolicy,
  context: TeamPlanningContext,
): SlackChannelSnapshot[] {
  return (team.additionalChannels ?? []).flatMap((policy) => {
    const channel = findChannel(
      context.channelsByName,
      policy,
      true,
      context.errors,
      true,
    );
    return channel ? [channel] : [];
  });
}

function planDirectAsksMembership(
  team: ManagedTeamPolicy,
  asksChannel: null | SlackChannelSnapshot,
  desiredMemberIds: ReadonlyMap<string, string>,
  context: TeamPlanningContext,
): {
  additions: ChannelMembershipChange[];
  removals: ChannelMembershipChange[];
} {
  if (!asksChannel) return { additions: [], removals: [] };
  const additions: ChannelMembershipChange[] = [];
  appendMissing(additions, asksChannel, desiredMemberIds);
  const removals =
    team.asksMembershipMode === "authoritative"
      ? channelRemovalCandidates(asksChannel, desiredMemberIds, context, false)
      : explicitChannelRemovals(asksChannel, context.excludedSlackIds, context);
  return { additions, removals };
}

function resolveManagedChannels(
  team: ManagedTeamPolicy,
  context: TeamPlanningContext,
): ResolveManagedChannelsResult {
  if (team.channelMode === "none") {
    return { asksChannel: null, channelRenames: [], privateChannel: null };
  }
  const required = team.channelMode === "required";
  const privateResult = findCanonicalOrLegacyChannel(
    context.channelsByName,
    team.privateChannel,
    [
      team.legacyPrivateChannel,
      ...(team.additionalLegacyPrivateChannels ?? []),
    ],
    true,
    context.errors,
    required,
  );
  const asks = findCanonicalOrLegacyChannel(
    context.channelsByName,
    team.asksChannel,
    team.legacyAsksChannels ?? [],
    null,
    context.errors,
    required,
  );
  return {
    asksChannel: asks.channel,
    channelRenames: [privateResult.rename, asks.rename].filter(
      (rename): rename is ChannelRenameChange => rename !== null,
    ),
    privateChannel: privateResult.channel,
  };
}

function planSlackUserGroup(
  policy: {
    authority: SlackUserGroupAuthority;
    channelMembershipMode: SlackUserGroupReconciliation["channelMembershipMode"];
    membershipMode: ManagedTeamPolicy["membershipMode"];
    explicitlyExcludedSlackIds: ReadonlyMap<string, string>;
    membershipExcludedSlackIds: ReadonlyMap<string, string>;
    slackUserGroup: ManagedTeamPolicy["slackUserGroup"];
  },
  channels: readonly SlackChannelSnapshot[],
  desiredMembers: ReadonlyMap<string, string>,
  context: TeamPlanningContext,
): SlackUserGroupReconciliation {
  const current = resolveCurrentSlackUserGroup(policy.slackUserGroup, context);
  const { currentChannelIds, desiredChannelIds, requiredChannelIds } =
    resolveSlackUserGroupChannelIds(
      policy.channelMembershipMode,
      channels,
      current,
    );
  const currentUserIds = new Set(current?.userIds);
  const { desiredUserIds, memberAdditions, memberRemovals } =
    resolveSlackUserGroupMemberChanges(
      policy,
      desiredMembers,
      currentUserIds,
      context,
    );
  const channelsById = new Map(
    channels.map((channel) => [channel.id, channel]),
  );
  const channelAdditions = requiredChannelIds
    .filter((id) => !currentChannelIds.has(id))
    .flatMap((id) => {
      const channel = channelsById.get(id);
      return channel ? [channelIdentity(channel)] : [];
    });
  const currentAssociationChannels = resolveCurrentAssociationChannels(
    current,
    memberAdditions,
    policy.slackUserGroup.handle,
    context,
  );
  const effectiveAccessAdditions = resolveEffectiveAccessAdditions(
    uniqueChannels([...channels, ...currentAssociationChannels]),
    channelAdditions,
    desiredUserIds,
    memberAdditions,
    context,
  );
  const channelRemovals: SlackChannelIdentity[] =
    policy.channelMembershipMode === "authoritative"
      ? (current?.channelIds ?? [])
          .filter((id) => !requiredChannelIds.includes(id))
          .map((id) => channelIdentityById(id, context))
          .filter(
            (channel): channel is SlackChannelIdentity => channel !== null,
          )
      : [];
  const desiredName = displayName(policy.slackUserGroup.handle);
  const hasDrift =
    current === undefined ||
    memberAdditions.length > 0 ||
    memberRemovals.length > 0 ||
    channelAdditions.length > 0 ||
    channelRemovals.length > 0 ||
    current.name !== desiredName ||
    current.handle !== policy.slackUserGroup.handle;
  const status = resolveSlackUserGroupStatus(current, hasDrift);
  return {
    automationOwnership: policy.slackUserGroup.automationOwnership ?? {
      kind: "legacy_unmanaged",
    },
    authority: policy.authority,
    channelAdditions,
    channelMembershipMode: policy.channelMembershipMode,
    channelRemovals,
    currentHandle: current?.handle ?? null,
    currentName: current?.name ?? null,
    desiredChannelIds,
    desiredName,
    desiredUserIds,
    effectiveAccessAdditions: sortChanges(effectiveAccessAdditions),
    expectedSlackUserGroupId: policy.slackUserGroup.expectedId ?? null,
    handle: policy.slackUserGroup.handle,
    memberAdditions,
    memberRemovals,
    memberRemovalAuthority: slackUserGroupRemovalAuthority(
      memberRemovals,
      policy.membershipMode,
      policy.membershipExcludedSlackIds,
      policy.explicitlyExcludedSlackIds,
    ),
    membershipMode: policy.membershipMode,
    requiredChannelIds,
    rolloutPriority:
      policy.authority.kind === "google_group"
        ? "canonical_team"
        : "workspace_union",
    slackUserGroupId: current?.id ?? null,
    status,
  };
}

function resolveSlackUserGroupChannelIds(
  membershipMode: SlackUserGroupReconciliation["channelMembershipMode"],
  channels: readonly SlackChannelSnapshot[],
  current: SlackUserGroupSnapshot | undefined,
): ResolveSlackUserGroupChannelIdsResult {
  const requiredChannelIds = channels.map((channel) => channel.id).toSorted();
  const currentChannelIds = new Set(current?.channelIds);
  const desiredChannelIds =
    membershipMode === "additive"
      ? mergeUniqueStrings(currentChannelIds, requiredChannelIds).toSorted(
          (left, right) => left.localeCompare(right),
        )
      : requiredChannelIds;
  return { currentChannelIds, desiredChannelIds, requiredChannelIds };
}

function resolveSlackUserGroupStatus(
  current: SlackUserGroupSnapshot | undefined,
  hasDrift: boolean,
): SlackUserGroupReconciliation["status"] {
  if (!current) return "create";
  return hasDrift ? "update" : "in_sync";
}

function resolveSlackUserGroupMemberChanges(
  policy: {
    explicitlyExcludedSlackIds: ReadonlyMap<string, string>;
    membershipExcludedSlackIds: ReadonlyMap<string, string>;
    membershipMode: ManagedTeamPolicy["membershipMode"];
    slackUserGroup: ManagedTeamPolicy["slackUserGroup"];
  },
  desiredMembers: ReadonlyMap<string, string>,
  currentUserIds: ReadonlySet<string>,
  context: TeamPlanningContext,
): ResolveSlackUserGroupMemberChangesResult {
  const desiredUserIds = resolveDesiredUserIds(
    policy.membershipMode,
    desiredMembers,
    currentUserIds,
    policy.membershipExcludedSlackIds,
    context.inactiveSlackIds,
    context.protectedSlackIds,
    policy.explicitlyExcludedSlackIds,
    context.errors,
  );
  if (currentUserIds.size > 0 && desiredUserIds.length === 0) {
    context.errors.push(
      `Slack user group @${policy.slackUserGroup.handle} cannot be reconciled to zero members`,
    );
  }
  const memberAdditions = desiredMembers
    .entries()
    .filter(([slackUserId]) => !currentUserIds.has(slackUserId))
    .map(([slackUserId, identity]) => ({ identity, slackUserId }))
    .toArray()
    .toSorted(compareSlackUserGroupMember);
  const desiredUserIdSet = new Set(desiredUserIds);
  const memberRemovals = currentUserIds
    .values()
    .filter(
      (id) =>
        !desiredUserIdSet.has(id) &&
        (policy.membershipMode === "authoritative" ||
          policy.explicitlyExcludedSlackIds.has(id) ||
          policy.membershipExcludedSlackIds.has(id) ||
          context.inactiveSlackIds.has(id)),
    )
    .map((slackUserId) => ({
      identity:
        context.excludedSlackIds.get(slackUserId) ??
        context.inactiveSlackIds.get(slackUserId) ??
        slackIdentity(slackUserId, context),
      slackUserId,
    }))
    .toArray()
    .toSorted(compareSlackUserGroupMember);
  return { desiredUserIds, memberAdditions, memberRemovals };
}

function resolveCurrentAssociationChannels(
  current: SlackUserGroupSnapshot | undefined,
  memberAdditions: readonly SlackUserGroupMemberChange[],
  handle: string,
  context: TeamPlanningContext,
): SlackChannelSnapshot[] {
  return (current?.channelIds ?? []).flatMap((channelId) => {
    const channel = context.channelSnapshotsById.get(channelId);
    if (channel) return [channel];
    if (memberAdditions.length > 0) {
      context.errors.push(
        `Slack user group @${handle} channel association ${channelId} lacks membership evidence`,
      );
    }
    return [];
  });
}

function slackUserGroupRemovalAuthority(
  removals: readonly SlackUserGroupMemberChange[],
  membershipMode: ManagedTeamPolicy["membershipMode"],
  excludedSlackIds: ReadonlyMap<string, string>,
  explicitlyExcludedSlackIds: ReadonlyMap<string, string>,
): SlackUserGroupReconciliation["memberRemovalAuthority"] {
  if (
    removals.length > 0 &&
    removals.every(
      (member) =>
        excludedSlackIds.has(member.slackUserId) ||
        explicitlyExcludedSlackIds.has(member.slackUserId),
    )
  ) {
    return "contractor_group_authoritative";
  }
  if (membershipMode === "authoritative") return "google_group_authoritative";
  return "explicit_google_lifecycle";
}

function authorityGroupIds(
  emails: readonly string[],
  groupsByEmail: ReadonlyMap<string, GoogleGroupSnapshot>,
): string[] {
  return emails
    .map(normalizeEmail)
    .toSorted()
    .flatMap((email) => {
      const group = groupsByEmail.get(email);
      return group ? [group.id] : [];
    });
}

function resolveEffectiveAccessAdditions(
  channels: readonly SlackChannelSnapshot[],
  channelAdditions: readonly SlackChannelIdentity[],
  desiredUserIds: readonly string[],
  memberAdditions: readonly SlackUserGroupMemberChange[],
  context: TeamPlanningContext,
): ChannelMembershipChange[] {
  const newlyAssociatedChannelIds = new Set(
    channelAdditions.map((channel) => channel.id),
  );
  const changes = new Map<string, ChannelMembershipChange>();
  for (const channel of channels) {
    if (!channel.isPrivate || channel.isArchived) continue;
    const currentMemberIds = new Set(channel.memberIds);
    const candidateUserIds = newlyAssociatedChannelIds.has(channel.id)
      ? desiredUserIds
      : memberAdditions.map((member) => member.slackUserId);
    for (const slackUserId of candidateUserIds) {
      if (currentMemberIds.has(slackUserId)) continue;
      changes.set(`${channel.id}:${slackUserId}`, {
        channelId: channel.id,
        channelName: channel.name,
        identity: slackIdentity(slackUserId, context),
        isPrivate: true,
        slackUserId,
      });
    }
  }
  return sortChanges(changes.values().toArray());
}

function resolveCurrentSlackUserGroup(
  policy: ManagedTeamPolicy["slackUserGroup"],
  context: TeamPlanningContext,
): SlackUserGroupSnapshot | undefined {
  const canonicalMatches =
    context.slackUserGroupsByHandle.get(policy.handle) ?? [];
  const legacyMatches = policy.legacyHandles.flatMap(
    (handle) => context.slackUserGroupsByHandle.get(handle) ?? [],
  );
  const matches = new Map(
    [...canonicalMatches, ...legacyMatches].map((group) => [group.id, group]),
  )
    .values()
    .toArray();
  if (matches.length > 1)
    context.errors.push(`Slack user group @${policy.handle} is ambiguous`);
  const current = matches.length === 1 ? matches[0] : undefined;
  if (current && policy.expectedId && current.id !== policy.expectedId) {
    context.errors.push(
      `Slack user group @${policy.handle} identity mismatch: expected ${policy.expectedId}, found ${current.id}`,
    );
  }
  if (current?.isDisabled === true) {
    context.errors.push(`Slack user group @${policy.handle} is disabled`);
  }
  if (current && current.handle !== policy.handle) {
    context.warnings.push(
      `Slack user group @${current.handle} should be renamed to @${policy.handle}`,
    );
  }
  return current;
}

function resolveDesiredUserIds(
  membershipMode: ManagedTeamPolicy["membershipMode"],
  desiredMembers: ReadonlyMap<string, string>,
  currentUserIds: ReadonlySet<string>,
  excludedSlackIds: ReadonlyMap<string, string>,
  inactiveSlackIds: ReadonlyMap<string, string>,
  protectedSlackIds: ReadonlyMap<string, string>,
  explicitlyExcludedSlackIds: ReadonlyMap<string, string>,
  errors: string[],
): string[] {
  const desiredUserIdsSet = new Set(desiredMembers.keys());
  if (membershipMode === "additive") {
    for (const slackUserId of currentUserIds) {
      if (
        !inactiveSlackIds.has(slackUserId) &&
        !excludedSlackIds.has(slackUserId)
      ) {
        desiredUserIdsSet.add(slackUserId);
      }
    }
  }
  for (const slackUserId of excludedSlackIds.keys())
    desiredUserIdsSet.delete(slackUserId);
  for (const slackUserId of explicitlyExcludedSlackIds.keys())
    desiredUserIdsSet.delete(slackUserId);
  for (const slackUserId of currentUserIds) {
    const identity = protectedSlackIds.get(slackUserId);
    if (
      !identity ||
      desiredUserIdsSet.has(slackUserId) ||
      explicitlyExcludedSlackIds.has(slackUserId)
    ) {
      continue;
    }
    desiredUserIdsSet.add(slackUserId);
    errors.push(
      `Protected Slack identity ${identity} cannot be removed from a user group`,
    );
  }
  return desiredUserIdsSet.values().toArray().toSorted();
}

function resolveInactiveSlackIds(
  users: readonly GoogleDirectoryUser[],
  activeGoogleByEmail: ReadonlyMap<string, string>,
  slackByEmail: ReadonlyMap<string, string>,
  errors: string[],
): Map<string, string> {
  const claimedEmails = new Map<string, string>();
  for (const user of users) {
    if (!isExplicitlyInactiveGoogleUser(user)) continue;
    const identity = normalizeEmail(user.primaryEmail);
    for (const candidate of [
      user.primaryEmail,
      ...(user.aliases ?? []),
      ...(user.nonEditableAliases ?? []),
    ]) {
      claimInactiveGoogleEmail(
        normalizeEmail(candidate),
        identity,
        activeGoogleByEmail,
        claimedEmails,
        errors,
      );
    }
  }
  const inactiveSlackIds = new Map<string, string>();
  for (const [email, identity] of claimedEmails) {
    const slackUserId = slackByEmail.get(email);
    if (!slackUserId) continue;
    const existingIdentity = inactiveSlackIds.get(slackUserId);
    if (existingIdentity && existingIdentity !== identity) {
      errors.push(
        `Slack identity ${slackUserId} maps to multiple inactive Google users`,
      );
      continue;
    }
    inactiveSlackIds.set(slackUserId, identity);
  }
  return inactiveSlackIds;
}

function claimInactiveGoogleEmail(
  email: string,
  identity: string,
  activeGoogleByEmail: ReadonlyMap<string, string>,
  claimedEmails: Map<string, string>,
  errors: string[],
): void {
  if (activeGoogleByEmail.has(email)) {
    errors.push(
      `Inactive Google email ${email} conflicts with an active identity`,
    );
    return;
  }
  const existing = claimedEmails.get(email);
  if (existing && existing !== identity) {
    errors.push(`Duplicate inactive Google email ${email}`);
    return;
  }
  claimedEmails.set(email, identity);
}

function isExplicitlyInactiveGoogleUser(user: GoogleDirectoryUser): boolean {
  return (
    user.suspended === true ||
    user.archived === true ||
    user.deletionTime !== undefined
  );
}

function findCanonicalOrLegacyChannel(
  channelsByName: ReadonlyMap<string, SlackChannelSnapshot[]>,
  canonicalPolicy: { name: string },
  legacyPolicies: readonly { name: string }[],
  expectedPrivate: boolean | null,
  errors: string[],
  required: boolean,
): {
  channel: null | SlackChannelSnapshot;
  rename: ChannelRenameChange | null;
} {
  const canonical = channelsByName.get(canonicalPolicy.name) ?? [];
  const legacy = legacyPolicies.flatMap(
    (policy) => channelsByName.get(policy.name) ?? [],
  );
  if (canonical.length > 1 || legacy.length > 1) {
    errors.push(`Managed Slack channel #${canonicalPolicy.name} is ambiguous`);
    return { channel: null, rename: null };
  }
  if (canonical.length === 1 && legacy.length === 1) {
    errors.push(
      `Both canonical #${canonicalPolicy.name} and legacy #${legacy[0]?.name ?? "unknown"} exist`,
    );
    return { channel: null, rename: null };
  }
  if (canonical.length === 1) {
    return {
      channel: findChannel(
        channelsByName,
        canonicalPolicy,
        expectedPrivate,
        errors,
        required,
      ),
      rename: null,
    };
  }
  const legacyChannel = legacy[0];
  if (!legacyChannel) {
    if (required) {
      errors.push(
        `Managed Slack channel #${canonicalPolicy.name} is missing or not visible to the token`,
      );
    }
    return { channel: null, rename: null };
  }
  const channel = findChannel(
    channelsByName,
    { name: legacyChannel.name },
    expectedPrivate,
    errors,
    required,
  );
  if (!channel) return { channel: null, rename: null };
  return {
    channel,
    rename: {
      channelId: channel.id,
      currentName: channel.name,
      expectedName: canonicalPolicy.name,
      isPrivate: channel.isPrivate,
    },
  };
}

function resolveTeamMembership(
  group: GoogleGroupSnapshot,
  channels: readonly SlackChannelSnapshot[],
  context: TeamPlanningContext,
  missingIdentitySeverity: "error" | "warning",
): { managerTargets: ManualManagerTarget[]; memberIds: Map<string, string> } {
  const memberIds = new Map<string, string>();
  const managerTargets: ManualManagerTarget[] = [];
  for (const member of group.members) {
    const resolved = resolveGroupMemberIdentity(
      member,
      group.email,
      context,
      missingIdentitySeverity,
    );
    if (!resolved) continue;
    const { identity, slackUserId } = resolved;
    memberIds.set(slackUserId, identity);
    if (member.role === "MEMBER") continue;
    for (const channel of channels) {
      managerTargets.push({
        channelId: channel.id,
        channelName: channel.name,
        googleRole: member.role,
        identity,
        slackUserId,
        verification: "manual_required",
      });
    }
  }
  return { managerTargets, memberIds };
}

function resolveGroupMemberIdentity(
  member: GoogleGroupMember,
  groupEmail: string,
  context: TeamPlanningContext,
  missingIdentitySeverity: "error" | "warning",
): { identity: string; slackUserId: string } | null {
  if (member.type !== "USER") return null;
  if (member.status === "UNKNOWN") {
    context.errors.push(
      `Google group member ${normalizeEmail(member.email)} has unknown lifecycle state in ${normalizeEmail(groupEmail)}; access changes are blocked`,
    );
  }
  if (isInactiveGroupMember(member)) {
    context.warnings.push(
      `Google group member ${normalizeEmail(member.email)} is ${member.status} in ${normalizeEmail(groupEmail)} and excluded`,
    );
    return null;
  }
  const identity = canonicalGoogleIdentity(member.email, context.googleByEmail);
  const slackUserId = identity ? context.slackByEmail.get(identity) : undefined;
  if (identity && slackUserId) return { identity, slackUserId };
  context[missingIdentitySeverity === "error" ? "errors" : "warnings"].push(
    `Google group member ${normalizeEmail(member.email)} has no active Slack identity`,
  );
  return null;
}

function channelRemovalCandidates(
  channel: SlackChannelSnapshot,
  desiredIds: ReadonlyMap<string, string>,
  context: TeamPlanningContext,
  protectWorkspaceAdministrators: boolean,
): ChannelMembershipChange[] {
  const removals: ChannelMembershipChange[] = [];
  for (const slackUserId of channel.memberIds) {
    if (desiredIds.has(slackUserId)) continue;
    const member = context.slackMembersById.get(slackUserId);
    if (!member || !activeSlackHuman(member)) continue;
    const email = member.profile.email?.trim();
    if (!email) {
      context.warnings.push(
        `Slack member ${slackUserId} requires manual channel-membership review`,
      );
      continue;
    }
    const protectedIdentity = context.protectedSlackIds.get(slackUserId);
    if (protectedIdentity) {
      context.errors.push(
        `Protected Slack identity ${protectedIdentity} cannot be removed from #${channel.name}`,
      );
      continue;
    }
    if (protectWorkspaceAdministrators && isWorkspaceAdministrator(member)) {
      context.warnings.push(
        `Workspace administrator ${normalizeEmail(email)} requires manual private-channel review`,
      );
      continue;
    }
    removals.push({
      channelId: channel.id,
      channelName: channel.name,
      identity: normalizeEmail(email),
      isPrivate: channel.isPrivate,
      slackUserId,
    });
  }
  return removals;
}

function explicitChannelRemovals(
  channel: SlackChannelSnapshot,
  removedIds: ReadonlyMap<string, string>,
  context: TeamPlanningContext,
): ChannelMembershipChange[] {
  const currentIds = new Set(channel.memberIds);
  return removedIds
    .entries()
    .filter(([slackUserId]) => currentIds.has(slackUserId))
    .map(([slackUserId, identity]) => ({
      channelId: channel.id,
      channelName: channel.name,
      identity: identity || slackIdentity(slackUserId, context),
      isPrivate: channel.isPrivate,
      removalAuthority: "contractor_group_authoritative" as const,
      slackUserId,
    }))
    .toArray();
}

function assignedUserEmails(
  groups: readonly GoogleGroupSnapshot[],
  warnings: string[],
): Set<string> {
  const emails = new Set<string>();
  for (const group of groups) {
    for (const member of group.members) {
      if (member.type === "USER" && isInactiveGroupMember(member)) {
        warnings.push(
          `Google group member ${normalizeEmail(member.email)} is ${member.status} in ${normalizeEmail(group.email)} and excluded`,
        );
        continue;
      }
      if (isUserMember(member)) emails.add(normalizeEmail(member.email));
    }
  }
  return emails;
}

function recordNestedAssignmentGroups(
  groups: readonly GoogleGroupSnapshot[],
  errors: string[],
): void {
  for (const group of groups) {
    for (const member of group.members) {
      if (member.type !== "GROUP") continue;
      errors.push(
        `Nested Google group ${normalizeEmail(member.email)} in ${normalizeEmail(group.email)} is unsupported`,
      );
    }
  }
}

function isWorkspaceAdministrator(member: SlackMember): boolean {
  return (
    member["is_admin"] === true ||
    member["is_owner"] === true ||
    member["is_primary_owner"] === true ||
    member["enterprise_user"]?.["is_admin"] === true ||
    member["enterprise_user"]?.["is_owner"] === true ||
    member["enterprise_user"]?.["is_primary_owner"] === true
  );
}

function resolveProtectedSlackIds(
  googleUsers: readonly GoogleDirectoryUser[],
  protectedGoogleUserIds: readonly string[],
  slackMembers: readonly SlackMember[],
  slackByEmail: ReadonlyMap<string, string>,
  errors: string[],
  // eslint-disable-next-line @sarj/prefer-nominal-id-types -- Policy Google IDs and pinned Slack IDs enter from raw host configuration and are checked against their separate inventories here.
  pinnedSlackUserIds: readonly string[],
): Map<string, string> {
  const googleById = googleUsersByImmutableId(googleUsers, errors);
  const protectedSlackIds = new Map<string, string>();
  protectGoogleRootSlackIds(
    googleById,
    protectedGoogleUserIds,
    slackByEmail,
    protectedSlackIds,
    errors,
  );
  protectWorkspaceAdministratorSlackIds(slackMembers, protectedSlackIds);
  protectPinnedSlackIds(
    slackMembers,
    pinnedSlackUserIds,
    protectedSlackIds,
    errors,
  );
  return protectedSlackIds;
}

function protectGoogleRootSlackIds(
  googleById: ReadonlyMap<string, GoogleDirectoryUser>,
  protectedGoogleUserIds: readonly string[],
  slackByEmail: ReadonlyMap<string, string>,
  protectedSlackIds: Map<string, string>,
  errors: string[],
): void {
  for (const googleUserId of new Set(protectedGoogleUserIds)) {
    const googleUser = googleById.get(googleUserId);
    if (!googleUser) {
      errors.push(`Protected Google identity ${googleUserId} is missing`);
      continue;
    }
    const identity = normalizeEmail(googleUser.primaryEmail);
    for (const candidate of [
      googleUser.primaryEmail,
      ...(googleUser.aliases ?? []),
      ...(googleUser.nonEditableAliases ?? []),
    ]) {
      const slackUserId = slackByEmail.get(normalizeEmail(candidate));
      if (slackUserId) protectedSlackIds.set(slackUserId, identity);
    }
  }
}

function protectWorkspaceAdministratorSlackIds(
  slackMembers: readonly SlackMember[],
  protectedSlackIds: Map<string, string>,
): void {
  for (const member of slackMembers) {
    if (!activeSlackHuman(member) || !isWorkspaceAdministrator(member))
      continue;
    protectedSlackIds.set(
      member.id,
      normalizeEmail(member.profile.email ?? member.id),
    );
  }
}

function protectPinnedSlackIds(
  slackMembers: readonly SlackMember[],
  pinnedSlackUserIds: readonly string[],
  protectedSlackIds: Map<string, string>,
  errors: string[],
): void {
  const slackMembersById = new Map(
    slackMembers.map((member) => [member.id, member]),
  );
  for (const slackUserId of new Set(pinnedSlackUserIds)) {
    const member = slackMembersById.get(slackUserId);
    if (!member || !activeSlackHuman(member)) {
      errors.push(
        `Protected Slack identity ${slackUserId} is missing or inactive`,
      );
      continue;
    }
    protectedSlackIds.set(
      slackUserId,
      normalizeEmail(member.profile.email ?? slackUserId),
    );
  }
}

function googleUsersByImmutableId(
  googleUsers: readonly GoogleDirectoryUser[],
  errors: string[],
): Map<string, GoogleDirectoryUser> {
  const googleById = new Map<string, GoogleDirectoryUser>();
  for (const user of googleUsers) {
    if (googleById.has(user.id)) {
      errors.push(`Duplicate Google immutable identity ${user.id}`);
      continue;
    }
    googleById.set(user.id, user);
  }
  return googleById;
}

function buildGoogleEmailIndex(
  users: readonly GoogleDirectoryUser[],
  errors: string[],
): Map<string, string> {
  const index = new Map<string, string>();
  for (const user of users) {
    if (isInactiveGoogleUser(user)) continue;
    const canonical = normalizeEmail(user.primaryEmail);
    for (const candidate of [
      user.primaryEmail,
      ...(user.aliases ?? []),
      ...(user.nonEditableAliases ?? []),
    ]) {
      const email = normalizeEmail(candidate);
      const existing = index.get(email);
      if (existing && existing !== canonical)
        errors.push(`Duplicate active Google email ${email}`);
      index.set(email, canonical);
    }
  }
  return index;
}

function buildGoogleUserEmailIndex(
  users: readonly GoogleDirectoryUser[],
  errors: string[],
): Map<string, GoogleDirectoryUser> {
  const index = new Map<string, GoogleDirectoryUser>();
  const ambiguous = new Set<string>();
  for (const user of users) {
    for (const candidate of [
      user.primaryEmail,
      ...(user.aliases ?? []),
      ...(user.nonEditableAliases ?? []),
    ]) {
      const email = normalizeEmail(candidate);
      const existing = index.get(email);
      if (existing && existing.id !== user.id) {
        ambiguous.add(email);
        index.delete(email);
      } else if (!ambiguous.has(email)) {
        index.set(email, user);
      }
    }
  }
  for (const email of ambiguous)
    errors.push(`Duplicate Google exclusion identity ${email}`);
  return index;
}

function buildSlackEmailIndex(
  members: readonly SlackMember[],
  errors: string[],
): Map<string, string> {
  const index = new Map<string, string>();
  for (const member of members) {
    if (!activeSlackHuman(member)) continue;
    const email = normalizeEmail(member.profile.email ?? "");
    if (!email) continue;
    const existing = index.get(email);
    if (existing && existing !== member.id)
      errors.push(`Duplicate active Slack email ${email}`);
    index.set(email, member.id);
  }
  return index;
}

function resolveSlackIds(
  emails: ReadonlySet<string>,
  googleByEmail: ReadonlyMap<string, string>,
  slackByEmail: ReadonlyMap<string, string>,
  warnings: string[],
  warning: string,
): Map<string, string> {
  const result = new Map<string, string>();
  for (const email of emails) {
    const identity = canonicalGoogleIdentity(email, googleByEmail);
    const slackUserId = identity ? slackByEmail.get(identity) : undefined;
    if (!identity || !slackUserId) {
      warnings.push(`${warning}: ${email}`);
      continue;
    }
    result.set(slackUserId, identity);
  }
  return result;
}

function canonicalGoogleIdentity(
  email: string,
  googleByEmail: ReadonlyMap<string, string>,
): string | undefined {
  return googleByEmail.get(normalizeEmail(email));
}

function findChannel(
  channelsByName: ReadonlyMap<string, SlackChannelSnapshot[]>,
  policy: { name: string },
  expectedPrivate: boolean | null,
  errors: string[],
  required: boolean,
): null | SlackChannelSnapshot {
  const matches = channelsByName.get(policy.name) ?? [];
  if (matches.length === 0) {
    if (required) {
      errors.push(
        `Managed Slack channel #${policy.name} is missing or not visible to the token`,
      );
    }
    return null;
  }
  if (matches.length !== 1) {
    errors.push(`Managed Slack channel #${policy.name} is ambiguous`);
    return null;
  }
  const channel = matches[0];
  if (!channel) return null;
  if (expectedPrivate !== null && channel.isPrivate !== expectedPrivate) {
    if (required)
      errors.push(
        `Slack channel #${policy.name} privacy does not match policy`,
      );
    return null;
  }
  if (channel.isArchived) {
    if (required)
      errors.push(`Managed Slack channel #${policy.name} is archived`);
    return null;
  }
  return channel;
}

function uniqueChannels(
  channels: readonly SlackChannelSnapshot[],
): SlackChannelSnapshot[] {
  return new Map(channels.map((channel) => [channel.id, channel]))
    .values()
    .toArray()
    .toSorted((left, right) => left.id.localeCompare(right.id));
}

function mergeUniqueStrings(
  existing: ReadonlySet<string>,
  required: readonly string[],
): string[] {
  const result = new Set(existing);
  for (const value of required) result.add(value);
  return result.values().toArray();
}

function displayName(handle: string): string {
  return handle
    .replace(/^group-/, "")
    .split("-")
    .map((part) => `${part.charAt(0).toUpperCase()}${part.slice(1)}`)
    .join(" ");
}

function appendMissing(
  additions: ChannelMembershipChange[],
  channel: SlackChannelSnapshot,
  desired: ReadonlyMap<string, string>,
): void {
  const current = new Set(channel.memberIds);
  for (const [slackUserId, identity] of desired) {
    if (!current.has(slackUserId)) {
      additions.push({
        channelId: channel.id,
        channelName: channel.name,
        identity,
        isPrivate: channel.isPrivate,
        slackUserId,
      });
    }
  }
}

function isUserMember(member: GoogleGroupMember): boolean {
  return member.type === "USER" && !isInactiveGroupMember(member);
}

function isInactiveGroupMember(member: GoogleGroupMember): boolean {
  return member.status === "ARCHIVED" || member.status === "SUSPENDED";
}

function activeSlackHuman(member: SlackMember): boolean {
  return (
    member.id !== "USLACKBOT" &&
    member.deleted === false &&
    member["is_bot"] === false &&
    member["is_app_user"] === false &&
    member["is_restricted"] === false &&
    member["is_ultra_restricted"] === false
  );
}

function compareChannelIdentity(
  left: { channelId: string; identity: string },
  right: { channelId: string; identity: string },
): number {
  return (
    left.channelId.localeCompare(right.channelId) ||
    left.identity.localeCompare(right.identity)
  );
}

function compareChannelName(
  left: SlackChannelIdentity,
  right: SlackChannelIdentity,
): number {
  return left.name.localeCompare(right.name) || left.id.localeCompare(right.id);
}

function channelIdentity(channel: SlackChannelSnapshot): SlackChannelIdentity {
  return {
    id: channel.id,
    isArchived: channel.isArchived,
    isPrivate: channel.isPrivate,
    name: channel.name,
  };
}

function channelIdentityById(
  channelId: string,
  context: TeamPlanningContext,
): null | SlackChannelIdentity {
  return context.channelInventoryById.get(channelId) ?? null;
}

function memberChanges(
  members: ReadonlyMap<string, string>,
): SlackUserGroupMemberChange[] {
  return members
    .entries()
    .map(([slackUserId, identity]) => ({ identity, slackUserId }))
    .toArray()
    .toSorted(compareSlackUserGroupMember);
}

function memberChangesFromSlackIds(
  slackUserIds: readonly string[],
  members: readonly SlackMember[],
): SlackUserGroupMemberChange[] {
  const membersById = new Map(members.map((member) => [member.id, member]));
  return slackUserIds
    .map((slackUserId) => ({
      identity: normalizeEmail(
        membersById.get(slackUserId)?.profile.email ?? slackUserId,
      ),
      slackUserId,
    }))
    .toSorted(compareSlackUserGroupMember);
}

function resolveExcludedSlackIds(
  groupEmails: readonly string[],
  groups: readonly GoogleGroupSnapshot[],
  googleUserByEmail: ReadonlyMap<string, GoogleDirectoryUser>,
  slackByEmail: ReadonlyMap<string, string>,
  slackMembers: readonly SlackMember[],
  expectedGroupIds: Readonly<Record<string, string>>,
  protectedGoogleUserIds: ReadonlySet<string>,
  errors: string[],
  warnings: string[],
): Map<string, string> {
  const groupsByEmail = new Map(
    groups.map((group) => [normalizeEmail(group.email), group]),
  );
  const excludedGroups = groupEmails.flatMap((email) => {
    const group = groupsByEmail.get(normalizeEmail(email));
    if (group) {
      const expectedId = expectedGroupIds[normalizeEmail(email)];
      if (expectedId && group.id !== expectedId) {
        errors.push(
          `All-team exclusion group ${normalizeEmail(email)} has unexpected immutable Google ID`,
        );
        return [];
      }
      return [group];
    }
    errors.push(`All-team exclusion group ${normalizeEmail(email)} is missing`);
    return [];
  });
  const excluded = resolveSlackIds(
    excludedContractorUserEmails(
      excludedGroups,
      googleUserByEmail,
      protectedGoogleUserIds,
      errors,
    ),
    new Map(
      [...googleUserByEmail].map(([email, user]) => [
        email,
        normalizeEmail(user.primaryEmail),
      ]),
    ),
    slackByEmail,
    warnings,
    "excluded Google user has no active Slack identity",
  );
  const slackMembersById = new Map(
    slackMembers.map((member) => [member.id, member]),
  );
  for (const [slackUserId, identity] of excluded) {
    const slackMember = slackMembersById.get(slackUserId);
    if (slackMember && isWorkspaceAdministrator(slackMember)) {
      excluded.delete(slackUserId);
      errors.push(
        `Protected Slack administrator ${identity} cannot be contractor-excluded`,
      );
    }
  }
  return excluded;
}

function excludedContractorUserEmails(
  groups: readonly GoogleGroupSnapshot[],
  googleUserByEmail: ReadonlyMap<string, GoogleDirectoryUser>,
  protectedGoogleUserIds: ReadonlySet<string>,
  errors: string[],
): Set<string> {
  const emails = new Set<string>();
  for (const group of groups) {
    for (const member of group.members) {
      if (member.type !== "USER") continue;
      const email = validatedContractorEmail(
        member,
        group.email,
        googleUserByEmail,
        protectedGoogleUserIds,
        errors,
      );
      if (email) emails.add(email);
    }
  }
  return emails;
}

function validatedContractorEmail(
  member: GoogleGroupMember,
  groupEmail: string,
  googleUserByEmail: ReadonlyMap<string, GoogleDirectoryUser>,
  protectedGoogleUserIds: ReadonlySet<string>,
  errors: string[],
): string | undefined {
  const email = normalizeEmail(member.email);
  const googleUser = googleUserByEmail.get(email);
  if (!googleUser) {
    errors.push(
      `Contractor exclusion member ${email} has no verified Google identity`,
    );
    return;
  }
  if (googleUser.id !== member.id) {
    errors.push(
      `Contractor exclusion member ${email} has an immutable Google ID mismatch`,
    );
    return;
  }
  if (
    member.status !== "ACTIVE" &&
    !(member.status === "SUSPENDED" && googleUser.suspended === true) &&
    !(member.status === "ARCHIVED" && googleUser.archived === true)
  ) {
    errors.push(
      `Contractor exclusion member ${email} has ambiguous ${member.status} status in ${normalizeEmail(groupEmail)}`,
    );
    return;
  }
  // The contractor group is also an administrative boundary. Google OWNER and
  // MANAGER records operate the group; only a direct MEMBER record represents
  // a contractor who must be excluded from employee Slack projections.
  if (member.role !== "MEMBER") return;
  if (protectedGoogleUserIds.has(googleUser.id)) {
    errors.push(
      `Protected Google identity ${email} cannot be contractor-excluded`,
    );
    return;
  }
  return email;
}

function canonicalAsksPrivacy(
  team: ManagedTeamPolicy,
  inventory: readonly SlackChannelIdentity[],
): CanonicalAsksPrivacyAudit {
  const names = new Set([
    team.asksChannel.name,
    ...(team.legacyAsksChannels ?? []).map((channel) => channel.name),
  ]);
  const matches = inventory.filter((channel) => names.has(channel.name));
  let observed: CanonicalAsksPrivacyAudit["observed"] = "missing";
  if (matches.length > 1) observed = "ambiguous";
  else if (matches[0]?.isArchived === true) observed = "archived";
  else if (matches[0]?.isPrivate === true) observed = "private";
  else if (matches[0]) observed = "public";
  return {
    channelId: matches.length === 1 ? (matches[0]?.id ?? null) : null,
    expectedName: team.asksChannel.name,
    googleGroupEmail: normalizeEmail(team.googleGroupEmail),
    observed,
  };
}

function slackIdentity(
  slackUserId: string,
  context: TeamPlanningContext,
): string {
  const email = context.slackMembersById.get(slackUserId)?.profile.email;
  if (email) return normalizeEmail(email);
  context.warnings.push(
    `Slack user group member ${slackUserId} has no email identity`,
  );
  return `slack:${slackUserId}`;
}

function compareSlackUserGroupMember(
  left: SlackUserGroupMemberChange,
  right: SlackUserGroupMemberChange,
): number {
  return left.slackUserId.localeCompare(right.slackUserId);
}

function compareUserGroupHandle(
  left: SlackUserGroupReconciliation,
  right: SlackUserGroupReconciliation,
): number {
  return left.handle.localeCompare(right.handle);
}

function sortChanges(
  changes: ChannelMembershipChange[],
): ChannelMembershipChange[] {
  return changes.toSorted(compareChannelIdentity);
}

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].toSorted((left, right) =>
    left.localeCompare(right),
  );
}
