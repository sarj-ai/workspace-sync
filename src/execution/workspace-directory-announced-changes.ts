import type { WorkspaceDirectoryPlan } from "./contracts.ts";

export interface WorkspaceDirectoryAnnouncedChange {
  readonly changeKey: string;
  readonly text: string;
}

type WorkspaceDirectoryBranch = WorkspaceDirectoryPlan["branches"][number];
type Branch<Id extends WorkspaceDirectoryBranch["branchId"]> = Extract<
  WorkspaceDirectoryBranch,
  { branchId: Id }
>;

/*
 * Expands an authorized Workspace Directory branch into the exact human-visible
 * mutations that must be recorded before the provider branch may run.
 */
export function workspaceDirectoryAnnouncedChanges(
  plan: WorkspaceDirectoryPlan,
  branchId: WorkspaceDirectoryPlan["branches"][number]["branchId"],
): readonly WorkspaceDirectoryAnnouncedChange[] {
  const branch = plan.branches.find(
    (candidate) => candidate.branchId === branchId,
  );
  if (!branch)
    throw new Error(
      `workspace_directory_announcement_branch_missing:${branchId}`,
    );
  switch (branch.branchId) {
    case "sentry-memberships":
      return sentryMembershipAnnouncements(branch);
    case "pagerduty-teams":
      return pagerDutyAnnouncements(branch);
    case "google-group-cleanup":
      return branch.execution !== "managed" || branch.reviewed === null
        ? []
        : [
            {
              changeKey: `google-group-cleanup:${branch.reviewed.action.googleGroupId}:${branch.reviewed.action.memberId}`,
              text: `Workspace sync planned · Google Group inactive member removal · ${branch.reviewed.action.memberEmail} from ${branch.reviewed.action.googleGroupEmail} · ${branch.reviewed.action.lifecycle}`,
            },
          ];
    case "slack-names":
    case "linear-profiles":
      return branch.reviewed === null
        ? []
        : [
            {
              changeKey: `${branch.branchId}:${branch.reviewed.action.googleUserId}`,
              text: `Workspace sync planned · ${branch.branchId === "slack-names" ? "Slack real name" : "Linear full name"} · ${branch.reviewed.action.email}`,
            },
          ];
    case "slack-profiles":
      return slackProfileChanges(branch);
    case "drive-org-chart":
      return driveOrgChartChanges(branch);
    case "slack-groups-channels":
      return slackGroupsChannelsChanges(branch);
    case "github-access":
      return githubAccessChanges(branch);
    case "access-guard":
      return (branch.plan?.actions ?? []).map((action) => ({
        changeKey: `linear-suspend:${action.accountId}`,
        text: `Workspace sync planned · Linear suspension · ${action.email}`,
      }));
    case "identity-provisioning":
      return identityProvisioningChanges(branch);
    case "trycomp-people":
      return branch.execution !== "managed"
        ? []
        : branch.reviewedPlan.plan.actions.map((action) => ({
            changeKey: `trycomp-people:${action.type}:${action.email}`,
            text: `Workspace sync planned · Trycomp ${action.type} · ${action.email}`,
          }));
  }
}

function sentryMembershipAnnouncements(
  branch: Branch<"sentry-memberships">,
): readonly WorkspaceDirectoryAnnouncedChange[] {
  if (branch.execution !== "managed" || branch.reviewed === null) return [];
  return [
    {
      changeKey: `sentry-memberships:${branch.reviewed.googleUserId}:${branch.reviewed.action.type}`,
      text: `Workspace sync planned · Sentry ${branch.reviewed.action.type} · ${branch.reviewed.action.email}`,
    },
  ];
}

function pagerDutyAnnouncements(
  branch: Branch<"pagerduty-teams">,
): readonly WorkspaceDirectoryAnnouncedChange[] {
  if (branch.execution !== "managed" || branch.reviewed === null) return [];
  const { action } = branch.reviewed;
  return [
    {
      changeKey: `pagerduty-teams:${action.pagerDutyTeamId}:${action.pagerDutyUserId}`,
      text: `Workspace sync planned · PagerDuty team ${action.type} · ${action.email} → ${action.desiredPagerDutyRole} in team ${action.pagerDutyTeamId}`,
    },
  ];
}

function slackProfileChanges(
  branch: Branch<"slack-profiles">,
): readonly WorkspaceDirectoryAnnouncedChange[] {
  return branch.changes.map((change) => ({
    changeKey: `slack-profile:${change.googleUserId ?? "unlinked"}`,
    text: `Workspace sync planned · Slack profile · ${change.identity} · fields: ${change.changedFields.toSorted().join(", ")}`,
  }));
}

function driveOrgChartChanges(
  branch: Branch<"drive-org-chart">,
): readonly WorkspaceDirectoryAnnouncedChange[] {
  if (branch.currentSha256 === branch.desiredSha256) return [];
  return [
    {
      changeKey: `drive-org-chart:${branch.desiredSha256 ?? "unavailable"}`,
      text: `Workspace sync planned · Google Drive organization chart · desired evidence ${branch.desiredSha256 ?? "unavailable"}`,
    },
  ];
}

function slackGroupsChannelsChanges(
  branch: Branch<"slack-groups-channels">,
): readonly WorkspaceDirectoryAnnouncedChange[] {
  const channelAdditions = branch.selectedChannelAdditions.map((addition) => ({
    changeKey: `slack-direct-channel-add:${addition.channelId}:${addition.slackUserId}`,
    text: `Workspace sync planned · Slack direct channel addition · ${addition.identity} → #${addition.channelName}`,
  }));
  const groups = branch.selectedUserGroups.flatMap(slackUserGroupChanges);
  const rename =
    branch.selectedChannelRename === null
      ? []
      : [
          {
            changeKey: `slack-channel-rename:${branch.selectedChannelRename.channelId}`,
            text: `Workspace sync planned · Slack channel rename · ${branch.selectedChannelRename.currentName} → ${branch.selectedChannelRename.expectedName}`,
          },
        ];
  const provenanceRemovals = branch.selectedProvenanceChannelRemovals.map(
    (removal) => ({
      changeKey: `slack-provenance-channel-remove:${removal.channelId}:${removal.slackUserId}`,
      text: `Workspace sync planned · Slack provenance channel removal · ${removal.identity} ← #${removal.channelName}`,
    }),
  );
  return [...channelAdditions, ...groups, ...rename, ...provenanceRemovals];
}

function slackUserGroupChanges(
  group: Branch<"slack-groups-channels">["selectedUserGroups"][number],
): readonly WorkspaceDirectoryAnnouncedChange[] {
  const groupMetadata: WorkspaceDirectoryAnnouncedChange[] = [];
  if (group.slackUserGroupId === null) {
    groupMetadata.push({
      changeKey: `slack-group-create:${group.handle}`,
      text: `Workspace sync planned · Slack user-group creation · @${group.handle} · ${group.desiredName}`,
    });
  } else if (
    group.currentHandle !== group.handle ||
    group.currentName !== group.desiredName
  ) {
    groupMetadata.push({
      changeKey: `slack-group-update:${group.slackUserGroupId}`,
      text: `Workspace sync planned · Slack user-group update · @${group.currentHandle ?? group.handle} → @${group.handle} · ${group.currentName ?? group.desiredName} → ${group.desiredName}`,
    });
  }
  return [
    ...groupMetadata,
    ...group.memberAdditions.map((member) => ({
      changeKey: `slack-group-add:${group.handle}:${member.slackUserId}`,
      text: `Workspace sync planned · Slack user-group addition · ${member.identity} → @${group.handle}`,
    })),
    ...group.memberRemovals.map((member) => ({
      changeKey: `slack-group-remove:${group.handle}:${member.slackUserId}`,
      text: `Workspace sync planned · Slack user-group removal · ${member.identity} ← @${group.handle}`,
    })),
    ...group.effectiveAccessAdditions.map((addition) => ({
      changeKey: `slack-private-channel-access-add:${addition.channelId}:${addition.slackUserId}`,
      text: `Workspace sync planned · Slack private-channel access addition · ${addition.identity} → #${addition.channelName}`,
    })),
    ...group.channelAdditionIds.map((channelId) => ({
      changeKey: `slack-group-channel-add:${group.handle}:${channelId}`,
      text: `Workspace sync planned · Slack user-group channel grant · @${group.handle} → #${slackChannelName(group.channelAdditions, channelId)}`,
    })),
    ...group.channelRemovalIds.map((channelId) => ({
      changeKey: `slack-group-channel-remove:${group.handle}:${channelId}`,
      text: `Workspace sync planned · Slack user-group channel revocation · @${group.handle} ← #${slackChannelName(group.channelRemovals, channelId)}`,
    })),
  ];
}

function slackChannelName(
  channels: readonly { id: string; name: string }[] | undefined,
  channelId: string,
): string {
  return (
    channels?.find(({ id }) => id === channelId)?.name ?? "channel-unavailable"
  );
}

function githubAccessChanges(
  branch: Branch<"github-access">,
): readonly WorkspaceDirectoryAnnouncedChange[] {
  const selected =
    branch.execution === "managed" ? branch.selectedOperation : null;
  const team =
    selected !== null && "teamSlug" in selected.operation
      ? ` · team @${selected.operation.teamSlug}`
      : "";
  return selected === null
    ? []
    : [
        {
          changeKey: `github-access:${selected.googleUserId}:${selected.operation.kind}`,
          text: `Workspace sync planned · GitHub ${selected.operation.kind} · @${selected.operation.githubLogin}${team}`,
        },
      ];
}

function identityProvisioningChanges(
  branch: Branch<"identity-provisioning">,
): readonly WorkspaceDirectoryAnnouncedChange[] {
  const schema =
    branch.schemaPlan.kind === "unchanged" ||
    branch.schemaPlan.kind === "not-selected"
      ? []
      : [
          {
            changeKey: `google-schema:${branch.schemaPlan.kind}`,
            text: `Workspace sync planned · Google SarjIdentity schema · ${branch.schemaPlan.kind}`,
          },
        ];
  const seed =
    branch.githubIdentitySeed.kind !== "managed"
      ? []
      : branch.githubIdentitySeed.userPlans.flatMap((userPlan) =>
          userPlan.kind !== "update"
            ? []
            : {
                changeKey: `google-github-identity:${userPlan.user.id}`,
                text: `Workspace sync planned · Google GitHub identity mapping · ${userPlan.user.primaryEmail} → ${userPlan.desired.githubLogin}`,
              },
        );
  return [...schema, ...seed];
}
