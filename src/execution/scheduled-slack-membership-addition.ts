import { dequal } from "dequal";

import type { WorkspaceDirectoryPlan } from "./contracts.ts";

type SlackAccessPlan = WorkspaceDirectoryPlan["branches"][2];

export const MAX_SCHEDULED_SLACK_MEMBER_ADDITIONS = 5;

/* A bounded batch may be added to one existing, immutable automation-owned Slack group. */
export function isScheduledSlackMembershipAddition(
  branch: SlackAccessPlan,
): boolean {
  if (
    branch.execution !== "managed" ||
    branch.selectedChannelRename !== null ||
    branch.selectedProvenanceChannelRemovals.length > 0 ||
    branch.selectedRemovalCount !== 0 ||
    branch.selectedUserGroups.length !== 1
  ) {
    return false;
  }
  const [group] = branch.selectedUserGroups;
  const plannedGroup = branch.userGroups.find(
    ({ handle }) => handle === group?.handle,
  );
  if (
    group === undefined ||
    plannedGroup === undefined ||
    group.slackUserGroupId === null ||
    group.expectedSlackUserGroupId !== group.slackUserGroupId ||
    group.currentHandle !== group.handle ||
    group.currentName !== group.desiredName ||
    (group.automationOwnership.kind !== "automation_created" &&
      group.automationOwnership.kind !== "explicitly_adopted") ||
    !scheduledSlackMemberAdditionsAreSafe(group, plannedGroup) ||
    group.memberRemovals.length > 0 ||
    group.channelAdditionIds.length > 0 ||
    group.channelRemovalIds.length > 0 ||
    plannedGroup.status !== "update" ||
    plannedGroup.slackUserGroupId !== group.slackUserGroupId ||
    plannedGroup.currentHandle !== group.handle ||
    plannedGroup.currentName !== group.desiredName ||
    plannedGroup.desiredName !== group.desiredName ||
    !sameJson(plannedGroup.automationOwnership, group.automationOwnership) ||
    !sameJson(plannedGroup.authority, group.authority) ||
    !sameStringSet(plannedGroup.desiredChannelIds, group.requiredChannelIds) ||
    !sameStringSet(
      plannedGroup.requiredChannelIds ?? [],
      group.requiredChannelIds,
    )
  ) {
    return false;
  }
  return true;
}

/* One signed, immutable, Google-authoritative Slack user-group batch is safe to schedule. */
export function isScheduledSlackUserGroupReconciliation(
  branch: SlackAccessPlan,
): boolean {
  if (isScheduledSlackMembershipAddition(branch)) return true;
  if (
    branch.execution !== "managed" ||
    branch.selectedChannelAdditions.length > 0 ||
    branch.selectedChannelRename !== null ||
    branch.selectedProvenanceChannelRemovals.length > 0 ||
    branch.selectedRemovalCount !== 1 ||
    branch.selectedUserGroups.length !== 1
  ) {
    return false;
  }
  const [group] = branch.selectedUserGroups;
  const plannedGroup = branch.userGroups.find(
    ({ handle }) => handle === group?.handle,
  );
  if (
    group === undefined ||
    plannedGroup === undefined ||
    group.slackUserGroupId === null ||
    group.expectedSlackUserGroupId !== group.slackUserGroupId ||
    group.currentHandle !== group.handle ||
    group.currentName !== group.desiredName ||
    (group.automationOwnership.kind !== "automation_created" &&
      group.automationOwnership.kind !== "explicitly_adopted") ||
    !scheduledSlackMemberAdditionsAreSafe(group, plannedGroup, true) ||
    group.channelAdditionIds.length > 0 ||
    plannedGroup.status !== "update" ||
    plannedGroup.slackUserGroupId !== group.slackUserGroupId ||
    plannedGroup.currentHandle !== group.handle ||
    plannedGroup.currentName !== group.desiredName ||
    plannedGroup.desiredName !== group.desiredName ||
    !sameJson(plannedGroup.automationOwnership, group.automationOwnership) ||
    !sameJson(plannedGroup.authority, group.authority) ||
    !sameStringSet(plannedGroup.desiredChannelIds, group.requiredChannelIds) ||
    !sameStringSet(
      plannedGroup.requiredChannelIds ?? [],
      group.requiredChannelIds,
    )
  ) {
    return false;
  }
  const memberRemovalOnly =
    group.memberRemovals.length === 1 &&
    group.channelRemovalIds.length === 0 &&
    (plannedGroup.memberRemovalUserIds ?? []).includes(
      group.memberRemovals[0]?.slackUserId ?? "",
    );
  const channelRemovalOnly =
    group.memberRemovals.length === 0 &&
    group.channelRemovalIds.length === 1 &&
    !group.automationOwnership.allowedChannelIds.includes(
      group.channelRemovalIds[0] ?? "",
    );
  return memberRemovalOnly || channelRemovalOnly;
}

function scheduledSlackMemberAdditionsAreSafe(
  group: SlackAccessPlan["selectedUserGroups"][number],
  plannedGroup: SlackAccessPlan["userGroups"][number],
  allowEmpty = false,
): boolean {
  if (
    (group.automationOwnership.kind !== "automation_created" &&
      group.automationOwnership.kind !== "explicitly_adopted") ||
    (!allowEmpty && group.memberAdditions.length === 0) ||
    group.memberAdditions.length > MAX_SCHEDULED_SLACK_MEMBER_ADDITIONS
  ) {
    return false;
  }
  const addedSlackIdList = group.memberAdditions.map(
    ({ slackUserId }) => slackUserId,
  );
  const addedSlackIds = new Set(addedSlackIdList);
  if (
    addedSlackIds.size !== addedSlackIdList.length ||
    !sameStringSet(
      (plannedGroup.memberAdditionUserIds ?? []).slice(
        0,
        group.memberAdditions.length,
      ),
      addedSlackIdList,
    )
  ) {
    return false;
  }
  const requiredChannelIds = new Set(group.requiredChannelIds);
  const allowedChannelIds = new Set(
    group.automationOwnership.allowedChannelIds,
  );
  return group.effectiveAccessAdditions.every(
    ({ channelId, slackUserId }) =>
      addedSlackIds.has(slackUserId) &&
      requiredChannelIds.has(channelId) &&
      allowedChannelIds.has(channelId),
  );
}

function sameStringSet(
  left: readonly string[],
  right: readonly string[],
): boolean {
  if (left.length !== right.length) return false;
  const sortedRight = right.toSorted();
  return left.toSorted().every((value, index) => value === sortedRight[index]);
}

function sameJson(left: unknown, right: unknown): boolean {
  return dequal(left, right);
}
