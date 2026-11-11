import { dequal } from "dequal";

import { JsonValueSchema } from "../operations/schemas.ts";
import type { IOrgChannelMembershipObservationReader } from "../org-sync/channel-service.ts";
import type { WorkspaceDirectoryPlan } from "./contracts.ts";
import { slackGroupsChannelsManagedSlice } from "./slack-groups-channels-managed-slice.ts";

type Branch = WorkspaceDirectoryPlan["branches"][2];
type Observation = Awaited<
  ReturnType<
    IOrgChannelMembershipObservationReader["readOriginalMembershipObservation"]
  >
>;

export function observeOriginalSlackMembershipTarget(
  original: Branch,
  observed: Observation,
) {
  if (
    original.execution !== "managed" ||
    original.selectedIdentity?.googleUserId !== observed.googleUserId ||
    original.selectedIdentity.slackUserId !== observed.slackUserId ||
    observed.plan.errors.length > 0 ||
    new Set(observed.userGroups.map((group) => group.id)).size !==
      observed.userGroups.length ||
    new Set(observed.inventory.map((channel) => channel.id)).size !==
      observed.inventory.length ||
    new Set(observed.channels.map((channel) => channel.id)).size !==
      observed.channels.length
  )
    throw invalid();
  const checks = [
    ...original.selectedUserGroups.map((review) =>
      groupState(original, review, observed),
    ),
    ...original.selectedChannelAdditions.map((change) =>
      edgeState(change, observed, false),
    ),
    ...original.selectedProvenanceChannelRemovals.map((change) =>
      edgeState(change, observed, true),
    ),
    ...(original.selectedChannelRename === null
      ? []
      : [renameState(original.selectedChannelRename, observed)]),
  ];
  if (checks.length === 0) throw invalid();
  if (checks.every((check) => check.before))
    return JsonValueSchema.parse(
      slackGroupsChannelsManagedSlice(original, "pending"),
    );
  if (checks.every((check) => check.after))
    return JsonValueSchema.parse(
      slackGroupsChannelsManagedSlice(original, "verified"),
    );
  return JsonValueSchema.parse({ state: "drifted" });
}

function groupState(
  original: Branch,
  review: Branch["selectedUserGroups"][number],
  observed: Observation,
) {
  if (review.effectiveAccessAdditions.length > 0) throw invalid();
  const planned = original.userGroups.find(
    (group) => group.handle === review.handle,
  );
  const fresh = observed.plan.userGroups.filter(
    (group) => group.handle === review.handle,
  );
  const matches = observed.userGroups.filter(
    (group) =>
      group.id === review.expectedSlackUserGroupId ||
      group.handle === review.handle,
  );
  const current = matches.length === 1 ? matches[0] : undefined;
  const source = fresh.length === 1 ? fresh[0] : undefined;
  if (
    planned === undefined ||
    current === undefined ||
    source === undefined ||
    review.expectedSlackUserGroupId === null ||
    current.id !== review.expectedSlackUserGroupId ||
    current.id !== review.slackUserGroupId ||
    current.isDisabled ||
    review.automationOwnership.kind === "legacy_unmanaged" ||
    review.automationOwnership.kind === "automation_bootstrap" ||
    source.slackUserGroupId !== current.id ||
    planned.slackUserGroupId !== current.id ||
    !dequal(review.authority, planned.authority) ||
    !dequal(review.automationOwnership, planned.automationOwnership) ||
    !dequal(source.authority, planned.authority) ||
    !dequal(source.automationOwnership, planned.automationOwnership) ||
    planned.memberAdditionUserIds === undefined ||
    planned.memberRemovalUserIds === undefined ||
    planned.channelAdditionIds === undefined ||
    planned.channelRemovalIds === undefined
  )
    throw invalid();
  const usersBefore = reconstructBefore(
    planned.desiredUserIds,
    planned.memberAdditionUserIds,
    planned.memberRemovalUserIds,
  );
  const channelsBefore = reconstructBefore(
    planned.desiredChannelIds,
    planned.channelAdditionIds,
    planned.channelRemovalIds,
  );
  return {
    before:
      current.handle === review.currentHandle &&
      current.name === review.currentName &&
      sameSet(current.userIds, usersBefore) &&
      sameSet(current.channelIds, channelsBefore),
    after:
      current.handle === review.handle &&
      current.name === review.desiredName &&
      sameSet(
        current.userIds,
        applyChanges(
          usersBefore,
          review.memberAdditions.map((member) => member.slackUserId),
          review.memberRemovals.map((member) => member.slackUserId),
        ),
      ) &&
      sameSet(
        current.channelIds,
        applyChanges(
          channelsBefore,
          review.channelAdditionIds,
          review.channelRemovalIds,
        ),
      ),
  };
}

function edgeState(
  change: {
    channelId: string;
    channelName: string;
    isPrivate: boolean;
    slackUserId: string;
  },
  observed: Observation,
  removal: boolean,
) {
  const channel = observed.channels.find(
    (candidate) => candidate.id === change.channelId,
  );
  if (
    channel?.name !== change.channelName ||
    channel.isPrivate !== change.isPrivate ||
    channel.isArchived ||
    new Set(channel.memberIds).size !== channel.memberIds.length
  )
    throw invalid();
  const present = channel.memberIds.includes(change.slackUserId);
  return { before: present === removal, after: present !== removal };
}

function renameState(
  rename: NonNullable<Branch["selectedChannelRename"]>,
  observed: Observation,
) {
  const channel = observed.inventory.find(
    (candidate) => candidate.id === rename.channelId,
  );
  if (channel?.isPrivate !== rename.isPrivate || channel.isArchived)
    throw invalid();
  return {
    before: channel.name === rename.currentName,
    after: channel.name === rename.expectedName,
  };
}

function reconstructBefore(
  desired: readonly string[],
  additions: readonly string[],
  removals: readonly string[],
) {
  return applyChanges(desired, removals, additions);
}
function applyChanges(
  current: readonly string[],
  additions: readonly string[],
  removals: readonly string[],
) {
  if (
    [current, additions, removals].some(
      (ids) => new Set(ids).size !== ids.length,
    ) ||
    additions.some((id) => removals.includes(id)) ||
    additions.some((id) => current.includes(id)) ||
    removals.some((id) => !current.includes(id))
  )
    throw invalid();
  const result = new Set(current);
  for (const id of removals) result.delete(id);
  for (const id of additions) result.add(id);
  return [...result].toSorted(
    (sortLeft, sortRight) =>
      Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
  );
}
function sameSet(left: readonly string[], right: readonly string[]) {
  return (
    new Set(left).size === left.length &&
    new Set(right).size === right.length &&
    dequal(
      [...left].toSorted(
        (sortLeft, sortRight) =>
          Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
      ),
      [...right].toSorted(
        (sortLeft, sortRight) =>
          Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
      ),
    )
  );
}
function invalid(): Error {
  return new Error("workspace_slack_membership_observation_invalid");
}
