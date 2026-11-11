import { dequal } from "dequal";

import {
  WORKSPACE_DIRECTORY_ACTION_IDS,
  type WorkspaceDirectoryAuthorizedActionId,
  type WorkspaceDirectoryBranchId,
  type WorkspaceDirectoryPlan,
  type WorkspaceDirectoryWorkflowParams,
} from "./contracts.ts";
import { workspaceDirectoryAnnouncedChanges } from "./workspace-directory-announced-changes.ts";

const BRANCH_ORDER: readonly WorkspaceDirectoryBranchId[] = [
  "slack-profiles",
  "drive-org-chart",
  "slack-groups-channels",
  "github-access",
  "access-guard",
  "identity-provisioning",
  "trycomp-people",
  "slack-names",
  "linear-profiles",
  "google-group-cleanup",
  "pagerduty-teams",
  "sentry-memberships",
];

const BRANCH_ACTION_IDS: Readonly<
  Record<WorkspaceDirectoryBranchId, WorkspaceDirectoryAuthorizedActionId>
> = {
  "access-guard": WORKSPACE_DIRECTORY_ACTION_IDS.linearSuspensions,
  "drive-org-chart": WORKSPACE_DIRECTORY_ACTION_IDS.driveOrgChart,
  "github-access": WORKSPACE_DIRECTORY_ACTION_IDS.githubAccess,
  "identity-provisioning": WORKSPACE_DIRECTORY_ACTION_IDS.fanout,
  "slack-groups-channels": WORKSPACE_DIRECTORY_ACTION_IDS.slackGroupsChannels,
  "slack-profiles": WORKSPACE_DIRECTORY_ACTION_IDS.slackProfiles,
  "trycomp-people": WORKSPACE_DIRECTORY_ACTION_IDS.trycompPeople,
  "slack-names": WORKSPACE_DIRECTORY_ACTION_IDS.slackNames,
  "linear-profiles": WORKSPACE_DIRECTORY_ACTION_IDS.linearProfiles,
  "google-group-cleanup": WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup,
  "pagerduty-teams": WORKSPACE_DIRECTORY_ACTION_IDS.pagerDutyTeams,
  "sentry-memberships": WORKSPACE_DIRECTORY_ACTION_IDS.sentryMemberships,
};

export interface WorkspaceDirectorySlackManifestItem {
  readonly actionId: WorkspaceDirectoryAuthorizedActionId;
  readonly branchId: WorkspaceDirectoryBranchId;
  readonly changeKey: string;
  readonly text: string;
}

export interface WorkspaceDirectorySlackManifest {
  readonly auditOnly: readonly WorkspaceDirectorySlackManifestItem[];
  readonly deferred: readonly WorkspaceDirectorySlackManifestItem[];
  readonly selected: readonly WorkspaceDirectorySlackManifestItem[];
}

/* Deterministic counts for the plan-wide card; exact actions retain per-change ledger entries. */
export function workspaceDirectorySlackManifest(
  params: WorkspaceDirectoryWorkflowParams,
): WorkspaceDirectorySlackManifest {
  const authorized = new Set(params.authorizedActionIds);
  const candidates = managedCandidates(params.plan);
  const executionByBranch = new Map(
    params.plan.branches.map(({ branchId, execution }) => [
      branchId,
      execution,
    ]),
  );
  const auditOnly = [
    ...githubCandidates(params.plan),
    ...candidates.filter(
      ({ branchId }) => executionByBranch.get(branchId) === "audit-only",
    ),
  ];
  const actionableCandidates = candidates.filter(
    ({ branchId }) => executionByBranch.get(branchId) !== "audit-only",
  );
  const selected = BRANCH_ORDER.flatMap((branchId) => {
    const actionId = BRANCH_ACTION_IDS[branchId];
    if (
      !authorized.has(actionId) ||
      executionByBranch.get(branchId) !== "managed"
    )
      return [];
    return workspaceDirectoryAnnouncedChanges(params.plan, branchId).map(
      (change) => ({
        actionId,
        branchId,
        ...change,
      }),
    );
  });
  const selectedKeys = new Set(selected.map(({ changeKey }) => changeKey));
  return {
    auditOnly: sortManifestItems(auditOnly),
    deferred: sortManifestItems(
      actionableCandidates.filter(
        ({ changeKey }) => !selectedKeys.has(changeKey),
      ),
    ),
    selected: sortManifestItems(selected),
  };
}

function managedCandidates(
  plan: WorkspaceDirectoryPlan,
): WorkspaceDirectorySlackManifestItem[] {
  return [
    ...announcedCandidates(plan),
    ...managedGitHubDeferredCandidates(plan),
    ...slackCandidates(plan),
  ];
}

function managedGitHubDeferredCandidates(
  plan: WorkspaceDirectoryPlan,
): WorkspaceDirectorySlackManifestItem[] {
  const branch = plan.branches[3];
  if (branch.execution !== "managed") return [];
  const selected = branch.selectedOperation;
  return branch.accountPlans.flatMap((account) => {
    if (account.plan.kind !== "executable") return [];
    return account.plan.operations.flatMap((operation, operationIndex) => {
      if (
        selected?.googleUserId === account.googleUserId &&
        dequal(selected.operation, operation)
      )
        return [];
      const target = "teamSlug" in operation ? ` @${operation.teamSlug}` : "";
      return {
        actionId: WORKSPACE_DIRECTORY_ACTION_IDS.githubAccess,
        branchId: "github-access" as const,
        changeKey: `github-deferred:${account.googleUserId}:${operation.kind}:${String(operationIndex)}`,
        text: `GitHub ${operation.kind} · @${operation.githubLogin}${target}`,
      };
    });
  });
}

function announcedCandidates(
  plan: WorkspaceDirectoryPlan,
): WorkspaceDirectorySlackManifestItem[] {
  return plan.branches.flatMap(({ branchId }) =>
    workspaceDirectoryAnnouncedChanges(plan, branchId).map((change) => ({
      actionId: BRANCH_ACTION_IDS[branchId],
      branchId,
      ...change,
    })),
  );
}

function slackCandidates(
  plan: WorkspaceDirectoryPlan,
): WorkspaceDirectorySlackManifestItem[] {
  const branch = plan.branches[2];
  const selectedRemovals = new Set(
    branch.selectedProvenanceChannelRemovals.map(
      ({ channelId, slackUserId }) => `${channelId}:${slackUserId}`,
    ),
  );
  const selectedAdditions = new Set(
    [
      ...branch.selectedChannelAdditions,
      ...branch.selectedUserGroups.flatMap(
        ({ effectiveAccessAdditions }) => effectiveAccessAdditions,
      ),
    ].map(({ channelId, slackUserId }) => `${channelId}:${slackUserId}`),
  );
  return [
    ...slackChannelCandidates(branch, selectedAdditions, selectedRemovals),
    ...slackGroupCandidates(branch),
  ];
}

type SlackBranch = WorkspaceDirectoryPlan["branches"][2];

function slackChannelCandidates(
  branch: SlackBranch,
  selectedAdditions: ReadonlySet<string>,
  selectedRemovals: ReadonlySet<string>,
): WorkspaceDirectorySlackManifestItem[] {
  const actionId = WORKSPACE_DIRECTORY_ACTION_IDS.slackGroupsChannels;
  const branchId = "slack-groups-channels";
  const items: WorkspaceDirectorySlackManifestItem[] = [];
  for (const addition of branch.additions) {
    if (selectedAdditions.has(`${addition.channelId}:${addition.slackUserId}`))
      continue;
    items.push({
      actionId,
      branchId,
      changeKey: `slack-direct-channel-add:${addition.channelId}:${addition.slackUserId}`,
      text: `Slack direct channel addition · ${addition.identity} → #${addition.channelName}`,
    });
  }
  for (const removal of branch.removals) {
    if (selectedRemovals.has(`${removal.channelId}:${removal.slackUserId}`))
      continue;
    items.push({
      actionId,
      branchId,
      changeKey: `slack-direct-channel-remove:${removal.channelId}:${removal.slackUserId}`,
      text: `Slack direct channel removal · ${removal.identity} ← #${removal.channelName}`,
    });
  }
  for (const rename of branch.channelRenames) {
    if (rename.channelId === branch.selectedChannelRename?.channelId) continue;
    items.push({
      actionId,
      branchId,
      changeKey: `slack-channel-rename:${rename.channelId}`,
      text: `Slack channel rename · ${rename.currentName} → ${rename.expectedName}`,
    });
  }
  return items;
}

function slackGroupCandidates(
  branch: SlackBranch,
): WorkspaceDirectorySlackManifestItem[] {
  const actionId = WORKSPACE_DIRECTORY_ACTION_IDS.slackGroupsChannels;
  const branchId = "slack-groups-channels";
  const selectedGroupHandles = new Set(
    branch.selectedUserGroups.map(({ handle }) => handle),
  );
  const identities = slackIdentityByUserId(branch);
  const items: WorkspaceDirectorySlackManifestItem[] = [];
  for (const group of branch.userGroups) {
    if (group.status === "in_sync" || selectedGroupHandles.has(group.handle))
      continue;
    if (group.status === "create" || group.slackUserGroupId === null) {
      items.push({
        actionId,
        branchId,
        changeKey: `slack-group-create:${group.handle}`,
        text: `Slack user-group creation · @${group.handle}`,
      });
    }
    items.push(...slackGroupMemberCandidates(group, identities));
  }
  return items;
}

function slackGroupMemberCandidates(
  group: SlackBranch["userGroups"][number],
  identities: ReadonlyMap<string, string>,
): WorkspaceDirectorySlackManifestItem[] {
  const actionId = WORKSPACE_DIRECTORY_ACTION_IDS.slackGroupsChannels;
  const branchId: WorkspaceDirectoryBranchId = "slack-groups-channels";
  return [
    ...(group.memberAdditionUserIds ?? []).map((slackUserId) => ({
      actionId,
      branchId,
      changeKey: `slack-group-add:${group.handle}:${slackUserId}`,
      text: `Slack user-group addition · ${identities.get(slackUserId) ?? "Identity unavailable"} → @${group.handle}`,
    })),
    ...(group.memberRemovalUserIds ?? []).map((slackUserId) => ({
      actionId,
      branchId,
      changeKey: `slack-group-remove:${group.handle}:${slackUserId}`,
      text: `Slack user-group removal · ${identities.get(slackUserId) ?? "Identity unavailable"} ← @${group.handle}`,
    })),
  ];
}

function slackIdentityByUserId(
  branch: SlackBranch,
): ReadonlyMap<string, string> {
  const candidates = [
    ...branch.additions,
    ...branch.removals,
    ...branch.lifecycle.slackUsersWithoutTeamAssignment,
    ...branch.userGroups.flatMap((group) => [
      ...(group.memberAdditions ?? []),
      ...(group.memberRemovals ?? []),
    ]),
    ...branch.selectedUserGroups.flatMap((group) => [
      ...group.memberAdditions,
      ...group.memberRemovals,
    ]),
  ];
  const candidatesByUserId = new Map<string, Set<string>>();
  for (const { identity, slackUserId } of candidates) {
    if (identity === null) continue;
    const identities = candidatesByUserId.get(slackUserId) ?? new Set<string>();
    identities.add(identity);
    candidatesByUserId.set(slackUserId, identities);
  }
  const identityByUserId = new Map<string, string>();
  for (const [slackUserId, identities] of candidatesByUserId) {
    if (identities.size !== 1) continue;
    const identity = identities.values().next().value;
    if (identity !== undefined) identityByUserId.set(slackUserId, identity);
  }
  return identityByUserId;
}

function githubCandidates(
  plan: WorkspaceDirectoryPlan,
): WorkspaceDirectorySlackManifestItem[] {
  const branch = plan.branches[3];
  if (branch.execution !== "audit-only") return [];
  return branch.proposedChanges.map((change) => ({
    actionId: WORKSPACE_DIRECTORY_ACTION_IDS.githubAccess,
    branchId: "github-access" as const,
    changeKey: `github-audit:${change.id}`,
    text: `GitHub audit-only ${change.kind} · ${change.target}`,
  }));
}

function sortManifestItems(
  items: readonly WorkspaceDirectorySlackManifestItem[],
): WorkspaceDirectorySlackManifestItem[] {
  const branchRank = new Map(
    BRANCH_ORDER.map((branchId, index) => [branchId, index]),
  );
  const deduplicated = new Map(items.map((item) => [item.changeKey, item]));
  return deduplicated
    .values()
    .toArray()
    .toSorted(
      (left, right) =>
        (branchRank.get(left.branchId) ?? Number.MAX_SAFE_INTEGER) -
          (branchRank.get(right.branchId) ?? Number.MAX_SAFE_INTEGER) ||
        left.changeKey.localeCompare(right.changeKey, "en-US"),
    );
}
