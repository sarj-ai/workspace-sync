import { sameJson } from "../operations/canonical.ts";
import type { ManagedChange } from "../operations/schemas.ts";
import { TrycompReviewedPlanSchema } from "../trycomp/model.ts";
import { trycompManagedSlice } from "../trycomp/reviewed-identity.ts";
import { WorkspaceBranchAttemptPinsSchema } from "./branch-attempt-contracts.ts";
import type { WorkspaceDirectoryPlan } from "./contracts.ts";
import {
  googleGroupCleanupManagedSlice,
  googleGroupCleanupResourceId,
  googleGroupCleanupSourceIdentity,
} from "./reviewed-google-group-cleanup.ts";
import {
  reviewedNameManagedSlice,
  reviewedNameSourceIdentity,
} from "./reviewed-name-plan.ts";
import {
  pagerDutyTeamManagedSlice,
  pagerDutyTeamResourceId,
  pagerDutyTeamSourceIdentity,
} from "./reviewed-pagerduty-team.ts";
import {
  sentryWorkspaceManagedSlice,
  sentryWorkspaceResourceId,
  sentryWorkspaceSourceIdentity,
} from "./reviewed-sentry-workspace.ts";
import { selectedSlackMembershipUserId } from "./selected-slack-membership-user-id.ts";
import { slackGroupsChannelsManagedSlice } from "./slack-groups-channels-managed-slice.ts";

type Branch = WorkspaceDirectoryPlan["branches"][number];
type SlackGroupsChannelsBranch = WorkspaceDirectoryPlan["branches"][2];
const SOURCE_IDENTITY = WorkspaceBranchAttemptPinsSchema.shape.sourceIdentity;
const SIGNED_PIN_MISSING = "workspace_branch_signed_identity_pin_missing";

export function workspaceBranchSourceIdentity(
  branch: Branch,
  managedChange?: ManagedChange,
) {
  if (branch.execution !== "managed")
    throw new Error("workspace_branch_not_managed");
  switch (branch.branchId) {
    case "sentry-memberships":
      return sentrySourceIdentity(branch, managedChange);
    case "pagerduty-teams":
      return pagerDutySourceIdentity(branch, managedChange);
    case "google-group-cleanup":
      return cleanupSourceIdentity(branch, managedChange);
    case "slack-names":
    case "linear-profiles":
      return nameSourceIdentity(branch, managedChange);
    case "slack-profiles": {
      const change =
        branch.changes.length === 1 ? branch.changes[0] : undefined;
      return SOURCE_IDENTITY.parse({
        kind: "identity",
        systemId: "slack",
        googleUserId: change?.googleUserId,
        providerAccountId: change?.slackUserId,
      });
    }
    case "access-guard": {
      const action =
        branch.plan.actions.length === 1 ? branch.plan.actions[0] : undefined;
      return SOURCE_IDENTITY.parse({
        kind: "identity",
        systemId: "linear",
        googleUserId: action?.googleUserId,
        providerAccountId: action?.accountId,
      });
    }
    case "github-access":
      return SOURCE_IDENTITY.parse({
        kind: "identity",
        systemId: "github",
        googleUserId: branch.selectedOperation?.googleUserId,
        providerAccountId: branch.selectedOperation?.operation.githubUserId,
      });
    case "slack-groups-channels":
      return branch.selectedIdentity === undefined
        ? slackResourceSourceIdentity(branch, managedChange)
        : slackIdentitySourceIdentity(
            branch,
            branch.selectedIdentity,
            managedChange,
          );
    case "drive-org-chart":
      return driveSourceIdentity(branch, managedChange);
    case "identity-provisioning":
      throw new Error(SIGNED_PIN_MISSING);
    case "trycomp-people":
      return trycompSourceIdentity(branch, managedChange);
  }
}

function slackIdentitySourceIdentity(
  branch: SlackGroupsChannelsBranch,
  pin: { googleUserId: string; slackUserId: string },
  managedChange?: ManagedChange,
) {
  if (
    selectedSlackMembershipUserId(branch) !== pin.slackUserId ||
    managedChange?.actionId !== "workspace-directory.slack-groups-channels" ||
    managedChange.resource.type !== "slack-access" ||
    managedChange.resource.id !== pin.slackUserId ||
    !sameJson(
      managedChange.before,
      slackGroupsChannelsManagedSlice(branch, "pending"),
    ) ||
    !sameJson(
      managedChange.after,
      slackGroupsChannelsManagedSlice(branch, "verified"),
    )
  ) {
    throw new Error("workspace_branch_slack_membership_pin_mismatch");
  }
  return SOURCE_IDENTITY.parse({
    kind: "identity",
    systemId: "slack",
    googleUserId: pin.googleUserId,
    providerAccountId: pin.slackUserId,
  });
}

function slackResourceSourceIdentity(
  branch: SlackGroupsChannelsBranch,
  managedChange?: ManagedChange,
) {
  if (branch.selectedChannelAdditions.length > 0) {
    assertSlackChannelInvitationIsolation(branch);
    assertSlackResourceChange(branch, managedChange, "channel-invitations");
    return SOURCE_IDENTITY.parse({
      kind: "resource",
      systemId: "slack",
      resourceId: branch.planHash,
    });
  }
  if (branch.selectedChannelRename !== null) {
    if (
      branch.selectedUserGroupHandles.length !== 0 ||
      branch.selectedProvenanceChannelRemovals.length !== 0
    )
      throw new Error(SIGNED_PIN_MISSING);
    assertSlackResourceChange(branch, managedChange, "groups-channels");
    return SOURCE_IDENTITY.parse({
      kind: "resource",
      systemId: "slack",
      resourceId: branch.selectedChannelRename.channelId,
    });
  }
  const group = branch.selectedUserGroups[0];
  if (
    group?.automationOwnership.kind === "automation_bootstrap" &&
    group.slackUserGroupId === null &&
    group.expectedSlackUserGroupId === null &&
    branch.selectedUserGroups.length === 1 &&
    branch.selectedUserGroupHandles.length === 1 &&
    branch.selectedUserGroupHandles[0] === group.handle &&
    branch.selectedProvenanceChannelRemovals.length === 0 &&
    branch.planHash !== null &&
    branch.userGroups.some(
      ({ handle, status }) => handle === group.handle && status === "create",
    )
  ) {
    assertSlackResourceChange(branch, managedChange, "groups-channels");
    return SOURCE_IDENTITY.parse({
      kind: "resource",
      systemId: "slack",
      resourceId: branch.planHash,
    });
  }
  if (
    group === undefined ||
    branch.selectedUserGroups.length !== 1 ||
    branch.selectedUserGroupHandles.length !== 1 ||
    branch.selectedUserGroupHandles[0] !== group.handle ||
    branch.selectedProvenanceChannelRemovals.length !== 0 ||
    group.slackUserGroupId === null ||
    group.expectedSlackUserGroupId !== group.slackUserGroupId
  ) {
    throw new Error(SIGNED_PIN_MISSING);
  }
  assertSlackResourceChange(branch, managedChange, "groups-channels");
  return SOURCE_IDENTITY.parse({
    kind: "resource",
    systemId: "slack",
    resourceId: group.slackUserGroupId,
  });
}

function assertSlackResourceChange(
  branch: SlackGroupsChannelsBranch,
  change: ManagedChange | undefined,
  resourceId: "channel-invitations" | "groups-channels",
): void {
  if (
    change?.actionId !== "workspace-directory.slack-groups-channels" ||
    change.resource.type !== "slack-access" ||
    change.resource.id !== resourceId ||
    !sameJson(
      change.before,
      slackGroupsChannelsManagedSlice(branch, "pending"),
    ) ||
    !sameJson(change.after, slackGroupsChannelsManagedSlice(branch, "verified"))
  ) {
    throw new Error("workspace_branch_slack_resource_pin_mismatch");
  }
}

function assertSlackChannelInvitationIsolation(
  branch: SlackGroupsChannelsBranch,
): void {
  if (
    branch.selectedChannelRename !== null ||
    branch.selectedUserGroupHandles.length !== 0 ||
    branch.selectedProvenanceChannelRemovals.length !== 0
  )
    throw new Error(SIGNED_PIN_MISSING);
}

function sentrySourceIdentity(
  branch: Extract<Branch, { branchId: "sentry-memberships" }>,
  change?: ManagedChange,
) {
  if (
    branch.reviewed === null ||
    change?.actionId !== "workspace-directory.sentry-memberships" ||
    change.resource.type !== "sentry-membership" ||
    change.resource.id !== sentryWorkspaceResourceId(branch.reviewed) ||
    !sameJson(
      change.before,
      sentryWorkspaceManagedSlice(branch.reviewed, "pending"),
    ) ||
    !sameJson(
      change.after,
      sentryWorkspaceManagedSlice(branch.reviewed, "converged"),
    )
  ) {
    throw new Error("workspace_branch_sentry_membership_pin_mismatch");
  }
  return SOURCE_IDENTITY.parse(sentryWorkspaceSourceIdentity(branch.reviewed));
}

function pagerDutySourceIdentity(
  branch: Extract<Branch, { branchId: "pagerduty-teams" }>,
  change?: ManagedChange,
) {
  if (
    branch.reviewed === null ||
    change?.actionId !== "workspace-directory.pagerduty-teams" ||
    change.resource.type !== "pagerduty-team-membership" ||
    change.resource.id !== pagerDutyTeamResourceId(branch.reviewed) ||
    !sameJson(
      change.before,
      pagerDutyTeamManagedSlice(branch.reviewed, "pending"),
    ) ||
    !sameJson(
      change.after,
      pagerDutyTeamManagedSlice(branch.reviewed, "converged"),
    )
  )
    throw new Error("workspace_branch_pagerduty_team_pin_mismatch");
  return SOURCE_IDENTITY.parse(pagerDutyTeamSourceIdentity(branch.reviewed));
}

function cleanupSourceIdentity(
  branch: Extract<Branch, { branchId: "google-group-cleanup" }>,
  change?: ManagedChange,
) {
  if (
    branch.reviewed === null ||
    change?.actionId !== "workspace-directory.google-group-cleanup" ||
    change.resource.type !== "google-group-membership" ||
    change.resource.id !== googleGroupCleanupResourceId(branch.reviewed) ||
    !sameJson(
      change.before,
      googleGroupCleanupManagedSlice(branch.reviewed, "pending"),
    ) ||
    !sameJson(
      change.after,
      googleGroupCleanupManagedSlice(branch.reviewed, "converged"),
    )
  )
    throw new Error("workspace_branch_google_group_cleanup_pin_mismatch");
  return SOURCE_IDENTITY.parse(
    googleGroupCleanupSourceIdentity(branch.reviewed),
  );
}

function trycompSourceIdentity(
  branch: Extract<Branch, { branchId: "trycomp-people"; execution: "managed" }>,
  change?: ManagedChange,
) {
  const reviewed = TrycompReviewedPlanSchema.parse(branch.reviewedPlan);
  const identity = reviewed.selectedIdentity;
  if (identity === undefined || change === undefined)
    throw new Error(SIGNED_PIN_MISSING);
  const provider = identity.provider;
  const targetId =
    provider.kind === "member" ? provider.memberId : provider.email;
  if (
    change.actionId !== "workspace-directory.trycomp-people" ||
    change.resource.type !== "trycomp-person" ||
    change.resource.id !== targetId ||
    !sameJson(change.before, trycompManagedSlice(reviewed, "pending")) ||
    !sameJson(change.after, trycompManagedSlice(reviewed, "converged"))
  )
    throw new Error("workspace_branch_trycomp_target_pin_mismatch");
  return SOURCE_IDENTITY.parse(
    provider.kind === "member"
      ? {
          kind: "identity",
          systemId: "trycomp",
          googleUserId: identity.googleUserId,
          providerAccountId: provider.memberId,
        }
      : {
          kind: "pending-invitation",
          systemId: "trycomp",
          googleUserId: identity.googleUserId,
          email: provider.email,
        },
  );
}

function nameSourceIdentity(
  branch: Extract<Branch, { branchId: "linear-profiles" | "slack-names" }>,
  managedChange: ManagedChange | undefined,
) {
  if (branch.sourceFingerprint !== branch.reviewed?.sourceFingerprint)
    throw new Error(SIGNED_PIN_MISSING);
  if (
    managedChange?.actionId !== `workspace-directory.${branch.branchId}` ||
    managedChange.resource.type !== branch.branchId ||
    managedChange.resource.id !==
      reviewedNameSourceIdentity(branch.reviewed).providerAccountId ||
    !sameJson(
      managedChange.before,
      reviewedNameManagedSlice(branch.reviewed, "pending"),
    ) ||
    !sameJson(
      managedChange.after,
      reviewedNameManagedSlice(branch.reviewed, "converged"),
    )
  )
    throw new Error("workspace_branch_name_pin_mismatch");
  return SOURCE_IDENTITY.parse(reviewedNameSourceIdentity(branch.reviewed));
}

function driveSourceIdentity(
  branch: Extract<
    Branch,
    { branchId: "drive-org-chart"; execution: "managed" }
  >,
  change?: ManagedChange,
) {
  if (branch.fileId === undefined || change === undefined)
    throw new Error(SIGNED_PIN_MISSING);
  if (
    change.actionId !== "workspace-directory.drive-org-chart" ||
    change.resource.type !== "google-drive-file" ||
    change.resource.id !== branch.fileId ||
    !sameJson(change.before, {
      fileId: branch.fileId,
      sha256: branch.currentSha256,
    }) ||
    !sameJson(change.after, {
      fileId: branch.fileId,
      sha256: branch.desiredSha256,
    })
  )
    throw new Error("workspace_branch_drive_target_pin_mismatch");
  return SOURCE_IDENTITY.parse({
    kind: "resource",
    systemId: "google-drive",
    resourceId: branch.fileId,
  });
}
