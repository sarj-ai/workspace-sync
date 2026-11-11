import type { WorkspaceDirectoryPlan } from "./contracts.ts";
import { getWorkspaceExecutionPolicy } from "./get-workspace-execution-policy.ts";

type SlackAccessPlan = WorkspaceDirectoryPlan["branches"][2];

export function slackAccessLifecycleCounts(access: SlackAccessPlan) {
  const expectedNoTeamAssignmentIdentities = new Set(
    getWorkspaceExecutionPolicy().expectedNoTeamAssignmentIdentities,
  );
  return {
    nonstandardPublicChannels:
      access.lifecycle.nonstandardPublicChannels.length,
    privateChannelRenames:
      access.lifecycle.privateChannelRenameCandidates.length,
    teamChannelCollisions: access.lifecycle.slackTeamChannelCollisions.length,
    unclassifiedGoogleTeams:
      access.lifecycle.googleTeamGroupsOutsideAssignmentAllowlist.length,
    usersNeedingAssignments:
      access.lifecycle.slackUsersWithoutTeamAssignment.filter(
        ({ identity }) =>
          identity === null ||
          !expectedNoTeamAssignmentIdentities.has(identity),
      ).length,
    verticalRetirements: access.lifecycle.verticalRetirementCandidates.length,
  };
}

/*
 * Returns whether an audit-only branch observed provider drift.
 *
 * Diagnostics are deliberately excluded: readiness warnings are reported by
 * their branch but are not desired-state drift. Managed branches are also
 * excluded because their selected changes are represented in the signed
 * operation plan.
 */
export function workspaceDirectoryHasAuditOnlyFindings(
  plan: WorkspaceDirectoryPlan,
): boolean {
  return plan.branches.some((branch) => {
    switch (branch.branchId) {
      case "slack-profiles":
        return branch.execution === "audit-only" && branch.changes.length > 0;
      case "slack-groups-channels":
        return (
          branch.execution === "audit-only" &&
          (branch.additions.length > 0 ||
            branch.removals.length > 0 ||
            branch.channelRenames.length > 0 ||
            branch.userGroups.some(({ status }) => status !== "in_sync") ||
            Object.values(slackAccessLifecycleCounts(branch)).some(
              (count) => count > 0,
            ))
        );
      case "github-access":
        return (
          branch.execution === "audit-only" && branch.proposedChanges.length > 0
        );
      case "trycomp-people":
        return (
          branch.execution === "audit-only" &&
          branch.reviewedPlan.plan.actions.length > 0
        );
      case "google-group-cleanup":
      case "pagerduty-teams":
      case "sentry-memberships":
        return branch.execution === "audit-only" && branch.reviewed !== null;
      case "access-guard":
      case "drive-org-chart":
      case "identity-provisioning":
      case "linear-profiles":
      case "slack-names":
        return false;
      default: {
        const exhaustive: never = branch;
        return exhaustive;
      }
    }
  });
}
