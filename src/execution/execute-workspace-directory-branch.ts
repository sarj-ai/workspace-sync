import type { GithubDispatchClaim } from "../identity-provisioning/github-zero-dispatch.ts";
import type {
  WorkspaceDirectoryAuthorizedActionId,
  WorkspaceDirectoryWorkflowParams,
  WorkspaceDirectoryWorkflowResult,
} from "./contracts.ts";
import { WORKSPACE_DIRECTORY_ACTION_IDS } from "./contracts.ts";
import {
  WORKSPACE_DIRECTORY_DRIVE_ORG_CHART_ACTION_ID,
  WORKSPACE_DIRECTORY_FANOUT_ACTION_ID,
  WORKSPACE_DIRECTORY_GITHUB_ACCESS_ACTION_ID,
  WORKSPACE_DIRECTORY_LINEAR_SUSPENSIONS_ACTION_ID,
  WORKSPACE_DIRECTORY_SLACK_GROUPS_CHANNELS_ACTION_ID,
  WORKSPACE_DIRECTORY_SLACK_PROFILES_ACTION_ID,
} from "./operation.ts";
import type { WorkspaceDirectoryRuntime } from "./runtime-contract.ts";

type WorkflowRuntime = Pick<
  WorkspaceDirectoryRuntime,
  | "applyAccessGuard"
  | "applyDriveOrgChart"
  | "applyGitHubAccess"
  | "applyGoogleGroupCleanup"
  | "applyIdentityProvisioning"
  | "applyNameRepair"
  | "applyPagerDutyTeams"
  | "applySentryMemberships"
  | "applySlackGroupsChannels"
  | "applySlackProfiles"
  | "applyTrycomp"
>;
type WorkflowBranch =
  WorkspaceDirectoryWorkflowParams["plan"]["branches"][number];
type WorkflowBranchResult =
  WorkspaceDirectoryWorkflowResult["branches"][number];
type Branch<Id extends WorkflowBranch["branchId"]> = Extract<
  WorkflowBranch,
  { branchId: Id }
>;
const NAME_PARENT_ADAPTER_UNAVAILABLE =
  "workspace_directory_name_parent_adapter_unavailable";

export async function executeWorkspaceDirectoryBranch(
  runtime: WorkflowRuntime,
  params: WorkspaceDirectoryWorkflowParams,
  authorizedActionIds: ReadonlySet<WorkspaceDirectoryAuthorizedActionId>,
  branch: WorkflowBranch,
  githubDispatchClaim?: GithubDispatchClaim,
): Promise<WorkflowBranchResult> {
  switch (branch.branchId) {
    case "sentry-memberships":
      return executeSentryBranch(runtime, params, authorizedActionIds, branch);
    case "pagerduty-teams":
      return executePagerDutyBranch(
        runtime,
        params,
        authorizedActionIds,
        branch,
      );
    case "google-group-cleanup":
      if (branch.execution !== "managed") return nonManagedResult(branch);
      if (
        !authorizedActionIds.has(
          WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup,
        )
      )
        return {
          branchId: branch.branchId,
          execution: "managed",
          state: "skipped",
          detail: "No Google Group cleanup was authorized.",
        };
      if (runtime.applyGoogleGroupCleanup === undefined)
        throw new Error("workspace_google_group_cleanup_adapter_required");
      return {
        branchId: branch.branchId,
        execution: "managed",
        state: "applied",
        detail: await runtime.applyGoogleGroupCleanup(params.plan),
      };
    case "slack-names":
    case "linear-profiles":
      if (!authorizedActionIds.has(`workspace-directory.${branch.branchId}`))
        return {
          branchId: branch.branchId,
          execution: "managed",
          state: "skipped",
          detail:
            "The reviewed plan authorized no name repair; no mutation was attempted.",
        };
      if (runtime.applyNameRepair === undefined)
        throw new Error(NAME_PARENT_ADAPTER_UNAVAILABLE);
      return {
        branchId: branch.branchId,
        execution: "managed",
        state: "applied",
        detail: await runtime.applyNameRepair(params.plan, branch.branchId),
      };
    case "access-guard":
      return executeAccessGuard(runtime, params, authorizedActionIds, branch);
    case "identity-provisioning":
      return executeIdentityProvisioning(
        runtime,
        params,
        authorizedActionIds,
        branch,
      );
    case "drive-org-chart":
      return executeDriveOrgChart(runtime, params, authorizedActionIds, branch);
    case "slack-groups-channels":
      return executeSlackGroupsChannels(
        runtime,
        params,
        authorizedActionIds,
        branch,
      );
    case "slack-profiles":
      return executeSlackProfiles(runtime, params, authorizedActionIds, branch);
    case "github-access":
      return executeGitHubAccess(
        runtime,
        params,
        authorizedActionIds,
        branch,
        githubDispatchClaim,
      );
    case "trycomp-people":
      return executeTrycomp(runtime, params, authorizedActionIds, branch);
  }
}

async function executeTrycomp(
  runtime: WorkflowRuntime,
  params: WorkspaceDirectoryWorkflowParams,
  authorizedActionIds: ReadonlySet<WorkspaceDirectoryAuthorizedActionId>,
  branch: Branch<"trycomp-people">,
): Promise<WorkflowBranchResult> {
  if (branch.execution !== "managed") return nonManagedResult(branch);
  const authorized = authorizedActionIds.has(
    WORKSPACE_DIRECTORY_ACTION_IDS.trycompPeople,
  );
  return {
    branchId: branch.branchId,
    detail: authorized
      ? await runtime.applyTrycomp(params.plan)
      : "The reviewed plan authorized no Trycomp people action; no mutation was attempted.",
    execution: branch.execution,
    state: authorized ? "applied" : "skipped",
  };
}

async function executeGitHubAccess(
  runtime: WorkflowRuntime,
  params: WorkspaceDirectoryWorkflowParams,
  authorizedActionIds: ReadonlySet<WorkspaceDirectoryAuthorizedActionId>,
  branch: Branch<"github-access">,
  githubDispatchClaim?: GithubDispatchClaim,
): Promise<WorkflowBranchResult> {
  if (branch.execution !== "managed") return nonManagedResult(branch);
  const authorized = authorizedActionIds.has(
    WORKSPACE_DIRECTORY_GITHUB_ACCESS_ACTION_ID,
  );
  return {
    branchId: branch.branchId,
    detail: authorized
      ? await runtime.applyGitHubAccess(params.plan, githubDispatchClaim)
      : "The reviewed plan authorized no GitHub access action; no mutation was attempted.",
    execution: branch.execution,
    state: authorized ? "applied" : "skipped",
  };
}

async function executeSlackProfiles(
  runtime: WorkflowRuntime,
  params: WorkspaceDirectoryWorkflowParams,
  authorizedActionIds: ReadonlySet<WorkspaceDirectoryAuthorizedActionId>,
  branch: Branch<"slack-profiles">,
): Promise<WorkflowBranchResult> {
  if (branch.execution !== "managed") return nonManagedResult(branch);
  const authorized = authorizedActionIds.has(
    WORKSPACE_DIRECTORY_SLACK_PROFILES_ACTION_ID,
  );
  return {
    branchId: branch.branchId,
    detail: authorized
      ? await runtime.applySlackProfiles(params.plan)
      : "The reviewed plan authorized no Slack profile action; no mutation was attempted.",
    execution: branch.execution,
    state: authorized ? "applied" : "skipped",
  };
}

async function executeAccessGuard(
  runtime: WorkflowRuntime,
  params: WorkspaceDirectoryWorkflowParams,
  authorizedActionIds: ReadonlySet<WorkspaceDirectoryAuthorizedActionId>,
  branch: Branch<"access-guard">,
): Promise<WorkflowBranchResult> {
  if (branch.execution !== "managed") return nonManagedResult(branch);
  const authorized = authorizedActionIds.has(
    WORKSPACE_DIRECTORY_LINEAR_SUSPENSIONS_ACTION_ID,
  );
  return {
    branchId: branch.branchId,
    detail: authorized
      ? await runtime.applyAccessGuard(params.plan)
      : "The reviewed plan authorized no Linear suspension action; no mutation was attempted.",
    execution: branch.execution,
    state: authorized ? "applied" : "skipped",
  };
}

async function executeIdentityProvisioning(
  runtime: WorkflowRuntime,
  params: WorkspaceDirectoryWorkflowParams,
  authorizedActionIds: ReadonlySet<WorkspaceDirectoryAuthorizedActionId>,
  branch: Branch<"identity-provisioning">,
): Promise<WorkflowBranchResult> {
  const authorized = authorizedActionIds.has(
    WORKSPACE_DIRECTORY_FANOUT_ACTION_ID,
  );
  return {
    branchId: branch.branchId,
    detail: authorized
      ? await runtime.applyIdentityProvisioning(params.plan)
      : "The managed Google identity target was already converged during preflight; no mutation was attempted.",
    execution: branch.execution,
    state: authorized ? "applied" : "skipped",
  };
}

async function executeDriveOrgChart(
  runtime: WorkflowRuntime,
  params: WorkspaceDirectoryWorkflowParams,
  authorizedActionIds: ReadonlySet<WorkspaceDirectoryAuthorizedActionId>,
  branch: Branch<"drive-org-chart">,
): Promise<WorkflowBranchResult> {
  if (branch.execution !== "managed") return nonManagedResult(branch);
  const authorized = authorizedActionIds.has(
    WORKSPACE_DIRECTORY_DRIVE_ORG_CHART_ACTION_ID,
  );
  return {
    branchId: branch.branchId,
    detail: authorized
      ? await runtime.applyDriveOrgChart(params.plan)
      : "The organization chart was already converged during preflight; no mutation was attempted.",
    execution: branch.execution,
    state: authorized ? "applied" : "skipped",
  };
}

async function executeSlackGroupsChannels(
  runtime: WorkflowRuntime,
  params: WorkspaceDirectoryWorkflowParams,
  authorizedActionIds: ReadonlySet<WorkspaceDirectoryAuthorizedActionId>,
  branch: Branch<"slack-groups-channels">,
): Promise<WorkflowBranchResult> {
  if (branch.execution !== "managed") return nonManagedResult(branch);
  const authorized = authorizedActionIds.has(
    WORKSPACE_DIRECTORY_SLACK_GROUPS_CHANNELS_ACTION_ID,
  );
  return {
    branchId: branch.branchId,
    detail: authorized
      ? await runtime.applySlackGroupsChannels(params.plan)
      : "The reviewed plan authorized no Slack access action; no mutation was attempted.",
    execution: branch.execution,
    state: authorized ? "applied" : "skipped",
  };
}

function nonManagedResult(branch: WorkflowBranch): WorkflowBranchResult {
  if (branch.execution === "disabled") {
    return {
      branchId: branch.branchId,
      detail: branchDetail(branch),
      execution: branch.execution,
      state: "disabled",
    };
  }
  if (branch.execution === "audit-only") {
    return {
      branchId: branch.branchId,
      detail: branchDetail(branch),
      execution: branch.execution,
      state: "audited",
    };
  }
  throw new Error(
    `workspace_directory_managed_branch_handler_missing:${branch.branchId}`,
  );
}

async function executePagerDutyBranch(
  runtime: WorkflowRuntime,
  params: WorkspaceDirectoryWorkflowParams,
  authorizedActionIds: ReadonlySet<WorkspaceDirectoryAuthorizedActionId>,
  branch: Branch<"pagerduty-teams">,
): Promise<WorkflowBranchResult> {
  if (branch.execution !== "managed") return nonManagedResult(branch);
  if (!authorizedActionIds.has(WORKSPACE_DIRECTORY_ACTION_IDS.pagerDutyTeams))
    return {
      branchId: branch.branchId,
      execution: "managed",
      state: "skipped",
      detail: "No PagerDuty team membership was authorized.",
    };
  if (runtime.applyPagerDutyTeams === undefined)
    throw new Error("workspace_pagerduty_teams_adapter_required");
  return {
    branchId: branch.branchId,
    execution: "managed",
    state: "applied",
    detail: await runtime.applyPagerDutyTeams(params.plan),
  };
}

async function executeSentryBranch(
  runtime: WorkflowRuntime,
  params: WorkspaceDirectoryWorkflowParams,
  authorizedActionIds: ReadonlySet<WorkspaceDirectoryAuthorizedActionId>,
  branch: Branch<"sentry-memberships">,
): Promise<WorkflowBranchResult> {
  if (branch.execution !== "managed") return nonManagedResult(branch);
  if (
    !authorizedActionIds.has(WORKSPACE_DIRECTORY_ACTION_IDS.sentryMemberships)
  ) {
    return {
      branchId: branch.branchId,
      detail: "No Sentry membership was authorized.",
      execution: "managed",
      state: "skipped",
    };
  }
  if (runtime.applySentryMemberships === undefined) {
    throw new Error("workspace_sentry_adapter_required");
  }
  return {
    branchId: branch.branchId,
    detail: await runtime.applySentryMemberships(params.plan),
    execution: "managed",
    state: "applied",
  };
}

function branchDetail(branch: WorkflowBranch): string {
  switch (branch.branchId) {
    case "sentry-memberships":
      return "Sentry membership reconciliation is disabled; no membership write was attempted.";
    case "pagerduty-teams":
      return "PagerDuty team membership is not managed; no membership write was attempted.";
    case "google-group-cleanup":
      return "Google Group cleanup is not managed; no membership removal was attempted.";
    case "slack-names":
    case "linear-profiles":
      throw new Error(NAME_PARENT_ADAPTER_UNAVAILABLE);
    case "slack-profiles":
      return `Audited ${String(branch.changes.length)} Google-derived Slack profile changes; no mutation was attempted.`;
    case "drive-org-chart":
      return `Audited desired org chart ${branch.desiredSha256 ?? "unavailable"}.`;
    case "slack-groups-channels":
      return `Audited ${String(branch.additions.length)} additions, ${String(branch.removals.length)} removals, and ${String(branch.channelRenames.length)} renames.`;
    case "github-access":
      return branch.execution === "audit-only"
        ? `Audited ${String(branch.proposedChanges.length)} proposed GitHub access changes.`
        : "GitHub access is disabled; no mutation was attempted.";
    case "access-guard":
      return "Access Guard is disabled; no Linear mutation was attempted.";
    case "identity-provisioning":
      return "Google identity schema is disabled; no mutation was attempted.";
    case "trycomp-people":
      return branch.execution === "audit-only"
        ? `Audited ${String(branch.reviewedPlan.plan.actions.length)} Trycomp people changes; no mutation was attempted.`
        : "Trycomp people sync is disabled; no mutation was attempted.";
  }
}
