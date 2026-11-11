import { sameJson } from "../operations/canonical.ts";
import type { PreparedOperationApply } from "../operations/kernel.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import type { OperationWorkflowExecutor } from "../operations/workflow-executor.ts";
import {
  WORKSPACE_DIRECTORY_ACTION_IDS,
  type WorkspaceDirectoryAuthorizedActionId,
  WorkspaceDirectoryAuthorizedActionIdSchema,
  type WorkspaceDirectoryChangeDetails,
  WorkspaceDirectoryChangeDetailsSchema,
  type WorkspaceDirectoryPlan,
  WorkspaceDirectoryWorkflowParamsSchema,
} from "./contracts.ts";
import {
  launchWorkspaceDirectoryWorkflow,
  readWorkspaceDirectoryWorkflowStatus,
  type WorkspaceDirectoryWorkflowBinding,
} from "./workflow.ts";

type PreparedApply = Extract<PreparedOperationApply, { ok: true }>;

const EXPECTED_DETAILS_KIND_BY_ACTION_ID = {
  [WORKSPACE_DIRECTORY_ACTION_IDS.driveOrgChart]: "drive-org-chart",
  [WORKSPACE_DIRECTORY_ACTION_IDS.fanout]: "fanout",
  [WORKSPACE_DIRECTORY_ACTION_IDS.githubAccess]: "github-access",
  [WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup]: "google-group-cleanup",
  [WORKSPACE_DIRECTORY_ACTION_IDS.linearProfiles]: "linear-profiles",
  [WORKSPACE_DIRECTORY_ACTION_IDS.linearSuspensions]: "linear-suspensions",
  [WORKSPACE_DIRECTORY_ACTION_IDS.pagerDutyTeams]: "pagerduty-teams",
  [WORKSPACE_DIRECTORY_ACTION_IDS.sentryMemberships]: "sentry-memberships",
  [WORKSPACE_DIRECTORY_ACTION_IDS.slackGroupsChannels]: "slack-groups-channels",
  [WORKSPACE_DIRECTORY_ACTION_IDS.slackNames]: "slack-names",
  [WORKSPACE_DIRECTORY_ACTION_IDS.slackProfiles]: "slack-profiles",
  [WORKSPACE_DIRECTORY_ACTION_IDS.trycompPeople]: "trycomp-people",
} as const satisfies Readonly<
  Record<
    WorkspaceDirectoryAuthorizedActionId,
    WorkspaceDirectoryChangeDetails["kind"]
  >
>;

export function createWorkspaceDirectoryWorkflowExecutor(
  binding: WorkspaceDirectoryWorkflowBinding,
): OperationWorkflowExecutor {
  return {
    apply: async ({ prepared, principal }) => {
      const plan = workspaceDirectoryPlanFromPending(prepared);
      return launchWorkspaceDirectoryWorkflow(
        binding,
        WorkspaceDirectoryWorkflowParamsSchema.parse({
          authorizedActionIds: prepared.pending.map(({ actionId }) => actionId),
          plan,
          planGeneratedAt: prepared.plan.generatedAt,
          planHash: prepared.plan.planHash,
          requestedBy: principal.id,
        }),
      );
    },
    status: ({ instanceId }) =>
      readWorkspaceDirectoryWorkflowStatus(binding, instanceId),
  };
}

export function workspaceDirectoryPlanFromPending(
  prepared: Pick<PreparedApply, "pending">,
): WorkspaceDirectoryPlan {
  let plan: undefined | WorkspaceDirectoryPlan;
  for (const change of prepared.pending) {
    const parsed = WorkspaceDirectoryChangeDetailsSchema.safeParse(
      change.details,
    );
    if (!parsed.success)
      throw new Error("workspace_directory_plan_carrier_invalid");
    const actionId = WorkspaceDirectoryAuthorizedActionIdSchema.safeParse(
      change.actionId,
    );
    if (!actionId.success)
      throw new Error("workspace_directory_plan_carrier_action_id_invalid");
    const expectedKind = EXPECTED_DETAILS_KIND_BY_ACTION_ID[actionId.data];
    if (parsed.data.kind !== expectedKind)
      throw new Error("workspace_directory_plan_carrier_kind_mismatch");
    if (!("plan" in parsed.data) || parsed.data.plan === undefined)
      throw new Error("workspace_directory_plan_carrier_missing");
    if (
      plan !== undefined &&
      !sameJson(
        JsonValueSchema.parse(plan),
        JsonValueSchema.parse(parsed.data.plan),
      )
    )
      throw new Error("workspace_directory_plan_carrier_mismatch");
    plan = parsed.data.plan;
  }
  if (plan === undefined)
    throw new Error("workspace_directory_plan_carrier_missing");
  return plan;
}
