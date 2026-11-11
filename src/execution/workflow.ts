import { z } from "zod";

import { sha256Hex } from "../operations/canonical.ts";
import {
  type OperationWorkflowStatus,
  type WorkflowProviderStatus,
  WorkflowRunConflictError,
} from "../operations/workflow-status.ts";
import {
  WORKSPACE_DIRECTORY_ACTION_IDS,
  type WorkspaceDirectoryPlan,
  type WorkspaceDirectoryWorkflowParams,
  WorkspaceDirectoryWorkflowParamsSchema,
  type WorkspaceDirectoryWorkflowResult,
  WorkspaceDirectoryWorkflowResultSchema,
} from "./contracts.ts";
import { WorkspaceDirectoryBranchIdSchema } from "./flow.ts";

const ErrorTextSchema = z.string();

type StatusResult = Promise<{
  error?: { message?: unknown; name?: unknown };
  output?: unknown;
  status: WorkflowProviderStatus;
}>;
type LaunchWorkspaceDirectoryWorkflowResult = Promise<{
  authorizedActionIds: WorkspaceDirectoryWorkflowParams["authorizedActionIds"];
  instanceId: string;
  planHash: string;
  state: "accepted";
}>;

interface WorkspaceDirectoryWorkflowInstance {
  id: string;
  status(): StatusResult;
}

export interface WorkspaceDirectoryWorkflowBinding {
  create(options: {
    id: string;
    params: WorkspaceDirectoryWorkflowParams;
  }): Promise<{ id: string }>;
  get(id: string): Promise<WorkspaceDirectoryWorkflowInstance>;
}

export async function launchWorkspaceDirectoryWorkflow(
  binding: WorkspaceDirectoryWorkflowBinding,
  params: WorkspaceDirectoryWorkflowParams,
): LaunchWorkspaceDirectoryWorkflowResult {
  const parsed = WorkspaceDirectoryWorkflowParamsSchema.parse(params);
  const executionId = await workspaceDirectoryExecutionId(parsed);
  try {
    const instance = await binding.create({ id: executionId, params: parsed });
    return {
      authorizedActionIds: parsed.authorizedActionIds,
      instanceId: instance.id,
      planHash: parsed.planHash,
      state: "accepted",
    };
  } catch (error) {
    let existing: WorkspaceDirectoryWorkflowInstance;
    let status: Awaited<
      ReturnType<WorkspaceDirectoryWorkflowInstance["status"]>
    >;
    try {
      existing = await binding.get(executionId);
      status = await existing.status();
    } catch (lookupError) {
      if (error instanceof Error && error.cause === undefined) {
        Object.defineProperty(error, "cause", { value: lookupError });
      }
      throw error;
    }
    switch (status.status) {
      case "queued":
      case "running":
      case "waiting":
        break;
      case "complete": {
        if (
          !parseSuccessfulWorkflowResult(
            status.output,
            parsed.plan,
            parsed.planHash,
            executionId,
            parsed.authorizedActionIds,
          )
        ) {
          throw error;
        }
        break;
      }
      case "errored":
      case "terminated":
      case "rollingBack":
        // A bare Cloudflare Workflow restart erases completed step state. That can replay a
        // provider mutation whose later Slack readback failed, so recovery requires a fresh plan.
        throw error;
      case "paused":
      case "waitingForPause":
        throw new WorkflowRunConflictError(status.status, { cause: error });
      case "unknown":
        throw error;
    }
    return {
      authorizedActionIds: parsed.authorizedActionIds,
      instanceId: existing.id,
      planHash: parsed.planHash,
      state: "accepted",
    };
  }
}

export async function readWorkspaceDirectoryWorkflowStatus(
  binding: WorkspaceDirectoryWorkflowBinding,
  instanceId: string,
): Promise<OperationWorkflowStatus> {
  const instance = await binding.get(instanceId);
  const status = await instance.status();
  switch (status.status) {
    case "queued":
    case "running":
    case "waiting":
    case "rollingBack":
      return {
        instanceId: instance.id,
        providerStatus: status.status,
        state: "pending",
      };
    case "paused":
    case "waitingForPause":
      return {
        instanceId: instance.id,
        providerStatus: status.status,
        state: "paused",
      };
    case "errored":
    case "terminated":
      return {
        error: sanitizedWorkflowError(status.error),
        instanceId: instance.id,
        providerStatus: status.status,
        state: "failed",
      };
    case "unknown":
      return {
        instanceId: instance.id,
        providerStatus: status.status,
        state: "unknown",
      };
    case "complete": {
      const output = parseSuccessfulWorkflowResult(
        status.output,
        undefined,
        undefined,
        instanceId,
      );
      if (!output)
        throw new Error("workspace_directory_workflow_result_mismatch");
      return {
        instanceId: instance.id,
        planHash: output.planHash,
        providerStatus: status.status,
        state: "succeeded",
        units: output.branches.map(({ branchId, state }) => ({
          id: branchId,
          state,
        })),
      };
    }
  }
}

export function parseSuccessfulWorkflowResult(
  raw: unknown,
  plan: undefined | WorkspaceDirectoryPlan,
  expectedPlanHash: string | undefined,
  expectedExecutionId?: string,
  expectedAuthorizedActionIds?: WorkspaceDirectoryWorkflowParams["authorizedActionIds"],
): null | WorkspaceDirectoryWorkflowResult {
  const parsed = WorkspaceDirectoryWorkflowResultSchema.safeParse(raw);
  if (!parsed.success) return null;
  if (
    expectedPlanHash !== undefined &&
    parsed.data.planHash !== expectedPlanHash
  )
    return null;
  const executionId = expectedExecutionId ?? parsed.data.executionId;
  if (parsed.data.executionId !== executionId) return null;
  if (
    expectedAuthorizedActionIds !== undefined &&
    !sameActionIds(parsed.data.authorizedActionIds, expectedAuthorizedActionIds)
  ) {
    return null;
  }
  const authorizedActionIds = new Set(parsed.data.authorizedActionIds);
  const expected = expectedBranchExecutions(plan);
  if (
    !alignOptionalBranchExecutions(
      parsed.data,
      plan,
      expected,
      authorizedActionIds,
    )
  )
    return null;
  return workflowBranchesMatch(parsed.data, expected, authorizedActionIds)
    ? parsed.data
    : null;
}

function alignOptionalBranchExecutions(
  result: WorkspaceDirectoryWorkflowResult,
  plan: undefined | WorkspaceDirectoryPlan,
  expected: ReturnType<typeof expectedBranchExecutions>,
  authorizedActionIds: ReadonlySet<
    WorkspaceDirectoryWorkflowParams["authorizedActionIds"][number]
  >,
): boolean {
  for (const branchId of [
    "trycomp-people",
    "slack-names",
    "linear-profiles",
    "google-group-cleanup",
    "pagerduty-teams",
    "sentry-memberships",
  ] as const) {
    if (result.branches.some((branch) => branch.branchId === branchId))
      continue;
    const actionId = managedBranchActionId(branchId);
    if (actionId !== null && authorizedActionIds.has(actionId)) return false;
    if (plan === undefined) expected.delete(branchId);
  }
  return true;
}

function expectedBranchExecutions(
  plan: undefined | WorkspaceDirectoryPlan,
): Map<
  WorkspaceDirectoryWorkflowResult["branches"][number]["branchId"],
  undefined | WorkspaceDirectoryPlan["branches"][number]["execution"]
> {
  if (plan !== undefined) {
    return new Map(
      plan.branches.map((branch) => [branch.branchId, branch.execution]),
    );
  }
  return new Map(
    WorkspaceDirectoryBranchIdSchema.options.map((branchId) => [
      branchId,
      undefined,
    ]),
  );
}

function workflowBranchesMatch(
  result: WorkspaceDirectoryWorkflowResult,
  expected: Map<
    WorkspaceDirectoryWorkflowResult["branches"][number]["branchId"],
    undefined | WorkspaceDirectoryPlan["branches"][number]["execution"]
  >,
  authorizedActionIds: ReadonlySet<
    WorkspaceDirectoryWorkflowParams["authorizedActionIds"][number]
  >,
): boolean {
  if (result.branches.length !== expected.size) return false;
  for (const branch of result.branches) {
    const expectedExecution = expected.get(branch.branchId);
    if (
      !expected.has(branch.branchId) ||
      (expectedExecution !== undefined &&
        expectedExecution !== branch.execution)
    )
      return false;
    if (
      !isExpectedState(
        branch.branchId,
        branch.execution,
        branch.state,
        authorizedActionIds,
      )
    ) {
      return false;
    }
    expected.delete(branch.branchId);
  }
  return expected.size === 0;
}

function isExpectedState(
  branchId: WorkspaceDirectoryWorkflowResult["branches"][number]["branchId"],
  execution: "audit-only" | "disabled" | "managed",
  state: WorkspaceDirectoryWorkflowResult["branches"][number]["state"],
  authorizedActionIds: ReadonlySet<
    WorkspaceDirectoryWorkflowParams["authorizedActionIds"][number]
  >,
): boolean {
  if (execution === "managed") {
    const actionId = managedBranchActionId(branchId);
    return (
      state ===
      (actionId !== null && authorizedActionIds.has(actionId)
        ? "applied"
        : "skipped")
    );
  }
  if (execution === "audit-only") return state === "audited";
  return state === "disabled";
}

export function managedBranchActionId(
  branchId: WorkspaceDirectoryWorkflowResult["branches"][number]["branchId"],
): null | WorkspaceDirectoryWorkflowParams["authorizedActionIds"][number] {
  switch (branchId) {
    case "google-group-cleanup":
      return WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup;
    case "pagerduty-teams":
      return WORKSPACE_DIRECTORY_ACTION_IDS.pagerDutyTeams;
    case "sentry-memberships":
      return WORKSPACE_DIRECTORY_ACTION_IDS.sentryMemberships;
    case "access-guard":
      return WORKSPACE_DIRECTORY_ACTION_IDS.linearSuspensions;
    case "drive-org-chart":
      return WORKSPACE_DIRECTORY_ACTION_IDS.driveOrgChart;
    case "identity-provisioning":
      return WORKSPACE_DIRECTORY_ACTION_IDS.fanout;
    case "slack-groups-channels":
      return WORKSPACE_DIRECTORY_ACTION_IDS.slackGroupsChannels;
    case "slack-profiles":
      return WORKSPACE_DIRECTORY_ACTION_IDS.slackProfiles;
    case "github-access":
      return WORKSPACE_DIRECTORY_ACTION_IDS.githubAccess;
    case "trycomp-people":
      return WORKSPACE_DIRECTORY_ACTION_IDS.trycompPeople;
    case "slack-names":
      return WORKSPACE_DIRECTORY_ACTION_IDS.slackNames;
    case "linear-profiles":
      return WORKSPACE_DIRECTORY_ACTION_IDS.linearProfiles;
  }
}

function sameActionIds(
  left: readonly string[],
  right: readonly string[],
): boolean {
  const leftIds = new Set(left);
  return (
    left.length === right.length &&
    right.every((actionId) => leftIds.has(actionId))
  );
}

function sanitizedWorkflowError(
  error: { message?: unknown; name?: unknown } | undefined,
): { message: string; name: string } | null {
  if (!error) return null;
  const parsedName = ErrorTextSchema.safeParse(error.name);
  const parsedMessage = ErrorTextSchema.safeParse(error.message);
  const name = parsedName.success ? parsedName.data.trim().slice(0, 100) : "";
  const message = parsedMessage.success
    ? parsedMessage.data.trim().slice(0, 500)
    : "";
  return name && message ? { message, name } : null;
}

export async function workspaceDirectoryExecutionId(
  params: Pick<
    WorkspaceDirectoryWorkflowParams,
    "authorizedActionIds" | "planGeneratedAt" | "planHash"
  >,
): Promise<string> {
  return sha256Hex({
    authorizedActionIds: [...params.authorizedActionIds].toSorted(
      (sortLeft, sortRight) =>
        Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
    ),
    planGeneratedAt: params.planGeneratedAt,
    planHash: params.planHash,
  });
}
