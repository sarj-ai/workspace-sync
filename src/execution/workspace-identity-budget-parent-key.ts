import type { D1Database } from "@cloudflare/workers-types";

import { identityBudgetParentKey } from "../identity-provisioning/identity-budget-contracts.ts";
import type { WorkspaceDirectoryWorkflowParams } from "./contracts.ts";
import { workspaceDirectoryExecutionId } from "./workflow.ts";
import { WorkspaceScheduleHealthRepository } from "./workspace-schedule-health-repository.ts";

export async function workspaceIdentityBudgetParentKey(
  database: D1Database,
  params: WorkspaceDirectoryWorkflowParams,
) {
  const executionId = await workspaceDirectoryExecutionId(params);
  if (params.scheduledTickId === undefined)
    return identityBudgetParentKey({
      kind: "workflow",
      workflowExecutionId: executionId,
    });
  const tick = await new WorkspaceScheduleHealthRepository(database).read(
    params.scheduledTickId,
  );
  if (
    params.requestedBy !== "scheduled:workspace-directory" ||
    tick.phase !== "launched" ||
    tick.workflowId !== executionId ||
    tick.planHash !== params.planHash
  )
    throw new Error("workspace_identity_budget_parent_mismatch");
  return identityBudgetParentKey({
    kind: "scheduled",
    scheduleId: "organization-sync",
    scheduledAtMs: tick.scheduledAtMs,
  });
}
