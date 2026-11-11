import { sameJson, sha256Hex } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import type { WorkspaceDirectoryWorkflowParams } from "./contracts.ts";
import type { WorkspaceScheduleExecution } from "./schedule-health-contracts.ts";

export async function assertWorkspaceExecutionResume(
  execution: WorkspaceScheduleExecution,
  params: WorkspaceDirectoryWorkflowParams,
): Promise<void> {
  if (
    execution.result !== null ||
    execution.paramsDigest !==
      (await sha256Hex(JsonValueSchema.parse(params))) ||
    !sameJson(
      JsonValueSchema.parse(execution.params),
      JsonValueSchema.parse(params),
    )
  )
    throw new Error("workspace_workflow_execution_resume_mismatch");
}
