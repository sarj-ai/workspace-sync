import { getWorkspaceSyncPolicy } from "../configuration.ts";
export function getWorkspaceExecutionPolicy() {
  const execution = getWorkspaceSyncPolicy().execution;
  if (execution === null)
    throw new Error("workspace_sync_execution_not_configured");
  return execution;
}

export type WorkspaceRuntimePolicy = ReturnType<
  typeof getWorkspaceExecutionPolicy
>["accessGuard"];
