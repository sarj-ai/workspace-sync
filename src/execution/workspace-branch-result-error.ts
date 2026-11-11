import type { WorkspaceDirectoryWorkflowResult } from "./contracts.ts";

export class WorkspaceBranchResultError extends Error {
  readonly result: WorkspaceDirectoryWorkflowResult["branches"][number];

  constructor(options: {
    cause: unknown;
    result: WorkspaceDirectoryWorkflowResult["branches"][number];
  }) {
    super("workspace_branch_result_terminal_receipt_unverified", options);
    this.name = "WorkspaceBranchResultError";
    this.result = options.result;
  }
}
