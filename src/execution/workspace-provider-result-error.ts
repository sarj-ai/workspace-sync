import type { WorkspaceDirectoryWorkflowResult } from "./contracts.ts";

export class WorkspaceProviderResultError extends Error {
  readonly result: WorkspaceDirectoryWorkflowResult;
  readonly requiresBranchReceiptRecovery: boolean;

  constructor(
    message: string,
    options: ErrorOptions & {
      requiresBranchReceiptRecovery?: boolean;
      result: WorkspaceDirectoryWorkflowResult;
    },
  ) {
    super(message, options);
    this.name = "WorkspaceProviderResultError";
    this.result = options.result;
    this.requiresBranchReceiptRecovery =
      options.requiresBranchReceiptRecovery ?? false;
  }
}
