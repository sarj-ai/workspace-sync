import type { WorkspaceDirectoryPlan } from "./contracts.ts";

export function workspaceDirectoryOperationDiagnostics(
  plan: {
    readonly branches: readonly WorkspaceDirectoryPlan["branches"][number][];
  },
  includedActionIds: null | ReadonlySet<string>,
) {
  return plan.branches.flatMap((branch) =>
    branch.diagnostics.flatMap((diagnostic) => {
      if (
        diagnostic.scope?.kind === "action" &&
        includedActionIds !== null &&
        !includedActionIds.has(diagnostic.scope.actionId)
      ) {
        return [];
      }
      const shouldDowngrade =
        diagnostic.severity === "blocker" && diagnostic.scope?.kind === "audit";
      const { scope: _scope, ...operationDiagnostic } = diagnostic;
      return {
        ...operationDiagnostic,
        ...(diagnostic.scope?.kind === "action" && {
          actionId: diagnostic.scope.actionId,
        }),
        severity: shouldDowngrade ? ("warning" as const) : diagnostic.severity,
      };
    }),
  );
}
