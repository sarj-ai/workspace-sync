import type { PreparedOperationApply } from "./kernel.ts";
import type { OperationWorkflowStatus } from "./workflow-status.ts";

export interface OperationPrincipal {
  authorizationScopes: string[];
  id: string;
  roles: string[];
  via: string;
}
export interface WorkflowApplyAccepted {
  authorizedActionIds: string[];
  instanceId: string;
  planHash: string;
  state: "accepted";
}
export interface OperationWorkflowExecutor {
  apply(request: {
    prepared: Extract<PreparedOperationApply, { ok: true }>;
    principal: OperationPrincipal;
  }): Promise<WorkflowApplyAccepted>;
  status(request: {
    instanceId: string;
    principal: OperationPrincipal;
  }): Promise<OperationWorkflowStatus>;
}
