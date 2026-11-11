import { dequal } from "dequal";

import { canApplyLinearPlan } from "../access-guard/issue-set.ts";
import type { SignedOperationPlan } from "../operations/schemas.ts";
import {
  WORKSPACE_DIRECTORY_ACTION_IDS,
  WorkspaceDirectoryChangeDetailsSchema,
  type WorkspaceDirectoryPlan,
} from "./contracts.ts";

export function isScheduledLinearSuspension(
  signedPlan: SignedOperationPlan,
  directoryPlan: WorkspaceDirectoryPlan,
  enabled: boolean,
): boolean {
  const branch = directoryPlan.branches[4];
  if (
    !enabled ||
    signedPlan.plan.actor.id !== "scheduled:workspace-directory" ||
    branch.execution !== "managed" ||
    branch.scheduledLinearSuspension !== true ||
    branch.reviewedLinearSuspension !== undefined ||
    branch.plan.actions.length !== 1 ||
    !canApplyLinearPlan(branch.plan) ||
    branch.diagnostics.some(
      ({ severity, scope }) =>
        severity === "blocker" && scope?.kind !== "audit",
    )
  )
    return false;
  const action = branch.plan.actions[0];
  const changes = signedPlan.plan.changes.filter(
    ({ actionId }) =>
      actionId === WORKSPACE_DIRECTORY_ACTION_IDS.linearSuspensions,
  );
  const change = changes.length === 1 ? changes[0] : undefined;
  if (
    action === undefined ||
    change === undefined ||
    !directoryPlan.branches[5].subjects.some(
      (subject) =>
        subject.googleUserId === action.googleUserId &&
        subject.lifecycle !== "active",
    )
  )
    return false;
  const details = WorkspaceDirectoryChangeDetailsSchema.safeParse(
    change.details,
  );
  const slice = (active: boolean) => [
    { accountId: action.accountId, active, email: action.email },
  ];
  return (
    change.kind === "remove" &&
    change.risk === "high" &&
    change.resource.type === "linear-access" &&
    change.resource.id === "suspensions" &&
    change.confirmationCounts?.linearSuspensions === 1 &&
    dequal(change.before, slice(true)) &&
    dequal(change.after, slice(false)) &&
    details.success &&
    details.data.kind === "linear-suspensions" &&
    dequal(details.data.actions, branch.plan.actions) &&
    dequal(details.data.plan, directoryPlan)
  );
}
