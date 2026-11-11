import { dequal } from "dequal";

import type { SignedOperationPlan } from "../operations/schemas.ts";
import {
  WORKSPACE_DIRECTORY_ACTION_IDS,
  type WorkspaceDirectoryPlan,
} from "./contracts.ts";
import {
  githubAccessAfterSlice,
  githubAccessBeforeSlice,
} from "./github-access-managed.ts";

export function isScheduledGitHubAccess(
  signedPlan: SignedOperationPlan,
  directoryPlan: WorkspaceDirectoryPlan,
  enabled: boolean,
): boolean {
  const branch = directoryPlan.branches[3];
  const changes = signedPlan.plan.changes.filter(
    ({ actionId }) => actionId === WORKSPACE_DIRECTORY_ACTION_IDS.githubAccess,
  );
  const change = changes.length === 1 ? changes[0] : undefined;
  const selected =
    branch.execution === "managed" ? branch.selectedOperation : null;
  if (
    !enabled ||
    branch.execution !== "managed" ||
    branch.diagnostics.some(({ severity }) => severity === "blocker") ||
    selected === null ||
    change === undefined
  ) {
    return false;
  }
  const additive =
    selected.operation.kind === "invite-organization-member" ||
    selected.operation.kind === "add-team-member";
  return (
    additive &&
    change.resource.type === "github-organization-access" &&
    change.resource.id === selected.googleUserId &&
    change.kind === "change" &&
    change.risk === "medium" &&
    sameJson(change.before, githubAccessBeforeSlice(branch)) &&
    sameJson(change.after, githubAccessAfterSlice(branch))
  );
}

function sameJson(left: unknown, right: unknown): boolean {
  return dequal(left, right);
}
