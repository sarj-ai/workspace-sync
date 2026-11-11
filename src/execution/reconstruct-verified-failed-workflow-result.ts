import { dequal } from "dequal";

import { sha256Hex } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import {
  type WorkspaceDirectoryPlan,
  type WorkspaceDirectoryWorkflowResult,
  WorkspaceDirectoryWorkflowResultSchema,
} from "./contracts.ts";
import {
  type WorkspaceScheduleAppliedRecovery,
  type WorkspaceScheduleTick,
  WorkspaceScheduleTickSchema,
} from "./schedule-health-contracts.ts";
import {
  managedBranchActionId,
  parseSuccessfulWorkflowResult,
  workspaceDirectoryExecutionId,
} from "./workflow.ts";

const INVALID_RECOVERY = "workspace_verified_failed_result_recovery_invalid";

/* Rebuilds a successful result solely from immutable plan data and durable verified attempts. */
export async function reconstructVerifiedFailedWorkflowResult(
  raw: WorkspaceScheduleTick,
): Promise<WorkspaceDirectoryWorkflowResult> {
  let tick: WorkspaceScheduleTick;
  try {
    tick = WorkspaceScheduleTickSchema.parse(raw);
  } catch (cause) {
    throw new Error(INVALID_RECOVERY, { cause });
  }
  if (
    tick.phase !== "terminal" ||
    tick.outcome !== "failed" ||
    tick.mode !== "live" ||
    tick.execution?.result !== null ||
    tick.executionReceipts !== undefined ||
    tick.workflowId === null ||
    tick.planHash === null
  )
    throw new Error(INVALID_RECOVERY);

  const { execution } = tick;
  const { params } = execution;
  if (
    params.requestedBy !== "scheduled:workspace-directory" ||
    params.scheduledTickId !== tick.tickId ||
    params.planHash !== tick.planHash ||
    execution.paramsDigest !==
      (await sha256Hex(JsonValueSchema.parse(params))) ||
    tick.workflowId !== (await workspaceDirectoryExecutionId(params))
  )
    throw new Error(INVALID_RECOVERY);

  const attempts = tick.branchAttempts ?? [];
  if (
    params.authorizedActionIds.length === 0 ||
    attempts.length !== params.authorizedActionIds.length
  )
    throw new Error(INVALID_RECOVERY);
  const byBranch = new Map(
    attempts.map((attempt) => [attempt.branchId, attempt]),
  );
  if (
    byBranch.size !== attempts.length ||
    attempts.some(({ state }) => state !== "verified")
  )
    throw new Error(INVALID_RECOVERY);

  const branches = params.plan.branches.map((branch) => {
    const actionId = managedBranchActionId(branch.branchId);
    const authorized =
      actionId !== null && params.authorizedActionIds.includes(actionId);
    const attempt = byBranch.get(branch.branchId);
    if (authorized) {
      if (
        branch.execution !== "managed" ||
        attempt?.state !== "verified" ||
        attempt.actionId !== actionId
      )
        throw new Error(INVALID_RECOVERY);
      byBranch.delete(branch.branchId);
      return attempt.result;
    }
    if (attempt !== undefined) throw new Error(INVALID_RECOVERY);
    return unattemptedResult(branch);
  });
  if (byBranch.size !== 0) throw new Error(INVALID_RECOVERY);

  const parsed = WorkspaceDirectoryWorkflowResultSchema.safeParse({
    authorizedActionIds: params.authorizedActionIds,
    branches,
    executionId: tick.workflowId,
    planHash: tick.planHash,
  });
  if (!parsed.success)
    throw new Error(INVALID_RECOVERY, { cause: parsed.error });
  const result = parsed.data;
  if (
    parseSuccessfulWorkflowResult(
      result,
      params.plan,
      params.planHash,
      tick.workflowId,
      params.authorizedActionIds,
    ) === null
  )
    throw new Error(INVALID_RECOVERY);
  return result;
}

/* Returns the exact failed evidence represented by either side of the recovery transition. */
export async function verifiedAttemptRecoverySourceTick(
  raw: WorkspaceScheduleTick,
): Promise<WorkspaceScheduleTick> {
  const tick = WorkspaceScheduleTickSchema.parse(raw);
  if (tick.phase === "terminal" && tick.outcome === "failed") {
    await reconstructVerifiedFailedWorkflowResult(tick);
    return tick;
  }
  if (
    tick.phase !== "terminal" ||
    tick.outcome !== "applied" ||
    tick.recovery === undefined ||
    tick.execution === undefined
  )
    throw new Error(INVALID_RECOVERY);
  const recovery: WorkspaceScheduleAppliedRecovery = tick.recovery;
  const {
    executionReceipts: _receipts,
    recovery: _recovery,
    ...applied
  } = tick;
  const failed = WorkspaceScheduleTickSchema.parse({
    ...applied,
    completedAtMs: recovery.priorCompletedAtMs,
    execution: { ...tick.execution, result: null },
    outcome: recovery.priorOutcome,
    receipt: recovery.priorReceipt,
  });
  const expected = await reconstructVerifiedFailedWorkflowResult(failed);
  if (!dequal(tick.execution.result, expected))
    throw new Error(INVALID_RECOVERY);
  return failed;
}

export async function isExactAppliedRecoveryReplay(
  tick: WorkspaceScheduleTick,
): Promise<boolean> {
  if (
    tick.phase !== "terminal" ||
    tick.outcome !== "applied" ||
    tick.recovery === undefined
  )
    return false;
  try {
    await verifiedAttemptRecoverySourceTick(tick);
    return true;
  } catch {
    return false;
  }
}

function unattemptedResult(
  branch: WorkspaceDirectoryPlan["branches"][number],
): WorkspaceDirectoryWorkflowResult["branches"][number] {
  const detail = "Recovered from the signed plan without a provider attempt.";
  if (branch.execution === "managed")
    return {
      branchId: branch.branchId,
      detail,
      execution: "managed",
      state: "skipped",
    };
  if (branch.execution === "audit-only")
    return {
      branchId: branch.branchId,
      detail,
      execution: "audit-only",
      state: "audited",
    };
  return {
    branchId: branch.branchId,
    detail,
    execution: "disabled",
    state: "disabled",
  };
}
