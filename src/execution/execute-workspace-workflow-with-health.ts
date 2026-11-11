import { getWorkspaceSyncPolicy } from "../configuration.ts";
import { sha256Hex } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import { D1WorkspaceLedgerHistoryIndex } from "../workspace-directory/d1-workspace-ledger-history-index.ts";
import { assertWorkspaceExecutionResume } from "./assert-workspace-execution-resume.ts";
import type { WorkspaceExecutionBindings as WorkerEnv } from "./bindings.ts";
import { WorkspaceDirectoryChangeLedger } from "./change-ledger.ts";
import type {
  WorkspaceDirectoryWorkflowParams,
  WorkspaceDirectoryWorkflowResult,
} from "./contracts.ts";
import { createWorkspaceScheduledTerminalReceiptVerifier } from "./create-workspace-scheduled-terminal-receipt-verifier.ts";
import { getWorkspaceExecutionPolicy } from "./get-workspace-execution-policy.ts";
import type {
  WorkspaceScheduleExecutionReceipts,
  WorkspaceScheduleTick,
} from "./schedule-health-contracts.ts";
import { WorkspaceDirectoryPlanApplyLedger } from "./slack-plan-apply-ledger.ts";
import {
  parseSuccessfulWorkflowResult,
  workspaceDirectoryExecutionId,
} from "./workflow.ts";
import { WorkspaceProviderResultError } from "./workspace-provider-result-error.ts";
import {
  WorkspaceScheduleExecutionIdentitySchema,
  WorkspaceScheduleHealthRepository,
} from "./workspace-schedule-health-repository.ts";

const RECOVERY_EVIDENCE_MISSING =
  "workspace_workflow_recovery_evidence_missing";

export class WorkspaceExecutionFenceError extends Error {
  constructor(cause: unknown) {
    super("workspace_workflow_execution_fence_not_acquired", { cause });
    this.name = "WorkspaceExecutionFenceError";
  }
}

export async function executeWorkspaceWorkflowWithHealth(input: {
  botToken: string;
  env: Pick<WorkerEnv, "AUTOMATIONS_DB" | "CF_VERSION_METADATA">;
  execute(): Promise<WorkspaceDirectoryWorkflowResult>;
  params: WorkspaceDirectoryWorkflowParams;
}): Promise<WorkspaceDirectoryWorkflowResult> {
  const { params } = input;
  const tickId = params.scheduledTickId;
  if (tickId === undefined) return input.execute();
  const repository = new WorkspaceScheduleHealthRepository(
    input.env.AUTOMATIONS_DB,
  );
  const tick = await repository.read(tickId);
  const executionId = await workspaceDirectoryExecutionId(params);
  const changeLedger = new WorkspaceDirectoryChangeLedger({
    historyIndex: new D1WorkspaceLedgerHistoryIndex(input.env.AUTOMATIONS_DB),
    botToken: input.botToken,
    channelId: getWorkspaceExecutionPolicy().accessGuard.alertsChannelId,
    expectedChannelName:
      getWorkspaceExecutionPolicy().accessGuard.alertsChannelName,
    expectedTeamId: getWorkspaceSyncPolicy().org.expectedSlackTeamId,
  });
  if (
    isDeploymentOnlyMismatch(
      tick,
      params,
      executionId,
      input.env.CF_VERSION_METADATA,
    )
  ) {
    return failDeploymentMismatch(
      repository,
      changeLedger,
      tick,
      params,
      executionId,
    );
  }
  verifyWorkflowIdentity(
    tick,
    params,
    executionId,
    input.env.CF_VERSION_METADATA,
  );

  const ledger = new WorkspaceDirectoryPlanApplyLedger(changeLedger);
  const existingExecution = await repository.readExecution(tickId);
  if (tick.phase === "terminal") {
    if (tick.outcome === "failed") {
      await repairFailedReceipt(repository, ledger, params, executionId);
      throw new Error("workspace_workflow_terminal_failed");
    }
    return repairAppliedReceipts(
      repository,
      changeLedger,
      ledger,
      params,
      executionId,
    );
  }
  if (existingExecution !== null)
    await assertWorkspaceExecutionResume(existingExecution, params);
  let result: WorkspaceDirectoryWorkflowResult;
  try {
    result = await input.execute();
  } catch (cause) {
    if (cause instanceof WorkspaceExecutionFenceError) throw cause;
    if (cause instanceof WorkspaceProviderResultError) {
      result = cause.result;
    } else {
      await terminalizeFailedExecution(
        repository,
        ledger,
        params,
        executionId,
        cause,
      );
      throw cause;
    }
  }
  if (
    parseSuccessfulWorkflowResult(
      result,
      params.plan,
      params.planHash,
      executionId,
      params.authorizedActionIds,
    ) === null
  ) {
    const cause = new Error("workspace_workflow_health_result_mismatch");
    await terminalizeFailedExecution(
      repository,
      ledger,
      params,
      executionId,
      cause,
    );
    throw cause;
  }
  await repository.completeApplied(tickId, result);
  return repairAppliedReceipts(
    repository,
    changeLedger,
    ledger,
    params,
    executionId,
  );
}

async function failDeploymentMismatch(
  repository: WorkspaceScheduleHealthRepository,
  changeLedger: WorkspaceDirectoryChangeLedger,
  tick: WorkspaceScheduleTick,
  params: WorkspaceDirectoryWorkflowParams,
  executionId: string,
): Promise<never> {
  const tickId = tick.tickId;
  if (tick.execution !== undefined) {
    await assertWorkspaceExecutionResume(tick.execution, params);
    const cause = new Error("workspace_workflow_health_deployment_mismatch");
    await terminalizeFailedExecution(
      repository,
      new WorkspaceDirectoryPlanApplyLedger(changeLedger),
      params,
      executionId,
      cause,
    );
    throw cause;
  }
  if ((tick.branchAttempts?.length ?? 0) !== 0)
    throw new Error(RECOVERY_EVIDENCE_MISSING);
  const terminal = await repository.completeFailedNoDispatch(
    WorkspaceScheduleExecutionIdentitySchema.parse({
      tickId,
      workflowId: executionId,
    }),
  );
  const receipt =
    await createWorkspaceScheduledTerminalReceiptVerifier(changeLedger)(
      terminal,
    );
  if (receipt === null)
    throw new Error("workspace_workflow_deployment_race_receipt_missing");
  await repository.attachVerifiedReceipt(receipt);
  throw new Error("workspace_workflow_health_deployment_mismatch");
}

function isDeploymentOnlyMismatch(
  tick: WorkspaceScheduleTick,
  params: WorkspaceDirectoryWorkflowParams,
  executionId: string,
  deployment: WorkerEnv["CF_VERSION_METADATA"],
): boolean {
  return (
    params.requestedBy === "scheduled:workspace-directory" &&
    tick.tickId === params.scheduledTickId &&
    tick.phase === "launched" &&
    tick.workflowId === executionId &&
    tick.planHash === params.planHash &&
    (tick.deployment.id !== deployment.id ||
      tick.deployment.revision !== deployment.tag ||
      tick.deployment.timestamp !== deployment.timestamp)
  );
}

async function terminalizeFailedExecution(
  repository: WorkspaceScheduleHealthRepository,
  ledger: WorkspaceDirectoryPlanApplyLedger,
  params: WorkspaceDirectoryWorkflowParams,
  executionId: string,
  cause: unknown,
): Promise<void> {
  const tickId = params.scheduledTickId;
  if (tickId === undefined)
    throw new Error("workspace_workflow_health_tick_missing");
  await repository.complete(tickId, "failed");
  try {
    await repairFailedReceipt(repository, ledger, params, executionId);
  } catch (notificationError) {
    throw new AggregateError(
      [cause, notificationError],
      "workspace_workflow_health_failure_receipt_missing",
      { cause: notificationError },
    );
  }
}

function verifyWorkflowIdentity(
  tick: WorkspaceScheduleTick,
  params: WorkspaceDirectoryWorkflowParams,
  executionId: string,
  deployment: WorkerEnv["CF_VERSION_METADATA"],
): void {
  if (
    params.requestedBy !== "scheduled:workspace-directory" ||
    tick.tickId !== params.scheduledTickId ||
    (tick.phase !== "launched" &&
      !(
        tick.phase === "terminal" &&
        (tick.outcome === "applied" || tick.outcome === "failed")
      )) ||
    tick.workflowId !== executionId ||
    tick.planHash !== params.planHash ||
    tick.deployment.id !== deployment.id ||
    tick.deployment.revision !== deployment.tag ||
    tick.deployment.timestamp !== deployment.timestamp
  )
    throw new Error("workspace_workflow_health_identity_mismatch");
}

async function repairFailedReceipt(
  repository: WorkspaceScheduleHealthRepository,
  ledger: WorkspaceDirectoryPlanApplyLedger,
  params: WorkspaceDirectoryWorkflowParams,
  executionId: string,
): Promise<void> {
  const tickId = params.scheduledTickId;
  if (tickId === undefined)
    throw new Error("workspace_workflow_health_tick_missing");
  const execution = await repository.readExecution(tickId);
  if (
    execution?.result !== null ||
    execution.paramsDigest !== (await sha256Hex(JsonValueSchema.parse(params)))
  )
    throw new Error(RECOVERY_EVIDENCE_MISSING);
  const receipt = await ledger.repairFailed(params, execution.summaryHandle);
  await repository.attachVerifiedReceipt({
    channelId: receipt.channelId,
    contentHash: receipt.contentHash,
    verifiedAtMs: receipt.verifiedAtMs,
    slackTimestamp: receipt.timestamp,
    outcome: "failed",
    planHash: params.planHash,
    tickId,
    workflowId: executionId,
  });
}

async function repairAppliedReceipts(
  repository: WorkspaceScheduleHealthRepository,
  changeLedger: WorkspaceDirectoryChangeLedger,
  ledger: WorkspaceDirectoryPlanApplyLedger,
  params: WorkspaceDirectoryWorkflowParams,
  executionId: string,
): Promise<WorkspaceDirectoryWorkflowResult> {
  const tickId = params.scheduledTickId;
  if (tickId === undefined)
    throw new Error("workspace_workflow_health_tick_missing");
  const execution = await repository.readExecution(tickId);
  if (
    !execution?.result ||
    execution.paramsDigest !== (await sha256Hex(JsonValueSchema.parse(params)))
  ) {
    throw new Error(RECOVERY_EVIDENCE_MISSING);
  }
  const result = parseSuccessfulWorkflowResult(
    execution.result,
    params.plan,
    params.planHash,
    executionId,
    params.authorizedActionIds,
  );
  if (result === null)
    throw new Error("workspace_workflow_recovery_result_mismatch");
  const branchReceipts: WorkspaceScheduleExecutionReceipts["branchReceipts"] =
    [];
  for (const item of execution.branchHandles) {
    const branchResult = result.branches.find(
      ({ branchId }) => branchId === item.branchId,
    );
    if (branchResult === undefined)
      throw new Error("workspace_workflow_recovery_branch_missing");
    // eslint-disable-next-line no-await-in-loop -- Verify every original branch receipt before repairing the summary.
    const verified = await changeLedger.repairCompleted(
      item.handle,
      {
        text: `${item.change.text} · plan ${params.planHash.slice(0, 12)}`,
      },
      {
        text: `${item.change.text.replace("Workspace sync planned ·", "Workspace sync verified ·")} · ${branchResult.detail}`,
      },
    );
    branchReceipts.push({
      ...verified,
      branchId: item.branchId,
      changeKey: item.handle.changeKey,
    });
  }
  const receipt = await ledger.repairCompleted(
    params,
    result,
    execution.summaryHandle,
  );
  await repository.attachExecutionReceipts(tickId, {
    branchReceipts,
    summaryReceipt: {
      channelId: receipt.channelId,
      contentHash: receipt.contentHash,
      verifiedAtMs: receipt.verifiedAtMs,
      slackTimestamp: receipt.timestamp,
      outcome: "applied",
      planHash: params.planHash,
      tickId,
      workflowId: executionId,
    },
  });
  return result;
}
