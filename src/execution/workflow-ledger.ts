import { logEvent } from "../shared/log-event.ts";
import { sanitizedErrorFields } from "../shared/sanitize-error.ts";
import type {
  IWorkspaceDirectoryChangeLedger,
  WorkspaceDirectoryChangeLedgerHandle,
} from "./change-ledger.ts";
import {
  type WorkspaceDirectoryWorkflowParams,
  type WorkspaceDirectoryWorkflowResult,
  WorkspaceDirectoryWorkflowResultSchema,
} from "./contracts.ts";
import type { WorkspaceDirectoryApplyReporter } from "./slack-plan-apply-ledger.ts";
import { WorkspaceBranchResultError } from "./workspace-branch-result-error.ts";
import type { WorkspaceDirectoryAnnouncedChange } from "./workspace-directory-announced-changes.ts";
import { WorkspaceProviderResultError } from "./workspace-provider-result-error.ts";

export const STEP_CONFIG = {
  retries: {
    backoff: "exponential" as const,
    delay: "5 seconds" as const,
    limit: 3,
  },
  timeout: "10 minutes",
} as const;
const TERMINAL_RECEIPT_UNVERIFIED =
  "workspace_provider_result_terminal_receipt_unverified";
export const WORKFLOW_FAILURE_ALERT_TTL_SECONDS = 24 * 60 * 60;
const MAX_ANNOUNCED_CHANGES_PER_BRANCH = 250;
const NO_WORKSPACE_DIRECTORY_BRANCH_RESULT = undefined;

export interface WorkspaceDirectoryLifecycleStep {
  do<Result>(
    name: string,
    config: typeof STEP_CONFIG,
    callback: () => Promise<Result>,
  ): Promise<Result>;
}

export function recoverWorkspaceDirectoryPlanSummary(
  step: WorkspaceDirectoryLifecycleStep,
  ledger: WorkspaceDirectoryApplyReporter,
  params: WorkspaceDirectoryWorkflowParams,
): Promise<WorkspaceDirectoryChangeLedgerHandle> {
  return step.do("workspace-directory:recover-plan-summary", STEP_CONFIG, () =>
    ledger.recover({
      authorizedActionIds: params.authorizedActionIds,
      generatedAt: params.planGeneratedAt,
      plan: params.plan,
      planHash: params.planHash,
      requestedBy: params.requestedBy,
    }),
  );
}

export async function abortWorkspaceDirectoryAnnouncements(
  step: WorkspaceDirectoryLifecycleStep,
  ledger: IWorkspaceDirectoryChangeLedger,
  handlesByBranch: ReadonlyMap<
    WorkflowBranch["branchId"],
    readonly WorkspaceDirectoryLedgerChangeHandle[]
  >,
): Promise<void> {
  await step.do(
    "workspace-directory:abort-announcements",
    STEP_CONFIG,
    async () => {
      for (const handles of handlesByBranch.values()) {
        for (const { change, handle } of handles) {
          // eslint-disable-next-line no-await-in-loop -- Every prior branch announcement must reach an exact terminal state.
          await ledger.fail(handle, {
            text: `${change.text.replace("Workspace sync planned ·", "Workspace sync aborted ·")} · a later announcement failed; no provider mutation was attempted`,
          });
        }
      }
      return NO_WORKSPACE_DIRECTORY_BRANCH_RESULT;
    },
  );
}

export async function settleWorkspaceDirectoryBranches(
  step: WorkspaceDirectoryLifecycleStep,
  planApplyLedger: WorkspaceDirectoryApplyReporter,
  summaryHandle: WorkspaceDirectoryChangeLedgerHandle,
  params: WorkspaceDirectoryWorkflowParams,
  executionId: string,
  branchPromises: readonly Promise<
    WorkspaceDirectoryWorkflowResult["branches"][number]
  >[],
  deferTerminalReceipts = false,
): Promise<WorkspaceDirectoryWorkflowResult> {
  const settledBranches = await Promise.allSettled(branchPromises);
  const branchErrors: unknown[] = [];
  const receiptErrors: unknown[] = [];
  const branchResults: WorkspaceDirectoryWorkflowResult["branches"] = [];
  for (const settled of settledBranches) {
    if (
      settled.status === "rejected" &&
      params.scheduledTickId !== undefined &&
      settled.reason instanceof WorkspaceBranchResultError
    ) {
      branchResults.push(settled.reason.result);
      receiptErrors.push(settled.reason);
    } else if (settled.status === "rejected") branchErrors.push(settled.reason);
    else branchResults.push(settled.value);
  }
  if (branchErrors.length > 0) {
    await failPlanSummary(
      step,
      planApplyLedger,
      summaryHandle,
      params,
      branchErrors.length === 1
        ? branchErrors[0]
        : new AggregateError(
            branchErrors,
            "workspace_directory_branches_failed",
          ),
    );
  }
  let result: WorkspaceDirectoryWorkflowResult;
  try {
    // eslint-disable-next-line @sarj/no-zod-parse-typed-object -- Validate action-ID uniqueness and receipt hashes before completing the ledger.
    result = WorkspaceDirectoryWorkflowResultSchema.parse({
      authorizedActionIds: params.authorizedActionIds,
      branches: branchResults,
      executionId,
      planHash: params.planHash,
    });
  } catch (error) {
    await failPlanSummary(step, planApplyLedger, summaryHandle, params, error);
    throw error;
  }
  if (receiptErrors.length > 0)
    throw new WorkspaceProviderResultError(TERMINAL_RECEIPT_UNVERIFIED, {
      cause: new AggregateError(
        receiptErrors,
        "workspace_branch_receipts_unverified",
      ),
      requiresBranchReceiptRecovery: true,
      result,
    });
  if (deferTerminalReceipts) return result;
  await completeWorkspacePlanSummary(
    step,
    planApplyLedger,
    summaryHandle,
    params,
    result,
  );
  return result;
}

async function completeWorkspacePlanSummary(
  step: WorkspaceDirectoryLifecycleStep,
  planApplyLedger: WorkspaceDirectoryApplyReporter,
  summaryHandle: WorkspaceDirectoryChangeLedgerHandle,
  params: WorkspaceDirectoryWorkflowParams,
  result: WorkspaceDirectoryWorkflowResult,
): Promise<void> {
  try {
    await step.do(
      "workspace-directory:complete-plan-summary",
      STEP_CONFIG,
      async () => {
        await planApplyLedger.complete(summaryHandle, params, result);
        return NO_WORKSPACE_DIRECTORY_BRANCH_RESULT;
      },
    );
  } catch (error) {
    if (params.scheduledTickId !== undefined)
      throw new WorkspaceProviderResultError(TERMINAL_RECEIPT_UNVERIFIED, {
        cause: error,
        result,
      });
    await failPlanSummary(step, planApplyLedger, summaryHandle, params, error);
  }
}

export async function failPlanSummary(
  step: WorkspaceDirectoryLifecycleStep,
  ledger: WorkspaceDirectoryApplyReporter,
  handle: WorkspaceDirectoryChangeLedgerHandle,
  params: WorkspaceDirectoryWorkflowParams,
  primaryError: unknown,
  relatedErrors: readonly unknown[] = [],
): Promise<never> {
  try {
    await step.do(
      "workspace-directory:fail-plan-summary",
      STEP_CONFIG,
      async () => {
        await ledger.fail(handle, params);
        return NO_WORKSPACE_DIRECTORY_BRANCH_RESULT;
      },
    );
  } catch (notificationError) {
    throw new AggregateError(
      [primaryError, ...relatedErrors, notificationError],
      "workspace_directory_failure_and_terminal_notification_failed",
      { cause: notificationError },
    );
  }
  if (relatedErrors.length > 0) {
    throw new AggregateError(
      [primaryError, ...relatedErrors],
      "workspace_directory_preannouncement_and_abort_failed",
      { cause: primaryError },
    );
  }
  throw primaryError;
}

type WorkflowBranch =
  WorkspaceDirectoryWorkflowParams["plan"]["branches"][number];
type WorkflowBranchResult =
  WorkspaceDirectoryWorkflowResult["branches"][number];

export interface WorkspaceDirectoryLedgerChangeHandle {
  change: WorkspaceDirectoryAnnouncedChange;
  handle: WorkspaceDirectoryChangeLedgerHandle;
}

export interface WorkspaceDirectoryWorkflowStep {
  do<Result extends undefined | WorkflowBranchResult>(
    name: string,
    config: typeof STEP_CONFIG,
    callback: () => Promise<Result>,
  ): Promise<Result>;
}

interface WorkspaceDirectoryFailureAlerter {
  postError(
    title: string,
    error: unknown,
    context: Record<string, string>,
    ttlSeconds: number,
  ): Promise<unknown>;
}

export async function reportWorkspaceDirectoryPreannouncementFailure(
  alerts: WorkspaceDirectoryFailureAlerter,
  error: unknown,
  context: { readonly executionId: string; readonly planHash: string },
  writeLog: typeof logEvent = logEvent,
): Promise<void> {
  writeLog("workspace_directory.workflow_preannouncement_failed", {
    ...sanitizedErrorFields(error),
    "execution_id": context.executionId,
    "plan_hash": context.planHash,
  });
  try {
    await alerts.postError(
      "Workspace directory Workflow preannouncement failed",
      error,
      { executionId: context.executionId, planHash: context.planHash },
      WORKFLOW_FAILURE_ALERT_TTL_SECONDS,
    );
  } catch (alertError) {
    writeLog("workspace_directory.workflow_preannouncement_alert_failed", {
      ...sanitizedErrorFields(alertError),
      "execution_id": context.executionId,
      "plan_hash": context.planHash,
    });
  }
}

export interface WorkspaceDirectoryHistoryStep {
  do(
    name: string,
    config: typeof STEP_CONFIG,
    callback: () => Promise<boolean>,
  ): Promise<boolean>;
}

export async function prepareWorkspaceDirectoryLedgerHistory(
  step: WorkspaceDirectoryHistoryStep,
  ledger: IWorkspaceDirectoryChangeLedger,
  stepPrefix = "workspace-directory:index-ledger-history",
): Promise<void> {
  const synchronize = ledger.synchronizeHistory?.bind(ledger);
  if (synchronize === undefined) return;
  for (let batch = 0; batch < 100; batch += 1) {
    // eslint-disable-next-line no-await-in-loop -- Every bounded batch is durable before the next history range is read.
    const complete = await step.do(
      `${stepPrefix}:${String(batch)}`,
      STEP_CONFIG,
      synchronize,
    );
    if (complete) return;
  }
  throw new Error("workspace_directory_ledger_history_index_incomplete");
}

export async function preannounceChanges(
  ledger: IWorkspaceDirectoryChangeLedger,
  planHash: string,
  changes: readonly WorkspaceDirectoryAnnouncedChange[],
  abortOnFailure = true,
): Promise<readonly WorkspaceDirectoryLedgerChangeHandle[]> {
  if (changes.length > MAX_ANNOUNCED_CHANGES_PER_BRANCH)
    throw new Error("workspace_directory_announcement_safety_limit");
  const handles: WorkspaceDirectoryLedgerChangeHandle[] = [];
  try {
    for (const change of changes) {
      // eslint-disable-next-line no-await-in-loop -- The ledger is ordered and every readback gates all provider writes.
      const handle = await ledger.preannounce({
        changeKey: `${planHash}:${change.changeKey}`,
        text: `${change.text} · plan ${planHash.slice(0, 12)}`,
        ...(!abortOnFailure && { retryFailed: false }),
      });
      handles.push({ change, handle });
    }
  } catch (announcementError) {
    if (!abortOnFailure) throw announcementError;
    const cleanupErrors: unknown[] = [];
    for (const { change, handle } of handles) {
      try {
        // eslint-disable-next-line no-await-in-loop -- Every already-written announcement must receive an exact abort state before the preflight fails.
        await ledger.fail(handle, {
          text: `${change.text.replace("Workspace sync planned ·", "Workspace sync aborted ·")} · a later announcement failed; no provider mutation was attempted`,
        });
      } catch (cleanupError) {
        cleanupErrors.push(cleanupError);
      }
    }
    if (cleanupErrors.length > 0) {
      throw new AggregateError(
        [announcementError, ...cleanupErrors],
        "workspace_directory_announcement_and_abort_ledger_failed",
        { cause: announcementError },
      );
    }
    throw announcementError;
  }
  return handles;
}

export async function executeBranchWithLedger(
  step: WorkspaceDirectoryWorkflowStep,
  branch: WorkflowBranch,
  handles: readonly WorkspaceDirectoryLedgerChangeHandle[],
  ledger: IWorkspaceDirectoryChangeLedger,
  execute: () => Promise<WorkspaceDirectoryWorkflowResult["branches"][number]>,
  preserveProviderResult = false,
  deferTerminalReceipts = false,
  requireProviderAttemptEvidence = false,
  recoverVerifiedResult?: () => Promise<
    WorkspaceDirectoryWorkflowResult["branches"][number]
  >,
): Promise<WorkspaceDirectoryWorkflowResult["branches"][number]> {
  const recoveredProviderSuccess = handles.some(
    ({ handle }) => handle.state === "completed",
  );
  let result: WorkspaceDirectoryWorkflowResult["branches"][number];
  if (
    recoveredProviderSuccess &&
    branch.branchId !== "trycomp-people" &&
    !requireProviderAttemptEvidence
  ) {
    if (branch.execution !== "managed")
      throw new Error(
        "workspace_directory_completed_ledger_for_nonmanaged_branch",
      );
    result = {
      branchId: branch.branchId,
      detail:
        "Recovered verified completed Slack change ledger; provider mutation was not replayed.",
      execution: branch.execution,
      state: "applied",
    };
  } else {
    result = await executeProviderStep(
      step,
      branch,
      handles,
      ledger,
      execute,
      requireProviderAttemptEvidence ? recoverVerifiedResult : undefined,
    );
  }
  if (deferTerminalReceipts) return result;
  try {
    await step.do(
      `workspace-directory:complete:${branch.branchId}`,
      STEP_CONFIG,
      async () => {
        for (const { change, handle } of handles) {
          if (handle.state !== "completed") {
            // eslint-disable-next-line no-await-in-loop -- Each exact ledger record is independently updated and read back.
            await ledger.complete(handle, {
              text: `${change.text.replace("Workspace sync planned ·", "Workspace sync verified ·")} · ${result.detail}`,
            });
          }
        }
        return NO_WORKSPACE_DIRECTORY_BRANCH_RESULT;
      },
    );
  } catch (cause) {
    if (preserveProviderResult)
      throw new WorkspaceBranchResultError({ result, cause });
    throw cause;
  }
  return result;
}

async function executeProviderStep(
  step: WorkspaceDirectoryWorkflowStep,
  branch: WorkflowBranch,
  handles: readonly WorkspaceDirectoryLedgerChangeHandle[],
  ledger: IWorkspaceDirectoryChangeLedger,
  execute: () => Promise<WorkspaceDirectoryWorkflowResult["branches"][number]>,
  recoverVerifiedResult?: () => Promise<
    WorkspaceDirectoryWorkflowResult["branches"][number]
  >,
) {
  try {
    return await step.do(
      `workspace-directory:${branch.branchId}`,
      STEP_CONFIG,
      execute,
    );
  } catch (providerError) {
    let recoveryError: unknown;
    if (recoverVerifiedResult !== undefined) {
      try {
        return await recoverVerifiedResult();
      } catch (error) {
        recoveryError = error;
      }
    }
    try {
      await step.do(
        `workspace-directory:fail:${branch.branchId}`,
        STEP_CONFIG,
        async () => {
          for (const { change, handle } of handles) {
            // eslint-disable-next-line no-await-in-loop -- Preserve exact per-change failure evidence before surfacing the branch error.
            await ledger.fail(handle, {
              text: `${change.text.replace("Workspace sync planned ·", "Workspace sync failed ·")} · final provider and ledger state requires audit`,
            });
          }
          return NO_WORKSPACE_DIRECTORY_BRANCH_RESULT;
        },
      );
    } catch (ledgerError) {
      throw new AggregateError(
        [
          providerError,
          ...(recoveryError === undefined ? [] : [recoveryError]),
          ledgerError,
        ],
        "workspace_directory_provider_and_failure_ledger_failed",
        { cause: ledgerError },
      );
    }
    if (recoveryError !== undefined)
      throw new AggregateError(
        [providerError, recoveryError],
        "workspace_directory_provider_and_verified_attempt_recovery_failed",
        { cause: providerError },
      );
    throw providerError;
  }
}
