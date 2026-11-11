import { getWorkspaceSyncPolicy } from "../configuration.ts";
import { D1ResourceLeaseRepository } from "../identity-sync/resource-lease.ts";
import { sameJson, sha256Hex } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import { logEvent } from "../shared/log-event.ts";
import {
  safeErrorCodeChain,
  sanitizedErrorFields,
} from "../shared/sanitize-error.ts";
import {
  D1WorkspaceLedgerHistoryIndex,
  type WorkspaceLedgerHistoryIndex,
} from "../workspace-directory/d1-workspace-ledger-history-index.ts";
import type { WorkspaceAlertPort } from "./alert-port.ts";
import { assertWorkspaceExecutionResume } from "./assert-workspace-execution-resume.ts";
import type { WorkspaceExecutionBindings as WorkerEnv } from "./bindings.ts";
import {
  WorkspaceDirectoryChangeLedger,
  type WorkspaceDirectoryChangeLedgerHandle,
} from "./change-ledger.ts";
import type {
  WorkspaceDirectoryWorkflowParams,
  WorkspaceDirectoryWorkflowResult,
} from "./contracts.ts";
import { createWorkspaceGithubParentContext } from "./create-workspace-github-parent-context.ts";
import { createWorkspaceIdentityParentContext } from "./create-workspace-identity-parent-context.ts";
import { createWorkspaceLinearParentContext } from "./create-workspace-linear-parent-context.ts";
import { createWorkspaceNameParentContext } from "./create-workspace-name-parent-context.ts";
import { createWorkspaceRuntimeIdentityBudgets } from "./create-workspace-runtime-identity-budgets.ts";
import { createWorkspaceSlackLifecycleParentContext } from "./create-workspace-slack-lifecycle-parent-context.ts";
import {
  executeScheduledWorkspaceBranch,
  recoverVerifiedScheduledWorkspaceBranch,
} from "./execute-scheduled-workspace-branch.ts";
import { executeWorkspaceDirectoryBranch } from "./execute-workspace-directory-branch.ts";
import {
  executeWorkspaceWorkflowWithHealth,
  WorkspaceExecutionFenceError,
} from "./execute-workspace-workflow-with-health.ts";
import { getWorkspaceExecutionPolicy } from "./get-workspace-execution-policy.ts";
import type { TrycompPeopleSyncRuntime } from "./provider-runtime-ports.ts";
import { ReviewedSlackLifecycleIntentRepository } from "./reviewed-slack-lifecycle-intent.ts";
import type { WorkspaceRuntimeConfiguration } from "./runtime-configuration.ts";
import type { WorkspaceDirectoryRuntime } from "./runtime-contract.ts";
import type { WorkspaceDirectoryRuntimeOptions } from "./runtime.ts";
import { WorkspaceScheduleExecutionManifestSchema } from "./schedule-health-contracts.ts";
import { WorkspaceDirectoryPlanApplyLedger } from "./slack-plan-apply-ledger.ts";
import {
  createWorkspaceReviewedTrycompApply,
  createWorkspaceReviewedTrycompInvitationReader,
} from "./trycomp-apply.ts";
import {
  abortWorkspaceDirectoryAnnouncements,
  executeBranchWithLedger,
  failPlanSummary,
  preannounceChanges,
  prepareWorkspaceDirectoryLedgerHistory,
  recoverWorkspaceDirectoryPlanSummary,
  reportWorkspaceDirectoryPreannouncementFailure,
  settleWorkspaceDirectoryBranches,
  STEP_CONFIG,
  WORKFLOW_FAILURE_ALERT_TTL_SECONDS,
  type WorkspaceDirectoryHistoryStep,
  type WorkspaceDirectoryLedgerChangeHandle,
  type WorkspaceDirectoryLifecycleStep,
} from "./workflow-ledger.ts";
import { workspaceDirectoryExecutionId } from "./workflow.ts";
import {
  type WorkspaceDirectoryAnnouncedChange,
  workspaceDirectoryAnnouncedChanges,
} from "./workspace-directory-announced-changes.ts";
import { workspaceIdentityBudgetParentKey } from "./workspace-identity-budget-parent-key.ts";
import {
  type IWorkspaceScheduleHealthRepository,
  WorkspaceScheduleHealthRepository,
} from "./workspace-schedule-health-repository.ts";

type WorkflowStep = WorkspaceDirectoryLifecycleStep &
  WorkspaceDirectoryHistoryStep;

const EXECUTION_RESUME_MISMATCH =
  "workspace_workflow_execution_resume_mismatch";

const PROVIDER_LEDGER_BRANCH_IDS = Object.freeze([
  "google-group-cleanup",
  "slack-names",
  "linear-profiles",
  "pagerduty-teams",
  "sentry-memberships",
]);

const WORKSPACE_DIRECTORY_BRANCH_ACTION_IDS = {
  "access-guard": "workspace-directory.linear-suspensions",
  "drive-org-chart": "workspace-directory.drive-org-chart",
  "github-access": "workspace-directory.github-access",
  "identity-provisioning": "workspace-directory.fanout",
  "slack-groups-channels": "workspace-directory.slack-groups-channels",
  "slack-profiles": "workspace-directory.slack-profiles",
  "trycomp-people": "workspace-directory.trycomp-people",
  "slack-names": "workspace-directory.slack-names",
  "linear-profiles": "workspace-directory.linear-profiles",
  "google-group-cleanup": "workspace-directory.google-group-cleanup",
  "pagerduty-teams": "workspace-directory.pagerduty-teams",
  "sentry-memberships": "workspace-directory.sentry-memberships",
} as const satisfies Record<
  WorkspaceDirectoryWorkflowParams["plan"]["branches"][number]["branchId"],
  WorkspaceDirectoryWorkflowParams["authorizedActionIds"][number]
>;

type WorkflowBranch =
  WorkspaceDirectoryWorkflowParams["plan"]["branches"][number];

export async function beginScheduledExecution(
  step: WorkspaceDirectoryLifecycleStep,
  repository: Pick<
    IWorkspaceScheduleHealthRepository,
    "beginExecution" | "read"
  >,
  params: WorkspaceDirectoryWorkflowParams,
  summaryHandle: WorkspaceDirectoryChangeLedgerHandle,
  ledgerHandles: ReadonlyMap<
    WorkspaceDirectoryWorkflowParams["plan"]["branches"][number]["branchId"],
    readonly WorkspaceDirectoryLedgerChangeHandle[]
  >,
): Promise<void> {
  if (params.scheduledTickId === undefined) return;
  try {
    if (summaryHandle.state === "failed")
      throw new Error("workspace_original_summary_failed");
    const manifest = WorkspaceScheduleExecutionManifestSchema.parse({
      params,
      summaryHandle: { ...summaryHandle, state: summaryHandle.state },
      branchHandles: [...ledgerHandles].flatMap(([branchId, handles]) =>
        handles.map(({ change, handle }) => {
          if (handle.state === "failed")
            throw new Error("workspace_original_branch_failed");
          return {
            branchId,
            change,
            handle: { ...handle, state: handle.state },
          };
        }),
      ),
    });
    const tickId = params.scheduledTickId;
    const validateResume = async () => {
      const tick = await repository.read(tickId);
      if (
        tick.phase !== "launched" ||
        tick.tickId !== tickId ||
        tick.planHash !== params.planHash ||
        tick.workflowId !== (await workspaceDirectoryExecutionId(params)) ||
        tick.execution === undefined
      )
        throw new Error(EXECUTION_RESUME_MISMATCH);
      await assertWorkspaceExecutionResume(tick.execution, params);
      const stored = WorkspaceScheduleExecutionManifestSchema.parse({
        params: tick.execution.params,
        summaryHandle: tick.execution.summaryHandle,
        branchHandles: tick.execution.branchHandles,
      });
      if (
        !sameJson(
          JsonValueSchema.parse(stored),
          JsonValueSchema.parse(manifest),
        )
      )
        throw new Error(EXECUTION_RESUME_MISMATCH);
    };
    const manifestDigest = await sha256Hex(JsonValueSchema.parse(manifest));
    const acquired = await step.do(
      "workspace-directory:begin-execution",
      STEP_CONFIG,
      async () => {
        const tick = await repository.read(tickId);
        if (tick.execution === undefined)
          await repository.beginExecution(tickId, manifest);
        else await validateResume();
        return manifestDigest;
      },
    );
    if (acquired !== manifestDigest) throw new Error(EXECUTION_RESUME_MISMATCH);
    await validateResume();
  } catch (error) {
    throw new WorkspaceExecutionFenceError(error);
  }
}

function rejectScheduledPreflightFailure(
  params: WorkspaceDirectoryWorkflowParams,
  error: unknown,
): void {
  if (params.scheduledTickId !== undefined)
    throw new WorkspaceExecutionFenceError(error);
}

async function prepareWorkspaceProviderLedgerHistory(
  step: WorkspaceDirectoryHistoryStep,
  params: WorkspaceDirectoryWorkflowParams,
  botToken: string,
  historyIndex: WorkspaceLedgerHistoryIndex,
): Promise<void> {
  if (!hasProviderLedgerChanges(params, new Set(params.authorizedActionIds)))
    return;
  await prepareWorkspaceDirectoryLedgerHistory(
    step,
    new WorkspaceDirectoryChangeLedger({
      botToken,
      channelId: getWorkspaceExecutionPolicy().accessGuard.alertsChannelId,
      expectedChannelName:
        getWorkspaceExecutionPolicy().accessGuard.alertsChannelName,
      expectedTeamId: getWorkspaceSyncPolicy().org.expectedSlackTeamId,
      historyIndex,
    }),
    "workspace-directory:index-provider-ledger-history",
  );
}

function hasProviderLedgerChanges(
  params: WorkspaceDirectoryWorkflowParams,
  authorizedActionIds: ReadonlySet<
    WorkspaceDirectoryWorkflowParams["authorizedActionIds"][number]
  >,
): boolean {
  return params.plan.branches.some(
    (branch) =>
      PROVIDER_LEDGER_BRANCH_IDS.includes(branch.branchId) &&
      authorizedBranchChanges(params, authorizedActionIds, branch.branchId)
        .length > 0,
  );
}

function authorizedBranchChanges(
  params: WorkspaceDirectoryWorkflowParams,
  authorizedActionIds: ReadonlySet<
    WorkspaceDirectoryWorkflowParams["authorizedActionIds"][number]
  >,
  branchId: WorkflowBranch["branchId"],
): readonly WorkspaceDirectoryAnnouncedChange[] {
  const actionId = WORKSPACE_DIRECTORY_BRANCH_ACTION_IDS[branchId];
  return authorizedActionIds.has(actionId)
    ? workspaceDirectoryAnnouncedChanges(params.plan, branchId)
    : [];
}
// The host validates configuration and supplies SDK step and terminal-error ports.
export async function runWorkspaceDirectoryWorkflow(input: {
  params: WorkspaceDirectoryWorkflowParams;
  config: WorkspaceRuntimeConfiguration;
  bindings: WorkerEnv;
  step: WorkflowStep;
  alerts(): WorkspaceAlertPort;
  trycompRuntime(): TrycompPeopleSyncRuntime;
  nonRetryableError(message: string): Error;
  createRuntime(
    options: WorkspaceDirectoryRuntimeOptions,
  ): WorkspaceDirectoryRuntime;
}): Promise<WorkspaceDirectoryWorkflowResult> {
  const step = input.step;

  const params = input.params;
  const validatedEnv = input.config;
  if (
    params.requestedBy === "scheduled:workspace-directory" &&
    !validatedEnv.workspaceDirectoryParentEnabled
  ) {
    throw new Error("workspace_directory_parent_disabled");
  }
  const identityParentEnabled =
    validatedEnv.workspaceDirectoryParentEnabled &&
    !validatedEnv.orgSyncDisabled &&
    validatedEnv.orgSyncMode === "live";
  return executeWorkspaceWorkflowWithHealth({
    botToken: validatedEnv.reminderSlackBotToken,
    env: input.bindings,
    params,
    execute: async () => {
      const alerts = input.alerts();
      const changeLedger = new WorkspaceDirectoryChangeLedger({
        botToken: validatedEnv.reminderSlackBotToken,
        channelId: getWorkspaceExecutionPolicy().accessGuard.alertsChannelId,
        expectedChannelName:
          getWorkspaceExecutionPolicy().accessGuard.alertsChannelName,
        expectedTeamId: getWorkspaceSyncPolicy().org.expectedSlackTeamId,
        historyIndex: new D1WorkspaceLedgerHistoryIndex(
          input.bindings.AUTOMATIONS_DB,
        ),
      });
      const planApplyLedger = new WorkspaceDirectoryPlanApplyLedger(
        changeLedger,
      );
      const authorizedActionIds = new Set(params.authorizedActionIds);
      const executionId = await workspaceDirectoryExecutionId(params);
      let summaryHandle: WorkspaceDirectoryChangeLedgerHandle;
      try {
        summaryHandle = await recoverWorkspaceDirectoryPlanSummary(
          step,
          planApplyLedger,
          params,
        );
      } catch (error) {
        rejectScheduledPreflightFailure(params, error);
        await reportWorkspaceDirectoryPreannouncementFailure(alerts, error, {
          executionId,
          planHash: params.planHash,
        });
        throw error;
      }
      const ledgerHandles = new Map<
        WorkspaceDirectoryWorkflowParams["plan"]["branches"][number]["branchId"],
        readonly WorkspaceDirectoryLedgerChangeHandle[]
      >();
      try {
        await prepareWorkspaceDirectoryLedgerHistory(step, changeLedger);
        await prepareWorkspaceProviderLedgerHistory(
          step,
          params,
          validatedEnv.slackBotToken,
          new D1WorkspaceLedgerHistoryIndex(input.bindings.AUTOMATIONS_DB),
        );
        for (const branch of params.plan.branches) {
          const changes = authorizedBranchChanges(
            params,
            authorizedActionIds,
            branch.branchId,
          );
          // eslint-disable-next-line no-await-in-loop -- All announcements must be durably verified before any provider branch can begin.
          const handles = await step.do(
            `workspace-directory:announce:${branch.branchId}`,
            STEP_CONFIG,
            () =>
              preannounceChanges(
                changeLedger,
                params.planHash,
                changes,
                params.scheduledTickId === undefined,
              ),
          );
          ledgerHandles.set(branch.branchId, handles);
        }
      } catch (error) {
        rejectScheduledPreflightFailure(params, error);
        await reportWorkspaceDirectoryPreannouncementFailure(alerts, error, {
          executionId,
          planHash: params.planHash,
        });
        const abortErrors: unknown[] = [];
        try {
          await abortWorkspaceDirectoryAnnouncements(
            step,
            changeLedger,
            ledgerHandles,
          );
        } catch (abortError) {
          abortErrors.push(abortError);
        }
        await failPlanSummary(
          step,
          planApplyLedger,
          summaryHandle,
          params,
          error,
          abortErrors,
        );
      }
      await beginScheduledExecution(
        step,
        new WorkspaceScheduleHealthRepository(input.bindings.AUTOMATIONS_DB),
        params,
        summaryHandle,
        ledgerHandles,
      );
      const identityBudgetParent = validatedEnv.workspaceDirectoryParentEnabled
        ? await workspaceIdentityBudgetParentKey(
            input.bindings.AUTOMATIONS_DB,
            params,
          )
        : undefined;
      const identityBudgets = createWorkspaceRuntimeIdentityBudgets(
        input.bindings.AUTOMATIONS_DB,
        identityBudgetParent,
      );
      const runtime = input.createRuntime({
        ...identityBudgets,
        reviewedSlackLifecycleParentContext:
          createWorkspaceSlackLifecycleParentContext({
            enabled: identityParentEnabled,
            params,
            handles: ledgerHandles,
            ledger: changeLedger,
            repository: new WorkspaceScheduleHealthRepository(
              input.bindings.AUTOMATIONS_DB,
            ),
            intents: new ReviewedSlackLifecycleIntentRepository(
              input.bindings.AUTOMATIONS_DB,
            ),
            ...identityBudgets,
          }),
        githubParentContext: createWorkspaceGithubParentContext({
          enabled: identityParentEnabled,
          params,
          handles: ledgerHandles,
          ledger: changeLedger,
          repository: new WorkspaceScheduleHealthRepository(
            input.bindings.AUTOMATIONS_DB,
          ),
          ...identityBudgets,
        }),
        linearSuspensionParentContext: createWorkspaceLinearParentContext({
          intents: new ReviewedSlackLifecycleIntentRepository(
            input.bindings.AUTOMATIONS_DB,
          ),
          enabled: identityParentEnabled,
          params,
          handles: ledgerHandles,
          ledger: changeLedger,
          repository: new WorkspaceScheduleHealthRepository(
            input.bindings.AUTOMATIONS_DB,
          ),
          ...identityBudgets,
        }),
        googleGroupCleanupParentContext: (plan) => {
          const identityBudget = identityBudgets.googleIdentityBudget;
          if (identityBudget?.required !== true)
            throw new Error("workspace_google_group_cleanup_budget_required");
          const parent = createWorkspaceIdentityParentContext(
            {
              enabled: validatedEnv.workspaceDirectoryParentEnabled,
              params,
              handles: ledgerHandles,
              ledger: changeLedger,
              identityBudget,
              repository: new WorkspaceScheduleHealthRepository(
                input.bindings.AUTOMATIONS_DB,
              ),
            },
            plan,
            "google-group-cleanup",
          );
          const proof = params.reviewedProviderIntent?.proof;
          const deadlineAtMs = Math.min(
            Date.parse(params.planGeneratedAt) + 600000,
            proof !== undefined &&
              "provider" in proof &&
              proof.provider === "google-group-cleanup"
              ? proof.expiresAtMs
              : Infinity,
          );
          return {
            ...parent,
            mode: "parent",
            identityBudget,
            deadlineAtMs,
            verifyPreannouncement: async () => {
              await parent.assertWriteAuthority();
            },
          };
        },
        pagerDutyTeamParentContext: (plan) => {
          const identityBudget = identityBudgets.pagerDutyIdentityBudget;
          if (identityBudget?.required !== true)
            throw new Error("workspace_pagerduty_teams_budget_required");
          const parent = createWorkspaceIdentityParentContext(
            {
              enabled: validatedEnv.workspaceDirectoryParentEnabled,
              params,
              handles: ledgerHandles,
              ledger: changeLedger,
              identityBudget,
              repository: new WorkspaceScheduleHealthRepository(
                input.bindings.AUTOMATIONS_DB,
              ),
            },
            plan,
            "pagerduty-teams",
          );
          return {
            ...parent,
            mode: "parent",
            identityBudget,
            verifyPreannouncement: async () => {
              await parent.assertWriteAuthority();
            },
          };
        },
        sentryParentContext: (plan) => {
          const identityBudget = identityBudgets.sentryIdentityBudget;
          if (identityBudget?.required !== true) {
            throw new Error("workspace_sentry_budget_required");
          }
          const parent = createWorkspaceIdentityParentContext(
            {
              enabled:
                validatedEnv.workspaceDirectoryParentEnabled &&
                validatedEnv.workspaceDirectorySentryEnabled,
              params,
              handles: ledgerHandles,
              ledger: changeLedger,
              identityBudget,
              repository: new WorkspaceScheduleHealthRepository(
                input.bindings.AUTOMATIONS_DB,
              ),
            },
            plan,
            "sentry-memberships",
          );
          return {
            ...parent,
            mode: "parent",
            identityBudget,
            verifyPreannouncement: async () => {
              await parent.assertWriteAuthority();
            },
          };
        },
        nameRepairParentContext: createWorkspaceNameParentContext({
          ...identityBudgets,
          enabled:
            validatedEnv.workspaceDirectoryParentEnabled &&
            !validatedEnv.orgSyncDisabled &&
            validatedEnv.orgSyncMode === "live",
          params,
          handles: ledgerHandles,
          ledger: changeLedger,
          repository: new WorkspaceScheduleHealthRepository(
            input.bindings.AUTOMATIONS_DB,
          ),
        }),
        readVerifiedTrycompInvitation:
          createWorkspaceReviewedTrycompInvitationReader({
            database: input.bindings.AUTOMATIONS_DB,
            handles: ledgerHandles.get("trycomp-people") ?? [],
            params,
          }),
        applyReviewedTrycomp: createWorkspaceReviewedTrycompApply({
          identityBudget: identityBudgets.trycompIdentityBudget,
          database: input.bindings.AUTOMATIONS_DB,
          deployment: input.bindings.CF_VERSION_METADATA,
          env: validatedEnv,
          handles: ledgerHandles.get("trycomp-people") ?? [],
          ledger: changeLedger,
          params,
          runtime: () => input.trycompRuntime(),
          nonRetryableError: (message) => input.nonRetryableError(message),
        }),
        channelDatabase: input.bindings.AUTOMATIONS_DB,
        channelLeaseRepository: new D1ResourceLeaseRepository(
          input.bindings.AUTOMATIONS_DB,
        ),
      });
      const branchPromises = params.plan.branches.map((branch) =>
        executeBranchWithLedger(
          step,
          branch,
          ledgerHandles.get(branch.branchId) ?? [],
          changeLedger,
          () =>
            executeScheduledWorkspaceBranch({
              enabled: validatedEnv.workspaceDirectoryParentEnabled,
              params,
              branchId: branch.branchId,
              runtime,
              ledger: changeLedger,
              repository: new WorkspaceScheduleHealthRepository(
                input.bindings.AUTOMATIONS_DB,
              ),
              execute: (githubDispatchClaim) =>
                executeWorkspaceDirectoryBranch(
                  runtime,
                  params,
                  authorizedActionIds,
                  branch,
                  githubDispatchClaim,
                ),
            }),
          params.scheduledTickId !== undefined,
          params.scheduledTickId !== undefined,
          validatedEnv.workspaceDirectoryParentEnabled &&
            params.requestedBy === "scheduled:workspace-directory",
          () =>
            recoverVerifiedScheduledWorkspaceBranch({
              enabled: validatedEnv.workspaceDirectoryParentEnabled,
              params,
              branchId: branch.branchId,
              runtime,
              ledger: changeLedger,
              repository: new WorkspaceScheduleHealthRepository(
                input.bindings.AUTOMATIONS_DB,
              ),
            }),
        ).catch(async (error: unknown) => {
          logEvent("workspace_directory.workflow_branch_failed", {
            ...sanitizedErrorFields(error),
            "branch_id": branch.branchId,
            "error_codes": safeErrorCodeChain(error),
            "execution_id": executionId,
            "plan_hash": params.planHash,
          });
          try {
            await alerts.postError(
              "Workspace directory Workflow branch failed",
              error,
              {
                branchId: branch.branchId,
                executionId,
                planHash: params.planHash,
              },
              WORKFLOW_FAILURE_ALERT_TTL_SECONDS,
            );
          } catch (alertError) {
            logEvent("workspace_directory.workflow_alert_failed", {
              ...sanitizedErrorFields(alertError),
              "branch_id": branch.branchId,
              "execution_id": executionId,
            });
          }
          throw error;
        }),
      );
      return settleWorkspaceDirectoryBranches(
        step,
        planApplyLedger,
        summaryHandle,
        params,
        executionId,
        branchPromises,
        params.scheduledTickId !== undefined,
      );
    },
  });
}
