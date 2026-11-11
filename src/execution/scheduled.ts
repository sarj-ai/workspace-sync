import { dequal } from "dequal";

import { sameJson as sameCanonicalJson } from "../operations/canonical.ts";
import type { OperationKernel } from "../operations/kernel.ts";
import type { SignedOperationPlan } from "../operations/schemas.ts";
import { logEvent } from "../shared/log-event.ts";
import { sanitizedErrorFields } from "../shared/sanitize-error.ts";
import type { WorkspaceAlertPort as IAlertsClient } from "./alert-port.ts";
import {
  WORKSPACE_DIRECTORY_ACTION_IDS,
  type WorkspaceDirectoryAuthorizedActionId,
  WorkspaceDirectoryAuthorizedActionIdSchema,
  WorkspaceDirectoryChangeDetailsSchema,
  type WorkspaceDirectoryPlan,
  WorkspaceDirectoryWorkflowParamsSchema,
} from "./contracts.ts";
import {
  workspaceDirectoryBranch,
  type WorkspaceDirectoryBranchId,
} from "./flow.ts";
import { isScheduledGitHubAccess } from "./is-scheduled-git-hub-access.ts";
import { isScheduledLinearSuspension } from "./is-scheduled-linear-suspension.ts";
import { isWorkspaceObservation } from "./observation-carrier.ts";
import {
  WORKSPACE_DIRECTORY_DRIVE_ORG_CHART_ACTION_ID,
  WORKSPACE_DIRECTORY_FANOUT_ACTION_ID,
  WORKSPACE_DIRECTORY_GITHUB_ACCESS_ACTION_ID,
  WORKSPACE_DIRECTORY_LINEAR_SUSPENSIONS_ACTION_ID,
  WORKSPACE_DIRECTORY_OPERATION_ID,
  WORKSPACE_DIRECTORY_SLACK_GROUPS_CHANNELS_ACTION_ID,
  WORKSPACE_DIRECTORY_SLACK_PROFILES_ACTION_ID,
} from "./operation.ts";
import { googleGroupCleanupManagedSlice } from "./reviewed-google-group-cleanup.ts";
import {
  pagerDutyTeamManagedSlice,
  pagerDutyTeamResourceId,
} from "./reviewed-pagerduty-team.ts";
import {
  sentryWorkspaceManagedSlice,
  sentryWorkspaceResourceId,
} from "./reviewed-sentry-workspace.ts";
import type { IReviewedSlackLifecycleIntentClaims } from "./reviewed-slack-lifecycle-intent.ts";
import { runReviewedSlackLifecycleIntent } from "./run-reviewed-slack-lifecycle-intent.ts";
import type {
  WorkspaceScheduleBlockedReason,
  WorkspaceScheduleReceipt,
  WorkspaceScheduleStart,
  WorkspaceScheduleTick,
} from "./schedule-health-contracts.ts";
import { isScheduledSlackUserGroupReconciliation } from "./scheduled-slack-membership-addition.ts";
import {
  launchWorkspaceDirectoryWorkflow,
  workspaceDirectoryExecutionId,
  type WorkspaceDirectoryWorkflowBinding,
} from "./workflow.ts";
import {
  slackAccessLifecycleCounts,
  workspaceDirectoryHasAuditOnlyFindings,
} from "./workspace-directory-has-audit-only-findings.ts";
import { WorkspaceScheduleExecutionIdentitySchema } from "./workspace-schedule-health-repository.ts";
import type { IWorkspaceScheduleHealthRepository } from "./workspace-schedule-health-repository.ts";
const SCHEDULED_ACTOR = {
  authorizationScope: "workspace-directory:apply",
  id: "scheduled:workspace-directory",
} as const;

const PRODUCTION_ENVIRONMENT = "production";

const PROFILE_AUDIT_DRIFT_TTL_SECONDS = 48 * 60 * 60;

const SLACK_ACCESS_DRIFT_TTL_SECONDS = 72 * 60 * 60;

const SCHEDULED_TICK_RECOVERY_REQUIRED =
  "workspace_directory_scheduled_tick_recovery_required";

const SCHEDULED_ACTION_BRANCH_BY_ID = {
  [WORKSPACE_DIRECTORY_DRIVE_ORG_CHART_ACTION_ID]: "drive-org-chart",
  [WORKSPACE_DIRECTORY_FANOUT_ACTION_ID]: "identity-provisioning",
  [WORKSPACE_DIRECTORY_GITHUB_ACCESS_ACTION_ID]: "github-access",
  [WORKSPACE_DIRECTORY_LINEAR_SUSPENSIONS_ACTION_ID]: "access-guard",
  [WORKSPACE_DIRECTORY_SLACK_GROUPS_CHANNELS_ACTION_ID]:
    "slack-groups-channels",
  [WORKSPACE_DIRECTORY_SLACK_PROFILES_ACTION_ID]: "slack-profiles",
  [WORKSPACE_DIRECTORY_ACTION_IDS.trycompPeople]: "trycomp-people",
  [WORKSPACE_DIRECTORY_ACTION_IDS.slackNames]: "slack-names",
  [WORKSPACE_DIRECTORY_ACTION_IDS.linearProfiles]: "linear-profiles",
  [WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup]: "google-group-cleanup",
  [WORKSPACE_DIRECTORY_ACTION_IDS.pagerDutyTeams]: "pagerduty-teams",
  [WORKSPACE_DIRECTORY_ACTION_IDS.sentryMemberships]: "sentry-memberships",
} as const satisfies Readonly<
  Record<WorkspaceDirectoryAuthorizedActionId, WorkspaceDirectoryBranchId>
>;

type SlackProfilePlan = WorkspaceDirectoryPlan["branches"][0];

type SlackAccessPlan = WorkspaceDirectoryPlan["branches"][2];

export type ScheduledWorkspaceDirectoryResult =
  | {
      githubIdentityUpdates: number;
      kind: "review-required";
      linearSuspensions: number;
      planHash: string;
    }
  | {
      instanceId: string;
      kind: "launched";
      planHash: string;
      reviewPlanHash?: string;
    }
  | {
      kind: "blocked";
      planHash: string;
      reason: "diagnostics" | "safety-policy";
      blockedReason?: WorkspaceScheduleBlockedReason;
      reviewPlanHash?: string;
    }
  | {
      kind: "converged";
      planHash: string;
    }
  | {
      kind: "receipts-recovered";
      outcome: Extract<
        WorkspaceScheduleTick,
        {
          phase: "terminal";
        }
      >["outcome"];
      planHash: null | string;
      tickId: string;
    };

const SCHEDULED_CONTEXT_REQUIRED =
  "workspace_directory_scheduled_context_required";

const SCHEDULED_TERMINAL_RECEIPT_MISSING =
  "workspace_directory_scheduled_terminal_receipt_missing";

const SCHEDULED_TERMINAL_VERIFIER_REQUIRED =
  "workspace_directory_scheduled_terminal_verifier_required";

export interface ScheduledWorkspaceDirectoryDependencies {
  announcePlan: (signedPlan: SignedOperationPlan) => Promise<void>;
  kernel: Pick<OperationKernel, "plan" | "prepareApply">;
  linearSuspensionsEnabled?: boolean;
  parentEnabled: boolean;
  reportAccessIssues?: (plan: WorkspaceDirectoryPlan) => Promise<void>;
  reviewedLifecycleIntents?: IReviewedSlackLifecycleIntentClaims;
  scheduleHealth?: {
    repository: Pick<
      IWorkspaceScheduleHealthRepository,
      | "attachVerifiedReceipt"
      | "complete"
      | "completeFailedBeforePlan"
      | "completeFailedNoDispatch"
      | "launch"
      | "listStaleNoDispatchRecoveryCandidates"
      | "read"
      | "recordPlan"
      | "start"
    >;
    verifyTerminalReceipt?: (
      terminal: Extract<
        WorkspaceScheduleTick,
        {
          phase: "terminal";
        }
      >,
    ) => Promise<null | WorkspaceScheduleReceipt>;
  };
  trycompEnabled?: boolean;
  workflow: WorkspaceDirectoryWorkflowBinding;
}

export async function runIndependentWorkspaceDirectoryReports(
  reports: readonly (() => Promise<unknown>)[],
): Promise<void> {
  const outcomes = await Promise.allSettled(reports.map((report) => report()));
  const failures: unknown[] = [];
  for (const outcome of outcomes) {
    if (outcome.status === "rejected") failures.push(outcome.reason);
  }
  if (failures.length > 0) {
    throw new AggregateError(failures, "workspace_directory_reporting_failed");
  }
}

export async function reportScheduledSlackDrift(
  profiles: SlackProfilePlan,
  access: SlackAccessPlan,
  alerts: IAlertsClient,
): Promise<void> {
  await Promise.all([
    reportSlackProfileAuditDrift(profiles, alerts),
    reportSlackAccessDrift(access, alerts),
  ]);
}

async function reportSlackProfileAuditDrift(
  profiles: SlackProfilePlan,
  alerts: IAlertsClient,
): Promise<void> {
  const counts = {
    blocked: profiles.diagnostics.filter(
      ({ code }) => code === "profile_plan_role_audit_only",
    ).length,
    errors: profiles.diagnostics.filter(
      ({ severity }) => severity === "blocker",
    ).length,
  };
  if (counts.blocked === 0 && counts.errors === 0) return;
  await alerts.postError(
    "Google Workspace to Slack profile audit found incomplete evidence",
    new Error(
      "No profile changes were applied; inspect the private signed plan.",
    ),
    {
      blocked: String(counts.blocked),
      errors: String(counts.errors),
      mode: profiles.execution,
      ...(!(profiles.planHash === null) && { planHash: profiles.planHash }),
    },
    PROFILE_AUDIT_DRIFT_TTL_SECONDS,
    {
      details: [
        {
          heading: "Sanitized profile audit summary",
          text: `• ${String(counts.blocked)} profiles blocked by incomplete role evidence\n• ${String(counts.errors)} profile audit errors`,
        },
      ],
      tone: "warning",
    },
  );
}

async function reportSlackAccessDrift(
  access: SlackAccessPlan,
  alerts: IAlertsClient,
): Promise<void> {
  const changedUserGroups = access.userGroups.filter(
    ({ status }) => status !== "in_sync",
  ).length;
  const lifecycle = slackAccessLifecycleCounts(access);
  const counts = {
    additions: access.additions.length,
    channelRenames: access.channelRenames.length,
    errors: access.diagnostics.filter(({ severity }) => severity === "blocker")
      .length,
    lifecycleDrift: Object.values(lifecycle).reduce(
      (total, count) => total + count,
      0,
    ),
    warnings: access.diagnostics.filter(
      ({ code, severity }) =>
        code === "channel_plan_warning" && severity === "warning",
    ).length,
    removals: access.removals.length,
    userGroups: changedUserGroups,
  };
  if (Object.values(counts).every((count) => count === 0)) return;
  await alerts.postError(
    "Google Workspace to Slack access plan found drift",
    new Error("No unreviewed changes were applied."),
    {
      additions: String(counts.additions),
      channelRenames: String(counts.channelRenames),
      errors: String(counts.errors),
      lifecycleDrift: String(counts.lifecycleDrift),
      mode: access.execution,
      ...(!(access.planHash === null) && { planHash: access.planHash }),
      removals: String(counts.removals),
      userGroupChanges: String(counts.userGroups),
      warnings: String(counts.warnings),
    },
    SLACK_ACCESS_DRIFT_TTL_SECONDS,
    {
      details: [
        {
          heading: "Signed Workspace Directory plan",
          text: `• ${String(counts.additions)} direct additions\n• ${String(counts.removals)} direct removals\n• ${String(counts.userGroups)} user-group changes\n• ${String(counts.channelRenames)} channel renames\n• ${String(counts.lifecycleDrift)} lifecycle findings\n• ${String(counts.warnings)} planning warnings\n• ${String(counts.errors)} planning errors`,
        },
        {
          heading: "Sanitized lifecycle summary",
          text: `• ${String(lifecycle.unclassifiedGoogleTeams)} unclassified Google teams\n• ${String(lifecycle.nonstandardPublicChannels)} nonstandard public channels\n• ${String(lifecycle.privateChannelRenames)} private-channel rename candidates\n• ${String(lifecycle.teamChannelCollisions)} team-channel collisions\n• ${String(lifecycle.usersNeedingAssignments)} users needing team assignments\n• ${String(lifecycle.verticalRetirements)} vertical retirement candidates`,
        },
      ],
      tone: "warning",
    },
  );
}

export async function runScheduledWorkspaceDirectory(
  dependencies: ScheduledWorkspaceDirectoryDependencies,
  context?: WorkspaceScheduleStart,
): Promise<ScheduledWorkspaceDirectoryResult> {
  await recoverStaleNoDispatchTicks(dependencies, context);
  const tick = await startScheduledHealth(dependencies.scheduleHealth, context);
  if (tick?.phase === "terminal") {
    return recoverScheduledTerminalReceipt(dependencies.scheduleHealth, tick);
  }
  let observedPlanHash: string | undefined;
  let primaryError: Error | undefined;
  let result: ScheduledWorkspaceDirectoryResult | undefined;
  try {
    result = await runScheduledWorkspaceDirectoryPlan(
      dependencies,
      async (signedPlan) => {
        observedPlanHash = signedPlan.plan.planHash;
        await recordScheduledHealthPlan(
          dependencies.scheduleHealth,
          tick,
          signedPlan,
        );
      },
      tick?.tickId,
    );
  } catch (error) {
    primaryError = scheduledError(
      error,
      "workspace_directory_scheduled_failed",
    );
    logEvent("workspace_directory.scheduled_failed", {
      ...sanitizedErrorFields(error),
      ...(!(observedPlanHash === undefined) && {
        "plan_hash": observedPlanHash,
      }),
    });
  }
  const completionErrors: unknown[] = [];
  completionErrors.push(
    ...(await captureScheduledHealthCompletion(
      dependencies.scheduleHealth,
      tick,
      result,
      primaryError !== undefined || completionErrors.length > 0,
    )),
  );
  const [completionError] = completionErrors;
  if (primaryError !== undefined && completionErrors.length === 0)
    throw primaryError;
  if (
    primaryError === undefined &&
    completionErrors.length === 1 &&
    completionError !== undefined
  )
    throw completionError instanceof Error
      ? completionError
      : new Error("workspace_schedule_completion_failed", {
          cause: completionError,
        });
  if (primaryError !== undefined || completionErrors.length > 0) {
    throw new AggregateError(
      [
        ...(primaryError === undefined ? [] : [primaryError]),
        ...completionErrors,
      ],
      "workspace_directory_scheduled_and_receipt_failed",
      { cause: primaryError ?? completionError },
    );
  }
  if (result === undefined)
    throw new Error("workspace_directory_scheduled_result_missing");
  return result;
}

async function recoverStaleNoDispatchTicks(
  dependencies: ScheduledWorkspaceDirectoryDependencies,
  context: undefined | WorkspaceScheduleStart,
): Promise<void> {
  const health = dependencies.scheduleHealth;
  if (health === undefined) return;
  if (context === undefined) throw new Error(SCHEDULED_CONTEXT_REQUIRED);
  const candidates =
    await health.repository.listStaleNoDispatchRecoveryCandidates(
      context.scheduledAtMs,
    );
  for (const candidate of candidates) {
    // eslint-disable-next-line no-await-in-loop -- recovery is intentionally serialized by exact tick.
    await recoverStaleNoDispatchTick(dependencies, candidate);
  }
}

async function recoverStaleNoDispatchTick(
  dependencies: ScheduledWorkspaceDirectoryDependencies,
  candidate: WorkspaceScheduleTick,
): Promise<void> {
  const health = dependencies.scheduleHealth;
  if (
    health === undefined ||
    candidate.execution !== undefined ||
    (candidate.branchAttempts?.length ?? 0) !== 0 ||
    (candidate.phase !== "started" &&
      candidate.phase !== "launched" &&
      (candidate.phase !== "terminal" || candidate.outcome === "applied"))
  )
    throw new Error(SCHEDULED_TICK_RECOVERY_REQUIRED);
  if (candidate.phase === "started") {
    const terminal = await health.repository.completeFailedBeforePlan(
      candidate.tickId,
    );
    await verifyRecoveredTerminalReceipt(health, terminal);
    return;
  }
  const workflowId = candidate.workflowId;
  if (workflowId === null) {
    if (candidate.phase !== "terminal")
      throw new Error(SCHEDULED_TICK_RECOVERY_REQUIRED);
    await recoverScheduledTerminalReceipt(health, candidate);
    return;
  }
  const instance = await dependencies.workflow.get(workflowId);
  const status = await instance.status();
  if (
    instance.id !== workflowId ||
    (status.status !== "errored" && status.status !== "terminated")
  )
    throw new Error(SCHEDULED_TICK_RECOVERY_REQUIRED);
  const terminal =
    candidate.phase === "launched"
      ? await health.repository.completeFailedNoDispatch(
          WorkspaceScheduleExecutionIdentitySchema.parse({
            tickId: candidate.tickId,
            workflowId,
          }),
        )
      : await health.repository.read(candidate.tickId);
  await verifyRecoveredTerminalReceipt(health, terminal);
}

async function verifyRecoveredTerminalReceipt(
  health: NonNullable<
    ScheduledWorkspaceDirectoryDependencies["scheduleHealth"]
  >,
  terminal: WorkspaceScheduleTick,
): Promise<void> {
  if (terminal.phase !== "terminal" || terminal.outcome !== "failed")
    throw new Error(SCHEDULED_TICK_RECOVERY_REQUIRED);
  if (health.verifyTerminalReceipt === undefined)
    throw new Error(SCHEDULED_TERMINAL_VERIFIER_REQUIRED);
  const receipt = await health.verifyTerminalReceipt(terminal);
  if (receipt === null) throw new Error(SCHEDULED_TERMINAL_RECEIPT_MISSING);
  await health.repository.attachVerifiedReceipt(receipt);
}

async function startScheduledHealth(
  health: ScheduledWorkspaceDirectoryDependencies["scheduleHealth"],
  context: undefined | WorkspaceScheduleStart,
): Promise<undefined | WorkspaceScheduleTick> {
  if (health === undefined) return undefined;
  if (context === undefined) throw new Error(SCHEDULED_CONTEXT_REQUIRED);
  const tick = await health.repository.start(context);
  if (tick.phase === "launched")
    throw new Error(SCHEDULED_TICK_RECOVERY_REQUIRED);
  return tick;
}

async function recoverScheduledTerminalReceipt(
  health: ScheduledWorkspaceDirectoryDependencies["scheduleHealth"],
  tick: Extract<
    WorkspaceScheduleTick,
    {
      phase: "terminal";
    }
  >,
): Promise<ScheduledWorkspaceDirectoryResult> {
  // Only the same scheduled event can enter this path. Workflow-owned receipts
  // require their original execution manifest and are recovered by its bridge.
  if (
    health === undefined ||
    tick.workflowId !== null ||
    tick.execution !== undefined ||
    tick.outcome === "applied"
  )
    throw new Error(SCHEDULED_TICK_RECOVERY_REQUIRED);
  if (tick.notificationRequired) {
    if (health.verifyTerminalReceipt === undefined)
      throw new Error(SCHEDULED_TERMINAL_VERIFIER_REQUIRED);
    const receipt = await health.verifyTerminalReceipt(tick);
    if (receipt === null) throw new Error(SCHEDULED_TERMINAL_RECEIPT_MISSING);
    await health.repository.attachVerifiedReceipt(receipt);
  }
  return {
    kind: "receipts-recovered",
    outcome: tick.outcome,
    planHash: tick.planHash,
    tickId: tick.tickId,
  };
}

async function recordScheduledHealthPlan(
  health: ScheduledWorkspaceDirectoryDependencies["scheduleHealth"],
  tick: undefined | WorkspaceScheduleTick,
  signedPlan: SignedOperationPlan,
): Promise<void> {
  if (health === undefined || tick === undefined) return;
  const directoryPlan = workspaceDirectoryPlan(signedPlan);
  const hasChanges = signedPlan.plan.changes.some(
    (change) => !sameCanonicalJson(change.before, change.after),
  );
  const hasAuditOnlyFindings =
    workspaceDirectoryHasAuditOnlyFindings(directoryPlan);
  const auditOnly = !hasChanges && hasAuditOnlyFindings;
  await health.repository.recordPlan(tick.tickId, {
    mode: auditOnly ? "audit" : "live",
    notificationRequired: hasChanges || hasAuditOnlyFindings,
    planHash: signedPlan.plan.planHash,
  });
}

async function captureScheduledHealthCompletion(
  health: ScheduledWorkspaceDirectoryDependencies["scheduleHealth"],
  tick: undefined | WorkspaceScheduleTick,
  result: ScheduledWorkspaceDirectoryResult | undefined,
  failed: boolean,
): Promise<Error[]> {
  if (health === undefined || tick === undefined) return [];
  try {
    await completeScheduledHealth(health, tick.tickId, result, failed);
    return [];
  } catch (error) {
    return [
      scheduledError(error, "workspace_directory_scheduled_health_failed"),
    ];
  }
}

async function completeScheduledHealth(
  health: NonNullable<
    ScheduledWorkspaceDirectoryDependencies["scheduleHealth"]
  >,
  tickId: string,
  result: ScheduledWorkspaceDirectoryResult | undefined,
  failed: boolean,
): Promise<void> {
  const current = await health.repository.read(tickId);
  // Workflow terminal evidence is recovered by the completion bridge, never inferred
  // from launch ACKs or from an exception that may have happened after a write.
  if (current.phase === "launched" || current.phase === "terminal") return;
  const outcome = scheduledHealthOutcome(current, result, failed);
  const blockedReason = failed ? undefined : scheduledBlockedReason(result);
  const terminal =
    blockedReason === undefined
      ? await health.repository.complete(tickId, outcome)
      : await health.repository.complete(tickId, outcome, blockedReason);
  if (terminal.phase !== "terminal")
    throw new Error("workspace_directory_scheduled_terminal_missing");
  if (health.verifyTerminalReceipt === undefined) return;
  const receipt = await health.verifyTerminalReceipt(terminal);
  if (receipt !== null) await health.repository.attachVerifiedReceipt(receipt);
}

function scheduledBlockedReason(
  result: ScheduledWorkspaceDirectoryResult | undefined,
): undefined | WorkspaceScheduleBlockedReason {
  if (result?.kind === "review-required") return "review_required";
  if (result?.kind !== "blocked") return undefined;
  return (
    result.blockedReason ??
    (result.reason === "diagnostics" ? "diagnostics" : "action_policy")
  );
}

function scheduledHealthOutcome(
  current: WorkspaceScheduleTick,
  result: ScheduledWorkspaceDirectoryResult | undefined,
  failed: boolean,
) {
  if (failed || result === undefined) return "failed";
  if (result.kind !== "converged") return "blocked";
  return current.phase === "planned" && current.mode === "audit"
    ? "audit-only"
    : "no-op";
}

function scheduledError(error: unknown, fallbackMessage: string): Error {
  return error instanceof Error
    ? error
    : new Error(fallbackMessage, { cause: error });
}

async function runScheduledWorkspaceDirectoryPlan(
  dependencies: ScheduledWorkspaceDirectoryDependencies,
  observePlan: (plan: SignedOperationPlan) => Promise<void>,
  scheduledTickId?: string,
): Promise<ScheduledWorkspaceDirectoryResult> {
  const reviewed = await runReviewedSlackLifecycleScheduledTick(
    dependencies,
    observePlan,
    scheduledTickId,
  );
  if (reviewed !== null) return reviewed;
  const discoveryPlan = await dependencies.kernel.plan({
    actor: SCHEDULED_ACTOR,
    environment: PRODUCTION_ENVIRONMENT,
    input: {},
    operation: WORKSPACE_DIRECTORY_OPERATION_ID,
  });
  const discoveredDirectoryPlan = workspaceDirectoryPlan(discoveryPlan);
  const discoveryChanges = discoveryPlan.plan.changes.filter(
    (change) => !isWorkspaceObservation(change),
  );
  const safeActionIds = scheduledSafeActionIds(
    discoveryPlan,
    discoveredDirectoryPlan,
    dependencies.parentEnabled,
    dependencies.trycompEnabled === true,
    dependencies.linearSuspensionsEnabled === true,
  );
  if (safeActionIds.length === 0 && discoveryChanges.length > 0) {
    return finishManualOnlyDiscoveryPlan(
      dependencies,
      discoveryPlan,
      discoveredDirectoryPlan,
      observePlan,
    );
  }
  const deferredActionIds = discoveryChanges.flatMap(({ actionId }) => {
    const parsedActionId =
      WorkspaceDirectoryAuthorizedActionIdSchema.parse(actionId);
    return safeActionIds.includes(parsedActionId) ? [] : [parsedActionId];
  });
  const requiresRestrictedPlan = deferredActionIds.length > 0;
  if (requiresRestrictedPlan) await dependencies.announcePlan(discoveryPlan);
  const reportingFailure = await captureAccessIssueReportingFailure(
    discoveredDirectoryPlan,
    dependencies.reportAccessIssues,
  );
  const signedPlan = requiresRestrictedPlan
    ? await dependencies.kernel.plan({
        actor: SCHEDULED_ACTOR,
        environment: PRODUCTION_ENVIRONMENT,
        input: { includedActionIds: safeActionIds },
        operation: WORKSPACE_DIRECTORY_OPERATION_ID,
      })
    : discoveryPlan;
  await observePlan(signedPlan);
  await dependencies.announcePlan(signedPlan);
  const directoryPlan = workspaceDirectoryPlan(signedPlan);
  const linearSuspensions = directoryPlan.branches[4].plan?.actions.length ?? 0;
  const githubIdentityUpdates = githubIdentityUpdateCount(directoryPlan);
  const planHash = signedPlan.plan.planHash;
  const reviewPlanHash = requiresRestrictedPlan
    ? discoveryPlan.plan.planHash
    : undefined;
  if (!signedPlan.plan.applicable) {
    logScheduledResult("blocked", planHash, {
      githubIdentityUpdates,
      linearSuspensions,
    });
    return completeScheduledResult(
      {
        kind: "blocked",
        planHash,
        reason: "diagnostics",
        ...(!(reviewPlanHash === undefined) && { reviewPlanHash }),
      },
      reportingFailure,
    );
  }
  if (
    signedPlan.plan.changes.length === 0 &&
    discoveryPlan.plan.changes.length > 0
  ) {
    const requiredReviewPlanHash = discoveryPlan.plan.planHash;
    logScheduledResult("review_required", requiredReviewPlanHash, {
      githubIdentityUpdates,
      linearSuspensions,
    });
    return completeScheduledResult(
      {
        githubIdentityUpdates,
        kind: "review-required",
        linearSuspensions,
        planHash: requiredReviewPlanHash,
      },
      reportingFailure,
    );
  }
  return executeScheduledPlan({
    deferredActionIds,
    dependencies,
    directoryPlan,
    discoveredDirectoryPlan,
    githubIdentityUpdates,
    linearSuspensions,
    planHash,
    reportingFailure,
    requiresRestrictedPlan,
    reviewPlanHash,
    scheduledTickId,
    signedPlan,
  });
}

interface ScheduledPlanExecution {
  deferredActionIds: readonly WorkspaceDirectoryAuthorizedActionId[];
  dependencies: ScheduledWorkspaceDirectoryDependencies;
  directoryPlan: WorkspaceDirectoryPlan;
  discoveredDirectoryPlan: WorkspaceDirectoryPlan;
  githubIdentityUpdates: number;
  linearSuspensions: number;
  planHash: string;
  reportingFailure: Error | undefined;
  requiresRestrictedPlan: boolean;
  reviewPlanHash: string | undefined;
  scheduledTickId: string | undefined;
  signedPlan: SignedOperationPlan;
}

async function executeScheduledPlan({
  deferredActionIds,
  dependencies,
  directoryPlan,
  discoveredDirectoryPlan,
  githubIdentityUpdates,
  linearSuspensions,
  planHash,
  reportingFailure,
  requiresRestrictedPlan,
  reviewPlanHash,
  scheduledTickId,
  signedPlan,
}: ScheduledPlanExecution): Promise<ScheduledWorkspaceDirectoryResult> {
  const prepared = await dependencies.kernel.prepareApply(
    {
      confirmPlanHash: planHash,
      confirmations: {
        githubIdentityUpdates: { allowed: false, expectedCount: 0 },
        linearSuspensions: isScheduledLinearSuspension(
          signedPlan,
          directoryPlan,
          dependencies.parentEnabled &&
            dependencies.linearSuspensionsEnabled === true,
        )
          ? { allowed: true, expectedCount: 1 }
          : { allowed: false, expectedCount: 0 },
      },
      riskAcknowledged: scheduledParentRiskAcknowledged(
        signedPlan,
        directoryPlan,
        dependencies.parentEnabled,
        dependencies.trycompEnabled === true,
        dependencies.linearSuspensionsEnabled === true,
      ),
      signedPlan,
    },
    { actor: SCHEDULED_ACTOR, environment: PRODUCTION_ENVIRONMENT },
  );
  if (!prepared.ok) {
    logScheduledResult("blocked", planHash, {
      githubIdentityUpdates,
      linearSuspensions,
    });
    return completeScheduledResult(
      {
        kind: "blocked",
        planHash,
        reason: "safety-policy",
        blockedReason:
          prepared.result.state === "applied" ||
          prepared.result.state === "noop"
            ? "action_policy"
            : prepared.result.code,
        ...(!(reviewPlanHash === undefined) && { reviewPlanHash }),
      },
      reportingFailure,
    );
  }
  const authorizedActionIds = prepared.pending.map(({ actionId }) =>
    WorkspaceDirectoryAuthorizedActionIdSchema.parse(actionId),
  );
  if (authorizedActionIds.length === 0) {
    return completeScheduledResult(
      finishNoAuthorizedActions({
        deferredActionIds,
        discoveredDirectoryPlan,
        githubIdentityUpdates,
        linearSuspensions,
        planHash,
        requiresRestrictedPlan,
        reviewPlanHash,
      }),
      reportingFailure,
    );
  }
  const latestSafeActionIds = scheduledSafeActionIds(
    signedPlan,
    directoryPlan,
    dependencies.parentEnabled,
    dependencies.trycompEnabled === true,
    dependencies.linearSuspensionsEnabled === true,
  );
  if (
    !scheduledAuthorizedActionsAreSafe(
      authorizedActionIds,
      latestSafeActionIds,
      directoryPlan,
    )
  ) {
    logScheduledResult("blocked", planHash, {
      githubIdentityUpdates,
      linearSuspensions,
    });
    return completeScheduledResult(
      {
        kind: "blocked",
        planHash,
        reason: "safety-policy",
        ...(!(reviewPlanHash === undefined) && { reviewPlanHash }),
      },
      reportingFailure,
    );
  }
  const workflowParams = WorkspaceDirectoryWorkflowParamsSchema.parse({
    authorizedActionIds,
    plan: directoryPlan,
    planGeneratedAt: signedPlan.plan.generatedAt,
    planHash,
    requestedBy: SCHEDULED_ACTOR.id,
    ...(!(scheduledTickId === undefined) && { scheduledTickId }),
  });
  if (
    dependencies.scheduleHealth !== undefined &&
    scheduledTickId !== undefined
  ) {
    await dependencies.scheduleHealth.repository.launch(
      WorkspaceScheduleExecutionIdentitySchema.parse({
        tickId: scheduledTickId,
        workflowId: await workspaceDirectoryExecutionId(workflowParams),
      }),
    );
  }
  const accepted = await launchWorkspaceDirectoryWorkflow(
    dependencies.workflow,
    workflowParams,
  );
  logScheduledResult("launched", planHash, {
    githubIdentityUpdates,
    linearSuspensions,
    ...(!(reviewPlanHash === undefined) && { reviewPlanHash }),
  });
  return completeScheduledResult(
    {
      instanceId: accepted.instanceId,
      kind: "launched",
      planHash,
      ...(!(reviewPlanHash === undefined) && { reviewPlanHash }),
    },
    reportingFailure,
  );
}

function scheduledAuthorizedActionsAreSafe(
  authorizedActionIds: readonly WorkspaceDirectoryAuthorizedActionId[],
  latestSafeActionIds: readonly WorkspaceDirectoryAuthorizedActionId[],
  directoryPlan: WorkspaceDirectoryPlan,
): boolean {
  if (
    authorizedActionIds.some(
      (actionId) => !latestSafeActionIds.includes(actionId),
    )
  )
    return false;
  if (
    authorizedActionIds.includes(
      WORKSPACE_DIRECTORY_SLACK_GROUPS_CHANNELS_ACTION_ID,
    ) &&
    !isScheduledSlackUserGroupReconciliation(directoryPlan.branches[2])
  )
    return false;
  return authorizedActionIds.every(scheduledExecutionAllowsApply);
}

async function runReviewedSlackLifecycleScheduledTick(
  dependencies: ScheduledWorkspaceDirectoryDependencies,
  observePlan: (plan: SignedOperationPlan) => Promise<void>,
  tickId?: string,
) {
  const intents = dependencies.reviewedLifecycleIntents;
  if (intents === undefined) return null;
  const health = dependencies.scheduleHealth;
  if (
    !dependencies.parentEnabled ||
    tickId === undefined ||
    health === undefined
  )
    throw new Error("workspace_reviewed_lifecycle_scheduled_context_required");
  return runReviewedSlackLifecycleIntent({
    intents,
    kernel: dependencies.kernel,
    announcePlan: dependencies.announcePlan,
    observePlan,
    tickId,
    launch: async (params) => {
      const intent =
        params.reviewedProviderIntent ?? params.reviewedSlackLifecycleIntent;
      if (intent === undefined)
        throw new Error(
          "workspace_reviewed_lifecycle_original_intent_required",
        );
      const workflowId = await workspaceDirectoryExecutionId(params);
      await intents.assertClaimed(intent, tickId);
      await health.repository.launch(
        WorkspaceScheduleExecutionIdentitySchema.parse({
          tickId,
          workflowId,
        }),
      );
      await intents.assertClaimed(intent, tickId);
      return launchWorkspaceDirectoryWorkflow(dependencies.workflow, params);
    },
  });
}

function completeScheduledResult(
  result: ScheduledWorkspaceDirectoryResult,
  reportingFailure: Error | undefined,
): ScheduledWorkspaceDirectoryResult {
  if (reportingFailure !== undefined) throw reportingFailure;
  return result;
}

function finishNoAuthorizedActions(options: {
  deferredActionIds: readonly WorkspaceDirectoryAuthorizedActionId[];
  discoveredDirectoryPlan: WorkspaceDirectoryPlan;
  githubIdentityUpdates: number;
  linearSuspensions: number;
  planHash: string;
  requiresRestrictedPlan: boolean;
  reviewPlanHash: string | undefined;
}): ScheduledWorkspaceDirectoryResult {
  if (
    options.deferredActionIds.includes(
      WORKSPACE_DIRECTORY_SLACK_GROUPS_CHANNELS_ACTION_ID,
    )
  ) {
    logScheduledResult("blocked", options.planHash, {
      githubIdentityUpdates: options.githubIdentityUpdates,
      linearSuspensions: options.linearSuspensions,
      ...(!(options.reviewPlanHash === undefined) && {
        reviewPlanHash: options.reviewPlanHash,
      }),
    });
    return {
      kind: "blocked",
      planHash: options.planHash,
      reason: "safety-policy",
      ...(!(options.reviewPlanHash === undefined) && {
        reviewPlanHash: options.reviewPlanHash,
      }),
    };
  }
  if (options.requiresRestrictedPlan) {
    const linearSuspensions =
      options.discoveredDirectoryPlan.branches[4].plan?.actions.length ?? 0;
    const githubIdentityUpdates = githubIdentityUpdateCount(
      options.discoveredDirectoryPlan,
    );
    const reviewPlanHash = options.reviewPlanHash;
    if (reviewPlanHash === undefined)
      throw new Error("workspace_directory_scheduled_review_plan_hash_missing");
    logScheduledResult("review_required", reviewPlanHash, {
      githubIdentityUpdates,
      linearSuspensions,
    });
    return {
      githubIdentityUpdates,
      kind: "review-required",
      linearSuspensions,
      planHash: reviewPlanHash,
    };
  }
  logScheduledResult("converged", options.planHash, {
    githubIdentityUpdates: options.githubIdentityUpdates,
    linearSuspensions: options.linearSuspensions,
  });
  return { kind: "converged", planHash: options.planHash };
}

async function finishManualOnlyDiscoveryPlan(
  dependencies: ScheduledWorkspaceDirectoryDependencies,
  signedPlan: SignedOperationPlan,
  directoryPlan: WorkspaceDirectoryPlan,
  observePlan: (plan: SignedOperationPlan) => Promise<void>,
): Promise<ScheduledWorkspaceDirectoryResult> {
  await observePlan(signedPlan);
  await dependencies.announcePlan(signedPlan);
  const reportingFailure = await captureAccessIssueReportingFailure(
    directoryPlan,
    dependencies.reportAccessIssues,
  );
  const planHash = signedPlan.plan.planHash;
  const linearSuspensions = directoryPlan.branches[4].plan?.actions.length ?? 0;
  const githubIdentityUpdates = githubIdentityUpdateCount(directoryPlan);
  if (!signedPlan.plan.applicable) {
    logScheduledResult("blocked", planHash, {
      githubIdentityUpdates,
      linearSuspensions,
    });
    return completeScheduledResult(
      { kind: "blocked", planHash, reason: "diagnostics" },
      reportingFailure,
    );
  }
  logScheduledResult("review_required", planHash, {
    githubIdentityUpdates,
    linearSuspensions,
  });
  return completeScheduledResult(
    {
      githubIdentityUpdates,
      kind: "review-required",
      linearSuspensions,
      planHash,
    },
    reportingFailure,
  );
}

function scheduledSafeActionIds(
  signedPlan: SignedOperationPlan,
  directoryPlan: WorkspaceDirectoryPlan,
  parentEnabled: boolean,
  trycompEnabled: boolean,
  linearSuspensionsEnabled: boolean,
): WorkspaceDirectoryAuthorizedActionId[] {
  if (!parentEnabled) return [];
  const eligible = signedPlan.plan.changes.flatMap((change) => {
    if (isWorkspaceObservation(change)) return [];
    const { actionId } = change;
    const parsedActionId =
      WorkspaceDirectoryAuthorizedActionIdSchema.parse(actionId);
    if (
      !scheduledExecutionAllowsApply(parsedActionId) ||
      !boundedParentActionAllowed(
        parsedActionId,
        signedPlan,
        directoryPlan,
        parentEnabled,
      ) ||
      !scheduledSelectionAllowsApply(
        parsedActionId,
        signedPlan,
        directoryPlan,
        {
          linearSuspensionsEnabled,
          trycompEnabled,
        },
      )
    ) {
      return [];
    }
    return [parsedActionId];
  });
  // Cleanup changes Google membership authority used by GitHub, Comp, and Linear names.
  // Replan those consumers on a later tick instead of invalidating their signed sources.
  return eligible.includes(WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup)
    ? eligible.filter(
        (actionId) =>
          actionId !== WORKSPACE_DIRECTORY_ACTION_IDS.githubAccess &&
          actionId !== WORKSPACE_DIRECTORY_ACTION_IDS.trycompPeople &&
          actionId !== WORKSPACE_DIRECTORY_ACTION_IDS.linearProfiles,
      )
    : eligible;
}

function scheduledSelectionAllowsApply(
  actionId: WorkspaceDirectoryAuthorizedActionId,
  signedPlan: SignedOperationPlan,
  directoryPlan: WorkspaceDirectoryPlan,
  enabled: {
    linearSuspensionsEnabled: boolean;
    trycompEnabled: boolean;
  },
): boolean {
  switch (actionId) {
    case WORKSPACE_DIRECTORY_ACTION_IDS.linearSuspensions:
      return isScheduledLinearSuspension(
        signedPlan,
        directoryPlan,
        enabled.linearSuspensionsEnabled,
      );
    case WORKSPACE_DIRECTORY_ACTION_IDS.trycompPeople:
      return isScheduledTrycompAction(
        signedPlan,
        directoryPlan,
        enabled.trycompEnabled,
      );
    case WORKSPACE_DIRECTORY_FANOUT_ACTION_ID:
      return githubIdentityUpdateCount(directoryPlan) === 0;
    case WORKSPACE_DIRECTORY_SLACK_GROUPS_CHANNELS_ACTION_ID:
      return isScheduledSlackUserGroupReconciliation(directoryPlan.branches[2]);
    case WORKSPACE_DIRECTORY_ACTION_IDS.driveOrgChart:
    case WORKSPACE_DIRECTORY_ACTION_IDS.githubAccess:
    case WORKSPACE_DIRECTORY_ACTION_IDS.slackProfiles:
    case WORKSPACE_DIRECTORY_ACTION_IDS.slackNames:
    case WORKSPACE_DIRECTORY_ACTION_IDS.linearProfiles:
    case WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup:
    case WORKSPACE_DIRECTORY_ACTION_IDS.pagerDutyTeams:
    case WORKSPACE_DIRECTORY_ACTION_IDS.sentryMemberships:
      return true;
  }
}

function isScheduledTrycompAction(
  signedPlan: SignedOperationPlan,
  directoryPlan: WorkspaceDirectoryPlan,
  enabled: boolean,
): boolean {
  const branch = directoryPlan.branches.find(
    (candidate) => candidate.branchId === "trycomp-people",
  );
  if (
    !enabled ||
    branch?.execution !== "managed" ||
    branch.diagnostics.some(({ severity }) => severity === "blocker") ||
    branch.reviewedPlan.plan.errors.length > 0 ||
    branch.reviewedPlan.plan.actions.length !== 1
  )
    return false;
  const action = branch.reviewedPlan.plan.actions[0];
  const changes = signedPlan.plan.changes.filter(
    ({ actionId }) => actionId === WORKSPACE_DIRECTORY_ACTION_IDS.trycompPeople,
  );
  const change = changes[0];
  if (
    action === undefined ||
    changes.length !== 1 ||
    change?.resource.type !== "trycomp-person" ||
    change.resource.id !==
      (action.type === "invite" ? action.email : action.memberId)
  )
    return false;
  if (action.type === "deactivate") {
    return (
      change.kind === "remove" &&
      change.risk === "high" &&
      (action.deactivationAuthority === "contractor_group" ||
        action.deactivationAuthority === "inactive_google")
    );
  }
  return (
    change.kind === (action.type === "invite" ? "add" : "change") &&
    change.risk === "medium"
  );
}

function scheduledParentRiskAcknowledged(
  signedPlan: SignedOperationPlan,
  directoryPlan: WorkspaceDirectoryPlan,
  parentEnabled: boolean,
  trycompEnabled: boolean,
  linearSuspensionsEnabled: boolean,
): boolean {
  const linear = isScheduledLinearSuspension(
    signedPlan,
    directoryPlan,
    parentEnabled && linearSuspensionsEnabled,
  );
  const trycomp = isScheduledTrycompAction(
    signedPlan,
    directoryPlan,
    trycompEnabled,
  );
  const cleanup = isScheduledGoogleGroupCleanup(
    signedPlan,
    directoryPlan,
    parentEnabled,
  );
  const pagerDuty = isScheduledPagerDutyTeams(
    signedPlan,
    directoryPlan,
    parentEnabled,
  );
  const slack = isScheduledSlackUserGroupReconciliation(
    directoryPlan.branches[2],
  );
  const sentry = isScheduledSentryMemberships(
    signedPlan,
    directoryPlan,
    parentEnabled,
  );
  if (!trycomp && !cleanup && !pagerDuty && !slack && !linear && !sentry)
    return false;
  const riskyChanges = signedPlan.plan.changes.filter(
    ({ kind, risk }) => kind === "remove" || risk === "high",
  );
  return (
    riskyChanges.length > 0 &&
    riskyChanges.every(
      ({ actionId }) =>
        (sentry &&
          actionId === WORKSPACE_DIRECTORY_ACTION_IDS.sentryMemberships) ||
        (linear &&
          actionId === WORKSPACE_DIRECTORY_ACTION_IDS.linearSuspensions) ||
        (trycomp &&
          actionId === WORKSPACE_DIRECTORY_ACTION_IDS.trycompPeople) ||
        (cleanup &&
          actionId === WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup) ||
        (pagerDuty &&
          actionId === WORKSPACE_DIRECTORY_ACTION_IDS.pagerDutyTeams) ||
        (slack &&
          actionId === WORKSPACE_DIRECTORY_SLACK_GROUPS_CHANNELS_ACTION_ID),
    )
  );
}

function boundedParentActionAllowed(
  actionId: WorkspaceDirectoryAuthorizedActionId,
  signedPlan: SignedOperationPlan,
  directoryPlan: WorkspaceDirectoryPlan,
  enabled: boolean,
): boolean {
  if (actionId === WORKSPACE_DIRECTORY_ACTION_IDS.slackProfiles)
    return isScheduledSlackProfiles(signedPlan, directoryPlan, enabled);
  if (actionId === WORKSPACE_DIRECTORY_ACTION_IDS.githubAccess)
    return isScheduledGitHubAccess(signedPlan, directoryPlan, enabled);
  if (actionId === WORKSPACE_DIRECTORY_ACTION_IDS.pagerDutyTeams)
    return isScheduledPagerDutyTeams(signedPlan, directoryPlan, enabled);
  if (actionId === WORKSPACE_DIRECTORY_ACTION_IDS.sentryMemberships)
    return isScheduledSentryMemberships(signedPlan, directoryPlan, enabled);
  if (actionId === WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup)
    return isScheduledGoogleGroupCleanup(signedPlan, directoryPlan, enabled);
  return true;
}

export function isScheduledSlackProfiles(
  signedPlan: SignedOperationPlan,
  directoryPlan: WorkspaceDirectoryPlan,
  enabled: boolean,
): boolean {
  const branch = directoryPlan.branches[0];
  const changes = signedPlan.plan.changes.filter(
    ({ actionId }) => actionId === WORKSPACE_DIRECTORY_ACTION_IDS.slackProfiles,
  );
  const change = changes.length === 1 ? changes[0] : undefined;
  const selected = branch.changes.length === 1 ? branch.changes[0] : undefined;
  return (
    enabled &&
    branch.execution === "managed" &&
    !branch.diagnostics.some(({ severity }) => severity === "blocker") &&
    selected?.reason === "matched" &&
    selected.googleUserId !== null &&
    change?.resource.type === "slack-profile" &&
    change.resource.id === "profiles" &&
    change.kind === "change" &&
    change.risk === "medium" &&
    sameJson(
      change.before,
      branch.changes.map(({ before, slackUserId }) => ({
        fields: before,
        slackUserId,
      })),
    ) &&
    sameJson(
      change.after,
      branch.changes.map(({ after, slackUserId }) => ({
        fields: after,
        slackUserId,
      })),
    )
  );
}

export function isScheduledSentryMemberships(
  signedPlan: SignedOperationPlan,
  directoryPlan: WorkspaceDirectoryPlan,
  enabled: boolean,
): boolean {
  const branch = directoryPlan.branches.find(
    (candidate) => candidate.branchId === "sentry-memberships",
  );
  const changes = signedPlan.plan.changes.filter(
    ({ actionId }) =>
      actionId === WORKSPACE_DIRECTORY_ACTION_IDS.sentryMemberships,
  );
  const change = changes.length === 1 ? changes[0] : undefined;
  if (
    !enabled ||
    branch?.execution !== "managed" ||
    branch.reviewed === null ||
    branch.sourceFingerprint !== directoryPlan.authorityFingerprint ||
    branch.diagnostics.some(({ severity }) => severity === "blocker") ||
    change === undefined
  ) {
    return false;
  }
  return (
    change.resource.type === "sentry-membership" &&
    change.resource.id === sentryWorkspaceResourceId(branch.reviewed) &&
    change.kind === scheduledSentryChangeKind(branch.reviewed.action.type) &&
    change.risk ===
      (branch.reviewed.action.type === "remove-organization-member"
        ? "high"
        : "medium") &&
    sameJson(
      change.before,
      sentryWorkspaceManagedSlice(branch.reviewed, "pending"),
    ) &&
    sameJson(
      change.after,
      sentryWorkspaceManagedSlice(branch.reviewed, "converged"),
    )
  );
}

export function isScheduledPagerDutyTeams(
  signedPlan: SignedOperationPlan,
  directoryPlan: WorkspaceDirectoryPlan,
  enabled: boolean,
): boolean {
  const branch = directoryPlan.branches.find(
    (candidate) => candidate.branchId === "pagerduty-teams",
  );
  const changes = signedPlan.plan.changes.filter(
    ({ actionId }) =>
      actionId === WORKSPACE_DIRECTORY_ACTION_IDS.pagerDutyTeams,
  );
  const change = changes.length === 1 ? changes[0] : undefined;
  if (
    !enabled ||
    branch?.execution !== "managed" ||
    branch.reviewed === null ||
    branch.sourceFingerprint !== directoryPlan.authorityFingerprint ||
    branch.diagnostics.some(({ severity }) => severity === "blocker") ||
    change === undefined
  )
    return false;
  return (
    change.resource.type === "pagerduty-team-membership" &&
    change.resource.id === pagerDutyTeamResourceId(branch.reviewed) &&
    change.kind ===
      (branch.reviewed.action.type === "add" ? "add" : "change") &&
    change.risk === "high" &&
    sameJson(
      change.before,
      pagerDutyTeamManagedSlice(branch.reviewed, "pending"),
    ) &&
    sameJson(
      change.after,
      pagerDutyTeamManagedSlice(branch.reviewed, "converged"),
    )
  );
}

export function isScheduledGoogleGroupCleanup(
  signedPlan: SignedOperationPlan,
  directoryPlan: WorkspaceDirectoryPlan,
  enabled: boolean,
): boolean {
  const branch = directoryPlan.branches.find(
    (candidate) => candidate.branchId === "google-group-cleanup",
  );
  const changes = signedPlan.plan.changes.filter(
    ({ actionId }) =>
      actionId === WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup,
  );
  const change = changes[0];
  const reviewed = branch?.reviewed;
  return (
    enabled &&
    branch?.execution === "managed" &&
    !branch.killSwitchEngaged &&
    !branch.diagnostics.some(({ severity }) => severity === "blocker") &&
    reviewed !== null &&
    reviewed !== undefined &&
    reviewed.action.googleUserId === reviewed.action.memberId &&
    changes.length === 1 &&
    change?.kind === "remove" &&
    change.risk === "high" &&
    change.resource.type === "google-group-membership" &&
    change.resource.id ===
      `${reviewed.action.googleGroupId}:${reviewed.action.memberId}` &&
    sameJson(
      change.before,
      googleGroupCleanupManagedSlice(reviewed, "pending"),
    ) &&
    sameJson(
      change.after,
      googleGroupCleanupManagedSlice(reviewed, "converged"),
    )
  );
}

function sameJson(left: unknown, right: unknown): boolean {
  return dequal(left, right);
}

function scheduledExecutionAllowsApply(
  actionId: WorkspaceDirectoryAuthorizedActionId,
): boolean {
  const policy = workspaceDirectoryBranch(
    SCHEDULED_ACTION_BRANCH_BY_ID[actionId],
  ).scheduledExecution;
  switch (policy) {
    case "automatic":
    case "bounded-automatic":
    case "rollout-gated":
      return true;
    case "audit-only":
    case "manual-review":
      return false;
    default:
      return assertNeverScheduledExecution(policy);
  }
}

function assertNeverScheduledExecution(value: never): never {
  throw new Error(
    `unsupported workspace directory scheduled execution: ${String(value)}`,
  );
}

async function captureAccessIssueReportingFailure(
  plan: WorkspaceDirectoryPlan,
  report: ScheduledWorkspaceDirectoryDependencies["reportAccessIssues"],
): Promise<Error | undefined> {
  if (report === undefined) return;
  let reportingFailure: Error | undefined;
  try {
    await report(plan);
  } catch (error) {
    logEvent(
      "workspace_directory.reporting_failed",
      sanitizedErrorFields(error),
    );
    reportingFailure = scheduledError(
      error,
      "workspace_directory_reporting_failed",
    );
  }
  return reportingFailure;
}

function workspaceDirectoryPlan(
  signedPlan: SignedOperationPlan,
): WorkspaceDirectoryPlan {
  const embeddedPlans = signedPlan.plan.changes.flatMap(({ details }) => {
    const parsed = WorkspaceDirectoryChangeDetailsSchema.safeParse(details);
    return parsed.success && "plan" in parsed.data ? [parsed.data.plan] : [];
  });
  if (embeddedPlans.length === 0)
    throw new Error("workspace_directory_scheduled_plan_missing");
  const plan = embeddedPlans[0];
  if (!plan) throw new Error("workspace_directory_scheduled_plan_missing");
  return plan;
}

function githubIdentityUpdateCount(plan: WorkspaceDirectoryPlan): number {
  const seed = plan.branches[5].githubIdentitySeed;
  return seed.kind === "managed"
    ? seed.userPlans.filter(({ kind }) => kind === "update").length
    : 0;
}

function logScheduledResult(
  status: "blocked" | "converged" | "launched" | "review_required",
  planHash: string,
  counts: {
    githubIdentityUpdates: number;
    linearSuspensions: number;
    reviewPlanHash?: string;
  },
): void {
  logEvent("workspace_directory.scheduled", {
    "github_identity_updates": counts.githubIdentityUpdates,
    "linear_suspensions": counts.linearSuspensions,
    "plan_hash": planHash,
    ...(!(counts.reviewPlanHash === undefined) && {
      "review_plan_hash": counts.reviewPlanHash,
    }),
    status,
  });
}

function scheduledSentryChangeKind(type: string): "add" | "change" | "remove" {
  if (type === "remove-organization-member") return "remove";
  return type === "invite" ? "add" : "change";
}
