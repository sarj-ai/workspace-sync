import { z } from "zod";

import {
  WORKSPACE_DIRECTORY_FLOW,
  WorkspaceDirectoryBranchIdSchema,
  WorkspaceDirectoryScheduledExecutionSchema,
} from "./flow.ts";
import type { WorkspaceScheduleHealth } from "./workspace-schedule-health-repository.ts";

const DigestSchema = z.string().regex(/^[a-f0-9]{64}$/u);
const TimeSchema = z.number().int().nonnegative();
const AttentionReasonSchema = z.enum([
  "latest-run-blocked",
  "latest-run-failed",
  "mutation-safety-unresolved",
  "pending-schedule-ticks",
  "schedule-unhealthy",
]);
const DiagnosticSeveritySchema = z.enum(["blocker", "warning"]);
const LastMutationSchema = z.enum(["none", "attempted", "verified"]);
const ModeSchema = z.enum(["audit", "live"]);
const OutcomeSchema = z.enum([
  "applied",
  "audit-only",
  "blocked",
  "failed",
  "no-op",
]);
const PhaseSchema = z.enum(["started", "planned", "launched", "terminal"]);
const RolloutStateSchema = z.enum(["disabled", "enabled"]);

const WorkspaceStatusDiagnosticSchema = z.strictObject({
  code: z.string().trim().min(1).max(100),
  severity: DiagnosticSeveritySchema,
});

const WorkspaceStatusBranchSchema = z.strictObject({
  branchId: WorkspaceDirectoryBranchIdSchema,
  blockerCount: z.number().int().nonnegative(),
  diagnostics: z.array(WorkspaceStatusDiagnosticSchema).max(20),
  diagnosticsTruncated: z.boolean(),
  displayName: z.string().trim().min(1),
  latestRunMutation: LastMutationSchema,
  rolloutState: RolloutStateSchema,
  scheduledExecution: WorkspaceDirectoryScheduledExecutionSchema,
  targetSystemIds: z.array(z.string().trim().min(1)),
  warningCount: z.number().int().nonnegative(),
});

const WorkspaceStatusLatestSchema = z.strictObject({
  completedAtMs: TimeSchema.nullable(),
  deployment: z.strictObject({
    id: z.string().trim().min(1),
    revision: z.string().regex(/^[a-f0-9]{40}$/u),
    timestamp: z.iso.datetime(),
  }),
  mode: ModeSchema.nullable(),
  notificationRequired: z.boolean(),
  notificationVerified: z.boolean(),
  outcome: OutcomeSchema.nullable(),
  phase: PhaseSchema,
  planHash: DigestSchema.nullable(),
  scheduledAtMs: TimeSchema,
  startedAtMs: TimeSchema,
  tickId: DigestSchema,
  workflowId: DigestSchema.nullable(),
});

export const WorkspaceSyncStatusResponseSchema = z
  .strictObject({
    branches: z.array(WorkspaceStatusBranchSchema),
    attentionReasons: z.array(AttentionReasonSchema).max(5),
    healthy: z.boolean(),
    latest: WorkspaceStatusLatestSchema.nullable(),
    mutationSafetyClear: z.boolean(),
    observedAt: z.iso.datetime(),
    pendingTicks: z.number().int().nonnegative(),
    scheduleHealthy: z.boolean(),
    schemaVersion: z.literal("workspace-sync-status/v1"),
    unresolvedMutations: z.number().int().nonnegative(),
  })
  .meta({ id: "WorkspaceSyncStatus" });

export function workspaceSyncStatus(
  health: WorkspaceScheduleHealth,
  observedAtMs: number,
): z.output<typeof WorkspaceSyncStatusResponseSchema> {
  const latest = health.latest;
  const planBranches = new Map(
    latest?.execution?.params.plan.branches.map((branch) => [
      branch.branchId,
      branch,
    ]),
  );
  const attempts = latest?.branchAttempts ?? [];

  return WorkspaceSyncStatusResponseSchema.parse({
    attentionReasons: projectAttentionReasons(health),
    branches: WORKSPACE_DIRECTORY_FLOW.branches.map((branch) => {
      const planBranch = planBranches.get(branch.branchId);
      const branchAttempts = attempts.filter(
        ({ branchId }) => branchId === branch.branchId,
      );
      const diagnostics =
        planBranch?.diagnostics.filter(({ severity }) => severity !== "info") ??
        [];
      return {
        branchId: branch.branchId,
        blockerCount: diagnostics.filter(
          ({ severity }) => severity === "blocker",
        ).length,
        diagnostics: diagnostics.slice(0, 20).map(({ code, severity }) => ({
          code: code.slice(0, 100),
          severity,
        })),
        diagnosticsTruncated: diagnostics.length > 20,
        displayName: branch.displayName,
        latestRunMutation: projectLatestRunMutation(branchAttempts),
        rolloutState: branch.rolloutState,
        scheduledExecution: branch.scheduledExecution,
        targetSystemIds: branch.targets.map(({ systemId }) => systemId),
        warningCount: diagnostics.filter(
          ({ severity }) => severity === "warning",
        ).length,
      };
    }),
    healthy: health.healthy,
    latest: projectLatest(latest),
    mutationSafetyClear: health.mutationSafetyClear,
    observedAt: new Date(observedAtMs).toISOString(),
    pendingTicks: health.pendingTicks,
    scheduleHealthy: health.scheduleHealthy,
    schemaVersion: "workspace-sync-status/v1",
    unresolvedMutations: health.unresolvedMutations,
  });
}

function projectAttentionReasons(health: WorkspaceScheduleHealth) {
  const reasons: z.input<
    typeof WorkspaceSyncStatusResponseSchema
  >["attentionReasons"] = [];
  if (!health.scheduleHealthy) reasons.push("schedule-unhealthy");
  if (health.pendingTicks > 0) reasons.push("pending-schedule-ticks");
  if (!health.mutationSafetyClear) reasons.push("mutation-safety-unresolved");
  if (
    health.latest?.phase === "terminal" &&
    health.latest.outcome === "blocked"
  ) {
    reasons.push("latest-run-blocked");
  }
  if (
    health.latest?.phase === "terminal" &&
    health.latest.outcome === "failed"
  ) {
    reasons.push("latest-run-failed");
  }
  return reasons;
}

function projectLatestRunMutation(
  attempts: NonNullable<WorkspaceScheduleHealth["latest"]>["branchAttempts"],
) {
  if (attempts?.some(({ state }) => state === "attempted"))
    return "attempted" as const;
  if (attempts?.some(({ state }) => state === "verified"))
    return "verified" as const;
  return "none" as const;
}

function projectLatest(latest: WorkspaceScheduleHealth["latest"]) {
  if (latest === null) return null;
  const terminal = latest.phase === "terminal";
  const hasWorkflow = latest.phase === "launched" || terminal;
  return {
    completedAtMs: terminal ? latest.completedAtMs : null,
    deployment: latest.deployment,
    mode: latest.phase === "started" ? null : latest.mode,
    notificationRequired:
      latest.phase !== "started" && latest.notificationRequired,
    notificationVerified: terminal && latest.receipt !== null,
    outcome: terminal ? latest.outcome : null,
    phase: latest.phase,
    planHash: latest.phase === "started" ? null : latest.planHash,
    scheduledAtMs: latest.scheduledAtMs,
    startedAtMs: latest.startedAtMs,
    tickId: latest.tickId,
    workflowId: hasWorkflow ? latest.workflowId : null,
  };
}
