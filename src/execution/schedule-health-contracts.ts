import { dequal } from "dequal";
import { z } from "zod";

import {
  type WorkspaceBranchAttempt,
  WorkspaceBranchAttemptSchema,
} from "./branch-attempt-contracts.ts";
import { workspaceChangeLedgerChannelId } from "./change-ledger-contracts.ts";
import {
  WorkspaceDirectoryWorkflowParamsSchema,
  WorkspaceDirectoryWorkflowResultSchema,
} from "./contracts.ts";
import { WorkspaceDirectoryBranchIdSchema } from "./flow.ts";
import {
  managedBranchActionId,
  parseSuccessfulWorkflowResult,
} from "./workflow.ts";

const DigestSchema = z.string().regex(/^[a-f0-9]{64}$/u);
const TimeSchema = z.number().int().nonnegative();
const OutcomeSchema = z.enum([
  "applied",
  "audit-only",
  "blocked",
  "failed",
  "no-op",
]);
const ModeSchema = z.enum(["audit", "live"]);

/** Categorical pre-dispatch evidence only; never provider messages or identities. */
export const WorkspaceScheduleBlockedReasonSchema = z.enum([
  "diagnostics",
  "review_required",
  "action_policy",
  "plan_expired",
  "source_drift",
  "target_drift",
  "read_failed",
  "write_failed",
  "readback_failed",
  "mutation_confirmation_mismatch",
  "mutation_confirmation_required",
  "apply_not_supported",
  "plan_blocked",
  "risk_acknowledgement_required",
]);
export type WorkspaceScheduleBlockedReason = z.output<
  typeof WorkspaceScheduleBlockedReasonSchema
>;

const OriginalHandleStateSchema = z.enum(["announced", "completed"]);
const OriginalHandleSchema = z.strictObject({
  announcementDigest: DigestSchema,
  changeKey: z.string().min(1),
  channelId: z
    .string()
    .refine((value) => value === workspaceChangeLedgerChannelId()),
  state: OriginalHandleStateSchema,
  timestamp: z.string().regex(/^\d+\.\d{6}$/u),
});
export const WorkspaceScheduleExecutionManifestSchema = z.strictObject({
  params: WorkspaceDirectoryWorkflowParamsSchema,
  summaryHandle: OriginalHandleSchema,
  branchHandles: z
    .array(
      z.strictObject({
        branchId: WorkspaceDirectoryBranchIdSchema,
        change: z.strictObject({
          changeKey: z.string().min(1),
          text: z.string().min(1),
        }),
        handle: OriginalHandleSchema,
      }),
    )
    .max(1000),
});
export type WorkspaceScheduleExecutionManifest = z.output<
  typeof WorkspaceScheduleExecutionManifestSchema
>;
export const WorkspaceScheduleExecutionSchema =
  WorkspaceScheduleExecutionManifestSchema.extend({
    version: z.literal("workspace-receipt-recovery/v1"),
    paramsDigest: DigestSchema,
    startedAtMs: TimeSchema,
    result: WorkspaceDirectoryWorkflowResultSchema.nullable(),
  }).meta({ id: "WorkspaceScheduleExecution" });
export type WorkspaceScheduleExecution = z.output<
  typeof WorkspaceScheduleExecutionSchema
>;

export const WorkspaceScheduleStartSchema = z.strictObject({
  deployment: z.strictObject({
    id: z.string().min(1).max(200),
    revision: z.string().regex(/^[a-f0-9]{40}$/u),
    timestamp: z.iso.datetime(),
  }),
  scheduledAtMs: TimeSchema,
});
export type WorkspaceScheduleStart = z.output<
  typeof WorkspaceScheduleStartSchema
>;

export const WorkspaceSchedulePlanSchema = z.strictObject({
  mode: ModeSchema,
  notificationRequired: z.boolean(),
  planHash: DigestSchema,
});
export type WorkspaceSchedulePlan = z.output<
  typeof WorkspaceSchedulePlanSchema
>;

/** Input is an attestation from the existing Slack readback verifier, never a send acknowledgement. */
export const WorkspaceScheduleReceiptSchema = z.strictObject({
  channelId: z
    .string()
    .refine((value) => value === workspaceChangeLedgerChannelId()),
  contentHash: DigestSchema,
  outcome: OutcomeSchema,
  planHash: DigestSchema.nullable(),
  slackTimestamp: z.string().regex(/^\d+\.\d+$/u),
  tickId: DigestSchema,
  verifiedAtMs: TimeSchema,
  workflowId: DigestSchema.nullable(),
});
export type WorkspaceScheduleReceipt = z.output<
  typeof WorkspaceScheduleReceiptSchema
>;
export const WorkspaceScheduleExecutionReceiptsSchema = z
  .strictObject({
    branchReceipts: z
      .array(
        z.strictObject({
          branchId: WorkspaceDirectoryBranchIdSchema,
          changeKey: z.string().min(1),
          channelId: z
            .string()
            .refine((value) => value === workspaceChangeLedgerChannelId()),
          timestamp: z.string().regex(/^\d+\.\d{6}$/u),
          contentHash: DigestSchema,
          verifiedAtMs: TimeSchema,
        }),
      )
      .max(1000),
    summaryReceipt: WorkspaceScheduleReceiptSchema,
  })
  .meta({ id: "WorkspaceScheduleExecutionReceipts" });
export type WorkspaceScheduleExecutionReceipts = z.output<
  typeof WorkspaceScheduleExecutionReceiptsSchema
>;

export const WorkspaceScheduleAppliedRecoverySchema = z.strictObject({
  priorCompletedAtMs: TimeSchema,
  priorOutcome: z.literal("failed"),
  priorReceipt: WorkspaceScheduleReceiptSchema.nullable(),
  recoveredAtMs: TimeSchema,
  version: z.literal("workspace-verified-attempt-result-recovery/v1"),
});
export type WorkspaceScheduleAppliedRecovery = z.output<
  typeof WorkspaceScheduleAppliedRecoverySchema
>;

const BaseShape = {
  ...WorkspaceScheduleStartSchema.shape,
  startedAtMs: TimeSchema,
  tickId: DigestSchema,
  execution: WorkspaceScheduleExecutionSchema.optional(),
  executionReceipts: WorkspaceScheduleExecutionReceiptsSchema.optional(),
  branchAttempts: z.array(WorkspaceBranchAttemptSchema).max(100).optional(),
};
const WorkspaceScheduleTickBaseSchema = z.discriminatedUnion("phase", [
  z.strictObject({ ...BaseShape, phase: z.literal("started") }),
  z.strictObject({
    ...BaseShape,
    ...WorkspaceSchedulePlanSchema.shape,
    phase: z.literal("planned"),
  }),
  z.strictObject({
    ...BaseShape,
    ...WorkspaceSchedulePlanSchema.shape,
    mode: z.literal("live"),
    phase: z.literal("launched"),
    workflowId: DigestSchema,
  }),
  z.strictObject({
    ...BaseShape,
    completedAtMs: TimeSchema,
    mode: ModeSchema.nullable(),
    notificationRequired: z.boolean(),
    outcome: OutcomeSchema,
    blockedReason: WorkspaceScheduleBlockedReasonSchema.optional(),
    phase: z.literal("terminal"),
    planHash: DigestSchema.nullable(),
    receipt: WorkspaceScheduleReceiptSchema.nullable(),
    recovery: WorkspaceScheduleAppliedRecoverySchema.optional(),
    workflowId: DigestSchema.nullable(),
  }),
]);
type TickRecord = z.output<typeof WorkspaceScheduleTickBaseSchema>;

export const WorkspaceScheduleTickSchema =
  WorkspaceScheduleTickBaseSchema.superRefine(validateExecutionReceipts)
    .superRefine(validateBranchAttempts)
    .superRefine(validateReceiptCoverage)
    .superRefine(validateExecutionLifecycle)
    .superRefine(validateExecutionResult)
    .superRefine(validateAppliedRecovery)
    .superRefine(validateBlockedReason)
    .superRefine((tick, context) => {
      if (tick.scheduledAtMs > tick.startedAtMs) {
        context.addIssue({
          code: "custom",
          message: "tick cannot start before scheduled time",
        });
      }
      if (tick.phase !== "terminal") return;
      if (tick.completedAtMs < tick.startedAtMs) {
        context.addIssue({
          code: "custom",
          message: "terminal time precedes tick start",
        });
      }
      if (
        tick.outcome === "applied" &&
        (tick.workflowId === null || tick.mode !== "live")
      ) {
        context.addIssue({
          code: "custom",
          message: "applied outcome requires live workflow identity",
        });
      }
      if (tick.planHash === null && tick.outcome !== "failed") {
        context.addIssue({
          code: "custom",
          message: "only pre-plan failure may omit the plan hash",
        });
      }
      if (
        (tick.outcome === "applied" ||
          tick.outcome === "blocked" ||
          tick.outcome === "failed") &&
        !tick.notificationRequired
      ) {
        context.addIssue({
          code: "custom",
          message:
            "mutation, blocked, and failed outcomes require terminal notification",
        });
      }
      const receipt = tick.receipt;
      if (
        receipt !== null &&
        (receipt.tickId !== tick.tickId ||
          receipt.planHash !== tick.planHash ||
          receipt.workflowId !== tick.workflowId ||
          receipt.outcome !== tick.outcome ||
          receipt.verifiedAtMs < tick.completedAtMs)
      ) {
        context.addIssue({
          code: "custom",
          message: "terminal receipt does not match the completed tick",
        });
      }
    });
export type WorkspaceScheduleTick = z.output<
  typeof WorkspaceScheduleTickSchema
>;
export type WorkspaceScheduleOutcome = z.output<typeof OutcomeSchema>;

function validateBlockedReason(
  tick: TickRecord,
  context: z.RefinementCtx,
): void {
  if (tick.phase !== "terminal") return;
  if (
    tick.blockedReason !== undefined &&
    (tick.outcome !== "blocked" ||
      tick.workflowId !== null ||
      tick.execution !== undefined ||
      (tick.branchAttempts?.length ?? 0) !== 0)
  ) {
    context.addIssue({
      code: "custom",
      message: "blocked reason requires a pre-dispatch blocked tick",
    });
  }
}

function validateAppliedRecovery(
  tick: TickRecord,
  context: z.RefinementCtx,
): void {
  if (tick.phase !== "terminal" || tick.recovery === undefined) return;
  const recovery = tick.recovery;
  if (
    tick.outcome !== "applied" ||
    tick.execution?.result === null ||
    tick.execution === undefined ||
    recovery.recoveredAtMs !== tick.completedAtMs ||
    recovery.priorCompletedAtMs > recovery.recoveredAtMs ||
    (recovery.priorReceipt !== null &&
      (recovery.priorReceipt.outcome !== "failed" ||
        recovery.priorReceipt.tickId !== tick.tickId ||
        recovery.priorReceipt.planHash !== tick.planHash ||
        recovery.priorReceipt.workflowId !== tick.workflowId ||
        recovery.priorReceipt.verifiedAtMs < recovery.priorCompletedAtMs))
  ) {
    context.addIssue({
      code: "custom",
      message:
        "applied recovery must preserve the exact failed terminal evidence",
    });
  }
}

function validateBranchAttempts(
  tick: TickRecord,
  context: z.RefinementCtx,
): void {
  const attempts = tick.branchAttempts ?? [];
  if (
    new Set(attempts.map(({ branchId }) => branchId)).size !== attempts.length
  ) {
    context.addIssue({
      code: "custom",
      message: "only one durable attempt is allowed per branch",
    });
  }
  for (const attempt of attempts) {
    if (!branchAttemptMatchesParent(tick, attempt)) {
      context.addIssue({
        code: "custom",
        message: "branch attempt does not match its durable parent execution",
      });
    }
  }
}

function branchAttemptMatchesParent(
  tick: TickRecord,
  attempt: WorkspaceBranchAttempt,
): boolean {
  const execution = tick.execution;
  if (
    execution === undefined ||
    (tick.phase !== "launched" && tick.phase !== "terminal")
  )
    return false;
  const branch = execution.params.plan.branches.find(
    ({ branchId }) => branchId === attempt.branchId,
  );
  const handles = execution.branchHandles.filter(
    ({ branchId }) => branchId === attempt.branchId,
  );
  if (
    attempt.workflowId !== tick.workflowId ||
    attempt.paramsDigest !== execution.paramsDigest ||
    attempt.sourceFingerprint !== execution.params.plan.authorityFingerprint ||
    branch?.execution !== "managed" ||
    managedBranchActionId(attempt.branchId) !== attempt.actionId ||
    !execution.params.authorizedActionIds.includes(attempt.actionId) ||
    handles.length === 0 ||
    handles[0]?.change.changeKey !== attempt.changeKey ||
    (handles.length === 1
      ? attempt.changeSetDigest !== undefined
      : attempt.changeSetDigest === undefined) ||
    attempt.attemptedAtMs < execution.startedAtMs
  )
    return false;
  if (tick.phase !== "terminal") return true;
  if (attempt.attemptedAtMs > tick.completedAtMs) return false;
  if (tick.outcome !== "applied") {
    if (attempt.state === "not-dispatched")
      return (
        tick.outcome === "failed" &&
        attempt.refusal.recordedAtMs <= tick.completedAtMs
      );
    return (
      attempt.state !== "verified" || attempt.verifiedAtMs <= tick.completedAtMs
    );
  }
  return (
    attempt.state === "verified" &&
    attempt.verifiedAtMs <= tick.completedAtMs &&
    dequal(
      execution.result?.branches.find(
        ({ branchId }) => branchId === attempt.branchId,
      ),
      attempt.result,
    )
  );
}

function validateExecutionReceipts(
  tick: TickRecord,
  context: z.RefinementCtx,
): void {
  const execution = tick.execution;
  if (
    tick.executionReceipts !== undefined &&
    (execution?.result === null ||
      execution === undefined ||
      tick.phase !== "terminal" ||
      tick.outcome !== "applied" ||
      !dequal(tick.receipt, tick.executionReceipts.summaryReceipt))
  ) {
    context.addIssue({
      code: "custom",
      message:
        "execution receipts require the exact applied result and summary",
    });
  }
  if (
    execution !== undefined &&
    tick.phase === "terminal" &&
    tick.outcome === "applied" &&
    tick.receipt !== null &&
    tick.executionReceipts === undefined
  ) {
    context.addIssue({
      code: "custom",
      message: "applied execution requires complete branch receipt evidence",
    });
  }
}

function validateReceiptCoverage(
  tick: TickRecord,
  context: z.RefinementCtx,
): void {
  const execution = tick.execution;
  const proof = tick.executionReceipts;
  if (
    execution === undefined ||
    proof === undefined ||
    tick.phase !== "terminal"
  )
    return;
  const seen = new Set<string>();
  if (
    proof.branchReceipts.length !== execution.branchHandles.length ||
    proof.summaryReceipt.slackTimestamp !== execution.summaryHandle.timestamp
  ) {
    context.addIssue({
      code: "custom",
      message: "receipt coverage does not match original manifest",
    });
  }
  for (const receipt of proof.branchReceipts) {
    const original = execution.branchHandles.find(
      ({ branchId, handle }) =>
        branchId === receipt.branchId && handle.changeKey === receipt.changeKey,
    );
    if (
      original?.handle.timestamp !== receipt.timestamp ||
      seen.has(receipt.changeKey) ||
      receipt.verifiedAtMs < tick.completedAtMs
    ) {
      context.addIssue({
        code: "custom",
        message: "branch receipt does not match original handle",
      });
    }
    seen.add(receipt.changeKey);
  }
}

function validateExecutionLifecycle(
  tick: TickRecord,
  context: z.RefinementCtx,
): void {
  const execution = tick.execution;
  if (execution === undefined) return;
  if (
    (tick.phase !== "launched" && tick.phase !== "terminal") ||
    execution.params.scheduledTickId !== tick.tickId ||
    execution.params.requestedBy !== "scheduled:workspace-directory" ||
    execution.startedAtMs < tick.startedAtMs ||
    execution.params.planHash !== tick.planHash
  ) {
    context.addIssue({
      code: "custom",
      message: "execution record does not match tick lifecycle",
    });
  }
  if (
    tick.phase === "terminal" &&
    (execution.startedAtMs > tick.completedAtMs ||
      (tick.outcome === "applied" && execution.result === null))
  ) {
    context.addIssue({
      code: "custom",
      message: "applied execution requires a result and ordered timestamps",
    });
  }
}

function validateExecutionResult(
  tick: TickRecord,
  context: z.RefinementCtx,
): void {
  const execution = tick.execution;
  if (!execution?.result) return;
  if (
    tick.phase !== "terminal" ||
    tick.outcome !== "applied" ||
    tick.workflowId === null ||
    parseSuccessfulWorkflowResult(
      execution.result,
      execution.params.plan,
      execution.params.planHash,
      tick.workflowId,
      execution.params.authorizedActionIds,
    ) === null
  ) {
    context.addIssue({
      code: "custom",
      message: "durable provider result does not match exact execution",
    });
  }
}

export const WorkspaceScheduleHealthSchema = z
  .strictObject({
    healthy: z.boolean(),
    latest: WorkspaceScheduleTickSchema.nullable(),
    mutationSafetyClear: z.boolean(),
    pendingTicks: z.number().int().nonnegative(),
    scheduleHealthy: z.boolean(),
    unresolvedMutations: z.number().int().nonnegative(),
  })
  .superRefine((health, context) => {
    if (
      health.healthy !==
        (health.scheduleHealthy && health.mutationSafetyClear) ||
      (health.mutationSafetyClear && health.unresolvedMutations > 0) ||
      (health.scheduleHealthy &&
        (health.latest?.phase !== "terminal" || health.pendingTicks > 0))
    ) {
      context.addIssue({
        code: "custom",
        message: "inconsistent Workspace schedule health evidence",
      });
    }
  });
