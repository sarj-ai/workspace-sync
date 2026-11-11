import { sameJson, sha256Hex } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import type { OperationWorkflowExecutor } from "../operations/workflow-executor.ts";
import type { OperationWorkflowStatus } from "../operations/workflow-status.ts";
import { WorkspaceDirectoryOperationInputSchema } from "./contracts.ts";
import {
  reviewedProviderAdmissionProof,
  reviewedProviderSelection,
  usesReviewedProviderAdmission,
} from "./reviewed-provider-admission.ts";
import type {
  IReviewedSlackLifecycleIntentAdmission,
  IReviewedSlackLifecycleIntentClaims,
  ReviewedSlackLifecycleIntent,
} from "./reviewed-slack-lifecycle-intent.ts";
import type { WorkspaceScheduleTick } from "./schedule-health-contracts.ts";
import { workspaceDirectoryExecutionId } from "./workflow.ts";
import type { IWorkspaceScheduleHealthRepository } from "./workspace-schedule-health-repository.ts";

const ORIGINAL_EXECUTION_REQUIRED =
  "workspace_reviewed_lifecycle_original_execution_required";
const EXECUTION_HASH_CHANGED =
  "workspace_reviewed_lifecycle_execution_hash_changed";

interface ExecutorInput {
  enabled: boolean;
  intents: IReviewedSlackLifecycleIntentAdmission &
    Pick<IReviewedSlackLifecycleIntentClaims, "read">;
  legacy: OperationWorkflowExecutor;
  now?: () => number;
  schedules: Pick<
    IWorkspaceScheduleHealthRepository,
    "read" | "resolveAppliedReviewedIntent"
  >;
}

export function createReviewedSlackLifecycleExecutor(
  input: ExecutorInput,
): OperationWorkflowExecutor {
  return {
    apply: async (request) => {
      const operationInput = WorkspaceDirectoryOperationInputSchema.parse(
        request.prepared.plan.input,
      );
      if (
        !usesReviewedProviderAdmission(operationInput, request.prepared.pending)
      )
        return input.legacy.apply(request);
      if (!input.enabled)
        throw new Error("workspace_reviewed_lifecycle_parent_disabled");
      const proof = await reviewedProviderAdmissionProof(request.prepared);
      const intent = await input.intents.admit(proof);
      return {
        state: "accepted",
        instanceId: intent.intentId,
        planHash: proof.originalPlanHash,
        authorizedActionIds: [reviewedProviderSelection(proof).actionId],
      };
    },
    status: async (request) => {
      const intent = input.enabled
        ? await input.intents.read(request.instanceId)
        : null;
      if (intent === null) return input.legacy.status(request);
      if (intent.state === "pending") {
        const resolved =
          await input.schedules.resolveAppliedReviewedIntent(intent);
        if (resolved !== null)
          return readResolvedAppliedIntentStatus(
            input,
            request,
            intent,
            resolved,
          );
        return queuedIntentStatus(intent, input.now?.() ?? Date.now());
      }
      return readClaimedIntentStatus(input, request, intent);
    },
  };
}

async function readResolvedAppliedIntentStatus(
  input: ExecutorInput,
  request: Parameters<OperationWorkflowExecutor["status"]>[0],
  intent: ReviewedSlackLifecycleIntent,
  tick: WorkspaceScheduleTick,
): Promise<OperationWorkflowStatus> {
  if (
    tick.phase !== "terminal" ||
    tick.outcome !== "applied" ||
    tick.workflowId === null ||
    !tick.execution?.result ||
    tick.executionReceipts === undefined
  )
    throw new Error("workspace_reviewed_lifecycle_resolved_execution_required");
  await assertExecutionIdentity(tick);
  const status = await input.legacy.status({
    ...request,
    instanceId: tick.workflowId,
  });
  if (
    status.state !== "succeeded" ||
    status.planHash !== tick.execution.params.planHash ||
    status.instanceId !== tick.workflowId
  )
    throw new Error("workspace_reviewed_lifecycle_resolved_execution_required");
  return {
    ...status,
    instanceId: intent.intentId,
    planHash: intent.proof.originalPlanHash,
  };
}

async function readClaimedIntentStatus(
  input: ExecutorInput,
  request: Parameters<OperationWorkflowExecutor["status"]>[0],
  intent: ReviewedSlackLifecycleIntent,
): Promise<OperationWorkflowStatus> {
  if (intent.claimedTickId === null)
    throw new Error("workspace_reviewed_lifecycle_original_claim_required");
  const tick = await input.schedules.read(intent.claimedTickId);
  if (tick.execution === undefined)
    return queuedIntentStatus(intent, input.now?.() ?? Date.now());
  if (
    !sameJson(
      JsonValueSchema.parse(
        tick.execution.params.reviewedProviderIntent ??
          tick.execution.params.reviewedSlackLifecycleIntent,
      ),
      JsonValueSchema.parse(intent),
    ) ||
    tick.execution.params.scheduledTickId !== intent.claimedTickId ||
    tick.execution.params.requestedBy !== "scheduled:workspace-directory" ||
    !("workflowId" in tick) ||
    tick.workflowId === null
  )
    throw new Error(ORIGINAL_EXECUTION_REQUIRED);
  await assertExecutionIdentity(tick);
  const status = await input.legacy.status({
    ...request,
    instanceId: tick.workflowId,
  });
  if (status.state !== "succeeded")
    return { ...status, instanceId: intent.intentId };
  if (status.planHash !== tick.execution.params.planHash)
    throw new Error(EXECUTION_HASH_CHANGED);
  if (
    tick.phase !== "terminal" ||
    tick.outcome !== "applied" ||
    tick.executionReceipts === undefined
  )
    return {
      state: "pending",
      providerStatus: "waiting",
      instanceId: intent.intentId,
    };
  return {
    ...status,
    instanceId: intent.intentId,
    planHash: intent.proof.originalPlanHash,
  };
}

async function assertExecutionIdentity(
  tick: WorkspaceScheduleTick,
): Promise<void> {
  const workflowId = "workflowId" in tick ? tick.workflowId : null;
  if (tick.execution === undefined || workflowId === null)
    throw new Error(ORIGINAL_EXECUTION_REQUIRED);
  if (
    (await workspaceDirectoryExecutionId(tick.execution.params)) !==
      workflowId ||
    (await sha256Hex(JsonValueSchema.parse(tick.execution.params))) !==
      tick.execution.paramsDigest
  )
    throw new Error(EXECUTION_HASH_CHANGED);
}

function queuedIntentStatus(
  intent: ReviewedSlackLifecycleIntent,
  now: number,
): OperationWorkflowStatus {
  return now >= intent.proof.expiresAtMs
    ? {
        state: "failed",
        providerStatus: "terminated",
        instanceId: intent.intentId,
        error: {
          name: "ReviewedApprovalExpired",
          message:
            "The original reviewed approval expired before verified workflow execution. Generate a new plan.",
        },
      }
    : {
        state: "pending",
        providerStatus: "queued",
        instanceId: intent.intentId,
      };
}
