import { takeGithubZeroDispatchProof } from "../identity-provisioning/github-organization-api-port.ts";
import type { GithubDispatchClaim } from "../identity-provisioning/github-zero-dispatch.ts";
import { sameJson, sha256Hex } from "../operations/canonical.ts";
import { JsonValueSchema, type ManagedChange } from "../operations/schemas.ts";
import { assertWorkspaceBranchClaimFresh } from "./assert-workspace-branch-claim-fresh.ts";
import {
  type WorkspaceBranchAttempt,
  type WorkspaceBranchAttemptPins,
  WorkspaceBranchAttemptPinsSchema,
} from "./branch-attempt-contracts.ts";
import type { IWorkspaceDirectoryChangeLedger } from "./change-ledger.ts";
import {
  type WorkspaceDirectoryBranchId,
  type WorkspaceDirectoryWorkflowParams,
  type WorkspaceDirectoryWorkflowResult,
  WorkspaceDirectoryWorkflowResultSchema,
} from "./contracts.ts";
import {
  workspaceDirectoryChanges,
  workspaceDirectorySourceFingerprints,
} from "./operation.ts";
import { orderedBranchReceiptSetDigest } from "./ordered-branch-receipt-set-digest.ts";
import { readWorkspaceDirectoryManagedSlice } from "./read-workspace-directory-managed-slice.ts";
import { readWorkspaceSourceFingerprint } from "./read-workspace-source-fingerprint.ts";
import type { WorkspaceDirectoryRuntime } from "./runtime-contract.ts";
import type { WorkspaceScheduleExecution } from "./schedule-health-contracts.ts";
import {
  managedBranchActionId,
  workspaceDirectoryExecutionId,
} from "./workflow.ts";
import { workspaceBranchSourceIdentity } from "./workspace-branch-source-identity.ts";
import { workspaceDirectoryAnnouncedChanges } from "./workspace-directory-announced-changes.ts";
import type { IWorkspaceScheduleHealthRepository } from "./workspace-schedule-health-repository.ts";

type BranchResult = WorkspaceDirectoryWorkflowResult["branches"][number];
interface Input {
  branchId: WorkspaceDirectoryBranchId;
  enabled: boolean;
  execute(claim?: GithubDispatchClaim): Promise<BranchResult>;
  ledger: IWorkspaceDirectoryChangeLedger;
  now?: () => number;
  params: WorkspaceDirectoryWorkflowParams;
  repository: Pick<
    IWorkspaceScheduleHealthRepository,
    "claimBranchAttempt" | "read" | "verifyBranchAttempt"
  > &
    Partial<Pick<IWorkspaceScheduleHealthRepository, "recordGithubNoDispatch">>;
  runtime: WorkspaceDirectoryRuntime;
}

const GITHUB_NOT_DISPATCHED = "workspace_github_prewrite_not_dispatched";
const ORIGINAL_HANDLE_MISMATCH = "workspace_branch_original_handle_mismatch";

/* Only a newly acquired durable claim may dispatch. Attempted/unknown never retries a writer. */
export async function executeScheduledWorkspaceBranch(
  input: Input,
): Promise<BranchResult> {
  const { params, branchId, runtime, repository } = input;
  if (!input.enabled) return input.execute();
  const tickId = scheduledTickId(params);
  if (tickId === undefined) return input.execute();
  const branch = params.plan.branches.find(
    (item) => item.branchId === branchId,
  );
  if (branch === undefined) throw new Error("workspace_branch_missing");
  const actionId = managedBranchActionId(branchId);
  if (
    branch.execution !== "managed" ||
    actionId === null ||
    !params.authorizedActionIds.includes(actionId)
  ) {
    return input.execute();
  }
  const changes = workspaceDirectoryChanges(params.plan).filter(
    (item) => item.actionId === actionId,
  );
  const change = changes.length === 1 ? changes[0] : undefined;
  if (change === undefined)
    throw new Error("workspace_branch_exact_change_missing");
  const tick = await repository.read(tickId);
  const paramsDigest = await sha256Hex(JsonValueSchema.parse(params));
  const workflowId = await workspaceDirectoryExecutionId(params);
  if (
    params.requestedBy !== "scheduled:workspace-directory" ||
    tick.tickId !== tickId ||
    tick.phase !== "launched" ||
    tick.execution === undefined ||
    tick.workflowId !== workflowId ||
    tick.execution.paramsDigest !== paramsDigest
  )
    throw new Error("workspace_branch_parent_mismatch");
  const originals = originalBranchHandles(tick.execution, params, branchId);
  const receiptPins = await branchReceiptPins(originals);
  const pins = WorkspaceBranchAttemptPinsSchema.parse({
    workflowId,
    paramsDigest,
    branchId,
    actionId,
    ...receiptPins,
    sourceIdentity: workspaceBranchSourceIdentity(branch, change),
    sourceFingerprint: params.plan.authorityFingerprint,
    beforeFingerprint: await sha256Hex(change.before),
    afterFingerprint: await sha256Hex(change.after),
  });
  const existing = tick.branchAttempts?.find(
    (item) => item.branchId === branchId,
  );
  if (existing !== undefined) {
    const storedPins = WorkspaceBranchAttemptPinsSchema.strip().parse(existing);
    if (
      (await sha256Hex(JsonValueSchema.parse(storedPins))) !==
      (await sha256Hex(JsonValueSchema.parse(pins)))
    )
      throw new Error("workspace_branch_attempt_pin_mismatch");
    assertVerifiedBranchReplay(existing);
    await assertOriginalAnnouncements(input.ledger, params, originals, false);
    await assertSlice(runtime, change, pins.afterFingerprint);
    await assertSource(runtime, params, actionId);
    return existing.result;
  }
  await assertOriginalAnnouncements(input.ledger, params, originals, true);
  await assertSlice(runtime, change, pins.beforeFingerprint);
  await assertSource(runtime, params, actionId);
  assertWorkspaceBranchClaimFresh(params, input.now?.() ?? Date.now());
  const githubDispatchClaim = await newGithubDispatchClaim(branch, repository);
  await repository.claimBranchAttempt(tickId, {
    ...pins,
    params,
    githubDispatchClaim,
  });
  const rawResult = await executeWithNoDispatchProof(
    input,
    tickId,
    pins,
    githubDispatchClaim,
  );
  const result = parseAppliedBranchResult(rawResult, branchId);
  const observedAfterFingerprint = await assertSlice(
    runtime,
    change,
    pins.afterFingerprint,
  );
  await assertSource(runtime, params, actionId);
  await repository.verifyBranchAttempt(tickId, {
    ...pins,
    githubDispatchClaim,
    observedAfterFingerprint,
    result,
  });
  return result;
}

function assertVerifiedBranchReplay(
  attempt: WorkspaceBranchAttempt,
): asserts attempt is Extract<WorkspaceBranchAttempt, { state: "verified" }> {
  if (attempt.state === "not-dispatched")
    throw new Error(GITHUB_NOT_DISPATCHED);
  if (attempt.state !== "verified")
    throw new Error("workspace_branch_attempt_unresolved");
}

async function newGithubDispatchClaim(
  branch: WorkspaceDirectoryWorkflowParams["plan"]["branches"][number],
  repository: Input["repository"],
): Promise<GithubDispatchClaim | undefined> {
  if (
    branch.branchId !== "github-access" ||
    branch.execution !== "managed" ||
    repository.recordGithubNoDispatch === undefined
  )
    return undefined;
  if (branch.selectedOperation === null)
    throw new Error("workspace_branch_exact_change_missing");
  return {
    protocol: "github-single-operation/v1",
    claimId: crypto.randomUUID(),
    operationHash: await sha256Hex(
      JsonValueSchema.parse(branch.selectedOperation.operation),
    ),
  };
}
async function executeWithNoDispatchProof(
  input: Input,
  tickId: string,
  pins: WorkspaceBranchAttemptPins,
  githubDispatchClaim: GithubDispatchClaim | undefined,
): Promise<BranchResult> {
  const repository = input.repository;
  try {
    return await input.execute(githubDispatchClaim);
  } catch (error) {
    const proof = takeGithubZeroDispatchProof(error);
    if (
      proof !== undefined &&
      githubDispatchClaim !== undefined &&
      repository.recordGithubNoDispatch !== undefined
    ) {
      await repository.recordGithubNoDispatch(tickId, pins, proof);
      throw new Error(GITHUB_NOT_DISPATCHED, { cause: error });
    }
    throw error;
  }
}

/*
 * Recovers only an already-durable verified provider result. This function has no
 * claim or writer path and is safe to call after the Workflow platform loses a
 * step return value.
 */
export async function recoverVerifiedScheduledWorkspaceBranch(
  input: Omit<Input, "execute">,
) {
  const { params, branchId, runtime, repository } = input;
  const tickId = scheduledTickId(params);
  if (!input.enabled || tickId === undefined)
    throw new Error("workspace_branch_verified_attempt_required");
  const branch = params.plan.branches.find(
    (item) => item.branchId === branchId,
  );
  const actionId = managedBranchActionId(branchId);
  if (
    branch?.execution !== "managed" ||
    actionId === null ||
    !params.authorizedActionIds.includes(actionId)
  )
    throw new Error("workspace_branch_verified_attempt_required");
  const change = workspaceDirectoryChanges(params.plan).find(
    (item) => item.actionId === actionId,
  );
  if (change === undefined)
    throw new Error("workspace_branch_exact_change_missing");
  const tick = await repository.read(tickId);
  const paramsDigest = await sha256Hex(JsonValueSchema.parse(params));
  const workflowId = await workspaceDirectoryExecutionId(params);
  if (
    tick.tickId !== tickId ||
    tick.phase !== "launched" ||
    tick.execution === undefined ||
    tick.workflowId !== workflowId ||
    tick.execution.paramsDigest !== paramsDigest
  )
    throw new Error("workspace_branch_parent_mismatch");
  const originals = originalBranchHandles(tick.execution, params, branchId);
  const receiptPins = await branchReceiptPins(originals);
  const pins = WorkspaceBranchAttemptPinsSchema.parse({
    workflowId,
    paramsDigest,
    branchId,
    actionId,
    ...receiptPins,
    sourceIdentity: workspaceBranchSourceIdentity(branch, change),
    sourceFingerprint: params.plan.authorityFingerprint,
    beforeFingerprint: await sha256Hex(change.before),
    afterFingerprint: await sha256Hex(change.after),
  });
  const existing = tick.branchAttempts?.find(
    (item) => item.branchId === branchId,
  );
  if (existing?.state !== "verified")
    throw new Error("workspace_branch_verified_attempt_required");
  const storedPins = WorkspaceBranchAttemptPinsSchema.strip().parse(existing);
  if (
    (await sha256Hex(JsonValueSchema.parse(storedPins))) !==
    (await sha256Hex(JsonValueSchema.parse(pins)))
  )
    throw new Error("workspace_branch_attempt_pin_mismatch");
  await assertOriginalAnnouncements(input.ledger, params, originals, false);
  await assertSlice(runtime, change, pins.afterFingerprint);
  await assertSource(runtime, params, actionId);
  return existing.result;
}

function scheduledTickId(params: WorkspaceDirectoryWorkflowParams) {
  if (
    params.scheduledTickId === undefined &&
    params.requestedBy === "scheduled:workspace-directory"
  )
    throw new Error("workspace_branch_scheduled_tick_missing");
  return params.scheduledTickId;
}

function parseAppliedBranchResult(
  raw: BranchResult,
  branchId: WorkspaceDirectoryBranchId,
) {
  const result =
    WorkspaceDirectoryWorkflowResultSchema.shape.branches.element.parse(raw);
  if (result.branchId !== branchId || result.state !== "applied")
    throw new Error("workspace_branch_provider_result_mismatch");
  return result;
}

function originalBranchHandles(
  execution: WorkspaceScheduleExecution,
  params: WorkspaceDirectoryWorkflowParams,
  branchId: WorkspaceDirectoryBranchId,
): WorkspaceScheduleExecution["branchHandles"] {
  const handles = execution.branchHandles.filter(
    (item) => item.branchId === branchId,
  );
  const changes = workspaceDirectoryAnnouncedChanges(params.plan, branchId);
  if (
    handles.length === 0 ||
    handles.length !== changes.length ||
    handles.some((original, index) => {
      const expected = changes[index];
      return (
        expected === undefined ||
        !sameJson(
          JsonValueSchema.parse(original.change),
          JsonValueSchema.parse(expected),
        )
      );
    })
  )
    throw new Error(ORIGINAL_HANDLE_MISMATCH);
  return handles;
}

async function branchReceiptPins(
  originals: WorkspaceScheduleExecution["branchHandles"],
): Promise<{ changeKey: string; changeSetDigest?: string }> {
  const first = originals[0];
  if (first === undefined) throw new Error(ORIGINAL_HANDLE_MISMATCH);
  return {
    changeKey: first.change.changeKey,
    ...(!(originals.length === 1) && {
      changeSetDigest: await orderedBranchReceiptSetDigest(originals),
    }),
  };
}

async function assertOriginalAnnouncements(
  ledger: IWorkspaceDirectoryChangeLedger,
  params: WorkspaceDirectoryWorkflowParams,
  originals: WorkspaceScheduleExecution["branchHandles"],
  requireAnnounced: boolean,
): Promise<void> {
  if (ledger.recover === undefined)
    throw new Error("workspace_branch_announcement_verifier_missing");
  for (const original of originals) {
    // eslint-disable-next-line no-await-in-loop -- Every exact original receipt gates the single provider batch.
    const recovered = await ledger.recover({
      changeKey: `${params.planHash}:${original.change.changeKey}`,
      text: `${original.change.text} · plan ${params.planHash.slice(0, 12)}`,
      retryFailed: false,
    });
    if (
      recovered === null ||
      recovered.state === "failed" ||
      (requireAnnounced && recovered.state !== "announced") ||
      recovered.changeKey !== original.handle.changeKey ||
      !sameJson(recovered.channelId, original.handle.channelId) ||
      recovered.timestamp !== original.handle.timestamp ||
      recovered.announcementDigest !== original.handle.announcementDigest
    )
      throw new Error("workspace_branch_original_announcement_unverified");
  }
}

async function assertSlice(
  runtime: WorkspaceDirectoryRuntime,
  change: ManagedChange,
  expected: string,
) {
  const observed = await readWorkspaceDirectoryManagedSlice(runtime, change);
  const fingerprint = await sha256Hex(observed);
  if (fingerprint !== expected)
    throw new Error("workspace_branch_target_drift");
  return fingerprint;
}

async function assertSource(
  runtime: WorkspaceDirectoryRuntime,
  params: WorkspaceDirectoryWorkflowParams,
  actionId: string,
) {
  const expected = workspaceDirectorySourceFingerprints(
    params.plan,
    new Set([actionId]),
  );
  const observed = await Promise.all(
    expected.map((source) =>
      readWorkspaceSourceFingerprint(runtime, source.resourceId),
    ),
  );
  if (expected.some((source, index) => observed[index] !== source.version))
    throw new Error("workspace_branch_source_drift");
}
