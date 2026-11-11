import type { IdentityWriteBudget } from "../identity-provisioning/identity-budget-contracts.ts";
import { sameJson, sha256Hex } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import { WorkspaceBranchAttemptPinsSchema } from "./branch-attempt-contracts.ts";
import type {
  IWorkspaceDirectoryChangeLedger,
  WorkspaceDirectoryChangeLedgerHandle,
} from "./change-ledger.ts";
import type {
  WorkspaceDirectoryPlan,
  WorkspaceDirectoryWorkflowParams,
} from "./contracts.ts";
import { workspaceDirectoryChanges } from "./operation.ts";
import {
  managedBranchActionId,
  workspaceDirectoryExecutionId,
} from "./workflow.ts";
import { workspaceBranchSourceIdentity } from "./workspace-branch-source-identity.ts";
import {
  type WorkspaceDirectoryAnnouncedChange,
  workspaceDirectoryAnnouncedChanges,
} from "./workspace-directory-announced-changes.ts";
import type { IWorkspaceScheduleHealthRepository } from "./workspace-schedule-health-repository.ts";

interface LedgerEntry {
  change: WorkspaceDirectoryAnnouncedChange;
  handle: WorkspaceDirectoryChangeLedgerHandle;
}
export interface WorkspaceIdentityParentInput {
  enabled: boolean;
  handles: ReadonlyMap<string, readonly LedgerEntry[]>;
  identityBudget?: IdentityWriteBudget;
  ledger: IWorkspaceDirectoryChangeLedger;
  now?: () => number;
  params: WorkspaceDirectoryWorkflowParams;
  repository: Pick<IWorkspaceScheduleHealthRepository, "read">;
}

export interface WorkspaceIdentityParentContext {
  assertFreshPlan(): void;
  assertWriteAuthority(): Promise<void>;
}

export function createWorkspaceIdentityParentContext(
  input: WorkspaceIdentityParentInput,
  plan: WorkspaceDirectoryPlan,
  branchId:
    | "access-guard"
    | "github-access"
    | "google-group-cleanup"
    | "pagerduty-teams"
    | "sentry-memberships"
    | "slack-groups-channels",
): WorkspaceIdentityParentContext {
  const { params } = input;
  const branch = params.plan.branches.find(
    (item) => item.branchId === branchId,
  );
  const actionId = managedBranchActionId(branchId);
  if (actionId === null) throw new Error("workspace_parent_action_required");
  const tickId = params.scheduledTickId;
  if (
    !input.enabled ||
    tickId === undefined ||
    params.requestedBy !== "scheduled:workspace-directory" ||
    input.identityBudget?.required !== true ||
    !params.authorizedActionIds.includes(actionId) ||
    !equal(plan, params.plan) ||
    branch?.execution !== "managed"
  )
    throw new Error("workspace_parent_signed_parent_required");
  const changes = workspaceDirectoryChanges(params.plan).filter(
    (item) => item.actionId === actionId,
  );
  const change = changes.length === 1 ? changes[0] : undefined;
  if (change === undefined)
    throw new Error("workspace_parent_exact_change_required");
  const announcements = workspaceDirectoryAnnouncedChanges(
    params.plan,
    branchId,
  );
  const entries = input.handles.get(branchId) ?? [];
  const original = entries[0];
  if (
    entries.length !== 1 ||
    announcements.length !== 1 ||
    original === undefined ||
    !equal(original.change, announcements[0]) ||
    original.handle.changeKey !==
      `${params.planHash}:${original.change.changeKey}`
  )
    throw new Error("workspace_parent_original_receipt_required");
  const assertFreshPlan = () => {
    const now = input.now?.() ?? Date.now();
    const age = now - Date.parse(params.planGeneratedAt);
    const proof = params.reviewedProviderIntent?.proof;
    const originalApprovalExpiresAtMs =
      proof !== undefined &&
      "provider" in proof &&
      proof.provider === "google-group-cleanup"
        ? proof.expiresAtMs
        : Infinity;
    if (
      !Number.isFinite(age) ||
      age < 0 ||
      age >= 600_000 ||
      now >= originalApprovalExpiresAtMs
    )
      throw new Error("workspace_parent_plan_expired");
  };
  return {
    assertFreshPlan,
    assertWriteAuthority: async () => {
      assertFreshPlan();
      const [
        tick,
        workflowId,
        paramsDigest,
        beforeFingerprint,
        afterFingerprint,
      ] = await Promise.all([
        input.repository.read(tickId),
        workspaceDirectoryExecutionId(params),
        sha256Hex(JsonValueSchema.parse(params)),
        sha256Hex(change.before),
        sha256Hex(change.after),
      ]);
      const pins = {
        workflowId,
        paramsDigest,
        beforeFingerprint,
        afterFingerprint,
        actionId,
        branchId,
        changeKey: original.change.changeKey,
        sourceFingerprint: params.plan.authorityFingerprint,
        sourceIdentity: workspaceBranchSourceIdentity(branch, change),
      };
      const attempts =
        tick.branchAttempts?.filter((item) => item.branchId === branchId) ?? [];
      const attempt = attempts.length === 1 ? attempts[0] : undefined;
      if (
        tick.tickId !== tickId ||
        tick.phase !== "launched" ||
        tick.workflowId !== workflowId ||
        tick.execution?.paramsDigest !== paramsDigest ||
        !equal(
          tick.execution.branchHandles.filter(
            (item) => item.branchId === branchId,
          ),
          [{ branchId, ...original }],
        ) ||
        attempt?.state !== "attempted" ||
        !equal(WorkspaceBranchAttemptPinsSchema.strip().parse(attempt), pins)
      )
        throw new Error("workspace_parent_original_attempt_required");
      assertFreshPlan();
      const recovered = await input.ledger.recover?.({
        changeKey: original.handle.changeKey,
        text: `${original.change.text} · plan ${params.planHash.slice(0, 12)}`,
        retryFailed: false,
      });
      if (
        recovered?.state !== "announced" ||
        !equal(recovered, { ...original.handle, state: "announced" })
      )
        throw new Error("workspace_parent_original_receipt_unverified");
      assertFreshPlan();
    },
  };
}

function equal(left: unknown, right: unknown) {
  return sameJson(JsonValueSchema.parse(left), JsonValueSchema.parse(right));
}
