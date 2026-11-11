import type { IdentityWriteBudget } from "../identity-provisioning/identity-budget-contracts.ts";
import { sameJson, sha256Hex } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import { WorkspaceBranchAttemptPinsSchema } from "./branch-attempt-contracts.ts";
import type {
  IWorkspaceDirectoryChangeLedger,
  WorkspaceDirectoryChangeLedgerHandle,
} from "./change-ledger.ts";
import {
  WORKSPACE_DIRECTORY_ACTION_IDS,
  type WorkspaceDirectoryWorkflowParams,
} from "./contracts.ts";
import {
  type ReviewedNameAction,
  ReviewedNameActionSchema,
  reviewedNameManagedSlice,
  reviewedNameSourceIdentity,
} from "./reviewed-name-plan.ts";
import type { WorkspaceNameParentContext } from "./reviewed-workspace-name-adapter.ts";
import { workspaceDirectoryExecutionId } from "./workflow.ts";
import {
  type WorkspaceDirectoryAnnouncedChange,
  workspaceDirectoryAnnouncedChanges,
} from "./workspace-directory-announced-changes.ts";
import type { IWorkspaceScheduleHealthRepository } from "./workspace-schedule-health-repository.ts";

type NameBranchId = ReviewedNameAction["branchId"];
interface LedgerEntry {
  change: WorkspaceDirectoryAnnouncedChange;
  handle: WorkspaceDirectoryChangeLedgerHandle;
}

/* The adapter cannot bypass its original durable parent attempt or use a standalone receipt. */
export function createWorkspaceNameParentContext(input: {
  enabled: boolean;
  params: WorkspaceDirectoryWorkflowParams;
  handles: ReadonlyMap<string, readonly LedgerEntry[]>;
  ledger: IWorkspaceDirectoryChangeLedger;
  repository: Pick<IWorkspaceScheduleHealthRepository, "read">;
  slackIdentityBudget?: IdentityWriteBudget;
  linearIdentityBudget?: IdentityWriteBudget;
  now?: () => number;
}): (reviewed: ReviewedNameAction) => WorkspaceNameParentContext {
  return (raw) => {
    const reviewed = ReviewedNameActionSchema.parse(raw);
    const { params } = input;
    const tickId = params.scheduledTickId;
    const actionId = nameActionId(reviewed.branchId);
    const identityBudget =
      reviewed.branchId === "slack-names"
        ? input.slackIdentityBudget
        : input.linearIdentityBudget;
    const branch = params.plan.branches.find(
      ({ branchId }) => branchId === reviewed.branchId,
    );
    if (
      !input.enabled ||
      tickId === undefined ||
      params.requestedBy !== "scheduled:workspace-directory" ||
      !params.authorizedActionIds.includes(actionId) ||
      identityBudget?.required !== true ||
      (branch?.branchId !== "slack-names" &&
        branch?.branchId !== "linear-profiles") ||
      !equal(branch.reviewed, reviewed)
    )
      throw new Error("workspace_name_signed_parent_required");
    const changes = workspaceDirectoryAnnouncedChanges(
      params.plan,
      reviewed.branchId,
    );
    const entries = input.handles.get(reviewed.branchId) ?? [];
    const original = entries[0];
    if (
      entries.length !== 1 ||
      changes.length !== 1 ||
      original === undefined ||
      !equal(original.change, changes[0]) ||
      original.handle.changeKey !==
        `${params.planHash}:${original.change.changeKey}`
    )
      throw new Error("workspace_name_original_receipt_required");
    const assertFreshPlan = () => {
      const age =
        (input.now?.() ?? Date.now()) - Date.parse(params.planGeneratedAt);
      if (!Number.isFinite(age) || age < 0 || age >= 10 * 60_000)
        throw new Error("workspace_name_reviewed_plan_expired");
    };
    const verifyOriginalReceipt = async () => {
      assertFreshPlan();
      const recovered = await input.ledger.recover?.({
        changeKey: original.handle.changeKey,
        text: `${original.change.text} · plan ${params.planHash.slice(0, 12)}`,
        retryFailed: false,
      });
      if (
        recovered?.state !== "announced" ||
        !equal(
          { ...recovered, state: "announced" },
          { ...original.handle, state: "announced" },
        )
      )
        throw new Error("workspace_name_original_receipt_unverified");
      assertFreshPlan();
    };
    return {
      identityBudget,
      assertFreshPlan,
      verifyPreannouncement: async (actual) => {
        if (
          !equal(actual, {
            action: reviewed.action,
            expectedPlanHash: reviewed.expectedPlanHash,
          })
        )
          throw new Error("workspace_name_signed_child_mismatch");
        await verifyOriginalReceipt();
      },
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
          sha256Hex(reviewedNameManagedSlice(reviewed, "pending")),
          sha256Hex(reviewedNameManagedSlice(reviewed, "converged")),
        ]);
        const attempt = tick.branchAttempts?.find(
          ({ branchId }) => branchId === reviewed.branchId,
        );
        const expectedPins = {
          workflowId,
          paramsDigest,
          branchId: reviewed.branchId,
          actionId,
          changeKey: original.change.changeKey,
          sourceIdentity: reviewedNameSourceIdentity(reviewed),
          sourceFingerprint: params.plan.authorityFingerprint,
          beforeFingerprint,
          afterFingerprint,
        };
        if (
          tick.tickId !== tickId ||
          tick.phase !== "launched" ||
          tick.workflowId !== workflowId ||
          tick.execution?.paramsDigest !== paramsDigest ||
          !equal(
            tick.execution.branchHandles.filter(
              ({ branchId }) => branchId === reviewed.branchId,
            ),
            [{ branchId: reviewed.branchId, ...original }],
          ) ||
          attempt?.state !== "attempted" ||
          !equal(
            WorkspaceBranchAttemptPinsSchema.strip().parse(attempt),
            expectedPins,
          )
        )
          throw new Error("workspace_name_original_attempt_required");
        await verifyOriginalReceipt();
        assertFreshPlan();
      },
    };
  };
}

function nameActionId(branchId: NameBranchId) {
  return branchId === "slack-names"
    ? WORKSPACE_DIRECTORY_ACTION_IDS.slackNames
    : WORKSPACE_DIRECTORY_ACTION_IDS.linearProfiles;
}

function equal(left: unknown, right: unknown): boolean {
  return sameJson(JsonValueSchema.parse(left), JsonValueSchema.parse(right));
}
