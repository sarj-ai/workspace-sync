import type { D1Database } from "@cloudflare/workers-types";
import { dequal } from "dequal";
import { z } from "zod";

import type { IdentityWriteBudget } from "../identity-provisioning/identity-budget-contracts.ts";
import {
  D1ResourceLeaseRepository,
  type ResourceLeaseRepository,
  withResourceLease,
} from "../identity-sync/resource-lease.ts";
import {
  TRYCOMP_SYNC_MINIMUM_LEASE_HEADROOM_MS,
  TRYCOMP_SYNC_RESOURCE_LEASE_DURATION_MS,
  TRYCOMP_SYNC_RESOURCE_LEASE_KEY,
} from "../trycomp/config.ts";
import type { TrycompReviewedPlan } from "../trycomp/model.ts";
import { assertTrycompSelectedIdentity } from "../trycomp/reviewed-identity.ts";
import {
  D1TrycompSafetyStore,
  type TrycompDeploymentEvidence,
  type TrycompMutationStore,
  type TrycompSafetyStore,
} from "../trycomp/safety.ts";
import type {
  ITrycompPeopleSyncService,
  TrycompAuthorityInput,
} from "../trycomp/service.ts";
import type {
  IWorkspaceDirectoryChangeLedger,
  WorkspaceDirectoryChangeLedgerHandle,
} from "./change-ledger.ts";
import type { WorkspaceDirectoryWorkflowParams } from "./contracts.ts";
import type { TrycompPeopleSyncRuntime } from "./provider-runtime-ports.ts";
import { readWorkspaceTrycompVerifiedMemberId } from "./read-workspace-trycomp-verified-member-id.ts";
import type { WorkspaceRuntimeConfiguration as ValidatedEnv } from "./runtime-configuration.ts";
import { captureTrycompAuthority } from "./trycomp-adapter.ts";
import { workspaceDirectoryAnnouncedChanges } from "./workspace-directory-announced-changes.ts";
import {
  D1WorkspaceTrycompMutationStore,
  type WorkspaceTrycompReceipt,
} from "./workspace-receipt.ts";

const SCHEDULED_EXECUTION_REQUIRED =
  "workspace_trycomp_scheduled_execution_required";
const REVIEWED_PLAN_MAX_AGE_MS = 10 * 60_000;
const PlanGeneratedAtSchema = z.iso.datetime({ offset: true });

function assertFreshReviewedPlan(planGeneratedAt: string, now: number): void {
  const parsed = PlanGeneratedAtSchema.safeParse(planGeneratedAt);
  const generatedAt = parsed.success ? Date.parse(parsed.data) : NaN;
  const age = now - generatedAt;
  if (!Number.isFinite(age) || age < 0 || age >= REVIEWED_PLAN_MAX_AGE_MS) {
    throw new Error("workspace_trycomp_reviewed_plan_expired");
  }
}

function workspaceTrycompEnabled(env: ValidatedEnv): boolean {
  return (
    env.workspaceDirectoryTrycompEnabled &&
    !env.trycompSyncDisabled &&
    env.trycompSyncMode === "live"
  );
}

export interface WorkspaceTrycompApplyPorts {
  nonRetryableError(message: string): Error;
  captureAuthority(): Promise<TrycompAuthorityInput>;
  createJournal(receipt: WorkspaceTrycompReceipt): TrycompMutationStore;
  deployment: TrycompDeploymentEvidence;
  leaseRepository: ResourceLeaseRepository;
  now(): number;
  readVerifiedInvitationMemberId?: (
    receipt: WorkspaceTrycompReceipt,
  ) => Promise<null | string>;
  recoverReceipt(): Promise<null | WorkspaceDirectoryChangeLedgerHandle>;
  safetyReader: TrycompSafetyStore;
  service: ITrycompPeopleSyncService;
}

export interface WorkspaceTrycompApplyInput {
  enabled: boolean;
  expectedHandle: WorkspaceDirectoryChangeLedgerHandle;
  parentPlanHash: string;
  planGeneratedAt: string;
  requestedBy: string;
  reviewedPlan: TrycompReviewedPlan;
}

/* Exact reviewed target only; Workflow retries may not choose a new Trycomp identity. */
export async function applyWorkspaceReviewedTrycomp(
  input: WorkspaceTrycompApplyInput,
  ports: WorkspaceTrycompApplyPorts,
): Promise<string> {
  try {
    if (
      !input.enabled ||
      input.requestedBy !== "scheduled:workspace-directory"
    ) {
      throw new Error(SCHEDULED_EXECUTION_REQUIRED);
    }
    assertFreshReviewedPlan(input.planGeneratedAt, ports.now());
    const execution = await withResourceLease(
      ports.leaseRepository,
      TRYCOMP_SYNC_RESOURCE_LEASE_KEY,
      TRYCOMP_SYNC_RESOURCE_LEASE_DURATION_MS,
      async (lease) => {
        const assertWriteAuthority = async () => {
          assertFreshReviewedPlan(input.planGeneratedAt, ports.now());
          await ports.leaseRepository.assertActive(
            lease,
            TRYCOMP_SYNC_MINIMUM_LEASE_HEADROOM_MS,
          );
          assertFreshReviewedPlan(input.planGeneratedAt, ports.now());
        };
        await assertWriteAuthority();
        await ports.safetyReader.assertClosed();
        const authority = await ports.captureAuthority();
        assertTrycompSelectedIdentity(
          input.reviewedPlan,
          authority.googleUsers,
        );
        const fresh = await ports.service.captureReviewedPlan(authority);
        if (fresh.sourceFingerprint !== input.reviewedPlan.sourceFingerprint) {
          throw new Error("workspace_trycomp_reviewed_source_changed");
        }
        const originalReceipt = workspaceTrycompReceipt(
          input.expectedHandle,
          input.parentPlanHash,
          input.reviewedPlan,
        );
        const readVerifiedInvitationMemberId =
          ports.readVerifiedInvitationMemberId;
        const slice = await ports.service.readReviewedSlice(
          input.reviewedPlan,
          {
            authority,
            ...(!(readVerifiedInvitationMemberId === undefined) && {
              verifiedInvitationMemberId: () =>
                readVerifiedInvitationMemberId(originalReceipt),
            }),
          },
        );
        await assertWriteAuthority();
        if (slice.state === "converged")
          return "Reviewed Trycomp target already converged";
        if (slice.state !== "pending")
          throw new Error("workspace_trycomp_reviewed_target_changed");
        const recoverReceipt = async () => {
          const handle = await ports.recoverReceipt();
          if (
            handle?.state !== "announced" ||
            handle.announcementDigest !==
              input.expectedHandle.announcementDigest ||
            handle.changeKey !== input.expectedHandle.changeKey ||
            handle.channelId !== input.expectedHandle.channelId ||
            handle.timestamp !== input.expectedHandle.timestamp
          ) {
            throw new Error(
              "workspace_trycomp_verified_parent_receipt_required",
            );
          }
          return handle;
        };
        const handle = await recoverReceipt();
        const receipt: WorkspaceTrycompReceipt = {
          announcementDigest: handle.announcementDigest,
          changeKey: handle.changeKey,
          channelId: handle.channelId,
          parentPlanHash: input.parentPlanHash,
          requestedBy: "scheduled:workspace-directory",
          reviewedPlan: input.reviewedPlan,
          timestamp: handle.timestamp,
        };
        const report = await ports.service.applyReviewed({
          ...authority,
          assertWriteAuthority,
          deployment: ports.deployment,
          lease,
          mode: "live",
          mutationJournal: ports.createJournal(receipt),
          preannounce: async (plan, renew) => {
            await renew();
            if (plan.planHash !== input.reviewedPlan.plan.planHash) {
              throw new Error("workspace_trycomp_child_plan_changed");
            }
            const verified = await recoverReceipt();
            return {
              intentKey: verified.announcementDigest,
              slackTimestamp: verified.timestamp,
            };
          },
          refreshAuthority: () => ports.captureAuthority(),
          reviewedPlan: input.reviewedPlan,
          requireSelectedIdentity: true,
          safetyReader: ports.safetyReader,
          trigger: "cron",
        });
        if (report.status !== "converged")
          throw new Error("workspace_trycomp_reviewed_apply_incomplete");
        return `Reviewed Trycomp target verified · run ${report.runId}`;
      },
    );
    if (execution.kind === "busy")
      throw new Error("workspace_trycomp_singleton_busy");
    return execution.result;
  } catch (cause) {
    // Includes release/journal exceptions after a write. Durable failure must be reviewed, not retried.
    const error = ports.nonRetryableError(
      "workspace_trycomp_reviewed_apply_failed",
    );
    error.cause = cause;
    throw error;
  }
}

export function createWorkspaceReviewedTrycompApply(input: {
  runtime(): TrycompPeopleSyncRuntime;
  nonRetryableError(message: string): Error;
  database: D1Database;
  deployment: TrycompDeploymentEvidence;
  env: ValidatedEnv;
  identityBudget?: IdentityWriteBudget | undefined;
  handles: readonly { handle: WorkspaceDirectoryChangeLedgerHandle }[];
  ledger: IWorkspaceDirectoryChangeLedger;
  params: WorkspaceDirectoryWorkflowParams;
}): (reviewedPlan: TrycompReviewedPlan) => Promise<string> {
  return async (reviewedPlan) => {
    if (
      !workspaceTrycompEnabled(input.env) ||
      input.params.scheduledTickId === undefined ||
      input.params.requestedBy !== "scheduled:workspace-directory"
    ) {
      throw input.nonRetryableError(SCHEDULED_EXECUTION_REQUIRED);
    }
    if (input.identityBudget?.required !== true)
      throw input.nonRetryableError(
        "workspace_trycomp_identity_budget_required",
      );
    const parentChild = input.params.plan.branches.find(
      (branch) => branch.branchId === "trycomp-people",
    );
    if (
      parentChild?.branchId !== "trycomp-people" ||
      !dequal(parentChild.reviewedPlan, reviewedPlan)
    ) {
      throw input.nonRetryableError("workspace_trycomp_signed_child_mismatch");
    }
    const changes = workspaceDirectoryAnnouncedChanges(
      input.params.plan,
      "trycomp-people",
    );
    const change = changes[0];
    const expectedHandle = input.handles[0]?.handle;
    const recover = input.ledger.recover?.bind(input.ledger);
    if (
      change === undefined ||
      changes.length !== 1 ||
      input.handles.length !== 1 ||
      expectedHandle === undefined ||
      recover === undefined ||
      expectedHandle.changeKey !==
        `${input.params.planHash}:${change.changeKey}`
    ) {
      throw input.nonRetryableError("workspace_trycomp_parent_receipt_missing");
    }
    const runtime = input.runtime();
    return applyWorkspaceReviewedTrycomp(
      {
        enabled: workspaceTrycompEnabled(input.env),
        expectedHandle,
        parentPlanHash: input.params.planHash,
        planGeneratedAt: input.params.planGeneratedAt,
        requestedBy: input.params.requestedBy,
        reviewedPlan,
      },
      {
        nonRetryableError: (message) => input.nonRetryableError(message),
        captureAuthority: () => captureTrycompAuthority(runtime),
        createJournal: (receipt) =>
          new D1WorkspaceTrycompMutationStore(
            input.database,
            receipt,
            Date.now,
            input.identityBudget,
          ),
        deployment: input.deployment,
        leaseRepository: new D1ResourceLeaseRepository(input.database),
        now: Date.now,
        recoverReceipt: () =>
          recover({
            changeKey: expectedHandle.changeKey,
            text: `${change.text} · plan ${input.params.planHash.slice(0, 12)}`,
          }),
        safetyReader: new D1TrycompSafetyStore(input.database),
        service: runtime.service,
        readVerifiedInvitationMemberId: (receipt) =>
          readWorkspaceTrycompVerifiedMemberId(input.database, receipt),
      },
    );
  };
}

function workspaceTrycompReceipt(
  handle: WorkspaceDirectoryChangeLedgerHandle,
  parentPlanHash: string,
  reviewedPlan: TrycompReviewedPlan,
): WorkspaceTrycompReceipt {
  return {
    announcementDigest: handle.announcementDigest,
    changeKey: handle.changeKey,
    channelId: handle.channelId,
    parentPlanHash,
    requestedBy: "scheduled:workspace-directory",
    reviewedPlan,
    timestamp: handle.timestamp,
  };
}

export function createWorkspaceReviewedTrycompInvitationReader(input: {
  database: D1Database;
  handles: readonly { handle: WorkspaceDirectoryChangeLedgerHandle }[];
  params: WorkspaceDirectoryWorkflowParams;
}): (reviewed: TrycompReviewedPlan) => Promise<null | string> {
  return async (reviewed) => {
    const branch = input.params.plan.branches.find(
      ({ branchId }) => branchId === "trycomp-people",
    );
    const expected = input.handles[0]?.handle;
    if (
      input.params.scheduledTickId === undefined ||
      input.params.requestedBy !== "scheduled:workspace-directory" ||
      branch?.branchId !== "trycomp-people" ||
      branch.execution !== "managed" ||
      !dequal(branch.reviewedPlan, reviewed) ||
      input.handles.length !== 1 ||
      expected === undefined
    )
      throw new Error("workspace_trycomp_original_invitation_parent_required");
    const action = reviewed.plan.actions[0];
    if (
      action?.type !== "invite" ||
      expected.changeKey !==
        `${input.params.planHash}:trycomp-people:invite:${action.email}`
    )
      throw new Error("workspace_trycomp_original_invitation_action_required");
    return readWorkspaceTrycompVerifiedMemberId(
      input.database,
      workspaceTrycompReceipt(expected, input.params.planHash, reviewed),
    );
  };
}
