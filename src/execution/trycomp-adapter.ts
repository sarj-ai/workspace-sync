import { mergeGoogleDirectoryAuthority } from "../org-sync/google-directory-authority.ts";
import type {
  TrycompReviewedPlan,
  TrycompReviewedSlice,
} from "../trycomp/model.ts";
import { assertTrycompSelectedIdentity } from "../trycomp/reviewed-identity.ts";
import type { WorkspaceDirectoryBranchPlan } from "./contracts.ts";
import type { TrycompPeopleSyncRuntime } from "./provider-runtime-ports.ts";
import type { WorkspaceRuntimeConfiguration as ValidatedEnv } from "./runtime-configuration.ts";

type TrycompPeopleBranchPlan = Extract<
  WorkspaceDirectoryBranchPlan,
  { branchId: "trycomp-people" }
>;

interface ITrycompAdapter {
  apply(reviewedPlan: TrycompReviewedPlan): Promise<string>;
  capture(): Promise<TrycompPeopleBranchPlan>;
  readSlice(reviewedPlan: TrycompReviewedPlan): Promise<TrycompReviewedSlice>;
  sourceFingerprint(): Promise<null | string>;
}

export class TrycompAdapter implements ITrycompAdapter {
  readonly #env: ValidatedEnv;
  readonly #runtime: () => TrycompPeopleSyncRuntime;
  readonly #applyReviewed:
    | ((plan: TrycompReviewedPlan) => Promise<string>)
    | undefined;
  readonly #readVerifiedInvitation:
    | ((plan: TrycompReviewedPlan) => Promise<null | string>)
    | undefined;

  constructor(
    env: ValidatedEnv,
    runtime: () => TrycompPeopleSyncRuntime,
    applyReviewed?: (plan: TrycompReviewedPlan) => Promise<string>,
    readVerifiedInvitation?: (
      plan: TrycompReviewedPlan,
    ) => Promise<null | string>,
  ) {
    this.#env = env;
    this.#runtime = runtime;
    this.#applyReviewed = applyReviewed;
    this.#readVerifiedInvitation = readVerifiedInvitation;
  }

  async capture(): Promise<TrycompPeopleBranchPlan> {
    if (
      !this.#env.workspaceDirectoryTrycompEnabled ||
      this.#env.trycompSyncDisabled
    ) {
      return {
        branchId: "trycomp-people",
        diagnostics: [],
        execution: "disabled",
        killSwitchEngaged: true,
        reviewedPlan: null,
      };
    }
    const runtime = this.#runtime();
    const reviewedPlan = await runtime.service.captureReviewedPlan(
      await captureTrycompAuthority(runtime),
    );
    const diagnostics = projectTrycompDiagnostics(reviewedPlan);
    return {
      branchId: "trycomp-people",
      diagnostics,
      ...(this.#env.trycompSyncMode === "live"
        ? { execution: "managed" as const, killSwitchEngaged: false as const }
        : {
            execution: "audit-only" as const,
            killSwitchEngaged: true as const,
          }),
      reviewedPlan,
    };
  }

  async sourceFingerprint(): Promise<null | string> {
    if (
      !this.#env.workspaceDirectoryTrycompEnabled ||
      this.#env.trycompSyncDisabled ||
      this.#env.trycompSyncMode !== "live"
    )
      return null;
    const branch = await this.capture();
    return branch.execution === "managed"
      ? branch.reviewedPlan.sourceFingerprint
      : null;
  }

  async readSlice(reviewedPlan: TrycompReviewedPlan) {
    const runtime = this.#runtime();
    const authority = await captureTrycompAuthority(runtime);
    if (
      this.#env.workspaceDirectoryTrycompEnabled &&
      reviewedPlan.plan.actions.length > 0
    )
      assertTrycompSelectedIdentity(reviewedPlan, authority.googleUsers);
    const readVerifiedInvitation = this.#readVerifiedInvitation;
    return runtime.service.readReviewedSlice(reviewedPlan, {
      authority,
      ...(!(readVerifiedInvitation === undefined) && {
        verifiedInvitationMemberId: () => readVerifiedInvitation(reviewedPlan),
      }),
    });
  }

  async apply(reviewedPlan: TrycompReviewedPlan): Promise<string> {
    if (
      !this.#env.workspaceDirectoryTrycompEnabled ||
      this.#env.trycompSyncDisabled ||
      this.#env.trycompSyncMode !== "live" ||
      this.#applyReviewed === undefined
    ) {
      throw new Error("workspace_trycomp_reviewed_execution_unavailable");
    }
    return this.#applyReviewed(reviewedPlan);
  }
}

export function projectTrycompDiagnostics(reviewedPlan: TrycompReviewedPlan) {
  const errors = [...reviewedPlan.plan.errors];
  if (
    reviewedPlan.plan.actions.length > 0 &&
    reviewedPlan.selectedIdentity === undefined
  )
    errors.push(
      "Trycomp selected action requires a signed immutable Google identity",
    );
  return errors.map((message) => ({
    code: "trycomp_authority_blocked",
    message,
    scope: {
      actionId: "workspace-directory.trycomp-people" as const,
      kind: "action" as const,
    },
    severity: "blocker" as const,
  }));
}

export async function captureTrycompAuthority(
  runtime: TrycompPeopleSyncRuntime,
) {
  const runId = crypto.randomUUID();
  const [active, deleted, groups] = await Promise.all([
    runtime.google.listAllUsers(runId),
    runtime.google.listDeletedUsers(runId),
    runtime.groups.listGroups([runtime.contractorGroupEmail], runId),
  ]);
  const contractorGroup = groups[0];
  if (contractorGroup?.email !== runtime.contractorGroupEmail) {
    throw new Error("trycomp_contractor_group_missing");
  }
  return {
    activeGoogleUserCount: active.length,
    contractorGroup,
    googleUsers: mergeGoogleDirectoryAuthority(active, deleted),
  };
}
