import { sameJson } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import type { GoogleGroupCleanupAction } from "../workspace-directory/google-group-cleanup-sync.ts";
import {
  GoogleGroupCleanupBranchPlanSchema,
  type WorkspaceDirectoryPlan,
} from "./contracts.ts";
import type {
  GoogleGroupCleanupParentExecution,
  GoogleGroupCleanupServiceContract,
} from "./google-group-cleanup-service.ts";
import type { ReviewedActionContext } from "./reviewed-action-context.ts";
import {
  googleGroupCleanupManagedSlice,
  type ReviewedGoogleGroupCleanupIntent,
  ReviewedGoogleGroupCleanupIntentSchema,
} from "./reviewed-google-group-cleanup.ts";

const OBSERVATION_DEADLINE_MS = 60_000;

export type GoogleGroupCleanupParentContext = Extract<
  ReviewedActionContext<GoogleGroupCleanupAction>,
  { mode: "parent" }
> & { readonly deadlineAtMs?: number };

interface CleanupAdapterDependencies {
  assertGoogleAuthority(
    plan: WorkspaceDirectoryPlan,
    deadlineAt?: number,
  ): Promise<unknown>;
  parentContext?: (
    plan: WorkspaceDirectoryPlan,
  ) => GoogleGroupCleanupParentContext;
  service(): Pick<
    GoogleGroupCleanupServiceContract,
    "applyReviewed" | "auditPlan" | "readReviewed"
  >;
}

export interface IGoogleCleanupParentReader {
  capture(
    plan: WorkspaceDirectoryPlan,
    execution: "audit-only" | "disabled" | "managed",
    reviewed?: ReviewedGoogleGroupCleanupIntent,
  ): Promise<ReturnType<typeof GoogleGroupCleanupBranchPlanSchema.parse>>;
  readSlice(
    plan: WorkspaceDirectoryPlan,
  ): Promise<ReturnType<typeof JsonValueSchema.parse>>;
}
export interface IGoogleCleanupParentWriter {
  apply(plan: WorkspaceDirectoryPlan): Promise<string>;
}

export class ReviewedGoogleGroupCleanupAdapter
  implements IGoogleCleanupParentReader, IGoogleCleanupParentWriter
{
  readonly #dependencies: CleanupAdapterDependencies;
  constructor(dependencies: CleanupAdapterDependencies) {
    this.#dependencies = dependencies;
  }

  async capture(
    plan: WorkspaceDirectoryPlan,
    execution: "audit-only" | "disabled" | "managed",
    rawReviewed?: ReviewedGoogleGroupCleanupIntent,
  ) {
    const audit =
      execution === "disabled"
        ? null
        : await this.#dependencies.service().auditPlan();
    await this.#dependencies.assertGoogleAuthority(plan);
    const reviewed =
      rawReviewed === undefined
        ? undefined
        : ReviewedGoogleGroupCleanupIntentSchema.parse(rawReviewed);
    if (reviewed !== undefined) {
      const exactAction =
        audit?.actions.some((candidate) =>
          sameJson(
            ReviewedGoogleGroupCleanupIntentSchema.parse({
              action: candidate,
              expectedPlanHash: reviewed.expectedPlanHash,
            }).action,
            reviewed.action,
          ),
        ) === true;
      if (
        execution !== "managed" ||
        reviewed.expectedPlanHash !== audit?.planHash ||
        !exactAction
      )
        throw new Error(
          "workspace_google_group_cleanup_original_action_changed",
        );
    }
    const action = reviewed?.action ?? audit?.actions[0];
    return GoogleGroupCleanupBranchPlanSchema.parse({
      branchId: "google-group-cleanup",
      execution,
      killSwitchEngaged: execution !== "managed",
      reviewed:
        action === undefined || audit === null
          ? null
          : { action, expectedPlanHash: audit.planHash },
      sourceFingerprint: plan.authorityFingerprint,
      diagnostics: (audit?.warnings ?? []).map((warning) => ({
        code: warning.type,
        message: `Privileged inactive membership requires manual review in ${warning.googleGroupEmail}.`,
        severity: "warning",
      })),
    });
  }

  async readSlice(plan: WorkspaceDirectoryPlan) {
    const reviewed = selected(plan);
    const deadlineAt = Date.now() + OBSERVATION_DEADLINE_MS;
    await this.#dependencies.assertGoogleAuthority(plan, deadlineAt);
    const state = await this.#dependencies
      .service()
      .readReviewed(reviewed, deadlineAt);
    await this.#dependencies.assertGoogleAuthority(plan, deadlineAt);
    return state === "drifted"
      ? JsonValueSchema.parse({ state })
      : googleGroupCleanupManagedSlice(reviewed, state);
  }

  async apply(plan: WorkspaceDirectoryPlan): Promise<string> {
    const reviewed = selected(plan);
    const original = this.#dependencies.parentContext?.(plan);
    if (original?.identityBudget.required !== true)
      throw new Error("workspace_google_group_cleanup_parent_required");
    const parent: GoogleGroupCleanupParentExecution = {
      ...original,
      assertFinalSourceAuthority: async () => {
        await this.#dependencies.assertGoogleAuthority(
          plan,
          original.deadlineAtMs,
        );
        original.assertFreshPlan();
      },
      assertWriteAuthority: async () => {
        await original.assertWriteAuthority();
        await this.#dependencies.assertGoogleAuthority(
          plan,
          original.deadlineAtMs,
        );
        original.assertFreshPlan();
      },
      verifyPreannouncement: async (actual) => {
        if (
          !sameJson(
            JsonValueSchema.parse(actual),
            JsonValueSchema.parse(reviewed),
          )
        )
          throw new Error(
            "workspace_google_group_cleanup_original_action_required",
          );
        await original.verifyPreannouncement(actual);
      },
    };
    const result = await this.#dependencies
      .service()
      .applyReviewed(reviewed, parent);
    if (result === "busy")
      throw new Error("workspace_google_group_cleanup_lease_busy");
    return "The original inactive Google Group membership was removed and verified.";
  }
}

function selected(plan: WorkspaceDirectoryPlan) {
  const branch = plan.branches.find(
    (candidate) => candidate.branchId === "google-group-cleanup",
  );
  if (
    branch?.execution !== "managed" ||
    branch.reviewed === null ||
    branch.sourceFingerprint !== plan.authorityFingerprint
  )
    throw new Error("workspace_google_group_cleanup_reviewed_action_required");
  return branch.reviewed;
}
