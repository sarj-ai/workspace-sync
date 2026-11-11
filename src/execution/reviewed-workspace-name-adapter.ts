import { sameJson } from "../operations/canonical.ts";
import { type JsonValue, JsonValueSchema } from "../operations/schemas.ts";
import type { LinearProfileAction } from "../workspace-directory/linear-profile-sync.ts";
import type { SlackNameAction } from "../workspace-directory/slack-name-sync.ts";
import type { WorkspaceDirectoryPlan } from "./contracts.ts";
import type { WorkspaceNameServices } from "./provider-runtime-ports.ts";
import type {
  ReviewedAction,
  ReviewedActionContext,
} from "./reviewed-action-context.ts";
import {
  type ReviewedNameAction,
  reviewedNameManagedSlice,
  reviewedNameSourceIdentity,
} from "./reviewed-name-plan.ts";

export type WorkspaceNameParentContext = Omit<
  Extract<
    ReviewedActionContext<LinearProfileAction | SlackNameAction>,
    { mode: "parent" }
  >,
  "mode"
>;

export interface IWorkspaceNameReader {
  readSlice(
    plan: WorkspaceDirectoryPlan,
    branchId: ReviewedNameAction["branchId"],
  ): Promise<JsonValue>;
  readSourceFingerprint(
    branchId: ReviewedNameAction["branchId"],
  ): Promise<string>;
}
export interface IWorkspaceNameWriter {
  apply(
    plan: WorkspaceDirectoryPlan,
    branchId: ReviewedNameAction["branchId"],
  ): Promise<string>;
}

export interface WorkspaceNameAdapterDependencies {
  assertGoogleAuthority(plan: WorkspaceDirectoryPlan): Promise<unknown>;
  parentContext?: (reviewed: ReviewedNameAction) => WorkspaceNameParentContext;
  services(): WorkspaceNameServices;
}

export class ReviewedWorkspaceNameAdapter
  implements IWorkspaceNameReader, IWorkspaceNameWriter
{
  readonly #dependencies: WorkspaceNameAdapterDependencies;
  constructor(dependencies: WorkspaceNameAdapterDependencies) {
    this.#dependencies = dependencies;
  }

  async readSourceFingerprint(
    branchId: ReviewedNameAction["branchId"],
  ): Promise<string> {
    const services = this.#dependencies.services();
    return branchId === "slack-names"
      ? services.slack.readSourceFingerprint()
      : services.linear.readSourceFingerprint();
  }

  async readSlice(
    plan: WorkspaceDirectoryPlan,
    branchId: ReviewedNameAction["branchId"],
  ) {
    const reviewed = selectedNameAction(plan, branchId);
    await this.#assertSource(plan, reviewed);
    const services = this.#dependencies.services();
    const state =
      reviewed.branchId === "slack-names"
        ? await services.slack.readReviewed(reviewed)
        : await services.linear.readReviewed(reviewed);
    await this.#assertSource(plan, reviewed);
    return state === "drifted"
      ? JsonValueSchema.parse({
          ...reviewedNameSourceIdentity(reviewed),
          state,
        })
      : reviewedNameManagedSlice(reviewed, state);
  }

  async apply(
    plan: WorkspaceDirectoryPlan,
    branchId: ReviewedNameAction["branchId"],
  ): Promise<string> {
    const reviewed = selectedNameAction(plan, branchId);
    const context = this.#dependencies.parentContext?.(reviewed);
    if (context?.identityBudget.required !== true)
      throw new Error("workspace_directory_name_parent_context_required");
    const parent = {
      mode: "parent" as const,
      identityBudget: context.identityBudget,
      assertFreshPlan: () => context.assertFreshPlan(),
      assertWriteAuthority: async () => {
        await this.#assertSource(plan, reviewed);
        await context.assertWriteAuthority();
        context.assertFreshPlan();
      },
      verifyPreannouncement: async (
        candidate: ReviewedAction<LinearProfileAction | SlackNameAction>,
      ) => {
        if (
          !sameJson(
            JsonValueSchema.parse(candidate),
            JsonValueSchema.parse({
              action: reviewed.action,
              expectedPlanHash: reviewed.expectedPlanHash,
            }),
          )
        )
          throw new Error("workspace_directory_name_receipt_action_mismatch");
        await context.verifyPreannouncement(candidate);
      },
    };
    await parent.assertWriteAuthority();
    const services = this.#dependencies.services();
    const result =
      reviewed.branchId === "slack-names"
        ? await services.slack.applyReviewed(reviewed, parent)
        : await services.linear.applyReviewed(reviewed, parent);
    if (result !== "completed")
      throw new Error("workspace_directory_name_parent_lease_busy");
    return "The exact reviewed name repair converged and was verified.";
  }

  async #assertSource(
    plan: WorkspaceDirectoryPlan,
    reviewed: ReviewedNameAction,
  ): Promise<void> {
    await this.#dependencies.assertGoogleAuthority(plan);
    if (
      (await this.readSourceFingerprint(reviewed.branchId)) !==
      reviewed.sourceFingerprint
    )
      throw new Error("workspace_directory_name_source_drift");
  }
}

function selectedNameAction(
  plan: WorkspaceDirectoryPlan,
  branchId: ReviewedNameAction["branchId"],
): ReviewedNameAction {
  const branch = plan.branches.find(
    (candidate) => candidate.branchId === branchId,
  );
  if (
    (branch?.branchId !== "slack-names" &&
      branch?.branchId !== "linear-profiles") ||
    branch.reviewed?.sourceFingerprint !== branch.sourceFingerprint
  )
    throw new Error("workspace_directory_name_reviewed_action_missing");
  return branch.reviewed;
}
