import type { z } from "zod";

import { sameJson } from "../operations/canonical.ts";
import type { JsonValue } from "../operations/schemas.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import { logErrorEvent } from "../shared/log-event.ts";
import {
  PosthogMembershipsBranchPlanSchema,
  WORKSPACE_DIRECTORY_ACTION_IDS,
  type WorkspaceDirectoryPlan,
} from "./contracts.ts";
import type {
  PosthogMembershipExecutionPort,
  PosthogMembershipParent,
} from "./posthog-membership-service.ts";
import {
  ReviewedPosthogMembershipSchema,
  posthogMembershipManagedSlice,
} from "./reviewed-posthog-membership.ts";

export interface PosthogMembershipAdapterDependencies {
  assertGoogleAuthority(plan: WorkspaceDirectoryPlan): Promise<unknown>;
  service(): PosthogMembershipExecutionPort;
  parentContext?(
    plan: WorkspaceDirectoryPlan,
  ): Omit<PosthogMembershipParent, "assertFinalSourceAuthority">;
}
export interface PosthogMembershipAdapterPort {
  capture(
    plan: WorkspaceDirectoryPlan,
    enabled: boolean,
  ): Promise<z.output<typeof PosthogMembershipsBranchPlanSchema>>;
  readSlice(plan: WorkspaceDirectoryPlan): Promise<JsonValue>;
  apply(plan: WorkspaceDirectoryPlan): Promise<string>;
}
export class ReviewedPosthogMembershipAdapter implements PosthogMembershipAdapterPort {
  readonly #ports: PosthogMembershipAdapterDependencies;
  constructor(ports: PosthogMembershipAdapterDependencies) {
    this.#ports = ports;
  }

  async capture(plan: WorkspaceDirectoryPlan, enabled: boolean) {
    if (!enabled)
      return PosthogMembershipsBranchPlanSchema.parse({
        branchId: "posthog-memberships",
        execution: "disabled",
        killSwitchEngaged: true,
        reviewed: null,
        sourceFingerprint: plan.authorityFingerprint,
        diagnostics: [],
      });
    const audit = await (async () => {
      try {
        return await this.#ports.service().capture();
      } catch {
        logErrorEvent("workspace_directory.posthog_capture_failed", {
          "error_code": "posthog_evidence_unavailable",
        });
        return null;
      }
    })();
    await this.#ports.assertGoogleAuthority(plan);
    const codes =
      audit === null ? ["posthog_evidence_unavailable"] : audit.plan.blockers;
    const diagnostics = codes.map((code) => ({
      code,
      severity: "blocker" as const,
      message: "PostHog membership authority is incomplete or has drifted.",
      scope: {
        kind: "action" as const,
        actionId: WORKSPACE_DIRECTORY_ACTION_IDS.posthogMemberships,
      },
    }));
    const action = audit?.plan.actions[0];
    const reviewed =
      audit !== null && action !== undefined && codes.length === 0
        ? ReviewedPosthogMembershipSchema.parse({
            action,
            expectedPlanHash: audit.plan.planHash,
            sourceAuthorityFingerprint: audit.sourceAuthorityFingerprint,
            organizationId: audit.provider.organizationId,
          })
        : null;
    return PosthogMembershipsBranchPlanSchema.parse({
      branchId: "posthog-memberships",
      execution: "managed",
      killSwitchEngaged: false,
      reviewed,
      sourceFingerprint: plan.authorityFingerprint,
      diagnostics,
    });
  }

  async readSlice(plan: WorkspaceDirectoryPlan) {
    const reviewed = selected(plan);
    await this.#ports.assertGoogleAuthority(plan);
    const state = await this.#ports.service().readReviewed(reviewed);
    await this.#ports.assertGoogleAuthority(plan);
    return state === "drifted"
      ? JsonValueSchema.parse({ state })
      : posthogMembershipManagedSlice(reviewed, state);
  }

  async apply(plan: WorkspaceDirectoryPlan): Promise<string> {
    const reviewed = selected(plan);
    const original = this.#ports.parentContext?.(plan);
    if (original?.identityBudget.required !== true)
      throw new Error("workspace_posthog_parent_required");
    const parent: PosthogMembershipParent = {
      ...original,
      assertWriteAuthority: async () => {
        await original.assertWriteAuthority();
        await this.#ports.assertGoogleAuthority(plan);
        original.assertFreshPlan();
      },
      assertFinalSourceAuthority: async () => {
        await this.#ports.assertGoogleAuthority(plan);
        original.assertFreshPlan();
      },
      verifyPreannouncement: async (actual) => {
        if (
          !sameJson(
            JsonValueSchema.parse(actual),
            JsonValueSchema.parse({
              action: reviewed.action,
              expectedPlanHash: reviewed.expectedPlanHash,
            }),
          )
        )
          throw new Error("workspace_posthog_original_action_required");
        await original.verifyPreannouncement(actual);
      },
    };
    if (
      (await this.#ports.service().applyReviewed(reviewed, parent)) === "busy"
    )
      throw new Error("workspace_posthog_lease_busy");
    return "The original PostHog membership was applied and verified.";
  }
}
function selected(plan: WorkspaceDirectoryPlan) {
  const branch = plan.branches.find(
    (item) => item.branchId === "posthog-memberships",
  );
  if (
    branch?.execution !== "managed" ||
    branch.reviewed === null ||
    branch.sourceFingerprint !== plan.authorityFingerprint ||
    branch.diagnostics.some(({ severity }) => severity === "blocker")
  )
    throw new Error("workspace_posthog_reviewed_action_required");
  return branch.reviewed;
}
