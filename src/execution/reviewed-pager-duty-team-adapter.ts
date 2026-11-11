import { sameJson } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import { logErrorEvent } from "../shared/log-event.ts";
import type { PagerDutyTeamWritableAction } from "../workspace-directory/pagerduty-team-sync.ts";
import {
  PagerDutyTeamsBranchPlanSchema,
  WORKSPACE_DIRECTORY_ACTION_IDS,
  type WorkspaceDirectoryPlan,
} from "./contracts.ts";
import type {
  PagerDutyTeamExecutionPort,
  PagerDutyTeamParentExecution,
} from "./pager-duty-team-service.ts";
import type { ReviewedActionContext } from "./reviewed-action-context.ts";
import { pagerDutyTeamManagedSlice } from "./reviewed-pagerduty-team.ts";

export type PagerDutyTeamParentContext = Extract<
  ReviewedActionContext<PagerDutyTeamWritableAction>,
  { mode: "parent" }
>;
interface Dependencies {
  assertGoogleAuthority(plan: WorkspaceDirectoryPlan): Promise<unknown>;
  parentContext?: (plan: WorkspaceDirectoryPlan) => PagerDutyTeamParentContext;
  service(): PagerDutyTeamExecutionPort;
}

export interface IPagerDutyTeamParentReader {
  capture(
    plan: WorkspaceDirectoryPlan,
    execution: "disabled" | "managed",
  ): Promise<ReturnType<typeof PagerDutyTeamsBranchPlanSchema.parse>>;
  readSlice(
    plan: WorkspaceDirectoryPlan,
  ): Promise<ReturnType<typeof JsonValueSchema.parse>>;
}
export interface IPagerDutyTeamParentWriter {
  apply(plan: WorkspaceDirectoryPlan): Promise<string>;
}

export class ReviewedPagerDutyTeamAdapter
  implements IPagerDutyTeamParentReader, IPagerDutyTeamParentWriter
{
  readonly #dependencies: Dependencies;
  constructor(dependencies: Dependencies) {
    this.#dependencies = dependencies;
  }

  async capture(
    plan: WorkspaceDirectoryPlan,
    execution: "disabled" | "managed",
  ) {
    const audit = await this.#dependencies
      .service()
      .auditPlan()
      .catch(() => {
        logErrorEvent("workspace_directory.pagerduty_capture_failed", {
          "error_code": "pagerduty_evidence_unavailable",
        });
        return null;
      });
    await this.#dependencies.assertGoogleAuthority(plan);
    if (audit === null)
      return PagerDutyTeamsBranchPlanSchema.parse({
        branchId: "pagerduty-teams",
        execution,
        killSwitchEngaged: execution !== "managed",
        reviewed: null,
        sourceFingerprint: plan.authorityFingerprint,
        diagnostics: [
          {
            code: "pagerduty_evidence_unavailable",
            severity: "blocker",
            message:
              "Fresh PagerDuty team evidence is unavailable; no membership changes are authorized.",
            scope: {
              kind: "action",
              actionId: WORKSPACE_DIRECTORY_ACTION_IDS.pagerDutyTeams,
            },
          },
        ],
      });
    const action = audit.actions.find(
      (candidate) => candidate.type !== "remove",
    );
    return PagerDutyTeamsBranchPlanSchema.parse({
      branchId: "pagerduty-teams",
      execution,
      killSwitchEngaged: execution !== "managed",
      reviewed:
        action === undefined
          ? null
          : {
              action,
              expectedPlanHash: audit.planHash,
              reviewId: audit.reviewId,
            },
      sourceFingerprint: plan.authorityFingerprint,
      diagnostics: [
        ...audit.diagnostics.map(({ code, detail, severity }) => ({
          code,
          message: detail,
          scope: {
            kind: "action",
            actionId: WORKSPACE_DIRECTORY_ACTION_IDS.pagerDutyTeams,
          },
          severity: severity === "error" ? "blocker" : "warning",
        })),
        ...audit.actions
          .filter((candidate) => candidate.type === "remove")
          .map((candidate) => ({
            code: "pagerduty_removal_unsupported",
            scope: {
              kind: "action",
              actionId: WORKSPACE_DIRECTORY_ACTION_IDS.pagerDutyTeams,
            },
            message: `Removal of ${candidate.email} from team ${candidate.pagerDutyTeamId} is audit-only; this integration cannot remove memberships.`,
            severity: "warning",
          })),
      ],
    });
  }

  async readSlice(plan: WorkspaceDirectoryPlan) {
    const reviewed = selected(plan);
    await this.#dependencies.assertGoogleAuthority(plan);
    const state = await this.#dependencies.service().readReviewed(reviewed);
    await this.#dependencies.assertGoogleAuthority(plan);
    return state === "drifted"
      ? JsonValueSchema.parse({ state })
      : pagerDutyTeamManagedSlice(reviewed, state);
  }

  async apply(plan: WorkspaceDirectoryPlan): Promise<string> {
    const reviewed = selected(plan);
    const original = this.#dependencies.parentContext?.(plan);
    if (original?.identityBudget.required !== true)
      throw new Error("workspace_pagerduty_teams_parent_required");
    const parent: PagerDutyTeamParentExecution = {
      ...original,
      assertWriteAuthority: async () => {
        await original.assertWriteAuthority();
        await this.#dependencies.assertGoogleAuthority(plan);
        original.assertFreshPlan();
      },
      assertFinalSourceAuthority: async () => {
        await this.#dependencies.assertGoogleAuthority(plan);
        original.assertFreshPlan();
      },
      verifyPreannouncement: async (actual) => {
        if (
          !sameJson(
            JsonValueSchema.parse(actual),
            JsonValueSchema.parse(reviewed),
          )
        )
          throw new Error("workspace_pagerduty_teams_original_action_required");
        await original.verifyPreannouncement(actual);
      },
    };
    if (
      (await this.#dependencies.service().applyReviewed(reviewed, parent)) ===
      "busy"
    )
      throw new Error("workspace_pagerduty_teams_lease_busy");
    return "The original PagerDuty team membership was applied and verified.";
  }
}

function selected(plan: WorkspaceDirectoryPlan) {
  const branch = plan.branches.find(
    (candidate) => candidate.branchId === "pagerduty-teams",
  );
  if (
    branch?.execution !== "managed" ||
    branch.reviewed === null ||
    branch.sourceFingerprint !== plan.authorityFingerprint ||
    branch.diagnostics.some(({ severity }) => severity === "blocker")
  )
    throw new Error("workspace_pagerduty_teams_reviewed_action_required");
  return branch.reviewed;
}
