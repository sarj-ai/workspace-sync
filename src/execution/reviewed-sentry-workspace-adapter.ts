import { sameJson } from "../operations/canonical.ts";
import { type JsonValue, JsonValueSchema } from "../operations/schemas.ts";
import { logErrorEvent } from "../shared/log-event.ts";
import type { SentryWorkspaceAction } from "../workspace-directory/sentry-workspace-sync.ts";
import {
  SentryMembershipsBranchPlanSchema,
  WORKSPACE_DIRECTORY_ACTION_IDS,
  type WorkspaceDirectoryBranchPlan,
  type WorkspaceDirectoryPlan,
} from "./contracts.ts";
import type { ReviewedActionContext } from "./reviewed-action-context.ts";
import {
  type ReviewedSentryWorkspace,
  ReviewedSentryWorkspaceSchema,
  sentryWorkspaceManagedSlice,
} from "./reviewed-sentry-workspace.ts";
import { assertSentryWorkspaceAuthorityPins } from "./sentry-workspace-authority-pins.ts";
import type { SentryWorkspaceParentConfig } from "./sentry-workspace-parent-config.ts";
import type {
  SentryWorkspaceExecutionPort,
  SentryWorkspaceParentExecution,
} from "./sentry-workspace-service.ts";
import { SentryParentEvidenceError } from "./sentry-workspace-service.ts";

export type SentryWorkspaceParentContext = Extract<
  ReviewedActionContext<SentryWorkspaceAction>,
  { mode: "parent" }
>;

interface Dependencies {
  assertGoogleAuthority(plan: WorkspaceDirectoryPlan): Promise<unknown>;
  parentContext?: (
    plan: WorkspaceDirectoryPlan,
  ) => SentryWorkspaceParentContext;
  service(): SentryWorkspaceExecutionPort;
}

export interface IReviewedSentryWorkspaceAdapter {
  apply(plan: WorkspaceDirectoryPlan): Promise<string>;
  capture(
    plan: WorkspaceDirectoryPlan,
    config: SentryWorkspaceParentConfig,
  ): Promise<
    Extract<WorkspaceDirectoryBranchPlan, { branchId: "sentry-memberships" }>
  >;
  readSlice(plan: WorkspaceDirectoryPlan): Promise<JsonValue>;
}

export class ReviewedSentryWorkspaceAdapter implements IReviewedSentryWorkspaceAdapter {
  readonly #dependencies: Dependencies;

  constructor(dependencies: Dependencies) {
    this.#dependencies = dependencies;
  }

  async capture(
    plan: WorkspaceDirectoryPlan,
    config: SentryWorkspaceParentConfig,
  ) {
    const audit = await (async () => {
      try {
        await Promise.resolve();
        return await this.#dependencies.service().auditParentPlan();
      } catch (error: unknown) {
        logErrorEvent("workspace_directory.sentry_capture_failed", {
          "error_code": "sentry_evidence_unavailable",
          "evidence_reason":
            error instanceof SentryParentEvidenceError
              ? error.reason
              : "provider-unavailable",
          "evidence_stage":
            error instanceof SentryParentEvidenceError
              ? error.stage
              : "unknown",
        });
        return null;
      }
    })();
    await this.#dependencies.assertGoogleAuthority(plan);
    const diagnostics = configDiagnostics(config);
    if (audit === null) {
      diagnostics.push(blocker("sentry_evidence_unavailable"));
    }
    if (audit !== null && config.execution === "managed") {
      try {
        assertSentryWorkspaceAuthorityPins(
          config.pins,
          audit.providerAuthority,
        );
      } catch {
        diagnostics.push(blocker("sentry_authority_pin_mismatch"));
      }
    }
    const action = audit?.plan.actions[0];
    const identity =
      audit === null || action === undefined
        ? undefined
        : audit.googleIdentities.find(({ email }) => email === action.email);
    if (action !== undefined && identity === undefined) {
      diagnostics.push(blocker("sentry_google_identity_missing"));
    }
    const managed = config.execution === "managed";
    const reviewed =
      managed &&
      audit !== null &&
      action !== undefined &&
      identity !== undefined &&
      !diagnostics.some(({ severity }) => severity === "blocker")
        ? ReviewedSentryWorkspaceSchema.parse({
            action,
            authorityPins: config.pins,
            expectedPlanHash: audit.plan.planHash,
            googleUserId: identity.googleUserId,
            sourceAuthorityFingerprint: audit.authorityFingerprint,
          })
        : null;
    return SentryMembershipsBranchPlanSchema.parse({
      branchId: "sentry-memberships",
      diagnostics,
      execution: managed ? "managed" : "disabled",
      killSwitchEngaged: !managed,
      reviewed,
      sourceFingerprint: plan.authorityFingerprint,
    });
  }

  async readSlice(plan: WorkspaceDirectoryPlan) {
    const reviewed = selected(plan);
    await this.#dependencies.assertGoogleAuthority(plan);
    const state = await this.#dependencies.service().readReviewed(reviewed);
    await this.#dependencies.assertGoogleAuthority(plan);
    return state === "drifted"
      ? JsonValueSchema.parse({ state })
      : sentryWorkspaceManagedSlice(reviewed, state);
  }

  async apply(plan: WorkspaceDirectoryPlan): Promise<string> {
    const reviewed = selected(plan);
    const original = this.#dependencies.parentContext?.(plan);
    if (original?.identityBudget.required !== true) {
      throw new Error("workspace_sentry_parent_required");
    }
    const parent: SentryWorkspaceParentExecution = {
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
            JsonValueSchema.parse({
              action: reviewed.action,
              expectedPlanHash: reviewed.expectedPlanHash,
            }),
          )
        ) {
          throw new Error("workspace_sentry_original_action_required");
        }
        await original.verifyPreannouncement(actual);
      },
    };
    if (
      (await this.#dependencies.service().applyReviewed(reviewed, parent)) ===
      "busy"
    ) {
      throw new Error("workspace_sentry_lease_busy");
    }
    return "The original Sentry membership was applied and verified.";
  }
}

function selected(plan: WorkspaceDirectoryPlan): ReviewedSentryWorkspace {
  const branch = plan.branches.find(
    (candidate) => candidate.branchId === "sentry-memberships",
  );
  if (
    branch?.execution !== "managed" ||
    branch.reviewed === null ||
    branch.sourceFingerprint !== plan.authorityFingerprint ||
    branch.diagnostics.some(({ severity }) => severity === "blocker")
  ) {
    throw new Error("workspace_sentry_reviewed_action_required");
  }
  return branch.reviewed;
}

function configDiagnostics(config: SentryWorkspaceParentConfig) {
  if (config.execution === "managed") return [];
  return [
    config.execution === "blocked"
      ? blocker(config.reason)
      : {
          code: config.reason,
          message: "Sentry signed-parent execution remains disabled.",
          scope: {
            actionId: WORKSPACE_DIRECTORY_ACTION_IDS.sentryMemberships,
            kind: "action" as const,
          },
          severity: "info" as const,
        },
  ];
}

function blocker(code: string) {
  return {
    code,
    message:
      "Sentry authority is incomplete or has drifted; no membership write is authorized.",
    scope: {
      actionId: WORKSPACE_DIRECTORY_ACTION_IDS.sentryMemberships,
      kind: "action" as const,
    },
    severity: "blocker" as const,
  };
}
