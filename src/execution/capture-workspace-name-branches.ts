import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import {
  LinearProfilesBranchPlanSchema,
  SlackNamesBranchPlanSchema,
  WORKSPACE_DIRECTORY_ACTION_IDS,
  type WorkspaceDirectoryPlan,
} from "./contracts.ts";
import type { WorkspaceNameServices } from "./provider-runtime-ports.ts";
import {
  selectReviewedLinearProfile,
  selectReviewedSlackName,
} from "./reviewed-name-plan.ts";

export async function captureWorkspaceNameBranches(
  plan: WorkspaceDirectoryPlan,
  users: readonly GoogleDirectoryUser[],
  services: WorkspaceNameServices,
  includes: (
    actionId:
      | typeof WORKSPACE_DIRECTORY_ACTION_IDS.linearProfiles
      | typeof WORKSPACE_DIRECTORY_ACTION_IDS.slackNames,
  ) => boolean,
) {
  const branches: Extract<
    WorkspaceDirectoryPlan["branches"][number],
    { branchId: "linear-profiles" | "slack-names" }
  >[] = [];
  if (includes(WORKSPACE_DIRECTORY_ACTION_IDS.slackNames)) {
    const capture = await services.slack.captureParent(users);
    const ids = new Set(
      (plan.branches[0].execution === "managed"
        ? plan.branches[0].changes
        : []
      ).flatMap(({ googleUserId }) =>
        googleUserId === null ? [] : [googleUserId],
      ),
    );
    if (
      plan.branches[2].execution === "managed" &&
      plan.branches[2].selectedIdentity !== undefined
    )
      ids.add(plan.branches[2].selectedIdentity.googleUserId);
    const selected =
      ids.size > 1
        ? { kind: "service-identity-deferred" as const }
        : selectReviewedSlackName(capture, ids.values().next().value);
    branches.push(
      SlackNamesBranchPlanSchema.parse({
        branchId: "slack-names",
        execution: "managed",
        killSwitchEngaged: false,
        sourceFingerprint: capture.sourceFingerprint,
        reviewed: selected.kind === "selected" ? selected.reviewed : null,
        diagnostics: nameDiagnostics(
          capture.diagnostics,
          selected.kind,
          WORKSPACE_DIRECTORY_ACTION_IDS.slackNames,
        ),
      }),
    );
  }
  if (includes(WORKSPACE_DIRECTORY_ACTION_IDS.linearProfiles)) {
    const capture = await services.linear.captureParent(users);
    const ids = new Set(
      plan.branches[4].plan?.actions.map(({ googleUserId }) => googleUserId),
    );
    const selected =
      ids.size > 1
        ? { kind: "service-identity-deferred" as const }
        : selectReviewedLinearProfile(capture, ids.values().next().value);
    branches.push(
      LinearProfilesBranchPlanSchema.parse({
        branchId: "linear-profiles",
        execution: "managed",
        killSwitchEngaged: false,
        sourceFingerprint: capture.sourceFingerprint,
        reviewed: selected.kind === "selected" ? selected.reviewed : null,
        diagnostics: nameDiagnostics(
          capture.diagnostics,
          selected.kind,
          WORKSPACE_DIRECTORY_ACTION_IDS.linearProfiles,
        ),
      }),
    );
  }
  return branches;
}

function nameDiagnostics(
  diagnostics: readonly { googleUserId: string; reason: string }[],
  selection: string,
  actionId:
    | typeof WORKSPACE_DIRECTORY_ACTION_IDS.linearProfiles
    | typeof WORKSPACE_DIRECTORY_ACTION_IDS.slackNames,
) {
  return [
    ...diagnostics.map(({ googleUserId, reason }) => ({
      code: `name_identity_${reason}`,
      message: `Name reconciliation Google identity ${googleUserId} is ${reason}.`,
      severity:
        reason === "protected" ? ("info" as const) : ("blocker" as const),
      scope: { kind: "action" as const, actionId },
    })),
    ...(selection !== "service-identity-deferred"
      ? []
      : [
          {
            code: "name_service_identity_deferred",
            message:
              "Name repair deferred to preserve the selected service identity budget.",
            severity: "warning" as const,
            scope: { kind: "action" as const, actionId },
          },
        ]),
  ];
}
