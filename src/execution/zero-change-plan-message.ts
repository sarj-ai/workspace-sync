import {
  type SignedOperationPlan,
  SignedOperationPlanSchema,
} from "../operations/schemas.ts";
import type { WorkspaceDirectoryLedgerMessage } from "./change-ledger-contracts.ts";
import {
  WORKSPACE_DIRECTORY_ACTION_IDS,
  WorkspaceDirectoryOperationInputSchema,
} from "./contracts.ts";
import { WORKSPACE_DIRECTORY_FLOW } from "./flow.ts";

const ACTION_BRANCH_OVERRIDES: ReadonlyMap<string, string> = new Map([
  [WORKSPACE_DIRECTORY_ACTION_IDS.fanout, "identity-provisioning"],
  [WORKSPACE_DIRECTORY_ACTION_IDS.linearSuspensions, "access-guard"],
]);
const DIAGNOSTIC_PRIORITY = { blocker: 0, warning: 1, info: 2 } as const;
const GRAPHEME_SEGMENTER = new Intl.Segmenter("en-US", {
  granularity: "grapheme",
});

/* Reports only signed envelope facts; an empty change list contains no branch snapshot. */
export function zeroChangePlanMessage(
  signedPlan: SignedOperationPlan,
): WorkspaceDirectoryLedgerMessage {
  const { plan } = SignedOperationPlanSchema.parse(signedPlan);
  if (
    plan.operation !== "workspace-directory.reconcile" ||
    plan.changes.length !== 0 ||
    Object.values(plan.summary).some((count) => count !== 0)
  )
    throw new Error("workspace_directory_zero_change_plan_required");
  const input = WorkspaceDirectoryOperationInputSchema.parse(plan.input);
  const scope =
    input.includedActionIds === null
      ? "Default Workspace Directory scope"
      : input.includedActionIds
          .map(
            (actionId) =>
              WORKSPACE_DIRECTORY_FLOW.branches.find(
                ({ branchId }) =>
                  branchId ===
                  (ACTION_BRANCH_OVERRIDES.get(actionId) ??
                    actionId.replace("workspace-directory.", "")),
              )?.displayName ?? actionId,
          )
          .join(", ") || "No integrations selected";
  const blockers = plan.diagnostics.filter(
    ({ severity }) => severity === "blocker",
  ).length;
  const warnings = plan.diagnostics.filter(
    ({ severity }) => severity === "warning",
  ).length;
  const info = plan.diagnostics.filter(
    ({ severity }) => severity === "info",
  ).length;
  const lines = [
    "No selected changes. No provider writes are selected. Review diagnostics; this is not proof that every integration is converged.",
    `Scope: ${scope}`,
    `Blockers ${String(blockers)} · Warnings ${String(warnings)} · Info ${String(info)} · Applicable: ${plan.applicable ? "yes" : "no"}`,
    ...diagnosticExcerpts(plan.diagnostics),
    `Plan ${plan.planHash}\nGenerated ${plan.generatedAt}\nExpires ${plan.expiresAt}\nRequested by ${plan.actor.id}`,
  ];
  return {
    text: ["Workspace Directory · PLAN", ...lines]
      .join(" · ")
      .replaceAll(/\s+/gu, " "),
    blocks: [
      {
        type: "header",
        "block_id": "zero-plan-title",
        text: {
          type: "plain_text",
          emoji: true,
          text: "Workspace Directory · PLAN",
        },
      },
      ...lines.map((text, index) => ({
        type: "section",
        "block_id": `zero-plan-${String(index)}`,
        text: { type: "plain_text", emoji: true, text },
      })),
    ],
  };
}

function diagnosticExcerpts(
  diagnostics: SignedOperationPlan["plan"]["diagnostics"],
): string[] {
  const selected = diagnostics
    .toSorted(
      (a, b) =>
        DIAGNOSTIC_PRIORITY[a.severity] - DIAGNOSTIC_PRIORITY[b.severity],
    )
    .slice(0, 4);
  const lines = selected.map(({ severity, code, message }) => {
    const excerpt =
      message.length > 500
        ? `${message.slice(0, GRAPHEME_SEGMENTER.segment(message).containing(499)?.index ?? 0)}… (excerpt; full diagnostic in signed plan)`
        : message;
    return `${severity.toUpperCase()} · ${code}\n${excerpt}`;
  });
  if (diagnostics.length > selected.length)
    lines.push(
      `${String(diagnostics.length - selected.length)} more diagnostics in the signed plan.`,
    );
  return lines;
}
