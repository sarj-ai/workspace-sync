import { dequal } from "dequal";

import type { SignedOperationPlan } from "../operations/schemas.ts";
import { escapeSlackMrkdwn as escapeSlackMarkdown } from "../shared/escape-slack-mrkdwn.ts";
import type { WorkspaceDirectoryLedgerMessage } from "./change-ledger-contracts.ts";
import type {
  IWorkspaceDirectoryChangeLedger,
  WorkspaceDirectoryChangeLedgerHandle,
  WorkspaceDirectoryTerminalReceipt,
} from "./change-ledger.ts";
import {
  type WorkspaceDirectoryAuthorizedActionId,
  WorkspaceDirectoryAuthorizedActionIdSchema,
  type WorkspaceDirectoryBranchId,
  WorkspaceDirectoryChangeDetailsSchema,
  type WorkspaceDirectoryPlan,
  type WorkspaceDirectoryWorkflowParams,
  type WorkspaceDirectoryWorkflowResult,
} from "./contracts.ts";
import { workspaceDirectoryOperationDiagnostics } from "./workspace-directory-operation-diagnostics.ts";
import type { WorkspaceDirectorySlackManifestItem } from "./workspace-directory-slack-manifest.ts";
import { workspaceDirectorySlackManifest } from "./workspace-directory-slack-manifest.ts";
import { zeroChangePlanMessage } from "./zero-change-plan-message.ts";

const SUMMARY_CHANGE_KEY_SUFFIX = "plan-apply-summary";
const SUMMARY_HISTORY_SKEW_MS = 60_000;
const TERMINAL_VERIFIER_UNAVAILABLE =
  "workspace_directory_terminal_verifier_unavailable";
const TERMINAL_REPAIR_UNAVAILABLE =
  "workspace_directory_terminal_repair_unavailable";
const MAX_DETAIL_SECTION_BLOCKS = 40;
const SECTION_TEXT_LIMIT = 2_900;
const GRAPHEME_SEGMENTER = new Intl.Segmenter("en-US", {
  granularity: "grapheme",
});

interface PlainTextObject {
  readonly emoji?: boolean;
  readonly text: string;
  readonly type: "plain_text";
}

interface MarkdownTextObject {
  readonly text: string;
  readonly type: "mrkdwn";
  readonly verbatim: true;
}

interface RawTextObject {
  readonly text: string;
  readonly type: "raw_text";
}

type SummaryBlock =
  | {
      readonly "block_id": string;
      readonly "column_settings": readonly { readonly "is_wrapped": boolean }[];
      readonly rows: readonly (readonly RawTextObject[])[];
      readonly type: "table";
    }
  | {
      readonly "block_id": string;
      readonly elements: readonly PlainTextObject[];
      readonly type: "context";
    }
  | {
      readonly "block_id": string;
      readonly text: MarkdownTextObject | PlainTextObject;
      readonly type: "section";
    }
  | {
      readonly "block_id": string;
      readonly text: PlainTextObject;
      readonly type: "header";
    }
  | { readonly "block_id": string; readonly type: "divider" };

export interface WorkspaceDirectoryPlanAnnouncement {
  readonly authorizedActionIds: readonly WorkspaceDirectoryAuthorizedActionId[];
  readonly generatedAt: string;
  readonly plan: WorkspaceDirectoryPlan;
  readonly planHash: string;
  readonly requestedBy: string;
}

export interface WorkspaceDirectoryPlanAnnouncer {
  announce(
    input: WorkspaceDirectoryPlanAnnouncement,
  ): Promise<WorkspaceDirectoryChangeLedgerHandle>;
}

export interface WorkspaceDirectorySignedPlanAnnouncer {
  announceSignedPlan(
    signedPlan: SignedOperationPlan,
  ): Promise<WorkspaceDirectoryChangeLedgerHandle>;
}

export interface WorkspaceDirectoryApplyReporter {
  complete(
    handle: WorkspaceDirectoryChangeLedgerHandle,
    params: WorkspaceDirectoryWorkflowParams,
    result: WorkspaceDirectoryWorkflowResult,
  ): Promise<void>;
  fail(
    handle: WorkspaceDirectoryChangeLedgerHandle,
    params: WorkspaceDirectoryWorkflowParams,
  ): Promise<void>;
  recover(
    input: WorkspaceDirectoryPlanAnnouncement,
  ): Promise<WorkspaceDirectoryChangeLedgerHandle>;
  repairCompleted?(
    params: WorkspaceDirectoryWorkflowParams,
    result: WorkspaceDirectoryWorkflowResult,
    handle: WorkspaceDirectoryChangeLedgerHandle,
  ): Promise<WorkspaceDirectoryTerminalReceipt>;
  repairFailed?(
    params: WorkspaceDirectoryWorkflowParams,
    handle: WorkspaceDirectoryChangeLedgerHandle,
  ): Promise<WorkspaceDirectoryTerminalReceipt>;
  verifyCompleted?(
    params: WorkspaceDirectoryWorkflowParams,
    result: WorkspaceDirectoryWorkflowResult,
    handle: WorkspaceDirectoryChangeLedgerHandle,
  ): Promise<WorkspaceDirectoryTerminalReceipt>;
  verifyFailed?(
    params: WorkspaceDirectoryWorkflowParams,
    handle: WorkspaceDirectoryChangeLedgerHandle,
  ): Promise<WorkspaceDirectoryTerminalReceipt>;
}

export class WorkspaceDirectoryPlanApplyLedger
  implements
    WorkspaceDirectoryApplyReporter,
    WorkspaceDirectoryPlanAnnouncer,
    WorkspaceDirectorySignedPlanAnnouncer
{
  readonly #ledger: IWorkspaceDirectoryChangeLedger;

  constructor(ledger: IWorkspaceDirectoryChangeLedger) {
    this.#ledger = ledger;
  }

  announceSignedPlan(
    signedPlan: SignedOperationPlan,
  ): Promise<WorkspaceDirectoryChangeLedgerHandle> {
    if (signedPlan.plan.changes.length !== 0)
      return this.announce(workspaceDirectoryPlanAnnouncement(signedPlan));
    return this.#ledger.preannounce({
      changeKey: summaryChangeKey(
        signedPlan.plan.planHash,
        signedPlan.plan.generatedAt,
      ),
      historyOldest: summaryHistoryOldest(signedPlan.plan.generatedAt),
      ...zeroChangePlanMessage(signedPlan),
    });
  }

  announce(
    input: WorkspaceDirectoryPlanAnnouncement,
  ): Promise<WorkspaceDirectoryChangeLedgerHandle> {
    return this.#ledger.preannounce({
      changeKey: summaryChangeKey(input.planHash, input.generatedAt),
      historyOldest: summaryHistoryOldest(input.generatedAt),
      ...planMessage(input),
    });
  }

  async recover(
    input: WorkspaceDirectoryPlanAnnouncement,
  ): Promise<WorkspaceDirectoryChangeLedgerHandle> {
    if (this.#ledger.recover === undefined)
      throw new Error("workspace_directory_plan_ledger_recovery_unavailable");
    const recovered = await this.#ledger.recover({
      changeKey: summaryChangeKey(input.planHash, input.generatedAt),
      historyOldest: summaryHistoryOldest(input.generatedAt),
      ...planMessage(input),
    });
    if (recovered === null)
      throw new Error("workspace_directory_plan_announcement_missing");
    return recovered;
  }

  complete(
    handle: WorkspaceDirectoryChangeLedgerHandle,
    params: WorkspaceDirectoryWorkflowParams,
    result: WorkspaceDirectoryWorkflowResult,
  ): Promise<void> {
    return this.#ledger.complete(handle, applyMessage(params, result));
  }

  fail(
    handle: WorkspaceDirectoryChangeLedgerHandle,
    params: WorkspaceDirectoryWorkflowParams,
  ): Promise<void> {
    return this.#ledger.fail(handle, failedMessage(params));
  }

  verifyCompleted(
    params: WorkspaceDirectoryWorkflowParams,
    result: WorkspaceDirectoryWorkflowResult,
    handle: WorkspaceDirectoryChangeLedgerHandle,
  ): Promise<WorkspaceDirectoryTerminalReceipt> {
    assertSummaryHandle(params, handle);
    if (this.#ledger.verifyTerminal === undefined) {
      throw new Error(TERMINAL_VERIFIER_UNAVAILABLE);
    }
    return this.#ledger.verifyTerminal(
      handle,
      "completed",
      applyMessage(params, result),
    );
  }

  repairCompleted(
    params: WorkspaceDirectoryWorkflowParams,
    result: WorkspaceDirectoryWorkflowResult,
    handle: WorkspaceDirectoryChangeLedgerHandle,
  ): Promise<WorkspaceDirectoryTerminalReceipt> {
    assertSummaryHandle(params, handle);
    if (this.#ledger.repairCompleted === undefined) {
      throw new Error(TERMINAL_REPAIR_UNAVAILABLE);
    }
    const announcement = planMessage({
      authorizedActionIds: params.authorizedActionIds,
      generatedAt: params.planGeneratedAt,
      plan: params.plan,
      planHash: params.planHash,
      requestedBy: params.requestedBy,
    });
    return this.#ledger.repairCompleted(
      handle,
      announcement,
      applyMessage(params, result),
    );
  }

  repairFailed(
    params: WorkspaceDirectoryWorkflowParams,
    handle: WorkspaceDirectoryChangeLedgerHandle,
  ): Promise<WorkspaceDirectoryTerminalReceipt> {
    assertSummaryHandle(params, handle);
    if (this.#ledger.repairFailed === undefined)
      throw new Error(TERMINAL_REPAIR_UNAVAILABLE);
    return this.#ledger.repairFailed(
      handle,
      planMessage({
        authorizedActionIds: params.authorizedActionIds,
        generatedAt: params.planGeneratedAt,
        plan: params.plan,
        planHash: params.planHash,
        requestedBy: params.requestedBy,
      }),
      failedMessage(params),
    );
  }

  verifyFailed(
    params: WorkspaceDirectoryWorkflowParams,
    handle: WorkspaceDirectoryChangeLedgerHandle,
  ): Promise<WorkspaceDirectoryTerminalReceipt> {
    assertSummaryHandle(params, handle);
    if (this.#ledger.verifyTerminal === undefined) {
      throw new Error(TERMINAL_VERIFIER_UNAVAILABLE);
    }
    return this.#ledger.verifyTerminal(handle, "failed", failedMessage(params));
  }
}

function assertSummaryHandle(
  params: WorkspaceDirectoryWorkflowParams,
  handle: WorkspaceDirectoryChangeLedgerHandle,
): void {
  if (
    handle.changeKey !==
    summaryChangeKey(params.planHash, params.planGeneratedAt)
  ) {
    throw new Error("workspace_directory_terminal_summary_handle_mismatch");
  }
}

export function workspaceDirectoryPlanAnnouncement(
  signedPlan: SignedOperationPlan,
): WorkspaceDirectoryPlanAnnouncement {
  const plans = signedPlan.plan.changes.flatMap(({ details }) => {
    const parsed = WorkspaceDirectoryChangeDetailsSchema.safeParse(details);
    return parsed.success && "plan" in parsed.data ? [parsed.data.plan] : [];
  });
  const plan = plans[0];
  if (plan === undefined)
    throw new Error("workspace_directory_plan_announcement_missing_plan");
  if (plans.some((candidate) => !dequal(candidate, plan)))
    throw new Error("workspace_directory_plan_announcement_mismatched_plans");
  return {
    authorizedActionIds: signedPlan.plan.changes.map(({ actionId }) =>
      WorkspaceDirectoryAuthorizedActionIdSchema.parse(actionId),
    ),
    generatedAt: signedPlan.plan.generatedAt,
    plan,
    planHash: signedPlan.plan.planHash,
    requestedBy: signedPlan.plan.actor.id,
  };
}

function planMessage(
  input: WorkspaceDirectoryPlanAnnouncement,
): WorkspaceDirectoryLedgerMessage {
  const manifest = workspaceDirectorySlackManifest({
    authorizedActionIds: [...input.authorizedActionIds],
    plan: input.plan,
    planGeneratedAt: input.generatedAt,
    planHash: input.planHash,
    requestedBy: input.requestedBy,
  });
  const selectedActionIds = new Set(input.authorizedActionIds);
  const diagnostics = diagnosticCounts(input.plan, selectedActionIds);
  assertEveryApplySummaryFits(manifest);
  const blocks: SummaryBlock[] = [
    header("plan-title", "Workspace Directory · PLAN"),
    markdownSection(
      "plan-status",
      planStatus(input.plan, manifest, diagnostics, selectedActionIds),
    ),
    divider("plan-branch-divider"),
    branchTable(
      input.plan,
      manifest.selected,
      manifest.deferred,
      manifest.auditOnly,
      selectedActionIds,
    ),
    ...detailBlocks(
      "plan",
      groupedManifestLines(
        manifest,
        "plan",
        undefined,
        diagnostics.blockers > 0,
      ),
    ),
    context(
      "plan-context",
      `Plan: ${input.planHash} · Requested by: ${singleLine(input.requestedBy)} · No provider writes started`,
    ),
  ];
  let fallbackStatus = "ready for review";
  if (diagnostics.blockers > 0) fallbackStatus = "blocked";
  else if (manifest.selected.length === 0) fallbackStatus = "review only";
  return {
    blocks,
    text: `Workspace Directory PLAN ${input.planHash.slice(0, 12)} · ${fallbackStatus} · selected ${String(manifest.selected.length)}${fallbackActionKind(manifest.selected, "selected")} · deferred ${String(manifest.deferred.length)} · audit-only ${String(manifest.auditOnly.length)} · selected/global blockers ${String(diagnostics.blockers)} · visibility-only blockers ${String(diagnostics.visibilityBlockers)} · warnings ${String(diagnostics.warnings)} · no provider writes started`,
  };
}

function applyMessage(
  params: WorkspaceDirectoryWorkflowParams,
  result: WorkspaceDirectoryWorkflowResult,
): WorkspaceDirectoryLedgerMessage {
  assertMatchingResult(params, result);
  const manifest = workspaceDirectorySlackManifest(params);
  const stateByBranch = new Map(
    result.branches.map(({ branchId, state }) => [branchId, state]),
  );
  const appliedItems = manifest.selected.filter(
    ({ branchId }) => stateByBranch.get(branchId) === "applied",
  );
  const notAppliedItems = manifest.selected.filter(
    (item) => !appliedItems.includes(item),
  );
  const applied = appliedItems.length;
  const notApplied = notAppliedItems.length;
  const blocks: SummaryBlock[] = [
    header(
      "apply-title",
      `Workspace Directory · ${notApplied === 0 ? "APPLY VERIFIED" : "APPLY PARTIAL"}`,
    ),
    markdownSection(
      "apply-status",
      applyStatus(applied, notApplied, manifest, result.executionId),
    ),
    divider("apply-branch-divider"),
    applyBranchTable(params.plan, manifest.selected, stateByBranch),
    ...detailBlocks(
      "apply",
      groupedManifestLines(manifest, "apply", stateByBranch),
    ),
    context(
      "apply-context",
      `Plan: ${params.planHash} · Requested by: ${singleLine(params.requestedBy)} · Exact records remain in this channel`,
    ),
  ];
  return {
    blocks,
    text: `Workspace Directory ${notApplied === 0 ? "APPLY VERIFIED" : "APPLY PARTIAL"} ${params.planHash.slice(0, 12)} · applied ${String(applied)}${fallbackActionKind(appliedItems, "applied")} · authorized but not applied ${String(notApplied)}${fallbackActionKind(notAppliedItems, "not applied")} · deferred ${String(manifest.deferred.length)} · audit-only ${String(manifest.auditOnly.length)}`,
  };
}

function failedMessage(
  params: WorkspaceDirectoryWorkflowParams,
): WorkspaceDirectoryLedgerMessage {
  return {
    blocks: [
      header("failed-title", "Workspace Directory · APPLY FAILED"),
      section(
        "failed-status",
        "Apply did not reach a fully verified terminal state. Provider and ledger state require audit before retry.",
      ),
      divider("failed-divider"),
      section(
        "failed-details",
        "No failure details are included here to avoid leaking credentials or provider responses.",
      ),
      context(
        "failed-context",
        `Plan ${params.planHash} · Requested by ${singleLine(params.requestedBy)}`,
      ),
    ] satisfies SummaryBlock[],
    text: `Workspace Directory APPLY FAILED ${params.planHash.slice(0, 12)} · audit required before retry`,
  };
}

function planStatus(
  plan: WorkspaceDirectoryPlan,
  manifest: SlackManifest,
  diagnostics: PlanDiagnosticCounts,
  selectedActionIds: ReadonlySet<string>,
): string {
  const totals = [
    "*Plan totals*",
    `• Selected: ${String(manifest.selected.length)}${diagnostics.blockers > 0 ? " (blocked)" : ""}`,
    `• Deferred: ${String(manifest.deferred.length)} (review only; will not run)`,
    `• Audit findings: ${String(manifest.auditOnly.length)} (visibility only; never written)`,
    `• Unselected action / audit blockers: ${String(diagnostics.visibilityBlockers)} (visibility only; do not block selected changes)`,
    `• Warnings: ${String(diagnostics.warnings)} (visibility only)`,
  ].join("\n");
  if (diagnostics.blockers > 0) {
    const blockerRows = plan.branches.flatMap((branch) => {
      const count = diagnosticCounts(
        { branches: [branch] },
        selectedActionIds,
      ).blockers;
      return count === 0
        ? []
        : `• ${branchLabel(branch.branchId)}: ${String(count)}`;
    });
    return [
      "*:no_entry: Blocked — no changes will run*",
      `${countNoun(diagnostics.blockers, "blocker")} must be resolved before this plan can be approved.`,
      totals,
      "*Blockers by integration*",
      ...blockerRows,
      "*Next step*",
      "Resolve the blockers, generate a fresh PLAN, then approve its exact selected changes. No provider writes have started.",
    ].join("\n");
  }
  if (manifest.selected.length === 0) {
    return [
      "*:information_source: Review only — nothing selected to apply*",
      totals,
      "*Next step*",
      "Review the deferred changes below. Generate a fresh PLAN with exact selections when they are ready to run. No provider writes have started.",
    ].join("\n");
  }
  return [
    "*:white_check_mark: Ready for approval*",
    totals,
    "*Next step*",
    "Review every selected change below, then approve this exact plan. Deferred and audit-only items will not run. No provider writes have started.",
  ].join("\n");
}

function countNoun(count: number, singular: string): string {
  return `${String(count)} ${singular}${count === 1 ? "" : "s"}`;
}

function applyStatus(
  applied: number,
  notApplied: number,
  manifest: SlackManifest,
  executionId: string,
): string {
  const status =
    notApplied === 0
      ? "*:white_check_mark: Apply verified — terminal readback complete*"
      : "*:warning: Apply partial — review actions not applied*";
  return [
    status,
    "*Outcome totals*",
    `• Applied and verified: ${String(applied)}`,
    `• Authorized but not applied: ${String(notApplied)}`,
    `• Deferred: ${String(manifest.deferred.length)} (did not run)`,
    `• Audit findings: ${String(manifest.auditOnly.length)} (visibility only)`,
    `• Execution: ${executionId.slice(0, 12)}`,
  ].join("\n");
}

function branchTable(
  plan: WorkspaceDirectoryPlan,
  selected: ReturnType<typeof workspaceDirectorySlackManifest>["selected"],
  deferred: ReturnType<typeof workspaceDirectorySlackManifest>["deferred"],
  auditOnly: ReturnType<typeof workspaceDirectorySlackManifest>["auditOnly"],
  selectedActionIds: ReadonlySet<string>,
): SummaryBlock {
  const rows = plan.branches.flatMap((branch) => {
    const proposedCount = selected.filter(
      ({ branchId }) => branchId === branch.branchId,
    ).length;
    const deferredCount = deferred.filter(
      ({ branchId }) => branchId === branch.branchId,
    ).length;
    const auditOnlyCount = auditOnly.filter(
      ({ branchId }) => branchId === branch.branchId,
    ).length;
    const diagnostics = diagnosticCounts(
      { branches: [branch] },
      selectedActionIds,
    );
    if (
      proposedCount +
        deferredCount +
        auditOnlyCount +
        diagnostics.blockers +
        diagnostics.visibilityBlockers +
        diagnostics.warnings ===
      0
    )
      return [];
    return [
      [
        rawText(branchLabel(branch.branchId)),
        rawText(
          compactCounts([
            [proposedCount, "apply"],
            [deferredCount, "deferred"],
            [auditOnlyCount, "audit"],
          ]),
        ),
        rawText(
          compactCounts([
            [diagnostics.blockers, "selected/global blockers"],
            [
              diagnostics.visibilityBlockers,
              "unselected action / audit blockers (visibility only)",
            ],
            [diagnostics.warnings, "warnings"],
          ]),
        ),
      ],
    ];
  });
  return table("plan-branches", ["Integration", "Plan", "Diagnostics"], rows);
}

function applyBranchTable(
  plan: WorkspaceDirectoryPlan,
  selected: ReturnType<typeof workspaceDirectorySlackManifest>["selected"],
  stateByBranch: ReadonlyMap<
    WorkspaceDirectoryBranchId,
    WorkspaceDirectoryWorkflowResult["branches"][number]["state"]
  >,
): SummaryBlock {
  const rows = plan.branches.flatMap((branch) => {
    const selectedCount = selected.filter(
      ({ branchId }) => branchId === branch.branchId,
    ).length;
    if (selectedCount === 0) return [];
    return [
      [
        rawText(branchLabel(branch.branchId)),
        rawText(String(selectedCount)),
        rawText(stateLabel(stateByBranch.get(branch.branchId))),
      ],
    ];
  });
  return table(
    "apply-branches",
    ["Integration", "Authorized", "Outcome"],
    rows,
  );
}

interface PlanDiagnosticCounts {
  readonly blockers: number;
  readonly visibilityBlockers: number;
  readonly warnings: number;
}

function diagnosticCounts(
  plan: {
    readonly branches: readonly WorkspaceDirectoryPlan["branches"][number][];
  },
  selectedActionIds: ReadonlySet<string>,
): PlanDiagnosticCounts {
  const diagnostics = workspaceDirectoryOperationDiagnostics(
    plan,
    selectedActionIds,
  );
  const blockers = diagnostics.filter(
    ({ severity }) => severity === "blocker",
  ).length;
  const allDiagnostics = plan.branches.flatMap((branch) => branch.diagnostics);
  const allBlockers = allDiagnostics.filter(
    ({ severity }) => severity === "blocker",
  ).length;
  return {
    blockers,
    visibilityBlockers: allBlockers - blockers,
    warnings: allDiagnostics.filter(({ severity }) => severity === "warning")
      .length,
  };
}

function compactCounts(counts: readonly (readonly [number, string])[]): string {
  const nonzero = counts.filter(([count]) => count > 0);
  return nonzero.length === 0
    ? "—"
    : nonzero.map(([count, label]) => `${String(count)} ${label}`).join(" · ");
}

function assertMatchingResult(
  params: WorkspaceDirectoryWorkflowParams,
  result: WorkspaceDirectoryWorkflowResult,
): void {
  if (params.planHash !== result.planHash)
    throw new Error("workspace_directory_plan_apply_result_hash_mismatch");
  if (
    !dequal(
      [...params.authorizedActionIds].toSorted(
        (sortLeft, sortRight) =>
          Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
      ),
      [...result.authorizedActionIds].toSorted(
        (sortLeft, sortRight) =>
          Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
      ),
    )
  )
    throw new Error(
      "workspace_directory_plan_apply_result_authorization_mismatch",
    );
}

function summaryChangeKey(planHash: string, generatedAt: string): string {
  return `${planHash}:${SUMMARY_CHANGE_KEY_SUFFIX}:${String(Date.parse(generatedAt))}`;
}

function summaryHistoryOldest(generatedAt: string): string {
  const generatedAtMs = Date.parse(generatedAt);
  if (!Number.isFinite(generatedAtMs)) {
    throw new TypeError("workspace_directory_plan_generated_at_invalid");
  }
  return `${String(Math.max(0, Math.floor((generatedAtMs - SUMMARY_HISTORY_SKEW_MS) / 1_000)))}.000000`;
}

function header(blockId: string, text: string): SummaryBlock {
  return { "block_id": blockId, text: plainText(text), type: "header" };
}

function section(blockId: string, text: string): SummaryBlock {
  return { "block_id": blockId, text: plainText(text), type: "section" };
}

function markdownSection(blockId: string, text: string): SummaryBlock {
  return {
    "block_id": blockId,
    text: { text, type: "mrkdwn", verbatim: true },
    type: "section",
  };
}

function divider(blockId: string): SummaryBlock {
  return { "block_id": blockId, type: "divider" };
}

function table(
  blockId: string,
  headings: readonly string[],
  rows: readonly (readonly RawTextObject[])[],
): SummaryBlock {
  return {
    "block_id": blockId,
    "column_settings": headings.map(() => ({ "is_wrapped": true })),
    rows: [headings.map(rawText), ...rows],
    type: "table",
  };
}

function rawText(text: string): RawTextObject {
  return { text, type: "raw_text" };
}

type SlackManifest = ReturnType<typeof workspaceDirectorySlackManifest>;

function groupedManifestLines(
  manifest: SlackManifest,
  phase: "apply" | "plan",
  stateByBranch?: ReadonlyMap<
    WorkspaceDirectoryBranchId,
    WorkspaceDirectoryWorkflowResult["branches"][number]["state"]
  >,
  blocked = false,
): string[] {
  const applied =
    phase === "apply"
      ? manifest.selected.filter(
          ({ branchId }) => stateByBranch?.get(branchId) === "applied",
        )
      : manifest.selected;
  const notApplied = manifest.selected.filter(
    (item) => !applied.includes(item),
  );
  let selectedLines: string[] = [];
  if (phase === "plan") {
    selectedLines = groupedDispositionLines(
      blocked
        ? "SELECTED BUT BLOCKED — will not run"
        : "READY TO APPLY — requires exact approval",
      applied,
    );
  } else if (applied.length > 0) {
    selectedLines = groupedDispositionLines("APPLIED AND VERIFIED", applied);
  }
  return [
    ...selectedLines,
    ...(phase === "apply" && notApplied.length > 0
      ? groupedDispositionLines("AUTHORIZED BUT NOT APPLIED", notApplied)
      : []),
    ...groupedDispositionLines("DEFERRED — will not run", manifest.deferred),
  ];
}

function assertEveryApplySummaryFits(manifest: SlackManifest): void {
  const selectedBranches = manifest.selected
    .map(({ branchId }) => branchId)
    .filter(
      (branchId, index, branches) => branches.indexOf(branchId) === index,
    );
  const partitionCount = 2 ** selectedBranches.length;
  for (let partition = 0; partition < partitionCount; partition += 1) {
    const states = new Map<
      WorkspaceDirectoryBranchId,
      WorkspaceDirectoryWorkflowResult["branches"][number]["state"]
    >();
    for (const [index, branchId] of selectedBranches.entries()) {
      states.set(
        branchId,
        (partition & (1 << index)) === 0 ? "skipped" : "applied",
      );
    }
    detailBlocks("apply", groupedManifestLines(manifest, "apply", states));
  }
}

function groupedDispositionLines(
  heading: string,
  items: readonly WorkspaceDirectorySlackManifestItem[],
): string[] {
  if (items.length === 0) return [];
  const renameItems = items.filter(({ changeKey }) =>
    changeKey.startsWith("slack-channel-rename:"),
  );
  const directAdditionItems = items.filter(({ changeKey }) =>
    changeKey.startsWith("slack-direct-channel-add:"),
  );
  const directRemovalItems = items.filter(
    ({ changeKey }) =>
      changeKey.startsWith("slack-direct-channel-remove:") ||
      changeKey.startsWith("slack-provenance-channel-remove:"),
  );
  const groupAdditionItems = items.filter(({ changeKey }) =>
    changeKey.startsWith("slack-group-add:"),
  );
  const groupRemovalItems = items.filter(({ changeKey }) =>
    changeKey.startsWith("slack-group-remove:"),
  );
  const categorizedKeys = new Set(
    [
      ...renameItems,
      ...directAdditionItems,
      ...directRemovalItems,
      ...groupAdditionItems,
      ...groupRemovalItems,
    ].map(({ changeKey }) => changeKey),
  );
  const otherItems = items.filter(
    ({ changeKey }) => !categorizedKeys.has(changeKey),
  );
  return [
    `${heading} · ${String(items.length)}`,
    ...renameSummaryLines(renameItems),
    ...channelMembershipSummaryLines(
      "Direct channel additions",
      directAdditionItems,
      "→",
    ),
    ...channelMembershipSummaryLines(
      "Direct channel removals",
      directRemovalItems,
      "←",
    ),
    ...userGroupSummaryLines(groupAdditionItems, groupRemovalItems),
    ...otherItems.map(({ text }) => conciseActionText(text)),
  ];
}

function renameSummaryLines(
  items: readonly WorkspaceDirectorySlackManifestItem[],
): string[] {
  if (items.length === 0) return [];
  const changes = items.map(({ text }) => lastActionSegment(text));
  return [`Channel renames · ${String(items.length)}: ${changes.join("; ")}`];
}

function channelMembershipSummaryLines(
  label: string,
  items: readonly WorkspaceDirectorySlackManifestItem[],
  direction: "←" | "→",
): string[] {
  if (items.length === 0) return [];
  const byChannel = new Map<string, string[]>();
  for (const { text } of items) {
    const detail = lastActionSegment(text);
    const separator = ` ${direction} #`;
    const separatorIndex = detail.lastIndexOf(separator);
    const identity =
      separatorIndex < 0 ? detail : detail.slice(0, separatorIndex);
    const channel =
      separatorIndex < 0
        ? "channel unavailable"
        : `#${detail.slice(separatorIndex + separator.length)}`;
    const identities = byChannel.get(channel) ?? [];
    identities.push(identity);
    byChannel.set(channel, identities);
  }
  return [
    `${label} · ${String(items.length)}`,
    ...byChannel
      .keys()
      .toArray()
      .toSorted((left, right) => left.localeCompare(right, "en-US"))
      .map((channel) => {
        const identities = byChannel.get(channel) ?? [];
        return `${channel} — ${identities.toSorted((left, right) => left.localeCompare(right, "en-US")).join(", ")}`;
      }),
  ];
}

function userGroupSummaryLines(
  additions: readonly WorkspaceDirectorySlackManifestItem[],
  removals: readonly WorkspaceDirectorySlackManifestItem[],
): string[] {
  if (additions.length + removals.length === 0) return [];
  const changes = new Map<
    string,
    { additions: string[]; identity: string; removals: string[] }
  >();
  addUserGroupChanges(changes, additions, "additions", "→");
  addUserGroupChanges(changes, removals, "removals", "←");
  return [
    `User-group membership changes · ${String(additions.length + removals.length)}`,
    ...changes
      .keys()
      .toArray()
      .toSorted((left, right) => left.localeCompare(right, "en-US"))
      .map((identityKey) => {
        const change = changes.get(identityKey);
        if (change === undefined)
          return "Identity unavailable — membership change unavailable";
        const actions: string[] = [];
        if (change.additions.length > 0)
          actions.push(
            `add to ${change.additions.toSorted((sortLeft, sortRight) => Number(sortLeft > sortRight) - Number(sortLeft < sortRight)).join(", ")}`,
          );
        if (change.removals.length > 0)
          actions.push(
            `remove from ${change.removals.toSorted((sortLeft, sortRight) => Number(sortLeft > sortRight) - Number(sortLeft < sortRight)).join(", ")}`,
          );
        return `${change.identity} — ${actions.join("; ")}`;
      }),
  ];
}

function addUserGroupChanges(
  changes: Map<
    string,
    { additions: string[]; identity: string; removals: string[] }
  >,
  items: readonly WorkspaceDirectorySlackManifestItem[],
  collection: "additions" | "removals",
  direction: "←" | "→",
): void {
  for (const { changeKey, text } of items) {
    const detail = lastActionSegment(text);
    const separator = ` ${direction} @`;
    const separatorIndex = detail.lastIndexOf(separator);
    const identity =
      separatorIndex < 0 ? detail : detail.slice(0, separatorIndex);
    const group =
      separatorIndex < 0
        ? "@group-unavailable"
        : `@${detail.slice(separatorIndex + separator.length)}`;
    const identityKey =
      identity === "Identity unavailable"
        ? `${identity}:${changeKey}`
        : identity;
    const entry = changes.get(identityKey) ?? {
      additions: [],
      identity,
      removals: [],
    };
    entry[collection].push(group);
    changes.set(identityKey, entry);
  }
}

function lastActionSegment(text: string): string {
  return text.split(" · ").at(-1) ?? text;
}

function conciseActionText(text: string): string {
  return text.replace("Workspace sync planned · ", "");
}

function fallbackActionKind(
  items: readonly WorkspaceDirectorySlackManifestItem[],
  disposition: "applied" | "not applied" | "selected",
): string {
  if (items.length !== 1) return "";
  const item = items[0];
  if (item === undefined) return "";
  return ` · ${disposition}: ${branchLabel(item.branchId)} change`;
}

function detailBlocks(
  phase: "apply" | "plan",
  rawLines: readonly string[],
): SummaryBlock[] {
  if (rawLines.length === 0) return [];
  const visible = rawLines.flatMap((line) => splitDetailLine(singleLine(line)));
  const packedSections: string[] = [];
  let packed = "";
  for (const [index, line] of visible.entries()) {
    const formatted = detailLine(line, index);
    const candidate =
      packed.length === 0 ? formatted : `${packed}\n${formatted}`;
    if (candidate.length <= SECTION_TEXT_LIMIT) {
      packed = candidate;
    } else {
      if (packed.length === 0) {
        throw new Error(
          "workspace_directory_plan_detail_line_exceeds_slack_limit",
        );
      }
      packedSections.push(packed);
      packed = formatted;
    }
  }
  if (packed.length > 0) packedSections.push(packed);
  if (packedSections.length > MAX_DETAIL_SECTION_BLOCKS) {
    throw new Error("workspace_directory_plan_summary_exceeds_slack_limits");
  }
  return [
    divider(`${phase}-detail-divider`),
    section(`${phase}-detail-heading`, "Change details"),
    ...packedSections.map((text, index) =>
      markdownSection(`${phase}-detail-${String(index + 1)}`, text),
    ),
  ];
}

function detailLine(line: string, index: number): string {
  const escaped = escapeSlackMarkdown(line);
  if (
    index === 0 ||
    /^[A-Z][A-Z ]+ —/u.test(line) ||
    / · \d+(?::|$)/u.test(line)
  )
    return `*${escaped}*`;
  return `• ${escaped}`;
}

function splitDetailLine(line: string): string[] {
  const graphemes = graphemeSegments(line);
  if (line.length <= 500) return [line];
  const chunks: string[] = [];
  let chunkLength = 0;
  let chunkParts: string[] = [];
  for (const grapheme of graphemes) {
    if (grapheme.length > SECTION_TEXT_LIMIT - 20) {
      throw new Error(
        "workspace_directory_plan_detail_grapheme_exceeds_slack_limit",
      );
    }
    if (chunkLength > 0 && chunkLength + grapheme.length > 500) {
      chunks.push(chunkParts.join(""));
      chunkLength = 0;
      chunkParts = [];
    }
    chunkParts.push(grapheme);
    chunkLength += grapheme.length;
  }
  if (chunkLength > 0) chunks.push(chunkParts.join(""));
  return chunks.map((value, index) =>
    index === 0 ? value : `CONTINUED · ${value}`,
  );
}

function graphemeSegments(text: string): string[] {
  return Array.from(GRAPHEME_SEGMENTER.segment(text), ({ segment }) => segment);
}

function context(blockId: string, text: string): SummaryBlock {
  return { "block_id": blockId, elements: [plainText(text)], type: "context" };
}

function plainText(text: string): PlainTextObject {
  // Slack rewrites native emoji to colon aliases when `emoji` is enabled
  // (for example, `⛔` becomes `:no_entry:`). These ledger messages are
  // attested by exact Block Kit readback, so opt out of that lossy rewrite.
  return { emoji: false, text, type: "plain_text" };
}

function singleLine(text: string): string {
  return text.replaceAll(/\s+/gu, " ").trim();
}

function branchLabel(
  branchId: WorkspaceDirectoryPlan["branches"][number]["branchId"],
): string {
  const labels: Partial<Record<WorkspaceDirectoryBranchId, string>> = {
    "github-access": "GitHub Access",
    "pagerduty-teams": "PagerDuty Teams",
    "slack-groups-channels": "Slack Groups & Channels",
    "trycomp-people": "TryComp People",
  };
  const label = labels[branchId];
  if (label !== undefined) return label;
  return branchId
    .split("-")
    .map((part) => `${part.slice(0, 1).toUpperCase()}${part.slice(1)}`)
    .join(" ");
}

function stateLabel(
  state:
    | undefined
    | WorkspaceDirectoryWorkflowResult["branches"][number]["state"],
): string {
  return state === undefined ? "UNREPORTED" : state.toUpperCase();
}
