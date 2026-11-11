import type { WorkspaceDirectoryLedgerMessage } from "./change-ledger-contracts.ts";
import type { IWorkspaceDirectoryChangeLedger } from "./change-ledger.ts";
import {
  type WorkspaceScheduleReceipt,
  WorkspaceScheduleReceiptSchema,
  type WorkspaceScheduleTick,
  WorkspaceScheduleTickSchema,
} from "./schedule-health-contracts.ts";

type TerminalTick = Extract<WorkspaceScheduleTick, { phase: "terminal" }>;

function terminalMessage(tick: TerminalTick): WorkspaceDirectoryLedgerMessage {
  const presentation = terminalPresentation(tick);
  const title = `Workspace Directory · ${presentation.title}`;
  const summary = presentation.summary;
  const details = [
    summary,
    `Plan: ${tick.planHash?.slice(0, 12) ?? "not captured"} · Mode: ${tick.mode ?? "not captured"} · Scheduled: ${new Date(tick.scheduledAtMs).toISOString()}`,
    `Deployment: ${tick.deployment.id} · Revision: ${tick.deployment.revision.slice(0, 12)}`,
  ].join("\n");
  const fallbackDetails = [
    summary,
    `Outcome: ${tick.outcome}`,
    `Tick: ${tick.tickId}`,
    `Plan: ${tick.planHash ?? "not captured"}`,
    `Mode: ${tick.mode ?? "not captured"}`,
    `Scheduled: ${new Date(tick.scheduledAtMs).toISOString()}`,
    `Deployment: ${tick.deployment.id}`,
    `Revision: ${tick.deployment.revision}`,
    `Deployed: ${tick.deployment.timestamp}`,
  ].join("\n");
  return {
    blocks: [
      {
        "block_id": "scheduled-terminal-title",
        text: { emoji: true, text: title, type: "plain_text" },
        type: "header",
      },
      {
        "block_id": "scheduled-terminal-details",
        text: { emoji: true, text: details, type: "plain_text" },
        type: "section",
      },
    ],
    text: `${title}\n${fallbackDetails}`
      .replaceAll("\n", " ")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;"),
  };
}

function terminalPresentation(tick: TerminalTick): {
  summary: string;
  title: string;
} {
  switch (tick.outcome) {
    case "applied":
      return {
        summary: "Provider changes were applied and verified.",
        title: "Scheduled apply verified",
      };
    case "audit-only":
      return {
        summary:
          "Read-only audit completed. No provider writes were attempted.",
        title: "Scheduled audit",
      };
    case "blocked":
      return {
        summary: "Safety checks blocked the run before provider execution.",
        title: "Scheduled run blocked",
      };
    case "failed":
      return tick.workflowId === null
        ? {
            summary:
              "Scheduling or planning failed before a workflow launched.",
            title: "Scheduled run failed",
          }
        : {
            summary: "Workflow ended before provider execution began.",
            title: "Scheduled workflow failed",
          };
    case "no-op":
      return {
        summary: "No changes were required. No provider writes were attempted.",
        title: "Scheduled — no changes",
      };
  }
}

export function createWorkspaceScheduledTerminalReceiptVerifier(
  ledger: IWorkspaceDirectoryChangeLedger,
): (
  terminal: WorkspaceScheduleTick,
) => Promise<null | WorkspaceScheduleReceipt> {
  return async (input) => {
    const terminal = WorkspaceScheduleTickSchema.parse(input);
    if (
      terminal.phase !== "terminal" ||
      terminal.execution !== undefined ||
      terminal.outcome === "applied" ||
      (terminal.workflowId !== null && terminal.outcome !== "failed")
    )
      throw new Error(
        "workspace_schedule_terminal_report_requires_non_workflow_terminal",
      );
    if (!terminal.notificationRequired) return null;
    if (ledger.verifyTerminal === undefined)
      throw new Error(
        "workspace_schedule_terminal_report_requires_exact_verifier",
      );
    const message = terminalMessage(terminal);
    const handle = await ledger.preannounce({
      ...message,
      changeKey: `workspace-schedule-terminal:${terminal.tickId}`,
      historyOldest: (terminal.scheduledAtMs / 1000).toFixed(6),
      retryFailed: false,
    });
    if (handle.state === "failed")
      throw new Error("workspace_schedule_terminal_report_failed_handle");
    if (handle.state === "announced") await ledger.complete(handle, message);
    const verified = await ledger.verifyTerminal(handle, "completed", message);
    const receipt = WorkspaceScheduleReceiptSchema.parse({
      channelId: verified.channelId,
      contentHash: verified.contentHash,
      outcome: terminal.outcome,
      planHash: terminal.planHash,
      slackTimestamp: verified.timestamp,
      tickId: terminal.tickId,
      verifiedAtMs: verified.verifiedAtMs,
      workflowId: terminal.workflowId,
    });
    WorkspaceScheduleTickSchema.parse({ ...terminal, receipt });
    return receipt;
  };
}
