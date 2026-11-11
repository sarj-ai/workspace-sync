import { getWorkspaceExecutionPolicy } from "./get-workspace-execution-policy.ts";

export function workspaceChangeLedgerChannelId(): string {
  return getWorkspaceExecutionPolicy().ledger.channelId;
}
export function workspaceChangeLedgerChannelName(): string {
  return getWorkspaceExecutionPolicy().ledger.channelName;
}

export interface WorkspaceDirectoryLedgerMessage {
  blocks?: readonly unknown[];
  text: string;
}
