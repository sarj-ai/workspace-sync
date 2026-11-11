import { JsonValueSchema } from "../operations/schemas.ts";
import type { WorkspaceDirectoryPlan } from "./contracts.ts";

type Branch = WorkspaceDirectoryPlan["branches"][2];

export function slackGroupsChannelsManagedSlice(
  branch: Branch,
  state: "pending" | "verified",
) {
  return JsonValueSchema.parse({
    ...(state === "pending" && { planHash: branch.planHash }),
    selectedChannelAdditions: branch.selectedChannelAdditions,
    selectedChannelId: branch.selectedChannelRename?.channelId ?? null,
    selectedProvenanceChannelRemovals: branch.selectedProvenanceChannelRemovals,
    selectedUserGroupHandles: branch.selectedUserGroupHandles,
    selectedUserGroups: branch.selectedUserGroups,
    ...(branch.execution === "managed" &&
      branch.selectedIdentity !== undefined && {
        selectedIdentity: branch.selectedIdentity,
      }),
    state,
  });
}
