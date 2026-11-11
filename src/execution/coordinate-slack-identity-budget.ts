import type { WorkspaceDirectoryPlan } from "./contracts.ts";
import { isScheduledSlackUserGroupReconciliation } from "./scheduled-slack-membership-addition.ts";

type Profiles = WorkspaceDirectoryPlan["branches"][0];
type Channels = WorkspaceDirectoryPlan["branches"][2];

// Automatic membership changes take priority; otherwise profile repair can progress.
export function coordinateSlackIdentityBudget(
  profiles: Profiles,
  channels: Channels,
  enabled = true,
): { profiles: Profiles; channels: Channels } {
  if (
    !enabled ||
    profiles.execution !== "managed" ||
    channels.execution !== "managed" ||
    channels.selectedIdentity === undefined ||
    profiles.changes.every(
      ({ googleUserId }) =>
        googleUserId === channels.selectedIdentity?.googleUserId,
    )
  )
    return { profiles, channels };
  if (!isScheduledSlackUserGroupReconciliation(channels)) {
    return {
      profiles,
      channels: {
        branchId: "slack-groups-channels",
        execution: "audit-only",
        killSwitchEngaged: true,
        planHash: channels.planHash,
        additions: channels.additions,
        removals: channels.removals,
        channelRenames: channels.channelRenames,
        userGroups: channels.userGroups,
        lifecycle: channels.lifecycle,
        selectedChannelAdditions: [],
        selectedChannelRename: null,
        selectedProvenanceChannelRemovals: [],
        selectedRemovalCount: 0,
        selectedUserGroupHandles: [],
        selectedUserGroups: [],
        diagnostics: [
          ...channels.diagnostics,
          {
            code: "membership_service_identity_deferred",
            message:
              "Membership repair deferred to preserve the selected Slack profile identity budget.",
            severity: "warning",
            scope: {
              kind: "action",
              actionId: "workspace-directory.slack-groups-channels",
            },
          },
        ],
      },
    };
  }
  return {
    channels,
    profiles: {
      ...profiles,
      execution: "audit-only",
      killSwitchEngaged: true,
      diagnostics: [
        ...profiles.diagnostics,
        {
          code: "profile_service_identity_deferred",
          message:
            "Profile repair deferred to preserve the selected Slack membership identity budget.",
          severity: "warning",
          scope: {
            kind: "action",
            actionId: "workspace-directory.slack-profiles",
          },
        },
      ],
    },
  };
}
