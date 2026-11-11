import type { OrgChannelSyncConfig } from "./channel-service.ts";
export interface OrgChannelRemovalPolicy {
  allowRemovals: boolean;
  automaticMemberRemovalScope: OrgChannelSyncConfig["automaticMemberRemovalScope"];
  maxAutomaticChannelMembershipRemovals: number;
}

export function deriveOrgChannelRemovalPolicy(input: {
  contractorManagedSlackUserGroupIds: readonly string[];
  contractorMemberRemovalGateEnabled: boolean;
  globalRemovalGateEnabled: boolean;
  maxAutomaticChannelMembershipRemovals: number;
}): OrgChannelRemovalPolicy {
  if (input.globalRemovalGateEnabled) {
    return {
      allowRemovals: true,
      automaticMemberRemovalScope: { kind: "all_managed" },
      maxAutomaticChannelMembershipRemovals:
        input.maxAutomaticChannelMembershipRemovals,
    };
  }
  if (input.contractorMemberRemovalGateEnabled) {
    return {
      allowRemovals: true,
      automaticMemberRemovalScope: {
        kind: "immutable_ids",
        slackUserGroupIds: [...input.contractorManagedSlackUserGroupIds],
      },
      maxAutomaticChannelMembershipRemovals:
        input.maxAutomaticChannelMembershipRemovals,
    };
  }
  return {
    allowRemovals: false,
    automaticMemberRemovalScope: { kind: "none" },
    maxAutomaticChannelMembershipRemovals: 0,
  };
}
