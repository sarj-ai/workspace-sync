interface MembershipTarget {
  readonly slackUserId: string;
}

interface MembershipSelection {
  readonly execution: string;
  readonly selectedChannelAdditions: readonly MembershipTarget[];
  readonly selectedChannelRename: unknown;
  readonly selectedProvenanceChannelRemovals: readonly MembershipTarget[];
  readonly selectedUserGroups: readonly {
    readonly slackUserGroupId: null | string;
    readonly expectedSlackUserGroupId: null | string;
    readonly currentHandle: null | string;
    readonly handle: string;
    readonly currentName: null | string;
    readonly desiredName: string;
    readonly automationOwnership: { readonly kind: string };
    readonly channelAdditionIds: readonly string[];
    readonly channelRemovalIds: readonly string[];
    readonly memberAdditions: readonly MembershipTarget[];
    readonly memberRemovals: readonly MembershipTarget[];
    readonly effectiveAccessAdditions: readonly MembershipTarget[];
  }[];
}

/* Only actual membership deltas qualify; roster-wide or resource-only effects are not identity writes. */
export function selectedSlackMembershipUserId(
  branch: MembershipSelection,
): string | undefined {
  if (branch.execution !== "managed" || branch.selectedChannelRename !== null)
    return undefined;
  const ids = new Set(
    [
      ...branch.selectedChannelAdditions,
      ...branch.selectedProvenanceChannelRemovals,
    ].map(({ slackUserId }) => slackUserId),
  );
  for (const group of branch.selectedUserGroups) {
    if (
      group.slackUserGroupId === null ||
      group.expectedSlackUserGroupId !== group.slackUserGroupId ||
      group.currentHandle !== group.handle ||
      group.currentName !== group.desiredName ||
      group.automationOwnership.kind === "legacy_unmanaged" ||
      group.automationOwnership.kind === "automation_bootstrap" ||
      group.channelAdditionIds.length > 0 ||
      group.channelRemovalIds.length > 0
    )
      return undefined;
    for (const members of [group.memberAdditions, group.memberRemovals])
      for (const member of members) ids.add(member.slackUserId);
    if (
      group.effectiveAccessAdditions.some(
        ({ slackUserId }) => !ids.has(slackUserId),
      )
    )
      return undefined;
  }
  return ids.size === 1 ? ids.values().next().value : undefined;
}
