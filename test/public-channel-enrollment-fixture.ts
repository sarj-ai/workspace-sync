import type {
  AllTeamPolicy,
  GoogleGroupSnapshot,
  SlackChannelSnapshot,
} from "../src/org-sync/channel-model.ts";

export function channel(id: string, name: string): SlackChannelSnapshot {
  return { id, name, isPrivate: false, isArchived: false, memberIds: ["UONE"] };
}

export function fixture() {
  const identities = [
    { id: "one", slackId: "UONE", email: "one@company.test" },
    { id: "two", slackId: "UTWO", email: "two@company.test" },
    {
      id: "contractor",
      slackId: "UCONTRACTOR",
      email: "contractor@company.test",
    },
  ];
  const member = (identity: (typeof identities)[number]) => ({
    id: identity.id,
    email: identity.email,
    role: "MEMBER" as const,
    status: "ACTIVE" as const,
    type: "USER" as const,
  });
  const employees: GoogleGroupSnapshot = {
    email: "team-employees@company.test",
    id: "employee-group",
    members: identities.map(member),
  };
  const contractors: GoogleGroupSnapshot = {
    email: "team-contractors@company.test",
    id: "contractor-group-test",
    members: identities
      .filter((identity) => identity.id === "contractor")
      .map(member),
  };
  const allTeam: AllTeamPolicy = {
    channelMembershipMode: "authoritative",
    excludedGoogleGroupEmails: [contractors.email],
    expectedExcludedGoogleGroupIds: { [contractors.email]: contractors.id },
    googleGroupEmails: [employees.email],
    membershipMode: "authoritative",
    publicChannelPrefixes: ["asks-"],
    slackUserGroup: {
      handle: "group-all",
      expectedId: "SALL",
      legacyHandles: [],
      automationOwnership: {
        kind: "explicitly_adopted",
        allowedChannelIds: [],
        cutoverRevision: "a".repeat(40),
        evidenceDigest: "b".repeat(64),
        sourceGoogleGroupIds: [employees.id],
        excludedGoogleGroupIds: [contractors.id],
      },
    },
  };
  const channels = [
    channel("CPUBLIC", "asks-other-team"),
    channel("COTHER", "general"),
    { ...channel("CPRIVATE", "asks-private"), isPrivate: true },
    { ...channel("CARCHIVED", "asks-archived"), isArchived: true },
  ];
  return {
    activeGoogleUsers: identities.map((identity) => ({
      id: identity.id,
      primaryEmail: identity.email,
    })),
    allTeam,
    allowedPublicChannelNames: ["general"],
    allowedPublicChannelPrefixes: ["asks-"],
    assignmentGroupEmails: [employees.email],
    assignmentGroups: [employees],
    googleGroupInventory: [employees, contractors],
    managedGroups: [employees, contractors],
    managedTeams: [],
    slack: {
      channels,
      inventory: channels.map(
        ({ memberIds: _memberIds, ...identity }) => identity,
      ),
      members: identities.map((identity) => ({
        id: identity.slackId,
        profile: { email: identity.email },
        deleted: false,
        "is_bot": false,
        "is_app_user": false,
        "is_admin": false,
        "is_owner": false,
        "is_primary_owner": false,
        "is_restricted": false,
        "is_ultra_restricted": false,
      })),
      scopes: [],
      teamId: "TWORKSPACE",
      userGroups: [
        {
          id: "SALL",
          handle: "group-all",
          name: "All",
          isDisabled: false,
          channelIds: [],
          userIds: ["UONE", "UTWO"],
        },
      ],
    },
  };
}
