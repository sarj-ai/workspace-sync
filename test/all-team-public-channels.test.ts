import { describe, expect, it } from "vitest";

import {
  type AllTeamPolicy,
  buildOrgChannelPlan,
  type GoogleGroupSnapshot,
  type SlackChannelSnapshot,
} from "../src/org-sync/channel-model.ts";

function channel(id: string, name: string): SlackChannelSnapshot {
  return { id, name, isPrivate: false, isArchived: false, memberIds: ["UONE"] };
}

function fixture() {
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

describe("all-employee public channel enrollment", () => {
  it("enrolls employees in a different team's public channel without admitting contractors or private/archived channels", () => {
    const plan = buildOrgChannelPlan(fixture());
    expect(plan.errors).toEqual([]);
    const all = plan.userGroups.find((group) => group.handle === "group-all");
    expect(all?.desiredChannelIds).toEqual([]);
    expect(all?.desiredUserIds).toEqual(["UONE", "UTWO"]);
    expect(
      plan.additions.map(({ slackUserId, channelId }) => ({
        slackUserId,
        channelId,
      })),
    ).toEqual([{ slackUserId: "UTWO", channelId: "CPUBLIC" }]);
    expect(all?.automationOwnership).toMatchObject({ allowedChannelIds: [] });
    expect(
      plan.lifecycle.allTeamProjection?.requiredChannels.map(({ id }) => id),
    ).toEqual(["CPUBLIC"]);
  });

  it("discovers a future matching channel without changing the policy's immutable ID list", () => {
    const input = fixture();
    const future = channel("CFUTURE", "asks-new-team");
    input.slack.channels.push(future);
    input.slack.inventory.push(future);
    const plan = buildOrgChannelPlan(input);
    expect(plan.additions.map(({ channelId }) => channelId)).toEqual([
      "CFUTURE",
      "CPUBLIC",
    ]);
    expect(plan.userGroups[0]?.desiredChannelIds).toEqual([]);
    expect(input.allTeam.slackUserGroup.automationOwnership).toMatchObject({
      allowedChannelIds: [],
    });
  });

  it("preserves channelless adoption when the prefix policy is absent", () => {
    const input = fixture();
    delete input.allTeam.publicChannelPrefixes;
    const plan = buildOrgChannelPlan(input);
    expect(plan.userGroups[0]?.desiredChannelIds).toEqual([]);
    expect(plan.additions).toEqual([]);
  });

  it.each(["", "asks", "ASKS-", "-"])("rejects unsafe prefix %j", (prefix) => {
    const input = fixture();
    input.allTeam.publicChannelPrefixes = [prefix];
    expect(() => buildOrgChannelPlan(input)).toThrow(
      "nonempty Slack name prefixes",
    );
  });

  it("requires managed group ownership before enabling dynamic enrollment", () => {
    const input = fixture();
    delete input.allTeam.slackUserGroup.automationOwnership;
    expect(() => buildOrgChannelPlan(input)).toThrow(
      "requires managed user group ownership",
    );
  });
});
