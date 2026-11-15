import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  activeResourceLease,
  resourceLeaseKey,
} from "../src/identity-sync/resource-lease.ts";
import type {
  ManagedTeamPolicy,
  SlackChannelSyncSnapshot,
} from "../src/org-sync/channel-model.ts";
import { OrgChannelSyncService } from "../src/org-sync/channel-service.ts";
import type { IOrgChannelSlackClient } from "../src/org-sync/org-channel-slack-client.ts";
import { channel, fixture } from "./public-channel-enrollment-fixture.ts";

const READ_SCOPES = [
  "channels:read",
  "groups:read",
  "users:read",
  "users:read.email",
  "usergroups:read",
];

function serviceFixture(
  scopes: readonly string[],
  kind: "private" | "public" = "public",
) {
  const input = fixture();
  const state: SlackChannelSyncSnapshot = input.slack;
  state.scopes = [...READ_SCOPES, ...scopes];
  let managedTeams: ManagedTeamPolicy[] = [];
  if (kind === "private") {
    state.channels = [
      { ...channel("CPRIVATE", "employee-team"), isPrivate: true },
      { ...channel("CASKS", "asks-employees"), memberIds: ["UONE", "UTWO"] },
    ];
    state.userGroups.push({
      id: "SEMPLOYEES",
      handle: "group-employees",
      name: "Employees",
      isDisabled: false,
      channelIds: ["CPRIVATE"],
      userIds: ["UONE", "UTWO"],
    });
    managedTeams = [
      {
        accessMode: "direct",
        asksChannel: { name: "asks-employees" },
        asksMembershipMode: "additive",
        channelMode: "required",
        excludedGoogleGroupEmails: input.allTeam.excludedGoogleGroupEmails,
        googleGroupEmail: input.assignmentGroupEmails[0] ?? "",
        legacyPrivateChannel: { name: "legacy-employees" },
        membershipMode: "additive",
        privateChannel: { name: "employee-team" },
        slackUserGroup: {
          handle: "group-employees",
          legacyHandles: [],
          expectedId: "SEMPLOYEES",
        },
      },
    ];
  } else {
    state.channels = [
      ...Array.from({ length: 7 }, (_, index) =>
        channel(`CNEW${String(index)}`, `asks-simulation-${String(index)}`),
      ),
      ...state.channels.filter(({ id }) => id !== "CPUBLIC"),
    ];
  }
  state.inventory = state.channels.map(
    ({ memberIds: _memberIds, ...identity }) => identity,
  );
  const invite = vi.fn<NonNullable<IOrgChannelSlackClient["invite"]>>(
    (channelId, userId) => {
      const selected = state.channels.find(({ id }) => id === channelId);
      if (!selected) throw new Error("Fixture channel missing");
      selected.memberIds.push(userId);
      return Promise.resolve();
    },
  );
  const listSnapshot = vi.fn<IOrgChannelSlackClient["listSnapshot"]>(() =>
    Promise.resolve(state),
  );
  const getChannelIdentity = vi.fn<
    IOrgChannelSlackClient["getChannelIdentity"]
  >((channelId) => {
    const selected = state.channels.find(({ id }) => id === channelId);
    if (!selected) return Promise.reject(new Error("Fixture channel missing"));
    const { memberIds: _memberIds, ...identity } = selected;
    return Promise.resolve(identity);
  });
  const lease = activeResourceLease({
    expiresAtMs: Date.now() + 60_000,
    generation: 1,
    ownerId: "11111111-1111-4111-8111-111111111111",
    resourceKey: resourceLeaseKey("identity-sync/test-invitation-scopes"),
  });
  const service = new OrgChannelSyncService(
    {
      allTeam: input.allTeam,
      allowedPublicChannelNames: input.allowedPublicChannelNames,
      allowedPublicChannelPrefixes: input.allowedPublicChannelPrefixes,
      assignmentGroupEmails: input.assignmentGroupEmails,
      automaticMemberRemovalScope: { kind: "all_managed" },
      expectedSlackTeamId: "TWORKSPACE",
      managedTeams,
      maxAutomaticAdditions: 10,
      maxAutomaticChannelInvites: 5,
      maxAutomaticRemovals: 0,
      maxAutomaticUserGroupChanges: 0,
      minimumActiveGoogleUsers: 1,
    },
    {
      listAllUsers: () =>
        Promise.resolve(
          input.activeGoogleUsers.map((user) => ({
            ...user,
            aliases: [],
            archived: false,
            suspended: false,
          })),
        ),
    },
    {
      listAllGroups: () => Promise.resolve(input.managedGroups),
      listGroups: () => Promise.resolve(input.managedGroups),
    },
    {
      listSnapshot,
      invite,
      getChannelIdentity,
      getUserGroup: () => Promise.resolve(state.userGroups[0] ?? null),
      listChannelMembers: (id) =>
        Promise.resolve([
          ...(state.channels.find((c) => c.id === id)?.memberIds ?? []),
        ]),
      kick: () => Promise.reject(new Error("Unexpected removal")),
    },
    {
      acquire: () => Promise.resolve({ kind: "acquired", lease }),
      assertActive: () => Promise.resolve(),
      release: () => Promise.resolve(),
    },
  );
  return { service, state, invite, listSnapshot, getChannelIdentity };
}

const RUN = { allowRemovals: false, mode: "live", trigger: "cron" } as const;

beforeEach(() => {
  vi.stubGlobal("fetch", () => {
    throw new Error("Unexpected network request");
  });
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Slack invitation scope compatibility", () => {
  it.each(["channels:write", "channels:write.invites"])(
    "converges public enrollment with %s under the existing safety ceiling",
    async (scope) => {
      const f = serviceFixture([scope]);
      const first = await f.service.run(RUN);
      expect(first).toMatchObject({ status: "success", writes: 5, errors: [] });
      expect(first.warnings).toContain(
        "2 direct channel membership additions deferred by the per-run safety ceiling",
      );
      await expect(f.service.run(RUN)).resolves.toMatchObject({
        status: "success",
        writes: 2,
        errors: [],
      });
      await expect(f.service.run(RUN)).resolves.toMatchObject({
        writes: 0,
        errors: [],
      });
      expect(f.invite).toHaveBeenCalledTimes(7);
      expect(f.invite.mock.calls.every(([, userId]) => userId === "UTWO")).toBe(
        true,
      );
      expect(
        f.state.channels.find(({ id }) => id === "CPRIVATE")?.memberIds,
      ).not.toContain("UTWO");
      expect(
        f.state.channels.find(({ id }) => id === "CARCHIVED")?.memberIds,
      ).not.toContain("UTWO");
      const future = channel("CFUTURE", "asks-new-team");
      f.state.channels.push(future);
      f.state.inventory.push(future);
      await expect(f.service.run(RUN)).resolves.toMatchObject({
        status: "success",
        writes: 1,
        errors: [],
      });
      expect(f.invite).toHaveBeenLastCalledWith(
        "CFUTURE",
        "UTWO",
        expect.any(String),
        expect.any(Number),
      );
      expect(f.listSnapshot.mock.calls.at(-1)?.[5]).toEqual(["asks-"]);
      expect(f.state.userGroups[0]?.channelIds).toEqual([]);
    },
  );

  it.each(["groups:write", "groups:write.invites", "channels:manage"])(
    "does not admit public invitations using %s",
    async (scope) => {
      const f = serviceFixture([scope]);
      const result = await f.service.run(RUN);
      expect(result).toMatchObject({ status: "blocked", writes: 0 });
      expect(result.errors).toContain(
        "Slack token lacks the matching channel invitation scope",
      );
      expect(f.invite).not.toHaveBeenCalled();
    },
  );

  it.each(["groups:write", "groups:write.invites"])(
    "permits only explicitly managed private invitations with %s",
    async (scope) => {
      const f = serviceFixture([scope], "private");
      await expect(f.service.run(RUN)).resolves.toMatchObject({
        status: "success",
        writes: 1,
        errors: [],
      });
      expect(f.invite).toHaveBeenCalledWith(
        "CPRIVATE",
        "UTWO",
        expect.any(String),
        expect.any(Number),
      );
    },
  );

  it.each(["channels:write", "channels:write.invites"])(
    "does not admit private invitations using %s",
    async (scope) => {
      const f = serviceFixture([scope], "private");
      const result = await f.service.run(RUN);
      expect(result).toMatchObject({ status: "blocked", writes: 0 });
      expect(result.errors).toContain(
        "Slack token lacks the matching channel invitation scope",
      );
      expect(f.invite).not.toHaveBeenCalled();
    },
  );

  it.each(["public", "private"] as const)(
    "blocks %s invitations with read scopes alone",
    async (kind) => {
      const f = serviceFixture([], kind);
      await expect(f.service.run(RUN)).resolves.toMatchObject({
        status: "blocked",
        writes: 0,
      });
      expect(f.invite).not.toHaveBeenCalled();
    },
  );

  it("still rejects a public channel becoming private before its invitation", async () => {
    const f = serviceFixture(["channels:write"]);
    f.getChannelIdentity.mockImplementationOnce((channelId) =>
      Promise.resolve({
        id: channelId,
        name: "asks-simulation-0",
        isPrivate: true,
        isArchived: false,
      }),
    );
    const result = await f.service.run(RUN);
    expect(result.writes).toBe(0);
    expect(
      result.errors.some((message) =>
        message.includes("changed before invitation"),
      ),
    ).toBe(true);
    expect(f.invite).not.toHaveBeenCalled();
  });
});
