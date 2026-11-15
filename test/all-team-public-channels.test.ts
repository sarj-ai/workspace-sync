import { describe, expect, it } from "vitest";

import { buildOrgChannelPlan } from "../src/org-sync/channel-model.ts";
import { channel, fixture } from "./public-channel-enrollment-fixture.ts";

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
