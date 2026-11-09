import { describe, expect, it, vi } from "vitest";

import type {
  GoogleDirectoryUser,
  SlackMember,
} from "../src/org-sync/model.ts";
import type { SlackSnapshot } from "../src/org-sync/org-slack-client.ts";
import {
  applySlackNamePlanAction,
  auditSlackNameSync,
  planSlackNameSync,
  SlackNameDriftError,
  SlackNameIdentityError,
  SlackNameRoleError,
} from "../src/workspace-directory/slack-name-sync.ts";

const TEAM_ID = "TTEST000001";

function google(email = "jdoe@company.test"): GoogleDirectoryUser {
  return {
    id: "google-1",
    name: { fullName: "Jane Doe" },
    primaryEmail: email,
  };
}

function member(
  id: string,
  email: string,
  realName: string,
  displayName: string,
  overrides: Partial<SlackMember> = {},
): SlackMember {
  return {
    id,
    profile: { "display_name": displayName, email, "real_name": realName },
    ...overrides,
  };
}

function snapshot(target: SlackMember): SlackSnapshot {
  return {
    actorUserId: "UOWNER",
    fields: [],
    members: [
      member("UOWNER", "owner@company.test", "Owner Person", "Owner", {
        "is_primary_owner": true,
      }),
      target,
    ],
    scopes: ["users.profile:write", "users:read", "users:read.email"],
    teamId: TEAM_ID,
  };
}

describe("Google-authoritative Slack name planning", () => {
  it.each([
    "allowed",
    "denied",
    "missing-callback",
    "admin-promoted",
    "identity-changed",
  ] as const)(
    "enforces the required final name identity budget: %s",
    async (decision) => {
      const users = [{ ...google(), id: "101" }];
      let target = member("UJANE", "jdoe@company.test", "jdoe", "Nickname");
      const order: string[] = [];
      const reserve = vi.fn(async (id: string) => {
        order.push(`reserve:${id}`);
        if (decision === "denied") throw new Error("identity_budget_exhausted");
        if (decision === "admin-promoted")
          target = { ...target, "is_admin": true };
        if (decision === "identity-changed")
          target = {
            ...target,
            profile: { ...target.profile, email: "different@company.test" },
          };
      });
      const slack = {
        getProfile: vi.fn(async () => target.profile),
        listSnapshot: vi.fn(async () => snapshot(target)),
        setProfile: vi.fn(
          async (_id: string, profile: { "real_name"?: string }) => {
            order.push("write");
            target = { ...target, profile: { ...target.profile, ...profile } };
          },
        ),
      };
      const audited = await auditSlackNameSync(users, slack, TEAM_ID);
      const action = audited.actions[0];
      if (action === undefined) throw new Error("expected_slack_name_action");
      const budget = { required: true as const, reserve };
      if (decision === "missing-callback")
        Reflect.deleteProperty(budget, "reserve");
      const [result] = await Promise.allSettled([
        applySlackNamePlanAction(
          users,
          slack,
          TEAM_ID,
          action,
          audited.planHash,
          budget,
        ),
      ]);
      expect(result.status).toBe(
        decision === "allowed" ? "fulfilled" : "rejected",
      );
      expect(order).toEqual(
        decision === "missing-callback"
          ? []
          : ["reserve:101", ...(decision === "allowed" ? ["write"] : [])],
      );
      expect(slack.setProfile).toHaveBeenCalledTimes(
        decision === "allowed" ? 1 : 0,
      );
    },
  );

  it("repairs only a real name that exactly equals the email default", () => {
    expect(
      planSlackNameSync(
        [google()],
        snapshot(member("UJANE", "jdoe@company.test", "jdoe", "Jane D")),
      ).actions,
    ).toEqual([
      expect.objectContaining({
        desiredName: "Jane Doe",
        slackUserId: "UJANE",
      }),
    ]);
  });

  it("preserves display-name usernames even when they equal the email local part", () => {
    expect(
      planSlackNameSync(
        [google()],
        snapshot(member("UJANE", "jdoe@company.test", "Jane Doe", "jdoe")),
      ).actions,
    ).toEqual([]);
  });

  it("preserves blank and custom names", () => {
    expect(
      planSlackNameSync([google(), google("custom@company.test")], {
        ...snapshot(member("UJANE", "jdoe@company.test", "Jane D.", "")),
        members: [
          ...snapshot(member("UJANE", "jdoe@company.test", "Jane D.", ""))
            .members,
          member("UCUSTOM", "custom@company.test", "Custom Human", "Nickname"),
        ],
      }).actions,
    ).toEqual([]);
  });

  it("fails closed on duplicate Slack identities or an insufficient actor role", () => {
    const duplicated = snapshot(
      member("UJANE", "jdoe@company.test", "jdoe", ""),
    );
    duplicated.members.push(member("UJANE2", "jdoe@company.test", "jdoe", ""));
    expect(() => planSlackNameSync([google()], duplicated)).toThrow(
      SlackNameIdentityError,
    );

    const restrictedActor = snapshot(
      member("UADMIN", "jdoe@company.test", "jdoe", "", { "is_admin": true }),
    );
    restrictedActor.members[0] = member(
      "UOWNER",
      "owner@company.test",
      "Owner",
      "Owner",
    );
    expect(() => planSlackNameSync([google()], restrictedActor)).toThrow(
      SlackNameRoleError,
    );
  });

  it("rejects an alias shared by different active Google identities", () => {
    expect(() =>
      planSlackNameSync(
        [
          google(),
          {
            ...google("other@company.test"),
            id: "google-2",
            aliases: ["JDOE@company.test"],
          },
        ],
        snapshot(member("UJANE", "jdoe@company.test", "jdoe", "")),
      ),
    ).toThrow("slack_name_google_identity_ambiguous");
  });

  it("matches non-editable Google aliases and permits a 31-person gradual plan", () => {
    const users = Array.from({ length: 31 }, (_, index) => ({
      id: `google-${String(index)}`,
      name: { fullName: `Person ${String(index)}` },
      nonEditableAliases: index === 0 ? ["alias@company.test"] : [],
      primaryEmail: `person${String(index)}@company.test`,
    }));
    const targets = Array.from({ length: 31 }, (_, index) => {
      const email =
        index === 0
          ? "alias@company.test"
          : `person${String(index)}@company.test`;
      return member(
        `U${String(index).padStart(4, "0")}`,
        email,
        email.split("@", 1)[0] ?? "",
        "",
      );
    });
    const input = snapshot(
      targets[0] ??
        member("UFALLBACK", "fallback@company.test", "fallback", ""),
    );
    const actor = input.members[0];
    if (actor === undefined) throw new Error("expected_slack_actor");
    input.members = [actor, ...targets];

    const plan = planSlackNameSync(users, input);

    expect(plan.actions).toHaveLength(31);
    expect(plan.actions).toContainEqual(
      expect.objectContaining({
        email: "alias@company.test",
        desiredName: "Person 0",
      }),
    );
  });

  it("re-audits, writes only selected fields, and verifies readback", async () => {
    let target = member("UJANE", "jdoe@company.test", "jdoe", "Nickname");
    const slack = {
      getProfile: vi.fn(async () => target.profile),
      listSnapshot: vi.fn(async () => snapshot(target)),
      setProfile: vi.fn(
        async (_id: string, profile: { "real_name"?: string }) => {
          target = { ...target, profile: { ...target.profile, ...profile } };
        },
      ),
    };
    const audited = await auditSlackNameSync([google()], slack, TEAM_ID);
    const action = audited.actions[0];
    if (action === undefined) throw new Error("expected_slack_name_action");

    await applySlackNamePlanAction(
      [google()],
      slack,
      TEAM_ID,
      action,
      audited.planHash,
    );

    expect(slack.setProfile).toHaveBeenCalledWith(
      "UJANE",
      { "real_name": "Jane Doe" },
      expect.any(String),
    );
    expect(target.profile).toMatchObject({
      "display_name": "Nickname",
      "real_name": "Jane Doe",
    });
  });

  it("rejects drift before writing", async () => {
    let target = member("UJANE", "jdoe@company.test", "jdoe", "");
    const slack = {
      getProfile: vi.fn(async () => target.profile),
      listSnapshot: vi.fn(async () => snapshot(target)),
      setProfile: vi.fn(async () => undefined),
    };
    const audited = await auditSlackNameSync([google()], slack, TEAM_ID);
    const action = audited.actions[0];
    if (action === undefined) throw new Error("expected_slack_name_action");
    target = {
      ...target,
      profile: { ...target.profile, "real_name": "Custom Name" },
    };

    await expect(
      applySlackNamePlanAction(
        [google()],
        slack,
        TEAM_ID,
        action,
        audited.planHash,
      ),
    ).rejects.toBeInstanceOf(SlackNameDriftError);
    expect(slack.setProfile).not.toHaveBeenCalled();
  });
});
