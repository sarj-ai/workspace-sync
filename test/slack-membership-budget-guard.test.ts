import { describe, expect, it, vi } from "vitest";

import { createSlackMembershipBudgetGuard } from "../src/org-sync/create-slack-membership-budget-guard.ts";
import type {
  GoogleDirectoryUser,
  SlackMember,
} from "../src/org-sync/model.ts";

function authority(): {
  directoryUsers: GoogleDirectoryUser[];
  slackMembers: SlackMember[];
} {
  const fields = {
    deleted: false,
    "is_admin": false,
    "is_app_user": false,
    "is_bot": false,
    "is_owner": false,
    "is_primary_owner": false,
    "is_restricted": false,
    "is_ultra_restricted": false,
  };
  return {
    directoryUsers: [
      { id: "123", primaryEmail: "one@company.test" },
      { id: "456", primaryEmail: "two@company.test" },
    ] satisfies GoogleDirectoryUser[],
    slackMembers: [
      { ...fields, id: "UONE", profile: { email: "one@company.test" } },
      { ...fields, id: "UTWO", profile: { email: "two@company.test" } },
    ],
  };
}

describe("Slack membership identity budget", () => {
  it("rejects the full multi-identity batch before reserving or writing", () => {
    const reserve = vi.fn();
    expect(() =>
      createSlackMembershipBudgetGuard({
        authority: authority(),
        budget: { required: true, reserve },
        refreshAuthority: async () => authority(),
        slackUserIds: ["UONE", "UTWO"],
      }),
    ).toThrow("multiple_google_identities");
    expect(reserve).not.toHaveBeenCalled();
  });

  it.each(["missing", "ambiguous"] as const)(
    "rejects %s mapping before reservation",
    (kind) => {
      const source = authority();
      if (kind === "ambiguous")
        source.directoryUsers[1] = {
          id: "456",
          primaryEmail: "two@company.test",
          aliases: ["one@company.test"],
        };
      expect(() =>
        createSlackMembershipBudgetGuard({
          authority: source,
          budget: { required: true, reserve: vi.fn() },
          refreshAuthority: async () => source,
          slackUserIds: [kind === "missing" ? "UUNKNOWN" : "UONE"],
        }),
      ).toThrow("mapping_missing_or_ambiguous");
    },
  );

  it("reserves only the same fresh immutable identity across multiple writes", async () => {
    const reserve = vi.fn(async () => undefined);
    const refreshAuthority = vi.fn(async () => authority());
    const guard = createSlackMembershipBudgetGuard({
      authority: authority(),
      budget: { required: true, reserve },
      refreshAuthority,
      slackUserIds: ["UONE", "UONE"],
    });
    if (guard === undefined) throw new Error("guard missing");
    await guard(["UONE"]);
    await guard(["UONE"]);
    expect(reserve.mock.calls).toEqual([["123"], ["123"]]);
    await expect(guard(["UTWO"])).rejects.toThrow("identity_changed");
    expect(reserve).toHaveBeenCalledTimes(2);
  });

  it.each(["identity", "privilege"] as const)(
    "rejects %s drift during the reservation await",
    async (kind) => {
      const fresh = authority();
      const reserve = vi.fn(async () => {
        fresh.directoryUsers[0] = {
          id: kind === "identity" ? "789" : "123",
          primaryEmail: "one@company.test",
          isAdmin: kind === "privilege",
        };
      });
      const guard = createSlackMembershipBudgetGuard({
        authority: authority(),
        budget: { required: true, reserve },
        refreshAuthority: async () => fresh,
        slackUserIds: ["UONE"],
      });
      if (guard === undefined) throw new Error("guard missing");
      await expect(guard(["UONE"])).rejects.toThrow("identity_changed");
      expect(reserve).toHaveBeenCalledExactlyOnceWith("123");
    },
  );

  it("rejects fresh identity reassignment and preserves legacy optional behavior", async () => {
    const reserve = vi.fn(async () => undefined);
    const fresh = authority();
    fresh.directoryUsers[0] = { id: "789", primaryEmail: "one@company.test" };
    const guard = createSlackMembershipBudgetGuard({
      authority: authority(),
      budget: { required: true, reserve },
      refreshAuthority: async () => fresh,
      slackUserIds: ["UONE"],
    });
    if (guard === undefined) throw new Error("guard missing");
    await expect(guard(["UONE"])).rejects.toThrow("identity_changed");
    expect(reserve).not.toHaveBeenCalled();
    expect(
      createSlackMembershipBudgetGuard({
        authority: authority(),
        budget: undefined,
        refreshAuthority: async () => fresh,
        slackUserIds: ["UUNKNOWN", "UTWO"],
      }),
    ).toBeUndefined();
  });
});
