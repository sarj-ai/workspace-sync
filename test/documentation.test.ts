import { spawnSync } from "node:child_process";

import { describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { apply, plan } from "../examples/plan-and-apply.ts";
import { profilePlan } from "../examples/profile-plan.ts";
import metadata from "../package.json" with { type: "json" };
import {
  architecture,
  architectureMermaid,
} from "../site/src/lib/architecture.ts";
import type {
  GoogleDirectoryUser,
  SlackProfile,
} from "../src/org-sync/model.ts";
import type { IOrgSlackClient } from "../src/org-sync/org-slack-client.ts";
import { OrgSyncService } from "../src/org-sync/service.ts";

describe("documentation examples", () => {
  it.each([
    {},
    {
      GOOGLE_SERVICE_ACCOUNT_EMAIL: "service@company.test",
      GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY: "   ",
    },
    {
      GOOGLE_SERVICE_ACCOUNT_EMAIL: "invalid-email",
      GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY: "private-material-must-stay-private",
    },
  ])("rejects invalid credentials without exposing their values", (env) => {
    const result = spawnSync(
      process.execPath,
      ["examples/audit-directory.ts", "examples/policy.example.json"],
      {
        cwd: new URL("../", import.meta.url),
        env,
        encoding: "utf8",
        timeout: 10_000,
      },
    );
    expect(result.error).toBeUndefined();
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("ZodError");
    expect(result.stderr).not.toContain("private-material-must-stay-private");
    expect(result.stdout).toBe("");
  });

  it("renders a valid synthetic plan from the actual planner", () => {
    expect(profilePlan.errors).toEqual([]);
    expect(profilePlan.profiles).toHaveLength(1);
    expect(profilePlan.profiles[0]).toMatchObject({
      changedFields: ["title"],
      current: { title: "Engineer" },
      desired: { title: "Staff Engineer" },
      slackUserId: "UADA",
    });
  });

  it.each([
    { drift: false, status: "success", writes: 1, verified: 1 },
    { drift: true, status: "blocked", writes: 0, verified: 0 },
  ])(
    "applies only the reviewed plan (drift: $drift)",
    async ({ drift, status, writes, verified }) => {
      const user: GoogleDirectoryUser = {
        id: "12345",
        primaryEmail: "ada@company.test",
        organizations: [
          { department: "Engineering", primary: true, title: "Staff Engineer" },
        ],
      };
      let current: SlackProfile = {
        email: user.primaryEmail,
        title: "Engineer",
        fields: { XfTeam: { value: "Engineering" } },
      };
      const setProfile = vi.fn<IOrgSlackClient["setProfile"]>(
        async (_id, profile) => {
          current = {
            ...current,
            ...profile,
            fields: { ...current.fields, ...profile.fields },
          };
        },
      );
      const reserve = vi
        .fn<(userId: string) => Promise<void>>()
        .mockResolvedValue(undefined);
      const sync = new OrgSyncService({
        config: {
          allowedEmptyDepartmentGoogleUserIds: [],
          excludedGoogleUserIds: [],
          expectedRootGoogleUserIds: [user.id],
          expectedSlackTeamId: "TEXAMPLE",
          fieldIds: {
            manages: "XfManages",
            reportsTo: "XfReportsTo",
            team: "XfTeam",
          },
          managedDomain: "company.test",
          maxAutomaticChanges: 1,
          minimumGoogleParticipants: 1,
          protectedDepartedGoogleUserIds: [],
        },
        google: { listAllUsers: async () => [user] },
        slack: {
          getProfile: async () => current,
          listSnapshot: async () => ({
            actorUserId: "UADMIN",
            fields: [
              {
                id: "XfManages",
                label: "Manages",
                type: "user",
                "is_protected": true,
              },
              {
                id: "XfReportsTo",
                label: "Reports to",
                type: "user",
                "is_protected": true,
              },
              {
                id: "XfTeam",
                label: "Team",
                type: "text",
                "is_protected": true,
              },
            ],
            members: [
              { id: "UADMIN", profile: {}, "is_admin": true },
              { id: "UADA", profile: current },
            ],
            scopes: [
              "users.profile:read",
              "users.profile:write",
              "users:read",
              "users:read.email",
            ],
            teamId: "TEXAMPLE",
          }),
          setProfile,
        },
      });
      const reviewed = await plan(sync);
      expect(reviewed.status).toBe("audit");
      expect(reviewed.planHash).toMatch(/^[a-f0-9]{64}$/u);
      expect(setProfile).not.toHaveBeenCalled();
      expect(reserve).not.toHaveBeenCalled();
      if (drift)
        user.organizations = [
          {
            department: "Engineering",
            primary: true,
            title: "Principal Engineer",
          },
        ];
      const result = await apply(sync, reviewed, { required: true, reserve });
      expect(result).toMatchObject({ status, writes, verified });
      expect(result.planHash === reviewed.planHash).toBe(!drift);
      expect(setProfile).toHaveBeenCalledTimes(writes);
      expect(reserve.mock.calls).toEqual(drift ? [] : [[user.id]]);
    },
  );

  it("keeps diagram edges and source links within the public API", () => {
    const ids = new Set(architecture.nodes.map((node) => node.id));
    expect(ids.size).toBe(architecture.nodes.length);
    const modules = new Set(
      Object.values(metadata.exports).flatMap((target) => {
        const result = z.object({ import: z.string() }).safeParse(target);
        return result.success
          ? [result.data.import.slice("./dist/".length, -".js".length)]
          : [];
      }),
    );
    for (const node of architecture.nodes)
      expect(modules.has(node.module)).toBe(true);
    for (const edge of architecture.edges) {
      expect(ids.has(edge.source)).toBe(true);
      expect(ids.has(edge.target)).toBe(true);
      expect(architectureMermaid()).toContain(
        `${edge.source} --> ${edge.target}`,
      );
    }
  });
});
