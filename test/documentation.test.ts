import { spawnSync } from "node:child_process";

import { describe, expect, it } from "vitest";
import { z } from "zod";

import { profilePlan } from "../examples/profile-plan.ts";
import metadata from "../package.json" with { type: "json" };
import {
  architecture,
  architectureMermaid,
} from "../site/src/lib/architecture.ts";

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

  it("keeps diagram edges and source links within the public API", () => {
    const ids = new Set<string>(architecture.nodes.map((node) => node.id));
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
