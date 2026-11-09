import { describe, expect, it } from "vitest";

import {
  GitHubIdentitySeedInputError,
  GitHubIdentitySeedPlanningService,
  googleIdentityUpdatesFromSeedPlan,
  planGitHubIdentitySeed,
} from "../src/identity-sync/github-identity-seed-planner.ts";

const VERIFIED_AT = "2026-08-20T12:00:00.000Z";

function googleUser(id: string, overrides: Record<string, unknown> = {}) {
  return {
    displayName: `Person ${id}`,
    googleUserId: id,
    lifecycle: "active",
    primaryEmail: `person-${id}@company.test`,
    ...overrides,
  };
}

function githubMember(
  id: string,
  login: string,
  overrides: Record<string, unknown> = {},
) {
  return { githubLogin: login, githubUserId: id, ...overrides };
}

function verified(githubUserId: string, githubLogin: string) {
  return {
    githubLogin,
    githubUserId,
    source: "github-enterprise-saml",
    verifiedAt: VERIFIED_AT,
  };
}

describe("GitHub identity seed planner", () => {
  it("emits stable exact matches ordered by immutable Google ID", async () => {
    const first = await planGitHubIdentitySeed({
      githubMembers: [
        githubMember("9002", "beta"),
        githubMember("9001", "Alpha"),
      ],
      googleUsers: [
        googleUser("102", { githubEvidence: verified("9002", "beta") }),
        googleUser("101", { githubEvidence: verified("9001", "alpha") }),
      ],
      sourceRevision: "google-etag:7/github-snapshot:11",
    });
    const second = await planGitHubIdentitySeed({
      githubMembers: [
        githubMember("9001", "alpha"),
        githubMember("9002", "beta"),
      ],
      googleUsers: [
        googleUser("101", { githubEvidence: verified("9001", "alpha") }),
        googleUser("102", { githubEvidence: verified("9002", "beta") }),
      ],
      sourceRevision: "google-etag:7/github-snapshot:11",
    });

    expect(first).toEqual(second);
    expect(
      first.entries.map((entry) => [entry.subject.googleUserId, entry.kind]),
    ).toEqual([
      ["101", "exact-match"],
      ["102", "exact-match"],
    ]);
    expect(first.summary).toEqual({
      conflicts: 0,
      exactMatches: 2,
      unresolved: 0,
    });
    expect(first.contentHash).toMatch(/^[a-f0-9]{64}$/u);
  });

  it("never promotes email or name heuristics to verified matches", async () => {
    const artifact = await planGitHubIdentitySeed({
      githubMembers: [
        githubMember("9001", "email-clue", {
          email: "person-101@company.test",
        }),
        githubMember("9002", "name-clue", { name: "Person 102" }),
      ],
      googleUsers: [googleUser("101"), googleUser("102"), googleUser("103")],
      sourceRevision: "snapshot-1",
    });

    expect(
      artifact.entries.map((entry) => [
        entry.kind,
        entry.kind === "exact-match" ? undefined : entry.reason,
      ]),
    ).toEqual([
      ["unresolved", "unverified-heuristic"],
      ["unresolved", "unverified-heuristic"],
      ["unresolved", "missing-verified-evidence"],
    ]);
    await expect(googleIdentityUpdatesFromSeedPlan(artifact)).resolves.toEqual(
      [],
    );
  });

  it("makes ambiguous heuristics and inconsistent immutable evidence explicit conflicts", async () => {
    const artifact = await planGitHubIdentitySeed({
      githubMembers: [
        githubMember("9001", "one", { email: "person-101@company.test" }),
        githubMember("9002", "two", { name: "Person 101" }),
        githubMember("9003", "three"),
      ],
      googleUsers: [
        googleUser("101"),
        googleUser("102", { githubEvidence: verified("9003", "two") }),
      ],
      sourceRevision: "snapshot-2",
    });

    expect(
      artifact.entries.map((entry) => [
        entry.kind,
        entry.kind === "exact-match" ? undefined : entry.reason,
      ]),
    ).toEqual([
      ["conflict", "ambiguous-heuristic"],
      ["conflict", "evidence-id-login-mismatch"],
    ]);
    await expect(googleIdentityUpdatesFromSeedPlan(artifact)).rejects.toThrow(
      GitHubIdentitySeedInputError,
    );
  });

  it.each([
    {
      expected: "duplicate Google user ID: 101",
      githubMembers: [githubMember("9001", "one")],
      googleUsers: [googleUser("101"), googleUser("101")],
    },
    {
      expected: "duplicate GitHub login: one",
      githubMembers: [githubMember("9001", "one"), githubMember("9002", "ONE")],
      googleUsers: [googleUser("101")],
    },
    {
      expected: "duplicate verified GitHub user ID: 9001",
      githubMembers: [githubMember("9001", "one")],
      googleUsers: [
        googleUser("101", { githubEvidence: verified("9001", "one") }),
        googleUser("102", { githubEvidence: verified("9001", "one") }),
      ],
    },
    {
      expected: "Google user 101 is suspended",
      githubMembers: [],
      googleUsers: [googleUser("101", { lifecycle: "suspended" })],
    },
  ])(
    "rejects unsafe snapshots before producing an artifact",
    async (testCase) => {
      await expect(
        planGitHubIdentitySeed({
          githubMembers: testCase.githubMembers,
          googleUsers: testCase.googleUsers,
          sourceRevision: "snapshot-rejected",
        }),
      ).rejects.toThrow(testCase.expected);
    },
  );

  it("uses injected read-only sources and emits Google service inputs without applying them", async () => {
    const calls: string[] = [];
    const service = new GitHubIdentitySeedPlanningService({
      github: {
        listOrganizationMembers: async () => {
          calls.push("github-read");
          return [githubMember("9001", "one")];
        },
      },
      google: {
        listIdentitySeedUsers: async () => {
          calls.push("google-read");
          return [
            googleUser("101", { githubEvidence: verified("9001", "one") }),
          ];
        },
      },
      sourceRevision: async () => "injected-snapshot",
    });

    const artifact = await service.plan();

    expect(calls.toSorted((left, right) => left.localeCompare(right))).toEqual([
      "github-read",
      "google-read",
    ]);
    await expect(googleIdentityUpdatesFromSeedPlan(artifact)).resolves.toEqual([
      { desired: { githubLogin: "one", githubUserId: "9001" }, userId: "101" },
    ]);
  });

  it("rejects a seed artifact changed after its content hash was computed", async () => {
    const artifact = await planGitHubIdentitySeed({
      githubMembers: [githubMember("9001", "one")],
      googleUsers: [
        googleUser("101", { githubEvidence: verified("9001", "one") }),
      ],
      sourceRevision: "snapshot-before",
    });

    await expect(
      googleIdentityUpdatesFromSeedPlan({
        ...artifact,
        sourceRevision: "snapshot-after",
      }),
    ).rejects.toThrow("seed plan content hash does not match its body");
  });
});
