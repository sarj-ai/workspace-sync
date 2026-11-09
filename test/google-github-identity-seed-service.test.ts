import { describe, expect, it, vi } from "vitest";

import type { GitHubIdentitySeedSnapshot } from "../src/github-access-audit/git-hub-access-audit-client.ts";
import {
  desiredManagedSlice,
  GoogleGithubIdentitySeedService,
  managedSlice,
} from "../src/identity-sync/google-github-identity-seed-service.ts";
import type { GoogleWorkspaceIdentityUserGateway } from "../src/org-sync/google-identity-schema.ts";
import type { GoogleDirectoryUser } from "../src/org-sync/model.ts";

const GOOGLE_FINGERPRINT = "a".repeat(64);

function githubSnapshot(
  overrides: Partial<GitHubIdentitySeedSnapshot> = {},
): GitHubIdentitySeedSnapshot {
  return {
    capturedAt: "2026-08-23T12:00:00.000Z",
    errors: [],
    members: [{ id: 9001, login: "octocat", role: "member", type: "User" }],
    samlExternalIdentities: [
      { guid: "saml-1", login: "octocat", nameId: "person@company.test" },
    ],
    ...overrides,
  };
}

function googleUser(
  identity?: { githubLogin: string; githubUserId: string },
  etag = "etag-1",
  input: { alias?: string; id?: string; primaryEmail?: string } = {},
): GoogleDirectoryUser {
  return {
    aliases: [input.alias ?? "person@company.test"],
    ...(!(identity === undefined) && {
      customSchemas: { SarjIdentity: identity },
    }),
    etag,
    id: input.id ?? "10001",
    name: { fullName: "Example Person" },
    primaryEmail: input.primaryEmail ?? "primary@company.test",
  };
}

function twoUserGithubSnapshot(): GitHubIdentitySeedSnapshot {
  return githubSnapshot({
    members: [
      { id: 9001, login: "octocat", role: "member", type: "User" },
      { id: 9002, login: "hubot", role: "member", type: "User" },
    ],
    samlExternalIdentities: [
      { guid: "saml-1", login: "octocat", nameId: "person@company.test" },
      { guid: "saml-2", login: "hubot", nameId: "second@company.test" },
    ],
  });
}

function secondGoogleUser(): GoogleDirectoryUser {
  return googleUser(undefined, "etag-2", {
    alias: "second@company.test",
    id: "10002",
    primaryEmail: "second-primary@company.test",
  });
}

function gateway() {
  let user = googleUser();
  let writes = 0;
  const reads: string[] = [];
  const updates: Parameters<
    GoogleWorkspaceIdentityUserGateway["updateUser"]
  >[0][] = [];
  const google: GoogleWorkspaceIdentityUserGateway = {
    readUserById: async (userId) => {
      reads.push(userId);
      return {
        customSchemas: user.customSchemas,
        etag: user.etag,
        id: user.id,
        primaryEmail: user.primaryEmail,
      };
    },
    updateUser: async (input) => {
      updates.push(input);
      writes++;
      user = googleUser(input.identity, `etag-${String(writes + 1)}`);
    },
  };
  return {
    google,
    reads,
    updates,
    get user() {
      return user;
    },
    get writes() {
      return writes;
    },
  };
}

describe("Google GitHub identity seed operation service", () => {
  it("plans an exact SAML-backed diff without writing and binds immutable IDs and ETag", async () => {
    const state = gateway();
    const service = new GoogleGithubIdentitySeedService({
      github: { captureIdentitySeed: async () => githubSnapshot() },
      google: state.google,
      maxChanges: 2,
    });

    const plan = await service.capture([state.user], GOOGLE_FINGERPRINT);

    expect(plan).toMatchObject({
      artifact: {
        entries: [
          {
            kind: "exact-match",
            subject: { googleUserId: "10001" },
            target: { githubLogin: "octocat", githubUserId: "9001" },
          },
        ],
        summary: { conflicts: 0, exactMatches: 1, unresolved: 0 },
      },
      kind: "managed",
      userPlans: [
        {
          desired: { githubLogin: "octocat", githubUserId: "9001" },
          kind: "update",
          user: { etag: "etag-1", id: "10001" },
        },
      ],
    });
    expect(state.reads).toEqual([]);
    expect(state.writes).toBe(0);
  });

  it("applies the signed plan once and converges a second capture to zero diff", async () => {
    const state = gateway();
    const service = new GoogleGithubIdentitySeedService({
      github: { captureIdentitySeed: async () => githubSnapshot() },
      google: state.google,
      maxChanges: 2,
    });
    const plan = await service.capture([state.user], GOOGLE_FINGERPRINT);
    if (plan.kind !== "managed") throw new Error("expected managed seed plan");
    const before = managedSlice(plan.userPlans);
    const desired = desiredManagedSlice(plan.userPlans);

    await expect(service.applyPlan(plan)).resolves.toBe(1);
    expect(state.updates).toMatchObject([
      { expectedEtag: "etag-1", userId: "10001" },
    ]);
    await expect(service.readManagedSlice(plan)).resolves.toEqual(desired);
    expect(desired).not.toEqual(before);
    const converged = await service.capture([state.user], GOOGLE_FINGERPRINT);
    expect(converged).toMatchObject({
      kind: "managed",
      userPlans: [{ kind: "unchanged" }],
    });
    await expect(service.readManagedSlice(converged)).resolves.toEqual([]);
    await expect(service.applyPlan(converged)).resolves.toBe(0);
    expect(state.writes).toBe(1);
    expect(state.reads).toHaveLength(3);
  });

  it("forwards the required budget to the final Google writer before any mutation", async () => {
    const state = gateway();
    const service = new GoogleGithubIdentitySeedService({
      github: { captureIdentitySeed: async () => githubSnapshot() },
      google: state.google,
      maxChanges: 2,
    });
    const plan = await service.capture([state.user], GOOGLE_FINGERPRINT);
    const denied = vi
      .fn()
      .mockRejectedValue(new Error("identity_budget_exhausted"));
    await expect(
      service.applyPlan(plan, { required: true, reserve: denied }),
    ).rejects.toThrow("identity_budget_exhausted");
    expect(denied).toHaveBeenCalledExactlyOnceWith("10001");
    expect(state.writes).toBe(0);
    const reserve = vi.fn(async () => {
      expect(state.writes).toBe(0);
    });
    await expect(
      service.applyPlan(plan, { required: true, reserve }),
    ).resolves.toBe(1);
    expect(reserve).toHaveBeenCalledExactlyOnceWith("10001");
    expect(state.writes).toBe(1);
  });

  it("fails closed when one Google identity maps to multiple SAML identities", async () => {
    const state = gateway();
    const service = new GoogleGithubIdentitySeedService({
      github: {
        captureIdentitySeed: async () =>
          githubSnapshot({
            members: [
              { id: 9001, login: "octocat", role: "member", type: "User" },
              { id: 9002, login: "other", role: "member", type: "User" },
            ],
            samlExternalIdentities: [
              {
                guid: "saml-1",
                login: "octocat",
                nameId: "person@company.test",
              },
              { guid: "saml-2", login: "other", nameId: "person@company.test" },
            ],
          }),
      },
      google: state.google,
      maxChanges: 2,
    });

    await expect(
      service.capture([state.user], GOOGLE_FINGERPRINT),
    ).resolves.toEqual({
      issues: ["A Google identity maps to multiple GitHub SAML identities"],
      kind: "blocked",
    });
    expect(state.writes).toBe(0);
  });

  it("fails closed when GitHub cannot provide complete first-party identity evidence", async () => {
    const state = gateway();
    const service = new GoogleGithubIdentitySeedService({
      github: {
        captureIdentitySeed: async () =>
          githubSnapshot({
            errors: [
              {
                capability: "saml_external_identities",
                code: "forbidden",
                message: "provider detail must not escape",
              },
            ],
          }),
      },
      google: state.google,
      maxChanges: 2,
    });

    await expect(
      service.capture([state.user], GOOGLE_FINGERPRINT),
    ).resolves.toEqual({
      issues: ["GitHub saml_external_identities snapshot unavailable"],
      kind: "blocked",
    });
  });

  it("blocks PLAN before provider reads when exact updates exceed the mutation cap", async () => {
    let reads = 0;
    let writes = 0;
    const service = new GoogleGithubIdentitySeedService({
      github: { captureIdentitySeed: async () => twoUserGithubSnapshot() },
      google: {
        readUserById: async () => {
          reads++;
          throw new Error("unexpected read");
        },
        updateUser: async () => {
          writes++;
        },
      },
      maxChanges: 1,
      maxProviderReads: 20,
    });

    await expect(
      service.capture([googleUser(), secondGoogleUser()], GOOGLE_FINGERPRINT),
    ).resolves.toEqual({
      issues: ["Google GitHub identity seed requires 2 changes; cap is 1"],
      kind: "blocked",
    });
    expect({ reads, writes }).toEqual({ reads: 0, writes: 0 });
  });

  it("blocks APPLY before provider reads when the runtime mutation cap is lower", async () => {
    let reads = 0;
    let writes = 0;
    const google: GoogleWorkspaceIdentityUserGateway = {
      readUserById: async () => {
        reads++;
        throw new Error("unexpected read");
      },
      updateUser: async () => {
        writes++;
      },
    };
    const github = { captureIdentitySeed: async () => twoUserGithubSnapshot() };
    const plan = await new GoogleGithubIdentitySeedService({
      github,
      google,
      maxChanges: 2,
      maxProviderReads: 20,
    }).capture([googleUser(), secondGoogleUser()], GOOGLE_FINGERPRINT);
    const constrained = new GoogleGithubIdentitySeedService({
      github,
      google,
      maxChanges: 1,
      maxProviderReads: 20,
    });

    await expect(constrained.applyPlan(plan)).rejects.toThrow(
      "change cap exceeded",
    );
    expect({ reads, writes }).toEqual({ reads: 0, writes: 0 });
  });

  it("blocks PLAN when exact APPLY readback would exceed the separate provider-read cap", async () => {
    const service = new GoogleGithubIdentitySeedService({
      github: { captureIdentitySeed: async () => twoUserGithubSnapshot() },
      google: {
        readUserById: async () => {
          throw new Error("unexpected read");
        },
        updateUser: async () => {
          throw new Error("unexpected write");
        },
      },
      maxChanges: 2,
      maxProviderReads: 11,
    });

    await expect(
      service.capture([googleUser(), secondGoogleUser()], GOOGLE_FINGERPRINT),
    ).resolves.toEqual({
      issues: [
        "Google GitHub identity seed requires 12 provider reads; cap is 11",
      ],
      kind: "blocked",
    });
  });
});
