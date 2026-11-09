import { describe, expect, it, vi } from "vitest";
import type { z } from "zod";

import {
  type AuthorityRevision,
  type GitHubLogin,
  type GitHubUserId,
  type GoogleUserId,
  type PrimaryEmail,
  provisioningIdempotencyKey,
} from "../src/catalog/identity-authority.ts";
import {
  DryRunGitHubOrganizationConnector,
  executeGitHubOrganizationOperation,
  executeGitHubOrganizationPlan,
  GitHubBlockedPlanError,
  GitHubDesiredOrganizationAccessSchema,
  GitHubMutationCapabilityError,
  GitHubObservedOrganizationAccountSchema,
  type GitHubOrganizationPort,
  GitHubPlanDriftError,
  type GitHubProvisioningOperation,
  planGitHubOrganizationAccess,
} from "../src/identity-provisioning/github-organization-connector.ts";

const GITHUB_LOGIN = "octocat" as GitHubLogin;
const GITHUB_USER_ID = "583231" as GitHubUserId;
const GOOGLE_USER_ID = "123456789" as GoogleUserId;
const AUTHORITY_DIGEST = "a".repeat(64);
const WRITE_CONTEXT = {
  assertWriteAuthority: async () => undefined,
  assertFreshPlan: () => undefined,
};

function presentDesired() {
  return {
    desiredTeamSlugs: ["engineering", "platform"],
    idempotencyKey: provisioningIdempotencyKey({
      action: "provision",
      authorityDigest: AUTHORITY_DIGEST,
      googleUserId: GOOGLE_USER_ID,
      providerId: "github",
    }),
    kind: "present",
    managedTeamSlugs: ["engineering", "legacy-admins", "platform"],
    organizationRole: "member",
    rehirePolicy: "fresh-least-privilege",
    subject: {
      authorityRevision: "directory:42" as AuthorityRevision,
      isAdmin: false,
      isDelegatedAdmin: false,
      github: {
        githubLogin: GITHUB_LOGIN,
        githubUserId: GITHUB_USER_ID,
        kind: "verified",
        verifiedAt: "2026-08-20T10:00:00.000Z",
      },
      googleUserId: GOOGLE_USER_ID,
      lifecycle: { kind: "active" },
      observedAt: "2026-08-20T10:00:00.000Z",
      primaryEmail: "octocat@company.test" as PrimaryEmail,
    },
  } as const;
}

function absentDesired() {
  return {
    idempotencyKey: provisioningIdempotencyKey({
      action: "deprovision",
      authorityDigest: AUTHORITY_DIGEST,
      googleUserId: GOOGLE_USER_ID,
      providerId: "github",
    }),
    kind: "absent",
    subject: {
      authorityRevision: "directory:43" as AuthorityRevision,
      isAdmin: false,
      isDelegatedAdmin: false,
      github: { kind: "unlinked" },
      googleUserId: GOOGLE_USER_ID,
      lifecycle: { kind: "suspended" },
      observedAt: "2026-08-20T11:00:00.000Z",
      primaryEmail: "octocat@company.test" as PrimaryEmail,
    },
    target: { githubLogin: GITHUB_LOGIN, githubUserId: GITHUB_USER_ID },
  } as const;
}

function observed(
  overrides: Partial<
    z.input<typeof GitHubObservedOrganizationAccountSchema>
  > = {},
) {
  return {
    complete: true,
    directRepositoryGrants: [],
    identity: { githubLogin: GITHUB_LOGIN, githubUserId: GITHUB_USER_ID },
    membership: {
      githubLogin: GITHUB_LOGIN,
      githubUserId: GITHUB_USER_ID,
      role: "member",
    },
    observedAt: "2026-08-20T11:00:00.000Z",
    outsideCollaborator: false,
    pendingInvitations: [],
    repositoryInventoryComplete: true,
    samlLinked: true,
    teamMemberships: [
      {
        githubLogin: GITHUB_LOGIN,
        githubUserId: GITHUB_USER_ID,
        inherited: false,
        role: "member",
        state: "active",
        teamId: 10,
        teamSlug: "legacy-admins",
      },
      {
        githubLogin: GITHUB_LOGIN,
        githubUserId: GITHUB_USER_ID,
        inherited: false,
        role: "member",
        state: "active",
        teamId: 11,
        teamSlug: "engineering",
      },
    ],
    ...overrides,
  };
}

function reviewedGrantFixture() {
  const grant = {
    githubLogin: GITHUB_LOGIN,
    githubUserId: GITHUB_USER_ID,
    permission: "push" as const,
    repositoryId: 99,
    repositoryName: "example/private-service",
  };
  return {
    desired: {
      ...presentDesired(),
      desiredTeamSlugs: ["engineering", "legacy-admins", "platform"],
      reviewedDirectGrantRetention: {
        allowedTeamSlugs: ["platform"],
        githubLogin: GITHUB_LOGIN,
        githubUserId: GITHUB_USER_ID,
        googleUserId: GOOGLE_USER_ID,
        grants: [
          {
            permission: grant.permission,
            repositoryId: grant.repositoryId,
            repositoryName: grant.repositoryName,
          },
        ],
        primaryEmail: "octocat@company.test",
        reviewedAt: "2026-11-04",
      },
    },
    grant,
    snapshot: GitHubObservedOrganizationAccountSchema.parse(
      observed({ directRepositoryGrants: [grant] }),
    ),
  };
}

describe("GitHub organization provisioning connector", () => {
  it("executes only the approved team addition while retaining exact reviewed direct grants", async () => {
    const { desired, snapshot } = reviewedGrantFixture();
    const plan = planGitHubOrganizationAccess(desired, snapshot);
    expect(plan).toMatchObject({
      kind: "executable",
      operations: [
        { kind: "add-team-member", teamSlug: "platform", role: "member" },
      ],
    });
    if (plan.kind !== "executable") throw new Error("fixture");
    const execute = vi.fn(async (operation: GitHubProvisioningOperation) => ({
      kind: operation.kind,
      state: "converged" as const,
    }));
    await executeGitHubOrganizationOperation(
      { capability: "mutating", observeAccount: async () => snapshot, execute },
      desired,
      plan.operations[0],
      async () => desired,
    );
    expect(execute).toHaveBeenCalledExactlyOnceWith(
      plan.operations[0],
      expect.any(Function),
      undefined,
    );
    expect(snapshot.directRepositoryGrants).toEqual([
      reviewedGrantFixture().grant,
    ]);
  });

  it("does not accept an unresolved direct role as an exact reviewed grant", () => {
    const fixture = reviewedGrantFixture();
    const snapshot = observed({
      ...fixture.snapshot,
      directRepositoryGrants: [
        { ...fixture.grant, unresolvedDirectRole: true },
      ],
    });
    expect(
      planGitHubOrganizationAccess(fixture.desired, snapshot),
    ).toMatchObject({
      kind: "blocked",
    });
  });

  it.each([
    "google",
    "github",
    "login",
    "email",
    "repository-id",
    "repository-name",
    "permission",
    "extra-grant",
    "missing-grant",
    "team",
    "removal",
    "invitation",
  ] as const)(
    "refuses a retained-grant addition when the %s boundary changes",
    (boundary) => {
      const fixture = reviewedGrantFixture();
      const review = fixture.desired.reviewedDirectGrantRetention;
      const grant = fixture.grant;
      const desired = {
        ...fixture.desired,
        ...(boundary === "removal" && { desiredTeamSlugs: ["platform"] }),
        reviewedDirectGrantRetention: {
          ...review,
          ...(boundary === "google" && { googleUserId: "99999" }),
          ...(boundary === "github" && { githubUserId: "99999" }),
          ...(boundary === "login" && { githubLogin: "another-user" }),
          ...(boundary === "email" && { primaryEmail: "another@company.test" }),
          ...(boundary === "team" && { allowedTeamSlugs: ["another-team"] }),
        },
      };
      const snapshot = observed({
        ...fixture.snapshot,
        ...(boundary === "invitation" && { membership: null }),
        directRepositoryGrants:
          boundary === "missing-grant"
            ? []
            : [
                {
                  ...grant,
                  ...(boundary === "repository-id" && { repositoryId: 100 }),
                  ...(boundary === "repository-name" && {
                    repositoryName: "example/renamed",
                  }),
                  ...(boundary === "permission" && {
                    permission: "admin" as const,
                  }),
                },
                ...(boundary === "extra-grant"
                  ? [{ ...grant, repositoryId: 101 }]
                  : []),
              ],
      });
      expect(planGitHubOrganizationAccess(desired, snapshot)).toMatchObject({
        kind: "blocked",
        blockers: expect.arrayContaining([
          { code: "direct-repository-grants", detail: expect.any(String) },
        ]),
      });
    },
  );

  it.each([
    "owner",
    "maintainer",
    "saml",
    "inventory",
    "outside",
    "protected",
  ] as const)(
    "retains the %s safeguard after exact direct-grant review",
    (boundary) => {
      const fixture = reviewedGrantFixture();
      const plan = planGitHubOrganizationAccess(
        {
          ...fixture.desired,
          subject: {
            ...fixture.desired.subject,
            isAdmin: boundary === "protected",
          },
        },
        observed({
          ...fixture.snapshot,
          ...(boundary === "owner" && {
            membership: {
              githubLogin: GITHUB_LOGIN,
              githubUserId: GITHUB_USER_ID,
              role: "owner",
            },
          }),
          ...(boundary === "maintainer" && {
            teamMemberships: [
              {
                githubLogin: GITHUB_LOGIN,
                githubUserId: GITHUB_USER_ID,
                inherited: false,
                role: "maintainer",
                state: "active",
                teamId: 10,
                teamSlug: "legacy-admins",
              },
            ],
          }),
          samlLinked: boundary !== "saml",
          repositoryInventoryComplete: boundary !== "inventory",
          outsideCollaborator: boundary === "outside",
        }),
      );
      expect(plan.kind).toBe("blocked");
    },
  );

  it("rejects changed grant review authority before a selected write", async () => {
    const { desired, snapshot } = reviewedGrantFixture();
    const plan = planGitHubOrganizationAccess(desired, snapshot);
    if (plan.kind !== "executable") throw new Error("fixture");
    const execute = vi.fn();
    await expect(
      executeGitHubOrganizationOperation(
        {
          capability: "mutating",
          observeAccount: async () => snapshot,
          execute,
        },
        desired,
        plan.operations[0],
        async () => ({ ...desired, reviewedDirectGrantRetention: undefined }),
      ),
    ).rejects.toBeInstanceOf(GitHubPlanDriftError);
    expect(execute).not.toHaveBeenCalled();
  });

  it.each(["parent", "expiry", "allowed"] as const)(
    "enforces final parent %s state after provider preparation",
    async (decision) => {
      const desired = presentDesired();
      const plan = planGitHubOrganizationAccess(desired, observed());
      if (plan.kind !== "executable") throw new Error("fixture");
      const order: string[] = [];
      const write = vi.fn();
      const port: GitHubOrganizationPort = {
        capability: "mutating",
        observeAccount: async () => observed(),
        execute: async (operation, assertFinalWriteAuthority) => {
          order.push("provider");
          await assertFinalWriteAuthority?.();
          write(operation);
          return { kind: operation.kind, state: "converged" };
        },
      };
      const run = executeGitHubOrganizationOperation(
        port,
        desired,
        plan.operations[0],
        async () => {
          order.push("google");
          return desired;
        },
        { required: true, reserve: async () => undefined },
        {
          assertWriteAuthority: async (actual) => {
            expect(actual).toEqual(plan.operations[0]);
            expect(order.at(-1)).toBe("provider");
            order.push("parent");
            if (decision === "parent") throw new Error("parent_denied");
          },
          assertFreshPlan: () => {
            order.push("expiry");
            if (decision === "expiry") throw new Error("expired");
          },
        },
      );
      let result: string;
      try {
        const receipt = await run;
        result = receipt.state;
      } catch {
        result = "failed";
      }
      expect(result).toBe(decision === "allowed" ? "converged" : "failed");
      expect(write).toHaveBeenCalledTimes(decision === "allowed" ? 1 : 0);
      expect(order.slice(-4)).toEqual(
        decision === "parent"
          ? ["google", "google", "provider", "parent"]
          : ["provider", "parent", "google", "expiry"],
      );
    },
  );
  it("rejects a missing required parent before reservation", async () => {
    const desired = presentDesired();
    const plan = planGitHubOrganizationAccess(desired, observed());
    if (plan.kind !== "executable") throw new Error("fixture");
    const reserve = vi.fn();
    const execute = vi.fn();
    await expect(
      executeGitHubOrganizationOperation(
        {
          capability: "mutating",
          observeAccount: async () => observed(),
          execute,
        },
        desired,
        plan.operations[0],
        async () => desired,
        { required: true, reserve },
      ),
    ).rejects.toThrow("original_parent_context_required");
    expect(reserve).not.toHaveBeenCalled();
    expect(execute).not.toHaveBeenCalled();
  });
  it.each([
    ["missing identity", null],
    ["lifecycle drift", absentDesired()],
    [
      "admin promotion",
      {
        ...presentDesired(),
        subject: { ...presentDesired().subject, isAdmin: true },
      },
    ],
    [
      "missing admin evidence",
      {
        ...presentDesired(),
        subject: { ...presentDesired().subject, isAdmin: undefined },
      },
    ],
    [
      "protected alias",
      {
        ...presentDesired(),
        subject: {
          ...presentDesired().subject,
          aliases: ["root-admin@company.test"],
        },
      },
    ],
    [
      "immutable identity drift",
      {
        ...presentDesired(),
        subject: { ...presentDesired().subject, googleUserId: "987654321" },
      },
    ],
    [
      "GitHub mapping drift",
      {
        ...presentDesired(),
        subject: {
          ...presentDesired().subject,
          github: { ...presentDesired().subject.github, githubUserId: "999" },
        },
      },
    ],
  ])(
    "blocks writer authority %s after provider observation",
    async (_label, refreshed) => {
      const desired = presentDesired();
      const plan = planGitHubOrganizationAccess(desired, observed());
      if (plan.kind !== "executable" || plan.operations[0] === undefined)
        throw new Error("expected operation");
      const order: string[] = [];
      const execute = vi.fn();
      const reserve = vi.fn(async () => undefined);
      const refreshDesired = vi.fn(async (id: string) => {
        expect(id).toBe(GOOGLE_USER_ID);
        order.push("google");
        return refreshed;
      });
      const port: GitHubOrganizationPort = {
        capability: "mutating",
        observeAccount: vi.fn(async () => {
          order.push("github");
          return observed();
        }),
        execute,
      };
      await expect(
        executeGitHubOrganizationOperation(
          port,
          desired,
          plan.operations[0],
          refreshDesired,
          {
            required: true,
            reserve,
          },
        ),
      ).rejects.toBeInstanceOf(GitHubPlanDriftError);
      expect(order).toEqual(["github", "google"]);
      expect(execute).not.toHaveBeenCalled();
      expect(reserve).not.toHaveBeenCalled();
    },
  );

  it.each(["single", "batch"] as const)(
    "blocks a %s writer when its immutable subject budget is exhausted",
    async (kind) => {
      const desired = presentDesired();
      const plan = planGitHubOrganizationAccess(desired, observed());
      if (plan.kind !== "executable")
        throw new Error("expected executable plan");
      const execute = vi.fn();
      const order: string[] = [];
      const refresh = vi.fn(async () => {
        order.push("authority");
        return desired;
      });
      const reserve = vi.fn(async () => {
        order.push("budget");
        throw new Error("identity_budget_exhausted");
      });
      const port: GitHubOrganizationPort = {
        capability: "mutating",
        observeAccount: async () => observed(),
        execute,
      };
      const budget = { required: true as const, reserve };
      await expect(
        kind === "single"
          ? executeGitHubOrganizationOperation(
              port,
              desired,
              plan.operations[0],
              refresh,
              budget,
              WRITE_CONTEXT,
            )
          : executeGitHubOrganizationPlan(port, plan, refresh, budget),
      ).rejects.toThrow("identity_budget_exhausted");
      expect(order).toEqual(["authority", "budget"]);
      expect(reserve).toHaveBeenCalledExactlyOnceWith(GOOGLE_USER_ID);
      expect(execute).not.toHaveBeenCalled();
    },
  );

  it.each(["single", "batch"] as const)(
    "blocks %s mutation when privilege changes during reservation",
    async (kind) => {
      const desired = presentDesired();
      const plan = planGitHubOrganizationAccess(desired, observed());
      if (plan.kind !== "executable")
        throw new Error("expected executable plan");
      let promoted = false;
      const refresh = vi.fn(async () =>
        promoted
          ? { ...desired, subject: { ...desired.subject, isAdmin: true } }
          : desired,
      );
      const reserve = vi.fn(async () => {
        promoted = true;
      });
      const execute = vi.fn();
      const port: GitHubOrganizationPort = {
        capability: "mutating",
        observeAccount: async () => observed(),
        execute,
      };
      const budget = { required: true as const, reserve };
      await expect(
        kind === "single"
          ? executeGitHubOrganizationOperation(
              port,
              desired,
              plan.operations[0],
              refresh,
              budget,
              WRITE_CONTEXT,
            )
          : executeGitHubOrganizationPlan(port, plan, refresh, budget),
      ).rejects.toThrow();
      expect(reserve).toHaveBeenCalledExactlyOnceWith(GOOGLE_USER_ID);
      expect(refresh).toHaveBeenCalledTimes(2);
      expect(execute).not.toHaveBeenCalled();
    },
  );

  it.each(["single", "batch"] as const)(
    "blocks %s mutation when privilege changes during provider preparation",
    async (kind) => {
      const desired = presentDesired();
      const plan = planGitHubOrganizationAccess(desired, observed());
      if (plan.kind !== "executable")
        throw new Error("expected executable plan");
      let promoted = false;
      const refresh = vi.fn(async () =>
        promoted
          ? { ...desired, subject: { ...desired.subject, isAdmin: true } }
          : desired,
      );
      const write = vi.fn();
      const port: GitHubOrganizationPort = {
        capability: "mutating",
        observeAccount: async () => observed(),
        execute: async (operation, assertFinalWriteAuthority) => {
          promoted = true;
          await assertFinalWriteAuthority?.();
          write(operation);
          return { kind: operation.kind, state: "converged" };
        },
      };
      await expect(
        kind === "single"
          ? executeGitHubOrganizationOperation(
              port,
              desired,
              plan.operations[0],
              refresh,
            )
          : executeGitHubOrganizationPlan(port, plan, refresh),
      ).rejects.toBeInstanceOf(GitHubPlanDriftError);
      expect(refresh).toHaveBeenCalledTimes(3);
      expect(write).not.toHaveBeenCalled();
    },
  );

  it("refreshes complete authority before each write and stops a partially applied batch on capture failure", async () => {
    const desired = presentDesired();
    const plan = planGitHubOrganizationAccess(desired, observed());
    if (plan.kind !== "executable" || plan.operations.length < 2)
      throw new Error("expected multiple operations");
    const order: string[] = [];
    const execute = vi.fn(async (operation: GitHubProvisioningOperation) => {
      order.push("write");
      return { kind: operation.kind, state: "converged" as const };
    });
    const refreshDesired = vi.fn(async () => {
      order.push("google");
      if (execute.mock.calls.length > 0)
        throw new Error("contractor_authority_incomplete");
      return desired;
    });
    const port: GitHubOrganizationPort = {
      capability: "mutating",
      observeAccount: vi.fn(async () => observed()),
      execute,
    };
    await expect(
      executeGitHubOrganizationPlan(port, plan, refreshDesired),
    ).rejects.toThrow("contractor_authority_incomplete");
    expect(order).toEqual(["google", "google", "write", "google"]);
    expect(execute).toHaveBeenCalledOnce();
  });

  it.each([
    { primaryEmail: "root-admin@company.test" },
    { aliases: ["root-admin@company.test"] },
    { isAdmin: true },
    { isDelegatedAdmin: true },
    { isAdmin: undefined },
    { isDelegatedAdmin: undefined },
  ])(
    "rejects protected Google authority independently at dispatch: %j",
    async (override) => {
      const original = absentDesired();
      const desired = {
        ...original,
        subject: { ...original.subject, ...override },
      };
      const execute = vi.fn();
      const port: GitHubOrganizationPort = {
        capability: "mutating",
        execute,
        observeAccount: vi.fn(async () => observed()),
      };
      expect(planGitHubOrganizationAccess(desired, observed())).toMatchObject({
        blockers: expect.arrayContaining([
          expect.objectContaining({ code: "protected-google-identity" }),
        ]),
        kind: "blocked",
      });
      await expect(
        executeGitHubOrganizationOperation(
          port,
          desired,
          {
            githubLogin: GITHUB_LOGIN,
            githubUserId: GITHUB_USER_ID,
            kind: "remove-organization-member",
          },
          async () => desired,
        ),
      ).rejects.toBeInstanceOf(GitHubBlockedPlanError);
      expect(execute).not.toHaveBeenCalled();
    },
  );
  it("plans least privilege only inside the explicit managed-team boundary", () => {
    const plan = planGitHubOrganizationAccess(presentDesired(), observed());

    expect(plan).toMatchObject({
      kind: "executable",
      operations: [
        { kind: "add-team-member", role: "member", teamSlug: "platform" },
        { kind: "remove-team-member", teamSlug: "legacy-admins" },
      ],
    });
    if (plan.kind !== "executable") throw new Error("expected executable plan");
    expect(
      plan.operations.every((operation) => !("repositoryName" in operation)),
    ).toBe(true);
  });

  it("preserves unmanaged team membership", () => {
    const plan = planGitHubOrganizationAccess(
      {
        ...presentDesired(),
        managedTeamSlugs: ["engineering", "platform"],
      },
      observed(),
    );

    expect(plan).toMatchObject({
      kind: "executable",
      operations: [{ kind: "add-team-member", teamSlug: "platform" }],
    });
  });

  it("rejects a desired team outside the explicit managed-team boundary", () => {
    expect(() =>
      GitHubDesiredOrganizationAccessSchema.parse({
        ...presentDesired(),
        managedTeamSlugs: ["engineering"],
      }),
    ).toThrow(/explicit managed-team boundary/u);
  });

  it("protects organization owners from automated changes", () => {
    const plan = planGitHubOrganizationAccess(
      absentDesired(),
      observed({
        membership: {
          githubLogin: GITHUB_LOGIN,
          githubUserId: GITHUB_USER_ID,
          role: "owner",
        },
      }),
    );

    expect(plan).toMatchObject({
      blockers: [{ code: "owner-protected" }],
      kind: "blocked",
    });
  });

  it("blocks additive team membership with direct grants before selecting an unwritable operation", () => {
    const plan = planGitHubOrganizationAccess(
      presentDesired(),
      observed({
        directRepositoryGrants: [
          {
            githubLogin: GITHUB_LOGIN,
            githubUserId: GITHUB_USER_ID,
            permission: "push",
            repositoryId: 99,
            repositoryName: "example/private-service",
          },
        ],
      }),
    );

    expect(plan).toMatchObject({
      kind: "blocked",
      blockers: [{ code: "direct-repository-grants" }],
    });
  });

  it("blocks a managed-team removal while direct repository grants remain", () => {
    const plan = planGitHubOrganizationAccess(
      { ...presentDesired(), desiredTeamSlugs: ["engineering"] },
      observed({
        directRepositoryGrants: [
          {
            githubLogin: GITHUB_LOGIN,
            githubUserId: GITHUB_USER_ID,
            permission: "push",
            repositoryId: 99,
            repositoryName: "example/private-service",
          },
        ],
      }),
    );

    expect(plan).toMatchObject({
      blockers: [{ code: "direct-repository-grants" }],
      kind: "blocked",
    });
  });

  it("blocks deprovisioning with direct repository grants for manual review", () => {
    const plan = planGitHubOrganizationAccess(
      absentDesired(),
      observed({
        directRepositoryGrants: [
          {
            githubLogin: GITHUB_LOGIN,
            githubUserId: GITHUB_USER_ID,
            permission: "push",
            repositoryId: 99,
            repositoryName: "example/private-service",
          },
        ],
      }),
    );

    expect(plan).toMatchObject({
      blockers: [{ code: "direct-repository-grants" }],
      kind: "blocked",
    });
  });

  it("blocks additive team membership for maintainers consistently with the writer", () => {
    const plan = planGitHubOrganizationAccess(
      presentDesired(),
      observed({
        teamMemberships: [
          {
            githubLogin: GITHUB_LOGIN,
            githubUserId: GITHUB_USER_ID,
            inherited: false,
            role: "maintainer",
            state: "active",
            teamId: 10,
            teamSlug: "legacy-admins",
          },
        ],
      }),
    );

    expect(plan).toMatchObject({
      kind: "blocked",
      blockers: [{ code: "team-maintainer" }],
    });
  });

  it("continues to block outside collaborators", () => {
    const plan = planGitHubOrganizationAccess(
      presentDesired(),
      observed({ outsideCollaborator: true }),
    );

    expect(plan).toMatchObject({
      blockers: [{ code: "outside-collaborator" }],
      kind: "blocked",
    });
  });

  it.each(["admin", "billing_manager"] as const)(
    "blocks privileged %s invitations",
    (role) => {
      const plan = planGitHubOrganizationAccess(
        absentDesired(),
        observed({
          membership: null,
          pendingInvitations: [
            {
              githubLogin: GITHUB_LOGIN,
              githubUserId: GITHUB_USER_ID,
              invitationId: 71,
              role,
            },
          ],
          teamMemberships: [],
        }),
      );

      expect(plan).toMatchObject({
        blockers: [{ code: "privileged-invitation" }],
        kind: "blocked",
      });
    },
  );

  it("cancels a pending invitation during deprovisioning", () => {
    const plan = planGitHubOrganizationAccess(
      absentDesired(),
      observed({
        membership: null,
        pendingInvitations: [
          {
            githubLogin: GITHUB_LOGIN,
            githubUserId: GITHUB_USER_ID,
            invitationId: 71,
            role: "direct_member",
          },
        ],
        teamMemberships: [],
      }),
    );

    expect(plan).toMatchObject({
      kind: "executable",
      operations: [{ invitationId: 71, kind: "cancel-invitation" }],
    });
  });

  it("removes membership after cancelling ordinary invitations during deprovisioning", () => {
    const plan = planGitHubOrganizationAccess(
      absentDesired(),
      observed({
        pendingInvitations: [
          {
            githubLogin: GITHUB_LOGIN,
            githubUserId: GITHUB_USER_ID,
            invitationId: 71,
            role: "direct_member",
          },
        ],
      }),
    );

    expect(plan).toMatchObject({
      kind: "executable",
      operations: [
        { invitationId: 71, kind: "cancel-invitation" },
        { githubLogin: GITHUB_LOGIN, kind: "remove-organization-member" },
      ],
    });
  });

  it("keeps dry runs non-mutating through an explicit read-only capability", async () => {
    const execute = vi.fn(async (operation: GitHubProvisioningOperation) => ({
      kind: operation.kind,
      state: "converged" as const,
    }));
    const mutatingPort: GitHubOrganizationPort = {
      capability: "mutating",
      execute,
      observeAccount: vi.fn(async () => observed()),
    };
    const port = {
      capability: "read-only" as const,
      observeAccount: mutatingPort.observeAccount.bind(mutatingPort),
    };

    const plan = await new DryRunGitHubOrganizationConnector(port).plan(
      presentDesired(),
    );

    expect(plan.kind).toBe("executable");
    expect(execute).not.toHaveBeenCalled();
  });

  it("requires an explicit mutating capability to execute a plan", async () => {
    const port: GitHubOrganizationPort = {
      capability: "read-only",
      observeAccount: vi.fn(async () => observed()),
    };
    const plan = planGitHubOrganizationAccess(presentDesired(), observed());

    await expect(
      executeGitHubOrganizationPlan(port, plan, async () => presentDesired()),
    ).rejects.toBeInstanceOf(GitHubMutationCapabilityError);
  });

  it("executes exactly one currently planned selected operation", async () => {
    const execute = vi.fn(async (operation: GitHubProvisioningOperation) => ({
      kind: operation.kind,
      state: "converged" as const,
    }));
    const port: GitHubOrganizationPort = {
      capability: "mutating",
      execute,
      observeAccount: vi.fn(async () => observed()),
    };
    const plan = planGitHubOrganizationAccess(presentDesired(), observed());
    if (plan.kind !== "executable") throw new Error("expected executable plan");
    const selected = plan.operations[0];
    if (selected === undefined) throw new Error("expected selected operation");

    await expect(
      executeGitHubOrganizationOperation(
        port,
        presentDesired(),
        selected,
        async () => presentDesired(),
      ),
    ).resolves.toEqual({ kind: selected.kind, state: "converged" });
    expect(execute).toHaveBeenCalledOnce();
    expect(execute).toHaveBeenCalledWith(
      selected,
      expect.any(Function),
      undefined,
    );
  });

  it("rejects a selected operation that disappeared from the fresh plan", async () => {
    const execute = vi.fn(async (operation: GitHubProvisioningOperation) => ({
      kind: operation.kind,
      state: "converged" as const,
    }));
    const initialPlan = planGitHubOrganizationAccess(
      presentDesired(),
      observed(),
    );
    if (initialPlan.kind !== "executable")
      throw new Error("expected executable plan");
    const selected = initialPlan.operations[0];
    if (selected === undefined) throw new Error("expected selected operation");
    const port: GitHubOrganizationPort = {
      capability: "mutating",
      execute,
      observeAccount: vi.fn(async () =>
        observed({
          teamMemberships: [
            {
              githubLogin: GITHUB_LOGIN,
              githubUserId: GITHUB_USER_ID,
              inherited: false,
              role: "member",
              state: "active",
              teamId: 11,
              teamSlug: "engineering",
            },
            {
              githubLogin: GITHUB_LOGIN,
              githubUserId: GITHUB_USER_ID,
              inherited: false,
              role: "member",
              state: "active",
              teamId: 12,
              teamSlug: "platform",
            },
          ],
        }),
      ),
    };

    await expect(
      executeGitHubOrganizationOperation(
        port,
        presentDesired(),
        selected,
        async () => presentDesired(),
      ),
    ).rejects.toBeInstanceOf(GitHubPlanDriftError);
    expect(execute).not.toHaveBeenCalled();
  });

  it("rejects selecting a removal while its replacement addition remains first", async () => {
    const execute = vi.fn(async (operation: GitHubProvisioningOperation) => ({
      kind: operation.kind,
      state: "converged" as const,
    }));
    const port: GitHubOrganizationPort = {
      capability: "mutating",
      execute,
      observeAccount: vi.fn(async () => observed()),
    };
    const plan = planGitHubOrganizationAccess(presentDesired(), observed());
    if (plan.kind !== "executable") throw new Error("expected executable plan");
    const removal = plan.operations.find(
      ({ kind }) => kind === "remove-team-member",
    );
    if (removal === undefined) throw new Error("expected removal operation");

    await expect(
      executeGitHubOrganizationOperation(
        port,
        presentDesired(),
        removal,
        async () => presentDesired(),
      ),
    ).rejects.toBeInstanceOf(GitHubPlanDriftError);
    expect(execute).not.toHaveBeenCalled();
  });

  it("re-observes before mutation so a retried invitation is not duplicated", async () => {
    const execute = vi.fn(async (operation: GitHubProvisioningOperation) => ({
      kind: operation.kind,
      state: "converged" as const,
    }));
    const initial = observed({
      membership: null,
      pendingInvitations: [],
      teamMemberships: [],
    });
    const plan = planGitHubOrganizationAccess(presentDesired(), initial);
    const port: GitHubOrganizationPort = {
      capability: "mutating",
      execute,
      observeAccount: vi.fn(async () =>
        observed({
          membership: null,
          pendingInvitations: [
            {
              githubLogin: GITHUB_LOGIN,
              githubUserId: GITHUB_USER_ID,
              invitationId: 71,
              role: "direct_member",
            },
          ],
          teamMemberships: [],
        }),
      ),
    };

    await expect(
      executeGitHubOrganizationPlan(port, plan, async () => presentDesired()),
    ).rejects.toBeInstanceOf(GitHubBlockedPlanError);
    expect(execute).not.toHaveBeenCalled();
  });

  it("rejects newly observed unsafe access before applying an approved snapshot", async () => {
    const execute = vi.fn(async (operation: GitHubProvisioningOperation) => ({
      kind: operation.kind,
      state: "converged" as const,
    }));
    const plan = planGitHubOrganizationAccess(absentDesired(), observed());
    const port: GitHubOrganizationPort = {
      capability: "mutating",
      execute,
      observeAccount: vi.fn(async () =>
        observed({
          directRepositoryGrants: [
            {
              githubLogin: GITHUB_LOGIN,
              githubUserId: GITHUB_USER_ID,
              permission: "push",
              repositoryId: 99,
              repositoryName: "example/private-service",
            },
          ],
        }),
      ),
    };

    await expect(
      executeGitHubOrganizationPlan(port, plan, async () => absentDesired()),
    ).rejects.toBeInstanceOf(GitHubBlockedPlanError);
    expect(execute).not.toHaveBeenCalled();
  });

  it("rejects mixed immutable identities at the API boundary", () => {
    expect(() =>
      GitHubObservedOrganizationAccountSchema.parse(
        observed({
          teamMemberships: [
            {
              githubLogin: "different-user",
              githubUserId: GITHUB_USER_ID,
              inherited: false,
              role: "member",
              state: "active",
              teamId: 12,
              teamSlug: "platform",
            },
          ],
        }),
      ),
    ).toThrow(/Every observation must match its account key/u);
  });

  it("rejects a GitHub desired-access key borrowed from another Google subject", () => {
    expect(() =>
      GitHubDesiredOrganizationAccessSchema.parse({
        ...presentDesired(),
        idempotencyKey: `identity:v1:99999:github:provision:${"a".repeat(64)}`,
      }),
    ).toThrow(/bound to the immutable Google subject/u);
  });

  it("blocks team changes until the active member has a linked SAML identity", () => {
    const plan = planGitHubOrganizationAccess(
      presentDesired(),
      observed({ samlLinked: false }),
    );
    expect(plan).toMatchObject({
      blockers: [expect.objectContaining({ code: "saml-unlinked" })],
      kind: "blocked",
    });
  });

  it("waits for a pending desired team membership rather than selecting another add", () => {
    const snapshot = observed({
      teamMemberships: [
        {
          githubLogin: GITHUB_LOGIN,
          githubUserId: GITHUB_USER_ID,
          inherited: false,
          role: "member",
          state: "pending",
          teamId: 17,
          teamSlug: "engineering",
        },
      ],
    });
    const plan = planGitHubOrganizationAccess(presentDesired(), snapshot);
    expect(plan).toMatchObject({
      kind: "blocked",
      blockers: [expect.objectContaining({ code: "pending-team-membership" })],
    });
    const removal = planGitHubOrganizationAccess(absentDesired(), snapshot);
    expect(removal).toMatchObject({
      kind: "executable",
      operations: [
        {
          githubLogin: GITHUB_LOGIN,
          githubUserId: GITHUB_USER_ID,
          kind: "remove-organization-member",
        },
      ],
    });
  });

  it("preserves desired active inherited access without attempting to rewrite it", () => {
    const desired = { ...presentDesired(), desiredTeamSlugs: ["engineering"] };
    const plan = planGitHubOrganizationAccess(
      desired,
      observed({
        teamMemberships: [
          {
            githubLogin: GITHUB_LOGIN,
            githubUserId: GITHUB_USER_ID,
            inherited: true,
            role: "member",
            state: "active",
            teamId: 17,
            teamSlug: "engineering",
          },
        ],
      }),
    );
    expect(plan).toMatchObject({ kind: "executable", operations: [] });
  });

  it("reports a pending invitation as awaiting acceptance instead of converged access", () => {
    const plan = planGitHubOrganizationAccess(
      presentDesired(),
      observed({
        membership: null,
        pendingInvitations: [
          {
            githubLogin: GITHUB_LOGIN,
            githubUserId: GITHUB_USER_ID,
            invitationId: 72,
            role: "direct_member",
          },
        ],
        samlLinked: false,
        teamMemberships: [],
      }),
    );
    expect(plan).toMatchObject({
      blockers: [expect.objectContaining({ code: "pending-invitation" })],
      kind: "blocked",
    });
  });

  it.each([
    ["managed presence", presentDesired()],
    ["organization removal", absentDesired()],
  ] as const)(
    "blocks %s without complete all-repository coverage",
    (_label, desired) => {
      const plan = planGitHubOrganizationAccess(
        desired,
        observed({ repositoryInventoryComplete: false }),
      );
      expect(plan).toMatchObject({
        blockers: [
          expect.objectContaining({ code: "repository-inventory-incomplete" }),
        ],
        kind: "blocked",
      });
    },
  );

  it("protects maintainers of unmanaged teams during organization removal", () => {
    const plan = planGitHubOrganizationAccess(
      absentDesired(),
      observed({
        teamMemberships: [
          {
            githubLogin: GITHUB_LOGIN,
            githubUserId: GITHUB_USER_ID,
            inherited: false,
            role: "maintainer",
            state: "active",
            teamId: 99,
            teamSlug: "unmanaged-security",
          },
        ],
      }),
    );
    expect(plan).toMatchObject({
      blockers: [expect.objectContaining({ code: "team-maintainer" })],
      kind: "blocked",
    });
  });

  it("blocks direct removal of membership inherited from a child team", () => {
    const plan = planGitHubOrganizationAccess(
      presentDesired(),
      observed({
        teamMemberships: [
          {
            githubLogin: GITHUB_LOGIN,
            githubUserId: GITHUB_USER_ID,
            inherited: true,
            role: "member",
            state: "active",
            teamId: 10,
            teamSlug: "legacy-admins",
          },
        ],
      }),
    );
    expect(plan).toMatchObject({
      blockers: [
        expect.objectContaining({ code: "inherited-team-membership" }),
      ],
      kind: "blocked",
    });
  });
});

it("blocks opaque invitation evidence without inventing a cancellable invitation", () => {
  const plan = planGitHubOrganizationAccess(
    GitHubDesiredOrganizationAccessSchema.parse(absentDesired()),
    observed({
      membership: null,
      pendingInvitations: [],
      teamMemberships: [],
      unresolvedInvitations: "opaque-direct",
    }),
  );
  expect(plan).toMatchObject({
    kind: "blocked",
    blockers: [expect.objectContaining({ code: "pending-invitation" })],
  });
  expect(plan).not.toHaveProperty("operations");
});
it("does not tolerate opaque invitations for known-member deprovisioning", () => {
  const plan = planGitHubOrganizationAccess(
    GitHubDesiredOrganizationAccessSchema.parse(absentDesired()),
    observed({ unresolvedInvitations: "opaque-direct" }),
  );
  expect(plan).toMatchObject({
    kind: "blocked",
    blockers: [expect.objectContaining({ code: "pending-invitation" })],
  });
});
it("retains only known-member additive team reconciliation with ordinary opaque evidence", () => {
  const plan = planGitHubOrganizationAccess(
    GitHubDesiredOrganizationAccessSchema.parse(presentDesired()),
    observed({ teamMemberships: [], unresolvedInvitations: "opaque-direct" }),
  );
  expect(plan).toMatchObject({ kind: "executable" });
});
