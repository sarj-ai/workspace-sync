import { describe, expect, it, vi } from "vitest";
import { z } from "zod";

import type {
  GitHubLogin,
  GitHubUserId,
} from "../src/catalog/identity-authority.ts";
import type { ReviewedGitHubDirectGrantRetention } from "../src/github-access-audit/reviewed-direct-grants.ts";
import {
  assertDistinctGitHubOrganizationCredentials,
  assertTrustedGithubZeroDispatchProof,
  GitHubCredentialSeparationError,
  GitHubIdentityPinError,
  GitHubMutationReadbackError,
  GitHubOrganizationApiPort,
  GitHubOrganizationBoundExceededError,
  GitHubOrganizationPinError,
  GitHubOrganizationScopeError,
  GitHubPreWriteSafetyError,
  GitHubRequestTransportError,
  GitHubUnresolvedPrivilegedInvitationError,
  GitHubWriterTenantResponseError,
  takeGithubZeroDispatchProof,
} from "../src/identity-provisioning/github-organization-api-port.ts";
import {
  GitHubProvisioningOperationSchema,
  readOnlyGitHubOrganizationPort,
} from "../src/identity-provisioning/github-organization-connector.ts";
import { sha256Hex } from "../src/operations/canonical.ts";
import { JsonValueSchema } from "../src/operations/schemas.ts";
import { isString } from "./support/value-guards.ts";

const GITHUB_LOGIN = "octocat" as GitHubLogin;
const GITHUB_USER_ID = "583231" as GitHubUserId;
const GITHUB_API = "https://api.github.com";
const OrganizationOverrideSchema = z.union([
  z.record(z.string(), z.unknown()),
  z.array(z.unknown()),
]);

function json(value: unknown, status = 200): Response {
  return Response.json(value, { status });
}

function empty(status = 204): Response {
  return new Response(null, { status });
}

function pathOf(input: RequestInfo | URL): string {
  if (isString(input)) return new URL(input).href;
  if (input instanceof URL) return input.href;
  return new URL(input.url).href;
}

interface StandardFetchValues {
  directCollaborators: unknown[];
  directPermissionSource?: { permission: string; roleName: string };
  invitations: unknown[];
  membership: unknown;
  organization: unknown;
  outside: boolean;
  repositories: unknown[];
  samlLinked: boolean;
  teamMembership: unknown;
  user: unknown;
}

function standardRead(url: string, values: StandardFetchValues): Response {
  const exactResponses: Readonly<Record<string, () => Response>> = {
    [`${GITHUB_API}/orgs/example`]: () => json(values.organization),
    [`${GITHUB_API}/orgs/example/memberships/octocat`]: () =>
      values.membership === null ? empty(404) : json(values.membership),
    [`${GITHUB_API}/orgs/example/outside_collaborators/octocat`]: () =>
      empty(values.outside ? 204 : 404),
    [`${GITHUB_API}/orgs/example/teams/engineering`]: () =>
      json({ id: 17, slug: "engineering" }),
    [`${GITHUB_API}/orgs/example/teams/engineering/memberships/octocat`]: () =>
      values.teamMembership === null ? empty(404) : json(values.teamMembership),
    [`${GITHUB_API}/users/octocat`]: () => json(values.user),
  };
  const exactResponse = exactResponses[url];
  if (exactResponse !== undefined) return exactResponse();
  if (url.startsWith(`${GITHUB_API}/orgs/example/invitations?`))
    return json(values.invitations);
  if (url.startsWith(`${GITHUB_API}/orgs/example/repos?`))
    return json(values.repositories);
  if (url.startsWith(`${GITHUB_API}/orgs/example/teams?`))
    return json([{ id: 17, slug: "engineering" }]);
  if (url.includes("/teams/engineering/members?"))
    return json(
      values.teamMembership === null
        ? []
        : [{ id: 583231, inherited: false, login: GITHUB_LOGIN }],
    );
  if (url.includes("/collaborators?affiliation=direct"))
    return json(values.directCollaborators);
  return empty(404);
}

function fixtureDirectRole(flags: {
  admin?: boolean | undefined;
  maintain?: boolean | undefined;
  push?: boolean | undefined;
  triage?: boolean | undefined;
}) {
  if (flags.admin) return { permission: "ADMIN", roleName: "admin" };
  if (flags.maintain) return { permission: "WRITE", roleName: "maintain" };
  if (flags.push) return { permission: "WRITE", roleName: "write" };
  if (flags.triage) return { permission: "READ", roleName: "triage" };
  return { permission: "READ", roleName: "read" };
}

function standardGraphqlRead(
  init: RequestInit | undefined,
  values: StandardFetchValues,
): Response {
  const payload = isString(init?.body)
    ? (JSON.parse(init.body) as {
        query?: unknown;
        variables?: { name?: string };
      })
    : {};
  if (
    isString(payload.query) &&
    payload.query.includes("GitHubDirectRepositoryPermissionSources")
  ) {
    const repositoryName = z.string().parse(payload.variables?.name);
    const repository = z
      .array(z.object({ id: z.number(), "full_name": z.string() }))
      .parse(values.repositories)
      .find((item) => item["full_name"] === `example/${repositoryName}`);
    const collaborators = z
      .array(
        z.object({
          id: z.number(),
          login: z.string(),
          permissions: z.object({
            admin: z.boolean().optional(),
            maintain: z.boolean().optional(),
            pull: z.boolean().optional(),
            push: z.boolean().optional(),
            triage: z.boolean().optional(),
          }),
        }),
      )
      .parse(values.directCollaborators);
    return json({
      data: {
        repository: {
          databaseId: repository?.id,
          nameWithOwner: repository?.["full_name"],
          collaborators: {
            edges: collaborators.map((item) => ({
              node: { databaseId: item.id, login: item.login },
              permissionSources: [
                {
                  ...(values.directPermissionSource ??
                    fixtureDirectRole(item.permissions)),
                  source: {
                    kind: "Repository",
                    databaseId: repository?.id,
                    nameWithOwner: repository?.["full_name"],
                  },
                },
              ],
            })),
            pageInfo: { endCursor: null, hasNextPage: false },
          },
        },
      },
    });
  }
  if (
    !isString(payload.query) ||
    !payload.query.includes("externalIdentities") ||
    !payload.query.includes("databaseId")
  ) {
    return json({ message: "unsupported GraphQL query shape" }, 400);
  }
  return json({
    data: {
      organization: {
        samlIdentityProvider: {
          externalIdentities: {
            nodes: values.samlLinked
              ? [
                  {
                    samlIdentity: { nameId: "octocat@company.test" },
                    user: { databaseId: 583231, login: GITHUB_LOGIN },
                  },
                ]
              : [],
            pageInfo: { endCursor: null, hasNextPage: false },
          },
        },
      },
    },
  });
}

function standardFetch(overrides: Partial<StandardFetchValues> = {}) {
  const repositories = overrides.repositories ?? [];
  const organization = OrganizationOverrideSchema.safeParse(
    overrides.organization,
  );
  const organizationFields = organization.success
    ? Object.fromEntries(Object.entries(organization.data))
    : {};
  const values = {
    directCollaborators: [],
    invitations: [],
    membership: {
      role: "member",
      state: "active",
      user: { id: 583231, login: GITHUB_LOGIN },
    },
    outside: false,
    repositories,
    samlLinked: true,
    teamMembership: { role: "member", state: "active" },
    user: { id: 583231, login: GITHUB_LOGIN },
    ...overrides,
    organization: {
      id: 100000001,
      login: "example",
      "owned_private_repos": repositories.length,
      "public_repos": 0,
      ...organizationFields,
    },
  };
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = pathOf(input);
    const method = init?.method ?? "GET";
    if (method === "GET") return standardRead(url, values);
    if (method === "POST" && url === `${GITHUB_API}/graphql`)
      return standardGraphqlRead(init, values);
    if (method === "PUT" || method === "DELETE")
      return empty(method === "PUT" ? 200 : 204);
    return empty(404);
  });
}

function port(
  fetchImpl: typeof fetch,
  options: {
    managedTeamPins?: Readonly<Record<string, number>>;
    maxPages?: number;
    maxRequests?: number;
    reviewedDirectGrantRetentions?: readonly ReviewedGitHubDirectGrantRetention[];
  } = {},
) {
  return new GitHubOrganizationApiPort({
    fetchImpl,
    managedTeamSlugs: ["engineering"],
    organizationId: "100000001",
    organizationLogin: "example",
    samlToken: "test-saml-reader-token",
    token: "test-token",
    ...options,
  });
}

describe("GitHubOrganizationApiPort", () => {
  const retainedGrantReview = {
    allowedTeamSlugs: ["engineering"],
    githubLogin: GITHUB_LOGIN,
    githubUserId: GITHUB_USER_ID,
    googleUserId: "123456789",
    primaryEmail: "octocat@company.test",
    reviewedAt: "2026-11-04",
    grants: [
      {
        repositoryId: 99,
        repositoryName: "example/legacy",
        permission: "push" as const,
      },
    ],
  };
  const reviewedAddition = GitHubProvisioningOperationSchema.parse({
    githubLogin: GITHUB_LOGIN,
    githubUserId: GITHUB_USER_ID,
    kind: "add-team-member",
    role: "member",
    teamSlug: "engineering",
  });
  const retainedCollaborator = {
    id: Number(GITHUB_USER_ID),
    login: GITHUB_LOGIN,
    permissions: { admin: false, pull: true, push: true },
  };

  it("rechecks exact retained grants before one guarded team write and provider readback", async () => {
    const fetchImpl = standardFetch({
      repositories: [{ "full_name": "example/legacy", id: 99 }],
      directCollaborators: [retainedCollaborator],
    });
    const guard = vi.fn(async () => undefined);
    await expect(
      port(fetchImpl, {
        reviewedDirectGrantRetentions: [retainedGrantReview],
      }).execute(reviewedAddition, guard),
    ).resolves.toEqual({ kind: "add-team-member", state: "converged" });
    expect(guard).toHaveBeenCalledOnce();
    expect(
      fetchImpl.mock.calls.filter(([, init]) =>
        ["PUT", "DELETE"].includes(init?.method ?? "GET"),
      ),
    ).toEqual([
      [
        `${GITHUB_API}/orgs/example/teams/engineering/memberships/octocat`,
        expect.objectContaining({
          method: "PUT",
          body: JSON.stringify({ role: "member" }),
        }),
      ],
    ]);
    expect(
      fetchImpl.mock.calls.some(([input]) =>
        pathOf(input).includes("/collaborators?affiliation=direct"),
      ),
    ).toBe(true);
  });

  it("retains a direct write grant when the REST flags reflect inherited administrator access", async () => {
    const fetchImpl = standardFetch({
      repositories: [{ "full_name": "example/legacy", id: 99 }],
      directCollaborators: [
        {
          ...retainedCollaborator,
          permissions: { admin: true, pull: true, push: true },
        },
      ],
      directPermissionSource: { permission: "WRITE", roleName: "write" },
    });
    await expect(
      port(fetchImpl, {
        reviewedDirectGrantRetentions: [retainedGrantReview],
      }).execute(reviewedAddition, async () => undefined),
    ).resolves.toEqual({ kind: "add-team-member", state: "converged" });
  });

  it("keeps account observation independent of unrelated collaborators permission-source reads", async () => {
    const fetchImpl = standardFetch({
      repositories: [{ "full_name": "example/legacy", id: 99 }],
      directCollaborators: [
        { ...retainedCollaborator, id: 123, login: "another" },
      ],
    });
    const observed = await port(fetchImpl).observeAccount({
      githubLogin: GITHUB_LOGIN,
      githubUserId: GITHUB_USER_ID,
    });
    expect(observed.directRepositoryGrants).toEqual([]);
    expect(
      fetchImpl.mock.calls.some(
        ([, init]) =>
          isString(init?.body) &&
          init.body.includes("GitHubDirectRepositoryPermissionSources"),
      ),
    ).toBe(false);
  });

  it("retains the exact reviewed custom role", async () => {
    const fetchImpl = standardFetch({
      repositories: [{ "full_name": "example/legacy", id: 99 }],
      directCollaborators: [retainedCollaborator],
      directPermissionSource: {
        permission: "WRITE",
        roleName: "Write + Force",
      },
    });
    const reviewed = {
      ...retainedGrantReview,
      grants: retainedGrantReview.grants.map((grant) => ({
        ...grant,
        customRoleName: "Write + Force",
      })),
    };
    await expect(
      port(fetchImpl, { reviewedDirectGrantRetentions: [reviewed] }).execute(
        reviewedAddition,
        async () => undefined,
      ),
    ).resolves.toEqual({ kind: "add-team-member", state: "converged" });
  });

  it.each(["Different custom role", "write"])(
    "rejects a changed custom role with the same write base: %s",
    async (roleName) => {
      const fetchImpl = standardFetch({
        repositories: [{ "full_name": "example/legacy", id: 99 }],
        directCollaborators: [retainedCollaborator],
        directPermissionSource: { permission: "WRITE", roleName },
      });
      const reviewed = {
        ...retainedGrantReview,
        grants: retainedGrantReview.grants.map((grant) => ({
          ...grant,
          customRoleName: "Write + Force",
        })),
      };
      const guard = vi.fn(async () => undefined);
      await expect(
        port(fetchImpl, { reviewedDirectGrantRetentions: [reviewed] }).execute(
          reviewedAddition,
          guard,
        ),
      ).rejects.toBeInstanceOf(GitHubPreWriteSafetyError);
      expect(guard).not.toHaveBeenCalled();
      expect(
        fetchImpl.mock.calls.filter(([, init]) => init?.method === "PUT"),
      ).toHaveLength(0);
    },
  );

  it.each([
    "permission",
    "repository-id",
    "missing",
    "extra",
    "team",
    "no-guard",
    "no-review",
  ] as const)(
    "refuses retained direct-grant writes when %s changes at the provider boundary",
    async (boundary) => {
      const fetchImpl = standardFetch({
        repositories: [
          {
            "full_name": "example/legacy",
            id: boundary === "repository-id" ? 100 : 99,
          },
          ...(boundary === "extra"
            ? [{ "full_name": "example/extra", id: 101 }]
            : []),
        ],
        directCollaborators:
          boundary === "missing"
            ? []
            : [
                {
                  ...retainedCollaborator,
                  permissions: {
                    ...retainedCollaborator.permissions,
                    admin: boundary === "permission",
                  },
                },
              ],
      });
      const guard = vi.fn(async () => undefined);
      await expect(
        port(fetchImpl, {
          reviewedDirectGrantRetentions:
            boundary === "no-review"
              ? []
              : [
                  {
                    ...retainedGrantReview,
                    allowedTeamSlugs:
                      boundary === "team" ? ["other-team"] : ["engineering"],
                  },
                ],
        }).execute(
          reviewedAddition,
          boundary === "no-guard" ? undefined : guard,
        ),
      ).rejects.toBeInstanceOf(GitHubPreWriteSafetyError);
      expect(guard).not.toHaveBeenCalled();
      expect(
        fetchImpl.mock.calls.filter(([, init]) =>
          ["PUT", "DELETE"].includes(init?.method ?? "GET"),
        ),
      ).toHaveLength(0);
    },
  );

  it("preserves the native global receiver for the default Workers fetch", async () => {
    const runtimeFetch = vi.fn(function (
      this: unknown,
      input: RequestInfo | URL,
    ) {
      expect(this).toBe(globalThis);
      expect(pathOf(input)).toBe(`${GITHUB_API}/orgs/example`);
      return Promise.resolve(json({ id: 100000001, login: "example" }));
    });
    vi.stubGlobal("fetch", runtimeFetch);
    try {
      const organizationPort = new GitHubOrganizationApiPort({
        managedTeamSlugs: ["engineering"],
        organizationId: "100000001",
        organizationLogin: "example",
        samlToken: "test-saml-reader-token",
        token: "test-token",
      });
      await expect(
        organizationPort.verifyWriterTenant(),
      ).resolves.toBeUndefined();
      expect(runtimeFetch).toHaveBeenCalledOnce();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it.each(
    [307, 308].flatMap((status) =>
      ["GET", "POST", "PUT", "DELETE"].map((method) => ({ method, status })),
    ),
  )(
    "rejects $status redirects for authenticated $method requests",
    async ({ method, status }) => {
      const regular = standardFetch();
      const redirect = vi.fn(() =>
        Response.redirect("https://unapproved.example/access", status),
      );
      const fetchImpl = vi.fn<typeof fetch>(async (input, init) => {
        const requestMethod = init?.method ?? "GET";
        const matches =
          requestMethod === method &&
          (method !== "GET" || pathOf(input) === `${GITHUB_API}/orgs/example`);
        return matches ? redirect() : regular(input, init);
      });

      await expect(
        port(fetchImpl).execute(
          GitHubProvisioningOperationSchema.parse({
            githubLogin: GITHUB_LOGIN,
            githubUserId: GITHUB_USER_ID,
            kind:
              method === "DELETE" ? "remove-team-member" : "add-team-member",
            ...(!(method === "DELETE") && { role: "member" }),
            teamSlug: "engineering",
          }),
        ),
      ).rejects.toThrow(String(status));
      expect(redirect).toHaveBeenCalledOnce();
      expect(
        fetchImpl.mock.calls.every(
          ([input, init]) =>
            new URL(pathOf(input)).origin === GITHUB_API &&
            init?.redirect === "manual",
        ),
      ).toBe(true);
    },
  );

  it("rejects reuse of one nonempty credential for SAML reads and REST writes", async () => {
    await expect(
      assertDistinctGitHubOrganizationCredentials(
        "same-nonempty-token",
        "same-nonempty-token",
      ),
    ).rejects.toBeInstanceOf(GitHubCredentialSeparationError);
  });

  it("verifies the writer tenant with one read and no inventory or mutation", async () => {
    const fetchImpl = standardFetch();

    await expect(port(fetchImpl).verifyWriterTenant()).resolves.toBeUndefined();

    expect(fetchImpl).toHaveBeenCalledOnce();
    const call = fetchImpl.mock.calls[0];
    if (call === undefined) throw new Error("Expected one writer tenant probe");
    const [input, init] = call;
    expect(pathOf(input)).toBe(`${GITHUB_API}/orgs/example`);
    expect(init?.method).toBe("GET");
    expect(init?.redirect).toBe("manual");
    expect(new Headers(init?.headers).get("authorization")).toBe(
      "Bearer test-token",
    );
  });

  it("rejects identical credentials before any provider request or write", async () => {
    const fetchImpl = standardFetch();
    const organizationPort = new GitHubOrganizationApiPort({
      fetchImpl,
      managedTeamSlugs: ["engineering"],
      organizationId: "100000001",
      organizationLogin: "example",
      samlToken: "same-nonempty-token",
      token: "same-nonempty-token",
    });

    await expect(
      organizationPort.execute(
        GitHubProvisioningOperationSchema.parse({
          githubLogin: GITHUB_LOGIN,
          githubUserId: GITHUB_USER_ID,
          kind: "remove-organization-member",
        }),
      ),
    ).rejects.toBeInstanceOf(GitHubCredentialSeparationError);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("rejects identical credentials before direct or connector-wrapped observation", async () => {
    const fetchImpl = standardFetch();
    const organizationPort = new GitHubOrganizationApiPort({
      fetchImpl,
      managedTeamSlugs: ["engineering"],
      organizationId: "100000001",
      organizationLogin: "example",
      samlToken: "same-nonempty-token",
      token: "same-nonempty-token",
    });
    const identity = {
      githubLogin: GITHUB_LOGIN,
      githubUserId: GITHUB_USER_ID,
    };

    await expect(
      organizationPort.observeAccount(identity),
    ).rejects.toBeInstanceOf(GitHubCredentialSeparationError);
    await expect(
      readOnlyGitHubOrganizationPort(organizationPort).observeAccount({
        ...identity,
        primaryEmail: "octocat@company.test",
      }),
    ).rejects.toBeInstanceOf(GitHubCredentialSeparationError);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("retries a transient writer tenant probe instead of poisoning the adapter instance", async () => {
    const reads = standardFetch();
    let failedOnce = false;
    const fetchImpl = vi.fn<typeof fetch>(async (input, init) => {
      const writerTenantProbe =
        pathOf(input) === `${GITHUB_API}/orgs/example` &&
        init?.method === "GET" &&
        new Headers(init.headers).get("authorization") === "Bearer test-token";
      if (writerTenantProbe && !failedOnce) {
        failedOnce = true;
        return empty(503);
      }
      return reads(input, init);
    });
    const organizationPort = port(fetchImpl);
    const identity = {
      githubLogin: GITHUB_LOGIN,
      githubUserId: GITHUB_USER_ID,
    };

    await expect(organizationPort.observeAccount(identity)).rejects.toThrow(
      "503",
    );
    await expect(
      organizationPort.observeAccount(identity),
    ).resolves.toMatchObject({
      complete: true,
      identity,
    });
  });

  it("uses the audit credential for every provider read and the writer only for its tenant probe", async () => {
    const reads = standardFetch();
    const fetchImpl = vi.fn<typeof fetch>(async (input, init) => {
      const writerTenantProbe =
        pathOf(input) === `${GITHUB_API}/orgs/example` &&
        init?.method === "GET" &&
        new Headers(init.headers).get("authorization") === "Bearer test-token";
      if (writerTenantProbe) return json({ id: 100000001, login: "example" });
      return reads(input, init);
    });

    await port(fetchImpl).observeAccount({
      githubLogin: GITHUB_LOGIN,
      githubUserId: GITHUB_USER_ID,
    });

    const graphqlCall = fetchImpl.mock.calls.find(
      ([input, init]) =>
        pathOf(input) === `${GITHUB_API}/graphql` && init?.method === "POST",
    );
    expect(graphqlCall).toBeDefined();
    const graphqlBody = graphqlCall?.[1]?.body;
    expect(isString(graphqlBody)).toBe(true);
    if (!isString(graphqlBody))
      throw new Error("expected GraphQL request body");
    const payload = JSON.parse(graphqlBody) as { query: string };
    expect(payload.query).toContain("externalIdentities");
    expect(payload.query).toContain("databaseId");
    expect(new Headers(graphqlCall?.[1]?.headers).get("authorization")).toBe(
      "Bearer test-saml-reader-token",
    );
    const organizationCalls = fetchImpl.mock.calls.filter(
      ([input, init]) =>
        pathOf(input) === `${GITHUB_API}/orgs/example` &&
        init?.method === "GET",
    );
    expect(
      organizationCalls.map(([, init]) =>
        new Headers(init?.headers).get("authorization"),
      ),
    ).toEqual(["Bearer test-token", "Bearer test-saml-reader-token"]);
    expect(
      fetchImpl.mock.calls
        .filter(
          ([, init]) => !["DELETE", "PUT"].includes(init?.method ?? "GET"),
        )
        .slice(1)
        .every(
          ([, init]) =>
            new Headers(init?.headers).get("authorization") ===
            "Bearer test-saml-reader-token",
        ),
    ).toBe(true);
  });

  it("fails closed when a managed team slug resolves to a different immutable team ID", async () => {
    await expect(
      port(standardFetch(), {
        managedTeamPins: { engineering: 999 },
      }).observeAccount({
        githubLogin: GITHUB_LOGIN,
        githubUserId: GITHUB_USER_ID,
      }),
    ).rejects.toBeInstanceOf(GitHubOrganizationScopeError);
  });

  it("captures the exact pinned identity and only the configured managed teams", async () => {
    const fetchImpl = standardFetch({
      directCollaborators: [
        {
          id: 583231,
          login: GITHUB_LOGIN,
          permissions: {
            admin: false,
            maintain: false,
            pull: true,
            push: true,
            triage: false,
          },
        },
      ],
      invitations: [
        {
          id: 71,
          invitee: { id: 583231, login: GITHUB_LOGIN },
          role: "billing_manager",
        },
      ],
      outside: true,
      repositories: [{ "full_name": "example/private-service", id: 99 }],
      teamMembership: { role: "maintainer", state: "active" },
    });

    await expect(
      port(fetchImpl).observeAccount({
        githubLogin: GITHUB_LOGIN,
        githubUserId: GITHUB_USER_ID,
      }),
    ).resolves.toMatchObject({
      complete: true,
      directRepositoryGrants: [{ permission: "push", repositoryId: 99 }],
      identity: { githubLogin: GITHUB_LOGIN, githubUserId: GITHUB_USER_ID },
      outsideCollaborator: true,
      pendingInvitations: [{ invitationId: 71, role: "billing_manager" }],
      teamMemberships: [
        { role: "maintainer", teamId: 17, teamSlug: "engineering" },
      ],
    });
    expect(
      fetchImpl.mock.calls.some(([input]) =>
        pathOf(input).includes("/teams/engineering"),
      ),
    ).toBe(true);
  });

  it("preserves pending team membership without requiring an active-member listing", async () => {
    const fetchImpl = standardFetch({
      teamMembership: { role: "member", state: "pending" },
    });

    await expect(
      port(fetchImpl).observeAccount({
        githubLogin: GITHUB_LOGIN,
        githubUserId: GITHUB_USER_ID,
      }),
    ).resolves.toMatchObject({
      teamMemberships: [
        expect.objectContaining({
          inherited: false,
          state: "pending",
          teamSlug: "engineering",
        }),
      ],
    });
    expect(
      fetchImpl.mock.calls.some(([input]) =>
        pathOf(input).includes("/teams/engineering/members?"),
      ),
    ).toBe(false);
  });

  it("fails closed when either immutable organization pin changes", async () => {
    await expect(
      port(
        standardFetch({ organization: { id: 99, login: "example" } }),
      ).observeAccount({
        githubLogin: GITHUB_LOGIN,
        githubUserId: GITHUB_USER_ID,
      }),
    ).rejects.toBeInstanceOf(GitHubOrganizationPinError);
    await expect(
      port(
        standardFetch({ organization: { id: 100000001, login: "other-org" } }),
      ).observeAccount({
        githubLogin: GITHUB_LOGIN,
        githubUserId: GITHUB_USER_ID,
      }),
    ).rejects.toBeInstanceOf(GitHubOrganizationPinError);
  });

  it("fails closed when the login resolves to a different immutable user ID", async () => {
    await expect(
      port(
        standardFetch({ user: { id: 9, login: GITHUB_LOGIN } }),
      ).observeAccount({
        githubLogin: GITHUB_LOGIN,
        githubUserId: GITHUB_USER_ID,
      }),
    ).rejects.toBeInstanceOf(GitHubIdentityPinError);
  });

  it("fails closed on a privileged email invitation that cannot be pinned to an identity", async () => {
    await expect(
      port(
        standardFetch({
          invitations: [{ id: 71, invitee: null, role: "billing_manager" }],
        }),
      ).observeAccount({
        githubLogin: GITHUB_LOGIN,
        githubUserId: GITHUB_USER_ID,
      }),
    ).rejects.toBeInstanceOf(GitHubUnresolvedPrivilegedInvitationError);
  });

  it("rejects an operation outside the configured team boundary before any request", async () => {
    const fetchImpl = standardFetch();
    await expect(
      port(fetchImpl).execute(
        GitHubProvisioningOperationSchema.parse({
          githubLogin: GITHUB_LOGIN,
          githubUserId: GITHUB_USER_ID,
          kind: "add-team-member",
          role: "member",
          teamSlug: "finance",
        }),
      ),
    ).rejects.toBeInstanceOf(GitHubOrganizationScopeError);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("accepts idempotent delete statuses and performs immediate full readback", async () => {
    const fetchImpl = standardFetch({ membership: null, teamMembership: null });
    await expect(
      port(fetchImpl).execute(
        GitHubProvisioningOperationSchema.parse({
          githubLogin: GITHUB_LOGIN,
          githubUserId: GITHUB_USER_ID,
          kind: "remove-team-member",
          teamSlug: "engineering",
        }),
      ),
    ).resolves.toEqual({ kind: "remove-team-member", state: "converged" });
    expect(fetchImpl).toHaveBeenCalledWith(
      `${GITHUB_API}/orgs/example/teams/engineering/memberships/octocat`,
      expect.objectContaining({
        headers: expect.any(Headers),
        method: "DELETE",
      }),
    );
    const deleteCall = fetchImpl.mock.calls.find(
      ([, init]) => init?.method === "DELETE",
    );
    expect(new Headers(deleteCall?.[1]?.headers).get("authorization")).toBe(
      "Bearer test-token",
    );
    expect(
      fetchImpl.mock.calls.some(
        ([input]) => pathOf(input) === `${GITHUB_API}/orgs/example`,
      ),
    ).toBe(true);
    expect(
      fetchImpl.mock.calls.some(([input]) => pathOf(input).includes("/repos?")),
    ).toBe(true);
  });

  it("accepts an idempotent delete 404 after a safe pre-write observation", async () => {
    const reads = standardFetch({ membership: null, teamMembership: null });
    const fetchImpl = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) =>
        init?.method === "DELETE" ? empty(404) : reads(input, init),
    );

    await expect(
      port(fetchImpl).execute(
        GitHubProvisioningOperationSchema.parse({
          githubLogin: GITHUB_LOGIN,
          githubUserId: GITHUB_USER_ID,
          kind: "remove-team-member",
          teamSlug: "engineering",
        }),
      ),
    ).resolves.toEqual({ kind: "remove-team-member", state: "converged" });
  });

  it("rechecks desired authority after provider preparation and refuses a denied write", async () => {
    const fetchImpl = standardFetch({ membership: null, teamMembership: null });
    const assertFinalWriteAuthority = vi.fn(async () => {
      expect(
        fetchImpl.mock.calls.some(([input]) =>
          pathOf(input).includes("/repos?"),
        ),
      ).toBe(true);
      throw new Error("google_authority_drift");
    });
    await expect(
      port(fetchImpl).execute(
        GitHubProvisioningOperationSchema.parse({
          githubLogin: GITHUB_LOGIN,
          githubUserId: GITHUB_USER_ID,
          kind: "remove-team-member",
          teamSlug: "engineering",
        }),
        assertFinalWriteAuthority,
      ),
    ).rejects.toThrow("google_authority_drift");
    expect(assertFinalWriteAuthority).toHaveBeenCalledOnce();
    expect(
      fetchImpl.mock.calls.every(
        ([, init]) => !["DELETE", "PUT"].includes(init?.method ?? "GET"),
      ),
    ).toBe(true);
  });

  it("blocks privileged drift before issuing any mutation", async () => {
    const fetchImpl = standardFetch({
      membership: {
        role: "admin",
        state: "active",
        user: { id: 583231, login: GITHUB_LOGIN },
      },
    });

    await expect(
      port(fetchImpl).execute(
        GitHubProvisioningOperationSchema.parse({
          githubLogin: GITHUB_LOGIN,
          githubUserId: GITHUB_USER_ID,
          kind: "remove-organization-member",
        }),
      ),
    ).rejects.toBeInstanceOf(GitHubPreWriteSafetyError);
    expect(
      fetchImpl.mock.calls.every(
        ([, init]) => !["DELETE", "PUT"].includes(init?.method ?? "GET"),
      ),
    ).toBe(true);
  });

  it.each(["add-team-member", "remove-team-member"] as const)(
    "refuses a pending selected team before %s dispatch",
    async (kind) => {
      const fetchImpl = standardFetch({
        teamMembership: { role: "member", state: "pending" },
      });
      await expect(
        port(fetchImpl).execute(
          GitHubProvisioningOperationSchema.parse({
            githubLogin: GITHUB_LOGIN,
            githubUserId: GITHUB_USER_ID,
            kind,
            teamSlug: "engineering",
            ...(kind === "add-team-member" && { role: "member" }),
          }),
        ),
      ).rejects.toBeInstanceOf(GitHubPreWriteSafetyError);
      expect(
        fetchImpl.mock.calls.every(
          ([, init]) => !["PUT", "DELETE"].includes(init?.method ?? "GET"),
        ),
      ).toBe(true);
    },
  );

  it.each(["pending", "inherited", "active-direct"] as const)(
    "requires active direct team access after one PUT: %s",
    async (state) => {
      const before = standardFetch({ teamMembership: null });
      const after = standardFetch({
        teamMembership: {
          role: "member",
          state: state === "pending" ? "pending" : "active",
        },
      });
      let dispatched = false;
      const fetchImpl = vi.fn(
        async (input: RequestInfo | URL, init?: RequestInit) => {
          if (init?.method === "PUT") {
            dispatched = true;
            return empty(200);
          }
          if (!dispatched) return before(input, init);
          if (
            pathOf(input).includes("/teams/engineering/members?") &&
            state === "inherited"
          )
            return json([{ id: 583231, login: GITHUB_LOGIN, inherited: true }]);
          return after(input, init);
        },
      );
      const result = port(fetchImpl).execute(
        GitHubProvisioningOperationSchema.parse({
          githubLogin: GITHUB_LOGIN,
          githubUserId: GITHUB_USER_ID,
          kind: "add-team-member",
          teamSlug: "engineering",
          role: "member",
        }),
      );
      const outcome = await result.catch((error: unknown) => ({
        readbackRefused: error instanceof GitHubMutationReadbackError,
      }));
      expect(outcome).toEqual(
        state === "active-direct"
          ? { kind: "add-team-member", state: "converged" }
          : { readbackRefused: true },
      );
      expect(
        fetchImpl.mock.calls.filter(([, init]) => init?.method === "PUT"),
      ).toHaveLength(1);
    },
  );

  it("rejects a successful write whose readback did not converge", async () => {
    await expect(
      port(standardFetch()).execute(
        GitHubProvisioningOperationSchema.parse({
          githubLogin: GITHUB_LOGIN,
          githubUserId: GITHUB_USER_ID,
          kind: "remove-team-member",
          teamSlug: "engineering",
        }),
      ),
    ).rejects.toBeInstanceOf(GitHubMutationReadbackError);
  });

  it("returns a successful invited receipt without declaring pending membership converged", async () => {
    const fetchImpl = standardFetch({
      membership: {
        role: "member",
        state: "pending",
        user: { id: 583231, login: GITHUB_LOGIN },
      },
    });

    await expect(
      port(fetchImpl).execute(
        GitHubProvisioningOperationSchema.parse({
          githubLogin: GITHUB_LOGIN,
          githubUserId: GITHUB_USER_ID,
          kind: "invite-organization-member",
          role: "member",
        }),
      ),
    ).resolves.toEqual({
      access: "pending-acceptance",
      kind: "invite-organization-member",
      state: "invited",
    });
    expect(
      fetchImpl.mock.calls.some(
        ([input, init]) =>
          pathOf(input) === `${GITHUB_API}/orgs/example/memberships/octocat` &&
          init?.method === "PUT",
      ),
    ).toBe(true);
  });

  it("fails instead of returning a partial observation at the page bound", async () => {
    const fetchImpl = standardFetch({
      invitations: Array.from({ length: 100 }, (_, index) => ({
        id: index + 1,
        invitee: null,
        role: "direct_member",
      })),
    });
    await expect(
      port(fetchImpl, { maxPages: 1 }).observeAccount({
        githubLogin: GITHUB_LOGIN,
        githubUserId: GITHUB_USER_ID,
      }),
    ).rejects.toBeInstanceOf(GitHubOrganizationBoundExceededError);
  });

  it("uses an independent request budget for sequential and concurrent top-level calls", async () => {
    const organizationPort = port(standardFetch(), { maxRequests: 12 });
    const identity = {
      githubLogin: GITHUB_LOGIN,
      githubUserId: GITHUB_USER_ID,
    };

    await expect(
      organizationPort.observeAccount(identity),
    ).resolves.toMatchObject({
      complete: true,
    });
    await expect(
      Promise.all([
        organizationPort.observeAccount(identity),
        organizationPort.observeAccount(identity),
      ]),
    ).resolves.toHaveLength(2);
  });

  it("redacts GitHub response bodies from provider errors", async () => {
    const fallback = standardFetch();
    const fetchImpl = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        if (pathOf(input) === `${GITHUB_API}/orgs/example`) {
          return new Response("sensitive-provider-payload", { status: 500 });
        }
        return fallback(input, init);
      },
    );

    const error = await port(fetchImpl)
      .observeAccount({
        githubLogin: GITHUB_LOGIN,
        githubUserId: GITHUB_USER_ID,
      })
      .catch((failure: unknown) => failure);
    if (!(error instanceof Error)) throw new Error("expected provider error");
    expect(error.message).not.toContain("sensitive-provider-payload");
    expect(error.message).toContain("http_500");
  });

  it("preserves provider status evidence when response-body disposal throws", async () => {
    const fallback = standardFetch();
    const fetchImpl = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        if (pathOf(input) !== `${GITHUB_API}/orgs/example`)
          return fallback(input, init);
        const response = new Response("sensitive-provider-payload", {
          status: 403,
        });
        Object.defineProperty(response, "body", {
          value: { cancel: () => Promise.reject(new TypeError("locked")) },
        });
        return response;
      },
    );

    await expect(port(fetchImpl).verifyWriterTenant()).rejects.toThrow(
      "http_403",
    );
  });

  it("classifies a writer probe transport failure without exposing provider detail", async () => {
    const fetchImpl = vi.fn<typeof fetch>(() =>
      Promise.reject(new TypeError("sensitive transport detail")),
    );

    await expect(port(fetchImpl).verifyWriterTenant()).rejects.toBeInstanceOf(
      GitHubRequestTransportError,
    );
  });

  it("classifies an invalid successful writer response without exposing its body", async () => {
    const fetchImpl = vi.fn<typeof fetch>(() =>
      Promise.resolve(
        new Response("sensitive invalid response", { status: 200 }),
      ),
    );

    await expect(port(fetchImpl).verifyWriterTenant()).rejects.toBeInstanceOf(
      GitHubWriterTenantResponseError,
    );
  });

  it("blocks team writes when the active member is not SAML-linked", async () => {
    await expect(
      port(standardFetch({ samlLinked: false })).execute(
        GitHubProvisioningOperationSchema.parse({
          githubLogin: GITHUB_LOGIN,
          githubUserId: GITHUB_USER_ID,
          kind: "remove-team-member",
          teamSlug: "engineering",
        }),
      ),
    ).rejects.toBeInstanceOf(GitHubPreWriteSafetyError);
  });

  it("blocks organization removal when repository visibility is partial", async () => {
    await expect(
      port(
        standardFetch({
          organization: {
            id: 100000001,
            login: "example",
            "owned_private_repos": 2,
            "public_repos": 0,
          },
          repositories: [{ "full_name": "example/visible-one", id: 1 }],
        }),
      ).execute(
        GitHubProvisioningOperationSchema.parse({
          githubLogin: GITHUB_LOGIN,
          githubUserId: GITHUB_USER_ID,
          kind: "remove-organization-member",
        }),
      ),
    ).rejects.toBeInstanceOf(GitHubPreWriteSafetyError);
  });

  it("requires enough request budget to capture its configured scope", () => {
    expect(() => port(standardFetch(), { maxRequests: 6 })).toThrow(
      /cannot capture the configured managed-team boundary/u,
    );
  });
});

describe("single-operation GitHub zero-dispatch proof", () => {
  const operation = GitHubProvisioningOperationSchema.parse({
    githubLogin: GITHUB_LOGIN,
    githubUserId: GITHUB_USER_ID,
    kind: "add-team-member",
    teamSlug: "engineering",
    role: "member",
  });
  async function claim() {
    return {
      protocol: "github-single-operation/v1" as const,
      claimId: crypto.randomUUID(),
      operationHash: await sha256Hex(JsonValueSchema.parse(operation)),
    };
  }
  it.each(["credentials", "provider-observation", "final-authority"] as const)(
    "brands only the %s prewrite refusal and consumes it once",
    async (category) => {
      const base = standardFetch({
        teamMembership: null,
        ...(category === "provider-observation" && {
          membership: {
            role: "admin",
            state: "active",
            user: { id: 583231, login: GITHUB_LOGIN },
          },
        }),
      });
      const fetchImpl = vi.fn(
        async (input: RequestInfo | URL, init?: RequestInit) =>
          category === "credentials"
            ? json({ message: "denied" }, 403)
            : base(input, init),
      );
      const guard = async () => {
        if (category === "final-authority")
          throw new Error("authority-refused");
      };
      const dispatchClaim = await claim();
      const error = await port(fetchImpl)
        .execute(operation, guard, dispatchClaim)
        .catch((value: unknown) => value);
      const proof = takeGithubZeroDispatchProof(error);
      expect(proof).toEqual({ claim: dispatchClaim, operation, category });
      if (proof === undefined) throw new Error("expected proof");
      expect(() => assertTrustedGithubZeroDispatchProof(proof)).not.toThrow();
      expect(takeGithubZeroDispatchProof(error)).toBeUndefined();
      expect(
        fetchImpl.mock.calls.filter(([, init]) =>
          ["PUT", "DELETE"].includes(init?.method ?? "GET"),
        ),
      ).toHaveLength(0);
      expect(() => assertTrustedGithubZeroDispatchProof({ ...proof })).toThrow(
        "github_zero_dispatch_proof_untrusted",
      );
    },
  );
  it("does not brand legacy execution or an error-string spoof", async () => {
    const error = await port(
      standardFetch({ teamMembership: { role: "member", state: "pending" } }),
    )
      .execute(operation)
      .catch((value: unknown) => value);
    expect(takeGithubZeroDispatchProof(error)).toBeUndefined();
    expect(
      takeGithubZeroDispatchProof(new Error("github_prewrite_not_dispatched")),
    ).toBeUndefined();
  });
  it.each(["403", "timeout", "readback"] as const)(
    "retains uncertainty after mutation dispatch: %s",
    async (failure) => {
      const reads = standardFetch({ teamMembership: null });
      const fetchImpl = vi.fn(
        async (input: RequestInfo | URL, init?: RequestInit) => {
          if (init?.method === "PUT") {
            if (failure === "timeout")
              throw new DOMException("timed out", "TimeoutError");
            return empty(failure === "403" ? 403 : 200);
          }
          return reads(input, init);
        },
      );
      const error = await port(fetchImpl)
        .execute(operation, undefined, await claim())
        .catch((value: unknown) => value);
      expect(error).toBeInstanceOf(Error);
      expect(takeGithubZeroDispatchProof(error)).toBeUndefined();
      expect(
        fetchImpl.mock.calls.filter(([, init]) => init?.method === "PUT"),
      ).toHaveLength(1);
    },
  );
});

describe("documented GitHub invitation correlation", () => {
  it("hydrates top-level login, never treating invitation ID as user ID", async () => {
    const fetchImpl = standardFetch({
      membership: null,
      invitations: [
        {
          id: 71,
          login: "OctoCat",
          email: null,
          role: "direct_member",
          inviter: { id: 999, login: "owner" },
        },
      ],
    });
    const observed = await port(fetchImpl).observeAccount({
      githubLogin: GITHUB_LOGIN,
      githubUserId: GITHUB_USER_ID,
      primaryEmail: "octocat@company.test",
    });
    expect(observed.pendingInvitations).toEqual([
      {
        githubLogin: GITHUB_LOGIN,
        githubUserId: GITHUB_USER_ID,
        invitationId: 71,
        role: "direct_member",
      },
    ]);
    expect(
      fetchImpl.mock.calls.every(([, init]) =>
        ["GET", "POST"].includes(init?.method ?? "GET"),
      ),
    ).toBe(true);
  });
  it.each([
    { email: "octocat@company.test", match: true },
    { email: "unrelated@company.test", match: false },
  ])(
    "uses exact authoritative primary email for email-only invitations: $match",
    async ({ email, match }) => {
      const observed = await port(
        standardFetch({
          membership: null,
          invitations: [{ id: 71, email, role: "direct_member" }],
        }),
      ).observeAccount({
        githubLogin: GITHUB_LOGIN,
        githubUserId: GITHUB_USER_ID,
        primaryEmail: "octocat@company.test",
      });
      expect(observed.pendingInvitations).toHaveLength(match ? 1 : 0);
      expect(observed.unresolvedInvitations).toBeUndefined();
    },
  );
  it.each([null, "unrelated@company.test"])(
    "refuses removals with unresolvable invitation ownership even for a member",
    async (email) => {
      const fetchImpl = standardFetch({
        invitations: [{ id: 71, email, role: "direct_member" }],
      });
      await expect(
        port(fetchImpl).execute(
          GitHubProvisioningOperationSchema.parse({
            githubLogin: GITHUB_LOGIN,
            githubUserId: GITHUB_USER_ID,
            kind: "remove-organization-member",
          }),
        ),
      ).rejects.toBeInstanceOf(GitHubPreWriteSafetyError);
      expect(
        fetchImpl.mock.calls.some(([, init]) => init?.method === "DELETE"),
      ).toBe(false);
    },
  );
  it("rejects conflicting legacy invitee ID after top-level login hydration before mutation", async () => {
    const fetchImpl = standardFetch({
      invitations: [
        {
          id: 71,
          login: "octocat",
          invitee: { id: 999, login: "octocat" },
          role: "direct_member",
        },
      ],
    });
    await expect(
      port(fetchImpl).execute(
        GitHubProvisioningOperationSchema.parse({
          githubLogin: GITHUB_LOGIN,
          githubUserId: GITHUB_USER_ID,
          kind: "cancel-invitation",
          invitationId: 71,
        }),
      ),
    ).rejects.toThrow("github_invitation_identity_conflict");
    expect(
      fetchImpl.mock.calls.some(([, init]) => init?.method === "DELETE"),
    ).toBe(false);
  });
  it("does not claim cancellation convergence when exact invitation ID remains with opaque readback", async () => {
    const reads = standardFetch({
      membership: null,
      invitations: [{ id: 71, login: "octocat", role: "direct_member" }],
    });
    let deleted = false;
    const fetchImpl = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        if (init?.method === "DELETE") {
          deleted = true;
          return empty();
        }
        if (deleted && pathOf(input).includes("/invitations?"))
          return json([{ id: 71, email: null, role: "direct_member" }]);
        return reads(input, init);
      },
    );
    await expect(
      port(fetchImpl).execute(
        GitHubProvisioningOperationSchema.parse({
          githubLogin: GITHUB_LOGIN,
          githubUserId: GITHUB_USER_ID,
          kind: "cancel-invitation",
          invitationId: 71,
        }),
      ),
    ).rejects.toBeInstanceOf(GitHubMutationReadbackError);
    expect(
      fetchImpl.mock.calls.filter(([, init]) => init?.method === "DELETE"),
    ).toHaveLength(1);
  });
});
