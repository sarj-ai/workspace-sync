import { afterEach, describe, expect, it, vi } from "vitest";

import { GitHubAccessAuditClient } from "../src/github-access-audit/git-hub-access-audit-client.ts";
import { isString } from "./support/value-guards.ts";

function jsonFor(url: URL) {
  if (url.pathname === "/orgs/example") {
    return {
      "default_repository_permission": "read",
      id: 100_000_001,
      login: "example",
      "members_can_create_repositories": false,
    };
  }
  return [];
}

const HYDRATION_RESPONSES = new Map<string, unknown>([
  ["/orgs/example", { id: 100_000_001, login: "example" }],
  [
    "/orgs/example/teams",
    [
      {
        id: 1,
        name: "Engineering",
        parent: null,
        privacy: "closed",
        slug: "eng",
      },
    ],
  ],
  [
    "/orgs/example/repos",
    [
      {
        archived: false,
        "full_name": "example/core",
        id: 4,
        name: "core",
        visibility: "private",
      },
    ],
  ],
  ["/repos/example/core/teams", [{ id: 1, permission: "push", slug: "eng" }]],
  [
    "/repos/example/core/collaborators",
    [
      {
        id: 5,
        login: "contractor",
        permissions: { admin: true, pull: true, push: true },
        type: "User",
      },
    ],
  ],
]);

const hydrationFetch: typeof fetch = async (input, init) => {
  const url = new URL(input instanceof Request ? input.url : input.toString());
  if (url.pathname === "/orgs/example/teams/eng/members") {
    const actor =
      url.searchParams.get("role") === "maintainer"
        ? { id: 2, login: "lead", type: "User" }
        : { id: 3, login: "dev", type: "User" };
    return Response.json([actor]);
  }
  if (url.pathname === "/graphql") {
    if (
      isString(init?.body) &&
      init.body.includes("GitHubDirectRepositoryPermissionSources")
    ) {
      return Response.json({
        data: {
          repository: {
            databaseId: 4,
            nameWithOwner: "example/core",
            collaborators: {
              edges: [
                {
                  node: { databaseId: 5, login: "contractor" },
                  permissionSources: [
                    {
                      permission: "READ",
                      roleName: "read",
                      source: {
                        kind: "Repository",
                        databaseId: 4,
                        nameWithOwner: "example/core",
                      },
                    },
                  ],
                },
              ],
              pageInfo: { endCursor: null, hasNextPage: false },
            },
          },
        },
      });
    }
    return Response.json({
      data: { organization: { samlIdentityProvider: null } },
    });
  }
  if (url.pathname.includes("/scim/"))
    return new Response(null, { status: 404 });
  return Response.json(HYDRATION_RESPONSES.get(url.pathname) ?? []);
};

describe("GitHub access audit client", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("calls the Worker global fetch without rebinding it to the client instance", async () => {
    const receivers: unknown[] = [];
    const globalFetch = new Proxy<typeof fetch>(
      async (input) => {
        const url = new URL(
          input instanceof Request ? input.url : input.toString(),
        );
        if (url.pathname === "/graphql") {
          return Response.json({
            data: { organization: { samlIdentityProvider: null } },
          });
        }
        if (url.pathname.includes("/scim/"))
          return new Response(null, { status: 404 });
        return Response.json(jsonFor(url));
      },
      {
        apply: (target, receiver, argumentsList) => {
          receivers.push(receiver);
          return Reflect.apply(target, receiver, argumentsList) as ReturnType<
            typeof fetch
          >;
        },
      },
    );
    vi.stubGlobal("fetch", globalFetch);
    const client = new GitHubAccessAuditClient({
      organization: "example",
      token: "read-token",
    });

    await client.capture(Date.now() + 30_000);

    expect(receivers).not.toContain(client);
  });

  it("accepts a redacted null organization base permission", async () => {
    const client = new GitHubAccessAuditClient({
      fetchImpl: async (input) => {
        const url = new URL(
          input instanceof Request ? input.url : input.toString(),
        );
        if (url.pathname === "/orgs/example") {
          return Response.json({
            "default_repository_permission": null,
            id: 100_000_001,
            login: "example",
          });
        }
        if (url.pathname === "/graphql") {
          return Response.json({
            data: { organization: { samlIdentityProvider: null } },
          });
        }
        if (url.pathname.includes("/scim/"))
          return new Response(null, { status: 404 });
        return Response.json([]);
      },
      organization: "example",
      token: "read-token",
    });

    const snapshot = await client.capture(Date.now() + 30_000);

    expect(snapshot.organization?.["default_repository_permission"]).toBeNull();
    expect(snapshot.errors).not.toContainEqual(
      expect.objectContaining({ capability: "organization" }),
    );
  });

  it("uses only GET reads plus the read-only GraphQL POST and tolerates unavailable identities", async () => {
    const methods: string[] = [];
    const userAgents: string[] = [];
    const client = new GitHubAccessAuditClient({
      fetchImpl: async (input, init) => {
        const url = new URL(
          input instanceof Request ? input.url : input.toString(),
        );
        const method = init?.method ?? "GET";
        methods.push(`${method} ${url.pathname}`);
        userAgents.push(new Headers(init?.headers).get("user-agent") ?? "");
        if (url.pathname === "/graphql") {
          return Response.json({
            data: { organization: { samlIdentityProvider: null } },
          });
        }
        if (url.pathname.includes("/scim/"))
          return new Response(null, { status: 404 });
        return Response.json(jsonFor(url));
      },
      organization: "example",
      token: "read-token",
    });
    const snapshot = await client.capture(Date.now() + 30_000);
    expect(snapshot.errors.map((error) => error.capability)).toEqual(
      expect.arrayContaining(["saml_external_identities", "scim_identities"]),
    );
    expect(
      methods.every(
        (method) => method.startsWith("GET ") || method === "POST /graphql",
      ),
    ).toBe(true);
    expect(
      userAgents.every(
        (userAgent) => userAgent === "workspace-sync-github-access-audit",
      ),
    ).toBe(true);
  });

  it("marks a capped core page as incomplete evidence", async () => {
    const fullPage = Array.from({ length: 100 }, (_, index) => ({
      id: index + 1,
      login: `user-${String(index)}`,
      type: "User",
    }));
    const client = new GitHubAccessAuditClient({
      fetchImpl: async (input) => {
        const url = new URL(
          input instanceof Request ? input.url : input.toString(),
        );
        if (url.pathname === "/orgs/example/members")
          return Response.json(fullPage);
        if (url.pathname === "/orgs/example") {
          return Response.json({ login: "example" });
        }
        if (url.pathname === "/graphql") {
          return Response.json({
            data: { organization: { samlIdentityProvider: null } },
          });
        }
        if (url.pathname.includes("/scim/"))
          return new Response(null, { status: 404 });
        return Response.json([]);
      },
      maxPages: 1,
      organization: "example",
      token: "read-token",
    });
    const snapshot = await client.capture(Date.now() + 30_000);
    expect(snapshot.errors).toContainEqual(
      expect.objectContaining({
        capability: "members",
        code: expect.stringContaining("page_limit"),
      }),
    );
  });

  it.each([
    { cursors: ["a", "a"], expectedRequests: 2 },
    { cursors: ["a", "b", "a"], expectedRequests: 3 },
  ])(
    "fails incomplete SAML traversal after $expectedRequests cyclic requests",
    async ({ cursors, expectedRequests }) => {
      let graphqlRequests = 0;
      const client = new GitHubAccessAuditClient({
        organization: "example",
        token: "read-token",
        maxPages: 20,
        fetchImpl: async (input) => {
          const url = new URL(
            input instanceof Request ? input.url : input.toString(),
          );
          if (url.pathname !== "/graphql") return Response.json([]);
          const endCursor = cursors[graphqlRequests % cursors.length];
          graphqlRequests++;
          return Response.json({
            data: {
              organization: {
                samlIdentityProvider: {
                  externalIdentities: {
                    nodes: [],
                    pageInfo: { endCursor, hasNextPage: true },
                  },
                },
              },
            },
          });
        },
      });
      const snapshot = await client.captureIdentitySeed(Date.now() + 30_000);
      expect(graphqlRequests).toBe(expectedRequests);
      expect(snapshot.samlExternalIdentities).toEqual([]);
      expect(snapshot.errors).toContainEqual({
        capability: "saml_external_identities",
        code: "saml_invalid_cursor",
        message: "saml_invalid_cursor",
      });
    },
  );

  it("surfaces only the bounded GitHub API message for failed reads", async () => {
    const client = new GitHubAccessAuditClient({
      fetchImpl: async () =>
        Response.json(
          {
            "documentation_url": "https://docs.github.com/",
            message: "  policy\nblocked  ",
          },
          { status: 403 },
        ),
      organization: "example",
      token: "read-token",
    });

    const snapshot = await client.capture(Date.now() + 30_000);

    expect(snapshot.errors).not.toHaveLength(0);
    expect(
      snapshot.errors.every(
        (error) => error.message === "github_http_403:policy blocked",
      ),
    ).toBe(true);
  });

  it("marks expired deadlines and request-budget exhaustion as incomplete", async () => {
    const deadlineClient = new GitHubAccessAuditClient({
      fetchImpl: async () => Response.json([]),
      organization: "example",
      token: "read-token",
    });
    const expired = await deadlineClient.capture(Date.now() - 1);
    expect(expired.errors).toContainEqual(
      expect.objectContaining({
        code: "github_access_audit_deadline_exceeded",
      }),
    );

    const cappedClient = new GitHubAccessAuditClient({
      fetchImpl: async (input) => {
        const url = new URL(
          input instanceof Request ? input.url : input.toString(),
        );
        if (url.pathname === "/orgs/example")
          return Response.json({ login: "example" });
        if (url.pathname === "/graphql") {
          return Response.json({
            data: { organization: { samlIdentityProvider: null } },
          });
        }
        return Response.json([]);
      },
      maxRequests: 1,
      organization: "example",
      token: "read-token",
    });
    const capped = await cappedClient.capture(Date.now() + 30_000);
    expect(capped.errors).toContainEqual(
      expect.objectContaining({ code: "github_request_limit_exceeded" }),
    );
  });

  it("hydrates team membership and repository grants through bounded detail reads", async () => {
    const client = new GitHubAccessAuditClient({
      fetchImpl: hydrationFetch,
      organization: "example",
      token: "read-token",
    });
    const snapshot = await client.capture(Date.now() + 30_000);
    expect(snapshot.teams[0]).toEqual(
      expect.objectContaining({
        directMembers: [expect.objectContaining({ login: "dev" })],
        maintainers: [expect.objectContaining({ login: "lead" })],
      }),
    );
    expect(snapshot.repositories[0]).toEqual(
      expect.objectContaining({
        directCollaborators: [
          expect.objectContaining({
            login: "contractor",
            permissions: expect.objectContaining({
              admin: false,
              pull: true,
              push: false,
            }),
          }),
        ],
        teamGrants: [
          expect.objectContaining({ permission: "push", slug: "eng" }),
        ],
      }),
    );
  });

  it("captures deprovision repository and team evidence without reading SAML or SCIM", async () => {
    const paths: string[] = [];
    const queries: string[] = [];
    const client = new GitHubAccessAuditClient({
      fetchImpl: async (input, init) => {
        const url = new URL(
          input instanceof Request ? input.url : input.toString(),
        );
        paths.push(`${init?.method ?? "GET"} ${url.pathname}`);
        if (url.pathname === "/graphql" && isString(init?.body))
          queries.push(init.body);
        return hydrationFetch(input, init);
      },
      organization: "example",
      token: "read-token",
    });

    const snapshot = await client.captureDeprovisionAuthority(
      Date.now() + 30_000,
    );

    expect(snapshot.errors).toEqual([]);
    expect(snapshot.repositories[0]?.directCollaborators[0]?.login).toBe(
      "contractor",
    );
    expect(snapshot.repositories[0]).toEqual({
      directCollaborators: [
        expect.objectContaining({ id: 5, login: "contractor", type: "User" }),
      ],
      "full_name": "example/core",
      id: 4,
    });
    expect(snapshot.teams[0]).toEqual(
      expect.objectContaining({
        directMembers: [expect.objectContaining({ login: "dev" })],
        maintainers: [expect.objectContaining({ login: "lead" })],
        slug: "eng",
      }),
    );
    expect(paths).toContain("POST /graphql");
    expect(
      queries.every((query) => !query.includes("externalIdentities")),
    ).toBe(true);
    expect(paths.every((path) => !path.includes("/scim/"))).toBe(true);
    expect(paths.some((path) => path.includes("/teams"))).toBe(true);
  });

  it("enforces one request-concurrency budget across every capability", async () => {
    let active = 0;
    let maximum = 0;
    const client = new GitHubAccessAuditClient({
      fetchImpl: async (input) => {
        active++;
        maximum = Math.max(maximum, active);
        await new Promise<void>((resolve) => {
          setTimeout(() => resolve(), 1);
        });
        active--;
        const url = new URL(
          input instanceof Request ? input.url : input.toString(),
        );
        if (url.pathname === "/orgs/example")
          return Response.json({ login: "example" });
        if (url.pathname === "/graphql") {
          return Response.json({
            data: { organization: { samlIdentityProvider: null } },
          });
        }
        if (url.pathname.includes("/scim/"))
          return new Response(null, { status: 404 });
        return Response.json([]);
      },
      maxConcurrentRequests: 2,
      organization: "example",
      token: "read-token",
    });
    await client.capture(Date.now() + 30_000);
    expect(maximum).toBe(2);
  });
});

it.each(["capture", "captureDeprovisionAuthority"] as const)(
  "hydrates actual REST top-level invitation login during %s",
  async (capture) => {
    const paths: string[] = [];
    const client = new GitHubAccessAuditClient({
      organization: "example",
      token: "read-token",
      fetchImpl: async (input) => {
        const url = new URL(
          input instanceof Request ? input.url : input.toString(),
        );
        paths.push(url.pathname);
        if (url.pathname.endsWith("/invitations"))
          return Response.json([
            {
              id: 71,
              login: "Unrelated",
              email: null,
              role: "direct_member",
              inviter: { id: 99, login: "owner" },
            },
          ]);
        if (url.pathname === "/users/unrelated")
          return Response.json({ id: 12345, login: "Unrelated", type: "User" });
        if (url.pathname === "/graphql")
          return Response.json({
            data: { organization: { samlIdentityProvider: null } },
          });
        if (url.pathname.includes("/scim/"))
          return new Response(null, { status: 404 });
        return Response.json(jsonFor(url));
      },
    });
    const snapshot = await client[capture](Date.now() + 30_000);
    expect(
      snapshot.errors.filter(({ capability }) => capability === "invitations"),
    ).toEqual([]);
    expect(snapshot.invitations).toEqual([
      {
        id: 71,
        login: "Unrelated",
        email: null,
        role: "direct_member",
        invitee: { id: 12345, login: "Unrelated", type: "User" },
      },
    ]);
    expect(paths.filter((path) => path === "/users/unrelated")).toHaveLength(1);
  },
);
