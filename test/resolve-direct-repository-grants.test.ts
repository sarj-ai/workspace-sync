import { describe, expect, it, vi } from "vitest";

import { resolveDirectRepositoryGrants } from "../src/github/resolve-direct-repository-grants.ts";

const REPOSITORY = { "full_name": "example/core", id: 7 };
const ACTOR = {
  id: 10,
  login: "engineer",
  permissions: { admin: true, pull: true, push: true },
};

function source(roleName = "write", permission = "WRITE", id = 7) {
  return {
    permission,
    roleName,
    source: {
      kind: "Repository",
      databaseId: id,
      nameWithOwner: "example/core",
    },
  };
}

function page(
  options: {
    actorId?: number;
    actorLogin?: string;
    cursor?: null | string;
    hasNextPage?: boolean;
    repositoryId?: number;
    repositoryName?: string;
    sources?: readonly ReturnType<typeof source>[];
  } = {},
) {
  return {
    data: {
      repository: {
        databaseId: options.repositoryId ?? 7,
        nameWithOwner: options.repositoryName ?? "example/core",
        collaborators: {
          edges: [
            {
              node: {
                databaseId: options.actorId ?? 10,
                login: options.actorLogin ?? "engineer",
              },
              permissionSources: options.sources ?? [source()],
            },
          ],
          pageInfo: {
            endCursor: options.cursor ?? null,
            hasNextPage: options.hasNextPage ?? false,
          },
        },
      },
    },
  };
}

describe("direct repository grant sources", () => {
  it("uses the direct write source despite inherited administrator access", async () => {
    const read = vi.fn(async () =>
      page({
        sources: [
          source(),
          {
            ...source("admin", "ADMIN"),
            source: { ...source().source, kind: "Team" },
          },
        ],
      }),
    );
    const [observed] = await resolveDirectRepositoryGrants(
      REPOSITORY,
      [ACTOR],
      read,
      3,
    );
    expect(observed?.permissions).toEqual({
      admin: false,
      maintain: false,
      pull: true,
      push: true,
      triage: true,
    });
    expect(observed?.customRoleName).toBeUndefined();
    expect(read).toHaveBeenCalledWith(
      expect.stringContaining("permissionSources"),
      {
        owner: "example",
        name: "core",
        cursor: null,
      },
    );
  });

  it.each([
    ["admin", "ADMIN", "admin"],
    ["maintain", "WRITE", "maintain"],
    ["write", "WRITE", "push"],
    ["triage", "READ", "triage"],
    ["read", "READ", "pull"],
  ])("preserves the built-in %s role", async (role, base, flag) => {
    const [observed] = await resolveDirectRepositoryGrants(
      REPOSITORY,
      [ACTOR],
      async () => page({ sources: [source(role, base)] }),
      1,
    );
    expect(observed?.permissions).toHaveProperty(flag, true);
    expect(observed?.customRoleName).toBeUndefined();
  });

  it("keeps a custom role name alongside its base permission", async () => {
    const [observed] = await resolveDirectRepositoryGrants(
      REPOSITORY,
      [ACTOR],
      async () => page({ sources: [source("Write + Force")] }),
      1,
    );
    expect(observed?.customRoleName).toBe("Write + Force");
    expect(observed?.permissions.admin).toBe(false);
    expect(observed?.permissions.push).toBe(true);
  });

  it.each([
    ["repository identity", { repositoryId: 8 }],
    ["repository name", { repositoryName: "another/core" }],
    ["actor identity", { actorId: 11 }],
    ["actor login", { actorLogin: "different" }],
    ["missing direct source", { sources: [] }],
    [
      "conflicting direct sources",
      { sources: [source(), source("admin", "ADMIN")] },
    ],
    ["source repository identity", { sources: [source("write", "WRITE", 8)] }],
    ["contradictory role", { sources: [source("admin")] }],
    ["unknown permission", { sources: [source("write", "UNKNOWN")] }],
    ["no permission", { sources: [source("read", "NONE")] }],
  ] as const)(
    "rejects %s without trusting REST permission flags",
    async (_label, options) => {
      await expect(
        resolveDirectRepositoryGrants(
          REPOSITORY,
          [ACTOR],
          async () => page(options),
          2,
        ),
      ).rejects.toThrow();
    },
  );

  it("deduplicates identical repository sources returned by GitHub", async () => {
    const [observed] = await resolveDirectRepositoryGrants(
      REPOSITORY,
      [ACTOR],
      async () => page({ sources: [source(), source()] }),
      1,
    );
    expect(observed?.permissions.admin).toBe(false);
    expect(observed?.permissions.push).toBe(true);
  });

  it("retains protected-owner ambiguity for review rather than inferring one direct role", async () => {
    const value = page({ sources: [source(), source("admin", "ADMIN")] });
    const observedPage = {
      ...value,
      data: {
        repository: {
          ...value.data.repository,
          collaborators: {
            ...value.data.repository.collaborators,
            edges: [
              {
                node: { databaseId: ACTOR.id, login: ACTOR.login },
                permissionSources: [
                  ...value.data.repository.collaborators.edges.flatMap(
                    (edge) => edge.permissionSources,
                  ),
                  {
                    permission: "ADMIN",
                    roleName: null,
                    source: {
                      kind: "Organization",
                      databaseId: 100000001,
                      login: "example",
                    },
                  },
                ],
              },
            ],
          },
        },
      },
    };
    const [observed] = await resolveDirectRepositoryGrants(
      REPOSITORY,
      [ACTOR],
      async () => observedPage,
      1,
    );
    expect(observed?.unresolvedDirectRole).toBe(true);
    expect(observed?.permissions.admin).toBe(true);
  });

  it("rejects partial GraphQL failures even when response data is present", async () => {
    await expect(
      resolveDirectRepositoryGrants(
        REPOSITORY,
        [ACTOR],
        async () => ({ ...page(), errors: [{ message: "denied" }] }),
        2,
      ),
    ).rejects.toThrow("github_direct_grant_graphql_error");
  });

  it("reads every page before correlating a REST actor", async () => {
    const read = vi
      .fn()
      .mockResolvedValueOnce(
        page({
          actorId: 11,
          actorLogin: "other",
          cursor: "next",
          hasNextPage: true,
        }),
      )
      .mockResolvedValueOnce(page());
    await expect(
      resolveDirectRepositoryGrants(
        REPOSITORY,
        [{ ...ACTOR, id: 11, login: "other" }, ACTOR],
        read,
        2,
      ),
    ).resolves.toHaveLength(2);
    expect(read).toHaveBeenLastCalledWith(expect.any(String), {
      owner: "example",
      name: "core",
      cursor: "next",
    });
  });

  it("rejects an additional direct actor observed after the REST inventory", async () => {
    const result = page();
    result.data.repository.collaborators.edges.push({
      node: { databaseId: 11, login: "new-user" },
      permissionSources: [source()],
    });
    await expect(
      resolveDirectRepositoryGrants(REPOSITORY, [ACTOR], async () => result, 1),
    ).rejects.toThrow("github_direct_grant_inventory_changed");
  });

  it("rejects duplicate actors across pages", async () => {
    const read = vi
      .fn()
      .mockResolvedValueOnce(page({ cursor: "next", hasNextPage: true }))
      .mockResolvedValueOnce(page());
    await expect(
      resolveDirectRepositoryGrants(REPOSITORY, [ACTOR], read, 2),
    ).rejects.toThrow("github_direct_grant_duplicate_actor");
  });

  it("rejects repeating cursors and page exhaustion", async () => {
    const repeating = vi
      .fn()
      .mockResolvedValueOnce(
        page({ actorId: 11, cursor: "same", hasNextPage: true }),
      )
      .mockResolvedValueOnce(page({ cursor: "same", hasNextPage: true }));
    await expect(
      resolveDirectRepositoryGrants(REPOSITORY, [ACTOR], repeating, 3),
    ).rejects.toThrow("github_direct_grant_cursor_invalid");
    await expect(
      resolveDirectRepositoryGrants(
        REPOSITORY,
        [ACTOR],
        async () => page({ cursor: "next", hasNextPage: true }),
        1,
      ),
    ).rejects.toThrow("github_direct_grant_page_limit_exceeded");
  });

  it("does not add a GraphQL request when the complete direct REST list is empty", async () => {
    const read = vi.fn();
    await expect(
      resolveDirectRepositoryGrants(REPOSITORY, [], read, 1),
    ).resolves.toEqual([]);
    expect(read).not.toHaveBeenCalled();
  });
});
