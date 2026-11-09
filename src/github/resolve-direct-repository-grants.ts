import { z } from "zod";

const BUILT_IN_ROLES: ReadonlyMap<string, string> = new Map([
  ["admin", "ADMIN"],
  ["maintain", "WRITE"],
  ["write", "WRITE"],
  ["triage", "READ"],
  ["read", "READ"],
]);

const PinSchema = z.object({
  databaseId: z.number().int().positive(),
  nameWithOwner: z.string(),
});
const PageSchema = z.object({
  data: z.object({
    repository: PinSchema.extend({
      collaborators: z.object({
        edges: z.array(
          z.object({
            node: z.object({
              databaseId: z.number().int().positive(),
              login: z.string().min(1),
            }),
            permissionSources: z.array(
              z.object({
                permission: z.enum(["ADMIN", "NONE", "READ", "WRITE"]),
                roleName: z.string().min(1).nullable(),
                source: z.object({
                  kind: z.string(),
                  databaseId: z.number().int().positive().optional(),
                  login: z.string().optional(),
                  nameWithOwner: z.string().optional(),
                }),
              }),
            ),
          }),
        ),
        pageInfo: z.object({
          endCursor: z.string().nullable(),
          hasNextPage: z.boolean(),
        }),
      }),
    }),
  }),
  errors: z.array(z.unknown()).optional(),
});

interface PermissionFlags {
  admin: boolean;
  maintain?: boolean | undefined;
  pull: boolean;
  push: boolean;
  triage?: boolean | undefined;
}

// REST collaborator flags include inherited access; repository permission sources isolate direct roles.
export async function resolveDirectRepositoryGrants<
  Actor extends {
    id: number;
    login: string;
    permissions?: PermissionFlags | undefined;
  },
>(
  repository: { id: number; "full_name": string },
  actors: readonly Actor[],
  graphql: (
    query: string,
    variables: Record<string, unknown>,
  ) => Promise<unknown>,
  maxPages: number,
): Promise<
  (Actor & {
    permissions: PermissionFlags;
    customRoleName?: string;
    unresolvedDirectRole?: true;
  })[]
> {
  if (actors.length === 0) return [];
  const { owner, name } = requestLocation(repository["full_name"], maxPages);
  const edges = new Map<
    number,
    z.output<
      typeof PageSchema
    >["data"]["repository"]["collaborators"]["edges"][number]
  >();
  const cursors = new Set<string>();
  let cursor: null | string = null;
  for (let page = 1; page <= maxPages; page++) {
    // eslint-disable-next-line no-await-in-loop -- Each GraphQL cursor depends on the preceding complete page.
    const response = await graphql(DIRECT_GRANTS_QUERY, {
      cursor,
      name,
      owner,
    });
    const parsed = PageSchema.parse(response);
    if (parsed.errors?.length)
      throw new Error("github_direct_grant_graphql_error");
    const observed = parsed.data.repository;
    if (
      observed.databaseId !== repository.id ||
      observed.nameWithOwner !== repository["full_name"]
    )
      throw new Error("github_direct_grant_repository_mismatch");
    captureEdges(edges, observed.collaborators.edges);
    if (!observed.collaborators.pageInfo.hasNextPage) {
      assertMatchingInventory(actors, edges);
      return actors.map((actor) => resolveActor(repository, actor, edges));
    }
    const next = observed.collaborators.pageInfo.endCursor;
    if (!next || cursors.has(next))
      throw new Error("github_direct_grant_cursor_invalid");
    cursors.add(next);
    cursor = next;
  }
  throw new Error("github_direct_grant_page_limit_exceeded");
}

type DirectGrantEdge = z.output<
  typeof PageSchema
>["data"]["repository"]["collaborators"]["edges"][number];

function requestLocation(fullName: string, maxPages: number) {
  const [owner, name, extra] = fullName.split("/", 3);
  if (
    !owner ||
    !name ||
    extra !== undefined ||
    !Number.isSafeInteger(maxPages) ||
    maxPages < 1
  )
    throw new Error("github_direct_grant_request_invalid");
  return { owner, name };
}

function captureEdges(
  target: Map<number, DirectGrantEdge>,
  edges: readonly DirectGrantEdge[],
) {
  for (const edge of edges) {
    if (target.has(edge.node.databaseId))
      throw new Error("github_direct_grant_duplicate_actor");
    target.set(edge.node.databaseId, edge);
  }
}

function assertMatchingInventory(
  actors: readonly { id: number }[],
  edges: ReadonlyMap<number, DirectGrantEdge>,
) {
  if (
    edges.size !== actors.length ||
    new Set(actors.map((actor) => actor.id)).size !== actors.length
  )
    throw new Error("github_direct_grant_inventory_changed");
}

function resolveActor<
  Actor extends {
    id: number;
    login: string;
    permissions?: PermissionFlags | undefined;
  },
>(
  repository: { id: number; "full_name": string },
  actor: Actor,
  edges: ReadonlyMap<number, DirectGrantEdge>,
) {
  const edge = edges.get(actor.id);
  if (edge?.node.login.toLowerCase() !== actor.login.toLowerCase())
    throw new Error("github_direct_grant_actor_mismatch");
  const sources = new Map(
    edge.permissionSources
      .filter((item) => item.source.kind === "Repository")
      .map((item) => [JSON.stringify(item), item]),
  )
    .values()
    .toArray();
  if (
    sources.length > 1 &&
    actor.permissions !== undefined &&
    protectedOwnerSources(repository, actor, edge, sources)
  )
    return {
      ...actor,
      permissions: actor.permissions,
      unresolvedDirectRole: true as const,
    };
  if (sources.length !== 1)
    throw new Error("github_direct_grant_source_missing_or_ambiguous");
  const source = sources[0];
  if (
    source?.source.databaseId !== repository.id ||
    source.source.nameWithOwner !== repository["full_name"]
  )
    throw new Error("github_direct_grant_source_pin_mismatch");
  return { ...actor, ...directRole(source.permission, source.roleName) };
}

function protectedOwnerSources(
  repository: { id: number; "full_name": string },
  actor: { permissions?: PermissionFlags | undefined },
  edge: DirectGrantEdge,
  sources: DirectGrantEdge["permissionSources"],
) {
  return (
    actor.permissions?.admin === true &&
    sources.every(
      (item) =>
        item.source.databaseId === repository.id &&
        item.source.nameWithOwner === repository["full_name"],
    ) &&
    edge.permissionSources.some(
      (item) =>
        item.source.kind === "Organization" &&
        item.permission === "ADMIN" &&
        item.source.login === repository["full_name"].split("/", 1)[0],
    )
  );
}

function directRole(
  base: "ADMIN" | "NONE" | "READ" | "WRITE",
  role: null | string,
): {
  permissions: PermissionFlags;
  customRoleName?: string;
} {
  if (base === "NONE" || role === null)
    throw new Error("github_direct_grant_role_unavailable");
  const expectedBase = BUILT_IN_ROLES.get(role);
  if (expectedBase !== undefined && expectedBase !== base)
    throw new Error("github_direct_grant_role_mismatch");
  const admin = base === "ADMIN";
  const push = admin || base === "WRITE";
  return {
    ...(expectedBase === undefined && { customRoleName: role }),
    permissions: {
      admin,
      maintain: admin || role === "maintain",
      pull: true,
      push,
      triage: push || role === "triage",
    },
  };
}

const DIRECT_GRANTS_QUERY = `
  query GitHubDirectRepositoryPermissionSources($owner: String!, $name: String!, $cursor: String) {
    repository(owner: $owner, name: $name) {
      databaseId nameWithOwner
      collaborators(first: 100, after: $cursor, affiliation: DIRECT) {
        edges {
          node { databaseId login }
          permissionSources {
            permission roleName
            source { kind: __typename ... on Repository { databaseId nameWithOwner } ... on Organization { databaseId login } }
          }
        }
        pageInfo { endCursor hasNextPage }
      }
    }
  }
`;
