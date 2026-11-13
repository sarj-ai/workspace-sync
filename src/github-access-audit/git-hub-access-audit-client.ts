import { z } from "zod";

import { githubConditionalReadFetch } from "../clients/github-conditional-read-fetch.ts";
import {
  GitHubOrganizationActorSchema,
  GitHubOrganizationMembershipReader,
  type GitHubOrganizationMembershipReaderContract,
  type GitHubOrganizationMembershipSnapshot,
} from "../github/organization-membership-reader.ts";
import { resolveDirectRepositoryGrants } from "../github/resolve-direct-repository-grants.ts";
import { fetchPort } from "../runtime/fetch-port.ts";
import {
  type GitHubActorSchema as ActorSchema,
  GitHubCollaboratorSchema as CollaboratorSchema,
  GitHubOrganizationSchema as OrganizationSchema,
  GitHubRepositorySchema as RepositorySchema,
  GitHubSamlResponseSchema as SamlResponseSchema,
  GitHubScimPageSchema as ScimPageSchema,
  GitHubTeamGrantSchema as TeamGrantSchema,
  GitHubTeamMemberSchema as TeamMemberSchema,
  GitHubTeamSchema as TeamSchema,
} from "./github-contracts.ts";
import {
  type GitHubDeprovisionAuthority,
  GitHubDeprovisionAuthoritySchema,
} from "./github-deprovision-authority-contract.ts";

const GITHUB_API = "https://api.github.com";
const GITHUB_USER_AGENT = "workspace-sync-github-access-audit";
const DEFAULT_MAX_PAGES = 20;
const DEFAULT_MAX_REQUESTS = 500;
const DETAIL_CONCURRENCY = 5;
const PAGE_SIZE = 100;
const REQUEST_TIMEOUT_MS = 15_000;

export interface GitHubAuditError {
  capability: GitHubCapability;
  code: string;
  message: string;
}

export type GitHubCapability =
  | "invitations"
  | "members"
  | "organization"
  | "outside_collaborators"
  | "repositories"
  | "saml_external_identities"
  | "scim_identities"
  | "teams";

export interface GitHubAccessSnapshot {
  capturedAt: string;
  errors: GitHubAuditError[];
  invitations: GitHubOrganizationMembershipSnapshot["invitations"];
  members: (z.infer<typeof ActorSchema> & { role: "admin" | "member" })[];
  organization: null | z.infer<typeof OrganizationSchema>;
  outsideCollaborators: z.infer<typeof ActorSchema>[];
  repositories: (z.infer<typeof RepositorySchema> & {
    directCollaborators: z.infer<typeof CollaboratorSchema>[];
    teamGrants: z.infer<typeof TeamGrantSchema>[];
  })[];
  samlExternalIdentities: {
    databaseId?: number;
    guid: string;
    login: null | string;
    nameId: null | string;
  }[];
  scimIdentities: z.infer<typeof ScimPageSchema>["Resources"];
  teams: (z.infer<typeof TeamSchema> & {
    directMembers: z.infer<typeof TeamMemberSchema>[];
    maintainers: z.infer<typeof TeamMemberSchema>[];
  })[];
}

export interface GitHubIdentitySeedSnapshot {
  capturedAt: string;
  errors: GitHubAuditError[];
  members: GitHubAccessSnapshot["members"];
  samlExternalIdentities: GitHubAccessSnapshot["samlExternalIdentities"];
}

export interface GitHubAccessAuditClientOptions {
  fetchImpl?: typeof fetch;
  maxConcurrentRequests?: number;
  maxPages?: number;
  maxRequests?: number;
  organization: string;
  token: string;
}

export interface GitHubAccessAuditReader {
  capture(deadlineAt?: number): Promise<GitHubAccessSnapshot>;
  captureDeprovisionAuthority(
    deadlineAt?: number,
  ): Promise<GitHubDeprovisionAuthority>;
  captureIdentitySeed(deadlineAt?: number): Promise<GitHubIdentitySeedSnapshot>;
}

/** Read-only GitHub organization inventory with capability-scoped failures. */
export class GitHubAccessAuditClient implements GitHubAccessAuditReader {
  #deadlineAt: number | undefined;
  readonly #fetchImpl: typeof fetch;
  readonly #maxConcurrentRequests: number;
  readonly #maxPages: number;
  readonly #maxRequests: number;
  readonly #organization: string;
  #requestCount = 0;
  #requestsInFlight = 0;
  readonly #requestWaiters: (() => void)[] = [];
  readonly #token: string;

  constructor(options: GitHubAccessAuditClientOptions) {
    this.#fetchImpl = fetchPort(
      options.fetchImpl ?? githubConditionalReadFetch,
    );
    this.#maxConcurrentRequests =
      options.maxConcurrentRequests ?? DETAIL_CONCURRENCY;
    this.#maxPages = options.maxPages ?? DEFAULT_MAX_PAGES;
    this.#maxRequests = options.maxRequests ?? DEFAULT_MAX_REQUESTS;
    if (!Number.isSafeInteger(this.#maxPages) || this.#maxPages < 1) {
      throw new Error("maxPages must be positive");
    }
    if (
      !Number.isSafeInteger(this.#maxConcurrentRequests) ||
      this.#maxConcurrentRequests < 1
    ) {
      throw new Error("maxConcurrentRequests must be positive");
    }
    if (!Number.isSafeInteger(this.#maxRequests) || this.#maxRequests < 1) {
      throw new Error("maxRequests must be positive");
    }
    this.#organization = options.organization;
    this.#token = options.token;
  }

  async capture(deadlineAt?: number): Promise<GitHubAccessSnapshot> {
    this.#deadlineAt = deadlineAt;
    this.#requestCount = 0;
    const errors: GitHubAuditError[] = [];
    const membershipReader: GitHubOrganizationMembershipReaderContract =
      new GitHubOrganizationMembershipReader(
        this.#organization,
        async (path, schema) => this.#paginate(path, schema),
        async (login) =>
          GitHubOrganizationActorSchema.parse(
            await this.#getJson(`/users/${encodeURIComponent(login)}`),
          ),
      );
    const [
      organization,
      members,
      invitations,
      outsideCollaborators,
      teams,
      repositories,
      samlExternalIdentities,
      scimIdentities,
    ] = await Promise.all([
      this.#captureCapability(
        "organization",
        async () =>
          OrganizationSchema.parse(await this.#getJson(`/orgs/${this.#org()}`)),
        null,
        errors,
      ),
      this.#captureCapability(
        "members",
        async () => membershipReader.listMembers(),
        [],
        errors,
      ),
      this.#captureCapability(
        "invitations",
        async () => membershipReader.listInvitations(),
        [],
        errors,
      ),
      this.#captureCapability(
        "outside_collaborators",
        async () => membershipReader.listOutsideCollaborators(),
        [],
        errors,
      ),
      this.#captureCapability(
        "teams",
        async () => this.#listTeams(),
        [],
        errors,
      ),
      this.#captureCapability(
        "repositories",
        async () => this.#listRepositories(),
        [],
        errors,
      ),
      this.#captureCapability(
        "saml_external_identities",
        async () => this.#listSamlIdentities(),
        [],
        errors,
      ),
      this.#captureCapability(
        "scim_identities",
        async () => this.#listScimIdentities(),
        [],
        errors,
      ),
    ]);
    return {
      capturedAt: new Date().toISOString(),
      errors,
      invitations,
      members,
      organization,
      outsideCollaborators,
      repositories,
      samlExternalIdentities,
      scimIdentities,
      teams,
    };
  }

  async captureIdentitySeed(
    deadlineAt?: number,
  ): Promise<GitHubIdentitySeedSnapshot> {
    this.#deadlineAt = deadlineAt;
    this.#requestCount = 0;
    const errors: GitHubAuditError[] = [];
    const membershipReader: GitHubOrganizationMembershipReaderContract =
      new GitHubOrganizationMembershipReader(
        this.#organization,
        async (path, schema) => this.#paginate(path, schema),
        async (login) =>
          GitHubOrganizationActorSchema.parse(
            await this.#getJson(`/users/${encodeURIComponent(login)}`),
          ),
      );
    const [members, samlExternalIdentities] = await Promise.all([
      this.#captureCapability(
        "members",
        async () => membershipReader.listMembers(),
        [],
        errors,
      ),
      this.#captureCapability(
        "saml_external_identities",
        async () => this.#listSamlIdentities(),
        [],
        errors,
      ),
    ]);
    return {
      capturedAt: new Date().toISOString(),
      errors,
      members,
      samlExternalIdentities,
    };
  }

  /*
   * Captures the complete organization-access surfaces needed for safe deprovision planning.
   * SAML and SCIM identity payloads are intentionally omitted because this planner is pinned to
   * the immutable Google SarjIdentity mapping and does not consume either identity surface.
   */
  async captureDeprovisionAuthority(
    deadlineAt?: number,
  ): Promise<GitHubDeprovisionAuthority> {
    this.#deadlineAt = deadlineAt;
    this.#requestCount = 0;
    const errors: GitHubAuditError[] = [];
    const membershipReader: GitHubOrganizationMembershipReaderContract =
      new GitHubOrganizationMembershipReader(
        this.#organization,
        async (path, schema) => this.#paginate(path, schema),
        async (login) =>
          GitHubOrganizationActorSchema.parse(
            await this.#getJson(`/users/${encodeURIComponent(login)}`),
          ),
      );
    const [
      organization,
      members,
      invitations,
      outsideCollaborators,
      repositories,
      teams,
    ] = await Promise.all([
      this.#captureCapability(
        "organization",
        async () =>
          OrganizationSchema.parse(await this.#getJson(`/orgs/${this.#org()}`)),
        null,
        errors,
      ),
      this.#captureCapability(
        "members",
        async () => membershipReader.listMembers(),
        [],
        errors,
      ),
      this.#captureCapability(
        "invitations",
        async () => membershipReader.listInvitations(),
        [],
        errors,
      ),
      this.#captureCapability(
        "outside_collaborators",
        async () => membershipReader.listOutsideCollaborators(),
        [],
        errors,
      ),
      this.#captureCapability(
        "repositories",
        async () => this.#listDeprovisionRepositories(),
        [],
        errors,
      ),
      this.#captureCapability(
        "teams",
        async () => this.#listTeams(),
        [],
        errors,
      ),
    ]);
    return GitHubDeprovisionAuthoritySchema.parse({
      capturedAt: new Date().toISOString(),
      errors,
      invitations,
      members,
      organization,
      outsideCollaborators,
      repositories,
      teams,
    });
  }

  async #captureCapability<T>(
    capability: GitHubCapability,
    read: () => Promise<T>,
    fallback: T,
    errors: GitHubAuditError[],
  ): Promise<T> {
    try {
      return await read();
    } catch (error) {
      const parsed = auditError(capability, error);
      errors.push(parsed);
      return fallback;
    }
  }

  async #getJson(path: string): Promise<unknown> {
    return this.#request(`${GITHUB_API}${path}`, { method: "GET" });
  }

  async #listRepositories(): Promise<GitHubAccessSnapshot["repositories"]> {
    const repositories = await this.#paginate(
      `/orgs/${this.#org()}/repos?type=all&sort=full_name`,
      RepositorySchema,
    );
    return boundedMap(repositories, async (repository) => {
      const repo = encodeURIComponent(repository.name);
      const [teamGrants, directCollaborators] = await Promise.all([
        this.#paginate(`/repos/${this.#org()}/${repo}/teams`, TeamGrantSchema),
        this.#listDirectCollaborators(repository),
      ]);
      return { ...repository, directCollaborators, teamGrants };
    });
  }

  async #listDeprovisionRepositories(): Promise<
    GitHubDeprovisionAuthority["repositories"]
  > {
    const repositories = await this.#paginate(
      `/orgs/${this.#org()}/repos?type=all&sort=full_name`,
      RepositorySchema,
    );
    return boundedMap(repositories, async (repository) => ({
      directCollaborators: await this.#listDirectCollaborators(repository),
      "full_name": repository["full_name"],
      id: repository.id,
    }));
  }

  async #listDirectCollaborators(
    repository: z.output<typeof RepositorySchema>,
  ) {
    const actors = await this.#paginate(
      `/repos/${this.#org()}/${encodeURIComponent(repository.name)}/collaborators?affiliation=direct`,
      CollaboratorSchema.omit({
        customRoleName: true,
        unresolvedDirectRole: true,
      }),
    );
    return resolveDirectRepositoryGrants(
      repository,
      actors,
      (query, variables) => this.#graphql(query, variables),
      this.#maxPages,
    );
  }

  async #listSamlIdentities(): Promise<
    NonNullable<GitHubAccessSnapshot["samlExternalIdentities"]>
  > {
    const identities: NonNullable<
      GitHubAccessSnapshot["samlExternalIdentities"]
    > = [];
    let cursor: null | string = null;
    const cursors = new Set<string>();
    for (let page = 1; page <= this.#maxPages; page++) {
      const response = SamlResponseSchema.parse(
        // eslint-disable-next-line no-await-in-loop -- GraphQL cursor pagination is ordered and bounded.
        await this.#graphql(SAML_IDENTITIES_QUERY, {
          cursor,
          organization: this.#organization,
        }),
      );
      if (response.errors?.length) {
        throw new Error(
          `graphql:${response.errors.map((item) => item.message).join(";")}`,
        );
      }
      const connection =
        response.data?.organization?.samlIdentityProvider?.externalIdentities;
      if (!connection) throw new Error("saml_identity_provider_unavailable");
      identities.push(
        ...connection.nodes.map((identity) => ({
          ...(!(identity.user?.databaseId === undefined) && {
            databaseId: identity.user.databaseId,
          }),
          guid: identity.guid,
          login: identity.user?.login ?? null,
          nameId: identity.samlIdentity?.nameId ?? null,
        })),
      );
      if (!connection.pageInfo.hasNextPage) return identities;
      if (
        !connection.pageInfo.endCursor ||
        cursors.has(connection.pageInfo.endCursor)
      ) {
        throw new Error("saml_invalid_cursor");
      }
      cursors.add(connection.pageInfo.endCursor);
      cursor = connection.pageInfo.endCursor;
    }
    throw new Error("saml_page_limit_exceeded");
  }

  async #graphql(
    query: string,
    variables: Record<string, unknown>,
  ): Promise<unknown> {
    return this.#request(`${GITHUB_API}/graphql`, {
      body: JSON.stringify({ query, variables }),
      headers: { "content-type": "application/json" },
      method: "POST",
    });
  }

  async #listScimIdentities(): Promise<
    NonNullable<GitHubAccessSnapshot["scimIdentities"]>
  > {
    const identities: NonNullable<GitHubAccessSnapshot["scimIdentities"]> = [];
    let startIndex = 1;
    for (let page = 1; page <= this.#maxPages; page++) {
      const query = new URLSearchParams({
        count: String(PAGE_SIZE),
        startIndex: String(startIndex),
      });

      const parsed = ScimPageSchema.parse(
        // eslint-disable-next-line no-await-in-loop -- SCIM index pagination is ordered and bounded.
        await this.#request(
          `${GITHUB_API}/scim/v2/organizations/${this.#org()}/Users?${query.toString()}`,
          { headers: { accept: "application/scim+json" }, method: "GET" },
        ),
      );
      identities.push(...parsed.Resources);
      if (identities.length >= parsed.totalResults) return identities;
      const next = parsed.startIndex + parsed.itemsPerPage;
      if (parsed.itemsPerPage === 0 || next <= startIndex)
        throw new Error("scim_invalid_page");
      startIndex = next;
    }
    throw new Error("scim_page_limit_exceeded");
  }

  async #listTeams(): Promise<GitHubAccessSnapshot["teams"]> {
    const teams = await this.#paginate(
      `/orgs/${this.#org()}/teams`,
      TeamSchema,
    );
    return boundedMap(teams, async (team) => {
      const [directMembers, maintainers] = await Promise.all([
        this.#paginate(
          `/orgs/${this.#org()}/teams/${encodeURIComponent(team.slug)}/members?role=member`,
          TeamMemberSchema,
        ),
        this.#paginate(
          `/orgs/${this.#org()}/teams/${encodeURIComponent(team.slug)}/members?role=maintainer`,
          TeamMemberSchema,
        ),
      ]);
      return { ...team, directMembers, maintainers };
    });
  }

  #org(): string {
    return encodeURIComponent(this.#organization);
  }

  async #paginate<T>(path: string, itemSchema: z.ZodType<T>): Promise<T[]> {
    const items: T[] = [];
    for (let page = 1; page <= this.#maxPages; page++) {
      const separator = path.includes("?") ? "&" : "?";

      const parsed = z.array(itemSchema).parse(
        // eslint-disable-next-line no-await-in-loop -- REST pagination is ordered and bounded.
        await this.#getJson(
          `${path}${separator}per_page=${String(PAGE_SIZE)}&page=${String(page)}`,
        ),
      );
      items.push(...parsed);
      if (parsed.length < PAGE_SIZE) return items;
    }
    throw new Error(
      `rest_page_limit_exceeded:${path.split("?", 1)[0] ?? path}`,
    );
  }

  async #request(url: string, init: RequestInit): Promise<unknown> {
    await this.#acquireRequestSlot();
    try {
      this.#requestCount++;
      if (this.#requestCount > this.#maxRequests)
        throw new Error("github_request_limit_exceeded");
      const headers = new Headers(init.headers);
      if (!headers.has("accept"))
        headers.set("accept", "application/vnd.github+json");
      headers.set("authorization", `Bearer ${this.#token}`);
      headers.set("user-agent", GITHUB_USER_AGENT);
      headers.set("x-github-api-version", "2022-11-28");
      const remainingMs =
        this.#deadlineAt === undefined
          ? REQUEST_TIMEOUT_MS
          : this.#deadlineAt - Date.now();
      if (remainingMs <= 0)
        throw new Error("github_access_audit_deadline_exceeded");
      const response = await this.#fetchImpl(url, {
        ...init,
        headers,
        signal: AbortSignal.timeout(Math.min(REQUEST_TIMEOUT_MS, remainingMs)),
      });
      if (!response.ok) {
        const detail = await readGitHubErrorDetail(response);
        const suffix = detail === null ? "" : `:${detail}`;
        throw new GitHubReadError(
          `github_http_${String(response.status)}${suffix}`,
          {
            status: response.status,
          },
        );
      }
      return await response.json();
    } finally {
      this.#releaseRequestSlot();
    }
  }

  #releaseRequestSlot(): void {
    const next = this.#requestWaiters.shift();
    if (next) next();
    else this.#requestsInFlight--;
  }

  async #acquireRequestSlot(): Promise<void> {
    if (this.#requestsInFlight >= this.#maxConcurrentRequests) {
      await new Promise<void>((resolve) => {
        this.#requestWaiters.push(resolve);
      });
      return;
    }
    this.#requestsInFlight++;
  }
}

async function readGitHubErrorDetail(
  response: Response,
): Promise<null | string> {
  try {
    const body = z
      .object({ message: z.string().max(500) })
      .safeParse(await response.json());
    return body.success
      ? body.data.message.replaceAll(/\s+/gu, " ").trim().slice(0, 200)
      : null;
  } catch {
    return null;
  }
}

async function boundedMap<Input, Output>(
  items: readonly Input[],
  operation: (item: Input) => Promise<Output>,
): Promise<Output[]> {
  const output: Output[] = [];
  for (let offset = 0; offset < items.length; offset += DETAIL_CONCURRENCY) {
    // eslint-disable-next-line no-await-in-loop -- Complete each bounded provider batch before admitting the next.
    const batch = await Promise.all(
      items.slice(offset, offset + DETAIL_CONCURRENCY).map(operation),
    );
    output.push(...batch);
  }
  return output;
}

class GitHubReadError extends Error {
  readonly status: number;

  constructor(message: string, options: ErrorOptions & { status: number }) {
    super(message, options);
    this.name = "GitHubReadError";
    this.status = options.status;
  }
}

function auditError(
  capability: GitHubCapability,
  error: unknown,
): GitHubAuditError {
  if (error instanceof GitHubReadError) {
    return {
      capability,
      code: `http_${String(error.status)}`,
      message: error.message,
    };
  }
  const message = error instanceof Error ? error.message : "unknown_error";
  return { capability, code: message.slice(0, 120), message };
}

const SAML_IDENTITIES_QUERY = `
  query GitHubAccessAuditSamlIdentities($organization: String!, $cursor: String) {
    organization(login: $organization) {
      samlIdentityProvider {
        externalIdentities(first: 100, after: $cursor) {
          nodes { guid samlIdentity { nameId } user { databaseId login } }
          pageInfo { endCursor hasNextPage }
        }
      }
    }
  }
`;
