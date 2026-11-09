import { z } from "zod";

import { runtimeFetch } from "../clients/runtime-fetch.ts";
import { fetchWithRetry, type Sleep } from "../org-sync/http.ts";
import { fetchPort } from "../runtime/fetch-port.ts";

const SENTRY_API_BASE = "https://sentry.io/api/0";
const DEFAULT_MAX_PAGES = 3;
// Three pages across each of the three base collections plus 25 details stays
// below Sentry's 40-per-second organization-member GET limit.
const DEFAULT_MAX_REQUESTS = 34;
const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_READ_DEADLINE_MS = 60_000;
const DEFAULT_READ_MAX_ATTEMPTS = 3;
const MAX_MEMBER_DETAIL_EMAILS = 50;
const MAX_MEMBER_DETAIL_TARGETS = 25;
const MEMBER_DETAIL_CONCURRENCY = 4;
const CallableSchema = z.function();
const IssuePathStringSchema = z.string();

const SlugSchema = z
  .string()
  .trim()
  .min(1)
  .max(64)
  .regex(/^[a-z0-9][a-z0-9_-]*$/u);
const EmailSchema = z.email().transform((value) => value.toLowerCase());
const PositiveIntegerSchema = z.number().int().positive();
const SentryProviderIdSchema = z.string().regex(/^\d{1,32}$/u);
const SentryScopeSchema = z
  .string()
  .min(3)
  .max(64)
  .regex(/^[a-z]+:[a-z]+$/u);
const SentryAuthorityFieldPathSchema = z.enum([
  "actor-detail.email",
  "actor-detail.expired",
  "actor-detail.id",
  "actor-detail.orgRole",
  "actor-detail.pending",
  "actor-detail.role",
  "actor-detail.teamRoles",
  "actor-detail.teams",
  "actor-detail.user",
  "actor-summary.email",
  "actor-summary.expired",
  "actor-summary.id",
  "actor-summary.orgRole",
  "actor-summary.pending",
  "actor-summary.user",
  "auth.auth",
  "auth.user",
  "organization.id",
  "organization.slug",
  "organization.status",
  "output.actor",
  "output.organization",
  "output.project",
  "output.team",
  "project.id",
  "project.organization",
  "project.slug",
  "project.status",
  "project.teams",
  "team.hasAccess",
  "team.id",
  "team.organization",
  "team.slug",
  "team.teamRole",
]);
const SentryAuthorityFailureReasonSchema = z.enum([
  "authority-mismatch",
  "credential-unconfigured",
  "provider-contract",
  "provider-unavailable",
  "unsupported-credential",
]);
const SentryAuthorityMismatchStageSchema = z.enum([
  "actor-detail-identity",
  "actor-state",
  "actor-summary-identity",
  "actor-team-role",
  "actor-role",
  "organization-status",
  "project-status",
  "project-team-binding",
  "team-access",
  "tenant-identity",
]);
type SentryAuthorityMismatchStage = z.output<
  typeof SentryAuthorityMismatchStageSchema
>;
const SENTRY_AUTHORITY_FALLBACK_FIELD_PATH = {
  "actor-detail": "actor-detail.user",
  "actor-summary": "actor-summary.user",
  auth: "auth.auth",
  organization: "organization.status",
  output: "output.actor",
  project: "project.organization",
  team: "team.organization",
} as const;
const ConfigSchema = z.strictObject({
  fetchImpl: z
    .custom<typeof fetch>((value) => CallableSchema.safeParse(value).success)
    .optional(),
  maxPages: PositiveIntegerSchema.default(DEFAULT_MAX_PAGES),
  maxRequests: PositiveIntegerSchema.default(DEFAULT_MAX_REQUESTS),
  organizationSlug: SlugSchema,
  projectSlug: SlugSchema,
  readDeadlineMs: PositiveIntegerSchema.default(DEFAULT_READ_DEADLINE_MS),
  readMaxAttempts: PositiveIntegerSchema.max(DEFAULT_READ_MAX_ATTEMPTS).default(
    DEFAULT_READ_MAX_ATTEMPTS,
  ),
  retrySleep: z
    .custom<Sleep>((value) => CallableSchema.safeParse(value).success)
    .optional(),
  requestTimeoutMs: PositiveIntegerSchema.default(DEFAULT_TIMEOUT_MS),
  teamSlug: SlugSchema,
  token: z.string().trim().min(1),
});

const SentryUserSchema = z.object({
  email: EmailSchema.optional(),
  id: z.string().trim().min(1).optional(),
});
const SentryIdentityUserSchema = z.object({ id: SentryProviderIdSchema });
const SentryOrganizationRoleSchema = z.enum([
  "admin",
  "billing",
  "manager",
  "member",
  "owner",
]);
const SentryTeamRoleSchema = z.enum(["admin", "contributor"]);
type SentryOrganizationRole = z.output<typeof SentryOrganizationRoleSchema>;
type SentryTeamRole = z.output<typeof SentryTeamRoleSchema>;

function effectiveSentryTeamRole(
  organizationRole: SentryOrganizationRole,
  explicitTeamRole: null | SentryTeamRole,
  isMember: boolean,
): null | SentryTeamRole {
  if (!isMember) return null;
  if (
    organizationRole === "admin" ||
    organizationRole === "manager" ||
    organizationRole === "owner"
  )
    return "admin";
  return explicitTeamRole ?? "contributor";
}

const SentryAuthInfoSchema = z.object({
  auth: z.object({ scopes: z.array(z.string()) }),
  user: SentryIdentityUserSchema.nullable(),
});
const SentryOrganizationMemberSummarySchema = z.object({
  email: EmailSchema.nullish(),
  expired: z.boolean(),
  id: z.string().trim().min(1),
  orgRole: SentryOrganizationRoleSchema,
  pending: z.boolean(),
  user: SentryUserSchema.nullish(),
});
export const SentryOrganizationMemberSchema =
  SentryOrganizationMemberSummarySchema.extend({
    role: SentryOrganizationRoleSchema,
    teamRoles: z.array(
      z.object({
        role: SentryTeamRoleSchema.nullable(),
        teamSlug: SlugSchema,
      }),
    ),
    teams: z.array(SlugSchema).nullish(),
  });
const SentryOrganizationMemberDetailSchema =
  SentryOrganizationMemberSchema.extend({
    teams: z.array(SlugSchema),
  });
export const SentryTeamMemberSchema = z.object({
  email: EmailSchema.nullish(),
  id: z.string().trim().min(1),
  pending: z.boolean().optional().default(false),
  user: SentryUserSchema.nullish(),
});
export const SentryProjectTeamSchema = z.object({
  id: z.string().trim().min(1),
  slug: SlugSchema,
});
const SentryOrganizationIdentitySchema = z.object({
  id: SentryProviderIdSchema,
  slug: SlugSchema,
  status: z.object({ id: z.string().trim().min(1) }),
});
const SentryNestedOrganizationIdentitySchema = z.object({
  id: SentryProviderIdSchema,
  slug: SlugSchema,
});
const SentryProjectIdentitySchema = z.object({
  id: SentryProviderIdSchema,
  organization: SentryNestedOrganizationIdentitySchema,
  slug: SlugSchema,
  status: z.string().trim().min(1),
  teams: z.array(SentryProjectTeamSchema),
});
const SentryTeamIdentitySchema = z.object({
  hasAccess: z.boolean(),
  id: SentryProviderIdSchema,
  isMember: z.boolean(),
  organization: SentryNestedOrganizationIdentitySchema,
  slug: SlugSchema,
  teamRole: SentryTeamRoleSchema.nullable(),
});
export const SentryWorkspaceAuthorityBootstrapSchema = z.strictObject({
  actor: z.strictObject({
    id: SentryProviderIdSchema,
    orgRole: SentryOrganizationRoleSchema,
    role: SentryOrganizationRoleSchema,
    scopes: z
      .array(SentryScopeSchema)
      .min(1)
      .max(50)
      .refine(
        (scopes) => new Set(scopes).size === scopes.length,
        "duplicate Sentry scopes",
      ),
    teamRole: SentryTeamRoleSchema.nullable(),
  }),
  organization: z.strictObject({
    id: SentryProviderIdSchema,
    slug: SlugSchema,
  }),
  project: z.strictObject({
    id: SentryProviderIdSchema,
    slug: SlugSchema,
  }),
  mode: z.literal("audit"),
  team: z.strictObject({
    id: SentryProviderIdSchema,
    slug: SlugSchema,
  }),
  writes: z.literal(0),
});
export const SentryWorkspaceAuthorityBootstrapFailureSchema = z
  .strictObject({
    error: z.literal("Sentry authority bootstrap failed"),
    fieldPaths: z.array(SentryAuthorityFieldPathSchema).max(32),
    mode: z.literal("audit"),
    readiness: z.literal("blocked"),
    reason: SentryAuthorityFailureReasonSchema,
    stage: SentryAuthorityMismatchStageSchema.optional(),
    writes: z.literal(0),
  })
  .meta({ id: "SentryWorkspaceAuthorityBootstrapFailure" });

export type SentryOrganizationMember = z.output<
  typeof SentryOrganizationMemberSchema
>;
export type SentryWorkspaceAuthorityBootstrap = z.output<
  typeof SentryWorkspaceAuthorityBootstrapSchema
>;
export type SentryTeamMember = z.output<typeof SentryTeamMemberSchema>;
export type SentryProjectTeam = z.output<typeof SentryProjectTeamSchema>;
export type SentryWorkspaceClientConfig = z.input<typeof ConfigSchema>;

export interface SentryWorkspaceSnapshot {
  readonly organizationMembers: readonly SentryOrganizationMember[];
  readonly projectTeams: readonly SentryProjectTeam[];
  readonly teamMembers: readonly SentryTeamMember[];
}

interface RequestBudget {
  count: number;
  deadlineAt: number;
}

export interface ISentryWorkspaceClient {
  addTeamMember(
    memberId: string,
    assertWriteAuthority?: () => Promise<void>,
  ): Promise<void>;
  assertCanRegenerateInvite(): Promise<void>;
  authorityBootstrap(): Promise<SentryWorkspaceAuthorityBootstrap>;
  invite(
    email: string,
    assertWriteAuthority?: () => Promise<void>,
  ): Promise<void>;
  listOrganizationMembers(): Promise<
    z.output<typeof OrganizationMembersSchema>
  >;
  reinvite(
    memberId: string,
    assertWriteAuthority?: () => Promise<void>,
  ): Promise<void>;
  removeOrganizationMember(
    memberId: string,
    assertWriteAuthority: () => Promise<void>,
  ): Promise<void>;
  snapshot(
    memberDetailEmails?: readonly string[],
  ): Promise<SentryWorkspaceSnapshot>;
}
const OrganizationMembersSchema = z.array(
  SentryOrganizationMemberSummarySchema,
);

interface SentryOrganizationInventoryClient {
  listOrganizationMembers(): Promise<
    z.output<typeof OrganizationMembersSchema>
  >;
}

/** A bounded Sentry adapter. Construction alone never enables provider writes. */
export class SentryWorkspaceClient
  implements ISentryWorkspaceClient, SentryOrganizationInventoryClient
{
  readonly #fetchImpl: typeof fetch;
  readonly #maxPages: number;
  readonly #maxRequests: number;
  readonly #organizationSlug: string;
  readonly #projectSlug: string;
  readonly #readDeadlineMs: number;
  readonly #readMaxAttempts: number;
  readonly #requestTimeoutMs: number;
  readonly #retrySleep: Sleep | undefined;
  readonly #teamSlug: string;
  readonly #token: string;

  constructor(rawConfig: SentryWorkspaceClientConfig) {
    const config = ConfigSchema.parse(rawConfig);
    this.#fetchImpl = fetchPort(config.fetchImpl ?? runtimeFetch);
    this.#maxPages = config.maxPages;
    this.#maxRequests = config.maxRequests;
    this.#organizationSlug = config.organizationSlug;
    this.#projectSlug = config.projectSlug;
    this.#readDeadlineMs = config.readDeadlineMs;
    this.#readMaxAttempts = config.readMaxAttempts;
    this.#requestTimeoutMs = config.requestTimeoutMs;
    this.#retrySleep = config.retrySleep;
    this.#teamSlug = config.teamSlug;
    this.#token = config.token;
  }

  async snapshot(
    rawMemberDetailEmails: readonly string[] = [],
  ): Promise<SentryWorkspaceSnapshot> {
    if (rawMemberDetailEmails.length > MAX_MEMBER_DETAIL_EMAILS) {
      throw new SentryWorkspaceBoundExceededError("member-detail");
    }
    const memberDetailEmails = new Set(
      rawMemberDetailEmails.map((email) => EmailSchema.parse(email)),
    );
    const budget = this.#requestBudget();
    const [listedOrganizationMembers, teamMembers, projectTeams] =
      await Promise.all([
        this.#paginate(
          `/organizations/${this.#organizationSlug}/members/`,
          SentryOrganizationMemberSummarySchema,
          budget,
        ),
        this.#paginate(
          `/teams/${this.#organizationSlug}/${this.#teamSlug}/members/`,
          SentryTeamMemberSchema,
          budget,
        ),
        this.#paginate(
          `/projects/${this.#organizationSlug}/${this.#projectSlug}/teams/`,
          SentryProjectTeamSchema,
          budget,
        ),
      ]);
    assertUniqueMemberSummaries(listedOrganizationMembers);
    const detailTargets = listedOrganizationMembers.filter((member) => {
      const email = sentryMemberEmail(member);
      return email !== null && memberDetailEmails.has(email);
    });
    if (detailTargets.length > MAX_MEMBER_DETAIL_TARGETS) {
      throw new SentryWorkspaceBoundExceededError("member-detail");
    }
    if (budget.count + detailTargets.length > this.#maxRequests) {
      throw new SentryWorkspaceBoundExceededError("request");
    }
    const detailedMembers: SentryOrganizationMember[] = [];
    for (
      let offset = 0;
      offset < detailTargets.length;
      offset += MEMBER_DETAIL_CONCURRENCY
    ) {
      const batch = detailTargets.slice(
        offset,
        offset + MEMBER_DETAIL_CONCURRENCY,
      );
      // eslint-disable-next-line no-await-in-loop -- fixed-size batches bound provider concurrency.
      const details = await Promise.all(
        batch.map((member) => this.#memberDetail(member, budget)),
      );
      detailedMembers.push(...details);
    }
    return { organizationMembers: detailedMembers, projectTeams, teamMembers };
  }

  // Complete organization inventory; unlike snapshot(), this is not a selected detail slice.
  async listOrganizationMembers() {
    const members = await this.#paginate(
      `/organizations/${this.#organizationSlug}/members/`,
      SentryOrganizationMemberSummarySchema,
      this.#requestBudget(),
    );
    assertUniqueMemberSummaries(members);
    return members;
  }

  async addTeamMember(
    memberId: string,
    assertWriteAuthority?: () => Promise<void>,
  ): Promise<void> {
    await this.#write(
      "POST",
      `/organizations/${this.#organizationSlug}/members/${encodeURIComponent(memberId)}/teams/${this.#teamSlug}/`,
      undefined,
      [201, 204],
      assertWriteAuthority,
    );
  }

  async removeOrganizationMember(
    memberId: string,
    assertWriteAuthority: () => Promise<void>,
  ): Promise<void> {
    await this.#write(
      "DELETE",
      `/organizations/${this.#organizationSlug}/members/${SentryProviderIdSchema.parse(memberId)}/`,
      undefined,
      [204],
      assertWriteAuthority,
    );
  }

  async assertCanRegenerateInvite(): Promise<void> {
    const response = await this.#request(
      `${SENTRY_API_BASE}/`,
      { method: "GET" },
      this.#requestBudget(),
    );
    const authInfo = SentryAuthInfoSchema.parse(await response.json());
    if (
      authInfo.user === null ||
      !authInfo.auth.scopes.includes("member:admin")
    ) {
      throw new SentryWorkspaceCapabilityError("member:admin");
    }
  }

  async authorityBootstrap(): Promise<SentryWorkspaceAuthorityBootstrap> {
    const budget = this.#requestBudget();
    const authResponse = await this.#request(
      `${SENTRY_API_BASE}/`,
      { method: "GET" },
      budget,
    );
    const authInfo = parseAuthorityProviderValue(
      SentryAuthInfoSchema,
      await authResponse.json(),
      "auth",
    );
    if (authInfo.user === null)
      throw new SentryWorkspaceUnsupportedCredentialError();
    const actorId = authInfo.user.id;
    const [organization, project, team, actorMemberSummaries] =
      await Promise.all([
        this.#read(
          `/organizations/${this.#organizationSlug}/`,
          SentryOrganizationIdentitySchema,
          budget,
          "organization",
        ),
        this.#read(
          `/projects/${this.#organizationSlug}/${this.#projectSlug}/`,
          SentryProjectIdentitySchema,
          budget,
          "project",
        ),
        this.#read(
          `/teams/${this.#organizationSlug}/${this.#teamSlug}/`,
          SentryTeamIdentitySchema,
          budget,
          "team",
        ),
        (async () => {
          const response = await this.#request(
            `${SENTRY_API_BASE}/organizations/${this.#organizationSlug}/members/?query=${encodeURIComponent(`user.id:${actorId}`)}`,
            { method: "GET" },
            budget,
          );
          return parseAuthorityProviderValue(
            OrganizationMembersSchema,
            await response.json(),
            "actor-summary",
          );
        })(),
      ]);
    const actorSummary =
      actorMemberSummaries.length === 1 ? actorMemberSummaries[0] : undefined;
    if (actorSummary?.user?.id !== actorId) {
      throw new SentryWorkspaceAuthorityBootstrapError(
        "actor-summary-identity",
      );
    }
    const actor = await this.#memberDetail(
      actorSummary,
      budget,
      "actor-detail",
    );
    const actorManagedTeamRoles = actor.teamRoles.filter(
      ({ teamSlug }) => teamSlug === this.#teamSlug,
    );
    const actorExplicitTeamRole = actorManagedTeamRoles[0]?.role ?? null;
    const actorEffectiveTeamRole = effectiveSentryTeamRole(
      actor.orgRole,
      actorExplicitTeamRole,
      team.isMember,
    );
    const projectAttached = project.teams.some(
      ({ id, slug }) => id === team.id && slug === team.slug,
    );
    const mismatchStage = firstAuthorityMismatchStage([
      [actor.user?.id !== actorId, "actor-detail-identity"],
      [actor.pending || actor.expired, "actor-state"],
      [actor.role !== actor.orgRole, "actor-role"],
      [
        actorManagedTeamRoles.length > 1 ||
          team.isMember !== (actorManagedTeamRoles.length === 1) ||
          actorEffectiveTeamRole !== team.teamRole,
        "actor-team-role",
      ],
      [
        organization.id !== project.organization.id ||
          organization.id !== team.organization.id ||
          organization.slug !== this.#organizationSlug ||
          organization.slug !== project.organization.slug ||
          organization.slug !== team.organization.slug ||
          project.slug !== this.#projectSlug ||
          team.slug !== this.#teamSlug,
        "tenant-identity",
      ],
      [organization.status.id !== "active", "organization-status"],
      [project.status !== "active", "project-status"],
      [!team.hasAccess, "team-access"],
      [!projectAttached, "project-team-binding"],
    ]);
    if (mismatchStage !== null)
      throw new SentryWorkspaceAuthorityBootstrapError(mismatchStage);
    return parseAuthorityProviderValue(
      SentryWorkspaceAuthorityBootstrapSchema,
      {
        actor: {
          id: actorId,
          orgRole: actor.orgRole,
          role: actor.role,
          scopes: [...new Set(authInfo.auth.scopes)].toSorted((left, right) =>
            left.localeCompare(right),
          ),
          teamRole: actorEffectiveTeamRole,
        },
        organization: {
          id: organization.id,
          slug: organization.slug,
        },
        mode: "audit",
        project: {
          id: project.id,
          slug: project.slug,
        },
        team: {
          id: team.id,
          slug: team.slug,
        },
        writes: 0,
      },
      "output",
    );
  }

  async invite(
    email: string,
    assertWriteAuthority?: () => Promise<void>,
  ): Promise<void> {
    await this.#write(
      "POST",
      `/organizations/${this.#organizationSlug}/members/`,
      {
        email: EmailSchema.parse(email),
        orgRole: "member",
        teamRoles: [{ role: "contributor", teamSlug: this.#teamSlug }],
      },
      [201],
      assertWriteAuthority,
    );
  }

  async reinvite(
    memberId: string,
    assertWriteAuthority?: () => Promise<void>,
  ): Promise<void> {
    await this.#write(
      "PUT",
      `/organizations/${this.#organizationSlug}/members/${encodeURIComponent(memberId)}/`,
      {
        regenerate: true,
        reinvite: true,
      },
      [200],
      assertWriteAuthority,
    );
  }

  async #memberDetail(
    listedMember: z.output<typeof SentryOrganizationMemberSummarySchema>,
    budget: RequestBudget,
    authorityBoundary?: "actor-detail",
  ): Promise<SentryOrganizationMember> {
    const response = await this.#request(
      `${SENTRY_API_BASE}/organizations/${this.#organizationSlug}/members/${encodeURIComponent(listedMember.id)}/`,
      { method: "GET" },
      budget,
    );
    const rawDetailed: unknown = await response.json();
    const detailed =
      authorityBoundary === undefined
        ? SentryOrganizationMemberDetailSchema.parse(rawDetailed)
        : parseAuthorityProviderValue(
            SentryOrganizationMemberDetailSchema,
            rawDetailed,
            authorityBoundary,
          );
    if (
      detailed.id !== listedMember.id ||
      sentryMemberEmail(detailed) !== sentryMemberEmail(listedMember)
    ) {
      throw new Error("sentry_workspace_member_detail_mismatch");
    }
    return detailed;
  }

  async #read<T>(
    path: string,
    schema: z.ZodType<T>,
    budget: RequestBudget,
    authorityBoundary?: "organization" | "project" | "team",
  ): Promise<T> {
    const response = await this.#request(
      `${SENTRY_API_BASE}${path}`,
      { method: "GET" },
      budget,
    );
    const value: unknown = await response.json();
    return authorityBoundary === undefined
      ? schema.parse(value)
      : parseAuthorityProviderValue(schema, value, authorityBoundary);
  }

  async #paginate<T>(
    path: string,
    schema: z.ZodType<T>,
    budget: RequestBudget,
  ): Promise<T[]> {
    const values: T[] = [];
    const initialUrl = `${SENTRY_API_BASE}${path}`;
    const readPage = async (url: string, page: number): Promise<void> => {
      if (page >= this.#maxPages)
        throw new SentryWorkspaceBoundExceededError("page");
      const response = await this.#request(url, { method: "GET" }, budget);
      const body: unknown = await response.json();
      values.push(...z.array(schema).parse(body));
      const following = nextPage(response.headers.get("link"), initialUrl);
      if (following !== null) await readPage(following, page + 1);
    };
    await readPage(initialUrl, 0);
    return values;
  }

  async #write(
    method: "DELETE" | "POST" | "PUT",
    path: string,
    body: unknown,
    expectedStatuses: readonly number[],
    assertWriteAuthority?: () => Promise<void>,
  ): Promise<void> {
    const budget = this.#requestBudget();
    const init: RequestInit =
      body === undefined ? { method } : { body: JSON.stringify(body), method };
    await assertWriteAuthority?.();
    const response = await this.#request(
      `${SENTRY_API_BASE}${path}`,
      init,
      budget,
    );
    if (!expectedStatuses.includes(response.status)) {
      throw new SentryWorkspaceUnexpectedMutationStatusError(response.status);
    }
  }

  async #request(
    url: string,
    init: RequestInit,
    budget: RequestBudget,
  ): Promise<Response> {
    const headers = new Headers(init.headers);
    headers.set("accept", "application/json");
    headers.set("authorization", `Bearer ${this.#token}`);
    if (init.body !== undefined)
      headers.set("content-type", "application/json");
    const request = {
      ...init,
      headers,
      redirect: "manual",
    } satisfies RequestInit;
    const countedFetch: typeof fetch = async (input, countedInit) => {
      budget.count += 1;
      if (budget.count > this.#maxRequests)
        throw new SentryWorkspaceBoundExceededError("request");
      return this.#fetchImpl(input, countedInit);
    };
    const response =
      init.method === "GET"
        ? await fetchWithRetry(url, request, {
            deadlineAt: budget.deadlineAt,
            fetchImpl: countedFetch,
            label: "sentry.workspace.read",
            maxAttempts: this.#readMaxAttempts,
            respectRetryAfter: true,
            retryError: (error) =>
              !(error instanceof SentryWorkspaceBoundExceededError),
            ...(!(this.#retrySleep === undefined) && {
              sleep: this.#retrySleep,
            }),
            timeoutMs: this.#requestTimeoutMs,
          })
        : await countedFetch(url, {
            ...request,
            signal: AbortSignal.timeout(this.#requestTimeoutMs),
          });
    if (!response.ok) throw new SentryWorkspaceRequestError(response.status);
    return response;
  }

  #requestBudget(): RequestBudget {
    return { count: 0, deadlineAt: Date.now() + this.#readDeadlineMs };
  }
}

function nextPage(link: null | string, initialUrl: string): null | string {
  if (link === null || link.trim() === "") return null;
  for (const segment of link.split(",")) {
    const match = /^\s*<([^>]+)>;\s*(.*)$/u.exec(segment);
    if (match?.[1] === undefined || match[2] === undefined) continue;
    if (/\brel="next"/u.test(match[2]) && /\bresults="true"/u.test(match[2])) {
      const next = new URL(match[1]);
      const initial = new URL(initialUrl);
      if (
        next.origin !== initial.origin ||
        next.pathname !== initial.pathname ||
        next.username !== "" ||
        next.password !== ""
      ) {
        throw new Error("sentry_workspace_untrusted_pagination_url");
      }
      return next.href;
    }
  }
  return null;
}

function assertUniqueMemberSummaries(
  members: readonly z.output<typeof SentryOrganizationMemberSummarySchema>[],
): void {
  const emails = new Set<string>();
  const ids = new Set<string>();
  for (const member of members) {
    const email = sentryMemberEmail(member);
    if (email === null || emails.has(email) || ids.has(member.id)) {
      throw new Error("sentry_workspace_member_summary_ambiguous");
    }
    emails.add(email);
    ids.add(member.id);
  }
}

export function sentryMemberEmail(member: {
  readonly email?: null | string | undefined;
  readonly user?: { readonly email?: string | undefined } | null | undefined;
}): null | string {
  const email = member.email ?? member.user?.email;
  return email === undefined ? null : EmailSchema.parse(email);
}

export class SentryWorkspaceBoundExceededError extends Error {
  constructor(
    bound: "member-detail" | "page" | "request",
    options?: ErrorOptions,
  ) {
    super(`sentry_workspace_${bound}_bound_exceeded`, options);
    this.name = "SentryWorkspaceBoundExceededError";
  }
}

export class SentryWorkspaceRequestError extends Error {
  readonly status: number;
  constructor(status: number, options?: ErrorOptions) {
    super(`sentry_workspace_request_failed:${String(status)}`, options);
    this.name = "SentryWorkspaceRequestError";
    this.status = status;
  }
}

export class SentryWorkspaceUnexpectedMutationStatusError extends Error {
  readonly status: number;
  constructor(status: number, options?: ErrorOptions) {
    super(
      `sentry_workspace_unexpected_mutation_status:${String(status)}`,
      options,
    );
    this.name = "SentryWorkspaceUnexpectedMutationStatusError";
    this.status = status;
  }
}

export class SentryWorkspaceCapabilityError extends Error {
  constructor(capability: "member:admin", options?: ErrorOptions) {
    super(`sentry_workspace_missing_capability:${capability}`, options);
    this.name = "SentryWorkspaceCapabilityError";
  }
}

export class SentryWorkspaceAuthorityBootstrapError extends Error {
  readonly stage: SentryAuthorityMismatchStage;

  constructor(stage: SentryAuthorityMismatchStage, options?: ErrorOptions) {
    super("sentry_workspace_authority_bootstrap_failed", options);
    this.name = "SentryWorkspaceAuthorityBootstrapError";
    this.stage = stage;
  }
}

function firstAuthorityMismatchStage(
  checks: readonly (readonly [boolean, SentryAuthorityMismatchStage])[],
): null | SentryAuthorityMismatchStage {
  return checks.find(([mismatch]) => mismatch)?.[1] ?? null;
}

export class SentryWorkspaceProviderContractError extends Error {
  readonly fieldPaths: readonly z.output<
    typeof SentryAuthorityFieldPathSchema
  >[];

  constructor(
    fieldPaths: readonly z.output<typeof SentryAuthorityFieldPathSchema>[],
    options?: ErrorOptions,
  ) {
    super("sentry_workspace_provider_contract_invalid", options);
    this.name = "SentryWorkspaceProviderContractError";
    this.fieldPaths = fieldPaths;
  }
}

export class SentryWorkspaceUnsupportedCredentialError extends Error {
  constructor() {
    super("sentry_workspace_unsupported_credential");
    this.name = "SentryWorkspaceUnsupportedCredentialError";
  }
}

function parseAuthorityProviderValue<T>(
  schema: z.ZodType<T>,
  value: unknown,
  boundary:
    | "actor-detail"
    | "actor-summary"
    | "auth"
    | "organization"
    | "output"
    | "project"
    | "team",
): T {
  const parsed = schema.safeParse(value);
  if (parsed.success) return parsed.data;
  const paths = new Set<z.output<typeof SentryAuthorityFieldPathSchema>>();
  for (const issue of parsed.error.issues) {
    const pathPart = IssuePathStringSchema.safeParse(issue.path[0]);
    const first = pathPart.success ? pathPart.data : undefined;
    const candidate = first === undefined ? undefined : `${boundary}.${first}`;
    const safe = SentryAuthorityFieldPathSchema.safeParse(candidate);
    if (safe.success) paths.add(safe.data);
  }
  if (paths.size === 0) {
    const fallback = SENTRY_AUTHORITY_FALLBACK_FIELD_PATH[boundary];
    paths.add(fallback);
  }
  throw new SentryWorkspaceProviderContractError(
    [...paths].toSorted(
      (sortLeft, sortRight) =>
        Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
    ),
  );
}
