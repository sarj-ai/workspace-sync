import { z } from "zod";

import {
  GitHubLoginSchema,
  GitHubUserIdSchema,
} from "../catalog/identity-authority.ts";
import { githubConditionalReadFetch } from "../clients/github-conditional-read-fetch.ts";
import {
  matchesReviewedGitHubDirectGrants,
  type ReviewedGitHubDirectGrantRetention,
} from "../github-access-audit/reviewed-direct-grants.ts";
import {
  correlateGitHubInvitation,
  GitHubOrganizationActorSchema,
  GitHubOrganizationInvitationSchema,
  resolveGitHubInvitationActors,
  unresolvedGitHubInvitations,
} from "../github/organization-membership-reader.ts";
import { resolveDirectRepositoryGrants } from "../github/resolve-direct-repository-grants.ts";
import { fetchPort } from "../runtime/fetch-port.ts";
import {
  GitHubMutationReceiptSchema,
  GitHubObservedOrganizationAccountSchema,
  type GitHubProvisioningOperation,
  type MutatingGitHubOrganizationPort,
  ReviewedDirectGrantRetentionSchema,
} from "./github-organization-connector.ts";
import {
  type GithubDispatchClaim,
  GithubDispatchClaimSchema,
  type GithubPrewriteRefusalCategory,
} from "./github-zero-dispatch.ts";

const MembershipStateSchema = z.enum(["active", "pending"]);

const GITHUB_API_BASE = "https://api.github.com";
const GITHUB_API_VERSION = "2022-11-28";
const PAGE_SIZE = 100;
const DEFAULT_MAX_PAGES = 10;
const DEFAULT_MAX_REQUESTS = 250;
const DEFAULT_REQUEST_TIMEOUT_MS = 15_000;

const OrganizationLoginSchema = z
  .string()
  .min(1)
  .max(39)
  .regex(/^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9]))*$/u)
  .transform((value) => value.toLowerCase());
const OrganizationIdSchema = z.string().regex(/^[1-9]\d*$/u);
const TeamSlugSchema = z
  .string()
  .min(1)
  .max(100)
  .regex(/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u);
const PositiveIntegerSchema = z.number().int().positive();
const CallableSchema = z.function();
const ConfigSchema = z
  .strictObject({
    fetchImpl: z
      .custom<typeof fetch>((value) => CallableSchema.safeParse(value).success)
      .optional(),
    managedTeamPins: z
      .record(TeamSlugSchema, PositiveIntegerSchema)
      .optional()
      .default({}),
    managedTeamSlugs: z.array(TeamSlugSchema).min(1).readonly(),
    maxPages: PositiveIntegerSchema.default(DEFAULT_MAX_PAGES),
    maxRequests: PositiveIntegerSchema.default(DEFAULT_MAX_REQUESTS),
    organizationId: OrganizationIdSchema,
    organizationLogin: OrganizationLoginSchema,
    requestTimeoutMs: PositiveIntegerSchema.default(DEFAULT_REQUEST_TIMEOUT_MS),
    reviewedDirectGrantRetentions: z
      .array(ReviewedDirectGrantRetentionSchema)
      .readonly()
      .default([]),
    samlToken: z.string().min(1),
    token: z.string().min(1),
  })
  .superRefine((config, context) => {
    if (
      new Set(config.managedTeamSlugs).size !== config.managedTeamSlugs.length
    ) {
      context.addIssue({
        code: "custom",
        message: "managedTeamSlugs must not contain duplicates",
      });
    }
    const managed = new Set(config.managedTeamSlugs);
    if (
      Object.keys(config.managedTeamPins).some((slug) => !managed.has(slug))
    ) {
      context.addIssue({
        code: "custom",
        message: "managedTeamPins must stay inside the managed-team boundary",
        path: ["managedTeamPins"],
      });
    }
    if (config.maxRequests < config.managedTeamSlugs.length * 2 + 5) {
      context.addIssue({
        code: "custom",
        message:
          "maxRequests cannot capture the configured managed-team boundary",
        path: ["maxRequests"],
      });
    }
  });

const OrganizationPinSchema = z.object({
  id: PositiveIntegerSchema,
  login: OrganizationLoginSchema,
});
const OrganizationSchema = OrganizationPinSchema.extend({
  "owned_private_repos": z.number().int().nonnegative(),
  "public_repos": z.number().int().nonnegative(),
});
const UserSchema = z.object({
  id: PositiveIntegerSchema,
  login: GitHubLoginSchema,
});
const MembershipSchema = z.object({
  role: z.enum(["admin", "member"]),
  state: MembershipStateSchema,
  user: UserSchema,
});
const RepositorySchema = z.object({
  "full_name": z.string().regex(/^[^/]+\/[^/]+$/u),
  id: PositiveIntegerSchema,
});
const CollaboratorSchema = UserSchema.extend({
  permissions: z.object({
    admin: z.boolean().default(false),
    maintain: z.boolean().default(false),
    pull: z.boolean().default(false),
    push: z.boolean().default(false),
    triage: z.boolean().default(false),
  }),
});
const TeamSchema = z.object({
  id: PositiveIntegerSchema,
  slug: TeamSlugSchema,
});
const TeamMembershipSchema = z.object({
  role: z.enum(["maintainer", "member"]),
  state: MembershipStateSchema,
});
const TeamMemberSchema = UserSchema.extend({
  inherited: z.boolean().optional().default(false),
});
const SamlResponseSchema = z.object({
  data: z.object({
    organization: z.object({
      samlIdentityProvider: z.object({
        externalIdentities: z.object({
          nodes: z.array(
            z.object({
              samlIdentity: z
                .object({ nameId: z.string().nullable() })
                .nullable(),
              user: z
                .object({
                  databaseId: PositiveIntegerSchema,
                  login: GitHubLoginSchema,
                })
                .nullable(),
            }),
          ),
          pageInfo: z.object({
            endCursor: z.string().nullable(),
            hasNextPage: z.boolean(),
          }),
        }),
      }),
    }),
  }),
  errors: z.array(z.object({ message: z.string() })).optional(),
});
type DirectRepositoryGrantInput = z.input<
  typeof GitHubObservedOrganizationAccountSchema
>["directRepositoryGrants"][number];
type TeamMembershipInput = z.input<
  typeof GitHubObservedOrganizationAccountSchema
>["teamMemberships"][number];
interface RequestBudget {
  requests: number;
}
const OBSERVATION_STAGES = [
  "direct_grants",
  "identity_pins",
  "invitations",
  "membership",
  "outside_collaborator",
  "repositories",
  "result_schema",
  "saml",
  "team_memberships",
  "teams",
  "writer_tenant_probe",
] as const;
type ObservationStage = (typeof OBSERVATION_STAGES)[number];

export type GitHubOrganizationApiPortConfig = z.input<typeof ConfigSchema>;

export async function assertDistinctGitHubOrganizationCredentials(
  samlToken: string,
  writerToken: string,
): Promise<void> {
  const encoder = new TextEncoder();
  const [samlDigest, writerDigest] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(samlToken)),
    crypto.subtle.digest("SHA-256", encoder.encode(writerToken)),
  ]);
  const samlBytes = new Uint8Array(samlDigest);
  const writerBytes = new Uint8Array(writerDigest);
  let difference = 0;
  for (const [index, samlByte] of samlBytes.entries()) {
    difference |= samlByte ^ (writerBytes[index] ?? 0);
  }
  if (difference === 0) throw new GitHubCredentialSeparationError();
}

/**
 * Bounded first-party GitHub organization adapter. Constructing this port does
 * not enable a workflow; production writes still require explicit runtime wiring.
 */
export class GitHubOrganizationApiPort implements MutatingGitHubOrganizationPort {
  readonly capability = "mutating";
  #credentialReadiness: Promise<void> | undefined;
  readonly #fetchImpl: typeof fetch;
  readonly #managedTeamSlugs: readonly z.output<typeof TeamSlugSchema>[];
  readonly #managedTeamPins: Readonly<Record<string, number>>;
  readonly #maxPages: number;
  readonly #maxRequests: number;
  readonly #organizationId: string;
  readonly #organizationLogin: string;
  readonly #requestTimeoutMs: number;
  readonly #reviewedDirectGrantRetentions: readonly ReviewedGitHubDirectGrantRetention[];
  readonly #samlToken: string;
  readonly #token: string;

  constructor(rawConfig: GitHubOrganizationApiPortConfig) {
    const config = ConfigSchema.parse({
      fetchImpl: rawConfig.fetchImpl,
      managedTeamPins: rawConfig.managedTeamPins,
      managedTeamSlugs: rawConfig.managedTeamSlugs,
      maxPages: rawConfig.maxPages,
      maxRequests: rawConfig.maxRequests,
      organizationId: rawConfig.organizationId,
      organizationLogin: rawConfig.organizationLogin,
      requestTimeoutMs: rawConfig.requestTimeoutMs,
      reviewedDirectGrantRetentions: rawConfig.reviewedDirectGrantRetentions,
      samlToken: rawConfig.samlToken,
      token: rawConfig.token,
    });
    // Workers' native fetch validates its receiver. Calling a stored reference
    // as a private-field method binds the port instance and throws before an
    // HTTP response exists, so keep the runtime global call receiver-safe.
    this.#fetchImpl = fetchPort(config.fetchImpl ?? githubConditionalReadFetch);
    this.#managedTeamPins = config.managedTeamPins;
    this.#managedTeamSlugs = config.managedTeamSlugs.toSorted();
    this.#maxPages = config.maxPages;
    this.#maxRequests = config.maxRequests;
    this.#organizationId = config.organizationId;
    this.#organizationLogin = config.organizationLogin;
    this.#requestTimeoutMs = config.requestTimeoutMs;
    this.#reviewedDirectGrantRetentions = config.reviewedDirectGrantRetentions;
    this.#samlToken = config.samlToken;
    this.#token = config.token;
  }

  async observeAccount(rawIdentity: {
    readonly primaryEmail?: string;
    readonly githubLogin: z.output<typeof GitHubLoginSchema>;
    readonly githubUserId: z.output<typeof GitHubUserIdSchema>;
  }) {
    await this.verifyWriterTenant();
    const budget: RequestBudget = { requests: 0 };
    const identity = {
      githubLogin: GitHubLoginSchema.parse(rawIdentity.githubLogin),
      githubUserId: GitHubUserIdSchema.parse(rawIdentity.githubUserId),
    };
    const organization = await observeStage("identity_pins", () =>
      this.#assertPins(identity, budget),
    );
    const teams = await observeStage("teams", () =>
      this.#paginate(`/orgs/${this.#org()}/teams`, TeamSchema, budget),
    );
    if (
      this.#managedTeamSlugs.some(
        (slug) => !teams.some((team) => team.slug === slug),
      ) ||
      Object.entries(this.#managedTeamPins).some(
        ([slug, id]) =>
          !teams.some((team) => team.slug === slug && team.id === id),
      )
    ) {
      throw new GitHubOrganizationScopeError();
    }
    const [
      membership,
      pendingInvitations,
      outsideCollaborator,
      teamMemberships,
      repositories,
      samlLinked,
    ] = await Promise.all([
      observeStage("membership", () => this.#membership(identity, budget)),
      observeStage("invitations", () => this.#invitations(budget)),
      observeStage("outside_collaborator", () =>
        this.#isOutsideCollaborator(identity.githubLogin, budget),
      ),
      observeStage("team_memberships", () =>
        this.#teamMemberships(identity, teams, budget),
      ),
      observeStage("repositories", () =>
        this.#paginate(
          `/orgs/${this.#org()}/repos?type=all&sort=full_name`,
          RepositorySchema,
          budget,
        ),
      ),
      observeStage("saml", () => this.#samlLinked(identity, budget)),
    ]);
    const expectedRepositoryCount =
      organization["public_repos"] + organization["owned_private_repos"];
    const repositoryInventoryComplete =
      new Set(repositories.map(({ id }) => id)).size ===
      expectedRepositoryCount;
    const directRepositoryGrants: DirectRepositoryGrantInput[] = [];
    for (const repository of repositories) {
      if (
        repository["full_name"].split("/", 2)[0]?.toLowerCase() !==
        this.#organizationLogin
      ) {
        throw new GitHubOrganizationPinError();
      }
      // GitHub has no organization-wide direct-grant lookup; this bounded scan is deliberate.
      // eslint-disable-next-line no-await-in-loop -- Serial reads enforce the global request budget.
      const collaborators = await observeStage("direct_grants", async () => {
        const actors = await this.#paginate(
          `/repos/${repository["full_name"]
            .split("/")
            .map((part) => encodeURIComponent(part))
            .join("/")}/collaborators?affiliation=direct`,
          CollaboratorSchema,
          budget,
        );
        if (
          !actors.some(
            (candidate) => String(candidate.id) === identity.githubUserId,
          )
        )
          return [];
        return resolveDirectRepositoryGrants(
          repository,
          actors,
          async (query, variables) => {
            const response = await this.#request(
              "/graphql",
              {
                body: JSON.stringify({ query, variables }),
                headers: { "content-type": "application/json" },
                method: "POST",
              },
              budget,
            );
            if (!response.ok)
              throw await githubHttpError(
                response,
                "observe direct grant sources",
              );
            return response.json();
          },
          this.#maxPages,
        );
      });
      const collaborator = collaborators.find(
        (candidate) => String(candidate.id) === identity.githubUserId,
      );
      if (collaborator === undefined) continue;
      directRepositoryGrants.push({
        ...identity,
        ...(collaborator.customRoleName !== undefined && {
          customRoleName: collaborator.customRoleName,
        }),
        ...(collaborator.unresolvedDirectRole === true && {
          unresolvedDirectRole: true as const,
        }),
        permission: permissionFor(collaborator.permissions),
        repositoryId: repository.id,
        repositoryName: repository["full_name"],
      });
    }
    return observeStage("result_schema", () =>
      Promise.resolve(
        GitHubObservedOrganizationAccountSchema.parse({
          complete: true,
          directRepositoryGrants,
          identity,
          membership,
          observedAt: new Date().toISOString(),
          outsideCollaborator,
          pendingInvitations: pendingInvitations
            .filter(
              (invitation) =>
                correlateGitHubInvitation(invitation, {
                  ...identity,
                  primaryEmail: rawIdentity.primaryEmail,
                }) === "match",
            )
            .map((invitation) => ({
              ...identity,
              invitationId: invitation.id,
              role: invitation.role,
            })),
          ...unresolvedGitHubInvitations(pendingInvitations, {
            ...identity,
            primaryEmail: rawIdentity.primaryEmail,
          }),
          repositoryInventoryComplete,
          samlLinked,
          teamMemberships,
        }),
      ),
    );
  }

  /* Verifies credential separation and the immutable writer organization pin without writing. */
  async verifyWriterTenant(): Promise<void> {
    await observeStage("writer_tenant_probe", () =>
      this.#assertCredentialReadiness(),
    );
  }

  async execute(
    operation: GitHubProvisioningOperation,
    assertFinalWriteAuthority?: () => Promise<void>,
    dispatchClaim?: GithubDispatchClaim,
  ) {
    const boundary = githubPrewriteBoundary();
    let category: GithubPrewriteRefusalCategory = "scope";
    try {
      if (
        "teamSlug" in operation &&
        !this.#managedTeamSlugs.includes(operation.teamSlug)
      )
        throw new GitHubOrganizationScopeError();
      category = "credentials";
      await this.#assertCredentialReadiness();
      category = "provider-observation";
      await this.#assertSafePrewrite(
        operation,
        assertFinalWriteAuthority !== undefined,
      );
      category = "final-authority";
      await assertFinalWriteAuthority?.();
    } catch (error) {
      if (dispatchClaim !== undefined)
        throw boundary.refuse(dispatchClaim, operation, category, error);
      throw error;
    }
    boundary.markDispatched();
    const budget: RequestBudget = { requests: 0 };
    switch (operation.kind) {
      case "invite-organization-member":
        await this.#write(
          "PUT",
          `/orgs/${this.#org()}/memberships/${encodeURIComponent(operation.githubLogin)}`,
          [200, 201],
          budget,
          { role: "member" },
        );
        break;
      case "cancel-invitation":
        await this.#write(
          "DELETE",
          `/orgs/${this.#org()}/invitations/${String(operation.invitationId)}`,
          [204, 404],
          budget,
        );
        break;
      case "remove-organization-member":
        await this.#write(
          "DELETE",
          `/orgs/${this.#org()}/memberships/${encodeURIComponent(operation.githubLogin)}`,
          [204, 404],
          budget,
        );
        break;
      case "add-team-member":
        await this.#write(
          "PUT",
          `/orgs/${this.#org()}/teams/${encodeURIComponent(operation.teamSlug)}/memberships/${encodeURIComponent(operation.githubLogin)}`,
          [200],
          budget,
          { role: "member" },
        );
        break;
      case "remove-team-member":
        await this.#write(
          "DELETE",
          `/orgs/${this.#org()}/teams/${encodeURIComponent(operation.teamSlug)}/memberships/${encodeURIComponent(operation.githubLogin)}`,
          [204, 404],
          budget,
        );
        break;
    }
    return this.#verifyOperation(operation, budget);
  }

  async #assertSafePrewrite(
    operation: GitHubProvisioningOperation,
    hasFinalAuthorityGuard: boolean,
  ): Promise<void> {
    const observed = GitHubObservedOrganizationAccountSchema.parse(
      await this.observeAccount({
        githubLogin: operation.githubLogin,
        githubUserId: operation.githubUserId,
      }),
    );
    if (
      (observed.unresolvedInvitations &&
        !(
          observed.unresolvedInvitations === "opaque-direct" &&
          observed.membership?.role === "member" &&
          operation.kind === "add-team-member"
        )) ||
      Object.values(
        githubPrewriteSafetyFlags(
          operation,
          observed,
          hasFinalAuthorityGuard ? this.#reviewedDirectGrantRetentions : [],
        ),
      ).some(Boolean)
    )
      throw new GitHubPreWriteSafetyError();
  }

  async #assertCredentialReadiness(): Promise<void> {
    this.#credentialReadiness ??=
      this.#verifyCredentialSeparationAndWriterTenant();
    try {
      await this.#credentialReadiness;
    } catch (error) {
      this.#credentialReadiness = undefined;
      throw error;
    }
  }

  async #verifyCredentialSeparationAndWriterTenant(): Promise<void> {
    await assertDistinctGitHubOrganizationCredentials(
      this.#samlToken,
      this.#token,
    );
    const response = await this.#requestWithCredential(
      `/orgs/${this.#org()}`,
      { method: "GET" },
      { requests: 0 },
      this.#token,
    );
    if (!response.ok)
      throw await githubHttpError(response, "verify writer organization");
    // A deliberately narrow writer credential only needs organization metadata.
    // Private-repository counts belong to the audit credential's inventory read.
    const organization = OrganizationPinSchema.parse(
      await response.json().catch(() => {
        throw new GitHubWriterTenantResponseError();
      }),
    );
    if (
      String(organization.id) !== this.#organizationId ||
      organization.login !== this.#organizationLogin
    ) {
      throw new GitHubOrganizationPinError();
    }
  }

  async #assertPins(
    identity: {
      githubLogin: z.output<typeof GitHubLoginSchema>;
      githubUserId: z.output<typeof GitHubUserIdSchema>;
    },
    budget: RequestBudget,
  ): Promise<z.output<typeof OrganizationSchema>> {
    const [organization, user] = await Promise.all([
      this.#json(`/orgs/${this.#org()}`, OrganizationSchema, budget),
      this.#json(
        `/users/${encodeURIComponent(identity.githubLogin)}`,
        UserSchema,
        budget,
      ),
    ]);
    if (
      String(organization.id) !== this.#organizationId ||
      organization.login !== this.#organizationLogin
    ) {
      throw new GitHubOrganizationPinError();
    }
    if (
      String(user.id) !== identity.githubUserId ||
      user.login !== identity.githubLogin
    ) {
      throw new GitHubIdentityPinError();
    }
    return organization;
  }

  async #invitations(budget: RequestBudget) {
    const invitations = await this.#paginate(
      `/orgs/${this.#org()}/invitations`,
      GitHubOrganizationInvitationSchema,
      budget,
    );
    const resolved = await resolveGitHubInvitationActors(
      invitations,
      async (login) =>
        this.#json(
          `/users/${encodeURIComponent(login)}`,
          GitHubOrganizationActorSchema,
          budget,
        ),
    );
    if (
      resolved.some(
        (invitation) =>
          !invitation.invitee && invitation.role !== "direct_member",
      )
    )
      throw new GitHubUnresolvedPrivilegedInvitationError();
    return resolved;
  }

  async #isOutsideCollaborator(
    login: z.output<typeof GitHubLoginSchema>,
    budget: RequestBudget,
  ): Promise<boolean> {
    const response = await this.#request(
      `/orgs/${this.#org()}/outside_collaborators/${encodeURIComponent(login)}`,
      { method: "GET" },
      budget,
    );
    if (response.status === 204) return true;
    if (response.status === 404) return false;
    throw await githubHttpError(response, "observe outside collaborator");
  }

  async #membership(
    identity: {
      githubLogin: z.output<typeof GitHubLoginSchema>;
      githubUserId: z.output<typeof GitHubUserIdSchema>;
    },
    budget: RequestBudget,
  ) {
    const membership = await this.#membershipState(identity, budget);
    if (membership?.state !== "active") return null;
    return {
      ...identity,
      role:
        membership.role === "admin" ? ("owner" as const) : ("member" as const),
    };
  }

  async #membershipState(
    identity: {
      githubLogin: z.output<typeof GitHubLoginSchema>;
      githubUserId: z.output<typeof GitHubUserIdSchema>;
    },
    budget: RequestBudget,
  ) {
    const response = await this.#request(
      `/orgs/${this.#org()}/memberships/${encodeURIComponent(identity.githubLogin)}`,
      { method: "GET" },
      budget,
    );
    if (response.status === 404) return null;
    if (!response.ok)
      throw await githubHttpError(response, "observe organization membership");
    const membership = MembershipSchema.parse(await response.json());
    if (
      String(membership.user.id) !== identity.githubUserId ||
      membership.user.login !== identity.githubLogin
    ) {
      throw new GitHubIdentityPinError();
    }
    return membership;
  }

  async #teamMemberships(
    identity: {
      githubLogin: z.output<typeof GitHubLoginSchema>;
      githubUserId: z.output<typeof GitHubUserIdSchema>;
    },
    teams: readonly z.output<typeof TeamSchema>[],
    budget: RequestBudget,
  ) {
    const memberships: TeamMembershipInput[] = [];
    for (const team of teams) {
      // eslint-disable-next-line no-await-in-loop -- Serial reads enforce the global request budget.
      const { membership } = await this.#teamMembershipState(
        team.slug,
        identity,
        budget,
      );
      if (membership === null) continue;
      memberships.push({
        ...identity,
        ...membership,
        teamId: team.id,
        teamSlug: team.slug,
      });
    }
    return memberships;
  }

  async #samlLinked(
    identity: {
      githubLogin: z.output<typeof GitHubLoginSchema>;
      githubUserId: string;
    },
    budget: RequestBudget,
  ): Promise<boolean> {
    let cursor: null | string = null;
    for (let page = 1; page <= this.#maxPages; page++) {
      // eslint-disable-next-line no-await-in-loop -- SAML cursor pagination is ordered and bounded.
      const response = await this.#request(
        "/graphql",
        {
          body: JSON.stringify({
            query: SAML_IDENTITIES_QUERY,
            variables: { cursor, organization: this.#organizationLogin },
          }),
          headers: { "content-type": "application/json" },
          method: "POST",
        },
        budget,
      );
      if (!response.ok) {
        // eslint-disable-next-line no-await-in-loop -- Bound and classify the failed response before terminating pagination.
        const failure = await githubHttpError(
          response,
          "observe saml identity",
        );
        throw failure;
      }
      // eslint-disable-next-line no-await-in-loop -- Page parsing precedes cursor selection.
      const parsed = SamlResponseSchema.parse(await response.json());
      if (parsed.errors?.length)
        throw new Error("github_saml_identity_graphql_error");
      const connection =
        parsed.data.organization.samlIdentityProvider.externalIdentities;
      if (
        connection.nodes.some(
          ({ samlIdentity, user }) =>
            user?.databaseId === Number(identity.githubUserId) &&
            user.login.toLowerCase() === identity.githubLogin.toLowerCase() &&
            samlIdentity?.nameId,
        )
      ) {
        return true;
      }
      if (!connection.pageInfo.hasNextPage) return false;
      if (
        !connection.pageInfo.endCursor ||
        connection.pageInfo.endCursor === cursor
      ) {
        throw new Error("github_saml_identity_invalid_cursor");
      }
      cursor = connection.pageInfo.endCursor;
    }
    throw new GitHubOrganizationBoundExceededError("pages");
  }

  async #teamMembershipState(
    teamSlug: z.output<typeof TeamSlugSchema>,
    identity: {
      githubLogin: z.output<typeof GitHubLoginSchema>;
      githubUserId: z.output<typeof GitHubUserIdSchema>;
    },
    budget: RequestBudget,
  ) {
    const team = await this.#json(
      `/orgs/${this.#org()}/teams/${encodeURIComponent(teamSlug)}`,
      TeamSchema,
      budget,
    );
    if (team.slug !== teamSlug) throw new GitHubOrganizationScopeError();
    const response = await this.#request(
      `/orgs/${this.#org()}/teams/${encodeURIComponent(teamSlug)}/memberships/${encodeURIComponent(identity.githubLogin)}`,
      { method: "GET" },
      budget,
    );
    if (response.status === 404) return { membership: null, team };
    if (!response.ok)
      throw await githubHttpError(response, "observe team membership");
    const membership = TeamMembershipSchema.parse(await response.json());
    if (membership.state === "pending") {
      return { membership: { ...membership, inherited: false }, team };
    }
    const members = await this.#paginate(
      `/orgs/${this.#org()}/teams/${encodeURIComponent(teamSlug)}/members?role=all`,
      TeamMemberSchema,
      budget,
    );
    const listed = members.find(
      (member) => member.id === Number(identity.githubUserId),
    );
    if (listed === undefined) throw new GitHubIdentityPinError();
    return { membership: { ...membership, inherited: listed.inherited }, team };
  }

  async #verifyOperation(
    operation: GitHubProvisioningOperation,
    budget: RequestBudget,
  ): Promise<z.output<typeof GitHubMutationReceiptSchema>> {
    const identity = {
      githubLogin: operation.githubLogin,
      githubUserId: operation.githubUserId,
    };
    await this.#assertPins(identity, budget);
    if (operation.kind === "invite-organization-member") {
      const membership = await this.#membershipState(identity, budget);
      if (membership?.role === "member" && membership.state === "active") {
        return GitHubMutationReceiptSchema.parse({
          access: "active-member",
          kind: operation.kind,
          state: "invited",
        });
      }
      if (membership?.role === "member" && membership.state === "pending") {
        return GitHubMutationReceiptSchema.parse({
          access: "pending-acceptance",
          kind: operation.kind,
          state: "invited",
        });
      }
      throw new GitHubMutationReadbackError(operation.kind);
    }
    if (!(await this.#operationConverged(operation, identity, budget))) {
      throw new GitHubMutationReadbackError(operation.kind);
    }
    return GitHubMutationReceiptSchema.parse({
      kind: operation.kind,
      state: "converged",
    });
  }

  async #operationConverged(
    operation: GitHubProvisioningOperation,
    identity: {
      githubLogin: z.output<typeof GitHubLoginSchema>;
      githubUserId: z.output<typeof GitHubUserIdSchema>;
    },
    budget: RequestBudget,
  ): Promise<boolean> {
    switch (operation.kind) {
      case "invite-organization-member":
        return false;
      case "cancel-invitation": {
        const invitations = await this.#paginate(
          `/orgs/${this.#org()}/invitations`,
          GitHubOrganizationInvitationSchema,
          budget,
        );
        return invitations.every(
          (invitation) => invitation.id !== operation.invitationId,
        );
      }
      case "remove-organization-member":
        return (await this.#membershipState(identity, budget)) === null;
      case "add-team-member": {
        const { membership } = await this.#teamMembershipState(
          operation.teamSlug,
          identity,
          budget,
        );
        return (
          membership?.role === operation.role &&
          membership.state === "active" &&
          !membership.inherited
        );
      }
      case "remove-team-member": {
        const { membership } = await this.#teamMembershipState(
          operation.teamSlug,
          identity,
          budget,
        );
        return membership === null;
      }
    }
  }

  async #json<T>(
    path: string,
    schema: z.ZodType<T>,
    budget: RequestBudget,
  ): Promise<T> {
    const response = await this.#request(path, { method: "GET" }, budget);
    if (!response.ok) throw await githubHttpError(response, `GET ${path}`);
    return schema.parse(await response.json());
  }

  async #paginate<T>(
    basePath: string,
    itemSchema: z.ZodType<T>,
    budget: RequestBudget,
  ): Promise<T[]> {
    const items: T[] = [];
    for (let page = 1; page <= this.#maxPages; page++) {
      const separator = basePath.includes("?") ? "&" : "?";
      // eslint-disable-next-line no-await-in-loop -- Pagination is serialized and globally bounded.
      const response = await this.#request(
        `${basePath}${separator}per_page=${String(PAGE_SIZE)}&page=${String(page)}`,
        { method: "GET" },
        budget,
      );
      if (!response.ok) {
        // eslint-disable-next-line no-await-in-loop -- Error bodies belong to the serialized page request.
        throw await githubHttpError(response, `paginate ${basePath}`);
      }
      // eslint-disable-next-line no-await-in-loop -- Response parsing belongs to the serialized page request.
      const pageItems = z.array(itemSchema).parse(await response.json());
      items.push(...pageItems);
      if (pageItems.length < PAGE_SIZE) return items;
    }
    throw new GitHubOrganizationBoundExceededError("pages");
  }

  async #request(
    path: string,
    init: RequestInit,
    budget: RequestBudget,
  ): Promise<Response> {
    return this.#requestWithCredential(path, init, budget, this.#samlToken);
  }

  async #requestWithCredential(
    path: string,
    init: RequestInit,
    budget: RequestBudget,
    credential: string,
  ): Promise<Response> {
    if (budget.requests >= this.#maxRequests) {
      throw new GitHubOrganizationBoundExceededError("requests");
    }
    budget.requests++;
    let headers: Headers;
    try {
      headers = new Headers({
        accept: "application/vnd.github+json",
        authorization: `Bearer ${credential}`,
        "user-agent": "sarj-workspace-directory",
        "x-github-api-version": GITHUB_API_VERSION,
      });
      for (const [name, value] of new Headers(init.headers))
        headers.set(name, value);
    } catch (cause) {
      throw new GitHubRequestHeadersError({ cause });
    }
    try {
      return await this.#fetchImpl(`${GITHUB_API_BASE}${path}`, {
        ...init,
        headers,
        // Never follow an authenticated redirect. Workers can reject
        // `redirect: "error"` at the transport boundary, while `manual`
        // returns the redirect response for the existing non-2xx checks.
        redirect: "manual",
        signal: AbortSignal.timeout(this.#requestTimeoutMs),
      });
    } catch (error) {
      if (
        error instanceof Error &&
        (error.name === "TimeoutError" || error.name === "AbortError")
      ) {
        throw error;
      }
      throw new GitHubRequestTransportError({ cause: error });
    }
  }

  async #write(
    method: "DELETE" | "PUT",
    path: string,
    expectedStatuses: readonly number[],
    budget: RequestBudget,
    body?: unknown,
  ): Promise<void> {
    const response = await this.#requestWithCredential(
      path,
      {
        method,
        ...(!(body === undefined) && {
          body: JSON.stringify(body),
          headers: { "content-type": "application/json" },
        }),
      },
      budget,
      this.#token,
    );
    if (!expectedStatuses.includes(response.status)) {
      throw await githubHttpError(response, `${method} mutation`);
    }
    await response.body?.cancel();
  }

  #org(): string {
    return encodeURIComponent(this.#organizationLogin);
  }
}

export function githubPrewriteSafetyFlags(
  operation: GitHubProvisioningOperation,
  observed: z.output<typeof GitHubObservedOrganizationAccountSchema>,
  reviewedRetentions: readonly ReviewedGitHubDirectGrantRetention[] = [],
) {
  const reviewed = reviewedRetentions.find(
    (entry) =>
      entry.githubUserId === operation.githubUserId &&
      entry.githubLogin.toLowerCase() === operation.githubLogin.toLowerCase(),
  );
  const retainedForAddition =
    reviewed !== undefined &&
    operation.kind === "add-team-member" &&
    reviewed.allowedTeamSlugs.includes(operation.teamSlug) &&
    observed.membership?.role === "member" &&
    observed.repositoryInventoryComplete &&
    matchesReviewedGitHubDirectGrants(
      reviewed,
      {
        ...observed.identity,
        googleUserId: reviewed.googleUserId,
        primaryEmail: reviewed.primaryEmail,
      },
      observed.directRepositoryGrants,
    );
  return {
    owner: observed.membership?.role === "owner",
    outsideCollaborator: observed.outsideCollaborator,
    directRepositoryGrants:
      (observed.directRepositoryGrants.length > 0 || reviewed !== undefined) &&
      !retainedForAddition,
    privilegedInvitation: observed.pendingInvitations.some(
      ({ role }) => role !== "direct_member",
    ),
    teamMaintainer: observed.teamMemberships.some(
      ({ role }) => role === "maintainer",
    ),
    invitationAlreadyPending:
      operation.kind === "invite-organization-member" &&
      observed.pendingInvitations.length > 0,
    removalRepositoryInventoryIncomplete:
      operation.kind === "remove-organization-member" &&
      !observed.repositoryInventoryComplete,
    teamSamlUnlinked: "teamSlug" in operation && !observed.samlLinked,
    pendingSelectedTeam:
      "teamSlug" in operation &&
      observed.teamMemberships.some(
        ({ state, teamSlug }) =>
          teamSlug === operation.teamSlug && state === "pending",
      ),
    inheritedSelectedTeam:
      "teamSlug" in operation &&
      observed.teamMemberships.some(
        ({ inherited, teamSlug }) =>
          teamSlug === operation.teamSlug && inherited,
      ),
  };
}

export class GitHubOrganizationPinError extends Error {
  constructor() {
    super("github_organization_pin_mismatch");
    this.name = "GitHubOrganizationPinError";
  }
}

export class GitHubCredentialSeparationError extends Error {
  constructor() {
    super("github_saml_reader_and_writer_credentials_must_differ");
    this.name = "GitHubCredentialSeparationError";
  }
}

export class GitHubRequestHeadersError extends Error {
  constructor(options?: ErrorOptions) {
    super("github_request_headers_invalid", options);
    this.name = "GitHubRequestHeadersError";
  }
}

export class GitHubRequestTransportError extends Error {
  constructor(options?: ErrorOptions) {
    super("github_request_transport_failed", options);
    this.name = "GitHubRequestTransportError";
  }
}

export class GitHubWriterTenantResponseError extends Error {
  constructor() {
    super("github_writer_tenant_response_invalid");
    this.name = "GitHubWriterTenantResponseError";
  }
}

export class GitHubIdentityPinError extends Error {
  constructor() {
    super("github_identity_pin_mismatch");
    this.name = "GitHubIdentityPinError";
  }
}

export class GitHubOrganizationScopeError extends Error {
  constructor() {
    super("github_team_outside_managed_scope");
    this.name = "GitHubOrganizationScopeError";
  }
}

export class GitHubOrganizationBoundExceededError extends Error {
  constructor(bound: "pages" | "requests", options?: ErrorOptions) {
    super(`github_organization_${bound}_bound_exceeded`, options);
    this.name = "GitHubOrganizationBoundExceededError";
  }
}

export class GitHubUnresolvedPrivilegedInvitationError extends Error {
  constructor() {
    super("github_unresolved_privileged_invitation");
    this.name = "GitHubUnresolvedPrivilegedInvitationError";
  }
}

export class GitHubMutationReadbackError extends Error {
  constructor(
    kind: GitHubProvisioningOperation["kind"],
    options?: ErrorOptions,
  ) {
    super(`github_${kind}_readback_mismatch`, options);
    this.name = "GitHubMutationReadbackError";
  }
}

export class GitHubPreWriteSafetyError extends Error {
  constructor() {
    super("github_prewrite_privileged_state_blocked");
    this.name = "GitHubPreWriteSafetyError";
  }
}

async function observeStage<T>(
  stage: ObservationStage,
  operation: () => Promise<T>,
): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (
      error instanceof Error &&
      githubProviderObservationStage(error) === undefined
    ) {
      Object.defineProperty(error, "githubObservationStage", { value: stage });
    }
    throw error;
  }
}

export function githubProviderObservationStage(
  error: unknown,
): ObservationStage | undefined {
  if (!(error instanceof Error)) return undefined;
  const stage: unknown = Object.getOwnPropertyDescriptor(
    error,
    "githubObservationStage",
  )?.value;
  return OBSERVATION_STAGES.find((candidate) => candidate === stage);
}

function permissionFor(
  permissions: z.output<typeof CollaboratorSchema>["permissions"],
) {
  if (permissions.admin) return "admin" as const;
  if (permissions.maintain) return "maintain" as const;
  if (permissions.push) return "push" as const;
  if (permissions.triage) return "triage" as const;
  return "pull" as const;
}

async function githubHttpError(
  response: Response,
  context: string,
): Promise<Error> {
  try {
    await response.body?.cancel();
  } catch {
    // Body disposal is best-effort and must never hide the bounded HTTP status evidence.
  }
  return new Error(
    `github_${context.replaceAll(/[^a-z0-9]+/giu, "_")}_http_${String(response.status)}`,
  );
}

const SAML_IDENTITIES_QUERY = `
  query WorkspaceDirectorySamlIdentities($organization: String!, $cursor: String) {
    organization(login: $organization) {
      samlIdentityProvider {
        externalIdentities(first: 100, after: $cursor) {
          nodes {
            samlIdentity { nameId }
            user { id login databaseId }
          }
          pageInfo { endCursor hasNextPage }
        }
      }
    }
  }
`;

const PROOFS = new WeakMap<Error, GithubZeroDispatchProof>();
const TRUSTED = new WeakSet<GithubZeroDispatchProof>();

function githubPrewriteBoundary() {
  let dispatched = false;
  return {
    markDispatched() {
      dispatched = true;
    },
    refuse(
      claim: GithubDispatchClaim,
      operation: GitHubProvisioningOperation,
      category: GithubPrewriteRefusalCategory,
      cause: unknown,
    ): Error {
      if (dispatched) throw new Error("github_zero_dispatch_boundary_invalid");
      const proof = Object.freeze({
        claim: Object.freeze(GithubDispatchClaimSchema.parse(claim)),
        operation: Object.freeze({ ...operation }),
        category,
      });
      const error = new Error("github_prewrite_not_dispatched", { cause });
      PROOFS.set(error, proof);
      TRUSTED.add(proof);
      return error;
    },
  };
}

export function takeGithubZeroDispatchProof(
  error: unknown,
): GithubZeroDispatchProof | undefined {
  if (!(error instanceof Error)) return undefined;
  const proof = PROOFS.get(error);
  PROOFS.delete(error);
  return proof;
}
export function assertTrustedGithubZeroDispatchProof(
  proof: GithubZeroDispatchProof,
): void {
  if (!TRUSTED.has(proof))
    throw new Error("github_zero_dispatch_proof_untrusted");
}

export interface GithubZeroDispatchProof {
  readonly category: GithubPrewriteRefusalCategory;
  readonly claim: GithubDispatchClaim;
  readonly operation: GitHubProvisioningOperation;
}
