import { z } from "zod";

import {
  GitHubLoginSchema,
  GitHubUserIdSchema,
} from "../catalog/identity-authority.ts";
import type { GitHubAccessSnapshot } from "../github-access-audit/git-hub-access-audit-client.ts";
import {
  correlateGitHubInvitation,
  unresolvedGitHubInvitations,
} from "../github/organization-membership-reader.ts";
import {
  GitHubObservedOrganizationAccountSchema,
  type ReadOnlyGitHubOrganizationPort,
} from "./github-organization-connector.ts";

const ConfigSchema = z.strictObject({
  managedTeamPins: z
    // eslint-disable-next-line zod/no-transform-in-record-key -- Team-pin configuration currently normalizes surrounding key whitespace before snapshot matching.
    .record(z.string().trim().min(1), z.number().int().positive())
    .optional()
    .default({}),
  managedTeamSlugs: z.array(z.string().trim().min(1)),
  organizationId: z.string().regex(/^[1-9]\d*$/u),
  organizationLogin: z
    .string()
    .trim()
    .min(1)
    .transform((value) => value.toLowerCase()),
});
const PrimaryEmailSchema = z.email();

/** Adapts one complete organization inventory to O(1) per-account planning reads. */
export class GitHubOrganizationSnapshotPort implements ReadOnlyGitHubOrganizationPort {
  readonly capability = "read-only";
  readonly #snapshot: GitHubAccessSnapshot;

  constructor(
    snapshot: GitHubAccessSnapshot,
    rawConfig: {
      readonly managedTeamPins?: Readonly<Record<string, number>>;
      readonly managedTeamSlugs: readonly string[];
      readonly organizationId: string;
      readonly organizationLogin: string;
    },
  ) {
    const config = ConfigSchema.parse(rawConfig);
    const coreErrors = snapshot.errors.filter(
      ({ capability }) => capability !== "scim_identities",
    );
    if (coreErrors.length > 0 || snapshot.organization === null) {
      throw new Error("github_organization_snapshot_incomplete");
    }
    if (
      snapshot.organization.login.toLowerCase() !== config.organizationLogin
    ) {
      throw new Error("github_organization_snapshot_login_mismatch");
    }
    if (String(snapshot.organization.id) !== config.organizationId) {
      throw new Error("github_organization_snapshot_id_mismatch");
    }
    const observedTeamSlugs = new Set(snapshot.teams.map(({ slug }) => slug));
    if (config.managedTeamSlugs.some((slug) => !observedTeamSlugs.has(slug))) {
      throw new Error("github_managed_team_missing");
    }
    if (
      Object.entries(config.managedTeamPins).some(
        ([slug, id]) =>
          !snapshot.teams.some((team) => team.slug === slug && team.id === id),
      )
    ) {
      throw new Error("github_managed_team_pin_mismatch");
    }
    this.#snapshot = snapshot;
  }

  observeAccount(rawIdentity: {
    readonly githubLogin: z.output<typeof GitHubLoginSchema>;
    readonly githubUserId: z.output<typeof GitHubUserIdSchema>;
    readonly primaryEmail: string;
  }) {
    const identity = {
      githubLogin: GitHubLoginSchema.parse(rawIdentity.githubLogin),
      githubUserId: GitHubUserIdSchema.parse(rawIdentity.githubUserId),
      primaryEmail: PrimaryEmailSchema.parse(
        rawIdentity.primaryEmail,
      ).toLowerCase(),
    };
    const actor = this.#actor(identity);
    const samlLinked = this.#snapshot.samlExternalIdentities.some(
      (externalIdentity) =>
        String(externalIdentity.databaseId) === identity.githubUserId &&
        externalIdentity.login?.toLowerCase() ===
          identity.githubLogin.toLowerCase() &&
        externalIdentity.nameId !== null,
    );
    const expectedRepositoryCount =
      this.#snapshot.organization?.["public_repos"] === undefined ||
      this.#snapshot.organization["owned_private_repos"] === undefined
        ? null
        : this.#snapshot.organization["public_repos"] +
          this.#snapshot.organization["owned_private_repos"];
    const repositoryInventoryComplete =
      expectedRepositoryCount !== null &&
      new Set(this.#snapshot.repositories.map(({ id }) => id)).size ===
        expectedRepositoryCount;
    const observedIdentity =
      actor === undefined
        ? {
            githubLogin: identity.githubLogin,
            githubUserId: identity.githubUserId,
          }
        : {
            githubLogin: GitHubLoginSchema.parse(actor.login),
            githubUserId: String(actor.id),
          };
    const membership = this.#snapshot.members.find(
      (member) => member.id === actor?.id,
    );
    const pendingInvitations = this.#snapshot.invitations.filter(
      (invitation) =>
        correlateGitHubInvitation(invitation, identity) === "match",
    );
    return Promise.resolve(
      GitHubObservedOrganizationAccountSchema.parse({
        complete: true,
        directRepositoryGrants: this.#snapshot.repositories.flatMap(
          (repository) => {
            const collaborator = repository.directCollaborators.find(
              (candidate) => candidate.id === actor?.id,
            );
            if (collaborator === undefined) return [];
            return {
              ...observedIdentity,
              ...(collaborator.customRoleName !== undefined && {
                customRoleName: collaborator.customRoleName,
              }),
              ...(collaborator.unresolvedDirectRole === true && {
                unresolvedDirectRole: true as const,
              }),
              permission: permissionFor(collaborator.permissions),
              repositoryId: repository.id,
              repositoryName: repository["full_name"],
            };
          },
        ),
        identity: observedIdentity,
        membership:
          membership === undefined
            ? null
            : {
                ...observedIdentity,
                role: membership.role === "admin" ? "owner" : "member",
              },
        observedAt: this.#snapshot.capturedAt,
        outsideCollaborator: this.#snapshot.outsideCollaborators.some(
          (candidate) => candidate.id === actor?.id,
        ),
        pendingInvitations: pendingInvitations.map((invitation) => ({
          ...observedIdentity,
          invitationId: invitation.id,
          role: invitation.role,
        })),
        ...unresolvedGitHubInvitations(this.#snapshot.invitations, identity),
        repositoryInventoryComplete,
        samlLinked,
        teamMemberships: this.#snapshot.teams.flatMap((team) => {
          const isMaintainer = team.maintainers.some(
            (candidate) => candidate.id === actor?.id,
          );
          const isMember = team.directMembers.some(
            (candidate) => candidate.id === actor?.id,
          );
          return isMaintainer || isMember
            ? {
                ...observedIdentity,
                inherited:
                  (isMaintainer
                    ? team.maintainers.find(
                        (candidate) => candidate.id === actor?.id,
                      )?.inherited
                    : team.directMembers.find(
                        (candidate) => candidate.id === actor?.id,
                      )?.inherited) ?? false,
                role: isMaintainer
                  ? ("maintainer" as const)
                  : ("member" as const),
                state: "active" as const,
                teamId: team.id,
                teamSlug: team.slug,
              }
            : [];
        }),
      }),
    );
  }

  #actor(identity: { githubLogin: string; githubUserId: string }) {
    const actors = [
      ...this.#snapshot.members,
      ...this.#snapshot.outsideCollaborators,
      ...this.#snapshot.invitations.flatMap(({ invitee }) =>
        invitee === null || invitee === undefined ? [] : [invitee],
      ),
    ];
    const matches = actors.filter(
      (actor) =>
        String(actor.id) === identity.githubUserId ||
        actor.login.toLowerCase() === identity.githubLogin.toLowerCase(),
    );
    const distinctMatches = new Map(
      matches.map((actor) => [`${String(actor.id)}:${actor.login}`, actor]),
    );
    if (distinctMatches.size > 1) {
      throw new Error("github_organization_snapshot_actor_ambiguous");
    }
    return distinctMatches.values().next().value;
  }
}

function permissionFor(
  permissions: GitHubAccessSnapshot["repositories"][number]["directCollaborators"][number]["permissions"],
) {
  if (permissions?.admin) return "admin" as const;
  if (permissions?.maintain) return "maintain" as const;
  if (permissions?.push) return "push" as const;
  if (permissions?.triage) return "triage" as const;
  return "pull" as const;
}
