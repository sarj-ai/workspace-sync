import { z } from "zod";

import {
  GitHubLoginSchema,
  GitHubUserIdSchema,
} from "../catalog/identity-authority.ts";
import type { GitHubDeprovisionAuthority } from "../github-access-audit/github-deprovision-authority-contract.ts";
import {
  correlateGitHubInvitation,
  unresolvedGitHubInvitations,
} from "../github/organization-membership-reader.ts";
import {
  GitHubObservedOrganizationAccountSchema,
  type ReadOnlyGitHubOrganizationPort,
} from "./github-organization-connector.ts";

const ConfigSchema = z.strictObject({
  organizationId: z.string().regex(/^[1-9]\d*$/u),
  organizationLogin: z
    .string()
    .trim()
    .min(1)
    .transform((value) => value.toLowerCase()),
});
const PrimaryEmailSchema = z.email();

/** Adapts the minimal, complete deprovision inventory to one fail-closed account observation. */
export class GitHubDeprovisionAuthorityPort implements ReadOnlyGitHubOrganizationPort {
  readonly capability = "read-only";
  readonly #snapshot: GitHubDeprovisionAuthority;

  constructor(
    snapshot: GitHubDeprovisionAuthority,
    rawConfig: {
      readonly organizationId: string;
      readonly organizationLogin: string;
    },
  ) {
    const config = ConfigSchema.parse(rawConfig);
    if (snapshot.errors.length > 0 || snapshot.organization === null) {
      throw new Error("github_deprovision_authority_incomplete");
    }
    if (
      snapshot.organization.login.toLowerCase() !== config.organizationLogin
    ) {
      throw new Error("github_deprovision_authority_login_mismatch");
    }
    if (String(snapshot.organization.id) !== config.organizationId) {
      throw new Error("github_deprovision_authority_id_mismatch");
    }
    if (
      snapshot.invitations.some(
        (invitation) => !invitation.invitee && !invitation.email,
      )
    ) {
      throw new Error("github_deprovision_authority_unresolved_invitation");
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
    const expectedRepositoryCount =
      this.#snapshot.organization?.["owned_private_repos"] === undefined ||
      this.#snapshot.organization["public_repos"] === undefined
        ? null
        : this.#snapshot.organization["owned_private_repos"] +
          this.#snapshot.organization["public_repos"];
    const observedRepositoryCount = new Set(
      this.#snapshot.repositories.map((repository) => repository.id),
    ).size;
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
        pendingInvitations: this.#snapshot.invitations
          .filter(
            (invitation) =>
              correlateGitHubInvitation(invitation, identity) === "match",
          )
          .map((invitation) => ({
            ...observedIdentity,
            invitationId: invitation.id,
            role: invitation.role,
          })),
        ...unresolvedGitHubInvitations(this.#snapshot.invitations, identity),
        repositoryInventoryComplete:
          expectedRepositoryCount !== null &&
          observedRepositoryCount === expectedRepositoryCount,
        // This minimal deprovision snapshot intentionally does not capture SAML identities. An
        // absent desired state never relies on SAML evidence, so preserve the unknown state as
        // false instead of inventing a link.
        samlLinked: false,
        teamMemberships: this.#snapshot.teams.flatMap((team) => {
          const maintainer = team.maintainers.find(
            (candidate) => candidate.id === actor?.id,
          );
          const member = team.directMembers.find(
            (candidate) => candidate.id === actor?.id,
          );
          const teamActor = maintainer ?? member;
          if (teamActor === undefined) return [];
          return {
            ...observedIdentity,
            inherited: teamActor.inherited ?? false,
            role:
              maintainer === undefined
                ? ("member" as const)
                : ("maintainer" as const),
            state: "active" as const,
            teamId: team.id,
            teamSlug: team.slug,
          };
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
      ...this.#snapshot.repositories.flatMap(
        ({ directCollaborators }) => directCollaborators,
      ),
    ];
    const matches = actors.filter(
      (actor) =>
        String(actor.id) === identity.githubUserId ||
        actor.login.toLowerCase() === identity.githubLogin.toLowerCase(),
    );
    const distinctMatches = new Map(
      matches.map((actor) => [
        `${String(actor.id)}:${actor.login.toLowerCase()}`,
        actor,
      ]),
    );
    if (distinctMatches.size > 1) {
      throw new Error("github_deprovision_authority_actor_ambiguous");
    }
    return distinctMatches.values().next().value;
  }
}

function permissionFor(
  permissions: GitHubDeprovisionAuthority["repositories"][number]["directCollaborators"][number]["permissions"],
) {
  if (permissions?.admin) return "admin" as const;
  if (permissions?.maintain) return "maintain" as const;
  if (permissions?.push) return "push" as const;
  if (permissions?.triage) return "triage" as const;
  return "pull" as const;
}
