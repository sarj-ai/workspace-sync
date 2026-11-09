import { z } from "zod";

export const GitHubOrganizationActorSchema = z.object({
  id: z.number().int().positive(),
  login: z.string().min(1),
  type: z.enum(["Bot", "User"]).optional().default("User"),
});

export const GitHubOrganizationInvitationSchema = z.object({
  email: z.email().nullish(),
  id: z.number().int().positive(),
  login: z.string().min(1).nullish(),
  invitee: GitHubOrganizationActorSchema.nullish(),
  role: z.enum(["admin", "billing_manager", "direct_member"]),
});

export interface GitHubOrganizationMembershipSnapshot {
  invitations: z.output<typeof GitHubOrganizationInvitationSchema>[];
  members: (z.output<typeof GitHubOrganizationActorSchema> & {
    role: "admin" | "member";
  })[];
  outsideCollaborators: z.output<typeof GitHubOrganizationActorSchema>[];
}

export type GitHubPageReader = <T>(
  path: string,
  itemSchema: z.ZodType<T>,
) => Promise<T[]>;

export interface GitHubOrganizationMembershipReaderContract {
  capture(): Promise<GitHubOrganizationMembershipSnapshot>;
  listInvitations(): Promise<
    GitHubOrganizationMembershipSnapshot["invitations"]
  >;
  listMembers(): Promise<GitHubOrganizationMembershipSnapshot["members"]>;
  listOutsideCollaborators(): Promise<
    GitHubOrganizationMembershipSnapshot["outsideCollaborators"]
  >;
}

/** First-party organization access inventory shared by audit and reconciliation flows. */
export class GitHubOrganizationMembershipReader implements GitHubOrganizationMembershipReaderContract {
  readonly #organization: string;
  readonly #paginate: GitHubPageReader;
  readonly #readActor:
    | ((
        login: string,
      ) => Promise<z.output<typeof GitHubOrganizationActorSchema>>)
    | undefined;

  constructor(
    organization: string,
    paginate: GitHubPageReader,
    readActor?: (
      login: string,
    ) => Promise<z.output<typeof GitHubOrganizationActorSchema>>,
  ) {
    this.#organization = encodeURIComponent(organization);
    this.#paginate = paginate;
    this.#readActor = readActor;
  }

  async capture(): Promise<GitHubOrganizationMembershipSnapshot> {
    const [members, outsideCollaborators, invitations] = await Promise.all([
      this.listMembers(),
      this.listOutsideCollaborators(),
      this.listInvitations(),
    ]);
    return { invitations, members, outsideCollaborators };
  }

  async listInvitations(): Promise<
    GitHubOrganizationMembershipSnapshot["invitations"]
  > {
    const invitations = await this.#paginate(
      `/orgs/${this.#organization}/invitations`,
      GitHubOrganizationInvitationSchema,
    );
    return resolveGitHubInvitationActors(invitations, this.#readActor);
  }

  async listMembers(): Promise<
    GitHubOrganizationMembershipSnapshot["members"]
  > {
    const [admins, ordinary] = await Promise.all([
      this.#paginate(
        `/orgs/${this.#organization}/members?role=admin`,
        GitHubOrganizationActorSchema,
      ),
      this.#paginate(
        `/orgs/${this.#organization}/members?role=member`,
        GitHubOrganizationActorSchema,
      ),
    ]);
    return [
      ...admins.map((member) => ({ ...member, role: "admin" as const })),
      ...ordinary.map((member) => ({ ...member, role: "member" as const })),
    ].toSorted((left, right) => left.login.localeCompare(right.login));
  }

  async listOutsideCollaborators(): Promise<
    GitHubOrganizationMembershipSnapshot["outsideCollaborators"]
  > {
    return this.#paginate(
      `/orgs/${this.#organization}/outside_collaborators`,
      GitHubOrganizationActorSchema,
    );
  }
}

export async function resolveGitHubInvitationActors(
  invitations: GitHubOrganizationMembershipSnapshot["invitations"],
  readActor?: (
    login: string,
  ) => Promise<z.output<typeof GitHubOrganizationActorSchema>>,
): Promise<GitHubOrganizationMembershipSnapshot["invitations"]> {
  if (!readActor) return invitations;
  const actors = new Map<
    string,
    z.output<typeof GitHubOrganizationActorSchema>
  >();
  const result: GitHubOrganizationMembershipSnapshot["invitations"] = [];
  for (const invitation of invitations) {
    if (!invitation.login) {
      result.push(invitation);
      continue;
    }
    const login = invitation.login.toLowerCase();
    let actor = actors.get(login);
    if (!actor) {
      if (actors.size >= 100)
        throw new Error("github_invitation_identity_read_limit");
      // eslint-disable-next-line no-await-in-loop -- Serial hydration shares the bounded caller request budget.
      actor = GitHubOrganizationActorSchema.parse(await readActor(login));
      if (actor.login.toLowerCase() !== login)
        throw new Error("github_invitation_identity_conflict");
      actors.set(login, actor);
    }
    if (invitation.invitee && !sameInvitationActor(invitation.invitee, actor)) {
      throw new Error("github_invitation_identity_conflict");
    }
    result.push({ ...invitation, invitee: actor });
  }
  return result;
}

export function correlateGitHubInvitation(
  invitation: {
    readonly email?: null | string | undefined;
    readonly login?: null | string | undefined;
    readonly invitee?:
      | { readonly id: number | string; readonly login: string }
      | null
      | undefined;
  },
  identity: {
    readonly githubUserId: string;
    readonly githubLogin: string;
    readonly primaryEmail?: string | undefined;
  },
): "match" | "unrelated" | "unresolved" {
  const emailMatches = sameInvitationEmail(
    invitation.email,
    identity.primaryEmail,
  );
  if (invitation.invitee) {
    const idMatches = String(invitation.invitee.id) === identity.githubUserId;
    const loginMatches =
      invitation.invitee.login.toLowerCase() ===
      identity.githubLogin.toLowerCase();
    if (
      invitation.login &&
      invitation.login.toLowerCase() !== invitation.invitee.login.toLowerCase()
    )
      return "unresolved";
    if (idMatches !== loginMatches || (emailMatches && !idMatches))
      return "unresolved";
    return idMatches ? "match" : "unrelated";
  }
  if (invitation.login) return "unresolved";
  if (invitation.email && identity.primaryEmail)
    return emailMatches ? "match" : "unrelated";
  return "unresolved";
}

function sameInvitationActor(
  left: { id: number; login: string },
  right: { id: number; login: string },
): boolean {
  return (
    left.id === right.id &&
    left.login.toLowerCase() === right.login.toLowerCase()
  );
}

export function unresolvedGitHubInvitations(
  invitations: readonly GitHubOrganizationMembershipSnapshot["invitations"][number][],
  identity: {
    readonly githubUserId: string;
    readonly githubLogin: string;
    readonly primaryEmail?: string | undefined;
  },
): { unresolvedInvitations?: "identity-or-privilege" | "opaque-direct" } {
  const unresolved = invitations.filter(
    (invitation) =>
      correlateGitHubInvitation(invitation, identity) === "unresolved",
  );
  if (unresolved.length === 0) return {};
  return {
    unresolvedInvitations: unresolved.some(
      (invitation) =>
        Boolean(invitation.invitee) ||
        Boolean(invitation.login) ||
        invitation.role !== "direct_member",
    )
      ? "identity-or-privilege"
      : "opaque-direct",
  };
}

function sameInvitationEmail(
  left: null | string | undefined,
  right: string | undefined,
): boolean {
  if (!left || !right) return false;
  return left.toLowerCase() === right.toLowerCase();
}
