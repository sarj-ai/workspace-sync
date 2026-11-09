import {
  bootstrapEmployeeEntitlementAuthority,
  buildEmployeeEntitlementAuthority,
  contractorAuthorityGroup,
  isEmployeeEntitlementExcluded,
} from "../identity-provisioning/employee-entitlement-policy.ts";
import { normalizeIdentityEmail as normalize } from "../identity-sync/normalize-identity-email.ts";
import { plannedChange as change, exceptionChange } from "./access-change.ts";
import { compareSamlScim } from "./compare-saml-scim.ts";
import { contentHash } from "./content-hash.ts";
import { correlateIdentities } from "./correlate-identities.ts";
import type { GitHubAccessSnapshot } from "./git-hub-access-audit-client.ts";
import type { GoogleAuthoritySnapshot } from "./google-contracts.ts";
import {
  expandGroupUsers,
  indexGoogleUsers,
  indexMemberships,
} from "./google-graph.ts";
import type { GithubAccessAuditReport, ProposedAccessChange } from "./model.ts";
import { classifyRemovalGrace } from "./removal-grace.ts";
import {
  computeRepositoryAccess,
  permissionFromFlags,
} from "./repository-access.ts";
import {
  matchesReviewedGitHubDirectGrants,
  type ReviewedGitHubDirectGrantRetention,
} from "./reviewed-direct-grants.ts";
import {
  isReviewedGitHubTeamMembership,
  type ReviewedGitHubTeamMembership,
} from "./reviewed-team-memberships.ts";

export interface GithubAccessAuditPolicy {
  activeOutsideRootRemovals: "blocked" | "reviewed";
  excludedGroupEmails: readonly string[];
  membershipGraceMs: number;
  organization: string;
  policyVersion: string;
  reportsIngestionMarginMs: number;
  reviewedDirectGrantRetentions?: readonly ReviewedGitHubDirectGrantRetention[];
  reviewedTeamMemberships?: readonly ReviewedGitHubTeamMembership[];
  rootGroupEmail: string;
  teamMappings: Readonly<Record<string, string>>;
  teamPins: Readonly<Record<string, number>>;
  unmanagedGithubTeams: readonly string[];
}

export interface GithubAccessAuditSources {
  github: { capture(deadlineAt?: number): Promise<GitHubAccessSnapshot> };
  google: {
    capture(
      request: {
        mappedGroupEmails: readonly string[];
        reportsLookbackDays?: number;
        rootGroupEmail: string;
      },
      runId: string,
      deadlineAt?: number,
    ): Promise<GoogleAuthoritySnapshot>;
  };
}

export interface IGithubAccessAuditService {
  run(runId?: string): Promise<GithubAccessAuditReport>;
}

export class GithubAccessAuditService implements IGithubAccessAuditService {
  readonly #policy: GithubAccessAuditPolicy & {
    deadlineMs: number;
    reportsLookbackDays: number;
  };
  readonly #sources: GithubAccessAuditSources;

  constructor(
    sources: GithubAccessAuditSources,
    policy: GithubAccessAuditPolicy & {
      deadlineMs: number;
      reportsLookbackDays: number;
    },
  ) {
    this.#sources = sources;
    this.#policy = policy;
  }

  async run(
    runId: string = crypto.randomUUID(),
  ): Promise<GithubAccessAuditReport> {
    const deadlineAt = Date.now() + this.#policy.deadlineMs;
    const [google, github] = await Promise.all([
      this.#sources.google.capture(
        {
          // The contractor authority is independent of the engineering group
          // graph and must always be captured for employee-only eligibility.
          mappedGroupEmails: [
            ...Object.keys(this.#policy.teamMappings),
            ...this.#policy.excludedGroupEmails,
            contractorAuthorityGroup().email,
          ],
          reportsLookbackDays: this.#policy.reportsLookbackDays,
          rootGroupEmail: this.#policy.rootGroupEmail,
        },
        runId,
        deadlineAt,
      ),
      this.#sources.github.capture(deadlineAt),
    ]);
    return buildGithubAccessAuditReport(
      google,
      github,
      this.#policy,
      new Date(),
      runId,
    );
  }
}

export async function buildGithubAccessAuditReport(
  google: GoogleAuthoritySnapshot,
  github: GitHubAccessSnapshot,
  policy: GithubAccessAuditPolicy,
  now = new Date(),
  runId: string = crypto.randomUUID(),
): Promise<GithubAccessAuditReport> {
  const generatedAt = now.toISOString();
  const samlCapabilityFailed = github.errors.some(
    (error) => error.capability === "saml_external_identities",
  );
  const samlIdentityCorrelationAvailable =
    !samlCapabilityFailed && github.samlExternalIdentities.length > 0;
  const coreGithubErrors = github.errors.filter(
    (error) => error.capability !== "scim_identities",
  );
  let complete = google.complete && coreGithubErrors.length === 0;
  const warnings = github.errors
    .filter((error) => error.capability === "scim_identities")
    .map((error) => `GitHub ${error.capability}: ${error.message}`);
  if (google.reports.status !== "available") {
    warnings.push(
      "Google Admin Reports membership-event history is unavailable or partial; ordinary removal age remains unknown.",
    );
  }
  warnings.push(
    "Reinstating a former GitHub member can restore historical teams, repository grants, role, and forks; default V2 rehires to fresh least privilege.",
    "A verified private Sarj email is useful for invitations and SCIM correlation but is not required as the public or primary GitHub email for SAML.",
  );
  const mappedTeamSlugs = new Set(Object.values(policy.teamMappings));
  const unexpectedTeams = github.teams
    .map((team) => team.slug)
    .filter(
      (slug) =>
        !mappedTeamSlugs.has(slug) &&
        !policy.unmanagedGithubTeams.includes(slug),
    );
  if (unexpectedTeams.length > 0) {
    warnings.push(
      `Unclassified GitHub teams: ${unexpectedTeams.toSorted(compareString).join(", ")}`,
    );
  }
  const errors = [
    ...google.issues.map((issue) => `Google ${issue.code}: ${issue.message}`),
    ...coreGithubErrors.map(
      (error) => `GitHub ${error.capability}: ${error.message}`,
    ),
  ];
  if (
    !samlCapabilityFailed &&
    github.members.length > 0 &&
    github.samlExternalIdentities.length === 0
  ) {
    complete = false;
    errors.push(
      "GitHub saml_external_identities: inventory is empty while organization members exist",
    );
  }

  const usersByEmail = indexGoogleUsers(google.users);
  const groupByEmail = new Map(
    google.groups.map((group) => [normalize(group.email), group]),
  );
  const root = groupByEmail.get(normalize(policy.rootGroupEmail));
  if (!root)
    errors.push(`Google root group ${policy.rootGroupEmail} was not resolved`);
  const membersByGroup = indexMemberships(google.memberships);
  const employeeEntitlementAuthority = await resolveContractorAuthority();
  const rootUsers = root
    ? expandGroupUsers(root.id, membersByGroup, new Set())
    : new Set<string>();
  const activeEmails = new Set<string>();
  for (const [email, user] of usersByEmail) {
    if (!user.suspended && !user.archived && !user.deleted)
      activeEmails.add(email);
  }
  const excludedEmails = new Set<string>();
  const githubExcludedGoogleGroups: {
    groupEmail: string;
    members: string[];
  }[] = [];
  collectExcludedGroups();
  const activeRootUsers = new Set(
    [...rootUsers.intersection(activeEmails)].filter((email) => {
      const user = usersByEmail.get(email);
      return (
        !excludedEmails.has(email) &&
        !isEmployeeEntitlementExcluded(
          email,
          user?.id,
          employeeEntitlementAuthority,
        )
      );
    }),
  );
  const desiredEmailsByTeam = new Map<string, Set<string>>();
  const detachedMappings: string[] = [];
  collectDesiredTeamMembers();
  const identity = correlateIdentities(github, usersByEmail);
  const changes: ProposedAccessChange[] = detachedMappings.map((groupEmail) =>
    change(
      "policy_exception",
      groupEmail,
      undefined,
      policy.teamMappings[groupEmail] ?? policy.organization,
      "blocked",
      [policy.rootGroupEmail, groupEmail],
      "Mapped Google team group is detached from the authoritative engineering root",
      false,
    ),
  );
  proposeOrgAdditions();
  proposeOrgRemovals();
  proposeTeamMembershipChanges();
  const elevated =
    desiredEmailsByTeam.get("voice-elevated-permissions") ?? new Set<string>();
  const platform = desiredEmailsByTeam.get("eng-platform") ?? new Set<string>();
  flagElevatedMembership();
  addManualReviewExceptions();
  annotateRemovalGrace();
  async function resolveContractorAuthority(): Promise<
    ReturnType<typeof bootstrapEmployeeEntitlementAuthority>
  > {
    let authority = bootstrapEmployeeEntitlementAuthority();
    const contractorGroup = google.groups.find(
      (group) => group.id === contractorAuthorityGroup().id,
    );
    try {
      if (contractorGroup === undefined)
        throw new Error("contractor_authority_group_missing");
      authority = await buildEmployeeEntitlementAuthority({
        ...contractorGroup,
        members: (membersByGroup.get(contractorGroup.id) ?? []).map(
          (member) => ({
            email: member.memberEmail,
            id: member.memberId,
            ...(!(member.role === undefined) && { role: member.role }),
            ...(!(member.status === undefined) && { status: member.status }),
            type: member.memberType,
          }),
        ),
      });
    } catch (error) {
      complete = false;
      errors.push(
        `Google contractor authority: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    return authority;
  }

  function collectExcludedGroups(): void {
    for (const groupEmail of policy.excludedGroupEmails) {
      const group = groupByEmail.get(normalize(groupEmail));
      if (!group) {
        errors.push(
          `GitHub-excluded Google group ${groupEmail} was not resolved`,
        );
        continue;
      }
      githubExcludedGoogleGroups.push({
        groupEmail: normalize(groupEmail),
        members: collectExcludedMembers(group),
      });
    }
  }

  function collectExcludedMembers(
    group: GoogleAuthoritySnapshot["groups"][number],
  ): string[] {
    const groupMembers = new Set<string>();
    for (const email of expandGroupUsers(group.id, membersByGroup, new Set())) {
      const user = usersByEmail.get(email);
      groupMembers.add(normalize(user?.primaryEmail ?? email));
      for (const candidate of [
        email,
        user?.primaryEmail,
        ...(user?.aliases ?? []),
      ]) {
        if (candidate !== undefined) excludedEmails.add(normalize(candidate));
      }
    }
    return [...groupMembers].toSorted(compareString);
  }

  function collectDesiredTeamMembers(): void {
    for (const [groupEmail, teamSlug] of Object.entries(policy.teamMappings)) {
      const group = groupByEmail.get(normalize(groupEmail));
      const reachable =
        group !== undefined && google.reachableGroupIds.includes(group.id);
      if (group && !reachable) {
        errors.push(
          `Mapped Google group ${groupEmail} is not a descendant of ${policy.rootGroupEmail}`,
        );
        detachedMappings.push(groupEmail);
      }
      const mappedUsers =
        group && reachable
          ? expandGroupUsers(group.id, membersByGroup, new Set())
          : new Set<string>();
      const activeMappedUsers = mappedUsers.intersection(activeRootUsers);
      desiredEmailsByTeam.set(teamSlug, activeMappedUsers);
      if (!group)
        errors.push(`Mapped Google group ${groupEmail} was not resolved`);
    }
  }

  function proposeOrgAdditions(): void {
    for (const email of samlIdentityCorrelationAvailable
      ? activeRootUsers
      : []) {
      const user = usersByEmail.get(email);
      const login = identity.loginByEmail.get(email);
      if (user?.suspended || user?.archived || user?.deleted) continue;
      if (!login || !github.members.some((member) => member.login === login)) {
        changes.push(
          change(
            "org_add",
            email,
            login,
            policy.organization,
            "member",
            [policy.rootGroupEmail],
            "Eligible Google root-group member is not an active GitHub organization member",
            complete && Boolean(login),
            user,
          ),
        );
      }
    }
  }

  function proposeOrgRemovals(): void {
    for (const member of samlIdentityCorrelationAvailable
      ? github.members
      : []) {
      proposeOrgRemovalForMember(member);
    }
  }

  function proposeOrgRemovalForMember(
    member: GitHubAccessSnapshot["members"][number],
  ): void {
    const email = identity.emailByLogin.get(member.login);
    const user = email ? usersByEmail.get(email) : undefined;
    if (
      !email ||
      excludedEmails.has(email) ||
      addContractorException(member, email, user)
    )
      return;
    const inactive =
      user === undefined
        ? undefined
        : user.suspended || user.archived || user.deleted;
    if (addOutsideRootException(member, email, user, inactive)) return;
    if (shouldRemoveFromOrganization(email, inactive)) {
      changes.push(
        change(
          "org_remove",
          email,
          member.login,
          policy.organization,
          "none",
          [policy.rootGroupEmail],
          inactive
            ? "Google account is suspended, archived, or deleted"
            : "GitHub member is outside the authoritative Google root group",
          complete,
          user,
          member.id,
        ),
      );
    }
  }

  function shouldRemoveFromOrganization(
    email: string,
    inactive: boolean | undefined,
  ): boolean {
    return !rootUsers.has(email) || Boolean(inactive);
  }

  function addContractorException(
    member: GitHubAccessSnapshot["members"][number],
    email: string,
    user: GoogleAuthoritySnapshot["users"][number] | undefined,
  ): boolean {
    if (
      !isEmployeeEntitlementExcluded(
        email,
        user?.id,
        employeeEntitlementAuthority,
      )
    )
      return false;
    changes.push(
      change(
        "policy_exception",
        email,
        member.login,
        policy.organization,
        "blocked",
        [contractorAuthorityGroup().email],
        "Contractor GitHub access is preserved pending explicit review; automation will not add or remove it",
        false,
        user,
        member.id,
      ),
    );
    return true;
  }

  function addOutsideRootException(
    member: GitHubAccessSnapshot["members"][number],
    email: string,
    user: GoogleAuthoritySnapshot["users"][number] | undefined,
    inactive: boolean | undefined,
  ): boolean {
    if (
      rootUsers.has(email) ||
      inactive ||
      policy.activeOutsideRootRemovals !== "blocked"
    )
      return false;
    changes.push(
      change(
        "policy_exception",
        email,
        member.login,
        policy.organization,
        "blocked",
        [policy.rootGroupEmail],
        "Active GitHub member is outside the provisional Google root; removal is blocked until an explicit access-github-org authority exists",
        false,
        user,
        member.id,
      ),
    );
    return true;
  }

  function proposeTeamMembershipChanges(): void {
    for (const [teamSlug, desiredEmails] of desiredEmailsByTeam) {
      const team = github.teams.find(
        (candidate) => candidate.slug === teamSlug,
      );
      if (!team) {
        errors.push(`Mapped GitHub team ${teamSlug} was not resolved`);
        continue;
      }
      if (
        policy.teamPins[teamSlug] === undefined ||
        team.id !== policy.teamPins[teamSlug]
      ) {
        errors.push(
          `Mapped GitHub team ${teamSlug} immutable ID did not match`,
        );
        continue;
      }
      if (!samlIdentityCorrelationAvailable) continue;
      const current = new Set(
        [...team.directMembers, ...team.maintainers].map((item) => item.login),
      );
      const desiredLogins = new Map<string, string>();
      proposeTeamAdditions(teamSlug, desiredEmails, current, desiredLogins);
      proposeTeamRemovals(team, current, desiredLogins);
    }
  }

  function proposeTeamAdditions(
    teamSlug: string,
    desiredEmails: Set<string>,
    current: Set<string>,
    desiredLogins: Map<string, string>,
  ): void {
    for (const email of desiredEmails) {
      const login = identity.loginByEmail.get(email);
      if (login) desiredLogins.set(login, email);
      if (!login || !current.has(login)) {
        changes.push(
          change(
            "team_add",
            email,
            login,
            teamSlug,
            "member",
            [policy.rootGroupEmail, emailForTeam(policy, teamSlug)],
            "Authoritative Google group membership differs from the GitHub team",
            complete && Boolean(login),
            usersByEmail.get(email),
          ),
        );
      }
    }
  }

  function proposeTeamRemovals(
    team: GitHubAccessSnapshot["teams"][number],
    current: Set<string>,
    desiredLogins: Map<string, string>,
  ): void {
    const teamSlug = team.slug;
    for (const login of current) {
      const email = identity.emailByLogin.get(login);
      if (
        email === undefined ||
        desiredLogins.has(login) ||
        excludedEmails.has(email)
      )
        continue;
      if (retainsReviewedTeamMember(team, login, email)) {
        warnings.push(
          `Reviewed existing GitHub team membership retained: @${login} in ${teamSlug}`,
        );
        continue;
      }
      if (
        isEmployeeEntitlementExcluded(
          email,
          usersByEmail.get(email)?.id,
          employeeEntitlementAuthority,
        )
      )
        continue;
      changes.push(
        change(
          "team_remove",
          email,
          login,
          teamSlug,
          "none",
          [policy.rootGroupEmail, emailForTeam(policy, teamSlug)],
          "GitHub team member is absent from the authoritative Google group",
          complete,
          usersByEmail.get(email),
        ),
      );
    }
  }

  function retainsReviewedTeamMember(
    team: GitHubAccessSnapshot["teams"][number],
    login: string,
    email: string | undefined,
  ): boolean {
    const user = email === undefined ? undefined : usersByEmail.get(email);
    const member = team.directMembers.find(
      (candidate) => candidate.login === login,
    );
    return (
      user !== undefined &&
      !user.suspended &&
      !user.archived &&
      !user.deleted &&
      member !== undefined &&
      member.inherited !== true &&
      !team.maintainers.some((candidate) => candidate.login === login) &&
      isReviewedGitHubTeamMembership(
        {
          googleUserId: user.id,
          githubUserId: String(member.id),
          githubLogin: member.login,
          teamId: team.id,
          teamSlug: team.slug,
        },
        policy.reviewedTeamMemberships ?? [],
      )
    );
  }

  function flagElevatedMembership(): void {
    for (const email of elevated) {
      if (!platform.has(email)) {
        changes.push(
          change(
            "policy_exception",
            email,
            identity.loginByEmail.get(email),
            "voice-elevated-permissions",
            "blocked",
            [
              emailForTeam(policy, "eng-platform"),
              emailForTeam(policy, "voice-elevated-permissions"),
            ],
            "Elevated voice membership must be a subset of eng-platform",
            false,
            usersByEmail.get(email),
          ),
        );
      }
    }
  }

  function addManualReviewExceptions(): void {
    addDirectRepositoryReviews(retainedDirectGrantActors());
    for (const collaborator of github.outsideCollaborators) {
      changes.push(
        exceptionChange(
          "outside_collaborator",
          collaborator,
          policy.organization,
          "repository_specific",
          "Outside collaborators are outside workforce SAML and require sponsor, expiry, and least-privilege review",
        ),
      );
    }
    for (const team of github.teams) {
      for (const maintainer of team.maintainers) {
        changes.push(
          exceptionChange(
            "team_maintainer",
            maintainer,
            team.slug,
            "maintainer",
            "GitHub team maintainer privilege requires periodic human certification",
          ),
        );
      }
    }
  }

  function addDirectRepositoryReviews(retained: ReadonlySet<string>): void {
    for (const repository of github.repositories) {
      for (const collaborator of repository.directCollaborators) {
        if (retained.has(String(collaborator.id))) continue;
        changes.push(
          exceptionChange(
            "direct_repository_grant",
            collaborator,
            repository["full_name"],
            permissionFromFlags(collaborator.permissions),
            "Direct repository access bypasses managed team authority and requires human review",
          ),
        );
      }
    }
  }

  function retainedDirectGrantActors(): Set<string> {
    const retained = new Set<string>();
    if (
      !complete ||
      errors.length > 0 ||
      policy.reviewedDirectGrantRetentions === undefined
    )
      return retained;
    for (const reviewed of policy.reviewedDirectGrantRetentions) {
      const user = usersByEmail.get(reviewed.primaryEmail);
      const member = github.members.find(
        (candidate) => String(candidate.id) === reviewed.githubUserId,
      );
      if (
        user === undefined ||
        !activeRootUsers.has(reviewed.primaryEmail) ||
        member?.role !== "member" ||
        identity.loginByEmail.get(reviewed.primaryEmail)?.toLowerCase() !==
          member.login.toLowerCase() ||
        github.outsideCollaborators.some((actor) => actor.id === member.id)
      )
        continue;
      const grants = github.repositories.flatMap((repository) =>
        repository.directCollaborators
          .filter((actor) => actor.id === member.id)
          .map((actor) => ({
            ...(actor.customRoleName !== undefined && {
              customRoleName: actor.customRoleName,
            }),
            ...(actor.unresolvedDirectRole === true && {
              unresolvedDirectRole: true as const,
            }),
            repositoryId: repository.id,
            repositoryName: repository["full_name"],
            permission: permissionFromFlags(actor.permissions),
          })),
      );
      if (
        matchesReviewedGitHubDirectGrants(
          reviewed,
          {
            googleUserId: user.id,
            primaryEmail: user.primaryEmail,
            githubUserId: String(member.id),
            githubLogin: member.login,
          },
          grants,
        )
      ) {
        retained.add(String(member.id));
        warnings.push(
          `Reviewed existing GitHub direct repository grants retained: @${member.login}`,
        );
      }
    }
    return retained;
  }

  function annotateRemovalGrace(): void {
    for (const planned of changes) {
      if (planned.kind !== "org_remove" && planned.kind !== "team_remove")
        continue;
      const user = planned.subject.email
        ? usersByEmail.get(planned.subject.email)
        : undefined;
      planned.grace = classifyRemovalGrace(
        user,
        planned.subject.email,
        planned.kind === "org_remove"
          ? policy.rootGroupEmail
          : emailForTeam(policy, planned.target),
        google.reports,
        now,
        policy,
      );
    }
  }

  const repositoryAccess = computeRepositoryAccess(
    github,
    changes,
    policy.teamMappings,
  );
  const samlScimReadiness = buildSamlScimReadiness(github);

  changes.sort((left, right) => left.id.localeCompare(right.id));
  const reportWithoutHash: Omit<GithubAccessAuditReport, "contentHash"> = {
    complete: complete && errors.length === 0,
    counts: {
      githubMembers: github.members.length,
      googleEligibleUsers: rootUsers.size,
      internalRepositories: github.repositories.filter(
        (repo) => repo.visibility === "internal",
      ).length,
      proposedChanges: changes.length,
      reportsMembershipEvents: google.reports.events.length,
      repositories: github.repositories.length,
      teams: github.teams.length,
    },
    errors: errors.toSorted(compareString),
    generatedAt,
    identityMismatches: identity.mismatches,
    inventory: {
      bots: [
        ...github.members,
        ...github.outsideCollaborators,
        ...github.repositories.flatMap(
          (repository) => repository.directCollaborators,
        ),
      ]
        .filter((actor) => actor.type === "Bot")
        .map((actor) => actor.login)
        .filter((login, index, all) => all.indexOf(login) === index)
        .toSorted(compareString),
      deletedGoogleUsers: google.users
        .filter((user) => user.deleted)
        .map((user) => user.primaryEmail)
        .toSorted(compareString),
      directRepositoryGrants: github.repositories.flatMap((repo) =>
        repo.directCollaborators.map((collaborator) => ({
          ...(collaborator.customRoleName !== undefined && {
            customRoleName: collaborator.customRoleName,
          }),
          ...(collaborator.unresolvedDirectRole === true && {
            unresolvedDirectRole: true as const,
          }),
          login: collaborator.login,
          permission: permissionFromFlags(collaborator.permissions),
          repository: repo["full_name"],
        })),
      ),
      githubExcludedGoogleGroups: githubExcludedGoogleGroups.toSorted(
        (left, right) => left.groupEmail.localeCompare(right.groupEmail),
      ),
      internalRepositories: github.repositories
        .filter((repo) => repo.visibility === "internal")
        .map((repo) => repo["full_name"])
        .toSorted(compareString),
      invitations: github.invitations,
      maintainers: github.teams.flatMap((team) =>
        team.maintainers.map((maintainer) => ({
          login: maintainer.login,
          team: team.slug,
        })),
      ),
      organization: github.organization,
      orgOwners: github.members
        .filter((member) => member.role === "admin")
        .map((member) => member.login)
        .toSorted(compareString),
      outsideCollaborators: github.outsideCollaborators
        .map((member) => member.login)
        .toSorted(compareString),
      repositories: github.repositories,
      suspendedGoogleUsers: google.users
        .filter((user) => user.suspended || user.archived)
        .map((user) => user.primaryEmail)
        .toSorted(compareString),
      teams: github.teams,
      unmanagedGithubTeams: github.teams
        .filter((team) => !mappedTeamSlugs.has(team.slug))
        .map((team) => team.slug)
        .toSorted(compareString),
      unmappedGoogleGroups: google.unmappedDescendantGroups
        .map((group) => group.email)
        .toSorted(compareString),
    },
    policyVersion: policy.policyVersion,
    proposedChanges: changes,
    repositoryAccess,
    runId,
    samlScimReadiness,
    sourceTimestamps: { github: github.capturedAt, google: google.capturedAt },
    warnings: warnings.toSorted(compareString),
  };
  const semantic = {
    ...reportWithoutHash,
    generatedAt: undefined,
    runId: undefined,
    sourceTimestamps: undefined,
  };
  return { ...reportWithoutHash, contentHash: await contentHash(semantic) };
}

function buildSamlScimReadiness(
  github: GitHubAccessSnapshot,
): GithubAccessAuditReport["samlScimReadiness"] {
  const identityReadiness = compareSamlScim(github);
  const exactNameIdMatchesUserName = identityReadiness.exact;
  const samlBlockers: string[] = [...identityReadiness.blockers];
  const samlAvailable = !github.errors.some(
    (error) => error.capability === "saml_external_identities",
  );
  const scimAvailable = !github.errors.some(
    (error) => error.capability === "scim_identities",
  );
  if (!samlAvailable)
    samlBlockers.push(
      "SAML external identity data is unavailable; SAML may be disabled or the token lacks access.",
    );
  if (!scimAvailable)
    samlBlockers.push(
      "SCIM identity data is unavailable; custom provisioning remains blocked pending GitHub Support confirmation.",
    );
  if (exactNameIdMatchesUserName === false)
    samlBlockers.push(
      "At least one SAML NameID does not exactly match the corresponding SCIM userName.",
    );
  if (github.repositories.some((repo) => repo.visibility === "internal"))
    samlBlockers.push(
      "Organization-level SAML does not cover internal repositories; evaluate enterprise-level enforcement.",
    );

  return {
    blockers: samlBlockers,
    exactNameIdMatchesUserName,
    samlIdentityDataAvailable: samlAvailable,
    scimIdentityDataAvailable: scimAvailable,
  };
}

function emailForTeam(policy: GithubAccessAuditPolicy, slug: string): string {
  return (
    Object.entries(policy.teamMappings).find(
      ([, team]) => team === slug,
    )?.[0] ?? slug
  );
}

function compareString(left: string, right: string): number {
  return left.localeCompare(right);
}
