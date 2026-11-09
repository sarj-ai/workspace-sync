import type { GitHubAccessSnapshot } from "./git-hub-access-audit-client.ts";
import type {
  EffectiveRepositoryAccess,
  ProposedAccessChange,
  RepositoryPermission,
} from "./model.ts";

const PERMISSION_RANK: Readonly<Record<RepositoryPermission, number>> = {
  admin: 5,
  maintain: 4,
  none: 0,
  pull: 1,
  push: 3,
  triage: 2,
  unknown: 0,
};

interface PermissionSource {
  permission: RepositoryPermission;
  source: string;
}

interface InheritedGrant {
  after: boolean;
  before: boolean;
  source: PermissionSource;
}

interface AccessContext {
  adds: Set<string>;
  basePermission: RepositoryPermission;
  currentOrgMembers: Set<string>;
  descendantsByTeam: Map<string, string[]>;
  managed: Set<string>;
  memberLoginsByTeam: Map<string, Set<string>>;
  orgAdds: Set<string>;
  orgRemovals: Set<string>;
  removes: Set<string>;
}

export function computeRepositoryAccess(
  github: GitHubAccessSnapshot,
  changes: ProposedAccessChange[],
  teamMappings: Readonly<Record<string, string>>,
): EffectiveRepositoryAccess[] {
  const context: AccessContext = {
    adds: changeLogins(changes, "team_add"),
    basePermission: normalizeRepositoryPermission(
      github.organization?.["default_repository_permission"],
    ),
    currentOrgMembers: new Set(github.members.map((member) => member.login)),
    descendantsByTeam: new Map(
      github.teams.map((team) => [
        team.slug,
        descendantsIncluding(team.slug, github.teams),
      ]),
    ),
    managed: new Set(Object.values(teamMappings)),
    memberLoginsByTeam: new Map(
      github.teams.map((team) => [
        team.slug,
        new Set(
          [...team.directMembers, ...team.maintainers].map(
            (member) => member.login,
          ),
        ),
      ]),
    ),
    orgAdds: subjectLogins(changes, "org_add"),
    orgRemovals: subjectLogins(changes, "org_remove"),
    removes: changeLogins(changes, "team_remove"),
  };
  const result = github.repositories.flatMap((repo) =>
    repositoryAccess(
      repo,
      github.members.map((member) => member.login),
      context,
    ),
  );
  return result.toSorted((left, right) =>
    `${left.repository}:${left.login}`.localeCompare(
      `${right.repository}:${right.login}`,
    ),
  );
}

function repositoryAccess(
  repo: GitHubAccessSnapshot["repositories"][number],
  memberLogins: string[],
  context: AccessContext,
): EffectiveRepositoryAccess[] {
  const logins = new Set(memberLogins);
  for (const collaborator of repo.directCollaborators)
    logins.add(collaborator.login);
  for (const login of context.orgAdds) logins.add(login);
  return [...logins].flatMap((login) => {
    const direct = repo.directCollaborators.find(
      (item) => item.login === login,
    );
    const beforeSources: PermissionSource[] = direct
      ? [
          {
            permission: permissionFromFlags(direct.permissions),
            source: "direct",
          },
        ]
      : [];
    const afterSources = [...beforeSources];
    appendOrganizationSources(login, context, beforeSources, afterSources);
    for (const grant of repo.teamGrants) {
      const inherited = inheritedGrant(login, grant, context);
      if (inherited.before) beforeSources.push(inherited.source);
      if (inherited.after) afterSources.push(inherited.source);
    }
    if (context.orgRemovals.has(login)) afterSources.length = 0;
    const before = strongest(beforeSources);
    const after = strongest(afterSources);
    return before !== after || before !== "none"
      ? {
          after,
          before,
          login,
          repository: repo["full_name"],
          sourcesAfter: afterSources
            .map((item) => item.source)
            .toSorted(compareString),
          sourcesBefore: beforeSources
            .map((item) => item.source)
            .toSorted(compareString),
        }
      : [];
  });
}

function appendOrganizationSources(
  login: string,
  context: AccessContext,
  beforeSources: PermissionSource[],
  afterSources: PermissionSource[],
): void {
  if (context.basePermission === "none") return;
  const source = {
    permission: context.basePermission,
    source: "organization:base_permission",
  };
  if (context.currentOrgMembers.has(login)) beforeSources.push(source);
  if (
    (context.currentOrgMembers.has(login) || context.orgAdds.has(login)) &&
    !context.orgRemovals.has(login)
  )
    afterSources.push(source);
}

function inheritedGrant(
  login: string,
  grant: GitHubAccessSnapshot["repositories"][number]["teamGrants"][number],
  context: AccessContext,
): InheritedGrant {
  const slugs = context.descendantsByTeam.get(grant.slug) ?? [grant.slug];
  const present = slugs.some((slug) =>
    context.memberLoginsByTeam.get(slug)?.has(login),
  );
  const membershipChanged = slugs.some((slug) => context.managed.has(slug));
  const added = slugs.some((slug) => context.adds.has(`${slug}:${login}`));
  const removedFromEveryPresentTeam = slugs
    .filter((slug) => context.managed.has(slug))
    .every((slug) => context.removes.has(`${slug}:${login}`));
  return {
    after: membershipChanged
      ? (present || added) && !removedFromEveryPresentTeam
      : present,
    before: present,
    source: { permission: grant.permission, source: `team:${grant.slug}` },
  };
}

export function permissionFromFlags(
  flags:
    | {
        admin: boolean;
        maintain?: boolean | undefined;
        pull: boolean;
        push: boolean;
        triage?: boolean | undefined;
      }
    | undefined,
): RepositoryPermission {
  if (!flags) return "unknown";
  if (flags.admin) return "admin";
  if (flags.maintain) return "maintain";
  if (flags.push) return "push";
  if (flags.triage) return "triage";
  return flags.pull ? "pull" : "none";
}

function changeLogins(
  changes: ProposedAccessChange[],
  kind: "team_add" | "team_remove",
): Set<string> {
  return new Set(
    changes.flatMap((item) =>
      item.kind === kind && item.subject.login
        ? `${item.target}:${item.subject.login}`
        : [],
    ),
  );
}

function subjectLogins(
  changes: ProposedAccessChange[],
  kind: "org_add" | "org_remove",
): Set<string> {
  return new Set(
    changes.flatMap((item) =>
      item.kind === kind && item.subject.login ? [item.subject.login] : [],
    ),
  );
}

function normalizeRepositoryPermission(
  permission: "admin" | "none" | "read" | "write" | null | undefined,
): RepositoryPermission {
  if (permission === "read") return "pull";
  if (permission === "write") return "push";
  return permission ?? "none";
}

function descendantsIncluding(
  parentSlug: string,
  teams: GitHubAccessSnapshot["teams"],
): string[] {
  const result = new Set([parentSlug]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const team of teams) {
      if (
        team.parent &&
        result.has(team.parent.slug) &&
        !result.has(team.slug)
      ) {
        result.add(team.slug);
        changed = true;
      }
    }
  }
  return [...result];
}

function strongest(
  items: { permission: RepositoryPermission }[],
): RepositoryPermission {
  return items.reduce<RepositoryPermission>(
    (best, item) =>
      PERMISSION_RANK[item.permission] > PERMISSION_RANK[best]
        ? item.permission
        : best,
    "none",
  );
}

function compareString(left: string, right: string): number {
  return left.localeCompare(right);
}
