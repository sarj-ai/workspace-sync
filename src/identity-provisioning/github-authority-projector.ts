import { z } from "zod";

import {
  type AuthorityIdentity,
  AuthorityIdentitySchema,
  provisioningIdempotencyKey,
} from "../catalog/identity-authority.ts";
import { contentHash } from "../github-access-audit/content-hash.ts";
import type {
  GoogleAuditGroup,
  GoogleAuditMembership,
} from "../github-access-audit/google-contracts.ts";
import { indexMemberships } from "../github-access-audit/google-graph.ts";
import { projectGoogleDirectoryAuthority } from "../identity-lifecycle/project-google-directory-authority.ts";
import { normalizeIdentityEmail } from "../identity-sync/normalize-identity-email.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import {
  type EmployeeEntitlementAuthority,
  hasCompleteEmployeeEntitlementAuthority,
  isEmployeeEntitlementExcluded,
} from "./employee-entitlement-policy.ts";
import { GitHubDesiredOrganizationAccessSchema } from "./github-organization-connector.ts";

const TeamSlugSchema = z
  .string()
  .min(1)
  .max(100)
  .regex(/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u);

const DiagnosticCodeSchema = z.enum([
  "active-outside-root",
  "duplicate-github-login",
  "duplicate-github-user-id",
  "duplicate-google-group-email",
  "duplicate-google-group-id",
  "duplicate-google-user-email",
  "duplicate-google-user-id",
  "duplicate-membership",
  "identity-invalid",
  "identity-unlinked",
  "inactive-identity-unlinked",
  "github-exclusion-collision",
  "managed-team-collision",
  "mapped-group-detached",
  "mapped-group-missing",
  "contractor-access-review",
  "contractor-authority-incomplete",
  "root-group-missing",
  "root-user-without-managed-team",
  "unmanaged-team-collision",
  "unknown-membership-group",
  "unknown-membership-subject",
]);

const DiagnosticSchema = z
  .strictObject({
    code: DiagnosticCodeSchema,
    detail: z.string().trim().min(1),
    googleUserId: z.string().trim().min(1).optional(),
    level: z.enum(["error", "warning"]),
    subject: z.string().trim().min(1),
  })
  .readonly();

const ProjectedAccessSchema = z
  .strictObject({
    desired: GitHubDesiredOrganizationAccessSchema,
    googleUserId: z.string().trim().min(1),
  })
  .readonly();

export const GitHubAuthorityProjectionSchema = z
  .strictObject({
    complete: z.boolean(),
    diagnostics: z.array(DiagnosticSchema).readonly(),
    managedTeamSlugs: z.array(TeamSlugSchema).readonly(),
    plans: z.array(ProjectedAccessSchema).readonly(),
  })
  .readonly();

export type GitHubAuthorityProjection = z.output<
  typeof GitHubAuthorityProjectionSchema
>;

export interface GitHubAuthorityProjectionInput {
  readonly capturedAt: string;
  readonly complete: true;
  readonly groups: readonly GoogleAuditGroup[];
  readonly memberships: readonly GoogleAuditMembership[];
  readonly users: readonly GoogleDirectoryUser[];
}

export interface GitHubAuthorityProjectionPolicy {
  readonly employeeEntitlementAuthority?: EmployeeEntitlementAuthority;
  readonly excludedGroupEmails: readonly string[];
  readonly rootGroupEmail: string;
  readonly teamMappings: Readonly<Record<string, string>>;
  readonly unmanagedGithubTeams: readonly string[];
}

/*
 * Projects complete Google Directory authority into GitHub desired state.
 * This function performs no provider reads or writes; diagnostics make every
 * unsafe or ambiguous policy state explicit before connector planning.
 */
export async function projectGitHubOrganizationAuthority(
  input: GitHubAuthorityProjectionInput,
  policy: GitHubAuthorityProjectionPolicy,
): Promise<GitHubAuthorityProjection> {
  const diagnostics: z.input<typeof DiagnosticSchema>[] = [];
  const users = uniqueUsers(input.users, diagnostics);
  const groups = uniqueGroups(input.groups, diagnostics);
  validateMemberships(input.memberships, users, groups, diagnostics);
  const membersByGroup = indexMemberships([...input.memberships]);
  const managedTeamSlugs = validateTeamPolicy(policy, diagnostics);
  const graph = projectGroupAuthority(
    groups,
    membersByGroup,
    policy,
    diagnostics,
  );
  const authorities = projectIdentities(
    users,
    graph.excludedUserIds,
    input.capturedAt,
    diagnostics,
  );
  const plans = await projectDesiredAccess(
    users,
    authorities,
    graph,
    managedTeamSlugs,
    policy.rootGroupEmail,
    policy.employeeEntitlementAuthority,
    diagnostics,
  );

  const parsedDiagnostics = diagnostics
    .map((item) => DiagnosticSchema.parse(item))
    .toSorted(compareDiagnostic);
  return GitHubAuthorityProjectionSchema.parse({
    complete: parsedDiagnostics.every(
      (diagnostic) => diagnostic.level !== "error",
    ),
    diagnostics: parsedDiagnostics,
    managedTeamSlugs,
    plans: plans.toSorted((left, right) =>
      left.googleUserId.localeCompare(right.googleUserId),
    ),
  });
}

interface GroupAuthorityProjection {
  readonly excludedUserIds: ReadonlySet<string>;
  readonly mappedTeamsByUserId: ReadonlyMap<string, ReadonlySet<string>>;
  readonly rootUserIds: ReadonlySet<string>;
}

function projectGroupAuthority(
  groups: readonly GoogleAuditGroup[],
  membersByGroup: Map<string, GoogleAuditMembership[]>,
  policy: GitHubAuthorityProjectionPolicy,
  diagnostics: z.input<typeof DiagnosticSchema>[],
): GroupAuthorityProjection {
  const groupByEmail = new Map(
    groups.map((group) => [normalizeIdentityEmail(group.email), group]),
  );
  const root = groupByEmail.get(normalizeIdentityEmail(policy.rootGroupEmail));
  if (root === undefined) {
    diagnostics.push({
      code: "root-group-missing",
      detail: `Authoritative root group ${policy.rootGroupEmail} was not captured`,
      level: "error",
      subject: normalizeIdentityEmail(policy.rootGroupEmail),
    });
  }
  const reachable =
    root === undefined
      ? new Set<string>()
      : reachableGroups(root.id, membersByGroup);
  const rootUsers =
    root === undefined
      ? new Set<string>()
      : expandGroupUserIds(root.id, membersByGroup, new Set());
  const excludedUserIds = mapExcludedUsers(
    groupByEmail,
    membersByGroup,
    policy,
    diagnostics,
  );
  return {
    excludedUserIds,
    mappedTeamsByUserId: mapManagedTeams(
      groupByEmail,
      membersByGroup,
      reachable,
      policy,
      diagnostics,
    ),
    rootUserIds: rootUsers,
  };
}

function mapManagedTeams(
  groupByEmail: ReadonlyMap<string, GoogleAuditGroup>,
  membersByGroup: Map<string, GoogleAuditMembership[]>,
  reachableGroupIds: ReadonlySet<string>,
  policy: GitHubAuthorityProjectionPolicy,
  diagnostics: z.input<typeof DiagnosticSchema>[],
): ReadonlyMap<string, ReadonlySet<string>> {
  const result = new Map<string, Set<string>>();
  for (const [rawGroupEmail, rawTeamSlug] of Object.entries(
    policy.teamMappings,
  ).toSorted(([left], [right]) => left.localeCompare(right))) {
    const group = groupByEmail.get(normalizeIdentityEmail(rawGroupEmail));
    if (group === undefined || !reachableGroupIds.has(group.id)) {
      reportInvalidMappedGroup(
        rawGroupEmail,
        group,
        policy.rootGroupEmail,
        diagnostics,
      );
      continue;
    }
    const userIds = expandGroupUserIds(group.id, membersByGroup, new Set());
    const teamSlug = TeamSlugSchema.parse(rawTeamSlug);
    for (const userId of userIds) {
      result.set(userId, new Set([...(result.get(userId) ?? []), teamSlug]));
    }
  }
  return result;
}

function mapExcludedUsers(
  groupByEmail: ReadonlyMap<string, GoogleAuditGroup>,
  membersByGroup: Map<string, GoogleAuditMembership[]>,
  policy: GitHubAuthorityProjectionPolicy,
  diagnostics: z.input<typeof DiagnosticSchema>[],
): ReadonlySet<string> {
  const excluded = new Set<string>();
  const mappedEmails = new Set(
    Object.keys(policy.teamMappings).map(normalizeIdentityEmail),
  );
  for (const rawGroupEmail of policy.excludedGroupEmails.toSorted()) {
    const groupEmail = normalizeIdentityEmail(rawGroupEmail);
    if (mappedEmails.has(groupEmail)) {
      diagnostics.push({
        code: "github-exclusion-collision",
        detail: `Google group ${rawGroupEmail} cannot be both GitHub-excluded and team-mapped`,
        level: "error",
        subject: groupEmail,
      });
      continue;
    }
    const group = groupByEmail.get(groupEmail);
    if (group === undefined) {
      reportInvalidMappedGroup(
        rawGroupEmail,
        group,
        policy.rootGroupEmail,
        diagnostics,
      );
      continue;
    }
    for (const userId of expandGroupUserIds(
      group.id,
      membersByGroup,
      new Set(),
    )) {
      excluded.add(userId);
    }
  }
  return excluded;
}

function reportInvalidMappedGroup(
  groupEmail: string,
  group: GoogleAuditGroup | undefined,
  rootGroupEmail: string,
  diagnostics: z.input<typeof DiagnosticSchema>[],
): void {
  diagnostics.push({
    code:
      group === undefined ? "mapped-group-missing" : "mapped-group-detached",
    detail:
      group === undefined
        ? `Mapped Google group ${groupEmail} was not captured`
        : `Mapped Google group ${groupEmail} is outside ${rootGroupEmail}`,
    level: "error",
    subject: normalizeIdentityEmail(groupEmail),
  });
}

function projectIdentities(
  users: readonly GoogleDirectoryUser[],
  excludedUserIds: ReadonlySet<string>,
  capturedAt: string,
  diagnostics: z.input<typeof DiagnosticSchema>[],
): ReadonlyMap<string, AuthorityIdentity> {
  const authorities = new Map<string, AuthorityIdentity>();
  const githubLoginOwner = new Map<string, string>();
  const githubIdOwner = new Map<string, string>();
  for (const user of users.toSorted((left, right) =>
    left.id.localeCompare(right.id),
  )) {
    if (excludedUserIds.has(user.id)) continue;
    const result = safeAuthority(user, capturedAt, diagnostics);
    if (!result.ok) continue;
    const authority = result.authority;
    authorities.set(user.id, authority);
    if (authority.github.kind !== "verified") continue;
    recordIdentityOwner(
      githubLoginOwner,
      authority.github.githubLogin,
      user.id,
      "duplicate-github-login",
      diagnostics,
    );
    recordIdentityOwner(
      githubIdOwner,
      authority.github.githubUserId,
      user.id,
      "duplicate-github-user-id",
      diagnostics,
    );
  }
  return authorities;
}

async function projectDesiredAccess(
  users: readonly GoogleDirectoryUser[],
  authorities: ReadonlyMap<string, AuthorityIdentity>,
  graph: GroupAuthorityProjection,
  managedTeamSlugs: readonly string[],
  rootGroupEmail: string,
  employeeEntitlementAuthority: EmployeeEntitlementAuthority | undefined,
  diagnostics: z.input<typeof DiagnosticSchema>[],
): Promise<z.input<typeof ProjectedAccessSchema>[]> {
  const candidates = users
    .toSorted((left, right) => left.id.localeCompare(right.id))
    .map(async (user) => {
      if (graph.excludedUserIds.has(user.id)) return;
      const authority = authorities.get(user.id);
      if (authority === undefined) return;
      const desired = await desiredAccessForUser(
        user,
        authority,
        graph,
        managedTeamSlugs,
        rootGroupEmail,
        employeeEntitlementAuthority,
        diagnostics,
      );
      return desired === undefined
        ? undefined
        : { desired, googleUserId: user.id };
    });
  const projected = await Promise.all(candidates);
  return projected.filter(
    (plan): plan is Exclude<typeof plan, undefined> => plan !== undefined,
  );
}

async function desiredAccessForUser(
  user: GoogleDirectoryUser,
  authority: AuthorityIdentity,
  graph: GroupAuthorityProjection,
  managedTeamSlugs: readonly string[],
  rootGroupEmail: string,
  employeeEntitlementAuthority: EmployeeEntitlementAuthority | undefined,
  diagnostics: z.input<typeof DiagnosticSchema>[],
) {
  if (authority.lifecycle.kind !== "active") {
    return desiredAbsence(user, authority, diagnostics);
  }
  if (
    isEmployeeEntitlementExcluded(
      authority.primaryEmail,
      user.id,
      employeeEntitlementAuthority,
      [...(user.aliases ?? []), ...(user.nonEditableAliases ?? [])],
    )
  ) {
    diagnostics.push({
      code: "contractor-access-review",
      detail:
        "Contractor is excluded from future GitHub organization and team grants; existing access is preserved for review",
      googleUserId: user.id,
      level: "warning",
      subject: normalizeIdentityEmail(authority.primaryEmail),
    });
    return;
  }
  if (!hasCompleteEmployeeEntitlementAuthority(employeeEntitlementAuthority)) {
    diagnostics.push({
      code: "contractor-authority-incomplete",
      detail:
        "Complete current contractor authority is required for employee grants; existing access is preserved",
      googleUserId: user.id,
      level: "error",
      subject: normalizeIdentityEmail(authority.primaryEmail),
    });
    return;
  }
  if (!graph.rootUserIds.has(user.id)) {
    if (authority.github.kind === "verified") {
      diagnostics.push({
        code: "active-outside-root",
        detail: `Active mapped Google user is outside ${rootGroupEmail}; no GitHub removal is inferred`,
        googleUserId: user.id,
        level: "warning",
        subject: normalizeIdentityEmail(authority.primaryEmail),
      });
    }
    return;
  }
  const desiredTeamSlugs = [
    ...(graph.mappedTeamsByUserId.get(user.id) ?? []),
  ].toSorted(
    (sortLeft, sortRight) =>
      Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
  );
  if (desiredTeamSlugs.length === 0) {
    diagnostics.push({
      code: "root-user-without-managed-team",
      detail:
        "Root engineering membership alone does not authorize GitHub organization access; join a managed engineering subteam first",
      googleUserId: user.id,
      level: "warning",
      subject: normalizeIdentityEmail(authority.primaryEmail),
    });
    return;
  }
  if (authority.github.kind !== "verified") {
    diagnostics.push({
      code: "identity-unlinked",
      detail:
        "Active root user requires a complete immutable SarjIdentity GitHub mapping",
      googleUserId: user.id,
      level: "warning",
      subject: normalizeIdentityEmail(authority.primaryEmail),
    });
    return;
  }
  return GitHubDesiredOrganizationAccessSchema.parse({
    desiredTeamSlugs,
    idempotencyKey: provisioningIdempotencyKey({
      action: "provision",
      authorityDigest: await contentHash({
        authority,
        desiredTeamSlugs,
        managedTeamSlugs,
        employeeEntitlementFingerprint:
          employeeEntitlementAuthority?.fingerprint,
      }),
      googleUserId: authority.googleUserId,
      providerId: "github",
    }),
    kind: "present",
    managedTeamSlugs,
    organizationRole: "member",
    rehirePolicy: "fresh-least-privilege",
    subject: authority,
  });
}

async function desiredAbsence(
  user: GoogleDirectoryUser,
  authority: AuthorityIdentity,
  diagnostics: z.input<typeof DiagnosticSchema>[],
) {
  if (authority.lifecycle.kind === "active") return;
  if (authority.github.kind !== "verified") {
    diagnostics.push({
      code: "inactive-identity-unlinked",
      detail: `${authority.lifecycle.kind} Google user requires a complete immutable SarjIdentity mapping before GitHub absence can be enforced`,
      googleUserId: user.id,
      level: "warning",
      subject: normalizeIdentityEmail(authority.primaryEmail),
    });
    return;
  }
  const target = {
    githubLogin: authority.github.githubLogin,
    githubUserId: authority.github.githubUserId,
  };
  return GitHubDesiredOrganizationAccessSchema.parse({
    idempotencyKey: provisioningIdempotencyKey({
      action: "deprovision",
      authorityDigest: await contentHash({ authority, target }),
      googleUserId: authority.googleUserId,
      providerId: "github",
    }),
    kind: "absent",
    subject: authority,
    target,
  });
}

function uniqueUsers(
  input: readonly GoogleDirectoryUser[],
  diagnostics: z.input<typeof DiagnosticSchema>[],
): GoogleDirectoryUser[] {
  const ids = new Map<string, GoogleDirectoryUser>();
  const emails = new Map<string, string>();
  for (const user of input) {
    if (ids.has(user.id)) {
      diagnostics.push({
        code: "duplicate-google-user-id",
        detail: `Google user ID ${user.id} occurs more than once`,
        googleUserId: user.id,
        level: "error",
        subject: user.id,
      });
      continue;
    }
    ids.set(user.id, user);
    for (const email of [
      user.primaryEmail,
      ...(user.aliases ?? []),
      ...(user.nonEditableAliases ?? []),
    ]) {
      const normalized = normalizeIdentityEmail(email);
      const owner = emails.get(normalized);
      if (owner !== undefined && owner !== user.id) {
        diagnostics.push({
          code: "duplicate-google-user-email",
          detail: `Google email ${normalized} belongs to multiple immutable users`,
          googleUserId: user.id,
          level: "error",
          subject: normalized,
        });
      } else emails.set(normalized, user.id);
    }
  }
  return ids.values().toArray();
}

function uniqueGroups(
  input: readonly GoogleAuditGroup[],
  diagnostics: z.input<typeof DiagnosticSchema>[],
): GoogleAuditGroup[] {
  const ids = new Map<string, GoogleAuditGroup>();
  const emails = new Map<string, string>();
  for (const group of input) {
    const email = normalizeIdentityEmail(group.email);
    if (ids.has(group.id)) {
      diagnostics.push({
        code: "duplicate-google-group-id",
        detail: `Google group ID ${group.id} occurs more than once`,
        level: "error",
        subject: group.id,
      });
      continue;
    }
    ids.set(group.id, group);
    const owner = emails.get(email);
    if (owner !== undefined && owner !== group.id) {
      diagnostics.push({
        code: "duplicate-google-group-email",
        detail: `Google group email ${email} belongs to multiple immutable groups`,
        level: "error",
        subject: email,
      });
    } else emails.set(email, group.id);
  }
  return ids.values().toArray();
}

function validateMemberships(
  memberships: readonly GoogleAuditMembership[],
  users: readonly GoogleDirectoryUser[],
  groups: readonly GoogleAuditGroup[],
  diagnostics: z.input<typeof DiagnosticSchema>[],
): void {
  const groupIds = new Set(groups.map((group) => group.id));
  const userIds = new Set(users.map((user) => user.id));
  const seen = new Set<string>();
  for (const membership of memberships) {
    const key = `${membership.groupId}:${membership.memberType}:${membership.memberId}`;
    if (seen.has(key)) {
      diagnostics.push({
        code: "duplicate-membership",
        detail: `Google membership ${key} occurs more than once`,
        level: "error",
        subject: key,
      });
    }
    seen.add(key);
    if (!groupIds.has(membership.groupId)) {
      diagnostics.push({
        code: "unknown-membership-group",
        detail: `Membership parent group ${membership.groupId} was not captured`,
        level: "error",
        subject: key,
      });
    }
    const knownSubject =
      membership.memberType === "GROUP"
        ? groupIds.has(membership.memberId)
        : userIds.has(membership.memberId);
    if (!knownSubject) {
      diagnostics.push({
        code: "unknown-membership-subject",
        detail: `Membership subject ${membership.memberId} was not captured`,
        level: "error",
        subject: key,
      });
    }
  }
}

function validateTeamPolicy(
  policy: GitHubAuthorityProjectionPolicy,
  diagnostics: z.input<typeof DiagnosticSchema>[],
): string[] {
  const ownerByTeam = new Map<string, string>();
  const unmanaged = new Set(
    policy.unmanagedGithubTeams.map((team) => TeamSlugSchema.parse(team)),
  );
  for (const [groupEmail, rawTeamSlug] of Object.entries(policy.teamMappings)) {
    const teamSlug = TeamSlugSchema.parse(rawTeamSlug);
    const owner = ownerByTeam.get(teamSlug);
    if (owner !== undefined && owner !== groupEmail) {
      diagnostics.push({
        code: "managed-team-collision",
        detail: `GitHub team ${teamSlug} is targeted by multiple Google groups`,
        level: "error",
        subject: teamSlug,
      });
    } else ownerByTeam.set(teamSlug, groupEmail);
    if (unmanaged.has(teamSlug)) {
      diagnostics.push({
        code: "unmanaged-team-collision",
        detail: `GitHub team ${teamSlug} is both managed and unmanaged`,
        level: "error",
        subject: teamSlug,
      });
    }
  }
  return ownerByTeam.keys().toArray().toSorted();
}

type AuthorityProjectionResult =
  | { readonly authority: AuthorityIdentity; readonly ok: true }
  | { readonly ok: false };

function safeAuthority(
  user: GoogleDirectoryUser,
  capturedAt: string,
  diagnostics: z.input<typeof DiagnosticSchema>[],
): AuthorityProjectionResult {
  try {
    return {
      authority: AuthorityIdentitySchema.parse(
        projectGoogleDirectoryAuthority(user, capturedAt),
      ),
      ok: true,
    };
  } catch (error) {
    diagnostics.push({
      code: "identity-invalid",
      detail:
        error instanceof Error
          ? error.message
          : "Google identity could not be parsed",
      googleUserId: user.id,
      level: "error",
      subject: normalizeIdentityEmail(user.primaryEmail),
    });
    return { ok: false };
  }
}

function recordIdentityOwner(
  owners: Map<string, string>,
  value: string,
  googleUserId: string,
  code: "duplicate-github-login" | "duplicate-github-user-id",
  diagnostics: z.input<typeof DiagnosticSchema>[],
): void {
  const owner = owners.get(value);
  if (owner !== undefined && owner !== googleUserId) {
    diagnostics.push({
      code,
      detail: `GitHub identity key ${value} belongs to multiple Google users`,
      googleUserId,
      level: "error",
      subject: value,
    });
  } else owners.set(value, googleUserId);
}

function reachableGroups(
  rootGroupId: string,
  memberships: Map<string, GoogleAuditMembership[]>,
): Set<string> {
  const reachable = new Set<string>();
  const pending = [rootGroupId];
  while (pending.length > 0) {
    const groupId = pending.pop();
    if (groupId === undefined || reachable.has(groupId)) continue;
    reachable.add(groupId);
    const members = memberships.get(groupId);
    if (!members) continue;
    for (const member of members) {
      if (member.memberType === "GROUP") pending.push(member.memberId);
    }
  }
  return reachable;
}

function expandGroupUserIds(
  groupId: string,
  memberships: Map<string, GoogleAuditMembership[]>,
  seen: Set<string>,
): Set<string> {
  if (seen.has(groupId)) return new Set();
  seen.add(groupId);
  const userIds = new Set<string>();
  const members = memberships.get(groupId);
  if (!members) return userIds;
  for (const member of members) {
    if (member.memberType === "USER") userIds.add(member.memberId);
    else {
      for (const userId of expandGroupUserIds(
        member.memberId,
        memberships,
        seen,
      )) {
        userIds.add(userId);
      }
    }
  }
  return userIds;
}

function compareDiagnostic(
  left: z.output<typeof DiagnosticSchema>,
  right: z.output<typeof DiagnosticSchema>,
): number {
  return `${left.level}:${left.code}:${left.subject}:${left.googleUserId ?? ""}`.localeCompare(
    `${right.level}:${right.code}:${right.subject}:${right.googleUserId ?? ""}`,
  );
}
