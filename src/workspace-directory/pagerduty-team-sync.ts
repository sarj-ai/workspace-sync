import { dequal } from "dequal";
import { z } from "zod";

import { contentHash } from "../github-access-audit/content-hash.ts";
import {
  type EmployeeEntitlementAuthority,
  hasCompleteEmployeeEntitlementAuthority,
  isEmployeeEntitlementExcluded,
} from "../identity-provisioning/employee-entitlement-policy.ts";
import { protectedIdentityBlocker } from "../identity-provisioning/protected-identity-blocker.ts";
import { normalizeIdentityEmail } from "../identity-sync/normalize-identity-email.ts";
import type { GoogleGroupSnapshot } from "../org-sync/channel-model.ts";
import {
  type GoogleDirectoryUser,
  isActiveGoogleDirectoryUser,
} from "../org-sync/model.ts";
import {
  type PagerDutyMissingUser,
  PagerDutyMissingUserSchema,
  PagerDutyTeamDiagnosticCodeSchema,
} from "./pagerduty-readiness-contracts.ts";
import type { PagerDutyTeamSnapshot } from "./pagerduty-team-client.ts";
import {
  type PagerDutyTeamMapping,
  PagerDutyTeamRoleSchema,
} from "./pagerduty-team-config.ts";

const PagerDutyTeamDiagnosticSeveritySchema = z.enum(["error", "warning"]);
const PagerDutyTeamAuditStatusSchema = z.enum(["blocked", "ready"]);
const PagerDutyTeamActionBaseShape = {
  email: z.email(),
  pagerDutyTeamId: z.string().regex(/^P[A-Z0-9]+$/),
  pagerDutyUserId: z.string().regex(/^P[A-Z0-9]+$/),
} as const;

const PagerDutyTeamAddActionSchema = z
  .strictObject({
    ...PagerDutyTeamActionBaseShape,
    googleGroupId: z.string().min(1),
    googleUserId: z.string().min(1),
    desiredPagerDutyRole: PagerDutyTeamRoleSchema,
    type: z.literal("add"),
  })
  .readonly();
const PagerDutyTeamSetRoleActionSchema = z
  .strictObject({
    ...PagerDutyTeamActionBaseShape,
    googleGroupId: z.string().min(1),
    googleUserId: z.string().min(1),
    currentPagerDutyRole: PagerDutyTeamRoleSchema,
    desiredPagerDutyRole: PagerDutyTeamRoleSchema,
    type: z.literal("set-role"),
  })
  .readonly();
const PagerDutyTeamRemoveActionSchema = z
  .strictObject({
    ...PagerDutyTeamActionBaseShape,
    currentPagerDutyRole: PagerDutyTeamRoleSchema,
    type: z.literal("remove"),
  })
  .readonly();

export const PagerDutyTeamActionSchema = z.discriminatedUnion("type", [
  PagerDutyTeamAddActionSchema,
  PagerDutyTeamSetRoleActionSchema,
  PagerDutyTeamRemoveActionSchema,
]);
export const PagerDutyTeamWritableActionSchema = z.discriminatedUnion("type", [
  PagerDutyTeamAddActionSchema,
  PagerDutyTeamSetRoleActionSchema,
]);

const PagerDutyTeamDiagnosticSchema = z
  .strictObject({
    code: PagerDutyTeamDiagnosticCodeSchema,
    detail: z.string().min(1),
    severity: PagerDutyTeamDiagnosticSeveritySchema,
  })
  .readonly();

const PagerDutyTeamAuditCoreShape = {
  actions: z.array(PagerDutyTeamActionSchema).readonly(),
  diagnostics: z.array(PagerDutyTeamDiagnosticSchema).readonly(),
  evidenceHash: z.string().regex(/^[a-f0-9]{64}$/),
  mappingCount: z.number().int().nonnegative(),
  mutationsDisabled: z.boolean(),
  pagerDutyTeamCount: z.number().int().nonnegative().nullable(),
  pagerDutyUserCount: z.number().int().nonnegative().nullable(),
  reviewId: z.uuid(),
  status: PagerDutyTeamAuditStatusSchema,
} as const;
const PagerDutyTeamAuditCoreSchema = z
  .strictObject(PagerDutyTeamAuditCoreShape)
  .readonly();

export const AuditedPagerDutyTeamPlanSchema = z
  .strictObject({
    ...PagerDutyTeamAuditCoreShape,
    planHash: z.string().regex(/^[a-f0-9]{64}$/),
  })
  .readonly();

export type AuditedPagerDutyTeamPlan = z.output<
  typeof AuditedPagerDutyTeamPlanSchema
>;

export interface PagerDutyTeamAuditInput {
  credentialConfigured: boolean;
  employeeEntitlementAuthority?: EmployeeEntitlementAuthority;
  googleGroups?: readonly GoogleGroupSnapshot[];
  googleUsers?: readonly GoogleDirectoryUser[];
  mappings: readonly PagerDutyTeamMapping[];
  mutationsDisabled: boolean;
  pagerDuty?: PagerDutyTeamSnapshot;
  reviewId: string;
}

export type CompletePagerDutyTeamAuditInput = PagerDutyTeamAuditInput &
  Required<
    Pick<
      PagerDutyTeamAuditInput,
      | "employeeEntitlementAuthority"
      | "googleGroups"
      | "googleUsers"
      | "pagerDuty"
    >
  >;
export type PagerDutyTeamAction = z.output<typeof PagerDutyTeamActionSchema>;
export type PagerDutyTeamWritableAction = z.output<
  typeof PagerDutyTeamWritableActionSchema
>;
type PagerDutyTeamDiagnostic = z.output<typeof PagerDutyTeamDiagnosticSchema>;

export async function planPagerDutyTeamSync(
  input: PagerDutyTeamAuditInput,
): Promise<AuditedPagerDutyTeamPlan> {
  const diagnostics: z.output<typeof PagerDutyTeamDiagnosticSchema>[] = [];
  const actions: z.output<typeof PagerDutyTeamActionSchema>[] = [];
  if (input.mappings.length === 0) {
    diagnostics.push({
      code: "mapping-configuration-empty",
      detail:
        "No Google Group to PagerDuty Team pins have been reviewed and configured",
      severity: "error",
    });
  }
  if (!input.credentialConfigured) {
    diagnostics.push({
      code: "credential-missing",
      detail: "The dedicated PagerDuty team-sync credential is not configured",
      severity: "error",
    });
  }
  const hasCompleteEvidence = Boolean(
    hasCompleteEmployeeEntitlementAuthority(
      input.employeeEntitlementAuthority,
    ) &&
    input.googleGroups &&
    input.googleUsers &&
    input.pagerDuty,
  );
  if (input.mappings.length > 0 && !hasCompleteEvidence) {
    diagnostics.push({
      code: "evidence-incomplete",
      detail:
        "Fresh Google and PagerDuty evidence is required for every configured mapping",
      severity: "error",
    });
  }
  if (
    input.mappings.length > 0 &&
    hasCompleteEvidence &&
    input.employeeEntitlementAuthority &&
    input.googleGroups &&
    input.googleUsers &&
    input.pagerDuty
  ) {
    appendMappedPlans(
      {
        ...input,
        employeeEntitlementAuthority: input.employeeEntitlementAuthority,
        googleGroups: input.googleGroups,
        googleUsers: input.googleUsers,
        pagerDuty: input.pagerDuty,
      },
      actions,
      diagnostics,
    );
  }
  const evidenceHash = await contentHash(canonicalEvidence(input));
  const core = PagerDutyTeamAuditCoreSchema.parse({
    actions: actions.toSorted(compareAction),
    diagnostics: diagnostics.toSorted(compareDiagnostic),
    evidenceHash,
    mappingCount: input.mappings.length,
    mutationsDisabled: input.mutationsDisabled,
    pagerDutyTeamCount: input.pagerDuty?.teams.length ?? null,
    pagerDutyUserCount: input.pagerDuty?.users.length ?? null,
    reviewId: input.reviewId,
    status: diagnostics.some(({ severity }) => severity === "error")
      ? "blocked"
      : "ready",
  });
  return AuditedPagerDutyTeamPlanSchema.parse({
    ...core,
    planHash: await contentHash(core),
  });
}

export function pagerDutyTeamActionsEqual(
  left: PagerDutyTeamAction,
  right: PagerDutyTeamAction,
): boolean {
  return dequal(left, right);
}

export function pagerDutyMissingUsers(
  input: CompletePagerDutyTeamAuditInput,
): PagerDutyMissingUser[] {
  if (
    !hasCompleteEmployeeEntitlementAuthority(input.employeeEntitlementAuthority)
  )
    throw new Error("pagerduty_readiness_employee_authority_incomplete");
  const diagnostics: PagerDutyTeamDiagnostic[] = [];
  const groups = new Map(input.googleGroups.map((group) => [group.id, group]));
  const teams = new Map(input.pagerDuty.teams.map((team) => [team.id, team]));
  const users = new Map(input.googleUsers.map((user) => [user.id, user]));
  const providerUsers = uniquePagerDutyUsersByEmail(
    input.pagerDuty,
    diagnostics,
  );
  const providerEmails = new Set(
    input.pagerDuty.users.map(({ email }) => normalizeIdentityEmail(email)),
  );
  const missing = new Map<string, PagerDutyMissingUser>();
  for (const mapping of input.mappings) {
    const group = exactPinnedGroup(mapping, groups, diagnostics);
    if (!group || !exactPinnedTeam(mapping, teams, diagnostics)) continue;
    desiredPagerDutyUsers(
      mapping,
      group,
      users,
      input.employeeEntitlementAuthority,
      providerUsers,
      diagnostics,
      (user) => {
        const email = normalizeIdentityEmail(user.primaryEmail);
        if (
          providerEmails.has(email) ||
          pagerDutyIdentityIsProtected(user, "user")
        )
          return;
        const prior = missing.get(user.id);
        const target = {
          googleGroupId: mapping.googleGroupId,
          pagerDutyTeamId: mapping.pagerDutyTeamId,
          desiredRole: mapping.pagerDutyRole,
        };
        missing.set(
          user.id,
          PagerDutyMissingUserSchema.parse({
            googleUserId: user.id,
            email,
            targets: [...(prior?.targets ?? []), target],
          }),
        );
      },
    );
  }
  return missing
    .values()
    .toArray()
    .toSorted((left, right) =>
      left.googleUserId.localeCompare(right.googleUserId),
    );
}

export function pagerDutyTeamActionPreconditionMatches(
  action: PagerDutyTeamWritableAction,
  membership: {
    readonly role: z.output<typeof PagerDutyTeamRoleSchema>;
  } | null,
): boolean {
  return action.type === "add"
    ? membership === null
    : membership?.role === action.currentPagerDutyRole;
}

export function pagerDutyTeamActionIsConverged(
  action: PagerDutyTeamWritableAction,
  membership: {
    readonly role: z.output<typeof PagerDutyTeamRoleSchema>;
  } | null,
): boolean {
  return membership?.role === action.desiredPagerDutyRole;
}

/*
 * Proves response-loss recovery by rebuilding the exact pre-mutation provider
 * evidence and requiring it to reproduce the reviewed plan hash and action.
 */
export async function pagerDutyTeamActionIsRecoverable(
  input: CompletePagerDutyTeamAuditInput,
  action: PagerDutyTeamWritableAction,
  expectedPlanHash: string,
): Promise<boolean> {
  const currentMembership = input.pagerDuty.memberships.find(
    ({ teamId, userId }) =>
      teamId === action.pagerDutyTeamId && userId === action.pagerDutyUserId,
  );
  if (currentMembership?.role !== action.desiredPagerDutyRole) return false;
  const otherMemberships = input.pagerDuty.memberships.filter(
    ({ teamId, userId }) =>
      teamId !== action.pagerDutyTeamId || userId !== action.pagerDutyUserId,
  );
  const reconstructedMemberships =
    action.type === "add"
      ? otherMemberships
      : [
          ...otherMemberships,
          {
            role: action.currentPagerDutyRole,
            teamId: action.pagerDutyTeamId,
            userId: action.pagerDutyUserId,
          },
        ];
  const reconstructed = await planPagerDutyTeamSync({
    ...input,
    pagerDuty: { ...input.pagerDuty, memberships: reconstructedMemberships },
  });
  return (
    reconstructed.status === "ready" &&
    reconstructed.planHash === expectedPlanHash &&
    reconstructed.actions.some((candidate) =>
      pagerDutyTeamActionsEqual(candidate, action),
    )
  );
}

function canonicalEvidence(input: PagerDutyTeamAuditInput) {
  return {
    employeeEntitlementAuthority:
      input.employeeEntitlementAuthority === undefined
        ? undefined
        : {
            complete: input.employeeEntitlementAuthority.complete,
            excludedEmails:
              input.employeeEntitlementAuthority.excludedEmails.toSorted(),
            excludedGoogleUserIds:
              input.employeeEntitlementAuthority.excludedGoogleUserIds.toSorted(),
            fingerprint: input.employeeEntitlementAuthority.fingerprint,
            groupEmail: input.employeeEntitlementAuthority.groupEmail,
            groupId: input.employeeEntitlementAuthority.groupId,
          },
    googleGroups: input.googleGroups
      ?.map((group) => ({
        email: group.email.toLowerCase(),
        id: group.id,
        members: group.members
          .map(({ email, id, role, status, type }) => ({
            email: email.toLowerCase(),
            id,
            role,
            status,
            type,
          }))
          .toSorted((left, right) =>
            `${left.type}:${left.id}`.localeCompare(
              `${right.type}:${right.id}`,
            ),
          ),
      }))
      .toSorted((left, right) => left.id.localeCompare(right.id)),
    googleUsers: input.googleUsers
      ?.map(
        ({
          aliases,
          archived,
          deletionTime,
          id,
          isAdmin,
          isDelegatedAdmin,
          nonEditableAliases,
          primaryEmail,
          suspended,
        }) => ({
          aliases: (aliases ?? []).map(normalizeIdentityEmail).toSorted(),
          archived: archived ?? false,
          deletionTime: deletionTime ?? null,
          id,
          isAdmin: isAdmin ?? null,
          isDelegatedAdmin: isDelegatedAdmin ?? null,
          nonEditableAliases: (nonEditableAliases ?? [])
            .map(normalizeIdentityEmail)
            .toSorted(),
          primaryEmail: primaryEmail.toLowerCase(),
          suspended: suspended ?? false,
        }),
      )
      .toSorted((left, right) => left.id.localeCompare(right.id)),
    mappings: input.mappings.toSorted((left, right) =>
      left.googleGroupId.localeCompare(right.googleGroupId),
    ),
    pagerDuty:
      input.pagerDuty === undefined
        ? undefined
        : {
            memberships: input.pagerDuty.memberships.toSorted(
              compareMembershipEvidence,
            ),
            teams: input.pagerDuty.teams.toSorted((left, right) =>
              left.id.localeCompare(right.id),
            ),
            users: input.pagerDuty.users.toSorted((left, right) =>
              left.id.localeCompare(right.id),
            ),
          },
  };
}

function compareMembershipEvidence(
  left: PagerDutyTeamSnapshot["memberships"][number],
  right: PagerDutyTeamSnapshot["memberships"][number],
): number {
  return `${left.teamId}:${left.userId}`.localeCompare(
    `${right.teamId}:${right.userId}`,
  );
}

function appendMappedPlans(
  input: CompletePagerDutyTeamAuditInput,
  actions: PagerDutyTeamAction[],
  diagnostics: PagerDutyTeamDiagnostic[],
): void {
  const groupsById = new Map(
    input.googleGroups.map((group) => [group.id, group]),
  );
  const teamsById = new Map(
    input.pagerDuty.teams.map((team) => [team.id, team]),
  );
  const googleUsersById = new Map(
    input.googleUsers.map((user) => [user.id, user]),
  );
  const pagerDutyUsersById = new Map(
    input.pagerDuty.users.map((user) => [user.id, user]),
  );
  const pagerDutyUsersByEmail = uniquePagerDutyUsersByEmail(
    input.pagerDuty,
    diagnostics,
  );
  const protectedContractorPagerDutyUsers = contractorPagerDutyUsers(
    input.googleUsers,
    input.employeeEntitlementAuthority,
    input.pagerDuty,
  );

  for (const mapping of input.mappings) {
    const group = exactPinnedGroup(mapping, groupsById, diagnostics);
    const teamPinned = exactPinnedTeam(mapping, teamsById, diagnostics);
    if (!group || !teamPinned) continue;
    const desired = desiredPagerDutyUsers(
      mapping,
      group,
      googleUsersById,
      input.employeeEntitlementAuthority,
      pagerDutyUsersByEmail,
      diagnostics,
    );
    if (!desired.complete) continue;
    appendMembershipDrift(
      input.pagerDuty,
      mapping,
      desired.users,
      protectedContractorPagerDutyUsers,
      pagerDutyUsersById,
      actions,
      diagnostics,
    );
  }
}

function exactPinnedGroup(
  mapping: PagerDutyTeamMapping,
  groupsById: ReadonlyMap<string, GoogleGroupSnapshot>,
  diagnostics: PagerDutyTeamDiagnostic[],
): GoogleGroupSnapshot | null {
  const group = groupsById.get(mapping.googleGroupId);
  if (group?.email.toLowerCase() === mapping.googleGroupEmail) return group;
  diagnostics.push({
    code: "google-group-pin-mismatch",
    detail: `Configured Google Group pin is unavailable: ${mapping.googleGroupId}`,
    severity: "error",
  });
  return null;
}

function exactPinnedTeam(
  mapping: PagerDutyTeamMapping,
  teamsById: ReadonlyMap<string, PagerDutyTeamSnapshot["teams"][number]>,
  diagnostics: PagerDutyTeamDiagnostic[],
): boolean {
  if (
    teamsById.get(mapping.pagerDutyTeamId)?.name === mapping.pagerDutyTeamName
  )
    return true;
  diagnostics.push({
    code: "pagerduty-team-pin-mismatch",
    detail: `Configured PagerDuty Team pin is unavailable: ${mapping.pagerDutyTeamId}`,
    severity: "error",
  });
  return false;
}

function desiredPagerDutyUsers(
  mapping: PagerDutyTeamMapping,
  group: GoogleGroupSnapshot,
  googleUsersById: ReadonlyMap<string, GoogleDirectoryUser>,
  employeeEntitlementAuthority: EmployeeEntitlementAuthority,
  pagerDutyUsersByEmail: ReadonlyMap<
    string,
    PagerDutyTeamSnapshot["users"][number]
  >,
  diagnostics: PagerDutyTeamDiagnostic[],
  onMissing?: (user: GoogleDirectoryUser) => void,
): {
  complete: boolean;
  users: ReadonlyMap<string, { email: string; googleUserId: string }>;
} {
  const desiredUsers = new Map<
    string,
    { email: string; googleUserId: string }
  >();
  let complete = true;
  const includedMembers = group.members.filter((member) => {
    const googleUser =
      member.type === "USER" ? googleUsersById.get(member.id) : undefined;
    return !pagerDutyMappingExcludesIdentity(mapping, member.email, googleUser);
  });
  for (const member of includedMembers) {
    const googleUser =
      member.type === "USER" ? googleUsersById.get(member.id) : undefined;
    if (
      member.type === "USER" &&
      (isEmployeeEntitlementExcluded(
        member.email,
        member.id,
        employeeEntitlementAuthority,
      ) ||
        (googleUser !== undefined &&
          googleUserIsContractor(googleUser, employeeEntitlementAuthority)))
    ) {
      continue;
    }
    if (
      !googleUser ||
      member.status !== "ACTIVE" ||
      !isActiveGoogleDirectoryUser(googleUser)
    ) {
      diagnostics.push({
        code: "google-group-member-ineligible",
        detail: `Google Group member is not one direct active user: ${member.id}`,
        severity: "error",
      });
      complete = false;
      continue;
    }
    const email = normalizeIdentityEmail(googleUser.primaryEmail);
    const pagerDutyUser = pagerDutyUsersByEmail.get(email);
    if (!pagerDutyUser) {
      onMissing?.(googleUser);
      diagnostics.push({
        code: "pagerduty-user-missing",
        detail: `Active Google Group member has no unique PagerDuty account: ${email}`,
        severity: "error",
      });
      complete = false;
      continue;
    }
    if (pagerDutyIdentityIsProtected(googleUser, pagerDutyUser.role)) {
      diagnostics.push({
        code: "protected-identity",
        detail: `PagerDuty Team writes require an unprotected Google identity and an ordinary PagerDuty user: ${email}`,
        severity: "error",
      });
      complete = false;
      continue;
    }
    desiredUsers.set(pagerDutyUser.id, { email, googleUserId: googleUser.id });
  }
  return { complete, users: desiredUsers };
}

function pagerDutyMappingExcludesIdentity(
  mapping: PagerDutyTeamMapping,
  memberEmail: string,
  googleUser: GoogleDirectoryUser | undefined,
): boolean {
  const excludedEmails = new Set(
    (mapping.excludedEmails ?? []).map(normalizeIdentityEmail),
  );
  if (excludedEmails.has(normalizeIdentityEmail(memberEmail))) return true;
  return (
    googleUser !== undefined &&
    googleUserEmails(googleUser).some((email) => excludedEmails.has(email))
  );
}

function pagerDutyIdentityIsProtected(
  user: GoogleDirectoryUser,
  pagerDutyRole: string,
): boolean {
  return (
    pagerDutyRole !== "user" ||
    protectedIdentityBlocker({
      googleUserId: user.id,
      primaryEmail: user.primaryEmail,
      aliases: [...(user.aliases ?? []), ...(user.nonEditableAliases ?? [])],
      isAdmin: user.isAdmin,
      isDelegatedAdmin: user.isDelegatedAdmin,
    }) !== undefined
  );
}

function contractorPagerDutyUsers(
  googleUsers: readonly GoogleDirectoryUser[],
  employeeEntitlementAuthority: EmployeeEntitlementAuthority,
  pagerDuty: PagerDutyTeamSnapshot,
): ReadonlyMap<string, string> {
  const contractorEmails = new Set(
    employeeEntitlementAuthority.excludedEmails.map(normalizeIdentityEmail),
  );
  for (const user of googleUsers) {
    const emails = googleUserEmails(user);
    if (googleUserIsContractor(user, employeeEntitlementAuthority)) {
      for (const email of emails) contractorEmails.add(email);
    }
  }
  return new Map(
    pagerDuty.users
      .filter(({ email }) =>
        contractorEmails.has(normalizeIdentityEmail(email)),
      )
      .map((user) => [user.id, normalizeIdentityEmail(user.email)]),
  );
}

function googleUserIsContractor(
  user: GoogleDirectoryUser,
  employeeEntitlementAuthority: EmployeeEntitlementAuthority,
): boolean {
  return googleUserEmails(user).some((email) =>
    isEmployeeEntitlementExcluded(email, user.id, employeeEntitlementAuthority),
  );
}

function googleUserEmails(user: GoogleDirectoryUser): string[] {
  return [
    user.primaryEmail,
    ...(user.aliases ?? []),
    ...(user.nonEditableAliases ?? []),
  ]
    .map(normalizeIdentityEmail)
    .toSorted((left, right) => left.localeCompare(right));
}

function appendMembershipDrift(
  snapshot: PagerDutyTeamSnapshot,
  mapping: PagerDutyTeamMapping,
  desiredUsers: ReadonlyMap<string, { email: string; googleUserId: string }>,
  preservedUsers: ReadonlyMap<string, string>,
  pagerDutyUsersById: ReadonlyMap<
    string,
    PagerDutyTeamSnapshot["users"][number]
  >,
  actions: PagerDutyTeamAction[],
  diagnostics: PagerDutyTeamDiagnostic[],
): void {
  const currentByUserId = new Map(
    snapshot.memberships
      .filter(({ teamId }) => teamId === mapping.pagerDutyTeamId)
      .map((membership) => [membership.userId, membership]),
  );
  for (const [userId, { email, googleUserId }] of desiredUsers) {
    const current = currentByUserId.get(userId);
    if (current?.role === mapping.pagerDutyRole) continue;
    if (current?.role === "manager" || mapping.pagerDutyRole === "manager") {
      diagnostics.push({
        code: "protected-identity",
        detail: `PagerDuty Team manager changes require manual review: ${email}`,
        severity: "error",
      });
      continue;
    }
    actions.push(
      current
        ? {
            currentPagerDutyRole: current.role,
            desiredPagerDutyRole: mapping.pagerDutyRole,
            email,
            googleGroupId: mapping.googleGroupId,
            googleUserId,
            pagerDutyTeamId: mapping.pagerDutyTeamId,
            pagerDutyUserId: userId,
            type: "set-role",
          }
        : {
            desiredPagerDutyRole: mapping.pagerDutyRole,
            email,
            googleGroupId: mapping.googleGroupId,
            googleUserId,
            pagerDutyTeamId: mapping.pagerDutyTeamId,
            pagerDutyUserId: userId,
            type: "add",
          },
    );
  }
  for (const [userId, membership] of currentByUserId) {
    if (desiredUsers.has(userId)) continue;
    const preservedEmail = preservedUsers.get(userId);
    if (preservedEmail !== undefined) {
      diagnostics.push({
        code: "contractor-membership-preserved",
        detail: `Contractor PagerDuty Team membership requires explicit manual review: ${preservedEmail}`,
        severity: "warning",
      });
      continue;
    }
    const pagerDutyUser = pagerDutyUsersById.get(userId);
    if (!pagerDutyUser) continue;
    actions.push({
      currentPagerDutyRole: membership.role,
      email: pagerDutyUser.email,
      pagerDutyTeamId: mapping.pagerDutyTeamId,
      pagerDutyUserId: userId,
      type: "remove",
    });
  }
}

function uniquePagerDutyUsersByEmail(
  snapshot: PagerDutyTeamSnapshot,
  diagnostics: PagerDutyTeamDiagnostic[],
): Map<string, PagerDutyTeamSnapshot["users"][number]> {
  const result = new Map<string, PagerDutyTeamSnapshot["users"][number]>();
  const ambiguous = new Set<string>();
  for (const user of snapshot.users) {
    const email = normalizeIdentityEmail(user.email);
    if (result.has(email)) {
      result.delete(email);
      ambiguous.add(email);
    } else if (!ambiguous.has(email)) {
      result.set(email, user);
    }
  }
  for (const email of ambiguous) {
    diagnostics.push({
      code: "pagerduty-user-email-ambiguous",
      detail: `PagerDuty email maps to more than one account: ${email}`,
      severity: "error",
    });
  }
  return result;
}

function compareAction(
  left: z.output<typeof PagerDutyTeamActionSchema>,
  right: z.output<typeof PagerDutyTeamActionSchema>,
): number {
  return `${left.pagerDutyTeamId}:${left.pagerDutyUserId}:${left.type}`.localeCompare(
    `${right.pagerDutyTeamId}:${right.pagerDutyUserId}:${right.type}`,
  );
}

function compareDiagnostic(
  left: z.output<typeof PagerDutyTeamDiagnosticSchema>,
  right: z.output<typeof PagerDutyTeamDiagnosticSchema>,
): number {
  return `${left.code}:${left.detail}`.localeCompare(
    `${right.code}:${right.detail}`,
  );
}
