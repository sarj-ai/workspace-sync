import { isInactiveGoogleUser } from "../google-workspace/user-lifecycle.ts";
import { normalizeIdentityEmail as normalizeEmail } from "../identity-sync/normalize-identity-email.ts";
import type { GoogleGroupSnapshot } from "../org-sync/channel-model.ts";
import { orgSyncSettings } from "../org-sync/config.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import {
  hasTrycompDeactivationSafety,
  isVerifiedDeviceFreeTrycompRevocation,
} from "./deactivation-safety.ts";
import { isTrycompMembershipDeactivated } from "./is-trycomp-membership-deactivated.ts";
import type { TrycompAction, TrycompMember, TrycompPlan } from "./model.ts";
import { TrycompPlanSchema } from "./model.ts";

const REMOVABLE_TRYCOMP_ROLE = "employee";
const ACTION_ORDER = { deactivate: 0, invite: 1, reactivate: 2 } as const;

export async function buildTrycompPlan(input: {
  automaticIdentityLimit?: 1;
  offboardingOnly?: boolean;
  activeGoogleUserCount?: number;
  activationDeniedEmails?: readonly string[];
  contractorGroup: GoogleGroupSnapshot;
  excludedGoogleUserIds: readonly string[];
  expectedContractorGroupId: string;
  googleUsers: readonly GoogleDirectoryUser[];
  managedDomain: string;
  minimumGoogleUsers: number;
  protectedEmails?: readonly string[];
  protectedGoogleUserIds?: readonly string[];
  writeProtectedEmails?: readonly string[];
  writeProtectedGoogleUserIds?: readonly string[];
  trycompMembers: readonly TrycompMember[];
}): Promise<TrycompPlan> {
  const errors: string[] = [];
  const warnings: string[] = [];
  const activeGoogleUserCount =
    input.activeGoogleUserCount ?? input.googleUsers.length;
  if (activeGoogleUserCount < input.minimumGoogleUsers) {
    errors.push(
      `Google Directory population ${String(activeGoogleUserCount)} is below floor ${String(input.minimumGoogleUsers)}`,
    );
  }
  if (input.contractorGroup.id !== input.expectedContractorGroupId) {
    errors.push(
      "Configured contractor group resolved to an unexpected immutable Google ID",
    );
  }

  const googleByEmail = buildGoogleEmailIndex(input.googleUsers, errors);
  const googleById = buildGoogleIdIndex(input.googleUsers, errors);
  const activationDeniedEmails = new Set(
    (input.activationDeniedEmails ?? []).map(normalizeEmail),
  );
  const activationDeniedGoogleIds = resolveGoogleIds(
    activationDeniedEmails,
    googleByEmail,
  );
  const writeProtectedEmails = new Set(
    (input.writeProtectedEmails ?? input.protectedEmails ?? []).map(
      normalizeEmail,
    ),
  );
  const writeProtectedGoogleUserIds =
    input.writeProtectedGoogleUserIds ?? input.protectedGoogleUserIds ?? [];
  const writeProtectedGoogleIds = resolveProtectedGoogleIds(
    writeProtectedGoogleUserIds,
    writeProtectedEmails,
    googleByEmail,
    googleById,
    errors,
  );
  const frozenGoogleIds = new Set(input.excludedGoogleUserIds);
  for (const id of writeProtectedGoogleIds) frozenGoogleIds.add(id);
  applyAbsoluteWriteProtections(
    input.googleUsers,
    frozenGoogleIds,
    writeProtectedEmails,
  );
  const contractorGoogleIds = contractorGoogleIdSet(
    input.contractorGroup,
    googleByEmail,
    errors,
  );
  const desiredEmails = desiredEmployeeEmails(
    input.googleUsers,
    contractorGoogleIds,
    input.managedDomain,
  );
  const membersByEmail = trycompMemberIndex({
    members: input.trycompMembers,
    desiredEmails,
    googleByEmail,
    frozenGoogleIds,
    contractorGoogleIds,
    errors,
    warnings,
  });
  const candidates = planActions({
    offboardingOnly: input.offboardingOnly === true,
    activationDeniedEmails,
    activationDeniedGoogleIds,
    contractorGoogleIds,
    desiredEmails,
    errors,
    frozenGoogleIds,
    googleByEmail,
    managedDomain: input.managedDomain,
    membersByEmail,
    writeProtectedEmails,
    warnings,
  }).toSorted(compareAction);
  const actions =
    input.automaticIdentityLimit === 1 ? candidates.slice(0, 1) : candidates;
  if (actions.length < candidates.length) {
    warnings.push(
      "Additional Trycomp changes deferred by the shared one-identity automatic limit",
    );
  }
  const planHash = await authorityBoundPlanHash({
    activationDeniedEmails,
    activeGoogleUserCount,
    actions,
    offboardingOnly: input.offboardingOnly === true,
    contractorGroup: input.contractorGroup,
    expectedContractorGroupId: input.expectedContractorGroupId,
    excludedGoogleUserIds: input.excludedGoogleUserIds,
    frozenGoogleIds,
    googleUsers: input.googleUsers,
    managedDomain: input.managedDomain,
    minimumGoogleUsers: input.minimumGoogleUsers,
    writeProtectedEmails,
    writeProtectedGoogleUserIds,
    trycompMembers: input.trycompMembers,
  });
  return TrycompPlanSchema.parse({
    actions,
    errors: [...new Set(errors)].toSorted(
      (sortLeft, sortRight) =>
        Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
    ),
    planHash,
    stats: {
      activeGoogleEmployees: desiredEmails.size,
      contractorGoogleUsers: contractorGoogleIds.size,
      trycompMembers: input.trycompMembers.length,
    },
    warnings: [...new Set(warnings)].toSorted(
      (sortLeft, sortRight) =>
        Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
    ),
  });
}

function resolveGoogleIds(
  emails: ReadonlySet<string>,
  googleByEmail: ReadonlyMap<string, GoogleDirectoryUser>,
): Set<string> {
  const ids = new Set<string>();
  for (const email of emails) {
    const user = googleByEmail.get(email);
    if (user) ids.add(user.id);
  }
  return ids;
}

function applyAbsoluteWriteProtections(
  users: readonly GoogleDirectoryUser[],
  frozenGoogleIds: Set<string>,
  writeProtectedEmails: Set<string>,
): void {
  for (const user of users) {
    const aliases = googleIdentityEmails(user);
    if (!isAbsolutelyWriteProtected(user, aliases)) continue;
    frozenGoogleIds.add(user.id);
    for (const email of aliases) writeProtectedEmails.add(email);
  }
}

function googleIdentityEmails(user: GoogleDirectoryUser): string[] {
  return [
    user.primaryEmail,
    ...(user.aliases ?? []),
    ...(user.nonEditableAliases ?? []),
  ].map(normalizeEmail);
}

function isAbsolutelyWriteProtected(
  user: GoogleDirectoryUser,
  aliases: readonly string[],
): boolean {
  return (
    user.isAdmin !== false ||
    user.isDelegatedAdmin !== false ||
    orgSyncSettings().expectedRootGoogleUserIds.includes(user.id) ||
    aliases.includes(orgSyncSettings().googleAdminSubject)
  );
}

interface PlanActionInput {
  activationDeniedEmails: ReadonlySet<string>;
  activationDeniedGoogleIds: ReadonlySet<string>;
  contractorGoogleIds: ReadonlySet<string>;
  desiredEmails: ReadonlySet<string>;
  errors: string[];
  frozenGoogleIds: ReadonlySet<string>;
  googleByEmail: ReadonlyMap<string, GoogleDirectoryUser>;
  managedDomain: string;
  membersByEmail: ReadonlyMap<string, IndexedTrycompMember>;
  offboardingOnly: boolean;
  warnings: string[];
  writeProtectedEmails: ReadonlySet<string>;
}

function planActions(input: PlanActionInput): TrycompAction[] {
  const deactivations = deactivationActions(input);
  return input.offboardingOnly
    ? deactivations.filter(
        (action) =>
          action.type === "deactivate" &&
          action.deactivationAuthority === "inactive_google",
      )
    : [...activationActions(input), ...deactivations];
}

function activationActions(input: PlanActionInput): TrycompAction[] {
  const actions: TrycompAction[] = [];
  for (const email of [...input.desiredEmails].toSorted(
    (sortLeft, sortRight) =>
      Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
  )) {
    const google = input.googleByEmail.get(email);
    if (
      !google ||
      input.frozenGoogleIds.has(google.id) ||
      input.activationDeniedGoogleIds.has(google.id) ||
      input.activationDeniedEmails.has(email) ||
      input.writeProtectedEmails.has(email)
    )
      continue;
    const indexed = input.membersByEmail.get(email);
    if (!indexed) {
      actions.push({ email, type: "invite" });
      continue;
    }
    const { member, observedEmail } = indexed;
    if (!member.isActive || member.deactivated) {
      actions.push({
        email,
        memberId: member.id,
        ...(!(observedEmail === email) && { providerEmail: observedEmail }),
        type: "reactivate",
      });
    }
  }

  return actions;
}

function deactivationActions(input: PlanActionInput): TrycompAction[] {
  const actions: TrycompAction[] = [];
  for (const [email, indexed] of input.membersByEmail) {
    const action = planDeactivation(input, email, indexed);
    if (action) actions.push(action);
  }
  return actions;
}

function planDeactivation(
  input: PlanActionInput,
  email: string,
  indexed: IndexedTrycompMember,
): TrycompAction | undefined {
  const { member, observedEmail } = indexed;
  const managedSuffix = `@${input.managedDomain.toLocaleLowerCase("en-US")}`;
  if (
    !email.endsWith(managedSuffix) ||
    input.desiredEmails.has(email) ||
    isTrycompMembershipDeactivated(member) ||
    input.writeProtectedEmails.has(email)
  )
    return;
  const google = input.googleByEmail.get(email);
  if (!google) {
    if (!member.isActive && !member.deactivated) {
      input.warnings.push(
        `Personnel-inactive Trycomp member ${email} has no Google Directory identity and requires manual access review`,
      );
    } else {
      input.errors.push(
        `Trycomp member ${email} has no Google Directory identity`,
      );
    }
    return;
  }
  if (input.frozenGoogleIds.has(google.id)) return;
  if (member.role.toLocaleLowerCase("en-US") !== REMOVABLE_TRYCOMP_ROLE) {
    input.warnings.push(
      `Trycomp member ${email} retains protected non-removable role ${member.role}`,
    );
    return;
  }
  if (!hasTrycompDeactivationSafety(member.user.role, member.fleetDmLabelId)) {
    input.warnings.push(
      `Trycomp member ${email} lacks device-free ordinary-platform-user deactivation evidence`,
    );
    return;
  }
  if (usesContractorAuthority(input, google)) {
    return {
      deactivationAuthority: "contractor_group",
      email,
      memberId: member.id,
      ...(!(observedEmail === email) && { providerEmail: observedEmail }),
      type: "deactivate",
    };
  }
  if (!isInactiveGoogleUser(google)) {
    input.errors.push(
      `Trycomp member ${email} lacks positive Google deactivation authority`,
    );
    return;
  }
  return {
    deactivationAuthority: "inactive_google",
    email,
    memberId: member.id,
    ...(!(observedEmail === email) && { providerEmail: observedEmail }),
    type: "deactivate",
  };
}

function usesContractorAuthority(
  input: PlanActionInput,
  google: GoogleDirectoryUser,
): boolean {
  return (
    input.contractorGoogleIds.has(google.id) &&
    !(input.offboardingOnly && isInactiveGoogleUser(google))
  );
}

function contractorGoogleIdSet(
  group: GoogleGroupSnapshot,
  googleByEmail: ReadonlyMap<string, GoogleDirectoryUser>,
  errors: string[],
): Set<string> {
  const ids = new Set<string>();
  for (const member of group.members) {
    if (member.type === "GROUP") {
      errors.push(
        `Nested contractor group ${normalizeEmail(member.email)} was not expanded`,
      );
      continue;
    }
    if (member.type !== "USER") continue;
    const google = googleByEmail.get(normalizeEmail(member.email));
    if (!google) {
      errors.push(
        `Contractor group member ${normalizeEmail(member.email)} has no Google identity`,
      );
      continue;
    }
    if (google.id !== member.id) {
      errors.push(
        `Contractor group member ${normalizeEmail(member.email)} has an immutable ID mismatch`,
      );
      continue;
    }
    ids.add(google.id);
    if (
      member.status !== "ACTIVE" &&
      !(member.status === "SUSPENDED" && google.suspended === true) &&
      !(member.status === "ARCHIVED" && google.archived === true)
    ) {
      errors.push(
        `Contractor group member ${normalizeEmail(member.email)} has ambiguous ${member.status} status`,
      );
    }
  }
  return ids;
}

function resolveProtectedGoogleIds(
  configuredIds: readonly string[],
  protectedEmails: ReadonlySet<string>,
  googleByEmail: ReadonlyMap<string, GoogleDirectoryUser>,
  googleById: ReadonlyMap<string, GoogleDirectoryUser>,
  errors: string[],
): Set<string> {
  const ids = new Set(configuredIds);
  for (const id of configuredIds) {
    if (!googleById.has(id))
      errors.push(`Protected Google identity ${id} is missing`);
  }
  for (const email of protectedEmails) {
    const google = googleByEmail.get(email);
    // Email-only protections also cover service identities that intentionally
    // exist in Trycomp but not in Google Workspace.
    if (google) ids.add(google.id);
  }
  return ids;
}

function desiredEmployeeEmails(
  users: readonly GoogleDirectoryUser[],
  contractorGoogleIds: ReadonlySet<string>,
  managedDomain: string,
): Set<string> {
  const managedSuffix = `@${managedDomain.toLocaleLowerCase("en-US")}`;
  return new Set(
    users.flatMap((user) => {
      const email = normalizeEmail(user.primaryEmail);
      const excluded =
        isInactiveGoogleUser(user) ||
        contractorGoogleIds.has(user.id) ||
        !email.endsWith(managedSuffix);
      return excluded ? [] : [email];
    }),
  );
}

interface IndexedTrycompMember {
  member: TrycompMember;
  observedEmail: string;
}

function trycompMemberIndex(input: {
  members: readonly TrycompMember[];
  desiredEmails: ReadonlySet<string>;
  googleByEmail: ReadonlyMap<string, GoogleDirectoryUser>;
  frozenGoogleIds: ReadonlySet<string>;
  contractorGoogleIds: ReadonlySet<string>;
  errors: string[];
  warnings: string[];
}): Map<string, IndexedTrycompMember> {
  const recordsByEmail = new Map<string, IndexedTrycompMember[]>();
  for (const member of input.members) {
    const observedEmail = normalizeEmail(member.user.email);
    const email = normalizeEmail(
      input.googleByEmail.get(observedEmail)?.primaryEmail ?? observedEmail,
    );
    const records = recordsByEmail.get(email) ?? [];
    records.push({ member, observedEmail });
    recordsByEmail.set(email, records);
  }
  const membersByEmail = new Map<string, IndexedTrycompMember>();
  for (const [email, records] of recordsByEmail) {
    const current =
      records.length === 1
        ? records[0]
        : currentMembershipWithHistoricalAlias({ ...input, email, records });
    if (current === undefined) {
      input.errors.push(`Trycomp returned duplicate member identity ${email}`);
    } else {
      membersByEmail.set(email, current);
      if (records.length > 1) {
        input.warnings.push(
          `Trycomp retains a verified deactivated historical alias for ${email}`,
        );
      }
    }
  }
  return membersByEmail;
}

function currentMembershipWithHistoricalAlias(input: {
  email: string;
  records: readonly IndexedTrycompMember[];
  desiredEmails: ReadonlySet<string>;
  googleByEmail: ReadonlyMap<string, GoogleDirectoryUser>;
  frozenGoogleIds: ReadonlySet<string>;
  contractorGoogleIds: ReadonlySet<string>;
}): IndexedTrycompMember | undefined {
  const google = input.googleByEmail.get(input.email);
  if (
    input.records.length !== 2 ||
    !input.desiredEmails.has(input.email) ||
    google?.isAdmin !== false ||
    google.isDelegatedAdmin !== false ||
    isInactiveGoogleUser(google) ||
    input.frozenGoogleIds.has(google.id) ||
    input.contractorGoogleIds.has(google.id)
  )
    return undefined;
  const current = input.records.find(
    ({ member, observedEmail }) =>
      observedEmail === input.email && member.isActive && !member.deactivated,
  );
  const historical = input.records.find((record) => record !== current);
  if (
    current === undefined ||
    historical === undefined ||
    historical.observedEmail === input.email ||
    historical.member.id === current.member.id ||
    input.googleByEmail.get(historical.observedEmail)?.id !== google.id ||
    current.member.role !== REMOVABLE_TRYCOMP_ROLE ||
    historical.member.role !== REMOVABLE_TRYCOMP_ROLE ||
    !hasTrycompDeactivationSafety(
      current.member.user.role,
      current.member.fleetDmLabelId,
    ) ||
    !isVerifiedDeviceFreeTrycompRevocation(historical.member)
  )
    return undefined;
  return current;
}

export function buildGoogleEmailIndex(
  users: readonly GoogleDirectoryUser[],
  errors: string[],
): Map<string, GoogleDirectoryUser> {
  const index = new Map<string, GoogleDirectoryUser>();
  const ambiguous = new Set<string>();
  for (const user of users) {
    for (const email of [
      user.primaryEmail,
      ...(user.aliases ?? []),
      ...(user.nonEditableAliases ?? []),
    ]) {
      const normalized = normalizeEmail(email);
      const existing = index.get(normalized);
      if (existing && existing.id !== user.id) {
        ambiguous.add(normalized);
        index.delete(normalized);
      } else if (!ambiguous.has(normalized)) {
        index.set(normalized, user);
      }
    }
  }
  for (const email of ambiguous)
    errors.push(`Google Directory identity ${email} is ambiguous`);
  return index;
}

function buildGoogleIdIndex(
  users: readonly GoogleDirectoryUser[],
  errors: string[],
): Map<string, GoogleDirectoryUser> {
  const index = new Map<string, GoogleDirectoryUser>();
  for (const user of users) {
    if (index.has(user.id))
      errors.push(
        `Google Directory returned duplicate immutable ID ${user.id}`,
      );
    else index.set(user.id, user);
  }
  return index;
}

function compareAction(left: TrycompAction, right: TrycompAction): number {
  return (
    ACTION_ORDER[left.type] - ACTION_ORDER[right.type] ||
    left.email.localeCompare(right.email)
  );
}

async function authorityBoundPlanHash(input: {
  activationDeniedEmails: ReadonlySet<string>;
  activeGoogleUserCount: number;
  actions: readonly TrycompAction[];
  offboardingOnly: boolean;
  contractorGroup: GoogleGroupSnapshot;
  expectedContractorGroupId: string;
  excludedGoogleUserIds: readonly string[];
  frozenGoogleIds: ReadonlySet<string>;
  googleUsers: readonly GoogleDirectoryUser[];
  managedDomain: string;
  minimumGoogleUsers: number;
  writeProtectedEmails: ReadonlySet<string>;
  writeProtectedGoogleUserIds: readonly string[];
  trycompMembers: readonly TrycompMember[];
}): Promise<string> {
  const evidence = {
    activationDeniedEmails: [...input.activationDeniedEmails].toSorted(
      (sortLeft, sortRight) =>
        Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
    ),
    activeGoogleUserCount: input.activeGoogleUserCount,
    actions: input.actions,
    contractorGroup: {
      email: normalizeEmail(input.contractorGroup.email),
      id: input.contractorGroup.id,
      members: input.contractorGroup.members
        .map((member) => ({
          email: normalizeEmail(member.email),
          id: member.id,
          role: member.role,
          status: member.status,
          type: member.type,
        }))
        .toSorted(
          (left, right) =>
            left.id.localeCompare(right.id) ||
            left.email.localeCompare(right.email),
        ),
    },
    expectedContractorGroupId: input.expectedContractorGroupId,
    excludedGoogleUserIds: [...input.excludedGoogleUserIds].toSorted(
      (sortLeft, sortRight) =>
        Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
    ),
    frozenGoogleIds: [...input.frozenGoogleIds].toSorted(
      (sortLeft, sortRight) =>
        Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
    ),
    googleUsers: input.googleUsers
      .map((user) => ({
        aliases: (user.aliases ?? []).map(normalizeEmail).toSorted(),
        archived: user.archived ?? false,
        deletionTime: user.deletionTime ?? null,
        id: user.id,
        isAdmin: user.isAdmin ?? null,
        isDelegatedAdmin: user.isDelegatedAdmin ?? null,
        nonEditableAliases: (user.nonEditableAliases ?? [])
          .map(normalizeEmail)
          .toSorted(),
        primaryEmail: normalizeEmail(user.primaryEmail),
        suspended: user.suspended ?? false,
      }))
      .toSorted((left, right) => left.id.localeCompare(right.id)),
    managedDomain: input.managedDomain.toLocaleLowerCase("en-US"),
    minimumGoogleUsers: input.minimumGoogleUsers,
    policyVersion: 6,
    offboardingOnly: input.offboardingOnly,
    writeProtectedEmails: [...input.writeProtectedEmails].toSorted(
      (sortLeft, sortRight) =>
        Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
    ),
    writeProtectedGoogleUserIds: [
      ...input.writeProtectedGoogleUserIds,
    ].toSorted(
      (sortLeft, sortRight) =>
        Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
    ),
    trycompMembers: input.trycompMembers
      .map((member) => ({
        deactivated: member.deactivated,
        fleetDmLabelId: member.fleetDmLabelId,
        platformRole: member.user.role,
        email: normalizeEmail(member.user.email),
        id: member.id,
        isActive: member.isActive,
        role: member.role,
      }))
      .toSorted((left, right) => left.id.localeCompare(right.id)),
  };
  return sha256(JSON.stringify(evidence));
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}
