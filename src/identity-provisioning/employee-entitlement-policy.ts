import { getWorkspaceSyncPolicy } from "../configuration.ts";
import { normalizeIdentityEmail } from "../identity-sync/normalize-identity-email.ts";
import { sha256 } from "../runtime/sha256.ts";

export interface EmployeeEntitlementAuthority {
  readonly complete: boolean;
  readonly excludedEmails: readonly string[];
  readonly excludedGoogleUserIds: readonly string[];
  readonly fingerprint: string;
  readonly groupEmail: string;
  readonly groupId: string;
}

interface ContractorGroupAuthorityInput {
  readonly email: string;
  readonly id: string;
  readonly members: readonly {
    readonly email?: string;
    readonly id: string;
    readonly role?: "MANAGER" | "MEMBER" | "OWNER";
    readonly status?: "ACTIVE" | "ARCHIVED" | "SUSPENDED" | "UNKNOWN";
    readonly type: "CUSTOMER" | "GROUP" | "USER";
  }[];
}

export async function buildEmployeeEntitlementAuthority(
  group: ContractorGroupAuthorityInput,
): Promise<EmployeeEntitlementAuthority> {
  const groupEmail = normalizeIdentityEmail(group.email);
  const authorityEmails: readonly string[] =
    contractorAuthorityGroup().acceptedEmails;
  if (
    group.id !== contractorAuthorityGroup().id ||
    !authorityEmails.includes(groupEmail)
  ) {
    throw new Error("contractor_authority_identity_mismatch");
  }
  // Google Groups uses OWNER and MANAGER for group administration. Those
  // records must not grant or revoke contractor entitlements: only an explicit
  // MEMBER record identifies a contractor subject.
  const contractorMembers = group.members.filter(
    (member) => member.type === "USER" && member.role === "MEMBER",
  );
  if (group.members.some((member) => member.type === "GROUP")) {
    throw new Error("contractor_authority_nested_group_unsupported");
  }
  if (group.members.some((member) => member.type !== "USER")) {
    throw new Error("contractor_authority_member_type_unsupported");
  }
  if (
    group.members.some(
      (member) => member.type === "USER" && member.role === undefined,
    )
  ) {
    throw new Error("contractor_authority_member_role_missing");
  }
  // Known inactive members remain contractor exclusions; lifecycle transitions must not invalidate this deny authority.
  if (
    group.members.some(
      (member) =>
        (member.status !== "ACTIVE" &&
          member.status !== "SUSPENDED" &&
          member.status !== "ARCHIVED") ||
        member.email === undefined ||
        member.email.trim() === "",
    )
  ) {
    throw new Error("contractor_authority_member_incomplete");
  }
  const dynamicEmails = contractorMembers.map((member) =>
    normalizeIdentityEmail(member.email ?? ""),
  );
  const excludedEmailSet = new Set<string>(employeeEntitlementExcludedEmails());
  for (const email of dynamicEmails) excludedEmailSet.add(email);
  const excludedEmails = [...excludedEmailSet].toSorted(
    (sortLeft, sortRight) =>
      Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
  );
  const excludedGoogleUserIds = [
    ...new Set(contractorMembers.map((member) => member.id)),
  ].toSorted(
    (sortLeft, sortRight) =>
      Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
  );
  const fingerprint = await sha256(
    JSON.stringify({
      excludedEmails,
      excludedGoogleUserIds,
      groupEmail: contractorAuthorityGroup().email,
      groupId: contractorAuthorityGroup().id,
    }),
  );
  return {
    complete: true,
    excludedEmails,
    excludedGoogleUserIds,
    fingerprint,
    groupEmail: contractorAuthorityGroup().email,
    groupId: contractorAuthorityGroup().id,
  };
}

export function bootstrapEmployeeEntitlementAuthority(): EmployeeEntitlementAuthority {
  return {
    complete: false,
    excludedEmails: [...employeeEntitlementExcludedEmails()],
    excludedGoogleUserIds: [],
    fingerprint: "bootstrap-employee-entitlement-authority",
    groupEmail: contractorAuthorityGroup().email,
    groupId: contractorAuthorityGroup().id,
  };
}

/* Bootstrap exclusions are a deny floor, never proof that employee grants are safe. */
export function hasCompleteEmployeeEntitlementAuthority(
  authority: EmployeeEntitlementAuthority | undefined,
): boolean {
  return (
    authority?.complete === true &&
    authority.groupId === contractorAuthorityGroup().id &&
    contractorAuthorityGroup().acceptedEmails.some(
      (email) => email === normalizeIdentityEmail(authority.groupEmail),
    ) &&
    /^[a-f0-9]{64}$/u.test(authority.fingerprint)
  );
}

export function isEmployeeEntitlementExcluded(
  primaryEmail: string,
  googleUserId?: string,
  authority: EmployeeEntitlementAuthority = bootstrapEmployeeEntitlementAuthority(),
  aliases: readonly string[] = [],
): boolean {
  const identityEmails = new Set(
    [primaryEmail, ...aliases].map(normalizeIdentityEmail),
  );
  return (
    employeeEntitlementExcludedEmails().some((email) =>
      identityEmails.has(email),
    ) ||
    authority.excludedEmails.some((email) =>
      identityEmails.has(normalizeIdentityEmail(email)),
    ) ||
    (googleUserId !== undefined &&
      authority.excludedGoogleUserIds.includes(googleUserId))
  );
}

export function contractorAuthorityGroup() {
  return getWorkspaceSyncPolicy().contractorAuthorityGroup;
}
export function employeeEntitlementExcludedEmails() {
  return getWorkspaceSyncPolicy().employeeEntitlementExcludedEmails;
}
