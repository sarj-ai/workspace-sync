import { normalizeIdentityEmail as normalizeEmail } from "../identity-sync/normalize-identity-email.ts";
import type {
  GoogleGroupMember,
  GoogleGroupSnapshot,
} from "./channel-model.ts";

const MAX_NESTED_GROUP_DEPTH = 10;

export function flattenGoogleGroups(
  rootGroupEmails: readonly string[],
  groups: readonly GoogleGroupSnapshot[],
): GoogleGroupSnapshot[] {
  const groupsByEmail = new Map(
    groups.map((group) => [normalizeEmail(group.email), group]),
  );
  const roots = rootGroupEmails.map((email) => {
    const normalizedEmail = normalizeEmail(email);
    const group = groupsByEmail.get(normalizedEmail);
    if (!group)
      throw new Error(`Required Google group ${normalizedEmail} is missing`);
    return group;
  });
  validateNestedGoogleGroupGraph(roots, groupsByEmail);
  const flattenedMembersByEmail = new Map<string, GoogleGroupMember[]>();

  return roots.map((group) => ({
    ...group,
    members: flattenGoogleGroupMembers(
      group.email,
      groupsByEmail,
      flattenedMembersByEmail,
    ),
  }));
}

function validateNestedGoogleGroupGraph(
  roots: readonly GoogleGroupSnapshot[],
  groupsByEmail: ReadonlyMap<string, GoogleGroupSnapshot>,
): void {
  const validatedDepthByEmail = new Map<string, number>();
  for (const root of roots) {
    validateNestedGoogleGroup(
      root.email,
      [],
      groupsByEmail,
      validatedDepthByEmail,
    );
  }
}

function validateNestedGoogleGroup(
  groupEmail: string,
  path: readonly string[],
  groupsByEmail: ReadonlyMap<string, GoogleGroupSnapshot>,
  validatedDepthByEmail: Map<string, number>,
): void {
  const normalizedEmail = normalizeEmail(groupEmail);
  assertNestedGroupTraversal(normalizedEmail, path);
  const validatedDepth = validatedDepthByEmail.get(normalizedEmail);
  if (validatedDepth !== undefined && validatedDepth >= path.length) return;
  const group = groupsByEmail.get(normalizedEmail);
  if (!group)
    throw new Error(`Nested Google group ${normalizedEmail} is missing`);
  for (const member of group.members) {
    if (member.type === "USER") continue;
    if (member.type === "CUSTOMER") {
      throw new Error(
        `Google group ${normalizedEmail} contains unsupported CUSTOMER membership`,
      );
    }
    if (member.status === "ARCHIVED" || member.status === "SUSPENDED") {
      throw new Error(
        `Nested Google group ${normalizeEmail(member.email)} is ${member.status} in ${normalizedEmail}`,
      );
    }
    validateNestedGoogleGroup(
      member.email,
      [...path, normalizedEmail],
      groupsByEmail,
      validatedDepthByEmail,
    );
  }
  validatedDepthByEmail.set(normalizedEmail, path.length);
}

function assertNestedGroupTraversal(
  groupEmail: string,
  path: readonly string[],
): void {
  const cycleStart = path.indexOf(groupEmail);
  if (cycleStart >= 0) {
    throw new Error(
      `Nested Google group cycle: ${[...path.slice(cycleStart), groupEmail].join(" -> ")}`,
    );
  }
  if (path.length >= MAX_NESTED_GROUP_DEPTH) {
    throw new Error(
      `Nested Google group ${groupEmail} exceeded depth ${String(MAX_NESTED_GROUP_DEPTH)}`,
    );
  }
}

function flattenGoogleGroupMembers(
  groupEmail: string,
  groupsByEmail: ReadonlyMap<string, GoogleGroupSnapshot>,
  flattenedMembersByEmail: Map<string, GoogleGroupMember[]>,
): GoogleGroupMember[] {
  const normalizedEmail = normalizeEmail(groupEmail);
  const cached = flattenedMembersByEmail.get(normalizedEmail);
  if (cached) return cached;
  const group = groupsByEmail.get(normalizedEmail);
  if (!group)
    throw new Error(`Nested Google group ${normalizedEmail} is missing`);

  const membersByEmail = new Map<string, GoogleGroupMember>();
  for (const member of group.members) {
    if (member.type === "USER") {
      retainPreferredMember(membersByEmail, member);
      continue;
    }
    if (member.type === "CUSTOMER") {
      throw new Error("Unsupported Google CUSTOMER group membership");
    }
    for (const nestedMember of flattenGoogleGroupMembers(
      member.email,
      groupsByEmail,
      flattenedMembersByEmail,
    )) {
      retainPreferredMember(membersByEmail, {
        ...nestedMember,
        role: "MEMBER",
      });
    }
  }
  const flattenedMembers = membersByEmail.values().toArray();
  flattenedMembersByEmail.set(normalizedEmail, flattenedMembers);
  return flattenedMembers;
}

function retainPreferredMember(
  membersByEmail: Map<string, GoogleGroupMember>,
  candidate: GoogleGroupMember,
): void {
  const email = normalizeEmail(candidate.email);
  const current = membersByEmail.get(email);
  if (!current || memberPreference(candidate) > memberPreference(current)) {
    membersByEmail.set(email, candidate);
  }
}

function memberPreference(member: GoogleGroupMember): number {
  if (member.status === "ARCHIVED" || member.status === "SUSPENDED") return 0;
  if (member.role === "OWNER") return 3;
  if (member.role === "MANAGER") return 2;
  return 1;
}
