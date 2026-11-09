import { normalizeIdentityEmail as normalize } from "../identity-sync/normalize-identity-email.ts";
import type {
  GoogleAuditMembership,
  GoogleAuditUser,
} from "./google-contracts.ts";

export function indexGoogleUsers(
  users: GoogleAuditUser[],
): Map<string, GoogleAuditUser> {
  const result = new Map<string, GoogleAuditUser>();
  const ambiguous = new Set<string>();
  for (const user of users) {
    for (const email of [user.primaryEmail, ...user.aliases]) {
      const key = normalize(email);
      const existing = result.get(key);
      if (ambiguous.has(key)) continue;
      if (existing && existing.id !== user.id) {
        result.delete(key);
        ambiguous.add(key);
      } else {
        result.set(key, user);
      }
    }
  }
  return result;
}

export function indexMemberships(
  memberships: GoogleAuditMembership[],
): Map<string, GoogleAuditMembership[]> {
  const result = new Map<string, GoogleAuditMembership[]>();
  for (const membership of memberships) {
    result.set(membership.groupId, [
      ...(result.get(membership.groupId) ?? []),
      membership,
    ]);
  }
  return result;
}

export function expandGroupUsers(
  groupId: string,
  index: Map<string, GoogleAuditMembership[]>,
  seen: Set<string>,
): Set<string> {
  if (seen.has(groupId)) return new Set();
  seen.add(groupId);
  const users = new Set<string>();
  const members = index.get(groupId);
  if (!members) return users;
  for (const member of members) {
    if (member.memberType === "USER") users.add(normalize(member.memberEmail));
    else
      for (const nested of expandGroupUsers(member.memberId, index, seen))
        users.add(nested);
  }
  return users;
}
