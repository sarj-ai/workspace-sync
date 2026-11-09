import type { TrycompMember } from "./model.ts";

export function isTrycompMembershipDeactivated(
  member: Pick<TrycompMember, "deactivated" | "isActive">,
): boolean {
  return !member.isActive && member.deactivated;
}
