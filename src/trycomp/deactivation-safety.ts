import { isTrycompMembershipDeactivated } from "./is-trycomp-membership-deactivated.ts";
import type { TrycompMember } from "./model.ts";

export function hasTrycompDeactivationSafety(
  platformRole: unknown,
  fleetDmLabelId: unknown,
): boolean {
  return platformRole === "user" && fleetDmLabelId === null;
}

export function isVerifiedDeviceFreeTrycompRevocation(
  member: TrycompMember,
): boolean {
  return (
    isTrycompMembershipDeactivated(member) &&
    hasTrycompDeactivationSafety(member.user.role, member.fleetDmLabelId)
  );
}
