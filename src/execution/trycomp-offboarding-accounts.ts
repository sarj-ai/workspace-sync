import { DownstreamAccountSchema } from "../access-guard/model.ts";
import { isTrycompMembershipDeactivated } from "../trycomp/is-trycomp-membership-deactivated.ts";
import type { TrycompMember } from "../trycomp/model.ts";

export function trycompOffboardingAccounts(members: readonly TrycompMember[]) {
  return members.map((member) => {
    if (member.isActive && member.deactivated)
      throw new Error("offboarding_provider_state_conflict");
    return DownstreamAccountSchema.parse({
      active: !isTrycompMembershipDeactivated(member),
      email: member.user.email,
      id: member.id,
    });
  });
}
