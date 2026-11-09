import { dequal } from "dequal";

import { GoogleUserIdSchema } from "../catalog/identity-authority.ts";
import { normalizeIdentityEmail } from "../identity-sync/normalize-identity-email.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import type {
  TrycompPlan,
  TrycompReviewedPlan,
  TrycompSelectedIdentity,
} from "./model.ts";
import { buildGoogleEmailIndex } from "./plan.ts";

export function selectedTrycompIdentity(
  plan: TrycompPlan,
  users: readonly GoogleDirectoryUser[],
): TrycompSelectedIdentity | undefined {
  if (plan.errors.length > 0 || plan.actions.length !== 1) return undefined;
  const action = plan.actions[0];
  if (action === undefined) return undefined;
  const errors: string[] = [];
  const index = buildGoogleEmailIndex(users, errors);
  const user = index.get(normalizeIdentityEmail(action.email));
  const id = GoogleUserIdSchema.safeParse(user?.id);
  if (
    errors.length > 0 ||
    !id.success ||
    user?.isAdmin !== false ||
    user.isDelegatedAdmin !== false
  )
    return undefined;
  return {
    googleUserId: id.data,
    provider:
      action.type === "invite"
        ? { kind: "pending-invitation", email: action.email }
        : {
            kind: "member",
            memberId: action.memberId,
            email: action.providerEmail ?? action.email,
          },
  };
}

export function assertTrycompSelectedIdentity(
  reviewed: TrycompReviewedPlan,
  users: readonly GoogleDirectoryUser[],
): void {
  const actual = selectedTrycompIdentity(reviewed.plan, users);
  if (
    reviewed.selectedIdentity === undefined ||
    actual === undefined ||
    !dequal(actual, reviewed.selectedIdentity)
  )
    throw new Error("trycomp_reviewed_identity_missing_or_changed");
}

/* Historical v1 callers did not sign the additive identity pin. Only those inputs use legacy equality. */
export function sameReviewedTrycompPlan(
  reviewed: TrycompReviewedPlan,
  fresh: TrycompReviewedPlan,
): boolean {
  if (reviewed.selectedIdentity !== undefined) return dequal(reviewed, fresh);
  const { selectedIdentity: _pin, ...legacyFresh } = fresh;
  return dequal(reviewed, legacyFresh);
}

export function trycompManagedSlice(
  reviewed: TrycompReviewedPlan,
  state: "converged" | "drifted" | "pending",
) {
  return reviewed.selectedIdentity === undefined
    ? { state }
    : { state, selectedIdentity: reviewed.selectedIdentity };
}
