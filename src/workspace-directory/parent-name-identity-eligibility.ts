import { GoogleUserIdSchema } from "../catalog/identity-authority.ts";
import { protectedIdentityBlocker } from "../identity-provisioning/protected-identity-blocker.ts";
import { orgSyncSettings } from "../org-sync/config.ts";
import {
  type GoogleDirectoryUser,
  isActiveGoogleDirectoryUser,
} from "../org-sync/model.ts";

export type ParentNameEligibility =
  | "authority-drifted"
  | "eligible"
  | "missing-evidence"
  | "protected";

export function parentNameIdentityEligibility(
  users: readonly GoogleDirectoryUser[],
  action: { googleUserId: string; email: string },
  desiredName: string,
): ParentNameEligibility {
  const matches = users.filter(({ id }) => id === action.googleUserId);
  const user = matches[0];
  if (
    matches.length !== 1 ||
    user === undefined ||
    !GoogleUserIdSchema.safeParse(user.id).success
  )
    return "missing-evidence";
  if (
    !isActiveGoogleDirectoryUser(user) ||
    user.name?.fullName?.trim() !== desiredName
  )
    return "authority-drifted";
  if (orgSyncSettings().protectedDepartedGoogleUserIds.includes(user.id))
    return "protected";
  const aliases = [...(user.aliases ?? []), ...(user.nonEditableAliases ?? [])];
  if (
    ![user.primaryEmail, ...aliases].some(
      (email) => email.trim().toLowerCase() === action.email,
    )
  )
    return "authority-drifted";
  const blocker = protectedIdentityBlocker({
    googleUserId: user.id,
    primaryEmail: user.primaryEmail,
    aliases,
    isAdmin: user.isAdmin,
    isDelegatedAdmin: user.isDelegatedAdmin,
  });
  if (blocker === undefined) return "eligible";
  return blocker.startsWith("Complete Google")
    ? "missing-evidence"
    : "protected";
}
