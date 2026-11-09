import { normalizeIdentityEmail } from "../identity-sync/normalize-identity-email.ts";
import {
  type GoogleDirectoryUser,
  isActiveGoogleDirectoryUser,
} from "../org-sync/model.ts";

export function indexNamedActiveGoogleUsers(
  users: readonly GoogleDirectoryUser[],
  duplicateIdentity: () => Error,
): Map<string, GoogleDirectoryUser> {
  const index = new Map<string, GoogleDirectoryUser>();
  for (const user of users) {
    if (!isActiveGoogleDirectoryUser(user) || !user.name?.fullName?.trim())
      continue;
    for (const rawEmail of [
      user.primaryEmail,
      ...(user.aliases ?? []),
      ...(user.nonEditableAliases ?? []),
    ]) {
      const email = normalizeIdentityEmail(rawEmail);
      const existing = index.get(email);
      if (existing !== undefined && existing.id !== user.id)
        throw duplicateIdentity();
      index.set(email, user);
    }
  }
  return index;
}
