import { normalizeIdentityEmail } from "../identity-sync/normalize-identity-email.ts";
import type { GoogleDirectoryUser } from "./model.ts";

/*
 * Combines live and explicitly deleted Directory records into one immutable-ID authority snapshot.
 * Conflicting records fail closed instead of choosing whichever response happened to arrive last.
 */
export function mergeGoogleDirectoryAuthority(
  activeUsers: readonly GoogleDirectoryUser[],
  deletedUsers: readonly GoogleDirectoryUser[],
): GoogleDirectoryUser[] {
  const usersById = new Map<string, GoogleDirectoryUser>();
  for (const user of activeUsers)
    addGoogleAuthorityUser(usersById, user, "active");
  for (const user of deletedUsers)
    addGoogleAuthorityUser(usersById, user, "deleted");
  return usersById
    .values()
    .toArray()
    .toSorted((left, right) => left.id.localeCompare(right.id));
}

export function googleAuthorityFingerprintRecord(user: GoogleDirectoryUser) {
  return {
    archived: user.archived ?? false,
    aliases: (user.aliases ?? []).map(normalizeIdentityEmail).toSorted(),
    deletionTime: user.deletionTime ?? "",
    githubLogin: user.customSchemas?.SarjIdentity?.githubLogin ?? "",
    githubUserId: user.customSchemas?.SarjIdentity?.githubUserId ?? "",
    id: user.id,
    isAdmin: user.isAdmin ?? null,
    isDelegatedAdmin: user.isDelegatedAdmin ?? null,
    nonEditableAliases: (user.nonEditableAliases ?? [])
      .map(normalizeIdentityEmail)
      .toSorted(),
    primaryEmail: normalizeIdentityEmail(user.primaryEmail),
    suspended: user.suspended ?? false,
  };
}

function addGoogleAuthorityUser(
  usersById: Map<string, GoogleDirectoryUser>,
  user: GoogleDirectoryUser,
  source: "active" | "deleted",
): void {
  if (source === "deleted" && user.deletionTime === undefined) {
    throw new Error(
      `workspace_directory_deleted_user_missing_deletion_time:${user.id}`,
    );
  }
  const existing = usersById.get(user.id);
  if (!existing) {
    usersById.set(user.id, user);
    return;
  }
  const existingRecord = JSON.stringify(
    googleAuthorityFingerprintRecord(existing),
  );
  const candidateRecord = JSON.stringify(
    googleAuthorityFingerprintRecord(user),
  );
  if (existingRecord !== candidateRecord) {
    throw new Error(`workspace_directory_google_identity_conflict:${user.id}`);
  }
}
