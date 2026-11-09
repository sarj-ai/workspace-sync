import { z } from "zod";

import { contentHash } from "../github-access-audit/content-hash.ts";
import type { OperationDiagnostic } from "../operations/schemas.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import type { GitHubDeprovisionGoogleAuthoritySnapshotSchema } from "./github-deprovision-google-authority-contract.ts";
import { protectedIdentityBlocker } from "./protected-identity-blocker.ts";

export type GoogleDeprovisionAuthoritySnapshot = z.output<
  typeof GitHubDeprovisionGoogleAuthoritySnapshotSchema
>;
const DeletionTimeSchema = z.iso.datetime({ offset: true });

/* Validates global identity uniqueness and deleted-user evidence for deprovision planners. */
export function validateGoogleDeprovisionAuthority(
  snapshot: GoogleDeprovisionAuthoritySnapshot,
): OperationDiagnostic[] {
  const diagnostics: OperationDiagnostic[] = [];
  const identities = [...snapshot.users, ...snapshot.deletedUsers];
  findDuplicateValues(
    identities.map(({ id }) => id),
    "duplicate_google_user_id",
    "Google immutable user ID",
    diagnostics,
  );
  const emailOwners = new Map<string, string>();
  for (const user of identities) {
    if (
      snapshot.deletedUsers.includes(user) &&
      !DeletionTimeSchema.safeParse(user.deletionTime).success
    ) {
      diagnostics.push({
        code: "google_deleted_user_invalid",
        message: `Deleted Google immutable user ${user.id} lacks a valid deletion timestamp.`,
        severity: "blocker",
      });
    }
    for (const email of googleDeprovisionIdentityEmails(user)) {
      recordOwner(emailOwners, email, user.id, diagnostics);
    }
  }
  return diagnostics;
}

/* Resolves only the exact immutable ID across the complete live and deleted inventories. */
export function resolveGoogleDeprovisionTarget(
  snapshot: GoogleDeprovisionAuthoritySnapshot,
  googleUserId: string,
  diagnostics: OperationDiagnostic[],
): GoogleDirectoryUser | null {
  const matches = [...snapshot.users, ...snapshot.deletedUsers].filter(
    ({ id }) => id === googleUserId,
  );
  if (matches.length === 0) {
    diagnostics.push({
      code: "google_identity_missing",
      message: `Immutable Google Directory user ${googleUserId} is absent from the complete live and deleted-user inventories.`,
      severity: "blocker",
    });
  }
  const target = matches.length === 1 ? (matches[0] ?? null) : null;
  if (target !== null) {
    const protection = protectedIdentityBlocker({
      aliases: [
        ...(target.aliases ?? []),
        ...(target.nonEditableAliases ?? []),
      ],
      googleUserId: target.id,
      isAdmin: target.isAdmin,
      isDelegatedAdmin: target.isDelegatedAdmin,
      primaryEmail: target.primaryEmail,
    });
    if (protection !== undefined) {
      diagnostics.push({
        code: "protected_google_identity",
        message: protection,
        severity: "blocker",
      });
      return null;
    }
  }
  return target;
}

/* Hashes a canonical inventory projection so source ordering cannot change plan identity. */
export async function fingerprintGoogleDeprovisionAuthority(
  snapshot: GoogleDeprovisionAuthoritySnapshot,
): Promise<string> {
  return contentHash(canonicalGoogleDeprovisionAuthority(snapshot));
}

export function canonicalGoogleDeprovisionAuthority(
  snapshot: GoogleDeprovisionAuthoritySnapshot,
) {
  return {
    deletedUsers: snapshot.deletedUsers
      .map(canonicalGoogleUser)
      .toSorted(compareGoogleUser),
    users: snapshot.users.map(canonicalGoogleUser).toSorted(compareGoogleUser),
  };
}

export function googleDeprovisionIdentityEmails(
  user: GoogleDirectoryUser,
): Set<string> {
  return new Set(
    [
      user.primaryEmail,
      ...(user.aliases ?? []),
      ...(user.nonEditableAliases ?? []),
    ].map((email) => email.toLowerCase()),
  );
}

function canonicalGoogleUser<User extends GoogleDirectoryUser>(
  user: User,
): User {
  return {
    ...user,
    ...(!(user.aliases === undefined) && { aliases: user.aliases.toSorted() }),
    ...(!(user.nonEditableAliases === undefined) && {
      nonEditableAliases: user.nonEditableAliases.toSorted(),
    }),
  };
}

function compareGoogleUser(
  left: GoogleDirectoryUser,
  right: GoogleDirectoryUser,
): number {
  return `${left.id}:${left.primaryEmail}`.localeCompare(
    `${right.id}:${right.primaryEmail}`,
  );
}

function findDuplicateValues(
  values: readonly string[],
  code: string,
  label: string,
  diagnostics: OperationDiagnostic[],
): void {
  const seen = new Set<string>();
  const reported = new Set<string>();
  for (const value of values) {
    if (seen.has(value) && !reported.has(value)) {
      diagnostics.push({
        code,
        message: `${label} ${value} occurs more than once in the complete Google authority inventory.`,
        severity: "blocker",
      });
      reported.add(value);
    }
    seen.add(value);
  }
}

function recordOwner(
  owners: Map<string, string>,
  value: string,
  googleUserId: string,
  diagnostics: OperationDiagnostic[],
): void {
  const owner = owners.get(value);
  if (owner !== undefined && owner !== googleUserId) {
    diagnostics.push({
      code: "duplicate_google_user_email",
      message: `Google identity email ${value} belongs to multiple immutable Google users.`,
      severity: "blocker",
    });
    return;
  }
  owners.set(value, googleUserId);
}
