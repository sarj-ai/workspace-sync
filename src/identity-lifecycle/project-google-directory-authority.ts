import {
  type AuthorityIdentity,
  AuthorityIdentitySchema,
} from "../catalog/identity-authority.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import { authoritativeGoogleDirectoryUserState } from "./contracts.ts";

export function projectGoogleDirectoryAuthority(
  user: GoogleDirectoryUser,
  observedAt: string,
): AuthorityIdentity {
  const state = authoritativeGoogleDirectoryUserState(user);
  const identity = user.customSchemas?.SarjIdentity;
  const github =
    identity?.githubLogin !== undefined && identity.githubUserId !== undefined
      ? {
          githubLogin: identity.githubLogin,
          githubUserId: identity.githubUserId,
          kind: "verified" as const,
          verifiedAt: observedAt,
        }
      : { kind: "unlinked" as const };
  return AuthorityIdentitySchema.parse({
    aliases: [
      ...new Set(
        [...(user.aliases ?? []), ...(user.nonEditableAliases ?? [])].map(
          (email) => email.toLowerCase(),
        ),
      ),
    ].toSorted(
      (sortLeft, sortRight) =>
        Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
    ),
    authorityRevision: `google-directory:${user.id}:${user.etag ?? observedAt}`,
    github,
    googleUserId: user.id,
    isAdmin: user.isAdmin,
    isDelegatedAdmin: user.isDelegatedAdmin,
    lifecycle: { kind: state.state },
    observedAt,
    primaryEmail:
      state.state === "deleted"
        ? (state.lastKnownPrimaryEmail ?? user.primaryEmail)
        : state.primaryEmail,
  });
}
