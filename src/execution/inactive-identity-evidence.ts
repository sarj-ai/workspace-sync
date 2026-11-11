import { z } from "zod";

import {
  GitHubLoginSchema,
  GitHubUserIdSchema,
  GoogleUserIdSchema,
} from "../catalog/identity-authority.ts";
import { runtimeFetch } from "../clients/runtime-fetch.ts";
import { getWorkspaceSyncPolicy } from "../configuration.ts";
import {
  GitHubAccessAuditClient,
  type GitHubIdentitySeedSnapshot,
} from "../github-access-audit/git-hub-access-audit-client.ts";
import { isInactiveGoogleUser } from "../google-workspace/user-lifecycle.ts";
import { GitHubIdentityLookupClient } from "../identity-sync/github-identity-admin-attestation.ts";
import { sha256Hex } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import { mergeGoogleDirectoryAuthority } from "../org-sync/google-directory-authority.ts";
import {
  DIRECTORY_READONLY_SCOPE,
  type GoogleDirectoryClient,
} from "../org-sync/google-directory-client.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import { mapSequential } from "../runtime/sequential.ts";
import type { WorkspaceSyncRuntimeBindings } from "./provider-runtime-ports.ts";
import type { WorkspaceRuntimeConfiguration as ValidatedEnv } from "./runtime-configuration.ts";

const EXPIRED = "inactive_github_identity_evidence_expired";
const GithubPairSchema = z.strictObject({
  githubUserId: GitHubUserIdSchema,
  githubLogin: GitHubLoginSchema,
});
const GithubProfileSchema = z.object({
  id: z.number().int().positive(),
  login: GitHubLoginSchema,
  type: z.literal("User"),
});
const PairSchema = z.strictObject({
  githubUserId: GitHubUserIdSchema,
  githubLogin: GitHubLoginSchema,
  nameIdMatch: z.enum(["primary", "alias"]),
  membership: z.enum(["current-member", "not-current-member"]),
});
const BlockerSchema = z.enum([
  "google_identity_ambiguous",
  "google_protected_or_unknown",
  "saml_missing",
  "saml_identity_incomplete",
  "saml_identity_ambiguous",
  "github_identity_mismatch",
  "github_protected_role",
  "github_identity_unavailable",
  "google_mapping_conflict",
]);
export const InactiveGithubIdentityEvidenceSchema = z.strictObject({
  diagnosticOnly: z.literal(true),
  writesAttempted: z.literal(0),
  observedAt: z.iso.datetime(),
  sourceComplete: z.boolean(),
  issues: z.array(
    z.enum([
      "source_incomplete",
      "inventory_below_floor",
      "duplicate_inventory_identity",
      "result_limit_exceeded",
      "google_authority_anchor_unverified",
    ]),
  ),
  sourceHash: z
    .string()
    .regex(/^[a-f0-9]{64}$/u)
    .nullable(),
  identities: z
    .array(
      z.strictObject({
        googleUserId: GoogleUserIdSchema,
        primaryEmail: z.email(),
        lifecycle: z.enum(["suspended", "archived", "deleted"]),
        accountAccess: z.literal("unknown"),
        blocker: BlockerSchema.nullable(),
        pairing: PairSchema.nullable(),
      }),
    )
    .max(100),
});
export type InactiveGithubIdentityEvidence = z.output<
  typeof InactiveGithubIdentityEvidenceSchema
>;
type Blocker = z.output<typeof BlockerSchema>;
type Pair = z.output<typeof PairSchema>;
type Saml = GitHubIdentitySeedSnapshot["samlExternalIdentities"][number];
// SAML identity evidence never proves absence of account access.
export async function inspectInactiveGithubIdentities(
  bindings: WorkspaceSyncRuntimeBindings,
  env: ValidatedEnv,
) {
  const google = bindings.google(
    "inactive_github_identity_evidence",
    DIRECTORY_READONLY_SCOPE,
  );
  return inspectInactiveGithubIdentitiesFromSources({
    google,
    resolveGithubUser: (login, deadline) =>
      new GitHubIdentityLookupClient({
        token: env.githubAccessAuditToken,
        fetchImpl: (input, init) => {
          const remaining = deadline - Date.now();
          if (remaining <= 0) throw new Error(EXPIRED);
          return runtimeFetch(input, {
            ...init,
            redirect: "manual",
            signal: AbortSignal.timeout(Math.min(15000, remaining)),
          });
        },
      }).resolveUser(login),
    github: new GitHubAccessAuditClient({
      organization: env.githubAccessAuditOrganization,
      token: env.githubAccessAuditToken,
    }),
  });
}
export async function inspectInactiveGithubIdentitiesFromSources(sources: {
  google: Pick<GoogleDirectoryClient, "listAllUsers" | "listDeletedUsers">;
  github: Pick<GitHubAccessAuditClient, "captureIdentitySeed">;
  resolveGithubUser(login: string, deadline: number): Promise<unknown>;
}) {
  const observedAt = new Date().toISOString();
  const deadline = Date.now() + 60000;
  const runId = crypto.randomUUID();
  const [users, deleted, github] = await Promise.all([
    sources.google.listAllUsers(runId, deadline),
    sources.google.listDeletedUsers(runId, deadline),
    sources.github.captureIdentitySeed(deadline),
  ]);
  if (Date.now() >= deadline) throw new Error(EXPIRED);
  const result = await projectInactiveGithubIdentities(
    mergeGoogleDirectoryAuthority(users, deleted),
    github,
    observedAt,
    (login) => sources.resolveGithubUser(login, deadline),
  );
  if (Date.now() >= deadline) throw new Error(EXPIRED);
  return result;
}
export async function projectInactiveGithubIdentities(
  users: readonly GoogleDirectoryUser[],
  github: GitHubIdentitySeedSnapshot,
  observedAt: string,
  resolveGithubUser: (login: string) => Promise<unknown>,
): Promise<InactiveGithubIdentityEvidence> {
  const base = {
    diagnosticOnly: true as const,
    writesAttempted: 0 as const,
    observedAt,
  };
  const inactive = users.filter(isInactiveGoogleUser);
  const issues: InactiveGithubIdentityEvidence["issues"] = [];
  if (github.errors.length > 0) issues.push("source_incomplete");
  if (!hasGoogleAuthorityAnchors(users))
    issues.push("google_authority_anchor_unverified");
  if (
    users.length < getWorkspaceSyncPolicy().org.minimumGoogleParticipants ||
    github.members.length === 0
  )
    issues.push("inventory_below_floor");
  if (inactive.length > 100) issues.push("result_limit_exceeded");
  if (
    duplicates(users.map(({ id }) => id)) ||
    duplicates(github.members.map(({ id }) => String(id))) ||
    duplicates(github.members.map(({ login }) => login.toLowerCase())) ||
    duplicates(github.samlExternalIdentities.map(({ guid }) => guid))
  )
    issues.push("duplicate_inventory_identity");
  if (issues.length > 0)
    return {
      ...base,
      sourceComplete: false,
      issues,
      sourceHash: null,
      identities: [],
    };
  const rows = await mapSequential(inactive, async (user) => {
    let result = pairingFor(user, users, github);
    if (result.pairing !== null)
      result = await verifyCurrentIdentity(result.pairing, resolveGithubUser);
    return {
      googleUserId: GoogleUserIdSchema.parse(user.id),
      primaryEmail: user.primaryEmail,
      lifecycle: lifecycle(user),
      accountAccess: "unknown" as const,
      ...result,
    };
  });
  const identities = rows.toSorted((a, b) =>
    a.googleUserId.localeCompare(b.googleUserId),
  );
  return InactiveGithubIdentityEvidenceSchema.parse({
    ...base,
    sourceComplete: true,
    issues: [],
    identities,
    sourceHash: await sha256Hex(
      JsonValueSchema.parse({
        users,
        members: github.members,
        saml: github.samlExternalIdentities,
        identities,
      }),
    ),
  });
}
function hasGoogleAuthorityAnchors(
  users: readonly GoogleDirectoryUser[],
): boolean {
  const rootsPresentAndActive =
    getWorkspaceSyncPolicy().org.expectedRootGoogleUserIds.every((id) => {
      const matches = users.filter((user) => user.id === id);
      return (
        matches.length === 1 &&
        matches.every((user) => !isInactiveGoogleUser(user))
      );
    });
  const adminSubjects = users.filter(
    (user) =>
      normalize(user.primaryEmail) ===
      normalize(getWorkspaceSyncPolicy().org.googleAdminSubject),
  );
  return (
    rootsPresentAndActive &&
    adminSubjects.length === 1 &&
    adminSubjects.every((user) => !isInactiveGoogleUser(user))
  );
}
function pairingFor(
  user: GoogleDirectoryUser,
  users: readonly GoogleDirectoryUser[],
  github: GitHubIdentitySeedSnapshot,
): {
  blocker: Blocker | null;
  pairing: null | Pair;
} {
  const blocked = (blocker: Blocker) => ({ blocker, pairing: null });
  if (
    user.isAdmin !== false ||
    user.isDelegatedAdmin !== false ||
    getWorkspaceSyncPolicy().org.expectedRootGoogleUserIds.some(
      (id) => id === user.id,
    )
  )
    return blocked("google_protected_or_unknown");
  const emails = names(user);
  if (
    users.some(
      (other) =>
        other.id !== user.id &&
        names(other).some((email) => emails.includes(email)),
    )
  )
    return blocked("google_identity_ambiguous");
  const identities = github.samlExternalIdentities.filter(
    (candidate) =>
      candidate.nameId !== null && emails.includes(normalize(candidate.nameId)),
  );
  if (identities.length === 0) return blocked("saml_missing");
  if (identities.length !== 1) return blocked("saml_identity_ambiguous");
  const identity = identities[0];
  if (identity === undefined) return blocked("saml_missing");
  const pair = parseSaml(identity);
  if (pair === null) return blocked("saml_identity_incomplete");
  if (
    github.samlExternalIdentities.some(
      (other) =>
        other !== identity &&
        (other.databaseId === identity.databaseId ||
          other.login?.toLowerCase() === pair.githubLogin),
    )
  )
    return blocked("saml_identity_ambiguous");
  const matchingMembers = github.members.filter(
    (member) =>
      String(member.id) === pair.githubUserId ||
      member.login.toLowerCase() === pair.githubLogin,
  );
  if (
    matchingMembers.some(
      (member) =>
        String(member.id) !== pair.githubUserId ||
        member.login.toLowerCase() !== pair.githubLogin,
    )
  )
    return blocked("github_identity_mismatch");
  if (
    matchingMembers.some(
      (member) => member.role !== "member" || member.type !== "User",
    )
  )
    return blocked("github_protected_role");
  if (mappingConflicts(user, users, pair))
    return blocked("google_mapping_conflict");
  return {
    blocker: null,
    pairing: {
      ...pair,
      nameIdMatch:
        normalize(identity.nameId ?? "") === normalize(user.primaryEmail)
          ? "primary"
          : "alias",
      membership:
        matchingMembers.length === 1 ? "current-member" : "not-current-member",
    },
  };
}
function parseSaml(identity: Saml) {
  const parsed = GithubPairSchema.safeParse({
    githubUserId:
      Number.isSafeInteger(identity.databaseId) &&
      (identity.databaseId ?? 0) > 0
        ? String(identity.databaseId)
        : null,
    githubLogin: identity.login,
  });
  return parsed.success ? parsed.data : null;
}
function mappingConflicts(
  user: GoogleDirectoryUser,
  users: readonly GoogleDirectoryUser[],
  pair: {
    githubUserId: string;
    githubLogin: string;
  },
) {
  return users.some((other) => {
    const mapping = other.customSchemas?.SarjIdentity;
    if (
      mapping?.githubUserId === undefined &&
      mapping?.githubLogin === undefined
    )
      return false;
    if (other.id === user.id)
      return (
        mapping.githubUserId !== pair.githubUserId ||
        mapping.githubLogin?.toLowerCase() !== pair.githubLogin
      );
    return (
      mapping.githubUserId === pair.githubUserId ||
      mapping.githubLogin?.toLowerCase() === pair.githubLogin
    );
  });
}
function names(user: GoogleDirectoryUser) {
  return [
    ...new Set(
      [
        user.primaryEmail,
        ...(user.aliases ?? []),
        ...(user.nonEditableAliases ?? []),
      ].map(normalize),
    ),
  ];
}
function normalize(value: string) {
  return value.trim().toLowerCase();
}
function duplicates(values: readonly string[]) {
  return new Set(values).size !== values.length;
}
async function verifyCurrentIdentity(
  pairing: Pair,
  resolve: (login: string) => Promise<unknown>,
): Promise<{
  blocker: Blocker | null;
  pairing: null | Pair;
}> {
  try {
    const profile = GithubProfileSchema.parse(
      await resolve(pairing.githubLogin),
    );
    if (
      String(profile.id) !== pairing.githubUserId ||
      profile.login !== pairing.githubLogin
    )
      return { blocker: "github_identity_mismatch", pairing: null };
    return { blocker: null, pairing };
  } catch {
    return { blocker: "github_identity_unavailable", pairing: null };
  }
}
function lifecycle(
  user: GoogleDirectoryUser,
): "archived" | "deleted" | "suspended" {
  if (user.deletionTime !== undefined) return "deleted";
  return user.archived ? "archived" : "suspended";
}
