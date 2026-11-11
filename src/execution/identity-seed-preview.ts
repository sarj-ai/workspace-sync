import { z } from "zod";

import { GitHubAccessAuditClient } from "../github-access-audit/git-hub-access-audit-client.ts";
import {
  GoogleGithubIdentitySeedService,
  type GoogleGithubIdentitySeedSource,
} from "../identity-sync/google-github-identity-seed-service.ts";
import { mergeGoogleDirectoryAuthority } from "../org-sync/google-directory-authority.ts";
import {
  DIRECTORY_READONLY_SCOPE,
  type GoogleDirectoryClient,
} from "../org-sync/google-directory-client.ts";
import { GoogleGithubIdentityApplyMaxProviderReads } from "../org-sync/google-identity-schema.ts";
import type { WorkspaceSyncRuntimeBindings } from "./provider-runtime-ports.ts";
import type { WorkspaceRuntimeConfiguration as ValidatedEnv } from "./runtime-configuration.ts";
import { fingerprintGoogleAuthority } from "./runtime.ts";
const FingerprintSchema = z.string().regex(/^[a-f0-9]{64}$/u);
const IdentitySchema = z.strictObject({
  githubLogin: z.string().min(1),
  githubUserId: z.string().min(1),
});
export const GithubIdentitySeedPreviewSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    issues: z.array(z.string().min(1)),
    kind: z.literal("blocked"),
    writesAttempted: z.literal(0),
  }),
  z.strictObject({
    artifactHash: FingerprintSchema,
    githubSourceFingerprint: FingerprintSchema,
    googleAuthorityFingerprint: FingerprintSchema,
    kind: z.literal("ready"),
    maxChanges: z.number().int().positive(),
    updates: z.array(
      z.strictObject({
        current: IdentitySchema.partial().nullable(),
        desired: IdentitySchema,
        googleUserId: z.string().min(1),
        primaryEmail: z.email(),
      }),
    ),
    writesAttempted: z.literal(0),
  }),
]);
export type GithubIdentitySeedPreview = z.output<
  typeof GithubIdentitySeedPreviewSchema
>;
// This cap bounds diagnostic output and provider reads; it never authorizes an APPLY.
const PREVIEW_MAX_CHANGES = 50;
export async function previewGithubIdentitySeed(
  bindings: WorkspaceSyncRuntimeBindings,
  env: ValidatedEnv,
): Promise<GithubIdentitySeedPreview> {
  if (
    env.githubAccessAuditOrganization.trim() === "" ||
    env.githubAccessAuditToken.trim() === ""
  ) {
    return {
      issues: ["GitHub SAML audit credential is unavailable"],
      kind: "blocked",
      writesAttempted: 0,
    };
  }
  const google = bindings.google(
    "github_identity_seed_preview",
    DIRECTORY_READONLY_SCOPE,
  );
  return previewGithubIdentitySeedFromSources({
    github: new GitHubAccessAuditClient({
      organization: env.githubAccessAuditOrganization,
      token: env.githubAccessAuditToken,
    }),
    google,
  });
}
export async function previewGithubIdentitySeedFromSources(sources: {
  github: GoogleGithubIdentitySeedSource;
  google: Pick<
    GoogleDirectoryClient,
    "listAllUsers" | "listDeletedUsers" | "readUserById"
  >;
}): Promise<GithubIdentitySeedPreview> {
  const runId = crypto.randomUUID();
  const [active, deleted] = await Promise.all([
    sources.google.listAllUsers(runId),
    sources.google.listDeletedUsers(runId),
  ]);
  const users = mergeGoogleDirectoryAuthority(active, deleted);
  const googleAuthorityFingerprint = await fingerprintGoogleAuthority(users);
  const seed = new GoogleGithubIdentitySeedService({
    github: sources.github,
    google: {
      readUserById: (userId) => sources.google.readUserById(userId),
      updateUser: () =>
        Promise.reject(new Error("github_identity_seed_preview_is_read_only")),
    },
    maxChanges: PREVIEW_MAX_CHANGES,
    maxProviderReads:
      PREVIEW_MAX_CHANGES * GoogleGithubIdentityApplyMaxProviderReads,
  });
  const plan = await seed.capture(users, googleAuthorityFingerprint);
  if (plan.kind !== "managed") {
    return GithubIdentitySeedPreviewSchema.parse({
      issues: plan.kind === "blocked" ? plan.issues : [plan.reason],
      kind: "blocked",
      writesAttempted: 0,
    });
  }
  return GithubIdentitySeedPreviewSchema.parse({
    artifactHash: plan.artifact.contentHash,
    githubSourceFingerprint: plan.githubSourceFingerprint,
    googleAuthorityFingerprint,
    kind: "ready",
    maxChanges: PREVIEW_MAX_CHANGES,
    updates: plan.userPlans.flatMap((userPlan) =>
      userPlan.kind === "update"
        ? {
            current: userPlan.current,
            desired: userPlan.desired,
            googleUserId: userPlan.user.id,
            primaryEmail: userPlan.user.primaryEmail,
          }
        : [],
    ),
    writesAttempted: 0,
  });
}
