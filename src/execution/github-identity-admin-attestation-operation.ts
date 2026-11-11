import { z } from "zod";

import {
  GitHubIdentityAdminAttestationError,
  type GitHubIdentityAdminAttestationPlan,
  GitHubIdentityAdminAttestationPlanSchema,
  GitHubIdentityAdminAttestationRequestSchema,
  GitHubIdentityAdminAttestationSourceError,
  type IGitHubIdentityAdminAttestationService,
} from "../identity-sync/github-identity-admin-attestation.ts";
import { sha256Hex } from "../operations/canonical.ts";
import {
  defineOperation,
  OperationInputError,
  OperationSourceError,
  type RegisteredOperation,
} from "../operations/registry.ts";
import type { SourceFingerprint } from "../operations/schemas.ts";
import { JsonValueSchema } from "../operations/schemas.ts";

export const GITHUB_IDENTITY_ADMIN_ATTESTATION_OPERATION_ID =
  "workspace-directory.github-identity-attest";

const GoogleGitHubIdentityObservedSchema = z
  .strictObject({
    githubLogin: z.string().min(1).nullable(),
    githubUserId: z.string().regex(/^\d+$/u).nullable(),
  })
  .nullable();

const GitHubIdentityManagedRowSchema = z.strictObject({
  githubIdentity: z.strictObject({
    githubLogin: z.string().min(1),
    githubUserId: z.string().regex(/^\d+$/u),
  }),
  googleIdentity: GoogleGitHubIdentityObservedSchema,
  googlePrimaryEmail: z.email(),
  googleUserId: z.string().regex(/^\d+$/u),
});

const GitHubIdentityManagedSliceSchema = z.strictObject({
  identities: z.array(GitHubIdentityManagedRowSchema),
});

const GitHubIdentityAdminAttestationOperationInputSchema =
  GitHubIdentityAdminAttestationRequestSchema.transform((input) =>
    JsonValueSchema.parse(input),
  );

export const GitHubIdentityAdminAttestationDetailsSchema = z.strictObject({
  plan: JsonValueSchema,
  request: JsonValueSchema,
});

type ManagedRow = z.output<typeof GitHubIdentityManagedRowSchema>;

/*
 * Registers explicit administrator attestations as one reviewed batch. The operation only records
 * immutable GitHub identity in Google Workspace; it never changes GitHub organization access.
 */
export function createGitHubIdentityAdminAttestationOperation(
  service: IGitHubIdentityAdminAttestationService,
): RegisteredOperation {
  const plan = async (
    input: unknown,
    context: { actorId: string; attestedAt: string },
  ) => {
    try {
      return await service.plan(input, context);
    } catch (error) {
      if (error instanceof GitHubIdentityAdminAttestationSourceError) {
        throw new OperationSourceError(
          `github-identity-attestation.${error.source}`,
          {
            cause: error,
          },
        );
      }
      if (error instanceof GitHubIdentityAdminAttestationError) {
        throw new OperationInputError({ cause: error });
      }
      throw new OperationSourceError("github-identity-attestation", {
        cause: error,
      });
    }
  };

  return defineOperation({
    name: GITHUB_IDENTITY_ADMIN_ATTESTATION_OPERATION_ID,
    policyVersion: "2026-09-26.2",
    inputSchema: GitHubIdentityAdminAttestationOperationInputSchema,
    detailsSchema: GitHubIdentityAdminAttestationDetailsSchema,
    metadata: {
      destructive: false,
      execution: "sync",
      requiredRole: "operations-admin",
      requiredScope: "workspace-directory:apply",
      risk: "high",
      sourceSystems: ["operator-request", "github", "google-workspace"],
      summary:
        "Bind reviewed GitHub logins to Google users using immutable provider IDs.",
      supportsApply: true,
      supportsPlan: true,
      targetSystems: ["google-workspace"],
    },
    async buildPlan(input, context) {
      const reviewed = await plan(input, attestationContext(context));
      const before = managedSlice(reviewed, "before");
      const after = managedSlice(reviewed, "after");
      return {
        applicable: true,
        changes:
          after.identities.length === 0
            ? []
            : [
                {
                  actionId: "github-identity-admin-attestation:apply",
                  after,
                  before,
                  confirmationCounts: {
                    githubIdentityUpdates: after.identities.length,
                  },
                  details: {
                    plan: JsonValueSchema.parse(reviewed),
                    request: input,
                  },
                  display: `Attest ${String(after.identities.length)} GitHub identity mapping${after.identities.length === 1 ? "" : "s"}`,
                  kind: before.identities.every(
                    ({ googleIdentity }) => googleIdentity === null,
                  )
                    ? ("add" as const)
                    : ("change" as const),
                  reason:
                    "An administrator explicitly reviewed each Google subject and GitHub login.",
                  resource: {
                    id: "github-identities",
                    type: "google-workspace.github-identity",
                  },
                  risk: "high" as const,
                },
              ],
        diagnostics: [],
        sourceFingerprints: await sourceFingerprints(reviewed),
      };
    },
    async readSourceFingerprints(input, context) {
      return sourceFingerprints(await plan(input, attestationContext(context)));
    },
    async readManagedSlice(change, context) {
      const details = parseDetails(change.details);
      const refreshed = await plan(
        details.request,
        attestationContext(context),
      );
      return currentManagedSlice(details.plan, refreshed);
    },
    async applyChange(change) {
      const { plan: reviewed } = parseDetails(change.details);
      await service.apply(reviewed, reviewed.planHash);
    },
  });
}

function attestationContext(context: { actor: { id: string }; now: Date }): {
  actorId: string;
  attestedAt: string;
} {
  return { actorId: context.actor.id, attestedAt: context.now.toISOString() };
}

function parseDetails(input: unknown): {
  plan: GitHubIdentityAdminAttestationPlan;
  request: z.output<typeof GitHubIdentityAdminAttestationRequestSchema>;
} {
  const details = GitHubIdentityAdminAttestationDetailsSchema.parse(input);
  return {
    plan: GitHubIdentityAdminAttestationPlanSchema.parse(details.plan),
    request: GitHubIdentityAdminAttestationRequestSchema.parse(details.request),
  };
}

function managedSlice(
  plan: GitHubIdentityAdminAttestationPlan,
  side: "after" | "before",
): z.output<typeof GitHubIdentityManagedSliceSchema> {
  return GitHubIdentityManagedSliceSchema.parse({
    identities: plan.entries.flatMap((entry): ManagedRow[] => {
      if (entry.googlePlan.kind !== "update") return [];
      return [
        {
          githubIdentity: entry.target,
          googleIdentity: normalizeObservedIdentity(
            side === "after"
              ? entry.googlePlan.desired
              : entry.googlePlan.current,
          ),
          googlePrimaryEmail: entry.googlePlan.user.primaryEmail,
          googleUserId: entry.googlePlan.user.id,
        },
      ];
    }),
  });
}

function currentManagedSlice(
  reviewed: GitHubIdentityAdminAttestationPlan,
  refreshed: GitHubIdentityAdminAttestationPlan,
): z.output<typeof GitHubIdentityManagedSliceSchema> {
  const identities = reviewed.entries.flatMap((entry): ManagedRow[] => {
    if (entry.googlePlan.kind !== "update") return [];
    const googleUserId = entry.googlePlan.user.id;
    const current = refreshed.entries.find(
      (candidate) => candidate.googlePlan.user.id === googleUserId,
    );
    if (!current)
      throw new Error(`Google identity ${googleUserId} disappeared after PLAN`);
    const googleIdentity = normalizeObservedIdentity(
      current.googlePlan.kind === "update"
        ? current.googlePlan.current
        : current.googlePlan.identity,
    );
    return [
      {
        githubIdentity: current.target,
        googleIdentity,
        googlePrimaryEmail: current.googlePlan.user.primaryEmail,
        googleUserId,
      },
    ];
  });
  return GitHubIdentityManagedSliceSchema.parse({ identities });
}

function normalizeObservedIdentity(
  identity: {
    githubLogin?: string | undefined;
    githubUserId?: string | undefined;
  } | null,
): { githubLogin: null | string; githubUserId: null | string } | null {
  if (identity === null) return null;
  return {
    githubLogin: identity.githubLogin ?? null,
    githubUserId: identity.githubUserId ?? null,
  };
}

async function sourceFingerprints(
  plan: GitHubIdentityAdminAttestationPlan,
): Promise<SourceFingerprint[]> {
  return Promise.all(
    plan.entries.map(async (entry) => ({
      authority: "identity-admin",
      resourceId: entry.googlePlan.user.id,
      resourceType: "github-google-identity-attestation",
      version: await sha256Hex({
        attestation: {
          attestedBy: entry.attestation.attestedBy,
          githubLogin: entry.attestation.githubLogin,
          subject: entry.attestation.subject,
        },
        githubIdentity: entry.target,
        googlePrimaryEmail: entry.googlePlan.user.primaryEmail,
        googleUserId: entry.googlePlan.user.id,
      }),
    })),
  );
}
