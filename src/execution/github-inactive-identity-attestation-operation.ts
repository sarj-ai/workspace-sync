import {
  afterSchemas,
  InactiveGitHubAttestationPlanSchema,
  InactiveGitHubAttestationRequestSchema,
  type InactiveGitHubIdentityAttestationService,
  inactiveIdentitySlice,
} from "../identity-sync/github-inactive-identity-attestation.ts";
import { sha256Hex } from "../operations/canonical.ts";
import { defineOperation } from "../operations/registry.ts";
import { JsonValueSchema } from "../operations/schemas.ts";

export const INACTIVE_GITHUB_ATTESTATION_OPERATION =
  "workspace-directory.github-inactive-identity-attest";
export const INACTIVE_GITHUB_ATTESTATION_ACTION =
  "github-inactive-identity-attestation:apply";

export function createInactiveGitHubIdentityAttestationOperation(
  service: Pick<
    InactiveGitHubIdentityAttestationService,
    "apply" | "plan" | "read"
  >,
) {
  return defineOperation({
    name: INACTIVE_GITHUB_ATTESTATION_OPERATION,
    policyVersion: "2026-09-27.1",
    inputSchema: InactiveGitHubAttestationRequestSchema,
    detailsSchema: JsonValueSchema,
    actionIds: [INACTIVE_GITHUB_ATTESTATION_ACTION],
    ttlSeconds: 600,
    metadata: {
      destructive: false,
      execution: "sync",
      requiredRole: "operations-admin",
      requiredScope: "workspace-directory:apply",
      risk: "high",
      sourceSystems: ["operator-request", "github", "google-workspace"],
      targetSystems: ["google-workspace"],
      summary:
        "Record an explicitly confirmed immutable GitHub identity for one inactive Google user.",
      supportsApply: true,
      supportsPlan: true,
    },
    async buildPlan(input, context) {
      const plan = await service.plan(input, {
        actorId: context.actor.id,
        attestedAt: context.now.toISOString(),
      });
      return {
        applicable: true,
        diagnostics: [],
        sourceFingerprints: await fingerprints(input, plan.before),
        changes:
          plan.attestation.entries[0]?.googlePlan.kind === "unchanged"
            ? []
            : [
                {
                  actionId: INACTIVE_GITHUB_ATTESTATION_ACTION,
                  kind: "add" as const,
                  risk: "high" as const,
                  before: inactiveIdentitySlice(plan.before),
                  after: inactiveIdentitySlice({
                    ...plan.before,
                    customSchemas: afterSchemas(plan.before, input),
                  }),
                  details: JsonValueSchema.parse(plan),
                  confirmationCounts: { githubIdentityUpdates: 1 },
                  resource: {
                    id: input.googleUserId,
                    type: "google-workspace.inactive-github-identity",
                  },
                  display:
                    "Record one confirmed GitHub identity on an inactive Google user",
                  reason:
                    "Explicit administrator confirmation supplies ownership; provider reads verify immutable IDs. Only identity metadata changes.",
                },
              ],
      };
    },
    async readSourceFingerprints(input) {
      return fingerprints(input, await service.read(input));
    },
    async readManagedSlice(change) {
      const plan = InactiveGitHubAttestationPlanSchema.parse(change.details);
      return inactiveIdentitySlice(await service.read(plan.request));
    },
    async applyChange(change) {
      await service.apply(change.details);
    },
  });
}

async function fingerprints(
  request: Parameters<typeof InactiveGitHubAttestationRequestSchema.parse>[0],
  before: Awaited<ReturnType<InactiveGitHubIdentityAttestationService["read"]>>,
) {
  return [
    {
      authority: "identity-admin",
      resourceId: before.id,
      resourceType: "inactive-github-google-identity-attestation",
      version: await sha256Hex(JsonValueSchema.parse({ request, before })),
    },
  ];
}
