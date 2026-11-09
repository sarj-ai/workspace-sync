/**
 * Google Workspace supplies directory authority for guarded reconciliation with
 * Slack, GitHub, Linear, PagerDuty, Sentry and Trycomp. Provider clients, planners,
 * leases, write budgets and readbacks compose into host-owned workflows.
 *
 * Configure one tenant per process or Worker isolate. Policy is cloned and frozen;
 * a different tenant requires a separate process or isolate. Credentials belong
 * in the host's secret store and must never appear in policy or logs. Isolate
 * persistence and provider credentials per tenant as well.
 *
 * Trusted host code owns authentication, scheduling, migrations, persistence,
 * signed-plan approval and audit retention. Untrusted callers must not supply
 * policy, credentials or provider ports, or invoke provider writes directly.
 * Directory access defaults to the read-only scope. Write access requires an
 * explicit scope, narrow provider grants and the operation's authority guards.
 *
 * Preserve fresh authority, reviewed plan hashes, provenance, write budgets,
 * leases and provider readbacks when composing an executor. D1 adapters expect
 * host-owned tables; the package does not migrate production databases.
 */
import { dequal } from "dequal";
import { z } from "zod";

import { OrgSyncSettingsSchema } from "./org-sync/org-sync-settings-schema.ts";

const GoogleUserIdSchema = z.string().regex(/^[1-9]\d{4,29}$/u);
const EmailSchema = z.email().transform((value) => value.toLowerCase());
const ContractorAuthorityGroupSchema = z
  .strictObject({
    acceptedEmails: z.array(EmailSchema).min(1),
    email: EmailSchema,
    id: z.string().min(1),
  })
  .refine((group) => group.acceptedEmails.includes(group.email), {
    message: "The canonical contractor group email must be an accepted email",
  });
const ReviewedDirectGrantSchema = z.strictObject({
  allowedTeamSlugs: z.array(z.string().min(1)),
  githubLogin: z.string().min(1),
  githubUserId: z.string().regex(/^[1-9]\d*$/u),
  googleUserId: GoogleUserIdSchema,
  grants: z.array(
    z.strictObject({
      customRoleName: z.string().min(1).optional(),
      permission: z.enum(["admin", "maintain", "pull", "push", "triage"]),
      repositoryId: z.number().int().positive(),
      repositoryName: z.string().regex(/^[\w.-]+\/[\w.-]+$/u),
    }),
  ),
  primaryEmail: EmailSchema,
  reviewedAt: z.iso.date(),
});
const ReviewedTeamMembershipSchema = z.strictObject({
  githubLogin: z.string().min(1),
  githubUserId: z.string().regex(/^[1-9]\d*$/u),
  googleUserId: GoogleUserIdSchema,
  reviewedAt: z.iso.date(),
  teamId: z.number().int().positive(),
  teamSlug: z.string().min(1),
});
const TrycompPolicySchema = z.strictObject({
  contractorGroupEmail: EmailSchema,
  contractorGroupId: z.string().min(1),
  maxAutomaticActivations: z.number().int().nonnegative(),
  maxAutomaticContractorDeactivations: z.number().int().nonnegative(),
  maxAutomaticInactiveGoogleDeactivations: z.number().int().nonnegative(),
  maxAutomaticDeactivations: z.number().int().nonnegative(),
  offboardingOnly: z.boolean(),
  minimumGoogleUsers: z.number().int().positive(),
});

export const WorkspaceSyncPolicySchema = z
  .strictObject({
    contractorAuthorityGroup: ContractorAuthorityGroupSchema,
    employeeEntitlementExcludedEmails: z.array(EmailSchema),
    ignoredDeletedGoogleUserIds: z.array(GoogleUserIdSchema),
    org: OrgSyncSettingsSchema,
    reviewedGitHubDirectGrantRetentions: z.array(ReviewedDirectGrantSchema),
    reviewedGitHubTeamMemberships: z.array(ReviewedTeamMembershipSchema),
    sentryTeamSlug: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/u),
    trycomp: TrycompPolicySchema,
  })
  .superRefine((policy, context) => {
    if (
      policy.trycomp.contractorGroupId !== policy.contractorAuthorityGroup.id ||
      policy.trycomp.contractorGroupEmail !==
        policy.contractorAuthorityGroup.email
    ) {
      context.addIssue({
        code: "custom",
        message: "Contractor authority must be consistent across providers",
        path: ["trycomp"],
      });
    }
  });

export type WorkspaceSyncPolicy = z.output<typeof WorkspaceSyncPolicySchema>;
let configuredPolicy: WorkspaceSyncPolicy | undefined;

/* Configure one tenant per process or Worker isolate before constructing clients.
 * No credentials belong in this policy. Configuration is immutable for the
 * isolate lifetime; a second tenant requires a separate isolate or process.
 */
export function configureWorkspaceSyncPolicy(input: unknown): void {
  const parsed = WorkspaceSyncPolicySchema.parse(input);
  if (configuredPolicy !== undefined) {
    if (!dequal(configuredPolicy, parsed)) {
      throw new Error("workspace_sync_policy_already_configured");
    }
    return;
  }
  configuredPolicy = deepFreeze(parsed);
}

export function getWorkspaceSyncPolicy(): WorkspaceSyncPolicy {
  if (configuredPolicy === undefined)
    throw new Error("workspace_sync_policy_not_configured");
  return configuredPolicy;
}

function deepFreeze<Value>(value: Value): Value {
  // eslint-disable-next-line @sarj/no-runtime-typeof -- Recursive freezing is a generic primitive/object utility, not an input parser.
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
