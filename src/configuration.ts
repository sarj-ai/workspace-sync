/**
 * Google Workspace supplies directory authority for guarded reconciliation with
 * Slack, GitHub, Linear, PagerDuty, Sentry and Trycomp.
 *
 * Use one immutable policy per process or Worker isolate. Isolate tenant storage
 * and credentials; keep secrets out of policy and logs.
 *
 * The package owns scheduling, durable execution, reconciliation and repository
 * transitions. The trusted host owns authentication, credentials, SDK bindings,
 * migrations, signed-plan authorization and audit retention. Untrusted callers must not supply
 * policy, credentials or provider ports. Directory access defaults to read-only;
 * writes require explicit scopes, narrow grants and authority guards.
 *
 * Executors must preserve fresh authority, reviewed hashes, provenance, write
 * budgets, leases and provider readbacks. D1 tables and migrations belong to the host.
 */
import { dequal } from "dequal";
import { z } from "zod";

import { WorkspaceExecutionPolicySchema } from "./execution/policy.ts";
import { OrgSyncSettingsSchema } from "./org-sync/org-sync-settings-schema.ts";

const GoogleUserIdSchema = z.string().regex(/^[1-9]\d{4,29}$/u);
const EmailSchema = z.email().toLowerCase();
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
    execution: WorkspaceExecutionPolicySchema.nullable().default(null),
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

export {
  OrgSyncService as SlackProfileSync,
  type SlackProfileSyncContract,
} from "./org-sync/service.ts";
