import { z } from "zod";

import {
  GitHubLoginSchema,
  GitHubUserIdSchema,
} from "../catalog/identity-authority.ts";
import { normalizeIdentityEmail } from "../identity-sync/normalize-identity-email.ts";
import { ProviderReadinessContextSchema } from "../provider-readiness.ts";

const GitHubAccountTypeSchema = z.enum(["Bot", "User"]);
const RawStringSchema = z.string();

const OptionalTrimmedStringSchema = z.preprocess((value) => {
  const parsed = RawStringSchema.safeParse(value);
  return parsed.success && parsed.data.trim() === "" ? undefined : value;
}, z.string().trim().min(1).optional());
const EmailSchema = z.string().trim().toLowerCase().pipe(z.email());

export const GoogleAccessUserSchema = z.object({
  aliases: z.array(EmailSchema).default([]),
  archived: z.boolean().optional().default(false),
  customSchemas: z
    .object({
      SarjIdentity: z
        .object({
          githubLogin: z.string().optional(),
          githubUserId: z.string().optional(),
        })
        .optional(),
    })
    .optional(),
  deletionTime: z.iso.datetime().optional(),
  id: z.string().trim().min(1),
  isAdmin: z.boolean().optional(),
  isDelegatedAdmin: z.boolean().optional(),
  name: z.object({ fullName: OptionalTrimmedStringSchema }).optional(),
  nonEditableAliases: z.array(EmailSchema).default([]),
  organizations: z
    .array(
      z.object({
        department: OptionalTrimmedStringSchema,
        primary: z.boolean().optional(),
        title: OptionalTrimmedStringSchema,
      }),
    )
    .default([]),
  primaryEmail: EmailSchema,
  relations: z
    .array(
      z.object({
        type: z.string().trim().min(1),
        value: OptionalTrimmedStringSchema,
      }),
    )
    .default([]),
  suspended: z.boolean().optional().default(false),
});
export type GoogleAccessUser = z.output<typeof GoogleAccessUserSchema>;

export const DownstreamAccountSchema = z.object({
  active: z.boolean(),
  admin: z.boolean().optional(),
  app: z.boolean().optional(),
  displayName: OptionalTrimmedStringSchema,
  email: EmailSchema,
  id: z.string().trim().min(1),
  owner: z.boolean().optional(),
});
export type DownstreamAccount = z.output<typeof DownstreamAccountSchema>;

export const GitHubAccessAccountSchema = z.strictObject({
  access: z.enum(["member", "outside_collaborator"]),
  active: z.literal(true),
  id: GitHubUserIdSchema,
  login: GitHubLoginSchema,
  type: GitHubAccountTypeSchema,
});
export type GitHubAccessAccount = z.output<typeof GitHubAccessAccountSchema>;

export const GitHubAccessInvitationSchema = z.strictObject({
  email: EmailSchema.nullish(),
  id: z.number().int().positive(),
  login: GitHubLoginSchema.nullish(),
  invitee: z
    .strictObject({
      id: GitHubUserIdSchema,
      login: GitHubLoginSchema,
      type: GitHubAccountTypeSchema,
    })
    .nullish(),
  role: z.enum(["admin", "billing_manager", "direct_member"]),
});
export type GitHubAccessInvitation = z.output<
  typeof GitHubAccessInvitationSchema
>;

export const GitHubAccessReadSchema = z.strictObject({
  accounts: z.array(GitHubAccessAccountSchema),
  invitations: z.array(GitHubAccessInvitationSchema),
});
export type GitHubAccessRead = z.output<typeof GitHubAccessReadSchema>;

export const ProviderNameSchema = z.enum([
  "ashby",
  "attio",
  "github",
  "linear",
  "pagerduty",
  "slack",
]);
export type ProviderName = z.output<typeof ProviderNameSchema>;

export const EmailProviderNameSchema = z.enum([
  "ashby",
  "attio",
  "linear",
  "pagerduty",
  "slack",
]);
export type EmailProviderName = z.output<typeof EmailProviderNameSchema>;

export const ProviderSnapshotSchema = z.union([
  z.object({
    accounts: z.array(DownstreamAccountSchema),
    ok: z.literal(true),
    provider: EmailProviderNameSchema,
  }),
  z.object({
    accounts: z.array(GitHubAccessAccountSchema),
    invitations: z.array(GitHubAccessInvitationSchema),
    ok: z.literal(true),
    provider: z.literal("github"),
  }),
  z.strictObject({
    ok: z.literal(false),
    provider: z.literal("linear"),
    readiness: ProviderReadinessContextSchema,
  }),
  z.strictObject({
    errorCode: z.string().trim().min(1),
    ok: z.literal(false),
    provider: ProviderNameSchema,
  }),
]);
export type ProviderSnapshot = z.output<typeof ProviderSnapshotSchema>;

export const AccessGuardConfigSchema = z.object({
  allowedEmptyDepartmentGoogleUserIds: z
    .array(z.string().trim().min(1))
    .default([]),
  allowedEmptyManagerGoogleUserIds: z
    .array(z.string().trim().min(1))
    .default([]),
  excludedGoogleUserIds: z.array(z.string().trim().min(1)).default([]),
  protectedDepartedGoogleUserIds: z.array(z.string().trim().min(1)).default([]),
  maxReviewedLinearSuspensions: z.number().int().nonnegative().default(0),
  minimumGoogleUsers: z.number().int().positive().default(1),
  minimumProviderAccounts: z
    .partialRecord(ProviderNameSchema, z.number().int().positive())
    .default({}),
  requiredProviders: z
    .array(ProviderNameSchema)
    .refine((providers) => new Set(providers).size === providers.length, {
      message: "requiredProviders must be unique",
    }),
  rootGoogleUserIds: z.array(z.string().trim().min(1)).min(1),
});
export type AccessGuardConfig = z.output<typeof AccessGuardConfigSchema>;

export const AccessIssueSchema = z.object({
  details: z.record(z.string(), z.string()),
  googleUserId: z.string().trim().min(1).optional(),
  id: z.string().trim().min(1),
  kind: z.enum([
    "active_downstream_without_google",
    "active_downstream_for_inactive_google",
    "coverage_failure",
    "missing_google_org_metadata",
  ]),
  provider: ProviderNameSchema.optional(),
  summary: z.string().trim().min(1),
});
export type AccessIssue = z.output<typeof AccessIssueSchema>;

const GeneralAccessDiagnosticSchema = z
  .object({
    code: z.enum([
      "ambiguous_github_identity",
      "ambiguous_google_email",
      "ambiguous_provider_email",
      "conflicting_github_identity",
      "invalid_google_org_shape",
      "invalid_google_github_identity",
      "pending_provider_invitation",
      "provider_error",
      "protected_linear_account",
      "unmatched_provider_account",
    ]),
    context: z.record(
      z.string(),
      z.union([z.string(), z.number(), z.boolean()]),
    ),
    level: z.enum(["error", "warning"]),
    message: z.string().trim().min(1),
    provider: ProviderNameSchema.optional(),
  })
  .refine(
    (diagnostic) => Reflect.get(diagnostic.context, "kind") !== "linear_tenant",
    {
      message: "linear_tenant context is reserved for provider_readiness",
      path: ["context"],
    },
  );
const ProviderReadinessDiagnosticSchema = z.strictObject({
  code: z.literal("provider_readiness"),
  context: ProviderReadinessContextSchema,
  level: z.literal("error"),
  message: z.string().trim().min(1),
  provider: z.literal("linear"),
});
export const AccessDiagnosticSchema = z.union([
  ProviderReadinessDiagnosticSchema,
  GeneralAccessDiagnosticSchema,
]);
export type AccessDiagnostic = z.output<typeof AccessDiagnosticSchema>;

export const AccessGuardPlanSchema = z.object({
  actions: z.array(
    z.object({
      accountId: z.string().min(1),
      email: EmailSchema,
      googleUserId: z.string().min(1),
      provider: z.literal("linear"),
      type: z.literal("suspend"),
    }),
  ),
  diagnostics: z.array(AccessDiagnosticSchema),
  issues: z.array(AccessIssueSchema),
  stats: z.object({
    activeGooglePeople: z.number().int().nonnegative(),
    googleUsers: z.number().int().nonnegative(),
    providerAccounts: z.partialRecord(
      ProviderNameSchema,
      z.number().int().nonnegative(),
    ),
    inactiveGoogleUsers: z.number().int().nonnegative(),
  }),
});
export type AccessGuardPlan = z.output<typeof AccessGuardPlanSchema>;

export interface AccessGuardAuditOptions {
  linearSuspensionTarget?: Pick<
    AccessGuardPlan["actions"][number],
    "accountId" | "email" | "googleUserId"
  >;
  scheduledLinearSuspension?: true;
}

export const LinearAccessManagedSliceSchema = z.array(
  z.strictObject({
    accountId: z.string().min(1),
    active: z.boolean(),
    email: EmailSchema,
  }),
);
export type LinearAccessManagedSlice = z.output<
  typeof LinearAccessManagedSliceSchema
>;

export function normalizeEmail(value: string): string {
  return normalizeIdentityEmail(value);
}
