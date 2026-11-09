import { z } from "zod";

import { GoogleUserIdSchema } from "../catalog/identity-authority.ts";
import { PagerDutyTeamRoleSchema } from "./pagerduty-team-config.ts";

export const PagerDutyTeamDiagnosticCodeSchema = z.enum([
  "contractor-membership-preserved",
  "credential-missing",
  "evidence-incomplete",
  "google-group-member-ineligible",
  "google-group-pin-mismatch",
  "mapping-configuration-empty",
  "pagerduty-team-pin-mismatch",
  "pagerduty-user-email-ambiguous",
  "pagerduty-user-missing",
  "protected-identity",
]);
const PagerDutyLicenseReadinessDiagnosticCodeSchema = z.enum([
  "paid_capacity_unverified",
  "dedicated_credential_missing",
  "dedicated_credential_unavailable",
]);
const PagerDutyReadinessDiagnosticCodeSchema = z.union([
  PagerDutyTeamDiagnosticCodeSchema,
  PagerDutyLicenseReadinessDiagnosticCodeSchema,
]);

export const MAX_PAGERDUTY_READINESS_IDENTITIES = 4;
const MAX_LICENSES = 100;
const PagerDutyIdSchema = z.string().regex(/^P[A-Z0-9]+$/u);
const PagerDutyBaseRoleSchema = z.enum([
  "admin",
  "limited_user",
  "observer",
  "owner",
  "read_only_user",
  "restricted_access",
  "read_only_limited_user",
  "user",
]);
export const PagerDutyLicenseSchema = z.object({
  id: PagerDutyIdSchema,
  "valid_roles": z.array(PagerDutyBaseRoleSchema).max(20),
  "current_value": z.number().int().nonnegative(),
  "allocations_available": z.number().int().nonnegative().nullable(),
});
export const PagerDutyLicensesResponseSchema = z.object({
  licenses: z.array(PagerDutyLicenseSchema).max(MAX_LICENSES),
});
export const PagerDutyLicensingSnapshotSchema = z.strictObject({
  licenses: z.array(PagerDutyLicenseSchema).max(MAX_LICENSES),
  allocationCount: z.number().int().nonnegative(),
});
export type PagerDutyLicensingSnapshot = z.output<
  typeof PagerDutyLicensingSnapshotSchema
>;

export const PagerDutyMissingUserSchema = z.strictObject({
  googleUserId: GoogleUserIdSchema,
  email: z.email(),
  targets: z
    .array(
      z.strictObject({
        googleGroupId: z.string().min(1),
        pagerDutyTeamId: PagerDutyIdSchema,
        desiredRole: PagerDutyTeamRoleSchema,
      }),
    )
    .min(1)
    .max(20),
});
export type PagerDutyMissingUser = z.output<typeof PagerDutyMissingUserSchema>;
const CredentialEvidenceSchema = z.enum([
  "missing",
  "read-verified",
  "unavailable",
]);
const ReadinessDiagnosticSeveritySchema = z.enum(["blocker", "warning"]);
export const PagerDutyReadinessSchema = z.strictObject({
  mutationDisabled: z.boolean(),
  writesAttempted: z.literal(0),
  credentialEvidence: CredentialEvidenceSchema,
  writePermissionEvidence: z.literal("unverified"),
  paidCapacity: z.literal("unknown"),
  sourceComplete: z.boolean(),
  missingUserCount: z.number().int().nonnegative(),
  missingUsersTruncated: z.boolean(),
  missingUsers: z
    .array(PagerDutyMissingUserSchema)
    .max(MAX_PAGERDUTY_READINESS_IDENTITIES),
  licensing: PagerDutyLicensingSnapshotSchema.nullable(),
  diagnostics: z.array(
    z.strictObject({
      code: PagerDutyReadinessDiagnosticCodeSchema,
      severity: ReadinessDiagnosticSeveritySchema,
    }),
  ),
});
