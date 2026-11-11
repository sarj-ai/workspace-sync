import { z } from "zod";

export const AccessGuardSettingsSchema = z.strictObject({
  allowedEmptyManagerGoogleUserIds: z
    .array(z.string().regex(/^\d+$/u))
    .describe("Reviewed identities whose manager may remain unassigned"),
  alertsChannelId: z
    .string()
    .regex(/^C[A-Z0-9]+$/u)
    .describe(
      "Private #alerts-it-admin channel that holds alerts and the Slack metadata ledger",
    ),
  alertsChannelName: z
    .literal("alerts-it-admin")
    .describe(
      "Exact live Slack channel name pinned alongside the immutable channel ID",
    ),
  enabled: z
    .boolean()
    .describe("Checked-in kill switch for the scheduled access guard"),
  expectedAttioWorkspaceId: z
    .uuid()
    .nullable()
    .describe(
      "Immutable Attio tenant ID; null keeps Attio access auditing fail-closed",
    ),
  expectedGitHubOrganization: z
    .string()
    .regex(/^[A-Za-z0-9-]+$/u)
    .describe(
      "Exact GitHub organization used for read-only SCIM access coverage",
    ),
  expectedLinearOrganizationId: z
    .uuid()
    .nullable()
    .describe(
      "Immutable Linear tenant ID; null keeps Linear audit and enforcement fail-closed",
    ),
  expectedLinearOrganizationUrlKey: z
    .string()
    .regex(/^[a-z0-9-]+$/u)
    .describe(
      "Human-verifiable Linear workspace URL key used during tenant discovery",
    ),
  maxAutomaticLinearSuspensions: z
    .literal(0)
    .describe("Unsigned scheduled mutation is permanently disabled"),
  maxReviewedLinearSuspensions: z
    .number()
    .int()
    .nonnegative()
    .describe("Checked-in cap for signed Workspace Directory PLAN/APPLY"),
  minimumProviderAccounts: z
    .strictObject({
      attio: z.number().int().positive(),
      github: z.number().int().positive(),
      linear: z.number().int().positive(),
      pagerduty: z.number().int().positive(),
      slack: z.number().int().positive(),
    })
    .describe(
      "Conservative fail-closed account floors for every provider snapshot",
    ),
});

export type AccessGuardSettings = z.output<typeof AccessGuardSettingsSchema>;
