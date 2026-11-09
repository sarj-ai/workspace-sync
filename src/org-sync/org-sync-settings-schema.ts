import { z } from "zod";

const GoogleUserIdSchema = z
  .string()
  .regex(/^\d+$/u)
  .describe("Immutable Google Directory user ID");
const SlackCustomFieldIdSchema = z
  .string()
  .regex(/^X[A-Za-z0-9]+$/u)
  .describe("Slack workspace profile custom-field ID");

export const OrgSyncSettingsSchema = z
  .strictObject({
    allowedEmptyDepartmentGoogleUserIds: z
      .array(GoogleUserIdSchema)
      .describe("Root Google identities permitted to have an empty department"),
    allTeamDriveId: z
      .string()
      .min(1)
      .describe(
        "All Team Shared Drive root where the managed HTML org chart is upserted",
      ),
    excludedGoogleUserIds: z
      .array(GoogleUserIdSchema)
      .describe(
        "Explicit non-person Directory identities omitted from the employee chart",
      ),
    expectedRootGoogleUserIds: z
      .array(GoogleUserIdSchema)
      .min(1)
      .describe("Exact Google identities that must have no manager"),
    expectedSlackTeamId: z
      .string()
      .regex(/^T[A-Z0-9]+$/u)
      .describe(
        "Slack workspace ID; reconciliation fails closed for any other workspace",
      ),
    protectedDepartedGoogleUserIds: z
      .array(GoogleUserIdSchema)
      .describe(
        "Departed identities that may be deleted, but must remain suspended if retained or restored under the same immutable ID",
      ),
    fieldIds: z
      .strictObject({
        manages: SlackCustomFieldIdSchema.describe(
          "API-managed Slack “Manages” people field",
        ),
        reportsTo: SlackCustomFieldIdSchema.describe(
          "API-managed Slack “Reports to” person field",
        ),
        team: SlackCustomFieldIdSchema.describe(
          "API-managed Slack “Team” field",
        ),
      })
      .describe("Exact API-managed Slack profile field IDs"),
    googleAdminSubject: z
      .email()
      .describe(
        "Workspace administrator impersonated by the read-only Directory client",
      ),
    googleUserProject: z
      .string()
      .min(1)
      .describe("Google Cloud project charged for Directory API quota"),
    managedDomain: z
      .string()
      .regex(/^[a-z0-9.-]+\.[a-z]{2,}$/u)
      .describe(
        "Only existing Slack members with email addresses in this domain are targeted",
      ),
    maxAutomaticChanges: z
      .number()
      .int()
      .nonnegative()
      .describe(
        "Maximum changed Slack profiles allowed without an approved authority-plan hash",
      ),
    minimumGoogleParticipants: z
      .number()
      .int()
      .positive()
      .describe(
        "Fail-closed population floor for active Google org participants",
      ),
    orgChartFileId: z
      .string()
      .regex(/^[A-Za-z0-9_-]{10,}$/u)
      .refine((value) => value !== "bootstrap-required", {
        message:
          "The managed org chart must be pinned to its immutable Drive file ID",
      })
      .describe(
        "Immutable app-created Drive file ID for the managed organization chart",
      ),
  })
  .superRefine((settings, context) => {
    const fieldIds = Object.values(settings.fieldIds);
    if (new Set(fieldIds).size !== fieldIds.length) {
      context.addIssue({
        code: "custom",
        message: "Slack field IDs must be distinct",
        path: ["fieldIds"],
      });
    }

    const roots = new Set(settings.expectedRootGoogleUserIds);
    if (roots.size !== settings.expectedRootGoogleUserIds.length) {
      context.addIssue({
        code: "custom",
        message: "Expected Google root IDs must be distinct",
        path: ["expectedRootGoogleUserIds"],
      });
    }
    for (const userId of settings.allowedEmptyDepartmentGoogleUserIds) {
      if (!roots.has(userId)) {
        context.addIssue({
          code: "custom",
          message:
            "An empty-department exception must also be an expected root",
          path: ["allowedEmptyDepartmentGoogleUserIds"],
        });
      }
    }
  });

export type OrgSyncSettings = z.infer<typeof OrgSyncSettingsSchema>;
