import { z } from "zod";

const PagerDutyIdSchema = z.string().regex(/^P[A-Z0-9]+$/);
const MAX_PAGERDUTY_TEAM_MAPPINGS = 20;
const MAX_PAGERDUTY_TEAM_EXCLUSIONS = 100;
export const PagerDutyTeamRoleSchema = z.enum([
  "manager",
  "observer",
  "responder",
]);

export const PagerDutyTeamMappingSchema = z
  .strictObject({
    excludedEmails: z
      .array(z.email().transform((value) => value.toLowerCase()))
      .max(MAX_PAGERDUTY_TEAM_EXCLUSIONS)
      .readonly()
      .optional(),
    googleGroupEmail: z.email().transform((value) => value.toLowerCase()),
    googleGroupId: z.string().min(1),
    pagerDutyRole: PagerDutyTeamRoleSchema,
    pagerDutyTeamId: PagerDutyIdSchema,
    pagerDutyTeamName: z.string().trim().min(1),
  })
  .readonly();

export const PagerDutyTeamSyncSettingsSchema = z
  .strictObject({
    mappings: z
      .array(PagerDutyTeamMappingSchema)
      .max(MAX_PAGERDUTY_TEAM_MAPPINGS)
      .readonly(),
  })
  .superRefine(({ mappings }, context) => {
    for (const key of [
      "googleGroupEmail",
      "googleGroupId",
      "pagerDutyTeamId",
    ] as const) {
      if (
        new Set(mappings.map((mapping) => mapping[key])).size !==
        mappings.length
      ) {
        context.addIssue({
          code: "custom",
          message: `${key} mappings must be unique`,
        });
      }
    }
  })
  .readonly();

export type PagerDutyTeamMapping = z.output<typeof PagerDutyTeamMappingSchema>;
export type PagerDutyTeamSyncSettings = z.output<
  typeof PagerDutyTeamSyncSettingsSchema
>;
