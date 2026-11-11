import { z } from "zod";

import { SLACK_PROFILE_MANAGED_FIELD_IDS } from "./flow.ts";

export const ManagedFieldNameSchema = z.enum(SLACK_PROFILE_MANAGED_FIELD_IDS);

export const DesiredManagedFieldsSchema = z.strictObject({
  linkedin: z.string(),
  manages: z.string(),
  reportsTo: z.string(),
  team: z.string(),
  title: z.string(),
});
