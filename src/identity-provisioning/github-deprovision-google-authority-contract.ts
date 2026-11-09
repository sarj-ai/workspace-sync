import { z } from "zod";

import { GoogleUserIdSchema } from "../catalog/identity-authority.ts";

/** Minimal Google Directory user evidence persisted by the versioned deprovision snapshot. */
export const GitHubDeprovisionGoogleAuthorityUserSchema = z
  .object({
    aliases: z.array(z.email()).optional(),
    archived: z.boolean().optional(),
    customSchemas: z
      .object({
        SarjIdentity: z
          .object({
            githubLogin: z.string().min(1).optional(),
            githubUserId: z
              .string()
              .regex(/^[1-9]\d*$/u)
              .optional(),
          })
          .optional(),
      })
      .optional(),
    deletionTime: z.iso.datetime({ offset: true }).optional(),
    etag: z.string().trim().min(1).optional(),
    id: GoogleUserIdSchema,
    isAdmin: z.boolean().optional(),
    isDelegatedAdmin: z.boolean().optional(),
    nonEditableAliases: z.array(z.email()).optional(),
    primaryEmail: z.email(),
    suspended: z.boolean().optional(),
  })
  .readonly();

const GoogleAuthorityUsersShape = {
  deletedUsers: z.array(GitHubDeprovisionGoogleAuthorityUserSchema).readonly(),
  users: z.array(GitHubDeprovisionGoogleAuthorityUserSchema).readonly(),
} as const;

/** Complete live and deleted inventories captured by one bounded Directory refresh. */
export const GitHubDeprovisionGoogleAuthorityInventorySchema = z
  .strictObject({
    complete: z.literal(true),
    ...GoogleAuthorityUsersShape,
  })
  .readonly();

/** Planner-facing view of the same versioned inventory with its conservative capture time. */
export const GitHubDeprovisionGoogleAuthoritySnapshotSchema = z
  .strictObject({
    capturedAt: z.iso.datetime({ offset: true }),
    ...GoogleAuthorityUsersShape,
  })
  .readonly();

export type GitHubDeprovisionGoogleAuthoritySnapshotInput = z.input<
  typeof GitHubDeprovisionGoogleAuthoritySnapshotSchema
>;
