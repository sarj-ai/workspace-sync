import { z } from "zod";

export const GoogleDirectoryUserIdSchema = z
  .string()
  .regex(/^\d{5,30}$/)
  .brand<"GoogleDirectoryUserId">();

export const GoogleDirectoryLifecycleEventSchema = z.enum([
  "add",
  "delete",
  "makeAdmin",
  "undelete",
  "update",
]);
export type GoogleDirectoryUserId = z.output<
  typeof GoogleDirectoryUserIdSchema
>;

const RefetchedGoogleDirectoryUserSchema = z.strictObject({
  archived: z.boolean().optional().default(false),
  deletionTime: z.iso.datetime().optional(),
  id: GoogleDirectoryUserIdSchema,
  primaryEmail: z.email().optional(),
  suspended: z.boolean().optional().default(false),
});

const LiveGoogleIdentitySchema = z.strictObject({
  googleUserId: GoogleDirectoryUserIdSchema,
  primaryEmail: z.email(),
});

export const AuthoritativeGoogleDirectoryUserStateSchema = z.discriminatedUnion(
  "state",
  [
    LiveGoogleIdentitySchema.extend({ state: z.literal("active") }),
    LiveGoogleIdentitySchema.extend({ state: z.literal("suspended") }),
    LiveGoogleIdentitySchema.extend({ state: z.literal("archived") }),
    z.strictObject({
      deletedAt: z.iso.datetime(),
      googleUserId: GoogleDirectoryUserIdSchema,
      lastKnownPrimaryEmail: z.email().optional(),
      state: z.literal("deleted"),
    }),
  ],
);

export type AuthoritativeGoogleDirectoryUserState = z.output<
  typeof AuthoritativeGoogleDirectoryUserStateSchema
>;

export function authoritativeGoogleDirectoryUserState(
  input: z.input<typeof RefetchedGoogleDirectoryUserSchema>,
): AuthoritativeGoogleDirectoryUserState {
  const user = RefetchedGoogleDirectoryUserSchema.parse({
    archived: input.archived,
    deletionTime: input.deletionTime,
    id: input.id,
    primaryEmail: input.primaryEmail,
    suspended: input.suspended,
  });
  if (user.deletionTime !== undefined) {
    return AuthoritativeGoogleDirectoryUserStateSchema.parse({
      deletedAt: user.deletionTime,
      googleUserId: user.id,
      lastKnownPrimaryEmail: user.primaryEmail,
      state: "deleted",
    });
  }
  if (user.primaryEmail === undefined)
    throw new Error("google_directory_live_user_email_missing");
  if (user.archived) {
    return AuthoritativeGoogleDirectoryUserStateSchema.parse({
      googleUserId: user.id,
      primaryEmail: user.primaryEmail,
      state: "archived",
    });
  }
  if (user.suspended) {
    return AuthoritativeGoogleDirectoryUserStateSchema.parse({
      googleUserId: user.id,
      primaryEmail: user.primaryEmail,
      state: "suspended",
    });
  }
  return AuthoritativeGoogleDirectoryUserStateSchema.parse({
    googleUserId: user.id,
    primaryEmail: user.primaryEmail,
    state: "active",
  });
}

export const RefreshGoogleDirectoryUserTaskSchema = z.strictObject({
  event: GoogleDirectoryLifecycleEventSchema,
  googleUserId: GoogleDirectoryUserIdSchema,
  notificationId: z
    .string()
    .min(1)
    .max(200)
    .brand<"GoogleDirectoryNotificationId">(),
  notificationPrimaryEmail: z.email(),
  observedAt: z.iso.datetime(),
  type: z.literal("identity.refresh-google-directory-user"),
});

export type RefreshGoogleDirectoryUserTask = z.output<
  typeof RefreshGoogleDirectoryUserTaskSchema
>;
