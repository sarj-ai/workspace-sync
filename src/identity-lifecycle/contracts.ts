import { z } from "zod";

export const GoogleDirectoryUserIdSchema = z
  .string()
  .regex(/^\d{5,30}$/)
  .brand<"GoogleDirectoryUserId">();

const GoogleWatchChannelIdSchema = z
  .string()
  .min(16)
  .max(64)
  .regex(/^[A-Za-z0-9._:-]+$/)
  .brand<"GoogleWatchChannelId">();
const GoogleWatchResourceIdSchema = z
  .string()
  .min(1)
  .max(512)
  .brand<"GoogleWatchResourceId">();
const GoogleWatchMessageNumberSchema = z
  .string()
  .max(20)
  .regex(/^(?:0|[1-9]\d*)$/)
  .brand<"GoogleWatchMessageNumber">();
const GoogleWatchChannelTokenSchema = z.string().min(32).max(256);
const GoogleWatchEventSchema = z.enum([
  "add",
  "delete",
  "makeAdmin",
  "sync",
  "undelete",
  "update",
]);
export const GoogleDirectoryLifecycleEventSchema =
  GoogleWatchEventSchema.exclude(["sync"]);

export const GoogleDirectoryWatchNotificationSchema = z.strictObject({
  channelExpiration: z.string().min(1).max(128).optional(),
  channelId: GoogleWatchChannelIdSchema,
  channelToken: GoogleWatchChannelTokenSchema,
  changed: z.string().min(1).max(512).optional(),
  event: GoogleWatchEventSchema,
  messageNumber: GoogleWatchMessageNumberSchema,
  resourceId: GoogleWatchResourceIdSchema,
  resourceUri: z.url({ protocol: /^https$/u }),
});
export const GoogleDirectoryLifecycleNotificationSchema =
  GoogleDirectoryWatchNotificationSchema.extend({
    event: GoogleDirectoryLifecycleEventSchema,
  });

export type GoogleDirectoryWatchNotification = z.output<
  typeof GoogleDirectoryWatchNotificationSchema
>;
export type GoogleDirectoryUserId = z.output<
  typeof GoogleDirectoryUserIdSchema
>;
export type GoogleDirectoryLifecycleNotification = z.output<
  typeof GoogleDirectoryLifecycleNotificationSchema
>;

export const GoogleDirectoryWatchUserBodySchema = z.strictObject({
  etag: z.string().min(1).max(512),
  id: GoogleDirectoryUserIdSchema,
  kind: z.literal("admin#directory#user"),
  primaryEmail: z.email(),
});

export type GoogleDirectoryWatchUserBody = z.output<
  typeof GoogleDirectoryWatchUserBodySchema
>;

export function parseGoogleDirectoryWatchHeaders(
  headers: Headers,
): GoogleDirectoryWatchNotification {
  return GoogleDirectoryWatchNotificationSchema.parse({
    channelExpiration: headers.get("x-goog-channel-expiration") ?? undefined,
    channelId: headers.get("x-goog-channel-id"),
    channelToken: headers.get("x-goog-channel-token"),
    changed: headers.get("x-goog-changed") ?? undefined,
    event: headers.get("x-goog-resource-state"),
    messageNumber: headers.get("x-goog-message-number"),
    resourceId: headers.get("x-goog-resource-id"),
    resourceUri: headers.get("x-goog-resource-uri"),
  });
}

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

export function googleDirectoryNotificationId(
  notification: GoogleDirectoryWatchNotification,
): z.input<typeof RefreshGoogleDirectoryUserTaskSchema>["notificationId"] {
  return `${notification.channelId}:${notification.messageNumber}`;
}
