import { describe, expect, it } from "vitest";

import { AuthoritativeGoogleDirectoryNotificationSubjectResolver } from "../src/identity-lifecycle/authoritative-google-directory-notification-subject-resolver.ts";
import {
  GoogleDirectoryLifecycleNotificationSchema,
  GoogleDirectoryWatchUserBodySchema,
} from "../src/identity-lifecycle/contracts.ts";
import type { GoogleDirectoryUser } from "../src/org-sync/model.ts";

const notification = GoogleDirectoryLifecycleNotificationSchema.parse({
  channelId: "channel-000000000001",
  channelToken: "a-synthetic-channel-token-with-32-bytes",
  messageNumber: "42",
  resourceId: "resource",
  resourceUri: "https://admin.googleapis.com/admin/directory/v1/users",
  event: "delete",
});
const subject = GoogleDirectoryWatchUserBodySchema.parse({
  etag: "etag",
  id: "100000000000000000020",
  kind: "admin#directory#user",
  primaryEmail: "person@example.com",
});
const deleted: GoogleDirectoryUser = {
  id: subject.id,
  primaryEmail: subject.primaryEmail,
  deletionTime: "2026-01-01T00:00:00Z",
};

describe("deleted notification subject authority", () => {
  it.each([
    [{ ...deleted, deletionTime: undefined }],
    [deleted, deleted],
    [{ ...deleted, primaryEmail: "other@example.com" }],
  ])(
    "rejects missing, duplicate or conflicting tombstone authority",
    async (...rows) => {
      const resolver =
        new AuthoritativeGoogleDirectoryNotificationSubjectResolver({
          getUserById: async () => null,
          listDeletedUsers: async () => rows.flat(),
        });
      await expect(
        resolver.resolveImmutableGoogleUserId(notification, subject),
      ).resolves.toBeNull();
    },
  );

  it("accepts exactly one valid deleted immutable identity", async () => {
    const resolver =
      new AuthoritativeGoogleDirectoryNotificationSubjectResolver({
        getUserById: async () => null,
        listDeletedUsers: async () => [deleted],
      });
    await expect(
      resolver.resolveImmutableGoogleUserId(notification, subject),
    ).resolves.toBe(subject.id);
  });
});
