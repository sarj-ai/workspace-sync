import { describe, expect, it } from "vitest";

import {
  authoritativeGoogleDirectoryUserState,
  RefreshGoogleDirectoryUserTaskSchema,
} from "../src/identity-lifecycle/contracts.ts";

const GOOGLE_USER_ID = "123456789012345678901";

describe("Google Directory lifecycle contracts", () => {
  it.each([
    [{ id: GOOGLE_USER_ID, primaryEmail: "active@company.test" }, "active"],
    [
      {
        id: GOOGLE_USER_ID,
        primaryEmail: "suspended@company.test",
        suspended: true,
      },
      "suspended",
    ],
    [
      {
        archived: true,
        id: GOOGLE_USER_ID,
        primaryEmail: "archived@company.test",
        suspended: true,
      },
      "archived",
    ],
    [
      {
        deletionTime: "2026-08-20T12:00:00.000Z",
        id: GOOGLE_USER_ID,
        primaryEmail: "deleted@company.test",
      },
      "deleted",
    ],
  ] as const)(
    "classifies an authoritative refetch as %s",
    (input, expectedState) => {
      expect(authoritativeGoogleDirectoryUserState(input).state).toBe(
        expectedState,
      );
    },
  );

  it("rejects a live refetch without an email", () => {
    expect(() =>
      authoritativeGoogleDirectoryUserState({ id: GOOGLE_USER_ID }),
    ).toThrow("google_directory_live_user_email_missing");
  });

  it("projects lifecycle fields from a full Google Directory record", () => {
    const directoryRecord = {
      aliases: ["alias@company.test"],
      etag: "directory-etag",
      id: GOOGLE_USER_ID,
      name: { fullName: "Example Person" },
      primaryEmail: "active@company.test",
    };

    expect(
      authoritativeGoogleDirectoryUserState(directoryRecord),
    ).toMatchObject({
      googleUserId: GOOGLE_USER_ID,
      primaryEmail: "active@company.test",
      state: "active",
    });
  });

  it("rejects sync as a queued user refresh event", () => {
    expect(
      RefreshGoogleDirectoryUserTaskSchema.safeParse({
        event: "sync",
        googleUserId: GOOGLE_USER_ID,
        notificationId: "channel:1",
        notificationPrimaryEmail: "person@company.test",
        observedAt: "2026-08-20T12:00:00.000Z",
        type: "identity.refresh-google-directory-user",
      }).success,
    ).toBe(false);
  });
});
