import { describe, expect, it, vi } from "vitest";

import { GoogleDirectoryAuthorityReader } from "../src/identity-lifecycle/google-directory-authority-reader.ts";

const GOOGLE_USER_ID = "123456789012345678901";
const RUN_ID = "00000000-0000-4000-8000-000000000001";
const DEADLINE_AT = Date.parse("2026-08-31T12:00:00.000Z");

describe("GoogleDirectoryAuthorityReader", () => {
  it("returns the exact live immutable-ID record without reading deleted users", async () => {
    const liveUser = {
      id: GOOGLE_USER_ID,
      primaryEmail: "person@company.test",
      suspended: true,
    };
    const getUserById = vi.fn().mockResolvedValue(liveUser);
    const listDeletedAuthorityUsers = vi.fn();
    const reader = new GoogleDirectoryAuthorityReader({
      getUserById,
      listDeletedAuthorityUsers,
    });

    await expect(
      reader.getUserById(GOOGLE_USER_ID, RUN_ID, DEADLINE_AT),
    ).resolves.toBe(liveUser);
    expect(getUserById).toHaveBeenCalledWith(
      GOOGLE_USER_ID,
      RUN_ID,
      DEADLINE_AT,
    );
    expect(listDeletedAuthorityUsers).not.toHaveBeenCalled();
  });

  it("uses the complete deleted inventory only after users.get returns 404", async () => {
    const deletedUser = {
      deletionTime: "2026-08-30T12:00:00.000Z",
      id: GOOGLE_USER_ID,
      primaryEmail: "person@company.test",
    };
    const listDeletedAuthorityUsers = vi
      .fn()
      .mockResolvedValue([
        { id: "987654321098765432109", primaryEmail: "other@company.test" },
        deletedUser,
      ]);
    const reader = new GoogleDirectoryAuthorityReader({
      getUserById: vi.fn().mockResolvedValue(null),
      listDeletedAuthorityUsers,
    });

    await expect(
      reader.getUserById(GOOGLE_USER_ID, RUN_ID, DEADLINE_AT),
    ).resolves.toBe(deletedUser);
    expect(listDeletedAuthorityUsers).toHaveBeenCalledWith(RUN_ID, DEADLINE_AT);
  });

  it("returns null when the exact immutable ID is absent from both authoritative surfaces", async () => {
    const reader = new GoogleDirectoryAuthorityReader({
      getUserById: vi.fn().mockResolvedValue(null),
      listDeletedAuthorityUsers: vi.fn().mockResolvedValue([
        {
          deletionTime: "2026-08-30T12:00:00.000Z",
          id: "987654321098765432109",
          primaryEmail: "person@company.test",
        },
      ]),
    });

    await expect(
      reader.getUserById(GOOGLE_USER_ID, RUN_ID, DEADLINE_AT),
    ).resolves.toBeNull();
  });

  it("propagates users.get provider failures without reading deleted users", async () => {
    const providerError = new Error("Google Directory users.get HTTP 503");
    const listDeletedAuthorityUsers = vi.fn();
    const reader = new GoogleDirectoryAuthorityReader({
      getUserById: vi.fn().mockRejectedValue(providerError),
      listDeletedAuthorityUsers,
    });

    await expect(
      reader.getUserById(GOOGLE_USER_ID, RUN_ID, DEADLINE_AT),
    ).rejects.toBe(providerError);
    expect(listDeletedAuthorityUsers).not.toHaveBeenCalled();
  });

  it("fails closed when users.get returns a different immutable ID", async () => {
    const reader = new GoogleDirectoryAuthorityReader({
      getUserById: vi.fn().mockResolvedValue({
        id: "987654321098765432109",
        primaryEmail: "person@company.test",
      }),
      listDeletedAuthorityUsers: vi.fn(),
    });

    await expect(
      reader.getUserById(GOOGLE_USER_ID, RUN_ID, DEADLINE_AT),
    ).rejects.toThrow("google_directory_authority_user_id_mismatch");
  });

  it("fails closed when the deleted inventory contains duplicate immutable IDs", async () => {
    const deletedUser = {
      deletionTime: "2026-08-30T12:00:00.000Z",
      id: GOOGLE_USER_ID,
      primaryEmail: "person@company.test",
    };
    const reader = new GoogleDirectoryAuthorityReader({
      getUserById: vi.fn().mockResolvedValue(null),
      listDeletedAuthorityUsers: vi
        .fn()
        .mockResolvedValue([deletedUser, deletedUser]),
    });

    await expect(
      reader.getUserById(GOOGLE_USER_ID, RUN_ID, DEADLINE_AT),
    ).rejects.toThrow("google_directory_authority_duplicate_deleted_user");
  });

  it.each([undefined, "not-an-iso-datetime"])(
    "fails closed when an exact deleted user has invalid deletionTime %s",
    async (deletionTime) => {
      const reader = new GoogleDirectoryAuthorityReader({
        getUserById: vi.fn().mockResolvedValue(null),
        listDeletedAuthorityUsers: vi.fn().mockResolvedValue([
          {
            deletionTime,
            id: GOOGLE_USER_ID,
            primaryEmail: "person@company.test",
          },
        ]),
      });

      await expect(
        reader.getUserById(GOOGLE_USER_ID, RUN_ID, DEADLINE_AT),
      ).rejects.toThrow(
        "google_directory_authority_deleted_user_deletion_time_invalid",
      );
    },
  );

  it("rejects non-numeric identifiers before making a provider call", async () => {
    const getUserById = vi.fn();
    const reader = new GoogleDirectoryAuthorityReader({
      getUserById,
      listDeletedAuthorityUsers: vi.fn(),
    });

    await expect(
      reader.getUserById("person@company.test", RUN_ID, DEADLINE_AT),
    ).rejects.toThrow();
    expect(getUserById).not.toHaveBeenCalled();
  });
});
