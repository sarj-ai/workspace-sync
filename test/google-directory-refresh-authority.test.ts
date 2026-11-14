import { describe, expect, it, vi } from "vitest";

import { RefreshGoogleDirectoryUserTaskSchema } from "../src/identity-lifecycle/contracts.ts";
import {
  GoogleDirectoryLifecycleRefreshHandler,
  type GoogleDirectoryLifecycleRefreshClient,
  type GoogleDirectoryLifecycleRefreshStore,
} from "../src/identity-lifecycle/google-directory-lifecycle-refresh-handler.ts";

const GOOGLE_USER_ID = "123456789012345678901";
const task = (event: "delete" | "update") =>
  RefreshGoogleDirectoryUserTaskSchema.parse({
    event,
    googleUserId: GOOGLE_USER_ID,
    notificationId: "retained-queue-event:1",
    notificationPrimaryEmail: "unverified-transport@company.test",
    observedAt: "2026-08-20T12:00:00.000Z",
    type: "identity.refresh-google-directory-user",
  });
function fixture() {
  const client = {
    getUserById: vi
      .fn<GoogleDirectoryLifecycleRefreshClient["getUserById"]>()
      .mockResolvedValue(null),
    listDeletedAuthorityUsers: vi
      .fn<GoogleDirectoryLifecycleRefreshClient["listDeletedAuthorityUsers"]>()
      .mockResolvedValue([]),
  } satisfies GoogleDirectoryLifecycleRefreshClient;
  const store = {
    recordLifecycleEvent: vi
      .fn<GoogleDirectoryLifecycleRefreshStore["recordLifecycleEvent"]>()
      .mockResolvedValue("recorded"),
    claimLifecycleEvent: vi
      .fn<GoogleDirectoryLifecycleRefreshStore["claimLifecycleEvent"]>()
      .mockResolvedValue({ kind: "unavailable" }),
    claimNextLifecycleEvent:
      vi.fn<GoogleDirectoryLifecycleRefreshStore["claimNextLifecycleEvent"]>(),
    clearTombstone:
      vi.fn<GoogleDirectoryLifecycleRefreshStore["clearTombstone"]>(),
    completeLifecycleEvent:
      vi.fn<GoogleDirectoryLifecycleRefreshStore["completeLifecycleEvent"]>(),
    holdExpiredDeletedAuthority:
      vi.fn<
        GoogleDirectoryLifecycleRefreshStore["holdExpiredDeletedAuthority"]
      >(),
    recordTombstone:
      vi.fn<GoogleDirectoryLifecycleRefreshStore["recordTombstone"]>(),
    retryLifecycleEvent:
      vi.fn<GoogleDirectoryLifecycleRefreshStore["retryLifecycleEvent"]>(),
  } satisfies GoogleDirectoryLifecycleRefreshStore;
  return {
    client,
    store,
    handler: new GoogleDirectoryLifecycleRefreshHandler({ client, store }),
  };
}

describe("retained queued refresh authority", () => {
  it.each(["delete", "update"] as const)(
    "does not manufacture %s authority from an absent user or transport fields",
    async (event) => {
      const { handler, client, store } = fixture();
      await expect(handler.handle(task(event))).rejects.toThrow(
        "google_directory_authoritative_user_missing",
      );
      expect(client.getUserById).toHaveBeenCalledOnce();
      expect(client.listDeletedAuthorityUsers).toHaveBeenCalledOnce();
      expect(store.recordLifecycleEvent).not.toHaveBeenCalled();
      expect(store.claimLifecycleEvent).not.toHaveBeenCalled();
      expect(store.recordTombstone).not.toHaveBeenCalled();
    },
  );

  it("records positive deleted authority only from the exact current deleted-user inventory", async () => {
    const { handler, client, store } = fixture();
    client.listDeletedAuthorityUsers.mockResolvedValue([
      {
        id: GOOGLE_USER_ID,
        primaryEmail: "verified-provider@company.test",
        deletionTime: "2026-08-19T11:00:00.000Z",
      },
    ]);
    await expect(handler.handle(task("delete"))).resolves.toBeUndefined();
    expect(store.recordLifecycleEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        authorityState: "deleted",
        googleUserId: GOOGLE_USER_ID,
        kind: "delete",
        eventKey: "retained-queue-event:1",
      }),
    );
    expect(store.recordTombstone).not.toHaveBeenCalled();
  });

  it("preserves provider failure instead of admitting a queued deletion", async () => {
    const { handler, client, store } = fixture();
    const failure = new Error("Google Directory transport failed");
    client.getUserById.mockRejectedValue(failure);
    await expect(handler.handle(task("delete"))).rejects.toBe(failure);
    expect(client.listDeletedAuthorityUsers).not.toHaveBeenCalled();
    expect(store.recordLifecycleEvent).not.toHaveBeenCalled();
  });
});
