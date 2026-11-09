import { describe, expect, it, vi } from "vitest";

import { GoogleDirectoryFullReconciler } from "../src/identity-lifecycle/google-directory-full-reconciler.ts";

describe("Google Directory full reconciliation", () => {
  it("does not read Directory state while the lifecycle kill switch is engaged", async () => {
    const listAllUsers = vi.fn();
    const reconcileUser = vi.fn();
    const result = await new GoogleDirectoryFullReconciler(
      { listAllUsers, listDeletedUsers: vi.fn() },
      { reconcileUser },
      false,
    ).reconcile(1_000);

    expect(result).toEqual({ kind: "disabled" });
    expect(listAllUsers).not.toHaveBeenCalled();
    expect(reconcileUser).not.toHaveBeenCalled();
  });

  it("routes active and deleted identities through the same fenced refresh path", async () => {
    const reconcileUser = vi.fn().mockResolvedValue(undefined);
    const result = await new GoogleDirectoryFullReconciler(
      {
        listAllUsers: vi.fn().mockResolvedValue([
          {
            id: "123456789012345678901",
            primaryEmail: "active@company.test",
          },
        ]),
        listDeletedUsers: vi.fn().mockResolvedValue([
          {
            deletionTime: "2026-08-20T11:00:00.000Z",
            id: "223456789012345678901",
            primaryEmail: "deleted@company.test",
          },
        ]),
      },
      { reconcileUser },
      true,
      () => Date.parse("2026-08-20T12:00:00.000Z"),
    ).reconcile(Date.parse("2026-08-20T12:00:00.000Z"));

    expect(result).toEqual({ active: 1, deleted: 1, kind: "reconciled" });
    expect(reconcileUser).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({ id: "123456789012345678901" }),
      "google-directory:full:1787227200000:123456789012345678901",
      "2026-08-20T12:00:00.000Z",
      "update",
      { kind: "audit-only" },
    );
    expect(reconcileUser).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ id: "223456789012345678901" }),
      "google-directory:full:1787227200000:223456789012345678901",
      "2026-08-20T12:00:00.000Z",
      "delete",
      undefined,
    );
  });

  it("fails closed if active and deleted snapshots contain the same immutable identity", async () => {
    const user = {
      id: "123456789012345678901",
      primaryEmail: "person@company.test",
    };
    const reconciler = new GoogleDirectoryFullReconciler(
      {
        listAllUsers: vi.fn().mockResolvedValue([user]),
        listDeletedUsers: vi
          .fn()
          .mockResolvedValue([
            { ...user, deletionTime: "2026-08-20T11:00:00.000Z" },
          ]),
      },
      { reconcileUser: vi.fn() },
      true,
    );

    await expect(reconciler.reconcile(1_000)).rejects.toThrow(
      "google_directory_full_reconciliation_identity_overlap",
    );
  });

  it("recovers suspended and archived users with runtime policy despite another subject failing", async () => {
    const users = [
      {
        id: "123456789012345678901",
        primaryEmail: "suspended@company.test",
        suspended: true,
      },
      {
        id: "223456789012345678901",
        primaryEmail: "archived@company.test",
        archived: true,
      },
    ];
    const recoverPending = vi
      .fn()
      .mockRejectedValue(new Error("pending event blocked"));
    const reconcileUser = vi
      .fn()
      .mockRejectedValueOnce(new Error("provider blocked"))
      .mockResolvedValue(undefined);
    const reconciler = new GoogleDirectoryFullReconciler(
      {
        listAllUsers: vi.fn().mockResolvedValue(users),
        listDeletedUsers: vi.fn().mockResolvedValue([]),
      },
      { recoverPending, reconcileUser },
      true,
    );

    await expect(reconciler.reconcile(1_000)).rejects.toThrow(
      "google_directory_full_reconciliation_incomplete",
    );
    expect(recoverPending).toHaveBeenCalledOnce();
    expect(reconcileUser).toHaveBeenCalledTimes(2);
    expect(reconcileUser).toHaveBeenNthCalledWith(
      1,
      users[0],
      expect.any(String),
      expect.any(String),
      "update",
      undefined,
    );
    expect(reconcileUser).toHaveBeenNthCalledWith(
      2,
      users[1],
      expect.any(String),
      expect.any(String),
      "update",
      undefined,
    );
  });
});
