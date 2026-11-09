import { describe, expect, it, vi } from "vitest";

import {
  AttioDeprovisionAuthorityRefreshError,
  refreshAttioDeprovisionAuthoritySnapshot,
} from "../src/identity-provisioning/attio-deprovision-authority-refresh.ts";

const CAPTURED_AT = "2026-09-01T12:00:00.000Z";
const WORKSPACE_ID = "e41575c4-362a-4be5-9bed-f3faaade5597";

function attio(overrides: Record<string, unknown> = {}) {
  return {
    capturedAt: CAPTURED_AT,
    complete: true,
    scimStatus: "available",
    scimUsers: [],
    token: { scopes: ["user_management:read"], workspaceId: WORKSPACE_ID },
    workspaceMembers: [],
    ...overrides,
  };
}

function google(overrides: Record<string, unknown> = {}) {
  return { complete: true, deletedUsers: [], users: [], ...overrides };
}

describe("Attio deprovision authority refresh", () => {
  it.each([
    ["incomplete Attio capture", attio({ complete: false }), google()],
    ["malformed Attio capture", { ...attio(), extra: true }, google()],
    ["incomplete Google capture", attio(), google({ complete: false })],
    ["malformed Google capture", attio(), { ...google(), extra: true }],
  ])(
    "preserves the previous snapshot on %s",
    async (_label, capturedAttio, capturedGoogle) => {
      const write = vi.fn();

      await expect(
        refreshAttioDeprovisionAuthoritySnapshot({
          captureAttio: () => Promise.resolve(capturedAttio),
          captureGoogle: () => Promise.resolve(capturedGoogle),
          store: { read: vi.fn(), write },
        }),
      ).rejects.toBeInstanceOf(AttioDeprovisionAuthorityRefreshError);
      expect(write).not.toHaveBeenCalled();
    },
  );

  it("preserves the previous snapshot when either capture rejects", async () => {
    const write = vi.fn();

    await expect(
      refreshAttioDeprovisionAuthoritySnapshot({
        captureAttio: () => Promise.resolve(attio()),
        captureGoogle: () => Promise.reject(new Error("google unavailable")),
        store: { read: vi.fn(), write },
      }),
    ).rejects.toMatchObject({
      code: "source-unavailable",
      component: "google-capture",
    });
    expect(write).not.toHaveBeenCalled();
  });

  it("writes one complete versioned snapshot and returns bounded counts", async () => {
    const write = vi.fn();
    const capturedAttio = attio({
      scimUsers: [
        {
          active: true,
          emails: [{ primary: true, value: "person@company.test" }],
          id: "b86a16a2-8c76-4439-bafb-610fc3bfdbd2",
          lastModified: "2026-08-01T00:00:00.000Z",
          userName: "person@company.test",
        },
      ],
      workspaceMembers: [
        {
          accessLevel: "member",
          emailAddress: "person@company.test",
          id: {
            workspaceId: WORKSPACE_ID,
            workspaceMemberId: "b86a16a2-8c76-4439-bafb-610fc3bfdbd2",
          },
        },
      ],
    });
    const capturedGoogle = google({
      deletedUsers: [{ id: "10002", primaryEmail: "deleted@company.test" }],
      users: [
        { id: "10001", primaryEmail: "person@company.test", suspended: true },
      ],
    });

    const result = await refreshAttioDeprovisionAuthoritySnapshot({
      captureAttio: () => Promise.resolve(capturedAttio),
      captureGoogle: () => Promise.resolve(capturedGoogle),
      store: { read: vi.fn(), write },
    });

    expect(write).toHaveBeenCalledOnce();
    expect(write).toHaveBeenCalledWith({
      attio: capturedAttio,
      capturedAt: CAPTURED_AT,
      google: capturedGoogle,
      schemaVersion: "attio-deprovision-authority-snapshot/v3",
    });
    expect(result).toEqual({
      capturedAt: CAPTURED_AT,
      deletedUsers: 1,
      scimStatus: "available",
      scimUsers: 1,
      users: 1,
      workspaceMembers: 1,
    });
  });

  it("observes Google lifecycle last and anchors freshness to the older Attio observation", async () => {
    const order: string[] = [];
    const write = vi.fn();
    const olderAttioCapture = "2026-09-01T11:55:00.000Z";

    await refreshAttioDeprovisionAuthoritySnapshot({
      captureAttio: async () => {
        order.push("attio");
        return attio({ capturedAt: olderAttioCapture });
      },
      captureGoogle: async () => {
        order.push("google");
        return google();
      },
      store: { read: vi.fn(), write },
    });

    expect(order).toEqual(["attio", "google"]);
    expect(write).toHaveBeenCalledWith(
      expect.objectContaining({ capturedAt: olderAttioCapture }),
    );
  });

  it.each([
    [
      "attio-capture",
      { capturedAttio: { ...attio(), extra: true }, capturedGoogle: google() },
    ],
    [
      "google-capture",
      { capturedAttio: attio(), capturedGoogle: { ...google(), extra: true } },
    ],
  ] as const)(
    "labels invalid %s evidence without provider details",
    async (component, inputs) => {
      await expect(
        refreshAttioDeprovisionAuthoritySnapshot({
          captureAttio: () => Promise.resolve(inputs.capturedAttio),
          captureGoogle: () => Promise.resolve(inputs.capturedGoogle),
          store: { read: vi.fn(), write: vi.fn() },
        }),
      ).rejects.toMatchObject({ code: "source-invalid", component });
    },
  );
});
