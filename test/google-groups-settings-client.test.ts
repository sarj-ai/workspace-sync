import { describe, expect, it, vi } from "vitest";

import { GoogleGroupsSettingsClient } from "../src/org-sync/google-groups-settings-client.ts";

const TARGET = {
  googleGroupEmail: "office-north@company.test",
  googleGroupId: "immutable-id",
};

describe("Google Groups Settings client", () => {
  it("uses the dedicated settings scope and returns an exact GET snapshot", async () => {
    const accessToken = vi.fn(async () => "token");
    const fetchImpl = vi.fn(async () =>
      Response.json({
        email: TARGET.googleGroupEmail,
        etag: "etag-1",
        kind: "groupsSettings#groups",
        whoCanJoin: "INVITED_CAN_JOIN",
      }),
    );
    const client = new GoogleGroupsSettingsClient({
      auth: { accessToken },
      fetchImpl,
    });

    await expect(client.readSettings(TARGET, "run-id")).resolves.toMatchObject({
      etag: "etag-1",
      googleGroupEmail: TARGET.googleGroupEmail,
      settings: { whoCanJoin: "INVITED_CAN_JOIN" },
    });
    expect(accessToken).toHaveBeenCalledExactlyOnceWith(
      "https://www.googleapis.com/auth/apps.groups.settings",
      "run-id",
    );
    expect(fetchImpl).toHaveBeenCalledExactlyOnceWith(
      "https://www.googleapis.com/groups/v1/groups/office-north%40company.test",
      expect.objectContaining({
        headers: { authorization: "Bearer token" },
      }),
    );
  });

  it("fails closed if Groups Settings resolves a different email", async () => {
    const client = new GoogleGroupsSettingsClient({
      auth: { accessToken: vi.fn(async () => "token") },
      fetchImpl: vi.fn(async () =>
        Response.json({ email: "other@company.test", etag: "etag-1" }),
      ),
    });

    await expect(client.readSettings(TARGET, "run-id")).rejects.toThrow(
      "Google Groups Settings returned a different group email",
    );
  });
});
