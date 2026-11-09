import { describe, expect, it } from "vitest";

import {
  OrgSyncSettingsSchema,
  orgSyncSettings,
} from "../src/org-sync/config.ts";

describe("org sync settings", () => {
  it("pins the managed chart to an immutable Drive file and remains self-documented", () => {
    const expectedFileId = "test-org-chart-file";
    expect(OrgSyncSettingsSchema.parse(orgSyncSettings())).toMatchObject({
      allTeamDriveId: "test-shared-drive",
      orgChartFileId: expectedFileId,
    });
    expect(() =>
      OrgSyncSettingsSchema.parse({
        ...orgSyncSettings(),
        orgChartFileId: "bootstrap-required",
      }),
    ).toThrow(/immutable Drive file ID/);

    const shape = OrgSyncSettingsSchema.shape;
    for (const setting of Object.values(shape))
      expect(setting.description).toBeTruthy();
  });

  it("rejects policy relationships that cannot safely converge", () => {
    expect(() =>
      OrgSyncSettingsSchema.parse({
        ...orgSyncSettings(),
        allowedEmptyDepartmentGoogleUserIds: ["999"],
        fieldIds: {
          ...orgSyncSettings().fieldIds,
          manages: orgSyncSettings().fieldIds.reportsTo,
        },
      }),
    ).toThrow(/Slack field IDs must be distinct|empty-department exception/);
  });
});
