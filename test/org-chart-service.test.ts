import { describe, expect, it } from "vitest";

import type { GoogleDirectoryUser } from "../src/org-sync/model.ts";
import {
  type OrgChartDrivePort,
  OrgChartService,
} from "../src/org-sync/org-chart-service.ts";

const ORG_CHART_POLICY = {
  allowedEmptyDepartmentGoogleUserIds: [],
  excludedGoogleUserIds: ["excluded"],
  expectedRootGoogleUserIds: ["active"],
  minimumGoogleParticipants: 1,
  protectedDepartedGoogleUserIds: ["deleted"],
};

function person(
  id: string,
  state: Partial<GoogleDirectoryUser> = {},
): GoogleDirectoryUser {
  return {
    id,
    name: { fullName: id },
    organizations: [
      { department: "Engineering", primary: true, title: "Engineer" },
    ],
    primaryEmail: `${id}@company.test`,
    relations: [],
    ...state,
  };
}

describe("OrgChartService", () => {
  it("renders deterministic initials without fetching non-canonical Directory photo bytes", async () => {
    const drive: OrgChartDrivePort = {
      fileId: "chart-file",
      readContentSha256: async () => "current-sha256",
      upsert: async () => ({
        action: "unchanged",
        fileId: "chart-file",
        webViewLink: "https://drive.google.com/file/d/chart-file/view",
      }),
    };
    const service = new OrgChartService(drive, ORG_CHART_POLICY);

    const report = await service.run({
      mode: "audit",
      users: [
        person("active"),
        person("excluded", {
          thumbnailPhotoUrl: "https://example.com/excluded.jpg",
        }),
        person("deleted", { deletionTime: "2026-08-26T12:00:00.000Z" }),
        person("suspended", { suspended: true }),
        person("archived", { archived: true }),
      ],
    });

    expect(report).toMatchObject({
      fileId: "chart-file",
      people: 1,
      photos: 0,
    });
  });
});
