import { describe, expect, it } from "vitest";

import {
  buildOrgProjectionPlan,
  type GoogleDirectoryUser,
  isActiveGoogleDirectoryUser,
} from "../src/org-sync/model.ts";
import {
  orgChartParticipants,
  type OrgChartPolicy,
  renderOrgChartArtifact,
} from "../src/org-sync/org-chart.ts";

const person: GoogleDirectoryUser = {
  id: "10001",
  name: { fullName: "Automation Engineer" },
  primaryEmail: "automation@company.test",
  organizations: [{ primary: true, department: "Engineering" }],
};
const bot: GoogleDirectoryUser = {
  id: "10002",
  name: { fullName: "Directory Robot" },
  primaryEmail: "service@company.test",
  aliases: ["service-alias@company.test"],
  nonEditableAliases: ["service-legacy@company.test"],
  customSchemas: { WorkspaceAccount: { isBot: true } },
};
const policy: OrgChartPolicy = {
  allowedEmptyDepartmentGoogleUserIds: [],
  excludedGoogleUserIds: [],
  expectedRootGoogleUserIds: [person.id],
  minimumGoogleParticipants: 1,
  protectedDepartedGoogleUserIds: [],
};

describe("Google Workspace bot-account presentation flag", () => {
  it("omits flagged bots from the chart while including people regardless of their email", () => {
    const unflagged = {
      ...person,
      customSchemas: { WorkspaceAccount: { isBot: false } },
    };
    const artifact = renderOrgChartArtifact([unflagged, bot], policy);
    expect(artifact.people).toBe(1);
    expect(artifact.svg).toContain("Automation Engineer");
    expect(artifact.svg).not.toContain("Directory Robot");
  });

  it("counts only people toward the chart safety floor", () => {
    expect(() =>
      orgChartParticipants([person, bot], {
        ...policy,
        minimumGoogleParticipants: 2,
      }),
    ).toThrow("below chart safety floor");
  });

  it("skips bot profiles and aliases without reporting or clearing them as Slack orphans", () => {
    const emails = [
      person.primaryEmail,
      bot.primaryEmail,
      "service-alias@company.test",
      "service-legacy@company.test",
    ];
    const plan = buildOrgProjectionPlan({
      googleUsers: [person, bot],
      slackUsers: emails.map((email, index) => ({
        id: `U${String(index)}`,
        profile: {
          email,
          fields: { TEAM: { value: "Retain existing bot fields" } },
        },
      })),
      fieldIds: {
        linkedin: null,
        manages: "MANAGES",
        reportsTo: "REPORTS",
        team: "TEAM",
      },
      managedDomain: "company.test",
      expectedRootGoogleUserIds: [person.id],
    });
    expect(plan.errors).toEqual([]);
    expect(plan.profiles.map((profile) => profile.identity)).toEqual([
      person.primaryEmail,
    ]);
    expect(plan.googleParticipants).toBe(1);
    expect(plan.slackOrphans).toEqual([]);
    expect(plan.unplacedGoogle).toEqual([]);
  });

  it("preserves lifecycle authority for an active bot account", () => {
    expect(isActiveGoogleDirectoryUser(bot)).toBe(true);
  });
});
