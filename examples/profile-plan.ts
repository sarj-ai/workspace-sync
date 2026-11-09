import { buildOrgProjectionPlan } from "../src/org-sync/model.ts";

export const profilePlan = buildOrgProjectionPlan({
  fieldIds: {
    linkedin: null,
    manages: "XfManages",
    reportsTo: "XfReportsTo",
    team: "XfTeam",
  },
  expectedRootGoogleUserIds: ["12345"],
  googleUsers: [
    {
      id: "12345",
      name: { fullName: "Ada Example" },
      primaryEmail: "ada@company.test",
      organizations: [
        { department: "Engineering", primary: true, title: "Staff Engineer" },
      ],
    },
  ],
  managedDomain: "company.test",
  slackUsers: [
    {
      id: "UADA",
      profile: {
        email: "ada@company.test",
        title: "Engineer",
        fields: { XfTeam: { value: "Engineering" } },
      },
    },
  ],
});
