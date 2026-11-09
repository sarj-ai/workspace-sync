import { describe, expect, it } from "vitest";

import type { GoogleDirectoryUser } from "../src/org-sync/model.ts";
import {
  chartPeople,
  renderOrgChartArtifact,
  renderOrgChartSvg,
} from "../src/org-sync/org-chart.ts";

function person(
  id: string,
  email: string,
  options: {
    department?: string;
    manager?: string;
    name?: string;
    title?: string;
  } = {},
): GoogleDirectoryUser {
  return {
    id,
    name: { fullName: options.name ?? email.split("@", 1)[0] },
    organizations: [
      {
        department: options.department ?? "Engineering",
        primary: true,
        title: options.title ?? "Engineer",
      },
    ],
    primaryEmail: email,
    relations: options.manager
      ? [{ type: "manager", value: options.manager }]
      : [],
  };
}

describe("Google organization chart renderer", () => {
  it("renders a deterministic, responsive, accessible forest in hierarchy order", () => {
    const users = [
      person("2", "root-admin@company.test", {
        name: "Morgan Example",
        title: "CEO",
      }),
      person("1", "amir@company.test", { name: "Amir Example", title: "CEO" }),
      person("3", "morgan@company.test", {
        department: "Operations",
        manager: "root-admin@company.test",
        name: "Morgan & <Delivery>",
        title: "Head of Delivery / Operations",
      }),
    ];
    const first = renderOrgChartSvg(users);
    const second = renderOrgChartSvg(users.toReversed());

    expect(first).toBe(second);
    expect(first).toContain('viewBox="0 0 ');
    expect(first).toContain('width="100%"');
    expect(first).toContain(
      "Google Workspace Directory is the source of record",
    );
    expect(first).toContain("Head of Delivery / Operations");
    expect(first).toContain("Morgan &amp; &lt;Delivery&gt;");
    expect(first.indexOf("Morgan Example")).toBeLessThan(
      first.indexOf("Morgan &amp; &lt;Delivery&gt;"),
    );
  });

  it("fails closed for unresolved managers, cycles, and multiple primary organizations", () => {
    expect(() =>
      renderOrgChartSvg([
        person("1", "a@company.test", { manager: "missing@company.test" }),
      ]),
    ).toThrow(/cannot be resolved/);
    expect(() =>
      renderOrgChartSvg([
        person("1", "a@company.test", { manager: "b@company.test" }),
        person("2", "b@company.test", { manager: "a@company.test" }),
      ]),
    ).toThrow(/cycle/);
    const invalid = person("1", "a@company.test");
    invalid.organizations = [
      { department: "Engineering", primary: true },
      { department: "Product", primary: true },
    ];
    expect(() => renderOrgChartSvg([invalid])).toThrow(
      /more than one primary organization/,
    );
  });

  it("ignores suspended accounts and only explicitly excluded service identities", () => {
    const suspended = person("2", "old@company.test");
    suspended.suspended = true;
    const service: GoogleDirectoryUser = {
      id: "3",
      primaryEmail: "service@company.test",
    };
    const svg = renderOrgChartSvg(
      [person("1", "root-admin@company.test"), suspended, service],
      ["3"],
    );
    expect(svg).toContain("1 active people");
    expect(svg).not.toContain("old@company.test");
    expect(svg).not.toContain("service@company.test");
    const visibleUnplaced = renderOrgChartSvg([
      person("1", "root-admin@company.test"),
      service,
    ]);
    expect(visibleUnplaced).toContain("Needs placement");
    expect(visibleUnplaced).toContain("Google profile incomplete");
  });

  it("preserves reporting through a suspended manager by using its active manager", () => {
    const root = person("root", "root-admin@company.test", { title: "CEO" });
    const suspendedManager = person("manager", "manager-example@company.test", {
      manager: "root-admin@company.test",
      title: "Head of Engineering",
    });
    suspendedManager.suspended = true;
    const activeReport = person("report", "report-example@company.test", {
      manager: "manager-example@company.test",
    });
    const policy = {
      allowedEmptyDepartmentGoogleUserIds: [],
      excludedGoogleUserIds: [],
      expectedRootGoogleUserIds: ["root"],
      minimumGoogleParticipants: 2,
      protectedDepartedGoogleUserIds: [],
    };

    const people = chartPeople([root, suspendedManager, activeReport], policy);

    expect(people).toHaveLength(2);
    expect(people.find(({ id }) => id === "report")?.managerId).toBe("root");
    expect(people.some(({ id }) => id === "manager")).toBe(false);
  });

  it("fails closed when an inactive manager chain has no active ancestor or contains a cycle", () => {
    const report = person("report", "report@company.test", {
      manager: "inactive@company.test",
    });
    const inactive = person("inactive", "inactive@company.test");
    inactive.suspended = true;
    expect(() => renderOrgChartSvg([report, inactive])).toThrow(
      /no active manager/,
    );

    inactive.relations = [{ type: "manager", value: "archived@company.test" }];
    const archived = person("archived", "archived@company.test", {
      manager: "inactive@company.test",
    });
    archived.archived = true;
    expect(() => renderOrgChartSvg([report, inactive, archived])).toThrow(
      /contains a cycle/,
    );
  });

  it("keeps a 48-person organization bounded by hierarchy depth rather than leaf count", () => {
    const root = person("root", "root@company.test", { title: "CEO" });
    const reports = Array.from({ length: 47 }, (_, index) =>
      person(
        `person-${String(index)}`,
        `person-${String(index)}@company.test`,
        {
          manager: "root@company.test",
        },
      ),
    );
    const svg = renderOrgChartSvg([root, ...reports]);
    const viewBox = /viewBox="0 0 (\d+) (\d+)"/.exec(svg);
    expect(viewBox).not.toBeNull();
    expect(Number(viewBox?.[1])).toBeLessThan(1_000);
    expect(Number(viewBox?.[2])).toBeGreaterThan(4_000);
  });

  it("marks non-root manager and department gaps and validates the authority policy", () => {
    const root = person("root", "root@company.test", { title: "CEO" });
    const missingManager = person("person", "person@company.test");
    const missingDepartment = person("teamless", "teamless@company.test", {
      manager: "root@company.test",
    });
    missingDepartment.organizations = [{ department: "", primary: true }];
    const suspended = person("departed", "departed@company.test");
    suspended.suspended = true;
    const policy = {
      allowedEmptyDepartmentGoogleUserIds: [],
      excludedGoogleUserIds: [],
      expectedRootGoogleUserIds: ["root"],
      protectedDepartedGoogleUserIds: ["departed"],
      minimumGoogleParticipants: 3,
    };
    const artifact = renderOrgChartArtifact(
      [root, missingManager, missingDepartment, suspended],
      policy,
    );
    expect(artifact.people).toBe(3);
    expect(artifact.svg).toContain("Google manager missing");
    expect(artifact.svg).toContain("Google department missing");

    const invalidRoot = structuredClone(root);
    invalidRoot.relations = [{ type: "manager", value: "person@company.test" }];
    expect(() =>
      renderOrgChartArtifact(
        [invalidRoot, missingManager, missingDepartment, suspended],
        policy,
      ),
    ).toThrow(/reporting root.*manager/);
    expect(() =>
      renderOrgChartArtifact([root, missingManager, missingDepartment], policy),
    ).not.toThrow();
    expect(() =>
      renderOrgChartArtifact(
        [
          root,
          missingManager,
          missingDepartment,
          {
            ...suspended,
            deletionTime: "2026-08-27T00:00:00.000Z",
            suspended: undefined,
          },
        ],
        policy,
      ),
    ).not.toThrow();
    expect(() =>
      renderOrgChartArtifact(
        [
          root,
          missingManager,
          missingDepartment,
          { ...suspended, archived: true },
        ],
        policy,
      ),
    ).not.toThrow();
    expect(() =>
      renderOrgChartArtifact(
        [
          root,
          missingManager,
          missingDepartment,
          person("departed", "departed@company.test"),
        ],
        policy,
      ),
    ).toThrow(/departed.*restored to active/);
  });
});
