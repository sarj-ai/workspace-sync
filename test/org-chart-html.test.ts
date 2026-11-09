import { describe, expect, it } from "vitest";

import type { GoogleDirectoryUser } from "../src/org-sync/model.ts";
import {
  NUNITO_REGULAR_BASE64,
  NUNITO_SEMIBOLD_BASE64,
} from "../src/org-sync/org-chart-fonts.ts";
import { renderOrgChartHtml } from "../src/org-sync/render-org-chart-html.ts";

const POLICY = {
  allowedEmptyDepartmentGoogleUserIds: ["root"],
  excludedGoogleUserIds: [],
  expectedRootGoogleUserIds: ["root"],
  protectedDepartedGoogleUserIds: [],
  minimumGoogleParticipants: 1,
};

function person(
  id: string,
  email: string,
  options: {
    department?: string;
    github?: { login: string; userId: string };
    linkedin?: string;
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
    customSchemas: options.github
      ? {
          SarjIdentity: {
            githubLogin: options.github.login,
            githubUserId: options.github.userId,
          },
        }
      : undefined,
    relations: options.manager
      ? [{ type: "manager", value: options.manager }]
      : [],
    websites: options.linkedin
      ? [
          {
            customType: "LinkedIn",
            primary: true,
            type: "custom",
            value: options.linkedin,
          },
        ]
      : [],
  };
}

describe("Google organization directory HTML", () => {
  it.each([NUNITO_REGULAR_BASE64, NUNITO_SEMIBOLD_BASE64])(
    "embeds a valid Sarj Nunito TrueType font",
    (encoded) => {
      const decoded = Uint8Array.from(
        atob(encoded),
        (character) => character.codePointAt(0) ?? 0,
      );

      expect(decoded.byteLength).toBeGreaterThan(100_000);
      expect(decoded.slice(0, 4)).toEqual(new Uint8Array([0, 1, 0, 0]));
    },
  );

  it("is deterministic, self-contained, and works as an accessible document without JavaScript", () => {
    const users = [
      person("root", "root-admin@company.test", {
        department: "",
        name: "Morgan Example",
        title: "CEO",
      }),
      person("morgan", "morgan@company.test", {
        department: "Operations",
        github: { login: "Morgan-Test", userId: "583231" },
        linkedin: "https://www.linkedin.com/in/morgan-test",
        manager: "root-admin@company.test",
        name: "Morgan Example",
        title: "Head of Delivery / Operations",
      }),
    ];
    const photo = "data:image/jpeg;base64,/9j/2Q==";
    const first = renderOrgChartHtml(
      users,
      POLICY,
      new Map([["morgan", photo]]),
    );
    const second = renderOrgChartHtml(
      users.toReversed(),
      POLICY,
      new Map([["morgan", photo]]),
    );

    expect(first).toEqual(second);
    expect(first.html).toContain("<!doctype html>");
    expect(first.html).not.toMatch(
      /type=["']search|id=["']search|data-search/iu,
    );
    expect(first.html).not.toMatch(
      /\.search(?:-status)?\{|dataset\.search|function filter\(/u,
    );
    expect(first.html).not.toContain("No matches");
    expect(first.html).toContain("Head of Delivery / Operations");
    expect(first.html).toContain(photo);
    expect(first.html).toContain("No team");
    expect(first.html).toContain('<details class="person-card');
    expect(first.html).toContain("<summary>");
    expect(first.html).toContain(
      'Manages</dt><dd><a class="person-jump" href="#person-morgan">Morgan Example</a>',
    );
    expect(first.html).toContain(
      'Reports to</dt><dd><a class="person-jump" href="#person-root">Morgan Example</a>',
    );
    expect(first.html).toContain(
      'href="https://www.linkedin.com/in/morgan-test"',
    );
    expect(first.html).toContain('href="https://github.com/morgan-test"');
    expect(first.html).toContain("@morgan-test ↗");
    expect(first.html).not.toContain("583231");
    expect(first.html).toContain('id="linkedin-view"');
    expect(first.html).toContain('id="hierarchy-view"');
    expect(first.html).toContain('aria-label="Reporting tree"');
    expect(first.html).toContain(
      'aria-controls="hierarchy-view">Tree</button>',
    );
    expect(first.html).not.toContain(">Hierarchy</button>");
    expect(first.html).toContain(
      '<a class="hierarchy-person person-jump" href="#person-morgan">',
    );
    expect(first.html).toContain('<th scope="col">LinkedIn</th>');
    expect(first.html).toContain('<th scope="col">GitHub</th>');
    expect(first.html).toContain('font-family:"Nunito"');
    expect(first.html).toContain("@media(prefers-color-scheme:dark)");
    expect(first.html).not.toContain("Sarj · People");
    expect(first.html).not.toContain("<h1>Organization</h1>");
    expect(first.html).not.toContain("organized by team");
    expect(first.html).toContain('<script data-cfasync="false">');
    expect(first.html).not.toContain("Drag to pan");
    expect(first.html).not.toContain("Zoom");
    expect(first.html).not.toContain('class="chip');
    expect(first.html).not.toContain('class="details"');
    expect(first.html).not.toMatch(/<(?:script|img)[^>]+src=["']https?:/u);
    expect(first.html).not.toMatch(/<link[^>]+href=["']https?:/u);
    expect(first.photos).toBe(1);
  });

  it("sorts sections and every person list alphabetically", () => {
    const users = [
      person("root-z", "root-admin@company.test", {
        department: "",
        name: "Morgan Example",
        title: "CEO",
      }),
      person("root-a", "amir@company.test", {
        department: "",
        name: "Alex Example",
        title: "CEO",
      }),
      person("ops-z", "z@company.test", {
        department: "Operations",
        manager: "root-admin@company.test",
        name: "Zara Ops",
      }),
      person("ops-a", "a@company.test", {
        department: "Operations",
        manager: "root-admin@company.test",
        name: "Adam Ops",
      }),
      person("eng", "e@company.test", {
        manager: "root-admin@company.test",
        name: "Erin Example",
      }),
    ];
    const { html } = renderOrgChartHtml(users, {
      ...POLICY,
      allowedEmptyDepartmentGoogleUserIds: ["root-z", "root-a"],
      expectedRootGoogleUserIds: ["root-z", "root-a"],
    });

    expect(html.indexOf(">Engineering</h2>")).toBeLessThan(
      html.indexOf(">Founders</h2>"),
    );
    expect(html.indexOf(">Founders</h2>")).toBeLessThan(
      html.indexOf(">Operations</h2>"),
    );
    const founders = html.slice(
      html.indexOf(">Founders</h2>"),
      html.indexOf(">Operations</h2>"),
    );
    const operations = html.slice(
      html.indexOf(">Operations</h2>"),
      html.indexOf('id="linkedin-view"'),
    );
    expect(founders.indexOf("Alex Example")).toBeLessThan(
      founders.indexOf("Morgan Example"),
    );
    expect(operations.indexOf("Adam Ops")).toBeLessThan(
      operations.indexOf("Zara Ops"),
    );
  });

  it("neutralizes hostile Directory strings across HTML and inline JSON boundaries", () => {
    const hostile = person("root", "root-admin@company.test", {
      department: "",
      name: "</script>\u{2028}<img src=x onerror=alert(1)>",
      title: 'CEO & "owner"',
    });
    const { html } = renderOrgChartHtml([hostile], POLICY);

    expect(html).not.toContain("</script><img");
    expect(html).toContain("&lt;/script&gt;");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(html.match(/<\/script>/gu)).toHaveLength(1);
  });

  it("fails closed instead of rendering partial or hostile GitHub identities", () => {
    const incomplete = person("root", "root-admin@company.test", {
      department: "",
    });
    incomplete.customSchemas = { SarjIdentity: { githubLogin: "octocat" } };
    expect(() => renderOrgChartHtml([incomplete], POLICY)).toThrow(
      /invalid GitHub identity/,
    );

    const hostile = person("root", "root-admin@company.test", {
      department: "",
      github: { login: 'octocat" onclick="alert(1)', userId: "583231" },
    });
    expect(() => renderOrgChartHtml([hostile], POLICY)).toThrow(
      /invalid GitHub identity/,
    );
  });

  it("rejects untrusted or excessive photo data", () => {
    const user = person("root", "root-admin@company.test", { department: "" });
    expect(() =>
      renderOrgChartHtml(
        [user],
        POLICY,
        new Map([["root", "https://x.test/a.jpg"]]),
      ),
    ).toThrow(/unsafe data URL/);
    const huge = `data:image/png;base64,${"A".repeat(5_000_004)}`;
    expect(() =>
      renderOrgChartHtml([user], POLICY, new Map([["root", huge]])),
    ).toThrow(/safe total size/);
  });
});
