import { describe, expect, it } from "vitest";

import { GoogleAccessAuditClient } from "../src/github-access-audit/google-access-audit-client.ts";
import type { GoogleDirectoryUser } from "../src/org-sync/model.ts";

const ACTIVE_USER: GoogleDirectoryUser = {
  id: "u1",
  primaryEmail: "ada@company.test",
};
const DELETED_USER: GoogleDirectoryUser = {
  deletionTime: "2026-01-01T00:00:00.000Z",
  id: "u2",
  primaryEmail: "former@company.test",
};

function client(options: {
  activeUsers?: GoogleDirectoryUser[];
  deletedUsers?: GoogleDirectoryUser[];
  groupRead: (email: string) => Promise<{
    email: string;
    id: string;
    members: {
      email: string;
      id: string;
      role: "MEMBER";
      status: "ACTIVE";
      type: "GROUP" | "USER";
    }[];
  }>;
  reportsFetch?: typeof fetch;
}) {
  return new GoogleAccessAuditClient({
    directory: {
      listAllUsers: async () => options.activeUsers ?? [ACTIVE_USER],
      listDeletedUsers: async () => options.deletedUsers ?? [DELETED_USER],
    },
    fetchImpl:
      options.reportsFetch ?? (async () => Response.json({ items: [] })),
    groups: {
      listGroups: async ([email]) =>
        email ? [await options.groupRead(email)] : [],
    },
    reportsAuth: { accessToken: async () => "reports-token" },
    userProject: "workspace-sync-test",
  });
}

describe("Google access authority snapshot", () => {
  it("retains documented Admin group membership events and ignores unrelated changes", async () => {
    const audit = client({
      groupRead: async (email) => ({ email, id: "root", members: [] }),
      reportsFetch: async () =>
        Response.json({
          items: [
            {
              id: { time: "2026-01-01T00:00:00.000Z" },
              events: [
                "ADD_GROUP_MEMBER",
                "REMOVE_GROUP_MEMBER",
                "UPDATE_GROUP_MEMBER",
              ].map((name) => ({
                name,
                parameters: [
                  { name: "GROUP_EMAIL", value: "Team-Eng@company.test" },
                  { name: "USER_EMAIL", value: "Ada@company.test" },
                ],
              })),
            },
          ],
        }),
    });
    const snapshot = await audit.capture(
      { mappedGroupEmails: [], rootGroupEmail: "team-eng@company.test" },
      "run-id",
    );
    expect(snapshot.reports.status).toBe("available");
    expect(snapshot.reports.events).toEqual(
      ["ADD_GROUP_MEMBER", "REMOVE_GROUP_MEMBER"].map((name) => ({
        name,
        time: "2026-01-01T00:00:00.000Z",
        groupEmail: "team-eng@company.test",
        subjectEmail: "ada@company.test",
        parameters: {
          "GROUP_EMAIL": ["Team-Eng@company.test"],
          "USER_EMAIL": ["Ada@company.test"],
        },
      })),
    );
  });

  it("traverses nested groups once, tolerates cycles, and includes deleted users", async () => {
    const reads: string[] = [];
    const audit = client({
      groupRead: async (email) => {
        reads.push(email);
        if (email === "team-eng@company.test") {
          return {
            email,
            id: "root",
            members: [
              {
                email: "team-child@company.test",
                id: "child",
                role: "MEMBER",
                status: "ACTIVE",
                type: "GROUP",
              },
            ],
          };
        }
        return {
          email,
          id: "child",
          members: [
            {
              email: "team-eng@company.test",
              id: "root",
              role: "MEMBER",
              status: "ACTIVE",
              type: "GROUP",
            },
            {
              email: "ada@company.test",
              id: "u1",
              role: "MEMBER",
              status: "ACTIVE",
              type: "USER",
            },
          ],
        };
      },
    });
    const snapshot = await audit.capture(
      {
        mappedGroupEmails: ["team-child@company.test"],
        rootGroupEmail: "team-eng@company.test",
      },
      "run-id",
    );
    expect(snapshot.complete).toBe(true);
    expect(snapshot.reachableGroupIds).toEqual(["child", "root"]);
    expect(snapshot.users).toContainEqual(
      expect.objectContaining({ deleted: true, id: "u2" }),
    );
    expect(reads).toEqual(["team-eng@company.test", "team-child@company.test"]);
  });

  it("retains partial evidence when one configured group fails", async () => {
    const audit = client({
      groupRead: async (email) => {
        if (email === "missing@company.test") throw new Error("not found");
        return { email, id: "root", members: [] };
      },
    });
    const snapshot = await audit.capture(
      {
        mappedGroupEmails: ["missing@company.test"],
        rootGroupEmail: "team-eng@company.test",
      },
      "run-id",
    );
    expect(snapshot.complete).toBe(false);
    expect(snapshot.groups).toHaveLength(1);
    expect(snapshot.users).toHaveLength(2);
    expect(snapshot.issues).toContainEqual(
      expect.objectContaining({ code: "group_read_failed" }),
    );
  });

  it("marks repeated Reports pagination partial without losing the Directory graph", async () => {
    const audit = client({
      groupRead: async (email) => ({ email, id: "root", members: [] }),
      reportsFetch: async () =>
        Response.json({ items: [], nextPageToken: "repeat" }),
    });
    const snapshot = await audit.capture(
      { mappedGroupEmails: [], rootGroupEmail: "team-eng@company.test" },
      "run-id",
    );
    expect(snapshot.complete).toBe(true);
    expect(snapshot.groups).toHaveLength(1);
    expect(snapshot.reports).toEqual(
      expect.objectContaining({
        issues: ["Repeated Google Reports page token"],
        status: "partial",
      }),
    );
  });

  it("fails closed on active/deleted address reuse and alias collisions", async () => {
    const audit = client({
      activeUsers: [
        ACTIVE_USER,
        {
          aliases: ["shared@company.test"],
          id: "u3",
          primaryEmail: "grace@company.test",
        },
        {
          aliases: ["shared@company.test"],
          id: "u4",
          primaryEmail: "linus@company.test",
        },
      ],
      deletedUsers: [{ ...DELETED_USER, primaryEmail: "ada@company.test" }],
      groupRead: async (email) => ({ email, id: "root", members: [] }),
    });
    const snapshot = await audit.capture(
      { mappedGroupEmails: [], rootGroupEmail: "team-eng@company.test" },
      "run-id",
    );
    expect(snapshot.complete).toBe(false);
    expect(
      snapshot.issues.filter(
        (issue) => issue.code === "google_identity_collision",
      ),
    ).toHaveLength(2);
  });
});
