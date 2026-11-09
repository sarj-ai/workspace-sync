import { describe, expect, it } from "vitest";

import type { GoogleGroupSnapshot } from "../src/org-sync/channel-model.ts";
import { orgSyncSettings } from "../src/org-sync/config.ts";
import type { GoogleDirectoryUser } from "../src/org-sync/model.ts";
import { planGoogleGroupCleanup } from "../src/workspace-directory/google-group-cleanup-sync.ts";

const ACTIVE_ID = "10000000001";
const SUSPENDED_ID = "10000000002";
const DELETED_ID = "10000000003";
const ARCHIVED_ID = "10000000004";

function user(
  id: string,
  overrides: Partial<GoogleDirectoryUser> = {},
): GoogleDirectoryUser {
  return {
    id,
    isAdmin: false,
    isDelegatedAdmin: false,
    primaryEmail: `${id}@company.test`,
    ...overrides,
  };
}

function group(
  id: string,
  email: string,
  members: GoogleGroupSnapshot["members"],
): GoogleGroupSnapshot {
  return { email, id, members };
}

function pins(groups: readonly GoogleGroupSnapshot[]) {
  return groups.map(({ email, id }) => ({ email, id }));
}

const DIRECTORY_USERS: GoogleDirectoryUser[] = [
  user(ACTIVE_ID),
  user(SUSPENDED_ID, {
    primaryEmail: "suspended@company.test",
    suspended: true,
  }),
  user(DELETED_ID, {
    deletionTime: "2026-09-01T12:00:00.000Z",
    primaryEmail: "deleted@company.test",
  }),
  user(ARCHIVED_ID, { archived: true, primaryEmail: "archived@company.test" }),
];

describe("planGoogleGroupCleanup", () => {
  it.each([
    { isAdmin: true },
    { isDelegatedAdmin: true },
    { isAdmin: undefined },
    { isDelegatedAdmin: undefined },
    { aliases: [orgSyncSettings().googleAdminSubject] },
    { nonEditableAliases: [orgSyncSettings().googleAdminSubject] },
    { id: orgSyncSettings().protectedDepartedGoogleUserIds[0] ?? "" },
  ])(
    "excludes protected or unknown Directory authority: %j",
    async (overrides) => {
      const target = user(SUSPENDED_ID, { suspended: true, ...overrides });
      const managedGoogleGroups = [
        group("group-platform", "team-platform@company.test", [
          {
            email: target.primaryEmail,
            id: target.id,
            role: "MEMBER",
            type: "USER",
            status: "ACTIVE",
          },
        ]),
      ];
      const plan = await planGoogleGroupCleanup({
        directoryUsers: [target],
        managedGoogleGroups,
        managedGoogleGroupPins: pins(managedGoogleGroups),
      });
      expect(plan.actions).toEqual([]);
      expect(plan.excludedGoogleUserIds).toContain(target.id);
    },
  );
  it("removes only direct MEMBER identities authoritatively archived, suspended, or deleted", async () => {
    const managedGoogleGroups = [
      group("group-platform", "team-platform@company.test", [
        {
          email: "active@company.test",
          id: ACTIVE_ID,
          role: "MEMBER",
          status: "ACTIVE",
          type: "USER",
        },
        {
          email: "old-suspended@company.test",
          id: SUSPENDED_ID,
          role: "MEMBER",
          status: "SUSPENDED",
          type: "USER",
        },
        {
          email: "old-deleted@company.test",
          id: DELETED_ID,
          role: "MEMBER",
          status: "ACTIVE",
          type: "USER",
        },
        {
          email: "archived@company.test",
          id: ARCHIVED_ID,
          role: "MEMBER",
          status: "ARCHIVED",
          type: "USER",
        },
        {
          email: "nested@company.test",
          id: SUSPENDED_ID,
          role: "MEMBER",
          status: "ACTIVE",
          type: "GROUP",
        },
      ]),
    ];
    const plan = await planGoogleGroupCleanup({
      directoryUsers: DIRECTORY_USERS,
      managedGoogleGroupPins: pins(managedGoogleGroups),
      managedGoogleGroups,
    });

    expect(plan.actions).toEqual([
      expect.objectContaining({
        authorityEmail: "archived@company.test",
        googleUserId: ARCHIVED_ID,
        lifecycle: "archived",
        memberEmail: "archived@company.test",
        memberId: ARCHIVED_ID,
      }),
      expect.objectContaining({
        authorityEmail: "deleted@company.test",
        googleUserId: DELETED_ID,
        lifecycle: "deleted",
        memberEmail: "old-deleted@company.test",
        memberId: DELETED_ID,
      }),
      expect.objectContaining({
        authorityEmail: "suspended@company.test",
        googleUserId: SUSPENDED_ID,
        lifecycle: "suspended",
        memberEmail: "old-suspended@company.test",
        memberId: SUSPENDED_ID,
      }),
    ]);
    expect(plan.warnings).toEqual([]);
    expect(plan.planHash).toMatch(/^[a-f0-9]{64}$/u);
  });

  it("joins on immutable user ID and never removes an email-only match", async () => {
    const managedGoogleGroups = [
      group("group-eng", "team-eng@company.test", [
        {
          email: "suspended@company.test",
          id: "10000000009",
          role: "MEMBER",
          status: "SUSPENDED",
          type: "USER",
        },
      ]),
    ];
    await expect(
      planGoogleGroupCleanup({
        directoryUsers: DIRECTORY_USERS,
        managedGoogleGroupPins: pins(managedGoogleGroups),
        managedGoogleGroups,
      }),
    ).rejects.toThrow("google_group_cleanup_member_email_identity_mismatch");
  });

  it("removes inactive owners and managers while honoring configured group exclusions", async () => {
    const managedGoogleGroups = [
      group("group-platform", "team-platform@company.test", [
        {
          email: "owner@company.test",
          id: SUSPENDED_ID,
          role: "OWNER",
          status: "ACTIVE",
          type: "USER",
        },
        {
          email: "manager@company.test",
          id: DELETED_ID,
          role: "MANAGER",
          status: "ACTIVE",
          type: "USER",
        },
        {
          email: "archived@company.test",
          id: ARCHIVED_ID,
          role: "OWNER",
          status: "ARCHIVED",
          type: "USER",
        },
      ]),
      group("group-contractors", "team-eng-contract@company.test", [
        {
          email: "suspended@company.test",
          id: SUSPENDED_ID,
          role: "MEMBER",
          status: "ACTIVE",
          type: "USER",
        },
      ]),
    ];
    const plan = await planGoogleGroupCleanup({
      directoryUsers: DIRECTORY_USERS,
      excludedGoogleGroupIds: ["group-contractors"],
      managedGoogleGroupPins: pins(managedGoogleGroups),
      managedGoogleGroups,
    });

    expect(plan.actions).toEqual([
      expect.objectContaining({
        lifecycle: "archived",
        memberId: ARCHIVED_ID,
        role: "OWNER",
      }),
      expect.objectContaining({ memberId: DELETED_ID, role: "MANAGER" }),
      expect.objectContaining({ memberId: SUSPENDED_ID, role: "OWNER" }),
    ]);
    expect(plan.warnings).toEqual([]);
    expect(plan.excludedGoogleGroupIds).toEqual(["group-contractors"]);
  });

  it("cleans a validated deleted identity even when Google omits its administrator flags", async () => {
    const target: GoogleDirectoryUser = {
      id: DELETED_ID,
      primaryEmail: "deleted@company.test",
      deletionTime: "2026-10-18T12:00:00.000Z",
    };
    const groups = [
      group("other-group", "service-devs@company.test", [
        {
          id: target.id,
          email: target.primaryEmail,
          role: "MEMBER",
          type: "USER",
          status: "ACTIVE",
        },
      ]),
    ];
    const plan = await planGoogleGroupCleanup({
      directoryUsers: [target],
      managedGoogleGroupPins: pins(groups),
      managedGoogleGroups: groups,
    });
    expect(plan.actions).toEqual([
      expect.objectContaining({
        googleUserId: DELETED_ID,
        lifecycle: "deleted",
      }),
    ]);
    expect(plan.excludedGoogleUserIds).not.toContain(DELETED_ID);
  });

  it("never plans removal of an explicitly protected root identity", async () => {
    const managedGoogleGroups = [
      group("group-platform", "team-platform@company.test", [
        {
          email: "suspended@company.test",
          id: SUSPENDED_ID,
          role: "MEMBER",
          status: "SUSPENDED",
          type: "USER",
        },
      ]),
    ];
    const plan = await planGoogleGroupCleanup({
      directoryUsers: DIRECTORY_USERS,
      excludedGoogleUserIds: [SUSPENDED_ID, SUSPENDED_ID],
      managedGoogleGroupPins: pins(managedGoogleGroups),
      managedGoogleGroups,
    });

    expect(plan.actions).toEqual([]);
    expect(plan.excludedGoogleUserIds).toEqual([SUSPENDED_ID]);
  });

  it("is deterministic across input ordering and hashes the pinned group authority", async () => {
    const groups = [
      group("group-platform", "team-platform@company.test", [
        {
          email: "suspended@company.test",
          id: SUSPENDED_ID,
          role: "MEMBER",
          status: "ACTIVE",
          type: "USER",
        },
      ]),
      group("group-design", "team-design@company.test", [
        {
          email: "deleted@company.test",
          id: DELETED_ID,
          role: "MEMBER",
          status: "ACTIVE",
          type: "USER",
        },
      ]),
    ];
    const [platformGroup, designGroup] = groups;
    if (platformGroup === undefined || designGroup === undefined)
      throw new Error("fixture_missing");
    const first = await planGoogleGroupCleanup({
      directoryUsers: DIRECTORY_USERS,
      excludedGoogleGroupIds: ["excluded-b", "excluded-a", "excluded-a"],
      managedGoogleGroupPins: pins(groups),
      managedGoogleGroups: groups,
    });
    const reordered = await planGoogleGroupCleanup({
      directoryUsers: DIRECTORY_USERS.toReversed(),
      excludedGoogleGroupIds: ["excluded-a", "excluded-b"],
      managedGoogleGroupPins: pins(groups),
      managedGoogleGroups: groups.toReversed().map((item) => ({
        ...item,
        members: item.members.toReversed(),
      })),
    });

    expect(reordered).toEqual(first);
    expect(first.managedGoogleGroups.map(({ id }) => id)).toEqual([
      "group-design",
      "group-platform",
    ]);

    await expect(
      planGoogleGroupCleanup({
        directoryUsers: DIRECTORY_USERS,
        excludedGoogleGroupIds: ["excluded-a", "excluded-b"],
        managedGoogleGroupPins: pins(groups),
        managedGoogleGroups: [
          { ...platformGroup, id: "group-platform-replaced" },
          designGroup,
        ],
      }),
    ).rejects.toThrow("google_group_cleanup_group_pin_mismatch");
  });

  it("rejects duplicate immutable authority and provider identifiers", async () => {
    await expect(
      planGoogleGroupCleanup({
        directoryUsers: [
          user(SUSPENDED_ID, { suspended: true }),
          user(SUSPENDED_ID),
        ],
        managedGoogleGroupPins: [],
        managedGoogleGroups: [],
      }),
    ).rejects.toThrow(
      `google_group_cleanup_duplicate_directory_user_id:${SUSPENDED_ID}`,
    );

    await expect(
      planGoogleGroupCleanup({
        directoryUsers: DIRECTORY_USERS,
        managedGoogleGroupPins: [
          { email: "team-platform@company.test", id: "group-platform" },
        ],
        managedGoogleGroups: [
          group("group-platform", "team-platform@company.test", [
            {
              email: "first@company.test",
              id: SUSPENDED_ID,
              role: "MEMBER",
              status: "ACTIVE",
              type: "USER",
            },
            {
              email: "second@company.test",
              id: SUSPENDED_ID,
              role: "MEMBER",
              status: "ACTIVE",
              type: "USER",
            },
          ]),
        ],
      }),
    ).rejects.toThrow(
      `google_group_cleanup_duplicate_member_id:group-platform:${SUSPENDED_ID}`,
    );
  });
});
