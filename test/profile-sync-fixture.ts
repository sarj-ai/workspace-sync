import { vi } from "vitest";

import { SlackProfileSync } from "../src/configuration.ts";
import type {
  GoogleDirectoryUser,
  SlackProfile,
} from "../src/org-sync/model.ts";
import type { IOrgSlackClient } from "../src/org-sync/org-slack-client.ts";
import type { OrgSyncServiceOptions } from "../src/org-sync/service.ts";

export function profileSyncFixture() {
  const profile: SlackProfile = {
    email: "ada@company.test",
    title: "Engineer",
    fields: { XfTeam: { value: "Engineering" } },
  };
  const state = {
    user: {
      id: "12345",
      primaryEmail: "ada@company.test",
      organizations: [
        { department: "Engineering", primary: true, title: "Staff Engineer" },
      ],
    } satisfies GoogleDirectoryUser,
    profile,
  };
  const getProfile = vi.fn<IOrgSlackClient["getProfile"]>(async () =>
    structuredClone(state.profile),
  );
  const update = async (
    _id: string,
    patch: Parameters<IOrgSlackClient["setProfile"]>[1],
  ) => {
    state.profile = {
      ...state.profile,
      ...patch,
      fields: { ...state.profile.fields, ...patch.fields },
    };
  };
  const setProfile = vi.fn<IOrgSlackClient["setProfile"]>(update);
  const options: OrgSyncServiceOptions = {
    config: {
      allowedEmptyDepartmentGoogleUserIds: [],
      excludedGoogleUserIds: [],
      expectedRootGoogleUserIds: [state.user.id],
      expectedSlackTeamId: "TEXAMPLE",
      fieldIds: {
        manages: "XfManages",
        reportsTo: "XfReportsTo",
        team: "XfTeam",
      },
      managedDomain: "company.test",
      maxAutomaticChanges: 1,
      minimumGoogleParticipants: 1,
      protectedDepartedGoogleUserIds: [],
    },
    google: { listAllUsers: vi.fn(async () => [structuredClone(state.user)]) },
    slack: {
      getProfile,
      setProfile,
      listSnapshot: vi.fn(async () => ({
        actorUserId: "UADMIN",
        fields: [
          {
            id: "XfManages",
            label: "Manages",
            type: "user",
            "is_protected": true,
          },
          {
            id: "XfReportsTo",
            label: "Reports to",
            type: "user",
            "is_protected": true,
          },
          { id: "XfTeam", label: "Team", type: "text", "is_protected": true },
        ],
        members: [
          { id: "UADMIN", profile: {}, "is_admin": true },
          { id: "UADA", profile: structuredClone(state.profile) },
        ],
        scopes: [
          "users.profile:read",
          "users.profile:write",
          "users:read",
          "users:read.email",
        ],
        teamId: "TEXAMPLE",
      })),
    },
  };
  return {
    sync: new SlackProfileSync(options),
    options,
    state,
    getProfile,
    setProfile,
    update,
  };
}
