import { describe, expect, it } from "vitest";

import {
  bootstrapEmployeeEntitlementAuthority,
  buildEmployeeEntitlementAuthority,
} from "../src/identity-provisioning/employee-entitlement-policy.ts";
import type { GoogleGroupSnapshot } from "../src/org-sync/channel-model.ts";
import type { GoogleDirectoryUser } from "../src/org-sync/model.ts";
import type { PagerDutyTeamSnapshot } from "../src/workspace-directory/pagerduty-team-client.ts";
import {
  type PagerDutyTeamMapping,
  PagerDutyTeamSyncSettingsSchema,
} from "../src/workspace-directory/pagerduty-team-config.ts";
import {
  PagerDutyTeamWritableActionSchema,
  pagerDutyTeamActionIsRecoverable,
  planPagerDutyTeamSync,
} from "../src/workspace-directory/pagerduty-team-sync.ts";

const MAPPING: PagerDutyTeamMapping = {
  googleGroupEmail: "team-platform@company.test",
  googleGroupId: "group-platform",
  pagerDutyRole: "responder",
  pagerDutyTeamId: "PTEAM1",
  pagerDutyTeamName: "Platform",
};
const REVIEW_ID = "00000000-0000-4000-8000-000000000001";
const EMPLOYEE_ENTITLEMENT_AUTHORITY = await buildEmployeeEntitlementAuthority({
  email: "team-contractors@company.test",
  id: "contractor-group-test",
  members: [],
});

function user(email: string): GoogleDirectoryUser {
  return {
    id: email,
    primaryEmail: email,
    isAdmin: false,
    isDelegatedAdmin: false,
  };
}

function group(...emails: string[]): GoogleGroupSnapshot {
  return {
    email: MAPPING.googleGroupEmail,
    id: MAPPING.googleGroupId,
    members: emails.map((email) => ({
      email,
      id: email,
      role: "MEMBER" as const,
      status: "ACTIVE" as const,
      type: "USER" as const,
    })),
  };
}

function pagerDuty(): PagerDutyTeamSnapshot {
  return {
    capturedAt: "2026-09-02T00:00:00.000Z",
    memberships: [
      { role: "observer", teamId: "PTEAM1", userId: "PUSER1" },
      { role: "manager", teamId: "PTEAM1", userId: "PUSER3" },
    ],
    teams: [{ id: "PTEAM1", name: "Platform" }],
    users: [
      { email: "a@example.com", id: "PUSER1", name: "A", role: "user" },
      { email: "b@example.com", id: "PUSER2", name: "B", role: "user" },
      { email: "c@example.com", id: "PUSER3", name: "C", role: "user" },
    ],
  };
}

describe("PagerDuty team planner", () => {
  it.each([
    { label: "Google admin", google: { isAdmin: true }, providerRole: "user" },
    {
      label: "Google delegated admin",
      google: { isDelegatedAdmin: true },
      providerRole: "user",
    },
    {
      label: "unknown Google privilege",
      google: { isAdmin: undefined },
      providerRole: "user",
    },
    {
      label: "root alias",
      google: { nonEditableAliases: ["root-admin@company.test"] },
      providerRole: "user",
    },
    { label: "PagerDuty admin", google: {}, providerRole: "admin" },
    {
      label: "unknown PagerDuty role",
      google: {},
      providerRole: "future-role",
    },
  ])("blocks $label team writes", async ({ google, providerRole }) => {
    const original = pagerDuty();
    const snapshot = {
      ...original,
      users: original.users.map((account) =>
        account.id === "PUSER1" ? { ...account, role: providerRole } : account,
      ),
    };
    const plan = await planPagerDutyTeamSync({
      credentialConfigured: true,
      employeeEntitlementAuthority: EMPLOYEE_ENTITLEMENT_AUTHORITY,
      googleGroups: [group("a@example.com")],
      googleUsers: [{ ...user("a@example.com"), ...google }],
      mappings: [MAPPING],
      mutationsDisabled: false,
      pagerDuty: snapshot,
      reviewId: REVIEW_ID,
    });
    expect(plan.status).toBe("blocked");
    expect(plan.actions).toEqual([]);
    expect(plan.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "protected-identity" }),
      ]),
    );
  });

  it("does not authorize grants from bootstrap-only contractor evidence", async () => {
    const plan = await planPagerDutyTeamSync({
      credentialConfigured: true,
      employeeEntitlementAuthority: bootstrapEmployeeEntitlementAuthority(),
      googleGroups: [group("a@example.com")],
      googleUsers: [user("a@example.com")],
      mappings: [MAPPING],
      mutationsDisabled: false,
      pagerDuty: pagerDuty(),
      reviewId: REVIEW_ID,
    });
    expect(plan.status).toBe("blocked");
    expect(plan.actions).toEqual([]);
  });

  it("preserves an existing team manager for manual review", async () => {
    const plan = await planPagerDutyTeamSync({
      credentialConfigured: true,
      employeeEntitlementAuthority: EMPLOYEE_ENTITLEMENT_AUTHORITY,
      googleGroups: [group("c@example.com")],
      googleUsers: [user("c@example.com")],
      mappings: [MAPPING],
      mutationsDisabled: false,
      pagerDuty: pagerDuty(),
      reviewId: REVIEW_ID,
    });
    expect(plan.status).toBe("blocked");
    expect(
      plan.actions.some(({ pagerDutyUserId }) => pagerDutyUserId === "PUSER3"),
    ).toBe(false);
  });

  it("rejects duplicate exact mapping pins", () => {
    expect(() =>
      PagerDutyTeamSyncSettingsSchema.parse({ mappings: [MAPPING, MAPPING] }),
    ).toThrow("mappings must be unique");
  });

  it("returns a stable blocked plan while mappings and the dedicated credential are absent", async () => {
    const input = {
      credentialConfigured: false,
      mappings: [],
      mutationsDisabled: true,
      reviewId: REVIEW_ID,
    } as const;
    const first = await planPagerDutyTeamSync(input);
    const second = await planPagerDutyTeamSync(input);

    expect(first).toEqual(second);
    expect(first).toMatchObject({
      actions: [],
      evidenceHash: expect.stringMatching(/^[a-f0-9]{64}$/u),
      mappingCount: 0,
      mutationsDisabled: true,
      pagerDutyTeamCount: null,
      pagerDutyUserCount: null,
      status: "blocked",
    });
    expect(first.diagnostics.map(({ code }) => code)).toEqual([
      "credential-missing",
      "mapping-configuration-empty",
    ]);
  });

  it("deterministically reports add, role, and removal drift without applying it", async () => {
    const plan = await planPagerDutyTeamSync({
      credentialConfigured: true,
      employeeEntitlementAuthority: EMPLOYEE_ENTITLEMENT_AUTHORITY,
      googleGroups: [group("a@example.com", "b@example.com")],
      googleUsers: [user("a@example.com"), user("b@example.com")],
      mappings: [MAPPING],
      mutationsDisabled: true,
      pagerDuty: pagerDuty(),
      reviewId: REVIEW_ID,
    });

    expect(plan.status).toBe("ready");
    expect(plan.diagnostics).toEqual([]);
    expect(plan.actions).toEqual([
      {
        currentPagerDutyRole: "observer",
        desiredPagerDutyRole: "responder",
        email: "a@example.com",
        googleGroupId: "group-platform",
        googleUserId: "a@example.com",
        pagerDutyTeamId: "PTEAM1",
        pagerDutyUserId: "PUSER1",
        type: "set-role",
      },
      {
        desiredPagerDutyRole: "responder",
        email: "b@example.com",
        googleGroupId: "group-platform",
        googleUserId: "b@example.com",
        pagerDutyTeamId: "PTEAM1",
        pagerDutyUserId: "PUSER2",
        type: "add",
      },
      {
        currentPagerDutyRole: "manager",
        email: "c@example.com",
        pagerDutyTeamId: "PTEAM1",
        pagerDutyUserId: "PUSER3",
        type: "remove",
      },
    ]);
    expect(plan.planHash).toMatch(/^[a-f0-9]{64}$/u);
    expect(plan.evidenceHash).toMatch(/^[a-f0-9]{64}$/u);
  });

  it("blocks on mismatched exact pins and ambiguous target identities", async () => {
    const baseTarget = pagerDuty();
    const target = {
      ...baseTarget,
      users: [
        ...baseTarget.users,
        {
          email: "A@example.com",
          id: "PUSER4",
          name: "Duplicate A",
          role: "user",
        },
      ],
    };
    const plan = await planPagerDutyTeamSync({
      credentialConfigured: true,
      employeeEntitlementAuthority: EMPLOYEE_ENTITLEMENT_AUTHORITY,
      googleGroups: [group("a@example.com")],
      googleUsers: [user("a@example.com")],
      mappings: [{ ...MAPPING, pagerDutyTeamName: "Wrong name" }],
      mutationsDisabled: true,
      pagerDuty: target,
      reviewId: REVIEW_ID,
    });

    expect(plan.status).toBe("blocked");
    expect(plan.actions).toEqual([]);
    expect(plan.diagnostics.map(({ code }) => code)).toEqual([
      "pagerduty-team-pin-mismatch",
      "pagerduty-user-email-ambiguous",
    ]);
  });

  it("never proposes removals from incomplete Google membership evidence", async () => {
    const incomplete = group("a@example.com");
    incomplete.members.push({
      email: "nested@example.com",
      id: "nested-group",
      role: "MEMBER",
      status: "ACTIVE",
      type: "GROUP",
    });
    const plan = await planPagerDutyTeamSync({
      credentialConfigured: true,
      employeeEntitlementAuthority: EMPLOYEE_ENTITLEMENT_AUTHORITY,
      googleGroups: [incomplete],
      googleUsers: [user("a@example.com")],
      mappings: [MAPPING],
      mutationsDisabled: true,
      pagerDuty: pagerDuty(),
      reviewId: REVIEW_ID,
    });

    expect(plan.status).toBe("blocked");
    expect(plan.actions).toEqual([]);
    expect(plan.diagnostics).toContainEqual(
      expect.objectContaining({
        code: "google-group-member-ineligible",
        severity: "error",
      }),
    );
  });

  it("binds the plan hash to exact mappings even when both plans have no actions", async () => {
    const target = { ...pagerDuty(), memberships: [] };
    const shared = {
      credentialConfigured: true,
      employeeEntitlementAuthority: EMPLOYEE_ENTITLEMENT_AUTHORITY,
      googleGroups: [group()],
      googleUsers: [],
      mutationsDisabled: true,
      pagerDuty: target,
      reviewId: REVIEW_ID,
    } as const;
    const responder = await planPagerDutyTeamSync({
      ...shared,
      mappings: [MAPPING],
    });
    const observer = await planPagerDutyTeamSync({
      ...shared,
      mappings: [{ ...MAPPING, pagerDutyRole: "observer" }],
    });

    expect(responder.actions).toEqual([]);
    expect(observer.actions).toEqual([]);
    expect(responder.evidenceHash).not.toBe(observer.evidenceHash);
    expect(responder.planHash).not.toBe(observer.planHash);
  });

  it.each([
    {
      existing: false,
      inMappedGroup: true,
      pagerDutyEmail: "contractor@example.com",
      warning: false,
    },
    {
      existing: true,
      inMappedGroup: false,
      pagerDutyEmail: "contractor-alias@example.com",
      warning: true,
    },
  ])(
    "never adds, updates, or removes a pinned contractor when existing=$existing and mapped=$inMappedGroup",
    async ({ existing, inMappedGroup, pagerDutyEmail, warning }) => {
      const authority = await buildEmployeeEntitlementAuthority({
        email: "team-contractors@company.test",
        id: "contractor-group-test",
        members: [
          {
            email: "contractor@example.com",
            id: "google-contractor",
            role: "MEMBER",
            status: "ACTIVE",
            type: "USER",
          },
        ],
      });
      const plan = await planPagerDutyTeamSync({
        credentialConfigured: true,
        employeeEntitlementAuthority: authority,
        googleGroups: [
          {
            email: MAPPING.googleGroupEmail,
            id: MAPPING.googleGroupId,
            members: inMappedGroup
              ? [
                  {
                    email: "contractor-alias@example.com",
                    id: "google-contractor",
                    role: "MEMBER" as const,
                    status: "ACTIVE" as const,
                    type: "USER" as const,
                  },
                ]
              : [],
          },
        ],
        googleUsers: [
          {
            id: "google-contractor",
            nonEditableAliases: ["contractor-alias@example.com"],
            primaryEmail: "contractor@example.com",
          },
        ],
        mappings: [MAPPING],
        mutationsDisabled: true,
        pagerDuty: {
          capturedAt: "2026-09-04T00:00:00.000Z",
          memberships: existing
            ? [{ role: "observer", teamId: "PTEAM1", userId: "PCONTRACTOR" }]
            : [],
          teams: [{ id: "PTEAM1", name: "Platform" }],
          users: [
            {
              email: pagerDutyEmail,
              id: "PCONTRACTOR",
              name: "Contractor",
              role: "user",
            },
          ],
        },
        reviewId: REVIEW_ID,
      });

      expect(plan.status).toBe("ready");
      expect(plan.actions).toEqual([]);
      const preserved = expect.objectContaining({
        code: "contractor-membership-preserved",
      });
      expect(plan.diagnostics).toEqual(warning ? [preserved] : []);
    },
  );

  it("denies desired membership when only a Google alias identifies the contractor", async () => {
    const plan = await planPagerDutyTeamSync({
      credentialConfigured: true,
      employeeEntitlementAuthority: EMPLOYEE_ENTITLEMENT_AUTHORITY,
      googleGroups: [group("renamed-contractor@example.com")],
      googleUsers: [
        {
          id: "renamed-contractor@example.com",
          nonEditableAliases: ["excluded-two@company.test"],
          primaryEmail: "renamed-contractor@example.com",
        },
      ],
      mappings: [MAPPING],
      mutationsDisabled: true,
      pagerDuty: {
        capturedAt: "2026-09-04T00:00:00.000Z",
        memberships: [],
        teams: [{ id: "PTEAM1", name: "Platform" }],
        users: [
          {
            email: "renamed-contractor@example.com",
            id: "PCONTRACTOR",
            name: "Contractor",
            role: "user",
          },
        ],
      },
      reviewId: REVIEW_ID,
    });

    expect(plan.status).toBe("ready");
    expect(plan.actions).toEqual([]);
    expect(plan.diagnostics).toEqual([]);
  });

  it("keeps a genuinely missing employee account as a blocking diagnostic", async () => {
    const plan = await planPagerDutyTeamSync({
      credentialConfigured: true,
      employeeEntitlementAuthority: EMPLOYEE_ENTITLEMENT_AUTHORITY,
      googleGroups: [group("employee@example.com")],
      googleUsers: [user("employee@example.com")],
      mappings: [MAPPING],
      mutationsDisabled: true,
      pagerDuty: { ...pagerDuty(), memberships: [], users: [] },
      reviewId: REVIEW_ID,
    });

    expect(plan.status).toBe("blocked");
    expect(plan.actions).toEqual([]);
    expect(plan.diagnostics).toContainEqual(
      expect.objectContaining({
        code: "pagerduty-user-missing",
        severity: "error",
      }),
    );
  });

  it("keeps PagerDuty-specific exclusions out without changing Google authority", async () => {
    const excluded = { ...MAPPING, excludedEmails: ["excluded@example.com"] };
    const plan = await planPagerDutyTeamSync({
      credentialConfigured: true,
      employeeEntitlementAuthority: EMPLOYEE_ENTITLEMENT_AUTHORITY,
      googleGroups: [group("excluded@example.com")],
      googleUsers: [user("excluded@example.com")],
      mappings: [excluded],
      mutationsDisabled: false,
      pagerDuty: { ...pagerDuty(), memberships: [], users: [] },
      reviewId: REVIEW_ID,
    });

    expect(plan.status).toBe("ready");
    expect(plan.actions).toEqual([]);
    expect(plan.diagnostics).toEqual([]);
  });

  it("keeps removals outside the writable contract", () => {
    expect(() =>
      PagerDutyTeamWritableActionSchema.parse({
        currentPagerDutyRole: "responder",
        email: "a@example.com",
        pagerDutyTeamId: "PTEAM1",
        pagerDutyUserId: "PUSER1",
        type: "remove",
      }),
    ).toThrow();
  });

  it("recovers a response-lost addition only from exact authority and reconstructed evidence", async () => {
    const before = { ...pagerDuty(), memberships: [] };
    const input = {
      credentialConfigured: true,
      employeeEntitlementAuthority: EMPLOYEE_ENTITLEMENT_AUTHORITY,
      googleGroups: [group("a@example.com")],
      googleUsers: [user("a@example.com")],
      mappings: [MAPPING],
      mutationsDisabled: false,
      pagerDuty: before,
      reviewId: REVIEW_ID,
    } as const;
    const plan = await planPagerDutyTeamSync(input);
    const action = PagerDutyTeamWritableActionSchema.parse(plan.actions[0]);
    const after = {
      ...input,
      pagerDuty: {
        ...before,
        memberships: [
          {
            role: action.desiredPagerDutyRole,
            teamId: action.pagerDutyTeamId,
            userId: action.pagerDutyUserId,
          },
        ],
      },
    };

    await expect(
      pagerDutyTeamActionIsRecoverable(after, action, plan.planHash),
    ).resolves.toBe(true);
    await expect(
      pagerDutyTeamActionIsRecoverable(
        { ...after, googleGroups: [group()] },
        action,
        plan.planHash,
      ),
    ).resolves.toBe(false);
  });
});
