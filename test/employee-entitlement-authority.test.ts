import { describe, expect, it } from "vitest";

import {
  bootstrapEmployeeEntitlementAuthority,
  buildEmployeeEntitlementAuthority,
  hasCompleteEmployeeEntitlementAuthority,
  isEmployeeEntitlementExcluded,
} from "../src/identity-provisioning/employee-entitlement-policy.ts";

const GROUP = {
  email: "team-eng-contract@company.test",
  id: "contractor-group-test",
  members: [
    {
      email: "dynamic@company.test",
      id: "dynamic-google-id",
      role: "MEMBER" as const,
      status: "ACTIVE" as const,
      type: "USER" as const,
    },
    {
      email: "root-admin@company.test",
      id: "999999999999999999902",
      role: "OWNER" as const,
      status: "ACTIVE" as const,
      type: "USER" as const,
    },
  ],
};

const DIRECT_MEMBER = {
  email: "dynamic@company.test",
  id: "dynamic-google-id",
  role: "MEMBER" as const,
  status: "ACTIVE" as const,
  type: "USER" as const,
};

describe("employee entitlement authority", () => {
  it("never treats bootstrap exclusions or omitted authority as complete grant evidence", () => {
    const bootstrap = bootstrapEmployeeEntitlementAuthority();
    expect(bootstrap.complete).toBe(false);
    expect(hasCompleteEmployeeEntitlementAuthority(bootstrap)).toBe(false);
    expect(hasCompleteEmployeeEntitlementAuthority(undefined)).toBe(false);
    expect(isEmployeeEntitlementExcluded("excluded-one@company.test")).toBe(
      true,
    );
    expect(isEmployeeEntitlementExcluded("employee@company.test")).toBe(false);
  });

  it("requires the pinned dynamic group and a captured fingerprint", async () => {
    const authority = await buildEmployeeEntitlementAuthority(GROUP);
    expect(hasCompleteEmployeeEntitlementAuthority(authority)).toBe(true);
    expect(
      hasCompleteEmployeeEntitlementAuthority({
        ...authority,
        groupId: "other",
      }),
    ).toBe(false);
    expect(
      hasCompleteEmployeeEntitlementAuthority({
        ...authority,
        groupEmail: "other@company.test",
      }),
    ).toBe(false);
    expect(
      hasCompleteEmployeeEntitlementAuthority({
        ...authority,
        fingerprint: "bootstrap-employee-entitlement-authority",
      }),
    ).toBe(false);
  });

  it("matches aliases and retains the bootstrap deny floor with dynamic authority", async () => {
    const authority = await buildEmployeeEntitlementAuthority(GROUP);
    expect(
      isEmployeeEntitlementExcluded(
        "renamed@company.test",
        undefined,
        authority,
        ["DYNAMIC@company.test"],
      ),
    ).toBe(true);
    expect(
      isEmployeeEntitlementExcluded(
        "renamed@company.test",
        undefined,
        { ...authority, excludedEmails: [] },
        ["EXCLUDED-ONE@company.test"],
      ),
    ).toBe(true);
  });

  it("rejects unsupported customer membership rather than silently dropping it", async () => {
    await expect(
      buildEmployeeEntitlementAuthority({
        ...GROUP,
        members: [{ ...DIRECT_MEMBER, type: "CUSTOMER" }],
      }),
    ).rejects.toThrow("contractor_authority_member_type_unsupported");
  });

  it("accepts the legacy alias and excludes only direct contractor members", async () => {
    const authority = await buildEmployeeEntitlementAuthority(GROUP);
    expect(authority.groupEmail).toBe("team-contractors@company.test");
    expect(
      isEmployeeEntitlementExcluded(
        "dynamic@company.test",
        undefined,
        authority,
      ),
    ).toBe(true);
    expect(
      isEmployeeEntitlementExcluded(
        "renamed@company.test",
        "dynamic-google-id",
        authority,
      ),
    ).toBe(true);
    expect(
      isEmployeeEntitlementExcluded(
        "root-admin@company.test",
        "999999999999999999902",
        authority,
      ),
    ).toBe(false);
  });

  it.each(["OWNER", "MANAGER"] as const)(
    "does not treat an administrative %s record as a contractor subject",
    async (role) => {
      const authority = await buildEmployeeEntitlementAuthority({
        ...GROUP,
        members: [{ ...DIRECT_MEMBER, role }],
      });

      expect(authority.excludedEmails).not.toContain("dynamic@company.test");
      expect(authority.excludedGoogleUserIds).not.toContain(
        "dynamic-google-id",
      );
      expect(
        isEmployeeEntitlementExcluded(
          "dynamic@company.test",
          "dynamic-google-id",
          authority,
        ),
      ).toBe(false);
    },
  );

  it("keeps a mixed administrative and contractor snapshot role-separated", async () => {
    const authority = await buildEmployeeEntitlementAuthority({
      ...GROUP,
      members: [
        DIRECT_MEMBER,
        {
          email: "administrator@company.test",
          id: "administrator-google-id",
          role: "OWNER",
          status: "ACTIVE",
          type: "USER",
        },
      ],
    });

    expect(authority.excludedEmails).toContain("dynamic@company.test");
    expect(authority.excludedEmails).not.toContain(
      "administrator@company.test",
    );
    expect(authority.excludedGoogleUserIds).toEqual(["dynamic-google-id"]);
  });

  it.each(["SUSPENDED", "ARCHIVED"] as const)(
    "keeps %s contractor exclusions and fingerprint unchanged",
    async (status) => {
      const active = await buildEmployeeEntitlementAuthority({
        ...GROUP,
        members: [DIRECT_MEMBER],
      });
      const inactive = await buildEmployeeEntitlementAuthority({
        ...GROUP,
        members: [{ ...DIRECT_MEMBER, status }],
      });
      expect(inactive).toEqual(active);
      expect(
        isEmployeeEntitlementExcluded(
          "renamed@company.test",
          DIRECT_MEMBER.id,
          inactive,
        ),
      ).toBe(true);
      expect(
        isEmployeeEntitlementExcluded(DIRECT_MEMBER.email, undefined, inactive),
      ).toBe(true);
    },
  );

  it.each(["OWNER", "MANAGER"] as const)(
    "keeps known inactive %s administration separate from contractor exclusion",
    async (role) => {
      const active = await buildEmployeeEntitlementAuthority({
        ...GROUP,
        members: [{ ...DIRECT_MEMBER, role }],
      });
      for (const status of ["SUSPENDED", "ARCHIVED"] as const) {
        await expect(
          buildEmployeeEntitlementAuthority({
            ...GROUP,
            members: [{ ...DIRECT_MEMBER, role, status }],
          }),
        ).resolves.toEqual(active);
      }
      expect(active.excludedGoogleUserIds).not.toContain(DIRECT_MEMBER.id);
    },
  );

  it.each([
    { status: "UNKNOWN" as const },
    { email: "" },
    { email: " ".repeat(3) },
  ])("rejects incomplete direct member evidence %j", async (change) => {
    await expect(
      buildEmployeeEntitlementAuthority({
        ...GROUP,
        members: [{ ...DIRECT_MEMBER, ...change }],
      }),
    ).rejects.toThrow("contractor_authority_member_incomplete");
  });

  it.each(["status", "email"] as const)(
    "rejects a missing member %s",
    async (field) => {
      const { [field]: _omitted, ...member } = DIRECT_MEMBER;
      await expect(
        buildEmployeeEntitlementAuthority({ ...GROUP, members: [member] }),
      ).rejects.toThrow("contractor_authority_member_incomplete");
    },
  );

  it("still rejects a known inactive member without an explicit role", async () => {
    const { role: _role, ...member } = DIRECT_MEMBER;
    await expect(
      buildEmployeeEntitlementAuthority({
        ...GROUP,
        members: [{ ...member, status: "SUSPENDED" }],
      }),
    ).rejects.toThrow("contractor_authority_member_role_missing");
  });

  it("fails closed for nested groups", async () => {
    await expect(
      buildEmployeeEntitlementAuthority({
        ...GROUP,
        members: [
          {
            email: "nested@company.test",
            id: "nested-id",
            role: "MEMBER",
            status: "ACTIVE",
            type: "GROUP",
          },
        ],
      }),
    ).rejects.toThrow("contractor_authority_nested_group_unsupported");
  });
});
