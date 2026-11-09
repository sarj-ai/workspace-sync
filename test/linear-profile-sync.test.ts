import { describe, expect, it, vi } from "vitest";

import type { LinearProfileAccount } from "../src/access-guard/linear-provider.ts";
import { enforceLinearSuspension } from "../src/access-guard/provider.ts";
import type { GoogleDirectoryUser } from "../src/org-sync/model.ts";
import {
  applyLinearProfilePlanAction,
  auditLinearProfileSync,
  LinearProfileDriftError,
  planLinearProfileSync,
} from "../src/workspace-directory/linear-profile-sync.ts";

function google(
  email: string,
  fullName: string,
  overrides: Partial<GoogleDirectoryUser> = {},
): GoogleDirectoryUser {
  return {
    aliases: [],
    archived: false,
    customSchemas: {},
    id: `google-${email}`,
    name: { fullName },
    nonEditableAliases: [],
    organizations: [],
    primaryEmail: email,
    relations: [],
    suspended: false,
    ...overrides,
  };
}

function linear(
  email: string,
  fullName: string,
  overrides: Partial<LinearProfileAccount> = {},
): LinearProfileAccount {
  return {
    active: true,
    displayName: `handle-${email.replace(/@.*$/u, "")}`,
    email,
    id: `linear-${email}`,
    name: fullName,
    ...overrides,
  };
}

describe("Linear profile sync planning", () => {
  it("repairs only exact full-email and local-part defaults", () => {
    const users = [
      google("ada@company.test", "Ada Lovelace"),
      google("grace@company.test", "Grace Hopper"),
      google("custom@company.test", "Custom Person"),
    ];
    const plan = planLinearProfileSync(users, [
      linear("ada@company.test", "ADA@COMPANY.TEST"),
      linear("grace@company.test", "grace"),
      linear("custom@company.test", "Preferred Handle"),
    ]);

    expect(plan.actions).toEqual([
      {
        beforeFullName: "ADA@COMPANY.TEST",
        desiredFullName: "Ada Lovelace",
        email: "ada@company.test",
        googleUserId: "google-ada@company.test",
        linearUserId: "linear-ada@company.test",
        type: "repair-default-full-name",
      },
      {
        beforeFullName: "grace",
        desiredFullName: "Grace Hopper",
        email: "grace@company.test",
        googleUserId: "google-grace@company.test",
        linearUserId: "linear-grace@company.test",
        type: "repair-default-full-name",
      },
    ]);
  });

  it("skips inactive, unmatched, unnamed, converged, and custom-name accounts", () => {
    const plan = planLinearProfileSync(
      [
        google("active@company.test", "Active Person"),
        google("custom@company.test", "Custom Person"),
        google("suspended@company.test", "Suspended Person", {
          suspended: true,
        }),
        google("unnamed@company.test", "", { name: undefined }),
      ],
      [
        linear("active@company.test", "Active Person"),
        linear("suspended@company.test", "suspended"),
        linear("unnamed@company.test", "unnamed"),
        linear("missing@company.test", "missing"),
        linear("inactive@company.test", "inactive", { active: false }),
        linear("custom@company.test", "Preferred Handle"),
      ],
    );
    expect(plan.actions).toEqual([]);
  });

  it("fails closed on ambiguous provider email identities", () => {
    expect(() =>
      planLinearProfileSync(
        [google("ada@company.test", "Ada Lovelace")],
        [linear("ada@company.test", "ada"), linear("ADA@company.test", "ADA")],
      ),
    ).toThrow("linear_profile_linear_identity_ambiguous");
  });

  it("rejects an alias shared by different active Google identities", () => {
    expect(() =>
      planLinearProfileSync(
        [
          google("ada@company.test", "Ada Lovelace"),
          google("other@company.test", "Other Person", {
            aliases: ["ADA@company.test"],
          }),
        ],
        [],
      ),
    ).toThrow("linear_profile_google_identity_ambiguous");
  });

  it("matches non-editable Google aliases and permits a 31-person gradual plan", () => {
    const aliased = google("jane.doe@company.test", "Jane Doe", {
      nonEditableAliases: ["jdoe@company.test"],
    });
    const users = [
      aliased,
      ...Array.from({ length: 30 }, (_, index) =>
        google(
          `person${String(index)}@company.test`,
          `Person ${String(index)}`,
        ),
      ),
    ];
    const accounts = [
      linear("jdoe@company.test", "jdoe"),
      ...Array.from({ length: 30 }, (_, index) =>
        linear(`person${String(index)}@company.test`, `person${String(index)}`),
      ),
    ];

    const plan = planLinearProfileSync(users, accounts);

    expect(plan.actions).toHaveLength(31);
    expect(plan.actions).toContainEqual(
      expect.objectContaining({
        email: "jdoe@company.test",
        desiredFullName: "Jane Doe",
      }),
    );
  });
});

describe("Linear profile sync apply", () => {
  it("cannot select another identity through profile repair after a suspension attempt", async () => {
    let reserved: string | undefined;
    const budget = {
      required: true as const,
      reserve: async (id: string) => {
        if (reserved !== undefined && reserved !== id)
          throw new Error("identity_budget_conflict");
        reserved = id;
      },
    };
    const provider = {
      getAccount: vi.fn().mockResolvedValue({
        active: true,
        admin: false,
        app: false,
        owner: false,
        email: "departed@company.test",
        id: "linear-departed",
      }),
      listAccounts: vi.fn(),
      name: "linear" as const,
      suspendAccount: vi.fn(
        async (
          _id: string,
          _runId: string,
          assertFinalWriteAuthority?: () => Promise<void>,
        ) => {
          await assertFinalWriteAuthority?.();
          throw new Error("ambiguous_write");
        },
      ),
    };
    await expect(
      enforceLinearSuspension(
        provider,
        {
          accountId: "linear-departed",
          email: "departed@company.test",
          googleUserId: "100000000000000000001",
        },
        "suspension-child-run",
        budget,
        {
          assertFinalSourceAuthority: async () => undefined,
          assertWriteAuthority: async () => undefined,
          assertFreshPlan: () => undefined,
        },
      ),
    ).resolves.toMatchObject({ outcome: "failed_closed" });
    expect(provider.suspendAccount).toHaveBeenCalledOnce();
    const users = [
      google("ada@company.test", "Ada Lovelace", {
        id: "100000000000000000002",
      }),
    ];
    const before = linear("ada@company.test", "ada");
    const client = {
      getAccount: vi.fn().mockResolvedValue(before),
      listProfileAccounts: vi.fn().mockResolvedValue([before]),
      updateFullName: vi.fn(),
    };
    const audited = await auditLinearProfileSync(users, client);
    const action = audited.actions[0];
    if (action === undefined) throw new Error("expected_linear_profile_action");
    await expect(
      applyLinearProfilePlanAction(
        users,
        client,
        action,
        audited.planHash,
        budget,
      ),
    ).rejects.toThrow("identity_budget_conflict");
    expect(client.updateFullName).not.toHaveBeenCalled();
    expect(reserved).toBe("100000000000000000001");
  });

  it.each([
    "allowed",
    "denied",
    "missing-callback",
    "admin-promoted",
    "identity-changed",
  ] as const)(
    "requires the final immutable-identity reservation: %s",
    async (decision) => {
      const users = [
        google("ada@company.test", "Ada Lovelace", {
          id: "100000000000000000001",
        }),
      ];
      const before = linear("ada@company.test", "ada");
      const after = linear("ada@company.test", "Ada Lovelace");
      const order: string[] = [];
      let fresh = before;
      const reserve = vi.fn(async (id: string) => {
        order.push(`reserve:${id}`);
        if (decision === "denied") throw new Error("identity_budget_conflict");
        if (decision === "admin-promoted") fresh = { ...before, admin: true };
        if (decision === "identity-changed")
          fresh = { ...before, email: "different@company.test" };
      });
      const client = {
        getAccount: vi.fn(async () => fresh),
        listProfileAccounts: vi.fn().mockResolvedValue([before]),
        updateFullName: vi.fn(async () => {
          order.push("write");
          fresh = after;
          return after;
        }),
      };
      const audited = await auditLinearProfileSync(users, client);
      const action = audited.actions[0];
      if (action === undefined)
        throw new Error("expected_linear_profile_action");
      const budget = { required: true as const, reserve };
      if (decision === "missing-callback")
        Reflect.deleteProperty(budget, "reserve");
      const applied = applyLinearProfilePlanAction(
        users,
        client,
        action,
        audited.planHash,
        budget,
      );
      const [result] = await Promise.allSettled([applied]);
      expect(result.status).toBe(
        decision === "allowed" ? "fulfilled" : "rejected",
      );
      expect(order).toEqual(
        decision === "missing-callback"
          ? []
          : [
              `reserve:${action.googleUserId}`,
              ...(decision === "allowed" ? ["write"] : []),
            ],
      );
      expect(client.updateFullName).toHaveBeenCalledTimes(
        decision === "allowed" ? 1 : 0,
      );
      expect(reserve).toHaveBeenCalledTimes(
        decision === "missing-callback" ? 0 : 1,
      );
    },
  );

  it("re-audits, writes one exact full name, and verifies readback", async () => {
    const users = [google("ada@company.test", "Ada Lovelace")];
    const before = linear("ada@company.test", "ada");
    const after = linear("ada@company.test", "Ada Lovelace");
    const client = {
      getAccount: vi
        .fn()
        .mockResolvedValueOnce(before)
        .mockResolvedValueOnce(after),
      listProfileAccounts: vi.fn().mockResolvedValue([before]),
      updateFullName: vi.fn().mockResolvedValue(after),
    };
    const audited = await auditLinearProfileSync(users, client);

    const action = audited.actions[0];
    if (action === undefined) throw new Error("expected_linear_profile_action");
    await applyLinearProfilePlanAction(users, client, action, audited.planHash);

    expect(client.updateFullName).toHaveBeenCalledWith(
      before.id,
      "Ada Lovelace",
      expect.any(String),
    );
    expect(client.getAccount).toHaveBeenCalledTimes(2);
  });

  it("rejects a custom-name prewrite drift without writing", async () => {
    const users = [google("ada@company.test", "Ada Lovelace")];
    const before = linear("ada@company.test", "ada");
    const client = {
      getAccount: vi
        .fn()
        .mockResolvedValue(linear("ada@company.test", "Preferred Handle")),
      listProfileAccounts: vi.fn().mockResolvedValue([before]),
      updateFullName: vi.fn(),
    };
    const audited = await auditLinearProfileSync(users, client);

    const action = audited.actions[0];
    if (action === undefined) throw new Error("expected_linear_profile_action");
    await expect(
      applyLinearProfilePlanAction(users, client, action, audited.planHash),
    ).rejects.toBeInstanceOf(LinearProfileDriftError);
    expect(client.updateFullName).not.toHaveBeenCalled();
  });

  it("preserves Linear displayName usernames when the full name is already present", () => {
    const plan = planLinearProfileSync(
      [google("ada@company.test", "Ada Lovelace")],
      [linear("ada@company.test", "Ada Lovelace", { displayName: "ada" })],
    );
    expect(plan.actions).toEqual([]);
  });
});
