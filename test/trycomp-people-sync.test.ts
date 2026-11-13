import { describe, expect, it, vi } from "vitest";

import { employeeEntitlementExcludedEmails } from "../src/identity-provisioning/employee-entitlement-policy.ts";
import {
  activeResourceLease,
  resourceLeaseKey,
} from "../src/identity-sync/resource-lease.ts";
import type { GoogleGroupSnapshot } from "../src/org-sync/channel-model.ts";
import type { GoogleDirectoryUser } from "../src/org-sync/model.ts";
import {
  type ITrycompPeopleClient,
  TrycompPeopleClient,
} from "../src/trycomp/client.ts";
import {
  type TrycompMember,
  TrycompReviewedPlanSchema,
} from "../src/trycomp/model.ts";
import { buildTrycompPlan } from "../src/trycomp/plan.ts";
import {
  sameReviewedTrycompPlan,
  selectedTrycompIdentity,
} from "../src/trycomp/reviewed-identity.ts";
import type {
  TrycompMutationStore,
  TrycompSafetyStore,
} from "../src/trycomp/safety.ts";
import {
  type TrycompReviewedApplyInput,
  TrycompPeopleSyncService,
} from "../src/trycomp/service.ts";

async function applyNextReviewed(
  service: TrycompPeopleSyncService,
  input: Omit<TrycompReviewedApplyInput, "reviewedPlan">,
) {
  await input.safetyReader.assertClosed();
  const reviewedPlan = await service.captureReviewedPlan(input);
  return service.applyReviewed({ ...input, reviewedPlan });
}

const TEST_LEASE = activeResourceLease({
  expiresAtMs: 60_000,
  generation: 1,
  ownerId: "11111111-1111-4111-8111-111111111111",
  resourceKey: resourceLeaseKey("org-sync/trycomp-people"),
});
const TEST_DEPLOYMENT = {
  id: "test-worker-version",
  tag: "a".repeat(40),
  timestamp: "2026-08-29T12:00:00.000Z",
} as const;

class MemoryMutationSafety implements TrycompMutationStore, TrycompSafetyStore {
  assertClosed(): Promise<void> {
    return Promise.resolve();
  }
  beginRun(): Promise<void> {
    return Promise.resolve();
  }
  completeRun(): Promise<void> {
    return Promise.resolve();
  }
  failRun(): Promise<void> {
    return Promise.resolve();
  }
  markAttempted(): Promise<void> {
    return Promise.resolve();
  }
  markProviderAccepted(): Promise<void> {
    return Promise.resolve();
  }
  recordPreannouncement(): Promise<void> {
    return Promise.resolve();
  }
  readonly markVerified = vi.fn<TrycompMutationStore["markVerified"]>(
    async () => undefined,
  );
  openForAmbiguous(): Promise<void> {
    return Promise.resolve();
  }
  readModel(): Promise<never> {
    throw new Error("not needed by service tests");
  }
  status() {
    return Promise.resolve({
      "opened_action_index": null,
      "opened_at_ms": null,
      "opened_run_id": null,
      reason: null,
      state: "closed" as const,
      "updated_at_ms": 0,
    });
  }
}

function journaledAuthority() {
  const safety = new MemoryMutationSafety();
  return {
    deployment: TEST_DEPLOYMENT,
    lease: TEST_LEASE,
    mutationJournal: safety,
    preannounce: vi.fn(async () => ({
      intentKey: "b".repeat(64),
      slackTimestamp: "123.456",
    })),
    safetyReader: safety,
  };
}

const CONTRACTORS: GoogleGroupSnapshot = {
  email: "team-eng-contract@company.test",
  id: "contractors",
  members: [
    {
      email: "contractor@company.test",
      id: "102",
      role: "MEMBER",
      status: "ACTIVE",
      type: "USER",
    },
  ],
};

function googleUser(
  id: string,
  primaryEmail: string,
  state: Partial<GoogleDirectoryUser> = {},
): GoogleDirectoryUser {
  return {
    id,
    primaryEmail,
    isAdmin: false,
    isDelegatedAdmin: false,
    ...state,
  };
}

function member(
  id: string,
  email: string,
  state: Partial<TrycompMember> = {},
): TrycompMember {
  return {
    deactivated: false,
    id,
    isActive: true,
    role: "employee",
    fleetDmLabelId: null,
    user: { email, role: "user" },
    ...state,
  };
}

class MemoryTrycompClient implements ITrycompPeopleClient {
  readonly members = new Map<string, TrycompMember>();

  constructor(initial: TrycompMember[]) {
    for (const value of initial)
      this.members.set(value.id, structuredClone(value));
  }

  async deactivate(memberId: string): Promise<void> {
    const current = this.#required(memberId);
    this.members.set(memberId, {
      ...current,
      isActive: false,
      deactivated: true,
    });
  }

  inviteEmployee(email: string): Promise<void> {
    const id = `invited-${String(this.members.size)}`;
    this.members.set(id, member(id, email));
    return Promise.resolve();
  }

  listMembers(): Promise<TrycompMember[]> {
    return Promise.resolve(
      this.members
        .values()
        .map((value) => structuredClone(value))
        .toArray(),
    );
  }

  async reactivate(memberId: string): Promise<void> {
    const current = this.#required(memberId);
    this.members.set(memberId, {
      ...current,
      deactivated: false,
      isActive: true,
    });
  }

  #required(memberId: string): TrycompMember {
    const value = this.members.get(memberId);
    if (!value) throw new Error("missing test member");
    return value;
  }
}

function reviewedFixture(mode: "audit" | "live" = "live") {
  const client = new MemoryTrycompClient([]);
  const authority = {
    contractorGroup: { ...CONTRACTORS, members: [] },
    googleUsers: [
      googleUser("101", "a@company.test"),
      googleUser("102", "b@company.test"),
    ],
  };
  const service = new TrycompPeopleSyncService(client, {
    allowDeactivations: true,
    approvedPlanHash: "",
    excludedGoogleUserIds: [],
    expectedContractorGroupId: "contractors",
    managedDomain: "company.test",
    maxAutomaticActivations: 1,
    maxAutomaticDeactivations: 1,
    minimumGoogleUsers: 2,
    mode,
  });
  const safety = journaledAuthority();
  const beginRun = vi.spyOn(safety.mutationJournal, "beginRun");
  const invite = vi.spyOn(client, "inviteEmployee");
  const input = {
    ...authority,
    ...safety,
    assertWriteAuthority: vi.fn(async () => undefined),
    refreshAuthority: vi.fn(async () => authority),
  };
  return { authority, beginRun, client, input, invite, service };
}

function historicalAliasFixture() {
  return {
    contractorGroup: {
      ...CONTRACTORS,
      members: [] as GoogleGroupSnapshot["members"],
    },
    excludedGoogleUserIds: [] as string[],
    expectedContractorGroupId: "contractors",
    googleUsers: [
      googleUser("101", "current@company.test", {
        aliases: ["old@company.test"],
      }),
    ],
    managedDomain: "company.test",
    minimumGoogleUsers: 1,
    offboardingOnly: true,
    trycompMembers: [
      member("current", "current@company.test"),
      member("historical", "old@company.test", {
        isActive: false,
        deactivated: true,
      }),
    ],
    writeProtectedEmails: [] as string[],
    writeProtectedGoogleUserIds: [] as string[],
  };
}

describe("Trycomp preserved historical aliases", () => {
  it.each([false, true])(
    "retains both records without actions, reversed=%s",
    async (reversed) => {
      const input = historicalAliasFixture();
      if (reversed) input.trycompMembers.reverse();
      const before = structuredClone(input);
      const plan = await buildTrycompPlan(input);
      expect(plan.errors).toEqual([]);
      expect(plan.actions).toEqual([]);
      expect(plan.stats.trycompMembers).toBe(2);
      expect(plan.warnings).toContain(
        "Trycomp retains a verified deactivated historical alias for current@company.test",
      );
      expect(input).toEqual(before);
      const unfiltered = await buildTrycompPlan({
        ...input,
        offboardingOnly: false,
      });
      expect(unfiltered.errors).toEqual([]);
      expect(unfiltered.actions).toEqual([]);
      const reordered = await buildTrycompPlan({
        ...input,
        trycompMembers: input.trycompMembers.toReversed(),
      });
      expect(reordered.planHash).toBe(plan.planHash);
    },
  );

  it.each(["audit", "live"] as const)(
    "preserves both records through the %s service",
    async (mode) => {
      const fixture = historicalAliasFixture();
      const client = new MemoryTrycompClient(fixture.trycompMembers);
      const deactivate = vi.spyOn(client, "deactivate");
      const reactivate = vi.spyOn(client, "reactivate");
      const invite = vi.spyOn(client, "inviteEmployee");
      const service = new TrycompPeopleSyncService(client, {
        ...fixture,
        allowDeactivations: true,
        approvedPlanHash: "",
        maxAutomaticActivations: 1,
        maxAutomaticDeactivations: 1,
        mode,
      });
      const reviewed = await service.captureReviewedPlan(fixture);
      expect(reviewed.plan.errors).toEqual([]);
      expect(reviewed.plan.actions).toEqual([]);
      if (mode === "live") {
        const report = await service.applyReviewed({
          ...fixture,
          ...journaledAuthority(),
          assertWriteAuthority: vi.fn(async () => undefined),
          refreshAuthority: vi.fn(async () => fixture),
          reviewedPlan: reviewed,
        });
        expect(report.status).toBe("converged");
        expect(report.applied).toEqual([]);
      }
      expect(deactivate).not.toHaveBeenCalled();
      expect(reactivate).not.toHaveBeenCalled();
      expect(invite).not.toHaveBeenCalled();
      await expect(client.listMembers()).resolves.toEqual(
        fixture.trycompMembers,
      );
    },
  );

  it("keeps historical records bound to the review fingerprint", async () => {
    const input = historicalAliasFixture();
    const plan = await buildTrycompPlan(input);
    const changed = await buildTrycompPlan({
      ...input,
      trycompMembers: input.trycompMembers.map((record) =>
        record.id === "historical"
          ? { ...record, id: "replacement-history" }
          : record,
      ),
    });
    expect(changed.errors).toEqual([]);
    expect(changed.actions).toEqual(plan.actions);
    expect(changed.planHash).not.toBe(plan.planHash);
  });

  it.each([
    "both-active",
    "both-inactive",
    "current-inconsistent",
    "history-inconsistent",
    "history-personnel-only",
    "current-device",
    "history-device",
    "history-device-unknown",
    "current-platform-admin",
    "history-platform-admin",
    "history-platform-unknown",
    "current-membership-owner",
    "history-membership-owner",
    "google-admin",
    "google-admin-unknown",
    "google-delegated-admin",
    "google-suspended",
    "google-archived",
    "google-deleted",
    "configured-exclusion",
    "protected-id",
    "protected-email",
    "contractor",
    "three-records",
    "same-member-id",
    "two-aliases",
  ] as const)("keeps %s ambiguous and blocked", async (scenario) => {
    const input = historicalAliasFixture();
    const current = input.trycompMembers[0];
    const historical = input.trycompMembers[1];
    const google = input.googleUsers[0];
    if (
      current === undefined ||
      historical === undefined ||
      google === undefined
    )
      throw new Error("Missing identity fixture");
    switch (scenario) {
      case "both-active":
        historical.isActive = true;
        historical.deactivated = false;
        break;
      case "both-inactive":
        current.isActive = false;
        current.deactivated = true;
        break;
      case "current-inconsistent":
        current.deactivated = true;
        break;
      case "history-inconsistent":
        historical.isActive = true;
        break;
      case "history-personnel-only":
        historical.deactivated = false;
        break;
      case "current-device":
        current.fleetDmLabelId = 42;
        break;
      case "history-device":
        historical.fleetDmLabelId = 42;
        break;
      case "history-device-unknown":
        historical.fleetDmLabelId = undefined;
        break;
      case "current-platform-admin":
        current.user.role = "admin";
        break;
      case "history-platform-admin":
        historical.user.role = "admin";
        break;
      case "history-platform-unknown":
        historical.user.role = undefined;
        break;
      case "current-membership-owner":
        current.role = "owner";
        break;
      case "history-membership-owner":
        historical.role = "owner";
        break;
      case "google-admin":
        google.isAdmin = true;
        break;
      case "google-admin-unknown":
        google.isAdmin = undefined;
        break;
      case "google-delegated-admin":
        google.isDelegatedAdmin = true;
        break;
      case "google-suspended":
        google.suspended = true;
        break;
      case "google-archived":
        google.archived = true;
        break;
      case "google-deleted":
        google.deletionTime = "2026-10-01T00:00:00Z";
        break;
      case "configured-exclusion":
        input.excludedGoogleUserIds.push("101");
        break;
      case "protected-id":
        input.writeProtectedGoogleUserIds.push("101");
        break;
      case "protected-email":
        input.writeProtectedEmails.push("old@company.test");
        break;
      case "contractor":
        input.contractorGroup.members.push({
          role: "MEMBER",
          status: "ACTIVE",
          type: "USER",
          id: "101",
          email: "old@company.test",
        });
        break;
      case "three-records":
        input.trycompMembers.push({ ...historical, id: "third" });
        break;
      case "same-member-id":
        historical.id = current.id;
        break;
      case "two-aliases":
        google.aliases?.push("other@company.test");
        current.user.email = "other@company.test";
        break;
    }
    const plan = await buildTrycompPlan(input);
    expect(plan.errors).toContain(
      "Trycomp returned duplicate member identity current@company.test",
    );
    expect(plan.actions).toEqual([]);
    expect(plan.warnings).not.toContain(
      "Trycomp retains a verified deactivated historical alias for current@company.test",
    );
  });

  it("continues planning unrelated identities with their exact provider IDs", async () => {
    const input = historicalAliasFixture();
    input.googleUsers.push(
      googleUser("102", "inactive@company.test", { suspended: true }),
    );
    input.trycompMembers.push(
      member("inactive-member", "inactive@company.test"),
    );
    const plan = await buildTrycompPlan(input);
    expect(plan.errors).toEqual([]);
    expect(plan.actions).toEqual([
      {
        deactivationAuthority: "inactive_google",
        email: "inactive@company.test",
        memberId: "inactive-member",
        type: "deactivate",
      },
    ]);
    expect(plan.stats.trycompMembers).toBe(3);
  });
});

describe("Trycomp exact reviewed service ports", () => {
  it("rejects an unpinned legacy plan before a new provider write", async () => {
    const fixture = reviewedFixture();
    fixture.authority.googleUsers[0] = googleUser("123", "a@company.test");
    const fresh = await fixture.service.captureReviewedPlan(fixture.authority);
    const { selectedIdentity: _pin, ...legacy } = fresh;
    await expect(
      fixture.service.applyReviewed({
        ...fixture.input,
        reviewedPlan: legacy,
      }),
    ).rejects.toThrow("trycomp_reviewed_identity_missing_or_changed");
    expect(fixture.invite).not.toHaveBeenCalled();
    expect(fixture.beginRun).not.toHaveBeenCalled();
  });

  it.each([{ id: "456" }, { isAdmin: true }, { isDelegatedAdmin: true }])(
    "rejects pinned authority replacement or promotion before any dispatch: %j",
    async (change) => {
      const fixture = reviewedFixture();
      fixture.authority.googleUsers[0] = googleUser("123", "a@company.test");
      const reviewed = await fixture.service.captureReviewedPlan(
        fixture.authority,
      );
      fixture.authority.googleUsers[0] = googleUser(
        "123",
        "a@company.test",
        change,
      );
      const list = vi.spyOn(fixture.client, "listMembers");
      await expect(
        fixture.service.readReviewedSlice(reviewed, {
          authority: fixture.authority,
        }),
      ).rejects.toThrow("identity_missing_or_changed");
      await expect(
        fixture.service.applyReviewed({
          ...fixture.input,
          reviewedPlan: reviewed,
        }),
      ).rejects.toThrow("identity_missing_or_changed");
      expect(list).not.toHaveBeenCalled();
      expect(fixture.invite).not.toHaveBeenCalled();
      expect(fixture.beginRun).not.toHaveBeenCalled();
    },
  );

  it("signs the immutable Google identity without inventing an invitation member ID", async () => {
    const fixture = reviewedFixture();
    fixture.authority.googleUsers[0] = googleUser("123", "a@company.test");
    const reviewed = await fixture.service.captureReviewedPlan(
      fixture.authority,
    );
    expect(reviewed.selectedIdentity).toEqual({
      googleUserId: "123",
      provider: { kind: "pending-invitation", email: "a@company.test" },
    });
    const { selectedIdentity: _pin, ...legacy } = reviewed;
    expect(sameReviewedTrycompPlan(legacy, reviewed)).toBe(true);
    expect(sameReviewedTrycompPlan(reviewed, legacy)).toBe(false);
    expect(
      sameReviewedTrycompPlan(reviewed, {
        selectedIdentity: reviewed.selectedIdentity,
        ...legacy,
      }),
    ).toBe(true);
    expect(
      sameReviewedTrycompPlan(legacy, {
        ...reviewed,
        sourceFingerprint: "f".repeat(64),
      }),
    ).toBe(false);
  });

  it("uses the shared alias and deleted-user mapping and excludes ambiguous or privileged authority", async () => {
    const fixture = reviewedFixture();
    const reviewed = await fixture.service.captureReviewedPlan(
      fixture.authority,
    );
    const alias = googleUser("123", "primary@company.test", {
      aliases: ["a@company.test"],
      deletionTime: "2026-08-01T00:00:00Z",
    });
    expect(selectedTrycompIdentity(reviewed.plan, [alias])?.googleUserId).toBe(
      "123",
    );
    for (const users of [
      [],
      [googleUser("123", "a@company.test", { isAdmin: true })],
      [alias, googleUser("456", "a@company.test")],
    ]) {
      expect(selectedTrycompIdentity(reviewed.plan, users)).toBeUndefined();
    }
  });

  it.each([null, "original", "replacement"])(
    "requires the original verified invitation journal identity: %s",
    async (verifiedId) => {
      const fixture = reviewedFixture();
      fixture.authority.googleUsers[0] = googleUser("123", "a@company.test");
      const reviewed = await fixture.service.captureReviewedPlan(
        fixture.authority,
      );
      fixture.client.members.set(
        "original",
        member("original", "a@company.test"),
      );
      const slice = await fixture.service.readReviewedSlice(reviewed, {
        authority: fixture.authority,
        verifiedInvitationMemberId: async () => verifiedId,
      });
      expect(slice).toEqual({
        state: verifiedId === "original" ? "converged" : "drifted",
        selectedIdentity: reviewed.selectedIdentity,
      });
      expect(fixture.invite).not.toHaveBeenCalled();
    },
  );

  it("rejects fresh source drift before provider readback or a required-pin write", async () => {
    const fixture = reviewedFixture();
    fixture.authority.googleUsers[0] = googleUser("123", "a@company.test");
    const reviewed = await fixture.service.captureReviewedPlan(
      fixture.authority,
    );
    const list = vi.spyOn(fixture.client, "listMembers");
    fixture.authority.googleUsers[0] = googleUser("123", "a@company.test", {
      suspended: true,
    });
    await expect(
      fixture.service.readReviewedSlice(reviewed, {
        authority: fixture.authority,
      }),
    ).rejects.toThrow("source_changed");
    expect(list).not.toHaveBeenCalled();
    const { selectedIdentity: _pin, ...legacy } = reviewed;
    await expect(
      fixture.service.applyReviewed({
        ...fixture.input,
        reviewedPlan: legacy,
      }),
    ).rejects.toThrow("identity_missing_or_changed");
    expect(fixture.beginRun).not.toHaveBeenCalled();
    expect(fixture.invite).not.toHaveBeenCalled();
  });

  it("rechecks write authority after journal attempted and before the provider write", async () => {
    const fixture = reviewedFixture();
    const reviewed = await fixture.service.captureReviewedPlan(
      fixture.authority,
    );
    let expired = false;
    vi.spyOn(fixture.input.mutationJournal, "markAttempted").mockImplementation(
      async () => {
        expired = true;
      },
    );
    const ambiguous = vi.spyOn(
      fixture.input.mutationJournal,
      "openForAmbiguous",
    );
    const report = await fixture.service.applyReviewed({
      ...fixture.input,
      assertWriteAuthority: async () => {
        if (expired) throw new Error("review_expired_during_journal");
      },
      reviewedPlan: reviewed,
    });
    expect(report.status).toBe("failed");
    expect(fixture.invite).not.toHaveBeenCalled();
    expect(ambiguous).toHaveBeenCalledOnce();
  });
  it("captures only one selected identity without journal, notification, or provider writes", async () => {
    const fixture = reviewedFixture();
    const reviewed = await fixture.service.captureReviewedPlan(fixture.input);
    expect(reviewed.plan.actions).toEqual([
      { email: "a@company.test", type: "invite" },
    ]);
    expect(reviewed.sourceFingerprint).toMatch(/^[a-f0-9]{64}$/u);
    expect(reviewed.targetBefore).toEqual([]);
    expect(fixture.beginRun).not.toHaveBeenCalled();
    expect(fixture.input.preannounce).not.toHaveBeenCalled();
    expect(fixture.invite).not.toHaveBeenCalled();
    await expect(
      fixture.service.readReviewedSlice(reviewed, {
        authority: fixture.authority,
      }),
    ).resolves.toEqual({
      state: "pending",
      selectedIdentity: reviewed.selectedIdentity,
    });
  });

  it("keeps reviewed identity stable across authority inventory ordering", async () => {
    const fixture = reviewedFixture();
    const first = await fixture.service.captureReviewedPlan(fixture.authority);
    const reordered = await fixture.service.captureReviewedPlan({
      ...fixture.authority,
      googleUsers: fixture.authority.googleUsers.toReversed(),
    });
    expect(reordered).toEqual(first);
  });

  it.each(["isAdmin", "isDelegatedAdmin"] as const)(
    "binds missing %s distinctly from explicit false in the reviewed source",
    async (field) => {
      const fixture = reviewedFixture();
      const knownUsers = fixture.authority.googleUsers.map((user) => ({
        ...user,
        isAdmin: false,
        isDelegatedAdmin: false,
      }));
      const missingUsers = knownUsers.map((user) => ({
        ...user,
        [field]: undefined,
      }));
      const known = await fixture.service.captureReviewedPlan({
        ...fixture.authority,
        googleUsers: knownUsers,
      });
      const missing = await fixture.service.captureReviewedPlan({
        ...fixture.authority,
        googleUsers: missingUsers,
      });
      expect(missing.sourceFingerprint).not.toBe(known.sourceFingerprint);
    },
  );

  it("rejects a changed provider role in the reviewed target slice", async () => {
    const fixture = reviewedFixture();
    fixture.client.members.set(
      "m1",
      member("m1", "a@company.test", { isActive: false, deactivated: true }),
    );
    fixture.client.members.set("m2", member("m2", "b@company.test"));
    const reviewed = await fixture.service.captureReviewedPlan(
      fixture.authority,
    );
    expect(reviewed.plan.actions[0]?.type).toBe("reactivate");
    await expect(
      fixture.service.readReviewedSlice(reviewed, {
        authority: fixture.authority,
      }),
    ).resolves.toEqual({
      state: "pending",
      selectedIdentity: reviewed.selectedIdentity,
    });
    fixture.client.members.set(
      "m1",
      member("m1", "a@company.test", { role: "owner" }),
    );
    await expect(
      fixture.service.readReviewedSlice(reviewed, {
        authority: fixture.authority,
      }),
    ).resolves.toEqual({
      state: "drifted",
      selectedIdentity: reviewed.selectedIdentity,
    });
  });

  it.each(["action", "source", "target", "hash"] as const)(
    "rejects a changed reviewed %s before journal or provider writes",
    async (change) => {
      const fixture = reviewedFixture();
      const reviewed = await fixture.service.captureReviewedPlan(
        fixture.authority,
      );
      switch (change) {
        case "action":
          reviewed.plan.actions = [{ email: "b@company.test", type: "invite" }];
          break;
        case "source":
          reviewed.sourceFingerprint = "f".repeat(64);
          break;
        case "target":
          reviewed.targetBefore = [
            {
              id: "unreviewed",
              email: "a@company.test",
              role: "employee",
              isActive: false,
              deactivated: true,
            },
          ];
          break;
        case "hash":
          reviewed.plan.planHash = "f".repeat(64);
          break;
      }
      const applying = fixture.service.applyReviewed({
        ...fixture.input,
        reviewedPlan: reviewed,
      });
      if (change === "action") {
        await expect(applying).rejects.toThrow(
          "Selected identity must match the sole error-free reviewed action",
        );
      } else {
        const result = await applying;
        expect(result.status).toBe("blocked");
      }
      expect(fixture.beginRun).not.toHaveBeenCalled();
      expect(fixture.input.preannounce).not.toHaveBeenCalled();
      expect(fixture.invite).not.toHaveBeenCalled();
    },
  );

  it("requires original invitation evidence before treating an observed account as converged", async () => {
    const fixture = reviewedFixture();
    const reviewed = await fixture.service.captureReviewedPlan(
      fixture.authority,
    );
    fixture.client.members.set(
      "existing-a",
      member("existing-a", "a@company.test"),
    );
    await expect(
      fixture.service.readReviewedSlice(reviewed, {
        authority: fixture.authority,
      }),
    ).resolves.toEqual({
      state: "drifted",
      selectedIdentity: reviewed.selectedIdentity,
    });
    const result = await fixture.service.applyReviewed({
      ...fixture.input,
      reviewedPlan: reviewed,
    });
    expect(result.status).toBe("blocked");
    expect(result.planned).toEqual(reviewed.plan.actions);
    expect(fixture.beginRun).not.toHaveBeenCalled();
    expect(fixture.invite).not.toHaveBeenCalled();
  });

  it("applies the reviewed identity and keeps its verified milestone stable when more work remains", async () => {
    const fixture = reviewedFixture();
    const reviewed = await fixture.service.captureReviewedPlan(
      fixture.authority,
    );
    const result = await fixture.service.applyReviewed({
      ...fixture.input,
      reviewedPlan: reviewed,
    });
    expect(result.status).toBe("converged");
    expect(result.applied).toEqual(reviewed.plan.actions);
    expect(fixture.invite).toHaveBeenCalledOnce();
    expect(fixture.input.mutationJournal.markVerified).toHaveBeenCalledWith(
      result.runId,
      0,
      "invited-0",
    );
    await expect(
      fixture.service.readReviewedSlice(reviewed, {
        authority: fixture.authority,
        verifiedInvitationMemberId: async () =>
          fixture.input.mutationJournal.markVerified.mock.calls.at(-1)?.[2] ??
          null,
      }),
    ).resolves.toEqual({
      state: "converged",
      selectedIdentity: reviewed.selectedIdentity,
    });
    const next = await fixture.service.captureReviewedPlan(fixture.authority);
    expect(next.plan.actions).toEqual([
      { email: "b@company.test", type: "invite" },
    ]);
    await expect(
      fixture.service.readReviewedSlice(reviewed, {
        authority: fixture.authority,
        verifiedInvitationMemberId: async () =>
          fixture.input.mutationJournal.markVerified.mock.calls.at(-1)?.[2] ??
          null,
      }),
    ).resolves.toEqual({
      state: "converged",
      selectedIdentity: reviewed.selectedIdentity,
    });
  });

  it("fails closed when Google authority changes after preannouncement", async () => {
    const fixture = reviewedFixture();
    const reviewed = await fixture.service.captureReviewedPlan(
      fixture.authority,
    );
    fixture.input.refreshAuthority
      .mockResolvedValueOnce(fixture.authority)
      .mockResolvedValue({
        ...fixture.authority,
        googleUsers: [
          googleUser("101", "a@company.test", {
            aliases: ["new-alias@company.test"],
          }),
          googleUser("102", "b@company.test"),
        ],
      });
    const result = await fixture.service.applyReviewed({
      ...fixture.input,
      reviewedPlan: reviewed,
    });
    expect(result.status).toBe("failed");
    expect(fixture.input.preannounce).toHaveBeenCalledOnce();
    expect(fixture.invite).not.toHaveBeenCalled();
  });

  it("blocks reviewed writes in audit configuration", async () => {
    const fixture = reviewedFixture("audit");
    const reviewed = await fixture.service.captureReviewedPlan(
      fixture.authority,
    );
    const result = await fixture.service.applyReviewed({
      ...fixture.input,
      reviewedPlan: reviewed,
    });
    expect(result.status).toBe("blocked");
    expect(fixture.beginRun).not.toHaveBeenCalled();
    expect(fixture.invite).not.toHaveBeenCalled();
  });

  it("rejects reviewed plans containing more than one action", async () => {
    const fixture = reviewedFixture();
    const reviewed = await fixture.service.captureReviewedPlan(
      fixture.authority,
    );
    expect(
      TrycompReviewedPlanSchema.safeParse({
        ...reviewed,
        plan: {
          ...reviewed.plan,
          actions: [
            ...reviewed.plan.actions,
            { email: "b@company.test", type: "invite" },
          ],
        },
      }).success,
    ).toBe(false);
  });
});

function revocationFixture(offboardingOnly = false) {
  const client = new MemoryTrycompClient([
    member("target", "departed@company.test", {
      isActive: false,
      deactivated: false,
    }),
  ]);
  const authority = {
    activeGoogleUserCount: 1,
    contractorGroup: { ...CONTRACTORS, members: [] },
    googleUsers: [
      {
        ...googleUser("123", "departed@company.test"),
        suspended: true,
        isAdmin: false,
        isDelegatedAdmin: false,
      },
    ],
  };
  const service = new TrycompPeopleSyncService(client, {
    allowDeactivations: true,
    approvedPlanHash: "",
    expectedContractorGroupId: "contractors",
    excludedGoogleUserIds: [],
    managedDomain: "company.test",
    maxAutomaticActivations: 1,
    maxAutomaticDeactivations: 1,
    minimumGoogleUsers: 1,
    mode: "live",
    offboardingOnly,
  });
  const input = {
    ...authority,
    ...journaledAuthority(),
    assertWriteAuthority: vi.fn(async () => undefined),
    refreshAuthority: vi.fn(async () => authority),
  };
  return { authority, client, input, service };
}

describe("Trycomp membership revocation", () => {
  it.each([
    "platform-admin",
    "platform-missing",
    "fleet-associated",
    "fleet-missing",
  ] as const)(
    "refuses %s evidence before selection and after the durable attempt boundary",
    async (scenario) => {
      const fixture = revocationFixture(true);
      const reviewed = await fixture.service.captureReviewedPlan(
        fixture.authority,
      );
      expect(reviewed.targetBefore[0]).toMatchObject({
        platformRole: "user",
        fleetDmLabelId: null,
      });
      const mutate = () => {
        const current = fixture.client.members.get("target");
        if (!current) throw new Error("missing fixture");
        if (scenario === "platform-admin") current.user.role = "admin";
        if (scenario === "platform-missing") current.user.role = undefined;
        if (scenario === "fleet-associated") current.fleetDmLabelId = 42;
        if (scenario === "fleet-missing") current.fleetDmLabelId = undefined;
      };
      const deactivate = vi.spyOn(fixture.client, "deactivate");
      vi.spyOn(
        fixture.input.mutationJournal,
        "markAttempted",
      ).mockImplementation(async () => mutate());
      const result = await fixture.service.applyReviewed({
        ...fixture.input,
        reviewedPlan: reviewed,
      });
      expect(result.status).toBe("failed");
      expect(deactivate).not.toHaveBeenCalled();
      const fresh = await fixture.service.captureReviewedPlan(
        fixture.authority,
      );
      expect(fresh.plan.actions).toEqual([]);
      expect(fresh.plan.warnings).toContain(
        "Trycomp member departed@company.test lacks device-free ordinary-platform-user deactivation evidence",
      );
    },
  );

  it("keeps missing security evidence optional when reading genuine old completed history", async () => {
    const fixture = revocationFixture();
    const reviewed = await fixture.service.captureReviewedPlan(
      fixture.authority,
    );
    const legacy = TrycompReviewedPlanSchema.parse({
      ...reviewed,
      deactivationMode: "membership-revocation",
      targetBefore: reviewed.targetBefore.map(
        ({ fleetDmLabelId: _fleet, platformRole: _role, ...old }) => old,
      ),
    });
    await fixture.client.deactivate("target");
    const current = fixture.client.members.get("target");
    if (!current) throw new Error("missing fixture");
    current.fleetDmLabelId = undefined;
    current.user.role = undefined;
    await expect(
      fixture.service.readReviewedSlice(legacy, {
        authority: fixture.authority,
      }),
    ).resolves.toMatchObject({ state: "converged" });
    await expect(
      fixture.service.readReviewedSlice(reviewed, {
        authority: fixture.authority,
      }),
    ).resolves.toMatchObject({ state: "drifted" });
  });

  it("blocks a legacy write plan even with the same member and current authority", async () => {
    const fixture = revocationFixture();
    const reviewed = await fixture.service.captureReviewedPlan(
      fixture.authority,
    );
    const legacy = TrycompReviewedPlanSchema.parse({
      ...reviewed,
      deactivationMode: "membership-revocation",
      targetBefore: reviewed.targetBefore.map(
        ({ fleetDmLabelId: _fleet, platformRole: _role, ...old }) => old,
      ),
    });
    const deactivate = vi.spyOn(fixture.client, "deactivate");
    const result = await fixture.service.applyReviewed({
      ...fixture.input,
      reviewedPlan: legacy,
    });
    expect(result.status).toBe("blocked");
    expect(deactivate).not.toHaveBeenCalled();
  });

  it.each([
    "platform-admin",
    "platform-missing",
    "fleet-associated",
    "fleet-missing",
  ] as const)(
    "does not verify a revocation after %s evidence changed",
    async (scenario) => {
      const fixture = revocationFixture(true);
      vi.spyOn(fixture.client, "deactivate").mockImplementation(async () => {
        const current = member("target", "departed@company.test", {
          isActive: false,
          deactivated: true,
        });
        if (scenario === "platform-admin") current.user.role = "admin";
        if (scenario === "platform-missing") current.user.role = undefined;
        if (scenario === "fleet-associated") current.fleetDmLabelId = 42;
        if (scenario === "fleet-missing") current.fleetDmLabelId = undefined;
        fixture.client.members.set("target", current);
      });
      const verified = vi.spyOn(fixture.input.mutationJournal, "markVerified");
      const result = await applyNextReviewed(fixture.service, fixture.input);
      expect(result.status).toBe("failed");
      expect(verified).not.toHaveBeenCalled();
    },
  );

  it("leaves an orphaned personnel-inactive account for manual review while revoking one verified departure", async () => {
    const fixture = revocationFixture();
    const orphan = member("orphan", "a-orphan@company.test", {
      isActive: false,
      deactivated: false,
    });
    fixture.client.members.set(orphan.id, orphan);
    const deactivate = vi.spyOn(fixture.client, "deactivate");
    const reviewed = await fixture.service.captureReviewedPlan(
      fixture.authority,
    );
    expect(reviewed.plan.errors).toEqual([]);
    expect(reviewed.plan.warnings).toContain(
      "Personnel-inactive Trycomp member a-orphan@company.test has no Google Directory identity and requires manual access review",
    );
    expect(reviewed.plan.actions).toEqual([
      {
        type: "deactivate",
        memberId: "target",
        email: "departed@company.test",
        deactivationAuthority: "inactive_google",
      },
    ]);
    const result = await fixture.service.applyReviewed({
      ...fixture.input,
      reviewedPlan: reviewed,
    });
    expect(result.status).toBe("converged");
    expect(deactivate).toHaveBeenCalledExactlyOnceWith(
      "target",
      expect.any(String),
    );
    expect(fixture.client.members.get("orphan")).toEqual(orphan);
    expect(fixture.client.members.get("target")).toMatchObject({
      isActive: false,
      deactivated: true,
    });
    await expect(
      fixture.service.readReviewedSlice(reviewed, {
        authority: fixture.authority,
      }),
    ).resolves.toMatchObject({ state: "converged" });
  });

  it.each(["active-orphan", "duplicate-orphan", "google-floor"] as const)(
    "preserves the global %s blocker beside a verified departure",
    async (scenario) => {
      const fixture = revocationFixture();
      fixture.client.members.set(
        "orphan",
        member("orphan", "a-orphan@company.test", {
          isActive: scenario === "active-orphan",
          deactivated: false,
        }),
      );
      if (scenario === "duplicate-orphan")
        fixture.client.members.set(
          "duplicate",
          member("duplicate", "a-orphan@company.test", {
            isActive: false,
            deactivated: false,
          }),
        );
      if (scenario === "google-floor")
        fixture.authority.activeGoogleUserCount = 0;
      const deactivate = vi.spyOn(fixture.client, "deactivate");
      const reviewed = await fixture.service.captureReviewedPlan(
        fixture.authority,
      );
      expect(reviewed.plan.errors.length).toBeGreaterThan(0);
      const result = await fixture.service.applyReviewed({
        ...fixture.input,
        reviewedPlan: reviewed,
      });
      expect(result.status).toBe("blocked");
      expect(deactivate).not.toHaveBeenCalled();
      expect(fixture.client.members.get("target")).toMatchObject({
        isActive: false,
        deactivated: false,
      });
    },
  );

  it("selects a personnel-inactive member for one real revocation and verifies both flags", async () => {
    const fixture = revocationFixture();
    const deactivate = vi.spyOn(fixture.client, "deactivate");
    const reviewed = await fixture.service.captureReviewedPlan(
      fixture.authority,
    );
    expect(reviewed.deactivationMode).toBe("device-free-membership-revocation");
    expect(reviewed.plan.actions).toEqual([
      {
        type: "deactivate",
        memberId: "target",
        email: "departed@company.test",
        deactivationAuthority: "inactive_google",
      },
    ]);
    const result = await fixture.service.applyReviewed({
      ...fixture.input,
      reviewedPlan: reviewed,
    });
    expect(result.status).toBe("converged");
    expect(deactivate).toHaveBeenCalledOnce();
    expect(fixture.client.members.get("target")).toMatchObject({
      isActive: false,
      deactivated: true,
    });
    await expect(
      fixture.service.readReviewedSlice(reviewed, {
        authority: fixture.authority,
      }),
    ).resolves.toMatchObject({ state: "converged" });
  });

  it("rejects a provider response that leaves personnel inactive but membership access intact", async () => {
    const fixture = revocationFixture();
    const deactivate = vi
      .spyOn(fixture.client, "deactivate")
      .mockResolvedValue();
    const verified = vi.spyOn(fixture.input.mutationJournal, "markVerified");
    const result = await applyNextReviewed(fixture.service, fixture.input);
    expect(result).toMatchObject({
      status: "failed",
      errors: ["trycomp_deactivation_not_observed"],
    });
    expect(deactivate).toHaveBeenCalledOnce();
    expect(verified).not.toHaveBeenCalled();
  });

  it.each(["reactivated", "admin", "provider-owner"] as const)(
    "blocks $label after the budget reservation",
    async (change) => {
      const fixture = revocationFixture();
      const deactivate = vi.spyOn(fixture.client, "deactivate");
      vi.spyOn(
        fixture.input.mutationJournal,
        "markAttempted",
      ).mockImplementation(async () => {
        if (change === "provider-owner") {
          fixture.client.members.set(
            "target",
            member("target", "departed@company.test", {
              role: "owner",
              isActive: false,
            }),
          );
        } else {
          fixture.authority.googleUsers = fixture.authority.googleUsers.map(
            (user) => ({
              ...user,
              suspended: change !== "reactivated",
              isAdmin: change === "admin",
            }),
          );
        }
      });
      const result = await applyNextReviewed(fixture.service, fixture.input);
      expect(result.status).toBe("failed");
      expect(deactivate).not.toHaveBeenCalled();
    },
  );

  it("preserves legacy intent readback without upgrading its stored JSON or authorizing a new write", async () => {
    const fixture = revocationFixture();
    const reviewed = await fixture.service.captureReviewedPlan(
      fixture.authority,
    );
    const { deactivationMode: _mode, ...legacy } = reviewed;
    expect(TrycompReviewedPlanSchema.parse(legacy)).toEqual(legacy);
    await expect(
      fixture.service.readReviewedSlice(legacy, {
        authority: fixture.authority,
      }),
    ).resolves.toMatchObject({ state: "converged" });
    await expect(
      fixture.service.readReviewedSlice(reviewed, {
        authority: fixture.authority,
      }),
    ).resolves.toMatchObject({ state: "pending" });
    const deactivate = vi.spyOn(fixture.client, "deactivate");
    const result = await fixture.service.applyReviewed({
      ...fixture.input,
      reviewedPlan: legacy,
    });
    expect(result.status).toBe("blocked");
    expect(deactivate).not.toHaveBeenCalled();
  });

  it("rejects an unexpected removal identity without retrying the DELETE", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(
      Response.json({
        success: true,
        deletedMember: { id: "other", email: "other@company.test" },
      }),
    );
    await expect(
      new TrycompPeopleClient("test-key", fetchImpl).deactivate(
        "target",
        "request",
      ),
    ).rejects.toThrow("trycomp_deactivation_identity_mismatch");
    expect(fetchImpl).toHaveBeenCalledOnce();
  });
});

describe("Trycomp people lifecycle sync", () => {
  it("uses the scoped people API soft-deactivation contract and exact request identity", async () => {
    const requests: Request[] = [];
    const active = member("m1", "employee@company.test");
    const responses = [
      Response.json({ count: 1, data: [active] }),
      Response.json({
        success: true,
        deletedMember: { id: active.id, email: active.user.email },
      }),
      Response.json(active),
      new Response(null, { status: 204 }),
    ];
    const fetchImpl = vi.fn<typeof fetch>(async (input, init) => {
      requests.push(new Request(input, init));
      const response = responses.shift();
      if (!response) throw new Error("unexpected Trycomp request");
      return response;
    });
    const client = new TrycompPeopleClient("test-key", fetchImpl);

    await expect(client.listMembers("operation-list")).resolves.toEqual([
      active,
    ]);
    await client.deactivate("m1", "operation-deactivate");
    await client.reactivate("m1", "operation-reactivate");
    await client.inviteEmployee("new@company.test", "operation-invite");

    expect(requests.map(({ method, url }) => ({ method, url }))).toEqual([
      {
        method: "GET",
        url: "https://api.trycomp.ai/v1/people?includeDeactivated=true",
      },
      {
        method: "DELETE",
        url: "https://api.trycomp.ai/v1/people/m1?skipOffboarding=true",
      },
      { method: "PATCH", url: "https://api.trycomp.ai/v1/people/m1" },
      { method: "POST", url: "https://api.trycomp.ai/v1/people/invite" },
    ]);
    expect(
      requests.every(
        (request) => request.headers.get("x-api-key") === "test-key",
      ),
    ).toBe(true);
    expect(
      requests.map((request) => request.headers.get("x-request-id")),
    ).toEqual([
      "operation-list",
      "operation-deactivate",
      "operation-reactivate",
      "operation-invite",
    ]);
    await expect(requests[1]?.text()).resolves.toBe("");
    await expect(requests[2]?.json()).resolves.toEqual({ isActive: true });
    expect(requests[2]?.headers.get("content-type")).toBe("application/json");
    await expect(requests[3]?.json()).resolves.toEqual({
      invites: [
        {
          email: "new@company.test",
          roles: ["employee"],
          sendPortalEmail: false,
        },
      ],
    });
  });

  it("reactivates through the update-member contract with an idempotent request id", async () => {
    const requests: Request[] = [];
    const reactivated = member("member/1", "employee@company.test");
    const fetchImpl = vi.fn<typeof fetch>((input, init) => {
      requests.push(new Request(input, init));
      return Promise.resolve(Response.json(reactivated));
    });
    const client = new TrycompPeopleClient("test-key", fetchImpl);

    await client.reactivate("member/1", "stable-operation-key");

    expect(requests).toHaveLength(1);
    const request = requests[0];
    expect(request).toBeDefined();
    if (!request) throw new Error("missing Trycomp request");
    expect(request).toMatchObject({
      method: "PATCH",
      url: "https://api.trycomp.ai/v1/people/member%2F1",
    });
    expect(request.headers.get("content-type")).toBe("application/json");
    expect(request.headers.get("x-api-key")).toBe("test-key");
    expect(request.headers.get("x-request-id")).toBe("stable-operation-key");
    await expect(request.json()).resolves.toEqual({ isActive: true });
  });

  it("fails closed when the Trycomp people response appears truncated", async () => {
    const client = new TrycompPeopleClient(
      "test-key",
      vi.fn<typeof fetch>(() =>
        Promise.resolve(
          Response.json({ count: 2, data: [member("m1", "one@company.test")] }),
        ),
      ),
    );

    await expect(client.listMembers("run-1")).rejects.toThrow(
      "trycomp_people_count_mismatch",
    );
  });

  it("changes the authority-bound hash when a Google alias changes without changing actions", async () => {
    const input = {
      contractorGroup: { ...CONTRACTORS, members: [] },
      excludedGoogleUserIds: [],
      expectedContractorGroupId: "contractors",
      managedDomain: "company.test",
      minimumGoogleUsers: 1,
      protectedEmails: [],
      protectedGoogleUserIds: [],
      trycompMembers: [member("m1", "employee@company.test")],
    } satisfies Omit<Parameters<typeof buildTrycompPlan>[0], "googleUsers">;
    const before = await buildTrycompPlan({
      ...input,
      googleUsers: [
        googleUser("101", "employee@company.test", {
          aliases: ["first@company.test"],
        }),
      ],
    });
    const after = await buildTrycompPlan({
      ...input,
      googleUsers: [
        googleUser("101", "employee@company.test", {
          aliases: ["second@company.test"],
        }),
      ],
    });

    expect(before.actions).toEqual(after.actions);
    expect(before.planHash).not.toBe(after.planHash);
  });

  it("binds Google admin protection to the plan hash", async () => {
    const base = {
      contractorGroup: { ...CONTRACTORS, members: [] },
      excludedGoogleUserIds: [],
      expectedContractorGroupId: "contractors",
      managedDomain: "company.test",
      minimumGoogleUsers: 1,
      trycompMembers: [member("m1", "admin@company.test")],
    };
    const ordinary = await buildTrycompPlan({
      ...base,
      googleUsers: [
        googleUser("101", "admin@company.test", { suspended: true }),
      ],
    });
    const admin = await buildTrycompPlan({
      ...base,
      googleUsers: [
        googleUser("101", "admin@company.test", {
          isAdmin: true,
          suspended: true,
        }),
      ],
    });
    expect(ordinary.actions).toHaveLength(1);
    expect(admin.actions).toEqual([]);
    expect(admin.planHash).not.toBe(ordinary.planHash);
  });

  it.each([
    { isAdmin: undefined },
    { isDelegatedAdmin: undefined },
    { isAdmin: undefined, isDelegatedAdmin: undefined },
  ])(
    "blocks every mutation when Google privilege evidence is unknown: %j",
    async (flags) => {
      for (const action of ["invite", "reactivate", "deactivate"] as const) {
        const input = {
          contractorGroup: { ...CONTRACTORS, members: [] },
          excludedGoogleUserIds: [],
          expectedContractorGroupId: "contractors",
          managedDomain: "company.test",
          minimumGoogleUsers: 1,
          trycompMembers:
            action === "invite"
              ? []
              : [
                  member("m1", "alias@company.test", {
                    isActive: action === "deactivate",
                  }),
                ],
        };
        const identity = {
          aliases: ["alias@company.test"],
          suspended: action === "deactivate",
        };
        const known = await buildTrycompPlan({
          ...input,
          googleUsers: [googleUser("101", "employee@company.test", identity)],
        });
        const unknown = await buildTrycompPlan({
          ...input,
          googleUsers: [
            googleUser("101", "employee@company.test", {
              ...identity,
              ...flags,
            }),
          ],
        });
        expect(known.actions).toHaveLength(1);
        expect(known.actions[0]?.type).toBe(action);
        expect(unknown.actions).toEqual([]);
        expect(unknown.planHash).not.toBe(known.planHash);
      }
    },
  );

  it.each([{ isAdmin: true }, { isDelegatedAdmin: true }])(
    "never deactivates a generic Google administrator: %j",
    async (flags) => {
      const plan = await buildTrycompPlan({
        contractorGroup: { ...CONTRACTORS, members: [] },
        excludedGoogleUserIds: [],
        expectedContractorGroupId: "contractors",
        googleUsers: [
          googleUser("admin-id", "admin@company.test", {
            ...flags,
            suspended: true,
          }),
        ],
        managedDomain: "company.test",
        minimumGoogleUsers: 1,
        trycompMembers: [member("admin-member", "admin@company.test")],
      });
      expect(plan.errors).toEqual([]);
      expect(plan.actions).toEqual([]);
    },
  );

  it("uses only current Directory users for the population floor", async () => {
    const plan = await buildTrycompPlan({
      activeGoogleUserCount: 1,
      contractorGroup: { ...CONTRACTORS, members: [] },
      excludedGoogleUserIds: [],
      expectedContractorGroupId: "contractors",
      googleUsers: [
        googleUser("active", "active@company.test"),
        googleUser("deleted", "deleted@company.test", {
          deletionTime: "2026-09-01T00:00:00.000Z",
        }),
      ],
      managedDomain: "company.test",
      minimumGoogleUsers: 2,
      trycompMembers: [],
    });
    expect(plan.errors).toContain(
      "Google Directory population 1 is below floor 2",
    );
  });

  it("blocks denied aliases after a Google primary-email rename", async () => {
    const plan = await buildTrycompPlan({
      activationDeniedEmails: ["old-contractor@company.test"],
      contractorGroup: { ...CONTRACTORS, members: [] },
      excludedGoogleUserIds: [],
      expectedContractorGroupId: "contractors",
      googleUsers: [
        googleUser("contractor-id", "new-contractor@company.test", {
          aliases: ["old-contractor@company.test"],
        }),
      ],
      managedDomain: "company.test",
      minimumGoogleUsers: 1,
      trycompMembers: [],
    });
    expect(plan.actions).toEqual([]);
  });

  it("uses the observed Trycomp alias for exact reactivation readback", async () => {
    const client = new MemoryTrycompClient([
      member("m1", "old@company.test", { deactivated: true, isActive: false }),
    ]);
    const googleUsers = [
      googleUser("101", "new@company.test", { aliases: ["old@company.test"] }),
    ];
    const service = new TrycompPeopleSyncService(client, {
      allowDeactivations: false,
      approvedPlanHash: "",
      expectedContractorGroupId: "contractors",
      excludedGoogleUserIds: [],
      managedDomain: "company.test",
      maxAutomaticActivations: 1,
      maxAutomaticDeactivations: 0,
      minimumGoogleUsers: 1,
      mode: "live",
    });
    const report = await applyNextReviewed(service, {
      assertWriteAuthority: vi.fn(async () => undefined),
      contractorGroup: { ...CONTRACTORS, members: [] },
      googleUsers,
      ...journaledAuthority(),
      refreshAuthority: vi.fn(async () => ({
        contractorGroup: { ...CONTRACTORS, members: [] },
        googleUsers,
      })),
    });
    expect(report.status).toBe("converged");
    expect(report.applied).toEqual([
      {
        email: "new@company.test",
        memberId: "m1",
        providerEmail: "old@company.test",
        type: "reactivate",
      },
    ]);
  });

  it.each([
    ["listMembers", "list-members"],
    ["inviteEmployee", "invite-member"],
    ["reactivate", "reactivate-member"],
    ["deactivate", "deactivate-member"],
  ] as const)(
    "rejects redirects without retrying %s or forwarding credentials",
    async (operation, diagnosticOperation) => {
      const fetchImpl = vi.fn<typeof fetch>(async () =>
        Response.redirect("https://unapproved.example/people", 307),
      );
      const client = new TrycompPeopleClient("test-key", fetchImpl);
      const request =
        operation === "listMembers"
          ? client.listMembers("redirect-operation")
          : client[operation]("employee@example.com", "redirect-operation");

      await expect(request).rejects.toThrow(
        `trycomp_people_${diagnosticOperation}_http_307`,
      );
      expect(fetchImpl).toHaveBeenCalledOnce();
      expect(fetchImpl).toHaveBeenCalledWith(
        expect.stringMatching(/^https:\/\/api\.trycomp\.ai\/v1\/people/),
        expect.objectContaining({ redirect: "manual" }),
      );
    },
  );

  it.each([
    ["listMembers", "list-members", "GET"],
    ["inviteEmployee", "invite-member", "POST"],
    ["reactivate", "reactivate-member", "PATCH"],
    ["deactivate", "deactivate-member", "DELETE"],
  ] as const)(
    "identifies forbidden %s without leaking provider data or retrying",
    async (operation, diagnosticOperation, method) => {
      const response = new Response(
        "private-response-body private-person@example.com",
        {
          status: 403,
        },
      );
      const fetchImpl = vi.fn<typeof fetch>(async () => response);
      const client = new TrycompPeopleClient("private-api-token", fetchImpl);
      const request =
        operation === "listMembers"
          ? client.listMembers("private-request-id")
          : client[operation]("private-target", "private-request-id");

      await expect(request).rejects.toEqual(
        new Error(`trycomp_people_${diagnosticOperation}_http_403`),
      );
      expect(fetchImpl).toHaveBeenCalledOnce();
      expect(fetchImpl.mock.calls[0]?.[1]?.method ?? "GET").toBe(method);
      expect(response.bodyUsed).toBe(true);
    },
  );

  it("bounds provider requests and composes caller cancellation", async () => {
    const timeout = new AbortController();
    const caller = new AbortController();
    const timeoutSpy = vi
      .spyOn(AbortSignal, "timeout")
      .mockReturnValue(timeout.signal);
    const fetchImpl = vi.fn<typeof fetch>(async (_input, init) => {
      const signal = init?.signal;
      if (!signal) throw new Error("expected a bounded signal");
      return new Promise<Response>((_resolve, reject) => {
        signal.addEventListener(
          "abort",
          () => reject(new Error("request aborted", { cause: signal.reason })),
          { once: true },
        );
      });
    });
    const client = new TrycompPeopleClient("test-key", fetchImpl);
    const request = client.listMembers("operation-timeout", caller.signal);

    timeout.abort(new DOMException("timed out", "TimeoutError"));

    await expect(request).rejects.toThrow("trycomp_people_request_timeout");
    expect(timeoutSpy).toHaveBeenCalledWith(30_000);
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(caller.signal.aborted).toBe(false);
    timeoutSpy.mockRestore();
  });

  it("classifies caller cancellation and provider fetch rejection without retrying", async () => {
    const caller = new AbortController();
    caller.abort(new DOMException("cancelled", "AbortError"));
    const cancelledFetch = vi.fn<typeof fetch>(() =>
      Promise.reject(
        new Error("request cancelled", { cause: caller.signal.reason }),
      ),
    );
    const rejectedFetch = vi.fn<typeof fetch>(() =>
      Promise.reject(new Error("socket closed")),
    );

    await expect(
      new TrycompPeopleClient("test-key", cancelledFetch).listMembers(
        "operation-cancelled",
        caller.signal,
      ),
    ).rejects.toThrow("trycomp_people_request_aborted");
    await expect(
      new TrycompPeopleClient("test-key", rejectedFetch).listMembers(
        "operation-rejected",
      ),
    ).rejects.toThrow("trycomp_people_fetch_failed");
    expect(cancelledFetch).toHaveBeenCalledOnce();
    expect(rejectedFetch).toHaveBeenCalledOnce();
  });

  it.each([
    ["SUSPENDED", { suspended: true }],
    ["ARCHIVED", { archived: true }],
  ] as const)(
    "retains verified %s contractor exclusion without granting access",
    async (status, state) => {
      const input = {
        contractorGroup: {
          ...CONTRACTORS,
          members: CONTRACTORS.members.map((entry) => ({ ...entry, status })),
        },
        excludedGoogleUserIds: [],
        expectedContractorGroupId: "contractors",
        googleUsers: [googleUser("102", "contractor@company.test", state)],
        managedDomain: "company.test",
        minimumGoogleUsers: 1,
      };
      const activeMembership = await buildTrycompPlan({
        ...input,
        trycompMembers: [member("m2", "contractor@company.test")],
      });
      expect(activeMembership.errors).toEqual([]);
      expect(activeMembership.actions).toEqual([
        {
          deactivationAuthority: "contractor_group",
          email: "contractor@company.test",
          memberId: "m2",
          type: "deactivate",
        },
      ]);
      expect(activeMembership.stats.activeGoogleEmployees).toBe(0);
      expect(activeMembership.stats.contractorGoogleUsers).toBe(1);
      for (const trycompMembers of [
        [],
        [
          member("m2", "contractor@company.test", {
            isActive: false,
            deactivated: true,
          }),
        ],
      ]) {
        const plan = await buildTrycompPlan({ ...input, trycompMembers });
        expect(plan.errors).toEqual([]);
        expect(plan.actions).toEqual([]);
      }
      for (const protection of [
        { excludedGoogleUserIds: ["102"] },
        { writeProtectedGoogleUserIds: ["102"] },
        {
          googleUsers: [
            googleUser("102", "contractor@company.test", {
              ...state,
              isAdmin: true,
            }),
          ],
        },
        {
          trycompMembers: [
            member("m2", "contractor@company.test", { role: "owner" }),
          ],
        },
      ]) {
        const protectedPlan = await buildTrycompPlan({
          ...input,
          trycompMembers: [member("m2", "contractor@company.test")],
          ...protection,
        });
        expect(protectedPlan.errors).toEqual([]);
        expect(protectedPlan.actions).toEqual([]);
      }
    },
  );

  it.each([
    [{ id: "wrong-id" }, "immutable ID mismatch"],
    [{ type: "GROUP" as const }, "Nested contractor group"],
    [{ email: "unknown@company.test" }, "has no Google identity"],
  ])(
    "blocks invalid inactive contractor identity %j",
    async (groupMember, reason) => {
      const plan = await buildTrycompPlan({
        contractorGroup: {
          ...CONTRACTORS,
          members: CONTRACTORS.members.map((entry) => ({
            ...entry,
            status: "SUSPENDED" as const,
            ...groupMember,
          })),
        },
        excludedGoogleUserIds: [],
        expectedContractorGroupId: "contractors",
        googleUsers: [
          googleUser("102", "contractor@company.test", { suspended: true }),
        ],
        managedDomain: "company.test",
        minimumGoogleUsers: 1,
        trycompMembers: [],
      });
      expect(plan.errors.join("\n")).toContain(reason);
      expect(plan.actions).toEqual([]);
    },
  );

  it.each([
    ["UNKNOWN", { suspended: true }],
    ["SUSPENDED", {}],
    ["ARCHIVED", {}],
    ["SUSPENDED", { archived: true }],
    ["ARCHIVED", { suspended: true }],
  ] as const)(
    "blocks ambiguous contractor status %s with lifecycle %j",
    async (status, state) => {
      const plan = await buildTrycompPlan({
        contractorGroup: {
          ...CONTRACTORS,
          members: CONTRACTORS.members.map((entry) => ({ ...entry, status })),
        },
        excludedGoogleUserIds: [],
        expectedContractorGroupId: "contractors",
        googleUsers: [googleUser("102", "contractor@company.test", state)],
        managedDomain: "company.test",
        minimumGoogleUsers: 1,
        trycompMembers: [],
      });
      expect(plan.errors).toContain(
        `Contractor group member contractor@company.test has ambiguous ${status} status`,
      );
      expect(plan.actions).toEqual([]);
    },
  );

  it("plans employees and records explicit contractor and inactive-Google authority", async () => {
    const plan = await buildTrycompPlan({
      contractorGroup: CONTRACTORS,
      excludedGoogleUserIds: [],
      expectedContractorGroupId: "contractors",
      googleUsers: [
        googleUser("101", "employee@company.test"),
        googleUser("102", "contractor@company.test"),
        googleUser("103", "departed@company.test", { suspended: true }),
      ],
      managedDomain: "company.test",
      minimumGoogleUsers: 3,
      protectedEmails: [],
      protectedGoogleUserIds: [],
      trycompMembers: [
        member("m2", "contractor@company.test"),
        member("m3", "departed@company.test"),
      ],
    });

    expect(plan.errors).toEqual([]);
    expect(plan.actions).toEqual([
      {
        deactivationAuthority: "contractor_group",
        email: "contractor@company.test",
        memberId: "m2",
        type: "deactivate",
      },
      {
        deactivationAuthority: "inactive_google",
        email: "departed@company.test",
        memberId: "m3",
        type: "deactivate",
      },
      { email: "employee@company.test", type: "invite" },
    ]);
    expect(plan.stats).toEqual({
      activeGoogleEmployees: 1,
      contractorGoogleUsers: 1,
      trycompMembers: 2,
    });
  });

  it.each(["contractor_group", "inactive_google"] as const)(
    "prioritizes %s deactivation over lexically earlier activations under the shared limit",
    async (deactivationAuthority) => {
      const offboarded = googleUser(
        "103",
        "z-offboard@company.test",
        deactivationAuthority === "inactive_google" ? { suspended: true } : {},
      );
      const googleUsers = [
        googleUser("101", "a-invite@company.test"),
        googleUser("102", "b-reactivate@company.test"),
        offboarded,
      ];
      const trycompMembers = [
        member("m1", "b-reactivate@company.test", {
          deactivated: true,
          isActive: false,
        }),
        member("m2", "z-offboard@company.test"),
      ];
      const contractorGroup = {
        ...CONTRACTORS,
        members:
          deactivationAuthority === "contractor_group"
            ? [
                {
                  email: offboarded.primaryEmail,
                  id: offboarded.id,
                  role: "MEMBER" as const,
                  status: "ACTIVE" as const,
                  type: "USER" as const,
                },
              ]
            : [],
      };
      const input = {
        automaticIdentityLimit: 1 as const,
        contractorGroup,
        excludedGoogleUserIds: [],
        expectedContractorGroupId: "contractors",
        googleUsers,
        managedDomain: "company.test",
        minimumGoogleUsers: 3,
        protectedEmails: [],
        protectedGoogleUserIds: [],
        trycompMembers,
      };

      const plan = await buildTrycompPlan(input);
      const reordered = await buildTrycompPlan({
        ...input,
        contractorGroup: {
          ...contractorGroup,
          members: contractorGroup.members.toReversed(),
        },
        googleUsers: googleUsers.toReversed(),
        trycompMembers: trycompMembers.toReversed(),
      });

      expect(plan.actions).toEqual([
        {
          deactivationAuthority,
          email: offboarded.primaryEmail,
          memberId: "m2",
          type: "deactivate",
        },
      ]);
      expect(plan.warnings).toContain(
        "Additional Trycomp changes deferred by the shared one-identity automatic limit",
      );
      expect(reordered).toEqual(plan);
    },
  );

  it("shares one automatic identity across activation and deactivation even with approval", async () => {
    const client = new MemoryTrycompClient([
      member("m1", "employee@company.test", {
        deactivated: true,
        isActive: false,
      }),
      member("m2", "contractor@company.test"),
    ]);
    const googleUsers = [
      googleUser("101", "employee@company.test"),
      googleUser("102", "contractor@company.test"),
    ];
    const plan = await buildTrycompPlan({
      contractorGroup: CONTRACTORS,
      excludedGoogleUserIds: [],
      expectedContractorGroupId: "contractors",
      googleUsers,
      managedDomain: "company.test",
      minimumGoogleUsers: 2,
      protectedEmails: [],
      protectedGoogleUserIds: [],
      trycompMembers: await client.listMembers(),
    });
    const service = new TrycompPeopleSyncService(client, {
      allowDeactivations: true,
      approvedPlanHash: plan.planHash,
      expectedContractorGroupId: "contractors",
      excludedGoogleUserIds: [],
      managedDomain: "company.test",
      maxAutomaticActivations: 2,
      maxAutomaticDeactivations: 1,
      minimumGoogleUsers: 2,
      mode: "live",
      protectedEmails: [],
      protectedGoogleUserIds: [],
    });

    const first = await applyNextReviewed(service, {
      assertWriteAuthority: vi.fn(async () => undefined),
      contractorGroup: CONTRACTORS,
      googleUsers,
      ...journaledAuthority(),
      refreshAuthority: vi.fn(async () => ({
        contractorGroup: CONTRACTORS,
        googleUsers,
      })),
    });

    expect(first.status).toBe("converged");
    expect(first.planned).toEqual([
      {
        deactivationAuthority: "contractor_group",
        email: "contractor@company.test",
        memberId: "m2",
        type: "deactivate",
      },
    ]);
    expect(first.applied).toEqual(first.planned);
    expect(first.warnings).toContain(
      "Additional Trycomp changes deferred by the shared one-identity automatic limit",
    );
    expect(client.members.get("m2")).toMatchObject({ isActive: false });

    const second = await applyNextReviewed(service, {
      assertWriteAuthority: vi.fn(async () => undefined),
      contractorGroup: CONTRACTORS,
      googleUsers,
      ...journaledAuthority(),
      refreshAuthority: vi.fn(async () => ({
        contractorGroup: CONTRACTORS,
        googleUsers,
      })),
    });

    expect(second.status).toBe("converged");
    expect(client.members.get("m1")).toMatchObject({
      deactivated: false,
      isActive: true,
    });
    expect(client.members.get("m2")).toMatchObject({
      isActive: false,
    });
    expect(second.planned).toEqual([
      { email: "employee@company.test", memberId: "m1", type: "reactivate" },
    ]);
    expect(second.applied).toEqual(second.planned);
  });

  it("returns a journal completion failure after one write without throwing into a new selection", async () => {
    const client = new MemoryTrycompClient([]);
    const googleUsers = [
      googleUser("102", "zebra@company.test"),
      googleUser("101", "alpha@company.test"),
    ];
    const contractorGroup = { ...CONTRACTORS, members: [] };
    const service = new TrycompPeopleSyncService(client, {
      allowDeactivations: true,
      approvedPlanHash: "",
      expectedContractorGroupId: "contractors",
      excludedGoogleUserIds: [],
      managedDomain: "company.test",
      maxAutomaticActivations: 2,
      maxAutomaticDeactivations: 1,
      minimumGoogleUsers: 2,
      mode: "live",
    });
    const authority = journaledAuthority();
    vi.spyOn(authority.mutationJournal, "completeRun").mockRejectedValue(
      new Error("journal_unavailable"),
    );
    const report = await applyNextReviewed(service, {
      ...authority,
      assertWriteAuthority: vi.fn(async () => undefined),
      contractorGroup,
      googleUsers,
      refreshAuthority: vi.fn(async () => ({ contractorGroup, googleUsers })),
    });
    expect(report.status).toBe("failed");
    expect(report.errors).toEqual(["journal_unavailable"]);
    expect(report.applied).toEqual([
      { email: "alpha@company.test", type: "invite" },
    ]);
    expect(
      client.members
        .values()
        .map(({ user }) => user.email)
        .toArray(),
    ).toEqual(["alpha@company.test"]);
  });

  it("verifies the exact Slack preannouncement before the first provider write", async () => {
    const trace: string[] = [];
    const members: TrycompMember[] = [];
    const client = {
      deactivate: vi.fn(async () => undefined),
      inviteEmployee: vi.fn(async (email: string) => {
        trace.push("provider:write");
        members.push(member("invited", email));
      }),
      listMembers: vi.fn(async () => structuredClone(members)),
      reactivate: vi.fn(async () => undefined),
    } satisfies ITrycompPeopleClient;
    const service = new TrycompPeopleSyncService(client, {
      allowDeactivations: false,
      approvedPlanHash: "",
      expectedContractorGroupId: "contractors",
      excludedGoogleUserIds: [],
      managedDomain: "company.test",
      maxAutomaticActivations: 1,
      maxAutomaticDeactivations: 0,
      minimumGoogleUsers: 1,
      mode: "live",
      protectedEmails: [],
      protectedGoogleUserIds: [],
    });
    const authority = journaledAuthority();
    const report = await applyNextReviewed(service, {
      assertWriteAuthority: vi.fn(async () => undefined),
      contractorGroup: { ...CONTRACTORS, members: [] },
      googleUsers: [googleUser("101", "employee@company.test")],
      ...authority,
      preannounce: vi.fn(async (announced) => {
        expect(announced.planned).toEqual([
          { email: "employee@company.test", type: "invite" },
        ]);
        trace.push("slack:verified");
        return { intentKey: "c".repeat(64), slackTimestamp: "222.333" };
      }),
      refreshAuthority: vi.fn(async () => ({
        contractorGroup: { ...CONTRACTORS, members: [] },
        googleUsers: [googleUser("101", "employee@company.test")],
      })),
    });

    expect(report.status).toBe("converged");
    expect(trace).toEqual(["slack:verified", "provider:write"]);
  });

  it("fails closed without calling the provider when Slack preannouncement is unverified", async () => {
    const client = {
      deactivate: vi.fn(async () => undefined),
      inviteEmployee: vi.fn(async () => undefined),
      listMembers: vi.fn(async () => []),
      reactivate: vi.fn(async () => undefined),
    } satisfies ITrycompPeopleClient;
    const service = new TrycompPeopleSyncService(client, {
      allowDeactivations: false,
      approvedPlanHash: "",
      expectedContractorGroupId: "contractors",
      excludedGoogleUserIds: [],
      managedDomain: "company.test",
      maxAutomaticActivations: 1,
      maxAutomaticDeactivations: 0,
      minimumGoogleUsers: 1,
      mode: "live",
      protectedEmails: [],
      protectedGoogleUserIds: [],
    });
    const report = await applyNextReviewed(service, {
      assertWriteAuthority: vi.fn(async () => undefined),
      contractorGroup: { ...CONTRACTORS, members: [] },
      googleUsers: [googleUser("101", "employee@company.test")],
      ...journaledAuthority(),
      preannounce: vi.fn(async () => {
        throw new Error("trycomp_preannouncement_readback_failed");
      }),
      refreshAuthority: vi.fn(async () => ({
        contractorGroup: { ...CONTRACTORS, members: [] },
        googleUsers: [googleUser("101", "employee@company.test")],
      })),
    });

    expect(report).toMatchObject({
      applied: [],
      errors: ["trycomp_preannouncement_readback_failed"],
      status: "failed",
    });
    expect(client.inviteEmployee).not.toHaveBeenCalled();
  });

  it("blocks deactivation when the independent gate is closed", async () => {
    const client = new MemoryTrycompClient([
      member("m2", "departed@company.test"),
    ]);
    const noContractors = { ...CONTRACTORS, members: [] };
    const service = new TrycompPeopleSyncService(client, {
      allowDeactivations: false,
      approvedPlanHash: "",
      expectedContractorGroupId: "contractors",
      excludedGoogleUserIds: [],
      managedDomain: "company.test",
      maxAutomaticActivations: 1,
      maxAutomaticDeactivations: 1,
      minimumGoogleUsers: 1,
      mode: "live",
      protectedEmails: [],
      protectedGoogleUserIds: [],
    });

    const report = await applyNextReviewed(service, {
      assertWriteAuthority: vi.fn(async () => undefined),
      contractorGroup: noContractors,
      googleUsers: [
        googleUser("102", "departed@company.test", { suspended: true }),
      ],
      ...journaledAuthority(),
      refreshAuthority: vi.fn(async () => ({
        contractorGroup: noContractors,
        googleUsers: [
          googleUser("102", "departed@company.test", { suspended: true }),
        ],
      })),
    });

    expect(report).toMatchObject({
      applied: [],
      errors: ["Trycomp deactivations are disabled"],
      status: "blocked",
    });
  });

  it("checks the write authority before a reviewed provider interaction", async () => {
    const fixture = reviewedFixture();
    const reviewedPlan = await fixture.service.captureReviewedPlan(
      fixture.authority,
    );
    const list = vi.spyOn(fixture.client, "listMembers");
    fixture.input.assertWriteAuthority.mockRejectedValue(
      new Error("resource_lease_fenced"),
    );
    await expect(
      fixture.service.applyReviewed({
        ...fixture.input,
        reviewedPlan,
      }),
    ).rejects.toThrow("resource_lease_fenced");
    expect(list).not.toHaveBeenCalled();
    expect(fixture.invite).not.toHaveBeenCalled();
    expect(fixture.beginRun).not.toHaveBeenCalled();
  });

  it("blocks when the fresh Trycomp preflight changes the authority-bound plan", async () => {
    const initialMember = member("m1", "contractor@company.test");
    const first = [initialMember];
    const second = [{ ...initialMember, isActive: false }];
    let lists = 0;
    const client = {
      deactivate: vi.fn(async () => undefined),
      inviteEmployee: vi.fn(async () => undefined),
      listMembers: vi.fn(async () =>
        structuredClone(lists++ === 0 ? first : second),
      ),
      reactivate: vi.fn(async () => undefined),
    } satisfies ITrycompPeopleClient;
    const service = new TrycompPeopleSyncService(client, {
      allowDeactivations: true,
      approvedPlanHash: "",
      expectedContractorGroupId: "contractors",
      excludedGoogleUserIds: [],
      managedDomain: "company.test",
      maxAutomaticActivations: 0,
      maxAutomaticDeactivations: 1,
      minimumGoogleUsers: 1,
      mode: "live",
      protectedEmails: [],
      protectedGoogleUserIds: [],
    });

    const report = await applyNextReviewed(service, {
      assertWriteAuthority: vi.fn(async () => undefined),
      contractorGroup: CONTRACTORS,
      googleUsers: [googleUser("102", "contractor@company.test")],
      ...journaledAuthority(),
      refreshAuthority: vi.fn(async () => ({
        contractorGroup: CONTRACTORS,
        googleUsers: [googleUser("102", "contractor@company.test")],
      })),
    });

    expect(report).toMatchObject({
      applied: [],
      errors: ["Trycomp authority changed during live preflight"],
      status: "blocked",
    });
    expect(client.deactivate).not.toHaveBeenCalled();
  });

  it("blocks when fresh Google contractor authority changes before a write", async () => {
    const client = new MemoryTrycompClient([
      member("m1", "contractor@company.test"),
    ]);
    const activeUser = googleUser("102", "contractor@company.test");
    const service = new TrycompPeopleSyncService(client, {
      allowDeactivations: true,
      approvedPlanHash: "",
      expectedContractorGroupId: "contractors",
      excludedGoogleUserIds: [],
      managedDomain: "company.test",
      maxAutomaticActivations: 0,
      maxAutomaticDeactivations: 1,
      minimumGoogleUsers: 1,
      mode: "live",
      protectedEmails: [],
      protectedGoogleUserIds: [],
    });

    const report = await applyNextReviewed(service, {
      assertWriteAuthority: vi.fn(async () => undefined),
      contractorGroup: CONTRACTORS,
      googleUsers: [activeUser],
      ...journaledAuthority(),
      refreshAuthority: vi.fn(async () => ({
        contractorGroup: { ...CONTRACTORS, members: [] },
        googleUsers: [activeUser],
      })),
    });

    expect(report).toMatchObject({
      applied: [],
      errors: ["Trycomp authority changed during live preflight"],
      status: "blocked",
    });
    expect(client.members.get("m1")).toMatchObject({ isActive: true });
  });

  it("revalidates direct immutable contractor authority immediately before the write", async () => {
    const client = new MemoryTrycompClient([
      member("m1", "contractor@company.test"),
    ]);
    const contractor = googleUser("102", "contractor@company.test");
    let refreshes = 0;
    const service = new TrycompPeopleSyncService(client, {
      allowDeactivations: true,
      approvedPlanHash: "",
      expectedContractorGroupId: "contractors",
      excludedGoogleUserIds: [],
      managedDomain: "company.test",
      maxAutomaticActivations: 0,
      maxAutomaticContractorDeactivations: 1,
      maxAutomaticDeactivations: 1,
      maxAutomaticInactiveGoogleDeactivations: 0,
      minimumGoogleUsers: 1,
      mode: "live",
      writeProtectedEmails: [],
      writeProtectedGoogleUserIds: [],
    });

    const report = await applyNextReviewed(service, {
      assertWriteAuthority: vi.fn(async () => undefined),
      contractorGroup: CONTRACTORS,
      googleUsers: [contractor],
      ...journaledAuthority(),
      refreshAuthority: vi.fn(async () => ({
        contractorGroup:
          refreshes++ === 0 ? CONTRACTORS : { ...CONTRACTORS, members: [] },
        googleUsers: [contractor],
      })),
    });

    expect(report).toMatchObject({
      applied: [],
      errors: ["trycomp_action_authority_changed"],
      status: "failed",
    });
    expect(client.members.get("m1")).toMatchObject({ isActive: true });
  });

  it("stops before provider mutation when the D1 generation fence is lost", async () => {
    const client = new MemoryTrycompClient([]);
    let assertions = 0;
    const service = new TrycompPeopleSyncService(client, {
      allowDeactivations: false,
      approvedPlanHash: "",
      expectedContractorGroupId: "contractors",
      excludedGoogleUserIds: [],
      managedDomain: "company.test",
      maxAutomaticActivations: 1,
      maxAutomaticDeactivations: 0,
      minimumGoogleUsers: 1,
      mode: "live",
      protectedEmails: [],
      protectedGoogleUserIds: [],
    });

    await expect(
      applyNextReviewed(service, {
        assertWriteAuthority: vi.fn(async () => {
          assertions += 1;
          if (assertions === 2) throw new Error("resource_lease_fenced");
        }),
        contractorGroup: { ...CONTRACTORS, members: [] },
        googleUsers: [googleUser("101", "employee@company.test")],
        ...journaledAuthority(),
        refreshAuthority: vi.fn(async () => ({
          contractorGroup: { ...CONTRACTORS, members: [] },
          googleUsers: [googleUser("101", "employee@company.test")],
        })),
      }),
    ).resolves.toMatchObject({
      applied: [],
      errors: ["resource_lease_fenced"],
      status: "failed",
    });
    expect(client.members.size).toBe(0);
  });

  it("recognizes owner-role contractors while preserving write-protected admins", async () => {
    const rootadmin = googleUser(
      "999999999999999999902",
      "root-admin@company.test",
    );
    const plan = await buildTrycompPlan({
      contractorGroup: {
        ...CONTRACTORS,
        members: [
          ...CONTRACTORS.members,
          {
            email: "root-admin@company.test",
            id: rootadmin.id,
            role: "OWNER",
            status: "ACTIVE",
            type: "USER",
          },
        ],
      },
      excludedGoogleUserIds: [],
      expectedContractorGroupId: "contractors",
      googleUsers: [rootadmin, googleUser("102", "contractor@company.test")],
      managedDomain: "company.test",
      minimumGoogleUsers: 2,
      protectedEmails: ["root-admin@company.test"],
      protectedGoogleUserIds: [rootadmin.id],
      trycompMembers: [member("rootadmin-member", "root-admin@company.test")],
    });

    expect(plan.errors).toEqual([]);
    expect(plan.actions).not.toContainEqual(
      expect.objectContaining({
        email: "root-admin@company.test",
        type: "deactivate",
      }),
    );
    expect(plan.stats.contractorGoogleUsers).toBe(2);
  });

  it.each([
    googleUser("999999999999999999902", "renamed@company.test"),
    googleUser("different-id", "renamed@company.test", {
      aliases: ["root-admin@company.test"],
    }),
  ])(
    "hard-blocks root administrator by immutable ID or alias even with empty runtime protection",
    async (rootadmin) => {
      const client = new MemoryTrycompClient([
        member("rootadmin-member", "renamed@company.test"),
      ]);
      const service = new TrycompPeopleSyncService(client, {
        allowDeactivations: true,
        approvedPlanHash: "",
        expectedContractorGroupId: "contractors",
        excludedGoogleUserIds: [],
        managedDomain: "company.test",
        maxAutomaticActivations: 1,
        maxAutomaticContractorDeactivations: 1,
        maxAutomaticInactiveGoogleDeactivations: 1,
        minimumGoogleUsers: 1,
        mode: "live",
        writeProtectedEmails: [],
        writeProtectedGoogleUserIds: [],
      });

      const reviewed = await service.captureReviewedPlan({
        contractorGroup: { ...CONTRACTORS, members: [] },
        googleUsers: [{ ...rootadmin, suspended: true }],
      });
      expect(reviewed.plan.actions).toEqual([]);
      expect(client.members.get("rootadmin-member")).toMatchObject({
        isActive: true,
      });
    },
  );

  it("never activates denied identities but still deactivates them with Google authority", async () => {
    const serviceIdentity = googleUser(
      "trycomp-service-id",
      "service@company.test",
    );
    const excludedperson = {
      ...googleUser("excludedperson-id", "excluded-four@company.test"),
      suspended: true,
    };
    const plan = await buildTrycompPlan({
      activationDeniedEmails: employeeEntitlementExcludedEmails(),
      contractorGroup: { ...CONTRACTORS, members: [] },
      excludedGoogleUserIds: [],
      expectedContractorGroupId: "contractors",
      googleUsers: [serviceIdentity, excludedperson],
      managedDomain: "company.test",
      minimumGoogleUsers: 2,
      protectedEmails: [],
      protectedGoogleUserIds: [],
      trycompMembers: [
        member("excludedperson-member", "excluded-four@company.test"),
      ],
    });

    expect(plan.errors).toEqual([]);
    expect(plan.actions).toEqual([
      {
        deactivationAuthority: "inactive_google",
        email: "excluded-four@company.test",
        memberId: "excludedperson-member",
        type: "deactivate",
      },
    ]);
  });

  it("fully protects the Trycomp service identity without requiring a Google identity", async () => {
    const rootadmin = googleUser(
      "999999999999999999902",
      "root-admin@company.test",
    );
    const plan = await buildTrycompPlan({
      activationDeniedEmails: employeeEntitlementExcludedEmails(),
      contractorGroup: { ...CONTRACTORS, members: [] },
      excludedGoogleUserIds: [],
      expectedContractorGroupId: "contractors",
      googleUsers: [rootadmin],
      managedDomain: "company.test",
      minimumGoogleUsers: 1,
      trycompMembers: [member("service-member", "service@company.test")],
      writeProtectedEmails: ["root-admin@company.test", "service@company.test"],
      writeProtectedGoogleUserIds: ["999999999999999999902"],
    });

    expect(plan.errors).toEqual([]);
    expect(plan.actions).toEqual([]);
  });

  it("deactivates an activation-denied direct contractor but never reactivates them", async () => {
    const excludedperson = googleUser(
      "excludedperson-id",
      "excluded-four@company.test",
    );
    const contractorGroup = {
      ...CONTRACTORS,
      members: [
        {
          email: "excluded-four@company.test",
          id: "excludedperson-id",
          role: "MEMBER" as const,
          status: "ACTIVE" as const,
          type: "USER" as const,
        },
      ],
    };
    const active = await buildTrycompPlan({
      activationDeniedEmails: ["excluded-four@company.test"],
      contractorGroup,
      excludedGoogleUserIds: [],
      expectedContractorGroupId: "contractors",
      googleUsers: [excludedperson],
      managedDomain: "company.test",
      minimumGoogleUsers: 1,
      trycompMembers: [
        member("excludedperson-member", "excluded-four@company.test"),
      ],
    });
    const inactive = await buildTrycompPlan({
      activationDeniedEmails: ["excluded-four@company.test"],
      contractorGroup,
      excludedGoogleUserIds: [],
      expectedContractorGroupId: "contractors",
      googleUsers: [excludedperson],
      managedDomain: "company.test",
      minimumGoogleUsers: 1,
      trycompMembers: [
        member("excludedperson-member", "excluded-four@company.test", {
          deactivated: true,
          isActive: false,
        }),
      ],
    });

    expect(active.actions).toEqual([
      {
        deactivationAuthority: "contractor_group",
        email: "excluded-four@company.test",
        memberId: "excludedperson-member",
        type: "deactivate",
      },
    ]);
    expect(inactive.actions).toEqual([]);
  });

  it("freezes excluded identities instead of deprovisioning them", async () => {
    const plan = await buildTrycompPlan({
      contractorGroup: { ...CONTRACTORS, members: [] },
      excludedGoogleUserIds: ["frozen-id"],
      expectedContractorGroupId: "contractors",
      googleUsers: [googleUser("frozen-id", "frozen@company.test")],
      managedDomain: "company.test",
      minimumGoogleUsers: 1,
      protectedEmails: [],
      protectedGoogleUserIds: [],
      trycompMembers: [member("frozen-member", "frozen@company.test")],
    });

    expect(plan.errors).toEqual([]);
    expect(plan.actions).toEqual([]);
  });

  it("blocks missing Google authority and privileged Trycomp roles", async () => {
    const missing = await buildTrycompPlan({
      contractorGroup: { ...CONTRACTORS, members: [] },
      excludedGoogleUserIds: [],
      expectedContractorGroupId: "contractors",
      googleUsers: [googleUser("101", "employee@company.test")],
      managedDomain: "company.test",
      minimumGoogleUsers: 1,
      protectedEmails: [],
      protectedGoogleUserIds: [],
      trycompMembers: [member("unknown", "unknown@company.test")],
    });
    const privileged = await buildTrycompPlan({
      contractorGroup: CONTRACTORS,
      excludedGoogleUserIds: [],
      expectedContractorGroupId: "contractors",
      googleUsers: [googleUser("102", "contractor@company.test")],
      managedDomain: "company.test",
      minimumGoogleUsers: 1,
      protectedEmails: [],
      protectedGoogleUserIds: [],
      trycompMembers: [
        member("owner-member", "contractor@company.test", { role: "owner" }),
      ],
    });

    expect(missing.actions).toEqual([
      { email: "employee@company.test", type: "invite" },
    ]);
    expect(missing.errors).toContain(
      "Trycomp member unknown@company.test has no Google Directory identity",
    );
    expect(privileged.actions).toEqual([]);
    expect(privileged.errors).toEqual([]);
    expect(privileged.warnings).toContain(
      "Trycomp member contractor@company.test retains protected non-removable role owner",
    );
  });
});

describe("Trycomp Google offboarding-only selection", () => {
  function input() {
    return {
      automaticIdentityLimit: 1 as const,
      activeGoogleUserCount: 5,
      contractorGroup: {
        ...CONTRACTORS,
        members: [
          ...CONTRACTORS.members,
          {
            email: "departed@company.test",
            id: "103",
            role: "MEMBER" as const,
            status: "SUSPENDED" as const,
            type: "USER" as const,
          },
        ],
      },
      excludedGoogleUserIds: [],
      expectedContractorGroupId: "contractors",
      managedDomain: "company.test",
      minimumGoogleUsers: 1,
      googleUsers: [
        googleUser("101", "invite@company.test"),
        googleUser("102", "contractor@company.test"),
        googleUser("103", "departed@company.test", { suspended: true }),
        googleUser("104", "reactivate@company.test"),
      ],
      trycompMembers: [
        member("active-contractor", "contractor@company.test"),
        member("departed", "departed@company.test"),
        member("reactivate", "reactivate@company.test", {
          isActive: false,
          deactivated: true,
        }),
      ],
    };
  }

  it("filters before the shared one-identity limit and uses inactive authority for retained contractors", async () => {
    const ordinary = await buildTrycompPlan(input());
    expect(ordinary.actions[0]).toMatchObject({
      email: "contractor@company.test",
      deactivationAuthority: "contractor_group",
    });
    const offboarding = await buildTrycompPlan({
      ...input(),
      offboardingOnly: true,
    });
    expect(offboarding.errors).toEqual([]);
    expect(offboarding.actions).toEqual([
      {
        type: "deactivate",
        email: "departed@company.test",
        memberId: "departed",
        deactivationAuthority: "inactive_google",
      },
    ]);
    expect(offboarding.planHash).not.toBe(ordinary.planHash);
  });

  it("never selects invites, reactivations, or active contractor removals and binds even no-op policy", async () => {
    const source = input();
    source.googleUsers = source.googleUsers.filter((user) => user.id !== "103");
    source.contractorGroup.members = source.contractorGroup.members.filter(
      (user) => user.id !== "103",
    );
    source.trycompMembers = source.trycompMembers.filter(
      (user) => user.id !== "departed",
    );
    const offboarding = await buildTrycompPlan({
      ...source,
      offboardingOnly: true,
    });
    expect(offboarding.actions).toEqual([]);
    const noMembers = {
      ...source,
      trycompMembers: [],
      contractorGroup: { ...CONTRACTORS, members: [] },
      googleUsers: [],
    };
    const general = await buildTrycompPlan(noMembers);
    const restricted = await buildTrycompPlan({
      ...noMembers,
      offboardingOnly: true,
    });
    expect(general.actions).toEqual([]);
    expect(restricted.actions).toEqual([]);
    expect(general.planHash).not.toBe(restricted.planHash);
  });

  it("preserves incomplete authority and protected provider-role blockers", async () => {
    const source = input();
    source.trycompMembers = source.trycompMembers.map((user) =>
      user.id === "departed" ? { ...user, role: "contractor" } : user,
    );
    const protectedPlan = await buildTrycompPlan({
      ...source,
      offboardingOnly: true,
    });
    expect(protectedPlan.actions).toEqual([]);
    const incompletePlan = await buildTrycompPlan({
      ...source,
      offboardingOnly: true,
      activeGoogleUserCount: 0,
    });
    expect(incompletePlan.errors).toContain(
      "Google Directory population 0 is below floor 1",
    );
  });
});
