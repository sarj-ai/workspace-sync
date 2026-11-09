import { describe, expect, it, vi } from "vitest";

import {
  AuthorityIdentitySchema,
  ProviderAccountSchema,
} from "../src/catalog/identity-authority.ts";
import type {
  IdentityProviderConnector,
  IdentityProviderPlanningContext,
  ProviderLifecycleAction,
  ProviderLifecycleProtocol,
} from "../src/identity-provisioning/contracts.ts";
import {
  IdentityProvisioningExecutionPolicySchema,
  identityProvisioningApproval,
  identityProvisioningSha256,
  ProviderLifecycleProtocolSchema,
  ProviderObservationSchema,
} from "../src/identity-provisioning/contracts.ts";
import { DesiredIdentityStatePlanner } from "../src/identity-provisioning/desired-identity-state-planner.ts";
import {
  IdentityProvisioningOrchestrator,
  IdentityProvisioningSafetyPolicyError,
} from "../src/identity-provisioning/orchestrator.ts";
import type { IdentityReconciliationExecutionStore } from "../src/identity-provisioning/persistence.ts";

const GOOGLE_USER_ID = "123456789012345678901";
const COMPLETE_CONTEXT: IdentityProviderPlanningContext = {
  employeeEntitlementAuthority: {
    complete: true,
    excludedEmails: [],
    excludedGoogleUserIds: [],
    fingerprint: "a".repeat(64),
    groupEmail: "team-contractors@company.test",
    groupId: "contractor-group-test",
  },
};

function plannerWithCompleteAuthority() {
  const planner = new DesiredIdentityStatePlanner();
  return {
    plan: (
      authority: Parameters<DesiredIdentityStatePlanner["plan"]>[0],
      observation: Parameters<DesiredIdentityStatePlanner["plan"]>[1],
      context: IdentityProviderPlanningContext = COMPLETE_CONTEXT,
    ) => planner.plan(authority, observation, context),
  };
}
const HASH = identityProvisioningSha256("a".repeat(64));
const GITHUB_AUDIT_PROTOCOL = {
  authority: "google-workspace",
  execution: "audit-only",
  managedActions: [],
  providerId: "github",
  verification: "authoritative-readback",
} as const;
const GITHUB_DEPROVISION_PROTOCOL = {
  authority: "google-workspace",
  execution: "managed",
  managedActions: ["deprovision"],
  providerId: "github",
  verification: "authoritative-readback",
} as const;
const SLACK_AUDIT_PROTOCOL = {
  authority: "google-workspace",
  execution: "audit-only",
  managedActions: [],
  providerId: "slack",
  verification: "authoritative-readback",
} as const;

function subject(
  lifecycle: "active" | "archived" | "deleted" | "suspended",
  github: "unlinked" | "verified" = "verified",
  primaryEmail = "person@company.test",
) {
  return AuthorityIdentitySchema.parse({
    authorityRevision: "google:42",
    github:
      github === "verified"
        ? {
            githubLogin: "octocat",
            githubUserId: "583231",
            kind: "verified",
            verifiedAt: "2026-08-20T12:00:00.000Z",
          }
        : { kind: "unlinked" },
    googleUserId: GOOGLE_USER_ID,
    isAdmin: false,
    isDelegatedAdmin: false,
    lifecycle: { kind: lifecycle },
    observedAt: "2026-08-20T12:00:00.000Z",
    primaryEmail,
  });
}

const GITHUB_ACCOUNT = ProviderAccountSchema.parse({
  githubLogin: "octocat",
  githubUserId: "583231",
  providerId: "github",
});

describe("identity provider boundary contracts", () => {
  it("rejects observations whose account belongs to another provider", () => {
    expect(
      ProviderObservationSchema.safeParse({
        account: { accountId: "U012345", providerId: "slack" },
        kind: "present",
        providerId: "github",
      }).success,
    ).toBe(false);
  });

  it("rejects duplicate apply capabilities and unexplained kill switches", () => {
    expect(
      IdentityProvisioningExecutionPolicySchema.safeParse({
        approval: {
          approvalId: "33333333-3333-4333-8333-333333333333",
          approvedAtMs: 1_000,
          approvedBy: "permissions-admin@company.test",
          expiresAtMs: 2_000,
          planHash: HASH,
        },
        enabledProviders: ["github", "github"],
        kind: "approved-apply",
      }).success,
    ).toBe(false);
    expect(
      IdentityProvisioningExecutionPolicySchema.safeParse({
        kind: "kill-switch-engaged",
        reason: "  ",
      }).success,
    ).toBe(false);
    expect(
      IdentityProvisioningExecutionPolicySchema.safeParse({
        enabledProviders: ["github"],
        kind: "bounded-automatic-deprovision",
        maxSubjects: 2,
      }).success,
    ).toBe(false);
  });

  it("requires a self-consistent Google-authoritative provider protocol", () => {
    expect(
      ProviderLifecycleProtocolSchema.safeParse({
        authority: "google-workspace",
        execution: "audit-only",
        managedActions: ["deprovision"],
        providerId: "github",
        verification: "authoritative-readback",
      }).success,
    ).toBe(false);
    expect(
      ProviderLifecycleProtocolSchema.safeParse({
        ...GITHUB_DEPROVISION_PROTOCOL,
        managedActions: ["deprovision", "deprovision"],
      }).success,
    ).toBe(false);
  });
});

describe("desired identity state planner", () => {
  const planner = plannerWithCompleteAuthority();

  it.each(["archived", "deleted", "suspended"] as const)(
    "accepts verified absence for %s identities without authorizing protected writes",
    async (lifecycle) => {
      const inactive = {
        ...subject(lifecycle),
        isAdmin: undefined,
        isDelegatedAdmin: undefined,
      };
      await expect(
        planner.plan(inactive, { kind: "absent", providerId: "github" }),
      ).resolves.toMatchObject({ kind: "satisfied" });
      await expect(
        planner.plan(inactive, {
          kind: "present",
          providerId: "github",
          account: GITHUB_ACCOUNT,
        }),
      ).resolves.toMatchObject({
        kind: "blocked",
        blockers: [{ code: "safety-policy" }],
      });
      await expect(
        planner.plan(inactive, {
          kind: "unsupported",
          providerId: "github",
          detail: "The immutable GitHub identity is unknown",
        }),
      ).resolves.toMatchObject({ kind: "blocked" });
    },
  );

  it("still blocks a protected active identity when provisioning would be required", async () => {
    await expect(
      planner.plan(
        { ...subject("active"), isAdmin: true },
        { kind: "absent", providerId: "github" },
      ),
    ).resolves.toMatchObject({
      kind: "blocked",
      blockers: [{ code: "safety-policy" }],
    });
  });

  it("blocks employee grants with missing or incomplete contractor authority", async () => {
    const rawPlanner = new DesiredIdentityStatePlanner();
    const observation = { kind: "absent", providerId: "github" } as const;
    await expect(
      rawPlanner.plan(subject("active"), observation),
    ).resolves.toMatchObject({
      kind: "blocked",
      blockers: [{ code: "safety-policy" }],
    });
    await expect(
      rawPlanner.plan(subject("active"), observation, {
        employeeEntitlementAuthority: {
          ...COMPLETE_CONTEXT.employeeEntitlementAuthority,
          complete: false,
        },
      }),
    ).resolves.toMatchObject({
      kind: "blocked",
      blockers: [{ code: "safety-policy" }],
    });
  });

  it("denies contractor grants by alias while preserving existing access for review", async () => {
    const contractor = AuthorityIdentitySchema.parse({
      ...subject("active"),
      aliases: ["excluded-four@company.test"],
    });
    await expect(
      planner.plan(contractor, { kind: "absent", providerId: "github" }),
    ).resolves.toMatchObject({ kind: "satisfied" });
    await expect(
      planner.plan(contractor, {
        account: GITHUB_ACCOUNT,
        kind: "present",
        providerId: "github",
      }),
    ).resolves.toMatchObject({
      kind: "blocked",
      blockers: [{ code: "safety-policy" }],
    });
  });

  it("provisions a verified active identity and blocks an unlinked identity", async () => {
    const observation = { kind: "absent", providerId: "github" } as const;
    const provision = await planner.plan(subject("active"), observation);
    const blocked = await planner.plan(
      subject("active", "unlinked"),
      observation,
    );
    expect(provision.kind).toBe("provision");
    expect(blocked).toMatchObject({
      blockers: [{ code: "identity-unlinked" }],
      kind: "blocked",
    });
  });

  it("provisions a verified active identity when the provider account is absent", async () => {
    const plan = await planner.plan(subject("active"), {
      kind: "absent",
      providerId: "github",
    });
    expect(plan).toMatchObject({ kind: "provision", target: GITHUB_ACCOUNT });
  });

  it.each([
    "excluded-one@company.test",
    "excluded-two@company.test",
    "excluded-three@company.test",
    "service@company.test",
    "excluded-four@company.test",
  ])(
    "never auto-provisions excluded identity %s and preserves existing provider access for review",
    async (primaryEmail) => {
      const excludedIdentity = subject("active", "verified", primaryEmail);
      await expect(
        planner.plan(excludedIdentity, {
          kind: "absent",
          providerId: "github",
        }),
      ).resolves.toMatchObject({ kind: "satisfied" });
      await expect(
        planner.plan(excludedIdentity, {
          account: GITHUB_ACCOUNT,
          kind: "present",
          providerId: "github",
        }),
      ).resolves.toMatchObject({
        blockers: [{ code: "safety-policy" }],
        kind: "blocked",
      });
    },
  );

  it("uses the fresh contractor authority by immutable Google ID", async () => {
    const plan = await planner.plan(
      subject("active", "verified", "renamed-contractor@company.test"),
      { kind: "absent", providerId: "github" },
      {
        employeeEntitlementAuthority: {
          complete: true,
          excludedEmails: [],
          excludedGoogleUserIds: [GOOGLE_USER_ID],
          fingerprint: "f".repeat(64),
          groupEmail: "team-contractors@company.test",
          groupId: "contractor-group-test",
        },
      },
    );
    expect(plan).toMatchObject({ kind: "satisfied" });
  });

  it("blocks an active identity when the observed provider identity conflicts with authority", async () => {
    const conflictingAccount = ProviderAccountSchema.parse({
      githubLogin: "different-person",
      githubUserId: "999999",
      providerId: "github",
    });
    const plan = await planner.plan(subject("active"), {
      account: conflictingAccount,
      kind: "present",
      providerId: "github",
    });
    expect(plan).toMatchObject({
      blockers: [{ code: "provider-ambiguous" }],
      kind: "blocked",
    });
  });

  it.each(["suspended", "archived", "deleted"] as const)(
    "deprovisions a %s authority identity",
    async (lifecycle) => {
      const plan = await planner.plan(subject(lifecycle), {
        account: GITHUB_ACCOUNT,
        kind: "present",
        providerId: "github",
      });
      expect(plan.kind).toBe("deprovision");
    },
  );

  it("does not create an operation when the verified provider identity is already present", async () => {
    await expect(
      planner.plan(subject("active"), {
        account: GITHUB_ACCOUNT,
        kind: "present",
        providerId: "github",
      }),
    ).resolves.toMatchObject({ kind: "satisfied", providerId: "github" });
  });

  it("derives the same retry identity from the same desired state", async () => {
    const observation = { kind: "absent", providerId: "github" } as const;
    const first = await planner.plan(subject("active"), observation);
    const retry = await planner.plan(subject("active"), observation);
    expect(first).toMatchObject({
      idempotencyKey: expect.any(String),
      kind: "provision",
    });
    expect(retry).toMatchObject({
      idempotencyKey: first.kind === "provision" ? first.idempotencyKey : "",
    });
  });

  it.each(["archived", "deleted", "suspended"] as const)(
    "treats an absent provider account as satisfied for a %s identity",
    async (lifecycle) => {
      const plan = await planner.plan(subject(lifecycle), {
        kind: "absent",
        providerId: "github",
      });
      expect(plan).toMatchObject({ kind: "satisfied", providerId: "github" });
    },
  );

  it("blocks ambiguous and unsupported observations without producing an operation key", async () => {
    const ambiguous = await planner.plan(subject("active"), {
      candidates: [GITHUB_ACCOUNT],
      kind: "ambiguous",
      providerId: "github",
    });
    const unsupported = await planner.plan(subject("active"), {
      detail: "connector disabled",
      kind: "unsupported",
      providerId: "github",
    });
    expect(ambiguous).toMatchObject({
      blockers: [{ code: "provider-ambiguous" }],
      kind: "blocked",
    });
    expect(unsupported).toMatchObject({
      blockers: [{ code: "provider-unsupported" }],
      kind: "blocked",
    });
    expect(ambiguous).not.toHaveProperty("idempotencyKey");
    expect(unsupported).not.toHaveProperty("idempotencyKey");
  });
});

describe("identity provisioning orchestrator", () => {
  it("rejects connector protocols whose provider or execution identity does not match", () => {
    const providerMismatch: IdentityProviderConnector = {
      execution: "audit-only",
      observe: vi.fn(),
      plan: vi.fn(),
      protocol: { ...GITHUB_AUDIT_PROTOCOL, providerId: "slack" },
      providerId: "github",
      verify: vi.fn(),
    };
    const executionMismatch: IdentityProviderConnector = {
      execution: "audit-only",
      observe: vi.fn(),
      plan: vi.fn(),
      protocol: GITHUB_DEPROVISION_PROTOCOL,
      providerId: "github",
      verify: vi.fn(),
    };
    const repository = {
      claimAutomaticDeprovisionOperation: vi
        .fn()
        .mockResolvedValue({ kind: "unavailable" }),
      claimOperation: vi.fn(),
      completeOperation: vi.fn(),
      createPlan: vi.fn(),
      retryOperation: vi.fn(),
    } satisfies IdentityReconciliationExecutionStore;
    const dependencies = {
      claimDurationMs: 30_000,
      claimOwnerId: () => "22222222-2222-4222-8222-222222222222",
      clock: () => 1_000,
      repository,
      runId: () => "11111111-1111-4111-8111-111111111111",
    };

    expect(
      () =>
        new IdentityProvisioningOrchestrator({
          ...dependencies,
          connectors: [providerMismatch],
        }),
    ).toThrow("identity_provider_protocol_provider_mismatch");
    expect(
      () =>
        new IdentityProvisioningOrchestrator({
          ...dependencies,
          connectors: [executionMismatch],
        }),
    ).toThrow("identity_provider_protocol_execution_mismatch");
  });

  it("fails closed when automatic deprovision receives more than one subject", async () => {
    const observe = vi.fn().mockResolvedValue({
      account: GITHUB_ACCOUNT,
      kind: "present",
      providerId: "github",
    });
    const github: IdentityProviderConnector = {
      apply: vi.fn(),
      execution: "managed",
      observe,
      plan: (authority, observation) =>
        new DesiredIdentityStatePlanner().plan(
          authority,
          observation,
          COMPLETE_CONTEXT,
        ),
      protocol: GITHUB_DEPROVISION_PROTOCOL,
      providerId: "github",
      verify: vi.fn(),
    };
    const repository = {
      claimAutomaticDeprovisionOperation: vi
        .fn()
        .mockResolvedValue({ kind: "unavailable" }),
      claimOperation: vi.fn(),
      completeOperation: vi.fn(),
      createPlan: vi.fn(),
      retryOperation: vi.fn(),
    } satisfies IdentityReconciliationExecutionStore;
    const orchestrator = new IdentityProvisioningOrchestrator({
      claimDurationMs: 30_000,
      claimOwnerId: () => "22222222-2222-4222-8222-222222222222",
      clock: () => 1_000,
      connectors: [github],
      repository,
      runId: () => "11111111-1111-4111-8111-111111111111",
    });

    await expect(
      orchestrator.reconcile([subject("suspended"), subject("deleted")], {
        enabledProviders: ["github"],
        kind: "bounded-automatic-deprovision",
        maxSubjects: 1,
      }),
    ).rejects.toBeInstanceOf(IdentityProvisioningSafetyPolicyError);
    expect(observe).not.toHaveBeenCalled();
  });

  it("allows only an inactive GitHub deprovision through the bounded automatic policy", async () => {
    const apply = vi.fn();
    const github: IdentityProviderConnector = {
      apply,
      execution: "managed",
      observe: vi.fn().mockResolvedValue({
        account: GITHUB_ACCOUNT,
        kind: "present",
        providerId: "github",
      }),
      plan: (authority, observation) =>
        new DesiredIdentityStatePlanner().plan(
          authority,
          observation,
          COMPLETE_CONTEXT,
        ),
      protocol: GITHUB_DEPROVISION_PROTOCOL,
      providerId: "github",
      verify: vi.fn(),
    };
    const claimOperation = vi.fn().mockResolvedValue({ kind: "unavailable" });
    const repository = {
      claimAutomaticDeprovisionOperation: vi
        .fn()
        .mockResolvedValue({ kind: "unavailable" }),
      claimOperation,
      completeOperation: vi.fn(),
      createPlan: vi
        .fn()
        .mockResolvedValue("11111111-1111-4111-8111-111111111111"),
      retryOperation: vi.fn(),
    } satisfies IdentityReconciliationExecutionStore;
    const orchestrator = new IdentityProvisioningOrchestrator({
      claimDurationMs: 30_000,
      claimOwnerId: () => "22222222-2222-4222-8222-222222222222",
      clock: () => 1_000,
      connectors: [github],
      repository,
      runId: () => "11111111-1111-4111-8111-111111111111",
    });
    const policy = {
      enabledProviders: ["github"] as const,
      kind: "bounded-automatic-deprovision" as const,
      maxSubjects: 1 as const,
    };

    const active = await orchestrator.reconcile([subject("active")], policy);
    const suspended = await orchestrator.reconcile(
      [subject("suspended")],
      policy,
    );

    expect(active.executions).toEqual([]);
    expect(suspended.executions).toEqual([
      expect.objectContaining({
        kind: "claim-unavailable",
        providerId: "github",
      }),
    ]);
    expect(claimOperation).not.toHaveBeenCalled();
    expect(
      repository.claimAutomaticDeprovisionOperation,
    ).toHaveBeenCalledOnce();
    expect(apply).not.toHaveBeenCalled();
  });

  it("rejects an approved provision before claim when the connector manages only deprovision", async () => {
    const planner = plannerWithCompleteAuthority();
    const apply = vi.fn();
    const managedActions: ProviderLifecycleAction[] = ["deprovision"];
    const mutableProtocol = {
      ...GITHUB_DEPROVISION_PROTOCOL,
      managedActions,
    } satisfies ProviderLifecycleProtocol;
    const github: IdentityProviderConnector = {
      apply,
      execution: "managed",
      observe: vi
        .fn()
        .mockResolvedValue({ kind: "absent", providerId: "github" }),
      plan: (authority, observation) => planner.plan(authority, observation),
      protocol: mutableProtocol,
      providerId: "github",
      verify: vi.fn(),
    };
    const claimOperation = vi.fn();
    const repository = {
      claimAutomaticDeprovisionOperation: vi
        .fn()
        .mockResolvedValue({ kind: "unavailable" }),
      claimOperation,
      completeOperation: vi.fn(),
      createPlan: vi
        .fn()
        .mockResolvedValue("11111111-1111-4111-8111-111111111111"),
      retryOperation: vi.fn(),
    } satisfies IdentityReconciliationExecutionStore;
    const orchestrator = new IdentityProvisioningOrchestrator({
      claimDurationMs: 30_000,
      claimOwnerId: () => "22222222-2222-4222-8222-222222222222",
      clock: () => 1_000,
      connectors: [github],
      repository,
      runId: () => "11111111-1111-4111-8111-111111111111",
    });
    managedActions.push("provision");
    const audit = await orchestrator.reconcile([subject("active")], {
      kind: "audit-only",
    });
    if (audit.planHash === null) throw new Error("expected_identity_plan");

    const result = await orchestrator.reconcile([subject("active")], {
      approval: identityProvisioningApproval({
        approvalId: "33333333-3333-4333-8333-333333333333",
        approvedAtMs: 900,
        approvedBy: "permissions-admin@company.test",
        expiresAtMs: 2_000,
        planHash: audit.planHash,
      }),
      enabledProviders: ["github"],
      kind: "approved-apply",
    });

    expect(result.executions).toEqual([
      expect.objectContaining({
        kind: "provider-disabled",
        providerId: "github",
        reasonCode: "connector_action_not_managed",
      }),
    ]);
    expect(claimOperation).not.toHaveBeenCalled();
    expect(apply).not.toHaveBeenCalled();
  });

  it("bounds provider observations while preserving subject order", async () => {
    const planner = plannerWithCompleteAuthority();
    const releases: (() => void)[] = [];
    let active = 0;
    let maxActive = 0;
    const github: IdentityProviderConnector = {
      execution: "audit-only",
      observe: vi.fn(async () => {
        active += 1;
        maxActive = Math.max(maxActive, active);
        await new Promise<void>((resolve) => {
          releases.push(() => {
            active -= 1;
            resolve();
          });
        });
        return { kind: "absent", providerId: "github" } as const;
      }),
      plan: (authority, observation) => planner.plan(authority, observation),
      protocol: GITHUB_AUDIT_PROTOCOL,
      providerId: "github",
      verify: vi.fn().mockResolvedValue({ kind: "verified", resultHash: HASH }),
    };
    const repository = {
      claimAutomaticDeprovisionOperation: vi
        .fn()
        .mockResolvedValue({ kind: "unavailable" }),
      claimOperation: vi.fn(),
      completeOperation: vi.fn(),
      createPlan: vi
        .fn()
        .mockResolvedValue("33333333-3333-4333-8333-333333333333"),
      retryOperation: vi.fn(),
    } satisfies IdentityReconciliationExecutionStore;
    const orchestrator = new IdentityProvisioningOrchestrator({
      claimDurationMs: 30_000,
      claimOwnerId: () => "22222222-2222-4222-8222-222222222222",
      clock: () => 1_000,
      connectors: [github],
      maxConcurrency: 2,
      repository,
      runId: () => "11111111-1111-4111-8111-111111111111",
    });

    const reconciliation = orchestrator.reconcile(
      [
        subject("active"),
        subject("active"),
        subject("active"),
        subject("active"),
      ],
      { kind: "audit-only" },
    );
    await vi.waitFor(() => expect(releases).toHaveLength(2));
    const firstBatch = [...releases];
    releases.length = 0;
    for (const release of firstBatch) release();
    await vi.waitFor(() => expect(releases).toHaveLength(2));
    const secondBatch = [...releases];
    releases.length = 0;
    for (const release of secondBatch) release();

    const result = await reconciliation;
    expect(maxActive).toBe(2);
    expect(result.runId).toBe("33333333-3333-4333-8333-333333333333");
    expect(result.planning.map(({ googleUserId }) => googleUserId)).toEqual([
      GOOGLE_USER_ID,
      GOOGLE_USER_ID,
      GOOGLE_USER_ID,
      GOOGLE_USER_ID,
    ]);
  });

  it("isolates one provider planning failure from another provider", async () => {
    const planner = plannerWithCompleteAuthority();
    const github: IdentityProviderConnector = {
      execution: "audit-only",
      observe: vi.fn().mockResolvedValue({
        kind: "absent",
        providerId: "github",
      }),
      plan: (authority, observation) => planner.plan(authority, observation),
      protocol: GITHUB_AUDIT_PROTOCOL,
      providerId: "github",
      verify: vi.fn().mockResolvedValue({ kind: "verified", resultHash: HASH }),
    };
    const slack: IdentityProviderConnector = {
      execution: "audit-only",
      observe: vi.fn().mockRejectedValue(new Error("slack_unavailable")),
      plan: (authority, observation) => planner.plan(authority, observation),
      protocol: SLACK_AUDIT_PROTOCOL,
      providerId: "slack",
      verify: vi.fn().mockResolvedValue({ kind: "verified", resultHash: HASH }),
    };
    const repository = {
      claimAutomaticDeprovisionOperation: vi
        .fn()
        .mockResolvedValue({ kind: "unavailable" }),
      claimOperation: vi.fn(),
      completeOperation: vi.fn(),
      createPlan: vi
        .fn()
        .mockResolvedValue("11111111-1111-4111-8111-111111111111"),
      retryOperation: vi.fn(),
    } satisfies IdentityReconciliationExecutionStore;
    const orchestrator = new IdentityProvisioningOrchestrator({
      claimDurationMs: 30_000,
      claimOwnerId: () => "22222222-2222-4222-8222-222222222222",
      clock: () => 1_000,
      connectors: [github, slack],
      repository,
      runId: () => "11111111-1111-4111-8111-111111111111",
    });

    const result = await orchestrator.reconcile([subject("active")], {
      kind: "audit-only",
    });

    expect(result.planning).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "planned", providerId: "github" }),
        expect.objectContaining({ kind: "failed", providerId: "slack" }),
      ]),
    );
    expect(result.executions).toEqual([
      expect.objectContaining({ kind: "audit-only", providerId: "github" }),
    ]);
  });

  it("cannot persist its caller-supplied approval and requires an independently approved plan", async () => {
    const planner = plannerWithCompleteAuthority();
    const apply = vi.fn();
    const github: IdentityProviderConnector = {
      apply,
      execution: "managed",
      observe: vi.fn().mockResolvedValue({
        account: GITHUB_ACCOUNT,
        kind: "present",
        providerId: "github",
      }),
      plan: (authority, observation) => planner.plan(authority, observation),
      protocol: GITHUB_DEPROVISION_PROTOCOL,
      providerId: "github",
      verify: vi.fn(),
    };
    const claimOperation = vi.fn().mockResolvedValue({ kind: "unavailable" });
    const repository = {
      claimAutomaticDeprovisionOperation: vi
        .fn()
        .mockResolvedValue({ kind: "unavailable" }),
      claimOperation,
      completeOperation: vi.fn(),
      createPlan: vi
        .fn()
        .mockResolvedValue("11111111-1111-4111-8111-111111111111"),
      retryOperation: vi.fn(),
    } satisfies IdentityReconciliationExecutionStore;
    const orchestrator = new IdentityProvisioningOrchestrator({
      claimDurationMs: 30_000,
      claimOwnerId: () => "22222222-2222-4222-8222-222222222222",
      clock: () => 1_000,
      connectors: [github],
      repository,
      runId: () => "11111111-1111-4111-8111-111111111111",
    });
    const audit = await orchestrator.reconcile([subject("suspended")], {
      kind: "audit-only",
    });
    if (audit.planHash === null) throw new Error("expected_identity_plan");

    const expired = await orchestrator.reconcile([subject("suspended")], {
      approval: identityProvisioningApproval({
        approvalId: "33333333-3333-4333-8333-333333333333",
        approvedAtMs: 800,
        approvedBy: "permissions-admin@company.test",
        expiresAtMs: 1_000,
        planHash: audit.planHash,
      }),
      enabledProviders: ["github"],
      kind: "approved-apply",
    });

    expect(expired.executions).toEqual([
      expect.objectContaining({
        kind: "provider-disabled",
        providerId: "github",
      }),
    ]);
    expect(claimOperation).not.toHaveBeenCalled();

    const result = await orchestrator.reconcile([subject("suspended")], {
      approval: identityProvisioningApproval({
        approvalId: "33333333-3333-4333-8333-333333333333",
        approvedAtMs: 900,
        approvedBy: "permissions-admin@company.test",
        expiresAtMs: 2_000,
        planHash: audit.planHash,
      }),
      enabledProviders: ["github"],
      kind: "approved-apply",
    });

    expect(claimOperation).toHaveBeenCalledOnce();
    expect(apply).not.toHaveBeenCalled();
    expect(result.executions).toEqual([
      expect.objectContaining({
        kind: "claim-unavailable",
        providerId: "github",
      }),
    ]);
  });

  it("rejects an approval whose expiry does not follow its approval time", () => {
    expect(() =>
      identityProvisioningApproval({
        approvalId: "33333333-3333-4333-8333-333333333333",
        approvedAtMs: 1_000,
        approvedBy: "permissions-admin@company.test",
        expiresAtMs: 1_000,
        planHash: HASH,
      }),
    ).toThrow();
  });
});
