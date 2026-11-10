import { describe, expect, it, vi } from "vitest";

import {
  type AuthorityIdentity,
  type AuthorityRevision,
  type DesiredProvisioningPlan,
  DesiredProvisioningPlanSchema,
  type GitHubLogin,
  type GitHubUserId,
  type GoogleUserId,
  type PrimaryEmail,
  provisioningIdempotencyKey,
} from "../src/catalog/identity-authority.ts";
import { ProviderApplyReceiptSchema } from "../src/identity-provisioning/contracts.ts";
import { DesiredIdentityStatePlanner } from "../src/identity-provisioning/desired-identity-state-planner.ts";
import {
  GitHubIdentityMismatchError,
  GitHubManagedDeprovisionConnector,
  GitHubOrganizationPinMismatchError,
  GitHubReadbackMismatchError,
  GitHubUnsafeMutationError,
} from "../src/identity-provisioning/github-managed-deprovision-connector.ts";
import type { IdentityWriteBudget } from "../src/identity-provisioning/identity-budget-contracts.ts";

const GITHUB_LOGIN = "octocat" as GitHubLogin;
const GITHUB_USER_ID = "583231" as GitHubUserId;
const GOOGLE_USER_ID = "123456789" as GoogleUserId;
const ORGANIZATION_ID = "99123";
const ORGANIZATION_LOGIN = "example";

function subject(
  lifecycle: "active" | "archived" | "deleted" | "suspended",
): AuthorityIdentity {
  return {
    authorityRevision: "directory:43" as AuthorityRevision,
    github: {
      githubLogin: GITHUB_LOGIN,
      githubUserId: GITHUB_USER_ID,
      kind: "verified",
      verifiedAt: "2026-08-20T10:00:00.000Z",
    },
    googleUserId: GOOGLE_USER_ID,
    isAdmin: false,
    isDelegatedAdmin: false,
    lifecycle: { kind: lifecycle },
    observedAt: "2026-08-20T11:00:00.000Z",
    primaryEmail: "octocat@company.test" as PrimaryEmail,
  } as AuthorityIdentity;
}

function deprovisionPlan(
  lifecycle: "archived" | "deleted" | "suspended" = "suspended",
): Extract<DesiredProvisioningPlan, { kind: "deprovision" }> {
  const authority = subject(lifecycle);
  const plan = DesiredProvisioningPlanSchema.parse({
    idempotencyKey: provisioningIdempotencyKey({
      action: "deprovision",
      authorityDigest: "a".repeat(64),
      googleUserId: GOOGLE_USER_ID,
      providerId: "github",
    }),
    kind: "deprovision" as const,
    subject: authority,
    target: {
      githubLogin: GITHUB_LOGIN,
      githubUserId: GITHUB_USER_ID,
      providerId: "github" as const,
    },
  });
  if (plan.kind !== "deprovision") throw new Error("expected_deprovision_plan");
  return plan;
}

function provisionPlan(): Extract<
  DesiredProvisioningPlan,
  { kind: "provision" }
> {
  const active = subject("active");
  const plan = DesiredProvisioningPlanSchema.parse({
    idempotencyKey: provisioningIdempotencyKey({
      action: "provision",
      authorityDigest: "b".repeat(64),
      googleUserId: GOOGLE_USER_ID,
      providerId: "github",
    }),
    kind: "provision" as const,
    subject: active,
    target: {
      githubLogin: GITHUB_LOGIN,
      githubUserId: GITHUB_USER_ID,
      providerId: "github" as const,
    },
  });
  if (plan.kind !== "provision") throw new Error("expected_provision_plan");
  return plan;
}

function dispatchReceipt() {
  return vi.fn<() => Promise<void>>().mockResolvedValue(undefined);
}

function json(value: unknown): Response {
  return Response.json(value);
}

function organization(id = Number(ORGANIZATION_ID)): Response {
  return json({ id, login: ORGANIZATION_LOGIN, url: "ignored-extra-field" });
}

function user(id = Number(GITHUB_USER_ID)): Response {
  return json({ id, login: GITHUB_LOGIN, name: "ignored-extra-field" });
}

function membership(role = "member"): Response {
  return json({
    role,
    state: "active",
    user: { id: Number(GITHUB_USER_ID), login: GITHUB_LOGIN },
  });
}

describe("GitHub post-reservation provider authority", () => {
  it.each([
    "reactivated",
    "missing",
    "admin",
    "remapped",
    "different-person",
  ] as const)(
    "blocks a %s Google identity immediately before the provider write",
    async (change) => {
      const writes = vi.fn();
      const fetchImpl: typeof fetch = async (input, init) => {
        if (init?.method === "DELETE") {
          writes();
          return new Response(null, { status: 204 });
        }
        const url = requestUrl(input);
        if (url.endsWith(`/orgs/${ORGANIZATION_LOGIN}`)) return organization();
        if (url.includes("/users/")) return user();
        return membership();
      };
      const reserve = vi.fn();
      const readGoogleAuthority = vi.fn(async () => {
        expect(reserve).toHaveBeenCalledExactlyOnceWith(GOOGLE_USER_ID);
        if (change === "missing") return null;
        const authority = subject(
          change === "reactivated" ? "active" : "suspended",
        );
        if (change === "admin") return { ...authority, isAdmin: true };
        if (change === "different-person") {
          return { ...authority, googleUserId: "987654321" as GoogleUserId };
        }
        if (change === "remapped")
          return { ...authority, github: { kind: "unlinked" as const } };
        return authority;
      });
      await expect(
        connector(
          fetchImpl,
          { required: true, reserve },
          readGoogleAuthority,
        ).apply(deprovisionPlan(), dispatchReceipt()),
      ).rejects.toThrow("github_deprovision_google_authority_changed");
      expect(readGoogleAuthority).toHaveBeenCalledExactlyOnceWith(
        GOOGLE_USER_ID,
      );
      expect(writes).not.toHaveBeenCalled();
    },
  );

  it("does not write when fresh Google authority is unavailable", async () => {
    const responses = [
      organization(),
      user(),
      membership(),
      organization(),
      user(),
      membership(),
    ];
    const fetchImpl = vi.fn<typeof fetch>(
      async () => responses.shift() ?? json({}),
    );
    const failure = new Error("google_unavailable");
    await expect(
      connector(fetchImpl, undefined, async () => {
        throw failure;
      }).apply(deprovisionPlan(), dispatchReceipt()),
    ).rejects.toBe(failure);
    expect(
      fetchImpl.mock.calls.every(([, init]) => init?.method !== "DELETE"),
    ).toBe(true);
  });

  it("rejects an existing organization administrator before reservation", async () => {
    const responses = [organization(), user(), membership("admin")];
    const fetchImpl = vi.fn<typeof fetch>(
      async () => responses.shift() ?? json({}),
    );
    const reserve = vi.fn();
    await expect(
      connector(fetchImpl, { required: true, reserve }).apply(
        deprovisionPlan(),
        dispatchReceipt(),
      ),
    ).rejects.toBeInstanceOf(GitHubUnsafeMutationError);
    expect(reserve).not.toHaveBeenCalled();
    expect(
      fetchImpl.mock.calls.every(([, init]) => init?.method !== "DELETE"),
    ).toBe(true);
  });

  it.each(["admin", "identity-drift"] as const)(
    "rejects %s arising during reservation before DELETE",
    async (change) => {
      let role = "member";
      let userId = Number(GITHUB_USER_ID);
      const writes = vi.fn();
      const fetchImpl: typeof fetch = async (input, init) => {
        if (init?.method === "DELETE") {
          writes();
          return new Response(null, { status: 204 });
        }
        const url = requestUrl(input);
        if (url.endsWith(`/orgs/${ORGANIZATION_LOGIN}`)) return organization();
        if (url.includes("/users/")) return user(userId);
        return membership(role);
      };
      const reserve = vi.fn(async () => {
        if (change === "admin") role = "admin";
        else userId = 999;
      });
      await expect(
        connector(fetchImpl, { required: true, reserve }).apply(
          deprovisionPlan(),
          dispatchReceipt(),
        ),
      ).rejects.toThrow();
      expect(reserve).toHaveBeenCalledExactlyOnceWith(GOOGLE_USER_ID);
      expect(writes).not.toHaveBeenCalled();
    },
  );
});

function connector(
  fetchImpl: typeof fetch,
  identityBudget?: IdentityWriteBudget,
  readGoogleAuthority = async (): Promise<AuthorityIdentity | null> =>
    subject("suspended"),
  residualFetch: typeof fetch = async () => json([]),
): GitHubManagedDeprovisionConnector {
  return new GitHubManagedDeprovisionConnector({
    fetchImpl: (input, init) => {
      const url = requestUrl(input);
      return /\/(outside_collaborators|invitations)\?/u.test(url)
        ? residualFetch(input, init)
        : fetchImpl(input, init);
    },
    ...(!(identityBudget === undefined) && { identityBudget }),
    organizationId: ORGANIZATION_ID,
    organizationLogin: ORGANIZATION_LOGIN,
    planner: new DesiredIdentityStatePlanner(),
    readGoogleAuthority,
    token: "dedicated-write-token",
  });
}

function requestUrl(input: RequestInfo | URL): string {
  return input instanceof Request ? input.url : input.toString();
}

describe("GitHub managed deprovision connector", () => {
  it.each([
    "outside-collaborator",
    "invitation-login",
    "invitation-email",
  ] as const)(
    "does not report absent or mutate when %s access remains",
    async (kind) => {
      const fetchImpl = vi.fn<typeof fetch>(async (input) => {
        const url = requestUrl(input);
        if (url.endsWith("/orgs/example")) return organization();
        if (url.endsWith("/users/octocat")) return user();
        return new Response(null, { status: 404 });
      });
      const residualFetch = vi.fn<typeof fetch>(async (input) => {
        const outside = requestUrl(input).includes("/outside_collaborators?");
        if (outside)
          return json(
            kind === "outside-collaborator"
              ? [{ id: Number(GITHUB_USER_ID), login: GITHUB_LOGIN }]
              : [],
          );
        if (kind === "invitation-login")
          return json([{ id: 99, login: GITHUB_LOGIN, email: null }]);
        if (kind === "invitation-email")
          return json([{ id: 99, login: null, email: "OCTOCAT@company.test" }]);
        return json([]);
      });
      const managed = connector(fetchImpl, undefined, undefined, residualFetch);
      await expect(
        managed.observe(subject("suspended")),
      ).resolves.toMatchObject({
        kind: "unsupported",
      });
      await expect(
        managed.apply(deprovisionPlan(), dispatchReceipt()),
      ).rejects.toBeInstanceOf(GitHubIdentityMismatchError);
      expect(
        fetchImpl.mock.calls.every(([, init]) => init?.method !== "DELETE"),
      ).toBe(true);
      await expect(
        managed.verify(
          deprovisionPlan(),
          ProviderApplyReceiptSchema.parse({
            idempotencyKey: deprovisionPlan().idempotencyKey,
            providerReceiptId: `github:${ORGANIZATION_ID}:${GITHUB_USER_ID}:absent`,
          }),
        ),
      ).resolves.toMatchObject({ kind: "mismatch" });
    },
  );

  it("finds residual access on later pages and fails closed on incomplete inventory", async () => {
    const fetchImpl: typeof fetch = async (input) => {
      const url = requestUrl(input);
      if (url.endsWith("/orgs/example")) return organization();
      if (url.endsWith("/users/octocat")) return user();
      return new Response(null, { status: 404 });
    };
    const residualFetch = vi.fn<typeof fetch>(async (input) => {
      const url = requestUrl(input);
      if (url.includes("/invitations?")) return json([]);
      if (url.endsWith("page=1"))
        return json(
          Array.from({ length: 100 }, (_, index) => ({
            id: index + 1,
            login: `other-${String(index)}`,
          })),
        );
      return json([{ id: Number(GITHUB_USER_ID), login: GITHUB_LOGIN }]);
    });
    await expect(
      connector(fetchImpl, undefined, undefined, residualFetch).observe(
        subject("suspended"),
      ),
    ).resolves.toMatchObject({ kind: "unsupported" });
    expect(
      residualFetch.mock.calls.some(([input]) =>
        requestUrl(input).endsWith("page=2"),
      ),
    ).toBe(true);
    await expect(
      connector(
        fetchImpl,
        undefined,
        undefined,
        async () => new Response(null, { status: 403 }),
      ).observe(subject("suspended")),
    ).rejects.toThrow("github_residual_access_inventory_http_403");
  });

  it("does not verify membership removal when readback retains outside access", async () => {
    let present = true;
    const fetchImpl = vi.fn<typeof fetch>(async (input, init) => {
      const url = requestUrl(input);
      if (url.endsWith("/orgs/example")) return organization();
      if (url.endsWith("/users/octocat")) return user();
      if (init?.method === "DELETE") {
        present = false;
        return new Response(null, { status: 204 });
      }
      return present ? membership() : new Response(null, { status: 404 });
    });
    const residualFetch: typeof fetch = async (input) =>
      json(
        requestUrl(input).includes("/outside_collaborators?")
          ? [{ id: Number(GITHUB_USER_ID), login: GITHUB_LOGIN }]
          : [],
      );
    await expect(
      connector(fetchImpl, undefined, undefined, residualFetch).apply(
        deprovisionPlan(),
        dispatchReceipt(),
      ),
    ).rejects.toBeInstanceOf(GitHubReadbackMismatchError);
    expect(
      fetchImpl.mock.calls.filter(([, init]) => init?.method === "DELETE"),
    ).toHaveLength(1);
  });

  it("fails budget reservation before DELETE and does not classify it as an ambiguous write", async () => {
    const responses = [organization(), user(), membership()];
    const fetchImpl = vi.fn<typeof fetch>(
      async () => responses.shift() ?? json({}),
    );
    const rejected = new Error("identity_budget_exhausted");
    const reserve = vi.fn(async () => {
      throw rejected;
    });
    await expect(
      connector(fetchImpl, { required: true, reserve }).apply(
        deprovisionPlan(),
        dispatchReceipt(),
      ),
    ).rejects.toBe(rejected);
    expect(reserve).toHaveBeenCalledExactlyOnceWith(GOOGLE_USER_ID);
    expect(fetchImpl).toHaveBeenCalledTimes(3);
    expect(
      fetchImpl.mock.calls.every(([, init]) => init?.method !== "DELETE"),
    ).toBe(true);
  });

  it("reserves the immutable Google subject before an ambiguous provider failure", async () => {
    const responses = [
      organization(),
      user(),
      membership(),
      organization(),
      user(),
      membership(),
      new Response(null, { status: 503 }),
      organization(),
      user(),
      membership(),
    ];
    const order: string[] = [];
    const fetchImpl = vi.fn<typeof fetch>(async (_input, init) => {
      if (init?.method === "DELETE") order.push("write");
      return responses.shift() ?? json({});
    });
    const reserve = vi.fn(async () => {
      order.push("budget");
    });
    await expect(
      connector(fetchImpl, { required: true, reserve }).apply(
        deprovisionPlan(),
        dispatchReceipt(),
      ),
    ).rejects.toThrow("github_membership_delete_http_503");
    expect(order).toEqual(["budget", "write"]);
    expect(reserve).toHaveBeenCalledExactlyOnceWith(GOOGLE_USER_ID);
  });

  it("publishes a Google-authoritative deprovision-only protocol", () => {
    const managed = connector(vi.fn<typeof fetch>());

    expect(managed.protocol).toEqual({
      authority: "google-workspace",
      execution: "managed",
      managedActions: ["deprovision"],
      providerId: "github",
      verification: "authoritative-readback",
    });
  });

  it("treats a 404 organization membership as already converged without writing", async () => {
    let callCount = 0;
    const fetchImpl = vi.fn<typeof fetch>(async (_input, init) => {
      callCount += 1;
      const method = init?.method ?? "GET";
      if (method === "DELETE") throw new Error("unexpected mutation");
      const call = callCount % 3;
      if (call === 1) return organization();
      if (call === 2) return user();
      return new Response(null, { status: 404 });
    });
    const managed = connector(fetchImpl);
    const plan = deprovisionPlan();

    await expect(managed.apply(plan, dispatchReceipt())).resolves.toMatchObject(
      {
        idempotencyKey: plan.idempotencyKey,
        providerReceiptId: `github:${ORGANIZATION_ID}:${GITHUB_USER_ID}:absent`,
      },
    );
    expect(
      fetchImpl.mock.calls.every(([, init]) => init?.method !== "DELETE"),
    ).toBe(true);
  });

  it.each([true, false])(
    "recovers an uncertain dispatch through readback without another DELETE (%s)",
    async (absent) => {
      let count = 0;
      const fetchImpl = vi.fn<typeof fetch>(async (_input, init) => {
        if (init?.method === "DELETE")
          throw new Error("recovery must never write");
        count += 1;
        if (count % 3 === 1) return organization();
        if (count % 3 === 2) return user();
        return absent ? new Response(null, { status: 404 }) : membership();
      });
      const recovered = await connector(fetchImpl).recover(deprovisionPlan());
      expect(recovered.kind).toBe(absent ? "verified" : "mismatch");
      expect(
        fetchImpl.mock.calls.every(([, init]) => init?.method !== "DELETE"),
      ).toBe(true);
    },
  );

  it("fails closed when the immutable account ID differs from Google authority", async () => {
    let callCount = 0;
    const fetchImpl = vi.fn<typeof fetch>(async () => {
      callCount += 1;
      return callCount === 1 ? organization() : user(999_999);
    });
    const managed = connector(fetchImpl);

    await expect(
      managed.apply(deprovisionPlan(), dispatchReceipt()),
    ).rejects.toBeInstanceOf(GitHubIdentityMismatchError);
  });

  it("rejects a deprovision target that is not the exact Google authority mapping", async () => {
    const fetchImpl = vi.fn<typeof fetch>();
    const plan = deprovisionPlan();
    const mismatched = DesiredProvisioningPlanSchema.parse({
      ...plan,
      target: { ...plan.target, githubUserId: "999999" },
    });
    if (mismatched.kind === "blocked")
      throw new Error("expected_executable_plan");

    await expect(
      connector(fetchImpl).apply(mismatched, dispatchReceipt()),
    ).rejects.toBeInstanceOf(GitHubIdentityMismatchError);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("pins both the organization login and immutable numeric ID", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () => organization(77));

    await expect(
      connector(fetchImpl).observe(subject("suspended")),
    ).rejects.toBeInstanceOf(GitHubOrganizationPinMismatchError);
  });

  it("is duplicate-safe: a repeated apply observes absence and does not issue another delete", async () => {
    let present = true;
    let deleteCount = 0;
    const fetchImpl = vi.fn<typeof fetch>(async (input, init) => {
      const url = requestUrl(input);
      if (url.endsWith("/orgs/example")) return organization();
      if (url.endsWith("/users/octocat")) return user();
      if (init?.method === "DELETE") {
        deleteCount += 1;
        present = false;
        return new Response(null, { status: 204 });
      }
      return present ? membership() : new Response(null, { status: 404 });
    });
    const managed = connector(fetchImpl);
    const plan = deprovisionPlan("archived");

    const first = await managed.apply(plan, dispatchReceipt());
    const second = await managed.apply(plan, dispatchReceipt());

    expect(second).toEqual(first);
    expect(deleteCount).toBe(1);
  });

  it("rereads an ambiguous failed write and accepts only observed convergence", async () => {
    let present = true;
    const fetchImpl = vi.fn<typeof fetch>(async (input, init) => {
      const url = requestUrl(input);
      if (url.endsWith("/orgs/example")) return organization();
      if (url.endsWith("/users/octocat")) return user();
      if (init?.method === "DELETE") {
        present = false;
        throw new Error("connection reset after GitHub accepted the write");
      }
      return present ? membership() : new Response(null, { status: 404 });
    });

    await expect(
      connector(fetchImpl).apply(deprovisionPlan("deleted"), dispatchReceipt()),
    ).resolves.toMatchObject({
      providerReceiptId: `github:${ORGANIZATION_ID}:${GITHUB_USER_ID}:absent`,
    });
  });

  it("rejects a successful write whose readback still shows membership", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async (input, init) => {
      const url = requestUrl(input);
      if (url.endsWith("/orgs/example")) return organization();
      if (url.endsWith("/users/octocat")) return user();
      return init?.method === "DELETE"
        ? new Response(null, { status: 204 })
        : membership();
    });

    await expect(
      connector(fetchImpl).apply(deprovisionPlan(), dispatchReceipt()),
    ).rejects.toBeInstanceOf(GitHubReadbackMismatchError);
  });

  it("verifies with a fresh readback and rejects receipt substitution", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async (input) => {
      const url = requestUrl(input);
      if (url.endsWith("/orgs/example")) return organization();
      if (url.endsWith("/users/octocat")) return user();
      return new Response(null, { status: 404 });
    });
    const managed = connector(fetchImpl);
    const plan = deprovisionPlan();
    const receipt = await managed.apply(plan, dispatchReceipt());

    await expect(managed.verify(plan, receipt)).resolves.toMatchObject({
      kind: "verified",
    });
    await expect(
      managed.verify(
        plan,
        ProviderApplyReceiptSchema.parse({
          ...receipt,
          providerReceiptId: "github:other:absent",
        }),
      ),
    ).resolves.toEqual({
      errorCode: "github_receipt_mismatch",
      kind: "mismatch",
    });
  });

  it("observes active organization administrators as unsupported without failing the audit", async () => {
    const responses = [organization(), user(), membership("admin")];
    const fetchImpl = vi.fn<typeof fetch>(
      async () => responses.shift() ?? new Response("", { status: 500 }),
    );
    const managed = connector(fetchImpl);
    const active = subject("active");
    const observation = await managed.observe(active);
    expect(observation).toMatchObject({
      kind: "unsupported",
      providerId: "github",
    });
    await expect(managed.plan(active, observation)).resolves.toMatchObject({
      kind: "blocked",
    });
    expect(fetchImpl).toHaveBeenCalledTimes(3);
    expect(
      fetchImpl.mock.calls.every(([, init]) => init?.method !== "DELETE"),
    ).toBe(true);
    await expect(
      managed.apply(provisionPlan(), dispatchReceipt()),
    ).rejects.toBeInstanceOf(GitHubUnsafeMutationError);
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });

  it.each(["archived", "deleted", "suspended"] as const)(
    "still rejects inactive organization administrators (%s) before any write",
    async (lifecycle) => {
      const responses = [organization(), user(), membership("admin")];
      const fetchImpl = vi.fn<typeof fetch>(
        async () => responses.shift() ?? new Response("", { status: 500 }),
      );
      await expect(
        connector(fetchImpl).observe(subject(lifecycle)),
      ).rejects.toBeInstanceOf(GitHubUnsafeMutationError);
      expect(
        fetchImpl.mock.calls.every(([, init]) => init?.method !== "DELETE"),
      ).toBe(true);
    },
  );

  it("keeps active administrator identity mismatches ambiguous", async () => {
    const responses = [
      organization(),
      user(),
      json({
        role: "admin",
        state: "active",
        user: { id: 999999, login: "another" },
      }),
    ];
    const fetchImpl = vi.fn<typeof fetch>(
      async () => responses.shift() ?? new Response("", { status: 500 }),
    );
    await expect(
      connector(fetchImpl).observe(subject("active")),
    ).resolves.toMatchObject({
      kind: "ambiguous",
    });
    expect(
      fetchImpl.mock.calls.every(([, init]) => init?.method !== "DELETE"),
    ).toBe(true);
  });

  it("never plans or applies a destructive mutation for an active subject", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async (input) => {
      const url = requestUrl(input);
      if (url.endsWith("/orgs/example")) return organization();
      if (url.endsWith("/users/octocat")) return user();
      return membership();
    });
    const managed = connector(fetchImpl);
    const active = subject("active");
    const observation = await managed.observe(active);

    await expect(managed.plan(active, observation)).resolves.toMatchObject({
      kind: "blocked",
    });
    await expect(
      managed.apply(provisionPlan(), dispatchReceipt()),
    ).rejects.toBeInstanceOf(GitHubUnsafeMutationError);
    expect(
      fetchImpl.mock.calls.every(([, init]) => init?.method !== "DELETE"),
    ).toBe(true);
  });
});
