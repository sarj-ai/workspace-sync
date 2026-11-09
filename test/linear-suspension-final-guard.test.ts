import { describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { LinearAccessProvider } from "../src/access-guard/linear-provider.ts";
import { enforceLinearSuspension } from "../src/access-guard/provider.ts";

const action = {
  accountId: "linear-1",
  email: "departed@example.com",
  googleUserId: "100000000000000000001",
};
const TENANT = {
  expectedOrganizationId: "00000000-0000-4000-8000-000000000001",
  expectedOrganizationUrlKey: "sarj",
};

function fixture() {
  const order: string[] = [];
  const account = {
    id: action.accountId,
    email: action.email,
    active: true,
    admin: false,
    owner: false,
    app: false,
  };
  const fetchImpl = vi.fn<typeof fetch>(async (_input, init) => {
    const { query } = z
      .object({ query: z.string() })
      .parse(JSON.parse(z.string().parse(init?.body)));
    if (query.includes("AccessGuardOrganization")) {
      order.push("tenant");
      return Response.json({
        data: {
          organization: {
            id: TENANT.expectedOrganizationId,
            urlKey: TENANT.expectedOrganizationUrlKey,
          },
        },
      });
    }
    if (query.includes("userSuspend")) {
      order.push("write");
      account.active = false;
      return Response.json({ data: { userSuspend: { success: true } } });
    }
    order.push("read");
    return Response.json({ data: { user: account } });
  });
  return {
    account,
    order,
    provider: new LinearAccessProvider("test-key", TENANT, fetchImpl),
    reserve: vi.fn(async () => undefined),
  };
}

describe("Linear suspension final parent boundary", () => {
  it("requires a parent context before spending a required budget", async () => {
    const { provider, reserve, order } = fixture();
    await expect(
      enforceLinearSuspension(provider, action, "run", {
        required: true,
        reserve,
      }),
    ).resolves.toMatchObject({
      outcome: "failed_closed",
      errorCode: "linear_suspension_parent_context_required",
    });
    expect(reserve).not.toHaveBeenCalled();
    expect(order).not.toContain("write");
  });

  it("rechecks exact authority after tenant lookup and writes once before original-target readback", async () => {
    const { provider, reserve, order } = fixture();
    const assertWriteAuthority = vi.fn(async (actual) => {
      expect(actual).toEqual(action);
      expect(order.at(-1)).toBe("tenant");
      order.push("authority");
    });
    await expect(
      enforceLinearSuspension(
        provider,
        action,
        "run",
        { required: true, reserve },
        {
          assertFinalSourceAuthority: async () => undefined,
          assertWriteAuthority,
          assertFreshPlan: () => {
            order.push("expiry");
          },
        },
      ),
    ).resolves.toMatchObject({ outcome: "suspended_and_verified" });
    expect(reserve).toHaveBeenCalledExactlyOnceWith(action.googleUserId);
    expect(assertWriteAuthority).toHaveBeenCalledOnce();
    expect(order.slice(-5)).toEqual([
      "read",
      "expiry",
      "write",
      "tenant",
      "read",
    ]);
    expect(order.filter((step) => step === "write")).toHaveLength(1);
  });

  it.each(["authority", "admin", "identity", "inactive", "expiry"] as const)(
    "denies %s drift without mutation or false convergence",
    async (drift) => {
      const { provider, reserve, order, account } = fixture();
      const result = await enforceLinearSuspension(
        provider,
        action,
        "run",
        { required: true, reserve },
        {
          assertFinalSourceAuthority: async () => undefined,
          assertWriteAuthority: async () => {
            if (drift === "authority") {
              account.active = false;
              throw new Error("original_parent_denied");
            }
            if (drift === "admin") account.admin = true;
            if (drift === "identity") account.email = "different@example.com";
            if (drift === "inactive") account.active = false;
          },
          assertFreshPlan: () => {
            if (drift === "expiry") throw new Error("expired");
          },
        },
      );
      expect(result).toMatchObject({
        outcome: "failed_closed",
        errorCode: "linear_suspension_final_preflight_denied",
      });
      expect(reserve).toHaveBeenCalledOnce();
      expect(order).not.toContain("write");
    },
  );
});
