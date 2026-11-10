import { describe, expect, it, vi } from "vitest";

import {
  activeResourceLease,
  resourceLeaseKey,
  type ResourceLeaseRepository,
  withResourceLease,
} from "../src/identity-sync/resource-lease.ts";
import { providerWrite } from "../src/runtime/provider-write.ts";

const LEASE = activeResourceLease({
  expiresAtMs: 1000,
  generation: 1,
  ownerId: "11111111-1111-4111-8111-111111111111",
  resourceKey: "provider/test",
});

function repository() {
  return {
    acquire: vi
      .fn<ResourceLeaseRepository["acquire"]>()
      .mockResolvedValue({ kind: "acquired", lease: LEASE }),
    assertActive: vi.fn<ResourceLeaseRepository["assertActive"]>(),
    release: vi
      .fn<ResourceLeaseRepository["release"]>()
      .mockResolvedValue(undefined),
  };
}

describe("provider effect boundaries", () => {
  it("records uncertainty even when the provider throws a non-Error", async () => {
    const effect = vi.fn<() => Promise<void>>().mockRejectedValue(undefined);
    const outcome = await providerWrite(effect);
    expect(outcome.kind).toBe("uncertain");
    expect(effect).toHaveBeenCalledOnce();
  });

  it("distinguishes acknowledgement from verified provider state", async () => {
    await expect(
      providerWrite(vi.fn<() => Promise<void>>().mockResolvedValue(undefined)),
    ).resolves.toEqual({
      kind: "acknowledged",
    });
  });

  it("releases a lease after a synchronous rejection before a Promise is returned", async () => {
    const store = repository();
    const original = new Error("synchronous effect failure");
    await expect(
      withResourceLease(store, resourceLeaseKey("provider/test"), 100, () => {
        throw original;
      }),
    ).rejects.toBe(original);
    expect(store.release).toHaveBeenCalledExactlyOnceWith(LEASE);
  });

  it("preserves the original effect error when lease release also fails", async () => {
    const store = repository();
    const original = new Error("effect outcome unknown");
    store.release.mockRejectedValue(new Error("release failed"));
    await expect(
      withResourceLease(store, resourceLeaseKey("provider/test"), 100, () =>
        Promise.reject(original),
      ),
    ).rejects.toBe(original);
    expect(store.release).toHaveBeenCalledOnce();
  });
});
