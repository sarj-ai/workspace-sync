import { describe, expect, it } from "vitest";

import {
  configureWorkspaceSyncPolicy,
  getWorkspaceSyncPolicy,
  WorkspaceSyncPolicySchema,
} from "../src/configuration.ts";
import { TEST_POLICY } from "./policy.ts";

describe("tenant policy isolation", () => {
  it("permits idempotent initialization and rejects a different tenant", () => {
    expect(() => configureWorkspaceSyncPolicy(TEST_POLICY)).not.toThrow();
    expect(() =>
      configureWorkspaceSyncPolicy({
        ...TEST_POLICY,
        org: { ...TEST_POLICY.org, managedDomain: "other.example" },
      }),
    ).toThrow("workspace_sync_policy_already_configured");
  });

  it("does not retain a mutable caller-owned object", () => {
    const input = structuredClone(TEST_POLICY);
    configureWorkspaceSyncPolicy(input);
    input.org.expectedRootGoogleUserIds.length = 0;
    expect(getWorkspaceSyncPolicy().org.expectedRootGoogleUserIds).toHaveLength(
      2,
    );
    expect(Object.isFrozen(getWorkspaceSyncPolicy())).toBe(true);
    expect(
      Object.isFrozen(getWorkspaceSyncPolicy().org.expectedRootGoogleUserIds),
    ).toBe(true);
    expect(() =>
      getWorkspaceSyncPolicy().org.expectedRootGoogleUserIds.pop(),
    ).toThrow(TypeError);
  });

  it("rejects incomplete policy and inconsistent contractor authority", () => {
    expect(WorkspaceSyncPolicySchema.safeParse({}).success).toBe(false);
    expect(
      WorkspaceSyncPolicySchema.safeParse({
        ...TEST_POLICY,
        trycomp: { ...TEST_POLICY.trycomp, contractorGroupId: "other" },
      }).success,
    ).toBe(false);
  });

  it("rejects credentials and extra policy fields", () => {
    expect(
      WorkspaceSyncPolicySchema.safeParse({
        ...TEST_POLICY,
        privateKey: "test",
      }).success,
    ).toBe(false);
  });
});
