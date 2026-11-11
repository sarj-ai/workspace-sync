import { describe, expect, it, vi } from "vitest";

import { assertWorkspaceBranchClaimFresh } from "../src/execution/assert-workspace-branch-claim-fresh.ts";
import {
  GoogleGroupCleanupService,
  type GoogleGroupCleanupParentExecution,
  type GoogleGroupCleanupServiceDependencies,
} from "../src/execution/google-group-cleanup-service.ts";
import { ReviewedGoogleGroupCleanupSchema } from "../src/execution/reviewed-google-group-cleanup.ts";
import { WorkspaceScheduleExecutionIdentitySchema } from "../src/execution/workspace-schedule-health-repository.ts";
import { normalizeGooglePrivateKey } from "../src/org-sync/normalize-google-private-key.ts";

const REVIEWED = ReviewedGoogleGroupCleanupSchema.parse({
  action: {
    googleGroupEmail: "team@company.test",
    googleGroupId: "group",
    googleUserId: "12345",
    lifecycle: "suspended",
    memberEmail: "former@company.test",
    memberId: "12345",
    type: "remove-inactive-google-group-member",
  },
  expectedPlanHash: "a".repeat(64),
});
function fixture() {
  const unexpected = vi.fn(async (): Promise<never> => {
    throw new Error("unexpected external effect");
  });
  const dependencies: GoogleGroupCleanupServiceDependencies = {
    directory: {
      getUserById: unexpected,
      listAllUsers: unexpected,
      listDeletedUsers: unexpected,
    },
    groups: { listAllGroups: unexpected, listGroups: unexpected },
    leaseRepository: {
      acquire: unexpected,
      assertActive: unexpected,
      release: unexpected,
    },
    managedGoogleGroupPins: [{ email: "team@company.test", id: "group" }],
    writer: { auditDirectMember: unexpected, removeDirectMember: unexpected },
  };
  const context = {
    mode: "parent",
    identityBudget: { required: true, reserve: unexpected },
    assertFreshPlan: vi.fn(),
    assertWriteAuthority: unexpected,
    assertFinalSourceAuthority: unexpected,
    verifyPreannouncement: vi.fn(async () => undefined),
  } satisfies GoogleGroupCleanupParentExecution;
  return { context, dependencies, unexpected };
}

describe("canonical execution admission", () => {
  it("rejects writes from an audit service before any parent or provider effect", async () => {
    const f = fixture();
    await expect(
      new GoogleGroupCleanupService(
        { kind: "audit" },
        f.dependencies,
      ).applyReviewed(REVIEWED, f.context),
    ).rejects.toThrow("google_group_cleanup_signed_parent_required");
    expect(f.context.verifyPreannouncement).not.toHaveBeenCalled();
    expect(f.unexpected).not.toHaveBeenCalled();
  });
  it("rejects an unbudgeted command before any external effect", async () => {
    const f = fixture();
    await expect(
      new GoogleGroupCleanupService(
        { kind: "parent" },
        f.dependencies,
      ).applyReviewed(REVIEWED, {
        ...f.context,
        identityBudget: { required: false },
      }),
    ).rejects.toThrow("google_group_cleanup_signed_parent_required");
    expect(f.unexpected).not.toHaveBeenCalled();
  });
  it("does not acquire a lease or contact providers after receipt verification fails", async () => {
    const f = fixture();
    const failure = new Error("receipt uncertain");
    vi.mocked(f.context.verifyPreannouncement).mockRejectedValue(failure);
    await expect(
      new GoogleGroupCleanupService(
        { kind: "parent" },
        f.dependencies,
      ).applyReviewed(REVIEWED, f.context),
    ).rejects.toBe(failure);
    expect(f.unexpected).not.toHaveBeenCalled();
  });
  it("rejects expiration after receipt verification before acquiring a lease", async () => {
    const f = fixture();
    const failure = new Error("approval expired");
    vi.mocked(f.context.assertFreshPlan).mockImplementation(() => {
      throw failure;
    });
    await expect(
      new GoogleGroupCleanupService(
        { kind: "parent" },
        f.dependencies,
      ).applyReviewed(REVIEWED, f.context),
    ).rejects.toBe(failure);
    expect(f.context.verifyPreannouncement).toHaveBeenCalledOnce();
    expect(f.unexpected).not.toHaveBeenCalled();
  });
});
describe("durable parent identity and deadline boundaries", () => {
  it("validates both identifier roles and rejects incomplete persisted identity", () => {
    expect(
      WorkspaceScheduleExecutionIdentitySchema.safeParse({
        tickId: "a".repeat(64),
        workflowId: "b".repeat(64),
      }).success,
    ).toBe(true);
    for (const identity of [
      {},
      { tickId: "a".repeat(64) },
      { tickId: "invalid", workflowId: "b".repeat(64) },
      { tickId: "a".repeat(64), workflowId: "invalid" },
    ]) {
      expect(
        WorkspaceScheduleExecutionIdentitySchema.safeParse(identity).success,
      ).toBe(false);
    }
  });
  it("accepts a fresh claim and honors the earliest durable approval deadline", () => {
    const start = Date.parse("2026-01-01T00:00:00Z");
    const params = {
      planGeneratedAt: new Date(start).toISOString(),
      reviewedProviderIntent: { proof: { expiresAtMs: start + 1000 } },
    };
    expect(() => assertWorkspaceBranchClaimFresh(params, start)).not.toThrow();
    expect(() =>
      assertWorkspaceBranchClaimFresh(params, start + 999),
    ).not.toThrow();
    expect(() => assertWorkspaceBranchClaimFresh(params, start + 1000)).toThrow(
      "workspace_branch_plan_expired",
    );
    expect(() => assertWorkspaceBranchClaimFresh(params, start - 1)).toThrow(
      "workspace_branch_plan_expired",
    );
  });
  it("normalizes environment PEM newlines without changing an already decoded key", () => {
    const decoded = "header\nbody\nfooter";
    expect(normalizeGooglePrivateKey(String.raw`header\nbody\nfooter`)).toBe(
      decoded,
    );
    expect(normalizeGooglePrivateKey(decoded)).toBe(decoded);
  });
});
