import { describe, expect, it } from "vitest";

import {
  PosthogMembershipsBranchPlanSchema,
  WorkspaceDirectoryPlanSchema,
} from "../src/execution/contracts.ts";
import { workspaceDirectoryChanges } from "../src/execution/operation.ts";
import { isScheduledPosthogMemberships } from "../src/execution/scheduled.ts";
import { workspaceBranchSourceIdentity } from "../src/execution/workspace-branch-source-identity.ts";
import { SignedOperationPlanSchema } from "../src/operations/schemas.ts";

const digest = "a".repeat(64);
function fixture() {
  const disabled = {
    diagnostics: [],
    execution: "disabled",
    killSwitchEngaged: true,
  };
  const branch = PosthogMembershipsBranchPlanSchema.parse({
    branchId: "posthog-memberships",
    execution: "managed",
    killSwitchEngaged: false,
    sourceFingerprint: digest,
    diagnostics: [],
    reviewed: {
      organizationId: "00000000-0000-0000-0000-000000000001",
      expectedPlanHash: digest,
      sourceAuthorityFingerprint: digest,
      action: {
        type: "invite",
        googleUserId: "222222",
        email: "product@company.test",
      },
    },
  });
  const plan = WorkspaceDirectoryPlanSchema.parse({
    authorityFingerprint: digest,
    googleUsers: 40,
    policyVersion: "workspace-directory-v12",
    branches: [
      { ...disabled, branchId: "slack-profiles", changes: [], planHash: null },
      {
        ...disabled,
        branchId: "drive-org-chart",
        bytes: 0,
        people: 0,
        photos: 0,
        currentSha256: null,
        desiredSha256: null,
      },
      {
        ...disabled,
        branchId: "slack-groups-channels",
        additions: [],
        removals: [],
        channelRenames: [],
        userGroups: [],
        planHash: null,
        lifecycle: {
          googleTeamGroupsOutsideAssignmentAllowlist: [],
          nonstandardPublicChannels: [],
          privateChannelRenameCandidates: [],
          slackTeamChannelCollisions: [],
          slackUsersWithoutTeamAssignment: [],
          verticalRetirementCandidates: [],
        },
      },
      {
        ...disabled,
        branchId: "github-access",
        contentHash: null,
        proposedChanges: [],
      },
      { ...disabled, branchId: "access-guard", plan: null },
      {
        branchId: "identity-provisioning",
        diagnostics: [],
        execution: "managed",
        killSwitchEngaged: false,
        providerExecution: "audit-only",
        subjects: [],
        githubIdentitySeed: { kind: "disabled", reason: "not-selected" },
        schemaPlan: { kind: "not-selected" },
      },
      branch,
    ],
  });
  const changes = workspaceDirectoryChanges(plan);
  const signed = SignedOperationPlanSchema.parse({
    signature: digest,
    plan: {
      actor: {
        id: "scheduled:workspace-directory",
        authorizationScope: "workspace-directory:apply",
      },
      applicable: true,
      applyAuthorized: true,
      changes,
      diagnostics: [],
      environment: "test",
      expiresAt: "2026-01-01T01:00:00.000Z",
      generatedAt: "2026-01-01T00:00:00.000Z",
      input: {},
      operation: "workspace-directory.reconcile",
      planHash: digest,
      policyVersion: "workspace-directory-v12",
      schemaVersion: 2,
      sourceFingerprints: [],
      summary: { add: 1, change: 0, invoke: 0, remove: 0, total: 1 },
    },
  });
  return { plan, branch, signed };
}
describe("PostHog signed parent selection", () => {
  it("binds the selected immutable Google identity to the original semantic change", () => {
    const f = fixture();
    expect(isScheduledPosthogMemberships(f.signed, f.plan, true)).toBe(true);
    expect(
      workspaceBranchSourceIdentity(f.branch, f.signed.plan.changes[0]),
    ).toMatchObject({
      kind: "identity",
      systemId: "posthog",
      googleUserId: "222222",
      providerAccountId: "product@company.test",
    });
    expect(isScheduledPosthogMemberships(f.signed, f.plan, false)).toBe(false);
  });
  it.each(["workspace-directory-v10", "workspace-directory-v11"])(
    "cannot add PostHog authority to legacy policy %s",
    (policyVersion) => {
      const f = fixture();
      expect(
        WorkspaceDirectoryPlanSchema.safeParse({ ...f.plan, policyVersion })
          .success,
      ).toBe(false);
    },
  );
  it("rejects forged resource IDs, before/after receipts, risk, change kinds, or duplicate changes", () => {
    const f = fixture();
    const change = f.signed.plan.changes[0];
    if (change === undefined) throw new Error("fixture_change_missing");
    const forgeries = [
      { ...change, resource: { ...change.resource, id: "different" } },
      { ...change, before: { state: "converged" } },
      { ...change, after: { state: "pending" } },
      { ...change, risk: "low" as const },
      { ...change, kind: "remove" as const },
    ];
    for (const forged of forgeries)
      expect(
        isScheduledPosthogMemberships(
          { ...f.signed, plan: { ...f.signed.plan, changes: [forged] } },
          f.plan,
          true,
        ),
      ).toBe(false);
    expect(
      isScheduledPosthogMemberships(
        { ...f.signed, plan: { ...f.signed.plan, changes: [change, change] } },
        f.plan,
        true,
      ),
    ).toBe(false);
    expect(() =>
      workspaceBranchSourceIdentity(f.branch, {
        ...change,
        resource: { ...change.resource, id: "different" },
      }),
    ).toThrow("workspace_branch_posthog_pin_mismatch");
  });
});
