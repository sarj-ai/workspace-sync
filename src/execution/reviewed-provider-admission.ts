import { sameJson, sha256Hex } from "../operations/canonical.ts";
import type { PreparedOperationApply } from "../operations/kernel.ts";
import {
  JsonValueSchema,
  type ManagedChange,
  type OperationPlanEnvelope,
} from "../operations/schemas.ts";
import {
  WORKSPACE_DIRECTORY_ACTION_IDS,
  WorkspaceDirectoryChangeDetailsSchema,
  WorkspaceDirectoryOperationInputSchema,
  type WorkspaceDirectoryPlan,
} from "./contracts.ts";
import {
  workspaceDirectoryChanges,
  workspaceDirectorySourceFingerprints,
} from "./operation.ts";
import {
  googleGroupCleanupManagedSlice,
  googleGroupCleanupResourceId,
} from "./reviewed-google-group-cleanup.ts";
import { selectReviewedLinearSuspension } from "./reviewed-linear-suspension.ts";
import {
  assertReviewedSlackLifecyclePlanMatches,
  reviewedSlackLifecycleAdmissionProof,
} from "./reviewed-slack-lifecycle-admission.ts";
import {
  ReviewedGoogleGroupCleanupIntentProofSchema,
  ReviewedLinearIntentProofSchema,
  type ReviewedProviderIntentProof,
} from "./reviewed-slack-lifecycle-intent.ts";

const ACTION = WORKSPACE_DIRECTORY_ACTION_IDS.linearSuspensions;
const EXACT_REQUIRED = "reviewed_provider_exact_original_action_required";
const ORIGINAL_AUTHORITY_CHANGED =
  "reviewed_provider_original_authority_changed";

type ReviewedProviderAdmissionInput = Pick<
  Extract<PreparedOperationApply, { ok: true }>,
  "pending" | "plan"
>;

export function usesReviewedProviderAdmission(
  rawInput: unknown,
  pending: readonly ManagedChange[],
): boolean {
  const input = WorkspaceDirectoryOperationInputSchema.parse(rawInput);
  return (
    "reviewedSlackLifecycleRemoval" in input ||
    "reviewedLinearSuspension" in input ||
    pending[0]?.actionId === WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup
  );
}

export async function reviewedProviderAdmissionProof(
  prepared: ReviewedProviderAdmissionInput,
): Promise<ReviewedProviderIntentProof> {
  const input = WorkspaceDirectoryOperationInputSchema.parse(
    prepared.plan.input,
  );
  const cleanupPending = prepared.pending.filter(
    ({ actionId }) =>
      actionId === WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup,
  );
  if (cleanupPending.length > 0) {
    if (
      prepared.pending.length !== 1 ||
      cleanupPending.length !== 1 ||
      prepared.plan.changes.some(
        (change) =>
          change.actionId !==
            WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup &&
          !equal(change.before, change.after),
      )
    )
      throw new Error(EXACT_REQUIRED);
    const evidence = await googleCleanupEnvelopeEvidence(prepared.plan);
    return ReviewedGoogleGroupCleanupIntentProofSchema.parse({
      ...evidence,
      actorHash: await sha256Hex(JsonValueSchema.parse(prepared.plan.actor)),
      originalPlanHash: prepared.plan.planHash,
      generatedAtMs: Date.parse(prepared.plan.generatedAt),
      expiresAtMs: Math.min(
        Date.parse(prepared.plan.expiresAt),
        Date.parse(prepared.plan.generatedAt) + 600_000,
      ),
    });
  }
  if (!("reviewedLinearSuspension" in input))
    return reviewedSlackLifecycleAdmissionProof(prepared);
  if (
    prepared.pending.length !== 1 ||
    !equal(prepared.pending, prepared.plan.changes)
  )
    throw new Error(EXACT_REQUIRED);
  const evidence = await linearEnvelopeEvidence(prepared.plan);
  return ReviewedLinearIntentProofSchema.parse({
    ...evidence,
    actorHash: await sha256Hex(JsonValueSchema.parse(prepared.plan.actor)),
    originalPlanHash: prepared.plan.planHash,
    generatedAtMs: Date.parse(prepared.plan.generatedAt),
    expiresAtMs: Math.min(
      Date.parse(prepared.plan.expiresAt),
      Date.parse(prepared.plan.generatedAt) + 600_000,
    ),
  });
}

export async function assertReviewedProviderPlanMatches(
  proof: ReviewedProviderIntentProof,
  plan: OperationPlanEnvelope,
): Promise<void> {
  if (!("provider" in proof))
    return assertReviewedSlackLifecyclePlanMatches(proof, plan);
  if (proof.provider === "google-group-cleanup") {
    assertGoogleCleanupEvidence(
      proof,
      await googleCleanupEnvelopeEvidence(plan),
    );
    return;
  }
  assertLinearEvidence(proof, await linearEnvelopeEvidence(plan));
}

async function googleCleanupEnvelopeEvidence(plan: OperationPlanEnvelope) {
  const input = WorkspaceDirectoryOperationInputSchema.parse(plan.input);
  const cleanupChanges = plan.changes.filter(
    ({ actionId }) =>
      actionId === WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup,
  );
  const change = cleanupChanges.length === 1 ? cleanupChanges[0] : undefined;
  if (
    !plan.applicable ||
    !plan.applyAuthorized ||
    plan.operation !== "workspace-directory.reconcile" ||
    change === undefined ||
    plan.changes.some(
      (candidate) =>
        candidate.actionId !==
          WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup &&
        !equal(candidate.before, candidate.after),
    )
  )
    throw new Error(EXACT_REQUIRED);
  const details = WorkspaceDirectoryChangeDetailsSchema.parse(change.details);
  if (details.kind !== "google-group-cleanup") throw new Error(EXACT_REQUIRED);
  const evidence = await googleCleanupDirectoryEvidence(details.plan);
  const sourceFingerprints = workspaceDirectorySourceFingerprints(
    details.plan,
    new Set([WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup]),
  );
  if (
    change.kind !== "remove" ||
    change.risk !== "high" ||
    change.resource.type !== "google-group-membership" ||
    change.resource.id !== googleGroupCleanupResourceId(evidence.reviewed) ||
    evidence.beforeHash !== (await sha256Hex(change.before)) ||
    evidence.afterHash !== (await sha256Hex(change.after)) ||
    ("reviewedGoogleGroupCleanup" in input &&
      !equal(input.reviewedGoogleGroupCleanup, evidence.reviewed)) ||
    !sourceFingerprints.every((fingerprint) =>
      plan.sourceFingerprints.some((candidate) =>
        equal(candidate, fingerprint),
      ),
    )
  )
    throw new Error(EXACT_REQUIRED);
  return evidence;
}

async function googleCleanupDirectoryEvidence(plan: WorkspaceDirectoryPlan) {
  const branch = plan.branches.find(
    (candidate) => candidate.branchId === "google-group-cleanup",
  );
  if (
    branch?.execution !== "managed" ||
    branch.killSwitchEngaged ||
    branch.reviewed === null ||
    branch.sourceFingerprint !== plan.authorityFingerprint
  )
    throw new Error(EXACT_REQUIRED);
  const reviewed = branch.reviewed;
  const changes = workspaceDirectoryChanges(plan).filter(
    ({ actionId }) =>
      actionId === WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup,
  );
  const change = changes.length === 1 ? changes[0] : undefined;
  const before = googleGroupCleanupManagedSlice(reviewed, "pending");
  const after = googleGroupCleanupManagedSlice(reviewed, "converged");
  if (
    change === undefined ||
    !equal(change.before, before) ||
    !equal(change.after, after)
  )
    throw new Error(EXACT_REQUIRED);
  const sourceFingerprints = workspaceDirectorySourceFingerprints(
    plan,
    new Set([WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup]),
  );
  return {
    provider: "google-group-cleanup" as const,
    reviewed,
    beforeHash: await sha256Hex(before),
    afterHash: await sha256Hex(after),
    branchHash: await sha256Hex(JsonValueSchema.parse(branch)),
    leafPlanHash: await sha256Hex(JsonValueSchema.parse(reviewed)),
    sourceHash: await sha256Hex(JsonValueSchema.parse(sourceFingerprints)),
  };
}

async function linearEnvelopeEvidence(plan: OperationPlanEnvelope) {
  const input = WorkspaceDirectoryOperationInputSchema.parse(plan.input);
  const change = plan.changes.length === 1 ? plan.changes[0] : undefined;
  if (
    !("reviewedLinearSuspension" in input) ||
    !plan.applicable ||
    !plan.applyAuthorized ||
    plan.operation !== "workspace-directory.reconcile" ||
    change?.actionId !== ACTION
  )
    throw new Error(EXACT_REQUIRED);
  const details = WorkspaceDirectoryChangeDetailsSchema.parse(change.details);
  if (details.kind !== "linear-suspensions" || details.plan === undefined)
    throw new Error(EXACT_REQUIRED);
  const evidence = await linearDirectoryEvidence(details.plan);
  if (
    change.kind !== "remove" ||
    change.risk !== "high" ||
    change.resource.type !== "linear-access" ||
    change.resource.id !== "suspensions" ||
    evidence.beforeHash !== (await sha256Hex(change.before)) ||
    evidence.afterHash !== (await sha256Hex(change.after)) ||
    !equal(input.reviewedLinearSuspension, evidence.reviewed) ||
    !equal(details.actions, details.plan.branches[4].plan?.actions) ||
    evidence.sourceHash !==
      (await sha256Hex(JsonValueSchema.parse(plan.sourceFingerprints)))
  )
    throw new Error(EXACT_REQUIRED);
  return evidence;
}

export async function assertReviewedLinearIntentPlan(
  proof: ReviewedProviderIntentProof,
  plan: WorkspaceDirectoryPlan,
): Promise<void> {
  if (!("provider" in proof)) throw new Error(EXACT_REQUIRED);
  assertLinearEvidence(proof, await linearDirectoryEvidence(plan));
}

/*
 * Proves that an independently scheduled Google cleanup selected the exact
 * immutable membership removal admitted by the original reviewed intent.
 * Other reviewed providers cannot currently be written automatically and are
 * deliberately ineligible for this status-only convergence projection.
 */
export async function scheduledGoogleCleanupMatchesReviewedIntent(
  proof: ReviewedProviderIntentProof,
  plan: WorkspaceDirectoryPlan,
): Promise<boolean> {
  if (!("provider" in proof) || proof.provider !== "google-group-cleanup")
    return false;
  try {
    assertGoogleCleanupEvidence(
      proof,
      await googleCleanupDirectoryEvidence(plan),
    );
    return true;
  } catch {
    return false;
  }
}

async function linearDirectoryEvidence(plan: WorkspaceDirectoryPlan) {
  const branch = plan.branches[4];
  if (
    branch.execution !== "managed" ||
    branch.reviewedLinearSuspension === undefined ||
    branch.plan.actions.length !== 1
  )
    throw new Error(EXACT_REQUIRED);
  const reviewed = branch.reviewedLinearSuspension;
  selectReviewedLinearSuspension(branch.plan, reviewed);
  const changes = workspaceDirectoryChanges(plan).filter(
    ({ actionId }) => actionId === ACTION,
  );
  const change = changes.length === 1 ? changes[0] : undefined;
  if (
    change?.kind !== "remove" ||
    change.risk !== "high" ||
    !equal(change.before, [
      { accountId: reviewed.accountId, active: true, email: reviewed.email },
    ]) ||
    !equal(change.after, [
      { accountId: reviewed.accountId, active: false, email: reviewed.email },
    ])
  )
    throw new Error(EXACT_REQUIRED);
  return {
    provider: "linear" as const,
    reviewed,
    beforeHash: await sha256Hex(change.before),
    afterHash: await sha256Hex(change.after),
    branchHash: await sha256Hex(JsonValueSchema.parse(branch)),
    leafPlanHash: await sha256Hex(JsonValueSchema.parse(branch.plan)),
    sourceHash: await sha256Hex(
      JsonValueSchema.parse(
        workspaceDirectorySourceFingerprints(plan, new Set([ACTION])),
      ),
    ),
  };
}

function assertLinearEvidence(
  proof: ReviewedProviderIntentProof,
  evidence: Awaited<ReturnType<typeof linearDirectoryEvidence>>,
) {
  if (
    !("provider" in proof) ||
    !equal(evidence, {
      provider: proof.provider,
      reviewed: proof.reviewed,
      beforeHash: proof.beforeHash,
      afterHash: proof.afterHash,
      branchHash: proof.branchHash,
      leafPlanHash: proof.leafPlanHash,
      sourceHash: proof.sourceHash,
    })
  )
    throw new Error(ORIGINAL_AUTHORITY_CHANGED);
}

export function reviewedProviderSelection(proof: ReviewedProviderIntentProof) {
  if (!("provider" in proof))
    return {
      actionId: WORKSPACE_DIRECTORY_ACTION_IDS.slackGroupsChannels,
      confirmations: {},
      input: {
        includedActionIds: [WORKSPACE_DIRECTORY_ACTION_IDS.slackGroupsChannels],
        reviewedSlackLifecycleRemoval: proof.reviewed,
      },
    };
  if (proof.provider === "google-group-cleanup")
    return {
      actionId: WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup,
      confirmations: {},
      input: {
        includedActionIds: [WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup],
        reviewedGoogleGroupCleanup: proof.reviewed,
      },
    };
  return {
    actionId: ACTION,
    confirmations: { linearSuspensions: { allowed: true, expectedCount: 1 } },
    input: {
      includedActionIds: [ACTION],
      reviewedLinearSuspension: proof.reviewed,
    },
  };
}

function assertGoogleCleanupEvidence(
  proof: ReviewedProviderIntentProof,
  evidence: Awaited<ReturnType<typeof googleCleanupDirectoryEvidence>>,
) {
  if (
    !("provider" in proof) ||
    proof.provider !== "google-group-cleanup" ||
    !equal(evidence, {
      provider: proof.provider,
      reviewed: proof.reviewed,
      beforeHash: proof.beforeHash,
      afterHash: proof.afterHash,
      branchHash: proof.branchHash,
      leafPlanHash: proof.leafPlanHash,
      sourceHash: proof.sourceHash,
    })
  )
    throw new Error(ORIGINAL_AUTHORITY_CHANGED);
}

function equal(left: unknown, right: unknown) {
  return sameJson(JsonValueSchema.parse(left), JsonValueSchema.parse(right));
}
