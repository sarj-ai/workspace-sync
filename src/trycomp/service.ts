import { dequal } from "dequal";

import { contentHash } from "../github-access-audit/content-hash.ts";
import { normalizeIdentityEmail as normalizeEmail } from "../identity-sync/normalize-identity-email.ts";
import type { ActiveResourceLease } from "../identity-sync/resource-lease.ts";
import type { GoogleGroupSnapshot } from "../org-sync/channel-model.ts";
import { orgSyncSettings } from "../org-sync/config.ts";
import { googleAuthorityFingerprintRecord } from "../org-sync/google-directory-authority.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import { sha256 } from "../runtime/sha256.ts";
import { logEvent } from "../shared/log-event.ts";
import type { ITrycompPeopleClient } from "./client.ts";
import {
  hasTrycompDeactivationSafety,
  isVerifiedDeviceFreeTrycompRevocation,
} from "./deactivation-safety.ts";
import {
  type TrycompAction,
  type TrycompMember,
  type TrycompPlan,
  type TrycompReviewedMember,
  type TrycompReviewedPlan,
  TrycompReviewedPlanSchema,
  type TrycompReviewedSlice,
  type TrycompRunReport,
} from "./model.ts";
import { buildGoogleEmailIndex, buildTrycompPlan } from "./plan.ts";
import {
  assertTrycompSelectedIdentity,
  sameReviewedTrycompPlan,
  selectedTrycompIdentity,
  trycompManagedSlice,
} from "./reviewed-identity.ts";
import type {
  TrycompActionAuthorityEvidence,
  TrycompDeploymentEvidence,
  TrycompMutationStore,
  TrycompSafetyStore,
} from "./safety.ts";

const PROTECTED_IDENTITY_WRITE_BLOCKED =
  "trycomp_protected_identity_write_blocked";

export interface TrycompPeopleSyncConfig {
  activationDeniedEmails?: readonly string[];
  allowDeactivations: boolean;
  approvedPlanHash: string;
  excludedGoogleUserIds: readonly string[];
  expectedContractorGroupId: string;
  managedDomain: string;
  maxAutomaticActivations: number;
  maxAutomaticContractorDeactivations?: number;
  maxAutomaticDeactivations?: number;
  maxAutomaticInactiveGoogleDeactivations?: number;
  minimumGoogleUsers: number;
  mode: "audit" | "live";
  offboardingOnly?: boolean;
  protectedEmails?: readonly string[];
  protectedGoogleUserIds?: readonly string[];
  writeProtectedEmails?: readonly string[];
  writeProtectedGoogleUserIds?: readonly string[];
}

export interface TrycompAuthorityInput {
  activeGoogleUserCount?: number;
  contractorGroup: GoogleGroupSnapshot;
  googleUsers: readonly GoogleDirectoryUser[];
}

export interface TrycompPeopleSyncInput extends TrycompAuthorityInput {
  assertWriteAuthority?: () => Promise<void>;
  deployment?: TrycompDeploymentEvidence;
  lease?: ActiveResourceLease;
  mode?: "audit" | "live";
  mutationJournal?: TrycompMutationStore;
  preannounce?: (
    plan: Pick<TrycompRunReport, "planHash" | "planned" | "runId">,
    renew: () => Promise<void>,
  ) => Promise<{ intentKey: string; slackTimestamp: string }>;
  refreshAuthority?: () => Promise<TrycompAuthorityInput>;
  requireSelectedIdentity?: boolean;
  safetyReader?: TrycompSafetyStore;
  trigger: "cron" | "http";
}

export interface ITrycompPeopleSyncService {
  applyReviewed(
    input: TrycompPeopleSyncInput & { reviewedPlan: TrycompReviewedPlan },
  ): Promise<TrycompRunReport>;
  captureReviewedPlan(
    authority: TrycompAuthorityInput,
  ): Promise<TrycompReviewedPlan>;
  /** Pinned plans require fresh authority and original invitation evidence; legacy plans retain provider-only readback. */
  readReviewedSlice(
    reviewedPlan: TrycompReviewedPlan,
    evidence?: TrycompReviewedReadEvidence,
  ): Promise<TrycompReviewedSlice>;
  run(input: TrycompPeopleSyncInput): Promise<TrycompRunReport>;
}

export interface TrycompReviewedReadEvidence {
  authority: TrycompAuthorityInput;
  verifiedInvitationMemberId?: (() => Promise<null | string>) | undefined;
}

type FencedTrycompPeopleSyncInput = TrycompPeopleSyncInput &
  Required<
    Pick<TrycompPeopleSyncInput, "assertWriteAuthority" | "refreshAuthority">
  >;
type LiveTrycompPeopleSyncInput = FencedTrycompPeopleSyncInput &
  Required<
    Pick<
      TrycompPeopleSyncInput,
      | "deployment"
      | "lease"
      | "mutationJournal"
      | "preannounce"
      | "safetyReader"
    >
  >;

function hasLiveSafety(
  input: TrycompPeopleSyncInput,
): input is LiveTrycompPeopleSyncInput {
  return (
    hasFencedRefreshableAuthority(input) &&
    Boolean(
      input.deployment &&
      input.lease &&
      input.mutationJournal &&
      input.preannounce &&
      input.safetyReader,
    )
  );
}

function hasFencedRefreshableAuthority(
  input: TrycompPeopleSyncInput,
): input is FencedTrycompPeopleSyncInput {
  return Boolean(input.assertWriteAuthority && input.refreshAuthority);
}

export class TrycompPeopleSyncService implements ITrycompPeopleSyncService {
  readonly #client: ITrycompPeopleClient;
  readonly #config: TrycompPeopleSyncConfig;

  constructor(client: ITrycompPeopleClient, config: TrycompPeopleSyncConfig) {
    this.#client = client;
    this.#config = config;
  }

  async captureReviewedPlan(
    authority: TrycompAuthorityInput,
  ): Promise<TrycompReviewedPlan> {
    return this.#captureReviewedPlan(
      authority,
      await this.#client.listMembers(crypto.randomUUID()),
    );
  }

  async readReviewedSlice(
    rawPlan: TrycompReviewedPlan,
    evidence?: TrycompReviewedReadEvidence,
  ): Promise<TrycompReviewedSlice> {
    const reviewed = TrycompReviewedPlanSchema.parse(rawPlan);
    if (reviewed.selectedIdentity !== undefined) {
      if (evidence === undefined)
        throw new Error("trycomp_reviewed_identity_authority_required");
      assertTrycompSelectedIdentity(reviewed, evidence.authority.googleUsers);
      if (
        (await reviewedAuthorityFingerprint(evidence.authority)) !==
        reviewed.sourceFingerprint
      )
        throw new Error("trycomp_reviewed_identity_source_changed");
    }
    const members = await this.#client.listMembers(crypto.randomUUID());
    let slice = reviewedSlice(reviewed, members);
    if (
      reviewed.selectedIdentity?.provider.kind === "pending-invitation" &&
      slice.state === "converged"
    ) {
      const originalMemberId = await evidence?.verifiedInvitationMemberId?.();
      const current = selectedMembers(reviewed.plan.actions, members);
      if (
        originalMemberId === null ||
        originalMemberId === undefined ||
        current.length !== 1 ||
        current[0]?.id !== originalMemberId
      )
        slice = { state: "drifted" };
    }
    return trycompManagedSlice(reviewed, slice.state);
  }

  async applyReviewed(
    input: TrycompPeopleSyncInput & { reviewedPlan: TrycompReviewedPlan },
  ): Promise<TrycompRunReport> {
    const reviewed = TrycompReviewedPlanSchema.parse(input.reviewedPlan);
    if (
      input.requireSelectedIdentity ||
      reviewed.selectedIdentity !== undefined
    )
      assertTrycompSelectedIdentity(reviewed, input.googleUsers);
    const report = reviewedReport(reviewed, crypto.randomUUID(), "live");
    if (
      this.#config.mode !== "live" ||
      input.mode === "audit" ||
      input.trigger !== "cron" ||
      !hasLiveSafety(input)
    ) {
      return {
        ...report,
        errors: [
          "Trycomp reviewed apply requires live configuration and fenced, journaled, refreshable write authority",
        ],
        status: "blocked",
      };
    }
    if (reviewed.plan.errors.length > 0)
      return { ...report, status: "blocked" };
    return this.#runLive(input, report, reviewed);
  }

  async run(input: TrycompPeopleSyncInput): Promise<TrycompRunReport> {
    const runId = crypto.randomUUID();
    const mode = input.mode ?? this.#config.mode;
    if (mode === "live") {
      if (!hasLiveSafety(input)) {
        return this.#blockedWithoutPlan(
          runId,
          mode,
          "Trycomp live sync requires fenced, journaled, refreshable write authority",
        );
      }
      await input.safetyReader.assertClosed();
    }
    if (mode === "live" && input.trigger === "cron") {
      return this.applyReviewed({
        ...input,
        reviewedPlan: await this.captureReviewedPlan(input),
      });
    }
    const members = await this.#client.listMembers(runId);
    const plan = await this.#buildPlan(input, members);
    const report: TrycompRunReport = {
      applied: [],
      errors: plan.errors,
      mode,
      planHash: plan.planHash,
      planned: plan.actions,
      runId,
      status: mode === "audit" ? "audit" : "converged",
      warnings: plan.warnings,
    };
    if (plan.errors.length > 0) {
      const blocked = { ...report, status: "blocked" as const };
      if (mode !== "live") await this.#recordScheduledAudit(input, blocked);
      return blocked;
    }
    await this.#recordScheduledAudit(input, report);
    return report;
  }

  async #recordScheduledAudit(
    input: TrycompPeopleSyncInput,
    report: TrycompRunReport,
  ): Promise<void> {
    if (input.trigger !== "cron" || !input.mutationJournal) return;
    if (!input.deployment)
      throw new Error("trycomp_deployment_evidence_missing");
    const operationKeys = await Promise.all(
      report.planned.map((action, index) =>
        this.#operationKey(report.planHash, action, index),
      ),
    );
    await input.mutationJournal.beginRun({
      actionAuthority: actionAuthorityEvidence(
        report.planned,
        input.googleUsers,
        input.contractorGroup,
      ),
      actions: report.planned,
      deployment: input.deployment,
      mode: report.mode,
      planHash: report.planHash,
      providerOperationKeys: operationKeys,
      runId: report.runId,
      trigger: input.trigger,
    });
    if (report.status === "blocked") {
      await input.mutationJournal.failRun(
        report.runId,
        report.errors.join("; "),
      );
    } else {
      await input.mutationJournal.completeRun(report.runId);
    }
  }

  async #runLive(
    input: LiveTrycompPeopleSyncInput,
    report: TrycompRunReport,
    reviewed: TrycompReviewedPlan,
  ): Promise<TrycompRunReport> {
    const runId = report.runId;
    const { assertWriteAuthority, refreshAuthority } = input;
    await assertWriteAuthority();
    const freshAuthority = await refreshAuthority();
    const freshMembers = await this.#client.listMembers(runId);
    const freshReviewed = await this.#captureReviewedPlan(
      freshAuthority,
      freshMembers,
    );
    const freshPlan = freshReviewed.plan;
    const protectedActionEmails = this.#writeProtectedActionEmails(
      freshAuthority.googleUsers,
    );
    const authorizationErrors = this.#livePlanErrors(
      freshReviewed,
      reviewed,
      protectedActionEmails,
    );
    if (authorizationErrors.length > 0) {
      return { ...report, errors: authorizationErrors, status: "blocked" };
    }
    const mutationJournal = input.mutationJournal;
    const safetyReader = input.safetyReader;
    const lease = input.lease;
    const freshOperationKeys = await Promise.all(
      freshPlan.actions.map((action, index) =>
        this.#operationKey(freshPlan.planHash, action, index),
      ),
    );
    await safetyReader.assertClosed();
    await mutationJournal.beginRun({
      actionAuthority: actionAuthorityEvidence(
        freshPlan.actions,
        freshAuthority.googleUsers,
        freshAuthority.contractorGroup,
      ),
      actions: freshPlan.actions,
      deployment: input.deployment,
      mode: report.mode,
      planHash: freshPlan.planHash,
      providerOperationKeys: freshOperationKeys,
      runId,
      trigger: input.trigger,
    });
    if (freshPlan.actions.length > 0) {
      try {
        const receipt = await input.preannounce(
          { planHash: freshPlan.planHash, planned: freshPlan.actions, runId },
          assertWriteAuthority,
        );
        await mutationJournal.recordPreannouncement({
          intentKey: receipt.intentKey,
          lease,
          runId,
          slackTimestamp: receipt.slackTimestamp,
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        logEvent("trycomp_sync.preannouncement_failed", {
          error: message,
          "run_id": runId,
        });
        await this.#recordRunFailure(
          mutationJournal,
          safetyReader,
          runId,
          message,
        );
        return { ...report, errors: [message], status: "failed" };
      }
    }
    const applied: TrycompAction[] = [];
    try {
      for (const [actionIndex, action] of freshPlan.actions.entries()) {
        if (protectedActionEmails.has(action.email)) {
          throw new Error(PROTECTED_IDENTITY_WRITE_BLOCKED);
        }
        // The D1 generation fence is checked before every provider interaction so an expired
        // or superseded worker cannot continue mutating Trycomp.
        // eslint-disable-next-line no-await-in-loop -- Provider writes are deliberately serialized.
        await assertWriteAuthority();
        // eslint-disable-next-line no-await-in-loop -- Writes and readbacks are serialized to bound provider load and stop at the first ambiguous result.
        await safetyReader.assertClosed();
        // Re-read both authorities immediately before each provider write. A contractor-group,
        // Google lifecycle, alias, or Trycomp target change invalidates the individual action.
        // eslint-disable-next-line no-await-in-loop -- Every mutation requires fresh independent authority.
        const actionAuthority = await refreshAuthority();
        // eslint-disable-next-line no-await-in-loop -- Exact provider state is part of the per-action authority fence.
        const actionMembers = await this.#client.listMembers(
          freshOperationKeys[actionIndex] ?? "",
        );
        // eslint-disable-next-line no-await-in-loop -- The authority-bound action must be recomputed immediately before mutation.
        await this.#assertFreshActionAuthority(
          action,
          actionAuthority,
          actionMembers,
          reviewed,
        );
        // eslint-disable-next-line no-await-in-loop -- Each provider write and exact readback must finish before the next action can begin.
        await this.#applyAndVerify(
          action,
          actionIndex,
          freshOperationKeys[actionIndex] ?? "",
          runId,
          assertWriteAuthority,
          mutationJournal,
          lease,
          actionMembers,
          async () => {
            const finalAuthority = await refreshAuthority();
            const finalMembers = await this.#client.listMembers(
              freshOperationKeys[actionIndex] ?? "",
            );
            await this.#assertFreshActionAuthority(
              action,
              finalAuthority,
              finalMembers,
              reviewed,
            );
            await assertWriteAuthority();
          },
        );
        applied.push(action);
      }
      await mutationJournal.completeRun(runId);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logEvent("trycomp_sync.write_failed", {
        error: message,
        "run_id": runId,
      });
      await this.#recordRunFailure(
        mutationJournal,
        safetyReader,
        runId,
        message,
      );
      return { ...report, applied, errors: [message], status: "failed" };
    }
    logEvent("trycomp_sync.completed", {
      applied: applied.length,
      contractors: freshPlan.stats.contractorGoogleUsers,
      "google_employees": freshPlan.stats.activeGoogleEmployees,
      "plan_hash": freshPlan.planHash,
      "run_id": runId,
    });
    return { ...report, applied, status: "converged" };
  }

  async #recordRunFailure(
    mutationJournal: TrycompMutationStore,
    safetyReader: TrycompSafetyStore,
    runId: string,
    message: string,
  ): Promise<void> {
    try {
      const breaker = await safetyReader.status();
      if (breaker.state === "closed")
        await mutationJournal.failRun(runId, message);
    } catch (journalError) {
      logEvent("trycomp_sync.journal_failure", {
        error:
          journalError instanceof Error
            ? journalError.message
            : String(journalError),
        "run_id": runId,
      });
    }
  }

  #livePlanErrors(
    freshReviewed: TrycompReviewedPlan,
    reviewed: TrycompReviewedPlan,
    protectedActionEmails: ReadonlySet<string>,
  ): string[] {
    const freshPlan = freshReviewed.plan;
    if (freshPlan.errors.length > 0) return freshPlan.errors;
    if (!sameReviewedTrycompPlan(reviewed, freshReviewed)) {
      return ["Trycomp authority changed during live preflight"];
    }
    const activations = freshPlan.actions.filter(
      (action) => action.type !== "deactivate",
    ).length;
    return [
      ...freshPlan.actions.flatMap((action) =>
        protectedActionEmails.has(action.email)
          ? `Trycomp action targets protected identity ${action.email}`
          : [],
      ),
      ...this.#authorizationErrors(activations, freshPlan),
    ];
  }

  #buildPlan(input: TrycompPeopleSyncInput, members: readonly TrycompMember[]) {
    return buildTrycompPlan({
      ...((input.mode ?? this.#config.mode) === "live" &&
        input.trigger === "cron" && { automaticIdentityLimit: 1 as const }),
      ...(!(input.activeGoogleUserCount === undefined) && {
        activeGoogleUserCount: input.activeGoogleUserCount,
      }),
      activationDeniedEmails: this.#config.activationDeniedEmails ?? [],
      offboardingOnly: this.#config.offboardingOnly === true,
      contractorGroup: input.contractorGroup,
      expectedContractorGroupId: this.#config.expectedContractorGroupId,
      excludedGoogleUserIds: this.#config.excludedGoogleUserIds,
      googleUsers: input.googleUsers,
      managedDomain: this.#config.managedDomain,
      minimumGoogleUsers: this.#config.minimumGoogleUsers,
      writeProtectedEmails:
        this.#config.writeProtectedEmails ?? this.#config.protectedEmails ?? [],
      writeProtectedGoogleUserIds:
        this.#config.writeProtectedGoogleUserIds ??
        this.#config.protectedGoogleUserIds ??
        [],
      trycompMembers: members,
    });
  }

  async #captureReviewedPlan(
    authority: TrycompAuthorityInput,
    members: readonly TrycompMember[],
  ): Promise<TrycompReviewedPlan> {
    const plan = await this.#buildPlan(
      { ...authority, mode: "live", trigger: "cron" },
      members,
    );
    const selectedIdentity = selectedTrycompIdentity(
      plan,
      authority.googleUsers,
    );
    return TrycompReviewedPlanSchema.parse({
      plan,
      schemaVersion: "trycomp-reviewed/v1",
      ...(plan.actions.some((action) => action.type === "deactivate") && {
        deactivationMode: "device-free-membership-revocation" as const,
      }),
      sourceFingerprint: await reviewedAuthorityFingerprint(authority),
      targetBefore: selectedMembers(
        plan.actions,
        members,
        plan.actions.some((action) => action.type === "deactivate"),
      ),
      ...(!(selectedIdentity === undefined) && { selectedIdentity }),
    });
  }

  async #applyAndVerify(
    action: TrycompAction,
    actionIndex: number,
    operationKey: string,
    runId: string,
    assertWriteAuthority: () => Promise<void>,
    safety: TrycompMutationStore,
    lease: ActiveResourceLease,
    preflightMembers: readonly TrycompMember[],
    refreshActionAuthority: () => Promise<void>,
  ): Promise<void> {
    let attempted = false;
    try {
      if (action.type === "deactivate") {
        this.#exactActionMember(action, preflightMembers);
        await assertWriteAuthority();
        await safety.markAttempted({ actionIndex, lease, runId });
        attempted = true;
        await assertWriteAuthority();
        await refreshActionAuthority();
        await this.#client.deactivate(action.memberId, operationKey);
        await safety.markProviderAccepted(runId, actionIndex);
        await assertWriteAuthority();
        const after = this.#exactActionMember(
          action,
          await this.#client.listMembers(operationKey),
        );
        if (!isVerifiedDeviceFreeTrycompRevocation(after))
          throw new Error("trycomp_deactivation_not_observed");
        await safety.markVerified(runId, actionIndex, action.memberId);
        return;
      }
      if (action.type === "reactivate") {
        this.#exactActionMember(action, preflightMembers);
        await assertWriteAuthority();
        await safety.markAttempted({ actionIndex, lease, runId });
        attempted = true;
        await assertWriteAuthority();
        await this.#client.reactivate(action.memberId, operationKey);
        await safety.markProviderAccepted(runId, actionIndex);
        await assertWriteAuthority();
        const after = this.#exactActionMember(
          action,
          await this.#client.listMembers(operationKey),
        );
        if (!after.isActive || after.deactivated)
          throw new Error("trycomp_reactivation_not_observed");
        await safety.markVerified(runId, actionIndex, action.memberId);
        return;
      }
      await assertWriteAuthority();
      await safety.markAttempted({ actionIndex, lease, runId });
      attempted = true;
      await assertWriteAuthority();
      await this.#client.inviteEmployee(action.email, operationKey);
      await safety.markProviderAccepted(runId, actionIndex);
      await assertWriteAuthority();
      const after = await this.#client.listMembers(operationKey);
      const invited = after.filter(
        (member) =>
          member.user.email.toLocaleLowerCase("en-US") === action.email,
      );
      if (
        invited.length !== 1 ||
        !invited[0]?.isActive ||
        invited[0].deactivated ||
        invited[0].role.toLocaleLowerCase("en-US") !== "employee"
      )
        throw new Error("trycomp_invite_not_observed");
      await safety.markVerified(runId, actionIndex, invited[0].id);
    } catch (error) {
      if (attempted) {
        const message = error instanceof Error ? error.message : String(error);
        await safety.openForAmbiguous(runId, actionIndex, message);
      }
      throw error;
    }
  }

  async #operationKey(
    planHash: string,
    action: TrycompAction,
    index: number,
  ): Promise<string> {
    return sha256(
      JSON.stringify({ action, index, planHash, policyVersion: 1 }),
    );
  }

  #blockedWithoutPlan(
    runId: string,
    mode: "audit" | "live",
    error: string,
  ): TrycompRunReport {
    return {
      applied: [],
      errors: [error],
      mode,
      planHash: "0".repeat(64),
      planned: [],
      runId,
      status: "blocked",
      warnings: [],
    };
  }

  #exactActionMember(
    action: Extract<TrycompAction, { memberId: string }>,
    members: readonly TrycompMember[],
  ): TrycompMember {
    const matches = members.filter((member) => member.id === action.memberId);
    if (matches.length !== 1 || matches[0] === undefined) {
      throw new Error("trycomp_target_identity_changed");
    }
    this.#assertTarget(action, matches[0]);
    return matches[0];
  }

  #assertTarget(
    action: Extract<TrycompAction, { memberId: string }>,
    member: TrycompMember,
  ): void {
    if (
      member.id !== action.memberId ||
      member.user.email.toLocaleLowerCase("en-US") !==
        (action.providerEmail ?? action.email) ||
      member.role.toLocaleLowerCase("en-US") !== "employee"
    ) {
      throw new Error("trycomp_target_identity_changed");
    }
  }

  #writeProtectedActionEmails(
    googleUsers: readonly GoogleDirectoryUser[],
  ): Set<string> {
    return writeProtectedActionEmails(this.#config, googleUsers);
  }

  #authorizationErrors(activations: number, plan: TrycompPlan): string[] {
    const errors: string[] = [];
    if (new Set(plan.actions.map(({ email }) => email)).size > 1) {
      errors.push(
        "Trycomp automatic changes exceed the shared one-identity limit",
      );
    }
    errors.push(...this.#activationPolicyErrors(activations, plan));
    const contractorDeactivations = plan.actions.filter(
      (action) =>
        action.type === "deactivate" &&
        action.deactivationAuthority === "contractor_group",
    ).length;
    const inactiveGoogleDeactivations = plan.actions.filter(
      (action) =>
        action.type === "deactivate" &&
        action.deactivationAuthority === "inactive_google",
    ).length;
    const deactivations = plan.actions.filter(
      (action) => action.type === "deactivate",
    ).length;
    const unclassifiedDeactivations =
      deactivations - contractorDeactivations - inactiveGoogleDeactivations;
    if (unclassifiedDeactivations > 0) {
      errors.push(
        "Trycomp deactivation lacks explicit Google authority classification",
      );
    }
    if (deactivations > 0 && !this.#config.allowDeactivations) {
      errors.push("Trycomp deactivations are disabled");
    }
    const totalDeactivationCap = this.#config.maxAutomaticDeactivations ?? 0;
    if (deactivations > totalDeactivationCap) {
      errors.push(
        `Trycomp deactivation count ${String(deactivations)} exceeds total automatic cap ${String(totalDeactivationCap)}`,
      );
    }
    if (
      contractorDeactivations >
      (this.#config.maxAutomaticContractorDeactivations ??
        this.#config.maxAutomaticDeactivations ??
        0)
    ) {
      errors.push(
        `Trycomp contractor deactivation count ${String(contractorDeactivations)} exceeds hard cap ${String(this.#config.maxAutomaticContractorDeactivations ?? this.#config.maxAutomaticDeactivations ?? 0)}`,
      );
    }
    if (
      inactiveGoogleDeactivations >
        (this.#config.maxAutomaticInactiveGoogleDeactivations ??
          this.#config.maxAutomaticDeactivations ??
          0) &&
      this.#config.approvedPlanHash !== plan.planHash
    ) {
      errors.push(
        `Trycomp inactive-Google deactivation count ${String(inactiveGoogleDeactivations)} exceeds automatic cap ${String(this.#config.maxAutomaticInactiveGoogleDeactivations ?? this.#config.maxAutomaticDeactivations ?? 0)} without the exact approved plan hash`,
      );
    }
    return errors;
  }

  #activationPolicyErrors(activations: number, plan: TrycompPlan): string[] {
    const errors: string[] = [];
    const activationCap = this.#config.offboardingOnly
      ? 0
      : this.#config.maxAutomaticActivations;
    if (
      this.#config.offboardingOnly &&
      plan.actions.some(
        (action) =>
          action.type !== "deactivate" ||
          action.deactivationAuthority !== "inactive_google",
      )
    ) {
      errors.push(
        "Trycomp offboarding-only policy requires inactive Google deactivation authority",
      );
    }
    if (activations > activationCap) {
      errors.push(
        `Trycomp activation count ${String(activations)} exceeds automatic cap ${String(activationCap)}`,
      );
    }
    return errors;
  }

  async #assertFreshActionAuthority(
    action: TrycompAction,
    authority: {
      activeGoogleUserCount?: number;
      contractorGroup: GoogleGroupSnapshot;
      googleUsers: readonly GoogleDirectoryUser[];
    },
    members: readonly TrycompMember[],
    reviewed: TrycompReviewedPlan,
  ): Promise<void> {
    const protectedEmails = this.#writeProtectedActionEmails(
      authority.googleUsers,
    );
    if (protectedEmails.has(action.email)) {
      throw new Error(PROTECTED_IDENTITY_WRITE_BLOCKED);
    }
    const freshReviewed = await this.#captureReviewedPlan(authority, members);
    if (!sameReviewedTrycompPlan(reviewed, freshReviewed)) {
      throw new Error("trycomp_action_authority_changed");
    }
    const plan = freshReviewed.plan;
    const activations = plan.actions.filter(
      (candidate) => candidate.type !== "deactivate",
    ).length;
    const exactAction = plan.actions.some((candidate) =>
      dequal(candidate, action),
    );
    if (
      plan.errors.length > 0 ||
      this.#authorizationErrors(activations, plan).length > 0 ||
      !exactAction
    ) {
      throw new Error("trycomp_action_authority_changed");
    }
  }
}

function reviewedReport(
  reviewed: TrycompReviewedPlan,
  runId: string,
  mode: "audit" | "live",
): TrycompRunReport {
  return {
    applied: [],
    errors: reviewed.plan.errors,
    mode,
    planHash: reviewed.plan.planHash,
    planned: reviewed.plan.actions,
    runId,
    status: reviewed.plan.errors.length > 0 ? "blocked" : "converged",
    warnings: reviewed.plan.warnings,
  };
}

export async function reviewedAuthorityFingerprint(
  authority: TrycompAuthorityInput,
): Promise<string> {
  return contentHash({
    activeGoogleUserCount:
      authority.activeGoogleUserCount ?? authority.googleUsers.length,
    contractorGroup: {
      email: normalizeEmail(authority.contractorGroup.email),
      id: authority.contractorGroup.id,
      members: authority.contractorGroup.members.map((member) => ({
        email: normalizeEmail(member.email),
        id: member.id,
        role: member.role,
        status: member.status,
        type: member.type,
      })),
    },
    googleUsers: authority.googleUsers.map((user) => ({
      ...googleAuthorityFingerprintRecord(user),
      isAdmin: user.isAdmin ?? null,
      isDelegatedAdmin: user.isDelegatedAdmin ?? null,
    })),
  });
}

function selectedMembers(
  actions: readonly TrycompAction[],
  members: readonly TrycompMember[],
  includeDeactivationSafety = false,
): TrycompReviewedMember[] {
  return members
    .filter((member) =>
      actions.some(
        (action) =>
          normalizeEmail(member.user.email) ===
            (action.type === "invite"
              ? action.email
              : (action.providerEmail ?? action.email)) ||
          (action.type !== "invite" && member.id === action.memberId),
      ),
    )
    .map((member) => ({
      deactivated: member.deactivated,
      ...(includeDeactivationSafety && {
        fleetDmLabelId: member.fleetDmLabelId,
        platformRole: member.user.role,
      }),
      email: normalizeEmail(member.user.email),
      id: member.id,
      isActive: member.isActive,
      role: member.role.trim().toLowerCase(),
    }))
    .toSorted(
      (left, right) =>
        left.id.localeCompare(right.id) ||
        left.email.localeCompare(right.email),
    );
}

function reviewedSlice(
  reviewed: TrycompReviewedPlan,
  members: readonly TrycompMember[],
): TrycompReviewedSlice {
  if (reviewed.plan.errors.length > 0) return { state: "drifted" };
  const action = reviewed.plan.actions[0];
  if (action === undefined) return { state: "converged" };
  const current = selectedMembers(
    reviewed.plan.actions,
    members,
    reviewed.deactivationMode === "device-free-membership-revocation",
  );
  const target = current.length === 1 ? current[0] : undefined;
  if (
    target !== undefined &&
    reviewedTargetConverged(action, target, reviewed.deactivationMode)
  )
    return { state: "converged" };
  return {
    state: dequal(current, reviewed.targetBefore) ? "pending" : "drifted",
  };
}

function reviewedTargetConverged(
  action: TrycompAction,
  target: TrycompReviewedMember,
  deactivationMode: TrycompReviewedPlan["deactivationMode"],
): boolean {
  if (target.role !== "employee") return false;
  if (
    deactivationMode === "device-free-membership-revocation" &&
    !hasTrycompDeactivationSafety(target.platformRole, target.fleetDmLabelId)
  )
    return false;
  const sameIdentity =
    action.type === "invite"
      ? target.email === action.email
      : target.id === action.memberId &&
        target.email === (action.providerEmail ?? action.email);
  const sameState =
    action.type === "deactivate"
      ? !target.isActive &&
        (deactivationMode === undefined || target.deactivated)
      : target.isActive && !target.deactivated;
  return sameIdentity && sameState;
}

function actionAuthorityEvidence(
  actions: readonly TrycompAction[],
  googleUsers: readonly GoogleDirectoryUser[],
  contractorGroup: GoogleGroupSnapshot,
): TrycompActionAuthorityEvidence[] {
  const errors: string[] = [];
  const googleByEmail = buildGoogleEmailIndex(googleUsers, errors);
  if (errors.length > 0) throw new Error("trycomp_action_identity_ambiguous");
  return actions.map((action) => ({
    authorityGroupId:
      action.type === "deactivate" &&
      action.deactivationAuthority === "contractor_group"
        ? contractorGroup.id
        : null,
    deactivationAuthority:
      action.type === "deactivate"
        ? (action.deactivationAuthority ?? null)
        : null,
    googleUserId: googleByEmail.get(action.email)?.id ?? null,
  }));
}

function writeProtectedActionEmails(
  config: TrycompPeopleSyncConfig,
  googleUsers: readonly GoogleDirectoryUser[],
): Set<string> {
  const configuredEmails = new Set(
    [
      ...(config.writeProtectedEmails ?? config.protectedEmails ?? []),
      orgSyncSettings().googleAdminSubject,
    ].map(normalizeEmail),
  );
  const configuredIds = new Set(
    config.writeProtectedGoogleUserIds ?? config.protectedGoogleUserIds,
  );
  for (const id of orgSyncSettings().expectedRootGoogleUserIds)
    configuredIds.add(id);
  const protectedEmails = new Set(configuredEmails);
  for (const user of googleUsers) {
    const aliases = [
      user.primaryEmail,
      ...(user.aliases ?? []),
      ...(user.nonEditableAliases ?? []),
    ].map(normalizeEmail);
    const configuredProtection =
      configuredIds.has(user.id) ||
      aliases.some((email) => configuredEmails.has(email));
    const administrator =
      user.isAdmin === true || user.isDelegatedAdmin === true;
    if (!configuredProtection && !administrator) continue;
    for (const email of aliases) protectedEmails.add(email);
  }
  return protectedEmails;
}
