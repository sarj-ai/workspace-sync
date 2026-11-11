import type { D1PreparedStatement } from "@cloudflare/workers-types";
import { dequal } from "dequal";
import { z } from "zod";

import {
  assertTrustedGithubZeroDispatchProof,
  type GithubZeroDispatchProof,
} from "../identity-provisioning/github-organization-api-port.ts";
import { sha256Hex } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import { WORKSPACE_DEPLOYMENT_FENCE_KEY } from "../workspace-directory/workspace-deployment-fence-repository.ts";
import { assertWorkspaceBranchClaimFresh } from "./assert-workspace-branch-claim-fresh.ts";
import {
  type WorkspaceBranchAttempt,
  type WorkspaceBranchAttemptClaim,
  WorkspaceBranchAttemptClaimSchema,
  type WorkspaceBranchAttemptPins,
  WorkspaceBranchAttemptPinsSchema,
  WorkspaceBranchAttemptSchema,
  type WorkspaceBranchAttemptVerification,
  WorkspaceBranchAttemptVerificationSchema,
} from "./branch-attempt-contracts.ts";
import {
  CanaryBranchResolutionStore,
  type CanaryResolutionPins,
} from "./canary-branch-resolution-store.ts";
import type { WorkspaceDirectoryWorkflowResult } from "./contracts.ts";
import { getWorkspaceExecutionPolicy } from "./get-workspace-execution-policy.ts";
import { orderedBranchReceiptSetDigest } from "./ordered-branch-receipt-set-digest.ts";
import {
  isExactAppliedRecoveryReplay,
  reconstructVerifiedFailedWorkflowResult,
} from "./reconstruct-verified-failed-workflow-result.ts";
import {
  RESOLVED_BRANCH_ATTEMPT_CTES_SQL,
  RESOLVED_BRANCH_ATTEMPT_MATCH_SQL,
} from "./resolved-branch-attempt-match-sql.ts";
import {
  reviewedProviderSelection,
  scheduledGoogleCleanupMatchesReviewedIntent,
} from "./reviewed-provider-admission.ts";
import type { ReviewedSlackLifecycleIntent } from "./reviewed-slack-lifecycle-intent.ts";
import {
  WorkspaceScheduleAppliedRecoverySchema,
  type WorkspaceScheduleBlockedReason,
  WorkspaceScheduleBlockedReasonSchema,
  type WorkspaceScheduleExecution,
  type WorkspaceScheduleExecutionManifest,
  WorkspaceScheduleExecutionManifestSchema,
  type WorkspaceScheduleExecutionReceipts,
  WorkspaceScheduleExecutionReceiptsSchema,
  type WorkspaceScheduleOutcome,
  type WorkspaceSchedulePlan,
  WorkspaceSchedulePlanSchema,
  type WorkspaceScheduleReceipt,
  WorkspaceScheduleReceiptSchema,
  type WorkspaceScheduleStart,
  WorkspaceScheduleStartSchema,
  type WorkspaceScheduleTick,
  WorkspaceScheduleTickSchema,
} from "./schedule-health-contracts.ts";
import {
  managedBranchActionId,
  parseSuccessfulWorkflowResult,
  workspaceDirectoryExecutionId,
} from "./workflow.ts";
import type {
  WorkspaceDatabase,
  WorkspaceDatabaseSession,
  WorkspaceStatement,
} from "./workspace-database.ts";
import { workspaceDirectoryAnnouncedChanges } from "./workspace-directory-announced-changes.ts";
function stable(value: WorkspaceScheduleExecutionReceipts) {
  return {
    branchReceipts: value.branchReceipts
      .map((receipt) => ({ ...receipt, verifiedAtMs: 0 }))
      .toSorted((left, right) => left.changeKey.localeCompare(right.changeKey)),
    summaryReceipt: { ...value.summaryReceipt, verifiedAtMs: 0 },
  };
}

const RowSchema = z.strictObject({
  revision: z.number().int().nonnegative(),
  "snapshot_json": z.string(),
});
const DigestSchema = z.string().regex(/^[a-f0-9]{64}$/u);
const CountSchema = z.strictObject({ count: z.number().int().nonnegative() });
const HealthInputSchema = z.strictObject({
  maxAgeMs: z.number().int().positive(),
  nowMs: z.number().int().nonnegative(),
});
const RecoveryBeforeSchema = z.number().int().nonnegative();
const MutationSafetySchema = z.strictObject({
  "breaker_closed": z.number().int().min(0).max(1),
  unresolved: z.number().int().nonnegative(),
});

const COMPLETED_GITHUB_REFUSAL_SQL = `COALESCE((
  json_extract(snapshot_json,'$.phase')='terminal'
  AND json_extract(snapshot_json,'$.outcome')='failed'
  AND json_type(snapshot_json,'$.receipt')='object'
  AND json_extract(snapshot_json,'$.receipt.outcome')='failed'
  AND json_extract(snapshot_json,'$.receipt.planHash')=json_extract(snapshot_json,'$.planHash')
  AND json_extract(snapshot_json,'$.receipt.workflowId')=json_extract(snapshot_json,'$.workflowId')
  AND json_extract(snapshot_json,'$.receipt.tickId')=tick_id
  AND json_extract(snapshot_json,'$.receipt.channelId')=json_extract(snapshot_json,'$.execution.summaryHandle.channelId')
  AND json_extract(snapshot_json,'$.receipt.slackTimestamp')=json_extract(snapshot_json,'$.execution.summaryHandle.timestamp')
  AND json_type(snapshot_json,'$.receipt.verifiedAtMs')='integer'
  AND json_extract(snapshot_json,'$.receipt.verifiedAtMs')>=json_extract(snapshot_json,'$.completedAtMs')
  AND length(json_extract(snapshot_json,'$.receipt.contentHash'))=64
  AND json_extract(snapshot_json,'$.receipt.contentHash') NOT GLOB '*[^a-f0-9]*'
  AND EXISTS (SELECT 1 FROM json_each(snapshot_json,'$.branchAttempts') refusal
    WHERE json_extract(refusal.value,'$.state')='not-dispatched'
      AND json_extract(refusal.value,'$.branchId')='github-access'
      AND json_extract(refusal.value,'$.githubDispatchClaim.protocol')='github-single-operation/v1')
  AND NOT EXISTS (SELECT 1 FROM json_each(snapshot_json,'$.branchAttempts') pending
    WHERE COALESCE(json_extract(pending.value,'$.state'),'') NOT IN ('verified','not-dispatched'))
),0)`;

interface StoredTick {
  revision: number;
  tick: WorkspaceScheduleTick;
}

export interface WorkspaceScheduleHealth {
  healthy: boolean;
  latest: null | WorkspaceScheduleTick;
  mutationSafetyClear: boolean;
  pendingTicks: number;
  scheduleHealthy: boolean;
  unresolvedMutations: number;
}

export class WorkspaceScheduleDeploymentFencedError extends Error {
  constructor() {
    super("workspace_schedule_deployment_fenced");
    this.name = "WorkspaceScheduleDeploymentFencedError";
  }
}

export class WorkspaceScheduleMutationSafetyError extends Error {
  constructor() {
    super("workspace_schedule_mutation_safety_unresolved");
    this.name = "WorkspaceScheduleMutationSafetyError";
  }
}

export const WorkspaceScheduleExecutionIdentitySchema = z.strictObject({
  tickId: DigestSchema.brand<"WorkspaceScheduleTickId">(),
  workflowId: DigestSchema.brand<"WorkspaceWorkflowId">(),
});
export type WorkspaceScheduleExecutionIdentity = z.output<
  typeof WorkspaceScheduleExecutionIdentitySchema
>;
export interface IWorkspaceScheduleHealthRepository {
  attachExecutionReceipts(
    tickId: string,
    receipts: WorkspaceScheduleExecutionReceipts,
  ): Promise<WorkspaceScheduleTick>;
  attachVerifiedReceipt(
    receipt: WorkspaceScheduleReceipt,
  ): Promise<WorkspaceScheduleTick>;
  beginExecution(
    tickId: string,
    manifest: WorkspaceScheduleExecutionManifest,
  ): Promise<WorkspaceScheduleTick>;
  claimBranchAttempt(
    tickId: string,
    input: WorkspaceBranchAttemptClaim,
  ): Promise<WorkspaceBranchAttempt>;
  complete(
    tickId: string,
    outcome: WorkspaceScheduleOutcome,
    blockedReason?: WorkspaceScheduleBlockedReason,
  ): Promise<WorkspaceScheduleTick>;
  completeApplied(
    tickId: string,
    result: WorkspaceDirectoryWorkflowResult,
  ): Promise<WorkspaceScheduleTick>;
  completeFailedBeforePlan(tickId: string): Promise<WorkspaceScheduleTick>;
  completeFailedNoDispatch(
    identity: WorkspaceScheduleExecutionIdentity,
  ): Promise<WorkspaceScheduleTick>;
  health(
    input: z.input<typeof HealthInputSchema>,
  ): Promise<WorkspaceScheduleHealth>;
  launch(
    identity: WorkspaceScheduleExecutionIdentity,
  ): Promise<WorkspaceScheduleTick>;
  listStaleNoDispatchRecoveryCandidates(
    beforeMs: number,
  ): Promise<readonly WorkspaceScheduleTick[]>;
  read(tickId: string): Promise<WorkspaceScheduleTick>;
  readBranchAttempt(
    tickId: string,
    branchId: WorkspaceBranchAttempt["branchId"],
  ): Promise<null | WorkspaceBranchAttempt>;
  readExecution(tickId: string): Promise<null | WorkspaceScheduleExecution>;
  recordGithubNoDispatch(
    tickId: string,
    pins: WorkspaceBranchAttemptPins,
    proof: GithubZeroDispatchProof,
  ): Promise<WorkspaceBranchAttempt>;
  recordPlan(
    tickId: string,
    plan: WorkspaceSchedulePlan,
  ): Promise<WorkspaceScheduleTick>;
  recoverAppliedFromVerifiedAttempts(
    tickId: string,
  ): Promise<WorkspaceScheduleTick>;
  resolveAppliedReviewedIntent(
    intent: ReviewedSlackLifecycleIntent,
  ): Promise<null | WorkspaceScheduleTick>;
  start(input: WorkspaceScheduleStart): Promise<WorkspaceScheduleTick>;
  verifyBranchAttempt(
    tickId: string,
    input: WorkspaceBranchAttemptVerification,
  ): Promise<WorkspaceBranchAttempt>;
}

/** Persists observation, not provider authorization. No method sends a message or mutates a provider. */
export class WorkspaceScheduleHealthRepository<
  Statement extends WorkspaceStatement<Statement> = D1PreparedStatement,
> implements IWorkspaceScheduleHealthRepository {
  readonly #db: WorkspaceDatabaseSession<Statement>;
  readonly #now: () => number;
  readonly #resolutionStore: CanaryBranchResolutionStore<Statement>;

  constructor(
    database: WorkspaceDatabase<Statement>,
    now: () => number = Date.now,
    resolutionPins?: CanaryResolutionPins,
  ) {
    this.#db = database.withSession("first-primary");
    this.#now = now;
    this.#resolutionStore = new CanaryBranchResolutionStore(
      database,
      undefined,
      now,
      resolutionPins,
    );
  }

  async claimBranchAttempt(
    tickId: string,
    raw: WorkspaceBranchAttemptClaim,
  ): Promise<WorkspaceBranchAttempt> {
    const input = WorkspaceBranchAttemptClaimSchema.parse(raw);
    const { params: _params, ...pins } = input;
    const attempt = WorkspaceBranchAttemptSchema.parse({
      ...pins,
      state: "attempted",
      attemptedAtMs: this.#now(),
    });
    // Branches execute concurrently after every announcement is durable. A
    // different branch may therefore win the shared tick-row CAS between our
    // read and write. Re-read only before this branch has any provider
    // permission, prove that the parent pins are unchanged and this branch is
    // still unclaimed, then retry the append. Same-branch retries remain a hard
    // conflict and nothing is retried after provider dispatch.
    return this.#claimBranchAttempt(
      tickId,
      input,
      attempt,
      await sha256Hex(JsonValueSchema.parse(input.params)),
      input.params.plan.branches.length * 2,
    );
  }

  async recordGithubNoDispatch(
    tickId: string,
    raw: WorkspaceBranchAttemptPins,
    proof: GithubZeroDispatchProof,
  ): Promise<WorkspaceBranchAttempt> {
    assertTrustedGithubZeroDispatchProof(proof);
    const pins = WorkspaceBranchAttemptPinsSchema.parse(raw);
    return this.#recordGithubNoDispatch(tickId, pins, proof, 4);
  }

  async verifyBranchAttempt(
    tickId: string,
    raw: WorkspaceBranchAttemptVerification,
  ): Promise<WorkspaceBranchAttempt> {
    const input = WorkspaceBranchAttemptVerificationSchema.parse(raw);
    const stored = await this.#read(tickId);
    const branchCount = stored.tick.execution?.params.plan.branches.length;
    if (branchCount === undefined) throw conflict();
    return this.#verifyBranchAttempt(tickId, input, branchCount * 2);
  }

  async readBranchAttempt(
    tickId: string,
    branchId: WorkspaceBranchAttempt["branchId"],
  ): Promise<null | WorkspaceBranchAttempt> {
    const stored = await this.#read(tickId);
    return (
      stored.tick.branchAttempts?.find(
        (attempt) => attempt.branchId === branchId,
      ) ?? null
    );
  }

  async start(raw: WorkspaceScheduleStart): Promise<WorkspaceScheduleTick> {
    const input = WorkspaceScheduleStartSchema.parse(raw);
    const startedAtMs = this.#now();
    // Resolution metadata is only an exclusion from the unresolved-attempt
    // guard below. If its immutable evidence cannot be revalidated, omit the
    // exclusion and let the atomic SQL admission check fail closed. Do not let
    // malformed historical evidence crash cron before a tick can be recorded.
    const resolution = await this.#resolutionStore
      .readForHealth()
      .catch(() => null);
    const resolutionTick = resolution?.tick.tickId ?? "";
    const resolutionHash = resolution?.sourceHash ?? "";
    const tickId = await sha256Hex({
      kind: "workspace-directory-scheduled-tick/v1",
      scheduledAtMs: input.scheduledAtMs,
      workerVersionId: input.deployment.id,
    });
    const tick = WorkspaceScheduleTickSchema.parse({
      ...input,
      phase: "started",
      startedAtMs,
      tickId,
    });
    const inserted = await this.#db
      .prepare(
        `WITH ${RESOLVED_BRANCH_ATTEMPT_CTES_SQL}
       INSERT INTO workspace_directory_schedule_tick
       (tick_id, scheduled_at_ms, worker_version_id, worker_revision, revision, snapshot_json)
       SELECT ?4, ?5, ?6, ?7, 0, ?8
       WHERE NOT EXISTS (
         SELECT 1 FROM workspace_directory_schedule_tick WHERE tick_id = ?4
       ) AND NOT EXISTS (
         SELECT 1 FROM automation_singleton_lease
         WHERE lease_key = ?9 AND expires_at_ms > ?10
       ) AND EXISTS (
         SELECT 1 FROM trycomp_sync_breaker
         WHERE breaker_key = 'org-sync/trycomp-people' AND state = 'closed'
       ) AND NOT EXISTS (SELECT 1 FROM google_identity_attestation WHERE kind IS NULL) AND NOT EXISTS (
         SELECT 1 FROM trycomp_unresolved_mutation
       ) AND NOT EXISTS (
         SELECT 1 FROM workspace_directory_schedule_tick, json_each(snapshot_json, '$.branchAttempts')
         WHERE json_extract(json_each.value, '$.state') = 'attempted'
           AND NOT ${RESOLVED_BRANCH_ATTEMPT_MATCH_SQL}
       ) AND NOT EXISTS (
         SELECT 1 FROM workspace_directory_schedule_tick
         WHERE EXISTS (SELECT 1 FROM json_each(snapshot_json,'$.branchAttempts')
           WHERE json_extract(value,'$.state')='not-dispatched')
           AND NOT ${COMPLETED_GITHUB_REFUSAL_SQL}
       ) ON CONFLICT(tick_id) DO NOTHING`,
      )
      .bind(
        resolutionTick,
        resolutionHash,
        getWorkspaceExecutionPolicy().legacyCanaryResolution.evidenceId,
        tickId,
        input.scheduledAtMs,
        input.deployment.id,
        input.deployment.revision,
        JSON.stringify(tick),
        WORKSPACE_DEPLOYMENT_FENCE_KEY,
        startedAtMs,
      )
      .run();
    if (inserted.meta.changes === 0) {
      const existing = await this.#db
        .prepare(
          "SELECT tick_id FROM workspace_directory_schedule_tick WHERE tick_id = ?1",
        )
        .bind(tickId)
        .first();
      if (existing === null) {
        const fence = await this.#db
          .prepare(
            `SELECT 1 FROM automation_singleton_lease
             WHERE lease_key = ?1 AND expires_at_ms > ?2`,
          )
          .bind(WORKSPACE_DEPLOYMENT_FENCE_KEY, startedAtMs)
          .first();
        if (fence !== null) throw new WorkspaceScheduleDeploymentFencedError();
        throw new WorkspaceScheduleMutationSafetyError();
      }
    }
    const stored = await this.#read(tickId);
    if (!dequal(stored.tick.deployment, input.deployment)) throw conflict();
    return stored.tick;
  }

  async recordPlan(
    tickId: string,
    raw: WorkspaceSchedulePlan,
  ): Promise<WorkspaceScheduleTick> {
    const plan = WorkspaceSchedulePlanSchema.parse(raw);
    const stored = await this.#read(tickId);
    if (stored.tick.phase !== "started") {
      if (
        stored.tick.planHash !== plan.planHash ||
        stored.tick.mode !== plan.mode ||
        !notificationPolicyMatches(stored.tick, plan)
      )
        throw conflict();
      return stored.tick;
    }
    return this.#write(stored, { ...stored.tick, ...plan, phase: "planned" });
  }

  async launch(
    identity: WorkspaceScheduleExecutionIdentity,
  ): Promise<WorkspaceScheduleTick> {
    const { tickId, workflowId } =
      WorkspaceScheduleExecutionIdentitySchema.parse(identity);
    const stored = await this.#read(tickId);
    if (stored.tick.phase === "launched" || stored.tick.phase === "terminal") {
      if (stored.tick.workflowId !== workflowId) throw conflict();
      return stored.tick;
    }
    if (stored.tick.phase !== "planned" || stored.tick.mode !== "live")
      throw conflict();
    return this.#write(stored, {
      ...stored.tick,
      phase: "launched",
      workflowId,
    });
  }

  async complete(
    tickId: string,
    outcome: WorkspaceScheduleOutcome,
    blockedReason?: WorkspaceScheduleBlockedReason,
  ): Promise<WorkspaceScheduleTick> {
    if (blockedReason !== undefined) {
      WorkspaceScheduleBlockedReasonSchema.parse(blockedReason);
      if (outcome !== "blocked") throw conflict();
    }
    return this.#complete(
      tickId,
      outcome,
      outcome === "failed" ? 3 : 0,
      blockedReason,
    );
  }

  /* A successful return is the only initial-dispatch permission; even identical retries fail closed. */
  async beginExecution(
    tickId: string,
    raw: WorkspaceScheduleExecutionManifest,
  ): Promise<WorkspaceScheduleTick> {
    const manifest = WorkspaceScheduleExecutionManifestSchema.parse(raw);
    const stored = await this.#read(tickId);
    const tick = stored.tick;
    if (
      tick.phase !== "launched" ||
      tick.execution !== undefined ||
      manifest.params.scheduledTickId !== tickId ||
      manifest.params.planHash !== tick.planHash ||
      manifest.params.requestedBy !== "scheduled:workspace-directory" ||
      (await workspaceDirectoryExecutionId(manifest.params)) !== tick.workflowId
    )
      throw conflict();
    assertExactManifest(manifest);
    return this.#write(stored, {
      ...tick,
      execution: {
        ...manifest,
        version: "workspace-receipt-recovery/v1",
        paramsDigest: await sha256Hex(JsonValueSchema.parse(manifest.params)),
        startedAtMs: this.#now(),
        result: null,
      },
    });
  }

  /* The exact successful result and applied outcome become durable in one revision-fenced update. */
  async completeApplied(
    tickId: string,
    raw: WorkspaceDirectoryWorkflowResult,
  ): Promise<WorkspaceScheduleTick> {
    const stored = await this.#read(tickId);
    const tick = stored.tick;
    const execution = tick.execution;
    if (
      execution === undefined ||
      (tick.phase !== "launched" && tick.phase !== "terminal") ||
      tick.workflowId === null
    )
      throw conflict();
    const { params } = execution;
    const result = parseSuccessfulWorkflowResult(
      raw,
      params.plan,
      params.planHash,
      tick.workflowId,
      params.authorizedActionIds,
    );
    if (result === null) throw conflict();
    if (tick.phase === "terminal") {
      if (tick.outcome !== "applied" || !dequal(execution.result, result))
        throw conflict();
      return tick;
    }
    return this.#write(stored, {
      ...tick,
      phase: "terminal",
      outcome: "applied",
      completedAtMs: this.#now(),
      notificationRequired: true,
      receipt: null,
      execution: { ...execution, result },
    });
  }

  /* Atomically repairs only a fully verified failed execution; it never calls a provider. */
  async recoverAppliedFromVerifiedAttempts(
    tickId: string,
  ): Promise<WorkspaceScheduleTick> {
    const stored = await this.#read(tickId);
    if (await isExactAppliedRecoveryReplay(stored.tick)) return stored.tick;

    let result: WorkspaceDirectoryWorkflowResult;
    try {
      result = await reconstructVerifiedFailedWorkflowResult(stored.tick);
    } catch (cause) {
      throw conflict(cause);
    }
    if (stored.tick.phase !== "terminal" || stored.tick.execution === undefined)
      throw conflict();
    const completedAtMs = this.#now();
    const parsedRecovery = WorkspaceScheduleAppliedRecoverySchema.safeParse({
      priorCompletedAtMs: stored.tick.completedAtMs,
      priorOutcome: "failed",
      priorReceipt: stored.tick.receipt,
      recoveredAtMs: completedAtMs,
      version: "workspace-verified-attempt-result-recovery/v1",
    });
    if (!parsedRecovery.success) throw conflict(parsedRecovery.error);
    if (completedAtMs < stored.tick.completedAtMs) throw conflict();
    const recovery = parsedRecovery.data;
    const { executionReceipts: _receipts, ...failed } = stored.tick;
    try {
      return await this.#write(stored, {
        ...failed,
        completedAtMs,
        execution: { ...stored.tick.execution, result },
        outcome: "applied",
        receipt: null,
        recovery,
      });
    } catch (error) {
      if (!isTransitionConflict(error)) throw error;
      const replay = await this.#read(tickId);
      if (await isExactAppliedRecoveryReplay(replay.tick)) return replay.tick;
      throw error;
    }
  }

  async readExecution(
    tickId: string,
  ): Promise<null | WorkspaceScheduleExecution> {
    const stored = await this.#read(tickId);
    return stored.tick.execution ?? null;
  }

  async completeFailedBeforePlan(
    tickId: string,
  ): Promise<WorkspaceScheduleTick> {
    const stored = await this.#read(tickId);
    const tick = stored.tick;
    if (
      tick.phase !== "started" ||
      tick.execution !== undefined ||
      (tick.branchAttempts?.length ?? 0) !== 0
    )
      throw conflict();
    return this.#write(stored, {
      ...tick,
      completedAtMs: this.#now(),
      mode: null,
      notificationRequired: true,
      outcome: "failed",
      phase: "terminal",
      planHash: null,
      receipt: null,
      workflowId: null,
    });
  }

  async completeFailedNoDispatch(
    identity: WorkspaceScheduleExecutionIdentity,
  ): Promise<WorkspaceScheduleTick> {
    const { tickId, workflowId } =
      WorkspaceScheduleExecutionIdentitySchema.parse(identity);
    const stored = await this.#read(tickId);
    const tick = stored.tick;
    if (
      tick.phase !== "launched" ||
      tick.workflowId !== workflowId ||
      tick.execution !== undefined ||
      (tick.branchAttempts?.length ?? 0) !== 0
    )
      throw conflict();
    return this.#write(stored, {
      ...tick,
      completedAtMs: this.#now(),
      notificationRequired: true,
      outcome: "failed",
      phase: "terminal",
      receipt: null,
    });
  }

  async listStaleNoDispatchRecoveryCandidates(
    beforeMs: number,
  ): Promise<readonly WorkspaceScheduleTick[]> {
    RecoveryBeforeSchema.parse(beforeMs);
    const rows = await this.#db
      .prepare(
        `SELECT revision, snapshot_json FROM workspace_directory_schedule_tick
         WHERE scheduled_at_ms < ?1
           AND json_type(snapshot_json, '$.execution') IS NULL
           AND NOT EXISTS (SELECT 1 FROM json_each(snapshot_json, '$.branchAttempts'))
           AND ((json_extract(snapshot_json, '$.phase') = 'started')
             OR (json_extract(snapshot_json, '$.phase') = 'launched')
             OR (json_extract(snapshot_json, '$.phase') = 'terminal'
               AND json_extract(snapshot_json, '$.notificationRequired') = 1
               AND ((json_extract(snapshot_json, '$.outcome') = 'failed'
                   AND json_type(snapshot_json, '$.workflowId') = 'text')
                 OR (json_type(snapshot_json, '$.workflowId') = 'null'
                   AND json_extract(snapshot_json, '$.outcome') IN ('failed', 'blocked', 'audit-only', 'no-op')))
               AND json_type(snapshot_json, '$.receipt') = 'null'))
         ORDER BY scheduled_at_ms ASC, tick_id ASC LIMIT 10`,
      )
      .bind(beforeMs)
      .all();
    const ticks: WorkspaceScheduleTick[] = [];
    for (const row of rows.results) {
      // eslint-disable-next-line no-await-in-loop -- every immutable candidate is independently validated.
      const stored = await this.#validateStored(parseRow(row));
      if (
        stored.tick.execution !== undefined ||
        (stored.tick.branchAttempts?.length ?? 0) !== 0 ||
        (stored.tick.phase !== "started" &&
          stored.tick.phase !== "launched" &&
          !(
            stored.tick.phase === "terminal" &&
            stored.tick.outcome !== "applied" &&
            stored.tick.notificationRequired &&
            (stored.tick.workflowId === null ||
              stored.tick.outcome === "failed") &&
            stored.tick.receipt === null
          ))
      )
        throw conflict();
      ticks.push(stored.tick);
    }
    return ticks;
  }

  /*
   * Resolves the narrow admission/scheduler race where a primary-safe
   * scheduled Google cleanup independently applied the exact reviewed action
   * before the scheduled claim observed the newly admitted intent. This is a
   * read-only projection over durable terminal evidence; it never claims an
   * intent or grants provider authority.
   */
  async resolveAppliedReviewedIntent(
    intent: ReviewedSlackLifecycleIntent,
  ): Promise<null | WorkspaceScheduleTick> {
    if (
      !("provider" in intent.proof) ||
      intent.proof.provider !== "google-group-cleanup"
    )
      return null;
    const rows = await this.#db
      .prepare(
        `SELECT revision, snapshot_json FROM workspace_directory_schedule_tick
         WHERE scheduled_at_ms >= ?1 AND scheduled_at_ms < ?2
           AND json_extract(snapshot_json, '$.phase') = 'terminal'
           AND json_extract(snapshot_json, '$.outcome') = 'applied'
           AND json_extract(snapshot_json, '$.completedAtMs') <= ?2
           AND json_type(snapshot_json, '$.execution.result') = 'object'
           AND json_type(snapshot_json, '$.executionReceipts') = 'object'
         ORDER BY scheduled_at_ms ASC, tick_id ASC LIMIT 10`,
      )
      .bind(intent.proof.generatedAtMs, intent.proof.expiresAtMs)
      .all();
    const expectedActionId = reviewedProviderSelection(intent.proof).actionId;
    const candidates = await Promise.all(
      rows.results.map(async (row) => {
        const { tick } = await this.#validateStored(parseRow(row));
        const result = tick.execution?.result;
        if (
          tick.phase !== "terminal" ||
          tick.outcome !== "applied" ||
          tick.execution === undefined ||
          result === null ||
          result === undefined ||
          tick.executionReceipts === undefined ||
          result.authorizedActionIds.length !== 1 ||
          result.authorizedActionIds[0] !== expectedActionId ||
          !result.branches.some(
            ({ branchId, state }) =>
              branchId === "google-group-cleanup" && state === "applied",
          ) ||
          !(await scheduledGoogleCleanupMatchesReviewedIntent(
            intent.proof,
            tick.execution.params.plan,
          ))
        )
          return null;
        return tick;
      }),
    );
    return candidates.find((tick) => tick !== null) ?? null;
  }

  async attachVerifiedReceipt(
    raw: WorkspaceScheduleReceipt,
  ): Promise<WorkspaceScheduleTick> {
    const receipt = WorkspaceScheduleReceiptSchema.parse(raw);
    const stored = await this.#read(receipt.tickId);
    if (
      stored.tick.execution !== undefined &&
      stored.tick.phase === "terminal" &&
      stored.tick.outcome === "applied"
    )
      throw conflict();
    if (stored.tick.phase !== "terminal" || receipt.verifiedAtMs > this.#now())
      throw conflict();
    WorkspaceScheduleTickSchema.parse({ ...stored.tick, receipt });
    if (stored.tick.receipt !== null) {
      if (
        !dequal(stored.tick.receipt, {
          ...receipt,
          verifiedAtMs: stored.tick.receipt.verifiedAtMs,
        })
      )
        throw conflict();
      return stored.tick;
    }
    return this.#write(stored, { ...stored.tick, receipt });
  }

  async attachExecutionReceipts(
    tickId: string,
    raw: WorkspaceScheduleExecutionReceipts,
  ): Promise<WorkspaceScheduleTick> {
    const receipts = WorkspaceScheduleExecutionReceiptsSchema.parse(raw);
    const stored = await this.#read(tickId);
    const tick = stored.tick;
    if (
      tick.phase !== "terminal" ||
      tick.outcome !== "applied" ||
      tick.execution?.result === null ||
      tick.execution === undefined ||
      receipts.summaryReceipt.tickId !== tickId ||
      receipts.summaryReceipt.verifiedAtMs > this.#now() ||
      receipts.summaryReceipt.slackTimestamp !==
        tick.execution.summaryHandle.timestamp
    )
      throw conflict();
    const manifest = tick.execution.branchHandles;
    if (receipts.branchReceipts.length !== manifest.length) throw conflict();
    const seen = new Set<string>();
    for (const receipt of receipts.branchReceipts) {
      const original = manifest.find(
        ({ branchId, handle }) =>
          branchId === receipt.branchId &&
          handle.changeKey === receipt.changeKey,
      );
      if (
        original === undefined ||
        seen.has(receipt.changeKey) ||
        receipt.timestamp !== original.handle.timestamp ||
        receipt.verifiedAtMs < tick.completedAtMs ||
        receipt.verifiedAtMs > this.#now()
      )
        throw conflict();
      seen.add(receipt.changeKey);
    }
    WorkspaceScheduleTickSchema.parse({
      ...tick,
      receipt: receipts.summaryReceipt,
      executionReceipts: receipts,
    });
    if (tick.executionReceipts !== undefined) {
      if (!dequal(stable(tick.executionReceipts), stable(receipts)))
        throw conflict();
      return tick;
    }
    return this.#write(stored, {
      ...tick,
      receipt: receipts.summaryReceipt,
      executionReceipts: receipts,
    });
  }

  async read(tickId: string): Promise<WorkspaceScheduleTick> {
    const stored = await this.#read(tickId);
    return stored.tick;
  }

  async health(raw: z.input<typeof HealthInputSchema>) {
    const input = HealthInputSchema.parse(raw);
    // A historical incident resolution is only an exclusion from the unresolved
    // mutation count. If its immutable evidence can no longer be revalidated,
    // fail closed by counting the attempt as unresolved instead of making the
    // entire status endpoint unavailable. This preserves the write safety
    // boundary while keeping operators able to observe and repair the debt.
    const resolution = await this.#resolutionStore
      .readForHealth()
      .catch(() => null);
    const resolutionTick = resolution?.tick.tickId ?? "";
    const resolutionHash = resolution?.sourceHash ?? "";
    const [latestRows, pendingRows, safetyRows] = await this.#db.batch([
      this.#db.prepare(
        `SELECT revision, snapshot_json FROM workspace_directory_schedule_tick
         ORDER BY scheduled_at_ms DESC, tick_id DESC LIMIT 1`,
      ),
      this.#db
        .prepare(
          `WITH ${RESOLVED_BRANCH_ATTEMPT_CTES_SQL}
         SELECT COUNT(*) AS count FROM workspace_directory_schedule_tick
         WHERE json_extract(snapshot_json, '$.phase') != 'terminal'
           OR (json_extract(snapshot_json, '$.notificationRequired') = 1
               AND json_type(snapshot_json, '$.receipt') = 'null')
           OR (NOT ${RESOLVED_BRANCH_ATTEMPT_MATCH_SQL} AND (
             EXISTS (SELECT 1 FROM json_each(snapshot_json, '$.branchAttempts')
               WHERE json_extract(value, '$.state') = 'attempted')
             OR (json_extract(snapshot_json, '$.phase') = 'terminal'
               AND json_extract(snapshot_json, '$.outcome') = 'failed'
               AND json_type(snapshot_json, '$.execution') = 'object'
               AND json_type(snapshot_json, '$.execution.result') = 'null'
               AND EXISTS (SELECT 1 FROM json_each(snapshot_json, '$.branchAttempts'))
               AND NOT ${COMPLETED_GITHUB_REFUSAL_SQL})))`,
        )
        .bind(
          resolutionTick,
          resolutionHash,
          getWorkspaceExecutionPolicy().legacyCanaryResolution.evidenceId,
        ),
      this.#db
        .prepare(
          `WITH ${RESOLVED_BRANCH_ATTEMPT_CTES_SQL} SELECT
         (SELECT COUNT(*) FROM google_identity_attestation WHERE kind IS NULL) +
         (SELECT COUNT(*) FROM trycomp_unresolved_mutation) +
         (SELECT COUNT(*) FROM workspace_directory_schedule_tick, json_each(snapshot_json, '$.branchAttempts')
          WHERE json_extract(json_each.value, '$.state') = 'attempted' AND NOT ${RESOLVED_BRANCH_ATTEMPT_MATCH_SQL}) AS unresolved,
         (SELECT COUNT(*) FROM trycomp_sync_breaker
          WHERE breaker_key = 'org-sync/trycomp-people' AND state = 'closed') AS breaker_closed`,
        )
        .bind(
          resolutionTick,
          resolutionHash,
          getWorkspaceExecutionPolicy().legacyCanaryResolution.evidenceId,
        ),
    ]);
    const latestRow = latestRows?.results[0];
    const latestStored =
      latestRow === undefined
        ? null
        : await this.#validateStored(parseRow(latestRow));
    const latest = latestStored?.tick ?? null;
    const pending = CountSchema.parse(pendingRows?.results[0]).count;
    const safety = MutationSafetySchema.parse(safetyRows?.results[0]);
    const fresh =
      latest !== null &&
      latest.scheduledAtMs <= input.nowMs &&
      latest.scheduledAtMs >= Math.max(0, input.nowMs - input.maxAgeMs);
    const scheduleHealthy =
      fresh &&
      pending === 0 &&
      latest.phase === "terminal" &&
      latest.completedAtMs <= input.nowMs &&
      (latest.receipt === null || latest.receipt.verifiedAtMs <= input.nowMs) &&
      (latest.outcome === "applied" ||
        latest.outcome === "audit-only" ||
        latest.outcome === "no-op");
    const mutationSafetyClear =
      safety["breaker_closed"] === 1 && safety.unresolved === 0;
    return {
      healthy: scheduleHealthy && mutationSafetyClear,
      latest,
      mutationSafetyClear,
      pendingTicks: pending,
      scheduleHealthy,
      unresolvedMutations: safety.unresolved,
    };
  }

  async #recordGithubNoDispatch(
    tickId: string,
    pins: WorkspaceBranchAttemptPins,
    proof: GithubZeroDispatchProof,
    retries: number,
  ): Promise<WorkspaceBranchAttempt> {
    const stored = await this.#read(tickId);
    const attempt = stored.tick.branchAttempts?.find(
      (item) => item.branchId === pins.branchId,
    );
    if (
      attempt === undefined ||
      !dequal(WorkspaceBranchAttemptPinsSchema.strip().parse(attempt), pins) ||
      !dequal(attempt.githubDispatchClaim, proof.claim)
    )
      throw conflict();
    await assertGithubRefusalOperation(stored.tick.execution, proof);
    if (attempt.state === "not-dispatched") {
      if (
        attempt.refusal.category !== proof.category ||
        attempt.refusal.operationHash !== proof.claim.operationHash
      )
        throw conflict();
      return attempt;
    }
    if (attempt.state !== "attempted" || stored.tick.phase !== "launched")
      throw conflict();
    const refused = WorkspaceBranchAttemptSchema.parse({
      ...attempt,
      state: "not-dispatched",
      refusal: {
        category: proof.category,
        operationHash: proof.claim.operationHash,
        recordedAtMs: this.#now(),
      },
    });
    try {
      await this.#write(stored, {
        ...stored.tick,
        branchAttempts: stored.tick.branchAttempts?.map((item) =>
          item.branchId === pins.branchId ? refused : item,
        ),
      });
      return refused;
    } catch (error) {
      const current = await this.#read(tickId);
      const replay = current.tick.branchAttempts?.find(
        (item) => item.branchId === pins.branchId,
      );
      if (replay !== undefined && dequal(replay, refused)) return replay;
      if (!isTransitionConflict(error) || retries === 0) throw error;
      return this.#recordGithubNoDispatch(tickId, pins, proof, retries - 1);
    }
  }

  async #complete(
    tickId: string,
    outcome: WorkspaceScheduleOutcome,
    retriesRemaining: number,
    blockedReason?: WorkspaceScheduleBlockedReason,
  ): Promise<WorkspaceScheduleTick> {
    const stored = await this.#read(tickId);
    const tick = stored.tick;
    if (tick.execution !== undefined && outcome !== "failed") throw conflict();
    if (tick.phase === "terminal") {
      assertTerminalCompletionMatches(tick, outcome, blockedReason);
      return tick;
    }
    assertCompletionAllowed(tick, outcome);
    try {
      return await this.#write(stored, {
        deployment: tick.deployment,
        scheduledAtMs: tick.scheduledAtMs,
        startedAtMs: tick.startedAtMs,
        tickId,
        completedAtMs: this.#now(),
        mode: tick.phase === "started" ? null : tick.mode,
        notificationRequired:
          tick.phase === "started" ||
          tick.notificationRequired ||
          ["applied", "blocked", "failed"].includes(outcome),
        outcome,
        ...(!(blockedReason === undefined) && { blockedReason }),
        phase: "terminal",
        planHash: tick.phase === "started" ? null : tick.planHash,
        receipt: null,
        workflowId: tick.phase === "launched" ? tick.workflowId : null,
        ...(!(tick.execution === undefined) && { execution: tick.execution }),
        ...(!(tick.branchAttempts === undefined) && {
          branchAttempts: tick.branchAttempts,
        }),
      });
    } catch (error) {
      if (!isTransitionConflict(error) || retriesRemaining === 0) throw error;
      return this.#complete(
        tickId,
        outcome,
        retriesRemaining - 1,
        blockedReason,
      );
    }
  }

  async #claimBranchAttempt(
    tickId: string,
    input: WorkspaceBranchAttemptClaim,
    attempt: WorkspaceBranchAttempt,
    expectedParamsDigest: string,
    retriesRemaining: number,
  ): Promise<WorkspaceBranchAttempt> {
    const stored = await this.#read(tickId);
    const { tick } = stored;
    if (
      tick.phase !== "launched" ||
      tick.execution === undefined ||
      input.params.scheduledTickId !== tickId ||
      input.params.requestedBy !== "scheduled:workspace-directory" ||
      input.paramsDigest !== expectedParamsDigest ||
      input.paramsDigest !== tick.execution.paramsDigest ||
      !(await branchAttemptReceiptsMatch(input, tick.execution)) ||
      tick.branchAttempts?.some(({ branchId }) => branchId === input.branchId)
    )
      throw conflict();
    await validateGithubDispatchClaim(attempt, tick.execution);
    assertWorkspaceBranchClaimFresh(input.params, this.#now());
    try {
      await this.#write(stored, {
        ...tick,
        branchAttempts: [...(tick.branchAttempts ?? []), attempt],
      });
      return attempt;
    } catch (error) {
      if (!isTransitionConflict(error) || retriesRemaining === 0) throw error;
      return this.#claimBranchAttempt(
        tickId,
        input,
        attempt,
        expectedParamsDigest,
        retriesRemaining - 1,
      );
    }
  }

  async #read(tickId: string): Promise<StoredTick> {
    DigestSchema.parse(tickId);
    const row = await this.#db
      .prepare(
        "SELECT revision, snapshot_json FROM workspace_directory_schedule_tick WHERE tick_id = ?1",
      )
      .bind(tickId)
      .first();
    if (row === null) throw new Error("workspace_schedule_tick_missing");
    const stored = parseRow(row);
    if (stored.tick.tickId !== tickId) throw conflict();
    return this.#validateStored(stored);
  }

  async #validateStored(stored: StoredTick): Promise<StoredTick> {
    const execution = stored.tick.execution;
    if (execution !== undefined) await validateStoredExecution(stored);
    return stored;
  }

  async #verifyBranchAttempt(
    tickId: string,
    input: WorkspaceBranchAttemptVerification,
    retriesRemaining: number,
  ): Promise<WorkspaceBranchAttempt> {
    const stored = await this.#read(tickId);
    const { tick } = stored;
    const attempt = tick.branchAttempts?.find(
      ({ branchId }) => branchId === input.branchId,
    );
    if (
      attempt === undefined ||
      attempt.state === "not-dispatched" ||
      !sameAttemptPins(attempt, input) ||
      !dequal(attempt.githubDispatchClaim, input.githubDispatchClaim)
    )
      throw conflict();
    const replay = verifiedAttemptReplay(attempt, input);
    if (replay !== null) return replay;
    if (tick.phase !== "launched" || tick.execution === undefined)
      throw conflict();
    const verified = WorkspaceBranchAttemptSchema.parse({
      ...input,
      state: "verified",
      attemptedAtMs: attempt.attemptedAtMs,
      verifiedAtMs: this.#now(),
    });
    if (await this.#tryWriteVerifiedAttempt(stored, input.branchId, verified))
      return verified;
    if (retriesRemaining === 0) throw conflict();
    return this.#verifyBranchAttempt(tickId, input, retriesRemaining - 1);
  }

  async #tryWriteVerifiedAttempt(
    stored: StoredTick,
    branchId: WorkspaceBranchAttempt["branchId"],
    verified: WorkspaceBranchAttempt,
  ): Promise<boolean> {
    try {
      await this.#write(stored, {
        ...stored.tick,
        branchAttempts: stored.tick.branchAttempts?.map((candidate) =>
          candidate.branchId === branchId ? verified : candidate,
        ),
      });
      return true;
    } catch (error) {
      if (!isTransitionConflict(error)) throw error;
      return false;
    }
  }

  async #write(
    stored: StoredTick,
    raw: unknown,
  ): Promise<WorkspaceScheduleTick> {
    const tick = WorkspaceScheduleTickSchema.parse(raw);
    const result = await this.#db
      .prepare(
        `UPDATE workspace_directory_schedule_tick SET snapshot_json = ?1, revision = revision + 1
       WHERE tick_id = ?2 AND revision = ?3`,
      )
      .bind(JSON.stringify(tick), tick.tickId, stored.revision)
      .run();
    if (result.meta.changes !== 1) throw conflict();
    return tick;
  }
}

async function assertGithubRefusalOperation(
  execution: undefined | WorkspaceScheduleExecution,
  proof: GithubZeroDispatchProof,
): Promise<void> {
  const operation = execution?.params.plan.branches[3];
  if (
    operation?.execution !== "managed" ||
    operation.selectedOperation === null ||
    !dequal(operation.selectedOperation.operation, proof.operation) ||
    (await sha256Hex(JsonValueSchema.parse(proof.operation))) !==
      proof.claim.operationHash
  )
    throw conflict();
}

async function validateStoredExecution(stored: StoredTick): Promise<void> {
  const execution = stored.tick.execution;
  if (execution === undefined) return;
  if (
    (await sha256Hex(JsonValueSchema.parse(execution.params))) !==
    execution.paramsDigest
  )
    throw conflict();
  if (stored.tick.branchAttempts) {
    for (const attempt of stored.tick.branchAttempts) {
      // eslint-disable-next-line no-await-in-loop -- Every stored attempt must bind its exact original receipt set.
      if (!(await branchAttemptReceiptsMatch(attempt, execution)))
        throw conflict();
      // eslint-disable-next-line no-await-in-loop -- Each protocol claim must bind its exact signed operation.
      await validateGithubDispatchClaim(attempt, execution);
    }
  }
  if (
    (stored.tick.phase !== "launched" && stored.tick.phase !== "terminal") ||
    (await workspaceDirectoryExecutionId(execution.params)) !==
      stored.tick.workflowId
  )
    throw conflict();
  assertExactManifest(execution);
}

async function validateGithubDispatchClaim(
  attempt: WorkspaceBranchAttempt,
  execution: WorkspaceScheduleExecution,
): Promise<void> {
  if (attempt.githubDispatchClaim !== undefined) {
    const branch = execution.params.plan.branches[3];
    if (
      branch.execution !== "managed" ||
      branch.selectedOperation === null ||
      (await sha256Hex(
        JsonValueSchema.parse(branch.selectedOperation.operation),
      )) !== attempt.githubDispatchClaim.operationHash
    )
      throw conflict();
  }
}

async function branchAttemptReceiptsMatch(
  attempt: Pick<
    WorkspaceBranchAttempt,
    "branchId" | "changeKey" | "changeSetDigest"
  >,
  execution: WorkspaceScheduleExecution,
): Promise<boolean> {
  const handles = execution.branchHandles.filter(
    ({ branchId }) => branchId === attempt.branchId,
  );
  const first = handles[0];
  if (first?.change.changeKey !== attempt.changeKey) return false;
  if (handles.length === 1) return attempt.changeSetDigest === undefined;
  return (
    attempt.changeSetDigest === (await orderedBranchReceiptSetDigest(handles))
  );
}
function sameAttemptPins(
  left: WorkspaceBranchAttempt,
  right: WorkspaceBranchAttemptVerification,
): boolean {
  const pins = WorkspaceBranchAttemptPinsSchema.strip();
  return dequal(pins.parse(left), pins.parse(right));
}

function assertExactManifest(
  manifest: WorkspaceScheduleExecutionManifest,
): void {
  const { params, summaryHandle, branchHandles } = manifest;
  if (
    summaryHandle.changeKey !==
    `${params.planHash}:plan-apply-summary:${String(Date.parse(params.planGeneratedAt))}`
  )
    throw conflict();
  const authorized = new Set(params.authorizedActionIds);
  const expected = params.plan.branches.flatMap((branch) => {
    const actionId = managedBranchActionId(branch.branchId);
    return actionId !== null && authorized.has(actionId)
      ? workspaceDirectoryAnnouncedChanges(params.plan, branch.branchId).map(
          (change) => ({
            branchId: branch.branchId,
            change,
          }),
        )
      : [];
  });
  if (branchHandles.length !== expected.length) throw conflict();
  const keys = new Set<string>();
  const timestamps = new Set([summaryHandle.timestamp]);
  for (const entry of branchHandles) {
    const match = expected.find(
      (candidate) =>
        candidate.branchId === entry.branchId &&
        candidate.change.changeKey === entry.change.changeKey,
    );
    if (
      match === undefined ||
      !dequal(match.change, entry.change) ||
      entry.handle.changeKey !==
        `${params.planHash}:${entry.change.changeKey}` ||
      keys.has(entry.handle.changeKey) ||
      timestamps.has(entry.handle.timestamp)
    )
      throw conflict();
    keys.add(entry.handle.changeKey);
    timestamps.add(entry.handle.timestamp);
  }
}

function parseRow(raw: unknown): StoredTick {
  const row = RowSchema.parse(raw);
  return {
    revision: row.revision,
    tick: WorkspaceScheduleTickSchema.parse(JSON.parse(row["snapshot_json"])),
  };
}

function conflict(cause?: unknown): Error {
  return new Error("workspace_schedule_transition_conflict", { cause });
}

function isTransitionConflict(error: unknown): error is Error {
  return (
    error instanceof Error &&
    error.message === "workspace_schedule_transition_conflict"
  );
}

function verifiedAttemptReplay(
  attempt: WorkspaceBranchAttempt,
  input: WorkspaceBranchAttemptVerification,
): null | WorkspaceBranchAttempt {
  if (attempt.state !== "verified") return null;
  if (
    input.observedAfterFingerprint !== attempt.observedAfterFingerprint ||
    !dequal(input.result, attempt.result)
  )
    throw conflict();
  return attempt;
}

function notificationPolicyMatches(
  tick: Exclude<WorkspaceScheduleTick, { phase: "started" }>,
  plan: WorkspaceSchedulePlan,
): boolean {
  // Terminal mutation/error policy is stronger than the original plan policy.
  // Replaying the pinned plan may never downgrade the stored terminal requirement.
  return (
    tick.notificationRequired === plan.notificationRequired ||
    (tick.phase === "terminal" &&
      ["applied", "blocked", "failed"].includes(tick.outcome))
  );
}

function assertCompletionAllowed(
  tick: WorkspaceScheduleTick,
  outcome: WorkspaceScheduleOutcome,
): void {
  if (tick.phase === "started" && outcome !== "failed") throw conflict();
  if (outcome === "applied" && tick.phase !== "launched") throw conflict();
  if (
    (outcome === "no-op" || outcome === "audit-only") &&
    tick.phase !== "planned"
  )
    throw conflict();
  if (
    outcome === "audit-only" &&
    tick.phase === "planned" &&
    tick.mode !== "audit"
  )
    throw conflict();
}

function assertTerminalCompletionMatches(
  tick: Extract<WorkspaceScheduleTick, { phase: "terminal" }>,
  outcome: WorkspaceScheduleOutcome,
  blockedReason: undefined | WorkspaceScheduleBlockedReason,
): void {
  if (
    tick.outcome !== outcome ||
    (blockedReason !== undefined && tick.blockedReason !== blockedReason)
  )
    throw conflict();
}
