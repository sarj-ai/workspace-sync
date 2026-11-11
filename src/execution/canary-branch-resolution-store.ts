import type { D1PreparedStatement } from "@cloudflare/workers-types";
import { z } from "zod";

import { sameJson, sha256Hex } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import { getWorkspaceExecutionPolicy } from "./get-workspace-execution-policy.ts";
import type { CanaryResolutionPins } from "./policy.ts";
export type { CanaryResolutionPins } from "./policy.ts";
import { WORKSPACE_DIRECTORY_ACTION_IDS } from "./contracts.ts";
import {
  workspaceDirectoryChanges,
  workspaceDirectorySourceFingerprints,
} from "./operation.ts";
import { ClaimedReviewedSlackLifecycleIntentSchema } from "./reviewed-slack-lifecycle-intent.ts";
import { WorkspaceScheduleTickSchema } from "./schedule-health-contracts.ts";
import {
  workspaceDirectoryExecutionId,
  type WorkspaceDirectoryWorkflowBinding,
} from "./workflow.ts";
import { workspaceBranchSourceIdentity } from "./workspace-branch-source-identity.ts";
import type {
  WorkspaceDatabase,
  WorkspaceDatabaseSession,
  WorkspaceStatement,
} from "./workspace-database.ts";

const RowSchema = z.strictObject({
  revision: z.number().int(),
  "snapshot_json": z.string(),
  "scheduled_at_ms": z.number().int(),
  "worker_version_id": z.string(),
  "worker_revision": z.string(),
  "proof_json": z.string(),
  "claimed_at_ms": z.number().int(),
  "expires_at_ms": z.number().int(),
  "budget_key": z.string(),
  "google_user_id": z.string(),
  "reserved_at_ms": z.number().int(),
  "triggers_json": z.string(),
});
const DigestSchema = z.string().regex(/^[a-f0-9]{64}$/u);
const TriggerMapSchema = z.record(z.string(), z.string());
const ResolutionRowSchema = z.strictObject({
  "intent_id": DigestSchema,
  "source_hash": DigestSchema,
  "snapshot_json": z.string(),
  "proof_json": z.string(),
  "triggers_json": z.string(),
  "tick_revision": z.number().int(),
  "claimed_at_ms": z.number().int(),
  "budget_key": z.string(),
  kind: z.literal("not-dispatched"),
  "evidence_id": z.string(),
  "recorded_at_ms": z.number().int(),
  "workflow_status": z.literal("errored"),
  "resolution_change_hash": DigestSchema,
});

export interface CanaryResolutionSnapshot {
  resolved: boolean;
  row: z.output<typeof RowSchema>;
  sourceHash: string;
  tick: z.output<typeof WorkspaceScheduleTickSchema>;
}
const SOURCE_SQL = `SELECT tick.revision, tick.snapshot_json, tick.scheduled_at_ms,
  tick.worker_version_id, tick.worker_revision, intent.proof_json, intent.claimed_at_ms, intent.expires_at_ms,
  budget.parent_execution_key AS budget_key, budget.google_user_id, budget.reserved_at_ms,
  (SELECT json_group_object(name, sql) FROM sqlite_schema WHERE type = 'trigger' AND name IN
    ('identity_reconciliation_budget_no_update', 'identity_reconciliation_budget_no_delete', 'identity_reconciliation_budget_no_replace',
     'workspace_branch_resolution_no_update', 'workspace_branch_resolution_no_delete', 'workspace_branch_resolution_no_replace')) AS triggers_json
  FROM workspace_directory_schedule_tick AS tick
  JOIN workspace_reviewed_slack_lifecycle_intent AS intent ON intent.claimed_tick_id = tick.tick_id
  JOIN identity_reconciliation_budget_reservation AS budget ON budget.service_id = 'slack'
    AND budget.parent_execution_key = 'identity-budget:v1:scheduled:organization-sync:' || tick.scheduled_at_ms
  WHERE tick.tick_id = ?1 AND intent.intent_id = ?2 AND intent.state = 'claimed'`;

/** This store can append forensic metadata only. No method can mutate original evidence or providers. */
export class CanaryBranchResolutionStore<
  Statement extends WorkspaceStatement<Statement> = D1PreparedStatement,
> implements ICanaryBranchResolutionStore {
  readonly #db: WorkspaceDatabaseSession<Statement>;
  readonly #binding: Pick<WorkspaceDirectoryWorkflowBinding, "get"> | undefined;
  readonly #now: () => number;
  readonly #pins: CanaryResolutionPins;

  constructor(
    db: WorkspaceDatabase<Statement>,
    binding: Pick<WorkspaceDirectoryWorkflowBinding, "get"> | undefined,
    now: () => number = Date.now,
    pins: CanaryResolutionPins = getWorkspaceExecutionPolicy()
      .legacyCanaryResolution,
  ) {
    this.#db = db.withSession("first-primary");
    this.#binding = binding;
    this.#now = now;
    this.#pins = Object.freeze({ ...pins });
  }

  async read(): Promise<CanaryResolutionSnapshot> {
    const snapshot = await this.#readSource();
    await this.#assertTerminal();
    return snapshot;
  }

  /* Revalidates the fixed historical attestation, never authorizes dispatch or accepts caller pins. */
  async readForHealth(): Promise<CanaryResolutionSnapshot | null> {
    const existing = await this.#db
      .prepare(
        "SELECT tick_id FROM workspace_branch_attempt_resolution WHERE tick_id = ?1",
      )
      .bind(this.#pins.tickId)
      .first();
    if (existing === null) return null;
    return this.#readSource();
  }

  async attach(
    expected: CanaryResolutionSnapshot,
    resolutionChangeHash: string,
    expiresAtMs: number,
  ): Promise<void> {
    DigestSchema.parse(resolutionChangeHash);
    const current = await this.read();
    if (
      current.sourceHash !== expected.sourceHash ||
      !sameJson(
        JsonValueSchema.parse(current.row),
        JsonValueSchema.parse(expected.row),
      )
    )
      throw conflict();
    if (current.resolved) return;
    const recordedAtMs = this.#now();
    if (!Number.isSafeInteger(expiresAtMs) || recordedAtMs >= expiresAtMs)
      throw conflict();
    const row = current.row;
    const result = await this.#db
      .prepare(`INSERT INTO workspace_branch_attempt_resolution
      (tick_id, intent_id, kind, evidence_id, tick_revision, snapshot_json, proof_json, claimed_at_ms,
       budget_key, triggers_json, source_hash, resolution_change_hash, recorded_at_ms, workflow_status)
      SELECT ?1, ?2, 'not-dispatched', ?3, revision, snapshot_json, proof_json, claimed_at_ms,
       budget_key, triggers_json, ?4, ?5, ?6, 'errored'
      FROM (
        SELECT tick.revision, tick.snapshot_json, tick.scheduled_at_ms,
          tick.worker_version_id, tick.worker_revision, intent.proof_json, intent.claimed_at_ms,
          intent.expires_at_ms, budget.parent_execution_key AS budget_key, budget.google_user_id,
          budget.reserved_at_ms,
          (SELECT json_group_object(name, sql) FROM sqlite_schema WHERE type = 'trigger' AND name IN
            ('identity_reconciliation_budget_no_update', 'identity_reconciliation_budget_no_delete',
             'identity_reconciliation_budget_no_replace', 'workspace_branch_resolution_no_update',
             'workspace_branch_resolution_no_delete', 'workspace_branch_resolution_no_replace')) AS triggers_json
        FROM workspace_directory_schedule_tick AS tick
        JOIN workspace_reviewed_slack_lifecycle_intent AS intent ON intent.claimed_tick_id = tick.tick_id
        JOIN identity_reconciliation_budget_reservation AS budget ON budget.service_id = 'slack'
          AND budget.parent_execution_key = 'identity-budget:v1:scheduled:organization-sync:' || tick.scheduled_at_ms
        WHERE tick.tick_id = ?7 AND intent.intent_id = ?8 AND intent.state = 'claimed'
      ) AS original
      WHERE revision = ?9 AND snapshot_json = ?10 AND scheduled_at_ms = ?11
        AND worker_version_id = ?12 AND worker_revision = ?13 AND proof_json = ?14
        AND claimed_at_ms = ?15 AND expires_at_ms = ?16 AND budget_key = ?17
        AND google_user_id = ?18 AND reserved_at_ms = ?19 AND triggers_json = ?20 AND ?6 < ?21
        AND NOT EXISTS (SELECT 1 FROM workspace_branch_attempt_resolution WHERE tick_id = ?1)`)
      .bind(
        this.#pins.tickId,
        this.#pins.intentId,
        this.#pins.evidenceId,
        current.sourceHash,
        resolutionChangeHash,
        recordedAtMs,
        this.#pins.tickId,
        this.#pins.intentId,
        row.revision,
        row["snapshot_json"],
        row["scheduled_at_ms"],
        row["worker_version_id"],
        row["worker_revision"],
        row["proof_json"],
        row["claimed_at_ms"],
        row["expires_at_ms"],
        row["budget_key"],
        row["google_user_id"],
        row["reserved_at_ms"],
        row["triggers_json"],
        expiresAtMs,
      )
      .run();
    if (result.meta.changes !== 1) throw conflict();
  }

  async #readSource(): Promise<CanaryResolutionSnapshot> {
    const row = RowSchema.parse(
      await this.#db
        .prepare(SOURCE_SQL)
        .bind(this.#pins.tickId, this.#pins.intentId)
        .first(),
    );
    const tick = WorkspaceScheduleTickSchema.parse(
      JSON.parse(row["snapshot_json"]),
    );
    await validateSource(row, tick, this.#pins, this.#now());
    const sourceHash = await sha256Hex(JsonValueSchema.parse(row));
    const stored = await this.#db
      .prepare(`SELECT intent_id, source_hash, snapshot_json, proof_json, triggers_json,
      tick_revision, claimed_at_ms, budget_key, kind, evidence_id, recorded_at_ms, workflow_status,
      resolution_change_hash FROM workspace_branch_attempt_resolution WHERE tick_id = ?1`)
      .bind(this.#pins.tickId)
      .first();
    if (stored !== null)
      assertResolution(stored, row, sourceHash, this.#pins, this.#now());
    return { row, tick, sourceHash, resolved: stored !== null };
  }

  async #assertTerminal(): Promise<void> {
    if (this.#binding === undefined) throw conflict();
    const instance = await this.#binding.get(this.#pins.workflowId);
    const status = await instance.status();
    if (instance.id !== this.#pins.workflowId || status.status !== "errored")
      throw conflict();
  }
}

async function validateSource(
  row: z.output<typeof RowSchema>,
  tick: z.output<typeof WorkspaceScheduleTickSchema>,
  pins: CanaryResolutionPins,
  now: number,
): Promise<void> {
  if (
    tick.phase !== "terminal" ||
    tick.outcome !== "failed" ||
    tick.receipt === null ||
    tick.completedAtMs > now ||
    tick.receipt.verifiedAtMs > now ||
    tick.execution?.result !== null ||
    tick.branchAttempts?.length !== 1 ||
    tick.tickId !== pins.tickId ||
    tick.workflowId !== pins.workflowId ||
    row.revision !== pins.revision ||
    row["scheduled_at_ms"] !== pins.scheduledAtMs ||
    tick.scheduledAtMs !== pins.scheduledAtMs ||
    row["worker_version_id"] !== pins.workerVersionId ||
    row["worker_revision"] !== pins.workerRevision ||
    tick.deployment.id !== pins.workerVersionId ||
    tick.deployment.revision !== pins.workerRevision ||
    row["expires_at_ms"] !== pins.expiresAtMs ||
    row["expires_at_ms"] >= row["reserved_at_ms"] ||
    row["reserved_at_ms"] !== pins.reservedAtMs ||
    row["reserved_at_ms"] > tick.completedAtMs ||
    row["google_user_id"] !== pins.googleUserId
  )
    throw conflict();
  const params = tick.execution.params;
  const claim = ClaimedReviewedSlackLifecycleIntentSchema.parse({
    state: "claimed",
    intentId: pins.intentId,
    claimedTickId: pins.tickId,
    claimedAtMs: row["claimed_at_ms"],
    proof: JsonValueSchema.parse(JSON.parse(row["proof_json"])),
  });
  if (
    (await sha256Hex(JsonValueSchema.parse(claim.proof))) !== pins.intentId ||
    claim.proof.expiresAtMs !== pins.expiresAtMs ||
    claim.proof.originalPlanHash !== pins.planHash ||
    !sameJson(
      JsonValueSchema.parse(params.reviewedSlackLifecycleIntent),
      JsonValueSchema.parse(claim),
    ) ||
    params.scheduledTickId !== pins.tickId ||
    params.requestedBy !== "scheduled:workspace-directory" ||
    tick.execution.paramsDigest !== pins.paramsDigest ||
    (await sha256Hex(JsonValueSchema.parse(params))) !== pins.paramsDigest ||
    (await workspaceDirectoryExecutionId(params)) !== pins.workflowId ||
    claim.proof.reviewed.googleUserId !== pins.googleUserId ||
    claim.proof.reviewed.slackUserId !== pins.slackUserId ||
    claim.proof.reviewed.slackUserGroupId !== pins.slackUserGroupId
  )
    throw conflict();
  const attempt = tick.branchAttempts[0];
  const branch = params.plan.branches.find(
    ({ branchId }) => branchId === "slack-groups-channels",
  );
  const changes = workspaceDirectoryChanges(params.plan).filter(
    ({ actionId }) =>
      actionId === WORKSPACE_DIRECTORY_ACTION_IDS.slackGroupsChannels,
  );
  const change = changes[0];
  if (
    attempt?.state !== "attempted" ||
    attempt.branchId !== "slack-groups-channels" ||
    attempt.attemptedAtMs !== pins.attemptedAtMs ||
    branch === undefined ||
    change === undefined ||
    changes.length !== 1 ||
    (await sha256Hex(JsonValueSchema.parse(branch))) !==
      claim.proof.branchHash ||
    branch.branchId !== "slack-groups-channels" ||
    branch.planHash !== claim.proof.leafPlanHash ||
    !sameJson(
      JsonValueSchema.parse(attempt.sourceIdentity),
      JsonValueSchema.parse(workspaceBranchSourceIdentity(branch, change)),
    ) ||
    (await sha256Hex(change.before)) !== attempt.beforeFingerprint ||
    (await sha256Hex(change.after)) !== attempt.afterFingerprint ||
    (await sha256Hex(
      JsonValueSchema.parse(
        workspaceDirectorySourceFingerprints(
          params.plan,
          new Set([WORKSPACE_DIRECTORY_ACTION_IDS.slackGroupsChannels]),
        ),
      ),
    )) !== claim.proof.sourceHash
  )
    throw conflict();
  assertBudgetTriggers(row["triggers_json"]);
}

const EXPECTED_TRIGGERS = Object.freeze({
  "identity_reconciliation_budget_no_update":
    "CREATE TRIGGER identity_reconciliation_budget_no_update BEFORE UPDATE ON identity_reconciliation_budget_reservation BEGIN SELECT RAISE(ABORT, 'identity_budget_reservation_immutable'); END",
  "identity_reconciliation_budget_no_delete":
    "CREATE TRIGGER identity_reconciliation_budget_no_delete BEFORE DELETE ON identity_reconciliation_budget_reservation BEGIN SELECT RAISE(ABORT, 'identity_budget_reservation_permanent'); END",
  "identity_reconciliation_budget_no_replace":
    "CREATE TRIGGER identity_reconciliation_budget_no_replace BEFORE INSERT ON identity_reconciliation_budget_reservation WHEN EXISTS (SELECT 1 FROM identity_reconciliation_budget_reservation WHERE parent_execution_key = NEW.parent_execution_key AND service_id = NEW.service_id AND (google_user_id IS NOT NEW.google_user_id OR reserved_at_ms IS NOT NEW.reserved_at_ms)) BEGIN SELECT RAISE(ABORT, 'identity_budget_reservation_immutable'); END",
  "workspace_branch_resolution_no_update":
    "CREATE TRIGGER workspace_branch_resolution_no_update BEFORE UPDATE ON workspace_branch_attempt_resolution BEGIN SELECT RAISE(ABORT, 'workspace_branch_resolution_immutable'); END",
  "workspace_branch_resolution_no_delete":
    "CREATE TRIGGER workspace_branch_resolution_no_delete BEFORE DELETE ON workspace_branch_attempt_resolution BEGIN SELECT RAISE(ABORT, 'workspace_branch_resolution_permanent'); END",
  "workspace_branch_resolution_no_replace":
    "CREATE TRIGGER workspace_branch_resolution_no_replace BEFORE INSERT ON workspace_branch_attempt_resolution WHEN EXISTS (SELECT 1 FROM workspace_branch_attempt_resolution WHERE tick_id = NEW.tick_id) BEGIN SELECT RAISE(ABORT, 'workspace_branch_resolution_immutable'); END",
});

function assertBudgetTriggers(raw: string): void {
  const triggers = TriggerMapSchema.parse(JSON.parse(raw));
  if (
    Object.keys(triggers).length !== 6 ||
    Object.entries(EXPECTED_TRIGGERS).some(
      ([key, sql]) => normalizeSql(triggers[key] ?? "") !== sql,
    )
  )
    throw conflict();
}

function normalizeSql(sql: string): string {
  return sql.replaceAll(/\s+/gu, " ").trim();
}

function assertResolution(
  raw: unknown,
  row: z.output<typeof RowSchema>,
  sourceHash: string,
  pins: CanaryResolutionPins,
  now: number,
): void {
  const originalTick = WorkspaceScheduleTickSchema.parse(
    JSON.parse(row["snapshot_json"]),
  );
  const stored = ResolutionRowSchema.parse(raw);
  if (
    stored["intent_id"] !== pins.intentId ||
    stored["source_hash"] !== sourceHash ||
    stored["snapshot_json"] !== row["snapshot_json"] ||
    stored["proof_json"] !== row["proof_json"] ||
    stored["triggers_json"] !== row["triggers_json"] ||
    stored["tick_revision"] !== row.revision ||
    stored["claimed_at_ms"] !== row["claimed_at_ms"] ||
    stored["budget_key"] !== row["budget_key"] ||
    stored["evidence_id"] !== pins.evidenceId ||
    stored["recorded_at_ms"] < row["reserved_at_ms"] ||
    stored["recorded_at_ms"] > now ||
    originalTick.phase !== "terminal" ||
    stored["recorded_at_ms"] < originalTick.completedAtMs
  )
    throw conflict();
}

function conflict(): Error {
  return new Error("workspace_canary_resolution_conflict");
}

interface ICanaryBranchResolutionStore {
  attach(
    expected: CanaryResolutionSnapshot,
    changeHash: string,
    expiresAtMs: number,
  ): Promise<void>;
  read(): Promise<CanaryResolutionSnapshot>;
  readForHealth(): Promise<CanaryResolutionSnapshot | null>;
}
