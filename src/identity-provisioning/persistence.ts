import type {
  D1Database,
  D1PreparedStatement,
} from "@cloudflare/workers-types";
import { z } from "zod";

import {
  AuthorityRevisionSchema,
  DesiredProvisioningPlanSchema,
  GoogleUserIdSchema,
  PrimaryEmailSchema,
  ProvisioningIdempotencyKeySchema,
  ProvisioningProviderIdSchema,
} from "../catalog/identity-authority.ts";
import {
  type IdentityProvisioningExecutionPolicy,
  IdentityProvisioningExecutionPolicySchema,
} from "./contracts.ts";
import { protectedIdentityBlocker } from "./protected-identity-blocker.ts";
import { VERIFIED_LIFECYCLE_COHORT_SQL } from "./verified-lifecycle-cohort-sql.ts";

const EpochMillisecondsSchema = z
  .number()
  .int()
  .nonnegative()
  .brand<"EpochMilliseconds">();
const PositiveDurationSchema = z
  .number()
  .int()
  .positive()
  .brand<"PositiveDurationMilliseconds">();
const TombstonePurgeLimitSchema = z.number().int().positive().max(500);
const Sha256Schema = z
  .string()
  .regex(/^[a-f0-9]{64}$/u)
  .brand<"Sha256">();
const EventKeySchema = z
  .string()
  .min(1)
  .max(200)
  .regex(/^[A-Za-z0-9._:/-]+$/u)
  .brand<"IdentityLifecycleEventKey">();
export const IdentityReconciliationRunIdSchema = z
  .uuid()
  .brand<"IdentityReconciliationRunId">();
const RunIdSchema = IdentityReconciliationRunIdSchema;
const OperationKeySchema = ProvisioningIdempotencyKeySchema;
const ClaimOwnerIdSchema = z.uuid().brand<"IdentityProvisioningClaimOwnerId">();
const ClaimGenerationSchema = z
  .number()
  .int()
  .positive()
  .brand<"IdentityProvisioningClaimGeneration">();
const ProviderSchema = ProvisioningProviderIdSchema;
const ActionSchema = z.enum(["deprovision", "provision"]);
const AuthorityStateSchema = z.enum([
  "active",
  "suspended",
  "archived",
  "deleted",
]);
const VerifiedLifecycleAuthoritySchema = z.strictObject({
  authorityState: AuthorityStateSchema,
  googleUserId: GoogleUserIdSchema,
  payloadHash: Sha256Schema,
});
const MAX_EQUIVALENT_LIFECYCLE_EVENTS = 5000;
const ErrorCodeSchema = z
  .string()
  .regex(/^[a-z][a-z0-9_.-]{0,127}$/u)
  .brand<"IdentityProvisioningErrorCode">();
export const IdentityLifecycleEventInputSchema = z.strictObject({
  authorityState: AuthorityStateSchema,
  eventKey: EventKeySchema,
  googleUserId: GoogleUserIdSchema,
  kind: z.enum(["add", "update", "delete", "undelete"]),
  occurredAtMs: EpochMillisecondsSchema,
  payloadHash: Sha256Schema,
  receivedAtMs: EpochMillisecondsSchema,
});
const LifecycleEventIdentityRowSchema = z.strictObject({
  "authority_state": AuthorityStateSchema,
  "event_key": EventKeySchema,
  "event_kind": IdentityLifecycleEventInputSchema.shape.kind,
  "google_user_id": GoogleUserIdSchema,
  "occurred_at_ms": EpochMillisecondsSchema,
  "payload_hash": Sha256Schema,
  "received_at_ms": EpochMillisecondsSchema,
});
const LifecycleClaimRowSchema = z.strictObject({
  "authority_state": AuthorityStateSchema,
  "claim_expires_at_ms": EpochMillisecondsSchema,
  "claim_generation": ClaimGenerationSchema,
  "claim_owner_id": ClaimOwnerIdSchema,
  "event_key": EventKeySchema,
  "event_kind": IdentityLifecycleEventInputSchema.shape.kind,
  "google_user_id": GoogleUserIdSchema,
  "payload_hash": Sha256Schema,
});
const LifecycleClaimSchema = z.strictObject({
  authorityState: AuthorityStateSchema,
  eventKey: EventKeySchema,
  expiresAtMs: EpochMillisecondsSchema,
  generation: ClaimGenerationSchema,
  googleUserId: GoogleUserIdSchema,
  kind: IdentityLifecycleEventInputSchema.shape.kind,
  ownerId: ClaimOwnerIdSchema,
  payloadHash: Sha256Schema,
});
const TombstoneVersionRowSchema = z.strictObject({
  "deleted_at_ms": EpochMillisecondsSchema,
});
export const IdentityTombstoneInputSchema = z
  .strictObject({
    deletedAtMs: EpochMillisecondsSchema,
    googleUserId: GoogleUserIdSchema,
    lifecycleEventKey: EventKeySchema,
    primaryEmail: PrimaryEmailSchema,
    retainedUntilMs: EpochMillisecondsSchema,
  })
  .refine(({ deletedAtMs, retainedUntilMs }) => retainedUntilMs > deletedAtMs, {
    message: "retainedUntilMs must be after deletedAtMs",
    path: ["retainedUntilMs"],
  });

const ReconciliationRunInputSchema = z.strictObject({
  authorityRevision: AuthorityRevisionSchema,
  createdAtMs: EpochMillisecondsSchema,
  planHash: Sha256Schema,
  runId: RunIdSchema,
});
const ReconciliationRunIdentityRowSchema = z.strictObject({
  "run_id": RunIdSchema,
});
const ReconciliationOperationInputSchema = z
  .strictObject({
    action: ActionSchema,
    desiredStateHash: Sha256Schema,
    googleUserId: GoogleUserIdSchema,
    operationKey: OperationKeySchema,
    provider: ProviderSchema,
  })
  .refine(
    ({ action, desiredStateHash, googleUserId, operationKey, provider }) =>
      operationKey ===
      `identity:v1:${googleUserId}:${provider}:${action}:${desiredStateHash}`,
    {
      message: "operationKey must identify the exact desired operation",
      path: ["operationKey"],
    },
  );
const OperationClaimRowSchema = z.strictObject({
  state: z.enum(["claimed", "recovering"]),
  action: ActionSchema,
  "claim_expires_at_ms": EpochMillisecondsSchema,
  "claim_generation": ClaimGenerationSchema,
  "claim_owner_id": ClaimOwnerIdSchema,
  "desired_state_hash": Sha256Schema,
  "google_user_id": GoogleUserIdSchema,
  "operation_key": OperationKeySchema,
  provider: ProviderSchema,
  "run_id": RunIdSchema,
});
const OperationClaimBaseSchema = z.strictObject({
  action: ActionSchema,
  desiredStateHash: Sha256Schema,
  expiresAtMs: EpochMillisecondsSchema,
  generation: ClaimGenerationSchema,
  googleUserId: GoogleUserIdSchema,
  operationKey: OperationKeySchema,
  ownerId: ClaimOwnerIdSchema,
  provider: ProviderSchema,
  runId: RunIdSchema,
});

const FreshOperationClaimSchema = OperationClaimBaseSchema.extend({
  phase: z.literal("claimed"),
}).readonly();
const RecoveringOperationClaimSchema = OperationClaimBaseSchema.extend({
  phase: z.literal("recovering"),
}).readonly();
const OperationClaimSchema = z.discriminatedUnion("phase", [
  FreshOperationClaimSchema,
  RecoveringOperationClaimSchema,
]);
export type FreshIdentityOperationClaim = z.output<
  typeof FreshOperationClaimSchema
>;

export type IdentityLifecycleEventInput = z.output<
  typeof IdentityLifecycleEventInputSchema
>;
export type IdentityLifecycleEventClaim = z.output<typeof LifecycleClaimSchema>;
export type IdentityTombstoneInput = z.output<
  typeof IdentityTombstoneInputSchema
>;
export type IdentityReconciliationRunInput = z.output<
  typeof ReconciliationRunInputSchema
>;
export type IdentityReconciliationRunId = z.output<typeof RunIdSchema>;
export type IdentityReconciliationOperationInput = z.output<
  typeof ReconciliationOperationInputSchema
>;
export type IdentityReconciliationOperationClaim = z.output<
  typeof OperationClaimSchema
>;

export function identityReconciliationRunInput(
  input: z.input<typeof ReconciliationRunInputSchema>,
): IdentityReconciliationRunInput {
  return ReconciliationRunInputSchema.parse(input);
}

export function identityReconciliationOperationInput(
  input: z.input<typeof ReconciliationOperationInputSchema>,
): IdentityReconciliationOperationInput {
  return ReconciliationOperationInputSchema.parse(input);
}

export interface IdentityLifecycleEventStore {
  claimLifecycleEvent(
    eventKey: string,
    ownerId: string,
    nowMs: number,
    durationMs: number,
  ): Promise<IdentityProvisioningClaim<IdentityLifecycleEventClaim>>;
  claimNextLifecycleEvent(
    ownerId: string,
    nowMs: number,
    durationMs: number,
  ): Promise<IdentityProvisioningClaim<IdentityLifecycleEventClaim>>;
  clearTombstone(
    googleUserId: string,
    lifecycleEventKey: string,
    claim?: IdentityLifecycleEventClaim,
  ): Promise<boolean>;
  completeLifecycleEvent(
    claim: IdentityLifecycleEventClaim,
    completedAtMs: number,
  ): Promise<void>;
  completeVerifiedLifecycleCohort?(
    claim: IdentityLifecycleEventClaim,
    completedAtMs: number,
    authority: z.input<typeof VerifiedLifecycleAuthoritySchema>,
  ): Promise<number>;
  holdExpiredDeletedAuthority(
    claim: IdentityLifecycleEventClaim,
    observedAtMs: number,
  ): Promise<number>;
  purgeExpiredTombstones(nowMs: number, limit: number): Promise<number>;
  recordLifecycleEvent(
    input: IdentityLifecycleEventInput,
  ): Promise<"duplicate" | "recorded">;
  recordTombstone(
    input: IdentityTombstoneInput,
    claim?: IdentityLifecycleEventClaim,
  ): Promise<void>;
  retryLifecycleEvent(
    claim: IdentityLifecycleEventClaim,
    errorCode: string,
    nowMs: number,
  ): Promise<void>;
}

export interface IdentityReconciliationStore {
  claimAutomaticDeprovisionOperation(
    authorization: AutomaticDeprovisionAuthorization,
    ownerId: string,
    nowMs: number,
    durationMs: number,
  ): Promise<IdentityProvisioningClaim<IdentityReconciliationOperationClaim>>;
  markDispatching(
    claim: FreshIdentityOperationClaim,
    nowMs: number,
  ): Promise<void>;
  completeOperation(
    claim: IdentityReconciliationOperationClaim,
    resultHash: string,
    completedAtMs: number,
  ): Promise<void>;
  createPlan(
    run: IdentityReconciliationRunInput,
    operations: readonly IdentityReconciliationOperationInput[],
  ): Promise<IdentityReconciliationRunId>;
  retryOperation(
    claim: IdentityReconciliationOperationClaim,
    errorCode: string,
  ): Promise<void>;
}

export type IdentityReconciliationExecutionStore = Pick<
  IdentityReconciliationStore,
  | "claimAutomaticDeprovisionOperation"
  | "markDispatching"
  | "completeOperation"
  | "createPlan"
  | "retryOperation"
>;

export interface AutomaticDeprovisionAuthorization {
  readonly operation: Extract<
    z.output<typeof DesiredProvisioningPlanSchema>,
    { kind: "deprovision" }
  >;
  readonly planHash: string;
  readonly policy: Extract<
    IdentityProvisioningExecutionPolicy,
    { kind: "bounded-automatic-deprovision" }
  >;
}

export type IdentityProvisioningClaim<Result> =
  | { readonly kind: "acquired"; readonly claim: Result }
  | { readonly kind: "unavailable" };

export class IdentityProvisioningFenceError extends Error {
  constructor() {
    super("identity_provisioning_claim_fenced");
    this.name = "IdentityProvisioningFenceError";
  }
}

export class IdentityProvisioningIdempotencyCollisionError extends Error {
  constructor(options?: ErrorOptions) {
    super("identity_provisioning_idempotency_collision", options);
    this.name = "IdentityProvisioningIdempotencyCollisionError";
  }
}

function identityProvisioningIdempotencyCollision(
  cause?: unknown,
): IdentityProvisioningIdempotencyCollisionError {
  return new IdentityProvisioningIdempotencyCollisionError({ cause });
}

function lifecycleClaim(row: z.output<typeof LifecycleClaimRowSchema>) {
  return LifecycleClaimSchema.parse({
    authorityState: row["authority_state"],
    eventKey: row["event_key"],
    expiresAtMs: row["claim_expires_at_ms"],
    generation: row["claim_generation"],
    googleUserId: row["google_user_id"],
    kind: row["event_kind"],
    ownerId: row["claim_owner_id"],
    payloadHash: row["payload_hash"],
  });
}

function operationClaim(row: z.output<typeof OperationClaimRowSchema>) {
  return OperationClaimSchema.parse({
    phase: row.state,
    action: row.action,
    desiredStateHash: row["desired_state_hash"],
    expiresAtMs: row["claim_expires_at_ms"],
    generation: row["claim_generation"],
    googleUserId: row["google_user_id"],
    operationKey: row["operation_key"],
    ownerId: row["claim_owner_id"],
    provider: row.provider,
    runId: row["run_id"],
  });
}

function lifecycleIdentityMatches(
  row: z.output<typeof LifecycleEventIdentityRowSchema>,
  input: IdentityLifecycleEventInput,
): boolean {
  return (
    row["authority_state"] === input.authorityState &&
    row["event_key"] === input.eventKey &&
    row["event_kind"] === input.kind &&
    row["google_user_id"] === input.googleUserId &&
    row["occurred_at_ms"] === input.occurredAtMs &&
    row["payload_hash"] === input.payloadHash &&
    row["received_at_ms"] === input.receivedAtMs
  );
}
const ReconciliationOperationsSchema = z
  .array(ReconciliationOperationInputSchema)
  .min(1);

export class D1IdentityProvisioningRepository
  implements IdentityLifecycleEventStore, IdentityReconciliationStore
{
  readonly #db: D1Database;

  constructor(db: D1Database) {
    this.#db = db;
  }

  async recordLifecycleEvent(
    rawInput: z.input<typeof IdentityLifecycleEventInputSchema>,
  ): Promise<"duplicate" | "recorded"> {
    const input = IdentityLifecycleEventInputSchema.parse(rawInput);
    const inserted = await this.#db
      .prepare(
        `INSERT INTO identity_lifecycle_event
           (event_key, google_user_id, event_kind, authority_state, payload_hash, occurred_at_ms, received_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT (event_key) DO NOTHING
         RETURNING event_key`,
      )
      .bind(
        input.eventKey,
        input.googleUserId,
        input.kind,
        input.authorityState,
        input.payloadHash,
        input.occurredAtMs,
        input.receivedAtMs,
      )
      .first();
    if (inserted) return "recorded";
    const existing = await this.#db
      .prepare(
        `SELECT event_key, google_user_id, event_kind, authority_state, payload_hash, occurred_at_ms, received_at_ms
         FROM identity_lifecycle_event WHERE event_key = ?1`,
      )
      .bind(input.eventKey)
      .first();
    const row = LifecycleEventIdentityRowSchema.parse(existing);
    if (!lifecycleIdentityMatches(row, input)) {
      throw new IdentityProvisioningIdempotencyCollisionError();
    }
    return "duplicate";
  }

  async claimLifecycleEvent(
    rawEventKey: string,
    rawOwnerId: string,
    rawNowMs: number,
    rawDurationMs: number,
  ): Promise<IdentityProvisioningClaim<IdentityLifecycleEventClaim>> {
    const eventKey = EventKeySchema.parse(rawEventKey);
    const ownerId = ClaimOwnerIdSchema.parse(rawOwnerId);
    const nowMs = EpochMillisecondsSchema.parse(rawNowMs);
    const durationMs = PositiveDurationSchema.parse(rawDurationMs);
    const claimExpiresAtMs = EpochMillisecondsSchema.parse(nowMs + durationMs);
    const raw = await this.#db
      .prepare(
        `UPDATE identity_lifecycle_event
         SET state = 'claimed', claim_owner_id = ?2,
             claim_generation = claim_generation + 1, claim_expires_at_ms = ?4,
             attempt_count = attempt_count + 1, error_code = NULL,
             last_attempt_at_ms = MAX(COALESCE(last_attempt_at_ms, ?3), ?3),
             next_attempt_at_ms = NULL
         WHERE event_key = ?1
           AND ((state = 'pending' AND COALESCE(next_attempt_at_ms, 0) <= ?3)
                OR (state = 'claimed' AND claim_expires_at_ms <= ?3))
         RETURNING event_key, google_user_id, event_kind, authority_state, payload_hash,
                   claim_owner_id, claim_generation, claim_expires_at_ms`,
      )
      .bind(eventKey, ownerId, nowMs, claimExpiresAtMs)
      .first();
    if (!raw) return { kind: "unavailable" };
    return {
      kind: "acquired",
      claim: lifecycleClaim(LifecycleClaimRowSchema.parse(raw)),
    };
  }

  async claimNextLifecycleEvent(
    rawOwnerId: string,
    rawNowMs: number,
    rawDurationMs: number,
  ): Promise<IdentityProvisioningClaim<IdentityLifecycleEventClaim>> {
    const ownerId = ClaimOwnerIdSchema.parse(rawOwnerId);
    const nowMs = EpochMillisecondsSchema.parse(rawNowMs);
    const durationMs = PositiveDurationSchema.parse(rawDurationMs);
    const expiresAtMs = EpochMillisecondsSchema.parse(nowMs + durationMs);
    // A newer attempt advances its subject and source group's priority across passes.
    const raw = await this.#db
      .prepare(
        `WITH pending_groups AS MATERIALIZED (
           SELECT MIN(event_key) AS event_key, 'pending' AS state, google_user_id,
             authority_state, payload_hash, event_kind, MIN(occurred_at_ms) AS occurred_at_ms,
             MAX(last_attempt_at_ms) AS last_attempt_at_ms,
             MIN(COALESCE(next_attempt_at_ms, 0)) AS next_attempt_at_ms
           FROM identity_lifecycle_event INDEXED BY idx_identity_lifecycle_pending_equivalent
           WHERE state = 'pending'
           GROUP BY google_user_id, authority_state, payload_hash, event_kind
         ), recovery_subjects AS MATERIALIZED (
           SELECT google_user_id,
             COALESCE(MAX(last_attempt_at_ms), MIN(occurred_at_ms)) AS subject_priority_ms
           FROM (
             SELECT google_user_id, last_attempt_at_ms, occurred_at_ms FROM pending_groups
             UNION ALL
             SELECT google_user_id, last_attempt_at_ms, occurred_at_ms
             FROM identity_lifecycle_event WHERE state = 'claimed'
           ) GROUP BY google_user_id
         ), next_event AS MATERIALIZED (
           SELECT candidate.event_key, candidate.state, candidate.google_user_id,
             candidate.authority_state, candidate.payload_hash, candidate.event_kind
           FROM (
             SELECT pending.event_key, pending.state, pending.google_user_id,
               pending.authority_state, pending.payload_hash, pending.event_kind,
               pending.occurred_at_ms, pending.last_attempt_at_ms
             FROM pending_groups AS pending
             WHERE pending.next_attempt_at_ms <= ?3
             UNION ALL
             SELECT event_key, state, google_user_id, authority_state, payload_hash, event_kind,
               occurred_at_ms, last_attempt_at_ms
             FROM identity_lifecycle_event
             WHERE state = 'claimed' AND claim_expires_at_ms <= ?3
           ) AS candidate JOIN recovery_subjects AS subject
             ON subject.google_user_id = candidate.google_user_id
           WHERE NOT EXISTS (
               SELECT 1 FROM identity_lifecycle_event AS held
               WHERE held.google_user_id = candidate.google_user_id
                 AND held.state = 'claimed' AND held.claim_expires_at_ms > ?3
             )
           ORDER BY subject.subject_priority_ms,
             COALESCE(candidate.last_attempt_at_ms, candidate.occurred_at_ms),
             candidate.occurred_at_ms, candidate.event_key LIMIT 1
         )
         UPDATE identity_lifecycle_event
         SET state = 'claimed',
           claim_owner_id = ?1, claim_expires_at_ms = ?2,
             claim_generation = claim_generation + 1, attempt_count = attempt_count + 1,
             error_code = NULL,
             last_attempt_at_ms = MAX(COALESCE(last_attempt_at_ms, ?3), ?3),
             next_attempt_at_ms = NULL
         WHERE event_key = (
           SELECT CASE WHEN chosen.state = 'claimed' THEN chosen.event_key ELSE (
             SELECT matching.event_key FROM identity_lifecycle_event AS matching
             WHERE matching.state = 'pending' AND COALESCE(matching.next_attempt_at_ms, 0) <= ?3
               AND matching.google_user_id = chosen.google_user_id
               AND matching.authority_state = chosen.authority_state
               AND matching.payload_hash = chosen.payload_hash
               AND matching.event_kind = chosen.event_kind
             ORDER BY matching.occurred_at_ms DESC, matching.event_key LIMIT 1
           ) END FROM next_event AS chosen
         )
         RETURNING event_key, google_user_id, event_kind, authority_state, payload_hash,
                   claim_owner_id, claim_generation, claim_expires_at_ms`,
      )
      .bind(ownerId, expiresAtMs, nowMs)
      .first();
    if (!raw) return { kind: "unavailable" };
    return {
      kind: "acquired",
      claim: lifecycleClaim(LifecycleClaimRowSchema.parse(raw)),
    };
  }

  async completeLifecycleEvent(
    rawClaim: z.input<typeof LifecycleClaimSchema>,
    rawCompletedAtMs: number,
  ): Promise<void> {
    const claim = LifecycleClaimSchema.parse(rawClaim);
    const completedAtMs = EpochMillisecondsSchema.parse(rawCompletedAtMs);
    const row = await this.#db
      .prepare(
        `UPDATE identity_lifecycle_event
         SET state = 'completed', completed_at_ms = ?1,
             claim_owner_id = NULL, claim_expires_at_ms = NULL
         WHERE event_key = ?2 AND state = 'claimed'
           AND claim_owner_id = ?3 AND claim_generation = ?4
         RETURNING event_key`,
      )
      .bind(completedAtMs, claim.eventKey, claim.ownerId, claim.generation)
      .first();
    if (!row) throw new IdentityProvisioningFenceError();
  }

  // Called after the normal fresh audit or required deprovision reconciliation succeeds.
  // The source claim stays the witness; matching older deliveries retain their original authority.
  async completeVerifiedLifecycleCohort(
    rawClaim: z.input<typeof LifecycleClaimSchema>,
    rawCompletedAtMs: number,
    rawAuthority: z.input<typeof VerifiedLifecycleAuthoritySchema>,
  ): Promise<number> {
    const claim = LifecycleClaimSchema.parse(rawClaim);
    const completedAtMs = EpochMillisecondsSchema.parse(rawCompletedAtMs);
    const authority = VerifiedLifecycleAuthoritySchema.parse(rawAuthority);
    if (authority.googleUserId !== claim.googleUserId)
      throw new IdentityProvisioningFenceError();
    const result = await this.#db
      .prepare(VERIFIED_LIFECYCLE_COHORT_SQL)
      .bind(
        claim.eventKey,
        claim.ownerId,
        claim.generation,
        claim.googleUserId,
        claim.authorityState,
        claim.payloadHash,
        claim.kind,
        completedAtMs,
        authority.authorityState,
        authority.payloadHash,
        MAX_EQUIVALENT_LIFECYCLE_EVENTS,
      )
      .run();
    if (
      result.meta.changes < 1 ||
      result.meta.changes > MAX_EQUIVALENT_LIFECYCLE_EVENTS + 1
    )
      throw new IdentityProvisioningFenceError();
    return result.meta.changes;
  }

  async retryLifecycleEvent(
    rawClaim: z.input<typeof LifecycleClaimSchema>,
    rawErrorCode: string,
    rawNowMs: number,
  ): Promise<void> {
    const claim = LifecycleClaimSchema.parse(rawClaim);
    const errorCode = ErrorCodeSchema.parse(rawErrorCode);
    const nowMs = EpochMillisecondsSchema.parse(rawNowMs);
    const row = await this.#db
      .prepare(
        `UPDATE identity_lifecycle_event
         SET state = 'pending', error_code = ?1,
             next_attempt_at_ms = MAX(?5, COALESCE(last_attempt_at_ms, ?5))
               + MIN(900000, 30000 * (1 << MIN(MAX(attempt_count - 1, 0), 5))),
             claim_owner_id = NULL, claim_expires_at_ms = NULL
         WHERE event_key = ?2 AND state = 'claimed'
           AND claim_owner_id = ?3 AND claim_generation = ?4
         RETURNING event_key`,
      )
      .bind(errorCode, claim.eventKey, claim.ownerId, claim.generation, nowMs)
      .first();
    if (!row) throw new IdentityProvisioningFenceError();
  }

  // Called only after an exact live 404 and a complete deleted-user inventory miss.
  async holdExpiredDeletedAuthority(
    rawClaim: z.input<typeof LifecycleClaimSchema>,
    rawObservedAtMs: number,
  ): Promise<number> {
    const claim = LifecycleClaimSchema.parse(rawClaim);
    const observedAtMs = EpochMillisecondsSchema.parse(rawObservedAtMs);
    if (claim.authorityState !== "deleted" || claim.kind !== "delete") return 0;
    const deletedAuthorityWindowMs = 20 * 24 * 60 * 60 * 1_000;
    const result = await this.#db
      .withSession("first-primary")
      .prepare(
        `WITH eligible_deletion AS MATERIALIZED (
           SELECT tombstone.deleted_at_ms
           FROM identity_lifecycle_event AS claimed
           JOIN identity_tombstone AS tombstone USING (google_user_id)
           WHERE claimed.event_key = ?1 AND claimed.google_user_id = ?2
             AND claimed.state = 'claimed' AND claimed.claim_owner_id = ?3
             AND claimed.claim_generation = ?4 AND claimed.claim_expires_at_ms > ?5
             AND claimed.authority_state = 'deleted' AND claimed.event_kind = 'delete'
             AND claimed.payload_hash = ?6 AND claimed.completed_at_ms IS NULL
             AND tombstone.deleted_at_ms < ?5 - ?7 AND tombstone.retained_until_ms > ?5
             AND claimed.occurred_at_ms BETWEEN tombstone.deleted_at_ms AND ?5
             AND NOT EXISTS (
               SELECT 1 FROM identity_lifecycle_event AS newer
               WHERE newer.google_user_id = claimed.google_user_id
                 AND newer.authority_state != 'deleted'
                 AND newer.occurred_at_ms >= tombstone.deleted_at_ms
             )
         )
         UPDATE identity_lifecycle_event AS target
         SET state = 'terminal_failed', error_code = 'deleted_authority_expired_review_required',
             next_attempt_at_ms = NULL, claim_owner_id = NULL, claim_expires_at_ms = NULL
         WHERE target.google_user_id = ?2 AND target.authority_state = 'deleted'
           AND target.event_kind = 'delete' AND target.completed_at_ms IS NULL
           AND (target.state = 'pending' OR (target.state = 'claimed'
             AND target.event_key = ?1 AND target.claim_owner_id = ?3
             AND target.claim_generation = ?4))
           AND EXISTS (SELECT 1 FROM eligible_deletion
             WHERE target.occurred_at_ms BETWEEN eligible_deletion.deleted_at_ms AND ?5)`,
      )
      .bind(
        claim.eventKey,
        claim.googleUserId,
        claim.ownerId,
        claim.generation,
        observedAtMs,
        claim.payloadHash,
        deletedAuthorityWindowMs,
      )
      .run();
    return result.meta.changes;
  }

  async recordTombstone(
    rawInput: z.input<typeof IdentityTombstoneInputSchema>,
    rawClaim?: z.input<typeof LifecycleClaimSchema>,
  ): Promise<void> {
    const input = IdentityTombstoneInputSchema.parse(rawInput);
    const claim =
      rawClaim === undefined ? undefined : LifecycleClaimSchema.parse(rawClaim);
    if (
      claim !== undefined &&
      (claim.eventKey !== input.lifecycleEventKey ||
        claim.googleUserId !== input.googleUserId ||
        claim.kind !== "delete")
    ) {
      throw new IdentityProvisioningFenceError();
    }
    const row = await this.#db
      .prepare(
        `INSERT INTO identity_tombstone
           (google_user_id, primary_email, lifecycle_event_key, deleted_at_ms, retained_until_ms)
         SELECT ?1, ?2, ?3, ?4, ?5
         FROM identity_lifecycle_event
         WHERE event_key = ?3 AND google_user_id = ?1
           AND event_kind = 'delete'
           AND (
             state = 'completed'
             OR (
               state = 'claimed'
               AND claim_owner_id = ?6
               AND claim_generation = ?7
             )
           )
           AND NOT EXISTS (
             SELECT 1 FROM identity_lifecycle_event AS newer_authority
             WHERE newer_authority.google_user_id = ?1
               AND newer_authority.authority_state IN ('active', 'suspended', 'archived')
               AND newer_authority.occurred_at_ms >= ?4
           )
         ON CONFLICT (google_user_id) DO UPDATE SET
           primary_email = excluded.primary_email,
           lifecycle_event_key = excluded.lifecycle_event_key,
           deleted_at_ms = excluded.deleted_at_ms,
           retained_until_ms = excluded.retained_until_ms
         WHERE excluded.deleted_at_ms >= identity_tombstone.deleted_at_ms
         RETURNING google_user_id`,
      )
      .bind(
        input.googleUserId,
        input.primaryEmail,
        input.lifecycleEventKey,
        input.deletedAtMs,
        input.retainedUntilMs,
        claim?.ownerId ?? null,
        claim?.generation ?? null,
      )
      .first();
    if (row) return;
    const supersedingAuthority = await this.#db
      .prepare(
        `SELECT 1 FROM identity_lifecycle_event AS original_delete
         WHERE original_delete.event_key = ?3
           AND original_delete.google_user_id = ?1
           AND original_delete.event_kind = 'delete'
           AND (
             original_delete.state = 'completed'
             OR (
               original_delete.state = 'claimed'
               AND original_delete.claim_owner_id = ?4
               AND original_delete.claim_generation = ?5
             )
           )
           AND EXISTS (
             SELECT 1 FROM identity_lifecycle_event AS newer_authority
             WHERE newer_authority.google_user_id = ?1
               AND newer_authority.authority_state IN ('active', 'suspended', 'archived')
               AND newer_authority.occurred_at_ms >= ?2
           )
         LIMIT 1`,
      )
      .bind(
        input.googleUserId,
        input.deletedAtMs,
        input.lifecycleEventKey,
        claim?.ownerId ?? null,
        claim?.generation ?? null,
      )
      .first();
    if (supersedingAuthority !== null) return;
    const current = await this.#db
      .prepare(
        "SELECT deleted_at_ms FROM identity_tombstone WHERE google_user_id = ?1",
      )
      .bind(input.googleUserId)
      .first();
    const currentVersion = current
      ? TombstoneVersionRowSchema.parse(current)
      : null;
    if (
      currentVersion !== null &&
      currentVersion["deleted_at_ms"] > input.deletedAtMs
    )
      return;
    throw new IdentityProvisioningFenceError();
  }

  async clearTombstone(
    rawGoogleUserId: string,
    rawLifecycleEventKey: string,
    rawClaim?: z.input<typeof LifecycleClaimSchema>,
  ): Promise<boolean> {
    const googleUserId = GoogleUserIdSchema.parse(rawGoogleUserId);
    const lifecycleEventKey = EventKeySchema.parse(rawLifecycleEventKey);
    const claim =
      rawClaim === undefined ? undefined : LifecycleClaimSchema.parse(rawClaim);
    if (
      claim !== undefined &&
      (claim.eventKey !== lifecycleEventKey ||
        claim.googleUserId !== googleUserId ||
        claim.authorityState === "deleted")
    ) {
      throw new IdentityProvisioningFenceError();
    }
    const result = await this.#db
      .prepare(
        `DELETE FROM identity_tombstone
         WHERE google_user_id = ?1
           AND EXISTS (
             SELECT 1 FROM identity_lifecycle_event
             WHERE event_key = ?2 AND google_user_id = ?1
               AND authority_state IN ('active', 'suspended', 'archived')
               AND (
                 state = 'completed'
                 OR (
                   state = 'claimed'
                   AND claim_owner_id = ?3
                   AND claim_generation = ?4
                 )
               )
               AND occurred_at_ms >= identity_tombstone.deleted_at_ms
           )`,
      )
      .bind(
        googleUserId,
        lifecycleEventKey,
        claim?.ownerId ?? null,
        claim?.generation ?? null,
      )
      .run();
    return result.meta.changes === 1;
  }

  async purgeExpiredTombstones(
    rawNowMs: number,
    rawLimit: number,
  ): Promise<number> {
    const nowMs = EpochMillisecondsSchema.parse(rawNowMs);
    const limit = TombstonePurgeLimitSchema.parse(rawLimit);
    const result = await this.#db
      .prepare(
        `DELETE FROM identity_tombstone
         WHERE google_user_id IN (
           SELECT google_user_id
           FROM identity_tombstone
           WHERE retained_until_ms <= ?1
           ORDER BY retained_until_ms, google_user_id
           LIMIT ?2
         )`,
      )
      .bind(nowMs, limit)
      .run();
    return result.meta.changes;
  }

  async createPlan(
    rawRun: z.input<typeof ReconciliationRunInputSchema>,
    rawOperations: readonly z.input<
      typeof ReconciliationOperationInputSchema
    >[],
  ): Promise<IdentityReconciliationRunId> {
    const run = ReconciliationRunInputSchema.parse(rawRun);
    const operations = ReconciliationOperationsSchema.parse(rawOperations);
    const statements: D1PreparedStatement[] = [
      this.#db
        .prepare(
          `INSERT INTO identity_reconciliation_run
             (run_id, authority_revision, plan_hash, created_at_ms)
           VALUES (?1, ?2, ?3, ?4)
           ON CONFLICT (authority_revision, plan_hash) DO UPDATE SET
             authority_revision = excluded.authority_revision
           RETURNING run_id`,
        )
        .bind(run.runId, run.authorityRevision, run.planHash, run.createdAtMs),
      ...operations.map((operation) =>
        this.#db
          .prepare(
            `INSERT INTO identity_reconciliation_operation
               (operation_key, run_id, google_user_id, provider, action, desired_state_hash)
             SELECT ?1, run_id, ?2, ?3, ?4, ?5
             FROM identity_reconciliation_run
             WHERE authority_revision = ?6 AND plan_hash = ?7
             ON CONFLICT (operation_key) DO UPDATE SET
               operation_key = CASE
                 WHEN run_id = (
                   SELECT run_id FROM identity_reconciliation_run
                   WHERE authority_revision = ?6 AND plan_hash = ?7
                 )
                   AND google_user_id = excluded.google_user_id
                   AND provider = excluded.provider
                   AND action = excluded.action
                   AND desired_state_hash = excluded.desired_state_hash
                 THEN excluded.operation_key ELSE NULL END`,
          )
          .bind(
            operation.operationKey,
            operation.googleUserId,
            operation.provider,
            operation.action,
            operation.desiredStateHash,
            run.authorityRevision,
            run.planHash,
          ),
      ),
    ];
    try {
      const [runResult] = await this.#db.batch(statements);
      const row = ReconciliationRunIdentityRowSchema.parse(
        runResult?.results[0],
      );
      return row["run_id"];
    } catch (error) {
      if (error instanceof Error && /constraint|unique/iu.test(error.message)) {
        throw identityProvisioningIdempotencyCollision(error);
      }
      throw error;
    }
  }

  // Automatic authority is separate from the reviewed approval claim path.
  async claimAutomaticDeprovisionOperation(
    authorization: AutomaticDeprovisionAuthorization,
    rawOwnerId: string,
    rawNowMs: number,
    rawDurationMs: number,
  ): Promise<IdentityProvisioningClaim<IdentityReconciliationOperationClaim>> {
    const policy = IdentityProvisioningExecutionPolicySchema.parse(
      authorization.policy,
    );
    const operation = DesiredProvisioningPlanSchema.parse(
      authorization.operation,
    );
    if (
      policy.kind !== "bounded-automatic-deprovision" ||
      operation.kind !== "deprovision" ||
      operation.target.providerId !== "github" ||
      protectedIdentityBlocker(operation.subject) !== undefined
    )
      return { kind: "unavailable" };
    const planHash = Sha256Schema.parse(authorization.planHash);
    const ownerId = ClaimOwnerIdSchema.parse(rawOwnerId);
    const nowMs = EpochMillisecondsSchema.parse(rawNowMs);
    const expiresAtMs = EpochMillisecondsSchema.parse(
      nowMs + PositiveDurationSchema.parse(rawDurationMs),
    );
    const raw = await this.#db
      .prepare(
        `UPDATE identity_reconciliation_operation
       SET state = CASE WHEN state IN ('dispatching', 'uncertain', 'recovering') THEN 'recovering' ELSE 'claimed' END,
           claim_owner_id = ?1, claim_expires_at_ms = ?2,
           claim_generation = claim_generation + 1, attempt_count = attempt_count + 1,
           error_code = NULL
       WHERE operation_key = ?3 AND google_user_id = ?4 AND provider = ?5
         AND action = 'deprovision'
         AND (state IN ('pending', 'uncertain') OR (state IN ('claimed', 'dispatching', 'recovering') AND claim_expires_at_ms <= ?6))
         AND EXISTS (
           SELECT 1 FROM identity_reconciliation_run AS run
           WHERE run.run_id = identity_reconciliation_operation.run_id
             AND run.plan_hash = ?7 AND run.authority_revision = ?8
             AND NOT EXISTS (
               SELECT 1 FROM identity_reconciliation_operation AS sibling
               WHERE sibling.run_id = run.run_id
                 AND (sibling.google_user_id != ?4 OR sibling.provider != ?5
                      OR sibling.action != 'deprovision')
             )
         )
       RETURNING state, operation_key, run_id, google_user_id, provider, action,
                 desired_state_hash, claim_owner_id, claim_generation, claim_expires_at_ms`,
      )
      .bind(
        ownerId,
        expiresAtMs,
        operation.idempotencyKey,
        operation.subject.googleUserId,
        operation.target.providerId,
        nowMs,
        planHash,
        operation.subject.authorityRevision,
      )
      .first();
    if (!raw) return { kind: "unavailable" };
    return {
      kind: "acquired",
      claim: operationClaim(OperationClaimRowSchema.parse(raw)),
    };
  }

  async markDispatching(
    rawClaim: FreshIdentityOperationClaim,
    rawNowMs: number,
  ): Promise<void> {
    const claim = FreshOperationClaimSchema.parse(rawClaim);
    const nowMs = EpochMillisecondsSchema.parse(rawNowMs);
    const row = await this.#db
      .prepare(
        `UPDATE identity_reconciliation_operation SET state = 'dispatching'
       WHERE operation_key = ?1 AND state = 'claimed'
         AND claim_owner_id = ?2 AND claim_generation = ?3 AND claim_expires_at_ms > ?4
       RETURNING operation_key`,
      )
      .bind(claim.operationKey, claim.ownerId, claim.generation, nowMs)
      .first();
    if (row === null) throw new IdentityProvisioningFenceError();
  }

  async completeOperation(
    rawClaim: z.input<typeof OperationClaimSchema>,
    rawResultHash: string,
    rawCompletedAtMs: number,
  ): Promise<void> {
    const claim = OperationClaimSchema.parse(rawClaim);
    const resultHash = Sha256Schema.parse(rawResultHash);
    const completedAtMs = EpochMillisecondsSchema.parse(rawCompletedAtMs);
    const row = await this.#db
      .prepare(
        `UPDATE identity_reconciliation_operation
         SET state = 'succeeded', result_hash = ?1, completed_at_ms = ?2,
             claim_owner_id = NULL, claim_expires_at_ms = NULL
         WHERE operation_key = ?3 AND state IN ('claimed', 'dispatching', 'recovering')
           AND claim_owner_id = ?4 AND claim_generation = ?5
         RETURNING operation_key`,
      )
      .bind(
        resultHash,
        completedAtMs,
        claim.operationKey,
        claim.ownerId,
        claim.generation,
      )
      .first();
    if (!row) throw new IdentityProvisioningFenceError();
  }

  async retryOperation(
    rawClaim: z.input<typeof OperationClaimSchema>,
    rawErrorCode: string,
  ): Promise<void> {
    const claim = OperationClaimSchema.parse(rawClaim);
    const errorCode = ErrorCodeSchema.parse(rawErrorCode);
    const row = await this.#db
      .prepare(
        `UPDATE identity_reconciliation_operation
         SET state = CASE WHEN state = 'claimed' THEN 'pending' ELSE 'uncertain' END, error_code = ?1,
             claim_owner_id = NULL, claim_expires_at_ms = NULL
         WHERE operation_key = ?2 AND state IN ('claimed', 'dispatching', 'recovering')
           AND claim_owner_id = ?3 AND claim_generation = ?4
         RETURNING operation_key`,
      )
      .bind(errorCode, claim.operationKey, claim.ownerId, claim.generation)
      .first();
    if (!row) throw new IdentityProvisioningFenceError();
  }
}
