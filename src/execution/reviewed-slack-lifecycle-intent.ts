import type { D1Database, D1DatabaseSession } from "@cloudflare/workers-types";
import { z } from "zod";

import { sameJson, sha256Hex } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import { ReviewedSlackLifecycleRemovalSchema } from "../org-sync/reviewed-lifecycle-removal.ts";
import { ReviewedGoogleGroupCleanupIntentSchema } from "./reviewed-google-group-cleanup.ts";
import { ReviewedLinearSuspensionSchema } from "./reviewed-linear-suspension.ts";

const HashSchema = z.string().regex(/^[a-f0-9]{64}$/u);
const INTENT_INVALID = "workspace_reviewed_lifecycle_intent_invalid";
const INTENT_EXPIRED = "workspace_reviewed_lifecycle_intent_expired";

export function isReviewedPlanWithinOriginalApproval(
  proof: { generatedAtMs: number; expiresAtMs: number },
  generatedAt: string,
): boolean {
  const generatedAtMs = Date.parse(generatedAt);
  return (
    Number.isFinite(generatedAtMs) &&
    generatedAtMs >= proof.generatedAtMs &&
    generatedAtMs < proof.expiresAtMs
  );
}
const IntentStateSchema = z.enum(["pending", "claimed"]);

export const ReviewedSlackLifecycleIntentProofSchema = z
  .strictObject({
    actorHash: HashSchema,
    branchHash: HashSchema,
    expiresAtMs: z.number().int().nonnegative(),
    generatedAtMs: z.number().int().nonnegative(),
    leafPlanHash: HashSchema,
    originalPlanHash: HashSchema,
    reviewed: ReviewedSlackLifecycleRemovalSchema,
    sourceHash: HashSchema,
  })
  .refine(
    (proof) =>
      proof.expiresAtMs > proof.generatedAtMs &&
      proof.expiresAtMs <= proof.generatedAtMs + 600_000,
    "original approval expiry must not exceed ten minutes",
  );

export type ReviewedSlackLifecycleIntentProof = z.output<
  typeof ReviewedSlackLifecycleIntentProofSchema
>;

export const ReviewedLinearIntentProofSchema = z
  .strictObject({
    ...ReviewedSlackLifecycleIntentProofSchema.shape,
    provider: z.literal("linear"),
    reviewed: ReviewedLinearSuspensionSchema,
    beforeHash: HashSchema,
    afterHash: HashSchema,
  })
  .refine(
    (proof) =>
      proof.expiresAtMs > proof.generatedAtMs &&
      proof.expiresAtMs <= proof.generatedAtMs + 600_000,
    "original approval expiry must not exceed ten minutes",
  );
export const ReviewedGoogleGroupCleanupIntentProofSchema = z
  .strictObject({
    ...ReviewedSlackLifecycleIntentProofSchema.shape,
    provider: z.literal("google-group-cleanup"),
    reviewed: ReviewedGoogleGroupCleanupIntentSchema,
    beforeHash: HashSchema,
    afterHash: HashSchema,
  })
  .refine(
    (proof) =>
      proof.expiresAtMs > proof.generatedAtMs &&
      proof.expiresAtMs <= proof.generatedAtMs + 600_000,
    "original approval expiry must not exceed ten minutes",
  );
export const ReviewedProviderIntentProofSchema = z.union([
  ReviewedSlackLifecycleIntentProofSchema,
  ReviewedLinearIntentProofSchema,
  ReviewedGoogleGroupCleanupIntentProofSchema,
]);
export type ReviewedProviderIntentProof = z.output<
  typeof ReviewedProviderIntentProofSchema
>;

export const ClaimedReviewedSlackLifecycleIntentSchema = z
  .strictObject({
    claimedAtMs: z.number().int().nonnegative(),
    claimedTickId: HashSchema,
    intentId: HashSchema,
    proof: ReviewedSlackLifecycleIntentProofSchema,
    state: z.literal("claimed"),
  })
  .refine(
    (intent) =>
      intent.claimedAtMs >= intent.proof.generatedAtMs &&
      intent.claimedAtMs < intent.proof.expiresAtMs,
    "claim must be inside original approval lifetime",
  );

export const ClaimedReviewedProviderIntentSchema = z
  .strictObject({
    ...ClaimedReviewedSlackLifecycleIntentSchema.shape,
    proof: ReviewedProviderIntentProofSchema,
  })
  .refine(
    (intent) =>
      intent.claimedAtMs >= intent.proof.generatedAtMs &&
      intent.claimedAtMs < intent.proof.expiresAtMs,
    "claim must be inside original approval lifetime",
  );
export type ReviewedProviderIntent = ReviewedSlackLifecycleIntent;
export type IReviewedProviderIntentAdmission =
  IReviewedSlackLifecycleIntentAdmission;
export type IReviewedProviderIntentClaims = IReviewedSlackLifecycleIntentClaims;

export interface ReviewedSlackLifecycleIntent {
  readonly claimedAtMs: null | number;
  readonly claimedTickId: null | string;
  readonly intentId: string;
  readonly proof: ReviewedProviderIntentProof;
  readonly state: "claimed" | "pending";
}

const RowSchema = z.strictObject({
  "claimed_at_ms": z.number().int().nullable(),
  "claimed_tick_id": HashSchema.nullable(),
  "expires_at_ms": z.number().int(),
  "intent_id": HashSchema,
  "proof_json": z.string(),
  state: IntentStateSchema,
});

export interface IReviewedSlackLifecycleIntentAdmission {
  admit(
    proof: ReviewedProviderIntentProof,
  ): Promise<ReviewedSlackLifecycleIntent>;
}

export interface IReviewedSlackLifecycleIntentClaims {
  assertClaimed(
    expected: ReviewedSlackLifecycleIntent,
    tickId: string,
  ): Promise<void>;
  claim(tickId: string): Promise<null | ReviewedSlackLifecycleIntent>;
  read(intentId: string): Promise<null | ReviewedSlackLifecycleIntent>;
}

export class ReviewedSlackLifecycleIntentRepository
  implements
    IReviewedSlackLifecycleIntentAdmission,
    IReviewedSlackLifecycleIntentClaims
{
  readonly #database: D1Database;
  readonly #now: () => number;
  #primarySession: D1DatabaseSession | undefined;

  constructor(database: D1Database, now: () => number = Date.now) {
    this.#database = database;
    this.#now = now;
  }

  async admit(
    rawProof: ReviewedProviderIntentProof,
  ): Promise<ReviewedSlackLifecycleIntent> {
    const proof = ReviewedProviderIntentProofSchema.parse(rawProof);
    this.#assertFresh(proof);
    const intentId = await sha256Hex(JsonValueSchema.parse(proof));
    this.#assertFresh(proof);
    await this.#primary
      .prepare(`INSERT INTO workspace_reviewed_slack_lifecycle_intent
      (intent_id, proof_json, expires_at_ms, state) VALUES (?1, ?2, ?3, 'pending')
      ON CONFLICT(intent_id) DO NOTHING`)
      .bind(intentId, JSON.stringify(proof), proof.expiresAtMs)
      .run();
    const stored = await this.#read(intentId);
    if (
      stored === null ||
      !sameJson(
        JsonValueSchema.parse(stored.proof),
        JsonValueSchema.parse(proof),
      )
    )
      throw new Error(INTENT_INVALID);
    this.#assertFresh(stored.proof);
    return stored;
  }

  async claim(tickId: string): Promise<null | ReviewedSlackLifecycleIntent> {
    const tick = HashSchema.parse(tickId);
    const original = await this.#primary
      .prepare(
        "SELECT intent_id FROM workspace_reviewed_slack_lifecycle_intent WHERE claimed_tick_id = ?1",
      )
      .bind(tick)
      .first();
    if (original !== null)
      throw new Error("workspace_reviewed_lifecycle_claim_already_consumed");
    const now = this.#now();
    const row = await this.#primary
      .prepare(`UPDATE workspace_reviewed_slack_lifecycle_intent
      SET state = 'claimed', claimed_tick_id = ?1, claimed_at_ms = ?2
      WHERE intent_id = (
        SELECT intent_id FROM workspace_reviewed_slack_lifecycle_intent
        WHERE state = 'pending' AND expires_at_ms > ?2
        ORDER BY expires_at_ms, intent_id LIMIT 1
      ) AND state = 'pending' AND expires_at_ms > ?2
      RETURNING intent_id, proof_json, expires_at_ms, state, claimed_tick_id, claimed_at_ms`)
      .bind(tick, now)
      .first();
    if (row === null) return null;
    const claimed = await decode(row);
    if (
      claimed.state !== "claimed" ||
      claimed.claimedTickId !== tick ||
      claimed.claimedAtMs !== now
    )
      throw new Error(INTENT_INVALID);
    this.#assertFresh(claimed.proof);
    return claimed;
  }

  async read(intentId: string): Promise<null | ReviewedSlackLifecycleIntent> {
    return this.#read(intentId);
  }

  async assertClaimed(
    expected: ReviewedSlackLifecycleIntent,
    tickId: string,
  ): Promise<void> {
    this.#assertFresh(expected.proof);
    const current = await this.read(expected.intentId);
    if (
      current?.state !== "claimed" ||
      current.claimedTickId !== tickId ||
      !sameJson(JsonValueSchema.parse(current), JsonValueSchema.parse(expected))
    )
      throw new Error("workspace_reviewed_lifecycle_original_claim_required");
    this.#assertFresh(current.proof);
  }

  async #read(intentId: string): Promise<null | ReviewedSlackLifecycleIntent> {
    const row = await this.#primary
      .prepare(
        "SELECT intent_id, proof_json, expires_at_ms, state, claimed_tick_id, claimed_at_ms FROM workspace_reviewed_slack_lifecycle_intent WHERE intent_id = ?1",
      )
      .bind(HashSchema.parse(intentId))
      .first();
    return row === null ? null : decode(row);
  }

  get #primary(): D1DatabaseSession {
    // APPLY admission and the next scheduled claim can execute in different
    // colo sessions. Always route this small authorization ledger to primary;
    // a stale replica miss would let the scheduled reconciler run the same
    // action independently while the reviewed intent remained pending. Keep
    // session creation lazy so route/OpenAPI construction remains storage-free.
    this.#primarySession ??= this.#database.withSession("first-primary");
    return this.#primarySession;
  }

  #assertFresh(proof: ReviewedProviderIntentProof): void {
    const now = this.#now();
    if (now < proof.generatedAtMs || now >= proof.expiresAtMs)
      throw new Error(INTENT_EXPIRED);
  }
}

async function decode(raw: unknown): Promise<ReviewedSlackLifecycleIntent> {
  const row = RowSchema.parse(raw);
  const proof = ReviewedProviderIntentProofSchema.parse(
    JSON.parse(row["proof_json"]),
  );
  if (
    row["expires_at_ms"] !== proof.expiresAtMs ||
    (await sha256Hex(JsonValueSchema.parse(proof))) !== row["intent_id"] ||
    (row.state === "pending" &&
      (row["claimed_tick_id"] !== null || row["claimed_at_ms"] !== null)) ||
    (row.state === "claimed" &&
      (row["claimed_tick_id"] === null || row["claimed_at_ms"] === null))
  )
    throw new Error(INTENT_INVALID);
  return {
    intentId: row["intent_id"],
    proof,
    state: row.state,
    claimedTickId: row["claimed_tick_id"],
    claimedAtMs: row["claimed_at_ms"],
  };
}
