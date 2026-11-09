import type { D1Database } from "@cloudflare/workers-types";
import { z } from "zod";

import { logEvent } from "../shared/log-event.ts";

const ResourceKeySchema = z
  .string()
  .regex(/^[a-z0-9]+(?:[./:-][a-z0-9]+)*$/u)
  .brand<"ResourceLeaseKey">();
const OwnerIdSchema = z.uuid().brand<"ResourceLeaseOwnerId">();
const GenerationSchema = z
  .number()
  .int()
  .positive()
  .brand<"ResourceLeaseGeneration">();
const EpochMillisecondsSchema = z
  .number()
  .int()
  .nonnegative()
  .brand<"EpochMilliseconds">();
const NonnegativeDurationSchema = z
  .number()
  .int()
  .nonnegative()
  .brand<"NonnegativeDurationMilliseconds">();
const PositiveDurationSchema = z
  .number()
  .int()
  .positive()
  .brand<"PositiveDurationMilliseconds">();
const LeaseRowSchema = z.strictObject({
  "expires_at_ms": EpochMillisecondsSchema,
  generation: GenerationSchema,
  "owner_id": OwnerIdSchema,
});
const ActiveResourceLeaseSchema = z.strictObject({
  expiresAtMs: EpochMillisecondsSchema,
  generation: GenerationSchema,
  ownerId: OwnerIdSchema,
  resourceKey: ResourceKeySchema,
});

export type ResourceLeaseKey = z.output<typeof ResourceKeySchema>;
export type ResourceLeaseGeneration = z.output<typeof GenerationSchema>;

export type ActiveResourceLease = z.output<typeof ActiveResourceLeaseSchema>;

export type ResourceLeaseAcquisition =
  | { readonly kind: "acquired"; readonly lease: ActiveResourceLease }
  | { readonly kind: "busy" };

export interface ResourceLeaseRepository {
  acquire(
    resourceKey: ResourceLeaseKey,
    durationMs: number,
  ): Promise<ResourceLeaseAcquisition>;
  assertActive(
    lease: ActiveResourceLease,
    minRemainingMs?: number,
  ): Promise<void>;
  release(lease: ActiveResourceLease): Promise<void>;
}

export type ResourceLeaseExecution<Result> =
  | { readonly kind: "busy" }
  | { readonly kind: "completed"; readonly result: Result };

export class ResourceLeaseFencedError extends Error {
  readonly generation: ResourceLeaseGeneration;
  readonly resourceKey: ResourceLeaseKey;

  constructor(lease: ActiveResourceLease, options?: ErrorOptions) {
    super("resource_lease_fenced", options);
    this.generation = lease.generation;
    this.name = "ResourceLeaseFencedError";
    this.resourceKey = lease.resourceKey;
  }
}

export function resourceLeaseKey(value: string): ResourceLeaseKey {
  return ResourceKeySchema.parse(value);
}

export function activeResourceLease(
  value: z.input<typeof ActiveResourceLeaseSchema>,
): ActiveResourceLease {
  return ActiveResourceLeaseSchema.parse(value);
}

export async function withResourceLease<Result>(
  repository: ResourceLeaseRepository,
  resourceKey: ResourceLeaseKey,
  durationMs: number,
  operation: (lease: ActiveResourceLease) => Promise<Result>,
): Promise<ResourceLeaseExecution<Result>> {
  const acquisition = await repository.acquire(resourceKey, durationMs);
  if (acquisition.kind === "busy") return acquisition;

  let operationFailed = false;
  let operationError: unknown;
  let result!: Result;
  try {
    result = await operation(acquisition.lease);
  } catch (error) {
    operationFailed = true;
    operationError = error;
  }
  try {
    await repository.release(acquisition.lease);
  } catch (releaseError) {
    if (!operationFailed) throw releaseError;
    logEvent("resource_lease.release_failed", {
      error:
        releaseError instanceof Error
          ? releaseError.message
          : String(releaseError),
      generation: acquisition.lease.generation,
      "resource_key": acquisition.lease.resourceKey,
    });
  }
  if (operationFailed) throw operationError;
  return { kind: "completed", result };
}

export const SLACK_USER_GROUPS_RESOURCE_LEASE_KEY = resourceLeaseKey(
  "identity-sync/slack-user-groups",
);

export class D1ResourceLeaseRepository implements ResourceLeaseRepository {
  readonly #clock: () => number;
  readonly #db: D1Database;
  readonly #ownerIdFactory: () => string;

  constructor(
    db: D1Database,
    options: {
      readonly clock?: () => number;
      readonly ownerIdFactory?: () => string;
    } = {},
  ) {
    this.#clock = options.clock ?? Date.now;
    this.#db = db;
    this.#ownerIdFactory =
      options.ownerIdFactory ?? (() => crypto.randomUUID());
  }

  async acquire(
    resourceKey: ResourceLeaseKey,
    durationMs: number,
  ): Promise<ResourceLeaseAcquisition> {
    const duration = PositiveDurationSchema.parse(durationMs);
    const now = EpochMillisecondsSchema.parse(this.#clock());
    const expiresAtMs = EpochMillisecondsSchema.parse(now + duration);
    const ownerId = OwnerIdSchema.parse(this.#ownerIdFactory());
    const raw = await this.#db
      .prepare(
        `INSERT INTO automation_singleton_lease
           (lease_key, owner_id, expires_at_ms, generation)
         VALUES (?1, ?2, ?3, 1)
         ON CONFLICT (lease_key) DO UPDATE SET
           owner_id = excluded.owner_id,
           expires_at_ms = excluded.expires_at_ms,
           generation = automation_singleton_lease.generation + 1
         WHERE automation_singleton_lease.expires_at_ms <= ?4
         RETURNING owner_id, expires_at_ms, generation`,
      )
      .bind(resourceKey, ownerId, expiresAtMs, now)
      .first();
    if (!raw) return { kind: "busy" };
    const row = LeaseRowSchema.parse(raw);
    if (row["owner_id"] !== ownerId)
      throw new Error("resource_lease_owner_mismatch");
    return {
      kind: "acquired",
      lease: activeResourceLease({
        expiresAtMs: row["expires_at_ms"],
        generation: row.generation,
        ownerId: row["owner_id"],
        resourceKey,
      }),
    };
  }

  async assertActive(
    lease: ActiveResourceLease,
    rawMinRemainingMs = 0,
  ): Promise<void> {
    const now = EpochMillisecondsSchema.parse(this.#clock());
    const minRemainingMs = NonnegativeDurationSchema.parse(rawMinRemainingMs);
    const requiredUntilMs = EpochMillisecondsSchema.parse(now + minRemainingMs);
    const raw = await this.#db
      .prepare(
        `SELECT owner_id, expires_at_ms, generation
         FROM automation_singleton_lease
         WHERE lease_key = ?1
           AND owner_id = ?2
           AND generation = ?3
           AND expires_at_ms > ?4
           AND expires_at_ms >= ?5`,
      )
      .bind(
        lease.resourceKey,
        lease.ownerId,
        lease.generation,
        now,
        requiredUntilMs,
      )
      .first();
    if (!raw) throw new ResourceLeaseFencedError(lease);
    LeaseRowSchema.parse(raw);
  }

  async release(lease: ActiveResourceLease): Promise<void> {
    await this.#db
      .prepare(
        `UPDATE automation_singleton_lease
         SET expires_at_ms = 0
         WHERE lease_key = ?1 AND owner_id = ?2 AND generation = ?3`,
      )
      .bind(lease.resourceKey, lease.ownerId, lease.generation)
      .run();
  }
}
