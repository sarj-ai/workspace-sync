import type { D1Database, D1DatabaseSession } from "@cloudflare/workers-types";
import { z } from "zod";

import {
  type ActiveResourceLease,
  activeResourceLease,
  type ResourceLeaseAcquisition,
  ResourceLeaseFencedError,
  resourceLeaseKey,
} from "../identity-sync/resource-lease.ts";

const PositiveDurationSchema = z.number().int().positive();
const EpochMillisecondsSchema = z.number().int().nonnegative();
const OwnerIdSchema = z.uuid();
const LeaseRowSchema = z.strictObject({
  "expires_at_ms": EpochMillisecondsSchema,
  generation: z.number().int().positive(),
  "owner_id": z.uuid(),
});

export const WORKSPACE_DEPLOYMENT_FENCE_KEY = resourceLeaseKey(
  "workspace-directory/deployment",
);

export interface WorkspaceDeploymentFenceRepository {
  acquire(durationMs: number): Promise<ResourceLeaseAcquisition>;
  read(): Promise<ActiveResourceLease | null>;
  release(fence: ActiveResourceLease): Promise<void>;
}

/** Coordinates deployment with scheduler admission only; it grants no provider-write authority. */
export class D1WorkspaceDeploymentFenceRepository implements WorkspaceDeploymentFenceRepository {
  readonly #clock: () => number;
  readonly #db: D1DatabaseSession;
  readonly #ownerIdFactory: () => string;

  constructor(
    database: D1Database,
    options: {
      readonly clock?: () => number;
      readonly ownerIdFactory?: () => string;
    } = {},
  ) {
    this.#clock = options.clock ?? Date.now;
    this.#db = database.withSession("first-primary");
    this.#ownerIdFactory =
      options.ownerIdFactory ?? (() => crypto.randomUUID());
  }

  async acquire(durationMs: number): Promise<ResourceLeaseAcquisition> {
    const duration = PositiveDurationSchema.parse(durationMs);
    const now = EpochMillisecondsSchema.parse(this.#clock());
    const expiresAtMs = EpochMillisecondsSchema.parse(now + duration);
    const ownerId = OwnerIdSchema.parse(this.#ownerIdFactory());
    const raw = await this.#db
      .prepare(
        `INSERT INTO automation_singleton_lease
           (lease_key, owner_id, expires_at_ms, generation)
         SELECT ?1, ?2, ?3, 1
         WHERE NOT EXISTS (
           SELECT 1 FROM workspace_directory_schedule_tick
           WHERE json_extract(snapshot_json, '$.phase') != 'terminal'
         )
         ON CONFLICT (lease_key) DO UPDATE SET
           owner_id = excluded.owner_id,
           expires_at_ms = excluded.expires_at_ms,
           generation = automation_singleton_lease.generation + 1
         WHERE automation_singleton_lease.expires_at_ms <= ?4
         RETURNING owner_id, expires_at_ms, generation`,
      )
      .bind(WORKSPACE_DEPLOYMENT_FENCE_KEY, ownerId, expiresAtMs, now)
      .first();
    if (raw === null) return { kind: "busy" };
    const row = LeaseRowSchema.parse(raw);
    if (row["owner_id"] !== ownerId)
      throw new Error("workspace_deployment_fence_owner_mismatch");
    return {
      kind: "acquired",
      lease: activeResourceLease({
        expiresAtMs: row["expires_at_ms"],
        generation: row.generation,
        ownerId: row["owner_id"],
        resourceKey: WORKSPACE_DEPLOYMENT_FENCE_KEY,
      }),
    };
  }

  async read(): Promise<ActiveResourceLease | null> {
    const now = EpochMillisecondsSchema.parse(this.#clock());
    const raw = await this.#db
      .prepare(
        `SELECT owner_id, expires_at_ms, generation
         FROM automation_singleton_lease
         WHERE lease_key = ?1 AND expires_at_ms > ?2`,
      )
      .bind(WORKSPACE_DEPLOYMENT_FENCE_KEY, now)
      .first();
    if (raw === null) return null;
    const row = LeaseRowSchema.parse(raw);
    return activeResourceLease({
      expiresAtMs: row["expires_at_ms"],
      generation: row.generation,
      ownerId: row["owner_id"],
      resourceKey: WORKSPACE_DEPLOYMENT_FENCE_KEY,
    });
  }

  async release(rawFence: ActiveResourceLease): Promise<void> {
    const fence = activeResourceLease(rawFence);
    if (fence.resourceKey !== WORKSPACE_DEPLOYMENT_FENCE_KEY) {
      throw new ResourceLeaseFencedError(fence);
    }
    const result = await this.#db
      .prepare(
        `UPDATE automation_singleton_lease SET expires_at_ms = 0
         WHERE lease_key = ?1 AND owner_id = ?2 AND generation = ?3`,
      )
      .bind(WORKSPACE_DEPLOYMENT_FENCE_KEY, fence.ownerId, fence.generation)
      .run();
    if (result.meta.changes === 1 || (await this.read()) === null) return;
    throw new ResourceLeaseFencedError(fence);
  }
}
