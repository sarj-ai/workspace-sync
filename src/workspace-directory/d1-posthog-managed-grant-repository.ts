import type { D1Database } from "@cloudflare/workers-types";
import { z } from "zod";

import {
  ResourceLeaseFencedError,
  type ActiveResourceLease,
} from "../identity-sync/resource-lease.ts";
import { PosthogIdSchema } from "./posthog-membership-client.ts";
import {
  PosthogManagedGrantSchema,
  type IPosthogManagedGrantRepository,
  type PosthogManagedGrant,
} from "./posthog-membership-plan.ts";

/** The host owns the migration; retired rows prevent re-adopting later manual grants. */
export class D1PosthogManagedGrantRepository implements IPosthogManagedGrantRepository {
  readonly #database: D1Database;
  constructor(database: D1Database) {
    this.#database = database;
  }
  async list(organizationId: string): Promise<PosthogManagedGrant[]> {
    const result = await this.#database
      .withSession("first-primary")
      .prepare(`
      SELECT google_user_id AS googleUserId, email, invite_id AS inviteId, user_uuid AS userUuid, state
      FROM workspace_posthog_managed_grant WHERE organization_id = ?1 ORDER BY google_user_id
    `)
      .bind(PosthogIdSchema.parse(organizationId))
      .all();
    return z.array(PosthogManagedGrantSchema).max(10_000).parse(result.results);
  }
  async record(
    organizationId: string,
    raw: PosthogManagedGrant,
    lease: ActiveResourceLease,
  ): Promise<void> {
    if (lease.resourceKey !== `workspace-directory/posthog/${organizationId}`)
      throw new ResourceLeaseFencedError(lease);
    const grant = PosthogManagedGrantSchema.parse(raw);
    const result = await this.#database
      .withSession("first-primary")
      .prepare(`
      INSERT INTO workspace_posthog_managed_grant
        (organization_id, google_user_id, email, invite_id, user_uuid, state, updated_at_ms)
      SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7
      WHERE EXISTS (SELECT 1 FROM automation_singleton_lease
        WHERE lease_key = ?8 AND owner_id = ?9 AND generation = ?10
          AND expires_at_ms > CAST(unixepoch('subsec') * 1000 AS INTEGER))
      ON CONFLICT (organization_id, google_user_id) DO UPDATE SET
        email = excluded.email, invite_id = excluded.invite_id, user_uuid = excluded.user_uuid,
        state = excluded.state, updated_at_ms = excluded.updated_at_ms
    `)
      .bind(
        PosthogIdSchema.parse(organizationId),
        grant.googleUserId,
        grant.email,
        grant.inviteId,
        grant.userUuid,
        grant.state,
        Date.now(),
        lease.resourceKey,
        lease.ownerId,
        lease.generation,
      )
      .run();
    if (result.meta.changes !== 1) throw new ResourceLeaseFencedError(lease);
  }
}
