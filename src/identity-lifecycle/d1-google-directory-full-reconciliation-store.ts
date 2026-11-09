import type { D1Database } from "@cloudflare/workers-types";

import { isActiveGoogleUser } from "../google-workspace/user-lifecycle.ts";
import { sha256Hex } from "../operations/canonical.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import { authorityPayloadHash } from "./authority-payload-hash.ts";
import { authoritativeGoogleDirectoryUserState } from "./contracts.ts";

export interface GoogleDirectoryFullReconciliationStore {
  begin(
    runId: string,
    scheduledAtMs: number,
    startedAtMs: number,
  ): Promise<void>;
  captureInventory(
    runId: string,
    scheduledAtMs: number,
    users: readonly GoogleDirectoryUser[],
  ): Promise<void>;
  complete(runId: string, completedAtMs: number): Promise<boolean>;
  fail(runId: string, completedAtMs: number): Promise<void>;
}

export class D1GoogleDirectoryFullReconciliationStore implements GoogleDirectoryFullReconciliationStore {
  readonly #db: D1Database;
  readonly #deployment: { readonly id: string; readonly tag?: string };
  readonly #requiredAdminSubject: string;
  readonly #minimumUsers: number;
  readonly #rootGoogleUserIds: readonly string[];

  constructor(
    db: D1Database,
    deployment: { readonly id: string; readonly tag?: string },
    requiredAdminSubject: string,
    minimumUsers: number,
    rootGoogleUserIds: readonly string[],
  ) {
    this.#db = db;
    this.#deployment = deployment;
    this.#requiredAdminSubject = requiredAdminSubject.toLowerCase();
    this.#minimumUsers = minimumUsers;
    this.#rootGoogleUserIds = rootGoogleUserIds;
  }

  async begin(
    runId: string,
    scheduledAtMs: number,
    startedAtMs: number,
  ): Promise<void> {
    await this.#db
      .prepare(
        `INSERT INTO google_directory_full_reconciliation_run
         (run_id, scheduled_at_ms, started_at_ms, worker_version_id, worker_revision, state)
         VALUES (?1, ?2, ?3, ?4, ?5, 'started')`,
      )
      .bind(
        runId,
        scheduledAtMs,
        startedAtMs,
        this.#deployment.id,
        this.#deployment.tag ?? null,
      )
      .run();
  }

  async captureInventory(
    runId: string,
    scheduledAtMs: number,
    users: readonly GoogleDirectoryUser[],
  ): Promise<void> {
    if (
      users.length < this.#minimumUsers ||
      this.#rootGoogleUserIds.some(
        (id) =>
          !users.some((user) => user.id === id && isActiveGoogleUser(user)),
      )
    ) {
      throw new Error("google_directory_full_inventory_incomplete");
    }
    if (
      !users.some(
        (user) =>
          user.primaryEmail.toLowerCase() === this.#requiredAdminSubject &&
          user.deletionTime === undefined,
      )
    ) {
      throw new Error("google_directory_full_inventory_admin_missing");
    }
    const expected = await Promise.all(
      users.map(async (user) => ({
        eventKey: `google-directory:full:${String(scheduledAtMs)}:${user.id}`,
        eventKind: user.deletionTime === undefined ? "update" : "delete",
        payloadHash: await authorityPayloadHash(
          authoritativeGoogleDirectoryUserState(user),
        ),
      })),
    );
    const result = await this.#db
      .prepare(
        `UPDATE google_directory_full_reconciliation_run
         SET expected_events_json = ?1, expected_count = ?2, manifest_hash = ?3
         WHERE run_id = ?4 AND scheduled_at_ms = ?5
           AND state = 'started' AND expected_events_json IS NULL`,
      )
      .bind(
        JSON.stringify(expected),
        expected.length,
        await sha256Hex(expected),
        runId,
        scheduledAtMs,
      )
      .run();
    if (result.meta.changes !== 1)
      throw new Error("google_directory_full_inventory_not_recorded");
  }

  async complete(runId: string, completedAtMs: number): Promise<boolean> {
    // A skipped claim or a crash can leave a prefix of completed events. Require the exact
    // inventory and payload set; a successful loop or an aggregate event count is insufficient.
    const result = await this.#db
      .prepare(
        `UPDATE google_directory_full_reconciliation_run
         SET state = 'completed', completed_at_ms = ?2
         WHERE run_id = ?1 AND state = 'started' AND expected_events_json IS NOT NULL
           AND expected_count = json_array_length(expected_events_json)
           AND NOT EXISTS (
             SELECT 1 FROM json_each(expected_events_json) AS expected
             LEFT JOIN identity_lifecycle_event AS event
               ON event.event_key = json_extract(expected.value, '$.eventKey')
             WHERE event.event_key IS NULL OR event.state != 'completed'
               OR event.completed_at_ms IS NULL
               OR event.completed_at_ms > ?2
               OR event.payload_hash != json_extract(expected.value, '$.payloadHash')
               OR event.event_kind != json_extract(expected.value, '$.eventKind')
               OR event.occurred_at_ms != scheduled_at_ms
           )`,
      )
      .bind(runId, completedAtMs)
      .run();
    return result.meta.changes === 1;
  }

  async fail(runId: string, completedAtMs: number): Promise<void> {
    await this.#db
      .prepare(
        `UPDATE google_directory_full_reconciliation_run
         SET state = 'failed', completed_at_ms = ?2
         WHERE run_id = ?1 AND state = 'started'`,
      )
      .bind(runId, completedAtMs)
      .run();
  }
}
