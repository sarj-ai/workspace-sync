import type { D1Database } from "@cloudflare/workers-types";
import { z } from "zod";

import type { GoogleDirectoryWatchNotification } from "./contracts.ts";

const CLAIM_DURATION_MS = 60_000;
const ClaimedNotificationRowSchema = z.strictObject({
  generation: z.number().int().positive(),
});
const ExistingNotificationRowSchema = z.strictObject({
  "lease_expires_at_ms": z.number().int().nonnegative(),
  status: z.enum(["claimed", "enqueued", "failed", "ignored"]),
});

export interface GoogleWatchNotificationLease {
  readonly channelId: string;
  readonly generation: number;
  readonly messageNumber: string;
  readonly ownerId: string;
}

export type GoogleWatchNotificationClaim =
  | { readonly kind: "acquired"; readonly lease: GoogleWatchNotificationLease }
  | { readonly kind: "duplicate"; readonly outcome: "enqueued" | "ignored" }
  | { readonly kind: "in-flight"; readonly retryAfterSeconds: number };

export interface GoogleWatchNotificationReceiptStore {
  claim(
    notification: GoogleDirectoryWatchNotification,
    nowMs: number,
  ): Promise<GoogleWatchNotificationClaim>;
  finish(
    lease: GoogleWatchNotificationLease,
    outcome: "enqueued" | "failed" | "ignored",
    nowMs: number,
  ): Promise<boolean>;
}

export class D1GoogleWatchNotificationReceiptStore implements GoogleWatchNotificationReceiptStore {
  readonly #db: D1Database;

  constructor(db: D1Database) {
    this.#db = db;
  }

  async claim(
    notification: GoogleDirectoryWatchNotification,
    nowMs: number,
  ): Promise<GoogleWatchNotificationClaim> {
    const ownerId = crypto.randomUUID();
    const leaseExpiresAtMs = nowMs + CLAIM_DURATION_MS;
    const result = await this.#db
      .prepare(
        `INSERT INTO google_directory_watch_notification
           (channel_id, message_number, resource_state, status, owner_id, generation,
            received_at_ms, lease_expires_at_ms, finished_at_ms)
         VALUES (?1, ?2, ?3, 'claimed', ?4, 1, ?5, ?6, NULL)
         ON CONFLICT(channel_id, message_number) DO UPDATE SET
           resource_state = excluded.resource_state,
           status = 'claimed',
           owner_id = excluded.owner_id,
           generation = google_directory_watch_notification.generation + 1,
           received_at_ms = excluded.received_at_ms,
           lease_expires_at_ms = excluded.lease_expires_at_ms,
           finished_at_ms = NULL
         WHERE google_directory_watch_notification.status = 'failed'
            OR (google_directory_watch_notification.status = 'claimed'
                AND google_directory_watch_notification.lease_expires_at_ms <= ?5)`,
      )
      .bind(
        notification.channelId,
        notification.messageNumber,
        notification.event,
        ownerId,
        nowMs,
        leaseExpiresAtMs,
      )
      .run();
    if (result.meta.changes === 1) {
      const raw = await this.#db
        .prepare(
          `SELECT generation FROM google_directory_watch_notification
           WHERE channel_id = ?1 AND message_number = ?2 AND owner_id = ?3 AND status = 'claimed'`,
        )
        .bind(notification.channelId, notification.messageNumber, ownerId)
        .first();
      if (!raw) throw new Error("google_watch_notification_claim_lost");
      const row = ClaimedNotificationRowSchema.parse(raw);
      return {
        kind: "acquired",
        lease: {
          channelId: notification.channelId,
          generation: row.generation,
          messageNumber: notification.messageNumber,
          ownerId,
        },
      };
    }
    const raw = await this.#db
      .prepare(
        `SELECT status, lease_expires_at_ms FROM google_directory_watch_notification
         WHERE channel_id = ?1 AND message_number = ?2`,
      )
      .bind(notification.channelId, notification.messageNumber)
      .first();
    if (raw === null)
      throw new Error("google_watch_notification_missing_after_claim_conflict");
    const existing = ExistingNotificationRowSchema.parse(raw);
    switch (existing.status) {
      case "enqueued":
      case "ignored":
        return { kind: "duplicate", outcome: existing.status };
      case "failed":
        return { kind: "in-flight", retryAfterSeconds: 1 };
      case "claimed":
        return {
          kind: "in-flight",
          retryAfterSeconds: Math.max(
            1,
            Math.ceil((existing["lease_expires_at_ms"] - nowMs) / 1000),
          ),
        };
      default: {
        const unsupported: never = existing.status;
        throw new Error(
          `unsupported_google_notification_state:${String(unsupported)}`,
        );
      }
    }
  }

  async finish(
    lease: GoogleWatchNotificationLease,
    outcome: "enqueued" | "failed" | "ignored",
    nowMs: number,
  ): Promise<boolean> {
    const result = await this.#db
      .prepare(
        `UPDATE google_directory_watch_notification
         SET status = ?5, finished_at_ms = ?6
         WHERE channel_id = ?1 AND message_number = ?2 AND owner_id = ?3
           AND generation = ?4 AND status = 'claimed'`,
      )
      .bind(
        lease.channelId,
        lease.messageNumber,
        lease.ownerId,
        lease.generation,
        outcome,
        nowMs,
      )
      .run();
    return result.meta.changes === 1;
  }
}
