import type { D1Database } from "@cloudflare/workers-types";
import { z } from "zod";

import { sha256 } from "../runtime/sha256.ts";
import { GOOGLE_DIRECTORY_WATCH_EVENTS } from "./channel-manager.ts";
import type { GoogleDirectoryWatchNotification } from "./contracts.ts";

const WatchEventSchema = z.enum(GOOGLE_DIRECTORY_WATCH_EVENTS);
const ActiveWatchChannelSchema = z.strictObject({
  "channel_id": z.string().min(16).max(64),
  "event_kind": WatchEventSchema,
  "expires_at_ms": z.number().int().positive(),
  "resource_id": z.string(),
  "resource_uri": z.url({ protocol: /^https$/u }),
  "token_sha256": z.string().regex(/^[a-f0-9]{64}$/u),
});

export type GoogleWatchChannelAuthentication =
  | { readonly kind: "authenticated" }
  | {
      readonly kind: "rejected";
      readonly reason: "expired" | "mismatch" | "unknown";
    };

export interface GoogleWatchChannelAuthenticator {
  authenticate(
    notification: GoogleDirectoryWatchNotification,
    nowMs: number,
  ): Promise<GoogleWatchChannelAuthentication>;
}

export async function googleWatchTokenSha256(token: string): Promise<string> {
  return sha256(token);
}

function constantTimeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |=
      (left.codePointAt(index) ?? 0) ^ (right.codePointAt(index) ?? 0);
  }
  return difference === 0;
}

export class D1GoogleWatchChannelAuthenticator implements GoogleWatchChannelAuthenticator {
  readonly #db: D1Database;

  constructor(db: D1Database) {
    this.#db = db;
  }

  async authenticate(
    notification: GoogleDirectoryWatchNotification,
    nowMs: number,
  ): Promise<GoogleWatchChannelAuthentication> {
    const raw = await this.#db
      .prepare(
        `SELECT channel_id, event_kind, resource_id, resource_uri, token_sha256, expires_at_ms
         FROM google_directory_watch_channel
         WHERE channel_id = ?1 AND status = 'active'`,
      )
      .bind(notification.channelId)
      .first();
    if (!raw) return { kind: "rejected", reason: "unknown" };
    const channel = ActiveWatchChannelSchema.parse(raw);
    if (channel["expires_at_ms"] <= nowMs)
      return { kind: "rejected", reason: "expired" };
    const receivedTokenHash = await googleWatchTokenSha256(
      notification.channelToken,
    );
    const matches =
      constantTimeEqual(channel["token_sha256"], receivedTokenHash) &&
      constantTimeEqual(channel["resource_id"], notification.resourceId) &&
      constantTimeEqual(channel["resource_uri"], notification.resourceUri) &&
      (notification.event === "sync" ||
        notification.event === channel["event_kind"]);
    return matches
      ? { kind: "authenticated" }
      : { kind: "rejected", reason: "mismatch" };
  }
}
