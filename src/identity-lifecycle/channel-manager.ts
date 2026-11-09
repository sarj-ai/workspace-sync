import type { D1Database } from "@cloudflare/workers-types";
import { z } from "zod";

export interface GoogleDirectoryWatchConfig {
  googleDirectoryWatchAddress: string;
  googleDirectoryWatchToken: string;
  orgSyncGoogleServiceAccountEmail: string;
  orgSyncGoogleServiceAccountPrivateKey: string;
  googleDirectoryLifecycleDisabled: boolean;
}

export const GOOGLE_DIRECTORY_WATCH_EVENTS = [
  "add",
  "delete",
  "makeAdmin",
  "undelete",
  "update",
] as const;
const WatchEventSchema = z.enum(GOOGLE_DIRECTORY_WATCH_EVENTS);
const ChannelIdSchema = z.string().min(16).max(64);
const ResourceIdSchema = z.string().min(1).max(512);
const ActiveChannelRowSchema = z.strictObject({
  "channel_id": ChannelIdSchema,
  "created_at_ms": z.number().int().nonnegative(),
  "event_kind": WatchEventSchema,
  "expires_at_ms": z.number().int().positive(),
  "resource_id": ResourceIdSchema,
  "resource_uri": z.url({ protocol: /^https$/u }),
});
const CreatedWatchChannelSchema = z.strictObject({
  channelId: ChannelIdSchema,
  event: WatchEventSchema,
  expiresAtMs: z.number().int().positive(),
  resourceId: ResourceIdSchema,
  resourceUri: z.url({ protocol: /^https$/u }),
});

const RENEW_BEFORE_MS = 2 * 60 * 60 * 1_000;
const WATCH_TTL_SECONDS = 24 * 60 * 60;

export type GoogleDirectoryWatchEvent = z.output<typeof WatchEventSchema>;
export type GoogleDirectoryWatchChannel = z.output<
  typeof CreatedWatchChannelSchema
>;

export type GoogleDirectoryWatchRenewalAction =
  | {
      readonly current: GoogleDirectoryWatchChannel;
      readonly event: GoogleDirectoryWatchEvent;
      readonly kind: "renew";
    }
  | { readonly event: GoogleDirectoryWatchEvent; readonly kind: "create" };

export type GoogleDirectoryWatchRenewalPlan =
  | {
      readonly actions: readonly GoogleDirectoryWatchRenewalAction[];
      readonly kind: "ready";
    }
  | { readonly kind: "blocked"; readonly missing: readonly string[] }
  | { readonly kind: "disabled" };

export type GoogleDirectoryWatchRenewalResult =
  | {
      readonly created: number;
      readonly kind: "executed";
      readonly replaced: number;
    }
  | { readonly kind: "blocked"; readonly missing: readonly string[] }
  | { readonly kind: "disabled" };

export interface GoogleDirectoryWatchRenewalPort {
  plan(nowMs: number): Promise<GoogleDirectoryWatchRenewalPlan>;
  renew(nowMs: number): Promise<GoogleDirectoryWatchRenewalResult>;
}

export interface GoogleDirectoryWatchChannelRepository {
  activate(
    channel: GoogleDirectoryWatchChannel,
    tokenSha256: string,
    nowMs: number,
  ): Promise<void>;
  listActive(): Promise<readonly GoogleDirectoryWatchChannel[]>;
  markStopped(channelId: string): Promise<void>;
}

export interface GoogleDirectoryWatchGateway {
  create(input: {
    readonly address: string;
    readonly channelId: string;
    readonly event: GoogleDirectoryWatchEvent;
    readonly token: string;
    readonly ttlSeconds: number;
  }): Promise<GoogleDirectoryWatchChannel>;
  stop(
    channel: Pick<GoogleDirectoryWatchChannel, "channelId" | "resourceId">,
  ): Promise<void>;
}
const TokenDigestSchema = z.string().regex(/^[a-f0-9]{64}$/u);

const ActiveChannelRowsSchema = z.array(ActiveChannelRowSchema);

export class D1GoogleDirectoryWatchChannelRepository implements GoogleDirectoryWatchChannelRepository {
  readonly #db: D1Database;

  constructor(db: D1Database) {
    this.#db = db;
  }

  async activate(
    rawChannel: GoogleDirectoryWatchChannel,
    tokenSha256: string,
    nowMs: number,
  ): Promise<void> {
    const channel = CreatedWatchChannelSchema.parse(rawChannel);
    const digest = TokenDigestSchema.parse(tokenSha256);
    await this.#db
      .prepare(
        `INSERT INTO google_directory_watch_channel
           (channel_id, resource_id, resource_uri, event_kind, token_sha256, status, created_at_ms, expires_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6, ?7)
         ON CONFLICT (channel_id) DO NOTHING`,
      )
      .bind(
        channel.channelId,
        channel.resourceId,
        channel.resourceUri,
        channel.event,
        digest,
        nowMs,
        channel.expiresAtMs,
      )
      .run();
  }

  async listActive(): Promise<readonly GoogleDirectoryWatchChannel[]> {
    const result = await this.#db
      .prepare(
        `SELECT channel_id, resource_id, resource_uri, event_kind, created_at_ms, expires_at_ms
         FROM google_directory_watch_channel
         WHERE status = 'active'
         ORDER BY event_kind, created_at_ms DESC, channel_id DESC`,
      )
      .all();
    return ActiveChannelRowsSchema.parse(result.results).map((row) =>
      CreatedWatchChannelSchema.parse({
        channelId: row["channel_id"],
        event: row["event_kind"],
        expiresAtMs: row["expires_at_ms"],
        resourceId: row["resource_id"],
        resourceUri: row["resource_uri"],
      }),
    );
  }

  async markStopped(channelId: string): Promise<void> {
    await this.#db
      .prepare(
        `UPDATE google_directory_watch_channel
         SET status = 'stopped'
         WHERE channel_id = ?1 AND status = 'active'`,
      )
      .bind(ChannelIdSchema.parse(channelId))
      .run();
  }
}

function missingConfiguration(env: GoogleDirectoryWatchConfig): string[] {
  const required = {
    googleDirectoryWatchAddress: env.googleDirectoryWatchAddress,
    googleDirectoryWatchToken: env.googleDirectoryWatchToken,
    orgSyncGoogleServiceAccountEmail: env.orgSyncGoogleServiceAccountEmail,
    orgSyncGoogleServiceAccountPrivateKey:
      env.orgSyncGoogleServiceAccountPrivateKey,
  };
  return Object.entries(required)
    .filter(([, value]) => value.trim() === "")
    .map(([key]) => key);
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export class GoogleDirectoryWatchChannelManager implements GoogleDirectoryWatchRenewalPort {
  readonly #env: GoogleDirectoryWatchConfig;
  readonly #gateway: GoogleDirectoryWatchGateway;
  readonly #repository: GoogleDirectoryWatchChannelRepository;

  constructor(
    env: GoogleDirectoryWatchConfig,
    repository: GoogleDirectoryWatchChannelRepository,
    gateway: GoogleDirectoryWatchGateway,
  ) {
    this.#env = env;
    this.#repository = repository;
    this.#gateway = gateway;
  }

  async plan(nowMs: number): Promise<GoogleDirectoryWatchRenewalPlan> {
    if (this.#env.googleDirectoryLifecycleDisabled) return { kind: "disabled" };
    const missing = missingConfiguration(this.#env);
    if (missing.length > 0) return { kind: "blocked", missing };
    if (this.#env.googleDirectoryWatchToken.length < 32) {
      return {
        kind: "blocked",
        missing: ["googleDirectoryWatchToken(minimum 32 characters)"],
      };
    }
    const active = await this.#repository.listActive();
    const newestByEvent = new Map<
      GoogleDirectoryWatchEvent,
      GoogleDirectoryWatchChannel
    >();
    for (const channel of active) {
      if (!newestByEvent.has(channel.event))
        newestByEvent.set(channel.event, channel);
    }
    const actions = GOOGLE_DIRECTORY_WATCH_EVENTS.flatMap(
      (event): GoogleDirectoryWatchRenewalAction[] => {
        const channel = newestByEvent.get(event);
        if (channel === undefined) return [{ event, kind: "create" }];
        return channel.expiresAtMs - nowMs <= RENEW_BEFORE_MS
          ? [{ current: channel, event, kind: "renew" }]
          : [];
      },
    );
    return { actions, kind: "ready" };
  }

  async renew(nowMs: number): Promise<GoogleDirectoryWatchRenewalResult> {
    const plan = await this.plan(nowMs);
    if (plan.kind !== "ready") return plan;
    const tokenSha256 = await sha256(this.#env.googleDirectoryWatchToken);
    let replaced = 0;
    for (const action of plan.actions) {
      const channelId = `workspace-sync-${action.event}-${crypto.randomUUID()}`;
      // eslint-disable-next-line no-await-in-loop -- Each replacement must be durably activated before its predecessor is stopped.
      const created = await this.#gateway.create({
        address: this.#env.googleDirectoryWatchAddress,
        channelId,
        event: action.event,
        token: this.#env.googleDirectoryWatchToken,
        ttlSeconds: WATCH_TTL_SECONDS,
      });
      if (created.channelId !== channelId || created.event !== action.event) {
        throw new Error("google_directory_watch_create_identity_mismatch");
      }
      // eslint-disable-next-line no-await-in-loop -- Persistence establishes an accepted overlap before remote stop.
      await this.#repository.activate(created, tokenSha256, nowMs);
      if (action.kind === "renew") {
        // eslint-disable-next-line no-await-in-loop -- Remote stop must succeed before the durable channel is retired.
        await this.#gateway.stop(action.current);
        // eslint-disable-next-line no-await-in-loop -- State transition follows the corresponding remote effect.
        await this.#repository.markStopped(action.current.channelId);
        replaced += 1;
      }
    }
    return { created: plan.actions.length, kind: "executed", replaced };
  }
}
