import { z } from "zod";

import { GoogleDelegatedAuth } from "../org-sync/google-delegated-auth.ts";
import { fetchWithRetry, type RetryOptions } from "../org-sync/http.ts";
import type {
  GoogleDirectoryWatchChannel,
  GoogleDirectoryWatchEvent,
  GoogleDirectoryWatchGateway,
} from "./channel-manager.ts";

const DIRECTORY_USERS_WATCH_ENDPOINT =
  "https://admin.googleapis.com/admin/directory/v1/users/watch";
const DIRECTORY_CHANNELS_STOP_ENDPOINT =
  "https://www.googleapis.com/admin/directory/v1/channels/stop";
const DIRECTORY_READONLY_SCOPE =
  "https://www.googleapis.com/auth/admin.directory.user.readonly";
const CreateInputSchema = z.strictObject({
  address: z.url({ protocol: /^https$/u }),
  channelId: z.string().min(16).max(64),
  event: z.enum(["add", "delete", "makeAdmin", "undelete", "update"]),
  token: z.string().min(32).max(256),
  // eslint-disable-next-line @sarj/prefer-millisecond-control-duration-schema -- Google Directory params.ttl is serialized directly in seconds at this provider boundary.
  ttlSeconds: z.number().int().positive().max(86_400),
});
const GoogleChannelResponseSchema = z.object({
  expiration: z.string().regex(/^[1-9]\d*$/u),
  id: z.string().min(16).max(64),
  resourceId: z.string().min(1).max(512),
  resourceUri: z.url({ protocol: /^https$/u }),
});

export interface GoogleDirectoryWatchGatewayOptions extends Pick<
  RetryOptions,
  "fetchImpl" | "random" | "sleep"
> {
  readonly adminSubject: string;
  readonly privateKey: string;
  readonly serviceAccountEmail: string;
  readonly userProject: string;
}

export class GoogleAdminDirectoryWatchGateway implements GoogleDirectoryWatchGateway {
  readonly #auth: GoogleDelegatedAuth;
  readonly #options: GoogleDirectoryWatchGatewayOptions;

  constructor(options: GoogleDirectoryWatchGatewayOptions) {
    this.#options = options;
    this.#auth = new GoogleDelegatedAuth({
      adminSubject: options.adminSubject,
      fetchImpl: options.fetchImpl,
      operation: "google_directory_watch",
      privateKey: options.privateKey,
      random: options.random,
      serviceAccountEmail: options.serviceAccountEmail,
      sleep: options.sleep,
    });
  }

  async create(rawInput: {
    readonly address: string;
    readonly channelId: string;
    readonly event: GoogleDirectoryWatchEvent;
    readonly token: string;
    readonly ttlSeconds: number;
  }): Promise<GoogleDirectoryWatchChannel> {
    const input = CreateInputSchema.parse(rawInput);
    const runId = crypto.randomUUID();
    const token = await this.#auth.accessToken(DIRECTORY_READONLY_SCOPE, runId);
    const query = new URLSearchParams({
      customer: "my_customer",
      event: input.event,
    });
    const response = await fetchWithRetry(
      `${DIRECTORY_USERS_WATCH_ENDPOINT}?${query.toString()}`,
      {
        body: JSON.stringify({
          address: input.address,
          id: input.channelId,
          params: { ttl: String(input.ttlSeconds) },
          token: input.token,
          type: "web_hook",
        }),
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
          "x-goog-user-project": this.#options.userProject,
        },
        method: "POST",
      },
      {
        fetchImpl: this.#options.fetchImpl,
        label: `google.directory.users.watch.${input.event}`,
        maxAttempts: 1,
        random: this.#options.random,
        runId,
        sleep: this.#options.sleep,
      },
    );
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(
        `Google Directory users.watch HTTP ${String(response.status)}`,
      );
    }
    const channel = GoogleChannelResponseSchema.parse(await response.json());
    return {
      channelId: channel.id,
      event: input.event,
      expiresAtMs: Number(channel.expiration),
      resourceId: channel.resourceId,
      resourceUri: channel.resourceUri,
    };
  }

  async stop(
    channel: Pick<GoogleDirectoryWatchChannel, "channelId" | "resourceId">,
  ): Promise<void> {
    const runId = crypto.randomUUID();
    const token = await this.#auth.accessToken(DIRECTORY_READONLY_SCOPE, runId);
    const response = await fetchWithRetry(
      DIRECTORY_CHANNELS_STOP_ENDPOINT,
      {
        body: JSON.stringify({
          id: channel.channelId,
          resourceId: channel.resourceId,
        }),
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
          "x-goog-user-project": this.#options.userProject,
        },
        method: "POST",
      },
      {
        fetchImpl: this.#options.fetchImpl,
        label: "google.directory.channels.stop",
        random: this.#options.random,
        runId,
        sleep: this.#options.sleep,
      },
    );
    if (!response.ok && response.status !== 404 && response.status !== 410) {
      await response.body?.cancel();
      throw new Error(
        `Google Directory channels.stop HTTP ${String(response.status)}`,
      );
    }
    await response.body?.cancel();
  }
}
