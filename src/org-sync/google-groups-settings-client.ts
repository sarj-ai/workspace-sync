import { z } from "zod";

import { normalizeIdentityEmail as normalizeEmail } from "../identity-sync/normalize-identity-email.ts";
import type { JsonValue } from "../operations/schemas.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import type { GoogleDelegatedAuthContract } from "./google-delegated-auth.ts";
import { fetchWithRetry, type RetryOptions } from "./http.ts";

const GROUPS_SETTINGS_ENDPOINT = "https://www.googleapis.com/groups/v1/groups";
const GROUPS_SETTINGS_SCOPE =
  "https://www.googleapis.com/auth/apps.groups.settings";
const SettingsResponseSchema = JsonValueSchema.pipe(
  z.record(z.string(), JsonValueSchema).and(
    z.object({
      email: z.email(),
      etag: z.string().min(1),
    }),
  ),
);

export interface GoogleGroupSettingsTarget {
  readonly googleGroupEmail: string;
}

export interface GoogleGroupSettingsSnapshot extends GoogleGroupSettingsTarget {
  readonly etag: string;
  readonly settings: JsonValue;
}

/** A GET-only port. Its implementation deliberately exposes no settings mutation method. */
export interface GoogleGroupSettingsReader {
  readSettings(
    target: GoogleGroupSettingsTarget,
    runId: string,
  ): Promise<GoogleGroupSettingsSnapshot>;
}

export interface GoogleGroupsSettingsClientOptions extends Pick<
  RetryOptions,
  "fetchImpl" | "random" | "sleep"
> {
  auth: GoogleDelegatedAuthContract;
}

export class GoogleGroupsSettingsClient implements GoogleGroupSettingsReader {
  readonly #options: GoogleGroupsSettingsClientOptions;

  constructor(options: GoogleGroupsSettingsClientOptions) {
    this.#options = Object.freeze({ ...options });
  }

  async readSettings(
    target: GoogleGroupSettingsTarget,
    runId: string,
  ): Promise<GoogleGroupSettingsSnapshot> {
    const token = await this.#options.auth.accessToken(
      GROUPS_SETTINGS_SCOPE,
      runId,
    );
    const response = await fetchWithRetry(
      `${GROUPS_SETTINGS_ENDPOINT}/${encodeURIComponent(target.googleGroupEmail)}`,
      {
        headers: { authorization: `Bearer ${token}` },
      },
      {
        fetchImpl: this.#options.fetchImpl,
        label: "google.groups-settings.groups.get",
        random: this.#options.random,
        runId,
        sleep: this.#options.sleep,
      },
    );
    if (!response.ok) {
      response.body?.cancel().catch(() => null);
      throw new Error(
        `google.groups-settings.groups.get HTTP ${String(response.status)}`,
      );
    }
    const settings = SettingsResponseSchema.parse(await response.json());
    if (
      normalizeEmail(settings.email) !== normalizeEmail(target.googleGroupEmail)
    ) {
      throw new Error(
        "Google Groups Settings returned a different group email",
      );
    }
    return {
      etag: settings.etag,
      googleGroupEmail: normalizeEmail(settings.email),
      settings,
    };
  }
}
