import { z } from "zod";

import { GitHubDeprovisionAuthoritySchema } from "../github-access-audit/github-deprovision-authority-contract.ts";
import { GitHubDeprovisionGoogleAuthorityInventorySchema } from "./github-deprovision-google-authority-contract.ts";

export const GITHUB_DEPROVISION_AUTHORITY_SNAPSHOT_SCHEMA_VERSION =
  "github-deprovision-authority-snapshot/v1";
export const GITHUB_DEPROVISION_AUTHORITY_SNAPSHOT_KEY =
  "identity-provisioning:github-deprovision-authority-snapshot:v1";
export const GITHUB_DEPROVISION_AUTHORITY_SNAPSHOT_MAX_AGE_MS = 20 * 60 * 1_000;
export const GITHUB_DEPROVISION_AUTHORITY_SNAPSHOT_TTL_SECONDS = 60 * 60;
export const GITHUB_DEPROVISION_AUTHORITY_SNAPSHOT_MAX_BYTES =
  20 * 1_024 * 1_024;

export const GitHubDeprovisionAuthoritySnapshotSchema = z.strictObject({
  capturedAt: z.iso.datetime({ offset: true }),
  github: GitHubDeprovisionAuthoritySchema,
  google: GitHubDeprovisionGoogleAuthorityInventorySchema,
  schemaVersion: z.literal(
    GITHUB_DEPROVISION_AUTHORITY_SNAPSHOT_SCHEMA_VERSION,
  ),
});

export type GitHubDeprovisionAuthoritySnapshot = z.output<
  typeof GitHubDeprovisionAuthoritySnapshotSchema
>;
export type GitHubDeprovisionAuthoritySnapshotInput = z.input<
  typeof GitHubDeprovisionAuthoritySnapshotSchema
>;

export interface GitHubDeprovisionAuthoritySnapshotKvPort {
  get(key: string, type: "text"): Promise<null | string>;
  put(
    key: string,
    value: string,
    options: { readonly expirationTtl: number },
  ): Promise<void>;
}

export interface GitHubDeprovisionAuthoritySnapshotStorePort {
  read(): Promise<GitHubDeprovisionAuthoritySnapshot>;
  write(snapshot: GitHubDeprovisionAuthoritySnapshotInput): Promise<void>;
}

export type GitHubDeprovisionAuthoritySnapshotStoreErrorCode =
  | "future"
  | "malformed"
  | "missing"
  | "oversized"
  | "stale";

export class GitHubDeprovisionAuthoritySnapshotStoreError extends Error {
  readonly code: GitHubDeprovisionAuthoritySnapshotStoreErrorCode;

  constructor(
    code: GitHubDeprovisionAuthoritySnapshotStoreErrorCode,
    options?: ErrorOptions,
  ) {
    super(`github_deprovision_authority_snapshot_${code}`, options);
    this.name = "GitHubDeprovisionAuthoritySnapshotStoreError";
    this.code = code;
  }
}

export interface GitHubDeprovisionAuthoritySnapshotStoreOptions {
  readonly maxAgeMs?: number;
  readonly maxPayloadBytes?: number;
  readonly now?: () => number;
}

/** Versioned, fail-closed background authority snapshot persisted in Workers KV. */
export class KvGitHubDeprovisionAuthoritySnapshotStore implements GitHubDeprovisionAuthoritySnapshotStorePort {
  readonly #kv: GitHubDeprovisionAuthoritySnapshotKvPort;
  readonly #maxAgeMs: number;
  readonly #maxPayloadBytes: number;
  readonly #now: () => number;

  constructor(
    kv: GitHubDeprovisionAuthoritySnapshotKvPort,
    options: GitHubDeprovisionAuthoritySnapshotStoreOptions = {},
  ) {
    this.#kv = kv;
    this.#maxAgeMs = positiveInteger(
      options.maxAgeMs ?? GITHUB_DEPROVISION_AUTHORITY_SNAPSHOT_MAX_AGE_MS,
      "maxAgeMs",
    );
    this.#maxPayloadBytes = positiveInteger(
      options.maxPayloadBytes ??
        GITHUB_DEPROVISION_AUTHORITY_SNAPSHOT_MAX_BYTES,
      "maxPayloadBytes",
    );
    if (
      this.#maxPayloadBytes > GITHUB_DEPROVISION_AUTHORITY_SNAPSHOT_MAX_BYTES
    ) {
      throw new Error(
        "maxPayloadBytes exceeds the hard Workers KV snapshot limit",
      );
    }
    this.#now = options.now ?? Date.now;
  }

  async read(): Promise<GitHubDeprovisionAuthoritySnapshot> {
    const payload = await this.#kv.get(
      GITHUB_DEPROVISION_AUTHORITY_SNAPSHOT_KEY,
      "text",
    );
    if (payload === null) throw snapshotError("missing");
    assertPayloadSize(payload, this.#maxPayloadBytes);
    const snapshot = parseSnapshot(payload);
    const capturedAtMs = Date.parse(snapshot.capturedAt);
    const nowMs = this.#now();
    if (capturedAtMs > nowMs) throw snapshotError("future");
    if (nowMs - capturedAtMs > this.#maxAgeMs) throw snapshotError("stale");
    return snapshot;
  }

  async write(
    snapshot: GitHubDeprovisionAuthoritySnapshotInput,
  ): Promise<void> {
    const parsed = parseSnapshotInput(snapshot);
    const payload = JSON.stringify(parsed);
    assertPayloadSize(payload, this.#maxPayloadBytes);
    await this.#kv.put(GITHUB_DEPROVISION_AUTHORITY_SNAPSHOT_KEY, payload, {
      expirationTtl: GITHUB_DEPROVISION_AUTHORITY_SNAPSHOT_TTL_SECONDS,
    });
  }
}

function assertPayloadSize(payload: string, maxPayloadBytes: number): void {
  if (new TextEncoder().encode(payload).byteLength > maxPayloadBytes) {
    throw snapshotError("oversized");
  }
}

function parseSnapshot(payload: string): GitHubDeprovisionAuthoritySnapshot {
  try {
    return GitHubDeprovisionAuthoritySnapshotSchema.parse(JSON.parse(payload));
  } catch (error) {
    throw snapshotError("malformed", error);
  }
}

function parseSnapshotInput(
  snapshot: GitHubDeprovisionAuthoritySnapshotInput,
): GitHubDeprovisionAuthoritySnapshot {
  const parsed = GitHubDeprovisionAuthoritySnapshotSchema.safeParse(snapshot);
  if (!parsed.success) throw snapshotError("malformed");
  return parsed.data;
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1)
    throw new Error(`${name} must be a positive integer`);
  return value;
}

function snapshotError(
  code: GitHubDeprovisionAuthoritySnapshotStoreErrorCode,
  cause?: unknown,
): GitHubDeprovisionAuthoritySnapshotStoreError {
  return new GitHubDeprovisionAuthoritySnapshotStoreError(
    code,
    cause === undefined ? undefined : { cause },
  );
}
