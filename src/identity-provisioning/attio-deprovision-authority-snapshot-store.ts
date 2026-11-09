import { z } from "zod";

import { contentHash } from "../github-access-audit/content-hash.ts";
import {
  AttioDeprovisionAuthoritySchema,
  AttioScimUserSchema,
  AttioWorkspaceMemberSchema,
} from "./attio-deprovision-authority-capture.ts";
import { GitHubDeprovisionGoogleAuthorityInventorySchema } from "./github-deprovision-google-authority-contract.ts";
import { canonicalGoogleDeprovisionAuthority } from "./google-deprovision-authority.ts";

export const ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_SCHEMA_VERSION =
  "attio-deprovision-authority-snapshot/v3";
export const ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_KEY =
  "identity-provisioning:attio-deprovision-authority-snapshot:v3";
const LEGACY_ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_KEY =
  "identity-provisioning:attio-deprovision-authority-snapshot:v2";
export const ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_MAX_AGE_MS = 20 * 60 * 1_000;
export const ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_TTL_SECONDS = 60 * 60;
export const ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_MAX_BYTES = 4 * 1_024 * 1_024;
const Sha256Schema = z.string().regex(/^[a-f0-9]{64}$/u);
const LegacyAttioDeprovisionAuthoritySchema = z.strictObject({
  capturedAt: z.iso.datetime({ offset: true }),
  complete: z.literal(true),
  scimUsers: z.array(AttioScimUserSchema).readonly(),
  token: z
    .strictObject({
      scopes: z.tuple([z.literal("user_management:read")]).readonly(),
      workspaceId: z.uuid(),
    })
    .readonly(),
  workspaceMembers: z.array(AttioWorkspaceMemberSchema).readonly(),
});
const LegacyAttioDeprovisionAuthoritySnapshotSchema = z.strictObject({
  attio: LegacyAttioDeprovisionAuthoritySchema,
  capturedAt: z.iso.datetime({ offset: true }),
  digests: z
    .strictObject({ attio: Sha256Schema, google: Sha256Schema })
    .readonly(),
  google: GitHubDeprovisionGoogleAuthorityInventorySchema,
  schemaVersion: z.literal("attio-deprovision-authority-snapshot/v2"),
});

const AttioDeprovisionAuthoritySnapshotInputSchema = z.strictObject({
  attio: AttioDeprovisionAuthoritySchema,
  capturedAt: z.iso.datetime({ offset: true }),
  google: GitHubDeprovisionGoogleAuthorityInventorySchema,
  schemaVersion: z.literal(ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_SCHEMA_VERSION),
});

export const AttioDeprovisionAuthoritySnapshotSchema =
  AttioDeprovisionAuthoritySnapshotInputSchema.extend({
    digests: z
      .strictObject({ attio: Sha256Schema, google: Sha256Schema })
      .readonly(),
  }).readonly();

export type AttioDeprovisionAuthoritySnapshot = z.output<
  typeof AttioDeprovisionAuthoritySnapshotSchema
>;
export type AttioDeprovisionAuthoritySnapshotInput = z.input<
  typeof AttioDeprovisionAuthoritySnapshotInputSchema
>;

export interface AttioDeprovisionAuthoritySnapshotKvPort {
  get(key: string, type: "text"): Promise<null | string>;
  put(
    key: string,
    value: string,
    options: { readonly expirationTtl: number },
  ): Promise<void>;
}

export interface AttioDeprovisionAuthoritySnapshotStorePort {
  read(): Promise<AttioDeprovisionAuthoritySnapshot>;
  write(snapshot: AttioDeprovisionAuthoritySnapshotInput): Promise<void>;
}

export type AttioDeprovisionAuthoritySnapshotStoreErrorCode =
  | "future"
  | "malformed"
  | "missing"
  | "oversized"
  | "stale"
  | "write-failed";

export class AttioDeprovisionAuthoritySnapshotStoreError extends Error {
  readonly code: AttioDeprovisionAuthoritySnapshotStoreErrorCode;

  constructor(
    code: AttioDeprovisionAuthoritySnapshotStoreErrorCode,
    options?: ErrorOptions,
  ) {
    super(`attio_deprovision_authority_snapshot_${code}`, options);
    this.name = "AttioDeprovisionAuthoritySnapshotStoreError";
    this.code = code;
  }
}

export interface AttioDeprovisionAuthoritySnapshotStoreOptions {
  readonly maxAgeMs?: number;
  readonly maxPayloadBytes?: number;
  readonly now?: () => number;
}

/** Versioned, fail-closed Attio and Google authority snapshot persisted as one KV value. */
export class KvAttioDeprovisionAuthoritySnapshotStore implements AttioDeprovisionAuthoritySnapshotStorePort {
  readonly #kv: AttioDeprovisionAuthoritySnapshotKvPort;
  readonly #maxAgeMs: number;
  readonly #maxPayloadBytes: number;
  readonly #now: () => number;

  constructor(
    kv: AttioDeprovisionAuthoritySnapshotKvPort,
    options: AttioDeprovisionAuthoritySnapshotStoreOptions = {},
  ) {
    this.#kv = kv;
    this.#maxAgeMs = positiveInteger(
      options.maxAgeMs ?? ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_MAX_AGE_MS,
      "maxAgeMs",
    );
    this.#maxPayloadBytes = positiveInteger(
      options.maxPayloadBytes ?? ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_MAX_BYTES,
      "maxPayloadBytes",
    );
    if (
      this.#maxPayloadBytes > ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_MAX_BYTES
    ) {
      throw new Error(
        "maxPayloadBytes exceeds the hard Workers KV snapshot limit",
      );
    }
    this.#now = options.now ?? Date.now;
  }

  async read(): Promise<AttioDeprovisionAuthoritySnapshot> {
    const payload = await this.#kv.get(
      ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_KEY,
      "text",
    );
    if (payload === null) return this.#readLegacySnapshot();
    assertPayloadSize(payload, this.#maxPayloadBytes);
    const snapshot = parseSnapshotPayload(payload);
    this.#assertFresh(snapshot);
    return snapshot;
  }

  async write(snapshot: AttioDeprovisionAuthoritySnapshotInput): Promise<void> {
    const parsed = parseSnapshotInput(snapshot);
    const canonical = canonicalSnapshotInput(parsed);
    const [attio, google] = await Promise.all([
      contentHash(canonicalAttioDeprovisionAuthority(canonical.attio)),
      contentHash(
        canonicalGoogleDeprovisionAuthority({
          capturedAt: canonical.capturedAt,
          deletedUsers: canonical.google.deletedUsers,
          users: canonical.google.users,
        }),
      ),
    ]);
    const payload = JSON.stringify(
      AttioDeprovisionAuthoritySnapshotSchema.parse({
        ...canonical,
        digests: { attio, google },
      }),
    );
    assertPayloadSize(payload, this.#maxPayloadBytes);
    try {
      await this.#kv.put(ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_KEY, payload, {
        expirationTtl: ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_TTL_SECONDS,
      });
    } catch (error) {
      throw snapshotError("write-failed", error);
    }
  }

  async #readLegacySnapshot(): Promise<AttioDeprovisionAuthoritySnapshot> {
    const payload = await this.#kv.get(
      LEGACY_ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_KEY,
      "text",
    );
    if (payload === null) throw snapshotError("missing");
    assertPayloadSize(payload, this.#maxPayloadBytes);
    const snapshot = await parseLegacySnapshotPayload(payload);
    this.#assertFresh(snapshot);
    return snapshot;
  }

  #assertFresh(snapshot: AttioDeprovisionAuthoritySnapshot): void {
    const capturedAtMs = Date.parse(snapshot.capturedAt);
    const nowMs = this.#now();
    if (capturedAtMs > nowMs) throw snapshotError("future");
    if (nowMs - capturedAtMs > this.#maxAgeMs) throw snapshotError("stale");
  }
}

function canonicalSnapshotInput(
  snapshot: z.output<typeof AttioDeprovisionAuthoritySnapshotInputSchema>,
): z.output<typeof AttioDeprovisionAuthoritySnapshotInputSchema> {
  return AttioDeprovisionAuthoritySnapshotInputSchema.parse({
    ...snapshot,
    attio: {
      ...snapshot.attio,
      scimUsers: snapshot.attio.scimUsers
        .map((user) => ({
          ...user,
          emails: user.emails.toSorted((left, right) =>
            left.value.localeCompare(right.value),
          ),
        }))
        .toSorted((left, right) => left.id.localeCompare(right.id)),
      workspaceMembers: snapshot.attio.workspaceMembers.toSorted(
        (left, right) =>
          left.id.workspaceMemberId.localeCompare(right.id.workspaceMemberId),
      ),
    },
    google: {
      ...snapshot.google,
      deletedUsers: snapshot.google.deletedUsers
        .map(canonicalGoogleUser)
        .toSorted(compareGoogle),
      users: snapshot.google.users
        .map(canonicalGoogleUser)
        .toSorted(compareGoogle),
    },
  });
}

export function canonicalAttioDeprovisionAuthority(
  authority: AttioDeprovisionAuthoritySnapshotInput["attio"],
) {
  const { capturedAt: _capturedAt, ...stableAuthority } = authority;
  return stableAuthority;
}

function canonicalGoogleUser<
  User extends AttioDeprovisionAuthoritySnapshot["google"]["users"][number],
>(user: User): User {
  return {
    ...user,
    ...(!(user.aliases === undefined) && { aliases: user.aliases.toSorted() }),
    ...(!(user.nonEditableAliases === undefined) && {
      nonEditableAliases: user.nonEditableAliases.toSorted(),
    }),
  };
}

function compareGoogle(
  left: AttioDeprovisionAuthoritySnapshot["google"]["users"][number],
  right: AttioDeprovisionAuthoritySnapshot["google"]["users"][number],
): number {
  return `${left.id}:${left.primaryEmail}`.localeCompare(
    `${right.id}:${right.primaryEmail}`,
  );
}

function assertPayloadSize(payload: string, maxPayloadBytes: number): void {
  if (new TextEncoder().encode(payload).byteLength > maxPayloadBytes) {
    throw snapshotError("oversized");
  }
}

function parseSnapshotPayload(
  payload: string,
): AttioDeprovisionAuthoritySnapshot {
  try {
    const snapshot = AttioDeprovisionAuthoritySnapshotSchema.parse(
      JSON.parse(payload),
    );
    assertConservativeCaptureTime(snapshot);
    return snapshot;
  } catch (error) {
    throw snapshotError("malformed", error);
  }
}

async function parseLegacySnapshotPayload(
  payload: string,
): Promise<AttioDeprovisionAuthoritySnapshot> {
  try {
    const legacy = LegacyAttioDeprovisionAuthoritySnapshotSchema.parse(
      JSON.parse(payload),
    );
    if (legacy.capturedAt !== legacy.attio.capturedAt)
      throw snapshotError("malformed");
    const attio = AttioDeprovisionAuthoritySchema.parse({
      ...legacy.attio,
      scimStatus: "available",
    });
    return AttioDeprovisionAuthoritySnapshotSchema.parse({
      ...legacy,
      attio,
      digests: {
        ...legacy.digests,
        attio: await contentHash(canonicalAttioDeprovisionAuthority(attio)),
      },
      schemaVersion: ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_SCHEMA_VERSION,
    });
  } catch (error) {
    if (error instanceof AttioDeprovisionAuthoritySnapshotStoreError)
      throw error;
    throw snapshotError("malformed", error);
  }
}

function parseSnapshotInput(
  snapshot: AttioDeprovisionAuthoritySnapshotInput,
): z.output<typeof AttioDeprovisionAuthoritySnapshotInputSchema> {
  const parsed =
    AttioDeprovisionAuthoritySnapshotInputSchema.safeParse(snapshot);
  if (!parsed.success) throw snapshotError("malformed");
  assertConservativeCaptureTime(parsed.data);
  return parsed.data;
}

function assertConservativeCaptureTime(
  snapshot: Pick<
    AttioDeprovisionAuthoritySnapshotInput,
    "attio" | "capturedAt"
  >,
): void {
  if (snapshot.capturedAt !== snapshot.attio.capturedAt)
    throw snapshotError("malformed");
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${name} must be a positive integer`);
  }
  return value;
}

function snapshotError(
  code: AttioDeprovisionAuthoritySnapshotStoreErrorCode,
  cause?: unknown,
): AttioDeprovisionAuthoritySnapshotStoreError {
  return new AttioDeprovisionAuthoritySnapshotStoreError(
    code,
    cause === undefined ? undefined : { cause },
  );
}
