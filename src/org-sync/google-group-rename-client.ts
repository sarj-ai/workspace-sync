import { z } from "zod";

import { sameJson } from "../operations/canonical.ts";
import { type JsonValue, JsonValueSchema } from "../operations/schemas.ts";
import {
  GoogleGroupIdentitySchema,
  GoogleGroupMemberSchema,
} from "./channel-model.ts";
import { googleApiRequest } from "./google-api-request.ts";
import {
  GoogleDelegatedAuth,
  type GoogleDelegatedAuthOptions,
} from "./google-delegated-auth.ts";
import { readExactGroupMembers } from "./google-group-members.ts";

const DIRECTORY_GROUPS_ENDPOINT =
  "https://admin.googleapis.com/admin/directory/v1/groups";
const GROUP_SETTINGS_ENDPOINT = "https://www.googleapis.com/groups/v1/groups";
const DIRECTORY_GROUP_READ_SCOPE =
  "https://www.googleapis.com/auth/admin.directory.group.readonly";
const DIRECTORY_GROUP_WRITE_SCOPE =
  "https://www.googleapis.com/auth/admin.directory.group";
const GROUP_SETTINGS_SCOPE =
  "https://www.googleapis.com/auth/apps.groups.settings";
const StringListSchema = z.array(z.string());

export type GoogleGroupRenameSourceStage =
  | "collision-group-read"
  | "directory-read-auth"
  | "directory-write-auth"
  | "group-members-read"
  | "group-read"
  | "group-settings-contract"
  | "group-settings-email-mismatch"
  | "group-settings-http-401"
  | "group-settings-http-403"
  | "group-settings-http-404"
  | "group-settings-http-429"
  | "group-settings-http-other"
  | "group-settings-read-auth"
  | "group-settings-read"
  | "group-settings-request"
  | "group-write";

export class GoogleGroupRenameSourceError extends Error {
  readonly stage: GoogleGroupRenameSourceStage;

  constructor(stage: GoogleGroupRenameSourceStage, options?: ErrorOptions) {
    super(`Google group rename source failed at ${stage}.`, options);
    this.name = "GoogleGroupRenameSourceError";
    this.stage = stage;
  }
}

const SettingsResponseSchema = z.record(z.string(), JsonValueSchema);
const GroupSettingsEmailSchema = z.email();
const DirectoryGroupSnapshotSchema = GoogleGroupIdentitySchema.extend({
  metadata: z.record(z.string(), JsonValueSchema),
});

export const GoogleGroupRenameInputSchema = z
  .strictObject({
    newEmail: z.email().toLowerCase(),
    oldEmail: z.email().toLowerCase(),
  })
  .refine(({ newEmail, oldEmail }) => newEmail !== oldEmail, {
    message: "Old and new Google group emails must differ",
    path: ["newEmail"],
  });
export type GoogleGroupRenameInput = z.output<
  typeof GoogleGroupRenameInputSchema
>;

export const GoogleGroupRenameDetailsSchema =
  GoogleGroupRenameInputSchema.safeExtend({
    googleGroupId: z.string().trim().min(1),
  }).strict();
export type GoogleGroupRenameDetails = z.output<
  typeof GoogleGroupRenameDetailsSchema
>;

export const GoogleGroupRenameSnapshotSchema = z.strictObject({
  collision: GoogleGroupIdentitySchema.nullable(),
  group: DirectoryGroupSnapshotSchema,
  members: z.array(GoogleGroupMemberSchema),
  settings: SettingsResponseSchema,
});
export type GoogleGroupRenameSnapshot = z.output<
  typeof GoogleGroupRenameSnapshotSchema
>;

export interface IGoogleGroupRenameClient {
  readSnapshot(
    input: GoogleGroupRenameDetails | GoogleGroupRenameInput,
    runId: string,
    deadlineAt?: number,
  ): Promise<GoogleGroupRenameSnapshot>;
  renameExact(
    input: GoogleGroupRenameDetails,
    expectedBefore: GoogleGroupRenameSnapshot,
    runId: string,
    deadlineAt?: number,
  ): Promise<void>;
}

export interface GoogleGroupRenameClientOptions extends GoogleDelegatedAuthOptions {
  userProject: string;
}

/** Narrow provider surface for one reviewed in-place group email rename. */
export class GoogleGroupRenameClient implements IGoogleGroupRenameClient {
  readonly #auth: GoogleDelegatedAuth;
  readonly #options: GoogleGroupRenameClientOptions;

  constructor(options: GoogleGroupRenameClientOptions) {
    this.#auth = new GoogleDelegatedAuth(options);
    this.#options = Object.freeze({ ...options });
  }

  async readSnapshot(
    input: GoogleGroupRenameDetails | GoogleGroupRenameInput,
    runId: string,
    deadlineAt?: number,
  ): Promise<GoogleGroupRenameSnapshot> {
    const [directoryToken, settingsToken] = await Promise.all([
      sourceStage(
        "directory-read-auth",
        this.#auth.accessToken(DIRECTORY_GROUP_READ_SCOPE, runId, deadlineAt),
      ),
      sourceStage(
        "group-settings-read-auth",
        this.#auth.accessToken(GROUP_SETTINGS_SCOPE, runId, deadlineAt),
      ),
    ]);
    const requestedGroupId =
      "googleGroupId" in input ? input.googleGroupId : undefined;
    const [requestedGroup, collisionGroup] = await Promise.all([
      sourceStage(
        "group-read",
        this.#readGroupIfPresent(
          requestedGroupId ?? input.oldEmail,
          directoryToken,
          runId,
          deadlineAt,
        ),
      ),
      sourceStage(
        "collision-group-read",
        this.#readGroupIfPresent(
          input.newEmail,
          directoryToken,
          runId,
          deadlineAt,
        ),
      ),
    ]);
    const group = requestedGroup ?? collisionGroup;
    if (group === null)
      throw new Error(
        "Google group was not found at either exact rename email",
      );
    if (requestedGroupId !== undefined && group.id !== requestedGroupId) {
      throw new Error(
        "Google group immutable ID did not match the signed rename details",
      );
    }
    const [members, settings] = await Promise.all([
      sourceStage(
        "group-members-read",
        this.#readMembers(group.id, directoryToken, runId, deadlineAt),
      ),
      sourceStage(
        "group-settings-read",
        this.#readSettings(group.email, settingsToken, runId, deadlineAt),
      ),
    ]);
    return GoogleGroupRenameSnapshotSchema.parse({
      collision:
        collisionGroup === null
          ? null
          : { email: collisionGroup.email, id: collisionGroup.id },
      group,
      members: normalizeMembers(members),
      settings,
    });
  }

  async renameExact(
    input: GoogleGroupRenameDetails,
    expectedBefore: GoogleGroupRenameSnapshot,
    runId: string,
    deadlineAt?: number,
  ): Promise<void> {
    // This is the final complete provider read immediately before the bounded PATCH.
    const before = await this.readSnapshot(input, runId, deadlineAt);
    if (!sameJson(before, expectedBefore)) {
      throw new Error("Google group changed immediately before rename");
    }
    const token = await sourceStage(
      "directory-write-auth",
      this.#auth.accessToken(DIRECTORY_GROUP_WRITE_SCOPE, runId, deadlineAt),
    );
    let mutationError: Error | undefined;
    try {
      const response = await sourceStage(
        "group-write",
        this.#request(
          `${DIRECTORY_GROUPS_ENDPOINT}/${encodeURIComponent(input.googleGroupId)}`,
          token,
          "google.directory.groups.rename",
          runId,
          deadlineAt,
          {
            body: JSON.stringify({ email: input.newEmail }),
            headers: { "content-type": "application/json" },
            method: "PATCH",
          },
          1,
        ),
      );
      if (!response.ok) {
        response.body?.cancel().catch(() => null);
        throw new Error(
          `google.directory.groups.rename HTTP ${String(response.status)}`,
        );
      }
      await response.body?.cancel();
    } catch (error) {
      mutationError = error instanceof Error ? error : new Error(String(error));
    }

    // Resolve an ambiguous PATCH only through an exact post-write provider readback.
    const after = await this.readSnapshot(input, runId, deadlineAt);
    if (isExactRenameReadback(input, expectedBefore, after)) return;
    if (mutationError !== undefined) throw mutationError;
    throw new Error(
      "Google group rename did not preserve the reviewed snapshot",
    );
  }

  async #readGroupIfPresent(
    key: string,
    token: string,
    runId: string,
    deadlineAt?: number,
  ) {
    const response = await this.#request(
      `${DIRECTORY_GROUPS_ENDPOINT}/${encodeURIComponent(key)}`,
      token,
      "google.directory.groups.get_for_exact_rename",
      runId,
      deadlineAt,
    );
    if (response.status === 404) {
      await response.body?.cancel();
      return null;
    }
    if (!response.ok) {
      response.body?.cancel().catch(() => null);
      throw new Error(
        `google.directory.groups.get_for_exact_rename HTTP ${String(response.status)}`,
      );
    }
    return parseDirectoryGroup(await response.json());
  }

  async #readMembers(
    groupId: string,
    token: string,
    correlationId: string,
    deadlineAt?: number,
  ) {
    const label = "google.directory.members.list_for_exact_rename";
    const members = await readExactGroupMembers(groupId, label, (url) =>
      this.#request(url, token, label, correlationId, deadlineAt),
    );
    return members;
  }

  async #readSettings(
    currentGroupEmail: string,
    token: string,
    runId: string,
    deadlineAt?: number,
  ): Promise<JsonValue> {
    const response = await sourceStage(
      "group-settings-request",
      this.#request(
        `${GROUP_SETTINGS_ENDPOINT}/${encodeURIComponent(currentGroupEmail)}?alt=json`,
        token,
        "google.groups_settings.get_for_exact_rename",
        runId,
        deadlineAt,
        { headers: { accept: "application/json" } },
      ),
    );
    if (!response.ok) {
      response.body?.cancel().catch(() => null);
      throw new GoogleGroupRenameSourceError(
        groupSettingsHttpStage(response.status),
      );
    }
    let raw: z.output<typeof SettingsResponseSchema>;
    let settingsEmail: string;
    try {
      raw = SettingsResponseSchema.parse(await response.json());
      settingsEmail = GroupSettingsEmailSchema.parse(raw.email).toLowerCase();
    } catch (cause) {
      throw new GoogleGroupRenameSourceError("group-settings-contract", {
        cause,
      });
    }
    if (settingsEmail !== currentGroupEmail.toLowerCase()) {
      throw new GoogleGroupRenameSourceError("group-settings-email-mismatch");
    }
    // These are response envelope fields; email is expected to change during the rename.
    const { email: _email, etag: _etag, kind: _kind, ...stableSettings } = raw;
    return JsonValueSchema.parse(stableSettings);
  }

  #request(
    url: string,
    token: string,
    label: string,
    runId: string,
    deadlineAt?: number,
    init: RequestInit = {},
    maxAttempts?: number,
  ): Promise<Response> {
    return googleApiRequest(url, token, this.#options.userProject, init, {
      ...(!(deadlineAt === undefined) && { deadlineAt }),
      ...(!(maxAttempts === undefined) && { maxAttempts }),
      fetchImpl: this.#options.fetchImpl,
      label,
      random: this.#options.random,
      runId,
      sleep: this.#options.sleep,
    });
  }
}

function groupSettingsHttpStage(status: number): GoogleGroupRenameSourceStage {
  switch (status) {
    case 401:
      return "group-settings-http-401";
    case 403:
      return "group-settings-http-403";
    case 404:
      return "group-settings-http-404";
    case 429:
      return "group-settings-http-429";
    default:
      return "group-settings-http-other";
  }
}

async function sourceStage<T>(
  stage: GoogleGroupRenameSourceStage,
  pending: Promise<T>,
): Promise<T> {
  try {
    return await pending;
  } catch (cause) {
    if (cause instanceof GoogleGroupRenameSourceError) throw cause;
    throw new GoogleGroupRenameSourceError(stage, { cause });
  }
}

function normalizeMembers(
  members: readonly z.output<typeof GoogleGroupMemberSchema>[],
): z.output<typeof GoogleGroupMemberSchema>[] {
  return members
    .map((member) => ({ ...member, email: member.email.toLowerCase() }))
    .toSorted((left, right) =>
      [left.id, left.type, left.email, left.role, left.status]
        .join("\0")
        .localeCompare(
          [right.id, right.type, right.email, right.role, right.status].join(
            "\0",
          ),
        ),
    );
}

function parseDirectoryGroup(
  value: unknown,
): z.output<typeof DirectoryGroupSnapshotSchema> {
  const raw = SettingsResponseSchema.parse(value);
  const identity = GoogleGroupIdentitySchema.parse(raw);
  const { email: _email, etag: _etag, id: _id, kind: _kind, ...metadata } = raw;
  return DirectoryGroupSnapshotSchema.parse({
    ...identity,
    metadata: normalizeGroupMetadata(metadata),
  });
}

function normalizeGroupMetadata(
  metadata: Record<string, JsonValue>,
): Record<string, JsonValue> {
  const normalized = { ...metadata };
  for (const field of ["aliases", "nonEditableAliases"] as const) {
    const value = normalized[field];
    const strings = StringListSchema.safeParse(value);
    if (strings.success) {
      normalized[field] = strings.data
        .map((item) => item.toLowerCase())
        .toSorted();
    }
  }
  return normalized;
}

export function isExactRenameReadback(
  input: GoogleGroupRenameDetails,
  before: GoogleGroupRenameSnapshot,
  after: GoogleGroupRenameSnapshot,
): boolean {
  return (
    after.group.id === input.googleGroupId &&
    after.group.email.toLowerCase() === input.newEmail &&
    after.collision?.id === input.googleGroupId &&
    after.collision.email.toLowerCase() === input.newEmail &&
    isRenameMetadataPreserved(
      input,
      before.group.metadata,
      after.group.metadata,
    ) &&
    sameJson(before.members, after.members) &&
    sameJson(before.settings, after.settings)
  );
}

function isRenameMetadataPreserved(
  input: GoogleGroupRenameDetails,
  before: Record<string, JsonValue>,
  after: Record<string, JsonValue>,
): boolean {
  const { aliases: beforeAliases, ...beforeStable } = before;
  const { aliases: afterAliases, ...afterStable } = after;
  if (!sameJson(beforeStable, afterStable)) return false;
  const beforeSet = stringSet(beforeAliases);
  const afterSet = stringSet(afterAliases);
  if (beforeSet === null || afterSet === null)
    return sameOptionalJson(beforeAliases, afterAliases);
  const expectedWithOldPrimary = [
    ...new Set([...beforeSet, input.oldEmail]),
  ].toSorted(
    (sortLeft, sortRight) =>
      Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
  );
  return (
    sameJson(afterSet, beforeSet) || sameJson(afterSet, expectedWithOldPrimary)
  );
}

function sameOptionalJson(
  left: JsonValue | undefined,
  right: JsonValue | undefined,
): boolean {
  if (left === undefined || right === undefined) return left === right;
  return sameJson(left, right);
}

function stringSet(value: JsonValue | undefined): null | string[] {
  if (value === undefined) return [];
  const strings = StringListSchema.safeParse(value);
  if (!strings.success) return null;
  return [...new Set(strings.data.map((item) => item.toLowerCase()))].toSorted(
    (sortLeft, sortRight) =>
      Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
  );
}
