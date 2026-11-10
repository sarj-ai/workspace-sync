import { z } from "zod";

import { sameJson } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import { providerWrite } from "../runtime/provider-write.ts";
import {
  GoogleGroupIdentitySchema,
  type GoogleGroupMemberSchema,
} from "./channel-model.ts";
import { googleApiRequest } from "./google-api-request.ts";
import {
  GoogleDelegatedAuth,
  type GoogleDelegatedAuthOptions,
} from "./google-delegated-auth.ts";
import { readExactGroupMembers } from "./google-group-members.ts";

const DIRECTORY_GROUPS_ENDPOINT =
  "https://admin.googleapis.com/admin/directory/v1/groups";
const DIRECTORY_GROUP_READ_SCOPE =
  "https://www.googleapis.com/auth/admin.directory.group.readonly";
const DIRECTORY_GROUP_WRITE_SCOPE =
  "https://www.googleapis.com/auth/admin.directory.group";

const DirectoryGroupSnapshotSchema = GoogleGroupIdentitySchema.extend({
  metadata: z.record(z.string(), JsonValueSchema),
});
const DirectoryGroupResponseSchema = z.record(z.string(), JsonValueSchema);

export const GoogleGroupDeletionTargetSchema = z.strictObject({
  googleGroupEmail: z.email().toLowerCase(),
  googleGroupId: z.string().trim().min(1).optional(),
});
export type GoogleGroupDeletionTarget = z.output<
  typeof GoogleGroupDeletionTargetSchema
>;

export const GoogleGroupDeletionDetailsSchema =
  GoogleGroupDeletionTargetSchema.required({
    googleGroupId: true,
  });
export type GoogleGroupDeletionDetails = z.output<
  typeof GoogleGroupDeletionDetailsSchema
>;

export type GoogleGroupDeletionSnapshot =
  | {
      readonly group: z.output<typeof DirectoryGroupSnapshotSchema>;
      readonly members: z.output<typeof GoogleGroupMemberSchema>[];
      readonly state: "present";
    }
  | { readonly state: "absent" };

export interface IGoogleGroupDeletionClient {
  deleteExact(
    target: GoogleGroupDeletionDetails,
    expectedBefore: Extract<GoogleGroupDeletionSnapshot, { state: "present" }>,
    runId: string,
    deadlineAt?: number,
  ): Promise<void>;
  readSnapshot(
    target: GoogleGroupDeletionTarget,
    runId: string,
    deadlineAt?: number,
  ): Promise<GoogleGroupDeletionSnapshot>;
}

export interface GoogleGroupDeletionClientOptions extends GoogleDelegatedAuthOptions {
  userProject: string;
}

/** Narrow provider surface for deletion of one immutable, reviewed Google Group. */
export class GoogleGroupDeletionClient implements IGoogleGroupDeletionClient {
  readonly #auth: GoogleDelegatedAuth;
  readonly #options: GoogleGroupDeletionClientOptions;

  constructor(options: GoogleGroupDeletionClientOptions) {
    this.#auth = new GoogleDelegatedAuth(options);
    this.#options = Object.freeze({ ...options });
  }

  async readSnapshot(
    rawTarget: GoogleGroupDeletionTarget,
    runId: string,
    deadlineAt?: number,
  ): Promise<GoogleGroupDeletionSnapshot> {
    const target = GoogleGroupDeletionTargetSchema.parse(rawTarget);
    const token = await this.#auth.accessToken(
      DIRECTORY_GROUP_READ_SCOPE,
      runId,
      deadlineAt,
    );
    const byEmail = await this.#readGroupIfPresent(
      target.googleGroupEmail,
      token,
      runId,
      deadlineAt,
    );
    let byId: null | z.output<typeof DirectoryGroupSnapshotSchema> = null;
    if (target.googleGroupId !== undefined) {
      byId = await this.#readGroupIfPresent(
        target.googleGroupId,
        token,
        runId,
        deadlineAt,
      );
    } else if (byEmail !== null) {
      byId = await this.#readGroupIfPresent(
        byEmail.id,
        token,
        runId,
        deadlineAt,
      );
    }
    if (byEmail === null && byId === null) return { state: "absent" };
    if (byEmail?.id !== byId?.id || byEmail === null || byId === null) {
      throw new Error(
        "Google group email and immutable ID lookup did not agree",
      );
    }
    if (
      byEmail.email.toLowerCase() !== target.googleGroupEmail ||
      (target.googleGroupId !== undefined &&
        byEmail.id !== target.googleGroupId)
    ) {
      throw new Error("Google group deletion target identity drifted");
    }
    return {
      group: byEmail,
      members: await this.#readMembers(byEmail.id, token, runId, deadlineAt),
      state: "present",
    };
  }

  async deleteExact(
    target: GoogleGroupDeletionDetails,
    expectedBefore: Extract<GoogleGroupDeletionSnapshot, { state: "present" }>,
    runId: string,
    deadlineAt?: number,
  ): Promise<void> {
    const before = await this.readSnapshot(target, runId, deadlineAt);
    if (
      before.state !== "present" ||
      !sameJson(
        deletionAuthoritySnapshot(before),
        deletionAuthoritySnapshot(expectedBefore),
      )
    ) {
      throw new Error("Google group changed immediately before deletion");
    }
    const token = await this.#auth.accessToken(
      DIRECTORY_GROUP_WRITE_SCOPE,
      runId,
      deadlineAt,
    );
    const outcome = await providerWrite(async () => {
      const response = await this.#request(
        `${DIRECTORY_GROUPS_ENDPOINT}/${encodeURIComponent(target.googleGroupId)}`,
        token,
        "google.directory.groups.delete_exact",
        runId,
        deadlineAt,
        { method: "DELETE" },
        1,
      );
      if (!response.ok) {
        response.body?.cancel().catch(() => null);
        throw new Error(
          `google.directory.groups.delete_exact HTTP ${String(response.status)}`,
        );
      }
      await response.body?.cancel();
    });
    const after = await this.readSnapshot(target, runId, deadlineAt);
    if (after.state === "absent") return;
    if (outcome.kind === "uncertain") throw outcome.error;
    throw new Error("Google group remained after exact deletion");
  }

  async #readGroupIfPresent(
    key: string,
    token: string,
    runId: string,
    deadlineAt?: number,
  ): Promise<null | z.output<typeof DirectoryGroupSnapshotSchema>> {
    const response = await this.#request(
      `${DIRECTORY_GROUPS_ENDPOINT}/${encodeURIComponent(key)}`,
      token,
      "google.directory.groups.get_for_exact_deletion",
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
        `google.directory.groups.get_for_exact_deletion HTTP ${String(response.status)}`,
      );
    }
    const raw = DirectoryGroupResponseSchema.parse(await response.json());
    const identity = GoogleGroupIdentitySchema.parse(raw);
    const { email: _email, id: _id, ...metadata } = raw;
    return DirectoryGroupSnapshotSchema.parse({ ...identity, metadata });
  }

  async #readMembers(
    groupId: string,
    token: string,
    correlationId: string,
    deadlineAt?: number,
  ) {
    const label = "google.directory.members.list_for_exact_deletion";
    const members = await readExactGroupMembers(groupId, label, (url) =>
      this.#request(url, token, label, correlationId, deadlineAt),
    );
    return members.toSorted((left, right) => left.id.localeCompare(right.id));
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

function deletionAuthoritySnapshot(
  snapshot: Extract<GoogleGroupDeletionSnapshot, { state: "present" }>,
) {
  return {
    group: { email: snapshot.group.email.toLowerCase(), id: snapshot.group.id },
    members: snapshot.members,
  };
}
