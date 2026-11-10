import { z } from "zod";

import { getWorkspaceSyncPolicy } from "../configuration.ts";
import type { GoogleDirectoryAuthoritySourcePort } from "../identity-lifecycle/google-directory-authority-reader.ts";
import { GoogleIdentityMaintenanceFenceError } from "../identity-sync/google-identity-maintenance-fence-error.ts";
import { GoogleIdentityParentPreflightError } from "../identity-sync/google-identity-parent-preflight-error.ts";
import { normalizeIdentityEmail } from "../identity-sync/normalize-identity-email.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import { readBoundedText } from "../runtime/read-bounded-text.ts";
import { logEvent } from "../shared/log-event.ts";
import { GoogleDelegatedAuth } from "./google-delegated-auth.ts";
import {
  type GoogleWorkspaceIdentitySchemaGateway,
  type GoogleWorkspaceIdentityUserGateway,
  type GoogleWorkspaceSchemaSnapshot,
  GoogleWorkspaceSchemaSnapshotSchema,
  type SARJ_IDENTITY_SCHEMA_NAME,
  type SarjIdentitySchemaField,
} from "./google-identity-schema.ts";
import { fetchWithRetry, type RetryOptions } from "./http.ts";
import {
  type GoogleDirectoryPreferenceUser,
  type GoogleDirectoryUser,
  isActiveGoogleDirectoryUser,
} from "./model.ts";

type ParsePhotoBatchPartResult = Readonly<{
  index: number;
  json: string;
  status: number;
}>;

const DIRECTORY_USERS_ENDPOINT =
  "https://admin.googleapis.com/admin/directory/v1/users";
const DIRECTORY_BATCH_ENDPOINT = "https://admin.googleapis.com/batch";
const DIRECTORY_SCHEMAS_ENDPOINT =
  "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/schemas";
export const DIRECTORY_SCOPE =
  "https://www.googleapis.com/auth/admin.directory.user";
const DIRECTORY_SCHEMA_READONLY_SCOPE =
  "https://www.googleapis.com/auth/admin.directory.userschema.readonly";
const DIRECTORY_SCHEMA_WRITE_SCOPE =
  "https://www.googleapis.com/auth/admin.directory.userschema";
export const DIRECTORY_READONLY_SCOPE =
  "https://www.googleapis.com/auth/admin.directory.user.readonly";
// Filter only configured deleted IDs; active identities remain authoritative.
function ignoredDeletedGoogleUserIds(): ReadonlySet<string> {
  return new Set(getWorkspaceSyncPolicy().ignoredDeletedGoogleUserIds);
}
const MAX_DIRECTORY_PAGES = 20;
const PHOTO_BATCH_SIZE = 20;
const MAX_PHOTO_BATCH_RESPONSE_BYTES = PHOTO_BATCH_SIZE * 410_000;

const GoogleCustomSchemaFieldsSchema = z.record(
  z.string().min(1),
  JsonValueSchema,
);
const GoogleCustomSchemasSchema = z
  .object({
    SarjIdentity: z
      .object({
        githubLogin: z.string().min(1).optional(),
        githubUserId: z.string().regex(/^\d+$/u).optional(),
      })
      .catchall(JsonValueSchema)
      .optional(),
    SocialBot: z
      .object({
        linkedinDigestPreferenceActionTs: z
          .string()
          .regex(/^\d{10,}\.\d{1,6}$/u)
          .optional(),
        linkedinDigestOptOut: z.boolean().optional(),
      })
      .catchall(JsonValueSchema)
      .optional(),
  })
  .catchall(GoogleCustomSchemaFieldsSchema)
  .optional();

const GooglePreferenceUserSchema = z.object({
  archived: z.boolean().optional(),
  customSchemas: GoogleCustomSchemasSchema,
  deletionTime: z.iso.datetime().optional(),
  etag: z.string().min(1).optional(),
  id: z.string().min(1),
  suspended: z.boolean().optional(),
});

const GoogleUserSchema = GooglePreferenceUserSchema.extend({
  aliases: z.array(z.string()).optional(),
  isAdmin: z.boolean().optional(),
  isDelegatedAdmin: z.boolean().optional(),
  name: z.object({ fullName: z.string().optional() }).optional(),
  nonEditableAliases: z.array(z.string()).optional(),
  organizations: z
    .array(
      z.object({
        department: z.string().optional(),
        primary: z.boolean().optional(),
        title: z.string().optional(),
      }),
    )
    .optional(),
  primaryEmail: z.email(),
  relations: z
    .array(
      z.object({
        type: z.string().optional(),
        value: z.string().optional(),
      }),
    )
    .optional(),
  thumbnailPhotoUrl: z.url().optional(),
  websites: z
    .array(
      z.object({
        customType: z.string().optional(),
        primary: z.boolean().optional(),
        type: z.string().optional(),
        value: z.string().optional(),
      }),
    )
    .optional(),
});

const GooglePhotoSchema = z.object({
  mimeType: z.enum(["image/jpeg", "image/png", "image/webp"]),
  photoData: z.string().min(1).max(400_000),
});

const UsersPageSchema = z.object({
  nextPageToken: z.string().optional(),
  users: z.array(GoogleUserSchema).default([]),
});
const SocialBotSchema = z.object({
  fields: z.array(
    z.object({
      fieldName: z.string(),
      fieldType: z.string(),
      multiValued: z.boolean().optional().default(false),
      readAccessType: z.string(),
    }),
  ),
  schemaName: z.literal("SocialBot"),
});

export interface IGoogleDirectoryClient {
  getUserById?(
    googleUserId: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<GoogleDirectoryUser | null>;
  listAllUsers(
    runId: string,
    deadlineAt?: number,
  ): Promise<GoogleDirectoryUser[]>;
  listDeletedIdentityUsers?(
    runId: string,
    deadlineAt?: number,
  ): Promise<readonly unknown[]>;
  listDeletedUsers?(
    runId: string,
    deadlineAt?: number,
  ): Promise<GoogleDirectoryUser[]>;
  listIdentityUsers?(
    runId?: string,
    deadlineAt?: number,
  ): Promise<readonly unknown[]>;
}

export interface ILinkedInDigestDirectoryClient extends IGoogleDirectoryClient {
  listLinkedInDigestUsers(
    runId: string,
    deadlineAt?: number,
  ): Promise<GoogleDirectoryUser[]>;
  verifyLinkedInDigestSchema(runId: string, deadlineAt?: number): Promise<void>;
}

export interface IGoogleDirectoryPhotoClient {
  listUserPhotos(
    users: readonly GoogleDirectoryUser[],
    runId: string,
    deadlineAt?: number,
  ): Promise<ReadonlyMap<string, string>>;
}

export interface IGoogleDirectoryPreferenceClient {
  getUserByEmail(
    email: string,
    runId: string,
    deadlineAt?: number,
  ): Promise<GoogleDirectoryPreferenceUser | null>;
  setLinkedInDigestOptOut(
    googleUserId: string,
    optedOut: boolean,
    actionTs: string,
    expectedEtag: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<void>;
}

export interface GoogleDirectoryClientOptions extends Pick<
  RetryOptions,
  "fetchImpl" | "random" | "sleep"
> {
  adminSubject: string;
  operation?: string;
  privateKey: string;
  scope?: typeof DIRECTORY_READONLY_SCOPE | typeof DIRECTORY_SCOPE;
  serviceAccountEmail: string;
  userProject: string;
}
const DirectoryEmailSchema = z.email();

export class GoogleDirectoryClient
  implements
    GoogleDirectoryAuthoritySourcePort,
    ILinkedInDigestDirectoryClient,
    IGoogleDirectoryPhotoClient,
    IGoogleDirectoryPreferenceClient,
    GoogleWorkspaceIdentitySchemaGateway,
    GoogleWorkspaceIdentityUserGateway
{
  readonly #auth: GoogleDelegatedAuth;
  readonly #options: GoogleDirectoryClientOptions;
  readonly #scope: typeof DIRECTORY_READONLY_SCOPE | typeof DIRECTORY_SCOPE;

  constructor(options: GoogleDirectoryClientOptions) {
    this.#options = Object.freeze({ ...options });
    this.#auth = new GoogleDelegatedAuth(options);
    this.#scope = options.scope ?? DIRECTORY_READONLY_SCOPE;
  }

  async readUserById(userId: string, deadlineAtMs?: number): Promise<unknown> {
    if (this.#scope !== DIRECTORY_SCOPE) {
      throw new Error(
        "Google identity updates require the writable user scope",
      );
    }
    const normalizedUserId = userId.trim();
    if (!/^\d+$/u.test(normalizedUserId)) {
      throw new Error(
        "A numeric immutable Google Directory user ID is required",
      );
    }
    const runId = crypto.randomUUID();
    const token = await this.#auth.accessToken(
      DIRECTORY_SCOPE,
      runId,
      deadlineAtMs,
    );
    const query = new URLSearchParams({
      fields:
        "id,primaryEmail,aliases,nonEditableAliases,isAdmin,isDelegatedAdmin,suspended,archived,deletionTime,etag,customSchemas",
      projection: "full",
    });
    const response = await fetchWithRetry(
      `${DIRECTORY_USERS_ENDPOINT}/${encodeURIComponent(normalizedUserId)}?${query.toString()}`,
      {
        headers: {
          authorization: `Bearer ${token}`,
          "x-goog-user-project": this.#options.userProject,
        },
      },
      {
        fetchImpl: this.#options.fetchImpl,
        label: "google.directory.users.get.github_identity",
        deadlineAt: deadlineAtMs,
        random: this.#options.random,
        runId,
        sleep: this.#options.sleep,
      },
    );
    if (response.status === 404) {
      await response.body?.cancel();
      return null;
    }
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(
        `Google Directory users.get HTTP ${String(response.status)}`,
      );
    }
    return response.json();
  }

  async updateUser(
    input: Parameters<GoogleWorkspaceIdentityUserGateway["updateUser"]>[0],
  ): Promise<void> {
    if (this.#scope !== DIRECTORY_SCOPE) {
      throw new Error(
        "Google identity updates require the writable user scope",
      );
    }
    const runId = crypto.randomUUID();
    let token: string;
    try {
      token = await this.#auth.accessToken(
        DIRECTORY_SCOPE,
        runId,
        input.maintenanceGuard?.deadlineAtMs,
      );
      await input.parentDispatch?.assertWriteAuthority();
      input.parentDispatch?.assertFreshPlan();
      await input.maintenanceGuard?.assertWriteAuthority();
      await input.maintenanceGuard?.beforeDispatch?.();
      await input.maintenanceGuard?.assertWriteAuthority();
    } catch (error) {
      if (input.maintenanceGuard !== undefined)
        throw new GoogleIdentityMaintenanceFenceError({ cause: error });
      if (input.parentDispatch !== undefined)
        throw new GoogleIdentityParentPreflightError({ cause: error });
      throw error;
    }
    const existingIdentity = input.preservedCustomSchemas.SarjIdentity ?? {};
    const response = await fetchWithRetry(
      `${DIRECTORY_USERS_ENDPOINT}/${encodeURIComponent(input.userId)}`,
      {
        body: JSON.stringify({
          customSchemas: {
            ...input.preservedCustomSchemas,
            SarjIdentity: { ...existingIdentity, ...input.identity },
          },
        }),
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
          "if-match": input.expectedEtag,
          "x-goog-user-project": this.#options.userProject,
        },
        method: "PUT",
      },
      {
        fetchImpl: this.#options.fetchImpl,
        label: "google.directory.users.update.github_identity",
        ...((input.parentDispatch !== undefined ||
          input.maintenanceGuard !== undefined) && {
          maxAttempts: 1,
        }),
        deadlineAt: input.maintenanceGuard?.deadlineAtMs,
        timeoutMs: 15_000,
        random: this.#options.random,
        runId,
        sleep: this.#options.sleep,
      },
    );
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(
        `Google Directory users.update HTTP ${String(response.status)}`,
      );
    }
    await response.body?.cancel();
    logEvent(
      `${this.#options.operation ?? "org_sync"}.google_github_identity_updated`,
      {
        "run_id": runId,
      },
    );
  }

  async addFields(
    snapshot: z.output<typeof GoogleWorkspaceSchemaSnapshotSchema>,
    fields: readonly SarjIdentitySchemaField[],
  ): Promise<void> {
    const current = GoogleWorkspaceSchemaSnapshotSchema.parse(snapshot);
    const runId = crypto.randomUUID();
    const token = await this.#auth.accessToken(
      DIRECTORY_SCHEMA_WRITE_SCOPE,
      runId,
    );
    const response = await fetchWithRetry(
      `${DIRECTORY_SCHEMAS_ENDPOINT}/${encodeURIComponent(current.schemaId)}`,
      {
        body: JSON.stringify({
          ...current,
          fields: [...current.fields, ...fields],
        }),
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
          "if-match": current.etag,
          "x-goog-user-project": this.#options.userProject,
        },
        method: "PUT",
      },
      {
        fetchImpl: this.#options.fetchImpl,
        label: "google.directory.schemas.update.sarj_identity",
        random: this.#options.random,
        runId,
        sleep: this.#options.sleep,
      },
    );
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(
        `Google Directory schemas.update HTTP ${String(response.status)}`,
      );
    }
    await response.body?.cancel();
    logEvent(
      `${this.#options.operation ?? "org_sync"}.google_identity_schema_updated`,
      {
        "run_id": runId,
      },
    );
  }

  async createSchema(input: {
    displayName: typeof SARJ_IDENTITY_SCHEMA_NAME;
    fields: readonly SarjIdentitySchemaField[];
    schemaName: typeof SARJ_IDENTITY_SCHEMA_NAME;
  }): Promise<void> {
    const runId = crypto.randomUUID();
    const token = await this.#auth.accessToken(
      DIRECTORY_SCHEMA_WRITE_SCOPE,
      runId,
    );
    const response = await fetchWithRetry(
      DIRECTORY_SCHEMAS_ENDPOINT,
      {
        body: JSON.stringify(input),
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
          "x-goog-user-project": this.#options.userProject,
        },
        method: "POST",
      },
      {
        fetchImpl: this.#options.fetchImpl,
        label: "google.directory.schemas.insert.sarj_identity",
        random: this.#options.random,
        runId,
        sleep: this.#options.sleep,
      },
    );
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(
        `Google Directory schemas.insert HTTP ${String(response.status)}`,
      );
    }
    await response.body?.cancel();
    logEvent(
      `${this.#options.operation ?? "org_sync"}.google_identity_schema_created`,
      {
        "run_id": runId,
      },
    );
  }

  async readSchema(
    schemaName: typeof SARJ_IDENTITY_SCHEMA_NAME,
  ): Promise<GoogleWorkspaceSchemaSnapshot | null> {
    const runId = crypto.randomUUID();
    const token = await this.#auth.accessToken(
      DIRECTORY_SCHEMA_READONLY_SCOPE,
      runId,
    );
    const response = await fetchWithRetry(
      `${DIRECTORY_SCHEMAS_ENDPOINT}/${encodeURIComponent(schemaName)}`,
      {
        headers: {
          authorization: `Bearer ${token}`,
          "x-goog-user-project": this.#options.userProject,
        },
      },
      {
        fetchImpl: this.#options.fetchImpl,
        label: "google.directory.schemas.get.sarj_identity",
        random: this.#options.random,
        runId,
        sleep: this.#options.sleep,
      },
    );
    if (response.status === 404) {
      await response.body?.cancel();
      return null;
    }
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(
        `Google Directory schemas.get HTTP ${String(response.status)}`,
      );
    }
    return GoogleWorkspaceSchemaSnapshotSchema.parse(await response.json());
  }

  async getUserById(
    googleUserId: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<GoogleDirectoryUser | null> {
    const normalizedUserId = googleUserId.trim();
    if (!/^\d{5,30}$/u.test(normalizedUserId)) {
      throw new Error(
        "A numeric immutable Google Directory user ID is required",
      );
    }
    const token = await this.#auth.accessToken(
      this.#scope,
      correlationId,
      deadlineAt,
    );
    const query = new URLSearchParams({ projection: "full" });
    const response = await fetchWithRetry(
      `${DIRECTORY_USERS_ENDPOINT}/${encodeURIComponent(normalizedUserId)}?${query.toString()}`,
      {
        headers: {
          authorization: `Bearer ${token}`,
          "x-goog-user-project": this.#options.userProject,
        },
      },
      {
        fetchImpl: this.#options.fetchImpl,
        label: "google.directory.users.get.identity_lifecycle",
        ...(!(deadlineAt === undefined) && { deadlineAt }),
        random: this.#options.random,
        runId: correlationId,
        sleep: this.#options.sleep,
      },
    );
    if (response.status === 404) {
      await response.body?.cancel();
      return null;
    }
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(
        `Google Directory users.get HTTP ${String(response.status)}`,
      );
    }
    return GoogleUserSchema.parse(await response.json());
  }

  async listAllUsers(
    runId: string,
    deadlineAt?: number,
  ): Promise<GoogleDirectoryUser[]> {
    return this.#listUsers(false, runId, deadlineAt);
  }

  async listIdentityUsers(
    runId: string = crypto.randomUUID(),
    deadlineAt?: number,
  ): Promise<GoogleDirectoryUser[]> {
    return this.#listUsers(false, runId, deadlineAt, {
      customFieldMask: "SarjIdentity",
      fields:
        "nextPageToken,users(id,primaryEmail,aliases,nonEditableAliases,isAdmin,isDelegatedAdmin,suspended,archived,deletionTime,etag,customSchemas)",
    });
  }

  async listDeletedIdentityUsers(
    runId: string,
    deadlineAt?: number,
  ): Promise<GoogleDirectoryUser[]> {
    const users = await this.#listUsers(true, runId, deadlineAt, {
      customFieldMask: "SarjIdentity",
      fields:
        "nextPageToken,users(id,primaryEmail,aliases,nonEditableAliases,isAdmin,isDelegatedAdmin,suspended,archived,deletionTime,etag,customSchemas)",
    });
    return users.filter((user) => !ignoredDeletedGoogleUserIds().has(user.id));
  }

  // Exact immutable-ID authority must retain records excluded from bulk projections.
  async listDeletedAuthorityUsers(
    runId: string,
    deadlineAt?: number,
  ): Promise<GoogleDirectoryUser[]> {
    return this.#listUsers(true, runId, deadlineAt);
  }

  async listDeletedUsers(
    runId: string,
    deadlineAt?: number,
  ): Promise<GoogleDirectoryUser[]> {
    const users = await this.#listUsers(true, runId, deadlineAt);
    return users.filter((user) => !ignoredDeletedGoogleUserIds().has(user.id));
  }

  async listLinkedInDigestUsers(
    runId: string,
    deadlineAt?: number,
  ): Promise<GoogleDirectoryUser[]> {
    return this.#listUsers(false, runId, deadlineAt, {
      customFieldMask: "SocialBot",
      fields:
        "nextPageToken,users(id,name,primaryEmail,suspended,archived,deletionTime,websites,customSchemas)",
    });
  }

  async verifyLinkedInDigestSchema(
    runId: string,
    deadlineAt?: number,
  ): Promise<void> {
    const token = await this.#auth.accessToken(
      DIRECTORY_SCHEMA_READONLY_SCOPE,
      runId,
      deadlineAt,
    );
    const response = await fetchWithRetry(
      `${DIRECTORY_SCHEMAS_ENDPOINT}/SocialBot`,
      {
        headers: {
          authorization: `Bearer ${token}`,
          "x-goog-user-project": this.#options.userProject,
        },
      },
      {
        fetchImpl: this.#options.fetchImpl,
        label: "google.directory.schemas.get.linkedin_digest",
        ...(!(deadlineAt === undefined) && { deadlineAt }),
        random: this.#options.random,
        runId,
        sleep: this.#options.sleep,
      },
    );
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(
        `Google Directory schemas.get HTTP ${String(response.status)}`,
      );
    }
    const schema = SocialBotSchema.parse(await response.json());
    const expected = new Map([
      ["linkedinDigestOptOut", "BOOL"],
      ["linkedinDigestPreferenceActionTs", "STRING"],
    ]);
    for (const [fieldName, fieldType] of expected) {
      const field = schema.fields.find(
        (candidate) => candidate.fieldName === fieldName,
      );
      if (
        field?.fieldType !== fieldType ||
        field.multiValued ||
        field.readAccessType !== "ADMINS_AND_SELF"
      ) {
        throw new Error(
          "Google Directory SocialBot schema is not safe for LinkedIn preferences",
        );
      }
    }
  }

  async setLinkedInDigestOptOut(
    googleUserId: string,
    optedOut: boolean,
    actionTs: string,
    expectedEtag: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<void> {
    if (this.#scope !== DIRECTORY_SCOPE) {
      throw new Error(
        "Google Directory preference updates require the writable user scope",
      );
    }
    const normalizedUserId = googleUserId.trim();
    if (!/^\d+$/u.test(normalizedUserId)) {
      throw new Error(
        "A numeric immutable Google Directory user ID is required",
      );
    }
    if (!/^\d{10,}\.\d{1,6}$/u.test(actionTs)) {
      throw new Error("A valid Slack preference action timestamp is required");
    }
    const normalizedEtag = expectedEtag.trim();
    if (!normalizedEtag)
      throw new Error("A Google Directory user etag is required");
    const token = await this.#auth.accessToken(
      DIRECTORY_SCOPE,
      correlationId,
      deadlineAt,
    );
    const response = await fetchWithRetry(
      `${DIRECTORY_USERS_ENDPOINT}/${encodeURIComponent(normalizedUserId)}`,
      {
        body: JSON.stringify({
          customSchemas: {
            SocialBot: {
              linkedinDigestOptOut: optedOut,
              linkedinDigestPreferenceActionTs: actionTs,
            },
          },
        }),
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
          "if-match": normalizedEtag,
          "x-goog-user-project": this.#options.userProject,
        },
        method: "PATCH",
      },
      {
        fetchImpl: this.#options.fetchImpl,
        label: "google.directory.users.patch.linkedin_digest_preference",
        ...(!(deadlineAt === undefined) && { deadlineAt }),
        random: this.#options.random,
        runId: correlationId,
        sleep: this.#options.sleep,
      },
    );
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(
        `Google Directory users.patch HTTP ${String(response.status)}`,
      );
    }
    await response.body?.cancel();
    logEvent(
      `${this.#options.operation ?? "org_sync"}.google_preference_updated`,
      {
        "opted_out": optedOut,
        "run_id": correlationId,
      },
    );
  }

  async getUserByEmail(
    email: string,
    runId: string,
    deadlineAt?: number,
  ): Promise<GoogleDirectoryPreferenceUser | null> {
    const normalizedEmail = normalizeIdentityEmail(email);
    if (!DirectoryEmailSchema.safeParse(normalizedEmail).success) {
      throw new Error("A valid Google Directory user email is required");
    }
    const token = await this.#auth.accessToken(this.#scope, runId, deadlineAt);
    const query = new URLSearchParams({
      customFieldMask: "SocialBot",
      fields: "id,suspended,archived,deletionTime,etag,customSchemas",
      projection: "custom",
    });
    const response = await fetchWithRetry(
      `${DIRECTORY_USERS_ENDPOINT}/${encodeURIComponent(normalizedEmail)}?${query.toString()}`,
      {
        headers: {
          authorization: `Bearer ${token}`,
          "x-goog-user-project": this.#options.userProject,
        },
      },
      {
        fetchImpl: this.#options.fetchImpl,
        label: "google.directory.users.get.linkedin_digest_preference",
        ...(!(deadlineAt === undefined) && { deadlineAt }),
        random: this.#options.random,
        runId,
        sleep: this.#options.sleep,
      },
    );
    if (response.status === 404) {
      await response.body?.cancel();
      return null;
    }
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(
        `Google Directory users.get HTTP ${String(response.status)}`,
      );
    }
    return GooglePreferenceUserSchema.parse(await response.json());
  }

  async listUserPhotos(
    users: readonly GoogleDirectoryUser[],
    runId: string,
    deadlineAt?: number,
  ): Promise<ReadonlyMap<string, string>> {
    const token = await this.#auth.accessToken(this.#scope, runId, deadlineAt);
    const photos = new Map<string, string>();
    const candidates = users.filter(
      (user) => isActiveGoogleDirectoryUser(user) && user.thumbnailPhotoUrl,
    );
    for (
      let offset = 0;
      offset < candidates.length;
      offset += PHOTO_BATCH_SIZE
    ) {
      const batch = candidates.slice(offset, offset + PHOTO_BATCH_SIZE);
      // eslint-disable-next-line no-await-in-loop -- Each bounded multipart response is consumed before the next batch reuses the memory budget.
      const results = await this.#getPhotoBatch(
        batch,
        token,
        runId,
        deadlineAt,
      );
      for (const [userId, photo] of results) photos.set(userId, photo);
    }
    logEvent("org_chart.google_photos", {
      candidates: candidates.length,
      photos: photos.size,
      "run_id": runId,
    });
    return photos;
  }

  async #getPhotoBatch(
    users: readonly GoogleDirectoryUser[],
    token: string,
    runId: string,
    deadlineAt?: number,
  ): Promise<ReadonlyMap<string, string>> {
    const boundary = `sarj_${crypto.randomUUID().replaceAll("-", "")}`;
    let parsed: ReadonlyMap<string, string> | undefined;
    let parseError: unknown;
    const fetchImpl = this.#options.fetchImpl ?? fetch;
    const parseBatchFetch: typeof fetch = async (input, init) => {
      const outer = await fetchImpl(input, init);
      if (!outer.ok) return outer;
      let body: string;
      try {
        body = await readBoundedText(
          outer,
          MAX_PHOTO_BATCH_RESPONSE_BYTES,
          () =>
            new PhotoBatchContractError(
              "Google Directory photo batch response exceeded safe size",
            ),
        );
      } catch (error) {
        if (error instanceof PhotoBatchContractError)
          return nonRetryableResponse(error);
        throw error;
      }
      try {
        const responseBoundary = multipartBoundary(
          outer.headers.get("content-type"),
        );
        parsed = parsePhotoBatchResponse(users, body, responseBoundary);
        return new Response(null, { status: 204 });
      } catch (error) {
        if (
          error instanceof PhotoBatchHttpError &&
          isTransientPhotoStatus(error.status)
        ) {
          return new Response(null, {
            headers: { "x-sarj-inner-status": String(error.status) },
            status: error.status,
          });
        }
        return nonRetryableResponse(error);
      }
    };
    const nonRetryableResponse = (error: unknown): Response => {
      parseError = error;
      return new Response(null, {
        headers: { "x-sarj-batch-parse-error": "1" },
        status: 422,
      });
    };
    const response = await fetchWithRetry(
      DIRECTORY_BATCH_ENDPOINT,
      {
        body: renderPhotoBatchRequest(users, boundary),
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": `multipart/mixed; boundary=${boundary}`,
          "x-goog-user-project": this.#options.userProject,
        },
        method: "POST",
      },
      {
        fetchImpl: parseBatchFetch,
        label: "google.directory.users.photos.batch",
        ...(!(deadlineAt === undefined) && { deadlineAt }),
        random: this.#options.random,
        runId,
        sleep: this.#options.sleep,
      },
    );
    if (!response.ok) {
      await response.body?.cancel();
      if (response.headers.has("x-sarj-batch-parse-error")) throw parseError;
      if (response.headers.has("x-sarj-inner-status")) {
        throw new Error(
          `Google Directory users.photos.get HTTP ${String(response.status)}`,
        );
      }
      throw new Error(
        `Google Directory users.photos.batch HTTP ${String(response.status)}`,
      );
    }
    if (!parsed)
      throw new Error("Google Directory photo batch response was not parsed");
    return parsed;
  }

  async #listUsers(
    showDeleted: boolean,
    runId: string,
    deadlineAt?: number,
    responseMask?: { customFieldMask: string; fields: string },
  ): Promise<GoogleDirectoryUser[]> {
    const token = await this.#auth.accessToken(this.#scope, runId, deadlineAt);
    const users: GoogleDirectoryUser[] = [];
    let pageToken = "";
    let page = 0;
    const seenPageTokens = new Set<string>();
    do {
      page++;
      if (page > MAX_DIRECTORY_PAGES) {
        throw new Error(
          `Google Directory exceeded ${String(MAX_DIRECTORY_PAGES)} pages`,
        );
      }
      if (pageToken && seenPageTokens.has(pageToken)) {
        throw new Error("Google Directory returned a repeated page token");
      }
      if (pageToken) seenPageTokens.add(pageToken);
      const query = new URLSearchParams({
        customer: "my_customer",
        maxResults: "500",
        orderBy: "email",
        projection: responseMask === undefined ? "full" : "custom",
        showDeleted: String(showDeleted),
      });
      if (responseMask) {
        query.set("customFieldMask", responseMask.customFieldMask);
        query.set("fields", responseMask.fields);
      }
      if (pageToken) query.set("pageToken", pageToken);
      // eslint-disable-next-line no-await-in-loop -- Each users.list page token is returned by the preceding response.
      const response = await fetchWithRetry(
        `${DIRECTORY_USERS_ENDPOINT}?${query.toString()}`,
        {
          headers: {
            authorization: `Bearer ${token}`,
            "x-goog-user-project": this.#options.userProject,
          },
        },
        {
          fetchImpl: this.#options.fetchImpl,
          label: "google.directory.users.list",
          ...(!(deadlineAt === undefined) && { deadlineAt }),
          random: this.#options.random,
          runId,
          sleep: this.#options.sleep,
        },
      );
      if (!response.ok) {
        response.body?.cancel().catch(() => null);
        throw new Error(
          `Google Directory users.list HTTP ${String(response.status)}`,
        );
      }
      // eslint-disable-next-line no-await-in-loop -- The current response body must be parsed before its next-page token is available.
      const parsed = UsersPageSchema.parse(await response.json());
      users.push(...parsed.users);
      pageToken = parsed.nextPageToken ?? "";
      logEvent(`${this.#options.operation ?? "org_sync"}.google_page`, {
        count: parsed.users.length,
        page,
        "run_id": runId,
      });
    } while (pageToken);
    logEvent(`${this.#options.operation ?? "org_sync"}.google_snapshot`, {
      pages: page,
      "run_id": runId,
      users: users.length,
    });
    return users;
  }
}

function renderPhotoBatchRequest(
  users: readonly GoogleDirectoryUser[],
  boundary: string,
): string {
  const parts = users.map(
    (user, index) =>
      `--${boundary}\r\nContent-Type: application/http\r\nContent-ID: <photo-${String(index)}>\r\n\r\nGET /admin/directory/v1/users/${encodeURIComponent(user.id)}/photos/thumbnail HTTP/1.1\r\n\r\n`,
  );
  return `${parts.join("")}--${boundary}--\r\n`;
}

function multipartBoundary(contentType: null | string): string {
  if (!contentType?.toLowerCase().startsWith("multipart/mixed")) {
    throw new Error("Google Directory photo batch response was not multipart");
  }
  const match = /(?:^|;)\s*boundary=(?:"([^"]+)"|([^;\s]+))/iu.exec(
    contentType,
  );
  const boundary = match?.[1] ?? match?.[2];
  if (!boundary || boundary.length > 200 || /[\r\n]/u.test(boundary)) {
    throw new Error(
      "Google Directory photo batch response omitted a valid boundary",
    );
  }
  return boundary;
}

function parsePhotoBatchResponse(
  users: readonly GoogleDirectoryUser[],
  body: string,
  boundary: string,
): ReadonlyMap<string, string> {
  const photos = new Map<string, string>();
  const seen = new Set<number>();
  for (const rawPart of body.split(`--${boundary}`)) {
    const part = rawPart.replace(/^\r?\n/u, "").replace(/\r?\n$/u, "");
    if (part === "" || part === "--") continue;
    const parsed = parsePhotoBatchPart(part);
    const index = parsed.index;
    assertPhotoBatchIndex(index, users.length, seen);
    seen.add(index);
    const user = users[index];
    if (!user)
      throw new Error(
        "Google Directory photo batch response referenced no user",
      );
    const photo = decodePhotoBatchResult(user, parsed);
    if (photo !== null) photos.set(user.id, photo);
  }
  if (seen.size !== users.length) {
    throw new Error(
      "Google Directory photo batch response omitted a requested user",
    );
  }
  return photos;
}

function assertPhotoBatchIndex(
  index: number,
  userCount: number,
  seen: ReadonlySet<number>,
): void {
  if (
    !Number.isSafeInteger(index) ||
    index < 0 ||
    index >= userCount ||
    seen.has(index)
  ) {
    throw new Error(
      "Google Directory photo batch response had an invalid Content-ID",
    );
  }
}

function decodePhotoBatchResult(
  user: GoogleDirectoryUser,
  result: Readonly<{ json: string; status: number }>,
): null | string {
  if (result.status === 404) return null;
  if (result.status < 200 || result.status >= 300) {
    throw new PhotoBatchHttpError(result.status);
  }
  const raw: unknown = JSON.parse(result.json);
  const photo = GooglePhotoSchema.parse(raw);
  const bytes = base64UrlByteLength(photo.photoData);
  if (bytes > 250_000) {
    throw new Error(`Google profile photo for ${user.id} exceeds safe size`);
  }
  const encoded = photo.photoData.replaceAll("-", "+").replaceAll("_", "/");
  const padded = encoded.padEnd(Math.ceil(encoded.length / 4) * 4, "=");
  return `data:${photo.mimeType};base64,${padded}`;
}

class PhotoBatchHttpError extends Error {
  readonly status: number;

  constructor(status: number, options?: ErrorOptions) {
    super(`Google Directory users.photos.get HTTP ${String(status)}`, options);
    this.name = "PhotoBatchHttpError";
    this.status = status;
  }
}

class PhotoBatchContractError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "PhotoBatchContractError";
  }
}

function isTransientPhotoStatus(status: number): boolean {
  return status === 408 || status === 429 || status >= 500;
}

function parsePhotoBatchPart(part: string): ParsePhotoBatchPartResult {
  const { body: nestedResponse, headers: outerHeaders } = splitMessage(
    part,
    "multipart response part",
  );
  if (!/^content-type:\s*application\/http\s*$/imu.test(outerHeaders)) {
    throw new Error(
      "Google Directory photo batch response part was not application/http",
    );
  }
  const contentId = /^content-id:\s*<?response-photo-(\d+)>?\s*$/imu.exec(
    outerHeaders,
  );
  const index = Number(contentId?.[1]);
  const { body: json, headers: nestedHeaders } = splitMessage(
    nestedResponse,
    "nested photo response",
  );
  const status = Number(
    /^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s|$)/u.exec(nestedHeaders)?.[1],
  );
  if (!Number.isSafeInteger(status)) {
    throw new TypeError(
      "Google Directory photo batch response omitted an HTTP status",
    );
  }
  return { index, json, status };
}

function splitMessage(
  value: string,
  label: string,
): Readonly<{ body: string; headers: string }> {
  const match = /\r?\n\r?\n/u.exec(value);
  if (!match) {
    throw new Error(`Google Directory ${label} was malformed`);
  }
  return {
    body: value.slice(match.index + match[0].length),
    headers: value.slice(0, match.index),
  };
}

function base64UrlByteLength(value: string): number {
  const unpadded = value.replaceAll("=", "");
  return Math.floor((unpadded.length * 3) / 4);
}
