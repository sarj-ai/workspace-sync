import { z } from "zod";

import { runtimeFetch } from "../clients/runtime-fetch.ts";
import { fetchWithRetry, type RetryOptions } from "../org-sync/http.ts";
import { readBoundedText } from "../runtime/read-bounded-text.ts";

const ATTIO_API_ORIGIN = "https://api.attio.com";
const ATTIO_SELF_PATH = "/v2/self";
const ATTIO_SCIM_USERS_PATH = "/scim/v2/Users";
const ATTIO_WORKSPACE_MEMBERS_PATH = "/v2/workspace_members";
const ATTIO_READ_SCOPE = "user_management:read";
const SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
const SCIM_LIST_RESPONSE_SCHEMA =
  "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const SCIM_PAGE_SIZE = 100;
const DEFAULT_MAX_PAGES = 20;
const MAX_RESPONSE_BYTES = 2 * 1_024 * 1_024;

const EmailSchema = z.string().trim().toLowerCase().pipe(z.email());
const WorkspaceIdSchema = z.uuid().brand<"AttioWorkspaceId">();
const AttioUserIdSchema = z.uuid().brand<"AttioUserId">();
const AttioRoleSchema = z.enum(["admin", "member"]);
const AttioWorkspaceAccessLevelSchema = z.enum([
  "admin",
  "member",
  "suspended",
]);
const AttioScimStatusSchema = z.enum(["available", "payment-required"]);

const AttioCaptureConfigurationSchema = z.strictObject({
  apiKey: z.string().trim().min(1),
  expectedWorkspaceId: WorkspaceIdSchema,
  maxPages: z.number().int().positive().max(100),
});

const AttioTokenMetadataResponseSchema = z.discriminatedUnion("active", [
  z.object({ active: z.literal(false) }),
  z.object({
    active: z.literal(true),
    scope: z.string(),
    "token_type": z.literal("Bearer"),
    "workspace_id": WorkspaceIdSchema,
  }),
]);

const AttioScimUserResponseSchema = z.object({
  active: z.boolean(),
  appRole: AttioRoleSchema.optional(),
  emails: z
    .array(
      z.object({
        primary: z.boolean(),
        type: z.literal("work"),
        value: EmailSchema,
      }),
    )
    .min(1),
  id: AttioUserIdSchema,
  meta: z.object({
    created: z.iso.datetime({ offset: true }),
    lastModified: z.iso.datetime({ offset: true }),
    resourceType: z.literal("User"),
  }),
  name: z.object({ familyName: z.string(), givenName: z.string() }),
  schemas: z.tuple([z.literal(SCIM_USER_SCHEMA)]),
  userName: EmailSchema,
});

const AttioScimUsersPageResponseSchema = z.object({
  Resources: z.array(AttioScimUserResponseSchema),
  itemsPerPage: z.number().int().nonnegative(),
  schemas: z.tuple([z.literal(SCIM_LIST_RESPONSE_SCHEMA)]),
  startIndex: z.number().int().positive(),
  totalResults: z.number().int().nonnegative(),
});

const AttioWorkspaceMemberResponseSchema = z.object({
  "access_level": AttioWorkspaceAccessLevelSchema,
  "email_address": EmailSchema,
  "first_name": z.string().optional(),
  id: z.object({
    "workspace_id": WorkspaceIdSchema,
    "workspace_member_id": AttioUserIdSchema,
  }),
  "last_name": z.string().optional(),
});

const AttioWorkspaceMembersResponseSchema = z.object({
  data: z.array(AttioWorkspaceMemberResponseSchema),
});

export const AttioWorkspaceMemberSchema = z
  .strictObject({
    accessLevel: AttioWorkspaceAccessLevelSchema,
    emailAddress: EmailSchema,
    id: z
      .strictObject({
        workspaceId: WorkspaceIdSchema,
        workspaceMemberId: AttioUserIdSchema,
      })
      .readonly(),
  })
  .readonly();

export const AttioScimUserSchema = z
  .strictObject({
    active: z.boolean(),
    appRole: AttioRoleSchema.optional(),
    emails: z
      .array(
        z.strictObject({
          primary: z.boolean(),
          value: EmailSchema,
        }),
      )
      .min(1)
      .readonly(),
    id: AttioUserIdSchema,
    lastModified: z.iso.datetime({ offset: true }),
    userName: EmailSchema,
  })
  .readonly();

export const AttioDeprovisionAuthoritySchema = z
  .strictObject({
    capturedAt: z.iso.datetime({ offset: true }),
    complete: z.literal(true),
    scimStatus: AttioScimStatusSchema,
    scimUsers: z.array(AttioScimUserSchema).readonly(),
    token: z
      .strictObject({
        scopes: z.tuple([z.literal(ATTIO_READ_SCOPE)]).readonly(),
        workspaceId: WorkspaceIdSchema,
      })
      .readonly(),
    workspaceMembers: z.array(AttioWorkspaceMemberSchema).readonly(),
  })
  .superRefine((authority, context) => {
    if (
      authority.scimStatus === "payment-required" &&
      authority.scimUsers.length !== 0
    ) {
      context.addIssue({
        code: "custom",
        message:
          "SCIM users must be empty when Attio reports that SCIM requires payment.",
        path: ["scimUsers"],
      });
    }
  })
  .readonly();

export type AttioDeprovisionAuthority = z.output<
  typeof AttioDeprovisionAuthoritySchema
>;

export type AttioDeprovisionAuthorityCaptureErrorCode =
  | "configuration-invalid"
  | "deadline-exceeded"
  | "response-oversized"
  | "scim-duplicate-user-id"
  | "scim-page-limit-exceeded"
  | "scim-pagination-invalid"
  | "scope-mismatch"
  | "source-http"
  | "source-invalid"
  | "source-unavailable"
  | "token-inactive"
  | "workspace-member-duplicate-id"
  | "workspace-mismatch";

export type AttioDeprovisionAuthorityCaptureErrorComponent =
  | "configuration"
  | "scim-users"
  | "token-metadata"
  | "workspace-members";

export class AttioDeprovisionAuthorityCaptureError extends Error {
  readonly code: AttioDeprovisionAuthorityCaptureErrorCode;
  readonly component: AttioDeprovisionAuthorityCaptureErrorComponent;
  readonly status: number | undefined;

  constructor(
    component: AttioDeprovisionAuthorityCaptureErrorComponent,
    code: AttioDeprovisionAuthorityCaptureErrorCode,
    options: ErrorOptions & { readonly status?: number } = {},
  ) {
    super(
      `attio_deprovision_authority_${component.replaceAll("-", "_")}_${code.replaceAll("-", "_")}`,
      options,
    );
    this.name = "AttioDeprovisionAuthorityCaptureError";
    this.code = code;
    this.component = component;
    this.status = options.status;
  }
}

export interface AttioDeprovisionAuthorityCaptureOptions {
  readonly apiKey: string;
  readonly expectedWorkspaceId: string;
  readonly fetchImpl?: typeof fetch;
  readonly maxPages?: number;
  readonly now?: () => Date;
  readonly random?: RetryOptions["random"];
  readonly sleep?: RetryOptions["sleep"];
}

export interface AttioDeprovisionAuthorityCapturePort {
  capture(
    deadlineAt?: number,
    runId?: string,
  ): Promise<AttioDeprovisionAuthority>;
}

/** Captures one complete, tenant-pinned, read-only Attio identity authority snapshot. */
export class AttioDeprovisionAuthorityCapture implements AttioDeprovisionAuthorityCapturePort {
  readonly #apiKey: string;
  readonly #expectedWorkspaceId: z.output<typeof WorkspaceIdSchema>;
  readonly #fetchImpl: typeof fetch;
  readonly #maxPages: number;
  readonly #now: () => Date;
  readonly #random: RetryOptions["random"];
  readonly #sleep: RetryOptions["sleep"];

  constructor(options: AttioDeprovisionAuthorityCaptureOptions) {
    const parsed = AttioCaptureConfigurationSchema.safeParse({
      apiKey: options.apiKey,
      expectedWorkspaceId: options.expectedWorkspaceId,
      maxPages: options.maxPages ?? DEFAULT_MAX_PAGES,
    });
    if (!parsed.success)
      throw captureError(
        "configuration",
        "configuration-invalid",
        parsed.error,
      );
    this.#apiKey = parsed.data.apiKey;
    this.#expectedWorkspaceId = parsed.data.expectedWorkspaceId;
    this.#fetchImpl = options.fetchImpl ?? runtimeFetch;
    this.#maxPages = parsed.data.maxPages;
    this.#now = options.now ?? (() => new Date());
    this.#random = options.random;
    this.#sleep = options.sleep;
  }

  async capture(
    deadlineAt?: number,
    runId?: string,
  ): Promise<AttioDeprovisionAuthority> {
    const token = await this.#captureTokenMetadata(deadlineAt, runId);
    const [scim, workspaceMembers] = await Promise.all([
      this.#captureScimAuthority(deadlineAt, runId),
      this.#captureWorkspaceMembers(deadlineAt, runId),
    ]);
    // Attio permits workspace members that are not managed by the connected SCIM authority.
    // Preserve both complete inventories; target-specific reconciliation happens during PLAN.
    return AttioDeprovisionAuthoritySchema.parse({
      capturedAt: this.#now().toISOString(),
      complete: true,
      scimStatus: scim.status,
      scimUsers: scim.users,
      token,
      workspaceMembers,
    });
  }

  async #captureScimAuthority(deadlineAt?: number, runId?: string) {
    try {
      return {
        status: "available" as const,
        users: await this.#captureScimUsers(deadlineAt, runId),
      };
    } catch (error) {
      if (
        error instanceof AttioDeprovisionAuthorityCaptureError &&
        error.component === "scim-users" &&
        error.code === "source-http" &&
        error.status === 402
      ) {
        return { status: "payment-required" as const, users: [] };
      }
      throw error;
    }
  }

  async #captureTokenMetadata(deadlineAt?: number, runId?: string) {
    const raw = await this.#requestJson(
      ATTIO_SELF_PATH,
      "token-metadata",
      deadlineAt,
      runId,
    );
    const parsed = parseSource(
      AttioTokenMetadataResponseSchema,
      raw,
      "token-metadata",
    );
    if (!parsed.active) throw captureError("token-metadata", "token-inactive");
    if (parsed["workspace_id"] !== this.#expectedWorkspaceId) {
      throw captureError("token-metadata", "workspace-mismatch");
    }
    const scopes = parsed.scope.trim().split(/\s+/u).filter(Boolean);
    if (scopes.length !== 1 || scopes[0] !== ATTIO_READ_SCOPE) {
      throw captureError("token-metadata", "scope-mismatch");
    }
    return {
      scopes: [ATTIO_READ_SCOPE] as const,
      workspaceId: parsed["workspace_id"],
    };
  }

  async #captureScimUsers(deadlineAt?: number, runId?: string) {
    const users: z.output<typeof AttioScimUserSchema>[] = [];
    let expectedTotal: number | undefined;
    let startIndex = 1;
    for (let pageNumber = 1; pageNumber <= this.#maxPages; pageNumber++) {
      const query = new URLSearchParams({
        count: String(SCIM_PAGE_SIZE),
        startIndex: String(startIndex),
      });
      // eslint-disable-next-line no-await-in-loop -- SCIM pagination is ordered and each page defines the next index.
      const raw = await this.#requestJson(
        `${ATTIO_SCIM_USERS_PATH}?${query.toString()}`,
        "scim-users",
        deadlineAt,
        runId,
      );
      const page = parseSource(
        AttioScimUsersPageResponseSchema,
        raw,
        "scim-users",
      );
      expectedTotal ??= page.totalResults;
      if (
        page.startIndex !== startIndex ||
        page.itemsPerPage !== page.Resources.length ||
        page.totalResults !== expectedTotal ||
        users.length + page.Resources.length > expectedTotal
      ) {
        throw captureError("scim-users", "scim-pagination-invalid");
      }
      users.push(
        ...page.Resources.map((user) =>
          AttioScimUserSchema.parse({
            active: user.active,
            ...(!(user.appRole === undefined) && { appRole: user.appRole }),
            emails: user.emails.map(({ primary, value }) => ({
              primary,
              value,
            })),
            id: user.id,
            lastModified: user.meta.lastModified,
            userName: user.userName,
          }),
        ),
      );
      if (users.length === expectedTotal) {
        assertUniqueIds(
          users.map(({ id }) => id),
          "scim-users",
          "scim-duplicate-user-id",
        );
        return users;
      }
      if (page.itemsPerPage === 0) {
        throw captureError("scim-users", "scim-pagination-invalid");
      }
      startIndex += page.itemsPerPage;
    }
    throw captureError("scim-users", "scim-page-limit-exceeded");
  }

  async #captureWorkspaceMembers(deadlineAt?: number, runId?: string) {
    const raw = await this.#requestJson(
      ATTIO_WORKSPACE_MEMBERS_PATH,
      "workspace-members",
      deadlineAt,
      runId,
    );
    const response = parseSource(
      AttioWorkspaceMembersResponseSchema,
      raw,
      "workspace-members",
    );
    const members = response.data.map((member) => {
      if (member.id["workspace_id"] !== this.#expectedWorkspaceId) {
        throw captureError("workspace-members", "workspace-mismatch");
      }
      return AttioWorkspaceMemberSchema.parse({
        accessLevel: member["access_level"],
        emailAddress: member["email_address"],
        id: {
          workspaceId: member.id["workspace_id"],
          workspaceMemberId: member.id["workspace_member_id"],
        },
      });
    });
    assertUniqueIds(
      members.map((member) => member.id.workspaceMemberId),
      "workspace-members",
      "workspace-member-duplicate-id",
    );
    return members;
  }

  async #requestJson(
    path: string,
    component: Exclude<
      AttioDeprovisionAuthorityCaptureErrorComponent,
      "configuration"
    >,
    deadlineAt?: number,
    runId?: string,
  ): Promise<unknown> {
    let response: Response;
    try {
      response = await fetchWithRetry(
        `${ATTIO_API_ORIGIN}${path}`,
        {
          headers: { authorization: `Bearer ${this.#apiKey}` },
          method: "GET",
          redirect: "manual",
        },
        {
          ...(!(deadlineAt === undefined) && { deadlineAt }),
          fetchImpl: this.#fetchImpl,
          label: `attio.deprovision.${component}`,
          random: this.#random,
          respectRetryAfter: deadlineAt !== undefined,
          runId,
          sleep: this.#sleep,
        },
      );
    } catch (error) {
      if (deadlineAt !== undefined && Date.now() >= deadlineAt) {
        throw captureError(component, "deadline-exceeded", error);
      }
      throw captureError(component, "source-unavailable", error);
    }
    if (!response.ok) {
      await response.body?.cancel();
      throw new AttioDeprovisionAuthorityCaptureError(
        component,
        "source-http",
        {
          status: response.status,
        },
      );
    }
    try {
      return await readBoundedJson(response, component);
    } catch (error) {
      if (error instanceof AttioDeprovisionAuthorityCaptureError) throw error;
      throw captureError(component, "source-invalid", error);
    }
  }
}

async function readBoundedJson(
  response: Response,
  component: Exclude<
    AttioDeprovisionAuthorityCaptureErrorComponent,
    "configuration"
  >,
): Promise<unknown> {
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_RESPONSE_BYTES) {
    throw captureError(component, "response-oversized");
  }
  if (response.body === null) throw new Error("attio_response_body_missing");
  const parsed: unknown = JSON.parse(
    await readBoundedText(response, MAX_RESPONSE_BYTES, () =>
      captureError(component, "response-oversized"),
    ),
  );
  return parsed;
}

function parseSource<Schema extends z.ZodType>(
  schema: Schema,
  raw: unknown,
  component: Exclude<
    AttioDeprovisionAuthorityCaptureErrorComponent,
    "configuration"
  >,
): z.output<Schema> {
  const parsed = schema.safeParse(raw);
  if (!parsed.success)
    throw captureError(component, "source-invalid", parsed.error);
  return parsed.data;
}

function assertUniqueIds(
  ids: readonly string[],
  component: "scim-users" | "workspace-members",
  code: "scim-duplicate-user-id" | "workspace-member-duplicate-id",
): void {
  if (new Set(ids).size !== ids.length) throw captureError(component, code);
}

function captureError(
  component: AttioDeprovisionAuthorityCaptureErrorComponent,
  code: AttioDeprovisionAuthorityCaptureErrorCode,
  cause?: unknown,
): AttioDeprovisionAuthorityCaptureError {
  return new AttioDeprovisionAuthorityCaptureError(
    component,
    code,
    cause === undefined ? undefined : { cause },
  );
}
