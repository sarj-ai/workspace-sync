import { z } from "zod";

import { runtimeFetch } from "../clients/runtime-fetch.ts";
import { fetchPort } from "../runtime/fetch-port.ts";
import {
  PagerDutyLicensesResponseSchema,
  type PagerDutyLicensingSnapshot,
  PagerDutyLicensingSnapshotSchema,
} from "./pagerduty-readiness-contracts.ts";
import { PagerDutyTeamRoleSchema } from "./pagerduty-team-config.ts";

const PAGERDUTY_API = "https://api.pagerduty.com";
const PAGERDUTY_ACCEPT = "application/vnd.pagerduty+json;version=2";
const DEFAULT_MAX_PAGES = 20;
const DEFAULT_MAX_REQUESTS = 50;
const DEFAULT_REQUEST_TIMEOUT_MS = 15_000;
const MAX_TEAM_IDS = 20;
const PAGE_SIZE = 100;

const PagerDutyIdSchema = z.string().regex(/^P[A-Z0-9]+$/);
const PagerDutyUserSchema = z.object({
  email: z.email().toLowerCase(),
  id: PagerDutyIdSchema,
  name: z.string().trim().min(1),
  role: z.string().trim().min(1),
});
const PagerDutyTeamSchema = z.object({
  id: PagerDutyIdSchema,
  name: z.string().trim().min(1),
});
const PagerDutyTeamMemberSchema = z.object({
  role: PagerDutyTeamRoleSchema,
  user: z.object({ id: PagerDutyIdSchema }),
});
const PaginationSchema = z.object({
  limit: z.number().int().positive().max(PAGE_SIZE),
  more: z.boolean(),
  offset: z.number().int().nonnegative(),
});
const UsersPageSchema = PaginationSchema.extend({
  users: z.array(PagerDutyUserSchema),
});
const TeamsPageSchema = PaginationSchema.extend({
  teams: z.array(PagerDutyTeamSchema),
});
const MembersPageSchema = PaginationSchema.extend({
  members: z.array(PagerDutyTeamMemberSchema),
});
const LicenseAllocationsPageSchema = PaginationSchema.extend({
  "license_allocations": z.array(
    z.object({
      user: z.object({ id: PagerDutyIdSchema }),
      license: z.object({ id: PagerDutyIdSchema }),
    }),
  ),
});

interface PagerDutyPage<Item> {
  items: Item[];
  limit: number;
  more: boolean;
  offset: number;
}

export const PagerDutyTeamSnapshotSchema = z
  .strictObject({
    capturedAt: z.iso.datetime({ offset: true }),
    memberships: z.array(
      z.strictObject({
        role: PagerDutyTeamRoleSchema,
        teamId: PagerDutyIdSchema,
        userId: PagerDutyIdSchema,
      }),
    ),
    teams: z.array(PagerDutyTeamSchema),
    users: z.array(PagerDutyUserSchema),
  })
  .superRefine((snapshot, context) => {
    addDuplicateIssue(
      snapshot.users.map(({ id }) => id),
      "user ID",
      context,
    );
    addDuplicateIssue(
      snapshot.teams.map(({ id }) => id),
      "team ID",
      context,
    );
    addDuplicateIssue(
      snapshot.memberships.map(({ teamId, userId }) => `${teamId}:${userId}`),
      "team membership",
      context,
    );
    const userIds = new Set(snapshot.users.map(({ id }) => id));
    const teamIds = new Set(snapshot.teams.map(({ id }) => id));
    for (const [index, membership] of snapshot.memberships.entries()) {
      if (!userIds.has(membership.userId)) {
        context.addIssue({
          code: "custom",
          message: "PagerDuty team membership references an unknown user",
          path: ["memberships", index, "userId"],
        });
      }
      if (!teamIds.has(membership.teamId)) {
        context.addIssue({
          code: "custom",
          message: "PagerDuty team membership references an unknown team",
          path: ["memberships", index, "teamId"],
        });
      }
    }
  })
  .readonly();

export type PagerDutyTeamSnapshot = z.output<
  typeof PagerDutyTeamSnapshotSchema
>;

export interface IPagerDutyTeamReader {
  snapshot(teamIds: readonly string[]): Promise<PagerDutyTeamSnapshot>;
}
export interface IPagerDutyLicenseReader {
  licensing(): Promise<PagerDutyLicensingSnapshot>;
}

export interface IPagerDutyTeamClient extends IPagerDutyTeamReader {
  getTeamMembership(
    teamId: string,
    // eslint-disable-next-line @sarj/prefer-nominal-id-types -- The public PagerDuty adapter accepts SDK string IDs; implementations parse both resource keys and perform guarded readbacks.
    userId: string,
  ): Promise<{ role: z.output<typeof PagerDutyTeamRoleSchema> } | null>;
  putTeamMembership(
    teamId: string,
    // eslint-disable-next-line @sarj/prefer-nominal-id-types -- The public PagerDuty adapter accepts SDK string IDs; implementations parse both resource keys and perform guarded readbacks.
    userId: string,
    role: z.output<typeof PagerDutyTeamRoleSchema>,
    assertFinalWriteAuthority?: () => Promise<void>,
  ): Promise<void>;
}

interface PagerDutyTeamReaderOptions {
  fetchImpl?: typeof fetch;
  maxPages?: number;
  maxRequests?: number;
  requestTimeoutMs?: number;
  token: string;
}
const ApiTokenSchema = z.string().min(1);

const TeamIdsSchema = z.array(PagerDutyIdSchema).max(MAX_TEAM_IDS);

export class PagerDutyTeamReader
  implements IPagerDutyTeamClient, IPagerDutyLicenseReader
{
  readonly #fetchImpl: typeof fetch;
  readonly #maxPages: number;
  readonly #maxRequests: number;
  readonly #requestTimeoutMs: number;
  readonly #token: string;

  constructor(options: PagerDutyTeamReaderOptions) {
    this.#fetchImpl = fetchPort(options.fetchImpl ?? runtimeFetch);
    this.#maxPages = boundedPositiveInteger(
      options.maxPages ?? DEFAULT_MAX_PAGES,
      DEFAULT_MAX_PAGES,
      "maxPages",
    );
    this.#maxRequests = boundedPositiveInteger(
      options.maxRequests ?? DEFAULT_MAX_REQUESTS,
      DEFAULT_MAX_REQUESTS,
      "maxRequests",
    );
    this.#requestTimeoutMs = boundedPositiveInteger(
      options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS,
      DEFAULT_REQUEST_TIMEOUT_MS,
      "requestTimeoutMs",
    );
    this.#token = ApiTokenSchema.parse(options.token);
  }

  async licensing(): Promise<PagerDutyLicensingSnapshot> {
    const budget = { count: 0 };
    const response = await this.#request("/licenses", budget);
    const { licenses } = PagerDutyLicensesResponseSchema.parse(
      await response.json(),
    );
    if (new Set(licenses.map(({ id }) => id)).size !== licenses.length)
      throw new Error("pagerduty_license_duplicate");
    const allocations = await this.#pages(
      "/license_allocations",
      (value) => {
        const page = LicenseAllocationsPageSchema.parse(value);
        return { ...page, items: page["license_allocations"] };
      },
      budget,
    );
    const ids = allocations.map(
      ({ user, license }) => `${user.id}:${license.id}`,
    );
    if (
      new Set(ids).size !== ids.length ||
      allocations.some(
        ({ license }) => !licenses.some(({ id }) => id === license.id),
      )
    )
      throw new Error("pagerduty_license_allocation_incomplete");
    return PagerDutyLicensingSnapshotSchema.parse({
      licenses,
      allocationCount: allocations.length,
    });
  }

  async snapshot(
    rawTeamIds: readonly string[],
  ): Promise<PagerDutyTeamSnapshot> {
    const teamIds = TeamIdsSchema.parse(rawTeamIds);
    if (new Set(teamIds).size !== teamIds.length)
      throw new Error("pagerduty_team_ids_duplicate");
    const budget = { count: 0 };
    const users = await this.#pages(
      "/users",
      (value) => {
        const page = UsersPageSchema.parse(value);
        return { ...page, items: page.users };
      },
      budget,
    );
    const teams = await this.#pages(
      "/teams",
      (value) => {
        const page = TeamsPageSchema.parse(value);
        return { ...page, items: page.teams };
      },
      budget,
    );
    const memberships: PagerDutyTeamSnapshot["memberships"][number][] = [];
    for (const teamId of teamIds.toSorted()) {
      // eslint-disable-next-line no-await-in-loop -- Team-member pagination shares one bounded request budget.
      const members = await this.#pages(
        `/teams/${encodeURIComponent(teamId)}/members`,
        (value) => {
          const page = MembersPageSchema.parse(value);
          return { ...page, items: page.members };
        },
        budget,
      );
      memberships.push(
        ...members.map(({ role, user }) => ({ role, teamId, userId: user.id })),
      );
    }
    return PagerDutyTeamSnapshotSchema.parse({
      capturedAt: new Date().toISOString(),
      memberships: memberships.toSorted(compareMembership),
      teams: teams.toSorted((left, right) => left.id.localeCompare(right.id)),
      users: users.toSorted((left, right) => left.id.localeCompare(right.id)),
    });
  }

  async getTeamMembership(
    rawTeamId: string,
    // eslint-disable-next-line @sarj/prefer-nominal-id-types -- The public PagerDuty adapter accepts SDK string IDs; implementations parse both resource keys and perform guarded readbacks.
    rawUserId: string,
  ): Promise<{ role: z.output<typeof PagerDutyTeamRoleSchema> } | null> {
    const teamId = PagerDutyIdSchema.parse(rawTeamId);
    const userId = PagerDutyIdSchema.parse(rawUserId);
    const members = await this.#teamMembers(teamId, { count: 0 });
    const matches = members.filter(({ user }) => user.id === userId);
    if (matches.length > 1)
      throw new Error("pagerduty_team_sync_duplicate_target_membership");
    const match = matches[0];
    return match === undefined ? null : { role: match.role };
  }

  async putTeamMembership(
    rawTeamId: string,
    // eslint-disable-next-line @sarj/prefer-nominal-id-types -- The public PagerDuty adapter accepts SDK string IDs; implementations parse both resource keys and perform guarded readbacks.
    rawUserId: string,
    rawRole: z.output<typeof PagerDutyTeamRoleSchema>,
    assertFinalWriteAuthority?: () => Promise<void>,
  ): Promise<void> {
    const teamId = PagerDutyIdSchema.parse(rawTeamId);
    const userId = PagerDutyIdSchema.parse(rawUserId);
    const role = PagerDutyTeamRoleSchema.parse(rawRole);
    const response = await this.#request(
      `/teams/${encodeURIComponent(teamId)}/users/${encodeURIComponent(userId)}`,
      { count: 0 },
      {
        body: JSON.stringify({ role }),
        headers: { "content-type": "application/json" },
        method: "PUT",
      },
      assertFinalWriteAuthority,
    );
    if (response.status !== 204) {
      response.body?.cancel().catch(() => null);
      throw new PagerDutyTeamUnexpectedMutationStatusError(response.status);
    }
  }

  async #teamMembers(teamId: string, budget: { count: number }) {
    return this.#pages(
      `/teams/${encodeURIComponent(teamId)}/members`,
      (value) => {
        const page = MembersPageSchema.parse(value);
        return { ...page, items: page.members };
      },
      budget,
    );
  }

  async #pages<Item>(
    path: string,
    parsePage: (value: unknown) => PagerDutyPage<Item>,
    budget: { count: number },
  ): Promise<Item[]> {
    const results: Item[] = [];
    let offset = 0;
    for (let page = 1; page <= this.#maxPages; page++) {
      const query = new URLSearchParams({
        limit: String(PAGE_SIZE),
        offset: String(offset),
      });
      // eslint-disable-next-line no-await-in-loop -- Offset pagination is ordered and bounded.
      const response = await this.#request(
        `${path}?${query.toString()}`,
        budget,
      );
      // eslint-disable-next-line no-await-in-loop -- Each page is parsed before selecting the next offset.
      const parsed = parsePage(await response.json());
      if (parsed.offset !== offset)
        throw new Error("pagerduty_team_sync_invalid_page");
      results.push(...parsed.items);
      if (!parsed.more) return results;
      const nextOffset = parsed.offset + parsed.limit;
      if (nextOffset <= offset)
        throw new Error("pagerduty_team_sync_invalid_page");
      offset = nextOffset;
    }
    throw new Error("pagerduty_team_sync_page_limit_exceeded");
  }

  async #request(
    path: string,
    budget: { count: number },
    init: RequestInit = {},
    assertFinalWriteAuthority?: () => Promise<void>,
  ): Promise<Response> {
    budget.count += 1;
    if (budget.count > this.#maxRequests) {
      throw new Error("pagerduty_team_sync_request_limit_exceeded");
    }
    const headers = new Headers(init.headers);
    headers.set("accept", PAGERDUTY_ACCEPT);
    headers.set("authorization", `Token token=${this.#token}`);
    await assertFinalWriteAuthority?.();
    const response = await this.#fetchImpl(`${PAGERDUTY_API}${path}`, {
      ...init,
      headers,
      redirect: "manual",
      signal: AbortSignal.timeout(this.#requestTimeoutMs),
    });
    if (!response.ok) {
      response.body?.cancel().catch(() => null);
      throw new PagerDutyTeamRequestError(response.status);
    }
    return response;
  }
}

export class PagerDutyTeamRequestError extends Error {
  readonly status: number;

  constructor(status: number, options?: ErrorOptions) {
    super(`pagerduty_team_sync_http_${String(status)}`, options);
    this.name = "PagerDutyTeamRequestError";
    this.status = status;
  }
}

export class PagerDutyTeamUnexpectedMutationStatusError extends Error {
  readonly status: number;

  constructor(status: number, options?: ErrorOptions) {
    super(
      `pagerduty_team_sync_unexpected_mutation_status_${String(status)}`,
      options,
    );
    this.name = "PagerDutyTeamUnexpectedMutationStatusError";
    this.status = status;
  }
}

function boundedPositiveInteger(
  value: number,
  maximum: number,
  name: string,
): number {
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) {
    throw new Error(
      `${name} must be a positive integer no greater than ${String(maximum)}`,
    );
  }
  return value;
}

function compareMembership(
  left: PagerDutyTeamSnapshot["memberships"][number],
  right: PagerDutyTeamSnapshot["memberships"][number],
): number {
  return `${left.teamId}:${left.userId}`.localeCompare(
    `${right.teamId}:${right.userId}`,
  );
}

function addDuplicateIssue(
  values: readonly string[],
  label: string,
  context: z.RefinementCtx,
): void {
  if (new Set(values).size === values.length) return;
  context.addIssue({ code: "custom", message: `duplicate PagerDuty ${label}` });
}
